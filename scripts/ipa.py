#!/usr/bin/env python3
"""Validate and patch user-supplied tvOS IPAs; never execute their code."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import zipfile

LOAD_PATH = "@executable_path/Frameworks/InfuseBypass.framework/InfuseBypass"
ARM64 = 0x0100000C
MAX_UNPACKED = 8 * 1024**3
LEGACY_INJECTIONS = {
    "Frameworks/InfusePlus.dylib": "InfusePlus.dylib",
    "Frameworks/CydiaSubstrate.framework/CydiaSubstrate": "CydiaSubstrate",
}


class InvalidIPA(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidIPA(message)


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value),
            f"Invalid OS version: {value!r}")
    parts = tuple(int(p) for p in value.split("."))
    return parts + (0,) * (3 - len(parts))


def packed_version(value):
    return (value >> 16, (value >> 8) & 255, value & 255)


def macho(data):
    """Parse load commands, including every slice of 32/64-bit fat files."""
    magic = bytes(data[:4])
    fat_formats = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
                   b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
    if magic in fat_formats:
        endian, wide = fat_formats[magic]
        require(len(data) >= 8, "Truncated fat header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if wide else 20
        require(0 < count <= 64 and 8 + count * entry_size <= len(data), "Invalid fat header")
        slices, regions = [], []
        for i in range(count):
            entry = struct.unpack_from(endian + ("IIQQII" if wide else "IIIII"), data, 8 + i * entry_size)
            offset, size = entry[2:4]
            require(offset >= 8 + count * entry_size and size > 0 and offset + size <= len(data),
                    "Invalid fat slice bounds")
            require(all(offset + size <= start or offset >= end for start, end in regions),
                    "Overlapping fat slices")
            regions.append((offset, offset + size))
            parsed = macho(data[offset:offset + size])
            require(len(parsed) == 1 and parsed[0]["cpu"] == entry[0], "Invalid fat slice")
            slices.extend(parsed)
        return slices
    thin_formats = {b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True),
                    b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False)}
    if magic not in thin_formats:
        return []
    endian, wide = thin_formats[magic]
    header_size = 32 if wide else 28
    require(len(data) >= header_size, "Truncated Mach-O header")
    _, cpu, subtype, filetype, ncmds, sizeofcmds, _ = struct.unpack_from(endian + "7I", data)
    require(ncmds <= 65535 and header_size + sizeofcmds <= len(data), "Invalid Mach-O commands")
    result = {"cpu": cpu, "subtype": subtype & 0xFFFFFF, "filetype": filetype,
              "platform": None, "minimum_os": None, "encrypted": False,
              "loads": [], "signed": False}
    pos, end = header_size, header_size + sizeofcmds
    for _ in range(ncmds):
        require(pos + 8 <= end, "Truncated Mach-O command")
        cmd, size = struct.unpack_from(endian + "II", data, pos)
        require(size >= 8 and size % 4 == 0 and pos + size <= end, "Invalid Mach-O command size")
        if cmd in (0x21, 0x2C):  # LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
            require(size >= (24 if cmd == 0x2C else 20), "Invalid encryption command")
            result["encrypted"] |= struct.unpack_from(endian + "I", data, pos + 16)[0] != 0
        if cmd == 0x32:  # LC_BUILD_VERSION
            require(size >= 24, "Invalid build-version command")
            result["platform"], minimum = struct.unpack_from(endian + "II", data, pos + 8)
            result["minimum_os"] = packed_version(minimum)
        if cmd in (0x24, 0x25, 0x2F, 0x30):  # Legacy platform commands
            require(size >= 16, "Invalid version-min command")
            result["platform"] = {0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}[cmd]
            result["minimum_os"] = packed_version(struct.unpack_from(endian + "I", data, pos + 8)[0])
        if cmd in (0xC, 0x80000018, 0x8000001F, 0x80000023):
            require(size >= 24, "Invalid dylib command")
            name_offset = struct.unpack_from(endian + "I", data, pos + 8)[0]
            require(24 <= name_offset < size, "Invalid dylib name offset")
            raw = data[pos + name_offset:pos + size]
            require(b"\0" in raw, "Unterminated dylib name")
            result["loads"].append(raw.split(b"\0", 1)[0].decode("utf-8"))
        if cmd == 0x1D:
            require(size >= 16, "Invalid code signature command")
            signature_offset, signature_size = struct.unpack_from(endian + "II", data, pos + 8)
            require(signature_offset + signature_size <= len(data), "Invalid code signature bounds")
            result["signed"] = True
        pos += size
    require(pos == end, "Mach-O command count/size mismatch")
    return [result]


def extract(ipa, destination):
    require(not destination.exists(), f"Work directory already exists: {destination}")
    with zipfile.ZipFile(ipa) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 100000, "Invalid archive entry count")
        require(sum(e.file_size for e in entries) <= MAX_UNPACKED, "IPA expands beyond 8 GiB")
        seen = set()
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and "\\" not in name and ":" not in name
                    and all(p not in (".", "..") for p in name.rstrip("/").split("/")),
                    "IPA contains an unsafe path")
            key = name.rstrip("/").casefold()
            require(key not in seen, "IPA contains duplicate paths")
            seen.add(key)
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                    "IPA contains links or special files; tvOS frameworks must be flat")
            require(not entry.flag_bits & 1, "Password-protected ZIPs are unsupported")
        destination.mkdir(parents=True)
        for entry in entries:
            if not entry.filename.startswith("Payload/"):
                continue
            target = destination.joinpath(*PurePosixPath(entry.filename).parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                mode = (entry.external_attr >> 16) & 0o777
                target.chmod(mode or 0o644)


def inspect_app(root, patched=False, allow_legacy_cleanup=False):
    payload = root / "Payload"
    require(payload.is_dir(), "Missing Payload directory")
    apps = list(payload.glob("*.app"))
    require(len(apps) == 1 and apps[0].is_dir(), "IPA must contain exactly one top-level .app")
    app = apps[0]
    require((app / "Info.plist").is_file(), "Missing app Info.plist")
    with (app / "Info.plist").open("rb") as source:
        info = plistlib.load(source)
    require(info.get("CFBundlePackageType") == "APPL", "Bundle is not an application")
    require(info.get("CFBundleIdentifier") == "com.firecore.infuse", "Expected Infuse (com.firecore.infuse)")
    require(info.get("CFBundleSupportedPlatforms") == ["AppleTVOS"]
            and 3 in info.get("UIDeviceFamily", []), "Upload a tvOS device IPA, not iOS or a simulator app")
    minimum = version(info.get("MinimumOSVersion"))
    require(minimum >= (13, 0, 0), "This workflow supports tvOS 13.0 or newer")
    executable = info.get("CFBundleExecutable", "")
    require(isinstance(executable, str) and executable not in ("", ".", "..")
            and "/" not in executable and "\\" not in executable, "Invalid CFBundleExecutable")
    binary = app / executable
    require(binary.is_file(), "CFBundleExecutable is missing")
    slices = macho(binary.read_bytes())
    arm = [s for s in slices if s["cpu"] == ARM64 and s["subtype"] == 0]
    require(len(arm) == 1 and arm[0]["filetype"] == 2 and arm[0]["platform"] == 3,
            "Executable must include a generic arm64 tvOS device slice")
    require(arm[0]["minimum_os"] <= minimum, "Info.plist MinimumOSVersion is below the executable's requirement")
    binaries = []
    for path in sorted(app.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as source:
            magic = source.read(4)
        if magic not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                         b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            continue
        parsed = macho(path.read_bytes())
        require(not any(s["encrypted"] for s in parsed),
                f"Encrypted executable: {path.relative_to(root)}. Supply your own decrypted IPA; this workflow cannot decrypt it.")
        device = [s for s in parsed if s["cpu"] == ARM64 and s["subtype"] == 0]
        legacy = allow_legacy_cleanup and path.relative_to(app).as_posix() in LEGACY_INJECTIONS
        allowed_platforms = (None, 2, 3) if legacy else (None, 3)
        require(device and all(s["platform"] in allowed_platforms for s in device),
                f"Not an arm64 tvOS binary: {path.relative_to(root)} "
                f"(CPU/subtype/platform: {[(s['cpu'], s['subtype'], s['platform']) for s in parsed]})")
        require(legacy or all(s["minimum_os"] is None or s["minimum_os"] <= minimum for s in device),
                f"Embedded binary requires a newer OS than MinimumOSVersion: {path.relative_to(root)}")
        binaries.append(path)
    if patched:
        require(arm[0]["loads"].count(LOAD_PATH) == 1, "Missing or duplicate framework load command")
        framework_binary = app / "Frameworks/InfuseBypass.framework/InfuseBypass"
        require(framework_binary.is_file(), "Injected framework is missing")
        framework = macho(framework_binary.read_bytes())
        require(len(framework) == 1 and framework[0]["cpu"] == ARM64
                and framework[0]["filetype"] == 6 and framework[0]["platform"] == 3,
                "Injected framework must be an arm64 tvOS dylib")
    return app, binary, info, binaries


def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def imports_for(binary):
    # Apple's parser understands chained fixups and legacy symbol/bind tables.
    result = subprocess.run(["xcrun", "dyld_info", "-imports", str(binary)],
                            capture_output=True, text=True, check=True, timeout=120)
    require(re.search(r"(?m)^\s*-?imports:\s*$", result.stdout) and not result.stderr.strip(),
            "Could not reliably inspect imports before removing an old injection")
    return result.stdout


def remove_unused_loads(binary, load_names):
    data = bytearray(binary.read_bytes())
    parsed = macho(data)
    require(len(parsed) == 1 and data[:4] == b"\xcf\xfa\xed\xfe", "Cleanup requires a thin arm64 executable")
    selected = [load for load in parsed[0]["loads"] if load in load_names]
    if not selected:
        return []
    # Removing a middle dependency would renumber libraries in existing imports.
    require(all(load in load_names for load in parsed[0]["loads"][-len(selected):]),
            "Old injection is not a trailing dependency; supply a clean IPA to avoid changing import ordinals")
    before = imports_for(binary)
    for load in selected:
        require(PurePosixPath(load).stem not in before,
                f"App imports symbols from {load}; cannot safely remove this injection. Supply a clean IPA")
    if parsed[0]["signed"]:
        run("codesign", "--remove-signature", binary)
        data = bytearray(binary.read_bytes())
        require(not macho(data)[0]["signed"], "Failed to remove executable signature before cleanup")
    count, size = struct.unpack_from("<II", data, 16)
    position, kept, removed = 32, [], []
    for _ in range(count):
        command, command_size = struct.unpack_from("<II", data, position)
        block = data[position:position + command_size]
        name = None
        if command in (0xC, 0x80000018, 0x8000001F, 0x80000023):
            offset = struct.unpack_from("<I", block, 8)[0]
            name = bytes(block[offset:]).split(b"\0", 1)[0].decode("utf-8")
        if name in load_names:
            # Re-export/upward dependencies change semantics beyond injection.
            require(command in (0xC, 0x80000018), "Cannot remove an old re-export or upward dependency")
            removed.append(name)
        else:
            kept.append(block)
        position += command_size
    commands = b"".join(kept)
    data[32:32 + size] = commands + b"\0" * (size - len(commands))
    struct.pack_into("<II", data, 16, len(kept), len(commands))
    binary.write_bytes(data)
    require(not set(removed).intersection(macho(data)[0]["loads"]), "Failed to remove old injection load commands")
    require(imports_for(binary) == before, "Removing an old injection changed the app's imports")
    return removed


def clean_legacy_injections(app, binary, binaries):
    legacy = {app / relative: name for relative, name in LEGACY_INJECTIONS.items()
              if (app / relative).is_file()}
    if not legacy:
        return []
    names = set(legacy.values())
    to_remove = set()
    for path in binaries:
        if path in legacy:
            continue
        for architecture in macho(path.read_bytes()):
            references = [load for load in architecture["loads"] if PurePosixPath(load).name in names]
            require(not references or path == binary,
                    f"{path.relative_to(app)} depends on an old injected tweak; supply a clean IPA")
            to_remove.update(references)
    removed_loads = remove_unused_loads(binary, to_remove)
    removed_files = []
    for path in legacy:
        relative = path.relative_to(app).as_posix()
        if path.name == "CydiaSubstrate":
            shutil.rmtree(path.parent)
        else:
            path.unlink()
        removed_files.append(relative)
    print("Removed old injected libraries: " + ", ".join(removed_files))
    print("Removed old executable loads: " + ", ".join(removed_loads))
    return removed_files


def pack(root, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted((root / "Payload").rglob("*")):
            require(not path.is_symlink(), "Cannot package symbolic links")
            if path.is_file() and path.name != ".DS_Store":
                archive.write(path, path.relative_to(root).as_posix())
    with zipfile.ZipFile(output) as archive:
        require(archive.testzip() is None, "Output IPA failed its ZIP checksum test")


def patch(args):
    extract(args.ipa, args.work)
    app, binary, info, _ = inspect_app(args.work, allow_legacy_cleanup=True)
    if not args.keep_extensions:
        for name in ("PlugIns", "Watch"):
            path = app / name
            if path.exists():
                shutil.rmtree(path)
    framework = app / "Frameworks/InfuseBypass.framework"
    if framework.exists():
        shutil.rmtree(framework)
    shutil.copytree(args.framework, framework, symlinks=False)
    # lipo prevents insert_dylib's partial-success behavior for universal files.
    slices = macho(binary.read_bytes())
    if len(slices) > 1:
        thin = binary.with_name(binary.name + ".arm64")
        run("xcrun", "lipo", binary, "-thin", "arm64", "-output", thin)
        thin.replace(binary)
    _, _, _, binaries = inspect_app(args.work, allow_legacy_cleanup=True)
    removed_injections = clean_legacy_injections(app, binary, binaries)
    # The temporary exception applies only during cleanup. The delivered IPA
    # still has to pass the strict platform check for every remaining binary.
    _, _, _, binaries = inspect_app(args.work)
    for path in binaries:
        if any(s["signed"] for s in macho(path.read_bytes())):
            run("codesign", "--remove-signature", path)
            require(not any(s["signed"] for s in macho(path.read_bytes())), "Failed to strip an old signature")
        path.chmod(path.stat().st_mode | 0o755)
    if LOAD_PATH not in macho(binary.read_bytes())[0]["loads"]:
        # Answer NO to any unsafe-padding/duplicate-command prompt.
        run(args.insert_dylib, "--inplace", "--no-strip-codesig", LOAD_PATH, binary,
            input="n\n", text=True, timeout=120)
    for path in sorted(app.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and path.name in ("_CodeSignature", "SC_Info"):
            shutil.rmtree(path)
        elif path.is_file() and path.name in ("embedded.mobileprovision", "embedded.provisionprofile"):
            path.unlink()
    inspect_app(args.work, patched=True)
    pack(args.work, args.output)
    # Re-extract and inspect the actual deliverable, including executable modes.
    verification = args.work.with_name(args.work.name + "-verification")
    extract(args.output, verification)
    _, verified_binary, _, _ = inspect_app(verification, patched=True)
    require(verified_binary.stat().st_mode & 0o111, "Output lost executable permissions")
    report = {"bundle_id": info["CFBundleIdentifier"], "version": info.get("CFBundleShortVersionString"),
              "minimum_tvos": info["MinimumOSVersion"], "architecture": "arm64",
              "input_sha256": sha256(args.ipa),
              "output_sha256": sha256(args.output),
              "extensions_removed": not args.keep_extensions, "signing": "unsigned; re-sign locally before installation",
              "removed_previous_injections": removed_injections,
              "framework_load": LOAD_PATH, "verification": "ZIP CRC + re-extracted tvOS Mach-O validation"}
    args.output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    args.output.with_suffix(".sha256").write_text(report["output_sha256"] + "  " + args.output.name + "\n")
    print(json.dumps(report, indent=2))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as target:
            target.write(f"## Patched tvOS IPA\n\nMinimum tvOS: **{info['MinimumOSVersion']}**. "
                         "Download the IPA from the output draft release, then sign and install it with Sideloadly. "
                         "The artifact is unsigned and device launch has not been tested.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--framework", type=Path, required=True)
    parser.add_argument("--insert-dylib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-extensions", action="store_true")
    args = parser.parse_args()
    try:
        patch(args)
    except (InvalidIPA, OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
