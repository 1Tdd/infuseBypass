import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ipa
import download_ipa


def binary(platform=3, encrypted=0, load=None, filetype=2, loads=None):
    commands = [struct.pack("<6I", 0x32, 24, platform, 13 << 16, 18 << 16, 0),
                struct.pack("<6I", 0x2C, 24, 0, 0, encrypted, 0)]
    for value in loads if loads is not None else ([load] if load else []):
        name = value.encode() + b"\0"
        name += b"\0" * (-len(name) % 8)
        commands.append(struct.pack("<6I", 0xC, 24 + len(name), 24, 0, 0, 0) + name)
    return struct.pack("<8I", 0xFEEDFACF, ipa.ARM64, 0, filetype, len(commands),
                       sum(map(len, commands)), 0, 0) + b"".join(commands)


class IPATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_ipa(self, name="Payload/My App.app/Player With Space", data=None, platform="AppleTVOS", mode=0o755):
        result = self.root / "input.ipa"
        with zipfile.ZipFile(result, "w") as archive:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(entry, data if data is not None else binary())
            archive.writestr("Payload/My App.app/Info.plist", plistlib.dumps({
                "CFBundlePackageType": "APPL", "CFBundleIdentifier": "com.firecore.infuse",
                "CFBundleExecutable": "Player With Space", "CFBundleSupportedPlatforms": [platform],
                "UIDeviceFamily": [3], "MinimumOSVersion": "13.0"}))
        return result

    def inspect(self, **kwargs):
        ipa.extract(self.make_ipa(**kwargs), self.root / "extracted")
        return ipa.inspect_app(self.root / "extracted")

    def test_tvos_and_executable_name_with_spaces(self):
        _, executable, _, _ = self.inspect()
        self.assertEqual(executable.name, "Player With Space")
        if os.name != "nt":  # Windows does not implement POSIX executable modes.
            self.assertTrue(executable.stat().st_mode & 0o111)

    def test_encrypted_input_is_rejected(self):
        with self.assertRaisesRegex(ipa.InvalidIPA, "Encrypted"):
            self.inspect(data=binary(encrypted=1))

    def test_ios_input_is_rejected(self):
        with self.assertRaisesRegex(ipa.InvalidIPA, "tvOS"):
            self.inspect(platform="iPhoneOS")

    def test_simulator_arm64_is_rejected(self):
        with self.assertRaisesRegex(ipa.InvalidIPA, "tvOS"):
            self.inspect(data=binary(platform=8))

    def test_unsafe_zip_path_is_rejected(self):
        with self.assertRaisesRegex(ipa.InvalidIPA, "unsafe path"):
            ipa.extract(self.make_ipa(name="Payload/../../escape"), self.root / "extracted")
        self.assertFalse((self.root / "escape").exists())

    def test_symlink_is_rejected(self):
        archive_path = self.root / "link.ipa"
        with zipfile.ZipFile(archive_path, "w") as archive:
            entry = zipfile.ZipInfo("Payload/App.app/link")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "../../../../escape")
        with self.assertRaisesRegex(ipa.InvalidIPA, "links"):
            ipa.extract(archive_path, self.root / "extracted")

    def test_duplicate_zip_paths_are_rejected(self):
        source = self.make_ipa()
        with zipfile.ZipFile(source, "a") as archive:
            archive.writestr("payload/my app.app/info.plist", "duplicate")
        with self.assertRaisesRegex(ipa.InvalidIPA, "duplicate"):
            ipa.extract(source, self.root / "extracted")

    def test_truncated_command_is_rejected(self):
        with self.assertRaises(ipa.InvalidIPA):
            ipa.macho(binary()[:-1])

    def test_fat_slices_are_all_checked(self):
        one, two = binary(), binary(encrypted=1)
        offset = 48
        fat = (struct.pack(">2I", 0xCAFEBABE, 2)
               + struct.pack(">5I", ipa.ARM64, 0, offset, len(one), 0)
               + struct.pack(">5I", ipa.ARM64, 0, offset + len(one), len(two), 0) + one + two)
        self.assertEqual([s["encrypted"] for s in ipa.macho(fat)], [False, True])

    def test_pack_preserves_payload_and_permissions(self):
        _, executable, _, _ = self.inspect()
        output = self.root / "output.ipa"
        ipa.pack(self.root / "extracted", output)
        with zipfile.ZipFile(output) as archive:
            self.assertTrue(all(n.startswith("Payload/") for n in archive.namelist()))
            entry = archive.getinfo("Payload/My App.app/Player With Space")
            self.assertEqual((entry.external_attr >> 16) & 0o777, executable.stat().st_mode & 0o777)
            if os.name != "nt":
                self.assertTrue((entry.external_attr >> 16) & 0o111)

    def test_patched_output_requires_framework(self):
        self.inspect(data=binary(load=ipa.LOAD_PATH))
        with self.assertRaisesRegex(ipa.InvalidIPA, "framework is missing"):
            ipa.inspect_app(self.root / "extracted", patched=True)

    def test_non_https_url_is_rejected(self):
        for url in ("http://example.com/app.ipa", "file:///tmp/app.ipa", "https://user:password@example.com/app.ipa"):
            with self.assertRaises(ValueError):
                download_ipa.check_url(url)

    def test_private_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public Internet"):
            download_ipa.check_url("https://127.0.0.1/app.ipa")

    def test_legacy_cleanup_exception_is_temporary_and_specific(self):
        app, _, _, _ = self.inspect()
        substrate = app / "Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
        substrate.parent.mkdir(parents=True)
        substrate.write_bytes(binary(platform=2, filetype=6))
        with self.assertRaisesRegex(ipa.InvalidIPA, "Not an arm64 tvOS"):
            ipa.inspect_app(self.root / "extracted")
        ipa.inspect_app(self.root / "extracted", allow_legacy_cleanup=True)
        unrelated = app / "Frameworks/Unrelated.dylib"
        unrelated.write_bytes(binary(platform=2, filetype=6))
        with self.assertRaisesRegex(ipa.InvalidIPA, "Not an arm64 tvOS"):
            ipa.inspect_app(self.root / "extracted", allow_legacy_cleanup=True)

    def test_unused_trailing_injection_can_be_removed(self):
        executable = self.root / "Player"
        old_load = "@rpath/InfusePlus.dylib"
        original = binary(loads=["/usr/lib/libSystem.B.dylib", old_load]) + b"UNCHANGED_SECTION_DATA"
        executable.write_bytes(original)
        imports = "-imports:\n  _puts (from libSystem)\n"
        with mock.patch.object(ipa, "imports_for", return_value=imports):
            self.assertEqual(ipa.remove_unused_loads(executable, {old_load}), [old_load])
        result = executable.read_bytes()
        self.assertEqual(len(result), len(original))
        self.assertEqual(ipa.macho(result)[0]["loads"], ["/usr/lib/libSystem.B.dylib"])
        self.assertTrue(result.endswith(b"UNCHANGED_SECTION_DATA"))

    def test_injection_with_symbol_imports_is_not_removed(self):
        executable = self.root / "Player"
        old_load = "@rpath/InfusePlus.dylib"
        original = binary(load=old_load)
        executable.write_bytes(original)
        with mock.patch.object(ipa, "imports_for", return_value="-imports:\n _injected (from InfusePlus)\n"):
            with self.assertRaisesRegex(ipa.InvalidIPA, "imports symbols"):
                ipa.remove_unused_loads(executable, {old_load})
        self.assertEqual(executable.read_bytes(), original)

    def test_middle_injection_is_not_removed(self):
        executable = self.root / "Player"
        old_load = "@rpath/InfusePlus.dylib"
        original = binary(loads=[old_load, "/usr/lib/libSystem.B.dylib"])
        executable.write_bytes(original)
        with self.assertRaisesRegex(ipa.InvalidIPA, "trailing dependency"):
            ipa.remove_unused_loads(executable, {old_load})
        self.assertEqual(executable.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
