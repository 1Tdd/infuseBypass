"""Build a synthetic, signed tvOS app and exercise the real patch/repack path."""
from argparse import Namespace
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ipa

root = Path("build/smoke")
app = root / "original/Payload/User Infuse.app"
app.mkdir(parents=True)
source = root / "fixture.c"
source.write_text("int main(void) { return 0; }\n")
sdk = subprocess.check_output(["xcrun", "--sdk", "appletvos", "--show-sdk-path"], text=True).strip()
ipa.run("xcrun", "--sdk", "appletvos", "clang", "-target", "arm64-apple-tvos13.0", "-isysroot", sdk,
        "-Wl,-headerpad,0x1000", source, "-o", app / "Player With Space")
info = {"CFBundlePackageType": "APPL", "CFBundleIdentifier": "com.firecore.infuse",
        "CFBundleName": "Synthetic tvOS fixture (not Infuse)", "CFBundleExecutable": "Player With Space",
        "CFBundleShortVersionString": "0.0.0", "CFBundleVersion": "1", "MinimumOSVersion": "13.0",
        "CFBundleSupportedPlatforms": ["AppleTVOS"], "UIDeviceFamily": [3]}
(app / "Info.plist").write_bytes(plistlib.dumps(info))
(app / "embedded.mobileprovision").write_bytes(b"synthetic old profile")
extension = app / "PlugIns/Test.appex"
extension.mkdir(parents=True)
shutil.copyfile(app / "Player With Space", extension / "Test")
(extension / "Info.plist").write_bytes(plistlib.dumps({**info, "CFBundleExecutable": "Test"}))
framework = Path("build/products/Release-appletvos/InfuseBypass.framework")
shutil.copytree(framework, app / "Frameworks/Existing.framework")
ipa.run("codesign", "--force", "--sign", "-", app / "Frameworks/Existing.framework")
ipa.run("codesign", "--force", "--sign", "-", app / "Player With Space")
original = root / "Synthetic_tvOS_input.ipa"
ipa.pack(root / "original", original)
output = root / "Synthetic_tvOS_patched.ipa"
args = Namespace(ipa=original, work=root / "patched", framework=framework,
                 insert_dylib=Path("build/tools/insert_dylib").resolve(), output=output, keep_extensions=False)
ipa.patch(args)
patched_app, executable, _, binaries = ipa.inspect_app(root / "patched", patched=True)
assert not (patched_app / "PlugIns").exists()
assert not (patched_app / "embedded.mobileprovision").exists()
assert all(not s["signed"] for b in binaries for s in ipa.macho(b.read_bytes()))
# macOS codesign's real signing engine must accept the modified binary and framework.
ipa.run("codesign", "--force", "--sign", "-", patched_app / "Frameworks/InfuseBypass.framework")
ipa.run("codesign", "--force", "--sign", "-", executable)
ipa.run("codesign", "--verify", "--strict", executable)
ipa.run("codesign", "--verify", "--strict", patched_app / "Frameworks/InfuseBypass.framework")
# Repatching the delivered IPA must not duplicate the load command.
ipa.patch(Namespace(**{**vars(args), "ipa": output, "work": root / "repatched", "output": root / "Repatched.ipa"}))
ipa.patch(Namespace(**{**vars(args), "work": root / "kept", "output": root / "Kept.ipa", "keep_extensions": True}))
assert (root / "kept/Payload/User Infuse.app/PlugIns/Test.appex/Test").is_file()
print("Real tvOS build, signature removal, injection, repack, re-signing, and repeated patch passed")
