# Infuse tvOS IPA workflow

Fork of [tylinux/infuseBypass](https://github.com/tylinux/infuseBypass). Supply your own **decrypted tvOS Infuse IPA**. The manual GitHub Action builds the arm64 framework, injects it into the executable named by `Info.plist`, and returns **`Infuse_patched_unsigned.ipa` as a direct release asset**.

The output is unsigned. **Sign and install it locally with [Sideloadly](https://sideloadly.io/)**; no Apple ID, signing certificate, or provisioning profile is needed in GitHub. A valid signature and provisioning profile for your Apple TV are still required to install. The workflow cannot turn an encrypted App Store download or an iPhone/iPad app into a working tvOS app.

## Upload through GitHub

1. In your fork, open **Releases → Draft a new release**. Set the tag to `ipa-input` and upload your own IPA as an asset. **Save draft**. A draft release is already prepared in this fork.
2. Keep the release a draft: publishing it in a public fork makes the uploaded IPA public. Draft releases are restricted to collaborators with push access.
3. Open **Actions → Patch uploaded tvOS IPA → Run workflow** on `main`.
4. Select `release`, enter `ipa-input`, and enter the **exact asset filename**, including `.ipa`. Optionally enter its SHA-256 checksum.
5. When the run succeeds, open the **output draft release link in the run summary**. Download **`Infuse_patched_unsigned.ipa`** from its assets. This download is an IPA, without an extra artifact ZIP wrapper.

You can update the input draft with another IPA, or use a different draft/release tag. Uploads are never committed to Git. Output releases are separate drafts named `ipa-output-<run ID>-<attempt>`; the action does not replace your input.

## Upload through a file-sharing service

1. Upload your own decrypted tvOS IPA to a file-sharing service that provides a **direct HTTPS file download link**.
2. Run the same workflow, select `url`, and paste the link into `ipa_url`. Release tag and filename fields are ignored in URL mode.
3. Download the final `.ipa` directly from the output draft release linked in the summary.

The URL must return the actual file without login, cookies, a password form, an HTML preview, or a confirmation page. Redirects to other public HTTPS addresses are supported. For a Dropbox share link, use the direct-download option (`dl=1`). Download links that expire must remain valid until the job downloads the file. Inputs are capped at 2 GiB.

For a private or signed download URL, add a repository Actions secret named **`IPA_DOWNLOAD_URL`**, select `url`, and leave `ipa_url` empty. The downloader masks the URL in logs, but manually entered workflow inputs are still stored in GitHub's run metadata. No GitHub authorization header is sent to the file-sharing service.

## Apple TV signing and installation

1. Download `Infuse_patched_unsigned.ipa` itself from the output draft release.
2. In Sideloadly, pair/select your Apple TV and load the IPA. For pairing on macOS, keep the Apple TV on **Settings → Remotes and Devices → Remote App and Devices**, as described in the [Sideloadly FAQ](https://sideloadly.io/faq.html).
3. Sign/install using your own Apple ID and a tvOS provisioning profile. The signing tool must re-sign the app **and all embedded frameworks**. Do not add the bypass framework again; the action already injected it.
4. Your Apple TV must run at least the **Minimum tvOS** shown in the run summary. The original application's requirement is preserved; the injected framework targets tvOS 13.0.

Top Shelf/app extensions are removed by default to simplify signing with personal accounts. Use `keep_extensions` only when your signing tool can provision and re-sign every extension and supply its required entitlements. The upstream hooks disable CloudKit access; iCloud synchronization and real shared app groups are unavailable. Local app-group storage uses the app's `Library/Caches/ApplicationGroupContainers` directory so it can be written on tvOS. This data can be purged by the OS; see [Apple's file-system guidance](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively).

## Validation and compatibility

The workflow checks:

- An actual tvOS device app (`AppleTVOS`, device family 3, `com.firecore.infuse`), with a generic arm64 executable and a valid minimum OS version.
- Every embedded Mach-O for encryption. An encrypted input fails with a clear error; there is no decryption step.
- Safe ZIP paths, duplicate entries, and file types; symlinks and special files are rejected. Device frameworks must use flat bundles.
- Old binary signatures, signature directories, and provisioning profiles are removed before local re-signing.
- Exactly one load command for the embedded arm64 tvOS framework. The insertion tool is instructed to refuse overwriting nonempty header padding.
- ZIP checksums, executable permissions, and a second inspection of the **re-extracted output IPA**.

The output draft also contains a JSON report and SHA-256 checksum. The action does not publish a release, upload an IPA to upstream, or execute the supplied app on the runner. Anyone with push access to this fork can access draft input/output releases; remove old drafts/assets when finished.

Upstream's README reports testing on **Infuse 8.1.9**, and its commit history adds **8.4.7** hooks. Other app versions may change internal methods. This fork fixes the shared replacement-method bug that affected the two purchase-status hooks and reduces the framework's deployment target from tvOS 26.1 to 13.0. Package validation does not establish that the purchase hooks or app launch work on a particular Infuse/tvOS combination. **Physical Apple TV installation and launch must be tested with your own IPA.**

## CI and local development

`Validate tvOS patcher` runs input-rejection tests, builds the real tvOS framework, checks both purchase-status hooks in one Objective-C runtime, and patches a synthetic tvOS app. The smoke test removes signatures, checks extension handling, re-signs the modified executable/framework with macOS `codesign`, verifies the signatures, and checks that repeating a patch does not duplicate its load command. Synthetic fixtures contain no Infuse app code.

On a Mac with Xcode and the tvOS SDK:

```bash
python3 -m unittest discover -s tests -v
bash scripts/build.sh
python3 tests/smoke.py
python3 scripts/ipa.py \
  --ipa /path/to/your/Infuse.ipa \
  --work /tmp/infuse-ipa-work \
  --framework build/products/Release-appletvos/InfuseBypass.framework \
  --insert-dylib "$PWD/build/tools/insert_dylib" \
  --output dist/Infuse_patched_unsigned.ipa
```

Use a fresh work directory. `build.sh` builds [tyilo/insert_dylib](https://github.com/tyilo/insert_dylib) at the pinned commit `eb7278162af8fcc372e7f2946a2dee6a386b17d8`. GitHub Actions dependencies are pinned to commit SHAs.
