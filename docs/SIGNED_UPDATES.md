# Signed native updates and recovery

The endpoint downloads a native package into bounded staging. It verifies an Ed25519 release manifest against the locally provisioned keyring, binds version, target, package kind, byte count, digest, expiry and sequence, and enforces the persisted anti-rollback floor. HTTP is allowed only by the local `allow_insecure_updates` setting; TLS does not substitute for a release signature. Trust keys and emergency rollback exceptions cannot be supplied by managed server policy.

The release manifest schema is `{ "manifest": { "schema": 1, "key_id": "...", "version": "...", "platform": "...", "package_kind": "deb|rpm|msi|pkg", "size_bytes": 123, "sha256": "...", "expires_at": 123, "sequence": 123 }, "signature": "128 lowercase hex characters" }`. Sign compact UTF-8 JSON with lexicographically sorted manifest keys. `packaging/ci/sign-manifest.py` signs this representation using an environment-provided private key. Private signing keys never belong in this repository; `packaging/trust/` contains public material only.

A privileged supervisor copies the staged package into protected storage and independently repeats signature, bounds and platform checks. It installs through dpkg/RPM, Windows Installer or macOS Installer, restarts the endpoint and requires a successful authenticated registration or heartbeat from the matching new version and transaction nonce. Registration acknowledges health immediately, including when the configured heartbeat interval exceeds the health deadline. A startup, an executable existing, or a writable shared health file is insufficient. Missing health causes installation of the cached previous signed package and a service restart. The protected journal survives supervisor restart and preserves bounded history with the failure reason. It durably consumes each request nonce before installation and refuses replay after completion, rollback or supervisor restart. Consumption receipts are bounded at 200 and are pruned only when the protected version/sequence floor would reject the old release; an emergency override disables pruning. If 200 receipts remain replayable, the helper refuses another install until an administrator resolves the failed-update history.

The first native install creates a private stable watchdog copy. Endpoint package upgrades preserve this file and do not restart it. Thus an agent that fails before an authenticated registration or heartbeat, or a defective new endpoint executable, cannot replace the component responsible for restoring the previous package.

| Platform | Agent | Stable watchdog | Native installer |
| --- | --- | --- | --- |
| Linux | `/usr/bin/lariska` under the unprivileged `lariska` service | `/var/lib/lariska-updater/supervisor`, root only | `.deb` or RPM |
| Windows | `C:\Program Files\Lariska\lariska.exe`, LocalService | `C:\ProgramData\LariskaUpdater\supervisor.exe`, SYSTEM scheduled task | Signed MSI |
| macOS | `/usr/local/bin/lariska`, launchd `_lariska` | `/Library/Application Support/LariskaUpdater/supervisor`, independent root LaunchDaemon | Signed `.pkg` |

The macOS endpoint writes its launchd output to `/Library/Application Support/Lariska/state/lariska.log`, owned by `_lariska`. The root updater writes to `/Library/Logs/Lariska/updater.log`.

The macOS installer refuses a nonempty state directory owned by root before changing its ownership. For a legacy root-run installation, stop both launchd jobs, back up state and enrollment, and migrate offline into a new administrator-controlled directory. Copy regular state files into new inodes, preserve their contents and reject symlinks and files with multiple hard links; assign the new state to `_lariska` and verify the saved agent identity before starting either job. The installer preserves existing state owned by `_lariska` and never recursively changes its files' ownership.

Configuration and trust policy must be administrator-owned and not writable by the endpoint. The endpoint owns only its state/cache/spool and update mailbox. The native installer provisions these boundaries. Enroll the endpoint using the normal protected configuration and provisioning-key file, then seed its initial rollback package before starting the updater:

```sh
sudo /var/lib/lariska-updater/supervisor update-seed \
  --config /etc/lariska/lariska.toml \
  --manifest lariska-current.deb.manifest.json --artifact lariska-current.deb
sudo systemctl enable --now lariska.service lariska-updater.service
```

Use the corresponding stable watchdog path and native artifact on Windows/macOS. The seed must be a signed package for the installed compiled version. Refusing an unseeded first update protects endpoints from a failed install without a recoverable predecessor.

Local policy is explicit:

```toml
[updates]
package_kind = "deb"
max_download_bytes = 268435456
health_timeout_secs = 180
history_limit = 20

[[updates.trusted_keys]]
id = "lariska-local-2026-10"
public_key = "1860465df51eb4733c8baa24612ff1fbe2185eb9c68b45fd439bfe86398ade8f"
revoked = false
```

For the requested self-signed native mode, set `allow_self_signed_native = true` and provision the exact Windows certificate thumbprint or macOS SHA-256 signer pin from `packaging/trust/public-trust.json`. Windows also needs the explicitly trusted signing certificate so Authenticode validates. Trust establishment is a local administrator action, independent of the update response. The sample self-signed packages are not Apple notarized and have no public CA trust; no public notarization claim is made.

`.github/workflows/native-packages.yml` builds native deb/RPM on x86_64 and aarch64, signed x86_64 MSI, and signed Intel/Apple Silicon macOS packages on disposable runners. RPM lifecycle runs inside a genuine Fedora system with its own package database and systemd. It installs version 0.4.0, drives a real heartbeat-negotiated update to the CI version 0.4.1, deliberately withholds version 0.4.2 health, restarts the independent watchdog and verifies rollback to 0.4.1, endpoint identity persistence, protected journal history and stable watchdog bytes. These versions are test fixtures, not Git tags or published releases. Native packages and `native-smoke.json` are CI artifacts; a workflow file alone does not establish a passed lifecycle run.

Shapoclyack stores one artifact per `(version, platform)` today. For each Linux target triple, choose either DEB or RPM for managed delivery; the current release store cannot offer both kinds for the same version/triple to a mixed fleet. An endpoint with a different locally configured package kind refuses the offer. Both formats remain available for manual native installation. Extending server release identity and agent negotiation to include package kind is separate work.

Agents without `signed_updates` support are blocked from receiving signed native releases: legacy self-update code expects executable bytes. Migrate legacy archive installations manually, preserving protected enrollment and state, before enabling native managed updates.

The workflow requires repository secrets `LARISKA_RELEASE_ED25519_KEY`, `LARISKA_WINDOWS_P12_B64`, `LARISKA_WINDOWS_P12_PASSWORD`, `LARISKA_MACOS_P12_B64` and `LARISKA_MACOS_P12_PASSWORD`.

The macOS certificate must contain critical installer EKU `1.2.840.113635.100.4.13` and installer marker `1.2.840.113635.100.6.1.14`; an application code-signing certificate is insufficient ([Apple installer certificate profile](https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v3.2.pdf), section 4.11.1). Provision its P12 in a format accepted by macOS Security.framework (PBESv1 with 3-key Triple DES and a SHA-1 MAC where required for compatibility; see [PKCS12 serialization](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12)). This affects only the encrypted import bundle; package signatures use RSA with SHA-256 and manifests use Ed25519. The bundle remains protected by filesystem permissions and GitHub Secrets.

Windows/macOS temporary trust and signing key material live on ephemeral CI runners. No local developer machine trust store is changed by the build scripts.
