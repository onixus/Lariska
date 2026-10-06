# Release process

## Cutting a release

1. Update the package version in `Cargo.toml` and `Cargo.lock`, README versions, installation examples and the dated changelog entry. Run the normal CI and the native lifecycle workflow on that exact commit before tagging.
2. Tag `vX.Y.Z` and push the tag — `.github/workflows/release.yml` triggers
   on any `v*.*.*` tag push.
3. The workflow builds five targets natively (no cross-compiling to a
   different OS's ABI — each binary is built on a runner for its own
   platform, except aarch64 Linux which cross-compiles from the x86_64
   Ubuntu runner via `gcc-aarch64-linux-gnu`):
   - `x86_64-unknown-linux-gnu`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-pc-windows-msvc`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
4. Each archive gets a `.sha256` checksum file alongside it. The reusable native workflow also builds seven packages: Linux x86_64/aarch64 DEB and RPM, Windows x86_64 MSI, and macOS x86_64/aarch64 PKG. Each native package has an Ed25519-signed `.manifest.json` binding its bytes, version and target. Release mode builds the source version; it does not execute the lifecycle smoke tests, so run those separately before publication.
5. A CycloneDX SBOM (`lariska.cdx.json`) is generated from `Cargo.lock` —
   this only reflects Rust dependencies (accurate and complete for a Rust
   binary with no bundled runtime).
6. A **draft** GitHub release is created with all artifacts attached —
   review it and publish manually. It is never auto-published, so a bad
   build never becomes visible to users without an authorized publication step. Confirm both workflows succeeded for the release commit, verify the downloaded checksums/manifests and package versions, then publish with `gh release edit vX.Y.Z --draft=false --latest`. The release should contain 25 assets: five archives, five checksums, seven native packages, seven manifests and one SBOM.

## Build provenance

Builds are not currently reproducible/hermetic (no `cargo vendor` pinning,
no reproducible-build flags) — this is a known gap, not a claim. The
CycloneDX SBOM plus the `Cargo.lock` committed alongside each tag is the
provenance record: given a tag, `cargo build --release --locked` from that
commit reproduces the same dependency versions, if not bit-identical
binaries.

## Code signing

Native deb/RPM/MSI/pkg delivery uses Ed25519-signed manifests. MSI and pkg
builds also require platform signing certificates in GitHub Secrets. The
configured certificates are self-signed: administrators must provision
their trust explicitly, and macOS packages are not Apple notarized.
Archive binaries remain unsigned and can trigger SmartScreen or Gatekeeper.
Private keys are supplied through the five GitHub Secrets listed in [Signed native updates](SIGNED_UPDATES.md); only public trust material belongs in Git. Validate the current commit's native lifecycle before distributing signed packages.

## Upgrade procedure

Managed updates now require a signed native package manifest, a locally provisioned trust key and an initial signed rollback seed. The independent privileged updater installs through the native package manager and verifies a heartbeat from the new version; timeout or failed health restores its protected cached previous package. See [Signed native updates](SIGNED_UPDATES.md).

The release workflow keeps GitHub releases draft and now waits for signed deb/RPM/MSI/pkg builds. Validate the native lifecycle workflow for the current commit before publishing a release. Self-signed native artifacts need explicitly provisioned local certificate trust/pins and are not notarized. Archive downloads remain useful for manual installation, but their checksum alone does not authorize remote native updates.

The manual path remains supported, and is the one to use when the console is
not involved — replace the binary and restart the service:

### Linux (systemd)

```bash
systemctl stop lariska
install -m 755 lariska-vX.Y.Z-x86_64-unknown-linux-gnu/lariska /usr/bin/lariska
systemctl start lariska
```

`state_dir` (`/var/lib/lariska`) is untouched by this — identity, the
delivery spool, and any queued-but-unsent snapshots survive the upgrade.
Config (`/etc/lariska/lariska.toml`) is also untouched; only touch it if the
new version adds a setting you want to opt into.

### macOS (launchd)

```bash
launchctl unload /Library/LaunchDaemons/com.shapoclyack.lariska.plist
install -m 755 lariska-vX.Y.Z-*-apple-darwin/lariska /usr/local/bin/lariska
launchctl load /Library/LaunchDaemons/com.shapoclyack.lariska.plist
```

### Windows (Service)

```bat
sc.exe stop Lariska
copy /Y lariska-vX.Y.Z-x86_64-pc-windows-msvc\lariska.exe "C:\Program Files\Lariska\lariska.exe"
sc.exe start Lariska
```

## Rollback procedure

The native supervisor restores the cached previous signed package automatically when new-version health is not acknowledged. Its stable executable and protected journal are independent of the newly installed endpoint, and a supervisor restart resumes recovery. The anti-rollback floor survives normal recovery; an administrative emergency override names one exact signed version and does not lower that floor.

For a manual archive installation, stop the service, restore the retained previous binary and restart it. Preserve `state_dir`: endpoint identity remains compatible. New agents can read v1 and v2 inventory spool payloads; an older v1-only binary cannot submit queued v2 snapshots and may quarantine them. Keep this evidence for recovery instead of deleting state. Deploy Shapoclyack dual-read/source-aware support before rolling out v2 agents.

## Incident response: server rejects a large fraction of submissions

1. Check `journalctl -u lariska` / the equivalent platform log for the
   `ApiError` variant being returned (see `src/api.rs`) — `Validation`/
   `Conflict`/`PayloadTooLarge` indicate a schema mismatch with the server,
   not a transient issue; `Auth`/`Forbidden` indicate a provisioning-key or
   tenant problem; `Transient`/`RateLimited` are expected to self-resolve
   via the retry/backoff in `src/delivery/retry.rs`.
2. Quarantined entries live under `<state_dir>/spool/quarantine/` — inspect
   them to see exactly what payload the server rejected before deciding
   whether to roll back Lariska or fix the server-side contract.
3. `lariska check-config` and `lariska inventory --output json` (no network
   calls) are the fastest way to confirm the *local* collector/config side
   is healthy independent of the server.

## Soak testing

Phase L6's acceptance bar ("a release candidate survives a multi-day soak
test with simulated outages") is a manual pre-release checklist item, not
CI-automated: run a release candidate against a staging Shapoclyack
instance for several days, periodically blocking network access or
stopping the staging API, and confirm the spool grows/drains correctly with
no crash and no data loss. This has not been performed for any release to
date — track it per-release in the release notes.
