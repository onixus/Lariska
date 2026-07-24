# Release process

## Cutting a release

1. Update `Cargo.toml`'s `version` and add a changelog entry.
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
4. Each archive gets a `.sha256` checksum file alongside it.
5. A CycloneDX SBOM (`lariska.cdx.json`) is generated from `Cargo.lock` —
   this only reflects Rust dependencies (accurate and complete for a Rust
   binary with no bundled runtime).
6. A **draft** GitHub release is created with all artifacts attached —
   review it and publish manually. It is never auto-published, so a bad
   build never becomes visible to users without a human step.

## Build provenance

Builds are not currently reproducible/hermetic (no `cargo vendor` pinning,
no reproducible-build flags) — this is a known gap, not a claim. The
CycloneDX SBOM plus the `Cargo.lock` committed alongside each tag is the
provenance record: given a tag, `cargo build --release --locked` from that
commit reproduces the same dependency versions, if not bit-identical
binaries.

## Code signing

Not implemented. Release artifacts are unsigned. Windows SmartScreen and
macOS Gatekeeper will both warn on first run. Signing requires
organizational certificate/notarization credentials that this project does
not own — resolve ownership before distributing to any fleet where
unsigned-binary warnings are unacceptable (Plan.md §19 "code-signing
ownership and release-key custody").

## Upgrade procedure

Lariska has no built-in self-update. Upgrading means replacing the binary
and restarting the service:

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

Same as upgrade, in reverse: stop the service, restore the previous binary
(keep the last N release archives on hand — they are exactly what was
downloaded from the GitHub release, no rebuild needed), restart. State
compatibility: the wire schema is versioned (`schema_version`, currently
`1`) and the local spool/identity file formats have not changed since Phase
L1 — a rollback within schema v1 is expected to work without touching
`state_dir`. If a future release ever bumps `schema_version` or changes the
spool file format, this document must be updated with the specific
incompatibility before that release ships.

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
