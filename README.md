# Lariska

Lariska is a cross-platform endpoint inventory agent for the Shapoclyack platform.
The first production goal is to identify an endpoint, collect a normalized list
of installed software, and deliver versioned inventory snapshots to Shapoclyack.

## Current status

The full agent lifecycle is implemented and verified end-to-end against a real
Shapoclyack API: provisioning-key JWT exchange with jittered refresh,
idempotent registration, an independent heartbeat loop, software collectors
for Linux (dpkg/rpm/pacman), Windows (registry), and macOS (Info.plist +
Homebrew), durable spool-then-submit delivery with crash recovery and
retry/backoff, and native service integration (systemd/launchd/Windows SCM)
with structured logging. See `docs/hardening.md` for exactly what data is
collected and `docs/RELEASE.md` for the release/upgrade/rollback process.

Known gaps: no MSI/code-signing yet, and the Windows Service integration has
never run against a real Windows Service Control Manager (verified only via
cross-compilation) — see `packaging/windows/README.md`.

## Install and connect

Download the archive for your platform from the
[latest GitHub release](https://github.com/onixus/Lariska/releases/latest),
create a tenant provisioning key in Shapoclyack, and configure Lariska with
the Shapoclyack server URL and the path to that key.

See [Installation and Shapoclyack connection](docs/INSTALL.md) for complete
Linux, macOS, and Windows instructions, service setup, verification, and
troubleshooting.

## Development commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
cargo deny check
```

Cross-repository end-to-end test against a disposable Shapoclyack stack
(requires Docker + Python):

```bash
SHAPOCLYACK_REPO=/path/to/Shapoclyack tests/e2e/run.sh
```

## Run locally

```bash
cargo run -- run --config lariska.toml
```

The agent must not print provisioning keys, JWTs, authorization headers, or
complete inventory payloads by default.
