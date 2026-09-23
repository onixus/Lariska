# Lariska Documentation Hub

[Русский README](../README_RU.md) · [English README](../README.md) · [Work plan](../WORKPLAN_RU.md) · [Technical plan](../Plan.md)

This `wiki/` directory is the canonical, version-controlled source for the Lariska wiki. The page names are compatible with GitHub Wiki conventions (`Home.md`, `_Sidebar.md`) and can be mirrored to the repository wiki without maintaining a second set of prose that quietly drifts into fiction.

## What Lariska is

Lariska is the endpoint inventory agent for Shapoclyack. It runs as a native service on Linux, Windows, or macOS; collects operating-system and runtime software; stores complete snapshots in a durable local queue; and delivers them to the Shapoclyack API through an independent worker.

Its design priorities are, in order:

1. inventory correctness;
2. low and bounded endpoint impact;
3. crash/network resilience;
4. security and privacy;
5. operability across a fleet.

## Start here

- [Architecture](Architecture.md): processes, modules, state, and invariants.
- [Configuration](Configuration.md): TOML keys, environment overrides, and safe defaults.
- [Collectors](Collectors.md): platform/runtime coverage, cache, and completeness semantics.
- [Operations](Operations.md): service lifecycle, state layout, queue behavior, and updates.
- [Security](Security.md): trust boundaries, collected data, hardening, and residual risks.
- [Troubleshooting](Troubleshooting.md): symptoms, checks, and recovery actions.
- [Development](Development.md): build, test, CI, fixtures, and contribution rules.
- [Roadmap](Roadmap.md): remaining engineering work and release direction.

## Five-minute setup

```bash
git clone https://github.com/onixus/Lariska.git
cd Lariska
cargo build --release
```

Create a protected provisioning-key file and a TOML configuration:

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = "/etc/lariska/provisioning.key"
state_dir = "/var/lib/lariska"
inventory_interval_secs = 3600
heartbeat_interval_secs = 60
request_timeout_secs = 30
inventory_full_refresh_interval_secs = 86400
max_spool_entries = 200
log_level = "info"
```

Then validate before running:

```bash
lariska check-config --config /etc/lariska/lariska.toml
lariska inventory --output json
lariska run --config /etc/lariska/lariska.toml --service
```

Use the complete [installation guide](../docs/INSTALL.md) for systemd, launchd, and Windows SCM deployment.

## Current behavior at a glance

- The daemon publishes only authoritative snapshots. A failed required collector does not erase server-side software state.
- Repeated scans use a bounded persistent cache when source fingerprints are unchanged.
- Inventory scheduling is jittered, non-overlapping, and less frequent on battery.
- Snapshots are written to a compressed local spool before delivery.
- Delivery, authentication, and network retry are independent from collection.
- Managed settings are validated locally and cannot replace local transport or credential policy.
- Local state and untrusted metadata are read under explicit size/item limits.

## Support boundary

Supported today:

- Linux package databases through dpkg, RPM, and pacman;
- Windows uninstall registry, loaded user hives, and selected CBS KB entries;
- macOS application bundles and Homebrew;
- Python, Node.js, and Java runtime metadata;
- Linux, Windows, and macOS native service modes.

Not yet complete:

- side-by-side installation identity in schema v1;
- source-aware partial snapshot carry-forward;
- Snap, Flatpak, MSIX/AppX, macOS receipts, and additional runtime ecosystems;
- signed release manifests and automatic update health rollback;
- zstd wire transport and delta submission;
- published endpoint-impact benchmark baselines.

The authoritative remaining work is tracked in [WORKPLAN_RU.md](../WORKPLAN_RU.md).
