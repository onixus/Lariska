# Changelog

All notable changes to the Lariska endpoint inventory agent will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-15

### Added
- **Remote management (Shapoclyack #358).** An operator changes what this agent
  does, and which build it runs, from the console instead of from the machine.
  The decision travels in the heartbeat response — the only channel that
  reaches a running agent — and is acted on here: intervals and log level take
  effect on the next tick, with no restart, and a build is downloaded with the
  agent's own token, checked against the sha256 the heartbeat named, and put in
  place of the installed binary, which is moved aside rather than deleted. A
  revision is applied once; the server repeating it changes nothing.
  `server_url`, the provisioning key and `state_dir` are not settable remotely:
  an agent that can be told where to report can be told to report somewhere
  else, through the very channel carrying the instruction. An upgrade is
  refused over plain HTTP unless `allow_insecure_updates` is set — the build
  and its digest travel on the same connection, so without TLS the check proves
  nothing.
- **Windows: MSI, per-user installs and applied updates.** Uninstall entries
  installed by Windows Installer are reported as `msi` rather than lumped in
  with `winreg`; per-user software is read from the loaded profiles under
  `HKEY_USERS` (not `HKEY_CURRENT_USER`, which under a SYSTEM service is the
  service's own hive); and the `KB` updates applied to the running build are
  read from Component Based Servicing, in state 112 only, because a package key
  exists for staged and superseded packages too. A Microsoft advisory is
  matched against an OS build plus the updates on top of it, so an inventory
  without them could not answer whether a host is patched.

### Fixed
- **The collapse of duplicate entries kept the wrong build.** The server holds
  `UNIQUE(snapshot_id, comparison_key)` on a key that excludes the version, so
  a host with two versions of one product installed cannot report both, and the
  greater one survives. "Greater" was decided by string order, where `"1.9.0"`
  beats `"1.10.0"` — so the inventory named a build the host had already
  replaced. Versions now compare by numeric component. The warning also names
  both versions in plain text instead of rendering them as Rust's
  `Some("8.0.61001")`.

### Fixed
- **The provisioning-key exchange used a path the API has never served.**
  `AUTH_EXCHANGE_PATH` was `/api/v1/auth/exchange`; Shapoclyack serves it at
  `/api/auth/agent/token` and has no `/api/v1` prefix at all, so the agent 404'd
  on its first request against any real deployment and never obtained a token —
  on every platform. Both wiremock tests hard-coded the same wrong path, so the
  suite passed by agreeing with the bug; they now reference the constant.
- **A Windows service was silent.** Logging went to stdout, which the SCM does
  not attach, so an installed service produced no log at all — including the
  reason it failed to start. The Windows service path now logs to
  `state_dir\lariska.log`, rotated once at 8 MiB. Gated on Windows: the systemd
  unit and the launchd job also pass `--service`, and there stdout is where the
  log belongs.
- **`docs/INSTALL.md` documented a configuration the agent rejects.** The
  Windows paths were given as TOML basic strings, where `"C:\ProgramData\..."`
  is a parse error on the `\P` escape. They are literal strings now.

### Added
- **OS product name and version on Windows.** Every snapshot previously reported
  `os_name` as the bare platform (`"windows"`) with `os_version` `null`;
  `detect_os_release` now reads `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
  and returns the product name and `major.minor.build.ubr`, the form MSRC uses.
  Windows 11 is recognised by build number, because its `ProductName` still
  reads "Windows 10". Linux and macOS still report the bare platform name with
  no version — their collectors are not written.
- **`packaging/windows/install-lariska.cmd` and `uninstall-lariska.cmd`.**
  Batch rather than PowerShell: the environments this agent targets commonly
  forbid running PowerShell scripts by policy. The installer restricts the data
  directories to SYSTEM and Administrators, validates the configuration with
  `check-config` before registering anything, and leaves the state directory
  alone on reinstall so the device keeps its identity. Neither script has been
  executed on Windows yet.

## [0.2.0] - 2026-08-23

### Added
- **PATH-Hijacking Hardening & Safe Path Resolution**:
  - Implemented `find_trusted_binary` restricting executable lookups to trusted system locations (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/opt/homebrew/bin`, `/usr/local/bin`) with path traversal (`../`) prevention.
- **Deep Inventory & Shadow IT Runtime Package Collectors**:
  - **Python**: Direct filesystem metadata parser for `site-packages` / `dist-packages` `*.dist-info/METADATA` extracting package names, versions, and authors without spawning python interpreters.
  - **Node.js**: Global `npm` package scanner parsing root and scoped (`@org/pkg`) `package.json` files.
  - **Java**: Automatic JVM / JDK detector parsing `release` metadata (`JAVA_VERSION`, `IMPLEMENTOR`, `OS_ARCH`).
- **Environment & Virtualization Classifier**:
  - Auto-detection for containers (Docker `/.dockerenv`, Podman `/run/.containerenv`, Kubernetes `KUBERNETES_SERVICE_HOST`, containerd cgroups) and hypervisors/clouds (KVM/QEMU, VMware, VirtualBox, Hyper-V, AWS Nitro/EC2, GCP).
  - Automatically enriches agent `labels` with `env.type`, `env.container_engine`, `env.hypervisor`, `env.cloud_provider`.
- **E-Core Pinning & Heterogeneous CPU Scheduling (QoS)**:
  - **macOS**: `PRIO_DARWIN_BG (0x1000)` and `QOS_CLASS_BACKGROUND` routing execution strictly to Apple Silicon Efficiency cores (E-cores).
  - **Linux**: CPU affinity locking via `sched_setaffinity` on Intel Atom E-cores (`/sys/.../types/cpu_atom/cpus`), AMD Zen 4c / Zen 5c compact cores (via ACPI CPPC `highest_perf`), and ARM big.LITTLE (`cpu_capacity`).
  - **Windows**: Windows 11 / 10 EcoQoS via `ProcessPowerThrottling` (`PROCESS_POWER_THROTTLING_EXECUTION_SPEED`) and `IDLE_PRIORITY_CLASS`.
- **Battery & Power Awareness**:
  - Cross-platform battery power detection (`is_on_battery()`) tagging `host.power_source` (`battery` / `ac`).
- **Crash Recovery & Panic Hook**:
  - Structured panic capture via `init_panic_hook`, saving sanitized diagnostic reports (`crash_report.json`) in `state_dir`, with automatic recovery, logging, and archiving upon agent restart.
- **Data Compression & Delta Synchronization**:
  - Local spool storage in `.json.zst` format with backward compatibility for uncompressed entries.
  - Transparent HTTP compression sending `Content-Encoding: zstd`.
  - In-memory `InventorySnapshot::diff()` engine computing added, removed, and modified software deltas.
- **CI/CD Pipeline in Jenkins**:
  - Declarative Jenkins pipeline ([`Jenkinsfile`](file:///Users/onixus/Git/Lariska/Jenkinsfile)) running in `rust:1-bookworm` with Cargo caching, code formatting check, strict Clippy linter, 53 unit/contract tests, release binary compilation, and artifact archiving.

## [0.1.3] - 2026-07-28

- Refresh dependencies and publish release binaries.

## [0.1.2] - 2026-07-27

- Fix the Windows archive output path so the `.zip` and checksum are attached to the GitHub release.
- Fail the release build when a platform produces no uploadable artifacts.

## [0.1.1] - 2026-07-27

- Publish the initial cross-platform Lariska agent release.
- Build archives for Linux x86_64/aarch64, Windows x86_64, and macOS x86_64/Apple Silicon.
- Generate SHA-256 checksum files and a CycloneDX SBOM.
- Fix release checksums on Windows runners by using Python's portable standard-library implementation.
