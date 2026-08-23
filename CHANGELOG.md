# Changelog

All notable changes to the Lariska endpoint inventory agent will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
