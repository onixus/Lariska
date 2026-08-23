# Lariska

Lariska is a high-performance, lightweight, cross-platform endpoint inventory agent designed for the Shapoclyack platform.
It collects software inventory, runtime packages (Shadow IT detection), virtualization/container environment metadata, and delivers compressed, versioned snapshots with local spooling and crash recovery.

---

## ⚡ Key Features

* **Zero Footprint & Low Host Impact (QoS & E-Core Pinning)**:
  * **E-Core Isolation**: Automatically detects and restricts execution strictly to Efficiency cores (E-cores / LITTLE cores / compact cores) on **Apple Silicon (M1–M4)**, **Intel Hybrid (Alder/Raptor Lake, Core Ultra)**, **AMD Hybrid (Zen 4c / Zen 5c via CPPC)**, and **ARM big.LITTLE**, avoiding interference with user and foreground processes.
  * **QoS & EcoQoS**: Sets background priority (`nice 19` / `IDLE_PRIORITY_CLASS` / `ProcessPowerThrottling` / Darwin BG).
  * **Battery & Power Awareness**: Detects battery vs AC power (`host.power_source`), adapting inventory frequency.
* **Deep Inventory & Shadow IT Detection**:
  * **OS Packages**: Linux (`dpkg`, `rpm`, `pacman`), Windows (Registry / 64-bit & 32-bit `Uninstall`), macOS (`/Applications` `Info.plist` + `brew list --versions`).
  * **Runtime Packages**: Python (`site-packages` / `*.dist-info/METADATA` parser without spawning interpreters), Node.js (global `npm` packages and `package.json`), Java (JVM / JDK `release` metadata).
  * **Environment Classifier**: Auto-detects Docker, Podman, Kubernetes, containerd, KVM/QEMU, VMware, VirtualBox, Hyper-V, AWS EC2, and GCP.
* **Security & Hardening**:
  * **PATH-Hijacking Protection**: Strict executable resolution against trusted system directories with directory traversal prevention.
  * **Identifier Hashing**: One-way SHA-256 pseudonymized hardware identifiers (`/etc/machine-id`, `MachineGuid`, `IOPlatformUUID`).
  * **Zero-Leak Telemetry**: Redacted secret paths, in-memory-only JWTs, bounded sanitized error messages.
* **Resilient Delivery & Delta Sync**:
  * **zstd Compression**: Spool entries saved as `.json.zst` and transmitted with `Content-Encoding: zstd`.
  * **Spool-then-Submit**: Durable local SQLite/file-based FIFO queue with exponential jittered backoff, terminal quarantine, and crash recovery.
  * **Delta-Sync Engine**: Computes granular `added` / `removed` / `modified` diffs between snapshots.
  * **Crash Reporter**: Global panic hook writing `crash_report.json` to disk, recovered and logged on restart.

---

## 📦 Install and Connect

Download the archive for your platform from the [latest GitHub release](https://github.com/onixus/Lariska/releases/latest), create a tenant provisioning key in Shapoclyack, and configure Lariska with the Shapoclyack server URL and the path to that key.

See [Installation and Shapoclyack connection](docs/INSTALL.md) for complete Linux, macOS, and Windows instructions, service setup, verification, and troubleshooting.

---

## 🛠️ Development & CI

```bash
# Code formatting check
cargo fmt --check

# Strict Clippy linter
cargo clippy --all-targets --all-features -- -D warnings

# Full test suite (51 library tests + 2 binary tests)
cargo test --all-targets --all-features

# Build optimized release binary
cargo build --release
```

### Local Jenkins CI Pipeline
Lariska includes a declarative [Jenkinsfile](file:///Users/onixus/Git/Lariska/Jenkinsfile) configured for local Jenkins at `http://localhost:8081/job/lariska/`. Every push runs formatting, clippy, test matrix, and release artifact builds in an isolated `rust:1-bookworm` container.

---

## 🚀 Usage

### Diagnostic Local Scan (No Network)

```bash
# Print normalized canonical inventory JSON to stdout
cargo run -- inventory --output json
```

### Validate Configuration

```bash
cargo run -- check-config --config lariska.toml
```

### Run Agent Service / Daemon

```bash
# Standalone agent process
cargo run -- run --config lariska.toml

# As a native system service (systemd / launchd / Windows SCM)
lariska run --config /etc/lariska/lariska.toml --service
```

---

## 📖 Documentation Reference

* **[docs/INSTALL.md](file:///Users/onixus/Git/Lariska/docs/INSTALL.md)** — Step-by-step deployment and service configuration guide.
* **[docs/hardening.md](file:///Users/onixus/Git/Lariska/docs/hardening.md)** — Security architecture, data collection bounds, hashing policy, and secrets management.
* **[docs/RELEASE.md](file:///Users/onixus/Git/Lariska/docs/RELEASE.md)** — Release procedures, service installation, upgrade, rollback, and disaster recovery.
* **[CHANGELOG.md](file:///Users/onixus/Git/Lariska/CHANGELOG.md)** — Complete version history and release notes.
* **[packaging/](file:///Users/onixus/Git/Lariska/packaging)** — Native service definitions for `systemd`, `launchd`, and Windows SCM.
