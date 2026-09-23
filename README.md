# Lariska

Lariska is a lightweight, cross-platform endpoint inventory agent for the Shapoclyack platform.
It collects software inventory, runtime packages, virtualization/container metadata, and submits versioned endpoint snapshots with compressed local spooling and crash recovery.

---

## ⚡ Key Features

* **Low Host Impact**:
  * **Background Scheduling**: Uses background/idle process priority (`nice 19`, Windows EcoQoS, Darwin background QoS) and makes a best-effort preference for efficiency cores on supported hybrid systems.
  * **Bounded Collection**: External commands have time and output limits; metadata files, spool entries, and response bodies are read with explicit size ceilings.
  * **Persistent Collector Cache**: Versioned, bounded cache entries reuse normalized platform and runtime inventory when cheap metadata fingerprints are unchanged; periodic full refreshes prevent stale data from becoming permanent.
  * **Battery & Fleet Awareness**: Detects AC/battery state, stretches inventory frequency on battery power, prevents overlapping collections, and applies deterministic per-agent jitter to avoid fleet-wide scan bursts.
* **Deep Inventory & Shadow IT Detection**:
  * **OS Packages**: Linux (`dpkg`, `rpm`, `pacman`), Windows Registry (64-bit and 32-bit `Uninstall` views plus selected servicing updates), and macOS application bundles/Homebrew.
  * **Runtime Packages**: Python (`site-packages` and `*.dist-info/METADATA` without spawning interpreters), global Node.js packages, and installed Java runtimes/JDKs.
  * **Environment Classifier**: Detects common container, hypervisor, and cloud environments including Docker, Podman, Kubernetes, containerd, KVM/QEMU, VMware, VirtualBox, Hyper-V, AWS, and GCP.
* **Security & Hardening**:
  * **Trusted Executable Resolution**: External collectors are resolved only from approved system directories instead of the ambient `PATH`.
  * **Identifier Hashing**: Platform identifiers are normalized and one-way hashed before submission.
  * **Secret-Safe Telemetry**: Provisioning keys and JWTs are not logged; error details and response bodies are bounded.
  * **Authoritative Snapshots Only**: A timed-out or failed collector does not publish a partial snapshot that could be misinterpreted as mass software removal.
* **Remote Management**:
  * **Settings without Restart**: Heartbeat/inventory intervals and log level can be managed through Shapoclyack; server URL, credentials, state paths, and transport-security switches remain local-only.
  * **Verified Self-Upgrade**: An offered build is downloaded through the configured TLS trust, checked against the published SHA-256, refused for a foreign target triple, and installed while retaining the previous binary for rollback.
* **Resilient Delivery**:
  * **Compressed Local Spool**: Pending snapshots are stored as `.json.zst`; HTTP inventory submission currently uses the full versioned JSON contract.
  * **Spool-then-Submit**: A durable file-based FIFO queue provides atomic persistence, bounded retry, terminal quarantine, and restart recovery.
  * **Bounded Recovery**: Pending snapshots are decoded and delivered one at a time; compressed and decompressed sizes are limited.
  * **Local Diff Model**: The model can calculate `added`, `removed`, and `modified` software entries. The current delivery contract submits full snapshots and lets Shapoclyack compute persisted changes.
  * **Crash Reporter**: A panic hook writes a bounded local crash report that is detected on the next start.

---

## 📦 Install and Connect

Download the archive for your platform from the [latest GitHub release](https://github.com/onixus/Lariska/releases/latest), create a tenant provisioning key in Shapoclyack, and configure Lariska with the Shapoclyack server URL and the path to that key.

See [Installation and Shapoclyack connection](docs/INSTALL.md) for Linux, macOS, and Windows setup, service installation, verification, and troubleshooting.

---

## 🛠️ Development & CI

```bash
# Code formatting check
cargo fmt --check

# Strict Clippy linter
cargo clippy --all-targets --all-features -- -D warnings

# Full test suite
cargo test --all-targets --all-features

# Build optimized release binary
cargo build --release
```

GitHub Actions runs formatting, Clippy, tests on Linux/Windows/macOS, dependency and license checks, secret scanning, APEX contract validation, and a cross-repository Shapoclyack fixture. A declarative [Jenkinsfile](Jenkinsfile) is also included for local CI deployments.

---

## 🚀 Usage

### Diagnostic Local Scan (No Network)

```bash
# Print normalized canonical inventory JSON to stdout
cargo run -- inventory --output json
```

Diagnostic output may include partial results and collector warnings. The daemon is stricter: it submits only authoritative snapshots for which all required collectors completed.

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

* **[Installation](docs/INSTALL.md)** — Deployment, service configuration, verification, and troubleshooting.
* **[Security hardening](docs/hardening.md)** — Collection bounds, hashing policy, secrets management, and service isolation.
* **[Release procedures](docs/RELEASE.md)** — Publishing, upgrade, rollback, and disaster recovery.
* **[Changelog](CHANGELOG.md)** — Version history and release notes.
* **[Packaging](packaging/)** — Native service definitions and installers for systemd, launchd, and Windows SCM.
