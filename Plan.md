# Lariska Technical Plan

Status: active architecture and delivery plan for the 0.3.x line. Last reviewed: 2026-09-23.

## 1. Purpose and boundary

Lariska is the endpoint-side inventory agent for [Shapoclyack](https://github.com/onixus/Shapoclyack). It owns local identity, bounded collection, durable queueing, heartbeat, remote policy application, and delivery of versioned endpoint snapshots.

Lariska does **not** own vulnerability matching, advisory ingestion, tenant asset policy, findings lifecycle, or network-scan jobs. Those remain server responsibilities. The endpoint communicates only through the documented Shapoclyack HTTP API; it never connects directly to Shapoclyack databases, Kafka, NATS, or internal workers.

## 2. Current production baseline

The following capabilities are implemented in the current source tree:

- stable Rust project building on Linux, Windows, and macOS;
- persistent random agent identity and hashed platform evidence;
- provisioning-key exchange for short-lived JWTs;
- idempotent registration and independent heartbeat loop;
- Linux, Windows, macOS, Python, Node.js, and Java inventory collectors;
- deterministic normalization and inventory schema v1;
- authoritative-only daemon submission when all required collectors complete;
- persistent per-collector cache with bounded fingerprints and forced full refresh;
- battery-aware, jittered, non-overlapping inventory scheduling;
- compressed durable spool with bounded decompression and quarantine;
- a delivery worker decoupled from inventory collection;
- persistent accepted-state digest across restarts;
- locally validated managed intervals and log levels;
- service integration for systemd, launchd, and Windows SCM;
- verified target/SHA-256 self-update path;
- cross-platform CI, dependency policy, secret scanning, APEX contract validation, and shared Shapoclyack fixtures.

The historical bootstrap phases are complete. This document therefore describes the architecture that must be preserved and the next changes that remain, rather than pretending the repository is still waiting for `Cargo.toml` to appear.

## 3. Architecture

```text
CLI / native service entry
        |
        v
app lifecycle ---------------------------------------------------+
  |               |                    |                         |
  v               v                    v                         v
heartbeat     inventory scheduler   managed policy          shutdown/update
  |               |                    |                         |
  |               v                    |                         |
  |       platform/runtime collectors  |                         |
  |               |                    |                         |
  |          fingerprint cache <-------+                         |
  |               |                                              |
  |         normalization and validation                         |
  |               |                                              |
  |         authoritative snapshot                               |
  |               |                                              |
  |          durable zstd spool                                  |
  |               |                                              |
  +----------> delivery worker ----------------------------------+
                  |
                  v
             Shapoclyack API
```

### Module responsibilities

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI dispatch and process exit status |
| `app.rs` | lifecycle orchestration, scheduling, shutdown, wiring of independent loops |
| `config.rs` | TOML/environment loading, local security policy, bounds validation |
| `identity.rs` | persistent agent identity and platform identifier hashing |
| `model.rs` | schema v1 wire model, normalization, deterministic ordering, local diff model |
| `auth.rs` | provisioning-key exchange, in-memory token cache, refresh |
| `api.rs` | bounded HTTP client and response classification |
| `heartbeat.rs` | registration, heartbeat, managed directive reception |
| `managed.rs` | validation/application of remote settings and staged update handling |
| `inventory/*` | platform/runtime collection, completeness, environment detection, cache fingerprints |
| `delivery/*` | queue policy, persisted accepted state, HTTP retry, quarantine, spool lifecycle |
| `qos.rs` | background priority, efficiency-core preference, power-source detection |
| `service.rs` | instance locking, native service integration, shutdown signals |
| `telemetry.rs` | structured logs and runtime log filtering |
| `crash.rs` | bounded panic report and recovery notice |

## 4. Non-negotiable invariants

Every change must preserve these properties:

1. **No partial state becomes authoritative.** A failed required collector cannot cause server-side removal events.
2. **Collection is independent from delivery.** Authentication, network retry, and server outages cannot block or stretch the local collection schedule.
3. **One collection at a time.** Slow hosts do not accumulate catch-up scans or overlapping filesystem walks.
4. **Memory is proportional to one bounded item.** Command output, files, cache entries, HTTP bodies, and spool recovery are capped before unbounded allocation.
5. **Disk state is atomic.** Identity, snapshots, cache entries, and accepted-state metadata are written through temporary files and rename where applicable.
6. **Secrets remain local and absent from logs.** Provisioning keys are read from protected files; JWTs stay in memory.
7. **Remote policy has a local safety boundary.** The endpoint validates all managed values and never accepts remote changes to server URL, credential paths, state paths, or transport-security switches.
8. **The ambient `PATH` is not trusted.** External collectors resolve commands only from approved system directories and do not invoke a shell.
9. **Retries are idempotent.** Snapshot IDs survive retries, and successful acknowledgement is the only condition for removal from the spool.
10. **Contract changes are cross-repository changes.** Any incompatible inventory model change requires Shapoclyack support, fixtures in both repositories, migration behavior, and documented rollout order.

## 5. Runtime flows

### 5.1 Startup

1. Load TOML and environment overrides.
2. Validate URL policy, intervals, timeout, secret path, and service-mode paths.
3. Initialize safe telemetry and crash recovery.
4. Apply background scheduling policy.
5. Acquire the state-directory single-instance lock.
6. Load or create the stable agent identity.
7. Build the API/auth clients and restore delivery state.
8. Register with bounded startup retry.
9. Start heartbeat, inventory, delivery, shutdown, and update control paths.

### 5.2 Inventory

1. Compute the agent-specific scheduled delay.
2. Stretch the recurring interval when the endpoint is on battery.
3. Fingerprint supported sources.
4. Reuse a complete, compatible, unexpired cache entry when the fingerprint is unchanged.
5. Otherwise execute the collector under its output/time/file limits.
6. Merge platform and runtime results while propagating completeness.
7. Normalize, sort, and deduplicate according to schema v1.
8. If incomplete, log bounded warnings and keep the last accepted server state unchanged.
9. If complete, atomically enqueue the snapshot and wake the delivery worker.

### 5.3 Delivery

1. Enumerate pending paths oldest first without decoding the whole backlog.
2. Decode and validate one snapshot under compressed and decompressed limits.
3. Obtain or refresh an in-memory JWT.
4. Submit with `Idempotency-Key: <snapshot_id>`.
5. Retry transient failures with bounded exponential jitter and `Retry-After` support.
6. Quarantine payload-specific terminal failures and continue to later entries.
7. Stop the current drain on systemic network/auth failures and retry at the worker cadence.
8. On acknowledgement, persist the semantic digest and acceptance time, then remove the spool entry.

### 5.4 Managed policy

Managed heartbeat interval, inventory interval, and log level are optional. A revision is applied atomically only when every supplied value is locally valid. Invalid revisions are rejected without changing runtime state or falsely marking the revision as applied.

## 6. Inventory contract v1

The request remains a flat, versioned document:

```json
{
  "schema_version": 1,
  "snapshot_id": "...",
  "agent_id": "agent_...",
  "collected_at": "2026-09-23T10:00:00Z",
  "hostname": "workstation-17",
  "os_family": "linux",
  "os_name": "Ubuntu 24.04.3 LTS",
  "os_version": "24.04",
  "os_arch": "x86_64",
  "agent_version": "0.3.1",
  "labels": {},
  "identifiers": [],
  "software": [],
  "collector_warnings": []
}
```

The shared fixture in `tests/fixtures/inventory_v1.json` is the executable contract. Schema v1 comparison identity is based on normalized name, publisher, architecture, and source; version is an attribute. This limitation is why multiple side-by-side installation instances can collapse and why schema v2 is a priority rather than a decorative future idea.

## 7. Local state

The configured `state_dir` can contain:

- persistent agent identity and the process lock;
- `spool/*.json.zst` pending snapshots;
- `spool/quarantine/` invalid or terminally rejected snapshots;
- `inventory-cache-v1/` bounded platform/Python/Node.js/Java cache documents;
- `delivery-state-v1.json` with the last accepted semantic digest and timestamp;
- a bounded crash report after an unexpected panic;
- staged update files and the retained previous executable when the update path is used.

Operators may inspect metadata and logs, but must not hand-edit queue/cache files while the service is running. Deleting cache is recoverable and forces a fresh scan; deleting identity creates a different endpoint and is therefore not routine cleanup.

## 8. Performance and host-impact policy

The agent prefers predictable ceilings over optimistic average behavior:

- process priority is background/idle where supported;
- efficiency-core affinity is best effort, never a correctness dependency;
- command execution has wall-clock and output limits;
- metadata reads and cache files are bounded;
- cache fingerprints are capped by item count;
- runtime filesystem collectors run without racing each other for disk bandwidth;
- startup and recurring jitter spread fleet load;
- battery operation increases the interval;
- delivery backlog is decoded one entry at a time;
- no network operation runs on the inventory critical path.

Published benchmark baselines are still required. They must report collection wall time, process CPU time, peak RSS, bytes/files read, external command count, cache hit ratio, queue age, and source completeness on representative workstation and server profiles.

## 9. Security model

Trust boundaries:

- the local configuration and provisioning key are operator-controlled;
- the Shapoclyack API is trusted only through configured TLS roots and authenticated responses;
- package databases, registry values, plist files, and runtime metadata are untrusted input;
- ambient environment variables and `PATH` are not trusted command sources;
- spool/cache files are untrusted after a crash or external modification and must be bounded and validated.

Current update verification checks TLS policy, target triple, and SHA-256. The target design adds a signed release manifest, streaming size enforcement, anti-rollback policy, native package installation, post-restart health acknowledgement, and automatic rollback.

## 10. Testing and release gates

Required pull-request gates:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

CI must additionally cover Linux, Windows, and macOS; dependency advisories; license/source policy; secret scanning; APEX contract validation; and the Shapoclyack fixture. Contract, queue, cache, scheduler, and updater changes require focused regression tests for malformed, oversized, interrupted, and replayed inputs.

Release artifacts should include binaries, SHA-256 checksums, SBOM, release notes, and documented provenance. Production distribution additionally requires native package signing/notarization where the platform supports it.

## 11. Active roadmap

### P0: Inventory schema v2 and source-aware completeness

- represent product identity separately from installation identity;
- carry package ID, scope, instance ID, and privacy-safe location/user evidence;
- preserve side-by-side versions;
- add per-source `complete`, `partial`, `failed`, and `not_applicable` status;
- let Shapoclyack carry forward failed sources instead of rejecting the whole cycle;
- provide dual-read/dual-write rollout and v1 fallback.

Acceptance: a failed Python collector cannot remove Python entries, while a complete dpkg result can still update Linux packages; JDK 17 and JDK 21 remain distinct installations.

### P0: Signed, streaming, recoverable updates

- enforce declared and hard maximum size while streaming to disk;
- hash during download and fsync before installation;
- verify an embedded-key signed release manifest;
- enforce anti-rollback policy;
- use platform-native package/update mechanisms where required;
- require health acknowledgement after restart and rollback automatically on failure.

Acceptance: an interrupted, oversized, foreign, unsigned, downgraded, or unhealthy update leaves the previous agent operational.

### P1: Collection budgets and measurable SLOs

- add a shared cooperative deadline/file/byte/item budget;
- expose per-source duration, cache hit, completeness, and item counts;
- add benchmark and soak scenarios for large inventories and long offline queues;
- publish workstation/server baselines and regression thresholds.

### P1: Collector and advisory coverage

- Linux: Snap, Flatpak, RPM epoch/distribution identity;
- Windows: MSIX/AppX, stronger package IDs, ARM64 distinctions;
- macOS: package receipts, bundle identifiers, signing team metadata;
- runtimes: opt-in user environments and additional ecosystems;
- coordinate Shapoclyack advisory providers so extra data is actually actionable.

### P1: Production packaging

- verify `.deb` and RPM builds in native packaging CI;
- produce signed MSI and notarized macOS package;
- define upgrade ownership for package-managed installations;
- test install, upgrade, rollback, and uninstall while preserving identity/state.

### P2: Transport efficiency

- negotiate bounded zstd HTTP request decoding in Shapoclyack;
- enable wire compression only after server-side decompression-bomb protection;
- evaluate delta submission with explicit base snapshot acknowledgement and full-snapshot recovery.

### P2: Operator diagnostics

- add a bounded local diagnostics command that reports source status, cache age, queue depth/age, and last accepted state without exposing secrets or full inventory;
- document supported cleanup and recovery procedures;
- surface endpoint freshness and degraded-source state in Shapoclyack.

The executable Russian roadmap, milestones, dependencies, and acceptance criteria are maintained in [WORKPLAN_RU.md](WORKPLAN_RU.md).
