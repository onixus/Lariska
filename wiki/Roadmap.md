# Roadmap

The executable milestone plan is maintained in [WORKPLAN_RU.md](../WORKPLAN_RU.md). The architectural rationale and invariants are in [Plan.md](../Plan.md). This page is the compact navigation view.

## Completed baseline

- cross-platform Rust project and CI;
- persistent endpoint identity and provisioning authentication;
- registration and independent heartbeat;
- Linux, Windows, macOS, Python, Node.js, and Java inventory;
- bounded command/file handling and trusted executable resolution;
- authoritative-only snapshot publication;
- persistent fingerprint cache and periodic cold refresh;
- jittered, non-overlapping, battery-aware scheduling;
- compressed bounded spool and quarantine;
- independent delivery worker and persistent accepted state;
- locally validated managed intervals/log levels;
- native service definitions and basic release artifacts.

## P0: correctness and update trust

### Inventory schema v2

- separate product identity from installation identity;
- preserve side-by-side versions;
- add package IDs, scope, and privacy-safe instance evidence;
- support mixed v1/v2 fleets.

### Per-source completeness

- report `complete`, `partial`, `failed`, and `not_applicable` per source;
- carry forward the last complete set for degraded sources;
- allow healthy sources to advance independently;
- suppress removal events unless the source completed.

### Signed recoverable updater

- stream to disk under declared and hard size limits;
- verify signed release manifests with embedded trust;
- add anti-rollback rules;
- install through platform-native mechanisms;
- require post-restart health and roll back automatically.

## P1: measurable endpoint impact

- cooperative collection deadlines/file/byte/item budgets;
- per-source duration, cache, completeness, read, and process metrics;
- cold/warm benchmark suite;
- soak tests for large inventories and long outages;
- published workstation/server baselines and regression thresholds.

## P1: coverage

- Snap and Flatpak;
- improved RPM and pacman identity;
- MSIX/AppX and ARM64 Windows views;
- macOS package receipts and signing identity;
- additional opt-in runtime ecosystems;
- coordinated Shapoclyack advisory/matching support.

## P1: production packaging

- verified deb/RPM build and install tests;
- signed MSI;
- signed/notarized macOS package;
- package-owned update path;
- install/upgrade/rollback/uninstall matrix;
- provenance/attestation in release workflow.

## P2: transport efficiency

- bounded zstd request decoding in Shapoclyack;
- wire compression after decompression-bomb protection;
- delta protocol with explicit base acknowledgement and full recovery snapshots.

## P2: operator experience

- bounded `lariska diagnostics` command;
- queue/cache/source freshness in Shapoclyack;
- runbooks for auth, TLS, collector, spool, cache, and update failures;
- documented state migration and identity recovery.

## Release direction

### 0.4.x

Target: schema-v2 groundwork, source completeness contract, and collection budgets/telemetry.

### 0.5.x

Target: signed streaming updater, native package ownership, and health rollback.

### 0.6.x

Target: expanded collectors, production packaging, and published performance baselines.

### 1.0 criteria

- no known path from partial collection to false removals;
- side-by-side installation identity supported end to end;
- signed and recoverable update path on supported platforms;
- tested native packages and service lifecycle;
- explicit support matrix and benchmark SLOs;
- stable versioned API contract and mixed-version rollout procedure;
- operator diagnostics and runbooks;
- release signing/provenance and documented security response process.

Version numbers are planning labels, not a license to stuff unrelated work into one release. Milestones may move when evidence says they should; invariants do not.
