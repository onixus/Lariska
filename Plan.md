# Lariska Endpoint Inventory Agent вЂ” AI Implementation Plan

## 1. Purpose

Lariska is a cross-platform endpoint agent for the
[Shapoclyack](https://github.com/onixus/Shapoclyack) platform. Its first
production capability is software inventory: identify the endpoint, collect a
normalized list of installed software, and deliver versioned inventory
snapshots to the Shapoclyack API.

Lariska is not the existing Shapoclyack remote network-scanner agent. Do not
implement scan-job claim or scan-result archive upload in this project unless a
later design explicitly merges the two roles.

## 2. Definition of done

The initial production release is complete when:

- the project builds with stable Rust on Linux, Windows, and macOS;
- the agent obtains a short-lived JWT using a Shapoclyack provisioning key;
- the agent registers and sends periodic heartbeats;
- each supported OS produces a normalized software inventory;
- the agent submits a versioned inventory payload over HTTPS;
- delivery is idempotent and survives temporary server/network failure;
- secrets and JWTs never appear in logs;
- the process can run as a native background service;
- unit, contract, and platform smoke tests run in CI;
- release artifacts and checksums are published for all supported platforms.

## 3. Required coordination

This implementation depends on the server work described in
`SHAPOCLYACK_BACKLOG.md`.

Before implementing network submission, freeze these server contracts:

1. Authentication: `POST /api/v1/auth/exchange`.
2. Registration: `POST /api/agent/register`.
3. Heartbeat: `POST /api/agent/heartbeat`.
4. Inventory ingest: proposed `POST /api/v1/endpoint/inventory`.
5. Inventory schema version: initial value `1`.
6. Maximum payload size and maximum number of software entries.
7. Idempotency behavior and expected response codes.

Use a shared JSON fixture in both repositories to prevent contract drift.

## 4. Non-goals for the first release

- vulnerability assessment of installed packages;
- automatic software removal or remediation;
- arbitrary remote command execution;
- user activity collection;
- file-content scanning;
- direct database or NATS access from an endpoint;
- using hostname alone as the permanent device identity;
- replacing Shapoclyack's existing network-scanner agent.

## 5. Target architecture

Keep the executable small and divide responsibilities into explicit modules:

```text
src/
  main.rs                 CLI entry point and exit codes
  app.rs                  orchestration and lifecycle
  config.rs               configuration loading and validation
  identity.rs             stable endpoint identity
  model.rs                versioned wire/domain models
  auth.rs                 provisioning-key exchange and token refresh
  api.rs                  Shapoclyack HTTP client
  heartbeat.rs            registration and heartbeat loop
  inventory/
    mod.rs                collector trait and normalization
    linux.rs
    windows.rs
    macos.rs
  delivery/
    mod.rs                submission policy
    spool.rs              durable local queue
    retry.rs
  service.rs              service lifecycle integration
  telemetry.rs            structured logs and metrics
tests/
  fixtures/
  contract/
```

Use dependency injection around command execution, clocks, randomness, file
storage, and HTTP so tests do not depend on the host machine.

## 6. Configuration contract

Support a configuration file plus environment overrides. Select one documented
format, preferably TOML. Do not accept secrets as normal CLI arguments because
they are visible in process listings.

Required settings:

| Setting | Purpose |
| --- | --- |
| `server_url` | Shapoclyack base URL |
| `provisioning_key_file` | Path to a protected file containing the bootstrap key |
| `state_dir` | Persistent identity and queue storage |
| `inventory_interval` | Full inventory collection interval |
| `heartbeat_interval` | Agent heartbeat interval |
| `request_timeout` | Per-request timeout |
| `tls_ca_file` | Optional private CA bundle |
| `log_level` | Runtime log filtering |

Optional settings:

- explicit proxy configuration;
- maximum spool size and retention;
- jitter percentage;
- platform collector timeouts;
- labels such as site, environment, or department;
- development-only allowance for plain HTTP, disabled by default.

Validation requirements:

- reject missing server URL and unreadable secret file;
- require HTTPS unless development mode is explicitly enabled;
- enforce safe minimum/maximum intervals and timeouts;
- reject relative state paths when running as a system service;
- never serialize secret values into diagnostics.

## 7. Wire models

Create versioned Serde models. Keep domain models separate from transport
responses.

Proposed inventory request:

```json
{
  "schema_version": 1,
  "snapshot_id": "018f...",
  "agent_id": "agent_...",
  "collected_at": "2026-07-24T08:00:00Z",
  "agent": {
    "version": "0.1.0",
    "hostname": "workstation-17",
    "labels": {
      "site": "helsinki"
    }
  },
  "os": {
    "family": "windows",
    "name": "Windows 11 Pro",
    "version": "24H2",
    "architecture": "x86_64"
  },
  "identifiers": [
    {
      "type": "machine_id",
      "value": "..."
    },
    {
      "type": "fqdn",
      "value": "workstation-17.example.local"
    }
  ],
  "software": [
    {
      "name": "Mozilla Firefox",
      "version": "141.0",
      "publisher": "Mozilla",
      "architecture": "x86_64",
      "source": "registry",
      "install_location": null
    }
  ]
}
```

Rules:

- `snapshot_id` is generated once and retained across retries;
- timestamps use UTC RFC 3339;
- optional data is represented as `null` or omitted consistently;
- software entries are sorted deterministically before hashing/submission;
- strings are trimmed and bounded;
- empty names are discarded;
- exact duplicates are removed;
- unknown versions remain absent rather than guessed.

## 8. Stable endpoint identity

Implement identity before authentication and inventory submission.

Recommended behavior:

1. On first start, create a random agent UUID and persist it atomically in the
   protected state directory.
2. Reuse the value on every subsequent start.
3. Collect platform identifiers as matching evidence, not as the sole local
   primary key.
4. Never derive identity from MAC address or hostname alone.
5. Detect unreadable/corrupt state and fail with a recovery-oriented error;
   never silently create a second identity.

Platform evidence:

- Linux: `/etc/machine-id` when available;
- Windows: `MachineGuid` and optionally hardware serial where permitted;
- macOS: `IOPlatformUUID`;
- all platforms: FQDN and hostname as secondary identifiers.

Document privacy implications. Hash identifiers client-side only if the server
contract adopts the same normalization and hashing algorithm.

## 9. Authentication and agent lifecycle

### 9.1 Token exchange

Call `POST /api/v1/auth/exchange` with:

```json
{
  "provisioning_key": "...",
  "agent_id": "agent_..."
}
```

Requirements:

- read the provisioning key only when required;
- keep JWTs in memory;
- refresh before expiration with randomized jitter;
- on `401`, refresh once and retry the original request once;
- distinguish invalid/revoked provisioning keys from transient errors;
- redact authorization headers and response bodies containing tokens.

### 9.2 Registration

Register after obtaining a JWT. Submit the stable `agent_id`, hostname, agent
version, and configured labels. Treat registration as idempotent.

### 9.3 Heartbeat

Send heartbeats independently of the inventory schedule. Use states:
`idle`, `busy`, and `error`. Include a short, sanitized detail string on
collector or delivery degradation. A failed heartbeat must not discard queued
inventory.

## 10. Platform collectors

Define a common collector trait that returns structured entries plus warnings.
A partial inventory is preferable to a crash, but the payload must say when a
collector was incomplete.

### 10.1 Linux

Initial sources:

- Debian/Ubuntu: `dpkg-query`;
- Fedora/RHEL-family: `rpm`;
- Arch-family: `pacman`;
- optional universal sources: Snap and Flatpak.

Requirements:

- detect available package managers;
- call commands directly without a shell;
- apply command timeouts and output-size limits;
- preserve package version and architecture;
- allow multiple sources on the same endpoint;
- report unsupported distributions without panicking.

### 10.2 Windows

Initial sources:

- 64-bit and 32-bit uninstall registry locations;
- both machine and current-user scopes where service permissions allow;
- avoid `Win32_Product` because it is slow and can trigger MSI repair.

Collect display name, version, publisher, architecture/view, and install
location when present. Use native Windows APIs or a well-maintained crate in
preference to parsing human-formatted PowerShell output.

### 10.3 macOS

Initial sources:

- application bundles under system and user application directories;
- Homebrew formulae and casks when Homebrew exists;
- optional package receipts through `pkgutil`.

Read bundle metadata rather than treating filenames as authoritative product
versions.

### 10.4 Normalization

Do not aggressively merge different products. Normalize whitespace, Unicode,
case-insensitive comparison keys, architecture names, and source names while
preserving original display values.

Unit tests must cover:

- malformed command output;
- missing versions;
- non-UTF-8 or replacement decoding;
- duplicate entries;
- very large inventories;
- command timeout and non-zero exit;
- platform-specific fixtures.

## 11. Durable delivery

Inventory collection and upload must be decoupled.

Workflow:

1. Collect and normalize inventory.
2. Serialize canonical JSON.
3. Compute a SHA-256 content digest.
4. If unchanged since the last acknowledged snapshot, send only when the
   configured full-refresh deadline is reached.
5. Write the snapshot atomically to the spool before sending.
6. Submit with `Idempotency-Key: <snapshot_id>`.
7. Remove it only after a successful server acknowledgement.

Retry policy:

- retry network errors, `408`, `425`, `429`, and `5xx`;
- honor `Retry-After`;
- use exponential backoff with full jitter and a maximum delay;
- do not retry validation errors indefinitely;
- refresh authentication once on `401`;
- stop and surface authorization errors on `403`;
- cap disk usage without deleting the newest unsent snapshot;
- quarantine malformed queue entries instead of looping forever.

The endpoint talks only to Shapoclyack HTTP. Shapoclyack owns any NATS publish.

## 12. Process lifecycle

Provide:

- `lariska run` for the long-running service;
- `lariska inventory --output json` for local diagnostics with no upload;
- `lariska check-config`;
- `lariska enroll` only if an explicit enrollment flow is later required;
- graceful shutdown on SIGTERM/Ctrl-C;
- single-instance locking for one state directory;
- explicit, documented exit codes.

Do not print the complete inventory by default because it can contain sensitive
organization data.

## 13. Native service packaging

### Linux

- systemd unit;
- dedicated non-login user;
- `/etc/lariska/lariska.toml`;
- state under `/var/lib/lariska`;
- hardened unit options compatible with collectors;
- `.deb` and `.rpm` packages after the binary workflow is stable.

### Windows

- Windows Service wrapper/integration;
- protected configuration and state under ProgramData;
- MSI or another signed enterprise-deployable installer;
- clean uninstall that preserves state only when explicitly requested.

### macOS

- launchd plist;
- configuration and state locations following platform conventions;
- signed/notarized package when production signing is available.

## 14. Observability and security

Structured logs should include event names, snapshot IDs, durations, counts,
status codes, and retry decisions. They must not include:

- provisioning keys;
- JWTs;
- authorization headers;
- raw machine identifiers at normal log levels;
- complete software inventories.

Add counters/timings for collection success, entries collected, queue depth,
upload result, authentication refresh, and heartbeat result. Start with logs;
add a metrics endpoint only if the deployment model requires one.

Security requirements:

- TLS verification enabled by default;
- explicit request and response size limits;
- dependency audit and license checks;
- least-privilege service identity;
- no shell interpolation;
- atomic state writes and restrictive file permissions;
- bounded memory when parsing collector output;
- document the collected data and retention expectations.

## 15. Testing strategy

### Unit tests

- config parsing/validation;
- identity persistence and corruption handling;
- collector parsers with fixtures;
- normalization/deduplication;
- token refresh decisions;
- retry classification/backoff;
- spool recovery and size limits;
- redaction.

### Contract tests

Run against a mock server using the shared fixtures:

- successful exchange/register/heartbeat/inventory;
- expired JWT refresh;
- invalid provisioning key;
- `429 Retry-After`;
- duplicate idempotency key;
- schema validation failure;
- server outage followed by recovery.

### Platform smoke tests

CI must compile on Linux, Windows, and macOS. Run collector smoke tests on each
native runner without asserting a specific installed-software count.

### End-to-end test

Use a disposable Shapoclyack stack:

1. create a tenant and provisioning key;
2. start Lariska with a fixture collector;
3. wait for registration and inventory acknowledgement;
4. query Shapoclyack and verify tenant, asset linkage, and software entries;
5. send an updated fixture and verify generated change events.

## 16. CI and release

Required checks:

- `cargo fmt --check`;
- `cargo clippy --all-targets --all-features -- -D warnings`;
- `cargo test --all-features`;
- cross-platform build matrix;
- dependency vulnerability audit;
- dependency license policy;
- secret scanning;
- contract fixture validation.

Release artifacts:

- versioned binaries for Linux x86_64/aarch64, Windows x86_64, and macOS
  x86_64/aarch64;
- SHA-256 checksums;
- generated SBOM;
- changelog and upgrade notes;
- reproducible or documented build provenance where practical.

## 17. Implementation sequence and PR boundaries

Each phase should be a small reviewable PR. Do not combine server and agent
changes in one repository.

### Phase L0 вЂ” Repair project foundation

Tasks:

- rename `cargo.toml` to `Cargo.toml`;
- add `[package]`, Rust edition, metadata, and a minimal dependency set;
- move `main.rs` to `src/main.rs`;
- add `.gitignore`, license decision, contributor commands, and CI skeleton;
- make `cargo fmt`, `cargo clippy`, and `cargo test` pass.

Acceptance:

- clean checkout builds with stable Rust;
- no placeholder token is printed;
- CI passes on three operating systems.

### Phase L1 вЂ” Models, configuration, and identity

Tasks:

- add versioned models;
- implement config precedence and secret redaction;
- implement persistent agent identity;
- add diagnostic/check-config commands.

Acceptance:

- restart preserves `agent_id`;
- corrupted state is detected;
- golden JSON fixture matches the proposed API contract.

### Phase L2 вЂ” Authentication, registration, and heartbeat

Tasks:

- implement bounded HTTP client;
- implement JWT exchange/refresh;
- implement idempotent registration;
- implement heartbeat loop.

Acceptance:

- mock-server lifecycle tests pass;
- secrets are absent from captured logs;
- transient errors recover without process restart.

### Phase L3 вЂ” Inventory collectors

Tasks:

- introduce collector trait and command abstraction;
- implement Linux collectors;
- implement Windows collectors;
- implement macOS collectors;
- normalize and deduplicate.

Acceptance:

- fixture tests cover every supported source;
- collector failure produces warnings, not a process panic;
- deterministic input produces deterministic canonical output.

### Phase L4 вЂ” Spool and inventory submission

Tasks:

- implement atomic durable queue;
- implement content digest and unchanged-snapshot suppression;
- implement idempotent upload and retry policy;
- expose queue state through sanitized diagnostics.

Acceptance:

- killing the process during upload does not lose the snapshot;
- duplicate delivery produces one server-side snapshot;
- disk limits and malformed spool files are tested.

### Phase L5 вЂ” Service integration and hardening

Tasks:

- graceful shutdown and single-instance lock;
- systemd, Windows Service, and launchd integration;
- permissions and hardening guidance;
- structured telemetry.

Acceptance:

- install/start/restart/stop works on each target platform;
- state survives upgrade;
- service runs without administrator/root privileges except where a collector
  has a documented platform requirement.

### Phase L6 вЂ” End-to-end and releases

Tasks:

- shared contract fixtures;
- Shapoclyack end-to-end test;
- installers/packages;
- release workflow, checksums, SBOM, and documentation.

Acceptance:

- the full definition of done is met;
- rollback and upgrade procedures are documented;
- a release candidate survives a multi-day soak test with simulated outages.

## 18. Instructions for the implementing AI

For every phase:

1. Inspect the current repository and latest Shapoclyack API before editing.
2. State assumptions and list exact files to change.
3. Preserve unrelated user changes.
4. Add tests with the implementation, not later.
5. Prefer small modules and typed errors over a large `main.rs`.
6. Do not log secrets or add development credentials.
7. Run the relevant formatter, linter, tests, and build matrix where available.
8. Update documentation and contract fixtures in the same PR.
9. Report commands run, results, unresolved risks, and server dependencies.
10. Stop and ask for a decision when the server contract conflicts with this
    plan; do not silently invent a second API.

## 19. Open decisions

Resolve before Phase L4:

- inventory retention period and server payload limits;
- whether snapshots may be compressed;
- identifier hashing/privacy policy;
- whether user-scope Windows/macOS inventory is required for a system service;
- exact software canonicalization rules;
- whether unchanged endpoints must submit a periodic full snapshot;
- supported minimum OS versions and CPU architectures;
- code-signing ownership and release-key custody.
