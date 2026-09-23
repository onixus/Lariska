# Development

## Prerequisites

- stable Rust toolchain with `rustfmt` and Clippy;
- Git;
- native build tools for the target platform;
- optional packaging tools for deb/RPM validation;
- access to a Shapoclyack checkout when changing the shared inventory contract.

## Build and test

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

Run a local diagnostic scan:

```bash
cargo run -- inventory --output json
```

Validate a configuration:

```bash
cargo run -- check-config --config lariska.toml
```

## Repository layout

```text
src/
  main.rs             CLI
  app.rs              lifecycle and scheduling
  config.rs           configuration
  identity.rs         persistent identity and hashes
  model.rs            inventory contract and normalization
  auth.rs             provisioning/JWT lifecycle
  api.rs              bounded HTTP client
  heartbeat.rs        register/heartbeat loop
  managed.rs          managed settings and update path
  inventory/
    cache.rs
    environment.rs
    linux.rs
    windows.rs
    macos.rs
    runtimes/
  delivery/
    mod.rs
    spool.rs
    state.rs
    retry.rs
  qos.rs
  service.rs
  telemetry.rs
  crash.rs
packaging/
docs/
wiki/
tests/fixtures/
```

## CI gates

GitHub Actions runs:

- formatting;
- strict Clippy;
- tests on Linux, Windows, and macOS;
- dependency advisory and license/source policy;
- secret scanning;
- APEX Architecture Contract validation;
- cross-repository validation of the Shapoclyack inventory fixture.

The repository also contains a declarative `Jenkinsfile` for local CI deployments. A PR is not ready merely because it compiled on the author's machine, a standard that should not need saying and yet keeps earning documentation space.

## Contract changes

Inventory wire changes require:

1. a versioned model change;
2. a fixture update in Lariska;
3. the matching fixture/schema/storage change in Shapoclyack;
4. documented server/agent rollout order;
5. backward compatibility or explicit migration;
6. replay, duplicate, malformed, and mixed-version tests.

Use `SHAPOCLYACK_FIXTURE_PATH` when running the cross-repository model test locally against a sibling checkout.

Do not reuse schema version 1 for an incompatible field or identity change.

## Collector changes

A collector PR should include:

- synthetic parser fixtures;
- malformed/truncated/non-UTF-8 cases where applicable;
- timeout and non-zero exit behavior;
- explicit output/file/item bounds;
- completeness semantics;
- cache fingerprint/invalidation behavior;
- platform-native CI coverage;
- impact on comparison keys and server matching;
- documentation updates in `wiki/Collectors.md`.

Avoid per-package subprocess execution when one bounded bulk query exists. Avoid mounting offline user hives or recursively scanning arbitrary home directories without an explicit privacy/budget design.

## Cache changes

Cache entries must remain:

- versioned;
- agent-version aware;
- bounded while reading and writing;
- atomic;
- invalidated by relevant source evidence;
- limited by a forced full-refresh interval;
- restricted to complete collector results;
- safe to delete without losing identity or pending delivery.

Tests should cover hit, miss, stale entry, corrupt entry, incompatible version, fingerprint change, and incomplete result.

## Delivery changes

Preserve these constraints:

- enqueue is disk-only and does not wait for the network;
- pending entries are decoded one at a time;
- compressed and decompressed sizes are bounded;
- acknowledgement precedes removal;
- transient and terminal failures are classified differently;
- a terminal payload does not permanently block later valid snapshots;
- accepted-state persistence is atomic and bounded;
- return-to-baseline transitions are not deduplicated away.

Tests should include outage/recovery, restart, duplicate state, intermediate state followed by return, quarantine, capacity eviction, corrupt state, and removal failure.

## Managed settings

Managed values are an input from a remote control plane, not an exemption from validation. Add new settings only when:

- the local safe range is defined;
- application is atomic per revision;
- invalid revisions remain unapplied;
- sensitive/local-only policy cannot be overwritten;
- heartbeat can report application/rejection state without leaking secrets.

## Update path

Changes to executable replacement require threat modeling and platform tests. At minimum test:

- foreign target;
- plain HTTP policy;
- declared/hard size limits;
- digest/signature mismatch;
- interrupted download;
- staging failure;
- install failure with restoration;
- restart failure and rollback;
- downgrade policy.

Do not infer that SHA-256 alone establishes publisher identity.

## Documentation rules

Behavioral changes must update, in the same PR:

- `README.md` and `README_RU.md` when user-facing;
- the relevant `wiki/` page;
- `Plan.md` when an invariant/architecture changes;
- `WORKPLAN_RU.md` when a milestone is completed, added, or reprioritized;
- `CHANGELOG.md` for release-visible changes.

## Pull-request checklist

- [ ] Scope is reviewable and has one primary purpose.
- [ ] No new unbounded read, allocation, queue, traversal, or detached task.
- [ ] Errors preserve identity and pending data.
- [ ] Logs are bounded and secret-safe.
- [ ] Platform behavior is tested where it differs.
- [ ] Contract fixtures remain synchronized.
- [ ] Performance/host impact is measured or structurally bounded.
- [ ] Upgrade and rollback consequences are documented.
- [ ] README/wiki/plan match the shipped implementation.
