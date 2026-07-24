# Lariska

Lariska is a cross-platform endpoint inventory agent for the Shapoclyack platform.
The first production goal is to identify an endpoint, collect a normalized list
of installed software, and deliver versioned inventory snapshots to Shapoclyack.

## Current status

This repository is in the project-foundation stage. The binary currently starts,
collects a basic local software list on supported platforms, and reports the
number of collected entries. Authentication, registration, heartbeat, durable
spooling, and gateway submission are planned but not implemented yet.

## Development commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Run locally

```bash
cargo run
```

The current prototype must not print provisioning keys, JWTs, authorization
headers, or complete inventory payloads by default.
