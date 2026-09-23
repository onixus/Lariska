# Security Model

## Trust boundaries

Lariska treats the following as separate trust domains:

1. **Local operator configuration**: server URL, credential path, state path, CA roots, and transport exceptions.
2. **Shapoclyack control plane**: authenticated heartbeat responses, managed settings, and update metadata.
3. **Endpoint metadata**: package databases, registry values, plist files, JSON metadata, and command output. All are untrusted input even when owned by the local OS.
4. **Local persistent state**: identity, cache, spool, and delivery metadata. These may be truncated or modified after a crash or administrative action.
5. **Ambient process environment**: especially `PATH`; it is not trusted for locating collector binaries.

## Data collected

Depending on platform and available sources, Lariska may collect:

- hostname;
- OS family, name, release, and architecture;
- pseudonymized platform identifiers;
- environment labels for containers, hypervisors, cloud platform, and power source;
- installed software name, version, publisher, architecture, source, and optional install location;
- selected Windows KB identifiers;
- bounded collector warnings;
- agent version and collection timestamp.

Install locations can reveal organization-specific directory structure. Treat inventory snapshots as sensitive operational data and apply appropriate tenant access, retention, and audit policy in Shapoclyack.

## Data not intentionally collected

- file contents outside bounded package/runtime metadata;
- documents, browser history, or user activity;
- credentials, private keys, JWT values, or authorization headers;
- arbitrary command output unrelated to supported collectors;
- active process lists;
- keystrokes, screenshots, or surveillance data;
- unrestricted remote command execution.

## Identifier privacy

Platform identifiers are normalized and one-way hashed before submission. This is pseudonymization, not anonymity: a stable unsalted hash can still correlate the same underlying identifier across observations. Raw identifiers should not appear in normal logs or API payloads.

A future contract should consider tenant-scoped HMAC identifiers, provenance, confidence, and clone detection. Such a change requires coordinated identity migration in Shapoclyack and cannot be slipped into an agent-only patch without consequences, however tempting that shortcut may look on a Friday.

## Local protections

- provisioning keys are read from files rather than CLI arguments;
- debug formatting redacts the credential path/value;
- JWTs are held in memory;
- service installations use dedicated/protected directories;
- state writes use temporary files and atomic rename where supported;
- instance locking prevents two processes from mutating one state directory;
- queue, cache, metadata, and crash files have explicit read/size limits;
- corrupt queue/cache state is discarded or quarantined rather than trusted;
- logs avoid full software inventory and raw identifiers.

File-system permissions remain an operator responsibility. A local administrator can read the agent state and replace the executable; Lariska does not claim to defend the host from its own root/SYSTEM account.

## Collector hardening

- no shell interpolation;
- commands resolved only from trusted system directories;
- arguments passed as an explicit list;
- stdin disabled;
- stdout bounded while being read;
- stderr not copied into unbounded telemetry;
- timeout kills and reaps the directly spawned process;
- metadata files are read with ceilings;
- filesystem fingerprint walks have an item limit;
- collector failures propagate completeness and cannot silently create removals.

A remaining improvement is process-group/job-object termination for tools that spawn descendants.

## Network protections

- HTTPS is required by default;
- private CA bundles are supported;
- request timeout and response-body limits are enforced;
- authentication refresh is bounded;
- transient retry is classified and delayed;
- idempotency keys prevent duplicate snapshot creation;
- payload-specific terminal failures are quarantined;
- plain HTTP and insecure update are separate local overrides.

`allow_plain_http` is suitable only for an isolated lab. `allow_insecure_updates` is more dangerous because it permits executing a binary whose bytes and digest may travel over the same unprotected channel.

## Managed policy containment

Remote policy can control only a small runtime surface:

- heartbeat interval;
- inventory interval;
- log level;
- desired update metadata.

Intervals and log levels are validated locally and applied atomically. Remote policy cannot change:

- Shapoclyack origin;
- credential location/content;
- state directory;
- local CA path;
- plain-HTTP permission;
- insecure-update permission.

## Update security

Current controls:

- same-origin update path joined to the configured server URL;
- target-triple verification;
- HTTPS requirement by default;
- SHA-256 verification;
- staging before replacement;
- retained previous executable and restore attempt after failed swap.

Residual risks:

- the digest is currently supplied by the same control plane as the artifact;
- there is no embedded-key signature over a release manifest;
- download size enforcement and streaming need final hardening;
- package/service permissions may prevent safe replacement;
- post-restart health rollback is not automated;
- anti-rollback policy is not complete.

The production target is a signed manifest, streaming hash/size enforcement, native package installation, health acknowledgement, and automatic rollback.

## Supply-chain controls

CI includes:

- strict Clippy and tests on supported operating systems;
- `cargo audit`;
- `cargo deny` advisories/license/source policy;
- secret scanning;
- SBOM generation in release workflow;
- SHA-256 release checksums;
- APEX Architecture Contract validation;
- cross-repository inventory fixture validation.

Future production releases should add artifact signing, build provenance/attestation, signed Windows binaries/MSI, and macOS signing/notarization.

## Reporting a vulnerability

Do not place credentials, raw endpoint identifiers, customer inventory, or exploit details in a public issue. Use the repository owner's private security contact or GitHub private vulnerability reporting when enabled. Public issues are appropriate for non-sensitive hardening proposals and reproducible behavior that exposes no tenant data.
