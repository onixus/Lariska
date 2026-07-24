# Lariska: hardening and data collection reference

## What Lariska collects

Sent to Shapoclyack on every accepted inventory snapshot (`POST
/api/endpoint/inventory`, schema v1):

- **Endpoint identity**: a random, locally-generated `agent_id`
  (`agent_<32 hex>`, never derived from hardware) plus one hashed platform
  identifier per endpoint (`bios_uuid_hash` — see below).
- **Hostname**, OS family/name/version/architecture, agent version.
- **Installed software**: name, version, publisher, architecture, source
  (`apt`/`dpkg`/`rpm`/`winreg`/`msi`/`brew`/`other`), and install location
  (a filesystem path, which on macOS/Windows can reveal a local username if
  software is installed under a home directory).
- Optional operator-supplied `labels` (e.g. site/environment) — none are set
  by default.
- `collector_warnings`: short diagnostic strings about incomplete collection
  (e.g. "no supported Linux package manager found"), never raw command
  output or full inventories.

**Never collected or sent**: raw machine identifiers (MAC address, hardware
serial, BIOS UUID) — only a one-way SHA-256 hash of one such identifier is
sent; file contents; user activity; arbitrary remote command execution
(explicitly out of scope, see `Plan.md` §4).

## Identifier hashing policy

`identity::platform_identifiers()` reads one platform-supplied identifier per
OS (`/etc/machine-id` on Linux, the `MachineGuid` registry value on Windows,
`IOPlatformUUID` via `ioreg` on macOS) and hashes it with **SHA-256, no
salt**, over the lowercased/trimmed value. No salt is deliberate: the server
matches devices on `(tenant_id, identifier_type, value_hash)`, so the same
physical machine must hash identically across agent reinstalls for
reconciliation to work. This means the hash is a stable pseudonymous
identifier for the machine within a tenant — document this in any privacy
notice covering fleet monitoring.

None of the three platform identifiers is literally a MAC address, hardware
serial, or TPM endorsement key (the four `identifier_type` values the server
accepts) — all three are reported as `bios_uuid_hash` as the closest semantic
fit. See the doc comment on `identity::platform_identifiers` for the full
rationale.

## Secrets handling

- The provisioning key is read from disk only at token-exchange time
  (`auth::AuthClient::exchange`), never cached, never logged.
- The exchanged JWT lives in memory only (`auth::TokenState`) — never
  persisted to disk. Its `Debug` impl redacts the token value; a unit test
  (`auth::tests::token_state_debug_never_leaks_the_access_token`) asserts
  this.
- `Config`'s `Debug` impl redacts `provisioning_key_file`'s contents are
  never printed, only the path.
- `Authorization` headers and response bodies from failed auth calls are
  never logged verbatim (`api::sanitize_detail` bounds and returns error body
  text, but no code path logs a bearer token).

## Structured logging

`telemetry::init` configures a `tracing` subscriber respecting `RUST_LOG` (or
the configured `log_level` if unset). Operational events use structured
fields (`attempt`, `error`, `retry_in`, `snapshot_id`, etc.) — see
`app.rs`/`heartbeat.rs`/`delivery/mod.rs` for call sites. Per Plan.md §14,
log fields must never include provisioning keys, JWTs, `Authorization`
headers, raw machine identifiers, or complete software inventories; every
existing call site follows this, but it is not automatically enforced —
review new `tracing::*!` call sites for this before merging.

## Process/service hardening

### Linux (`packaging/systemd/lariska.service`)

- Runs as a dedicated non-login `lariska` system user (create first: `useradd
  --system --no-create-home --shell /usr/sbin/nologin lariska`).
- `ProtectSystem=strict` + `ProtectHome=true` + a single `ReadWritePaths=`
  exception for the state directory — the unit cannot write anywhere else on
  disk.
- `CapabilityBoundingSet=` (empty) — none of the Linux collectors
  (`dpkg-query`/`rpm`/`pacman`) need elevated capabilities.
- `NoNewPrivileges=true`, `MemoryDenyWriteExecute=true`,
  `RestrictNamespaces=true`, and related sandboxing options are enabled;
  loosen only if a future collector genuinely needs one relaxed.

### macOS (`packaging/launchd/com.shapoclyack.lariska.plist`)

- Ships as a `LaunchDaemon` (root-owned paths under `/Library/...`) by
  default; switch to a dedicated service user via `UserName`/`GroupName` once
  one is provisioned for the target fleet — root is not least-privilege, it
  is the pragmatic default until that account exists.
- `KeepAlive` restarts the agent only on non-zero exit, so a clean
  intentional stop does not respawn it.

### Windows (`packaging/windows/README.md`)

- Runs as `SYSTEM` by default under the SCM (standard for a service
  installed via `sc.exe create` without an explicit `obj=` account) — a
  dedicated service account can be configured via `sc.exe config Lariska
  obj= ".\LariskaSvc" password= "..."` once one is provisioned; SYSTEM is
  required for the registry paths the Windows collector reads regardless
  (`HKLM\...\Uninstall` is readable by SYSTEM without special grants).
- `--service` mode rejects a relative `state_dir` (`Config` validation in
  `app::run_internal`) so a working-directory change by the SCM can never
  silently relocate the spool/identity files.

## Known gaps (as of Phase L5)

- Windows Service integration has never run against a real SCM (see
  `packaging/windows/README.md`).
- User-scope Windows/macOS software (per-user installs, not machine-wide) is
  not collected — Phase L3's collectors are machine-scope only, matching the
  "run without administrator/root privileges except where a collector has a
  documented platform requirement" acceptance bar without requiring
  per-user impersonation from a system service. Document this as a known
  inventory gap to anyone relying on complete per-user software visibility.
- No MSI/`.deb`/`.rpm` installer yet — manual/scripted install only (Phase
  L6).
