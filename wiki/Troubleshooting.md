# Troubleshooting

Start with bounded facts, not ceremonial restarts:

```bash
lariska check-config --config /path/to/lariska.toml
lariska inventory --output json
```

Then inspect the service log and Shapoclyack endpoint status. Never paste provisioning keys, JWTs, raw state files, or full customer inventory into a public issue.

## Service does not start

### `failed to read config file`

Check:

- the selected `--config` path or `LARISKA_CONFIG`;
- service-account read permissions;
- TOML escaping, especially Windows paths;
- whether the service unit points to the same path you tested interactively.

On Windows, prefer TOML literal strings for paths:

```toml
state_dir = 'C:\ProgramData\Lariska\state'
```

### `state_dir must be an absolute path when running with --service`

Use an absolute platform path. Relative paths depend on the service manager's working directory, which is the sort of ambiguity computers cherish and operators do not.

### single-instance/lock failure

Another process is using the same state directory. Verify the existing service/process before removing any lock-related state. Do not run a diagnostic daemon and the service concurrently against one `state_dir`.

## Registration or heartbeat fails

### Invalid/revoked provisioning key

- verify the key file contains only the intended key;
- check file permissions and line endings;
- create a new tenant provisioning key if the original was revoked;
- restart after replacing the protected key file;
- do not delete identity unless a new endpoint identity is actually intended.

### TLS/certificate error

- confirm `server_url` contains the origin and no `/api` suffix;
- check system time;
- provide `tls_ca_file` for a private CA;
- verify hostname/SAN and full certificate chain;
- do not solve production TLS errors with `allow_plain_http = true`.

### Registration retries then exits

Startup registration has bounded retry. A persistent auth/configuration failure is fatal by design. Transient failure should recover during the retry window; otherwise fix network/API availability and restart.

## Inventory is not submitted

### Log says collection was incomplete

The agent deliberately kept the previous server-side inventory. Inspect preceding collector warnings:

- package-manager timeout or non-zero exit;
- registry enumeration failure;
- application directory read error;
- runtime collector panic/error;
- output/file/fingerprint limit exceeded.

Run `lariska inventory --output json` interactively under the service account. Diagnostic mode prints partial data and warnings without uploading.

Do not bypass the completeness gate. Its alternative is a server confidently reporting that half the company uninstalled everything at once.

### No supported Linux package manager found

Check whether the host uses dpkg, RPM, or pacman and whether its database is in a standard location. Relocated databases may fall back to trusted-binary probing, but unsupported package systems require a new collector.

### Windows user software is missing

Only loaded user hives under `HKEY_USERS` are collected. Software installed only for a signed-out user may be absent until the profile is loaded. Mounting every offline `NTUSER.DAT` is intentionally not performed.

### Side-by-side versions collapse

This is a schema-v1 limitation when entries share name, publisher, architecture, and source. The agent retains the naturally newer version and emits a warning. Schema v2 installation identity is the planned fix.

## Inventory is slow or causes noticeable load

Check:

- whether the cycle is a cold scan after upgrade/cache deletion/full-refresh expiry;
- cache-hit/miss messages;
- unusually large runtime roots;
- package-manager database health;
- collector timeout warnings;
- whether the process received background priority;
- battery/AC state and effective interval;
- antivirus or filesystem filters delaying metadata reads.

Repeated warm cycles should reuse compatible complete cache entries when fingerprints are unchanged. A cache miss after every cycle usually means source metadata is continuously changing, the cache is unwritable/corrupt, or the full-refresh interval is too short.

## Spool grows

Inspect:

- API reachability;
- authentication/authorization errors;
- `429` and server `5xx` responses;
- oldest pending age;
- quarantine entries;
- state-directory disk space and permissions;
- whether the delivery worker is running independently of inventory.

Snapshots remain queued across restart. Do not delete pending files merely to make the directory look tidy. Resolve delivery first, or archive files while the service is stopped if forensic retention is required.

## Quarantine grows

A quarantined snapshot was locally corrupt/oversized or rejected terminally by the API.

Actions:

1. stop the service if inspecting files;
2. record file name, timestamp, agent version, and bounded log error;
3. verify client/server schema compatibility;
4. check payload limits and snapshot validation;
5. preserve a sensitive sample privately if required for debugging;
6. remove old quarantine files only under an explicit retention policy.

Later valid snapshots are not supposed to remain blocked behind one quarantined payload.

## Cache errors

Corrupt, oversized, expired, or incompatible cache entries are ignored and removed. The next cycle performs a real collection.

Safe manual reset:

1. stop the service;
2. remove `state_dir/inventory-cache-v1/` only;
3. start the service;
4. expect one cold scan.

Do not remove the entire state directory to clear cache.

## Delivery state is discarded

If `delivery-state-v1.json` is invalid, Lariska deletes it and later submits a complete snapshot. This may cause a redundant full refresh but should not lose endpoint identity or pending queue data.

## Managed settings are rejected

Check the revision values:

- heartbeat and inventory intervals must be 10–86400 seconds;
- log level must be `error`, `warn`, `info`, `debug`, or `trace`;
- all supplied fields are applied atomically.

Fix the policy in Shapoclyack. Repeating the same invalid revision will not change runtime state.

## Update fails

Common causes:

- update platform does not match the agent target triple;
- plain HTTP without the local insecure-update override;
- digest mismatch;
- service account cannot replace the installed binary;
- staging/state directory is not writable;
- supervisor does not restart the service after staging.

Prefer native package deployment in production until signed manifests and health rollback are complete. Keep the previous executable and update logs for recovery.

## Crash report detected after restart

The panic hook writes a bounded local report. Treat it as evidence, not a full dump:

- capture agent version, platform, command, and preceding logs;
- verify whether inventory/spool state recovered;
- remove or archive the report after investigation;
- reproduce with the same metadata fixture when possible, without publishing tenant data.

## Before opening an issue

Include:

- Lariska version and target triple;
- OS version and service manager;
- sanitized configuration excluding secret paths when sensitive;
- exact bounded error text;
- whether the problem occurs in diagnostic mode, daemon mode, or both;
- cache cold/warm state;
- queue depth and quarantine count;
- minimal reproduction or synthetic fixture.

Exclude credentials, JWTs, raw identifiers, complete inventory, and private server certificates.
