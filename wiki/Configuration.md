# Configuration

Lariska loads a TOML file, then applies supported environment-variable overrides. The configuration path is selected in this order:

1. `--config <path>`;
2. `LARISKA_CONFIG`;
3. `./lariska.toml`.

Secrets should be stored in files, not passed as command-line values or embedded in the TOML document.

## Complete example

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = "/etc/lariska/provisioning.key"
state_dir = "/var/lib/lariska"

inventory_interval_secs = 3600
heartbeat_interval_secs = 60
request_timeout_secs = 30
inventory_full_refresh_interval_secs = 86400
max_spool_entries = 200

log_level = "info"
tls_ca_file = "/etc/lariska/private-ca.pem"

allow_plain_http = false
allow_insecure_updates = false
```

## Settings

| Setting | Required | Default | Validation and behavior |
| --- | --- | --- | --- |
| `server_url` | yes | none | HTTPS required unless `allow_plain_http` is explicitly true |
| `provisioning_key_file` | yes | none | Must point to a readable file; contents are never printed in config diagnostics |
| `state_dir` | yes | none | Persistent identity, cache, queue, and delivery state; must be absolute in service mode |
| `inventory_interval_secs` | no | 3600 | 10–86400 seconds before battery policy/jitter |
| `heartbeat_interval_secs` | no | 60 | 10–86400 seconds |
| `request_timeout_secs` | no | 30 | 1–300 seconds |
| `tls_ca_file` | no | system roots | Optional private CA bundle |
| `log_level` | no | `info` | Runtime filter; managed values are restricted to `error`, `warn`, `info`, `debug`, or `trace` |
| `allow_plain_http` | no | false | Development/lab escape hatch for API traffic; keep false in production |
| `allow_insecure_updates` | no | false | Separate local override required before installing an update over plain HTTP |
| `inventory_full_refresh_interval_secs` | no | 86400 | 10–86400 seconds; invalidates unchanged collector cache and forces periodic submission |
| `max_spool_entries` | no | 200 | 1–10000; hard byte limits still apply independently |

## Environment overrides

| Environment variable | Setting |
| --- | --- |
| `LARISKA_SERVER_URL` | `server_url` |
| `LARISKA_PROVISIONING_KEY_FILE` | `provisioning_key_file` |
| `LARISKA_STATE_DIR` | `state_dir` |
| `LARISKA_INVENTORY_INTERVAL_SECS` | `inventory_interval_secs` |
| `LARISKA_HEARTBEAT_INTERVAL_SECS` | `heartbeat_interval_secs` |
| `LARISKA_REQUEST_TIMEOUT_SECS` | `request_timeout_secs` |
| `LARISKA_TLS_CA_FILE` | `tls_ca_file` |
| `LARISKA_LOG_LEVEL` | `log_level` |
| `LARISKA_ALLOW_PLAIN_HTTP` | `allow_plain_http` (`true` or `false`) |
| `LARISKA_INVENTORY_FULL_REFRESH_INTERVAL_SECS` | `inventory_full_refresh_interval_secs` |
| `LARISKA_MAX_SPOOL_ENTRIES` | `max_spool_entries` |

`allow_insecure_updates` remains a file-controlled local decision. It is intentionally not part of managed policy, and operators should not casually inject it into service environments either.

## Managed settings

Shapoclyack may supply:

- heartbeat interval;
- inventory interval;
- log level;
- desired agent version/update metadata.

The agent validates a managed revision locally before applying it. A bad interval or log level rejects the entire revision. The previous runtime state remains active, and the rejected revision is not falsely acknowledged as applied.

The following are local-only and cannot be changed remotely:

- `server_url`;
- provisioning-key path/content;
- `state_dir`;
- private CA path;
- plain-HTTP policy;
- insecure-update policy.

## Platform examples

### Linux service

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = "/etc/lariska/provisioning.key"
state_dir = "/var/lib/lariska"
log_level = "info"
```

Protect the key and configuration with restrictive ownership and permissions. The packaged systemd unit documents the expected service account and write paths.

### Windows service

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = "C:\\ProgramData\\Lariska\\config\\provisioning.key"
state_dir = "C:\\ProgramData\\Lariska\\state"
log_level = "info"
```

Use the example under `packaging/windows/lariska.example.toml` and the provided installer scripts.

### macOS launchd

Use absolute paths under an administrator-controlled configuration directory and a writable service state directory. The launchd template is stored under `packaging/launchd/`.

## Validation

```bash
lariska check-config --config /path/to/lariska.toml
```

The command confirms parsed configuration without printing the provisioning key. It does not prove network reachability or that the key is accepted; registration does that when the service starts.
