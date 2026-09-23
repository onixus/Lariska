# Installation and Shapoclyack connection

Lariska is distributed as a standalone binary for Linux, macOS, and Windows. It exchanges a tenant provisioning key for a short-lived agent token, registers the endpoint, sends independent heartbeats, performs bounded inventory collection, and queues authoritative snapshots for an independent delivery worker.

Release archives are currently unsigned and do not yet include production MSI, DEB, RPM, or PKG installers. Verify published SHA-256 files before installation. Windows SmartScreen and macOS Gatekeeper may warn on first run.

## 1. Create a provisioning key

Create a tenant provisioning key in Shapoclyack and copy the plaintext value immediately. Store it in a file readable only by the account that runs Lariska.

Do not put the key in:

- `lariska.toml`;
- shell history;
- command-line arguments;
- logs or public issue reports.

Example API request for an administrator:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${SHAPOCLYACK_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"label":"lariska-endpoints"}' \
  "https://shapoclyack.example.com/api/tenants/${TENANT_ID}/provisioning-keys"
```

Store only the returned `key` value.

## 2. Create the configuration

`server_url` is the Shapoclyack origin without `/api` at the end. HTTPS is required by default.

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
allow_plain_http = false
allow_insecure_updates = false
```

For a private CA:

```toml
tls_ca_file = "/etc/lariska/shapoclyack-ca.pem"
```

Plain HTTP is for an isolated lab only:

```toml
server_url = "http://127.0.0.1:8080"
allow_plain_http = true
```

The configuration path can be selected with `--config` or `LARISKA_CONFIG`. Supported fields have `LARISKA_*` environment overrides documented in [wiki/Configuration.md](../wiki/Configuration.md). `allow_insecure_updates` remains a file-controlled local decision and cannot be set by Shapoclyack managed policy.

Validate before installing the service:

```bash
lariska check-config --config /path/to/lariska.toml
```

## 3. Linux

Choose `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu` from the [latest release](https://github.com/onixus/Lariska/releases/latest). The source version at the time of this document is `0.4.0`; use the actual release tag being installed.

```bash
VERSION=0.4.0
TARGET=x86_64-unknown-linux-gnu
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz"
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
sha256sum -c "lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "lariska-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 lariska /usr/bin/lariska
```

Create a dedicated account and protected directories:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lariska
sudo install -d -o root -g lariska -m 0750 /etc/lariska
sudo install -d -o lariska -g lariska -m 0750 /var/lib/lariska
sudo install -o root -g lariska -m 0640 provisioning.key /etc/lariska/provisioning.key
sudo install -o root -g lariska -m 0640 lariska.toml /etc/lariska/lariska.toml
```

Validate under the service account and perform a no-network diagnostic scan:

```bash
sudo -u lariska /usr/bin/lariska check-config --config /etc/lariska/lariska.toml
sudo -u lariska /usr/bin/lariska inventory --output json
```

Install the supplied unit:

```bash
VERSION=0.4.0
curl -fsSL \
  "https://raw.githubusercontent.com/onixus/Lariska/v${VERSION}/packaging/systemd/lariska.service" \
  | sudo tee /etc/systemd/system/lariska.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now lariska
sudo systemctl status lariska
sudo journalctl -u lariska -n 100 --no-pager
```

The hardened unit writes state under `/var/lib/lariska`. Self-replacement of a package-owned `/usr/bin/lariska` by the unprivileged service may be unavailable; use controlled package deployment in production until the signed native updater milestone is complete.

## 4. macOS

Choose `aarch64-apple-darwin` for Apple Silicon or `x86_64-apple-darwin` for Intel.

```bash
VERSION=0.4.0
TARGET=aarch64-apple-darwin
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz"
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
shasum -a 256 -c "lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "lariska-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 lariska /usr/local/bin/lariska
```

Use these paths:

```toml
provisioning_key_file = "/Library/Application Support/Lariska/provisioning.key"
state_dir = "/Library/Application Support/Lariska/state"
```

Install files and the LaunchDaemon:

```bash
sudo install -d -m 0700 "/Library/Application Support/Lariska/state"
sudo install -d -m 0755 /Library/Logs/Lariska
sudo install -m 0600 provisioning.key "/Library/Application Support/Lariska/provisioning.key"
sudo install -m 0600 lariska.toml "/Library/Application Support/Lariska/lariska.toml"
VERSION=0.4.0
sudo curl -fsSL \
  "https://raw.githubusercontent.com/onixus/Lariska/v${VERSION}/packaging/launchd/com.shapoclyack.lariska.plist" \
  -o /Library/LaunchDaemons/com.shapoclyack.lariska.plist
sudo chown root:wheel /Library/LaunchDaemons/com.shapoclyack.lariska.plist
sudo chmod 0644 /Library/LaunchDaemons/com.shapoclyack.lariska.plist
sudo /usr/local/bin/lariska check-config \
  --config "/Library/Application Support/Lariska/lariska.toml"
sudo launchctl bootstrap system /Library/LaunchDaemons/com.shapoclyack.lariska.plist
sudo launchctl print system/com.shapoclyack.lariska
tail -n 100 /Library/Logs/Lariska/lariska.log
```

Release archives are not yet signed/notarized, so test Gatekeeper behavior in the target deployment workflow.

## 5. Windows

Download the `x86_64-pc-windows-msvc` ZIP and matching `.sha256` file from the latest release. From an elevated Command Prompt:

```bat
certutil -hashfile lariska-v0.4.0-x86_64-pc-windows-msvc.zip SHA256
install-lariska.cmd https://shapoclyack.example.com octo-pk-...
```

Compare the hash manually before installation.

`install-lariska.cmd` creates:

- `C:\Program Files\Lariska`;
- `C:\ProgramData\Lariska\config`;
- `C:\ProgramData\Lariska\state`.

It restricts data directories, writes the key/configuration, runs `check-config`, registers the native service, and starts it. Batch is used instead of PowerShell because many target environments restrict script execution.

Options:

- `/plainhttp` for an isolated lab;
- `/ca <PEM path>` for a private CA;
- `uninstall-lariska.cmd /purgedata` only when the endpoint identity and queued state should be destroyed.

Manual TOML should use literal strings for Windows paths:

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = 'C:\ProgramData\Lariska\config\provisioning.key'
state_dir = 'C:\ProgramData\Lariska\state'
inventory_interval_secs = 3600
heartbeat_interval_secs = 60
request_timeout_secs = 30
inventory_full_refresh_interval_secs = 86400
max_spool_entries = 200
log_level = "info"
allow_plain_http = false
allow_insecure_updates = false
```

Service logs are written to:

```bat
type C:\ProgramData\Lariska\state\lariska.log
```

The Windows service integration and installer are cross-compiled and reviewed; validate them on a real Service Control Manager and endpoint-management stack before a production rollout. Current notes are in [`packaging/windows/README.md`](../packaging/windows/README.md).

## 6. Verify the connection

On first successful start, Lariska:

1. creates or loads the stable identity under `state_dir`;
2. exchanges the provisioning key;
3. registers and starts heartbeat immediately;
4. restores pending delivery state;
5. schedules the first inventory using deterministic agent-specific jitter, capped at five minutes;
6. writes a complete snapshot to the local spool;
7. wakes the independent delivery worker.

Confirm:

- the service remains running;
- logs contain `Lariska Endpoint Agent started` without auth/TLS/validation errors;
- the endpoint appears in the expected Shapoclyack tenant;
- heartbeat advances;
- inventory appears after the first scheduled collection/delivery;
- `state_dir/spool` is not growing because of an unresolved API failure.

Do not delete `state_dir` during upgrade. It contains identity, collector cache, pending snapshots, and accepted delivery state.

## 7. Remote management

Shapoclyack may manage:

- `heartbeat_interval_secs`;
- `inventory_interval_secs`;
- `log_level`;
- desired update metadata.

Managed intervals/log level are validated locally and applied atomically per revision. Invalid policy leaves the previous runtime state in force and is not falsely acknowledged as applied.

Shapoclyack cannot remotely change:

- `server_url`;
- provisioning-key path/content;
- `state_dir`;
- CA path;
- `allow_plain_http`;
- `allow_insecure_updates`.

## 8. Update behavior

The current update path:

- joins a relative API path to the configured same-origin server;
- refuses a foreign target triple;
- requires HTTPS unless the local insecure-update override is enabled;
- verifies SHA-256 before replacement;
- stages the file and retains the previous binary;
- exits so the service supervisor starts the installed build.

Production limitations remain: no embedded-key signed manifest, final streaming/size design, native package ownership, anti-rollback policy, or automatic post-restart health rollback. See [WORKPLAN_RU.md](../WORKPLAN_RU.md).

## 9. Troubleshooting

Use the dedicated [troubleshooting guide](../wiki/Troubleshooting.md). Common first checks:

- `server_url` is the HTTPS origin and has no `/api` suffix;
- the key file is readable by the service account and not revoked;
- private CA configuration is correct;
- Lariska and Shapoclyack accept the same inventory schema;
- collector warnings did not make the cycle incomplete;
- pending queue age is not increasing;
- managed settings are within local bounds;
- state/config directories have the expected ownership and free space.
