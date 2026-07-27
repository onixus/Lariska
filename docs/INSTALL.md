# Installation and Shapoclyack connection

Lariska is distributed as a standalone binary for Linux, macOS, and Windows.
It enrolls an endpoint by exchanging a tenant provisioning key for a
short-lived agent token, registers the endpoint, sends heartbeats, and submits
software inventory snapshots.

Release archives are currently unsigned and do not include an MSI, DEB, RPM,
or PKG installer. Windows SmartScreen and macOS Gatekeeper may therefore show
a warning on first run.

## 1. Create a provisioning key

Sign in to Shapoclyack as an administrator, open **Tenants**, select or create
the tenant that should own the endpoint, and create a provisioning key. Copy
the plaintext key immediately: Shapoclyack returns it only once.

An administrator can also create the key through the Shapoclyack API:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${SHAPOCLYACK_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"label":"lariska-endpoints"}' \
  "https://shapoclyack.example.com/api/tenants/${TENANT_ID}/provisioning-keys"
```

Store only the `key` value returned by that request. Do not put the
provisioning key directly in `lariska.toml`, shell history, logs, or
command-line arguments. Save it in a file readable only by the account that
runs Lariska.

## 2. Create the configuration

`server_url` is the Shapoclyack origin, without `/api` at the end. HTTPS is
required by default.

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
```

For a private certificate authority, add:

```toml
tls_ca_file = "/etc/lariska/shapoclyack-ca.pem"
```

Plain HTTP should be used only in an isolated development environment:

```toml
server_url = "http://127.0.0.1:8080"
allow_plain_http = true
```

All settings can be overridden with `LARISKA_*` environment variables. The
configuration path can be selected with `--config` or `LARISKA_CONFIG`.

## 3. Linux

Select `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu` on the
[latest release page](https://github.com/onixus/Lariska/releases/latest).
The example below uses x86_64 and version `0.1.2`; change both values when
installing another release or architecture.

```bash
VERSION=0.1.2
TARGET=x86_64-unknown-linux-gnu
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz"
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
sha256sum -c "lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "lariska-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 lariska /usr/bin/lariska
```

Create a dedicated service account and protected configuration:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lariska
sudo install -d -o root -g lariska -m 0750 /etc/lariska
sudo install -d -o lariska -g lariska -m 0750 /var/lib/lariska
sudo install -o root -g lariska -m 0640 provisioning.key /etc/lariska/provisioning.key
sudo install -o root -g lariska -m 0640 lariska.toml /etc/lariska/lariska.toml
```

Validate the configuration before enabling the service:

```bash
sudo -u lariska /usr/bin/lariska check-config --config /etc/lariska/lariska.toml
sudo -u lariska /usr/bin/lariska inventory --output json
```

Install and start the supplied systemd unit:

```bash
VERSION=0.1.2
curl -fsSL \
  "https://raw.githubusercontent.com/onixus/Lariska/v${VERSION}/packaging/systemd/lariska.service" \
  | sudo tee /etc/systemd/system/lariska.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now lariska
sudo systemctl status lariska
sudo journalctl -u lariska -n 100 --no-pager
```

## 4. macOS

Select the `aarch64-apple-darwin` archive for Apple Silicon or
`x86_64-apple-darwin` for Intel:

```bash
VERSION=0.1.2
TARGET=aarch64-apple-darwin
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz"
curl -fLO "https://github.com/onixus/Lariska/releases/download/v${VERSION}/lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
shasum -a 256 -c "lariska-v${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "lariska-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 lariska /usr/local/bin/lariska
```

Create `/Library/Application Support/Lariska/lariska.toml` using the common
configuration above, but use these paths:

```toml
provisioning_key_file = "/Library/Application Support/Lariska/provisioning.key"
state_dir = "/Library/Application Support/Lariska/state"
```

Install the files and LaunchDaemon:

```bash
sudo install -d -m 0700 "/Library/Application Support/Lariska/state"
sudo install -d -m 0755 /Library/Logs/Lariska
sudo install -m 0600 provisioning.key "/Library/Application Support/Lariska/provisioning.key"
sudo install -m 0600 lariska.toml "/Library/Application Support/Lariska/lariska.toml"
VERSION=0.1.2
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

## 5. Windows

Download `lariska-v0.1.2-x86_64-pc-windows-msvc.zip` and its `.sha256` file
from the [latest release page](https://github.com/onixus/Lariska/releases/latest).
In an elevated PowerShell window:

```powershell
$Archive = ".\lariska-v0.1.2-x86_64-pc-windows-msvc.zip"
$Expected = (Get-Content "$Archive.sha256").Split()[0]
$Actual = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "SHA-256 checksum mismatch" }

New-Item -ItemType Directory -Force "C:\Program Files\Lariska" | Out-Null
New-Item -ItemType Directory -Force "C:\ProgramData\Lariska\config" | Out-Null
New-Item -ItemType Directory -Force "C:\ProgramData\Lariska\state" | Out-Null
Expand-Archive $Archive -DestinationPath "C:\Program Files\Lariska" -Force
```

Save the provisioning key as
`C:\ProgramData\Lariska\config\provisioning.key`, then create
`C:\ProgramData\Lariska\config\lariska.toml`:

```toml
server_url = "https://shapoclyack.example.com"
provisioning_key_file = "C:\ProgramData\Lariska\config\provisioning.key"
state_dir = "C:\ProgramData\Lariska\state"
inventory_interval_secs = 3600
heartbeat_interval_secs = 60
request_timeout_secs = 30
inventory_full_refresh_interval_secs = 86400
max_spool_entries = 200
log_level = "info"
allow_plain_http = false
```

Restrict both `C:\ProgramData\Lariska\config` and
`C:\ProgramData\Lariska\state` to `SYSTEM` and local Administrators. Validate
the configuration and register the Windows Service:

```powershell
& "C:\Program Files\Lariska\lariska.exe" check-config `
  --config "C:\ProgramData\Lariska\config\lariska.toml"
sc.exe create Lariska binPath= '"C:\Program Files\Lariska\lariska.exe" --winservice' start= auto DisplayName= "Lariska Endpoint Agent"
sc.exe description Lariska "Cross-platform endpoint inventory agent for Shapoclyack"
sc.exe start Lariska
sc.exe query Lariska
```

The native Windows Service integration has been cross-compiled but has not
yet been validated against a real Windows Service Control Manager. See
[`packaging/windows/README.md`](../packaging/windows/README.md) for current
status and uninstall instructions.

## 6. Verify the connection

On first successful start, Lariska creates a stable agent identity under
`state_dir`, exchanges the provisioning key, registers the endpoint, and
submits its first inventory snapshot. Confirm all of the following:

1. The service remains running.
2. Logs contain `Lariska Endpoint Agent started` and no authentication,
   certificate, or validation errors.
3. The endpoint appears in the Shapoclyack agent/fleet view for the expected
   tenant.
4. Its heartbeat timestamp advances.
5. Its endpoint inventory contains the collected software list.

Do not delete `state_dir` during an upgrade: it contains the stable agent
identity and queued inventory snapshots.

## Troubleshooting

- `server_url must use HTTPS`: use the HTTPS Shapoclyack origin. Set
  `allow_plain_http = true` only for isolated development.
- `authentication failed or expired`: verify that the provisioning key file
  contains the one-time plaintext key, has no surrounding quotes, belongs to
  the correct tenant, and has not been revoked.
- TLS or certificate errors: install the private CA in the OS trust store or
  set `tls_ca_file` to a readable PEM certificate.
- `access forbidden`: the key or issued agent token does not have access to
  the expected tenant.
- `request validation failed`: verify that the Lariska and Shapoclyack
  versions support the same endpoint inventory schema.
- Connection timeouts or `503`: verify DNS, firewall, reverse proxy, and
  Shapoclyack health. Lariska retries transient delivery failures and keeps
  unsent snapshots in `state_dir`.
