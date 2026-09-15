# Windows Service installation

Lariska registers as a native Windows Service via the `--winservice` entry
point (`src/service.rs`, `windows_scm` module) — no third-party wrapper
(NSSM, WinSW, etc.) is required.

**Verification status:** unverified against a real Service Control Manager.
The binary cross-compiles and links for `x86_64-pc-windows-gnu`, and clippy is
clean for that target, but install/start/stop has not yet been observed on
Windows hardware. Anything below marked *unverified* is a claim about code,
not an observation.

## Expected layout

| Path | Purpose |
| --- | --- |
| `C:\Program Files\Lariska\lariska.exe` | binary |
| `C:\ProgramData\Lariska\config\lariska.toml` | config (default path baked into the service entry point — see `app::default_service_config_path`) |
| `C:\ProgramData\Lariska\state\` | identity, spool, single-instance lock |

Both `ProgramData` paths must be ACL'd so only SYSTEM and local
Administrators can read them — the config file holds the path to the
provisioning key, and the state directory holds the durable delivery spool.

## Install

From an elevated (Administrator) PowerShell, with `lariska.exe` next to the
script:

```powershell
.\install-lariska.ps1 -ServerUrl https://shapoclyack.example.internal -ProvisioningKey pk_...
```

The script creates the directories, restricts their ACLs to SYSTEM and the
local Administrators group, writes the key and the configuration, runs
`lariska.exe check-config` against what it wrote, then registers and starts the
service. Re-running it upgrades in place: the service is stopped, the binary
and configuration are replaced, and the state directory — and with it the
agent identity the server knows this device by — is left alone.

Against a lab stand served over plain HTTP, add `-AllowPlainHttp`; the agent
refuses a non-HTTPS `server_url` otherwise, because the provisioning key and
the inventory would cross the network in the clear. For an internal CA, pass
`-TlsCaFile <path to PEM>`.

To register the service by hand instead, from an elevated prompt:

```bat
sc.exe create Lariska binPath= "\"C:\Program Files\Lariska\lariska.exe\" --winservice" start= auto DisplayName= "Lariska Endpoint Agent"
sc.exe description Lariska "Cross-platform endpoint inventory agent for Shapoclyack"
sc.exe start Lariska
```

Note the required space after each `binPath=`/`start=` — `sc.exe` is picky
about this — and the quoting inside `binPath`: the install path contains a
space, so the executable needs its own quotes or the SCM reads the path as
`C:\Program` with arguments.

## Uninstall

```powershell
.\uninstall-lariska.ps1
```

This keeps `C:\ProgramData\Lariska` — the agent identity lives there, and a
reinstall that keeps it reports as the same device rather than as a second
one. Pass `-PurgeData` to remove it.

## Stop behavior

The service control handler (`windows_scm::run_service`) responds to
`SERVICE_CONTROL_STOP` and `SERVICE_CONTROL_SHUTDOWN` by notifying the async
runtime's shutdown path — the same graceful-shutdown code path used by
Ctrl-C/SIGTERM on other platforms. It reports `SERVICE_STOPPED` back to the
SCM once `app::run_as_windows_service` returns.

## MSI / signed installer

Not yet built. Plan.md §13 calls for a signed, enterprise-deployable
installer; code-signing key custody is an open decision (Plan.md §19) that
must be resolved by whoever owns organizational certificates before an MSI
can be produced. Until then, use `install-lariska.ps1` for manual or scripted
(e.g. Group Policy startup script, RMM tool) installs; it takes every value it
needs as a parameter and is non-interactive.

## Logs

Under the SCM there is no console, so the service writes its log to
`C:\ProgramData\Lariska\state\lariska.log` instead of stdout (the plain
`lariska run` path still logs to stdout, as do the systemd and launchd
services). The file is appended to and rotated once to `lariska.log.1` when it
passes 8 MiB — a floor so the disk cannot fill, not a retention policy.

```powershell
Get-Content C:\ProgramData\Lariska\state\lariska.log -Tail 40 -Wait
```

A panic is written separately to `crash-report.json` in the same directory and
reported on the next start.

## Collecting an inventory without installing anything

```powershell
.\lariska.exe inventory --output json
```

Prints the snapshot this host would send — the registry entries, the OS fields
and the hardware identifier hashes — without a server, a config or a service.
This is the first thing to run on a new Windows build.
