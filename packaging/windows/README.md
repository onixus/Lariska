# Windows Service installation

Lariska registers as a native Windows Service via the `--winservice` entry
point (`src/service.rs`, `windows_scm` module) — no third-party wrapper
(NSSM, WinSW, etc.) is required.

**Verification status:** this integration compiles cleanly against the real
`windows-service` crate (verified via
`cargo check --target x86_64-pc-windows-gnu` cross-compilation) but has never
been run against a real Windows Service Control Manager — no Windows machine
was available in the environment that built it. Treat install/start/stop as
unverified until confirmed on real hardware or CI's Windows runner.

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

Run from an elevated (Administrator) prompt:

```bat
sc.exe create Lariska binPath= "C:\Program Files\Lariska\lariska.exe --winservice" start= auto DisplayName= "Lariska Endpoint Agent"
sc.exe description Lariska "Cross-platform endpoint inventory agent for Shapoclyack"
sc.exe start Lariska
```

Note the required space after each `binPath=`/`start=` — `sc.exe` is picky
about this.

## Uninstall

```bat
sc.exe stop Lariska
sc.exe delete Lariska
```

This does not delete `C:\ProgramData\Lariska\state` — remove it manually only
if the agent identity/history should not survive a clean reinstall.

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
can be produced. Until then, use the `sc.exe` commands above for manual or
scripted (e.g. Group Policy startup script, RMM tool) installs.
