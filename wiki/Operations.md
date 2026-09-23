# Operations

For installation commands and platform-specific file permissions, use [docs/INSTALL.md](../docs/INSTALL.md). This page describes day-two operation after the service exists, the part documentation often abandons because apparently software only fails before lunch.

## Standard locations

| Platform | Binary/config/state/log pattern |
| --- | --- |
| Linux | `/usr/bin/lariska`, `/etc/lariska/lariska.toml`, `/var/lib/lariska`, journald |
| macOS | `/usr/local/bin/lariska`, `/Library/Application Support/Lariska/lariska.toml`, `/Library/Application Support/Lariska/state`, `/Library/Logs/Lariska/lariska.log` |
| Windows | `C:\Program Files\Lariska`, `C:\ProgramData\Lariska\config`, `C:\ProgramData\Lariska\state`, `state\lariska.log` |

Custom paths are supported, but service mode requires an absolute `state_dir`.

## Service lifecycle

### Linux

```bash
sudo systemctl status lariska
sudo systemctl restart lariska
sudo journalctl -u lariska -n 200 --no-pager
sudo journalctl -u lariska -f
```

### macOS

```bash
sudo launchctl print system/com.shapoclyack.lariska
sudo launchctl kickstart -k system/com.shapoclyack.lariska
tail -n 200 /Library/Logs/Lariska/lariska.log
```

### Windows

```bat
sc.exe query Lariska
sc.exe stop Lariska
sc.exe start Lariska
type C:\ProgramData\Lariska\state\lariska.log
```

The Windows integration and installer are cross-compiled and reviewed; validate them against the real target environment before declaring a fleet rollout complete.

## Startup sequence

A normal start should:

1. parse and validate configuration;
2. initialize logging and inspect the previous crash report;
3. apply background scheduling policy;
4. acquire the state-directory lock;
5. load the existing identity;
6. restore queue and accepted delivery state;
7. register with Shapoclyack;
8. run independent heartbeat, inventory, and delivery loops.

A second process using the same `state_dir` should fail fast rather than share mutable state.

## State management

### Identity

The identity is the continuity of the endpoint. Back up the whole `state_dir` before migration or reinstall when the endpoint must keep the same server identity.

Do not delete identity as a routine troubleshooting step. Doing so creates a new agent/device relationship and can leave the old endpoint stale in Shapoclyack.

### Inventory cache

`inventory-cache-v1/` is disposable optimization state. Deleting it while the service is stopped forces a cold collection on the next cycle. The agent also invalidates stale, corrupt, incompatible, or expired entries automatically.

### Spool

`spool/` contains acknowledged-or-not-yet-acknowledged snapshots. The delivery worker processes entries oldest first and one at a time.

- Network/auth failure: entries remain pending.
- Payload-specific terminal failure: the entry moves to `spool/quarantine/` and later entries can continue.
- Capacity pressure: oldest unsent entries may be evicted, but the newest entry is retained.
- Corrupt/oversized local entry: it is quarantined instead of repeatedly crashing recovery.

Do not manually edit a compressed snapshot. Stop the service before moving files for forensic analysis.

### Delivery state

`delivery-state-v1.json` records the last accepted semantic digest and timestamp. It suppresses unchanged submissions across restarts. Invalid state is discarded safely, causing a later full submission rather than trusting bad metadata.

## Scheduling

The configured inventory interval is a base value:

- deterministic jitter distributes endpoints across the interval;
- the first scan is staggered but capped so a new endpoint appears promptly;
- battery operation increases the recurring delay;
- a managed policy can replace the base interval after local validation;
- the next scan is scheduled after the previous scan completes;
- missed time does not produce catch-up bursts.

Heartbeat remains independent and should continue while inventory or delivery is degraded.

## Cache and full refresh

A warm cache avoids package-manager commands and large runtime traversals when source fingerprints are unchanged. `inventory_full_refresh_interval_secs` sets the maximum cache age and also ensures unchanged endpoint state is periodically refreshed to the server.

After changing collector behavior or upgrading the agent, cache documents from a different agent version are ignored.

## Queue recovery after an outage

When Shapoclyack becomes reachable:

1. the delivery worker wakes on its retry cadence or a new enqueue;
2. pending entries are delivered oldest first;
3. identical endpoint states are not repeatedly queued;
4. a return-to-baseline state remains queued behind an intermediate state, preserving the transition;
5. acknowledgement persists delivery state and removes the file.

Collection continues during the outage, subject to spool entry/byte limits.

## Managed policy rollout

Recommended fleet rollout:

1. change the tenant default for a small canary group or explicit agents;
2. confirm managed revision application in logs and heartbeat state;
3. inspect inventory freshness, queue age, collection duration, and warnings;
4. expand in waves;
5. revert the policy if endpoint impact or server load changes unexpectedly.

Invalid settings are rejected atomically. The agent continues using the previous runtime policy.

## Update behavior

The current self-update path:

- refuses a foreign target triple;
- requires HTTPS unless the local insecure-update override is enabled;
- verifies the published SHA-256;
- stages a new executable and retains the previous one;
- exits so the service supervisor can start the new build.

Current limits:

- release artifacts/manifests are not yet cryptographically signed by an embedded trust key;
- download is not yet the final streaming/declared-size design;
- package-managed Linux installation may not permit the service account to replace `/usr/bin/lariska`;
- automatic post-restart health rollback is not complete.

For production fleets, prefer controlled native package deployment until the signed updater milestone is finished.

## Backup and migration

To move an endpoint while preserving identity:

1. stop Lariska;
2. copy the protected configuration, provisioning-key file, and complete `state_dir` preserving permissions;
3. install the same or a compatible version on the target host;
4. validate configuration;
5. start once and confirm registration/heartbeat before deleting the source copy.

Copying one identity to two concurrently running machines is unsupported and will create reconciliation conflicts.

## Routine checks

- service running and restarting normally;
- recent heartbeat in Shapoclyack;
- age of last accepted inventory;
- collector warnings and completeness;
- cache hit/miss behavior;
- queue depth and oldest pending age;
- quarantine growth;
- disk space in `state_dir`;
- agent version and managed revision;
- release/update failures.
