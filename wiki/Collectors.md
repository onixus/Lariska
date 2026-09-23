# Collectors and Inventory Completeness

## Collection contract

Every collector returns:

- normalized `SoftwareEntry` records;
- bounded warnings;
- a completeness flag.

Entries from a failed collector may still be useful for local diagnostics, but the daemon publishes only when the combined result is complete. This conservative v1 rule prevents a missing source from being interpreted as software removal.

## Platform coverage

### Linux

| Source | Evidence and method | Notes |
| --- | --- | --- |
| dpkg | `dpkg-query -W` | Used when `/var/lib/dpkg/status` indicates an active database |
| RPM | `rpm -qa` | Used when an RPM database exists under a standard location |
| pacman | `pacman -Q` | Package name/version; architecture and publisher are not obtained through the fast query |

The agent checks database evidence before invoking a manager so a Debian host with an incidental `rpm` binary does not perform a pointless RPM scan. When no standard database path exists, it can fall back to trusted-binary probing for relocated installations.

External commands:

- are resolved only from trusted system directories;
- are executed without a shell;
- have a timeout;
- have stdout capped while it is read;
- are killed and reaped after timeout/overflow.

### Windows

| Source | Coverage | Notes |
| --- | --- | --- |
| Machine uninstall registry | Native and WOW6432Node views | Avoids `Win32_Product`, which is slow and may trigger MSI repair |
| Loaded user hives | Per-user uninstall views under `HKEY_USERS` | Signed-out users whose hives are not loaded are not scanned |
| CBS packages | Separately named installed KB packages | Cumulative build state is represented primarily by `os_version` |

Registry enumeration errors mark the cycle incomplete. Expected absence of optional views, no loaded profiles, or no separately named CBS KBs is reported as a coverage warning where appropriate but is not automatically treated as a fatal system-wide failure.

### macOS

| Source | Coverage | Notes |
| --- | --- | --- |
| Application bundles | `/Applications` and the current home Applications directory | Reads bounded `Info.plist` metadata |
| Homebrew formulae | `brew list --formula --versions` | Trusted binary resolution and command bounds |
| Homebrew casks | `brew list --cask --versions` | Multiple version tokens are compared naturally |

Bundle directory/read failures are propagated into completeness. Missing optional directories or absent Homebrew are not failures.

## Runtime coverage

### Python

Lariska walks configured/system-discovered `site-packages` roots and parses bounded `*.dist-info/METADATA` files without starting a Python interpreter. Package name, version, and publisher metadata are normalized when available.

### Node.js

The collector walks known global package roots and reads bounded `package.json` documents. Optional metadata such as `author` is tolerated even when tools use unusual JSON shapes.

### Java

Known JVM/JDK roots are inspected through bounded `release` metadata. Entries without a usable version are not emitted as valid runtimes.

Runtime collectors run in a controlled blocking context and deliberately avoid racing all ecosystems across the disk at once.

## Persistent cache

The cache lives under `state_dir/inventory-cache-v1/` and stores separate documents for:

- platform inventory;
- Python;
- Node.js;
- Java.

A cache entry is reused only when:

- its format version is supported;
- it was written by the same agent version;
- the source fingerprint is unchanged;
- the cached result was complete;
- the full-refresh interval has not expired;
- the document parses and stays below the size limit.

Fingerprints use cheap metadata evidence from package databases and runtime roots. Fingerprint walks are item-bounded. Corrupt, stale, incompatible, or oversized cache entries are discarded and replaced by a real collection. Incomplete results are never cached.

The diagnostic `lariska inventory` command bypasses the persistent cache so the operator receives a fresh local read.

## Normalization

Lariska currently normalizes:

- surrounding and repeated whitespace;
- optional empty fields;
- common architecture aliases such as `amd64`/`x64` → `x86_64` and `arm64` → `aarch64`;
- source names into the schema-v1 source enum;
- deterministic ordering;
- duplicate identifiers and software comparison keys.

When schema v1 encounters multiple versions with the same product comparison key, it retains the naturally newer version and emits a warning about the dropped version. This is safer than arbitrary lexical ordering but is not a substitute for installation identity.

## Completeness examples

| Situation | Diagnostic output | Daemon submission |
| --- | --- | --- |
| Homebrew is not installed | Other sources, no failure | Allowed |
| `dpkg-query` times out | Partial entries plus warning | Blocked |
| One Windows uninstall entry cannot be opened | Remaining entries plus warning | Blocked |
| No user profiles are loaded on a Windows server | System entries plus coverage warning | Allowed |
| Runtime metadata file exceeds its limit | File skipped | Depends on collector-level error policy; warnings remain bounded |
| Cache document is corrupt | Cache ignored, fresh collection attempted | Allowed only if fresh result completes |

## Planned v2 behavior

Schema v2 will replace the all-or-nothing snapshot rule with per-source status:

- `complete`;
- `partial`;
- `failed`;
- `not_applicable`.

Shapoclyack will then carry forward the last complete set for degraded sources while accepting healthy source updates. Removal events will be legal only for a source that completed authoritatively.
