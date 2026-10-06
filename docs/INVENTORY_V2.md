# Inventory v2 and source completeness

Registration and heartbeat advertise `inventory_schema_versions: [1, 2]`. Lariska uses schema v2 only after the server explicitly returns `inventory_schema_version: 2`; an absent or unknown response selects v1. The older-server path still refuses the entire collection when any required collector is incomplete. Deploy the companion Shapoclyack change before enabling v2 on a fleet.

The product identity is the normalized name, publisher, architecture and source comparison key. The installation identity is a separate SHA-256 identifier over product identity, native package ID, scope and an opaque install instance. Native collectors use package-manager IDs, MSI ProductCode, registry hive/view/subkey, macOS bundle ID and the actual runtime metadata directory. Instance paths are canonicalized where available, hashed with a versioned domain and scoped to the endpoint's agent ID. Raw paths, usernames and user SIDs are absent from the v2 wire payload. System, user, runtime and container are distinct scopes.

Schema v2 normalizes and deduplicates by installation identity. JDK 17 and 21, multiple Homebrew versions, and packages in different Python environments retain separate rows. Normalization and resend preserve the same identifiers. Schema v1 conversion retains the historical newest-product-row behavior and emits a diagnostic when a side-by-side installation cannot be represented.

Every supported collector reports a `sources` record, including an absent optional source. Each record carries `source`, `status`, `collected_at`, `last_complete_at`, `collector_version` and a bounded diagnostic code. Sources include dpkg, RPM, pacman, Windows registry/MSI/CBS, macOS bundles/Homebrew and pip/npm/Java.

| Status | Effective inventory on the server |
| --- | --- |
| `complete` | Replace this source; missing installations can produce removals. |
| `partial` | Preserve its previous effective inventory; partial observations cannot manufacture changes. |
| `failed` | Preserve its previous effective inventory. |
| `not_applicable` | Preserve any previous effective inventory; only a complete observation authorizes removal. |

A malformed or unreadable runtime metadata file degrades its source instead of silently removing that installation. Windows unloaded profile hives degrade registry/MSI inventory so logging out does not remove user installations. CBS remains independent of the registry source. The cache stores complete results only, retains their actual collection time, and persists each source's last complete time across restarts. Status transitions change the delivery digest; collection timestamps alone do not defeat unchanged-inventory suppression.

`tests/fixtures/inventory_v2.json` is shared byte-for-byte with Shapoclyack's `tests/fixtures/endpoint_inventory_v2_valid.json`. Keep the v1 fixture and v1 ingestion available throughout the mixed-fleet migration. The Shapoclyack companion change owns effective-state carry-forward, removal/CVE decisions and source status/age display.
