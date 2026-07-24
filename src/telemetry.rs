/// Initializes structured logging. Honors `RUST_LOG` if set (standard
/// `tracing-subscriber` env-filter syntax); otherwise falls back to the
/// configured `log_level`. Safe to call more than once (e.g. across tests) —
/// later calls are no-ops.
///
/// Log fields must never include provisioning keys, JWTs, `Authorization`
/// headers, raw machine identifiers, or complete software inventories
/// (Plan.md §14). Call sites are responsible for this; nothing here scrubs
/// field content automatically, so never pass those values into a `tracing`
/// field.
pub fn init(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
