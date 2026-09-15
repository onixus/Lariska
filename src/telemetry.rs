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

/// Initializes logging into `path` instead of stdout, for the Windows service
/// entry point: under the SCM no console is attached, so anything written to
/// stdout is discarded and the service is silent (#358).
///
/// The file is opened in append mode and rotated once at startup when it has
/// grown past `MAX_LOG_BYTES` — the previous contents move to `<path>.1`, and
/// the generation before that is dropped. That is a deliberate floor, not a
/// log-management story: an operator who needs retention ships the file.
///
/// Falls back to stdout if the file cannot be opened, so a bad path degrades
/// to the previous behaviour rather than losing the run.
pub fn init_to_file(log_level: &str, path: &std::path::Path) {
    const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

    if std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) > MAX_LOG_BYTES {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let file = match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => file,
        Err(_) => {
            init(log_level);
            return;
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || {
            file.try_clone()
                .map(LogSink::File)
                .unwrap_or(LogSink::Discard)
        })
        .try_init();
}

/// Writer handed to the subscriber for each log line. `Discard` covers the
/// case where the handle cannot be cloned mid-run: dropping the line beats
/// panicking inside the logger.
enum LogSink {
    File(std::fs::File),
    Discard,
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.write(buf),
            Self::Discard => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Discard => Ok(()),
        }
    }
}
