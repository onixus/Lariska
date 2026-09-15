use std::sync::OnceLock;
use tracing_subscriber::reload;
use tracing_subscriber::EnvFilter;

/// Set once, when logging is initialised, and used afterwards to change the
/// level of a *running* agent (Shapoclyack #358).
///
/// The point of remote management is not having to go to the machine, and a
/// log level that needs a restart to change is a log level nobody turns up at
/// the moment they need it. `None` until `init`/`init_to_file` has run, and a
/// change asked for before that is dropped rather than queued: the level the
/// subscriber starts with comes from the configuration anyway.
static FILTER_HANDLE: OnceLock<reload::Handle<EnvFilter, tracing_subscriber::Registry>> =
    OnceLock::new();

/// Switches the running agent's log level. Unknown levels are refused, and the
/// current one kept: a policy nobody validated must not be able to silence an
/// agent.
pub fn set_log_level(level: &str) {
    let Some(handle) = FILTER_HANDLE.get() else {
        return;
    };
    let filter = match EnvFilter::try_new(level) {
        Ok(filter) => filter,
        Err(error) => {
            tracing::warn!(%level, %error, "refusing an unparseable log level");
            return;
        }
    };
    if let Err(error) = handle.reload(filter) {
        tracing::warn!(%error, "could not change the log level");
    } else {
        tracing::info!(%level, "log level changed by the server");
    }
}

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
    install(base_filter(log_level), None);
}

fn base_filter(log_level: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level))
}

/// Builds the subscriber, behind a reload layer so the level can be changed
/// later, and remembers the handle. `writer` is the file sink used under the
/// Windows SCM; `None` means stdout.
fn install(filter: EnvFilter, writer: Option<std::fs::File>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let (layer, handle) = reload::Layer::new(filter);

    let result = match writer {
        Some(file) => tracing_subscriber::registry()
            .with(layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(move || {
                        file.try_clone().map(LogSink::File).unwrap_or(LogSink::Discard)
                    }),
            )
            .try_init(),
        None => tracing_subscriber::registry()
            .with(layer)
            .with(tracing_subscriber::fmt::layer().with_target(false))
            .try_init(),
    };

    // Only the call that actually installed the subscriber owns the handle.
    // `try_init` failing means another one is already in place -- across tests,
    // usually -- and reloading a filter that is not wired to anything would be
    // a silent no-op reported as success.
    if result.is_ok() {
        let _ = FILTER_HANDLE.set(handle);
    }
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

    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => install(base_filter(log_level), Some(file)),
        Err(_) => init(log_level),
    }
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
