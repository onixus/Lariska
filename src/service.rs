use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

const LOCK_FILE_NAME: &str = "lariska.lock";

#[derive(Debug)]
pub enum ServiceError {
    Io(String),
    AlreadyRunning(PathBuf),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => formatter.write_str(message),
            Self::AlreadyRunning(path) => write!(
                formatter,
                "another Lariska instance already holds the lock at {} — is it already running for this state directory?",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Holds an OS-level advisory lock on a file under `state_dir` for as long
/// as this value is alive, preventing two agent processes from sharing one
/// state directory (Plan.md §12: "single-instance locking for one state
/// directory"). The lock is released automatically when the process exits
/// (the file descriptor closes) — there is no explicit unlock.
pub struct SingleInstanceLock {
    _file: File,
}

pub fn acquire(state_dir: &Path) -> Result<SingleInstanceLock, ServiceError> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| ServiceError::Io(format!("failed to create state directory: {error}")))?;

    let lock_path = state_dir.join(LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            ServiceError::Io(format!(
                "failed to open lock file {}: {error}",
                lock_path.display()
            ))
        })?;

    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        Ok(guard) => {
            // The guard's Drop would release the lock; we want it held for
            // the process lifetime instead, so we deliberately never drop
            // it. The lock still releases automatically on process exit
            // when the underlying file descriptor closes.
            std::mem::forget(guard);
        }
        Err(_) => return Err(ServiceError::AlreadyRunning(lock_path)),
    }

    Ok(SingleInstanceLock {
        _file: lock.into_inner(),
    })
}

/// Resolves when the process should shut down: `Ctrl-C`/`SIGINT` on every
/// platform, plus `SIGTERM` on Unix (the signal a service manager sends to
/// stop the unit).
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    result = tokio::signal::ctrl_c() => {
                        if result.is_err() {
                            tracing::error!("failed to listen for Ctrl-C");
                        }
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler; falling back to Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("failed to listen for Ctrl-C");
        }
    }
}

/// Windows Service Control Manager (SCM) integration. Lets Lariska run as a
/// native Windows Service (`sc.exe create Lariska binPath= "...lariska.exe
/// --winservice"`) instead of needing a third-party wrapper.
///
/// Known gap: this has been verified to compile against the real
/// `windows-service` crate API (cross-checked with
/// `cargo check --target x86_64-pc-windows-gnu`) but has never run against a
/// real SCM — this repository has no Windows machine available. Verify
/// install/start/stop manually before relying on it in production, per
/// Plan.md §17 Phase L5 acceptance ("install/start/restart/stop works on
/// each target platform").
#[cfg(windows)]
pub mod windows_scm {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    pub const SERVICE_NAME: &str = "Lariska";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    /// Blocks the calling thread until the SCM tells the service to stop.
    /// Call this instead of `app::run` when launched with `--winservice`.
    pub fn run_as_service() -> Result<(), String> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|error| format!("failed to start Windows service dispatcher: {error}"))
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            tracing::error!(%error, "Windows service run failed");
        }
    }

    fn run_service() -> Result<(), String> {
        let stop_notify = Arc::new(Notify::new());
        let handler_notify = Arc::clone(&stop_notify);

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    handler_notify.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .map_err(|error| format!("failed to register service control handler: {error}"))?;

        report_status(
            &status_handle,
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::default(),
        )?;

        let config_path = crate::app::default_service_config_path();
        let result = crate::app::run_as_windows_service(&config_path, stop_notify);

        let exit_code = if result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        };
        report_status(
            &status_handle,
            ServiceState::Stopped,
            exit_code,
            Duration::default(),
        )
        .ok();

        result
    }

    fn report_status(
        status_handle: &ServiceStatusHandle,
        state: ServiceState,
        exit_code: ServiceExitCode,
        wait_hint: Duration,
    ) -> Result<(), String> {
        status_handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code,
                checkpoint: 0,
                wait_hint,
                process_id: None,
            })
            .map_err(|error| format!("failed to report service status: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_on_the_same_state_dir_fails() {
        let state_dir =
            std::env::temp_dir().join(format!("lariska-service-lock-test-{}", std::process::id()));

        let first = acquire(&state_dir).expect("first lock should succeed");
        let second = acquire(&state_dir);

        assert!(matches!(second, Err(ServiceError::AlreadyRunning(_))));

        drop(first);
        std::fs::remove_dir_all(&state_dir).ok();
    }
}
