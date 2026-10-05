use lariska::app;
#[cfg(windows)]
use lariska::service;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CONFIG_PATH: &str = "lariska.toml";

fn main() -> ExitCode {
    match dispatch(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("run") => {
            let running_as_service = args[1..].iter().any(|arg| arg == "--service");
            app::run(&config_path(&args[1..]), running_as_service)
        }
        // Registered as the Windows service binPath target (e.g. `sc.exe
        // create Lariska binPath= "...lariska.exe --winservice"`). Blocks in
        // the SCM dispatcher loop instead of the normal CLI flow.
        Some("--winservice") => {
            #[cfg(windows)]
            {
                service::windows_scm::run_as_service()
            }
            #[cfg(not(windows))]
            {
                Err("--winservice is only supported when running on Windows".to_string())
            }
        }
        Some("check-config") => app::check_config(&config_path(&args[1..])),
        Some("update-supervisor") => lariska::native_update::supervise(
            &config_path(&args[1..]),
            args[1..].iter().any(|a| a == "--once"),
        ),
        Some("update-seed") => lariska::native_update::seed(
            &config_path(&args[1..]),
            &required_path(&args[1..], "--manifest")?,
            &required_path(&args[1..], "--artifact")?,
        ),
        Some("--version" | "version") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("inventory") => {
            ensure_inventory_args(&args[1..])?;
            app::print_inventory();
            Ok(())
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command: {command}")),
    }
}

fn required_path(args: &[String], flag: &str) -> Result<PathBuf, String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .ok_or_else(|| format!("required argument: {flag} path"))
}

fn config_path(args: &[String]) -> PathBuf {
    args.windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| PathBuf::from(&pair[1]))
        .or_else(|| env::var("LARISKA_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn ensure_inventory_args(args: &[String]) -> Result<(), String> {
    match args {
        [] => Ok(()),
        [flag, value] if flag == "--output" && value == "json" => Ok(()),
        _ => Err("usage: lariska inventory [--output json]".to_string()),
    }
}

fn print_usage() {
    println!(
        "Usage:\n  lariska run [--config path] [--service]\n  lariska check-config [--config path]\n  lariska inventory [--output json]\n  lariska update-supervisor --config path [--once]\n  lariska update-seed --config path --manifest path --artifact path\n  lariska --version"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_uses_cli_override() {
        let args = vec!["--config".to_string(), "custom.toml".to_string()];

        assert_eq!(config_path(&args), PathBuf::from("custom.toml"));
    }

    #[test]
    fn inventory_args_accept_json_output() {
        let args = vec!["--output".to_string(), "json".to_string()];

        assert!(ensure_inventory_args(&args).is_ok());
    }
}
