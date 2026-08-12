use serde::Deserialize;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_INVENTORY_INTERVAL_SECS: u64 = 3_600;
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 60;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const MIN_INTERVAL_SECS: u64 = 10;
const MAX_INTERVAL_SECS: u64 = 86_400;
const MIN_TIMEOUT_SECS: u64 = 1;
const MAX_TIMEOUT_SECS: u64 = 300;
const DEFAULT_FULL_REFRESH_INTERVAL_SECS: u64 = 86_400;
const DEFAULT_MAX_SPOOL_ENTRIES: u64 = 200;
const MIN_MAX_SPOOL_ENTRIES: u64 = 1;
const MAX_MAX_SPOOL_ENTRIES: u64 = 10_000;

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub server_url: String,
    pub provisioning_key_file: PathBuf,
    pub state_dir: PathBuf,
    pub inventory_interval: Duration,
    pub heartbeat_interval: Duration,
    pub request_timeout: Duration,
    pub tls_ca_file: Option<PathBuf>,
    pub log_level: String,
    pub allow_plain_http: bool,
    pub inventory_full_refresh_interval: Duration,
    pub max_spool_entries: usize,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("provisioning_key_file", &"<redacted>")
            .field("state_dir", &self.state_dir)
            .field("inventory_interval", &self.inventory_interval)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("request_timeout", &self.request_timeout)
            .field("tls_ca_file", &self.tls_ca_file)
            .field("log_level", &self.log_level)
            .field("allow_plain_http", &self.allow_plain_http)
            .field(
                "inventory_full_refresh_interval",
                &self.inventory_full_refresh_interval,
            )
            .field("max_spool_entries", &self.max_spool_entries)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server_url: Option<String>,
    provisioning_key_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    inventory_interval_secs: Option<u64>,
    heartbeat_interval_secs: Option<u64>,
    request_timeout_secs: Option<u64>,
    tls_ca_file: Option<PathBuf>,
    log_level: Option<String>,
    allow_plain_http: Option<bool>,
    inventory_full_refresh_interval_secs: Option<u64>,
    max_spool_entries: Option<u64>,
}

impl Config {
    pub fn from_file_and_env(path: &Path) -> Result<Self, ConfigError> {
        let mut file_config = parse_config_file(path)?;
        apply_env_overrides(&mut file_config)?;
        Self::from_file_config(file_config)
    }

    fn from_file_config(values: FileConfig) -> Result<Self, ConfigError> {
        let server_url = required_string(values.server_url, "server_url")?;
        let provisioning_key_file = required_path(values.provisioning_key_file, "provisioning_key_file")?;
        let state_dir = required_path(values.state_dir, "state_dir")?;
        let inventory_interval = Duration::from_secs(
            values
                .inventory_interval_secs
                .unwrap_or(DEFAULT_INVENTORY_INTERVAL_SECS),
        );
        let heartbeat_interval = Duration::from_secs(
            values
                .heartbeat_interval_secs
                .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_SECS),
        );
        let request_timeout = Duration::from_secs(
            values
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
        );
        let log_level = values.log_level.unwrap_or_else(|| "info".to_string());
        let allow_plain_http = values.allow_plain_http.unwrap_or(false);
        let inventory_full_refresh_interval = Duration::from_secs(
            values
                .inventory_full_refresh_interval_secs
                .unwrap_or(DEFAULT_FULL_REFRESH_INTERVAL_SECS),
        );
        let max_spool_entries = bounded_u64(
            "max_spool_entries",
            values
                .max_spool_entries
                .unwrap_or(DEFAULT_MAX_SPOOL_ENTRIES),
            MIN_MAX_SPOOL_ENTRIES,
            MAX_MAX_SPOOL_ENTRIES,
        )? as usize;

        let config = Self {
            server_url,
            provisioning_key_file,
            state_dir,
            inventory_interval,
            heartbeat_interval,
            request_timeout,
            tls_ca_file: values.tls_ca_file,
            log_level,
            allow_plain_http,
            inventory_full_refresh_interval,
            max_spool_entries,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server_url.trim().is_empty() {
            return Err(ConfigError::Invalid("server_url is required".to_string()));
        }

        if !self.allow_plain_http && !self.server_url.starts_with("https://") {
            return Err(ConfigError::Invalid(
                "server_url must use HTTPS unless allow_plain_http is true".to_string(),
            ));
        }

        if self.allow_plain_http
            && !self.server_url.starts_with("http://")
            && !self.server_url.starts_with("https://")
        {
            return Err(ConfigError::Invalid(
                "server_url must start with http:// or https://".to_string(),
            ));
        }

        if !self.provisioning_key_file.is_file() {
            return Err(ConfigError::Invalid(
                "provisioning_key_file must point to a readable file".to_string(),
            ));
        }

        validate_interval("inventory_interval", self.inventory_interval)?;
        validate_interval("heartbeat_interval", self.heartbeat_interval)?;
        validate_timeout("request_timeout", self.request_timeout)?;
        validate_interval(
            "inventory_full_refresh_interval",
            self.inventory_full_refresh_interval,
        )?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Io(String),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {}

fn parse_config_file(path: &Path) -> Result<FileConfig, ConfigError> {
    let content = fs::read_to_string(path)
        .map_err(|error| ConfigError::Io(format!("failed to read config file: {error}")))?;
    parse_toml(&content)
}

fn parse_toml(content: &str) -> Result<FileConfig, ConfigError> {
    toml::from_str(content)
        .map_err(|error| ConfigError::Invalid(format!("invalid TOML configuration: {error}")))
}

fn apply_env_overrides(values: &mut FileConfig) -> Result<(), ConfigError> {
    override_string(&mut values.server_url, "LARISKA_SERVER_URL");
    override_path(
        &mut values.provisioning_key_file,
        "LARISKA_PROVISIONING_KEY_FILE",
    );
    override_path(&mut values.state_dir, "LARISKA_STATE_DIR");
    override_u64(
        &mut values.inventory_interval_secs,
        "LARISKA_INVENTORY_INTERVAL_SECS",
    )?;
    override_u64(
        &mut values.heartbeat_interval_secs,
        "LARISKA_HEARTBEAT_INTERVAL_SECS",
    )?;
    override_u64(
        &mut values.request_timeout_secs,
        "LARISKA_REQUEST_TIMEOUT_SECS",
    )?;
    override_path(&mut values.tls_ca_file, "LARISKA_TLS_CA_FILE");
    override_string(&mut values.log_level, "LARISKA_LOG_LEVEL");
    override_bool(&mut values.allow_plain_http, "LARISKA_ALLOW_PLAIN_HTTP")?;
    override_u64(
        &mut values.inventory_full_refresh_interval_secs,
        "LARISKA_INVENTORY_FULL_REFRESH_INTERVAL_SECS",
    )?;
    override_u64(
        &mut values.max_spool_entries,
        "LARISKA_MAX_SPOOL_ENTRIES",
    )?;
    Ok(())
}

fn override_string(target: &mut Option<String>, name: &str) {
    if let Ok(value) = env::var(name) {
        *target = Some(value);
    }
}

fn override_path(target: &mut Option<PathBuf>, name: &str) {
    if let Ok(value) = env::var(name) {
        *target = Some(PathBuf::from(value));
    }
}

fn override_u64(target: &mut Option<u64>, name: &str) -> Result<(), ConfigError> {
    if let Ok(value) = env::var(name) {
        *target = Some(value.parse::<u64>().map_err(|_| {
            ConfigError::Invalid(format!("environment variable {name} must be an integer"))
        })?);
    }
    Ok(())
}

fn override_bool(target: &mut Option<bool>, name: &str) -> Result<(), ConfigError> {
    if let Ok(value) = env::var(name) {
        *target = Some(match value.as_str() {
            "true" => true,
            "false" => false,
            _ => {
                return Err(ConfigError::Invalid(format!(
                    "environment variable {name} must be true or false"
                )))
            }
        });
    }
    Ok(())
}

fn required_string(value: Option<String>, key: &str) -> Result<String, ConfigError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ConfigError::Invalid(format!("{key} is required")))
}

fn required_path(value: Option<PathBuf>, key: &str) -> Result<PathBuf, ConfigError> {
    value
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| ConfigError::Invalid(format!("{key} is required")))
}

fn bounded_u64(name: &str, value: u64, min: u64, max: u64) -> Result<u64, ConfigError> {
    if !(min..=max).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{name} must be between {min} and {max}"
        )));
    }
    Ok(value)
}

fn validate_interval(name: &str, value: Duration) -> Result<(), ConfigError> {
    let seconds = value.as_secs();
    if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&seconds) {
        return Err(ConfigError::Invalid(format!(
            "{name} must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS} seconds"
        )));
    }
    Ok(())
}

fn validate_timeout(name: &str, value: Duration) -> Result<(), ConfigError> {
    let seconds = value.as_secs();
    if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&seconds) {
        return Err(ConfigError::Invalid(format!(
            "{name} must be between {MIN_TIMEOUT_SECS} and {MAX_TIMEOUT_SECS} seconds"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn parse_toml_supports_comments_and_typed_values() {
        let values = parse_toml(
            r#"
            # comment
            server_url = "https://example.test"
            log_level = "debug"
            heartbeat_interval_secs = 30
            allow_plain_http = false
            "#,
        )
        .expect("config should parse");

        assert_eq!(values.server_url.as_deref(), Some("https://example.test"));
        assert_eq!(values.log_level.as_deref(), Some("debug"));
        assert_eq!(values.heartbeat_interval_secs, Some(30));
        assert_eq!(values.allow_plain_http, Some(false));
    }

    #[test]
    fn parse_toml_rejects_unknown_keys() {
        let error = parse_toml("heartbeat_intervl_secs = 30")
            .expect_err("unknown key should be rejected");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn parse_toml_rejects_wrong_types() {
        let error = parse_toml("heartbeat_interval_secs = \"thirty\"")
            .expect_err("wrong type should be rejected");

        assert!(error.to_string().contains("invalid type"));
    }

    #[test]
    fn config_debug_redacts_secret_path() {
        let temp_dir = env::temp_dir().join(format!("lariska-config-test-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let secret_path = temp_dir.join("secret.key");
        File::create(&secret_path).expect("secret file should be created");

        let config = Config::from_file_config(FileConfig {
            server_url: Some("https://example.test".to_string()),
            provisioning_key_file: Some(secret_path.clone()),
            state_dir: Some(temp_dir.clone()),
            ..FileConfig::default()
        })
        .expect("config should be valid");
        let debug = format!("{config:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret.key"));

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn config_rejects_plain_http_by_default() {
        let temp_dir = env::temp_dir().join(format!("lariska-http-test-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let secret_path = temp_dir.join("secret.key");
        let mut secret = File::create(&secret_path).expect("secret file should be created");
        writeln!(secret, "bootstrap").expect("secret should be written");

        let error = Config::from_file_config(FileConfig {
            server_url: Some("http://example.test".to_string()),
            provisioning_key_file: Some(secret_path),
            state_dir: Some(temp_dir.clone()),
            ..FileConfig::default()
        })
        .expect_err("plain http should be rejected");

        assert_eq!(
            error,
            ConfigError::Invalid(
                "server_url must use HTTPS unless allow_plain_http is true".to_string()
            )
        );

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }
}
