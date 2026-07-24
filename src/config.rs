use std::collections::HashMap;
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
/// Matches the server's `endpoint_inventory_max_snapshot_age_seconds`
/// default (24h) so an unchanged snapshot is never resent later than the
/// server's own staleness tolerance.
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

impl Config {
    pub fn from_file_and_env(path: &Path) -> Result<Self, ConfigError> {
        let file_values = parse_config_file(path)?;
        Self::from_values_and_env(file_values)
    }

    fn from_values_and_env(mut values: HashMap<String, String>) -> Result<Self, ConfigError> {
        apply_env_override(&mut values, "server_url", "LARISKA_SERVER_URL");
        apply_env_override(
            &mut values,
            "provisioning_key_file",
            "LARISKA_PROVISIONING_KEY_FILE",
        );
        apply_env_override(&mut values, "state_dir", "LARISKA_STATE_DIR");
        apply_env_override(
            &mut values,
            "inventory_interval_secs",
            "LARISKA_INVENTORY_INTERVAL_SECS",
        );
        apply_env_override(
            &mut values,
            "heartbeat_interval_secs",
            "LARISKA_HEARTBEAT_INTERVAL_SECS",
        );
        apply_env_override(
            &mut values,
            "request_timeout_secs",
            "LARISKA_REQUEST_TIMEOUT_SECS",
        );
        apply_env_override(&mut values, "tls_ca_file", "LARISKA_TLS_CA_FILE");
        apply_env_override(&mut values, "log_level", "LARISKA_LOG_LEVEL");
        apply_env_override(&mut values, "allow_plain_http", "LARISKA_ALLOW_PLAIN_HTTP");
        apply_env_override(
            &mut values,
            "inventory_full_refresh_interval_secs",
            "LARISKA_INVENTORY_FULL_REFRESH_INTERVAL_SECS",
        );
        apply_env_override(
            &mut values,
            "max_spool_entries",
            "LARISKA_MAX_SPOOL_ENTRIES",
        );

        let server_url = required_string(&values, "server_url")?;
        let provisioning_key_file = required_path(&values, "provisioning_key_file")?;
        let state_dir = required_path(&values, "state_dir")?;
        let inventory_interval = parse_duration(
            &values,
            "inventory_interval_secs",
            DEFAULT_INVENTORY_INTERVAL_SECS,
        )?;
        let heartbeat_interval = parse_duration(
            &values,
            "heartbeat_interval_secs",
            DEFAULT_HEARTBEAT_INTERVAL_SECS,
        )?;
        let request_timeout = parse_duration(
            &values,
            "request_timeout_secs",
            DEFAULT_REQUEST_TIMEOUT_SECS,
        )?;
        let tls_ca_file = optional_path(&values, "tls_ca_file");
        let log_level = values
            .get("log_level")
            .cloned()
            .unwrap_or_else(|| "info".to_string());
        let allow_plain_http = parse_bool(&values, "allow_plain_http")?;
        let inventory_full_refresh_interval = parse_duration(
            &values,
            "inventory_full_refresh_interval_secs",
            DEFAULT_FULL_REFRESH_INTERVAL_SECS,
        )?;
        let max_spool_entries = parse_bounded_u64(
            &values,
            "max_spool_entries",
            DEFAULT_MAX_SPOOL_ENTRIES,
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
            tls_ca_file,
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

fn parse_config_file(path: &Path) -> Result<HashMap<String, String>, ConfigError> {
    let content = fs::read_to_string(path)
        .map_err(|error| ConfigError::Io(format!("failed to read config file: {error}")))?;
    parse_key_values(&content)
}

fn parse_key_values(content: &str) -> Result<HashMap<String, String>, ConfigError> {
    let mut values = HashMap::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::Invalid(format!(
                "invalid config line {}: expected key = value",
                index + 1
            )));
        };

        values.insert(key.trim().to_string(), trim_value(value));
    }

    Ok(values)
}

fn trim_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn apply_env_override(values: &mut HashMap<String, String>, key: &str, env_key: &str) {
    if let Ok(value) = env::var(env_key) {
        values.insert(key.to_string(), value);
    }
}

fn required_string(values: &HashMap<String, String>, key: &str) -> Result<String, ConfigError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| ConfigError::Invalid(format!("{key} is required")))
}

fn required_path(values: &HashMap<String, String>, key: &str) -> Result<PathBuf, ConfigError> {
    Ok(PathBuf::from(required_string(values, key)?))
}

fn optional_path(values: &HashMap<String, String>, key: &str) -> Option<PathBuf> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn parse_duration(
    values: &HashMap<String, String>,
    key: &str,
    default_secs: u64,
) -> Result<Duration, ConfigError> {
    let seconds = match values.get(key) {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| ConfigError::Invalid(format!("{key} must be an integer")))?,
        None => default_secs,
    };

    Ok(Duration::from_secs(seconds))
}

fn parse_bounded_u64(
    values: &HashMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let value = match values.get(key) {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| ConfigError::Invalid(format!("{key} must be an integer")))?,
        None => default,
    };

    if !(min..=max).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{key} must be between {min} and {max}"
        )));
    }

    Ok(value)
}

fn parse_bool(values: &HashMap<String, String>, key: &str) -> Result<bool, ConfigError> {
    match values.get(key).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(_) => Err(ConfigError::Invalid(format!("{key} must be true or false"))),
    }
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
    fn parse_key_values_supports_quotes_and_comments() {
        let values = parse_key_values(
            r#"
            # comment
            server_url = "https://example.test"
            log_level = 'debug'
            "#,
        )
        .expect("config should parse");

        assert_eq!(
            values.get("server_url"),
            Some(&"https://example.test".to_string())
        );
        assert_eq!(values.get("log_level"), Some(&"debug".to_string()));
    }

    #[test]
    fn config_debug_redacts_secret_path() {
        let temp_dir = env::temp_dir().join(format!("lariska-config-test-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let secret_path = temp_dir.join("secret.key");
        File::create(&secret_path).expect("secret file should be created");

        let mut values = HashMap::new();
        values.insert("server_url".to_string(), "https://example.test".to_string());
        values.insert(
            "provisioning_key_file".to_string(),
            secret_path.display().to_string(),
        );
        values.insert("state_dir".to_string(), temp_dir.display().to_string());

        let config = Config::from_values_and_env(values).expect("config should be valid");
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

        let mut values = HashMap::new();
        values.insert("server_url".to_string(), "http://example.test".to_string());
        values.insert(
            "provisioning_key_file".to_string(),
            secret_path.display().to_string(),
        );
        values.insert("state_dir".to_string(), temp_dir.display().to_string());

        let error = Config::from_values_and_env(values).expect_err("plain http should be rejected");

        assert_eq!(
            error,
            ConfigError::Invalid(
                "server_url must use HTTPS unless allow_plain_http is true".to_string()
            )
        );

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }
}
