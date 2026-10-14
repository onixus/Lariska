//! One durable bundle owns the private key and issued certificate. Publication
//! happens only after key matching and validity checks; no partial pair exists.
use crate::{api::ApiError, config::Config};
use rcgen::{CertificateParams, KeyPair};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Serialize, Deserialize)]
struct Bundle {
    key: String,
    certificate: String,
    renew_after: String,
}
#[derive(Deserialize)]
struct Issued {
    certificate: String,
    renew_after: String,
}

pub struct State {
    bundle: Option<Bundle>,
    unavailable: bool,
    retry_at: i64,
}
impl State {
    pub fn load(config: &Config) -> Result<Self, ApiError> {
        let bundle = match fs::read(config.state_dir.join("client-identity.json")) {
            Ok(bytes) => {
                let b: Bundle = serde_json::from_slice(&bytes).map_err(fatal)?;
                validate(&b)?;
                Some(b)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(fatal(e)),
        };
        Ok(Self {
            bundle,
            unavailable: false,
            retry_at: 0,
        })
    }
    pub fn client(&self, config: &Config) -> Result<Client, ApiError> {
        build(
            config,
            self.bundle
                .as_ref()
                .filter(|b| valid_now(b).unwrap_or(false)),
        )
    }
    pub async fn ensure(&mut self, config: &Config, token: &str) -> Result<Client, ApiError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if !config.server_url.starts_with("https://") || self.unavailable {
            return self.client(config);
        }
        let due = match &self.bundle {
            Some(b) => !valid_now(b)? || now >= timestamp(&b.renew_after)?,
            None => true,
        };
        if !due {
            return self.client(config);
        }
        if now < self.retry_at {
            return Err(ApiError::Transient(
                "certificate enrollment is backing off".into(),
            ));
        }
        self.retry_at = now + 300;
        let key = KeyPair::generate().map_err(fatal)?;
        let csr = CertificateParams::new(Vec::<String>::new())
            .map_err(fatal)?
            .serialize_request(&key)
            .map_err(fatal)?
            .pem()
            .map_err(fatal)?;
        let response = self
            .client(config)?
            .post(format!(
                "{}/api/v1/agent/certificate",
                config.server_url.trim_end_matches('/')
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({"csr": csr, "agent_kind": "endpoint"}))
            .send()
            .await
            .map_err(|error| crate::api::classify_transport_error(&error))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND && self.bundle.is_none() {
            self.unavailable = true;
            return self.client(config);
        }
        let issued: Issued = crate::api::classify_response(response).await?;
        let bundle = Bundle {
            key: key.serialize_pem(),
            certificate: issued.certificate,
            renew_after: issued.renew_after,
        };
        validate(&bundle)?;
        if !valid_now(&bundle)? {
            return Err(fatal(
                "issuer returned a certificate outside its validity period",
            ));
        }
        let client = build(config, Some(&bundle))?;
        persist(&config.state_dir, &bundle)?;
        self.bundle = Some(bundle);
        self.retry_at = 0;
        Ok(client)
    }
    pub fn recover(&mut self) {
        self.bundle = None;
        self.unavailable = false;
        self.retry_at = 0;
    }
}
fn fatal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Fatal(format!("client certificate: {e}"))
}
fn timestamp(value: &str) -> Result<i64, ApiError> {
    Ok(OffsetDateTime::parse(value, &Rfc3339)
        .map_err(fatal)?
        .unix_timestamp())
}
fn valid_now(b: &Bundle) -> Result<bool, ApiError> {
    let pem = x509_parser::pem::parse_x509_pem(b.certificate.as_bytes())
        .map_err(fatal)?
        .1;
    let cert = pem.parse_x509().map_err(fatal)?;
    Ok(cert.validity().is_valid())
}
fn validate(b: &Bundle) -> Result<(), ApiError> {
    let key = KeyPair::from_pem(&b.key).map_err(fatal)?;
    let pem = x509_parser::pem::parse_x509_pem(b.certificate.as_bytes())
        .map_err(fatal)?
        .1;
    let cert = pem.parse_x509().map_err(fatal)?;
    if cert.public_key().raw != key.public_key_der() {
        return Err(fatal("certificate does not match private key"));
    }
    let renewal = timestamp(&b.renew_after)?;
    if renewal >= cert.validity().not_after.timestamp() {
        return Err(fatal("renewal must precede certificate expiration"));
    }
    Ok(())
}
fn build(config: &Config, bundle: Option<&Bundle>) -> Result<Client, ApiError> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.request_timeout);
    if let Some(path) = &config.tls_ca_file {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&fs::read(path).map_err(fatal)?).map_err(fatal)?,
        );
    }
    if let Some(b) = bundle {
        builder = builder.identity(
            reqwest::Identity::from_pem(format!("{}\n{}", b.key, b.certificate).as_bytes())
                .map_err(fatal)?,
        );
    }
    builder.build().map_err(fatal)
}
fn persist(dir: &Path, bundle: &Bundle) -> Result<(), ApiError> {
    fs::create_dir_all(dir).map_err(fatal)?;
    let path = dir.join("client-identity.json");
    let temp = dir.join(format!(".client-identity-{}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(fatal)?;
        file.write_all(&serde_json::to_vec(bundle).map_err(fatal)?)
            .map_err(fatal)?;
        file.sync_all().map_err(fatal)?;
        replace(&temp, &path).map_err(fatal)?;
        #[cfg(unix)]
        fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(fatal)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bundle(expired: bool) -> Bundle {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(2);
        params.not_after = now + time::Duration::days(if expired { -1 } else { 2 });
        let cert = params.clone().self_signed(&key).unwrap();
        Bundle {
            key: key.serialize_pem(),
            certificate: cert.pem(),
            renew_after: (params.not_before + time::Duration::hours(1))
                .format(&Rfc3339)
                .unwrap(),
        }
    }
    #[test]
    fn mismatched_pair_and_invalid_renewal_are_rejected() {
        let mut b = bundle(false);
        validate(&b).unwrap();
        b.key = KeyPair::generate().unwrap().serialize_pem();
        assert!(validate(&b).is_err());
        let mut b = bundle(false);
        b.renew_after = "9999-01-01T00:00:00Z".into();
        assert!(validate(&b).is_err());
    }
    #[test]
    fn expiry_is_checked_from_certificate_not_server_metadata() {
        assert!(!valid_now(&bundle(true)).unwrap());
        assert!(valid_now(&bundle(false)).unwrap());
    }
    #[test]
    fn pair_is_one_private_atomic_file_and_replacement_survives_reload() {
        let dir = std::env::temp_dir().join(format!("lariska-mtls-{}", rand::random::<u64>()));
        let first = bundle(false);
        persist(&dir, &first).unwrap();
        let next = bundle(false);
        persist(&dir, &next).unwrap();
        let saved: Bundle =
            serde_json::from_slice(&fs::read(dir.join("client-identity.json")).unwrap()).unwrap();
        assert_eq!(saved.key, next.key);
        assert_eq!(saved.certificate, next.certificate);
        validate(&saved).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("client-identity.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
