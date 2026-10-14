//! Real TLS transport contract: unauthenticated enrollment, followed by
//! mandatory certificate presentation on registration and renewal.
use lariska::{api::ApiClient, config::Config};
use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, KeyPair};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
    TlsAcceptor,
};

#[tokio::test]
async fn endpoint_enrolls_before_required_register_and_renews_with_current_identity() {
    run(Scenario::Renew).await;
}
#[tokio::test]
async fn renewal_503_keeps_valid_identity_on_heartbeat_and_during_backoff() {
    run(Scenario::Renew503).await;
}
#[tokio::test]
async fn lost_first_response_recovers_durable_csr_after_restart() {
    run(Scenario::LostResponse).await;
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum Scenario {
    Renew,
    Renew503,
    LostResponse,
}
async fn run(scenario: Scenario) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let client_issuer_key = KeyPair::generate().unwrap();
    let mut client_issuer_params = CertificateParams::new(vec![]).unwrap();
    client_issuer_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client-intermediate");
    client_issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let client_issuer = client_issuer_params
        .signed_by(&client_issuer_key, &ca, &ca_key)
        .unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&server_key, &ca, &ca_key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .unwrap();
    let server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let enrollments = Arc::new(AtomicUsize::new(0));
    let count = enrollments.clone();
    let ca_pem = ca.pem();
    let task = tokio::spawn(async move {
        let mut existing: Option<(String, Value)> = None;
        let requests = match scenario {
            Scenario::Renew => 4,
            Scenario::Renew503 => 5,
            Scenario::LostResponse => 3,
        };
        for _ in 0..requests {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            let has_cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|c| !c.is_empty());
            let mut raw = Vec::new();
            let header_end;
            loop {
                let mut bytes = [0; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&bytes[..n]);
                if let Some(i) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
                    header_end = i + 4;
                    break;
                }
            }
            let headers = String::from_utf8(raw[..header_end].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|v| v.parse::<usize>().unwrap())
                })
                .unwrap();
            while raw.len() < header_end + length {
                let mut bytes = [0; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                raw.extend_from_slice(&bytes[..n]);
            }
            let body: Value =
                serde_json::from_slice(&raw[header_end..header_end + length]).unwrap();
            let mut status = "200 OK";
            let response = if headers.starts_with("POST /api/v1/agent/certificate/recover ") {
                assert_eq!(scenario, Scenario::LostResponse);
                assert!(!has_cert);
                let (csr, response) = existing.as_ref().unwrap();
                assert_eq!(body["csr"].as_str().unwrap(), csr);
                response.clone()
            } else if headers.starts_with("POST /api/v1/agent/certificate ") {
                let number = count.fetch_add(1, Ordering::SeqCst);
                assert_eq!(has_cert, number > 0, "renewal must present existing cert");
                assert_eq!(body["agent_kind"], "endpoint");
                let mut csr =
                    CertificateSigningRequestParams::from_pem(body["csr"].as_str().unwrap())
                        .unwrap();
                csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
                csr.params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(1);
                csr.params.not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
                let issued = csr.signed_by(&client_issuer, &client_issuer_key).unwrap();
                // First certificate is already due to renew; second is stable.
                let renew = OffsetDateTime::now_utc()
                    + time::Duration::hours(if number == 0 && scenario != Scenario::LostResponse {
                        -1
                    } else {
                        12
                    });
                let issued = json!({"certificate":issued.pem(),"ca_certificate":client_issuer.pem(),"renew_after":renew.format(&Rfc3339).unwrap()});
                existing = Some((body["csr"].as_str().unwrap().to_string(), issued.clone()));
                if scenario == Scenario::LostResponse
                    || scenario == Scenario::Renew503 && number == 1
                {
                    status = "503 Service Unavailable";
                    json!({"detail":"issuer temporarily unavailable"})
                } else {
                    issued
                }
            } else {
                assert!(
                    headers.starts_with("POST /api/v1/agent/register ")
                        || headers.starts_with("POST /api/v1/agent/heartbeat ")
                );
                assert!(has_cert, "required registration has no cert");
                json!({"ok":true})
            };
            let data = serde_json::to_vec(&response).unwrap();
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",data.len()).as_bytes()).await.unwrap();
            stream.write_all(&data).await.unwrap();
        }
    });
    let dir = std::env::temp_dir().join(format!("lariska-tls-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("key"), "bootstrap").unwrap();
    // The config loader keeps this fixture aligned with public settings.
    std::fs::write(dir.join("ca.pem"), ca_pem).unwrap();
    let fixture = toml::to_string(&json!({
        "server_url": format!("https://localhost:{port}"),
        "provisioning_key_file": dir.join("key").to_string_lossy(),
        "state_dir": dir.to_string_lossy(),
        "tls_ca_file": dir.join("ca.pem").to_string_lossy(),
    }))
    .unwrap();
    std::fs::write(dir.join("agent.toml"), fixture).unwrap();
    let config = Config::from_file_and_env(&dir.join("agent.toml")).unwrap();
    let api = ApiClient::new(&config).unwrap();
    if scenario == Scenario::LostResponse {
        assert!(api
            .post_json::<_, Value>("/api/v1/agent/register", Some("token"), &json!({}), None)
            .await
            .is_err());
        assert!(dir.join("client-enrollment.json").exists());
        assert!(!dir.join("client-identity.json").exists());
        drop(api);
        let restarted = ApiClient::new(&config).unwrap();
        let _: Value = restarted
            .post_json("/api/v1/agent/register", Some("token"), &json!({}), None)
            .await
            .unwrap();
        assert!(!dir.join("client-enrollment.json").exists());
    } else {
        let _: Value = api
            .post_json("/api/v1/agent/register", Some("token"), &json!({}), None)
            .await
            .unwrap();
        let _: Value = api
            .post_json("/api/v1/agent/heartbeat", Some("token"), &json!({}), None)
            .await
            .unwrap();
        if scenario == Scenario::Renew503 {
            let _: Value = api
                .post_json("/api/v1/agent/heartbeat", Some("token"), &json!({}), None)
                .await
                .unwrap();
            assert!(dir.join("client-enrollment.json").exists());
        }
    }
    task.await.unwrap();
    assert_eq!(
        enrollments.load(Ordering::SeqCst),
        if scenario == Scenario::LostResponse {
            1
        } else {
            2
        }
    );
    std::fs::remove_dir_all(dir).unwrap();
}
