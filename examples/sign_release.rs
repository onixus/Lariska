//! Offline Ed25519 signing tool. Private keys are never release artifacts.
use ed25519_dalek::{Signer, SigningKey};
use lariska::update::{canonical_manifest, ReleaseManifest, SignedManifest};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command, private, public] if command == "keygen" => {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let signing = SigningKey::from_bytes(&seed);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            let mut file = options.open(private).map_err(|e| e.to_string())?;
            file.write_all(hex(&seed).as_bytes()).and_then(|()| file.sync_all()).map_err(|e| e.to_string())?;
            fs::write(public, hex(&signing.verifying_key().to_bytes())).map_err(|e| e.to_string())
        }
        [command, private, input, output] if command == "sign" => {
            let secret = fs::read_to_string(private).map_err(|e| e.to_string())?;
            let bytes = decode(secret.trim())?;
            let signing = SigningKey::from_bytes(&bytes);
            let input = fs::read(input).map_err(|e| e.to_string())?;
            if input.len() > 16 * 1024 { return Err("manifest exceeds size limit".into()); }
            let manifest: ReleaseManifest = serde_json::from_slice(&input).map_err(|e| e.to_string())?;
            let signature = hex(&signing.sign(&canonical_manifest(&manifest)?).to_bytes());
            let signed = SignedManifest { manifest, signature };
            let mut options = OpenOptions::new(); options.create_new(true).write(true);
            let mut file = options.open(Path::new(output)).map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec(&signed).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
        }
        _ => Err("usage: sign_release keygen <private-key> <public-key> | sign <private-key> <manifest.json> <signed.json>".into()),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("private key must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
