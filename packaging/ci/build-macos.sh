#!/usr/bin/env bash
set -euo pipefail
version=$1
binary=${2:-target/release/lariska}
# An application code-signing certificate cannot sign a flat installer package.
# Check the public certificate before building; productsign remains authoritative.
python - <<'PY'
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
import hashlib, json
from pathlib import Path
encoded = Path('packaging/trust/macos.cer').read_bytes()
certificate = x509.load_der_x509_certificate(encoded)
try:
    purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
except x509.ExtensionNotFound:
    raise SystemExit('macOS installer certificate has no Extended Key Usage')
if ObjectIdentifier('1.2.840.113635.100.4.13') not in purposes:
    raise SystemExit('macOS signing certificate requires installer EKU 1.2.840.113635.100.4.13; application Code Signing EKU cannot sign packages')
trust = json.loads(Path('packaging/trust/public-trust.json').read_text())
if hashlib.sha256(encoded).hexdigest() != trust['certificates']['macos']['sha256'].lower():
    raise SystemExit('macOS signing certificate differs from the provisioned public SHA-256 pin')
PY
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/root/usr/local/bin" "$staging/root/usr/local/libexec" "$staging/root/Library/LaunchDaemons" "$staging/root/usr/local/share/lariska/trust" "dist/$version"
install -m755 "$binary" "$staging/root/usr/local/bin/lariska"
install -m755 "$binary" "$staging/root/usr/local/libexec/lariska-updater"
install -m644 packaging/launchd/*.plist "$staging/root/Library/LaunchDaemons/"
install -m644 packaging/trust/public-trust.json packaging/trust/macos.cer "$staging/root/usr/local/share/lariska/trust/"
chmod 755 packaging/macos/scripts/postinstall
pkgbuild --root "$staging/root" --scripts packaging/macos/scripts --identifier com.shapoclyack.lariska --version "$version" --install-location / "$staging/unsigned.pkg"
productsign --timestamp=none --keychain "$LARISKA_SIGNING_KEYCHAIN" --sign 'Lariska Local Installer' "$staging/unsigned.pkg" "dist/$version/lariska-$version-$(uname -m)-apple-darwin.pkg"
pkgutil --check-signature "dist/$version/lariska-$version-$(uname -m)-apple-darwin.pkg" | tee "$staging/signature.txt"
# The imported P12 can contain a same-name identity with a different key. Bind
# the resulting package's leaf signer, not merely its CN, to the client pin.
python - "$staging/signature.txt" <<'PY_SIGNER'
import json, re, sys
from pathlib import Path
in_leaf = False
digest = ''
reading_digest = False
for line in Path(sys.argv[1]).read_text().splitlines():
    text = line.strip()
    entry = re.fullmatch(r'([0-9]+)\.\s*(.*)', text)
    if entry:
        if in_leaf:
            break
        in_leaf = entry[1] == '1'
        continue
    if not in_leaf:
        continue
    fingerprint = re.fullmatch(r'SHA-?256 Fingerprint:\s*(.*)', text, re.IGNORECASE)
    if fingerprint:
        reading_digest = True
        digest += ''.join(c for c in fingerprint[1] if c in '0123456789abcdefABCDEF')
    elif reading_digest:
        if re.fullmatch(r'[0-9a-fA-F:\s]*', text):
            digest += ''.join(c for c in text if c in '0123456789abcdefABCDEF')
        else:
            reading_digest = False
trust = json.loads(Path('packaging/trust/public-trust.json').read_text())
if len(digest) != 64 or digest.lower() != trust['certificates']['macos']['sha256'].lower():
    raise SystemExit('Signed macOS package leaf certificate differs from the provisioned public SHA-256 pin')
print('Signed macOS package leaf certificate matches the provisioned public pin')
PY_SIGNER
