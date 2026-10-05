#!/usr/bin/env bash
set -euo pipefail
version=$1
binary=${2:-target/release/lariska}
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
pkgutil --check-signature "dist/$version/lariska-$version-$(uname -m)-apple-darwin.pkg"
