#!/usr/bin/env bash
set -euo pipefail
version=$1
kind=$2
binary=${3:-target/release/lariska}
arch=$(uname -m)
case "$arch" in
  x86_64) deb_arch=amd64 ;;
  aarch64) deb_arch=arm64 ;;
  *) echo "unsupported native Linux architecture: $arch" >&2; exit 2 ;;
esac
target="$arch-unknown-linux-gnu"
out="dist/$version"
mkdir -p "$out"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/usr/bin" "$staging/usr/libexec" "$staging/lib/systemd/system" "$staging/usr/share/lariska/trust"
install -m755 "$binary" "$staging/usr/bin/lariska"
install -m755 "$binary" "$staging/usr/libexec/lariska-updater"
install -m644 packaging/systemd/*.service "$staging/lib/systemd/system/"
install -m644 packaging/trust/public-trust.json "$staging/usr/share/lariska/trust/"
if [ "$kind" = deb ]; then
  mkdir "$staging/DEBIAN"
  cat > "$staging/DEBIAN/control" <<EOF
Package: lariska
Version: $version
Architecture: $deb_arch
Maintainer: Shapoclyack
Description: Endpoint inventory and independently supervised signed native updater
Depends: libc6, adduser
EOF
  install -m755 packaging/deb/postinst "$staging/DEBIAN/postinst"
  install -m755 packaging/deb/prerm "$staging/DEBIAN/prerm"
  install -m755 packaging/deb/postrm "$staging/DEBIAN/postrm"
  dpkg-deb --root-owner-group --build "$staging" "$out/lariska-$version-$target.deb"
elif [ "$kind" = rpm ]; then
  mkdir -p "$staging/rpmbuild"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  tar -C "$staging" --exclude=rpmbuild -czf "$staging/rpmbuild/SOURCES/lariska.tar.gz" usr lib
  sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" packaging/rpm/lariska.spec > "$staging/rpmbuild/SPECS/lariska.spec"
  rpmbuild --define "_topdir $staging/rpmbuild" --define "_build_id_links none" --define "debug_package %{nil}" --target "$arch" -bb "$staging/rpmbuild/SPECS/lariska.spec"
  cp "$staging/rpmbuild/RPMS/$arch/lariska-$version-1.$arch.rpm" "$out/lariska-$version-$target.rpm"
else
  echo 'kind must be deb or rpm' >&2; exit 2
fi
