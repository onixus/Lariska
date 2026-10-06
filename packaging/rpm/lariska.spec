Name: lariska
Version: @VERSION@
Release: 1
Summary: Endpoint inventory and signed native package supervisor
License: Proprietary
Source0: lariska.tar.gz
BuildArch: @ARCH@
AutoReqProv: no

%description
Cross-platform endpoint inventory for Shapoclyack with an independent native recovery supervisor.

%prep

%build

%install
mkdir -p %{buildroot}
tar -xzf %{SOURCE0} -C %{buildroot}

%post
if ! getent passwd lariska >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin lariska
fi
install -d -m0750 -o root -g lariska /etc/lariska
install -d -m0750 -o lariska -g lariska /var/lib/lariska
install -d -m0700 -o root -g root /var/lib/lariska-updater
if [ ! -e /var/lib/lariska-updater/supervisor ]; then
  install -m0700 -o root -g root /usr/libexec/lariska-updater /var/lib/lariska-updater/supervisor
fi
systemctl daemon-reload || :
# Do not restart the stable updater during an endpoint package transaction.

%preun
if [ "$1" -eq 0 ]; then
  systemctl stop lariska.service lariska-updater.service || :
  systemctl disable lariska.service lariska-updater.service || :
fi

%postun
systemctl daemon-reload || :

%files
/usr/bin/lariska
/usr/libexec/lariska-updater
/lib/systemd/system/lariska.service
/lib/systemd/system/lariska-updater.service
/usr/share/lariska/trust/public-trust.json
