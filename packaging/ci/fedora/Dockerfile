FROM fedora:44
RUN dnf -y install systemd python3 shadow-utils util-linux procps-ng && dnf clean all
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
