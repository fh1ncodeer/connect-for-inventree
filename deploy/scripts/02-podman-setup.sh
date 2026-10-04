#!/bin/bash
# Root setup for rootless Podman (run once with sudo):
#  - install packages
#  - system user 'inventree' (home /opt/inventree, no login shell, no sudo)
#  - its own subuid/subgid range, linger (services run without login and start at boot)
#  - sudoers: the admin user may run commands AS inventree (not as root)
# Usage: sudo ./run.sh scripts/02-podman-setup.sh [admin-user]   (default: the user calling sudo)
set -euo pipefail
ADMIN_USER=${1:-${SUDO_USER:?run via sudo or pass the admin user}}

apt-get update
apt-get install -y podman netavark aardvark-dns passt slirp4netns uidmap fuse-overlayfs rsync

if ! id inventree &>/dev/null; then
  useradd --system --create-home --home-dir /opt/inventree \
          --shell /usr/sbin/nologin --comment "InvenTree service" inventree
fi
chmod 750 /opt/inventree

# Next free 65536-wide range after all existing subuid/subgid allocations.
next_range() {
  awk -F: 'BEGIN { m = 100000 } { e = $2 + $3; if (e > m) m = e } END { print m }' /etc/subuid /etc/subgid
}
if ! grep -q '^inventree:' /etc/subuid /etc/subgid; then
  START=$(next_range)
  usermod --add-subuids "$START-$((START + 65535))" --add-subgids "$START-$((START + 65535))" inventree
fi

install -d -o inventree -g inventree /opt/inventree/.config /opt/inventree/.config/containers
cat > /opt/inventree/.config/containers/containers.conf <<'X'
[network]
network_backend = "netavark"
X
chown inventree:inventree /opt/inventree/.config/containers/containers.conf

loginctl enable-linger inventree

echo "$ADMIN_USER ALL=(inventree) NOPASSWD: ALL" > "/etc/sudoers.d/$ADMIN_USER-inventree"
chmod 440 "/etc/sudoers.d/$ADMIN_USER-inventree"
visudo -cf "/etc/sudoers.d/$ADMIN_USER-inventree"

sleep 2
cd /tmp
U=$(id -u inventree)
grep inventree /etc/subuid /etc/subgid
sudo -u inventree -H env XDG_RUNTIME_DIR=/run/user/$U \
  podman info --format 'rootless={{.Host.Security.Rootless}} network={{.Host.NetworkBackend}} version={{.Version.Version}}'
