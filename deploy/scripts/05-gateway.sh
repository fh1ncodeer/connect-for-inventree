#!/bin/bash
# Runs AS inventree (not root), see install.sh.
# Installs the gateway binary, restore script and systemd units, enables the gateway
# and the nightly backup timer.
set -euo pipefail
SRC=/opt/inventree/deploy-src
H=/opt/inventree
export XDG_RUNTIME_DIR=/run/user/$(id -u)
umask 077
cd /tmp

[ -x $SRC/bin/inventree-gw ] || { echo "$SRC/bin/inventree-gw missing"; exit 1; }
mkdir -p $H/bin $H/gateway $H/.config/systemd/user
install -m 755 $SRC/bin/inventree-gw $H/bin/inventree-gw
install -m 700 $SRC/restore.sh $H/bin/restore.sh
install -m 644 $SRC/systemd/* $H/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable inventree-gw inventree-backup.timer
systemctl --user restart inventree-gw
systemctl --user start inventree-backup.timer
sleep 3
systemctl --user is-active inventree-gw inventree-backup.timer
echo "gateway id: $($H/bin/inventree-gw id)"
