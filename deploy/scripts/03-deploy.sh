#!/bin/bash
# Runs AS inventree (not root), see install.sh.
# Installs config and quadlets, generates secrets once, pulls images, starts InvenTree.
set -euo pipefail
SRC=/opt/inventree/deploy-src
H=/opt/inventree
[ -d $SRC ] || { echo "$SRC missing, run install.sh"; exit 1; }
export XDG_RUNTIME_DIR=/run/user/$(id -u)
umask 077
cd /tmp

mkdir -p $H/config $H/data/static $H/data/media $H/pgdata $H/logs/caddy $H/.config/containers/systemd

if [ ! -f $H/config/inventree.env ]; then
  PW=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  sed "s/__DBPW__/$PW/" $SRC/config/inventree.env.template > $H/config/inventree.env
  sed "s/__DBPW__/$PW/" $SRC/config/db.env.template      > $H/config/db.env
  echo "secrets generated"
fi
install -m 644 $SRC/config/Caddyfile $H/config/Caddyfile
install -m 644 $SRC/quadlets/* $H/.config/containers/systemd/
systemctl --user daemon-reload

for img in $(grep -h '^Image=' $SRC/quadlets/*.container | cut -d= -f2 | sort -u); do
  podman pull -q "$img"
done

systemctl --user start inventree-db inventree-cache inventree-server
for _ in $(seq 1 60); do podman healthcheck run inventree-server &>/dev/null && break; sleep 5; done
podman exec inventree-server invoke update
systemctl --user start inventree-worker inventree-proxy
podman ps --format "{{.Names}}\t{{.Status}}"
