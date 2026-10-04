#!/bin/bash
# Restores a decrypted InvenTree backup. Run as the 'inventree' user on the server:
#   inventree-gw decrypt --key backup-key.age inventree-<ts>.tar.age -o /opt/inventree/tmp/restore.tar
#   restore.sh /opt/inventree/tmp/restore.tar
# Overwrites the database, data/, config/ and gateway/ with the backup contents.
set -euo pipefail
exec </dev/null   # podman/systemctl must not consume stdin (e.g. when this script is piped)

TAR=$(realpath "$1")
H=/opt/inventree
W=$H/tmp/restore
export XDG_RUNTIME_DIR=/run/user/$(id -u)
umask 077

wait_for() { # <description> <command...>
  local what=$1; shift
  for _ in $(seq 1 60); do "$@" &>/dev/null && return 0; sleep 3; done
  echo "timeout waiting for $what" >&2; return 1
}

echo ">> unpacking $TAR"
rm -rf "$W"; mkdir -p "$W"
tar -xf "$TAR" -C "$W"
for f in db.dump data config gateway manifest.json; do
  [ -e "$W/$f" ] || { echo "backup is missing $f" >&2; exit 1; }
done
cat "$W/manifest.json"

echo ">> stopping InvenTree"
systemctl --user stop inventree-gw inventree-proxy inventree-worker inventree-server

echo ">> restoring files"
rsync -a --delete --exclude static --exclude backup "$W/data/" "$H/data/"
rsync -a "$W/config/" "$H/config/"
rsync -a "$W/gateway/" "$H/gateway/"

echo ">> restoring database"
systemctl --user start inventree-db
wait_for "database" podman exec inventree-db pg_isready -U inventree -d inventree
podman exec -i inventree-db pg_restore -U inventree -d inventree --clean --if-exists --no-owner <"$W/db.dump"

echo ">> starting InvenTree"
systemctl --user start inventree-server
wait_for "server" bash -c 'podman healthcheck run inventree-server'
podman exec inventree-server invoke update
systemctl --user start inventree-worker inventree-proxy inventree-gw

rm -rf "$W"
echo ">> restore complete. Remove the decrypted tar: rm $TAR"
