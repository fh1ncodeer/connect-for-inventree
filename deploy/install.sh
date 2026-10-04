#!/bin/bash
# Deploys InvenTree (and optionally the gateway) as the 'inventree' user.
# Run as the admin user AFTER scripts/02-podman-setup.sh (no root needed):
#   ./install.sh                                  # InvenTree only
#   ./install.sh path/to/inventree-gw             # InvenTree + gateway + backups
set -euo pipefail
cd "$(dirname "$0")"
SU="sudo -n -u inventree -H"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

cp -r config quadlets systemd scripts "$STAGE"/
cp ../contrib/restore.sh "$STAGE"/
if [ -n "${1:-}" ]; then mkdir "$STAGE/bin" && cp "$1" "$STAGE/bin/inventree-gw"; fi

cd /tmp
$SU bash -c 'rm -rf /opt/inventree/deploy-src && mkdir -p /opt/inventree/deploy-src'
tar -C "$STAGE" -c . | $SU tar -C /opt/inventree/deploy-src -x
$SU bash /opt/inventree/deploy-src/scripts/03-deploy.sh
[ -n "${1:-}" ] && $SU bash /opt/inventree/deploy-src/scripts/05-gateway.sh
echo ">> done. Create the InvenTree admin with:"
echo "   cd /tmp && sudo -u inventree -H env XDG_RUNTIME_DIR=/run/user/\$(id -u inventree) podman exec -it inventree-server invoke superuser"
