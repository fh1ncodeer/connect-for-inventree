#!/bin/bash
# Lets the admin user read the system journal (read only), so container logs are visible
# via journalctl CONTAINER_NAME=inventree-server.
# Usage: sudo ./run.sh scripts/04-journal-group.sh [admin-user]
set -euo pipefail
ADMIN_USER=${1:-${SUDO_USER:?run via sudo or pass the admin user}}
usermod -aG systemd-journal "$ADMIN_USER"
id "$ADMIN_USER"
