#!/bin/bash
# Enables ufw: everything incoming is blocked except SSH (22/tcp, v4+v6).
# Safety net: ufw is disabled again automatically after 5 minutes unless confirmed with
#   sudo systemctl stop ufw-rollback.timer
set -e
systemd-run --unit=ufw-rollback --on-active=5min /usr/sbin/ufw disable
ufw allow 22/tcp
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
echo
echo ">> Rollback in 5 minutes. Test a NEW ssh connection, then confirm with:"
echo ">>   sudo systemctl stop ufw-rollback.timer"
