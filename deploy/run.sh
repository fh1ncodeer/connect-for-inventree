#!/bin/bash
# Usage: sudo ./run.sh scripts/<name>.sh
# Runs a script with tracing and writes all output to logs/<timestamp>-<name>.log
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs
script="$1"; shift || true
[ -f "$script" ] || { echo "not found: $script"; exit 1; }
log="logs/$(date +%Y%m%d-%H%M%S)-$(basename "$script" .sh).log"
{
  echo "### $script  ($(date -Is), uid=$(id -u))"
  bash -x "$script" "$@"
  echo "### exit=$?"
} 2>&1 | tee "$log"
chown "${SUDO_USER:-$USER}": "$log" 2>/dev/null || true
echo ">> log: $log"
