#!/bin/bash
# Read only: firewall and network status
ufw status verbose
echo; iptables -S 2>/dev/null | head -50
echo; nft list ruleset 2>/dev/null | head -80
echo; ss -tulpn
