# Threat model

This document describes what Connect for InvenTree protects, against whom, how, and what
remains the operator's responsibility. It covers the gateway, the desktop app, the server setup
in `deploy/` and the backup feature. It does not cover InvenTree itself.

Target deployment: one company server, 1–20 employees, Windows/Linux desktops without admin
rights, one or a few admins.

## Assets

| Asset | Where it lives |
|---|---|
| Inventory data, user accounts, attachments | InvenTree database and `data/media` on the server |
| InvenTree secrets (`secret_key.txt`, DB password) | `/opt/inventree/data`, `/opt/inventree/config` (mode 600) |
| Gateway secret key (identity of the server) | `/opt/inventree/gateway/gateway.key` (mode 600) |
| Device allowlist (who may connect, who is admin) | `/opt/inventree/gateway/devices.json` |
| Device secret keys (identity of each desktop) | app data dir on each desktop (`device.key`) |
| Encrypted backups | server (`/opt/inventree/backups`) and admins' local backup folders |
| Backup secret key + passphrase | `backup-key.age` (passphrase protected) in the admin's backup folder, printed copy |

## Actors

| Actor | Assumed capabilities |
|---|---|
| Internet attacker | can scan the server, send arbitrary traffic, knows this source code |
| Network attacker | controls networks between desktop, relay and server (public Wi-Fi, ISP) |
| Relay operator | runs the relay (n0 by default, or your own); sees and can drop relayed packets |
| Unapproved person with the app | has the app binary and the gateway id |
| Former employee / stolen laptop | has a previously approved device (key file, maybe a saved InvenTree session) |
| Compromised admin device | malware or a third person on an admin's laptop |
| Other local users | other accounts on the server or on a shared desktop |
| Compromised server | attacker with code execution as `inventree` or root on the server |
| Supply chain | compromised container image or Rust crate |

## Trust boundaries

```
 desktop                               relay                     server
┌────────────────────────────┐                     ┌───────────────────────────────────┐
│ InvenTree page (webview)   │                     │ inventree-gw                      │
│   │ no IPC ─ ─ ─ ─ ─ ─ ─ ─ ┼─ (B1)               │   │ plain HTTP on 127.0.0.1 (B4)  │
│ app backend, device key    │◄──── iroh/QUIC ────►│ Caddy ─► InvenTree ─► Postgres    │
│ 127.0.0.1:8080 (B2)        │  E2E encrypted (B3) │ backups (age, public key only)(B5)│
└────────────────────────────┘                     └───────────────────────────────────┘
```

- **B1** remote InvenTree page ↔ app backend
- **B2** local port 8080 ↔ other processes/users on the desktop
- **B3** desktop ↔ relay/network ↔ gateway
- **B4** gateway ↔ InvenTree on the server (loopback)
- **B5** server ↔ backup copies off the server

## Threats and mitigations

### Reaching InvenTree from outside

| Threat | Mitigation | Residual risk |
|---|---|---|
| Exploiting InvenTree or Postgres from the internet | No open ports except SSH (ufw). Caddy binds `127.0.0.1:8000`; Postgres/Redis only in the container network. Rootless Podman, so published ports cannot bypass the firewall. | SSH remains exposed: key-only auth recommended. |
| Unapproved device connects through the gateway | Gateway forwards TCP streams only for device ids on the allowlist; ids are public keys authenticated by the QUIC/TLS handshake and cannot be spoofed without the secret key. | None known in the protocol; implementation has no automated tests yet. |
| Brute force / credential stuffing on the InvenTree login | Only approved devices reach the login page; InvenTree 2FA can be enforced. | InvenTree sees all requests as coming from the local proxy, so IP based limits inside InvenTree are ineffective. Enforce 2FA. |
| Host header / DNS rebinding tricks | `INVENTREE_ALLOWED_HOSTS=localhost`. | — |
| Flooding the pending list | Max. 50 pending entries, client strings truncated to 64 chars and stripped of control characters. | No rate limit on connection attempts; a determined attacker can fill the pending list (admin can delete entries). |

### Approval and admin functions

| Threat | Mitigation | Residual risk |
|---|---|---|
| Social engineering: attacker gets their device approved | Admin compares the short id shown in the colleague's app over a second channel (phone, in person). | Depends on the admin following the procedure. The short id has 32 bits; the full id is shown in the app's details. |
| Revoked device keeps its connection | Open connections re-check approval every 10 s and are closed. | Up to ~10 s of continued access. |
| Normal device uses admin functions | Gateway checks the admin flag for every admin request. | — |
| Compromised admin device | Admin devices cannot create other admins, cannot revoke/delete admin devices and cannot replace an existing backup key; those actions require the server CLI. | It can approve attacker devices, revoke colleagues and download encrypted backups. Backups stay unreadable without the backup secret key and passphrase. The InvenTree admin session on that device is an equal risk. |

### Desktop

| Threat | Mitigation | Residual risk |
|---|---|---|
| InvenTree content (or an XSS in InvenTree) calls app functions | Tauri capabilities grant IPC only to the bundled status page, not to the remote InvenTree page. The overlay link to the status page is intercepted by the app and never reaches the server. | A malicious page can navigate the window to the app's status page; actions there still need user clicks. |
| InvenTree content opens other sites, pop-ups or downloads | External links open in the system browser (http/https/mailto only, other schemes are blocked). InvenTree pop-ups (e.g. PDFs) open in a separate app window without IPC. Downloads are saved to the download folder without overwriting and are never opened automatically. | A malicious page could place files in the download folder. |
| InvenTree content uses device features | On Linux the app grants camera access (barcode scanning) to the InvenTree pages only; microphone, location, notifications and all other permission requests are denied. | A malicious InvenTree page (or XSS) could see the camera while the app is open. |
| Other processes/users on the desktop use the tunnel | Port bound to `127.0.0.1` only. | On shared machines (terminal servers) other local users can reach the InvenTree login page through it. |
| Stolen laptop or copied device key | Key file mode 600 (Unix) / user profile ACLs (Windows). Admin revokes the device. | No DPAPI/keychain protection yet; a copied key acts as that device until revoked. A saved InvenTree session cookie may also be on the laptop. |
| User is talked into connecting to a fake gateway that shows a look-alike InvenTree login (phishing) | Builds with `INVENTREE_GATEWAY_ID` have the gateway id baked in; it cannot be changed in the app or via `config.json`. The status page shows the gateway's short id. | Builds without a baked-in id let users enter any gateway id. Use baked-in builds for companies; enforce InvenTree 2FA. |
| Tampered app binary | — | Releases are unsigned; distribute binaries over a trusted channel. |

### Network and relay

| Threat | Mitigation | Residual risk |
|---|---|---|
| Eavesdropping / tampering on the network | iroh uses QUIC with TLS 1.3, endpoints authenticated by their public keys; relays forward encrypted packets only. Relay connections use TLS. | — |
| Relay operator reads traffic | End-to-end encryption between app and gateway. | The relay sees metadata: which ids connect, when, from which IPs, traffic volume. |
| Relay or discovery service unavailable or blocking | Direct connections are used when hole punching succeeds. | With the default n0 relays and DNS discovery (meant for development) the service depends on n0. Run your own relay for production. |
| Abuse of your own relay by strangers | `iroh-relay` access rules (allowlist), rate limits. | An open relay can be used as free bandwidth by others (no access to your data). |

### Server

| Threat | Mitigation | Residual risk |
|---|---|---|
| Container escape | Rootless Podman as unprivileged `inventree` user (no login shell, no sudo); no Docker daemon. | Escape yields the `inventree` user, which has all InvenTree data. |
| Other local server users | `/opt/inventree` is mode 750, secrets 600. | Any local user can reach `127.0.0.1:8000` (login page). |
| Admin's sudo rule | `admin ALL=(inventree)` only, not root. | Whoever controls the admin's server account controls InvenTree. |
| Compromised server | — | Full access to live data. If the backup key file and passphrase are entered on the server during a restore, the attacker can capture them and decrypt all backups. Decrypt on a trusted machine if in doubt. |
| Vulnerable or malicious images | Images pinned by tag (InvenTree version pinned); InvenTree plugins disabled. | Tags are not digests; image contents are trusted from Docker Hub. Keep InvenTree updated. |

### Backups

| Threat | Mitigation | Residual risk |
|---|---|---|
| Backup copies leak (laptop, cloud folder) | age encryption (X25519) to the admin's public key; the server never holds the secret key. Files mode 600. | Archive names and sizes are visible. |
| Weak backup passphrase | Key file is protected with age/scrypt; the app requires ≥ 12 characters. | A weak passphrase plus a leaked `backup-key.age` (it is stored next to the backups by default) allows offline guessing. Use a long passphrase or store the key file elsewhere. |
| Plaintext on disk during backup | `pg_dump` written to a mode-700 temp dir and deleted after archiving. | Briefly present on the server; a crash can leave it behind until the next run. |
| Loss of backup key / passphrase | Secret key shown once for printing. | Without it no backup can be restored. |
| Loss of gateway key | Included in backups. | Without a backup all apps must be re-pointed to a new gateway id. |
| Admin stops syncing | App warns when the local copy is stale. | Off-site copies exist only while an admin device syncs; add a server-side off-site job if needed. |

## Out of scope

- Vulnerabilities in InvenTree, Postgres, Redis, Caddy, iroh, Tauri/WebKit/WebView2 themselves
- Security of the operating systems, physical access to the server, SSH configuration
- Authorization inside InvenTree (roles, permissions) and InvenTree account management
- Availability guarantees / DoS resistance

## Operator checklist

- Enforce 2FA in InvenTree; strong admin password
- Distribute app builds with the gateway id baked in (`INVENTREE_GATEWAY_ID`)
- Compare short ids over a second channel before approving devices; revoke devices of leavers
- Long backup passphrase; keep secret key and passphrase away from the laptop
- Keep InvenTree and the server updated; restrict SSH to keys
- Run your own relay for production use
