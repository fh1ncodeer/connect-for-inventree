# Connect for InvenTree

Self-hosted [InvenTree](https://inventree.org) for small teams, reachable from home offices
**without opening a single port on the server** and without installing anything with admin
rights on the employees' computers.

- **Gateway** (`inventree-gw`) runs next to InvenTree and accepts connections only from
  approved devices, over [iroh](https://iroh.computer) (QUIC, end-to-end encrypted, NAT traversal).
- **Desktop app** (`connect-for-inventree`, Tauri) is a single executable. It creates a device key,
  waits until an admin approves it, then shows InvenTree in its window.
- **Admin devices** approve further devices and manage encrypted backups from inside the app.

> Unofficial project, not affiliated with or endorsed by the InvenTree project.
> Status: early development, see [Limitations](#limitations).

## How it works

```
 employee PC                                  server (no open ports)
┌───────────────────────────┐                ┌──────────────────────────────────────┐
│ connect-for-inventree     │  iroh / QUIC   │ inventree-gw ──► 127.0.0.1:8000      │
│  window ─► 127.0.0.1:8080 ├───────────────►│  allowlist        Caddy ─► InvenTree │
│  device key               │ outbound only, │  backups          Postgres, Redis    │
└───────────────────────────┘ relay or direct│                   (rootless Podman)  │
                                (holepunch)  └──────────────────────────────────────┘
```

Both sides only make outbound connections; iroh relays help them find each other and carry
the traffic if no direct path exists. Relays only ever see encrypted data.

## Security model

- The server's firewall blocks all incoming traffic except SSH. InvenTree listens on
  `127.0.0.1:8000` only.
- Every device has its own key pair. The gateway only forwards traffic for device ids on its
  allowlist; revoking a device closes its connection within ~10 seconds.
- Approval is a second factor in front of the normal InvenTree login (and its 2FA): an approved
  device only gets as far as the login page.
- Admin devices can approve, revoke and delete other devices from the app. Admin devices
  themselves can only be changed on the server, so the app can neither lock out the admin nor
  create further admins.
- The InvenTree page inside the app has no access to the app's backend (Tauri capabilities).
- InvenTree, the gateway and the backups run as an unprivileged system user with rootless
  Podman; no Docker daemon, no root containers.
- Backups are encrypted with [age](https://age-encryption.org) to the admin's public key. The
  server can create backups but cannot read them.

Details, known residual risks and an operator checklist: [THREAT_MODEL.md](THREAT_MODEL.md).

## Repository layout

| Path | |
|---|---|
| `crates/gateway` | `inventree-gw`: gateway daemon, device allowlist, backups, CLI |
| `crates/app` | `connect-for-inventree`: Tauri desktop client (status, device management, backups) |
| `crates/proto` | wire protocol shared by both |
| `deploy/` | server setup: scripts, quadlets (Postgres, Redis, InvenTree, Caddy), systemd units |
| `contrib/restore.sh` | restores a decrypted backup |

## Server setup

Tested on Ubuntu 24.04. Everything except `02` and `04` runs without root.

```sh
cd deploy
sudo ./run.sh scripts/01-ufw.sh            # optional: firewall, SSH only (with auto-rollback)
sudo ./run.sh scripts/02-podman-setup.sh   # podman, user 'inventree', sudoers rule for you -> inventree
sudo ./run.sh scripts/04-journal-group.sh  # optional: read container logs via journalctl

cargo build --release -p inventree-gw      # on the server or a machine with the same glibc
./install.sh ../target/release/inventree-gw
```

`install.sh` deploys InvenTree with Postgres, Redis and Caddy as Podman quadlets under
`/opt/inventree`, generates the database password, installs the gateway and the nightly backup
timer, and prints the **gateway id** that clients need. Then create the InvenTree admin as
printed at the end.

InvenTree must be configured with `INVENTREE_SITE_URL=http://localhost:8080` (done by the
template in `deploy/config`).

Logs: `journalctl CONTAINER_NAME=inventree-server`, `journalctl _SYSTEMD_USER_UNIT=inventree-gw.service`.

## Client

```sh
cargo build --release -p connect-for-inventree
INVENTREE_GATEWAY_ID=<gateway id> cargo build --release -p connect-for-inventree   # bake the id in (locked)
cargo xwin build --release -p connect-for-inventree --target x86_64-pc-windows-msvc  # Windows exe
```

With a baked-in gateway id the app connects only to that gateway; users cannot change it (protects
against being talked into a fake gateway). Without it, users enter the gateway id once in the app.

Inside the app, external links open in the system browser, InvenTree pop-ups (e.g. label PDFs)
open in a second window, and downloads go to the download folder.

Linux needs WebKitGTK 4.1 (and `gst-plugins-good` for the camera barcode scanner); Windows 10/11 ship the required WebView2. Config and device key live
in the app's local data dir (`~/.local/share/<identifier>`, `%LOCALAPPDATA%\<identifier>`).

## Rollout

1. Start the app on the admin's computer; it shows a short id such as `3F9A-B27C`.
2. On the server, approve it once as admin device:
   `deploy/gw approve 3f9a-b27c --user admin --admin`
3. Colleagues start the app and tell the admin their short id (by phone or in person). The admin
   approves them in the app under **⇄ Connection → Manage devices** and creates their InvenTree
   accounts as usual.

Gateway CLI (via the `deploy/gw` wrapper or `sudo -u inventree /opt/inventree/bin/inventree-gw`):

```
inventree-gw id                                    # gateway id
inventree-gw pending | list
inventree-gw approve 3f9a-b27c --user anna [--admin]
inventree-gw revoke 3f9a-b27c
inventree-gw delete 3f9a-b27c
```

## Backups

`inventree-backup.timer` creates a zstd-compressed, encrypted backup every night (02:30, last 14 kept in
`/opt/inventree/backups`). Contents: `db.dump` (pg_dump -Fc), `data/` (media, config.yaml,
secret_key.txt, ...), `config/`, `gateway/` (gateway key, devices, backup recipients),
`quadlets/`, `manifest.json`.

In the app (**Backups**, admin devices only):

- **Key setup** (once): choose a passphrase; the app creates an age key pair, sends only the
  public key to the server, stores the secret key passphrase-protected as `backup-key.age` in the
  backup folder and shows it once for printing. Keep the secret key and passphrase somewhere
  other than the laptop – without them no backup can be restored.
- **Automatic sync**: the newest backup is downloaded into a local folder; folder, interval and
  number of kept backups are configurable. The app warns when the local copy is outdated.
- **Backup now**, manual downloads of older backups.

```
inventree-gw backup-create                 # what the timer runs
inventree-gw backup-key-list | backup-key-add age1...
inventree-gw decrypt --key backup-key.age inventree-<ts>.tar.zst.age -o backup.tar
```

### Restore

On the server, as `inventree`. The key file goes to the server only temporarily; if you no
longer trust the server, decrypt on your own computer and copy only the result.

```sh
ssh -t server "cd /tmp && sudo -u inventree /opt/inventree/bin/inventree-gw decrypt \
  --key /opt/inventree/tmp/backup-key.age /opt/inventree/backups/inventree-<ts>.tar.zst.age \
  -o /opt/inventree/tmp/restore.tar"
rm /opt/inventree/tmp/backup-key.age

/opt/inventree/bin/restore.sh /opt/inventree/tmp/restore.tar
rm /opt/inventree/tmp/restore.tar          # plaintext!
```

`restore.sh` stops InvenTree, restores `data/`, `config/` and `gateway/`, runs
`pg_restore --clean`, starts the server, runs `invoke update` and starts the remaining services.

## Limitations

- **Relays**: the gateway and app use the public relays and DNS discovery of n0, which are meant
  for development and testing. For production run your own `iroh-relay` (e.g. on a small VPS).
- **Windows**: the client builds for Windows but has not been tested there yet. The device key is
  protected by file system permissions only (no DPAPI yet). The exe is unsigned.
- The app serves InvenTree on `127.0.0.1:8080`; on shared machines (terminal servers) every local
  user can reach that port (they still need an InvenTree login).
- Camera barcode scanning on Linux: WebKitGTK crashes when an infrared camera (grey-only
  format, e.g. on Surface devices) is selected; choose the normal camera.
- Only a few unit tests; no end-to-end tests yet.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
