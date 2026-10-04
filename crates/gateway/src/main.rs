//! InvenTree gateway: accepts iroh connections from approved devices and
//! forwards their TCP streams to the local InvenTree proxy.

mod backup;
mod store;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint,
    endpoint::{Connection, presets},
};
use proto::{
    ALPN, AdminReply, AdminRequest, CLOSE_NOT_APPROVED, Hello, HelloReply, STREAM_ADMIN,
    STREAM_HELLO, STREAM_TCP, read_msg, sanitize, write_msg,
};
use store::{Status, with_store};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::{info, warn};

/// How often an open connection re-checks that its device is still approved.
const RECHECK_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(version, about = "InvenTree iroh gateway")]
struct Cli {
    /// Directory with gateway.key and devices.json
    #[arg(long, env = "GW_DATA", default_value = "/opt/inventree/gateway")]
    data: PathBuf,
    /// InvenTree home (data/, config/, backups/)
    #[arg(long, env = "GW_HOME", default_value = "/opt/inventree")]
    home: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the gateway
    Run {
        /// Where approved streams are forwarded to
        #[arg(long, default_value = "127.0.0.1:8000")]
        target: String,
    },
    /// Print the gateway id (clients need this once)
    Id,
    /// List all devices
    List,
    /// List devices waiting for approval
    Pending,
    /// Approve a device and assign it to an InvenTree user
    Approve {
        id: String,
        #[arg(long)]
        user: String,
        /// Allow this device to manage other devices from the app
        #[arg(long)]
        admin: bool,
    },
    /// Revoke a device (open connections are closed within seconds)
    Revoke { id: String },
    /// Remove a device entry completely
    Delete { id: String },
    /// Create an encrypted backup now (used by the systemd timer)
    BackupCreate {
        /// Number of backups to keep on the server
        #[arg(long, default_value_t = 14)]
        keep: usize,
    },
    /// Add an age public key that backups are encrypted to
    BackupKeyAdd { recipient: String },
    /// Show the age public keys backups are encrypted to
    BackupKeyList,
    /// Decrypt a backup (for restore)
    Decrypt {
        /// Key file: backup-key.age from the app (asks for the passphrase) or a plain age identity
        #[arg(long)]
        key: PathBuf,
        input: PathBuf,
        /// Output tar file
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = backup::Paths { home: cli.home.clone(), gateway: cli.data.clone() };
    match cli.cmd {
        Cmd::Run { target } => run(cli.data, cli.home, target).await,
        Cmd::BackupCreate { keep } => {
            let path = backup::create(&paths, keep)?;
            println!("created {}", path.display());
            Ok(())
        }
        Cmd::BackupKeyAdd { recipient } => {
            backup::add_recipient(&cli.data, &recipient)?;
            println!("added backup key");
            Ok(())
        }
        Cmd::BackupKeyList => {
            for r in backup::recipients(&cli.data)? {
                println!("{r}");
            }
            Ok(())
        }
        Cmd::Decrypt { key, input, output } => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&output)?;
            backup::decrypt(&input, &key, &mut out)?;
            println!("decrypted to {}", output.display());
            Ok(())
        }
        Cmd::Id => {
            let key = proto::load_or_create_key(&cli.data.join("gateway.key"))?;
            println!("{}", key.public());
            Ok(())
        }
        Cmd::List => print_devices(&cli.data, None),
        Cmd::Pending => print_devices(&cli.data, Some(Status::Pending)),
        Cmd::Approve { id, user, admin } => with_store(&cli.data, |s| {
            let d = s.find_mut(&id)?;
            d.status = Status::Approved;
            d.user = Some(user);
            d.admin = admin;
            let role = if admin { " as admin device" } else { "" };
            println!("approved {} ({}) for {}{role}", d.id, d.device_name, d.user.as_deref().unwrap_or(""));
            Ok(())
        }),
        Cmd::Revoke { id } => with_store(&cli.data, |s| {
            let d = s.find_mut(&id)?;
            d.status = Status::Revoked;
            println!("revoked {} ({})", d.id, d.device_name);
            Ok(())
        }),
        Cmd::Delete { id } => with_store(&cli.data, |s| {
            let target = s.find_mut(&id)?.id.clone();
            s.devices.retain(|d| d.id != target);
            println!("deleted {target}");
            Ok(())
        }),
    }
}

fn print_devices(data: &PathBuf, only: Option<Status>) -> Result<()> {
    with_store(data, |s| {
        println!("{:<10} {:<9} {:<12} {:<6} {:<20} {:<16} {}", "SHORT", "STATUS", "USER", "ADMIN", "DEVICE", "OS-USER", "LAST SEEN");
        for d in s.devices.iter().filter(|d| only.is_none_or(|st| d.status == st)) {
            println!(
                "{:<10} {:<9} {:<12} {:<6} {:<20} {:<16} {}",
                format!("{}-{}", &d.id[..4], &d.id[4..8]),
                format!("{:?}", d.status).to_lowercase(),
                d.user.as_deref().unwrap_or("-"),
                if d.admin { "yes" } else { "" },
                d.device_name,
                d.os_user,
                d.last_seen
            );
        }
        Ok(())
    })
}

async fn run(data: PathBuf, home: PathBuf, target: String) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,noq=warn".into()),
        )
        .without_time()
        .with_ansi(false)
        .init();

    let key = proto::load_or_create_key(&data.join("gateway.key"))?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    info!("gateway id: {}", endpoint.id());
    info!("forwarding approved devices to {target}");

    while let Some(incoming) = endpoint.accept().await {
        let data = data.clone();
        let home = home.clone();
        let target = target.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_conn(conn, data, home, target).await {
                        info!("connection ended: {e:#}");
                    }
                }
                Err(e) => warn!("incoming connection failed: {e}"),
            }
        });
    }
    Ok(())
}

fn status_of(data: &PathBuf, id: &str) -> Option<Status> {
    with_store(data, |s| Ok(s.get(id).map(|d| d.status))).ok().flatten()
}

fn is_admin(data: &PathBuf, id: &str) -> bool {
    with_store(data, |s| Ok(s.get(id).is_some_and(|d| d.status == Status::Approved && d.admin)))
        .unwrap_or(false)
}

/// Executes a device management request from an admin device.
/// Admin devices themselves can only be changed via the CLI, so nobody can lock out the admin
/// or promote further admins from the app.
fn admin_request(data: &PathBuf, home: &PathBuf, by: &str, req: AdminRequest) -> AdminReply {
    let paths = backup::Paths { home: home.clone(), gateway: data.clone() };
    match req {
        AdminRequest::BackupStatus => {
            return match backup::list(&paths) {
                Ok(backups) => AdminReply::Backups {
                    key_set: backup::recipients(data).is_ok_and(|r| !r.is_empty()),
                    running: backup::is_running(&paths),
                    last_run: backup::last_run(&paths),
                    backups,
                },
                Err(e) => AdminReply::Error { message: format!("{e:#}") },
            };
        }
        AdminRequest::BackupSetKey { recipient } => {
            let res = (|| {
                anyhow::ensure!(
                    backup::recipients(data)?.is_empty(),
                    "Es ist bereits ein Backup-Schlüssel hinterlegt. Ändern nur auf dem Server."
                );
                backup::add_recipient(data, &recipient)
            })();
            info!("{by}: set backup key -> {res:?}");
            return res.map_or_else(|e| AdminReply::Error { message: format!("{e:#}") }, |_| AdminReply::Ok);
        }
        AdminRequest::BackupNow => {
            let res = std::process::Command::new("systemctl")
                .args(["--user", "start", "--no-block", "inventree-backup.service"])
                .status();
            info!("{by}: backup requested -> {res:?}");
            return match res {
                Ok(s) if s.success() => AdminReply::Ok,
                Ok(s) => AdminReply::Error { message: format!("systemctl: {s}") },
                Err(e) => AdminReply::Error { message: e.to_string() },
            };
        }
        AdminRequest::BackupGet { .. } => {
            return AdminReply::Error { message: "unexpected download request".into() };
        }
        _ => {}
    }
    let res = with_store(data, |s| {
        let reply = match req {
            AdminRequest::List => AdminReply::Devices { devices: s.devices.clone() },
            AdminRequest::Approve { id, user } => {
                let d = s.find_mut(&id)?;
                anyhow::ensure!(!d.admin, "Admin-Geräte können nur auf dem Server geändert werden");
                let user = sanitize(user.trim());
                anyhow::ensure!(!user.is_empty(), "Benutzername fehlt");
                d.status = Status::Approved;
                d.user = Some(user);
                info!("{by}: approved {} ({}) for {}", d.id, d.device_name, d.user.as_deref().unwrap_or(""));
                AdminReply::Ok
            }
            AdminRequest::Revoke { id } => {
                let d = s.find_mut(&id)?;
                anyhow::ensure!(!d.admin, "Admin-Geräte können nur auf dem Server geändert werden");
                d.status = Status::Revoked;
                info!("{by}: revoked {} ({})", d.id, d.device_name);
                AdminReply::Ok
            }
            AdminRequest::Delete { id } => {
                let d = s.find_mut(&id)?;
                anyhow::ensure!(!d.admin, "Admin-Geräte können nur auf dem Server geändert werden");
                let target = d.id.clone();
                s.devices.retain(|d| d.id != target);
                info!("{by}: deleted {target}");
                AdminReply::Ok
            }
            _ => unreachable!("handled above"),
        };
        Ok(reply)
    });
    res.unwrap_or_else(|e| AdminReply::Error { message: format!("{e:#}") })
}

/// Streams one backup file to an admin device.
async fn send_backup(
    paths: &backup::Paths,
    name: &str,
    offset: u64,
    mut send: iroh::endpoint::SendStream,
) -> Result<()> {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let path = match backup::resolve(paths, name) {
        Ok(p) => p,
        Err(e) => {
            write_msg(&mut send, &AdminReply::Error { message: format!("{e:#}") }).await?;
            send.finish()?;
            return Ok(());
        }
    };
    let mut file = tokio::fs::File::open(&path).await?;
    let size = file.metadata().await?.len();
    anyhow::ensure!(offset <= size, "offset beyond end of file");
    write_msg(&mut send, &AdminReply::Download { size }).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    tokio::io::copy(&mut file, &mut send).await?;
    send.flush().await?;
    send.finish()?;
    info!("sent backup {name} ({} bytes from offset {offset})", size - offset);
    Ok(())
}

async fn handle_conn(conn: Connection, data: PathBuf, home: PathBuf, target: String) -> Result<()> {
    let id = conn.remote_id().to_string();
    let short = proto::short_id(&conn.remote_id());

    // Close the connection as soon as the device is revoked or deleted.
    let watcher = {
        let conn = conn.clone();
        let data = data.clone();
        let id = id.clone();
        tokio::spawn(async move {
            let mut was_approved = false;
            loop {
                tokio::time::sleep(RECHECK_INTERVAL).await;
                let approved = status_of(&data, &id) == Some(Status::Approved);
                if was_approved && !approved {
                    info!("{id}: no longer approved, closing");
                    conn.close(CLOSE_NOT_APPROVED.into(), b"not approved");
                    return;
                }
                was_approved = approved;
            }
        })
    };

    let result = async {
        loop {
            let (mut send, mut recv) = conn.accept_bi().await?;
            let kind = recv.read_u8().await?;
            match kind {
                STREAM_HELLO => {
                    let hello: Hello = read_msg(&mut recv).await?;
                    let (name, user) = (sanitize(&hello.device_name), sanitize(&hello.os_user));
                    let device = with_store(&data, |s| Ok(s.seen(&id, &name, &user).cloned()))?;
                    let reply = match device {
                        Some(d) if d.status == Status::Approved => {
                            HelloReply::Approved { user: d.user, admin: d.admin }
                        }
                        Some(d) if d.status == Status::Revoked => HelloReply::Revoked,
                        _ => HelloReply::Pending,
                    };
                    info!("{short}: hello from '{name}' ({user}), v{} -> {reply:?}", sanitize(&hello.version));
                    write_msg(&mut send, &reply).await?;
                    send.finish()?;
                }
                STREAM_TCP => {
                    if status_of(&data, &id) != Some(Status::Approved) {
                        conn.close(CLOSE_NOT_APPROVED.into(), b"not approved");
                        anyhow::bail!("{short}: tcp stream from unapproved device");
                    }
                    let target = target.clone();
                    tokio::spawn(async move {
                        let res = async {
                            let mut tcp = TcpStream::connect(&target).await.context("connecting to target")?;
                            let mut quic = tokio::io::join(recv, send);
                            tokio::io::copy_bidirectional(&mut tcp, &mut quic).await?;
                            anyhow::Ok(())
                        }
                        .await;
                        if let Err(e) = res {
                            tracing::debug!("stream ended: {e:#}");
                        }
                    });
                }
                STREAM_ADMIN => {
                    let req: AdminRequest = read_msg(&mut recv).await?;
                    if let AdminRequest::BackupGet { name, offset } = &req {
                        if is_admin(&data, &id) {
                            let paths = backup::Paths { home: home.clone(), gateway: data.clone() };
                            let (name, offset) = (name.clone(), *offset);
                            let short = short.clone();
                            tokio::spawn(async move {
                                if let Err(e) = send_backup(&paths, &name, offset, send).await {
                                    warn!("{short}: backup download failed: {e:#}");
                                }
                            });
                            continue;
                        }
                    }
                    let reply = if is_admin(&data, &id) {
                        let (data, home, short) = (data.clone(), home.clone(), short.clone());
                        tokio::task::spawn_blocking(move || admin_request(&data, &home, &short, req)).await?
                    } else {
                        warn!("{short}: admin request from non-admin device");
                        AdminReply::Error { message: "Dieses Gerät darf keine Geräte verwalten".into() }
                    };
                    write_msg(&mut send, &reply).await?;
                    send.finish()?;
                }
                other => anyhow::bail!("{short}: unknown stream type {other}"),
            }
        }
    }
    .await;
    watcher.abort();
    result
}
