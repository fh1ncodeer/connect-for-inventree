//! Backup sync for admin devices: pulls the newest encrypted backup from the gateway
//! into a local folder on a configurable schedule.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::Connection;
use proto::{AdminReply, AdminRequest, BackupInfo, STREAM_ADMIN, read_msg, write_msg};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{App, save_config};

const EXTENSION: &str = ".tar.zst.age";
pub const KEY_FILE: &str = "backup-key.age";
/// After a failed sync, wait at least this long before trying again automatically.
const RETRY_AFTER_ERROR: Duration = Duration::from_secs(15 * 60);
const MIN_PASSPHRASE: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    pub folder: Option<String>,
    pub interval_hours: u32,
    pub keep: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { enabled: true, folder: None, interval_hours: 24, keep: 14 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub last_ok: Option<String>,
    pub last_attempt: Option<String>,
    pub last_file: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LocalFile {
    name: String,
    size: u64,
}

#[derive(Debug, Serialize)]
pub struct Overview {
    settings: Settings,
    folder: String,
    state: SyncState,
    /// Local copy is missing or older than expected.
    stale: bool,
    syncing: bool,
    local: Vec<LocalFile>,
    server: Option<AdminReply>,
    server_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeySetup {
    public_key: String,
    secret_key: String,
    key_file: String,
}

#[derive(Debug, Clone, Serialize)]
struct Progress {
    name: String,
    done: u64,
    total: u64,
}

pub fn default_folder(app: &AppHandle) -> PathBuf {
    app.path()
        .document_dir()
        .or_else(|_| app.path().home_dir())
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("InvenTree-Backups")
}

pub fn folder(app: &AppHandle, settings: &Settings) -> PathBuf {
    settings.folder.as_ref().map(PathBuf::from).unwrap_or_else(|| default_folder(app))
}

fn now() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}

fn age_of(ts: &Option<String>) -> Option<Duration> {
    let t = humantime::parse_rfc3339(ts.as_deref()?).ok()?;
    SystemTime::now().duration_since(t).ok()
}

fn is_stale(settings: &Settings, state: &SyncState) -> bool {
    let limit = Duration::from_secs(u64::from(settings.interval_hours) * 3600 * 2).max(Duration::from_secs(48 * 3600));
    age_of(&state.last_ok).is_none_or(|a| a > limit)
}

fn is_due(settings: &Settings, state: &SyncState) -> bool {
    let interval = Duration::from_secs(u64::from(settings.interval_hours.max(1)) * 3600);
    let ok_due = age_of(&state.last_ok).is_none_or(|a| a >= interval);
    let retry_ok = state.last_error.is_none() || age_of(&state.last_attempt).is_none_or(|a| a >= RETRY_AFTER_ERROR);
    ok_due && retry_ok
}

/// Backups and the key file are only readable by the current user (mode 0600 on Unix;
/// on Windows the user profile ACLs apply).
fn private_options() -> fs::OpenOptions {
    #[allow(unused_mut)]
    let mut opts = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

pub async fn admin_call(conn: &Connection, request: &AdminRequest) -> Result<AdminReply> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_u8(STREAM_ADMIN).await?;
    write_msg(&mut send, request).await?;
    send.finish()?;
    let reply: AdminReply = read_msg(&mut recv).await?;
    if let AdminReply::Error { message } = &reply {
        bail!("{message}");
    }
    Ok(reply)
}

fn admin_conn(state: &App) -> Result<Connection> {
    let is_admin = matches!(state.status.lock().unwrap().phase, crate::Phase::Approved { admin: true, .. });
    ensure!(is_admin, "Only available on admin devices");
    state.conn.lock().unwrap().clone().context("Not connected to the server")
}

fn local_files(dir: &Path) -> Vec<LocalFile> {
    let mut files: Vec<LocalFile> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            (name.ends_with(EXTENSION) && !name.starts_with('.'))
                .then(|| LocalFile { size: e.metadata().map(|m| m.len()).unwrap_or(0), name })
        })
        .collect();
    files.sort_by(|a, b| b.name.cmp(&a.name));
    files
}

pub async fn overview(app: &AppHandle, state: &App) -> Overview {
    let (settings, sync_state) = {
        let cfg = state.config.lock().unwrap();
        (cfg.backup.clone(), cfg.backup_state.clone())
    };
    let dir = folder(app, &settings);
    let (server, server_error) = match admin_conn(state) {
        Ok(conn) => match admin_call(&conn, &AdminRequest::BackupStatus).await {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        },
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    Overview {
        stale: is_stale(&settings, &sync_state),
        syncing: state.backup_syncing.load(Ordering::SeqCst),
        local: local_files(&dir),
        folder: dir.display().to_string(),
        settings,
        state: sync_state,
        server,
        server_error,
    }
}

pub fn save_settings(state: &App, mut settings: Settings) -> Result<()> {
    settings.interval_hours = settings.interval_hours.clamp(1, 24 * 30);
    settings.keep = settings.keep.clamp(1, 365);
    settings.folder = settings.folder.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
    let mut cfg = state.config.lock().unwrap();
    cfg.backup = settings;
    save_config(&state.config_path, &cfg)
}

/// Downloads one backup into the folder, resuming a previous partial download.
async fn download(app: &AppHandle, conn: &Connection, dir: &Path, info: &BackupInfo) -> Result<PathBuf> {
    let target = dir.join(&info.name);
    if target.metadata().is_ok_and(|m| m.len() == info.size) {
        return Ok(target);
    }
    let partial = dir.join(format!(".{}.partial", info.name));
    let offset = partial.metadata().map(|m| m.len()).unwrap_or(0);
    let offset = if offset > info.size { 0 } else { offset };

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_u8(STREAM_ADMIN).await?;
    write_msg(&mut send, &AdminRequest::BackupGet { name: info.name.clone(), offset }).await?;
    send.finish()?;
    let size = match read_msg::<_, AdminReply>(&mut recv).await? {
        AdminReply::Download { size } => size,
        AdminReply::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    };

    let mut file = private_options().create(true).append(true).open(&partial)?;
    if offset == 0 {
        file.set_len(0)?;
    }
    let mut done = offset;
    let mut buf = vec![0u8; 256 * 1024];
    let mut last_emit = SystemTime::now();
    loop {
        let n = AsyncReadExt::read(&mut recv, &mut buf).await?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        done += n as u64;
        if last_emit.elapsed().unwrap_or_default() > Duration::from_millis(300) {
            let _ = app.emit("backup-progress", Progress { name: info.name.clone(), done, total: size });
            last_emit = SystemTime::now();
        }
    }
    file.sync_all()?;
    drop(file);
    ensure!(done == size, "Download incomplete ({done} of {size} bytes), will resume");
    fs::rename(&partial, &target)?;
    let _ = app.emit("backup-progress", Progress { name: info.name.clone(), done, total: size });
    Ok(target)
}

fn prune_local(dir: &Path, keep: u32) -> Result<()> {
    for old in local_files(dir).into_iter().skip(keep.max(1) as usize) {
        fs::remove_file(dir.join(old.name))?;
    }
    Ok(())
}

/// Fetches the newest backup (or `only` a specific one) into the backup folder.
pub async fn sync(app: &AppHandle, state: &App, only: Option<String>) -> Result<String> {
    if state.backup_syncing.swap(true, Ordering::SeqCst) {
        bail!("A sync is already running");
    }
    let result = sync_inner(app, state, only).await;
    state.backup_syncing.store(false, Ordering::SeqCst);

    let mut cfg = state.config.lock().unwrap();
    cfg.backup_state.last_attempt = Some(now());
    match &result {
        Ok(name) => {
            cfg.backup_state.last_ok = Some(now());
            cfg.backup_state.last_file = Some(name.clone());
            cfg.backup_state.last_error = None;
        }
        Err(e) => cfg.backup_state.last_error = Some(format!("{e:#}")),
    }
    let _ = save_config(&state.config_path, &cfg);
    drop(cfg);
    let _ = app.emit("backup-changed", ());
    result
}

async fn sync_inner(app: &AppHandle, state: &App, only: Option<String>) -> Result<String> {
    let conn = admin_conn(state)?;
    let settings = state.config.lock().unwrap().backup.clone();
    let dir = folder(app, &settings);
    fs::create_dir_all(&dir).with_context(|| format!("creating folder {}", dir.display()))?;

    let AdminReply::Backups { key_set, backups, .. } = admin_call(&conn, &AdminRequest::BackupStatus).await? else {
        bail!("unexpected reply from the server");
    };
    ensure!(key_set, "No backup key has been set up yet");
    let info = match &only {
        Some(name) => backups.iter().find(|b| &b.name == name).context("Backup no longer exists on the server")?,
        None => backups.first().context("There is no backup on the server yet")?,
    };
    download(app, &conn, &dir, info).await?;
    if only.is_none() {
        prune_local(&dir, settings.keep)?;
    }
    Ok(info.name.clone())
}

/// Runs in the background and syncs whenever a sync is due.
pub async fn sync_loop(app: AppHandle, state: App) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let (settings, sync_state) = {
            let cfg = state.config.lock().unwrap();
            (cfg.backup.clone(), cfg.backup_state.clone())
        };
        if !settings.enabled || admin_conn(&state).is_err() || !is_due(&settings, &sync_state) {
            continue;
        }
        let _ = sync(&app, &state, None).await;
    }
}

pub async fn create_now(state: &App) -> Result<()> {
    let conn = admin_conn(state)?;
    admin_call(&conn, &AdminRequest::BackupNow).await?;
    Ok(())
}

/// Creates the backup key pair. The secret key is stored passphrase-protected in the
/// backup folder and returned once for printing; only the public key goes to the server.
pub async fn setup_key(app: &AppHandle, state: &App, passphrase: String) -> Result<KeySetup> {
    ensure!(
        passphrase.chars().count() >= MIN_PASSPHRASE,
        "The passphrase must have at least {MIN_PASSPHRASE} characters"
    );
    let conn = admin_conn(state)?;
    let settings = state.config.lock().unwrap().backup.clone();
    let dir = folder(app, &settings);
    fs::create_dir_all(&dir)?;
    let key_path = dir.join(KEY_FILE);
    ensure!(!key_path.exists(), "{} already exists", key_path.display());

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret_key = identity.to_string().expose_secret().to_string();

    let plain = format!(
        "# InvenTree backup key, created {}\n# public key: {public_key}\n{secret_key}\n",
        now()
    );
    let encryptor = age::Encryptor::with_user_passphrase(passphrase.into());
    let mut out = vec![];
    {
        let armor = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)?;
        let mut w = encryptor.wrap_output(armor)?;
        w.write_all(plain.as_bytes())?;
        w.finish()?.finish()?;
    }
    private_options().write(true).create_new(true).open(&key_path)?.write_all(&out)?;

    if let Err(e) = admin_call(&conn, &AdminRequest::BackupSetKey { recipient: public_key.clone() }).await {
        let _ = fs::remove_file(&key_path);
        return Err(e);
    }
    Ok(KeySetup { public_key, secret_key, key_file: key_path.display().to_string() })
}
