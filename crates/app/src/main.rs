//! Connect for InvenTree: desktop client that tunnels InvenTree through iroh.
//!
//! The app keeps a device key, introduces itself to the gateway and, once the
//! device is approved, serves InvenTree on 127.0.0.1:8080 and shows it in the window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backup;

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use proto::{
    ALPN, AdminReply, AdminRequest, Hello, HelloReply, STREAM_ADMIN, STREAM_HELLO, STREAM_TCP,
    read_msg, write_msg,
};
use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Emitter, Manager, State, Url, WebviewUrl, WebviewWindowBuilder,
    menu::{Menu, MenuItem, Submenu},
    webview::{DownloadEvent, NewWindowResponse},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Notify,
};

/// Local address InvenTree is served on. Must match INVENTREE_SITE_URL on the server.
const LOCAL_ADDR: &str = "127.0.0.1:8080";
const LOCAL_URL: &str = "http://localhost:8080/";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const PENDING_POLL: Duration = Duration::from_secs(5);
/// Gateway id baked in at build time. If set, it cannot be changed in the app or via
/// config.json, so nobody can talk a user into connecting to a fake gateway.
const BAKED_GATEWAY_ID: Option<&str> = option_env!("INVENTREE_GATEWAY_ID");
/// Links on the InvenTree pages with this path prefix are handled by the app itself.
const APP_LINK_PREFIX: &str = "/__connect/";

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
enum Phase {
    Setup,
    Connecting,
    Pending,
    Approved { user: Option<String>, admin: bool },
    Revoked,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
struct Status {
    #[serde(flatten)]
    phase: Phase,
    device_id: String,
    device_short: String,
    gateway_id: Option<String>,
    /// The gateway id is baked into this build and cannot be changed.
    gateway_locked: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config {
    gateway_id: Option<String>,
    #[serde(default)]
    backup: backup::Settings,
    #[serde(default)]
    backup_state: backup::SyncState,
}

struct Shared {
    status: Mutex<Status>,
    conn: Mutex<Option<Connection>>,
    config_path: PathBuf,
    config: Mutex<Config>,
    /// Woken when the configuration changes or the user asks for a retry.
    wake: Notify,
    /// URL of the bundled status page, used to navigate back from InvenTree.
    home_url: Mutex<Option<Url>>,
    backup_syncing: AtomicBool,
}

type App = Arc<Shared>;

impl Shared {
    fn set_phase(&self, app: &AppHandle, phase: Phase) {
        let status = {
            let mut s = self.status.lock().unwrap();
            s.phase = phase;
            s.gateway_id = self.config.lock().unwrap().gateway_id.clone();
            s.clone()
        };
        let _ = app.emit("status", status);
    }

    fn gateway(&self) -> Option<String> {
        self.config.lock().unwrap().gateway_id.clone()
    }
}

#[tauri::command]
fn get_status(state: State<'_, App>) -> Status {
    state.status.lock().unwrap().clone()
}

#[tauri::command]
fn set_gateway(app: AppHandle, state: State<'_, App>, gateway_id: String) -> Result<(), String> {
    if BAKED_GATEWAY_ID.is_some() {
        return Err("The gateway is fixed in this build and cannot be changed.".into());
    }
    let id = gateway_id.trim().to_string();
    id.parse::<EndpointId>().map_err(|e| format!("Invalid gateway id: {e}"))?;
    let mut cfg = state.config.lock().unwrap();
    cfg.gateway_id = Some(id);
    save_config(&state.config_path, &cfg).map_err(|e| e.to_string())?;
    drop(cfg);
    state.set_phase(&app, Phase::Connecting);
    state.wake.notify_one();
    Ok(())
}

#[tauri::command]
fn retry(state: State<'_, App>) {
    state.wake.notify_one();
}

/// Device management, only answered by the gateway for admin devices.
#[tauri::command]
async fn admin_request(state: State<'_, App>, request: AdminRequest) -> Result<AdminReply, String> {
    let conn = state.conn.lock().unwrap().clone().ok_or("Not connected to the server")?;
    let res = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_u8(STREAM_ADMIN).await?;
        write_msg(&mut send, &request).await?;
        send.finish()?;
        read_msg::<_, AdminReply>(&mut recv).await
    }
    .await;
    res.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn show_devices(app: AppHandle, state: State<'_, App>) {
    show_page(&app, &state, "devices");
}

#[tauri::command]
fn show_backups(app: AppHandle, state: State<'_, App>) {
    show_page(&app, &state, "backups");
}

fn show_page(app: &AppHandle, state: &App, page: &str) {
    if let Some(mut url) = state.home_url.lock().unwrap().clone() {
        url.set_fragment(Some(page));
        let _ = navigate(app, url);
    }
}

#[tauri::command]
async fn backup_overview(app: AppHandle, state: State<'_, App>) -> Result<backup::Overview, String> {
    Ok(backup::overview(&app, state.inner()).await)
}

#[tauri::command]
fn backup_save_settings(state: State<'_, App>, settings: backup::Settings) -> Result<(), String> {
    backup::save_settings(state.inner(), settings).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn backup_sync_now(app: AppHandle, state: State<'_, App>, name: Option<String>) -> Result<String, String> {
    backup::sync(&app, state.inner(), name).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn backup_create_now(state: State<'_, App>) -> Result<(), String> {
    backup::create_now(state.inner()).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn backup_setup_key(
    app: AppHandle,
    state: State<'_, App>,
    passphrase: String,
) -> Result<backup::KeySetup, String> {
    backup::setup_key(&app, state.inner(), passphrase).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn open_inventree(app: AppHandle) -> Result<(), String> {
    navigate(&app, LOCAL_URL.parse().unwrap()).map_err(|e| e.to_string())
}

fn navigate(app: &AppHandle, url: Url) -> Result<()> {
    let win = app.get_webview_window("main").context("main window missing")?;
    win.navigate(url)?;
    Ok(())
}

/// InvenTree as served through the tunnel.
fn is_inventree_url(url: &Url) -> bool {
    url.host_str() == Some("localhost") && url.port() == Some(8080)
}

/// The app's own bundled pages (tauri://localhost on Linux/macOS, http://tauri.localhost on Windows).
fn is_app_url(url: &Url) -> bool {
    url.scheme() == "tauri" || url.host_str() == Some("tauri.localhost") || url.scheme() == "about"
}

/// External links (e.g. InvenTree documentation) open in the system browser, never in the app.
fn open_external(url: &Url) {
    if matches!(url.scheme(), "http" | "https" | "mailto") {
        let _ = tauri_plugin_opener::open_url(url.as_str(), None::<&str>);
    }
}

/// Saves downloads (exports, attachments) into the user's download folder without
/// overwriting existing files, and shows a short notice in the window when done.
fn handle_download<R: tauri::Runtime>(webview: tauri::Webview<R>, event: DownloadEvent<'_>) -> bool {
    match event {
        DownloadEvent::Requested { url, destination } => {
            let name = destination
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .or_else(|| url.path_segments().and_then(|mut s| s.next_back()).map(str::to_string))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "download".into());
            let Ok(dir) = webview.app_handle().path().download_dir() else { return false };
            *destination = unique_path(&dir, &name);
            true
        }
        DownloadEvent::Finished { path, success, .. } => {
            let msg = match (success, path) {
                (true, Some(p)) => format!("Saved to {}", p.display()),
                (true, None) => "Download finished".to_string(),
                (false, _) => "Download failed".to_string(),
            };
            let _ = webview.eval(format!("({})({})", TOAST_JS, serde_json::to_string(&msg).unwrap_or_default()));
            true
        }
        _ => true,
    }
}

/// `dir/name`, or `dir/name (1)`, `dir/name (2)`, ... if that already exists.
fn unique_path(dir: &std::path::Path, name: &str) -> PathBuf {
    let name = std::path::Path::new(name).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let candidate = dir.join(&name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.clone(), String::new()),
    };
    (1..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .expect("infinite iterator")
}

const TOAST_JS: &str = r#"(m) => { const d = document.createElement("div"); d.textContent = m;
  d.style.cssText = "position:fixed;right:12px;bottom:12px;z-index:2147483647;max-width:60vw;padding:8px 14px;border-radius:8px;background:#2b6cb0;color:#fff;font:13px system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.3)";
  document.body.appendChild(d); setTimeout(() => d.remove(), 6000); }"#;

/// Opens an InvenTree page (e.g. a generated PDF) that asked for a new window in a separate
/// app window. It shares the login session with the main window and gets no IPC access.
fn open_inventree_popup(app: &AppHandle, url: Url) {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let _ = WebviewWindowBuilder::new(app, format!("popup-{n}"), WebviewUrl::External(url))
        .title("InvenTree")
        .inner_size(1000.0, 800.0)
        .zoom_hotkeys_enabled(true)
        .on_navigation(|url| {
            if is_inventree_url(url) || is_app_url(url) {
                return true;
            }
            open_external(url);
            false
        })
        .on_new_window(|url, _| {
            open_external(&url);
            NewWindowResponse::Deny
        })
        .on_download(handle_download)
        .build();
}

/// WebKitGTK disables getUserMedia by default and denies permission requests that are not
/// handled. Enable it and grant camera access (barcode scanning) to the InvenTree pages only;
/// every other permission request (microphone, location, notifications, ...) is denied.
#[cfg(target_os = "linux")]
fn allow_camera_for_inventree(win: &tauri::WebviewWindow) {
    let _ = win.with_webview(|wv| {
        use webkit2gtk::{
            PermissionRequestExt, SettingsExt, UserMediaPermissionRequest, UserMediaPermissionRequestExt,
            WebViewExt, glib::prelude::Cast,
        };
        let view = wv.inner();
        if let Some(settings) = WebViewExt::settings(&view) {
            settings.set_enable_media_stream(true);
        }
        view.connect_permission_request(|view, request| {
            let on_inventree = view
                .uri()
                .and_then(|u| Url::parse(&u).ok())
                .is_some_and(|u| is_inventree_url(&u));
            let camera_only = request
                .downcast_ref::<UserMediaPermissionRequest>()
                .is_some_and(|r| r.is_for_video_device() && !r.is_for_audio_device());
            if on_inventree && camera_only {
                request.allow();
            } else {
                request.deny();
            }
            true
        });
    });
}

fn go_home(app: &AppHandle, state: &App) {
    if let Some(url) = state.home_url.lock().unwrap().clone() {
        let _ = navigate(app, url);
    }
}

fn load_config(path: &PathBuf) -> Config {
    let mut cfg: Config = fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if let Some(id) = BAKED_GATEWAY_ID {
        cfg.gateway_id = Some(id.to_string());
    }
    cfg
}

fn save_config(path: &PathBuf, cfg: &Config) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

fn hello() -> Hello {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".into());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into());
    Hello { device_name: host, os_user: user, version: env!("CARGO_PKG_VERSION").into() }
}

/// Connects to the gateway and introduces the device.
async fn introduce(endpoint: &Endpoint, gateway: &str) -> Result<(Connection, HelloReply)> {
    let id: EndpointId = gateway.parse()?;
    let conn = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(id, ALPN))
        .await
        .map_err(|_| anyhow!("Timed out connecting to the gateway"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_u8(STREAM_HELLO).await?;
    write_msg(&mut send, &hello()).await?;
    send.finish()?;
    let reply: HelloReply = read_msg(&mut recv).await?;
    Ok((conn, reply))
}

/// Keeps the connection to the gateway alive and tracks the approval state.
async fn connection_loop(app: AppHandle, state: App, endpoint: Endpoint) {
    let mut backoff = Duration::from_secs(2);
    loop {
        let Some(gateway) = state.gateway() else {
            state.set_phase(&app, Phase::Setup);
            state.wake.notified().await;
            continue;
        };
        state.set_phase(&app, Phase::Connecting);

        let wait = match introduce(&endpoint, &gateway).await {
            Ok((conn, HelloReply::Approved { user, admin })) => {
                backoff = Duration::from_secs(2);
                *state.conn.lock().unwrap() = Some(conn.clone());
                state.set_phase(&app, Phase::Approved { user, admin });
                let _ = navigate(&app, LOCAL_URL.parse().unwrap());
                tokio::select! {
                    _ = conn.closed() => {}
                    _ = state.wake.notified() => conn.close(0u32.into(), b"reconnect"),
                }
                *state.conn.lock().unwrap() = None;
                go_home(&app, &state);
                Duration::from_secs(1)
            }
            Ok((conn, HelloReply::Pending)) => {
                conn.close(0u32.into(), b"bye");
                state.set_phase(&app, Phase::Pending);
                PENDING_POLL
            }
            Ok((conn, HelloReply::Revoked)) => {
                conn.close(0u32.into(), b"bye");
                state.set_phase(&app, Phase::Revoked);
                PENDING_POLL * 2
            }
            Err(e) => {
                state.set_phase(&app, Phase::Error { message: format!("{e:#}") });
                backoff = (backoff * 2).min(Duration::from_secs(30));
                backoff
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = state.wake.notified() => {}
        }
    }
}

/// Serves InvenTree locally: every TCP connection becomes one QUIC stream to the gateway.
async fn forward_loop(listener: TcpListener, state: App) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let conn = state.conn.lock().unwrap().clone();
        let Some(conn) = conn else { continue };
        tokio::spawn(async move {
            let _ = forward(tcp, conn).await;
        });
    }
}

async fn forward(mut tcp: TcpStream, conn: Connection) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    send.write_u8(STREAM_TCP).await?;
    let mut quic = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut tcp, &mut quic).await?;
    Ok(())
}

fn setup(app: &mut tauri::App) -> Result<()> {
    let dir = app.path().app_local_data_dir()?;
    fs::create_dir_all(&dir)?;
    let key = proto::load_or_create_key(&dir.join("device.key"))?;
    let config_path = dir.join("config.json");
    let config = load_config(&config_path);

    let state: App = Arc::new(Shared {
        status: Mutex::new(Status {
            phase: Phase::Connecting,
            device_id: key.public().to_string(),
            device_short: proto::short_id(&key.public()),
            gateway_id: config.gateway_id.clone(),
            gateway_locked: BAKED_GATEWAY_ID.is_some(),
        }),
        conn: Mutex::new(None),
        config_path,
        config: Mutex::new(config),
        wake: Notify::new(),
        home_url: Mutex::new(None),
        backup_syncing: AtomicBool::new(false),
    });
    app.manage(state.clone());

    let menu = Menu::with_items(
        app,
        &[&Submenu::with_items(
            app,
            "Connection",
            true,
            &[
                &MenuItem::with_id(app, "status", "Show status", true, Some("CmdOrCtrl+Shift+S"))?,
                &MenuItem::with_id(app, "inventree", "Open InvenTree", true, Some("CmdOrCtrl+Shift+I"))?,
                &MenuItem::with_id(app, "devices", "Manage devices", true, Some("CmdOrCtrl+Shift+G"))?,
                &MenuItem::with_id(app, "backups", "Backups", true, Some("CmdOrCtrl+Shift+B"))?,
                &MenuItem::with_id(app, "reconnect", "Reconnect", true, Some("CmdOrCtrl+Shift+R"))?,
            ],
        )?],
    )?;
    let nav_handle = app.handle().clone();
    let new_window_handle = app.handle().clone();
    let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Connect for InvenTree")
        .inner_size(1280.0, 860.0)
        .menu(menu)
        .zoom_hotkeys_enabled(true)
        .initialization_script(include_str!("overlay.js"))
        .on_navigation(move |url| {
            let ours = is_inventree_url(url);
            if !ours && !is_app_url(url) {
                open_external(url);
                return false;
            }
            if !(ours && url.path().starts_with(APP_LINK_PREFIX)) {
                return true;
            }
            // Navigating from inside the navigation callback is not allowed, so defer it.
            let app = nav_handle.clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<App>().inner().clone();
                go_home(&app, &state);
            });
            false
        })
        .on_new_window(move |url, _features| {
            // Links with target="_blank": InvenTree pages (e.g. PDFs) get their own app window,
            // everything else goes to the system browser.
            if is_inventree_url(&url) {
                let app = new_window_handle.clone();
                tauri::async_runtime::spawn(async move {
                    open_inventree_popup(&app, url);
                });
            } else {
                open_external(&url);
            }
            NewWindowResponse::Deny
        })
        .on_download(handle_download)
        .build()?;
    #[cfg(target_os = "linux")]
    allow_camera_for_inventree(&win);
    *state.home_url.lock().unwrap() = win.url().ok();
    app.on_menu_event(|app, event| {
        let state = app.state::<App>().inner().clone();
        match event.id().as_ref() {
            "status" => go_home(app, &state),
            "inventree" => {
                if state.conn.lock().unwrap().is_some() {
                    let _ = navigate(app, LOCAL_URL.parse().unwrap());
                }
            }
            "devices" => show_page(app, &state, "devices"),
            "backups" => show_page(app, &state, "backups"),
            "reconnect" => state.wake.notify_one(),
            _ => {}
        }
    });

    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let listener = match TcpListener::bind(LOCAL_ADDR).await {
            Ok(l) => l,
            Err(e) => {
                state.set_phase(&handle, Phase::Error {
                    message: format!("Port {LOCAL_ADDR} is in use ({e}). Is the app already running?"),
                });
                return;
            }
        };
        let endpoint = match Endpoint::builder(presets::N0).secret_key(key).bind().await {
            Ok(ep) => ep,
            Err(e) => {
                state.set_phase(&handle, Phase::Error { message: format!("iroh: {e}") });
                return;
            }
        };
        tokio::spawn(forward_loop(listener, state.clone()));
        tokio::spawn(backup::sync_loop(handle.clone(), state.clone()));
        connection_loop(handle, state, endpoint).await;
    });
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| setup(app).map_err(Into::into))
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_gateway,
            retry,
            open_inventree,
            admin_request,
            show_devices,
            show_backups,
            backup_overview,
            backup_save_settings,
            backup_sync_now,
            backup_create_now,
            backup_setup_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running Connect for InvenTree");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_does_not_overwrite() {
        let dir = std::env::temp_dir().join(format!("cfi-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "export.csv"), dir.join("export.csv"));
        fs::write(dir.join("export.csv"), "").unwrap();
        assert_eq!(unique_path(&dir, "export.csv"), dir.join("export (1).csv"));
        fs::write(dir.join("export (1).csv"), "").unwrap();
        assert_eq!(unique_path(&dir, "export.csv"), dir.join("export (2).csv"));
        // no extension, and path components in the suggested name are stripped
        fs::write(dir.join("README"), "").unwrap();
        assert_eq!(unique_path(&dir, "README"), dir.join("README (1)"));
        assert_eq!(unique_path(&dir, "../../etc/passwd"), dir.join("passwd"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn url_classification() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(is_inventree_url(&u("http://localhost:8080/web/part/1")));
        assert!(!is_inventree_url(&u("http://localhost:8000/")));
        assert!(is_app_url(&u("tauri://localhost/index.html")));
        assert!(is_app_url(&u("http://tauri.localhost/index.html")));
        assert!(!is_app_url(&u("https://docs.inventree.org/")));
    }
}
