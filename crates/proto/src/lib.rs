//! Shared protocol between the InvenTree gateway and the desktop client.
//!
//! Every QUIC bi-stream starts with one type byte:
//! - [`STREAM_HELLO`]: client sends a length-prefixed JSON [`Hello`], gateway answers with [`HelloReply`]
//! - [`STREAM_TCP`]: raw bytes, forwarded to InvenTree (only for approved devices)
//! - [`STREAM_ADMIN`]: one [`AdminRequest`] / [`AdminReply`] exchange (only for admin devices)

use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"connect-for-inventree/1";

pub const STREAM_HELLO: u8 = 1;
pub const STREAM_TCP: u8 = 2;
pub const STREAM_ADMIN: u8 = 3;

/// QUIC close code used by the gateway when a device is not (or no longer) approved.
pub const CLOSE_NOT_APPROVED: u32 = 403;

const MAX_MSG: u32 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub device_name: String,
    pub os_user: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HelloReply {
    Approved {
        user: Option<String>,
        #[serde(default)]
        admin: bool,
    },
    Pending,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Approved,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub status: DeviceStatus,
    pub device_name: String,
    pub os_user: String,
    pub user: Option<String>,
    /// Admin devices may manage other devices from the app. Only settable via the gateway CLI.
    #[serde(default)]
    pub admin: bool,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum AdminRequest {
    List,
    Approve { id: String, user: String },
    Revoke { id: String },
    Delete { id: String },
    BackupStatus,
    /// Sets the age recipient (public key) for backups. Only allowed while none is set.
    BackupSetKey { recipient: String },
    BackupNow,
    /// Reply is [`AdminReply::Download`], followed by the raw file bytes from `offset`.
    BackupGet { name: String, offset: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub name: String,
    pub size: u64,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRun {
    pub time: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum AdminReply {
    Devices { devices: Vec<Device> },
    Backups {
        key_set: bool,
        running: bool,
        last_run: Option<BackupRun>,
        backups: Vec<BackupInfo>,
    },
    Download { size: u64 },
    Ok,
    Error { message: String },
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let buf = serde_json::to_vec(msg)?;
    w.write_u32(buf.len() as u32).await?;
    w.write_all(&buf).await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let len = r.read_u32().await?;
    if len > MAX_MSG {
        bail!("message too large: {len} bytes");
    }
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Human friendly short form of an endpoint id, e.g. `3f9a-b27c`.
pub fn short_id(id: &EndpointId) -> String {
    let s = id.to_string();
    format!("{}-{}", &s[..4], &s[4..8])
}

/// Loads the secret key from `path`, or creates a new one (file mode 0600).
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let hex = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return hex.trim().parse().context("invalid secret key file");
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let key = SecretKey::generate();
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(hex_encode(&key.to_bytes()).as_bytes())?;
    Ok(key)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strips control characters and limits length of client supplied strings.
pub fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}
