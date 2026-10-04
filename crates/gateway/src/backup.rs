//! Encrypted backups of the whole InvenTree installation.
//!
//! A backup is one tar archive, encrypted with age to the admin's public key, so the server
//! can create backups but never read them. Contents:
//! - `db.dump`: `pg_dump -Fc` of the InvenTree database
//! - `data/`: InvenTree data dir (media, config.yaml, secret_key.txt, ...), without static files
//! - `config/`: env files and Caddyfile
//! - `gateway/`: gateway key, device list, backup recipients
//! - `quadlets/`: container definitions
//! - `manifest.json`

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::SystemTime,
};

use age::x25519;
use anyhow::{Context, Result, bail, ensure};
use proto::{BackupInfo, BackupRun};

pub const EXTENSION: &str = ".tar.age";
const RECIPIENTS_FILE: &str = "backup-recipients.txt";
const LAST_RUN_FILE: &str = "last-run.json";
const RUNNING_FILE: &str = "running";
/// Data dir entries that are rebuilt by InvenTree and not worth backing up.
const SKIP_IN_DATA: &[&str] = &["static", "backup"];

pub struct Paths {
    /// InvenTree home, e.g. /opt/inventree
    pub home: PathBuf,
    /// Gateway data dir, e.g. /opt/inventree/gateway
    pub gateway: PathBuf,
}

impl Paths {
    pub fn backups(&self) -> PathBuf {
        self.home.join("backups")
    }
}

pub fn recipients(gateway: &Path) -> Result<Vec<x25519::Recipient>> {
    let path = gateway.join(RECIPIENTS_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).context("reading backup recipients"),
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.parse().map_err(|e| anyhow::anyhow!("invalid recipient '{l}': {e}")))
        .collect()
}

pub fn add_recipient(gateway: &Path, recipient: &str) -> Result<()> {
    let recipient = recipient.trim();
    recipient
        .parse::<x25519::Recipient>()
        .map_err(|e| anyhow::anyhow!("invalid age public key: {e}"))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(gateway.join(RECIPIENTS_FILE))?;
    writeln!(f, "{recipient}")?;
    Ok(())
}

pub fn list(paths: &Paths) -> Result<Vec<BackupInfo>> {
    let mut out = vec![];
    let dir = match fs::read_dir(paths.backups()) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(EXTENSION) {
            continue;
        }
        let meta = entry.metadata()?;
        out.push(BackupInfo {
            name,
            size: meta.len(),
            created: meta.modified().map(rfc3339).unwrap_or_default(),
        });
    }
    // Names contain a sortable timestamp, newest first.
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(out)
}

/// Resolves a backup name from a client to a path, refusing anything outside the backup dir.
pub fn resolve(paths: &Paths, name: &str) -> Result<PathBuf> {
    ensure!(
        name.ends_with(EXTENSION) && !name.contains(['/', '\\']) && !name.starts_with('.'),
        "invalid backup name"
    );
    let path = paths.backups().join(name);
    ensure!(path.is_file(), "backup not found");
    Ok(path)
}

pub fn last_run(paths: &Paths) -> Option<BackupRun> {
    let text = fs::read_to_string(paths.backups().join(LAST_RUN_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn is_running(paths: &Paths) -> bool {
    paths.backups().join(RUNNING_FILE).exists()
}

/// Creates a new encrypted backup and prunes old ones. Records the outcome in last-run.json.
pub fn create(paths: &Paths, keep: usize) -> Result<PathBuf> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(paths.backups())?;
    let running = paths.backups().join(RUNNING_FILE);
    File::create(&running)?;
    let result = create_inner(paths, keep);
    let _ = fs::remove_file(&running);

    let run = BackupRun {
        time: rfc3339(SystemTime::now()),
        ok: result.is_ok(),
        message: match &result {
            Ok(p) => format!("{} erstellt", p.file_name().unwrap_or_default().to_string_lossy()),
            Err(e) => format!("{e:#}"),
        },
    };
    let _ = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(paths.backups().join(LAST_RUN_FILE))
        .and_then(|mut f| f.write_all(serde_json::to_string_pretty(&run)?.as_bytes()));
    result
}

fn create_inner(paths: &Paths, keep: usize) -> Result<PathBuf> {
    let recipients = recipients(&paths.gateway)?;
    ensure!(
        !recipients.is_empty(),
        "kein Backup-Schlüssel hinterlegt (in der App unter Backups einrichten)"
    );

    let tmp = paths.home.join("tmp");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&tmp)?;
    let dump = tmp.join("db.dump");
    let result = (|| {
        pg_dump(&dump)?;
        write_archive(paths, &recipients, &dump)
    })();
    let _ = fs::remove_file(&dump);
    let path = result?;

    prune(paths, keep)?;
    Ok(path)
}

fn pg_dump(out: &Path) -> Result<()> {
    let file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(out)?;
    let output = Command::new("podman")
        .args(["exec", "inventree-db", "pg_dump", "-U", "inventree", "-Fc", "inventree"])
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .output()
        .context("running pg_dump via podman")?;
    if !output.status.success() {
        bail!("pg_dump failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    ensure!(fs::metadata(out)?.len() > 0, "pg_dump produced an empty file");
    Ok(())
}

fn write_archive(paths: &Paths, recipients: &[x25519::Recipient], dump: &Path) -> Result<PathBuf> {
    let name = format!("inventree-{}{EXTENSION}", rfc3339(SystemTime::now()).replace([':', '-'], ""));
    let final_path = paths.backups().join(&name);
    let partial = paths.backups().join(format!(".{name}.partial"));

    let file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&partial)?;
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let writer = encryptor.wrap_output(BufWriter::new(file))?;

    let mut tar = tar::Builder::new(writer);
    tar.follow_symlinks(false);
    tar.append_path_with_name(dump, "db.dump")?;

    let data = paths.home.join("data");
    for entry in fs::read_dir(&data).context("reading InvenTree data dir")? {
        let entry = entry?;
        let fname = entry.file_name();
        if SKIP_IN_DATA.contains(&fname.to_string_lossy().as_ref()) {
            continue;
        }
        let dest = Path::new("data").join(&fname);
        if entry.file_type()?.is_dir() {
            tar.append_dir_all(&dest, entry.path())?;
        } else {
            tar.append_path_with_name(entry.path(), &dest)?;
        }
    }
    tar.append_dir_all("config", paths.home.join("config"))?;
    for f in ["gateway.key", "devices.json", RECIPIENTS_FILE] {
        let p = paths.gateway.join(f);
        if p.exists() {
            tar.append_path_with_name(&p, Path::new("gateway").join(f))?;
        }
    }
    let quadlets = paths.home.join(".config/containers/systemd");
    if quadlets.is_dir() {
        tar.append_dir_all("quadlets", quadlets)?;
    }

    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "created": rfc3339(SystemTime::now()),
        "gateway_version": env!("CARGO_PKG_VERSION"),
        "contents": ["db.dump (pg_dump -Fc)", "data/", "config/", "gateway/", "quadlets/"],
    }))?;
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs());
    header.set_cksum();
    tar.append_data(&mut header, "manifest.json", manifest.as_slice())?;

    let writer = tar.into_inner()?;
    let mut buf = writer.finish()?;
    buf.flush()?;
    buf.get_ref().sync_all()?;
    drop(buf);

    fs::rename(&partial, &final_path)?;
    Ok(final_path)
}

fn prune(paths: &Paths, keep: usize) -> Result<()> {
    for old in list(paths)?.into_iter().skip(keep.max(1)) {
        fs::remove_file(paths.backups().join(&old.name))?;
    }
    Ok(())
}

/// Decrypts a backup with a key file. The key file may be a plain age identity or,
/// as created by the app, an armored age file protected with a passphrase.
pub fn decrypt(input: &Path, key_file: &Path, output: &mut dyn Write) -> Result<()> {
    let key_text = read_key_file(key_file)?;
    let identity: x25519::Identity = key_text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .context("no AGE-SECRET-KEY in key file")?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid secret key: {e}"))?;
    let decryptor = age::Decryptor::new(io::BufReader::new(File::open(input)?))?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    io::copy(&mut reader, output)?;
    Ok(())
}

fn read_key_file(path: &Path) -> Result<String> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.starts_with(b"AGE-SECRET-KEY-") || raw.starts_with(b"#") {
        return Ok(String::from_utf8(raw)?);
    }
    let passphrase = rpassword::prompt_password("Passphrase für den Backup-Schlüssel: ")?;
    let reader = age::armor::ArmoredReader::new(raw.as_slice());
    let decryptor = age::Decryptor::new(reader)?;
    let identity = age::scrypt::Identity::new(passphrase.into());
    let mut out = String::new();
    decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("falsche Passphrase?")?
        .read_to_string(&mut out)?;
    Ok(out)
}

fn rfc3339(t: SystemTime) -> String {
    humantime::format_rfc3339_seconds(t).to_string()
}
