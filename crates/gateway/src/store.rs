//! Device allowlist, stored as JSON. All access goes through [`with_store`],
//! which holds an exclusive file lock, so the daemon and the CLI can run concurrently.

use std::{
    fs::{self, File},
    path::Path,
    time::SystemTime,
};

use anyhow::{Context, Result, bail};
pub use proto::{Device, DeviceStatus as Status};
use serde::{Deserialize, Serialize};

/// Upper bound for unapproved entries, so unknown clients can't grow the file forever.
const MAX_PENDING: usize = 50;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub devices: Vec<Device>,
}

impl Store {
    pub fn get(&self, id: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == id)
    }

    /// Records a hello from `id`. Unknown devices are added as pending (if there is room).
    pub fn seen(&mut self, id: &str, device_name: &str, os_user: &str) -> Option<&Device> {
        let now = now();
        if let Some(i) = self.devices.iter().position(|d| d.id == id) {
            let d = &mut self.devices[i];
            d.last_seen = now;
            d.device_name = device_name.to_string();
            d.os_user = os_user.to_string();
            return Some(&self.devices[i]);
        }
        let pending = self.devices.iter().filter(|d| d.status == Status::Pending).count();
        if pending >= MAX_PENDING {
            return None;
        }
        self.devices.push(Device {
            id: id.to_string(),
            status: Status::Pending,
            device_name: device_name.to_string(),
            os_user: os_user.to_string(),
            user: None,
            admin: false,
            first_seen: now.clone(),
            last_seen: now,
        });
        self.devices.last()
    }

    /// Finds exactly one device by id prefix (short ids like `3f9a-b27c` are accepted).
    pub fn find_mut(&mut self, prefix: &str) -> Result<&mut Device> {
        let prefix = prefix.replace('-', "").to_lowercase();
        if prefix.len() < 4 {
            bail!("id prefix too short");
        }
        let mut matches = self.devices.iter_mut().filter(|d| d.id.starts_with(&prefix));
        match (matches.next(), matches.next()) {
            (Some(d), None) => Ok(d),
            (None, _) => bail!("no device matches '{prefix}'"),
            _ => bail!("'{prefix}' is ambiguous, use more characters"),
        }
    }
}

pub fn with_store<R>(dir: &Path, f: impl FnOnce(&mut Store) -> Result<R>) -> Result<R> {
    fs::create_dir_all(dir)?;
    let lock = File::create(dir.join("devices.lock"))?;
    lock.lock().context("locking device store")?;

    let path = dir.join("devices.json");
    let before = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).context("reading devices.json"),
    };
    let mut store: Store = if before.is_empty() {
        Store::default()
    } else {
        serde_json::from_str(&before).context("parsing devices.json")?
    };

    let result = f(&mut store)?;

    let after = serde_json::to_string_pretty(&store)?;
    if after != before {
        let tmp = dir.join("devices.json.tmp");
        fs::write(&tmp, &after)?;
        fs::rename(&tmp, &path)?;
    }
    Ok(result)
}

fn now() -> String {
    humantime::format_rfc3339_seconds(SystemTime::now()).to_string()
}
