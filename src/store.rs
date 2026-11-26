//! Enrolled devices and sites. Secrets are held in memory and persisted only in sealed
//! form: either in `devices.json` or, when a remote secret store is configured, there.

use crate::ike::crypto;
use crate::net::Cidr;
use crate::seal::Vault;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    /// The IKE identity the peer must present.
    pub id: String,
    pub name: String,
    /// `sub` claim of the user who enrolled it.
    pub owner: String,
    pub owner_name: String,
    /// In memory only. Empty while unknown. Read from old files to migrate them.
    #[serde(default, skip_serializing)]
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<String>,
    /// The secret lives in the remote secret store.
    #[serde(default)]
    pub remote: bool,
    /// Non-empty for site-to-site gateways.
    #[serde(default)]
    pub remote_subnets: Vec<String>,
    pub created: u64,
    /// Unix time after which the credential stops working. Sites may have none.
    pub expires: Option<u64>,
}

impl Device {
    pub fn active(&self) -> bool {
        self.expires.is_none_or(|e| e > now())
    }

    pub fn subnets(&self) -> Vec<Cidr> {
        self.remote_subnets.iter().filter_map(|s| s.parse().ok()).collect()
    }
}

#[derive(Default)]
pub struct Store {
    path: Option<PathBuf>,
    vault: Option<Arc<Vault>>,
    /// Secrets belong in a remote store rather than in the local file.
    remote_backend: bool,
    pub devices: Vec<Device>,
    /// Devices revoked whose remote secret is not yet confirmed deleted.
    pub revocations: Vec<String>,
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)
}

fn read_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> io::Result<T> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e),
    }
}

impl Store {
    pub fn in_memory() -> Store {
        Store::default()
    }

    /// Whether the file already holds data that only an existing master key can read.
    pub fn needs_existing_key(path: &Path) -> io::Result<bool> {
        let devices: Vec<Device> = read_json(path)?;
        Ok(devices.iter().any(|d| d.sealed.is_some() || d.remote))
    }

    pub fn load(path: PathBuf, vault: Arc<Vault>, remote_backend: bool) -> io::Result<Store> {
        let mut devices: Vec<Device> = read_json(&path)?;
        for d in &mut devices {
            if !d.secret.is_empty() {
                // A file from before secrets were encrypted.
                d.sealed = Some(vault.seal(&d.id, &d.secret));
                d.remote = false;
            } else if let Some(sealed) = &d.sealed {
                d.secret = vault.open(&d.id, sealed).ok_or_else(|| {
                    io::Error::other(format!("cannot decrypt {} (wrong master key?)", d.id))
                })?;
            } else if d.remote && !remote_backend {
                return Err(io::Error::other(
                    "secrets are held in Cloud Cache but [cloud_cache] is not configured",
                ));
            }
        }
        let revocations = read_json(&path.with_file_name("revocations.json"))?;
        let store = Store { path: Some(path), vault: Some(vault), remote_backend, devices, revocations };
        store.save()?;
        Ok(store)
    }

    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        write_private(path, &serde_json::to_vec_pretty(&self.devices)?)
    }

    fn save_revocations(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        write_private(&path.with_file_name("revocations.json"), &serde_json::to_vec(&self.revocations)?)
    }

    pub fn find(&self, id: &[u8]) -> Option<&Device> {
        self.devices.iter().find(|d| d.id.as_bytes() == id)
    }

    fn check_overlap(&self, subnets: &[Cidr]) -> io::Result<()> {
        let overlap = subnets
            .iter()
            .any(|new| self.devices.iter().any(|d| d.subnets().iter().any(|old| old.overlaps(new))));
        if overlap { Err(io::Error::other("subnet overlaps an existing site")) } else { Ok(()) }
    }

    /// Generates an identity and a 256 bit secret. Nothing is stored until [`Store::insert`].
    pub fn new_device(
        &self,
        name: &str,
        owner: &str,
        owner_name: &str,
        remote_subnets: &[Cidr],
        expires: Option<u64>,
    ) -> io::Result<Device> {
        self.check_overlap(remote_subnets)?;
        let random: [u8; 8] = crypto::random();
        let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Device {
            id: format!("{hex}@ripsec"),
            name: name.to_string(),
            owner: owner.to_string(),
            owner_name: owner_name.to_string(),
            secret: URL_SAFE_NO_PAD.encode(crypto::random::<32>()),
            sealed: None,
            remote: false,
            remote_subnets: remote_subnets.iter().map(Cidr::to_string).collect(),
            created: now(),
            expires,
        })
    }

    /// Persists a device. With a remote backend its secret must already be stored there.
    pub fn insert(&mut self, mut device: Device) -> io::Result<()> {
        self.check_overlap(&device.subnets())?;
        device.remote = self.remote_backend;
        device.sealed =
            self.vault.as_ref().filter(|_| !device.remote).map(|v| v.seal(&device.id, &device.secret));
        self.devices.push(device);
        if let Err(e) = self.save() {
            self.devices.pop();
            return Err(e);
        }
        Ok(())
    }

    /// Records that the remote copy of this secret must be deleted.
    pub fn queue_revocation(&mut self, id: &str) -> io::Result<()> {
        if self.remote_backend && !self.revocations.iter().any(|r| r == id) {
            self.revocations.push(id.to_string());
            self.save_revocations()?;
        }
        Ok(())
    }

    pub fn finish_revocation(&mut self, id: &str) -> io::Result<()> {
        self.revocations.retain(|r| r != id);
        self.save_revocations()
    }

    /// Takes effect immediately, whether or not the remote store is reachable.
    pub fn remove(&mut self, id: &str) -> io::Result<()> {
        self.queue_revocation(id)?;
        self.devices.retain(|d| d.id != id);
        self.save()
    }

    pub fn set_expiry(&mut self, id: &str, expires: Option<u64>) -> io::Result<()> {
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == id) {
            d.expires = expires;
        }
        self.save()
    }

    /// Updates the in-memory copy of a remotely held secret. `None` disables the device.
    pub fn set_secret(&mut self, id: &str, secret: Option<String>) {
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == id && d.remote) {
            d.secret = secret.unwrap_or_default();
        }
    }

    /// The remote store acknowledged this secret, so the local copy is dropped.
    pub fn mark_remote(&mut self, id: &str) -> io::Result<()> {
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == id) {
            d.remote = true;
            d.sealed = None;
        }
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ripsec-{name}-{}", u64::from_ne_bytes(crypto::random())));
        fs::create_dir_all(&dir).unwrap();
        dir.join("devices.json")
    }

    fn vault() -> Arc<Vault> {
        Arc::new(Vault::new(&[9; 32]))
    }

    #[test]
    fn migrates_plaintext_and_never_writes_secrets() {
        let path = scratch("migrate");
        fs::write(&path, r#"[{"id":"a@ripsec","name":"n","owner":"o","owner_name":"o","secret":"hunter2","created":0,"expires":null}]"#).unwrap();
        let store = Store::load(path.clone(), vault(), false).unwrap();
        assert_eq!(store.devices[0].secret, "hunter2");
        assert!(!fs::read_to_string(&path).unwrap().contains("hunter2"));
        assert_eq!(Store::load(path.clone(), vault(), false).unwrap().devices[0].secret, "hunter2");
        assert!(Store::load(path.clone(), Arc::new(Vault::new(&[1; 32])), false).is_err());
        assert!(Store::needs_existing_key(&path).unwrap());
    }

    #[test]
    fn remote_secrets_are_not_kept_on_disk_and_revocations_persist() {
        let path = scratch("remote");
        let mut store = Store::load(path.clone(), vault(), true).unwrap();
        let device = store.new_device("n", "o", "o", &[], None).unwrap();
        let id = device.id.clone();
        store.insert(device).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("sealed") && !text.contains("secret"));
        // Without the backend such a file cannot be used.
        assert!(Store::load(path.clone(), vault(), false).is_err());
        store.remove(&id).unwrap();
        assert_eq!(Store::load(path, vault(), true).unwrap().revocations, [id]);
    }
}
