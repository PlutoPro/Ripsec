//! The stored profile. It holds the device secret, so its directory must be private: on
//! Windows only the system and administrators can read it (set up by `install`), and on
//! Android it is the app's own storage, excluded from backups.

use crate::ipc::ProfileSummary;
use crate::profile::Profile;
use crate::tunnel::Options;
use ripsec_proto::net::Cidr;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_PROFILE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct Saved {
    /// The portal's strongSwan file, as downloaded.
    profile: String,
    server: Option<String>,
    port: Option<u16>,
    routes: Vec<String>,
}

pub struct Store {
    directory: PathBuf,
}

/// A host name or IPv4 address, and nothing that could be read as anything else.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn saved(text: String, options: &[&str]) -> Result<Saved, String> {
    let profile = Profile::parse(&text)?;
    if !valid_host(&profile.server) {
        return Err("the profile names an invalid server".into());
    }
    let mut saved = Saved { profile: text, server: None, port: None, routes: Vec::new() };
    let mut options = options.iter();
    while let Some(name) = options.next() {
        let value = options.next().ok_or_else(|| format!("{name} needs a value"))?;
        match *name {
            "--server" if valid_host(value) => saved.server = Some(value.to_string()),
            "--port" => {
                let port = value.parse().ok().filter(|p| *p != 0);
                saved.port = Some(port.ok_or("invalid port")?);
            }
            "--route" => saved.routes.push(value.parse::<Cidr>()?.to_string()),
            _ => return Err(format!("invalid option {name} {value}")),
        }
    }
    Ok(saved)
}

impl Store {
    pub fn at(directory: PathBuf) -> Store {
        Store { directory }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn path(&self) -> PathBuf {
        self.directory.join("profile.json")
    }

    pub fn import(&self, file: &Path, options: &[&str]) -> Result<(), String> {
        let size = fs::metadata(file).map_err(|e| format!("{}: {e}", file.display()))?.len();
        if size > MAX_PROFILE {
            return Err("that file is too large to be a profile".into());
        }
        let text = fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        self.import_text(text, options)
    }

    /// Stores a profile already read, with options as on the command line.
    pub fn import_text(&self, text: String, options: &[&str]) -> Result<(), String> {
        if text.len() as u64 > MAX_PROFILE {
            return Err("that file is too large to be a profile".into());
        }
        let saved = saved(text, options)?;
        if !self.directory.is_dir() {
            return Err("the data directory is missing; is Ripsec installed?".into());
        }
        let json = serde_json::to_vec(&saved).map_err(|e| e.to_string())?;
        let temporary = self.directory.join("profile.tmp");
        fs::write(&temporary, json)
            .and_then(|()| fs::rename(&temporary, self.path()))
            .map_err(|e| format!("cannot save the profile: {e}"))
    }

    pub fn remove(&self) -> Result<(), String> {
        match fs::remove_file(self.path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        }
    }

    /// `None` when no profile has been added.
    pub fn load(&self) -> Result<Option<(Profile, Options)>, String> {
        let json = match fs::read(self.path()) {
            Ok(json) => json,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read the profile: {e}")),
        };
        let saved: Saved = serde_json::from_slice(&json).map_err(|_| "the stored profile is damaged")?;
        let profile = Profile::parse(&saved.profile)?;
        let routes = saved.routes.iter().map(|r| r.parse()).collect::<Result<Vec<Cidr>, _>>()?;
        let options = Options { server: saved.server, port: saved.port, routes, ..Options::default() };
        Ok(Some((profile, options)))
    }
}

pub fn summary(profile: &Profile, options: &Options) -> ProfileSummary {
    let routes = if options.routes.is_empty() { &profile.routes } else { &options.routes };
    ProfileSummary {
        id: profile.id.clone(),
        server: options.server.clone().unwrap_or_else(|| profile.server.clone()),
        port: options.port.or(profile.port).unwrap_or(4500),
        routes: routes.iter().map(ToString::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "connections {\n ripsec {\n remote_addrs = vpn.example.com\n local {\n id = a@ripsec\n }\n \
        remote {\n id = vpn\n }\n children {\n net {\n remote_ts = 0.0.0.0/0\n }\n }\n }\n }\n \
        secrets {\n s {\n secret = \"top-secret-value\"\n }\n }\n";

    #[test]
    fn imports_with_options_and_never_summarises_the_secret() {
        let directory = std::env::temp_dir().join(format!("ripsec-store-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("ripsec.conf");
        fs::write(&file, PROFILE).unwrap();
        let store = Store::at(directory.clone());
        assert!(store.load().unwrap().is_none());
        store.import(&file, &["--port", "14500", "--route", "10.1.2.3/24"]).unwrap();
        let (profile, options) = store.load().unwrap().unwrap();
        let summary = summary(&profile, &options);
        assert_eq!((summary.server.as_str(), summary.port), ("vpn.example.com", 14500));
        assert_eq!(summary.routes, ["10.1.2.0/24"]);
        assert!(!serde_json::to_string(&summary).unwrap().contains("top-secret-value"));
        store.remove().unwrap();
        store.remove().unwrap();
        assert!(store.load().unwrap().is_none());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_odd_input() {
        let bad = |options: &[&str]| saved(PROFILE.into(), options).is_err();
        assert!(bad(&["--server", "-x"]));
        assert!(bad(&["--server", "a b"]));
        assert!(bad(&["--port", "0"]));
        assert!(bad(&["--route", "everything"]));
        assert!(bad(&["--port"]));
        assert!(saved("not a profile".into(), &[]).is_err());
        assert!(saved(PROFILE.replace("vpn.example.com", "a;b"), &[]).is_err());
    }
}
