//! Keeps device secrets in Cloud Cache.
//!
//! One thread owns the connection and does everything in order, so a newer write for a key is
//! never sent while an older one is unresolved. In priority order: writes the portal is waiting
//! for, revocations (persisted until confirmed), moving local secrets over, then re-reading.
//! The IKE engine only ever sees the in-memory copy and never waits for the network.

use crate::cloudcache::{Client, Failure, Reply, Settings, Token, TokenSource, tls_config};
use crate::config::CloudCache;
use crate::seal::Vault;
use crate::store::{Device, Store, now};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Entries outlive the credential, so that an expired device can still be renewed.
const RENEWAL_GRACE: u64 = 30 * 86_400;
/// A command can take about 8 seconds during a failover.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE: Duration = Duration::from_secs(60);
/// How long after a delete to confirm the key is still gone.
const VERIFY_AFTER: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_QUEUE: usize = 256;
/// How long the portal waits for an acknowledgement.
const PORTAL_WAIT: Duration = Duration::from_secs(20);

struct Write {
    id: String,
    sealed: String,
    expires: Option<u64>,
    done: oneshot::Sender<Result<(), String>>,
}

/// The portal's side of the worker.
#[derive(Clone)]
pub struct Handle {
    queue: mpsc::SyncSender<Write>,
    vault: Arc<Vault>,
}

impl Handle {
    /// Stores a device's secret, returning once Cloud Cache has acknowledged it. On error the
    /// write may still happen later: a caller that gives up on a new device must revoke it.
    pub async fn store(&self, device: &Device) -> Result<(), String> {
        let (done, acknowledged) = oneshot::channel();
        let write = Write {
            id: device.id.clone(),
            sealed: self.vault.seal(&device.id, &device.secret),
            expires: device.expires,
            done,
        };
        self.queue.try_send(write).map_err(|_| "secret store is backed up".to_string())?;
        match tokio::time::timeout(PORTAL_WAIT, acknowledged).await {
            Ok(Ok(result)) => result,
            _ => Err("secret store did not acknowledge in time".into()),
        }
    }
}

enum Command<'a> {
    Put { key: &'a str, value: &'a str, expires: Option<u64> },
    Delete { key: &'a str },
}

impl Command<'_> {
    /// The expiry is absolute, so resending a write does not extend it.
    fn line(&self) -> String {
        match self {
            Command::Put { key, value, expires: None } => format!("SET {key} {value}"),
            Command::Put { key, value, expires: Some(at) } => {
                let seconds = (at + RENEWAL_GRACE).saturating_sub(now()).max(1);
                format!("SETEX {key} {seconds} {value}")
            }
            Command::Delete { key } => format!("DEL {key}"),
        }
    }
}

struct Worker {
    client: Client,
    store: Arc<Mutex<Store>>,
    vault: Arc<Vault>,
    server_id: String,
    refresh_every: Duration,
    incoming: mpsc::Receiver<Write>,
    writes: VecDeque<Write>,
    /// Deleted keys waiting to be checked, and when to check them.
    verifying: HashMap<String, Instant>,
    refresh: VecDeque<String>,
    next_refresh: Instant,
    /// Set while backing off after a failure.
    paused_until: Instant,
    backoff: Duration,
}

impl Worker {
    fn key(&self, id: &str) -> String {
        format!("ripsec:{}:{id}", self.server_id)
    }

    fn lock(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn healthy(&mut self) {
        self.backoff = Duration::from_millis(500);
    }

    fn pause(&mut self, why: &str) {
        eprintln!("Cloud Cache: {why}; retrying in {:?}", self.backoff);
        self.paused_until = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    /// Runs a command, backing off on failure. `None` means it has to be tried again.
    fn run(&mut self, line: &str) -> Option<Result<Reply, String>> {
        match self.client.command(line) {
            Ok(reply) => {
                self.healthy();
                Some(Ok(reply))
            }
            Err(Failure::Retry(why) | Failure::Unknown(why)) => {
                self.pause(&why);
                None
            }
            Err(Failure::Unauthorized) => {
                self.pause("ALERT: access token rejected, check the ripsec-gateway client");
                self.backoff = MAX_BACKOFF;
                None
            }
            Err(Failure::Fatal(why)) => {
                eprintln!("Cloud Cache: ALERT: {why}");
                self.paused_until = Instant::now() + MAX_BACKOFF;
                Some(Err(why))
            }
        }
    }

    fn do_write(&mut self) {
        let Some(write) = self.writes.front() else { return };
        let key = self.key(&write.id);
        let line = Command::Put { key: &key, value: &write.sealed, expires: write.expires }.line();
        // Unresolved writes stay at the head, ahead of anything newer for the same key.
        let Some(result) = self.run(&line) else { return };
        if let Some(write) = self.writes.pop_front() {
            let result = match result {
                Ok(Reply::Ok) => Ok(()),
                Ok(_) => Err("unexpected reply".into()),
                Err(why) => Err(why),
            };
            let _ = write.done.send(result);
        }
    }

    /// Deletes revoked secrets, then confirms a little later that they stayed deleted.
    fn do_revocation(&mut self) -> bool {
        let now = Instant::now();
        let pending = self.lock().revocations.clone();
        let Some(id) = pending.into_iter().find(|id| self.verifying.get(id).is_none_or(|at| *at <= now))
        else {
            return false;
        };
        let key = self.key(&id);
        if self.verifying.contains_key(&id) {
            match self.run(&format!("GET {key}")) {
                Some(Ok(Reply::Nil)) => {
                    self.verifying.remove(&id);
                    if let Err(e) = self.lock().finish_revocation(&id) {
                        eprintln!("cannot save revocations: {e}");
                    }
                }
                // It came back, so delete it again.
                Some(Ok(_)) => {
                    self.verifying.remove(&id);
                }
                _ => {}
            }
        } else if let Some(Ok(_)) = self.run(&Command::Delete { key: &key }.line()) {
            self.verifying.insert(id, now + VERIFY_AFTER);
        }
        true
    }

    /// Moves one secret that is still held locally.
    fn do_migration(&mut self) -> bool {
        let Some(device) = self.lock().devices.iter().find(|d| !d.remote && !d.secret.is_empty()).cloned()
        else {
            return false;
        };
        let key = self.key(&device.id);
        let sealed = self.vault.seal(&device.id, &device.secret);
        let line = Command::Put { key: &key, value: &sealed, expires: device.expires }.line();
        if let Some(Ok(Reply::Ok)) = self.run(&line) {
            match self.lock().mark_remote(&device.id) {
                Ok(()) => eprintln!("moved the secret of {} to Cloud Cache", device.id),
                Err(e) => eprintln!("cannot save devices: {e}"),
            }
        }
        true
    }

    fn do_refresh(&mut self) {
        let Some(id) = self.refresh.front().cloned() else { return };
        let key = self.key(&id);
        // On failure the secret we already hold stays in use.
        let Some(result) = self.run(&format!("GET {key}")) else { return };
        self.refresh.pop_front();
        let secret = match result {
            Ok(Reply::Value(sealed)) => {
                let secret = self.vault.open(&id, &sealed);
                if secret.is_none() {
                    eprintln!("Cloud Cache: INCIDENT: the entry for {id} failed authentication");
                }
                secret
            }
            Ok(Reply::Nil) => {
                eprintln!("Cloud Cache: no secret for {id}; the device is disabled");
                None
            }
            _ => return,
        };
        self.lock().set_secret(&id, secret);
    }

    fn step(&mut self) {
        let now = Instant::now();
        if now < self.paused_until {
            return;
        }
        if !self.writes.is_empty() {
            return self.do_write();
        }
        if self.do_revocation() || self.do_migration() {
            return;
        }
        if self.refresh.is_empty() && now >= self.next_refresh {
            // Collected first, so the store is unlocked before the queue is replaced.
            let remote: VecDeque<String> =
                self.lock().devices.iter().filter(|d| d.remote).map(|d| d.id.clone()).collect();
            self.refresh = remote;
            self.next_refresh = now + self.refresh_every;
        }
        if !self.refresh.is_empty() {
            return self.do_refresh();
        }
        if self.client.connected() && self.client.last_used.elapsed() >= KEEPALIVE {
            let _ = self.run("PING");
        }
    }

    fn busy(&self) -> bool {
        Instant::now() >= self.paused_until && (!self.writes.is_empty() || !self.refresh.is_empty())
    }

    fn main_loop(mut self) {
        loop {
            let wait = if self.busy() { Duration::ZERO } else { Duration::from_millis(500) };
            match self.incoming.recv_timeout(wait) {
                Ok(write) => self.writes.push_back(write),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            self.writes.extend(self.incoming.try_iter());
            self.step();
        }
    }
}

/// Client credentials grant against the token endpoint.
fn token_source(config: &CloudCache) -> Result<TokenSource, String> {
    let mut builder = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10)));
    if let Some(path) = &config.token_ca_file {
        let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let certs = ureq::tls::parse_pem(&pem)
            .filter_map(|item| match item {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect::<Vec<_>>();
        if certs.is_empty() {
            return Err(format!("{}: no certificate found", path.display()));
        }
        let tls =
            ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::new_with_certs(&certs)).build();
        builder = builder.tls_config(tls);
    }
    let agent: ureq::Agent = builder.build().into();
    let (url, id, secret) =
        (config.token_url.clone(), config.client_id.clone(), config.client_secret.clone());
    Ok(Box::new(move || {
        let form = [("grant_type", "client_credentials"), ("client_id", &id), ("client_secret", &secret)];
        let body: serde_json::Value = agent
            .post(&url)
            .send_form(form)
            .map_err(|e| format!("token endpoint: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|_| "token endpoint: unreadable response".to_string())?;
        let value = body["access_token"].as_str().ok_or("token endpoint: no access_token")?.to_string();
        let lifetime = Duration::from_secs(body["expires_in"].as_u64().unwrap_or(60).max(10));
        Ok(Token { value, lifetime })
    }))
}

/// Starts the worker thread.
pub fn start(
    config: &CloudCache,
    server_id: &str,
    store: Arc<Mutex<Store>>,
    vault: Arc<Vault>,
) -> Result<Handle, String> {
    let settings = Settings {
        address: config.address.clone(),
        organization_id: config.organization_id.clone(),
        read_timeout: READ_TIMEOUT,
    };
    let client = Client::new(settings, tls_config(&config.ca_file)?, token_source(config)?);
    let (queue, incoming) = mpsc::sync_channel(MAX_QUEUE);
    let now = Instant::now();
    let worker = Worker {
        client,
        store,
        vault: vault.clone(),
        server_id: server_id.to_string(),
        refresh_every: Duration::from_secs(config.refresh_seconds.max(1)),
        incoming,
        writes: VecDeque::new(),
        verifying: HashMap::new(),
        refresh: VecDeque::new(),
        next_refresh: now,
        paused_until: now,
        backoff: Duration::from_millis(500),
    };
    thread::Builder::new()
        .name("cloud-cache".into())
        .spawn(move || worker.main_loop())
        .map_err(|e| e.to_string())?;
    Ok(Handle { queue, vault })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resent_writes_keep_the_same_expiry() {
        let expires = Some(now() + 100);
        let line = Command::Put { key: "k", value: "v", expires }.line();
        let seconds: u64 = line.split(' ').nth(2).unwrap().parse().unwrap();
        assert!(seconds > RENEWAL_GRACE && seconds <= RENEWAL_GRACE + 100);
        assert_eq!(Command::Put { key: "k", value: "v", expires: None }.line(), "SET k v");
        assert_eq!(Command::Delete { key: "k" }.line(), "DEL k");
    }
}
