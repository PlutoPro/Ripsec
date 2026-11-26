//! The one connection a background service manages, and what the app is told about it.

use crate::connection::{self, Event};
use crate::ipc::{Request, State, Status};
use crate::store::{Store, summary};
use crate::tun::{Network, System};
use crate::tunnel::Counters;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Instant;

const MAX_LOG: u64 = 256 * 1024;

#[derive(Default)]
struct Live {
    state: State,
    address: Option<String>,
    routes: Vec<String>,
    since: Option<Instant>,
    error: Option<String>,
}

struct Worker {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

pub struct Controller {
    store: Store,
    live: Arc<Mutex<Live>>,
    counters: Mutex<Arc<Counters>>,
    worker: Mutex<Option<Worker>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A short history for troubleshooting, beside the profile. Never contains secrets.
fn log(path: &std::path::Path, message: &str) {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_LOG) {
        let _ = std::fs::rename(path, path.with_extension("old"));
    }
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{time} {message}");
    }
}

impl Controller {
    pub fn new(store: Store) -> Arc<Controller> {
        Arc::new(Controller {
            store,
            live: Arc::default(),
            counters: Mutex::default(),
            worker: Mutex::default(),
        })
    }

    pub fn handle(&self, request: Request) -> Status {
        match request {
            Request::Status => {}
            Request::Connect => self.connect_with(Arc::new(System)),
            Request::Disconnect => self.disconnect(),
        }
        self.status()
    }

    /// Starts connecting, using this to create the interface. Does nothing if a
    /// connection is already being kept up.
    pub fn connect_with(&self, network: Arc<dyn Network>) {
        if let Err(e) = self.connect(network.clone()) {
            lock(&self.live).error = Some(e);
            network.finished();
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn status(&self) -> Status {
        let profile = self.store.load();
        let counters = lock(&self.counters).clone();
        let live = lock(&self.live);
        Status {
            state: live.state,
            error: live.error.clone().or_else(|| profile.as_ref().err().cloned()),
            profile: profile.ok().flatten().map(|(p, o)| summary(&p, &o)),
            address: live.address.clone(),
            routes: live.routes.clone(),
            connected_seconds: live.since.map_or(0, |t| t.elapsed().as_secs()),
            bytes_in: counters.bytes_in.load(Ordering::Relaxed),
            bytes_out: counters.bytes_out.load(Ordering::Relaxed),
        }
    }

    fn connect(&self, network: Arc<dyn Network>) -> Result<(), String> {
        let mut worker = lock(&self.worker);
        if worker.as_ref().is_some_and(|w| !w.thread.is_finished()) {
            return Ok(());
        }
        let (profile, mut options) = self.store.load()?.ok_or("add a profile first")?;
        options.network = network;
        let counters = Arc::new(Counters::default());
        *lock(&self.counters) = counters.clone();
        *lock(&self.live) = Live { state: State::Connecting, ..Live::default() };

        let stop = Arc::new(AtomicBool::new(false));
        let (flag, live) = (stop.clone(), self.live.clone());
        let journal = self.store.directory().join("service.log");
        let thread = std::thread::spawn(move || {
            log(&journal, "connecting");
            let result = connection::run(&profile, &options, &flag, &counters, &mut |event| {
                let mut live = lock(&live);
                match event {
                    Event::Connecting => {
                        if live.state != State::Reconnecting {
                            live.state = State::Connecting;
                        }
                    }
                    Event::Up { address, routes } => {
                        log(&journal, &format!("connected as {address}"));
                        live.state = State::Connected;
                        live.address = Some(address.to_string());
                        live.routes = routes.iter().map(ToString::to_string).collect();
                        live.since = Some(Instant::now());
                        live.error = None;
                    }
                    Event::Lost | Event::Closed | Event::Renewing | Event::Unreachable { .. } => {
                        log(&journal, "reconnecting");
                        live.state = State::Reconnecting;
                        live.address = None;
                        live.since = None;
                    }
                }
            });
            log(
                &journal,
                &match &result {
                    Ok(()) => "disconnected".to_string(),
                    Err(e) => format!("failed: {e}"),
                },
            );
            *lock(&live) = Live { error: result.err(), ..Live::default() };
            options.network.finished();
        });
        *worker = Some(Worker { stop, thread });
        Ok(())
    }

    /// Returns once the tunnel and its routes are gone.
    pub fn disconnect(&self) {
        let mut worker = lock(&self.worker);
        if let Some(Worker { stop, thread }) = worker.take() {
            stop.store(true, Ordering::Relaxed);
            let _ = thread.join();
        }
        *lock(&self.live) = Live::default();
    }
}
