//! Keeps a tunnel up: connects, reconnects after the server is lost, restarts or the keys
//! are old, and gives up when trying again could not help.

use crate::ike;
use crate::profile::Profile;
use crate::tunnel::{Connected, Counters, Ended, Options};
use ripsec_proto::net::Cidr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A connection the server closes sooner than this counts against trying again.
const SHORT_LIVED: Duration = Duration::from_secs(120);
/// Two computers sharing one profile would otherwise take turns for ever.
const MAX_SHORT_LIVED: u32 = 3;

pub enum Event<'a> {
    Connecting,
    Up {
        address: Ipv4Addr,
        routes: &'a [Cidr],
    },
    /// The server stopped answering; a new connection follows.
    Lost,
    /// The server closed the connection, as it does when it shuts down; we try again.
    /// A revoked device is then refused, which ends it.
    Closed,
    /// The connection is being replaced to get fresh keys.
    Renewing,
    Unreachable {
        retry_in: Duration,
    },
}

/// Runs until `stop` is set (`Ok`), or until the connection cannot be made or kept (`Err`).
/// A first attempt that fails is reported at once; after a success, we keep trying.
pub fn run(
    profile: &Profile,
    options: &Options,
    stop: &AtomicBool,
    counters: &Counters,
    on: &mut dyn FnMut(Event),
) -> Result<(), String> {
    let mut backoff = Duration::from_secs(1);
    let mut connected_before = false;
    let mut closed_quickly = 0;
    while !stop.load(Ordering::Relaxed) {
        on(Event::Connecting);
        match Connected::handshake(profile, options, stop) {
            Ok(connected) => {
                let address = connected.address();
                let started = Instant::now();
                let ended =
                    connected.run(options, stop, counters, |routes| on(Event::Up { address, routes }))?;
                connected_before = true;
                backoff = Duration::from_secs(1);
                match ended {
                    Ended::Stopped => return Ok(()),
                    Ended::ClosedByServer => {
                        closed_quickly = if started.elapsed() < SHORT_LIVED { closed_quickly + 1 } else { 0 };
                        if closed_quickly >= MAX_SHORT_LIVED {
                            return Err("the server keeps closing the connection; is this profile \
                                        in use somewhere else?"
                                .into());
                        }
                        on(Event::Closed);
                        wait(Duration::from_secs(2), stop);
                    }
                    Ended::Lost => on(Event::Lost),
                    Ended::Expired => on(Event::Renewing),
                }
            }
            Err(ike::Error::Cancelled) => return Ok(()),
            Err(ike::Error::NoResponse | ike::Error::Io(_)) if connected_before => {
                on(Event::Unreachable { retry_in: backoff });
                wait(backoff, stop);
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Sleeps, but not past a request to stop.
fn wait(duration: Duration, stop: &AtomicBool) {
    let until = Instant::now() + duration;
    while Instant::now() < until && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
}
