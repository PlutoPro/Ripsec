//! Keeps a tunnel up: connects, reconnects after the server is lost or the keys are old,
//! and gives up when trying again could not help.

use crate::ike;
use crate::profile::Profile;
use crate::tunnel::{Connected, Counters, Ended, Options};
use ripsec_proto::net::Cidr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub enum Event<'a> {
    Connecting,
    Up {
        address: Ipv4Addr,
        routes: &'a [Cidr],
    },
    /// The server stopped answering; a new connection follows.
    Lost,
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
    while !stop.load(Ordering::Relaxed) {
        on(Event::Connecting);
        match Connected::handshake(profile, options, stop) {
            Ok(connected) => {
                let address = connected.address();
                let ended =
                    connected.run(options, stop, counters, |routes| on(Event::Up { address, routes }))?;
                connected_before = true;
                backoff = Duration::from_secs(1);
                match ended {
                    Ended::Stopped => return Ok(()),
                    Ended::ClosedByServer => return Err("the server closed the connection".into()),
                    Ended::Lost => on(Event::Lost),
                    Ended::Expired => on(Event::Renewing),
                }
            }
            Err(ike::Error::Cancelled) => return Ok(()),
            Err(ike::Error::NoResponse | ike::Error::Io(_)) if connected_before => {
                on(Event::Unreachable { retry_in: backoff });
                let until = Instant::now() + backoff;
                while Instant::now() < until && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
