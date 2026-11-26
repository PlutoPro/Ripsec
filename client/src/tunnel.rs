//! One connection from handshake to disconnect: moves packets between the virtual
//! interface and the server, and notices when the server goes away.

use crate::esp;
use crate::ike::{self, Event, MARKER, Session};
use crate::profile::Profile;
use crate::tun::{self, Tun};
use ripsec_proto::net::Cidr;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Keeps NAT mappings open.
const KEEPALIVE: Duration = Duration::from_secs(20);
/// Silence after which we ask whether the server is still there, and then give up.
const PROBE_AFTER: Duration = Duration::from_secs(30);
const PROBE_EVERY: Duration = Duration::from_secs(5);
const DEAD_AFTER: Duration = Duration::from_secs(60);
/// The server never rekeys, so a long session is replaced to get fresh keys.
const MAX_AGE: Duration = Duration::from_secs(8 * 3600);

pub struct Options {
    /// Overrides the server named in the profile.
    pub server: Option<String>,
    /// Overrides the profile's port. Without either, 4500.
    pub port: Option<u16>,
    /// Overrides the networks routed through the tunnel. They must be within the profile's.
    pub routes: Vec<Cidr>,
}

/// Why a working connection ended.
#[derive(Debug, PartialEq)]
pub enum Ended {
    /// We were asked to stop.
    Stopped,
    /// The server disconnected us, for example because the device was revoked.
    ClosedByServer,
    /// The server stopped answering.
    Lost,
    /// Time for new keys.
    Expired,
}

#[derive(Default)]
pub struct Counters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

pub struct Connected {
    socket: UdpSocket,
    session: Session,
    child: ike::Child,
    server: Ipv4Addr,
}

fn resolve(host: &str, port: u16) -> Result<SocketAddrV4, ike::Error> {
    (host, port)
        .to_socket_addrs()?
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| ike::Error::Refused(format!("{host} has no IPv4 address")))
}

impl Connected {
    /// Performs the handshake. No network settings are touched yet.
    pub fn handshake(
        profile: &Profile,
        options: &Options,
        stop: &AtomicBool,
    ) -> Result<Connected, ike::Error> {
        let port = options.port.or(profile.port).unwrap_or(4500);
        let server = resolve(options.server.as_deref().unwrap_or(&profile.server), port)?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect(server)?;
        let (session, child) = Session::connect(&socket, profile, stop)?;
        Ok(Connected { socket, session, child, server: *server.ip() })
    }

    pub fn address(&self) -> Ipv4Addr {
        self.child.address
    }

    pub fn routes(&self) -> &[Cidr] {
        &self.child.routes
    }

    pub fn disconnect(mut self) {
        self.session.close(&self.socket);
    }

    /// Sets up the interface, the routes and both directions of ESP.
    fn prepare(&self, options: &Options) -> Result<(Tun, Vec<Cidr>, esp::Sender, esp::Receiver), String> {
        let allowed = &self.child.routes;
        let routes: Vec<Cidr> =
            if options.routes.is_empty() { allowed.clone() } else { options.routes.clone() };
        let within = |r: &Cidr| allowed.iter().any(|a| a.first() <= r.first() && r.last() <= a.last());
        if let Some(outside) = routes.iter().find(|r| !within(r)) {
            return Err(format!("the server does not carry {outside}"));
        }
        let sender = esp::Sender::new(self.child.spi_out, &self.child.key_out).ok_or("invalid keys")?;
        let receiver = esp::Receiver::new(self.child.spi_in, &self.child.key_in).ok_or("invalid keys")?;
        // A DNS server is only set if the tunnel actually leads to it.
        let everything = routes.iter().any(|r| r.prefix == 0);
        // The server's own onward traffic would be routed straight back into the tunnel.
        if everything && self.server.is_loopback() {
            return Err("the server is on this computer, so not all traffic can go through it; \
                        limit the routes"
                .into());
        }
        let dns = self.child.dns.iter().copied().filter(|d| everything || covers(&routes, *d)).collect();
        let tun = Tun::open(&tun::Settings {
            address: self.child.address,
            routes: routes.clone(),
            dns,
            server: self.server,
        })?;
        Ok((tun, routes, sender, receiver))
    }

    /// Creates the interface and carries traffic until `stop` is set or the connection ends.
    /// `up` is called once traffic can flow.
    pub fn run(
        mut self,
        options: &Options,
        stop: &AtomicBool,
        counters: &Counters,
        up: impl FnOnce(&[Cidr]),
    ) -> Result<Ended, String> {
        let (tun, routes, mut sender, mut receiver) = match self.prepare(options) {
            Ok(ready) => ready,
            Err(e) => {
                // Do not leave a session behind on the server.
                self.session.close(&self.socket);
                return Err(e);
            }
        };
        let address = self.child.address;
        up(&routes);

        let done = AtomicBool::new(false);
        let socket = &self.socket;
        let ended = std::thread::scope(|scope| {
            // Interface to server.
            scope.spawn(|| {
                let mut buffer = vec![0u8; 65536];
                while !done.load(Ordering::Relaxed) {
                    let packet = match tun.recv(&mut buffer) {
                        Ok(Some(n)) => &buffer[..n],
                        Ok(None) => continue,
                        Err(e) => {
                            if !done.load(Ordering::Relaxed) {
                                eprintln!("cannot read the interface: {e}");
                            }
                            break;
                        }
                    };
                    // Only IPv4 from our assigned address to somewhere the server carries.
                    if !addresses(packet).is_some_and(|(from, to)| from == address && covers(&routes, to)) {
                        continue;
                    }
                    let Some(sealed) = sender.seal(packet) else { break };
                    // A send that fails is a lost packet; the liveness check handles the rest.
                    if socket.send(&sealed).is_ok() {
                        counters.bytes_out.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    }
                }
            });

            // Server to interface, and everything about the connection itself.
            let mut buffer = vec![0u8; 65536];
            let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
            let started = Instant::now();
            let (mut heard, mut kept_alive, mut probed) = (started, started, started);
            let ended = loop {
                if stop.load(Ordering::Relaxed) {
                    break Ended::Stopped;
                }
                if let Ok(n) = socket.recv(&mut buffer) {
                    let datagram = &buffer[..n];
                    if let Some(message) = datagram.strip_prefix(&MARKER) {
                        match self.session.handle(socket, message) {
                            Ok(Event::Closed) => break Ended::ClosedByServer,
                            Ok(Event::Alive) => heard = Instant::now(),
                            Ok(Event::Ignored) | Err(_) => {}
                        }
                    } else if let Some(packet) = receiver.open(datagram) {
                        heard = Instant::now();
                        // The server may only deliver traffic from our routes to our address.
                        if addresses(&packet).is_some_and(|(from, to)| to == address && covers(&routes, from))
                            && tun.send(&packet).is_ok()
                        {
                            counters.bytes_in.fetch_add(packet.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
                let now = Instant::now();
                if now - kept_alive >= KEEPALIVE {
                    let _ = socket.send(&[0xff]);
                    kept_alive = now;
                }
                if now - heard >= DEAD_AFTER {
                    break Ended::Lost;
                }
                if now - heard >= PROBE_AFTER && now - probed >= PROBE_EVERY {
                    let _ = self.session.probe(socket);
                    probed = now;
                }
                if now - started >= MAX_AGE {
                    break Ended::Expired;
                }
            };
            done.store(true, Ordering::Relaxed);
            tun.stop();
            ended
        });

        if matches!(ended, Ended::Stopped | Ended::Expired) {
            self.session.close(&self.socket);
        }
        Ok(ended)
    }
}

/// Source and destination of an IPv4 packet.
fn addresses(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let at = |i: usize| <[u8; 4]>::try_from(&packet[i..i + 4]).ok().map(Ipv4Addr::from);
    Some((at(12)?, at(16)?))
}

fn covers(routes: &[Cidr], address: Ipv4Addr) -> bool {
    let address = u32::from(address);
    routes.iter().any(|r| r.first() <= address && address <= r.last())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ipv4_addresses_only() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 168, 1, 9]);
        let (from, to) = addresses(&packet).unwrap();
        assert_eq!((from.to_string().as_str(), to.to_string().as_str()), ("10.0.0.1", "192.168.1.9"));
        assert!(covers(&["192.168.1.0/24".parse().unwrap()], to));
        assert!(!covers(&["192.168.1.0/24".parse().unwrap()], from));
        packet[0] = 0x60;
        assert!(addresses(&packet).is_none());
        assert!(addresses(&packet[..19]).is_none());
    }
}
