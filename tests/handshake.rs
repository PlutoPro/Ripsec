//! The real client against the real server engine, over loopback UDP, with a data plane
//! that only records what the engine would have given the kernel.
//!
//! Unlike the Docker tests this needs no privileges, and it can look at both ends' keys,
//! lose packets on purpose and send nonsense.

use ripsec::config::Vpn;
use ripsec::dataplane::{Child as Installed, Dataplane};
use ripsec::ike::{Engine, Outgoing, crypto};
use ripsec::store::{Device, Store};
use ripsec_client::esp;
use ripsec_client::ike::{Child, Error, Event, MARKER, Session};
use ripsec_client::profile::Profile;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SERVER_ID: &str = "vpn.test";

#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<Installed>>>);

impl Dataplane for Recorder {
    fn add(&mut self, child: &Installed) -> io::Result<()> {
        self.0.lock().unwrap().push(child.clone());
        Ok(())
    }
    fn remove(&mut self, child: &Installed, _: bool) {
        self.0.lock().unwrap().retain(|c| c.spi_in != child.spi_in);
    }
    fn bytes(&mut self, _: &Installed) -> (u64, u64) {
        (0, 0)
    }
}

enum Control {
    /// Run the engine's periodic work as if this much time had passed.
    Tick(Duration),
}

struct Server {
    address: SocketAddr,
    store: Arc<Mutex<Store>>,
    device: Device,
    kernel: Recorder,
    sessions: Arc<AtomicUsize>,
    control: std::sync::mpsc::Sender<Control>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// `lose` drops the first copy of every message in each direction.
    fn start(lose: bool) -> Server {
        let mut store = Store::in_memory();
        let device = store.new_device("test", "owner", "tester", &[], None).unwrap();
        store.insert(device.clone()).unwrap();
        let store = Arc::new(Mutex::new(store));
        let config = Vpn {
            local_ip: "127.0.0.1".parse().unwrap(),
            public_address: "127.0.0.1".into(),
            server_id: SERVER_ID.into(),
            pool: "10.99.0.0/24".parse().unwrap(),
            dns: vec!["10.50.0.53".parse().unwrap()],
            local_subnets: vec!["10.50.0.0/16".parse().unwrap()],
            require_pq: true,
        };
        let kernel = Recorder::default();
        let mut engine = Engine::new(config, kernel.clone(), store.clone());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let address = socket.local_addr().unwrap();
        let sessions = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (control, commands) = std::sync::mpsc::channel();

        let (count, stopped) = (sessions.clone(), stop.clone());
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; 65536];
            let mut seen_in: Vec<Vec<u8>> = Vec::new();
            let mut seen_out: Vec<Vec<u8>> = Vec::new();
            let send = |out: Vec<Outgoing>, seen: &mut Vec<Vec<u8>>| {
                for packet in out {
                    if lose && !seen.contains(&packet.data) {
                        seen.push(packet.data);
                        continue;
                    }
                    let framed = [&MARKER[..], &packet.data].concat();
                    let _ = socket.send_to(&framed, packet.to);
                }
            };
            while !stopped.load(Ordering::Relaxed) {
                if let Ok(Control::Tick(ahead)) = commands.try_recv() {
                    send(engine.tick(Instant::now() + ahead), &mut seen_out);
                }
                if let Ok((n, SocketAddr::V4(from))) = socket.recv_from(&mut buffer)
                    && let Some(message) = buffer[..n].strip_prefix(&MARKER)
                {
                    if lose && !seen_in.iter().any(|m| m == message) {
                        seen_in.push(message.to_vec());
                        continue;
                    }
                    send(engine.handle(message, from, 4500), &mut seen_out);
                }
                count.store(engine.sessions().len(), Ordering::Relaxed);
            }
        });
        Server { address, store, device, kernel, sessions, control, stop, thread: Some(thread) }
    }

    fn profile(&self) -> Profile {
        Profile {
            server: self.address.ip().to_string(),
            port: Some(self.address.port()),
            id: self.device.id.clone(),
            server_id: SERVER_ID.into(),
            secret: self.device.secret.clone(),
            routes: vec!["0.0.0.0/0".parse().unwrap()],
        }
    }

    fn socket(&self) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(self.address).unwrap();
        socket
    }

    fn connect(&self, profile: &Profile) -> Result<(UdpSocket, Session, Child), Error> {
        let socket = self.socket();
        let (session, child) = Session::connect(&socket, profile, &AtomicBool::new(false))?;
        Ok((socket, session, child))
    }

    fn eventually(&self, sessions: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.sessions.load(Ordering::Relaxed) != sessions {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Passes the next IKE message from the server to the client session.
fn deliver(socket: &UdpSocket, session: &mut Session) -> Event {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buffer = [0u8; 65536];
    let n = socket.recv(&mut buffer).expect("nothing arrived from the server");
    session.handle(socket, buffer[..n].strip_prefix(&MARKER).unwrap()).unwrap()
}

#[test]
fn both_ends_agree_on_keys_addresses_and_routes() {
    let server = Server::start(false);
    let (_socket, _session, child) = server.connect(&server.profile()).unwrap();
    assert!(server.eventually(1));
    let installed = server.kernel.0.lock().unwrap().clone();
    assert_eq!(installed.len(), 1);
    let theirs = &installed[0];

    assert_eq!((theirs.spi_in, theirs.spi_out), (child.spi_out, child.spi_in));
    assert_eq!(theirs.key_in, child.key_out);
    assert_eq!(theirs.key_out, child.key_in);
    assert_ne!(child.key_in, child.key_out);
    assert!(theirs.esn);
    // The client must have made the server use UDP encapsulation.
    assert!(theirs.udp_encap);

    assert_eq!(child.address.to_string(), "10.99.0.2");
    assert_eq!(child.dns, ["10.50.0.53".parse::<std::net::Ipv4Addr>().unwrap()]);
    // Never wider than what the server allows.
    assert_eq!(child.routes, ["10.50.0.0/16".parse().unwrap()]);
    assert_eq!(theirs.remote_ts[0].addr(), child.address);

    // A packet sealed with our keys opens with the server's.
    let mut ours = esp::Sender::new(child.spi_out, &child.key_out).unwrap();
    let mut receiver = esp::Receiver::new(theirs.spi_in, &theirs.key_in).unwrap();
    let packet = [0x45u8; 100];
    assert_eq!(receiver.open(&ours.seal(&packet).unwrap()).unwrap(), packet);
}

#[test]
fn every_connection_gets_new_keys() {
    let server = Server::start(false);
    let (_, _, first) = server.connect(&server.profile()).unwrap();
    let (_, _, second) = server.connect(&server.profile()).unwrap();
    assert_ne!(first.key_out, second.key_out);
    assert_ne!(first.spi_in, second.spi_in);
    // One live session per credential: the older one is gone.
    assert!(server.eventually(1));
    assert_eq!(server.kernel.0.lock().unwrap().len(), 1);
}

#[test]
fn wrong_credentials_are_refused() {
    let server = Server::start(false);
    let refused = |change: &dyn Fn(&mut Profile)| {
        let mut profile = server.profile();
        change(&mut profile);
        matches!(server.connect(&profile), Err(Error::Refused(_)))
    };
    assert!(refused(&|p| p.secret.push('x')));
    assert!(refused(&|p| p.id = "someone-else@ripsec".into()));
    // The server proves who it is, too.
    assert!(refused(&|p| p.server_id = "impostor.test".into()));
    assert!(server.kernel.0.lock().unwrap().len() <= 1);

    server.store.lock().unwrap().remove(&server.device.id).unwrap();
    assert!(refused(&|_| {}), "a revoked device connected");
}

#[test]
fn revocation_closes_the_connection() {
    let server = Server::start(false);
    let (socket, mut session, _) = server.connect(&server.profile()).unwrap();
    server.store.lock().unwrap().remove(&server.device.id).unwrap();
    server.control.send(Control::Tick(Duration::from_secs(1))).unwrap();
    assert_eq!(deliver(&socket, &mut session), Event::Closed);
    assert!(server.eventually(0));
    assert!(server.kernel.0.lock().unwrap().is_empty());
}

#[test]
fn liveness_checks_work_in_both_directions_and_leaving_is_noticed() {
    let server = Server::start(false);
    let (socket, mut session, _) = server.connect(&server.profile()).unwrap();
    // The server asks, we answer, repeatedly.
    for round in 1..=3 {
        server.control.send(Control::Tick(Duration::from_secs(31 * round))).unwrap();
        assert_eq!(deliver(&socket, &mut session), Event::Alive);
        thread::sleep(Duration::from_millis(100));
    }
    // We ask, the server answers.
    for _ in 0..3 {
        session.probe(&socket).unwrap();
        assert_eq!(deliver(&socket, &mut session), Event::Alive);
    }
    assert!(server.eventually(1));
    session.close(&socket);
    assert!(server.eventually(0));
    assert!(server.kernel.0.lock().unwrap().is_empty());
}

#[test]
fn survives_losing_every_first_transmission() {
    let server = Server::start(true);
    let (_socket, _session, child) = server.connect(&server.profile()).unwrap();
    assert!(server.eventually(1));
    assert_eq!(server.kernel.0.lock().unwrap()[0].key_in, child.key_out);
}

#[test]
fn garbage_does_not_disturb_either_end() {
    let server = Server::start(false);
    let (socket, mut session, _) = server.connect(&server.profile()).unwrap();
    for round in 0..3000usize {
        let noise: [u8; 64] = crypto::random();
        let mut message = noise.repeat(1 + round % 5);
        message.truncate(round % 300);
        // Half of them look like they belong to this connection's protocol version.
        if message.len() >= 28 && round % 2 == 0 {
            message[17] = 0x20;
            let length = (message.len() as u32).to_be_bytes();
            message[24..28].copy_from_slice(&length);
        }
        assert_eq!(session.handle(&socket, &message).unwrap(), Event::Ignored);
        let _ = socket.send(&[&MARKER[..], &message].concat());
    }
    // Both ends still talk.
    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut buffer = [0u8; 65536];
    while socket.recv(&mut buffer).is_ok() {}
    // The flood can overflow the server's receive buffer, so ask again if need be.
    socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let answered = (0..20).any(|_| {
        session.probe(&socket).unwrap();
        socket.recv(&mut buffer).is_ok_and(|n| {
            buffer[..n]
                .strip_prefix(&MARKER)
                .is_some_and(|m| session.handle(&socket, m).unwrap() == Event::Alive)
        })
    });
    assert!(answered);
}

#[test]
fn a_pending_handshake_can_be_abandoned() {
    // Nothing is listening here.
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(silent.local_addr().unwrap()).unwrap();
    let server = Server::start(false);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let started = Instant::now();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        flag.store(true, Ordering::Relaxed);
    });
    let result = Session::connect(&socket, &server.profile(), &stop);
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(started.elapsed() < Duration::from_secs(2));
}
