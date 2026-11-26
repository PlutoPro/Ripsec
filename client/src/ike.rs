//! The IKEv2 initiator: IKE_SA_INIT, the ML-KEM IKE_INTERMEDIATE exchange and IKE_AUTH,
//! then answering the server and checking that it is still there.
//!
//! IKE always runs on the NAT traversal port with the non-ESP marker, and always claims to
//! be behind NAT, so that ESP is carried in UDP and any server port works.

use crate::profile::Profile;
use ripsec_proto::crypto::{self, DH_X25519, DhOffer, KE_ML_KEM_768, KemOffer, Prf};
use ripsec_proto::net::{self, Cidr};
use ripsec_proto::proposal;
use ripsec_proto::secured::{Keys, Reassembly, int_auth, reassemble};
use ripsec_proto::wire::{self, Chain, HEADER_LEN, Header, Payload, be16, exchange, flag, notify, payload};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

/// Precedes IKE messages on the NAT traversal port, where ESP shares the socket.
pub const MARKER: [u8; 4] = [0; 4];
const CFG_REQUEST: u8 = 1;
const CFG_REPLY: u8 = 2;
const ATTR_IP4_ADDRESS: u16 = 1;
const ATTR_IP4_DNS: u16 = 3;
/// Waits between retransmissions of a request.
const RETRY: [u64; 5] = [1, 2, 3, 5, 8];

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// No usable answer. Worth trying again later.
    NoResponse,
    /// The server refused us. Trying again will not help.
    Refused(String),
    /// The server sent something we cannot accept.
    Protocol(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "network error: {e}"),
            Error::NoResponse => write!(f, "no response from the server"),
            Error::Refused(why) => write!(f, "{why}"),
            Error::Protocol(why) => write!(f, "protocol error: {why}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// What the handshake produced for the data plane.
pub struct Child {
    pub spi_out: u32,
    pub spi_in: u32,
    pub key_out: Vec<u8>,
    pub key_in: Vec<u8>,
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// Networks the server carries for us.
    pub routes: Vec<Cidr>,
}

pub struct Session {
    spi_i: u64,
    spi_r: u64,
    keys: Keys,
    frag_ok: bool,
    /// Message ID of our next request.
    next_id: u32,
    /// Message ID expected on the server's next request.
    peer_id: u32,
    last_reply: Vec<Vec<u8>>,
    reassembly: Option<Reassembly>,
    /// Our outstanding liveness check.
    probe: Option<Vec<Vec<u8>>>,
}

/// What an incoming IKE message means for the connection.
#[derive(PartialEq, Debug)]
pub enum Event {
    /// Nothing the data plane needs to know, but the server is alive.
    Alive,
    /// The server closed the connection.
    Closed,
    Ignored,
}

fn send(socket: &UdpSocket, message: &[u8]) -> io::Result<()> {
    socket.send(&[&MARKER[..], message].concat()).map(|_| ())
}

fn message(header: Header, chain: &Chain) -> Vec<u8> {
    let mut header = header;
    header.next = chain.first;
    let mut out = header.encode(HEADER_LEN + chain.bytes.len());
    out.extend_from_slice(&chain.bytes);
    out
}

/// Sends a request until `accept` recognises the answer among what comes back.
fn exchange_with<T>(
    socket: &UdpSocket,
    packets: &[Vec<u8>],
    mut accept: impl FnMut(&[u8]) -> Option<T>,
) -> Result<T, Error> {
    let mut buffer = vec![0u8; 65536];
    for wait in RETRY {
        for packet in packets {
            send(socket, packet)?;
        }
        let deadline = Instant::now() + Duration::from_secs(wait);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            socket.set_read_timeout(Some(left.max(Duration::from_millis(1))))?;
            match socket.recv(&mut buffer) {
                Ok(n) => {
                    if let Some(data) = buffer[..n].strip_prefix(&MARKER)
                        && let Some(answer) = accept(data)
                    {
                        return Ok(answer);
                    }
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
                // ICMP errors, which anyone could have forged. Keep waiting.
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
    Err(Error::NoResponse)
}

fn key_exchange(group: u16, data: &[u8]) -> Vec<u8> {
    [&group.to_be_bytes()[..], &[0, 0], data].concat()
}

fn error_notify(payloads: &[Payload]) -> Option<u16> {
    // Types below 16384 report errors.
    wire::notifies(payloads).map(|n| n.kind).find(|k| *k < 16384)
}

fn refusal(kind: u16) -> Error {
    Error::Refused(match kind {
        notify::AUTHENTICATION_FAILED => {
            "the server rejected this device (revoked, expired or wrong profile)".into()
        }
        notify::NO_PROPOSAL_CHOSEN => "the server does not accept these algorithms".into(),
        notify::TS_UNACCEPTABLE => "the server does not allow the requested networks".into(),
        notify::INTERNAL_ADDRESS_FAILURE => "the server has no free address".into(),
        other => format!("the server refused with error {other}"),
    })
}

fn psk_auth(prf: Prf, secret: &str, octets: &[&[u8]]) -> Vec<u8> {
    let key = prf.run(secret.as_bytes(), &[b"Key Pad for IKEv2"]);
    prf.run(&key, octets)
}

fn identity(id: &str) -> Vec<u8> {
    let kind = if id.contains('@') { 3 } else { 2 };
    [&[kind, 0, 0, 0][..], id.as_bytes()].concat()
}

/// Reads the assigned address and DNS servers from the configuration reply.
fn configuration(body: &[u8]) -> (Option<Ipv4Addr>, Vec<Ipv4Addr>) {
    let (mut address, mut dns) = (None, Vec::new());
    if body.first() != Some(&CFG_REPLY) {
        return (address, dns);
    }
    let mut at = 4;
    while let (Some(kind), Some(len)) = (be16(body, at), be16(body, at + 2)) {
        let Some(value) = body.get(at + 4..at + 4 + usize::from(len)) else { break };
        if let Ok(octets) = <[u8; 4]>::try_from(value) {
            match kind & 0x7fff {
                ATTR_IP4_ADDRESS => address = Some(Ipv4Addr::from(octets)),
                ATTR_IP4_DNS if dns.len() < 4 => dns.push(Ipv4Addr::from(octets)),
                _ => {}
            }
        }
        at += 4 + usize::from(len);
    }
    (address, dns)
}

/// An answer to one of our protected requests.
struct Answer {
    header: Header,
    first: u8,
    plain: Vec<u8>,
}

impl Session {
    fn header(&self, exchange: u8, flags: u8, msg_id: u32) -> Header {
        Header { spi_i: self.spi_i, spi_r: self.spi_r, next: 0, exchange, flags, msg_id }
    }

    fn request(&mut self, socket: &UdpSocket, exchange: u8, chain: &Chain) -> Result<Answer, Error> {
        let header = self.header(exchange, flag::INITIATOR, self.next_id);
        let packets = self.keys.seal(header, chain.first, &chain.bytes, self.frag_ok);
        let (keys, mut fragments) = (&self.keys, None);
        let answer = exchange_with(socket, &packets, |data| {
            let h = Header::parse(data)?;
            let ours = h.spi_i == header.spi_i
                && h.spi_r == header.spi_r
                && h.msg_id == header.msg_id
                && h.exchange == exchange
                && h.flags & flag::RESPONSE != 0;
            if !ours {
                return None;
            }
            let (first, plain) = reassemble(&mut fragments, h.msg_id, keys.open(data)?)?;
            Some(Answer { header: h, first, plain })
        })?;
        self.next_id += 1;
        Ok(answer)
    }

    /// Runs the three exchanges. `socket` must be connected to the server.
    pub fn connect(socket: &UdpSocket, profile: &Profile) -> Result<(Session, Child), Error> {
        let server = match socket.peer_addr()? {
            std::net::SocketAddr::V4(v4) => v4,
            _ => return Err(Error::Protocol("only IPv4 servers are supported")),
        };
        let unavailable = Error::Protocol("cryptography unavailable");
        let spi_i = loop {
            let spi = u64::from_be_bytes(crypto::random());
            if spi != 0 {
                break spi;
            }
        };
        let ni = crypto::random::<32>().to_vec();
        let dh = DhOffer::x25519().ok_or(unavailable)?;

        // IKE_SA_INIT, once more with a cookie if the server asks for one.
        let mut cookie: Option<Vec<u8>> = None;
        let (request, response, reply_header) = loop {
            let mut chain = Chain::default();
            if let Some(cookie) = &cookie {
                chain.notify(notify::COOKIE, cookie);
            }
            chain.push(payload::SA, &proposal::offer_ike());
            chain.push(payload::KE, &key_exchange(DH_X25519, &dh.public));
            chain.push(payload::NONCE, &ni);
            // A source hash that cannot match makes the server use UDP encapsulation.
            chain.notify(notify::NAT_DETECTION_SOURCE_IP, &crypto::random::<20>());
            let destination = crypto::sha1(&[
                &spi_i.to_be_bytes(),
                &[0; 8],
                &server.ip().octets(),
                &server.port().to_be_bytes(),
            ]);
            chain.notify(notify::NAT_DETECTION_DESTINATION_IP, &destination);
            chain.notify(notify::FRAGMENTATION_SUPPORTED, &[]);
            chain.notify(notify::INTERMEDIATE_EXCHANGE_SUPPORTED, &[]);
            let header = Header {
                spi_i,
                spi_r: 0,
                next: 0,
                exchange: exchange::SA_INIT,
                flags: flag::INITIATOR,
                msg_id: 0,
            };
            let request = message(header, &chain);
            let (response, h) = exchange_with(socket, std::slice::from_ref(&request), |data| {
                let h = Header::parse(data)?;
                let ours = h.spi_i == spi_i
                    && h.msg_id == 0
                    && h.exchange == exchange::SA_INIT
                    && h.flags & flag::RESPONSE != 0;
                ours.then(|| (data.to_vec(), h))
            })?;
            let payloads = wire::parse_payloads(h.next, &response[HEADER_LEN..])
                .map_err(|_| Error::Protocol("malformed IKE_SA_INIT response"))?;
            if let Some(n) = wire::notifies(&payloads).find(|n| n.kind == notify::COOKIE) {
                if cookie.is_some() {
                    return Err(Error::Protocol("the server asked for a second cookie"));
                }
                cookie = Some(n.data.to_vec());
                continue;
            }
            if let Some(kind) = error_notify(&payloads) {
                return Err(refusal(kind));
            }
            break (request, response, h);
        };

        let payloads = wire::parse_payloads(reply_header.next, &response[HEADER_LEN..])
            .map_err(|_| Error::Protocol("malformed IKE_SA_INIT response"))?;
        let (Some(sa), Some(ke), Some(nr)) = (
            wire::find(&payloads, payload::SA).and_then(proposal::parse_sa),
            wire::find(&payloads, payload::KE),
            wire::find(&payloads, payload::NONCE),
        ) else {
            return Err(Error::Protocol("incomplete IKE_SA_INIT response"));
        };
        let has = |kind| wire::notifies(&payloads).any(|n| n.kind == kind);
        // No fallback: the server must have accepted exactly the post-quantum offer.
        let suite = proposal::select_ike(&sa, Some(DH_X25519), true, true)
            .filter(|s| s.dh == Some(DH_X25519) && s.pq == Some(KE_ML_KEM_768))
            .filter(|s| s.key_bits == 256 && s.prf == Prf::Sha384)
            .filter(|_| has(notify::INTERMEDIATE_EXCHANGE_SUPPORTED))
            .ok_or(Error::Protocol("the server did not accept post-quantum key exchange"))?;
        let nr = nr.to_vec();
        let spi_r = reply_header.spi_r;
        if spi_r == 0 || !(16..=256).contains(&nr.len()) || be16(ke, 0) != Some(DH_X25519) {
            return Err(Error::Protocol("invalid IKE_SA_INIT response"));
        }
        let shared =
            ke.get(4..).and_then(|k| dh.agree(k)).ok_or(Error::Protocol("invalid key exchange value"))?;
        let prf = suite.prf;
        let skeyseed = prf.run(&[ni.as_slice(), &nr].concat(), &[&shared]);
        let derive = |skeyseed: &[u8]| {
            Keys::derive(prf, suite.key_len(), skeyseed, &ni, &nr, spi_i, spi_r)
                .map(Keys::into_initiator)
                .ok_or(Error::Protocol("key derivation failed"))
        };
        let mut session = Session {
            spi_i,
            spi_r,
            keys: derive(&skeyseed)?,
            frag_ok: has(notify::FRAGMENTATION_SUPPORTED),
            next_id: 1,
            peer_id: 0,
            last_reply: Vec::new(),
            reassembly: None,
            probe: None,
        };

        // IKE_INTERMEDIATE carries ML-KEM and is authenticated later by IKE_AUTH.
        let kem = KemOffer::ml_kem_768().ok_or(Error::Protocol("cryptography unavailable"))?;
        let mut chain = Chain::default();
        chain.push(payload::KE, &key_exchange(KE_ML_KEM_768, &kem.public));
        let sent_header = session.header(exchange::INTERMEDIATE, flag::INITIATOR, session.next_id);
        let ours = int_auth(prf, &session.keys.pi, sent_header, chain.first, &chain.bytes);
        let answer = session.request(socket, exchange::INTERMEDIATE, &chain)?;
        let theirs = int_auth(prf, &session.keys.pr, answer.header, answer.first, &answer.plain);
        let payloads = wire::parse_payloads(answer.first, &answer.plain)
            .map_err(|_| Error::Protocol("malformed IKE_INTERMEDIATE response"))?;
        if let Some(kind) = error_notify(&payloads) {
            return Err(refusal(kind));
        }
        let shared = wire::find(&payloads, payload::KE)
            .filter(|ke| be16(ke, 0) == Some(KE_ML_KEM_768))
            .and_then(|ke| kem.decapsulate(ke.get(4..)?))
            .ok_or(Error::Protocol("invalid ML-KEM response"))?;
        let skeyseed = prf.run(&session.keys.d, &[&shared, &ni, &nr]);
        session.keys = derive(&skeyseed)?;

        // IKE_AUTH.
        let auth_id = session.next_id;
        let intermediate = [ours.as_slice(), &theirs, &auth_id.to_be_bytes()].concat();
        let idi = identity(&profile.id);
        let signed_id = prf.run(&session.keys.pi, &[&idi]);
        let auth = psk_auth(prf, &profile.secret, &[&request, &nr, &signed_id, &intermediate]);
        let spi_in = loop {
            let spi = u32::from_be_bytes(crypto::random());
            if spi > 0xff {
                break spi;
            }
        };
        let any = [Cidr::new(Ipv4Addr::UNSPECIFIED, 0).ok_or(Error::Protocol("internal error"))?];
        let mut chain = Chain::default();
        chain.push(payload::IDI, &idi);
        chain.push(payload::AUTH, &[&[2, 0, 0, 0][..], &auth].concat());
        let mut cp = vec![CFG_REQUEST, 0, 0, 0];
        for attribute in [ATTR_IP4_ADDRESS, ATTR_IP4_DNS] {
            cp.extend_from_slice(&attribute.to_be_bytes());
            cp.extend_from_slice(&[0, 0]);
        }
        chain.push(payload::CP, &cp);
        chain.push(payload::SA, &proposal::offer_esp(spi_in));
        chain.push(payload::TSI, &net::encode_ts(&any));
        chain.push(payload::TSR, &net::encode_ts(&profile.routes));
        let answer = session.request(socket, exchange::AUTH, &chain)?;
        let payloads = wire::parse_payloads(answer.first, &answer.plain)
            .map_err(|_| Error::Protocol("malformed IKE_AUTH response"))?;

        let (Some(idr), Some(auth)) =
            (wire::find(&payloads, payload::IDR), wire::find(&payloads, payload::AUTH))
        else {
            return Err(error_notify(&payloads).map_or(Error::Protocol("no authentication"), refusal));
        };
        // The server proves it holds the same secret, and is who the profile says.
        let signed_id = prf.run(&session.keys.pr, &[idr]);
        let expected = psk_auth(prf, &profile.secret, &[&response, &ni, &signed_id, &intermediate]);
        let proven = auth.len() > 4 && auth[0] == 2 && crypto::ct_eq(&expected, &auth[4..]);
        if !proven || idr.get(4..) != Some(profile.server_id.as_bytes()) {
            return Err(Error::Refused("the server could not prove its identity".into()));
        }
        if let Some(kind) = error_notify(&payloads) {
            return Err(refusal(kind));
        }

        let (address, dns) =
            wire::find(&payloads, payload::CP).map(configuration).unwrap_or((None, Vec::new()));
        let address = address.ok_or(Error::Protocol("the server assigned no address"))?;
        let esp = wire::find(&payloads, payload::SA)
            .and_then(proposal::parse_sa)
            .and_then(|p| proposal::select_esp(&p, None))
            .filter(|s| s.key_bits == 256 && s.esn)
            .ok_or(Error::Protocol("no acceptable ESP proposal"))?;
        let spi_out = esp
            .peer_spi
            .as_slice()
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| Error::Protocol("invalid ESP SPI"))?;
        let ranges = wire::find(&payloads, payload::TSR)
            .and_then(net::parse_ts)
            .ok_or(Error::Protocol("no traffic selectors"))?;
        // Never route more than the profile asked for, whatever the server answers.
        let routes = net::narrow(&ranges, &profile.routes);
        if routes.is_empty() {
            return Err(Error::Protocol("the server allows none of the profile's networks"));
        }
        let len = esp.key_len();
        let mut key_out = prf.plus(&session.keys.d, &[&ni, &nr], 2 * len);
        let key_in = key_out.split_off(len);
        session.next_id = auth_id + 1;
        Ok((session, Child { spi_out, spi_in, key_out, key_in, address, dns, routes }))
    }

    /// Handles an IKE message that arrived outside the handshake.
    pub fn handle(&mut self, socket: &UdpSocket, data: &[u8]) -> io::Result<Event> {
        let Some(header) = Header::parse(data) else { return Ok(Event::Ignored) };
        if header.spi_i != self.spi_i || header.spi_r != self.spi_r || header.flags & flag::INITIATOR != 0 {
            return Ok(Event::Ignored);
        }
        let Some(opened) = self.keys.open(data) else { return Ok(Event::Ignored) };

        if header.flags & flag::RESPONSE != 0 {
            if header.msg_id.wrapping_add(1) != self.next_id || self.probe.is_none() {
                return Ok(Event::Ignored);
            }
            self.probe = None;
            return Ok(Event::Alive);
        }
        if header.msg_id.wrapping_add(1) == self.peer_id {
            if opened.fragment.is_none_or(|(n, _)| n == 1) {
                for packet in &self.last_reply {
                    send(socket, packet)?;
                }
            }
            return Ok(Event::Alive);
        }
        if header.msg_id != self.peer_id {
            return Ok(Event::Ignored);
        }
        let Some((first, plain)) = reassemble(&mut self.reassembly, header.msg_id, opened) else {
            return Ok(Event::Ignored);
        };
        let payloads = wire::parse_payloads(first, &plain).unwrap_or_default();
        let closed =
            payloads.iter().any(|p| p.kind == payload::DELETE && p.body.first() == Some(&wire::PROTO_IKE));
        let mut chain = Chain::default();
        if header.exchange != exchange::INFORMATIONAL {
            // The client does the rekeying, and the server never starts one.
            chain.notify(notify::NO_PROPOSAL_CHOSEN, &[]);
        }
        let reply = self.header(header.exchange, flag::INITIATOR | flag::RESPONSE, header.msg_id);
        self.last_reply = self.keys.seal(reply, chain.first, &chain.bytes, self.frag_ok);
        self.peer_id = self.peer_id.wrapping_add(1);
        for packet in &self.last_reply {
            send(socket, packet)?;
        }
        Ok(if closed { Event::Closed } else { Event::Alive })
    }

    /// Sends, or resends, an empty request that the server must answer.
    pub fn probe(&mut self, socket: &UdpSocket) -> io::Result<()> {
        if self.probe.is_none() {
            let header = self.header(exchange::INFORMATIONAL, flag::INITIATOR, self.next_id);
            self.next_id = self.next_id.wrapping_add(1);
            self.probe = Some(self.keys.seal(header, 0, &[], false));
        }
        for packet in self.probe.iter().flatten() {
            send(socket, packet)?;
        }
        Ok(())
    }

    /// Tells the server we are leaving, so it removes the session at once. Best effort:
    /// if the message is lost the server notices through its own liveness check.
    pub fn close(&mut self, socket: &UdpSocket) {
        let mut chain = Chain::default();
        chain.push(payload::DELETE, &[wire::PROTO_IKE, 0, 0, 0]);
        if let Err(e) = self.request(socket, exchange::INFORMATIONAL, &chain) {
            eprintln!("could not tell the server we left: {e}");
        }
    }
}
