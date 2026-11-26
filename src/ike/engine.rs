//! SA table, message dispatch, the initial exchanges and liveness.

use super::child::Followup;
use super::crypto::{self, Prf};
use super::proposal::{self, Suite};
use super::secured::{Keys, Reassembly, int_auth, reassemble, response_header};
use super::wire::{self, Chain, HEADER_LEN, Header, Payload, be16, exchange, flag, notify, payload};
use crate::config::Vpn;
use crate::dataplane::{Child, Dataplane};
use crate::store::{Device, Store};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Above this many unfinished handshakes, initiators must echo a cookie.
const COOKIE_THRESHOLD: usize = 32;
const MAX_HALF_OPEN: usize = 512;
const MAX_SAS: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const RETIRED_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_BEFORE_PROBE: Duration = Duration::from_secs(30);
const MAX_PROBES: u32 = 5;

pub struct Outgoing {
    pub data: Vec<u8>,
    pub to: SocketAddrV4,
    /// 500 or 4500.
    pub local_port: u16,
}

#[derive(Serialize, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub owner: String,
    pub owner_name: String,
    pub peer: String,
    pub virtual_ip: Option<Ipv4Addr>,
    pub post_quantum: bool,
    pub connected_seconds: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// State needed only until the peer is authenticated.
pub(super) struct Handshake {
    init_request: Vec<u8>,
    init_response: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    pq_pending: Option<u16>,
    /// IntAuth of the initiator and responder IKE_INTERMEDIATE messages.
    int_auth: Option<(Vec<u8>, Vec<u8>)>,
}

pub(super) enum State {
    Handshake(Box<Handshake>),
    Established,
    /// Replaced by a rekeyed SA and waiting for the peer to delete it.
    Retired,
}

struct Probe {
    packets: Vec<Vec<u8>>,
    sent: Instant,
    tries: u32,
}

pub(super) struct Sa {
    pub spi_i: u64,
    pub spi_r: u64,
    pub peer: SocketAddrV4,
    pub local_port: u16,
    pub suite: Suite,
    pub keys: Keys,
    pub state: State,
    pub post_quantum: bool,
    pub frag_ok: bool,
    pub nat: bool,
    /// Next request ID expected from the peer.
    pub recv_id: u32,
    /// Next request ID we will use.
    send_id: u32,
    last_reply: Vec<Vec<u8>>,
    /// The keys the last request arrived under, if answering it changed them.
    superseded: Option<Keys>,
    reassembly: Option<Reassembly>,
    pub created: Instant,
    pub last_seen: Instant,
    last_bytes: u64,
    probe: Option<Probe>,
    pub device_id: String,
    pub virtual_ip: Option<Ipv4Addr>,
    pub children: Vec<Child>,
    pub followup: Option<Followup>,
}

impl Sa {
    pub fn new(
        spi_i: u64,
        spi_r: u64,
        peer: SocketAddrV4,
        local_port: u16,
        suite: Suite,
        keys: Keys,
        state: State,
    ) -> Sa {
        let now = Instant::now();
        Sa {
            spi_i,
            spi_r,
            peer,
            local_port,
            suite,
            keys,
            state,
            post_quantum: false,
            frag_ok: false,
            nat: false,
            recv_id: 0,
            send_id: 0,
            last_reply: Vec::new(),
            superseded: None,
            reassembly: None,
            created: now,
            last_seen: now,
            last_bytes: 0,
            probe: None,
            device_id: String::new(),
            virtual_ip: None,
            children: Vec::new(),
            followup: None,
        }
    }

    fn to_peer(&self, data: Vec<u8>) -> Outgoing {
        Outgoing { data, to: self.peer, local_port: self.local_port }
    }

    /// Encrypts a request of our own. We are always the responder of the IKE SA.
    fn request(&mut self, exchange: u8, chain: &Chain) -> Vec<Vec<u8>> {
        let header = Header {
            spi_i: self.spi_i,
            spi_r: self.spi_r,
            next: 0,
            exchange,
            flags: 0,
            msg_id: self.send_id,
        };
        self.send_id += 1;
        self.keys.seal(header, chain.first, &chain.bytes, self.frag_ok)
    }
}

/// What a request handler wants done with the response.
pub(super) struct Reply {
    pub chain: Chain,
    pub close: bool,
    /// Keys to switch to once the response has been encrypted with the old ones.
    pub next_keys: Option<Keys>,
}

impl Reply {
    pub fn ok(chain: Chain) -> Reply {
        Reply { chain, close: false, next_keys: None }
    }

    pub fn error(kind: u16, data: &[u8]) -> Reply {
        let mut chain = Chain::default();
        chain.notify(kind, data);
        Reply::ok(chain)
    }

    pub fn fatal(kind: u16) -> Reply {
        Reply { close: true, ..Reply::error(kind, &[]) }
    }
}

pub struct Engine<D> {
    pub(super) config: Vpn,
    pub(super) dataplane: D,
    pub(super) store: Arc<Mutex<Store>>,
    pub(super) sas: HashMap<u64, Sa>,
    cookie_secret: [u8; 32],
    pub(super) next_reqid: u32,
}

fn nat_hash(spi_i: u64, spi_r: u64, addr: SocketAddrV4) -> Vec<u8> {
    crypto::sha1(&[
        &spi_i.to_be_bytes(),
        &spi_r.to_be_bytes(),
        &addr.ip().octets(),
        &addr.port().to_be_bytes(),
    ])
}

/// The authentication data for shared key authentication (RFC 7296 section 2.15).
fn psk_auth(prf: Prf, secret: &str, octets: &[&[u8]]) -> Vec<u8> {
    let key = prf.run(secret.as_bytes(), &[b"Key Pad for IKEv2"]);
    prf.run(&key, octets)
}

fn nonce_ok(n: &[u8]) -> bool {
    (16..=256).contains(&n.len())
}

impl<D: Dataplane> Engine<D> {
    pub fn new(config: Vpn, dataplane: D, store: Arc<Mutex<Store>>) -> Engine<D> {
        let reqid = u32::from_be_bytes(crypto::random());
        Engine {
            config,
            dataplane,
            store,
            sas: HashMap::new(),
            cookie_secret: crypto::random(),
            next_reqid: (reqid & 0x0fff_ffff) | 0x1000_0000,
        }
    }

    pub(super) fn device(&self, id: &str) -> Option<Device> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.find(id.as_bytes()).filter(|d| d.active() && !d.secret.is_empty()).cloned()
    }

    pub(super) fn new_spi(&self) -> u64 {
        loop {
            let spi = u64::from_be_bytes(crypto::random());
            if spi != 0 && !self.sas.contains_key(&spi) {
                return spi;
            }
        }
    }

    /// Handles one IKE message (the non-ESP marker already removed).
    pub fn handle(&mut self, data: &[u8], from: SocketAddrV4, local_port: u16) -> Vec<Outgoing> {
        let Some(header) = Header::parse(data) else { return Vec::new() };
        if header.flags & flag::INITIATOR == 0 {
            return Vec::new();
        }
        if header.exchange == exchange::SA_INIT {
            return self.sa_init(header, data, from, local_port);
        }
        // Take the SA out of the table so handlers can borrow the engine freely.
        let Some(mut sa) = self.sas.remove(&header.spi_r) else { return Vec::new() };
        let mut out = Vec::new();
        let keep = if sa.spi_i == header.spi_i {
            self.secured(&mut sa, header, data, from, local_port, &mut out)
        } else {
            true
        };
        if keep {
            self.sas.insert(sa.spi_r, sa);
        } else {
            self.teardown(&mut sa);
        }
        out
    }

    fn secured(
        &mut self,
        sa: &mut Sa,
        header: Header,
        data: &[u8],
        from: SocketAddrV4,
        local_port: u16,
        out: &mut Vec<Outgoing>,
    ) -> bool {
        // Nothing is trusted, including the source address, before the integrity check.
        let Some(opened) = sa.keys.open(data) else {
            // IKE_INTERMEDIATE changes the keys, but if our response was lost the peer
            // repeats its request under the old ones (RFC 9242).
            let repeated = header.flags & flag::RESPONSE == 0
                && header.msg_id.wrapping_add(1) == sa.recv_id
                && sa
                    .superseded
                    .as_ref()
                    .and_then(|keys| keys.open(data))
                    .is_some_and(|o| o.fragment.is_none_or(|(n, _)| n == 1));
            if repeated {
                out.extend(sa.last_reply.iter().map(|p| Outgoing { data: p.clone(), to: from, local_port }));
            }
            return true;
        };

        if header.flags & flag::RESPONSE != 0 {
            if header.msg_id.wrapping_add(1) == sa.send_id {
                sa.probe = None;
                sa.last_seen = Instant::now();
            }
            return true;
        }
        if header.msg_id.wrapping_add(1) == sa.recv_id {
            // Retransmitted request: repeat the answer, once per message.
            if opened.fragment.is_none_or(|(n, _)| n == 1) {
                out.extend(sa.last_reply.iter().map(|p| Outgoing { data: p.clone(), to: from, local_port }));
            }
            return true;
        }
        if header.msg_id != sa.recv_id {
            return true;
        }
        let Some((first, plain)) = reassemble(&mut sa.reassembly, header.msg_id, opened) else {
            return true;
        };
        sa.peer = from;
        sa.local_port = local_port;
        sa.last_seen = Instant::now();

        let reply = match wire::parse_payloads(first, &plain) {
            Err(wire::ParseError::UnsupportedCritical(kind)) => {
                Some(Reply::error(notify::UNSUPPORTED_CRITICAL_PAYLOAD, &[kind]))
            }
            Err(wire::ParseError::Syntax) => Some(Reply::fatal(notify::INVALID_SYNTAX)),
            Ok(payloads) => match (&sa.state, header.exchange) {
                (State::Handshake(h), exchange::INTERMEDIATE) if h.pq_pending.is_some() => {
                    self.intermediate(sa, header, first, &plain, &payloads)
                }
                (State::Handshake(h), exchange::AUTH) if h.pq_pending.is_none() => {
                    Some(self.auth(sa, header, &payloads, out))
                }
                (State::Established, exchange::CREATE_CHILD_SA) => Some(self.create_child(sa, &payloads)),
                (State::Established, exchange::FOLLOWUP_KE) => Some(self.followup(sa, &payloads)),
                (State::Established | State::Retired, exchange::INFORMATIONAL) => {
                    Some(self.informational(sa, &payloads))
                }
                _ => None,
            },
        };
        let Some(reply) = reply else { return true };
        let rh = response_header(sa.spi_i, sa.spi_r, header.exchange, header.msg_id);
        sa.last_reply = sa.keys.seal(rh, reply.chain.first, &reply.chain.bytes, sa.frag_ok);
        sa.recv_id = sa.recv_id.wrapping_add(1);
        out.extend(sa.last_reply.iter().map(|p| sa.to_peer(p.clone())));
        sa.superseded = reply.next_keys.map(|keys| std::mem::replace(&mut sa.keys, keys));
        !reply.close
    }

    fn sa_init(&mut self, header: Header, data: &[u8], from: SocketAddrV4, local_port: u16) -> Vec<Outgoing> {
        if header.spi_r != 0 || header.msg_id != 0 || header.flags & flag::RESPONSE != 0 {
            return Vec::new();
        }
        // Retransmission of a request we already answered.
        let mut half_open = 0;
        for sa in self.sas.values() {
            if let State::Handshake(h) = &sa.state {
                half_open += 1;
                if sa.spi_i == header.spi_i && h.init_request == data {
                    return vec![Outgoing { data: h.init_response.clone(), to: from, local_port }];
                }
            }
        }
        let unprotected = |kind: u16, value: &[u8]| {
            let mut chain = Chain::default();
            chain.notify(kind, value);
            let mut rh = response_header(header.spi_i, 0, exchange::SA_INIT, 0);
            rh.next = chain.first;
            let mut msg = rh.encode(HEADER_LEN + chain.bytes.len());
            msg.extend(chain.bytes);
            vec![Outgoing { data: msg, to: from, local_port }]
        };
        if half_open >= MAX_HALF_OPEN || self.sas.len() >= MAX_SAS {
            return Vec::new();
        }
        let payloads = match wire::parse_payloads(header.next, &data[HEADER_LEN..]) {
            Ok(p) => p,
            Err(wire::ParseError::UnsupportedCritical(k)) => {
                return unprotected(notify::UNSUPPORTED_CRITICAL_PAYLOAD, &[k]);
            }
            Err(_) => return Vec::new(),
        };
        let (Some(sa_body), Some(ke), Some(ni)) = (
            wire::find(&payloads, payload::SA),
            wire::find(&payloads, payload::KE),
            wire::find(&payloads, payload::NONCE),
        ) else {
            return Vec::new();
        };
        if !nonce_ok(ni) {
            return Vec::new();
        }
        if half_open >= COOKIE_THRESHOLD {
            let cookie =
                Prf::Sha256.run(&self.cookie_secret, &[ni, &from.ip().octets(), &header.spi_i.to_be_bytes()]);
            let echoed = wire::notifies(&payloads).find(|n| n.kind == notify::COOKIE);
            if !echoed.is_some_and(|n| crypto::ct_eq(n.data, &cookie)) {
                return unprotected(notify::COOKIE, &cookie);
            }
        }
        let (Some(group), Some(peer_public), Some(proposals)) =
            (be16(ke, 0), ke.get(4..), proposal::parse_sa(sa_body))
        else {
            return Vec::new();
        };
        let has = |kind| wire::notifies(&payloads).any(|n| n.kind == kind);
        let intermediate_ok = has(notify::INTERMEDIATE_EXCHANGE_SUPPORTED);
        let frag_ok = has(notify::FRAGMENTATION_SUPPORTED);
        let Some(suite) =
            proposal::select_ike(&proposals, Some(group), intermediate_ok, self.config.require_pq)
        else {
            eprintln!("{from}: no acceptable IKE proposal (require_post_quantum={})", self.config.require_pq);
            return unprotected(notify::NO_PROPOSAL_CHOSEN, &[]);
        };
        let Some(dh) = suite.dh else { return Vec::new() };
        if dh != group {
            return unprotected(notify::INVALID_KE_PAYLOAD, &dh.to_be_bytes());
        }
        let Some((public, shared)) = crypto::dh_respond(group, peer_public) else { return Vec::new() };

        let spi_i = header.spi_i;
        let spi_r = self.new_spi();
        let nr = crypto::random::<32>().to_vec();
        let skeyseed = suite.prf.run(&[ni, &nr].concat(), &[&shared]);
        let Some(keys) = Keys::derive(suite.prf, suite.key_len(), &skeyseed, ni, &nr, spi_i, spi_r) else {
            return Vec::new();
        };

        let local = SocketAddrV4::new(self.config.local_ip, local_port);
        let sources: Vec<&[u8]> = wire::notifies(&payloads)
            .filter(|n| n.kind == notify::NAT_DETECTION_SOURCE_IP)
            .map(|n| n.data)
            .collect();
        let peer_natted = !sources.is_empty() && !sources.contains(&nat_hash(spi_i, 0, from).as_slice());
        let we_are_natted = wire::notifies(&payloads)
            .any(|n| n.kind == notify::NAT_DETECTION_DESTINATION_IP && n.data != nat_hash(spi_i, 0, local));

        let mut chain = Chain::default();
        chain.push(payload::SA, &suite.encode(wire::PROTO_IKE, &[]));
        let mut ke_reply = group.to_be_bytes().to_vec();
        ke_reply.extend_from_slice(&[0, 0]);
        ke_reply.extend(public);
        chain.push(payload::KE, &ke_reply);
        chain.push(payload::NONCE, &nr);
        if !sources.is_empty() {
            chain.notify(notify::NAT_DETECTION_SOURCE_IP, &nat_hash(spi_i, spi_r, local));
            chain.notify(notify::NAT_DETECTION_DESTINATION_IP, &nat_hash(spi_i, spi_r, from));
        }
        if frag_ok {
            chain.notify(notify::FRAGMENTATION_SUPPORTED, &[]);
        }
        if suite.pq.is_some() {
            chain.notify(notify::INTERMEDIATE_EXCHANGE_SUPPORTED, &[]);
        }
        let mut rh = response_header(spi_i, spi_r, exchange::SA_INIT, 0);
        rh.next = chain.first;
        let mut response = rh.encode(HEADER_LEN + chain.bytes.len());
        response.extend(chain.bytes);

        let handshake = Handshake {
            init_request: data.to_vec(),
            init_response: response.clone(),
            ni: ni.to_vec(),
            nr,
            pq_pending: suite.pq,
            int_auth: None,
        };
        let mut sa =
            Sa::new(spi_i, spi_r, from, local_port, suite, keys, State::Handshake(Box::new(handshake)));
        sa.recv_id = 1;
        sa.frag_ok = frag_ok;
        sa.nat = peer_natted || we_are_natted;
        self.sas.insert(spi_r, sa);
        vec![Outgoing { data: response, to: from, local_port }]
    }

    /// The ML-KEM exchange. Everything after it is protected by the hybrid keys.
    fn intermediate(
        &mut self,
        sa: &mut Sa,
        header: Header,
        first: u8,
        plain: &[u8],
        payloads: &[Payload],
    ) -> Option<Reply> {
        let (prf, key_len, spi_i, spi_r) = (sa.keys.prf, sa.suite.key_len(), sa.spi_i, sa.spi_r);
        let State::Handshake(h) = &mut sa.state else { return None };
        let method = h.pq_pending?;
        let ke = wire::find(payloads, payload::KE)?;
        if be16(ke, 0)? != method {
            return Some(Reply::fatal(notify::INVALID_SYNTAX));
        }
        let Some((ciphertext, shared)) = crypto::kem_respond(method, ke.get(4..)?) else {
            return Some(Reply::fatal(notify::INVALID_SYNTAX));
        };
        let mut chain = Chain::default();
        let mut body = method.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0]);
        body.extend(ciphertext);
        chain.push(payload::KE, &body);

        // IntAuth uses the keys that protect this exchange, before the update.
        let rh = response_header(spi_i, spi_r, header.exchange, header.msg_id);
        h.int_auth = Some((
            int_auth(prf, &sa.keys.pi, header, first, plain),
            int_auth(prf, &sa.keys.pr, rh, chain.first, &chain.bytes),
        ));
        h.pq_pending = None;
        let skeyseed = prf.run(&sa.keys.d, &[&shared, &h.ni, &h.nr]);
        let next = Keys::derive(prf, key_len, &skeyseed, &h.ni, &h.nr, spi_i, spi_r)?;
        sa.post_quantum = true;
        Some(Reply { chain, close: false, next_keys: Some(next) })
    }

    fn auth(&mut self, sa: &mut Sa, header: Header, payloads: &[Payload], out: &mut Vec<Outgoing>) -> Reply {
        let failed = || Reply::fatal(notify::AUTHENTICATION_FAILED);
        let State::Handshake(h) = &sa.state else { return failed() };
        let (Some(idi), Some(auth)) =
            (wire::find(payloads, payload::IDI), wire::find(payloads, payload::AUTH))
        else {
            return failed();
        };
        // Shared key message integrity code is the only method offered so far.
        if idi.len() < 5 || auth.len() < 5 || auth[0] != 2 {
            eprintln!("{}: unsupported authentication method", sa.peer);
            return failed();
        }
        let identity = String::from_utf8_lossy(&idi[4..]).into_owned();
        let Some(device) = self.device(&identity) else {
            eprintln!("{}: unknown or expired identity {identity:?}", sa.peer);
            return failed();
        };
        let prf = sa.keys.prf;
        let int_auth = h
            .int_auth
            .as_ref()
            .map_or_else(Vec::new, |(i, r)| [i.as_slice(), r, &header.msg_id.to_be_bytes()].concat());
        let signed_id = prf.run(&sa.keys.pi, &[idi]);
        let expected = psk_auth(prf, &device.secret, &[&h.init_request, &h.nr, &signed_id, &int_auth]);
        if !crypto::ct_eq(&expected, &auth[4..]) {
            eprintln!("{}: authentication failed for {identity}", sa.peer);
            return failed();
        }

        let id_type = if self.config.server_id.contains('@') { 3 } else { 2 };
        let mut idr = vec![id_type, 0, 0, 0];
        idr.extend_from_slice(self.config.server_id.as_bytes());
        let signed_id = prf.run(&sa.keys.pr, &[&idr]);
        let ours = psk_auth(prf, &device.secret, &[&h.init_response, &h.ni, &signed_id, &int_auth]);
        let (ni, nr) = (h.ni.clone(), h.nr.clone());

        // One live session per credential, which also keeps kernel policies unambiguous.
        let stale: Vec<u64> =
            self.sas.values().filter(|s| s.device_id == device.id).map(|s| s.spi_r).collect();
        for spi in stale {
            out.extend(self.disconnect(spi));
        }

        sa.device_id = device.id.clone();
        sa.state = State::Established;
        sa.send_id = 0;

        let mut chain = Chain::default();
        chain.push(payload::IDR, &idr);
        let mut auth_body = vec![2, 0, 0, 0];
        auth_body.extend(ours);
        chain.push(payload::AUTH, &auth_body);
        self.first_child(sa, &device, payloads, &ni, &nr, &mut chain);
        eprintln!("{}: {} ({}) connected, post-quantum={}", sa.peer, device.name, device.id, sa.post_quantum);
        Reply::ok(chain)
    }

    fn informational(&mut self, sa: &mut Sa, payloads: &[Payload]) -> Reply {
        let mut deleted_ours = Vec::new();
        for p in payloads.iter().filter(|p| p.kind == payload::DELETE) {
            let (Some(&protocol), Some(&size), Some(count)) =
                (p.body.first(), p.body.get(1), be16(p.body, 2))
            else {
                continue;
            };
            if protocol == wire::PROTO_IKE {
                // A rekeyed SA being cleaned up is not a disconnect.
                if matches!(sa.state, State::Established) {
                    eprintln!("{}: {} disconnected", sa.peer, sa.device_id);
                }
                return Reply { close: true, ..Reply::ok(Chain::default()) };
            }
            if protocol == wire::PROTO_ESP && size == 4 {
                for spi in p.body[4..].as_chunks::<4>().0.iter().take(usize::from(count)) {
                    let spi = u32::from_be_bytes(*spi);
                    if let Some(i) = sa.children.iter().position(|c| c.spi_out == spi) {
                        let child = sa.children.remove(i);
                        let last = !sa.children.iter().any(|c| c.reqid == child.reqid);
                        self.dataplane.remove(&child, last);
                        deleted_ours.push(child.spi_in);
                    }
                }
            }
        }
        let mut chain = Chain::default();
        if !deleted_ours.is_empty() {
            let mut body = vec![wire::PROTO_ESP, 4];
            body.extend_from_slice(&(deleted_ours.len() as u16).to_be_bytes());
            deleted_ours.iter().for_each(|s| body.extend_from_slice(&s.to_be_bytes()));
            chain.push(payload::DELETE, &body);
        }
        Reply::ok(chain)
    }

    fn teardown(&mut self, sa: &mut Sa) {
        while let Some(child) = sa.children.pop() {
            let last = !sa.children.iter().any(|c| c.reqid == child.reqid);
            self.dataplane.remove(&child, last);
        }
    }

    /// Drops a session, telling the peer on a best effort basis.
    pub fn disconnect(&mut self, spi_r: u64) -> Vec<Outgoing> {
        let Some(mut sa) = self.sas.remove(&spi_r) else { return Vec::new() };
        self.teardown(&mut sa);
        if !matches!(sa.state, State::Established) {
            return Vec::new();
        }
        let mut chain = Chain::default();
        chain.push(payload::DELETE, &[wire::PROTO_IKE, 0, 0, 0]);
        let packets = sa.request(exchange::INFORMATIONAL, &chain);
        packets.into_iter().map(|p| sa.to_peer(p)).collect()
    }

    pub fn shutdown(&mut self) -> Vec<Outgoing> {
        let all: Vec<u64> = self.sas.keys().copied().collect();
        all.into_iter().flat_map(|spi| self.disconnect(spi)).collect()
    }

    /// Periodic work: expiry, revocation and dead peer detection.
    pub fn tick(&mut self, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let ids: Vec<u64> = self.sas.keys().copied().collect();
        for id in ids {
            let Some(mut sa) = self.sas.remove(&id) else { continue };
            let age = |t: Instant| now.saturating_duration_since(t);
            let keep = match sa.state {
                State::Handshake(_) => age(sa.created) < HANDSHAKE_TIMEOUT,
                State::Retired => age(sa.last_seen) < RETIRED_TIMEOUT,
                State::Established if self.device(&sa.device_id).is_none() => {
                    eprintln!("{}: {} revoked or expired", sa.peer, sa.device_id);
                    self.sas.insert(id, sa);
                    out.extend(self.disconnect(id));
                    continue;
                }
                State::Established => self.probe(&mut sa, now, &mut out),
            };
            if keep {
                self.sas.insert(id, sa);
            } else {
                self.teardown(&mut sa);
            }
        }
        out
    }

    /// Returns false once the peer is considered dead.
    fn probe(&mut self, sa: &mut Sa, now: Instant, out: &mut Vec<Outgoing>) -> bool {
        if let Some(probe) = &mut sa.probe {
            if now.saturating_duration_since(probe.sent) >= Duration::from_secs(2 << probe.tries.min(4)) {
                if probe.tries >= MAX_PROBES {
                    eprintln!("{}: {} stopped responding", sa.peer, sa.device_id);
                    return false;
                }
                probe.tries += 1;
                probe.sent = now;
                let (peer, local_port) = (sa.peer, sa.local_port);
                out.extend(probe.packets.iter().map(|p| Outgoing { data: p.clone(), to: peer, local_port }));
            }
        } else if now.saturating_duration_since(sa.last_seen) >= IDLE_BEFORE_PROBE {
            let received: u64 = sa.children.iter().map(|c| self.dataplane.bytes(c).0).sum();
            if received > sa.last_bytes {
                // ESP traffic proves the peer is alive.
                sa.last_seen = now;
            } else {
                let packets = sa.request(exchange::INFORMATIONAL, &Chain::default());
                out.extend(packets.iter().map(|p| sa.to_peer(p.clone())));
                sa.probe = Some(Probe { packets, sent: now, tries: 0 });
            }
            sa.last_bytes = received;
        }
        true
    }

    pub fn sessions(&mut self) -> Vec<SessionInfo> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for sa in self.sas.values().filter(|s| matches!(s.state, State::Established)) {
            let device = store.find(sa.device_id.as_bytes());
            let (mut bytes_in, mut bytes_out) = (0, 0);
            for c in &sa.children {
                let (i, o) = self.dataplane.bytes(c);
                bytes_in += i;
                bytes_out += o;
            }
            out.push(SessionInfo {
                id: format!("{:016x}", sa.spi_r),
                device_id: sa.device_id.clone(),
                device_name: device.map_or_else(String::new, |d| d.name.clone()),
                owner: device.map_or_else(String::new, |d| d.owner.clone()),
                owner_name: device.map_or_else(String::new, |d| d.owner_name.clone()),
                peer: sa.peer.to_string(),
                virtual_ip: sa.virtual_ip,
                post_quantum: sa.post_quantum,
                connected_seconds: sa.created.elapsed().as_secs(),
                bytes_in,
                bytes_out,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct NoDataplane;
    impl Dataplane for NoDataplane {
        fn add(&mut self, _: &Child) -> io::Result<()> {
            Ok(())
        }
        fn remove(&mut self, _: &Child, _: bool) {}
        fn bytes(&mut self, _: &Child) -> (u64, u64) {
            (0, 0)
        }
    }

    fn engine() -> Engine<NoDataplane> {
        let config = Vpn {
            local_ip: Ipv4Addr::new(192, 0, 2, 1),
            public_address: "vpn.test".into(),
            server_id: "vpn.test".into(),
            pool: "10.9.0.0/24".parse().unwrap(),
            dns: vec![],
            local_subnets: vec!["0.0.0.0/0".parse().unwrap()],
            require_pq: true,
        };
        Engine::new(config, NoDataplane, Arc::new(Mutex::new(Store::in_memory())))
    }

    /// Hostile input must never panic the daemon.
    #[test]
    fn survives_random_datagrams() {
        let mut e = engine();
        let from: SocketAddrV4 = "198.51.100.7:500".parse().unwrap();
        for round in 0..20_000u32 {
            let seed: [u8; 64] = crypto::random();
            let mut body = seed.repeat(1 + (round % 8) as usize);
            body.truncate(usize::from(seed[0]) * 2);
            let header = Header {
                spi_i: 1,
                spi_r: 0,
                next: [33, 34, 40, 41, 46, 53][usize::from(seed[1]) % 6],
                exchange: 34,
                flags: flag::INITIATOR,
                msg_id: 0,
            };
            let mut packet = header.encode(HEADER_LEN + body.len());
            // Mostly well formed chain lengths, so parsing goes deeper.
            if body.len() >= 4 && seed[2] & 1 == 0 {
                body[0] = [0, 33, 34, 40, 41][usize::from(seed[3]) % 5];
                body[1] = 0;
                let len = (body.len() as u16).to_be_bytes();
                body[2..4].copy_from_slice(&len);
            }
            packet.extend(body);
            e.handle(&packet, from, 500);
            e.handle(&seed, from, 4500);
        }
    }
}
