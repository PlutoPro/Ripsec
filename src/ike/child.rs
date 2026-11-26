//! CHILD SA negotiation and rekeying of both SA kinds.

use super::crypto;
use super::engine::{Engine, Reply, Sa, State};
use super::proposal::{self, Suite};
use super::secured::Keys;
use super::wire::{self, Chain, Payload, be16, be64, notify, payload};
use crate::dataplane::{Child, Dataplane};
use crate::net::{self, Cidr};
use crate::store::Device;
use std::net::{Ipv4Addr, SocketAddrV4};

const MAX_CHILDREN: usize = 16;
const CFG_REQUEST: u8 = 1;
const CFG_REPLY: u8 = 2;
const ATTR_IP4_ADDRESS: u16 = 1;
const ATTR_IP4_NETMASK: u16 = 2;
const ATTR_IP4_DNS: u16 = 3;
const ATTR_IP4_SUBNET: u16 = 13;

/// A CREATE_CHILD_SA exchange waiting for its ML-KEM IKE_FOLLOWUP_KE.
pub(super) struct Followup {
    link: [u8; 16],
    rekey: Rekey,
}

struct Rekey {
    suite: Suite,
    ni: Vec<u8>,
    nr: Vec<u8>,
    /// Shared secret of the (EC)DH exchange, if there was one.
    dh_secret: Vec<u8>,
    target: Target,
}

enum Target {
    Ike { spi_i: u64, spi_r: u64 },
    Esp { spi_in: u32, local_ts: Vec<Cidr>, remote_ts: Vec<Cidr> },
}

fn wants_address(payloads: &[Payload]) -> bool {
    let Some(cp) = wire::find(payloads, payload::CP) else { return false };
    if cp.first() != Some(&CFG_REQUEST) {
        return false;
    }
    let mut at = 4;
    while let (Some(kind), Some(len)) = (be16(cp, at), be16(cp, at + 2)) {
        if kind & 0x7fff == ATTR_IP4_ADDRESS {
            return true;
        }
        at += 4 + usize::from(len);
    }
    false
}

fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn ke_payload(group: u16, data: &[u8]) -> Vec<u8> {
    let mut body = group.to_be_bytes().to_vec();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(data);
    body
}

fn new_esp_spi() -> u32 {
    loop {
        let spi = u32::from_be_bytes(crypto::random());
        if spi > 0xff {
            return spi;
        }
    }
}

impl<D: Dataplane> Engine<D> {
    fn allocate_address(&self) -> Option<Ipv4Addr> {
        let pool = self.config.pool;
        // The network, broadcast and first host (reserved for the gateway) are skipped.
        (pool.first() + 2..pool.last())
            .map(Ipv4Addr::from)
            .find(|ip| !self.sas.values().any(|s| s.virtual_ip == Some(*ip)))
    }

    /// Intersects the peer's selectors with what this device is allowed to reach and claim.
    fn selectors(&self, sa: &Sa, device: &Device, payloads: &[Payload]) -> Option<(Vec<Cidr>, Vec<Cidr>)> {
        let remote = net::parse_ts(wire::find(payloads, payload::TSI)?)?;
        let local = net::parse_ts(wire::find(payloads, payload::TSR)?)?;
        let mut allowed = device.subnets();
        if allowed.is_empty() {
            allowed.extend(sa.virtual_ip.map(Cidr::host));
        }
        let remote = net::narrow(&remote, &allowed);
        let local = net::narrow(&local, &self.config.local_subnets);
        (!remote.is_empty() && !local.is_empty()).then_some((local, remote))
    }

    /// Derives keys (RFC 7296 section 2.17, RFC 9370 section 2.2.4) and programs the kernel.
    #[allow(clippy::too_many_arguments)]
    fn install(
        &mut self,
        sa: &mut Sa,
        suite: &Suite,
        spi_in: u32,
        local_ts: Vec<Cidr>,
        remote_ts: Vec<Cidr>,
        seed: &[&[u8]],
    ) -> bool {
        let Some(spi_out) = suite.peer_spi.as_slice().try_into().ok().map(u32::from_be_bytes) else {
            return false;
        };
        if sa.children.len() >= MAX_CHILDREN {
            return false;
        }
        let len = suite.key_len();
        let mut key_in = sa.keys.prf.plus(&sa.keys.d, seed, 2 * len);
        let key_out = key_in.split_off(len);
        // A replacement for the same selectors shares the reqid and so the policies.
        let reqid =
            sa.children.iter().find(|c| c.local_ts == local_ts && c.remote_ts == remote_ts).map_or_else(
                || {
                    self.next_reqid += 1;
                    self.next_reqid
                },
                |c| c.reqid,
            );
        let child = Child {
            reqid,
            local: SocketAddrV4::new(self.config.local_ip, sa.local_port),
            peer: sa.peer,
            udp_encap: sa.nat,
            spi_in,
            spi_out,
            key_in,
            key_out,
            esn: suite.esn,
            local_ts,
            remote_ts,
        };
        match self.dataplane.add(&child) {
            Ok(()) => {
                sa.children.push(child);
                true
            }
            Err(e) => {
                eprintln!("{}: cannot install CHILD SA: {e}", sa.peer);
                false
            }
        }
    }

    /// The CHILD SA created inside IKE_AUTH, including address assignment.
    pub(super) fn first_child(
        &mut self,
        sa: &mut Sa,
        device: &Device,
        payloads: &[Payload],
        ni: &[u8],
        nr: &[u8],
        chain: &mut Chain,
    ) {
        let Some(proposals) = wire::find(payloads, payload::SA).and_then(proposal::parse_sa) else {
            return;
        };
        let mut config_reply = None;
        if device.remote_subnets.is_empty() && wants_address(payloads) {
            let Some(ip) = self.allocate_address() else {
                return chain.notify(notify::INTERNAL_ADDRESS_FAILURE, &[]);
            };
            sa.virtual_ip = Some(ip);
            let mut cp = vec![CFG_REPLY, 0, 0, 0];
            attribute(&mut cp, ATTR_IP4_ADDRESS, &ip.octets());
            attribute(&mut cp, ATTR_IP4_NETMASK, &[255; 4]);
            for dns in &self.config.dns {
                attribute(&mut cp, ATTR_IP4_DNS, &dns.octets());
            }
            for net in self.config.local_subnets.iter().filter(|n| n.prefix > 0) {
                let mask = u32::MAX << (32 - u32::from(net.prefix));
                let value = [net.addr().octets(), mask.to_be_bytes()].concat();
                attribute(&mut cp, ATTR_IP4_SUBNET, &value);
            }
            config_reply = Some(cp);
        }
        let Some(suite) = proposal::select_esp(&proposals, None) else {
            return chain.notify(notify::NO_PROPOSAL_CHOSEN, &[]);
        };
        let Some((local_ts, remote_ts)) = self.selectors(sa, device, payloads) else {
            return chain.notify(notify::TS_UNACCEPTABLE, &[]);
        };
        let spi_in = new_esp_spi();
        if !self.install(sa, &suite, spi_in, local_ts.clone(), remote_ts.clone(), &[ni, nr]) {
            return chain.notify(notify::TEMPORARY_FAILURE, &[]);
        }
        if let Some(cp) = config_reply {
            chain.push(payload::CP, &cp);
        }
        chain.push(payload::SA, &suite.encode(wire::PROTO_ESP, &spi_in.to_be_bytes()));
        chain.push(payload::TSI, &net::encode_ts(&remote_ts));
        chain.push(payload::TSR, &net::encode_ts(&local_ts));
    }

    pub(super) fn create_child(&mut self, sa: &mut Sa, payloads: &[Payload]) -> Reply {
        sa.followup = None;
        let syntax = || Reply::error(notify::INVALID_SYNTAX, &[]);
        let (Some(proposals), Some(ni)) = (
            wire::find(payloads, payload::SA).and_then(proposal::parse_sa),
            wire::find(payloads, payload::NONCE),
        ) else {
            return syntax();
        };
        if !(16..=256).contains(&ni.len()) {
            return syntax();
        }
        let ke = wire::find(payloads, payload::KE);
        let group = ke.and_then(|k| be16(k, 0));
        let is_ike = proposals.first().is_some_and(|p| p.protocol == wire::PROTO_IKE);
        let suite = if is_ike {
            proposal::select_ike(&proposals, group, true, self.config.require_pq)
        } else {
            proposal::select_esp(&proposals, group)
        };
        let Some(suite) = suite else { return Reply::error(notify::NO_PROPOSAL_CHOSEN, &[]) };

        let mut dh_public = None;
        let mut dh_secret = Vec::new();
        if let Some(dh) = suite.dh {
            if Some(dh) != group {
                return Reply::error(notify::INVALID_KE_PAYLOAD, &dh.to_be_bytes());
            }
            let Some((public, secret)) = ke.and_then(|k| k.get(4..)).and_then(|k| crypto::dh_respond(dh, k))
            else {
                return syntax();
            };
            dh_public = Some(ke_payload(dh, &public));
            dh_secret = secret;
        } else if is_ike {
            return syntax();
        }
        let nr = crypto::random::<32>().to_vec();

        let mut chain = Chain::default();
        let mut ts_reply = None;
        let target = if is_ike {
            let Some(spi_i) = be64(&suite.peer_spi, 0).filter(|s| *s != 0 && suite.peer_spi.len() == 8)
            else {
                return syntax();
            };
            let spi_r = self.new_spi();
            chain.push(payload::SA, &suite.encode(wire::PROTO_IKE, &spi_r.to_be_bytes()));
            Target::Ike { spi_i, spi_r }
        } else {
            let rekeyed = wire::notifies(payloads).find(|n| n.kind == notify::REKEY_SA);
            if let Some(n) = rekeyed {
                let known = n.protocol == wire::PROTO_ESP
                    && sa.children.iter().any(|c| c.spi_out.to_be_bytes() == n.spi);
                if !known {
                    return Reply::error(notify::CHILD_SA_NOT_FOUND, &[]);
                }
            }
            let Some(device) = self.device(&sa.device_id) else {
                return Reply::error(notify::TEMPORARY_FAILURE, &[]);
            };
            let Some((local_ts, remote_ts)) = self.selectors(sa, &device, payloads) else {
                return Reply::error(notify::TS_UNACCEPTABLE, &[]);
            };
            let spi_in = new_esp_spi();
            chain.push(payload::SA, &suite.encode(wire::PROTO_ESP, &spi_in.to_be_bytes()));
            ts_reply = Some((net::encode_ts(&remote_ts), net::encode_ts(&local_ts)));
            Target::Esp { spi_in, local_ts, remote_ts }
        };
        chain.push(payload::NONCE, &nr);
        if let Some(public) = dh_public {
            chain.push(payload::KE, &public);
        }
        if let Some((tsi, tsr)) = ts_reply {
            chain.push(payload::TSI, &tsi);
            chain.push(payload::TSR, &tsr);
        }

        let needs_pq = suite.pq.is_some();
        let rekey = Rekey { suite, ni: ni.to_vec(), nr, dh_secret, target };
        if needs_pq {
            let link: [u8; 16] = crypto::random();
            chain.notify(notify::ADDITIONAL_KEY_EXCHANGE, &link);
            sa.followup = Some(Followup { link, rekey });
        } else if !self.complete(sa, rekey, &[]) {
            return Reply::error(notify::TEMPORARY_FAILURE, &[]);
        }
        Reply::ok(chain)
    }

    pub(super) fn followup(&mut self, sa: &mut Sa, payloads: &[Payload]) -> Reply {
        let Some(pending) = sa.followup.take() else {
            return Reply::error(notify::INVALID_SYNTAX, &[]);
        };
        let linked = wire::notifies(payloads)
            .any(|n| n.kind == notify::ADDITIONAL_KEY_EXCHANGE && n.data == pending.link);
        let encapsulated = pending.rekey.suite.pq.filter(|_| linked).and_then(|method| {
            let ke = wire::find(payloads, payload::KE)?;
            if be16(ke, 0)? != method {
                return None;
            }
            let (ciphertext, secret) = crypto::kem_respond(method, ke.get(4..)?)?;
            Some((ke_payload(method, &ciphertext), secret))
        });
        let Some((ke, secret)) = encapsulated else {
            return Reply::error(notify::INVALID_SYNTAX, &[]);
        };
        if !self.complete(sa, pending.rekey, &secret) {
            return Reply::error(notify::TEMPORARY_FAILURE, &[]);
        }
        let mut chain = Chain::default();
        chain.push(payload::KE, &ke);
        Reply::ok(chain)
    }

    fn complete(&mut self, sa: &mut Sa, r: Rekey, pq_secret: &[u8]) -> bool {
        let seed: [&[u8]; 4] = [&r.dh_secret, &r.ni, &r.nr, pq_secret];
        match r.target {
            Target::Esp { spi_in, local_ts, remote_ts } => {
                self.install(sa, &r.suite, spi_in, local_ts, remote_ts, &seed)
            }
            Target::Ike { spi_i, spi_r } => {
                let skeyseed = sa.keys.prf.run(&sa.keys.d, &seed);
                let Some(keys) =
                    Keys::derive(r.suite.prf, r.suite.key_len(), &skeyseed, &r.ni, &r.nr, spi_i, spi_r)
                else {
                    return false;
                };
                let post_quantum = r.suite.pq.is_some();
                let mut new =
                    Sa::new(spi_i, spi_r, sa.peer, sa.local_port, r.suite, keys, State::Established);
                new.post_quantum = post_quantum;
                new.frag_ok = sa.frag_ok;
                new.nat = sa.nat;
                new.created = sa.created;
                new.device_id = sa.device_id.clone();
                new.virtual_ip = sa.virtual_ip.take();
                new.children = std::mem::take(&mut sa.children);
                sa.device_id.clear();
                sa.state = State::Retired;
                self.sas.insert(spi_r, new);
                true
            }
        }
    }
}
