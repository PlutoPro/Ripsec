//! SA payload parsing and algorithm selection (RFC 7296 section 3.3, RFC 9370).

use super::crypto::{DH_ECP256, DH_ECP384, DH_X25519, KE_ML_KEM_768, KE_ML_KEM_1024, Prf};
use super::wire::{PROTO_ESP, PROTO_IKE, be16};

const ENCR: u8 = 1;
const PRF: u8 = 2;
const INTEG: u8 = 3;
const KE: u8 = 4;
const ESN: u8 = 5;
const ADDKE1: u8 = 6;
const ADDKE7: u8 = 12;
const ENCR_AES_GCM_16: u16 = 20;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Transform {
    pub kind: u8,
    pub id: u16,
    pub key_bits: Option<u16>,
}

#[derive(Debug)]
pub struct Proposal {
    pub number: u8,
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    fn ids(&self, kind: u8) -> impl Iterator<Item = u16> + '_ {
        self.transforms.iter().filter(move |t| t.kind == kind).map(|t| t.id)
    }

    fn pick(&self, kind: u8, preference: &[u16]) -> Option<u16> {
        preference.iter().copied().find(|want| self.ids(kind).any(|id| id == *want))
    }

    fn gcm_bits(&self) -> Option<u16> {
        [256u16, 128].into_iter().find(|bits| {
            self.transforms
                .iter()
                .any(|t| t.kind == ENCR && t.id == ENCR_AES_GCM_16 && t.key_bits == Some(*bits))
        })
    }

    /// AEAD ciphers must not be combined with a separate integrity algorithm.
    fn integrity_ok(&self) -> bool {
        self.ids(INTEG).next().is_none() || self.ids(INTEG).any(|id| id == 0)
    }
}

pub fn parse_sa(mut b: &[u8]) -> Option<Vec<Proposal>> {
    let mut out = Vec::new();
    loop {
        let len = be16(b, 2)? as usize;
        if len < 8 || len > b.len() || out.len() >= 32 {
            return None;
        }
        let (number, protocol, spi_len, count) = (b[4], b[5], b[6] as usize, b[7]);
        let spi = b.get(8..8 + spi_len)?.to_vec();
        let mut rest = b.get(8 + spi_len..len)?;
        let mut transforms = Vec::new();
        for _ in 0..count {
            let tlen = be16(rest, 2)? as usize;
            if tlen < 8 || tlen > rest.len() || transforms.len() >= 64 {
                return None;
            }
            // The only attribute defined for IKEv2 is the fixed size key length.
            let key_bits = (tlen >= 12 && be16(rest, 8)? == 0x800e).then(|| be16(rest, 10)).flatten();
            transforms.push(Transform { kind: rest[4], id: be16(rest, 6)?, key_bits });
            rest = &rest[tlen..];
        }
        out.push(Proposal { number, protocol, spi, transforms });
        let last = b[0] == 0;
        b = &b[len..];
        if last {
            return b.is_empty().then_some(out);
        }
    }
}

fn encode_sa(number: u8, protocol: u8, spi: &[u8], transforms: &[Transform]) -> Vec<u8> {
    let mut body = Vec::new();
    for (i, t) in transforms.iter().enumerate() {
        let more = if i + 1 == transforms.len() { 0 } else { 3 };
        let len: u16 = if t.key_bits.is_some() { 12 } else { 8 };
        body.extend_from_slice(&[more, 0]);
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&[t.kind, 0]);
        body.extend_from_slice(&t.id.to_be_bytes());
        if let Some(bits) = t.key_bits {
            body.extend_from_slice(&[0x80, 0x0e]);
            body.extend_from_slice(&bits.to_be_bytes());
        }
    }
    let mut out = vec![0, 0];
    out.extend_from_slice(&((8 + spi.len() + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[number, protocol, spi.len() as u8, transforms.len() as u8]);
    out.extend_from_slice(spi);
    out.extend(body);
    out
}

/// The chosen algorithms of an IKE or ESP SA.
#[derive(Debug, Clone)]
pub struct Suite {
    pub number: u8,
    pub peer_spi: Vec<u8>,
    pub key_bits: u16,
    /// Always set for IKE, unused for ESP.
    pub prf: Prf,
    pub dh: Option<u16>,
    /// ML-KEM method of the first additional key exchange.
    pub pq: Option<u16>,
    pub esn: bool,
    transforms: Vec<Transform>,
}

impl Suite {
    pub fn encode(&self, protocol: u8, our_spi: &[u8]) -> Vec<u8> {
        encode_sa(self.number, protocol, our_spi, &self.transforms)
    }

    /// Length of one direction's AES-GCM key material, salt included.
    pub fn key_len(&self) -> usize {
        usize::from(self.key_bits / 8) + 4
    }
}

fn t(kind: u8, id: u16) -> Transform {
    Transform { kind, id, key_bits: None }
}

/// Chooses the additional key exchange transforms. `None` rejects the proposal.
fn select_addke(p: &Proposal) -> Option<(Option<u16>, Vec<Transform>)> {
    let mut pq = None;
    let mut chosen = Vec::new();
    for kind in ADDKE1..=ADDKE7 {
        if p.ids(kind).next().is_none() {
            continue;
        }
        let want = if kind == ADDKE1 { p.pick(kind, &[KE_ML_KEM_768, KE_ML_KEM_1024]) } else { None };
        match want {
            Some(id) => {
                pq = Some(id);
                chosen.push(t(kind, id));
            }
            None => {
                p.pick(kind, &[0])?;
                chosen.push(t(kind, 0));
            }
        }
    }
    Some((pq, chosen))
}

fn dh_choice(p: &Proposal, offered_group: Option<u16>) -> Option<u16> {
    let supported = [DH_X25519, DH_ECP384, DH_ECP256];
    // Prefer the group the peer already sent a key for, to save a round trip.
    offered_group
        .filter(|g| supported.contains(g) && p.ids(KE).any(|id| id == *g))
        .or_else(|| p.pick(KE, &supported))
}

fn ike_suite(p: &Proposal, offered_group: Option<u16>, allow_additional: bool) -> Option<Suite> {
    if p.protocol != PROTO_IKE || !p.integrity_ok() {
        return None;
    }
    let bits = p.gcm_bits()?;
    let prf_id = p.pick(PRF, &[7, 6, 5])?;
    let dh = dh_choice(p, offered_group)?;
    let (pq, addke) = select_addke(p)?;
    if !allow_additional && !addke.is_empty() {
        return None;
    }
    let mut transforms =
        vec![Transform { kind: ENCR, id: ENCR_AES_GCM_16, key_bits: Some(bits) }, t(PRF, prf_id), t(KE, dh)];
    transforms.extend(addke);
    Some(Suite {
        number: p.number,
        peer_spi: p.spi.clone(),
        key_bits: bits,
        prf: Prf::from_id(prf_id)?,
        dh: Some(dh),
        pq,
        esn: false,
        transforms,
    })
}

/// Picks an IKE SA suite, preferring any proposal that is post-quantum.
pub fn select_ike(
    proposals: &[Proposal],
    offered_group: Option<u16>,
    allow_additional: bool,
    require_pq: bool,
) -> Option<Suite> {
    let mut usable = proposals.iter().filter_map(|p| ike_suite(p, offered_group, allow_additional));
    let first = usable.next()?;
    let best = if first.pq.is_some() { Some(first.clone()) } else { usable.find(|s| s.pq.is_some()) };
    match best {
        Some(s) => Some(s),
        None => (!require_pq).then_some(first),
    }
}

/// Picks an ESP suite. `with_ke` is set when the exchange carries a key exchange payload.
pub fn select_esp(proposals: &[Proposal], offered_group: Option<u16>) -> Option<Suite> {
    proposals.iter().find_map(|p| {
        if p.protocol != PROTO_ESP || p.spi.len() != 4 || !p.integrity_ok() {
            return None;
        }
        let bits = p.gcm_bits()?;
        let esn = p.pick(ESN, &[1, 0])?;
        let mut transforms = vec![Transform { kind: ENCR, id: ENCR_AES_GCM_16, key_bits: Some(bits) }];
        let (mut dh, mut pq) = (None, None);
        if offered_group.is_some() {
            dh = Some(dh_choice(p, offered_group)?);
            transforms.push(t(KE, dh?));
            let (chosen_pq, addke) = select_addke(p)?;
            pq = chosen_pq;
            transforms.extend(addke);
        }
        transforms.push(t(ESN, esn));
        Some(Suite {
            number: p.number,
            peer_spi: p.spi.clone(),
            key_bits: bits,
            prf: Prf::Sha256,
            dh,
            pq,
            esn: esn == 1,
            transforms,
        })
    })
}

/// The client's only IKE offer: AES-256-GCM, SHA-384, X25519 combined with ML-KEM-768.
pub fn offer_ike() -> Vec<u8> {
    let encr = Transform { kind: ENCR, id: ENCR_AES_GCM_16, key_bits: Some(256) };
    encode_sa(1, PROTO_IKE, &[], &[encr, t(PRF, 6), t(KE, DH_X25519), t(ADDKE1, KE_ML_KEM_768)])
}

/// The client's only ESP offer for the first CHILD SA: AES-256-GCM with 64 bit sequence numbers.
pub fn offer_esp(spi: u32) -> Vec<u8> {
    let encr = Transform { kind: ENCR, id: ENCR_AES_GCM_16, key_bits: Some(256) };
    encode_sa(1, PROTO_ESP, &spi.to_be_bytes(), &[encr, t(ESN, 1)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ike(number: u8, extra: &[Transform]) -> Proposal {
        let mut transforms = vec![
            Transform { kind: ENCR, id: ENCR_AES_GCM_16, key_bits: Some(256) },
            t(PRF, 6),
            t(KE, DH_X25519),
        ];
        transforms.extend_from_slice(extra);
        Proposal { number, protocol: PROTO_IKE, spi: vec![], transforms }
    }

    #[test]
    fn prefers_post_quantum_proposal() {
        let offers = [ike(1, &[]), ike(2, &[t(ADDKE1, KE_ML_KEM_768)])];
        let s = select_ike(&offers, Some(DH_X25519), true, false).unwrap();
        assert_eq!((s.number, s.pq), (2, Some(KE_ML_KEM_768)));
    }

    #[test]
    fn require_pq_rejects_classical() {
        assert!(select_ike(&[ike(1, &[])], None, true, true).is_none());
        assert!(select_ike(&[ike(1, &[t(ADDKE1, 0)])], None, true, true).is_none());
        assert!(select_ike(&[ike(1, &[])], None, true, false).is_some());
        // Additional exchanges need IKE_INTERMEDIATE support.
        assert!(select_ike(&[ike(1, &[t(ADDKE1, KE_ML_KEM_768)])], None, false, false).is_none());
    }

    #[test]
    fn sa_round_trips() {
        let offers = [ike(1, &[t(ADDKE1, KE_ML_KEM_768)])];
        let s = select_ike(&offers, None, true, true).unwrap();
        let parsed = parse_sa(&s.encode(PROTO_IKE, &[])).unwrap();
        assert_eq!(parsed[0].transforms, offers[0].transforms);
        assert!(parse_sa(&[0, 0, 0, 200]).is_none());
    }
}
