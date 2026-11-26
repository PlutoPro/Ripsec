//! Key schedule and the encrypted (and fragmented) payload of one IKE SA.

use super::crypto::{GCM_IV, GCM_TAG, Gcm, Prf};
use super::wire::{HEADER_LEN, Header, be16, flag, payload};

/// Messages larger than this are sent as fragments when the peer supports it.
const MAX_MESSAGE: usize = 1200;
const FRAGMENT_DATA: usize = 1100;
const MAX_FRAGMENTS: u16 = 32;
const MAX_REASSEMBLED: usize = 16 * 1024;

pub struct Keys {
    pub prf: Prf,
    pub d: Vec<u8>,
    pub pi: Vec<u8>,
    pub pr: Vec<u8>,
    rx: Gcm,
    tx: Gcm,
    /// Explicit IV counter: never repeats for the lifetime of `tx`.
    iv: u64,
}

impl Keys {
    /// {SK_d | SK_ei | SK_er | SK_pi | SK_pr}; AEAD suites have no SK_a keys.
    pub fn derive(
        prf: Prf,
        key_len: usize,
        skeyseed: &[u8],
        ni: &[u8],
        nr: &[u8],
        spi_i: u64,
        spi_r: u64,
    ) -> Option<Keys> {
        let n = prf.len();
        let material =
            prf.plus(skeyseed, &[ni, nr, &spi_i.to_be_bytes(), &spi_r.to_be_bytes()], 3 * n + 2 * key_len);
        let mut rest = material.as_slice();
        let mut take = |len: usize| {
            let (head, tail) = rest.split_at(len);
            rest = tail;
            head
        };
        let d = take(n).to_vec();
        let rx = Gcm::new(take(key_len))?;
        let tx = Gcm::new(take(key_len))?;
        let pi = take(n).to_vec();
        let pr = take(n).to_vec();
        Some(Keys { prf, d, pi, pr, rx, tx, iv: 0 })
    }

    /// [`Keys::derive`] orients the keys for the responder; this turns them round.
    pub fn into_initiator(mut self) -> Keys {
        std::mem::swap(&mut self.rx, &mut self.tx);
        self
    }

    /// Builds an SK payload message, or several SKF messages for large content.
    pub fn seal(&mut self, header: Header, first: u8, inner: &[u8], may_fragment: bool) -> Vec<Vec<u8>> {
        if !may_fragment || HEADER_LEN + 4 + GCM_IV + inner.len() + 1 + GCM_TAG <= MAX_MESSAGE {
            return vec![self.seal_one(header, first, inner, None)];
        }
        let chunks: Vec<&[u8]> = inner.chunks(FRAGMENT_DATA).collect();
        let total = chunks.len() as u16;
        chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                let next = if i == 0 { first } else { 0 };
                self.seal_one(header, next, chunk, Some((i as u16 + 1, total)))
            })
            .collect()
    }

    fn seal_one(
        &mut self,
        mut header: Header,
        first: u8,
        data: &[u8],
        fragment: Option<(u16, u16)>,
    ) -> Vec<u8> {
        let extra = if fragment.is_some() { 4 } else { 0 };
        let sk_len = 4 + extra + GCM_IV + data.len() + 1 + GCM_TAG;
        header.next = if fragment.is_some() { payload::SKF } else { payload::SK };
        let mut out = header.encode(HEADER_LEN + sk_len);
        out.extend_from_slice(&[first, 0]);
        out.extend_from_slice(&(sk_len as u16).to_be_bytes());
        if let Some((number, total)) = fragment {
            out.extend_from_slice(&number.to_be_bytes());
            out.extend_from_slice(&total.to_be_bytes());
        }
        self.iv += 1;
        let iv = self.iv.to_be_bytes();
        let mut plain = Vec::with_capacity(data.len() + 1 + GCM_TAG);
        plain.extend_from_slice(data);
        plain.push(0); // pad length
        let sealed = self.tx.seal(iv, &out, plain);
        out.extend_from_slice(&iv);
        out.extend(sealed);
        out
    }

    /// Authenticates and decrypts one received message or fragment.
    pub fn open(&self, packet: &[u8]) -> Option<Opened> {
        let kind = *packet.get(16)?;
        let aad_len = match kind {
            payload::SK => HEADER_LEN + 4,
            payload::SKF => HEADER_LEN + 8,
            _ => return None,
        };
        let next = *packet.get(HEADER_LEN)?;
        if usize::from(be16(packet, HEADER_LEN + 2)?) != packet.len() - HEADER_LEN {
            return None;
        }
        let fragment = if kind == payload::SKF {
            Some((be16(packet, HEADER_LEN + 4)?, be16(packet, HEADER_LEN + 6)?))
        } else {
            None
        };
        let mut data = self.rx.open(
            packet.get(aad_len..aad_len + GCM_IV)?,
            packet.get(..aad_len)?,
            packet.get(aad_len + GCM_IV..)?,
        )?;
        let padding = usize::from(data.pop()?);
        data.truncate(data.len().checked_sub(padding)?);
        Some(Opened { next, data, fragment })
    }
}

pub struct Opened {
    pub next: u8,
    pub data: Vec<u8>,
    pub fragment: Option<(u16, u16)>,
}

/// Collects the fragments of one message.
pub struct Reassembly {
    msg_id: u32,
    next: u8,
    parts: Vec<Option<Vec<u8>>>,
}

/// Returns (first inner payload type, plaintext) once a message is complete.
pub fn reassemble(slot: &mut Option<Reassembly>, msg_id: u32, o: Opened) -> Option<(u8, Vec<u8>)> {
    let Some((number, total)) = o.fragment else {
        *slot = None;
        return Some((o.next, o.data));
    };
    if number == 0 || number > total || total > MAX_FRAGMENTS {
        return None;
    }
    let total = usize::from(total);
    // A retransmission may use smaller fragments, which makes the older ones useless.
    if slot.as_ref().is_none_or(|r| r.msg_id != msg_id || r.parts.len() < total) {
        *slot = Some(Reassembly { msg_id, next: 0, parts: vec![None; total] });
    }
    let r = slot.as_mut()?;
    if r.parts.len() != total {
        return None;
    }
    if number == 1 {
        r.next = o.next;
    }
    r.parts[usize::from(number) - 1] = Some(o.data);
    let size: usize = r.parts.iter().flatten().map(Vec::len).sum();
    if size > MAX_REASSEMBLED {
        *slot = None;
        return None;
    }
    if r.parts.iter().any(Option::is_none) {
        return None;
    }
    let r = slot.take()?;
    Some((r.next, r.parts.into_iter().flatten().flatten().collect()))
}

/// RFC 9242: authenticates an IKE_INTERMEDIATE message as if it were unfragmented.
pub fn int_auth(prf: Prf, key: &[u8], mut header: Header, first: u8, plain: &[u8]) -> Vec<u8> {
    header.next = payload::SK;
    let mut a = header.encode(HEADER_LEN + 4 + plain.len());
    a.extend_from_slice(&[first, 0]);
    a.extend_from_slice(&((plain.len() + 4) as u16).to_be_bytes());
    prf.run(key, &[&a, plain])
}

pub fn response_header(spi_i: u64, spi_r: u64, exchange: u8, msg_id: u32) -> Header {
    Header { spi_i, spi_r, next: 0, exchange, flags: flag::RESPONSE, msg_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(n: u16, total: u16, data: &[u8]) -> Opened {
        Opened { next: if n == 1 { 33 } else { 0 }, data: data.to_vec(), fragment: Some((n, total)) }
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut slot = None;
        assert!(reassemble(&mut slot, 1, opened(2, 2, b"world")).is_none());
        let (next, data) = reassemble(&mut slot, 1, opened(1, 2, b"hello ")).unwrap();
        assert_eq!((next, data.as_slice()), (33, &b"hello world"[..]));
        assert!(reassemble(&mut slot, 2, opened(3, 2, b"x")).is_none());
        assert!(reassemble(&mut slot, 2, opened(1, 999, b"x")).is_none());
    }
}
