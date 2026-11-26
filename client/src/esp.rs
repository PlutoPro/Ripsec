//! ESP in tunnel mode with AES-256-GCM (RFC 4303, RFC 4106), always with extended
//! (64 bit) sequence numbers and an anti-replay window.

use ripsec_proto::crypto::{GCM_IV, GCM_TAG, Gcm};

const HEADER: usize = 8;
const NEXT_IPV4: u8 = 4;
/// How far behind the newest packet an older one is still accepted.
const WINDOW: u64 = 1024;
const WORDS: usize = (WINDOW / 64) as usize;

/// The sending direction.
pub struct Sender {
    spi: u32,
    key: Gcm,
    /// Also the explicit IV, so an IV never repeats under one key.
    sequence: u64,
}

impl Sender {
    pub fn new(spi: u32, key_material: &[u8]) -> Option<Sender> {
        Some(Sender { spi, key: Gcm::new(key_material)?, sequence: 0 })
    }

    /// Wraps one IPv4 packet. `None` once the sequence space is used up.
    pub fn seal(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        self.sequence = self.sequence.checked_add(1)?;
        let high = ((self.sequence >> 32) as u32).to_be_bytes();
        let low = (self.sequence as u32).to_be_bytes();
        let spi = self.spi.to_be_bytes();

        // Pad so that the two trailer bytes end on a four byte boundary.
        let padding = (4 - (packet.len() + 2) % 4) % 4;
        let mut plain = Vec::with_capacity(packet.len() + padding + 2 + GCM_TAG);
        plain.extend_from_slice(packet);
        plain.extend((1..=padding as u8).collect::<Vec<_>>());
        plain.extend_from_slice(&[padding as u8, NEXT_IPV4]);

        let aad = [spi, high, low].concat();
        let iv = self.sequence.to_be_bytes();
        let sealed = self.key.seal(iv, &aad, plain);
        let mut out = Vec::with_capacity(HEADER + GCM_IV + sealed.len());
        out.extend_from_slice(&spi);
        out.extend_from_slice(&low);
        out.extend_from_slice(&iv);
        out.extend(sealed);
        Some(out)
    }
}

/// The receiving direction.
pub struct Receiver {
    spi: u32,
    key: Gcm,
    highest: u64,
    /// Bit `n % WINDOW` is set when sequence number `n` has been accepted.
    seen: [u64; WORDS],
}

impl Receiver {
    pub fn new(spi: u32, key_material: &[u8]) -> Option<Receiver> {
        Some(Receiver { spi, key: Gcm::new(key_material)?, highest: 0, seen: [0; WORDS] })
    }

    /// Recovers the high half of a sequence number from the low half (RFC 4303 appendix A).
    fn expand(&self, low: u32) -> Option<u64> {
        let bottom = self.highest.saturating_sub(WINDOW - 1);
        let mut candidate = (bottom & !0xffff_ffff) | u64::from(low);
        if candidate < bottom {
            candidate = candidate.checked_add(1 << 32)?;
        }
        Some(candidate)
    }

    fn was_seen(&self, sequence: u64) -> bool {
        let bit = sequence % WINDOW;
        self.seen[(bit / 64) as usize] & (1 << (bit % 64)) != 0
    }

    fn set(&mut self, sequence: u64, on: bool) {
        let bit = sequence % WINDOW;
        let word = &mut self.seen[(bit / 64) as usize];
        if on { *word |= 1 << (bit % 64) } else { *word &= !(1 << (bit % 64)) }
    }

    /// Authenticates, decrypts and replay checks one packet, returning the inner IPv4 packet.
    pub fn open(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < HEADER + GCM_IV + GCM_TAG + 2 || datagram[..4] != self.spi.to_be_bytes() {
            return None;
        }
        let low: [u8; 4] = datagram[4..8].try_into().ok()?;
        let sequence = self.expand(u32::from_be_bytes(low))?;
        if sequence == 0 || (sequence <= self.highest && self.was_seen(sequence)) {
            return None;
        }
        let high = ((sequence >> 32) as u32).to_be_bytes();
        let aad = [self.spi.to_be_bytes(), high, low].concat();
        let mut plain =
            self.key.open(&datagram[HEADER..HEADER + GCM_IV], &aad, &datagram[HEADER + GCM_IV..])?;

        // Only an authenticated packet may move the window.
        if sequence > self.highest {
            let forgotten = (sequence - self.highest).min(WINDOW);
            for old in sequence - forgotten + 1..=sequence {
                self.set(old, false);
            }
            self.highest = sequence;
        }
        self.set(sequence, true);

        let next = plain.pop()?;
        let padding = usize::from(plain.pop()?);
        plain.truncate(plain.len().checked_sub(padding)?);
        (next == NEXT_IPV4).then_some(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Sender, Receiver) {
        (Sender::new(7, &[9; 36]).unwrap(), Receiver::new(7, &[9; 36]).unwrap())
    }

    #[test]
    fn round_trips_every_padding_length() {
        let (mut tx, mut rx) = pair();
        for len in 20..40 {
            let packet = vec![0x45; len];
            let sealed = tx.seal(&packet).unwrap();
            assert_eq!((sealed.len() - HEADER - GCM_IV - GCM_TAG) % 4, 0);
            assert_eq!(rx.open(&sealed).unwrap(), packet);
        }
    }

    #[test]
    fn rejects_tampering_replays_and_other_spis() {
        let (mut tx, mut rx) = pair();
        let sealed = tx.seal(b"packet").unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(rx.open(&bad).is_none(), "byte {i}");
        }
        assert!(rx.open(&sealed).is_some());
        assert!(rx.open(&sealed).is_none(), "replay");
        assert!(rx.open(&sealed[..20]).is_none());
    }

    #[test]
    fn accepts_reordering_inside_the_window_only() {
        let (mut tx, mut rx) = pair();
        let packets: Vec<_> = (0..WINDOW + 10).map(|_| tx.seal(b"x").unwrap()).collect();
        assert!(rx.open(packets.last().unwrap()).is_some());
        assert!(rx.open(&packets[10]).is_some(), "oldest still inside");
        assert!(rx.open(&packets[9]).is_none(), "just outside");
        assert!(rx.open(&packets[500]).is_some());
        assert!(rx.open(&packets[500]).is_none());
    }

    #[test]
    fn crosses_the_32_bit_boundary() {
        let (mut tx, mut rx) = pair();
        tx.sequence = u64::from(u32::MAX) - 3;
        rx.highest = tx.sequence;
        let packets: Vec<_> = (0..8).map(|_| tx.seal(b"x").unwrap()).collect();
        for i in [0, 6, 2, 7, 3] {
            assert!(rx.open(&packets[i]).is_some(), "packet {i}");
        }
        assert!(rx.open(&packets[6]).is_none());
        assert!(rx.highest > u64::from(u32::MAX));
    }
}
