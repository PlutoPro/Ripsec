//! Cryptographic operations, all delegated to AWS-LC.

use aws_lc_rs::{aead, agreement, digest, hmac, kem, rand};

pub const DH_ECP256: u16 = 19;
pub const DH_ECP384: u16 = 20;
pub const DH_X25519: u16 = 31;
pub const KE_ML_KEM_768: u16 = 36;
pub const KE_ML_KEM_1024: u16 = 37;

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out).expect("system RNG failed");
    out
}

pub fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    parts.iter().for_each(|p| ctx.update(p));
    ctx.finish().as_ref().to_vec()
}

/// Comparison whose running time does not depend on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Prf {
    Sha256,
    Sha384,
    Sha512,
}

impl Prf {
    pub fn from_id(id: u16) -> Option<Prf> {
        match id {
            5 => Some(Prf::Sha256),
            6 => Some(Prf::Sha384),
            7 => Some(Prf::Sha512),
            _ => None,
        }
    }

    /// Output length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            Prf::Sha256 => 32,
            Prf::Sha384 => 48,
            Prf::Sha512 => 64,
        }
    }

    pub fn run(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let alg = match self {
            Prf::Sha256 => hmac::HMAC_SHA256,
            Prf::Sha384 => hmac::HMAC_SHA384,
            Prf::Sha512 => hmac::HMAC_SHA512,
        };
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(alg, key));
        parts.iter().for_each(|p| ctx.update(p));
        ctx.sign().as_ref().to_vec()
    }

    /// prf+ from RFC 7296 section 2.13.
    pub fn plus(self, key: &[u8], seed: &[&[u8]], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + self.len());
        let mut t: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while out.len() < len {
            let mut parts: Vec<&[u8]> = vec![&t];
            parts.extend_from_slice(seed);
            let count = [counter];
            parts.push(&count);
            t = self.run(key, &parts);
            out.extend_from_slice(&t);
            counter += 1;
        }
        out.truncate(len);
        out
    }
}

/// Ephemeral (EC)DH as responder: returns our public value and the shared secret.
pub fn dh_respond(group: u16, peer: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (alg, len, ecp): (&'static agreement::Algorithm, usize, bool) = match group {
        DH_X25519 => (&agreement::X25519, 32, false),
        DH_ECP256 => (&agreement::ECDH_P256, 64, true),
        DH_ECP384 => (&agreement::ECDH_P384, 96, true),
        _ => return None,
    };
    if peer.len() != len {
        return None;
    }
    // IKE omits the 0x04 "uncompressed point" prefix that the crypto library expects.
    let peer_key = if ecp { [&[4u8], peer].concat() } else { peer.to_vec() };
    let rng = rand::SystemRandom::new();
    let private = agreement::EphemeralPrivateKey::generate(alg, &rng).ok()?;
    let public = private.compute_public_key().ok()?;
    let public = public.as_ref()[usize::from(ecp)..].to_vec();
    let shared =
        agreement::agree_ephemeral(private, agreement::UnparsedPublicKey::new(alg, peer_key), (), |secret| {
            Ok(secret.to_vec())
        })
        .ok()?;
    Some((public, shared))
}

/// The initiator's half of an X25519 exchange.
pub struct DhOffer {
    private: agreement::EphemeralPrivateKey,
    pub public: Vec<u8>,
}

impl DhOffer {
    pub fn x25519() -> Option<DhOffer> {
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rand::SystemRandom::new()).ok()?;
        let public = private.compute_public_key().ok()?.as_ref().to_vec();
        Some(DhOffer { private, public })
    }

    pub fn agree(self, peer: &[u8]) -> Option<Vec<u8>> {
        if peer.len() != 32 {
            return None;
        }
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
        agreement::agree_ephemeral(self.private, peer, (), |secret| Ok(secret.to_vec())).ok()
    }
}

/// The initiator's half of an ML-KEM-768 exchange.
pub struct KemOffer {
    private: kem::DecapsulationKey,
    pub public: Vec<u8>,
}

impl KemOffer {
    pub fn ml_kem_768() -> Option<KemOffer> {
        let private = kem::DecapsulationKey::generate(&kem::ML_KEM_768).ok()?;
        let public = private.encapsulation_key().ok()?.key_bytes().ok()?.as_ref().to_vec();
        Some(KemOffer { private, public })
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // 1088 bytes is the ML-KEM-768 ciphertext size.
        if ciphertext.len() != 1088 {
            return None;
        }
        Some(self.private.decapsulate(ciphertext.into()).ok()?.as_ref().to_vec())
    }
}

/// ML-KEM encapsulation: returns (ciphertext, shared secret).
pub fn kem_respond(method: u16, peer_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let alg = match method {
        KE_ML_KEM_768 => &kem::ML_KEM_768,
        KE_ML_KEM_1024 => &kem::ML_KEM_1024,
        _ => return None,
    };
    let key = kem::EncapsulationKey::new(alg, peer_key).ok()?;
    let (ciphertext, secret) = key.encapsulate().ok()?;
    Some((ciphertext.as_ref().to_vec(), secret.as_ref().to_vec()))
}

pub const GCM_SALT: usize = 4;
pub const GCM_IV: usize = 8;
pub const GCM_TAG: usize = 16;

/// AES-GCM with a 16 byte tag as used by IKEv2 (RFC 5282).
pub struct Gcm {
    key: aead::LessSafeKey,
    salt: [u8; GCM_SALT],
}

impl Gcm {
    /// `material` is the AES key followed by the 4 byte salt.
    pub fn new(material: &[u8]) -> Option<Gcm> {
        let split = material.len().checked_sub(GCM_SALT)?;
        let alg = match split {
            16 => &aead::AES_128_GCM,
            32 => &aead::AES_256_GCM,
            _ => return None,
        };
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(alg, &material[..split]).ok()?);
        Some(Gcm { key, salt: material[split..].try_into().ok()? })
    }

    fn nonce(&self, iv: &[u8]) -> aead::Nonce {
        let mut n = [0u8; 12];
        n[..GCM_SALT].copy_from_slice(&self.salt);
        n[GCM_SALT..].copy_from_slice(iv);
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Returns ciphertext followed by the tag.
    pub fn seal(&self, iv: [u8; GCM_IV], aad: &[u8], mut data: Vec<u8>) -> Vec<u8> {
        self.key
            .seal_in_place_append_tag(self.nonce(&iv), aead::Aad::from(aad), &mut data)
            .expect("AES-GCM seal cannot fail for IKE sized messages");
        data
    }

    pub fn open(&self, iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if iv.len() != GCM_IV {
            return None;
        }
        let mut data = ciphertext.to_vec();
        let len = self.key.open_in_place(self.nonce(iv), aead::Aad::from(aad), &mut data).ok()?.len();
        data.truncate(len);
        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};

    #[test]
    fn ml_kem_secrets_agree() {
        let dk = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let ek = dk.encapsulation_key().unwrap().key_bytes().unwrap();
        let (ct, secret) = kem_respond(KE_ML_KEM_768, ek.as_ref()).unwrap();
        let theirs = dk.decapsulate(ct.as_slice().into()).unwrap();
        assert_eq!(theirs.as_ref(), secret.as_slice());
    }

    #[test]
    fn initiator_and_responder_agree() {
        let offer = DhOffer::x25519().unwrap();
        let (public, shared) = dh_respond(DH_X25519, &offer.public).unwrap();
        assert_eq!(offer.agree(&public).unwrap(), shared);
        let offer = KemOffer::ml_kem_768().unwrap();
        let (ciphertext, shared) = kem_respond(KE_ML_KEM_768, &offer.public).unwrap();
        assert_eq!(offer.decapsulate(&ciphertext).unwrap(), shared);
        assert!(offer.decapsulate(&ciphertext[1..]).is_none());
    }

    #[test]
    fn dh_rejects_wrong_sizes() {
        assert!(dh_respond(DH_X25519, &[1; 31]).is_none());
        assert!(dh_respond(DH_ECP256, &[0; 64]).is_none());
        assert!(dh_respond(14, &[1; 256]).is_none());
    }

    #[test]
    fn gcm_detects_tampering() {
        let g = Gcm::new(&[7; 36]).unwrap();
        let mut sealed = g.seal([1; 8], b"aad", b"hello".to_vec());
        assert_eq!(g.open(&[1; 8], b"aad", &sealed).unwrap(), b"hello");
        assert!(g.open(&[1; 8], b"AAD", &sealed).is_none());
        sealed[0] ^= 1;
        assert!(g.open(&[1; 8], b"aad", &sealed).is_none());
    }

    #[test]
    fn prf_plus_has_requested_length() {
        let a = Prf::Sha384.plus(b"k", &[b"seed"], 100);
        assert_eq!(a.len(), 100);
        assert_eq!(&a[..48], &Prf::Sha384.run(b"k", &[b"seed", &[1]])[..]);
    }
}
