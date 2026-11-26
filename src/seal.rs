//! Encryption of device secrets before they are stored anywhere (AES-256-GCM).

use crate::ike::crypto;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const PREFIX: &str = "v1:";
pub const KEY_ENV: &str = "RIPSEC_MASTER_KEY";

pub struct Vault {
    key: LessSafeKey,
}

impl Vault {
    pub fn new(key: &[u8; 32]) -> Vault {
        let key = UnboundKey::new(&AES_256_GCM, key).expect("AES-256 keys are 32 bytes");
        Vault { key: LessSafeKey::new(key) }
    }

    fn decode_key(text: &str) -> io::Result<Vault> {
        let key: [u8; 32] = STANDARD
            .decode(text.trim())
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| io::Error::other("master key must be 32 bytes, base64 encoded"))?;
        Ok(Vault::new(&key))
    }

    /// Uses the key from the environment or `path`. A new key is only created when
    /// `may_create` is set, so a lost key is never silently replaced.
    pub fn open_or_create(path: &Path, may_create: bool) -> io::Result<Vault> {
        if let Ok(text) = std::env::var(KEY_ENV) {
            return Vault::decode_key(&text);
        }
        match fs::read_to_string(path) {
            Ok(text) => Vault::decode_key(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound && may_create => {
                let key: [u8; 32] = crypto::random();
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                let mut file = options.open(path)?;
                file.write_all(STANDARD.encode(key).as_bytes())?;
                file.sync_all()?;
                Ok(Vault::new(&key))
            }
            Err(e) => Err(io::Error::new(e.kind(), format!("master key {}: {e}", path.display()))),
        }
    }

    /// `context` (the device ID) is authenticated, so values cannot be swapped between devices.
    pub fn seal(&self, context: &str, secret: &str) -> String {
        let nonce: [u8; NONCE_LEN] = crypto::random();
        let mut data = secret.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context.as_bytes()),
                &mut data,
            )
            .expect("sealing a short secret cannot fail");
        format!("{PREFIX}{}", STANDARD.encode([&nonce[..], &data].concat()))
    }

    pub fn open(&self, context: &str, sealed: &str) -> Option<String> {
        let bytes = STANDARD.decode(sealed.strip_prefix(PREFIX)?).ok()?;
        let (nonce, data) = bytes.split_at_checked(NONCE_LEN)?;
        let mut data = data.to_vec();
        let plain = self
            .key
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).ok()?,
                Aad::from(context.as_bytes()),
                &mut data,
            )
            .ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_are_bound_to_their_device_and_key() {
        let vault = Vault::new(&[1; 32]);
        let sealed = vault.seal("a@ripsec", "secret");
        assert!(sealed.starts_with("v1:") && !sealed.contains("secret") && !sealed.contains('\n'));
        assert_eq!(vault.open("a@ripsec", &sealed).as_deref(), Some("secret"));
        assert_eq!(vault.open("b@ripsec", &sealed), None);
        assert_eq!(Vault::new(&[2; 32]).open("a@ripsec", &sealed), None);
        assert_ne!(vault.seal("a@ripsec", "secret"), sealed, "nonces must differ");
        assert_eq!(vault.open("a@ripsec", "v1:AAAA"), None);
    }
}
