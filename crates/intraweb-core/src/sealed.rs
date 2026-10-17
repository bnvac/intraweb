//! Encryption for private channels.
//!
//! Your signing key is not used for this. The Ed25519 library says plainly not
//! to reuse a signing key for key agreement, and it is right -- so an
//! independent X25519 key is derived from the vault seed with HKDF and a
//! domain label. Separate key material, but still the one file you back up, so
//! copying the vault still copies all of you.
//!
//! What this buys: a private channel that is actually private. Posts cross the
//! same open network as everything else, where anyone holding the wifi
//! password is listening, so delivering only to members would be a promise the
//! wire does not keep.

use crate::hex;
use crate::identity::Identity;
use anyhow::{Context, Result, ensure};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Separates this key from anything else ever derived from the same seed.
const KEY_DERIVATION_LABEL: &[u8] = b"intraweb-x25519-v1";
/// Separates a channel-key wrapping from any other use of a shared secret.
const WRAP_LABEL: &[u8] = b"intraweb-channel-key-wrap-v1";

pub const ENCRYPTION_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Somebody's public encryption key, announced alongside their identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EncryptionKey([u8; ENCRYPTION_KEY_LEN]);

impl EncryptionKey {
    pub fn from_bytes(bytes: [u8; ENCRYPTION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }

    pub fn parse_hex(s: &str) -> Option<Self> {
        hex::decode_array::<ENCRYPTION_KEY_LEN>(s).map(Self)
    }
}

impl Serialize for EncryptionKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid encryption key"))
    }
}

/// The private half, derived from the vault seed.
pub struct SealingKey {
    secret: StaticSecret,
}

impl SealingKey {
    /// Derive this vault's encryption key: deterministic, so it needs no extra
    /// file and survives a vault copy, yet independent of the signing scalar.
    pub fn derive(identity: &Identity) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::new(None, identity.seed());
        let mut material = [0u8; ENCRYPTION_KEY_LEN];
        hk.expand(KEY_DERIVATION_LABEL, &mut material)
            .expect("32 bytes is a valid HKDF length");
        Self {
            secret: StaticSecret::from(material),
        }
    }

    pub fn public(&self) -> EncryptionKey {
        EncryptionKey(PublicKey::from(&self.secret).to_bytes())
    }

    /// Shared secret with another party, bound to a purpose.
    fn shared_key(&self, peer: &EncryptionKey, label: &[u8]) -> Key {
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(*peer.as_bytes()));
        let hk = hkdf::Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(label, &mut key)
            .expect("32 bytes is a valid HKDF length");
        Key::from(key)
    }
}

/// A secret wrapped for exactly one recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub nonce: String,
    pub ciphertext: String,
}

/// Wrap a channel key so only the holder of `recipient` can read it.
pub fn wrap_for(
    sender: &SealingKey,
    recipient: &EncryptionKey,
    channel_key: &[u8; 32],
) -> Result<WrappedKey> {
    let cipher = ChaCha20Poly1305::new(&sender.shared_key(recipient, WRAP_LABEL));
    let nonce_bytes = random_nonce()?;
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce_bytes), channel_key.as_slice())
        .map_err(|_| anyhow::anyhow!("could not wrap the channel key"))?;

    Ok(WrappedKey {
        nonce: hex::encode(&nonce_bytes),
        ciphertext: hex::encode(&ciphertext),
    })
}

/// Unwrap a channel key addressed to us.
pub fn unwrap_from(
    receiver: &SealingKey,
    sender: &EncryptionKey,
    wrapped: &WrappedKey,
) -> Result<[u8; 32]> {
    let nonce_bytes = hex::decode_array::<NONCE_LEN>(&wrapped.nonce).context("malformed nonce")?;
    let ciphertext = decode_hex_vec(&wrapped.ciphertext).context("malformed wrapped key")?;

    let cipher = ChaCha20Poly1305::new(&receiver.shared_key(sender, WRAP_LABEL));
    let plain = cipher
        .decrypt(&Nonce::from(nonce_bytes), ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("that channel key was not sealed for us"))?;

    let key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .context("channel key is the wrong size")?;
    Ok(key)
}

/// Encrypt one post with a channel key.
pub fn seal_with_channel_key(channel_key: &[u8; 32], plaintext: &str) -> Result<(String, String)> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*channel_key));
    let nonce_bytes = random_nonce()?;
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce_bytes), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("could not encrypt the message"))?;
    Ok((hex::encode(&nonce_bytes), hex::encode(&ciphertext)))
}

/// Decrypt one post with a channel key.
pub fn open_with_channel_key(
    channel_key: &[u8; 32],
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<String> {
    let nonce_bytes = hex::decode_array::<NONCE_LEN>(nonce_hex).context("malformed nonce")?;
    let ciphertext = decode_hex_vec(ciphertext_hex).context("malformed ciphertext")?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*channel_key));
    let plain = cipher
        .decrypt(&Nonce::from(nonce_bytes), ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("could not decrypt; wrong key or the message was altered"))?;

    String::from_utf8(plain).context("decrypted message is not valid utf-8")
}

/// A fresh random channel key.
pub fn new_channel_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|e| anyhow::anyhow!("could not read entropy for a channel key: {e}"))?;
    Ok(key)
}

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("could not read entropy for a nonce: {e}"))?;
    Ok(nonce)
}

fn decode_hex_vec(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "hex string has an odd length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).context("invalid hex"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encryption_key_is_not_the_signing_key() {
        // The whole reason this module derives rather than reuses.
        let id = Identity::generate().unwrap();
        assert_ne!(
            SealingKey::derive(&id).public().as_bytes(),
            id.peer_id().as_bytes()
        );
    }

    #[test]
    fn the_same_vault_always_derives_the_same_encryption_key() {
        // Portability: copy the vault, keep the ability to read your channels.
        let id = Identity::generate().unwrap();
        assert_eq!(
            SealingKey::derive(&id).public(),
            SealingKey::derive(&id).public()
        );
    }

    #[test]
    fn different_vaults_derive_different_keys() {
        let a = SealingKey::derive(&Identity::generate().unwrap());
        let b = SealingKey::derive(&Identity::generate().unwrap());
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn a_member_can_unwrap_the_channel_key() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (ak, bk) = (SealingKey::derive(&alice), SealingKey::derive(&bob));
        let channel_key = new_channel_key().unwrap();

        let wrapped = wrap_for(&ak, &bk.public(), &channel_key).unwrap();
        assert_eq!(
            unwrap_from(&bk, &ak.public(), &wrapped).unwrap(),
            channel_key
        );
    }

    #[test]
    fn an_outsider_cannot_unwrap_the_channel_key() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let mallory = Identity::generate().unwrap();
        let (ak, bk) = (SealingKey::derive(&alice), SealingKey::derive(&bob));
        let mk = SealingKey::derive(&mallory);
        let channel_key = new_channel_key().unwrap();

        let wrapped = wrap_for(&ak, &bk.public(), &channel_key).unwrap();

        assert!(
            unwrap_from(&mk, &ak.public(), &wrapped).is_err(),
            "somebody never invited must not get the key",
        );
    }

    #[test]
    fn a_post_round_trips_through_the_channel_key() {
        let key = new_channel_key().unwrap();
        let (nonce, ciphertext) = seal_with_channel_key(&key, "meet at the gate").unwrap();
        assert_eq!(
            open_with_channel_key(&key, &nonce, &ciphertext).unwrap(),
            "meet at the gate"
        );
    }

    #[test]
    fn the_wrong_channel_key_cannot_read_a_post() {
        let key = new_channel_key().unwrap();
        let other = new_channel_key().unwrap();
        let (nonce, ciphertext) = seal_with_channel_key(&key, "secret").unwrap();
        assert!(open_with_channel_key(&other, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn an_altered_post_is_refused_rather_than_mangled() {
        // The point of an AEAD: tampering fails loudly instead of decrypting
        // to something plausible.
        let key = new_channel_key().unwrap();
        let (nonce, ciphertext) = seal_with_channel_key(&key, "fuel at 0600").unwrap();

        let mut bytes = decode_hex_vec(&ciphertext).unwrap();
        bytes[0] ^= 0x01;

        assert!(open_with_channel_key(&key, &nonce, &hex::encode(&bytes)).is_err());
    }

    #[test]
    fn every_post_gets_a_fresh_nonce() {
        // Reusing a nonce with the same key breaks the cipher outright.
        let key = new_channel_key().unwrap();
        let (first, _) = seal_with_channel_key(&key, "same text").unwrap();
        let (second, _) = seal_with_channel_key(&key, "same text").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn junk_ciphertext_is_refused_without_panicking() {
        let key = new_channel_key().unwrap();
        let zeros = "0".repeat(24);
        for (nonce, text) in [("", ""), ("zz", "zz"), ("00", "0"), (zeros.as_str(), "ff")] {
            assert!(open_with_channel_key(&key, nonce, text).is_err());
        }
    }
}
