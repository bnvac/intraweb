//! Ed25519 identity: the portable root of who you are on the neighborhood web.
//!
//! Your identity is a keypair, not an account on somebody's server. Copy the
//! vault to another machine and you are still you, at every hub you join. Hubs
//! never hold your key and cannot mint an identity on your behalf.

use crate::hex;
use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

pub const SEED_LEN: usize = 32;
pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

/// Bytes of the public-key digest shown to humans for out-of-band checks.
/// Eight bytes is 64 bits of grinding work to collide -- enough to read aloud.
const FINGERPRINT_BYTES: usize = 8;

/// A peer's public identity: the 32-byte Ed25519 verifying key.
///
/// This is the only durable name in the system. Nicknames are decoration and
/// may collide; a `PeerId` is the thing that actually identifies someone.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; PUBKEY_LEN]);

impl PeerId {
    pub fn from_bytes(bytes: [u8; PUBKEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_LEN] {
        &self.0
    }

    /// Parse the 64-character hex form used on the wire and in the database.
    pub fn parse_hex(s: &str) -> Option<Self> {
        hex::decode_array::<PUBKEY_LEN>(s).map(Self)
    }

    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }

    /// Short human-checkable digest, e.g. `a1b2-c3d4-e5f6-7890`.
    ///
    /// Two people comparing this over the radio is the whole out-of-band
    /// verification story. It is a digest of the key, not a prefix of it, so
    /// it stays meaningful even if key formats gain structure later.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        let short = &digest[..FINGERPRINT_BYTES];
        let mut out = String::with_capacity(FINGERPRINT_BYTES * 2 + 3);
        for (i, byte) in short.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                out.push('-');
            }
            out.push_str(&hex::encode(&[*byte]));
        }
        out
    }

    /// Verify a detached signature made by this peer.
    ///
    /// Uses `verify_strict`, which rejects small-order and otherwise degenerate
    /// keys. On an open LAN we assume packets are hostile until proven otherwise.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.0).context("malformed public key")?;
        let sig_bytes: [u8; SIG_LEN] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature must be {SIG_LEN} bytes"))?;
        key.verify_strict(message, &Signature::from_bytes(&sig_bytes))
            .context("signature did not verify")
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.fingerprint())
    }
}

impl Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid peer id"))
    }
}

/// A loaded secret identity. Keep it in the vault; never send it to a hub.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Mint a brand new identity from operating-system entropy.
    ///
    /// We seed from `getrandom` rather than taking an RNG parameter so this
    /// crate is not coupled to whichever `rand_core` major version the signing
    /// library currently tracks.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        getrandom::fill(&mut seed).map_err(|e| {
            anyhow::anyhow!("could not read entropy from the operating system: {e}")
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The raw seed, for deriving other key material from this vault.
    ///
    /// Only `sealed` should need this, and only through HKDF with a domain
    /// label -- never to sign or encrypt with directly.
    pub(crate) fn seed(&self) -> &[u8; SEED_LEN] {
        self.signing.as_bytes()
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId(self.signing.verifying_key().to_bytes())
    }

    pub fn fingerprint(&self) -> String {
        self.peer_id().fingerprint()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Load an identity from disk, creating one on first run.
    ///
    /// Returns `true` alongside the identity when a new key was minted, so the
    /// caller can tell the operator to back up their vault.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            return Ok((Self::load(path)?, false));
        }
        let identity = Self::generate()?;
        identity.save(path)?;
        Ok((identity, true))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("could not read identity at {}", path.display()))?;
        let seed_hex = raw
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .context("identity file contains no key")?;
        let Some(seed) = hex::decode_array::<SEED_LEN>(seed_hex) else {
            bail!(
                "identity at {} is corrupt: expected {SEED_LEN} hex-encoded bytes",
                path.display()
            );
        };
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Write the identity, readable only by its owner.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let body = format!(
            "# intraweb identity v1 -- KEEP THIS SECRET.\n\
             # This single line is your identity at every hub you ever join.\n\
             # Back up the whole vault folder; losing this file loses your name.\n\
             {}\n",
            hex::encode(self.signing.as_bytes())
        );
        std::fs::write(path, body)
            .with_context(|| format!("could not write identity to {}", path.display()))?;
        restrict_permissions(path)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("could not restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    // Windows inherits the user profile ACL, which is already owner-only.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies() {
        let id = Identity::generate().unwrap();
        let sig = id.sign(b"hello neighbor");
        id.peer_id().verify(b"hello neighbor", &sig).unwrap();
    }

    #[test]
    fn rejects_tampered_message() {
        let id = Identity::generate().unwrap();
        let sig = id.sign(b"hello neighbor");
        assert!(id.peer_id().verify(b"hello stranger", &sig).is_err());
    }

    #[test]
    fn rejects_other_signer() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let sig = mallory.sign(b"i am alice");
        assert!(alice.peer_id().verify(b"i am alice", &sig).is_err());
    }

    #[test]
    fn identity_survives_a_round_trip_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let (first, created) = Identity::load_or_create(&path).unwrap();
        assert!(created, "first call should mint a key");
        let (second, created_again) = Identity::load_or_create(&path).unwrap();
        assert!(!created_again, "second call should reuse the key");

        // This is the portability promise: same vault, same name.
        assert_eq!(first.peer_id(), second.peer_id());
    }

    #[test]
    fn peer_id_hex_round_trips() {
        let id = Identity::generate().unwrap();
        let peer = id.peer_id();
        assert_eq!(PeerId::parse_hex(&peer.to_hex()), Some(peer));
    }

    #[test]
    fn fingerprint_is_human_shaped() {
        let peer = Identity::generate().unwrap().peer_id();
        let fp = peer.fingerprint();
        assert_eq!(fp.len(), 19, "8 bytes as 4 hyphenated groups");
        assert_eq!(fp.matches('-').count(), 3);
    }
}
