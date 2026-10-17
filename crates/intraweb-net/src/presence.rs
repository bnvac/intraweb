//! The signed presence record every node shouts on the local network.
//!
//! The same record travels two ways: as mDNS TXT properties, and inside a UDP
//! broadcast datagram for networks that filter multicast. Both carry an Ed25519
//! signature over a canonical encoding, so a node cannot announce itself under
//! somebody else's key. Nicknames remain forgeable by design -- they are labels,
//! not identity -- and the keyring in `intraweb-core` is what notices a familiar
//! name arriving on an unfamiliar key.

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use intraweb_core::EncryptionKey;
use intraweb_core::identity::{Identity, PeerId, SIG_LEN};
use intraweb_core::sealed::SealingKey;
use intraweb_core::{PROTOCOL_VERSION, peer::now_secs};
use std::collections::HashMap;

/// Magic bytes opening every beacon datagram, so we ignore unrelated traffic
/// that happens to land on our port.
pub const BEACON_MAGIC: &[u8; 4] = b"IWB1";

/// Datagrams larger than this are dropped unread. A presence record is a few
/// hundred bytes; anything bigger is a mistake or an attempt to waste our time.
pub const MAX_BEACON_BYTES: usize = 1024;

/// How far a peer's clock may drift from ours before we distrust the record.
/// Generous, because unattended field devices often boot with no clock at all.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Prefix bound into every signature so a presence record can never be replayed
/// as a signature over some other kind of message.
const SIGNING_DOMAIN: &str = "intraweb-presence-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {
    pub version: u16,
    pub peer_id: PeerId,
    /// Announced so a private channel's key can be sealed to this peer without
    /// a separate exchange. Derived from the same vault seed but independent
    /// of the signing key, and covered by the signature, so the binding
    /// between the two keys is authenticated.
    pub encryption_key: EncryptionKey,
    pub nickname: String,
    pub api_port: u16,
    pub is_hub: bool,
    pub hub_name: String,
    pub timestamp: u64,
}

impl Presence {
    pub fn new(
        identity: &Identity,
        nickname: &str,
        api_port: u16,
        is_hub: bool,
        hub_name: &str,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            peer_id: identity.peer_id(),
            encryption_key: SealingKey::derive(identity).public(),
            nickname: scrub(nickname),
            api_port,
            is_hub,
            hub_name: scrub(hub_name),
            timestamp: now_secs(),
        }
    }

    /// Deterministic bytes covered by the signature.
    ///
    /// Built by hand rather than serialized, because a signature is only worth
    /// anything if both sides agree byte-for-byte on what was signed. Every
    /// field is scrubbed of the separator, so the encoding cannot be made
    /// ambiguous by a hostile nickname.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{SIGNING_DOMAIN}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.peer_id.to_hex(),
            self.encryption_key.to_hex(),
            self.nickname,
            self.api_port,
            u8::from(self.is_hub),
            self.hub_name,
            self.timestamp,
        )
        .into_bytes()
    }

    pub fn sign(&self, identity: &Identity) -> [u8; SIG_LEN] {
        identity.sign(&self.signing_bytes())
    }

    /// Check a record's signature and freshness against our own clock.
    pub fn verify(&self, signature: &[u8], now: u64) -> Result<()> {
        ensure!(
            self.version == PROTOCOL_VERSION,
            "unsupported protocol version {}",
            self.version
        );
        let drift = now.abs_diff(self.timestamp);
        ensure!(
            drift <= MAX_CLOCK_SKEW_SECS,
            "presence record is {drift}s out of date"
        );
        self.peer_id.verify(&self.signing_bytes(), signature)
    }

    /// Render as mDNS TXT key/value properties.
    pub fn to_txt(&self, signature: &[u8]) -> HashMap<String, String> {
        HashMap::from([
            ("v".into(), self.version.to_string()),
            ("pk".into(), self.peer_id.to_hex()),
            ("ek".into(), self.encryption_key.to_hex()),
            ("nick".into(), self.nickname.clone()),
            ("api".into(), self.api_port.to_string()),
            ("hub".into(), u8::from(self.is_hub).to_string()),
            ("hubname".into(), self.hub_name.clone()),
            ("ts".into(), self.timestamp.to_string()),
            ("sig".into(), B64.encode(signature)),
        ])
    }

    /// Rebuild a record from mDNS TXT properties, returning it with its claimed
    /// signature. The caller must still call [`Presence::verify`].
    pub fn from_txt(txt: &HashMap<String, String>) -> Result<(Self, Vec<u8>)> {
        let get = |key: &str| -> Result<String> {
            txt.get(key)
                .cloned()
                .with_context(|| format!("presence is missing '{key}'"))
        };
        let presence = Self {
            version: get("v")?.parse().context("bad version")?,
            peer_id: PeerId::parse_hex(&get("pk")?).context("bad public key")?,
            encryption_key: EncryptionKey::parse_hex(&get("ek")?).context("bad encryption key")?,
            nickname: scrub(&get("nick")?),
            api_port: get("api")?.parse().context("bad api port")?,
            is_hub: get("hub")? == "1",
            hub_name: scrub(&get("hubname").unwrap_or_default()),
            timestamp: get("ts")?.parse().context("bad timestamp")?,
        };
        let signature = B64.decode(get("sig")?).context("bad signature encoding")?;
        Ok((presence, signature))
    }

    /// Serialize into a beacon datagram: magic, length, body, signature.
    pub fn to_beacon(&self, signature: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            signature.len() == SIG_LEN,
            "signature must be {SIG_LEN} bytes"
        );
        let body = self.signing_bytes();
        let len: u16 = body
            .len()
            .try_into()
            .context("presence record is too large")?;

        let mut packet = Vec::with_capacity(BEACON_MAGIC.len() + 2 + body.len() + SIG_LEN);
        packet.extend_from_slice(BEACON_MAGIC);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(&body);
        packet.extend_from_slice(signature);
        ensure!(
            packet.len() <= MAX_BEACON_BYTES,
            "beacon datagram is too large"
        );
        Ok(packet)
    }

    /// Parse a beacon datagram. Every length is checked before it is trusted,
    /// because this runs on bytes from anyone who can reach the broadcast port.
    pub fn from_beacon(packet: &[u8]) -> Result<(Self, Vec<u8>)> {
        ensure!(
            packet.len() <= MAX_BEACON_BYTES,
            "datagram exceeds the size limit"
        );
        ensure!(
            packet.len() > BEACON_MAGIC.len() + 2 + SIG_LEN,
            "datagram is too short"
        );
        ensure!(&packet[..4] == BEACON_MAGIC, "not an intraweb beacon");

        let len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let body_start = BEACON_MAGIC.len() + 2;
        let body_end = body_start
            .checked_add(len)
            .context("declared length overflows")?;
        ensure!(
            packet.len() == body_end + SIG_LEN,
            "declared length does not match the datagram",
        );

        let body = std::str::from_utf8(&packet[body_start..body_end])
            .context("presence record is not valid utf-8")?;
        let presence = Self::from_signing_str(body)?;
        // Reject a record whose re-encoding differs from what was signed;
        // otherwise a hostile sender could smuggle fields past verification.
        ensure!(
            presence.signing_bytes() == body.as_bytes(),
            "presence record is not canonical"
        );
        Ok((presence, packet[body_end..].to_vec()))
    }

    fn from_signing_str(body: &str) -> Result<Self> {
        let parts: Vec<&str> = body.split('|').collect();
        ensure!(
            parts.len() == 9,
            "presence record has {} fields, expected 9",
            parts.len()
        );
        ensure!(parts[0] == SIGNING_DOMAIN, "unexpected signing domain");
        let is_hub = match parts[6] {
            "0" => false,
            "1" => true,
            other => bail!("bad hub flag {other:?}"),
        };
        Ok(Self {
            version: parts[1].parse().context("bad version")?,
            peer_id: PeerId::parse_hex(parts[2]).context("bad public key")?,
            encryption_key: EncryptionKey::parse_hex(parts[3]).context("bad encryption key")?,
            nickname: parts[4].to_string(),
            api_port: parts[5].parse().context("bad api port")?,
            is_hub,
            hub_name: parts[7].to_string(),
            timestamp: parts[8].parse().context("bad timestamp")?,
        })
    }
}

/// Strip anything that could confuse the signing encoding, DNS labels, or a URL.
fn scrub(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "neighbor".to_string()
    } else {
        cleaned.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presence_for(identity: &Identity) -> Presence {
        Presence::new(identity, "ben", 8420, false, "basecamp")
    }

    #[test]
    fn beacon_round_trips_and_verifies() {
        let id = Identity::generate().unwrap();
        let presence = presence_for(&id);
        let sig = presence.sign(&id);

        let packet = presence.to_beacon(&sig).unwrap();
        let (parsed, parsed_sig) = Presence::from_beacon(&packet).unwrap();

        assert_eq!(parsed, presence);
        parsed.verify(&parsed_sig, now_secs()).unwrap();
    }

    #[test]
    fn txt_round_trips_and_verifies() {
        let id = Identity::generate().unwrap();
        let presence = presence_for(&id);
        let sig = presence.sign(&id);

        let (parsed, parsed_sig) = Presence::from_txt(&presence.to_txt(&sig)).unwrap();

        assert_eq!(parsed, presence);
        parsed.verify(&parsed_sig, now_secs()).unwrap();
    }

    #[test]
    fn a_node_cannot_announce_under_another_key() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();

        // Mallory claims Alice's key but can only sign with their own.
        let mut forged = presence_for(&mallory);
        forged.peer_id = alice.peer_id();
        let sig = forged.sign(&mallory);

        assert!(
            forged.verify(&sig, now_secs()).is_err(),
            "forged identity must not verify"
        );
    }

    #[test]
    fn tampering_with_the_port_breaks_the_signature() {
        let id = Identity::generate().unwrap();
        let presence = presence_for(&id);
        let sig = presence.sign(&id);

        let mut tampered = presence.clone();
        tampered.api_port = 9999;

        assert!(tampered.verify(&sig, now_secs()).is_err());
    }

    #[test]
    fn stale_records_are_rejected() {
        let id = Identity::generate().unwrap();
        let presence = presence_for(&id);
        let sig = presence.sign(&id);

        let far_future = presence.timestamp + MAX_CLOCK_SKEW_SECS + 60;
        assert!(
            presence.verify(&sig, far_future).is_err(),
            "replayed record must be refused"
        );
        assert!(
            presence.verify(&sig, presence.timestamp + 10).is_ok(),
            "small drift is fine"
        );
    }

    #[test]
    fn junk_datagrams_are_refused_without_panicking() {
        // Every one of these is something a stranger can put on the wire.
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"IWB1".to_vec(),
            b"XXXX\x00\x10short".to_vec(),
            {
                // Declared length far beyond the datagram.
                let mut p = BEACON_MAGIC.to_vec();
                p.extend_from_slice(&u16::MAX.to_be_bytes());
                p.extend_from_slice(&[0u8; 80]);
                p
            },
            vec![0xff; MAX_BEACON_BYTES * 2],
        ];
        for case in cases {
            assert!(
                Presence::from_beacon(&case).is_err(),
                "should reject {} bytes",
                case.len()
            );
        }
    }

    #[test]
    fn hostile_nicknames_cannot_break_the_encoding() {
        let id = Identity::generate().unwrap();
        // A nickname stuffed with separators would let a sender forge extra
        // fields if it reached the encoder intact.
        let presence = Presence::new(&id, "a|b|9999|1|evil", 8420, false, "hub");
        assert!(!presence.nickname.contains('|'));

        let sig = presence.sign(&id);
        let packet = presence.to_beacon(&sig).unwrap();
        let (parsed, parsed_sig) = Presence::from_beacon(&packet).unwrap();
        parsed.verify(&parsed_sig, now_secs()).unwrap();
        assert_eq!(
            parsed.api_port, 8420,
            "fields must not be smuggled in via the nickname"
        );
    }
}
