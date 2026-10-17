//! Channels: the neighborhood one everybody can read, and private ones only
//! members can.
//!
//! A post is signed the way mail is, so authorship cannot be forged, and a
//! private post is additionally encrypted under a channel key that only
//! members hold. There is no central log: posting means handing the message to
//! each recipient's node directly, and each node keeps its own copy. No hub
//! ever carries a channel.

use crate::identity::{Identity, PeerId, SIG_LEN};
use crate::sealed;
use crate::{hex, peer::now_secs};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POST_VERSION: u16 = 1;
pub const MAX_POST_BYTES: usize = 8 * 1024;
/// Channel names are shown in lists and typed at the command line.
pub const MAX_CHANNEL_NAME: usize = 40;

const SIGNING_DOMAIN: &str = "intraweb-post-v1";
const INVITE_DOMAIN: &str = "intraweb-invite-v1";
/// The neighborhood channel's id is fixed, so every node computes the same one
/// without anybody creating or announcing it.
const NEIGHBORHOOD_LABEL: &[u8] = b"intraweb-neighborhood-channel-v1";
/// A guestbook is a public channel belonging to one key, so its id is derived
/// from that key. Anyone can compute where to sign; only the owner keeps it.
const GUESTBOOK_LABEL: &[u8] = b"intraweb-guestbook-v1";

/// Identifies a channel. Random for a private one, fixed for the public one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ChannelId([u8; 32]);

impl ChannelId {
    /// The channel everybody on the network is implicitly in.
    pub fn neighborhood() -> Self {
        Self(Sha256::digest(NEIGHBORHOOD_LABEL).into())
    }

    pub fn is_neighborhood(&self) -> bool {
        *self == Self::neighborhood()
    }

    /// The channel that is somebody's guestbook.
    ///
    /// A guestbook needs no new machinery: it is a public channel whose id
    /// everybody can derive from the owner's key, so signing it reuses the
    /// same signed posts, deduplication, rate limiting and blocking as any
    /// other channel.
    pub fn guestbook_of(owner: PeerId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(GUESTBOOK_LABEL);
        hasher.update(owner.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn is_guestbook_of(&self, owner: PeerId) -> bool {
        *self == Self::guestbook_of(owner)
    }

    pub fn new_private() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| anyhow::anyhow!("could not read entropy for a channel id: {e}"))?;
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }

    pub fn parse_hex(s: &str) -> Option<Self> {
        hex::decode_array::<32>(s).map(Self)
    }

    /// Short form for listings and for typing.
    pub fn short(&self) -> String {
        self.to_hex().chars().take(8).collect()
    }
}

impl Serialize for ChannelId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid channel id"))
    }
}

/// One message in a channel, as it travels.
///
/// `body` is the message for a public channel and hex ciphertext for a private
/// one. The signature covers both cases identically, so authorship is provable
/// whether or not the reader can decrypt it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    pub version: u16,
    pub channel: ChannelId,
    pub from: PeerId,
    pub created_at: u64,
    /// Empty when the post is not encrypted.
    #[serde(default)]
    pub nonce: String,
    pub body: String,
    pub encrypted: bool,
}

impl Post {
    /// A message anybody in range may read.
    pub fn public(channel: ChannelId, from: PeerId, body: &str) -> Self {
        Self {
            version: POST_VERSION,
            channel,
            from,
            created_at: now_secs(),
            nonce: String::new(),
            body: body.to_string(),
            encrypted: false,
        }
    }

    /// A message only channel members can read.
    pub fn private(
        channel: ChannelId,
        from: PeerId,
        channel_key: &[u8; 32],
        body: &str,
    ) -> Result<Self> {
        ensure!(body.len() <= MAX_POST_BYTES, "that message is too long");
        let (nonce, ciphertext) = sealed::seal_with_channel_key(channel_key, body)?;
        Ok(Self {
            version: POST_VERSION,
            channel,
            from,
            created_at: now_secs(),
            nonce,
            body: ciphertext,
            encrypted: true,
        })
    }

    /// Read a private post, given the channel key.
    pub fn open(&self, channel_key: &[u8; 32]) -> Result<String> {
        if !self.encrypted {
            return Ok(self.body.clone());
        }
        sealed::open_with_channel_key(channel_key, &self.nonce, &self.body)
    }

    /// Deterministic bytes covered by the signature. Body and nonce are
    /// base64'd so a message containing the separator cannot forge fields.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{SIGNING_DOMAIN}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.channel.to_hex(),
            self.from.to_hex(),
            self.created_at,
            u8::from(self.encrypted),
            B64.encode(self.nonce.as_bytes()),
            B64.encode(self.body.as_bytes()),
        )
        .into_bytes()
    }

    pub fn check_limits(&self) -> Result<()> {
        ensure!(
            self.body.len() <= MAX_POST_BYTES * 2,
            "that message is too long"
        );
        Ok(())
    }

    pub fn sign(&self, identity: &Identity) -> [u8; SIG_LEN] {
        identity.sign(&self.signing_bytes())
    }

    pub fn verify(&self, signature: &[u8]) -> Result<()> {
        ensure!(
            self.version == POST_VERSION,
            "unsupported post version {}",
            self.version
        );
        self.check_limits()?;
        self.from.verify(&self.signing_bytes(), signature)
    }
}

/// A post as it travels, as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPost {
    #[serde(flatten)]
    pub post: Post,
    pub signature: String,
}

impl SignedPost {
    pub fn seal(post: Post, identity: &Identity) -> Result<Self> {
        post.check_limits()?;
        Ok(Self {
            signature: B64.encode(post.sign(identity)),
            post,
        })
    }

    /// Verify the signature really belongs to the key the post names.
    pub fn accept(&self) -> Result<()> {
        let signature = B64
            .decode(&self.signature)
            .context("signature is not valid base64")?;
        self.post.verify(&signature)
    }
}

/// An invitation to a private channel, carrying the channel key sealed so that
/// only the invitee can open it.
///
/// Signed by the inviter, so a stranger cannot push a channel into somebody's
/// list, and encrypted to the invitee, so the key is safe on a network where
/// anyone with the wifi password is listening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub version: u16,
    pub channel: ChannelId,
    pub name: String,
    pub from: PeerId,
    pub to: PeerId,
    pub created_at: u64,
    pub wrapped_key: sealed::WrappedKey,
    pub signature: String,
}

impl Invite {
    /// Seal a channel key for one member.
    pub fn create(
        identity: &Identity,
        sealing: &sealed::SealingKey,
        recipient: PeerId,
        recipient_key: &sealed::EncryptionKey,
        channel: ChannelId,
        name: &str,
        channel_key: &[u8; 32],
    ) -> Result<Self> {
        let wrapped = sealed::wrap_for(sealing, recipient_key, channel_key)?;
        let mut invite = Self {
            version: POST_VERSION,
            channel,
            name: scrub_channel_name(name),
            from: identity.peer_id(),
            to: recipient,
            created_at: now_secs(),
            wrapped_key: wrapped,
            signature: String::new(),
        };
        invite.signature = B64.encode(identity.sign(&invite.signing_bytes()));
        Ok(invite)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{INVITE_DOMAIN}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.version,
            self.channel.to_hex(),
            B64.encode(self.name.as_bytes()),
            self.from.to_hex(),
            self.to.to_hex(),
            self.created_at,
            self.wrapped_key.nonce,
            self.wrapped_key.ciphertext,
        )
        .into_bytes()
    }

    /// Check the invitation is genuine and meant for us, then open the key.
    pub fn accept(
        &self,
        me: PeerId,
        my_sealing: &sealed::SealingKey,
        inviter_key: &sealed::EncryptionKey,
    ) -> Result<[u8; 32]> {
        ensure!(self.version == POST_VERSION, "unsupported invite version");
        ensure!(self.to == me, "that invitation is for somebody else");

        let signature = B64
            .decode(&self.signature)
            .context("signature is not valid base64")?;
        self.from
            .verify(&self.signing_bytes(), &signature)
            .context("the invitation is not signed by who it claims")?;

        sealed::unwrap_from(my_sealing, inviter_key, &self.wrapped_key)
    }
}

/// Scrub a channel name for display and for typing at a prompt.
pub fn scrub_channel_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
        .take(MAX_CHANNEL_NAME)
        .collect();
    let trimmed = cleaned.trim().to_string();
    if trimmed.is_empty() {
        "channel".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::{SealingKey, new_channel_key};

    #[test]
    fn every_node_computes_the_same_neighborhood_channel() {
        // Nobody creates it and nobody announces it; it simply is.
        assert_eq!(ChannelId::neighborhood(), ChannelId::neighborhood());
        assert!(ChannelId::neighborhood().is_neighborhood());
    }

    #[test]
    fn a_guestbook_belongs_to_exactly_one_key() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());

        // Anybody can work out where to sign, without being told.
        assert_eq!(
            ChannelId::guestbook_of(alice.peer_id()),
            ChannelId::guestbook_of(alice.peer_id()),
        );
        assert_ne!(
            ChannelId::guestbook_of(alice.peer_id()),
            ChannelId::guestbook_of(bob.peer_id()),
        );

        assert!(ChannelId::guestbook_of(alice.peer_id()).is_guestbook_of(alice.peer_id()));
        assert!(!ChannelId::guestbook_of(alice.peer_id()).is_guestbook_of(bob.peer_id()));
    }

    #[test]
    fn a_guestbook_is_not_the_neighborhood_channel() {
        let alice = Identity::generate().unwrap();
        assert!(!ChannelId::guestbook_of(alice.peer_id()).is_neighborhood());
    }

    #[test]
    fn private_channels_get_distinct_ids() {
        let a = ChannelId::new_private().unwrap();
        let b = ChannelId::new_private().unwrap();
        assert_ne!(a, b);
        assert!(!a.is_neighborhood());
    }

    #[test]
    fn a_public_post_is_readable_and_its_author_provable() {
        let alice = Identity::generate().unwrap();
        let sealed = SignedPost::seal(
            Post::public(ChannelId::neighborhood(), alice.peer_id(), "gate open"),
            &alice,
        )
        .unwrap();

        sealed.accept().unwrap();
        assert_eq!(sealed.post.body, "gate open");
        assert!(!sealed.post.encrypted);
    }

    #[test]
    fn a_private_post_is_unreadable_without_the_channel_key() {
        let alice = Identity::generate().unwrap();
        let channel = ChannelId::new_private().unwrap();
        let key = new_channel_key().unwrap();

        let sealed = SignedPost::seal(
            Post::private(channel, alice.peer_id(), &key, "meet at the ridge").unwrap(),
            &alice,
        )
        .unwrap();

        // Anyone can confirm who wrote it; only members can read it.
        sealed.accept().unwrap();
        assert!(!sealed.post.body.contains("ridge"));
        assert_eq!(sealed.post.open(&key).unwrap(), "meet at the ridge");
        assert!(sealed.post.open(&new_channel_key().unwrap()).is_err());
    }

    #[test]
    fn a_forged_author_does_not_verify() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();

        let post = Post::public(ChannelId::neighborhood(), alice.peer_id(), "stand down");
        let sealed = SignedPost {
            signature: B64.encode(post.sign(&mallory)),
            post,
        };

        assert!(sealed.accept().is_err(), "mallory cannot post as alice");
    }

    #[test]
    fn editing_a_post_breaks_its_signature() {
        let alice = Identity::generate().unwrap();
        let mut sealed = SignedPost::seal(
            Post::public(ChannelId::neighborhood(), alice.peer_id(), "0600"),
            &alice,
        )
        .unwrap();

        sealed.post.body = "0900".into();
        assert!(sealed.accept().is_err());
    }

    #[test]
    fn moving_a_post_to_another_channel_breaks_its_signature() {
        // Otherwise a private post could be replayed into the public channel.
        let alice = Identity::generate().unwrap();
        let mut sealed = SignedPost::seal(
            Post::public(
                ChannelId::new_private().unwrap(),
                alice.peer_id(),
                "internal",
            ),
            &alice,
        )
        .unwrap();

        sealed.post.channel = ChannelId::neighborhood();
        assert!(sealed.accept().is_err());
    }

    #[test]
    fn separators_in_a_message_cannot_forge_fields() {
        let alice = Identity::generate().unwrap();
        let hostile = "|1|deadbeef|9999|1|";
        let sealed = SignedPost::seal(
            Post::public(ChannelId::neighborhood(), alice.peer_id(), hostile),
            &alice,
        )
        .unwrap();

        sealed.accept().unwrap();
        assert_eq!(sealed.post.body, hostile);
    }

    #[test]
    fn an_oversized_post_is_refused() {
        let alice = Identity::generate().unwrap();
        let key = new_channel_key().unwrap();
        let huge = "x".repeat(MAX_POST_BYTES + 1);

        assert!(
            Post::private(
                ChannelId::new_private().unwrap(),
                alice.peer_id(),
                &key,
                &huge
            )
            .is_err()
        );
    }

    #[test]
    fn the_envelope_round_trips_as_json() {
        let alice = Identity::generate().unwrap();
        let key = new_channel_key().unwrap();
        let channel = ChannelId::new_private().unwrap();
        let sealed = SignedPost::seal(
            Post::private(channel, alice.peer_id(), &key, "hello").unwrap(),
            &alice,
        )
        .unwrap();

        let parsed: SignedPost =
            serde_json::from_str(&serde_json::to_string(&sealed).unwrap()).unwrap();

        parsed.accept().unwrap();
        assert_eq!(parsed.post.open(&key).unwrap(), "hello");
    }

    #[test]
    fn an_invited_member_can_open_the_channel_key() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (ak, bk) = (SealingKey::derive(&alice), SealingKey::derive(&bob));
        let channel = ChannelId::new_private().unwrap();
        let key = new_channel_key().unwrap();

        let invite = Invite::create(
            &alice,
            &ak,
            bob.peer_id(),
            &bk.public(),
            channel,
            "crew",
            &key,
        )
        .unwrap();

        assert_eq!(
            invite.accept(bob.peer_id(), &bk, &ak.public()).unwrap(),
            key
        );
    }

    #[test]
    fn an_invitation_for_somebody_else_is_refused() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let mallory = Identity::generate().unwrap();
        let (ak, bk, mk) = (
            SealingKey::derive(&alice),
            SealingKey::derive(&bob),
            SealingKey::derive(&mallory),
        );
        let key = new_channel_key().unwrap();

        let invite = Invite::create(
            &alice,
            &ak,
            bob.peer_id(),
            &bk.public(),
            ChannelId::new_private().unwrap(),
            "crew",
            &key,
        )
        .unwrap();

        assert!(invite.accept(mallory.peer_id(), &mk, &ak.public()).is_err());
    }

    #[test]
    fn a_forged_invitation_is_refused() {
        // Otherwise anybody could push a channel into your list.
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let mallory = Identity::generate().unwrap();
        let (ak, bk, mk) = (
            SealingKey::derive(&alice),
            SealingKey::derive(&bob),
            SealingKey::derive(&mallory),
        );
        let key = new_channel_key().unwrap();

        let mut invite = Invite::create(
            &mallory,
            &mk,
            bob.peer_id(),
            &bk.public(),
            ChannelId::new_private().unwrap(),
            "crew",
            &key,
        )
        .unwrap();
        invite.from = alice.peer_id();

        assert!(invite.accept(bob.peer_id(), &bk, &ak.public()).is_err());
    }

    #[test]
    fn tampering_with_an_invitation_breaks_it() {
        let (alice, bob) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (ak, bk) = (SealingKey::derive(&alice), SealingKey::derive(&bob));
        let key = new_channel_key().unwrap();
        let mut invite = Invite::create(
            &alice,
            &ak,
            bob.peer_id(),
            &bk.public(),
            ChannelId::new_private().unwrap(),
            "crew",
            &key,
        )
        .unwrap();

        invite.name = "somewhere else".into();
        assert!(invite.accept(bob.peer_id(), &bk, &ak.public()).is_err());
    }

    #[test]
    fn channel_names_are_scrubbed() {
        assert_eq!(
            scrub_channel_name("Ridge Crew <script>"),
            "Ridge Crew script"
        );
        assert_eq!(scrub_channel_name("!!!"), "channel");
        assert_eq!(scrub_channel_name(&"x".repeat(100)).len(), MAX_CHANNEL_NAME);
    }
}
