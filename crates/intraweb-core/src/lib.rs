//! Core types for intraweb: your neighborhood web.
//!
//! The organizing idea is that a person is a keypair and a folder, and a hub is
//! only a place to meet. Nothing here knows how to talk to a network; that is
//! `intraweb-net`'s job. Keeping the split lets the discovery layer be swapped
//! or tested without touching identity or storage.

pub mod channel;
pub mod config;
pub mod db;
pub mod hex;
pub mod identicon;
pub mod identity;
pub mod mail;
pub mod peer;
pub mod sealed;
pub mod vault;

pub use channel::{ChannelId, Post, SignedPost};
pub use config::Config;
pub use db::Store;
pub use identity::{Identity, PeerId};
pub use mail::{Mail, SignedMail};
pub use peer::{DiscoverySource, Peer, TrustState, now_secs};
pub use sealed::{EncryptionKey, SealingKey};
pub use vault::{Runtime, Vault};

/// Wire-protocol version. Bumped when the discovery payload changes shape, so
/// a node from a future release is skipped rather than misread.
///
/// v3 announces an encryption key alongside the identity, so a private
/// channel's key can be sealed to a member without a separate exchange.
///
/// v2 dropped the separate transport port: mail and file transfer ride the
/// node's own HTTP port, which already gives resumable ranged downloads and
/// keeps every exchange on one directly-dialled socket.
pub const PROTOCOL_VERSION: u16 = 3;

/// mDNS service type every node registers and browses for.
pub const SERVICE_TYPE: &str = "_intraweb._tcp.local.";
