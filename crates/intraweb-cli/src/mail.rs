//! Addressing and delivering local mail.
//!
//! You type a nickname; what gets signed, sent, and filed is a public key. The
//! two are not the same thing and the gap between them is where impersonation
//! lives, so a name that matches more than one key is refused outright rather
//! than resolved by guesswork.
//!
//! Delivery is the sender's job. A message waits in the outbox until the
//! recipient's node is on the network, then goes straight to it. No hub is ever
//! asked to hold it.

use crate::http;
use anyhow::{Context, Result};
use intraweb_core::peer::{DiscoverySource, Peer, TrustState, now_secs};
use intraweb_core::{Identity, Mail, PeerId, SignedMail, Store};
use intraweb_net::Roster;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Delivery attempts are local; a node that cannot answer this fast is gone.
const DELIVER_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the outbox retries. Slower than discovery, because the thing it
/// waits for -- somebody walking back into range -- happens on human timescales.
pub const OUTBOX_INTERVAL_SECS: u64 = 5;

/// What a typed recipient turned out to mean.
#[derive(Debug, Clone, PartialEq)]
pub enum Recipient {
    /// Exactly one key answers to this.
    One(Box<Peer>),
    /// Nobody in range answers to it.
    Unknown,
    /// Several keys do. The caller must show these and let a person choose.
    Ambiguous(Vec<Peer>),
}

/// Work out which key a typed recipient means.
///
/// Accepts a full public key, a nickname, or a fingerprint prefix. Nicknames
/// are checked before fingerprints because that is what people type, but a
/// nickname shared by two keys never silently picks one.
pub fn resolve(peers: &[Peer], query: &str) -> Recipient {
    let needle = query.trim().to_lowercase();

    // A full key is unambiguous by construction.
    if let Some(peer_id) = PeerId::parse_hex(&needle)
        && let Some(peer) = peers.iter().find(|p| p.peer_id == peer_id)
    {
        return Recipient::One(Box::new(peer.clone()));
    }

    let by_nickname: Vec<&Peer> = peers.iter().filter(|p| p.nickname == needle).collect();
    if !by_nickname.is_empty() {
        return pick(by_nickname);
    }

    // Fingerprints are shown hyphenated but people paste them either way.
    let bare = needle.replace('-', "");
    if bare.len() >= 4 {
        let by_fingerprint: Vec<&Peer> = peers
            .iter()
            .filter(|p| p.fingerprint.replace('-', "").starts_with(&bare))
            .collect();
        if !by_fingerprint.is_empty() {
            return pick(by_fingerprint);
        }
    }

    Recipient::Unknown
}

fn pick(matches: Vec<&Peer>) -> Recipient {
    match matches.as_slice() {
        [only] => Recipient::One(Box::new((*only).clone())),
        _ => Recipient::Ambiguous(matches.into_iter().cloned().collect()),
    }
}

/// Put a message in the outbox. It leaves as soon as the recipient is reachable.
pub fn queue(
    store: &Mutex<Store>,
    from: PeerId,
    to: PeerId,
    subject: &str,
    body: &str,
    attachment: Option<&str>,
) -> Result<i64> {
    let mut mail = Mail::new(from, to, subject, body, now_secs());
    if let Some(path) = attachment {
        mail = mail.with_attachment(path);
    }
    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the mail store is busy"))?;
    store.queue_outgoing(&mail)
}

/// Try to deliver everything waiting. Returns how many got through.
///
/// Anything whose recipient is not currently in range is simply left alone;
/// there is nothing to report and nothing to retry against.
/// The message as it was written, from its row in the outbox.
///
/// Every field has to come back. The attachment once did not: delivery
/// rebuilt the message from subject and body alone, so a file offered through
/// the outbox arrived without it and nobody was told. (Real bug, named
/// regression test.)
fn rebuild(from: PeerId, queued: &intraweb_core::db::StoredMail) -> Mail {
    let mail = Mail::new(
        from,
        queued.peer_id,
        &queued.subject,
        &queued.body,
        queued.created_at,
    );
    match queued.attachment.as_deref() {
        Some(path) => mail.with_attachment(path),
        None => mail,
    }
}

pub async fn deliver_pending(
    store: &Arc<Mutex<Store>>,
    roster: &Roster,
    identity: &Identity,
) -> usize {
    let pending = {
        let Ok(store) = store.lock() else { return 0 };
        store.pending_outgoing().unwrap_or_default()
    };
    if pending.is_empty() {
        return 0;
    }

    let peers = roster.peers();
    let mut delivered = 0;

    for queued in pending {
        let Some(peer) = peers.iter().find(|p| p.peer_id == queued.peer_id) else {
            continue; // Not in range. Wait.
        };
        let mail = rebuild(identity.peer_id(), &queued);
        let Ok(sealed) = SignedMail::seal(mail, identity) else {
            continue;
        };

        match deliver_one(peer, &sealed).await {
            Ok(()) => {
                if let Ok(store) = store.lock()
                    && store.mark_delivered(queued.id, now_secs()).is_ok()
                {
                    delivered += 1;
                    tracing::info!(to = %peer.nickname, subject = %queued.subject, "mail delivered");
                }
            }
            Err(err) => {
                tracing::debug!(to = %peer.nickname, %err, "mail still waiting");
            }
        }
    }
    delivered
}

/// Hand one message straight to the recipient's node.
pub async fn deliver_one(peer: &Peer, sealed: &SignedMail) -> Result<()> {
    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;
    let body = serde_json::to_string(sealed).context("could not encode the message")?;

    let response =
        http::post_json(addr, peer.api_port, "/api/mail", &body, DELIVER_TIMEOUT).await?;
    anyhow::ensure!(
        response.is_success(),
        "{} refused the message (HTTP {})",
        peer.nickname,
        response.status,
    );
    Ok(())
}

/// Everyone we could address, in range or not.
///
/// Mail to someone who has gone home is the normal case for a queue, so the
/// keyring is folded in behind the live roster. Entries that come only from the
/// keyring carry no address, so delivery simply waits for them to reappear.
pub fn addressable(live: &[Peer], store: &Mutex<Store>) -> Vec<Peer> {
    let mut peers = live.to_vec();
    let Ok(store) = store.lock() else {
        return peers;
    };
    let Ok(known) = store.known_peers(500) else {
        return peers;
    };

    for entry in known {
        if peers.iter().any(|p| p.peer_id == entry.peer_id) {
            continue;
        }
        peers.push(Peer {
            peer_id: entry.peer_id,
            // Known only from the keyring, so their encryption key is unknown
            // and they cannot be invited to a private channel until seen.
            encryption_key: None,
            fingerprint: entry.peer_id.fingerprint(),
            nickname: entry.nickname,
            addrs: Vec::new(),
            api_port: 0,
            is_hub: false,
            hub_name: None,
            source: DiscoverySource::Mdns,
            trust: if entry.verified {
                TrustState::Verified
            } else {
                TrustState::Known
            },
            first_seen: 0,
            last_seen: 0,
        });
    }
    peers
}

/// Build a recipient from a public key we have never seen.
///
/// Somebody can hand you their key on paper. Refusing to write to them until
/// they happen to be online would make the outbox pointless.
pub fn peer_from_key(query: &str) -> Option<Peer> {
    let peer_id = PeerId::parse_hex(query.trim())?;
    Some(Peer {
        peer_id,
        // A key written on paper says nothing about their encryption key.
        encryption_key: None,
        fingerprint: peer_id.fingerprint(),
        nickname: peer_id.fingerprint(),
        addrs: Vec::new(),
        api_port: 0,
        is_hub: false,
        hub_name: None,
        source: DiscoverySource::Mdns,
        trust: TrustState::New,
        first_seen: 0,
        last_seen: 0,
    })
}

/// Turn a typed recipient into exactly one key, or explain why we cannot.
pub fn resolve_or_explain(peers: &[Peer], query: &str) -> Result<Peer> {
    match resolve(peers, query) {
        Recipient::One(peer) => Ok(*peer),
        Recipient::Unknown => {
            // A full public key is self-describing; nothing needs to know them.
            if let Some(peer) = peer_from_key(query) {
                return Ok(peer);
            }
            if peers.is_empty() {
                anyhow::bail!("nobody is in range. Run `intraweb doctor` if you expected company.");
            }
            let names: Vec<&str> = peers.iter().map(|p| p.nickname.as_str()).collect();
            anyhow::bail!(
                "no neighbor matches {query:?}. In range: {}",
                names.join(", ")
            );
        }
        Recipient::Ambiguous(candidates) => {
            let mut lines = vec![format!(
                "{} keys answer to {query:?}. Say which, using a fingerprint:",
                candidates.len()
            )];
            for peer in candidates {
                lines.push(format!("  {}  {}", peer.fingerprint, peer.nickname));
            }
            anyhow::bail!("{}", lines.join("\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::peer::{DiscoverySource, TrustState};
    use std::net::{IpAddr, Ipv4Addr};

    /// Regression: delivery rebuilt queued mail from subject and body alone,
    /// so an attachment offered through the outbox arrived without it.
    #[test]
    fn queued_mail_keeps_its_attachment_on_the_way_out() {
        let store = Mutex::new(Store::open_in_memory().unwrap());
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        queue(
            &store,
            alice.peer_id(),
            bob.peer_id(),
            "the bench",
            "photo attached",
            Some("bench.jpg"),
        )
        .unwrap();

        let pending = store.lock().unwrap().pending_outgoing().unwrap();
        let outgoing = rebuild(alice.peer_id(), &pending[0]);
        assert_eq!(outgoing.attachment.as_deref(), Some("bench.jpg"));
        assert_eq!(outgoing.subject, "the bench");
    }

    fn peer_named(nickname: &str) -> Peer {
        let peer_id = Identity::generate().unwrap().peer_id();
        Peer {
            peer_id,
            encryption_key: Some(
                intraweb_core::SealingKey::derive(&Identity::generate().unwrap()).public(),
            ),
            fingerprint: peer_id.fingerprint(),
            nickname: nickname.to_string(),
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
            api_port: 8420,
            is_hub: false,
            hub_name: None,
            source: DiscoverySource::Mdns,
            trust: TrustState::Known,
            first_seen: 0,
            last_seen: 0,
        }
    }

    #[test]
    fn a_plain_nickname_resolves() {
        let peers = vec![peer_named("alice"), peer_named("bob")];
        let Recipient::One(found) = resolve(&peers, "alice") else {
            panic!("should resolve to exactly one");
        };
        assert_eq!(found.nickname, "alice");
    }

    #[test]
    fn a_shared_nickname_is_refused_not_guessed() {
        // The whole point: two keys, one label. Picking either would be a lie.
        let peers = vec![peer_named("alice"), peer_named("alice")];
        let Recipient::Ambiguous(candidates) = resolve(&peers, "alice") else {
            panic!("a shared nickname must never resolve to one key");
        };
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn a_fingerprint_prefix_disambiguates() {
        let peers = vec![peer_named("alice"), peer_named("alice")];
        let target = &peers[1];
        let prefix: String = target.fingerprint.chars().take(9).collect();

        let Recipient::One(found) = resolve(&peers, &prefix) else {
            panic!("a fingerprint prefix should pick exactly one");
        };
        assert_eq!(found.peer_id, target.peer_id);
    }

    #[test]
    fn a_fingerprint_resolves_with_or_without_hyphens() {
        let peers = vec![peer_named("alice")];
        let hyphenated = peers[0].fingerprint.clone();
        let bare = hyphenated.replace('-', "");

        assert!(matches!(resolve(&peers, &hyphenated), Recipient::One(_)));
        assert!(matches!(resolve(&peers, &bare), Recipient::One(_)));
    }

    #[test]
    fn a_full_public_key_resolves() {
        let peers = vec![peer_named("alice"), peer_named("alice")];
        let target = &peers[0];
        let Recipient::One(found) = resolve(&peers, &target.peer_id.to_hex()) else {
            panic!("a full key is unambiguous");
        };
        assert_eq!(found.peer_id, target.peer_id);
    }

    #[test]
    fn nobody_in_range_is_reported_as_unknown() {
        let peers = vec![peer_named("alice")];
        assert_eq!(resolve(&peers, "carol"), Recipient::Unknown);
        assert_eq!(resolve(&[], "alice"), Recipient::Unknown);
    }

    #[test]
    fn a_nickname_beats_a_coincidental_fingerprint_prefix() {
        // Whatever people type, they mean the name they can see.
        let mut peers = vec![peer_named("beef"), peer_named("other")];
        peers[1].fingerprint = "beef-0000-0000-0000".to_string();

        let Recipient::One(found) = resolve(&peers, "beef") else {
            panic!("should resolve");
        };
        assert_eq!(found.nickname, "beef");
    }

    #[test]
    fn a_too_short_fragment_is_not_treated_as_a_fingerprint() {
        // One or two characters would match half the network.
        let peers = vec![peer_named("alice")];
        assert_eq!(
            resolve(&peers, &peers[0].fingerprint[..2]),
            Recipient::Unknown
        );
    }
}
