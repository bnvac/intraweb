//! Posting to channels, and letting people into private ones.
//!
//! Posting means handing the message to each recipient's node directly. There
//! is no log on a hub and no server keeping the canonical history -- every node
//! holds what it was told. A node that was switched off misses what was said,
//! which is the honest cost of having nowhere central to ask.

use crate::http;
use anyhow::{Context, Result};
use intraweb_core::channel::{ChannelId, Invite, Post, SignedPost};
use intraweb_core::peer::{Peer, now_secs};
use intraweb_core::sealed::SealingKey;
use intraweb_core::{Identity, Store};
use intraweb_net::Roster;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DELIVER_TIMEOUT: Duration = Duration::from_secs(5);

/// How a post went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    pub reached: usize,
    pub missed: usize,
}

/// Say something in a channel, to the peers given.
///
/// Private channels are encrypted under the channel key before signing, so the
/// post is unreadable to anyone not admitted even though it crosses the same
/// open network as everything else.
///
/// The post is built once and those exact bytes go both to our own log and to
/// every recipient. Signatures are what deduplicate a post, so building it a
/// second time would arrive looking like a different message.
pub async fn say_to(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    peers: &[Peer],
    channel: ChannelId,
    body: &str,
) -> Result<Delivery> {
    say_offering(store, identity, peers, channel, body, None).await
}

/// Say something, optionally offering a file from our shared folder.
///
/// The one place a post is built, so whatever rules a post must satisfy are
/// checked here for every caller.
pub async fn say_offering(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    peers: &[Peer],
    channel: ChannelId,
    body: &str,
    attachment: Option<&str>,
) -> Result<Delivery> {
    let (channel_key, members, is_known_public) = {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        let known_public = store
            .channels()?
            .into_iter()
            .any(|c| c.channel_id == channel && !c.is_private);
        (
            store.channel_key(channel)?,
            store.members(channel)?,
            known_public,
        )
    };

    let is_private = channel_key.is_some();
    let post = match channel_key {
        Some(key) => Post::private(channel, identity.peer_id(), &key, body)?,
        None => {
            // Posting in the clear is only right where the channel is meant
            // to be readable: the neighborhood, or a guestbook. Anywhere else
            // a missing key means we were never admitted.
            anyhow::ensure!(
                channel.is_neighborhood() || is_known_public,
                "you do not hold that channel's key, so you cannot post to it",
            );
            Post::public(channel, identity.peer_id(), body).with_attachment(attachment)
        }
    };
    // Refused here, before signing, with the reason: the private constructor
    // takes no attachment, so without this one would vanish silently.
    anyhow::ensure!(
        !(is_private && attachment.is_some()),
        "a private channel cannot carry attachments, because the shared folder \
         they live in is public",
    );
    post.check_limits()?;
    let sealed = SignedPost::seal(post, identity)?;

    // Keep our own copy first: what we said should appear whether or not
    // anybody was around to hear it.
    {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        store.store_post(&sealed, body, true)?;
    }

    // Narrowing to members is how a private channel stays private, so it
    // applies to private channels only. A public one -- the neighborhood, or
    // somebody's guestbook -- goes to whoever was asked for; a guestbook
    // signer holds no member list for a book that is not theirs.
    let recipients: Vec<&Peer> = if is_private {
        peers
            .iter()
            .filter(|p| members.contains(&p.peer_id))
            .collect()
    } else {
        peers.iter().collect()
    };

    let mut reached = 0;
    let mut missed = 0;
    for peer in recipients {
        match deliver_post(peer, &sealed).await {
            Ok(()) => reached += 1,
            Err(err) => {
                missed += 1;
                tracing::debug!(to = %peer.nickname, %err, "could not deliver a post");
            }
        }
    }
    Ok(Delivery { reached, missed })
}

/// Say something to everyone a live roster can see.
pub async fn say(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    channel: ChannelId,
    body: &str,
    attachment: Option<&str>,
) -> Result<Delivery> {
    say_offering(store, identity, &roster.peers(), channel, body, attachment).await
}

async fn deliver_post(peer: &Peer, sealed: &SignedPost) -> Result<()> {
    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;
    let body = serde_json::to_string(sealed)?;
    let response = http::post_json(
        addr,
        peer.api_port,
        "/api/channels/post",
        &body,
        DELIVER_TIMEOUT,
    )
    .await?;
    anyhow::ensure!(
        response.is_success(),
        "{} answered {}",
        peer.nickname,
        response.status
    );
    Ok(())
}

/// Ask one peer for what we missed in a channel, and file whatever checks out.
///
/// Returns how many posts were new to us. Everything is verified here exactly
/// as it would be on arrival: a peer handing back history is no more trusted
/// than one announcing it in the first place.
pub async fn backfill_from(
    store: &Arc<Mutex<Store>>,
    peer: &Peer,
    channel: ChannelId,
    since: u64,
) -> Result<usize> {
    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;
    let path = format!("/api/channels/{}/backfill?since={since}", channel.to_hex());

    let response = http::get(addr, peer.api_port, &path, DELIVER_TIMEOUT).await?;
    anyhow::ensure!(
        response.is_success(),
        "{} answered {}",
        peer.nickname,
        response.status
    );

    let envelopes: Vec<SignedPost> =
        serde_json::from_str(&response.body).context("that peer sent history we cannot read")?;

    let channel_key = {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        store.channel_key(channel)?
    };

    let mut filed = 0;
    for sealed in envelopes {
        // Unsigned or misattributed history is simply dropped.
        if sealed.accept().is_err() || sealed.post.channel != channel {
            continue;
        }

        let (body, readable) = match &channel_key {
            Some(key) => match sealed.post.open(key) {
                Ok(plain) => (plain, true),
                Err(_) => (sealed.post.body.clone(), false),
            },
            None if sealed.post.encrypted => (sealed.post.body.clone(), false),
            None => (sealed.post.body.clone(), true),
        };

        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        if store.store_post(&sealed, &body, readable).unwrap_or(false) {
            filed += 1;
        }
    }
    Ok(filed)
}

/// Catch up on every channel we know, from whoever is in range.
///
/// A node that was switched off has no way to learn what was said while it
/// was away -- there is no server holding the history, only neighbors who
/// each kept their own copy. Asking them is the only way back.
pub async fn catch_up(store: &Arc<Mutex<Store>>, peers: &[Peer]) -> usize {
    if peers.is_empty() {
        return 0;
    }

    let channels = {
        let Ok(store) = store.lock() else { return 0 };
        store.channels().unwrap_or_default()
    };

    let mut filed = 0;
    for channel in channels {
        let since = {
            let Ok(store) = store.lock() else { continue };
            // Overlap a little, so a post that arrived in the same second as
            // our newest one is not stepped over.
            store
                .newest_post_at(channel.channel_id)
                .unwrap_or(0)
                .saturating_sub(1)
        };

        for peer in peers {
            match backfill_from(store, peer, channel.channel_id, since).await {
                Ok(count) => filed += count,
                Err(err) => {
                    tracing::debug!(from = %peer.nickname, %err, "could not catch up");
                }
            }
        }
    }

    if filed > 0 {
        tracing::info!(filed, "caught up on what was said while we were away");
    }
    filed
}

/// Start a private channel with ourselves as its first member.
pub fn create_private(store: &Mutex<Store>, identity: &Identity, name: &str) -> Result<ChannelId> {
    let channel = ChannelId::new_private()?;
    let key = intraweb_core::sealed::new_channel_key()?;

    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    store.upsert_channel(channel, name, true, Some(&key), now_secs())?;
    store.add_member(channel, identity.peer_id(), now_secs())?;
    Ok(channel)
}

/// Let somebody into a private channel.
///
/// They must be in range: the key is sealed to the encryption key they
/// announce, and there is no sealing a secret to a key we have never seen.
pub async fn invite(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    sealing: &SealingKey,
    channel: ChannelId,
    peer: &Peer,
) -> Result<()> {
    let recipient_key = peer
        .encryption_key
        .context("that neighbor is not in range, so there is no key to seal the invitation to")?;

    let (channel_key, name, net) = {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        let key = store
            .channel_key(channel)?
            .context("you do not hold that channel's key, so you cannot invite anyone")?;
        let record = store
            .channels()?
            .into_iter()
            .find(|c| c.channel_id == channel);
        let net = record.as_ref().and_then(|c| c.net_id);
        let name = record.map_or_else(|| "channel".to_string(), |c| c.name);
        (key, name, net)
    };

    let invitation = Invite::create(
        identity,
        sealing,
        peer.peer_id,
        &recipient_key,
        channel,
        &name,
        &channel_key,
    )?
    .in_net(net, identity);

    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;
    let body = serde_json::to_string(&invitation)?;
    let response = http::post_json(
        addr,
        peer.api_port,
        "/api/channels/invite",
        &body,
        DELIVER_TIMEOUT,
    )
    .await?;
    anyhow::ensure!(
        response.is_success(),
        "{} refused the invitation ({})",
        peer.nickname,
        response.status,
    );

    // Only record them as a member once their node has taken the invitation.
    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    store.add_member(channel, peer.peer_id, now_secs())?;
    Ok(())
}

/// Sign somebody's guestbook.
///
/// A guestbook is a public channel whose id is derived from its owner's key,
/// so this is an ordinary post that happens to go to exactly one node.
pub async fn sign_guestbook(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    owner: &Peer,
    body: &str,
) -> Result<()> {
    let channel = ChannelId::guestbook_of(owner.peer_id);

    {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("the store is busy"))?;
        store.upsert_channel(
            channel,
            &format!("{}'s guestbook", owner.nickname),
            false,
            None,
            now_secs(),
        )?;
    }

    let delivery = say_to(store, identity, std::slice::from_ref(owner), channel, body).await?;
    anyhow::ensure!(
        delivery.reached > 0,
        "could not reach {} to leave that",
        owner.nickname
    );
    Ok(())
}

/// Make sure our own guestbook exists, so entries have somewhere to land.
pub fn ensure_guestbook(store: &Mutex<Store>, identity: &Identity) -> Result<()> {
    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    store.upsert_channel(
        ChannelId::guestbook_of(identity.peer_id()),
        "my guestbook",
        false,
        None,
        now_secs(),
    )
}

/// Make sure the neighborhood channel exists in this vault.
pub fn ensure_neighborhood(store: &Mutex<Store>) -> Result<()> {
    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    store.upsert_channel(
        ChannelId::neighborhood(),
        "neighborhood",
        false,
        None,
        now_secs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_neighborhood_channel_is_created_once_and_kept() {
        let store = Mutex::new(Store::open_in_memory().unwrap());
        ensure_neighborhood(&store).unwrap();
        ensure_neighborhood(&store).unwrap();

        let channels = store.lock().unwrap().channels().unwrap();
        assert_eq!(channels.len(), 1);
        assert!(!channels[0].is_private);
        assert!(channels[0].channel_id.is_neighborhood());
    }

    #[test]
    fn creating_a_private_channel_admits_its_creator() {
        let store = Mutex::new(Store::open_in_memory().unwrap());
        let alice = Identity::generate().unwrap();

        let channel = create_private(&store, &alice, "ridge crew").unwrap();

        let store = store.lock().unwrap();
        assert!(
            store.channel_key(channel).unwrap().is_some(),
            "the creator can read it"
        );
        assert!(store.is_member(channel, alice.peer_id()).unwrap());
    }

    #[tokio::test]
    async fn posting_to_a_channel_we_cannot_read_is_refused() {
        // Otherwise we would post in the clear to a channel whose members
        // expect everything in it to be encrypted.
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let theirs = ChannelId::new_private().unwrap();
        store
            .lock()
            .unwrap()
            .upsert_channel(theirs, "theirs", true, None, 100)
            .unwrap();

        assert!(say_to(&store, &alice, &[], theirs, "hello").await.is_err());
    }

    #[tokio::test]
    async fn our_own_post_is_kept_even_with_nobody_around() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        ensure_neighborhood(&store).unwrap();

        let delivery = say_to(&store, &alice, &[], ChannelId::neighborhood(), "anyone?")
            .await
            .unwrap();

        assert_eq!(delivery.reached, 0);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .posts(ChannelId::neighborhood(), 10)
                .unwrap()[0]
                .body,
            "anyone?"
        );
    }

    #[tokio::test]
    async fn a_public_channel_is_not_narrowed_to_members() {
        // Regression: signing a guestbook reached nobody, because delivery was
        // filtered by a member list the signer has no reason to hold.
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let book = ChannelId::guestbook_of(bob.peer_id());

        store
            .lock()
            .unwrap()
            .upsert_channel(book, "bob's guestbook", false, None, 100)
            .unwrap();

        // A peer who is not a recorded member of this book. Delivery must be
        // attempted anyway -- it fails only because nothing is listening on
        // that port, which is what proves the member filter did not drop it.
        let stranger = Peer {
            peer_id: bob.peer_id(),
            encryption_key: None,
            fingerprint: bob.peer_id().fingerprint(),
            nickname: "bob".into(),
            addrs: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            api_port: 1,
            is_hub: false,
            hub_name: None,
            source: intraweb_core::DiscoverySource::Mdns,
            trust: intraweb_core::TrustState::Known,
            first_seen: 0,
            last_seen: 0,
        };

        let delivery = say_to(&store, &alice, &[stranger], book, "nice page")
            .await
            .unwrap();
        assert_eq!(
            delivery.missed, 1,
            "it must try, not silently skip a non-member"
        );
        assert_eq!(
            store.lock().unwrap().posts(book, 10).unwrap()[0].body,
            "nice page"
        );
    }

    #[tokio::test]
    async fn catching_up_with_nobody_in_range_does_nothing() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        ensure_neighborhood(&store).unwrap();
        assert_eq!(catch_up(&store, &[]).await, 0);
    }

    #[tokio::test]
    async fn an_unreachable_peer_does_not_stop_the_catch_up() {
        // One neighbor being gone must not abandon the rest of the sweep.
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let bob = Identity::generate().unwrap();
        ensure_neighborhood(&store).unwrap();

        let gone = Peer {
            peer_id: bob.peer_id(),
            encryption_key: None,
            fingerprint: bob.peer_id().fingerprint(),
            nickname: "bob".into(),
            addrs: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            api_port: 1,
            is_hub: false,
            hub_name: None,
            source: intraweb_core::DiscoverySource::Mdns,
            trust: intraweb_core::TrustState::Known,
            first_seen: 0,
            last_seen: 0,
        };

        assert_eq!(
            catch_up(&store, &[gone]).await,
            0,
            "it returns rather than failing"
        );
    }

    #[tokio::test]
    async fn what_we_store_is_what_we_send() {
        // One build, one signature. Building the post twice would make our own
        // copy and the delivered copy look like different messages, and
        // signatures are what deduplicate them.
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let channel = create_private(&store, &alice, "crew").unwrap();

        say_to(&store, &alice, &[], channel, "one message")
            .await
            .unwrap();
        say_to(&store, &alice, &[], channel, "one message")
            .await
            .unwrap();

        // Same text twice is genuinely two posts (different nonce and time),
        // but each was stored exactly once.
        let posts = store.lock().unwrap().posts(channel, 10).unwrap();
        assert_eq!(posts.len(), 2);
        assert!(posts.iter().all(|p| p.body == "one message" && p.readable));
    }
}
