//! Founding, joining and taking part in nets.
//!
//! Everything here is a post in a channel: a net's acts go into its
//! governance log, and a new net is announced in the directory so it can be
//! found. The state of a net is never stored, only folded from the log on
//! demand, so it cannot drift from what was actually said.
//!
//! Each act is checked against that state before it is sent. The fold
//! enforces the same rules on everybody's posts regardless; checking first is
//! so an operator is told "only the leader can do that" instead of posting
//! something every node will quietly ignore.

use crate::channels::{Delivery, say_offering};
use anyhow::{Context, Result, bail, ensure};
use intraweb_core::channel::{ChannelId, scrub_channel_name};
use intraweb_core::net::{self, Event, MotionKind, NetId, NetState};
use intraweb_core::peer::now_secs;
use intraweb_core::{Identity, PeerId, Store};
use intraweb_net::Roster;
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// The most entries folded for one net. A net that outgrows this has a
/// problem no fold will fix; capping it keeps a hostile flood from making
/// every dashboard refresh slower.
const LOG_LIMIT: u32 = 5000;

pub const ROLE_CHAT: &str = "chat";
pub const ROLE_GOVERNANCE: &str = "governance";
pub const ROLE_DIRECTORY: &str = "directory";

/// A net as the directory lists it.
#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    pub net_id: NetId,
    pub name: String,
    pub founder: PeerId,
    pub founded_at: u64,
}

fn lock(store: &Mutex<Store>) -> Result<std::sync::MutexGuard<'_, Store>> {
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))
}

/// Make sure the directory of nets is one of our channels, so charters
/// announced by anyone in range are kept.
pub fn ensure_directory(store: &Mutex<Store>) -> Result<()> {
    let store = lock(store)?;
    store.upsert_channel(ChannelId::directory(), "nets", false, None, now_secs())?;
    store.set_channel_net(ChannelId::directory(), None, ROLE_DIRECTORY)
}

fn parse(body: &str) -> Option<Event> {
    serde_json::from_str(body).ok()
}

/// Every net announced in the directory, oldest first.
///
/// A charter is only listed if its author can prove the id: it is derived
/// from the founder's key, so somebody else's copy lists nothing.
pub fn directory(store: &Mutex<Store>) -> Result<Vec<Listing>> {
    let log = lock(store)?.channel_log(ChannelId::directory(), LOG_LIMIT)?;
    let mut nets: Vec<Listing> = Vec::new();
    for entry in log {
        let Some(Event::Charter { net, name, nonce }) = parse(&entry.body) else {
            continue;
        };
        if NetId::derive(entry.from, &nonce) != net || nets.iter().any(|n| n.net_id == net) {
            continue;
        }
        nets.push(Listing {
            net_id: net,
            name: scrub_channel_name(&name),
            founder: entry.from,
            founded_at: entry.at,
        });
    }
    Ok(nets)
}

/// The nets whose log we keep, i.e. the ones we are in.
pub fn joined(store: &Mutex<Store>) -> Result<Vec<NetId>> {
    Ok(lock(store)?
        .channels()?
        .into_iter()
        .filter(|c| c.role == ROLE_GOVERNANCE)
        .filter_map(|c| c.net_id)
        .collect())
}

/// What a net is right now, as far as the log we hold says.
pub fn state(store: &Mutex<Store>, net: NetId) -> Result<NetState> {
    let log = lock(store)?.channel_log(net.governance(), LOG_LIMIT)?;
    let entries = log
        .into_iter()
        .filter_map(|entry| {
            parse(&entry.body).map(|event| net::Entry {
                from: entry.from,
                at: entry.at,
                signature: entry.signature,
                event,
            })
        })
        .collect();
    Ok(net::fold(net, entries, now_secs()))
}

/// The net a channel belongs to, if any.
pub fn net_of(store: &Mutex<Store>, channel: ChannelId) -> Option<NetId> {
    lock(store)
        .ok()?
        .channels()
        .ok()?
        .into_iter()
        .find(|c| c.channel_id == channel)
        .and_then(|c| c.net_id)
}

/// Follow a net's two public channels: its log, and its conversation.
fn follow(store: &Mutex<Store>, net: NetId, name: &str) -> Result<()> {
    let store = lock(store)?;
    let now = now_secs();
    store.upsert_channel(net.governance(), &format!("{name} log"), false, None, now)?;
    store.set_channel_net(net.governance(), Some(net), ROLE_GOVERNANCE)?;
    store.upsert_channel(net.general(), &format!("{name} general"), false, None, now)?;
    store.set_channel_net(net.general(), Some(net), ROLE_CHAT)
}

async fn post(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    channel: ChannelId,
    event: &Event,
) -> Result<Delivery> {
    event.check()?;
    let body = serde_json::to_string(event)?;
    say_offering(store, identity, &roster.peers(), channel, &body, None).await
}

/// Found a net, lead it, and announce it so others can find and join it.
pub async fn create(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    name: &str,
) -> Result<NetId> {
    let name = scrub_channel_name(name);
    ensure!(!name.is_empty(), "a net needs a name");
    let (net, nonce) = NetId::found(identity.peer_id())?;
    follow(store, net, &name)?;

    let charter = Event::Charter { net, name, nonce };
    // Into its own log first: that is what makes us its founder.
    post(store, identity, roster, net.governance(), &charter).await?;
    ensure_directory(store)?;
    post(store, identity, roster, ChannelId::directory(), &charter).await?;
    Ok(net)
}

/// Join a net listed in the directory, then fetch its history from whoever
/// is in range so its state shows at once rather than at the next catch-up.
pub async fn join(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
) -> Result<()> {
    let listing = directory(store)?
        .into_iter()
        .find(|n| n.net_id == net)
        .context("that net is not in the directory; it may not have been announced in range")?;
    follow(store, net, &listing.name)?;

    let peers = roster.peers();
    for channel in [net.governance(), net.general()] {
        for peer in &peers {
            let _ = crate::channels::backfill_from(store, peer, channel, 0).await;
        }
    }

    let current = state(store, net)?;
    ensure!(
        !current.banned.contains(&identity.peer_id()),
        "the members of {} voted you out, so that key cannot rejoin",
        listing.name
    );
    if current.is_member(identity.peer_id()) {
        return Ok(());
    }
    post(
        store,
        identity,
        roster,
        net.governance(),
        &Event::Join { net },
    )
    .await?;
    Ok(())
}

/// Leave a net and stop following its channels. What was said is kept.
pub async fn leave(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
) -> Result<()> {
    post(
        store,
        identity,
        roster,
        net.governance(),
        &Event::Leave { net },
    )
    .await?;
    let store = lock(store)?;
    store.forget_channel(net.governance())?;
    store.forget_channel(net.general())
}

fn member_state(store: &Mutex<Store>, identity: &Identity, net: NetId) -> Result<NetState> {
    let current = state(store, net)?;
    ensure!(
        current.is_member(identity.peer_id()),
        "you are not a member of this net; join it first"
    );
    Ok(current)
}

fn require_leader(current: &NetState, identity: &Identity, what: &str) -> Result<()> {
    ensure!(
        current.leader == Some(identity.peer_id()),
        "only the net leader can {what}"
    );
    Ok(())
}

/// Open a motion: impeach the leader, or (leader only) remove a member.
pub async fn open_motion(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
    kind: MotionKind,
    target: PeerId,
) -> Result<String> {
    let current = member_state(store, identity, net)?;
    match kind {
        MotionKind::Impeach => ensure!(
            current.leader == Some(target),
            "only the current leader can be impeached"
        ),
        MotionKind::Kick => {
            require_leader(&current, identity, "call a vote to remove somebody")?;
            ensure!(target != identity.peer_id(), "you cannot vote yourself out");
            ensure!(
                current.is_member(target),
                "they are not a member of this net"
            );
        }
    }
    if current.members.len() > net::MAX_ELIGIBLE {
        bail!(
            "a vote can include at most {} members, and this net has {}",
            net::MAX_ELIGIBLE,
            current.members.len()
        );
    }

    let id = net::new_motion_id()?;
    let motion = Event::Motion {
        net,
        id: id.clone(),
        kind,
        target,
        eligible: current.eligible_now(),
    };
    post(store, identity, roster, net.governance(), &motion).await?;
    Ok(id)
}

pub async fn vote(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
    motion: &str,
    yes: bool,
) -> Result<()> {
    let current = member_state(store, identity, net)?;
    let open = current
        .motions
        .iter()
        .find(|m| m.id == motion)
        .context("there is no such vote in this net")?;
    ensure!(
        open.status == net::MotionStatus::Open,
        "that vote is already closed"
    );
    ensure!(
        open.eligible_keys
            .contains(&net::short_key(identity.peer_id())),
        "you joined after this vote opened, so it is not yours to decide"
    );
    post(
        store,
        identity,
        roster,
        net.governance(),
        &Event::Vote {
            net,
            motion: motion.to_string(),
            yes,
        },
    )
    .await?;
    Ok(())
}

pub async fn set_policy(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
    low_data_mandatory: bool,
) -> Result<()> {
    let current = member_state(store, identity, net)?;
    require_leader(&current, identity, "change the net's rules")?;
    post(
        store,
        identity,
        roster,
        net.governance(),
        &Event::Policy {
            net,
            low_data_mandatory,
        },
    )
    .await?;
    Ok(())
}

pub async fn announce(
    store: &Arc<Mutex<Store>>,
    identity: &Identity,
    roster: &Roster,
    net: NetId,
    text: &str,
    ping: bool,
) -> Result<Delivery> {
    let current = member_state(store, identity, net)?;
    require_leader(&current, identity, "make announcements")?;
    post(
        store,
        identity,
        roster,
        net.governance(),
        &Event::Announce {
            net,
            text: text.trim().to_string(),
            ping,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster_alone() -> Roster {
        intraweb_net::Roster::empty(PeerId::from_bytes([0; 32]))
    }

    #[tokio::test]
    async fn a_founded_net_is_listed_and_led_by_its_founder() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let net = create(&store, &alice, &roster_alone(), "basecamp")
            .await
            .unwrap();

        let listed = directory(&store).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "basecamp");
        assert_eq!(joined(&store).unwrap(), vec![net]);
        assert_eq!(state(&store, net).unwrap().leader, Some(alice.peer_id()));
    }

    #[tokio::test]
    async fn only_the_leader_is_offered_the_leaders_powers() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let roster = roster_alone();
        let net = create(&store, &alice, &roster, "basecamp").await.unwrap();
        // Bob joins through the same log, as he would after a backfill.
        join(&store, &bob, &roster, net).await.unwrap();

        let err = set_policy(&store, &bob, &roster, net, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("only the net leader"), "{err}");
        assert!(set_policy(&store, &alice, &roster, net, true).await.is_ok());
        assert!(state(&store, net).unwrap().low_data_mandatory);
    }

    #[tokio::test]
    async fn leaving_stops_following_the_nets_channels() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let alice = Identity::generate().unwrap();
        let roster = roster_alone();
        let net = create(&store, &alice, &roster, "basecamp").await.unwrap();
        leave(&store, &alice, &roster, net).await.unwrap();
        assert!(joined(&store).unwrap().is_empty());
    }
}
