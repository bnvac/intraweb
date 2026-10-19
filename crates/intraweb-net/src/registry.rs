//! The live roster of who is on the network right now.
//!
//! This is deliberately in-memory and deliberately forgetful. A peer that stops
//! announcing falls off; nothing here is replicated to anyone. Durable facts
//! (which keys we have met before) live in the keyring, not in this table.

use crate::presence::Presence;
use intraweb_core::identity::PeerId;
use intraweb_core::peer::{DiscoverySource, Peer, TrustState};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sighting {
    /// A peer we did not have on the roster a moment ago.
    Arrived,
    /// A peer we already knew about, refreshed.
    Refreshed,
    /// Our own announcement, echoed back to us. Ignored.
    SelfEcho,
}

/// How often a still-present peer's sighting is written through to the keyring.
///
/// Beacons arrive every couple of seconds, and writing each one meant a SQLite
/// UPDATE per peer per beacon -- pointless lock traffic, and pointless flash
/// wear on the SD card a field node boots from. The roster already holds the
/// live `last_seen`; the durable copy only needs to be roughly right.
pub const PERSIST_INTERVAL_SECS: u64 = 60;

pub struct PeerRegistry {
    self_id: PeerId,
    timeout_secs: u64,
    peers: HashMap<PeerId, Peer>,
    /// Nickname and time of the last write-through, per peer.
    persisted: HashMap<PeerId, (String, u64)>,
    /// Keys we refuse to see. Held in memory so the check costs nothing on a
    /// path that runs for every beacon from every peer.
    blocked: HashSet<PeerId>,
    /// Newest presence timestamp accepted from each peer, so a captured
    /// announcement cannot be played back at us.
    newest_presence: HashMap<PeerId, u64>,
    /// Service names mDNS has resolved, each mapped to the key whose signature
    /// we checked when it did.
    ///
    /// Recorded only after verification, because a withdrawal names a service,
    /// not a key: believing the key in an unverified record would let anyone
    /// evict anyone, by announcing somebody else's id and then withdrawing it.
    mdns_names: HashMap<String, PeerId>,
    /// Peers mDNS is currently asserting the presence of.
    mdns_held: HashSet<PeerId>,
}

impl PeerRegistry {
    pub fn new(self_id: PeerId, timeout_secs: u64) -> Self {
        Self {
            self_id,
            timeout_secs,
            peers: HashMap::new(),
            persisted: HashMap::new(),
            blocked: HashSet::new(),
            newest_presence: HashMap::new(),
            mdns_names: HashMap::new(),
            mdns_held: HashSet::new(),
        }
    }

    /// Hold a peer present on the strength of mDNS having resolved them.
    ///
    /// mDNS is edge-triggered: a record resolves once and then stands, and the
    /// responder renews it behind our back rather than notifying us again. So
    /// there is no stream of mDNS sightings to time out against, and applying
    /// the beacon's heartbeat timeout to a peer known only over mDNS dropped
    /// them at every timeout -- discovery that worked for thirty seconds and
    /// then went quiet, on exactly the multicast-only networks mDNS is there
    /// to serve. (Real bug, named regression test.)
    pub fn hold_mdns(&mut self, fullname: &str, peer_id: PeerId) {
        self.mdns_names.insert(fullname.to_string(), peer_id);
        self.mdns_held.insert(peer_id);
    }

    /// mDNS withdrew a service, by goodbye packet or by letting the record
    /// expire. Returns the peer if that withdrawal was the end of them.
    ///
    /// Releases the hold, and evicts outright when mDNS was the only thing
    /// that ever saw them: they have no heartbeat to wait out, so holding them
    /// for one would be inventing a delay nothing is measuring. A peer the
    /// beacon also knows is left to the sweep, which is where that call
    /// belongs -- losing the multicast record is not losing the peer.
    pub fn release_mdns(&mut self, fullname: &str) -> Option<Peer> {
        let peer_id = self.mdns_names.remove(fullname)?;
        self.mdns_held.remove(&peer_id);

        if self.peers.get(&peer_id)?.source != DiscoverySource::Mdns {
            return None;
        }

        let departed = self.peers.remove(&peer_id)?;
        self.persisted.remove(&peer_id);
        self.newest_presence.remove(&peer_id);
        Some(departed)
    }

    /// Whether this announcement is newer than the last we took from the peer.
    ///
    /// A signed record stays valid for as long as the clock-skew window
    /// allows, so anyone who captured one can play it back. Requiring each
    /// announcement to be strictly newer than the last we took makes a replay
    /// useless: it can neither rewind what a peer announced nor vouch that
    /// they are still here.
    ///
    /// Strictness matters most on the mDNS path, where a record grants a hold
    /// that no timeout expires. Accepting an equal timestamp there would let
    /// anyone who captured one record keep a peer who has long since left on
    /// every roster on the link, indefinitely, by republishing it.
    ///
    /// Nothing is lost by refusing the repeats, because mDNS liveness does not
    /// come from them -- `hold_mdns` holds the peer present until the record
    /// is withdrawn. A peer dropped by a lossy link and then re-resolved from
    /// the same record waits for the announcer's next refresh, which is why
    /// that refresh has to be well inside the clock-skew window.
    ///
    /// The memory is dropped when a peer is swept, which is deliberate: a node
    /// that goes away and comes back -- possibly with a clock that reset to
    /// the epoch, as field hardware without a battery does -- must be able to
    /// announce itself again.
    pub fn is_fresh(&self, peer_id: PeerId, timestamp: u64) -> bool {
        match self.newest_presence.get(&peer_id) {
            Some(newest) => timestamp > *newest,
            None => true,
        }
    }

    pub fn note_presence(&mut self, peer_id: PeerId, timestamp: u64) {
        let newest = self.newest_presence.entry(peer_id).or_insert(timestamp);
        *newest = (*newest).max(timestamp);
    }

    pub fn is_blocked(&self, peer_id: PeerId) -> bool {
        self.blocked.contains(&peer_id)
    }

    /// Replace the blocklist, dropping anyone newly blocked from the roster.
    ///
    /// Blocking should take effect at once rather than when a peer next times
    /// out; somebody reaching for the block button wants them gone now.
    pub fn set_blocked(&mut self, blocked: HashSet<PeerId>) {
        self.peers.retain(|peer_id, _| !blocked.contains(peer_id));
        self.persisted
            .retain(|peer_id, _| !blocked.contains(peer_id));
        self.blocked = blocked;
    }

    /// The trust we already hold for a peer, when this sighting need not reach
    /// the keyring.
    ///
    /// Returns `None` -- meaning "go and write" -- whenever the durable record
    /// could be wrong: an unknown key, a changed nickname (which is how an
    /// impersonation attempt shows up), or a write-through that is simply due.
    pub fn cached_trust(&self, peer_id: PeerId, nickname: &str, now: u64) -> Option<TrustState> {
        let peer = self.peers.get(&peer_id)?;
        let (persisted_nick, persisted_at) = self.persisted.get(&peer_id)?;

        if persisted_nick != nickname {
            return None;
        }
        if now.saturating_sub(*persisted_at) >= PERSIST_INTERVAL_SECS {
            return None;
        }
        Some(peer.trust)
    }

    /// Apply a trust decision made locally, right now.
    ///
    /// Throttling write-through means the next sighting would otherwise reuse
    /// the cached trust and ignore what the operator just did, leaving a
    /// verified peer looking unverified for up to a minute. Updating in place
    /// and dropping the bookkeeping makes it immediate instead.
    pub fn set_trust(&mut self, peer_id: PeerId, trust: TrustState) -> bool {
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return false;
        };
        // A raised warning still outranks anything else.
        if !peer.trust.is_warning() {
            peer.trust = trust;
        }
        self.persisted.remove(&peer_id);
        true
    }

    /// Note that this peer's sighting reached the keyring.
    pub fn mark_persisted(&mut self, peer_id: PeerId, nickname: &str, now: u64) {
        self.persisted.insert(peer_id, (nickname.to_string(), now));
    }

    /// Fold a verified presence record into the roster.
    ///
    /// The caller must have checked the signature already; the registry is
    /// about liveness, not authenticity.
    pub fn record(
        &mut self,
        presence: &Presence,
        addrs: Vec<IpAddr>,
        source: DiscoverySource,
        trust: TrustState,
        now: u64,
    ) -> Sighting {
        if presence.peer_id == self.self_id {
            return Sighting::SelfEcho;
        }

        match self.peers.get_mut(&presence.peer_id) {
            Some(existing) => {
                existing.nickname = presence.nickname.clone();
                existing.encryption_key = Some(presence.encryption_key);
                existing.api_port = presence.api_port;
                existing.is_hub = presence.is_hub;
                existing.hub_name = hub_name(presence);
                existing.source = existing.source.merge(source);
                existing.last_seen = now;
                // Never downgrade a judgement we already made: a peer flagged
                // as an impostor stays flagged for the session.
                if !existing.trust.is_warning() {
                    existing.trust = trust;
                }
                for addr in addrs {
                    if !existing.addrs.contains(&addr) {
                        existing.addrs.push(addr);
                    }
                }
                Sighting::Refreshed
            }
            None => {
                self.peers.insert(
                    presence.peer_id,
                    Peer {
                        peer_id: presence.peer_id,
                        encryption_key: Some(presence.encryption_key),
                        fingerprint: presence.peer_id.fingerprint(),
                        nickname: presence.nickname.clone(),
                        addrs,
                        api_port: presence.api_port,
                        is_hub: presence.is_hub,
                        hub_name: hub_name(presence),
                        source,
                        trust,
                        first_seen: now,
                        last_seen: now,
                    },
                );
                Sighting::Arrived
            }
        }
    }

    /// Drop peers we have not heard from inside the timeout. Returns who left,
    /// so the caller can log departures rather than silently shrinking the list.
    pub fn sweep(&mut self, now: u64) -> Vec<Peer> {
        let timeout = self.timeout_secs;
        // A peer mDNS is holding present has no heartbeat to be stale against;
        // they leave when mDNS withdraws them, not on this timer.
        let held = &self.mdns_held;
        let departed: Vec<Peer> = self
            .peers
            .values()
            .filter(|peer| peer.is_stale(now, timeout) && !held.contains(&peer.peer_id))
            .cloned()
            .collect();
        for peer in &departed {
            self.peers.remove(&peer.peer_id);
            // Otherwise the map grows for every peer that ever passed through,
            // and a returning peer would skip its write-through.
            self.persisted.remove(&peer.peer_id);
            // Forget their clock too, so a peer that comes back -- perhaps
            // with a clock that reset -- is not locked out by its own past.
            self.newest_presence.remove(&peer.peer_id);
        }
        departed
    }

    /// Current roster: hubs first, then alphabetically, so the list a person
    /// reads does not reshuffle itself every refresh.
    pub fn snapshot(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self.peers.values().cloned().collect();
        peers.sort_by(|a, b| {
            b.is_hub
                .cmp(&a.is_hub)
                .then_with(|| a.nickname.cmp(&b.nickname))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });
        peers
    }

    /// Every hub currently reachable. Joining all of them at once is the point:
    /// one vault, many neighborhoods.
    pub fn hubs(&self) -> Vec<Peer> {
        self.snapshot()
            .into_iter()
            .filter(|peer| peer.is_hub)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

fn hub_name(presence: &Presence) -> Option<String> {
    presence.is_hub.then(|| presence.hub_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::Identity;
    use std::net::Ipv4Addr;

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    fn presence(id: &Identity, nick: &str, is_hub: bool) -> Presence {
        Presence::new(id, nick, 8420, is_hub, "basecamp")
    }

    fn registry() -> (PeerRegistry, Identity) {
        let me = Identity::generate().unwrap();
        (PeerRegistry::new(me.peer_id(), 30), me)
    }

    #[test]
    fn arrival_then_refresh() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        let first = reg.record(
            &p,
            vec![addr(10)],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        let second = reg.record(
            &p,
            vec![addr(10)],
            DiscoverySource::Mdns,
            TrustState::Known,
            110,
        );

        assert_eq!(first, Sighting::Arrived);
        assert_eq!(second, Sighting::Refreshed);
        assert_eq!(reg.len(), 1, "the same key must not appear twice");
    }

    #[test]
    fn our_own_echo_is_ignored() {
        let (mut reg, me) = registry();
        let mine = presence(&me, "me", false);

        let outcome = reg.record(
            &mine,
            vec![addr(5)],
            DiscoverySource::Beacon,
            TrustState::New,
            100,
        );

        assert_eq!(outcome, Sighting::SelfEcho);
        assert!(reg.is_empty(), "we must not list ourselves as a neighbor");
    }

    #[test]
    fn seeing_a_peer_both_ways_merges_the_source() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(
            &p,
            vec![addr(10)],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.record(
            &p,
            vec![addr(10)],
            DiscoverySource::Beacon,
            TrustState::Known,
            101,
        );

        assert_eq!(reg.snapshot()[0].source, DiscoverySource::Both);
    }

    #[test]
    fn addresses_accumulate_without_duplicates() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(
            &p,
            vec![addr(10)],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.record(
            &p,
            vec![addr(10), addr(11)],
            DiscoverySource::Mdns,
            TrustState::Known,
            101,
        );

        assert_eq!(reg.snapshot()[0].addrs, vec![addr(10), addr(11)]);
    }

    #[test]
    fn a_conflict_flag_is_never_quietly_downgraded() {
        let (mut reg, _me) = registry();
        let mallory = Identity::generate().unwrap();
        let p = presence(&mallory, "alice", false);

        reg.record(
            &p,
            vec![addr(66)],
            DiscoverySource::Mdns,
            TrustState::NicknameConflict,
            100,
        );
        reg.record(
            &p,
            vec![addr(66)],
            DiscoverySource::Mdns,
            TrustState::Known,
            110,
        );

        assert_eq!(
            reg.snapshot()[0].trust,
            TrustState::NicknameConflict,
            "a warning must not evaporate just because the peer kept announcing",
        );
    }

    #[test]
    fn an_unknown_peer_always_reaches_the_keyring() {
        let (reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        assert_eq!(reg.cached_trust(alice.peer_id(), "alice", 100), None);
    }

    #[test]
    fn a_settled_peer_skips_the_write_until_the_interval_is_up() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(&p, vec![], DiscoverySource::Mdns, TrustState::Known, 100);
        reg.mark_persisted(alice.peer_id(), "alice", 100);

        // A beacon two seconds later costs nothing.
        assert_eq!(
            reg.cached_trust(alice.peer_id(), "alice", 102),
            Some(TrustState::Known)
        );
        // Once the interval passes, write through again.
        assert_eq!(
            reg.cached_trust(alice.peer_id(), "alice", 100 + PERSIST_INTERVAL_SECS),
            None
        );
    }

    #[test]
    fn a_changed_nickname_always_reaches_the_keyring() {
        // This is where impersonation surfaces, so it must never be skipped.
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::Known,
            100,
        );
        reg.mark_persisted(alice.peer_id(), "alice", 100);

        assert_eq!(reg.cached_trust(alice.peer_id(), "alice-laptop", 101), None);
    }

    #[test]
    fn a_returning_peer_writes_through_again() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(&p, vec![], DiscoverySource::Mdns, TrustState::Known, 100);
        reg.mark_persisted(alice.peer_id(), "alice", 100);
        reg.sweep(200);

        reg.record(&p, vec![], DiscoverySource::Mdns, TrustState::Known, 201);
        assert_eq!(
            reg.cached_trust(alice.peer_id(), "alice", 202),
            None,
            "bookkeeping was dropped"
        );
    }

    #[test]
    fn verifying_a_peer_shows_up_immediately_not_a_minute_later() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(&p, vec![], DiscoverySource::Mdns, TrustState::Known, 100);
        reg.mark_persisted(alice.peer_id(), "alice", 100);

        assert!(reg.set_trust(alice.peer_id(), TrustState::Verified));

        assert_eq!(
            reg.snapshot()[0].trust,
            TrustState::Verified,
            "the roster updates at once"
        );
        assert_eq!(
            reg.cached_trust(alice.peer_id(), "alice", 101),
            None,
            "the next sighting must re-read rather than restore the stale value",
        );
    }

    #[test]
    fn a_local_trust_decision_cannot_clear_a_conflict_warning() {
        let (mut reg, _me) = registry();
        let mallory = Identity::generate().unwrap();
        let p = presence(&mallory, "alice", false);

        reg.record(
            &p,
            vec![],
            DiscoverySource::Mdns,
            TrustState::NicknameConflict,
            100,
        );
        reg.set_trust(mallory.peer_id(), TrustState::Verified);

        assert_eq!(reg.snapshot()[0].trust, TrustState::NicknameConflict);
    }

    #[test]
    fn an_older_announcement_cannot_rewind_a_peer() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap().peer_id();

        assert!(reg.is_fresh(alice, 100), "the first one is always new");
        reg.note_presence(alice, 100);

        assert!(!reg.is_fresh(alice, 90), "an older one, captured earlier");
        assert!(!reg.is_fresh(alice, 1), "one captured long ago");
        assert!(
            !reg.is_fresh(alice, 100),
            "the very same one played back: on the mDNS path this would buy an \
             indefinite hold on a peer who has left"
        );
        assert!(reg.is_fresh(alice, 101), "their next genuine announcement");
    }

    #[test]
    fn a_peer_that_comes_back_can_announce_again() {
        // Field hardware without a battery boots at the epoch. Remembering a
        // departed peer's clock forever would lock it out of its own network.
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let p = presence(&alice, "alice", false);

        reg.record(&p, vec![], DiscoverySource::Beacon, TrustState::New, 100);
        reg.note_presence(alice.peer_id(), 5_000_000);
        reg.sweep(200);

        assert!(
            reg.is_fresh(alice.peer_id(), 1),
            "a reset clock is not a replay"
        );
    }

    #[test]
    fn one_peer_replaying_does_not_affect_another() {
        let (mut reg, _me) = registry();
        let (alice, bob) = (
            Identity::generate().unwrap().peer_id(),
            Identity::generate().unwrap().peer_id(),
        );
        reg.note_presence(alice, 500);

        assert!(reg.is_fresh(bob, 100), "bob has his own clock");
    }

    #[test]
    fn stale_peers_are_swept_and_reported() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.record(
            &presence(&bob, "bob", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            180,
        );

        let departed = reg.sweep(200);

        assert_eq!(departed.len(), 1);
        assert_eq!(departed[0].nickname, "alice");
        assert_eq!(reg.len(), 1);
    }

    const ALICE_SERVICE: &str = "alice-00112233._intraweb._tcp.local.";

    /// Regression: mDNS resolves a service once and the responder then renews
    /// the record behind our back rather than notifying us again, so there is
    /// no second sighting to refresh a heartbeat with. Sweeping an mDNS peer on
    /// the beacon's timeout dropped them after thirty seconds -- discovery that
    /// worked briefly and then went quiet, on exactly the multicast-only
    /// networks mDNS is there to cover.
    #[test]
    fn a_peer_held_by_mdns_outlives_the_heartbeat_timeout() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.hold_mdns(ALICE_SERVICE, alice.peer_id());

        assert!(
            reg.sweep(100_000).is_empty(),
            "mDNS has not withdrawn them, so they have not left"
        );
        assert_eq!(reg.len(), 1);
    }

    /// Nothing but mDNS ever saw them, so there is no heartbeat to wait out.
    #[test]
    fn a_peer_mdns_withdraws_leaves_at_once_if_nothing_else_saw_them() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.hold_mdns(ALICE_SERVICE, alice.peer_id());

        let departed = reg.release_mdns(ALICE_SERVICE);
        assert_eq!(
            departed.map(|peer| peer.nickname),
            Some("alice".to_string())
        );
        assert!(reg.is_empty(), "they are gone, not merely unheld");
    }

    /// A withdrawal names a service, not a key, so it may only evict somebody
    /// we ourselves filed under that name after checking their signature.
    #[test]
    fn a_withdrawal_naming_an_unverified_service_evicts_nobody() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.hold_mdns(ALICE_SERVICE, alice.peer_id());

        assert_eq!(reg.release_mdns("mallory-99._intraweb._tcp.local."), None);
        assert!(
            reg.sweep(100_000).is_empty(),
            "alice's hold must survive a stranger's service being withdrawn"
        );
    }

    /// Losing the multicast record is not losing the peer: the beacon is the
    /// other half of discovery and gets to vouch for them on its own.
    #[test]
    fn the_beacon_still_vouches_for_a_peer_mdns_has_lost() {
        let (mut reg, _me) = registry();
        let alice = Identity::generate().unwrap();

        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.hold_mdns(ALICE_SERVICE, alice.peer_id());

        // The beacon has been seeing them too.
        reg.record(
            &presence(&alice, "alice", false),
            vec![],
            DiscoverySource::Beacon,
            TrustState::New,
            195,
        );

        assert!(
            reg.release_mdns(ALICE_SERVICE).is_none(),
            "multicast losing them is not the beacon losing them"
        );
        assert!(reg.sweep(200).is_empty(), "the beacon still sees them");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn hubs_sort_first_so_the_roster_reads_sensibly() {
        let (mut reg, _me) = registry();
        let zoe = Identity::generate().unwrap();
        let hub = Identity::generate().unwrap();

        reg.record(
            &presence(&zoe, "zoe", false),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );
        reg.record(
            &presence(&hub, "library", true),
            vec![],
            DiscoverySource::Mdns,
            TrustState::New,
            100,
        );

        let snapshot = reg.snapshot();
        assert!(snapshot[0].is_hub);
        assert_eq!(snapshot[0].nickname, "library");
        assert_eq!(reg.hubs().len(), 1);
    }

    #[test]
    fn multiple_hubs_are_all_listed() {
        let (mut reg, _me) = registry();
        for name in ["basecamp", "library", "firehouse"] {
            let hub = Identity::generate().unwrap();
            reg.record(
                &presence(&hub, name, true),
                vec![],
                DiscoverySource::Mdns,
                TrustState::New,
                100,
            );
        }
        // One vault, many neighborhoods: we never pick just one.
        assert_eq!(reg.hubs().len(), 3);
    }
}
