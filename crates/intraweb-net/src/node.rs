//! The running node: both discovery paths, the keyring, and the live roster.
//!
//! Announcing is not "joining" in any ceremonial sense. A node shouts what it
//! is, listens for everyone else, and keeps a roster that expires. If three
//! hubs are within earshot, it appears on all three at once -- there is no
//! primary, and no hub is ever asked for permission.

use crate::beacon::{ANNOUNCE_INTERVAL_SECS, Beacon};
use crate::mdns::MdnsNode;
use crate::presence::Presence;
use crate::registry::{PeerRegistry, Sighting};
use anyhow::{Context, Result};
use intraweb_core::peer::{DiscoverySource, Peer, now_secs};
use intraweb_core::{Config, Identity, Store};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Shared read access to the roster, handed to the API and the terminal UI so
/// both render exactly the same thing.
#[derive(Clone)]
pub struct Roster {
    inner: Arc<RwLock<PeerRegistry>>,
}

impl Roster {
    /// A roster with nobody in it, for tests and for commands that act on a
    /// peer list they gathered themselves.
    pub fn empty(self_id: intraweb_core::PeerId) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerRegistry::new(self_id, 30))),
        }
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.inner
            .read()
            .map(|reg| reg.snapshot())
            .unwrap_or_default()
    }

    pub fn hubs(&self) -> Vec<Peer> {
        self.inner.read().map(|reg| reg.hubs()).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|reg| reg.len()).unwrap_or(0)
    }

    /// Refresh the set of keys we refuse to hear from.
    pub fn set_blocked(&self, blocked: std::collections::HashSet<intraweb_core::PeerId>) {
        if let Ok(mut reg) = self.inner.write() {
            reg.set_blocked(blocked);
        }
    }

    pub fn is_blocked(&self, peer_id: intraweb_core::PeerId) -> bool {
        self.inner
            .read()
            .map(|reg| reg.is_blocked(peer_id))
            .unwrap_or(false)
    }

    /// Record that the operator verified a peer, so the roster reflects it now
    /// rather than at the next keyring write-through.
    pub fn note_verified(&self, peer_id: intraweb_core::PeerId) -> bool {
        self.inner
            .write()
            .map(|mut reg| reg.set_trust(peer_id, intraweb_core::TrustState::Verified))
            .unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct Node {
    pub roster: Roster,
    mdns: Arc<MdnsNode>,
    /// The name we currently announce. Shared with the beacon loop so a
    /// rename is picked up on its next tick rather than at the next restart.
    announced: Arc<RwLock<String>>,
    identity: Arc<Identity>,
    api_port: u16,
    hub: bool,
    hub_name: String,
}

impl Node {
    /// Start announcing and listening. Returns once both loops are running.
    pub fn start(
        config: &Config,
        identity: Arc<Identity>,
        store: Arc<Mutex<Store>>,
    ) -> Result<Self> {
        Self::spawn(config, identity, store, true)
    }

    /// Listen without announcing.
    ///
    /// For commands that look around rather than take part. Nobody else learns
    /// we were here, and a node already running on this machine keeps its own
    /// announcement uncontested.
    pub fn observe(
        config: &Config,
        identity: Arc<Identity>,
        store: Arc<Mutex<Store>>,
    ) -> Result<Self> {
        Self::spawn(config, identity, store, false)
    }

    fn spawn(
        config: &Config,
        identity: Arc<Identity>,
        store: Arc<Mutex<Store>>,
        announce: bool,
    ) -> Result<Self> {
        let nickname = config.sanitized_nickname();
        let announced = Arc::new(RwLock::new(nickname.clone()));
        let presence = Presence::new(
            &identity,
            &nickname,
            config.api_port,
            config.hub,
            &config.hub_name,
        );
        let signature = presence.sign(&identity);

        let self_id = identity.peer_id();
        let registry = Arc::new(RwLock::new(PeerRegistry::new(
            self_id,
            config.peer_timeout_secs,
        )));
        let roster = Roster {
            inner: Arc::clone(&registry),
        };

        let mdns = Arc::new(if announce {
            MdnsNode::start(&presence, &signature, config.hub)?
        } else {
            MdnsNode::observer()?
        });

        // Inbound mDNS.
        {
            let mut sightings = mdns.browse()?;
            let registry = Arc::clone(&registry);
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                while let Some(sighting) = sightings.recv().await {
                    absorb(
                        &registry,
                        &store,
                        self_id,
                        &sighting.presence,
                        &sighting.signature,
                        sighting.addrs,
                        DiscoverySource::Mdns,
                    );
                }
            });
        }

        if config.beacon_enabled {
            let beacon = Arc::new(
                Beacon::bind(config.beacon_port)
                    .with_context(|| format!("could not open udp/{}", config.beacon_port))?,
            );

            // Outbound beacons. Re-signed each time so the timestamp stays
            // fresh and old packets cannot be replayed indefinitely.
            if announce {
                let beacon = Arc::clone(&beacon);
                let identity = Arc::clone(&identity);
                let config = config.clone();
                let announced = Arc::clone(&announced);
                tokio::spawn(async move {
                    let mut ticker =
                        tokio::time::interval(Duration::from_secs(ANNOUNCE_INTERVAL_SECS));
                    loop {
                        ticker.tick().await;
                        // Read the name each tick, so a rename takes effect
                        // without the node being restarted.
                        let nickname = announced
                            .read()
                            .map(|held| held.clone())
                            .unwrap_or_else(|_| config.sanitized_nickname());
                        let presence = Presence::new(
                            &identity,
                            &nickname,
                            config.api_port,
                            config.hub,
                            &config.hub_name,
                        );
                        match presence.to_beacon(&presence.sign(&identity)) {
                            Ok(packet) => {
                                beacon.announce(&packet).await;
                            }
                            Err(err) => tracing::warn!(%err, "could not build a beacon"),
                        }
                    }
                });
            }

            // Inbound beacons.
            {
                let registry = Arc::clone(&registry);
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    loop {
                        let Ok((packet, from)) = beacon.recv().await else {
                            continue;
                        };
                        let Ok((presence, signature)) = Presence::from_beacon(&packet) else {
                            continue;
                        };
                        absorb(
                            &registry,
                            &store,
                            self_id,
                            &presence,
                            &signature,
                            vec![from.ip()],
                            DiscoverySource::Beacon,
                        );
                    }
                });
            }
        }

        // Keep the in-memory blocklist in step with the keyring, so a block
        // made from the CLI reaches a already-running node.
        {
            let registry = Arc::clone(&registry);
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    let blocked = {
                        let Ok(store) = store.lock() else { continue };
                        store.blocked_peers().unwrap_or_default()
                    };
                    if let Ok(mut reg) = registry.write() {
                        reg.set_blocked(blocked.into_iter().collect());
                    }
                }
            });
        }

        // Expire peers that stopped announcing.
        {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(2));
                loop {
                    ticker.tick().await;
                    let departed = match registry.write() {
                        Ok(mut reg) => reg.sweep(now_secs()),
                        Err(_) => continue,
                    };
                    for peer in departed {
                        tracing::info!(nickname = %peer.nickname, "peer went quiet");
                    }
                }
            });
        }

        Ok(Self {
            roster,
            mdns,
            announced,
            identity,
            api_port: config.api_port,
            hub: config.hub,
            hub_name: config.hub_name.clone(),
        })
    }

    /// Announce a new name to the network, without a restart.
    ///
    /// The beacon picks it up on its next tick because it reads the shared
    /// name; mDNS has to be told, because a registration is replaced by
    /// withdrawing it and making another.
    pub fn rename(&self, nickname: &str) -> Result<()> {
        let presence = Presence::new(
            &self.identity,
            nickname,
            self.api_port,
            self.hub,
            &self.hub_name,
        );
        let signature = presence.sign(&self.identity);

        // Store the scrubbed form, so the beacon announces exactly what mDNS
        // just registered rather than something that differs by a character.
        if let Ok(mut held) = self.announced.write() {
            held.clone_from(&presence.nickname);
        }

        self.mdns.reannounce(&presence, &signature, self.hub)
    }

    pub fn shutdown(&self) {
        self.mdns.shutdown();
    }
}

/// Verify a sighting, record it in the keyring, and fold it into the roster.
///
/// Anything that fails verification is dropped silently at debug level: on an
/// open network, unverifiable packets are background noise, not incidents.
fn absorb(
    registry: &Arc<RwLock<PeerRegistry>>,
    store: &Arc<Mutex<Store>>,
    self_id: intraweb_core::PeerId,
    presence: &Presence,
    signature: &[u8],
    addrs: Vec<std::net::IpAddr>,
    source: DiscoverySource,
) {
    // Our own broadcast comes straight back to us and verifies perfectly --
    // it is genuinely our signature. Drop it here rather than after the
    // registry's self-check, or we file ourselves in our own keyring.
    if presence.peer_id == self_id {
        return;
    }

    // A blocked key is dropped before anything else happens: no verification,
    // no keyring write, no roster entry.
    if registry
        .read()
        .map(|reg| reg.is_blocked(presence.peer_id))
        .unwrap_or(false)
    {
        return;
    }

    let now = now_secs();
    if let Err(err) = presence.verify(signature, now) {
        tracing::debug!(%err, "discarding an unverifiable presence record");
        return;
    }

    // Most sightings are a peer we already know, saying the same thing it said
    // two seconds ago. Those need no database write at all.
    let cached = registry
        .read()
        .ok()
        .and_then(|reg| reg.cached_trust(presence.peer_id, &presence.nickname, now));

    let trust = match cached {
        Some(trust) => trust,
        None => {
            // Scoped so the database lock is never held across the roster lock.
            let persisted = {
                let Ok(store) = store.lock() else { return };
                store.observe_peer(presence.peer_id, &presence.nickname, now)
            };
            match persisted {
                Ok(trust) => {
                    if let Ok(mut reg) = registry.write() {
                        reg.mark_persisted(presence.peer_id, &presence.nickname, now);
                    }
                    trust
                }
                Err(err) => {
                    tracing::warn!(%err, "could not record a peer sighting");
                    return;
                }
            }
        }
    };

    let Ok(mut reg) = registry.write() else {
        return;
    };
    if reg.record(presence, addrs, source, trust, now) == Sighting::Arrived {
        tracing::info!(
            nickname = %presence.nickname,
            fingerprint = %presence.peer_id.fingerprint(),
            ?trust,
            "peer appeared",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::peer::TrustState;

    /// Regression: a node used to record its own echoed beacon in its keyring,
    /// inflating `known_peers` and filing itself as one of its own neighbors.
    #[test]
    fn our_own_echo_never_reaches_the_keyring() {
        let me = Arc::new(Identity::generate().unwrap());
        let self_id = me.peer_id();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let registry = Arc::new(RwLock::new(PeerRegistry::new(self_id, 30)));

        let mine = Presence::new(&me, "alice", 8420, true, "basecamp");
        let signature = mine.sign(&me);

        absorb(
            &registry,
            &store,
            self_id,
            &mine,
            &signature,
            vec![],
            DiscoverySource::Beacon,
        );

        assert_eq!(store.lock().unwrap().known_peer_count().unwrap(), 0);
        assert!(registry.read().unwrap().is_empty());
    }

    #[test]
    fn a_genuine_neighbor_is_still_recorded() {
        let me = Arc::new(Identity::generate().unwrap());
        let bob = Identity::generate().unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let registry = Arc::new(RwLock::new(PeerRegistry::new(me.peer_id(), 30)));

        let theirs = Presence::new(&bob, "bob", 8420, false, "");
        let signature = theirs.sign(&bob);

        absorb(
            &registry,
            &store,
            me.peer_id(),
            &theirs,
            &signature,
            vec![],
            DiscoverySource::Mdns,
        );

        assert_eq!(store.lock().unwrap().known_peer_count().unwrap(), 1);
        assert_eq!(
            registry.read().unwrap().snapshot()[0].trust,
            TrustState::New
        );
    }

    #[test]
    fn an_unverifiable_record_is_discarded_entirely() {
        let me = Arc::new(Identity::generate().unwrap());
        let mallory = Identity::generate().unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let registry = Arc::new(RwLock::new(PeerRegistry::new(me.peer_id(), 30)));

        let theirs = Presence::new(&mallory, "bob", 8420, false, "");
        let wrong_signature = [0u8; 64];

        absorb(
            &registry,
            &store,
            me.peer_id(),
            &theirs,
            &wrong_signature,
            vec![],
            DiscoverySource::Mdns,
        );

        assert_eq!(
            store.lock().unwrap().known_peer_count().unwrap(),
            0,
            "junk must not be filed"
        );
        assert!(registry.read().unwrap().is_empty());
    }
}
