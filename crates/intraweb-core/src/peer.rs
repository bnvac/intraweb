//! Peer records and the trust states the dashboard renders.

use crate::identity::PeerId;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// How we came to know a peer is present. Both paths running is normal and
/// healthy; seeing only `Beacon` means the network is filtering multicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoverySource {
    Mdns,
    Beacon,
    Both,
}

impl DiscoverySource {
    pub fn merge(self, other: Self) -> Self {
        if self == other { self } else { Self::Both }
    }
}

/// What we can honestly say about who a peer is.
///
/// The pivotal case is `NicknameConflict`. Nicknames are not unique and never
/// can be without a registry, so we do not pretend to police them. What we can
/// do is notice when a name we have seen before shows up carrying a different
/// key, and say so loudly instead of silently rendering a familiar label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    /// First sighting of this key. Trusted on use, remembered from here on.
    New,
    /// Key matches what we recorded previously.
    Known,
    /// A human compared fingerprints out of band and confirmed the match.
    Verified,
    /// This nickname previously belonged to a different key. Possible impostor.
    NicknameConflict,
    /// A key we have never seen whose fingerprint opens like one we know.
    ///
    /// A full fingerprint collision is out of reach, but grinding keys until
    /// the first group or two match is cheap -- and people compare the first
    /// group and stop reading.
    LookalikeFingerprint,
}

impl TrustState {
    /// Whether the dashboard should draw attention to this peer.
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::NicknameConflict | Self::LookalikeFingerprint)
    }

    /// A warning, once raised, is never quietly replaced by a calmer state.
    pub fn is_warning(self) -> bool {
        self.needs_attention()
    }
}

/// A peer as currently seen on the network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: PeerId,
    /// Short digest for reading aloud when verifying out of band.
    pub fingerprint: String,
    pub nickname: String,
    pub addrs: Vec<IpAddr>,
    pub api_port: u16,
    /// True when this peer offers itself as a meeting point.
    pub is_hub: bool,
    pub hub_name: Option<String>,
    pub source: DiscoverySource,
    pub trust: TrustState,
    /// Unix seconds. The UI formats these; the daemon stays locale-free.
    pub first_seen: u64,
    pub last_seen: u64,
}

impl Peer {
    /// Best address to reach this peer on, preferring IPv4 for LAN gear that
    /// still handles v6 badly.
    pub fn preferred_addr(&self) -> Option<IpAddr> {
        self.addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| self.addrs.first())
            .copied()
    }

    /// Where a browser should go to see this peer's corner of the web.
    pub fn site_url(&self) -> Option<String> {
        let addr = self.preferred_addr()?;
        let host = match addr {
            IpAddr::V6(v6) => format!("[{v6}]"),
            IpAddr::V4(v4) => v4.to_string(),
        };
        Some(format!(
            "http://{host}:{}/~{}",
            self.api_port, self.nickname
        ))
    }

    pub fn is_stale(&self, now: u64, timeout_secs: u64) -> bool {
        now.saturating_sub(self.last_seen) > timeout_secs
    }
}

/// Current unix time in seconds, saturating at the epoch for absurd clocks.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample(addrs: Vec<IpAddr>) -> Peer {
        let peer_id = Identity::generate().unwrap().peer_id();
        Peer {
            peer_id,
            fingerprint: peer_id.fingerprint(),
            nickname: "ben".into(),
            addrs,
            api_port: 8420,
            is_hub: false,
            hub_name: None,
            source: DiscoverySource::Mdns,
            trust: TrustState::New,
            first_seen: 100,
            last_seen: 100,
        }
    }

    #[test]
    fn prefers_ipv4_for_stubborn_lan_hardware() {
        let peer = sample(vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        ]);
        assert_eq!(
            peer.preferred_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)))
        );
    }

    #[test]
    fn falls_back_to_ipv6_when_alone() {
        let peer = sample(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert_eq!(peer.preferred_addr(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(
            peer.site_url().unwrap().contains("[::1]"),
            "v6 hosts need brackets"
        );
    }

    #[test]
    fn site_url_points_at_the_peer_not_a_hub() {
        let peer = sample(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))]);
        assert_eq!(peer.site_url().unwrap(), "http://192.168.1.20:8420/~ben");
    }

    #[test]
    fn staleness_uses_the_configured_timeout() {
        let peer = sample(vec![]);
        assert!(!peer.is_stale(120, 30));
        assert!(peer.is_stale(200, 30));
    }

    #[test]
    fn discovery_sources_merge_into_both() {
        assert_eq!(
            DiscoverySource::Mdns.merge(DiscoverySource::Mdns),
            DiscoverySource::Mdns
        );
        assert_eq!(
            DiscoverySource::Mdns.merge(DiscoverySource::Beacon),
            DiscoverySource::Both
        );
    }
}
