//! Node configuration. Small on purpose: discovery is meant to need no setup.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Dashboard and JSON API. The hub also tries port 80 so URLs stay clean.
pub const DEFAULT_API_PORT: u16 = 8420;
/// UDP broadcast beacon, used where the network filters multicast.
pub const DEFAULT_BEACON_PORT: u16 = 8420;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Display name. Decoration only -- your key is your real identity, and two
    /// people may pick the same nickname without either being an impostor.
    pub nickname: String,

    /// A line about yourself, shown on your own dashboard. Purely local -- it
    /// is not announced, so it costs nothing on the wire and nobody else's
    /// node has to carry it.
    pub tagline: String,

    /// Run as a hub: claim `intranet.local` and keep a roster for the network.
    /// A hub is a meeting point, not an owner. It stores no member content.
    pub hub: bool,

    /// Name shown for this hub in rosters. Ignored unless `hub` is true.
    pub hub_name: String,

    /// Announce to every hub discovered, not just the first one found.
    /// This is what makes one vault appear across many neighborhoods at once.
    pub join_all_hubs: bool,

    /// Dashboard, JSON API, mail delivery, and file downloads. One port: a
    /// peer that can show you a page can also take your mail.
    pub api_port: u16,
    pub beacon_port: u16,

    /// Send UDP broadcast beacons as well as mDNS. Cheap insurance: plenty of
    /// consumer access points quietly drop multicast.
    pub beacon_enabled: bool,

    /// Seconds without a sighting before a peer drops off the roster.
    pub peer_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: default_nickname(),
            tagline: String::new(),
            hub: false,
            hub_name: "neighborhood".to_string(),
            join_all_hubs: true,
            api_port: DEFAULT_API_PORT,
            beacon_port: DEFAULT_BEACON_PORT,
            beacon_enabled: true,
            peer_timeout_secs: 30,
        }
    }
}

impl Config {
    /// Read config from the vault, writing a commented default on first run.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("could not parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let body = toml::to_string_pretty(self).context("could not serialize config")?;
        std::fs::write(path, format!("{CONFIG_HEADER}{body}"))
            .with_context(|| format!("could not write {}", path.display()))
    }

    /// Nicknames travel in mDNS TXT records and URLs, so keep them tame.
    pub fn sanitized_nickname(&self) -> String {
        let cleaned: String = self
            .nickname
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
}

const CONFIG_HEADER: &str = "\
# intraweb -- your neighborhood web
#
# Your identity is the key in identity.key, not anything written here.
# Renaming yourself below does not change who you are to peers who already
# know you; they will simply see the new label next to the same fingerprint.

";

fn default_nickname() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "neighbor".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let written = Config::load_or_create(&path).unwrap();
        let reread = Config::load_or_create(&path).unwrap();

        assert_eq!(written.api_port, reread.api_port);
        assert_eq!(written.nickname, reread.nickname);
        assert!(reread.join_all_hubs, "multi-hub is the default posture");
    }

    #[test]
    fn nicknames_are_scrubbed_for_dns_and_urls() {
        let config = Config {
            nickname: "Ben Vaccaro!! <script>".to_string(),
            ..Config::default()
        };
        assert_eq!(config.sanitized_nickname(), "benvaccaroscript");
    }

    #[test]
    fn empty_nickname_falls_back() {
        let config = Config {
            nickname: "!!!".to_string(),
            ..Config::default()
        };
        assert_eq!(config.sanitized_nickname(), "neighbor");
    }
}
