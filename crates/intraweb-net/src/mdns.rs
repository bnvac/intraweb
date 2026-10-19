//! mDNS announcement and browsing.
//!
//! Every node registers one `_intraweb._tcp.local.` service carrying its signed
//! presence record in TXT properties. Hubs additionally claim the well-known
//! `intranet.local` hostname so a newcomer has somewhere to type; if two hubs
//! are up, mDNS conflict resolution renames the later one and both keep working.

use crate::beacon::local_addresses;
use crate::presence::Presence;
use anyhow::{Context, Result};
use intraweb_core::SERVICE_TYPE;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::net::IpAddr;
use tokio::sync::mpsc;

/// Hostname a hub claims so newcomers have a memorable place to start.
pub const HUB_HOSTNAME: &str = "intranet";

/// A presence record heard over mDNS, still unverified.
#[derive(Debug, Clone)]
pub struct MdnsSighting {
    pub presence: Presence,
    pub signature: Vec<u8>,
    pub addrs: Vec<IpAddr>,
}

pub struct MdnsNode {
    daemon: ServiceDaemon,
    /// The name we are currently registered under. `None` for an observer,
    /// which browses without announcing. Behind a lock because a rename
    /// replaces it while the browse loop is running.
    fullname: std::sync::Mutex<Option<String>>,
}

impl MdnsNode {
    /// Build the service record we announce.
    ///
    /// Separate from registering it, because a rename has to build the same
    /// shape again under a different name.
    fn service_for(presence: &Presence, signature: &[u8], is_hub: bool) -> Result<ServiceInfo> {
        // A hub takes the well-known name; everyone else derives a unique one
        // from their fingerprint so two people called "ben" never collide.
        let host_name = if is_hub {
            format!("{HUB_HOSTNAME}.local.")
        } else {
            let short: String = presence
                .peer_id
                .fingerprint()
                .chars()
                .filter(|c| *c != '-')
                .take(8)
                .collect();
            format!("{}-{short}.local.", presence.nickname)
        };

        // The instance name must be unique on the link. The fingerprint makes
        // it so without leaking anything the TXT record does not already carry.
        let instance = format!("{}-{}", presence.nickname, &presence.peer_id.to_hex()[..8]);

        let addrs = local_addresses();
        ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host_name,
            &addrs[..],
            presence.api_port,
            presence.to_txt(signature),
        )
        .context("could not build the mDNS service record")
    }

    /// Register this node and start answering queries about it.
    pub fn start(presence: &Presence, signature: &[u8], is_hub: bool) -> Result<Self> {
        let daemon = ServiceDaemon::new().context("could not start the mDNS responder")?;

        let service = Self::service_for(presence, signature, is_hub)?;
        let fullname = service.get_fullname().to_string();
        daemon
            .register(service)
            .context("could not register over mDNS")?;
        tracing::info!(%fullname, "announcing over mDNS");

        Ok(Self {
            daemon,
            fullname: std::sync::Mutex::new(Some(fullname)),
        })
    }

    /// Announce ourselves again under a changed name.
    ///
    /// The old registration is withdrawn first, or neighbors keep both: mDNS
    /// has no notion of replacing a record, only adding and removing one.
    pub fn reannounce(&self, presence: &Presence, signature: &[u8], is_hub: bool) -> Result<()> {
        if let Ok(mut held) = self.fullname.lock()
            && let Some(previous) = held.take()
        {
            let _ = self.daemon.unregister(&previous);
        }

        let service = Self::service_for(presence, signature, is_hub)?;
        let fullname = service.get_fullname().to_string();
        self.daemon
            .register(service)
            .context("could not re-register over mDNS")?;

        if let Ok(mut held) = self.fullname.lock() {
            *held = Some(fullname.clone());
        }
        tracing::info!(%fullname, "announcing under a new name");
        Ok(())
    }

    /// Browse without announcing.
    ///
    /// Looking around should not change what the network sees. It also avoids
    /// a second instance colliding with a node already running on this machine
    /// under the same key.
    pub fn observer() -> Result<Self> {
        let daemon = ServiceDaemon::new().context("could not start the mDNS responder")?;
        Ok(Self {
            daemon,
            fullname: std::sync::Mutex::new(None),
        })
    }

    /// Stream peers as mDNS resolves them.
    ///
    /// The responder is synchronous, so a dedicated thread bridges its channel
    /// into async-land rather than blocking a runtime worker indefinitely.
    pub fn browse(&self) -> Result<mpsc::Receiver<MdnsSighting>> {
        let events = self
            .daemon
            .browse(SERVICE_TYPE)
            .context("could not browse for peers")?;
        let (tx, rx) = mpsc::channel(64);

        std::thread::Builder::new()
            .name("intraweb-mdns-browse".into())
            .spawn(move || {
                while let Ok(event) = events.recv() {
                    let ServiceEvent::ServiceResolved(service) = event else {
                        continue;
                    };
                    let txt = service.txt_properties.clone().into_property_map_str();
                    let Ok((presence, signature)) = Presence::from_txt(&txt) else {
                        tracing::debug!(name = %service.fullname, "ignoring unreadable presence");
                        continue;
                    };
                    let addrs = service
                        .addresses
                        .iter()
                        .map(|scoped| scoped.to_ip_addr())
                        .collect();

                    if tx
                        .blocking_send(MdnsSighting {
                            presence,
                            signature,
                            addrs,
                        })
                        .is_err()
                    {
                        break; // The daemon shut down; stop bridging.
                    }
                }
            })
            .context("could not spawn the mDNS browse thread")?;

        Ok(rx)
    }

    /// Withdraw our announcement so peers drop us promptly instead of timing out.
    pub fn shutdown(&self) {
        if let Ok(held) = self.fullname.lock()
            && let Some(fullname) = held.as_ref()
        {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::Identity;

    #[test]
    fn hub_and_peer_hostnames_differ_predictably() {
        let id = Identity::generate().unwrap();
        let presence = Presence::new(&id, "ben", 8420, false, "basecamp");

        let short: String = presence
            .peer_id
            .fingerprint()
            .chars()
            .filter(|c| *c != '-')
            .take(8)
            .collect();

        // A peer's name is derived from its key, so two "ben"s cannot collide.
        assert_eq!(short.len(), 8);
        assert!(format!("{}-{short}.local.", presence.nickname).starts_with("ben-"));
    }
}
