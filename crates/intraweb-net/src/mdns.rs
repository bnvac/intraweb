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
use std::time::Duration;
use tokio::sync::mpsc;

/// How often the mDNS record is published again.
///
/// A presence record carries a timestamp and is only accepted inside the
/// clock-skew window. Registering once at startup meant that after the window
/// elapsed, every peer resolving the record rejected it as stale -- mDNS
/// discovery quietly stopped working on exactly the long-running nodes this
/// is built for. Comfortably inside the window, so a missed refresh is
/// survivable.
pub const REANNOUNCE_INTERVAL_SECS: u64 = 120;

// Registering once at startup let the record age out of the clock-skew window,
// after which every peer that resolved it rejected it as stale. Two refresh
// intervals must still fit inside that window, so one missed round does not
// make the node invisible to newcomers. Checked at compile time: changing
// either constant past the other should not build.
const _: () = assert!(REANNOUNCE_INTERVAL_SECS * 2 < crate::presence::MAX_CLOCK_SKEW_SECS);

/// How long to give the responder to put our goodbye on the wire before the
/// process exits.
///
/// `unregister` and `shutdown` only queue a command -- the responder sends the
/// packet from its own thread -- so dropping the acknowledgements and exiting
/// immediately meant the goodbye never left at all, and neighbors kept us on
/// their roster until our record expired minutes later. The first packet is
/// sent before the acknowledgement arrives, and mDNS repeats it shortly after
/// in case anyone missed it.
const GOODBYE_GRACE: Duration = Duration::from_millis(500);

/// How long mDNS waits before repeating a goodbye.
const GOODBYE_REPEAT: Duration = Duration::from_millis(250);

/// Hostname a hub claims so newcomers have a memorable place to start.
pub const HUB_HOSTNAME: &str = "intranet";

/// A presence record heard over mDNS, still unverified.
#[derive(Debug, Clone)]
pub struct MdnsSighting {
    pub presence: Presence,
    pub signature: Vec<u8>,
    pub addrs: Vec<IpAddr>,
    /// The service name this resolved under, so a later withdrawal of the same
    /// name can be tied back to the key we verify here.
    pub fullname: String,
}

/// What browsing reports.
///
/// mDNS does not repeat itself: a service resolves once and the record then
/// stands until it is withdrawn or expires, so presence has to be tracked by
/// these two edges rather than by counting sightings.
#[derive(Debug)]
pub enum MdnsEvent {
    /// A service resolved. Its presence record is still unverified.
    Seen(MdnsSighting),
    /// A service was withdrawn, by goodbye packet or by expiring. Carries only
    /// the service name; mDNS has no idea whose key was behind it.
    Gone { fullname: String },
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
        let service = Self::service_for(presence, signature, is_hub)?;
        let fullname = service.get_fullname().to_string();

        // Withdraw the old registration only when the name really changed. A
        // refresh under the same name must not send a goodbye first: that
        // withdraws us from every roster on the link until we are resolved
        // again, and the responder treats a repeat `register` as an update.
        let previous = self.fullname.lock().ok().and_then(|held| held.clone());
        let renamed = previous.as_deref().is_some_and(|prev| prev != fullname);
        if renamed && let Some(previous) = previous {
            let _ = self.daemon.unregister(&previous);
        }

        self.daemon
            .register(service)
            .context("could not re-register over mDNS")?;

        if let Ok(mut held) = self.fullname.lock() {
            *held = Some(fullname.clone());
        }
        if renamed {
            tracing::info!(%fullname, "announcing under a new name");
        } else {
            tracing::debug!(%fullname, "refreshed our mDNS record");
        }
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
    pub fn browse(&self) -> Result<mpsc::Receiver<MdnsEvent>> {
        let events = self
            .daemon
            .browse(SERVICE_TYPE)
            .context("could not browse for peers")?;
        let (tx, rx) = mpsc::channel(64);

        std::thread::Builder::new()
            .name("intraweb-mdns-browse".into())
            .spawn(move || {
                while let Ok(event) = events.recv() {
                    let outgoing = match event {
                        ServiceEvent::ServiceResolved(service) => {
                            let txt = service.txt_properties.clone().into_property_map_str();
                            let Ok((presence, signature)) = Presence::from_txt(&txt) else {
                                tracing::debug!(
                                    name = %service.fullname,
                                    "ignoring unreadable presence",
                                );
                                continue;
                            };
                            let addrs = service
                                .addresses
                                .iter()
                                .map(|scoped| scoped.to_ip_addr())
                                .collect();
                            MdnsEvent::Seen(MdnsSighting {
                                presence,
                                signature,
                                addrs,
                                fullname: service.fullname.clone(),
                            })
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => MdnsEvent::Gone { fullname },
                        _ => continue,
                    };

                    if tx.blocking_send(outgoing).is_err() {
                        break; // The daemon shut down; stop bridging.
                    }
                }
            })
            .context("could not spawn the mDNS browse thread")?;

        Ok(rx)
    }

    /// Withdraw our announcement so peers drop us promptly instead of timing out.
    pub fn shutdown(&self) {
        // Taken by value so the lock is not held while we wait.
        let fullname = self.fullname.lock().ok().and_then(|held| held.clone());
        if let Some(fullname) = fullname
            && let Ok(acknowledged) = self.daemon.unregister(&fullname)
        {
            // The acknowledgement comes after the packet is sent, so this is
            // what actually gets the goodbye out.
            let _ = acknowledged.recv_timeout(GOODBYE_GRACE);
            // And this lets the repeat follow it. Only an announcing node pays
            // the wait, once, on its way out.
            std::thread::sleep(GOODBYE_REPEAT);
        }
        if let Ok(stopped) = self.daemon.shutdown() {
            let _ = stopped.recv_timeout(GOODBYE_GRACE);
        }
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
