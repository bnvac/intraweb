//! Finding and opening the sites your neighbors are serving.
//!
//! Surfing asks each peer directly. There is no index, no crawler, and nothing
//! to route through: the roster supplies addresses and we speak HTTP to the
//! node itself. A hub that answered on a peer's behalf would be the very thing
//! this project exists to avoid.
//!
//! The HTTP lives in this crate rather than `intraweb-net` on purpose --
//! discovery has no business knowing what a web page is.

use anyhow::Result;
use intraweb_core::peer::{Peer, TrustState};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Enough of a page to reach `<title>` without pulling down somebody's photo
/// album to render a one-line listing.
const MAX_PROBE_BYTES: usize = 16 * 1024;

/// LAN round trips are fast. A peer that cannot answer in this long is either
/// gone or firewalled, and either way should not stall the listing.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// What we can say about one neighbor's site after asking it.
#[derive(Debug, Clone)]
pub struct SiteCard {
    pub nickname: String,
    pub fingerprint: String,
    pub is_hub: bool,
    /// What we can honestly say about who is behind this nickname.
    pub trust: TrustState,
    pub url: String,
    /// The page's own `<title>`, when it served one.
    pub title: Option<String>,
    /// Whether the peer actually answered. Listed-but-silent is worth showing.
    pub reachable: bool,
    pub status: Option<u16>,
}

impl SiteCard {
    /// The warning a listing must print instead of quietly showing a name.
    ///
    /// Surfing is exactly where impersonation would pay off, so a site whose
    /// nickname has changed keys says so next to its link, with the
    /// fingerprint needed to tell the two apart.
    pub fn warning(&self) -> Option<String> {
        (self.trust == TrustState::NicknameConflict).then(|| {
            format!(
                "not the \"{}\" you met before -- different key ({})",
                self.nickname, self.fingerprint
            )
        })
    }

    /// One-line description for the listing.
    pub fn describe(&self) -> String {
        match (&self.title, self.reachable, self.status) {
            (Some(title), _, _) => title.clone(),
            (None, true, Some(code)) if code >= 400 => format!("no site here (HTTP {code})"),
            (None, true, _) => "untitled page".to_string(),
            (None, false, _) => "not answering".to_string(),
        }
    }
}

/// Ask every peer what it is serving, all at once.
pub async fn survey(peers: Vec<Peer>, timeout: Duration) -> Vec<SiteCard> {
    let probes = peers
        .into_iter()
        .map(|peer| async move { probe(&peer, timeout).await });
    // Concurrent on purpose: a dozen neighbors should take one timeout, not a dozen.
    futures_lite(probes).await
}

/// Minimal `join_all`, so surfing does not pull in a futures crate.
async fn futures_lite<F, T>(futures: impl Iterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(value) = handle.await {
            out.push(value);
        }
    }
    out
}

/// Fetch a peer's front page and read what it says about itself.
pub async fn probe(peer: &Peer, timeout: Duration) -> SiteCard {
    let mut card = SiteCard {
        nickname: peer.nickname.clone(),
        fingerprint: peer.fingerprint.clone(),
        is_hub: peer.is_hub,
        trust: peer.trust,
        url: peer.site_url().unwrap_or_default(),
        title: None,
        reachable: false,
        status: None,
    };

    let Some(addr) = peer.preferred_addr() else {
        return card;
    };
    let path = format!("/~{}/", peer.nickname);

    // A refused connection and a slow one mean the same thing to a person
    // reading the list: you cannot get there from here.
    if let Ok(Ok(response)) = tokio::time::timeout(timeout, fetch(addr, peer.api_port, &path)).await
    {
        card.reachable = true;
        card.status = parse_status(&response);
        if card.status.is_some_and(|code| (200..300).contains(&code)) {
            card.title = extract_title(&response);
        }
    }
    card
}

/// One plain HTTP/1.0 exchange. No client library for a request this small.
async fn fetch(addr: IpAddr, port: u16, path: &str) -> Result<String> {
    let host = match addr {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    let mut stream = TcpStream::connect((addr, port)).await?;

    // HTTP/1.0 so the peer closes the connection itself and we can read to EOF
    // without parsing chunked encoding.
    let request = format!(
        "GET {path} HTTP/1.0\r\n\
         Host: {host}:{port}\r\n\
         User-Agent: intraweb-surf\r\n\
         Accept: text/html\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while buf.len() < MAX_PROBE_BYTES {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    buf.truncate(MAX_PROBE_BYTES);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Pull the status code out of an HTTP response.
fn parse_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Extract and tidy a page's `<title>`.
///
/// Deliberately forgiving: this reads pages written by neighbors in a text
/// editor, not machine-generated markup, so it should cope with odd casing and
/// attributes rather than insist on well-formed HTML.
fn extract_title(response: &str) -> Option<String> {
    let lower = response.to_lowercase();
    let open = lower.find("<title")?;
    // Skip any attributes on the tag itself.
    let content_start = open + lower[open..].find('>')? + 1;
    let close = lower[content_start..].find("</title>")? + content_start;

    let raw = response.get(content_start..close)?;
    let decoded = raw
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        // Ampersand last, so "&amp;lt;" does not become "<".
        .replace("&amp;", "&");

    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(truncate(&collapsed, 60))
}

/// Trim to a character budget without splitting a multi-byte character.
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit.saturating_sub(1)).collect();
    format!("{}…", kept.trim_end())
}

/// Hand a URL to the desktop's browser, where there is one.
pub fn open_in_browser(url: &str) -> Result<()> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|err| {
            anyhow::anyhow!("could not launch a browser ({opener}): {err}\nOpen it yourself: {url}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::Identity;
    use intraweb_core::peer::{DiscoverySource, TrustState};
    use std::net::Ipv4Addr;

    fn card(title: Option<&str>, reachable: bool, status: Option<u16>) -> SiteCard {
        SiteCard {
            nickname: "ben".into(),
            fingerprint: "aaaa-bbbb-cccc-dddd".into(),
            is_hub: false,
            trust: TrustState::Known,
            url: "http://192.168.1.5:8420/~ben".into(),
            title: title.map(String::from),
            reachable,
            status,
        }
    }

    #[test]
    fn reads_a_title_from_an_ordinary_page() {
        let response = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n\
                        <!doctype html><head><title>Basecamp Notice Board</title></head>";
        assert_eq!(
            extract_title(response).as_deref(),
            Some("Basecamp Notice Board")
        );
    }

    #[test]
    fn copes_with_hand_written_markup() {
        // Odd casing, an attribute on the tag, and a title spread over lines --
        // all things a person writing HTML by hand actually does.
        let response =
            "HTTP/1.0 200 OK\r\n\r\n<HTML><TITLE lang=\"en\">\n  Ben's\n  Photos\n</TITLE>";
        assert_eq!(extract_title(response).as_deref(), Some("Ben's Photos"));
    }

    #[test]
    fn decodes_entities_without_double_decoding() {
        let response = "HTTP/1.0 200 OK\r\n\r\n<title>Tools &amp; Spares &#39;24</title>";
        assert_eq!(
            extract_title(response).as_deref(),
            Some("Tools & Spares '24")
        );

        // An escaped entity must survive as text rather than becoming a tag.
        let tricky = "HTTP/1.0 200 OK\r\n\r\n<title>&amp;lt;not a tag&amp;gt;</title>";
        assert_eq!(extract_title(tricky).as_deref(), Some("&lt;not a tag&gt;"));
    }

    #[test]
    fn missing_or_empty_titles_are_none() {
        assert_eq!(
            extract_title("HTTP/1.0 200 OK\r\n\r\n<p>no title here</p>"),
            None
        );
        assert_eq!(
            extract_title("HTTP/1.0 200 OK\r\n\r\n<title>   </title>"),
            None
        );
        assert_eq!(
            extract_title("HTTP/1.0 200 OK\r\n\r\n<title>unterminated"),
            None
        );
    }

    #[test]
    fn long_titles_are_trimmed_on_a_character_boundary() {
        let long = "é".repeat(200);
        let response = format!("HTTP/1.0 200 OK\r\n\r\n<title>{long}</title>");
        let title = extract_title(&response).expect("should still produce a title");
        assert!(title.chars().count() <= 60);
        assert!(title.ends_with('…'));
    }

    #[test]
    fn reads_status_codes() {
        assert_eq!(parse_status("HTTP/1.0 200 OK\r\n\r\n"), Some(200));
        assert_eq!(parse_status("HTTP/1.1 404 Not Found\r\n\r\n"), Some(404));
        assert_eq!(parse_status("garbage"), None);
        assert_eq!(parse_status(""), None);
    }

    #[test]
    fn an_impostor_is_flagged_with_the_fingerprint_needed_to_tell_them_apart() {
        let mut impostor = card(Some("Photos"), true, Some(200));
        impostor.trust = TrustState::NicknameConflict;

        let warning = impostor
            .warning()
            .expect("a name clash must never render silently");
        assert!(warning.contains("different key"));
        assert!(
            warning.contains("aaaa-bbbb-cccc-dddd"),
            "must show how to tell them apart"
        );
    }

    #[test]
    fn ordinary_neighbors_carry_no_warning() {
        assert!(
            card(Some("Notice Board"), true, Some(200))
                .warning()
                .is_none()
        );
    }

    #[test]
    fn descriptions_say_what_actually_happened() {
        assert_eq!(
            card(Some("Notice Board"), true, Some(200)).describe(),
            "Notice Board"
        );
        assert_eq!(card(None, true, Some(200)).describe(), "untitled page");
        assert_eq!(
            card(None, true, Some(404)).describe(),
            "no site here (HTTP 404)"
        );
        assert_eq!(card(None, false, None).describe(), "not answering");
    }

    #[tokio::test]
    async fn a_peer_with_no_address_is_reported_unreachable_not_skipped() {
        let peer_id = Identity::generate().unwrap().peer_id();
        let peer = Peer {
            peer_id,
            encryption_key: Some(
                intraweb_core::SealingKey::derive(&Identity::generate().unwrap()).public(),
            ),
            fingerprint: peer_id.fingerprint(),
            nickname: "ghost".into(),
            addrs: vec![],
            api_port: 8420,
            is_hub: false,
            hub_name: None,
            source: DiscoverySource::Mdns,
            trust: TrustState::New,
            first_seen: 0,
            last_seen: 0,
        };

        let card = probe(&peer, Duration::from_millis(50)).await;
        assert!(!card.reachable);
        assert_eq!(card.describe(), "not answering");
    }

    #[tokio::test]
    async fn a_closed_port_times_out_without_hanging() {
        let peer_id = Identity::generate().unwrap().peer_id();
        let peer = Peer {
            peer_id,
            encryption_key: Some(
                intraweb_core::SealingKey::derive(&Identity::generate().unwrap()).public(),
            ),
            fingerprint: peer_id.fingerprint(),
            nickname: "quiet".into(),
            // Port 1 on loopback: nothing is listening there.
            addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            api_port: 1,
            is_hub: false,
            hub_name: None,
            source: DiscoverySource::Beacon,
            trust: TrustState::New,
            first_seen: 0,
            last_seen: 0,
        };

        let card = probe(&peer, Duration::from_millis(300)).await;
        assert!(!card.reachable);
    }
}
