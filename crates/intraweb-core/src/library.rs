//! Media libraries a node points its neighbors at.
//!
//! Plenty of people already run Jellyfin, Navidrome, Calibre-Web or Immich on
//! the machine under the desk. A library entry tells the neighborhood that it
//! exists and where it listens, so it shows up as a button on your card.
//!
//! A library is a link, never a relay. The browser goes straight to the
//! service on your machine; no node, and no hub, carries a byte of the media.
//! That keeps the rule that a hub stores and proxies nothing, and it means a
//! film streams at whatever speed the two machines manage between them.
//!
//! Everything here also arrives from strangers, because a neighbor's list is
//! read over the network. [`Library::checked`] is the one gate both paths go
//! through, so a hostile node cannot hand the dashboard a script URL or a
//! name built to break the page.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// The kinds the dashboard knows how to label. Anything else is "other", so a
/// node from a newer release with a new kind still shows up.
pub const KINDS: &[&str] = &["video", "music", "books", "photos", "other"];

/// Longest name shown on a button before it stops being a button.
const MAX_NAME: usize = 40;
/// Longest path kept. Real ones are `/` or `/web/`.
const MAX_PATH: usize = 120;
/// Ceiling on how many entries one node may list, so a neighbor cannot fill
/// the dashboard with thousands of buttons.
pub const MAX_LIBRARIES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// What neighbors see on the button, e.g. "Films" or "Jellyfin".
    pub name: String,
    /// Port the service listens on, on this same machine.
    pub port: u16,
    /// Where its web interface starts. `/` for most.
    #[serde(default = "root_path")]
    pub path: String,
    /// One of [`KINDS`].
    #[serde(default = "other_kind")]
    pub kind: String,
}

fn root_path() -> String {
    "/".to_string()
}

fn other_kind() -> String {
    "other".to_string()
}

impl Library {
    /// Build a library from untrusted parts, refusing anything that could be
    /// turned against the page that renders it.
    pub fn checked(name: &str, port: u16, path: &str, kind: &str) -> Result<Self> {
        // Control characters and markup delimiters have no business in a
        // button label; dropping them is simpler than escaping them twice.
        let name: String = name
            .chars()
            .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '"' | '`'))
            .collect::<String>()
            .trim()
            .chars()
            .take(MAX_NAME)
            .collect();
        if name.is_empty() {
            bail!("give the library a name, like \"Films\" or \"Jellyfin\"");
        }
        if port == 0 {
            bail!("port 0 is not a port; use the one the service listens on, like 8096");
        }

        let path = if path.is_empty() { "/" } else { path };
        // The URL is built as http://<their address>:<port><path>, so the path
        // is the only part a sender controls. It must stay a path on that host:
        // no scheme, no second host smuggled in with `//`, nothing that is not
        // plain URL text.
        if !path.starts_with('/') || path.starts_with("//") {
            bail!("the path must start with a single /, like /web/");
        }
        if path.len() > MAX_PATH
            || !path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-._~%".contains(c))
        {
            bail!("the path may only use letters, digits and / - . _ ~ %");
        }

        let kind = if KINDS.contains(&kind) {
            kind.to_string()
        } else {
            "other".to_string()
        };
        Ok(Self {
            name,
            port,
            path: path.to_string(),
            kind,
        })
    }

    /// Re-check an entry, as read from a config file or a neighbor.
    pub fn recheck(&self) -> Result<Self> {
        Self::checked(&self.name, self.port, &self.path, &self.kind)
    }

    /// Guess the kind from the service people usually mean by a port, so
    /// `intraweb library add Films 8096` needs no flag.
    pub fn kind_for_port(port: u16) -> &'static str {
        match port {
            8096 | 8920 | 32400 => "video", // Jellyfin, Plex
            4533 | 4040 => "music",         // Navidrome, Airsonic
            8083 | 5000 => "books",         // Calibre-Web, Kavita
            2283 | 2342 => "photos",        // Immich, PhotoPrism
            _ => "other",
        }
    }
}

/// Keep the good entries from an untrusted list and drop the rest, capped.
pub fn sanitize_list(list: Vec<Library>) -> Vec<Library> {
    list.into_iter()
        .filter_map(|lib| lib.recheck().ok())
        .take(MAX_LIBRARIES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_library_is_accepted_as_given() {
        let lib = Library::checked("Films", 8096, "/web/", "video").unwrap();
        assert_eq!(lib.name, "Films");
        assert_eq!(lib.path, "/web/");
        assert_eq!(lib.kind, "video");
    }

    #[test]
    fn an_empty_path_means_the_root() {
        assert_eq!(
            Library::checked("Music", 4533, "", "music").unwrap().path,
            "/"
        );
    }

    #[test]
    fn a_path_cannot_name_another_host() {
        assert!(Library::checked("x", 80, "//evil.example/", "video").is_err());
        assert!(Library::checked("x", 80, "http://evil.example/", "video").is_err());
        assert!(Library::checked("x", 80, "javascript:alert(1)", "video").is_err());
    }

    #[test]
    fn a_path_cannot_carry_markup_or_spaces() {
        assert!(Library::checked("x", 80, "/a\"onload=1", "video").is_err());
        assert!(Library::checked("x", 80, "/a b", "video").is_err());
        assert!(Library::checked("x", 80, "/<script>", "video").is_err());
    }

    #[test]
    fn markup_is_stripped_from_a_name_and_an_empty_name_refused() {
        let lib = Library::checked("<b>Films</b>", 8096, "/", "video").unwrap();
        assert!(!lib.name.contains('<') && !lib.name.contains('>'));
        assert!(Library::checked("<>", 8096, "/", "video").is_err());
        assert!(Library::checked("   ", 8096, "/", "video").is_err());
    }

    #[test]
    fn a_long_name_is_cut_to_fit_a_button() {
        let lib = Library::checked(&"a".repeat(500), 8096, "/", "video").unwrap();
        assert_eq!(lib.name.chars().count(), MAX_NAME);
    }

    #[test]
    fn port_zero_is_refused() {
        assert!(Library::checked("Films", 0, "/", "video").is_err());
    }

    #[test]
    fn an_unknown_kind_becomes_other_rather_than_failing() {
        assert_eq!(
            Library::checked("Maps", 9000, "/", "maps").unwrap().kind,
            "other"
        );
    }

    #[test]
    fn well_known_ports_suggest_a_kind() {
        assert_eq!(Library::kind_for_port(8096), "video");
        assert_eq!(Library::kind_for_port(4533), "music");
        assert_eq!(Library::kind_for_port(8083), "books");
        assert_eq!(Library::kind_for_port(2283), "photos");
        assert_eq!(Library::kind_for_port(1234), "other");
    }

    #[test]
    fn a_hostile_list_is_filtered_and_capped() {
        let mut list = vec![Library {
            name: "ok".into(),
            port: 1,
            path: "//evil".into(),
            kind: "video".into(),
        }];
        for i in 0..100 {
            list.push(Library {
                name: format!("lib {i}"),
                port: 8000,
                path: "/".into(),
                kind: "video".into(),
            });
        }
        let kept = sanitize_list(list);
        assert_eq!(kept.len(), MAX_LIBRARIES);
        assert!(kept.iter().all(|l| l.path == "/"));
    }
}
