//! Guards on the two ways a node is reachable: the filesystem it publishes,
//! and the browser sitting on the same machine.
//!
//! Both of the holes these close were demonstrated against a running node
//! rather than theorised, and both are the kind that only show up once
//! somebody points a real browser or a real symlink at you.

use std::path::{Component, Path, PathBuf};

/// Decode `%XX` escapes. The file services do their own decoding, so a guard
/// that skipped it could be walked straight past with `%2e%2e`.
pub fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a requested path really lands inside the folder we meant to publish.
///
/// `..` is rejected outright, and anything that exists is canonicalised before
/// the prefix check, so a symlink pointing out of the vault fails here. That
/// escape was real: a link in `files/` happily served `/etc/passwd`.
///
/// A path that does not exist is allowed through -- there is nothing to leak,
/// and the file service will answer 404 by itself.
pub fn resolves_within(root: &Path, request_path: &str) -> bool {
    let decoded = percent_decode(request_path);
    let relative = decoded.trim_start_matches('/');

    // Reject traversal before touching the disk. Windows prefixes and absolute
    // roots are refused for the same reason.
    let candidate = Path::new(relative);
    if candidate
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return false;
    }

    let Ok(canonical_root) = root.canonicalize() else {
        // We cannot publish a folder that is not there; let the 404 happen.
        return true;
    };
    let target: PathBuf = canonical_root.join(candidate);

    match target.canonicalize() {
        Ok(resolved) => resolved.starts_with(&canonical_root),
        Err(_) => true,
    }
}

/// Whether a browser request may change something.
///
/// A page on any other site can POST to `http://localhost:8420` and, until
/// this existed, could queue mail signed with your key. Browsers always attach
/// `Origin` to a cross-site write, so a mismatch is refused. Requests with no
/// `Origin` at all are other intraweb nodes and the command line, which are not
/// browsers and cannot be steered by a web page.
pub fn write_is_allowed(origin: Option<&str>, host: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    // "null" is what a sandboxed or file:// page sends. Never trust it.
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some(origin_host) = origin.split("://").nth(1) else {
        return false;
    };
    match host {
        Some(host) => origin_host.eq_ignore_ascii_case(host),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("files/maps")).unwrap();
        std::fs::write(dir.path().join("files/notes.txt"), "public").unwrap();
        std::fs::write(dir.path().join("files/maps/ridge.txt"), "public").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "private").unwrap();
        dir
    }

    #[test]
    fn ordinary_files_are_served() {
        let dir = fixture();
        let root = dir.path().join("files");
        assert!(resolves_within(&root, "/notes.txt"));
        assert!(resolves_within(&root, "maps/ridge.txt"));
    }

    #[test]
    fn a_symlink_out_of_the_folder_is_refused() {
        // The demonstrated hole: a link in files/ served content from outside
        // the vault, /etc/passwd included.
        let dir = fixture();
        let root = dir.path().join("files");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("secret.txt"), root.join("escape.txt")).unwrap();

        assert!(!resolves_within(&root, "/escape.txt"));
    }

    #[test]
    fn a_symlink_staying_inside_is_still_fine() {
        let dir = fixture();
        let root = dir.path().join("files");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("notes.txt"), root.join("alias.txt")).unwrap();

        assert!(
            resolves_within(&root, "/alias.txt"),
            "linking within your own folder is allowed"
        );
    }

    #[test]
    fn traversal_is_refused_plain_and_encoded() {
        let dir = fixture();
        let root = dir.path().join("files");
        assert!(!resolves_within(&root, "/../secret.txt"));
        assert!(!resolves_within(&root, "/%2e%2e/secret.txt"));
        assert!(!resolves_within(&root, "/maps/../../secret.txt"));
    }

    #[test]
    fn a_leading_slash_is_relative_to_the_shared_folder() {
        let dir = fixture();
        let root = dir.path().join("files");

        // "//etc/passwd" means <shared folder>/etc/passwd, which does not
        // exist, so it is left to 404 rather than reaching the real file.
        assert!(resolves_within(&root, "//etc/passwd"));

        // What must never pass is a path that climbs out.
        assert!(!resolves_within(&root, "/../../etc/passwd"));
        assert!(!resolves_within(&root, "maps/../../secret.txt"));
    }

    #[test]
    fn a_symlinked_directory_cannot_be_used_as_a_doorway() {
        // Linking a whole folder is the easy mistake: one link, everything
        // under it published.
        let dir = fixture();
        let root = dir.path().join("files");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("private.txt"), "private").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("shortcut")).unwrap();

        assert!(!resolves_within(&root, "/shortcut/private.txt"));
    }

    #[test]
    fn a_missing_file_is_left_to_answer_404() {
        let dir = fixture();
        let root = dir.path().join("files");
        assert!(resolves_within(&root, "/nothing-here.txt"));
    }

    #[test]
    fn percent_decoding_handles_junk_without_panicking() {
        assert_eq!(percent_decode("%2e%2e"), "..");
        assert_eq!(percent_decode("plain/path"), "plain/path");
        assert_eq!(percent_decode("%zz"), "%zz", "invalid escapes stay literal");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[test]
    fn the_dashboard_may_write_to_its_own_node() {
        assert!(write_is_allowed(
            Some("http://localhost:8420"),
            Some("localhost:8420")
        ));
        assert!(write_is_allowed(
            Some("http://intranet.local"),
            Some("intranet.local")
        ));
    }

    #[test]
    fn another_site_may_not_write() {
        // Demonstrated: this exact request queued signed mail.
        assert!(!write_is_allowed(
            Some("https://evil.example"),
            Some("localhost:8420")
        ));
        assert!(!write_is_allowed(
            Some("http://localhost:9999"),
            Some("localhost:8420")
        ));
        assert!(!write_is_allowed(Some("null"), Some("localhost:8420")));
    }

    #[test]
    fn peers_and_the_command_line_are_not_browsers() {
        // Neither attaches Origin, and neither can be driven by a web page.
        assert!(write_is_allowed(None, Some("192.168.1.8:8420")));
    }

    #[test]
    fn an_origin_with_no_host_to_compare_is_refused() {
        assert!(!write_is_allowed(Some("https://evil.example"), None));
    }
}
