//! The local JSON API, and the static serving of your own corner of the web.
//!
//! This is the single source of truth for state. The browser dashboard and the
//! terminal UI are both thin clients over these endpoints, so the two can never
//! drift into disagreeing about who is on the network.
//!
//! Note what is *not* here: no endpoint proxies another node's content. The
//! roster hands out addresses, and the browser goes straight to the peer. A hub
//! that relayed content would become the thing this project exists to avoid.

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use intraweb_core::SignedMail;
use intraweb_core::channel::{ChannelId, Invite, SignedPost};
use intraweb_core::identity::PeerId;
use intraweb_core::peer::now_secs;
use intraweb_core::sealed::SealingKey;
use intraweb_core::{Config, Identity, Store, Vault};
use intraweb_net::Roster;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::services::ServeDir;

/// Dashboard assets are compiled in, so the binary really is the whole program.
const DASHBOARD_HTML: &str = include_str!("../web/index.html");
const DASHBOARD_CSS: &str = include_str!("../web/style.css");
const DASHBOARD_JS: &str = include_str!("../web/app.js");

#[derive(Clone)]
pub struct AppState {
    pub roster: Roster,
    pub identity: Arc<Identity>,
    pub store: Arc<Mutex<Store>>,
    pub config: Arc<Config>,
    pub vault: Arc<Vault>,
    /// What to publish as this node's site. Normally the vault's `site/`, but
    /// `intraweb serve` points it at a folder without copying anything in.
    pub site_dir: PathBuf,
    pub started_at: u64,
    /// Bounds what strangers can make this node store.
    pub limiter: Arc<crate::limits::RateLimiter>,
    /// The running node, so a rename can be announced without a restart.
    /// `None` for commands that serve nothing.
    pub node: Option<Arc<intraweb_net::Node>>,
}

#[derive(Serialize)]
struct Status {
    nickname: String,
    tagline: String,
    peer_id: String,
    fingerprint: String,
    is_hub: bool,
    hub_name: Option<String>,
    api_port: u16,
    peers_online: usize,
    hubs_online: usize,
    known_peers: u64,
    unread_mail: u64,
    /// Our own guestbook, so the dashboard can give it its own panel instead
    /// of leaving it among the channel tabs.
    guestbook_channel: String,
    vault_path: String,
    site_path: String,
    uptime_secs: u64,
    now: u64,
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(status_of(&state))
}

fn status_of(state: &AppState) -> Status {
    let known_peers = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.known_peer_count().ok())
        .unwrap_or(0);

    Status {
        nickname: state.config.sanitized_nickname(),
        tagline: profile_on_disk(state).tagline,
        peer_id: state.identity.peer_id().to_hex(),
        fingerprint: state.identity.fingerprint(),
        is_hub: state.config.hub,
        hub_name: state.config.hub.then(|| state.config.hub_name.clone()),
        api_port: state.config.api_port,
        peers_online: state.roster.len(),
        hubs_online: state.roster.hubs().len(),
        known_peers,
        guestbook_channel: ChannelId::guestbook_of(state.identity.peer_id()).to_hex(),
        unread_mail: state
            .store
            .lock()
            .ok()
            .and_then(|store| store.unread_count().ok())
            .unwrap_or(0),
        vault_path: state.vault.root().display().to_string(),
        site_path: state.site_dir.display().to_string(),
        uptime_secs: now_secs().saturating_sub(state.started_at),
        now: now_secs(),
    }
}

async fn peers(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(state.roster.peers())
}

/// Every hub in earshot. Plural on purpose: one vault, many neighborhoods.
async fn hubs(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(state.roster.hubs())
}

async fn hub_history(State(state): State<AppState>) -> impl IntoResponse {
    let history = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.hub_history(20).ok())
        .unwrap_or_default();
    axum::Json(history)
}

/// Record that a human compared fingerprints out of band and they matched.
async fn verify_peer(
    State(state): State<AppState>,
    Path(peer_hex): Path<String>,
) -> impl IntoResponse {
    let Some(peer_id) = PeerId::parse_hex(&peer_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid peer id").into_response();
    };
    let Ok(store) = state.store.lock() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "keyring is unavailable").into_response();
    };
    match store.mark_verified(peer_id) {
        Ok(true) => {
            state.roster.note_verified(peer_id);
            (StatusCode::OK, "verified").into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "we have never seen that peer").into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not verify: {err}"),
        )
            .into_response(),
    }
}

/// Refuse to see or hear from a key from now on.
async fn block_peer(
    State(state): State<AppState>,
    Path(peer_hex): Path<String>,
) -> impl IntoResponse {
    let Some(peer_id) = PeerId::parse_hex(&peer_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid peer id").into_response();
    };
    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the keyring is busy").into_response();
    };
    match store.block(peer_id, "blocked from the dashboard", now_secs()) {
        Ok(()) => {
            // Take effect now rather than at the next blocklist refresh.
            let blocked = store.blocked_peers().unwrap_or_default();
            drop(store);
            state.roster.set_blocked(blocked.into_iter().collect());
            (StatusCode::OK, "blocked").into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}")).into_response(),
    }
}

async fn unblock_peer(
    State(state): State<AppState>,
    Path(peer_hex): Path<String>,
) -> impl IntoResponse {
    let Some(peer_id) = PeerId::parse_hex(&peer_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid peer id").into_response();
    };
    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the keyring is busy").into_response();
    };
    match store.unblock(peer_id) {
        Ok(_) => {
            let blocked = store.blocked_peers().unwrap_or_default();
            drop(store);
            state.roster.set_blocked(blocked.into_iter().collect());
            (StatusCode::OK, "unblocked").into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}")).into_response(),
    }
}

/// Run the network diagnosis on demand. Kept short so the dashboard can wait.
async fn doctor(State(state): State<AppState>) -> impl IntoResponse {
    match intraweb_net::doctor::run(state.config.beacon_port, Duration::from_secs(3)).await {
        Ok(report) => axum::Json(report).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("diagnosis failed: {err}"),
        )
            .into_response(),
    }
}

/// Take delivery of a message from another node.
///
/// Two things are checked before anything is written: that the signature
/// matches the key the message names, and that it is addressed to us. The
/// second stops this node being used as a drop box for other people's mail.
async fn receive_mail(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let sealed: SignedMail = match serde_json::from_str(&body) {
        Ok(sealed) => sealed,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unreadable message: {err}"),
            )
                .into_response();
        }
    };

    if let Err(err) = sealed.accept(state.identity.peer_id()) {
        // Unsigned or misaddressed mail on an open network is noise, not news.
        tracing::debug!(%err, "refused an incoming message");
        return (StatusCode::FORBIDDEN, format!("refused: {err}")).into_response();
    }

    // Only now is the sender's identity proven, so only now is it worth
    // spending a lookup or a rate-limit token on them.
    let sender = sealed.mail.from;

    if state.roster.is_blocked(sender) {
        tracing::debug!(fingerprint = %sender.fingerprint(), "refused mail from a blocked key");
        return (StatusCode::FORBIDDEN, "refused").into_response();
    }

    if !state.limiter.allow(sender, crate::limits::now_float()) {
        tracing::warn!(fingerprint = %sender.fingerprint(), "rate limited an incoming message");
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }

    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the mail store is busy").into_response();
    };

    // A full inbox is refused rather than allowed to fill the disk a field
    // node boots from.
    if store.inbox_bytes().unwrap_or(0) > MAX_INBOX_BYTES {
        tracing::warn!("inbox is at its size limit; refusing mail");
        return (StatusCode::INSUFFICIENT_STORAGE, "this inbox is full").into_response();
    }

    match store.store_incoming(&sealed, now_secs()) {
        // A duplicate still reports success: the sender has done its job and
        // should stop retrying.
        Ok(filed) => {
            if filed {
                tracing::info!(
                    from = %sealed.mail.from.fingerprint(),
                    subject = %sealed.mail.subject,
                    "mail received",
                );
            }
            (StatusCode::OK, if filed { "filed" } else { "already held" }).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not file it: {err}"),
        )
            .into_response(),
    }
}

/// Everything the dashboard needs, in one request.
///
/// It used to poll status and peers separately every couple of seconds, which
/// doubled the traffic and the wakeups for no benefit -- they are always
/// rendered together.
async fn combined_state(State(state): State<AppState>) -> impl IntoResponse {
    let status = status_of(&state);
    let peers = state.roster.peers();
    let mail = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.inbox(50).ok())
        .unwrap_or_default();

    axum::Json(serde_json::json!({ "status": status, "peers": peers, "mail": mail }))
}

#[derive(serde::Deserialize)]
struct Compose {
    to: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
}

/// Queue a message written in the dashboard.
///
/// Resolution is the same as the CLI's, ambiguity included: a nickname held by
/// two keys is reported back rather than resolved to whichever came first.
async fn send_mail(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let Ok(compose) = serde_json::from_str::<Compose>(&body) else {
        return (StatusCode::BAD_REQUEST, "could not read that form").into_response();
    };

    let peers = crate::mail::addressable(&state.roster.peers(), &state.store);
    let recipient = match crate::mail::resolve_or_explain(&peers, &compose.to) {
        Ok(peer) => peer,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    };

    match crate::mail::queue(
        &state.store,
        state.identity.peer_id(),
        recipient.peer_id,
        &compose.subject,
        &compose.body,
        None,
    ) {
        Ok(_) => (
            StatusCode::OK,
            format!(
                "Queued for {} ({})",
                recipient.nickname, recipient.fingerprint
            ),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")).into_response(),
    }
}

async fn inbox(State(state): State<AppState>) -> impl IntoResponse {
    let messages = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.inbox(100).ok())
        .unwrap_or_default();
    axum::Json(messages)
}

async fn outbox(State(state): State<AppState>) -> impl IntoResponse {
    let messages = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.outbox(100).ok())
        .unwrap_or_default();
    axum::Json(messages)
}

async fn mark_all_read(State(state): State<AppState>) -> impl IntoResponse {
    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the mail store is busy").into_response();
    };
    match store.mark_all_read(now_secs()) {
        Ok(count) => (StatusCode::OK, count.to_string()).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// The page this node publishes, and whatever sits beside it.
#[derive(Serialize)]
struct SiteView {
    /// The folder being published, so the editor can say where it writes.
    /// `intraweb serve` points this outside the vault.
    path: String,
    /// `index.html` as it stands, empty when there is not one yet.
    html: String,
    files: Vec<SiteFile>,
}

#[derive(Serialize)]
struct SiteFile {
    name: String,
    size: u64,
}

/// The page a node serves at `/~nickname`.
const SITE_INDEX: &str = "index.html";

/// The largest thing the dashboard will write into the published folder.
///
/// The body is buffered whole to be written, and a node is expected to run on
/// a Pi booting off an SD card, so this bounds both the memory it takes and
/// the mess a slip of the mouse can make. Large media belongs in `files/`,
/// which is served off disk without being read into memory at all.
const MAX_SITE_WRITE: usize = 4 * 1024 * 1024;

/// Accept a plain filename, and nothing that could name somewhere else.
///
/// The name arrives inside a URL, so it is percent-encoded and hostile until
/// checked. Anything with a separator, a traversal or a leading dot is refused
/// outright rather than rewritten into something safe: a name that needs
/// repairing is not the name the person meant to type, and silently saving
/// their file somewhere else is worse than saying no.
fn safe_site_name(raw: &str) -> Option<String> {
    let name = crate::guard::percent_decode(raw);
    if name.is_empty() || name.len() > 96 || name.starts_with('.') {
        return None;
    }
    if name.contains(['/', '\\', '\0']) {
        return None;
    }
    // Belt and braces: the name must still describe one ordinary path segment.
    let plain = std::path::Path::new(&name)
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)));
    plain.then_some(name)
}

/// Whether this path is a symlink, which is never ours to write through.
///
/// `ServeDir` following a link out of the published folder was a real hole,
/// closed by `guarded_dir`. Writing is the same hole pointed the other way: a
/// link planted in the folder would let a save land outside it, so a save onto
/// one is refused rather than followed.
fn is_symlink(path: &std::path::Path) -> bool {
    path.symlink_metadata()
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

async fn get_site(State(state): State<AppState>) -> impl IntoResponse {
    let dir = &state.site_dir;
    let html = std::fs::read_to_string(dir.join(SITE_INDEX)).unwrap_or_default();

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == SITE_INDEX {
                continue;
            }
            // Deliberately not following links: what one points at is not
            // this node's to publish or to describe.
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            files.push(SiteFile {
                name,
                size: meta.len(),
            });
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));

    axum::Json(SiteView {
        path: dir.display().to_string(),
        html,
        files,
    })
}

async fn put_site(State(state): State<AppState>, body: String) -> impl IntoResponse {
    write_site_file(
        &state,
        SITE_INDEX,
        body.as_bytes(),
        "Saved. Your page is live.",
    )
}

async fn put_site_file(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(name) = safe_site_name(&name) else {
        return (
            StatusCode::BAD_REQUEST,
            "that filename cannot be used; plain names only, no folders",
        )
            .into_response();
    };
    let message = format!("Uploaded {name}.");
    write_site_file(&state, &name, &body, &message)
}

/// The one path from the dashboard to the published folder.
///
/// Shared so the size cap and the symlink refusal cannot be in force on one
/// route and forgotten on the next.
fn write_site_file(
    state: &AppState,
    name: &str,
    body: &[u8],
    message: &str,
) -> axum::response::Response {
    if body.len() > MAX_SITE_WRITE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "that is larger than the {}MB this will write; put big files in the vault's \
                 files/ folder, which is served straight off disk",
                MAX_SITE_WRITE / (1024 * 1024)
            ),
        )
            .into_response();
    }

    let dir = &state.site_dir;
    if let Err(err) = std::fs::create_dir_all(dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not create {}: {err}", dir.display()),
        )
            .into_response();
    }

    let path = dir.join(name);
    if is_symlink(&path) {
        return (
            StatusCode::FORBIDDEN,
            format!("{name} is a link to somewhere else; refusing to write through it"),
        )
            .into_response();
    }

    match std::fs::write(&path, body) {
        Ok(()) => (StatusCode::OK, message.to_string()).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not save {name}: {err}"),
        )
            .into_response(),
    }
}

async fn delete_site_file(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(name) = safe_site_name(&name) else {
        return (StatusCode::BAD_REQUEST, "that filename cannot be used").into_response();
    };

    let path = state.site_dir.join(&name);
    // Removing a link removes the link and not its target, so this one is safe
    // either way -- but a directory is not this endpoint's to delete.
    match path.symlink_metadata() {
        Ok(meta) if meta.file_type().is_dir() => {
            (StatusCode::BAD_REQUEST, "that is a folder").into_response()
        }
        Ok(_) => match std::fs::remove_file(&path) {
            Ok(()) => (StatusCode::OK, format!("Removed {name}.")).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not remove {name}: {err}"),
            )
                .into_response(),
        },
        Err(_) => (StatusCode::NOT_FOUND, "there is no such file").into_response(),
    }
}

#[derive(Serialize)]
struct SharedFile {
    path: String,
    size: u64,
}

/// What this node is sharing, so a peer can list it before downloading.
async fn shared_files(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(walk_files(&state.vault.files_dir()))
}

/// Ceiling on stored incoming mail. Well beyond ordinary use, and far below
/// what would fill the card a field node runs from.
const MAX_INBOX_BYTES: u64 = 64 * 1024 * 1024;

/// Cap on how much of a shared tree we will enumerate in one listing.
const MAX_LISTED_FILES: usize = 1000;

fn walk_files(root: &std::path::Path) -> Vec<SharedFile> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_LISTED_FILES {
                return out;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            // Follow no symlinks: a link out of the shared folder would publish
            // whatever it points at.
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file()
                && let Ok(relative) = path.strip_prefix(root)
            {
                out.push(SharedFile {
                    path: relative.to_string_lossy().replace('\\', "/"),
                    size: meta.len(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Refuse writes driven by another website.
///
/// A page on any origin can POST to `http://localhost:8420`, and before this
/// existed such a request queued mail signed with the operator's key. Browsers
/// always attach `Origin` to a cross-site write; peers and the command line
/// send none and cannot be steered by a web page.
async fn refuse_cross_site_writes(request: Request, next: Next) -> axum::response::Response {
    let is_read = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if !is_read {
        let header_str = |name: header::HeaderName| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let origin = header_str(header::ORIGIN);
        let host = header_str(header::HOST);

        if !crate::guard::write_is_allowed(origin.as_deref(), host.as_deref()) {
            tracing::warn!(?origin, "refused a cross-site write");
            return (
                StatusCode::FORBIDDEN,
                "refused: this request came from another website",
            )
                .into_response();
        }
    }
    next.run(request).await
}

/// Refuse a file request that would resolve outside the folder being published.
///
/// `ServeDir` blocks `..` but follows symlinks, so a link in `files/` served
/// whatever it pointed at -- `/etc/passwd` included, which is how this was found.
async fn refuse_escaping_paths(
    State(root): State<PathBuf>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    if !crate::guard::resolves_within(&root, request.uri().path()) {
        tracing::warn!(path = %request.uri().path(), "refused a path leaving the shared folder");
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    next.run(request).await
}

/// Wrap a directory service so nothing under it can point out of it.
///
/// Layered onto `ServeDir` rather than nested in a `Router`, because `nest`
/// and `nest_service` disagree about a trailing slash and `nest_service` is
/// the one that serves `/~name/` as the directory index.
fn guarded_dir(
    root: PathBuf,
) -> impl Clone
+ Send
+ Sync
+ 'static
+ tower::Service<
    Request,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
    Future = impl Send,
> {
    tower::ServiceBuilder::new()
        .layer(middleware::from_fn_with_state(
            root.clone(),
            refuse_escaping_paths,
        ))
        .service(ServeDir::new(&root))
}

// ---- profile --------------------------------------------------------------

/// A key's picture, so people compare a shape rather than skim hex.
async fn identicon(Path(peer_hex): Path<String>) -> impl IntoResponse {
    let trimmed = peer_hex.strip_suffix(".svg").unwrap_or(&peer_hex);
    let Some(peer_id) = PeerId::parse_hex(trimmed) else {
        return (StatusCode::BAD_REQUEST, "not a valid peer id").into_response();
    };
    (
        [
            ("content-type", "image/svg+xml"),
            // Deterministic and permanent, so it never needs refetching.
            ("cache-control", "public, max-age=31536000, immutable"),
        ],
        intraweb_core::identicon::svg(peer_id, 128),
    )
        .into_response()
}

#[derive(Serialize, serde::Deserialize, Default)]
struct Profile {
    nickname: String,
    tagline: String,
}

/// Read the profile from disk rather than the copy loaded at startup, so an
/// edit shows up without a restart.
fn profile_on_disk(state: &AppState) -> Profile {
    match Config::load_or_create(&state.vault.config_path()) {
        Ok(config) => Profile {
            nickname: config.sanitized_nickname(),
            tagline: config.tagline,
        },
        Err(_) => Profile::default(),
    }
}

async fn get_profile(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(profile_on_disk(&state))
}

/// Save an edited profile.
///
/// The tagline takes effect at once because it is read from disk. The
/// nickname only changes what neighbors see once the node restarts, since the
/// announcement is signed and published when discovery starts -- the response
/// says so rather than letting it look as though nothing happened.
async fn put_profile(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let Ok(edit) = serde_json::from_str::<Profile>(&body) else {
        return (StatusCode::BAD_REQUEST, "could not read that form").into_response();
    };

    let path = state.vault.config_path();
    let Ok(mut config) = Config::load_or_create(&path) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not read the config",
        )
            .into_response();
    };

    let renamed = !edit.nickname.trim().is_empty() && edit.nickname != config.sanitized_nickname();
    if !edit.nickname.trim().is_empty() {
        config.nickname = edit.nickname;
    }
    config.tagline = edit.tagline;

    if let Err(err) = config.save(&path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")).into_response();
    }

    if !renamed {
        return (StatusCode::OK, "Saved.").into_response();
    }

    // Announce the new name now. The config is already written, so a failure
    // here means the name is saved but not yet announced -- worth saying,
    // because a restart would then fix it.
    match state
        .node
        .as_ref()
        .map(|node| node.rename(&config.sanitized_nickname()))
    {
        Some(Ok(())) => {
            (StatusCode::OK, "Saved, and your neighbors have been told.").into_response()
        }
        Some(Err(err)) => (
            StatusCode::OK,
            format!("Saved, but the new name could not be announced ({err:#}). Restart to fix."),
        )
            .into_response(),
        None => (StatusCode::OK, "Saved.").into_response(),
    }
}

/// The picture this node's owner chose, if they chose one.
///
/// 404 when they have not: the dashboard falls back to the identicon, which
/// is drawn from the key and therefore always exists.
async fn avatar(State(state): State<AppState>) -> impl IntoResponse {
    let Some(path) = state.vault.avatar_path() else {
        return (StatusCode::NOT_FOUND, "no avatar set").into_response();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return (StatusCode::NOT_FOUND, "no avatar set").into_response();
    };

    let kind = mime_guess::from_path(&path)
        .first_or_octet_stream()
        .to_string();
    (
        [
            ("content-type", kind),
            // A neighbor may change their picture, so do not hold it long.
            ("cache-control", "public, max-age=300".to_string()),
        ],
        bytes,
    )
        .into_response()
}

// ---- guestbook ------------------------------------------------------------

/// What neighbors have written in our book.
async fn read_guestbook(State(state): State<AppState>) -> impl IntoResponse {
    let book = ChannelId::guestbook_of(state.identity.peer_id());
    let entries = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.posts(book, 100).ok())
        .unwrap_or_default();
    axum::Json(entries)
}

/// Write in a neighbor's book.
async fn sign_guestbook(
    State(state): State<AppState>,
    Path(peer_hex): Path<String>,
    body: String,
) -> impl IntoResponse {
    let Some(peer_id) = PeerId::parse_hex(&peer_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid peer id").into_response();
    };
    let Ok(said) = serde_json::from_str::<SayBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "could not read that").into_response();
    };
    if said.body.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "write something first").into_response();
    }
    let Some(owner) = state
        .roster
        .peers()
        .into_iter()
        .find(|p| p.peer_id == peer_id)
    else {
        return (StatusCode::BAD_REQUEST, "that neighbor is not in range").into_response();
    };

    match crate::channels::sign_guestbook(&state.store, &state.identity, &owner, &said.body).await {
        Ok(()) => (
            StatusCode::OK,
            format!("signed {}'s guestbook", owner.nickname),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// Throw one of our own messages away.
async fn delete_mail(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the mail store is busy").into_response();
    };
    match store.delete_mail(id) {
        Ok(true) => (StatusCode::OK, "deleted").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such message").into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

// ---- channels -------------------------------------------------------------

/// Take a post from another node.
///
/// Verified first, then through the same gates as mail: a blocked key gets
/// nowhere and a flood is throttled. A post for a private channel we hold no
/// key for is stored as ciphertext and marked unreadable, so it is kept
/// honestly rather than displayed as something we cannot actually read.
async fn receive_post(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let sealed: SignedPost = match serde_json::from_str(&body) {
        Ok(post) => post,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, format!("unreadable post: {err}")).into_response();
        }
    };

    if sealed.accept().is_err() {
        return (
            StatusCode::FORBIDDEN,
            "that post is not signed by who it claims",
        )
            .into_response();
    }

    let author = sealed.post.from;
    if state.roster.is_blocked(author) {
        return (StatusCode::FORBIDDEN, "refused").into_response();
    }
    if !state.limiter.allow(author, crate::limits::now_float()) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }

    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the store is busy").into_response();
    };

    let channel = sealed.post.channel;
    let known = store.channels().unwrap_or_default();

    // A private channel we were never invited to is somebody else's business;
    // do not accumulate their traffic.
    // Our own guestbook is always open: that is the point of having one.
    let is_ours = channel.is_neighborhood()
        || channel.is_guestbook_of(state.identity.peer_id())
        || known.iter().any(|c| c.channel_id == channel);
    if !is_ours {
        return (StatusCode::NOT_FOUND, "no such channel here").into_response();
    }

    let (body_to_store, readable) = match store.channel_key(channel) {
        Ok(Some(key)) => match sealed.post.open(&key) {
            Ok(plain) => (plain, true),
            Err(_) => (sealed.post.body.clone(), false),
        },
        _ if sealed.post.encrypted => (sealed.post.body.clone(), false),
        _ => (sealed.post.body.clone(), true),
    };

    match store.store_post(&sealed, &body_to_store, readable) {
        Ok(filed) => {
            if filed {
                tracing::info!(
                    from = %author.fingerprint(),
                    channel = %channel.short(),
                    "post received",
                );
            }
            (StatusCode::OK, "filed").into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Take an invitation to a private channel.
async fn receive_invite(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let invite: Invite = match serde_json::from_str(&body) {
        Ok(invite) => invite,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unreadable invitation: {err}"),
            )
                .into_response();
        }
    };

    if state.roster.is_blocked(invite.from) {
        return (StatusCode::FORBIDDEN, "refused").into_response();
    }

    // Opening what they sealed needs the encryption key they announce.
    let Some(inviter) = state
        .roster
        .peers()
        .into_iter()
        .find(|p| p.peer_id == invite.from)
    else {
        return (StatusCode::BAD_REQUEST, "we cannot see whoever sent that").into_response();
    };
    let Some(inviter_key) = inviter.encryption_key else {
        return (
            StatusCode::BAD_REQUEST,
            "that peer announces no encryption key",
        )
            .into_response();
    };

    let sealing = SealingKey::derive(&state.identity);
    let channel_key = match invite.accept(state.identity.peer_id(), &sealing, &inviter_key) {
        Ok(key) => key,
        Err(err) => {
            tracing::debug!(%err, "refused an invitation");
            return (StatusCode::FORBIDDEN, format!("refused: {err}")).into_response();
        }
    };

    let Ok(store) = state.store.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "the store is busy").into_response();
    };
    let now = now_secs();
    if let Err(err) = store
        .upsert_channel(invite.channel, &invite.name, true, Some(&channel_key), now)
        .and_then(|()| store.add_member(invite.channel, state.identity.peer_id(), now))
        .and_then(|()| store.add_member(invite.channel, invite.from, now))
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    tracing::info!(channel = %invite.name, from = %invite.from.fingerprint(), "invited to a channel");
    (StatusCode::OK, "joined").into_response()
}

/// Most posts we will hand over in one catch-up.
const MAX_BACKFILL: u32 = 200;

/// Hand a peer the history it missed while it was switched off.
///
/// Posts are served exactly as they arrived. A private channel's posts are
/// ciphertext, so serving them to somebody who is not a member gives nothing
/// away -- the encryption is the access control, and the 256-bit channel id
/// they had to know to ask is itself something only members are told.
async fn backfill(
    State(state): State<AppState>,
    Path(channel_hex): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(channel) = ChannelId::parse_hex(&channel_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid channel id").into_response();
    };
    let since: u64 = params
        .get("since")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let envelopes = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.envelopes_since(channel, since, MAX_BACKFILL).ok())
        .unwrap_or_default();

    // Already JSON, so pass it through rather than decoding and re-encoding.
    (
        [("content-type", "application/json")],
        format!("[{}]", envelopes.join(",")),
    )
        .into_response()
}

async fn list_channels(State(state): State<AppState>) -> impl IntoResponse {
    let channels = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.channels().ok())
        .unwrap_or_default();
    axum::Json(channels)
}

async fn channel_posts(
    State(state): State<AppState>,
    Path(channel_hex): Path<String>,
) -> impl IntoResponse {
    let Some(channel) = ChannelId::parse_hex(&channel_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid channel id").into_response();
    };
    let posts = state
        .store
        .lock()
        .ok()
        .and_then(|store| store.posts(channel, 200).ok())
        .unwrap_or_default();
    axum::Json(posts).into_response()
}

#[derive(serde::Deserialize)]
struct SayBody {
    body: String,
}

async fn say_in_channel(
    State(state): State<AppState>,
    Path(channel_hex): Path<String>,
    body: String,
) -> impl IntoResponse {
    let Some(channel) = ChannelId::parse_hex(&channel_hex) else {
        return (StatusCode::BAD_REQUEST, "not a valid channel id").into_response();
    };
    let Ok(said) = serde_json::from_str::<SayBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "could not read that").into_response();
    };
    if said.body.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "nothing to say").into_response();
    }

    match crate::channels::say(
        &state.store,
        &state.identity,
        &state.roster,
        channel,
        &said.body,
    )
    .await
    {
        Ok(delivery) => (
            StatusCode::OK,
            format!("said to {} neighbor(s)", delivery.reached),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct NewChannel {
    name: String,
}

async fn new_channel(State(state): State<AppState>, body: String) -> impl IntoResponse {
    let Ok(request) = serde_json::from_str::<NewChannel>(&body) else {
        return (StatusCode::BAD_REQUEST, "could not read that").into_response();
    };
    match crate::channels::create_private(&state.store, &state.identity, &request.name) {
        Ok(channel) => (StatusCode::OK, channel.to_hex()).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")).into_response(),
    }
}

async fn invite_to_channel(
    State(state): State<AppState>,
    Path((channel_hex, peer_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let (Some(channel), Some(peer_id)) = (
        ChannelId::parse_hex(&channel_hex),
        PeerId::parse_hex(&peer_hex),
    ) else {
        return (StatusCode::BAD_REQUEST, "not a valid channel or peer").into_response();
    };
    let Some(peer) = state
        .roster
        .peers()
        .into_iter()
        .find(|p| p.peer_id == peer_id)
    else {
        return (StatusCode::BAD_REQUEST, "that neighbor is not in range").into_response();
    };

    let sealing = SealingKey::derive(&state.identity);
    match crate::channels::invite(&state.store, &state.identity, &sealing, channel, &peer).await {
        Ok(()) => (StatusCode::OK, format!("invited {}", peer.nickname)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

pub fn router(state: AppState) -> Router {
    let nickname = state.config.sanitized_nickname();

    // Your own site and files, served straight off disk. Normally the vault's
    // own folder -- the one that follows you to every hub.
    let site = guarded_dir(state.site_dir.clone());
    let files = guarded_dir(state.vault.files_dir());

    Router::new()
        .route("/", get(|| async { Html(DASHBOARD_HTML) }))
        .route(
            "/style.css",
            get(|| async { ([("content-type", "text/css; charset=utf-8")], DASHBOARD_CSS) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    DASHBOARD_JS,
                )
            }),
        )
        .route("/api/status", get(status))
        .route("/api/peers", get(peers))
        .route("/api/hubs", get(hubs))
        .route("/api/hubs/history", get(hub_history))
        .route("/api/doctor", get(doctor))
        .route("/api/profile", get(get_profile).post(put_profile))
        .route("/identicon/{peer}", get(identicon))
        .route("/avatar", get(avatar))
        .route("/api/state", get(combined_state))
        .route("/api/mail", get(inbox).post(receive_mail))
        .route("/api/mail/send", post(send_mail))
        .route("/api/mail/outbox", get(outbox))
        .route("/api/mail/read", post(mark_all_read))
        .route("/api/mail/{id}/delete", post(delete_mail))
        .route("/api/guestbook", get(read_guestbook))
        .route("/api/guestbook/{peer}", post(sign_guestbook))
        .route("/api/files", get(shared_files))
        .route("/api/site", get(get_site).post(put_site))
        .route(
            "/api/site/file/{name}",
            post(put_site_file).delete(delete_site_file),
        )
        // Axum's own cap is the backstop and says only that a limit was hit.
        // Leaving room above our limit means an ordinary overshoot -- someone
        // dragging in a photo straight off a camera -- reaches the handler and
        // gets told where big files actually belong.
        .layer(axum::extract::DefaultBodyLimit::max(4 * MAX_SITE_WRITE))
        .route("/api/channels", get(list_channels))
        .route("/api/channels/new", post(new_channel))
        .route("/api/channels/post", post(receive_post))
        .route("/api/channels/invite", post(receive_invite))
        .route("/api/channels/{channel}/posts", get(channel_posts))
        .route("/api/channels/{channel}/backfill", get(backfill))
        .route("/api/channels/{channel}/say", post(say_in_channel))
        .route(
            "/api/channels/{channel}/invite/{peer}",
            post(invite_to_channel),
        )
        .route("/api/peers/{peer_id}/verify", post(verify_peer))
        .route("/api/peers/{peer_id}/block", post(block_peer))
        .route("/api/peers/{peer_id}/unblock", post(unblock_peer))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
        .nest_service(&format!("/~{nickname}"), site)
        .nest_service("/files", files)
        .layer(middleware::from_fn(refuse_cross_site_writes))
}

/// Whether to try the clean, port-free URL.
///
/// A hub prefers port 80 so a newcomer can type a bare hostname. But a port the
/// operator actually chose always wins: silently ignoring `--port` sends someone
/// chasing a dead URL, which is far worse than a long one.
pub fn should_try_low_port(is_hub: bool, port_was_chosen: bool) -> bool {
    is_hub && !port_was_chosen
}

/// Bind the dashboard, preferring port 80 so URLs stay free of a port number.
///
/// Falling back rather than failing is deliberate: binding low ports needs
/// privilege, and an operator who ran the binary as themselves should still get
/// a working node, just at a longer URL.
pub async fn bind(preferred_low_port: bool, port: u16) -> Result<(tokio::net::TcpListener, u16)> {
    if preferred_low_port {
        if let Ok(listener) =
            tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 80))).await
        {
            return Ok((listener, 80));
        }
        // Point at something that actually exists today rather than a
        // subcommand we have not built yet.
        tracing::warn!(
            "could not bind port 80, serving on {port} instead; to get the \
             shorter URL, grant the capability once with: \
             sudo setcap 'cap_net_bind_service=+ep' $(command -v intraweb)"
        );
    }
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .with_context(|| format!("could not bind port {port}"))?;
    Ok((listener, port))
}

#[cfg(test)]
mod tests {
    use super::{safe_site_name, should_try_low_port};

    #[test]
    fn a_plain_hub_takes_the_clean_url() {
        assert!(should_try_low_port(true, false));
    }

    #[test]
    fn an_explicit_port_is_never_overridden() {
        // Regression: --port used to be swallowed by the port-80 preference,
        // leaving the operator curling a port nothing was listening on.
        assert!(!should_try_low_port(true, true));
    }

    #[test]
    fn ordinary_peers_never_reach_for_port_80() {
        assert!(!should_try_low_port(false, false));
        assert!(!should_try_low_port(false, true));
    }

    #[test]
    fn an_ordinary_filename_is_accepted() {
        assert_eq!(safe_site_name("me.jpg").as_deref(), Some("me.jpg"));
        assert_eq!(
            safe_site_name("holiday%20snap.png").as_deref(),
            Some("holiday snap.png"),
            "a space arrives encoded and is not suspicious"
        );
    }

    #[test]
    fn a_name_that_points_out_of_the_published_folder_is_refused() {
        for hostile in [
            "../identity.key",
            "..%2Fidentity.key",
            "%2e%2e%2fidentity.key",
            "sub/dir.png",
            "/etc/passwd",
            "..",
            "",
        ] {
            assert_eq!(
                safe_site_name(hostile),
                None,
                "{hostile} must not name a file to write"
            );
        }
    }

    /// A dotfile is how the interesting things in a vault are named, and a
    /// published folder is not the place to be writing them from a browser.
    #[test]
    fn a_hidden_name_is_refused() {
        assert_eq!(safe_site_name(".ssh"), None);
        assert_eq!(safe_site_name(".%2e%2fidentity.key"), None);
    }

    #[test]
    fn an_absurdly_long_name_is_refused() {
        assert_eq!(safe_site_name(&"a".repeat(97)), None);
        assert!(safe_site_name(&"a".repeat(96)).is_some());
    }
}
