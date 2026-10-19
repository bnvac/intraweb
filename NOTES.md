# NOTES.md — intraweb

Running log of decisions, open questions, and known gaps. Append; do not rewrite.

## Roadmap

| Phase | Scope | State |
| --- | --- | --- |
| P0 | Discovery, identity, roster, both dashboards, doctor | **done** |
| P1 | Local mail, store-and-forward, signed | **done** |
| P2 | Mini-site publishing | partly — `serve` from the CLI; no upload UI |
| P3 | Resumable direct file transfer | **done** — ranged HTTP, `ls` / `get` |
| P4 | Mail attachments | **done** — sender-held references |
| — | Release CI, cross-compiled musl + macOS binaries | **done** |

Schema is at v2: v1 created the keyring and the mail table, v2 added unread
tracking and the inbound-duplicate guard. Migrations are additive and a vault
from the first release opens without the operator doing anything.

<!-- MEMORY_UPDATE_START -->
### Update: 2026-09-11
* **Decisions/Changes**: Pre-build architecture settled and P0 built. Rust
  workspace (`core` / `net` / `cli`), edition 2024. Identity is Ed25519 with
  trust-on-first-use; seeded from `getrandom` into `SigningKey::from_bytes`
  rather than taking an RNG parameter, so the crate is not coupled to whichever
  `rand_core` major `ed25519-dalek` currently tracks (3.0 wants 0.10).
  Federation model revised mid-session per Ben: hubs own nothing, a node joins
  many hubs at once and serves one portable vault to all of them — Mastodon's
  shape without the data gravity. This killed the earlier `ben@basecamp`
  node-scoped addressing; identity is the pubkey, nickname is decoration.
  Presence is signed and travels two ways (mDNS TXT + UDP broadcast beacon),
  with a hand-built canonical encoding because a signature is only worth
  something if both sides agree byte-for-byte. Dashboard is web + ratatui, both
  reading one shared `Roster` object rather than the TUI doing HTTP to itself.
  `doctor` ships in P0 as argued: it separates "nobody here" from "your AP is
  isolating clients", which otherwise look identical.
* **Known Bugs/Gaps**: Two real bugs found by end-to-end testing, both fixed
  with named regression tests: (1) a node recorded its own echoed beacon in its
  own keyring, because self-echo was dropped at the registry rather than before
  the database write; (2) `--port` was silently swallowed by the hub's port-80
  preference, leaving the operator curling a dead port. Still open: TUI is
  local-only (a remote TUI would need an HTTP client, deferred rather than pull
  in `reqwest` against the lean-binary goal); no release CI or cross-compile
  matrix yet, so `install.sh` points at releases that do not exist until that
  lands; transport port 8421 is announced but nothing listens on it until P1;
  beacon replay is bounded only by a 300s clock-skew window, which is
  proportionate for LAN presence but is not a nonce.
<!-- MEMORY_UPDATE_END -->

<!-- MEMORY_UPDATE_START -->
### Update: 2026-10-17 (security, channels, profiles)
* **Decisions/Changes**: Two vulnerabilities found by attacking a running node
  rather than reading code, both fixed with named regression tests: a symlink
  in `files/` served `/etc/passwd` (ServeDir blocks `..` but follows links),
  and any website could POST to localhost and queue mail signed with the
  operator's key. Requests are now canonicalised before serving, and
  cross-origin writes are refused by Origin check.
  On impersonation: a fingerprint is public and cannot be used to sign as you,
  so the real attack is grinding a key whose fingerprint *opens* like a known
  one. New keys are checked against the keyring for a shared prefix and a near
  miss is flagged; blocking is durable and refuses mail, posts and invitations.
  Rate limiting spends from a **global** bucket as well as a per-sender one,
  because identities are free to mint.
  Channels added. A private channel is encrypted under a channel key, not
  merely delivered to members, since posts cross an open network. The
  encryption key is a **separate** X25519 key derived from the vault seed by
  HKDF — the Ed25519 library explicitly warns against reusing a signing key
  for key agreement. Presence announces it (protocol v3).
  A guestbook turned out to need no new machinery: it is a public channel whose
  id derives from the owner's key, reusing signed posts, dedupe, rate limiting
  and blocking.
  Every key now has an identicon, because people compare pictures far more
  reliably than hex. Avatars override it; the identicon is the always-present
  fallback. Profiles are served over HTTP per node rather than announced,
  because presence rides in a 1024-byte datagram.
  Attachments are references: the file stays with the sender and the fetch is
  the existing ranged download, so it resumes.
* **Known Bugs/Gaps**: Bugs found and fixed this pass — delivery narrowed to
  members broke guestbooks (narrowing is for private channels only); an
  explicit CSS `display` beat the `hidden` attribute so the profile editor was
  never hidden; `can_read` asked "holds a key" and so labelled the public
  channel unreadable; the guestbook appeared both as a channel tab and its own
  panel. Still open: no upload UI for sites; `surf` re-probes without caching;
  beacon replay is bounded by a 300s clock-skew window rather than a nonce;
  channel history does not backfill, so a node that was off misses what was
  said; a renamed nickname is only announced after a restart.
* **Process**: An hour of uncommitted channel work was lost to a container
  rebuild. Commit each working piece.
<!-- MEMORY_UPDATE_END -->

<!-- MEMORY_UPDATE_START -->
### Update: 2026-09-11 (P1 + P3 + efficiency)
* **Decisions/Changes**: The open questions are now decided. **Mail and files
  ride the node's own HTTP port** rather than a bespoke socket protocol, so
  `transport_port` is gone and the wire format is protocol v2. This was the
  session's biggest call: `ServeDir` already answers Range requests, so
  resumable transfer existed for free and a whole framed protocol was deleted
  before being written. Verified against a 30 MB file truncated mid-transfer —
  server returns 206, the resumed file's SHA-256 matches the original.
  **Mail addressing is key-anchored**: a nickname resolves, a nickname held by
  two keys is refused with both fingerprints, and a bare public key always
  works so you can write to someone from a key on paper. Mail to an offline
  peer queues and the sender's outbox loop delivers when they appear
  (verified live: queued to a never-seen key, carol came online, delivered).
  Three efficiency changes, each justified rather than speculative: keyring
  write-through throttled to 60s (was a SQLite UPDATE per peer per 2s beacon —
  pointless flash wear on an SD card), interface enumeration cached for 30s
  (was a full `getifaddrs` every announce, forever), and the dashboard's two
  polls merged into one `/api/state`. A running node now publishes its bound
  port in `runtime.json`, so local commands read its roster instead of
  re-discovering: `mail send` went from 3s to 0.019s. Release CI added
  (musl x86_64/aarch64 + both macOS arches), so `install.sh` finally points at
  artifacts that will exist.
* **Considered and rejected**: caching the roster snapshot. `last_seen` changes
  on every sighting, so the cache would invalidate almost as often as it was
  read — real complexity, near-zero gain.
* **Known Bugs/Gaps**: Four bugs found and fixed this pass. (1) Throttling
  write-through made a verified peer look unverified for up to a minute;
  `Roster::note_verified` now applies it instantly, which is better than the
  old behavior. (2) `mail send` marked delivery using "the newest pending row"
  instead of the id `queue` returned — wrong row if two were queued in the same
  second. (3) Mail could not be addressed to anyone out of range at all, which
  defeated the outbox entirely. (4) An expected error (unknown recipient) dumped
  an anyhow backtrace; `main` now prints the error chain and exits 1.
  Still open: no attachments on mail; no upload UI for sites; `surf` re-probes
  with no caching; mail has no delete or reply; the beacon's replay window is
  still a 300s clock-skew bound rather than a nonce; nothing rate-limits inbound
  mail beyond the 256 KiB body cap, so a hostile LAN peer could fill a disk.
<!-- MEMORY_UPDATE_END -->

<!-- MEMORY_UPDATE_START -->
### Update: 2026-09-11 (later)
* **Decisions/Changes**: Added `intraweb serve <dir>` and `intraweb surf`.
  `serve` publishes a folder in place at `/~nickname` — nothing is copied into
  the vault, so pointing at a directory never disturbs what you normally
  publish; it is `up` with a site override, so all the usual flags apply.
  `surf` probes each neighbor over plain HTTP/1.0 and shows the page's own
  `<title>`; no client crate, so the binary stays lean. Two boundaries were
  decided by CLAUDE.md rather than convenience: HTTP probing lives in
  `intraweb-cli` because `intraweb-net` must not know what a web page is, and
  the surf listing shows conflict warnings with fingerprints because rule 3
  requires name/key conflicts to be *shown*. Added `Node::observe` /
  `MdnsNode::observer` so surfing listens without announcing — verified in a
  live three-node run that the surfer never appeared in anyone's roster.
  TUI screenshots captured from the real binary via tmux `capture-pane`.
* **Known Bugs/Gaps**: Three more bugs found and fixed, each with a named
  regression test: (1) the TUI header was sized 4 rows while drawing 3 lines
  plus borders, silently clipping "N neighbor(s) online" — now an asserted
  invariant; (2) roster columns were unaligned because nickname width varied;
  (3) the doctor test asserted an empty network and failed the moment real
  nodes were running — rewritten to assert invariants instead. Still open: no
  way to open a peer's site from inside the TUI (surf covers it from the CLI);
  `surf` re-probes every run with no caching, fine on a LAN but wasteful on a
  large roster; `serve` does not watch the folder, so it serves whatever is on
  disk at request time (which is actually the desired behavior, but means no
  notification if the folder is deleted underneath it).
<!-- MEMORY_UPDATE_END -->

<!-- MEMORY_UPDATE_START -->
### Update: 2026-10-19 (mDNS presence, site editor)

* **Decisions/Changes**:
  * **mDNS presence is edge-triggered; the beacon's is a heartbeat.** The
    responder resolves a service *once* and then renews the record without
    notifying us again — it keeps a `resolved` set specifically to suppress
    repeats — so there was never a stream of mDNS sightings to time out
    against. The roster was applying the beacon's 30s timeout to a path with
    no heartbeat, which dropped every mDNS-only peer at every timeout. Beacons
    arriving every 2s had been masking it completely; it only shows up under
    `--no-beacon`, i.e. exactly the multicast-only networks mDNS exists for.
    `hold_mdns` / `release_mdns` now hold a peer present until mDNS withdraws
    them, and the sweep skips a held peer. (CLAUDE.md rules 23–25.)
  * **A withdrawal names a service, not a key.** `absorb()` returns whether it
    took the record, and a service name is filed against a key only once that
    signature has been checked — otherwise anyone could evict anyone by
    announcing someone else's id and then withdrawing it.
  * **Replay rejection is back to strictly-newer.** Equal timestamps had to be
    accepted while liveness depended on repeated sightings; on the mDNS path a
    record now grants a hold that no timeout expires, so accepting a replay
    would pin a departed peer to every roster on the link indefinitely. The
    hold carries liveness, so nothing needs the repeats.
  * **A periodic refresh must not unregister first.** Withdrawing before
    re-registering is right for a rename (the instance name embeds the
    nickname) but wrong for a refresh: it withdrew us from every roster until
    we were resolved again. The responder treats a repeat `register` as an
    update — its own docs say so.
  * **SIGTERM is an exit.** `unregister` and `shutdown` only queue a command for
    the responder's thread, so dropping the acknowledgements and exiting meant
    the goodbye never left. Both signals are handled and shutdown now waits for
    the packet. Graceful departure: ~31s → under 3s.
  * **Your page is written from the dashboard.** Four endpoints, no new
    dependency — a file posts as a raw body with its name in the path, so there
    is no multipart parser. One shared write path, so the size cap and symlink
    refusal cannot apply on one route and be forgotten on the next.
  * Verified against two real nodes and a real browser, not asserted: present
    at 7/42/77/117/137s under `--no-beacon` where it was empty at 40s before;
    traversal, symlink write-through and cross-origin POST all refused with the
    vault's `identity.key` as the target.

* **Known Bugs/Gaps**:
  * An ungracefully-killed mDNS-only peer lingers until its record expires
    (~2 min) rather than 30s. That is ordinary mDNS, and the beacon covers it
    on a normal network, but the roster is briefly wrong on a multicast-only
    one.
  * Nothing bounds a published folder filled by hand; only the dashboard's own
    writes are capped.
  * `v0.1.0` is still untagged, so `install.sh` points at artifacts that do not
    exist yet. Outward-facing — waiting on an explicit yes.
<!-- MEMORY_UPDATE_END -->

## Open questions for Ben

Answered in session (recorded so they are not re-litigated):

1. Topology — hub + peers, hub is a meeting point only.
2. Trust — Ed25519 + TOFU, no passwords, no CA.
3. Dashboard — both web and TUI, over one source of truth.
4. Targets — aarch64 + x86_64; Pi Zero / ARMv6 dropped.
5. Federation — many hubs per node, one shared vault. *(revised mid-build)*

Decided while building, no longer open:

6. **Resumable transfers** — yes, and they cost nothing: ranged HTTP.
7. **Release hosting** — GitHub Releases, wired up in `.github/workflows`.
8. **Service lifecycle** — not building it. The port-80 fallback prints a real
   `setcap` command, which is all it was ever going to do.
9. **Mail addressing** — by key. Nicknames resolve as a convenience; ambiguity
   is refused rather than guessed.
10. **Transport** — one HTTP port for everything. No second protocol.

Closed since:

11. **Attachments.** Built as a reference, never a copy: the bytes stay with the
    sender until fetched. The path is covered by the signature and checked for
    `..` before signing, so a message cannot be repointed at another file.
12. **Inbound limits.** Built, with a *global* bucket beside the per-sender one —
    identities are free to mint, so a per-sender limit alone is theatre.

Genuinely still open:

13. **Departure latency over multicast only.** A node that is unplugged rather
    than stopped lingers until its mDNS record expires, which is a couple of
    minutes. That is ordinary mDNS behavior and the beacon covers for it on a
    normal network, but on a multicast-only one the roster is briefly wrong.
14. **Nothing bounds a published folder.** The dashboard caps what it will
    write, but a vault whose `site/` is filled by hand can still fill the card
    a node boots from.
