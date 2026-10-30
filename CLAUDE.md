# CLAUDE.md — intraweb

Architecture rules and project context. Read this before changing anything;
it exists so sessions do not have to re-derive decisions from chat history.

## What this is

A zero-config local intranet. Slogan: **your neighborhood web**. One static
binary, no internet, no central server.

## The load-bearing idea

**A person is a keypair and a folder. A hub is a place to meet.**

Every design question resolves against that sentence. In particular:

- A hub **never** stores, proxies, or relays another node's content. The roster
  hands out addresses; the browser goes straight to the peer. If a change would
  make the hub a relay, the change is wrong.
- A node can be on **many hubs at once**, serving the same vault to all of them.
  Anything that assumes a single "home" hub is wrong.
- The vault is portable. Copy it to another machine and you are the same person,
  on every hub, with no migration step.

## Crate layout

| Crate | Owns | Must not |
| --- | --- | --- |
| `intraweb-core` | Identity, vault, config, SQLite keyring, peer types | Know anything about networks |
| `intraweb-net` | mDNS, UDP beacon, roster, diagnostics, orchestration | Know anything about HTTP or the UI |
| `intraweb-cli` | CLI, JSON API, web dashboard, terminal UI, all HTTP | Hold state the roster should own |

The split is what lets discovery be tested without touching identity, and the
roster be rendered twice without duplicating logic.

## One port, one protocol

Everything a node says to another node goes over that node's own HTTP port:
pages, mail, and file downloads. There is no second socket protocol, and
`transport_port` was removed from the wire format in protocol v2.

This is still direct point-to-point TCP — one socket dialled straight at the
peer, no relay — and it buys ranged, resumable downloads for nothing, because
`ServeDir` already implements them. Do not reintroduce a bespoke transport; if
something needs a new verb, it is an HTTP route.

## Keys

Two keys per vault, and they are not interchangeable:

- **Ed25519**, in `identity.key`: who you are. Signs everything.
- **X25519**, derived from the same seed by HKDF with a domain label: how a
  secret is sealed to you. Announced in presence so a channel key can be
  sealed without a separate exchange.

Never sign with the encryption key or encrypt with the signing key. The
Ed25519 library says plainly not to reuse a signing key for key agreement and
points at the research; deriving keeps one file to back up while keeping the
key material independent.

## Rules that are easy to get wrong

1. **Verify before you record.** Anything arriving from the network is hostile
   until its signature checks out. `absorb()` in `net/node.rs` is the only path
   from wire to keyring; keep it that way.
2. **Drop self-echo before the database, not after.** Our own broadcast returns
   to us and verifies correctly, because it really is our signature. It must be
   discarded at the top of `absorb()`. (This was a real bug; there is a
   regression test.)
3. **Nicknames are labels, keys are identity.** Never enforce nickname
   uniqueness — there is no registry and there cannot be one. Detect and *show*
   name/key conflicts instead. `TrustState::NicknameConflict` must never be
   silently downgraded once raised.
4. **Signed fields are scrubbed before signing.** `presence::scrub` strips the
   `|` separator so a hostile nickname cannot smuggle extra fields into the
   canonical encoding. Never sign unscrubbed user input.
5. **An explicit choice always wins.** A hub prefers port 80 for a clean URL,
   but a chosen port is honored. Silently relocating the dashboard sends people
   chasing a dead address. (Also a real bug, also a regression test.)
6. **Both discovery paths, always.** mDNS alone fails on networks that filter
   multicast; broadcast alone gives up `.local` names. Neither is optional.
7. **Never hold the store lock across the roster lock**, or across an `.await`.
   `absorb()` scopes them deliberately.
8. **Looking is not joining.** `surf` and anything else that only inspects the
   network uses `Node::observe`, which listens without announcing. Browsing
   what neighbors publish must not change what they see, and a second
   announcement under the same key would collide with a node already running on
   the machine.
9. **Any listing of people shows trust.** `surf` prints the conflict warning and
   fingerprint next to a name whose key has changed. Surfing is exactly where
   impersonation would pay off, so no surface may render a bare nickname as if
   it were an identity.
10. **A rendered block must fit what it draws.** The TUI header was sized four
    rows while drawing three lines plus borders, silently clipping the roster
    counts. `HEADER_LINES`/`HEADER_HEIGHT` encode the relationship and a test
    asserts it.
11. **Addressing is by key; names are a convenience.** `mail::resolve` accepts
    a nickname, a fingerprint prefix, or a full key, but a nickname held by two
    keys is returned as `Ambiguous` and the caller must make a person choose.
    Never break the tie automatically.
12. **Mail to someone out of range must still queue.** That is what an outbox
    is for. Addressing consults the keyring and accepts a bare public key, so a
    key handed over on paper is enough to write to somebody.
13. **Do not write to SQLite on every sighting.** Beacons arrive every couple of
    seconds; the roster holds the live `last_seen` and the durable copy only
    needs to be roughly right. `PeerRegistry::cached_trust` decides, and always
    returns `None` for an unknown key or a changed nickname, because that is
    where impersonation surfaces.
14. **A local trust decision applies immediately.** Throttled write-through
    means the next sighting would otherwise restore the stale value, so
    verifying calls `Roster::note_verified` as well as the store.
15. **A private channel is encrypted, not merely addressed carefully.** Posts
    cross the same open network as everything else, where anyone with the wifi
    password is listening. Delivering only to members would be a promise the
    wire does not keep.
16. **Narrowing delivery to members is for private channels only.** It is a
    privacy mechanism, not a routing one. Applying it to public channels broke
    guestbooks, because a signer holds no member list for somebody else's book.
    (Real bug, named regression test.)
17. **A guestbook is a public channel derived from its owner's key.** It needs
    no new envelope, storage or rate limiting; reuse the channel machinery.
    `ChannelId::guestbook_of` is how anyone works out where to sign.
18. **An attachment is a reference, never a copy.** The bytes stay with the
    sender until fetched. Its path is covered by the signature and checked for
    `..` before signing, so a message cannot be repointed at another file or
    name something outside the shared folder.
19. **Cross-site writes are refused.** Any page the operator visits can POST to
    localhost; before this existed such a request queued mail signed with their
    key. Browsers attach `Origin` to a cross-site write, and a mismatch is a
    403. Peers and the CLI send none and are unaffected. (Demonstrated hole.)
20. **File requests are canonicalised before they are served.** `ServeDir`
    blocks `..` but follows symlinks, so a link in `files/` served
    `/etc/passwd`. Anything resolving outside the published folder is a 404.
    (Demonstrated hole.)
21. **A rate limit needs a global bucket.** Identities are free to mint, so a
    per-sender limit alone is theatre: a flooder uses a fresh key each time.
    The map of remembered senders is capped for the same reason.
22. **Tests never assume an empty network.** The machine running them may have
    real nodes on it. Assert invariants (a warning always carries a remedy; the
    verdict follows from the counts), not specific peer counts.
23. **mDNS presence is edge-triggered; the beacon's is a heartbeat.** A service
    resolves *once* and the responder then renews the record behind your back
    without notifying you again, so there is no stream of mDNS sightings to
    time out against. `hold_mdns` holds the peer present until the record is
    withdrawn, and `release_mdns` is the only thing that ends it. Applying the
    beacon's timeout to an mDNS peer dropped them after thirty seconds, which
    is exactly the multicast-only network mDNS is there to serve. (Real bug,
    named regression test.)
24. **A withdrawal names a service, not a key.** mDNS has no idea whose key was
    behind a record it drops, so a service name may only evict somebody filed
    under it *after* their signature was checked. `absorb` returns whether it
    took the record, and nothing is held on a record it refused -- otherwise
    anyone could evict anyone by announcing someone else's id and withdrawing
    it.
25. **Say goodbye before exiting, and wait for it to leave.** `unregister` and
    `shutdown` only queue a command for the responder's own thread; dropping
    the acknowledgements and exiting meant the goodbye never went out and
    neighbors kept the node until its record expired. SIGTERM counts as an
    exit: a node run by a service manager is stopped with it, not Ctrl-C.

26. **A private channel carries no attachments.** The shared folder is public;
    anyone in range can list and fetch from it. A file offered inside a
    private conversation would be readable by everyone all the same, and
    encrypting the path would only hide that. `Post::check_limits` refuses it,
    so a hostile node cannot send one either.
27. **A picture is judged by its bytes, and SVG is never one.** The avatar is
    served from the dashboard's own origin, where a script can do anything the
    operator can. Magic bytes decide the type; the name and declared type are
    the sender's to lie about.
28. **Traffic numbers are local.** A node reports what it measured, never a
    "network speed": that would mean broadcasting numbers to everyone, which
    is replication, and throughput belongs to a pair of machines anyway.
    Latency and throughput stay separate, throughput only from transfers over
    32KB, and only outbound -- a served file is timed only to its headers.
29. **Hidden hides that you are here, not who you are.** Anything sent while
    hidden is still signed. Starting hidden registers nothing; registering and
    withdrawing would flash you onto every roster.

30. **A net is its log.** Every act in a net is a signed post in its
    governance channel, and `net::fold` derives the state. Nothing about a net
    is stored except those posts, so no node can hold a version the log does
    not support. The fold must stay deterministic: same posts, same leader.
31. **Order a log causally, not just by clock.** The founding charter folds
    first; within one second a join precedes a motion precedes a vote; a vote
    for a motion not yet reached is held until it opens. Clocks differ between
    machines, and ordering by time alone lost joins and votes. (Real bug, two
    named regression tests.)
32. **A vote names its voters when it opens.** Nets are open and keys are
    free, so eligibility is fixed in the motion and only current members can
    be named. Keys minted after a vote opens count for nothing; keys minted
    in advance still do, and the dashboard says so. Do not claim more.
33. **A net id proves its founder.** It is derived from the founder's key and
    a nonce, so a copied charter founds nothing.
34. **A library is a link, not a relay.** `intraweb library` lists a media
    service the node already runs; neighbors get a button that opens it on
    that node's own address. The URL is built from the address we reach the
    peer on, never taken from the list they send, and every entry goes
    through `Library::checked`, because the list comes from a stranger.
    Detecting, adding and removing answer only to loopback: the API port is
    the one neighbors reach, and a remote "what runs here" is a port scan.
    Detection needs the service's own name in its answer, never just an
    open port.

## Conventions

- Comments explain *why*, especially where a line encodes a security decision
  or a network-reality workaround. Do not narrate what the code plainly says.
- Test names are sentences describing the behavior being protected
  (`a_new_key_wearing_a_known_name_is_flagged`).
- Every bug found in real testing gets a regression test naming it as such.
- Error messages address the operator and say what to do, not what failed
  internally. `doctor` is the model for this.
- No `unwrap()` outside tests.

## Testing

```sh
cargo test                 # unit + regression
cargo clippy --all-targets -- -D warnings
```

Screenshots of the terminal UI are taken from the real binary, not mocked:

```sh
tmux new-session -d -s iw -x 84 -y 13 "INTRAWEB_VAULT=/tmp/c intraweb up --tui"
sleep 4 && tmux capture-pane -p -t iw
```

Beware `pkill -f intraweb` when cleaning up: the pattern matches the shell
running it and kills your own command. Use `pkill -x intraweb`.

`cargo fmt` reflows code, so a scripted string replacement written against
pre-format source will silently miss. Format first, then patch, then re-check —
a signature change whose body edit missed compiles perfectly and does nothing.
A script making several such edits and writing once at the end writes nothing
at all when one anchor misses; verify each edit landed.

Commit each working piece. An hour of channel work was lost to a container
rebuild because it was held uncommitted.

Headless Chromium clamps its viewport to about 485px, so a narrower
`--window-size` crops a wider render rather than laying out for a phone. It
looks like an overflow bug and is not one.

CI runs `cargo fmt --all -- --check`, clippy with `-D warnings`, and the full
suite. All three must be clean before pushing.

Two nodes on one machine, which is also how discovery is tested end to end:

```sh
INTRAWEB_VAULT=/tmp/a intraweb up --hub --nickname alice --port 8480 &
INTRAWEB_VAULT=/tmp/b intraweb up --nickname bob --port 8481 &
curl -s localhost:8480/api/peers
```

The beacon sets `SO_REUSEPORT`, so both nodes share the beacon port; give them
distinct API ports.

## Deliberately out of scope

Multi-hop mesh routing across subnets, BLE fallback, database replication
between nodes, dynamic server-side scripts, global DNS, and 32-bit ARM
(Pi Zero) targets. Say no to these rather than half-building them.
