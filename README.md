# intraweb

**your neighborhood web**

A local-first intranet that needs no internet, no servers, and no setup. Put the
binary on a laptop or a Raspberry Pi, connect to the same Wi-Fi as everyone else,
and you can see each other, visit each other's pages, and send each other mail.

```sh
intraweb up
```

That is the whole setup. Nodes find each other in about a second.

## The idea

Most "local network" software makes one machine the server and everybody else a
client. Then the server owns your account, your files, and your name, and when
it goes away, so do you.

intraweb does it the other way round:

- **You are a keypair and a folder.** Your identity is an Ed25519 key in your
  vault. Copy the vault to another machine and you are still you.
- **Hubs are places, not owners.** A hub keeps a roster and offers a memorable
  address. It stores none of your content and cannot create or revoke you.
- **One folder, many neighborhoods.** Join a hub at home, another at the
  makerspace, a third at a field site. All three serve the same vault. Nothing
  is copied, and leaving takes nothing away.

The closest familiar comparison is Mastodon's federation, minus the part where
your data lives on somebody's instance.

## Install

Single static binary, no runtime dependencies:

```sh
curl -fsSL https://raw.githubusercontent.com/2008wbbv/intraweb/main/install.sh | sh
```

That fetches a prebuilt binary if one exists for your machine. If it does not,
the script builds from source instead — and checks first that it can, rather
than letting you find out several screens into a failed compile.

### Building from source

You need Rust and a **C compiler**. Rust shells out to `cc` to link every
binary, and the bundled SQLite is C, so a machine with Rust but no toolchain
(a fresh live session, a minimal container) will fail with
``linker `cc` not found``.

```sh
sudo apt-get install -y build-essential   # Debian, Ubuntu, Mint
sudo dnf install -y gcc                   # Fedora, RHEL
sudo pacman -S --needed base-devel        # Arch
sudo apk add build-base                   # Alpine
xcode-select --install                    # macOS
```

Then:

```sh
git clone https://github.com/2008wbbv/intraweb.git
cd intraweb
sh install.sh          # builds and installs to ~/.local/bin
# or: cargo build --release   → target/release/intraweb
```

For off-grid provisioning, copying the finished binary over with `scp` or a USB
stick works exactly as well — there is nothing else to install, and the machine
you copy it to needs no toolchain at all.

## Use

```sh
intraweb up                        # join the neighborhood
intraweb up --hub --hub-name oak   # host a hub at intranet.local
intraweb up --tui                  # same thing, in the terminal
intraweb serve ./photos            # publish a folder to the neighborhood
intraweb surf                      # see what the neighbors are publishing
intraweb mail send bob -m "hi"     # write to a neighbor
intraweb mail                      # read what you have been sent
intraweb ls bob                    # what is bob sharing?
intraweb get bob maps/ridge.pdf    # fetch it (resumes if interrupted)
intraweb say "gate is open"        # the neighborhood channel
intraweb chat                      # read it
intraweb channel new ridge crew    # a private channel, encrypted
intraweb sign bob "thanks!"        # write in a neighbor's guestbook
intraweb block someone             # stop seeing or hearing from a key
intraweb doctor                    # why can't I see anyone?
intraweb id                        # my fingerprint, for verifying in person
```

Open the dashboard at `http://intranet.local` (or `http://localhost:8420` if no
hub is running). It is plain HTML and JavaScript, and works on any phone on the
network.

### Your vault

```
~/.intraweb/
  identity.key   secret   your key — back this up, it is your name everywhere
  config.toml    private  nickname and preferences
  intraweb.db    private  who you have met, which hubs you have visited
  site/          PUBLIC   your mini-site, served at /~yourname
  files/         PUBLIC   media and downloads neighbors can pull
```

Drop an `index.html` in `site/` and it is live at every hub you join, or write
it from the dashboard's **Your page** panel, which also takes the pictures that
go beside it. Point `$INTRAWEB_VAULT` somewhere else to run more than one node
on one machine.


## In the terminal

`intraweb up --tui` gives the same roster as the browser dashboard, reading the
same live state — useful over SSH on a headless Pi.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│intraweb  your neighborhood web                                                   │
│carol  peer  844c-8e7b-9dfd-5d0a                                                  │
│1 neighbor(s) online, 1 hub(s) in range                                           │
└──────────────────────────────────────────────────────────────────────────────────┘
┌ Neighborhood ────────────────────────────────────────────────────────────────────┐
│  alice           [hub]  192.0.2.2        7abc-41d0-bd44-f2c2  1s ago             │
│* bob                    192.0.2.2        b1f1-13ab-865f-f337  1s ago             │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────┐
│j/k move   v mark verified after comparing fingerprints   q quit                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

`*` marks a neighbor whose fingerprint you have checked in person. A neighbor
using a name you have seen before on a **different key** is called out in red
rather than quietly shown as a familiar face.

## Publishing and browsing

Publish any folder without copying it into your vault:

```sh
intraweb serve ./photos
```

The folder is served in place at `/~yourname`, on every hub you are joined to,
and your vault's own `site/` is left exactly as it was.

To see what everyone else is publishing:

```
Looking around the neighborhood for 3s...

*  1  alice     Basecamp Notice Board               http://192.0.2.2:8480/~alice
   2  bob       A corner of the neighborhood web    http://192.0.2.2:8481/~bob
   3  carol     A corner of the neighborhood web    http://192.0.2.2:8482/~carol

* hub
Open one with: intraweb surf --open <number>
```

`surf` asks each neighbor directly and shows the page's own `<title>`. There is
no index and no crawler — the roster supplies addresses and your machine speaks
to theirs. A neighbor that is announcing but not answering is listed as such
instead of being hidden, and a name that has changed keys carries a warning with
the fingerprint you need to tell the two apart.

## Channels

```sh
intraweb say "road past the ridge is open"   # everyone in range
intraweb chat                                 # read the neighborhood
intraweb channel new ridge crew               # start a private one
intraweb channel invite "ridge crew" bob      # let bob in
intraweb say -c "ridge crew" "gate code 4471" # members only
```

Saying something hands it to each recipient's node directly. No hub carries a
channel and no server keeps the history: every node holds what it was told,
which also means a node that was switched off misses what was said. That is
the honest cost of having nowhere central to ask.

Private channels are **encrypted**, not merely delivered carefully. Posts
cross the same open network as everything else, where anyone holding the wifi
password is listening, so member-only delivery alone would be a promise the
wire does not keep. Inviting somebody seals the channel key to the encryption
key they announce — which means they have to be in range, since there is no
sealing a secret to a key you have never seen.

## Guestbooks

```sh
intraweb sign alice "thanks for the radio relay"
intraweb guestbook        # read your own
```

A guestbook is just a public channel whose address is derived from its
owner's key, so anyone can work out where to sign without being told.

## Mail

```sh
intraweb mail send alice -s "fuel drop" -m "Thursday 0600."
intraweb mail send alice -m "see attached" -a maps/ridge.tif
intraweb mail            # inbox
intraweb mail reply 3 -m "on my way"
intraweb mail delete 3
intraweb mail outbox     # including anything still queued
```

An attachment is a reference, not a copy. The message names a file in your
shared folder and the bytes stay with you until they fetch them, so a large
attachment costs nothing to send and the fetch resumes like any download.

Every message is signed with your key, so the sender cannot be forged, and goes
straight to the recipient's node. Nothing passes through a hub.

Addressing is by **key**, not by name. You may type a nickname and it will be
resolved, but if two keys answer to that nickname the send is refused and you
are shown both fingerprints to choose between — picking one for you would be a
guess about the thing that matters most.

Writing to somebody who is not around is normal: the message waits in your
outbox and leaves the moment they appear. You can address a public key you have
never seen, so a key written on paper is enough to write to someone.

## Files

```sh
intraweb ls alice                       # what alice is sharing
intraweb get alice maps/survey.tif      # fetch it
```

Downloads resume. If a transfer dies at 400 MB, running the same command again
asks for the rest rather than starting over, and nothing is ever held in memory,
so file size does not decide whether a transfer succeeds.

Anything you drop in your vault's `files/` folder is what neighbors see here.

## Who is who

Every key gets a picture drawn from it, shown beside the name everywhere.
Fingerprints are the honest way to tell two people apart and nobody reads
them — people skim the first group and stop, which is exactly the gap a
ground lookalike key walks through. A changed picture is far harder to miss
than `09fc-d332` becoming `09fc-d441`. It is a reading aid, not a security
boundary: confirming somebody still means comparing the fingerprint.

Drop an image named `avatar.png` in your vault to use your own picture
instead. Edit your name and a line about yourself from the dashboard.

## Trust

There are no passwords, and no certificate authority — neither would mean much
on an open LAN with no internet.

Instead, every announcement is signed. A node **cannot** announce itself under
someone else's key; the signature would not verify. What a node *can* do is pick
any nickname it likes, because nicknames are labels, not identity.

So intraweb watches the one thing that actually signals an impostor: a name you
have seen before turning up on a key you have not. That gets flagged loudly in
the dashboard rather than quietly rendered as a familiar face. To be certain
about someone, compare fingerprints out loud:

```
$ intraweb id
fingerprint  ba10-4253-4e1b-194a
```

Then mark them verified (`v` in the terminal UI, or the button in the dashboard).

intraweb also watches for a key whose fingerprint *opens* like one you already
know. A full collision is out of reach, but grinding until the first group or
two match is cheap, so a near miss is flagged rather than quietly shown.

If somebody will not leave you alone:

```sh
intraweb block someone
```

They are dropped from your roster and their mail, posts and invitations are
refused at the door.

## When nobody shows up

Usually the network, not the software. Plenty of consumer access points isolate
wireless clients or drop multicast, and both look identical from the dashboard:
an empty roster.

```sh
intraweb doctor
```

It listens on both discovery paths and tells you which one is working. intraweb
announces over **mDNS** and **UDP broadcast** at the same time precisely because
so many networks quietly break one of them.

## Media libraries

Already run Jellyfin, Navidrome, Calibre-Web or Immich? Point the
neighborhood at it:

```sh
intraweb library detect                  # find services already running here
intraweb library detect --add            # ...and list them all
intraweb library add Films 8096          # anything else, by port
intraweb library add Books 8083 --kind books
intraweb library list
intraweb libraries bob                   # what bob points at
```

Each library shows up as a button on your card in everyone's dashboard. It is
a link, not a relay: their browser goes straight to the service on your
machine, so the media never passes through intraweb or a hub, and it streams
as fast as the two machines manage. The service has to listen on your network
(not only on localhost) and your firewall has to allow its port; `library add`
warns if nothing is answering yet.

The dashboard has the same thing as a **Media libraries** box: *Find services
on this computer*, then one click per service. Detection recognises a service
by its own name on its own page, not by an open port, and knows Jellyfin,
Plex, Navidrome, Audiobookshelf, Calibre-Web, Kavita, Komga, Immich,
PhotoPrism, Kiwix, Home Assistant, Paperless-ngx, Mealie, Forgejo and Gitea.
Listing, removing and detecting only answer to this machine; a neighbor asking
gets a 403, so the dashboard's port is not a free port scan.

A neighbor's list is checked before it is shown: names lose markup, a path
can only be a path on that neighbor's own address, and nobody can list more
than sixteen.

## No router? Bring one

intraweb only needs machines that can hear each other. It does not need the
internet, and it does not need a router.

- **An ESP32.** `hardware/esp32-ap` turns a $5 board into a Wi-Fi network on a
  battery bank: up to 10 devices, a page that tells newcomers what to run, and
  nothing stored on it. See its README for flashing.
- **A laptop or Pi.** `nmcli device wifi hotspot ssid intraweb password
  neighborhood` makes a network on Linux; the machine sharing it runs
  `intraweb up` like everyone else.
- **Two laptops and a cable.** Plug Ethernet straight between them; both take
  link-local addresses and find each other with no router or DHCP.
- **A phone hotspot**, with mobile data off if you want to be sure nothing
  leaves the room. Windows and macOS hotspots usually want an internet
  connection to share, so offline, use a Linux laptop, a Pi or the ESP32.
- **Any old router** with no cable in the WAN port.

Whichever you use, check client isolation is off, and run `intraweb doctor` if
nobody shows up.

## Status

Working today: discovery, portable identity, the roster, the web and terminal
dashboards, diagnostics, `serve`, `surf`, signed store-and-forward mail with
attachments, channels both public and private, guestbooks, and resumable file
transfer. Your page is written from the dashboard.

**Nets** are open groups of channels anyone in range can find and join. The
founder leads; members can impeach a leader (a new one is drawn at random) and
the leader can call a vote to remove a member. A leader can make low data
mandatory, announce, and ping everyone. There is no server holding any of
this: a net is a log of signed posts, and every node works out the same
answer from it. Votes count members who had joined when the vote opened; an
open net cannot stop somebody who made many keys in advance.

See `NOTES.md` for what is still undecided.

## License

MIT OR Apache-2.0
