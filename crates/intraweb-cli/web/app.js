"use strict";

// The dashboard is a thin client. Every fact it shows comes from the local
// JSON API, which the terminal UI reads too, so the two can never disagree.

const REFRESH_MS = 2000;

/** Nicknames are scrubbed server-side, but never build markup from remote text. */
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function relativeTime(seconds) {
  if (seconds < 2) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function duration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} responded ${response.status}`);
  return response.json();
}

function text(id, value) {
  document.getElementById(id).textContent = value;
}

function peerAddress(peer) {
  const address = (peer.addrs && peer.addrs[0]) || null;
  if (!address) return null;
  return address.includes(":") ? `[${address}]` : address;
}

function badges(peer) {
  const out = [];
  if (peer.is_hub) out.push('<span class="badge hub">hub</span>');
  if (peer.trust === "verified") out.push('<span class="badge verified">verified</span>');
  if (peer.trust === "new") out.push('<span class="badge">new</span>');
  if (peer.trust === "nickname_conflict") out.push('<span class="badge conflict">name clash</span>');
  if (peer.trust === "lookalike_fingerprint") out.push('<span class="badge conflict">lookalike</span>');
  return out.join(" ");
}

/// What to say about a peer whose identity does not add up.
function alarmText(peer) {
  if (peer.trust === "nickname_conflict") {
    return `<strong>Not the ${escapeHtml(peer.nickname)} you met before.</strong>
      Same name, different key &mdash; compare fingerprints in person.`;
  }
  if (peer.trust === "lookalike_fingerprint") {
    return `<strong>This fingerprint opens like one you already know.</strong>
      Keys can be ground until the first groups match. Read all of it, not the start.`;
  }
  return null;
}

function neighborCard(peer, rank, now) {
  const alarming = peer.trust === "nickname_conflict" || peer.trust === "lookalike_fingerprint";
  const classes = ["neighbor"];
  if (peer.is_hub) classes.push("is-hub");
  if (alarming) classes.push("is-alarming");

  const host = peerAddress(peer);
  const siteUrl = host
    ? `http://${host}:${peer.api_port}/~${encodeURIComponent(peer.nickname)}`
    : null;

  const warning = alarmText(peer);
  const alarm = warning ? `<div class="alarm">${warning}</div>` : "";

  return `
    <article class="${classes.join(" ")}">
      <span class="rank">${rank}</span>
      <img class="identicon" alt="" loading="lazy"
           src="${host && !lowData() ? `http://${host}:${peer.api_port}/avatar` : `/identicon/${escapeHtml(peer.peer_id)}.svg`}"
           data-fallback="/identicon/${escapeHtml(peer.peer_id)}.svg"
           onerror="this.onerror=null;this.src=this.dataset.fallback">
      <div class="neighbor-name">${escapeHtml(peer.nickname)} ${badges(peer)}</div>
      <div class="fp">${escapeHtml(peer.fingerprint)}</div>
      <div class="meta">
        ${host ? escapeHtml(host) : "address unknown"}
        &middot; ${escapeHtml(peer.source)}
        &middot; ${escapeHtml(relativeTime(Math.max(0, now - peer.last_seen)))}
      </div>
      ${alarm}
      <div class="actions">
        ${siteUrl ? `<a href="${siteUrl}" target="_blank" rel="noopener">Visit page</a>` : ""}
        ${peer.trust !== "verified"
          ? `<button type="button" data-verify="${escapeHtml(peer.peer_id)}">Checked in person</button>`
          : ""}
        ${selectedChannel && !selectedChannel.channel_id_is_public
          ? `<button type="button" data-invite="${escapeHtml(peer.peer_id)}">Invite to ${escapeHtml(selectedChannel.name)}</button>`
          : ""}
        <button type="button" data-sign="${escapeHtml(peer.peer_id)}">Sign guestbook</button>
        <button type="button" class="danger" data-block="${escapeHtml(peer.peer_id)}">Block</button>
      </div>
      ${host ? `<div class="libs" data-libs="${escapeHtml(peer.peer_id)}"></div>` : ""}
    </article>`;
}

// Which channel the reader is looking at. Kept here so a refresh does not
// yank them back to the neighborhood mid-conversation.
let selectedChannelId = null;
let selectedChannel = null;
// Stepped out of every channel: nothing is read until they step back in.
let steppedOut = false;

// The latest of each, so renderers can cross-reference without refetching.
let lastStatus = null;
let lastPeers = [];
let lastActivity = null;
let contactsByKey = new Map();
let sharedFiles = [];
let nodeReachable = true;

function lowData() {
  return Boolean(lastStatus && lastStatus.low_data);
}

// Nets: what the directory lists, and the full state of the ones we are in.
let netsList = [];
let netDetails = new Map();
// The net open in the Nets panel, which follows the channel you are in.
let viewNetId = null;

function netName(netId) {
  const listed = netsList.find((n) => n.net_id === netId);
  return listed ? listed.name : "a net";
}

/// The net the channel being read belongs to, with its state, if we are in it.
function currentNet() {
  const id = selectedChannel && selectedChannel.net_id;
  return id ? netDetails.get(id) || null : null;
}

/// Pictures off for this channel: by your own choice, or by its net's leader.
function channelLowData() {
  const net = currentNet();
  return lowData() || Boolean(net && net.net.low_data_mandatory);
}

/// A channel's name as shown: net channels carry their net, so "general"
/// in two nets cannot be mistaken for one another.
function channelLabel(channel) {
  if (!channel.net_id) return `${channel.is_private ? "\u25cf " : "#"}${channel.name}`;
  const net = netName(channel.net_id);
  const short = channel.name.startsWith(`${net} `) ? channel.name.slice(net.length + 1) : channel.name;
  return `${net} \u203a ${channel.is_private ? "\u25cf " : "#"}${short}`;
}

/// A post's or letter's time: the clock alone for today, the date otherwise.
function clock(seconds) {
  const when = new Date(seconds * 1000);
  const today = new Date();
  const sameDay = when.toDateString() === today.toDateString();
  const time = when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay
    ? time
    : `${when.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}

/// Who a key is, as far as we know: their name if we have one, and always
/// the start of their fingerprint beside it -- a bare name in a list is
/// exactly where somebody wearing it would pass unnoticed.
function whoIs(peerId, fingerprint) {
  if (lastStatus && peerId === lastStatus.peer_id) return "you";
  const live = lastPeers.find((p) => p.peer_id === peerId);
  const known = contactsByKey.get(peerId);
  const name = (live && live.nickname) || (known && known.nickname);
  fingerprint = fingerprint || (live && live.fingerprint) || (known && known.fingerprint) || peerId;
  const fp = escapeHtml((fingerprint || "").slice(0, 4));
  const alarming = live && (live.trust === "nickname_conflict" || live.trust === "lookalike_fingerprint");
  return name
    ? `${alarming ? "&#9888; " : ""}${escapeHtml(name)} <span class="fp-tag">${fp}</span>`
    : escapeHtml((fingerprint || "").slice(0, 9));
}

const PICTURE = /\.(png|jpe?g|gif|webp|avif)$/i;

/// A file a neighbor offers lives on their node, so it is fetched from there.
function offeredFile(path, peerId) {
  if (!path) return "";
  const name = escapeHtml(path);
  // Our own file is served right here; we are never on our own roster.
  const ours = lastStatus && peerId === lastStatus.peer_id;
  const sender = lastPeers.find((p) => p.peer_id === peerId);
  const host = sender ? peerAddress(sender) : null;
  if (!ours && !host) {
    return `<span class="attached">&#128206; ${name} <span class="aside-note">(they are out of range)</span></span>`;
  }
  const url = ours
    ? `/files/${encodeURI(path)}`
    : `http://${host}:${sender.api_port}/files/${encodeURI(path)}`;
  if (PICTURE.test(path) && !channelLowData()) {
    return `<a class="attached" href="${url}" target="_blank" rel="noopener">
      <img src="${url}" alt="${name}" loading="lazy"
           onerror="this.replaceWith(document.createTextNode('picture unavailable: ${name}'))"></a>`;
  }
  const note = PICTURE.test(path)
    ? lowData()
      ? " (picture &mdash; not loaded in low data mode)"
      : " (picture &mdash; this net's leader has made low data mandatory)"
    : "";
  return `<a class="attached" href="${url}" target="_blank" rel="noopener">&#128206; ${name}${note}</a>`;
}

function renderMe(status) {
  const mine = document.getElementById("me-icon");
  mine.dataset.fallback = `/identicon/${status.peer_id}.svg`;
  mine.onerror = () => {
    mine.onerror = null;
    mine.src = mine.dataset.fallback;
  };
  mine.src = "/avatar";
  text("me-nickname", status.nickname);
  text("me-role", status.is_hub ? `hosting "${status.hub_name || ""}"` : "neighbor");
  text("me-fingerprint", status.fingerprint);
  text("me-uptime", duration(status.uptime_secs));
  const vaultPath = document.getElementById("vault-path");
  vaultPath.textContent = status.vault_path;
  vaultPath.title = status.vault_path;
  const sitePath = document.getElementById("site-path");
  sitePath.textContent = status.site_path;
  sitePath.title = status.site_path;
  text("known-peers", `${status.known_peers} key(s) in the keyring`);

  const tagline = document.getElementById("me-tagline");
  tagline.textContent = status.tagline || "";
  tagline.hidden = !status.tagline;

  const site = document.getElementById("me-site");
  site.textContent = `/~${status.nickname}`;
  site.href = `/~${status.nickname}/`;

  const editorLink = document.getElementById("site-link");
  editorLink.textContent = `/~${status.nickname}`;
  editorLink.href = `/~${status.nickname}/`;

  document.querySelector(".presence").classList.add("live");
  text("presence-text", `online · ${status.peers_online} in range`);
}

function renderRosters(peers, status) {
  const now = status.now;
  const hubs = peers.filter((p) => p.is_hub);
  const neighbors = peers.filter((p) => !p.is_hub);

  text(
    "peer-count",
    peers.length === 0
      ? "nobody yet"
      : `${peers.length} in range${hubs.length ? `, ${hubs.length} hub` : ""}`,
  );

  // One running number across both lists, so a neighbor can be referred to by it.
  let rank = 0;
  document.getElementById("hubs").innerHTML = hubs
    .map((peer) => neighborCard(peer, ++rank, now))
    .join("");

  document.getElementById("peers").innerHTML = neighbors.length
    ? neighbors.map((peer) => neighborCard(peer, ++rank, now)).join("")
    : `<p class="empty">${
        hubs.length ? "No neighbors beyond the hub yet." : "Nobody in range yet."
      }</p>`;
  fillLibraries();
}

// A neighbor's media libraries change rarely, so ask each node at most once a
// minute however often the roster redraws.
const libraryCache = new Map();
const LIBRARY_GLYPH = { video: "\u25B6", music: "\u266A", books: "\u2261", photos: "\u25A3", other: "\u2197" };

function libraryButtons(links) {
  return links
    .map((l) => `<a class="lib" href="${escapeHtml(l.url)}" target="_blank" rel="noopener"
        title="Opens ${escapeHtml(l.url)} on their machine">${LIBRARY_GLYPH[l.kind] || LIBRARY_GLYPH.other} ${escapeHtml(l.name)}</a>`)
    .join("");
}

function fillLibraries() {
  const now = Date.now();
  for (const el of document.querySelectorAll("[data-libs]")) {
    const id = el.dataset.libs;
    let cached = libraryCache.get(id);
    if (!cached || now - cached.at > 60000) {
      cached = { at: now, links: cached ? cached.links : [] };
      libraryCache.set(id, cached);
      fetch(`/api/peers/${encodeURIComponent(id)}/libraries`)
        .then((r) => (r.ok ? r.json() : []))
        .then((links) => {
          cached.links = Array.isArray(links) ? links : [];
          for (const target of document.querySelectorAll(`[data-libs="${CSS.escape(id)}"]`)) {
            target.innerHTML = libraryButtons(cached.links);
          }
        })
        .catch(() => {});
    }
    el.innerHTML = libraryButtons(cached.links);
  }
}

// ---- your own media libraries ------------------------------------------------

let lastDetected = [];

async function postLibrary(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  document.getElementById("library-result").textContent = response.ok ? "" : text;
  return response.ok;
}

async function saveLibrary(library) {
  if (await postLibrary("/api/libraries/add", library)) {
    await loadLibraries();
    if (lastDetected.length) renderDetected(await getJson("/api/libraries/detect"));
  }
}

async function loadLibraries() {
  let libs = [];
  try {
    libs = await getJson("/api/libraries");
  } catch {
    return;
  }
  document.getElementById("libraries-meta").textContent = libs.length ? `${libs.length} listed` : "";
  document.getElementById("my-libraries").innerHTML = libs.length
    ? `<ul class="lib-list">${libs
        .map(
          (l) => `<li><span>${LIBRARY_GLYPH[l.kind] || LIBRARY_GLYPH.other} ${escapeHtml(l.name)}</span>
            <span class="mono">:${escapeHtml(String(l.port))}${escapeHtml(l.path === "/" ? "" : l.path)}</span>
            <button type="button" class="quiet danger" data-lib-remove="${escapeHtml(l.name)}">Remove</button></li>`,
        )
        .join("")}</ul>`
    : "";
}

function renderDetected(found) {
  lastDetected = Array.isArray(found) ? found : [];
  document.getElementById("detected-libraries").innerHTML = lastDetected.length
    ? `<ul class="lib-list">${lastDetected
        .map(
          (d, i) => `<li><span>${LIBRARY_GLYPH[d.kind] || LIBRARY_GLYPH.other} ${escapeHtml(d.name)}
              <small>${escapeHtml(d.what)}</small></span>
            <span class="mono">:${escapeHtml(String(d.port))}</span>
            ${d.listed ? '<span class="aside-note">listed</span>' : `<button type="button" data-lib-add="${i}">Add</button>`}</li>`,
        )
        .join("")}</ul>`
    : '<p class="empty">None of the services intraweb knows by name are running here. Add any other by its port below.</p>';
}

document.getElementById("library-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const ok = await postLibrary("/api/libraries/add", {
    name: form.name.value,
    port: Number(form.port.value),
    kind: form.kind.value,
  });
  if (ok) {
    form.reset();
    await loadLibraries();
  }
});

loadLibraries();

/// An attachment lives on the sender's node, so the link points there.
/// Without their address there is nothing to link to, so say the name only.
function attachmentLink(message, peers) {
  if (!message.attachment) return "";

  const sender = peers.find((p) => p.peer_id === message.peer_id);
  const host = sender ? peerAddress(sender) : null;
  const name = escapeHtml(message.attachment);

  return host
    ? `<div class="attachment">attached:
         <a href="http://${host}:${sender.api_port}/files/${encodeURI(message.attachment)}"
            target="_blank" rel="noopener">${name}</a></div>`
    : `<div class="attachment">attached: ${name} <span class="aside-note">(sender is out of range)</span></div>`;
}

function renderMail(messages, now, peers) {
  const unread = messages.filter((m) => !m.read_at).length;
  text("mail-count", messages.length === 0 ? "empty" : `${messages.length} received${unread ? `, ${unread} unread` : ""}`);

  document.getElementById("mail").innerHTML = messages.length
    ? messages
        .map(
          (message) => `
        <article class="letter ${message.read_at ? "" : "unread"}">
          <div class="subject">${escapeHtml(message.subject || "(no subject)")}</div>
          <div class="from">${whoIs(message.peer_id, message.fingerprint)}
            &middot; <time title="${escapeHtml(new Date(message.created_at * 1000).toLocaleString())}">${escapeHtml(clock(message.created_at))}</time>
            &middot; ${escapeHtml(relativeTime(Math.max(0, now - message.created_at)))}</div>
          <div class="body">${escapeHtml(message.body)}</div>
          ${attachmentLink(message, peers)}
          <div class="actions">
            <button type="button" class="danger" data-delete-mail="${message.id}">Delete</button>
          </div>
        </article>`,
        )
        .join("")
    : '<p class="empty">No mail yet.</p>';
}

function renderDoctor(report) {
  const checks = report.checks
    .map(
      (check) => `
      <div class="check">
        <span class="dot ${escapeHtml(check.status)}"></span>
        <span>
          <span class="label">${escapeHtml(check.name)}</span> &mdash; ${escapeHtml(check.detail)}
          ${check.remedy ? `<div class="remedy">${escapeHtml(check.remedy)}</div>` : ""}
        </span>
      </div>`,
    )
    .join("");
  document.getElementById("doctor").innerHTML =
    `${checks}<div class="verdict">${escapeHtml(report.verdict)}</div>`;
}

function renderGuestbook(entries) {
  document.getElementById("guestbook-meta").textContent =
    entries.length === 0 ? "empty" : `${entries.length} entr${entries.length === 1 ? "y" : "ies"}`;

  document.getElementById("guestbook").innerHTML = entries.length
    ? entries
        .map(
          (entry) => `
        <article class="letter">
          <div class="from">
            <img class="identicon" src="/identicon/${escapeHtml(entry.from)}.svg" alt=""
                 width="18" height="18" loading="lazy">
            ${escapeHtml(entry.fingerprint)}
          </div>
          <div class="body">${escapeHtml(entry.body)}</div>
        </article>`,
        )
        .join("")
    : '<p class="empty">Nobody has signed your guestbook yet.</p>';
}

function renderChannels(allChannels, status) {
  const tabs = document.getElementById("channel-tabs");
  // Our own guestbook has a panel of its own; listing it here as well would
  // just be the same thing twice. A net's log and the directory are records,
  // not conversations, and have the Nets panel.
  const channels = allChannels.filter(
    (c) => c.channel_id !== status.guestbook_channel && c.role === "chat",
  );

  if (!selectedChannelId && !steppedOut && channels.length) {
    const neighborhood = channels.find((c) => !c.is_private) || channels[0];
    selectedChannelId = neighborhood.channel_id;
  }
  renderWhereabouts(channels);
  selectedChannel = channels.find((c) => c.channel_id === selectedChannelId) || null;
  if (selectedChannel) {
    selectedChannel.channel_id_is_public = !selectedChannel.is_private;
  }

  tabs.innerHTML = channels
    .map(
      (channel) => `
      <button type="button"
              class="channel-tab ${channel.channel_id === selectedChannelId ? "active" : ""} ${
                channel.can_read ? "" : "locked"
              }"
              data-channel="${escapeHtml(channel.channel_id)}">
        ${escapeHtml(channelLabel(channel))}
      </button>`,
    )
    .join("");

  document.getElementById("channel-meta").textContent = selectedChannel
    ? selectedChannel.is_private
      ? "private \u00b7 members only"
      : "everyone in range"
    : steppedOut
      ? "stepped out"
      : "";
  document.getElementById("say-form").hidden = !selectedChannel;
  renderAttachAvailability();
}

/// The masthead says where you are, beside the slogan, and is how you move.
/// Rebuilt only when the list changes, so an open menu is not snatched away
/// by the two-second refresh.
let whereaboutsKey = "";
function renderWhereabouts(channels) {
  const select = document.getElementById("header-channel");
  const key = JSON.stringify([
    channels.map((c) => [c.channel_id, channelLabel(c)]),
    selectedChannelId,
  ]);
  if (key === whereaboutsKey) return;
  whereaboutsKey = key;
  select.innerHTML =
    channels
      .map(
        (c) => `<option value="${escapeHtml(c.channel_id)}" ${c.channel_id === selectedChannelId ? "selected" : ""}>
          \u00b7 in ${escapeHtml(channelLabel(c))}</option>`,
      )
      .join("") +
    `<option value="" ${selectedChannelId ? "" : "selected"}>\u00b7 stepped out</option>`;
}

let lastPostsHtml = "";
function renderPosts(posts, { force = false } = {}) {
  const box = document.getElementById("channel-posts");
  const here = currentNet();
  const leaderHere = here && here.net.leader;
  const html = steppedOut
    ? '<p class="empty">You stepped out. Pick a channel at the top to step back in.</p>'
    : posts.length
      ? posts
          .map(
            (post) => `
        <div class="post ${post.readable ? "" : "sealed"}">
          <time class="when" datetime="${new Date(post.created_at * 1000).toISOString()}"
                title="${escapeHtml(new Date(post.created_at * 1000).toLocaleString())}">${escapeHtml(clock(post.created_at))}</time>
          <span class="who named" title="${escapeHtml(post.fingerprint)}">${whoIs(post.from, post.fingerprint)}${
            leaderHere && post.from === leaderHere ? '<span class="badge-leader">net leader</span>' : ""
          }</span>
          <span class="said">${
            post.readable
              ? escapeHtml(post.body)
              : "encrypted &mdash; you are not in this channel"
          }${post.readable ? offeredFile(post.attachment, post.from) : ""}</span>
        </div>`,
          )
          .join("")
      : '<p class="empty">Nothing said here yet.</p>';

  // Repainting identical markup every refresh would refetch every picture
  // and make them flicker; and it would yank somebody reading back up the
  // conversation down to the bottom.
  if (html === lastPostsHtml && !force) return;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  lastPostsHtml = html;
  box.innerHTML = html;
  if (atBottom || force) box.scrollTop = box.scrollHeight;
}

async function refreshChannel(options) {
  if (!selectedChannelId) {
    renderPosts([], options);
    return;
  }
  try {
    renderPosts(await getJson(`/api/channels/${selectedChannelId}/posts`), options);
  } catch (err) {
    renderPosts([], options);
  }
}

async function refresh() {
  try {
    // One request: status, roster and mail are always rendered together.
    const state = await getJson("/api/state");
    lastStatus = state.status;
    lastPeers = state.peers;
    nodeReachable = true;
    const [contacts, activity] = await Promise.all([
      getJson("/api/contacts"),
      getJson("/api/activity"),
    ]);
    contactsByKey = new Map(contacts.map((c) => [c.peer_id, c]));
    lastActivity = activity;
    renderMe(state.status);
    renderRosters(state.peers, state.status);
    renderContacts(contacts, state.status.now);
    renderActivity(activity, state.status, state.peers);
    renderMail(state.mail, state.status.now, state.peers);
    await refreshNets();
    renderChannels(await getJson("/api/channels"), state.status);
    renderNetDetail();
    renderGuestbook(await getJson("/api/guestbook"));
    await refreshChannel();
  } catch (err) {
    nodeReachable = false;
    document.querySelector(".presence").classList.remove("live");
    text("presence-text", "node unreachable");
  }
  renderAvatarControls();
}

document.addEventListener("click", async (event) => {
  const blockButton = event.target.closest("[data-block]");
  if (blockButton) {
    blockButton.disabled = true;
    await fetch(`/api/peers/${blockButton.dataset.block}/block`, { method: "POST" });
    await refresh();
    return;
  }

  const verifyButton = event.target.closest("[data-verify]");
  if (verifyButton) {
    verifyButton.disabled = true;
    await fetch(`/api/peers/${verifyButton.dataset.verify}/verify`, { method: "POST" });
    await refresh();
    return;
  }

  if (event.target.id === "detect-libraries") {
    const button = event.target;
    button.disabled = true;
    button.textContent = "Looking…";
    try {
      renderDetected(await getJson("/api/libraries/detect"));
    } catch {
      document.getElementById("detected-libraries").innerHTML =
        '<p class="empty">Could not look. Is this the dashboard on this computer?</p>';
    }
    button.disabled = false;
    button.textContent = "Look again";
    return;
  }

  const addDetected = event.target.closest("[data-lib-add]");
  if (addDetected) {
    const found = lastDetected[Number(addDetected.dataset.libAdd)];
    if (found) await saveLibrary({ name: found.name, port: found.port, path: found.path, kind: found.kind });
    return;
  }

  const removeLibrary = event.target.closest("[data-lib-remove]");
  if (removeLibrary) {
    await postLibrary("/api/libraries/remove", { name: removeLibrary.dataset.libRemove });
    await loadLibraries();
    return;
  }

  if (event.target.id === "run-doctor") {
    const button = event.target;
    button.disabled = true;
    button.textContent = "Listening…";
    document.getElementById("doctor").innerHTML =
      '<p class="empty">Listening on both discovery paths…</p>';
    try {
      renderDoctor(await getJson("/api/doctor"));
    } catch (err) {
      document.getElementById("doctor").innerHTML = '<p class="empty">The check could not run.</p>';
    }
    button.disabled = false;
    button.textContent = "Run check";
  }
});

document.addEventListener("click", async (event) => {
  const tab = event.target.closest("[data-channel]");
  if (tab) {
    selectedChannelId = tab.dataset.channel;
    steppedOut = false;
    viewNetId = null; // follow the channel's net
    await refresh();
    await refreshChannel({ force: true });
    return;
  }

  const signButton = event.target.closest("[data-sign]");
  if (signButton) {
    const note = window.prompt("What would you like to write in their guestbook?");
    if (!note || !note.trim()) return;
    signButton.disabled = true;
    const response = await fetch(`/api/guestbook/${signButton.dataset.sign}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body: note }),
    });
    document.getElementById("say-result").textContent = await response.text();
    signButton.disabled = false;
    return;
  }

  const deleteMail = event.target.closest("[data-delete-mail]");
  if (deleteMail) {
    deleteMail.disabled = true;
    await fetch(`/api/mail/${deleteMail.dataset.deleteMail}/delete`, { method: "POST" });
    await refresh();
    return;
  }

  const inviteButton = event.target.closest("[data-invite]");
  if (inviteButton && selectedChannelId) {
    inviteButton.disabled = true;
    const response = await fetch(
      `/api/channels/${selectedChannelId}/invite/${inviteButton.dataset.invite}`,
      { method: "POST" },
    );
    document.getElementById("say-result").textContent = await response.text();
    inviteButton.disabled = false;
    return;
  }

  if (event.target.id === "start-edit") {
    const form = document.getElementById("edit-profile");
    const profile = await getJson("/api/profile");
    document.getElementById("edit-nickname").value = profile.nickname;
    document.getElementById("edit-tagline").value = profile.tagline;
    form.hidden = false;
    event.target.hidden = true;
    return;
  }

  if (event.target.id === "cancel-edit") {
    document.getElementById("edit-profile").hidden = true;
    document.getElementById("start-edit").hidden = false;
  }
});

document.getElementById("edit-profile").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.getElementById("edit-result");
  result.textContent = "Saving\u2026";

  const response = await fetch("/api/profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nickname: document.getElementById("edit-nickname").value,
      tagline: document.getElementById("edit-tagline").value,
    }),
  });
  // The server says plainly when a rename needs a restart to be announced.
  result.textContent = await response.text();
  if (response.ok) refresh();
});

document.getElementById("say-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("say-body");
  const attachment = document.getElementById("say-file").value || null;
  if ((!input.value.trim() && !attachment) || !selectedChannelId) return;
  if (attachment && !confirmCost("say", attachment)) return;

  const response = await fetch(`/api/channels/${selectedChannelId}/say`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body: input.value, attachment }),
  });
  document.getElementById("say-result").textContent = await response.text();
  if (response.ok) {
    input.value = "";
    clearAttachment("say");
    await refreshChannel({ force: true });
  }
});

document.getElementById("new-channel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = document.getElementById("new-channel-name");
  const response = await fetch("/api/channels/new", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: name.value,
      net: document.getElementById("new-channel-net").value || null,
    }),
  });
  if (response.ok) {
    selectedChannelId = (await response.text()).trim();
    name.value = "";
    await refresh();
  } else {
    document.getElementById("say-result").textContent = await response.text();
  }
});

document.getElementById("compose").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.getElementById("compose-result");
  const payload = {
    to: document.getElementById("compose-to").value,
    subject: document.getElementById("compose-subject").value,
    body: document.getElementById("compose-body").value,
    attachment: document.getElementById("compose-file").value || null,
  };
  if (payload.attachment && !confirmCost("compose", payload.attachment)) return;

  result.textContent = "Sending…";
  const response = await fetch("/api/mail/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  // The server reports ambiguity in full; show it rather than a generic failure.
  result.textContent = await response.text();
  if (response.ok) {
    document.getElementById("compose-subject").value = "";
    document.getElementById("compose-body").value = "";
    clearAttachment("compose");
    refresh();
  }
});

/* Your own page.
 *
 * Loaded once rather than on the poll: refreshing a textarea under somebody's
 * cursor throws away whatever they were half way through typing. `siteDirty`
 * is what tells the two apart.
 */

/* Matches MAX_SITE_WRITE on the node, so an oversized file is refused here
   with the same advice instead of being pushed up the wire first. */
const MAX_SITE_BYTES = 4 * 1024 * 1024;
let siteDirty = false;

function fileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderSiteFiles(files) {
  const box = document.getElementById("site-files");
  if (!files.length) {
    box.innerHTML = "";
    return;
  }
  box.innerHTML = files
    .map(
      (file) => `<div class="site-file">
      <span class="name mono">${escapeHtml(file.name)}</span>
      <span class="size">${escapeHtml(fileSize(file.size))}</span>
      <button type="button" class="quiet" data-site-copy="${escapeHtml(file.name)}">Insert</button>
      <button type="button" class="quiet danger" data-site-delete="${escapeHtml(file.name)}">Remove</button>
    </div>`,
    )
    .join("");
}

async function loadSite({ keepEdits = false } = {}) {
  try {
    const site = await getJson("/api/site");
    const editor = document.getElementById("site-html");
    if (!keepEdits || !siteDirty) {
      editor.value = site.html;
      siteDirty = false;
    }
    renderSiteFiles(site.files);
    // The folder is already named in the Vault panel; repeating a long
    // absolute path in a title bar only pushes the heading off a small screen.
    const meta = document.getElementById("site-meta");
    meta.textContent = site.files.length
      ? `${site.files.length} file${site.files.length === 1 ? "" : "s"}`
      : "";
    meta.title = site.path;
  } catch (err) {
    document.getElementById("site-result").textContent = "could not read your page";
  }
}

document.getElementById("site-html").addEventListener("input", () => {
  siteDirty = true;
  document.getElementById("site-result").textContent = "unsaved";
});

document.getElementById("save-site").addEventListener("click", async (event) => {
  const result = document.getElementById("site-result");
  const body = document.getElementById("site-html").value;
  if (body.length > MAX_SITE_BYTES) {
    result.textContent = "that page is too big to save";
    return;
  }

  event.target.disabled = true;
  result.textContent = "Saving\u2026";
  try {
    const response = await fetch("/api/site", {
      method: "POST",
      headers: { "Content-Type": "text/html" },
      body,
    });
    result.textContent = await response.text();
    if (response.ok) siteDirty = false;
  } catch (err) {
    result.textContent = "the node did not answer";
  } finally {
    event.target.disabled = false;
  }
});

document.getElementById("revert-site").addEventListener("click", async () => {
  siteDirty = false;
  await loadSite();
  document.getElementById("site-result").textContent = "Reverted to what is published.";
});

document.getElementById("site-upload").addEventListener("change", async (event) => {
  const result = document.getElementById("site-result");
  const chosen = Array.from(event.target.files || []);
  if (!chosen.length) return;

  for (const file of chosen) {
    if (file.size > MAX_SITE_BYTES) {
      result.textContent = `${file.name} is too big; put large files in the vault's files/ folder`;
      continue;
    }
    result.textContent = `Uploading ${file.name}\u2026`;
    try {
      const response = await fetch(`/api/site/file/${encodeURIComponent(file.name)}`, {
        method: "POST",
        body: file,
      });
      result.textContent = await response.text();
    } catch (err) {
      result.textContent = `could not upload ${file.name}`;
    }
  }
  // Clear it, or choosing the same file twice in a row fires no event.
  event.target.value = "";
  // Keep whatever is being typed; only the file list needs to catch up.
  await loadSite({ keepEdits: true });
});

document.getElementById("site-files").addEventListener("click", async (event) => {
  const copy = event.target.dataset.siteCopy;
  if (copy) {
    const tag = /\.(png|jpe?g|gif|webp|svg)$/i.test(copy)
      ? `<img src="${copy}" alt="">`
      : `<a href="${copy}">${copy}</a>`;
    const editor = document.getElementById("site-html");
    // Dropped in at the cursor, which is where somebody writing a page wants
    // it -- and writing it in is more use than a clipboard they must paste.
    const at = editor.selectionStart ?? editor.value.length;
    editor.value = `${editor.value.slice(0, at)}${tag}${editor.value.slice(at)}`;
    editor.focus();
    editor.selectionStart = editor.selectionEnd = at + tag.length;
    siteDirty = true;
    document.getElementById("site-result").textContent = "unsaved";
    return;
  }

  const name = event.target.dataset.siteDelete;
  if (!name) return;
  const result = document.getElementById("site-result");
  try {
    const response = await fetch(`/api/site/file/${encodeURIComponent(name)}`, {
      method: "DELETE",
    });
    result.textContent = await response.text();
  } catch (err) {
    result.textContent = `could not remove ${name}`;
  }
  await loadSite({ keepEdits: true });
});

/* ------------------------------------------------------------ contacts ---- */

/// Everyone met before, the ones in range first. Also feeds the mail form's
/// suggestions, where a name two keys share is offered as fingerprints
/// instead -- picking one of those by name would be a coin toss.
function renderContacts(contacts, now) {
  const online = contacts.filter((c) => c.online).length;
  text("contacts-meta", contacts.length ? `${online} of ${contacts.length} in range` : "nobody yet");

  document.getElementById("contacts").innerHTML = contacts.length
    ? contacts
        .map(
          (c) => `
      <div class="contact ${c.online ? "online" : ""}">
        <span class="state" title="${c.online ? "in range now" : "out of range"}"></span>
        <span class="name">${escapeHtml(c.nickname)}${c.verified ? " &#10003;" : ""}</span>
        <span class="fp">${escapeHtml(c.fingerprint)}</span>
        <span class="seen">${c.online ? "here now" : `seen ${escapeHtml(relativeTime(Math.max(0, now - c.last_seen)))}`}</span>
        <button type="button" class="quiet" data-write="${escapeHtml(c.fingerprint)}">Write</button>
      </div>`,
        )
        .join("")
    : '<p class="empty">Nobody met yet. People you see appear here and stay.</p>';

  const counts = new Map();
  contacts.forEach((c) => counts.set(c.nickname, (counts.get(c.nickname) || 0) + 1));
  document.getElementById("contact-suggestions").innerHTML = contacts
    .map((c) => {
      const value = counts.get(c.nickname) > 1 ? c.fingerprint : c.nickname;
      const label = `${c.nickname} · ${c.fingerprint}${c.online ? " · here now" : ""}`;
      return `<option value="${escapeHtml(value)}" label="${escapeHtml(label)}"></option>`;
    })
    .join("");
}

/* ------------------------------------------------------------ activity ---- */

function rate(bytesPerSecond) {
  return `${fileSize(bytesPerSecond)}/s`;
}

let modeRequestInFlight = false;

function renderActivity(activity, status, peers) {
  text("act-uptime", `online ${duration(status.uptime_secs)}`);

  // There is no "the network" to have an uptime; a hub is the nearest thing
  // to a place, so say how long it has been in sight.
  const hubs = peers.filter((p) => p.is_hub);
  if (status.is_hub) {
    text("act-hub", `you are the hub · up ${duration(status.uptime_secs)}`);
  } else if (hubs.length) {
    const oldest = hubs.reduce((a, b) => (a.first_seen <= b.first_seen ? a : b));
    text(
      "act-hub",
      `${oldest.hub_name || oldest.nickname} · in sight ${duration(Math.max(0, status.now - oldest.first_seen))}`,
    );
  } else {
    text("act-hub", "no hub in range");
  }

  text("act-latency", activity.latency_ms == null ? "nothing sent yet" : `${activity.latency_ms} ms`);
  text(
    "act-speed",
    activity.throughput_bps == null
      ? "not measured yet — needs a transfer over 32KB"
      : rate(activity.throughput_bps),
  );
  text("act-out", fileSize(activity.bytes_out));
  text("act-in", fileSize(activity.bytes_in));
  text(
    "act-last",
    activity.last_exchange_at
      ? `${relativeTime(Math.max(0, status.now - activity.last_exchange_at))}${
          activity.failures ? ` · ${activity.failures} failed` : ""
        }`
      : "—",
  );

  const modes = [status.hidden && "hidden", status.low_data && "low data"].filter(Boolean);
  text("activity-meta", modes.join(" · "));

  // Leave the boxes alone while a change is on its way, or the refresh would
  // flick them back to the old answer.
  if (!modeRequestInFlight) {
    document.getElementById("toggle-hidden").checked = status.hidden;
    document.getElementById("toggle-low-data").checked = status.low_data;
  }
  document.getElementById("hidden-note").hidden = !status.hidden;
}

async function setMode(path, body) {
  const result = document.getElementById("mode-result");
  modeRequestInFlight = true;
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    result.textContent = await response.text();
  } catch (err) {
    result.textContent = "the node did not answer";
  } finally {
    modeRequestInFlight = false;
  }
  await refresh();
  await refreshChannel({ force: true });
}

document.getElementById("toggle-hidden").addEventListener("change", (event) =>
  setMode("/api/hidden", { hidden: event.target.checked }),
);
document.getElementById("toggle-low-data").addEventListener("change", (event) =>
  setMode("/api/low-data", { low_data: event.target.checked }),
);

/* -------------------------------------------------------- where you are ---- */

document.getElementById("header-channel").addEventListener("change", async (event) => {
  selectedChannelId = event.target.value || null;
  steppedOut = !selectedChannelId;
  viewNetId = null; // follow the channel's net
  await refresh();
  await refreshChannel({ force: true });
});

/* -------------------------------------------------------- your picture ---- */

/// Changing your picture needs the node; with it unreachable the upload would
/// fail half way, so the control says so instead of offering it.
function renderAvatarControls() {
  const input = document.getElementById("avatar-upload");
  const reset = document.getElementById("avatar-reset");
  const result = document.getElementById("avatar-result");
  input.disabled = !nodeReachable;
  reset.disabled = !nodeReachable;
  if (!nodeReachable) {
    result.textContent = "The node is not answering, so the picture cannot change right now.";
    result.dataset.stale = "1";
  } else if (result.dataset.stale) {
    result.textContent = "";
    delete result.dataset.stale;
  }
}

const MAX_AVATAR_BYTES = 512 * 1024;

document.getElementById("avatar-upload").addEventListener("change", async (event) => {
  const result = document.getElementById("avatar-result");
  const file = event.target.files && event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (file.size > MAX_AVATAR_BYTES) {
    result.textContent = `That picture is ${fileSize(file.size)}; every neighbor downloads it, so keep it under 512 KB.`;
    return;
  }
  result.textContent = "Uploading…";
  try {
    const response = await fetch("/api/avatar", { method: "POST", body: file });
    result.textContent = await response.text();
    // Ask for the new one rather than the cached old one.
    document.getElementById("me-icon").src = `/avatar?${Date.now()}`;
  } catch (err) {
    result.textContent = "The node did not answer.";
  }
});

document.getElementById("avatar-reset").addEventListener("click", async () => {
  const result = document.getElementById("avatar-result");
  try {
    const response = await fetch("/api/avatar", { method: "DELETE" });
    result.textContent = await response.text();
    document.getElementById("me-icon").src = `/avatar?${Date.now()}`;
  } catch (err) {
    result.textContent = "The node did not answer.";
  }
});

/* --------------------------------------------------------- attachments ---- */

/* The bytes stay on this node until somebody fetches them, and in a channel
   every neighbor fetches separately -- so the cost is shown before sending,
   not discovered after. */

const LARGE_FOR_A_CHANNEL = 1024 * 1024;
// A deliberately modest guess for when nothing has been measured yet.
const ASSUMED_BPS = 2 * 1024 * 1024;

async function loadSharedFiles() {
  try {
    sharedFiles = await getJson("/api/files");
  } catch (err) {
    sharedFiles = [];
  }
  for (const which of ["say", "compose"]) {
    const select = document.getElementById(`${which}-file`);
    const chosen = select.value;
    select.innerHTML =
      '<option value="">— no file —</option>' +
      sharedFiles
        .map((f) => `<option value="${escapeHtml(f.path)}">${escapeHtml(f.path)} (${escapeHtml(fileSize(f.size))})</option>`)
        .join("");
    select.value = chosen;
  }
}

function describeCost(which, path) {
  const file = sharedFiles.find((f) => f.path === path);
  if (!file) return { text: "", large: false };
  const measured = lastActivity && lastActivity.throughput_bps;
  const bps = measured || ASSUMED_BPS;
  const seconds = Math.max(1, Math.round(file.size / bps));
  const basis = measured ? "at the speed this node has measured" : "on ordinary wifi (nothing measured yet)";
  const fetchers = which === "say" ? lastPeers.length : 1;
  const large = which === "say" && file.size > LARGE_FOR_A_CHANNEL;
  let text = `${fileSize(file.size)} — about ${duration(seconds)} per download ${basis}.`;
  if (which === "say") {
    text += ` Each of the ${fetchers} neighbor(s) in range fetches it from you separately`;
    text += fetchers > 1 ? `, up to ${fileSize(file.size * fetchers)} in all.` : ".";
  }
  if (large) text += " That is large for a channel; consider mail instead.";
  return { text, large };
}

function showCost(which) {
  const note = document.getElementById(`${which}-cost`);
  const { text: words, large } = describeCost(which, document.getElementById(`${which}-file`).value);
  note.textContent = words;
  note.classList.toggle("cost-warning", large);
}

function confirmCost(which, path) {
  const { text: words, large } = describeCost(which, path);
  return !large || window.confirm(`${words}\n\nSend it anyway?`);
}

function clearAttachment(which) {
  document.getElementById(`${which}-file`).value = "";
  showCost(which);
}

/// Attachments are unavailable in low data mode, and in private channels,
/// whose members would be reading about a file the whole network can fetch.
function renderAttachAvailability() {
  const reasons = {
    say: lowData()
      ? "Low data mode is on, so nothing is attached."
      : channelLowData()
        ? `${netName(selectedChannel.net_id)}'s leader has made low data mandatory, so nothing is attached here.`
      : selectedChannel && selectedChannel.is_private
        ? "Private channels cannot carry files: your shared folder is public, so anyone could fetch it."
        : "",
    compose: lowData() ? "Low data mode is on, so nothing is attached." : "",
  };
  for (const which of ["say", "compose"]) {
    const box = document.getElementById(`${which}-attach`);
    const note = document.getElementById(`${which}-cost`);
    const reason = reasons[which];
    box.querySelectorAll("select, input").forEach((el) => (el.disabled = Boolean(reason)));
    if (reason) {
      document.getElementById(`${which}-file`).value = "";
      note.textContent = reason;
      note.classList.remove("cost-warning");
      box.dataset.blocked = "1";
    } else if (box.dataset.blocked) {
      // Just unblocked: replace the reason with the real cost, if any.
      delete box.dataset.blocked;
      showCost(which);
    }
  }
}

for (const which of ["say", "compose"]) {
  document.getElementById(`${which}-file`).addEventListener("change", () => showCost(which));
  document.getElementById(`${which}-attach`).addEventListener("toggle", (event) => {
    if (event.target.open) loadSharedFiles().then(() => showCost(which));
  });
  document.getElementById(`${which}-upload`).addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (!file) return;
    const note = document.getElementById(`${which}-cost`);
    if (file.size > MAX_SITE_BYTES) {
      note.textContent = `${file.name} is ${fileSize(file.size)}; copy files that big into the vault's files/ folder directly.`;
      return;
    }
    note.textContent = `Sharing ${file.name}…`;
    try {
      const response = await fetch(`/api/files/${encodeURIComponent(file.name)}`, {
        method: "POST",
        body: file,
      });
      if (!response.ok) {
        note.textContent = await response.text();
        return;
      }
      await loadSharedFiles();
      document.getElementById(`${which}-file`).value = file.name;
      showCost(which);
    } catch (err) {
      note.textContent = "The node did not answer.";
    }
  });
}

document.addEventListener("click", (event) => {
  const write = event.target.closest("[data-write]");
  if (!write) return;
  const to = document.getElementById("compose-to");
  // The fingerprint, not the name: unambiguous even if two people share it.
  to.value = write.dataset.write;
  document.getElementById("compose-subject").focus();
  to.scrollIntoView({ block: "center", behavior: "smooth" });
});

/* -------------------------------------------------------------- preview ---- */

let previewTimer = null;

function renderPreview() {
  const frame = document.getElementById("site-preview");
  if (frame.hidden) return;
  const nickname = (lastStatus && lastStatus.nickname) || "";
  // Relative links and pictures resolve against the published folder, as
  // they will for a neighbor.
  const base = `<base href="/~${encodeURIComponent(nickname)}/">`;
  frame.srcdoc = base + document.getElementById("site-html").value;
}

document.getElementById("preview-site").addEventListener("click", (event) => {
  const frame = document.getElementById("site-preview");
  frame.hidden = !frame.hidden;
  event.target.setAttribute("aria-expanded", String(!frame.hidden));
  event.target.textContent = frame.hidden ? "Preview" : "Hide preview";
  renderPreview();
});

document.getElementById("site-html").addEventListener("input", () => {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(renderPreview, 300);
});

/* ------------------------------------------------------ folding modules ---- */

/* Every module heading becomes a button that folds its panel. Which are
   folded is remembered in this browser only -- it is how you like your
   dashboard, not something the node needs to know. */

const FOLDED_KEY = "intraweb.folded";

function readFolded() {
  try {
    return new Set(JSON.parse(localStorage.getItem(FOLDED_KEY) || "[]"));
  } catch (err) {
    return new Set();
  }
}

function writeFolded(folded) {
  try {
    localStorage.setItem(FOLDED_KEY, JSON.stringify([...folded]));
  } catch (err) {
    // Private windows refuse storage; folding still works for the visit.
  }
}

function makeFoldable() {
  const folded = readFolded();
  document.querySelectorAll(".module").forEach((module) => {
    const head = module.querySelector(".module-head");
    const body = module.querySelector(".module-body");
    if (!head || !body || head.querySelector(".fold")) return;

    const id = head.id;
    body.id = body.id || `${id}-body`;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "fold";
    button.setAttribute("aria-controls", body.id);
    // Everything but the counts goes inside the button, so the counts stay
    // visible on a folded panel.
    [...head.childNodes]
      .filter((node) => !(node.classList && node.classList.contains("module-meta")))
      .forEach((node) => button.appendChild(node));
    head.prepend(button);

    const apply = (isFolded) => {
      module.classList.toggle("folded", isFolded);
      button.setAttribute("aria-expanded", String(!isFolded));
    };
    apply(folded.has(id));
    button.addEventListener("click", () => {
      const nowFolded = !module.classList.contains("folded");
      apply(nowFolded);
      if (nowFolded) folded.add(id);
      else folded.delete(id);
      writeFolded(folded);
    });
  });
}

/* ---------------------------------------------------------------- nets ---- */

/* A net's state is folded on the node from its signed log; the page only
   shows it and posts what the operator decides. Every refusal comes back from
   the node in words, and is shown as it came. */

async function refreshNets() {
  try {
    netsList = await getJson("/api/nets");
  } catch (err) {
    netsList = [];
  }
  const joined = netsList.filter((n) => n.joined);
  const details = await Promise.all(
    joined.map((n) => getJson(`/api/nets/${n.net_id}`).catch(() => null)),
  );
  netDetails = new Map();
  joined.forEach((n, i) => {
    if (details[i]) netDetails.set(n.net_id, details[i]);
  });
  if (viewNetId && !netsList.some((n) => n.net_id === viewNetId)) viewNetId = null;
  renderNetDirectory();
  renderChannelNetChoices();
  notifyPings();
}

/// A key as a person, using the net's own names first: members of a net you
/// joined today may never have crossed your roster.
function memberName(hex, names) {
  const known = lastPeers.some((p) => p.peer_id === hex) || contactsByKey.has(hex);
  if (known || (lastStatus && hex === lastStatus.peer_id)) return whoIs(hex);
  const fp = contactsByKey.get(hex)?.fingerprint || hex;
  return names && names[hex]
    ? `${escapeHtml(names[hex])} <span class="fp-tag">${escapeHtml(fp.slice(0, 4))}</span>`
    : escapeHtml(hex.slice(0, 9));
}

function renderNetDirectory() {
  text(
    "nets-meta",
    netsList.length
      ? `${netsList.filter((n) => n.joined).length} joined of ${netsList.length}`
      : "none yet",
  );
  document.getElementById("net-directory").innerHTML = netsList.length
    ? netsList
        .map((n) => {
          const meta = n.joined
            ? `${n.members} member${n.members === 1 ? "" : "s"}${n.you_lead ? " · you lead" : ""}${
                n.low_data_mandatory ? " · low data" : ""
              }`
            : `started by ${whoIs(n.founder)}`;
          const actions = n.joined
            ? `<button type="button" class="quiet" data-net-view="${escapeHtml(n.net_id)}">Open</button>
               <button type="button" class="quiet danger" data-net-leave="${escapeHtml(n.net_id)}">Leave</button>`
            : `<button type="button" data-net-join="${escapeHtml(n.net_id)}">Join</button>`;
          return `<div class="net-row ${n.net_id === viewNetId ? "viewing" : ""}">
            <span class="name">${escapeHtml(n.name)}</span>
            <span class="meta">${n.joined ? escapeHtml(meta) : meta}</span>
            ${actions}
          </div>`;
        })
        .join("")
    : '<p class="empty">No nets in range yet. Start one, and neighbors can find and join it.</p>';
}

function renderChannelNetChoices() {
  const select = document.getElementById("new-channel-net");
  const chosen = select.value;
  select.innerHTML =
    '<option value="">no net</option>' +
    netsList
      .filter((n) => n.joined)
      .map((n) => `<option value="${escapeHtml(n.net_id)}">in ${escapeHtml(n.name)}</option>`)
      .join("");
  select.value = chosen;
}

let netModeInFlight = false;

function renderNetDetail() {
  // Following the channel you are in, unless you opened another net yourself.
  if (!viewNetId && selectedChannel && selectedChannel.net_id) viewNetId = selectedChannel.net_id;
  const detail = viewNetId ? netDetails.get(viewNetId) : null;
  const box = document.getElementById("net-detail");
  box.hidden = !detail;
  renderFooterLeader();
  if (!detail) return;

  const { net, names } = detail;
  const me = lastStatus.peer_id;
  const short = me.slice(0, 16);
  const isMember = net.members.some((m) => m.peer_id === me);
  const iLead = net.leader === me;

  text("net-title", net.name || netName(viewNetId));
  document.getElementById("net-leader").innerHTML = net.leader
    ? `Net leader: ${memberName(net.leader, names)}${
        net.low_data_mandatory ? ' · <strong>low data is mandatory</strong>' : ""
      }`
    : "Nobody leads this net right now.";

  // Announcements: newest first, always signed off as the leader's.
  const recent = net.announcements.slice(-5).reverse();
  document.getElementById("net-announcements").innerHTML = recent
    .map(
      (a) => `<div class="announcement">${a.ping ? "&#128276; " : ""}${escapeHtml(a.text)}
        <span class="by">${memberName(a.from, names)} <span class="badge-leader">net leader</span>
          &middot; ${escapeHtml(clock(a.at))}</span></div>`,
    )
    .join("");

  const open = net.motions.filter((m) => m.status === "open");
  const closed = net.motions.filter((m) => m.status !== "open").slice(-3).reverse();
  const canImpeach =
    isMember && net.leader && !iLead && !open.some((m) => m.kind === "impeach");
  document.getElementById("net-motions").innerHTML =
    open
      .map((m) => {
        const mine = m.votes.find(([who]) => who === me);
        const eligible = m.eligible_keys.includes(short);
        const what = m.kind === "impeach" ? `Impeach ${memberName(m.target, names)}` : `Remove ${memberName(m.target, names)}`;
        const left = Math.max(0, m.closes_at - lastStatus.now);
        return `<div class="motion open">
          <strong>${what}</strong>
          <div class="tally">${m.yes} yes &middot; ${m.no} no &middot; ${m.eligible} can vote, ${
            Math.floor(m.eligible / 2) + 1
          } carries it &middot; closes in ${escapeHtml(duration(left))}${
            mine ? ` &middot; you voted ${mine[1] ? "yes" : "no"}` : ""
          }</div>
          ${
            eligible
              ? `<div class="actions">
                  <button type="button" data-net-vote="${escapeHtml(m.id)}" data-yes="1">Yes</button>
                  <button type="button" class="quiet" data-net-vote="${escapeHtml(m.id)}" data-yes="0">No</button>
                </div>`
              : '<div class="tally">You joined after this vote opened, so it is not yours to decide.</div>'
          }
        </div>`;
      })
      .join("") +
    closed
      .map(
        (m) => `<div class="motion"><strong>${
          m.kind === "impeach" ? "Impeach" : "Remove"
        } ${memberName(m.target, names)}</strong>
          <div class="tally">${escapeHtml(m.outcome || m.status)}</div></div>`,
      )
      .join("") +
    (canImpeach
      ? `<button type="button" class="quiet" data-net-impeach="${escapeHtml(net.leader)}">Move to impeach the leader</button>`
      : "");

  document.getElementById("net-members").innerHTML = net.members
    .map(
      (m, i) => `<div class="member">
        ${memberName(m.peer_id, names)}${m.peer_id === net.leader ? '<span class="badge-leader">net leader</span>' : ""}
        <span class="since">${i === 0 ? "here longest · " : ""}joined ${escapeHtml(clock(m.joined_at))}</span>
        ${
          iLead && m.peer_id !== me && !open.some((o) => o.kind === "kick" && o.target === m.peer_id)
            ? `<button type="button" class="quiet danger" data-net-kick="${escapeHtml(m.peer_id)}">Call vote to remove</button>`
            : ""
        }
      </div>`,
    )
    .join("");

  document.getElementById("net-leader-tools").hidden = !iLead;
  if (!netModeInFlight) document.getElementById("net-low-data").checked = net.low_data_mandatory;

  document.getElementById("net-history").innerHTML = net.history
    .slice(-10)
    .reverse()
    .map((h) => `<div>${escapeHtml(clock(h.at))} &mdash; ${escapeHtml(h.text)}</div>`)
    .join("");
}

/// "net leader" at the bottom of the page, for the net you are in.
function renderFooterLeader() {
  const id = (selectedChannel && selectedChannel.net_id) || viewNetId;
  const detail = id ? netDetails.get(id) : null;
  document.getElementById("footer-leader").innerHTML =
    detail && detail.net.leader
      ? `net leader of ${escapeHtml(detail.net.name || "this net")}: ${memberName(detail.net.leader, detail.names)}`
      : "";
}

async function netAction(path, body) {
  const result = document.getElementById("net-result");
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const words = await response.text();
    result.textContent = words;
    return response.ok ? words : null;
  } catch (err) {
    result.textContent = "The node did not answer.";
    return null;
  } finally {
    await refresh();
  }
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest(
    "[data-net-join],[data-net-leave],[data-net-view],[data-net-vote],[data-net-impeach],[data-net-kick]",
  );
  if (!target) return;
  const d = target.dataset;
  target.disabled = true;

  if (d.netJoin) {
    viewNetId = d.netJoin;
    await netAction(`/api/nets/${d.netJoin}/join`);
  } else if (d.netLeave) {
    if (!window.confirm(`Leave ${netName(d.netLeave)}? What was said there is kept.`)) {
      target.disabled = false;
      return;
    }
    if (viewNetId === d.netLeave) viewNetId = null;
    await netAction(`/api/nets/${d.netLeave}/leave`);
  } else if (d.netView) {
    viewNetId = d.netView;
    renderNetDirectory();
    renderNetDetail();
  } else if (d.netVote) {
    await netAction(`/api/nets/${viewNetId}/vote`, { motion: d.netVote, yes: d.yes === "1" });
  } else if (d.netImpeach) {
    if (window.confirm("Open a vote to impeach the leader? A majority of members picks a new one at random.")) {
      await netAction(`/api/nets/${viewNetId}/motion`, { kind: "impeach", target: d.netImpeach });
    }
  } else if (d.netKick) {
    if (window.confirm("Call a vote to remove this member? The members decide; a majority removes them.")) {
      await netAction(`/api/nets/${viewNetId}/motion`, { kind: "kick", target: d.netKick });
    }
  }
  target.disabled = false;
});

document.getElementById("new-net-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("new-net-name");
  const created = await netAction("/api/nets/new", { name: input.value });
  if (created) {
    viewNetId = created.trim();
    input.value = "";
    await refresh();
  }
});

document.getElementById("announce-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("announce-text");
  if (!input.value.trim() || !viewNetId) return;
  const ping = document.getElementById("announce-ping");
  if (await netAction(`/api/nets/${viewNetId}/announce`, { text: input.value, ping: ping.checked })) {
    input.value = "";
    ping.checked = false;
  }
});

document.getElementById("net-low-data").addEventListener("change", async (event) => {
  if (!viewNetId) return;
  netModeInFlight = true;
  try {
    await netAction(`/api/nets/${viewNetId}/policy`, { low_data_mandatory: event.target.checked });
  } finally {
    netModeInFlight = false;
  }
});

/* ---------------------------------------------------------------- pings ---- */

/* A ping is shown once per browser until dismissed, and only if it is recent:
   opening the dashboard a week later should not set off last week's alarms. */

const SEEN_PINGS_KEY = "intraweb.seenPings";
const PING_FRESH_SECS = 60 * 60;
let shownPing = null;

function seenPings() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SEEN_PINGS_KEY) || "[]"));
  } catch (err) {
    return new Set();
  }
}

function markPingSeen(id) {
  try {
    const seen = [...seenPings(), id].slice(-200);
    localStorage.setItem(SEEN_PINGS_KEY, JSON.stringify(seen));
  } catch (err) {
    // Without storage the banner still works; it just may show again.
  }
}

function notifyPings() {
  if (!lastStatus || shownPing) return;
  const seen = seenPings();
  for (const [netId, detail] of netDetails) {
    for (const a of detail.net.announcements) {
      if (!a.ping || lastStatus.now - a.at > PING_FRESH_SECS) continue;
      const id = `${netId}:${a.at}:${a.from.slice(0, 16)}`;
      if (seen.has(id)) continue;
      shownPing = { id, title: document.title };
      const words = `${detail.net.name || "A net"} — net leader: ${a.text}`;
      document.getElementById("ping-text").textContent = `\u{1F514} ${words}`;
      document.getElementById("ping-banner").hidden = false;
      document.title = `\u{1F514} ${shownPing.title}`;
      try {
        if (window.Notification && Notification.permission === "granted") {
          new Notification(detail.net.name || "intraweb", { body: a.text });
        }
      } catch (err) {
        // Some browsers refuse notifications from plain http; the banner stays.
      }
      return;
    }
  }
}

document.getElementById("ping-dismiss").addEventListener("click", () => {
  if (!shownPing) return;
  markPingSeen(shownPing.id);
  document.title = shownPing.title;
  shownPing = null;
  document.getElementById("ping-banner").hidden = true;
  notifyPings();
});

document.getElementById("enable-notifications").addEventListener("click", async (event) => {
  if (!window.Notification) {
    event.target.textContent = "This browser cannot show notifications";
    return;
  }
  const answer = await Notification.requestPermission();
  event.target.textContent =
    answer === "granted" ? "Pings will show as notifications" : "Notifications were not allowed";
});

makeFoldable();
loadSharedFiles();

refresh();
loadSite();
setInterval(refresh, REFRESH_MS);
