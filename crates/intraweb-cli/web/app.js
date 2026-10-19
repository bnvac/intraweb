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
           src="${host ? `http://${host}:${peer.api_port}/avatar` : `/identicon/${escapeHtml(peer.peer_id)}.svg`}"
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
    </article>`;
}

// Which channel the reader is looking at. Kept here so a refresh does not
// yank them back to the neighborhood mid-conversation.
let selectedChannelId = null;
let selectedChannel = null;

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
}

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
          <div class="from">${escapeHtml(message.peer_id.slice(0, 16))}&hellip;
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
  // just be the same thing twice.
  const channels = allChannels.filter((c) => c.channel_id !== status.guestbook_channel);

  if (!selectedChannelId && channels.length) {
    const neighborhood = channels.find((c) => !c.is_private) || channels[0];
    selectedChannelId = neighborhood.channel_id;
  }
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
        ${channel.is_private ? "&#9679; " : ""}${escapeHtml(channel.name)}
      </button>`,
    )
    .join("");

  document.getElementById("channel-meta").textContent = selectedChannel
    ? selectedChannel.is_private
      ? "private \u00b7 members only"
      : "everyone in range"
    : "";
}

function renderPosts(posts) {
  document.getElementById("channel-posts").innerHTML = posts.length
    ? posts
        .map(
          (post) => `
        <div class="post ${post.readable ? "" : "sealed"}">
          <span class="who">${escapeHtml(post.fingerprint.slice(0, 9))}</span>
          <span class="said">${
            post.readable
              ? escapeHtml(post.body)
              : "encrypted &mdash; you are not in this channel"
          }</span>
        </div>`,
        )
        .join("")
    : '<p class="empty">Nothing said here yet.</p>';
}

async function refreshChannel() {
  if (!selectedChannelId) return;
  try {
    renderPosts(await getJson(`/api/channels/${selectedChannelId}/posts`));
    const box = document.getElementById("channel-posts");
    box.scrollTop = box.scrollHeight;
  } catch (err) {
    renderPosts([]);
  }
}

async function refresh() {
  try {
    // One request: status, roster and mail are always rendered together.
    const state = await getJson("/api/state");
    renderMe(state.status);
    renderRosters(state.peers, state.status);
    renderMail(state.mail, state.status.now, state.peers);
    renderChannels(await getJson("/api/channels"), state.status);
    renderGuestbook(await getJson("/api/guestbook"));
    await refreshChannel();
  } catch (err) {
    document.querySelector(".presence").classList.remove("live");
    text("presence-text", "node unreachable");
  }
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
    await refresh();
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
  if (!input.value.trim() || !selectedChannelId) return;

  const response = await fetch(`/api/channels/${selectedChannelId}/say`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body: input.value }),
  });
  document.getElementById("say-result").textContent = await response.text();
  if (response.ok) {
    input.value = "";
    await refreshChannel();
  }
});

document.getElementById("new-channel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = document.getElementById("new-channel-name");
  const response = await fetch("/api/channels/new", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: name.value }),
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
  };

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

refresh();
loadSite();
setInterval(refresh, REFRESH_MS);
