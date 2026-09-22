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
  return out.join(" ");
}

function neighborCard(peer, rank, now) {
  const alarming = peer.trust === "nickname_conflict";
  const classes = ["neighbor"];
  if (peer.is_hub) classes.push("is-hub");
  if (alarming) classes.push("is-alarming");

  const host = peerAddress(peer);
  const siteUrl = host
    ? `http://${host}:${peer.api_port}/~${encodeURIComponent(peer.nickname)}`
    : null;

  // A name clash is the one thing worth interrupting someone over: a familiar
  // label arriving on a key we have never seen before.
  const alarm = alarming
    ? `<div class="alarm"><strong>Not the ${escapeHtml(peer.nickname)} you met before.</strong>
       Same name, different key &mdash; compare fingerprints in person.</div>`
    : "";

  return `
    <article class="${classes.join(" ")}">
      <span class="rank">${rank}</span>
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
      </div>
    </article>`;
}

function renderMe(status) {
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

function renderMail(messages, now) {
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

async function refresh() {
  try {
    // One request: status, roster and mail are always rendered together.
    const state = await getJson("/api/state");
    renderMe(state.status);
    renderRosters(state.peers, state.status);
    renderMail(state.mail, state.status.now);
  } catch (err) {
    document.querySelector(".presence").classList.remove("live");
    text("presence-text", "node unreachable");
  }
}

document.addEventListener("click", async (event) => {
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

refresh();
setInterval(refresh, REFRESH_MS);
