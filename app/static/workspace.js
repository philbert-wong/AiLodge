"use strict";

// A team's private workspace. Every request carries the session cookie (set at
// log-in) plus a custom header the server requires, which blocks cross-site forgery.

const $ = (sel) => document.querySelector(sel);
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Agents and providers control some of what appears here (agent names, prompt
// previews), so everything from the server is escaped before it's shown.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
const money = (n) => "$" + Number(n || 0).toFixed(2);
const smallMoney = (n) => (n > 0 && n < 0.01 ? `$${Number(n).toFixed(5)}` : money(n));
const timeOf = (ms) =>
  new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const short = (h) => (h ? h.slice(0, 10) + "…" : "");

function duration(minutes) {
  if (minutes >= 1440) {
    const d = Math.round(minutes / 1440);
    return `${d} ${d === 1 ? "day" : "days"}`;
  }
  if (minutes >= 60) {
    const h = Math.round(minutes / 60);
    return `${h} ${h === 1 ? "hour" : "hours"}`;
  }
  return `${minutes} min`;
}

function endsIn(seconds) {
  if (seconds <= 0) return "Ended";
  if (seconds >= 2 * 86400) return `in ${Math.round(seconds / 86400)} days`;
  if (seconds >= 2 * 3600) return `in ${Math.round(seconds / 3600)} hours`;
  return `in ${Math.max(1, Math.round(seconds / 60))} min`;
}

const state = { keys: [], tokens: [], pass: null, verify: null, seen: new Set(), pollTimer: null };

async function api(path, options = {}) {
  const res = await fetch("/api/ws" + path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-Leash-App": "1", ...(options.headers || {}) },
  });
  if (res.status === 401) {
    window.location.assign("/login");
    throw new Error("Please log in again.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`);
  return data;
}

async function accountApi(path, method = "GET") {
  const res = await fetch("/api/account" + path, { method, headers: { "X-Leash-App": "1" } });
  if (res.status === 401) {
    window.location.assign("/login");
    throw new Error("Please log in again.");
  }
  return res.json().catch(() => ({}));
}

function message(el, text, tone) {
  el.textContent = text || "";
  el.className = "form-msg" + (tone ? " " + tone : "");
}

function banner(text) {
  const el = $("#ws-banner");
  el.textContent = text;
  el.hidden = !text;
}

// ---------------------------------------------------------------------------
// Setup checklist
// ---------------------------------------------------------------------------
function renderSetup(setup) {
  const done = { key: setup.keys > 0, agent: setup.agents > 0, alerts: setup.alerts };
  let count = 0;
  for (const [name, ok] of Object.entries(done)) {
    $(`#setup-${name}`).classList.toggle("done", ok);
    if (ok) count += 1;
  }
  $("#setup-progress").textContent = count === 3 ? "All set. Your agents are on a leash." : `${count} of 3 done`;
  $("#setup").classList.toggle("complete", count === 3);
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------
function hostOf(url) {
  try { return new URL(url).host; } catch { return url; }
}

function renderKeys(list) {
  state.keys = list;
  // Don't redraw an unchanged list: that would close open details and clear test results.
  const json = JSON.stringify(list);
  if (json === state.keysJson) return;
  state.keysJson = json;
  const ul = $("#keys");
  if (!list.length) {
    ul.innerHTML = '<li class="empty">No keys saved yet.</li>';
  } else {
    ul.innerHTML = list
      .map((k) => {
        const tampered = k.status === "tampered";
        return `<li class="key${tampered ? " tampered" : ""}" data-id="${esc(k.id)}">
          <div class="key-top">
            <span class="key-name">${esc(k.name)}</span>
            <span class="key-meta">${esc(k.model)} at ${esc(hostOf(k.base_url))} · key <code>${esc(k.key_hint)}</code></span>
          </div>
          ${tampered ? '<p class="key-warn">This saved key was changed in the database, so Leash refuses to use it. Remove it and save the key again.</p>' : ""}
          <details>
            <summary>What Leash stored</summary>
            <dl class="stored">
              <dt>Encryption</dt><dd>${esc(k.stored.algorithm)}</dd>
              <dt>Saved as</dt><dd><code>${esc(k.stored.ciphertext)}</code></dd>
              <dt>Locked with</dt><dd>${esc(k.stored.master_key_location)}</dd>
            </dl>
          </details>
          <div class="key-actions">
            ${tampered ? "" : '<button class="btn" data-act="test" type="button">Test it</button>'}
            <button class="btn btn-danger" data-act="remove" type="button">Remove</button>
          </div>
          <p class="key-result"></p>
        </li>`;
      })
      .join("");
  }
  syncAgentOptions();
  state.run?.refreshChoices();
}

$("#keys").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const li = btn.closest("li");
  const id = li.dataset.id;
  const out = li.querySelector(".key-result");
  btn.disabled = true;
  try {
    if (btn.dataset.act === "test") {
      out.className = "key-result";
      out.textContent = "Sending one short message through Leash…";
      const r = await api(`/connections/${encodeURIComponent(id)}/test`, { method: "POST" });
      out.className = "key-result " + (r.ok ? "good" : "bad");
      out.textContent = r.ok ? `It works. The AI replied: “${r.reply}”` : `It didn't work: ${r.reply}`;
    } else {
      const name = li.querySelector(".key-name").textContent;
      if (!window.confirm(`Remove “${name}”? Leash erases the encrypted key, and every pass that uses it stops working.`)) return;
      await api(`/connections/${encodeURIComponent(id)}/remove`, { method: "POST" });
      await refresh();
    }
  } catch (err) {
    out.className = "key-result bad";
    out.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

$("#key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const msg = $("#key-msg");
  message(msg, "Encrypting and saving…");
  try {
    const saved = await api("/connections", {
      method: "POST",
      body: JSON.stringify({
        name: f.elements.name.value.trim(),
        model: f.elements.model.value.trim(),
        base_url: f.elements.base_url.value.trim(),
        api_key: f.elements.api_key.value.trim(),
      }),
    });
    f.elements.api_key.value = "";
    f.elements.name.value = "";
    message(msg, `Saved “${saved.name}”, encrypted. Press “Test it” to check it works.`, "good");
    await refresh();
    $("#agent-form").elements.upstream.value = saved.id;
  } catch (err) {
    message(msg, err.message, "bad");
  }
});

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
function syncAgentOptions() {
  const select = $("#agent-form").elements.upstream;
  const previous = select.value;
  const usable = state.keys.filter((k) => k.status === "active");
  select.innerHTML =
    usable.map((k) => `<option value="${esc(k.id)}">${esc(k.name)} (${esc(k.model)})</option>`).join("") +
    '<option value="fake">Practice AI (free; fake replies, pretend $0.05 a call)</option>';
  if ([...select.options].some((o) => o.value === previous)) select.value = previous;
}

function modelFor(upstream) {
  const k = state.keys.find((x) => x.id === upstream);
  return k ? k.model : "practice-model";
}

function renderAgents(list) {
  state.tokens = list;
  const rows = list.filter((t) => t.agent !== "key-test");
  const body = $("#agents-body");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No agents yet. Create a pass above.</td></tr>';
    return;
  }
  const pill = {
    active: ["Working", "pill-active"],
    revoked: ["Stopped", "pill-stopped"],
    expired: ["Ended", "pill-done"],
    "call limit": ["Call limit reached", "pill-stopped"],
    "budget spent": ["Money limit reached", "pill-stopped"],
  };
  body.innerHTML = rows
    .map((t) => {
      const [label, cls] = pill[t.status] || [t.status, "pill-done"];
      const canStop = t.status !== "revoked" && t.status !== "expired";
      return `<tr>
        <td><strong>${esc(t.agent)}</strong></td>
        <td>${esc(t.upstream_label || t.upstream)}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td>
        <td>${t.calls_used} / ${t.max_calls}</td>
        <td>${smallMoney(t.spent_usd)} / ${smallMoney(t.budget_usd)}</td>
        <td>${t.status === "revoked" ? "Stopped" : endsIn(t.expires_in_s)}</td>
        <td>${canStop ? `<button class="btn btn-danger btn-small" data-jti="${esc(t.jti)}" data-agent="${esc(t.agent)}" type="button">Stop</button>` : ""}</td>
      </tr>`;
    })
    .join("");
}

$("#agents-body").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-jti]");
  if (!btn) return;
  btn.disabled = true;
  try {
    await api(`/tokens/${encodeURIComponent(btn.dataset.jti)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason: "Stopped from the workspace" }),
    });
    await refresh();
  } catch (err) {
    banner(err.message);
    btn.disabled = false;
  }
});

$("#agent-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const msg = $("#agent-msg");
  message(msg, "");
  const upstream = f.elements.upstream.value;
  try {
    const issued = await api("/tokens", {
      method: "POST",
      body: JSON.stringify({
        agent: f.elements.agent.value.trim(),
        upstream,
        budget_usd: Number(f.elements.budget_usd.value),
        max_calls: Math.round(Number(f.elements.max_calls.value)),
        ttl_minutes: Number(f.elements.ttl_minutes.value),
      }),
    });
    state.pass = { token: issued.token, agent: issued.claims.agent, model: modelFor(upstream) };
    showPass();
    f.elements.agent.value = "";
    await refresh();
  } catch (err) {
    message(msg, err.message, "bad");
  }
});

function showPass() {
  const p = state.pass;
  $("#pass-agent").textContent = p.agent;
  $("#pass-token").textContent = p.token;
  $("#pass-code").textContent = `from openai import OpenAI

client = OpenAI(
    base_url="${location.origin}/v1",
    api_key="${p.token}",  # this agent's pass, not your key
)

client.chat.completions.create(
    model="${p.model}",
    messages=[{"role": "user", "content": "Hello"}],
)`;
  $("#pass-try-out").textContent = "";
  $("#pass-try-out").className = "outcome";
  $("#pass").hidden = false;
  $("#pass").scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "nearest" });
}

$("#pass-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.pass.token);
    $("#pass-copy").textContent = "Copied";
  } catch {
    const range = document.createRange();
    range.selectNodeContents($("#pass-token"));
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    $("#pass-copy").textContent = "Selected, press Ctrl+C";
  }
  setTimeout(() => { $("#pass-copy").textContent = "Copy"; }, 2000);
});

$("#pass-close").addEventListener("click", () => {
  state.pass = null; // forget the pass; Leash can't show it again either
  $("#pass").hidden = true;
  $("#pass-token").textContent = "";
  $("#pass-code").textContent = "";
});

$("#pass-try").addEventListener("click", async () => {
  const out = $("#pass-try-out");
  const btn = $("#pass-try");
  btn.disabled = true;
  out.className = "outcome";
  out.textContent = "Sending through Leash…";
  try {
    const res = await fetch("/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + state.pass.token },
      body: JSON.stringify({
        model: state.pass.model,
        messages: [{ role: "user", content: "In one short sentence, say hello and confirm you can hear me." }],
        max_tokens: 60,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      const reply = (data.choices?.[0]?.message?.content || "(empty reply)").trim();
      const calls = res.headers.get("X-Leash-Calls-Remaining");
      const left = Number(res.headers.get("X-Leash-Budget-Remaining"));
      out.className = "outcome good";
      out.innerHTML = `<strong>It works.</strong> The AI replied: “${esc(reply)}” This pass has ${esc(calls)} calls and ${esc(smallMoney(left))} left.`;
    } else {
      out.className = "outcome bad";
      out.innerHTML = `<strong>Blocked or failed.</strong> ${esc(data.error?.message || `Status ${res.status}`)}`;
    }
  } catch (err) {
    out.className = "outcome bad";
    out.textContent = err.message;
  }
  btn.disabled = false;
  refresh();
});

// ---------------------------------------------------------------------------
// Alerts (Slack or Discord)
// ---------------------------------------------------------------------------
const KIND_LABEL = {
  CANARY_TRIGGERED: "Trap key used",
  SECRET_BLOCKED: "Leak blocked",
  KILL_SWITCH: "Every agent stopped",
  KEY_INTEGRITY_FAILED: "Saved key was tampered with",
  LIMIT_REACHED: "An agent hit its limit",
  GLOBAL_BUDGET: "Global budget reached",
};

function renderAlerts(list) {
  const ul = $("#alerts");
  ul.innerHTML = list.length
    ? list
        .slice(0, 8)
        .map((a) => `<li><span class="alert-kind">${esc(KIND_LABEL[a.kind] || a.kind)}</span>${esc(a.message)} <span class="alert-time">${timeOf(a.ts_ms)}</span></li>`)
        .join("")
    : '<li class="empty">Nothing suspicious yet.</li>';
}

function renderHook(hook) {
  const service = hook.kind === "discord" ? "Discord" : "Slack";
  $("#hook-test").hidden = !hook.set;
  $("#hook-remove").hidden = !hook.set;
  $("#hook-save").textContent = hook.set ? "Replace" : "Save";
  const input = $("#hook-form").elements.url;
  input.placeholder = hook.set ? "Paste a new address to replace it" : "https://hooks.slack.com/services/…";
  const msg = $("#hook-msg");
  if (!msg.dataset.sticky) message(msg, hook.set ? `Alerts go to ${service} (${hook.hint}). The address is stored encrypted.` : "", hook.set ? "good" : "");
}

function stickyMessage(text, tone) {
  const msg = $("#hook-msg");
  message(msg, text, tone);
  msg.dataset.sticky = "1";
  setTimeout(() => { delete msg.dataset.sticky; }, 6000);
}

$("#hook-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = e.target.elements.url;
  if (!input.value.trim()) return stickyMessage("Paste your Slack or Discord webhook address first.", "bad");
  try {
    const hook = await api("/webhook", { method: "POST", body: JSON.stringify({ url: input.value.trim() }) });
    input.value = "";
    stickyMessage(`Saved. Alerts will go to ${hook.kind === "discord" ? "Discord" : "Slack"}. Press “Send a test” to check.`, "good");
    await refresh();
  } catch (err) {
    stickyMessage(err.message, "bad");
  }
});

$("#hook-test").addEventListener("click", async () => {
  $("#hook-test").disabled = true;
  try {
    const r = await api("/webhook/test", { method: "POST" });
    stickyMessage(r.ok ? "Test alert sent. Check your channel." : r.error, r.ok ? "good" : "bad");
  } catch (err) {
    stickyMessage(err.message, "bad");
  }
  $("#hook-test").disabled = false;
});

$("#hook-remove").addEventListener("click", async () => {
  try {
    await api("/webhook/remove", { method: "POST" });
    stickyMessage("Alerts turned off. The stored address was deleted.", "");
    await refresh();
  } catch (err) {
    stickyMessage(err.message, "bad");
  }
});

// ---------------------------------------------------------------------------
// Trap keys
// ---------------------------------------------------------------------------
function renderTraps(list) {
  $("#traps").innerHTML = list
    .map(
      (c) => `<li>
        <code>${esc(c.key)}</code>
        <span>Idea: ${esc(c.planted_in.charAt(0).toLowerCase() + c.planted_in.slice(1))}</span>
        <button class="btn btn-small" type="button" data-copy="${esc(c.key)}">Copy</button>
      </li>`
    )
    .join("");
}

$("#traps").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-copy]");
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    btn.textContent = "Copied";
  } catch {
    btn.textContent = "Copy failed";
  }
  setTimeout(() => { btn.textContent = "Copy"; }, 1500);
});

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------
const EVENT_LABEL = {
  LOG_STARTED: ["Log started", ""],
  ACCOUNT_CREATED: ["Workspace created", ""],
  TOKEN_ISSUED: ["Pass created", ""],
  TOKEN_REVOKED: ["Agent stopped", "block"],
  CALL_ALLOWED: ["Call allowed", "allow"],
  CALL_BLOCKED: ["Call blocked", "block"],
  CANARY_TRIGGERED: ["Trap key used", "block"],
  KILL_SWITCH_ON: ["Every agent stopped", "block"],
  KILL_SWITCH_OFF: ["Agents resumed", ""],
  UPSTREAM_ERROR: ["AI provider error", "block"],
  KEY_STORED: ["Key saved (encrypted)", ""],
  KEY_REMOVED: ["Key removed", ""],
  KEY_INTEGRITY_FAILED: ["Saved key was tampered with", "block"],
  KEYS_UPGRADED: ["Keys locked to your password", ""],
  ALERTS_CONNECTED: ["Alerts turned on", ""],
  ALERTS_DISCONNECTED: ["Alerts turned off", ""],
};

function upstreamName(id) {
  if (id === "fake") return "the practice AI";
  const k = state.keys.find((x) => x.id === id);
  return k ? `key “${k.name}”` : "a saved key";
}

function describe(entry) {
  const d = entry.detail || {};
  switch (entry.event) {
    case "ACCOUNT_CREATED":
      return `Workspace for ${d.team}`;
    case "TOKEN_ISSUED":
      return `${d.agent}: ${d.max_calls} calls, ${smallMoney(d.budget_usd)}, ends after ${duration(d.ttl_minutes)}, uses ${upstreamName(d.upstream)}${d.key_unlock ? " (only this pass can unlock the key)" : ""}`;
    case "CALL_ALLOWED":
      return `${d.agent} spent ${smallMoney(d.cost_usd)} (total ${smallMoney(d.spent_usd)}, call ${d.calls_used}). Message “${d.prompt_preview || ""}”`;
    case "CALL_BLOCKED":
      return `${d.agent ? d.agent + ": " : ""}${d.reason}`;
    case "CANARY_TRIGGERED":
      return `Trap key planted in: ${d.planted_in}`;
    case "TOKEN_REVOKED":
      return `${d.agent}: ${d.reason}`;
    case "KEY_STORED":
      return `${d.name}: key ${d.key_hint} for ${d.model}, saved encrypted${d.master_key_id === "acct-v1" ? " and locked to your password" : ""}`;
    case "KEY_REMOVED":
      return `${d.name}: erased for good`;
    case "KEYS_UPGRADED":
      return `${d.keys} saved key${d.keys === 1 ? "" : "s"} now locked with your password as well as the master key`;
    case "KEY_INTEGRITY_FAILED":
      return `${d.agent}: the saved key “${d.connection}” was changed in the database, so Leash refused to use it`;
    case "ALERTS_CONNECTED":
      return `Sending alerts to ${d.service === "discord" ? "Discord" : "Slack"}`;
    case "UPSTREAM_ERROR":
      return `${d.agent}: ${d.reason}`;
    default:
      return d.note || d.reason || "";
  }
}

function renderChain(entries) {
  const firstRender = state.seen.size === 0;
  $("#chain").innerHTML = entries
    .map((e) => {
      const [label, kind] = EVENT_LABEL[e.event] || [e.event, ""];
      const isNew = !firstRender && !state.seen.has(e.id);
      return `<li class="link${isNew ? " is-new" : ""}" data-id="${e.id}">
        <div class="link-top">
          <span class="link-event" data-kind="${kind}">${esc(label)}</span>
          <span class="link-meta">#${e.id} · ${timeOf(e.ts_ms)}</span>
        </div>
        <div class="link-detail">${esc(describe(e))}</div>
        <div class="link-hashes"><span>id <b>${esc(short(e.hash))}</b></span><span>links to ${esc(short(e.prev_hash))}</span></div>
      </li>`;
    })
    .join("");
  entries.forEach((e) => state.seen.add(e.id));
  if (state.verify) paintVerify(state.verify);
}

function paintVerify(result) {
  document.querySelectorAll("#chain .link").forEach((li) => {
    const id = Number(li.dataset.id);
    li.classList.remove("verified", "broken", "unverifiable");
    let cls = "verified";
    if (!result.ok) cls = id < result.broken_at ? "verified" : id === result.broken_at ? "broken" : "unverifiable";
    li.classList.add(cls);
  });
}

$("#verify-btn").addEventListener("click", async () => {
  const out = $("#verify-out");
  try {
    const res = await api("/audit/verify");
    state.verify = res;
    out.className = "outcome " + (res.ok ? "good" : "bad");
    out.innerHTML = res.ok
      ? `<strong>The log is intact.</strong> All ${res.checked} entries check out, in order, with nothing changed or removed.`
      : `<strong>Tampering found at entry #${esc(res.broken_at)}.</strong> ${esc(res.reason)}`;
    paintVerify(res);
  } catch (err) {
    out.className = "outcome bad";
    out.textContent = err.message;
  }
});

// ---------------------------------------------------------------------------
// Kill switch, stats, log out
// ---------------------------------------------------------------------------
function renderStats(s) {
  $("#s-active").textContent = s.active_tokens;
  $("#s-allowed").textContent = s.calls_allowed;
  $("#s-blocked").textContent = s.calls_blocked;
  $("#s-spent").textContent = smallMoney(s.spent_usd);
  $("#s-alerts").textContent = s.alerts;
  const kill = $("#kill-btn");
  kill.setAttribute("aria-pressed", String(s.kill_all));
  $("#kill-label").textContent = s.kill_all ? "Every agent is stopped. Resume" : "Stop every agent";
}

$("#kill-btn").addEventListener("click", async () => {
  const on = $("#kill-btn").getAttribute("aria-pressed") !== "true";
  if (on && !window.confirm("Stop every agent in this workspace right now? Their next calls will be refused until you resume.")) return;
  try {
    await api("/kill", { method: "POST", body: JSON.stringify({ on }) });
    await refresh();
  } catch (err) {
    banner(err.message);
  }
});

$("#logout").addEventListener("click", async () => {
  await fetch("/api/account/logout", { method: "POST", headers: { "X-Leash-App": "1" } });
  window.location.assign("/");
});

// ---------------------------------------------------------------------------
// Refresh loop
// ---------------------------------------------------------------------------
async function refresh() {
  try {
    const [me, stats, keys, tokens, alerts, audit, hook] = await Promise.all([
      accountApi("/me"),
      api("/stats"),
      api("/connections"),
      api("/tokens"),
      api("/alerts"),
      api("/audit?limit=40"),
      api("/webhook"),
    ]);
    $("#ws-team").textContent = me.team;
    $("#ws-email").textContent = me.email;
    document.title = `${me.team} · Leash`;
    renderSetup(me.setup);
    renderStats(stats);
    renderKeys(keys);
    renderAgents(tokens);
    renderAlerts(alerts);
    renderChain(audit);
    renderHook(hook);
    banner("");
  } catch (err) {
    banner(`Couldn't refresh: ${err.message}`);
  }
}

async function boot() {
  await refresh();
  state.run = LeashRun.mount($("#agent-run"), {
    api,
    mode: "workspace",
    realChoices: () =>
      state.keys.filter((k) => k.status === "active").map((k) => ({ value: k.id, model: k.model, label: `${k.name} (${k.model})` })),
    onAfter: refresh,
  });
  renderTraps(await api("/canaries"));
  state.pollTimer = setInterval(() => {
    if (document.visibilityState === "visible") refresh();
  }, 6000);
}

boot();
