// tattlr ui. Plain JS, no libraries. Data only ever goes in via textContent.
"use strict";

const csrf = document.querySelector('meta[name="csrf"]').content;
const AGENTS = { claude: "Claude Code", codex: "Codex", cursor: "Cursor", gemini: "Gemini CLI", openclaw: "OpenClaw" };
const S = { entries: [], pending: [], filter: "all", agent: "", rap: null, skew: 0 };

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
const agentName = (a) => AGENTS[a] || a || "agent";
const firstSentence = (s) => {
  if (!s) return "";
  const i = s.search(/\.(\s|$)/);
  return i > 0 ? s.slice(0, i) : s;
};
const tilde = (p) => (p || "").replace(/^\/(home|Users)\/[^/]+/, "~");
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
function ago(t) {
  const s = Math.max(0, (Date.now() - new Date(t)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

function verdictOf(e) {
  if (e.approval === "approved") return ["approved", "approved"];
  if (e.approval === "denied") return ["denied", "denied"];
  if (e.approval === "timed out") return ["deny", "timed out"];
  if (e.decision === "allow" && e.would) return ["would", "would " + e.would];
  return [e.decision, e.decision === "deny" ? "blocked" : e.decision];
}

function keep(e) {
  if (S.agent && e.agent !== S.agent) return false;
  const [cls] = verdictOf(e);
  switch (S.filter) {
    case "all": return true;
    case "stopped": return cls !== "allow";
    case "deny": return cls === "deny" || cls === "denied";
    case "ask": return e.decision === "ask" || !!e.approval;
    case "would": return cls === "would";
    case "allow": return cls === "allow" || cls === "approved";
  }
  return true;
}

// ---------- header ----------
function renderPolicy(st) {
  const p = $("policy");
  p.replaceChildren(
    h("span", { class: "pill mode-" + st.mode, text: st.mode + " mode" }),
    h("span", { class: "pill", text: st.approval_timeout > 0 ? "inbox waits " + st.approval_timeout + "s" : "inbox off" }),
    h("span", { class: "pill", text: st.notify ? "notify on" : "notify off" }),
    st.policy_error ? h("span", { class: "pill warn", title: st.policy_error, text: "policy error" }) : null,
  );
}

function renderStats() {
  const day = Date.now() - 864e5;
  const n = { checked: 0, blocked: 0, asked: 0, approved: 0, would: 0 };
  for (const e of S.entries) {
    if (new Date(e.time) < day) continue;
    n.checked++;
    if (e.decision === "deny") n.blocked++;
    if (e.decision === "ask" || e.approval) n.asked++;
    if (e.approval === "approved") n.approved++;
    if (e.would) n.would++;
  }
  const card = (v, l, c) => h("div", { class: "stat " + c }, h("div", { class: "n", text: v }), h("div", { class: "l", text: l }));
  $("stats").replaceChildren(
    card(n.checked, "tool calls checked today", ""),
    card(n.blocked, "blocked", "red"),
    card(n.asked, "asked you", "yellow"),
    card(n.approved, "approved in the inbox", "green"),
    card(n.would, "would block (observe)", "blue"),
  );
}

// ---------- inbox ----------
async function decide(id, decision, card) {
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    const r = await fetch("/api/decide", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ id, decision }),
      credentials: "same-origin",
    });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    S.pending = S.pending.filter((p) => p.id !== id);
    renderInbox();
  } catch (err) {
    card.querySelector(".why").textContent = "Could not send that: " + err.message;
    card.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

function renderInbox() {
  const box = $("inbox");
  box.hidden = S.pending.length === 0;
  $("inbox-count").textContent = S.pending.length > 1 ? "(" + S.pending.length + ")" : "";
  document.title = S.pending.length ? "(" + S.pending.length + ") tattlr" : "tattlr";
  $("inbox-list").replaceChildren(...S.pending.map((p) => {
    const card = h("article", { class: "ask", "data-id": p.id, "data-deadline": p.deadline, "data-total": p.timeout_ms || 30000 },
      h("div", { class: "row1" },
        p.severity ? h("span", { class: "sev " + p.severity, text: p.severity }) : null,
        h("span", { class: "who", text: agentName(p.agent) }),
        h("span", { class: "what", text: "wants to run " + (p.tool || "a tool") }),
        h("span", { class: "left" })),
      h("div", { class: "ev", text: p.evidence || "(no details)" }),
      h("p", { class: "why", text: [firstSentence(p.reason), tilde(p.cwd)].filter(Boolean).join("  ·  ") }),
      h("div", { class: "acts" },
        h("button", { class: "btn deny", text: "Deny", onclick: () => decide(p.id, "deny", card) }),
        h("button", { class: "btn ok", text: "Approve", onclick: () => decide(p.id, "approve", card) })),
      h("div", { class: "bar" }));
    return card;
  }));
  tick();
}

function tick() {
  for (const c of document.querySelectorAll(".ask")) {
    const left = Math.max(0, Number(c.dataset.deadline) - (Date.now() + S.skew));
    const total = Number(c.dataset.total) || 30000;
    c.querySelector(".left").textContent = left > 0 ? Math.ceil(left / 1000) + "s left, then the policy decides" : "falling back to the policy";
    c.querySelector(".bar").style.width = (100 * left / total).toFixed(1) + "%";
  }
}
setInterval(tick, 250);

// ---------- timeline ----------
function row(e, fresh) {
  const [cls, label] = verdictOf(e);
  const title = firstSentence(e.reason);
  return h("li", { class: "ev-row" + (fresh ? " fresh" : "") },
    h("div", { class: "t" }, clock(e.time), h("small", { text: ago(e.time) })),
    h("div", {}, h("span", { class: "tag " + cls, text: label })),
    h("div", {},
      h("div", { class: "main-line" },
        h("span", { class: "agent", text: agentName(e.agent) }),
        e.tool ? h("span", { class: "tool", text: e.tool }) : null,
        e.severity ? h("span", { class: "sev " + e.severity, text: e.severity }) : null,
        title ? h("span", { class: "title", text: title }) : null),
      e.evidence ? h("div", { class: "cmd", title: e.evidence, text: e.evidence }) : null,
      h("div", { class: "meta", text: [tilde(e.cwd), e.mode && e.mode + " mode", e.tainted && "touched a canary", e.error].filter(Boolean).join("  ·  ") })));
}

function renderTimeline(freshCount) {
  const list = S.entries.filter(keep).slice().reverse().slice(0, 300);
  $("timeline").replaceChildren(...list.map((e, i) => row(e, i < (freshCount || 0))));
  $("timeline").hidden = list.length === 0;
  $("empty").hidden = list.length !== 0;
  const sel = $("agent-filter");
  const seen = [...new Set(S.entries.map((e) => e.agent))].sort();
  if (sel.options.length - 1 !== seen.length) {
    sel.replaceChildren(h("option", { value: "", text: "All agents" }), ...seen.map((a) => h("option", { value: a, text: agentName(a) })));
    sel.value = S.agent;
  }
}

// ---------- rap sheet ----------
function sevColor(score) {
  return score >= 70 ? "var(--red)" : score >= 40 ? "var(--orange)" : score >= 15 ? "var(--yellow)" : "var(--green)";
}

async function loadRap(fresh) {
  const box = $("rap");
  if (!S.rap || fresh) box.replaceChildren(h("p", { class: "empty", text: "Reading your agent logs..." }));
  try {
    const r = await fetch("/api/rapsheet" + (fresh ? "?fresh=1" : ""), { credentials: "same-origin" });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    S.rap = await r.json();
    renderRap();
  } catch (err) {
    box.replaceChildren(h("p", { class: "empty", text: "Could not build the rap sheet: " + err.message }));
  }
}

function renderRap() {
  const r = S.rap;
  const fact = (n, l) => h("div", {}, h("div", { class: "n", text: n }), h("div", { class: "l", text: l }));
  const parts = [
    h("div", { class: "rap-head" },
      h("div", { class: "score" },
        h("div", { class: "big", style: "color:" + sevColor(r.score), text: r.score }),
        h("div", { class: "of", text: "out of 100" }),
        h("div", { class: "verdict", text: r.verdict })),
      h("div", { class: "facts" },
        fact(r.sessions, "sessions"), fact(r.tool_calls, "tool calls"),
        fact(r.flagged, "flagged"), fact(r.logs, "logs read"))),
  ];
  const agents = h("div", { class: "card" },
    h("button", { class: "btn refresh", text: "Rescan", onclick: () => loadRap(true) }),
    h("h3", { text: "Agents" }));
  if (!r.agents.length) agents.append(h("p", { class: "empty", text: "No agent logs found on this machine." }));
  for (const a of r.agents) {
    agents.append(h("div", { class: "arow" },
      h("b", { text: agentName(a.agent) }),
      h("div", { class: "meter" }, h("i", { style: "width:" + Math.max(2, a.score) + "%;background:" + sevColor(a.score) })),
      h("span", { class: "dim", text: a.score + "/100" }),
      h("span", { class: "dim", text: a.flagged_calls + " of " + a.tool_calls + " calls flagged" })));
  }
  parts.push(agents);
  if (r.offenses.length) {
    parts.push(h("div", { class: "card" }, h("h3", { text: "Top offenses" }),
      r.offenses.map((o) => h("div", { class: "orow" },
        h("span", { class: "sev " + o.severity, text: o.severity }),
        h("span", { text: o.title, title: (o.agents || []).map(agentName).join(", ") }),
        h("span", { class: "c", text: "×" + o.count })))));
  }
  if (r.moments.length) {
    parts.push(h("div", { class: "card" }, h("h3", { text: "Worst moments" }),
      r.moments.map((m) => h("div", { class: "mrow" },
        h("div", { class: "main-line" },
          h("span", { class: "sev " + m.severity, text: m.severity }),
          h("span", { class: "agent", text: agentName(m.agent) }),
          h("span", { class: "title", text: (m.titles || []).join(", ") })),
        h("div", { class: "cmd", title: m.evidence, text: m.evidence }),
        h("div", { class: "meta", text: [tilde(m.project), m.time && new Date(m.time).toLocaleString()].filter(Boolean).join("  ·  ") })))));
  }
  $("rap").replaceChildren(...parts);
}

// ---------- wiring ----------
function show(view) {
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("on", t.dataset.view === view);
  $("view-timeline").hidden = view !== "timeline";
  $("view-rap").hidden = view !== "rap";
  if (view === "rap" && !S.rap) loadRap(false);
  history.replaceState(null, "", view === "rap" ? "#rap" : "#");
}
for (const t of document.querySelectorAll(".tab")) t.addEventListener("click", () => show(t.dataset.view));
for (const c of document.querySelectorAll(".chip")) {
  c.addEventListener("click", () => {
    S.filter = c.dataset.filter;
    document.querySelectorAll(".chip").forEach((x) => x.classList.toggle("on", x === c));
    renderTimeline();
  });
}
$("agent-filter").addEventListener("change", (e) => { S.agent = e.target.value; renderTimeline(); });

async function loadState() {
  const r = await fetch("/api/state", { credentials: "same-origin" });
  if (r.status === 401) { location.reload(); return; }
  const st = await r.json();
  S.skew = st.now - Date.now();
  S.entries = st.entries;
  S.pending = st.pending;
  renderPolicy(st);
  renderStats();
  renderInbox();
  renderTimeline();
}

function connect() {
  const es = new EventSource("/api/stream");
  const live = $("live");
  es.onopen = () => { live.classList.remove("off"); live.querySelector("b").textContent = "live"; loadState(); };
  es.onerror = () => { live.classList.add("off"); live.querySelector("b").textContent = "reconnecting"; };
  es.addEventListener("audit", (m) => {
    const add = JSON.parse(m.data);
    S.entries = S.entries.concat(add).slice(-1000);
    renderStats();
    renderTimeline(add.length);
  });
  es.addEventListener("pending", (m) => { S.pending = JSON.parse(m.data); renderInbox(); });
}

setInterval(() => document.querySelectorAll(".ev-row small").length && renderTimeline(), 30000);
loadState().then(connect);
if (location.hash === "#rap") show("rap");
