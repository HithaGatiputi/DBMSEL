// ===================================================================
// Incident Investigation Console — vanilla JS single-page app
// ===================================================================
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = t => t ? String(t).replace("T", " ").slice(0, 19) : "";
const fmtS = t => t ? `<span class="nw">${String(t).replace("T", " ").slice(0, 16)}</span>` : "";      // short, one line
const human = c => String(c || "").replace(/_/g, " ");
const sev = s => s ? `<span class="sev ${esc(s)}">${esc(s)}</span>` : "";
const pill = s => `<span class="pill">${esc(s)}</span>`;
// tiny, safe markdown for AI text: escape first, then **bold** and `code` only
const md = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
const SRC = { sensor: "sensor", simulator: "simulated", ctu13: "CTU-13 real" };
const srcBadge = s => s && s !== "sensor" ? `<span class="pill src-${esc(s)}">${esc(SRC[s] || s)}</span>` : "";
const SEV_COL = { Low: "var(--Low)", Medium: "var(--Medium)", High: "var(--High)", Critical: "var(--Critical)" };
const STATUSES = ["Investigating", "Contained", "Resolved", "Closed", "False Positive"];
const CATS = ["failed_login", "successful_login", "new_device_access", "file_access", "confidential_file_access", "privilege_escalation", "data_transfer", "port_scan", "malware_alert"];
let ME = null, TOKEN = null, STAFF = [];

// ------------------------------------------------------------- storage
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { } },
};

// ----------------------------------------------------------------- api
function errText(data, fallback) {
  const d = data && data.detail;
  if (Array.isArray(d)) return d.map(x => `${(x.loc || []).slice(1).join(".")}: ${x.msg.replace(/^Value error, /, "")}`).join("; ");
  return d || fallback;
}
async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body ? "POST" : "GET"), headers: {} };
  if (TOKEN) init.headers.Authorization = "Bearer " + TOKEN;
  if (opts.body) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  const r = await fetch("/api" + path, init);
  if (opts.raw) { if (!r.ok) throw new Error(r.statusText); return r; }
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/login") { logout(); throw new Error("Session expired — please sign in again"); }
  if (!r.ok) throw new Error(errText(data, r.statusText));
  return data;
}
function toast(msg, bad) {
  const t = $("#toast"); t.textContent = msg; t.style.display = "block"; t.style.borderColor = bad ? "var(--Critical)" : "var(--Low)";
  clearTimeout(toast.h); toast.h = setTimeout(() => t.style.display = "none", 4500);
}
async function safe(fn) { try { return await fn(); } catch (e) { toast(e.message, true); } }
function modal(html) { $("#mbody").innerHTML = html; $("#modal").hidden = false; }
$("#mclose").onclick = () => $("#modal").hidden = true;
$("#modal").onclick = e => { if (e.target.id === "modal") $("#modal").hidden = true; };

const bars = (rows, key = "k", val = "n") => { const m = Math.max(1, ...rows.map(r => +r[val])); return rows.map(r => `<div class="bar"><span class="n" title="${esc(r[key])}">${esc(r[key])}</span><span class="b"><i style="width:${100 * r[val] / m}%"></i></span><b>${r[val]}</b></div>`).join(""); };
function table(cols, rows, onclick) {
  if (!rows.length) return `<p class="mut">No rows.</p>`;
  return `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th>${esc(c.h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r, i) => `<tr class="${onclick ? "click" : ""}" data-i="${i}">${cols.map(c => `<td>${c.f ? c.f(r) : esc(r[c.k])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function bindRows(sel, rows, fn) { $$(sel + " tr.click").forEach(tr => tr.onclick = () => fn(rows[tr.dataset.i])); }

// --------------------------------------------------------------- login
function showLogin() { $("#app").hidden = true; $("#login").hidden = false; $("#lu").focus(); }
function logout() { TOKEN = null; ME = null; store.set("token", null); showLogin(); }
$("#logout").onclick = logout;
$("#loginForm").onsubmit = async e => {
  e.preventDefault();
  const u = $("#lu").value.trim(), p = $("#lp").value;
  $("#lerr").textContent = "";
  if (u.length < 3) return $("#lerr").textContent = "Enter your username (at least 3 characters).";
  if (!p) return $("#lerr").textContent = "Enter your password.";
  try {
    const r = await api("/login", { body: { username: u, password: p } });
    TOKEN = r.token; store.set("token", TOKEN); $("#lp").value = ""; boot();
  } catch (err) { $("#lerr").textContent = err.message; }
};

// ---------------------------------------------------------------- tabs
const loaders = { overview, incidents, alerts, events, ask, reports, logs, audit, admin, design, guide };
$$("#nav button").forEach(b => b.onclick = () => show(b.dataset.tab));
const PAGES = {
  overview: ["Dashboard", "What needs your attention right now"],
  incidents: ["Incidents", "Cases the system built automatically from related alerts. Click one to investigate it."],
  alerts: ["Alerts", "Single suspicious events flagged by the detection rules and the machine-learning model"],
  events: ["Events & logs", "Every recorded activity, plus a search of the original raw logs"],
  ask: ["Ask AI", "Ask a question in plain English. The answer comes straight from the database, read-only."],
  reports: ["Reports", "Ready-made database reports. View them here or download them as CSV."],
  audit: ["Audit trail", "Every change to every incident: who, what and when. These records cannot be edited or deleted."],
  admin: ["Admin", "Security self-test, automatic response, users, devices, detection rules and settings"],
  guide: ["How to use", "A short step-by-step tour of the system"],
  design: ["Project design", "Objectives, database design, normalisation and diagrams"],
};
let VIEW = "overview";
function show(tab) {
  if (tab === "logs") tab = "events";                       // raw-log search now lives on the Events page
  if (!PAGES[tab]) tab = "overview";
  $("#ptitle").textContent = PAGES[tab][0]; $("#psub").textContent = PAGES[tab][1];
  window.scrollTo(0, 0);
  $$("#nav button").forEach(b => b.classList.toggle("on", b.dataset.tab === tab));
  $$("main > section").forEach(s => s.hidden = s.id !== "tab-" + tab);
  store.set("tab", tab);
  VIEW = tab;
  safe(() => loaders[tab]());
}

// ------------------------------------------------------------ overview
function flowCard(f, c) {
  if (!f.cic_holdout) return `<p class="mut">Not trained yet. Run <code>python -m app.cli train-flow</code>.</p>`;
  const row = (name, m, note) => m && m.roc_auc !== undefined ? { name, auc: m.roc_auc, p: m.precision, r: m.recall, n: m.n, note } : null;
  const rows = [row("CIC-IDS2017 hold-out (30%)", f.cic_holdout, "same distribution"),
  row("CIC-IDS2017 unseen day (Friday)", f.cic_unseen_day_friday, "new attack types"),
  row("CTU-13, CIC-only model (pure transfer)", f.ctu13_cross_dataset, "different network, year, tools"),
  row("CTU-13 held-out scenarios 5/11/12", f.ctu13_heldout_scenarios, "unseen botnet captures")].filter(Boolean);
  return table([{ h: "Test set", k: "name" }, { h: "ROC-AUC", k: "auc" }, { h: "Precision", k: "p" }, { h: "Recall", k: "r" }, { h: "Flows", k: "n" }, { h: "Why it differs", k: "note" }], rows) +
    `<p class="mut small">Trained on ${esc(f.dataset || "")}. Each row is a real test set the model was not trained on. The CIC-only model drops on CTU-13; adding other CTU-13 captures to training closes much of that gap on botnets it has never seen. The live alert threshold (0.80) was chosen on validation data only.</p>` +
    (c.botnet_flows ? `<h3>Held-out CTU-13 botnets replayed through the full pipeline</h3><p>Infected hosts flagged <b>${c.infected_hosts_flagged}</b> · clean hosts flagged <b>${c.clean_hosts_flagged}</b> · alert precision <b>${c.alert_precision}</b> · incident purity <b>${c.mean_incident_purity}</b> · botnet flows alerted ${c["botnet_alert_rate (recall)"]} · normal flows alerted ${c["normal_alert_rate (false positive rate)"]} (${c.botnet_flows} botnet + ${c.normal_flows} normal real flows)</p>` : "") +
    `<h3>Detection by CIC-IDS2017 attack type (hold-out, threshold 0.5)</h3>` + bars(Object.entries(f.cic_recall_by_attack || {}).map(([k, v]) => ({ k, n: Math.round(v["detected_at_0.5"] * 100) })));
}
async function overview() {
  const [s, list] = await Promise.all([api("/stats"), api("/incidents?limit=500")]);
  const el = $("#tab-overview"), ml = s.ml || {}, au = s.automation || {};
  const open = list.filter(i => ["New", "Investigating", "Contained"].includes(i.status));
  const crit = open.filter(i => i.severity_level === "Critical").length;
  const mine = open.filter(i => i.analyst === ME.username).length;
  const kpi = (v, l, hint) => `<div class="card kpi" title="${esc(hint)}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  el.innerHTML = `
  <div class="grid g4">
    ${kpi(open.length, "Open incidents", "Cases still being worked on (New, Investigating or Contained)")}
    ${kpi(`<span style="color:var(--Critical)">${crit}</span>`, "Critical &amp; open", "Open cases with the highest danger score (75 or more)")}
    ${kpi(mine, "Assigned to me", "Open cases you are responsible for")}
    ${kpi(s.blocked_attempts, "Attacker attempts blocked", "Activity from blocked IP addresses or disabled accounts after containment")}
  </div><br>
  <div class="card"><div class="cardhead"><h3>Needs attention</h3><a href="#" id="allinc">All incidents →</a></div>
    ${open.length ? table([{ h: "Severity", f: r => sev(r.severity_level) }, { h: "Incident", f: r => `<b>${esc(r.title)}</b>` },
      { h: "Risk", f: r => `<b>${r.risk_score}</b>` }, { h: "Status", f: r => pill(r.status) },
      { h: "Analyst", f: r => esc(r.analyst || "unassigned") }], open.slice(0, 6), true)
      : `<p class="mut">Nothing open. 🎉</p>`}</div><br>
  <div class="grid g2">
    <div class="card"><h3>Incidents by severity</h3>${bars(["Critical", "High", "Medium", "Low"].map(k => ({ k, n: (s.by_severity.find(x => x.k === k) || { n: 0 }).n })))}</div>
    <div class="card"><h3>What kind of activity was recorded</h3>${bars(s.by_category.map(x => ({ k: x.k.replace(/_/g, " "), n: x.n })))}</div>
  </div><br>
  <div class="grid g4">
    ${kpi(s.events.toLocaleString(), "Events recorded", "All activity records stored")}
    ${kpi(s.alerts, "Alerts raised", "Events the rules or ML flagged as suspicious")}
    ${kpi(s.incidents, "Incidents in total", "All cases, including closed ones")}
    ${kpi(s.active_blocks, "Active blocks", "Attacker IPs and accounts currently blocked")}
  </div><br>
  ${ME.role === "Admin" ? `<div class="card"><h3>Demo tools (Admin)</h3>
    <p class="mut">Launch a simulated attack to see the system detect it, connect the steps into one incident and contain it. Simulated data is always labelled “simulated”.</p>
    <div class="row" style="margin:0">
      <select id="scen" aria-label="Attack scenario">${[["account_takeover_exfil", "Account takeover + data theft"], ["recon_bruteforce", "Port scan + password guessing"], ["insider_data_theft", "Insider steals data"], ["malware_outbreak", "Malware infection"], ["privilege_abuse", "Privilege abuse"]].map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select>
      <button class="btn" id="sim">⚡ Launch attack</button>
      <button class="btn sec" id="corr" title="Correlation also runs automatically every ${au.auto_correlate_seconds}s">Re-check alerts now</button>
    </div></div><br>` : ""}
  <details class="card"><summary><b>Detection model results</b> <span class="mut">(technical details)</span></summary><br>
    <div class="grid g2">
      <div><h3>Network model · trained on real traffic</h3>${flowCard(s.flow_ml || {}, s.ctu_eval || {})}</div>
      <div><h3>Behaviour model · logins, files, privileges</h3>
        <p>ROC-AUC <b>${ml.roc_auc_blended ?? "–"}</b> · Precision <b>${ml["precision_at_0.5"] ?? "–"}</b> · Recall <b>${ml["recall_at_0.5"] ?? "–"}</b></p>
        <p class="mut small">Trained on simulated activity, because no public labelled dataset of logins and file access exists, so these scores are optimistic. Network activity is also checked by the real-data model.</p>
        <h3>Most useful signals</h3>${bars(Object.entries(ml.feature_importance || {}).map(([k, n]) => ({ k: k.replace(/_/g, " "), n: +(n * 100).toFixed(1) })))}</div>
    </div></details>`;
  bindRows("#tab-overview .card", open.slice(0, 6), r => { show("incidents"); safe(() => incidentDetail(r.incident_id)); });
  $("#allinc").onclick = e => { e.preventDefault(); show("incidents"); };
  if ($("#sim")) $("#sim").onclick = () => safe(async () => {
    $("#sim").disabled = true; toast("Launching the simulated attack…");
    const r = await api("/simulate", { body: { scenario: $("#scen").value } });
    toast(`Attack detected: ${r.events_injected} events grouped into incident #${r.incident_id}`);
    if (r.incident_id) { show("incidents"); incidentDetail(r.incident_id); } else overview();
  }).finally(() => { const b = $("#sim"); if (b) b.disabled = false; });
  if ($("#corr")) $("#corr").onclick = () => safe(async () => { const r = await api("/correlate", { body: { window_minutes: 30 } }); toast(`Done: ${r.incidents_created} new incident(s), ${r.events_linked} alert(s) linked`); overview(); });
}

// ----------------------------------------------------------- incidents
async function incidents() {
  const el = $("#tab-incidents"), saved = JSON.parse(store.get("incFilter") || "{}");
  el.innerHTML = `<div class="row">
    <select id="fs" aria-label="Status"><option value="">All statuses</option>${["New", ...STATUSES].map(s => `<option>${s}</option>`).join("")}</select>
    <select id="fv" aria-label="Severity"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
    <label style="flex-direction:row;align-items:center"><input type="checkbox" id="fm"> Assigned to me</label></div><div class="card" id="il"></div>`;
  $("#fs").value = saved.s || ""; $("#fv").value = saved.v || ""; $("#fm").checked = !!saved.m;
  const load = async () => {
    store.set("incFilter", JSON.stringify({ s: $("#fs").value, v: $("#fv").value, m: $("#fm").checked }));
    const q = new URLSearchParams(); if ($("#fs").value) q.set("status", $("#fs").value); if ($("#fv").value) q.set("severity", $("#fv").value); if ($("#fm").checked) q.set("mine", "true");
    const rows = await api("/incidents?" + q);
    $("#il").innerHTML = `<p class="mut small">${rows.length} incident(s). Click a row to investigate.</p>` + table([{ h: "#", k: "incident_id" }, { h: "Title", k: "title" }, { h: "Severity", f: r => sev(r.severity_level) }, { h: "Risk", k: "risk_score" },
    { h: "Status", f: r => pill(r.status) }, { h: "Primary entity", f: r => esc(r.primary_user || r.primary_device || "") + (r.user_entity_role ? `<br><span class="mut small">${esc(r.user_entity_role)}</span>` : "") },
    { h: "Events", k: "event_count" }, { h: "Analyst", f: r => esc(r.analyst || "—") }, { h: "First seen", f: r => fmtS(r.first_event) }], rows, true);
    bindRows("#il", rows, r => incidentDetail(r.incident_id));
  };
  $("#fs").onchange = $("#fv").onchange = $("#fm").onchange = () => safe(load); await load();
}

async function incidentDetail(id) {
  VIEW = "incident:" + id;
  const d = await api("/incidents/" + id), i = d.incident, el = $("#tab-incidents");
  const isAdmin = ME.role === "Admin", mine = i.analyst === ME.username, closed = ["Closed", "False Positive"].includes(i.status);
  const canAct = isAdmin || mine, canTake = !closed && i.status !== "Resolved" && (!i.analyst || isAdmin) && !mine;
  const NEED_REASON = ["Resolved", "Closed", "False Positive"];
  const allowed = { New: ["Investigating", "False Positive"], Investigating: ["Contained", "Resolved", "False Positive"], Contained: ["Resolved", "Investigating"], Resolved: ["Closed", "Investigating"] }[i.status] || [];
  el.innerHTML = `<span class="back" id="bk">&larr; All incidents</span>
  <div class="card"><div class="row"><h2 style="margin:0">#${i.incident_id} ${esc(i.title)}</h2>${sev(i.severity_level)}${pill(i.status)}<b>Risk ${i.risk_score}/100</b></div>
    ${(i.sources || []).filter(x => x !== "sensor").length ? `<p class="small">${(i.sources || []).map(srcBadge).join(" ")} <span class="mut">this incident contains ${(i.sources || []).includes("simulator") ? "simulated" : "replayed dataset"} events, not live sensor data</span></p>` : ""}
    <p class="mut">Analyst: <b>${esc(i.analyst || "unassigned")}</b> · Primary user: ${esc(i.primary_user || "—")} ${i.user_entity_role ? pill(i.user_entity_role) : ""} · Primary device: ${esc(i.primary_device || "—")} ${i.device_entity_role ? pill(i.device_entity_role) : ""} · Created ${fmt(i.created_at)} · Updated ${fmt(i.updated_at)}${i.resolved_at ? " · Resolved " + fmt(i.resolved_at) : ""}</p>
    <div class="row actionsrow">
      ${canTake ? `<button class="btn" id="asg">Assign to me</button>` : ""}
      ${isAdmin && !closed ? `<select id="asgTo" aria-label="Assign to">${STAFF.map(s => `<option value="${s.user_id}">${esc(s.username)}</option>`).join("")}</select><button class="btn sec" id="asgOther">Assign</button>` : ""}
      ${allowed.length && canAct ? `<select id="ns" aria-label="New status">${allowed.map(s => `<option>${s}</option>`).join("")}</select><input id="nsNote" placeholder="reason" maxlength="1000"><button class="btn sec" id="sts">Change status</button>` : ""}
      <button class="btn sec" id="rep">Download report</button>
    </div>
    ${!canAct ? `<p class="mut small">${i.analyst ? `Owned by ${esc(i.analyst)}: only the owner or an Admin can change status, add actions or attach evidence.` : "Assign this incident to yourself to work on it."}</p>` : ""}
    <p><b>Analysis</b> ${pill(d.explanation_source)} ${d.ai_available && d.explanation_source === "rule-based" ? `<button class="btn sec sm" id="aiexp">✨ AI explanation</button>` : ""}<br><span id="expl">${md(d.explanation)}</span></p>
    <div class="chain">${d.kill_chain.map(k => `<span>${esc(k.tactic)} (${esc(k.technique)})</span>`).join("")}</div></div><br>
  <div class="grid g2">
    <div class="card"><h3>Event timeline (${d.timeline.length})</h3><div class="tl">${d.timeline.map(t => `<div class="st" style="--c:${SEV_COL[t.severity]}"><b>${t.step_sequence}. ${esc(t.event_category)}</b> ${sev(t.severity)} ${t.blocked ? '<span class="pill blk">⛔ BLOCKED</span>' : ""} <span class="mut small" title="Risk: how dangerous this step is (0–100). Anomaly: how unusual the ML model found it (0–1).">risk ${t.risk_score} · anomaly ${t.anomaly_score}</span><br>
      <span class="mut small">${fmt(t.event_timestamp)} · ${esc(t.username || "—")} @ ${esc(t.hostname)} · src ${esc(t.source_ip || "—")}</span><br><span class="mut small">${esc(t.detail || "")}</span><br>
      <a href="#" class="raw" data-e="${t.event_id}">raw log (MongoDB)</a> · <a href="#" class="win" data-e="${t.event_id}">±30 min context</a> <span class="mut small">· event ${t.event_id} · ${esc(t.correlation_rule)}</span> ${srcBadge(t.event_source)}</div>`).join("")}</div></div>
    <div>
      <div class="card"><h3>Response &amp; containment</h3>
        ${d.blocks.length ? table([{ h: "Blocked", f: b => `${b.entity_type === "ip" ? "IP" : "Account"} <b>${esc(b.entity)}</b>` },
          { h: "By", f: b => b.actor === "auto-response" ? pill("automatic") : esc(b.blocked_by) },
          { h: "Status", f: b => b.active ? '<span class="pill blk">active</span>' : `lifted by ${esc(b.lifted_by)}` },
          { h: "Attempts since", k: "blocked_attempts" },
          { h: "", f: b => b.active && isAdmin ? `<button class="btn sec sm lift" data-b="${b.block_id}">Lift…</button>` : "" }], d.blocks)
          : `<p class="mut">Nothing blocked yet. Critical incidents are contained automatically (attacker IPs blocked, compromised accounts disabled; staff accounts are flagged for review instead).</p>`}
        ${isAdmin && d.blocks.some(b => b.active && b.entity_type === "ip") ? `<p><button class="btn" id="ret">🔁 Simulate the attacker returning</button> <span class="mut small">sends new attempts from the blocked IP</span></p>` : ""}
        ${canAct && !closed ? `<form id="blkForm" class="form" novalidate style="margin-top:10px">
          <label>Block<select id="btype"><option value="ip">IP address</option><option value="user">User account</option></select></label>
          <label>Value<input id="bval" maxlength="64" placeholder="e.g. 185.18.159.138 or first.last"></label>
          <label style="grid-column:1/-1">Reason<input id="breason" maxlength="500" placeholder="why (required)"></label>
          <button class="btn sec">Block</button><span class="ferr" id="berr"></span></form>` : ""}
      </div><br>
      ${canAct ? `<div class="card"><h3>Record an action</h3>
        <form id="actForm" class="form" novalidate>
          <label>Type<select id="atype"><option value="NOTE">Note</option><option value="CONTAINMENT">Containment</option><option value="ESCALATION">Escalation</option></select></label>
          <label style="grid-column:1/-1">Notes<textarea id="anotes" rows="3" maxlength="2000" placeholder="What did you check or do?"></textarea><span class="ferr" id="aerr"></span></label>
          <button class="btn">Save action</button></form>
        <form id="evForm" class="form" novalidate style="margin-top:12px">
          <label>Attach event as evidence<input id="evid" type="number" min="1" placeholder="event id"></label>
          <label>Why<input id="evnote" maxlength="500" placeholder="optional"></label>
          <button class="btn sec">Attach</button><span class="ferr" id="everr"></span></form></div><br>` : ""}
      <div class="card actions"><h3>Investigation actions (${d.actions.length})</h3><div class="tl">${d.actions.map(a => `<div class="st"><b>${esc(a.action_type)}</b> <span class="mut small">${fmt(a.performed_at)} · ${esc(a.analyst)}</span><br>${esc(a.action_notes)}</div>`).join("") || '<p class="mut">No actions yet.</p>'}</div></div><br>
      <div class="card"><h3>Why this risk score? (computed in PostgreSQL)</h3>${table([{ h: "Component", k: "component" }, { h: "Rule", k: "weight" }, { h: "Points", k: "contribution" }], d.risk_breakdown)}</div><br>
      <div class="card"><h3>Findings</h3>${d.patterns.map(p => `<p><b>${esc(p.pattern)}</b> ${pill(p.mitre)}<br>${esc(p.summary)} <span class="mut small">(events ${p.events.slice(0, 6).join(", ")}${p.events.length > 6 ? "…" : ""})</span></p>`).join("") || "<span class=mut>None</span>"}</div><br>
      <div class="card"><h3>Framework context (RAG)</h3>${d.context.map(c => `<p><b>${esc(c.source)} ${esc(c.ref)} – ${esc(c.title)}</b><br><span class="mut small">${esc(c.text)}</span></p>`).join("")}</div><br>
      <div class="card"><h3>Audit trail (trigger-written, append-only)</h3>${table([{ h: "When", f: r => fmt(r.changed_at) }, { h: "Field", k: "field_changed" }, { h: "Change", f: r => `${esc(r.old_value ?? "")} → ${esc(r.new_value ?? "")}` }, { h: "By", f: r => esc(r.analyst || r.actor) }], d.audit.filter(a => a.field_changed !== "evidence_added"))}</div>
    </div></div>`;
  const reload = () => incidentDetail(id);
  $("#bk").onclick = () => safe(incidents);
  if ($("#asg")) $("#asg").onclick = () => safe(async () => { await api(`/incidents/${id}/assign`, { body: {} }); toast("Assigned to you"); reload(); });
  if ($("#asgOther")) $("#asgOther").onclick = () => safe(async () => { await api(`/incidents/${id}/assign`, { body: { assignee_id: +$("#asgTo").value } }); toast("Assigned"); reload(); });
  if ($("#sts")) $("#sts").onclick = () => {
    const st = $("#ns").value, note = $("#nsNote").value.trim();
    if (NEED_REASON.includes(st) && note.length < 5) return toast(`A reason (at least 5 characters) is required to mark it ${st}.`, true);
    safe(async () => { await api(`/incidents/${id}/status`, { body: { status: st, notes: note } }); toast("Status updated"); reload(); });
  };
  if ($("#aiexp")) $("#aiexp").onclick = () => {
    const b = $("#aiexp"); b.disabled = true; b.textContent = "Thinking… (local model, up to ~1 min)";
    safe(async () => { const r = await api(`/incidents/${id}/ai-explanation`, { body: {} });
      $("#expl").innerHTML = md(r.explanation); b.replaceWith(Object.assign(document.createElement("span"), { className: "pill", textContent: r.source })); })
      .finally(() => { if (document.body.contains(b)) { b.disabled = false; b.textContent = "✨ AI explanation"; } });
  };
  $("#rep").onclick = () => safe(async () => {
    const r = await api(`/incidents/${id}/report?format=md`, { raw: true }); const b = await r.blob();
    const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = `incident-${id}.md`; a.click(); URL.revokeObjectURL(a.href);
  });
  $$(".lift", el).forEach(b => b.onclick = () => { const why = prompt("Reason for lifting this block (required, at least 5 characters):");
    if (why && why.trim().length >= 5) safe(async () => { await api(`/blocks/${b.dataset.b}/lift`, { body: { reason: why.trim() } }); toast("Block lifted"); reload(); });
    else if (why !== null) toast("A reason of at least 5 characters is required", true); });
  if ($("#ret")) $("#ret").onclick = () => { $("#ret").disabled = true; $("#ret").textContent = "Attacker is trying again…";
    safe(async () => { const r = await api(`/incidents/${id}/attacker-returns`, { body: {} });
      toast(`Attacker ${r.attacker_ip} tried ${r.attempts} times — ${r.blocked} blocked, ${r.blocked_attempt_alerts} alerts raised`); reload(); }); };
  if ($("#blkForm")) $("#blkForm").onsubmit = e => { e.preventDefault(); $("#berr").textContent = "";
    const t = $("#btype").value, v = $("#bval").value.trim(), why = $("#breason").value.trim();
    if (t === "ip" && !/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return $("#berr").textContent = "Enter a valid IPv4 address.";
    if (t === "user" && !/^[a-z][a-z0-9._-]{2,49}$/.test(v)) return $("#berr").textContent = "Enter a username like first.last.";
    if (why.length < 5) return $("#berr").textContent = "A reason (at least 5 characters) is required.";
    safe(async () => { await api(`/incidents/${id}/block`, { body: { entity_type: t, value: v, reason: why } }); toast("Blocked"); reload(); }); };
  if ($("#actForm")) $("#actForm").onsubmit = e => { e.preventDefault(); const n = $("#anotes").value.trim(); $("#aerr").textContent = "";
    if (n.length < 3) return $("#aerr").textContent = "Notes must be at least 3 characters.";
    safe(async () => { await api(`/incidents/${id}/actions`, { body: { action_type: $("#atype").value, notes: n } }); toast("Action recorded"); reload(); }); };
  if ($("#evForm")) $("#evForm").onsubmit = e => { e.preventDefault(); const v = +$("#evid").value; $("#everr").textContent = "";
    if (!Number.isInteger(v) || v < 1) return $("#everr").textContent = "Enter a valid event id.";
    safe(async () => { await api(`/incidents/${id}/evidence`, { body: { event_id: v, notes: $("#evnote").value } }); toast("Evidence attached"); reload(); }); };
  $$("a.raw", el).forEach(a => a.onclick = ev => { ev.preventDefault(); safe(() => showRaw(a.dataset.e)); });
  $$("a.win", el).forEach(a => a.onclick = ev => { ev.preventDefault(); safe(() => showWindow(a.dataset.e)); });
}
async function showRaw(eid) {
  const r = await api(`/events/${eid}/raw`);
  const ok = r.integrity === "verified";
  modal(`<h3>Raw log · event ${r.event_id} ${srcBadge(r.event_source)}</h3>
    <p><span class="pill" style="border-color:${ok ? "var(--Low)" : "var(--Critical)"};color:${ok ? "var(--Low)" : "var(--Critical)"}">${ok ? "✓ integrity verified" : "⚠ " + esc(r.integrity)}</span>
    <span class="mut small">SHA-256 recorded in PostgreSQL at ingest, recomputed from the stored document now</span></p>
    <p class="mut small">Store: ${esc(r.backend)} · raw_log_ref <code>${esc(r.raw_log_ref)}</code> · sha256 <code>${esc((r.sha256 || "").slice(0, 16))}…</code></p><pre>${esc(JSON.stringify(r.document, null, 2))}</pre>`);
}
async function showWindow(eid) {
  const rows = await api(`/events/${eid}/window?minutes=30`);
  modal(`<h3>Events within ±30 min of event ${eid} sharing a user, IP or device</h3><p class="mut small">From <code>fn_event_window()</code> (DFD 2.1).</p>` +
    table([{ h: "Event", k: "event_id" }, { h: "Time", f: r => fmt(r.event_timestamp) }, { h: "Category", k: "event_category" }, { h: "Risk", k: "risk_score" }, { h: "User", k: "username" }, { h: "Host", k: "hostname" }, { h: "Src", k: "src" }, { h: "Shared", k: "shared_entity" }, { h: "Incident", f: r => r.incident_id ? "#" + r.incident_id : "—" }], rows));
}

// -------------------------------------------------------------- alerts
async function alerts() {
  const rows = await api("/alerts?limit=300"), rules = await api("/admin/rules");
  $("#tab-alerts").innerHTML = `<div class="grid g2"><div class="card"><h3>Alerts by detection rule</h3>${bars(rules.map(r => ({ k: r.rule_name, n: r.alerts })))}</div>
    <div class="card"><h3>How alerts are raised</h3><p class="mut">An AFTER INSERT trigger on <code>security_events</code> raises a <b>system_alert</b> when the active rule for the event's category matches: either the risk is at least 25 and the ML anomaly score reaches the rule's threshold (<code>ML_ANOMALY</code>), or the risk is at least 90 (<code>RULE_THRESHOLD</code>). Correlation then groups alerted events into incidents.</p></div></div><br>
    <div class="card"><h3>Latest alerts (${rows.length})</h3>${table([{ h: "Alert", k: "alert_id" }, { h: "Time", f: r => fmt(r.created_at) }, { h: "Rule", k: "rule_matched" }, { h: "Type", k: "alert_type" }, { h: "Severity", f: r => sev(r.severity) }, { h: "Risk", k: "risk_impact" }, { h: "Event", f: r => `${r.event_id} · ${esc(r.event_category)}` }, { h: "User", k: "username" }, { h: "Host", k: "hostname" }, { h: "Incident", f: r => r.incident_id ? `<a href="#" class="go" data-i="${r.incident_id}">#${r.incident_id}</a>` : "—" }], rows)}</div>`;
  $$("#tab-alerts a.go").forEach(a => a.onclick = e => { e.preventDefault(); show("incidents"); safe(() => incidentDetail(+a.dataset.i)); });
}

// -------------------------------------------------------------- events
async function events() {
  const el = $("#tab-events");
  el.innerHTML = `<div class="card"><h3>Recorded events</h3><p class="mut small">Click a row to see the original log for that event.</p><div class="row"><select id="ec" aria-label="Category"><option value="">All categories</option>${CATS.map(c => `<option>${c}</option>`).join("")}</select>
    <label style="flex-direction:row;align-items:center;gap:6px">Min risk <input id="er" type="number" min="0" max="100" value="40" style="width:80px"></label>
    <label style="flex-direction:row;align-items:center"><input type="checkbox" id="ea"> Alerted only</label>
    <button class="btn sec" id="eg">Filter</button></div><div id="el"></div></div><br><div id="logsbox"></div>`;
  logs($("#logsbox"));
  const load = async () => {
    const mr = Math.min(100, Math.max(0, +$("#er").value || 0)); $("#er").value = mr;
    const q = new URLSearchParams({ min_risk: mr, limit: 200 }); if ($("#ec").value) q.set("category", $("#ec").value); if ($("#ea").checked) q.set("alerted", "true");
    const rows = await api("/events?" + q);
    $("#el").innerHTML = table([{ h: "When", f: r => fmtS(r.event_timestamp) }, { h: "Activity", f: r => `<b>${esc(human(r.event_category))}</b>` },
      { h: "Severity", f: r => sev(r.severity) }, { h: "Risk", k: "risk_score" }, { h: "Who / where", f: r => `${esc(r.username || "—")}<br><span class="mut small">${esc(r.hostname)} · ${esc(r.source_ip || "")}</span>` },
      { h: "Tags", f: r => [r.alerted ? '<span class="pill">alert</span>' : "", r.blocked ? '<span class="pill blk">blocked</span>' : "", srcBadge(r.event_source)].join(" ") },
      { h: "Incident", f: r => r.incident_id ? "#" + r.incident_id : '<span class="mut">—</span>' }], rows, true);
    bindRows("#el", rows, r => safe(() => showRaw(r.event_id)));
  };
  $("#eg").onclick = () => safe(load); await load();
}

// ----------------------------------------------------------------- ask
function ask() {
  const el = $("#tab-ask");
  el.innerHTML = `<div class="card"><h3>Ask the database in plain English</h3><p class="mut">Your question becomes SQL. The SQL is checked by an AST validator (SELECT only, approved tables and functions, row cap) and then runs on a read-only PostgreSQL role.</p>
    <form id="qf" class="row" novalidate><input id="q" style="flex:1;min-width:240px" maxlength="500" placeholder="e.g. Which users had the most failed logins?"><button class="btn">Ask</button></form><div class="ferr" id="qerr"></div>
    <div class="row">${["Show open critical incidents", "Which users had the most failed logins?", "Who accessed restricted files after hours?", "Transfers larger than 100 MB", "Alerts by rule", "Analyst workload", "Which IPs ran port scans?", "drop table users"].map(s => `<button class="btn sec sm ex">${s}</button>`).join("")}</div><div id="ans"></div></div>`;
  const run = async () => {
    const q = $("#q").value.trim(); $("#qerr").textContent = "";
    if (q.length < 3) return $("#qerr").textContent = "Type a question (at least 3 characters).";
    $("#ans").innerHTML = "<p class=mut>Thinking… typed questions go to the AI model and can take 10–60 s on a laptop; the example buttons are instant.</p>";
    const r = await api("/query", { body: { question: q } });
    $("#ans").innerHTML = `<p>${pill(r.mode)} ${r.validated ? pill("validated · read-only role") : ""}</p>
      ${r.error ? `<p class="err">${esc(r.error)}</p>` : `<p>${esc(r.answer)}</p>`}${r.sql ? `<pre>${esc(r.sql)}</pre>` : ""}
      ${r.rows.length ? table(r.columns.map(c => ({ h: c, f: x => esc(x[c]) })), r.rows) : ""}`;
  };
  $("#qf").onsubmit = e => { e.preventDefault(); safe(run); };
  $$(".ex", el).forEach(b => b.onclick = () => { $("#q").value = b.textContent; safe(run); });
}

// ------------------------------------------------------------- reports
async function reports() {
  const cat = await api("/reports"), el = $("#tab-reports");
  el.innerHTML = `<div class="grid" style="grid-template-columns:minmax(220px,300px) 1fr"><div class="card"><h3>Query reports</h3>${cat.map((r, i) => `<p><a href="#" class="rk" data-k="${r.key}">${i + 1}. ${esc(r.title)}</a><br><span class="mut small">${esc(r.concept)}</span></p>`).join("")}</div><div class="card" id="rout"><p class="mut">Choose a report. Each one demonstrates a SQL concept and runs live on the read-only role. You can download any result as CSV.</p></div></div>`;
  const run = async k => {
    const r = await api("/reports/" + k);
    $("#rout").innerHTML = `<div class="row"><h2 style="margin:0">${esc(r.title)}</h2>${pill(r.concept)}<button class="btn sec sm" id="csv">Download CSV</button></div><pre>${esc(r.sql.replace(/^ {15}/gm, ""))}</pre><p class="mut small">${r.rows.length} row(s)</p>` + table(r.columns.map(c => ({ h: c, f: x => esc(typeof x[c] === "object" && x[c] ? JSON.stringify(x[c]) : x[c]) })), r.rows);
    $("#csv").onclick = () => safe(async () => { const res = await api(`/reports/${k}?format=csv`, { raw: true }); const b = await res.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = k + ".csv"; a.click(); });
  };
  $$("a.rk", el).forEach(a => a.onclick = e => { e.preventDefault(); safe(() => run(a.dataset.k)); });
  run(cat[0].key);
}

// ---------------------------------------------------------------- logs
function logs(target) {
  const el = target || $("#tab-events");
  el.innerHTML = `<div class="card"><h3>Search the original logs</h3><p class="mut">The untouched original records (syslog lines, packet samples, malware traces) are kept in MongoDB, each linked to its event in PostgreSQL.</p>
    <form id="lf" class="row" novalidate><input id="lq" style="flex:1" maxlength="100" placeholder="e.g. polkit, Emotet, Mirai, restricted, backup"><button class="btn">Search</button></form><div class="ferr" id="lerr2"></div><div id="lr"></div></div>`;
  $("#lf").onsubmit = e => { e.preventDefault(); const q = $("#lq").value.trim(); $("#lerr2").textContent = "";
    if (q.length < 2) return $("#lerr2").textContent = "Enter at least 2 characters.";
    safe(async () => { const r = await api("/logs/search?q=" + encodeURIComponent(q));
      $("#lr").innerHTML = `<p class="mut">Backend: ${esc(r.backend)} · ${r.results.length} hit(s)</p>` + r.results.map(d => `<pre>${esc(JSON.stringify(d, null, 1))}</pre>`).join(""); }); };
}

// --------------------------------------------------------------- audit
async function audit() {
  const rows = await api("/audit?limit=300");
  $("#tab-audit").innerHTML = `<div class="card"><h3>Incident audit log (written by PostgreSQL triggers; UPDATE, DELETE and TRUNCATE are blocked)</h3>` +
    table([{ h: "When", f: r => fmt(r.changed_at) }, { h: "Incident", f: r => "#" + r.incident_id }, { h: "Op", k: "operation" }, { h: "Field", k: "field_changed" }, { h: "Old", k: "old_value" }, { h: "New", k: "new_value" }, { h: "By", f: r => esc(r.analyst || r.actor) }], rows) + `</div>`;
}

// --------------------------------------------------------------- admin
async function admin() {
  const el = $("#tab-admin");
  if (ME.role !== "Admin") { el.innerHTML = `<div class="card"><p>Administrator role required.</p></div>`; return; }
  const sub = store.get("adminSub") || "users";
  el.innerHTML = `<div class="sub">${["selftest", "response", "users", "devices", "rules", "automation", "history"].map(s => `<button data-s="${s}" class="${s === sub ? "on" : ""}">${{ selftest: "🛡 Security self-test", response: "Response", users: "Users", devices: "Devices", rules: "Detection rules", automation: "Automation", history: "Change history" }[s]}</button>`).join("")}</div><div id="adm"></div>`;
  $$(".sub button", el).forEach(b => b.onclick = () => { store.set("adminSub", b.dataset.s); admin(); });
  await ({ selftest: admSelfTest, response: admResponse, users: admUsers, devices: admDevices, rules: admRules, automation: admAuto, history: admHistory }[sub])();
}
async function admSelfTest() {
  $("#adm").innerHTML = `<div class="card"><h3>Security self-test</h3>
    <p class="mut">Attacks the running system: password guessing, a forged token, SQL injection through Ask AI, writes through the read-only role, rewriting the audit trail, deleting evidence, an analyst taking over a colleague's incident, skipping the investigation, editing a raw MongoDB log, and a contained attacker trying again. Nothing is changed: database attempts are rolled back, tampering is tried on a copy, and the brute-force test uses a throw-away username.</p>
    <button class="btn" id="st">▶ Run security self-test</button><div id="stOut"></div></div>`;
  $("#st").onclick = () => { $("#st").disabled = true; $("#stOut").innerHTML = "<p class=mut>Attacking the system…</p>";
    safe(async () => { const r = await api("/admin/self-test", { body: {} });
      $("#stOut").innerHTML = `<h2 style="margin:14px 0">${r.blocked === r.total ? "✅" : "⚠️"} ${r.blocked} / ${r.total} attacks blocked</h2>` +
        table([{ h: "Attack", f: x => `<b>${esc(x.attack)}</b><br><span class="mut small">${esc(x.how)}</span>` },
               { h: "Result", f: x => x.result === "BLOCKED" ? '<span class="pill ok-pill">✓ BLOCKED</span>' : '<span class="pill blk">✗ NOT BLOCKED</span>' },
               { h: "Stopped by", k: "stopped_by" }, { h: "System's response", f: x => `<code>${esc(x.evidence)}</code>` }], r.results);
    }).finally(() => { if ($("#st")) $("#st").disabled = false; }); };
}
async function admResponse() {
  const p = await api("/admin/response-policy"), rows = await api("/blocks");
  $("#adm").innerHTML = `<div class="card"><h3>Automated response policy</h3>
    <form id="pf" class="form" novalidate>
      <label>Contain incidents with risk ≥<input id="p_risk" type="number" min="0" max="100" value="${p.min_risk}"></label>
      <label style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="p_ip" ${p.block_external_ips ? "checked" : ""}> Block external attacker IPs</label>
      <label style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="p_acc" ${p.disable_accounts ? "checked" : ""}> Disable compromised / insider accounts</label>
      <label style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="p_tko" ${p.contain_on_takeover ? "checked" : ""}> Contain at once when a brute-force login succeeds</label>
      <label style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="p_on" ${p.is_active ? "checked" : ""}> Policy active</label>
      <button class="btn">Save</button></form>
    <p class="mut small">Runs inside PostgreSQL (<code>sp_auto_contain</code>) after each correlation. Analyst and Admin accounts are never disabled automatically; they are flagged for manual review. Later events from a blocked IP or account are still recorded as evidence, but flagged <b>blocked</b> and raise a BLOCKED_ATTEMPT alert.</p></div><br>
    <div class="card"><h3>All blocks (${rows.length})</h3>${table([{ h: "#", k: "block_id" }, { h: "Type", k: "entity_type" }, { h: "Entity", f: b => `<b>${esc(b.entity)}</b>` },
      { h: "Incident", f: b => b.incident_id ? "#" + b.incident_id : "" }, { h: "By", f: b => b.actor === "auto-response" ? pill("automatic") : esc(b.blocked_by) },
      { h: "When", f: b => fmt(b.created_at) }, { h: "Attempts since", k: "blocked_attempts" },
      { h: "Status", f: b => b.active ? `<button class="btn sec sm lift2" data-b="${b.block_id}">Lift…</button>` : `lifted by ${esc(b.lifted_by)}: ${esc(b.lift_reason)}` }], rows)}</div>`;
  $("#pf").onsubmit = e => { e.preventDefault(); const r = +$("#p_risk").value;
    if (!(r >= 0 && r <= 100)) return toast("Risk must be 0–100", true);
    safe(async () => { await api("/admin/response-policy", { method: "PATCH", body: { min_risk: r, block_external_ips: $("#p_ip").checked, disable_accounts: $("#p_acc").checked, contain_on_takeover: $("#p_tko").checked, is_active: $("#p_on").checked } }); toast("Policy saved"); admResponse(); }); };
  $$("#adm .lift2").forEach(b => b.onclick = () => { const why = prompt("Reason for lifting this block (required):");
    if (why && why.trim().length >= 5) safe(async () => { await api(`/blocks/${b.dataset.b}/lift`, { body: { reason: why.trim() } }); toast("Block lifted"); admResponse(); });
    else if (why !== null) toast("A reason of at least 5 characters is required", true); });
}
const USER_RE = /^[a-z][a-z0-9._-]{2,49}$/, EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
async function admUsers() {
  const rows = await api("/admin/users");
  $("#adm").innerHTML = `<div class="card"><h3>Add user</h3><form id="uf" class="form" novalidate>
    <label>Username<input id="u_name" required placeholder="first.last" maxlength="50"></label>
    <label>Email<input id="u_mail" type="email" required maxlength="120"></label>
    <label>Role<select id="u_role">${["Employee", "Analyst", "Admin", "Executive", "Service"].map(r => `<option>${r}</option>`).join("")}</select></label>
    <label>Department<input id="u_dept" required maxlength="50"></label>
    <label>Initial password<input id="u_pw" type="password" maxlength="128" placeholder="required for Analyst/Admin"></label>
    <button class="btn">Create</button><div class="ferr" id="uerr" style="grid-column:1/-1"></div></form></div><br>
    <div class="card"><h3>Users (${rows.length})</h3>${table([{ h: "ID", k: "user_id" }, { h: "Username", k: "username" }, { h: "Email", k: "email" }, { h: "Role", k: "role" }, { h: "Dept", k: "department" }, { h: "Devices", k: "devices" }, { h: "Login", f: r => r.can_login ? "yes" : "—" },
    { h: "Active", f: r => `<button class="btn sec sm tog" data-id="${r.user_id}" data-a="${r.is_active}">${r.is_active ? "Active — deactivate" : "Inactive — activate"}</button>` },
    { h: "", f: r => ["Analyst", "Admin"].includes(r.role) ? `<button class="btn sec sm pw" data-id="${r.user_id}">Reset password</button>` : "" }], rows)}</div>`;
  $("#uf").onsubmit = e => {
    e.preventDefault(); const b = { username: $("#u_name").value.trim().toLowerCase(), email: $("#u_mail").value.trim(), role: $("#u_role").value, department: $("#u_dept").value.trim(), password: $("#u_pw").value || null };
    const errs = [];
    if (!USER_RE.test(b.username)) errs.push("Username: 3–50 lowercase letters, digits, . _ - and must start with a letter.");
    if (!EMAIL_RE.test(b.email)) errs.push("Enter a valid email address.");
    if (b.department.length < 2) errs.push("Department is required.");
    if (["Analyst", "Admin"].includes(b.role) && !b.password) errs.push("Analyst/Admin accounts need an initial password.");
    if (b.password && !(b.password.length >= 8 && /\d/.test(b.password) && /[A-Za-z]/.test(b.password))) errs.push("Password: at least 8 characters with letters and digits.");
    $("#uerr").textContent = errs.join(" "); if (errs.length) return;
    safe(async () => { await api("/admin/users", { body: b }); toast("User created"); admUsers(); });
  };
  $$("#adm .tog").forEach(btn => btn.onclick = () => safe(async () => { await api(`/admin/users/${btn.dataset.id}`, { method: "PATCH", body: { is_active: btn.dataset.a !== "true" } }); toast("Updated"); admUsers(); }));
  $$("#adm .pw").forEach(btn => btn.onclick = () => { const p = prompt("Temporary password (≥ 8 chars, letters and digits). The user must change it at next sign-in, and their open sessions end now:"); if (p) safe(async () => { await api(`/admin/users/${btn.dataset.id}`, { method: "PATCH", body: { password: p } }); toast("Password reset"); }); });
}
async function admDevices() {
  const rows = await api("/admin/devices"), users = await api("/users");
  $("#adm").innerHTML = `<div class="card"><h3>Register device</h3><form id="df" class="form" novalidate>
    <label>Hostname<input id="d_host" required maxlength="80" placeholder="hr-laptop-07"></label>
    <label>IP address<input id="d_ip" required placeholder="10.1.0.50"></label>
    <label>MAC address<input id="d_mac" required placeholder="aa:bb:cc:dd:ee:ff"></label>
    <label>OS version<input id="d_os" required maxlength="60" placeholder="Windows 11 23H2"></label>
    <label>Type<select id="d_type">${["laptop", "workstation", "server", "database", "firewall"].map(t => `<option>${t}</option>`).join("")}</select></label>
    <label>Criticality (1–5)<input id="d_crit" type="number" min="1" max="5" value="2"></label>
    <label>Owner<select id="d_owner"><option value="">— none —</option>${users.map(u => `<option value="${u.user_id}">${esc(u.username)}</option>`).join("")}</select></label>
    <button class="btn">Register</button><div class="ferr" id="derr" style="grid-column:1/-1"></div></form></div><br>
    <div class="card"><h3>Devices (${rows.length})</h3>${table([{ h: "ID", k: "device_id" }, { h: "Hostname", k: "hostname" }, { h: "IP", k: "ip_address" }, { h: "MAC", k: "mac_address" }, { h: "OS", k: "os_version" }, { h: "Type", k: "device_type" }, { h: "Owner", k: "owner" }, { h: "Last seen", f: r => fmt(r.last_seen) },
    { h: "Criticality", f: r => `<select class="crit" data-id="${r.device_id}">${[1, 2, 3, 4, 5].map(n => `<option ${n == r.criticality ? "selected" : ""}>${n}</option>`).join("")}</select>` }], rows)}</div>`;
  $("#df").onsubmit = e => {
    e.preventDefault(); const b = { hostname: $("#d_host").value.trim(), ip_address: $("#d_ip").value.trim(), mac_address: $("#d_mac").value.trim().toLowerCase().replace(/-/g, ":"), os_version: $("#d_os").value.trim(), device_type: $("#d_type").value, criticality: +$("#d_crit").value, owner_id: $("#d_owner").value ? +$("#d_owner").value : null };
    const errs = [];
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{1,78}[A-Za-z0-9]$/.test(b.hostname)) errs.push("Hostname: letters, digits, hyphens (3–80).");
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(b.ip_address) || b.ip_address.split(".").some(x => +x > 255)) errs.push("Enter a valid IPv4 address.");
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(b.mac_address)) errs.push("MAC like aa:bb:cc:dd:ee:ff.");
    if (b.os_version.length < 2) errs.push("OS version is required.");
    if (!(b.criticality >= 1 && b.criticality <= 5)) errs.push("Criticality must be 1–5.");
    $("#derr").textContent = errs.join(" "); if (errs.length) return;
    safe(async () => { await api("/admin/devices", { body: b }); toast("Device registered"); admDevices(); });
  };
  $$("#adm .crit").forEach(s => s.onchange = () => safe(async () => { await api(`/admin/devices/${s.dataset.id}`, { method: "PATCH", body: { criticality: +s.value } }); toast("Criticality updated"); }));
}
async function admRules() {
  const rows = await api("/admin/rules");
  $("#adm").innerHTML = `<div class="card"><h3>Detection rules</h3><p class="mut">Each rule sets the base risk for its event category and the ML anomaly threshold for raising an alert. Changes apply to newly ingested events and are recorded in the change history.</p>
    ${table([{ h: "Rule", k: "rule_name" }, { h: "Category", k: "event_category" }, { h: "Base risk", f: r => `<input class="rb" data-id="${r.rule_id}" type="number" min="0" max="100" step="1" value="${r.base_risk}" style="width:80px">` },
    { h: "Min anomaly", f: r => `<input class="ra" data-id="${r.rule_id}" type="number" min="0" max="1" step="0.05" value="${r.min_anomaly}" style="width:80px">` },
    { h: "Active", f: r => `<input class="ron" data-id="${r.rule_id}" type="checkbox" ${r.is_active ? "checked" : ""}>` }, { h: "Alerts", k: "alerts" }, { h: "Description", k: "description" },
    { h: "", f: r => `<button class="btn sec sm rs" data-id="${r.rule_id}">Save</button>` }], rows)}</div>`;
  $$("#adm .rs").forEach(b => b.onclick = () => {
    const id = b.dataset.id, br = +$(`.rb[data-id="${id}"]`).value, ma = +$(`.ra[data-id="${id}"]`).value;
    if (!(br >= 0 && br <= 100)) return toast("Base risk must be 0–100", true);
    if (!(ma >= 0 && ma <= 1)) return toast("Min anomaly must be 0–1", true);
    safe(async () => { await api(`/admin/rules/${id}`, { method: "PATCH", body: { base_risk: br, min_anomaly: ma, is_active: $(`.ron[data-id="${id}"]`).checked } }); toast("Rule saved"); });
  });
}
async function admAuto() {
  const h = await api("/health"), a = h.automation;
  $("#adm").innerHTML = `<div class="card"><h3>Automation</h3>
    <p>The background scheduler runs <code>fn_correlate_events()</code> every <b>${a.auto_correlate_seconds}s</b> (last run ${fmt(a.last_correlation) || "—"}, result ${esc(JSON.stringify(a.last_result || {}))}).</p>
    <p>Live telemetry stream: <b>${a.stream_on ? "ON" : "off"}</b>. It has ingested ${a.stream_events} events and ${a.stream_attacks} injected attacks so far. Each batch goes through the ML scorer, into MongoDB, into PostgreSQL, then through the alert triggers.</p>
    ${a.last_error ? `<p class="err">Last error: ${esc(a.last_error)}</p>` : ""}
    <form id="af" class="form" novalidate><label>Correlate every (seconds)<input id="a_sec" type="number" min="15" max="3600" value="${a.auto_correlate_seconds}"></label>
    <label style="flex-direction:row;align-items:center;gap:6px"><input type="checkbox" id="a_on" ${a.stream_on ? "checked" : ""}> Live stream on</label><button class="btn">Apply</button></form></div><br>
    <div class="card"><h3>Evidence integrity</h3><p class="mut">Recomputes the SHA-256 of every raw MongoDB document linked to an incident and compares it with the hash PostgreSQL stored at ingest. Any edit to a raw log shows up as TAMPERED.</p>
    <button class="btn sec" id="integ">Run integrity check</button><div id="integOut"></div></div>`;
  $("#integ").onclick = () => safe(async () => { $("#integOut").innerHTML = "<p class=mut>Checking…</p>"; const r = await api("/admin/integrity");
    $("#integOut").innerHTML = `<p>Checked <b>${r.checked}</b> evidence documents: <b class="ok">${r.verified} verified</b> · <b class="${r.TAMPERED ? "err" : ""}">${r.TAMPERED} tampered</b> · ${r.missing} missing · ${r["no-raw-log"]} without raw log</p>` +
      (r.problems.length ? table([{ h: "Event", k: "event_id" }, { h: "Result", k: "result" }], r.problems) : ""); });
  $("#af").onsubmit = e => { e.preventDefault(); const s = +$("#a_sec").value; if (!(s >= 15 && s <= 3600)) return toast("Interval must be 15–3600 seconds", true);
    safe(async () => { await api("/admin/automation", { body: { on: $("#a_on").checked, correlate_every_seconds: s } }); toast("Automation updated"); admAuto(); }); };
}
async function admHistory() {
  const rows = await api("/admin/entity-audit");
  $("#adm").innerHTML = `<div class="card"><h3>Admin change history (users, devices, rules)</h3><p class="mut">Written by triggers into <code>entity_audit_log</code> (DFD process 4.0).</p>` +
    table([{ h: "When", f: r => fmt(r.changed_at) }, { h: "Table", k: "table_name" }, { h: "Row", k: "row_pk" }, { h: "Op", k: "operation" }, { h: "By", k: "changed_by" },
    { h: "Change", f: r => { const o = r.old_row || {}, n = r.new_row || {}; const ks = Object.keys({ ...o, ...n }).filter(k => JSON.stringify(o[k]) !== JSON.stringify(n[k]) && k !== "last_seen"); return esc(ks.map(k => `${k}: ${o[k] ?? "∅"} → ${n[k] ?? "∅"}`).join("; ")); } }], rows) + `</div>`;
}

// -------------------------------------------------------------- design
function design() {
  const D = [["er_diagram", "Chen ER diagram"], ["relational_schema", "Relational schema (mapping of the ER diagram)"], ["dfd_level0", "DFD level 0 (context)"], ["dfd_level1", "DFD level 1"], ["dfd_level2", "DFD level 2: Detect & Correlate (process 2.0)"]];
  $("#tab-design").innerHTML = `<div class="grid g2">
  <div class="card"><h3>Objectives</h3><ol class="steps">
    <li>Store users, devices, security events, alerts and incidents in a normalised relational schema with enforced integrity.</li>
    <li>Score every event (rules + ML) and raise alerts inside the database.</li>
    <li>Automatically correlate alerted events into multi-stage incidents with ordered timelines.</li>
    <li>Make every analyst action accountable through transactions and tamper-proof, trigger-written audit trails.</li>
    <li>Integrate MongoDB for raw logs, linked to PostgreSQL through <code>raw_log_ref</code>.</li>
    <li>Help investigators with natural-language SQL (validated, read-only), explanations, MITRE ATT&amp;CK context and reports.</li>
    <li>Evaluate detection honestly on real public traffic: CIC-IDS2017 (2.8 M labelled flows) and held-out CTU-13 botnet captures.</li></ol></div>
  <div class="card"><h3>Normalisation summary</h3>${table([{ h: "Relation", k: "r" }, { h: "Key", k: "k" }, { h: "Highest NF", k: "nf" }], [
    { r: "USERS", k: "user_id; username, email unique", nf: "BCNF" }, { r: "DEVICES", k: "device_id; hostname, mac unique", nf: "BCNF" },
    { r: "SECURITY_EVENTS", k: "event_id", nf: "BCNF (event_kind is generated from category)" }, { r: "4 event sub-type tables", k: "event_id (PK+FK)", nf: "BCNF" },
    { r: "SYSTEM_ALERTS", k: "alert_id", nf: "BCNF" }, { r: "INCIDENTS", k: "incident_id", nf: "3NF (title/risk/severity are derived, maintained by functions)" },
    { r: "INCIDENT_EVENTS", k: "(incident_id, event_id)", nf: "BCNF" }, { r: "INVESTIGATION_ACTIONS", k: "action_id", nf: "BCNF" },
    { r: "AUDIT_LOGS (weak)", k: "(incident_id, audit_id)", nf: "BCNF" }])}
    <p class="mut small">Repeating groups are split into sub-type tables (1NF). All non-key attributes depend on the whole key (2NF, including the composite-key tables). There are no transitive dependencies: for example, the device owner's department is not copied onto events (3NF). The full functional-dependency analysis is in docs/DESIGN.md.</p></div>
  <div class="card"><h3>SQL + NoSQL integration</h3><p class="mut">PostgreSQL holds structured entities, relationships, workflow and audit data. MongoDB holds the raw, variable-schema payloads: packet samples, stack traces and vendor fields. At ingest the raw document is written first. Its ObjectId goes into <code>security_events.raw_log_ref</code>, and the new SQL <code>event_id</code> is written back into the document as <code>sql_event_id</code>. Analysts can move between the two from any timeline step, and full-text search runs on MongoDB's text index.</p></div>
  <div class="card"><h3>Societal relevance</h3><p class="mut">Breaches expose citizens' personal and financial data and disrupt hospitals, banks and public services. The system shortens detection and response time and keeps a tamper-proof record of who did what, which matters for compliance with India's DPDP Act 2023 and the CERT-In 6-hour reporting directive. It also keeps AI assistance read-only and explainable, so automated advice cannot alter evidence.</p></div>
  </div><br>${D.map(([f, t]) => `<div class="card"><h3>${t}</h3><img class="diag" src="/static/diagrams/${f}.jpg" alt="${t}" loading="lazy" data-t="${t}"></div><br>`).join("")}`;
  $$(".diag").forEach(img => img.onclick = () => modal(`<h3>${esc(img.dataset.t)}</h3><img src="${img.src}" style="width:100%;background:#fff;border-radius:8px">`));
}

// --------------------------------------------------------------- guide
function guide() {
  $("#tab-guide").innerHTML = `<div class="card"><h3>How to use the console (5-minute demo)</h3><ol class="steps">
  <li><b>Sign in</b> as <code>admin.iyer</code> (password <code>Rvce@2026</code>) to inject attacks; analysts such as <code>analyst.rao</code> investigate. Click your name in the header to change your password.</li>
  <li><b>Overview:</b> read the KPIs, then (as Admin) pick a scenario such as <i>account_takeover_exfil</i> and press <b>Inject attack</b>. Its events go through the ML scorer into MongoDB and PostgreSQL. Triggers raise alerts, correlation builds an incident, and the incident opens automatically.</li>
  <li><b>Incident page:</b> read the analysis and kill chain. Walk the timeline, and open <i>raw log</i> (MongoDB document) and <i>±30 min context</i> (<code>fn_event_window</code>). Look at <b>Why this risk score?</b> to see each component computed in SQL.</li>
  <li>Press <b>Assign to me</b>. The status moves to <i>Investigating</i>, and an ASSIGN action plus audit rows appear. Record a <b>Containment</b> action, then change the status to <i>Contained</i>. Try an illegal jump: the database rejects it.</li>
  <li>Sign in as a different analyst and open the same incident. The controls are gone: only the owner or an Admin can change status, add actions or attach evidence, and analysts cannot take over a colleague's incident. Closing, resolving or marking False Positive requires a written reason.</li>
  <li><b>Containment:</b> critical incidents are contained automatically. In the incident's <b>Response &amp; containment</b> card (as Admin) press <b>🔁 Simulate the attacker returning</b>: every new attempt from the blocked IP is flagged <b>⛔ BLOCKED</b>, raises an alert and joins the same incident.</li>
  <li><b>Admin → 🛡 Security self-test:</b> one click attacks the system ten different ways and shows each one blocked, with the database's own error message.</li>
  <li><b>Download report</b> gives a Markdown incident report with summary, timeline, entities, findings, MITRE context, actions and audit trail.</li>
  <li><b>Alerts:</b> alerts raised by the trigger, grouped by detection rule. <b>Events:</b> filter raw events and click a row to open its MongoDB document.</li>
  <li><b>Ask AI:</b> try “Which users had the most failed logins?” and look at the generated SQL. Try “drop table users” to see it blocked.</li>
  <li><b>SQL Reports:</b> 15 named queries (joins, HAVING, nested and correlated sub-queries, INTERSECT/EXCEPT, window functions, CTEs, materialized view). Each can be downloaded as CSV.</li>
  <li><b>Raw Logs:</b> full-text search in MongoDB, e.g. <code>polkit</code> or <code>Emotet</code>.</li>
  <li><b>Admin</b> (admin.iyer): add a user or device (forms validate in the browser and again on the server), tune a detection rule, turn on the live stream, and read the change history.</li>
  <li><b>Audit:</b> every incident change with who and when. These rows cannot be edited or deleted, even by the application's database role.</li></ol>
  <h3>Roles</h3><p class="mut"><b>Analyst:</b> investigate, pick up unassigned incidents, and work (actions, evidence, status) only on their own. <b>Admin:</b> everything an analyst can do on any incident, plus re-assign, inject simulated attacks, run the integrity check, and manage users, devices, rules and automation. Every event is tagged <b>sensor</b>, <b>simulated</b> or <b>CTU-13 real</b>, so test data can never pass as real evidence.</p></div>`;
}

// ---------------------------------------------------------------- live
// Every few seconds: if a new alert, incident or block appeared, show a banner
// and refresh list pages (never a page where the user may be typing).
let LIVE = null, LIVE_TIMER = null;
function banner(html, kind) {
  const b = $("#live"); b.className = kind || ""; b.innerHTML = html; b.hidden = false;
  clearTimeout(banner.h); banner.h = setTimeout(() => b.hidden = true, 9000);
  b.querySelectorAll("a[data-inc]").forEach(a => a.onclick = e => { e.preventDefault(); b.hidden = true; show("incidents"); safe(() => incidentDetail(+a.dataset.inc)); });
}
async function livePoll() {
  if (!TOKEN || $("#app").hidden || document.hidden) return;
  let now; try { now = await api("/live"); } catch { return; }
  if (LIVE) {
    const inc = now.latest_incident, blk = now.latest_block;
    if (now.last_block > LIVE.last_block && blk) {
      banner(`🛡 <b>Contained automatically:</b> ${blk.entity_type === "ip" ? "attacker IP" : "account"} <b>${esc(blk.entity)}</b> blocked ${blk.incident_id ? `— <a href="#" data-inc="${blk.incident_id}">incident #${blk.incident_id}</a>` : ""}`, "ok");
    } else if (now.blocked_attempts > LIVE.blocked_attempts) {
      banner(`⛔ <b>${now.blocked_attempts - LIVE.blocked_attempts} attacker attempt(s) blocked</b>${inc ? ` — <a href="#" data-inc="${inc.incident_id}">incident #${inc.incident_id}</a>` : ""}`, "bad");
    } else if (now.last_incident > LIVE.last_incident && inc) {
      banner(`🔴 <b>New incident #${inc.incident_id}:</b> ${esc(inc.title)} — ${esc(inc.severity_level)} · <a href="#" data-inc="${inc.incident_id}">open</a>`, "bad");
    } else if (now.last_alert > LIVE.last_alert) {
      banner(`⚠ <b>${now.last_alert - LIVE.last_alert} new alert(s)</b>${inc ? ` — <a href="#" data-inc="${inc.incident_id}">incident #${inc.incident_id}</a> · ${esc(inc.severity_level)}, risk ${inc.risk_score}` : ""}`, "warn");
    }
    const changed = now.last_alert !== LIVE.last_alert || now.last_block !== LIVE.last_block || now.blocked_attempts !== LIVE.blocked_attempts;
    if (changed && ["overview", "alerts", "incidents", "events", "audit"].includes(VIEW)) safe(() => loaders[VIEW]());
    if (changed && VIEW.startsWith("incident:") && !document.activeElement.matches("input,textarea,select"))
      safe(() => incidentDetail(+VIEW.split(":")[1]));
  }
  LIVE = now;
}

// ---------------------------------------------------------------- boot
function passwordForm(forced) {
  return `<form id="pwForm" class="form" novalidate>
    ${forced ? `<p style="grid-column:1/-1">Your password was set by an administrator. Choose a new one to continue.</p>` : ""}
    <label>Current password<input id="pw0" type="password" autocomplete="current-password"></label>
    <label>New password<input id="pw1" type="password" autocomplete="new-password" placeholder="8+ chars, letters and digits"></label>
    <label>Repeat new password<input id="pw2" type="password" autocomplete="new-password"></label>
    <button class="btn">Change password</button><div class="ferr" id="pwerr" style="grid-column:1/-1"></div></form>`;
}
function bindPasswordForm(after) {
  $("#pwForm").onsubmit = e => {
    e.preventDefault(); const a = $("#pw0").value, b = $("#pw1").value, c = $("#pw2").value; $("#pwerr").textContent = "";
    if (!a) return $("#pwerr").textContent = "Enter your current password.";
    if (!(b.length >= 8 && /\d/.test(b) && /[A-Za-z]/.test(b))) return $("#pwerr").textContent = "New password: at least 8 characters with letters and digits.";
    if (b !== c) return $("#pwerr").textContent = "The new passwords do not match.";
    if (a === b) return $("#pwerr").textContent = "The new password must be different.";
    api("/me/password", { body: { current_password: a, new_password: b } })
      .then(r => { TOKEN = r.token; store.set("token", TOKEN); toast("Password changed. Other sessions were signed out."); after(); })
      .catch(err => $("#pwerr").textContent = err.message);
  };
}
async function boot() {
  TOKEN = TOKEN || store.get("token");
  if (!TOKEN) return showLogin();
  try { ME = await api("/me"); } catch { return showLogin(); }
  if (ME.must_change) {
    $("#app").hidden = true; $("#login").hidden = false;
    $("#loginForm").hidden = true;
    let box = $("#pwBox"); if (!box) { box = document.createElement("div"); box.id = "pwBox"; box.className = "card loginCard"; $("#login").appendChild(box); }
    box.hidden = false; box.innerHTML = `<div class="brand big">Set a new password</div>` + passwordForm(true);
    bindPasswordForm(() => { box.hidden = true; $("#loginForm").hidden = false; boot(); });
    return;
  }
  $("#login").hidden = true; $("#app").hidden = false;
  $("#whoami").innerHTML = `<a href="#" id="chpw" title="Click to change your password"><b>${esc(ME.username)}</b> <span class="mut">${esc(ME.role)}</span></a>`;
  $("#chpw").onclick = e => { e.preventDefault(); modal(`<h3>Change password</h3>` + passwordForm(false)); bindPasswordForm(() => { $("#modal").hidden = true; }); };
  $$(".adminOnly").forEach(b => b.hidden = ME.role !== "Admin");
  STAFF = (await api("/users")).filter(u => ["Analyst", "Admin"].includes(u.role));
  api("/health").then(h => $("#health").innerHTML = `<span class="dot"></span> System online<br><span class="mut">PostgreSQL · ${esc(h.raw_store === "mongodb" ? "MongoDB" : h.raw_store)}<br>AI: ${esc(h.llm.replace(/ \(.*\)/, ""))}</span>`).catch(() => { });
  let tab = store.get("tab") || "overview"; if (tab === "admin" && ME.role !== "Admin") tab = "overview";
  show(tab);
  LIVE = null; livePoll(); clearInterval(LIVE_TIMER); LIVE_TIMER = setInterval(livePoll, 3000);
}
boot();
