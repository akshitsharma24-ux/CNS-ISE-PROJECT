// Admin view: statistics, report review queue, model retraining with the benchmark gate, audit trail.
import { api } from "./api.js";
import { isAuthenticated, renderGate } from "./auth.js";
import { $, $$, el, fmtTime, toast } from "./util.js";

let filter = "pending";
let pollTimer = null;

function stat(value, label) {
  return el("div", { class: "stat" }, el("b", { text: String(value ?? "-") }), el("span", { text: label }));
}

async function loadOverview() {
  const o = await api("/api/admin/overview", { admin: true });
  const s = o.stats;
  $("#stat-row").replaceChildren(
    stat(s.scans_total, "scans logged"),
    stat(s.by_verdict.SAFE || 0, "safe"), stat(s.by_verdict.SUSPICIOUS || 0, "suspicious"), stat(s.by_verdict.BLOCK || 0, "blocked"),
    stat(s.reports_pending, "reports pending"),
    stat(s.latency_ms_p50 !== null ? `${s.latency_ms_p50} ms` : "-", "median scan time"),
    stat(s.latency_ms_p95 !== null ? `${s.latency_ms_p95} ms` : "-", "95th percentile"));
}

const HEALTH_CHIP = { stable: ["safe", "Stable"], moderate_shift: ["warn", "Moderate shift"], significant_shift: ["block", "Significant shift"], insufficient_data: ["", "Not enough data"] };

function histogram(values, cls) {
  const peak = Math.max(...values, 0.01);
  return el("div", { class: `hist ${cls}`, role: "img", "aria-label": `Score histogram: ${values.map((v) => `${Math.round(v * 100)}%`).join(", ")}` },
    values.map((v) => { const bar = el("span", { title: `${Math.round(v * 100)}%` }); bar.style.height = `${Math.max(v / peak, 0.02) * 100}%`; return bar; }));
}

async function loadHealth() {
  $("#health-body").textContent = "Measuring the reference distribution (first time only, ~15 s)...";
  const h = await api("/api/admin/model-health", { admin: true });
  const [cls, label] = HEALTH_CHIP[h.status] || ["", h.status];
  const chip = $("#health-chip");
  chip.className = `chip ${cls}`.trim();
  chip.textContent = h.psi !== null ? `${label} - PSI ${h.psi}` : label;
  const rows = [["Recent web-link scans", h.n_recent]];
  if (h.psi !== null) {
    rows.push(["Mean link risk (recent vs benchmark)", `${h.recent.mean} vs ${h.reference.mean}`], ["Share flagged >= 0.5", `${Math.round(h.recent.flagged_share * 100)}%`]);
  }
  $("#health-body").replaceChildren(
    el("div", { class: "hist-pair" },
      el("div", {}, histogram(h.reference.histogram, "ref"), el("small", { text: "benchmark (0 to 1)" })),
      el("div", {}, histogram(h.recent.histogram, "cur"), el("small", { text: "recent scans" }))),
    el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: String(v) })])),
    el("p", { class: "muted small", text: h.message }));
}

function labelChip(label) {
  return el("span", { class: `chip ${label === "benign" ? "safe" : "block"}`, text: label });
}

async function loadReports() {
  const rows = await api(`/api/admin/reports?status=${filter}`, { admin: true });
  const tbody = $("#report-table tbody");
  if (!rows.length) {
    tbody.replaceChildren(el("tr", {}, el("td", { class: "none", colSpan: 5, text: `No ${filter} reports.` })));
    return;
  }
  tbody.replaceChildren(...rows.map((r) => el("tr", {},
    el("td", { class: "url", text: r.url }),
    el("td", {}, labelChip(r.user_label)),
    el("td", {}, r.verdict_at_report ? el("span", { class: "chip", text: r.verdict_at_report }) : "-"),
    el("td", { class: "small", text: r.note || "-" }),
    el("td", { class: "actions" }, r.status === "pending" ? [
      el("button", { class: "btn sm secondary", type: "button", onclick: () => review(r.report_id, "approve") }, "Approve"), " ",
      el("button", { class: "btn sm ghost", type: "button", onclick: () => review(r.report_id, "reject") }, "Reject"),
    ] : el("span", { class: "muted small", text: r.used_in_model ? `used in ${r.used_in_model}` : r.status })))));
}

async function review(id, action) {
  try {
    await api(`/api/admin/reports/${id}/review`, { method: "POST", json: { action }, admin: true });
    toast(action === "approve" ? "Approved - eligible for the next retrain" : "Rejected");
    await Promise.all([loadReports(), loadOverview()]);
  } catch (e) { toast(e.message, "err"); }
}

async function loadModels() {
  const m = await api("/api/admin/models", { admin: true });
  $("#model-active").textContent = `active ${m.active.url}`;
  const tbody = $("#model-table tbody");
  const rows = m.history;
  tbody.replaceChildren(...(rows.length ? rows.map((h) => el("tr", {},
    el("td", { class: "mono small", text: h.version }),
    el("td", {}, el("span", { class: `chip ${h.status === "active" ? "safe" : "block"}`, text: h.status })),
    el("td", { text: h.metrics.roc_auc ?? "-" }),
    el("td", { text: h.metrics.fpr ?? "-" }),
    el("td", { class: "small", text: h.note || "" }))) : [el("tr", {}, el("td", { class: "none", colSpan: 5, text: "No retraining runs yet. Approve some reports, then retrain." }))]));

  const status = $("#retrain-status");
  const btn = $("#retrain-btn");
  if (m.retrain.running) {
    status.replaceChildren(el("span", { class: "spinner" }), " Retraining and running the benchmark gate...");
    btn.disabled = true;
    schedulePoll();
  } else {
    btn.disabled = false;
    const last = m.retrain.last;
    status.textContent = last?.error ? `Failed: ${last.error}`
      : last ? (last.promoted ? `Promoted ${last.version}` : `Rejected ${last.version} - the gate protected the live model`) : "";
  }
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(() => loadModels().then(loadOverview).catch(() => {}), 2000);
}

async function loadAudit() {
  const rows = await api("/api/admin/audit", { admin: true });
  $("#audit-list").replaceChildren(...rows.map((a) => el("li", {},
    el("time", { text: fmtTime(a.created_at) }),
    el("span", {}, el("strong", { text: a.action }), ` ${a.subject}`, a.detail ? el("span", { class: "muted", text: ` - ${a.detail}` }) : null))));
}

async function retrain() {
  try {
    const r = await api("/api/admin/retrain", { method: "POST", admin: true });
    toast(r.message, r.started ? "ok" : "warn");
    await loadModels();
  } catch (e) { toast(e.message, "err"); }
}

export function initAdmin() {
  $$("#report-filter .seg-btn").forEach((b) => b.addEventListener("click", () => {
    filter = b.dataset.status;
    $$("#report-filter .seg-btn").forEach((x) => x.classList.toggle("is-active", x === b));
    loadReports().catch((e) => toast(e.message, "err"));
  }));
  $("#retrain-btn").addEventListener("click", retrain);
}

export function leaveAdmin() { clearTimeout(pollTimer); }

export async function enterAdmin() {
  const gate = $("#admin-gate"), body = $("#admin-body");
  if (!(await isAuthenticated().catch(() => false))) {
    body.hidden = true;
    renderGate(gate, "Admin console", enterAdmin);
    return;
  }
  gate.hidden = true;
  body.hidden = false;
  try { await Promise.all([loadOverview(), loadReports(), loadModels(), loadAudit()]); } catch (e) { toast(e.message, "err"); }
  loadHealth().catch((e) => { $("#health-body").textContent = e.message; });
}
