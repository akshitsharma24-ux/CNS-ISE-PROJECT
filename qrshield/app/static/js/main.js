// Entry point: hash router, theme, health chip, "How it works" results.
import { api } from "./api.js";
import { enterArchitecture, initArchitecture } from "./architecture.js";
import { enterAdmin, initAdmin, leaveAdmin } from "./admin.js";
import { enterIssuer, initIssuer } from "./issuer.js";
import { enterLab, initLab } from "./lab.js";
import { initScan, leaveScan } from "./scan.js";
import { $, $$, el, safeStorage } from "./util.js";

const VIEWS = ["home", "scan", "issuer", "lab", "admin", "how", "security", "faq", "about"];
const store = safeStorage();
let current = null;

function route() {
  const name = (location.hash.replace(/^#\/?/, "") || "home").split("/")[0];
  const view = VIEWS.includes(name) ? name : "home";
  if (current === "scan" && view !== "scan") leaveScan();
  if (current === "admin" && view !== "admin") leaveAdmin();
  current = view;
  $$("[data-view]").forEach((s) => { s.hidden = s.dataset.view !== view; });
  $$("[data-nav]").forEach((a) => a.classList.toggle("is-active", a.dataset.nav === view));
  if (view === "issuer") enterIssuer();
  if (view === "lab") enterLab();
  if (view === "admin") enterAdmin();
  if (view === "how") { loadResults(); enterArchitecture(); }
  window.scrollTo({ top: 0 });
}

// ---------------------------------------------------------------- theme
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
}
function initTheme() {
  const saved = store?.getItem("qrshield.theme");
  if (saved) applyTheme(saved);
  $("#theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme === "dark";
    const next = dark ? "light" : "dark";
    applyTheme(next);
    store?.setItem("qrshield.theme", next);
  });
}

// ---------------------------------------------------------------- health + results
async function loadHealth() {
  try {
    const h = await api("/api/health");
    $("#model-chip").textContent = `link ${h.models.url} | visual ${h.models.cv}`;
  } catch {
    $("#model-chip").textContent = "server offline";
  }
}

function pct(x) { return x === null || x === undefined ? "-" : `${(x * 100).toFixed(1)}%`; }

function table(rows, head) {
  return el("table", {}, head ? el("thead", {}, el("tr", {}, head.map((h) => el("th", { text: h })))) : null,
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", { text: String(c) }))))));
}

async function loadResults() {
  const box = $("#results-box");
  try {
    const r = await api("/api/results");
    const parts = [];
    if (r.url) {
      const t = r.url;
      parts.push(el("div", {}, el("h4", { text: "Link model (M1) - real public phishing corpora" }),
        table([
          ["Domain-disjoint test", t.domain_disjoint_test.roc_auc, pct(t.domain_disjoint_test.recall), pct(t.domain_disjoint_test.fpr)],
          ["External corpus (never trained on)", t.external_pirocheto.roc_auc, pct(t.external_pirocheto.recall), pct(t.external_pirocheto.fpr)],
        ], ["Evaluation", "ROC-AUC", "Recall@0.5", "FPR@0.5"]),
        el("p", { class: "muted small", text: `Recall on ${t.recent_phishing_recall.n.toLocaleString()} phishing links from 2026 feeds: ${pct(t.recent_phishing_recall["recall_at_0.5"])} (threshold 0.5).` })));
    }
    if (r.cv) {
      const c = r.cv;
      parts.push(el("div", {}, el("h4", { text: `Sticker check (M2) - ${c.n_real_photos ? "simulated + real" : "SIMULATED"} photos` }),
        table([
          ["Leave-one-surface-out", c.leave_one_surface_out.roc_auc, pct(c.leave_one_surface_out.recall), pct(c.leave_one_surface_out.false_positive_rate)],
          ["Group k-fold by session", c.group_5fold_by_session.roc_auc, pct(c.group_5fold_by_session.recall), pct(c.group_5fold_by_session.false_positive_rate)],
        ], ["Protocol", "ROC-AUC", "Recall", "FPR"]),
        el("p", { class: "muted small", text: "Per-style detail, including the styles it cannot catch (a perfectly fitted sticker), is in docs/evaluation.md. Simulated data measures the algorithm, not real-world accuracy." })));
    }
    if (!parts.length) parts.push(el("p", { class: "muted", text: "Run `make evaluate` to generate results." }));
    box.replaceChildren(...parts);
  } catch {
    box.textContent = "Results are not available yet.";
  }
}

// ---------------------------------------------------------------- boot
initTheme();
initScan();
initIssuer();
initLab();
initAdmin();
initArchitecture();
window.addEventListener("hashchange", route);
route();
loadHealth();
