// Crypto Lab: token inspector, live attack lab and the transparency log, all backed by the real verifier.
import { api, fetchBlob } from "./api.js";
import { isAuthenticated, renderGate } from "./auth.js";
import { entryBytes, hex, leafHash, unhex, verifyConsistency, verifyInclusion, verifyTreeHead } from "./merkle.js";
import { scanBlob } from "./scan.js";
import { $, el, fmtTime, icon, safeStorage, toast } from "./util.js";

const store = safeStorage();
const STATE_ICON = { pass: "check", fail: "block", skipped: "info", info: "info" };
const STATUS_CLASS = { valid: "safe", none: "", expired: "warn" };
const short = (h, n = 14) => (h && h.length > 2 * n ? `${h.slice(0, n)}...${h.slice(-6)}` : h);

// ---------------------------------------------------------------- 1. token inspector
function factRows(facts) {
  return Object.entries(facts || {}).filter(([, v]) => v !== null && v !== undefined && v !== "")
    .flatMap(([k, v]) => [el("dt", { text: k.replace(/_/g, " ") }), el("dd", { class: "mono wrap-any", text: Array.isArray(v) ? v.join(", ") : String(v) })]);
}

function renderTrace(t) {
  const out = $("#inspect-result");
  const steps = t.steps.map((s, n) => el("li", { class: `trace-step st-${s.state}` },
    el("span", { class: "trace-n", text: String(n + 1) }),
    el("div", { class: "trace-body" },
      el("div", { class: "trace-title" }, icon(STATE_ICON[s.state] || "info"), el("strong", { text: s.title }),
        el("span", { class: `chip ${s.state === "pass" ? "safe" : s.state === "fail" ? "block" : ""}`, text: s.state === "skipped" ? "not reached" : s.state })),
      el("p", { class: "muted small", text: s.why }),
      Object.keys(s.facts || {}).length ? el("details", { class: "more" }, el("summary", { text: "What it looked at" }), el("dl", { class: "kv" }, factRows(s.facts))) : null)));
  out.replaceChildren(
    el("div", { class: "trace-head" },
      el("span", { class: `chip lg ${STATUS_CLASS[t.status] ?? "block"}`, text: t.status.replace("_", " ").toUpperCase() }),
      el("span", { class: "muted small", text: t.decided_at ? `Decided at step "${t.decided_at}"` : t.status === "none" ? "No signature to check" : "Every check passed" }),
      el("span", { class: `chip ${t.agrees ? "safe" : "block"}`, title: "The replayed steps reach the same conclusion as the real verifier", text: t.agrees ? "matches the live verifier" : "MISMATCH" })),
    el("ol", { class: "trace" }, steps));
  out.hidden = false;
}

export async function inspect(payload) {
  $("#inspect-input").value = payload;
  try {
    renderTrace(await api("/api/registry/inspect", { method: "POST", json: { payload: payload.trim() } }));
  } catch (e) { toast(e.message, "err"); }
}

async function loadSample() {
  if (!(await isAuthenticated().catch(() => false))) { toast("Sign in as admin to mint a sample, or paste any signed link.", "err"); return; }
  const issuers = await api("/api/registry/issuers");
  const i = issuers.find((x) => !x.is_revoked);
  if (!i) { toast("No active issuer to sign with.", "err"); return; }
  const r = await api("/api/admin/sign", { method: "POST", admin: true, json: { issuer_id: i.issuer_id, url: `https://${i.domain}/m/42`, location_id: "lab-sample", validity_hours: 48 } });
  await inspect(r.signed_url);
}

// ---------------------------------------------------------------- 2. attack lab
async function scanAttack(payload, id) {
  const blob = await fetchBlob(`/api/demo/render-qr?text=${encodeURIComponent(payload)}`);
  location.hash = "#/scan";
  await scanBlob(blob, `attack-${id}.png`);
}

function renderAttacks(res) {
  const s = res.summary;
  const rows = res.results.map((r) => el("tr", { class: r.id === "genuine" ? "row-control" : "" },
    el("td", {}, el("strong", { text: r.title }), el("div", { class: "muted small", text: r.how }), el("div", { class: "muted small", text: `Attacker: ${r.attacker}` })),
    el("td", {}, el("span", { class: `chip ${STATUS_CLASS[r.actual] ?? "block"}`, text: r.actual.replace("_", " ") }),
      el("div", { class: "muted small", text: r.id === "genuine" ? "accepted (control)" : r.accepted ? "ACCEPTED - broken!" : r.actual === "none" ? "downgraded to unsigned" : "rejected" })),
    el("td", { class: "small", text: r.decided_at ? `step: ${r.decided_at}` : "-" }),
    el("td", { class: "actions" }, el("div", { class: "action-wrap" },
      el("button", { class: "btn sm ghost", type: "button", onclick: () => { inspect(r.payload); $("#inspect-card").scrollIntoView({ behavior: "smooth" }); } }, "Inspect"),
      el("button", { class: "btn sm secondary", type: "button", onclick: () => scanAttack(r.payload, r.id).catch((e) => toast(e.message, "err")) }, icon("qr"), "Scan its QR")))));
  $("#attack-result").replaceChildren(
    el("div", { class: `notice ${s.all_as_expected ? "info" : "warn"}` },
      el("strong", { text: `${s.rejected} of ${s.attacks} forged codes were not accepted as genuine.` }),
      el("p", { text: "Each row was built the way an attacker with that capability would, then pushed through the same verifier a real scan uses." })),
    el("div", { class: "table-wrap" }, el("table", { class: "table" },
      el("thead", {}, el("tr", {}, ["Attack", "Verifier says", "Stopped by", ""].map((h) => el("th", { text: h })))), el("tbody", {}, rows))));
  $("#attack-result").hidden = false;
}

async function runAttacks() {
  const btn = $("#attack-run");
  btn.disabled = true;
  try {
    renderAttacks(await api("/api/admin/lab/attacks", { method: "POST", admin: true, json: { issuer_id: $("#attack-issuer").value } }));
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; }
}

async function enterAttackLab() {
  const gate = $("#attack-gate"), body = $("#attack-body");
  if (!(await isAuthenticated().catch(() => false))) {
    body.hidden = true;
    renderGate(gate, "Attack lab", enterAttackLab);
    return;
  }
  gate.hidden = true;
  body.hidden = false;
  const issuers = (await api("/api/registry/issuers")).filter((i) => !i.is_revoked);
  $("#attack-issuer").replaceChildren(...issuers.map((i) => el("option", { value: i.issuer_id, text: `${i.name} (${i.domain})` })));
}

// ---------------------------------------------------------------- 3. transparency log
let snapshot = null;
const SEEN_KEY = "qrshield.log.seen";
function seenHead() { try { return JSON.parse(store?.getItem(SEEN_KEY) || "null"); } catch { return null; } }
function rememberHead(head) { try { store?.setItem(SEEN_KEY, JSON.stringify({ size: head.size, root_hash: head.root_hash, timestamp: head.timestamp })); } catch { /* optional */ } }

function proofView(p, steps, ok, tampered) {
  const out = $("#log-proof");
  out.replaceChildren(
    el("div", { class: `notice ${ok ? "info" : "warn"}` },
      el("strong", { text: ok ? `Entry #${p.index} is in the log.` : tampered ? "The edited entry does NOT match the log - tampering detected." : "Proof failed." }),
      el("p", { text: ok ? `Recomputed in your browser: ${steps.length} ${steps.length === 1 ? "hash leads" : "hashes lead"} from this entry to the signed root.` : "The hash chain no longer reaches the root the registry signed." })),
    el("ol", { class: "trace" }, [
      el("li", { class: "trace-step st-pass" }, el("span", { class: "trace-n", text: "0" }), el("div", { class: "trace-body" }, el("strong", { text: "Leaf = SHA-256(0x00 || entry)" }), el("p", { class: "mono small wrap-any", text: p.computedLeaf }))),
      ...steps.map((s, n) => el("li", { class: "trace-step st-pass" }, el("span", { class: "trace-n", text: String(n + 1) }),
        el("div", { class: "trace-body" }, el("strong", { text: `SHA-256(0x01 || ...) with ${s.side}` }), el("p", { class: "mono small wrap-any", text: `sibling ${short(s.sibling, 10)}  ->  ${short(s.result, 10)}` })))),
      el("li", { class: `trace-step ${ok ? "st-pass" : "st-fail"}` }, el("span", { class: "trace-n", text: "=" }),
        el("div", { class: "trace-body" }, el("strong", { text: `Signed root ${ok ? "matches" : "does not match"}` }), el("p", { class: "mono small wrap-any", text: p.root_hash }))),
    ]));
  out.hidden = false;
}

async function verifyEntry(index, tamper) {
  try {
    const p = await api(`/api/registry/log/proof/${index}`);
    const entry = tamper ? { ...p.entry, detail: `${p.entry.detail} (edited later)` } : p.entry;
    const leaf = await leafHash(entryBytes(entry));
    const res = await verifyInclusion(leaf, p.index, p.size, p.path.map(unhex), unhex(p.root_hash));
    proofView({ ...p, computedLeaf: hex(leaf) }, res.steps, res.ok, tamper);
  } catch (e) { toast(e.message, "err"); }
}

async function checkAppendOnly() {
  const prev = seenHead();
  const out = $("#log-consistency");
  if (!prev) { out.textContent = "Nothing remembered yet. This browser now remembers today's log head; change something in the Issuer portal and check again."; rememberHead(snapshot.head); return; }
  try {
    const c = await api(`/api/registry/log/consistency?first=${prev.size}`);
    const ok = (await verifyConsistency(prev.size, c.second, unhex(prev.root_hash), unhex(c.second_root), c.path.map(unhex)))
      && c.first_root === prev.root_hash;
    out.replaceChildren(el("span", { class: `chip ${ok ? "safe" : "block"}`, text: ok ? "append-only" : "HISTORY CHANGED" }),
      ` The log you saw with ${prev.size} entries ${ok ? `is an exact prefix of today's ${c.second}-entry log (${c.path.length} hashes of proof, checked here).` : "is NOT a prefix of today's log."}`);
    if (ok) rememberHead(snapshot.head);
  } catch (e) { out.textContent = e.message; }
}

async function loadLog() {
  snapshot = await api("/api/registry/log");
  const h = snapshot.head;
  const sig = await verifyTreeHead(h, snapshot.root_public_key);
  $("#log-head").replaceChildren(el("dl", { class: "kv" },
    el("dt", { text: "Entries" }), el("dd", { text: String(h.size) }),
    el("dt", { text: "Merkle root" }), el("dd", { class: "mono small wrap-any", text: h.root_hash }),
    el("dt", { text: "Signed at" }), el("dd", { text: fmtTime(h.timestamp) }),
    el("dt", { text: "Root signature" }), el("dd", {}, el("span", { class: `chip ${sig === false ? "block" : "safe"}`,
      text: sig === true ? "Ed25519 verified in your browser" : sig === null ? "signed by the pinned root (this browser lacks Ed25519)" : "INVALID" }))));
  $("#log-table tbody").replaceChildren(...snapshot.entries.map((e) => el("tr", {},
    el("td", { text: String(e.index) }), el("td", { class: "small", text: fmtTime(e.time) }),
    el("td", {}, el("span", { class: "chip", text: e.action.replace("issuer.", "") })),
    el("td", { class: "mono small wrap-any", text: e.subject }), el("td", { class: "small wrap-any", text: e.detail }),
    el("td", { class: "actions" }, el("div", { class: "action-wrap" },
      el("button", { class: "btn sm secondary", type: "button", onclick: () => verifyEntry(e.index, false) }, "Verify"),
      el("button", { class: "btn sm ghost", type: "button", title: "Pretend someone rewrote this entry afterwards", onclick: () => verifyEntry(e.index, true) }, "Edit & verify"))))));
}

// ---------------------------------------------------------------- wiring
export function initLab() {
  $("#inspect-form").addEventListener("submit", (ev) => { ev.preventDefault(); inspect($("#inspect-input").value); });
  $("#inspect-sample").addEventListener("click", () => loadSample().catch((e) => toast(e.message, "err")));
  $("#attack-run").addEventListener("click", runAttacks);
  $("#log-refresh").addEventListener("click", () => loadLog().catch((e) => toast(e.message, "err")));
  $("#log-consistency-btn").addEventListener("click", () => checkAppendOnly());
}

export async function enterLab() {
  await Promise.all([enterAttackLab().catch(() => {}), loadLog().catch((e) => toast(e.message, "err"))]);
}
