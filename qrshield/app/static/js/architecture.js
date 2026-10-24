// Interactive system architecture: click any component for what it does, where it lives and what it hands on;
// "Run a sample scan" pushes a real photo through the live pipeline and lights up each stage with its measured time.
import { api, fetchBlob } from "./api.js";
import { $, el, icon } from "./util.js";

const STAGES = {
  input: { badge: "IN", cls: "m0", icon: "camera", title: "Photo, camera or link", sub: "what the user provides",
    where: "app/static/js/scan.js, camera.js, image.js", in: "image upload, live frame or typed link", out: "image bytes (never stored) or text",
    notes: ["Images are downscaled and size-limited in the browser first, then limited again on the server.", "Nothing is written to disk: photos are analysed in memory."] },
  decode: { badge: "M0", cls: "m0", icon: "qr", title: "Capture & decode", sub: "read the code safely", timing: "decode",
    where: "qrshield/capture/", in: "image bytes", out: "payload, corners, quality report, other codes in frame",
    notes: ["zxing-cpp is the primary decoder with OpenCV fallbacks.", "Pixel and size limits are enforced before decoding, so a decompression bomb cannot exhaust memory.", "A quality gate refuses blurred or glared photos instead of guessing.", "Overlapping QR patterns (a code stacked on a code) are flagged here."] },
  url: { badge: "M1", cls: "m1", icon: "link", title: "Link analysis", sub: "look-alike and scam links", timing: "url",
    where: "qrshield/url_layer/", in: "decoded payload", out: "risk 0..1 plus plain-language signals",
    notes: ["Calibrated LightGBM on structured URL features, blended with a hashed character n-gram model.", "Brand-impersonation rules compare against official registered domains; UPI payee checks catch mismatched payees.", "Shorteners are inspected with an SSRF-safe fetch: one DNS resolution, public IPs only, redirects re-validated."] },
  visual: { badge: "M2", cls: "m2", icon: "camera", title: "Sticker check", sub: "pasted-over physical codes", timing: "visual",
    where: "qrshield/cv_layer/", in: "image + code corners", out: "calibrated tamper probability, evidence overlay",
    notes: ["The photo is rectified onto the QR plane, then 48 physical features are measured: sticker edges, shadow, paper colour, grain, gloss, hidden-code fragments.", "A calibrated LightGBM scores them; the evidence overlay draws only what was measured.", "An opt-in occlusion map shows where the model looked."] },
  crypto: { badge: "M3", cls: "m3", icon: "key", title: "Signature check", sub: "who issued this exact code", timing: "crypto",
    where: "qrshield/crypto_layer/", in: "decoded payload + trust store", out: "none, valid, invalid, unknown issuer, revoked, expired or domain mismatch",
    notes: ["Ed25519 token in the URL, checked against a pinned root key through a root-signed issuer certificate.", "Domain binding, a signed and versioned revocation list, key rotation.", "Fail-closed: no pinned root means nothing verifies. The signature is checked before expiry or domain."] },
  engine: { badge: "M4", cls: "m4", icon: "shield", title: "Decision engine", sub: "rules first, scores second", timing: "engine",
    where: "qrshield/engine/decide.py", in: "link risk, tamper probability, signature status", out: "SAFE, SUSPICIOUS or BLOCK, risk, up to three reasons",
    notes: ["Cryptographic facts decide before any score: a valid signature is certified, a failed one blocks.", "Unsigned codes are fused with noisy-OR; visual evidence alone can never BLOCK.", "Every verdict ships with its working."] },
  verdict: { badge: "UI", cls: "m5", icon: "eye", title: "Verdict, shown before opening", sub: "never opens automatically",
    where: "qrshield/app/static/", in: "engine decision + layer details", out: "verdict, reasons, three layer cards, safe-open flow",
    notes: ["Strict CSP with no inline script; all dynamic text goes through textContent.", "BLOCK hides the open button behind an explicit override."] },
};

const SERVICES = {
  registry: { badge: "DB", cls: "svc", icon: "lock", title: "Registry", where: "qrshield/registry/service.py", sub: "SQLite",
    in: "issuer registrations, revocations, scan telemetry", out: "certificates, signed CRLs, audit trail",
    notes: ["Holds issuers, certificates, the CRL history, anonymous telemetry (hashes and timings only) and an append-only audit log.", "Every certificate event also becomes a leaf of the transparency log."] },
  keys: { badge: "KEY", cls: "svc", icon: "key", title: "Root key & key store", where: "qrshield/registry/keystore.py", sub: "root signs certs, CRL, log head",
    in: "signing requests", out: "signatures",
    notes: ["The root private key lives in a 0600 file in the runtime home and is never committed; only its public half is pinned in the verifier.", "In production it would sit offline or in an HSM."] },
  models: { badge: "ML", cls: "svc", icon: "info", title: "Model store", where: "qrshield/model_store.py", sub: "versioned artefacts",
    in: "trained link and sticker models", out: "active model versions",
    notes: ["Bundled models plus versions promoted by the retrain gate. Models are stored as portable arrays and text, not pickled library objects.", "The admin page watches score drift (PSI) against the benchmark."] },
  log: { badge: "LOG", cls: "svc", icon: "check", title: "Transparency log", where: "qrshield/crypto_layer/transparency.py", sub: "Merkle tree, signed head",
    in: "certificate events", out: "inclusion and consistency proofs",
    notes: ["RFC 6962-style Merkle tree over every registration, revocation, restore and rotation.", "Your browser can recompute proofs itself in the Crypto lab."] },
  loop: { badge: "ML", cls: "svc", icon: "flag", title: "Report, review, retrain", where: "qrshield/retrain.py", sub: "human-gated learning",
    in: "user reports", out: "a promoted or rejected link model",
    notes: ["Only reports a person approves can reach training.", "A retrained model must beat the live one on a fixed benchmark and get canary links right, otherwise it is rejected."] },
};

let selected = "decode";
let timingMs = null;
let busy = false;

function nodeButton(key, def) {
  const btn = el("button", { class: `arch-node ${def.cls}`, type: "button", dataset: { node: key }, "aria-pressed": key === selected ? "true" : "false" },
    el("span", { class: `badge ${def.cls}`, text: def.badge }),
    el("span", { class: "arch-text" }, el("strong", { text: def.title }), el("small", { text: def.sub })),
    def.timing ? el("span", { class: "arch-ms", dataset: { ms: def.timing }, hidden: true }) : null);
  btn.addEventListener("click", () => select(key));
  return btn;
}

function select(key) {
  selected = key;
  for (const b of document.querySelectorAll("#arch-diagram .arch-node")) b.setAttribute("aria-pressed", String(b.dataset.node === key));
  const d = STAGES[key] || SERVICES[key];
  const rows = [["Code", d.where], ["Takes in", d.in], ["Hands on", d.out]];
  $("#arch-detail").replaceChildren(
    el("div", { class: "arch-detail-head" }, el("span", { class: `badge ${d.cls}`, text: d.badge }), el("h3", { text: d.title }),
      d.timing && timingMs?.[d.timing] !== undefined ? el("span", { class: "chip", text: `${timingMs[d.timing]} ms on the last scan` }) : null),
    el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { class: k === "Code" ? "mono small" : "", text: v })])),
    el("ul", { class: "arch-notes" }, d.notes.map((n) => el("li", { text: n }))));
}

function arrow(label) {
  return el("div", { class: "arch-arrow", "aria-hidden": "true" }, el("span", { text: label || "" }));
}

function build() {
  const root = $("#arch-diagram");
  root.replaceChildren(
    el("div", { class: "arch-row" }, nodeButton("input", STAGES.input)),
    arrow("image or text"),
    el("div", { class: "arch-row" }, nodeButton("decode", STAGES.decode)),
    arrow("payload + corners to three independent layers"),
    el("div", { class: "arch-row three" }, nodeButton("url", STAGES.url), nodeButton("visual", STAGES.visual), nodeButton("crypto", STAGES.crypto)),
    arrow("link risk, tamper probability, signature status"),
    el("div", { class: "arch-row" }, nodeButton("engine", STAGES.engine)),
    arrow("verdict + reasons"),
    el("div", { class: "arch-row" }, nodeButton("verdict", STAGES.verdict)),
    el("div", { class: "arch-services" },
      el("div", { class: "arch-services-title", text: "Supporting services" }),
      el("div", { class: "arch-row four" }, ...Object.entries(SERVICES).filter(([k]) => k !== "loop").map(([k, d]) => nodeButton(k, d))),
      el("div", { class: "arch-row" }, nodeButton("loop", SERVICES.loop))));
  select(selected);
}

function showTimings(data) {
  timingMs = data.timings_ms || {};
  for (const span of document.querySelectorAll("#arch-diagram [data-ms]")) {
    const v = timingMs[span.dataset.ms];
    span.hidden = v === undefined || v < 0;
    if (!span.hidden) span.textContent = `${v} ms`;
  }
  select(selected);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runSample() {
  if (busy) return;
  busy = true;
  const btn = $("#arch-run");
  btn.disabled = true;
  btn.textContent = "Scanning...";
  const status = $("#arch-status");
  try {
    const blob = await fetchBlob("/api/demo/scenario-image/4");
    const form = new FormData();
    form.append("image", new File([blob], "scenario-4.jpg", { type: "image/jpeg" }));
    const data = await api("/api/scan", { method: "POST", form });
    const order = ["input", "decode", "url", "visual", "crypto", "engine", "verdict"];
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    for (const key of order) {
      for (const b of document.querySelectorAll("#arch-diagram .arch-node")) b.classList.toggle("is-live", b.dataset.node === key);
      if (!reduce) await sleep(380);
    }
    for (const b of document.querySelectorAll("#arch-diagram .arch-node")) b.classList.remove("is-live");
    showTimings(data);
    const d = data.decision;
    status.replaceChildren(el("span", { class: `chip ${d.verdict === "SAFE" ? "safe" : d.verdict === "BLOCK" ? "block" : "warn"}`, text: d.verdict }),
      ` ${d.reasons[0] || ""} Total ${data.elapsed_ms} ms end to end; the three layers judge independently and meet only in the engine.`);
  } catch (e) {
    status.textContent = e.message;
  } finally {
    busy = false;
    btn.disabled = false;
    btn.replaceChildren(icon("qr"), "Run a sample scan");
  }
}

async function loadLiveFacts() {
  try {
    const [h, log] = await Promise.all([api("/api/health"), api("/api/registry/log")]);
    const setSub = (key, text) => { const s = document.querySelector(`#arch-diagram [data-node="${key}"] small`); if (s) s.textContent = text; };
    setSub("registry", `SQLite - CRL v${h.crl_version}`);
    setSub("models", `link ${h.models.url}, visual ${h.models.cv}`);
    setSub("log", `${log.head.size} entries, signed head`);
  } catch { /* the diagram stays useful without live facts */ }
}

export function initArchitecture() {
  if (!$("#arch-diagram")) return;
  build();
  $("#arch-run").addEventListener("click", runSample);
}

export function enterArchitecture() {
  loadLiveFacts();
}
