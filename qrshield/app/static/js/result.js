// Renders a scan response into the result card. Pure DOM building - no innerHTML.
import { $, copyText, el, fmtTime, icon, riskClass } from "./util.js";

const VERDICT = {
  SAFE: { icon: "shield", sub: "No strong warning signs found" },
  SUSPICIOUS: { icon: "warn", sub: "Be careful - check before you continue" },
  BLOCK: { icon: "block", sub: "Do not open this link" },
};
const SIG_LABEL = {
  none: "Unsigned", valid: "Verified", invalid: "INVALID signature", unknown_issuer: "UNKNOWN issuer",
  revoked: "REVOKED", expired: "Expired", domain_mismatch: "DOMAIN mismatch",
};
const SIG_CLASS = { none: "", valid: "safe", expired: "warn" };
const DIRECTION_ICON = { risk: "warn", safe: "check", info: "info" };

function chip(text, cls = "") {
  return el("span", { class: `chip ${cls}`.trim(), text });
}

function signalList(signals) {
  if (!signals?.length) return null;
  return el("ul", { class: "signals" }, signals.map((s) => {
    const dir = s.direction || "risk";
    return el("li", { class: `sig-${dir}` }, icon(DIRECTION_ICON[dir] || "info"), el("span", { text: s.text }));
  }));
}

function layerCard({ badge, cls, title, meta, pill, children }) {
  return el("div", { class: "layer-card" },
    el("div", { class: "layer-top" },
      el("div", {},
        el("div", { class: "layer-name" }, el("span", { class: `badge ${cls}`, text: badge }), title),
        meta ? el("div", { class: "layer-meta", text: meta }) : null),
      pill),
    children);
}

function urlCard(url) {
  const kind = { url: "Web link", upi: "UPI payment", other: "Other content" }[url.type] || url.type;
  const model = url.details?.model_version ? ` - model ${url.details.model_version}` : "";
  return layerCard({
    badge: "M1", cls: "m1", title: "Link analysis", meta: `${kind}${model}`,
    pill: chip(`Risk ${url.score.toFixed(2)}`, riskClass(url.score)),
    children: signalList(url.signals),
  });
}

function visualCard(cv, textOnly) {
  if (textOnly || cv.status === "not_applicable") {
    return layerCard({
      badge: "M2", cls: "m2", title: "Sticker check", meta: "Not checked - needs a photo of the code",
      pill: chip("n/a"), children: null,
    });
  }
  const pill = cv.status === "low_quality" ? chip("Retake photo", "warn") : chip(`Tamper ${cv.score.toFixed(2)}`, riskClass(cv.score));
  const kids = [signalList(cv.signals)];
  if (cv.heatmap_png_b64) {
    kids.push(el("div", { class: "evidence" },
      el("img", { src: cv.heatmap_png_b64, alt: "Evidence overlay showing what the sticker check measured around the code" }),
      cv.details?.legend?.length ? el("ul", { class: "legend" }, cv.details.legend.map((l) =>
        el("li", {}, el("i", { class: `lg-${l.color.slice(1)}`, dataset: { c: l.color } }), l.label))) : null));
  }
  const sal = cv.details?.saliency;
  if (sal?.png_b64) {
    kids.push(el("div", { class: "evidence saliency" },
      el("img", { src: sal.png_b64, alt: "Occlusion-sensitivity map: red regions pushed the model towards 'tampered', blue towards 'genuine'" }),
      el("p", { class: "muted small", text: sal.hot_spot
        ? `Where the AI looked: the strongest evidence sits ${sal.hot_spot_where}. Red pushed the model towards "tampered", blue towards "genuine".`
        : "Where the AI looked: no single region dominates the decision." }),
      el("p", { class: "muted small", text: `Method: ${sal.method}.` })));
  }
  const status = { ok: "Assessed", inconclusive: "Borderline - second photo advised", low_quality: "Photo quality too low to judge" }[cv.status] || cv.status;
  return layerCard({ badge: "M2", cls: "m2", title: "Sticker check", meta: status, pill, children: kids });
}

function cryptoCard(sig) {
  const label = SIG_LABEL[sig.status] || sig.status;
  const kids = [];
  if (sig.issuer) {
    const i = sig.issuer;
    kids.push(el("dl", { class: "kv" },
      el("dt", { text: "Issuer" }), el("dd", { text: i.name }),
      el("dt", { text: "Certified domain" }), el("dd", { text: i.domain }),
      el("dt", { text: "Key / location" }), el("dd", { text: `${i.key_id} / ${i.location_id || "-"}` }),
      el("dt", { text: "Code issued" }), el("dd", { text: fmtTime(i.issued_at) }),
      el("dt", { text: "Code expires" }), el("dd", { text: i.token_expires_at ? fmtTime(i.token_expires_at) : "never" }),
      el("dt", { text: "Certificate valid to" }), el("dd", { text: fmtTime(i.cert_valid_to) })));
  }
  if (sig.detail) kids.push(el("p", { class: "layer-meta", text: sig.detail }));
  const meta = sig.status === "none" ? "No signature in this code" : "Ed25519 + pinned root + revocation list";
  return layerCard({ badge: "M3", cls: "m3", title: "Digital signature", meta, pill: chip(label, SIG_CLASS[sig.status] ?? "block"), children: kids });
}

function working(data) {
  const b = data.decision.breakdown || {};
  const rows = [
    ["Link risk (M1)", b.url_risk], ["Tamper risk (M2)", b.tamper_risk], ["Signature (M3)", b.signature],
    ["Visual status", b.cv_status],
    ["Weights a / b", b.a !== undefined ? `${b.a} / ${b.b}` : "n/a (decided by signature)"],
    ["Fused risk = 1-(1-a*url)(1-b*tamper)", b.fused ?? "n/a"],
    ["Rules applied", (b.overrides || []).join(", ") || "none"],
    ["Time (ms)", Object.entries(data.timings_ms || {}).map(([k, v]) => `${k} ${v}`).join(" | ")],
    ["Models", `link ${data.models?.url} / visual ${data.models?.cv}`],
  ];
  return el("details", { class: "more" },
    el("summary", { text: "Show the working" }),
    el("div", { class: "working" }, el("table", {}, el("tbody", {}, rows.map(([k, v]) => el("tr", {}, el("th", { text: k }), el("td", { text: String(v ?? "-") })))))));
}

// A plain-text evidence report the user can keep or attach when reporting a scam (no photo, nothing sent anywhere).
async function saveReport(data) {
  const d = data.decision, L = data.layers;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data.payload));
  const sha = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  const bullets = (list) => (list?.length ? list.map((s) => `  - ${s.text}`).join("\n") : "  - nothing notable");
  const lines = [
    "QRSHIELD SCAN REPORT", "====================", "",
    `Scanned at     : ${new Date().toISOString()}`,
    `Verdict        : ${d.verdict}${d.certified ? " (QRshield certified)" : ""}`,
    `Overall risk   : ${d.risk.toFixed(2)} (0 = safe, 1 = certain attack)`,
    "", "Destination (never opened by QRshield)", `  ${data.payload}`,
    `  SHA-256: ${sha}`, "", "Why", ...d.reasons.map((r) => `  - ${r}`),
    "", `M1 Link analysis   risk ${L.url_layer.score.toFixed(2)}`, bullets(L.url_layer.signals),
    "", data.text_only || L.cv_layer.status === "not_applicable"
      ? "M2 Sticker check   not checked (link only, no photo)"
      : `M2 Sticker check   tamper ${L.cv_layer.score.toFixed(2)} (${L.cv_layer.status})`,
    ...(data.text_only ? [] : [bullets(L.cv_layer.signals)]),
    "", `M3 Signature       ${L.crypto_layer.status}${L.crypto_layer.issuer ? ` - ${L.crypto_layer.issuer.name} (${L.crypto_layer.issuer.domain})` : ""}`,
    `  ${L.crypto_layer.detail || ""}`.trimEnd(),
    "", `Models: link ${data.models?.url}, visual ${data.models?.cv}`,
    "", "This report contains no photo and no personal data. It is a risk assessment, not a guarantee.",
  ];
  const url = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/plain" }));
  const a = el("a", { href: url, download: `qrshield-report-${sha.slice(0, 8)}.txt` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function destination(data, onReport) {
  const verdict = data.decision.verdict;
  const isWeb = /^https?:\/\//i.test(data.payload);
  const openBtn = el("button", { class: `btn ${verdict === "SAFE" ? "primary" : "secondary"}`, type: "button", disabled: verdict !== "SAFE" || !isWeb },
    icon("link"), verdict === "BLOCK" ? "Open anyway (not recommended)" : verdict === "SUSPICIOUS" ? "Open anyway" : "Open link");
  openBtn.addEventListener("click", () => window.open(data.payload, "_blank", "noopener,noreferrer"));

  const box = el("div", { class: "destination" },
    el("div", { class: "label", text: "Destination - never opened automatically" }),
    el("div", { class: "payload", text: data.payload }));

  let confirmRow = null;
  if (isWeb && verdict !== "SAFE") {
    const cb = el("input", { type: "checkbox", id: "confirm-open" });
    cb.addEventListener("change", () => { openBtn.disabled = !cb.checked; });
    confirmRow = el("label", { class: `confirm ${verdict === "BLOCK" ? "block" : ""}`, for: "confirm-open" }, cb,
      el("span", { text: verdict === "BLOCK" ? "I understand the risk: this link looks malicious and I still want to open it." : "I understand this link looks suspicious and want to open it anyway." }));
    if (verdict === "BLOCK") {
      confirmRow.hidden = true;
      openBtn.hidden = true;
      const reveal = el("button", { class: "link-btn", type: "button", text: "Show override options" });
      reveal.addEventListener("click", () => { confirmRow.hidden = false; openBtn.hidden = false; reveal.remove(); });
      box.append(reveal);
    }
  }
  const actions = el("div", { class: "btn-row" },
    el("button", { class: "btn secondary", type: "button", onclick: () => copyText(data.payload) }, "Copy"),
    el("button", { class: "btn ghost", type: "button", onclick: onReport }, icon("flag"), "Report"),
    el("button", { class: "btn ghost", type: "button", id: "save-report", title: "Download a plain-text evidence report (no photo)", onclick: () => saveReport(data).catch(() => {}) }, icon("upload"), "Save report"),
    openBtn);
  if (!isWeb) box.append(el("p", { class: "muted small", text: "This is not a web link, so there is nothing to open from here." }));
  if (confirmRow) box.append(confirmRow);
  box.append(actions);
  if ((data.codes_in_frame?.length || 0) > 1) {
    box.append(el("p", { class: "muted small codes-note", text: `${data.codes_in_frame.length} QR codes were found in the photo; QRshield analysed the largest one.` }));
  }
  return box;
}

export function renderResult(data, { onReport } = {}) {
  const body = $("#result-body");
  $("#result-empty").hidden = true;
  body.hidden = false;
  body.replaceChildren();

  const d = data.decision;
  const v = VERDICT[d.verdict];
  body.append(
    el("div", { class: `verdict v-${d.verdict}`, role: "group", "aria-label": `Verdict: ${d.verdict}` },
      icon(v.icon, "verdict-icon"),
      el("div", {},
        el("div", { class: "verdict-word", text: d.verdict }),
        el("div", { class: "verdict-sub", text: v.sub }),
        d.certified ? el("span", { class: "certified" }, icon("check"), "QRSHIELD CERTIFIED") : null),
      el("div", { class: "verdict-risk" }, el("b", { text: d.risk.toFixed(2) }), el("small", { text: "risk" }))),
  );

  const meter = el("div", { class: `meter v-${d.verdict}`, role: "img", "aria-label": `Risk ${d.risk.toFixed(2)} on a scale of 0 to 1` }, el("span", { class: "meter-knob" }));
  meter.firstChild.style.left = `${Math.min(Math.max(d.risk, 0.01), 0.99) * 100}%`;
  body.append(meter, el("div", { class: "meter-scale" }, el("span", { text: "safe" }), el("span", { text: "suspicious" }), el("span", { text: "block" })));

  const reasons = el("ul", { class: `reasons v-${d.verdict}` }, d.reasons.map((r) => el("li", { text: r })));
  reasons.style.setProperty("--v", `var(--${d.verdict === "SAFE" ? "safe" : d.verdict === "BLOCK" ? "block" : "warn"})`);
  body.append(reasons);

  body.append(el("div", { class: "layers" },
    urlCard(data.layers.url_layer),
    visualCard(data.layers.cv_layer, data.text_only),
    cryptoCard(data.layers.crypto_layer)));
  body.append(destination(data, onReport), working(data));
  $("#result-card").scrollIntoView?.({ behavior: "smooth", block: "nearest" });
}

export function renderFailure(message, hints = []) {
  const body = $("#result-body");
  $("#result-empty").hidden = true;
  body.hidden = false;
  body.replaceChildren(
    el("div", { class: "verdict v-SUSPICIOUS" }, icon("warn", "verdict-icon"),
      el("div", {}, el("div", { class: "verdict-word", text: "NO CODE READ" }), el("div", { class: "verdict-sub", text: message })), el("span")),
    hints.length ? el("ul", { class: "reasons" }, hints.map((h) => el("li", { text: h }))) : null,
  );
}
