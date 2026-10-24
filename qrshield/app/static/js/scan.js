// The scan view: input sources, preview, scanning, second photo, demo scenarios, history, reporting.
import { api, ApiError, fetchBlob } from "./api.js";
import { cameraSupport, captureFrame, isRunning, startCamera, stopCamera } from "./camera.js";
import { prepareImage } from "./image.js";
import { renderFailure, renderResult } from "./result.js";
import { $, $$, el, icon, safeStorage, toast } from "./util.js";

const HISTORY_KEY = "qrshield.history.v1";
const HISTORY_MAX = 12;
const store = safeStorage();

const state = { file: null, file2: null, last: null, busy: false, pendingReport: null };

// ---------------------------------------------------------------- source tabs
function showSource(name) {
  $$(".seg-btn[data-source]").forEach((b) => {
    const on = b.dataset.source === name;
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-selected", String(on));
  });
  ["photo", "camera", "link"].forEach((s) => { $(`#source-${s}`).hidden = s !== name; });
  if (name !== "camera") stopCameraUi();
  if (name === "camera") {
    const support = cameraSupport();
    const notice = $("#camera-notice");
    notice.hidden = support.ok;
    notice.textContent = support.ok ? "" : support.message;
    $("#camera-start").disabled = !support.ok;
  }
}

function stopCameraUi() {
  stopCamera();
  $("#camera-capture").disabled = true;
  $("#camera-stop").disabled = true;
  $("#camera-start").disabled = false;
}

// ---------------------------------------------------------------- image selection
async function setImage(file, { auto = false, name } = {}) {
  try {
    state.file = await prepareImage(file);
  } catch (e) {
    toast(e.message, "err");
    return;
  }
  state.file2 = null;
  $("#second-photo").hidden = true;
  $("#second-name").textContent = "";
  const img = $("#preview-img");
  if (img.dataset.url) URL.revokeObjectURL(img.dataset.url);
  img.dataset.url = URL.createObjectURL(state.file);
  img.src = img.dataset.url;
  $("#preview-name").textContent = name || state.file.name || "photo";
  $("#preview").hidden = false;
  $("#quality-hints").hidden = true;
  $("#scan-btn").disabled = false;
  $("#scan-status").textContent = "Photo ready";
  if (auto) await scan();
}

function clearImage() {
  state.file = state.file2 = null;
  $("#preview").hidden = true;
  $("#second-photo").hidden = true;
  $("#scan-btn").disabled = true;
  $("#scan-status").textContent = "Ready";
  $("#quality-hints").hidden = true;
}

// ---------------------------------------------------------------- scanning
function setBusy(busy, text) {
  state.busy = busy;
  $("#scan-btn").disabled = busy || !state.file;
  $("#link-check").disabled = busy;
  $("#scan-status").replaceChildren(...(busy ? [el("span", { class: "spinner" }), ` ${text}`] : [text]));
}

function showHints(hints, kind = "warn") {
  const box = $("#quality-hints");
  if (!hints?.length) { box.hidden = true; return; }
  box.className = `notice ${kind}`;
  box.replaceChildren(el("strong", { text: kind === "warn" ? "Retake tips" : "Note" }), el("ul", {}, hints.map((h) => el("li", { text: h }))));
  box.hidden = false;
}

async function scan() {
  if (!state.file || state.busy) return;
  setBusy(true, "Analysing...");
  const form = new FormData();
  form.append("image", state.file);
  if (state.file2) form.append("image2", state.file2);
  try {
    const explain = $("#explain-toggle")?.checked ? "?explain=true" : "";
    const data = await api(`/api/scan${explain}`, { method: "POST", form });
    handleResult(data);
  } catch (e) {
    toast(e.message, "err");
    $("#scan-status").textContent = "Failed";
  } finally {
    setBusy(false, state.last ? "Done" : "Ready");
  }
}

async function checkLink() {
  const payload = $("#link-input").value.trim();
  if (!payload) { toast("Type or paste a link first", "warn"); return; }
  setBusy(true, "Checking...");
  try {
    handleResult(await api("/api/check", { method: "POST", json: { payload } }));
  } catch (e) {
    toast(e.message, "err");
  } finally {
    setBusy(false, state.last ? "Done" : "Ready");
  }
}

function handleResult(data) {
  if (!data.success) {
    state.last = null;
    renderFailure(data.error, data.quality?.hints || []);
    showHints(data.quality?.hints);
    return;
  }
  state.last = data;
  showHints(data.quality?.hints?.length && data.layers.cv_layer.status !== "ok" ? data.quality.hints : [], "info");
  renderResult(data, { onReport: () => openReport(data) });
  const needSecond = data.layers.cv_layer.status === "inconclusive" && !state.file2 && !data.text_only;
  $("#second-photo").hidden = !needSecond;
  pushHistory(data);
}

// ---------------------------------------------------------------- reporting
function openReport(data, label = "phishing", note = "") {
  state.pendingReport = data;
  $("#report-label").value = label;
  $("#report-note").value = note;
  $("#report-dialog").showModal();
}

async function sendReport(event) {
  event.preventDefault();
  const data = state.pendingReport;
  if (!data) return;
  const btn = $("#report-send");
  btn.disabled = true;
  try {
    await api("/api/report", { method: "POST", json: {
      scan_id: data.scan_id, payload: data.payload, user_label: $("#report-label").value,
      note: $("#report-note").value.trim(), verdict: data.decision.verdict } });
    toast("Report sent. A person will review it before it can influence anything.");
    $("#report-dialog").close("sent");
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------- history
function loadHistory() {
  if (!store) return [];
  try { return JSON.parse(store.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
}

function pushHistory(data) {
  if (!store) return;
  const slim = JSON.parse(JSON.stringify(data));
  if (slim.layers?.cv_layer) slim.layers.cv_layer.heatmap_png_b64 = null;     // keep storage small
  const items = loadHistory().filter((h) => h.data.scan_id !== data.scan_id);
  items.unshift({ ts: Date.now(), data: slim });
  try { store.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX))); } catch { /* quota */ }
  renderHistory();
}

function renderHistory() {
  const items = loadHistory();
  $("#history-card").hidden = items.length === 0;
  $("#history-list").replaceChildren(...items.map((h) => {
    const cls = { SAFE: "safe", SUSPICIOUS: "warn", BLOCK: "block" }[h.data.decision.verdict];
    const btn = el("button", { type: "button", title: h.data.payload },
      el("span", { class: `chip ${cls}`, text: h.data.decision.verdict }),
      el("span", { class: "p", text: h.data.payload }),
      el("span", { class: "muted small", text: new Date(h.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }));
    btn.addEventListener("click", () => { state.last = h.data; renderResult(h.data, { onReport: () => openReport(h.data) }); });
    return el("li", {}, btn);
  }));
}

// ---------------------------------------------------------------- demo scenarios
async function loadScenarios() {
  try {
    const list = await api("/api/demo/scenarios");
    $("#scenario-list").replaceChildren(...list.map((s) => {
      const cls = { SAFE: "safe", SUSPICIOUS: "warn", BLOCK: "block" }[s.expected];
      const b = el("button", { class: "scenario", type: "button", title: s.layers },
        el("span", { class: "top" }, el("span", { class: "num", text: String(s.id) }), el("span", { class: `chip ${cls}`, text: `expect ${s.expected}` })),
        el("strong", { text: s.title }), el("p", { text: s.story }));
      b.addEventListener("click", () => runScenario(s));
      return b;
    }));
  } catch {
    $("#demo-card").hidden = true;
  }
}

async function runScenario(s) {
  showSource("photo");
  setBusy(true, `Loading scenario ${s.id}...`);
  try {
    const blob = await fetchBlob(`/api/demo/scenario-image/${s.id}`);
    await setImage(new File([blob], `scenario-${s.id}.jpg`, { type: "image/jpeg" }), { name: `Scenario ${s.id}: ${s.short}` });
    setBusy(false, "Photo ready");
    await scan();
    if (s.id === 6 && state.last) openReport(state.last, "phishing", "Demo scenario 6: KYC scam code, reported for review.");
  } catch (e) {
    toast(e.message, "err");
    setBusy(false, "Ready");
  }
}

// ---------------------------------------------------------------- wiring
export function initScan() {
  $$(".seg-btn[data-source]").forEach((b) => b.addEventListener("click", () => showSource(b.dataset.source)));

  for (const id of ["file-camera", "file-gallery"]) {
    $(`#${id}`).addEventListener("change", (e) => { const f = e.target.files?.[0]; if (f) setImage(f); e.target.value = ""; });
  }
  $("#file-second").addEventListener("change", async (e) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    try { state.file2 = await prepareImage(f); } catch (err) { toast(err.message, "err"); return; }
    $("#second-name").textContent = `Second photo ready: ${f.name || "photo"}`;
    await scan();
  });

  const dz = $("#dropzone");
  ["dragenter", "dragover"].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove("is-over"); }));
  dz.addEventListener("drop", (e) => { const f = e.dataTransfer?.files?.[0]; if (f) setImage(f); });
  dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#file-gallery").click(); } });
  window.addEventListener("paste", (e) => {
    const item = Array.from(e.clipboardData?.items || []).find((i) => i.type.startsWith("image/"));
    if (item) { showSource("photo"); setImage(item.getAsFile(), { name: "pasted image" }); }
  });

  $("#preview-clear").addEventListener("click", clearImage);
  $("#scan-btn").addEventListener("click", scan);
  $("#link-check").addEventListener("click", checkLink);
  $("#link-input").addEventListener("keydown", (e) => { if (e.key === "Enter") checkLink(); });

  $("#camera-start").addEventListener("click", async () => {
    try {
      await startCamera();
      $("#camera-capture").disabled = false;
      $("#camera-stop").disabled = false;
      $("#camera-start").disabled = true;
    } catch (e) {
      const msg = e.name === "NotAllowedError" ? "Camera permission was denied. Allow it in the browser's site settings." : `Camera error: ${e.message}`;
      const n = $("#camera-notice"); n.textContent = msg; n.hidden = false;
    }
  });
  $("#camera-capture").addEventListener("click", async () => {
    try {
      const file = await captureFrame();
      stopCameraUi();
      showSource("photo");
      await setImage(file, { name: "camera capture", auto: true });
    } catch (e) { toast(e.message, "err"); }
  });
  $("#camera-stop").addEventListener("click", stopCameraUi);

  $("#report-form").addEventListener("submit", sendReport);
  $("#report-send").addEventListener("click", sendReport);
  $("#report-dialog").addEventListener("close", () => { state.pendingReport = null; });
  $("#history-clear").addEventListener("click", () => { store?.removeItem(HISTORY_KEY); renderHistory(); });

  loadScenarios();
  renderHistory();
}

export function leaveScan() { if (isRunning()) stopCameraUi(); }

// Used by the issuer portal's "scan this code" button.
export async function scanBlob(blob, name) {
  showSource("photo");
  await setImage(new File([blob], name, { type: blob.type || "image/png" }), { name, auto: true });
}
