// Small DOM helpers. All dynamic content goes through textContent / properties - never innerHTML -
// so attacker-controlled strings (decoded payloads, report notes, issuer names) cannot inject markup.
const SVG_NS = "http://www.w3.org/2000/svg";

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (key in node && key !== "list") node[key] = value;
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function icon(name, cls = "") {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", `icon ${cls}`.trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

export function toast(message, kind = "ok", ms = 4200) {
  const box = $("#toasts");
  const node = el("div", { class: `toast ${kind}`, role: kind === "err" ? "alert" : "status", text: message });
  box.append(node);
  setTimeout(() => node.remove(), ms);
}

export function fmtTime(epoch) {
  if (!epoch) return "never";
  return new Date(epoch * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function riskClass(score) {
  return score < 0.30 ? "safe" : score < 0.65 ? "warn" : "block";
}

// Decode a data: URI to a Blob without fetch() - the CSP (connect-src 'self') rightly forbids fetching data: URLs.
export function dataUriToBlob(uri) {
  const [head, body] = uri.split(",", 2);
  const mime = /data:([^;]+)/.exec(head)?.[1] || "application/octet-stream";
  const bytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return new Blob([bytes], { type: mime });
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Copy failed - select the text and copy it manually", "warn");
  }
}

export function setBusy(button, busy, label) {
  if (!button) return;
  button.disabled = busy;
  if (label !== undefined) button.dataset.label = button.dataset.label || button.textContent;
  button.setAttribute("aria-busy", busy ? "true" : "false");
}

export function safeStorage() {
  try {
    const k = "__qrshield_probe__";
    localStorage.setItem(k, "1");
    localStorage.removeItem(k);
    return localStorage;
  } catch {
    return null;
  }
}
