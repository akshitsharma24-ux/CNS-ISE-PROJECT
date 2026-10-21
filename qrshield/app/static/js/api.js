// Thin fetch wrapper: JSON in/out, readable errors, admin token handling.
export class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
  }
}

const TOKEN_KEY = "qrshield.admin";
export const adminToken = {
  get: () => { try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; } },
  set: (t) => { try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* private mode: keep in memory only */ memory = t; } },
  clear: () => { try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } memory = ""; },
};
let memory = "";

function detailOf(body, fallback) {
  if (!body) return fallback;
  if (typeof body.detail === "string") return body.detail;
  if (Array.isArray(body.detail)) return body.detail.map((d) => d.msg).join("; ");
  return fallback;
}

export async function api(path, { method = "GET", json, form, admin = false } = {}) {
  const headers = {};
  const init = { method, headers };
  if (json !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(json);
  }
  if (form) init.body = form;
  if (admin) headers["X-Admin-Token"] = adminToken.get() || memory;
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, "Cannot reach the QRshield server. Is it running?");
  }
  let body = null;
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) body = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, detailOf(body, `Request failed (${res.status})`));
  return body;
}

export async function fetchBlob(path) {
  const res = await fetch(path);
  if (!res.ok) throw new ApiError(res.status, `Could not load ${path}`);
  return res.blob();
}
