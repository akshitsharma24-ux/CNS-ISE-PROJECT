// Issuer Portal: register businesses, print signed QR codes, revoke / restore / rotate keys, inspect the CRL.
import { api } from "./api.js";
import { isAuthenticated, renderGate } from "./auth.js";
import { scanBlob } from "./scan.js";
import { $, copyText, dataUriToBlob, el, fmtTime, icon, toast } from "./util.js";

let loaded = false;

function statusChip(issuer) {
  return el("span", { class: `chip ${issuer.is_revoked ? "block" : "safe"}`, text: issuer.is_revoked ? "Revoked" : "Active" });
}

async function act(path, okMessage, confirmText) {
  if (confirmText && !window.confirm(confirmText)) return;
  try {
    const res = await api(path, { method: "POST", json: path.endsWith("/revoke") ? { reason: "Revoked from the issuer portal" } : undefined, admin: true });
    toast(`${okMessage}${res.crl_version ? ` (CRL v${res.crl_version})` : ""}`);
    await refresh();
  } catch (e) { toast(e.message, "err"); }
}

function renderTable(issuers) {
  const tbody = $("#issuer-table tbody");
  tbody.replaceChildren(...issuers.map((i) => el("tr", {},
    el("td", {}, el("strong", { text: i.name }), el("div", { class: "muted small", text: `${i.issuer_id} - ${i.key_id}` })),
    el("td", { class: "mono small wrap-any", text: i.domain }),
    el("td", {}, statusChip(i)),
    el("td", { class: "actions" }, el("div", { class: "action-wrap" },
      i.is_revoked
        ? el("button", { class: "btn sm secondary", type: "button", onclick: () => act(`/api/admin/issuers/${i.issuer_id}/restore`, `${i.name} restored`) }, "Restore")
        : [
            i.managed_key ? el("button", { class: "btn sm ghost", type: "button", title: "Issue a new key; the old key id goes on the CRL", onclick: () => act(`/api/admin/issuers/${i.issuer_id}/rotate`, "Key rotated", `Rotate the signing key of ${i.name}? Codes signed with the old key stop verifying.`) }, "Rotate key") : null,
            el("button", { class: "btn sm danger", type: "button", onclick: () => act(`/api/admin/issuers/${i.issuer_id}/revoke`, `${i.name} revoked`, `Revoke ${i.name}? Every code it signed will be reported as REVOKED.`) }, "Revoke"),
          ])))));
  const select = $("#sign-issuer");
  const current = select.value;
  select.replaceChildren(...issuers.filter((i) => i.managed_key && !i.is_revoked).map((i) => el("option", { value: i.issuer_id, text: `${i.name} (${i.domain})` })));
  if (current) select.value = current;
  syncSuggestedUrl(issuers);
}

function syncSuggestedUrl(issuers) {
  const url = $("#sign-url");
  if (url.value) return;
  const i = issuers.find((x) => x.issuer_id === $("#sign-issuer").value);
  if (i) url.value = `https://${i.domain}/m/42`;
}

function renderCrl(crl) {
  $("#crl-version").textContent = `version ${crl.version}`;
  const list = $("#crl-list");
  list.replaceChildren(...(crl.revoked.length
    ? crl.revoked.map((r) => el("li", {}, el("strong", { class: "mono small", text: r.id }), ` - ${r.reason} (${fmtTime(r.revoked_at)})`))
    : [el("li", { class: "muted", text: "Nothing revoked." })]));
}

async function refresh() {
  const [overview, root] = await Promise.all([api("/api/admin/overview", { admin: true }), api("/api/registry/root")]);
  renderTable(overview.issuers);
  renderCrl(overview.crl);
  $("#root-key").textContent = root.public_key;
}

async function onSign(ev) {
  ev.preventDefault();
  const out = $("#sign-result");
  const btn = ev.submitter;
  btn.disabled = true;
  try {
    const r = await api("/api/admin/sign", { method: "POST", admin: true, json: {
      issuer_id: $("#sign-issuer").value, url: $("#sign-url").value.trim(),
      location_id: $("#sign-loc").value.trim() || "counter-01", validity_hours: Number($("#sign-hours").value) } });
    const ok = r.self_check === "valid";
    out.replaceChildren(
      el("img", { src: r.qr_png_base64, alt: "Signed QR code" }),
      el("p", { class: "muted small", text: `${r.payload_bytes} bytes encoded - small enough for a clean, easy-to-scan print.` }),
      el("div", { class: "btn-row center" },
        el("a", { class: "btn secondary", href: r.qr_png_base64, download: "qrshield-signed.png" }, icon("upload"), "Download PNG"),
        el("button", { class: "btn primary", type: "button", onclick: async () => {
          location.hash = "#/scan";
          await scanBlob(dataUriToBlob(r.qr_png_base64), "signed-qr.png");
        } }, icon("shield"), "Scan this code now")),
      el("div", { class: "payload", text: r.signed_url }),
      el("div", { class: "btn-row center" }, el("button", { class: "btn ghost sm", type: "button", onclick: () => copyText(r.signed_url) }, "Copy signed link"),
        el("span", { class: `chip ${ok ? "safe" : "block"}`, text: `Registry self-check: ${r.self_check}` })),
      el("p", { class: "muted small", text: ok ? "Anyone scanning this with a normal camera simply opens the link; QRshield also proves who issued it."
        : "The self-check did not verify - the link may be outside this business's certified domain." }),
    );
    out.hidden = false;
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; }
}

async function onRegister(ev) {
  ev.preventDefault();
  const btn = ev.submitter;
  btn.disabled = true;
  try {
    await api("/api/admin/issuers", { method: "POST", admin: true, json: {
      issuer_id: $("#reg-id").value.trim(), name: $("#reg-name").value.trim(), domain: $("#reg-domain").value.trim() } });
    toast("Business registered and certificate issued");
    ev.target.reset();
    await refresh();
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; }
}

export function initIssuer() {
  $("#sign-form").addEventListener("submit", onSign);
  $("#register-form").addEventListener("submit", onRegister);
  $("#issuer-refresh").addEventListener("click", () => refresh().catch((e) => toast(e.message, "err")));
  $("#sign-issuer").addEventListener("change", () => { $("#sign-url").value = ""; refresh().catch(() => {}); });
  $("#demo-reset").addEventListener("click", () => act("/api/admin/demo/reset", "All issuers restored"));
}

export async function enterIssuer() {
  const gate = $("#issuer-gate"), body = $("#issuer-body");
  if (!(await isAuthenticated().catch(() => false))) {
    body.hidden = true;
    renderGate(gate, "Issuer portal", enterIssuer);
    return;
  }
  gate.hidden = true;
  body.hidden = false;
  try { await refresh(); loaded = true; } catch (e) { toast(e.message, "err"); }
}
