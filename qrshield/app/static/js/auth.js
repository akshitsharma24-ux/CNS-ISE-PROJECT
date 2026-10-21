// Admin sign-in shared by the Issuer Portal and the Admin view.
import { adminToken, api, ApiError } from "./api.js";
import { $, el, icon } from "./util.js";

export async function isAuthenticated() {
  if (!adminToken.get()) return false;
  try {
    await api("/api/admin/session", { admin: true });
    return true;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) { adminToken.clear(); return false; }
    throw e;
  }
}

export function promptLogin() {
  return new Promise((resolve) => {
    const dialog = $("#login-dialog");
    const input = $("#login-token");
    const error = $("#login-error");
    const send = $("#login-send");
    input.value = "";
    error.hidden = true;
    let settled = false;

    const finish = (ok) => { if (!settled) { settled = true; cleanup(); resolve(ok); } };
    const onSend = async (ev) => {
      ev.preventDefault();
      adminToken.set(input.value.trim());
      send.disabled = true;
      try {
        await api("/api/admin/session", { admin: true });
        dialog.close("ok");
        finish(true);
      } catch (e) {
        adminToken.clear();
        error.textContent = e.status === 401 ? "That token is not correct." : e.message;
        error.hidden = false;
        input.select();
      } finally {
        send.disabled = false;
      }
    };
    const onClose = () => finish(false);
    const cleanup = () => { send.removeEventListener("click", onSend); dialog.removeEventListener("close", onClose); };
    send.addEventListener("click", onSend);
    dialog.addEventListener("close", onClose);
    dialog.showModal();
    input.focus();
  });
}

export async function ensureAdmin() {
  return (await isAuthenticated()) || (await promptLogin());
}

export function renderGate(container, title, onSignedIn) {
  container.replaceChildren(
    icon("key", "xl"),
    el("h2", { text: title }),
    el("p", { class: "muted", text: "This area changes who is trusted, so it needs the admin token. The token is printed in the server console when QRshield starts." }),
    el("button", { class: "btn primary", type: "button", onclick: async () => { if (await promptLogin()) onSignedIn(); } }, icon("key"), "Sign in with admin token"),
  );
  container.hidden = false;
}

export function signOut() {
  adminToken.clear();
}
