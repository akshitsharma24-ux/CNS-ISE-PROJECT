// Merkle-tree checks done in the browser with WebCrypto SHA-256 (RFC 6962 / RFC 9162 hashing), so the page does
// not have to trust the server's word that a log entry is included or that the log only ever grew.
const enc = new TextEncoder();

export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));

async function sha256(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

export const leafHash = (data) => sha256(Uint8Array.of(0), data);
export const nodeHash = (left, right) => sha256(Uint8Array.of(1), left, right);

// The exact canonical bytes the registry hashed for one entry (sorted keys, no spaces, UTF-8).
export function entryBytes(entry) {
  return enc.encode(JSON.stringify({ action: entry.action, detail: entry.detail, subject: entry.subject, time: entry.time }));
}

const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// Returns {ok, steps}: `steps` lists every hash combined on the way up, for display.
export async function verifyInclusion(leaf, index, size, path, root) {
  const steps = [];
  if (index < 0 || index >= size) return { ok: false, steps };
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return { ok: false, steps };
    if (fn & 1 || fn === sn) {
      r = await nodeHash(p, r);
      steps.push({ side: "sibling on the left", sibling: hex(p), result: hex(r) });
      if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else {
      r = await nodeHash(r, p);
      steps.push({ side: "sibling on the right", sibling: hex(p), result: hex(r) });
    }
    fn >>= 1; sn >>= 1;
  }
  return { ok: sn === 0 && equal(r, root), steps, computed: hex(r) };
}

export async function verifyConsistency(first, second, firstRoot, secondRoot, path) {
  if (!(first > 0 && first <= second)) return false;
  if (first === second) return path.length === 0 && equal(firstRoot, secondRoot);
  const proof = [...path];
  if ((first & (first - 1)) === 0) proof.unshift(firstRoot);
  if (!proof.length) return false;
  let fn = first - 1, sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = proof[0], sr = proof[0];
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return equal(fr, firstRoot) && equal(sr, secondRoot) && sn === 0;
}

// Ed25519 check of the root-signed tree head, if this browser supports Ed25519 in WebCrypto.
// Returns true / false, or null when the browser cannot do Ed25519 (the Merkle checks above still stand alone).
export async function verifyTreeHead(head, rootPublicKeyB64u) {
  try {
    const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("raw", b64(rootPublicKeyB64u), "Ed25519", false, ["verify"]);
    const body = `{"root":"${head.root_hash}","size":${head.size},"timestamp":${head.timestamp}}`;
    const msg = new Uint8Array([...enc.encode("QRSHIELD-STH-v1\u0000"), ...enc.encode(body)]);
    return await crypto.subtle.verify("Ed25519", key, b64(head.sig), msg);
  } catch {
    return null;
  }
}
