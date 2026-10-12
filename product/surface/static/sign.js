// Signing in the person's browser (ARCHITECTURE.md §11.9). The private key never reaches the server: it is imported
// once into WebCrypto as a non-extractable key and kept in this browser's IndexedDB. The browser builds the canonical
// statement, the DSSE pre-authentication encoding and the envelope itself, from the body it shows the person: the web
// server only proposes a body and forwards the signed envelope to the kernel, which decides.
//
// Formats mirror kernel/canon.py and kernel/identity.py exactly: canonical JSON (sorted keys, no spaces, UTF-8, no
// floats), an in-toto statement whose subject binds sha256(canon(body)), and PAE "DSSEv1 <len> <type> <len> <payload>".

const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PREDICATE_PREFIX = "urn:standard:kernel:1:";
const enc = new TextEncoder();

export function canon(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("only integers are canonical");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(value[k])).join(",") + "}";
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (text) => Uint8Array.from(atob(text.trim()), (c) => c.charCodeAt(0));
const b64url = (text) => unb64(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));

export async function sha256(bytes) {
  return crypto.subtle.digest("SHA-256", bytes);
}

export async function statement(domain, kind, body) {
  const digest = hex(await sha256(enc.encode(canon(body))));
  return {
    _type: STATEMENT_TYPE, predicateType: PREDICATE_PREFIX + kind, predicate: body,
    subject: [{ name: `${domain}/${kind}:${body.id}`, digest: { sha256: digest } }],
  };
}

export function pae(payload) {
  const type = enc.encode(PAYLOAD_TYPE);
  const head = enc.encode(`DSSEv1 ${type.length} ${PAYLOAD_TYPE} ${payload.length} `);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

// A key file holds base64 of the raw 32-byte Ed25519 seed (as product/tools/ceremony.py writes it).
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export async function importKeyFile(text) {
  const seed = unb64(text);
  if (seed.length !== 32) throw new Error("a key file holds 32 bytes");
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(PKCS8_ED25519, 0);
  pkcs8.set(seed, 16);
  const extractable = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", extractable);
  const publicRaw = b64url(jwk.x);
  seed.fill(0);
  pkcs8.fill(0);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
  delete jwk.d;
  return { key, keyid: "sha256:" + hex(await sha256(publicRaw)), public: b64(publicRaw) };
}

export async function envelope(domain, kind, body, signer) {
  const payload = enc.encode(canon(await statement(domain, kind, body)));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, signer.key, pae(payload));
  return { payloadType: PAYLOAD_TYPE, payload: b64(payload), signatures: [{ keyid: signer.keyid, sig: b64(sig) }] };
}

// ---- keeping the key in this browser only --------------------------------------------------------------------------
function db() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open("standard", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export async function saveSigner(identity, signer) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const tx = d.transaction("keys", "readwrite");
    tx.objectStore("keys").put({ identity, ...signer }, "me");
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadSigner() {
  const d = await db();
  return new Promise((resolve) => {
    const r = d.transaction("keys").objectStore("keys").get("me");
    r.onsuccess = () => resolve(r.result || null);
    r.onerror = () => resolve(null);
  });
}

export async function forgetSigner() {
  const d = await db();
  return new Promise((resolve) => {
    const tx = d.transaction("keys", "readwrite");
    tx.objectStore("keys").delete("me");
    tx.oncomplete = resolve;
  });
}
