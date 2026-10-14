// Standard's front-end kit (block `front`): the browser-side rules hold by using it (POSTMESSAGE, CLIENT-STORAGE,
// OUT-ENCODE in scripts, PROTO-POLLUTION). No dependency; pinned with the release like the Python blocks.

const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

// Receive window messages only from listed origins, and only messages the `accept` function validates.
export function listen(origins, accept, handler, target = globalThis) {
  const allowed = new Set(origins);
  const onMessage = (event) => {
    if (!allowed.has(event.origin)) return;
    let data;
    try { data = accept(event.data); } catch { return; }
    if (data === undefined) return;
    handler(data, event.origin);
  };
  target.addEventListener("message", onMessage);
  return () => target.removeEventListener("message", onMessage);
}

// Preferences in browser storage: never a token or a listed sensitive field (CLIENT-STORAGE).
export function prefs(storage = globalThis.localStorage, sensitive = ["token", "password", "secret", "session", "key"]) {
  const refused = (name) => sensitive.some((s) => name.toLowerCase().includes(s));
  return {
    set(name, value) {
      if (refused(name)) throw new Error(`${name} is not stored in the browser`);
      storage.setItem(`pref:${name}`, JSON.stringify(value));
    },
    get(name, fallback = null) {
      try { const v = storage.getItem(`pref:${name}`); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
    },
  };
}

// Show text as text (OUT-ENCODE): never through innerHTML.
export function text(el, value) {
  el.textContent = value == null ? "" : String(value);
  return el;
}

// Data keyed by input lives in a Map (PROTO-POLLUTION); merging input into objects refuses prototype keys.
export function safeMerge(target, input) {
  for (const [k, v] of Object.entries(input ?? {})) {
    if (FORBIDDEN_KEYS.has(k)) throw new Error(`refused key ${k}`);
    target[k] = v;
  }
  return target;
}
