// Request input for Next.js (same contract as standard_blocks.input): every body and query goes through a declared
// strict Zod schema; unknown fields refused, a bounded body read once, repeated query parameters refused.
//
//   const OrderIn = z.object({ item: z.string().max(100), quantity: z.number().int().min(1) }).strict();
//   const order = await body(request, OrderIn);
//
// Beyond the checklists, as in the Python block: JSON is read the one way every parser agrees on (UTF-8 only, no
// byte-order mark, no duplicate key, no lone surrogate, depth at most @json_max_depth); every value is bounded (text,
// items, numbers) and read in one Unicode form (NFC), with invisible controls and bidirectional overrides refused
// ("Trojan Source", spoofed names) before the schema sees it.
import { HttpError } from "./session.js";

export const MAX_BODY = 1_000_000;
export const MAX_TEXT = 100_000, MAX_ITEMS = 10_000, MAX_NUMBER = 1e15;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;

export function strict(schema) {
  const def = schema?._def;
  // Zod 3: unknownKeys "strict"; Zod 4: catchall never
  return Boolean(def && (def.unknownKeys === "strict" || def.catchall?._def?.typeName === "ZodNever" ||
    def.catchall?._zod?.def?.type === "never" || def.catchall?.def?.type === "never"));
}

// The deepest nesting of a JSON text and whether an object repeats a key, read without parsing (strings decoded).
export function scanJson(text, maxDepth) {
  const stack = [];                 // per open container: a Set of keys (object) or null (array)
  let i = 0, deepest = 0, expectKey = false;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const raw = text.slice(i, j + 1);
      const top = stack[stack.length - 1];
      if (top && expectKey) {
        let key;
        try { key = JSON.parse(raw); } catch { throw new HttpError(400, "invalid JSON"); }
        if (top.has(key)) throw new HttpError(400, "invalid JSON: a key appears twice");
        top.add(key);
        expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === "{" || c === "[") {
      stack.push(c === "{" ? new Set() : null);
      deepest = Math.max(deepest, stack.length);
      if (deepest > maxDepth) throw new HttpError(400, "invalid JSON: nested too deep");
      expectKey = c === "{";
    } else if (c === "}" || c === "]") {
      stack.pop();
      expectKey = false;
    } else if (c === ",") {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
    i += 1;
  }
  return deepest;
}

export function strictJson(bytes, { maxDepth = 32, maxBytes = MAX_BODY } = {}) {
  if (bytes.length > maxBytes) throw new HttpError(413, "body too large");
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new HttpError(400, "invalid JSON: a byte-order mark");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new HttpError(400, "invalid JSON: not UTF-8"); }
  scanJson(text, maxDepth);
  let value;
  try { value = JSON.parse(text); } catch { throw new HttpError(400, "invalid JSON"); }
  return value;
}

// Every value bounded, one Unicode form, no invisible controls, no lone surrogates.
export function clean(value, depth = 0) {
  if (depth > 64) throw new HttpError(422, "nested too deep");
  if (typeof value === "string") {
    if (value.length > MAX_TEXT) throw new HttpError(422, "text too long");
    if (typeof value.isWellFormed === "function" ? !value.isWellFormed() : /[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) {
      throw new HttpError(422, "a lone surrogate");
    }
    const nfc = value.normalize("NFC");
    if (CONTROL.test(nfc)) throw new HttpError(422, "an invisible control character");
    return nfc;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Math.abs(value) > MAX_NUMBER) throw new HttpError(422, "number out of range");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ITEMS) throw new HttpError(422, "too many items");
    return value.map((v) => clean(v, depth + 1));
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length > MAX_ITEMS) throw new HttpError(422, "too many fields");
    const out = Object.create(null);
    for (const [k, v] of entries) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") throw new HttpError(422, "a reserved key");
      out[clean(k, depth + 1)] = clean(v, depth + 1);
    }
    return Object.assign({}, out);
  }
  return value;
}

function validate(schema, data) {
  if (!strict(schema)) throw new Error("input schemas are strict: z.object({...}).strict()");
  const r = schema.safeParse(clean(data));
  if (!r.success) {
    const issues = (r.error?.issues || []).slice(0, 20).map((i) => ({ path: i.path, code: i.code }));
    throw new HttpError(422, JSON.stringify({ invalid: issues }));
  }
  return Object.freeze(r.data);
}

export async function body(request, schema, { maxBytes = MAX_BODY, values = null } = {}) {
  const limit = Math.min(maxBytes, values ? Number(values.get("body_max_bytes")) : maxBytes);
  const depth = values ? Number(values.get("json_max_depth")) : 32;
  const type = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json") throw new HttpError(415, "application/json only");
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) throw new HttpError(413, "body too large");
  const reader = request.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) { await reader.cancel(); throw new HttpError(413, "body too large"); }
      chunks.push(value);
    }
  }
  return validate(schema, strictJson(Buffer.concat(chunks), { maxDepth: depth, maxBytes: limit }));
}

export function query(request, schema) {
  const params = new URL(request.url).searchParams;
  const keys = [...params.keys()];
  if (new Set(keys).size !== keys.length) throw new HttpError(400, "a parameter appears twice");
  return validate(schema, Object.fromEntries(params));
}
