// Structured, redacted security events for the blocks themselves (product code uses the log block when it exists).
// Beyond the checklists, as in the Python block: values shaped like credentials are redacted, control characters,
// ANSI escapes and bidirectional overrides are neutralised, records stay under MAX_RECORD, and each record carries
// `seq` and `chain` (SHA-256 of the previous chain and this record), so an edited or missing line breaks the chain.
import { createHash } from "node:crypto";

let sink = (line) => process.stdout.write(line);
export function setSink(fn) { sink = fn; }   // tests

const SECRET = /(password|passwd|secret|token|api[_-]?key|authorization|cookie|session)/i;
const VALUE_SECRET = new RegExp(["eyJ[\\w-]{8,}\\.[\\w-]{8,}\\.[\\w-]{8,}", "(AKIA|ASIA)[0-9A-Z]{16}", "[sr]k_(live|test)_\\w{8,}",
  "-----BEGIN [A-Z ]*PRIVATE KEY-----", "gh[pousr]_[A-Za-z0-9]{30,}", "github_pat_\\w{30,}", "xox[abposr]-[\\w-]{10,}",
  "AIza[\\w-]{35}", "[Bb]earer\\s+[\\w.~+/-]{16,}=*", "sk-(ant-|proj-)?[\\w-]{20,}", "glpat-[\\w-]{20}"].join("|"));
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
const MAX_RECORD = 8192;
const chain = { seq: 0, last: "0".repeat(64) };

function canonical(record) {
  return JSON.stringify(Object.fromEntries(Object.entries(record).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))));
}

export function event(name, fields = {}) {
  let record = { at: new Date().toISOString(), event: String(name).replace(CONTROL, " ").slice(0, 200) };
  for (const [k, v] of Object.entries(fields).sort()) {
    if (k === "seq" || k === "chain") continue;
    record[k] = SECRET.test(k) ? "[redacted]" : typeof v === "string"
      ? (VALUE_SECRET.test(v) ? "[redacted]" : v.replace(CONTROL, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).slice(0, 2000))
      : v;
  }
  if (JSON.stringify(record).length > MAX_RECORD) {
    record = Object.fromEntries(Object.entries(record).map(([k, v]) => [k, typeof v === "string" ? v.slice(0, 200) : v]));
    record.truncated = true;
  }
  chain.seq += 1;
  record.seq = chain.seq;
  chain.last = createHash("sha256").update(chain.last + canonical(record)).digest("hex");
  record.chain = chain.last;
  sink(JSON.stringify(record) + "\n");
  return record;
}

export const security = (name, fields) => event(`security.${name}`, fields);

// How many records, from the first line (the anchor), keep an unbroken chain.
export function verifyChain(lines) {
  let last = null, n = 0;
  for (const line of lines) {
    const record = JSON.parse(line);
    const c = record.chain;
    delete record.chain;
    if (last !== null && createHash("sha256").update(last + canonical(record)).digest("hex") !== c) break;
    last = c; n += 1;
  }
  return n;
}
