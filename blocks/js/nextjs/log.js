// Structured, redacted security events for the blocks themselves (product code uses the log block when it exists).
let sink = (line) => process.stdout.write(line);
export function setSink(fn) { sink = fn; }   // tests

const SECRET = /(password|passwd|secret|token|api[_-]?key|authorization|cookie|session)/i;

export function event(name, fields = {}) {
  const record = { at: new Date().toISOString(), event: String(name).slice(0, 200) };
  for (const [k, v] of Object.entries(fields).sort()) {
    record[k] = SECRET.test(k) ? "[redacted]" : typeof v === "string" ? v.replace(/[\r\n]/g, " ").slice(0, 2000) : v;
  }
  sink(JSON.stringify(record) + "\n");
  return record;
}

export const security = (name, fields) => event(`security.${name}`, fields);
