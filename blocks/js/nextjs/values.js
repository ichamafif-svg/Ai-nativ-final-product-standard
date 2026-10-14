// The named values in force (`@origins`, `@access`\u2026), handed to the product by Standard as JSON in STANDARD_VALUES;
// a value absent takes its strict default (defaults.json, copied from catalog/values.toml and kept equal by a
// test). Read again on every access, so a signed change of the rules applies at once. A value of the wrong type
// keeps its strict default (types.json); values that cannot be read stop the product rather than run on a guess.
import { readFileSync } from "node:fs";

const DEFAULTS = JSON.parse(readFileSync(new URL("./defaults.json", import.meta.url), "utf8"));
const TYPES = JSON.parse(readFileSync(new URL("./types.json", import.meta.url), "utf8"));
const reported = new Set();

function wellTyped(name, value) {
  const kind = TYPES[name];
  if (kind === "list") return Array.isArray(value) && value.every((v) => typeof v === "string" || Number.isInteger(v));
  if (kind === "map") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (kind === "int") return Number.isSafeInteger(value) && value >= 0;
  if (kind === "text") return typeof value === "string";
  return false;
}

export function checked(chosen) {
  if (chosen === null || typeof chosen !== "object" || Array.isArray(chosen)) throw new Error("the values in force are a JSON object");
  const out = {};
  for (const [name, value] of Object.entries(chosen)) {
    if (wellTyped(name, value)) out[name] = value;
    else if (!reported.has(name)) {
      reported.add(name);
      process.stderr.write(JSON.stringify({ event: "security.values.refused", name: String(name).slice(0, 80) }) + "\n");
    }
  }
  return out;
}

export class Values {
  constructor(chosen = null, source = null) {
    this.chosen = { ...(chosen || {}) };
    this.source = source;
  }

  static fromEnv(env = process.env) {
    if (env.STANDARD_VALUES_FILE) {
      const read = () => {
        try { return JSON.parse(readFileSync(env.STANDARD_VALUES_FILE, "utf8")); }
        catch (err) { throw new Error(`STANDARD_VALUES_FILE cannot be read: ${err.name}`); }
      };
      read();                                    // at start: a broken file stops the product now
      return new Values(null, read);
    }
    try { return new Values(JSON.parse(env.STANDARD_VALUES || "{}")); }
    catch { throw new Error("STANDARD_VALUES is not JSON"); }
  }

  all() {
    return { ...DEFAULTS, ...checked(this.source ? this.source() : this.chosen) };
  }

  get(name, fallback) {
    const all = this.all();
    if (!(name in all)) {
      if (fallback !== undefined) return fallback;
      throw new Error(`@${name} is not set and has no default: the rule that reads it stays uncovered`);
    }
    return all[name];
  }

  has(name) {
    return name in this.all();
  }

  set(name, value) {            // tests and local runs; in production the values come from the signed rules
    this.chosen[name] = value;
  }
}

export const defaults = DEFAULTS;
