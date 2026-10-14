// The named values in force (`@origins`, `@access`…), handed to the product by Standard as JSON in STANDARD_VALUES;
// a value absent takes its strict default (defaults.json, copied from standard/catalog/values.toml and kept equal by a
// test). Read again on every access, so a signed change of the rules applies at once.
import { readFileSync } from "node:fs";

const DEFAULTS = JSON.parse(readFileSync(new URL("./defaults.json", import.meta.url), "utf8"));

export class Values {
  constructor(chosen = null, source = null) {
    this.chosen = { ...(chosen || {}) };
    this.source = source;
  }

  static fromEnv(env = process.env) {
    if (env.STANDARD_VALUES_FILE) return new Values(null, () => JSON.parse(readFileSync(env.STANDARD_VALUES_FILE, "utf8")));
    return new Values(JSON.parse(env.STANDARD_VALUES || "{}"));
  }

  all() {
    return { ...DEFAULTS, ...(this.source ? this.source() : this.chosen) };
  }

  get(name) {
    const all = this.all();
    if (!(name in all)) throw new Error(`@${name} is not set and has no default: the rule that reads it stays uncovered`);
    return all[name];
  }

  set(name, value) {            // tests and local runs; in production the values come from the signed rules
    this.chosen[name] = value;
  }
}

export const defaults = DEFAULTS;
