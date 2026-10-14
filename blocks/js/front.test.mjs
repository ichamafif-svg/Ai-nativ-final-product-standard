import assert from "node:assert/strict";
import { listen, prefs, safeMerge, text } from "./front.mjs";

const target = new EventTarget();
const got = [];
listen(["https://pay.example"], (d) => (typeof d?.ok === "boolean" ? d : undefined), (d, o) => got.push([d.ok, o]), target);
const msg = (origin, data) => { const e = new Event("message"); e.origin = origin; e.data = data; target.dispatchEvent(e); };
msg("https://evil.example", { ok: true });
msg("https://pay.example", { ok: "yes" });
msg("https://pay.example", { ok: true });
assert.deepEqual(got, [[true, "https://pay.example"]]);

const store = new Map();
const s = prefs({ setItem: (k, v) => store.set(k, v), getItem: (k) => store.get(k) ?? null });
s.set("theme", "dark");
assert.equal(s.get("theme"), "dark");
assert.throws(() => s.set("accessToken", "x"));

assert.throws(() => safeMerge({}, JSON.parse('{"__proto__": {"admin": true}}')));
assert.equal(text({ textContent: "" }, "<b>x</b>").textContent, "<b>x</b>");
console.log("front ok");
