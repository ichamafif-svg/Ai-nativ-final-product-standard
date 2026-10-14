// Node tests for the Next.js blocks: node --test blocks/js/nextjs/test.mjs
// No Next, no Zod, no network: a fake NextResponse, a fake identity provider signing with WebCrypto, Zod-shaped schemas.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Values, defaults } from "./values.js";
import { setSink } from "./log.js";
import { guard, securityHeaders, redirectTo, cookieHeader, handler, clientIp } from "./web.js";
import { createOidc, HttpError } from "./session.js";
import { createAccess } from "./access.js";
import { body, query, strict } from "./input.js";

const logs = [];
setSink((line) => logs.push(JSON.parse(line)));

const NextResponse = { next: () => new Response(null, { status: 200, headers: { "x-next": "1" } }) };
const BASE = "https://shop.example";
const req = (path, { method = "GET", headers = {}, body: b } = {}) =>
  new Request(`${BASE}${path}`, { method, headers: { host: "shop.example", ...headers }, body: b });

// ---- values

test("defaults.json mirrors the catalog's defaults", async () => {
  const { execFileSync } = await import("node:child_process");
  const root = new URL("../../../", import.meta.url).pathname;
  const out = execFileSync("python3", ["-c",
    "import json,tomllib;d=tomllib.load(open('standard/catalog/values.toml','rb'));" +
    "print(json.dumps({k:v['default'] for k,v in d.items() if 'default' in v}, sort_keys=True))"], { cwd: root });
  assert.deepEqual(JSON.parse(out), JSON.parse(JSON.stringify(defaults, Object.keys(defaults).sort())));
});

test("a value without default is refused, a chosen one wins", () => {
  const v = new Values({ origins: ["https://a.example"] });
  assert.deepEqual(v.get("origins"), ["https://a.example"]);
  assert.throws(() => v.get("app"), /no default/);
});

// ---- web

test("security headers for next.config", () => {
  const [entry] = securityHeaders(new Values());
  const keys = entry.headers.map((h) => h.key);
  for (const k of ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]) assert.ok(keys.includes(k));
  assert.match(entry.headers.find((h) => h.key === "Content-Security-Policy").value, /frame-ancestors 'none'/);
});

test("guard refuses TRACE, repeated parameters, plain HTTP in production", async () => {
  const mw = guard(new Values(), NextResponse, { production: true });
  const trace = { method: "TRACE", url: `${BASE}/`, headers: new Headers({ host: "shop.example" }) };  // fetch refuses to build one
  assert.equal((await mw(trace)).status, 405);
  assert.equal((await mw(req("/x?a=1&a=2"))).status, 400);
  const http = (p, h) => new Request(`http://shop.example${p}`, { headers: { host: "shop.example", ...h } });
  assert.equal((await mw(http("/", { accept: "text/html" }))).status, 308);
  assert.equal((await mw(http("/api/x"))).status, 403);
  const ok = await mw(req("/"));
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("x-content-type-options"), "nosniff");
});

test("guard: CORS only from @origins", async () => {
  const mw = guard(new Values({ origins: ["https://app.example"] }), NextResponse);
  const pre = (o) => req("/api/x", { method: "OPTIONS", headers: { origin: o, "access-control-request-method": "POST" } });
  const good = await mw(pre("https://app.example"));
  assert.equal(good.status, 204);
  assert.equal(good.headers.get("access-control-allow-origin"), "https://app.example");
  assert.equal((await mw(pre("https://evil.example"))).status, 403);
  assert.equal((await mw(req("/api/x", { method: "POST", headers: { origin: "https://evil.example" } }))).status, 403);
  assert.equal((await mw(req("/api/x", { method: "POST", headers: { origin: BASE } }))).status, 200);
});

test("guard: CSRF double submit for cookie sessions, no-store, csrf cookie issued", async () => {
  const mw = guard(new Values(), NextResponse);
  const missing = await mw(req("/api/x", { method: "POST", headers: { cookie: "__Host-session=s" } }));
  assert.equal(missing.status, 403);
  const wrong = await mw(req("/api/x", { method: "POST", headers: { cookie: "__Host-session=s; __Host-csrf=a", "x-csrf-token": "b" } }));
  assert.equal(wrong.status, 403);
  const right = await mw(req("/api/x", { method: "POST", headers: { cookie: "__Host-session=s; __Host-csrf=a", "x-csrf-token": "a" } }));
  assert.equal(right.status, 200);
  assert.equal(right.headers.get("cache-control"), "no-store");
  const first = await mw(req("/", { headers: { cookie: "__Host-session=s" } }));
  assert.match(first.headers.get("set-cookie"), /^__Host-csrf=[\w-]+; Path=\/; Secure; SameSite=Lax$/);
  const bearer = await mw(req("/api/x", { method: "POST", headers: { authorization: "Bearer t" } }));
  assert.equal(bearer.status, 200);
});

test("guard: rate limit per address and path", async () => {
  const mw = guard(new Values({ rate_per_minute: 3, trusted_proxies: ["10.0.0.1"] }), NextResponse);
  const post = (ip) => mw(req("/api/login", { method: "POST", headers: { "x-forwarded-for": `${ip}, 10.0.0.1` } }));
  for (let i = 0; i < 3; i++) assert.equal((await post("1.2.3.4")).status, 200);
  assert.equal((await post("1.2.3.4")).status, 429);
  assert.equal((await post("5.6.7.8")).status, 200);
});

test("client address ignores X-Forwarded-For without trusted proxies", () => {
  const r = req("/", { headers: { "x-forwarded-for": "6.6.6.6" } });
  assert.equal(clientIp(r, new Values()), "direct");
  assert.equal(clientIp(r, new Values({ trusted_proxies: ["9.9.9.9"] })), "6.6.6.6");
});

test("cookies carry their flags; redirects stay home or go to @redirect_targets", () => {
  assert.equal(cookieHeader("theme", "dark"), "__Host-theme=dark; Path=/; Secure; SameSite=Lax; HttpOnly");
  const v = new Values({ redirect_targets: ["pay.example"] });
  const loc = (t) => redirectTo(req("/"), t, v).headers.get("location");
  assert.equal(loc("/orders"), "/orders");
  assert.equal(loc("//evil.example"), "/");
  assert.equal(loc("https://evil.example/x"), "/");
  assert.equal(loc("https://pay.example/x"), "https://pay.example/x");
  assert.equal(loc("javascript:alert(1)"), "/");
});

test("handler hides errors behind a reference", async () => {
  const r = await handler(async () => { throw new Error("db password wrong at 10.0.0.3"); })(req("/"));
  assert.equal(r.status, 500);
  const b = await r.json();
  assert.equal(b.error, "internal error");
  assert.ok(!JSON.stringify(b).includes("10.0.0.3"));
});

// ---- session: a fake identity provider

const ISSUER = "https://idp.example/realms/shop";
async function idp() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const state = { nonce: null, codes: new Map(), override: {} };
  async function sign(claims, header = { alg: "RS256", kid: "k1", typ: "JWT" }) {
    const input = `${enc(header)}.${enc(claims)}`;
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(input));
    return `${input}.${Buffer.from(sig).toString("base64url")}`;
  }
  const now = () => Math.floor(Date.now() / 1000);
  const claimsFor = (nonce, sub = "alice", roles = ["clerk"]) =>
    ({ iss: ISSUER, aud: "shop", sub, exp: now() + 300, iat: now(), nonce, roles, amr: ["pwd", "otp"], ...state.override });
  async function fetch(url, init = {}) {
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/auth`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/certs` });
    }
    if (url === `${ISSUER}/certs`) return Response.json({ keys: [jwk] });
    if (url === `${ISSUER}/token`) {
      const form = new URLSearchParams(init.body.toString());
      const pending = state.codes.get(form.get("code"));
      if (!pending) return Response.json({ error: "invalid_grant" }, { status: 400 });
      const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(form.get("code_verifier")))).toString("base64url");
      if (challenge !== pending.challenge) return Response.json({ error: "invalid_grant" }, { status: 400 });
      return Response.json({ id_token: await sign(claimsFor(pending.nonce, pending.sub, pending.roles)), access_token: "at" });
    }
    return new Response(null, { status: 404 });
  }
  // the browser at the provider: the user signs in, the provider sends back a code
  function authorize(location, sub = "alice", roles = ["clerk"]) {
    const q = new URL(location).searchParams;
    const code = `code-${Math.random()}`;
    state.codes.set(code, { nonce: q.get("nonce"), challenge: q.get("code_challenge"), sub, roles });
    return { code, state: q.get("state"), method: q.get("code_challenge_method") };
  }
  return { fetch, authorize, sign, claimsFor, state };
}

function setCookies(response) {
  const out = {};
  for (const c of response.headers.getSetCookie()) { const [kv] = c.split(";"); const i = kv.indexOf("="); out[kv.slice(0, i)] = kv.slice(i + 1); }
  return out;
}

async function signIn(oidc, provider, { sub, roles, tamper = (x) => x } = {}) {
  const start = await oidc.login(req("/auth/login"));
  const oidcCookie = setCookies(start)["__Host-oidc"];
  const back = tamper({ ...provider.authorize(start.headers.get("location"), sub, roles), cookie: oidcCookie, iss: ISSUER });
  const r = await oidc.callback(req(`/auth/callback?code=${back.code}&state=${back.state}&iss=${encodeURIComponent(back.iss)}`,
    { headers: { cookie: `__Host-oidc=${back.cookie}${back.extra || ""}` } }));
  return { r, session: setCookies(r)["__Host-session"], method: back.method };
}

const setup = async (chosen = {}) => {
  const provider = await idp();
  const values = new Values(chosen);
  const oidc = createOidc({ issuer: ISSUER, clientId: "shop", clientSecret: "s", redirectUri: `${BASE}/auth/callback`, fetch: provider.fetch }, values);
  return { provider, values, oidc };
};
const withSession = (sid, path = "/", init = {}) => req(path, { ...init, headers: { cookie: `__Host-session=${sid}`, ...(init.headers || {}) } });

test("sign-in: PKCE S256, verified ID token, a fresh session cookie", async () => {
  const { provider, oidc } = await setup();
  const { r, session, method } = await signIn(oidc, provider);
  assert.equal(method, "S256");
  assert.equal(r.status, 303);
  assert.match(r.headers.getSetCookie().find((c) => c.startsWith("__Host-session")), /Secure; SameSite=Lax; HttpOnly/);
  assert.ok(session.length >= 43);
  const user = await oidc.currentUser(withSession(session));
  assert.equal(user.id, `${ISSUER}|alice`);
  assert.deepEqual(user.roles, ["clerk"]);
  assert.equal(await oidc.currentUser(withSession("forged")), null);
});

test("sign-in refused: forged state, missing cookie, provider mix-up, replayed state", async () => {
  const { provider, oidc } = await setup();
  assert.equal((await signIn(oidc, provider, { tamper: (b) => ({ ...b, state: "forged" }) })).r.status, 400);
  assert.equal((await signIn(oidc, provider, { tamper: (b) => ({ ...b, cookie: "other" }) })).r.status, 400);
  assert.equal((await signIn(oidc, provider, { tamper: (b) => ({ ...b, iss: "https://evil.example" }) })).r.status, 400);
  const start = await oidc.login(req("/auth/login"));
  const back = provider.authorize(start.headers.get("location"));
  const cb = () => oidc.callback(req(`/auth/callback?code=${back.code}&state=${back.state}`, { headers: { cookie: `__Host-oidc=${back.state}` } }));
  assert.equal((await cb()).status, 303);
  assert.equal((await cb()).status, 400);
  assert.ok(logs.some((l) => l.event === "security.oidc.state"));
});

test("ID token refused: wrong nonce, wrong audience, expired, alg none, unknown key", async () => {
  const { provider, oidc } = await setup();
  for (const override of [{ nonce: "other" }, { aud: "another-app" }, { exp: 1 }, { iss: "https://evil.example" }]) {
    provider.state.override = override;
    assert.equal((await signIn(oidc, provider)).r.status, 401, JSON.stringify(override));
  }
  provider.state.override = {};
  const claims = provider.claimsFor(null);
  const none = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.`;
  await assert.rejects(oidc.verify(none), HttpError);
  await assert.rejects(oidc.verify(await provider.sign(claims, { alg: "RS256", kid: "nope" })), HttpError);
  await assert.rejects(oidc.verify(await provider.sign(claims, { alg: "HS256", kid: "k1" })), HttpError);
  assert.equal((await oidc.verify(await provider.sign(claims))).sub, "alice");
});

test("session rotated at sign-in, logout everywhere, idle timeout", async () => {
  const { provider, oidc, values } = await setup();
  const a = (await signIn(oidc, provider)).session;
  const b = (await signIn(oidc, provider, { tamper: (x) => ({ ...x, extra: `; __Host-session=${a}` }) })).session;
  assert.notEqual(a, b);
  assert.equal(await oidc.currentUser(withSession(a)), null);       // the old id is gone
  const c = (await signIn(oidc, provider)).session;
  const out = await oidc.logout(withSession(b, "/auth/logout?everywhere=true", { method: "POST" }));
  assert.match(out.headers.get("clear-site-data"), /cookies/);
  assert.equal(await oidc.currentUser(withSession(b)), null);
  assert.equal(await oidc.currentUser(withSession(c)), null);
  const d = (await signIn(oidc, provider)).session;
  values.set("session_idle_min", 0);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(await oidc.currentUser(withSession(d)), null);
});

test("fresh() asks to sign in again after max age", async () => {
  const { provider, oidc } = await setup();
  const s = (await signIn(oidc, provider)).session;
  assert.equal((await oidc.fresh(withSession(s), 300)).sub, "alice");
  provider.state.override = { auth_time: Math.floor(Date.now() / 1000) - 3600 };
  const old = (await signIn(oidc, provider)).session;
  const err = await oidc.fresh(withSession(old), 300).catch((e) => e);
  assert.equal(err.status, 401);
  assert.equal(err.headers["x-reauth"], "/auth/login?prompt=login");
});

test("bearer tokens are verified for their audience", async () => {
  const { provider, oidc } = await setup();
  const t = await provider.sign({ ...provider.claimsFor(undefined), aud: "shop-api" });
  const ok = await oidc.bearer(req("/", { headers: { authorization: `Bearer ${t}` } }), "shop-api");
  assert.equal(ok.sub, "alice");
  await assert.rejects(oidc.bearer(req("/", { headers: { authorization: `Bearer ${t}` } }), "shop"), HttpError);
  await assert.rejects(oidc.bearer(req("/"), "shop-api"), HttpError);
});

// ---- access

test("access matrix: public, signed-in, roles, missing id admin-only", async () => {
  const { provider, oidc, values } = await setup({ access: { "orders.read": ["clerk"], "me.read": "*" }, public: ["GET /health"] });
  const access = createAccess(oidc.currentUser, values);
  const ok = async (_r, _c, user) => Response.json({ who: user ? user.sub : null });
  const health = access.route("health", ok), read = access.route("orders.read", ok), me = access.route("me.read", ok),
    refund = access.route("orders.refund", ok);
  assert.equal((await health(req("/health"))).status, 200);
  assert.equal((await read(req("/api/orders"))).status, 401);
  const clerk = (await signIn(oidc, provider)).session;
  const admin = (await signIn(oidc, provider, { sub: "root", roles: ["admin"] })).session;
  const guest = (await signIn(oidc, provider, { sub: "bob", roles: [] })).session;
  assert.equal((await read(withSession(clerk, "/api/orders"))).status, 200);
  assert.equal((await read(withSession(guest, "/api/orders"))).status, 403);
  assert.equal((await me(withSession(guest, "/api/me"))).status, 200);
  assert.equal((await refund(withSession(clerk, "/api/refund"))).status, 403);
  assert.equal((await refund(withSession(admin, "/api/refund"))).status, 200);
  values.set("access", { "orders.read": ["clerk"], "orders.refund": ["clerk"] });       // read on every call
  assert.equal((await refund(withSession(clerk, "/api/refund"))).status, 200);
  assert.ok(logs.some((l) => l.event === "security.access.refused"));
});

test("server actions check access too", async () => {
  const { provider, oidc, values } = await setup({ access: { "orders.cancel": ["clerk"] } });
  const access = createAccess(oidc.currentUser, values);
  const clerk = (await signIn(oidc, provider)).session;
  const guest = (await signIn(oidc, provider, { sub: "bob", roles: [] })).session;
  const cancel = (sid) => access.action("orders.cancel", async (user, id) => `${user.sub} cancels ${id}`, () => withSession(sid));
  assert.equal(await cancel(clerk)(7), "alice cancels 7");
  await assert.rejects(cancel(guest)(7), (e) => e.status === 403);
});

// ---- input: Zod-shaped schemas

const zod = (shape, mode = "strict") => ({
  _def: { unknownKeys: mode },
  safeParse(data) {
    const issues = [];
    if (typeof data !== "object" || data === null || Array.isArray(data)) issues.push({ path: [], code: "invalid_type" });
    else {
      for (const [k, t] of Object.entries(shape)) if (typeof data[k] !== t) issues.push({ path: [k], code: "invalid_type" });
      if (mode === "strict") for (const k of Object.keys(data)) if (!(k in shape)) issues.push({ path: [k], code: "unrecognized_keys" });
    }
    return issues.length ? { success: false, error: { issues } } : { success: true, data };
  },
});
const post = (b, headers = {}) => req("/api/orders", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: b });

test("body: strict schema, bounded, JSON only", async () => {
  const Order = zod({ item: "string", quantity: "number" });
  assert.deepEqual(await body(post('{"item":"tea","quantity":2}'), Order), { item: "tea", quantity: 2 });
  const status = (p) => p.then(() => 200, (e) => e.status ?? e.message);
  assert.equal(await status(body(post('{"item":"tea","quantity":2,"admin":true}'), Order)), 422);
  assert.equal(await status(body(post('{"item":"tea"'), Order)), 400);
  assert.equal(await status(body(post("x".repeat(2000)), Order, { maxBytes: 1000 })), 413);
  assert.equal(await status(body(post("{}", { "content-type": "text/plain" }), Order)), 415);
  assert.match(await status(body(post('{"item":"tea","quantity":2}'), zod({ item: "string" }, "strip"))), /strict/);
});

test("query: repeated parameters refused, strict schema", () => {
  const Q = zod({ page: "string" });
  assert.deepEqual(query(req("/api/orders?page=2"), Q), { page: "2" });
  assert.throws(() => query(req("/api/orders?page=2&page=3"), Q), (e) => e.status === 400);
  assert.throws(() => query(req("/api/orders?page=2&debug=1"), Q), (e) => e.status === 422);
  assert.equal(strict({ _def: { catchall: { _zod: { def: { type: "never" } } } } }), true);
});
