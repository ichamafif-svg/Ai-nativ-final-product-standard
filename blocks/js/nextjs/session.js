// Sign-in through the identity provider, and the product's own sessions, for Next.js (same contract as
// standard_blocks.session): OpenID Connect code flow with PKCE (S256), state and nonce; the ID token's signature
// (algorithms from an allow-list, keys from the provider's JWKS), issuer, audience, expiry and nonce checked with
// WebCrypto; server-side sessions behind a 256-bit id in a __Host- cookie, rotated at sign-in, idle and absolute
// limits, logout everywhere, re-authentication. The product never sees a password; tokens never reach the browser.
//
// Beyond the checklists, as in the Python block: the store keeps only hashes of session ids; a session presented by
// another client (user agent) is ended; the provider's keys expire within the hour and an unknown key id refreshes
// them at most once a minute; a token naming or carrying its own key, or of another kind, is refused; @mfa is
// checked on the ID token's amr; the provider can end sessions by back-channel logout; pending sign-ins are bounded.
//
//   const oidc = createOidc({ issuer, clientId, clientSecret, redirectUri, store }, values);
//   // app/auth/login/route.js                export const GET = oidc.login;
//   // app/auth/callback/route.js             export const GET = oidc.callback;
//   // app/auth/logout/route.js               export const POST = oidc.logout;
//   // app/auth/backchannel-logout/route.js   export const POST = oidc.backchannelLogout;
//   const user = await oidc.currentUser(request);          // null when signed out
import { cookieHeader, cookies, same, SESSION_COOKIE, token } from "./web.js";
import { security } from "./log.js";
import { storeFor } from "./store.js";

const ALGORITHMS = {
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" }, kty: "RSA" },
  PS256: { import: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, kty: "RSA" },
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, kty: "EC" },
};
const PENDING_MS = 600_000;
const JWKS_TTL_MS = 3_600_000, JWKS_REFRESH_MS = 60_000, META_TTL_MS = 86_400_000;
const MAX_TOKEN = 16_384;
const EMBEDDED_KEYS = ["jku", "jwk", "x5u", "x5c", "crit"];
const SECOND_FACTORS = new Set(["mfa", "otp", "hwk", "sc", "fpt", "face", "iris", "retina", "vbm"]);   // RFC 8176
const BACKCHANNEL = "http://schemas.openid.net/event/backchannel-logout";

export class HttpError extends Error {
  constructor(status, message, headers = {}) { super(message); this.status = status; this.headers = headers; }
  toResponse() { return Response.json({ error: this.message }, { status: this.status, headers: this.headers }); }
}

const b64url = (s) => Buffer.from(s, "base64url");
export async function sha256(text) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)))).toString("hex");
}
const clientOf = async (request) => (await sha256(request.headers.get("user-agent") || "")).slice(0, 32);

// Server-side sessions in a store (store.js), keyed by the SHA-256 of the id; bound to the client that opened them.
export class Sessions {
  constructor(store = null) { this.store = storeFor(store); }

  async create(user, { client = "", idpSid = null, ttlS = 86400 } = {}) {
    const sid = token(32);
    const key = await sha256(sid), now = Date.now();
    await this.store.set(`s:${key}`, { user, created: now, seen: now, client, idpSid }, ttlS);
    await this.store.add(`u:${await sha256(user.id)}`, key, ttlS);
    if (idpSid) await this.store.add(`i:${await sha256(`${user.issuer}|${idpSid}`)}`, key, ttlS);
    return sid;
  }

  async get(sid, idleMs, maxMs, client = null) {
    if (!sid || sid.length > 100) return null;
    const key = await sha256(sid);
    const rec = await this.store.get(`s:${key}`);
    if (!rec) return null;
    const now = Date.now();
    if (now - rec.seen > idleMs || now - rec.created > maxMs) { await this.endKey(key, rec); return null; }
    if (client !== null && rec.client && !same(rec.client, client)) {
      security("session.other_client", { who: rec.user.id });
      await this.endKey(key, rec);
      return null;
    }
    rec.seen = now;
    await this.store.set(`s:${key}`, rec, Math.max(1, (maxMs - (now - rec.created)) / 1000));
    return rec;
  }

  async endKey(key, rec = null) {
    rec = rec || await this.store.get(`s:${key}`);
    await this.store.delete(`s:${key}`);
    if (rec) await this.store.discard(`u:${await sha256(rec.user.id)}`, key);
  }

  async end(sid) { await this.endKey(await sha256(sid)); }

  async endUser(userId, keep = null) {
    const keepKey = keep ? await sha256(keep) : null;
    const gone = (await this.store.members(`u:${await sha256(userId)}`)).filter((k) => k !== keepKey);
    for (const k of gone) await this.endKey(k);
    return gone.length;
  }

  async endProviderSession(issuer, idpSid) {
    const index = `i:${await sha256(`${issuer}|${idpSid}`)}`;
    const gone = await this.store.members(index);
    for (const k of gone) await this.endKey(k);
    await this.store.delete(index);
    return gone.length;
  }

  async ofUser(userId) {
    const out = [];
    for (const k of await this.store.members(`u:${await sha256(userId)}`)) {
      const r = await this.store.get(`s:${k}`);
      if (r) out.push({ id: k.slice(0, 8), created: r.created, seen: r.seen });
    }
    return out;
  }

  async backdate(sid, ms) {                    // Standard's timeout probe
    const key = await sha256(sid);
    const rec = await this.store.get(`s:${key}`);
    if (!rec) return false;
    rec.seen -= ms; rec.created -= ms;
    await this.store.set(`s:${key}`, rec, 3600);
    return true;
  }
}

export function createOidc({ issuer, clientId, clientSecret = null, redirectUri, scopes = ["openid"], fetch = globalThis.fetch,
  rolesClaim = "roles", tenantClaim = null, store = null, sessions = null }, values) {
  issuer = issuer.replace(/\/$/, "");
  if (!issuer.startsWith("https://")) throw new Error("the issuer is reached over https");
  if (!redirectUri.startsWith("https://")) throw new Error("the redirect URI is https");
  sessions = sessions || new Sessions(store);
  const pending = new Map();
  let meta = null, metaAt = 0, jwks = null, jwksAt = 0, refreshedAt = 0;

  async function getMeta() {
    if (!meta || Date.now() - metaAt > META_TTL_MS) {
      const r = await fetch(`${issuer}/.well-known/openid-configuration`, { redirect: "manual" });
      if (!r.ok) throw new HttpError(502, "identity provider unavailable");
      const m = await r.json();
      if (String(m.issuer || "").replace(/\/$/, "") !== issuer) throw new HttpError(502, "the provider names another issuer");
      for (const name of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
        if (!String(m[name] || "").startsWith("https://")) throw new HttpError(502, `the provider's ${name} is not https`);
      }
      meta = m; metaAt = Date.now();
    }
    return meta;
  }

  // The provider's keys, cached an hour; an unknown key id refreshes them at most once a minute.
  async function keys(refresh = false) {
    const now = Date.now();
    if (!jwks || now - jwksAt > JWKS_TTL_MS || (refresh && now - refreshedAt > JWKS_REFRESH_MS)) {
      refreshedAt = now;
      const r = await fetch((await getMeta()).jwks_uri, { redirect: "manual" });
      if (!r.ok) throw new HttpError(502, "identity provider unavailable");
      jwks = Object.fromEntries(((await r.json()).keys || [])
        .filter((k) => k.kid && (k.use || "sig") === "sig" && !("d" in k) && ["RSA", "EC", "OKP"].includes(k.kty))
        .map((k) => [k.kid, k]));
      jwksAt = now;
    }
    return jwks;
  }

  async function verify(jwt, { audience = clientId, nonce = null, kind = "id" } = {}) {
    const fail = () => new HttpError(401, "invalid token");
    if (typeof jwt !== "string" || jwt.length > MAX_TOKEN) throw fail();
    const parts = jwt.split(".");
    if (parts.length !== 3) throw fail();
    let header, claims;
    try { header = JSON.parse(b64url(parts[0])); claims = JSON.parse(b64url(parts[1])); } catch { throw fail(); }
    if (!header || !claims || typeof claims !== "object") throw fail();
    const alg = ALGORITHMS[header.alg];
    if (!alg || EMBEDDED_KEYS.some((k) => k in header)) throw fail();
    const typ = String(header.typ || "").toLowerCase();
    if (kind === "id" && (typ === "at+jwt" || typ === "logout+jwt")) throw fail();
    if (kind === "logout" && !["", "jwt", "logout+jwt"].includes(typ)) throw fail();
    const jwk = (await keys())[header.kid] || (await keys(true))[header.kid];
    if (!jwk || jwk.kty !== alg.kty || (jwk.alg && jwk.alg !== header.alg)) throw fail();
    let ok = false;
    try {
      const key = await crypto.subtle.importKey("jwk", jwk, alg.import, false, ["verify"]);
      ok = await crypto.subtle.verify(alg.verify, key, b64url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    } catch { ok = false; }
    const now = Date.now() / 1000;
    const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const required = kind === "logout" ? ["iat", "iss", "aud", "jti"] : ["exp", "iat", "iss", "aud", "sub"];
    if (!ok || required.some((c) => claims[c] === undefined) || String(claims.iss).replace(/\/$/, "") !== issuer
        || !auds.includes(audience) || (claims.exp !== undefined && (typeof claims.exp !== "number" || claims.exp + 30 < now))
        || typeof claims.iat !== "number" || claims.iat > now + 60 || (claims.nbf && claims.nbf - 30 > now)
        || (kind === "id" && auds.length > 1 && claims.azp !== clientId)
        || (nonce !== null && !same(String(claims.nonce || ""), nonce))) throw fail();
    return claims;
  }

  function toUser(claims, session = "") {
    let roles = claims[rolesClaim] || claims.realm_access?.roles || [];
    if (!Array.isArray(roles)) roles = [];
    const amr = Array.isArray(claims.amr) ? claims.amr.map(String) : [];
    return { sub: String(claims.sub), issuer, id: `${issuer}|${claims.sub}`, roles: roles.map(String).sort(),
      tenant: tenantClaim && claims[tenantClaim] != null ? String(claims[tenantClaim]) : null,
      authTime: Number(claims.auth_time || claims.iat) * 1000, amr, session };
  }

  // @mfa: all | admins | provider (the provider enforces it for everyone). Unknown values require it of everyone.
  function secondFactor(user) {
    const rule = String(values.get("mfa", "all"));
    if (rule === "provider") return true;
    const needed = rule !== "admins" || user.roles.includes("admin");
    return !needed || user.amr.some((m) => SECOND_FACTORS.has(m));
  }

  const limits = () => [Number(values.get("session_idle_min")) * 60_000, Number(values.get("session_max_hours")) * 3_600_000];

  async function login(request) {
    const m = await getMeta();
    const state = token(), nonce = token(), verifier = token(48);
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
    const now = Date.now();
    for (const [k, v] of pending) if (v.at < now - PENDING_MS) pending.delete(k);
    while (pending.size >= 10_000) pending.delete(pending.keys().next().value);     // a flood keeps the newest
    pending.set(state, { nonce, verifier, at: now });
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope: scopes.join(" "),
      state, nonce, code_challenge: challenge, code_challenge_method: "S256" });
    if (new URL(request.url).searchParams.get("prompt") === "login") { q.set("prompt", "login"); q.set("max_age", "0"); }
    const h = new Headers({ Location: `${m.authorization_endpoint}?${q}` });
    h.append("Set-Cookie", cookieHeader("__Host-oidc", state, { maxAge: PENDING_MS / 1000 }));
    return new Response(null, { status: 303, headers: h });
  }

  async function callback(request) {
    try {
      const url = new URL(request.url);
      const code = url.searchParams.get("code") || "", state = url.searchParams.get("state") || "";
      const iss = url.searchParams.get("iss");
      if (iss !== null && iss.replace(/\/$/, "") !== issuer) { security("oidc.mixup", {}); throw new HttpError(400, "sign-in failed"); }
      const jar = cookies(request);
      const pend = pending.get(state);
      pending.delete(state);
      if (!code || code.length > 2048 || !pend || !same(jar["__Host-oidc"] || "-", state || "+") || Date.now() - pend.at > PENDING_MS) {
        security("oidc.state", {});
        throw new HttpError(400, "sign-in failed");
      }
      const m = await getMeta();
      const headers = { "Content-Type": "application/x-www-form-urlencoded" };
      if (clientSecret) headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64")}`;
      const r = await fetch(m.token_endpoint, { method: "POST", headers, redirect: "manual",
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId,
          code_verifier: pend.verifier }) });
      let body = {};
      try { const text = r.ok ? await r.text() : ""; body = text.length < 65_536 ? JSON.parse(text || "{}") : {}; } catch { body = {}; }
      if (!body || typeof body.id_token !== "string") { security("oidc.token", { status: r.status }); throw new HttpError(400, "sign-in failed"); }
      const claims = await verify(body.id_token, { nonce: pend.nonce });
      const user = toUser(claims);
      if (!secondFactor(user)) {
        security("signin", { who: user.id, outcome: "no second factor" });
        throw new HttpError(403, "a second factor is required");
      }
      if (jar[SESSION_COOKIE]) await sessions.end(jar[SESSION_COOKIE]);           // a new id at every sign-in
      const sid = await sessions.create(user, { client: await clientOf(request), idpSid: claims.sid || null,
        ttlS: Number(values.get("session_max_hours")) * 3600 });
      security("signin", { who: user.id, outcome: "ok" });
      const h = new Headers({ Location: "/" });
      h.append("Set-Cookie", cookieHeader(SESSION_COOKIE, sid));
      h.append("Set-Cookie", "__Host-oidc=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
      return new Response(null, { status: 303, headers: h });
    } catch (err) {
      if (err instanceof HttpError) return err.toResponse();
      throw err;
    }
  }

  async function currentUser(request) {
    const sid = cookies(request)[SESSION_COOKIE];
    const rec = sid ? await sessions.get(sid, ...limits(), await clientOf(request)) : null;
    return rec ? { ...rec.user, session: sid } : null;
  }

  async function requireUser(request) {
    const user = await currentUser(request);
    if (!user) throw new HttpError(401, "sign in");
    return user;
  }

  async function fresh(request, maxAgeS = 300) {
    const user = await requireUser(request);
    if (Date.now() - user.authTime > maxAgeS * 1000) throw new HttpError(401, "sign in again", { "x-reauth": "/auth/login?prompt=login" });
    return user;
  }

  async function logout(request) {
    const sid = cookies(request)[SESSION_COOKIE];
    const rec = sid ? await sessions.get(sid, ...limits()) : null;
    if (rec) {
      if (new URL(request.url).searchParams.get("everywhere") === "true") await sessions.endUser(rec.user.id);
      await sessions.end(sid);
      security("signout", { who: rec.user.id, outcome: "ok" });
    }
    const h = new Headers({ "Content-Type": "application/json", "Clear-Site-Data": '"cache", "cookies", "storage"' });
    h.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    return new Response(JSON.stringify({ signed_out: true }), { status: 200, headers: h });
  }

  // OpenID Connect Back-Channel Logout: the provider ends the product's sessions; the logout token is used once.
  async function backchannelLogout(request) {
    const bad = () => Response.json({ error: "invalid_request" }, { status: 400 });
    let claims;
    try {
      const form = await request.formData();
      claims = await verify(String(form.get("logout_token") || ""), { kind: "logout" });
    } catch {
      security("oidc.backchannel", { outcome: "invalid token" });
      return bad();
    }
    const events = claims.events;
    if (!events || typeof events !== "object" || !(BACKCHANNEL in events) || "nonce" in claims || !(claims.sid || claims.sub)) return bad();
    const jti = `jti:${await sha256(String(claims.jti))}`;
    if (await sessions.store.get(jti)) return bad();                                  // replayed
    await sessions.store.set(jti, 1, 3600);
    const ended = claims.sid ? await sessions.endProviderSession(issuer, String(claims.sid))
      : await sessions.endUser(`${issuer}|${claims.sub}`);
    security("signout", { who: `${issuer}|${claims.sub || "?"}`, outcome: `backchannel:${ended}` });
    return Response.json({}, { headers: { "Cache-Control": "no-store" } });
  }

  async function listSessions(request) {
    try { const user = await requireUser(request); return Response.json({ sessions: await sessions.ofUser(user.id) }); }
    catch (err) { return err.toResponse(); }
  }

  async function bearer(request, audience) {
    const auth = request.headers.get("authorization") || "";
    if (!/^bearer /i.test(auth)) throw new HttpError(401, "sign in");
    return toUser(await verify(auth.slice(7).trim(), { audience, kind: "access" }));
  }

  return { login, callback, logout, backchannelLogout, sessions: listSessions, currentUser, requireUser, fresh, verify,
    bearer, store: sessions };
}
