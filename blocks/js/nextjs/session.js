// Sign-in through the identity provider, and the product's own sessions, for Next.js (same contract as
// standard_blocks.session): OpenID Connect code flow with PKCE (S256), state and nonce; the ID token's signature
// (algorithms from an allow-list, keys from the provider's JWKS), issuer, audience, expiry and nonce checked with
// WebCrypto; server-side sessions behind a 256-bit id in a __Host- cookie, rotated at sign-in, idle and absolute
// limits, logout everywhere, re-authentication. The product never sees a password; tokens never reach the browser.
//
//   const oidc = createOidc({ issuer, clientId, clientSecret, redirectUri }, values);
//   // app/auth/login/route.js       export const GET = oidc.login;
//   // app/auth/callback/route.js    export const GET = oidc.callback;
//   // app/auth/logout/route.js      export const POST = oidc.logout;
//   const user = await oidc.currentUser(request);          // null when signed out
import { cookieHeader, cookies, same, SESSION_COOKIE, token } from "./web.js";
import { security } from "./log.js";

const ALGORITHMS = {
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" } },
  PS256: { import: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 } },
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } },
};
const PENDING_MS = 600_000;

export class HttpError extends Error {
  constructor(status, message, headers = {}) { super(message); this.status = status; this.headers = headers; }
  toResponse() { return Response.json({ error: this.message }, { status: this.status, headers: this.headers }); }
}

const b64url = (s) => Buffer.from(s, "base64url");

export class Sessions {
  constructor() { this.byId = new Map(); }
  create(user) { const sid = token(32); this.byId.set(sid, { user, created: Date.now(), seen: Date.now() }); return sid; }
  get(sid, idleMs, maxMs) {
    const rec = this.byId.get(sid);
    if (!rec) return null;
    const now = Date.now();
    if (now - rec.seen > idleMs || now - rec.created > maxMs) { this.byId.delete(sid); return null; }
    rec.seen = now;
    return rec;
  }
  end(sid) { this.byId.delete(sid); }
  endUser(userId, keep = null) {
    let n = 0;
    for (const [sid, rec] of this.byId) if (rec.user.id === userId && sid !== keep) { this.byId.delete(sid); n++; }
    return n;
  }
  ofUser(userId) {
    return [...this.byId].filter(([, r]) => r.user.id === userId).map(([sid, r]) => ({ id: sid.slice(0, 8), created: r.created, seen: r.seen }));
  }
}

export function createOidc({ issuer, clientId, clientSecret = null, redirectUri, scopes = ["openid"], fetch = globalThis.fetch,
  rolesClaim = "roles", tenantClaim = null, sessions = new Sessions() }, values) {
  issuer = issuer.replace(/\/$/, "");
  if (!issuer.startsWith("https://")) throw new Error("the issuer is reached over https");
  const pending = new Map();
  let meta = null, jwks = null;

  async function getMeta() {
    if (!meta) {
      const r = await fetch(`${issuer}/.well-known/openid-configuration`);
      if (!r.ok) throw new HttpError(502, "identity provider unavailable");
      const m = await r.json();
      if (String(m.issuer || "").replace(/\/$/, "") !== issuer) throw new HttpError(502, "the provider names another issuer");
      meta = m;
    }
    return meta;
  }

  async function keys(refresh = false) {
    if (!jwks || refresh) {
      const r = await fetch((await getMeta()).jwks_uri);
      if (!r.ok) throw new HttpError(502, "identity provider unavailable");
      jwks = Object.fromEntries((await r.json()).keys.filter((k) => k.kid).map((k) => [k.kid, k]));
    }
    return jwks;
  }

  async function verify(jwt, { audience = clientId, nonce = null } = {}) {
    const fail = () => new HttpError(401, "invalid token");
    const parts = String(jwt).split(".");
    if (parts.length !== 3) throw fail();
    let header, claims;
    try { header = JSON.parse(b64url(parts[0])); claims = JSON.parse(b64url(parts[1])); } catch { throw fail(); }
    const alg = ALGORITHMS[header.alg];
    if (!alg) throw fail();
    let jwk = (await keys())[header.kid] || (await keys(true))[header.kid];
    if (!jwk) throw fail();
    const key = await crypto.subtle.importKey("jwk", jwk, alg.import, false, ["verify"]);
    const ok = await crypto.subtle.verify(alg.verify, key, b64url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    const now = Date.now() / 1000;
    const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!ok || String(claims.iss).replace(/\/$/, "") !== issuer || !auds.includes(audience) || !claims.sub
        || typeof claims.exp !== "number" || claims.exp + 30 < now || typeof claims.iat !== "number"
        || (claims.nbf && claims.nbf - 30 > now) || (nonce !== null && !same(String(claims.nonce || ""), nonce))) throw fail();
    return claims;
  }

  function toUser(claims, session = "") {
    const roles = claims[rolesClaim] || claims.realm_access?.roles || [];
    return { sub: String(claims.sub), issuer, id: `${issuer}|${claims.sub}`, roles: [...roles].map(String).sort(),
      tenant: tenantClaim && claims[tenantClaim] != null ? String(claims[tenantClaim]) : null,
      authTime: Number(claims.auth_time || claims.iat) * 1000, session };
  }

  const limits = () => [Number(values.get("session_idle_min")) * 60_000, Number(values.get("session_max_hours")) * 3_600_000];

  async function login(request) {
    const m = await getMeta();
    const state = token(), nonce = token(), verifier = token(48);
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
    const now = Date.now();
    for (const [k, v] of pending) if (v.at < now - PENDING_MS) pending.delete(k);
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
      if (!code || !pend || !same(jar["__Host-oidc"] || "-", state || "+") || Date.now() - pend.at > PENDING_MS) {
        security("oidc.state", {});
        throw new HttpError(400, "sign-in failed");
      }
      const m = await getMeta();
      const headers = { "Content-Type": "application/x-www-form-urlencoded" };
      if (clientSecret) headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
      const r = await fetch(m.token_endpoint, { method: "POST", headers, redirect: "manual",
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId,
          code_verifier: pend.verifier }) });
      const body = r.ok ? await r.json() : {};
      if (!body.id_token) { security("oidc.token", { status: r.status }); throw new HttpError(400, "sign-in failed"); }
      const claims = await verify(body.id_token, { nonce: pend.nonce });
      if (jar[SESSION_COOKIE]) sessions.end(jar[SESSION_COOKIE]);           // a new id at every sign-in
      const user = toUser(claims);
      const sid = sessions.create(user);
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
    const rec = sid ? sessions.get(sid, ...limits()) : null;
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
    const rec = sid ? sessions.get(sid, ...limits()) : null;
    if (rec) {
      if (new URL(request.url).searchParams.get("everywhere") === "true") sessions.endUser(rec.user.id);
      sessions.end(sid);
      security("signout", { who: rec.user.id, outcome: "ok" });
    }
    const h = new Headers({ "Content-Type": "application/json", "Clear-Site-Data": '"cache", "cookies", "storage"' });
    h.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    return new Response(JSON.stringify({ signed_out: true }), { status: 200, headers: h });
  }

  async function listSessions(request) {
    try { const user = await requireUser(request); return Response.json({ sessions: sessions.ofUser(user.id) }); }
    catch (err) { return err.toResponse(); }
  }

  async function bearer(request, audience) {
    const auth = request.headers.get("authorization") || "";
    if (!/^bearer /i.test(auth)) throw new HttpError(401, "sign in");
    return toUser(await verify(auth.slice(7), { audience }));
  }

  return { login, callback, logout, sessions: listSessions, currentUser, requireUser, fresh, verify, bearer, store: sessions };
}
