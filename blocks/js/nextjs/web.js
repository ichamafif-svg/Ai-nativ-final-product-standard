// The web layer for Next.js (same contract as standard_blocks.web): security headers, CORS from @origins, CSRF for
// cookie sessions, refused methods, repeated parameters, rate limits, HTTPS, no-store when authenticated, cookie flags,
// safe redirects, generic errors.
//
//   // middleware.js
//   import { NextResponse } from "next/server";
//   import { guard } from "@standard/blocks/web";
//   export const middleware = guard(values, NextResponse);
//
//   // next.config.js
//   headers: async () => securityHeaders(values)
import { security, event } from "./log.js";

export const SESSION_COOKIE = "__Host-session";
export const CSRF_COOKIE = "__Host-csrf";
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);
const REFUSED = new Set(["TRACE", "TRACK", "CONNECT"]);
const HSTS = "max-age=31536000; includeSubDomains; preload";

export function csp(values) {
  const extra = values.get("csp_sources").filter((s) => !/[\s;]/.test(s)).join(" ");
  const src = `'self' ${extra}`.trim();
  return `default-src ${src}; script-src ${src}; style-src ${src}; img-src ${src} data:; connect-src ${src}; ` +
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-to standard";
}

export function headerList(values) {
  return [
    ["Strict-Transport-Security", HSTS], ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "strict-origin-when-cross-origin"], ["Cross-Origin-Opener-Policy", "same-origin"],
    ["X-Frame-Options", "DENY"], ["Content-Security-Policy", csp(values)],
    ["Reporting-Endpoints", 'standard="/.well-known/csp-report"'],
  ];
}

// For next.config.js `headers()`: every route, every response. Also set `poweredByHeader: false`.
export function securityHeaders(values) {
  return [{ source: "/:path*", headers: headerList(values).map(([key, value]) => ({ key, value })) }];
}

export function cookies(request) {
  const out = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function same(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

export function token(bytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return Buffer.from(b).toString("base64url");
}

// A cookie with the __Host- prefix, Secure, SameSite=Lax, HttpOnly unless a script must read it, under 4 KB.
export function cookieHeader(name, value, { maxAge = null, readable = false } = {}) {
  const full = name.startsWith("__Host-") ? name : `__Host-${name}`;
  if (full.length + String(value).length > 4000) throw new Error("a cookie stays under 4 KB");
  return `${full}=${value}; Path=/; Secure; SameSite=Lax${readable ? "" : "; HttpOnly"}${maxAge === null ? "" : `; Max-Age=${maxAge}`}`;
}

export function setCookie(response, name, value, options) {
  response.headers.append("Set-Cookie", cookieHeader(name, value, options));
  return response;
}

// A redirect inside the app (a path), or to a host in @redirect_targets; anything else goes home.
export function redirectTo(request, target, values, status = 303) {
  let ok = typeof target === "string" && target.startsWith("/") && !target.startsWith("//") && !target.includes("\\");
  if (!ok) {
    try {
      const u = new URL(target);
      ok = u.protocol === "https:" && values.get("redirect_targets").includes(u.hostname);
    } catch { ok = false; }
  }
  if (!ok) { security("redirect.refused", { route: new URL(request.url).pathname }); target = "/"; }
  return new Response(null, { status, headers: { Location: target } });
}

// Wrap a route handler: an exception becomes a generic error with a reference; details go to the log.
export function handler(fn) {
  return async (...args) => {
    try {
      return await fn(...args);
    } catch (err) {
      if (err && typeof err.toResponse === "function") return err.toResponse();
      const ref = token(16);
      event("error.unhandled", { ref, kind: err?.name || "Error" });
      return Response.json({ error: "internal error", ref }, { status: 500 });
    }
  };
}

class Buckets {
  constructor() { this.state = new Map(); }
  take(key, perMinute) {
    const now = Date.now();
    const [tokens, at] = this.state.get(key) || [perMinute, now];
    const next = Math.min(perMinute, tokens + ((now - at) / 60000) * perMinute);
    if (next < 1) { this.state.set(key, [next, now]); return false; }
    this.state.set(key, [next - 1, now]);
    if (this.state.size > 100000) this.state.clear();
    return true;
  }
}

// The client address: the platform's own (request.ip), else X-Forwarded-For only behind @trusted_proxies (the hop
// the last trusted proxy saw), else one shared bucket.
export function clientIp(request, values) {
  if (request.ip) return request.ip;
  const trusted = values.get("trusted_proxies");
  if (!trusted.length) return "direct";
  const hops = (request.headers.get("x-forwarded-for") || "").split(",").map((s) => s.trim()).filter(Boolean);
  while (hops.length && trusted.includes(hops[hops.length - 1])) hops.pop();
  return hops.pop() || "direct";
}

function json(status, body, headers = {}, values = null) {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", ...headers });
  if (values) for (const [k, v] of headerList(values)) h.set(k, v);
  return new Response(JSON.stringify(body), { status, headers: h });
}

// The middleware: refuses what must not reach a route, and dresses the response Next continues with.
export function guard(values, NextResponse, { production = process.env.STANDARD_ENV === "production" } = {}) {
  const buckets = new Buckets();
  return async function middleware(request) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const jar = cookies(request);
    const authenticated = SESSION_COOKIE in jar || request.headers.has("authorization");
    if (REFUSED.has(method)) return json(405, { error: "method not allowed" }, {}, values);
    const keys = [...url.searchParams.keys()];
    if (new Set(keys).size !== keys.length) return json(400, { error: "a parameter appears twice" }, {}, values);
    if (production && url.protocol === "http:") {
      if (method === "GET" && (request.headers.get("accept") || "").includes("text/html")) {
        return new Response(null, { status: 308, headers: { Location: url.href.replace(/^http:/, "https:") } });
      }
      return json(403, { error: "https only" }, {}, values);
    }
    const origin = request.headers.get("origin");
    let cors = null;
    if (origin) {
      let host = null;
      try { host = new URL(origin).host; } catch { host = null; }
      cors = host && host === request.headers.get("host") ? "same" : values.get("origins").includes(origin) ? origin : "refused";
    }
    const corsHeaders = cors && cors !== "same" && cors !== "refused"
      ? { "Access-Control-Allow-Origin": cors, Vary: "Origin", "Access-Control-Allow-Credentials": "true" } : {};
    if (method === "OPTIONS" && request.headers.has("access-control-request-method")) {
      if (!cors || cors === "refused") return json(403, { error: "origin not allowed" }, {}, values);
      const h = new Headers({ ...corsHeaders, "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE",
        "Access-Control-Allow-Headers": "content-type, x-csrf-token, authorization", "Access-Control-Max-Age": "600" });
      for (const [k, v] of headerList(values)) h.set(k, v);
      return new Response(null, { status: 204, headers: h });
    }
    if (!SAFE.has(method)) {
      if (cors === "refused") return json(403, { error: "origin not allowed" }, {}, values);
      if (SESSION_COOKIE in jar && !request.headers.has("authorization")) {
        if (!same(request.headers.get("x-csrf-token") || "-", jar[CSRF_COOKIE] || "+")) {
          security("csrf.refused", { route: url.pathname });
          return json(403, { error: "csrf" }, {}, values);
        }
      }
      const ip = clientIp(request, values);
      if (!buckets.take(`${ip} ${url.pathname}`, Number(values.get("rate_per_minute")))) {
        return json(429, { error: "too many requests" }, { "Retry-After": "60" }, values);
      }
    }
    const response = NextResponse.next();
    for (const [k, v] of headerList(values)) response.headers.set(k, v);
    for (const [k, v] of Object.entries(corsHeaders)) response.headers.set(k, v);
    if (authenticated) response.headers.set("Cache-Control", "no-store");
    if (SESSION_COOKIE in jar && !(CSRF_COOKIE in jar)) {
      response.headers.append("Set-Cookie", cookieHeader(CSRF_COOKIE, token(16), { readable: true }));
    }
    return response;
  };
}
