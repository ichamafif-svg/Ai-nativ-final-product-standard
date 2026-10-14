// The web layer for Next.js (same contract as standard_blocks.web): security headers, CORS from @origins, CSRF for
// cookie sessions, refused methods, repeated parameters, rate limits, HTTPS, no-store when authenticated, cookie flags,
// safe redirects, generic errors. Beyond the checklists, as in the Python block: Fetch Metadata resource isolation
// (a cross-site request that is not a top-level navigation is refused unless its origin is in @origins), @hosts
// (421 for any other Host), bounded URLs, rate limits per address and route and per address overall in a shared store
// with least-recent eviction, Trusted Types and a deny-all Permissions-Policy, and product hooks that can only refuse.
//
//   // middleware.js
//   import { NextResponse } from "next/server";
//   import { guard } from "@standard/blocks/web";
//   export const middleware = guard(values, NextResponse);
//
//   // next.config.js
//   headers: async () => securityHeaders(values)
import { security, event } from "./log.js";
import { storeFor } from "./store.js";

export const SESSION_COOKIE = "__Host-session";
export const CSRF_COOKIE = "__Host-csrf";
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);
const REFUSED = new Set(["TRACE", "TRACK", "CONNECT"]);
const HSTS = "max-age=63072000; includeSubDomains; preload";
const MAX_URL = 8192;
// A CSP source the human may add: a host or a hash; never a keyword that reopens injection, never a separator.
const SOURCE = /^(?:(?:https:\/\/)?(?:\*\.)?[a-z0-9.-]+(?::\d{1,5})?(?:\/[\w./-]*)?|'sha(?:256|384|512)-[A-Za-z0-9+/]+=*')$/;
export const PERMISSIONS = "accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), browsing-topics=(), " +
  "camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), hid=(), " +
  "identity-credentials-get=(), idle-detection=(), interest-cohort=(), local-fonts=(), magnetometer=(), microphone=(), " +
  "midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(self), screen-wake-lock=(), serial=(), " +
  "usb=(), web-share=(), xr-spatial-tracking=()";

export function csp(values) {
  const extra = values.get("csp_sources").filter((s) => SOURCE.test(String(s))).join(" ");
  const src = `'self' ${extra}`.trim();
  let policy = `default-src ${src}; script-src ${src}; style-src ${src}; img-src ${src} data:; font-src ${src}; ` +
    `connect-src ${src}; media-src ${src}; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; ` +
    "frame-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests; report-to standard";
  if (values.get("trusted_types", "enforce") === "enforce") policy += "; require-trusted-types-for 'script'";
  return policy;
}

export function headerList(values) {
  const out = [
    ["Strict-Transport-Security", HSTS], ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "strict-origin-when-cross-origin"], ["Cross-Origin-Opener-Policy", "same-origin"],
    ["Cross-Origin-Resource-Policy", "same-origin"], ["X-Frame-Options", "DENY"],
    ["X-Permitted-Cross-Domain-Policies", "none"], ["Permissions-Policy", PERMISSIONS],
    ["Content-Security-Policy", csp(values)], ["Reporting-Endpoints", 'standard="/.well-known/csp-report"'],
    ["Origin-Agent-Cluster", "?1"],
  ];
  if (values.get("trusted_types", "enforce") === "report") {
    out.push(["Content-Security-Policy-Report-Only", "require-trusted-types-for 'script'; report-to standard"]);
  }
  return out;
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
  if (/[;,\r\n \t\0]/.test(full + value) || full.length + String(value).length > 4000) {
    throw new Error("a cookie is one token under 4 KB");
  }
  return `${full}=${value}; Path=/; Secure; SameSite=Lax${readable ? "" : "; HttpOnly"}${maxAge === null ? "" : `; Max-Age=${maxAge}`}`;
}

export function setCookie(response, name, value, options) {
  response.headers.append("Set-Cookie", cookieHeader(name, value, options));
  return response;
}

// A redirect inside the app (a path), or to a host in @redirect_targets; anything else goes home.
export function redirectTo(request, target, values, status = 303) {
  const bad = typeof target !== "string" || /[\\\r\n\t\0]/.test(target) || target.startsWith("//");
  let ok = !bad && target.startsWith("/");
  if (!ok && !bad) {
    try {
      const u = new URL(target);
      ok = u.protocol === "https:" && !u.username && !u.password && values.get("redirect_targets").includes(u.hostname);
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

function v4(addr) {
  const parts = addr.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) < 256)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

// An address inside one of @trusted_proxies: IPv4 addresses and CIDR ranges, other addresses exactly.
export function inNets(nets, addr) {
  const a = v4(addr.trim());
  for (const net of nets) {
    const [base, bits] = String(net).split("/");
    if (a !== null && v4(base) !== null) {
      const n = bits === undefined ? 32 : Number(bits);
      if (!(n >= 0 && n <= 32)) continue;
      const mask = n === 0 ? 0 : (2 ** 32 - 2 ** (32 - n));
      if (Math.floor(a / 2 ** (32 - n)) === Math.floor(v4(base) / 2 ** (32 - n)) || mask === 0) return true;
    } else if (String(net).toLowerCase() === addr.trim().toLowerCase()) return true;
  }
  return false;
}

// The client address: the platform's own (request.ip), else X-Forwarded-For only behind @trusted_proxies, read from
// the right (the left end is whatever the client wrote), else one shared bucket.
export function clientIp(request, values) {
  if (request.ip) return request.ip;
  const trusted = values.get("trusted_proxies");
  if (!trusted.length) return "direct";
  const hops = (request.headers.get("x-forwarded-for") || "").split(",").map((s) => s.trim()).filter(Boolean);
  while (hops.length && inNets(trusted, hops[hops.length - 1])) hops.pop();
  return hops.pop() || "direct";
}

function json(status, body, headers = {}, values = null) {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", ...headers });
  if (values) for (const [k, v] of headerList(values)) h.set(k, v);
  return new Response(JSON.stringify(body), { status, headers: h });
}

function hostOk(request, values) {
  if (!values.has("hosts") || !values.get("hosts").length) return true;
  let host = request.headers.get("host") || "";
  if (values.get("trusted_proxies").length && request.headers.get("x-forwarded-host")) {
    host = request.headers.get("x-forwarded-host").split(",").pop().trim();
  }
  const name = host.endsWith("]") ? host : host.replace(/:\d+$/, "");
  return values.get("hosts").map((h) => h.toLowerCase()).includes(name.toLowerCase().replace(/\.$/, ""));
}

// Fetch Metadata resource isolation: true when the request must be refused.
function isolated(method, headers, cors) {
  const site = headers.get("sec-fetch-site");
  if (!site || site === "same-origin" || site === "none" || (cors && cors !== "refused" && cors !== "same")) return false;
  const navigation = (method === "GET" || method === "HEAD") && headers.get("sec-fetch-mode") === "navigate" &&
    !["object", "embed", "iframe", "frame"].includes(headers.get("sec-fetch-dest"));
  return !navigation;
}

// The middleware: refuses what must not reach a route, and dresses the response Next continues with.
// `refuse`: product checks (request) -> reason or null; they can only refuse. `store`: shared limits (redisStore).
export function guard(values, NextResponse, { production = process.env.STANDARD_ENV === "production", store = null,
  refuse = [] } = {}) {
  const limits = storeFor(store);
  if (production && (!values.has("hosts") || !values.get("hosts").length)) {
    security("hosts.unset", { outcome: "every host name is answered: set @hosts" });
  }
  return async function middleware(request) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const jar = cookies(request);
    const authenticated = SESSION_COOKIE in jar || request.headers.has("authorization");
    if (url.pathname.length + url.search.length > MAX_URL) return json(414, { error: "URL too long" }, {}, values);
    if (REFUSED.has(method)) return json(405, { error: "method not allowed" }, {}, values);
    if (!hostOk(request, values)) {
      security("host.refused", { route: url.pathname });
      return json(421, { error: "unknown host" }, {}, values);
    }
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
    if (isolated(method, request.headers, cors)) {
      security("fetch_metadata.refused", { route: url.pathname });
      return json(403, { error: "cross-site request refused" }, {}, values);
    }
    for (const check of refuse) {                 // product hooks: they may only refuse
      let reason;
      try { reason = await check(request); } catch { reason = "check failed"; }
      if (reason) {
        security("hook.refused", { route: url.pathname });
        return json(403, { error: String(reason).slice(0, 100) }, {}, values);
      }
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
      const rate = Number(values.get("rate_per_minute"));
      if (!(await limits.take(`rl:${ip}:${url.pathname}`, rate)) || !(await limits.take(`rl:${ip}`, rate * 10))) {
        security("rate.limited", { route: url.pathname });
        return json(429, { error: "too many requests" }, { "Retry-After": "60" }, values);
      }
    }
    const declared = request.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > Number(values.get("body_max_bytes")) &&
        !(request.headers.get("content-type") || "").startsWith("multipart/form-data"))) {
      return json(/^\d+$/.test(declared) ? 413 : 400, { error: "body too large" }, {}, values);
    }
    const response = NextResponse.next();
    for (const [k, v] of headerList(values)) response.headers.set(k, v);
    for (const [k, v] of Object.entries(corsHeaders)) response.headers.set(k, v);
    response.headers.delete("x-powered-by");
    if (authenticated) response.headers.set("Cache-Control", "no-store");
    if (SESSION_COOKIE in jar && !(CSRF_COOKIE in jar)) {
      response.headers.append("Set-Cookie", cookieHeader(CSRF_COOKIE, token(16), { readable: true }));
    }
    return response;
  };
}
