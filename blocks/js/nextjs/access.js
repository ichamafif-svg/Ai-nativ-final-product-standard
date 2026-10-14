// Who may call which route or server action, for Next.js (same contract as standard_blocks.access): every route
// handler and server action names an id; @access maps ids to roles, read on every call; an id missing from @access is
// admin-only; @public ("METHOD /path") needs no sign-in; everything else needs one. Finer rules (owner, tenant,
// amount) come as `also` predicates (user, request) that can only refuse: run after the role is allowed, a predicate
// that throws or answers anything but true refuses, with the same 403 whatever the reason.
//
//   const access = createAccess(oidc.currentUser, values);
//   export const GET = access.route("orders.read", async (request, ctx, user) => Response.json(...));
//   export const cancel = access.action("orders.cancel", async (user, orderId) => ..., () => requestLike());
import { handler } from "./web.js";
import { HttpError } from "./session.js";
import { security } from "./log.js";

export const ADMIN = "admin";
export const MARK = Symbol.for("standard.access");

export function allowedRoles(values, id) {
  const roles = values.get("access")[id];
  return roles === undefined ? [ADMIN] : Array.isArray(roles) ? roles : [String(roles)];
}

export function createAccess(currentUser, values) {
  const access = {
    currentUser,

    isPublic(method, path) {
      return values.get("public").includes(`${method.toUpperCase()} ${path}`);
    },

    async check(id, request, { method = request.method, path = new URL(request.url).pathname, also = [] } = {}) {
      if (typeof id !== "string" || !/^[\w.:-]{1,100}$/.test(id)) throw new Error("an access id is [A-Za-z0-9_.:-]");
      if (access.isPublic(method, path)) return null;
      const user = await access.currentUser(request);
      if (!user) { security("access.unauthenticated", { route: id }); throw new HttpError(401, "sign in"); }
      const allowed = allowedRoles(values, id);
      if (allowed.includes("*") || user.roles.some((r) => allowed.includes(r))) {
        for (const predicate of also) {
          let ok = false;
          try { ok = (await predicate(user, request)) === true; } catch { ok = false; }
          if (!ok) {
            security("access.refused", { who: user.id, route: id, outcome: "predicate" });
            throw new HttpError(403, "not allowed");
          }
        }
        return user;
      }
      security("access.refused", { who: user.id, route: id });
      throw new HttpError(403, "not allowed");
    },

    // A route handler, wrapped: access first, then the handler with the user; errors become generic.
    route(id, fn, { also = [] } = {}) {
      const wrapped = handler(async (request, ctx) => fn(request, ctx, await access.check(id, request, { also })));
      wrapped[MARK] = id;
      return wrapped;
    },

    // A server action, wrapped: `requestLike()` gives the incoming headers (next/headers) as a Request-like object.
    action(id, fn, requestLike, { also = [] } = {}) {
      const wrapped = async (...args) => {
        const request = await requestLike();
        const user = await access.check(id, request, { method: "POST", path: `action:${id}`, also });
        return fn(user, ...args);
      };
      wrapped[MARK] = id;
      return wrapped;
    },
  };
  return access;
}
