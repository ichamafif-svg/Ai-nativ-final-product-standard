"""The Next.js stack (blocks/js/nextjs, D59): the blocks hold their contract (node tests); the scanner reads Next entry
points from where files live; adoption is owed per stack, only for blocks that stack has; the funnel shows the use
for the product's stack; Standard's probes judge a running Next app over HTTP."""
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from instruments import coverage, surfaces  # noqa: E402
from instruments.bans import violations  # noqa: E402
from standard.autonomy.funnel import brief, explain  # noqa: E402
from standard.catalog import effective, implementation, load  # noqa: E402

NODE = shutil.which("node") is not None


class Tree:
    def __init__(self, files):
        self.files = {p: (c.encode() if isinstance(c, str) else c) for p, c in files.items()}

    def paths(self):
        return set(self.files)

    def read(self, path):
        return self.files[path]


PACKAGE = '{"name": "shop", "dependencies": {"next": "15.0.0", "zod": "3.23.0"}}'
LIB = '''import { Values } from "@standard/blocks/values";
import { createOidc } from "@standard/blocks/session";
import { createAccess } from "@standard/blocks/access";
export const values = Values.fromEnv();
export const oidc = createOidc({ issuer: process.env.ISSUER, clientId: "shop", redirectUri: process.env.CB }, values);
export const access = createAccess(oidc.currentUser, values);
'''
MIDDLEWARE = '''import { NextResponse } from "next/server";
import { guard } from "@standard/blocks/web";
import { values } from "@/lib/standard";
export const middleware = guard(values, NextResponse);
'''
GOOD_ROUTE = '''import { z } from "zod";
import { body } from "@standard/blocks/input";
import { access } from "@/lib/standard";
const OrderIn = z.object({ item: z.string().max(100) }).strict();
export const GET = access.route("orders.read", async () => Response.json([]));
export const POST = access.route("orders.create", async (request) => Response.json(await body(request, OrderIn)));
'''
BAD_ROUTE = '''import { cookies } from "next/headers";
import jwt from "jsonwebtoken";
export async function POST(request) {
  const data = await request.json();
  cookies().set("session", jwt.sign(data, "k"));
  return Response.json(data);
}
'''
GOOD = {"package.json": PACKAGE, "lib/standard.js": LIB, "middleware.js": MIDDLEWARE,
        "app/(shop)/orders/route.js": GOOD_ROUTE, "app/health/route.js": "export const GET = () => Response.json({status: 'ok'});"}
BAD = {"package.json": PACKAGE, "app/orders/route.js": BAD_ROUTE}


class Blocks(unittest.TestCase):
    @unittest.skipUnless(NODE, "node is not installed")
    def test_the_nextjs_blocks_hold_their_contract(self):
        r = subprocess.run(["node", "--test", str(ROOT / "blocks" / "js" / "nextjs" / "test.mjs")], capture_output=True,
                           text=True, timeout=120, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])
        self.assertIn("# fail 0", r.stdout)

    def test_every_nextjs_module_named_in_the_catalog_exists(self):
        package = json.loads((ROOT / "blocks" / "js" / "nextjs" / "package.json").read_text())
        for name, block in load()["blocks"].items():
            impl = implementation(load(), name, "nextjs")
            if impl:
                self.assertIn("./" + impl["module"].rsplit("/", 1)[-1], package["exports"], name)

    def test_the_release_pins_the_nextjs_blocks(self):
        from standard.runtime import code_digest
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "repo"
            shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules", ".venv"))
            before = code_digest(dest)
            (dest / "blocks" / "js" / "nextjs" / "web.js").write_text("// loosened\n")
            self.assertNotEqual(code_digest(dest), before)


class Detection(unittest.TestCase):
    def test_entry_points_are_read_from_where_files_live(self):
        files = surfaces.scan(Tree({
            **GOOD,
            "src/app/(shop)/orders/[id]/route.ts": 'export const GET = access.route("orders.read", h);\n'
                                                 'export async function DELETE(r) {}\n',
            "pages/api/legacy/index.js": "export default function h(req, res) {}",
            "app/actions.ts": '"use server";\nexport const cancel = access.action("orders.cancel", f, req);\n',
        }))
        ep = {p: d["endpoints"] for p, d in files["files"].items() if d["endpoints"]}
        self.assertEqual(ep["app/(shop)/orders/route.js"], ["GET /orders", "POST /orders"])
        self.assertEqual(ep["src/app/(shop)/orders/[id]/route.ts"], ["DELETE /orders/:id", "GET /orders/:id"])
        self.assertEqual(ep["pages/api/legacy/index.js"], ["ANY /api/legacy"])
        self.assertEqual(ep["app/actions.ts"], ["POST action:cancel"])
        self.assertEqual(files["files"]["app/(shop)/orders/route.js"]["access"],
                         {"GET /orders": "orders.read", "POST /orders": "orders.create"})
        self.assertEqual(files["files"]["app/actions.ts"]["access"], {"POST action:cancel": "orders.cancel"})
        self.assertEqual(files["stacks"], ["nextjs"])
        self.assertTrue({"api", "web", "oidc", "lang:js"} <= set(files["features"]))
        self.assertNotIn("client-script", files["files"]["app/(shop)/orders/route.js"]["surfaces"])

    def test_the_bans_catch_the_usual_next_code(self):
        found = {pat for _, _, pat in violations(Tree(BAD), {n: b["bans"] for n, b in load()["blocks"].items()})}
        self.assertTrue({"js-import:jsonwebtoken", "js-call:request.json"} <= found, found)
        self.assertTrue(any(p.startswith("js-call:cookies") for p in found), found)
        self.assertEqual(violations(Tree(GOOD), {n: b["bans"] for n, b in load()["blocks"].items()}), [])


class Adoption(unittest.TestCase):
    def setUp(self):
        self.cat = load()
        self.values = effective(self.cat, {"app": "http://127.0.0.1:1"})

    def states(self, files):
        return coverage.evaluate(Tree(files), self.cat, self.values, probes={}, bandit={})

    def test_adoption_is_owed_per_stack_only_for_blocks_the_stack_has(self):
        bare = self.states({"package.json": PACKAGE, "app/orders/route.js": "export const GET = () => Response.json([]);"})
        adopt = {c[0] for s in bare.values() for k, c in s["checks"].items() if k == "blocks" and c[0].startswith("unrun")}
        self.assertIn("unrun:adopt @standard/blocks/web", adopt)
        self.assertFalse(any("standard_blocks" in a for a in adopt), adopt)             # not a Python product
        for name in ("crypto", "log", "data"):                                           # no Next block: nothing owed
            self.assertIsNone(implementation(self.cat, name, "nextjs"))
            self.assertFalse(any(name in a for a in adopt), adopt)
        good = self.states(GOOD)
        owed = {c[0] for s in good.values() for k, c in s["checks"].items() if k == "blocks" and c[0] != "pass"
                and c[0] != "na"}
        self.assertEqual(owed, set())

    def test_the_bad_route_fails_the_blocks_rules(self):
        bad = self.states(BAD)
        failing = {r for r, s in bad.items() if s["checks"].get("blocks", [""])[0] == "fail"}
        self.assertTrue(failing, "a banned API around a rule fails it")

    def test_the_funnel_shows_the_use_for_the_product_stack(self):
        rules = [r for r in self.cat["rules"] if r["block"] in ("web", "session")][:3]
        text = brief(rules, self.values, Tree(GOOD), self.cat)
        self.assertIn("(nextjs) ", text)
        self.assertNotIn("(fastapi) ", text)
        self.assertIn("middleware.js", text)                                   # the house example, from JS files
        why = explain(["app/orders/route.js:2:js-import:jsonwebtoken"], self.values, self.cat)
        self.assertIn("block session", why)
        self.assertIn("(nextjs) ", why)


SERVER = r'''
import http from "node:http";
const root = process.argv[2];
const { Values } = await import(`${root}/blocks/js/nextjs/values.js`);
const { guard, handler } = await import(`${root}/blocks/js/nextjs/web.js`);
const { setSink } = await import(`${root}/blocks/js/nextjs/log.js`);
const { createAccess } = await import(`${root}/blocks/js/nextjs/access.js`);
setSink(() => {});
const values = new Values({ rate_per_minute: 5 });
const mw = guard(values, { next: () => new Response(null, { status: 200 }) });
const access = createAccess(async () => null, values);
const bare = process.argv[3] === "bare";
const routes = {
  "GET /health": handler(async () => Response.json({ status: "ok" })),
  "GET /api/orders": access.route("orders.read", async () => Response.json([])),
  "POST /api/orders": access.route("orders.create", async () => Response.json({})),
};
http.createServer(async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c);
  const url = `http://${req.headers.host}${req.url}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  let r = bare ? new Response(null, { status: 200 }) : await mw({ method: req.method, url, headers });
  if (r.status === 200) {
    const key = `${req.method} ${new URL(url).pathname}`;
    const h = bare ? async () => Response.json({ status: "ok" }) : routes[key];
    const init = { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks) };
    const inner = bare ? Response.json({ status: "ok" }) : h ? await h(new Request(url, init)) : new Response("not found", { status: 404 });
    for (const [k, v] of r.headers) inner.headers.set(k, v);
    r = inner;
  }
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(0, "127.0.0.1", function () { console.log(this.address().port); });
'''


@unittest.skipUnless(NODE, "node is not installed")
class OverHttp(unittest.TestCase):
    """A running app behind the web and access blocks passes the HTTP probes; the same routes bare fail them."""

    def run_against(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "server.mjs"
            script.write_text(SERVER)
            proc = subprocess.Popen(["node", str(script), str(ROOT), mode], stdout=subprocess.PIPE, text=True)
            self.addCleanup(proc.stdout.close)
            try:
                port = int(proc.stdout.readline())
                values = effective(load(), {"app": f"http://127.0.0.1:{port}", "rate_per_minute": 5})
                tree = Tree({"package.json": PACKAGE, "app/health/route.js": "export const GET = h;",
                             "app/api/orders/route.js": "export const GET = a;\nexport const POST = b;"})
                start = time.time()
                out = coverage.app_probes(tree, values)
                self.assertLess(time.time() - start, 120)
                return out
            finally:
                proc.kill()
                proc.wait()

    def test_the_blocks_pass_and_bare_routes_fail(self):
        good, bare = self.run_against("blocks"), self.run_against("bare")
        for probe in ("headers", "cors", "csrf", "methods", "errors", "no-store", "param-pollution", "unauthenticated",
                      "health", "rate-limit"):
            self.assertEqual(good[probe][0], "pass", (probe, good[probe]))
        for probe in ("headers", "csrf", "methods", "param-pollution", "unauthenticated", "rate-limit"):
            self.assertEqual(bare[probe][0], "fail", (probe, bare[probe]))
        self.assertEqual(good["oidc-flow"][0], "gap")                     # in-process only: a gap, never a debt


if __name__ == "__main__":
    unittest.main()
