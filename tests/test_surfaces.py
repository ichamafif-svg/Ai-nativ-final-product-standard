"""Detection (instruments/surfaces.py): what a product has and what a change touches, read without running anything,
the same answer every time; every term of the catalog's vocabulary has a detector."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from instruments import surfaces  # noqa: E402
from standard.catalog import load, select  # noqa: E402


class Tree:
    def __init__(self, files):
        self.files = {p: (c.encode() if isinstance(c, str) else c) for p, c in files.items()}

    def paths(self):
        return set(self.files)

    def read(self, path):
        return self.files[path]


APP = '''from fastapi import FastAPI, UploadFile, File, Depends
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
import subprocess as sp
from os import system
import httpx, hashlib, pickle, logging

log = logging.getLogger(__name__)
app = FastAPI()

class Base(DeclarativeBase): pass

class Order(Base):
    __tablename__ = "orders"
    tenant_id: int

@app.get("/orders/{oid}")
def read(oid: int):
    return conn.execute(f"SELECT * FROM orders WHERE id = {oid}")

@app.post("/files")
async def upload(f: UploadFile = File(...)):
    sp.run(["convert", "a", "b"])
    return {"ok": True}

@app.post("/login")
def login(form: LoginIn):
    if form.password == stored_password:
        system("echo hi")
    log.info("login %s", form.user)
    data = pickle.loads(b"")
    r = httpx.get("https://billing.example/x", verify=False)
    return hashlib.md5(b"x").hexdigest()
'''
JS = '''// localStorage in a comment does not count
const s = "innerHTML in a string does not count";
el.innerHTML = note;
fetch("/api");
'''


class Detection(unittest.TestCase):
    def test_a_product_is_read_from_its_code(self):
        tree = Tree({"app/main.py": APP, "static/app.js": JS, "templates/page.html": "<form method=post></form>",
                     "alembic/versions/001_init.py": "def upgrade(): pass\n", "requirements.txt": "fastapi\n",
                     "node_modules/x/index.js": "eval('x')", "tests/test_x.py": "import pickle"})
        out = surfaces.scan(tree)
        main = out["files"]["app/main.py"]
        self.assertEqual(main["endpoints"], ["GET /orders/{oid}", "POST /files", "POST /login"])
        for c in ("sql-call", "subprocess", "deserialize", "http-client", "hash", "secret-compare", "log-write",
                  "tls-context", "request-body", "response-model"):
            self.assertIn(c, main["constructs"], c)
        for s in ("endpoint", "upload-endpoint", "data-model", "outbound-call", "log-call"):
            self.assertIn(s, main["surfaces"], s)
        js = out["files"]["static/app.js"]
        self.assertEqual(js["constructs"], ["html-output", "http-client"])         # comments and strings ignored
        self.assertNotIn("node_modules/x/index.js", out["files"])
        self.assertNotIn("tests/test_x.py", out["files"])
        self.assertIn("migration", out["files"]["alembic/versions/001_init.py"]["surfaces"])
        self.assertIn("form", out["files"]["templates/page.html"]["surfaces"])
        for f in ("api", "web", "oidc", "upload", "database", "outbound-http", "multitenant", "lang:python", "lang:js"):
            self.assertIn(f, out["features"], f)
        self.assertEqual(surfaces.scan(tree), out)                                      # the same answer
        self.assertIn("high-value", surfaces.scan(tree, declared=["high-value", "anything"])["features"])
        self.assertNotIn("anything", surfaces.scan(tree, declared=["anything"])["features"])

    def test_a_change_touches_only_what_its_files_hold(self):
        base = Tree({"app/main.py": "x = 1\n", "app/other.py": "import pickle\npickle.loads(b'')\n"})
        head = Tree({"app/main.py": "import re\nre.compile(user)\n", "app/other.py": "import pickle\npickle.loads(b'')\n"})
        self.assertEqual(surfaces.touched(base, head), ["construct:regex"])
        cat = load()
        fine = [r["id"] for r in select(cat, ["api", "lang:python"], surfaces.touched(base, head))]
        self.assertEqual(fine, ["REDOS", "REGEX-ESCAPE"])

    def test_an_express_server_is_read_like_a_fastapi_one(self):
        server = "const express = require('express');\nconst app = express();\napp.get('/orders/:id', h);\n" \
                 "router.post(\"/orders\", h);\n"
        out = surfaces.scan(Tree({"server.js": server}))
        self.assertEqual(out["files"]["server.js"]["endpoints"], ["GET /orders/:id", "POST /orders"])
        self.assertIn("api", out["features"])
        self.assertNotIn("client-script", out["files"]["server.js"]["surfaces"])

    def test_the_front_kit_holds_its_rules(self):
        import shutil
        import subprocess
        if shutil.which("node") is None:
            self.skipTest("node is not installed")
        r = subprocess.run(["node", str(ROOT / "blocks" / "js" / "front.test.mjs")], capture_output=True, text=True,
                           timeout=60)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "front ok"), r.stderr)

    def test_unparseable_and_huge_files_are_empty_never_an_error(self):
        out = surfaces.scan(Tree({"bad.py": "def (:", "big.py": b"x = 1\n" * 300_000}))
        self.assertEqual(out["files"]["bad.py"]["constructs"], [])
        self.assertEqual(out["files"]["big.py"]["constructs"], [])

    def test_every_vocabulary_term_has_a_detector(self):
        vocab, have = load()["vocabulary"], surfaces.detectors()
        for kind in ("features", "surfaces", "constructs"):
            self.assertEqual(set(vocab[kind]) - have[kind], set(), kind)


if __name__ == "__main__":
    unittest.main()
