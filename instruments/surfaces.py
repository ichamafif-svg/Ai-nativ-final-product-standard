"""What a product has, and what a change touches: features, surfaces and constructs (catalog/vocabulary.toml).

Deterministic: the same tree gives the same answer. Python files are read on their syntax tree with imports resolved
(`from os import system` makes `system(...)` a call to `os.system`); JavaScript and TypeScript are read lexically,
comments and strings removed, until a pinned parser replaces it (catalog lot 9). Nothing is executed.

    scan(tree)                      -> {"features": [...], "files": {path: {"surfaces": [...], "constructs": [...],
                                        "endpoints": [...]}}}
    touched(base, head)             -> sorted "surface:x" / "construct:y" terms in the files a change touches
    features(tree, declared=())     -> sorted features of the product (`declared` come from the rules of the game:
                                       high-value, adaptive, team)

A detection is information for choosing rules, never a fact: the scanner signs facts from measures, not from this.
"""
from __future__ import annotations

import ast
import re
from functools import lru_cache

MAX_FILE = 1_000_000
PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
TEMPLATES = (".html", ".jinja", ".jinja2", ".j2")
SKIP = re.compile(r"(^|/)(node_modules|\.venv|venv|\.git|dist|build|__pycache__|tests?)(/|$)")
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route"}
FORWARDED = {"x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto", "host"}
SECRETISH = re.compile(r"(token|secret|password|passwd|signature|digest|hmac|mac|api_?key|otp|nonce)", re.I)

# construct -> (qualified-name prefixes of calls, attribute names of method calls)
CALLS = {
    "subprocess": (("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "asyncio.create_subprocess",
                    "standard_blocks.process.run"), ()),
    "dynamic-code": (("eval", "exec", "compile", "__import__", "importlib.import_module"), ()),
    "template-build": (("jinja2.Template", "string.Template", "django.template.Template"), ("from_string",)),
    "html-output": (("markupsafe.Markup", "jinja2.Markup", "django.utils.safestring.mark_safe",
                     "starlette.responses.HTMLResponse", "fastapi.responses.HTMLResponse",
                     "standard_blocks.render.clean_html"), ()),
    "url-build": (("urllib.parse.urljoin", "urllib.parse.urlencode", "urllib.parse.quote", "standard_blocks.render.url"),
                  ()),
    "regex": (("re.compile", "re.match", "re.search", "re.fullmatch", "re.sub", "re.findall", "re.finditer", "re.split",
               "standard_blocks.parse.search"), ()),
    "xml-parse": (("xml.", "lxml.", "defusedxml.", "standard_blocks.parse.xml"), ()),
    "deserialize": (("pickle.", "marshal.", "shelve.", "yaml.load", "yaml.unsafe_load", "yaml.full_load",
                     "jsonpickle.", "standard_blocks.parse.yaml"), ()),
    "archive": (("zipfile.", "tarfile.", "gzip.", "bz2.", "lzma.", "shutil.unpack_archive"), ()),
    "cipher": (("cryptography.hazmat.primitives.ciphers", "cryptography.fernet", "Crypto.Cipher", "Cryptodome.Cipher",
                "standard_blocks.crypto.seal", "standard_blocks.crypto.open_"), ()),
    "hash": (("hashlib.", "hmac.", "standard_blocks.crypto.digest", "standard_blocks.crypto.mac",
              "standard_blocks.crypto.derive"), ()),
    "random": (("random.", "secrets.", "uuid.uuid1", "uuid.uuid4", "os.urandom", "standard_blocks.crypto.token"), ()),
    "token-decode": (("jwt.", "jose.", "authlib.jose", "standard_blocks.session.verify"), ()),
    "http-client": (("requests.", "httpx.", "urllib.request.", "aiohttp.", "http.client.", "urllib3.",
                     "standard_blocks.outbound."), ()),
    "cookie-set": ((), ("set_cookie",)),
    "redirect": (("starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse", "flask.redirect",
                  "django.shortcuts.redirect", "standard_blocks.web.redirect_to"), ()),
    "mail-send": (("smtplib.", "email.message.", "django.core.mail."), ("send_message", "sendmail")),
    "ldap-query": (("ldap3.", "ldap."), ()),
    "xpath-query": (("lxml.etree.XPath",), ("xpath",)),
    "csv-write": (("csv.writer", "csv.DictWriter", "standard_blocks.parse.csv_row"), ()),
    "env-read": (("os.getenv", "os.environ.get", "standard_blocks.runtime.load", "standard_blocks.runtime.secret"), ()),
    "lock": (("threading.Lock", "threading.RLock", "asyncio.Lock", "django.db.transaction.atomic"),
             ("begin", "with_for_update", "select_for_update")),
    "thread": (("threading.Thread", "concurrent.futures.", "multiprocessing.", "asyncio.create_task", "queue.Queue",
                "asyncio.Queue", "standard_blocks.runtime.bounded_queue"), ()),
    "tls-context": (("ssl.",), ()),
    "sql-call": (("sqlalchemy.text", "standard_blocks.data."), ("execute", "executemany", "executescript", "raw")),
}
LOG_ATTRS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "event"}
JS_TERMS = {
    "postmessage": re.compile(r"\bpostMessage\s*\(|\bonmessage\s*="),
    "browser-storage": re.compile(r"\b(localStorage|sessionStorage|indexedDB)\b"),
    "html-output": re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML)\b|document\.write\s*\("),
    "dynamic-code": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    "http-client": re.compile(r"\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b"),
    "cookie-set": re.compile(r"document\.cookie\s*=|\.cookie\s*\("),
    "subprocess": re.compile(r"child_process|\bexecSync\s*\(|\bspawn\s*\("),
    "sql-call": re.compile(r"\.(query|raw)\s*\("),
    "random": re.compile(r"Math\.random\s*\(|crypto\.getRandomValues|randomUUID"),
    "token-decode": re.compile(r"\bjwt\.(decode|verify)\b|jwtDecode"),
    "redirect": re.compile(r"\bres\.redirect\s*\(|location\.(href|assign|replace)\s*="),
    "env-read": re.compile(r"process\.env\b"),
    "log-write": re.compile(r"\bconsole\.(log|info|warn|error)\s*\("),
}


NEXT_ROUTE = re.compile(r"(?:^|/)(?:src/)?app/((?:[^/]+/)*)route\.(?:js|mjs|ts)$")
NEXT_PAGES_API = re.compile(r"(?:^|/)(?:src/)?pages/(api/(?:[^/]+/)*[^/]+?)(?:/index)?\.(?:js|mjs|ts|tsx|jsx)$")
NEXT_METHOD = re.compile(r"export\s+(?:async\s+function\s+|function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
NEXT_ACTION = re.compile(r"export\s+(?:async\s+function\s+|const\s+)([A-Za-z_$][\w$]*)")
JS_ACCESS = re.compile(r"""\.(route|action)\s*\(\s*(['"])([\w.:-]+)\2""")
JS_EXPORT_ACCESS = re.compile(r"""export\s+const\s+([A-Za-z_$][\w$]*)\s*=\s*[\w$.]+\.(?:route|action)\s*\(\s*(['"])([\w.:-]+)\2""")
EXPRESS = re.compile(r"""\b(app|router|server)\.(get|post|put|patch|delete)\s*\(\s*(['"`])(/[^'"`]*)\3""")


def _strip_js(text: str, *, keep_strings: bool = False) -> str:
    """Mask comments and strings in one scan, preserving offsets and lines (including URLs in strings).
    This is lexical inspection, not a JavaScript parser."""
    tokens = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|/\*.*?\*/|//[^\n]*''', re.S)

    def mask(match):
        token = match.group()
        if keep_strings and token[0] in "\"'`":
            return token
        blank = "".join("\n" if c == "\n" else " " for c in token)
        return token[0] + blank[1:-1] + token[-1] if token[0] in "\"'`" else blank
    return tokens.sub(mask, text)


class _Py(ast.NodeVisitor):
    def __init__(self):
        self.alias, self.constructs, self.surfaces, self.endpoints, self.imports = {}, set(), set(), [], set()
        self.access = {}                                   # endpoint -> the id its allow("…") declares
        self.models, self.tenant = False, False

    # -- names -----------------------------------------------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            self.alias[(a.asname or a.name).split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
            self.imports.add(a.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for a in node.names:
                self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
            self.imports.add(node.module)
        self.generic_visit(node)

    def qual(self, node) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            head = self.alias.get(node.id, node.id)
            return ".".join([head, *reversed(parts)])
        return None

    # -- constructs ------------------------------------------------------------------------------------------------
    def visit_Call(self, node):
        q = self.qual(node.func) or ""
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        for construct, (prefixes, attrs) in CALLS.items():
            if any(q == p or q.startswith(p if p.endswith(".") else p + ".") or q == p.rstrip(".") for p in prefixes) \
                    or (attr and attr in attrs):
                self.constructs.add(construct)
        if q == "open" or q.endswith("Path") or q in ("os.path.join", "starlette.responses.FileResponse",
                                                       "fastapi.responses.FileResponse"):
            if any(not isinstance(a, ast.Constant) for a in node.args):
                self.constructs.add("file-path")
        if q == "getattr" and len(node.args) > 1 and not isinstance(node.args[1], ast.Constant):
            self.constructs.add("dynamic-code")
        if attr == "format" and not isinstance(node.func.value, ast.Constant):
            self.constructs.add("format-string")
        if attr in LOG_ATTRS and isinstance(node.func.value, (ast.Name, ast.Attribute)) and \
                "log" in (self.qual(node.func.value) or "").lower() or q == "print":
            self.constructs.add("log-write")
            self.surfaces.add("log-call")
        if attr == "get" and (self.qual(node.func.value) or "").endswith("headers") and node.args and \
                isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in FORWARDED:
            self.constructs.add("header-read")
        for kw in node.keywords:
            if kw.arg in ("debug", "reload") and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.constructs.add("debug-flag")
            if kw.arg in ("verify", "check_hostname", "cert_reqs"):
                self.constructs.add("tls-context")
        if attr in ("json", "form", "body") and (self.qual(node.func.value) or "").split(".")[-1] in ("request", "req"):
            self.constructs.add("request-body")
        if construct_is_outbound(q):
            self.surfaces.add("outbound-call")
        if q.endswith("set_cookie") or attr == "set_cookie":
            self.surfaces.add("cookie")
        if q.startswith("os.environ") or q in ("os.getenv",):
            self.surfaces.add("config")
        self.generic_visit(node)

    def visit_Subscript(self, node):
        q = self.qual(node.value) or ""
        if q == "os.environ":
            self.constructs.add("env-read")
            self.surfaces.add("config")
        if q.endswith("headers") and isinstance(node.slice, ast.Constant) and \
                str(node.slice.value).lower() in FORWARDED:
            self.constructs.add("header-read")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr == "host" and (self.qual(node.value) or "").endswith("client"):
            self.constructs.add("header-read")
        self.generic_visit(node)

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            for side in (node.left, *node.comparators):
                name = side.id if isinstance(side, ast.Name) else side.attr if isinstance(side, ast.Attribute) else ""
                if SECRETISH.search(name):
                    self.constructs.add("secret-compare")
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) \
                and "%" in node.left.value and not isinstance(node.right, ast.Constant):
            self.constructs.add("format-string")
        if isinstance(node.op, ast.Add) and any(isinstance(s, ast.Constant) and isinstance(s.value, str) and
                                                re.match(r"https?://|/[\w/-]*\?", s.value) for s in (node.left, node.right)):
            self.constructs.add("url-build")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        literal = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if re.match(r"https?://", literal) or re.search(r"\?[\w-]+=$", literal):
            self.constructs.add("url-build")
        if re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b", literal, re.I):
            self.constructs.add("sql-call")
        self.generic_visit(node)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value:
                self.constructs.add("debug-flag")
        self.generic_visit(node)

    # -- surfaces --------------------------------------------------------------------------------------------------
    def visit_ClassDef(self, node):
        bases = {self.qual(b) or "" for b in node.bases}
        names = {stmt.target.id for stmt in node.body if isinstance(stmt, ast.AnnAssign) and
                 isinstance(stmt.target, ast.Name)} | {t.id for stmt in node.body if isinstance(stmt, ast.Assign)
                                                       for t in stmt.targets if isinstance(t, ast.Name)}
        orm = any(b.endswith(("Base", "DeclarativeBase", "models.Model", "SQLModel", "Document")) for b in bases)
        if orm and ("__tablename__" in names or any(b.endswith(("models.Model", "Document")) for b in bases)
                    or any(k.arg == "table" for k in node.keywords)):
            self.surfaces.add("data-model")
            self.models = True
            if names & {"tenant_id", "org_id", "organization_id", "account_id"}:
                self.tenant = True
        if any(b.endswith("BaseSettings") for b in bases):
            self.surfaces.add("config")
        if any((self.qual(d.func if isinstance(d, ast.Call) else d) or "").startswith(("strawberry.", "graphene."))
               for d in node.decorator_list) or any(b.startswith(("graphene.", "strawberry.")) for b in bases):
            self.surfaces.add("graphql-schema")
        self.generic_visit(node)

    def _route(self, node):
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            verb = dec.func.attr
            path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else None
            if verb in ("task", "shared_task", "scheduled_job"):
                self.surfaces.add("background-job")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            if verb == "websocket":
                self.surfaces.add("websocket-endpoint")
                self.endpoints.append(f"WS {path}")
                continue
            if verb not in METHODS:
                continue
            methods = [verb.upper()] if verb not in ("route", "api_route") else sorted(
                str(e.value).upper() for kw in dec.keywords if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple))
                for e in kw.value.elts if isinstance(e, ast.Constant)) or ["GET"]
            self.endpoints += [f"{m} {path}" for m in methods]
            ident = next((c.args[0].value for kw in dec.keywords if kw.arg == "dependencies"
                          for c in ast.walk(kw.value) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                          and c.func.attr == "allow" and c.args and isinstance(c.args[0], ast.Constant)), None)
            for m in methods:
                self.access[f"{m} {path}"] = ident
            self.surfaces.add("endpoint")
            self.constructs.add("response-model")
            args = node.args.args + node.args.kwonlyargs
            notes = {self.qual(a.annotation) or "" for a in args if a.annotation is not None}
            defaults = [d for d in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]]
            calls = {self.qual(d.func) or "" for d in defaults if isinstance(d, ast.Call)}
            if any(n.endswith("UploadFile") for n in notes) or any(c.endswith("File") for c in calls):
                self.surfaces.add("upload-endpoint")
            if any(c.endswith(("Body", "Form", "Query")) for c in calls) or any(
                    n and n[0].isupper() and not n.endswith(("Request", "Response", "UploadFile", "BackgroundTasks",
                                                              "Session", "User"))
                    and n.split(".")[-1] not in ("int", "str", "float", "bool") for n in notes):
                self.constructs.add("request-body")
            if any(c.endswith("Form") for c in calls):
                self.surfaces.add("form")
            if any(n.endswith("BackgroundTasks") for n in notes):
                self.surfaces.add("background-job")

    def visit_FunctionDef(self, node):
        self._route(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_With(self, node):
        for item in node.items:
            q = self.qual(item.context_expr.func if isinstance(item.context_expr, ast.Call) else item.context_expr) or ""
            if q.endswith(("begin", "atomic", "Lock", "lock")):
                self.constructs.add("lock")
        self.generic_visit(node)

    visit_AsyncWith = visit_With


def construct_is_outbound(q: str) -> bool:
    return any(q.startswith(p) for p in CALLS["http-client"][0])


@lru_cache(maxsize=4096)
def _python(source: bytes) -> dict:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return {"surfaces": [], "constructs": [], "endpoints": [], "imports": [], "models": False, "tenant": False}
    v = _Py()
    v.visit(tree)
    return {"surfaces": sorted(v.surfaces), "constructs": sorted(v.constructs), "endpoints": sorted(set(v.endpoints)),
            "imports": sorted(v.imports), "models": v.models, "tenant": v.tenant,
            "access": dict(sorted(v.access.items()))}


def _javascript(source: bytes) -> dict:
    raw = source.decode("utf-8", "replace")
    code = _strip_js(raw)
    found = {c for c, rx in JS_TERMS.items() if rx.search(code)}
    if re.search(r"addEventListener\s*\(\s*(['\"])message\1", raw):        # the event name is a string
        found.add("postmessage")
    constructs = sorted(found)
    endpoints = sorted({f"{m.group(2).upper()} {m.group(4)}" for m in EXPRESS.finditer(raw)})
    server = bool(endpoints) or bool(re.search(r"""(require\(\s*|from\s+)['"](express|fastify|koa)['"]""", raw))
    surfaces = ({"endpoint"} if endpoints else set()) | ({"client-script"} if not server else set()) | \
        ({"log-call"} if "log-write" in constructs else set()) | \
        ({"outbound-call"} if "http-client" in constructs else set())
    imports = sorted({m.group(2) for m in re.finditer(r"""(require\(\s*|from\s+)['"]([\w@/.-]+)['"]""", raw)})
    return {"surfaces": sorted(surfaces), "constructs": constructs, "endpoints": endpoints, "imports": imports,
            "models": False, "tenant": False, "webrtc": "RTCPeerConnection" in code}


def _next_path(segments: str) -> str:
    """app/(shop)/orders/[id]/ -> /orders/:id (route groups and parallel slots are not in the URL)."""
    parts = [p for p in segments.strip("/").split("/") if p and not p.startswith(("(", "@"))]
    parts = [re.sub(r"^\[\[?\.{3}(\w+)\]?\]$", r":\1*", re.sub(r"^\[(\w+)\]$", r":\1", p)) for p in parts]
    return "/" + "/".join(parts)


def _nextjs(path: str, source: bytes, out: dict) -> dict:
    """Next.js entry points read from where the file lives: App Router route handlers (app/**/route.ts, one endpoint
    per exported method), Pages Router API routes (pages/api/**, any method), server actions ("use server" files, one
    `POST action:<name>` per exported function). Each endpoint maps to the id its access.route/action("…") names."""
    raw = source.decode("utf-8", "replace")
    endpoints, ids = [], [m.group(3) for m in JS_ACCESS.finditer(raw)]
    m = NEXT_ROUTE.search(path)
    if m:
        endpoints = [f"{verb} {_next_path(m.group(1))}" for verb in sorted(set(NEXT_METHOD.findall(raw)))]
    m = NEXT_PAGES_API.search(path)
    if m:
        endpoints = [f"ANY {_next_path(re.sub(r'/index$', '', m.group(1)))}"]
    if re.match(r"""\s*(?:/\*.*?\*/\s*|//[^\n]*\n\s*)*(['"])use server\1""", raw, re.S):
        endpoints = [f"POST action:{name}" for name in sorted(set(NEXT_ACTION.findall(raw)))]
    if not endpoints:
        return out
    named = {m.group(1): m.group(3) for m in JS_EXPORT_ACCESS.finditer(raw)}
    access = {}
    for e in endpoints:
        verb, _, where = e.partition(" ")
        key = where.removeprefix("action:") if where.startswith("action:") else verb
        if key in named:
            access[e] = named[key]
        elif len(set(ids)) == 1:
            access[e] = ids[0]
    surfaces = (set(out["surfaces"]) - {"client-script"}) | {"endpoint"}
    return {**out, "surfaces": sorted(surfaces), "endpoints": sorted(set(out["endpoints"]) | set(endpoints)),
            "access": access}


def stacks(files: dict) -> list:
    """The stacks a product is written in, as the catalog names them: fastapi (Python: the Python blocks serve any
    ASGI app) and nextjs (Next imported, or a Next entry point found)."""
    out = set()
    if any(p.endswith(PY) for p in files):
        out.add("fastapi")
    if any(i == "next" or i.startswith("next/") for d in files.values() for i in d["imports"]) or \
            any(NEXT_ROUTE.search(p) or NEXT_PAGES_API.search(p) or re.search(r"(^|/)next\.config\.\w+$", p)
                for p in files):
        out.add("nextjs")
    return sorted(out)


def _other(path: str, source: bytes) -> dict:
    surfaces = set()
    text = source.decode("utf-8", "replace")
    if path.endswith(TEMPLATES):
        surfaces.add("template")
        if re.search(r"<form\b", text, re.I):
            surfaces.add("form")
        if re.search(r"<script\b", text, re.I):
            surfaces.add("client-script")
    if re.search(r"(^|/)(alembic/versions|migrations)/[^/]+\.(py|sql)$", path):
        surfaces.add("migration")
    if re.fullmatch(r"(.*/)?(requirements[\w.-]*\.txt|pyproject\.toml|package\.json|poetry\.lock|package-lock\.json)", path):
        surfaces.add("dependency")
    if re.fullmatch(r"(.*/)?(\.env(\.\w+)?|settings\.(toml|ya?ml|json))", path):
        surfaces.add("config")
    return {"surfaces": sorted(surfaces), "constructs": [], "endpoints": [], "imports": [], "models": False,
            "tenant": False}


def describe(path: str, source: bytes) -> dict:
    """Surfaces, constructs and endpoints of one file."""
    if len(source) > MAX_FILE:
        return {"surfaces": [], "constructs": [], "endpoints": [], "imports": [], "models": False, "tenant": False}
    out = _python(source) if path.endswith(PY) else _javascript(source) if path.endswith(JS) else _other(path, source)
    if path.endswith(JS):
        out = _nextjs(path, source, out)
    if path.endswith(PY):
        extra = _other(path, source)["surfaces"]
        if extra:
            out = {**out, "surfaces": sorted(set(out["surfaces"]) | set(extra))}
    return out


def _paths(tree) -> list:
    return sorted(p for p in tree.paths() if not SKIP.search(p))


def scan(tree, declared=()) -> dict:
    files = {p: describe(p, tree.read(p)) for p in _paths(tree)}
    return {"features": features_of(files, declared), "files": files, "stacks": stacks(files)}


def features_of(files: dict, declared=()) -> list:
    """Features from the files' descriptions. `declared`: features only the rules of the game know."""
    constructs = {c for d in files.values() for c in d["constructs"]}
    surfaces = {s for d in files.values() for s in d["surfaces"]}
    imports = {i for d in files.values() for i in d["imports"]}
    endpoints = [e for d in files.values() for e in d["endpoints"]]
    paths = list(files)

    def imported(*mods):
        return any(i == m or i.startswith((m + ".", m + "/")) for i in imports for m in mods)
    found = set()
    if "endpoint" in surfaces or "websocket-endpoint" in surfaces or imported("fastapi", "flask", "django", "starlette",
                                                                             "express", "fastify", "koa", "next"):
        found.add("api")
    if "api" in found and ("template" in surfaces or "html-output" in constructs or "cookie" in surfaces
                           or "form" in surfaces or imported("jinja2", "fastapi.templating", "next", "react")):
        found.add("web")
    if imported("standard_blocks.session", "@standard/blocks/session", "next-auth", "authlib", "oidc", "keycloak", "fastapi_users", "django.contrib.auth",
                "flask_login") or any(re.search(r"\s/(.*/)?(login|signin|sign-in|logout|token)$", e) for e in endpoints):
        found.add("oidc")
    if "upload-endpoint" in surfaces:
        found.add("upload")
    if "cipher" in constructs or imported("cryptography", "Crypto", "Cryptodome", "nacl", "standard_blocks.crypto"):
        found.add("crypto")
    if "outbound-call" in surfaces or "http-client" in constructs:
        found.add("outbound-http")
    if "data-model" in surfaces or "migration" in surfaces or "sql-call" in constructs or imported(
            "sqlalchemy", "sqlite3", "psycopg", "psycopg2", "pymysql", "pymongo", "django.db", "sqlmodel", "asyncpg"):
        found.add("database")
    for construct, feature in (("xml-parse", "xml"), ("ldap-query", "ldap"), ("csv-write", "csv-export"),
                               ("token-decode", "jwt"), ("thread", "concurrency")):
        if construct in constructs:
            found.add(feature)
    if imported("bleach", "nh3", "markdown", "mistune", "markdown_it"):
        found.add("rich-content")
    if "graphql-schema" in surfaces or imported("strawberry", "graphene", "ariadne"):
        found.add("graphql")
    if "websocket-endpoint" in surfaces:
        found.add("websocket")
    if imported("aiortc") or any(d.get("webrtc") for d in files.values()):
        found.add("webrtc")
    if any(d["tenant"] for d in files.values()):
        found.add("multitenant")
    if imported("authlib", "oauthlib", "requests_oauthlib", "standard_blocks.session", "@standard/blocks/session",
                "next-auth"):
        found.add("oauth-client")
    if imported("fastapi.security") or "token-decode" in constructs and "api" in found:
        found.add("resource-server")
    if any(re.search(r"\s/admin(/|$)", e) for e in endpoints) or imported("sqladmin", "django.contrib.admin"):
        found.add("admin")
    if any(p.endswith(".tex") for p in paths):
        found.add("latex")
    if any(p.endswith(PY) for p in paths):
        found.add("lang:python")
    if any(p.endswith(JS) for p in paths):
        found.add("lang:js")
    if any(p.endswith((".java", ".kt")) for p in paths):
        found.add("lang:java")
    if any(p.endswith((".c", ".h", ".cc", ".cpp", ".hpp")) for p in paths):
        found.add("lang:c")
    # mtls, high-value, adaptive and team are declared in the rules of the game, not read from code
    return sorted(found | {d for d in declared if d in ("high-value", "adaptive", "team", "mtls")})


def touched(base, head) -> list:
    """The surfaces and constructs of the files a change adds, changes or removes (both sides read)."""
    paths = sorted(p for p in set(base.paths()) | set(head.paths()) if not SKIP.search(p) and
                   (p not in base.paths() or p not in head.paths() or base.read(p) != head.read(p)))
    out = set()
    for p in paths:
        for tree in (base, head):
            if p in tree.paths():
                d = describe(p, tree.read(p))
                out |= {f"surface:{s}" for s in d["surfaces"]} | {f"construct:{c}" for c in d["constructs"]}
    return sorted(out)


def detectors() -> dict:
    """Every vocabulary term this module can report, for the catalog's own test."""
    constructs = set(CALLS) | set(JS_TERMS) | {"file-path", "format-string", "log-write", "header-read",
                                               "secret-compare", "debug-flag", "request-body", "response-model",
                                               "url-build", "sql-call", "lock", "tls-context", "env-read"}
    surfaces = {"endpoint", "upload-endpoint", "form", "cookie", "template", "outbound-call", "data-model",
                "migration", "log-call", "config", "dependency", "background-job", "websocket-endpoint",
                "graphql-schema", "client-script"}
    features = {"web", "api", "oidc", "upload", "crypto", "outbound-http", "database", "xml", "ldap", "latex",
                "csv-export", "rich-content", "graphql", "websocket", "webrtc", "multitenant", "mtls", "jwt",
                "oauth-client", "resource-server", "high-value", "adaptive", "admin", "concurrency", "lang:python",
                "lang:js", "lang:java", "lang:c"}
    return {"constructs": constructs, "surfaces": surfaces, "features": features}
