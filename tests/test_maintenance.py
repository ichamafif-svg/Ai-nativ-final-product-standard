"""End to end: a repository falls out of its floors and comes back autonomously, under the law (§9.1, §13).

A real git repository, real signatures, the durable journal, both judges, the guard and a compare-and-swap adapter.
The trust boundary is a test stand-in that declares every contract verified: this proves the logic, not the
physical properties of any T (§0.1).
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from fixture import HOUR, Ledger, client_law

from autonomy import Agent, Cycle, Route, WorkEngine, project
from trusted import EffectPort, Journal, PinStore, Signer, TrustedService
from trusted.adapters import GitRepository, Readback
from trusted.instruments import Instrument
from trusted.data import TrustedData
from trusted.operator import Instruments, Prover


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Verified:
    """Stand-in boundary: every contract declared verified. Never a production boundary."""

    def check(self, required, **_):
        return None


FILES = {
    "requirements.txt": "packaging==24.1\n",
    "app.py": "def add(a, b):\n    return a + b\n",
    "tests/test_app.py": "from app import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
}


def demo_repository(root: Path, files=FILES) -> Path:
    repo = root / "repo"
    repo.mkdir()
    sh(repo, "git", "init", "-q", "-b", "main")
    sh(repo, "git", "config", "user.email", "dev@example.org")
    sh(repo, "git", "config", "user.name", "dev")
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    sh(repo, "git", "add", "-A")
    sh(repo, "git", "commit", "-q", "-m", "initial")
    return repo


class Stand(unittest.TestCase):
    """A whole installation on one host. Subclasses may change FILES, DATA (a callable of time) and ASK."""
    FILES = FILES
    DATA = None
    ASK = None

    def setUp(self):
        root = self.root = Path(tempfile.mkdtemp())
        self.repo = demo_repository(root, self.FILES)
        self.store = root / "proposals"
        sh(root, "git", "clone", "-q", "--bare", str(self.repo), str(self.store))

        law = client_law(bindings={"owner": "h1", "inventory_source": "scanner", "scanner": "scanner",
                                   "compliance_officer": "h2"})
        L = self.L = Ledger(law=law)
        self.scanner_cap = L.grant("scanner", ["observe", "certify:real"], ["repo:*"])
        self.agent_cap = L.grant("agent", ["effect:remediate"], ["repo:*"], conditions=["remediate-autonomous"])
        self.review_cap = L.grant("agent", ["effect:remediate"], ["repo:*"], conditions=["remediate-reviewed"])
        self.oracle_cap = L.grant("oracle", ["reconcile", "evidence", "certify:real"], ["repo:*"])
        self.reviewer_cap = L.grant("h3", ["observe", "certify:real"], ["repo:*"])
        self.officer_cap = L.grant("h2", ["observe", "certify:real"], ["org:*"])
        self.agent_observe_cap = L.grant("agent", ["observe", "certify:real"], ["repo:*"])

        pins = PinStore(root / "pins" / "pins.db", create=True)
        self.journal = Journal(root / "journal.db", L.kernel, pins, L.state["domain"], create=True)
        for e in L.entries:
            self.journal.append(e)

        self.t = L.state["last_at"]
        clock = self.clock
        self.data = self.DATA(self.t) if self.DATA else TrustedData({"format": "standard-data/1", "taken_at": self.t})
        signer = lambda ident: Signer(ident, L.keys.private[ident][1])
        git_repo = GitRepository(self.repo, self.store)
        self.service = TrustedService(
            self.journal, boundary=Verified(), clock=clock, guard_signer=signer("guard"),
            effect_port=EffectPort({"remediate": git_repo.remediate}),
            reconciliation=Readback(git_repo, signer("oracle"), self.oracle_cap, clock))
        self.world = type("World", (), {"protections": lambda _: set()})()
        self.instruments = Instruments(self.service, Instrument(signer("scanner"), self.scanner_cap, clock),
                                       self.repo, self.store, data=self.data, world=self.world)
        self.signer = signer
        self.prover = Prover(self.service, git_repo, signer("oracle"), self.oracle_cap, clock)
        routes = [Route("agent-remediate", "RUN", "repo:*", frozenset({"repair"})),
                  Route("scanner", "RUN", "repo:*", frozenset({"observe", "cover", "prove"}))]
        self.cycle = Cycle(self.service, WorkEngine(root / "work.db"), Agent(signer("agent"), {"recipe": self.agent_cap, "review": self.review_cap},
                                 self.store, data=self.data, api_key="test" if self.ASK else None, ask=self.ASK),
                           routes, clock=clock, main=lambda: sh(self.repo, "git", "rev-parse", "main"),
                           state_path=root / "proposals.json", backoff_ms=0)

    def clock(self):
        """Trusted time that witnesses keep anchored: each reading moves one millisecond."""
        self.t += 1
        return self.t

    def witness(self):
        state = self.journal.snapshot()
        self.L.state = state
        at = self.clock()
        self.journal.append(self.L.entry("checkpoint", {"id": f"cp-{at}", "at": at, "author": "w1",
                                                        "size": state["size"], "head": state["head"]}, ["w1", "w2"]))

    def health(self):
        return self.service.health(required_at=self.t)

    def obligation(self, target):
        verdict = self.health()
        return next((o for o in verdict["open"] + verdict["escalated"] if o["obligation"] == f"target:{target}"), None)


class Maintenance(Stand):

    def test_an_sbom_gap_is_repaired_autonomously_and_proven(self):
        base = sh(self.repo, "git", "rev-parse", "main")
        self.instruments.measure()
        gap = self.obligation("sbom")
        self.assertEqual(gap["needs"], ["repair"])
        self.assertIsNone(self.obligation("secrets"))

        first = self.cycle.run()                     # the agent crafts; no independent fact yet: the law refuses
        self.assertEqual(first["crafted"]["sbom"]["route"], "recipe")
        self.assertEqual(first["submitted"]["sbom"], "CAP.CONDITION")

        self.witness()
        self.instruments.measure()                   # tests = green, reproduced = yes on the exact transition
        second = self.cycle.run()
        self.assertEqual(second["submitted"]["sbom"], "admitted")

        self.witness()
        results = self.service.dispatch_due()        # the guard departs once, compare-and-swap on main
        self.assertEqual(list(results.values()), ["ok"])
        head = sh(self.repo, "git", "rev-parse", "main")
        self.assertEqual(sh(self.repo, "git", "rev-parse", "main^"), base)
        self.assertIn("sbom.json", sh(self.repo, "git", "ls-tree", "--name-only", head))

        self.witness()
        self.prover.prove_due()                      # proof of application, by an independent oracle
        self.witness()
        self.instruments.measure()                   # the exigence itself, measured on the new main
        self.assertIsNone(self.obligation("sbom"))
        later = self.obligation("sbom")
        state = self.journal.snapshot()
        self.assertFalse([n for n in state["obligations"] if n.startswith("proof:")])
        self.assertIsNone(later)

    def test_the_debt_keeps_its_due_date_while_the_law_refuses(self):
        self.instruments.measure()
        before = self.obligation("sbom")
        self.cycle.run()
        self.witness()
        self.cycle.run()
        after = self.obligation("sbom")
        self.assertEqual((before["opened"], before["due"]), (after["opened"], after["due"]))

    def test_a_proposal_that_is_not_the_recipe_is_never_autonomous(self):
        self.instruments.measure()
        base = sh(self.repo, "git", "rev-parse", "main")
        from autonomy.agent import commit_files
        head = commit_files(self.store, base, {"sbom.json": b'{"components": []}\n'}, "hand-made")
        self.witness()
        self.instruments.measure()
        L = self.L
        L.state = self.journal.snapshot()
        agent = self.cycle.agent
        with self.assertRaises(Exception) as r:
            self.service.admit(agent.intent(L.state["domain"], self.clock(), "supply", "sbom", base, head))
        self.assertEqual(getattr(r.exception, "code", None), "CAP.CONDITION")

    def test_the_surface_reads_through_the_gateway_only(self):
        import contextlib
        import io
        import threading
        from surface.cli import main
        from trusted import AdmissionGateway
        self.instruments.measure()
        path = os.path.join(tempfile.mkdtemp(), "admission.sock")
        server = AdmissionGateway(path, self.service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["--socket", path, "tasks"]), 0)
                self.assertEqual(main(["--socket", path, "context", "target:sbom:repair"]), 0)
            text = out.getvalue()
            self.assertIn("target:sbom:repair", text)
            self.assertIn("remediate-autonomous", text)
            self.assertIn("the kernel decides", text)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
