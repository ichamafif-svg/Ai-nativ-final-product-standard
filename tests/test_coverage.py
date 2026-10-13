"""The chosen coverage (ARCHITECTURE.md §15.3–§15.4): each route, end to end, and the limits that stay visible."""
import json
import unittest

from test_maintenance import FILES, Stand, sh

from kernel import digest
from standard.surface.human import attest, review
from instruments.data import DataError, TrustedData

SBOM_24_1 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"type": "library", "name": "packaging", "version": "24.1", "purl": "pkg:pypi/packaging@24.1"}]}, indent=2) + "\n"


def data(**sections):
    return lambda t: TrustedData({"format": "standard-data/1", "taken_at": t, **sections})


class Route(Stand):
    def status(self, resource, prop):
        state = self.journal.snapshot()
        return state["observations"][f"{resource}|{prop}|scanner"]["status"]

    def land(self, rounds=3):
        """Instruments, agent, guard, proof, instruments again: until nothing more happens."""
        for _ in range(rounds):
            self.witness()
            self.instruments.measure()
            self.cycle.run()
            self.witness()
            self.service.dispatch_due()
            self.witness()
            self.prover.prove_due()
        self.witness()
        self.instruments.measure()


class Vulnerabilities(Route):
    FILES = {**FILES, "sbom.json": SBOM_24_1}
    DATA = staticmethod(data(advisories={"packaging==24.1": [{"id": "GHSA-demo", "fix_versions": ["24.2"]}], "packaging==24.2": []}))

    def test_a_vulnerable_pin_is_raised_autonomously_from_pinned_advisories(self):
        self.instruments.measure()
        self.assertEqual(self.status("repo:deps:vulns", "high"), "found:1")
        self.land(rounds=2)
        self.assertEqual(sh(self.repo, "git", "show", "main:requirements.txt"), "packaging==24.2")
        self.assertEqual(self.status("repo:deps:vulns", "high"), "none")
        self.assertEqual(self.status("repo:supply:sbom", "state"), "found:2")      # the next gap: new pin missing, old one stale

    def test_a_stale_snapshot_is_uncovered_never_green(self):
        self.t += 2 * 86_400_000
        self.witness()
        self.instruments.measure()
        self.assertEqual(self.status("repo:deps:vulns", "high"), "uncovered:LookupError")


class Actions(Route):
    FILES = {**FILES, "sbom.json": SBOM_24_1,
             ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"}
    DATA = staticmethod(data(actions={"actions/checkout@v4": "a" * 40},
                advisories={"packaging==24.1": []}))

    def test_unpinned_actions_are_pinned_to_the_snapshot_commit(self):
        self.instruments.measure()
        self.assertEqual(self.status("repo:ci:actions", "pinned"), "found:1")
        self.land(rounds=2)
        self.assertIn("actions/checkout@" + "a" * 40 + " # v4", sh(self.repo, "git", "show", "main:.github/workflows/ci.yml"))
        self.assertEqual(self.status("repo:ci:actions", "pinned"), "all")


SECRET = "sk-ant-" + "x" * 30


class Secrets(Route):
    FILES = {**FILES, "sbom.json": SBOM_24_1, "app.py": f'API_KEY = "{SECRET}"\n\n\ndef add(a, b):\n    return a + b\n'}
    prompts = []

    @staticmethod
    def ASK(prompt, key):
        Secrets.prompts.append(prompt)
        return {"title": "read the key from the environment",
                "files": {"app.py": 'import os\n\nAPI_KEY = os.environ.get("API_KEY", "")\n\n\n'
                                    'def add(a, b):\n    return a + b\n'}}

    def test_a_secret_is_removed_through_a_signed_human_review(self):
        self.instruments.measure()
        self.assertTrue(self.status("repo:code:secrets", "leaks").startswith("found:"))
        report = self.cycle.run()
        crafted = report["crafted"]["secrets"]
        self.assertEqual(crafted["route"], "review")
        self.assertNotIn(SECRET, "".join(self.prompts))                           # R15: the value never left
        self.assertEqual(report["submitted"]["secrets"], "CAP.CONDITION")
        self.witness()
        self.instruments.measure()                                                 # tests only: not reproducible
        self.assertEqual(self.cycle.run()["submitted"]["secrets"], "CAP.CONDITION")
        view = self.service.view()
        self.service.admit(review(view, self.signer("h3"), self.reviewer_cap, "secrets",
                                  crafted["base"], crafted["head"], "approved", at=self.clock()))
        self.assertEqual(self.cycle.run()["submitted"]["secrets"], "admitted")
        self.land(rounds=2)
        self.assertNotIn(SECRET, sh(self.repo, "git", "show", "main:app.py"))
        self.assertEqual(self.status("repo:code:secrets", "leaks"), "none")

    def test_the_agent_cannot_review_its_own_proposal(self):
        self.instruments.measure()
        crafted = self.cycle.run()["crafted"]["secrets"]
        self.witness()
        self.instruments.measure()
        self.service.admit(review(self.service.view(), self.signer("agent"), self.agent_observe_cap, "secrets",
                                  crafted["base"], crafted["head"], "approved", at=self.clock()))
        self.assertEqual(self.cycle.run()["submitted"]["secrets"], "CAP.CONDITION")


class Organisation(Route):
    def test_an_attestation_proves_an_organisational_target(self):
        view = self.service.view()
        open_ = {o["obligation"] for o in view["health"]["open"] + view["health"]["escalated"]}
        self.assertIn("target:isms", open_)
        for target in ("soa", "isms"):
            self.service.admit(attest(self.service.view(), self.signer("h2"), self.officer_cap, target, at=self.clock()))
        proven = {p["target"] for p in self.service.view()["health"]["proven"]}
        self.assertTrue({"soa", "isms"} <= proven)


class Limits(Route):
    def test_a_snapshot_loads_only_under_its_pin(self):
        snapshot = TrustedData({"format": "standard-data/1", "taken_at": 1})
        path = self.root / "data.json"
        path.write_bytes(__import__("kernel").canon(snapshot.value))
        self.assertEqual(TrustedData.load(path, snapshot.digest).digest, snapshot.digest)
        with self.assertRaises(DataError):
            TrustedData.load(path, digest("another snapshot"))

    def test_a_commit_that_bypassed_the_guard_is_visible_in_the_lineage(self):
        (self.repo / "app.py").write_text("def add(a, b):\n    return a - b\n")
        sh(self.repo, "git", "commit", "-qam", "direct push")
        self.instruments.measure()
        self.assertEqual(self.status("repo:main:lineage", "unjudged"), "found:1")
        self.assertEqual(self.status("repo:settings:main", "protection"), "found:3")

    def test_without_data_the_data_targets_are_uncovered(self):
        self.instruments.measure()
        for resource, prop in (("repo:deps:vulns", "high"), ("repo:deps:licenses", "policy"),
                               ("repo:deps:age", "major_behind")):
            self.assertTrue(self.status(resource, prop).startswith("uncovered"))


if __name__ == "__main__":
    unittest.main()
