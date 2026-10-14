"""The SSH gate (D23): clients fetch the canonical repository and push only to their own branches of the inbox."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bt.hosting import HOOK, route  # noqa: E402

CONFIG = {"repositories": {"app": {"canonical": "/c/app.git", "inbox": "/i/app.git",
                                   "readers": ["alice", "bob", "carol"], "writers": ["alice", "bob"]}}}


def git(*args, cwd=None, env=None, check=True):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check,
                          env={**os.environ, **(env or {})})


class Routing(unittest.TestCase):
    def test_fetch_reads_the_canonical_repository(self):
        self.assertEqual(route(CONFIG, "carol", "git-upload-pack '/app.git'"), ("git-upload-pack", "/c/app.git", {}))

    def test_push_lands_in_the_inbox_under_the_pushers_name(self):
        self.assertEqual(route(CONFIG, "alice", "git-receive-pack 'app'"),
                         ("git-receive-pack", "/i/app.git", {"STANDARD_IDENTITY": "alice"}))

    def test_refusals_say_nothing_about_what_exists(self):
        for identity, command in (("carol", "git-receive-pack 'app'"), ("mallory", "git-upload-pack 'app'"),
                                  ("alice", "git-upload-pack 'other'"), ("Alice", "git-upload-pack 'app'"),
                                  ("alice", "git-upload-pack '../app'"), ("alice", "git-upload-pack 'app'; id"),
                                  ("alice", "git-upload-archive 'app'"), ("alice", ""), ("", "git-upload-pack 'app'")):
            with self.assertRaises(PermissionError, msg=(identity, command)):
                route(CONFIG, identity, command)


class ThroughTheGate(unittest.TestCase):
    """A real git client over a stand-in for ssh: the remote command reaches the gate as SSH_ORIGINAL_COMMAND."""

    def setUp(self):
        root = Path(tempfile.mkdtemp())
        seed = root / "seed"
        git("init", "-q", "-b", "main", str(seed))
        (seed / "app.py").write_text("print('hi')\n")
        git("add", "-A", cwd=seed)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "seed", cwd=seed)
        self.canonical, self.inbox = root / "repos" / "app.git", root / "inbox" / "app.git"
        git("clone", "-q", "--bare", str(seed), str(self.canonical))
        git("init", "-q", "--bare", str(self.inbox))
        (self.inbox / "hooks" / "update").write_text(HOOK)
        os.chmod(self.inbox / "hooks" / "update", 0o755)
        config = root / "hosting.toml"
        config.write_text(f'[repositories.app]\ncanonical = "{self.canonical}"\ninbox = "{self.inbox}"\n'
                          'readers = ["alice", "bob"]\nwriters = ["alice", "bob"]\n')
        self.ssh = {}
        for who in ("alice", "bob"):
            script = root / f"ssh-{who}"
            script.write_text(f'#!/bin/sh\nshift\ncd {ROOT}\nSSH_ORIGINAL_COMMAND="$*" '
                              f'exec {sys.executable} -m bt.hosting {config} {who}\n')
            os.chmod(script, 0o755)
            self.ssh[who] = {"GIT_SSH_COMMAND": str(script)}
        self.work = root / "work"
        git("clone", "-q", "ssh://standard/app.git", str(self.work), env=self.ssh["alice"])
        git("-c", "user.name=a", "-c", "user.email=a@a", "commit", "-q", "--allow-empty", "-m", "change",
            cwd=self.work)
        self.main = git("rev-parse", "main", cwd=self.canonical).stdout.strip()

    def push(self, who, ref):
        return git("push", "-q", "origin", f"HEAD:{ref}", cwd=self.work, env=self.ssh[who], check=False)

    def test_a_client_pushes_its_own_branch_to_the_inbox(self):
        self.assertEqual(self.push("alice", "refs/heads/alice/fix").returncode, 0)
        self.assertEqual(git("rev-parse", "refs/heads/alice/fix", cwd=self.inbox).stdout.strip(),
                         git("rev-parse", "HEAD", cwd=self.work).stdout.strip())

    def test_main_and_other_names_are_refused_and_the_canonical_never_moves(self):
        self.assertNotEqual(self.push("alice", "refs/heads/main").returncode, 0)
        self.assertNotEqual(self.push("bob", "refs/heads/alice/fix").returncode, 0)
        self.assertNotEqual(self.push("alice", "refs/tags/v1").returncode, 0)
        self.assertEqual(git("for-each-ref", cwd=self.inbox).stdout, "")
        self.assertEqual(git("rev-parse", "main", cwd=self.canonical).stdout.strip(), self.main)


if __name__ == "__main__":
    unittest.main()


class Integration(unittest.TestCase):
    """Code the agent did not write reaches main only with main's tests green, no new gap on any floor target and the
    human's yes on that exact commit."""

    def test_approved_green_clean_work_lands_and_red_or_leaky_work_never_does(self):
        import argparse
        import threading
        sys.path.insert(0, str(ROOT / "tests"))
        from tools import ceremony
        from test_install import Clock
        from test_maintenance import FILES, demo_repository

        import standard.autonomy.__main__ as agent_process
        import standard.runtime.daemon as daemon
        from standard.surface.human import decide, load_signer
        from bt.gateway import AdmissionGateway

        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, {**FILES, "sbom.json": "{}\n"})
        inbox = root / "inbox.git"
        git("init", "-q", "--bare", str(inbox))
        (inbox / "hooks" / "update").write_text(HOOK)
        os.chmod(inbox / "hooks" / "update", 0o755)
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        ceremony.init(argparse.Namespace(dir=str(root / "install"), repo=str(repo), github=None, token_file=None, unconfined_tests=True,
                                         pins=str(root / "elsewhere" / "pins.db"), inbox=str(inbox)))
        operator = daemon.Installation(root / "install" / "standard.toml")
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        try:
            loop, repairer, _, refresh = agent_process.build(root / "install" / "standard.toml")
            loop.clock = repairer.clock = clock
            main = git("rev-parse", "main", cwd=repo).stdout.strip()

            def contribute(author, text):
                work = root / f"work-{author}"
                git("clone", "-q", str(repo), str(work))
                (work / "app.py").write_text(text)
                git("-c", f"user.name={author}", "-c", f"user.email={author}@client", "commit", "-qam", author,
                    cwd=work)
                git("push", "-q", str(inbox), f"HEAD:refs/heads/{author}/change", cwd=work,
                    env={"STANDARD_IDENTITY": author})
                return git("rev-parse", "HEAD", cwd=work).stdout.strip()

            def rounds(n=2):
                for _ in range(n):
                    operator.tick()
                    refresh()
                    clock.t += 120_000                       # past the agent's backoff
                    loop.run()
                operator.tick()

            def approve(author, head):
                keys = root / "install" / "keys"
                view = operator.service.view()
                operator.service.admit(decide(view, load_signer("human", keys / "human.key"),
                                              operator.config["grants"]["human"],
                                              f"repo:contrib:{author}/{main}/{head}", at=clock()))

            red = contribute("bob", "def add(a, b):\n    return a - b\n")
            leaky = contribute("eve", 'TOKEN = "AKIA' + 'ABCDEFGHIJKLMNOP"\n\n\ndef add(a, b):\n    return a + b\n')
            green = contribute("alice", "def add(a, b):\n    return a + b\n\n\ndef mul(a, b):\n    return a * b\n")
            rounds()
            self.assertEqual(git("rev-parse", "main", cwd=repo).stdout.strip(), main)     # no yes: nothing moves
            approve("bob", red)
            approve("eve", leaky)
            # D33: the human cannot replace a measure by an opinion: `tests` is the scanner's instrument only.
            from bt.signing import envelope
            for kind, extra in (("observation", {}), ("measurement", {"method": "main-suite",
                                                                        "coverage": "repo:inventory:all",
                                                                        "measured_at": clock.t + 1,
                                                                        "artifact": "sha256:" + "0" * 64})):
                s = operator.journal.snapshot()
                forged = envelope(s["domain"], kind, {
                    "id": f"forged-{kind}", "at": clock(), "author": "human", "under": operator.config["grants"]["human"],
                    "resource": f"repo:contrib:bob/{main}/{red}", "property": "tests", "status": "green",
                    "level": "real", **extra}, [load_signer("human", root / "install" / "keys" / "human.key")])
                with self.assertRaises(Exception) as refused:
                    operator.service.admit(forged)
                self.assertTrue(str(getattr(refused.exception, "code", refused.exception)).startswith("PROV"))
            rounds()
            self.assertEqual(git("rev-parse", "main", cwd=repo).stdout.strip(), main)     # approved but red: never
            state = operator.journal.snapshot()                                          # approved, green, but a
            self.assertTrue(state["observations"][f"repo:contrib:eve/{main}/{leaky}|regressions|scanner"]["status"]
                            .startswith("found:"))                                       # new secret: never
            approve("alice", green)
            rounds()
            self.assertEqual(git("rev-parse", "main", cwd=repo).stdout.strip(), green)
            state = operator.journal.snapshot()
            landed = [i for i in state["intents"].values() if i["op"] == "integrate"]
            self.assertEqual([i["args"]["contributor"] for i in landed], ["alice"])
            self.assertEqual(state["observations"]["repo:main:lineage|unjudged|scanner"]["status"], "none")
        finally:
            gateway.shutdown()
            gateway.server_close()
