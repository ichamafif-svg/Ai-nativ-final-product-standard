"""Enclose an already-compromised agent; native checks require an explicit disposable Linux fixture."""
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fabric.runtime.agent import AgentEnclosureError, command, layout

CODE = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def fixture(root):
    base = root / "install"
    (base / "agent" / "store").mkdir(parents=True)
    (base / "agent" / "agent.key").write_text("agent-only")
    (base / "admission").mkdir()
    (base / "public" / "requests").mkdir(parents=True)
    (base / "admission" / "gateway.sock").touch()
    source = root / "source"
    source.mkdir()
    config = base / "standard.toml"
    config.write_text(f'''[repository]
kind = "git"
path = "{source}"
[socket]
path = "admission/gateway.sock"
[agent]
key = "agent/agent.key"
store = "agent/store"
public_context = "public"
''')
    return config


class Policy(unittest.TestCase):
    def test_host_root_homes_keys_and_control_state_are_not_mounted(self):
        with tempfile.TemporaryDirectory() as root:
            config = fixture(Path(root))
            with patch("fabric.runtime.agent.shutil.which", return_value="/usr/bin/bwrap"), \
                    patch("fabric.runtime.agent.os.getuid", return_value=123), \
                    patch("fabric.runtime.agent.delegation", return_value=Path("/sys/fs/cgroup/standard-bac/123")):
                args = command(config)
            mounts = [args[i + 1] for i, arg in enumerate(args) if arg in ("--ro-bind", "--bind")]
            self.assertNotIn("/", mounts)
            self.assertNotIn("/home", mounts)
            self.assertNotIn(str(config.parent), mounts)
            self.assertIn("--unshare-net", args)
            self.assertIn("--unshare-pid", args)
            self.assertIn("--clearenv", args)
            self.assertIn(str(config.parent / "agent"), mounts)
            self.assertIn(str(config.parent / "admission"), mounts)

    def test_old_broad_socket_directory_remote_git_and_provider_key_files_fail_closed(self):
        changes = [('public_context = "public"\n', ''), ('path = "admission/gateway.sock"', 'path = "gateway.sock"'),
                   ('kind = "git"', 'kind = "github"'),
                   ('store = "agent/store"', 'store = "agent/store"\napi_key_file = "provider.key"')]
        for before, after in changes:
            with self.subTest(after=after), tempfile.TemporaryDirectory() as root:
                config = fixture(Path(root))
                if 'path = "gateway.sock"' in after:
                    (config.parent / "gateway.sock").touch()
                config.write_text(config.read_text().replace(before, after))
                with self.assertRaises(AgentEnclosureError):
                    layout(config)

    def test_an_agent_cannot_mount_the_control_directory_as_its_source(self):
        with tempfile.TemporaryDirectory() as root:
            config = fixture(Path(root))
            config.write_text(config.read_text().replace(str(Path(root) / "source"), str(config.parent)))
            with self.assertRaises(AgentEnclosureError):
                layout(config)


NATIVE = os.environ.get("STANDARD_AGENT_NATIVE") == "1" and os.getuid() == 0


@unittest.skipUnless(NATIVE, "explicit native Linux fixture required: STANDARD_AGENT_NATIVE=1 as root")
class Native(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agent-enclosure-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        self.config = fixture(self.root)
        self.account = pwd.getpwnam("standard-agent")
        self.guard = pwd.getpwnam("standard-guard")
        state = self.config.parent / "agent"
        for path in [state, *state.rglob("*")]:
            os.chown(path, self.account.pw_uid, self.account.pw_gid)
        for path in (self.config.parent, state, self.config.parent / "admission"):
            path.chmod(0o755)

    def enclosed(self, script):
        bootstrap = ('import os,sys; from fabric.runtime.agent import command; '
                     'a=command(sys.argv[1],program=[sys.executable,"-c",sys.argv[2]]); os.execv(a[0],a)')
        return subprocess.run(["/usr/local/libexec/standard-cgroup-run", "standard-agent", "env",
                               f"PYTHONPATH={CODE}", PYTHON, "-c", bootstrap, str(self.config), script],
                              cwd=CODE, capture_output=True, text=True, timeout=90)

    def test_arbitrary_agent_code_cannot_escape_but_can_run_a_nested_candidate(self):
        # World-readable and writable outside the jail: refusals must come from
        # namespaces/mounts, not convenient DAC settings or an inner Python policy.
        hidden = self.root / "control.key"
        hidden.write_text("fixture-control-key")
        hidden.chmod(0o644)
        source = self.root / "source" / "protected"
        source.write_text("known")
        source.chmod(0o666)
        script = f'''
import json, os, pathlib, socket, tempfile
from fabric.runtime.bac import Bac, Walls
r = {{}}
r["hidden"] = not pathlib.Path({str(hidden)!r}).exists()
try:
    pathlib.Path({str(source)!r}).write_text("tampered")
    r["source_readonly"] = False
except OSError:
    r["source_readonly"] = True
r["environment"] = "STANDARD_AGENT_NATIVE" not in os.environ
try:
    socket.create_connection(("1.1.1.1",443), timeout=1).close()
    r["network"] = False
except OSError:
    r["network"] = True
r["processes"] = len([p for p in pathlib.Path("/proc").iterdir() if p.name.isdigit()]) < 16
state = pathlib.Path({str(self.config.parent / 'agent')!r})
(state / "working").write_text("agent-owned")
r["work"] = (state / "working").read_text() == "agent-owned"
b = Bac(Walls(timeout_s=10, memory_mb=512))
r["nested_ready"] = b.ready
r["nested_reason"] = b.why
with tempfile.TemporaryDirectory() as cwd:
    result = b.run(["/usr/bin/true"],cwd)
    r["nested_code"] = result.code
print(json.dumps(r))
'''
        ran = self.enclosed(script)
        self.assertEqual(ran.returncode, 0, ran.stderr[-3000:])
        facts = json.loads(ran.stdout.strip().splitlines()[-1])
        for name in ("hidden", "source_readonly", "environment", "network", "processes", "work", "nested_ready"):
            self.assertTrue(facts[name], (name, facts))
        self.assertEqual(facts["nested_code"], 0, facts)
        self.assertEqual(source.read_text(), "known")

    def test_compromised_agent_is_revoked_and_reconstructed_without_erasing_evidence(self):
        import copy
        import hashlib
        import io
        import tarfile
        import threading
        from fixture import Ledger
        from fabric.control.bt.gateway import AdmissionGateway
        from fabric.control.kernel import apply
        from fabric.recovery.artifacts import prepare

        ledger = Ledger()
        grant = ledger.grant("agent", ["effect:inventory-refresh"], ["repo:*"])
        evidence = self.root / "evidence.jsonl"
        evidence.write_text("")

        class Control:
            def view(self):
                return {"state": ledger.state}

            def status(self):
                return {"fixture": True}

            def qualify(self, required):
                raise ValueError("fixture is not qualified production")

            def admit(self, entry):
                record, delta = ledger.kernel.decide(ledger.state, entry)
                law = ledger.kernel.law_by_digest(record["law"])
                ledger.checker.check(ledger.state, record, copy.deepcopy(delta), entry, law.raw, law.digest)
                apply(ledger.state, delta)
                with evidence.open("a") as output:
                    output.write(json.dumps(record) + "\n")
                return {"accepted": True}

        socket_path = self.config.parent / "admission" / "gateway.sock"
        socket_path.unlink()
        gateway = AdmissionGateway(socket_path, Control(), mode=0o660)
        os.chown(socket_path, 0, self.guard.pw_gid)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(gateway.server_close)
        self.addCleanup(gateway.shutdown)
        state = self.config.parent / "agent"
        request = state / "message.json"

        def call(kind, **fields):
            entry = ledger.entry(kind, {"id": f"attack-{ledger.state['size']}", "at": ledger.state["last_at"] + 1,
                                        "author": "agent", **fields}, ["agent"])
            request.write_text(json.dumps(entry))
            script = f'''
import json
from fabric.control.bt.gateway import GatewayClient
c = GatewayClient({str(socket_path)!r})
try:
    r = c.admit(json.load(open({str(request)!r})))
except Exception as e:
    r = {{"refused": str(e)}}
print(json.dumps(r))
'''
            ran = self.enclosed(script)
            self.assertEqual(ran.returncode, 0, ran.stderr[-3000:])
            return json.loads(ran.stdout.strip().splitlines()[-1])

        self.assertEqual(call("intent", under=grant, op="inventory-refresh", args={"scope": "all"}), {"accepted": True})
        self.assertEqual(call("grant", holder="agent", actions=["effect:inventory-refresh"], resources=["repo:*"], conditions=[],
                              not_after=10**12), {"refused": "CAP.HUMAN"})
        ledger.submit("revoke", "h1", grant=grant)
        self.assertEqual(call("intent", under=grant, op="inventory-refresh", args={"scope": "all"}),
                         {"refused": "CAP.WITHDRAWN"})
        # Trusted known bytes stay outside the compromised workspace. Recovery is
        # reconstruction only, never an implicit grant or client-data/key restore.
        archive = self.root / "known.tar"
        with tarfile.open(archive, "w") as bundle:
            data = b'print("known component")\n'
            member = tarfile.TarInfo("component.py")
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
        digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
        before = evidence.read_bytes()
        ran = self.enclosed(f'import pathlib; p=pathlib.Path({str(evidence)!r}); '
                            f'print(p.exists()); pathlib.Path({str(state / "compromised.py")!r}).write_text("hostile")')
        self.assertEqual(ran.returncode, 0, ran.stderr[-3000:])
        self.assertEqual(ran.stdout.strip(), "False")
        restored = prepare(archive, digest, self.root / "recovered")
        self.assertEqual((restored / "component.py").read_bytes(), data)
        self.assertEqual(evidence.read_bytes(), before)
        self.assertIn(grant, ledger.state["revoked"])

    def test_real_agent_loop_starts_with_only_its_key_and_gateway(self):
        import argparse
        import threading
        from tools import ceremony
        from fabric.control.runtime.operator import Installation
        from fabric.control.bt.gateway import AdmissionGateway

        source = self.root / "source"
        subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost",
                        "commit", "--allow-empty", "-qm", "known source"], check=True)
        shutil.rmtree(self.config.parent)
        ceremony.init(argparse.Namespace(dir=str(self.config.parent), repo=str(source), github=None,
                                         token_file=None, pins=None, unconfined_tests=False))
        state = self.config.parent / "agent"
        for path in [state, *state.rglob("*")]:
            os.chown(path, self.account.pw_uid, self.account.pw_gid)
        public = self.config.parent / "public"
        for path in (public, public / "requests"):
            path.chmod(0o755)
        findings = {"repo:code:security|lint": {"status": "dirty", "details": ["published fixture"]}}
        (public / "findings.json").write_text(json.dumps(findings))
        import hashlib
        contract = b"def test_known_contract():\n    assert False\n"
        digest = "sha256:" + hashlib.sha256(contract).hexdigest()
        (public / "requests" / digest.split(":")[1]).write_bytes(contract)
        with self.config.open("a") as output:
            output.write('\n[build]\nstore = "public/requests"\n')
        operator = Installation(self.config)
        gateway = AdmissionGateway(operator.socket, operator.service, mode=0o660)
        os.chown(operator.socket, 0, self.guard.pw_gid)
        (self.config.parent / "admission").chmod(0o755)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(gateway.server_close)
        self.addCleanup(gateway.shutdown)
        ran = self.enclosed('from engine.agents.__main__ import main, build; '
                            'from engine.verification.suite import load; '
                            f'loop,repairer,_,_=build({str(self.config)!r}); '
                            f'assert repairer._findings() == {findings!r}; '
                            'builder=next(p for p in loop.producers if p.name=="build"); '
                            f'assert load(builder.requests,{digest!r})=={contract!r}; '
                            f'raise SystemExit(main(["once", {str(self.config)!r}]))')
        self.assertEqual(ran.returncode, 0, (ran.stdout[-2000:], ran.stderr[-3000:]))
        report = json.loads(ran.stdout.strip().splitlines()[-1])
        self.assertNotIn("blocked", report)
        self.assertIn("played", report)
