"""The executor accepts bounded scratch operations, not the agent's host authority."""
import os
import socket
import tempfile
import threading
import unittest
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from fabric.runtime.bac import Ran, Walls
from fabric.runtime.supervisor import Executor, Refused, RemoteBac, Supervisor, pin


class FixtureBac:
    ready, why = True, None
    calls = []

    def __init__(self, walls):
        self.walls = walls

    def _execute(self, args, cwd, env, readable, writable, timeout, *, mount_sources):
        self.calls.append((self.walls, mount_sources, env))
        # Read the actual pinned input while its descriptors are alive.
        assert Path(mount_sources[cwd], "input").read_text() == "candidate"
        return Ran(0, "bounded result", ("memory",))


class Contract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        (self.work / "input").write_text("candidate")
        self.executor = Executor(self.root, bac_factory=FixtureBac)

    def request(self, **changes):
        return {"action": "run", "args": ["/usr/bin/true"], "cwd": str(self.work), "env": {},
                "readable": [], "writable": [], "walls": asdict(Walls()), **changes}

    def socket_available(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
                pass
        except PermissionError:
            self.skipTest("native Unix sockets unavailable on this host")

    def test_real_socket_roundtrip_and_dead_supervisor_fail_closed(self):
        self.socket_available()
        server = Supervisor(self.root / "executor.sock", self.executor, agent_uid=os.getuid())
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            client = RemoteBac(server.path, Walls())
            self.assertTrue(client.ready)
            result = client.run(["/usr/bin/true"], self.work)
            self.assertEqual((result.code, result.out, result.limited), (0, "bounded result", ("memory",)))
        finally:
            server.shutdown()
            worker.join()
            server.server_close()
        self.assertFalse(RemoteBac(server.path, Walls()).ready)
        self.assertEqual(client.run(["true"], self.work).code, 126)

    def test_larger_limits_host_paths_symlinks_socket_and_environment_are_refused(self):
        link = self.root / "link"
        link.symlink_to(self.work, target_is_directory=True)
        invalid = [self.request(cwd="/etc"), self.request(cwd=str(self.root)),
                   self.request(cwd=str(link)), self.request(readable=[str(self.root / "work" / ".." / "work")]),
                   self.request(walls=asdict(Walls(memory_mb=2049))),
                   self.request(env={"LD_PRELOAD": "/evil"}), self.request(profile="critical")]
        for request in invalid:
            with self.subTest(request=request), self.assertRaises((Refused, OSError)):
                self.executor.execute(request)

    def test_pinned_directory_cannot_be_replaced_by_symlink_before_mount(self):
        with ExitStack() as stack:
            _, descriptor = pin(self.root, str(self.work), stack)
            self.work.rename(self.root / "old")
            self.work.symlink_to("/etc", target_is_directory=True)
            self.assertEqual((Path(descriptor) / "input").read_text(), "candidate")
            self.assertFalse((Path(descriptor) / "passwd").exists())

    def test_peer_identity_is_checked_before_executing(self):
        self.socket_available()
        server = Supervisor(self.root / "executor.sock", self.executor, agent_uid=os.getuid() + 1)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            client = RemoteBac(server.path, Walls())
            self.assertFalse(client.ready)
            result = client.run(["true"], self.work)
            self.assertIn("CANDIDATE.IDENTITY", result.out)
        finally:
            server.shutdown()
            worker.join()
            server.server_close()

    def test_sandbox_uses_external_executor_without_instantiating_local_runtime(self):
        from engine.agents.sandbox import Sandbox
        with patch.dict(os.environ, {"STANDARD_CANDIDATE_SOCKET": str(self.root / "missing.sock")}), \
                patch("engine.agents.sandbox.Bac", side_effect=AssertionError("local fallback")):
            sandbox = Sandbox()
            self.assertFalse(sandbox.isolated)
            self.assertEqual(sandbox.run(["true"], self.work).code, 126)

    def test_actual_bac_bundle_uses_only_pinned_requested_mount_sources(self):
        from fabric.runtime.bac import Bac
        bac = object.__new__(Bac)
        bac.walls, bac.groups, bac.ids, bac.as_user = Walls(), True, None, None
        with ExitStack() as stack, tempfile.TemporaryDirectory() as bundle:
            path, source = pin(self.root, str(self.work), stack)
            bac._bundle(bundle, ["true"], path, {}, (), (), "fixture", {path: source})
            import json
            config = json.loads(Path(bundle, "config.json").read_text())
            mount = next(m for m in config["mounts"] if m["destination"] == path)
            self.assertEqual(mount["source"], source)
            self.assertEqual(config["process"]["cwd"], path)


if __name__ == "__main__":
    unittest.main()
