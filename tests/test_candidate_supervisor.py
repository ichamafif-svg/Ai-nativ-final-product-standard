"""The executor accepts bounded scratch operations, not the agent's host authority."""
import os
import socket
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from fabric.runtime.bac import Ran, Walls
from fabric.runtime.supervisor import Executor, Refused, RemoteBac, StageBudget, Supervisor, copy_in, copy_out, pin


class FixtureBac:
    ready, why = True, None
    calls = []

    def __init__(self, walls):
        self.walls = walls

    def _execute(self, args, cwd, env, readable, writable, timeout, *, mount_sources):
        self.calls.append((self.walls, mount_sources, env))
        # The OCI runtime sees only the private snapshot of the input.
        assert Path(mount_sources[cwd], "input").read_text() == "candidate"
        return Ran(0, "bounded result", ("memory",))


class MutatingBac(FixtureBac):
    def _execute(self, args, cwd, env, readable, writable, timeout, *, mount_sources):
        output = Path(mount_sources[writable[0]])
        (output / "old").rename(output / "renamed")
        (output / "delete").unlink()
        (output / "nested" / "stale").unlink()
        return Ran(0, "changed", ())


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

    def test_pinned_directory_copy_survives_path_substitution(self):
        with ExitStack() as stack:
            descriptor = pin(self.root, str(self.work), stack)
            self.work.rename(self.root / "old")
            self.work.symlink_to("/etc", target_is_directory=True)
            stage = self.root / "stage"
            copy_in(descriptor, stage)
            self.assertEqual((stage / "input").read_text(), "candidate")
            self.assertFalse((stage / "passwd").exists())

    def test_writable_snapshot_reconciles_removal_and_rename(self):
        output = self.root / "output"
        output.mkdir()
        (output / "old").write_text("moved")
        (output / "delete").write_text("removed")
        (output / "nested").mkdir()
        (output / "nested" / "stale").write_text("removed")
        executor = Executor(self.root, bac_factory=MutatingBac)
        self.assertEqual(executor.execute(self.request(writable=[str(output)]))["code"], 0)
        self.assertEqual((output / "renamed").read_text(), "moved")
        self.assertFalse((output / "old").exists())
        self.assertFalse((output / "delete").exists())
        self.assertFalse((output / "nested" / "stale").exists())

    def test_sparse_oversized_file_refused_before_candidate_run(self):
        sparse = self.root / "sparse"
        with sparse.open("wb") as stream:
            stream.truncate(1024)
        with ExitStack() as stack:
            fd = pin(self.root, str(sparse), stack)
            with self.assertRaisesRegex(Refused, "STAGING_LIMIT"):
                copy_in(fd, self.root / "stage", StageBudget(bytes_limit=512))
        self.assertFalse((self.root / "stage").exists())

    def test_copyback_budget_refuses_before_removing_original(self):
        original, staged = self.root / "original", self.root / "staged"
        original.mkdir()
        staged.mkdir()
        (original / "old").write_text("keep")
        (staged / "new").write_text("replacement")
        with ExitStack() as stack:
            fd = pin(self.root, str(original), stack)
            with self.assertRaisesRegex(Refused, "STAGING_LIMIT"):
                copy_out(staged, fd, StageBudget(bytes_limit=11))
        self.assertEqual((original / "old").read_text(), "keep")
        self.assertFalse((original / "new").exists())

    def test_writable_file_copyback(self):
        original, staged = self.root / "original", self.root / "staged"
        original.write_text("older-content")
        staged.write_text("new")
        with ExitStack() as stack:
            fd = pin(self.root, str(original), stack)
            copy_out(staged, fd)
        self.assertEqual(original.read_text(), "new")

    def test_expired_file_copyback_keeps_original(self):
        original, staged = self.root / "original", self.root / "staged"
        original.write_text("keep")
        staged.write_text("new")
        with ExitStack() as stack:
            fd = pin(self.root, str(original), stack)
            budget = StageBudget()
            budget.deadline = time.monotonic() - 1
            with self.assertRaisesRegex(Refused, "STAGING_LIMIT"):
                copy_out(staged, fd, budget)
        self.assertEqual(original.read_text(), "keep")

    def test_swapped_fifo_does_not_block_copy(self):
        from fabric.runtime.supervisor import _copy_entry
        source, target = self.root / "source", self.root / "target"
        source.mkdir()
        target.mkdir()
        os.mkfifo(source / "swap")
        regular = self.work / "input"
        # The metadata was read before the attacker replaced the file with a FIFO.
        with patch("fabric.runtime.supervisor.os.stat", return_value=regular.stat()):
            with ExitStack() as stack:
                source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
                target_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
                stack.callback(os.close, source_fd)
                stack.callback(os.close, target_fd)
                with self.assertRaisesRegex(Refused, "FILE_TYPE"):
                    _copy_entry(source_fd, target_fd, "swap", StageBudget())

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

    def test_same_uid_outside_the_agent_cgroup_is_refused(self):
        self.socket_available()
        server = Supervisor(self.root / "executor.sock", self.executor, agent_uid=os.getuid(),
                            agent_cgroup="/standard-bac/unknown/enclosure")
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            client = RemoteBac(server.path, Walls())
            self.assertFalse(client.ready)
            self.assertIn("CANDIDATE.IDENTITY", client.run(["true"], self.work).out)
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

    def test_actual_bac_bundle_mounts_private_snapshots(self):
        from fabric.runtime.bac import Bac
        bac = object.__new__(Bac)
        bac.walls, bac.groups, bac.ids, bac.as_user = Walls(), True, None, None
        with ExitStack() as stack, tempfile.TemporaryDirectory() as bundle:
            path = str(self.work)
            source = self.root / "stage"
            source.mkdir()
            bac._bundle(bundle, ["true"], path, {}, (), (), "fixture", {path: str(source)})
            import json
            config = json.loads(Path(bundle, "config.json").read_text())
            mount = next(m for m in config["mounts"] if m["destination"] == path)
            self.assertEqual(mount["source"], str(source))
            self.assertEqual(config["process"]["cwd"], path)


if __name__ == "__main__":
    unittest.main()
