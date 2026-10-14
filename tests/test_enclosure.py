"""The bac (D68): one definition, walls measured from inside by trying what they must refuse."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.sandbox import Sandbox  # noqa: E402
from enclosure import Bac, Walls  # noqa: E402
from enclosure.cgroups import Group  # noqa: E402
from instruments.walls import WALLS, measure  # noqa: E402

SMALL = Walls(timeout_s=30, memory_mb=512, processes=32, file_bytes=1_048_576)


class Groups(unittest.TestCase):
    def test_the_kernels_counters_say_which_limits_were_enforced(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "pids.events").write_text("max 0\n")
            (path / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
            self.assertEqual(Group([path], v2=True).hit(), ())
            (path / "pids.events").write_text("max 3\n")
            (path / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\n")
            self.assertEqual(Group([path], v2=True).hit(), ("memory", "processes"))


class Command(unittest.TestCase):
    def test_every_namespace_is_unshared_and_only_declared_paths_are_writable(self):
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as out:
            argv = Bac(SMALL).command(["run"], cwd, writable=[out])
        self.assertIn("--unshare-all", argv)
        self.assertNotIn("--share-net", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn(["--ro-bind", str(Path(cwd).resolve()), str(Path(cwd).resolve())],
                      [argv[i:i + 3] for i in range(len(argv))])
        self.assertIn(["--bind", str(Path(out).resolve()), str(Path(out).resolve())],
                      [argv[i:i + 3] for i in range(len(argv))])
        self.assertIn("--nproc=32", argv)
        self.assertEqual(argv[-1], "run")

    def test_the_agent_sandbox_is_this_bac(self):
        box = Sandbox(timeout=30, memory_mb=512, file_limit=1_048_576)
        self.assertIsInstance(box.bac, Bac)
        self.assertEqual(box.bac.walls, Walls(timeout_s=30, memory_mb=512, file_bytes=1_048_576))
        self.assertEqual(box.isolated, box.bac.ready)


@unittest.skipUnless(Bac(SMALL).ready, "bubblewrap jail unavailable")
class Measured(unittest.TestCase):
    def test_every_wall_holds(self):
        walls = measure(SMALL)
        self.assertEqual(set(walls), set(WALLS))
        absent = {"cgroups"} if Bac(SMALL).hierarchy is None else set()
        for wall in absent:
            self.assertEqual(walls[wall], "absent")
        for wall in set(WALLS) - absent:
            self.assertEqual(walls[wall], "held", wall)

    def test_a_bac_without_its_filter_is_measured_broken(self):
        class Unfiltered(Bac):
            def command(self, args, cwd, **kw):
                argv = super().command(args, cwd, **kw)
                if "--seccomp" in argv:
                    at = argv.index("--seccomp")
                    del argv[at:at + 2]
                return argv

        self.assertEqual(measure(SMALL, kind=Unfiltered)["syscalls"], "broken")

    @unittest.skipUnless(os.getuid() == 0, "the process limit already holds for other users")
    def test_as_root_nothing_runs_without_control_groups(self):
        bac = Bac(SMALL, groups=False)
        self.assertFalse(bac.ready)
        self.assertIn("control groups", bac.isolation)

    def test_a_bac_with_a_network_is_measured_broken(self):
        class Leaky(Bac):
            def command(self, args, cwd, **kw):
                argv = super().command(args, cwd, **kw)
                at = argv.index("--unshare-all") + 1
                return [*argv[:at], "--share-net", *argv[at:]]

        walls = measure(SMALL, kind=Leaky)
        self.assertEqual(walls["host_loopback"], "broken")

    def test_without_the_jail_nothing_runs_and_nothing_is_held(self):
        class Gone(Bac):
            def _unavailable(self):
                return "gone"

        self.assertEqual(Gone(SMALL).run(["/usr/bin/true"], tempfile.gettempdir()).code, 126)
        self.assertEqual(set(measure(SMALL, kind=Gone).values()), {"unmeasured"})


if __name__ == "__main__":
    unittest.main()
