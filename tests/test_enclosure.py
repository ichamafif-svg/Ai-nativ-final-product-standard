"""The bac (D68): one OCI definition, walls measured from inside by trying what they must refuse."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.agents.sandbox import Sandbox  # noqa: E402
from fabric.runtime.bac import Bac, Walls
from fabric.runtime import bac as bac_module# noqa: E402
from fabric.runtime import oci# noqa: E402
from engine.verification.walls import WALLS, measure  # noqa: E402

SMALL = Walls(timeout_s=30, memory_mb=512, processes=32, file_bytes=1_048_576)
BAC = Bac(SMALL)


class Configuration(unittest.TestCase):
    def setUp(self):
        self.cwd, self.out = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.config = oci.config(SMALL, ["run"], self.cwd, env={"PATH": "/usr/bin"}, writable=[self.out],
                                 cgroup="/standard-bac/x")

    def test_every_namespace_is_unshared_and_no_capability_is_granted(self):
        namespaces = {n["type"] for n in self.config["linux"]["namespaces"]}
        self.assertEqual(namespaces, {"pid", "network", "ipc", "uts", "mount", "cgroup", "user"})
        self.assertTrue(all(v == [] for v in self.config["process"]["capabilities"].values()))
        self.assertTrue(self.config["process"]["noNewPrivileges"])
        self.assertTrue(self.config["root"]["readonly"])

    def test_only_declared_paths_are_mounted_and_only_writable_ones_are_writable(self):
        by_path = {m["destination"]: m for m in self.config["mounts"] if m["type"] == "bind"}
        self.assertIn("ro", by_path[str(Path(self.cwd).resolve())]["options"])
        self.assertIn("rw", by_path[str(Path(self.out).resolve())]["options"])
        self.assertIn("ro", by_path["/usr"]["options"])
        self.assertTrue(all("ro" in m["options"] for p, m in by_path.items() if p != str(Path(self.out).resolve())))

    def test_the_filter_is_an_allow_list_without_capability_rules(self):
        profile = self.config["linux"]["seccomp"]
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        allowed = {n for r in profile["syscalls"] if r["action"] == "SCMP_ACT_ALLOW" and not r.get("args")
                   for n in r["names"]}
        for call in ("mount", "unshare", "setns", "keyctl", "bpf", "init_module"):
            self.assertNotIn(call, allowed)
        self.assertIn("read", allowed)

    def test_memory_has_two_walls_the_group_and_the_address_space(self):
        rlimits = {r["type"]: r["hard"] for r in self.config["process"]["rlimits"]}
        self.assertEqual(self.config["linux"]["resources"]["memory"]["limit"], 512 << 20)
        self.assertEqual(rlimits["RLIMIT_AS"], oci.address_space_mb(SMALL, "/g") << 20)
        alone = oci.config(SMALL, ["run"], self.cwd, env={}, cgroup=None)
        self.assertEqual({r["type"]: r["hard"] for r in alone["process"]["rlimits"]}["RLIMIT_AS"], 512 << 20)

    def test_limits_come_from_the_walls(self):
        rlimits = {r["type"]: r["hard"] for r in self.config["process"]["rlimits"]}
        self.assertEqual(rlimits["RLIMIT_NPROC"], 32)
        self.assertEqual(rlimits["RLIMIT_FSIZE"], 1_048_576)
        self.assertEqual(self.config["linux"]["resources"]["pids"]["limit"], 32)
        self.assertEqual(self.config["process"]["args"], ["run"])

    def test_runtime_accounts_receive_distinct_cgroup_subtrees(self):
        with patch.object(Bac, "_unavailable", return_value=None):
            own = Bac(SMALL)
            runner = Bac(SMALL)
            runner.ids = (12345, 12345)
            own_path = own.config(["true"], self.cwd)["linux"]["cgroupsPath"]
            other_path = runner.config(["true"], self.cwd)["linux"]["cgroupsPath"]
        self.assertNotEqual(own_path, other_path)
        self.assertIn("/12345/", other_path)

    def test_the_kernels_counters_say_which_limits_were_enforced(self):
        with tempfile.TemporaryDirectory() as root:
            place = Path(root, bac_module.GROUP, str(os.getuid()), "x")
            place.mkdir(parents=True)
            (place / "pids.events").write_text("max 0\n")
            (place / "memory.events").write_text("max 0\noom_kill 0\n")
            with patch.object(bac_module, "CGROUP_ROOT", Path(root)):
                self.assertIsNone(bac_module._limited("unreadable-or-absent"))
                self.assertEqual(bac_module._limited("x"), ())
                (place / "memory.events").unlink()
                self.assertIsNone(bac_module._limited("x"), "partial counters are not a clean observation")
                (place / "pids.events").write_text("max 3\n")
                (place / "memory.events").write_text("low 0\nmax 0\noom_kill 1\n")
                self.assertEqual(bac_module._limited("x"), ("memory", "processes"))

    def test_the_capability_map_is_read_from_the_bac_never_written_beside_it(self):
        from fabric.runtime.bac import capability_map
        walls = Walls(timeout_s=7, memory_mb=256, processes=9, file_bytes=4096, cpu_percent=50)
        limits = capability_map(walls)["limits"]
        self.assertEqual(limits, {"time_s": 7, "memory_mb": 256, "processes": 9, "file_bytes": 4096,
                                  "cpu_percent": 50})
        self.assertEqual(capability_map(walls)["network"]["outbound"], "none: no host is reachable")

    def test_the_mission_says_in_one_place_what_the_bac_gives_and_who_holds_each_rule(self):
        import json
        from interface.context.missions import assemble
        packet = json.loads(assemble({"product": {"features": ["web"], "stacks": ["fastapi"]}}, None,
                                     role="build", touched=["surface:endpoint"])[0])["packet"]
        self.assertNotIn("capabilities", packet)
        autonomy = packet["autonomy"]
        self.assertEqual(autonomy["bac"]["limits"]["memory_mb"], Walls().memory_mb)
        held = {rid for ids in autonomy["rules_by_holder"].values() for rid in ids}
        self.assertEqual(held, set(packet["rule_ids"]))

    def test_the_agent_sandbox_is_this_bac(self):
        box = Sandbox(timeout=30, memory_mb=512, file_limit=1_048_576)
        self.assertIsInstance(box.bac, Bac)
        self.assertEqual(box.bac.walls, Walls(timeout_s=30, memory_mb=512, file_bytes=1_048_576))
        self.assertEqual(box.isolated, box.bac.ready)


class ExhaustionEvidence(unittest.TestCase):
    def measure_exhaustion(self, event, output, code=137):
        from fabric.runtime.bac import Ran, TIMED_OUT
        from engine.verification.walls import MEMORY, PROCESSES

        class Fixture:
            ready, groups, runtime = True, True, "/usr/bin/fixture"

            def __init__(self, *args, **kwargs):
                pass

            def run(self, args, cwd):
                if MEMORY in args:
                    return Ran(code, output, event)
                if PROCESSES in args:
                    return Ran(0, '{"process_count": "held"}', ())
                if "/usr/bin/sleep" in args:
                    return Ran(TIMED_OUT, "", ())
                return Ran(0, "{}", ())

        return measure(SMALL, kind=Fixture)

    def test_timeout_reaps_the_launcher_when_the_native_kill_fails(self):
        import shlex
        from fabric.runtime.bac import TIMED_OUT
        with tempfile.TemporaryDirectory() as root:
            launcher, pid_file = Path(root, "runtime"), Path(root, "pid")
            launcher.write_text("#!/bin/sh\nif [ \"$1\" = run ]; then\n"
                                + "echo $$ > " + shlex.quote(str(pid_file)) + "\nexec sleep 60\nfi\nexit 1\n")
            launcher.chmod(0o700)
            with patch.object(Bac, "_unavailable", return_value=None):
                bac = Bac(SMALL)
            bac.runtime = str(launcher)
            with patch.object(bac, "_base", return_value=[str(launcher)]):
                ran = bac._execute(["true"], root, None, (), (), 0.1)
            self.assertEqual(ran.code, TIMED_OUT)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    def test_killed_reporter_needs_a_matching_native_event_and_attempt_marker(self):
        self.assertEqual(self.measure_exhaustion(("memory",), "attempt:memory")["memory"], "held")
        for event, output in ((None, "attempt:memory"), ((), "attempt:memory"),
                              (("processes",), "attempt:memory"), (("memory",), "")):
            self.assertEqual(self.measure_exhaustion(event, output)["memory"], "unmeasured")
        self.assertEqual(self.measure_exhaustion(("memory",), "attempt:memory", code=0)["memory"], "unmeasured")

    def test_counters_do_not_override_an_explicit_failed_probe(self):
        walls = self.measure_exhaustion(("memory",), 'attempt:memory\n{"memory": "broken"}')
        self.assertEqual(walls["memory"], "broken")

    def test_no_group_event_does_not_mean_the_group_is_broken(self):
        self.assertEqual(self.measure_exhaustion((), '{"memory": "held"}', code=0)["cgroups"], "unmeasured")


@unittest.skipUnless(BAC.ready, f"bac unavailable: {BAC.why}")
class Measured(unittest.TestCase):
    def test_every_wall_holds(self):
        walls = measure(SMALL)
        self.assertEqual(set(walls), set(WALLS))
        if not BAC.groups:
            self.assertEqual(walls["cgroups"], "absent")
        for wall in set(WALLS) - {"cgroups"}:
            self.assertEqual(walls[wall], "held", wall)
        self.assertIn(walls["cgroups"], ("held", "absent", "unmeasured"))

    def test_as_root_the_bac_never_runs_without_control_groups(self):
        if os.getuid() == 0:
            self.assertTrue(BAC.groups)

    def test_a_bac_with_a_network_is_measured_broken(self):
        class Leaky(Bac):
            def config(self, *a, **kw):
                config = super().config(*a, **kw)
                config["linux"]["namespaces"] = [n for n in config["linux"]["namespaces"] if n["type"] != "network"]
                return config

            def _base(self):
                # gVisor has an independent network mode in addition to the OCI
                # namespace. Remove both protections for this deliberately leaky fixture.
                return ["--network=host" if arg == "--network=none" else arg for arg in super()._base()]

        self.assertEqual(measure(SMALL, kind=Leaky)["host_loopback"], "broken")

    def test_a_bac_without_its_filter_is_measured_broken(self):
        class Unfiltered(Bac):
            def config(self, *a, **kw):
                config = super().config(*a, **kw)
                del config["linux"]["seccomp"]
                return config

        self.assertEqual(measure(SMALL, kind=Unfiltered)["syscalls"], "broken")

    def test_without_the_runtime_nothing_runs_and_nothing_is_held(self):
        class Gone(Bac):
            def _unavailable(self):
                return "gone"

        self.assertEqual(Gone(SMALL).run(["/usr/bin/true"], tempfile.gettempdir()).code, 126)
        self.assertEqual(set(measure(SMALL, kind=Gone).values()), {"unmeasured"})


if __name__ == "__main__":
    unittest.main()
