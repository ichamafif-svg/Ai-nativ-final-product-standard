"""The bac (D68): one OCI definition, walls measured from inside by trying what they must refuse."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.sandbox import Sandbox  # noqa: E402
from enclosure import Bac, Walls, bac as bac_module  # noqa: E402
from enclosure import oci  # noqa: E402
from instruments.walls import WALLS, measure  # noqa: E402

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

    def test_the_kernels_counters_say_which_limits_were_enforced(self):
        with tempfile.TemporaryDirectory() as root:
            place = Path(root, bac_module.GROUP, "x")
            place.mkdir(parents=True)
            (place / "pids.events").write_text("max 0\n")
            with patch.object(bac_module, "CGROUP_ROOT", Path(root)):
                self.assertEqual(bac_module._limited("x"), ())
                (place / "pids.events").write_text("max 3\n")
                (place / "memory.events").write_text("low 0\nmax 0\noom_kill 1\n")
                self.assertEqual(bac_module._limited("x"), ("memory", "processes"))

    def test_the_capability_map_is_read_from_the_bac_never_written_beside_it(self):
        from enclosure import capability_map
        walls = Walls(timeout_s=7, memory_mb=256, processes=9, file_bytes=4096, cpu_percent=50)
        limits = capability_map(walls)["limits"]
        self.assertEqual(limits, {"time_s": 7, "memory_mb": 256, "processes": 9, "file_bytes": 4096,
                                  "cpu_percent": 50})
        self.assertEqual(capability_map(walls)["network"]["outbound"], "none: no host is reachable")

    def test_the_mission_says_in_one_place_what_the_bac_gives_and_who_holds_each_rule(self):
        import json
        from context.missions import assemble
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
