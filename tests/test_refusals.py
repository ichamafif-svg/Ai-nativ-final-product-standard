"""Reading the bac's refusals (D69): lessons read against the map, never more than the map says."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from enclosure import Bac, Ran, Walls, capability_map  # noqa: E402
from enclosure.refusals import read  # noqa: E402

MAP = capability_map()


class Reading(unittest.TestCase):
    def test_a_network_attempt_is_a_lesson_held_by_the_egress(self):
        ran = Ran(1, "Traceback ...\nOSError: [Errno 101] Network is unreachable\n")
        [lesson] = read(ran, MAP, during="tests")
        self.assertEqual((lesson["kind"], lesson["capability"], lesson["held_by"]),
                         ("lesson", "network.outbound", "platform:egress"))
        self.assertEqual(lesson["available"], MAP["network"]["outbound"])
        self.assertEqual(lesson["ask"], MAP["ask"])

    def test_the_kernels_counters_and_the_deadline_are_read_without_any_output(self):
        capabilities = [r["capability"] for r in read(Ran(124, "", ("memory", "processes")), MAP, during="tests")]
        self.assertEqual(capabilities, ["limits.memory_mb", "limits.processes", "limits.time_s"])

    def test_an_unknown_error_stays_raw_and_a_clean_run_teaches_nothing(self):
        self.assertEqual(read(Ran(1, "ValueError: bad input\n"), MAP, during="tests"), [])
        self.assertEqual(read(Ran(0, "4 passed\n"), MAP, during="tests"), [])

    def test_the_stack_names_the_candidates_own_lines_never_libraries(self):
        out = ('Traceback (most recent call last):\n'
               '  File "/work/tree/app.py", line 7, in add\n'
               '  File "/usr/lib/python3.13/socket.py", line 864, in create_connection\n'
               '  File "/work/tree/.venv/lib/site-packages/x.py", line 3, in y\n'
               'OSError: [Errno 101] Network is unreachable\n')
        [lesson] = read(Ran(1, out), MAP, during="tests", root="/work/tree")
        self.assertEqual(lesson["stack"], ["app.py:7"])

    def test_a_record_never_says_more_than_the_map(self):
        out = "OSError: [Errno 30] Read-only file system: '/work/x'\nMemoryError\nFile too large"
        text = json.dumps(read(Ran(1, out), MAP, during="tests"))
        for word in ("seccomp", "namespace", "cgroup", "rlimit", "runc", "crun", "runsc", "gVisor", "RLIMIT"):
            self.assertNotIn(word, text)


BAC = Bac(Walls(timeout_s=30, memory_mb=512, processes=32, file_bytes=1_048_576))


@unittest.skipUnless(BAC.ready, f"bac unavailable: {BAC.why}")
class FromTheBac(unittest.TestCase):
    def test_real_collisions_become_lessons(self):
        code = ("import socket\ntry:\n    socket.create_connection(('203.0.113.7', 443), 1)\n"
                "except OSError as e:\n    print(e)\nopen('x', 'w')\n")
        with tempfile.TemporaryDirectory() as cwd:
            ran = BAC.run([sys.executable, "-I", "-c", code], cwd)
        lessons = {r["capability"] for r in read(ran, capability_map(BAC.walls, groups=BAC.groups), during="t")}
        self.assertEqual(lessons, {"network.outbound", "filesystem"})


if __name__ == "__main__":
    unittest.main()
