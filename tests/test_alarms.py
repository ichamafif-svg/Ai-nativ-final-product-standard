"""D69: the outer wall is silent toward the code and loud toward the platform."""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from enclosure.alarms import Watcher  # noqa: E402
from enclosure.bac import Bac  # noqa: E402


def kernel_log_readable() -> bool:
    try:
        os.close(os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK))
        return True
    except OSError:
        return False


class Reading(unittest.TestCase):
    def test_only_calls_no_ordinary_code_makes_are_alarms(self):
        watcher = Watcher(tempfile.mktemp())
        line = ('6,1,2,-;audit: type=1326 audit(1.2:3): auid=1 uid=0 gid=0 ses=1 subj=k pid=999999 comm="python3" '
                'exe="/usr/bin/python3" sig=0 arch=c000003e syscall={} compat=0 ip=0x1 code=0x50000')
        self.assertEqual(watcher.read(line.format(272))["attempt"], "python3 called unshare")
        self.assertIsNone(watcher.read(line.format(435)))          # clone3: libraries try it on their own
        self.assertIsNone(watcher.read("6,2,3,-;usb 1-1: new device"))


@unittest.skipUnless(kernel_log_readable() and Bac().ready, "needs the kernel log and the bac")
class FromTheBac(unittest.TestCase):
    def test_an_escape_attempt_is_an_alarm_attributed_to_its_run_and_the_code_sees_only_a_refusal(self):
        path = tempfile.mktemp()
        watcher = Watcher(path).start()
        try:
            with tempfile.TemporaryDirectory() as cwd:
                ran = Bac().run([sys.executable, "-I", "-c",
                                 "import os, time\ntry:\n    os.unshare(os.CLONE_NEWNS)\nexcept OSError as e:\n"
                                 "    print('refused', e.errno)\ntime.sleep(0.3)"], cwd)
            time.sleep(0.5)
        finally:
            watcher.stop()
        self.assertIn("refused 1", ran.out)                          # EPERM, nothing else
        text = Path(path).read_text() if Path(path).exists() else ""
        self.assertIn("called unshare", text)
        if Bac().groups:
            self.assertRegex(text, r'"run": "[0-9a-f]{32}"')


if __name__ == "__main__":
    unittest.main()
