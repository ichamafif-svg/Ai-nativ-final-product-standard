"""Quality beyond green tests (D70): mutation of changed lines, complexity and duplication of new code."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.agents.quality import COMPLEXITY, WINDOW, complexity, duplication, mutants  # noqa: E402


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def repo_with(files):
    repo = Path(tempfile.mkdtemp())
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo, git(repo, "rev-parse", "HEAD")


def commit(repo, files):
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "head")
    return git(repo, "rev-parse", "HEAD")


class Quality(unittest.TestCase):
    def test_mutants_touch_only_changed_lines(self):
        source = "def add(a, b):\n    return a + b\n\n\ndef same(a, b):\n    return a == b\n"
        found = mutants(source, {6})
        self.assertTrue(found and all(line == 6 for line, _, _ in found))
        self.assertTrue(any("a != b" in mutated for _, _, mutated in found))

    def test_a_new_complex_function_is_reported_an_old_one_is_not(self):
        branches = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(COMPLEXITY + 2))
        repo, base = repo_with({"app.py": "def old(x):\n" + branches})
        head = commit(repo, {"app.py": "def old(x):\n" + branches + "\n\ndef new(x):\n" + branches})
        found = complexity(repo, base, head, ["app.py"])
        self.assertEqual([f["function"] for f in found], ["new"])

    def test_copied_code_is_reported_with_where_it_comes_from(self):
        body = "".join(f"    total = total + {i} * factor\n" for i in range(WINDOW + 2))
        repo, base = repo_with({"lib/sums.py": "def weighted(factor):\n    total = 0\n" + body + "    return total\n",
                                "app.py": "X = 1\n"})
        head = commit(repo, {"app.py": "X = 1\n\n\ndef mine(factor):\n    total = 0\n" + body + "    return total\n"})
        found = duplication(repo, base, head, ["app.py"])
        self.assertEqual(found[0]["copy_of"], "lib/sums.py")


if __name__ == "__main__":
    unittest.main()
