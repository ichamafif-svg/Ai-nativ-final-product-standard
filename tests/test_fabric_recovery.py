"""Recovery must reconstruct exact trusted bytes, refuse malicious archives and leave live state alone."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from fabric.recovery.artifacts import prepare


class Recovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'release.tar.gz'
        self.live = self.root / 'live'
        self.live.write_bytes(b'known current deployment')

    def archive_of(self, name='app/service.py', data=b'print("restored")', *, kind=None):
        with tarfile.open(self.archive, 'w:gz') as archive:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            if kind:
                item.type, item.linkname, item.size = kind, '/etc/passwd', 0
            archive.addfile(item, io.BytesIO(data))
        return 'sha256:' + hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_reconstructs_a_release_without_changing_live_or_overwriting_previous_recovery(self):
        digest = self.archive_of()
        recovered = prepare(self.archive, digest, self.root / 'recovered')
        self.assertEqual((recovered / 'app/service.py').read_bytes(), b'print("restored")')
        self.assertEqual(self.live.read_bytes(), b'known current deployment')
        with self.assertRaises(FileExistsError):
            prepare(self.archive, digest, recovered)

    def test_tampering_publishes_nothing(self):
        digest = self.archive_of()
        self.archive.write_bytes(self.archive.read_bytes() + b'tampered')
        with self.assertRaises(ValueError):
            prepare(self.archive, digest, self.root / 'recovered')
        self.assertFalse((self.root / 'recovered').exists())

    def test_traversal_and_links_cannot_escape_the_recovery_directory(self):
        for name, kind in [('../outside', None), ('/absolute', None), ('app/link', tarfile.SYMTYPE),
                           ('app/link', tarfile.LNKTYPE)]:
            with self.subTest(name=name, kind=kind):
                digest = self.archive_of(name, kind=kind)
                with self.assertRaises(ValueError):
                    prepare(self.archive, digest, self.root / 'recovered')
                self.assertFalse((self.root / 'recovered').exists())
        self.assertFalse((self.root / 'outside').exists())

    def test_expansion_budget_is_checked_before_publishing(self):
        digest = self.archive_of(data=b'x' * 100)
        with self.assertRaises(ValueError):
            prepare(self.archive, digest, self.root / 'recovered', max_bytes=99)
        self.assertFalse((self.root / 'recovered').exists())
