"""A map is a revision-bound description, never an authority or measured fact."""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fabric.data.postgres import Database, PG, _as_postgres
from interface.context.cartography import SCHEMA, run


class MapDatabase(Database):
    """Plain PostgreSQL fixture: the descriptive map does not require PL/Python."""

    def start(self):
        self.root.parent.chmod(self.root.parent.stat().st_mode | 0o111)
        for path in (self.root, self.socket):
            path.mkdir(parents=True, exist_ok=True)
            self._chown(path)
        self.socket.chmod(0o755)
        subprocess.run([*_as_postgres(), str(PG / "initdb"), "-D", str(self.data), "-A", "reject", "-U", "postgres"],
                       check=True, capture_output=True, timeout=120)
        hba = self.data / "pg_hba.conf"
        hba.write_text("local all postgres peer\nlocal product product trust\nlocal all all reject\n")
        self._chown(hba)
        self.process = subprocess.Popen([*_as_postgres(), str(PG / "postgres"), "-D", str(self.data),
                                         "-c", f"unix_socket_directories={self.socket}", "-c", "listen_addresses="],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if subprocess.run([str(PG / "pg_isready"), "-h", str(self.socket)],
                              capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError("PostgreSQL did not start")
        self.psql("CREATE ROLE product LOGIN")
        self.psql("CREATE DATABASE product OWNER product")
        return self


@unittest.skipUnless(os.getuid() == 0 and (PG / "postgres").exists(),
                     "root PostgreSQL 16 test fixture unavailable")
class Cartography(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = MapDatabase(Path(self.tmp.name))
        self.addCleanup(self.db.stop)
        self.db.start()
        self.db.psql(SCHEMA.read_text(), database="product")
        self.db.psql("""
            INSERT INTO cartography.types(id,version,kind,label) VALUES
              ('probe',1,'object','Probe'), ('component',1,'object','Component'),
              ('observes',1,'relation','Observes');
            INSERT INTO cartography.revisions(scope,revision) VALUES ('standard','commit-a'),('standard','commit-b');
            INSERT INTO cartography.objects(scope,revision,id,type_id,type_version,slug,name) VALUES
              ('standard','commit-a','00000000-0000-0000-0000-000000000001','probe',1,'network-probe','Network probe'),
              ('standard','commit-a','00000000-0000-0000-0000-000000000002','probe',1,'db-probe','Database probe'),
              ('standard','commit-a','00000000-0000-0000-0000-000000000003','component',1,'gateway','Gateway'),
              ('standard','commit-b','00000000-0000-0000-0000-000000000001','probe',1,'network-probe','Network probe');
            INSERT INTO cartography.relations(scope,revision,id,type_id,type_version,source_id,target_id)
              VALUES ('standard','commit-a','00000000-0000-0000-0000-000000000004','observes',1,
                      '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003');
            INSERT INTO cartography.expectations(scope,revision,id,object_type,object_version,
                    relation_type,relation_version,direction)
              VALUES ('standard','commit-a','00000000-0000-0000-0000-000000000005','probe',1,
                      'observes',1,'outgoing');
            INSERT INTO cartography.sources(scope,revision,object_id,source_kind,source_uri,source_revision)
              VALUES ('standard','commit-a','00000000-0000-0000-0000-000000000001',
                      'git_file','fabric/network/gateway.py','commit-a');
        """, database="product")

    def sql(self, text, *, check=True):
        return self.db.psql(text, database="product", check=check)

    def test_gaps_and_sources_are_bound_to_one_revision(self):
        self.assertEqual(self.sql("SELECT slug||':'||status FROM cartography.gaps ORDER BY slug"),
                         "db-probe:missing\nnetwork-probe:documented")
        self.sql("""INSERT INTO cartography.exceptions(scope,revision,object_id,expectation_id,status,reason)
            VALUES ('standard','commit-a','00000000-0000-0000-0000-000000000002',
                    '00000000-0000-0000-0000-000000000005','not_applicable','experimental only')""")
        self.assertEqual(self.sql("SELECT status||':'||reason FROM cartography.gaps WHERE slug='db-probe'"),
                         "not_applicable:experimental only")
        self.assertIn("foreign key", self.sql("""INSERT INTO cartography.relations
            (scope,revision,type_id,type_version,source_id,target_id)
            VALUES ('standard','commit-b','observes',1,
            '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003')""",
            check=False).lower())

    def test_kind_integrity_and_sealing(self):
        self.assertIn("foreign key", self.sql("""INSERT INTO cartography.objects
            (scope,revision,type_id,type_version,slug,name)
            VALUES ('standard','commit-a','observes',1,'wrong','Wrong')""", check=False).lower())
        self.assertIn("type definitions are immutable", self.sql(
            "UPDATE cartography.types SET label='changed' WHERE id='probe'", check=False))
        self.sql("UPDATE cartography.revisions SET state='sealed' WHERE revision='commit-a'")
        self.assertIn("sealed cartography revision", self.sql(
            "DELETE FROM cartography.objects WHERE slug='db-probe'", check=False))
        self.assertIn("sealed cartography revision", self.sql(
            "UPDATE cartography.revisions SET state='draft' WHERE revision='commit-a'", check=False))

    def test_shared_json_reader_quotes_scope_and_returns_sources(self):
        self.sql("GRANT USAGE ON SCHEMA cartography TO product; "
                 "GRANT SELECT ON ALL TABLES IN SCHEMA cartography TO product")
        with patch.dict(os.environ, {"PGHOST": str(self.db.socket), "PGUSER": "product"}):
            opts = {"dbname": "product", "scope": "standard", "revision": "commit-a", "psql": str(PG / "psql")}
            self.assertEqual([g["status"] for g in run("gaps", **opts)["items"]], ["missing", "documented"])
            self.assertIsNone(run("gaps", **opts)["next_offset"])
            self.assertEqual(run("sources", **opts)["items"][0]["source_revision"], "commit-a")
            self.assertEqual(run("objects", **{**opts, "scope": "standard' OR true --"})["items"], [])

    def test_page_has_a_continuation_and_large_property_is_refused(self):
        self.sql("""INSERT INTO cartography.objects(scope,revision,type_id,type_version,slug,name)
            SELECT 'standard','commit-a','probe',1,'probe-'||n,'Probe '||n
            FROM generate_series(1,101) n""")
        self.assertIn("check constraint", self.sql("""INSERT INTO cartography.objects
            (scope,revision,type_id,type_version,slug,name,properties)
            VALUES ('standard','commit-a','probe',1,'oversized','Oversized',
                    jsonb_build_object('payload', repeat('x',5000)))""", check=False).lower())
        self.sql("GRANT USAGE ON SCHEMA cartography TO product; "
                 "GRANT SELECT ON ALL TABLES IN SCHEMA cartography TO product")
        with patch.dict(os.environ, {"PGHOST": str(self.db.socket), "PGUSER": "product"}):
            opts = {"dbname": "product", "scope": "standard", "revision": "commit-a", "psql": str(PG / "psql")}
            first = run("objects", **opts)
            self.assertEqual(len(first["items"]), 100)
            self.assertEqual(first["next_offset"], 100)
            last = run("objects", **opts, offset=100)
            self.assertEqual(len(last["items"]), 4)
            self.assertIsNone(last["next_offset"])


if __name__ == "__main__":
    unittest.main()
