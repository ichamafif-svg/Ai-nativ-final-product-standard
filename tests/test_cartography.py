"""Behavior of the checked-in descriptive SQLite map and its gap queries."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from interface.context.cartography import (DEFAULT_DB, compare, connect, gaps, import_json,
                                           initialize, neighborhood, read, shortest_path, validate)


class StandardMap(unittest.TestCase):
    def test_real_map_exposes_architecture_gaps_and_provenance(self):
        with connect() as db:
            self.assertEqual(validate(db), [])
            items = gaps(db)
            self.assertGreaterEqual(len(items), 30)
            self.assertTrue(any('independent supervisor UID' in x['title'] for x in items if x['category'] == 'architecture'))
            self.assertTrue(any('Client data and key restoration' in x['title'] for x in items if x['category'] == 'architecture'))
            self.assertTrue(any(x['id'] == 'gap/agent-egress-lifecycle' and 'install_server.sh' in x['description']
                                for x in items))
            self.assertTrue(any(x['category'] == 'missing_link' and x['id'] == 'resource/evidence'
                                for x in items))
            graph = neighborhood(db, 'capability/candidate-run')
            self.assertIn('authority/supervisor', {x['id'] for x in graph['nodes']})
            self.assertEqual([x['target_id'] for x in shortest_path(
                db, 'agent/mission', 'component/candidate')],
                ['capability/candidate-run', 'authority/supervisor', 'component/candidate'])
            self.assertTrue(any(x['kind'] == 'component' for x in read('search', db, key='OpenBao')['items']))
            self.assertEqual(read('search', db, key='%')['items'], [])
            self.assertRaises(sqlite3.OperationalError, db.execute,
                              "UPDATE nodes SET title='altered' WHERE id='authority/kernel'")

    def test_missing_link_is_resolved_by_real_relation_and_foreign_keys_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            data = {
                'metadata': [{'key': 'basis_sha', 'value': 'a' * 40}],
                'nodes': [
                    {'id': 'probe/a', 'kind': 'instrument', 'title': 'Probe', 'source': 'ARCHITECTURE.md'},
                    {'id': 'target/a', 'kind': 'component', 'title': 'Target', 'source': 'ARCHITECTURE.md'}],
                'expectations': [{'node_id': 'probe/a', 'link_kind': 'observes', 'direction': 'out',
                                  'target_kind': 'component', 'reason': 'Target required',
                                  'source': 'ARCHITECTURE.md'}]}
            import_json(path, data)
            with connect(path) as db:
                self.assertEqual(read('gaps', db)['items'][0]['id'], 'probe/a')
                with connect(DEFAULT_DB) as standard:
                    difference = compare(db, standard)
                    self.assertIn('probe/a', {x['id'] for x in difference['nodes']['removed']})
                    self.assertIn('authority/kernel', {x['id'] for x in difference['nodes']['added']})
            with self.assertRaises(sqlite3.IntegrityError):
                import_json(path, {'links': [{'source_id': 'probe/a', 'target_id': 'missing',
                                              'kind': 'observes', 'source': 'ARCHITECTURE.md'}]})
            import_json(path, {'links': [{'source_id': 'probe/a', 'target_id': 'target/a',
                                         'kind': 'observes', 'source': 'ARCHITECTURE.md'}]})
            with connect(path) as db:
                self.assertEqual(read('gaps', db)['items'], [])
                self.assertEqual(validate(db), [])
            with self.assertRaises(ValueError):
                initialize(path)

            with connect(path) as db:
                page = read('search', db, key='a', limit=1)
                self.assertEqual(len(page['items']), 1)
                self.assertEqual(page['next_offset'], 1)
                self.assertEqual(len(read('search', db, key='a', limit=1, offset=1)['items']), 1)

    def test_atomic_editor_rejects_unknown_column_and_invalid_source(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            with self.assertRaises(ValueError):
                import_json(path, {'nodes': [{'id': 'node', 'kind': 'component',
                                             'title': 'N', 'source': 'ARCHITECTURE.md', 'grant': True}]})
            with self.assertRaises(sqlite3.IntegrityError):
                import_json(path, {'nodes': [
                    {'id': 'good', 'kind': 'component', 'title': 'Good', 'source': 'ARCHITECTURE.md'},
                    {'id': 'bad', 'kind': 'invalid', 'title': 'Bad', 'source': 'ARCHITECTURE.md'}]})
            with connect(path) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM nodes').fetchone()[0], 0)
            import_json(path, {'metadata': [{'key': 'basis_sha', 'value': 'a' * 40}],
                               'nodes': [{'id': 'escaped', 'kind': 'component', 'title': 'Escape',
                                          'source': '../outside'}]})
            with connect(path) as db:
                self.assertIn('source absent or outside checkout: ../outside', validate(db))
            cli = subprocess.run([sys.executable, '-m', 'interface.context.cartography',
                                  'validate', '--db', str(path)], capture_output=True, text=True)
            self.assertEqual(cli.returncode, 1)
            self.assertIn('outside checkout', cli.stdout)

    def test_source_symlink_and_special_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / 'outside.py'
            outside.write_text('outside')
            checkout = root / 'checkout'
            checkout.mkdir()
            (checkout / 'link.py').symlink_to(outside)
            path = root / 'map?#%.sqlite'
            initialize(path)
            import_json(path, {'metadata': [{'key': 'basis_sha', 'value': 'a' * 40}],
                               'nodes': [{'id': 'link', 'kind': 'component', 'title': 'Link',
                                          'source': 'link.py'}]})
            with connect(path) as db:
                self.assertIn('source absent or outside checkout: link.py', validate(db, checkout))


if __name__ == '__main__':
    unittest.main()
