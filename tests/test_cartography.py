"""Behavior of the checked-in descriptive SQLite map and its gap queries."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from interface.context.cartography import (DEFAULT_DB, compare, connect, gaps, import_json,
                                           initialize, neighborhood, read, shortest_path, validate, context, coverage)


class StandardMap(unittest.TestCase):
    def test_inventory_audit_is_complete_without_claiming_security_completeness(self):
        with connect() as db:
            result = read('audit', db)
            self.assertTrue(result['inventory_complete'], result)
            self.assertEqual(result['coverage']['unreferenced'], 0)
            self.assertEqual(result['isolated_nodes'], [])
            self.assertEqual(result['unreachable_from_domains'], [])
            self.assertEqual(result['oversized_packets'], [])
            self.assertEqual(result['semantic_completeness'], 'not_proven')
            self.assertGreater(result['gap_counts']['missing_link'], 0)

    def test_fingerprints_expose_source_drift_and_old_maps_remain_unknown(self):
        from interface.context.cartography import fingerprint_sources, source_drift
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'known.py'
            source.write_text('first version')
            path = root / 'map.sqlite'
            initialize(path)
            import_json(path, {'metadata': [{'key': 'basis_sha', 'value': 'a' * 40}],
                               'nodes': [{'id': 'known', 'kind': 'component', 'title': 'Known', 'source': 'known.py'}]})
            with connect(path, write=True) as db:
                self.assertEqual(source_drift(db, root)['not_recorded'], ['known.py'])
                fingerprint_sources(db, root)
            with connect(path) as db:
                self.assertEqual(source_drift(db, root)['changed'], [])
                self.assertEqual(source_drift(db, root)['not_recorded'], [])
            source.write_text('changed bytes')
            with connect(path) as db:
                self.assertEqual(source_drift(db, root)['changed'], ['known.py'])
            with connect(path, write=True) as db:
                db.execute('DROP TABLE source_fingerprints')
            with connect(path) as db:
                self.assertEqual(source_drift(db, root)['not_recorded'], ['known.py'])

    def test_topology_distinguishes_host_namespace_and_measurement_fixtures(self):
        with connect() as db:
            packet = read('topology', db, key='resource/lab-agent-env')
            edges = {(x['source_id'], x['kind'], x['target_id']) for x in packet['links']}
            self.assertIn(('resource/lab-supervisor-process', 'outside_of', 'resource/lab-agent-env'), edges)
            self.assertNotIn(('resource/lab-agent-env', 'contains', 'resource/lab-supervisor-process'), edges)
            self.assertIn(('resource/lab-agent-env', 'mounts_ro', 'resource/lab-execution-dir'), edges)
            supervisor = read('topology', db, key='resource/lab-supervisor-process')
            self.assertIn('resource/uid-agent', {x['target_id'] for x in supervisor['links'] if x['kind'] == 'uses_identity'})
            self.assertFalse(any(x['kind'] == 'implements' for x in supervisor['links']))
            native = read('topology', db, key='instrument/topology-agent-native')
            self.assertIn('resource/probe-native-env', {x['target_id'] for x in native['links'] if x['kind'] == 'uses_environment'})
            fake = read('topology', db, key='instrument/topology-supervisor-contract')
            self.assertIn('resource/probe-fake-executor', {x['target_id'] for x in fake['links'] if x['kind'] == 'uses_environment'})
            self.assertTrue(any('Ne prouve aucune isolation OCI' in x['limitation'] for x in fake['conditions']))
            config = read('topology', db, key='instrument/topology-oci-config')
            self.assertIn('resource/role-instrument', {x['target_id'] for x in config['links'] if x['kind'] == 'has_role'})
            for id in ('resource/assembly-lab', 'resource/assembly-stack', 'resource/assembly-measurement'):
                self.assertEqual(read('topology', db, key=id)['focus'], id)

    def test_validation_rejects_metadata_only_or_missing_core_structure(self):
        with tempfile.TemporaryDirectory() as temp:
            empty = Path(temp) / 'metadata.sqlite'
            with connect(empty, write=True) as db:
                db.execute('CREATE TABLE metadata (key TEXT, value TEXT)')
                db.execute('INSERT INTO metadata VALUES (?,?)', ('basis_sha', 'a' * 40))
            with connect(empty) as db:
                self.assertIn('required map structure missing or incomplete: nodes', validate(db))
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            with connect(path, write=True) as db:
                db.execute('DROP VIEW missing_links')
            with connect(path) as db:
                self.assertIn('required map structure missing or incomplete: missing_links', validate(db))

    def test_ordered_flows_and_common_dependencies_are_navigable(self):
        with connect() as db:
            for (id,) in db.execute('SELECT id FROM nodes'):
                self.assertEqual(context(db, id)['focus'], id)
            for flow in read('overview', db)['flows']:
                steps = read('flow', db, key=flow['id'])['steps']
                self.assertEqual([s['position'] for s in steps], list(range(1, len(steps) + 1)))
                self.assertTrue(all(a['target_id'] == b['source_id'] for a, b in zip(steps, steps[1:])))
            packet = read('shared', db, key='component/effect-guard')
            self.assertIn(('resource/process-operator', 'component/observation-boundary'),
                          {(x['dependency_id'], x['node_id']) for x in packet['items']})
            first = read('shared', db, key='component/effect-guard', limit=1)
            second = read('shared', db, key='component/effect-guard', limit=1, offset=first['next_offset'])
            self.assertEqual(first['items'] + second['items'], packet['items'][:2])
            pin = next(x for x in context(db, 'capability/observe')['conditions']
                       if x['target_id'] == 'constraint/program-pin')
            self.assertIn('construction', pin['timing'])
            self.assertIn('Pas de rehash par call', pin['limitation'])

    def test_flow_integrity_and_condition_gaps_do_not_invent_certainty(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            edge = {'source_id': 'cap', 'kind': 'limited_by', 'target_id': 'control'}
            import_json(path, {'metadata': [{'key': 'basis_sha', 'value': 'a' * 40}], 'nodes': [
                {'id': id, 'kind': kind, 'title': id, 'source': 'ARCHITECTURE.md'}
                for id, kind in [('cap', 'capability'), ('control', 'constraint')]],
                'links': [{**edge, 'source': 'ARCHITECTURE.md'}],
                'flows': [{'id': 'walk', 'title': 'Walk', 'description': 'Documented only.', 'source': 'ARCHITECTURE.md'}]})
            with connect(path) as db:
                self.assertEqual(context(db, 'cap')['conditions'], [])
                self.assertEqual(context(db, 'cap')['missing_conditions'][0]['target_id'], 'control')
                self.assertTrue(any(x['category'] == 'missing_condition' for x in gaps(db)))
                self.assertIn('flow positions missing or non-contiguous: walk', validate(db))
            detail = {**edge, 'timing': 'on start', 'checks': 'ceiling', 'on_failure': 'refused',
                      'scope': 'one process', 'limitation': 'not every effect', 'source': 'ARCHITECTURE.md'}
            # Invalid edge reference rolls back both condition and step writes.
            with self.assertRaises(sqlite3.IntegrityError):
                import_json(path, {'link_conditions': [detail], 'flow_steps': [
                    {'flow_id': 'walk', 'position': 1, **edge, 'target_id': 'absent'}]})
            with connect(path) as db:
                self.assertEqual(context(db, 'cap')['conditions'], [])
            import_json(path, {'link_conditions': [detail], 'flow_steps': [
                {'flow_id': 'walk', 'position': 1, **edge}]})
            with connect(path) as db:
                self.assertEqual(validate(db), [])
                self.assertEqual(context(db, 'cap')['missing_conditions'], [])
                self.assertFalse(any(x['category'] == 'missing_condition' for x in gaps(db)))
                self.assertEqual(read('flow', db, key='walk')['steps'][0]['conditions']['timing'], 'on start')
            with connect(path, write=True) as db:
                db.execute("INSERT INTO flow_steps VALUES ('walk',2,'cap','limited_by','control')")
            with connect(path) as db:
                self.assertIn('flow has disconnected steps: walk', validate(db))

    def test_architecture_loop_is_connected_through_real_boundaries(self):
        with connect() as db:
            self.assertEqual([row['target_id'] for row in shortest_path(
                db, 'component/work-queue', 'resource/proposals')],
                ['component/repairer', 'component/candidate-workflow', 'resource/proposals'])
            self.assertEqual([row['target_id'] for row in shortest_path(
                db, 'component/trusted-service', 'resource/main')],
                ['component/effect-guard', 'component/git-adapter', 'resource/main'])
            self.assertTrue(shortest_path(db, 'resource/proposals', 'resource/journal', 8))
            packet = context(db, 'capability/observe')
            self.assertIn('gap/suite-report-trust', packet['question_ids'])
            for node in read('overview', db)['entrypoints']:
                self.assertEqual(context(db, node['id'])['focus'], node['id'])
            for (id,) in db.execute("SELECT id FROM nodes WHERE kind='domain'"):
                self.assertEqual(context(db, id)['focus'], id)

    def test_measurement_inputs_and_release_paths_are_distinct(self):
        with connect() as db:
            reads = {row[0] for row in db.execute("SELECT target_id FROM links WHERE source_id=? AND kind='reads'",
                                                 ('component/production-measures',))}
            self.assertIn('resource/recorded-series', reads)
            self.assertNotIn('resource/public-captures', reads)
            self.assertTrue(db.execute("SELECT 1 FROM links WHERE source_id='component/release-runner' "
                                       "AND kind='produces' AND target_id='resource/release-tree'").fetchone())
            self.assertTrue(db.execute("SELECT 1 FROM links WHERE source_id='component/reconstruct' "
                                       "AND kind='reconstructs' AND target_id='resource/release-artifact'").fetchone())
            self.assertIn('requests', {row['link_kind'] for row in context(db, 'capability/data-read')['missing_links']})

    def test_work_packet_answers_candidate_authority_effects_and_unknown_deployment(self):
        with connect() as db:
            packet = context(db, 'capability/candidate-run')
            outgoing = {(row['kind'], row['target_id']) for row in packet['links']
                        if row['source_id'] == packet['focus']}
            self.assertIn(('governed_by', 'authority/host-admin'), outgoing)
            self.assertIn(('mediated_by', 'authority/supervisor'), outgoing)
            self.assertIn(('limited_by', 'constraint/candidate-peer'), outgoing)
            self.assertIn(('accesses', 'resource/scratch'), outgoing)
            self.assertIn(('produces', 'effect/candidate-copyback'), outgoing)
            self.assertEqual({x['dimension']: x['state'] for x in packet['assessments']},
                             {'implementation': 'present', 'deployment': 'unknown', 'verification': 'unknown'})
            self.assertIn('gap/copyback-atomic', packet['question_ids'])
            self.assertIn('gap/candidate-runtime-profile', packet['question_ids'])
            files = [x for x in context(db, 'component/agent-bac')['nodes'] if x['representation'] == 'source']
            self.assertIn('fabric/runtime/agent.py', {x['source'] for x in files})
            self.assertEqual(len(packet['nodes']), len({node['id'] for node in packet['nodes']}))
            self.assertEqual(packet['missing_links'], [])

    def test_unknown_assessment_and_wrong_relation_target_do_not_hide_questions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            import_json(path, {'nodes': [
                {'id': 'cap', 'kind': 'capability', 'title': 'Cap', 'source': 'ARCHITECTURE.md'},
                {'id': 'file', 'kind': 'resource', 'title': 'File', 'source': 'ARCHITECTURE.md'}],
                'links': [{'source_id': 'cap', 'kind': 'governed_by', 'target_id': 'file', 'source': 'ARCHITECTURE.md'}],
                'expectations': [{'node_id': 'cap', 'link_kind': 'governed_by', 'direction': 'out',
                                  'target_kind': 'authority', 'reason': 'Authority unknown', 'source': 'ARCHITECTURE.md'}]})
            with connect(path) as db:
                packet = context(db, 'cap')
                self.assertTrue(all(x['state'] == 'unknown' for x in packet['assessments']))
                self.assertEqual(len(packet['missing_links']), 1)

    def test_coverage_uses_tracked_code_not_document_count_or_untracked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
            git('init', '-q')
            for name in ('fabric/known.py', 'engine/unknown.py', 'engine/also.py', 'README.md'):
                file = repo / name
                file.parent.mkdir(exist_ok=True)
                file.write_text('fixture')
            git('add', '.')
            git('-c', 'user.name=tests', '-c', 'user.email=tests@standard.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
            (repo / 'untracked.py').write_text('not in inventory')
            path = root / 'map.sqlite'
            initialize(path)
            import_json(path, {'nodes': [{'id': 'known', 'kind': 'component', 'title': 'Known',
                                          'source': 'fabric/known.py#symbol'}]})
            import_json(path, {'source_fingerprints': [{'source': 'engine/unknown.py', 'sha256': '0' * 64}]})
            with connect(path) as db:
                result = coverage(db, repo, limit=1)
                self.assertEqual((result['tracked'], result['referenced'], result['unreferenced']), (3, 1, 2))
                self.assertEqual(result['next_offset'], 1)
                last = coverage(db, repo, limit=1, offset=result['next_offset'])
                self.assertEqual(last['items'], ['engine/unknown.py'])
                self.assertIsNone(last['next_offset'])

    def test_compare_reads_older_schema_without_assessments(self):
        with tempfile.TemporaryDirectory() as temp:
            before, after = [Path(temp) / name for name in ('old.sqlite', 'new.sqlite')]
            for path in (before, after):
                initialize(path)
                import_json(path, {'nodes': [{'id': 'same', 'kind': 'component', 'title': 'Same', 'source': 'ARCHITECTURE.md'}]})
            with connect(before, write=True) as db:
                db.execute('DROP TABLE assessments')
                db.execute('DROP TABLE flow_steps')
                db.execute('DROP TABLE flows')
                db.execute('DROP TABLE link_conditions')
                db.execute('DROP TABLE source_fingerprints')
            import_json(after, {'assessments': [{'node_id': 'same', 'dimension': 'deployment', 'state': 'unknown',
                                                'note': 'Not observed.', 'source': 'ARCHITECTURE.md'}]})
            with connect(before) as old, connect(after) as new:
                self.assertEqual(compare(old, new)['assessments']['added'][0]['dimension'], 'deployment')
                self.assertEqual(read('overview', old)['flows'], [])
                self.assertEqual(context(old, 'same')['conditions'], [])
                self.assertEqual(compare(old, new)['flows']['added'], [])

    def test_context_refuses_oversized_packet_instead_of_hiding_constraints(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'map.sqlite'
            initialize(path)
            nodes = [{'id': f'node/{i}', 'kind': 'component', 'title': str(i),
                      'description': 'x' * 1900, 'source': 'ARCHITECTURE.md'} for i in range(20)]
            links = [{'source_id': 'node/0', 'kind': 'depends_on', 'target_id': f'node/{i}',
                      'source': 'ARCHITECTURE.md'} for i in range(1, 20)]
            import_json(path, {'nodes': nodes, 'links': links})
            with connect(path) as db:
                with self.assertRaisesRegex(ValueError, 'context exceeds'):
                    context(db, 'node/0')

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
