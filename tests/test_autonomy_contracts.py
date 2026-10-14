"""Independent measures, shared legal context and agent research must not manufacture authority."""
import argparse
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from instruments import jobs, probes, suite
from instruments.tree import Measure, Snapshot, export, verdict
from bt.assessment import TrustUnavailable
from bt.service import TrustedService
from runtime.operator import Instruments
from instruments.scope import repair as in_scope
from agent.candidate import AgentError
from agent.repair import Agent
from agent.build import Builder
from context.missions import render_context, task_context
from agent.repair import Repairer
from context.missions import gap_dossiers
from agent.patrol import patrol_context
from agent.patrol import propose_patrol
from context.model import target_state
from agent.llm import Gate, Provider
from agent.patrol import run_patrol
from context.model import ReadModel
from agent.precheck import precheck, suite as agent_suite
from agent.work import installed_routes, project
from agent.research import NoRedirect, Research, ResearchError
from agent.sandbox import Result
from agent.work import WorkEngine
from catalog.floors import FLOORS
from surface.web import Installation
from test_agent import Signer, store_with
from test_install import Clock
from test_maintenance import demo_repository, FILES
from tools import ceremony, qualify


class Reports(unittest.TestCase):
    def test_empty_partial_and_skipped_reports_cannot_be_green(self):
        root = Path(tempfile.mkdtemp())
        cases = ('<testsuite />', '<testsuite><testcase name="a"><skipped /></testcase></testsuite>',
                 '<testsuite><testcase name="a"/><testcase name="b"><skipped /></testcase></testsuite>')
        for text in cases:
            report = root / 'report.xml'
            report.write_text(text)
            self.assertNotEqual(verdict('green', suite.report_measure(report, 0)), 'green')

    def test_exit_code_disagreement_collection_error_and_duplicate_cases(self):
        root = Path(tempfile.mkdtemp())
        report = root / 'report.xml'
        report.write_text('<testsuite><testcase name="a"/></testsuite>')
        with self.assertRaises(RuntimeError):
            suite.report_measure(report, 2)
        report.write_text('<testsuite><testcase name="a"><error/></testcase></testsuite>')
        self.assertEqual(verdict('green', suite.report_measure(report, 2)), 'found:1')
        with self.assertRaises(RuntimeError):
            suite.report_measure(report, 0)
        report.write_text('<testsuite><testcase name="a"/><testcase name="a"/></testsuite>')
        with self.assertRaises(ValueError):
            suite.report_measure(report, 0)

    def test_agent_precheck_uses_the_same_report_rules(self):
        root = Path(tempfile.mkdtemp())
        (root / 'tests').mkdir()
        class Sandbox:
            @contextmanager
            def checkout(self, *args):
                yield root
            def run(self, args, *unused, **kwargs):
                report = next(str(a).split('=', 1)[1] for a in args if str(a).startswith('--junitxml='))
                Path(report).write_text('<testsuite />')
                return Result(0, '')
        status, _ = agent_suite(Sandbox(), root, 'base', 'head')
        self.assertNotEqual(status, 'green')

    def test_skipped_acceptance_cannot_contract_or_deliver(self):
        measure = Measure(frozenset({'a', 'b'}), frozenset({'a'}), ('a',))
        with patch('instruments.suite._contract', return_value=measure):
            self.assertTrue(suite.contract_on(None, 'r', b'contract')[0].startswith('uncovered:'))
            class Head:
                def paths(self): return {suite.contract_path('r')}
                def read(self, path): return b'contract'
            self.assertTrue(suite.acceptance_on(Head(), 'r', b'contract')[0].startswith('uncovered:'))

    def test_ci_runs_the_exact_snapshot_and_reports_failures(self):
        for code, expected in (('def add(a, b): return a + b\n', 'green'),
                               ('def add(a, b): return a - b\n', 'found:1')):
            store, commit = store_with({**FILES, 'app.py': code})
            measure = probes.ci(Snapshot(store, commit), {})
            self.assertEqual(verdict('green', measure), expected)

    def test_ci_job_records_dependencies_and_network_policy(self):
        subjects = {'main': 'main', 'install': True, 'targets': [], 'entities': {},
                    'anchor': 'anchor', 'judged': [], 'now': 0, 'proposals': [], 'inbox': [], 'production': False}
        job = jobs.plan(subjects)[0]
        self.assertEqual(job['inputs']['install'], {'value': True})
        self.assertTrue(job['network'])

    def test_client_target_identifiers_follow_the_kernel_language_in_proposals(self):
        from agent.candidate import commit_files
        store, base = store_with(FILES)
        tid = 'Client.Rule/v2'
        head = commit_files(store, base, {'app.py': b'x = 1\n'}, f'Standard-Target: {tid}\n')
        root = Path(tempfile.mkdtemp())
        before, after = export(store, base, root / 'base'), export(store, head, root / 'head')
        target = {'id': tid, 'resource': 'repo:client:custom', 'repair': 'remediate'}
        with patch('instruments.jobs.suite.tests_report', return_value=('green', [])):
            facts = jobs.remediation({'base': {'tree': str(before.path)}, 'head': {'tree': str(after.path)},
                                      'targets': [target]})
        self.assertEqual(facts[0][:3], [f'repo:client:custom/{base}/{head}', 'tests', 'green'])


class CoherentView(unittest.TestCase):
    def test_instrument_plan_rejects_a_different_journal_prefix(self):
        instruments = Instruments.__new__(Instruments)
        instruments.service = SimpleNamespace(journal=SimpleNamespace(snapshot=lambda: {'size': 2, 'head': 'new'}))
        with self.assertRaisesRegex(RuntimeError, 'prefix changed'):
            instruments.subjects({'prefix': {'size': 1, 'head': 'old'}})

    def test_service_retries_a_moving_prefix_and_never_mixes_health_with_law(self):
        snapshots = iter([{'size': 1, 'head': 'old'}, {'size': 2, 'head': 'new'}])
        state = lambda prefix: {**prefix, 'domain': 'g', 'observations': {}, 'grants': {}, 'entities': {},
                                 'law': {'client': {}},
                                 'root': {'identities': {}}, 'frozen': [], 'intents': {}, 'line': {}, 'statements': {}}
        service = TrustedService.__new__(TrustedService)
        service._require = lambda contracts: 1
        service.journal = SimpleNamespace(snapshot=lambda: state(next(snapshots)),
                                          kernel=SimpleNamespace(law_of=lambda s: SimpleNamespace(digest='law', raw={})))
        service.health = lambda **kwargs: {'head': 'new', 'size': 2, 'state': 'IN_PROGRESS'}
        service.assessment = lambda: 'SELF_ASSESSED'
        view = service.view()
        self.assertEqual((view['prefix']['size'], view['health']['size']), (2, 2))

    def test_service_fails_closed_if_prefix_keeps_moving(self):
        service = TrustedService.__new__(TrustedService)
        service._require = lambda contracts: 1
        service.journal = SimpleNamespace(snapshot=lambda: {'size': 1, 'head': 'old'})
        service.health = lambda **kwargs: {'head': 'new', 'size': 2}
        with self.assertRaises(TrustUnavailable):
            service.view()


class ContextAndRoutes(unittest.TestCase):
    def view(self, target):
        law = {**FLOORS, 'targets': [target], 'conditions': {**FLOORS['conditions'],
                    'client-custom-name': {'all': [{'observed': ['review', 'approved', 'real']}]}}}
        return {'prefix': {'size': 1, 'head': 'h', 'genesis': 'g'}, 'law': {'digest': 'law', 'effective': law},
                'health': {'state': 'IN_PROGRESS', 'as_of': 0, 'escalated': [],
                           'open': [{'type': 'target', 'target': target['id'], 'obligation': 'ob',
                                     'opened': 1, 'due': 10, 'needs': ['repair']}]}}

    def target(self):
        return {**next(t for t in FLOORS['targets'] if t['id'] == 'ci'),
                'id': 'client-specific', 'resource': 'repo:client:custom'}

    def test_read_model_contains_all_law_and_keeps_candidate_links_uncertain(self):
        view = self.view(self.target())
        view['facts'] = [{'id': 'fact-1', 'resource': 'repo:client:custom',
                          'property': 'status', 'status': 'red', 'author': 'scanner', 'at': 2}]
        findings = {'repo:client:custom|status': {'status': 'red', 'details': ['client.py:7:rule']}}
        view['law']['effective'] = {**view['law']['effective'], 'settings': {'objective': '99.9'}}
        model = ReadModel(view, findings, installed_routes(), lambda contracts: None, main='commit-1')
        graph = model.graph()
        self.assertEqual(graph['schema'], 'standard-read-model/v1')
        for section in ('ops', 'conditions', 'resources', 'instruments', 'targets', 'obligations'):
            self.assertTrue(any(node.startswith(f'law:{section}') for node in graph['declarations']))
        self.assertIn('rules:settings', graph['declarations'])
        self.assertIn('floor0:F0-1', graph['declarations'])
        self.assertFalse(any(n.startswith('external:') for n in graph['declarations']))   # no compliance theatre
        code = next(e for e in graph['relations'] if e['relation'] == 'possible_code_location')
        self.assertEqual((code['to'], code['status'], code['origin']),
                         ('code:client.py:7', 'candidate', 'diagnostic_finding'))
        self.assertTrue(any(e['relation'] == 'has_debt' and e['status'] == 'constitutional'
                            for e in graph['relations']))
        self.assertTrue(all(e['from'] in graph['declarations'] and e['to'] in graph['declarations']
                            for e in graph['relations']))

    def test_read_model_rejects_mixed_journal_prefixes(self):
        view = self.view(self.target())
        view['health'].update(head='other', size=1)
        with self.assertRaisesRegex(ValueError, 'different journal prefixes'):
            ReadModel(view)

    def test_read_model_queries_share_one_basis_across_consumers(self):
        from surface.views import run

        view = self.view(self.target())
        view['entities'] = {'build:request/r1': {'type': 'request'}}
        view['transitions'] = {'repo:feature:r1/base/head': {'tests': 'green'}}
        view['facts'] = [{'id': 'f1', 'resource': 'repo:feature:r1/base/head', 'property': 'tests',
                          'status': 'green', 'author': 'scanner', 'at': 2}]
        findings = {'repo:client:custom|status': {'status': 'red', 'details': [],
                                                  'input_main': 'older-commit'}}
        model = ReadModel(view, findings, installed_routes(), lambda needs: None, main='current-commit')
        self.assertEqual(model.entities('request')[0][0], 'build:request/r1')
        self.assertEqual(model.transition('repo:feature:r1/base/head')['tests'], 'green')
        self.assertEqual(model.facts_for('repo:feature:r1/base/head', 'tests')[0]['id'], 'f1')
        self.assertEqual(run(model, {}, {})['gaps'][0]['diagnostic_alignment'], 'stale')
        changed = {**view, 'prefix': {**view['prefix'], 'head': 'other'}}
        with self.assertRaisesRegex(ValueError, 'different journal or law basis'):
            task_context(changed, {'id': 't', 'resource': 'repo:client:custom', 'need': 'repair'}, model=model)

    def test_read_model_captures_inputs_once(self):
        view = self.view(self.target())
        findings = {'repo:client:custom|status': {'status': 'red'}}
        view['law']['effective'] = {**view['law']['effective'], 'settings': {'objective': '99.9'}}
        model = ReadModel(view, findings, main='main-1')
        captured = model.basis['inputs']
        view['law']['effective']['targets'].clear()
        findings['repo:client:custom|status']['status'] = 'green'
        view['law']['effective']['settings']['objective'] = '50'
        self.assertEqual(model.target('client-specific')['finding']['status'], 'red')
        self.assertEqual(model.settings['objective'], '99.9')
        self.assertEqual(captured, model.basis['inputs'])

    def test_read_model_links_transitions_entities_and_constitutional_proof(self):
        view = self.view(self.target())
        view['transitions'] = {'repo:feature:r1/base/head': {'tests': 'green'}}
        view['facts'] = [{'id': 'f1', 'resource': 'repo:feature:r1/base/head', 'property': 'tests',
                          'status': 'green', 'author': 'scanner', 'at': 2}]
        view['entities'] = {'build:request/r1': {'type': 'request', 'state': 'open'}}
        view['health']['proven'] = [{'target': 'client-specific'}]
        graph = ReadModel(view).graph()
        self.assertIn('transition:repo:feature:r1/base/head|tests', graph['declarations'])
        self.assertIn('entity:build:request/r1', graph['declarations'])
        self.assertIn('proof:client-specific', graph['declarations'])
        self.assertTrue(any(edge['from'] == 'fact:f1' and edge['relation'] == 'contributes_to'
                            for edge in graph['relations']))
        self.assertTrue(any(edge['to'] == 'proof:client-specific' and edge['status'] == 'constitutional'
                            for edge in graph['relations']))

    def test_stale_diagnostic_remains_visible_but_cannot_classify_current_debt(self):
        view = self.view(self.target())
        finding = {'repo:client:custom|status': {'status': 'red', 'details': ['client.py:7:rule'],
                                                 'measure_ref': 'sha256:old', 'input_main': 'old-commit'}}
        model = ReadModel(view, finding, main='current-commit')
        row = model.targets()[0]
        self.assertEqual((row['state'], row['diagnostic_alignment']), ('open', 'stale'))
        self.assertEqual(next(e['status'] for e in model.graph()['relations']
                              if e['relation'] == 'diagnosed_by'), 'stale')
        finding['repo:client:custom|status'].update(input_main='current-commit', law_digest_at_read='law')
        self.assertEqual(ReadModel(view, finding, main='current-commit').targets()[0]['diagnostic_alignment'],
                         'same_declared_inputs')

    def test_unknown_target_gets_research_without_a_false_repair_route(self):
        view = self.view(self.target())
        plan = project(view, installed_routes(), lambda needs: None)
        tasks = {t['need']: t for t in plan['tasks']}
        self.assertEqual(tasks['repair']['state'], 'NO_ROUTE')
        self.assertEqual(tasks['investigate']['state'], 'AVAILABLE')
        self.assertEqual(tasks['investigate']['for_needs'], ['repair'])
        self.assertEqual(tasks['investigate']['due'], tasks['repair']['due'])

    def test_shared_context_includes_client_conditions_and_missing_routes(self):
        view = self.view(self.target())
        view['grants'] = {'cap': {'holder': 'agent', 'state': 'active', 'resources': ['repo:client:*']}}
        task = next(t for t in project(view, installed_routes(), lambda needs: None)['tasks']
                    if t['need'] == 'repair')
        context = task_context(view, task)
        self.assertEqual(context['basis'], view['prefix'])
        self.assertEqual(context['decision']['resource'], task['resource'])
        self.assertIn('law_trace', context)
        self.assertIn('proof_plan', context)
        self.assertIn('autonomy', context)
        self.assertIn('client-custom-name', render_context(context))
        self.assertIn('Information only', render_context(context))
        self.assertEqual(context['grants'], view['grants'])
        self.assertEqual(context['decision']['status'], 'needs_route')

    def test_proof_plan_reads_admitted_status_and_keeps_operation_alternatives_separate(self):
        view = self.view(self.target())
        view['facts'] = [{'property': 'tests', 'status': 'green', 'resource': 'repo:client:custom'}]
        task = {'id': 'repair', 'need': 'repair', 'op': 'remediate', 'resource': 'repo:client:custom',
                'target': 'client-specific', 'state': 'AVAILABLE'}
        packet = task_context(view, task)
        options = {a['route']: a for a in packet['proof_plan']['alternatives']}
        self.assertEqual(packet['proof_plan']['observed']['tests'], 'green')
        self.assertFalse(options['scoped']['mismatch'])
        self.assertIn('reproduced', {x['name'] for x in options['reproduced']['missing']})
        self.assertIn('decision', {x['name'] for x in options['human']['missing']})

    def test_a_diagnostic_green_cannot_override_an_open_constitutional_debt(self):
        target = self.target()
        self.assertEqual(target_state(target, {'status': target['expect']}, [{'state': 'open'}], set()), 'open')
        self.assertEqual(target_state(target, {'status': 'red'}, [], {target['id']}), 'held')
        view = self.view(target)
        view['health']['proven'] = []
        finding = {'repo:client:custom|status': {'status': target['expect'], 'details': []}}
        rows = Installation.__new__(Installation).requirements(view, finding)
        self.assertEqual(rows[0]['state'], 'pending')
        self.assertTrue(rows[0]['diagnostic_conflict'])
        view['health']['open'] = []
        view['health']['proven'] = [{'target': target['id']}]
        self.assertEqual(Installation.__new__(Installation).requirements(view, finding)[0]['state'], 'held')

    def test_drift_controller_maps_gap_to_law_route_and_proof_without_authority(self):
        view = self.view(self.target())
        finding = {'repo:client:custom|status': {'status': 'red', 'details': ['client.py:7:rule']}}
        dossier = gap_dossiers(view, finding, installed_routes(), lambda needs: None)[0]
        self.assertEqual(dossier['id'], 'client-specific')
        self.assertEqual(dossier['state'], 'gap')
        self.assertEqual(dossier['law']['resource'], 'repo:client:custom')
        self.assertEqual(dossier['drift']['where'], ['client.py:7:rule'])
        self.assertEqual(dossier['route']['state'], 'NO_ROUTE')
        self.assertIn('llm_reading', dossier['methods'])
        self.assertIn('Dossier only', dossier['authority'])


    def test_patrol_human_context_keeps_full_declarations_and_weak_spots(self):
        view = self.view(self.target())
        context = patrol_context(view, {}, installed_routes(), lambda needs: None)
        self.assertEqual(context['kind'], 'law-patrol')
        self.assertEqual(context['mode'], 'wide')
        self.assertEqual(context['effective_law'], view['law']['effective'])
        self.assertNotIn('technical', context)                     # no repository snapshot to establish applicability
        self.assertTrue(context['weak_spots'])
        self.assertIn('Exploratory patrol only', context['authority'])

    def test_law_patrol_llm_returns_suspicions_only(self):
        sent = []
        class Research_:
            def dialogue(self, prompt, tree, key, **kwargs):
                sent.append((prompt, key))
                return {'suspicions': [{'law_ref': 'target:client-specific', 'surface': 'repo:client',
                                        'why': 'custom parser is not covered', 'evidence_seen': ['client.py'],
                                        'determinism_gap': 'no probe', 'needs': ['new instrument'],
                                        'suggested_action': 'add a scanner', 'confidence': 'medium',
                                        'facts': ['not allowed']}],
                        'facts': ['not allowed']}
        reply = propose_patrol({'focus': None, 'authority': 'Exploratory patrol only.'}, Snapshot(*store_with(FILES)), Research_())
        self.assertEqual(reply['suspicions'][0]['authority'], 'proposal_only')
        self.assertNotIn('facts', reply['suspicions'][0])
        self.assertIn('catalog requirements and block contracts', sent[0][0])

    def test_agent_patrol_runs_read_only_and_records_its_advisory_result(self):
        root = Path(tempfile.mkdtemp())
        (root / 'store').mkdir()
        calls = []
        class Research_:
            def dialogue(self, prompt, tree, *, key, allowed_actions, context):
                calls.append((key, allowed_actions))
                return {'suspicions': [{'law_ref': 'target:client-specific', 'why': 'possible blind spot',
                                        'facts': ['forbidden']}]}
        view = self.view(self.target())
        cycle = SimpleNamespace(agent=SimpleNamespace(llm=object(), research=Research_(), store=root / 'store'),
                                service=SimpleNamespace(view=lambda: view, qualify=lambda contracts: None),
                                _findings=lambda: {}, routes=installed_routes())
        with patch('agent.patrol.Snapshot', return_value=Snapshot(*store_with(FILES))):
            result = run_patrol(cycle, main=lambda: 'main-head')
        self.assertEqual(calls[0][1], ('read', 'search'))
        self.assertEqual(result['suspicions'][0]['authority'], 'proposal_only')
        self.assertNotIn('facts', result['suspicions'][0])
        self.assertEqual(len((root / 'patrol-results.jsonl').read_text().splitlines()), 1)

    def test_research_does_not_submit_or_close_the_obligation(self):
        view = self.view(self.target())
        class Service:
            def view(self): return view
            def qualify(self, contracts): return None
            def admit(self, statement): raise AssertionError('research cannot admit anything')
        class Agent_:
            def investigate(self, current, task, base, findings, settings=None):
                return {'summary': 'propose an external verifier', 'proposal': {'files': {'tools/check.py': 'pass'}}}
        root = Path(tempfile.mkdtemp())
        engine = WorkEngine(root / 'work.db')
        repairer = Repairer(Service(), engine, Agent_(), installed_routes(), clock=lambda: 2,
                            state_path=root / 'proposals.json')
        report = repairer.run(view, 'base')
        self.assertIn('ob:investigate', report['research'])
        self.assertEqual(report['crafted'], {})
        self.assertEqual({t['due'] for t in engine.tasks()}, {10})

    def test_repairs_receive_the_rules_in_force(self):
        target = next(t for t in FLOORS['targets'] if t['id'] == 'ci')
        view = self.view(target)
        sent = []
        class Service:
            def view(self): return view
            def qualify(self, contracts): return None
            def admit(self, statement): raise AssertionError('a producer never submits')
        class Agent_:
            def craft(self, *args, **kwargs):
                sent.append(kwargs['context'])
                return 'head', 'model'
        root = Path(tempfile.mkdtemp())
        view['law']['effective']['settings'] = {'objective': '99.9'}
        repairer = Repairer(Service(), WorkEngine(root / 'work.db'), Agent_(), installed_routes(), clock=lambda: 2,
                            state_path=root / 'proposals.json')
        self.assertEqual(repairer.run(view, 'base')['candidates']['ci'], 'head')
        self.assertIn('client-custom-name', sent[0]['effective_law']['conditions'])
        self.assertEqual(sent[0]['settings']['objective'], '99.9')

    def test_generic_precheck_does_not_claim_an_unmeasured_target_fixed(self):
        store, base = store_with(FILES)
        with patch('agent.precheck.suite', return_value=('green', [])), \
             patch('agent.precheck.tools', return_value={}):
            result = precheck(store, base, base, 'client-specific', {'client-specific': self.target()}, None,
                              SimpleNamespace(isolation='test fixture'))
        self.assertIsNone(result['fixed'])

    def test_build_receives_the_same_client_law_and_operation_context(self):
        store, base = store_with(FILES)
        sent = []
        gate = Gate({'frontier': Provider('fake', 'anthropic', 'm', 'k')}, store.parent / 'egress.log',
                    transport=lambda p, prompt: sent.append(prompt) or json.dumps(
                        {'findings': []} if prompt.startswith(('ROLE correctness:', 'ROLE simplicity:', 'ROLE design:'))
                        else {'files': {'app.py': 'x = 1'}}))
        builder = Builder(None, Signer(), {}, store, store.parent / 'requests', clock=lambda: 0, notes=store.parent / 'build.json', llm=gate)
        context = task_context(self.view(self.target()), {'id': 'request:r', 'resource': 'build:request/r',
                                                        'need': 'repair', 'op': 'implement'})
        with patch.object(builder, 'check', return_value=[]):
            builder.craft('r', 'example', b'spec', b'contract', base, {}, context=context)
        self.assertIn('standard-agent-context/v2', sent[0])
        self.assertNotIn('client-custom-name', sent[0])
        self.assertIn('repo:feature:{request}/{base}/{head}', sent[0])

    def test_bounded_context_preserves_full_declarations_and_documents_for_reading(self):
        from context.missions import assemble, write_scope
        store, base = store_with({"app.py": "x = 1", "unrelated.py": "PRIVATE_UNRELATED_CODE = 1"})
        view = self.view(self.target())
        view["law"]["effective"]["conditions"]["large-client-condition"] = {"description": "x" * 60000}
        context = task_context(view, {"id": "work", "resource": "repo:client:custom", "target": "client-specific", "op": "remediate"})
        document = "a" * 45000 + "ACCEPTANCE_TAIL"
        prompt, sources = assemble(context, Snapshot(store, base), role="build", scope=write_scope("repair", "ci"),
                                   documents={"acceptance": document})
        self.assertLess(len(prompt), 28000)
        self.assertNotIn("PRIVATE_UNRELATED_CODE", prompt)
        self.assertNotIn("large-client-condition", prompt)
        self.assertIn("law/conditions/large-client-condition", sources)
        self.assertEqual(sources["document/acceptance"], document)
        research = Research(None, store.parent / "notes")
        part = research.act(Snapshot(store, base), {"action": "read", "ref": "document/acceptance", "offset": 40000}, sources)
        self.assertIn("ACCEPTANCE_TAIL", part["text"])
        self.assertIsNone(part["next_offset"])
        self.assertIn("law/conditions/large-client-condition", research.act(Snapshot(store, base),
                      {"action": "search", "in": "context", "query": "large-client"}, sources)["refs"])
        with self.assertRaises(ResearchError):
            research.act(Snapshot(store, base), {"action": "read", "ref": "/etc/passwd"}, sources)

    def test_scoped_patrol_cannot_read_or_search_outside_its_subsystem(self):
        from agent.research import ReadScope
        store, base = store_with({"app/a.py": "visible = 1", "other/b.py": "OUTSIDE_MARKER = 1"})
        research = Research(None, store.parent / "notes")
        tree = ReadScope(Snapshot(store, base), {"app/a.py"})
        with self.assertRaises(ResearchError):
            research.act(tree, {"action": "read", "path": "other/b.py"})
        self.assertEqual(research.act(tree, {"action": "search", "query": "OUTSIDE_MARKER"})["matches"], [])
        with self.assertRaises(ResearchError):
            research.act(tree, {"action": "read", "path": "../other/b.py"})

    def test_patrol_uses_whole_product_applicability_and_records_exact_scope(self):
        store, base = store_with({"app/main.py": "from fastapi import FastAPI\napp = FastAPI()",
                                 "domain/order.py": "def order(): return 1", "other/private.py": "OUTSIDE_CODE = 1"})
        sent = []
        class Research_:
            def dialogue(self, prompt, tree, **kw):
                sent.append((prompt, tree.paths(), kw))
                return {"suspicions": []}
        view = self.view(self.target())
        cycle = SimpleNamespace(agent=SimpleNamespace(llm=object(), research=Research_(), store=store),
                                service=SimpleNamespace(view=lambda: view, qualify=lambda needs: None),
                                _findings=lambda: {}, routes=installed_routes())
        record = run_patrol(cycle, main=lambda: base, focus="rules:authorization:domain")
        self.assertEqual(sent[0][1], {"domain/order.py"})
        self.assertIn("AUTHZ", sent[0][0])
        self.assertNotIn("OUTSIDE_CODE", sent[0][0])
        self.assertEqual(record["scope"]["root"], "domain")
        self.assertEqual(record["state"], "proposed")
        self.assertEqual(sent[0][2]["allowed_actions"], ("read", "search"))
        with self.assertRaises(ValueError):
            run_patrol(cycle, main=lambda: base, focus="simplicity:../other")

    def test_signed_features_reach_scanner_constructor_and_patrol_consistently(self):
        from instruments.coverage import evaluate
        from context.missions import assemble
        store, base = store_with({"app.py": "from fastapi import FastAPI\napp = FastAPI()"})
        view = self.view(self.target())
        view["law"]["effective"]["settings"] = {"features": ["mtls"], "values": {"high_value": ["payments.send"]}}
        ctx = task_context(view, {"id": "work", "need": "repair", "resource": "repo:client:custom"})
        tree = Snapshot(store, base)
        packet = json.loads(assemble(ctx, tree, role="build", touched=["surface:endpoint"])[0])["packet"]
        self.assertIn("MSG-SIGN", packet["rule_ids"])
        from agent.candidate import CandidateWorkflow
        roles = []
        def ask(prompt, role, **kw):
            roles.append(role)
            self.assertIn("MSG-SIGN", prompt)
            self.assertEqual(json.loads(kw["context"]["parameter/high_value"])["value"], ["payments.send"])
            return {"files": {"app/new.py": "x = 1"}} if role == "build" else {"findings": []}
        CandidateWorkflow().run(ask, tree, "Task", context=ctx, touched=["surface:endpoint"], scope_ok=lambda p: True)
        self.assertEqual(set(roles), {"build", "correctness", "simplicity"})
        inputs = Instruments.__new__(Instruments)._rules(view)
        self.assertEqual(inputs["declared"], ["high-value", "mtls"])
        states = evaluate(tree, inputs["catalog"], inputs["values"], declared=inputs["declared"], probes={}, bandit={})
        self.assertNotEqual(states["MSG-SIGN"]["state"], "n/a")
        patrol = patrol_context(view, tree=tree, focus="rules:http-and-apis")
        self.assertIn("MSG-SIGN", patrol["rule_ids"])

    def test_simplicity_surface_and_model_preserve_scoped_block_contracts(self):
        from surface.views import patrol_packet
        store, base = store_with({"app.py": "from fastapi import FastAPI\napp = FastAPI()",
                                 "domain/order.py": "from standard_blocks.process import run\nrun(['convert'])",
                                 "other/private.py": "OUTSIDE_CODE = 1"})
        view, sent = self.view(self.target()), []
        tree = Snapshot(store, base)
        human = patrol_packet(view, {}, installed_routes(), lambda needs: None, "simplicity:domain", tree=tree)
        class Research_:
            def dialogue(self, prompt, scoped, **kw):
                sent.append((prompt, scoped, kw))
                return {"suspicions": []}
        context = patrol_context(view, focus="simplicity:domain", tree=tree)
        propose_patrol(context, tree, Research_())
        prompt, scoped, kw = sent[0]
        packet = json.loads(prompt[prompt.index('{"packet":'):])["packet"]
        self.assertEqual(packet["rule_ids"], human["rule_ids"])
        self.assertEqual(packet["scope"], human["scope"])
        self.assertEqual(packet["technical"], human["technical"])
        self.assertIn("INJ-CMD", packet["rule_ids"])
        self.assertIn("block process:", packet["technical"])
        self.assertEqual(scoped.paths(), {"domain/order.py"})
        self.assertNotIn("OUTSIDE_CODE", prompt)
        with self.assertRaises(ResearchError):
            Research(None, store.parent / "notes").act(scoped, {"action": "read", "path": "other/private.py"}, kw["context"])

    def test_catalog_category_debt_has_actual_observation_and_repair_routes(self):
        target=next(t for t in FLOORS["targets"] if t["id"]=="rules-authorization")
        view=self.view(target)
        view["health"]["open"][0]["needs"]=["observe","repair"]
        tasks=project(view,installed_routes(),lambda needed:None)["tasks"]
        self.assertEqual({t["need"] for t in tasks},{"observe","repair"})
        self.assertTrue(all(t["state"]=="AVAILABLE" for t in tasks))
        self.assertEqual({t["due"] for t in tasks},{10})

    def test_target_patrol_and_investigation_keep_the_exact_requirement(self):
        from context.missions import assemble
        target = next(t for t in FLOORS["targets"] if t["id"] == "rules-authorization")
        store, base = store_with({"app.py": "from fastapi import FastAPI\napp = FastAPI()"})
        view, tree = self.view(target), Snapshot(store, base)
        ctx = task_context(view, {"id": "research", "need": "investigate", "resource": target["resource"],
                                  "target": target["id"]})
        packet = json.loads(assemble(ctx, tree, role="investigate")[0])["packet"]
        self.assertIn("AUTHZ", packet["rule_ids"])
        patrol = patrol_context(view, focus=target["id"], tree=tree)
        self.assertEqual(patrol["requirement"], target)
        self.assertEqual(patrol["category"], "authorization")
        self.assertIn("AUTHZ", patrol["rule_ids"])
        with self.assertRaises(ValueError):
            patrol_context(view, focus="rules", tree=tree)



class ResearchTools(unittest.TestCase):
    def setup_research(self, replies):
        store, base = store_with(FILES)
        sent = []
        gate = Gate({'frontier': Provider('fake', 'anthropic', 'm', 'k')}, store.parent / 'egress.log',
                    transport=lambda p, prompt: sent.append(prompt) or json.dumps(replies.pop(0)))
        return Research(gate, store.parent / 'research.jsonl'), Snapshot(store, base), sent

    def test_read_search_then_propose_are_notes_not_facts(self):
        research, tree, prompts = self.setup_research([
            {'action': 'search', 'query': 'def add'}, {'action': 'read', 'path': 'app.py'},
            {'summary': 'reuse the existing addition', 'proposal': {'files': {'tools/check.py': 'print(1)'}}}])
        result = research.dialogue('investigate', tree)
        self.assertIn('summary', result)
        self.assertIn('app.py:1', prompts[1])
        self.assertIn('return a + b', prompts[2])
        self.assertIn('agent notes only', research.notes.read_text())
        self.assertFalse((tree.repo.parent / 'tools/check.py').exists())

    def test_patrol_research_refuses_fetch_even_when_the_model_requests_it(self):
        research, tree, prompts = self.setup_research([
            {'action': 'fetch', 'source': 'configured'}, {'suspicions': []}])
        with patch.object(research, 'act') as act:
            result = research.dialogue('patrol', tree, allowed_actions=('read', 'search'))
        act.assert_not_called()
        self.assertEqual(result, {'suspicions': []})
        self.assertNotIn('experiment', prompts[0])
        self.assertIn('this pass permits only read, search', prompts[1])

    def test_host_reads_unknown_urls_and_shells_are_refused(self):
        research, tree, _ = self.setup_research([])
        for request in ({'action': 'read', 'path': '/etc/passwd'}, {'action': 'read', 'path': '../keys/agent.key'},
                        {'action': 'fetch', 'source': 'https://attacker/'}, {'action': 'shell', 'command': 'id'}):
            with self.assertRaises(ResearchError):
                research.act(tree, request)
        with self.assertRaises(ResearchError):
            NoRedirect().redirect_request(None, None, None, None, None, None)
        with self.assertRaises(ResearchError):
            Research(None, '/tmp/unused', sources={'bad': 'file:///etc/passwd'})

    def test_experiment_never_falls_back_to_the_agent_account(self):
        research, tree, _ = self.setup_research([])
        with patch('agent.sandbox._can_isolate', return_value=False), \
             patch('agent.research.subprocess.run') as run:
            with self.assertRaises(ResearchError):
                research.experiment(tree, {'check.py': 'print(1)'}, 'check.py')
            run.assert_not_called()
        with self.assertRaises(ResearchError):
            research.experiment(tree, {'../check.py': 'print(1)'}, '../check.py')

    def test_experiment_mounts_only_runtime_and_scratch_without_network_or_secrets(self):
        research, tree, _ = self.setup_research([])
        source_repo = tree.repo
        tree = export(tree.repo, tree.commit, Path(tempfile.mkdtemp()) / 'snapshot')
        seen = []
        def run(args, **kwargs):
            seen.append((args, kwargs['env']))
            kwargs['stdout'].write(b'experiment output')
            return type('Done', (), {'returncode': 0})()
        with patch('agent.sandbox._can_isolate', return_value=True), \
             patch('agent.sandbox.subprocess.run', side_effect=run):
            result = research.experiment(tree, {'check.py': 'print(1)'}, 'check.py')
        self.assertTrue(result.ok)
        args, env = seen[0]
        self.assertIn('--unshare-all', args)
        self.assertIn('--cap-drop', args)
        self.assertNotIn(str(source_repo), args)
        self.assertNotIn('/home', args)
        self.assertNotIn('/srv', args)
        self.assertEqual(set(env), {'PATH', 'HOME', 'LANG', 'PYTHONDONTWRITEBYTECODE'})
        self.assertIn('--fsize=1048576', args)

    def test_fetch_uses_only_the_configured_source_and_bounded_content(self):
        research = Research(None, '/tmp/unused', sources={'docs': 'https://docs.example/approved'})
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                self.size = size
                return b'approved documentation'
        response = Response()
        with patch('agent.research.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(research.fetch('docs'), 'approved documentation')
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://docs.example/approved')
            self.assertEqual(response.size, 1000001)
            with self.assertRaises(ResearchError):
                research.fetch('https://attacker/')
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_real_jail_hides_the_host_or_refuses_to_execute(self):
        research, tree, _ = self.setup_research([])
        with tempfile.TemporaryDirectory() as host:
            secret = Path(host) / 'host-secret'
            secret.write_text('HOST-ONLY-SENTINEL')
            script = (f"try:\n    open({str(secret)!r}).read()\n"
                      "except OSError:\n    print('host inaccessible')\n"
                      "else:\n    raise RuntimeError('host file visible')\n"
                      "import socket\n"
                      "try:\n    socket.create_connection(('1.1.1.1', 80), 1)\n"
                      "except OSError:\n    print('network unavailable')\n"
                      "else:\n    raise RuntimeError('network reachable')\n")
            try:
                result = research.experiment(tree, {'check.py': script}, 'check.py')
            except ResearchError as exc:
                self.assertIn('require bubblewrap', str(exc))
                return
            if result.ok:
                self.assertIn('host inaccessible', result.out)
                self.assertIn('network unavailable', result.out)
            else:
                self.assertIn('bwrap', result.out)
            self.assertNotIn('HOST-ONLY-SENTINEL', result.out)

    def test_research_budget_cannot_loop_forever(self):
        research, tree, _ = self.setup_research([{'action': 'read', 'path': 'app.py'}] * 2)
        research.steps = 2
        with self.assertRaises(ResearchError):
            research.dialogue('investigate', tree)
        self.assertIn('agent notes only', research.notes.read_text())

    def test_a_client_scope_is_a_model_candidate_and_never_touches_invariants(self):
        store, base = store_with(FILES)
        gate = Gate({'frontier': Provider('fake', 'anthropic', 'm', 'k')}, store.parent / 'egress.log',
                    transport=lambda p, prompt: json.dumps({'findings': []} if prompt.startswith(('ROLE correctness:', 'ROLE simplicity:'))
                                                           else {'files': {'tools/check.py': 'def check(): return 1'}}))
        agent = Agent(store, llm=gate, scopes={'custom': ['tools/*.py']})
        check = {'ok': True, 'fixed': None, 'tests': 'green'}
        target = {'id': 'custom', 'resource': 'repo:client:custom', 'property': 'result', 'expect': 'verified'}
        with patch('agent.precheck.precheck', return_value=check):
            _, route = agent.craft('custom', base, targets={'custom': target})
        self.assertEqual(route, 'model')
        for path in ('tests/test_app.py', 'standard/rules.json', '.github/workflows/ci.yml', '../keys/a.key'):
            self.assertFalse(in_scope('custom', path, {'custom': ['*']}))
        unconfigured = Agent(store, llm=gate)
        with self.assertRaises(AgentError):
            unconfigured.craft('custom', base, targets={'custom': target})


class Qualification(unittest.TestCase):
    def installation(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        with patch.object(ceremony, 'now', Clock(1_900_000_000_000)):
            ceremony.init(argparse.Namespace(dir=str(root / 'install'), repo=str(repo), github=None, token_file=None, unconfined_tests=True,
                                             pins=None))
        return root / 'install'

    def test_release_checks_genesis_pin_and_detects_code_change_read_only(self):
        install = self.installation()
        import tomllib
        config = tomllib.loads((install / 'standard.toml').read_text())
        journal = install / config['ledger']['journal']
        identities = qualify.release_basis(journal, config['ledger']['genesis'], qualify.code_digest())
        self.assertIn('human', identities)
        with self.assertRaises(Exception):
            qualify.release_basis(journal, 'sha256:' + '0' * 64, qualify.code_digest())
        with self.assertRaises(Exception):
            qualify.release_basis(journal, config['ledger']['genesis'], 'sha256:' + '0' * 64)
        missing = install / 'missing.db'
        with self.assertRaises(sqlite3.OperationalError):
            qualify.release_basis(missing, config['ledger']['genesis'], qualify.code_digest())
        self.assertFalse(missing.exists())

    def test_empty_key_directory_unsigned_assessment_and_renamed_keys_do_not_pass(self):
        install = self.installation()
        keys = install / 'keys'
        (keys / 'human.key').rename(keys / 'renamed.key')
        report = {p['probe']: p for p in qualify.qualify(install / 'standard.toml')}
        self.assertEqual(report['T02 the human holds their own key']['result'], 'FAIL')
        (install / 'assessment.json').write_text(json.dumps({'payload': {'independent': True}}))
        for path in keys.glob('*.key'): path.unlink()
        report = {p['probe']: p for p in qualify.qualify(install / 'standard.toml')}
        self.assertEqual(report['key files owner-only']['result'], 'FAIL')
        self.assertEqual(report['independent assessment']['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
