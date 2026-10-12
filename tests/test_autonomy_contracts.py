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
from standard.autonomy.agent import Agent, AgentError, in_scope
from standard.autonomy.build import Builder
from standard.autonomy.context import render_context, task_context
from standard.autonomy.cycle import Cycle
from standard.autonomy.llm import Gate, Provider
from standard.autonomy.precheck import precheck, suite as agent_suite
from standard.autonomy.projection import installed_routes, project
from standard.autonomy.research import NoRedirect, Research, ResearchError
from standard.autonomy.sandbox import Result
from standard.autonomy.work import WorkEngine
from standard.floors import FLOORS
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
        subjects = {'main': 'main', 'install': True, 'targets': [], 'entities': {}, 'holders': {},
                    'anchor': 'anchor', 'judged': [], 'now': 0, 'proposals': [], 'inbox': [], 'production': False}
        job = jobs.plan(subjects)[0]
        self.assertEqual(job['inputs']['install'], {'value': True})
        self.assertTrue(job['network'])

    def test_client_target_identifiers_follow_the_kernel_language_in_proposals(self):
        from standard.autonomy.agent import commit_files
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
        task = project(view, installed_routes(), lambda needs: None)['tasks'][0]
        context = task_context(view, task)
        self.assertEqual(context['basis'], view['prefix'])
        self.assertIn('client-custom-name', render_context(context))
        self.assertIn('Information only', render_context(context))
        self.assertEqual(context['grants'], view['grants'])

    def test_cycle_research_does_not_submit_or_close_the_obligation(self):
        view = self.view(self.target())
        class Service:
            def view(self): return view
            def qualify(self, contracts): return None
            def admit(self, statement): raise AssertionError('research cannot admit anything')
        class Agent_:
            def investigate(self, current, task, base, findings):
                return {'summary': 'propose an external verifier', 'proposal': {'files': {'tools/check.py': 'pass'}}}
        root = Path(tempfile.mkdtemp())
        engine = WorkEngine(root / 'work.db')
        cycle = Cycle(Service(), engine, Agent_(), installed_routes(), clock=lambda: 2, main=lambda: 'base',
                      state_path=root / 'proposals.json')
        report = cycle.run()
        self.assertIn('ob:investigate', report['research'])
        self.assertEqual(report['submitted'], {})
        self.assertEqual(report['crafted'], {})
        self.assertEqual({t['due'] for t in engine.tasks()}, {10})

    def test_cycle_passes_the_legal_context_to_repairs(self):
        target = next(t for t in FLOORS['targets'] if t['id'] == 'ci')
        view = self.view(target)
        sent = []
        class Service:
            def view(self): return view
            def qualify(self, contracts): return None
            def admit(self, statement): return {'admitted': True}
        class Agent_:
            def craft(self, *args, **kwargs):
                sent.append(kwargs['law_text'])
                return 'head', 'review'
            def intent(self, *args): return {'intent': 'example'}
        root = Path(tempfile.mkdtemp())
        cycle = Cycle(Service(), WorkEngine(root / 'work.db'), Agent_(), installed_routes(), clock=lambda: 2,
                      main=lambda: 'base', state_path=root / 'proposals.json')
        self.assertEqual(cycle.run()['submitted']['ci'], 'admitted')
        self.assertIn('client-custom-name', sent[0])

    def test_generic_precheck_does_not_claim_an_unmeasured_target_fixed(self):
        store, base = store_with(FILES)
        with patch('standard.autonomy.precheck.suite', return_value=('green', [])), \
             patch('standard.autonomy.precheck.tools', return_value={}):
            result = precheck(store, base, base, 'client-specific', {'client-specific': self.target()}, None,
                              SimpleNamespace(isolation='test fixture'))
        self.assertIsNone(result['fixed'])

    def test_build_receives_the_same_client_law_and_operation_context(self):
        store, base = store_with(FILES)
        sent = []
        gate = Gate({'frontier': Provider('fake', 'anthropic', 'm', 'k')}, store.parent / 'egress.log',
                    transport=lambda p, prompt: sent.append(prompt) or json.dumps({'files': {'app.py': 'x = 1'}}))
        builder = Builder(None, Signer(), {}, store, store.parent / 'requests', main=lambda: base,
                          clock=lambda: 0, notes=store.parent / 'build.json', llm=gate)
        context = task_context(self.view(self.target()), {'id': 'request:r', 'resource': 'build:request/r',
                                                        'need': 'repair', 'op': 'implement'})
        with patch.object(builder, 'check', return_value=[]):
            builder.craft('r', 'example', b'spec', b'contract', base, {}, context=context)
        self.assertIn('client-custom-name', sent[0])
        self.assertIn('repo:feature:{request}/{base}/{head}', sent[0])


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
        with patch('standard.autonomy.research.shutil.which', return_value=None), \
             patch('standard.autonomy.research.subprocess.run') as run:
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
        with patch('standard.autonomy.research.subprocess.run', side_effect=run):
            result = research.experiment(tree, {'check.py': 'print(1)'}, 'check.py')
        self.assertTrue(result.ok)
        args, env = seen[0]
        self.assertIn('--unshare-all', args)
        self.assertIn('--cap-drop', args)
        self.assertNotIn(str(source_repo), args)
        self.assertNotIn('/home', args)
        self.assertNotIn('/srv', args)
        self.assertEqual(set(env), {'PATH', 'HOME', 'LANG'})
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
        with patch('standard.autonomy.research.urllib.request.build_opener') as opener:
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

    def test_configured_client_scope_requires_review_and_cannot_touch_invariants(self):
        store, base = store_with(FILES)
        gate = Gate({'frontier': Provider('fake', 'anthropic', 'm', 'k')}, store.parent / 'egress.log',
                    transport=lambda p, prompt: json.dumps({'files': {'tools/check.py': 'print(1)'}}))
        agent = Agent(Signer(), {'review': 'review-cap'}, store, llm=gate, scopes={'custom': ['tools/*.py']})
        check = {'ok': True, 'fixed': None, 'tests': 'green'}
        target = {'id': 'custom', 'resource': 'repo:client:custom', 'property': 'result', 'expect': 'verified'}
        with patch('standard.autonomy.precheck.precheck', return_value=check):
            _, route = agent.craft('custom', base, targets={'custom': target})
        self.assertEqual(route, 'review')
        for path in ('tests/test_app.py', 'standard/rules.json', '.github/workflows/ci.yml', '../keys/a.key'):
            self.assertFalse(in_scope('custom', path, {'custom': ['*']}))
        unconfigured = Agent(Signer(), 'cap', store, llm=gate)
        with self.assertRaises(AgentError):
            unconfigured.craft('custom', base, targets={'custom': target})


class Qualification(unittest.TestCase):
    def installation(self):
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        with patch.object(ceremony, 'now', Clock(1_900_000_000_000)):
            ceremony.init(argparse.Namespace(dir=str(root / 'install'), repo=str(repo), github=None, token_file=None,
                                             pins=None))
        return root / 'install'

    def test_release_checks_genesis_pin_and_detects_code_change_read_only(self):
        install = self.installation()
        import tomllib
        config = tomllib.loads((install / 'standard.toml').read_text())
        journal = install / config['ledger']['journal']
        identities = qualify.release_basis(journal, config['ledger']['genesis'], qualify.code_digest())
        self.assertIn('h1', identities)
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
        (keys / 'h1.key').rename(keys / 'renamed.key')
        report = {p['probe']: p for p in qualify.qualify(install / 'standard.toml')}
        self.assertEqual(report['T02 humans hold their own keys']['result'], 'FAIL')
        (install / 'assessment.json').write_text(json.dumps({'payload': {'independent': True}}))
        for path in keys.glob('*.key'): path.unlink()
        report = {p['probe']: p for p in qualify.qualify(install / 'standard.toml')}
        self.assertEqual(report['key files owner-only']['result'], 'FAIL')
        self.assertEqual(report['independent assessment']['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
