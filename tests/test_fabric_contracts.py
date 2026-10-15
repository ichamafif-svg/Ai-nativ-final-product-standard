"""Profiles, native capability translation and inventory must not manufacture security evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fabric.evidence.guarantees import inventory
from fabric.identity.keys import OpenBao, egress_policy
from fabric.runtime.bac import Bac, Ran, Walls
from fabric.runtime.profiles import runtime_names
from engine.catalog import load
from interface.context.feedback import matrix

ROOT = Path(__file__).resolve().parents[1]


class Contracts(unittest.TestCase):
    def test_registry_names_existing_enforcers_and_tests_and_keeps_limits_visible(self):
        rows = inventory()
        self.assertEqual(len({r['id'] for r in rows}), len(rows))
        for row in rows:
            self.assertTrue(row['assumptions'] and row['bypass'] and row['remaining'], row['id'])
            for file in row['tests'] + row['enforcer'].split('; '):
                self.assertTrue((ROOT / file).exists(), file)

    def test_native_policies_cannot_grant_other_keys_or_administration(self):
        paths = json.loads(egress_policy(['model'], {'product-a': ['encrypt']}))['path']
        self.assertEqual(set(paths), {'auth/token/revoke-self', 'secret/data/model', 'transit/encrypt/product-a'})
        self.assertEqual(paths['secret/data/model']['capabilities'], ['read'])
        for name in ['*', '../x', 'a/b', 'a+']:
            with self.assertRaises(ValueError):
                egress_policy([name], {})
        with self.assertRaises(ValueError):
            egress_policy([], {'guard': ['sign']})
        with self.assertRaises(ValueError):
            egress_policy([], {'product-a': ['rotate']})

    def test_native_tokens_have_a_hard_expiry_and_no_inherited_default_policy(self):
        bao = OpenBao('https://bao.example', 'bootstrap-not-for-the-proxy')
        with patch.object(bao, 'call', side_effect=[{}, {'auth': {'client_token': 'scoped'}}]) as call:
            child = bao.restrict(['model'], {})
        self.assertEqual(child.token, 'scoped')
        payload = call.call_args_list[-1].args[2]
        self.assertTrue(payload['no_default_policy'])
        self.assertFalse(payload['renewable'])
        self.assertEqual(payload['explicit_max_ttl'], '3600s')
        self.assertNotIn('root', payload['policies'])

    def test_stronger_profiles_cannot_silently_use_the_host_kernel_runtime(self):
        self.assertEqual(runtime_names('reinforced'), ('runsc',))
        self.assertEqual(runtime_names('critical'), ('runsc',))
        with self.assertRaises(ValueError):
            runtime_names('unknown')
        with patch('fabric.runtime.bac.shutil.which', return_value=None):
            bac = Bac(profile='critical')
        self.assertFalse(bac.ready)
        self.assertIn('runsc', bac.why)
        with patch('fabric.runtime.bac.shutil.which', return_value='/runtime'), \
                patch.object(Bac, '_execute', return_value=Ran(1, 'cgroups refused')) as execute:
            bac = Bac()
        self.assertFalse(bac.ready)
        self.assertTrue(bac.groups)
        self.assertEqual(execute.call_count, 3)

    def test_invalid_limits_are_rejected_before_launch(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                Walls(memory_mb=value)

    def test_inventory_never_qualifies_a_deployment(self):
        result = matrix(load())
        self.assertEqual({r['deployment'] for r in result['rules'].values()}, {'unmeasured'})
        self.assertEqual(result['rules']['SSRF']['sources']['run'], ['wall (implemented, unmeasured)'])

    def test_log_bounds_do_not_split_a_secret_into_publishable_fragments(self):
        from fabric.evidence.logs import Capture, LINE_MAX
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'capture.jsonl'
            capture = Capture(path, release='r', secrets=['secret-value'])
            os.write(capture.fileno(), b'x' * (LINE_MAX - 3) + b'secret-value\nnext secret-value\n')
            capture.close()
            lines = [json.loads(line)['line'] for line in path.read_text().splitlines()]
            self.assertEqual(lines, ['[oversized line omitted]', 'next [secret]'])
