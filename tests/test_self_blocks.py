"""Standard uses the product blocks without granting them admission or rewriting signed data."""
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpcore
import httpx

from engine.agents.llm import EgressError, Gate, Provider, anthropic, openai_compatible
from blocks.python.standard_blocks import Values
from blocks.python.standard_blocks.outbound import _CheckedBackend, request
from blocks.python.standard_blocks.parse import ParseError, strict_json
from blocks.python.standard_blocks.runtime import RuntimeRefused, read_secret
from interface.surface.web import handler
from tools import refresh_data


class ModelCalls(unittest.TestCase):
    def test_python_primitives_import_and_run_without_the_web_extra(self):
        script = '''
import importlib.abc, json, sys, tomllib
from pathlib import Path
class NoWeb(importlib.abc.MetaPathFinder):
    def find_spec(self, name, *args):
        if name.split('.')[0] in ('fastapi', 'starlette', 'jwt'):
            raise ImportError('web extra is absent')
sys.meta_path.insert(0, NoWeb())
from blocks.python.standard_blocks import crypto, data, input, log, outbound, parse, process, render, runtime
assert parse.strict_json(b'{"ok":true}') == {'ok': True}
assert crypto.same('same', 'same')
assert str(render.escape('<value>')) == '&lt;value&gt;'
package = tomllib.loads(Path('blocks/python/pyproject.toml').read_text())['project']
assert not any(d.lower().startswith(('fastapi', 'pyjwt')) for d in package['dependencies'])
assert any(d.startswith('fastapi') for d in package['optional-dependencies']['web'])
'''
        subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
                       capture_output=True, check=True, timeout=10)

    def test_both_providers_use_blocks_and_reveal_keys_only_in_headers(self):
        provider = Provider("p", "openai", "m", "PRIVATE-MODEL-KEY")
        self.assertNotIn("PRIVATE-MODEL-KEY", repr(provider))
        seen = []

        def respond(req):
            seen.append(req)
            text = '{"summary":"ok"}'
            return httpx.Response(200, json={"content": [{"text": text}],
                                            "choices": [{"message": {"content": text}}]})

        with patch("blocks.python.standard_blocks.outbound._transport",
                   side_effect=lambda hosts: httpx.MockTransport(respond)):
            self.assertEqual(openai_compatible("https://model.example/v1/chat?version=2", "m", provider.key, "hi"),
                             '{"summary":"ok"}')
            self.assertEqual(anthropic("", "m", provider.key, "hi"), '{"summary":"ok"}')
        self.assertEqual(str(seen[0].url), "https://model.example/v1/chat?version=2")
        self.assertEqual(seen[0].headers["authorization"], "Bearer PRIVATE-MODEL-KEY")
        self.assertEqual(seen[1].headers["x-api-key"], "PRIVATE-MODEL-KEY")
        self.assertEqual(json.loads(seen[0].content)["messages"][-1]["content"], "hi")

    def test_provider_redirects_http_and_oversized_or_ambiguous_json_are_refused(self):
        for response in (httpx.Response(307, headers={"location": "https://attacker.example/"}),
                         httpx.Response(500), httpx.Response(200, content=b'{"choices":[],"choices":[]}'),
                         httpx.Response(200, headers={"content-length": str(9 * 1024 * 1024)})):
            seen = []
            def respond(req):
                seen.append(str(req.url))
                return response
            with patch("blocks.python.standard_blocks.outbound._transport",
                       return_value=httpx.MockTransport(respond)):
                with self.assertRaises(EgressError):
                    openai_compatible("https://model.example/chat", "m", "k", "prompt")
            self.assertEqual(seen, ["https://model.example/chat"])
        with self.assertRaises(EgressError):
            openai_compatible("http://127.0.0.1:8080/chat", "m", "k", "prompt")

    def test_model_proposals_are_bounded_and_strict_even_with_a_custom_transport(self):
        with tempfile.TemporaryDirectory() as root:
            for reply in ('{"files":{},"files":{"a":"b"}}', '{"x":NaN}', '{"x":1e999}',
                          '{"x":' + '[' * 65 + '0' + ']' * 65 + '}', '{"x":"' + 'x' * (8 * 1024**2) + '"}'):
                gate = Gate({"frontier": Provider("p", "openai", "m", "k")}, Path(root) / "egress",
                            transport=lambda p, prompt: reply)
                with self.assertRaises(EgressError):
                    gate.ask("investigate")

    def test_operator_keys_use_the_secret_file_reader(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            key = root / "model.key"
            key.write_text("PRIVATE-MODEL-KEY\n")
            gate = Gate.from_config({"frontier": {"kind": "openai", "model": "m", "key_file": "model.key"}},
                                    lambda path: root / path, root / "egress")
            self.assertEqual(gate.tiers["frontier"].key.reveal(), "PRIVATE-MODEL-KEY")
            self.assertNotIn("PRIVATE-MODEL-KEY", repr(gate.tiers))
            for value in ("", " " * 65_537):
                key.write_text(value)
                with self.assertRaises(RuntimeRefused):
                    read_secret(key)
            key.write_text("value")
            for mode in (0o666, 0o620):
                key.chmod(mode)
                with self.assertRaises(RuntimeRefused):
                    read_secret(key)
            key.chmod(0o600)
            link = root / "link"
            link.symlink_to(key)
            with self.assertRaises(RuntimeRefused):
                read_secret(link)


class OutboundCalls(unittest.TestCase):
    def test_sync_client_closes_on_failure_and_retains_the_one_deadline(self):
        class Slow(httpx.AsyncBaseTransport):
            closed = False
            async def handle_async_request(self, request):
                await asyncio.sleep(1)
            async def aclose(self):
                self.closed = True
        transport = Slow()
        with self.assertRaises(httpx.TimeoutException):
            request("GET", "docs", endpoints={"docs": "https://docs.example/"},
                    values=Values({"destinations": ["docs.example"], "outbound_timeout_s": 1}),
                    timeout=.01, transport=transport)
        self.assertTrue(transport.closed)

    def test_checked_dns_refuses_mixed_addresses_and_connects_to_the_checked_ip(self):
        async def check():
            backend = _CheckedBackend(set())
            backend.inner = SimpleNamespace(connect_tcp=AsyncMock(return_value="connection"))
            public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))
            metadata = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
            loop = asyncio.get_running_loop()
            with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[public, metadata])):
                with self.assertRaises(httpcore.ConnectError) as refused:
                    await backend.connect_tcp("docs.example", 443)
                self.assertIn("link-local or metadata", str(refused.exception))
                backend.inner.connect_tcp.assert_not_called()
            with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[public])):
                self.assertEqual(await backend.connect_tcp("docs.example", 443), "connection")
                self.assertEqual(backend.inner.connect_tcp.call_args.args[:2], ("1.1.1.1", 443))
        asyncio.run(check())

    def test_refresh_keeps_public_hosts_fixed_and_refuses_non_json_metadata(self):
        seen = []
        def respond(req):
            seen.append(str(req.url))
            return httpx.Response(200, content=b'{"v":1,"v":2}')
        with patch("blocks.python.standard_blocks.outbound._transport",
                   side_effect=lambda hosts: httpx.MockTransport(respond)):
            with self.assertRaises(ParseError):
                refresh_data.get("https://pypi.org/pypi/example/json")
            with self.assertRaises(ValueError):
                refresh_data.get("https://attacker.example/json")
        self.assertEqual(seen, ["https://pypi.org/pypi/example/json"])


class ConsoleInputs(unittest.TestCase):
    def test_block_logs_leave_cli_json_alone_on_stdout(self):
        result = subprocess.run([sys.executable, "-c",
                                 "from blocks.python.standard_blocks import log; "
                                 "log.event('test'); print('{\"result\":true}')"],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                                check=True, timeout=10)
        self.assertEqual(json.loads(result.stdout), {"result": True})
        self.assertEqual(json.loads(result.stderr)["event"], "test")

    def test_ambiguous_json_never_reaches_storage_or_admission_and_signed_text_is_preserved(self):
        seen = []
        inst = SimpleNamespace(store_request=lambda body: seen.append(body) or {},
                               draft_rules=lambda body: seen.append(body) or {},
                               client=SimpleNamespace(admit=lambda body: seen.append(body) or "ok"))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(inst))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False) as client:
                for route in ("/api/requests", "/api/rules/draft", "/api/admit"):
                    for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]',
                                 b'{"x":"\\ud800"}', b'[' * 33 + b'0' + b']' * 33):
                        self.assertEqual(client.post(route, content=body,
                                                     headers={"content-type": "application/json"}).status_code, 400)
                self.assertEqual(seen, [])
                body = {"payload": "BASE64-SIGNED-DATA", "note": "e\u0301 \u2028 \n"}
                self.assertEqual(client.post("/api/admit", json=body).status_code, 200)
                self.assertEqual(seen, [body])             # parse only: never NFC/trim a signed document
                with self.assertLogs("standard", level="INFO") as logs:
                    client.get("/missing?api_key=PRIVATE-QUERY-VALUE")
                self.assertNotIn("PRIVATE-QUERY-VALUE", "".join(logs.output))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_strict_parser_preserves_valid_signed_data_without_normalization(self):
        body = {"note": "e\u0301", "at": 1_900_000_000_000, "body": "x\n\u2028"}
        self.assertEqual(strict_json(json.dumps(body)), body)


if __name__ == "__main__":
    unittest.main()
