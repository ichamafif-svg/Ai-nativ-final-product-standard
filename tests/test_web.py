"""The web interface (ARCHITECTURE.md §11.9): a browser signs exactly what the kernel verifies, and the server holds no
key, reads through the gateway and forwards envelopes."""

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import ceremony  # noqa: E402
from kernel.identity import open_envelope, verify  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402


def telemetry_fixture(url="http://svc/metrics", slo=0.999, pages=()):
    from types import SimpleNamespace
    from bt.host import Evidence, Series
    from runtime.operator import publish_readings
    from surface.telemetry import Telemetry

    root = Path(tempfile.mkdtemp())
    evidence = Evidence(root / "evidence")
    host = SimpleNamespace(evidence=evidence, series=Series(evidence, root / "series.json"))
    telemetry = Telemetry(root / "view.db", root / "readings", slo=slo)
    pages = iter(pages)

    def capture(now):
        text = next(pages)
        host.series.add("metrics-0", "metrics", now, None if text is None else text.encode())
        publish_readings(host, {"metrics-0": ("metrics", url)}, root / "readings", now, fresh_s=600)
        telemetry.refresh(now)

    return telemetry, capture


NODE = """
import { envelope, importKeyFile } from "%s";
const [key, domain, body] = process.argv.slice(2);
const signer = await importKeyFile(key);
console.log(JSON.stringify({ env: await envelope(domain, "observation", JSON.parse(body), signer), signer: { keyid: signer.keyid, public: signer.public } }));
"""


def node_sign(key_text: str, domain: str, body: dict) -> dict:
    script = Path(tempfile.mkdtemp()) / "sign.mjs"
    script.write_text(NODE % (ROOT / "surface" / "static" / "sign.js").as_uri())
    r = subprocess.run(
        ["node", str(script), key_text, domain, json.dumps(body)], capture_output=True, text=True, timeout=60
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return json.loads(r.stdout)


@unittest.skipUnless(subprocess.run(["which", "node"], capture_output=True).returncode == 0, "node is not installed")
class BrowserSigning(unittest.TestCase):
    def test_the_browser_signs_the_very_bytes_the_kernel_verifies(self):
        from bt.signing import envelope

        root = Path(tempfile.mkdtemp())
        signer = ceremony.new_key(root / "h3.key")
        body = {
            "id": "review-1",
            "at": 1_900_000_000_000,
            "author": "h3",
            "under": "grant-reviewer",
            "resource": "repo:contrib:alice/" + "a" * 40 + "/" + "b" * 40,
            "property": "review",
            "status": "approved",
            "level": "real",
            "note": 'é ü " \\ \n \u2028 €',
        }
        out = node_sign((root / "h3.key").read_text(), "sha256:" + "0" * 64, body)
        self.assertEqual(out["signer"]["public"], signer.public)
        self.assertEqual(out["signer"]["keyid"], signer.keyid)
        kind, opened, message, _ = open_envelope(out["env"])
        self.assertEqual((kind, opened), ("observation", body))
        self.assertTrue(verify(signer.root_key(), message, out["env"]["signatures"][0]))
        self.assertEqual(out["env"], envelope("sha256:" + "0" * 64, "observation", body, [signer]))  # byte for byte


class Server(unittest.TestCase):
    def test_state_dossier_and_admission_through_the_gateway(self):
        import runtime.operator as daemon
        from surface.web import Installation, handler
        from http.server import ThreadingHTTPServer
        from bt.gateway import AdmissionGateway

        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        ceremony.init(
            argparse.Namespace(
                dir=str(root / "install"),
                repo=str(repo),
                github=None,
                token_file=None,
                unconfined_tests=True,
                pins=str(root / "elsewhere" / "pins.db"),
            )
        )
        operator = daemon.Installation(root / "install" / "standard.toml")
        operator.tick()
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        with open(root / "install" / "standard.toml", "a") as f:  # this test's own telemetry, not the user's
            f.write(f'\n[run]\nstore = "{root / "telemetry.db"}"\n')
        inst = Installation(root / "install" / "standard.toml")
        web = ThreadingHTTPServer(("127.0.0.1", 0), handler(inst))
        threading.Thread(target=web.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{web.server_address[1]}"
        try:
            state = json.loads(urllib.request.urlopen(f"{url}/api/state").read())
            self.assertEqual(state["assessment"], "SELF_ASSESSED")
            rebound = urllib.request.Request(f"{url}/api/state", headers={"Host": "evil.example:8080"})
            with self.assertRaises(urllib.error.HTTPError) as foreign:  # review, high 5: DNS rebinding
                urllib.request.urlopen(rebound)
            self.assertEqual(foreign.exception.code, 403)
            self.assertIn("sbom", [g["target"] for g in state["run"]["gaps"]])
            self.assertEqual(state["signing"]["grants"]["human"]["holder"], "human")
            self.assertEqual(state["queue"], [])  # nothing waits for the human yet
            self.assertIn("deploy", state["law"]["routes"])
            self.assertEqual(state["product"], "repo")
            self.assertEqual(state["progress"]["schema"], "standard-progress/v1")
            states = {r["id"]: r["state"] for r in state["requirements"]}
            self.assertEqual(states["sbom"], "gap")  # the product's state, whatever the product
            self.assertNotIn("isms", states)  # no organisational target any more
            levels = {r["id"]: r["level"] for r in state["autonomy"]["requirements"]}
            self.assertEqual(
                (levels["sbom"], levels["secrets"], levels["branch"]), ("autonomous", "autonomous", "human")
            )
            self.assertEqual(state["autonomy"]["runtime"]["level"], "observed")  # no runtime operation in the law
            self.assertTrue(all(r["why"] for r in state["autonomy"]["requirements"]))
            run = json.loads(urllib.request.urlopen(f"{url}/api/run?window=900").read())
            self.assertEqual(set(run["frontier_reasons"]), {"see", "alert", "act", "prove"})
            self.assertTrue(all(r["no"] for r in run["frontier_reasons"].values()))  # every "no" says why
            self.assertEqual(run["frontier_total"]["act"], 0)  # nothing acts in production
            self.assertFalse(run["live"]["configured"])  # no [deploy]: said, not hidden
            covered = json.loads(urllib.request.urlopen(f"{url}/api/coverage").read())  # the catalog, per category
            self.assertEqual(len(covered["categories"]), 17)
            self.assertIsNone(covered["app"])  # not declared: said
            self.assertTrue(all(r["state"] for c in covered["categories"] for r in c["rules"]))
            settings = json.loads(urllib.request.urlopen(f"{url}/api/settings").read())  # D51: the rules of the game
            rules = settings["rules"]
            self.assertEqual(rules["settings"]["objective"], "99.9")
            self.assertEqual(settings["signing"]["grant"]["holder"], "human")
            self.assertEqual(rules["routes"]["restart"]["auto"], [])  # restarting stays yours
            self.assertIn("direct", rules["routes"]["deploy"]["auto"])
            self.assertEqual(rules["bounds"]["burn_fast"], {"socle": "14.4", "way": "ge"})
            self.assertEqual([h["kind"] for h in rules["history"]], ["genesis"])
            preview = json.loads(urllib.request.urlopen(f"{url}/api/preview?sli=availability&target=99.9").read())
            self.assertIn("minutes", preview)

            # Prévenir: a silent source opens an alert; a silence is a rule the human signs, never a fact.
            operator.instruments.sources = {"metrics-0": ("metrics", "http://standard/metrics")}
            operator.host.fetch = lambda u: (_ for _ in ()).throw(OSError("down"))
            operator.tick()
            inst.telemetry.refresh()
            inst.telemetry.track()
            clock.t += 3_700_000  # past run-sources' due
            operator.tick()
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertIn("target:run-sources", [a["name"] for a in alerts["alerts"]])  # overdue gaps alert too
            source = [a for a in alerts["alerts"] if a["source"] == "run"]
            self.assertEqual(len(source), 1)
            before = alerts["open"]
            alert = source[0]
            self.assertEqual((alert["kind"], alert["why"]["rule"]), ("source", "source_down"))
            self.assertEqual(alert["severity"], "page")  # D32: page or ticket
            from surface.human import load_signer
            from bt.signing import envelope

            post = lambda path, body: urllib.request.urlopen(
                urllib.request.Request(
                    f"{url}{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
                )
            )
            draft = json.loads(
                post(
                    "/api/rules/draft",
                    {
                        "sections": {
                            "silences": {
                                "m-maint": {
                                    "target_of": alert["subject"],
                                    "until": str(clock.t + 3_600_000),
                                    "reason": "maintenance",
                                }
                            }
                        }
                    },
                ).read()
            )
            signed = envelope(
                draft["domain"],
                "law",
                {
                    "id": "law-silence",
                    "at": max(clock(), draft["as_of"] + 1),
                    "author": "human",
                    "client": draft["client"],
                },
                [load_signer("human", root / "install" / "keys" / "human.key")],
            )
            self.assertEqual(post("/api/admit", signed).status, 200)  # in force at once
            inst.telemetry.track()
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertEqual(alerts["open"], before - 1)  # muted in the console only
            self.assertTrue(next(a for a in alerts["alerts"] if a["resource"] == alert["resource"])["silenced"])
            with self.assertRaises(urllib.error.HTTPError) as bad:  # a malformed rule never gets signed
                post("/api/rules/draft", {"settings": {"deploy_tz": "Mars/Olympus"}})
            self.assertEqual(bad.exception.code, 400)
            operator.host.fetch = lambda u: b""
            operator.tick()
            inst.telemetry.refresh()
            inst.telemetry.track()
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertFalse([a for a in alerts["alerts"] if a["source"] == "run" and a["closed_at"] is None])  # closed
            for asset in ("/app.css", "/sign.js", "/rules.js", "/app.js"):
                self.assertEqual(urllib.request.urlopen(f"{url}{asset}").status, 200)
            main = state["main"]
            self.assertIn("initial", json.loads(urllib.request.urlopen(f"{url}/api/dossier/{main}").read())["message"])
            page = urllib.request.urlopen(f"{url}/").read().decode()
            self.assertIn('src="/app.js"', page)
            forged = urllib.request.Request(
                f"{url}/api/admit",
                data=json.dumps({"payloadType": "x"}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(forged)
            self.assertEqual(refused.exception.code, 409)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(f"{url}/api/dossier/..%2f..%2fetc")
        finally:
            web.shutdown()
            web.server_close()
            gateway.shutdown()
            gateway.server_close()


class Telemetry(unittest.TestCase):
    """The Run page's numbers: rates, error rate, quantiles and budget from cumulative Prometheus histograms."""

    def exposition(self, ok, errors, fast, slow):
        name = "http_server_request_duration_seconds"
        out = []
        for status, n, under in (("200", ok, fast), ("500", errors, 0)):
            labels = f'http_request_method="GET",http_route="/users/{{id}}",http_response_status_code="{status}"'
            out += [
                f'{name}_bucket{{{labels},le="0.1"}} {under}',
                f'{name}_bucket{{{labels},le="1"}} {n}',
                f'{name}_bucket{{{labels},le="+Inf"}} {n}',
                f"{name}_count{{{labels}}} {n}",
            ]
        return "\n".join(out) + "\nsome_other_metric 3\n"

    def test_rates_errors_quantiles_budget_and_restarts(self):
        from surface.telemetry import declared_routes, quantile

        pages = iter([self.exposition(0, 0, 0, 0), self.exposition(900, 100, 800, 0), self.exposition(50, 0, 50, 0)])
        t, capture = telemetry_fixture(pages=pages)
        capture(now=1000)
        capture(now=1100)
        report = t.report([("GET", "/users/{id}"), ("DELETE", "/orders/{id}")], window=600, now=1100)
        users = next(r for r in report["routes"] if r["name"] == "/users/{id}")
        self.assertEqual((users["requests"], users["rps"]), (1000, 10.0))
        self.assertAlmostEqual(users["error_rate"], 0.1)
        self.assertEqual(users["state"], "failing")
        self.assertEqual(users["why"], {"rule": "error_rate", "value": 0.1, "limit": 0.05})
        self.assertLess(report["fleet"]["budget"], 0)  # 10 % errors against a 99.9 % objective
        self.assertEqual(users["p50"], 62.5)  # 500th of 800 under 100 ms
        idle = next(r for r in report["routes"] if r["name"] == "/orders/{id}")
        self.assertEqual((idle["state"], idle["observed"], idle["declared"]), ("idle", False, True))
        capture(now=1200)  # the service restarted: counters fell
        self.assertEqual(t.report(window=600, now=1200)["fleet"]["requests"], 1050)
        self.assertIsNone(quantile(0.5, {}))
        self.assertEqual(declared_routes('{"paths": {"/a": {"get": {}, "parameters": []}}}'), [("GET", "/a")])

    def test_a_silent_source_is_reported_never_zero(self):

        def down(url):
            raise OSError("connection refused")

        t, capture = telemetry_fixture(pages=[None])
        capture(now=1000)
        report = t.report(window=600, now=1000)
        self.assertFalse(report["targets"][0]["up"])
        self.assertIsNone(report["fleet"]["error_rate"])


class Components(unittest.TestCase):
    """Not only APIs: workers, jobs, databases, external dependencies and processes, each with its own signals."""

    def test_every_kind_is_recognised_from_the_conventions(self):
        def page(n, last_success):
            h = lambda fam, labels, count: (
                f'{fam}_bucket{{{labels},le="0.1"}} {count}\n'
                f'{fam}_bucket{{{labels},le="+Inf"}} {count}\n{fam}_count{{{labels}}} {count}\n'
            )
            return (
                h("messaging_process_duration_seconds", 'messaging_destination_name="orders"', n)
                + h(
                    "messaging_process_duration_seconds",
                    'messaging_destination_name="orders",error_type="declined"',
                    n // 10,
                )
                + 'messaging_queue_depth{messaging_destination_name="orders"} 7\n'
                + h(
                    "db_client_operation_duration_seconds",
                    'db_system_name="postgresql",db_namespace="shop",db_operation_name="select"',
                    n,
                )
                + h(
                    "http_client_request_duration_seconds",
                    'server_address="api.payments.example",http_response_status_code="503"',
                    n // 5,
                )
                + f'job_last_success_timestamp_seconds{{job="daily-report"}} {last_success}\n'
                + 'job_period_seconds{job="daily-report"} 60\njob_last_status{job="daily-report"} 1\n'
                + f"process_cpu_seconds_total {n / 100}\nprocess_resident_memory_bytes 52428800\nprocess_start_time_seconds 100\n"
            )

        pages = iter([page(0, 900), page(100, 1000)])
        t, capture = telemetry_fixture(url="http://svc:9000/metrics", pages=pages)
        capture(now=1000)
        capture(now=1100)
        c = t.report(window=600, now=1300)["components"]
        worker = c["worker"][0]
        self.assertEqual((worker["name"], worker["backlog"], worker["requests"]), ("orders", 7, 110))
        self.assertAlmostEqual(worker["error_rate"], 10 / 110)
        self.assertEqual(c["database"][0]["name"], "postgresql/shop")
        self.assertEqual(c["dependency"][0]["name"], "api.payments.example")
        self.assertEqual(c["dependency"][0]["state"], "failing")
        job = c["job"][0]
        self.assertEqual((job["name"], job["state"]), ("daily-report", "degraded"))  # 300 s since success, period 60
        self.assertEqual(job["why"], {"rule": "job_late", "value": 300.0, "limit": 120.0})
        process = c["process"][0]
        self.assertEqual((process["name"], process["memory"], process["uptime"]), ("svc:9000", 52428800, 1200))
        self.assertAlmostEqual(process["cpu"], 0.01)


class SharedCaptures(unittest.TestCase):
    def test_restart_replays_retained_bt_captures_once_without_network(self):
        from surface.telemetry import Telemetry as Reading
        from unittest.mock import patch

        metrics = Telemetry()
        t, capture = telemetry_fixture(pages=[metrics.exposition(0, 0, 0, 0), metrics.exposition(900, 100, 800, 0)])
        capture(1000)
        capture(1100)
        replay = Reading(t.readings.parent / "restart.db", t.readings)
        with patch("urllib.request.urlopen", side_effect=AssertionError("the interface must not collect")):
            self.assertEqual(replay.report(window=600, now=1100)["fleet"]["requests"], 1000)
            self.assertEqual(replay.report(window=600, now=1100)["fleet"]["requests"], 1000)
        self.assertEqual(replay.capture_basis["state"], "published")
        t.db.close()
        replay.db.close()

    def test_corrupt_absent_and_stale_captures_do_not_look_healthy_or_close_incidents(self):
        metrics = Telemetry()
        t, capture = telemetry_fixture(pages=[metrics.exposition(0, 0, 0, 0), metrics.exposition(900, 100, 800, 0)])
        capture(1000)
        capture(1100)
        t.track(now=1100)
        self.assertTrue(any(i["kind"] == "api" for i in t.incidents(0)))
        manifest = json.loads((t.readings / "index.json").read_text())
        chunk = json.loads((t.readings / manifest["sources"]["metrics-0"]["chunks"][0][7:]).read_text())
        leaf = t.readings / chunk[-1][1][7:]
        original = leaf.read_bytes()
        leaf.write_text("corrupt")
        report = t.report(window=600, now=1100)
        self.assertEqual(report["capture_basis"]["state"], "unavailable")
        self.assertTrue(all(r["state"] == "unknown" for r in report["routes"]))
        t.track(now=1100)
        self.assertTrue(any(i["kind"] == "api" and i["closed_at"] is None for i in t.incidents(0)))
        leaf.write_bytes(original)
        stale = t.report(window=3600, now=1800)
        self.assertFalse(stale["targets"][0]["up"])
        self.assertEqual(stale["routes"][0]["state"], "unknown")
        (t.readings / "index.json").unlink()
        self.assertEqual(t.report(now=1800)["capture_basis"]["state"], "unavailable")
        t.db.close()

    def test_latest_capture_at_the_same_instant_replaces_an_unavailable_source(self):
        t,capture=telemetry_fixture(pages=[None, "metric 1"])
        capture(1000)
        self.assertFalse(t.report(now=1000)["targets"][0]["up"])
        capture(1000)
        self.assertTrue(t.report(now=1000)["targets"][0]["up"])
        t.db.close()

    def test_public_projection_excludes_private_probe_and_runner_evidence(self):
        from bt.host import Evidence, Series
        from runtime.operator import publish_readings
        from types import SimpleNamespace

        root = Path(tempfile.mkdtemp())
        evidence = Evidence(root / "private")
        host = SimpleNamespace(evidence=evidence, series=Series(evidence, root / "series.json"))
        private = host.series.add("probes", "probes", 1000, b"PRIVATE_PROBE_RESPONSE")
        runner = host.series.add("runner", "runner", 1000, b"PRIVATE_RUNNER_METRICS")
        host.series.add("metrics-0", "metrics", 1000, b"public_metric 1")
        publish_readings(
            host,
            {"metrics-0": ("metrics", "http://metrics"), "runner": ("runner", "http://runner")},
            root / "public",
            1000,
        )
        manifest = json.loads((root / "public/index.json").read_text())
        self.assertEqual(set(manifest["sources"]), {"metrics-0"})
        self.assertFalse((root / "public" / private[7:]).exists())
        self.assertFalse((root / "public" / runner[7:]).exists())


if __name__ == "__main__":
    unittest.main()
