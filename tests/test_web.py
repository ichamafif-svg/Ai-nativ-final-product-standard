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
sys.path.insert(0, str(ROOT / "tools"))

import ceremony  # noqa: E402
from kernel.canon import canon  # noqa: E402
from kernel.identity import open_envelope, statement, verify  # noqa: E402
from test_install import Clock  # noqa: E402
from test_maintenance import FILES, demo_repository  # noqa: E402

NODE = """
import { envelope, importKeyFile } from "%s";
const [key, domain, body] = process.argv.slice(2);
const signer = await importKeyFile(key);
console.log(JSON.stringify({ env: await envelope(domain, "observation", JSON.parse(body), signer), signer: { keyid: signer.keyid, public: signer.public } }));
"""


def node_sign(key_text: str, domain: str, body: dict) -> dict:
    script = Path(tempfile.mkdtemp()) / "sign.mjs"
    script.write_text(NODE % (ROOT / "surface" / "static" / "sign.js").as_uri())
    r = subprocess.run(["node", str(script), key_text, domain, json.dumps(body)], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return json.loads(r.stdout)


@unittest.skipUnless(subprocess.run(["which", "node"], capture_output=True).returncode == 0, "node is not installed")
class BrowserSigning(unittest.TestCase):
    def test_the_browser_signs_the_very_bytes_the_kernel_verifies(self):
        from trusted.signing import envelope
        root = Path(tempfile.mkdtemp())
        signer = ceremony.new_key(root / "h3.key")
        body = {"id": "review-1", "at": 1_900_000_000_000, "author": "h3", "under": "grant-reviewer",
                "resource": "repo:contrib:alice/" + "a" * 40 + "/" + "b" * 40, "property": "review",
                "status": "approved", "level": "real", "note": 'é ü " \\ \n \u2028 €'}
        out = node_sign((root / "h3.key").read_text(), "sha256:" + "0" * 64, body)
        self.assertEqual(out["signer"]["public"], signer.public)
        self.assertEqual(out["signer"]["keyid"], signer.keyid)
        kind, opened, message, _ = open_envelope(out["env"])
        self.assertEqual((kind, opened), ("observation", body))
        self.assertTrue(verify(signer.root_key(), message, out["env"]["signatures"][0]))
        self.assertEqual(out["env"], envelope("sha256:" + "0" * 64, "observation", body, [signer]))   # byte for byte


class Server(unittest.TestCase):
    def test_state_dossier_and_admission_through_the_gateway(self):
        import trusted.daemon as daemon
        from surface.web import Installation, handler
        from http.server import ThreadingHTTPServer
        from trusted.gateway import AdmissionGateway
        root = Path(tempfile.mkdtemp())
        repo = demo_repository(root, FILES)
        clock = Clock(1_900_000_000_000)
        ceremony.now = daemon.now_ms = clock
        ceremony.init(argparse.Namespace(dir=str(root / "install"), repo=str(repo), github=None, token_file=None,
                                         pins=str(root / "elsewhere" / "pins.db")))
        clock.t += 3_600_100
        ceremony.activate(argparse.Namespace(dir=str(root / "install")))
        operator = daemon.Installation(root / "install" / "standard.toml")
        operator.tick()
        gateway = AdmissionGateway(operator.socket, operator.service)
        threading.Thread(target=gateway.serve_forever, daemon=True).start()
        with open(root / "install" / "standard.toml", "a") as f:     # this test's own telemetry, not the user's
            f.write(f'\n[run]\nstore = "{root / "telemetry.db"}"\n')
        inst = Installation(root / "install" / "standard.toml")
        web = ThreadingHTTPServer(("127.0.0.1", 0), handler(inst))
        threading.Thread(target=web.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{web.server_address[1]}"
        try:
            state = json.loads(urllib.request.urlopen(f"{url}/api/state").read())
            self.assertEqual(state["assessment"], "SELF_ASSESSED")
            self.assertIn("sbom", [g["target"] for g in state["run"]["gaps"]])
            self.assertEqual(state["signing"]["grants"]["reviewer"]["holder"], "h3")
            self.assertEqual(state["product"], "repo")
            states = {r["id"]: r["state"] for r in state["requirements"]}
            self.assertEqual(states["sbom"], "gap")                     # the product's state, whatever the product
            self.assertEqual(states["isms"], "attest")
            levels = {r["id"]: r["level"] for r in state["autonomy"]["requirements"]}
            self.assertEqual((levels["sbom"], levels["secrets"], levels["isms"]), ("autonomous", "supervised", "human"))
            self.assertEqual(state["autonomy"]["runtime"]["level"], "observed")    # no runtime operation in the law
            self.assertTrue(all(r["why"] for r in state["autonomy"]["requirements"]))
            run = json.loads(urllib.request.urlopen(f"{url}/api/run?window=900").read())
            self.assertEqual(set(run["frontier_reasons"]), {"see", "alert", "act", "prove"})
            self.assertTrue(all(r["no"] for r in run["frontier_reasons"].values()))   # every "no" says why
            self.assertEqual(run["frontier_total"]["act"], 0)                        # nothing acts in production
            self.assertFalse(run["live"]["configured"])                               # no [deploy]: said, not hidden
            settings = json.loads(urllib.request.urlopen(f"{url}/api/settings").read())    # D31: what engineers set
            self.assertEqual(settings["policy"]["defaults"]["objective"], 99.9)
            self.assertEqual(settings["signing"]["grant"]["holder"], "h1")
            self.assertIn("auto_rollback", settings["policy"]["defaults"])

            # Prévenir: a silent source opens an alert; a person takes it by a signature the kernel admits.
            inst.telemetry.targets, inst.telemetry.fetch = ["http://product/metrics"], lambda u: (_ for _ in ()).throw(OSError("down"))
            inst.telemetry.scrape()
            inst.telemetry.track()
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertIn("target:run-sources", [a["name"] for a in alerts["alerts"]])  # overdue gaps alert too
            source = [a for a in alerts["alerts"] if a["source"] == "run"]
            self.assertEqual(len(source), 1)
            before = alerts["untaken"]
            alert = source[0]
            self.assertEqual((alert["kind"], alert["why"]["rule"]), ("source", "source_down"))
            from surface.human import load_signer
            from trusted.signing import envelope
            ack = envelope(alerts["signing"]["domain"], "observation", {
                "id": "ack-1", "at": max(clock(), alerts["signing"]["as_of"] + 1), "author": "h3",
                "under": alerts["signing"]["grant"]["id"], "resource": alert["resource"], "property": "ack",
                "status": "taken", "level": "real"}, [load_signer("h3", root / "install" / "keys" / "h3.key")])
            admitted = urllib.request.Request(f"{url}/api/admit", data=json.dumps(ack).encode(),
                                              headers={"Content-Type": "application/json"})
            self.assertEqual(urllib.request.urlopen(admitted).status, 200)
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertEqual(alerts["untaken"], before - 1)                       # taken, and the journal keeps who
            self.assertTrue(next(a for a in alerts["alerts"] if a["resource"] == alert["resource"])["taken"])
            inst.telemetry.fetch = lambda u: ""
            inst.telemetry.scrape()
            inst.telemetry.track()
            alerts = json.loads(urllib.request.urlopen(f"{url}/api/alerts").read())
            self.assertFalse([a for a in alerts["alerts"] if a["source"] == "run" and a["closed_at"] is None])  # closed
            for asset in ("/app.css", "/sign.js", "/app.js"):
                self.assertEqual(urllib.request.urlopen(f"{url}{asset}").status, 200)
            main = state["main"]
            self.assertIn("initial", json.loads(urllib.request.urlopen(f"{url}/api/dossier/{main}").read())["message"])
            page = urllib.request.urlopen(f"{url}/").read().decode()
            self.assertIn('src="/app.js"', page)
            forged = urllib.request.Request(f"{url}/api/admit", data=json.dumps({"payloadType": "x"}).encode(),
                                            headers={"Content-Type": "application/json"})
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


if __name__ == "__main__":
    unittest.main()


class Telemetry(unittest.TestCase):
    """The Run page's numbers: rates, error rate, quantiles and budget from cumulative Prometheus histograms."""

    def exposition(self, ok, errors, fast, slow):
        name = "http_server_request_duration_seconds"
        out = []
        for status, n, under in (("200", ok, fast), ("500", errors, 0)):
            labels = f'http_request_method="GET",http_route="/users/{{id}}",http_response_status_code="{status}"'
            out += [f'{name}_bucket{{{labels},le="0.1"}} {under}', f'{name}_bucket{{{labels},le="1"}} {n}',
                    f'{name}_bucket{{{labels},le="+Inf"}} {n}', f"{name}_count{{{labels}}} {n}"]
        return "\n".join(out) + f"\nsome_other_metric 3\n"

    def test_rates_errors_quantiles_budget_and_restarts(self):
        from surface.telemetry import Telemetry as T, declared_routes, quantile
        pages = iter([self.exposition(0, 0, 0, 0), self.exposition(900, 100, 800, 0), self.exposition(50, 0, 50, 0)])
        t = T(Path(tempfile.mkdtemp()) / "t.db", ["http://svc/metrics"], slo=0.999, fetch=lambda url: next(pages))
        t.scrape(now=1000)
        t.scrape(now=1100)
        report = t.report([("GET", "/users/{id}"), ("DELETE", "/orders/{id}")], window=600, now=1100)
        users = next(r for r in report["routes"] if r["name"] == "/users/{id}")
        self.assertEqual((users["requests"], users["rps"]), (1000, 10.0))
        self.assertAlmostEqual(users["error_rate"], 0.1)
        self.assertEqual(users["state"], "failing")
        self.assertEqual(users["why"], {"rule": "error_rate", "value": 0.1, "limit": 0.05})
        self.assertLess(report["fleet"]["budget"], 0)                    # 10 % errors against a 99.9 % objective
        self.assertEqual(users["p50"], 62.5)                              # 500th of 800 under 100 ms
        idle = next(r for r in report["routes"] if r["name"] == "/orders/{id}")
        self.assertEqual((idle["state"], idle["observed"], idle["declared"]), ("idle", False, True))
        t.scrape(now=1200)                                                # the service restarted: counters fell
        self.assertEqual(t.report(window=600, now=1200)["fleet"]["requests"], 1050)
        self.assertIsNone(quantile(0.5, {}))
        self.assertEqual(declared_routes('{"paths": {"/a": {"get": {}, "parameters": []}}}'), [("GET", "/a")])

    def test_a_silent_source_is_reported_never_zero(self):
        from surface.telemetry import Telemetry as T

        def down(url):
            raise OSError("connection refused")
        t = T(Path(tempfile.mkdtemp()) / "t.db", ["http://svc/metrics"], fetch=down)
        t.scrape(now=1000)
        report = t.report(window=600, now=1000)
        self.assertFalse(report["targets"][0]["up"])
        self.assertIsNone(report["fleet"]["error_rate"])


class Components(unittest.TestCase):
    """Not only APIs: workers, jobs, databases, external dependencies and processes, each with its own signals."""

    def test_every_kind_is_recognised_from_the_conventions(self):
        from surface.telemetry import Telemetry as T
        def page(n, last_success):
            h = lambda fam, labels, count: (f'{fam}_bucket{{{labels},le="0.1"}} {count}\n'
                                            f'{fam}_bucket{{{labels},le="+Inf"}} {count}\n{fam}_count{{{labels}}} {count}\n')
            return (h("messaging_process_duration_seconds", 'messaging_destination_name="orders"', n)
                    + h("messaging_process_duration_seconds", 'messaging_destination_name="orders",error_type="declined"', n // 10)
                    + 'messaging_queue_depth{messaging_destination_name="orders"} 7\n'
                    + h("db_client_operation_duration_seconds", 'db_system_name="postgresql",db_namespace="shop",db_operation_name="select"', n)
                    + h("http_client_request_duration_seconds", 'server_address="api.payments.example",http_response_status_code="503"', n // 5)
                    + f'job_last_success_timestamp_seconds{{job="daily-report"}} {last_success}\n'
                    + 'job_period_seconds{job="daily-report"} 60\njob_last_status{job="daily-report"} 1\n'
                    + f"process_cpu_seconds_total {n / 100}\nprocess_resident_memory_bytes 52428800\nprocess_start_time_seconds 100\n")
        pages = iter([page(0, 900), page(100, 1000)])
        t = T(Path(tempfile.mkdtemp()) / "t.db", ["http://svc:9000/metrics"], fetch=lambda url: next(pages))
        t.scrape(now=1000)
        t.scrape(now=1100)
        c = t.report(window=600, now=1300)["components"]
        worker = c["worker"][0]
        self.assertEqual((worker["name"], worker["backlog"], worker["requests"]), ("orders", 7, 110))
        self.assertAlmostEqual(worker["error_rate"], 10 / 110)
        self.assertEqual(c["database"][0]["name"], "postgresql/shop")
        self.assertEqual(c["dependency"][0]["name"], "api.payments.example")
        self.assertEqual(c["dependency"][0]["state"], "failing")
        job = c["job"][0]
        self.assertEqual((job["name"], job["state"]), ("daily-report", "degraded"))   # 300 s since success, period 60
        self.assertEqual(job["why"], {"rule": "job_late", "value": 300.0, "limit": 120.0})
        process = c["process"][0]
        self.assertEqual((process["name"], process["memory"], process["uptime"]), ("svc:9000", 52428800, 1200))
        self.assertAlmostEqual(process["cpu"], 0.01)
