"""Unit tests. No network access: loopback HTTP is the only integration target.

Run with:  py -3.13 -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from cyberkit.core.config import Config
from cyberkit.core.http import split_host_port
from cyberkit.core.models import Finding, Host, Result, Service
from cyberkit.core.module import resolve, run_modules
from cyberkit.core.scope import Scope, ScopeViolation
from cyberkit.core.store import dedupe_hosts, write_json
from cyberkit.report.html import render_html


class _Handler(BaseHTTPRequestHandler):
    """Serves a page with an embedded fake secret so the matcher has work to do."""

    def do_GET(self) -> None:
        if self.path == "/.env":
            body = b"DB_PASSWORD=9f2aQweRtz81LmX4pVd\nSTRIPE_KEY=sk_live_abcdef0123456789abcdef\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><body><a href='/next'>next</a><a href='http://example.com/x'>offsite</a></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "TestServer/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def log_message(self, *_args) -> None:
        return None


class ScopeTests(unittest.TestCase):
    def test_loopback_allowed_by_default(self) -> None:
        scope = Scope(cidr_entries=["127.0.0.0/8"])
        self.assertTrue(scope.permits("127.0.0.1"))
        self.assertTrue(scope.permits("127.0.0.1:8099"))
        self.assertFalse(scope.permits("10.0.0.1"))

    def test_wildcard_host_entry(self) -> None:
        scope = Scope(host_entries=["*.corp.internal"])
        self.assertTrue(scope.permits("api.corp.internal"))
        self.assertFalse(scope.permits("api.corp.external"))

    def test_require_raises_outside_scope(self) -> None:
        scope = Scope(cidr_entries=["10.0.0.0/8"])
        with self.assertRaises(ScopeViolation):
            scope.require("192.168.5.5")

    def test_filter_splits_allowed_and_denied(self) -> None:
        scope = Scope(cidr_entries=["127.0.0.0/8"])
        allowed, denied = scope.filter(["127.0.0.1", "8.8.8.8"])
        self.assertEqual(allowed, ["127.0.0.1"])
        self.assertEqual(len(denied), 1)

    def test_expand_targets_deduplicates(self) -> None:
        scope = Scope()
        self.assertEqual(scope.expand_targets(["a", "a", "b"]), ["a", "b"])

    def test_overly_wide_network_is_refused(self) -> None:
        with self.assertRaises(ScopeViolation):
            Scope().expand_targets(["10.0.0.0/8"])

    def test_scope_file_roundtrip(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text("# comment\ncidr 127.0.0.0/8\nhost lab.internal\n")
            scope = Scope.from_file(path)
            self.assertTrue(scope.permits("127.0.0.1"))
            self.assertTrue(scope.permits("lab.internal"))


class HelperTests(unittest.TestCase):
    def test_split_host_port_variants(self) -> None:
        self.assertEqual(split_host_port("example.com"), ("example.com", None))
        self.assertEqual(split_host_port("10.0.0.5:8443"), ("10.0.0.5", 8443))
        self.assertEqual(split_host_port("https://a.b:9443/x"), ("a.b", 9443))
        self.assertEqual(split_host_port("[::1]:8080"), ("::1", 8080))

    def test_dedupe_hosts_merges_services(self) -> None:
        a = Host(target="h", services=[Service(port=80, service="http")])
        b = Host(
            target="h",
            addresses=["10.0.0.1"],
            services=[Service(port=80, banner="HTTP/1.1 200"), Service(port=443)],
        )
        merged = dedupe_hosts([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].services), 2)
        self.assertEqual(merged[0].services[0].banner, "HTTP/1.1 200")

    def test_result_sorts_findings_by_severity(self) -> None:
        result = Result(started_at=0.0, finished_at=1.0)
        host = Host(target="h")
        host.findings = [
            Finding(title="low", severity="low"),
            Finding(title="crit", severity="critical"),
            Finding(title="med", severity="medium"),
        ]
        result.hosts = [host]
        self.assertEqual([f.title for f in result.findings], ["crit", "med", "low"])

    def test_json_export_handles_bytes(self) -> None:
        result = Result(started_at=0.0, finished_at=1.0, meta={"raw": b"\x00\x01binary"})
        payload = json.dumps(result.to_dict())
        self.assertIn("hosts", payload)


class ReportTests(unittest.TestCase):
    def test_html_escapes_and_includes_findings(self) -> None:
        result = Result(started_at=0.0, finished_at=1.0)
        host = Host(target="<script>x</script>")
        host.findings = [Finding(title="Test & finding", severity="high", remediation="Fix <it>")]
        result.hosts = [host]
        html = render_html(result)
        self.assertIn("Test &amp; finding", html)
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("Fix &lt;it&gt;", html)


class LoopbackIntegrationTests(unittest.TestCase):
    """Exercises the real modules against a throwaway local HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_http_module_finds_service_and_headers(self) -> None:
        config = Config(
            targets=[f"127.0.0.1:{self.port}"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=3.0,
        )
        result = asyncio.run(run_modules(config, resolve(["http"])))
        self.assertEqual(len(result.hosts), 1)
        host = result.hosts[0]
        self.assertEqual(host.services[0].port, self.port)
        titles = {f.title for f in host.findings}
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Technology version disclosed in server", titles)

    def test_secrets_module_flags_exposed_env(self) -> None:
        config = Config(
            targets=[f"127.0.0.1:{self.port}"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=3.0,
        )
        result = asyncio.run(run_modules(config, resolve(["secrets"])))
        titles = {f.title for f in result.hosts[0].findings}
        self.assertIn("Environment file exposed over HTTP", titles)
        self.assertIn("Stripe live key exposed", titles)

    def test_crawler_stays_on_origin(self) -> None:
        config = Config(
            targets=[f"127.0.0.1:{self.port}"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=3.0,
        )
        result = asyncio.run(run_modules(config, resolve(["crawl"])))
        self.assertEqual(len(result.hosts[0].services), 1)

    def test_portscan_finds_listening_port(self) -> None:
        config = Config(
            targets=[f"127.0.0.1:{self.port}"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=3.0,
        )
        result = asyncio.run(run_modules(config, resolve(["portscan"])))
        ports = [s.port for s in result.hosts[0].services]
        self.assertEqual(ports, [self.port])

    def test_out_of_scope_target_is_blocked(self) -> None:
        config = Config(
            targets=["203.0.113.1"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=1.0,
        )
        result = asyncio.run(run_modules(config, resolve(["http"])))
        self.assertTrue(result.errors)
        self.assertEqual(len(result.hosts), 0)

    def test_json_report_written(self) -> None:
        import tempfile
        from pathlib import Path

        config = Config(
            targets=[f"127.0.0.1:{self.port}"],
            scope=Scope(cidr_entries=["127.0.0.0/8"]),
            timeout=3.0,
        )
        result = asyncio.run(run_modules(config, resolve(["http"])))
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(result, Path(tmp) / "r.json")
            self.assertTrue(path.is_file())
            self.assertIn("counts", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
