"""MCP stdio server tests: routing, tool parsing with fake HTTP, offline FP check."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout

from tests import support

# --------------------------------------------------------------------------- #
# Inline fixtures — real-shaped upstream payloads (no network in tests)
# --------------------------------------------------------------------------- #
NVD_PAYLOAD = {
    "totalResults": 2,
    "resultsPerPage": 2,
    "startIndex": 0,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2025-06-01T00:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2025-05-02T17:55:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "es",
                        "value": "Descripcion en espanol que debe ser ignorada.",
                    },
                    {
                        "lang": "en",
                        "value": (
                            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding 2.16.0) "
                            "JNDI features used in configuration, log messages, and "
                            "parameters allow an attacker who controls log messages to "
                            "execute arbitrary code loaded from LDAP servers."
                        ),
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 6.0,
                        },
                        {
                            "source": "134c704f-9b21-4f2e-91b3-4a467353bcc2",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        },
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2017-1000350",
                "sourceIdentifier": "security@apache.org",
                "published": "2018-04-25T18:29:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "An older issue in Apache HttpClient allows a MITM attacker "
                            "to cause a denial of service."
                        ),
                    }
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 5.9,
                                "baseSeverity": "MEDIUM",
                            },
                        }
                    ]
                },
            }
        },
    ],
}

OSV_PAYLOAD = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Decompression of untrusted data in okhttp",
            "details": (
                "okhttp's BrotliInputStream accepts compressed data from an untrusted "
                "peer without validating the decoded size.\n"
                "Second line of details."
            ),
            "aliases": ["CVE-2021-0341", "GHSA-w32h-j624-486x"],
            "published": "2021-08-05T00:00:00Z",
            "modified": "2023-09-05T00:00:00Z",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
            ],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "com.squareup.okhttp3:okhttp",
                    },
                    "versions": [
                        "3.12.0",
                        "3.12.1",
                        "3.12.2",
                        "3.12.3",
                        "3.12.4",
                        "3.12.5",
                        "3.12.6",
                        "3.12.7",
                        "3.12.8",
                        "3.12.9",
                        "3.12.10",
                        "3.12.11",
                    ],
                }
            ],
        },
        {
            "id": "OSV-2020-123",
            "details": "Details-only record without a summary field.\nExtra line ignored.",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "com.squareup.okhttp3:okhttp",
                    }
                }
            ],
        },
    ]
}

KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2025-05-19",
    "dateReleased": "2025-05-19T06:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-20",
            "dueDate": "2022-01-10",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": (
                "Apache Log4j2 contains a remote code execution vulnerability via JNDI "
                "lookups in logged messages."
            ),
            "requiredAction": "Apply updates per vendor instructions.",
            "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
        {
            "cveID": "CVE-2023-23306",
            "vendorProject": "Samsung",
            "product": "Mobile Devices",
            "vulnerabilityName": "Samsung Mobile Devices Out-of-Bounds Write",
            "dateAdded": "2023-03-24",
            "dueDate": "2023-04-14",
            "knownRansomwareCampaignUse": "Unknown",
            "shortDescription": "A buffer overflow in Samsung baseband processors.",
            "requiredAction": "Apply vendor updates.",
            "notes": "",
        },
    ],
}


class MCPTestCase(unittest.TestCase):
    """Shared helpers: module load, fake-HTTP injection, tools/call driving."""

    @classmethod
    def setUpClass(cls):
        cls.mcp = support.load_mcp_intel_module()

    def _inject(self, name, fake):
        """Replace a module-level HTTP seam for one test (restored on cleanup)."""
        original = getattr(self.mcp, name)
        setattr(self.mcp, name, fake)
        self.addCleanup(setattr, self.mcp, name, original)

    @staticmethod
    def _fake_get(payload=None, error=None):
        calls = []

        def fake(url, timeout=None, headers=None):
            calls.append({"url": url, "timeout": timeout})
            if error is not None:
                raise error
            if isinstance(payload, Exception):
                raise payload
            return json.dumps(payload).encode("utf-8")

        fake.calls = calls
        return fake

    @staticmethod
    def _fake_post(payload=None, error=None):
        calls = []

        def fake(url, body, timeout=None, headers=None):
            calls.append({"url": url, "payload": body, "timeout": timeout})
            if error is not None:
                raise error
            if isinstance(payload, Exception):
                raise payload
            return json.dumps(payload).encode("utf-8")

        fake.calls = calls
        return fake

    def _call(self, name, arguments):
        response = self.mcp.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        self.assertIsInstance(response, dict)
        self.assertIn("result", response)
        return response["result"]

    def _text(self, result):
        self.assertIn("content", result)
        self.assertEqual(result["content"][0]["type"], "text")
        return result["content"][0]["text"]


# --------------------------------------------------------------------------- #
# Message routing
# --------------------------------------------------------------------------- #
class MessageRoutingTests(MCPTestCase):
    def test_initialize_returns_required_result(self):
        response = self.mcp.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            }
        )
        result = response["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertEqual(result["capabilities"], {"tools": {}})
        self.assertEqual(result["serverInfo"]["name"], "depi-bug-intel")
        self.assertEqual(result["serverInfo"]["version"], "1.0.0")

    def test_initialize_echoes_client_protocol_version(self):
        response = self.mcp.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }
        )
        self.assertEqual(response["result"]["protocolVersion"], "2024-11-05")

    def test_initialize_without_params_falls_back_to_default(self):
        response = self.mcp.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(
            response["result"]["protocolVersion"], self.mcp.DEFAULT_PROTOCOL_VERSION
        )

    def test_initialized_notification_produces_no_response(self):
        response = self.mcp.handle_message(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        self.assertIsNone(response)

    def test_notification_without_id_is_never_answered(self):
        response = self.mcp.handle_message(
            {"jsonrpc": "2.0", "method": "some/unknown-notification"}
        )
        self.assertIsNone(response)

    def test_tools_list_returns_four_schema_tools(self):
        response = self.mcp.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = response["result"]["tools"]
        names = [tool["name"] for tool in tools]
        self.assertEqual(
            names,
            ["search_cves", "query_osv", "known_exploited", "false_positive_check"],
        )
        for tool in tools:
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertIsInstance(schema["properties"], dict)
            self.assertTrue(tool["description"])

    def test_tools_list_ecosystem_enum(self):
        response = self.mcp.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        ecosystem = tools["query_osv"]["inputSchema"]["properties"]["ecosystem"]
        self.assertEqual(ecosystem["enum"], ["Android", "Maven", "npm", "PyPI", "Go"])
        self.assertEqual(ecosystem["default"], "Android")
        self.assertEqual(tools["query_osv"]["inputSchema"]["required"], ["package"])
        self.assertEqual(tools["search_cves"]["inputSchema"]["required"], ["keyword"])

    def test_ping_returns_empty_result(self):
        response = self.mcp.handle_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        self.assertEqual(response, {"jsonrpc": "2.0", "id": 3, "result": {}})

    def test_unknown_method_is_method_not_found(self):
        response = self.mcp.handle_message(
            {"jsonrpc": "2.0", "id": 4, "method": "resources/list"}
        )
        self.assertEqual(response["error"]["code"], -32601)
        self.assertEqual(response["id"], 4)

    def test_malformed_json_is_parse_error(self):
        raw = self.mcp.process_line("{oops")
        response = json.loads(raw)
        self.assertEqual(response["error"]["code"], -32700)
        self.assertIsNone(response["id"])

    def test_blank_line_produces_no_response(self):
        self.assertIsNone(self.mcp.process_line("   \n"))

    def test_non_object_message_is_invalid_request(self):
        response = self.mcp.handle_message(42)
        self.assertEqual(response["error"]["code"], -32600)

    def test_request_without_method_is_invalid_request(self):
        response = self.mcp.handle_message({"jsonrpc": "2.0", "id": 5})
        self.assertEqual(response["error"]["code"], -32600)

    def test_batch_is_answered_as_an_array(self):
        response = self.mcp.handle_message(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "no/such-method"},
            ]
        )
        self.assertIsInstance(response, list)
        self.assertEqual(len(response), 2)
        by_id = {entry["id"]: entry for entry in response}
        self.assertEqual(by_id[1]["result"], {})
        self.assertEqual(by_id[2]["error"]["code"], -32601)

    def test_empty_batch_is_rejected_cleanly(self):
        response = self.mcp.handle_message([])
        self.assertEqual(response["error"]["code"], -32600)

    def test_all_notification_batch_answers_nothing(self):
        response = self.mcp.handle_message(
            [{"jsonrpc": "2.0", "method": "notifications/initialized"}]
        )
        self.assertIsNone(response)

    def test_tools_call_unknown_tool_is_iserror_result(self):
        result = self._call("no_such_tool", {})
        self.assertTrue(result["isError"])
        self.assertIn("Unknown tool", self._text(result))

    def test_tools_call_without_name_is_invalid_params(self):
        response = self.mcp.handle_message(
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}}
        )
        self.assertEqual(response["error"]["code"], -32602)

    def test_tools_call_non_object_arguments_is_invalid_params(self):
        response = self.mcp.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "search_cves", "arguments": "nope"},
            }
        )
        self.assertEqual(response["error"]["code"], -32602)


# --------------------------------------------------------------------------- #
# stdio loop (newline-delimited JSON, graceful EOF)
# --------------------------------------------------------------------------- #
class StdioLoopTests(MCPTestCase):
    def test_serve_converses_over_lines_and_exits_on_eof(self):
        stdin = io.StringIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            )
            + "\n\n   \n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            + "\n"
        )
        stdout = io.StringIO()
        with redirect_stderr(io.StringIO()):
            code = self.mcp.serve(stdin, stdout)
        self.assertEqual(code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        first, second = json.loads(lines[0]), json.loads(lines[1])
        self.assertEqual(first["result"]["serverInfo"]["name"], "depi-bug-intel")
        self.assertEqual(len(second["result"]["tools"]), 4)

    def test_serve_exits_cleanly_on_immediate_eof(self):
        stdout = io.StringIO()
        with redirect_stderr(io.StringIO()):
            code = self.mcp.serve(io.StringIO(""), stdout)
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")


# --------------------------------------------------------------------------- #
# search_cves (NVD)
# --------------------------------------------------------------------------- #
class SearchCvesTests(MCPTestCase):
    def test_parses_nvd_fixture(self):
        self._inject("http_get", self._fake_get(NVD_PAYLOAD))
        result = self._call("search_cves", {"keyword": "log4j", "limit": 5})
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("CVE-2021-44228", text)
        self.assertIn("CRITICAL 10.0", text)
        self.assertIn("JNDI features", text)
        self.assertIn("CVE-2017-1000350", text)
        self.assertIn("MEDIUM 5.9", text)
        # Non-English description must not win over the English one.
        self.assertNotIn("Descripcion en espanol", text)

    def test_request_url_shape_and_timeout(self):
        fake = self._fake_get(NVD_PAYLOAD)
        self._inject("http_get", fake)
        self._call("search_cves", {"keyword": "android webview", "limit": 5})
        self.assertEqual(len(fake.calls), 1)
        url = fake.calls[0]["url"]
        self.assertTrue(url.startswith(self.mcp.NVD_CVE_URL))
        self.assertIn("keywordSearch=android%20webview", url)
        self.assertIn("resultsPerPage=5", url)
        self.assertEqual(fake.calls[0]["timeout"], self.mcp.REQUEST_TIMEOUT)
        self.assertLessEqual(self.mcp.REQUEST_TIMEOUT, 20)

    def test_limit_is_clamped(self):
        fake = self._fake_get(NVD_PAYLOAD)
        self._inject("http_get", fake)
        self._call("search_cves", {"keyword": "x", "limit": 5000})
        self.assertIn("resultsPerPage=100", fake.calls[0]["url"])

    def test_missing_keyword_is_an_error(self):
        self._inject("http_get", self._fake_get(NVD_PAYLOAD))
        result = self._call("search_cves", {"keyword": "  "})
        self.assertTrue(result["isError"])
        self.assertIn("keyword", self._text(result))

    def test_non_numeric_limit_is_an_error(self):
        result = self._call("search_cves", {"keyword": "x", "limit": "many"})
        self.assertTrue(result["isError"])
        self.assertIn("limit", self._text(result))

    def test_unreachable_network_is_a_readable_error(self):
        self._inject(
            "http_get",
            self._fake_get(error=urllib.error.URLError("Connection refused")),
        )
        result = self._call("search_cves", {"keyword": "log4j"})
        self.assertTrue(result["isError"])
        text = self._text(result)
        self.assertIn("network unavailable", text)
        self.assertIn(self.mcp.NVD_HOST, text)
        self.assertNotIn("Traceback", text)

    def test_http_error_status_is_a_readable_error(self):
        error = urllib.error.HTTPError(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            503,
            "Service Unavailable",
            None,
            None,
        )
        self._inject("http_get", self._fake_get(error=error))
        result = self._call("search_cves", {"keyword": "log4j"})
        self.assertTrue(result["isError"])
        text = self._text(result)
        self.assertIn("HTTP 503", text)
        self.assertNotIn("Traceback", text)

    def test_invalid_json_body_is_a_readable_error(self):
        def broken(url, timeout=None, headers=None):
            return b"<html>gateway error</html>"

        self._inject("http_get", broken)
        result = self._call("search_cves", {"keyword": "log4j"})
        self.assertTrue(result["isError"])
        self.assertIn("invalid JSON", self._text(result))


# --------------------------------------------------------------------------- #
# query_osv (OSV)
# --------------------------------------------------------------------------- #
class QueryOsvTests(MCPTestCase):
    def test_parses_osv_fixture(self):
        self._inject("http_post_json", self._fake_post(OSV_PAYLOAD))
        result = self._call(
            "query_osv",
            {
                "package": "com.squareup.okhttp3:okhttp",
                "ecosystem": "Maven",
                "version": "3.12.0",
            },
        )
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("GHSA-xxxx-yyyy-zzzz", text)
        self.assertIn("[HIGH / CVSS:3.1/AV:N", text)
        self.assertIn("CVE-2021-0341", text)
        self.assertIn("versions: 3.12.0, 3.12.1", text)
        self.assertIn("+2 more", text)  # 12 versions, cap is 10
        self.assertIn("OSV-2020-123", text)
        self.assertIn("Details-only record without a summary", text)
        self.assertIn("severity n/a", text)

    def test_post_payload_shape(self):
        fake = self._fake_post(OSV_PAYLOAD)
        self._inject("http_post_json", fake)
        self._call(
            "query_osv",
            {"package": "okhttp", "ecosystem": "Android", "version": "2.7.5"},
        )
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["url"], self.mcp.OSV_QUERY_URL)
        self.assertEqual(
            fake.calls[0]["payload"],
            {
                "package": {"name": "okhttp", "ecosystem": "Android"},
                "version": "2.7.5",
            },
        )
        self.assertEqual(fake.calls[0]["timeout"], self.mcp.REQUEST_TIMEOUT)

    def test_null_version_is_omitted_from_payload(self):
        fake = self._fake_post({"vulns": []})
        self._inject("http_post_json", fake)
        result = self._call("query_osv", {"package": "okhttp"})
        self.assertFalse(result["isError"])
        self.assertNotIn("version", fake.calls[0]["payload"])
        self.assertEqual(fake.calls[0]["payload"]["package"]["ecosystem"], "Android")
        self.assertIn("0 known vulnerabilities", self._text(result))

    def test_invalid_ecosystem_is_rejected(self):
        self._inject("http_post_json", self._fake_post(OSV_PAYLOAD))
        result = self._call("query_osv", {"package": "x", "ecosystem": "RubyGems"})
        self.assertTrue(result["isError"])
        text = self._text(result)
        self.assertIn("Android", text)
        self.assertIn("PyPI", text)

    def test_missing_package_is_an_error(self):
        result = self._call("query_osv", {"package": ""})
        self.assertTrue(result["isError"])
        self.assertIn("package", self._text(result))

    def test_unreachable_network_is_a_readable_error(self):
        self._inject(
            "http_post_json",
            self._fake_post(error=urllib.error.URLError("timed out")),
        )
        result = self._call("query_osv", {"package": "okhttp"})
        self.assertTrue(result["isError"])
        text = self._text(result)
        self.assertIn("network unavailable", text)
        self.assertIn(self.mcp.OSV_HOST, text)
        self.assertNotIn("Traceback", text)


# --------------------------------------------------------------------------- #
# known_exploited (CISA KEV)
# --------------------------------------------------------------------------- #
class KnownExploitedTests(MCPTestCase):
    def test_present_cve_reports_due_date_and_ransomware_flag(self):
        self._inject("http_get", self._fake_get(KEV_PAYLOAD))
        result = self._call("known_exploited", {"cve_id": "CVE-2021-44228"})
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("IS in the CISA KEV", text)
        self.assertIn("dueDate: 2022-01-10", text)
        self.assertIn("ransomware: Known", text)
        self.assertIn("Apache/Log4j2", text)
        self.assertIn("dateAdded: 2021-12-20", text)

    def test_ransomware_unknown_flag_is_reported(self):
        self._inject("http_get", self._fake_get(KEV_PAYLOAD))
        result = self._call("known_exploited", {"cve_id": "CVE-2023-23306"})
        self.assertFalse(result["isError"])
        self.assertIn("ransomware: Unknown", self._text(result))

    def test_lowercase_cve_id_is_normalised(self):
        self._inject("http_get", self._fake_get(KEV_PAYLOAD))
        result = self._call("known_exploited", {"cve_id": "cve-2021-44228"})
        self.assertFalse(result["isError"])
        self.assertIn("IS in the CISA KEV", self._text(result))

    def test_absent_cve_is_a_clear_negative_result(self):
        self._inject("http_get", self._fake_get(KEV_PAYLOAD))
        result = self._call("known_exploited", {"cve_id": "CVE-2019-9999"})
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("is NOT in the CISA", text)
        self.assertIn("checked 2 entries", text)

    def test_malformed_cve_id_is_rejected(self):
        result = self._call("known_exploited", {"cve_id": "log4shell"})
        self.assertTrue(result["isError"])
        self.assertIn("CVE-", self._text(result))

    def test_unreachable_network_is_a_readable_error(self):
        self._inject(
            "http_get",
            self._fake_get(error=urllib.error.URLError("Name or service not known")),
        )
        result = self._call("known_exploited", {"cve_id": "CVE-2021-44228"})
        self.assertTrue(result["isError"])
        text = self._text(result)
        self.assertIn("network unavailable", text)
        self.assertNotIn("Traceback", text)


# --------------------------------------------------------------------------- #
# false_positive_check (offline, reuses scripts/findings.py parser)
# --------------------------------------------------------------------------- #
class FalsePositiveCheckTests(MCPTestCase):
    def test_defaults_to_shipped_fp_database(self):
        expected = os.path.join(support.ROOT_DIR, "memory", "FALSE_POSITIVE_DB.md")
        self.assertEqual(self.mcp.FP_DB_PATH, expected)
        # The real database ships 17 structured signature rows.
        from scripts import findings

        self.assertGreaterEqual(len(findings.FalsePositiveDB(expected).entries()), 17)

    def test_known_signature_is_flagged(self):
        result = self._call("false_positive_check", {"signature_hash": "3a8f1b20"})
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("IS a known false positive", text)
        self.assertIn("STORAGE", text)
        self.assertIn("6_fp_db_cleared FAILS", text)

    def test_unknown_signature_is_clear(self):
        result = self._call("false_positive_check", {"signature_hash": "deadbeef"})
        self.assertFalse(result["isError"])
        text = self._text(result)
        self.assertIn("NOT in the false-positive database", text)
        self.assertIn("6_fp_db_cleared passes", text)

    def test_malformed_hash_is_rejected(self):
        for bad in ("3a8f", "zzzzzzzz", ""):
            with self.subTest(hash=bad):
                result = self._call("false_positive_check", {"signature_hash": bad})
                self.assertTrue(result["isError"])
                self.assertIn("8 hex", self._text(result))

    def test_path_seam_uses_an_isolated_database(self):
        with support.temp_dir() as directory:
            path = os.path.join(directory, "FALSE_POSITIVE_DB.md")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    "# FP DB\n\n"
                    "| Signature Hash | Category | Pattern Description | Reason for FP |\n"
                    "|---|---|---|---|\n"
                    "| `deadbeef` | CODE | temp row | temp reason |\n"
                )
            self._inject("FP_DB_PATH", path)
            known = self._call("false_positive_check", {"signature_hash": "deadbeef"})
            self.assertFalse(known["isError"])
            self.assertIn("IS a known false positive", self._text(known))
            clear = self._call("false_positive_check", {"signature_hash": "3a8f1b20"})
            self.assertFalse(clear["isError"])
            self.assertIn("NOT in the false-positive database", self._text(clear))

    def test_missing_database_is_a_readable_error(self):
        self._inject("FP_DB_PATH", os.path.join(os.sep, "nonexistent", "fp.md"))
        result = self._call("false_positive_check", {"signature_hash": "3a8f1b20"})
        self.assertTrue(result["isError"])
        self.assertIn("not found", self._text(result))


# --------------------------------------------------------------------------- #
# --self-test (offline; exercises routing + fake-backend tools/call)
# --------------------------------------------------------------------------- #
class SelfTestTests(MCPTestCase):
    def test_self_test_flag_passes_in_process(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(io.StringIO()):
            code = self.mcp.main(["--self-test"])
        output = buffer.getvalue()
        self.assertEqual(code, 0, output)
        self.assertIn("SELF-TEST PASS", output)
        self.assertIn("[PASS] tools/list exposes 4 schema'd tools", output)

    def test_self_test_runs_the_real_script_without_network(self):
        script = os.path.join(support.ROOT_DIR, "scripts", "mcp_intel_server.py")
        completed = subprocess.run(
            [sys.executable, script, "--self-test"],
            cwd=support.ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("SELF-TEST PASS", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)
        for line in completed.stdout.splitlines():
            if line.startswith("["):
                self.assertTrue(
                    line.startswith("[PASS]") or line.startswith("[FAIL]"), line
                )


if __name__ == "__main__":
    unittest.main()
