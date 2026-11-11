#!/usr/bin/env python3
"""
MCP stdio server: vulnerability intelligence for `mcp-bug-intel-agent`.

Implements the Model Context Protocol over stdin/stdout using newline-delimited
JSON-RPC 2.0 messages (one message per line, no Content-Length headers — the
MCP stdio transport framing).  stdout carries protocol messages only; every
diagnostic goes to stderr.

Tools (all read-only, no device / emulator / target-network access — the hard
rule of AGENTS.md §2.4 for `mcp-bug-intel-agent`):

* ``search_cves``        -> NVD CVE API 2.0 keyword search (read-only GET).
* ``query_osv``          -> OSV ``/v1/query`` package vulnerability lookup (POST).
* ``known_exploited``    -> CISA Known Exploited Vulnerabilities catalog (GET).
* ``false_positive_check`` -> offline lookup in ``memory/FALSE_POSITIVE_DB.md``
  reusing the structured parser from ``scripts/findings.py`` (imported, never
  re-implemented).

Design rules
------------
* Standard library only (Python 3.14, no third-party dependencies).
* ``http_get`` / ``http_post_json`` are module-level seams so tests can inject
  fake backends without touching the network.
* Every outbound call has a hard timeout (``REQUEST_TIMEOUT`` <= 20 s) and
  degrades to an explicit, readable ``isError`` result — never a traceback.
* ``--self-test`` exercises routing (tools/list) plus a fake-backend
  tools/call end-to-end without any network access.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

# Reuse the single structured FP parser (never write a second one).
from scripts.findings import FalsePositiveDB  # noqa: E402  (path setup must precede it)

SERVER_NAME = "depi-bug-intel"
SERVER_VERSION = "1.0.0"
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

# Hard ceiling for every outbound call; the environment's network is unreliable.
REQUEST_TIMEOUT = 20  # seconds

USER_AGENT = f"{SERVER_NAME}/{SERVER_VERSION} (read-only MCP vulnerability intel)"

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_HOST = "services.nvd.nist.gov"
OSV_HOST = "api.osv.dev"
CISA_HOST = "www.cisa.gov"

OSV_ECOSYSTEMS: Tuple[str, ...] = ("Android", "Maven", "npm", "PyPI", "Go")

FP_DB_PATH = os.path.join(ROOT_DIR, "memory", "FALSE_POSITIVE_DB.md")

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Readability ceilings for generated text.
_DESCRIPTION_LIMIT = 240
_SUMMARY_LIMIT = 160
_OSV_MAX_ROWS = 20
_OSV_MAX_VERSIONS = 10


class ToolError(Exception):
    """Readable, client-safe tool failure.  Never surfaced as a traceback."""


# --------------------------------------------------------------------------- #
# Diagnostics (stderr only — stdout is reserved for protocol messages)
# --------------------------------------------------------------------------- #
def log(message: str) -> None:
    print(f"[mcp-intel] {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# HTTP seams — tests replace these module-level functions with fakes
# --------------------------------------------------------------------------- #
def http_get(url: str, timeout: float = REQUEST_TIMEOUT, headers: Optional[Dict[str, str]] = None) -> bytes:
    """GET ``url`` and return the raw body.  Module-level seam for tests."""
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        merged.update(headers)
    request = urllib.request.Request(url, headers=merged)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def http_post_json(
    url: str,
    payload: Any,
    timeout: float = REQUEST_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> bytes:
    """POST ``payload`` as JSON to ``url`` and return the raw body.  Test seam."""
    merged = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if headers:
        merged.update(headers)
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=merged, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _json_body(raw: Any) -> Any:
    """Decode an HTTP body (bytes/str) to JSON; accept an already-parsed object."""
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        raise ToolError(f"HTTP helper returned an unexpected type ({type(raw).__name__})")
    return json.loads(raw)


def _network_call(tool: str, host: str, func: Callable[[], Any]) -> Any:
    """Run ``func`` and convert every transport failure into a ToolError."""
    try:
        return func()
    except ToolError:
        raise
    except urllib.error.HTTPError as exc:
        raise ToolError(f"{tool}: {host} answered HTTP {exc.code} ({exc.reason})") from exc
    except urllib.error.URLError as exc:
        raise ToolError(
            f"{tool}: network unavailable — could not reach {host} "
            f"within {REQUEST_TIMEOUT}s ({exc.reason})"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"{tool}: {host} returned invalid JSON ({exc})") from exc
    except OSError as exc:
        raise ToolError(f"{tool}: network error contacting {host}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Payload parsers (pure functions — unit-tested with inline fixtures)
# --------------------------------------------------------------------------- #
def _shorten(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _nvd_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            return str(entry.get("value") or "").strip()
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("value"):
            return str(entry["value"]).strip()
    return "(no description)"


def _nvd_score(metrics: Dict[str, Any]) -> Tuple[Optional[float], str]:
    """Return (baseScore, severity) preferring CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("type") == "Primary":
                chosen = entry
                break
        if chosen is None and isinstance(entries[0], dict):
            chosen = entries[0]
        if chosen is None:
            continue
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore", chosen.get("baseScore"))
        severity = data.get("baseSeverity") or chosen.get("baseSeverity") or ""
        try:
            score_value: Optional[float] = float(score)
        except (TypeError, ValueError):
            score_value = None
        return score_value, str(severity).upper().strip()
    return None, ""


def parse_nvd_response(payload: Any, keyword: str, limit: int) -> str:
    """Format an NVD CVE 2.0 response as readable text."""
    if not isinstance(payload, dict):
        raise ToolError(
            f"search_cves: NVD returned an unexpected payload ({type(payload).__name__})"
        )
    vulnerabilities = payload.get("vulnerabilities") or []
    total = payload.get("totalResults")
    total_text = str(total) if isinstance(total, int) else "?"
    header = (
        f'NVD keyword search "{keyword}" — showing {min(len(vulnerabilities), limit)} '
        f"of {total_text} result(s) (limit {limit})"
    )
    if not vulnerabilities:
        return header + "\nNo CVEs matched that keyword."
    lines = [header]
    for item in vulnerabilities[:limit]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "CVE-????-????")
        score, severity = _nvd_score(cve.get("metrics") or {})
        if score is not None:
            rating = f"{severity or 'CVSS'} {score}"
        else:
            rating = severity or "no CVSS score"
        description = _shorten(_nvd_description(cve), _DESCRIPTION_LIMIT)
        lines.append(f"- {cve_id} [{rating}] {description}")
    return "\n".join(lines)


def _osv_cvss(severity_entries: Any) -> str:
    if not isinstance(severity_entries, list):
        return ""
    for entry in severity_entries:
        if isinstance(entry, dict) and entry.get("score"):
            return str(entry["score"]).strip()
    return ""


def _osv_versions(vuln: Dict[str, Any]) -> List[str]:
    versions: List[str] = []
    seen = set()
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for version in affected.get("versions") or []:
            text = str(version)
            if text not in seen:
                seen.add(text)
                versions.append(text)
    if len(versions) > _OSV_MAX_VERSIONS:
        return versions[:_OSV_MAX_VERSIONS] + [f"+{len(versions) - _OSV_MAX_VERSIONS} more"]
    return versions


def parse_osv_response(payload: Any, package: str, ecosystem: str, version: Optional[str]) -> str:
    """Format an OSV /v1/query response as readable text."""
    if not isinstance(payload, dict):
        raise ToolError(
            f"query_osv: OSV returned an unexpected payload ({type(payload).__name__})"
        )
    vulns = payload.get("vulns") or []
    scope = f"{ecosystem}:{package}" + (f" @ {version}" if version else "")
    if not vulns:
        suffix = " for the supplied version" if version else ""
        return f"OSV query {scope}: 0 known vulnerabilities{suffix}."
    lines = [f"OSV query {scope}: {len(vulns)} result(s)"]
    for vuln in vulns[:_OSV_MAX_ROWS]:
        if not isinstance(vuln, dict):
            continue
        vid = str(vuln.get("id") or "(no id)")
        summary = str(vuln.get("summary") or "").strip()
        if not summary:
            details = str(vuln.get("details") or "").strip()
            summary = details.splitlines()[0] if details else "(no summary)"
        severity_bits: List[str] = []
        database_specific = vuln.get("database_specific")
        if isinstance(database_specific, dict) and database_specific.get("severity"):
            severity_bits.append(str(database_specific["severity"]).upper())
        cvss = _osv_cvss(vuln.get("severity"))
        if cvss:
            severity_bits.append(cvss)
        severity_text = " / ".join(severity_bits) or "severity n/a"
        extras: List[str] = []
        versions = _osv_versions(vuln)
        if versions:
            extras.append("versions: " + ", ".join(versions))
        cve_aliases = [
            str(alias)
            for alias in (vuln.get("aliases") or [])
            if str(alias).upper().startswith("CVE-")
        ]
        if cve_aliases:
            extras.append("cve: " + ", ".join(cve_aliases[:5]))
        line = f"- {vid} [{severity_text}] {_shorten(summary, _SUMMARY_LIMIT)}"
        if extras:
            line += "\n    " + " | ".join(extras)
        lines.append(line)
    if len(vulns) > _OSV_MAX_ROWS:
        lines.append(f"... {len(vulns) - _OSV_MAX_ROWS} more not shown")
    return "\n".join(lines)


def parse_kev_response(payload: Any, cve_id: str) -> str:
    """Format a CISA KEV catalog lookup as readable text."""
    if not isinstance(payload, dict):
        raise ToolError(
            f"known_exploited: CISA KEV feed returned an unexpected payload ({type(payload).__name__})"
        )
    entries = payload.get("vulnerabilities") or []
    catalog = str(payload.get("catalogVersion") or "unknown version")
    match: Optional[Dict[str, Any]] = None
    for entry in entries:
        if isinstance(entry, dict) and str(entry.get("cveID") or "").upper() == cve_id:
            match = entry
            break
    if match is None:
        return (
            f"{cve_id} is NOT in the CISA Known Exploited Vulnerabilities catalog "
            f"(checked {len(entries)} entries, catalog {catalog})."
        )
    count = payload.get("count")
    count_text = str(count) if isinstance(count, int) else str(len(entries))
    lines = [
        f"{cve_id} IS in the CISA KEV catalog (catalog {catalog}, {count_text} entries):",
        f"  name: {match.get('vulnerabilityName') or '-'}",
        f"  vendor/product: {match.get('vendorProject') or '-'}/{match.get('product') or '-'}",
        f"  dateAdded: {match.get('dateAdded') or '-'}",
        f"  dueDate: {match.get('dueDate') or '-'}",
        f"  ransomware: {match.get('knownRansomwareCampaignUse') or '-'}",
    ]
    description = str(match.get("shortDescription") or "").strip()
    if description:
        lines.append(f"  description: {_shorten(description, _DESCRIPTION_LIMIT)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
def tool_search_cves(arguments: Dict[str, Any]) -> str:
    keyword = str(arguments.get("keyword") or "").strip()
    if not keyword:
        raise ToolError("search_cves requires a non-empty 'keyword' string")
    raw_limit = arguments.get("limit", 10)
    try:
        limit = 10 if raw_limit is None else int(raw_limit)
    except (TypeError, ValueError):
        raise ToolError("search_cves 'limit' must be an integer between 1 and 100") from None
    limit = max(1, min(limit, 100))
    query = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": limit},
        quote_via=urllib.parse.quote,
    )
    url = f"{NVD_CVE_URL}?{query}"
    payload = _network_call(
        "search_cves",
        NVD_HOST,
        lambda: _json_body(http_get(url, timeout=REQUEST_TIMEOUT)),
    )
    return parse_nvd_response(payload, keyword, limit)


def tool_query_osv(arguments: Dict[str, Any]) -> str:
    package = str(arguments.get("package") or "").strip()
    if not package:
        raise ToolError("query_osv requires a non-empty 'package' name")
    ecosystem = arguments.get("ecosystem") or "Android"
    if ecosystem not in OSV_ECOSYSTEMS:
        raise ToolError(
            f"query_osv 'ecosystem' must be one of: {', '.join(OSV_ECOSYSTEMS)} "
            f"(got {ecosystem!r})"
        )
    version = arguments.get("version")
    if version is not None and not isinstance(version, str):
        raise ToolError("query_osv 'version' must be a string or null")
    version = version or None
    request_payload: Dict[str, Any] = {
        "package": {"name": package, "ecosystem": ecosystem}
    }
    if version:
        request_payload["version"] = version
    payload = _network_call(
        "query_osv",
        OSV_HOST,
        lambda: _json_body(
            http_post_json(OSV_QUERY_URL, request_payload, timeout=REQUEST_TIMEOUT)
        ),
    )
    return parse_osv_response(payload, package, ecosystem, version)


def tool_known_exploited(arguments: Dict[str, Any]) -> str:
    cve_id = str(arguments.get("cve_id") or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ToolError(
            "known_exploited requires 'cve_id' like CVE-2021-44228 "
            f"(got {cve_id or 'nothing'})"
        )
    payload = _network_call(
        "known_exploited",
        CISA_HOST,
        lambda: _json_body(http_get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)),
    )
    return parse_kev_response(payload, cve_id)


def tool_false_positive_check(arguments: Dict[str, Any]) -> str:
    signature = str(arguments.get("signature_hash") or "").strip().lower().strip("`")
    if not re.fullmatch(r"[0-9a-f]{8}", signature):
        raise ToolError(
            "false_positive_check requires 'signature_hash' as exactly 8 hex characters "
            "(SHA256(category:identifier:signal)[:8])"
        )
    if not os.path.isfile(FP_DB_PATH):
        raise ToolError(f"false_positive_check: FP database not found at {FP_DB_PATH}")
    db = FalsePositiveDB(FP_DB_PATH)
    entry = db.lookup(signature)
    total = len(db.entries())
    if entry:
        return "\n".join(
            [
                f"{signature} IS a known false positive "
                f"(memory/FALSE_POSITIVE_DB.md, {total} signatures).",
                f"  category: {entry.get('category', '')}",
                f"  pattern: {entry.get('description', '')}",
                f"  reason: {entry.get('reason', '')}",
                "  Hard FP Gate check 6_fp_db_cleared FAILS -> "
                "downgrade the finding to INFORMATIONAL.",
            ]
        )
    return (
        f"{signature} is NOT in the false-positive database ({total} signatures checked). "
        "Hard FP Gate check 6_fp_db_cleared passes; the other six gate questions still apply."
    )


TOOL_FUNCTIONS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "search_cves": tool_search_cves,
    "query_osv": tool_query_osv,
    "known_exploited": tool_known_exploited,
    "false_positive_check": tool_false_positive_check,
}

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "search_cves",
        "description": (
            "Search the NVD CVE catalog (API 2.0) by keyword. Read-only public "
            "API lookup: no device, emulator or target network is ever touched. "
            "Returns CVE id, CVSS base score/severity and a short description."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Free-text keyword, e.g. 'log4j' or 'okhttp'.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Maximum number of CVEs to return (1-100).",
                },
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "query_osv",
        "description": (
            "Query the OSV vulnerability database for a package. Returns "
            "vulnerability id, summary, affected versions and severity/CVSS "
            "when present. Read-only; never contacts the target."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name, e.g. 'com.squareup.okhttp3:okhttp'.",
                },
                "ecosystem": {
                    "type": "string",
                    "enum": list(OSV_ECOSYSTEMS),
                    "default": "Android",
                    "description": "Package ecosystem the name belongs to.",
                },
                "version": {
                    "type": ["string", "null"],
                    "default": None,
                    "description": "Optional version to check; null matches any.",
                },
            },
            "required": ["package"],
        },
    },
    {
        "name": "known_exploited",
        "description": (
            "Check whether a CVE appears in the CISA Known Exploited "
            "Vulnerabilities (KEV) catalog and report its due date and "
            "ransomware-use flag. Read-only public feed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "pattern": r"^CVE-\d{4}-\d{4,}$",
                    "description": "CVE identifier, e.g. CVE-2021-44228.",
                },
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "false_positive_check",
        "description": (
            "Offline check of a finding signature hash against "
            "memory/FALSE_POSITIVE_DB.md (exact 8-hex match, no network). "
            "Returns the matching FP entry or reports Hard FP Gate check 6 as clear."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "signature_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{8}$",
                    "description": "SHA256(category:identifier:signal)[:8] signature hash.",
                },
            },
            "required": ["signature_hash"],
        },
    },
]


def _tool_result(text: str, is_error: bool) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a tools/call; tool failures become isError results, not errors."""
    handler = TOOL_FUNCTIONS.get(name)
    if handler is None:
        available = ", ".join(sorted(TOOL_FUNCTIONS))
        return _tool_result(f"Unknown tool '{name}'. Available tools: {available}", True)
    if not isinstance(arguments, dict):
        return _tool_result("Tool arguments must be a JSON object", True)
    try:
        return _tool_result(handler(arguments), False)
    except ToolError as exc:
        return _tool_result(str(exc), True)
    except Exception as exc:  # defensive: never leak a traceback to the client
        log(f"internal error in tool '{name}':\n{traceback.format_exc()}")
        return _tool_result(
            f"Internal error in '{name}': {type(exc).__name__}: {exc}", True
        )


# --------------------------------------------------------------------------- #
# JSON-RPC 2.0 / MCP routing
# --------------------------------------------------------------------------- #
def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _result(msg_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def handle_initialize(params: Any) -> Dict[str, Any]:
    requested = params.get("protocolVersion") if isinstance(params, dict) else None
    protocol = requested if isinstance(requested, str) and requested else DEFAULT_PROTOCOL_VERSION
    return {
        "protocolVersion": protocol,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_message(message: Any) -> Any:
    """Route one parsed JSON-RPC message.

    Returns a response dict, a list of responses (batch), or ``None`` for
    notifications, which must not be answered.
    """
    if isinstance(message, list):
        if not message:
            return _error(None, INVALID_REQUEST, "Invalid Request: empty batch")
        responses: List[Dict[str, Any]] = []
        for item in message:
            response = handle_message(item)
            if response is None:
                continue
            if isinstance(response, list):
                responses.extend(response)
            else:
                responses.append(response)
        return responses or None

    if not isinstance(message, dict):
        return _error(None, INVALID_REQUEST, "Invalid Request: expected a JSON object")

    msg_id = message.get("id")
    is_notification = "id" not in message
    method = message.get("method")

    if is_notification:
        log(f"notification received: {method or '(no method)'}")
        return None

    if not isinstance(method, str) or not method:
        return _error(msg_id, INVALID_REQUEST, "Invalid Request: missing 'method'")

    if method.startswith("notifications/"):
        log(f"notification received: {method}")
        return None

    params = message.get("params") if message.get("params") is not None else {}

    if method == "initialize":
        return _result(msg_id, handle_initialize(params))
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        if not isinstance(params, dict):
            return _error(msg_id, INVALID_PARAMS, "Invalid params: expected an object")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return _error(msg_id, INVALID_PARAMS, "Invalid params: 'name' is required")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _error(msg_id, INVALID_PARAMS, "Invalid params: 'arguments' must be an object")
        return _result(msg_id, call_tool(name, arguments))

    return _error(msg_id, METHOD_NOT_FOUND, f"Method not found: {method}")


def process_line(line: str) -> Optional[str]:
    """Turn one stdin line into a response line (or None for no answer)."""
    stripped = line.strip()
    if not stripped:
        return None
    try:
        message = json.loads(stripped)
    except json.JSONDecodeError as exc:
        log(f"malformed JSON rejected: {exc}")
        return json.dumps(_error(None, PARSE_ERROR, f"Parse error: {exc}"))
    try:
        response = handle_message(message)
    except Exception:  # defensive: keep the loop alive, report internally
        log(f"internal error while handling a message:\n{traceback.format_exc()}")
        msg_id = message.get("id") if isinstance(message, dict) else None
        response = _error(msg_id, INTERNAL_ERROR, "Internal error")
    if response is None:
        return None
    return json.dumps(response)


def serve(stdin: Optional[Any] = None, stdout: Optional[Any] = None) -> int:
    """Newline-delimited JSON-RPC loop; exits gracefully on stdin EOF."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    log(
        f"{SERVER_NAME} {SERVER_VERSION} ready "
        f"(protocol {DEFAULT_PROTOCOL_VERSION}, timeout {REQUEST_TIMEOUT}s)"
    )
    for line in stdin:
        response = process_line(line)
        if response is None:
            continue
        stdout.write(response + "\n")
        stdout.flush()
    log("stdin closed — graceful shutdown")
    return 0


# --------------------------------------------------------------------------- #
# Offline self-test (no network: every HTTP seam is faked)
# --------------------------------------------------------------------------- #
def run_self_test() -> int:
    """Exercise routing (tools/list) and a fake-backend tools/call, no network."""
    nvd_sample = {
        "totalResults": 1,
        "resultsPerPage": 1,
        "startIndex": 0,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "sourceIdentifier": "cve@mitre.org",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Self-test sample vulnerability in ExampleLib."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                }
            }
        ],
    }
    osv_sample = {
        "vulns": [
            {
                "id": "GHSA-self-test",
                "summary": "Self-test sample OSV record",
                "aliases": ["CVE-2023-0002"],
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "example"},
                        "versions": ["1.0.0", "1.0.1"],
                    }
                ],
            }
        ]
    }
    kev_sample = {
        "catalogVersion": "self-test",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-0003",
                "vendorProject": "Example",
                "product": "Lib",
                "vulnerabilityName": "Self-test sample KEV entry",
                "dateAdded": "2023-01-02",
                "dueDate": "2023-01-23",
                "knownRansomwareCampaignUse": "Known",
                "shortDescription": "Self-test description.",
            }
        ],
    }

    checks: List[Tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, bool(ok)))

    # --- routing without any HTTP ------------------------------------------ #
    init_response = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": DEFAULT_PROTOCOL_VERSION},
        }
    )
    check(
        "initialize returns serverInfo",
        isinstance(init_response, dict)
        and init_response.get("result", {}).get("serverInfo", {}).get("name") == SERVER_NAME,
    )

    notification = handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    )
    check("notifications/initialized produces no response", notification is None)

    list_response = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = list_response.get("result", {}).get("tools", []) if isinstance(list_response, dict) else []
    expected_names = sorted(tool["name"] for tool in TOOLS)
    check(
        "tools/list exposes 4 schema'd tools",
        len(tools) == 4
        and sorted(t.get("name") for t in tools) == expected_names
        and all(
            isinstance(t.get("inputSchema"), dict) and t["inputSchema"].get("type") == "object"
            for t in tools
        ),
    )

    ping_response = handle_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    check("ping returns an empty result", ping_response == {"jsonrpc": "2.0", "id": 3, "result": {}})

    unknown = handle_message({"jsonrpc": "2.0", "id": 4, "method": "no/such-method"})
    check(
        "unknown method -> -32601",
        isinstance(unknown, dict) and unknown.get("error", {}).get("code") == METHOD_NOT_FOUND,
    )

    malformed = process_line("{not valid json")
    parsed = json.loads(malformed) if malformed else None
    check(
        "malformed JSON -> -32700",
        isinstance(parsed, dict) and parsed.get("error", {}).get("code") == PARSE_ERROR,
    )

    # --- fake-backend tools/call (no network) ------------------------------ #
    global http_get, http_post_json
    real_get, real_post = http_get, http_post_json

    def fake_get(url: str, timeout: float = REQUEST_TIMEOUT, headers: Optional[Dict[str, str]] = None) -> bytes:
        if "nvd.nist.gov" in url:
            return json.dumps(nvd_sample).encode("utf-8")
        if "cisa.gov" in url:
            return json.dumps(kev_sample).encode("utf-8")
        raise AssertionError(f"self-test tried to GET an unexpected URL: {url}")

    def fake_post(
        url: str,
        payload: Any,
        timeout: float = REQUEST_TIMEOUT,
        headers: Optional[Dict[str, str]] = None,
    ) -> bytes:
        if "api.osv.dev" in url:
            return json.dumps(osv_sample).encode("utf-8")
        raise AssertionError(f"self-test tried to POST an unexpected URL: {url}")

    def call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        response = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        return response.get("result", {}) if isinstance(response, dict) else {}

    http_get, http_post_json = fake_get, fake_post
    try:
        cve_result = call("search_cves", {"keyword": "ExampleLib", "limit": 5})
        check(
            "tools/call search_cves (fake NVD)",
            cve_result.get("isError") is False
            and "CVE-2023-0001" in cve_result.get("content", [{}])[0].get("text", ""),
        )

        osv_result = call(
            "query_osv", {"package": "example", "ecosystem": "npm", "version": "1.0.0"}
        )
        check(
            "tools/call query_osv (fake OSV)",
            osv_result.get("isError") is False
            and "GHSA-self-test" in osv_result.get("content", [{}])[0].get("text", ""),
        )

        kev_result = call("known_exploited", {"cve_id": "cve-2023-0003"})
        check(
            "tools/call known_exploited (fake CISA KEV)",
            kev_result.get("isError") is False
            and "IS in the CISA KEV" in kev_result.get("content", [{}])[0].get("text", ""),
        )
    finally:
        http_get, http_post_json = real_get, real_post

    # --- offline FP-DB check (real shipped database, read-only) ------------ #
    fp_result = call("false_positive_check", {"signature_hash": "3a8f1b20"})
    check(
        "tools/call false_positive_check (offline FP DB)",
        fp_result.get("isError") is False
        and "known false positive" in fp_result.get("content", [{}])[0].get("text", ""),
    )

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"SELF-TEST {'PASS' if passed == len(checks) else 'FAIL'} ({passed}/{len(checks)} checks)")
    return 0 if passed == len(checks) else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp_intel_server.py",
        description=(
            "MCP stdio server: read-only vulnerability intelligence for "
            "mcp-bug-intel-agent (NVD CVE search, OSV package query, CISA KEV "
            "lookup, offline FP-DB check)."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run an offline self-test (tools/list + fake-backend tools/call) and exit",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        return serve()
    except KeyboardInterrupt:
        log("interrupted — shutting down")
        return 130


if __name__ == "__main__":
    sys.exit(main())
