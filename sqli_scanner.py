"""Lightweight SQLi probe.

Tests existing URL query parameters with a small payload set using
error-based and time-based detection. No AI dependency. Returns a list of
finding dicts in the same shape as checks.py.
"""

import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 6
SLEEP_SECONDS = 3

ERROR_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "\" OR \"1\"=\"1",
    "')) OR 1=1--",
]
TIME_PAYLOADS = [
    f"' OR SLEEP({SLEEP_SECONDS})-- ",
    f"'; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'-- ",
    f"' OR pg_sleep({SLEEP_SECONDS})-- ",
]

SQL_ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "mysqli_fetch", "PostgreSQL", "pg_query",
    "sqlite3", "SQLITE_ERROR", "Microsoft OLE DB", "unclosed quotation mark",
    "ORA-01756", "ORA-00933", "JDBC", "SQLException", "syntax error",
    "SQLSTATE", "near \"", "unterminated quoted string", "Warning: mysql",
)


def _has_sql_error(text):
    if not text:
        return None
    low = text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig.lower() in low:
            return sig
    return None


def _build_url(parsed, params):
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _finding(severity, title, evidence):
    return {
        "category": "SQL Injection",
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "remediation_key": "SQL Injection",
    }


def run_sqli_quick(url, baseline_response=None):
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qsl(parsed.query, keep_blank_values=True)
    baseline_len = len(baseline_response.content) if baseline_response is not None else 0

    for name, original in params:
        # Error-based — fast, one request per payload
        triggered = False
        for payload in ERROR_PAYLOADS:
            mutated = [(n, (original or "") + payload if n == name else v) for n, v in params]
            try:
                r = requests.get(_build_url(parsed, mutated), timeout=REQUEST_TIMEOUT,
                                 verify=False, allow_redirects=True)
            except Exception:
                continue

            sig = _has_sql_error(r.text)
            if sig:
                findings.append(_finding(
                    "critical",
                    f"Error-based SQLi: parameter '{name}' leaks DB error",
                    f"payload={payload[:80]}, signature='{sig}'",
                ))
                triggered = True
                break
            if r.status_code >= 500 and abs(len(r.content) - baseline_len) > 200:
                findings.append(_finding(
                    "medium",
                    f"Suspicious 5xx + length change on parameter '{name}'",
                    f"payload={payload[:80]}, status={r.status_code}, "
                    f"len_diff={abs(len(r.content) - baseline_len)}",
                ))
                triggered = True
                break

        if triggered:
            continue

        # Time-based — try one SLEEP payload per parameter to keep total time bounded
        payload = TIME_PAYLOADS[0]
        mutated = [(n, (original or "") + payload if n == name else v) for n, v in params]
        try:
            start = time.time()
            requests.get(_build_url(parsed, mutated),
                         timeout=REQUEST_TIMEOUT,
                         verify=False, allow_redirects=True)
            elapsed = time.time() - start
        except requests.Timeout:
            elapsed = REQUEST_TIMEOUT
        except Exception:
            continue

        if elapsed >= SLEEP_SECONDS:
            findings.append(_finding(
                "high",
                f"Time-based SQLi: parameter '{name}' delayed by SLEEP payload",
                f"payload={payload[:80]}, elapsed={elapsed:.1f}s",
            ))

    return findings
