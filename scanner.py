"""Scan orchestrator.

scan_target() is a generator yielding events:
    {type: 'log', level, text, ts}
    {type: 'progress', current, total, label}
    {type: 'finding', ...finding fields}
    {type: 'done', summary}

Designed to be streamed to the client over Server-Sent Events. Never raises —
exceptions inside individual checks become 'log' events at level=warning.

run_sqli_scan() is a synchronous wrapper preserved for backwards compatibility
with the legacy POST /api/scan endpoint.
"""

import time
from urllib.parse import urlparse

from checks import (
    fetch_baseline,
    check_security_headers,
    check_ssl_tls,
    check_cookies,
    check_csp,
    check_clickjacking,
    check_cors,
    check_sensitive_files,
    check_info_disclosure,
    check_outdated_components,
    check_xss_reflected,
)
from sqli_scanner import run_sqli_quick

# (label, fn(url, baseline_response) -> [findings])
CHECK_PIPELINE = [
    ("SSL/TLS Configuration", check_ssl_tls),
    ("Security Headers", check_security_headers),
    ("Cookie Hardening", check_cookies),
    ("Content Security Policy", check_csp),
    ("Clickjacking Protection", check_clickjacking),
    ("Information Disclosure", check_info_disclosure),
    ("CORS Configuration", check_cors),
    ("Sensitive Files", check_sensitive_files),
    ("Outdated Components", check_outdated_components),
    ("Reflected XSS", check_xss_reflected),
    ("SQL Injection", run_sqli_quick),
]


def _log(level, text):
    return {"type": "log", "level": level, "text": text, "ts": time.time()}


def _severity_log_level(severity):
    return {
        "critical": "CRITICAL",
        "high": "WARNING",
        "medium": "WARNING",
        "low": "INFO",
        "info": "INFO",
    }.get(severity, "INFO")


def _summary(findings, status_override=None):
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if status_override:
        risk = "Error"
        status = status_override
    elif sev_counts["critical"]:
        risk, status = "Critical", "Vulnerable"
    elif sev_counts["high"]:
        risk, status = "High", "Vulnerable"
    elif sev_counts["medium"]:
        risk, status = "Medium", "At Risk"
    elif sev_counts["low"] or sev_counts["info"]:
        risk, status = "Low", "Hardenable"
    else:
        risk, status = "Secure", "Secure"

    score = 100
    score -= sev_counts["critical"] * 25
    score -= sev_counts["high"] * 12
    score -= sev_counts["medium"] * 6
    score -= sev_counts["low"] * 2
    score = max(0, score)

    return {
        "status": status,
        "risk_level": risk,
        "score": score,
        "counts": sev_counts,
        "findings_total": len(findings),
        "findings": findings,
    }


def scan_target(url):
    """Generator yielding scan events."""
    yield _log("INFO", f"Initialising SentinelAI engine for {url}")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        yield _log("ERROR", f"Unsupported URL scheme: '{parsed.scheme}'. Use http:// or https://")
        yield {"type": "done", "summary": _summary([], status_override="Invalid")}
        return
    if not parsed.netloc:
        yield _log("ERROR", "URL has no host component")
        yield {"type": "done", "summary": _summary([], status_override="Invalid")}
        return

    yield _log("INFO", "Fetching baseline response...")
    try:
        baseline = fetch_baseline(url, timeout=8)
        yield _log(
            "SUCCESS",
            f"Baseline received: HTTP {baseline.status_code}, {len(baseline.content)} bytes",
        )
    except Exception as e:
        yield _log("ERROR", f"Target unreachable: {str(e)[:200]}")
        yield {"type": "done", "summary": _summary([], status_override="Unreachable")}
        return

    all_findings = []
    total = len(CHECK_PIPELINE)

    for i, (label, fn) in enumerate(CHECK_PIPELINE, start=1):
        yield _log("SCANNING", f"[{i}/{total}] {label}...")
        yield {"type": "progress", "current": i, "total": total, "label": label}
        started = time.time()
        try:
            findings = fn(url, baseline) or []
        except Exception as e:
            yield _log("WARNING", f"{label} check raised: {str(e)[:200]}")
            findings = []
        elapsed = time.time() - started

        for f in findings:
            all_findings.append(f)
            yield {"type": "finding", **f}
            yield _log(
                _severity_log_level(f.get("severity")),
                f"[{f.get('severity', 'info').upper()}] {f.get('category')}: {f.get('title')}",
            )
        if not findings:
            yield _log("INFO", f"  → no issues detected ({elapsed:.1f}s)")
        else:
            yield _log("INFO", f"  → {len(findings)} issue(s) found ({elapsed:.1f}s)")

    yield _log("SUCCESS", f"Scan complete. {len(all_findings)} total finding(s).")
    yield {"type": "done", "summary": _summary(all_findings)}


def run_sqli_scan(url):
    """Legacy entry point. Drains the generator and returns the final summary."""
    findings = []
    final_summary = None
    logs = []
    for event in scan_target(url):
        kind = event.get("type")
        if kind == "log":
            logs.append(f"[{event.get('level', 'INFO')}] {event['text']}")
        elif kind == "finding":
            findings.append({k: v for k, v in event.items() if k != "type"})
        elif kind == "done":
            final_summary = event.get("summary")

    summary = final_summary or _summary(findings)
    summary["details"] = logs
    summary["tech_stack"] = "Auto-detected"
    return summary
