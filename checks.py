"""OWASP-aligned passive and lightweight active security checks.

Each public function is fast (1-2 HTTP requests where possible) and returns a
list of finding dicts with the shape:
    {type, title, severity, evidence, remediation_key}

severity ∈ {critical, high, medium, low, info}.

Functions never raise — failures return an empty list (the orchestrator emits a
warning log instead).
"""

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
import urllib3

from outdated_components_db import detect_components

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 6
SENSITIVE_FILE_TIMEOUT = 4

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

COMMON_SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/backup.sql",
    "/backup.zip",
    "/db.sqlite",
    "/database.sqlite",
    "/.DS_Store",
    "/phpinfo.php",
    "/server-status",
    "/.htaccess",
    "/config.json",
    "/composer.lock",
]
SENSITIVE_FILE_INDICATORS = (
    "DB_PASSWORD",
    "DB_USERNAME",
    "AWS_ACCESS_KEY",
    "AWS_SECRET",
    "ref: refs/heads",
    "[mysql]",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "<?php",
    "phpinfo()",
)

STACK_TRACE_MARKERS = (
    "Traceback (most recent call last)",
    "at java.",
    "at sun.",
    "Microsoft.NETFramework",
    "Stack trace:",
    "Fatal error:",
    "Warning: include(",
    "ORA-",
    "PG::",
)


def _mask_email(text):
    if not isinstance(text, str):
        return text
    return EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def _finding(severity, category, title, evidence="", remediation_key=None):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "evidence": _mask_email(evidence) if evidence else "",
        "remediation_key": remediation_key or category,
    }


def fetch_baseline(url, timeout=REQUEST_TIMEOUT):
    """One canonical fetch reused by passive checks. Caller handles exceptions."""
    return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)


def check_security_headers(url, response):
    """OWASP A05 — Security Misconfiguration: missing hardening headers."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    expected = [
        ("strict-transport-security", "HSTS not set", "high"),
        ("x-frame-options", "X-Frame-Options not set (clickjacking risk)", "medium"),
        ("x-content-type-options", "X-Content-Type-Options not set (MIME-sniffing)", "low"),
        ("referrer-policy", "Referrer-Policy not set", "low"),
        ("permissions-policy", "Permissions-Policy not set", "info"),
    ]
    for header, msg, sev in expected:
        if header not in headers:
            findings.append(_finding(sev, "Missing Security Headers", msg,
                                     evidence=f"Header missing: {header}"))

    for leaky in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = (headers.get(leaky) or "").strip()
        if not value:
            continue
        findings.append(_finding(
            "low", "Information Disclosure",
            f"Technology fingerprint leaked via {leaky}",
            evidence=f"{leaky}: {value}",
        ))
    return findings


def check_ssl_tls(url, _response=None):
    """OWASP A02 — Cryptographic Failures: TLS configuration."""
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(_finding(
            "high", "Weak SSL/TLS",
            "Target served over plaintext HTTP (no TLS)",
            evidence=f"scheme={parsed.scheme}",
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return findings

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                version = ssock.version() or "unknown"

        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(_finding(
                "high", "Weak SSL/TLS",
                f"Outdated TLS version negotiated: {version}",
                evidence=f"version={version}",
            ))

        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(_finding(
                        "critical", "Weak SSL/TLS",
                        f"Certificate expired {abs(days_left)} days ago",
                        evidence=f"notAfter={not_after}",
                    ))
                elif days_left < 14:
                    findings.append(_finding(
                        "high", "Weak SSL/TLS",
                        f"Certificate expires in {days_left} days",
                        evidence=f"notAfter={not_after}",
                    ))
            except Exception:
                pass

    except Exception as e:
        findings.append(_finding(
            "info", "Weak SSL/TLS",
            "TLS handshake inspection failed",
            evidence=str(e)[:200],
        ))
    return findings


def check_cookies(url, response):
    """OWASP A07 — cookie hardening flags."""
    findings = []
    raw = response.headers.get("Set-Cookie")
    if not raw:
        return findings
    is_https = urlparse(url).scheme == "https"
    for blob in [c.strip() for c in raw.split(",") if "=" in c]:
        name = blob.split("=", 1)[0].split(";", 1)[0]
        flags = blob.lower()
        missing = []
        if is_https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            findings.append(_finding(
                "medium", "Insecure Cookie",
                f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                evidence=blob[:200],
            ))
    return findings


def check_csp(url, response):
    """OWASP A05 — Content Security Policy presence and quality."""
    findings = []
    csp = (response.headers.get("Content-Security-Policy")
           or response.headers.get("Content-Security-Policy-Report-Only"))
    if not csp:
        findings.append(_finding(
            "medium", "Weak CSP",
            "No Content-Security-Policy header set",
            evidence="CSP header absent",
        ))
        return findings
    lower = csp.lower()
    if "'unsafe-inline'" in lower:
        findings.append(_finding(
            "medium", "Weak CSP",
            "CSP allows 'unsafe-inline' (scripts or styles)",
            evidence=csp[:300],
        ))
    if "'unsafe-eval'" in lower:
        findings.append(_finding(
            "medium", "Weak CSP",
            "CSP allows 'unsafe-eval'",
            evidence=csp[:300],
        ))
    if "default-src" not in lower:
        findings.append(_finding(
            "low", "Weak CSP",
            "CSP missing default-src directive",
            evidence=csp[:300],
        ))
    return findings


def check_clickjacking(url, response):
    """OWASP A05 — clickjacking via missing frame protections."""
    headers = {k.lower(): v for k, v in response.headers.items()}
    if not headers.get("x-frame-options"):
        csp = (headers.get("content-security-policy") or "").lower()
        if "frame-ancestors" not in csp:
            return [_finding(
                "medium", "Clickjacking",
                "No X-Frame-Options or CSP frame-ancestors directive set",
                evidence="Both protections absent",
            )]
    return []


def check_cors(url, response):
    """OWASP A05 — CORS misconfiguration."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    origin = headers.get("access-control-allow-origin")
    creds = headers.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*" and creds:
        findings.append(_finding(
            "high", "CORS Misconfiguration",
            "Wildcard origin combined with credentials=true",
            evidence="ACAO=* AND ACAC=true",
        ))
    elif origin == "*":
        findings.append(_finding(
            "low", "CORS Misconfiguration",
            "Wildcard origin permitted (acceptable only for public APIs)",
            evidence="ACAO=*",
        ))

    try:
        probe = "https://attacker.example"
        r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False,
                         headers={"Origin": probe})
        if r.headers.get("Access-Control-Allow-Origin") == probe:
            findings.append(_finding(
                "high", "CORS Misconfiguration",
                "Origin header reflected without an allow-list",
                evidence=f"Reflected origin: {probe}",
            ))
    except Exception:
        pass
    return findings


def _probe_path(base, path):
    try:
        r = requests.get(base + path, timeout=SENSITIVE_FILE_TIMEOUT,
                         verify=False, allow_redirects=False)
        if r.status_code == 200 and r.content:
            body = r.text[:2000]
            if any(ind in body for ind in SENSITIVE_FILE_INDICATORS) or len(r.content) > 50:
                return path, len(r.content)
    except Exception:
        return None
    return None


def check_sensitive_files(url, _response=None):
    """OWASP A05/A06 — exposed dotfiles, backups, version control."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_probe_path, base, p) for p in COMMON_SENSITIVE_PATHS]
        for fut in as_completed(futures):
            try:
                hit = fut.result()
            except Exception:
                hit = None
            if hit:
                path, size = hit
                findings.append(_finding(
                    "critical", "Sensitive File Exposure",
                    f"Accessible file: {path}",
                    evidence=f"GET {path} → 200 ({size} bytes)",
                ))
    return findings


def check_info_disclosure(url, response):
    """OWASP A05 — emails, version banners, stack traces in HTML."""
    findings = []
    text = response.text or ""

    emails = EMAIL_RE.findall(text)
    if emails:
        sample = ", ".join(f"{e[0]}***@{e[1]}" for e in emails[:3])
        findings.append(_finding(
            "low", "Information Disclosure",
            f"{len(emails)} email address(es) exposed in HTML source",
            evidence=sample,
        ))

    for marker in STACK_TRACE_MARKERS:
        if marker in text:
            findings.append(_finding(
                "medium", "Information Disclosure",
                "Server returned a stack trace or framework error",
                evidence=marker,
            ))
            break
    return findings


def check_outdated_components(url, response):
    """OWASP A06 — Vulnerable and Outdated Components.

    Fingerprints server software, runtimes, CMS, and JS libraries from
    response headers and HTML, then flags versions older than the
    minimums in outdated_components_db.COMPONENT_RULES.
    """
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    html = response.text or ""
    for cid, name, detected, min_safe, rationale in detect_components(headers, html):
        findings.append(_finding(
            "high",
            "Vulnerable / Outdated Component",
            f"{name} {detected} is older than the minimum safe version {min_safe}",
            evidence=f"{cid}={detected}; reason={rationale}",
            remediation_key="Outdated Component",
        ))
    return findings


def check_xss_reflected(url, _response=None):
    """OWASP A03 — reflected XSS in URL query parameters (lightweight active probe)."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings
    params = parse_qsl(parsed.query, keep_blank_values=True)
    marker = "SENTINEL_XSS_PROBE_TOKEN"
    payload_template = '"><svg/onload=alert(1)>' + marker

    for name, _ in params:
        injected = [(n, payload_template if n == name else v) for n, v in params]
        new_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
        try:
            r = requests.get(new_url, timeout=REQUEST_TIMEOUT, verify=False)
            body = r.text or ""
        except Exception:
            continue
        if marker in body and ("<svg" in body.lower() or '"><' in body):
            findings.append(_finding(
                "high", "Reflected XSS",
                f"Parameter '{name}' reflects unescaped HTML payload",
                evidence=f"Marker '{marker}' echoed alongside script-capable tags",
            ))
    return findings
