"""Vercel Serverless Function — SentinelAI API.

Self-contained Python function for Vercel deployment.
All /api/* requests are routed here via vercel.json rewrites.
Uses the standalone scanner from start.py logic (stdlib only, no pip deps needed).
"""

import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

from http.server import BaseHTTPRequestHandler

# ─── Domain Restrictions (Computer Misuse Act 1990) ───────────────────
BLOCKED_DOMAIN_SUFFIXES = (
    ".gov.uk", ".gov", ".mil", ".nhs.uk", ".police.uk",
)
BLOCKED_DOMAINS_EXACT = {
    "barclays.co.uk", "hsbc.co.uk", "lloydsbank.com", "natwest.com",
    "santander.co.uk", "halifax.co.uk", "monzo.com", "starling.com",
    "tsb.co.uk", "rbs.co.uk",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "jpmorgan.com", "goldmansachs.com", "ubs.com", "deutsche-bank.com",
    "paypal.com", "stripe.com", "revolut.com",
}

REQUEST_DELAY = 0.3

# ─── SQL Injection payloads ───────────────────────────────────────────
SQL_PAYLOADS = [
    "'", "' OR '1'='1", "' OR 1=1--", '" OR "1"="1',
    "' UNION SELECT NULL--", "' AND 1=2--", "admin' --",
]
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "warning: mysql", "mysqli_fetch",
    "postgresql", "pg_query", "unterminated quoted string",
    "sqlite3", "sqlite_error", 'near "',
    "microsoft ole db", "unclosed quotation mark",
    "ora-01756", "ora-00933", "oracle error",
    "syntax error", "sqlstate", "sql error",
    "sqlexception", "java.sql", "database error",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
]

SECURITY_HEADERS_CHECKS = {
    "X-Frame-Options": {"risk": "High", "desc": "Protects against Clickjacking attacks"},
    "Content-Security-Policy": {"risk": "High", "desc": "Prevents XSS and code injection"},
    "Strict-Transport-Security": {"risk": "High", "desc": "Enforces HTTPS (HSTS)"},
    "X-Content-Type-Options": {"risk": "Medium", "desc": "Prevents MIME-type sniffing"},
    "Referrer-Policy": {"risk": "Low", "desc": "Controls referrer info leakage"},
    "Permissions-Policy": {"risk": "Low", "desc": "Controls browser feature access"},
    "X-XSS-Protection": {"risk": "Low", "desc": "Legacy XSS filter"},
}

SENSITIVE_PATHS = [
    ("/.env", "Critical", "Environment file with secrets"),
    ("/.git/config", "Critical", "Git config exposed"),
    ("/.git/HEAD", "Critical", "Git HEAD exposed"),
    ("/wp-config.php", "Critical", "WordPress DB credentials"),
    ("/backup.sql", "Critical", "Database backup file"),
    ("/phpinfo.php", "High", "PHP info page"),
    ("/robots.txt", "Info", "Robots.txt"),
    ("/sitemap.xml", "Info", "Sitemap"),
]

CSP_WEAKNESSES = {
    "'unsafe-inline'": "Allows inline scripts — XSS possible",
    "'unsafe-eval'": "Allows eval() — dangerous",
    "data:": "Allows data: URIs — can bypass CSP",
}

EMAIL_RE = re.compile(r'\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')


# ─── Helpers ──────────────────────────────────────────────────────────

def is_blocked_domain(url):
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in BLOCKED_DOMAINS_EXACT:
        return True
    return any(host == suf.lstrip(".") or host.endswith(suf) for suf in BLOCKED_DOMAIN_SUFFIXES)


def mask_email(text):
    if not isinstance(text, str):
        return text
    return EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def http_get(url, timeout=5):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        if parsed.scheme == 'https':
            port = port or 443
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            port = port or 80
            conn = HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "SentinelAI/5.0"})
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', errors='replace')
        status = resp.status
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
        return status, body, headers
    except Exception as e:
        return None, str(e), {}


def check_sql_error(text):
    text_lower = text.lower()
    for err in SQL_ERRORS:
        if err.lower() in text_lower:
            return True
    return False


def inject_payload_url(url, payload):
    if "=" not in url:
        return None
    base, _ = url.rsplit("=", 1)
    return f"{base}={payload}"


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'get').lower(),
                'inputs': []
            }
        elif tag in ('input', 'textarea') and self.current_form is not None:
            name = attrs_dict.get('name')
            if name:
                self.current_form['inputs'].append({'name': name, 'type': attrs_dict.get('type', 'text')})

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


# ─── Check modules ────────────────────────────────────────────────────

def _finding(severity, category, title, evidence="", remediation_key=None):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "evidence": mask_email(evidence) if evidence else "",
        "remediation_key": remediation_key or category,
    }


def check_security_headers(resp_headers):
    findings = []
    header_keys_lower = {k.lower(): v for k, v in resp_headers.items()}
    for header, info in SECURITY_HEADERS_CHECKS.items():
        if header.lower() not in header_keys_lower:
            sev = "high" if info["risk"] == "High" else ("medium" if info["risk"] == "Medium" else "low")
            findings.append(_finding(sev, "Missing Security Headers", f"{header} not set", f"Header missing: {header}"))
    return findings


def check_ssl_tls(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        findings.append(_finding("high", "Weak SSL/TLS", "Site served over plaintext HTTP", f"scheme={parsed.scheme}"))
        return findings
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                version = ssock.version() or "unknown"
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(_finding("high", "Weak SSL/TLS", f"Outdated TLS: {version}", f"version={version}"))
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(_finding("critical", "Weak SSL/TLS", f"Certificate expired {abs(days_left)} days ago"))
                elif days_left < 14:
                    findings.append(_finding("high", "Weak SSL/TLS", f"Certificate expires in {days_left} days"))
            except Exception:
                pass
    except Exception as e:
        findings.append(_finding("info", "Weak SSL/TLS", "TLS check failed", str(e)[:200]))
    return findings


def check_cookies(resp_headers, url):
    findings = []
    is_https = urlparse(url).scheme == "https"
    for k, v in resp_headers.items():
        if k.lower() == "set-cookie":
            name = v.split("=")[0].strip()
            cl = v.lower()
            missing = []
            if is_https and "secure" not in cl:
                missing.append("Secure")
            if "httponly" not in cl:
                missing.append("HttpOnly")
            if "samesite" not in cl:
                missing.append("SameSite")
            for flag in missing:
                findings.append(_finding("medium", "Insecure Cookie", f"Cookie '{name}' missing {flag}", v[:200]))
    return findings


def check_info_disclosure(resp_headers, body):
    findings = []
    server = resp_headers.get("Server", resp_headers.get("server", ""))
    if server and any(v in server for v in ["Apache/", "nginx/", "IIS/", "LiteSpeed/"]):
        findings.append(_finding("low", "Information Disclosure", f"Server version: {server}", f"server: {server}"))
    xpow = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
    if xpow:
        findings.append(_finding("low", "Information Disclosure", f"X-Powered-By: {xpow}", f"x-powered-by: {xpow}"))
    emails = EMAIL_RE.findall(body)
    if emails:
        sample = ", ".join(f"{e[0]}***@{e[1]}" for e in emails[:3])
        findings.append(_finding("low", "Information Disclosure", f"{len(emails)} email(s) exposed", sample))
    return findings


def check_cors(url, resp_headers):
    findings = []
    acao = resp_headers.get("Access-Control-Allow-Origin", resp_headers.get("access-control-allow-origin", ""))
    acac = resp_headers.get("Access-Control-Allow-Credentials", resp_headers.get("access-control-allow-credentials", ""))
    if acao == "*" and acac.lower() == "true":
        findings.append(_finding("high", "CORS Misconfiguration", "Wildcard + credentials", "ACAO=* AND ACAC=true"))
    elif acao == "*":
        findings.append(_finding("low", "CORS Misconfiguration", "Wildcard origin", "ACAO=*"))
    return findings


def check_clickjacking(resp_headers):
    findings = []
    xfo = resp_headers.get("X-Frame-Options", resp_headers.get("x-frame-options", "")).lower()
    csp = resp_headers.get("Content-Security-Policy", resp_headers.get("content-security-policy", "")).lower()
    if not xfo and "frame-ancestors" not in csp:
        findings.append(_finding("medium", "Clickjacking", "No X-Frame-Options or CSP frame-ancestors"))
    return findings


def check_csp(resp_headers):
    findings = []
    csp = resp_headers.get("Content-Security-Policy", resp_headers.get("content-security-policy", ""))
    if not csp:
        findings.append(_finding("medium", "Weak CSP", "No Content-Security-Policy header"))
        return findings
    for weakness, desc in CSP_WEAKNESSES.items():
        if weakness in csp.lower():
            findings.append(_finding("medium", "Weak CSP", f"CSP contains {weakness}", desc))
    return findings


def check_sensitive_paths(base_url):
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        origin += f":{parsed.port}"
    for path, risk, desc in SENSITIVE_PATHS:
        test_url = origin + path
        try:
            st, body, _ = http_get(test_url, timeout=3)
            if st == 200 and len(body) > 0:
                if "<html" in body.lower() and path not in ("/robots.txt", "/sitemap.xml"):
                    if "404" in body.lower() or "not found" in body.lower():
                        continue
                sev = "critical" if risk == "Critical" else ("high" if risk == "High" else "info")
                findings.append(_finding(sev, "Sensitive File Exposure", f"Accessible: {path}", f"GET {path} → 200"))
        except Exception:
            pass
    return findings


# ─── Main scan ────────────────────────────────────────────────────────

def _log(level, text):
    return {"type": "log", "level": level, "text": text, "ts": time.time()}


def _summary(findings, status_override=None):
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    if status_override:
        risk, status = "Error", status_override
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
        "status": status, "risk_level": risk, "score": score,
        "counts": sev_counts, "findings_total": len(findings), "findings": findings,
    }


def scan_target_generator(url):
    """Generator yielding SSE events."""
    yield _log("INFO", f"Initialising SentinelAI engine for {url}")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        yield _log("ERROR", f"Unsupported scheme: '{parsed.scheme}'")
        yield {"type": "done", "summary": _summary([], status_override="Invalid")}
        return
    if not parsed.netloc:
        yield _log("ERROR", "URL has no host")
        yield {"type": "done", "summary": _summary([], status_override="Invalid")}
        return

    # Fetch baseline
    yield _log("INFO", "Fetching baseline response...")
    status, body, headers = http_get(url, timeout=8)
    if status is None:
        yield _log("ERROR", f"Target unreachable: {body[:200]}")
        yield {"type": "done", "summary": _summary([], status_override="Unreachable")}
        return
    yield _log("SUCCESS", f"Baseline: HTTP {status}, {len(body)} bytes")

    all_findings = []
    checks = [
        ("SSL/TLS", lambda: check_ssl_tls(url)),
        ("Security Headers", lambda: check_security_headers(headers)),
        ("Cookie Security", lambda: check_cookies(headers, url)),
        ("CSP Analysis", lambda: check_csp(headers)),
        ("Clickjacking", lambda: check_clickjacking(headers)),
        ("Info Disclosure", lambda: check_info_disclosure(headers, body)),
        ("CORS", lambda: check_cors(url, headers)),
        ("Sensitive Files", lambda: check_sensitive_paths(url)),
    ]
    total = len(checks) + 2  # +SQL, +XSS

    for i, (label, fn) in enumerate(checks, 1):
        yield _log("SCANNING", f"[{i}/{total}] {label}...")
        yield {"type": "progress", "current": i, "total": total, "label": label}
        try:
            findings = fn() or []
        except Exception as e:
            yield _log("WARNING", f"{label} failed: {str(e)[:200]}")
            findings = []
        for f in findings:
            all_findings.append(f)
            yield {"type": "finding", **f}
            yield _log("WARNING", f"[{f.get('severity', 'info').upper()}] {f.get('category')}: {f.get('title')}")
        if not findings:
            yield _log("INFO", f"  → no issues")

    # SQL Injection
    idx = len(checks) + 1
    yield _log("SCANNING", f"[{idx}/{total}] SQL Injection...")
    yield {"type": "progress", "current": idx, "total": total, "label": "SQL Injection"}
    for payload in SQL_PAYLOADS:
        injected = inject_payload_url(url, payload)
        if not injected:
            continue
        time.sleep(REQUEST_DELAY)
        ts, tb, _ = http_get(injected, timeout=5)
        if ts is None:
            continue
        if check_sql_error(tb):
            f = _finding("critical", "SQL Injection", f"Error-based SQLi with payload: {payload}", f"payload={payload}")
            all_findings.append(f)
            yield {"type": "finding", **f}
            yield _log("WARNING", f"SQLi found: {payload}")
            break
        elif (ts or 0) >= 500:
            f = _finding("medium", "SQL Injection", f"Server error with payload: {payload}", f"status={ts}")
            all_findings.append(f)
            yield {"type": "finding", **f}

    # XSS
    idx = len(checks) + 2
    yield _log("SCANNING", f"[{idx}/{total}] Reflected XSS...")
    yield {"type": "progress", "current": idx, "total": total, "label": "Reflected XSS"}
    for payload in XSS_PAYLOADS:
        injected = inject_payload_url(url, payload)
        if not injected:
            continue
        time.sleep(REQUEST_DELAY)
        ts, tb, _ = http_get(injected, timeout=5)
        if ts and payload in tb:
            f = _finding("high", "Reflected XSS", f"Payload reflected: {payload[:40]}", f"payload={payload}")
            all_findings.append(f)
            yield {"type": "finding", **f}
            yield _log("WARNING", f"XSS found: {payload}")

    yield _log("SUCCESS", f"Scan complete. {len(all_findings)} finding(s).")
    yield {"type": "done", "summary": _summary(all_findings)}


# ─── Vercel handler ───────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):
    """Vercel serverless function handler."""

    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, status_code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._set_cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        if path == "/api/health":
            self._json_response(200, {"status": "ok"})
            return

        if path == "/api/scan/stream":
            url = qs.get("url", [""])[0]
            consent = qs.get("consent", ["false"])[0].lower() == "true"

            if not consent:
                self._send_sse_error("Legal consent required.")
                return
            if not url:
                self._send_sse_error("URL is required.")
                return
            if not url.startswith(("http://", "https://")):
                self._send_sse_error("URL must start with http:// or https://")
                return
            if is_blocked_domain(url):
                self._send_sse_error("Target is on the protected critical-infrastructure list.")
                return

            # Stream SSE
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("X-Accel-Buffering", "no")
            self._set_cors()
            self.end_headers()

            for ev in scan_target_generator(url):
                line = f"data: {json.dumps(ev)}\n\n"
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()
            self.wfile.write(b"event: end\ndata: {}\n\n")
            self.wfile.flush()
            return

        self._json_response(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                self._json_response(400, {"status": "error", "message": "Invalid JSON"})
                return

            url = data.get("url", "")
            consent = data.get("consent", False)

            if not consent:
                self._json_response(200, {"status": "error", "message": "Legal consent required."})
                return
            if not url or not url.startswith(("http://", "https://")):
                self._json_response(200, {"status": "error", "message": "URL is required and must start with http(s)://"})
                return
            if is_blocked_domain(url):
                self._json_response(200, {"status": "error", "message": "Target is blocked."})
                return

            # Run scan synchronously
            findings = []
            summary = None
            for ev in scan_target_generator(url):
                if ev.get("type") == "finding":
                    findings.append({k: v for k, v in ev.items() if k != "type"})
                elif ev.get("type") == "done":
                    summary = ev.get("summary")
            result = summary or _summary(findings)
            self._json_response(200, result)
            return

        self._json_response(404, {"error": "Not found"})

    def _send_sse_error(self, message):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self._set_cors()
        self.end_headers()
        payload = json.dumps({"type": "error", "message": message})
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
        self.wfile.write(b"event: end\ndata: {}\n\n")
        self.wfile.flush()

    def log_message(self, format, *args):
        pass  # Suppress default logging
