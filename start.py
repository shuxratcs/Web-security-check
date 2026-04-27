#!/usr/bin/env python3
"""
SentinelAI — Standalone server that works without any pip dependencies.
Uses only Python standard library (http.server + json).
Serves the pre-built frontend from dist/ and provides /api/scan endpoint.

Usage:
    python3 start.py

Then open http://localhost:8000 in your browser.
"""

import http.server
import json
import os
import ssl
import sys
import time
import threading
from urllib.parse import urlparse, parse_qs
from http.client import HTTPSConnection, HTTPConnection
from html.parser import HTMLParser

PORT = int(os.environ.get("PORT", 3000))
DIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")

# ─── Professionalism: Ethical & Legal Safeguards ──────────────────────────

# Rate limiting: delay between requests to avoid DoS on target (BCS Code of Conduct)
REQUEST_DELAY = 0.5  # seconds between requests to target server

# Audit log: accountability trail for all scans performed
AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.json")

# Scope control: block scanning of sensitive domains (Computer Misuse Act 1990 compliance)
RESTRICTED_DOMAINS = [
    "gov.uk", "police.uk", "nhs.uk", "mil.uk",
    "gov.us", ".mil", ".edu",
    "banking", "hsbc.co.uk", "barclays.co.uk", "lloydsbank.co.uk",
]

def is_restricted_domain(url):
    """Check if URL targets a restricted domain (legal safeguard)."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    for domain in RESTRICTED_DOMAINS:
        if domain in hostname:
            return True, domain
    return False, ""

def write_audit_log(url, result_status, findings_count):
    """Write scan record to audit log (accountability)."""
    from datetime import datetime
    entry = {
        "timestamp": datetime.now().isoformat(),
        "target_url": url,
        "result": result_status,
        "findings_count": findings_count
    }
    try:
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r') as f:
                log = json.load(f)
        else:
            log = []
        log.append(entry)
        # Keep only last 100 entries (data minimisation - GDPR)
        log = log[-100:]
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump(log, f, indent=2, ensure_ascii=False)
    except Exception:
        pass  # Non-critical

def mask_email(email):
    """Mask email for data minimisation (GDPR compliance)."""
    parts = email.split("@")
    if len(parts) != 2:
        return email
    name = parts[0]
    masked = name[0] + "***" if len(name) > 1 else "***"
    return f"{masked}@{parts[1]}"

# ─── Minimal Scanner (no external dependencies) ───────────────────────────


SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "' UNION SELECT NULL--",
    "' AND 1=2--",
    "admin' --",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "' OR 'a'='a",
]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "warning: mysql", "mysqli_fetch",
    "postgresql", "pg_query", "unterminated quoted string",
    "sqlite3", "sqlite_error", "near \"",
    "microsoft ole db", "unclosed quotation mark",
    "ora-01756", "ora-00933", "oracle error",
    "syntax error", "sqlstate", "sql error",
    "sqlexception", "java.sql", "database error", "db error",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
]

class FormParser(HTMLParser):
    """Extract forms and inputs from HTML using only stdlib."""
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
                self.current_form['inputs'].append({
                    'name': name,
                    'type': attrs_dict.get('type', 'text')
                })

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def http_get(url, timeout=5):
    """Simple HTTP GET using only stdlib."""
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
        
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', errors='replace')
        status = resp.status
        conn.close()
        return status, body
    except Exception as e:
        return None, str(e)


def http_get_full(url, timeout=5, extra_headers=None):
    """HTTP GET that also returns response headers and cookies."""
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

        hdrs = {"User-Agent": "SentinelAI/5.0"}
        if extra_headers:
            hdrs.update(extra_headers)
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', errors='replace')
        status = resp.status
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
        return status, body, headers
    except Exception as e:
        return None, str(e), {}


def inject_payload_url(url, payload):
    """Inject payload into URL query parameters."""
    if "=" not in url:
        return None
    base, _ = url.rsplit("=", 1)
    return f"{base}={payload}"


def check_sql_error(text):
    text_lower = text.lower()
    for err in SQL_ERRORS:
        if err.lower() in text_lower:
            return True
    return False


# ─── Module 1: Security Headers ──────────────────────────────────────────

SECURITY_HEADERS_CHECKS = {
    "X-Frame-Options": {
        "risk": "High", "category": "Security Headers",
        "desc": "Protects against Clickjacking attacks",
        "fix": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "Content-Security-Policy": {
        "risk": "High", "category": "Security Headers",
        "desc": "Prevents XSS and code injection attacks",
        "fix": "Add a Content-Security-Policy header restricting script sources"
    },
    "Strict-Transport-Security": {
        "risk": "High", "category": "Security Headers",
        "desc": "Enforces HTTPS connections (HSTS)",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "X-Content-Type-Options": {
        "risk": "Medium", "category": "Security Headers",
        "desc": "Prevents MIME-type sniffing",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "risk": "Low", "category": "Security Headers",
        "desc": "Controls referrer information leakage",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "risk": "Low", "category": "Security Headers",
        "desc": "Controls browser feature access (camera, mic, geolocation)",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "risk": "Low", "category": "Security Headers",
        "desc": "Legacy XSS filter for older browsers",
        "fix": "Add: X-XSS-Protection: 1; mode=block"
    },
}

def check_security_headers(resp_headers, logs):
    findings = []
    logs.append("[SCANNING] Analyzing security headers...")
    header_keys_lower = {k.lower(): v for k, v in resp_headers.items()}
    present = 0
    for header, info in SECURITY_HEADERS_CHECKS.items():
        if header.lower() in header_keys_lower:
            present += 1
            logs.append(f"[SUCCESS] Header present: {header}")
        else:
            findings.append({
                "type": f"Missing: {header}",
                "category": "Security Headers",
                "url": "",
                "payload": "",
                "confidence": 100,
                "reason": info["desc"],
                "remediation": f"### {header}\n\n**Risk:** {info['risk']}\n\n**Problem:** This header is missing.\n\n**{info['desc']}**\n\n**Fix:** {info['fix']}"
            })
            logs.append(f"[WARNING] Missing header: {header} ({info['risk']})")
    total = len(SECURITY_HEADERS_CHECKS)
    logs.append(f"[INFO] Security headers: {present}/{total} present")
    return findings


# ─── Module 2: SSL/TLS Check ─────────────────────────────────────────────

def check_ssl_tls(hostname, logs):
    import socket
    from datetime import datetime
    findings = []
    logs.append("[SCANNING] Checking SSL/TLS certificate...")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                expires_str = cert.get('notAfter', '')
                expires = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expires - datetime.now()).days
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', 'Unknown')
                logs.append(f"[SUCCESS] TLS Version: {protocol}")
                logs.append(f"[INFO] Certificate issuer: {issuer_name}")
                logs.append(f"[INFO] Certificate expires: {expires_str} ({days_left} days)")
                if protocol in ('TLSv1', 'TLSv1.1'):
                    findings.append({
                        "type": "Weak TLS Version",
                        "category": "SSL/TLS",
                        "url": "", "payload": "",
                        "confidence": 95,
                        "reason": f"Server uses {protocol} which is deprecated and vulnerable to attacks",
                        "remediation": f"### Weak TLS Version\n\n**Risk:** High\n\nUpgrade to TLS 1.2 or 1.3. Disable TLS 1.0 and 1.1 in your server config."
                    })
                    logs.append(f"[WARNING] Weak TLS version: {protocol}")
                if days_left < 0:
                    findings.append({
                        "type": "SSL Certificate Expired",
                        "category": "SSL/TLS",
                        "url": "", "payload": "",
                        "confidence": 100,
                        "reason": f"Certificate expired {abs(days_left)} days ago",
                        "remediation": "### Expired Certificate\n\n**Risk:** Critical\n\nRenew your SSL certificate immediately."
                    })
                    logs.append(f"[CRITICAL] Certificate EXPIRED {abs(days_left)} days ago!")
                elif days_left < 30:
                    findings.append({
                        "type": "SSL Certificate Expiring Soon",
                        "category": "SSL/TLS",
                        "url": "", "payload": "",
                        "confidence": 80,
                        "reason": f"Certificate expires in {days_left} days",
                        "remediation": f"### Certificate Expiring Soon\n\n**Risk:** Medium\n\nRenew within {days_left} days."
                    })
                    logs.append(f"[WARNING] Certificate expires in {days_left} days!")
                else:
                    logs.append(f"[SUCCESS] Certificate valid for {days_left} days")
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "SSL Certificate Invalid",
            "category": "SSL/TLS",
            "url": "", "payload": "",
            "confidence": 95,
            "reason": f"Certificate verification failed: {str(e)[:120]}",
            "remediation": "### Invalid Certificate\n\n**Risk:** High\n\nUse a valid certificate from a trusted CA (e.g. Let's Encrypt)."
        })
        logs.append(f"[WARNING] SSL verification error: {str(e)[:80]}")
    except Exception as e:
        logs.append(f"[INFO] SSL check skipped: {str(e)[:80]}")
    return findings


# ─── Module 3: Directory & File Discovery ─────────────────────────────────

SENSITIVE_PATHS = [
    ("/.env", "Critical", "Environment file with secrets/passwords"),
    ("/.git/config", "Critical", "Git config — may expose repo info"),
    ("/.git/HEAD", "Critical", "Git HEAD — confirms .git is exposed"),
    ("/wp-config.php", "Critical", "WordPress config with DB credentials"),
    ("/config.php", "High", "PHP config file"),
    ("/admin", "Medium", "Admin panel"),
    ("/administrator", "Medium", "Admin panel (Joomla)"),
    ("/phpmyadmin", "High", "phpMyAdmin database manager"),
    ("/backup.sql", "Critical", "Database backup file"),
    ("/db.sql", "Critical", "Database dump"),
    ("/phpinfo.php", "High", "PHP info page — exposes server details"),
    ("/server-status", "Medium", "Apache server status page"),
    ("/robots.txt", "Info", "Robots.txt — may reveal hidden paths"),
    ("/sitemap.xml", "Info", "Sitemap — reveals site structure"),
    ("/swagger.json", "Medium", "API documentation exposed"),
    ("/.htaccess", "High", "Apache config file"),
    ("/.DS_Store", "Low", "macOS directory file"),
    ("/web.config", "High", "IIS/ASP.NET config file"),
]

def check_sensitive_paths(base_url, logs):
    findings = []
    logs.append(f"[SCANNING] Probing {len(SENSITIVE_PATHS)} sensitive paths...")
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        origin += f":{parsed.port}"

    for path, risk, desc in SENSITIVE_PATHS:
        test_url = origin + path
        try:
            st, body = http_get(test_url, timeout=3)
            if st == 200 and len(body) > 0:
                # Avoid false positives from SPA fallbacks
                if "<html" in body.lower() and path not in ("/robots.txt", "/sitemap.xml", "/swagger.json"):
                    if "404" in body.lower() or "not found" in body.lower():
                        continue
                findings.append({
                    "type": f"Exposed: {path}",
                    "category": "Sensitive Files",
                    "url": test_url,
                    "payload": "",
                    "confidence": 85 if risk in ("Critical", "High") else 60,
                    "reason": desc,
                    "remediation": f"### Exposed File: {path}\n\n**Risk:** {risk}\n\n**{desc}**\n\nBlock access to this path in your web server config:\n```\n# Nginx\nlocation {path} {{ return 404; }}\n# Apache\n<Files \"{path.split('/')[-1]}\">\n  Require all denied\n</Files>\n```"
                })
                logs.append(f"[WARNING] Accessible: {path} ({risk})")
            elif st == 403:
                logs.append(f"[INFO] Forbidden (exists but blocked): {path}")
            else:
                pass  # 404 — not found, OK
        except:
            pass
    logs.append(f"[INFO] Directory scan complete")
    return findings


# ─── Module 4: Cookie Security ───────────────────────────────────────────

def check_cookies(resp_headers, logs):
    findings = []
    cookies_raw = []
    for k, v in resp_headers.items():
        if k.lower() == "set-cookie":
            cookies_raw.append(v)
    if not cookies_raw:
        logs.append("[INFO] No cookies set by server")
        return findings
    logs.append(f"[SCANNING] Analyzing {len(cookies_raw)} cookie(s)...")
    for cookie in cookies_raw:
        name = cookie.split("=")[0].strip()
        cl = cookie.lower()
        issues = []
        if "secure" not in cl:
            issues.append("Secure")
        if "httponly" not in cl:
            issues.append("HttpOnly")
        if "samesite" not in cl:
            issues.append("SameSite")
        for flag in issues:
            findings.append({
                "type": f"Cookie '{name}' missing {flag}",
                "category": "Cookie Security",
                "url": "", "payload": "",
                "confidence": 90,
                "reason": f"Cookie '{name}' is missing the {flag} flag",
                "remediation": f"### Cookie Missing {flag} Flag\n\n**Risk:** {'High' if flag in ('Secure','HttpOnly') else 'Medium'}\n\nSet the {flag} flag on cookie '{name}':\n```\nSet-Cookie: {name}=value; {flag}; HttpOnly; Secure; SameSite=Strict\n```"
            })
            logs.append(f"[WARNING] Cookie '{name}' missing {flag} flag")
    return findings


# ─── Module 5: Information Disclosure ─────────────────────────────────────

def check_info_disclosure(resp_headers, body, logs):
    import re
    findings = []
    logs.append("[SCANNING] Checking for information disclosure...")
    server = resp_headers.get("Server", resp_headers.get("server", ""))
    if server and any(v in server for v in ["Apache/", "nginx/", "IIS/", "LiteSpeed/"]):
        findings.append({
            "type": f"Server Version: {server}",
            "category": "Info Disclosure",
            "url": "", "payload": "",
            "confidence": 70,
            "reason": f"Server header reveals version: {server}",
            "remediation": f"### Server Version Disclosed\n\n**Risk:** Low\n\nRemove or obfuscate the Server header.\n```\n# Nginx\nserver_tokens off;\n# Apache\nServerTokens Prod\n```"
        })
        logs.append(f"[WARNING] Server version disclosed: {server}")
    xpow = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
    if xpow:
        findings.append({
            "type": f"X-Powered-By: {xpow}",
            "category": "Info Disclosure",
            "url": "", "payload": "",
            "confidence": 70,
            "reason": f"X-Powered-By header reveals technology: {xpow}",
            "remediation": f"### Technology Disclosed\n\n**Risk:** Low\n\nRemove the X-Powered-By header from your server config."
        })
        logs.append(f"[WARNING] X-Powered-By disclosed: {xpow}")
    # HTML comments with sensitive info
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    sensitive_kw = ['password', 'todo', 'fixme', 'hack', 'secret', 'api_key', 'token', 'debug']
    for c in comments:
        if any(kw in c.lower() for kw in sensitive_kw):
            findings.append({
                "type": "Sensitive HTML Comment",
                "category": "Info Disclosure",
                "url": "", "payload": "",
                "confidence": 75,
                "reason": f"HTML comment contains sensitive keyword: {c.strip()[:80]}",
                "remediation": "### Sensitive HTML Comment\n\n**Risk:** Medium\n\nRemove comments with sensitive data before deploying to production."
            })
            logs.append(f"[WARNING] Sensitive HTML comment found")
            break
    # Emails
    emails = list(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', body)))
    if emails:
        findings.append({
            "type": f"Emails Exposed ({len(emails)})",
            "category": "Info Disclosure",
            "url": "", "payload": "",
            "confidence": 60,
            "reason": f"Email addresses found in page source: {', '.join(mask_email(e) for e in emails[:3])}",
            "remediation": "### Email Addresses Exposed\n\n**Risk:** Low\n\nAvoid displaying raw email addresses. Use contact forms or obfuscation."
        })
        logs.append(f"[INFO] {len(emails)} email(s) found in source")
    return findings


# ─── Module 6: CORS Misconfiguration ─────────────────────────────────────

def check_cors(url, logs):
    findings = []
    logs.append("[SCANNING] Testing CORS configuration...")
    st, body, hdrs = http_get_full(url, extra_headers={"Origin": "https://evil-attacker.com"})
    if st is None:
        return findings
    acao = hdrs.get("Access-Control-Allow-Origin", hdrs.get("access-control-allow-origin", ""))
    acac = hdrs.get("Access-Control-Allow-Credentials", hdrs.get("access-control-allow-credentials", ""))
    if acao == "*":
        risk = "High" if acac.lower() == "true" else "Medium"
        findings.append({
            "type": "CORS Wildcard Origin",
            "category": "CORS",
            "url": "", "payload": "",
            "confidence": 90,
            "reason": "Server allows requests from any origin (Access-Control-Allow-Origin: *)",
            "remediation": "### CORS Wildcard\n\n**Risk:** " + risk + "\n\nRestrict allowed origins to your specific domains."
        })
        logs.append(f"[WARNING] CORS allows wildcard origin (*)")
    elif acao == "https://evil-attacker.com":
        findings.append({
            "type": "CORS Origin Reflection",
            "category": "CORS",
            "url": "", "payload": "",
            "confidence": 95,
            "reason": "Server reflects arbitrary Origin header — any site can make authenticated requests",
            "remediation": "### CORS Origin Reflection\n\n**Risk:** Critical\n\nDo NOT reflect the Origin header. Whitelist specific domains."
        })
        logs.append(f"[CRITICAL] CORS reflects arbitrary origin!")
    else:
        logs.append(f"[SUCCESS] CORS properly configured")
    return findings


# ─── Module 7: Clickjacking ──────────────────────────────────────────────

def check_clickjacking(resp_headers, logs):
    findings = []
    logs.append("[SCANNING] Checking clickjacking protection...")
    xfo = resp_headers.get("X-Frame-Options", resp_headers.get("x-frame-options", "")).lower()
    csp = resp_headers.get("Content-Security-Policy", resp_headers.get("content-security-policy", "")).lower()
    if not xfo and "frame-ancestors" not in csp:
        findings.append({
            "type": "Clickjacking Possible",
            "category": "Clickjacking",
            "url": "", "payload": "",
            "confidence": 85,
            "reason": "No X-Frame-Options or CSP frame-ancestors — page can be embedded in an iframe",
            "remediation": "### Clickjacking\n\n**Risk:** Medium\n\nAdd:\n```\nX-Frame-Options: DENY\n```\nor CSP:\n```\nContent-Security-Policy: frame-ancestors 'none'\n```"
        })
        logs.append(f"[WARNING] No clickjacking protection")
    else:
        logs.append(f"[SUCCESS] Clickjacking protection present")
    return findings


# ─── Module 8: CSP Analysis ──────────────────────────────────────────────

CSP_WEAKNESSES = {
    "'unsafe-inline'": "Allows inline scripts — XSS still possible",
    "'unsafe-eval'": "Allows eval() — dangerous for XSS",
    "data:": "Allows data: URIs — can bypass CSP",
    "http:": "Allows HTTP resources — vulnerable to MITM",
}

def check_csp_deep(resp_headers, logs):
    findings = []
    csp = resp_headers.get("Content-Security-Policy", resp_headers.get("content-security-policy", ""))
    if not csp:
        return findings  # Already flagged by security headers check
    logs.append("[SCANNING] Deep-analyzing Content-Security-Policy...")
    for weakness, desc in CSP_WEAKNESSES.items():
        if weakness in csp.lower():
            findings.append({
                "type": f"CSP Weakness: {weakness}",
                "category": "CSP Analysis",
                "url": "", "payload": "",
                "confidence": 80,
                "reason": desc,
                "remediation": f"### CSP Contains {weakness}\n\n**Risk:** Medium\n\n{desc}\n\nRemove `{weakness}` from your CSP and use nonces or hashes instead."
            })
            logs.append(f"[WARNING] CSP weakness: {weakness}")
    if "default-src" not in csp.lower() and "script-src" not in csp.lower():
        findings.append({
            "type": "CSP Missing Script Control",
            "category": "CSP Analysis",
            "url": "", "payload": "",
            "confidence": 75,
            "reason": "CSP has no default-src or script-src — scripts are unrestricted",
            "remediation": "### No Script Restrictions\n\n**Risk:** High\n\nAdd `script-src` or `default-src` directive to your CSP."
        })
        logs.append(f"[WARNING] CSP missing script-src / default-src")
    if not findings:
        logs.append(f"[SUCCESS] CSP appears well-configured")
    return findings


def run_scan(url):
    """Run comprehensive vulnerability scan using only stdlib."""
    findings = []
    logs = []

    logs.append("[INFO] Initializing SentinelAI Engine v5.0...")
    logs.append(f"[INFO] Target: {url}")

    # Legal safeguard: Check for restricted domains (Computer Misuse Act 1990)
    restricted, domain = is_restricted_domain(url)
    if restricted:
        logs.append(f"[ERROR] Domain '{domain}' is restricted. Scanning blocked for legal compliance.")
        return {
            "status": "Blocked",
            "risk_level": "N/A",
            "tech_stack": "Unknown",
            "findings": [],
            "scan_modules": [],
            "details": logs,
            "security_score": 0,
            "blocked_reason": f"Scanning of '{domain}' domains is blocked to comply with the Computer Misuse Act 1990."
        }

    # Phase 1: Fetch baseline with headers
    logs.append("[INFO] Fetching baseline response...")
    status, baseline, resp_headers = http_get_full(url)

    if status is None:
        logs.append(f"[ERROR] Target unreachable: {baseline}")
        return {
            "status": "Unreachable",
            "risk_level": "Error",
            "tech_stack": "Unknown",
            "findings": [],
            "scan_modules": [],
            "details": logs
        }

    logs.append(f"[INFO] Baseline received ({len(baseline)} bytes, HTTP {status})")

    # Phase 2: Tech stack detection (heuristic)
    tech_stack = "Unknown"
    bl = baseline.lower()
    server_hdr = resp_headers.get("Server", resp_headers.get("server", "")).lower()
    xpow_hdr = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", "")).lower()
    combined = bl + " " + server_hdr + " " + xpow_hdr
    if "php" in combined:
        tech_stack = "PHP"
    elif "asp.net" in combined:
        tech_stack = "ASP.NET"
    elif "django" in combined or "csrfmiddlewaretoken" in bl:
        tech_stack = "Python/Django"
    elif "express" in combined:
        tech_stack = "Node.js/Express"
    elif "laravel" in combined:
        tech_stack = "PHP/Laravel"
    elif "wordpress" in bl or "wp-content" in bl:
        tech_stack = "WordPress (PHP/MySQL)"
    elif "next.js" in combined or "__next" in bl:
        tech_stack = "Next.js"

    if tech_stack != "Unknown":
        logs.append(f"[SUCCESS] Tech stack detected: {tech_stack}")
    else:
        logs.append("[INFO] Tech stack: could not determine automatically")

    # Phase 3: Form discovery
    parser = FormParser()
    try:
        parser.feed(baseline)
    except:
        pass
    
    if parser.forms:
        logs.append(f"[INFO] Found {len(parser.forms)} form(s) on the page")
        for f in parser.forms:
            field_names = [i['name'] for i in f['inputs']]
            logs.append(f"[INFO]   Form → {f['method'].upper()} {f['action']} fields: {field_names}")

    # Phase 4: SQL Injection testing
    logs.append(f"[SCANNING] Testing {len(SQL_PAYLOADS)} SQL injection payloads...")

    for payload in SQL_PAYLOADS:
        injected_url = inject_payload_url(url, payload)
        if not injected_url:
            continue

        time.sleep(REQUEST_DELAY)  # Rate limiting (ethical safeguard)
        test_status, test_body = http_get(injected_url, timeout=5)
        if test_status is None:
            continue

        error_detected = check_sql_error(test_body)
        server_error = (test_status or 0) >= 500
        is_suspicious = error_detected or server_error

        logs.append(f"[SCANNING] Payload: {payload} → HTTP {test_status}, Δsize={abs(len(baseline) - len(test_body))}")

        if is_suspicious:
            confidence = 0
            reason = ""
            if error_detected:
                confidence = 85
                reason = "SQL error string detected in response body"
            elif server_error:
                confidence = 60
                reason = f"Server returned error status {test_status}"

            findings.append({
                "type": "SQL Injection",
                "category": "SQL Injection",
                "url": injected_url,
                "payload": payload,
                "confidence": confidence,
                "reason": reason,
                "remediation": generate_remediation("SQL Injection", tech_stack)
            })
            logs.append(f"[WARNING] Potential SQLi found with: {payload}")

    # Phase 5: XSS testing
    logs.append(f"[SCANNING] Testing {len(XSS_PAYLOADS)} XSS payloads...")
    for payload in XSS_PAYLOADS:
        injected_url = inject_payload_url(url, payload)
        if not injected_url:
            continue

        time.sleep(REQUEST_DELAY)  # Rate limiting (ethical safeguard)
        test_status, test_body = http_get(injected_url, timeout=5)
        if test_status is None:
            continue

        if payload in test_body:
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "category": "XSS",
                "url": injected_url,
                "payload": payload,
                "confidence": 90,
                "reason": "Payload was reflected unescaped in the response body",
                "remediation": generate_remediation("XSS", tech_stack)
            })
            logs.append(f"[WARNING] Reflected XSS found with: {payload}")
        else:
            logs.append(f"[SCANNING] XSS payload: {payload} → not reflected")

    # Phase 6: Security Headers
    findings.extend(check_security_headers(resp_headers, logs))

    # Phase 7: SSL/TLS
    parsed = urlparse(url)
    if parsed.scheme == 'https':
        findings.extend(check_ssl_tls(parsed.hostname, logs))
    else:
        logs.append("[WARNING] Site uses HTTP — no SSL/TLS to check")
        findings.append({
            "type": "No HTTPS",
            "category": "SSL/TLS",
            "url": "", "payload": "",
            "confidence": 100,
            "reason": "Site is served over unencrypted HTTP",
            "remediation": "### No HTTPS\n\n**Risk:** Critical\n\nEnable HTTPS with a valid SSL certificate (e.g. Let's Encrypt)."
        })

    # Phase 8: Sensitive File Discovery
    findings.extend(check_sensitive_paths(url, logs))

    # Phase 9: Cookie Security
    findings.extend(check_cookies(resp_headers, logs))

    # Phase 10: Information Disclosure
    findings.extend(check_info_disclosure(resp_headers, baseline, logs))

    # Phase 11: CORS
    findings.extend(check_cors(url, logs))

    # Phase 12: Clickjacking
    findings.extend(check_clickjacking(resp_headers, logs))

    # Phase 13: CSP Deep Analysis
    findings.extend(check_csp_deep(resp_headers, logs))

    # Build category summary
    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1

    scan_modules = [
        {"name": "SQL Injection", "icon": "💉", "count": categories.get("SQL Injection", 0)},
        {"name": "XSS", "icon": "⚡", "count": categories.get("XSS", 0)},
        {"name": "Security Headers", "icon": "🔒", "count": categories.get("Security Headers", 0)},
        {"name": "SSL/TLS", "icon": "🔐", "count": categories.get("SSL/TLS", 0)},
        {"name": "Sensitive Files", "icon": "📂", "count": categories.get("Sensitive Files", 0)},
        {"name": "Cookie Security", "icon": "🍪", "count": categories.get("Cookie Security", 0)},
        {"name": "Info Disclosure", "icon": "🕵️", "count": categories.get("Info Disclosure", 0)},
        {"name": "CORS", "icon": "🌐", "count": categories.get("CORS", 0)},
        {"name": "Clickjacking", "icon": "🖼️", "count": categories.get("Clickjacking", 0)},
        {"name": "CSP Analysis", "icon": "📜", "count": categories.get("CSP Analysis", 0)},
    ]

    # Final summary
    total = len(findings)
    high_sev = sum(1 for f in findings if f.get("confidence", 0) >= 80)
    if total > 0:
        logs.append(f"[CRITICAL] Scan complete — {total} issue(s) detected across {len(categories)} categories!")
    else:
        logs.append("[SUCCESS] Scan complete — no vulnerabilities detected.")

    # Weighted risk
    risk = "Low"
    if high_sev >= 3 or total >= 8:
        risk = "Critical"
    elif high_sev >= 1 or total >= 3:
        risk = "High"
    elif total >= 1:
        risk = "Medium"

    # Security score (0-100, weighted)
    score = 100
    for f in findings:
        conf = f.get("confidence", 50)
        if conf >= 90:
            score -= 12
        elif conf >= 70:
            score -= 7
        elif conf >= 50:
            score -= 4
        else:
            score -= 2
    score = max(0, score)

    # Write audit log (accountability - Professional Practice)
    result_status = "Vulnerable" if findings else "Secure"
    write_audit_log(url, result_status, len(findings))

    return {
        "status": result_status,
        "risk_level": risk,
        "tech_stack": tech_stack,
        "security_score": score,
        "findings": findings,
        "scan_modules": scan_modules,
        "details": logs
    }



def generate_remediation(vuln_type, tech_stack):
    """Generate remediation advice without AI."""
    if vuln_type == "SQL Injection":
        return f"""### SQL Injection — Remediation Guide

**Risk:** Critical — attackers can read, modify, or delete your entire database.

**Fix: Use Parameterized Queries (Prepared Statements)**

```python
# Python (with any DB driver)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```php
// PHP (PDO)
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
```

```javascript
// Node.js (mysql2)
const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [req.params.id]);
```

**Never** concatenate user input into SQL strings.
Use an ORM (SQLAlchemy, Eloquent, Sequelize) when possible.
"""
    elif vuln_type == "XSS":
        return f"""### Cross-Site Scripting (XSS) — Remediation Guide

**Risk:** High — attackers can steal user sessions and inject malicious content.

**Fix: Escape all user input before rendering**

```python
# Python (Jinja2 auto-escapes by default)
# Make sure autoescape is ON
from markupsafe import escape
safe_value = escape(user_input)
```

```php
// PHP
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

```javascript
// JavaScript (React auto-escapes JSX by default)
// NEVER use dangerouslySetInnerHTML with user input
```

Use Content-Security-Policy headers to mitigate impact.
"""
    return "No remediation available for this vulnerability type."


# ─── HTTP Server ──────────────────────────────────────────────────────────

MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
}

class SentinelHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"  {args[0]}")

    def do_GET(self):
        """Serve static files from dist/"""
        path = self.path.split('?')[0]
        if path == '/':
            path = '/index.html'

        file_path = os.path.join(DIST_DIR, path.lstrip('/'))

        if os.path.isfile(file_path):
            ext = os.path.splitext(file_path)[1]
            content_type = MIME_TYPES.get(ext, 'application/octet-stream')
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        else:
            # SPA fallback — serve index.html
            index_path = os.path.join(DIST_DIR, 'index.html')
            if os.path.isfile(index_path):
                with open(index_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', len(content))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle API requests."""
        if self.path == '/api/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body.decode('utf-8'))
            except:
                self._json_response(400, {"status": "error", "message": "Invalid JSON"})
                return

            if not data.get('consent'):
                self._json_response(200, {"status": "error", "message": "Legal consent required"})
                return

            url = data.get('url', '')
            if not url:
                self._json_response(200, {"status": "error", "message": "URL is required"})
                return

            # Run scan in a thread to not block
            print(f"\n  🔍 Starting scan: {url}")
            result = run_scan(url)
            print(f"  ✅ Scan complete: {result['status']} ({len(result['findings'])} findings)")
            self._json_response(200, result)
        else:
            self.send_error(404, "Not Found")

    def _json_response(self, status, data):
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def main():
    if not os.path.isdir(DIST_DIR):
        print(f"❌ Error: dist/ directory not found at {DIST_DIR}")
        print("   You need to build the frontend first: npm run build")
        sys.exit(1)

    if not os.path.isfile(os.path.join(DIST_DIR, 'index.html')):
        print(f"❌ Error: dist/index.html not found")
        sys.exit(1)

    server = http.server.HTTPServer(('127.0.0.1', PORT), SentinelHandler)
    
    print()
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║     🛡️  SentinelAI Security Scanner       ║")
    print("  ║                                           ║")
    print(f"  ║  Running on: http://localhost:{PORT}        ║")
    print("  ║  Press Ctrl+C to stop                     ║")
    print("  ╚═══════════════════════════════════════════╝")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()


if __name__ == '__main__':
    main()
