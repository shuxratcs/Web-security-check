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

PORT = 3000
DIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")

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


def run_scan(url):
    """Run vulnerability scan using only stdlib."""
    findings = []
    logs = []

    logs.append("[INFO] Initializing SentinelAI Engine...")
    logs.append(f"[INFO] Target: {url}")

    # Phase 1: Fetch baseline
    logs.append("[INFO] Fetching baseline response...")
    status, baseline = http_get(url)

    if status is None:
        logs.append(f"[ERROR] Target unreachable: {baseline}")
        return {
            "status": "Unreachable",
            "risk_level": "Error",
            "tech_stack": "Unknown",
            "findings": [],
            "details": logs
        }

    logs.append(f"[INFO] Baseline received ({len(baseline)} bytes, HTTP {status})")

    # Phase 2: Tech stack detection (heuristic)
    tech_stack = "Unknown"
    bl = baseline.lower()
    if "php" in bl or "x-powered-by: php" in bl:
        tech_stack = "PHP"
    elif "asp.net" in bl or "x-aspnet" in bl:
        tech_stack = "ASP.NET"
    elif "django" in bl or "csrfmiddlewaretoken" in bl:
        tech_stack = "Python/Django"
    elif "express" in bl or "x-powered-by: express" in bl:
        tech_stack = "Node.js/Express"
    elif "laravel" in bl:
        tech_stack = "PHP/Laravel"
    elif "wordpress" in bl or "wp-content" in bl:
        tech_stack = "WordPress (PHP/MySQL)"

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

        test_status, test_body = http_get(injected_url, timeout=5)
        if test_status is None:
            continue

        error_detected = check_sql_error(test_body)
        length_diff = abs(len(baseline) - len(test_body)) > 50
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

        test_status, test_body = http_get(injected_url, timeout=5)
        if test_status is None:
            continue

        # Check if payload is reflected in response
        if payload in test_body:
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "url": injected_url,
                "payload": payload,
                "confidence": 90,
                "reason": "Payload was reflected unescaped in the response body",
                "remediation": generate_remediation("XSS", tech_stack)
            })
            logs.append(f"[WARNING] Reflected XSS found with: {payload}")
        else:
            logs.append(f"[SCANNING] XSS payload: {payload} → not reflected")

    # Final summary
    if findings:
        logs.append(f"[CRITICAL] Scan complete — {len(findings)} vulnerability(ies) detected!")
    else:
        logs.append("[SUCCESS] Scan complete — no vulnerabilities detected.")

    risk = "Low"
    if len(findings) >= 3:
        risk = "Critical"
    elif len(findings) >= 1:
        risk = "High"

    return {
        "status": "Vulnerable" if findings else "Secure",
        "risk_level": risk,
        "tech_stack": tech_stack,
        "findings": findings,
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
