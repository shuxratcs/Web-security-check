"""Optional AI layer. The scanner works fully without it; AI is a 'second opinion'
plus richer remediation copy. All functions return safe fallbacks on any failure."""

import json
import os

from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

_model = None
if API_KEY:
    try:
        import google.generativeai as genai
        genai.configure(api_key=API_KEY)
        _model = genai.GenerativeModel(MODEL_NAME)
    except Exception:
        _model = None

AI_ENABLED = _model is not None


STATIC_REMEDIATIONS = {
    "SQL Injection": (
        "### SQL Injection — Remediation\n\n"
        "**Risk.** SQL injection lets an attacker read, modify, or destroy "
        "database records and may lead to full host takeover.\n\n"
        "**Prevention.**\n"
        "- Use parameterised queries / prepared statements for every user-supplied value.\n"
        "- Validate inputs at the application boundary (allow-list, expected types, length limits).\n"
        "- Apply least-privilege database accounts.\n"
        "- Layer a WAF for known SQLi patterns as defence-in-depth.\n\n"
        "**Example (Python / psycopg):**\n"
        "```python\n"
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n"
        "```"
    ),
    "Reflected XSS": (
        "### Reflected XSS — Remediation\n\n"
        "**Risk.** Attacker-controlled input is rendered into HTML without "
        "encoding, allowing arbitrary script execution in the victim's browser.\n\n"
        "**Prevention.**\n"
        "- Context-aware output encoding (HTML, attribute, JS, URL contexts each need different escaping).\n"
        "- Use a templating engine that auto-escapes by default.\n"
        "- Add a strict Content-Security-Policy that disallows inline scripts.\n\n"
        "**Example (React):** rendering `{userInput}` is auto-escaped. Avoid `dangerouslySetInnerHTML`."
    ),
    "Missing Security Headers": (
        "### Missing Security Headers — Remediation\n\n"
        "Add the following headers to all HTML responses:\n\n"
        "- `Strict-Transport-Security: max-age=31536000; includeSubDomains`\n"
        "- `X-Frame-Options: DENY` (or use CSP `frame-ancestors`)\n"
        "- `X-Content-Type-Options: nosniff`\n"
        "- `Referrer-Policy: strict-origin-when-cross-origin`\n"
        "- `Content-Security-Policy: default-src 'self'`"
    ),
    "Insecure Cookie": (
        "### Insecure Cookie — Remediation\n\n"
        "Set the following flags on every session cookie:\n\n"
        "- `Secure` — cookie sent only over HTTPS\n"
        "- `HttpOnly` — JavaScript cannot read the cookie\n"
        "- `SameSite=Lax` (or `Strict`) — mitigates CSRF\n"
        "- `Path=/`, `Domain` scoped narrowly to the issuing host"
    ),
    "Sensitive File Exposure": (
        "### Sensitive File Exposure — Remediation\n\n"
        "- Remove backups, dotfiles (`.env`, `.git`), and editor swap files from the deploy artefact.\n"
        "- Block direct access to dotfiles at the web-server / CDN level.\n"
        "- Treat any leaked credentials as compromised — rotate them immediately."
    ),
    "CORS Misconfiguration": (
        "### CORS Misconfiguration — Remediation\n\n"
        "Never combine `Access-Control-Allow-Origin: *` with "
        "`Access-Control-Allow-Credentials: true`. Reflect a known origin only "
        "after allow-listing it. Restrict allowed methods/headers to the minimum required."
    ),
    "Clickjacking": (
        "### Clickjacking — Remediation\n\n"
        "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and a CSP "
        "`frame-ancestors 'none'` directive on all sensitive pages."
    ),
    "Information Disclosure": (
        "### Information Disclosure — Remediation\n\n"
        "- Strip `Server`, `X-Powered-By`, and version banners from responses.\n"
        "- Disable detailed stack traces in production.\n"
        "- Audit HTML and JS for hardcoded emails, internal hostnames, and developer comments."
    ),
    "Weak SSL/TLS": (
        "### Weak SSL/TLS — Remediation\n\n"
        "- Disable TLS 1.0 / 1.1; require TLS 1.2+ (prefer 1.3).\n"
        "- Use a modern cipher suite (Mozilla Intermediate or stricter).\n"
        "- Renew certificates well before expiry; automate via ACME (Let's Encrypt, etc.)."
    ),
    "Weak CSP": (
        "### Weak CSP — Remediation\n\n"
        "A strong CSP starts from `default-src 'self'` and progressively adds only "
        "the origins required. Avoid `'unsafe-inline'` and `'unsafe-eval'`. "
        "Use nonces for legitimate inline scripts."
    ),
}


def _generate(prompt):
    """Single-shot Gemini call. Returns text or None — never raises."""
    if not _model:
        return None
    try:
        resp = _model.generate_content(prompt)
        return getattr(resp, "text", None)
    except Exception:
        return None


def _extract_json(text):
    if not text:
        return None
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0]
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0]
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        return None


def get_ai_recon(html_content):
    """Best-effort tech-stack identification. Returns a dict (never None)."""
    fallback = {"tech_stack": "Unknown", "vectors": ["SQLi", "XSS"]}
    text = _generate(
        "Identify the technology stack and likely test vectors from this HTML.\n"
        "Return strict JSON: {\"tech_stack\": \"...\", \"vectors\": [...]}.\n\n"
        f"HTML (truncated):\n{(html_content or '')[:4000]}"
    )
    parsed = _extract_json(text)
    return parsed if isinstance(parsed, dict) and "tech_stack" in parsed else fallback


def ai_judge_response(url, payload, response_text, status_code):
    """Optional second-opinion classifier. Returns a dict; vulnerable=False on failure."""
    fallback = {"vulnerable": False, "confidence": 0, "reason": "AI judge unavailable"}
    text = _generate(
        "Decide if a SQL injection succeeded based on the response below. "
        "Return strict JSON {\"vulnerable\": bool, \"confidence\": 0-100, \"reason\": \"...\"}.\n"
        f"URL: {url}\nPayload: {payload}\nStatus: {status_code}\n"
        f"Response (truncated):\n{(response_text or '')[:2500]}"
    )
    parsed = _extract_json(text)
    if isinstance(parsed, dict) and "vulnerable" in parsed:
        return parsed
    return fallback


def get_remediation(vuln_type, target_tech="Unknown"):
    """Return remediation Markdown. Falls back to a curated static blob keyed by vuln_type."""
    static = STATIC_REMEDIATIONS.get(vuln_type, "Refer to OWASP guidance for remediation steps.")
    text = _generate(
        f"Provide concise Markdown remediation guidance for a {vuln_type} vulnerability "
        f"on a {target_tech} stack. Include: (1) one-paragraph risk explanation, "
        "(2) prevention checklist, (3) one secure code example. Keep under 1500 characters."
    )
    return text or static
