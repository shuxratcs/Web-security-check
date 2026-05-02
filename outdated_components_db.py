"""Static catalogue of minimum acceptable versions for common web components.

Pure data + tiny pure-Python helpers. No third-party imports — both the
FastAPI backend (checks.py) and the stdlib-only Vercel handler
(api/index.py) import from here.

Each rule says: 'if the detected version is strictly less than min_safe,
flag it'. Rationale per entry comes from upstream EOL/security advisories
that were public as of January 2026; this list is intentionally short and
conservative — false positives are worse than missed flags for an MVP.

Sources are referenced in README.md → 'A06 catalogue' so the academic
report can cite them.
"""

import re

# {component_id: (display_name, min_safe_version, rationale)}
COMPONENT_RULES = {
    # Server software
    "apache":     ("Apache HTTPD",        "2.4.55", "CVE-2023-25690 mod_proxy request smuggling"),
    "nginx":      ("nginx",               "1.24.0", "Security and HTTP/3 fixes through 1.24 LTS"),
    "iis":        ("Microsoft IIS",       "10.0",   "IIS <10 ships on EOL Windows Server lines"),

    # Languages / runtimes
    "php":        ("PHP",                 "8.1.0",  "PHP 8.0 reached EOL on 2023-11-26"),
    "python":     ("Python",              "3.10.0", "Python <3.10 receives only security fixes"),

    # CMS
    "wordpress":  ("WordPress",           "6.4.0",  "Pre-6.4 misses several auth + XSS hardenings"),
    "drupal":     ("Drupal",              "10.0.0", "Drupal 9 reached EOL on 2023-11-01"),
    "joomla":     ("Joomla",              "4.4.0",  "Joomla 3.x reached EOL on 2023-08-17"),

    # JS libraries
    "jquery":     ("jQuery",              "3.5.0",  "CVE-2020-11022 / 11023 XSS in html() and append()"),
    "bootstrap":  ("Bootstrap",           "4.3.1",  "CVE-2019-8331 XSS via tooltip / popover"),
    "angularjs":  ("AngularJS",           "9999.0", "AngularJS (1.x) is permanently EOL since 2022-01"),
    "lodash":     ("lodash",              "4.17.21","CVE-2021-23337 command injection via template"),
    "moment":     ("Moment.js",           "2.29.4", "CVE-2022-31129 ReDoS in rfc2822 parsing"),
}


# Regex patterns to extract (component_id, version) tuples from text sources.
# Each pattern returns the version in group 1.
_HEADER_PATTERNS = [
    # 'Server: Apache/2.4.41 (Ubuntu)'
    ("apache",    re.compile(r"Apache(?:[/-])?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("nginx",     re.compile(r"nginx(?:[/-])(\d+\.\d+(?:\.\d+)?)",   re.I)),
    ("iis",       re.compile(r"Microsoft-IIS/(\d+\.\d+)",            re.I)),
    # X-Powered-By: PHP/7.4.33
    ("php",       re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)",            re.I)),
    ("python",    re.compile(r"Python/(\d+\.\d+(?:\.\d+)?)",         re.I)),
]

_HTML_PATTERNS = [
    # <meta name="generator" content="WordPress 5.8.2">
    ("wordpress", re.compile(r'name=["\']generator["\']\s+content=["\']WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.I)),
    ("drupal",    re.compile(r'name=["\']generator["\']\s+content=["\']Drupal\s+(\d+(?:\.\d+)*)',         re.I)),
    ("joomla",    re.compile(r'name=["\']generator["\']\s+content=["\']Joomla[^"\']*?(\d+\.\d+(?:\.\d+)?)',re.I)),

    # <script src="...jquery-3.4.1.min.js">  or  jquery/3.4.1/jquery.min.js
    ("jquery",    re.compile(r'jquery[-/](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',     re.I)),
    ("bootstrap", re.compile(r'bootstrap[-/](\d+\.\d+(?:\.\d+)?)(?:[./]|\.min)',  re.I)),
    ("angularjs", re.compile(r'angular(?:js)?[-/](1\.\d+(?:\.\d+)?)\.',            re.I)),
    ("lodash",    re.compile(r'lodash[-/.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',    re.I)),
    ("moment",    re.compile(r'moment[-/.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js',    re.I)),
]


def _version_tuple(v):
    """'2.4.55' -> (2, 4, 55, 0). Pads to length 4."""
    parts = re.findall(r"\d+", v)
    nums = [int(p) for p in parts[:4]]
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums)


def _is_outdated(detected, min_safe):
    try:
        return _version_tuple(detected) < _version_tuple(min_safe)
    except Exception:
        return False


def detect_components(headers, html):
    """Return [(component_id, display_name, detected_version, min_safe, rationale)]
    for components that are present AND outdated. Headers is a dict —
    we lowercase keys here so callers don't have to.
    Duplicates per component_id are de-duped (first hit wins).
    """
    seen = {}
    header_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())

    for cid, pat in _HEADER_PATTERNS:
        if cid in seen:
            continue
        m = pat.search(header_blob)
        if m:
            seen[cid] = m.group(1)

    if html:
        for cid, pat in _HTML_PATTERNS:
            if cid in seen:
                continue
            m = pat.search(html)
            if m:
                seen[cid] = m.group(1)

    findings = []
    for cid, detected in seen.items():
        rule = COMPONENT_RULES.get(cid)
        if not rule:
            continue
        name, min_safe, rationale = rule
        if _is_outdated(detected, min_safe):
            findings.append((cid, name, detected, min_safe, rationale))
    return findings
