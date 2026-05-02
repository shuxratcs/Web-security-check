# Web Security Check

Automated web vulnerability scanner targeting the OWASP Top 10 categories that
are most amenable to automation. Built as a final-year project (BSc Computer
Science, University of Wolverhampton, module 6CS007).

The tool runs an active+passive scan against a single user-supplied URL and
streams findings to a React dashboard in real time. It is deployed in two
configurations:

- **Railway** — full FastAPI backend with persistent SQLite history (primary
  deployment).
- **Vercel** — stdlib-only serverless handler with the same scan logic;
  history is ephemeral (per-cold-start) due to Vercel's read-only filesystem
  outside `/tmp`.

> **Authorised testing only.** Scanning systems you do not own or have
> explicit written permission to test may violate the UK Computer Misuse
> Act 1990 and equivalent laws elsewhere. The backend refuses targets on a
> built-in critical-infrastructure block-list (gov, NHS, police, military,
> major retail banks). Every scan is logged.

## OWASP coverage

| OWASP 2021 | Category | Module | Implementation |
|---|---|---|---|
| A02 | Cryptographic Failures | `checks.check_ssl_tls` | TLS version + cert expiry |
| A03 | Injection — SQLi | `sqli_scanner.run_sqli_quick` | Error-based + time-based on URL params |
| A03 | Injection — XSS | `checks.check_xss_reflected` | Reflected probe in URL params |
| A05 | Security Misconfiguration | `checks.check_security_headers`, `check_csp`, `check_clickjacking`, `check_cors`, `check_cookies` | Header hardening, CSP weakness, frame protections, cookie flags, CORS reflection |
| A05 | Sensitive Files | `checks.check_sensitive_files` | `.env`, `.git`, backups, dumps |
| A05 | Information Disclosure | `checks.check_info_disclosure` | Stack traces, leaked emails, server fingerprints |
| A06 | Vulnerable / Outdated Components | `checks.check_outdated_components` + `outdated_components_db` | Server, runtime, CMS, JS-library version detection against a curated EOL/CVE catalogue |

Out of scope (and why):
- **OWASP ZAP / SQLMap CLI integration** — both require running daemons or
  system binaries, which break the Vercel serverless deployment. The
  custom SQLi probe in `sqli_scanner.py` covers the same payload classes
  (error-based, boolean, time-based) without external processes.
- **A04 Insecure Design** — requires understanding business logic; not
  reliably automatable for an MVP.
- **DVWA / Juice Shop Docker harness** — needs a local Docker environment;
  belongs in the academic Test Results section, not the deployable artefact.

## Architecture

```
┌────────────────────────┐        ┌──────────────────────────────┐
│  React frontend (Vite) │ <────► │  FastAPI backend (Railway)   │
│  src/App.jsx           │  SSE   │  server.py                   │
└────────────────────────┘        │  ├── scanner.py (orchestrator)│
                                  │  ├── checks.py (A02/A05/A06) │
                                  │  ├── sqli_scanner.py (A03)   │
                                  │  ├── outdated_components_db  │
                                  │  └── history_store (SQLite)  │
                                  └──────────────────────────────┘

┌────────────────────────┐        ┌──────────────────────────────┐
│  React frontend (Vite) │ /api/* │  api/index.py (Vercel)       │
│  Vercel static build   │ ─────► │  stdlib-only mirror, sharing │
└────────────────────────┘        │  outdated_components_db &    │
                                  │  history_store via sys.path  │
                                  └──────────────────────────────┘
```

## Local development

Backend:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py                       # http://127.0.0.1:8000
```

Frontend (separate terminal):

```bash
npm install
npm run dev                            # http://127.0.0.1:5173
```

Production build:

```bash
npm run build                          # writes dist/
python server.py                       # serves dist/ as catch-all
```

## Tests

```bash
python tests/test_metrics.py           # detector accuracy harness
# or
python -m pytest tests/ -s
```

The harness spins up an in-process HTTP server with hand-crafted vulnerable
and clean fixture pages, runs the scanner against each, and prints a
TP/FP/FN table plus precision/recall. Fail conditions: any false negative
on an expected category, or any false positive on the clean baseline page.

## API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scan` | Synchronous scan; body `{url, consent}` |
| `GET`  | `/api/scan/stream?url=...&consent=true` | SSE event stream |
| `GET`  | `/api/history?limit=50` | Recent scans (most recent first) |
| `GET`  | `/api/scans/{id}` | One scan with all findings |
| `GET`  | `/api/audit` | Legacy alias of `/api/history?limit=100` |
| `GET`  | `/api/health` | Liveness probe |

## Persistence

Scans and findings are written to `$DATA_DIR/scans.db` (SQLite, stdlib).
`DATA_DIR` defaults to the repo root; it switches to `/tmp` on Vercel
(detected via `VERCEL` env var). Schema:

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_level TEXT,
    score INTEGER,
    findings_total INTEGER NOT NULL DEFAULT 0,
    counts_json TEXT,
    created_at TEXT NOT NULL                 -- ISO-8601 UTC
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category TEXT, title TEXT, severity TEXT,
    evidence TEXT, remediation_key TEXT
);
```

**Persistence on Vercel:** the `/tmp` filesystem is wiped between cold
starts, so history is best-effort within a warm invocation window. Use the
Railway deployment for durable history.

## Deploy

- **Railway:** push to GitHub; Railway picks up `railway.json` + `Procfile`
  and runs `pip install -r requirements.txt`, then
  `uvicorn server:app --host 0.0.0.0 --port $PORT`. SQLite lives on the
  attached disk.
- **Vercel:** `vercel.json` rewrites all `/api/*` to `api/index.py`;
  static frontend served from `dist/` after `npm run build`.

## Legal & ethics

- Refuses scans of UK gov/NHS/police/military/banking domains
  (`server.py` block-list).
- Requires explicit consent flag on every request.
- Email addresses in scan output are masked before display.
- Every scan (including rejections) is recorded in the history DB for
  accountability.

## A06 catalogue

The version rules in `outdated_components_db.COMPONENT_RULES` are derived
from upstream EOL and security advisories (Apache HTTPD, nginx, PHP,
WordPress, Drupal, Joomla, jQuery, Bootstrap, lodash, Moment.js,
AngularJS) public as of January 2026. The list is intentionally
conservative — a missed flag is worse than a false alarm in an MVP. New
rules can be added by extending that one dict.
