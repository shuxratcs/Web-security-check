import json
import os
import uvicorn
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from scanner import run_sqli_scan

load_dotenv()

# Critical-infrastructure domains that must not be scanned by this tool.
# Aligns with Computer Misuse Act 1990 — scanning these without authorisation
# from the system owner could constitute a Section 1 / Section 3 offence.
BLOCKED_DOMAIN_SUFFIXES = (
    ".gov.uk", ".gov", ".mil", ".nhs.uk", ".police.uk",
)
BLOCKED_DOMAINS_EXACT = {
    # Major UK banks
    "barclays.co.uk", "hsbc.co.uk", "lloydsbank.com", "natwest.com",
    "santander.co.uk", "halifax.co.uk", "monzo.com", "starling.com",
    "tsb.co.uk", "rbs.co.uk",
    # International financial institutions
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "jpmorgan.com", "goldmansachs.com", "ubs.com", "deutsche-bank.com",
    "paypal.com", "stripe.com", "revolut.com",
}

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit.log")
AUDIT_LOG_MAX_ENTRIES = 100


def is_blocked_domain(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in BLOCKED_DOMAINS_EXACT:
        return True
    return any(host == suf.lstrip(".") or host.endswith(suf) for suf in BLOCKED_DOMAIN_SUFFIXES)


def append_audit_log(target_url: str, status: str, findings_count: int) -> None:
    """Append a single audit entry. Auto-prunes to AUDIT_LOG_MAX_ENTRIES.
    Supports accountability (BCS Code of Conduct, Section 4) and ISO/IEC 27001
    audit-trail requirements while honouring data minimisation (only metadata)."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_url,
        "status": status,
        "findings": findings_count,
    }
    try:
        lines = []
        if os.path.exists(AUDIT_LOG_PATH):
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                lines = [ln for ln in (l.strip() for l in f) if ln]
        lines.append(json.dumps(entry))
        lines = lines[-AUDIT_LOG_MAX_ENTRIES:]
        with open(AUDIT_LOG_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        # Audit logging must never block a scan; failures are silently tolerated.
        pass


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    consent: bool


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    if not request.consent:
        return {"status": "error", "message": "Legal consent required"}

    if is_blocked_domain(request.url):
        append_audit_log(request.url, "blocked", 0)
        return {
            "status": "error",
            "message": (
                "Target domain is on the protected critical-infrastructure list "
                "(government, healthcare, law enforcement, military, or major "
                "financial institutions). Scanning is refused under the Computer "
                "Misuse Act 1990."
            ),
        }

    try:
        result = run_sqli_scan(request.url)
    except Exception as e:
        append_audit_log(request.url, "error", 0)
        return {"status": "error", "message": str(e)}

    append_audit_log(
        request.url,
        result.get("status", "unknown"),
        len(result.get("findings", [])),
    )
    return result


@app.get("/api/audit")
async def get_audit_log():
    """Read-only access to the audit trail (most recent first)."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return {"entries": []}
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            entries = [json.loads(ln) for ln in (l.strip() for l in f) if ln]
        return {"entries": list(reversed(entries))}
    except Exception as e:
        return {"entries": [], "error": str(e)}


# Mount the Vite built frontend
dist_dir = os.path.join(os.path.dirname(__file__), "dist")


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    """Serve Vite-built frontend assets with appropriate caching headers."""
    path = os.path.join(dist_dir, full_path)
    if os.path.isfile(path):
        return FileResponse(path)

    index_file = os.path.join(dist_dir, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(
            index_file,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    return {"error": "Frontend build not found. Run 'npm run build' first."}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
