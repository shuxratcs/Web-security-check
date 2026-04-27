import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from scanner import run_sqli_scan, scan_target

load_dotenv()

# Critical-infrastructure scope restrictions (Computer Misuse Act 1990).
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
        pass


def _validate(url: str, consent: bool):
    if not consent:
        return "Legal consent required."
    if not url:
        return "URL is required."
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    if is_blocked_domain(url):
        return (
            "Target is on the protected critical-infrastructure list "
            "(government, healthcare, law enforcement, military, or major "
            "financial institutions). Scanning is refused under the "
            "Computer Misuse Act 1990."
        )
    return None


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    consent: bool


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    err = _validate(request.url, request.consent)
    if err:
        append_audit_log(request.url or "", "rejected", 0)
        return {"status": "error", "message": err}

    try:
        result = run_sqli_scan(request.url)
    except Exception as e:
        append_audit_log(request.url, "error", 0)
        return {"status": "error", "message": str(e)[:500]}

    append_audit_log(
        request.url,
        result.get("status", "unknown"),
        len(result.get("findings", [])),
    )
    return result


@app.get("/api/scan/stream")
def scan_stream(url: str = Query(...), consent: bool = Query(False)):
    """SSE endpoint streaming scan progress in real time."""

    def event_gen():
        nonlocal_summary = {"status": "unknown", "findings_total": 0}

        err = _validate(url, consent)
        if err:
            payload = {"type": "error", "message": err}
            yield f"data: {json.dumps(payload)}\n\n"
            yield "event: end\ndata: {}\n\n"
            append_audit_log(url or "", "rejected", 0)
            return

        try:
            for ev in scan_target(url):
                if ev.get("type") == "done":
                    nonlocal_summary = ev.get("summary", nonlocal_summary)
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)[:500]})}\n\n"

        yield "event: end\ndata: {}\n\n"
        append_audit_log(
            url,
            nonlocal_summary.get("status", "unknown"),
            nonlocal_summary.get("findings_total", 0),
        )

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/audit")
async def get_audit_log():
    if not os.path.exists(AUDIT_LOG_PATH):
        return {"entries": []}
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            entries = [json.loads(ln) for ln in (l.strip() for l in f) if ln]
        return {"entries": list(reversed(entries))}
    except Exception as e:
        return {"entries": [], "error": str(e)[:200]}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# Mount the Vite-built frontend as a catch-all.
dist_dir = os.path.join(os.path.dirname(__file__), "dist")


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
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
