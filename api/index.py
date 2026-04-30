"""Vercel Serverless Function — SentinelAI API.

Wraps the FastAPI app for deployment as a single Vercel Python function.
All /api/* requests are routed here via vercel.json rewrites.
"""

import json
import os
import sys

# Ensure project root is on the path so scanner modules are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from scanner import run_sqli_scan, scan_target

# ─── Domain Restrictions (Computer Misuse Act 1990) ───────────────────
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


# ─── FastAPI App ──────────────────────────────────────────────────────
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
        return {"status": "error", "message": err}
    try:
        result = run_sqli_scan(request.url)
    except Exception as e:
        return {"status": "error", "message": str(e)[:500]}
    return result


@app.get("/api/scan/stream")
def scan_stream(url: str = Query(...), consent: bool = Query(False)):
    """SSE endpoint streaming scan progress in real time."""

    def event_gen():
        err = _validate(url, consent)
        if err:
            payload = {"type": "error", "message": err}
            yield f"data: {json.dumps(payload)}\n\n"
            yield "event: end\ndata: {}\n\n"
            return

        try:
            for ev in scan_target(url):
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)[:500]})}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}
