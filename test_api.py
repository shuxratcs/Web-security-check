from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import time

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

    # Mock data for testing the new MVP+ UI
    return {
        "status": "Vulnerable",
        "risk_level": "Critical",
        "tech_stack": "PHP/MySQL (Detected by AI)",
        "findings": [
            {
                "type": "SQL Injection",
                "url": f"{request.url}/search?id=1",
                "payload": "1' OR '1'='1",
                "confidence": 98,
                "reason": "AI Judge detected a change in database response structure and timing that matches Boolean-based SQLi.",
                "remediation": "### Fix: Use Prepared Statements\n\n```php\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $_GET['id']]);\n$user = $stmt->fetch();\n```"
            }
        ],
        "details": [
            "[INFO] Initializing SentinelAI Engine...",
            f"[INFO] Targeting: {request.url}",
            "[INFO] AI Recon: Identifying technology stack...",
            "[SUCCESS] Stack detected: PHP/MySQL",
            "[SCANNING] Testing form fields with adaptive payloads...",
            "[WARNING] Potential SQLi found in parameter 'id'",
            "[INFO] Triggering AI Judge for confirmation...",
            "[CRITICAL] AI confirmed vulnerability at /search?id=1",
            "[SUCCESS] Analysis complete. Vulnerabilities found!"
        ]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
