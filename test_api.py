from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

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
    
    # Здесь позже будет вызов sqlmap
    return {
        "target": request.url,
        "status": "Scanning Completed",
        "vulnerability_found": "SQL Injection (Boolean-based)",
        "risk_score": "9.8/10"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
