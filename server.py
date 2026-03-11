from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from scanner import run_sqli_scan

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
    
    # Run the real SQL Injection scanner
    return run_sqli_scan(request.url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
