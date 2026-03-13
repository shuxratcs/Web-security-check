from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import os
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

# Mount the Vite built frontend
dist_dir = os.path.join(os.path.dirname(__file__), "dist")

@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    path = os.path.join(dist_dir, full_path)
    if os.path.isfile(path):
        return FileResponse(path)
    
    index_file = os.path.join(dist_dir, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
        
    return {"error": "Frontend build not found. Run 'npm run build' first."}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
