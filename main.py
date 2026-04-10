from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import subprocess
import json
import shutil
import os
import sys
import asyncio

# ===============================
# UTF-8 FIX (Windows safe)
# ===============================
def configure_utf8():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except:
                pass

configure_utf8()

# ===============================
# PATH SETUP
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ===============================
# FASTAPI APP
# ===============================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ===============================
# INPUT MODEL
# ===============================
class DependencyInput(BaseModel):
    dependencies: Optional[str] = None

# ===============================
# NPM DETECTION
# ===============================
def get_npm():
    for cmd in ["npm", "npm.cmd"]:
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=True)
            return cmd
        except:
            continue
    return None

# ===============================
# RUN NPM AUDIT
# ===============================
def run_audit():
    npm = get_npm()
    if not npm:
        return {"error": "npm not installed"}

    try:
        result = subprocess.run(
            [npm, "audit", "--json"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )

        if not result.stdout:
            return {"error": "No audit output"}

        return json.loads(result.stdout)

    except Exception as e:
        return {"error": str(e)}

# ===============================
# ANALYSIS ENGINE (CORE AI LOGIC)
# ===============================
def analyze(data):
    if "error" in data:
        return {
            "score": 0,
            "risk": "Error",
            "message": data["error"]
        }

    meta = data.get("metadata", {})
    vulns = meta.get("vulnerabilities", {})

    critical = vulns.get("critical", 0)
    high = vulns.get("high", 0)
    moderate = vulns.get("moderate", 0)
    low = vulns.get("low", 0)

    total = critical + high + moderate + low

    # Risk scoring logic
    score = 100 - (critical * 40 + high * 25 + moderate * 15 + low * 5)
    score = max(score, 0)

    if score < 40:
        risk = "High Risk"
    elif score < 70:
        risk = "Moderate Risk"
    else:
        risk = "Secure"

    return {
        "score": score,
        "risk": risk,
        "total_vulnerabilities": total,
        "details": vulns
    }

# ===============================
# AUTO FIX ENGINE
# ===============================
def auto_fix(vulns):
    npm = get_npm()
    if not npm:
        return "npm missing"

    try:
        if vulns.get("critical", 0) > 0:
            subprocess.run([npm, "audit", "fix", "--force"], cwd=BASE_DIR)
            return "🔥 Critical fixed"

        elif vulns.get("high", 0) > 0:
            subprocess.run([npm, "audit", "fix"], cwd=BASE_DIR)
            return "⚠️ High fixed"

        return "✅ No fix needed"

    except Exception as e:
        return str(e)

# ===============================
# AUTO SCAN LOOP (AUTONOMOUS 🔥)
# ===============================
async def auto_loop():
    while True:
        print("🔄 Running autonomous scan...")

        data = run_audit()
        result = analyze(data)

        if "details" in result:
            fix = auto_fix(result["details"])
        else:
            fix = "Skipped"

        print("Result:", result)
        print("Fix:", fix)

        await asyncio.sleep(20)

# ===============================
# LIFESPAN EVENT
# ===============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(auto_loop())
    yield
    task.cancel()

app = FastAPI(lifespan=lifespan)

# ===============================
# ROUTES
# ===============================
@app.get("/")
def home():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

@app.get("/scan")
def scan():
    data = run_audit()
    result = analyze(data)

    if "details" in result:
        result["auto_fix"] = auto_fix(result["details"])

    return result

@app.post("/fix")
def fix():
    npm = get_npm()
    if not npm:
        return {"error": "npm not found"}

    backup = os.path.join(BASE_DIR, "package_backup.json")
    pkg = os.path.join(BASE_DIR, "package.json")

    try:
        if os.path.exists(pkg):
            shutil.copy(pkg, backup)

        subprocess.run([npm, "audit", "fix"], cwd=BASE_DIR)

        return {"status": "success"}

    except Exception as e:
        if os.path.exists(backup):
            shutil.copy(backup, pkg)

        return {"status": "rollback", "error": str(e)}

# ===============================
# WEBSOCKET (REAL-TIME SCAN)
# ===============================
@app.websocket("/ws")
async def websocket_scan(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            await ws.receive_text()

            data = run_audit()
            result = analyze(data)

            await ws.send_text(json.dumps(result))

    except WebSocketDisconnect:
        print("Disconnected")
