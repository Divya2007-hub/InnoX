from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json
import subprocess
import shutil
import os

app = FastAPI()
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
async def root():
    return FileResponse("index.html")

# ✅ CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DependencyInput(BaseModel):
    dependencies: str


def find_npm_executable():
    for cmd in ["npm", "npm.cmd"]:
        try:
            subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True)
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None


# 🧠 Run npm audit
def run_npm_audit():
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm executable not found on PATH"}

    try:
        result = subprocess.run(
            [npm_cmd, "audit", "--json"],
            capture_output=True,
            text=True
        )

        if not result.stdout:
            return {"error": result.stderr.strip() or "npm audit returned no output"}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "Failed to parse npm audit JSON output", "details": result.stderr.strip()}
    except Exception as e:
        return {"error": str(e)}


# 🧠 Analyze vulnerabilities
def analyze_npm_data(audit_data):
    if "error" in audit_data:
        return {
            "score": 0,
            "risk": "Error",
            "total": 0,
            "vulnerabilities": 0,
            "details": [],
            "fix": audit_data.get("details", "npm audit failed"),
            "error": audit_data["error"]
        }

    vulnerabilities = audit_data.get("metadata", {}).get("vulnerabilities", {})

    total_vulns = sum(vulnerabilities.values())
    total_deps = audit_data.get("metadata", {}).get("totalDependencies", 0)

    score = 100

    score -= vulnerabilities.get("critical", 0) * 40
    score -= vulnerabilities.get("high", 0) * 25
    score -= vulnerabilities.get("moderate", 0) * 15
    score -= vulnerabilities.get("low", 0) * 5

    score = max(score, 0)

    if total_vulns == 0:
        risk = "Secure"
    elif total_vulns <= 2:
        risk = "Moderate"
    else:
        risk = "High Risk"

    return {
        "score": score,
        "risk": risk,
        "total": total_deps,
        "vulnerabilities": total_vulns,
        "details": vulnerabilities,
        "fix": "Run: npm audit fix"
    }


# 🌐 SCAN API
@app.post("/scan")
def scan(data: DependencyInput):
    try:
        # Save incoming package.json
        with open("package.json", "w", encoding="utf-8") as f:
            f.write(data.dependencies)

        npm_cmd = find_npm_executable()
        if npm_cmd is None:
            return {"error": "npm executable not found on PATH"}

        # Install dependencies
        subprocess.run([npm_cmd, "install"], check=True, capture_output=True, text=True)

        audit_data = run_npm_audit()
        return analyze_npm_data(audit_data)

    except Exception as e:
        return {"error": str(e)}


# 🛠 FIX API (REAL FIX + ROLLBACK)
@app.post("/fix")
def fix():
    try:
        # Backup
        if os.path.exists("package.json"):
            shutil.copy("package.json", "package_backup.json")

        npm_cmd = find_npm_executable()
        if npm_cmd is None:
            return {"status": "error", "message": "npm executable not found on PATH"}

        # Run fix
        subprocess.run([npm_cmd, "audit", "fix"], check=True, capture_output=True, text=True)

        # Re-scan after fix
        audit_data = run_npm_audit()
        result = analyze_npm_data(audit_data)

        return {
            "status": "success",
            "message": "Fix applied successfully",
            "result": result
        }

    except Exception as e:
        # Rollback if failed
        if os.path.exists("package_backup.json"):
            shutil.copy("package_backup.json", "package.json")

        return {
            "status": "rollback",
            "message": "Fix failed, rollback applied",
            "error": str(e)
        }


# 🔌 WebSocket
@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            dependencies = message.get("dependencies", "")

            # Save file
            with open("package.json", "w", encoding="utf-8") as f:
                f.write(dependencies)

            npm_cmd = find_npm_executable()
            if npm_cmd is None:
                await websocket.send_text(json.dumps({"error": "npm executable not found on PATH"}))
                continue

            # Install dependencies
            subprocess.run([npm_cmd, "install"], check=True, capture_output=True, text=True)

            audit_data = run_npm_audit()
            result = analyze_npm_data(audit_data)

            await websocket.send_text(json.dumps(result))

    except WebSocketDisconnect:
        print("WebSocket disconnected")