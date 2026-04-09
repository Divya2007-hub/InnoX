from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import subprocess
import shutil
import os
import asyncio

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
    dependencies: Optional[str] = None


def find_npm_executable():
    for cmd in ["npm", "npm.cmd"]:
        try:
            subprocess.run([cmd, "--version"], capture_output=True, text=True, check=True)
            return cmd
        except Exception:
            continue
    return None


def run_npm_audit():
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    try:
        result = subprocess.run(
            [npm_cmd, "audit", "--json"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0 and not result.stdout:
            return {"error": result.stderr.strip() or "npm audit failed"}

        if not result.stdout:
            return {"error": "npm audit returned no output"}

        return json.loads(result.stdout)

    except Exception as e:
        return {"error": str(e)}


def analyze_npm_data(audit_data):
    if "error" in audit_data:
        return {
            "score": 0,
            "risk": "Error",
            "vulnerabilities": 0,
            "total_dependencies": 0,
            "fix": "npm audit failed",
            "message": audit_data["error"]
        }

    vulns = audit_data.get("metadata", {}).get("vulnerabilities", {})
    total_vulns = sum(vulns.values())
    total_deps = audit_data.get("metadata", {}).get("totalDependencies", 0)

    score = 100
    score -= vulns.get("critical", 0) * 40
    score -= vulns.get("high", 0) * 25
    score -= vulns.get("moderate", 0) * 15
    score -= vulns.get("low", 0) * 5
    score = max(score, 0)

    if score < 40:
        risk = "High Risk"
    elif score < 70:
        risk = "Moderate Risk"
    else:
        risk = "Secure"

    if vulns.get("critical", 0) > 0:
        fix = "⚠️ Critical issues → Run: npm audit fix --force"
    elif vulns.get("high", 0) > 2:
        fix = "⚠️ Multiple high issues → Run: npm audit fix"
    elif total_vulns > 0:
        fix = "Run: npm audit fix"
    else:
        fix = "✅ No action needed"

    return {
        "score": score,
        "risk": risk,
        "total_dependencies": total_deps,
        "vulnerabilities": total_vulns,
        "details": vulns,
        "fix": fix,
        "message": "Analysis complete"
    }


@app.get("/status")
def status():
    audit_data = run_npm_audit()
    return analyze_npm_data(audit_data)


@app.get("/package")
def load_package():
    if not os.path.exists("package.json"):
        return {"error": "package.json not found"}

    with open("package.json", "r", encoding="utf-8") as f:
        return {"content": f.read()}


async def auto_scan_loop():
    while True:
        with open("log.txt", "a", encoding="utf-8") as f:
            f.write("Auto scan executed\n")
        audit_data = run_npm_audit()
        result = analyze_npm_data(audit_data)
        print("Auto Result:", result)
        await asyncio.sleep(15)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(auto_scan_loop())


@app.post("/scan")
def scan(data: DependencyInput):
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    payload = data.dependencies or ""
    if not payload.strip():
        if not os.path.exists("package.json"):
            return {"error": "No package.json available"}

        with open("package.json", "r", encoding="utf-8") as f:
            payload = f.read()

    try:
        with open("package.json", "w", encoding="utf-8") as f:
            f.write(payload)

        subprocess.run([npm_cmd, "install"], check=True, capture_output=True, text=True)

        audit_data = run_npm_audit()
        return analyze_npm_data(audit_data)

    except Exception as e:
        return {"error": str(e)}


@app.post("/fix")
def fix():
    npm_cmd = find_npm_executable()
    if npm_cmd is None:
        return {"error": "npm not found"}

    try:
        if os.path.exists("package.json"):
            shutil.copy("package.json", "package_backup.json")

        subprocess.run([npm_cmd, "audit", "fix"], check=True, capture_output=True, text=True)

        audit_data = run_npm_audit()
        result = analyze_npm_data(audit_data)

        return {
            "status": "success",
            "message": "✅ Fix applied + security validated",
            "result": result
        }

    except Exception as e:
        if os.path.exists("package_backup.json"):
            shutil.copy("package_backup.json", "package.json")

        return {
            "status": "rollback",
            "message": "⚠️ Fix failed. System restored previous safe state",
            "error": str(e)
        }


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            dependencies = message.get("dependencies", "")

            npm_cmd = find_npm_executable()
            if npm_cmd is None:
                await websocket.send_text(json.dumps({"error": "npm not found"}))
                continue

            with open("package.json", "w", encoding="utf-8") as f:
                f.write(dependencies)

            subprocess.run([npm_cmd, "install"], check=True, capture_output=True, text=True)
            audit_data = run_npm_audit()
            result = analyze_npm_data(audit_data)
            await websocket.send_text(json.dumps(result))

    except WebSocketDisconnect:
        print("WebSocket disconnected")
