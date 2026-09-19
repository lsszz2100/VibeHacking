"""VibeHacking Unified Web Portal & Management Server (FastAPI)."""

import os
import sys
import subprocess
import socket
import shutil
try:
    import psutil
except ImportError:
    psutil = None
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
LABS_DIR = REPO_ROOT / "labs"

app = FastAPI(title="VibeHacking Unified Portal", version="1.0.0")

# Import LABS metadata from vhack.py
sys.path.insert(0, str(REPO_ROOT))
try:
    from vhack import LABS
except ImportError:
    LABS = {}

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)


def check_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.15)
        return s.connect_ex(("127.0.0.1", port)) == 0


def get_lab_port(lab_id: str) -> Optional[int]:
    meta = LABS.get(lab_id, {})
    url = meta.get("url", "")
    import re
    m = re.search(r":(\d{4,5})", url)
    if m:
        return int(m.group(1))
    return None


@app.get("/api/system/status")
def get_system_status():
    """시스템 리소스 및 핵심 도구 가동 현황 진단"""
    try:
        cpu_pct = psutil.cpu_percent(interval=0.1) if psutil else 0.0
        mem = psutil.virtual_memory() if psutil else None
        disk = shutil.disk_usage(str(REPO_ROOT))
        disk_free_gb = disk.free // (1024 ** 3)
    except Exception:
        cpu_pct = 0.0
        mem = None
        disk_free_gb = 10

    # Check docker command
    docker_available = shutil.which("docker") is not None
    docker_running = False
    if docker_available:
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
            docker_running = (res.returncode == 0)
        except Exception:
            docker_running = False

    return {
        "cpu_usage_percent": cpu_pct,
        "memory_used_mb": (mem.used // (1024 ** 2)) if mem else 0,
        "memory_total_mb": (mem.total // (1024 ** 2)) if mem else 0,
        "disk_free_gb": disk_free_gb,
        "docker_installed": docker_available,
        "docker_running": docker_running,
        "total_labs": len(LABS),
    }


@app.get("/api/labs")
def list_labs():
    """20개 전체 실습 랩의 최신 상태 및 메타데이터 반환"""
    result = []
    for lid, meta in sorted(LABS.items()):
        port = get_lab_port(lid)
        is_port_active = check_port_open(port) if port else False
        result.append({
            "id": lid,
            "name": meta["name"],
            "dir": meta["dir"],
            "desc": meta["desc"],
            "url": meta["url"],
            "port": port,
            "difficulty": meta["difficulty"],
            "related": meta["related"],
            "is_running": is_port_active,
        })
    return {"labs": result, "total": len(result)}


@app.post("/api/labs/{lab_id}/start")
def start_lab(lab_id: str):
    """랩 Docker 컨테이너 가동"""
    if lab_id not in LABS:
        raise HTTPException(status_code=404, detail="Lab ID not found")
    
    meta = LABS[lab_id]
    target_dir = LABS_DIR / meta["dir"]
    compose_file = target_dir / "docker-compose.yml"
    
    if not compose_file.exists():
        return {"status": "simulated", "message": f"Lab {lab_id} runs without compose or standalone."}

    cmd = ["docker", "compose", "up", "-d"]
    try:
        proc = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, timeout=60)
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/labs/{lab_id}/stop")
def stop_lab(lab_id: str):
    """랩 Docker 컨테이너 중지"""
    if lab_id not in LABS:
        raise HTTPException(status_code=404, detail="Lab ID not found")

    meta = LABS[lab_id]
    target_dir = LABS_DIR / meta["dir"]
    compose_file = target_dir / "docker-compose.yml"
    
    if not compose_file.exists():
        return {"status": "simulated", "message": f"Lab {lab_id} has no compose file."}

    cmd = ["docker", "compose", "down"]
    try:
        proc = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, timeout=60)
        return {
            "status": "success" if proc.returncode == 0 else "error",
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/labs/{lab_id}/test")
def test_lab(lab_id: str):
    """지정 랩 자동 무결성 테스트 실행"""
    if lab_id not in LABS:
        raise HTTPException(status_code=404, detail="Lab ID not found")

    meta = LABS[lab_id]
    test_dir = LABS_DIR / meta["dir"] / "tests"
    if not test_dir.exists():
        return {"status": "skipped", "message": "No test directory found", "passed": 0}

    cmd = [sys.executable, "-m", "pytest", str(test_dir), "-q"]
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=90)
        return {
            "status": "passed" if proc.returncode == 0 else "failed",
            "output": proc.stdout or proc.stderr,
            "success": (proc.returncode == 0),
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "success": False}


@app.get("/")
def portal_home():
    html_file = STATIC_DIR / "index.html"
    if html_file.exists():
        return FileResponse(str(html_file))
    return HTMLResponse("<h1>VibeHacking Portal Initializing...</h1>")
