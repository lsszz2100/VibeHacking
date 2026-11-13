#!/usr/bin/env python3
"""
scaffold_lab.py — VibeHacking Hands-on Lab Scaffolder
Creates a standard, battle-tested hands-on vulnerability lab directory structure
with 127.0.0.1 binding, FastAPI server, 4-stage progression, and Pytest suite.
"""

import argparse
import os
import sys
from pathlib import Path

def get_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for p in [current] + list(current.parents):
        if (p / "labs").exists() and (p / "vhack.py").exists():
            return p
    return Path.cwd()

DOCKERFILE_TEMPLATE = """FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE {port}

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{port}"]
"""

COMPOSE_TEMPLATE = """version: '3.8'

services:
  {slug}_lab:
    build: .
    container_name: vhack_lab_{lab_id}
    ports:
      - "127.0.0.1:{port}:{port}"
    restart: unless-stopped
    environment:
      - PYTHONUNBUFFERED=1
"""

REQUIREMENTS_TEMPLATE = """fastapi>=0.110.0
uvicorn>=0.28.0
jinja2>=3.1.0
pydantic>=2.0.0
pytest>=8.0.0
httpx>=0.27.0
requests>=2.31.0
"""

APP_MAIN_TEMPLATE = '''#!/usr/bin/env python3
"""
Lab {lab_id} — {title_ko} ({title_en})
Target Port: {port}
4-Stage progressive vulnerability & defense simulation
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Lab {lab_id}: {title_en}", version="1.0.0")

STATE = {{
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
}}

FLAGS = {{
    "stage1": "FLAG{{vhack_{slug}_st1_initial_recon}}",
    "stage2": "FLAG{{vhack_{slug}_st2_vulnerability_exploit}}",
    "stage3": "FLAG{{vhack_{slug}_st3_privilege_escalation}}",
    "stage4": "FLAG{{vhack_{slug}_st4_defense_and_mitigation}}",
}}

@app.get("/api/status")
async def get_status():
    solved = sum(1 for v in STATE.values() if v)
    return {{
        "lab_id": "{lab_id}",
        "name": "{title_en}",
        "port": {port},
        "status": "running",
        "total_stages": 4,
        "solved_count": solved,
        "stages": STATE,
    }}

@app.get("/", response_class=HTMLResponse)
async def index():
    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>Lab {lab_id} - {title_ko}</title>
        <style>
            body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
            .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; max-width: 800px; margin: auto; }}
            h1 {{ color: #58a6ff; }}
            .badge {{ background: #238636; color: white; padding: 4px 8px; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🔬 Lab {lab_id}: {title_ko}</h1>
            <p><strong>English:</strong> {title_en}</p>
            <p><strong>Port:</strong> {port} (127.0.0.1 bound)</p>
            <p><span class="badge">Running</span> 4-Stage Progressive Simulation Ready</p>
        </div>
    </body>
    </html>
    """

class StageAction(BaseModel):
    action: str
    payload: str = ""

@app.post("/api/stage1/verify")
async def verify_stage1(action: StageAction):
    if action.action == "recon":
        STATE["stage1_solved"] = True
        return {{"status": "success", "flag": FLAGS["stage1"]}}
    return JSONResponse(status_code=400, content={{"error": "Invalid action"}})

@app.post("/api/stage2/verify")
async def verify_stage2(action: StageAction):
    if action.action == "exploit" and "payload" in action.payload:
        STATE["stage2_solved"] = True
        return {{"status": "success", "flag": FLAGS["stage2"]}}
    return JSONResponse(status_code=400, content={{"error": "Invalid exploit"}})

@app.post("/api/stage3/verify")
async def verify_stage3(action: StageAction):
    if action.action == "escalate":
        STATE["stage3_solved"] = True
        return {{"status": "success", "flag": FLAGS["stage3"]}}
    return JSONResponse(status_code=400, content={{"error": "Invalid escalation"}})

@app.post("/api/stage4/verify")
async def verify_stage4(action: StageAction):
    if action.action == "mitigate":
        STATE["stage4_solved"] = True
        return {{"status": "success", "flag": FLAGS["stage4"]}}
    return JSONResponse(status_code=400, content={{"error": "Invalid mitigation"}})
'''

TEST_TEMPLATE = '''#!/usr/bin/env python3
"""Pytest verification suite for Lab {lab_id} ({title_en})."""

import importlib.util
import os
import sys
import pytest
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_{lab_id}_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_{lab_id}_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
STATE = _mod.STATE
FLAGS = _mod.FLAGS

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    for k in STATE:
        STATE[k] = False

def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "running"
    assert data["port"] == {port}
    assert data["total_stages"] == 4
    assert data["solved_count"] == 0

def test_index_page():
    res = client.get("/")
    assert res.status_code == 200
    assert "Lab {lab_id}" in res.text

def test_stage1_recon():
    res = client.post("/api/stage1/verify", json={{"action": "recon"}})
    assert res.status_code == 200
    assert res.json()["flag"] == FLAGS["stage1"]
    assert STATE["stage1_solved"] is True

def test_stage2_exploit():
    res = client.post("/api/stage2/verify", json={{"action": "exploit", "payload": "exploit_payload"}})
    assert res.status_code == 200
    assert res.json()["flag"] == FLAGS["stage2"]

def test_stage3_escalate():
    res = client.post("/api/stage3/verify", json={{"action": "escalate"}})
    assert res.status_code == 200
    assert res.json()["flag"] == FLAGS["stage3"]

def test_stage4_mitigate():
    res = client.post("/api/stage4/verify", json={{"action": "mitigate"}})
    assert res.status_code == 200
    assert res.json()["flag"] == FLAGS["stage4"]
'''

README_TEMPLATE = """# Lab {lab_id} — {title_ko} ({title_en})

## 📌 실습 개요
- **실습 번호**: Lab {lab_id}
- **포트 바인딩**: `127.0.0.1:{port}`
- **난이도**: Intermediate ~ Advanced
- **주요 테마**: {title_ko} 실전 분석 및 침투 방어 시뮬레이션

## 🚀 실습 구동 방법
```bash
# Docker Compose 기동
docker compose up -d

# 상태 확인
curl http://127.0.0.1:{port}/api/status

# vhack CLI를 통한 자동 테스트
python3 vhack.py lab test {lab_id}
```

## 🎯 4단계 실습 시나리오
1. **Stage 1 (Recon)**: 타겟 표면 정찰 및 취약 엔드포인트 식별
2. **Stage 2 (Exploit)**: 취약점 페이로드 전송 및 임의 코드/권한 획득
3. **Stage 3 (Escalate)**: 신뢰 경계 우회 및 루트/관리자 권한 상승
4. **Stage 4 (Mitigate)**: 패치 정책 적용 및 공격 방어 검증
"""

def scaffold(lab_id_str: str, slug: str, title_ko: str, title_en: str, dry_run: bool = False):
    lab_id = int(lab_id_str)
    port = 8000 + lab_id
    repo_root = get_repo_root()
    lab_dir_name = f"{lab_id:02d}_{slug}"
    target_dir = repo_root / "labs" / lab_dir_name

    print(f"🛠️ Scaffolding Lab {lab_id:02d}: {slug}")
    print(f"  Target Dir: {target_dir}")
    print(f"  Port: {port} (127.0.0.1:{port})")

    if dry_run:
        print("  [Dry-run] Directory creation skipped.")
        return target_dir

    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "app" / "templates").mkdir(parents=True, exist_ok=True)
    (target_dir / "tests").mkdir(parents=True, exist_ok=True)

    # Write files
    (target_dir / "Dockerfile").write_text(DOCKERFILE_TEMPLATE.format(port=port), encoding="utf-8")
    (target_dir / "docker-compose.yml").write_text(COMPOSE_TEMPLATE.format(slug=slug, lab_id=lab_id_str, port=port), encoding="utf-8")
    (target_dir / "requirements.txt").write_text(REQUIREMENTS_TEMPLATE, encoding="utf-8")
    (target_dir / "app" / "main.py").write_text(APP_MAIN_TEMPLATE.format(lab_id=lab_id_str, slug=slug, port=port, title_ko=title_ko, title_en=title_en), encoding="utf-8")
    (target_dir / "tests" / f"test_{slug}_lab.py").write_text(TEST_TEMPLATE.format(lab_id=lab_id_str, slug=slug, port=port, title_en=title_en), encoding="utf-8")
    (target_dir / "README.md").write_text(README_TEMPLATE.format(lab_id=lab_id_str, port=port, title_ko=title_ko, title_en=title_en), encoding="utf-8")

    print(f"  ✅ Generated Dockerfile, docker-compose.yml, app/main.py, tests/test_{slug}_lab.py, README.md")
    return target_dir

def main():
    parser = argparse.ArgumentParser(description="Scaffold a new VibeHacking hands-on lab.")
    parser.add_argument("--id", required=True, help="Lab ID number (e.g. 56)")
    parser.add_argument("--slug", required=True, help="Lab slug name (e.g. quantum_safe_tls)")
    parser.add_argument("--title-ko", required=True, help="Korean title")
    parser.add_argument("--title-en", required=True, help="English title")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without writing files")
    args = parser.parse_args()

    scaffold(args.id, args.slug, args.title_ko, args.title_en, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
