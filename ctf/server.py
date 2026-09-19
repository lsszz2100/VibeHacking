"""VibeHacking CTF Competition & Scoreboard Engine (FastAPI)."""

import os
import sys
import time
import math
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="VibeHacking CTF Arena", version="1.0.0")

# In-memory or state persistence
class CTFState:
    def __init__(self):
        self.teams: Dict[str, dict] = {
            "Admin_RedTeam": {"name": "Admin_RedTeam", "score": 0, "solves": [], "last_solve": 0},
            "BlueGuardians": {"name": "BlueGuardians", "score": 0, "solves": [], "last_solve": 0},
        }
        self.challenges: Dict[str, dict] = {
            "LAB19_ROOT": {
                "id": "LAB19_ROOT",
                "title": "DroidShield: Root Detection Bypass",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{dr01d_r00t_byp4ss_succ3ss_9281}",
                "solves": [],
            },
            "LAB19_PINNING": {
                "id": "LAB19_PINNING",
                "title": "DroidShield: Universal SSL Unpinning",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{ss1_p1nn1ng_fr1da_unp1nn3d_7143}",
                "solves": [],
            },
            "LAB19_JNI": {
                "id": "LAB19_JNI",
                "title": "DroidShield: JNI Native Return Hijack",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{jn1_n4t1v3_h00k_l1c3ns3_p4ss_3301}",
                "solves": [],
            },
            "LAB20_SEH": {
                "id": "LAB20_SEH",
                "title": "WinAppSec: SEH pop-pop-ret Overwrite",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{w1n_seh_0v3rwr1t3_p0p_p0p_r3t_9918}",
                "solves": [],
            },
            "LAB20_EGG": {
                "id": "LAB20_EGG",
                "title": "WinAppSec: 32-Byte Egg Hunter",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{3gg_hunt3r_w00tw00t_m3m_f0und_4412}",
                "solves": [],
            },
            "LAB20_HEVD": {
                "id": "LAB20_HEVD",
                "title": "WinAppSec: HEVD Kernel Token Stealing",
                "category": "kernel",
                "initial_points": 500,
                "flag": "FLAG{h3vd_r1ng0_t0k3n_st34l1ng_pwn3d_5532}",
                "solves": [],
            },
        }
        self.submissions_log: List[dict] = []

    def get_points(self, chal_id: str) -> int:
        """Dynamic Scoring: solves 수가 늘어날수록 점수 차감 (최저 100점)"""
        c = self.challenges.get(chal_id)
        if not c:
            return 100
        count = len(c["solves"])
        if count <= 1:
            return 500
        # Decay formula: 500 * (0.85 ** (count - 1)) min 100
        decayed = int(500 * (0.85 ** (count - 1)))
        return max(100, decayed)

state = CTFState()


class TeamRegisterRequest(BaseModel):
    team_name: str


class FlagSubmitRequest(BaseModel):
    team_name: str
    chal_id: str
    flag: str


@app.get("/api/ctf/challenges")
def get_challenges():
    """모의해킹 대회 문제 목록 및 현재 실시간 배점 반환"""
    data = []
    for cid, c in state.challenges.items():
        data.append({
            "id": cid,
            "title": c["title"],
            "category": c["category"],
            "current_points": state.get_points(cid),
            "solves_count": len(c["solves"]),
            "first_blood": c["solves"][0] if c["solves"] else None,
        })
    return {"challenges": data}


@app.get("/api/ctf/scoreboard")
def get_scoreboard():
    """실시간 스코어보드 순위 및 점수 반환"""
    board = []
    for tname, t in state.teams.items():
        board.append({
            "team": tname,
            "score": t["score"],
            "solves_count": len(t["solves"]),
            "last_solve": t["last_solve"],
        })
    # Sort by score desc, then last_solve asc
    board.sort(key=lambda x: (-x["score"], x["last_solve"]))
    for i, item in enumerate(board, 1):
        item["rank"] = i
    return {"scoreboard": board, "recent_activity": state.submissions_log[-10:]}


@app.post("/api/ctf/register")
def register_team(req: TeamRegisterRequest):
    name = req.team_name.strip()
    if not name or len(name) < 2:
        raise HTTPException(status_code=400, detail="Team name too short")
    if name in state.teams:
        return {"status": "exists", "message": "Team already registered", "team": name}
    state.teams[name] = {"name": name, "score": 0, "solves": [], "last_solve": 0}
    return {"status": "registered", "team": name}


@app.post("/api/ctf/submit")
def submit_flag(req: FlagSubmitRequest):
    """플래그 검증 및 실시간 점수 반영"""
    tname = req.team_name.strip()
    if tname not in state.teams:
        raise HTTPException(status_code=404, detail="Team not found. Please register first.")

    chal = state.challenges.get(req.chal_id)
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge not found")

    team = state.teams[tname]
    if req.chal_id in team["solves"]:
        return {"status": "already_solved", "message": "Challenge already solved by your team."}

    submitted_flag = req.flag.strip()
    is_correct = (submitted_flag == chal["flag"])

    now = int(time.time())
    state.submissions_log.append({
        "time": now,
        "team": tname,
        "chal_id": req.chal_id,
        "correct": is_correct,
    })

    if not is_correct:
        return {"status": "wrong_flag", "message": "Incorrect flag! Try again."}

    # First blood check
    is_first_blood = (len(chal["solves"]) == 0)
    pts = state.get_points(req.chal_id)
    if is_first_blood:
        pts += 50  # First Blood bonus

    chal["solves"].append(tname)
    team["solves"].append(req.chal_id)
    team["score"] += pts
    team["last_solve"] = now

    return {
        "status": "correct",
        "message": f"Correct! Earned {pts} points." + (" [FIRST BLOOD! 🩸]" if is_first_blood else ""),
        "points_awarded": pts,
        "first_blood": is_first_blood,
        "total_score": team["score"],
    }


@app.get("/", response_class=HTMLResponse)
def ctf_home():
    return """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="UTF-8">
      <title>VibeHacking CTF Arena & Scoreboard</title>
      <style>
        body { background: #0b0f19; color: #f3f4f6; font-family: monospace; padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { color: #ec4899; margin-bottom: 0.5rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; }
        th, td { padding: 12px; border: 1px solid #1f2937; text-align: left; }
        th { background: #1f2937; color: #38bdf8; }
        .rank-1 { color: #f59e0b; font-weight: bold; }
        .badge { background: #ec4899; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; }
        .input-box { background: #1f2937; border: 1px solid #374151; color: white; padding: 8px; border-radius: 4px; margin-right: 8px; }
        button { background: #ec4899; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🏆 VibeHacking CTF Arena (Scoreboard)</h1>
        <p>실전 랩 & 침투 시나리오 플래그 채점 및 실시간 순위표</p>

        <div style="margin: 1.5rem 0; padding: 1rem; background: #1e293b; border-radius: 6px;">
          <h3>🚩 플래그 제출 (Flag Submit)</h3>
          <input id="teamInput" class="input-box" placeholder="팀 이름 (예: Admin_RedTeam)">
          <input id="chalInput" class="input-box" placeholder="문제 ID (예: LAB19_ROOT)">
          <input id="flagInput" class="input-box" style="width: 300px;" placeholder="FLAG{...}">
          <button onclick="submitFlag()">제출</button>
          <span id="submitResult" style="margin-left: 10px;"></span>
        </div>

        <h2>📊 실시간 리더보드 (Scoreboard)</h2>
        <table>
          <thead>
            <tr><th>순위</th><th>팀 이름</th><th>점수</th><th>해결 수</th></tr>
          </thead>
          <tbody id="boardBody"></tbody>
        </table>
      </div>

      <script>
        async function loadBoard() {
          const res = await fetch('/api/ctf/scoreboard');
          const data = await res.json();
          const tbody = document.getElementById('boardBody');
          tbody.innerHTML = '';
          data.scoreboard.forEach(item => {
            const tr = document.createElement('tr');
            if (item.rank === 1) tr.className = 'rank-1';
            tr.innerHTML = `<td>#${item.rank}</td><td>${item.team}</td><td>${item.score} pts</td><td>${item.solves_count}</td>`;
            tbody.appendChild(tr);
          });
        }

        async function submitFlag() {
          const team = document.getElementById('teamInput').value;
          const chal = document.getElementById('chalInput').value;
          const flag = document.getElementById('flagInput').value;
          const resSpan = document.getElementById('submitResult');
          
          try {
            const res = await fetch('/api/ctf/submit', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({team_name: team, chal_id: chal, flag: flag})
            });
            const data = await res.json();
            resSpan.innerText = data.message;
            resSpan.style.color = data.status === 'correct' ? '#4ade80' : '#f87171';
            loadBoard();
          } catch (e) {
            resSpan.innerText = '오류 발생: ' + e.message;
          }
        }

        loadBoard();
        setInterval(loadBoard, 4000);
      </script>
    </body>
    </html>
    """
