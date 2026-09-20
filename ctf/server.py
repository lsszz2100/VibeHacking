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
app = FastAPI(title="VibeHacking CTF Arena", version="1.1.0")


def compute_dynamic_score(
    initial_points: int = 500,
    solves_count: int = 0,
    min_points: int = 100,
    decay_rate: float = 0.85,
) -> int:
    """
    Dynamic Scoring 알고리즘:
    - 0 또는 1 solve: initial_points (기본 500pt)
    - solves_count >= 2: initial_points * (decay_rate ** (solves_count - 1))
    - 최소 보장 점수: min_points (기본 100pt)
    """
    if solves_count <= 1:
        return initial_points
    decayed = int(initial_points * (decay_rate ** (solves_count - 1)))
    return max(min_points, decayed)


class CTFState:
    def __init__(self):
        self.teams: Dict[str, dict] = {
            "Admin_RedTeam": {"name": "Admin_RedTeam", "score": 0, "solves": [], "first_bloods": [], "last_solve": 0},
            "BlueGuardians": {"name": "BlueGuardians", "score": 0, "solves": [], "first_bloods": [], "last_solve": 0},
        }
        self.challenges: Dict[str, dict] = {
            "LAB01_SQLI": {
                "id": "LAB01_SQLI",
                "title": "WebSec: SQL Injection Auth Bypass",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{sqli_admin_bypass_success_01}",
                "solves": [],
                "first_blood": None,
            },
            "LAB01_XSS": {
                "id": "LAB01_XSS",
                "title": "WebSec: Stored XSS Session Hijacking",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{stored_xss_cookie_theft_01}",
                "solves": [],
                "first_blood": None,
            },
            "LAB02_CMDI": {
                "id": "LAB02_CMDI",
                "title": "AppSec: Command Injection Shell",
                "category": "system",
                "initial_points": 500,
                "flag": "FLAG{cmdi_reverse_shell_02}",
                "solves": [],
                "first_blood": None,
            },
            "LAB03_TRAVERSAL": {
                "id": "LAB03_TRAVERSAL",
                "title": "WebSec: Directory Traversal Leak",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{lfi_traversal_passwd_leak_03}",
                "solves": [],
                "first_blood": None,
            },
            "LAB04_SSRF": {
                "id": "LAB04_SSRF",
                "title": "Cloud: Metadata SSRF Pivot",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{ssrf_cloud_metadata_token_04}",
                "solves": [],
                "first_blood": None,
            },
            "LAB05_AUTH": {
                "id": "LAB05_AUTH",
                "title": "AuthSec: JWT None Algorithm Forgery",
                "category": "auth",
                "initial_points": 500,
                "flag": "FLAG{jwt_alg_none_admin_forged_05}",
                "solves": [],
                "first_blood": None,
            },
            "LAB06_DESERIAL": {
                "id": "LAB06_DESERIAL",
                "title": "AppSec: Pickle Deserialization RCE",
                "category": "appsec",
                "initial_points": 500,
                "flag": "FLAG{pickle_deserial_rce_06}",
                "solves": [],
                "first_blood": None,
            },
            "LAB07_GRAPHQL": {
                "id": "LAB07_GRAPHQL",
                "title": "WebSec: GraphQL Introspection & BOLA",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{graphql_introspection_leak_07}",
                "solves": [],
                "first_blood": None,
            },
            "LAB08_RACE": {
                "id": "LAB08_RACE",
                "title": "Logic: Race Condition Double Spend",
                "category": "logic",
                "initial_points": 500,
                "flag": "FLAG{race_condition_toctou_pwn_08}",
                "solves": [],
                "first_blood": None,
            },
            "LAB09_XXE": {
                "id": "LAB09_XXE",
                "title": "WebSec: XML External Entity Exfil",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{xxe_file_disclosure_09}",
                "solves": [],
                "first_blood": None,
            },
            "LAB10_WEBSOCKET": {
                "id": "LAB10_WEBSOCKET",
                "title": "Realtime: CSWSH Stream Hijacking",
                "category": "network",
                "initial_points": 500,
                "flag": "FLAG{cswsh_stream_hijack_10}",
                "solves": [],
                "first_blood": None,
            },
            "LAB11_CACHE": {
                "id": "LAB11_CACHE",
                "title": "WebSec: Web Cache Deception",
                "category": "web",
                "initial_points": 500,
                "flag": "FLAG{cache_deception_leak_11}",
                "solves": [],
                "first_blood": None,
            },
            "LAB12_CLICKJACK": {
                "id": "LAB12_CLICKJACK",
                "title": "Client: Nested Frame Clickjacking",
                "category": "client",
                "initial_points": 500,
                "flag": "FLAG{clickjacking_admin_action_12}",
                "solves": [],
                "first_blood": None,
            },
            "LAB13_CLOUDMETA": {
                "id": "LAB13_CLOUDMETA",
                "title": "Cloud: IMDSv2 Token Role Pivot",
                "category": "cloud",
                "initial_points": 500,
                "flag": "FLAG{cloud_metadata_v2_role_13}",
                "solves": [],
                "first_blood": None,
            },
            "LAB14_AD": {
                "id": "LAB14_AD",
                "title": "AD: Kerberoasting SPN Ticket Crack",
                "category": "ad",
                "initial_points": 500,
                "flag": "FLAG{ad_kerberoast_spn_ticket_14}",
                "solves": [],
                "first_blood": None,
            },
            "LAB15_CICD": {
                "id": "LAB15_CICD",
                "title": "DevSecOps: GitHub Actions Runner RCE",
                "category": "cicd",
                "initial_points": 500,
                "flag": "FLAG{cicd_runner_escape_token_15}",
                "solves": [],
                "first_blood": None,
            },
            "LAB16_REV": {
                "id": "LAB16_REV",
                "title": "Reversing: Bytecode Disassembly Keygen",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{bytecode_reverse_keygen_16}",
                "solves": [],
                "first_blood": None,
            },
            "LAB17_PWN": {
                "id": "LAB17_PWN",
                "title": "Pwn: Buffer Overflow Ret2win",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{ret2win_rip_overwrite_17}",
                "solves": [],
                "first_blood": None,
            },
            "LAB18_AI": {
                "id": "LAB18_AI",
                "title": "AISec: MCP Prompt Injection Exfil",
                "category": "ai",
                "initial_points": 500,
                "flag": "FLAG{mcp_tool_injection_exfil_18}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_ROOT": {
                "id": "LAB19_ROOT",
                "title": "DroidShield: Root Detection Bypass",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{dr01d_r00t_byp4ss_succ3ss_9281}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_PINNING": {
                "id": "LAB19_PINNING",
                "title": "DroidShield: Universal SSL Unpinning",
                "category": "mobile",
                "initial_points": 500,
                "flag": "FLAG{ss1_p1nn1ng_fr1da_unp1nn3d_7143}",
                "solves": [],
                "first_blood": None,
            },
            "LAB19_JNI": {
                "id": "LAB19_JNI",
                "title": "DroidShield: JNI Native Return Hijack",
                "category": "reversing",
                "initial_points": 500,
                "flag": "FLAG{jn1_n4t1v3_h00k_l1c3ns3_p4ss_3301}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_SEH": {
                "id": "LAB20_SEH",
                "title": "WinAppSec: SEH pop-pop-ret Overwrite",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{w1n_seh_0v3rwr1t3_p0p_p0p_r3t_9918}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_EGG": {
                "id": "LAB20_EGG",
                "title": "WinAppSec: 32-Byte Egg Hunter",
                "category": "pwn",
                "initial_points": 500,
                "flag": "FLAG{3gg_hunt3r_w00tw00t_m3m_f0und_4412}",
                "solves": [],
                "first_blood": None,
            },
            "LAB20_HEVD": {
                "id": "LAB20_HEVD",
                "title": "WinAppSec: HEVD Kernel Token Stealing",
                "category": "kernel",
                "initial_points": 500,
                "flag": "FLAG{h3vd_r1ng0_t0k3n_st34l1ng_pwn3d_5532}",
                "solves": [],
                "first_blood": None,
            },
            "CARCAN_ECU": {
                "id": "CARCAN_ECU",
                "title": "CarCan: UDS ECU Hard Reset & Firmware Exfil",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{carcan_uds_ecu_reset_pwned_35}",
                "solves": [],
                "first_blood": None,
            },
        }
        self.submissions_log: List[dict] = []
        self.first_bloods_feed: List[dict] = []

    def get_points(self, chal_id: str) -> int:
        """Dynamic Scoring: 다음 solve 시 획득할 점수 (solves 수가 늘어날수록 점수 차감, 최저 100점)"""
        c = self.challenges.get(chal_id)
        if not c:
            return 100
        next_solve_count = len(c["solves"]) + 1
        return compute_dynamic_score(
            initial_points=c.get("initial_points", 500),
            solves_count=next_solve_count,
            min_points=100,
            decay_rate=0.85,
        )


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
            "initial_points": c.get("initial_points", 500),
            "current_points": state.get_points(cid),
            "solves_count": len(c["solves"]),
            "first_blood": c["first_blood"],
        })
    return {"challenges": data}


@app.get("/api/ctf/firstbloods")
def get_firstbloods():
    """First Blood 명예의 전당 피드 반환"""
    return {"first_bloods": state.first_bloods_feed}


@app.get("/api/ctf/scoreboard")
def get_scoreboard():
    """실시간 스코어보드 순위, 점수, First Blood 뱃지 반환"""
    board = []
    for tname, t in state.teams.items():
        board.append({
            "team": tname,
            "score": t["score"],
            "solves_count": len(t["solves"]),
            "first_blood_count": len(t.get("first_bloods", [])),
            "last_solve": t["last_solve"],
        })
    # Sort by score desc, then last_solve asc
    board.sort(key=lambda x: (-x["score"], x["last_solve"]))
    for i, item in enumerate(board, 1):
        item["rank"] = i
    return {
        "scoreboard": board,
        "first_bloods": state.first_bloods_feed[-5:],
        "recent_activity": state.submissions_log[-10:],
    }


@app.post("/api/ctf/register")
def register_team(req: TeamRegisterRequest):
    name = req.team_name.strip()
    if not name or len(name) < 2:
        raise HTTPException(status_code=400, detail="Team name too short")
    if name in state.teams:
        return {"status": "exists", "message": "Team already registered", "team": name}
    state.teams[name] = {"name": name, "score": 0, "solves": [], "first_bloods": [], "last_solve": 0}
    return {"status": "registered", "team": name}


@app.post("/api/ctf/submit")
def submit_flag(req: FlagSubmitRequest):
    """플래그 검증, First Blood 알림 및 동적 점수(Dynamic Scoring) 반영"""
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
    first_blood_bonus = 0

    if is_first_blood:
        first_blood_bonus = 50
        pts += first_blood_bonus
        fb_entry = {
            "chal_id": req.chal_id,
            "title": chal["title"],
            "team": tname,
            "timestamp": now,
            "bonus": first_blood_bonus,
        }
        chal["first_blood"] = fb_entry
        team["first_bloods"].append(req.chal_id)
        state.first_bloods_feed.append(fb_entry)

    chal["solves"].append(tname)
    team["solves"].append(req.chal_id)
    team["score"] += pts
    team["last_solve"] = now

    msg = f"Correct! Earned {pts} points."
    if is_first_blood:
        msg += f" [FIRST BLOOD! 🩸 +{first_blood_bonus}pt Bonus!]"

    return {
        "status": "correct",
        "message": msg,
        "points_awarded": pts,
        "first_blood": is_first_blood,
        "first_blood_bonus": first_blood_bonus,
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
        body { background: #0b0f19; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 2rem; margin: 0; }
        .container { max-width: 1100px; margin: 0 auto; }
        h1 { color: #ec4899; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 10px; }
        .banner { background: linear-gradient(90deg, #3730a3 0%, #1e1b4b 100%); border-left: 4px solid #818cf8; padding: 12px 16px; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.95rem; }
        .grid { display: grid; grid-template-columns: 1fr 340px; gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 14px; border-bottom: 1px solid #1f2937; text-align: left; }
        th { background: #1f2937; color: #38bdf8; font-weight: 600; font-size: 0.9rem; }
        .rank-1 { color: #fbbf24; font-weight: bold; background: rgba(251, 191, 36, 0.05); }
        .badge { background: #ec4899; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
        .badge-fb { background: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
        .card { background: #1e293b; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
        .input-box { background: #0f172a; border: 1px solid #475569; color: white; padding: 10px; border-radius: 6px; margin-right: 8px; font-size: 0.95rem; }
        button { background: #ec4899; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s; }
        button:hover { background: #db2777; }
        .fb-feed-item { padding: 8px 10px; border-bottom: 1px solid #334155; font-size: 0.88rem; display: flex; align-items: center; justify-content: space-between; }
        .fb-feed-item:last-child { border-bottom: none; }
        .fb-team { color: #f43f5e; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🏆 VibeHacking CTF Arena</h1>
        <p style="color: #94a3b8; margin-top: 0;">26개 실습 랩 플래그 채점, 실시간 Dynamic Scoring & First Blood 영예의 전당</p>

        <div class="banner">
          ⚡ <b>Dynamic Scoring Engine:</b> 문제 기본 500pt에서 해결 팀 증가에 따라 점수 자동 감쇠(최저 100pt) | <b>🩸 First Blood:</b> 문제 최초 해결 시 <b>+50pt 추가 보너스</b> 지급!
        </div>

        <div class="card">
          <h3 style="margin-top: 0;">🚩 플래그 제출 (Flag Submit)</h3>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <input id="teamInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="팀 이름 (예: Admin_RedTeam)">
            <input id="chalInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="문제 ID (예: LAB01_SQLI)">
            <input id="flagInput" class="input-box" style="flex: 2; min-width: 250px;" placeholder="FLAG{...}">
            <button onclick="submitFlag()">제출하기</button>
          </div>
          <div id="submitResult" style="margin-top: 10px; font-weight: 500;"></div>
        </div>

        <div class="grid">
          <div>
            <h2 style="color: #38bdf8; margin-bottom: 0.5rem;">📊 실시간 리더보드 (Scoreboard)</h2>
            <table>
              <thead>
                <tr>
                  <th>순위</th>
                  <th>팀 이름</th>
                  <th>점수</th>
                  <th>해결 수</th>
                  <th>First Blood</th>
                </tr>
              </thead>
              <tbody id="boardBody"></tbody>
            </table>
          </div>

          <div>
            <h2 style="color: #f43f5e; margin-bottom: 0.5rem;">🩸 First Blood 피드</h2>
            <div class="card" style="padding: 0.5rem;" id="fbFeed">
              <div style="padding: 12px; color: #94a3b8; text-align: center;">아직 첫 피를 흘린 자가 없습니다...</div>
            </div>
          </div>
        </div>
      </div>

      <script>
        async function loadBoard() {
          try {
            const res = await fetch('/api/ctf/scoreboard');
            const data = await res.json();
            const tbody = document.getElementById('boardBody');
            tbody.innerHTML = '';
            data.scoreboard.forEach(item => {
              const tr = document.createElement('tr');
              if (item.rank === 1) tr.className = 'rank-1';
              const fbBadge = item.first_blood_count > 0 
                ? `<span class="badge-fb">🩸 x${item.first_blood_count}</span>` 
                : `<span style="color: #64748b;">-</span>`;
              tr.innerHTML = `<td>#${item.rank}</td><td><b>${item.team}</b></td><td><b>${item.score}</b> pts</td><td>${item.solves_count}</td><td>${fbBadge}</td>`;
              tbody.appendChild(tr);
            });

            const feedDiv = document.getElementById('fbFeed');
            if (data.first_bloods && data.first_bloods.length > 0) {
              feedDiv.innerHTML = data.first_bloods.map(fb => `
                <div class="fb-feed-item">
                  <div>
                    <span class="fb-team">${fb.team}</span>님이 <span style="color: #e2e8f0;">${fb.title || fb.chal_id}</span> 문제를 최초 해결!
                  </div>
                  <span class="badge-fb">+${fb.bonus}pt</span>
                </div>
              `).reverse().join('');
            }
          } catch (e) {
            console.error('스코어보드 로드 실패:', e);
          }
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
            resSpan.style.color = '#f87171';
          }
        }

        loadBoard();
        setInterval(loadBoard, 3000);
      </script>
    </body>
    </html>
    """
