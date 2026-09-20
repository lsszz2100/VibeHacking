"""VibeHacking CTF Competition & Scoreboard Engine (FastAPI)."""

import os
import sys
import time
import math
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="VibeHacking CTF Arena", version="1.2.0")


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
            "LAB21_CAN": {
                "id": "LAB21_CAN",
                "title": "CarCan: CAN Bus Speedometer Spoofing",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{can_bus_arbitration_speed_spoof_8821}",
                "solves": [],
                "first_blood": None,
            },
            "LAB21_UDS": {
                "id": "LAB21_UDS",
                "title": "CarCan: UDS SecurityAccess Seed-Key Bypass",
                "category": "carcan",
                "initial_points": 500,
                "flag": "FLAG{uds_security_access_seed_key_unlocked_3714}",
                "solves": [],
                "first_blood": None,
            },
        }
        self.submissions_log: List[dict] = []
        self.first_bloods_feed: List[dict] = []
        self.score_timeline: List[dict] = []
        self.subscribers: List[asyncio.Queue] = []

        # Initialize base timeline
        t0 = int(time.time()) - 60
        self.score_timeline.append({"time": t0, "team": "Admin_RedTeam", "score": 0, "chal_id": "INIT"})
        self.score_timeline.append({"time": t0, "team": "BlueGuardians", "score": 0, "chal_id": "INIT"})

    def broadcast_event(self, event: dict):
        """Broadcast real-time event to all connected SSE clients"""
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

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


@app.get("/api/ctf/timeline")
def get_timeline():
    """시계열 점수 추이 데이터 반환 (차트 렌더링용)"""
    return {
        "teams": list(state.teams.keys()),
        "timeline": state.score_timeline,
    }


@app.get("/api/ctf/team/{team_name}")
def get_team_profile(team_name: str):
    """특정 팀의 세부 해결 내역 및 First Blood 뱃지 반환"""
    team = state.teams.get(team_name)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    details = []
    for cid in team["solves"]:
        c = state.challenges.get(cid, {})
        details.append({
            "chal_id": cid,
            "title": c.get("title", cid),
            "category": c.get("category", "unknown"),
            "first_blood": cid in team.get("first_bloods", []),
        })
    return {
        "team": team_name,
        "score": team["score"],
        "solves_count": len(team["solves"]),
        "first_blood_count": len(team.get("first_bloods", [])),
        "solves": details,
    }


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


@app.get("/api/ctf/stream")
async def sse_stream(request: Request, once: bool = False):
    """실시간 점수 및 First Blood 스트리밍 (Server-Sent Events)"""
    async def event_generator():
        yield "event: handshake\ndata: {\"status\": \"connected\"}\n\n"
        if once:
            return

        queue = asyncio.Queue()
        state.subscribers.append(queue)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event.get('type', 'message')}\ndata: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in state.subscribers:
                state.subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/ctf/register")
def register_team(req: TeamRegisterRequest):
    name = req.team_name.strip()
    if not name or len(name) < 2:
        raise HTTPException(status_code=400, detail="Team name too short")
    if name in state.teams:
        return {"status": "exists", "message": "Team already registered", "team": name}
    now = int(time.time())
    state.teams[name] = {"name": name, "score": 0, "solves": [], "first_bloods": [], "last_solve": 0}
    state.score_timeline.append({"time": now, "team": name, "score": 0, "chal_id": "REGISTER"})
    state.broadcast_event({"type": "team_registered", "team": name, "time": now})
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

    # Record score timeline progression
    state.score_timeline.append({
        "time": now,
        "team": tname,
        "score": team["score"],
        "chal_id": req.chal_id,
        "pts": pts,
        "first_blood": is_first_blood,
    })

    # Broadcast event via SSE
    state.broadcast_event({
        "type": "flag_solve",
        "team": tname,
        "chal_id": req.chal_id,
        "title": chal["title"],
        "points": pts,
        "first_blood": is_first_blood,
        "bonus": first_blood_bonus,
        "time": now,
        "score": team["score"],
    })

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
        :root {
          --bg: #0b0f19;
          --card: #1e293b;
          --card-border: #334155;
          --accent: #ec4899;
          --cyan: #38bdf8;
          --red: #f43f5e;
          --gold: #fbbf24;
          --green: #4ade80;
        }
        body { background: var(--bg); color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 2rem; margin: 0; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: var(--accent); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 10px; }
        .banner { background: linear-gradient(90deg, #3730a3 0%, #1e1b4b 100%); border-left: 4px solid #818cf8; padding: 12px 16px; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.95rem; }
        .grid { display: grid; grid-template-columns: 1fr 360px; gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 14px; border-bottom: 1px solid #1f2937; text-align: left; }
        th { background: #1f2937; color: var(--cyan); font-weight: 600; font-size: 0.9rem; }
        .rank-1 { color: var(--gold); font-weight: bold; background: rgba(251, 191, 36, 0.05); }
        .badge { background: var(--accent); color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
        .badge-fb { background: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
        .card { background: var(--card); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; border: 1px solid var(--card-border); }
        .input-box { background: #0f172a; border: 1px solid #475569; color: white; padding: 10px; border-radius: 6px; margin-right: 8px; font-size: 0.95rem; }
        button { background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s; }
        button:hover { background: #db2777; }
        .fb-feed-item { padding: 8px 10px; border-bottom: 1px solid var(--card-border); font-size: 0.88rem; display: flex; align-items: center; justify-content: space-between; }
        .fb-feed-item:last-child { border-bottom: none; }
        .fb-team { color: var(--red); font-weight: bold; }
        .toast { position: fixed; top: 20px; right: 20px; background: rgba(244, 63, 94, 0.95); color: white; padding: 14px 20px; border-radius: 8px; font-weight: bold; box-shadow: 0 10px 25px rgba(0,0,0,0.5); z-index: 1000; display: none; animation: slideIn 0.3s forwards; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        
        /* Interactive Scoreboard Chart Canvas */
        .chart-box {
          background: #020617;
          border: 1px solid #1e293b;
          border-radius: 8px;
          padding: 1rem;
          margin-bottom: 1.5rem;
          position: relative;
        }
        canvas { width: 100%; height: 240px; display: block; }
        .live-tag { display: inline-flex; align-items: center; gap: 6px; color: var(--green); font-size: 0.85rem; font-weight: bold; }
        .live-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; animation: blink 1.2s infinite; }
        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.2; } 100% { opacity: 1; } }
      </style>
    </head>
    <body>
      <div id="toastBox" class="toast"></div>

      <div class="container">
        <h1>
          🏆 VibeHacking CTF Arena
          <span class="live-tag"><span class="live-dot"></span> LIVE SSE STREAMING</span>
        </h1>
        <p style="color: #94a3b8; margin-top: 0;">28개 실습 랩 플래그 채점, 실시간 Dynamic Scoring & First Blood 영예의 전당</p>

        <div class="banner">
          ⚡ <b>Dynamic Scoring Engine:</b> 문제 기본 500pt에서 해결 팀 증가에 따라 점수 자동 감쇠(최저 100pt) | <b>🩸 First Blood:</b> 문제 최초 해결 시 <b>+50pt 추가 보너스</b> 지급!
        </div>

        <!-- Interactive Score Timeline Chart -->
        <div class="chart-box">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <b style="color: var(--cyan); font-size: 0.95rem;">📈 팀별 실시간 점수 추이 그래프 (Score Progression Timeline)</b>
            <span id="chartLegend" style="font-size: 0.8rem; display: flex; gap: 12px;"></span>
          </div>
          <canvas id="scoreCanvas" width="1120" height="240"></canvas>
        </div>

        <div class="card">
          <h3 style="margin-top: 0;">🚩 플래그 제출 (Flag Submit)</h3>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <input id="teamInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="팀 이름 (예: Admin_RedTeam)">
            <input id="chalInput" class="input-box" style="flex: 1; min-width: 150px;" placeholder="문제 ID (예: LAB21_CAN)">
            <input id="flagInput" class="input-box" style="flex: 2; min-width: 250px;" placeholder="FLAG{...}">
            <button onclick="submitFlag()">제출하기</button>
          </div>
          <div id="submitResult" style="margin-top: 10px; font-weight: 500;"></div>
        </div>

        <div class="grid">
          <div>
            <h2 style="color: var(--cyan); margin-bottom: 0.5rem;">📊 실시간 리더보드 (Scoreboard)</h2>
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
            <h2 style="color: var(--red); margin-bottom: 0.5rem;">🩸 First Blood 피드</h2>
            <div class="card" style="padding: 0.5rem;" id="fbFeed">
              <div style="padding: 12px; color: #94a3b8; text-align: center;">아직 첫 피를 흘린 자가 없습니다...</div>
            </div>
          </div>
        </div>
      </div>

      <script>
        const TEAM_COLORS = ['#ec4899', '#38bdf8', '#fbbf24', '#4ade80', '#a855f7', '#f43f5e', '#34d399', '#f97316'];
        let cachedTimeline = [];

        function showToast(msg) {
          const t = document.getElementById('toastBox');
          t.innerHTML = msg;
          t.style.display = 'block';
          setTimeout(() => { t.style.display = 'none'; }, 4500);
        }

        async function drawTimelineChart() {
          try {
            const res = await fetch('/api/ctf/timeline');
            const data = await res.json();
            cachedTimeline = data.timeline;
            const teams = data.teams;

            const canvas = document.getElementById('scoreCanvas');
            const ctx = canvas.getContext('2d');
            const W = canvas.width;
            const H = canvas.height;
            ctx.clearRect(0, 0, W, H);

            // Group events by team
            const series = {};
            teams.forEach((t, i) => {
              series[t] = { color: TEAM_COLORS[i % TEAM_COLORS.length], points: [] };
            });

            data.timeline.forEach(ev => {
              if (series[ev.team]) {
                series[ev.team].points.push({ time: ev.time, score: ev.score });
              }
            });

            // Calculate min/max time and score
            let minT = Infinity, maxT = -Infinity, maxS = 500;
            data.timeline.forEach(ev => {
              if (ev.time < minT) minT = ev.time;
              if (ev.time > maxT) maxT = ev.time;
              if (ev.score > maxS) maxS = ev.score;
            });
            if (minT === maxT) maxT = minT + 60;
            maxS = Math.ceil(maxS * 1.15);

            // Draw grid lines
            ctx.strokeStyle = '#1e293b';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
              const y = H - 30 - (i / 4) * (H - 50);
              ctx.beginPath();
              ctx.moveTo(40, y);
              ctx.lineTo(W - 20, y);
              ctx.stroke();

              ctx.fillStyle = '#64748b';
              ctx.font = '10px monospace';
              ctx.fillText(Math.round((i / 4) * maxS), 5, y + 3);
            }

            // Draw lines for each team
            const legendDiv = document.getElementById('chartLegend');
            legendDiv.innerHTML = teams.map((t, idx) => `
              <span style="color: ${TEAM_COLORS[idx % TEAM_COLORS.length]}; font-weight: bold;">■ ${t}</span>
            `).join('');

            teams.forEach((t) => {
              const s = series[t];
              if (!s.points.length) return;
              ctx.strokeStyle = s.color;
              ctx.lineWidth = 2.5;
              ctx.beginPath();

              s.points.forEach((pt, idx) => {
                const x = 40 + ((pt.time - minT) / (maxT - minT)) * (W - 60);
                const y = H - 30 - (pt.score / maxS) * (H - 50);
                if (idx === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
              });
              ctx.stroke();

              // Draw point circles
              s.points.forEach((pt) => {
                const x = 40 + ((pt.time - minT) / (maxT - minT)) * (W - 60);
                const y = H - 30 - (pt.score / maxS) * (H - 50);
                ctx.fillStyle = s.color;
                ctx.beginPath();
                ctx.arc(x, y, 4, 0, Math.PI * 2);
                ctx.fill();
              });
            });
          } catch (e) {
            console.error('차트 렌더링 실패:', e);
          }
        }

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
            drawTimelineChart();
          } catch (e) {
            resSpan.innerText = '오류 발생: ' + e.message;
            resSpan.style.color = '#f87171';
          }
        }

        // Connect real-time Server-Sent Events (SSE)
        function initSSE() {
          try {
            const es = new EventSource('/api/ctf/stream');
            es.addEventListener('flag_solve', (e) => {
              const ev = JSON.parse(e.data);
              if (ev.first_blood) {
                showToast(`🩸 <b>FIRST BLOOD!</b> <span style="color:#fbbf24;">${ev.team}</span>님이 <b>${ev.title || ev.chal_id}</b> 최초 해결! (+${ev.points}pt)`);
              } else {
                showToast(`🚩 <b>FLAG SOLVE!</b> <span style="color:#38bdf8;">${ev.team}</span>님이 <b>${ev.title || ev.chal_id}</b> 해결! (+${ev.points}pt)`);
              }
              loadBoard();
              drawTimelineChart();
            });
            es.addEventListener('team_registered', (e) => {
              loadBoard();
              drawTimelineChart();
            });
            es.onerror = () => {
              // Reconnect automatically handled by browser EventSource
            };
          } catch (err) {
            console.warn('SSE 연결 실패, 폴링으로 전환:', err);
          }
        }

        loadBoard();
        drawTimelineChart();
        initSSE();
        setInterval(loadBoard, 5000);
      </script>
    </body>
    </html>
    """
