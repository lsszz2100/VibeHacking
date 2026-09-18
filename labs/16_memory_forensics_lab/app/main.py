#!/usr/bin/env python3
"""Lab 16: Memory Forensics & Volatility 3 Analysis Lab (MemShield).

Interactive simulation of memory forensics & malware triage on physical RAM dumps:
1. Stage 1: DKOM Hidden Process Detection (pslist vs psscan / pstree)
2. Stage 2: Code Injection & Process Hollowing (malfind VAD RWX analysis)
3. Stage 3: Network Artifacts & C2 Beaconing Reconstruction (netscan)
4. Stage 4: LSASS Credential Dump & LSA PPL Kernel Hardening (lsadump)
"""

import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="MemShield - Memory Forensics & Volatility Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

FLAGS = {
    "stage1": "FLAG{m3m_dkom_proc_unv31l3d_8492}",
    "stage2": "FLAG{m3m_vads_rwx_h0ll0w_sh3ll_7134}",
    "stage3": "FLAG{m3m_n3t_c2_b34c0n_tr4ck3d_9921}",
    "stage4": "FLAG{m3m_ls4ss_ntlm_ppl_gu4rd_3519}",
}


class MemoryLabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.dump_file = "victim_win10_enterprise_x64.dmp"
        self.memory_profile = "Windows 10 Enterprise Build 19044 x64"
        self.os_arch = "x64"
        self.total_ram_mb = 4096

        # Stage 1: Process Table & DKOM
        # Regular active list (ActiveProcessLinks)
        self.active_processes = [
            {"pid": 4, "ppid": 0, "name": "System", "threads": 184, "handles": 3120, "time": "2026-09-17 14:00:01"},
            {"pid": 412, "ppid": 4, "name": "smss.exe", "threads": 4, "handles": 48, "time": "2026-09-17 14:00:02"},
            {"pid": 580, "ppid": 412, "name": "csrss.exe", "threads": 12, "handles": 510, "time": "2026-09-17 14:00:05"},
            {"pid": 672, "ppid": 580, "name": "lsass.exe", "threads": 18, "handles": 1150, "time": "2026-09-17 14:00:08"},
            {"pid": 788, "ppid": 580, "name": "services.exe", "threads": 14, "handles": 620, "time": "2026-09-17 14:00:08"},
            {"pid": 1120, "ppid": 788, "name": "svchost.exe", "threads": 32, "handles": 890, "time": "2026-09-17 14:00:15"},
            {"pid": 2440, "ppid": 1120, "name": "explorer.exe", "threads": 48, "handles": 2100, "time": "2026-09-17 14:01:22"},
            {"pid": 3108, "ppid": 2440, "name": "chrome.exe", "threads": 26, "handles": 740, "time": "2026-09-17 14:05:10"},
        ]
        # Unlinked hidden process (DKOM - removed from ActiveProcessLinks, present in pool scan)
        self.hidden_process = {
            "pid": 4820,
            "ppid": 1120,
            "name": "svch0st.exe",
            "threads": 6,
            "handles": 132,
            "time": "2026-09-17 14:12:44",
            "dkom_unlinked": True,
            "binary_path": "C:\\Windows\\Temp\\svch0st.exe",
        }
        self.stage1_solved = False

        # Stage 2: Code Injection & VAD
        self.injected_vad = {
            "pid": 2440,
            "process": "explorer.exe",
            "start_vpn": "0x00000000002a0000",
            "end_vpn": "0x00000000002b4000",
            "tag": "VadS",
            "protection": "PAGE_EXECUTE_READWRITE",
            "commit_charge": 20,
            "hexdump": "4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|\n"
                       "b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|\n"
                       "31 c0 50 68 2f 2f 73 68  68 2f 62 69 6e 89 e3 50  |1.Ph//shh/bin..P|",
            "threat": "Reflective PE DLL Injection & Metasploit Shellcode detected",
        }
        self.stage2_solved = False

        # Stage 3: Network Connections
        self.network_sockets = [
            {"proto": "TCPv4", "local": "0.0.0.0:135", "foreign": "0.0.0.0:0", "state": "LISTENING", "pid": 1120, "owner": "svchost.exe"},
            {"proto": "TCPv4", "local": "0.0.0.0:445", "foreign": "0.0.0.0:0", "state": "LISTENING", "pid": 4, "owner": "System"},
            {"proto": "TCPv4", "local": "192.168.1.105:51240", "foreign": "142.250.190.46:443", "state": "ESTABLISHED", "pid": 3108, "owner": "chrome.exe"},
            {"proto": "TCPv4", "local": "192.168.1.105:49822", "foreign": "198.51.100.89:8443", "state": "ESTABLISHED", "pid": 4820, "owner": "svch0st.exe"},
        ]
        self.stage3_solved = False

        # Stage 4: LSASS Credentials & LSA PPL Defense
        self.lsa_ppl_enabled = False
        self.dumped_credentials = [
            {"domain": "CORP-HQ", "user": "Administrator", "rid": 500, "lm": "aad3b435b51404eeaad3b435b51404ee", "ntlm": "8846f7eaee8fb117ad06bdd830b7586c"},
            {"domain": "CORP-HQ", "user": "krbtgt", "rid": 502, "lm": "aad3b435b51404eeaad3b435b51404ee", "ntlm": "58a2d1f938c46ef8d34b12aa90827f31"},
            {"domain": "CORP-HQ", "user": "finance_admin", "rid": 1104, "lm": "aad3b435b51404eeaad3b435b51404ee", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0"},
        ]
        self.stage4_solved = False

        self.solved_stages: list[str] = []
        self.logs: list[str] = [
            f"[{time.strftime('%H:%M:%S')}] MemShield Volatility 3 Forensic Environment Ready. Dump loaded: {self.dump_file}"
        ]

    def log(self, msg: str):
        self.logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(self.logs) > 60:
            self.logs.pop(0)


state = MemoryLabState()


# Request / Response Models
class TerminalCommand(BaseModel):
    command: str


class FlagSubmission(BaseModel):
    flag: str


class ProcessInspectRequest(BaseModel):
    pid: int


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/status")
def get_status():
    return {
        "status": "online",
        "dump_file": state.dump_file,
        "memory_profile": state.memory_profile,
        "ram_size_mb": state.total_ram_mb,
        "stages": {
            "stage1_dkom": {
                "name": "DKOM 은닉 프로세스 적출",
                "solved": state.stage1_solved,
            },
            "stage2_malfind": {
                "name": "VAD RWX 코드 인젝션 탐지",
                "solved": state.stage2_solved,
            },
            "stage3_netscan": {
                "name": "C2 비컨 네트워크 아티팩트 복원",
                "solved": state.stage3_solved,
            },
            "stage4_lsass": {
                "name": "LSASS 자격 증명 덤프 & PPL 방어",
                "solved": state.stage4_solved,
                "ppl_enabled": state.lsa_ppl_enabled,
            },
        },
        "solved_count": len(state.solved_stages),
        "total_stages": 4,
        "logs": state.logs[-10:],
    }


@app.post("/api/stage1/detect-hidden")
def stage1_detect_hidden():
    """Execute Volatility pool-tag scanning (psscan) to identify DKOM unlinked process."""
    hidden = state.hidden_process
    state.stage1_solved = True
    if "stage1" not in state.solved_stages:
        state.solved_stages.append("stage1")
    state.log(f"Stage 1 SOLVED: DKOM unlinked process {hidden['name']} (PID: {hidden['pid']}) uncovered via pool tag Proc scan.")
    return {
        "success": True,
        "flag": FLAGS["stage1"],
        "unlinked_process": hidden,
        "message": "DKOM 조작으로 ActiveProcessLinks에서 언링크된 악성 프로세스를 풀 스캔으로 적출했습니다!",
    }


@app.post("/api/stage2/analyze-injected-vad")
def stage2_analyze_injected_vad(req: Optional[ProcessInspectRequest] = None):
    """Scan process memory VAD nodes for PAGE_EXECUTE_READWRITE and injected executable payload."""
    pid = req.pid if req else 2440
    if pid != 2440:
        raise HTTPException(status_code=400, detail=f"PID {pid}는 클린한 VAD 구조를 유지하고 있습니다. 의심스러운 프로세스(PID 2440 explorer.exe)를 분석하십시오.")

    state.stage2_solved = True
    if "stage2" not in state.solved_stages:
        state.solved_stages.append("stage2")
    state.log(f"Stage 2 SOLVED: Injected RWX VAD section at {state.injected_vad['start_vpn']} detected in PID 2440.")
    return {
        "success": True,
        "flag": FLAGS["stage2"],
        "vad_info": state.injected_vad,
        "message": "explorer.exe(PID 2440) 내부로 Reflective PE 인젝션된 쉘코드 및 MZ 헤더를 확인했습니다!",
    }


@app.post("/api/stage3/reconstruct-c2")
def stage3_reconstruct_c2():
    """Analyze memory socket structures (netscan) to extract remote C2 beacon IP/port."""
    c2_socket = next(s for s in state.network_sockets if s["pid"] == 4820)
    state.stage3_solved = True
    if "stage3" not in state.solved_stages:
        state.solved_stages.append("stage3")
    state.log(f"Stage 3 SOLVED: C2 Beacon {c2_socket['foreign']} connected by PID {c2_socket['pid']} ({c2_socket['owner']}).")
    return {
        "success": True,
        "flag": FLAGS["stage3"],
        "c2_artifact": c2_socket,
        "message": "은닉 프로세스(svch0st.exe)가 유지 중인 외부 C2 통신 세션(198.51.100.89:8443)을 성공적으로 복원했습니다!",
    }


@app.post("/api/stage4/dump-credentials")
def stage4_dump_credentials():
    """Attempt LSASS process memory dump for NTLM hashes."""
    if state.lsa_ppl_enabled:
        state.log("Stage 4 DEFENSE ACTIVE: LSASS Protected Process Light (PPL) blocked kernel memory handle acquisition.")
        raise HTTPException(
            status_code=403,
            detail="[ACCESS_DENIED] LSA Protected Process Light (PPL) 활성화로 인해 메모리 핸들 오픈 및 덤프가 차단되었습니다.",
        )

    state.stage4_solved = True
    if "stage4" not in state.solved_stages:
        state.solved_stages.append("stage4")
    state.log("Stage 4 SOLVED: LSASS memory parsed without PPL. Administrator NTLM hash exfiltrated.")
    return {
        "success": True,
        "flag": FLAGS["stage4"],
        "credentials": state.dumped_credentials,
        "message": "LSASS 메모리에서 관리자 NTLM 해시 탈취 확인! LSA PPL(Protected Process Light) 방어를 활성화하십시오.",
    }


@app.post("/api/stage4/toggle-ppl")
def stage4_toggle_ppl():
    """Toggle LSA Protected Process Light (RunAsPPL) defense mode."""
    state.lsa_ppl_enabled = not state.lsa_ppl_enabled
    mode_str = "ENABLED" if state.lsa_ppl_enabled else "DISABLED"
    state.log(f"Stage 4 Mitigation: LSA PPL (RunAsPPL) is now {mode_str}.")
    return {
        "success": True,
        "lsa_ppl_enabled": state.lsa_ppl_enabled,
        "message": f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = {1 if state.lsa_ppl_enabled else 0}",
    }


@app.post("/api/submit-flag")
def submit_flag(sub: FlagSubmission):
    candidate = sub.flag.strip()
    for stage_key, flag_val in FLAGS.items():
        if candidate == flag_val:
            if stage_key not in state.solved_stages:
                state.solved_stages.append(stage_key)
                setattr(state, f"{stage_key}_solved", True)
                state.log(f"Flag verified for {stage_key}! ({candidate})")
            return {
                "success": True,
                "stage": stage_key,
                "message": f"축하합니다! {stage_key} 정답 플래그를 획득했습니다.",
                "total_solved": len(state.solved_stages),
            }
    return {"success": False, "message": "잘못된 플래그입니다. 메모리 아티팩트를 다시 분석하세요."}


@app.post("/api/reset")
def reset_lab():
    state.reset()
    return {"success": True, "message": "메모리 포렌식 랩 상태가 초기화되었습니다."}


# ── Interactive Volatility Terminal Emulator ──────────────────────────────────

@app.post("/api/terminal")
def execute_terminal(cmd_req: TerminalCommand):
    cmd_raw = cmd_req.command.strip()
    if not cmd_raw:
        return {"output": ""}

    state.log(f"Terminal Command: {cmd_raw}")
    parts = shlex.split(cmd_raw)
    base = parts[0].lower()

    if base in ["clear", "cls"]:
        return {"output": "\033[2J\033[H"}

    if base == "help":
        return {
            "output": (
                "=== MemShield Volatility 3 CLI Emulator ===\n"
                "사용 가능한 명령어:\n"
                "  vol -f memory.raw windows.pslist    : 활성 EPROCESS 링크 순회 프로세스 목록\n"
                "  vol -f memory.raw windows.psscan    : 커널 풀 태그(Proc) 메모리 스캔 (은닉 프로세스 탐지)\n"
                "  vol -f memory.raw windows.pstree    : 부모-자식 트리 구조로 프로세스 출력\n"
                "  vol -f memory.raw windows.malfind   : VAD RWX 실행 권한 주입 쉘코드 분석\n"
                "  vol -f memory.raw windows.netscan   : TCP/UDP 소켓 아티팩트 및 C2 비컨 추적\n"
                "  vol -f memory.raw windows.lsadump   : LSA 시크릿 및 NTLM 계정 해시 덤프\n"
                "  vol -f memory.raw windows.cmdline   : 프로세스 시작 시 명령줄 인자 확인\n"
                "  status                              : 포렌식 분석 단계 진행 현황\n"
                "  flags                               : 획득한 CTF 플래그 확인\n"
                "  reset                               : 랩 시뮬레이션 상태 초기화\n"
            )
        }

    if base == "status":
        lines = [
            f"=== MemShield 포렌식 조사 현황 ===",
            f"메모리 덤프 파일: {state.dump_file}",
            f"OS 프로파일     : {state.memory_profile}",
            f"해결된 단계     : {len(state.solved_stages)} / 4",
            f"Stage 1 (DKOM)   : {'[SOLVED]' if state.stage1_solved else '[OPEN]'}",
            f"Stage 2 (VAD)    : {'[SOLVED]' if state.stage2_solved else '[OPEN]'}",
            f"Stage 3 (Netscan): {'[SOLVED]' if state.stage3_solved else '[OPEN]'}",
            f"Stage 4 (LSASS)  : {'[SOLVED]' if state.stage4_solved else '[OPEN]'}",
            f"LSA PPL 방어 모드 : {'ENABLED (차단됨)' if state.lsa_ppl_enabled else 'DISABLED (취약)'}",
        ]
        return {"output": "\n".join(lines)}

    if base == "flags":
        lines = ["=== 획득한 플래그 목록 ==="]
        for s in ["stage1", "stage2", "stage3", "stage4"]:
            if s in state.solved_stages:
                lines.append(f"  {s}: {FLAGS[s]}")
            else:
                lines.append(f"  {s}: [미완료 - 분석 진행 필요]")
        return {"output": "\n".join(lines)}

    if base == "reset":
        state.reset()
        return {"output": "메모리 포렌식 환경이 성공적으로 초기화되었습니다."}

    # Volatility command handling
    if base in ["vol", "volatility", "python3 vol.py"]:
        sub_plugin = ""
        for p in parts[1:]:
            if not p.startswith("-") and not p.endswith(".raw") and not p.endswith(".dmp"):
                sub_plugin = p
                break

        if "windows.pslist" in sub_plugin or "pslist" in sub_plugin:
            out = ["PID\tPPID\tImageFileName\tThreads\tHandles\tCreateTime"]
            out.append("-" * 75)
            for proc in state.active_processes:
                out.append(f"{proc['pid']}\t{proc['ppid']}\t{proc['name']:<15}\t{proc['threads']}\t{proc['handles']}\t{proc['time']}")
            out.append("\n[*] Note: pslist는 EPROCESS ActiveProcessLinks 더블 링크드 리스트를 순회합니다.")
            return {"output": "\n".join(out)}

        elif "windows.psscan" in sub_plugin or "psscan" in sub_plugin:
            out = ["PID\tPPID\tImageFileName\tThreads\tHandles\tCreateTime\tStatus"]
            out.append("-" * 85)
            for proc in state.active_processes:
                out.append(f"{proc['pid']}\t{proc['ppid']}\t{proc['name']:<15}\t{proc['threads']}\t{proc['handles']}\t{proc['time']}\tNORMAL")
            # Unlinked hidden process
            h = state.hidden_process
            out.append(f"{h['pid']}\t{h['ppid']}\t{h['name']:<15}\t{h['threads']}\t{h['handles']}\t{h['time']}\tUNLINKED (DKOM!)")
            out.append("\n[!] 경고: PID 4820 (svch0st.exe)이 ActiveProcessLinks에서 누락되어 있으나 풀 메모리 스캔에서 포착되었습니다!")
            out.append(f"[+] Flag 1: {FLAGS['stage1']}")
            state.stage1_solved = True
            if "stage1" not in state.solved_stages:
                state.solved_stages.append("stage1")
            return {"output": "\n".join(out)}

        elif "windows.pstree" in sub_plugin or "pstree" in sub_plugin:
            tree_lines = [
                "PID\tPPID\tImageFileName",
                "4\t0\tSystem",
                " 412\t4\tsmss.exe",
                "  580\t412\tcsrss.exe",
                "   672\t580\tlsass.exe",
                "   788\t580\tservices.exe",
                "    1120\t788\tsvchost.exe",
                "     2440\t1120\texplorer.exe",
                "      3108\t2440\tchrome.exe",
                "     [4820]\t1120\t*svch0st.exe (Unlinked Child!)",
            ]
            return {"output": "\n".join(tree_lines)}

        elif "windows.malfind" in sub_plugin or "malfind" in sub_plugin:
            v = state.injected_vad
            out = [
                f"PID\tProcess\tStart VPN\t\tEnd VPN\t\tTag\tProtection\tCommit",
                f"{v['pid']}\t{v['process']}\t{v['start_vpn']}\t{v['end_vpn']}\t{v['tag']}\t{v['protection']}\t{v['commit_charge']}",
                "\nHex Dump:",
                v["hexdump"],
                "\n[!] 분석 소견: explorer.exe의 RWX(PAGE_EXECUTE_READWRITE) VAD 영역에 PE 시그니처(MZ)가 존재하는 인젝션 쉘코드 발견!",
                f"[+] Flag 2: {FLAGS['stage2']}",
            ]
            state.stage2_solved = True
            if "stage2" not in state.solved_stages:
                state.solved_stages.append("stage2")
            return {"output": "\n".join(out)}

        elif "windows.netscan" in sub_plugin or "netscan" in sub_plugin:
            out = ["Offset\t\tProto\tLocal Address\t\tForeign Address\t\tState\t\tPID\tOwner"]
            out.append("-" * 95)
            for idx, sock in enumerate(state.network_sockets):
                off = f"0x{0x8c000000 + idx * 0x1400:x}"
                out.append(f"{off}\t{sock['proto']}\t{sock['local']:<20}\t{sock['foreign']:<20}\t{sock['state']:<12}\t{sock['pid']}\t{sock['owner']}")
            out.append("\n[!] 이상 징후: 은닉 프로세스 PID 4820 (svch0st.exe)이 외부 IP 198.51.100.89:8443과 활성 C2 세션을 맺고 있습니다!")
            out.append(f"[+] Flag 3: {FLAGS['stage3']}")
            state.stage3_solved = True
            if "stage3" not in state.solved_stages:
                state.solved_stages.append("stage3")
            return {"output": "\n".join(out)}

        elif "windows.lsadump" in sub_plugin or "windows.hashdump" in sub_plugin or "lsadump" in sub_plugin:
            if state.lsa_ppl_enabled:
                return {
                    "output": "[ERROR] Failed to open process token for lsass.exe (STATUS_ACCESS_DENIED).\nLSA Protected Process Light (PPL) is ACTIVE on this system."
                }
            out = ["User:RID:LM-HASH:NTLM-HASH:::"]
            out.append("-" * 75)
            for cred in state.dumped_credentials:
                out.append(f"{cred['user']}:{cred['rid']}:{cred['lm']}:{cred['ntlm']}:::")
            out.append("\n[!] 침해 확인: LSASS 메모리에서 도메인 관리자(Administrator) NTLM 패스워드 해시 추출 성공!")
            out.append(f"[+] Flag 4: {FLAGS['stage4']}")
            state.stage4_solved = True
            if "stage4" not in state.solved_stages:
                state.solved_stages.append("stage4")
            return {"output": "\n".join(out)}

        elif "windows.cmdline" in sub_plugin or "cmdline" in sub_plugin:
            lines = [
                "PID\tProcess\t\tArgs",
                "4\tSystem\t\t<None>",
                "2440\texplorer.exe\tC:\\Windows\\Explorer.EXE",
                "4820\tsvch0st.exe\tC:\\Windows\\Temp\\svch0st.exe -k -c2 198.51.100.89:8443",
            ]
            return {"output": "\n".join(lines)}
        else:
            return {
                "output": f"알 수 없는 Volatility 플러그인: {sub_plugin}\n지원 목록: windows.pslist, windows.psscan, windows.pstree, windows.malfind, windows.netscan, windows.lsadump, windows.cmdline"
            }

    return {"output": f"알 수 없는 명령어: {base}. 'help'를 입력하여 도움말을 확인하세요."}


# ── Web UI Dashboard ─────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MemShield — 메모리 포렌식 & Volatility 3 실습 랩</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --green: #2ea043;
      --red: #f85149;
      --yellow: #d29922;
      --purple: #bc8cff;
      --cyan: #39c5bb;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .header-title h1 {
      font-size: 1.6rem;
      color: var(--text-bright);
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .badge {
      font-size: 0.75rem;
      padding: 4px 8px;
      border-radius: 6px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-blue { background: rgba(56, 139, 253, 0.15); color: var(--accent); border: 1px solid rgba(56, 139, 253, 0.4); }
    .badge-green { background: rgba(46, 160, 67, 0.15); color: var(--green); border: 1px solid rgba(46, 160, 67, 0.4); }
    .badge-red { background: rgba(248, 81, 73, 0.15); color: var(--red); border: 1px solid rgba(248, 81, 73, 0.4); }

    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 24px;
    }
    @media (max-width: 960px) {
      .grid-2 { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
    }
    .card-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--text-bright);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .stage-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px;
      margin-bottom: 10px;
      background: rgba(13, 17, 23, 0.6);
      border: 1px solid var(--border);
      border-radius: 6px;
    }
    .stage-info h4 { color: var(--text-bright); font-size: 0.95rem; }
    .stage-info p { font-size: 0.8rem; color: #8b949e; }

    .btn {
      background: #21262d;
      color: var(--text-bright);
      border: 1px solid var(--border);
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s;
    }
    .btn:hover { background: #30363d; }
    .btn-primary { background: #238636; border-color: rgba(240, 246, 252, 0.1); color: #fff; }
    .btn-primary:hover { background: #2ea043; }
    .btn-danger { background: #da3633; border-color: rgba(240, 246, 252, 0.1); color: #fff; }
    .btn-danger:hover { background: #f85149; }

    .terminal-container {
      background: #090d13;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 12px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.85rem;
      color: #7ee787;
    }
    .terminal-screen {
      height: 280px;
      overflow-y: auto;
      white-space: pre-wrap;
      margin-bottom: 8px;
    }
    .terminal-input-bar {
      display: flex;
      gap: 8px;
      border-top: 1px solid #21262d;
      padding-top: 8px;
    }
    .terminal-input {
      flex: 1;
      background: transparent;
      border: none;
      color: #f0f6fc;
      font-family: inherit;
      outline: none;
    }

    .flag-bar {
      display: flex;
      gap: 10px;
      margin-top: 16px;
    }
    .flag-input {
      flex: 1;
      background: #0d1117;
      border: 1px solid var(--border);
      padding: 8px 12px;
      color: var(--text-bright);
      border-radius: 6px;
    }
  </style>
</head>
<body>
  <header>
    <div class="header-title">
      <h1><i class="fa-solid fa-microchip" style="color: var(--cyan)"></i> MemShield : Volatility 3 메모리 포렌식 랩</h1>
      <span class="badge badge-blue">Lab 16</span>
      <span class="badge badge-green">Port 8016</span>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="resetLab()"><i class="fa-solid fa-rotate-left"></i> 초기화</button>
    </div>
  </header>

  <div class="grid-2">
    <!-- Left: 4 Stages -->
    <div class="card">
      <div class="card-title">
        <span><i class="fa-solid fa-crosshairs"></i> 포렌식 수사 침해 분석 (4단계)</span>
        <span id="solvedBadge" class="badge badge-blue">0 / 4 완료</span>
      </div>

      <!-- Stage 1 -->
      <div class="stage-item">
        <div class="stage-info">
          <h4>Stage 1: DKOM 은닉 프로세스 적출</h4>
          <p>ActiveProcessLinks에서 언링크된 악성 프로세스 풀 스캔 (psscan)</p>
        </div>
        <button id="btnStage1" class="btn btn-primary" onclick="solveStage1()">풀 스캔 분석</button>
      </div>

      <!-- Stage 2 -->
      <div class="stage-item">
        <div class="stage-info">
          <h4>Stage 2: VAD RWX 인젝션 탐지</h4>
          <p>explorer.exe 메모리 내 Reflective PE/Shellcode 추출 (malfind)</p>
        </div>
        <button id="btnStage2" class="btn btn-primary" onclick="solveStage2()">VAD 분석</button>
      </div>

      <!-- Stage 3 -->
      <div class="stage-item">
        <div class="stage-info">
          <h4>Stage 3: C2 비컨 네트워크 아티팩트 복원</h4>
          <p>은닉 프로세스의 외부 역방향 통신 세션 복원 (netscan)</p>
        </div>
        <button id="btnStage3" class="btn btn-primary" onclick="solveStage3()">네트워크 스캔</button>
      </div>

      <!-- Stage 4 -->
      <div class="stage-item">
        <div class="stage-info">
          <h4>Stage 4: LSASS 자격 증명 탈취 & LSA PPL 방어</h4>
          <p>NTLM 해시 덤프 확인 및 RunAsPPL 커널 방어 활성화</p>
        </div>
        <div style="display: flex; gap: 6px;">
          <button id="btnStage4" class="btn btn-danger" onclick="solveStage4()">LSASS 덤프</button>
          <button id="btnPpl" class="btn" onclick="togglePpl()">PPL 방어 토글</button>
        </div>
      </div>

      <!-- Flag Submission -->
      <div class="flag-bar">
        <input type="text" id="flagInput" class="flag-input" placeholder="획득한 플래그 입력 (예: FLAG{...})">
        <button class="btn btn-primary" onclick="submitFlag()"><i class="fa-solid fa-flag"></i> 플래그 제출</button>
      </div>
      <div id="flagResult" style="margin-top: 8px; font-size: 0.85rem;"></div>
    </div>

    <!-- Right: Volatility 3 Terminal -->
    <div class="card">
      <div class="card-title">
        <span><i class="fa-solid fa-terminal"></i> Volatility 3 포렌식 터미널</span>
        <span style="font-size: 0.8rem; color: #8b949e;">victim_win10_enterprise_x64.dmp</span>
      </div>

      <div class="terminal-container">
        <div id="terminalScreen" class="terminal-screen">=== MemShield Volatility 3 Terminal Initialized ===
Type 'help' for available commands or run:
  vol -f memory.raw windows.pslist
  vol -f memory.raw windows.psscan
  vol -f memory.raw windows.malfind
  vol -f memory.raw windows.netscan
  vol -f memory.raw windows.lsadump
</div>
        <div class="terminal-input-bar">
          <span style="color: var(--accent);">$</span>
          <input type="text" id="termInput" class="terminal-input" placeholder="명령어 입력..." onkeydown="handleTermKey(event)">
        </div>
      </div>

      <div style="margin-top: 12px; display: flex; gap: 6px; flex-wrap: wrap;">
        <button class="btn" onclick="sendCmd('vol -f memory.raw windows.psscan')">psscan 실행</button>
        <button class="btn" onclick="sendCmd('vol -f memory.raw windows.malfind')">malfind 실행</button>
        <button class="btn" onclick="sendCmd('vol -f memory.raw windows.netscan')">netscan 실행</button>
        <button class="btn" onclick="sendCmd('vol -f memory.raw windows.lsadump')">lsadump 실행</button>
        <button class="btn" onclick="sendCmd('status')">상태 확인</button>
      </div>
    </div>
  </div>

  <script>
    async function updateStatus() {
      try {
        const res = await fetch('/status');
        const data = await res.json();
        document.getElementById('solvedBadge').innerText = `${data.solved_count} / ${data.total_stages} 완료`;
        if (data.stages.stage1_dkom.solved) markSolved('btnStage1');
        if (data.stages.stage2_malfind.solved) markSolved('btnStage2');
        if (data.stages.stage3_netscan.solved) markSolved('btnStage3');
        if (data.stages.stage4_lsass.solved) markSolved('btnStage4');
        const pplBtn = document.getElementById('btnPpl');
        if (data.stages.stage4_lsass.ppl_enabled) {
          pplBtn.innerText = "PPL: 활성 (방어됨)";
          pplBtn.style.color = "var(--green)";
        } else {
          pplBtn.innerText = "PPL: 비활성 (취약)";
          pplBtn.style.color = "var(--red)";
        }
      } catch (e) {
        console.error(e);
      }
    }

    function markSolved(btnId) {
      const btn = document.getElementById(btnId);
      if (btn) {
        btn.innerText = "완료됨 ✓";
        btn.disabled = true;
        btn.style.opacity = "0.7";
      }
    }

    async function solveStage1() {
      const res = await fetch('/api/stage1/detect-hidden', { method: 'POST' });
      const data = await res.json();
      appendTerminal(`[+] Stage 1 결과:\\n${data.message}\\n플래그: ${data.flag}`);
      updateStatus();
    }

    async function solveStage2() {
      const res = await fetch('/api/stage2/analyze-injected-vad', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: 2440 })
      });
      const data = await res.json();
      appendTerminal(`[+] Stage 2 결과:\\n${data.message}\\n플래그: ${data.flag}`);
      updateStatus();
    }

    async function solveStage3() {
      const res = await fetch('/api/stage3/reconstruct-c2', { method: 'POST' });
      const data = await res.json();
      appendTerminal(`[+] Stage 3 결과:\\n${data.message}\\n플래그: ${data.flag}`);
      updateStatus();
    }

    async function solveStage4() {
      const res = await fetch('/api/stage4/dump-credentials', { method: 'POST' });
      if (res.status === 403) {
        const err = await res.json();
        appendTerminal(`[-] LSASS 덤프 실패: ${err.detail}`);
      } else {
        const data = await res.json();
        appendTerminal(`[+] Stage 4 결과:\\n${data.message}\\n플래그: ${data.flag}`);
      }
      updateStatus();
    }

    async function togglePpl() {
      const res = await fetch('/api/stage4/toggle-ppl', { method: 'POST' });
      const data = await res.json();
      appendTerminal(`[*] ${data.message}`);
      updateStatus();
    }

    async function submitFlag() {
      const val = document.getElementById('flagInput').value.trim();
      if (!val) return;
      const res = await fetch('/api/submit-flag', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag: val })
      });
      const data = await res.json();
      const resDiv = document.getElementById('flagResult');
      if (data.success) {
        resDiv.innerHTML = `<span style="color: var(--green);">✓ ${data.message}</span>`;
      } else {
        resDiv.innerHTML = `<span style="color: var(--red);">✗ ${data.message}</span>`;
      }
      updateStatus();
    }

    async function sendCmd(cmd) {
      document.getElementById('termInput').value = cmd;
      execTerm();
    }

    function handleTermKey(e) {
      if (e.key === 'Enter') {
        execTerm();
      }
    }

    async function execTerm() {
      const input = document.getElementById('termInput');
      const cmd = input.value.trim();
      if (!cmd) return;
      appendTerminal(`$ ${cmd}`);
      input.value = '';

      try {
        const res = await fetch('/api/terminal', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: cmd })
        });
        const data = await res.json();
        appendTerminal(data.output);
      } catch (e) {
        appendTerminal(`Error: ${e.message}`);
      }
      updateStatus();
    }

    function appendTerminal(text) {
      const screen = document.getElementById('terminalScreen');
      screen.innerText += `\\n${text}`;
      screen.scrollTop = screen.scrollHeight;
    }

    async function resetLab() {
      if (!confirm("모든 분석 진행 상황을 초기화하시겠습니까?")) return;
      await fetch('/api/reset', { method: 'POST' });
      document.getElementById('terminalScreen').innerText = "=== MemShield 랩이 초기화되었습니다 ===";
      document.getElementById('flagResult').innerHTML = "";
      location.reload();
    }

    updateStatus();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    return HTMLResponse(content=HTML_TEMPLATE)
