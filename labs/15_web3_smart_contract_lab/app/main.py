#!/usr/bin/env python3
"""Lab 15: Web3 & Smart Contract Security Lab (ChainDefend).

Interactive simulation of decentralized finance (DeFi) & EVM smart contract vulnerabilities:
1. Reentrancy Attack (Checks-Effects-Interactions violation)
2. Batch Overflow & Integer Arithmetic Vulnerability
3. tx.origin Phishing & Access Control Bypass
4. Flash Loan & AMM Spot Price Oracle Manipulation
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

app = FastAPI(title="ChainDefend - Web3 & Smart Contract Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Challenge Flags
FLAGS = {
    "stage1": "FLAG{REENTRANCY_CHECK_EFFECT_INTERACTION_8831}",
    "stage2": "FLAG{ARITHMETIC_TOKEN_BATCH_OVERFLOW_4412}",
    "stage3": "FLAG{TX_ORIGIN_PHISHING_OWNERSHIP_HIJACK_5920}",
    "stage4": "FLAG{FLASH_LOAN_ORACLE_MANIPULATION_PWN_7139}",
}

# In-Memory State
class Web3LabState:
    def __init__(self):
        self.reset()

    def reset(self):
        # Stage 1: Reentrancy Vault
        self.vault_balance = 10.0  # ETH
        self.user_deposits = {"0xAttacker": 1.0, "0xVictimA": 5.0, "0xVictimB": 4.0}
        self.attacker_wallet = 1.0
        self.stage1_solved = False
        self.stage1_guard_enabled = False

        # Stage 2: Token Bank
        self.token_balances = {"0xAttacker": 10, "0xReceiverA": 0, "0xReceiverB": 0}
        self.token_total_supply = 1000000
        self.stage2_solved = False
        self.stage2_safemath_enabled = False

        # Stage 3: Governance Access Control
        self.admin_address = "0xAdmin999999999999999999999999999999999999"
        self.contract_owner = "0xAdmin999999999999999999999999999999999999"
        self.attacker_address = "0xAttacker11111111111111111111111111111111"
        self.stage3_solved = False
        self.stage3_check_msgsender = False

        # Stage 4: Flash Loan & AMM DEX
        # Constant Product AMM: reserve_eth * reserve_token = k
        self.reserve_eth = 100.0
        self.reserve_token = 100000.0  # 1 ETH = 1000 TOKEN
        self.k = self.reserve_eth * self.reserve_token
        self.lending_pool_eth = 500.0
        self.attacker_profit_token = 0.0
        self.stage4_solved = False
        self.stage4_oracle_twap_enabled = False

        self.solved_stages: list[str] = []
        self.logs: list[str] = [
            f"[{time.strftime('%H:%M:%S')}] Blockchain EVM Node initialized. Block #19823412."
        ]

    def log(self, msg: str):
        self.logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(self.logs) > 60:
            self.logs.pop(0)

state = Web3LabState()

# Request Models
class TerminalCommand(BaseModel):
    command: str

class FlagSubmission(BaseModel):
    flag: str

class ReentrancyRequest(BaseModel):
    attacker_contract: bool = True
    iterations: int = 10

class BatchTransferRequest(BaseModel):
    receivers: list[str]
    value_hex: str  # e.g., "0x8000000000000000000000000000000000000000000000000000000000000000" (2^255)

class PhishingRequest(BaseModel):
    phishing_contract_deployed: bool
    lured_admin_click: bool

class FlashLoanRequest(BaseModel):
    borrow_eth: float
    swap_direction: str  # "eth_to_token" or "token_to_eth"
    exploit_oracle: bool


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/status")
def get_status():
    return {
        "status": "online",
        "chain_id": 31337,
        "block_number": 19823412,
        "stages": {
            "stage1_reentrancy": {
                "solved": state.stage1_solved,
                "vault_balance_eth": state.vault_balance,
                "attacker_balance_eth": state.attacker_wallet,
                "reentrancy_guard": state.stage1_guard_enabled,
            },
            "stage2_overflow": {
                "solved": state.stage2_solved,
                "attacker_tokens": state.token_balances.get("0xAttacker", 0),
                "safemath_active": state.stage2_safemath_enabled,
            },
            "stage3_tx_origin": {
                "solved": state.stage3_solved,
                "current_owner": state.contract_owner,
                "is_attacker_owner": state.contract_owner == state.attacker_address,
                "check_msg_sender": state.stage3_check_msgsender,
            },
            "stage4_flashloan": {
                "solved": state.stage4_solved,
                "reserve_eth": state.reserve_eth,
                "reserve_token": state.reserve_token,
                "attacker_profit_tokens": state.attacker_profit_token,
                "twap_oracle_enabled": state.stage4_oracle_twap_enabled,
            },
        },
        "solved_count": len(state.solved_stages),
        "total_stages": 4,
    }

@app.post("/api/reset")
def reset_simulation():
    state.reset()
    state.log("EVM Simulator state reset to initial block snapshot.")
    return {"message": "Reset successful", "status": "ok"}

# Stage 1: Reentrancy
@app.post("/api/stage1/reentrancy-attack")
def attack_reentrancy(req: ReentrancyRequest):
    if state.stage1_guard_enabled:
        state.log("Reentrancy attack failed: ReentrancyGuard reverted the re-entrant call.")
        raise HTTPException(status_code=400, detail="Execution reverted: ReentrancyGuard: reentrant call")

    if not req.attacker_contract:
        # Normal withdraw
        if state.user_deposits.get("0xAttacker", 0) <= 0:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        amt = state.user_deposits["0xAttacker"]
        state.user_deposits["0xAttacker"] = 0
        state.vault_balance -= amt
        state.attacker_wallet += amt
        state.log(f"Normal withdraw executed: {amt} ETH.")
        return {"message": "Normal withdraw success", "vault_balance": state.vault_balance}

    # Malicious fallback recursive exploit
    stolen = min(state.vault_balance, req.iterations * 1.0)
    state.vault_balance -= stolen
    state.attacker_wallet += stolen
    state.user_deposits["0xAttacker"] = 0
    state.log(f"ALERT: Reentrancy recursive fallback triggered! Drained {stolen} ETH from Vault.")

    if state.vault_balance <= 0.0:
        state.stage1_solved = True
        if "stage1" not in state.solved_stages:
            state.solved_stages.append("stage1")
        return {
            "success": True,
            "message": "Vault drained to 0 ETH via recursive reentrancy fallback!",
            "vault_balance": state.vault_balance,
            "attacker_wallet": state.attacker_wallet,
            "flag": FLAGS["stage1"],
        }
    return {
        "success": True,
        "message": f"Partially drained {stolen} ETH. Run more iterations to drain completely.",
        "vault_balance": state.vault_balance,
    }

@app.post("/api/stage1/toggle-guard")
def toggle_reentrancy_guard():
    state.stage1_guard_enabled = not state.stage1_guard_enabled
    state.log(f"Stage 1 ReentrancyGuard set to {state.stage1_guard_enabled}.")
    return {"guard_enabled": state.stage1_guard_enabled}

# Stage 2: Integer Batch Overflow
@app.post("/api/stage2/batch-transfer")
def attack_batch_overflow(req: BatchTransferRequest):
    if state.stage2_safemath_enabled:
        state.log("Batch transfer rejected: SafeMath/Checked arithmetic prevented overflow.")
        raise HTTPException(status_code=400, detail="Transaction reverted: arithmetic overflow detected")

    receivers_count = len(req.receivers)
    if receivers_count == 0:
        raise HTTPException(status_code=400, detail="Receivers list cannot be empty")

    try:
        val_int = int(req.value_hex, 16) if req.value_hex.startswith("0x") else int(req.value_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid integer value format")

    # 256-bit unsigned math simulation
    MAX_UINT256 = (1 << 256) - 1
    total_unwrapped = receivers_count * val_int
    total_wrapped = total_unwrapped & MAX_UINT256

    # Vulnerability check: require(balances[msg.sender] >= total_wrapped)
    attacker_bal = state.token_balances.get("0xAttacker", 0)
    if attacker_bal < total_wrapped:
        raise HTTPException(status_code=400, detail=f"Insufficient balance: {attacker_bal} < {total_wrapped}")

    # Deduct wrapped total
    state.token_balances["0xAttacker"] -= total_wrapped
    for r in req.receivers:
        state.token_balances[r] = state.token_balances.get(r, 0) + val_int

    state.log(f"BatchTransfer executed: {receivers_count} receivers * {val_int} = wrapped {total_wrapped}")

    # Check if attacker or receiver gained astronomical tokens
    if any(bal > 1000000 for bal in state.token_balances.values()):
        state.stage2_solved = True
        if "stage2" not in state.solved_stages:
            state.solved_stages.append("stage2")
        return {
            "success": True,
            "message": "Batch overflow triggered! Huge token balance minted out of thin air!",
            "attacker_balance": state.token_balances.get("0xAttacker", 0),
            "receivers_balance": {r: state.token_balances.get(r) for r in req.receivers},
            "flag": FLAGS["stage2"],
        }

    return {"success": True, "balances": state.token_balances}

@app.post("/api/stage2/toggle-safemath")
def toggle_safemath():
    state.stage2_safemath_enabled = not state.stage2_safemath_enabled
    state.log(f"Stage 2 SafeMath set to {state.stage2_safemath_enabled}.")
    return {"safemath_enabled": state.stage2_safemath_enabled}

# Stage 3: tx.origin Phishing
@app.post("/api/stage3/phishing-attack")
def attack_tx_origin(req: PhishingRequest):
    if state.stage3_check_msgsender:
        state.log("tx.origin phishing blocked: Contract uses msg.sender check instead of tx.origin.")
        raise HTTPException(status_code=403, detail="Unauthorized: msg.sender is not contract owner")

    if not req.phishing_contract_deployed or not req.lured_admin_click:
        raise HTTPException(status_code=400, detail="Attack prerequisites missing: deploy phishing contract and lure admin.")

    # tx.origin is Admin, but msg.sender is PhishingContract
    state.contract_owner = state.attacker_address
    state.stage3_solved = True
    if "stage3" not in state.solved_stages:
        state.solved_stages.append("stage3")
    state.log("ALERT: tx.origin phishing successful! Governance ownership hijacked by 0xAttacker.")

    return {
        "success": True,
        "message": "Ownership transferred to 0xAttacker via tx.origin phishing bypass!",
        "new_owner": state.contract_owner,
        "flag": FLAGS["stage3"],
    }

@app.post("/api/stage3/toggle-defense")
def toggle_tx_origin_defense():
    state.stage3_check_msgsender = not state.stage3_check_msgsender
    state.log(f"Stage 3 Access Control check set to msg.sender == owner: {state.stage3_check_msgsender}")
    return {"check_msg_sender": state.stage3_check_msgsender}

# Stage 4: Flash Loan Price Manipulation
@app.post("/api/stage4/flashloan-attack")
def attack_flashloan(req: FlashLoanRequest):
    if state.stage4_oracle_twap_enabled:
        state.log("Flash loan manipulation failed: TWAP oracle filtered instant spot price spike.")
        raise HTTPException(status_code=400, detail="Oracle protection: Price deviation rejected by TWAP window.")

    if req.borrow_eth > state.lending_pool_eth:
        raise HTTPException(status_code=400, detail="Lending pool insufficient liquidity.")

    borrow_amount = req.borrow_eth
    # 1. Flash loan borrowed
    state.log(f"Flash loan initiated: borrowed {borrow_amount} ETH from lending pool.")

    # 2. Swap in AMM (x * y = k)
    # new_eth = reserve_eth + borrow_amount
    new_eth = state.reserve_eth + borrow_amount
    new_token = state.k / new_eth
    tokens_out = state.reserve_token - new_token

    state.reserve_eth = new_eth
    state.reserve_token = new_token
    spot_price_eth_per_token = state.reserve_eth / state.reserve_token

    state.log(f"AMM Swapped {borrow_amount} ETH for {tokens_out:.2f} tokens. Spot price skewed to {spot_price_eth_per_token:.4f} ETH/token.")

    # 3. Liquidate/Borrow from vulnerable lending protocol using spot price
    if req.exploit_oracle and borrow_amount >= 300.0:
        profit = tokens_out * 1.5
        state.attacker_profit_token = profit
        state.stage4_solved = True
        if "stage4" not in state.solved_stages:
            state.solved_stages.append("stage4")
        state.log(f"FLASH LOAN EXPLOIT SUCCESS: Extracted {profit:.2f} tokens profit at skewed oracle price.")

        # Rebalance AMM partially
        state.reserve_eth = 100.0
        state.reserve_token = 100000.0

        return {
            "success": True,
            "message": "Flash loan oracle manipulation completed! Massive profit extracted.",
            "profit_tokens": profit,
            "flag": FLAGS["stage4"],
        }

    # Normal payback
    state.reserve_eth = 100.0
    state.reserve_token = 100000.0
    return {
        "success": False,
        "message": "Flash loan repaid, but insufficient borrow volume or exploit toggle disabled to manipulate oracle.",
    }

@app.post("/api/stage4/toggle-twap")
def toggle_twap_defense():
    state.stage4_oracle_twap_enabled = not state.stage4_oracle_twap_enabled
    state.log(f"Stage 4 TWAP Oracle set to {state.stage4_oracle_twap_enabled}.")
    return {"twap_oracle_enabled": state.stage4_oracle_twap_enabled}

# Flag Verification
@app.post("/api/submit-flag")
def submit_flag(req: FlagSubmission):
    flag_cleaned = req.flag.strip()
    for stage_name, expected_flag in FLAGS.items():
        if flag_cleaned == expected_flag:
            if stage_name not in state.solved_stages:
                state.solved_stages.append(stage_name)
            state.log(f"FLAG VERIFIED: {stage_name.upper()} solved successfully!")
            return {
                "success": True,
                "stage": stage_name,
                "message": f"Congratulations! {stage_name.upper()} cleared.",
                "solved_total": len(state.solved_stages),
            }
    state.log(f"Flag rejected: {flag_cleaned[:12]}...")
    return {"success": False, "message": "Invalid flag submission."}

# Terminal Simulator
@app.post("/api/terminal")
def terminal_command(req: TerminalCommand):
    cmd_raw = req.command.strip()
    if not cmd_raw:
        return {"output": ""}

    parts = shlex.split(cmd_raw)
    cmd = parts[0].lower()

    if cmd == "help":
        out = (
            "ChainDefend EVM Terminal Help:\n"
            "  forge test [-v]             Run smart contract test suite\n"
            "  cast balance <address>       Inspect ETH/Token balance of address\n"
            "  cast call <contract> <func>  Call contract view function\n"
            "  solc --version               Check Solidity compiler version\n"
            "  status                       View challenges progress\n"
            "  cat <contract.sol>           Read contract source code\n"
            "  ls                           List available contracts\n"
            "  clear                        Clear terminal output"
        )
    elif cmd == "ls":
        out = "ReentrancyVault.sol  TokenBank.sol  Governance.sol  UniswapV2Pair.sol  Exploit.sol"
    elif cmd == "cat":
        arg = parts[1] if len(parts) > 1 else ""
        if "reentrancy" in arg.lower():
            out = (
                "// ReentrancyVault.sol\n"
                "contract ReentrancyVault {\n"
                "    mapping(address => uint256) public balances;\n"
                "    function withdraw() external {\n"
                "        uint256 bal = balances[msg.sender];\n"
                "        require(bal > 0);\n"
                "        (bool s, ) = msg.sender.call{value: bal}(\"\"); // VULNERABILITY\n"
                "        balances[msg.sender] = 0;\n"
                "    }\n"
                "}"
            )
        elif "token" in arg.lower():
            out = (
                "// TokenBank.sol\n"
                "function batchTransfer(address[] calldata receivers, uint256 value) external {\n"
                "    uint256 total = receivers.length * value; // VULNERABILITY: Overflow\n"
                "    require(balances[msg.sender] >= total);\n"
                "    balances[msg.sender] -= total;\n"
                "    for (uint i = 0; i < receivers.length; i++) balances[receivers[i]] += value;\n"
                "}"
            )
        elif "gov" in arg.lower():
            out = (
                "// Governance.sol\n"
                "function transferOwnership(address newOwner) public {\n"
                "    require(tx.origin == owner); // VULNERABILITY: tx.origin phishing\n"
                "    owner = newOwner;\n"
                "}"
            )
        elif "uni" in arg.lower():
            out = (
                "// UniswapV2Pair.sol\n"
                "// Spot price = reserve0 / reserve1\n"
                "// VULNERABILITY: Instant oracle query vulnerable to flash loan skew."
            )
        else:
            out = f"cat: {arg}: No such contract or file."
    elif cmd == "solc":
        out = "solc, the solidity compiler commandline interface\nVersion: 0.8.24+commit.e11b9ed9.Linux.g++"
    elif cmd == "forge" and len(parts) > 1 and parts[1] == "test":
        out = (
            "[⠊] Compiling...\n"
            "[⠒] Running tests...\n"
            f"[PASS] test_Reentrancy_Drain() (vault_bal={state.vault_balance} ETH)\n"
            f"[PASS] test_BatchOverflow_Mint() (attacker_tokens={state.token_balances.get('0xAttacker',0)})\n"
            f"[PASS] test_TxOrigin_Phish() (owner={state.contract_owner[:10]}...)\n"
            f"[PASS] test_FlashLoan_Oracle() (profit={state.attacker_profit_token:.2f})\n"
            f"Suite result: ok. 4 passed; 0 failed; finished in 18.21ms"
        )
    elif cmd == "cast":
        subcmd = parts[1] if len(parts) > 1 else ""
        if subcmd == "balance":
            out = (
                f"0xVault:     {state.vault_balance} ETH\n"
                f"0xAttacker:  {state.attacker_wallet} ETH / {state.token_balances.get('0xAttacker',0)} TOKENS\n"
                f"0xDEX Pool:  {state.reserve_eth} ETH / {state.reserve_token} TOKENS"
            )
        else:
            out = "cast: call executed successfully. Result: 0x000000000000000000000001"
    elif cmd == "status":
        out = f"ChainDefend Status: {len(state.solved_stages)}/4 Stages Cleared. Solved: {state.solved_stages}"
    else:
        out = f"zsh: command not found: {cmd}. Type 'help' for available commands."

    return {"output": out}

# Web Dashboard HTML
@app.get("/", response_class=HTMLResponse)
def index_page():
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 15 — ChainDefend Web3 & Smart Contract Security</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --panel: #111827;
            --border: #1f2937;
            --accent: #10b981;
            --eth: #627eea;
            --danger: #ef4444;
            --text: #e5e7eb;
            --dim: #9ca3af;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', system-ui, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .title h1 {{ font-size: 1.5rem; color: #fff; display: flex; align-items: center; gap: 8px; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
            background: #1e293b;
            color: var(--accent);
            border: 1px solid #334155;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card h2 {{
            font-size: 1.1rem;
            margin-bottom: 12px;
            color: #f3f4f6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .status-pill {{
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 4px;
            background: #374151;
        }}
        .status-pill.solved {{ background: #065f46; color: #34d399; font-weight: bold; }}
        .btn {{
            background: #2563eb;
            color: #fff;
            border: none;
            padding: 8px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            margin-top: 10px;
            font-size: 0.85rem;
        }}
        .btn:hover {{ background: #1d4ed8; }}
        .btn-danger {{ background: #dc2626; }}
        .btn-danger:hover {{ background: #b91c1c; }}
        .btn-secondary {{ background: #374151; }}
        .btn-secondary:hover {{ background: #4b5563; }}
        .terminal-box {{
            background: #030712;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: 'Consolas', monospace;
            font-size: 0.85rem;
            margin-top: 20px;
        }}
        .terminal-out {{
            min-height: 120px;
            max-height: 200px;
            overflow-y: auto;
            color: #a7f3d0;
            white-space: pre-wrap;
            margin-bottom: 10px;
        }}
        .terminal-input {{
            width: 100%;
            background: transparent;
            border: none;
            border-top: 1px solid #1f2937;
            padding-top: 8px;
            color: #fff;
            outline: none;
            font-family: inherit;
        }}
        .flag-box {{
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }}
        .flag-input {{
            flex: 1;
            padding: 8px 12px;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 4px;
            color: #fff;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">
            <h1>⛓️ ChainDefend — Web3 & 스마트 컨트랙트 보안 랩</h1>
            <span class="badge">EVM Hardhat/Foundry Sim #31337</span>
        </div>
        <button class="btn btn-secondary" onclick="resetLab()">EVM 상태 리셋</button>
    </div>

    <div class="grid">
        <!-- Stage 1: Reentrancy -->
        <div class="card">
            <h2>
                1. Reentrancy Vault
                <span class="status-pill {'solved' if state.stage1_solved else ''}" id="badge1">
                    {'SOLVED' if state.stage1_solved else 'UNSOLVED'}
                </span>
            </h2>
            <p style="font-size:0.85rem; color:var(--dim); margin-bottom:10px;">
                외부 호출 후 잔고 업데이트 취약점을 악용해 금고(Vault) 전액 탈취.
            </p>
            <div style="font-size:0.85rem;">
                금고 잔고: <b style="color:var(--eth);" id="vaultBal">{state.vault_balance} ETH</b><br>
                공격자 지갑: <b id="atkWallet">{state.attacker_wallet} ETH</b><br>
                ReentrancyGuard: <b id="guardStatus">{'ON' if state.stage1_guard_enabled else 'OFF'}</b>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-danger" onclick="attackReentrancy()">재진입 공격 실행</button>
                <button class="btn btn-secondary" onclick="toggleGuard()">방어 가드 토글</button>
            </div>
        </div>

        <!-- Stage 2: Batch Overflow -->
        <div class="card">
            <h2>
                2. Token Batch Overflow
                <span class="status-pill {'solved' if state.stage2_solved else ''}" id="badge2">
                    {'SOLVED' if state.stage2_solved else 'UNSOLVED'}
                </span>
            </h2>
            <p style="font-size:0.85rem; color:var(--dim); margin-bottom:10px;">
                <code>receivers.length * value</code>의 256비트 정수 오버플로를 유도하여 무한 토큰 탈취.
            </p>
            <div style="font-size:0.85rem;">
                공격자 토큰 잔고: <b style="color:#fbbf24;" id="atkTokens">{state.token_balances.get('0xAttacker', 0)} TOKENS</b><br>
                SafeMath/Checked 방어: <b id="safemathStatus">{'ON' if state.stage2_safemath_enabled else 'OFF'}</b>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-danger" onclick="attackOverflow()">배치 오버플로 공격</button>
                <button class="btn btn-secondary" onclick="toggleSafeMath()">SafeMath 토글</button>
            </div>
        </div>

        <!-- Stage 3: tx.origin Phishing -->
        <div class="card">
            <h2>
                3. tx.origin Phishing
                <span class="status-pill {'solved' if state.stage3_solved else ''}" id="badge3">
                    {'SOLVED' if state.stage3_solved else 'UNSOLVED'}
                </span>
            </h2>
            <p style="font-size:0.85rem; color:var(--dim); margin-bottom:10px;">
                취약한 <code>tx.origin == owner</code> 검증을 피싱 스마트 컨트랙트로 우회하여 관리자 탈취.
            </p>
            <div style="font-size:0.85rem;">
                컨트랙트 소유자: <b id="govOwner" style="font-family:monospace; font-size:0.75rem;">{state.contract_owner[:18]}...</b><br>
                msg.sender 권한 검증 방어: <b id="originDefenseStatus">{'ON' if state.stage3_check_msgsender else 'OFF'}</b>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-danger" onclick="attackTxOrigin()">피싱 공격 실행</button>
                <button class="btn btn-secondary" onclick="toggleOriginDefense()">msg.sender 방어 토글</button>
            </div>
        </div>

        <!-- Stage 4: Flash Loan AMM -->
        <div class="card">
            <h2>
                4. Flash Loan Oracle Manipulation
                <span class="status-pill {'solved' if state.stage4_solved else ''}" id="badge4">
                    {'SOLVED' if state.stage4_solved else 'UNSOLVED'}
                </span>
            </h2>
            <p style="font-size:0.85rem; color:var(--dim); margin-bottom:10px;">
                거대 플래시론으로 AMM 현물 가격 풀을 일시 왜곡시켜 과소평가 담보 차익 착취.
            </p>
            <div style="font-size:0.85rem;">
                DEX 풀: <b id="dexEth">{state.reserve_eth} ETH</b> / <b id="dexToken">{state.reserve_token} TOKEN</b><br>
                차익 탈취 수익: <b style="color:var(--accent);" id="flProfit">{state.attacker_profit_token:.2f} TOKENS</b><br>
                TWAP 오라클 방어: <b id="twapStatus">{'ON' if state.stage4_oracle_twap_enabled else 'OFF'}</b>
            </div>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-danger" onclick="attackFlashLoan()">플래시론 공격 실행</button>
                <button class="btn btn-secondary" onclick="toggleTWAP()">TWAP 오라클 토글</button>
            </div>
        </div>
    </div>

    <!-- Flag Submission -->
    <div class="card" style="margin-bottom:20px;">
        <h2>🚩 플래그 제출 및 채점 (Flag Verification)</h2>
        <div class="flag-box">
            <input type="text" id="flagInput" class="flag-input" placeholder="FLAG{{...}}">
            <button class="btn" onclick="submitFlag()">제출하기</button>
        </div>
        <div id="flagResult" style="margin-top:10px; font-size:0.85rem;"></div>
    </div>

    <!-- Interactive Terminal -->
    <div class="terminal-box">
        <div class="terminal-out" id="termOut">Web3 EVM Foundry & Cast CLI 준비 완료. 'help', 'ls', 'forge test' 명령어를 입력하세요.</div>
        <input type="text" class="terminal-input" id="termIn" placeholder="EVM 명령 입력 (예: forge test, cast balance 0xVault)..." onkeydown="handleTerm(event)">
    </div>

    <script>
        async function updateStatus() {{
            const res = await fetch('/status');
            const data = await res.json();
            document.getElementById('vaultBal').innerText = data.stages.stage1_reentrancy.vault_balance_eth + ' ETH';
            document.getElementById('atkWallet').innerText = data.stages.stage1_reentrancy.attacker_balance_eth + ' ETH';
            document.getElementById('guardStatus').innerText = data.stages.stage1_reentrancy.reentrancy_guard ? 'ON' : 'OFF';
            if (data.stages.stage1_reentrancy.solved) {{
                document.getElementById('badge1').innerText = 'SOLVED';
                document.getElementById('badge1').className = 'status-pill solved';
            }}
            document.getElementById('atkTokens').innerText = data.stages.stage2_overflow.attacker_tokens + ' TOKENS';
            document.getElementById('safemathStatus').innerText = data.stages.stage2_overflow.safemath_active ? 'ON' : 'OFF';
            if (data.stages.stage2_overflow.solved) {{
                document.getElementById('badge2').innerText = 'SOLVED';
                document.getElementById('badge2').className = 'status-pill solved';
            }}
            document.getElementById('govOwner').innerText = data.stages.stage3_tx_origin.current_owner.substring(0, 18) + '...';
            document.getElementById('originDefenseStatus').innerText = data.stages.stage3_tx_origin.check_msg_sender ? 'ON' : 'OFF';
            if (data.stages.stage3_tx_origin.solved) {{
                document.getElementById('badge3').innerText = 'SOLVED';
                document.getElementById('badge3').className = 'status-pill solved';
            }}
            document.getElementById('dexEth').innerText = data.stages.stage4_flashloan.reserve_eth + ' ETH';
            document.getElementById('dexToken').innerText = data.stages.stage4_flashloan.reserve_token + ' TOKEN';
            document.getElementById('flProfit').innerText = data.stages.stage4_flashloan.attacker_profit_tokens.toFixed(2) + ' TOKENS';
            document.getElementById('twapStatus').innerText = data.stages.stage4_flashloan.twap_oracle_enabled ? 'ON' : 'OFF';
            if (data.stages.stage4_flashloan.solved) {{
                document.getElementById('badge4').innerText = 'SOLVED';
                document.getElementById('badge4').className = 'status-pill solved';
            }}
        }}

        async function attackReentrancy() {{
            const res = await fetch('/api/stage1/reentrancy-attack', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ attacker_contract: true, iterations: 10 }})
            }});
            const data = await res.json();
            alert(data.message + (data.flag ? '\\n' + data.flag : ''));
            updateStatus();
        }}

        async function toggleGuard() {{
            await fetch('/api/stage1/toggle-guard', {{ method: 'POST' }});
            updateStatus();
        }}

        async function attackOverflow() {{
            const res = await fetch('/api/stage2/batch-transfer', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    receivers: ["0xReceiverA", "0xReceiverB"],
                    value_hex: "0x8000000000000000000000000000000000000000000000000000000000000000"
                }})
            }});
            const data = await res.json();
            alert(data.message + (data.flag ? '\\n' + data.flag : ''));
            updateStatus();
        }}

        async function toggleSafeMath() {{
            await fetch('/api/stage2/toggle-safemath', {{ method: 'POST' }});
            updateStatus();
        }}

        async function attackTxOrigin() {{
            const res = await fetch('/api/stage3/phishing-attack', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ phishing_contract_deployed: true, lured_admin_click: true }})
            }});
            const data = await res.json();
            alert(data.message + (data.flag ? '\\n' + data.flag : ''));
            updateStatus();
        }}

        async function toggleOriginDefense() {{
            await fetch('/api/stage3/toggle-defense', {{ method: 'POST' }});
            updateStatus();
        }}

        async function attackFlashLoan() {{
            const res = await fetch('/api/stage4/flashloan-attack', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ borrow_eth: 400.0, swap_direction: 'eth_to_token', exploit_oracle: true }})
            }});
            const data = await res.json();
            alert(data.message + (data.flag ? '\\n' + data.flag : ''));
            updateStatus();
        }}

        async function toggleTWAP() {{
            await fetch('/api/stage4/toggle-twap', {{ method: 'POST' }});
            updateStatus();
        }}

        async function resetLab() {{
            await fetch('/api/reset', {{ method: 'POST' }});
            alert('EVM Simulator reset.');
            updateStatus();
        }}

        async function submitFlag() {{
            const flag = document.getElementById('flagInput').value.trim();
            const res = await fetch('/api/submit-flag', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ flag }})
            }});
            const data = await res.json();
            const el = document.getElementById('flagResult');
            if (data.success) {{
                el.style.color = '#34d399';
                el.innerText = '✓ ' + data.message;
            }} else {{
                el.style.color = '#f87171';
                el.innerText = '✗ ' + data.message;
            }}
            updateStatus();
        }}

        async function handleTerm(e) {{
            if (e.key === 'Enter') {{
                const input = document.getElementById('termIn');
                const cmd = input.value;
                input.value = '';
                const out = document.getElementById('termOut');
                out.innerText += '\\n> ' + cmd;
                if (cmd.trim() === 'clear') {{
                    out.innerText = '';
                    return;
                }}
                const res = await fetch('/api/terminal', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ command: cmd }})
                }});
                const data = await res.json();
                out.innerText += '\\n' + data.output;
                out.scrollTop = out.scrollHeight;
            }}
        }}
    </script>
</body>
</html>
"""
