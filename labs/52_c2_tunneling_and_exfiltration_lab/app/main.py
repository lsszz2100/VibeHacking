#!/usr/bin/env python3
"""
Lab 52: C2TunnelGuard — C2 Network Tunneling & Covert Channel Defense Lab
Interactive simulation based on enterprise threat hunting and perimeter defense architectures:
1. DNS Tunneling Analysis: Shannon entropy calculation and Base32/Base64 exfiltration detection
2. Reverse SOCKS5 Pivoting: Chisel / SSH reverse proxy lateral isolation
3. Malleable C2 Jitter: Inter-packet arrival variance and C2 profile fingerprinting
4. Inline DPI & Behavioral Defense: Zeek heuristic tracking and Suricata stateful flowbits drop
"""

import math
from typing import Dict, Any, List, Optional
import os
import re
import hashlib
import json
import time
from collections import Counter
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 52: C2TunnelGuard — C2 Network Tunneling & Covert Channel Defense Lab",
    description="Multi-layered detection and inline mitigation for C2 covert channels and lateral pivoting.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{DNS_TUNNEL_SHANNON_ENTROPY_EXFIL_8841}"
STAGE2_FLAG = "FLAG{SOCKS5_CHISEL_REVERSE_PIVOT_BLOCKED_4129}"
STAGE3_FLAG = "FLAG{C2_MALLEABLE_JITTER_BEACON_NEUTRALIZED_9502}"
STAGE4_FLAG = "FLAG{INLINE_SURICATA_ZEEK_FLOWBITS_DROPPED_7730}"


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy H = -sum(p * log2(p)) for input string.
    Returns 0.0 for empty or single-character strings.
    """
    if not data or not isinstance(data, str):
        return 0.0
    cleaned = data.strip()
    length = len(cleaned)
    if length <= 1:
        return 0.0
    counts = Counter(cleaned)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


class LabState:
    """State manager for Lab 52."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        self.tunnel_isolated: bool = False
        self.active_dpi_rules: List[str] = []


state = LabState()


class DNSEntropyRequest(BaseModel):
    fqdn_query: str = Field(..., min_length=3, max_length=253, description="Target FQDN query (e.g. 78a9c3d2f9b1e0a2.c2.attacker.com)")
    record_type: str = Field(..., min_length=1, max_length=10, description="TXT, A, AAAA, CNAME")
    entropy_threshold: float = Field(..., ge=0.0, le=8.0, description="Entropy detection threshold (standard >= 3.8)")


class ReverseSocksRequest(BaseModel):
    tunnel_tool: str = Field(..., min_length=2, max_length=32, description="chisel, ssh_reverse, ligolo-ng")
    remote_host: str = Field(..., min_length=3, max_length=128, description="C2 proxy endpoint (e.g. 198.51.100.42:8443)")
    dynamic_socks_port: int = Field(..., ge=1, le=65535, description="Target internal SOCKS5 dynamic port (e.g. 1080)")
    isolation_policy: str = Field(..., min_length=3, max_length=64, description="EGRESS_FIREWALL_DROP, SOCKS_AUTHENTICATION_MANDATE")


class C2JitterRequest(BaseModel):
    c2_framework: str = Field(..., min_length=2, max_length=32, description="cobalt_strike, sliver, mythic")
    mean_sleep_sec: int = Field(..., ge=1, le=3600, description="Base heartbeat beacon sleep duration in seconds")
    jitter_percentage: int = Field(..., ge=0, le=100, description="Jitter variation percentage (e.g. 25, 30, 50)")
    header_watermark: str = Field(..., min_length=1, max_length=128, description="Malleable C2 HTTP metadata watermark (e.g. 0xcafe, ms_office_update)")


class InlineDPIRequest(BaseModel):
    sensor_engine: str = Field(..., min_length=2, max_length=32, description="suricata, zeek, snort3")
    rule_signature: str = Field(..., min_length=5, max_length=512, description="DPI signature with flowbits and action (e.g. alert/drop tcp any any -> any any (flowbits:set,c2_tunnel; drop;))")
    flowbits_tag: str = Field(..., min_length=2, max_length=64, description="Stateful flowbits tracking tag (e.g. c2_tunnel_detected)")
    verdict_action: str = Field(..., min_length=2, max_length=32, description="INLINE_DROP, REJECT_RESET")


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return r"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>Lab 52: C2TunnelGuard Console</title>
        <style>
            body { background: #0b0f19; color: #d1d5db; font-family: 'Fira Code', monospace; padding: 20px; }
            h1 { color: #f43f5e; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }
            .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .badge-ready { background: #065f46; color: #34d399; }
            pre { background: #030712; padding: 12px; border-radius: 6px; overflow-x: auto; color: #fca5a5; }
        </style>
    </head>
    <body>
        <h1>📡 Lab 52: C2TunnelGuard Console</h1>
        <div class="card">
            <p><strong>상태:</strong> <span class="badge badge-ready">ONLINE</span> | <strong>C2 방어 모니터링 포트:</strong> 8052</p>
            <p>DNS 터널링 Shannon 엔트로피 분석, 역방향 SOCKS5 피보팅 차단, Malleable C2 지터 비콘 핑거프린팅, Zeek/Suricata 인라인 DPI 방어를 수행하십시오.</p>
        </div>
        <div class="card">
            <h3>진행 단계 (Stages)</h3>
            <ul>
                <li><strong>Stage 1:</strong> DNS 은닉 터널링 Shannon 엔트로피 분석 ($H \ge 3.8$)</li>
                <li><strong>Stage 2:</strong> Chisel/SSH 역방향 SOCKS5 다이나믹 피보팅 차단</li>
                <li><strong>Stage 3:</strong> Malleable C2 비콘 지터(Jitter) 분산 분석 & 프로필 무력화</li>
                <li><strong>Stage 4:</strong> Zeek/Suricata Flowbits 상태 기반 인라인 DPI 실시간 차단</li>
            </ul>
        </div>
    </body>
    </html>
    """


@app.get("/status")
async def get_status():
    return {
        "lab": "52_c2_tunneling_and_exfiltration_lab",
        "title": "C2TunnelGuard — C2 Network Tunneling & Covert Channel Defense Lab",
        "port": 8052,
        "stages": {
            "stage1_dns_tunnel_entropy": state.stage1_completed,
            "stage2_reverse_socks_pivot": state.stage2_completed,
            "stage3_c2_jitter_beacon": state.stage3_completed,
            "stage4_inline_dpi_defense": state.stage4_completed,
        },
        "tunnel_isolated": state.tunnel_isolated,
        "active_dpi_rules_count": len(state.active_dpi_rules),
    }


@app.post("/api/reset")
async def reset_lab():
    state.reset()
    return {"status": "success", "message": "Lab 52 state has been reset."}


@app.post("/api/stage1/analyze_dns_entropy")
async def stage1_analyze_dns(req: DNSEntropyRequest):
    valid_records = {"TXT", "A", "AAAA", "CNAME"}
    rec_type = req.record_type.strip().upper()
    if rec_type not in valid_records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid DNS record type: {req.record_type}. Valid: {sorted(valid_records)}"
        )

    subdomains = [s for s in req.fqdn_query.strip().split(".") if s]
    if len(subdomains) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="FQDN must contain subdomains with encoded payload."
        )

    payload_chunk = subdomains[0]
    calculated_entropy = calculate_shannon_entropy(payload_chunk)

    if calculated_entropy < req.entropy_threshold or req.entropy_threshold < 3.5:
        return {
            "status": "inconclusive",
            "message": f"Calculated Shannon entropy ({calculated_entropy}) is below suspicious exfiltration threshold ({req.entropy_threshold}).",
            "entropy": calculated_entropy,
        }

    state.stage1_completed = True
    return {
        "status": "success",
        "message": "DNS Tunneling exfiltration channel identified! High Shannon entropy in subdomain indicates encoded data stream.",
        "analysis": {
            "query": req.fqdn_query,
            "record_type": rec_type,
            "payload_chunk": payload_chunk,
            "shannon_entropy": calculated_entropy,
            "verdict": "MALICIOUS_DNS_TUNNEL_EXFILTRATION",
        },
        "flag": STAGE1_FLAG,
    }


@app.post("/api/stage2/block_reverse_socks")
async def stage2_block_socks(req: ReverseSocksRequest):
    valid_tools = {"chisel", "ssh_reverse", "ligolo-ng"}
    tool = req.tunnel_tool.strip().lower()
    if tool not in valid_tools:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid tunneling tool: {req.tunnel_tool}. Valid: {sorted(valid_tools)}"
        )

    if req.dynamic_socks_port != 1080 and req.dynamic_socks_port <= 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid internal SOCKS5 dynamic port specification. Privileged ports <= 1024 are disallowed except 1080."
        )

    if req.isolation_policy != "EGRESS_FIREWALL_DROP":
        return {
            "status": "audited_only",
            "message": "Policy was logged but reverse tunnel remains established; egress pivot to lateral subnet succeeded.",
        }

    state.stage2_completed = True
    state.tunnel_isolated = True

    return {
        "status": "success",
        "message": f"Reverse {tool} tunnel toward {req.remote_host} blocked! SOCKS5 dynamic egress severed.",
        "containment": {
            "tunnel_tool": tool,
            "remote_host": req.remote_host,
            "blocked_port": req.dynamic_socks_port,
            "policy_applied": req.isolation_policy,
            "lateral_movement": "PREVENTED",
        },
        "flag": STAGE2_FLAG,
    }


@app.post("/api/stage3/fingerprint_c2_jitter")
async def stage3_fingerprint_jitter(req: C2JitterRequest):
    valid_frameworks = {"cobalt_strike", "sliver", "mythic"}
    framework = req.c2_framework.strip().lower()
    if framework not in valid_frameworks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid C2 framework: {req.c2_framework}. Valid: {sorted(valid_frameworks)}"
        )

    if req.mean_sleep_sec < 5 or req.mean_sleep_sec > 300:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sleep duration must be between 5 and 300 seconds."
        )

    if req.jitter_percentage < 10 or req.jitter_percentage > 90:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jitter percentage must be between 10% and 90%."
        )

    watermark = req.header_watermark.lower()
    if not ("cafe" in watermark or "malleable" in watermark or "office" in watermark):
        return {
            "status": "inconclusive",
            "message": "Header watermark signature does not match known C2 profile indicators.",
        }

    state.stage3_completed = True

    return {
        "status": "success",
        "message": f"{framework} Malleable C2 beacon profile successfully unmasked and fingerprinted!",
        "beacon_profile": {
            "framework": framework,
            "sleep_window": f"{req.mean_sleep_sec}s +/- {req.jitter_percentage}%",
            "header_watermark": req.header_watermark,
            "heuristic_confidence": "HIGH_CONFIDENCE_BEACON",
        },
        "flag": STAGE3_FLAG,
    }


@app.post("/api/stage4/enforce_inline_dpi")
async def stage4_enforce_dpi(req: InlineDPIRequest):
    valid_engines = {"suricata", "zeek", "snort3"}
    engine = req.sensor_engine.strip().lower()
    if engine not in valid_engines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sensor engine: {req.sensor_engine}. Valid: {sorted(valid_engines)}"
        )

    rule = req.rule_signature.lower()
    if not ("flowbits" in rule and ("drop" in rule or "reject" in rule)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule signature must specify flowbits state tracking and drop/reject action."
        )

    if req.verdict_action != "INLINE_DROP":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verdict action must be 'INLINE_DROP' to sever active covert connections."
        )

    state.stage4_completed = True
    clean_sig = req.rule_signature.strip()
    if clean_sig not in state.active_dpi_rules and len(state.active_dpi_rules) < 100:
        state.active_dpi_rules.append(clean_sig)

    return {
        "status": "success",
        "message": f"Inline DPI policy enforced across {engine}! Covert C2 tunnel packet stream dropped synchronously.",
        "dpi_enforcement": {
            "engine": engine,
            "flowbits_tag": req.flowbits_tag,
            "verdict": req.verdict_action,
            "impact": "Exfiltration and C2 beaconing completely halted at perimeter gateway.",
        },
        "flag": STAGE4_FLAG,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8052, reload=True)
