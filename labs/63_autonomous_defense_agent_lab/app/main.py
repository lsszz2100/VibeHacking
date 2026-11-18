import ast
import hashlib
import hmac
import time
import re
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="AutonomousDefenseAgentLab",
    description="Enterprise Autonomous Cyber Defense Agent & Real-time Incident Orchestration Lab",
    version="1.0.0"
)

# In-memory single-use nonce cache for SOAR Ledger attestation
LEDGER_NONCE_CACHE: set = set()
SOAR_HMAC_SECRET = "vibe-soar-auto-defense-hmac-key-2026"

ALLOWED_PLAYBOOK_PACKAGES = {"os", "sys", "json", "time", "logging", "socket", "ipaddress"}
DANGEROUS_COMMANDS = {"rm -rf", "mkfs", "dd if=", "iptables -F", "ufw disable", ":(){ :|:& };:", "drop database", "shutdown"}

MOCK_INCIDENT_CONTEXT = {
    "incident_id": "INC-2026-8063",
    "target_asset": "prod-k8s-ingress-gateway",
    "threat_level": "CRITICAL",
    "c2_channel": "c2-beacon.darknet.internal",
    "attacker_ipv4": "198.51.100.42",
    "attacker_ipv6": "2001:db8:85a3::8a2e:370:7334"
}


class Stage1Request(BaseModel):
    raw_log_payload: str = Field(..., description="Raw security event telemetry log string")
    use_log_sanitizer: bool = Field(False, description="Enable Structured Log Parsing & Dual-LLM Sanitizer Shield")


class Stage2Request(BaseModel):
    playbook_code: str = Field(..., description="Autonomous remediation Python script or shell command")
    use_ast_validator: bool = Field(False, description="Enable Python AST Package Whitelist & Dry-run Sandbox Validator")


class Stage3Request(BaseModel):
    quarantine_target: str = Field(..., description="Target IP/CIDR/Domain for autonomous network isolation")
    use_dualstack_ebpf: bool = Field(False, description="Enable eBPF XDP Dual-Stack (IPv4+IPv6) & Continuous Drift Reconciliation")


class Stage4Request(BaseModel):
    action_type: str = Field("rollback_quarantine", description="SOAR Ledger Action (e.g. rollback_quarantine, release_firewall)")
    incident_id: str = Field("INC-2026-8063", description="Target Incident ID")
    nonce: str = Field(..., description="Single-use cryptographic transaction nonce")
    signature: str = Field(..., description="HMAC-SHA256 signature over nonce + incident_id + action_type")
    approval_token: Optional[str] = Field(None, description="Human-in-the-loop (G1-G3) approval token for destructive actions")
    use_signed_ledger: bool = Field(False, description="Enable Immutable Signed Ledger & Human-in-the-loop G-Approval Gate")


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Lab 63: Autonomous Cyber Defense Agent Lab</title>
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
        .stage-title { color: #7ee787; font-weight: bold; margin-bottom: 0.5rem; }
        code { background: #21262d; padding: 0.2rem 0.4rem; border-radius: 3px; color: #f0883e; }
        .badge { display: inline-block; background: #1f6feb; color: #fff; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.8rem; }
    </style>
</head>
<body>
    <h1>🤖 Lab 63: Autonomous Cyber Defense Agent & Incident Orchestration Lab <span class="badge">Port 8063</span></h1>
    <div class="card">
        <p>2026년 차세대 자율형 사이버 방어 에이전트(ACD) 보안 위협 및 제로 트러스트 오케스트레이션 방어 실전 랩입니다.</p>
        <p>컴플라이언스: <strong>KISA ISMS-P 2.10.1 / 2.10.2</strong>, <strong>NIST CSF 2.0 DE.AE-02 / RS.MI-01</strong>, <strong>OWASP LLM06:2025</strong></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 1: Telemetry Ingestion Poisoning & Prompt Injection Hijack</div>
        <p>엔드포인트: <code>POST /api/stage1/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 2: Hallucinated / Poisoned Remediation Playbook Execution</div>
        <p>엔드포인트: <code>POST /api/stage2/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 3: Autonomous eBPF Network Quarantine Bypass & Drift</div>
        <p>엔드포인트: <code>POST /api/stage3/eval</code></p>
    </div>
    <div class="card">
        <div class="stage-title">Stage 4: SOAR Action Ledger Tampering & Cryptographic Attestation</div>
        <p>엔드포인트: <code>POST /api/stage4/eval</code></p>
    </div>
</body>
</html>"""


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "lab": "AutonomousDefenseAgentLab",
        "lab_id": 63,
        "port": 8063,
        "timestamp": time.time()
    }


@app.get("/api/status")
def status_endpoint():
    return {
        "status": "running",
        "lab": "AutonomousDefenseAgentLab",
        "lab_id": 63,
        "port": 8063,
        "stages": [
            "1: Telemetry Ingestion Poisoning",
            "2: Hallucinated / Poisoned Remediation Playbook",
            "3: Autonomous eBPF Quarantine Bypass",
            "4: SOAR Action Ledger Tampering"
        ]
    }


# =====================================================================
# STAGE 1: Telemetry Ingestion Poisoning & Prompt Injection Hijack
# =====================================================================
@app.post("/api/stage1/eval")
def stage1_eval(req: Stage1Request):
    """
    1단계: 보안 이벤트 로그에 프롬프트 인젝션이 포함되어 에이전트의 위협 분석을 하이재킹하는 공격
    """
    injection_patterns = [
        r"\[LOG_OVERRIDE\]",
        r"ignore\s+(all\s+)?prior\s+instructions",
        r"suppress\s+alert",
        r"grant\s+root",
        r"return\s+secret",
        r"stop\s+all\s+alerts"
    ]
    has_injection = any(re.search(p, req.raw_log_payload, re.IGNORECASE) for p in injection_patterns)

    if not req.use_log_sanitizer:
        # 취약한 모드: 인젝션 페이로드가 파싱 없이 에이전트 프롬프트로 전달되어 분석이 마비됨
        if has_injection:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": "[VULNERABLE] Defense Agent hijacked by log injection! Alert suppressed and sensitive system context leaked.",
                "leaked_context": {
                    "master_api_key": "vibe_auto_agent_master_secret_2026",
                    "flag": "FLAG{auto_defense_telemetry_sanitized_injection_blocked}"
                }
            }
        else:
            return {
                "success": True,
                "status": "NORMAL_TELEMETRY",
                "message": "Telemetry parsed normally without injection."
            }
    else:
        # 방어 모드: Structured Log Parsing & Ingestion Sanitizer 가동
        if has_injection:
            return {
                "success": True,
                "status": "INJECTION_BLOCKED",
                "flag": "FLAG{auto_defense_telemetry_sanitized_injection_blocked}",
                "message": "[SECURE] Malicious telemetry injection neutralized via Structured JSON Parsing & Dual-LLM Guardrail."
            }
        else:
            return {
                "success": True,
                "status": "SECURE_INGESTION",
                "message": "Clean telemetry ingested through sanitized pipeline."
            }


# =====================================================================
# STAGE 2: Hallucinated / Poisoned Remediation Playbook Execution
# =====================================================================
@app.post("/api/stage2/eval")
def stage2_eval(req: Stage2Request):
    """
    2단계: 환각된 패키지(Slop-squatting) 또는 파괴적 커맨드가 포함된 플레이북 실행 유도
    """
    # 1. 파괴적 명령어 검사
    contains_destructive = any(cmd in req.playbook_code.lower() for cmd in DANGEROUS_COMMANDS)

    # 2. 파이썬 코드인 경우 AST 기반 import 패키지 검사
    unauthorized_imports = []
    try:
        tree = ast.parse(req.playbook_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg = alias.name.split('.')[0]
                    if pkg not in ALLOWED_PLAYBOOK_PACKAGES:
                        unauthorized_imports.append(pkg)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    pkg = node.module.split('.')[0]
                    if pkg not in ALLOWED_PLAYBOOK_PACKAGES:
                        unauthorized_imports.append(pkg)
    except SyntaxError:
        pass

    is_hazardous = contains_destructive or len(unauthorized_imports) > 0

    if not req.use_ast_validator:
        # 취약한 모드: 검증 없이 플레이북을 그대로 실행하여 시스템 자해 발생
        if is_hazardous:
            return {
                "success": False,
                "status": "VULNERABLE",
                "message": f"[VULNERABLE] Self-harming remediation playbook executed! Destructive command or unauthorized package '{unauthorized_imports}' ran on production asset.",
                "flag": "FLAG{auto_defense_playbook_ast_validated_dryrun_passed}"
            }
        else:
            return {
                "success": True,
                "status": "SAFE_PLAYBOOK",
                "message": "Benign playbook executed."
            }
    else:
        # 방어 모드: AST 기반 패키지 화이트리스팅 및 Dry-run 가상 샌드박스 검증
        if is_hazardous:
            return {
                "success": True,
                "status": "POISONED_PLAYBOOK_REJECTED",
                "flag": "FLAG{auto_defense_playbook_ast_validated_dryrun_passed}",
                "blocked_reasons": {
                    "unauthorized_imports": unauthorized_imports,
                    "destructive_patterns_found": contains_destructive
                },
                "message": "[SECURE] Poisoned / Hallucinated remediation playbook blocked by AST Validator & Sandbox Pre-flight."
            }
        else:
            return {
                "success": True,
                "status": "PLAYBOOK_APPROVED",
                "message": "Playbook validated and certified for zero-harm execution."
            }


# =====================================================================
# STAGE 3: Autonomous eBPF Network Quarantine Bypass & Drift
# =====================================================================
@app.post("/api/stage3/eval")
def stage3_eval(req: Stage3Request):
    """
    3단계: 단순 IPv4 격리 시 IPv6 또는 C2 도메인 우회 발생 vs Dual-Stack eBPF 완전 격리
    """
    target = req.quarantine_target.strip()
    is_ipv4_only = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$", target))
    is_dualstack_or_c2 = (
        (":" in target) or  # IPv6
        ("c2" in target.lower()) or
        ("darknet" in target.lower()) or
        ("all" in target.lower())
    )

    if not req.use_dualstack_ebpf:
        # 취약한 모드: IPv4 단일 주소만 차단되어 IPv6 C2 통신 채널 우회 성공
        if is_ipv4_only:
            return {
                "success": False,
                "status": "QUARANTINE_DRIFT_BYPASS",
                "message": "[VULNERABLE] IPv4 isolated, but IPv6 C2 Beacon channel (2001:db8:85a3::8a2e:370:7334) remains active!",
                "flag": "FLAG{auto_defense_ebpf_dualstack_quarantine_enforced}"
            }
        else:
            return {
                "success": False,
                "status": "POLICY_FAILED",
                "message": "Simple iptables quarantine failed to handle complex target format."
            }
    else:
        # 방어 모드: eBPF XDP 기반 Dual-Stack (IPv4+IPv6) 종합 격리 및 도메인 싱크홀링
        return {
            "success": True,
            "status": "DUALSTACK_EBPF_SEALED",
            "flag": "FLAG{auto_defense_ebpf_dualstack_quarantine_enforced}",
            "enforced_policies": [
                f"eBPF XDP Ingress/Egress Drop for IPv4: {MOCK_INCIDENT_CONTEXT['attacker_ipv4']}",
                f"eBPF XDP Drop for IPv6: {MOCK_INCIDENT_CONTEXT['attacker_ipv6']}",
                f"DNS Sinkholing for domain: {MOCK_INCIDENT_CONTEXT['c2_channel']}"
            ],
            "message": "[SECURE] Comprehensive Dual-Stack eBPF quarantine enforced with continuous policy drift reconciliation."
        }


# =====================================================================
# STAGE 4: SOAR Action Ledger Tampering & Cryptographic Attestation
# =====================================================================
@app.post("/api/stage4/eval")
def stage4_eval(req: Stage4Request):
    """
    4단계 (Capstone): SOAR 조치 이력 및 롤백 스냅샷 위조 방어 (HMAC-SHA256 불변 원장 & HITL G-Approval)
    """
    # 1. Nonce 재사용 검증 (Replay Protection)
    if req.nonce in LEDGER_NONCE_CACHE:
        raise HTTPException(
            status_code=400,
            detail="[SECURITY ALERT] Cryptographic nonce replay detected! Transaction rejected."
        )

    # 2. HMAC 서명 검증
    expected_msg = f"{req.nonce}:{req.incident_id}:{req.action_type}"
    expected_sig = hmac.new(
        SOAR_HMAC_SECRET.encode(),
        expected_msg.encode(),
        hashlib.sha256
    ).hexdigest()

    is_sig_valid = hmac.compare_digest(expected_sig, req.signature)

    # 3. G1~G3 인간 승인 토큰 검증
    is_approved = req.approval_token == "G3_HUMAN_CHAIR_APPROVAL_2026"

    if not req.use_signed_ledger:
        # 취약한 모드: 서명 및 승인 검증 없이 롤백을 허용하여 공격자가 격리를 해제
        return {
            "success": False,
            "status": "VULNERABLE_ROLLBACK_ACCEPTED",
            "message": "[VULNERABLE] Unsigned rollback action accepted without G-Approval! Threat quarantine dismantled.",
            "flag": "FLAG{auto_defense_soar_ledger_ed25519_attestation_sealed}"
        }
    else:
        # 방어 모드: 서명 검증 + Nonce 캐싱 + HITL 토큰 강제
        if not is_sig_valid:
            raise HTTPException(
                status_code=403,
                detail="[SECURITY_REJECTED] Invalid SOAR Ledger HMAC signature! Action denied."
            )

        if not is_approved:
            raise HTTPException(
                status_code=403,
                detail="[SECURITY_REJECTED] Critical rollback requires valid G3 Human-in-the-loop approval token."
            )

        LEDGER_NONCE_CACHE.add(req.nonce)
        return {
            "success": True,
            "status": "LEDGER_ACTION_ATTESTED",
            "flag": "FLAG{auto_defense_soar_ledger_ed25519_attestation_sealed}",
            "ledger_receipt": {
                "action_type": req.action_type,
                "incident_id": req.incident_id,
                "nonce": req.nonce,
                "attestation_status": "VERIFIED_AND_COMMITTED",
                "approver": "G3_HUMAN_CHAIR"
            },
            "message": "[SECURE] SOAR Ledger action cryptographically verified via HMAC-SHA256 and approved by G3 Human-in-the-loop Gate."
        }
