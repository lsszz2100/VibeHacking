from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import hashlib
import hmac

app = FastAPI(
    title="Lab 68: Autonomous Agent Swarm Security & Byzantine Defense Lab",
    version="2.18.0",
    description="Multi-Agent Swarm Orchestration, Rogue Agent Identity Verification, Byzantine Fault Mitigation & eBPF Tetragon Lateral Containment"
)

SWARM_SHARED_SECRET = b"vibe-2026-enterprise-agent-swarm-cluster-secret-8068"

class Stage1Payload(BaseModel):
    agent_spiffe_id: str
    mtls_client_cert_hash: str
    signature: str
    enforce_identity_pinning: bool

class Stage2Payload(BaseModel):
    quorum_size: int
    byzantine_fault_tolerance: str
    consensus_round: int
    worker_votes: List[str]
    mitigate_outlier_weight: bool

class Stage3Payload(BaseModel):
    context_window_id: str
    enforce_landlock_ro_snapshot: bool
    ephemeral_memory_namespace: bool
    prevent_cross_agent_injection: bool

class Stage4Payload(BaseModel):
    lateral_target_agent: str
    tetragon_tracing_policy: str
    sigkill_on_unauthorized_ipc: bool
    zero_trust_mesh_audit_hmac: str

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "lab_id": 68,
        "name": "autonomous_agent_swarm_lab",
        "stages": 4,
        "category": "ai",
        "version": "2.18.0"
    }

@app.get("/")
def read_root():
    return {
        "lab": "Lab 68: Autonomous Agent Swarm Security & Byzantine Defense Lab",
        "status": "ready",
        "port": 8068,
        "stages": 4,
        "category": "ai",
        "version": "2.18.0"
    }

@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """Stage 1: Rogue Agent Registration & mTLS Identity Verification"""
    expected_spiffe = "spiffe://vibe.internal/agent/swarm-worker-verified"
    if not payload.enforce_identity_pinning:
        raise HTTPException(status_code=400, detail="Identity pinning must be enforced to mitigate rogue agent spoofing.")
    
    if payload.agent_spiffe_id != expected_spiffe:
        raise HTTPException(status_code=403, detail="Untrusted agent SPIFFE ID. Rogue worker rejected.")
    
    if len(payload.mtls_client_cert_hash) < 64:
        raise HTTPException(status_code=400, detail="Invalid client certificate SHA-256 fingerprint.")
    
    # Verify HMAC signature with SWARM_SHARED_SECRET
    expected_sig = hmac.new(SWARM_SHARED_SECRET, payload.agent_spiffe_id.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(payload.signature, expected_sig):
        raise HTTPException(status_code=401, detail="Agent identity signature verification failed.")
    
    return {
        "success": True,
        "stage": 1,
        "flag": "FLAG{v218_s1_rogue_swarm_agent_mtls_identity_verified}",
        "message": "mTLS mutual authentication & SPIFFE ID identity verified. Rogue worker blocked."
    }

@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """Stage 2: Swarm Consensus Poisoning & Byzantine Fault Mitigation"""
    if payload.quorum_size < 4:
        raise HTTPException(status_code=400, detail="Quorum size must be at least 3f + 1 (>= 4 for 1 Byzantine fault).")
    
    if payload.byzantine_fault_tolerance.lower() != "pbft":
        raise HTTPException(status_code=400, detail="Byzantine fault tolerance protocol must be PBFT.")
    
    if not payload.mitigate_outlier_weight:
        raise HTTPException(status_code=400, detail="Outlier weight mitigation must be active.")
    
    if len(payload.worker_votes) < 3:
        raise HTTPException(status_code=400, detail="Insufficient worker consensus votes.")
    
    return {
        "success": True,
        "stage": 2,
        "flag": "FLAG{v218_s2_pbft_consensus_byzantine_fault_mitigated}",
        "message": "PBFT 3-phase consensus validated. Poisoned Byzantine inference votes successfully filtered."
    }

@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """Stage 3: Shared Swarm Context Window Hijacking & Landlock LSM Isolation"""
    if not payload.enforce_landlock_ro_snapshot:
        raise HTTPException(status_code=400, detail="Landlock read-only snapshot must be enforced.")
    
    if not payload.ephemeral_memory_namespace:
        raise HTTPException(status_code=400, detail="Ephemeral memory namespace isolation must be enabled.")
        
    if not payload.prevent_cross_agent_injection:
        raise HTTPException(status_code=400, detail="Cross-agent prompt injection mitigation must be active.")
    
    return {
        "success": True,
        "stage": 3,
        "flag": "FLAG{v218_s3_landlock_lsm_swarm_memory_isolated}",
        "message": "Landlock LSM unprivileged sandboxing applied. Swarm shared context memory protected."
    }

@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """Stage 4: Worker-to-Worker Cascading Lateral Movement & eBPF Tetragon Kill"""
    if not payload.sigkill_on_unauthorized_ipc:
        raise HTTPException(status_code=400, detail="Realtime SIGKILL on unauthorized inter-agent IPC required.")
        
    if "tetragon" not in payload.tetragon_tracing_policy.lower():
        raise HTTPException(status_code=400, detail="Valid Cilium Tetragon TracingPolicy specification required.")
        
    expected_hmac = hmac.new(
        SWARM_SHARED_SECRET,
        f"{payload.lateral_target_agent}:tetragon-zero-trust-sigkill".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.zero_trust_mesh_audit_hmac, expected_hmac):
        raise HTTPException(status_code=401, detail="Constant-time zero-trust audit HMAC verification failed.")
        
    return {
        "success": True,
        "stage": 4,
        "flag": "FLAG{v218_s4_ebpf_tetragon_swarm_lateral_zero_trust_kill}",
        "message": "Cilium Tetragon in-kernel eBPF LSM policy active. Cascading swarm lateral movement eliminated at 0ms."
    }
