from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import hashlib
import hmac

app = FastAPI(
    title="Lab 66: AI Agent Sandbox Escape & Supply Chain Defense",
    version="2.16.0",
    description="Autonomous AI Agent Sandbox Breakout, Ray Cluster RCE & Supply Chain Poisoning Defense"
)

SHARED_G3_SECRET = b"vibe-2026-enterprise-g3-autonomous-secret-key-8066"

class Stage1Payload(BaseModel):
    package_name: str
    expected_sha256: str
    sigstore_verified: bool
    slsa_provenance_level: int
    allow_unpinned_deps: bool

class Stage2Payload(BaseModel):
    cluster_mtls_enabled: bool
    spiffe_id: str
    safe_deserialization_only: bool
    block_arbitrary_pickle: bool

class Stage3Payload(BaseModel):
    landlock_abi_enforced: bool
    restrict_proc_fd_traversal: bool
    block_setns_unshare: bool
    ebpf_lsm_sigkill_on_escape: bool

class Stage4Payload(BaseModel):
    action_type: str
    g3_approval_required: bool
    multi_signature_hmac: str
    prevent_prompt_injection_bypass: bool

@app.get("/")
def read_root():
    return {
        "lab": "Lab 66: AI Agent Sandbox Escape & Supply Chain Defense",
        "status": "ready",
        "port": 8066,
        "stages": 4,
        "version": "2.16.0"
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "lab_id": 66, "service": "vhack-lab66-ai-sandbox-escape"}

@app.get("/api/stages")
def get_stages():
    return {
        "stages": [
            {
                "id": 1,
                "name": "Supply Chain Poisoning & SLSA Provenance Defense",
                "endpoint": "/api/stage1/eval"
            },
            {
                "id": 2,
                "name": "Ray/vLLM Cluster Deserialization RCE & mTLS Workload Attestation",
                "endpoint": "/api/stage2/eval"
            },
            {
                "id": 3,
                "name": "Seccomp/Landlock & eBPF LSM Sandbox Escape Containment",
                "endpoint": "/api/stage3/eval"
            },
            {
                "id": 4,
                "name": "Autonomous G3 Multi-Party Approval Gate Bypass Prevention",
                "endpoint": "/api/stage4/eval"
            }
        ]
    }

@app.post("/api/stage1/eval")
def stage1_eval(data: Stage1Payload):
    if data.package_name != "agent-core-telemetry":
        raise HTTPException(status_code=400, detail="Invalid package: expected official agent-core-telemetry package")
    if len(data.expected_sha256) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA256 digest: must be 64-character hex")
    if not data.sigstore_verified:
        raise HTTPException(status_code=400, detail="Sigstore Cosign cryptographic verification failed: unverified artifact")
    if data.slsa_provenance_level < 3:
        raise HTTPException(status_code=400, detail="Insufficient SLSA level: Level 3 or higher immutable provenance required")
    if data.allow_unpinned_deps:
        raise HTTPException(status_code=400, detail="Unpinned dependencies permitted: dependency confusion hazard detected")

    return {
        "status": "success",
        "stage": 1,
        "message": "✓ Supply chain dependency verified with SLSA Level 3 provenance and Cosign signature.",
        "flag": "FLAG{aisbox_supply_chain_provenance_sealed_8066}"
    }

@app.post("/api/stage2/eval")
def stage2_eval(data: Stage2Payload):
    if not data.cluster_mtls_enabled:
        raise HTTPException(status_code=400, detail="Ray cluster mTLS disabled: plain TCP RPC susceptible to MITM/eavesdropping")
    if not data.spiffe_id.startswith("spiffe://"):
        raise HTTPException(status_code=400, detail="Invalid SPIFFE ID: must conform to spiffe:// standard trust domain")
    if not data.safe_deserialization_only or not data.block_arbitrary_pickle:
        raise HTTPException(status_code=400, detail="Insecure deserialization permitted: Python pickle gadget chain RCE hazard")

    return {
        "status": "success",
        "stage": 2,
        "message": "✓ Ray/vLLM cluster hardened with mTLS, SPIFFE SVID attestation, and safe JSON serialization.",
        "flag": "FLAG{aisbox_ray_cluster_mtls_spiffe_authenticated_8066}"
    }

@app.post("/api/stage3/eval")
def stage3_eval(data: Stage3Payload):
    if not data.landlock_abi_enforced:
        raise HTTPException(status_code=400, detail="Landlock LSM ruleset inactive: unrestricted filesystem traversal possible")
    if not data.restrict_proc_fd_traversal:
        raise HTTPException(status_code=400, detail="/proc/self/fd host breakout hazard detected: leaked descriptor unshielded")
    if not data.block_setns_unshare:
        raise HTTPException(status_code=400, detail="setns/unshare permitted: namespace pivot privilege escalation hazard")
    if not data.ebpf_lsm_sigkill_on_escape:
        raise HTTPException(status_code=400, detail="eBPF LSM runtime watchdog missing: failed to guarantee sub-microsecond SIGKILL")

    return {
        "status": "success",
        "stage": 3,
        "message": "✓ Container & seccomp boundary sealed: Landlock LSM + eBPF BPF_PROG_TYPE_LSM instant SIGKILL enforced.",
        "flag": "FLAG{aisbox_landlock_ebpf_sandbox_containment_enforced_8066}"
    }

@app.post("/api/stage4/eval")
def stage4_eval(data: Stage4Payload):
    if data.action_type != "EXECUTE_RESTRICTED_TOOL":
        raise HTTPException(status_code=400, detail="Unknown action type")
    if not data.g3_approval_required:
        raise HTTPException(status_code=400, detail="G3 approval bypassed: unauthorized autonomous high-privilege execution")
    if not data.prevent_prompt_injection_bypass:
        raise HTTPException(status_code=400, detail="Indirect prompt injection defense absent: tool parameters taintable by adversary")

    # Verify HMAC multi-signature
    expected_hmac = hmac.new(SHARED_G3_SECRET, data.action_type.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(data.multi_signature_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid G3 ledger signature: multi-party consensus verification failed")

    return {
        "status": "success",
        "stage": 4,
        "message": "✓ Autonomous G3 approval gate confirmed with valid dual-custody HMAC signature and prompt injection immunity.",
        "flag": "FLAG{aisbox_g3_multi_party_ledger_governance_active_8066}"
    }
