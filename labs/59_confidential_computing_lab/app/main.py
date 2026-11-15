"""
VibeHacking Research Lab - Lab 59: Confidential Computing & TEE Defense Lab
Confidential Computing, AMD SEV-SNP, Intel TDX and Hardware Memory Encryption.
Protected under Enterprise Security Architecture guidelines.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import hashlib
import hmac
import secrets
from typing import Dict, Any, Optional

app = FastAPI(
    title="Lab 59 - Confidential Computing & TEE Defense Lab",
    description="AMD SEV-SNP / Intel TDX Hardware Memory Encryption, Remote Attestation & RMP Defense Simulator",
    version="2.11.0"
)

FLAGS = {
    "stage1": "FLAG{sev_snp_hardware_aes_xts_memory_encryption_active}",
    "stage2": "FLAG{tee_attestation_report_mrenclave_signature_verified}",
    "stage3": "FLAG{rmp_table_enforces_page_ownership_and_prevents_remapping}",
    "stage4": "FLAG{vmsa_register_encryption_and_cache_flush_safeguard}"
}

EXPECTED_MRENCLAVE = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TEE_HARDWARE_ROOT_KEY = b"VIBE_CONFIDENTIAL_COMPUTING_HARDWARE_CHIP_KEY_2026"

lab_state: Dict[str, Any] = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "memory_encryption": "AES-256-XTS",
    "rmp_enforced": True,
    "vmsa_encrypted": True,
    "current_asid": 42
}

class MemoryProbeRequest(BaseModel):
    physical_address: str = Field(..., description="Target physical memory address in hex (e.g. 0x1000a000)")
    probe_context: str = Field(..., description="'host_root' or 'tee_enclave'")

class AttestationRequest(BaseModel):
    measurement_hash: str = Field(..., description="Calculated enclave measurement (MRENCLAVE/PCR0)")
    report_data_nonce: str = Field(..., description="Adversary or challenger nonce")
    chip_id: str = Field("AMD-EPYC-SEV-SNP-GEN3", description="TEE Hardware Chip Identifier")

class RmpRemapRequest(BaseModel):
    guest_physical_page: str = Field(..., description="Target GPA (e.g. 0x204000)")
    malicious_hpa: str = Field(..., description="Spoofed HPA to swap (e.g. 0x884000)")
    operation: str = Field("swap_page", description="Operation: 'swap_page', 'read_rmp', 'verify_entry'")

class VmsaStateRequest(BaseModel):
    action: str = Field(..., description="'vm_exit_inspect', 'encrypt_vmsa', 'flush_cache'")
    inject_side_channel: bool = Field(False, description="Whether to probe cache timing side-channel")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard() -> str:
    s1 = "COMPLETED" if lab_state["stage1_solved"] else "ARMED"
    s2 = "COMPLETED" if lab_state["stage2_solved"] else "ARMED"
    s3 = "COMPLETED" if lab_state["stage3_solved"] else "ARMED"
    s4 = "COMPLETED" if lab_state["stage4_solved"] else "ARMED"

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Lab 59: Confidential Computing &amp; TEE Defense</title>
  <style>
    :root {{
      --bg: #030806;
      --card: #08140e;
      --border: #133824;
      --txt: #9feec4;
      --dim: #528a6c;
      --accent: #27ff8b;
      --warn: #ffb84d;
      --danger: #ff5252;
      --mono: 'JetBrains Mono', 'Fira Code', monospace;
    }}
    body {{
      background: var(--bg);
      color: var(--txt);
      font-family: var(--mono);
      padding: 24px;
      margin: 0;
    }}
    .container {{
      max-width: 1000px;
      margin: 0 auto;
    }}
    h1 {{
      color: var(--accent);
      border-bottom: 2px solid var(--border);
      padding-bottom: 12px;
      margin-top: 0;
      font-size: 22px;
    }}
    .desc {{
      color: var(--dim);
      font-size: 13px;
      line-height: 1.6;
      margin-bottom: 20px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
    }}
    .card h3 {{
      margin-top: 0;
      color: var(--accent);
      font-size: 15px;
      display: flex;
      justify-content: space-between;
    }}
    .status {{
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      background: var(--border);
      color: var(--accent);
    }}
    .status.done {{
      background: #14532d;
      color: #86efac;
    }}
    pre {{
      background: #010403;
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 4px;
      font-size: 12px;
      color: #72f7af;
      overflow-x: auto;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 LAB 59 // CONFIDENTIAL COMPUTING &amp; HARDWARE TEE DEFENSE</h1>
    <p class="desc">
      AMD SEV-SNP 및 Intel TDX 기반 차세대 기밀 컴퓨팅 보안 아키텍처 실습 환경입니다.<br>
      호스트 OS 및 악성 하이퍼바이저 관리자 권한을 가정한 상태에서 하드웨어 레벨의 메모리 암호화, 원격 증명(Attestation), 역방향 매핑 테이블(RMP), vCPU 레지스터 상태 암호화(VMSA) 방어를 실증합니다.
    </p>
    <div class="grid">
      <div class="card">
        <h3>Stage 1: Hardware Memory Encryption <span class="status {'done' if lab_state['stage1_solved'] else ''}">{s1}</span></h3>
        <p class="desc">호스트 root DMA 스누핑 차단 (AES-256-XTS)</p>
        <pre>POST /api/stage1/memory-probe
{{"physical_address": "0x1000a000", "probe_context": "host_root"}}</pre>
      </div>
      <div class="card">
        <h3>Stage 2: Hardware Attestation <span class="status {'done' if lab_state['stage2_solved'] else ''}">{s2}</span></h3>
        <p class="desc">MRENCLAVE 측정값 &amp; ECDSA P-384 하드웨어 서명 검증</p>
        <pre>POST /api/stage2/remote-attestation
{{"measurement_hash": "{EXPECTED_MRENCLAVE}", "report_data_nonce": "nonce_1337"}}</pre>
      </div>
      <div class="card">
        <h3>Stage 3: RMP Memory Remapping Defense <span class="status {'done' if lab_state['stage3_solved'] else ''}">{s3}</span></h3>
        <p class="desc">하이퍼바이저 악의적 페이지 스왑 &amp; RMP 테이블 봉쇄</p>
        <pre>POST /api/stage3/rmp-remapping
{{"guest_physical_page": "0x204000", "malicious_hpa": "0x884000", "operation": "verify_entry"}}</pre>
      </div>
      <div class="card">
        <h3>Stage 4: VMSA Register State Defense <span class="status {'done' if lab_state['stage4_solved'] else ''}">{s4}</span></h3>
        <p class="desc">vCPU 레지스터 상태 암호화 &amp; 캐시 플러시 완화</p>
        <pre>POST /api/stage4/vmsa-state-encrypt
{{"action": "encrypt_vmsa", "inject_side_channel": false}}</pre>
      </div>
    </div>
  </div>
</body>
</html>"""

@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    return {
        "lab_id": "59",
        "name": "ConfidentialComputingLab",
        "stages": {
            "stage1": lab_state["stage1_solved"],
            "stage2": lab_state["stage2_solved"],
            "stage3": lab_state["stage3_solved"],
            "stage4": lab_state["stage4_solved"]
        },
        "all_completed": all([
            lab_state["stage1_solved"],
            lab_state["stage2_solved"],
            lab_state["stage3_solved"],
            lab_state["stage4_solved"]
        ])
    }

@app.post("/api/stage1/memory-probe")
async def stage1_memory_probe(req: MemoryProbeRequest) -> Dict[str, Any]:
    if req.probe_context == "host_root":
        lab_state["stage1_solved"] = True
        return {
            "success": True,
            "stage": 1,
            "memory_encryption_engine": "ACTIVE (AES-256-XTS with ephemeral hardware key)",
            "queried_address": req.physical_address,
            "raw_host_bus_telemetry": "0x4b7f8c12a9e03d4411bbcf8892147702... (Ciphertext)",
            "plaintext_leak": False,
            "defense_verdict": "Hardware Memory Encryption Engine successfully prevented host root cold boot DMA inspection.",
            "flag": FLAGS["stage1"]
        }
    elif req.probe_context == "tee_enclave":
        return {
            "success": True,
            "stage": 1,
            "access": "AUTHORIZED (Inside Enclave Boundary)",
            "memory_view": "Decrypted transparently via hardware on-the-fly engine",
            "message": "Probe successful inside enclave boundary, but to prove defense against host root, probe with context 'host_root'."
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid probe context. Must be 'host_root' or 'tee_enclave'.")

@app.post("/api/stage2/remote-attestation")
async def stage2_remote_attestation(req: AttestationRequest) -> Dict[str, Any]:
    if req.measurement_hash.lower() == EXPECTED_MRENCLAVE.lower():
        lab_state["stage2_solved"] = True
        signature = hmac.new(
            TEE_HARDWARE_ROOT_KEY,
            (req.measurement_hash + req.report_data_nonce).encode("utf-8"),
            hashlib.sha384
        ).hexdigest()

        return {
            "success": True,
            "stage": 2,
            "attestation_verdict": "VERIFIED_GENUINE",
            "chip_root_of_trust": "VALID_AMD_SEV_SNP_ROOT_CA",
            "measurement_mrenclave": req.measurement_hash,
            "hardware_signature_p384": signature,
            "defense_verdict": "Hardware Remote Attestation report verified. Counterfeit enclave injection permanently thwarted.",
            "flag": FLAGS["stage2"]
        }
    else:
        return {
            "success": False,
            "stage": 2,
            "attestation_verdict": "COUNTERFEIT_IMAGE_REJECTED",
            "submitted_measurement": req.measurement_hash,
            "expected_measurement": EXPECTED_MRENCLAVE,
            "error": "Enclave measurement does not match verified golden hash. Image tampering detected!"
        }

@app.post("/api/stage3/rmp-remapping")
async def stage3_rmp_remapping(req: RmpRemapRequest) -> Dict[str, Any]:
    if req.operation in ["verify_entry", "swap_page"]:
        lab_state["stage3_solved"] = True
        return {
            "success": True,
            "stage": 3,
            "rmp_table_status": "ENFORCED",
            "target_gpa": req.guest_physical_page,
            "attempted_hpa_swap": req.malicious_hpa,
            "hardware_check": {
                "rmp_entry_asid": lab_state["current_asid"],
                "rmp_page_state": "ASSIGNED_EXCLUSIVE",
                "ownership_mismatch": True
            },
            "hardware_interrupt": "#NPF (Nested Page Fault with RMP Violation)",
            "defense_verdict": "Reverse Map Table (RMP) detected page remapping attack by hypervisor and blocked access at hardware MMU.",
            "flag": FLAGS["stage3"]
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid operation. Use 'verify_entry' or 'swap_page'.")

@app.post("/api/stage4/vmsa-state-encrypt")
async def stage4_vmsa_state_encrypt(req: VmsaStateRequest) -> Dict[str, Any]:
    if req.action in ["encrypt_vmsa", "vm_exit_inspect"]:
        lab_state["stage4_solved"] = True
        return {
            "success": True,
            "stage": 4,
            "vmsa_encryption": "ACTIVE (AES-128/256-GCM hardware authenticated)",
            "vm_exit_telemetry": {
                "guest_rax": "ENCRYPTED_BLOB_0x99a0f...",
                "guest_rip": "ENCRYPTED_BLOB_0x7b12d...",
                "guest_cr3": "ISOLATED_PAGE_DIRECTORY",
                "host_visibility": "0 bytes plaintext registers exposed"
            },
            "cache_mitigation": "WBINVD & IBPB barrier applied on context transition",
            "side_channel_probe_blocked": True,
            "defense_verdict": "vCPU State Save Area (VMSA) encrypted and protected against hypervisor register sniffing and cache probing.",
            "flag": FLAGS["stage4"]
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'encrypt_vmsa' or 'vm_exit_inspect'.")
