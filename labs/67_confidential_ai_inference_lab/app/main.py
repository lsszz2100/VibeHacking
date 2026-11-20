from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import hashlib
import hmac

app = FastAPI(
    title="Lab 67: Confidential AI Inference & Hardware Enclave Attestation Defense Lab",
    version="2.17.0",
    description="AMD SEV-SNP/Intel TDX Confidential Computing, In-Enclave Weights Decryption & Cache Side-Channel Defense"
)

SHARED_TPM_SECRET = b"vibe-2026-enterprise-tpm-aik-hardware-secret-8067"

class Stage1Payload(BaseModel):
    hardware_provider: str
    attestation_quote: str
    measurement_pcr0: str
    require_snp_vcek: bool

class Stage2Payload(BaseModel):
    key_id: str
    encrypted_model_blob: str
    memory_encryption_xts: bool
    prevent_plain_weight_dump: bool

class Stage3Payload(BaseModel):
    constant_time_gemm: bool
    cache_line_flushing_mitigated: bool
    oblivious_ram_or_shuffling: bool
    detect_prime_probe: bool

class Stage4Payload(BaseModel):
    prompt_hash: str
    inference_output: str
    tpm_aik_signature: str
    hardware_root_of_trust: bool

@app.get("/")
def read_root():
    return {
        "lab": "Lab 67: Confidential AI Inference & Hardware Enclave Attestation Defense Lab",
        "status": "ready",
        "port": 8067,
        "stages": 4,
        "version": "2.17.0"
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "lab_id": 67, "service": "vhack-lab67-confidential-ai-inference"}

@app.get("/api/stages")
def get_stages():
    return {
        "stages": [
            {
                "id": 1,
                "name": "Hardware TEE Remote Attestation & Quote Verification (AMD SEV-SNP/TDX)",
                "endpoint": "/api/stage1/eval"
            },
            {
                "id": 2,
                "name": "In-Enclave AES-256-XTS Model Weight Decryption & Memory Encryption",
                "endpoint": "/api/stage2/eval"
            },
            {
                "id": 3,
                "name": "Microarchitectural Cache Timing (Flush+Reload/Prime+Probe) Side-Channel Defense",
                "endpoint": "/api/stage3/eval"
            },
            {
                "id": 4,
                "name": "Tamper-Evident Inference Output Cryptographic Signing (TPM AIK Root-of-Trust)",
                "endpoint": "/api/stage4/eval"
            }
        ]
    }

@app.post("/api/stage1/eval")
def stage1_eval(data: Stage1Payload):
    if data.hardware_provider not in ["amd-sev-snp", "intel-tdx"]:
        raise HTTPException(status_code=400, detail="Invalid TEE hardware: must be 'amd-sev-snp' or 'intel-tdx'")
    if len(data.attestation_quote) < 64:
        raise HTTPException(status_code=400, detail="Attestation quote invalid or truncated")
    if len(data.measurement_pcr0) != 64:
        raise HTTPException(status_code=400, detail="Invalid PCR0 measurement hash: must be 64-hex SHA-256")
    if not data.require_snp_vcek:
        raise HTTPException(status_code=400, detail="VCEK / Platform CA signature verification required")

    return {
        "status": "success",
        "stage": 1,
        "message": "✓ Hardware TEE remote attestation quote and PCR0 measurement verified via VCEK chain.",
        "flag": "FLAG{teeai_sev_snp_hardware_attestation_verified_8067}"
    }

@app.post("/api/stage2/eval")
def stage2_eval(data: Stage2Payload):
    if data.key_id != "kdf-tee-aes256-xts-v2":
        raise HTTPException(status_code=400, detail="Invalid key identifier: enclave KDF key mismatch")
    if len(data.encrypted_model_blob) < 32:
        raise HTTPException(status_code=400, detail="Encrypted model weight payload empty or corrupted")
    if not data.memory_encryption_xts:
        raise HTTPException(status_code=400, detail="Hardware AES-256-XTS memory encryption must be enabled")
    if not data.prevent_plain_weight_dump:
        raise HTTPException(status_code=400, detail="Plaintext weight extraction vulnerability: dump barrier required")

    return {
        "status": "success",
        "stage": 2,
        "message": "✓ Enclave model weights decrypted into AES-256-XTS encrypted enclave memory space.",
        "flag": "FLAG{teeai_in_enclave_xts_model_weights_sealed_8067}"
    }

@app.post("/api/stage3/eval")
def stage3_eval(data: Stage3Payload):
    if not data.constant_time_gemm:
        raise HTTPException(status_code=400, detail="Matrix multiplication timing vulnerability: constant-time GEMM required")
    if not data.cache_line_flushing_mitigated:
        raise HTTPException(status_code=400, detail="Flush+Reload vulnerability: clflush mitigation not active")
    if not data.oblivious_ram_or_shuffling:
        raise HTTPException(status_code=400, detail="Memory access patterns exposed: oblivious shuffling required")
    if not data.detect_prime_probe:
        raise HTTPException(status_code=400, detail="LLC Prime+Probe detector disabled: telemetry required")

    return {
        "status": "success",
        "stage": 3,
        "message": "✓ Microarchitectural cache timing side-channel attacks neutralized via constant-time ops and ORAM.",
        "flag": "FLAG{teeai_cache_timing_sidechannel_flush_reload_mitigated_8067}"
    }

@app.post("/api/stage4/eval")
def stage4_eval(data: Stage4Payload):
    if len(data.prompt_hash) != 64:
        raise HTTPException(status_code=400, detail="Prompt hash must be 64-character SHA-256 digest")
    if not data.inference_output:
        raise HTTPException(status_code=400, detail="Inference output empty")
    if not data.hardware_root_of_trust:
        raise HTTPException(status_code=400, detail="Hardware TPM root of trust is mandatory")

    expected_sig = hmac.new(
        SHARED_TPM_SECRET,
        f"{data.prompt_hash}:{data.inference_output}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(data.tpm_aik_signature, expected_sig):
        raise HTTPException(status_code=400, detail="Cryptographic attestation signature mismatch: invalid TPM AIK signature")

    return {
        "status": "success",
        "stage": 4,
        "message": "✓ Inference output signed with enclave hardware TPM AIK endorsement key.",
        "flag": "FLAG{teeai_tpm_aik_tamper_evident_inference_signed_8067}"
    }
