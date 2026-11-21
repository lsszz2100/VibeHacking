from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import hashlib
import hmac

app = FastAPI(
    title="Lab 74: Quantum Neural Hybrid & QPU Memory Isolation Defense Lab",
    version="2.24.0",
    description="Quantum-assisted Adversarial Perturbation Defense, QPU Memory Residual Zeroization, Hybrid PQC Gradient Shield & Circuit Merkle Attestation"
)

QUANTUM_NN_SHARED_SECRET = b"vibe-2026-enterprise-quantum-neural-hybrid-secret-8074"

class Stage1Payload(BaseModel):
    qnn_ansatz: str
    adversarial_epsilon: float
    qfi_divergence_threshold: float
    entanglement_depth: int

class Stage2Payload(BaseModel):
    zeroization_protocol: str
    pauli_twirling_rounds: int
    residual_state_fidelity: float
    qpu_session_id: str
    zeroization_hmac: str

class Stage3Payload(BaseModel):
    pqc_kem_scheme: str
    gradient_noise_snr_db: float
    cross_domain_attestation_active: bool
    parameter_tampering_blocked: bool

class Stage4Payload(BaseModel):
    qpu_microcode_sha256: str
    qnn_circuit_merkle_root: str
    attestation_sig: str
    qpu_audit_hmac: str

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "lab_id": 74,
        "name": "quantum_neural_hybrid_lab",
        "stages": 4,
        "category": "quantum",
        "version": "2.24.0"
    }

@app.get("/")
def read_root():
    return {
        "lab": "Lab 74: Quantum Neural Hybrid & QPU Memory Isolation Defense Lab",
        "status": "ready",
        "port": 8074,
        "stages": 4,
        "category": "quantum",
        "version": "2.24.0"
    }

@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """Stage 1: Quantum Adversarial Perturbation Filtering & QFI Geometry Metric"""
    if payload.qnn_ansatz != "parameterized_quantum_circuit_hardware_efficient":
        raise HTTPException(status_code=400, detail="QNN ansatz must be parameterized_quantum_circuit_hardware_efficient.")
    
    if payload.adversarial_epsilon > 0.05:
        raise HTTPException(status_code=400, detail="Adversarial epsilon must be <= 0.05 to filter adversarial quantum perturbations.")
    
    if payload.qfi_divergence_threshold < 1.45:
        raise HTTPException(status_code=400, detail="Quantum Fisher Information (QFI) divergence threshold must be >= 1.45.")
    
    if payload.entanglement_depth < 4:
        raise HTTPException(status_code=400, detail="Entanglement depth must be at least 4 layers.")
    
    return {
        "success": True,
        "stage": 1,
        "flag": "FLAG{v224_s1_qnn_fisher_information_filter_secured}",
        "message": "Quantum Fisher Information manifold verified. Quantum-assisted adversarial perturbation filtered."
    }

@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """Stage 2: QPU Memory Residual State Zeroization & Pauli Twirling Reset"""
    if payload.zeroization_protocol not in ["active_reset_pauli_twirling", "syndrome_parity_annihilation"]:
        raise HTTPException(status_code=400, detail="Valid zeroization protocol required (active_reset_pauli_twirling or syndrome_parity_annihilation).")
    
    if payload.pauli_twirling_rounds < 64:
        raise HTTPException(status_code=400, detail="Pauli twirling rounds must be >= 64 for complete decoherence suppression.")
    
    if payload.residual_state_fidelity > 0.001:
        raise HTTPException(status_code=400, detail="Residual state fidelity must be <= 0.001 (99.9% reset invariant).")
    
    expected_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{payload.zeroization_protocol}:{payload.qpu_session_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.zeroization_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid cryptographic QPU zeroization HMAC token.")
    
    return {
        "success": True,
        "stage": 2,
        "flag": "FLAG{v224_s2_qpu_memory_zeroization_coherence_reset}",
        "message": "QPU quantum memory zeroization enforced. Cross-tenant qubit coherence bleeding neutralized."
    }

@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """Stage 3: Hybrid Classical-Quantum PQC Enclave & Parameter Gradient Shield"""
    if payload.pqc_kem_scheme not in ["ml_kem_1024", "fips203_kyber_1024"]:
        raise HTTPException(status_code=400, detail="Post-quantum KEM must be ml_kem_1024 or fips203_kyber_1024.")
    
    if payload.gradient_noise_snr_db < 24.0:
        raise HTTPException(status_code=400, detail="Gradient differential privacy noise SNR must be >= 24.0 dB.")
    
    if not payload.cross_domain_attestation_active:
        raise HTTPException(status_code=400, detail="Cross-domain CPU-QPU mutual attestation must be active.")
    
    if not payload.parameter_tampering_blocked:
        raise HTTPException(status_code=400, detail="QNN variational parameter tampering must be blocked.")
    
    return {
        "success": True,
        "stage": 3,
        "flag": "FLAG{v224_s3_hybrid_pqc_gradient_shield_isolated}",
        "message": "Hybrid PQC enclave and parameter gradient differential noise active. Reverse inversion prevented."
    }

@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """Stage 4: Cryptographic QPU Firmware Attestation & Merkle Circuit Provenance (Capstone)"""
    if len(payload.qpu_microcode_sha256) != 64 or len(payload.qnn_circuit_merkle_root) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA-256 hash length for QPU microcode or circuit Merkle root.")
    
    if not payload.attestation_sig.startswith("sig_qnn_hybrid_v224_"):
        raise HTTPException(status_code=400, detail="Valid QNN hybrid attestation signature required.")
    
    expected_hmac = hmac.new(
        QUANTUM_NN_SHARED_SECRET,
        f"{payload.qpu_microcode_sha256}:{payload.qnn_circuit_merkle_root}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.qpu_audit_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid cryptographic QPU microcode audit HMAC attestation.")
    
    return {
        "success": True,
        "stage": 4,
        "flag": "FLAG{v224_s4_qnn_circuit_merkle_provenance_attested}",
        "message": "QPU microcode and quantum circuit Merkle tree attestation verified. Quantum RoT established."
    }
