"""
VibeHacking Research Lab - Lab 60: Quantum Cryptanalysis & Post-Quantum Active Defense Lab
Quantum Period Finding (Shor's QPE), Lattice Reduction (SVP/CVP LLL & BKZ),
SNDL (Store Now Decrypt Later) Mitigation, and Masked NTT Constant-Time Hardening.
Protected under Enterprise Security Architecture guidelines (127.0.0.1 bound).
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import hashlib
import hmac
import secrets
from typing import Dict, Any, Optional

app = FastAPI(
    title="Lab 60 - Quantum Cryptanalysis & Post-Quantum Active Defense Lab",
    description="Shor Algorithm Simulation, Lattice Reduction (SVP/CVP), SNDL Countermeasures & FIPS 203/204 Hardening",
    version="2.12.0"
)

FLAGS = {
    "stage1": "FLAG{shor_qpe_quantum_period_finding_neutralized_by_hybrid_kem}",
    "stage2": "FLAG{bkz_lattice_reduction_svp_fails_against_fips203_dimension768}",
    "stage3": "FLAG{sndl_harvest_attack_foiled_by_ephemeral_ml_kem_pfs}",
    "stage4": "FLAG{masked_ntt_arithmetic_prevents_quantum_fault_injection}"
}

lab_state: Dict[str, Any] = {
    "stage1_solved": False,
    "stage2_solved": False,
    "stage3_solved": False,
    "stage4_solved": False,
    "hybrid_kem": "X25519+ML-KEM-768",
    "lattice_dim": 768,
    "pfs_enforced": True,
    "masked_ntt": True
}

class QuantumPeriodRequest(BaseModel):
    target_modulus: str = Field(..., description="Target asymmetric public key or modulus (e.g. 'rsa_2048_n', 'ecdsa_p256')")
    circuit_qubits: int = Field(..., description="Simulated logical qubits count (e.g. 4096)")
    qpe_precision: str = Field("high", description="QPE phase estimation precision: 'standard' or 'high'")

class LatticeReductionRequest(BaseModel):
    lattice_dimension: int = Field(..., description="Target lattice dimension (e.g. 768)")
    reduction_algorithm: str = Field(..., description="Lattice basis reduction algorithm: 'LLL', 'BKZ_20', 'BKZ_40'")
    error_distribution_eta: int = Field(2, description="Noise parameter eta (FIPS 203 standard: 2)")

class SndlHarvestRequest(BaseModel):
    intercepted_traffic_age_years: int = Field(..., description="Years stored in adversary harvest vault")
    harvest_context: str = Field(..., description="Adversary posture (e.g. 'sndl_nation_state')")
    hybrid_kem_active: bool = Field(True, description="Whether Post-Quantum Ephemeral KEM was engaged during session")

class QuantumFaultRequest(BaseModel):
    fault_injection_type: str = Field(..., description="Injection mode: 'quantum_gate_jitter', 'clock_glitch', 'laser_fault'")
    side_channel_probe: str = Field(..., description="Side-channel vector: 'polynomial_ntt_timing', 'cache_bank_conflict'")
    masked_arithmetic: bool = Field(True, description="Whether constant-time polynomial masking is active")

@app.get("/api/status")
async def get_status() -> Dict[str, Any]:
    solved = sum(1 for v in [lab_state["stage1_solved"], lab_state["stage2_solved"], lab_state["stage3_solved"], lab_state["stage4_solved"]] if v)
    return {
        "lab_id": "60",
        "name": "Quantum Cryptanalysis & Post-Quantum Active Defense Lab",
        "port": 8060,
        "status": "running",
        "total_stages": 4,
        "solved_count": solved,
        "stages": {
            "stage1": lab_state["stage1_solved"],
            "stage2": lab_state["stage2_solved"],
            "stage3": lab_state["stage3_solved"],
            "stage4": lab_state["stage4_solved"],
        },
        "config": {
            "hybrid_kem": lab_state["hybrid_kem"],
            "lattice_dim": lab_state["lattice_dim"],
            "pfs_enforced": lab_state["pfs_enforced"],
            "masked_ntt": lab_state["masked_ntt"]
        }
    }

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
  <title>Lab 60: Quantum Cryptanalysis &amp; Post-Quantum Defense</title>
  <style>
    :root {{
      --bg: #03050c;
      --card: #090e1f;
      --border: #162447;
      --txt: #a5b4fc;
      --dim: #6366f1;
      --accent: #818cf8;
      --warn: #fbbf24;
      --danger: #f87171;
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
      color: #c7d2fe;
      border-bottom: 2px solid var(--border);
      padding-bottom: 12px;
      margin-top: 0;
      font-size: 22px;
    }}
    .desc {{
      color: #818cf8;
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
      color: #e0e7ff;
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
      background: #312e81;
      color: #c7d2fe;
    }}
    pre {{
      background: #02040a;
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 4px;
      font-size: 12px;
      color: #a5b4fc;
      overflow-x: auto;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>⚛️ LAB 60 // QUANTUM CRYPTANALYSIS &amp; POST-QUANTUM ACTIVE DEFENSE</h1>
    <p class="desc">
      쇼어(Shor) 알고리즘 주기 탐색, 격자 기반 기저 축소(SVP/CVP LLL/BKZ), SNDL(Store Now Decrypt Later) 도청 위협 및<br>
      FIPS 203 ML-KEM-768 격자 다항식 마스킹 실전 방어 시뮬레이션 환경입니다.
    </p>
    <div class="grid">
      <div class="card">
        <h3>Stage 1: Shor Period Finding <span class="status {'done' if lab_state['stage1_solved'] else ''}">{s1}</span></h3>
        <p class="desc">RSA-2048/ECC 주기 탐색 vs 하이브리드 KEM 능동 방어</p>
        <pre>POST /api/stage1/quantum-period-probe</pre>
      </div>
      <div class="card">
        <h3>Stage 2: Lattice Reduction (SVP) <span class="status {'done' if lab_state['stage2_solved'] else ''}">{s2}</span></h3>
        <p class="desc">BKZ-40 격자 기저 축소 vs FIPS 203 모듈 차원(k=3) 방어</p>
        <pre>POST /api/stage2/lattice-reduction-attack</pre>
      </div>
      <div class="card">
        <h3>Stage 3: SNDL Harvest Defense <span class="status {'done' if lab_state['stage3_solved'] else ''}">{s3}</span></h3>
        <p class="desc">장기 암호문 도청 공격 vs Ephemeral ML-KEM PFS 보호</p>
        <pre>POST /api/stage3/sndl-harvest-defense</pre>
      </div>
      <div class="card">
        <h3>Stage 4: Masked NTT &amp; Fault Shield <span class="status {'done' if lab_state['stage4_solved'] else ''}">{s4}</span></h3>
        <p class="desc">양자 게이트 지터 및 타이밍 누출 vs 상수시간 NTT 마스킹</p>
        <pre>POST /api/stage4/quantum-fault-defense</pre>
      </div>
    </div>
  </div>
</body>
</html>
"""

@app.post("/api/stage1/quantum-period-probe")
async def probe_quantum_period(req: QuantumPeriodRequest):
    if req.circuit_qubits < 4096:
        raise HTTPException(status_code=400, detail="Insufficient logical qubits for 2048-bit modulus factorization.")

    target = req.target_modulus.lower()
    if "rsa" not in target and "ecdsa" not in target:
        raise HTTPException(status_code=400, detail="Target must be classical RSA or ECC key modulus.")

    # Defense Mechanism: Hybrid KEM X25519 + ML-KEM-768 encapsulates session
    lab_state["stage1_solved"] = True
    return {
        "status": "MITIGATED_BY_HYBRID_KEM",
        "target": req.target_modulus,
        "shor_factorization": "FAILED_DUE_TO_PQC_LAYER",
        "quantum_security_bits": 192,
        "active_cipher_suite": "TLS_AES_256_GCM_SHA384_X25519_MLKEM768",
        "flag": FLAGS["stage1"]
    }

@app.post("/api/stage2/lattice-reduction-attack")
async def lattice_reduction_attack(req: LatticeReductionRequest):
    if req.lattice_dimension != 768:
        raise HTTPException(status_code=400, detail="Lattice dimension mismatch; FIPS 203 ML-KEM-768 requires dim=768.")

    if req.reduction_algorithm not in ["LLL", "BKZ_20", "BKZ_40"]:
        raise HTTPException(status_code=400, detail="Invalid lattice basis reduction algorithm.")

    # Defense: Ring-LWE shortest vector problem hardness holds against BKZ-40 (Hermite factor > 1.005)
    lab_state["stage2_solved"] = True
    return {
        "status": "LATTICE_HARDNESS_MAINTAINED",
        "reduction_algorithm": req.reduction_algorithm,
        "svp_hermite_factor": 1.0062,
        "error_poly_status": "UNRECOVERABLE",
        "security_level": "NIST_CATEGORY_3 (192-bit quantum equivalent)",
        "flag": FLAGS["stage2"]
    }

@app.post("/api/stage3/sndl-harvest-defense")
async def sndl_harvest_defense(req: SndlHarvestRequest):
    if req.intercepted_traffic_age_years <= 0:
        raise HTTPException(status_code=400, detail="Harvest vault storage age must be positive.")

    if not req.hybrid_kem_active:
        return JSONResponse(
            status_code=403,
            content={"status": "VULNERABLE", "detail": "Classical session decrypted by future CRQC"}
        )

    # Ephemeral Post-Quantum KEM guarantees Forward Secrecy even against retro-active quantum decryption
    lab_state["stage3_solved"] = True
    return {
        "status": "SNDL_IMMUNE",
        "harvest_context": req.harvest_context,
        "traffic_age_years": req.intercepted_traffic_age_years,
        "ephemeral_pfs": "GUARANTEED_BY_ML_KEM_768",
        "remediation": "All harvested sessions remain quantum-indistinguishable (IND-CCA2)",
        "flag": FLAGS["stage3"]
    }

@app.post("/api/stage4/quantum-fault-defense")
async def quantum_fault_defense(req: QuantumFaultRequest):
    if not req.masked_arithmetic:
        return JSONResponse(
            status_code=400,
            content={"status": "EXPLOITED", "detail": "NTT side-channel leaked private polynomial"}
        )

    if req.fault_injection_type != "quantum_gate_jitter" and "glitch" not in req.fault_injection_type:
        raise HTTPException(status_code=400, detail="Invalid fault injection technique.")

    # Masked NTT and rejection sampling protects polynomial arithmetic from physical/timing perturbation
    lab_state["stage4_solved"] = True
    return {
        "status": "FAULT_RESISTANT",
        "side_channel_probe": req.side_channel_probe,
        "constant_time_ntt": True,
        "rejection_sampling_shield": True,
        "defense_rule": "FIPS-204-MASKED-POLYNOMIAL-ARITHMETIC-ACTIVE",
        "flag": FLAGS["stage4"]
    }
