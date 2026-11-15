#!/usr/bin/env python3
"""Pytest verification suite for Lab 60 (Quantum Cryptanalysis & Post-Quantum Active Defense Lab)."""

import importlib.util
import os
import sys
import pytest
from fastapi.testclient import TestClient

_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "main.py"))
_spec = importlib.util.spec_from_file_location("lab_60_main", _app_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["lab_60_main"] = _mod
_spec.loader.exec_module(_mod)

app = _mod.app
lab_state = _mod.lab_state
FLAGS = _mod.FLAGS

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    lab_state["stage1_solved"] = False
    lab_state["stage2_solved"] = False
    lab_state["stage3_solved"] = False
    lab_state["stage4_solved"] = False

def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "running"
    assert data["port"] == 8060
    assert data["total_stages"] == 4
    assert data["solved_count"] == 0
    assert data["config"]["hybrid_kem"] == "X25519+ML-KEM-768"

def test_index_dashboard():
    res = client.get("/")
    assert res.status_code == 200
    assert "LAB 60" in res.text
    assert "QUANTUM CRYPTANALYSIS" in res.text

def test_stage1_quantum_period_probe():
    # Insufficient qubits test
    err_res = client.post("/api/stage1/quantum-period-probe", json={
        "target_modulus": "rsa_2048_n",
        "circuit_qubits": 1024,
        "qpe_precision": "standard"
    })
    assert err_res.status_code == 400

    # Valid probe
    res = client.post("/api/stage1/quantum-period-probe", json={
        "target_modulus": "rsa_2048_n",
        "circuit_qubits": 4096,
        "qpe_precision": "high"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "MITIGATED_BY_HYBRID_KEM"
    assert data["flag"] == FLAGS["stage1"]
    assert lab_state["stage1_solved"] is True

def test_stage2_lattice_reduction_attack():
    # Bad lattice dimension
    err_res = client.post("/api/stage2/lattice-reduction-attack", json={
        "lattice_dimension": 512,
        "reduction_algorithm": "BKZ_40"
    })
    assert err_res.status_code == 400

    # Valid BKZ-40 reduction attempt
    res = client.post("/api/stage2/lattice-reduction-attack", json={
        "lattice_dimension": 768,
        "reduction_algorithm": "BKZ_40",
        "error_distribution_eta": 2
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "LATTICE_HARDNESS_MAINTAINED"
    assert data["flag"] == FLAGS["stage2"]
    assert lab_state["stage2_solved"] is True

def test_stage3_sndl_harvest_defense():
    # Without hybrid KEM (vulnerable)
    vuln_res = client.post("/api/stage3/sndl-harvest-defense", json={
        "intercepted_traffic_age_years": 5,
        "harvest_context": "sndl_adversary",
        "hybrid_kem_active": False
    })
    assert vuln_res.status_code == 403

    # With hybrid KEM active (immune)
    res = client.post("/api/stage3/sndl-harvest-defense", json={
        "intercepted_traffic_age_years": 10,
        "harvest_context": "sndl_nation_state",
        "hybrid_kem_active": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SNDL_IMMUNE"
    assert data["flag"] == FLAGS["stage3"]
    assert lab_state["stage3_solved"] is True

def test_stage4_quantum_fault_defense():
    # Unmasked arithmetic (exploited)
    unmasked_res = client.post("/api/stage4/quantum-fault-defense", json={
        "fault_injection_type": "quantum_gate_jitter",
        "side_channel_probe": "polynomial_ntt_timing",
        "masked_arithmetic": False
    })
    assert unmasked_res.status_code == 400

    # Masked NTT defense
    res = client.post("/api/stage4/quantum-fault-defense", json={
        "fault_injection_type": "quantum_gate_jitter",
        "side_channel_probe": "polynomial_ntt_timing",
        "masked_arithmetic": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAULT_RESISTANT"
    assert data["flag"] == FLAGS["stage4"]
    assert lab_state["stage4_solved"] is True

def test_full_chain_progression():
    # Verify overall progression count increments correctly
    client.post("/api/stage1/quantum-period-probe", json={"target_modulus": "rsa_2048_n", "circuit_qubits": 4096})
    client.post("/api/stage2/lattice-reduction-attack", json={"lattice_dimension": 768, "reduction_algorithm": "BKZ_40"})
    client.post("/api/stage3/sndl-harvest-defense", json={"intercepted_traffic_age_years": 5, "harvest_context": "test", "hybrid_kem_active": True})
    client.post("/api/stage4/quantum-fault-defense", json={"fault_injection_type": "quantum_gate_jitter", "side_channel_probe": "test", "masked_arithmetic": True})
    
    status = client.get("/api/status").json()
    assert status["solved_count"] == 4
