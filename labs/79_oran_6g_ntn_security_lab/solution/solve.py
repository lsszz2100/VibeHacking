#!/usr/bin/env python3
"""Reference solver for Lab 79: Oran6gNtnSecurityLab."""

import hashlib
import hmac
import os
import urllib.request
import json

BASE_URL = "http://127.0.0.1:8079"
ORAN_SHARED_SECRET = os.environ.get(
    "VHACK_ORAN_SECRET",
    "vibe-2026-enterprise-oran-6g-ntn-secret-8079",
).encode("utf-8")


def post_json(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    s1 = post_json("/api/stage1/eval", {
        "xapp_id": "xapp_oran_2026_kpm_guard",
        "spiffe_svid_uri": "spiffe://oran.vibe.local/ns/ric/sa/kpm-guard",
        "e2_mtls_verified": True,
        "e2sm_kpm_schema_allowlisted": True,
    })
    print("Stage 1:", s1["flag"])

    ecpri_id = "ecpri_fh_2026_79_alpha"
    ecpri_hmac = hmac.new(ORAN_SHARED_SECRET, f"ecpri_session:{ecpri_id}".encode(), hashlib.sha256).hexdigest()
    s2 = post_json("/api/stage2/eval", {
        "fronthaul_protocol": "ecpri_split_7_2x",
        "macsec_cipher": "AES-256-GCM",
        "ptp_nts_authenticated": True,
        "ptp_clock_drift_ns": 24.5,
        "ecpri_session_id": ecpri_id,
        "ecpri_frame_hmac": ecpri_hmac,
    })
    print("Stage 2:", s2["flag"])

    s3 = post_json("/api/stage3/eval", {
        "slice_sst": 1,
        "a1_policy_signed_rbac": True,
        "sla_bandwidth_guarantees_pct": 99.5,
        "upf_teid_isolation_active": True,
    })
    print("Stage 3:", s3["flag"])

    ho_hash = hashlib.sha256(b"leo_handover_2026_79").hexdigest()
    ho_hmac = hmac.new(ORAN_SHARED_SECRET, f"ntn_handover:{ho_hash}".encode(), hashlib.sha256).hexdigest()
    s4 = post_json("/api/stage4/eval", {
        "pqc_kem_suite": "X25519_MLKEM768",
        "fips204_mldsa65_ric_attestation": "sig_oran_mldsa65_ric_enclave_attested",
        "ntn_handover_quorum_nodes": 4,
        "handover_token_hash": ho_hash,
        "oran_audit_hmac": ho_hmac,
    })
    print("Stage 4:", s4["flag"])


if __name__ == "__main__":
    main()
