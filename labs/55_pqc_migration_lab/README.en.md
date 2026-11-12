# Lab 55: PQCMigrationGuard — FIPS 203/204 Post-Quantum Cryptography Lab

> **Difficulty**: ★★★★☆ | **Port**: `8055` | **Related Section**: [57. Quantum Cryptography](../../57_Quantum_Cryptography/) | **Wargame Track**: `pqcmigrate` (Track 67)

---

## 🎯 Objectives
Understand NIST-standardized **FIPS 203 ML-KEM-768 (Kyber)** and **FIPS 204 ML-DSA-65 (Dilithium)**. Migrate legacy RSA-2048/ECDSA architectures to hybrid classical/post-quantum key exchange (X25519 + ML-KEM), thwarting **Store-Now-Decrypt-Later (SNDL)** and quantum downgrade stripping attacks.

---

## 🔬 Four Interactive Scenarios

1. **Stage 1: SNDL Threat & Shor's Algorithm Quantum Factoring Simulation**
   - Intercept legacy RSA-2048/ECDH session ciphertexts and simulate polynomial-time quantum cracking.
   - **Flag 1**: `FLAG{STORE_NOW_DECRYPT_LATER_QUANTUM_THREAT_5501}`

2. **Stage 2: NIST FIPS 203 ML-KEM-768 Lattice Encapsulation**
   - Perform Module-Lattice encapsulation (`Encaps`) and decapsulation (`Decaps`) over ring $R_q$ to derive a 256-bit shared secret.
   - **Flag 2**: `FLAG{FIPS203_ML_KEM_768_ENCAPSULATION_MASTERED_5502}`

3. **Stage 3: NIST FIPS 204 ML-DSA-65 Quantum-Resistant Digital Signatures**
   - Verify M-SIS lattice digital signatures and detect bit-flipping forgery attacks.
   - **Flag 3**: `FLAG{FIPS204_ML_DSA_65_LATTICE_SIGNATURE_VERIFIED_5503}`

4. **Stage 4: Enterprise Hybrid Key Exchange & Anti-Downgrade Defense**
   - Synthesize dual key material: $K_{combined} = \text{HKDF}(K_{X25519} \parallel K_{ML-KEM-768})$.
   - Enforce TLS 1.3 `X25519MLKEM768` NamedGroup policies to block quantum stripping attacks.
   - **Flag 4**: `FLAG{HYBRID_X25519_ML_KEM_ANTI_DOWNGRADE_SHIELDED_5504}`

---

## 🚀 Execution & Access

```bash
cd labs/55_pqc_migration_lab
docker compose up -d
# or run with python
python3 -m uvicorn app.main:app --port 8055
```
