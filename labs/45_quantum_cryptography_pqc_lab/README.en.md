# Lab 45: PQCShield — Post-Quantum Cryptography & PQC Migration Lab

Interactive security simulation covering classical public key vulnerabilities (RSA/ECDH) against Shor's algorithm, Harvest-Now-Decrypt-Later (HNDL) threats, hybrid KEM downgrade mitigations, and NIST FIPS 203 (ML-KEM-768) / FIPS 204 (ML-DSA-65) hardening.

## 🎯 Lab Objectives
1. **Stage 1 (Classical PKI & HNDL Risk Analysis)**: Sniff classical RSA-2048 / ECDH traffic, identify Harvest-Now-Decrypt-Later exposure, and simulate Shor's algorithm factorizability.
2. **Stage 2 (Hybrid KEM Downgrade Attack)**: Intercept TLS 1.3 ClientHello extensions, execute MitM downgrade stripping `X25519Kyber768Draft00`, and harvest downgraded classical sessions.
3. **Stage 3 (Lattice Side-Channel & Fault Injection Triage)**: Triage rejection sampling fault injections and detect timing side-channel anomalies in non-constant-time lattice operations.
4. **Stage 4 (FIPS 203 ML-KEM & FIPS 204 ML-DSA Migration)**: Deploy strict Dual-KDF hybrid enforcement, FIPS 203 ML-KEM-768 key encapsulation, and FIPS 204 ML-DSA-65 post-quantum certificates.

## 🚀 Quick Start

### Local Execution (Python)
```bash
cd labs/45_quantum_cryptography_pqc_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8045
```

### Docker Execution
```bash
docker-compose up -d --build
```
Open `http://127.0.0.1:8045` in your browser.

## 🧪 Test Suite
```bash
pytest -v labs/45_quantum_cryptography_pqc_lab/tests/
```
