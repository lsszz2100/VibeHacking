# Lab 45: PQCShield — 양자 내성 암호 & PQC 마이그레이션 실습

양자 컴퓨팅 위협(Shor's Algorithm, HNDL 공격)에 대응하여 고전 공개키 암호(RSA/ECDH)의 취약점을 분석하고, NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65) 및 하이브리드 키 교환 방어를 구현하는 실전 실습 랩입니다.

## 🎯 실습 목표
1. **Stage 1 (Classical PKI & HNDL Risk Analysis)**: 고전 RSA-2048 / ECDH 트래픽 도청 시뮬레이션, "지금 수집, 나중 해독(HNDL)" 위협 진단 및 쇼어 알고리즘 소인수분해 취약성 판별
2. **Stage 2 (Hybrid KEM Downgrade Attack)**: TLS 1.3 ClientHello 내 PQC 확장 필드(`X25519Kyber768Draft00`)를 제거하는 MitM 다운그레이드 공격 재현 및 세션 가로채기
3. **Stage 3 (Lattice Side-Channel & Fault Injection Triage)**: 격자 기반 거부 샘플링(Rejection Sampling) 결함 주입 및 상수 시간(Constant-time) 미준수 타이밍 부채널 이상 징후 탐지
4. **Stage 4 (FIPS 203 ML-KEM & FIPS 204 ML-DSA Migration)**: 하이브리드 이중 KDF(Dual-KDF) 강제 적용, FIPS 203 ML-KEM-768 키 캡슐화 및 FIPS 204 ML-DSA 인증서 체인 하드닝

## 🚀 빠른 시작

### 로컬 실행 (Python)
```bash
cd labs/45_quantum_cryptography_pqc_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8045
```

### Docker 실행
```bash
docker-compose up -d --build
```
브라우저에서 `http://127.0.0.1:8045` 접속

## 🧪 테스트 실행
```bash
pytest -v labs/45_quantum_cryptography_pqc_lab/tests/
```
