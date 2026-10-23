# Lab 49: PQCTLSGuard — 양자 내성 하이브리드 TLS 1.3 실전 실습 환경

## 1. 개요
* **서비스 포트**: `8049`
* **관련 챕터**: `57_Quantum_Cryptography/07_post_quantum_cryptography_and_lattice_migration_deepdive.md`
* **주요 목표**:
  1. 고전 RSA/ECC 암호체계의 HNDL(Harvest-Now-Decrypt-Later) 위협 감사
  2. X25519 + ML-KEM-768(Kyber) 하이브리드 키 교환 세션 수립
  3. ML-DSA-65(Dilithium) 격자 기반 양자 내성 디지털 서명 검증
  4. 다운그레이드 공격 방어 및 비양자 암호 폴백 금지 정책 강제
