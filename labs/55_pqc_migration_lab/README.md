# Lab 55: PQCMigrationGuard — FIPS 203/204 양자 내성 암호 마이그레이션 랩

> **난이도**: ★★★★☆ | **포트**: `8055` | **연계 섹션**: [57. 양자 암호학 (Quantum_Cryptography)](../../57_Quantum_Cryptography/) | **워게임 트랙**: `pqcmigrate` (트랙 67)

---

## 🎯 실습 목표
2026년 NIST 표준으로 확정된 **FIPS 203 ML-KEM-768(Kyber)** 및 **FIPS 204 ML-DSA-65(Dilithium)**를 이해하고, 레거시 RSA-2048/ECDSA 시스템을 양자 내성 하이브리드 키 교환(X25519 + ML-KEM)으로 마이그레이션하여 **수확 후 해독(Store-Now-Decrypt-Later, SNDL)** 및 양자 다운그레이드 공격을 원천 방어합니다.

---

## 🔬 4대 실습 시나리오

1. **Stage 1: SNDL 위협 & 쇼어 알고리즘 양자 해독 시뮬레이션**
   - 레거시 RSA-2048/ECDH 암호문 도청 및 쇼어 알고리즘을 통한 다항 시간 소인수분해/이산로그 역산 시뮬레이션.
   - **플래그 1**: `FLAG{STORE_NOW_DECRYPT_LATER_QUANTUM_THREAT_5501}`

2. **Stage 2: NIST FIPS 203 ML-KEM-768 격자 캡슐화**
   - Module-Lattice 기반 $R_q$ 다항식 링에서 공개키 $pk$로 암호문 $c$ 캡슐화(`Encaps`) 및 비밀키 $sk$ 역캡슐화(`Decaps`)를 통한 256비트 공유 비밀 도출.
   - **플래그 2**: `FLAG{FIPS203_ML_KEM_768_ENCAPSULATION_MASTERED_5502}`

3. **Stage 3: NIST FIPS 204 ML-DSA-65 양자 내성 전자서명 무결성**
   - 행렬 격자 기반 단기 정수 해(M-SIS) 문제에 기반한 전자서명 발급 및 비트 플리핑(Bit-Flipping) 위조 공격 탐지.
   - **플래그 3**: `FLAG{FIPS204_ML_DSA_65_LATTICE_SIGNATURE_VERIFIED_5503}`

4. **Stage 4: 엔터프라이즈 하이브리드 키 교환 & 다운그레이드 방어**
   - 과도기 하이브리드 키 수립: $K_{combined} = \text{HKDF}(K_{X25519} \parallel K_{ML-KEM-768})$.
   - TLS 1.3 `X25519MLKEM768` NamedGroup 강제를 통한 양자 다운그레이드 공격 원천 차단.
   - **플래그 4**: `FLAG{HYBRID_X25519_ML_KEM_ANTI_DOWNGRADE_SHIELDED_5504}`

---

## 🚀 기동 및 접속

```bash
# Docker Compose 기동
cd labs/55_pqc_migration_lab
docker compose up -d

# 또는 CLI 로컬 기동
python3 -m uvicorn app.main:app --port 8055

# 웹 콘솔 접속
# http://127.0.0.1:8055
```
