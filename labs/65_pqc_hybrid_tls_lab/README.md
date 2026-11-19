# Lab 65: Post-Quantum Hybrid TLS 1.3 & ML-KEM / ML-DSA Migration Lab

## 1. 개요 (Overview)
- **대상 포트**: `8065` (`127.0.0.1:8065`)
- **컨테이너 이름**: `vhack-lab65-pqc-hybrid-tls`
- **핵심 목표**: 양자 컴퓨터의 쇼어(Shor) 알고리즘 위협(SNDL - Harvest Now, Decrypt Later)에 대응하여, TLS 1.3 프로토콜에 FIPS 203 ML-KEM-768(Kyber) 하이브리드 키 교환과 FIPS 204 ML-DSA-65(Dilithium) 복합 전자서명을 적용하고, 액티브 다운그레이드 공격 및 NTT 부채널 타이밍 누출을 방어하는 포스트 양자 암호(PQC) 엔터프라이즈 마이그레이션 실습.

## 2. 4단계 실습 구조 (4-Stage Pipeline)
1. **Stage 1: Harvest Now, Decrypt Later (SNDL) & Hybrid ML-KEM-768 Key Exchange**
   - 취약점: 기존 고전 ECDHE(X25519/P-256) 단독 키 교환 세션이 도청·저장되어 미래의 양자 컴퓨터 쇼어 이산대수 공격에 의해 전수 복호화됨.
   - 방어책: 고전 X25519와 FIPS 203 ML-KEM-768을 결합한 하이브리드 KEM(`X25519_MLKEM768`)을 적용하여 $K = \text{HKDF-Extract}(K_{classical} \parallel K_{pqc})$로 세션키를 도출함으로써 격자 기반 LWE 난제로 복호화 원천 차단.
   - 플래그: `FLAG{pqc_hybrid_kem_sndl_resilient_2026}`
2. **Stage 2: Quantum Forgery & FIPS 204 ML-DSA-65 Composite Dual Signature**
   - 취약점: 고전 RSA-3072 또는 ECDSA P-384 서버 인증서가 양자 소인수분해/이산대수 공격으로 개인키가 유출되어 위조 및 액티브 MITM 스푸핑 발생.
   - 방어책: FIPS 204 ML-DSA-65(Dilithium3)와 ECDSA P-384를 결합한 복합 X.509 인증서(Composite Signature)를 도입하여 듀얼 서명 교차 검증을 강제.
   - 플래그: `FLAG{pqc_dual_sig_mldsa_composite_certified}`
3. **Stage 3: Active Downgrade Attack Defense & TLS 1.3 Cipher Suite Hardening**
   - 취약점: 공격자가 ClientHello/ServerHello를 변조하여 TLS 1.2 또는 고전 암호 스위트로 강제 다운그레이드(Cipher Stripping).
   - 방어책: TLS 1.3 프로토콜 전용 강제, 안티 다운그레이드 카나리 검증(`tls13_downgrade_canary`), 비PQC 레거시 암호 스위트 전면 비활성화.
   - 플래그: `FLAG{pqc_anti_downgrade_strict_handshake_guarded}`
4. **Stage 4: Side-Channel Timing Probe Defense & Constant-Time NTT Verification**
   - 취약점: ML-KEM 다항식 환(Ring) 연산 및 NTT(Number Theoretic Transform) 모듈러 역변환 과정에서 메모리 접근 시간 차이($\Delta t > 15 \text{ ns}$)로 비밀키 다항식 계수가 유출.
   - 방어책: 몽고메리 축약 기반 상수 시간(Constant-Time) NTT 연산 및 1차 불리언-산술 마스킹(Masked Memory) 기법을 적용하여 타이밍 편차($\Delta t < 0.2 \text{ ns}$) 완벽 제거.
   - 플래그: `FLAG{pqc_constant_time_ntt_masked_hardened}`

## 3. 컴플라이언스 매핑
- **KISA ISMS-P**: 2.7.1 (암호 통제), 2.7.2 (암호 키 관리)
- **NIST CSF 2.0**: PR.DS-01 (데이터 기밀성), PR.DS-02 (데이터 무결성), FIPS 203/204
- **OWASP Top 10**: A02:2025 (Cryptographic Failures)
- **CVSS 3.1 Score**: 8.6 (High) / `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
