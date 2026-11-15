# Lab 60: Quantum Cryptanalysis & Post-Quantum Active Defense Lab

## 개요
- **랩 ID**: `60`
- **이름**: `QuantumCryptanalysisLab` (양자 알고리즘 암호 분석 & 포스트 양자 능동 방어 실습 랩)
- **포트**: `8060` (`127.0.0.1` 루프백 바인딩)
- **주요 분야**: 양자 암호 분석 (Quantum Cryptanalysis), 쇼어 알고리즘(Shor's QPE), 격자 기저 축소(Lattice Basis Reduction SVP/CVP LLL & BKZ-40), SNDL (Store Now, Decrypt Later) 도청 방어, FIPS 203 ML-KEM-768 격자 다항식 마스킹
- **연계 트랙**: 워게임 Track 72 (`quantumcrypt`)
- **CVSS 3.1 점수**: 8.1 (High, `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`)

## 4단계 실전 시나리오
1. **Stage 1 (Shor's Algorithm Period Finding Defense)**: 양자 위상 추정(QPE)을 이용한 RSA-2048 / ECDSA P-256 주기 탐색 인수분해 시도 vs 하이브리드 KEM (X25519 + ML-KEM-768) 결합 캡슐화를 통한 양자 공격 원천 차단.
2. **Stage 2 (Lattice Basis Reduction SVP Attack)**: BKZ-40 격자 기저 축소를 통한 Ring-LWE 최단 벡터 탐색 시도 vs FIPS 203 ML-KEM-768 차원(k=3, η1=2) 격자 난제(Lattice Hardness) 방어.
3. **Stage 3 (SNDL Harvest & Decrypt Defense)**: 장기 보관된 도청 암호문에 대한 미래 양자 컴퓨터(CRQC) 사후 해독 공격 vs 완전한 전방향 비밀성(PFS) 및 Ephemeral KEM 무조건적 비식별성(IND-CCA2) 보장.
4. **Stage 4 (Quantum Fault Injection & Masked NTT Defense)**: 양자 게이트 지터 및 다항식 곱셈 사이드채널 타이밍 공격 vs 상수 시간 넘버 이론 변환(NTT) 마스킹 및 거절 샘플링(Rejection Sampling) 차단.
