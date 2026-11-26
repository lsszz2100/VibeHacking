# Lab 79: Oran6gNtnSecurityLab (6G NTN & O-RAN 통신망 보안 실전 랩)

- **포트**: `127.0.0.1:8079` (루프백 격리)
- **버전**: `v2.29.0`
- **4단계 실전 시나리오**:
  1. **Stage 1 (E2 xApp & gNodeB Recon/Defense)**: Near-RT RIC E2 인터페이스 악성 xApp 등록 차단 및 mTLS + SPIFFE X.509 스키마 화이트리스트 검증
  2. **Stage 2 (Open Fronthaul eCPRI & PTP Sync Hardening)**: 비인가 eCPRI C/U-Plane 패킷 주입 및 IEEE 1588v2 PTP Grandmaster 시간 동기화 스푸핑 차단 (MACsec AES-256-GCM + NTS-PTP)
  3. **Stage 3 (A1/O1 Policy Poisoning & Network Slice Isolation)**: Near-RT RIC A1 정책 오염 및 6G 네트워크 슬라이스 SLA 기아 공격 방어 (RBAC 서명 정책 및 슬라이스 격리)
  4. **Stage 4 (6G NTN PQC Handover & Zero-Trust RIC Attestation)**: 위성-지상국 Xn 핸드오버 SNDL 도청 방어 및 NIST FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 원격 증명
