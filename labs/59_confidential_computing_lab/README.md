# Lab 59: Confidential Computing & TEE Defense Lab

## 개요
- **랩 ID**: `59`
- **이름**: `ConfidentialComputingLab`
- **포트**: `8059` (`127.0.0.1` 루프백 바인딩)
- **주요 분야**: 기밀 컴퓨팅 (Confidential Computing), AMD SEV-SNP, Intel TDX, 하드웨어 메모리 암호화 엔진 (MEE), 하드웨어 원격 증명 (Remote Attestation), 역방향 매핑 테이블 (RMP), vCPU 레지스터 상태 암호화 (VMSA)
- **연계 트랙**: 워게임 Track 71 (`teeconfidential`)
- **CVSS 3.1 점수**: 8.5 (High, `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`)

## 4단계 실전 시나리오
1. **Stage 1 (Cold Boot & DMA Dump Defense)**: 호스트 root 또는 DMA 장치가 물리 메모리를 스누핑할 때 하드웨어 메모리 암호화(AES-256-XTS)를 통해 평문 데이터 누출을 원천 차단.
2. **Stage 2 (Remote Attestation)**: 하드웨어 보안 프로세서(PSP)의 ECDSA P-384 서명 체인 및 초기 엔클레이브 측정값(MRENCLAVE/PCR0) 무결성 검증으로 위조 엔클레이브 주입 차단.
3. **Stage 3 (Reverse Map Table RMP Defense)**: 악성 하이퍼바이저가 게스트 물리 페이지를 재매핑/스플라이싱 공격 시 하드웨어 RMP 테이블이 페이지 소유권 불일치를 감지하여 `#NPF` 인터럽트로 차단.
4. **Stage 4 (vCPU State Encryption VMSA)**: VM-Exit 시 하이퍼바이저가 게스트 레지스터 상태를 탈취하지 못하도록 VMSA 영역을 하드웨어 암호화하고 캐시 플러시(WBINVD/IBPB) 완화 적용.
