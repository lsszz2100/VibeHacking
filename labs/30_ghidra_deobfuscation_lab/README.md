# Lab 30: GhidraRev — 바이너리 분석 & 고급 난독화 해제 실습 랩 (Ghidra Deobfuscation Lab)

> 🔬 **포트**: `8030`  
> 🎯 **연계 교재**: [04장 리버스 엔지니어링: 07_ghidra_advanced_deobfuscation_deepdive.md](../../04_Reverse_Engineering/07_ghidra_advanced_deobfuscation_deepdive.md)  
> 🚩 **연계 워게임 트랙**: `ghidra` (Ghidra 역공학 & 난독화 해제 35제)

---

## 1. 랩 개요

현대 리버스 엔지니어링(Reverse Engineering)에서 상용 프로텍터(Themida, VMProtect)나 악성코드(Malware), 독점 펌웨어 바이너리는 정적 분석을 방해하기 위해 **심볼 스트립(Symbol Stripping)**, **제어 흐름 평탄화(Control Flow Flattening, CFF)**, **불투명 술어(Opaque Predicates)**, **안티 탬퍼 자체 무결성 체크섬(Self-Hashing Integrity)** 기법을 적극 활용합니다.

본 랩에서는 오픈소스 역공학 프레임워크인 **NSA Ghidra**의 Headless 자동화 분석, 상태 머신 디스패처 디플래트닝(Deflattening), 인라인 바이너리 패칭(Patching) 및 무결성 우회 전 과정을 실습합니다.

```
+-------------------------------------------------------------------------------+
|                       GhidraRev 침투 & 난독화 해제 체인                        |
+-------------------------------------------------------------------------------+
  [ 스트립트 바이너리 ]
          │
          ▼  Step 1: Ghidra Headless 스크립트 실행 (함수 프롤로그 시그니처 매칭)
  [ validate_license_core 심볼 복원 ]
          │
          ▼  Step 2: CFF 상태 머신 [10, 40, 25, 90] 디플래트닝 & 불투명 술어 제거
  [ 복원된 고수준 C 유사 코드 & 취약 분기점 (0x00401337) 식별 ]
          │
          ▼  Step 3: 74 18 (jz) -> 90 90 (nop nop) 바이너리 패치 & 자체 체크섬 우회
  [ 👑 무제한 라이선스 활성화 및 관리자 권한 획득 ]
+-------------------------------------------------------------------------------+
```

---

## 2. 랩 실행 방법

```bash
# vhack CLI를 통한 실행 (권장)
vhack lab start 30

# 또는 docker compose 직접 실행
cd labs/30_ghidra_deobfuscation_lab
docker compose up -d --build

# 웹 콘솔 접속
http://localhost:8030
```

---

## 3. 실습 단계 및 플래그

### Step 1: Ghidra Headless 심볼 복원
- **목표**: 함수 프롤로그 바이트 시그니처(`55 48 89 E5`)를 스캔하여 가상 주소 `0x00401200`의 핵심 검증 함수를 `validate_license_core`로 복원합니다.
- **플래그**: `FLAG{ghidra_headless_symbol_analysis_recovered_8030}`

### Step 2: Control Flow Flattening (CFF) 디플래트닝
- **목표**: `switch(state)` 디스패처 루프의 상태 전이 시퀀스 `[10, 40, 25, 90]`를 역산하고 불투명 술어를 NOP 처리하여 라이선스 로직을 복원합니다.
- **플래그**: `FLAG{control_flow_flattening_state_machine_defused_3921}`

### Step 3: 안티 탬퍼 우회 & 바이너리 인라인 패치
- **목표**: 주소 `0x00401337`의 조건부 점프(Opcode `74 18` jz)를 `90 90` (NOP) 또는 `eb 18` (JMP)로 패치하고 자체 `.text` 해시 검증을 우회합니다.
- **플래그**: `FLAG{binary_patch_integrity_hash_bypassed_9942}`

---

## 4. 방어 및 하드닝 (Defense & Hardening)

1. **Control Flow Integrity (CFI)**: Clang/GCC `-fsanitize=cfi` 또는 Intel CET(Control-flow Enforcement Technology)를 적용하여 간접 분기 및 점프 대상을 하드웨어 레벨에서 보호합니다.
2. **강력한 코드 서명(Code Signing)**: Authenticode / PKCS#7 디지털 서명 검증을 커널 로더 단에서 강제하여 임의 바이너리 바이트 변조 시 로딩을 원천 차단합니다.
3. **Hardware Root of Trust**: Secure Boot 및 TPM 2.0 PCR 해시 체인을 통해 바이너리 무결성을 측정하고 원격 증명(Remote Attestation)을 수행합니다.
