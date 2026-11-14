# Lab 57 — AntiReversingShield: 바이너리 보호 & 안티 리버싱 능동 방어 랩

## 📌 실습 개요
- **실습 번호**: Lab 57
- **포트 바인딩**: `127.0.0.1:8057` (로컬 루프백 격리)
- **난이도**: ★★★★★ (Advanced)
- **주요 테마**: 안티디버깅(PEB BeingDebugged / ptrace / 하드웨어 브레이크포인트), 동적 API Hashing(ROR13/Murmur3), 변형 패커 분석 & OEP 언패킹, 안티-VM & RDTSC 타이밍 분석 무력화

## 🚀 실습 구동 방법
```bash
# Docker Compose 기동 (또는 로컬 FastAPI 실행)
docker compose up -d

# 웹 콘솔 브라우저 접속
http://localhost:8057

# 상태 확인
curl http://127.0.0.1:8057/api/status

# vhack CLI를 통한 자동 검증
python3 vhack.py lab test 57
```

## 🎯 4단계 실전 시나리오
1. **Stage 1 (Dynamic Anti-Debugging & PEB / ptrace Bypass)**:
   - `ptrace(PTRACE_TRACEME)`, PEB `BeingDebugged`, 하드웨어 브레이크포인트(DR0~DR7) 탐지 트랩을 인라인 바이트 패칭(`31c0c3` / `9090`) 또는 `LD_PRELOAD`로 무력화
   - 획득 플래그: `FLAG{ANTI_DEBUGGING_PEB_PTRACE_BYPASSED_5701}`
2. **Stage 2 (API Hashing & Dynamic IAT Resolution)**:
   - 정적 IAT에 노출되지 않고 ROR13 해시(`0x91afca54`)로 동적 로딩되는 `VirtualAlloc` API를 크래킹하여 은닉 임포트 테이블 복원
   - 획득 플래그: `FLAG{API_HASHING_ROR13_DYNAMIC_IAT_RESOLVED_5702}`
3. **Stage 3 (Advanced Binary Packing & OEP Unpacking)**:
   - 커스텀 암호화 스텁의 tail jump를 추적하여 Original Entry Point(`0x00401580`)를 식별하고 IAT 재구축 및 언패킹 덤프 생성
   - 획득 플래그: `FLAG{CUSTOM_PACKER_OEP_DUMP_AND_UNPACKED_5703}`
4. **Stage 4 (Anti-VM & Timing Analysis Active Defense)**:
   - `RDTSC` 단일 스텝 명령어 지연시간 탐지, CPUID 하이퍼바이저 비트, SMBIOS 가상화 아티팩트(`VMware`, `QEMU`, `VirtualBox`)를 능동적으로 우회하여 가상 샌드박스 실행 보장
   - 획득 플래그: `FLAG{ANTI_VM_RDTSC_TIMING_DEFENSE_NEUTRALIZED_5704}`
