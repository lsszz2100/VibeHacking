# Lab 70: Autonomous Kernel eBPF LSM Hotpatching & 0-Day Runtime Defense Lab

## 개요
- **포트**: `8070` (`127.0.0.1:8070`)
- **카테고리**: 커널 보안 / eBPF 런타임 방어
- **버전**: `v2.20.0`
- **목표**: AI 자율 0-Day 커널 익스플로잇 vs 커널 eBPF LSM 동적 핫패칭 및 런타임 제로-레이턴시 차단

## 실습 단계 (4 Stages)
1. **Stage 1: eBPF LSM `security_bprm_check` 훅 설정**: 바이너리 실행 사전 가로채기 및 익스플로잇 시그니처 차단
2. **Stage 2: `BPF_MAP_TYPE_HASH` & RingBuffer 격리**: 커널 공간 실시간 룩업(<1µs) 및 이상 텔레메트리 스트리밍
3. **Stage 3: Seccomp-BPF 동적 핫패칭**: 재부팅 없는 취약 시스템 콜(`io_uring_enter`) 격리
4. **Stage 4: 머클 트리 기반 커널 패치 출처 증명**: 암호학적 해시체인 및 Ed25519 서명 검증
