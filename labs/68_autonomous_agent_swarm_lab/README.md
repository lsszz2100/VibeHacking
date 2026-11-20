# Lab 68: Autonomous Agent Swarm Security & Byzantine Defense Lab

**Port**: `127.0.0.1:8068`  
**Category**: `ai` (AI Security & Multi-Agent Swarm Defense)  
**Standard**: NIST CSF 2.0 (PR.AC, DE.CM), OWASP Top 10 for LLM (LLM06, LLM07, LLM08), KISA ISMS-P 2.10.1  

---

## 1. 개요 (Overview)

자율 분산 멀티에이전트 스웜(Autonomous Multi-Agent Swarm) 환경에서의 악성 워커 에이전트 사칭, 비잔틴 합의 오염, 공유 메모리 컨텍스트 탈취, 워커 간 연쇄 횡적 이동(Lateral Movement) 공격 기법과 이를 방어하는 eBPF/Landlock/mTLS/PBFT 방어 기법을 실습합니다.

---

## 2. 4단계 실습 구조 (4 Stages)

- **Stage 1 (Rogue Agent Registration & mTLS Identity Verification)**:
  - 공격: 비인가 사칭 에이전트가 위조된 RPC 인터페이스로 스웜 오케스트레이터에 무단 등록 시도.
  - 방어: X.509 mTLS 상호 인증 및 에이전트 SPIFFE ID / SHA-256 서명 기반 엄격 신원 검증.
  - Flag: `FLAG{v218_s1_rogue_swarm_agent_mtls_identity_verified}`

- **Stage 2 (Swarm Consensus Poisoning & Byzantine Fault Mitigation)**:
  - 공격: 오염된 워커 에이전트가 거짓 추론 결과와 악의적 의사결정을 스웜 합의 쿼럼에 주입.
  - 방어: PBFT(Practical Byzantine Fault Tolerance) 3단계 합의 검증 및 이상 가중치 이상치 격리.
  - Flag: `FLAG{v218_s2_pbft_consensus_byzantine_fault_mitigated}`

- **Stage 3 (Shared Swarm Context Window Hijacking & Landlock LSM Isolation)**:
  - 공격: 프롬프트 주입을 통해 다중 에이전트 간 공유되는 Context Window 및 휘발성 메모리 버퍼 오염.
  - 방어: Linux Landlock LSM 무특권 네임스페이스 격리 및 불변 읽기 전용 컨텍스트 스냅샷 강제.
  - Flag: `FLAG{v218_s3_landlock_lsm_swarm_memory_isolated}`

- **Stage 4 (Worker-to-Worker Cascading Lateral Movement & eBPF Tetragon Kill)**:
  - 공격: 감염된 에이전트가 로컬 소켓/IPC를 통해 주변 워커 에이전트 프로세스에 악성 페이로드 전파.
  - 방어: Cilium Tetragon eBPF sys_enter_connect/execve 실시간 모니터링 및 0ms SIGKILL 즉시 사살 격리.
  - Flag: `FLAG{v218_s4_ebpf_tetragon_swarm_lateral_zero_trust_kill}`

---

## 3. 검증 및 솔버 실행 (Verification & Solver)

```bash
# 솔버 직접 실행
python solution/solve.py

# CLI 연동 솔버 실행
vhack solve 68
```
