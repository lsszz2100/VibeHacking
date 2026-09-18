# Lab 16: 메모리 포렌식 & Volatility 3 분석 랩 (MemShield)

[![Lab Status](https://img.shields.io/badge/Lab-16_Active-brightgreen)](http://localhost:8016)
[![Port](https://img.shields.io/badge/Port-8016-blue)](http://localhost:8016)
[![Difficulty](https://img.shields.io/badge/Difficulty-★★★★☆-orange)](#)

APT 침해 사고가 발생한 엔드포인트의 물리 메모리 덤프(`victim_win10.dmp` / `memory.raw`)를 대상으로 **Volatility 3** 분석 기법을 실습하는 인터랙티브 메모리 포렌식 워크스테이션입니다.

---

## 🎯 학습 목표

1. **DKOM 은닉 프로세스 탐지**:
   - `EPROCESS` 더블 링크드 리스트(`ActiveProcessLinks`) 조작으로 `pslist`에서 은닉된 악성 프로세스를 풀 태그(`Proc`) 스캔 기반의 `psscan` 및 `pstree`로 적출
2. **코드 인젝션 & 프로세스 할로잉 탐지**:
   - VAD (Virtual Address Descriptor) 트리 내 `PAGE_EXECUTE_READWRITE` (RWX) 실행 권한 영역과 `MZ`(4D 5A) PE 시그니처 분석 (`malfind`)
3. **네트워크 아티팩트 & C2 비컨 복원**:
   - 활성 소켓 및 종료된 TCP 엔드포인트 스캔(`netscan`)을 통해 은닉 프로세스의 C2 역방향 터널링 세션 추적
4. **LSASS 자격 증명 덤프 & 커널 보호 방어**:
   - `lsass.exe` 메모리 내 NTLM 해시 덤프(`hashdump`/`lsadump`) 차단 및 Windows LSA PPL(Protected Process Light) 방어 기법 실습

---

## 🚀 빠른 시작

```bash
# vhack CLI를 통한 랩 가동
vhack lab start 16

# 또는 Docker Compose 직접 실행
cd labs/16_memory_forensics_lab
docker compose up -d --build

# 웹 콘솔 접속
# http://localhost:8016
```

---

## 🔬 4단계 포렌식 시나리오 & 플래그

| 단계 | 침해/포렌식 주제 | 핵심 도구 / 플러그인 | 완료 플래그 |
| :---: | :--- | :--- | :--- |
| **Stage 1** | DKOM 은닉 프로세스 탐지 | `vol windows.psscan`, `windows.pstree` | `FLAG{m3m_dkom_proc_unv31l3d_8492}` |
| **Stage 2** | VAD 인젝션 & 프로세스 할로잉 | `vol windows.malfind --pid 2440` | `FLAG{m3m_vads_rwx_h0ll0w_sh3ll_7134}` |
| **Stage 3** | C2 비컨 네트워크 아티팩트 복원 | `vol windows.netscan` | `FLAG{m3m_n3t_c2_b34c0n_tr4ck3d_9921}` |
| **Stage 4** | LSASS NTLM 덤프 & PPL 방어 | `vol windows.lsadump`, LSA Hardening | `FLAG{m3m_ls4ss_ntlm_ppl_gu4rd_3519}` |

---

## 💻 가상 Volatility 3 터미널 명령어

웹 콘솔 하단의 대화형 터미널에서 다음 명령어를 직접 실행할 수 있습니다:

```bash
vol -f memory.raw windows.pslist          # 활성 EPROCESS 링크 순회
vol -f memory.raw windows.psscan          # 커널 메모리 풀 스캔 (은닉 프로세스 탐지)
vol -f memory.raw windows.pstree          # 부모-자식 프로세스 트리 구조
vol -f memory.raw windows.malfind         # VAD RWX 인젝션 메모리 영역 덤프
vol -f memory.raw windows.netscan         # 네트워크 TCP/UDP 소켓 아티팩트
vol -f memory.raw windows.lsadump         # LSA 시크릿 및 계정 해시 덤프
vol -f memory.raw windows.cmdline         # 프로세스 인자 및 실행 명령줄
status                                    # 포렌식 조사 현황 대시보드
flags                                     # 획득 플래그 확인
help                                      # 명령어 도움말
```

---

## 🧪 자동화 검증

```bash
# Lab 16 단독 테스트
vhack lab test 16

# 전체 랩 통합 검증
vhack lab test --all
```
