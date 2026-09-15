# VibeHacking Project Context & Agent Memory (AGENTS.md)

이 문서는 VibeHacking 저장소에서 작업하는 AI 에이전트를 위한 핵심 프로젝트 컨텍스트 및 영구 메모리입니다.

---

## 1. 프로젝트 개요 및 현재 상태 (Current Status)

- **교재 챕터**: 01~75개 종합 보안 챕터 완비 (다국어 지원: KO, EN, JA, ZH)
- **인터랙티브 실습 랩 (Docker Labs)**: 총 12개 실전 랩 완비 (`labs/01` ~ `labs/12`)
- **브라우저 터미널 워게임**: **총 27개 트랙 / 945문제** 달성 (`wargame/index.html`, HUD `0/945`)
  - **27번째 신규 트랙**: `wasm` 🧩 WebAssembly 보안 (35개 문제: Tier 0~4)
  - 헤더 식별자, LEB128 정수 압축, 선형 메모리 버퍼 오버플로우 오프셋, 간접 호출(`call_indirect`) 변조, Wasm 샌드박스 탈출 및 포렌식 캡스톤

---

## 2. 실습 랩(1~12) & 교재 & 워게임 연계 매트릭스

| 랩 ID | 랩 이름 | 주요 침투/방어 주제 | 연계 교재 챕터 | 워게임 트랙 | 실행 명령 |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **01** | 웹 해킹 랩 | SQLi, XSS, CSRF, IDOR, 인증 우회 | `05_Web_Hacking` | `web` | `python3 vhack.py lab start 01` |
| **02** | 바이너리 익스플로잇 랩 | BOF, ret2libc, ROP, 포맷스트링, tcache | `03_System_Hacking` | `pwn` | `python3 vhack.py lab start 02` |
| **03** | 네트워크 해킹 랩 | Nmap 포트 정찰, 크리덴셜 공격, 피버팅 | `02_Network_Hacking` | `network` | `python3 vhack.py lab start 03` |
| **04** | 클라우드/컨테이너 보안 랩 | AWS IMDS SSRF, S3 탈취, 컨테이너 탈출 | `14_Cloud_Security` | `cloud` | `python3 vhack.py lab start 04` |
| **05** | 전체 시나리오 통합 랩 | DMZ 침투 → 내부 피벗 → DB 장악 풀체인 APT | `10_Pentest_Methodology` | `redteam` | `python3 vhack.py lab start 05` |
| **06** | 펌웨어 해킹 랩 | binwalk 추출, QEMU ARM/MIPS 에뮬레이션 | `61_Firmware_Hacking` | `hardware` | `python3 vhack.py lab start 06` |
| **07** | 모바일 보안 랩 | APK 디컴파일, API 키 탈취, JWT none | `28_Mobile_Hacking` | `mobile` | `python3 vhack.py lab start 07` |
| **08** | AI/LLM 보안 랩 (AI Shield) | 프롬프트 인젝션(Jailbreak), RAG 간접 주입, 도구 남용 | `11_AI_Powered_Security`, `69_LLM_Security` | `ai` | `python3 vhack.py lab start 08` |
| **09** | ICS/SCADA 보안 랩 (GridGuard) | Modbus/TCP FC03/05 조작, 센서 기만(FDI), SIS 비상 트립 | `37_ICS_SCADA`, `63_OT_ICS_Advanced` | `icsscada` | `python3 vhack.py lab start 09` |
| **10** | Kubernetes 보안 랩 (KubeShield) | SA 토큰 탈취, RBAC 남용, hostPath 탈출, privileged 장악 | `29_Container_Kubernetes_Security`, `70_Kubernetes_Security` | `cloud` | `python3 vhack.py lab start 10` |
| **11** | Active Directory 랩 (KeroShield) | AS-REP & Kerberoasting, DCSync, Golden Ticket | `54_Active_Directory_Attacks` | `activedirectory` | `python3 vhack.py lab start 11` |
| **12** | CI/CD & 공급망 랩 (PipePoison) | PPE 커맨드 인젝션, 의존성 혼동, 러너 시크릿 탈취, SLSA 변조 | `18_DevSecOps`, `35_Supply_Chain_Attacks` | `supplychain` | `python3 vhack.py lab start 12` |

---

## 3. 핵심 검증 및 테스트 명령어 (Verification Suite)

코드나 문서, 워게임 수정 시 반드시 다음 검증 스위트를 통과해야 합니다:

```bash
# 1. 전체 단위/통합 테스트 (42개 테스트: HA DB 백업, Lab 10, Lab 11, Lab 12)
pytest

# 2. 워게임 무결성 및 구조 검증 (945문제, 27트랙, 5티어)
node wargame/scripts/verify.js

# 3. 워게임 지문/힌트 간 교차 정답 노출(Leak) 스캔
node wargame/scripts/leakscan.js

# 4. 워게임 채점 규칙 및 README 포맷 엄격 감사
node wargame/scripts/audit.js --strict

# 5. 연산/유도형 챌린지 113개 자동 풀이 검증
node wargame/scripts/solve-derivable.js
```

---

## 4. 보안 및 Git 운영 지침 (Security & Operational Rules)

1. **민감 인증정보 보호**: Git 작업 시 토큰, 패스워드, SSH 개인키를 명령어 인자나 커밋 메시지, 코드에 절대 포함하지 마십시오. (`~/.netrc` 또는 git credential helper 사용)
2. **양방향 링크 무결성**: 교재 챕터(`06_*_lab.md`), `labs/README.md`, 각 랩의 `README.md` 간의 상대 링크와 워게임 트랙 표기가 항상 동기화되도록 유지하십시오.
3. **독립 테스트 환경 격리**: 실습 랩 테스트 작성 시 FastAPI 및 패키지 임포트 스코프 충돌을 방지하기 위해 dynamic import isolation 패턴을 준수하십시오.
