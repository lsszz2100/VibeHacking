# VibeHacking Project Context & Agent Memory (AGENTS.md)

이 문서는 VibeHacking 저장소에서 작업하는 AI 에이전트를 위한 핵심 프로젝트 컨텍스트 및 영구 메모리입니다.

---

## 1. 프로젝트 개요 및 현재 상태 (Current Status)

- **교재 챕터**: 01~75개 종합 보안 챕터 완비 (다국어 지원: KO, EN, JA, ZH)
  - **대용량 미분류 자료 인제스천 완비**: `02_Network_Hacking/07_practical_packet_analysis_deepdive.md` (Wireshark 심층 해부), `07_Digital_Forensics/07_filesystem_forensics_deepdive.md` (파일시스템 포렌식), `28_Mobile_Hacking/07_frida_android_dynamic_analysis_deepdive.md` (안드로이드 리버싱 & Frida 런타임 후킹), `03_System_Hacking/08_windows_seh_and_driver_exploit_deepdive.md` (Windows SEH 오버라이트 & 커널 취약 드라이버 익스플로잇)
  - **75개 전 챕터 웹 뷰어 / 온라인 리더 포털 구축**: Docsify 기반 다크 테마 웹 리더(`index.html`, `docs/`, `docs/vendor/` 오프라인 자산화 완비), `vhack docs [--port 3000]` 로컬 포털 CLI 완비
  - **75개 전 섹션 README.md 인덱스 동기화 완비**: [tools/sync_section_readmes.py](file:///mnt/d/바이브해킹%20자료/vibe-hacking/tools/sync_section_readmes.py)를 통한 자동 동기화
- **인터랙티브 실습 랩 (Docker Labs)**: **총 20개 실전 랩 완비** (`labs/01` ~ `labs/20`)
  - **Lab 19 (DroidShield)**: 안드로이드 리버싱 & Frida 후킹 랩 (루팅 탐지 우회, SSL Pinning 패치, Native 심볼 후킹, JNI Crypto 암호문 복호화, 포트: `8019`)
  - **Lab 20 (WinAppSec)**: 윈도우 바이너리 & 커널 드라이버 랩 (SEH 스택 오버라이트, SafeSEH/DEP/ASLR 회피, UAC 바이패스, HEVD IOCTL 임의 메모리 쓰기, Token Stealing 권한상승, 포트: `8020`)
- **브라우저 터미널 워게임**: **총 35개 트랙 / 1,225문제** 달성 (`wargame/index.html`, HUD `0/1225`)
  - **PWA 및 오프라인 지원 완비**: `manifest.json`, `sw.js` 서비스 워커 적용 및 데스크톱/모바일 앱 설치 지원
  - **워게임 UX 기능 고도화**: 진행도 JSON 파일 백업/복원(`export json`, `import [file]`, 💾/📂 버튼), 10대 요원 업적/뱃지 시스템(`badges` 명령어, 🏆 HUD 버튼 및 모달 팝업, CRT 토스트 알림) 완비
  - **신규 트랙**:
    - `droidpwn` 📱 모바일 & 안드로이드 보안 (35개 문제: Tier 0~4)
    - `winclient` 🪟 Windows 클라이언트 & 드라이버 익스플로잇 (35개 문제: Tier 0~4)
    - `carcan` 🚗 차량 보안·CAN Bus·UDS 진단 (35개 문제: Tier 0~4)
- **통합 웹 관제 대시보드 (Portal)**:
  - `portal/server.py`, `portal/static/index.html` 기반 실시간 랩 제어(20개 랩 시작/중지/재시작), 웹 셸 콘솔(`💻 셸`), 실시간 컨테이너 로그 스트리밍(`📜 로그`), PoC 익스플로잇 솔루션 뷰어(`💡 솔루션`), 자원 모니터링, 교재/워게임 원클릭 연동 (`vhack portal [--port 8800]`)
- **실습 랩 자동 익스플로잇 솔버 (Solvers)**:
  - `labs/solvers.py`, `labs/tests/test_lab_solvers.py`: 20개 전체 랩의 1~2단계 PoC 익스플로잇, 취약점 원리, 방어 대책 솔버 완비 및 CLI (`vhack solve <lab_id>`, `vhack lab solve <lab_id> [--step N]`)
- **CTF 대회 스코어보드 & 채점 엔진 (CTF)**:
  - `ctf/server.py`, `ctf/tests/test_ctf.py`: 26개 랩 플래그 등록, First Blood 알림 및 +50pt 보너스, 제출 팀 증가에 따른 점수 자동 감쇠(Dynamic Scoring Engine: 500pt -> 100pt), 실시간 순위표 및 First Blood 영예의 전당 피드 (`vhack ctf [--port 8888]`)
- **오프라인 번들러 패키징 (Bundler)**:
  - `tools/bundle_offline.py` 및 `vhack bundle [--tar <path>]` 통한 20개 랩, 35개 트랙(1,225문제), 75개 교재, 로컬 CDN 벤더 자산 전수 무결성 검증 및 배포 아카이브 생성 지원
- **표준 파이썬 패키징**: [pyproject.toml](file:///mnt/d/바이브해킹%20자료/vibe-hacking/pyproject.toml) 기반 패키징 완비 (`pip install -e .` 지원, 글로벌 `vhack` 명령 제공)
- **vhack CLI 고도화**:
  - `vhack solve`: 20개 실습 랩의 1~2단계 취약점 익스플로잇 자동 시뮬레이션 및 플래그 획득
  - `vhack doctor`: Python, Git, Docker, Compose, Node.js, 의존성 9종, 디스크, 포트 8000~8020 가용성 등 시스템 진단
  - `vhack setup-docker`: OS 및 WSL2 환경 자동 감지, Docker CE / Compose 자동 설치 및 WSL2 연동 진단 가이드
  - `vhack docs`: 75개 챕터 웹 리더 포털 로컬 HTTP 서버 실행
  - `vhack portal`: 통합 웹 관제 대시보드 실행 (웹 터미널, 실시간 로그, 솔루션 모달 탑재)
  - `vhack ctf`: 모의해킹 대회 스코어보드 및 Dynamic Scoring/First Blood 채점 서버 실행
  - `vhack bundle`: 오프라인 배포 무결성 검증 및 압축 번들 생성 (1,225문제 동기화)
  - `vhack wargame`: 내장 웹서버 구동 및 브라우저 자동 실행
  - `vhack lab test [--all | <lab_id>]`: 20개 실습 랩 자동 무결성 검증 (144개 테스트 All Green)
  - `vhack lab status`: 20개 랩 종합 상태 대시보드
- **CI/CD 파이프라인**: [`.github/workflows/ci.yml`](file:///.github/workflows/ci.yml) (Labs 01~20, `vhack doctor`, Pytest 전체 151개 테스트 All Green, Wargame 4대 엄격 검증 스위트 자동화) 및 Docs 배포 워크플로우

---

## 2. 실습 랩(1~20) & 교재 & 워게임 연계 매트릭스

| 랩 ID | 랩 이름 | 주요 침투/방어 주제 | 연계 교재 챕터 | 워게임 트랙 | 실행 명령 |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **01** | 웹 해킹 랩 | SQLi, XSS, CSRF, IDOR, 인증 우회 | `05_Web_Hacking` | `web` | `vhack lab start 01` |
| **02** | 바이너리 익스플로잇 랩 | BOF, ret2libc, ROP, 포맷스트링, tcache | `03_System_Hacking` | `pwn` | `vhack lab start 02` |
| **03** | 네트워크 해킹 랩 | Nmap 포트 정찰, 크리덴셜 공격, 피버팅 | `02_Network_Hacking` | `network` | `vhack lab start 03` |
| **04** | 클라우드/컨테이너 보안 랩 | AWS IMDS SSRF, S3 탈취, 컨테이너 탈출 | `14_Cloud_Security` | `cloud` | `vhack lab start 04` |
| **05** | 전체 시나리오 통합 랩 | DMZ 침투 → 내부 피벗 → DB 장악 풀체인 APT | `10_Pentest_Methodology` | `redteam` | `vhack lab start 05` |
| **06** | 펌웨어 해킹 랩 | binwalk 추출, QEMU ARM/MIPS 에뮬레이션 | `61_Firmware_Hacking` | `hardware` | `vhack lab start 06` |
| **07** | 모바일 보안 랩 | APK 디컴파일, API 키 탈취, JWT none | `28_Mobile_Hacking` | `mobile` | `vhack lab start 07` |
| **08** | AI/LLM 보안 랩 (AI Shield) | 프롬프트 인젝션(Jailbreak), RAG 간접 주입, 도구 남용 | `11_AI_Powered_Security`, `69_LLM_Security` | `ai` | `vhack lab start 08` |
| **09** | ICS/SCADA 보안 랩 (GridGuard) | Modbus/TCP FC03/05 조작, 센서 기만(FDI), SIS 비상 트립 | `37_ICS_SCADA`, `63_OT_ICS_Advanced` | `icsscada` | `vhack lab start 09` |
| **10** | Kubernetes 보안 랩 (KubeShield v1) | SA 토큰 탈취, RBAC 남용, hostPath 탈출, privileged 장악 | `29_Container_Kubernetes_Security`, `70_Kubernetes_Security` | `cloud` | `vhack lab start 10` |
| **11** | Active Directory 랩 (KeroShield) | AS-REP & Kerberoasting, DCSync, Golden Ticket | `54_Active_Directory_Attacks` | `activedirectory` | `vhack lab start 11` |
| **12** | CI/CD & 공급망 랩 (PipePoison) | PPE 커맨드 인젝션, 의존성 혼동, 러너 시크릿 탈취, SLSA 변조 | `18_DevSecOps`, `35_Supply_Chain_Attacks` | `supplychain` | `vhack lab start 12` |
| **13** | eBPF 커널 보안 랩 (BPFGuard) | Kprobe 시스템콜 도청, bpf_probe_write_user 메모리 변조, XDP 은닉 통신, BPF LSM 방어 | `01_Linux_Basics`, `26_Linux_Hardening`, `70_Kubernetes_Security` | `ebpf` | `vhack lab start 13` |
| **14** | 문서형 악성코드 & PDF 랩 (DocArmor) | OLE/VBA 매크로 난독화 해제, PDF FlateDecode 분석, CVE-2017-11882, CVE-2021-40444 | `06_Malware_Analysis`, `07_Digital_Forensics`, `45_Malware_Development` | `maldoc` | `vhack lab start 14` |
| **15** | Web3 & 스마트 컨트랙트 랩 (Web3Sec) | Reentrancy(DAO), Batch Overflow, tx.origin 인증 우회, Flash Loan AMM 조작 | `42_Blockchain_Web3_Security` | `web` / `pwn` | `vhack lab start 15` |
| **16** | 메모리 포렌식 & Volatility 랩 (MemShield) | DKOM 프로세스 은닉, VAD RWX 인젝션, C2 소켓 복원, LSASS NTLM dump & LSA PPL 방어 | `07_Digital_Forensics`, `44_Incident_Response_DFIR` | `volatility` | `vhack lab start 16` |
| **17** | 클라우드 네이티브 & K8s 랩 (KubeShield) | 특권 파드 탈출, RBAC 와일드카드 권한상승, 클라우드 IMDS 탈취, Cosign 어드미션 제어 | `29_Container_Kubernetes_Security`, `38_Cloud_Native_Security`, `70_Kubernetes_Security` | `cloud` | `vhack lab start 17` |
| **18** | AI 에이전트 & MCP 보안 랩 (AgentGuard) | 간접 프롬프트 인젝션, MCP 도구 자율 실행 하이재킹, 데이터 유출, BPF/LSM 방어 | `11_AI_Powered_Security`, `56_AI_Red_Teaming`, `69_LLM_Security` | `aiagent` | `vhack lab start 18` |
| **19** | 안드로이드 & Frida 후킹 랩 (DroidShield) | 루팅 탐지 우회, SSL Pinning 패치, Native 인라인 후킹, JNI Crypto 키 복원 | `28_Mobile_Hacking` | `droidpwn` | `vhack lab start 19` |
| **20** | Windows 바이너리 & 드라이버 랩 (WinAppSec) | SEH 스택 변조, SafeSEH/DEP/ASLR 우회, UAC 바이패스, HEVD IOCTL 토큰 스왑 | `03_System_Hacking`, `45_Malware_Development` | `winclient` | `vhack lab start 20` |

---

## 3. 핵심 검증 및 테스트 명령어 (Verification Suite)

코드나 문서, 워게임 수정 시 반드시 다음 검증 스위트를 통과해야 합니다:

```bash
# 1. 전체 단위/통합 테스트 (147개 테스트 전원 통과: Labs 01~20, Portal, CTF)
pytest -q

# 2. 실습 랩 CLI 자동 무결성 검증 (20개 랩 144개 테스트 통과)
python3 vhack.py lab test --all
# 또는 vhack이 설치된 경우:
vhack lab test --all

# 3. 환경 진단 검사 (8개 영역 100% 정상 확인)
vhack doctor

# 4. 오프라인 패키징 및 무결성 전수 검사
python3 vhack.py bundle

# 5. Docker 환경 진단 및 설정 가이드
vhack setup-docker --dry-run

# 6. 75개 챕터 웹 리더 포털 실행
vhack docs

# 7. 통합 웹 관제 대시보드 실행
vhack portal

# 8. 모의해킹 대회 스코어보드 & Dynamic Scoring 채점 엔진 실행
vhack ctf

# 9. 20개 실습 랩 자동 익스플로잇 솔버 실행
vhack solve 01 --step 1

# 10. 워게임 무결성 및 구조 검증 (1,225문제, 35트랙, 5티어)
node wargame/scripts/verify.js

# 11. 워게임 지문/힌트 간 교차 정답 노출(Leak) 스캔 (0건)
node wargame/scripts/leakscan.js

# 12. 워게임 채점 규칙 및 README 포맷 엄격 감사 ([A]~[J] 0결함)
node wargame/scripts/audit.js --strict

# 13. 연산/유도형 챌린지 258개 자동 풀이 검증 (258/258 통과)
node wargame/scripts/solve-derivable.js
```

---

## 4. 보안 및 Git 운영 지침 (Security & Operational Rules)

1. **민감 인증정보 보호**: Git 작업 시 토큰, 패스워드, SSH 개인키를 명령어 인자나 커밋 메시지, 코드에 절대 포함하지 마십시오. (`~/.netrc` 또는 git credential helper 사용)
2. **양방향 링크 무결성**: 교재 챕터(`06_*_lab.md`), `labs/README.md`, 각 랩의 `README.md` 간의 상대 링크와 워게임 트랙 표기가 항상 동기화되도록 유지하십시오.
3. **독립 테스트 환경 격리**: 실습 랩 테스트 작성 시 FastAPI 및 패키지 임포트 스코프 충돌을 방지하기 위해 dynamic import isolation 패턴을 준수하십시오.

---

## 5. 주요 마일스톤 이력 (Milestone History)

- **2026-09-20 (Portal Web Console/Logs/Solver Modal, Lab Solvers DB & CLI, Track 35 carcan 1,225 Milestone, CTF First Blood & Dynamic Scoring, 151 Tests All Green)**:
  - **웹 포털 관제 고도화 (`vhack portal`)**: 20개 랩 제어 외에 웹 셸 콘솔(`💻 셸`), 실시간 컨테이너 로그 스트리밍(`📜 로그`), 취약점 원리/대책/PoC 익스플로잇 솔루션 뷰어(`💡 솔루션`) 모달 UI 추가, 단위 테스트 전원 통과
  - **20개 실습 랩 자동 익스플로잇 솔버 구축 (`vhack solve`)**: `labs/solvers.py`에 20개 랩 1~2단계 PoC 익스플로잇, 취약점 원리, 방어 대책 솔버 완비 및 CLI (`vhack solve <lab_id>`, `vhack lab solve <lab_id> [--step N]`)
  - **워게임 35번째 트랙 (`carcan`) 확장 및 1,225문제 마일스톤**: 차량 보안·CAN Bus·UDS 진단 트랙 35개 문제 구축으로 1,225문제 완비, 4대 무결성 검증 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js` 258/1225) 전원 0결함 완벽 통과
  - **CTF 대회 스코어보드 고도화 (`vhack ctf`)**: 26개 랩 플래그 풀 구축, 문제 최초 해결 시 First Blood 뱃지 및 +50pt 보너스 지급, 참가자 수에 비례한 점수 자동 감쇠 알고리즘(Dynamic Scoring: 500pt -> 100pt), First Blood 명예의 전당 피드 및 스코어보드 UI 탑재
  - **전체 151개 테스트 100% 통과**: `pytest -q` (Labs 01~20 144개 테스트 + solvers 4개 + portal 6개 + ctf 4개 등 151개 ALL GREEN)
- **2026-09-19 (Lab 18 AgentGuard, Wargame Track 32 / 1,120 Challenges, Wargame UX & Badges, Deep-dive Ingestion, 18 Labs 131 Tests All Green, Remote Sync)**:
  - **Lab 18 AgentGuard 랩 신규 구축**: `labs/18_ai_agent_mcp_lab/` (간접 프롬프트 인젝션, MCP 도구 자율 실행 하이재킹, 데이터 유출, 시스템 커맨드 탈출, eBPF/LSM 보안 필터 방어, 포트 8018, 7개 단위 테스트 전원 통과)
  - **워게임 32번째 트랙 (`aiagent`) 확장**: 35개 문제 추가로 1,085제 → 1,120제 확장, 4대 엄격 검증 스위트 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js` 153/1120) 전원 무결격 통과
  - **워게임 UX 기능 고도화**: 진행도 JSON 파일 백업/복원(`export json`, `import [file]`, 💾/📂 버튼), 10대 요원 업적/뱃지 시스템(`badges` 명령어, 🏆 HUD 버튼 및 모달 팝업, CRT 토스트 알림) 완비
  - **대용량 미분류 자료 인제스천**:
    - `02_Network_Hacking/07_practical_packet_analysis_deepdive.md` (와이어샤크 TCP 세션 재구성, ZeroWindow/재전송 이상 분석, DNS 터널링 탐지 스크립트, SSLKEYLOGFILE 복호화 실무, Scapy 기반 TCP 패킷 카빙)
    - `07_Digital_Forensics/07_filesystem_forensics_deepdive.md` (FAT32 디렉터리 엔트리 32B 및 0xE5 삭제 복구, NTFS 1024B $MFT 레코드 분석, $0x10 vs $0x30 타임스톰핑 탐지, Data Run 디코딩, EXT2/3/4 Inode Extents 및 슬랙 공간 카빙)
    - `tools/sync_section_readmes.py` 전 섹션 동기화 완료
  - **18개 랩 131개 무결성 테스트 통과**: `vhack lab test --all` -> 18개 랩 131개 테스트 100% All Green, 전체 Pytest 134개 테스트 통과
  - **원격 저장소 동기화**: `main` 브랜치 커밋(`b1602e0`) 원격 저장소(`https://github.com/lsszz2100/VibeHacking.git`) 푸시 완료
- **2026-09-18 (Lab 17 KubeShield, Docsify Plugin Suite, 17 Labs 124 Tests All Green, Remote Sync)**:
  - **Lab 17 KubeShield 랩 신규 구축**: `labs/17_kubernetes_cloud_native_lab/` (특권 파드 탈출 vs PSA Restricted, RBAC 와일드카드 권한 상승 vs 최소 권한, IMDSv1 SSRF vs IMDSv2 Hop Limit 1 / NetworkPolicy, 공급망 위조 이미지 침투 vs Kyverno/Sigstore Cosign 어드미션 웹훅, 포트 8017, 11개 단위 테스트 전원 통과)
  - **Docsify 웹 뷰어 플러그인 고도화**: Mermaid 10 실시간 다이어그램 렌더링, `docsify-pagination` 챕터 이동 네비게이션, `docsify-copy-code` 코드 복사, `zoom-image` 이미지 확대, 상단 고정 네비게이션 바 & 실습 랩/워게임 원클릭 연동 배너 배치
  - **17개 랩 124개 무결성 테스트 통과**: `vhack lab test --all` -> 17개 랩 124개 테스트 100% All Green, 전체 Pytest 127개 테스트 통과
  - **원격 저장소 동기화**: `main` 브랜치 커밋(`64e82c1`, `4f0fdfc`) 원격 저장소(`https://github.com/lsszz2100/VibeHacking.git`) 푸시 완료
- **2026-09-18 (Lab 16, Docsify Portal, Wargame 31 Tracks / 1,085 Challenges, Docker Setup CLI)**:
  - **Lab 16 MemShield 랩 신규 구축**: `labs/16_memory_forensics_lab/` (DKOM unlinking, VAD RWX injection, C2 socket reconstruction, LSASS NTLM dump & LSA PPL defense, 포트 8016, 11개 테스트 전원 통과)
  - **75개 챕터 웹 리더 포털 구축**: Docsify 기반 다크 테마 포털(`index.html`, `_sidebar.md`, `_navbar.md`, `docs/`), GitHub Pages 자동 배포(`.github/workflows/deploy-docs.yml`), `vhack docs` CLI 내장 웹 서버 제공
  - **워게임 31번째 트랙 (`volatility`) 확장**: 35개 문제 추가로 1,050제 → 1,085제 확장, 4대 엄격 검증 스위트 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js`) 전원 무결격 통과
  - **로컬 개발 환경 편의성 강화 (`vhack setup-docker`)**: Linux 배포판 및 WSL2 자동 감지, Docker Desktop 연동 안내, 비대화형/Dry-run 설치 지원, `vhack doctor` 연계
- **2026-09-17 (Lab 15, 75 Sections Sync, CLI DX & Packaging)**:
  - **Lab 15 Web3 랩 신규 구축**: `labs/15_web3_smart_contract_lab/` (EVM 시뮬레이터, Reentrancy, Batch Overflow, tx.origin, Flash Loan AMM, Web3 CLI, 포트 8015, 12개 테스트 전원 통과)
  - **75개 전 섹션 README.md 표준화 & 동기화**: 53개 신규 생성, 22개 업데이트 및 `tools/sync_section_readmes.py` 동기화 도구 완비
  - **CLI 개발자 경험 강화**: `vhack doctor` (8대 영역 종합 환경 진단), `vhack wargame` (원클릭 워게임 브라우저 서버)
  - **표준 Python 패키징**: `pyproject.toml` 추가 (`pip install -e .` 및 전역 `vhack` 실행 지원)
  - **워게임 PWA 적용**: `manifest.json`, `sw.js` 서비스 워커 적용으로 오프라인 및 PWA 앱 설치 지원
  - **통합 테스트 & CI 검증**: 전체 Pytest 105개 PASS (15개 실습 랩 102개 테스트), 워게임 1,050제 무결성 100% PASS

