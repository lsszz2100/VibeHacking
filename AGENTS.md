# VibeHacking Project Context & Agent Memory (AGENTS.md)

이 문서는 VibeHacking 저장소에서 작업하는 AI 에이전트를 위한 핵심 프로젝트 컨텍스트 및 영구 메모리입니다.

---

## 1. 프로젝트 개요 및 현재 상태 (Current Status)

- **교재 챕터**: 01~75개 종합 보안 챕터 완비 (다국어 지원: KO, EN, JA, ZH)
  - **75개 전 챕터 웹 뷰어 / 온라인 리더 포털 구축**: Docsify 기반 다크 테마 웹 리더(`index.html`, `docs/`, `.github/workflows/deploy-docs.yml`), `vhack docs [--port 3000]` 로컬 포털 CLI 완비
  - **75개 전 섹션 README.md 인덱스 동기화 완비**: [tools/sync_section_readmes.py](file:///mnt/d/바이브해킹%20자료/vibe-hacking/tools/sync_section_readmes.py)를 통한 자동 동기화 및 챕터별 학습 목표/실습 랩 링크 체계화
- **인터랙티브 실습 랩 (Docker Labs)**: **총 17개 실전 랩 완비** (`labs/01` ~ `labs/17`)
  - **Lab 14 (DocArmor)**: 문서형 악성코드 & PDF 포렌식 랩 (OLE/VBA 매크로, CVE-2017-11882, CVE-2021-40444, PDF FlateDecode)
  - **Lab 15 (Web3 & Smart Contract Security)**: EVM 모의 환경, Reentrancy(DAO), Batch Overflow, tx.origin 인증 우회, Flash Loan AMM 가격 조작, Web3 CLI(`forge`/`cast`/`solc`) 터미널 에뮬레이터 (포트: `8015`)
  - **Lab 16 (MemShield)**: 메모리 포렌식 & Volatility 3 분석 랩 (DKOM 숨김 프로세스 언링크, VAD RWX 셸코드 주입, 악성 C2 소켓 복원, LSASS NTLM 덤프 & LSA PPL 방어, 포트: `8016`)
  - **Lab 17 (KubeShield)**: 클라우드 네이티브 & Kubernetes 보안 랩 (특권 파드 탈출, RBAC 와일드카드 권한상승, 클라우드 IMDSv1 SSRF 탈취 및 IMDSv2 방어, Cosign 공급망 어드미션 제어, 포트: `8017`)
- **브라우저 터미널 워게임**: **총 31개 트랙 / 1,085문제** 달성 (`wargame/index.html`, HUD `0/1085`)
  - **PWA 및 오프라인 지원 완비**: `manifest.json`, `sw.js` 서비스 워커 적용 및 데스크톱/모바일 앱 설치 지원
  - **27번째 트랙**: `wasm` 🧩 WebAssembly 보안 (35개 문제: Tier 0~4)
  - **28번째 트랙**: `ebpf` 🐝 eBPF & Kernel Security (35개 문제: Tier 0~4)
  - **29번째 트랙**: `firmware` 💾 Firmware & Embedded Security (35개 문제: Tier 0~4)
  - **30번째 트랙**: `maldoc` 📑 문서형 악성코드 & PDF 포렌식 (35개 문제: Tier 0~4)
  - **31번째 트랙**: `volatility` 🧠 메모리 포렌식 & Volatility (35개 문제: Tier 0~4)
- **웹 뷰어 / 온라인 리더 포털 (Docsify 4.13.1)**:
  - Mermaid 10 실시간 다이어그램 렌더링, `docsify-copy-code` 코드 블록 복사, `docsify-pagination` 챕터 이동 네비게이션, `zoom-image` 이미지 확대
  - 상단 통합 포털 네비게이션 바 & 실습 랩/워게임 원클릭 연동 배너
- **표준 파이썬 패키징**: [pyproject.toml](file:///mnt/d/바이브해킹%20자료/vibe-hacking/pyproject.toml) 기반 패키징 완비 (`pip install -e .` 지원, 글로벌 `vhack` 명령 제공)
- **vhack CLI 고도화**:
  - `vhack doctor`: Python, Git, Docker, Compose, Node.js, 의존성 9종, 디스크, 포트 8000~8017 가용성 등 8개 영역 시스템 진단 도구
  - `vhack setup-docker`: OS 및 WSL2 환경 자동 감지, Docker CE / Compose 자동 설치 및 WSL2 연동 진단 가이드 (`--dry-run`, `-y`)
  - `vhack docs`: 75개 챕터 웹 리더 포털 로컬 HTTP 서버 실행
  - `vhack wargame`: 내장 웹서버 구동 및 브라우저 자동 실행
  - `vhack lab test [--all | <lab_id>]`: 17개 실습 랩 자동 무결성 검증 (124개 테스트)
  - `vhack lab status`: 17개 랩 종합 상태 대시보드
- **CI/CD 파이프라인**: [`.github/workflows/ci.yml`](file:///.github/workflows/ci.yml) (Labs 01~17, `vhack doctor`, Pytest 127개 랩 테스트, Wargame 4대 엄격 검증 스위트 자동화) 및 Docs 배포 워크플로우

---

## 2. 실습 랩(1~17) & 교재 & 워게임 연계 매트릭스

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

---

## 3. 핵심 검증 및 테스트 명령어 (Verification Suite)

코드나 문서, 워게임 수정 시 반드시 다음 검증 스위트를 통과해야 합니다:

```bash
# 1. 전체 단위/통합 테스트 (127개 테스트 전원 통과: Labs 01~17 및 HA DB 백업)
pytest

# 2. 실습 랩 CLI 자동 무결성 검증 (17개 랩 124개 테스트 통과)
python3 vhack.py lab test --all
# 또는 vhack이 설치된 경우:
vhack lab test --all

# 3. 환경 진단 검사 (8개 영역 100% 정상 확인)
vhack doctor

# 4. Docker 환경 진단 및 설정 가이드
vhack setup-docker --dry-run

# 5. 75개 챕터 웹 리더 포털 실행
vhack docs

# 6. 워게임 무결성 및 구조 검증 (1,085문제, 31트랙, 5티어)
node wargame/scripts/verify.js

# 7. 워게임 지문/힌트 간 교차 정답 노출(Leak) 스캔 (0건)
node wargame/scripts/leakscan.js

# 8. 워게임 채점 규칙 및 README 포맷 엄격 감사 ([A]~[J] 0결함)
node wargame/scripts/audit.js --strict

# 9. 연산/유도형 챌린지 118개 자동 풀이 검증 (118/118 통과)
node wargame/scripts/solve-derivable.js
```

---

## 4. 보안 및 Git 운영 지침 (Security & Operational Rules)

1. **민감 인증정보 보호**: Git 작업 시 토큰, 패스워드, SSH 개인키를 명령어 인자나 커밋 메시지, 코드에 절대 포함하지 마십시오. (`~/.netrc` 또는 git credential helper 사용)
2. **양방향 링크 무결성**: 교재 챕터(`06_*_lab.md`), `labs/README.md`, 각 랩의 `README.md` 간의 상대 링크와 워게임 트랙 표기가 항상 동기화되도록 유지하십시오.
3. **독립 테스트 환경 격리**: 실습 랩 테스트 작성 시 FastAPI 및 패키지 임포트 스코프 충돌을 방지하기 위해 dynamic import isolation 패턴을 준수하십시오.

---

## 5. 주요 마일스톤 이력 (Milestone History)

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

