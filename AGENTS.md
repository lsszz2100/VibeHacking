# VibeHacking Project Context & Agent Memory (AGENTS.md)

이 문서는 VibeHacking 저장소에서 작업하는 AI 에이전트를 위한 핵심 프로젝트 컨텍스트 및 영구 메모리입니다.

---

## 1. 프로젝트 개요 및 현재 상태 (Current Status)

- **교재 챕터**: 01~75개 종합 보안 챕터 완비 (다국어 지원: KO, EN, JA, ZH, 총 474개 챕터)
  - **21대 심층 인제스천 챕터 완비**:
    1. `02_Network_Hacking/07_practical_packet_analysis_deepdive.md` (Wireshark 심층 해부, 패킷 분석, DNS 터널링, TLS 복호화)
    2. `06_Malware_Analysis/08_advanced_pdf_maldoc_structure_analysis_deepdive.md` (PDF 바이너리 객체, OLE/CFBF 매크로, CVE-2017-11882, CVE-2021-40444, 힙 스프레이)
    3. `06_Malware_Analysis/09_python_malware_analysis_automation_deepdive.md` (파이썬 오픈소스 기반 정적/동적 악성코드 분석 자동화, pefile/peframe, Shannon 엔트로피 패킹 판별, YARA 시그니처 룰셋, Cuckoo 가상 샌드박스 API 후킹 및 안티 분석 회피 무력화)
    4. `07_Digital_Forensics/07_filesystem_forensics_deepdive.md` (FAT32/NTFS $MFT/EXT4 Inode 파일시스템 포렌식)
    5. `07_Digital_Forensics/08_advanced_volatility3_kernel_rootkit_deepdive.md` (EPROCESS/Pool Tag, DKOM 3단계 교차 검증, IRP 후킹, Volatility 3 커스텀 플러그인, Stuxnet/BlackEnergy2 루트킷 분석)
    6. `28_Mobile_Hacking/07_frida_android_dynamic_analysis_deepdive.md` (안드로이드 리버싱 & Frida 런타임 후킹)
    7. `03_System_Hacking/08_windows_seh_and_driver_exploit_deepdive.md` (Windows SEH 오버라이트 & 커널 취약 드라이버 익스플로잇)
    8. `09_Exploit_Techniques/07_practical_exploit_writing_corelan_deepdive.md` (Corelan 실전 바이너리 익스플로잇 개발 및 완화 기법 우회)
    9. `30_Vulnerability_Research/07_practical_fuzzing_and_crash_triage_deepdive.md` (AFL++ 커버리지 퍼징, ASAN 섀도우 메모리 UAF 분석, 크래시 트리아지 & 패치 검증)
    10. `44_Incident_Response_DFIR/07_soc_siem_threat_hunting_deepdive.md` (SOC 관제 아키텍처, Sysmon 텔레메트리, Suricata NIDS 룰셋, Splunk SPL/KQL 위협 헌팅 및 SOAR 플레이북)
    11. `56_AI_Red_Teaming/07_ai_red_teaming_and_guardrail_eval_deepdive.md` (간접 프롬프트 주입 IPI, BPE 토큰 분할 가드레일 우회, 악성 MCP 도구 섀도잉 및 커널 eBPF 샌드박싱)
    12. `15_WiFi_Hacking/07_practical_wpa3_sae_and_pmkid_deepdive.md` (무선 네트워크 보안 심층 해부: 802.11 4-Way Handshake, WPA2 PMKID 오프라인 크래킹, WPA3 SAE Dragonfly 동기식 핸드셰이크, Dragonblood 부채널 타이밍 누출 공격, Rogue AP Evil Twin 구성 및 802.11w PMF/BIP-CMAC 프레임 무결성 방어)
    13. `32_Network_Device_Hacking/07_cisco_ios_and_enterprise_l2_infrastructure_attack_deepdive.md` (Cisco IOS 아키텍처, SNMPv2c ciscoConfigCopyMIB R/W running-config 덤프 및 Type 7 크래킹, DTP 트렁크 스푸핑 및 802.1D STP Priority 0 Root Bridge 하이재킹, Enterprise L2 하드닝: Port-Security, DHCP Snooping, DAI, BPDU Guard, CoPP)
    14. `54_Active_Directory_Attacks/07_adcs_esc_and_kerberos_delegation_deepdive.md` (AD CS ESC1~ESC13 아키텍처 해부, Enrollee Supplies SAN 임의 주체 인증서 발급, Kerberos PKINIT TGT 획득 및 Pass-the-Certificate, RBCD S4U2self/S4U2proxy Delegation 체인, Protected Users 및 msDS-KeyCredentialLink 하드닝)
    15. `04_Reverse_Engineering/07_ghidra_advanced_deobfuscation_deepdive.md` (Ghidra Sleigh/P-Code IR, Headless 자동 분석, OLLVM CFF 제어 흐름 평탄화 상태 머신 해체, 불투명 술어 제거, 안티 탬퍼 체크섬 우회 및 인라인 바이너리 패칭)
    16. `05_Web_Hacking/07_advanced_oauth2_oidc_and_sso_exploitation_deepdive.md` (OAuth 2.0 RFC 6749 인가 프레임워크 해부, Redirect URI 정규식 미흡 우회, PKCE RFC 7636 S256 다운그레이드/생략 공격, JWT RS256 공개키 PEM을 HMAC HS256 비밀키로 오인하는 Key Confusion 및 임의 관리자 세션 하이재킹)
    17. `32_Network_Device_Hacking/08_bgp_route_hijacking_and_rpki_deepdive.md` (BGP-4 RFC 4271 프로토콜 해부, Best Path 알고리즘, Exact Prefix 및 Sub-prefix LPM 하이재킹, AS-Path 위조 및 RFC 7908 경로 누출, RPKI ROV/ASPA/MANRS/OTC 엔터프라이즈 다계층 방어)
    18. `41_Korean_Certifications/08_kisa_infrastructure_vulnerability_assessment_deepdive.md` (KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준, U-01~U-72 전수 점검 가이드, 자동화 스크립트 구조, /etc/shadow 계정 보안, 취약 xinetd 비활성화, eBPF 기반 런타임 무결성 감사)
    19. `33_OSINT_Social_Engineering/07_shodan_and_attack_surface_recon_deepdive.md` (Shodan/Censys/crt.sh 기반 EASM 외부 공격 표면 관리, DNS 서브도메인 탈취, 노출된 Spring Actuator/.env/Git/S3 버킷 침투 정찰 및 Zero Trust 인그레스 격리)
    20. `14_Cloud_Security/07_aws_iam_privilege_escalation_deepdive.md` (AWS IAM 21개 권한상승 벡터 심층 분석: PassRole, CreatePolicyVersion, SetDefaultPolicyVersion, AssumeRole 신뢰 관계 악용, IMDSv2 메타데이터 보안, SCP 가드레일 하드닝)
    21. `23_Database_Hacking/07_enterprise_rdbms_privilege_escalation_and_injection_deepdive.md` (엔터프라이즈 RDBMS 권한 상승 & 인젝션 심층 분석: Oracle AUTHID DEFINER 권한 상승, MSSQL xp_cmdshell OLE 자동화 RCE, MySQL UDF 악성 공유 라이브러리 로딩, PostgreSQL CVE-2019-9193, DBShield FGA 세분화 감사 및 secure_file_priv 하드닝)
  - **75개 전 챕터 웹 뷰어 / 온라인 리더 포털 구축**: Docsify 기반 다크 테마 웹 리더(`index.html`, `docs/`, `docs/vendor/` 오프라인 자산화 완비), `vhack docs [--port 3000]` 로컬 포털 CLI 완비
  - **75개 전 섹션 README.md 인덱스 동기화 완비**: [tools/sync_section_readmes.py](file:///mnt/d/바이브해킹%20자료/vibe-hacking/tools/sync_section_readmes.py)를 통한 자동 동기화
- **인터랙티브 실습 랩 (Docker Labs)**: **총 37개 실전 랩 완비** (`labs/01` ~ `labs/37`)
  - **Lab 19 (DroidShield)**: 안드로이드 리버싱 & Frida 후킹 랩 (루팅 탐지 우회, SSL Pinning 패치, Native 심볼 후킹, JNI Crypto 암호문 복호화, 포트: `8019`)
  - **Lab 20 (WinAppSec)**: 윈도우 바이너리 & 커널 드라이버 랩 (SEH 스택 오버라이트, SafeSEH/DEP/ASLR 회피, UAC 바이패스, HEVD IOCTL 임의 메모리 쓰기, Token Stealing 권한상승, 포트: `8020`)
  - **Lab 21 (CarCanLab)**: 차량 보안 & CAN Bus 실전 랩 (CAN 버스 패킷 스니핑/주입, 계기판 속도 스푸핑, UDS SecurityAccess 시드키 인증 우회, ECU hardReset DoS, 포트: `8021`)
  - **Lab 22 (APIGuard)**: API 보안 & Modern Auth 실전 랩 (REST BOLA/IDOR, BFLA 관리자 탈취, GraphQL Introspection & Batching, JWT 'none' 서명 우회, 포트: `8022`)
  - **Lab 23 (SOCHunter / BlueShield)**: SOC 관제, SIEM 규칙 탐지, EDR 위협 헌팅 랩 (Sysmon 원격 스레드 인젝션 탐지, Suricata NIDS 탐지 룰 작성, Splunk/KQL 상관분석 및 SOAR 격리 플레이북, 포트: `8023`)
  - **Lab 24 (FuzzMaster)**: 퍼징 & 취약점 분석 실전 랩 (AFL++ 커버리지 기반 퍼징, ASAN 섀도우 메모리 Heap-UAF 트리아지, CWE-416 재현 PoC 및 패치 검증, 포트: `8024`)
  - **Lab 25 (AIRedGuard)**: AI 레드팀 & 탈옥 방어 실전 랩 (간접 프롬프트 주입 IPI RAG 오염, BPE 토큰 분할 가드레일 우회, 악성 MCP 도구 섀도잉 및 샌드박싱, 포트: `8025`)
  - **Lab 26 (MalSandbox)**: 악성코드 자동 분석 & 동적 샌드박스 실전 랩 (PE Shannon 엔트로피 분석, IsDebuggerPresent PEB 패치, YARA 시그니처 룰셋 헌팅, Sleep 지연 가속 및 cuckoomon API 인터셉트 격리, 포트: `8026`)
  - **Lab 27 (WiFiShield)**: 무선 네트워크 & WPA3 SAE / PMKID 보안 실전 랩 (WPA2 RSN IE PMKID 무인증 추출 및 사전 공격, WPA3 SAE Dragonfly Commit/Confirm 부채널 익스플로잇 및 다운그레이드 공격, Rogue AP Evil Twin 피싱 및 802.11w PMF 관리 프레임 보호 방어, 포트: `8027`)
  - **Lab 28 (NetShield)**: 네트워크 인프라 & Cisco 스위치 보안 실전 랩 (Cisco IOS SNMPv2c R/W running-config 덤프 및 Type 7 크래킹, DTP Trunk Spoofing & 802.1D STP Priority 0 Root Bridge 하이재킹, Enterprise L2 하드닝: Port-Security/DHCP Snooping/DAI/BPDU Guard/CoPP, 포트: `8028`)
  - **Lab 29 (CertPwn / ADCSLab)**: Active Directory 인증서 서비스(AD CS) & Kerberos 위임 실전 랩 (ESC1 취약 템플릿 탐지, Enrollee Supplies SAN Administrator 인증서 위조 발급, PKINIT TGT 요청 및 Pass-the-Certificate 도메인 장악, S4U2self/RBCD 제약 위임 차단 및 Protected Users 그룹 적용, 포트: `8029`)
  - **Lab 30 (GhidraRev)**: 바이너리 역공학 & Ghidra 고급 난독화 해제 실전 랩 (심볼 복원, OLLVM 제어 흐름 평탄화(CFF) 상태 머신 디플래트닝, 인라인 NOP/JMP 패칭, .text 런타임 체크섬 우회 및 섀도우 메모리 하드닝, 포트: `8030`)
  - **Lab 31 (SSOShield)**: OAuth 2.0 & OIDC SSO 취약점 실전 랩 (Redirect URI 정규식 우회 및 인가 코드 도청, PKCE S256 다운그레이드/생략 인가 코드 주입, JWT RS256 공개키를 HS256 HMAC 비밀키로 오인시키는 Key Confusion 공격 및 임의 관리자 세션 장악, 포트: `8031`)
  - **Lab 32 (BGPRouteGuard)**: BGP 라우팅 하이재킹 & RPKI ROA 실전 랩 (BGP-4 Exact Prefix 하이재킹, Sub-prefix LPM 최장 일치 공격, AS-Path 위조 및 피어 간 경로 누출, RPKI ROV/Prefix MaxLength/MANRS/OTC 다계층 하드닝, 포트: `8032`)
  - **Lab 33 (KISAShield)**: KISA 주요정보통신기반시설 취약점 평가 & 리눅스/서버 하드닝 랩 (U-01 root 직접 접속 제한, U-02/U-03 패스워드 복잡도 및 암호화 관리, U-10 xinetd 비활성화, U-23 DoS 취약 서비스 차단, U-44 SSH 안전 암호화 통신, eBPF 런타임 보안 무결성 감사, 포트: `8033`)
  - **Lab 34 (OSINTHunter)**: OSINT 서피스 정찰 & 섀도우 IT 헌터 랩 (WHOIS/DNS/crt.sh 정보 수집, Shodan/Censys 배너 및 취약 포트 정찰, Dangling S3 버킷 및 서브도메인 테이크오버 탐지, 노출된 Spring Actuator 환경변수/Git 리포지토리/Secret 카빙, 포트: `8034`)
  - **Lab 35 (CloudIAMGuard)**: 클라우드 IAM 권한 상승 & 조직 거버넌스 랩 (IAM 와일드카드 정책 및 PassRole 권한상승, AssumeRole 교차 계정 신뢰 악용 Confused Deputy 공격, IMDSv1 vs IMDSv2 토큰 방어, SCP 서비스 제어 정책 및 최소 권한 롤 하드닝, 포트: `8035`)
  - **Lab 36 (DBShield)**: 엔터프라이즈 데이터베이스 보안 & 권한 탈취/하드닝 랩 (MySQL UDF RCE 방지, MSSQL xp_cmdshell 비활성화, Oracle AUTHID DEFINER 권한 상승 탐지, PostgreSQL CVE-2019-9193, DBShield FGA 세분화 감사 및 secure_file_priv 하드닝, 포트: `8036`)
  - **Lab 37 (BLEShield)**: 블루투스 저에너지 & SDR 무선 보안 실전 랩 (BLE GATT 계층 모델 정찰, 비인가 특성 쓰기, SDR RF OOK/ASK 스펙트럼 복조, 고정 Nonce Replay 공격 및 암호학적 하드닝, 포트: `8037`)
- **브라우저 & 터미널 워게임**: **총 51개 트랙 / 1,785문제** 달성 (`wargame/index.html`, HUD `0/1785`, `vhack play`)
  - **터미널 네이티브 워게임 클라이언트 (`vhack play`)**: 51개 트랙 로드맵, 문제 검색, 지문/힌트 열람, 플래그 제출 및 로컬 진행도(`~/.vhack_wargame_progress.json`) 자동 저장 완비
  - **PWA 및 오프라인 지원 완비**: `manifest.json`, `sw.js` 서비스 워커 적용 및 데스크톱/모바일 앱 설치 지원
  - **워게임 UX 기능 고도화**: 진행도 JSON 파일 백업/복원(`export json`, `import [file]`, 💾/📂 버튼), 10대 요원 업적/뱃지 시스템(`badges` 명령어, 🏆 HUD 버튼 및 모달 팝업, CRT 토스트 알림) 완비
  - **워게임 7대 인터랙티브 보안 플레이그라운드**: 차량 CAN 버스 주입기, SQLi AST 구문트리, AD CS X.509/Kerberos 인스펙터, JWT none 검증기, KISA 기반시설 점검기, OSINT 정찰 레이더, DB RBAC & UDF Shield
  - **신규 51번째 트랙 완비**:
    - `blehack` 📡 블루투스 저에너지 & SDR RF 해킹 (35개 문제: Tier 0~4)
  - **4대 엄격 검증 스위트 100% All Green**: `verify.js`, `audit.js --strict` (0결함), `leakscan.js` (0유출), `solve-derivable.js` (818/1785 통과)
- **통합 웹 관제 대시보드 (Portal)**:
  - `portal/server.py`, `portal/static/index.html` 기반 실시간 랩 제어(36개 랩 시작/중지/재시작), 12대 카테고리 필터링 탭 바 및 일괄 가동/정지 지원, 웹 셸 콘솔(`💻 셸`), 실시간 컨테이너 로그 스트리밍(`📜 로그`), PoC 익스플로잇 솔루션 뷰어(`💡 솔루션`), 자원 모니터링 (`vhack portal [--port 8800]`)
- **실습 랩 자동 익스플로잇 솔버 (Solvers)**:
  - `labs/solvers.py`, `labs/tests/test_lab_solvers.py`: 36개 전체 랩의 1~3단계 PoC 익스플로잇, 취약점 원리, 방어 대책 솔버 완비 및 CLI (`vhack solve <lab_id>`, `vhack lab solve <lab_id> [--step N]`)
- **CTF 대회 스코어보드 & 채점 엔진 (CTF)**:
  - `ctf/server.py`, `ctf/tests/test_ctf.py`: 71개 랩 플래그 풀, 순차 해금 모드(Progressive Unlock) 지원, 💡 인터랙티브 힌트 상점 모달 UI 및 점수 차감 시스템 (`POST /api/ctf/hints/unlock`), First Blood 알림 및 +50pt 보너스, Dynamic Scoring 감쇠 공식, HTML5 실시간 점수 추이 시계열 그래프, 실시간 SSE 스트리밍 (`vhack ctf [--port 8888]`)
- **오프라인 번들러 및 릴리스 배포 파이프라인 (Bundler & Release)**:
  - `tools/bundle_offline.py`, `tools/verify_offline_deployment.sh`, `release/SHA256SUMS` 및 `vhack bundle [--tar <path>]` 통한 36개 랩, 50개 트랙(1,750문제), 75개 교재, 로컬 CDN 벤더 자산 전수 무결성 검증, SHA-256 검증 및 배포 아카이브(`release/vibehacking-v2.0.0.tar.gz`) 생성 지원
- **vhack CLI 고도화**:
  - `vhack play`: 50개 트랙 1,750문제 터미널 네이티브 워게임 클라이언트 (목록/검색/풀이/진행도 관리)
  - `vhack logs <lab_id> [-f] [-n N]`: 실습 랩 컨테이너 실시간 로그 스트리밍 단독 명령어 지원
  - `vhack solve`: 36개 실습 랩의 단계별 취약점 익스플로잇 자동 시뮬레이션 및 플래그 획득
  - `vhack doctor`: Python, Git, Docker, Compose, Node.js, 의존성 9종, 디스크, 포트 8000~8036 가용성 등 시스템 진단
  - `vhack lab test [--all | <lab_id>]`: 36개 실습 랩 자동 무결성 검증 (334개 테스트 All Green)
  - `vhack lab status`: 36개 랩 종합 상태 대시보드
- **CI/CD 파이프라인**: [`.github/workflows/ci.yml`](file:///.github/workflows/ci.yml) (Labs 01~36, `vhack doctor`, Pytest 전체 361개 테스트 All Green, Wargame 4대 엄격 검증 스위트 자동화) 및 Docs 배포 워크플로우

---

## 2. 실습 랩(01~36) & 교재 & 워게임 연계 매트릭스

| 랩 ID | 랩 이름 | 주요 침투/방어 주제 | 연계 교재 챕터 | 워게임 트랙 | 실행 명령 |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
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
| **21** | 차량 보안 & CAN Bus 랩 (CarCanLab) | CAN 버스 스푸핑, UDS 시드-키 인증 우회, ECU DoS | `37_ICS_SCADA`, `61_Firmware_Hacking`, `63_OT_ICS_Advanced` | `carcan` | `vhack lab start 21` |
| **22** | API 보안 & 현대적 인증 랩 (APIGuard) | BOLA/IDOR 수평 권한상승, BFLA 수직 권한상승, GraphQL Introspection, JWT alg: none 서명 우회 | `05_Web_Hacking`, `18_DevSecOps` | `apisec` | `vhack lab start 22` |
| **23** | SOC 위협 헌팅 & SIEM 랩 (SOCHunter) | Sysmon 원격 스레드 인젝션 탐지, Suricata NIDS 룰셋, Splunk/KQL 위협 헌팅, SOAR 격리 | `44_Incident_Response_DFIR` | `sochunt` | `vhack lab start 23` |
| **24** | 퍼징 & 취약점 분석 실전 랩 (FuzzMaster) | AFL++ 커버리지 기반 퍼징, ASAN 섀도우 메모리 Heap-UAF 트리아지, CWE-416 재현 PoC 및 패치 검증 | `30_Vulnerability_Research`, `66_Exploit_Development`, `74_Code_Auditing` | `fuzzing` | `vhack lab start 24` |
| **25** | AI 레드팀 & 탈옥 방어 랩 (AIRedGuard) | 간접 프롬프트 주입 IPI, BPE 토큰 분할 가드레일 우회, 악성 MCP 도구 섀도잉 및 샌드박싱 | `11_AI_Powered_Security`, `56_AI_Red_Teaming`, `69_LLM_Security` | `airedteam` | `vhack lab start 25` |
| **26** | 악성코드 자동 분석 & 동적 샌드박스 랩 (MalSandbox) | PE 엔트로피 분석, IsDebuggerPresent 패치, YARA 룰셋 헌팅, Sleep 지연 가속 및 API 후킹 | `06_Malware_Analysis`, `45_Malware_Development` | `malsandbox` | `vhack lab start 26` |
| **27** | 무선 네트워크 & WPA3 랩 (WiFiShield) | WPA2 PMKID 오프라인 사전 공격, WPA3 SAE Dragonfly 다운그레이드/부채널 타이밍 공격, Evil Twin 피싱 및 802.11w PMF 방어 | `15_WiFi_Hacking` | `wifisec` | `vhack lab start 27` |
| **28** | 네트워크 인프라 & Cisco 스위치 랩 (NetShield) | Cisco IOS SNMPv2c R/W running-config 덤프 및 Type 7 크래킹, DTP Trunk Spoofing & STP Root Bridge 탈취, Enterprise L2 하드닝 | `32_Network_Device_Hacking` | `netinfra` | `vhack lab start 28` |
| **29** | AD CS & Kerberos 위임 랩 (CertPwn) | ESC1 SAN 스푸핑, PKINIT Pass-the-Certificate, S4U2proxy/RBCD 위임, Protected Users 하드닝 | `54_Active_Directory_Attacks` | `adcs` | `vhack lab start 29` |
| **30** | 바이너리 분석 & Ghidra 난독화 해제 랩 (GhidraRev) | 심볼 복원, OLLVM CFF 디플래트닝, 인라인 바이너리 패칭, 자체 무결성 체크섬 우회 | `04_Reverse_Engineering` | `ghidra` | `vhack lab start 30` |
| **31** | OAuth 2.0 & OIDC SSO 랩 (SSOShield) | Redirect URI 우회, PKCE 다운그레이드/생략, JWT RS256/HS256 Key Confusion 관리자 토큰 위조 | `05_Web_Hacking` | `oauth` | `vhack lab start 31` |
| **32** | BGP 라우팅 & RPKI ROA 랩 (BGPRouteGuard) | BGP-4 Exact/Sub-prefix LPM 하이재킹, AS-Path 위조 & 경로 누출, RPKI ROV/MANRS/OTC 하드닝 | `32_Network_Device_Hacking` | `bgp` | `vhack lab start 32` |
| **33** | KISA 기반시설 취약점 평가 & 하드닝 랩 (KISAShield) | root 접속 제한(U-01), 패스워드 정책(U-02), xinetd 비활성화(U-10), DoS 서비스 차단(U-23), SSH 보안(U-44), eBPF 무결성 감사 | `41_Korean_Certifications` | `kisa` | `vhack lab start 33` |
| **34** | OSINT 서피스 정찰 & 섀도우 IT 랩 (OSINTHunter) | WHOIS/DNS/crt.sh 정보 수집, Shodan/Censys 배너 분석, Dangling S3 탈취, Spring Actuator/Git/Secret 헌팅 | `33_OSINT_Social_Engineering` | `osintrecon` | `vhack lab start 34` |
| **35** | 클라우드 IAM 권한상승 & 거버넌스 랩 (CloudIAMGuard) | IAM 와일드카드 PassRole 권한상승, AssumeRole 교차 계정 신뢰 악용 Confused Deputy, IMDSv2 방어, SCP 가드레일 하드닝 | `14_Cloud_Security` | `cloudiam` | `vhack lab start 35` |
| **36** | 엔터프라이즈 DB 보안 랩 (DBShield) | MySQL UDF RCE 방지, MSSQL xp_cmdshell 비활성화, Oracle AUTHID DEFINER 권한 상승 탐지, DBShield FGA/secure_file_priv 하드닝 | `23_Database_Hacking` | `dbsec` | `vhack lab start 36` |

---

## 3. 핵심 검증 및 테스트 명령어 (Verification Suite)

코드나 문서, 워게임 수정 시 반드시 다음 검증 스위트를 통과해야 합니다:

```bash
# 1. 전체 단위/통합 테스트 (361개 테스트 전원 통과: Labs 01~36, Solvers, Portal, CTF, Wargame CLI)
pytest -q

# 2. 실습 랩 CLI 자동 무결성 검증 (36개 랩 334개 테스트 통과)
python3 vhack.py lab test --all
# 또는 vhack이 설치된 경우:
vhack lab test --all

# 3. 환경 진단 검사 (8개 영역 100% 정상 확인, 36개 랩 포트 충돌 검사 완비)
vhack doctor

# 4. 오프라인 패키징 및 무결성 전수 검사
python3 tools/bundle_offline.py --check-only

# 5. 오프라인 릴리스 배포 자동 스모크 테스트 (7단계 완전 오프라인 검증 및 SHA256 체크섬)
bash tools/verify_offline_deployment.sh

# 6. Docker 환경 진단 및 설정 가이드
vhack setup-docker --dry-run

# 7. 75개 챕터 웹 리더 포털 실행
vhack docs

# 8. 통합 웹 관제 대시보드 실행 (127.0.0.1 기본 안전 바인딩)
vhack portal

# 9. 모의해킹 대회 스코어보드 & Progressive Unlock 엔진 실행 (힌트 상점 완비)
vhack ctf

# 10. 36개 실습 랩 자동 익스플로잇 솔버 실행
vhack solve 01 --step 1

# 11. 워게임 무결성 및 구조 검증 (1,750문제, 50트랙, 5티어)
node wargame/scripts/verify.js

# 12. 워게임 지문/힌트 간 교차 정답 노출(Leak) 스캔 (0건)
node wargame/scripts/leakscan.js

# 13. 워게임 채점 규칙 및 README 포맷 엄격 감사 ([A]~[J] 0결함)
node wargame/scripts/audit.js --strict

# 14. 워게임 텍스트 유도 가능 문제 솔버 전수 검증 (783/1750 통과)
node wargame/scripts/solve-derivable.js
```

---

## 4. 작업 윤리 및 필수 검증 철칙 (Integrity, Mandatory Verification & Operational Rules)

1. **허위 보고 절대 금지 (Zero Tolerance for False / Fabricated Reporting)**:
   - 실제로 수행하지 않은 작업, 실행하지 않은 명령어나 테스트 결과를 "완료했다"고 허위 보고하거나 추측으로 결과를 보고하는 행위를 엄격히 금지합니다.
   - 모든 보고는 반드시 실제 실행 결과(CLI 출력, exit code, 로그)를 기반으로만 작성되어야 합니다.
2. **실검증(Actual Execution) 필수**:
   - 코드, 설정, 문서, 테스트 작성 및 수정 후에는 반드시 해당 명령어(`pytest`, `node verify.js`, `node audit.js --strict`, `node leakscan.js`, `vhack` CLI 등)를 직접 실행하여 정상 동작 여부와 에러 유무를 확인해야 합니다. "통과될 것이다"라는 추측성 보고는 금지됩니다.
3. **교차 검증(Cross-Verification) 필수**:
   - 상호 연관된 모듈 간의 무결성을 반드시 교차 검증해야 합니다. (교재 챕터 ↔ 실습 랩 README ↔ `labs/solvers.py` ↔ `ctf/server.py` ↔ `portal/server.py` ↔ `wargame/assets/challenges.js` ↔ `vhack.py` 간의 메타데이터, 포트 번호, 플래그, 상대 링크 불일치 전수 확인)
4. **보안 검증(Security Verification) 필수**:
   - 로컬 웹 서비스 루프백(`127.0.0.1`) 바인딩, 웹 셸 실행 시 Path Traversal 및 위험 명령어 차단 필터, API 파라미터 경계값 검증, Git 토큰 및 API 키/비밀번호 노출 원천 차단(`chmod 600` 관리) 등 시큐어 코딩 및 보안 원칙을 사전에 필수로 검증해야 합니다.
5. **기능 테스트 & 버그 테스트 필수 (Functional & Edge-Case Bug Testing)**:
   - 정상 케이스뿐만 아니라 비정상 입력값, 경계값(Boundary conditions), 예외 처리, 동시성/포트 충돌 등 잠재적 버그를 검증하는 테스트 케이스를 필수로 작성하고 실행해야 합니다.
6. **지속적인 리팩토링(Continuous Refactoring) 필수**:
   - 기능 구현 완료에 그치지 않고, 코드 중복 제거, 모듈화, 네이밍 개선, 성능 최적화, 불필요한 레거시 정리 등 코드 품질 개선을 항상 수반해야 합니다.
7. **민감 인증정보 보호**: Git 작업 시 토큰, 패스워드, SSH 개인키를 명령어 인자나 커밋 메시지, 코드에 절대 포함하지 마십시오. (`~/.netrc` 또는 git credential helper 사용)
8. **양방향 링크 무결성**: 교재 챕터(`06_*_lab.md`), `labs/README.md`, 각 랩의 `README.md` 간의 상대 링크와 워게임 트랙 표기가 항상 동기화되도록 유지하십시오.
9. **독립 테스트 환경 격리**: 실습 랩 테스트 작성 시 FastAPI 및 패키지 임포트 스코프 충돌을 방지하기 위해 dynamic import isolation 패턴을 준수하십시오.
10. **로컬 서비스 보안 바인딩**: 개발/관리 웹 서버(`portal`, `ctf`)는 RCE 위험을 차단하기 위해 기본적으로 루프백 인터페이스(`127.0.0.1`)에 바인딩하며, 웹 셸 실행 시 경로 이탈(Path Traversal) 검증 및 파괴적 시스템 명령어 방어 필터를 필수로 적용합니다.

---

## 5. 주요 마일스톤 이력 (Milestone History)

- **2026-10-02 (Option 1~4 Complete: Lab 36 DBShield, Deepdive 21 Ingestion, Wargame Track 50 dbsec 1,750 Milestone, 7th Simulator DB RBAC, CTF Progressive Unlock & Portal Category Dashboard, 361 Tests All Green, Offline Bundle v2.0.0 Sync)**:
  - **Lab 36 엔터프라이즈 데이터베이스 보안 랩 신규 구축 (`labs/36_enterprise_database_security_lab/`)**:
    - MySQL UDF RCE 방지, MSSQL xp_cmdshell 비활성화, Oracle AUTHID DEFINER 권한 상승 탐지, PostgreSQL CVE-2019-9193, DBShield FGA 세분화 감사 및 secure_file_priv 하드닝 (포트 8036, 15개 단위/통합 테스트 전원 통과)
  - **심층 교재 21편 인제스천 완성**:
    - 21. `23_Database_Hacking/07_enterprise_rdbms_privilege_escalation_and_injection_deepdive.md` (Oracle AUTHID DEFINER, MSSQL OLE RCE, MySQL UDF 악성 라이브러리, PostgreSQL CVE-2019-9193, DBShield FGA/Audit Vault)
  - **워게임 50번째 트랙 (`dbsec`) 확장 및 1,750문제 대기록 달성**:
    - 35개 문제 추가 (총 50개 트랙, 1,750개 챌린지)
    - 4대 엄격 검증 스위트 All Green: `verify.js` (1,750제 50트랙 5티어), `audit.js --strict` ([A]~[J] 0결함), `leakscan.js` (0유출, 0 stale), `solve-derivable.js` (783/1,750 통과)
  - **워게임 7번째 인터랙티브 보안 시뮬레이터 구축 (`DB RBAC & UDF Shield`)**:
    - MySQL UDF RCE, MSSQL xp_cmdshell, Oracle AUTHID DEFINER, DBShield FGA/secure_file_priv 4대 시나리오 실시간 모의 실행 및 패치 시각화
    - HUD 🔬 모달, 빠른 칩 및 명령어(`dbsec`, `dbshield`, `udf`) 완비
  - **CTF 순차 해금 모드(Progressive Unlock) 구축**:
    - `ctf/server.py`: 17개 실습 세트 단계별 해금 체인, 하위 단계 미해결 시 상위 플래그 제출 차단(403 Forbidden), 71개 플래그 풀
  - **웹 관제 포털 대시보드 36개 랩 12대 카테고리 고도화**:
    - `portal/server.py`, `portal/static/index.html`: 12개 카테고리별 필터 바, 카테고리별/전체 일괄 가동·정지(batch start/stop), 11개 단위 테스트 전원 통과
  - **전 플랫폼 연동 및 전체 361개 테스트 100% All Green**:
    - `pytest -q`: **361 passed** (Labs 01~36 334개 + solvers 4개 + portal 11개 + ctf 8개 + wargame cli 4개)
    - `vhack lab test --all`: 36개 랩 334개 테스트 전원 통과
    - `vhack doctor`: 포트 8000~8036 정밀 진단 및 36개 랩 전수 연동
    - `bundle_offline.py` & `verify_offline_deployment.sh`: 7단계 스모크 테스트 100% 통과

- **2026-10-01 (Labs 33-35, Wargame 49 Tracks / 1,715 Challenges Milestone, 3 Deepdive Ingestions, 342 Tests All Green, Offline Bundle v2.0.0 Sync)**:
  - **Lab 33~35 신규 3개 실전 랩 구축 완료 (`labs/33_kisa_infrastructure_audit_lab/`, `labs/34_osint_surface_recon_lab/`, `labs/35_cloud_iam_privilege_escalation_lab/`)**:
    - Lab 33: KISA 주요정보통신기반시설 취약점 평가 & 서버 하드닝 랩 (U-01~U-72 점검, eBPF 런타임 감사, 포트 8033, 11개 단위 테스트 통과)
    - Lab 34: OSINT 공격 표면 및 섀도우 IT 헌터 랩 (Shodan/Censys 배너 분석, Dangling S3/Actuator 헌팅, 포트 8034, 12개 단위 테스트 통과)
    - Lab 35: 클라우드 IAM 권한상승 & 거버넌스 랩 (IAM 와일드카드, PassRole, AssumeRole, IMDSv2 방어, 포트 8035, 11개 단위 테스트 통과)
  - **3대 신규 심층 교재 챕터 인제스천 (총 20대 심층 챕터 완비)**:
    - 18. `41_Korean_Certifications/08_kisa_infrastructure_vulnerability_assessment_deepdive.md`
    - 19. `33_OSINT_Social_Engineering/07_shodan_and_attack_surface_recon_deepdive.md`
    - 20. `14_Cloud_Security/07_aws_iam_privilege_escalation_deepdive.md`
  - **워게임 신규 3개 트랙 (`kisa`, `osintrecon`, `cloudiam`) 확장 및 1,715문제 마일스톤**:
    - 105문제 추가 (총 49개 트랙, 1,715개 챌린지)
    - 4대 엄격 검증 스위트 All Green: `verify.js` (1,715제), `audit.js --strict` (0결함), `leakscan.js` (0유출), `solve-derivable.js` (748/1,715)
  - **35개 랩 통합 연동**:
    - `labs/solvers.py`: 35개 전체 랩 자동 익스플로잇 PoC 솔버 완비
    - `ctf/server.py`: 68개 플래그 풀 및 힌트 연동
    - `portal/server.py`: 35개 랩 제어 및 자원 모니터링 연동
    - `vhack doctor`: 포트 8000~8035 정밀 진단
    - `pytest -q`: **342 passed** (전수 통과)
    - `vhack lab test --all`: 35개 랩 319개 테스트 100% All Green

- **2026-09-30 (Labs 30-32, Wargame 46 Tracks / 1,610 Challenges Milestone, 3 Deepdive Ingestions, 308 Tests All Green)**:
  - **Lab 30~32 실전 랩 구축 (`labs/30_ghidra_advanced_deobfuscation_lab/`, `labs/31_oauth_oidc_sso_lab/`, `labs/32_bgp_route_hijacking_lab/`)**:
    - Lab 30 (GhidraRev): Ghidra 고급 난독화 해제 & OLLVM CFF 디플래트닝 (포트 8030)
    - Lab 31 (SSOShield): OAuth 2.0 & OIDC SSO 취약점 실전 랩 (포트 8031)
    - Lab 32 (BGPRouteGuard): BGP-4 라우팅 하이재킹 & RPKI ROA 랩 (포트 8032)
  - **3대 심층 교재 챕터 인제스천**:
    - 15. `04_Reverse_Engineering/07_ghidra_advanced_deobfuscation_deepdive.md`
    - 16. `05_Web_Hacking/07_advanced_oauth2_oidc_and_sso_exploitation_deepdive.md`
    - 17. `32_Network_Device_Hacking/08_bgp_route_hijacking_and_rpki_deepdive.md`
  - **워게임 트랙 확장 (`ghidra`, `oauth`, `bgp`) 및 1,610문제 마일스톤**
  - **전체 308개 테스트 통과**

- **2026-09-29 (Option 1~3 Complete: Lab 29 CertPwn, Wargame Track 43 adcs 1,505 Milestone, Interactive Security Playground, Offline Release v2.0.0 Pipeline, 250 Tests All Green, Remote Sync)**:
  - **Lab 29 CertPwn 신규 구축 (`labs/29_adcs_kerberos_delegation_lab/`)**: AD CS ESC1 취약 템플릿 탐지, Enrollee Supplies SAN Administrator 인증서 위조 발급, PKINIT TGT 요청 및 Pass-the-Certificate 도메인 장악, RBCD/S4U2proxy 위임 차단 및 Protected Users 그룹 하드닝 (포트 8029, 17개 단위/통합 테스트 전원 통과, 127.0.0.1 루프백 안전 바인딩)
  - **대용량 미분류 자료 인제스천 (AD CS & Kerberos 위임 심층 분석)**:
    - `54_Active_Directory_Attacks/07_adcs_esc_and_kerberos_delegation_deepdive.md` (ESC1~ESC13 아키텍처 해부, SAN 변조, PKINIT 흐름, UnPAC-the-Hash, RBCD msDS-AllowedToActOnBehalfOfOtherIdentity, Protected Users 및 msDS-KeyCredentialLink 하드닝)
    - `tools/sync_section_readmes.py` 전 섹션 동기화 완료
  - **워게임 43번째 트랙 (`adcs`) 확장 및 1,505문제 마일스톤**: AD CS, ESC1~ESC13, PKINIT, UnPAC-the-Hash, Kerberos RBCD/S4U, Protected Users 등을 포괄하는 35개 문제 추가로 1,470제 → 1,505제 확장 완료, 4대 엄격 무결성 검증 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js` 538/1505) 전원 0결함 완벽 통과
  - **워게임 인터랙티브 보안 플레이그라운드 & 시뮬레이터 모달 구축 (`wargame/assets/app.js`, `wargame/index.html`, `wargame/assets/style.css`)**:
    1. 🚗 CAN Bus Injector & Telemetry Simulator: 차량 속도계/RPM 게이지 시뮬레이션 및 프레임 주입/프리셋(Cruise, Over-speed, UDS, DoS)
    2. 💉 SQLi AST 구문트리 실시간 시각화기: 취약 Raw SQL(연산자 하이재킹 `OR 1=1`) vs 안전한 Prepared Statement AST 비교
    3. 🪪 AD CS / Kerberos ASN.1 인스펙터: X.509 ASN.1 Certificate(Subject, SAN, EKU) 구조 파싱, PKINIT TGT 요청 및 PAC 도메인 관리자 권한 진단
    4. 🔑 JWT None Algorithm 서명 우회 테스터: 실시간 Header/Payload/Signature 인코딩, `alg: none` 서명 우회 및 `role: admin` 권한상승 시뮬레이션
    - HUD 🔬 버튼, 빠른 커맨드 칩, 터미널 명령어(`playground`, `sim`, `can`, `sqli`, `adcs`, `jwt`) 완비
  - **완전 오프라인 릴리스 배포 및 스모크 테스트 파이프라인 (`release/`, `tools/bundle_offline.py`, `tools/verify_offline_deployment.sh`)**:
    - `bundle_offline.py`: 4대 하위 시스템 무결성 전수 검증 및 아카이브(`release/vibehacking-v2.0.0.tar.gz`, 7.01 MB) 생성, SHA-256 자동 계산 및 `release/SHA256SUMS` 기록
    - `verify_offline_deployment.sh`: 체크섬 무결성, 오프라인 벤더 에셋, 파이썬 컴파일, 워게임 자바스크립트 구문, 번들 무결성, 워게임 검증, CLI 스모크 테스트 7단계 자동 검증 스크립트 구축
  - **전 플랫폼 연동 및 전체 250개 테스트 100% All Green**:
    - `pytest -q`: **250 passed** (Labs 01~29 17개 단위 테스트 포함, solvers 4개, portal 8개, ctf 7개, wargame cli 4개)
    - `vhack doctor`: 포트 8000~8029 진단 및 29개 랩 전수 연동
    - `vhack solve`: 29개 실습 랩 자동 익스플로잇 솔버 연동
    - `ctf/server.py`: 50개 랩 플래그 풀 및 힌트 연동
  - **작업 윤리 및 검증 철칙 엄수**: 무관용 허위 보고 배제, 실검증(CLI 출력 증거 기반), 교차 검증, 보안 검증(127.0.0.1 기본 바인딩), 기능/버그 테스트 및 리팩토링 전수 준수
  - **원격 저장소 동기화**: `main` 브랜치 커밋(`aace4a0`) 원격 저장소(`https://github.com/lsszz2100/VibeHacking.git`) 푸시 완료

- **2026-09-28 (Lab 28 NetShield, Wargame 42 Tracks / 1,470 Challenges Milestone, Cisco IOS & Enterprise L2 Deepdive, 233 Tests All Green)**:
  - **Lab 28 네트워크 인프라 & Cisco 스위치 랩 신규 구축 (`labs/28_network_infra_lab/`)**: Cisco IOS SNMPv2c R/W running-config 덤프 및 Type 7 크래킹, DTP Trunk Spoofing & 802.1D STP Priority 0 Root Bridge 하이재킹, Enterprise L2 하드닝 (Port-Security, DHCP Snooping, DAI, BPDU Guard, CoPP), 포트 8028, 14개 단위 테스트 전원 통과
  - **교재 13번째 심층 챕터**: `32_Network_Device_Hacking/07_cisco_ios_and_enterprise_l2_infrastructure_attack_deepdive.md`
  - **워게임 42번째 트랙 (`netinfra`) 확장 및 1,470문제 마일스톤 달성**
  - **전체 233개 테스트 100% 통과**

- **2026-09-27 (Lab 27 WiFiShield, Wargame 41 Tracks / 1,435 Challenges Milestone, WPA3 SAE / PMKID Deepdive, 219 Tests All Green, Safe GitHub Remote Sync)**:
  - **Lab 27 무선 네트워크 & WPA3 보안 실전 랩 신규 구축 (`labs/27_wifi_wpa3_security_lab/`)**:
    - WPA2 RSN IE PMKID 무인증 추출 및 오프라인 사전 공격 (`FLAG{WPA2_PMKID_ROAMING_KEY_CRACKED_7721}`)
    - WPA3 SAE Dragonfly 동기식 핸드셰이크 부채널 타이밍 공격 & 다운그레이드 (`FLAG{WPA3_SAE_DRAGONFLY_SIDECHANNEL_PWN_8819}`)
    - Rogue AP Evil Twin 피싱 탐지 및 802.11w PMF (BIP-CMAC) 관리 프레임 무결성 방어 (`FLAG{80211W_PMF_MANAGEMENT_FRAME_PROTECTION_SECURED_9934}`)
    - 포트 `8027`, 9개 단위 테스트 전원 통과 (`test_wifi_security_lab.py`)
  - **컴포넌트 풀체인 27개 랩 연동**:
    - `labs/solvers.py`: Lab 27 PMKID/SAE/PMF 3단계 PoC 자동 솔버 및 27개 랩 테스트 통과
    - `ctf/server.py`: `LAB27_PMKID`, `LAB27_SAE`, `LAB27_MFP` 플래그 풀(총 44개) 및 💡 힌트 상점 아이템 연동
    - `portal/server.py` & UI: 27개 랩 제어 및 카운트 동기화
    - `vhack.py`: `LABS_METADATA` 27번 등록 및 `doctor` 포트 8027 가용성 진단
    - `labs/start_lab.sh` & `labs/stop_all.sh`: 27개 랩 제어 스크립트 확장
  - **워게임 41번째 트랙 (`wifisec`) & 1,435문제 마일스톤 달성**:
    - 무선 802.11 정찰, WPA2/WPA3 침투, Dragonfly 부채널, Evil Twin, 802.11w PMF 등을 포괄하는 35개 문제 (Tier 0~4) 완비
    - `wargame/assets/challenges.js`, `wargame/index.html` (HUD `0/1435`, 41 tracks)
    - 4대 엄격 무결성 검증 스위트 100% All Green:
      - `node wargame/scripts/verify.js`: 1,435문제 41개 트랙 5티어 구조 무결성 통과
      - `node wargame/scripts/audit.js --strict`: [A]~[J] 10대 검사 전 항목 0결함 통과
      - `node wargame/scripts/leakscan.js`: 0 leaks 통과 (전문 도메인 allowlist 19건 등록)
      - `node wargame/scripts/solve-derivable.js`: 468/1435 솔버 자동 풀이 100% 검증
  - **보안 자료 심층 인제스천**:
    - `15_WiFi_Hacking/07_practical_wpa3_sae_and_pmkid_deepdive.md` 12번째 심층 교재 챕터 신규 집필 완성
    - `tools/sync_section_readmes.py`: 75개 전 섹션 README 동기화 완료
  - **오프라인 배포 번들 동기화**:
    - `tools/bundle_offline.py` 및 `vhack bundle`: 27개 랩, 41개 트랙(1,435제), 75개 교재(465개 챕터), 오프라인 벤더 에셋 무결성 검증 통과
  - **전체 219개 테스트 100% 통과**:
    - `pytest -q`: **219 passed in 45s** (Labs 01~27 196개 + solvers 4개 + portal 8개 + ctf 7개 + wargame cli 4개)
    - `vhack lab test --all`: 27개 실습 랩 196개 테스트 전원 통과
  - **안전한 GitHub 인증 및 원격 푸시 완료**:
    - PAT를 안전하게 `~/.git-credentials` (chmod 600) 및 `~/.netrc` (chmod 600)에만 설정하여 보안 유출 원천 차단
    - 9개 커밋(`1cb0059..b7b02bd`) 성공적으로 `origin/main`으로 푸시 완료

- **2026-09-26 (Lab 26 MalSandbox, Wargame 40 Tracks / 1,400 Challenges Milestone, Python Malware Automation Ingestion, 210 Tests All Green, Offline Bundle)**:
  - **Lab 26 악성코드 자동 분석 & 동적 샌드박스 랩 신규 구축 (`labs/26_malware_sandbox_lab/`)**:
    - Shannon 엔트로피(6.5+ 패킹 판별) 및 IAT API 파싱을 통한 의심스러운 메모리 인젝션 호출(VirtualAlloc, WriteProcessMemory) 분석
    - PEB `BeingDebugged` 플래그 및 커스텀 안티 디버깅 회피 탐지
    - YARA 휴리스틱 시그니처 룰셋 기반 C2 도메인 및 쉘코드 패턴 헌팅
    - 동적 가상 샌드박스 텔레메트리, Sleep 타임 지연 가속 및 `cuckoomon` API 후킹 방어
    - 포트 `8026`, 8개 단위 테스트 전원 통과 (`test_malware_sandbox_lab.py`)
  - **컴포넌트 풀체인 연동**:
    - `labs/solvers.py`: Lab 26 정적 엔트로피/YARA/동적 샌드박스 3단계 PoC 자동 솔버 및 26개 랩 테스트 통과
    - `ctf/server.py`: `LAB26_STATIC`, `LAB26_YARA`, `LAB26_SANDBOX` 플래그 풀 및 💡 힌트 상점 아이템 연동
    - `portal/server.py` & UI: 26개 랩 제어 및 카운트 동기화
    - `vhack.py`: `LABS_METADATA` 26번 등록 및 `doctor` 포트 8026 가용성 진단
    - `labs/start_lab.sh` & `labs/stop_all.sh`: 26개 랩 제어 스크립트 확장
  - **워게임 40번째 트랙 (`malsandbox`) & 1,400문제 대기록 달성**:
    - 악성코드 정적/동적 분석, YARA 시그니처, 안티 회피 및 샌드박스 기법을 포괄하는 35개 문제 (Tier 0~4) 완비
    - `wargame/assets/challenges.js`, `wargame/index.html` (HUD `0/1400`, 40 tracks)
    - 4대 엄격 무결성 검증 스위트 100% All Green:
      - `node wargame/scripts/verify.js`: 1,400문제 40개 트랙 5티어 구조 무결성 통과
      - `node wargame/scripts/audit.js --strict`: [A]~[J] 10대 검사 전 항목 0결함 통과
      - `node wargame/scripts/leakscan.js`: 0 leaks 통과 (stale allowlist 10종 정리 및 25종 등록)
      - `node wargame/scripts/solve-derivable.js`: 433/1400 솔버 자동 풀이 100% 검증
  - **보안 자료 심층 인제스천**:
    - `06_Malware_Analysis/09_python_malware_analysis_automation_deepdive.md` 신규 심층 챕터 완성 (pefile, Shannon Entropy, YARA Rule Engine, Cuckoo Sandbox Evasion)
    - `tools/sync_section_readmes.py`: 75개 전 섹션 README 동기화 완료
  - **오프라인 배포 번들 생성**:
    - `vhack bundle`: 26개 랩, 40개 트랙(1,400제), 75개 교재(464개 챕터), 오프라인 벤더 에셋 무결성 검증 및 아카이브(`vibe-hacking-offline.tar.gz`, 6.92 MB) 생성 완료
  - **전체 210개 테스트 100% 통과**:
    - `pytest -q`: **210 passed** (Labs 01~26 187개 + solvers 4개 + portal 8개 + ctf 7개 + wargame cli 4개)
    - `vhack lab test --all`: 26개 실습 랩 187개 테스트 전원 통과

- **2026-09-22 (전체 기능 교차검증·보안 강화 및 186개 테스트 All Green 달성)**:
  - **보안 취약점 방어 및 포털 하드닝**:
    - `vhack portal` 및 `vhack ctf`: 외부 비인가 원격 명령 실행을 방지하기 위해 기본 호스트 바인딩을 `0.0.0.0`에서 안전한 루프백 `127.0.0.1`로 전환하고, CLI `--host` 인자 옵션 지원.
    - `portal/server.py`: 웹 콘솔 명령 실행(`exec_in_lab`) 시 `target_dir`의 Path Traversal 검증(`is_relative_to`) 및 시스템 파괴 명령어(`rm -rf /`, `mkfs` 등) 원천 차단 보안 필터 탑재.
    - 로그 스트리밍(`get_lab_logs`) 줄 수(`tail`) 및 솔루션 스텝(`step`) 안전 범위 경계값 제한 적용.
    - `portal/static/index.html`: UI 상의 랩 카운트(20 -> 23) 불일치 전면 수정.
  - **설정 및 테스트 스위트 불일치 해결**:
    - `pyproject.toml`: 설명 내 랩/문제 수(15 Labs, 1050 Wargame -> 23 Labs, 1295 Wargame) 동기화 및 `testpaths`에 `portal`, `ctf`, `wargame` 추가로 186개 전체 하위 시스템 통합 테스트 파이프라인 완성.
    - `wargame/tests/test_cli.py`: 신규 트랙 `sochunt` 반영에 따른 37개 트랙 및 플래그 검증 단언(assertion) 동기화.
    - `vhack doctor`: Lab 06 (8062), Lab 07 (8072), Lab 09 (5020) 포트 점유 검사 추가로 23개 포트 정밀 진단 완비.
  - **전체 검증 스위트 100% 통과**:
    - `pytest -q`: **186 passed** (Labs 01~23 164개 + solvers 4개 + portal 8개 + ctf 6개 + wargame cli 4개)
    - `vhack lab test --all`: 23개 실습 랩 164개 테스트 All Green
    - 워게임 4대 스위트: `verify.js` (1295제), `audit.js --strict` ([A]~[J] 0결함), `leakscan.js` (0 leaks), `solve-derivable.js` (328/1295) 전원 통과
    - `bundle_offline.py --check-only`: 4대 하위 시스템 100% clean and offline-ready.

- **2026-09-22 (Lab 23 SOCHunter, SOC Threat Hunting Deepdive Ingestion, Wargame Track 37 sochunt 1,295 Milestone)**:
  - **Lab 23 SOC 위협 헌팅 & SIEM 랩 신규 구축 (`labs/23_soc_threat_hunting_lab/`)**: Sysmon Event ID 8(CreateRemoteThread) 기반 메모리 인젝션 및 난독화 PowerShell 실행 탐지, Suricata NIDS 시그니처 룰셋 작성, Splunk SPL / Sentinel KQL 기반 다단계 APT 래터럴 무브먼트 헌팅 쿼리 및 SOAR 자동 호스트 격리 플레이북, 7개 단위 테스트 전원 통과 (포트 8023)
  - **23개 랩 익스플로잇 솔버 완성 (`labs/solvers.py`)**: Lab 23 Sysmon/Suricata/SIEM 단계별 자동 분석 및 플래그 획득 솔버 연동 (`vhack solve 23 [--step 1|2|3]`) 및 단위 테스트 통과
  - **대용량 미분류 자료 인제스천 (SOC & DFIR 위협 헌팅 심층 분석)**:
    - `44_Incident_Response_DFIR/07_soc_siem_threat_hunting_deepdive.md` (3계층 SOC 운영 아키텍처, Sysmon EID 1/3/8/10/11 텔레메트리 파이프라인, Suricata 7 고성능 룰셋 최적화, Splunk SPL vs Microsoft Sentinel KQL 실전 헌팅 쿼리, SOAR 자동 격리 워크플로우)
    - `tools/sync_section_readmes.py` 전 섹션 인덱스 동기화 완료
  - **워게임 37번째 트랙 (`sochunt`) 확장 및 1,295문제 마일스톤**: SOC 분석, EDR 원격 스레드 탐지, Zeek/Suricata NIDS, Splunk/KQL 상관분석, Kerberoasting/Golden Ticket 이상 징후 추적을 포괄하는 35개 문제 추가로 1,260제 → 1,295제 확장 완료, 4대 엄격 무결성 검증 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js` 328/1295) 전원 0결함 완벽 통과

- **2026-09-21 (Lab 22 APIGuard, Deepdive Corelan Exploit Ingestion, Wargame Track 36 apisec 1,260 Milestone, CLI DX Logs & Modal ESC, 164 Tests All Green)**:
  - **Lab 22 API 보안 & 현대적 인증 랩 신규 구축 (`labs/22_api_security_lab/`)**: REST BOLA/IDOR 취약점을 통한 타 고객 주문 데이터 유출, BFLA(Broken Function Level Authorization) 헤더 조작 관리자 함수 탈취, GraphQL Introspection 시스템 시크릿 열람, JWT `alg: none` 서명 검증 우회 임의 토큰 위조, 실시간 사이버 API 관제 대시보드 탑재, 7개 단위 테스트 전원 통과 (포트 8022)
  - **22개 랩 익스플로잇 솔버 완성 (`labs/solvers.py`)**: Lab 22 BOLA/BFLA/GraphQL/JWT 단계별 자동 익스플로잇 솔버 연동 (`vhack solve 22 [--step 1|2|3]`) 및 단위 테스트 통과
  - **대용량 미분류 자료 인제스천 (Exploit Writing 심층 분석)**:
    - `09_Exploit_Techniques/07_practical_exploit_writing_corelan_deepdive.md` (Corelan 시리즈 분석: 바닐라 EIP 오버라이트, SEH 구조체 덮어쓰기 및 pop pop ret 역산, DEP 우회 ROP 가젯 체이닝 및 VirtualProtect/VirtualAlloc 호출, 힙 스프레이 0x0c0c0c0c 구조화, 바이트 제한 에그헌팅 w/ NtAccessCheckAndAuditAlarm 시스템콜, 64비트 FASTCALL/SHSTK 우회 방안)
    - `tools/sync_section_readmes.py` 전 섹션 인덱스 동기화 완료
  - **워게임 36번째 트랙 (`apisec`) 확장 및 1,260문제 마일스톤**: API Security, OAuth2, OIDC, JWT, GraphQL, mTLS 등을 포괄하는 35개 문제 추가로 1,225제 → 1,260제 확장 완료, 4대 엄격 무결성 검증 (`verify.js`, `audit.js --strict`, `leakscan.js`, `solve-derivable.js` 293/1260) 전원 0결함 완벽 통과
  - **웹 관제 포털 및 CLI DX 고도화**:
    - `vhack logs <lab_id> [-f] [-n 50]`: 개별 랩 컨테이너 로그 실시간 스트리밍 독립 명령어 및 서브커맨드 지원
    - `portal/static/index.html`: 콘솔, 로그, 솔루션 팝업 모달 닫기 `Escape` 키보드 인터랙션 추가
    - `tools/bundle_offline.py`: 22개 랩, 36개 트랙(1,260제), 75개 챕터 오프라인 번들러 검증 무결격 통과
  - **전체 164개 테스트 100% 통과**: `pytest -q` (Labs 01~22 157개 테스트 + solvers 4개 + portal 6개 + ctf 6개 + wargame cli 4개 등 164개 ALL GREEN)
- **2026-09-20 (Part 2: Lab 21 CarCanLab, CTF Live SSE & Score Progression Chart, Terminal Wargame Client vhack play, 157 Tests All Green)**:
  - **Lab 21 차량 보안 & CAN Bus 랩 신규 구축 (`labs/21_automotive_can_lab/`)**: CAN 2.0B 가상 버스 스니핑/인젝션, 계기판 속도계 스푸핑(CAN ID 0x244), UDS(ISO 14229) 진단 세션(0x10) 및 SecurityAccess(0x27) 시드-키 챌린지 인증 우회, 펌웨어 덤프(0x34) 플래그 획득, ECU 버스 플러딩 DoS 공격(0x000 우선순위 선점) 및 리셋(0x11), 사이버 자동차 계기판 실시간 웹 대시보드 탑재, 6개 단위 테스트 전원 통과 (포트 8021)
  - **21개 랩 익스플로잇 솔버 완성 (`labs/solvers.py`)**: Lab 21 속도 스푸핑 및 UDS 시드-키 역산 펌웨어 덤프 자동 익스플로잇 솔버 연동 (`vhack solve 21 [--step 1|2]`) 및 단위 테스트 통과
  - **CTF 대회 스코어보드 고도화 (`vhack ctf`)**: HTML5 Canvas 기반 인터랙티브 시계열 점수 추이 그래프(Score Progression Timeline), Server-Sent Events(SSE, `/api/ctf/stream`) 기반 실시간 점수 변동/First Blood 브로드캐스팅 및 토스트 알림 탑재, 28개 랩 플래그 풀 완비, 단위 테스트 6종 전원 통과
  - **터미널 네이티브 워게임 클라이언트 (`vhack play` / `vhack wargame --cli`)**: 35개 트랙 1,225개 전 챌린지 터미널 브라우징, 키워드 검색(`--search`), 대화형 풀이 및 플래그 검증 제출(`--submit`), 로컬 진행도(`~/.vhack_wargame_progress.json`) 자동 저장/동기화 완비, 4개 단위 테스트 전원 통과
  - **전체 157개 테스트 100% 통과**: `pytest -q` (Labs 01~21 150개 테스트 + solvers 4개 + portal 6개 + ctf 6개 + wargame cli 4개 등 157개 ALL GREEN) 및 `bundle_offline.py --check-only` 무결성 검증 완료
- **2026-09-20 (Part 1: Portal Web Console/Logs/Solver Modal, Lab Solvers DB & CLI, Track 35 carcan 1,225 Milestone, CTF First Blood & Dynamic Scoring, 151 Tests All Green)**:
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

