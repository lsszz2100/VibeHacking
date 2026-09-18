# CTF 스타일 취약 환경 번들 — 바이브 해킹 Labs

이 디렉토리는 사이버보안 학습을 위한 **CTF 스타일 취약 환경**을 모아둔 번들입니다.
각 랩은 Docker Compose로 독립적으로 실행 가능하며, 실제 공격/방어 기술을 안전하게 실습할 수 있습니다.

---

## 환경 요구사항

| 항목 | 최소 버전 | 권장 |
|------|-----------|------|
| Docker Engine | 20.10+ | 24.x |
| Docker Compose | v2.0+ (또는 docker-compose v1.29+) | v2.x |
| 사용 가능한 RAM | 4 GB | 8 GB 이상 |
| 디스크 공간 | 10 GB | 20 GB 이상 |
| 운영체제 | Linux / macOS / WSL2 | Ubuntu 22.04 |

### 설치 확인

```bash
docker --version
docker compose version
# 또는 구버전
docker-compose --version
```

---

## 랩 목록 및 교재·워게임 연계 매트릭스

| # | 랩 이름 | 핵심 주제 | 난이도 | 연계 교재 챕터 | 연계 워게임 트랙 |
|---|---------|-----------|--------|----------------|------------------|
| 01 | [웹 해킹 랩](./01_web_hacking_lab/) | SQLi, XSS, CSRF, IDOR, 인증 우회 | ★★☆ | [05장 웹 해킹](../05_Web_Hacking/06_web_ctf_practical_lab.md) | `web` |
| 02 | [바이너리 익스플로잇 랩](./02_pwn_lab/) | BOF, ret2libc, ROP, 포맷스트링, 힙 | ★★★ | [03장 시스템 해킹](../03_System_Hacking/06_system_ctf_lab.md) | `pwn` |
| 03 | [네트워크 해킹 랩](./03_network_lab/) | 포트 스캔, 크리덴셜 공격, 피벗 | ★★☆ | [02장 네트워크 해킹](../02_Network_Hacking/06_network_ctf_lab.md) | `network` |
| 04 | [클라우드/컨테이너 보안 랩](./04_cloud_container_lab/) | K8s, IMDS, 컨테이너 탈출 | ★★★ | [14장 클라우드 보안](../14_Cloud_Security/06_cloud_security_ctf_lab.md) | `cloud` |
| 05 | [전체 시나리오 통합 랩](./05_full_scenario_lab/) | APT 체인, 내부망 침투, 데이터 탈취 | ★★★★ | [10장 침투 테스트](../10_Pentest_Methodology/06_pentest_ctf_lab.md) | `redteam` / `purpleteam` |
| 06 | [펌웨어 해킹 랩](./06_firmware_lab/) | binwalk, QEMU 에뮬레이션, 하드코딩 자격증명 | ★★★ | [61장 펌웨어 해킹](../61_Firmware_Hacking/06_firmware_ctf_lab.md) | `hardware` |
| 07 | [모바일 보안 랩](./07_mobile_lab/) | APK 분석, JWT alg:none, 하드코딩 API 키 | ★★★ | [28장 모바일 해킹](../28_Mobile_Hacking/06_mobile_ctf_lab.md) | `mobile` |
| 08 | [AI/LLM 보안 랩](./08_llm_security_lab/) | 프롬프트 인젝션, RAG 간접 주입, 에이전트 도구 남용, 시스템 프롬프트 탈취 | ★★★ | [11장 AI 보안](../11_AI_Powered_Security/06_ai_security_ctf_lab.md), [69장 LLM 보안](../69_LLM_Security/06_llm_security_ctf_lab.md) | `ai` |
| 09 | [ICS/SCADA 제어 보안 랩](./09_ics_scada_lab/) | Modbus/TCP 제어, 비인가 코일 조작, 텔레메트리 기만(FDI), SIS 비상 트립 | ★★★ | [37장 ICS/SCADA](../37_ICS_SCADA/06_ics_ctf_lab.md) | `icsscada` |
| 10 | [Kubernetes & 컨테이너 보안 랩](./10_k8s_security_lab/) | SA 토큰 탈취, RBAC 과다 권한 남용, hostPath 탈출, privileged 컨테이너 장악 | ★★★ | [29장 컨테이너](../29_Container_Kubernetes_Security/06_container_ctf_lab.md), [70장 쿠버네티스](../70_Kubernetes_Security/06_k8s_security_ctf_lab.md) | `cloud` |
| 11 | [Active Directory & Kerberos 침투 랩](./11_ad_kerberos_lab/) | AS-REP Roasting, Kerberoasting, DCSync, Golden Ticket 도메인 장악 | ★★★☆ | [54장 Active Directory](../54_Active_Directory_Attacks/06_ad_ctf_lab.md) | `activedirectory` |
| 12 | [CI/CD & 공급망 보안 랩](./12_cicd_supply_chain_lab/) | Poisoned Pipeline(PPE), 의존성 혼동(Dependency Confusion), 러너 시크릿 탈취, 릴리스 백도어 & SLSA 변조 | ★★★☆ | [18장 DevSecOps](../18_DevSecOps/06_devsecops_ctf_lab.md), [35장 공급망 공격](../35_Supply_Chain_Attacks/06_supply_chain_ctf_lab.md) | `supplychain` |
| 13 | [eBPF 커널 보안 랩](./13_ebpf_kernel_lab/) | Kprobe 시스템콜 도청, bpf_probe_write_user 메모리 변조 권한상승, XDP 은닉 통신, BPF LSM 무결성 방어 | ★★★★ | [01장 리눅스 기초](../01_Linux_Basics/06_linux_ctf_practical_lab.md), [26장 리눅스 하드닝](../26_Linux_Hardening/README.md), [70장 쿠버네티스](../70_Kubernetes_Security/06_k8s_security_ctf_lab.md) | `ebpf` |
| 14 | [문서형 악성코드 분석 랩](./14_maldoc_lab/) | OLE/VBA 매크로 난독화 해제, PDF FlateDecode 스트림 분석, CVE-2017-11882 수식 에디터 RCE, CVE-2021-40444 MSHTML 방어 | ★★★☆ | [06장 악성코드 분석](../06_Malware_Analysis/07_document_malware_analysis.md) | `maldoc` |
| 15 | [Web3 & 스마트 컨트랙트 보안 랩](./15_web3_smart_contract_lab/) | Reentrancy, 정수 오버플로, tx.origin 피싱, Flash Loan AMM 가격 조작 | ★★★★ | [42장 블록체인/Web3](../42_Blockchain_Web3_Security/06_blockchain_ctf_lab.md) | `web3` |
| 16 | [메모리 포렌식 & Volatility 랩](./16_memory_forensics_lab/) | DKOM 은닉 프로세스 적출, VAD RWX 쉘코드 탐지, C2 비컨 복원, LSASS PPL 방어 | ★★★★ | [06장 악성코드 분석](../06_Malware_Analysis/README.md), [07장 디지털 포렌식](../07_Digital_Forensics/06_forensics_ctf_lab.md), [44장 사고 대응](../44_Incident_Response_DFIR/README.md) | `volatility` |
| 17 | [클라우드 네이티브 & Kubernetes 랩](./17_kubernetes_cloud_native_lab/) | 특권 파드 탈출, RBAC 와일드카드 권한상승, 클라우드 IMDS 탈취, Cosign 어드미션 제어 | ★★★★ | [29장 컨테이너](../29_Container_Kubernetes_Security/README.md), [38장 클라우드 네이티브](../38_Cloud_Native_Security/README.md), [70장 쿠버네티스](../70_Kubernetes_Security/README.md) | `cloud` |


---

## 각 랩 학습 목표 및 핸즈온 가이드

### 01. 웹 해킹 랩
- OWASP Top 10 취약점을 직접 실습
- SQL 인젝션을 통한 데이터 추출 및 인증 우회
- XSS(Reflected, Stored, DOM)의 원리와 방어책 이해
- Burp Suite를 활용한 웹 트래픽 분석 및 조작
- DVWA, Juice Shop, WebGoat 등 검증된 취약 환경 활용
- **교재 챕터 연계**: [05장 웹 해킹 CTF 실습 랩](../05_Web_Hacking/06_web_ctf_practical_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `web` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 01` (접속: `http://localhost:8080/dvwa/`, `http://localhost:3001`)

### 02. 바이너리 익스플로잇 랩
- x86/x64 스택 구조 및 스택 오버플로우 원리 이해
- NX, ASLR, PIE, RELRO 등 메모리 보호 기법 학습
- ret2libc 및 ROP 가젯 체이닝 기법 습득
- 포맷 스트링 취약점을 활용한 메모리 읽기/쓰기
- tcache poisoning을 통한 힙 익스플로잇
- **교재 챕터 연계**: [03장 시스템 해킹 CTF 실습 랩](../03_System_Hacking/06_system_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `pwn` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 02` (접속: `nc localhost 10001~10005`)

### 03. 네트워크 해킹 랩
- nmap을 이용한 네트워크 스캔 및 서비스 핑거프린팅
- 취약한 서비스(SSH, FTP, Telnet) 크리덴셜 공격
- DNS zone transfer 취약점 및 SMTP 릴레이 남용
- 피벗(pivoting)을 통한 내부 네트워크 접근
- **교재 챕터 연계**: [02장 네트워크 해킹 CTF 실습 랩](../02_Network_Hacking/06_network_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `network` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 03` (진입: `docker exec -it net_lab_attacker bash`)

### 04. 클라우드/컨테이너 보안 랩
- AWS IMDS(Instance Metadata Service) 취약점 실습
- SSRF를 통한 클라우드 자격증명 탈취
- Docker 컨테이너 권한 남용 및 탈출(escape) 기법
- 취약한 컨테이너 레지스트리 악용
- **교재 챕터 연계**: [14장 클라우드 보안 CTF 실습 랩](../14_Cloud_Security/06_cloud_security_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `cloud` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 04` (접속: `http://localhost:8040`, `http://localhost:8443`)

### 05. 전체 시나리오 통합 랩
- APT(Advanced Persistent Threat) 공격 체인 시뮬레이션
- 외부 웹 → SSRF → 내부망 이동 → 데이터베이스 침투
- LDAP 열거 및 SMB/FTP 파일 서버 접근
- 전체 침투 테스트 보고서 작성 실습
- **교재 챕터 연계**: [10장 침투 테스트 방법론 CTF 실습 랩](../10_Pentest_Methodology/06_pentest_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `redteam` 및 `purpleteam` 트랙
- **빠른 실행**: `python3 vhack.py lab start 05` (접속: `http://localhost:8888`)

### 06. 펌웨어 해킹 랩
- binwalk를 이용한 펌웨어 구조 분석 및 파일시스템 자동 추출
- QEMU user-mode로 ARM/MIPS 임베디드 바이너리 에뮬레이션
- squashfs, LZMA 등 다양한 압축 포맷 해제 실습
- 펌웨어 바이너리 내 하드코딩 자격증명 탐색 및 CTF 플래그 획득
- **교재 챕터 연계**: [61장 펌웨어 해킹 CTF 실습 랩](../61_Firmware_Hacking/06_firmware_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `hardware` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 06` (접속: `http://localhost:8062`, 분석 쉘: `docker exec -it firmware_analyzer bash`)

### 07. 모바일 보안 랩
- jadx·apktool을 활용한 Android APK 정적 역컴파일 및 소스 탐색
- 하드코딩된 API 키 추출 및 취약한 백엔드 API 인증 우회
- JWT alg:none 취약점을 이용한 권한 상승 공격
- Frida·objection을 통한 런타임 동적 분석 기초
- **교재 챕터 연계**: [28장 모바일 해킹 CTF 실습 랩](../28_Mobile_Hacking/06_mobile_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `mobile` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 07` (접속: `http://localhost:8072`, 분석 쉘: `docker exec -it apk_analyzer bash`)

### 08. AI/LLM 보안 랩
- OWASP Top 10 for LLM 기반 실전 취약점 공격 및 방어 실습
- 시스템 프롬프트 탈취(Jailbreak) 및 기밀 마스터 키 추출
- 비위생적 마크다운 출력 렌더링을 통한 XSS 공격
- RAG(검색 증강 생성) 지식 베이스 문서를 통한 간접 프롬프트 주입
- 자율 AI 에이전트의 과도한 권한(Excessive Agency)과 위험 도구 남용 통제
- **교재 챕터 연계**: [11장 AI 보안 CTF 실습 랩](../11_AI_Powered_Security/06_ai_security_ctf_lab.md), [69장 LLM 보안 CTF 실습 랩](../69_LLM_Security/06_llm_security_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `ai` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 08` (웹 콘솔: `http://localhost:8088`)

### 09. ICS/SCADA 제어 보안 랩
- Purdue 참조 아키텍처 및 산업 필드버스 네트워크 분석
- Modbus/TCP(포트 5020) 프로토콜 역공학 및 기능 코드(FC03/FC05/FC06) 조작
- 비인가 코일 조작을 통한 물리적 냉각 펌프 무단 중단 공격
- 센서 텔레메트리 기만(False Data Injection)을 통한 과압 은폐
- 안전 계장 시스템(SIS) 비상 안전 트립 발동 및 심층 패킷 검사(DPI) 방어
- **교재 챕터 연계**: [37장 ICS/SCADA CTF 실습 랩](../37_ICS_SCADA/06_ics_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `icsscada` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 09` (HMI 패널: `http://localhost:8089`, Modbus TCP: `localhost:5020`)

### 10. Kubernetes & 컨테이너 보안 랩
- 클라우드 네이티브 아키텍처 및 K8s API 서버 인증 체계 이해
- Pod 내부 마운트된 ServiceAccount 토큰 추출 및 정찰 기법
- 과도하게 부여된 ClusterRole 및 RoleBinding을 통한 프로덕션 시크릿 덤프
- `hostPath` 볼륨 마운트 기반 악성 Pod 배포를 통한 노드 루트 탈출(Breakout)
- `privileged: true` 및 `hostPID: true` 옵션을 악용한 호스트 네임스페이스(`nsenter`) 장악
- Pod Security Standards (PSS) 및 CKS 기반 방어 대책 실무 적용
- **교재 챕터 연계**: [29장 컨테이너 & 쿠버네티스 CTF 실습 랩](../29_Container_Kubernetes_Security/06_container_ctf_lab.md), [70장 쿠버네티스 CTF 실습 랩](../70_Kubernetes_Security/06_k8s_security_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `cloud` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 10` (웹 콘솔 & K8s API: `http://localhost:8090`)

### 11. Active Directory & Kerberos 침투 랩 (KeroShield)
- 엔터프라이즈 윈도우 도메인(CORP.LOCAL) 및 Kerberos KDC 아키텍처 분석
- `DONT_REQ_PREAUTH` 계정 식별 및 AS-REP Roasting 오프라인 패스워드 크래킹
- 서비스 계정 SPN(Service Principal Name) 조회 및 Kerberoasting TGS 티켓 추출
- 복제 권한(`DS-Replication-Get-Changes-All`)을 악용한 DCSync 공격 및 `krbtgt` 해시 탈취
- 탈취한 `krbtgt` 키와 도메인 SID를 결합한 만능 Golden Ticket 위조 및 도메인 컨트롤러 장악
- SIEM 보안 감사 이벤트(Event ID 4768, 4769, 4662, 4672) 탐지 및 gMSA·AES 강화 대책 실무 습득
- **교재 챕터 연계**: [54장 Active Directory CTF 실습 랩](../54_Active_Directory_Attacks/06_ad_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `activedirectory` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 11` (웹 콘솔 & API: `http://localhost:8011`)

### 12. CI/CD & 소프트웨어 공급망 침투 랩 (PipePoison)
- OctoCorp 엔터프라이즈 CI/CD 파이프라인 아키텍처 및 SDLC 공격면 분석
- `pull_request_target` 트리거 기반 Poisoned Pipeline Execution (PPE) 커맨드 인젝션 및 러너 탈출
- 비공개/공용 패키지 인덱스 간 버전 우선순위를 악용한 의존성 혼동(Dependency Confusion) 및 악성 인스톨 훅 실행
- CI/CD 러너 메모리 및 환경변수 덤프를 통한 HashiCorp Vault 마스터 토큰 및 클라우드 시크릿 탈취
- 빌드 산출물 무단 변조(SolarWinds 스타일) 및 SLSA Level 3 출처 증적 / Sigstore Cosign 무결성 서명 방어 대책 실무 적용
- **교재 챕터 연계**: [18장 DevSecOps CTF 실습 랩](../18_DevSecOps/06_devsecops_ctf_lab.md), [35장 공급망 공격 CTF 실습 랩](../35_Supply_Chain_Attacks/06_supply_chain_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `supplychain` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 12` (웹 콘솔 & API: `http://localhost:8012`)

### 13. eBPF 커널 침투 및 런타임 보안 랩 (BPFGuard)
- 리눅스 커널 eBPF 서브시스템 아키텍처 및 커널 공간 계측 메커니즘 분석
- `sys_enter_execve` 시스템 콜 진입점에 Kprobe 후킹을 통한 비인가 자격증명 및 API 토큰 도청
- `bpf_probe_write_user` 커널 헬퍼 악용을 통한 `/etc/sudoers` 유저 버퍼 메모리 변조 및 무패스워드 루트 권한 상승
- 초고속 데이터 경로(XDP) 드라이버 후킹을 통한 스텔스 ICMP 은닉 채널(Covert Channel) 데이터 유출
- BPF LSM(`bpf_lsm_bpf`) 무결성 서명 강제 검증, JIT 하드닝, unprivileged_bpf 차단 등 다층 방어 체계 실증
- **교재 챕터 연계**: [01장 리눅스 기초 CTF 실습 랩](../01_Linux_Basics/06_linux_ctf_practical_lab.md), [26장 리눅스 하드닝](../26_Linux_Hardening/README.md), [70장 쿠버네티스 보안](../70_Kubernetes_Security/06_k8s_security_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `ebpf` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 13` (웹 콘솔 & API: `http://localhost:8013`)

### 14. 문서형 악성코드 분석 랩 (DocArmor)
- MS Office 바이너리 OLE(Compound File) 및 OpenXML 아키텍처 분석
- 다층 난독화(ChrW 연산, XOR 바이트 마스킹, StrReverse) VBA 매크로 분석 및 C2 URL 복원
- PDF 문서의 FlateDecode 스트림 인플레이션 및 `/OpenAction`과 `/JavaScript` 내 힙 스프레이 셸코드 탐색
- Microsoft Equation Editor `EQNEDT32.EXE` 폰트 이름 버퍼 오버플로우(CVE-2017-11882) RCE 분석
- Word OOXML `document.xml.rels` 외부 OLE 참조(CVE-2021-40444 MSHTML CAB) 탐지 및 보안 격리 방어
- **교재 챕터 연계**: [06장 악성코드 분석 - 문서형 악성코드](../06_Malware_Analysis/07_document_malware_analysis.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `maldoc` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 14` (웹 콘솔 & API: `http://localhost:8014`)

### 15. Web3 & 스마트 컨트랙트 보안 랩 (ChainDefend)
- EVM 기반 이더리움 스마트 컨트랙트 핵심 보안 취약점 4대 실습
- Checks-Effects-Interactions 패턴 위반 재진입(Reentrancy) 취약점 악용 및 금고 전액 탈취
- uint256 래핑 및 배치 전송(Batch Overflow) 정수 오버플로를 통한 무제한 토큰 발행
- tx.origin 피싱 기법을 이용한 컨트랙트 관리자 권한 탈취
- 플래시론(Flash Loan)을 활용한 탈중앙화 거래소(AMM) 현물 가격 오라클 조작 및 담보 차익 착취
- **교재 챕터 연계**: [42장 블록체인 및 Web3 보안 CTF 실습 랩](../42_Blockchain_Web3_Security/06_blockchain_ctf_lab.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `web3` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 15` (웹 콘솔 & API: `http://localhost:8015`)

### 16. 메모리 포렌식 & Volatility 3 분석 랩 (MemShield)
- Windows 10 엔터프라이즈 메모리 덤프(`victim_win10_enterprise_x64.dmp`) 대상 Volatility 3 심층 포렌식 실습
- `ActiveProcessLinks` 조작(DKOM)으로 은닉된 악성 프로세스(`svch0st.exe`) 풀 스캔(`psscan`, `pstree`) 적출
- `explorer.exe` 내 `PAGE_EXECUTE_READWRITE` (RWX) VAD 영역 및 PE 헤더(MZ) 인젝션 셸코드 분석(`malfind`)
- 은닉 프로세스의 원격 C2 비컨(`198.51.100.89:8443`) 네트워크 소켓 아티팩트 복원(`netscan`)
- `lsass.exe` 메모리 NTLM 해시 덤프(`lsadump`) 및 Windows LSA PPL(Protected Process Light) 커널 하드닝 방어
- **교재 챕터 연계**: [06장 악성코드 분석](../06_Malware_Analysis/README.md), [07장 디지털 포렌식](../07_Digital_Forensics/06_forensics_ctf_lab.md), [44장 사고 대응/DFIR](../44_Incident_Response_DFIR/README.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `volatility` 트랙 (35개 문제)
- **빠른 실행**: `python3 vhack.py lab start 16` (웹 콘솔 & API: `http://localhost:8016`)
### 17. 클라우드 네이티브 & Kubernetes 보안 랩 (KubeShield)
- 엔터프라이즈 Kubernetes 클러스터 대상 4대 핵심 침해 시나리오 및 방어 체계 실습
- 특권 컨테이너(`privileged: true`, `hostPath: /host`)를 통한 호스트 OS 네임스페이스 탈출 및 Pod Security Standards(PSA restricted) 차단
- 마운트된 ServiceAccount 토큰의 와일드카드(`*.* / [*]`) ClusterRole 악용 `cluster-admin` 권한 상승 및 최소 권한(Least Privilege) RBAC 정비
- AWS/클라우드 메타데이터(IMDSv1) 취약점을 통한 노드 IAM 자격 증명 탈취 및 IMDSv2 Hop Limit 1 / Egress NetworkPolicy 방어
- 서명되지 않은 악성 백도어 이미지 침투 시도 및 Kyverno/Gatekeeper 어드미션 웹훅과 Sigstore Cosign 서명 검증 강제화
- **교재 챕터 연계**: [29장 컨테이너 보안](../29_Container_Kubernetes_Security/README.md), [38장 클라우드 네이티브 보안](../38_Cloud_Native_Security/README.md), [70장 쿠버네티스 보안](../70_Kubernetes_Security/README.md)
- **워게임 트랙**: 워게임 터미널(`wargame/`) `cloud` 트랙
- **빠른 실행**: `python3 vhack.py lab start 17` (웹 콘솔 & API: `http://localhost:8017`)





---

## 빠른 시작 가이드

### 특정 랩 시작

```bash
# 01 웹 해킹 랩 시작
./start_lab.sh 01

# 02 바이너리 익스플로잇 랩 시작
./start_lab.sh 02

# 특정 랩 직접 실행
cd labs/01_web_hacking_lab
docker compose up -d

# 로그 확인
docker compose logs -f
```

### 전체 랩 정리

```bash
./stop_all.sh
```

### 개별 랩 종료

```bash
cd labs/01_web_hacking_lab
docker compose down

# 볼륨까지 삭제
docker compose down -v
```

---

## 주의사항

> **경고**: 이 랩은 의도적으로 취약하게 설계되어 있습니다.
> - **로컬 또는 격리된 환경**에서만 실행하세요.
> - 인터넷에 노출된 서버에 절대 배포하지 마세요.
> - 학습 목적 외의 용도로 사용하지 마세요.
> - 실습 후 반드시 컨테이너를 종료하세요.

---

## 추천 도구

| 도구 | 용도 | 설치 |
|------|------|------|
| Burp Suite Community | 웹 프록시 | https://portswigger.net |
| pwntools | 바이너리 익스플로잇 | `pip install pwntools` |
| nmap | 네트워크 스캔 | `apt install nmap` |
| Wireshark | 패킷 분석 | https://wireshark.org |
| GDB + pwndbg | 디버거 | https://github.com/pwndbg/pwndbg |
| sqlmap | SQLi 자동화 | `apt install sqlmap` |

---

## 참고 자료

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CTFtime](https://ctftime.org) — CTF 대회 일정
- [pwn.college](https://pwn.college) — 바이너리 익스플로잇 학습
- [HackTheBox](https://hackthebox.com) — 실전 모의해킹 플랫폼
- [TryHackMe](https://tryhackme.com) — 가이드형 사이버보안 학습
