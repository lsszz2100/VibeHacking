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

## 랩 목록

| # | 랩 이름 | 핵심 주제 | 난이도 |
|---|---------|-----------|--------|
| 01 | [웹 해킹 랩](./01_web_hacking_lab/) | SQLi, XSS, CSRF, IDOR, 인증 우회 | ★★☆ |
| 02 | [바이너리 익스플로잇 랩](./02_pwn_lab/) | BOF, ret2libc, ROP, 포맷스트링, 힙 | ★★★ |
| 03 | [네트워크 해킹 랩](./03_network_lab/) | 포트 스캔, 크리덴셜 공격, 피벗 | ★★☆ |
| 04 | [클라우드/컨테이너 보안 랩](./04_cloud_container_lab/) | K8s, IMDS, 컨테이너 탈출 | ★★★ |
| 05 | [전체 시나리오 통합 랩](./05_full_scenario_lab/) | APT 체인, 내부망 침투, 데이터 탈취 | ★★★★ |
| 06 | [펌웨어 해킹 랩](./06_firmware_lab/) | binwalk, QEMU 에뮬레이션, 하드코딩 자격증명 | ★★★ |
| 07 | [모바일 보안 랩](./07_mobile_lab/) | APK 분석, JWT alg:none, 하드코딩 API 키 | ★★★ |
| 08 | [AI/LLM 보안 랩](./08_llm_security_lab/) | 프롬프트 인젝션, RAG 간접 주입, 에이전트 도구 남용, 시스템 프롬프트 탈취 | ★★★ |
| 09 | [ICS/SCADA 제어 보안 랩](./09_ics_scada_lab/) | Modbus/TCP 제어, 비인가 코일 조작, 텔레메트리 기만(FDI), SIS 비상 트립 | ★★★ |
| 10 | [Kubernetes & 컨테이너 보안 랩](./10_k8s_security_lab/) | SA 토큰 탈취, RBAC 과다 권한 남용, hostPath 탈출, privileged 컨테이너 장악 | ★★★ |
| 11 | [Active Directory & Kerberos 침투 랩](./11_ad_kerberos_lab/) | AS-REP Roasting, Kerberoasting, DCSync, Golden Ticket 도메인 장악 | ★★★☆ |
| 12 | [CI/CD & 공급망 보안 랩](./12_cicd_supply_chain_lab/) | Poisoned Pipeline(PPE), 의존성 혼동(Dependency Confusion), 러너 시크릿 탈취, 릴리스 백도어 & SLSA 변조 | ★★★☆ |

---

## 각 랩 학습 목표

### 01. 웹 해킹 랩
- OWASP Top 10 취약점을 직접 실습
- SQL 인젝션을 통한 데이터 추출 및 인증 우회
- XSS(Reflected, Stored, DOM)의 원리와 방어책 이해
- Burp Suite를 활용한 웹 트래픽 분석 및 조작
- DVWA, Juice Shop, WebGoat 등 검증된 취약 환경 활용

### 02. 바이너리 익스플로잇 랩
- x86/x64 스택 구조 및 스택 오버플로우 원리 이해
- NX, ASLR, PIE, RELRO 등 메모리 보호 기법 학습
- ret2libc 및 ROP 가젯 체이닝 기법 습득
- 포맷 스트링 취약점을 활용한 메모리 읽기/쓰기
- tcache poisoning을 통한 힙 익스플로잇

### 03. 네트워크 해킹 랩
- nmap을 이용한 네트워크 스캔 및 서비스 핑거프린팅
- 취약한 서비스(SSH, FTP, Telnet) 크리덴셜 공격
- DNS zone transfer 취약점 및 SMTP 릴레이 남용
- 피벗(pivoting)을 통한 내부 네트워크 접근

### 04. 클라우드/컨테이너 보안 랩
- AWS IMDS(Instance Metadata Service) 취약점 실습
- SSRF를 통한 클라우드 자격증명 탈취
- Docker 컨테이너 권한 남용 및 탈출(escape) 기법
- 취약한 컨테이너 레지스트리 악용

### 05. 전체 시나리오 통합 랩
- APT(Advanced Persistent Threat) 공격 체인 시뮬레이션
- 외부 웹 → SSRF → 내부망 이동 → 데이터베이스 침투
- LDAP 열거 및 SMB/FTP 파일 서버 접근
- 전체 침투 테스트 보고서 작성 실습

### 06. 펌웨어 해킹 랩
- binwalk를 이용한 펌웨어 구조 분석 및 파일시스템 자동 추출
- QEMU user-mode로 ARM/MIPS 임베디드 바이너리 에뮬레이션
- squashfs, LZMA 등 다양한 압축 포맷 해제 실습
- 펌웨어 바이너리 내 하드코딩 자격증명 탐색 및 CTF 플래그 획득

### 07. 모바일 보안 랩
- jadx·apktool을 활용한 Android APK 정적 역컴파일 및 소스 탐색
- 하드코딩된 API 키 추출 및 취약한 백엔드 API 인증 우회
- JWT alg:none 취약점을 이용한 권한 상승 공격
- Frida·objection을 통한 런타임 동적 분석 기초

### 08. AI/LLM 보안 랩
- OWASP Top 10 for LLM 기반 실전 취약점 공격 및 방어 실습
- 시스템 프롬프트 탈취(Jailbreak) 및 기밀 마스터 키 추출
- 비위생적 마크다운 출력 렌더링을 통한 XSS 공격
- RAG(검색 증강 생성) 지식 베이스 문서를 통한 간접 프롬프트 주입
- 자율 AI 에이전트의 과도한 권한(Excessive Agency)과 위험 도구 남용 통제

### 09. ICS/SCADA 제어 보안 랩
- Purdue 참조 아키텍처 및 산업 필드버스 네트워크 분석
- Modbus/TCP(포트 5020) 프로토콜 역공학 및 기능 코드(FC03/FC05/FC06) 조작
- 비인가 코일 조작을 통한 물리적 냉각 펌프 무단 중단 공격
- 센서 텔레메트리 기만(False Data Injection)을 통한 과압 은폐
- 안전 계장 시스템(SIS) 비상 안전 트립 발동 및 심층 패킷 검사(DPI) 방어

### 10. Kubernetes & 컨테이너 보안 랩
- 클라우드 네이티브 아키텍처 및 K8s API 서버 인증 체계 이해
- Pod 내부 마운트된 ServiceAccount 토큰 추출 및 정찰 기법
- 과도하게 부여된 ClusterRole 및 RoleBinding을 통한 프로덕션 시크릿 덤프
- `hostPath` 볼륨 마운트 기반 악성 Pod 배포를 통한 노드 루트 탈출(Breakout)
- `privileged: true` 및 `hostPID: true` 옵션을 악용한 호스트 네임스페이스(`nsenter`) 장악
- Pod Security Standards (PSS) 및 CKS 기반 방어 대책 실무 적용

### 11. Active Directory & Kerberos 침투 랩 (KeroShield)
- 엔터프라이즈 윈도우 도메인(CORP.LOCAL) 및 Kerberos KDC 아키텍처 분석
- `DONT_REQ_PREAUTH` 계정 식별 및 AS-REP Roasting 오프라인 패스워드 크래킹
- 서비스 계정 SPN(Service Principal Name) 조회 및 Kerberoasting TGS 티켓 추출
- 복제 권한(`DS-Replication-Get-Changes-All`)을 악용한 DCSync 공격 및 `krbtgt` 해시 탈취
- 탈취한 `krbtgt` 키와 도메인 SID를 결합한 만능 Golden Ticket 위조 및 도메인 컨트롤러 장악
- SIEM 보안 감사 이벤트(Event ID 4768, 4769, 4662, 4672) 탐지 및 gMSA·AES 강화 대책 실무 습득

### 12. CI/CD & 소프트웨어 공급망 침투 랩 (PipePoison)
- OctoCorp 엔터프라이즈 CI/CD 파이프라인 아키텍처 및 SDLC 공격면 분석
- `pull_request_target` 트리거 기반 Poisoned Pipeline Execution (PPE) 커맨드 인젝션 및 러너 탈출
- 비공개/공용 패키지 인덱스 간 버전 우선순위를 악용한 의존성 혼동(Dependency Confusion) 및 악성 인스톨 훅 실행
- CI/CD 러너 메모리 및 환경변수 덤프를 통한 HashiCorp Vault 마스터 토큰 및 클라우드 시크릿 탈취
- 빌드 산출물 무단 변조(SolarWinds 스타일) 및 SLSA Level 3 출처 증적 / Sigstore Cosign 무결성 서명 방어 대책 실무 적용

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
