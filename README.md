<div align="center">

# ⚔️ VibeHacking

### 실전 사이버보안 완전 정복 — AI 시대의 해킹 바이블

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-40-blueviolet)](#목차)
[![Files](https://img.shields.io/badge/Docs-175%20Files-brightgreen)](#목차)
[![Lines](https://img.shields.io/badge/Lines-126%2C000%2B-orange)](#목차)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai-기반-사이버보안)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-gray)](https://claude.ai/code)

<br/>

> 이론부터 실습까지, CTF·버그바운티·모의해킹·레드팀에 실전 투입 가능한 수준으로 정리한 한국어 보안 지식 저장소.
> **2026년 Mythos·GPT-5.4-Cyber 시대**의 AI 기반 취약점 연구부터 클라우드·무선·암호학까지 완전 정복.

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## 왜 이 저장소인가

실전 역량을 키우고 싶은 보안 학습자를 위해, 직접 실행 가능한 코드와 체계적인 방법론을 한데 모았습니다.  
CTF·버그바운티·레드팀·AI 보안까지, **처음부터 한국어로 기획된 실전 중심 지식 허브**입니다.

**VibeHacking**만의 강점:

- **실전 코드 우선** — 모든 섹션에 복사-붙여넣기 가능한 명령어와 코드 포함
- **AI 통합** — Claude/GPT-5.4-Cyber를 보안 분석 도구로 활용하는 방법 포함
- **최신 동향** — 2026년 Anthropic Mythos, OpenAI GPT-5.4-Cyber 등 최첨단 AI 보안 생태계 반영
- **한국어 완성도** — 단순 번역이 아닌, 처음부터 한국어로 기획·작성
- **완전한 커버리지** — 버그바운티·SOC·클라우드·WiFi·암호학·레드팀까지 전 영역

---

## 목차

| # | 섹션 | 핵심 내용 | 파일 수 |
|---|------|-----------|---------|
| 01 | [Linux 기초 & Kali Linux](#01-linux-기초--kali-linux) | 필수 명령어, Kali 셋업, Bash 스크립팅 | 3 |
| 02 | [네트워크 해킹](#02-네트워크-해킹) | OSI/TCP-IP, 패킷 분석, 무선 해킹 | 3 |
| 03 | [시스템 해킹](#03-시스템-해킹) | 비밀번호 크랙, Buffer Overflow | 2 |
| 04 | [리버스 엔지니어링](#04-리버스-엔지니어링) | 어셈블리, OllyDbg, PE 구조 | 3 |
| 05 | [웹 해킹](#05-웹-해킹) | OWASP Top 10, SQLi 심화, XSS/CSRF | 3 |
| 06 | [악성코드 분석](#06-악성코드-분석) | 정적/동적 분석, Volatility, 안드로이드 | 3 |
| 07 | [디지털 포렌식](#07-디지털-포렌식) | 포렌식 절차, Windows 아티팩트, 네트워크 | 3 |
| 08 | [파이썬 해킹](#08-파이썬-해킹) | 도구 개발, 네트워크 스캐너, 웹 자동화 | 3 |
| 09 | [익스플로잇 기법](#09-익스플로잇-기법) | ROP Chain, SEH, Linux BOF, 권한 상승 | 2 |
| 10 | [침투 테스트 방법론](#10-침투-테스트-방법론) | 모의해킹 절차, OSINT 정찰, 보고서 작성 | 3 |
| 11 | [**AI 기반 사이버보안**](#11-ai-기반-사이버보안) | Mythos, GPT-5.4-Cyber, LLM 취약점 연구, CTF 자동화 | 4 |
| 12 | [**버그바운티**](#12-버그바운티) | 방법론, Burp Suite 심화, 자동화 도구 | 3 |
| 13 | [**SOC & Blue Team**](#13-soc--blue-team) | SOC 운영, Splunk 분석, 위협 헌팅 | 3 |
| 14 | [**클라우드 보안**](#14-클라우드-보안) | AWS/Azure/GCP 공격벡터, 침투테스트, 체크리스트 | 3 |
| 15 | [**WiFi 해킹**](#15-wifi-해킹) | WPA2 크랙, PMKID, Evil Twin, 자동화 | 3 |
| 16 | [**암호학**](#16-암호학) | 해커를 위한 암호학, 해시 공격, 응용 암호학 | 3 |
| 17 | [**레드팀 운영**](#17-레드팀-운영) | 플레이북, 피싱/사회공학, API 해킹 | 3 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST, 컨테이너 보안, CI/CD 파이프라인 | 3 |
| 19 | [**어셈블리 언어**](#19-어셈블리-언어) | x86/x64 기초, 셸코드 개발, 디스어셈블리 분석 | 3 |
| 20 | [**셸 스크립팅**](#20-셸-스크립팅) | Bash 기초, 침투 자동화, 사후 익스플로잇 | 3 |
| 21 | [**Windows 익스플로잇**](#21-windows-익스플로잇) | Windows 내부 구조, 권한 상승, 방어 우회 | 3 |
| 22 | [**패스워드 크래킹**](#22-패스워드-크래킹) | 해시 종류/워드리스트, Hashcat/John, 고급 기법 | 3 |
| 23 | [**Database Hacking**](#23-database-hacking) | Oracle/MySQL 공격, DB 권한 상승, 포렌식·감사 | 3 |
| 24 | [**네트워크 인프라 보안**](#24-네트워크-인프라-보안) | DNS 공격, 메일 서버(SPF/DKIM/DMARC), SSH 터널링 | 3 |
| 25 | [**위협 인텔리전스**](#25-위협-인텔리전스) | CTI 기초, OSINT/Shodan, 인시던트 대응, 허니팟 | 3 |
| 26 | [**Linux Hardening**](#26-linux-hardening) | iptables/nftables, PAM 인증, KISA 취약점 평가 | 3 |
| 27 | [**IoT 해킹**](#27-iot-해킹) | 공격 면 분석, 펌웨어 분석, IoT 익스플로잇 | 3 |
| 28 | [**모바일 해킹**](#28-모바일-해킹) | Android 펜테스팅, iOS 펜테스팅, 모바일 트래픽 분석 | 3 |
| 29 | [**컨테이너/쿠버네티스 보안**](#29-컨테이너쿠버네티스-보안) | Docker 보안, Kubernetes 공격, 컨테이너 탈출 | 3 |
| 30 | [**취약점 연구**](#30-취약점-연구) | 퍼징 기법, 취약점 분석, 고급 익스플로잇 개발 | 3 |
| 31 | [**AI/ML 시스템 보안**](#31-aiml-시스템-보안) | 적대적 예제, 프롬프트 인젝션, 모델 추출, 에이전트 보안 | 4 |
| 32 | [**네트워크 장비 해킹**](#32-네트워크-장비-해킹) | IOS 정찰, L2 공격, 라우팅 프로토콜 조작, 관리 평면 익스플로잇 | 4 |
| 33 | [**OSINT & 소셜 엔지니어링**](#33-osint--소셜-엔지니어링) | 정보 수집 방법론, 타겟 프로파일링, 피싱 인프라 구축·우회 | 4 |
| 34 | [**하드웨어 해킹**](#34-하드웨어-해킹) | 인터페이스 분석(UART/JTAG/SPI), 펌웨어 추출·분석, 사이드채널·폴트 인젝션 | 4 |
| 35 | [**공급망 공격**](#35-공급망-공격) | 소프트웨어 공급망 침해, CI/CD 파이프라인 독화, SolarWinds·XZ 패턴 분석 | 3 |
| 36 | [**자동차 해킹**](#36-자동차-해킹) | CAN 버스 분석, ECU 익스플로잇, 텔레매틱스·OTA 공격 | 4 |
| 37 | [**ICS/SCADA 보안**](#37-icsscada-보안) | ICS 프로토콜 정찰, SCADA 익스플로잇, OT 네트워크 공격·방어 | 4 |

---

## 학습 로드맵

```
[입문]
  Linux 기초  ──►  네트워크 기초  ──►  웹 해킹 입문
                                             │
[중급]                                        ▼
  시스템 해킹  ◄──  파이썬 자동화  ◄──  악성코드 분석
       │
       ▼
[고급]
  리버스 엔지니어링  ──►  익스플로잇 개발  ──►  침투 테스트 방법론
                                                        │
[전문가]                                                 ▼
  WiFi 해킹  ──►  클라우드 보안  ──►  레드팀 운영  ──►  버그바운티
  암호학     ──►  SOC/Blue Team  ──►  AI 보안 연구  ──►  DevSecOps
```

---

## 실습 환경

| 구성 요소 | 권장 사항 |
|-----------|-----------|
| 공격자 머신 | Kali Linux 2024.x |
| 가상화 | VMware Workstation / VirtualBox |
| 취약 환경 | Metasploitable2, DVWA, HackTheBox, TryHackMe, CloudGoat |
| 분석 도구 | Wireshark, Burp Suite, IDA Pro / Ghidra, OllyDbg |
| 언어 | Python 3.x, Bash, pwntools |
| AI 도구 | Claude Opus 4.6, GPT-5.4-Cyber (TAC 인증) |
| 무선 | Alfa AWUS036ACH (2.4/5GHz 모니터 모드 지원) |
| 클라우드 | AWS Free Tier, CloudGoat |

---

## 01. Linux 기초 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← 파일/프로세스/네트워크 필수 명령어
├── 02_kali_linux_setup.md           ← Kali 초기 설정, 도구 설치
└── 03_bash_scripting.md             ← 자동화 스크립팅, 실전 예제
```

**핵심 내용:** 파일 시스템, 프로세스 관리, 네트워크 명령, 권한 관리, Bash 자동화 스크립트 30+

---

## 02. 네트워크 해킹

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI 7계층, TCP/IP 스택, 프로토콜 분석
├── 02_packet_analysis.md    ← Wireshark 실전, tcpdump, 패킷 조작
└── 03_wireless_hacking.md   ← WEP/WPA2 크랙, Evil Twin, 무선 해킹
```

**핵심 내용:** 패킷 캡처·분석, ARP 스푸핑, MITM, 무선 네트워크 공격, 방화벽 우회

---

## 03. 시스템 해킹

```
03_System_Hacking/
├── 01_password_cracking.md          ← Hashcat, John, Rainbow Table, 온라인 크랙
├── 02_buffer_overflow.md            ← 스택 BOF 원리, 쉘코드, 실습 예제
├── 03_active_directory_attack.md    ← AD 공격 완전 가이드, Kerberoasting, DCSync
└── 04_kerberos_delegation_attacks.md ← 비제약/제약/RBCD 위임 공격 완전 실습
```

**핵심 내용:** 해시 크래킹 전략, BOF 원리부터 익스플로잇까지, Active Directory 공격 체인 완전 정복, Kerberos 위임(Unconstrained/Constrained/RBCD) 공격 체인

---

## 04. 리버스 엔지니어링

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md        ← x86/x64 어셈블리, 레지스터, 스택 프레임
├── 02_ollydbg_practical.md             ← OllyDbg/x64dbg 실전 분석
├── 03_pe_structure.md                  ← PE 파일 구조, IAT/EAT, 패킹
└── 04_ghidra_and_dynamic_analysis.md   ← Ghidra 완전 정복 + WorstFit Unicode 취약점
```

**핵심 내용:** 어셈블리 언어, 디버거 사용법, PE 구조 심층 분석, Ghidra 실전 분석·PyGhidra 자동화, WorstFit Best-Fit 매핑 공격 (CVE-2024-21338 등)

---

## 05. 웹 해킹

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10 (2021), Burp Suite, Nikto
├── 02_sql_injection_advanced.md   ← Blind/Time-based SQLi, NoSQL, SQLMap 실전
├── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS, CSRF, 웹쉘
└── 04_waf_bypass_advanced_web.md  ← WAF 탐지·우회 완전 치트시트, XFF 주입, Cache Poisoning
```

**핵심 내용:** OWASP Top 10 실습, SQL Injection 완전 정복, XSS/CSRF/파일 업로드/XXE/SSRF, WAF 우회 전기법 (Cloudflare/AWS WAF/ModSecurity), HTTP Request Smuggling, Web Cache Poisoning

---

## 06. 악성코드 분석

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 분류, 분석 환경, 정적/동적 분석, YARA
├── 02_memory_forensics_malware.md    ← Volatility 완전 정복, 코드 인젝션 탐지
└── 03_android_malware_analysis.md    ← APK 분석, Frida 후킹, MobSF
```

**핵심 내용:** 정적·동적·메모리 분석 전 과정, Volatility 플러그인, 안드로이드 악성코드

---

## 07. 디지털 포렌식

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← 포렌식 원칙, 증거 수집, 이미지 분석
├── 02_windows_forensics_artifacts.md     ← 레지스트리, 이벤트 로그, Prefetch, 브라우저
└── 03_network_forensics.md               ← Wireshark, Zeek, Suricata, 침해 대응
```

**핵심 내용:** 증거 수집 절차, Windows 아티팩트 완전 분석, 네트워크 포렌식, 타임라인 분석

---

## 08. 파이썬 해킹

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← 포트 스캐너·스니퍼·백도어 등 30가지 예제
├── 02_python_network_scanner.md     ← 멀티스레드 스캐너, ARP, DNS 열거, SSH 브루트포서
└── 03_python_web_exploitation.md    ← 웹 크롤러, SQLi 자동화, XSS 스캐너, 보고서 생성
```

**핵심 내용:** Scapy, paramiko, requests 활용 보안 도구 개발, 완전 동작하는 코드 50+

---

## 09. 익스플로잇 기법

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain, Heap Spray, SEH, Win32 셸코딩
├── 02_linux_exploitation.md      ← Linux BOF, Ret2Libc, 포맷 스트링, 권한 상승
└── 03_heap_exploitation.md       ← tcache 포이즈닝, UAF, House of 시리즈, pwndbg
```

**핵심 내용:** DEP/ASLR/NX 우회, ROP 체인 구성, 포맷 스트링 익스플로잇, 힙 익스플로잇 완전 정복

---

## 10. 침투 테스트 방법론

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← 전체 모의해킹 절차, MITRE ATT&CK, 보고서 작성
├── 02_osint_recon.md           ← Google Dorks, Shodan, 서브도메인 열거, GitHub 비밀 탐지
└── 03_report_writing.md        ← 전문 보고서 작성, CVSS 산정, PoC 작성, 경영진/기술 보고서 템플릿
```

**핵심 내용:** 체계적 침투 테스트 방법론, OSINT 도구 완전 활용, 전문 보고서 작성 (CVSS·PoC·규정 준수 포함)

---

## 11. AI 기반 사이버보안

> **2026년 현재, AI가 사이버보안의 판도를 바꾸고 있다.**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Mythos·GPT-5.4-Cyber·Project Glasswing 전체 지형도
├── 02_llm_vulnerability_research.md   ← LLM으로 제로데이 발견, AI 퍼징, 코드 분석 자동화
├── 03_ai_assisted_pentesting.md       ← AI 보조 침투 테스트 워크플로우, 프롬프트 엔지니어링
└── 04_ai_ctf_automation.md            ← CTF 자동화 AI 에이전트, 암호학·웹·포렌식 전문 서브에이전트
```

### 2026년 AI 보안 지형도

| 모델 | 주체 | 능력 | 접근 방법 |
|------|------|------|-----------|
| **Claude Mythos** | Anthropic | 17년 된 FreeBSD RCE 자율 발견, 수천 개 제로데이 | Project Glasswing (12개 파트너사만) |
| **GPT-5.4-Cyber** | OpenAI | 바이너리 리버싱, CTF 76% 자율 해결, YARA 생성 | TAC 인증 (chatgpt.com/cyber) |
| **Claude Opus 4.6** | Anthropic | 코드 취약점 분석, CTF 보조, YARA 자동화 | 일반 접근 가능 |

**핵심 내용:** AI 보안 생태계 완전 분석, Claude API 기반 취약점 스캐너 구현, AI 보조 침투 테스트 자동화, CTF 풀이 AI 에이전트 (암호학·웹·포렌식·리버싱 전문 서브에이전트 포함)

---

## 12. 버그바운티

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd 방법론, IDOR, XSS 우회, 자동화
├── 02_burp_suite_advanced.md      ← Burp Suite 완전 정복, JWT 공격, Request Smuggling
├── 03_bug_bounty_automation.md    ← Nuclei, ffuf, dalfox, 자동화 파이프라인
└── 04_api_security_testing.md     ← OWASP API Top 10 (2023) 완전 실습, GraphQL 공격, BOLA 자동화
```

**핵심 내용:** 버그바운티 전체 워크플로우, Burp Suite 고급 기능, 정찰→취약점→보고서 자동화, OWASP API Security Top 10 전 취약점 실습 (BOLA/Mass Assignment/JWT/SSRF), GraphQL Batching 공격

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md          ← SOC 구조, 인시던트 대응, 핵심 이벤트 ID, EDR
├── 02_splunk_siem_analysis.md      ← Splunk SPL 완전 정복, 100+ 탐지 쿼리
├── 03_threat_hunting.md            ← 위협 헌팅, 랜섬웨어 침해 조사, APT 추적
└── 04_qradar_xdr_blue_team.md      ← IBM QRadar AQL 심화 + Microsoft Sentinel KQL + XDR 플랫폼 비교
```

**핵심 내용:** SOC 티어별 역할, 공격 탐지 패턴 100+, Splunk/QRadar AQL/Sentinel KQL/Cortex XQL 쿼리, XDR 플랫폼(CrowdStrike/SentinelOne/Defender XDR), Blue Team Field Manual 절차, SOC 40 필수 도구

---

## 14. 클라우드 보안

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s 공격 벡터 완전 분석
├── 02_aws_pentest.md                 ← AWS 침투 테스트 방법론, 권한 상승, 자동화
└── 03_cloud_security_checklist.md    ← CIS 체크리스트, Terraform, SCP 정책
```

**핵심 내용:** IAM 권한 남용, S3 오설정, 컨테이너 이스케이프, Kubernetes 공격, 클라우드 보안 체크리스트

---

## 15. WiFi 해킹

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3 이론, aircrack-ng 기초
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack, PMKID 공격, 워드리스트 최적화
└── 03_advanced_wifi_attacks.md       ← Evil Twin, KARMA, Bettercap, Scapy 조작
```

**핵심 내용:** 4-Way Handshake, PMKID 수집, GPU 크래킹, Evil Twin 구축, 무선 자동화

---

## 16. 암호학

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AES 모드 공격, RSA 취약점, XOR 크래킹
├── 02_hash_attacks.md               ← MD5 충돌, 레인보우 테이블, Kerberoasting
└── 03_applied_cryptography.md       ← Padding Oracle, ECDSA 논스 재사용, JWT 공격
```

**핵심 내용:** 암호 구현 취약점, CTF 암호학 문제 패턴, 안전한 암호화 구현 가이드

---

## 17. 레드팀 운영

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md              ← 운영 구조, Cobalt Strike/Havoc, AV/EDR 우회
├── 02_phishing_and_social_engineering.md ← GoPhish, Evilginx2, 스피어피싱, BEC
└── 03_api_hacking.md                    ← OWASP API Top 10, GraphQL, 퍼저 개발
```

**핵심 내용:** 레드팀 vs 펜테스트 차이, C2 프레임워크 운영, 피싱 인프라, API 취약점 완전 정복

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left, Semgrep, SonarQube, Snyk, ZAP
├── 02_container_security.md        ← Dockerfile 보안, Trivy, Falco, K8s RBAC, cosign
└── 03_github_actions_security.md   ← CI/CD 보안, OIDC, SHA 핀닝, 전체 보안 파이프라인
```

**핵심 내용:** 보안 내재화(Shift Left), SAST/SCA/DAST/IaC 스캔 자동화, 컨테이너 런타임 탐지, GitLab/Jenkins/GitHub Actions 보안 파이프라인 완전 구현

---

## 19. 어셈블리 언어

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← 레지스터, 명령어, 스택 프레임, 호출 규약
├── 02_Shellcode_Development.md  ← 셸코드 작성, bad byte 제거, ctypes 실행 테스트
└── 03_Disassembly_Analysis.md   ← GDB/pwndbg, IDA/Ghidra, Capstone 자동화
```

**핵심 내용:** x86/x64 레지스터 완전 정복, NASM 코딩, 64비트 execve 셸코드 구현, Capstone 기반 자동 디스어셈블러

---

## 20. 셸 스크립팅

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← 변수/배열/조건/반복/함수, awk/sed, 포트 스캐너
├── 02_Pentest_Automation.md          ← 정찰 자동화, 서브도메인 열거, 취약점 스캔 래퍼
└── 03_Post_Exploitation_Scripts.md   ← 리버스 셸, 지속성 확보, Python C2 소켓 구현
```

**핵심 내용:** Bash 실전 스크립팅, 정찰~사후 익스플로잇 전 과정 자동화, 리버스 셸 원라이너 7종, Python C2 구현

---

## 21. Windows 익스플로잇

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PE 포맷, PEB/TEB, WinAPI 핵심 함수, PE 파서 코드
├── 02_Windows_Privilege_Escalation.md   ← 서비스/레지스트리/DLL 하이재킹, UAC 바이패스, 토큰 임퍼스네이션
└── 03_Defense_Evasion.md                ← AMSI/ETW 우회, 프로세스 인젝션 6종, LOLBAS, AES 페이로드 암호화
```

**핵심 내용:** Windows 내부 구조 심층 분석, 권한 상승 완전 정복, AMSI/AV/EDR 우회 기법

---

## 22. 패스워드 크래킹

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← 해시 알고리즘 비교, hashid, CeWL/Crunch/CUPP, Python 크래커
├── 02_Hashcat_and_John.md              ← 전체 공격 모드, 해시 타입별 모드 번호, 규칙 작성, 실전 워크플로우
└── 03_Advanced_Cracking_Techniques.md  ← 레인보우 테이블, PRINCE, 마스크 고급, 패스워드 스프레이 도구
```

**핵심 내용:** NTLM/WPA/ZIP/PDF 크래킹 전략, GPU 최적화, 레이트 리밋 우회 패스워드 스프레이 자동화

---

## 23. Database Hacking

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL 공격 벡터, 블라인드 SQLi, OOB 추출
├── 02_db_privilege_escalation.md   ← DB 사용자 권한 상승, 저장 프로시저 악용, UDF 인젝션
├── 03_db_forensics_defense.md      ← 데이터베이스 포렌식, 감사 로그, 쿼리 모니터링, 하드닝
└── README.md
```

**핵심 내용:** 다중 DB 공격 체인, DB 엔진 경유 권한 상승, 포렌식 분석 및 방어 강화

---

## 24. 네트워크 인프라 보안

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNS 하이재킹, 영역 전송, 캐시 포이즈닝, DNSSEC 우회
├── 02_mail_server_security.md              ← SPF/DKIM/DMARC 우회, 메일 서버 침해, 이메일 스푸핑
├── 03_ssh_tunneling_port_forwarding.md     ← SSH 터널링, 동적 포트 포워딩, SOCKS 프록시, 피버팅
└── README.md
```

**핵심 내용:** DNS/메일/SSH 인프라 레벨 공격, 서비스 익스플로잇, 피버팅을 통한 횡이동

---

## 25. 위협 인텔리전스

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTI 프레임워크(MITRE ATT&CK/STIX/TAXII), 위협 행위자 프로파일링
├── 02_osint_for_threat_intel.md    ← Shodan/Censys 자동화, 다크웹 OSINT, IOC 수집 파이프라인
├── 03_incident_response.md         ← IR 플레이북, 증거 수집, 악성코드 트리아지, 허니팟
└── README.md
```

**핵심 내용:** CTI 라이프사이클, 위협 행위자 귀속 분석, IOC 관리, 자동화 인시던트 대응 절차

---

## 26. Linux Hardening

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufw 규칙, 방화벽 감사, 상태 기반 필터링
├── 02_pam_and_auth_hardening.md         ← PAM 설정, SSH 하드닝, MFA 구성, sudo 정책
├── 03_kisa_vulnerability_assessment.md  ← KISA 보안 체크리스트, CIS 벤치마크, 자동화 평가 스크립트
└── README.md
```

**핵심 내용:** 방화벽 규칙 설계, 인증 강화, KISA/CIS 준수 자동화 보안 평가

---

## 27. IoT 해킹

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← IoT 공격 면 분석, OWASP IoT Top 10, Shodan/Censys 스캐닝
├── 02_firmware_analysis.md     ← 펌웨어 추출·분석, binwalk/Ghidra, 하드코딩 취약점 탐지
└── 03_iot_exploitation.md      ← UART/JTAG 접근, 임베디드 익스플로잇, 실전 공격 시나리오
```

**핵심 내용:** OWASP IoT Top 10 기반 공격 면 분석, 펌웨어 역공학(binwalk·Ghidra), UART/JTAG 하드웨어 해킹, IoT 장비 실전 침투

---

## 28. 모바일 해킹

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK 분석, ADB 루팅, Frida 동적 계측, SSL Pinning 우회
├── 02_ios_pentesting.md            ← IPA 추출, Objective-C/Swift 리버싱, Jailbreak 탐지 우회
└── 03_mobile_traffic_analysis.md   ← Burp Suite 모바일 프록시, 인증서 고정 우회, API 퍼징
```

**핵심 내용:** Android/iOS 완전 분석 파이프라인, Frida 기반 런타임 계측, 모바일 트래픽 중간자 공격, SSL Pinning 우회 기법

---

## 29. 컨테이너/쿠버네티스 보안

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Docker 보안 설정, 컨테이너 탈출 기법, 이미지 취약점 스캐닝
├── 02_kubernetes_attack.md    ← RBAC 권한 상승, etcd 탈취, Kubernetes 공격 벡터 완전 분석
└── 03_container_escape.md     ← cgroup/namespace 탈출, runc 취약점, 실전 컨테이너 탈출 PoC
```

**핵심 내용:** Docker/Kubernetes 공격·방어 전략, RBAC 권한 상승, 컨테이너 탈출 기법, Trivy·Falco 기반 런타임 보안

---

## 30. 취약점 연구

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz, 커버리지 기반 퍼징, 네트워크 퍼징
├── 02_vulnerability_analysis.md        ← CVSS 분석, CWE 분류, 정적/동적 분석, 소스 코드 감사
└── 03_exploit_development_advanced.md  ← 고급 힙 익스플로잇, 브라우저 익스플로잇, 커널 취약점 개발
```

**핵심 내용:** AFL++/libFuzzer 기반 자동화 취약점 탐지, CVSS·CWE 체계적 분석, 고급 힙/브라우저/커널 익스플로잇 개발

---

## 31. AI/ML 시스템 보안

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W, 전이 공격, adversarial training·randomized smoothing 방어
├── 02_prompt_injection_jailbreak.md   ← 직접·간접 프롬프트 인젝션, 탈옥, garak/PyRIT 자동 레드팀
├── 03_model_extraction_inversion.md   ← 모델 추출, 멤버십 추론(LiRA), 학습 데이터 재구성, DP-SGD 방어
└── 04_llm_agent_security.md           ← 도구 호출 SSRF/RCE, RAG 인덱스 오염, MCP 보안, 더블 LLM 아키텍처
```

**관점 차이:** 섹션 11이 "AI를 공격 도구로 사용"하는 쪽이라면, 섹션 31은 **AI/ML 시스템 자체가 표적**인 공격과 방어를 다룹니다. OWASP LLM Top 10·NIST AI 100-2·MITRE ATLAS 분류 체계 기반, 재현 가능한 PyTorch/Anthropic SDK PoC 포함.

---

## 32. 네트워크 장비 해킹

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE 구조, 장비 핑거프린팅, 관리 프로토콜 정찰
├── 02_layer2_attacks.md                  ← VLAN hopping, STP/DHCP 공격, CAM overflow, DAI 우회
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP 경로 주입, HSRP/VRRP 하이재킹
└── 04_management_plane_exploitation.md   ← SNMP·TACACS+·NETCONF·설정 파일 추출, 장비 백도어 식별
```

**관점 차이:** 섹션 02가 트래픽 스니핑·MITM 관점, 섹션 24가 DNS·메일·SSH 등 서비스 레벨 관점이라면, 섹션 32는 **라우터·스위치 자체의 관리/제어/데이터 평면**을 직접 공격합니다. 2025–2026 Cisco/FRRouting CVE(CVE-2025-20188, CVE-2026-20084 등) 재현 PoC와 GNS3·EVE-NG 실습 토폴로지 포함.

---

## 33. OSINT & 소셜 엔지니어링

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← 정보 수집 방법론, Shodan/Censys/FOFA, dorking 고급 기법
├── 02_target_profiling.md              ← 인물·조직 프로파일링, SNS 분석, 이메일 검증, 도메인 정찰
├── 03_social_engineering_attacks.md    ← 피싱·스피어피싱·비싱·스미싱, BEC, 프리텍스팅
└── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2 인프라, URL 우회, 안티피싱 탐지 우회
```

OSINT를 단순 정보 검색이 아닌 **공격 체인의 정찰 단계**로 활용하는 방법론에 집중합니다. Shodan·FOFA·Censys 쿼리 자동화, LinkedIn/GitHub/SNS 기반 타겟 프로파일링, GoPhish·Evilginx2 피싱 인프라 구축까지 레드팀 실전 관점으로 다룹니다.

---

## 34. 하드웨어 해킹

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md  ← UART/JTAG/SPI/I²C 인터페이스 식별·덤프, 핀아웃 분석
├── 02_firmware_analysis.md              ← binwalk 추출, 파일시스템 분석, 하드코딩 비밀, 취약 함수 탐지
├── 03_side_channel_and_fault_injection.md ← 전력 분석(SPA/DPA), 타이밍 공격, 글리칭, ChipWhisperer
└── README.md
```

전자 장치 자체의 물리적 공격 표면을 다룹니다. UART 시리얼 콘솔로 root 셸을 획득하고, JTAG로 펌웨어를 통째로 덤프하며, 사이드채널 분석으로 암호화 키를 추출하는 기법까지 — IoT·임베디드·하드웨어 보안 연구의 핵심 기술을 실전 도구(minicom, OpenOCD, binwalk, ChipWhisperer)와 함께 정리했습니다.

---

## 35. 공급망 공격

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← 오픈소스 패키지 독화, typosquatting, 의존성 혼동 공격
├── 02_build_and_ci_poisoning.md  ← CI/CD 파이프라인 침해, GitHub Actions 악용, SolarWinds·XZ Utils 패턴
└── README.md
```

SolarWinds·XZ Utils·3CX 등 실제 공급망 침해 사례를 해부합니다. PyPI·npm·Maven 패키지 독화 기법, GitHub Actions 워크플로 권한 탈취, 빌드 시스템 백도어 삽입까지 — 소프트웨어 개발 파이프라인 전 과정이 공격 표면임을 보여주는 실전 분석입니다.

---

## 36. 자동차 해킹

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CAN 버스 구조, OBD-II 진단, 메시지 스니핑·재전송
├── 02_ecu_exploitation.md           ← ECU 펌웨어 분석, UDS 진단 프로토콜 악용, 리맵핑
├── 03_telematics_and_ota_attacks.md ← V2X 통신, 텔레매틱스 유닛 침투, OTA 업데이트 가로채기
└── README.md
```

현대 자동차는 100개 이상의 ECU와 수십 가지 통신 프로토콜이 얽힌 이동하는 컴퓨터입니다. CAN 버스 스니핑부터 UDS 진단 프로토콜 악용, 텔레매틱스 원격 공격, Jeep Cherokee·Tesla 실제 해킹 재현까지 — 자동차 보안 연구의 전 스택을 python-can·Scapy·CANalyzer 관점으로 다룹니다.

---

## 37. ICS/SCADA 보안

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP 심화, Shodan 정찰, 멀티프로토콜 스캐너
├── 02_scada_exploitation.md       ← HMI/Historian/PLC 취약점, TRITON·INDUSTROYER 분석, SCADA 스캐너
├── 03_ot_network_attacks.md       ← Purdue 계층별 공격, IT→OT 횡이동, 무선 OT, OT 토폴로지 매퍼
└── README.md
```

발전소·정유·수처리·철도 등 핵심 인프라를 제어하는 ICS/OT 환경을 분석합니다. Stuxnet·TRITON·INDUSTROYER·PIPEDREAM 등 실제 사이버 무기를 해부하고, Modbus 코일 강제 쓰기부터 PLC DB 블록 패치, Historian 데이터 역주입, OT 전용 토폴로지 자동 매핑까지 — 가용성 최우선 환경의 공격과 방어를 실전 코드와 함께 정리했습니다.

---

## 주의사항

> **이 저장소의 모든 기법은 반드시 허가된 환경에서만 사용해야 합니다.**

- CTF, 버그바운티, 계약된 모의해킹 범위 내에서 활용
- 취약점 발견 시 책임있는 공개(Responsible Disclosure) 원칙 준수
- 무단 시스템 접근은 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 위반

---

<div align="center">

**⚔️ VibeHacking** — 실전 보안 전문가를 향한 여정

*Built with [Claude Code](https://claude.ai/code)*

</div>
