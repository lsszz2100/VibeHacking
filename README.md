<div align="center">

# ⚔️ VibeHacking

### 실전 사이버보안 완전 정복 — AI 시대의 해킹 바이블

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-55-blueviolet)](#목차)
[![Files](https://img.shields.io/badge/Docs-288%20Files-brightgreen)](#목차)
[![Lines](https://img.shields.io/badge/Lines-191%2C000%2B-orange)](#목차)
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
| 38 | [**Cloud Native 보안**](#38-cloud-native-보안) | CNAPP, eBPF 런타임 보안, 이미지 하드닝, 컨테이너 탈출 기법 | 4 |
| 39 | [**Zero Trust 아키텍처**](#39-zero-trust-아키텍처) | ZTA 원칙, 아이덴티티/장치 신뢰, 마이크로세그멘테이션, SASE | 4 |
| 40 | [**위협 헌팅**](#40-위협-헌팅) | 헌팅 방법론, MITRE ATT&CK 시나리오, KQL/SPL 쿼리 100+, SOAR 자동화 | 4 |
| 41 | [**한국 정보보안 자격증**](#41-한국-정보보안-자격증) | 정보보안기사·ISMS-P·CISSP/OSCP 로드맵, 보안 법령 | 5 |
| 42 | [**블록체인/Web3 보안**](#42-블록체인web3-보안) | EVM 구조, 스마트 컨트랙트 감사, DeFi 공격, Web3 침투 도구 | 4 |
| 43 | [**물리적 침투 테스트**](#43-물리적-침투-테스트) | 물리 보안 방법론, 잠금장치 우회, RFID 클로닝, 사회공학 | 4 |
| 44 | [**인시던트 대응/DFIR**](#44-인시던트-대응dfir) | IR 플레이북, 메모리·디스크 포렌식, 네트워크 포렌식, 박멸·복구 | 4 |
| 45 | [**악성코드 개발**](#45-악성코드-개발) | PE 구조, 셸코드·인젝션, C2 프레임워크, AV/EDR 우회 | 4 |
| 46 | [**CTF 기법**](#46-ctf-기법) | CTF 방법론·도구, PWN/REV, Web/Crypto, 자동화 프레임워크 | 4 |
| 47 | [**모바일 포렌식**](#47-모바일-포렌식) | Android/iOS 포렌식, 증거 추출, 모바일 포렌식 도구 | 4 |
| 48 | [**위협 모델링**](#48-위협-모델링) | STRIDE/PASTA/DREAD, Attack Tree, 위협 모델링 도구 | 4 |
| 49 | [**레드팀 인프라**](#49-레드팀-인프라) | C2 프레임워크, 도메인 프론팅, OPSEC, 인프라 자동화 | 4 |
| 50 | [**게임 해킹**](#50-게임-해킹) | 메모리 조작, Cheat Engine, 패킷 조작, 안티치트 분석 | 4 |
| 51 | [**브라우저 확장 보안**](#51-브라우저-확장-보안) | MV2/V3, 악성 확장 분석, Content Script XSS, 하드닝 | 4 |
| 52 | [**API 보안**](#52-api-보안) | OWASP API Top 10, BOLA, GraphQL, 퍼징, OAuth2 | 4 |
| 53 | [**서버리스 보안**](#53-서버리스-보안) | Lambda 공격, 이벤트 인젝션, IAM 남용, IaC 스캔 | 4 |
| 54 | [**Active Directory 공격**](#54-active-directory-공격) | AD 열거, Kerberoasting, DCSync, Golden Ticket | 4 |
| 55 | [**탐지 우회 기법**](#55-탐지-우회-기법) | AV/EDR 우회, IDS/IPS 우회, syscall, 흔적 제거 | 4 |
| 🧪 | [**CTF 실습 환경 (labs/)**](#ctf-실습-환경-labs) | 웹·바이너리·네트워크·클라우드·통합 시나리오 도커 랩 5종 | 50 |

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

## 38. Cloud Native 보안

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE 위협 모델, CNAPP, 컨테이너·서버리스·서비스메시 위협
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium, eBPF 기반 런타임 탐지·네트워크 정책
├── 03_image_hardening_supply_chain.md   ← Trivy/Grype 이미지 스캔, Cosign 서명, SBOM, OPA Gatekeeper
└── 04_cloud_native_attack_techniques.md ← 컨테이너 탈출, 서비스메시 MITM, 서버리스 이벤트 주입, KSPM
```

Cloud Native 환경(Kubernetes·서버리스·서비스메시)에서의 공격·방어를 다룹니다. eBPF 기반 런타임 보안(Falco/Tetragon), 컨테이너 이미지 서명·SBOM, OPA 정책 게이트웨이부터 실제 컨테이너 탈출 기법, 서비스메시 MITM, AWS Lambda 이벤트 주입까지 — CNAPP 관점으로 정리했습니다.

---

## 39. Zero Trust 아키텍처

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorp 모델, NIST SP 800-207, ZTA 성숙도 모델
├── 02_identity_and_device_trust.md     ← IdP/MFA/패스키, 장치 신뢰(MDM/EDR), SCIM 프로비저닝
├── 03_microsegmentation_and_network.md ← 마이크로세그멘테이션, mTLS, SASE/SD-WAN, eBPF 네트워크 정책
└── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp 구현, ZTA 감사 자동화
```

"절대 신뢰하지 말고, 항상 검증하라" — NIST SP 800-207 기반 Zero Trust 아키텍처를 실무 관점에서 다룹니다. BeyondCorp 사례, 아이덴티티/장치 신뢰 체계, 마이크로세그멘테이션, SASE 도입까지 실전 구현 가이드와 ZTA 성숙도 자가 평가 도구를 포함합니다.

---

## 40. 위협 헌팅

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← 헌팅 사이클, 가설 기반 헌팅, PEAK 프레임워크, TTP 드리프트
├── 02_mitre_attack_hunting.md        ← ATT&CK 전술별 헌팅 시나리오, 그룹 프로파일, Atomic Red Team
├── 03_hunting_queries_kql_spl.md     ← Sentinel KQL/Splunk SPL 헌팅 쿼리 100+, 이상 탐지 패턴
└── 04_automated_threat_hunting.md    ← SOAR 자동화, ML 기반 이상 탐지, 헌팅 플레이북 자동화
```

로그가 말해주지 않는 것을 찾아내는 능동적 위협 헌팅을 다룹니다. PEAK 프레임워크 기반 가설 설정, MITRE ATT&CK 전술별 헌팅 시나리오, Sentinel KQL/Splunk SPL 쿼리 100+ 예제, SOAR 기반 자동화 플레이북까지 — SOC에서 즉시 적용 가능한 실전 헌팅 기법을 정리했습니다.

---

## 41. 한국 정보보안 자격증

```
41_Korean_Certifications/
├── 01_information_security_engineer.md           ← 정보보안기사 필기 핵심이론 (5과목 완전 정복)
├── 02_information_security_engineer_practical.md ← 실기 기출 유형, 암호화·네트워크·시스템 실습
├── 03_ISMS_P_certification.md                    ← ISMS-P 인증 체계, 80개 통제항목, 심사 준비
├── 04_international_certifications.md            ← CISSP/CEH/OSCP/CISA 로드맵, 도메인 비교
└── 05_security_laws_and_compliance.md            ← 개인정보보호법·정보통신망법·전자금융거래법, GDPR 비교
```

한국 정보보안 자격증(정보보안기사·ISMS-P)과 국제 자격증(CISSP/CEH/OSCP/CISA)을 한 곳에 정리했습니다. 법령·컴플라이언스(개인정보보호법·GDPR)까지 포함하여 국내 보안 실무자가 반드시 알아야 할 제도적 기반을 다룹니다.

---

## 42. 블록체인/Web3 보안

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md  ← EVM 구조, UTXO vs 계정 모델, 51% 공격, 이클립스 공격
├── 02_smart_contract_auditing.md              ← 재진입·오버플로우·delegatecall 취약점, Slither/Mythril, PoC
├── 03_defi_protocol_attacks.md               ← Flash Loan 공격, 오라클 조작, MEV 샌드위치, Rug Pull 탐지
└── 04_web3_pentest_tools.md                  ← Foundry/Cast/Anvil, RPC 보안 평가, CTF 이더리움 챌린지
```

블록체인 아키텍처부터 DeFi 해킹까지 Web3 보안 전 영역을 다룹니다. EVM 스토리지 레이아웃, 스마트 컨트랙트 자동 감사(Slither), Flash Loan 공격 분석, Foundry 기반 PoC 작성, RPC 보안 평가 CLI까지 실전 도구 중심으로 구성했습니다.

---

## 43. 물리적 침투 테스트

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md         ← PTES 물리 도메인, 허가서 구성, 취약점 체크리스트
├── 02_lock_bypass_and_access_control.md       ← 락피킹·범핑, REX 센서 공격, 접근 제어 로그 이상 탐지
├── 03_rfid_nfc_cloning.md                    ← EM4100/HID Proxmark3 클로닝, MIFARE nested 공격, nfcpy
└── 04_physical_recon_and_social_engineering.md ← OSINT 정찰, 테일게이팅, 프리텍스팅, 보고서 생성
```

허가된 물리적 침투 테스트의 전 과정을 다룹니다. PTES 방법론, 잠금장치 우회 기법, RFID/NFC 클로닝(Proxmark3/FlipperZero), 사회공학 기법, 접근 제어 로그 이상 탐지 CLI까지 실전 중심으로 구성했습니다.

---

## 44. 인시던트 대응/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md         ← NIST SP 800-61r2, 랜섬웨어·피싱 플레이북, 타임라인 CLI
├── 02_memory_and_disk_forensics.md            ← Volatility3, MFT 분석, 의심 프로세스 자동 플래깅 CLI
├── 03_network_forensics_and_log_analysis.md   ← Zeek 로그, Windows 이벤트 ID, PCAP C2 IOC 추출 CLI
└── 04_threat_containment_and_eradication.md   ← 격리·박멸·복구, VSS 복원, Windows 지속성 수집 CLI
```

인시던트 발생부터 복구까지 DFIR 전 과정을 다룹니다. NIST 기반 플레이북, Volatility3 메모리 포렌식, Zeek/Sysmon 로그 분석, PCAP C2 탐지, 랜섬웨어 복구 절차까지 실전 IR 도구 모음입니다.

---

## 45. 악성코드 개발

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PE 파일 구조, IAT 분석, 엔트로피 탐지, pefile CLI
├── 02_shellcode_and_injection_techniques.md    ← PIC 셸코드, XOR 인코더, 프로세스 인젝션 기법 비교
├── 03_c2_framework_development.md              ← HTTP C2 서버·에이전트, DNS 터널링, Cobalt Strike 비교
└── 04_av_edr_evasion.md                       ← 직접 시스템콜, NTDLL 언훅, ETW/AMSI 패치, 샌드박스 탐지
```

레드팀 작전과 보안 연구를 위한 악성코드 기술을 다룹니다. PE 구조 분석, 셸코드 인코딩, 다양한 프로세스 인젝션 기법, Python HTTP C2 구현, AV/EDR 우회 기법 등 — 허가된 레드팀·CTF·보안 연구 목적으로 작성했습니다.

---

## 46. CTF 기법

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md   ← CTF 유형, 분야별 도구셋, Docker pwnbox, 노트 자동화 CLI
├── 02_pwn_and_rev_ctf.md             ← ret2win/ret2libc/ROP/힙, pwntools 완전 템플릿, angr 크랙미
├── 03_web_and_crypto_ctf.md          ← 블라인드 SQLi 자동화, SSTI, JWT 공격, RSA CTF 솔버 CLI
└── 04_ctf_automation_and_frameworks.md ← DynELF, angr 자동화, Frida 계측, 포렌식 파이프라인, CTFd API
```

CTF 대회를 체계적으로 공략하는 방법을 다룹니다. 분야별 도구 체계, pwntools 완성형 익스플로잇 템플릿, angr/z3 심볼릭 실행, Frida 동적 계측, 포렌식 자동화 파이프라인, CTFd API 자동화까지 — 실전 CTF에서 즉시 사용 가능한 코드 모음입니다.

---

## 47. 모바일 포렌식

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Android 파일시스템·ADB 포렌식·SQLite 아티팩트·백업 파싱 CLI
├── 02_ios_forensics.md              ← iOS APFS 구조·iTunes 백업 파싱·iMessage/Health 데이터 추출 CLI
├── 03_mobile_evidence_extraction.md ← 논리/파일시스템/물리 추출·해시 무결성·자동 증거 수집 CLI
└── 04_mobile_forensics_tools.md     ← Autopsy·MVT·Frida·jadx·APK 자동 분석 CLI
```

Android/iOS 모바일 기기 포렌식 전 과정을 다룹니다. ADB 기반 아티팩트 추출, iTunes 백업 복호화/파싱, MVT로 Pegasus 스파이웨어 탐지, Frida 동적 분석, APK 역분석까지 — 법적 증거 무결성 유지 방법 포함.

---

## 48. 위협 모델링

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE 6범주·DFD 작성·신뢰경계·자동 분석 CLI
├── 02_pasta_dread_attack_trees.md   ← PASTA 7단계·DREAD 점수·Attack Tree·Kill Chain·MITRE ATT&CK
├── 03_threat_modeling_tools.md      ← MS TMT·Threat Dragon·IriusRisk·CI/CD 통합·XML→HTML 보고서 CLI
└── 04_threat_modeling_practice.md   ← 전자상거래/모바일뱅킹/K8s 실전 시나리오·완전 워크플로우 CLI
```

STRIDE·PASTA·DREAD 방법론을 실전에 적용합니다. DFD 작성부터 위협 식별, 완화 통제 도출, CI/CD 파이프라인 통합까지 — Python CLI 한 줄로 전체 위협 모델링 자동화.

---

## 49. 레드팀 인프라

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md              ← Cobalt Strike/Sliver/Havoc 구조·HTTP C2 구현·탐지 규칙
├── 02_domain_fronting_redirectors.md ← CDN 프론팅·Apache/Nginx 리다이렉터·DNS 터널링·트래픽 필터 CLI
├── 03_opsec_infrastructure.md       ← OPSEC 5단계·Long/Short Haul 분리·CT 로그·자동 OPSEC 점검 CLI
└── 04_red_team_automation.md        ← Ansible/Terraform 인프라·페이로드 파이프라인·캠페인 관리 CLI
```

레드팀 C2 인프라 구축과 OPSEC을 다룹니다. Sliver/Havoc 프레임워크, Apache 리다이렉터, DNS 터널링, Terraform AWS 인프라 자동화까지 — 허가된 레드팀·CTF·보안 연구 목적.

---

## 50. 게임 해킹

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← 게임 메모리 구조·ReadProcessMemory·AOB 스캔·포인터체인 CLI
├── 02_cheat_engine_advanced.md      ← CE Lua 스크립팅·자동어셈블러·구조체 분석·CT 파일 파서 CLI
├── 03_packet_manipulation.md        ← 게임 패킷 캡처·mitmproxy·protobuf 역분석·패킷 재전송 CLI
└── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye 구조·탐지 기법·프로세스 분석 CLI·CTF 유형
```

게임 보안 연구 및 CTF 게임 해킹을 다룹니다. Cheat Engine 메모리 조작, 패킷 중간자 분석, 안티치트 동작 원리 이해까지 — 교육·CTF·보안 연구 목적.

---

## 51. 브라우저 확장 보안

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md    ← MV2/V3 비교·Background/Content Script·CSP·공격 표면 분석
├── 02_malicious_extension_analysis.md ← 악성 확장 유형·IOC·난독화 분석·CRX 자동 분석 CLI
├── 03_extension_pentesting.md      ← Content Script XSS·Cross-extension 공격·Selenium 자동 스캔 CLI
└── 04_extension_security_hardening.md ← MV3 보안 강화·최소권한·기업 GPO·위험도 평가 CLI
```

Chrome/Firefox 확장 보안 전반을 다룹니다. 악성 확장 탐지 IOC, CRX 자동 분석, Content Script XSS/postMessage 공격, Selenium 기반 동적 취약점 스캐너, 기업 정책 관리까지.

---

## 52. API 보안

```
52_API_Security/
├── 01_rest_api_security.md         ← OWASP API Top 10·BOLA 스캐너·JWT 취약점 분석 CLI
├── 02_graphql_security.md          ← 인트로스펙션·배치 쿼리·깊이 공격·스키마 자동 분석 CLI
├── 03_api_fuzzing.md               ← ffuf·OpenAPI 기반 자동 퍼저·파라미터 오염·응답 분석 CLI
└── 04_api_security_hardening.md    ← OAuth2 PKCE·Rate Limiting·Kong/NGINX 게이트웨이·감사 CLI
```

REST·GraphQL API 취약점 전반을 다룹니다. BOLA 자동 스캐너, JWT 위조·크래킹, GraphQL 배치 공격·깊이 DoS, OpenAPI 기반 퍼저, OAuth2 PKCE 구현, API 게이트웨이 보안 설정까지.

---

## 53. 서버리스 보안

```
53_Serverless_Security/
├── 01_lambda_function_attacks.md   ← 환경 변수 탈취·IMDSv1 SSRF·이벤트 인젝션·런타임 탐지 CLI
├── 02_serverless_injection.md      ← SQS/S3 이벤트 인젝션·타이포스쿼팅·커맨드 인젝션 정적 분석
├── 03_serverless_iam_abuse.md      ← 역할 과다 권한·AssumeRole 체인·최소 권한 정책 자동 생성 CLI
└── 04_serverless_hardening.md      ← IaC 보안 스캔·Terraform 보안 설정·Lambda Extension·감사 CLI
```

AWS Lambda 서버리스 환경 공격·방어를 다룹니다. IMDSv1 SSRF, 이벤트 소스 인젝션, IAM 역할 남용, 타이포스쿼팅 탐지, IaC(Checkov/cfn-guard) 스캔, Lambda Extension 런타임 보호까지.

---

## 54. Active Directory 공격

```
54_Active_Directory_Attacks/
├── 01_ad_enumeration.md            ← BloodHound·LDAP 열거·SPN/AS-REP 계정 자동 열거 CLI
├── 02_kerberos_attacks.md          ← Kerberoasting·AS-REP Roasting·Pass-the-Ticket·자동화 CLI
├── 03_lateral_movement_ad.md       ← PtH·NTLM 릴레이·DCSync·다중 호스트 횡이동 자동화 CLI
└── 04_ad_persistence.md            ← Golden Ticket·Shadow Credentials·ACL 남용·지속성 탐지 CLI
```

Active Directory 침투 전 과정을 다룹니다. BloodHound 수집·Cypher 쿼리, Kerberoasting/AS-REP Roasting 자동화, NTLM 릴레이·DCSync, Golden/Silver Ticket, AdminSDHolder·Shadow Credentials 지속성까지.

---

## 55. 탐지 우회 기법

```
55_Evasion_Techniques/
├── 01_av_evasion.md                ← XOR 인코더·샌드박스 탐지·프로세스 인젝션·AMSI 우회 CLI
├── 02_ids_ips_evasion.md           ← 패킷 단편화·DNS 터널링·트래픽 위장·Snort 룰 분석 CLI
├── 03_edr_bypass.md                ← 직접 syscall·NTDLL 후킹 탐지·메모리 인젝션 탐지 CLI
└── 04_log_evasion.md               ← 이벤트 로그 조작·타임스탬프 위조·흔적 제거 자동화 CLI
```

AV/EDR/IDS 우회 기법 전반을 다룹니다. XOR/AES 페이로드 인코더, 샌드박스 탐지·분기, 직접/간접 syscall, NTDLL 후킹 탐지, DNS/ICMP 터널링, C2 트래픽 위장, 침투 후 흔적 제거 체크리스트까지.

---

## CTF 실습 환경 (labs/)

```
labs/
├── 01_web_hacking_lab/      ← SQLi·XSS·SSRF·JWT 취약 Flask 앱 (도커 기반)
├── 02_pwn_lab/              ← BOF·포맷스트링·힙 익스플로잇 취약 바이너리 환경
├── 03_network_lab/          ← 패킷 분석·MITM·ARP 스푸핑 pcap + 실습 환경
├── 04_cloud_container_lab/  ← 취약 Docker/K8s 환경, 컨테이너 탈출 시나리오
├── 05_full_scenario_lab/    ← 정찰→침투→횡이동→권한상승→유출 통합 시나리오
├── start_lab.sh             ← 전체 랩 docker-compose up 자동화
└── stop_all.sh              ← 전체 랩 종료
```

5개 도커 기반 CTF 취약 환경 — 웹·바이너리·네트워크·클라우드·통합 시나리오를 로컬에서 즉시 실습할 수 있습니다. 플래그 12개, `start_lab.sh` 한 번으로 전체 환경 기동.

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
