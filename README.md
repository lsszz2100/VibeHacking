<div align="center">

# ⚔️ VibeHacking

### 실전 사이버보안 완전 정복 — AI 시대의 해킹 바이블

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-17-blueviolet)](#목차)
[![Files](https://img.shields.io/badge/Docs-85%2B%20Files-brightgreen)](#목차)
[![Lines](https://img.shields.io/badge/Lines-35%2C000%2B-orange)](#목차)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai-기반-사이버보안)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-gray)](https://claude.ai/code)

<br/>

> 이론부터 실습까지, CTF·버그바운티·모의해킹·레드팀에 실전 투입 가능한 수준으로 정리한 한국어 보안 지식 저장소.
> **2026년 Mythos·GPT-5.4-Cyber 시대**의 AI 기반 취약점 연구부터 클라우드·무선·암호학까지 완전 정복.

</div>

---

## 왜 이 저장소인가

기존 보안 자료들은 이론에 치우치거나, 영어 자료의 단순 번역이거나, 최신 동향을 반영하지 못한다.

**VibeHacking**은 다르다:

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
| 10 | [침투 테스트 방법론](#10-침투-테스트-방법론) | 모의해킹 절차, OSINT 정찰 | 2 |
| 11 | [**AI 기반 사이버보안**](#11-ai-기반-사이버보안) | Mythos, GPT-5.4-Cyber, LLM 취약점 연구 | 3 |
| 12 | [**버그바운티**](#12-버그바운티) | 방법론, Burp Suite 심화, 자동화 도구 | 3 |
| 13 | [**SOC & Blue Team**](#13-soc--blue-team) | SOC 운영, Splunk 분석, 위협 헌팅 | 3 |
| 14 | [**클라우드 보안**](#14-클라우드-보안) | AWS/Azure/GCP 공격벡터, 침투테스트, 체크리스트 | 3 |
| 15 | [**WiFi 해킹**](#15-wifi-해킹) | WPA2 크랙, PMKID, Evil Twin, 자동화 | 3 |
| 16 | [**암호학**](#16-암호학) | 해커를 위한 암호학, 해시 공격, 응용 암호학 | 3 |
| 17 | [**레드팀 운영**](#17-레드팀-운영) | 플레이북, 피싱/사회공학, API 해킹 | 3 |

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
  암호학     ──►  SOC/Blue Team  ──►  AI 보안 연구
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
├── 01_password_cracking.md   ← Hashcat, John, Rainbow Table, 온라인 크랙
└── 02_buffer_overflow.md     ← 스택 BOF 원리, 쉘코드, 실습 예제
```

**핵심 내용:** 해시 크래킹 전략, BOF 원리부터 익스플로잇까지, setUID 취약점

---

## 04. 리버스 엔지니어링

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64 어셈블리, 레지스터, 스택 프레임
├── 02_ollydbg_practical.md        ← OllyDbg/x64dbg 실전 분석
└── 03_pe_structure.md             ← PE 파일 구조, IAT/EAT, 패킹
```

**핵심 내용:** 어셈블리 언어, 디버거 사용법, PE 구조 심층 분석, IDA Pro/Ghidra

---

## 05. 웹 해킹

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10 (2021), Burp Suite, Nikto
├── 02_sql_injection_advanced.md   ← Blind/Time-based SQLi, NoSQL, SQLMap 실전
└── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS, CSRF, 웹쉘
```

**핵심 내용:** OWASP Top 10 실습, SQL Injection 완전 정복, XSS/CSRF/파일 업로드/XXE/SSRF

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
└── 02_linux_exploitation.md      ← Linux BOF, Ret2Libc, 포맷 스트링, 권한 상승
```

**핵심 내용:** DEP/ASLR/NX 우회, ROP 체인 구성, 포맷 스트링 익스플로잇, pwntools 실전

---

## 10. 침투 테스트 방법론

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← 전체 모의해킹 절차, MITRE ATT&CK, 보고서 작성
└── 02_osint_recon.md           ← Google Dorks, Shodan, 서브도메인 열거, GitHub 비밀 탐지
```

**핵심 내용:** 체계적 침투 테스트 방법론, OSINT 도구 완전 활용, 전문 보고서 작성

---

## 11. AI 기반 사이버보안

> **2026년 현재, AI가 사이버보안의 판도를 바꾸고 있다.**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Mythos·GPT-5.4-Cyber·Project Glasswing 전체 지형도
├── 02_llm_vulnerability_research.md   ← LLM으로 제로데이 발견, AI 퍼징, 코드 분석 자동화
└── 03_ai_assisted_pentesting.md       ← AI 보조 침투 테스트 워크플로우, 프롬프트 엔지니어링
```

### 2026년 AI 보안 지형도

| 모델 | 주체 | 능력 | 접근 방법 |
|------|------|------|-----------|
| **Claude Mythos** | Anthropic | 17년 된 FreeBSD RCE 자율 발견, 수천 개 제로데이 | Project Glasswing (12개 파트너사만) |
| **GPT-5.4-Cyber** | OpenAI | 바이너리 리버싱, CTF 76% 자율 해결, YARA 생성 | TAC 인증 (chatgpt.com/cyber) |
| **Claude Opus 4.6** | Anthropic | 코드 취약점 분석, CTF 보조, YARA 자동화 | 일반 접근 가능 |

**핵심 내용:** AI 보안 생태계 완전 분석, Claude API 기반 취약점 스캐너 구현, AI 보조 침투 테스트 자동화

---

## 12. 버그바운티

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd 방법론, IDOR, XSS 우회, 자동화
├── 02_burp_suite_advanced.md      ← Burp Suite 완전 정복, JWT 공격, Request Smuggling
└── 03_bug_bounty_automation.md    ← Nuclei, ffuf, dalfox, 자동화 파이프라인
```

**핵심 내용:** 버그바운티 전체 워크플로우, Burp Suite 고급 기능, 정찰→취약점→보고서 자동화

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC 구조, 인시던트 대응, 핵심 이벤트 ID, EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL 완전 정복, 100+ 탐지 쿼리
└── 03_threat_hunting.md         ← 위협 헌팅, 랜섬웨어 침해 조사, APT 추적
```

**핵심 내용:** SOC 티어별 역할, 공격 탐지 패턴 100+, Splunk/QRadar/ELK 쿼리, 위협 헌팅 방법론

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
