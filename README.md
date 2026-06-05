<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:003300,100:0d0d0d&height=140&section=header&text=VibeHacking&fontSize=52&fontColor=00FF41&animation=fadeIn&fontAlignY=42&desc=%EC%8B%A4%EC%A0%84+%EC%82%AC%EC%9D%B4%EB%B2%84%EB%B3%B4%EC%95%88+%EC%99%84%EC%A0%84+%EC%A0%95%EB%B3%B5&descSize=16&descAlignY=68&descColor=888888" width="100%" />

<div align="center">

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=18&duration=2600&pause=600&color=00FF41&center=true&vCenter=true&width=700&lines=68+Sections+%C2%B7+370%2B+Files+%C2%B7+440%2C000%2B+Lines;CTF+%C2%B7+Bug+Bounty+%C2%B7+Red+Team+%C2%B7+AI+Security;Hack+Smart.+Defend+Hard.;%EC%8B%A4%EC%A0%84+%EC%82%AC%EC%9D%B4%EB%B2%84%EB%B3%B4%EC%95%88+%EC%99%84%EC%A0%84+%EC%A0%95%EB%B3%B5)](https://github.com/lsszz2100/VibeHacking)

<br/>

[![Sections](https://img.shields.io/badge/⚔️_SECTIONS-68-FF0000?style=for-the-badge&labelColor=0d0d0d)](#목차)
[![Files](https://img.shields.io/badge/📄_FILES-370+-00FF41?style=for-the-badge&labelColor=0d0d0d&color=00AA2C)](#목차)
[![Lines](https://img.shields.io/badge/💻_LINES-440K%2B-FF8C00?style=for-the-badge&labelColor=0d0d0d)](#목차)
[![AI](https://img.shields.io/badge/🤖_AI--POWERED-Claude+GPT-9933FF?style=for-the-badge&labelColor=0d0d0d)](#11-ai-기반-사이버보안)
[![License](https://img.shields.io/badge/🔓_LICENSE-MIT-0078D7?style=for-the-badge&labelColor=0d0d0d)](LICENSE)

<br/>

[![한국어](https://img.shields.io/badge/🇰🇷_한국어-★_Active-00FF41?style=flat-square&labelColor=111111)](README.md)
[![English](https://img.shields.io/badge/🇺🇸_English-README.en.md-555555?style=flat-square&labelColor=111111)](README.en.md)
[![日本語](https://img.shields.io/badge/🇯🇵_日本語-README.ja.md-555555?style=flat-square&labelColor=111111)](README.ja.md)
[![中文](https://img.shields.io/badge/🇨🇳_中文-README.zh.md-555555?style=flat-square&labelColor=111111)](README.zh.md)

</div>

<br/>

```console
root@vibehacking:~# cat mission.txt
╔══════════════════════════════════════════════════════════════════════════════╗
║  이론부터 실습까지, CTF·버그바운티·모의해킹·레드팀에 실전 투입 가능한 수준으로  ║
║  정리한 한국어 보안 지식 저장소.                                               ║
║  2026년 Claude Opus 4·GPT-4o 시대의 AI 기반 취약점 연구부터                   ║
║  클라우드·무선·암호학·OT/ICS까지 완전 정복.                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
root@vibehacking:~# █
```

---

## ⚡ Why VibeHacking

<table>
<tr>
<td width="55%">

```python
# VibeHacking Feature Matrix
features = {
    "실전 코드 우선"  : "모든 섹션 복붙 가능한 완성형 CLI",
    "AI 통합"        : "Claude + GPT-4o 보안 워크플로",
    "최신 동향"      : "2026년 AI 보안 생태계 완전 반영",
    "한국어 완성도"  : "처음부터 한국어로 기획·작성",
    "이중언어"       : "한국어 / English 전 파일 제공",
    "완전한 커버리지": "68섹션 전 보안 영역",
    "CTF 실습 환경"  : "도커 기반 5개 랩 즉시 구동",
}
assert all(features.values()), "All checks passed ✓"
```

</td>
<td width="45%">

| 카테고리 | 섹션 | 비중 |
|:---------|:----:|:----:|
| 🔴 기초·시스템 | 01–10 | Foundation |
| 🟠 공격·레드팀 | 11–25 | Offensive |
| 🟡 고급 기법 | 26–40 | Advanced |
| 🟢 전문 영역 | 41–68 | Specialist |
| 🧪 실습 랩 | labs/ | CTF Ready |

</td>
</tr>
</table>

---

## 🤖 AI CLI로 자연어 학습

`claude` / `codex` / `gemini` 를 **레포 디렉토리 안에서** 실행하면 AI가 68개 섹션 전체를 읽고 자연어 튜터가 됩니다. `vhack` CLI 없이도 대화 한 줄로 학습·실습이 가능합니다.

```bash
cd VibeHacking
claude   # 또는 codex / gemini
```

| AI CLI | 설치 | 강점 |
|--------|------|------|
| **Claude Code** | `npm i -g @anthropic-ai/claude-code` | 파일 읽기 + 명령어 실행, 한국어 자연스러움 |
| **Codex CLI** | `npm i -g @openai/codex` | 코드 생성·분석 특화 |
| **Gemini CLI** | `npm i -g @google/gemini-cli` | 최대 컨텍스트 창 (100만 토큰+) |

**바로 쓸 수 있는 프롬프트:**

```
"보안 완전 초보인데 이 레포에서 어떤 순서로 공부해야 해?"
"05_Web_Hacking/02_sql_injection_advanced.md 읽고 핵심 기법 설명해줘"
"웹 해킹 Lab 01 시작하고 DVWA SQL 인젝션 실습을 단계별로 안내해줘"
"이 CTF 문제 풀이 말고 힌트만 줘"
"Kerberoasting 개념 설명하고 실습 환경 어떻게 구성해?"
```

> 🤖 전체 가이드 + 시나리오 4개 + 프롬프트 템플릿 → **[AI_LEARNING.md](./AI_LEARNING.md)**

---

## 🛠️ CLI + 실습 환경 — 바로 시작하기

### 1분 설치

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py list        # 68개 섹션 목록 확인
```

> 📖 자세한 설치 가이드 → **[INSTALL.md](./INSTALL.md)**
> 📘 전체 명령어 레퍼런스 → **[USAGE.md](./USAGE.md)**
> 🤖 AI CLI로 자연어 학습 → **[AI_LEARNING.md](./AI_LEARNING.md)**

### `vhack` 주요 명령어

```bash
# 학습 탐색
python3 vhack.py list                   # 전체 68개 섹션 목록
python3 vhack.py list --search web      # "web" 관련 섹션 필터
python3 vhack.py study 5                # 웹 해킹 섹션 파일 목록
python3 vhack.py study 5 1              # OWASP Top 10 문서 읽기
python3 vhack.py search "Kerberoasting" # 전체 문서 키워드 검색

# Docker 실습 환경 관리 (Docker 필요)
python3 vhack.py lab ls                 # 실습 환경 목록 + 접속 URL
python3 vhack.py lab start 01           # 웹 해킹 랩 시작 → 8080/dvwa · 3001 · 8081
python3 vhack.py lab start 02           # 바이너리 익스플로잇 랩
python3 vhack.py lab status             # 실행 중인 컨테이너 확인
python3 vhack.py lab stop --all         # 모든 랩 종료

# alias 등록 (한 번만 → 이후 vhack 으로 바로 사용 가능)
python3 vhack.py alias install          # 셸 자동 감지 → RC 파일에 등록
python3 vhack.py alias status           # 설치 현황 확인
python3 vhack.py alias remove           # alias 제거

# 업데이트
python3 vhack.py update                 # git pull
```

### 전체 명령어 Quick Reference

| 명령어 | 설명 |
|--------|------|
| `vhack list` | 전체 68개 섹션 목록 |
| `vhack list --search <키워드>` | 섹션명 필터링 |
| `vhack study <번호>` | 섹션 파일 목록 |
| `vhack study <번호> <파일>` | 터미널에서 파일 읽기 |
| `vhack search <키워드>` | 전체 문서 전문 검색 |
| `vhack info <번호>` | 섹션 상세 정보 |
| `vhack lab ls` | 실습 환경 목록 + 접속 URL |
| `vhack lab start <id>` | 실습 환경 시작 |
| `vhack lab stop <id>` | 실습 환경 종료 |
| `vhack lab stop --all` | 전체 종료 |
| `vhack lab status` | 실행 중인 컨테이너 확인 |
| `vhack lab logs <id>` | 실시간 로그 보기 |
| `vhack alias install` | 셸 alias 자동 등록 |
| `vhack alias install --profile <파일>` | 특정 프로파일에 등록 |
| `vhack alias status` | 설치 현황 확인 |
| `vhack alias remove` | alias 제거 |
| `vhack update` | `git pull` 로 최신화 |

### 실습 환경 (Docker 기반)

| 번호 | 랩 이름 | 내용 | 접속 | 난이도 |
|:----:|---------|------|------|:------:|
| **01** | 웹 해킹 랩 | DVWA · Juice Shop · WebGoat | 8080(DVWA·SQLi) / 3001(Juice Shop) / 8081(WebGoat) | ★★☆ |
| **02** | 바이너리 익스플로잇 랩 | BOF · ret2libc · ROP · fmtstr · heap | nc localhost 10001~10005 | ★★★ |
| **03** | 네트워크 해킹 랩 | SSH · FTP · DNS · SMTP 취약 서비스 | docker exec 진입 | ★★☆ |
| **04** | 클라우드/컨테이너 보안 랩 | SSRF · AWS IMDS · K8s 탈출 | http://localhost:8080 | ★★★ |
| **05** | 전체 시나리오 통합 랩 | APT 공격 체인 시뮬레이션 | http://localhost:8888 | ★★★★ |

```bash
# 빠른 실습 예시: 웹 해킹
python3 vhack.py study 5 1        # ① OWASP Top 10 이론 학습
python3 vhack.py lab start 01     # ② DVWA/Juice Shop 랩 시작
# ③ DVWA: http://localhost:8080/dvwa/  Juice Shop: http://localhost:3001
python3 vhack.py lab stop 01      # ④ 완료 후 종료
```

---

## 📡 목차

> 🟢 입문 · 🟡 중급 · 🔴 고급 · ⚫ 전문가

### 🔴 FOUNDATION — 기초 & 핵심 공격

| # | 섹션 | 핵심 내용 | 난이도 | 파일 |
|:-:|------|-----------|:------:|:----:|
| 01 | [Linux 기초 & Kali Linux](#01-linux-기초--kali-linux) | 필수 명령어, Kali 셋업, Bash 스크립팅 | 🟢 | 4 |
| 02 | [네트워크 해킹](#02-네트워크-해킹) | OSI/TCP-IP, 패킷 분석, 무선 해킹 | 🟢 | 4 |
| 03 | [시스템 해킹](#03-시스템-해킹) | 비밀번호 크랙, Buffer Overflow, AD | 🟡 | 4 |
| 04 | [리버스 엔지니어링](#04-리버스-엔지니어링) | 어셈블리, x64dbg, PE 구조, Ghidra | 🟡 | 4 |
| 05 | [웹 해킹](#05-웹-해킹) | OWASP Top 10, SQLi, XSS/CSRF, WAF 우회 | 🟡 | 5 |
| 06 | [악성코드 분석](#06-악성코드-분석) | 정적/동적 분석, Volatility, Android | 🔴 | 4 |
| 07 | [디지털 포렌식](#07-디지털-포렌식) | 포렌식 절차, Windows 아티팩트, 네트워크 | 🟡 | 4 |
| 08 | [파이썬 해킹](#08-파이썬-해킹) | 도구 개발, 네트워크 스캐너, 웹 자동화 | 🟡 | 4 |
| 09 | [익스플로잇 기법](#09-익스플로잇-기법) | ROP Chain, SEH, Linux BOF, 힙 익스플로잇 | 🔴 | 4 |
| 10 | [침투 테스트 방법론](#10-침투-테스트-방법론) | 모의해킹 절차, OSINT 정찰, 보고서 작성 | 🟡 | 4 |

### 🟠 OFFENSIVE CORE — AI·전문 공격

| # | 섹션 | 핵심 내용 | 난이도 | 파일 |
|:-:|------|-----------|:------:|:----:|
| 11 | [**AI 기반 사이버보안**](#11-ai-기반-사이버보안) | Claude Opus 4, GPT-4o, LLM 취약점, CTF 자동화 | ⚫ | 4 |
| 12 | [버그바운티](#12-버그바운티) | 방법론, Burp Suite 심화, 자동화 도구 | 🔴 | 4 |
| 13 | [SOC & Blue Team](#13-soc--blue-team) | SOC 운영, Splunk·QRadar, 위협 헌팅 | 🔴 | 4 |
| 14 | [클라우드 보안](#14-클라우드-보안) | AWS/Azure/GCP 공격, K8s, 체크리스트 | 🔴 | 4 |
| 15 | [WiFi 해킹](#15-wifi-해킹) | WPA2 크랙, PMKID, Evil Twin | 🟡 | 4 |
| 16 | [암호학](#16-암호학) | AES/RSA 취약점, 해시 공격, Padding Oracle | 🔴 | 4 |
| 17 | [레드팀 운영](#17-레드팀-운영) | C2 프레임워크, 피싱, API 해킹 | ⚫ | 4 |
| 18 | [DevSecOps](#18-devsecops) | SAST/SCA/DAST, 컨테이너, CI/CD | 🔴 | 4 |
| 19 | [어셈블리 언어](#19-어셈블리-언어) | x86/x64, 셸코드 개발, 디스어셈블리 | 🔴 | 4 |
| 20 | [셸 스크립팅](#20-셸-스크립팅) | Bash 자동화, 침투 자동화, C2 소켓 | 🟡 | 4 |
| 21 | [Windows 익스플로잇](#21-windows-익스플로잇) | 내부 구조, 권한 상승, 방어 우회 | 🔴 | 4 |
| 22 | [패스워드 크래킹](#22-패스워드-크래킹) | Hashcat/John, 레인보우, 패스워드 스프레이 | 🟡 | 4 |

### 🟡 ADVANCED TECHNIQUES — 심화 공격

| # | 섹션 | 핵심 내용 | 난이도 | 파일 |
|:-:|------|-----------|:------:|:----:|
| 23 | [Database Hacking](#23-database-hacking) | Oracle/MySQL 공격, DB 권한 상승 | 🔴 | 4 |
| 24 | [네트워크 인프라 보안](#24-네트워크-인프라-보안) | DNS/메일 공격, SSH 터널링 | 🔴 | 4 |
| 25 | [위협 인텔리전스](#25-위협-인텔리전스) | CTI, OSINT, 인시던트 대응 | 🔴 | 4 |
| 26 | [Linux Hardening](#26-linux-hardening) | iptables, PAM, KISA 평가 | 🟡 | 4 |
| 27 | [IoT 해킹](#27-iot-해킹) | 펌웨어 분석, UART/JTAG | 🔴 | 4 |
| 28 | [모바일 해킹](#28-모바일-해킹) | Android/iOS, Frida, SSL Pinning | 🔴 | 4 |
| 29 | [컨테이너/쿠버네티스 보안](#29-컨테이너쿠버네티스-보안) | Docker 탈출, K8s RBAC | 🔴 | 4 |
| 30 | [취약점 연구](#30-취약점-연구) | AFL++/libFuzzer, 고급 익스플로잇 | ⚫ | 4 |
| 31 | [AI/ML 시스템 보안](#31-aiml-시스템-보안) | 적대적 예제, 프롬프트 인젝션, LLM | ⚫ | 4 |
| 32 | [네트워크 장비 해킹](#32-네트워크-장비-해킹) | Cisco IOS, L2 공격, BGP 조작 | ⚫ | 4 |
| 33 | [OSINT & 소셜 엔지니어링](#33-osint--소셜-엔지니어링) | 정보 수집, 피싱 인프라 | 🔴 | 4 |
| 34 | [하드웨어 해킹](#34-하드웨어-해킹) | UART/JTAG/SPI, 사이드채널 | ⚫ | 4 |
| 35 | [공급망 공격](#35-공급망-공격) | 패키지 독화, CI/CD 침해, SolarWinds | ⚫ | 3 |
| 36 | [자동차 해킹](#36-자동차-해킹) | CAN 버스, ECU, V2X | ⚫ | 4 |
| 37 | [ICS/SCADA 보안](#37-icsscada-보안) | SCADA 공격, PLC 익스플로잇, OT | ⚫ | 4 |
| 38 | [Cloud Native 보안](#38-cloud-native-보안) | eBPF, CNAPP, 컨테이너 탈출 | ⚫ | 4 |
| 39 | [Zero Trust 아키텍처](#39-zero-trust-아키텍처) | BeyondCorp, mTLS, SASE | 🔴 | 4 |
| 40 | [위협 헌팅](#40-위협-헌팅) | MITRE ATT&CK, KQL/SPL 100+, SOAR | 🔴 | 4 |

### 🟢 SPECIALIST DOMAINS — 전문 영역

| # | 섹션 | 핵심 내용 | 난이도 | 파일 |
|:-:|------|-----------|:------:|:----:|
| 41 | [한국 정보보안 자격증](#41-한국-정보보안-자격증) | 정보보안기사·ISMS-P·CISSP/OSCP 로드맵 | 🟡 | 5 |
| 42 | [블록체인/Web3 보안](#42-블록체인web3-보안) | EVM, 스마트 컨트랙트 감사, DeFi | ⚫ | 4 |
| 43 | [물리적 침투 테스트](#43-물리적-침투-테스트) | 잠금 우회, RFID 클로닝, 사회공학 | 🔴 | 4 |
| 44 | [인시던트 대응/DFIR](#44-인시던트-대응dfir) | IR 플레이북, 메모리·디스크 포렌식 | 🔴 | 4 |
| 45 | [악성코드 개발](#45-악성코드-개발) | PE 구조, 셸코드, C2, AV/EDR 우회 | ⚫ | 4 |
| 46 | [CTF 기법](#46-ctf-기법) | PWN/REV/Web/Crypto, pwntools, angr | 🔴 | 5 |
| 47 | [모바일 포렌식](#47-모바일-포렌식) | Android/iOS 증거 추출, MVT | 🔴 | 4 |
| 48 | [위협 모델링](#48-위협-모델링) | STRIDE/PASTA/DREAD, Attack Tree | 🔴 | 4 |
| 49 | [레드팀 인프라](#49-레드팀-인프라) | C2, 도메인 프론팅, OPSEC, Terraform | ⚫ | 4 |
| 50 | [게임 해킹](#50-게임-해킹) | 메모리 조작, Cheat Engine, 패킷 분석 | 🔴 | 4 |
| 51 | [브라우저 확장 보안](#51-브라우저-확장-보안) | MV3, 악성 확장 분석, Content Script XSS | 🔴 | 4 |
| 52 | [API 보안](#52-api-보안) | OWASP API Top 10, GraphQL, OAuth2 | 🔴 | 4 |
| 53 | [서버리스 보안](#53-서버리스-보안) | Lambda 공격, 이벤트 인젝션, IAM 남용 | 🔴 | 4 |
| 54 | [Active Directory 공격](#54-active-directory-공격) | Kerberoasting, DCSync, Golden Ticket | ⚫ | 4 |
| 55 | [탐지 우회 기법](#55-탐지-우회-기법) | AV/EDR 우회, syscall, 흔적 제거 | ⚫ | 4 |
| 56 | [AI 레드팀](#56-ai-레드팀) | 프롬프트 인젝션, 모델 추출, 적대적 예제 | ⚫ | 5 |
| 57 | [양자 암호학](#57-양자-암호학) | QKD, 후양자 알고리즘, NIST PQC | ⚫ | 5 |
| 58 | [클라우드 침해 대응](#58-클라우드-침해-대응) | Cloud IR, AWS/Azure/GCP 포렌식 | ⚫ | 5 |
| 59 | [공급망 보안](#59-공급망-보안) | SBOM, 의존성 혼동, 빌드 무결성 | ⚫ | 5 |
| 60 | [브라우저 보안 심화](#60-브라우저-보안-심화) | JS엔진 익스플로잇, 샌드박스 탈출 | ⚫ | 6 |
| 61 | [펌웨어 해킹](#61-펌웨어-해킹) | 펌웨어 추출, QEMU 에뮬레이션 | ⚫ | 5 |
| 62 | [자동차 보안](#62-자동차-보안) | CAN 버스, ECU, V2X, OTA 공격 | ⚫ | 5 |
| 63 | [OT/ICS 심화](#63-otICS-심화) | SCADA, PLC 익스플로잇, OT 방어 | ⚫ | 5 |
| 64 | [위협 인텔리전스 플랫폼](#64-위협-인텔리전스-플랫폼) | TIP, MISP, IoC 자동화 파이프라인 | ⚫ | 6 |
| 65 | [리버스 엔지니어링 심화](#65-리버스-엔지니어링-심화) | 안티디버깅, 언패킹, 심볼릭 실행, CFG | ⚫ | 5 |
| 66 | [익스플로잇 개발](#66-익스플로잇-개발) | ROP 체인, Heap 익스플로잇, 커널·브라우저 취약점 | ⚫ | 5 |
| 67 | [악성코드 개발 이해](#67-악성코드-개발-이해) | C2 구조, 셸코드, 지속성, 탐지 우회 | ⚫ | 5 |
| 68 | [퍼플팀 운영](#68-퍼플팀-운영) | 공격 시뮬레이션, 탐지 엔지니어링, APT 에뮬레이션 | ⚫ | 5 |
| 🧪 | [**CTF 실습 환경 (labs/)**](#ctf-실습-환경-labs) | 웹·바이너리·네트워크·클라우드·통합 도커 랩 | 🔴 | 50 |

---

## 🗺️ 학습 로드맵

```
╔═══════════════════════════════════════════════════════════════╗
║                     VIBEHACKING ROADMAP                       ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  [🟢 BEGINNER]                                               ║
║   01 Linux  ──►  02 Network  ──►  05 Web Hacking             ║
║                                         │                     ║
║  [🟡 INTERMEDIATE]                      ▼                    ║
║   03 System  ◄──  08 Python  ◄──  06 Malware Analysis        ║
║       │                                                       ║
║       ▼                                                       ║
║  [🔴 ADVANCED]                                               ║
║   04 Rev.Eng  ──►  09 Exploit  ──►  10 Pentest Methodology   ║
║       │                                     │                 ║
║  [⚫ EXPERT]                                ▼                ║
║   17 Red Team  ──►  14 Cloud  ──►  12 Bug Bounty             ║
║   16 Crypto    ──►  13 SOC    ──►  11 AI Security            ║
║   45 Malware   ──►  54 AD     ──►  49 Red Team Infra         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 🖥️ 실습 환경

| 구성 요소 | 권장 사항 |
|-----------|-----------|
| 공격자 머신 | Kali Linux (최신) |
| 가상화 | VMware Workstation / VirtualBox |
| 취약 환경 | Metasploitable2, DVWA, HackTheBox, TryHackMe, CloudGoat |
| 분석 도구 | Wireshark, Burp Suite, IDA Free / Ghidra / x64dbg |
| 언어 | Python 3.10+, Bash, pwntools 4.x |
| AI 도구 | Claude Opus 4.6, GPT-4o |
| 무선 | Alfa AWUS036ACH (2.4/5GHz 모니터 모드 지원) |
| 클라우드 | AWS Free Tier, CloudGoat, Terraform |

---

## 01. Linux 기초 & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← 파일/프로세스/네트워크 필수 명령어
├── 02_kali_linux_setup.md           ← Kali 초기 설정, 도구 설치
├── 03_bash_scripting.md             ← 자동화 스크립팅, 실전 예제
└── 04_linux_privilege_escalation.md ← sudo/SUID/Cron/쓰기권한 권한 상승
```

**핵심 내용:** 파일 시스템, 프로세스 관리, 네트워크 명령, 권한 관리, Bash 자동화 스크립트 30+

---

## 02. 네트워크 해킹

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI 7계층, TCP/IP 스택, 프로토콜 분석
├── 02_packet_analysis.md    ← Wireshark 실전, tcpdump, 패킷 조작
├── 03_wireless_hacking.md   ← WEP/WPA2 크랙, Evil Twin, 무선 해킹
└── 04_mitm_advanced.md      ← MITM 심화, ARP 스푸핑 자동화
```

**핵심 내용:** 패킷 캡처·분석, ARP 스푸핑, MITM, 무선 네트워크 공격, 방화벽 우회

---

## 03. 시스템 해킹

```
03_System_Hacking/
├── 01_password_cracking.md           ← Hashcat, John, Rainbow Table, 온라인 크랙
├── 02_buffer_overflow.md             ← 스택 BOF 원리, 쉘코드, 실습 예제
├── 03_active_directory_attack.md     ← AD 공격 완전 가이드, Kerberoasting, DCSync
└── 04_kerberos_delegation_attacks.md ← 비제약/제약/RBCD 위임 공격 완전 실습
```

**핵심 내용:** 해시 크래킹 전략, BOF 원리부터 익스플로잇까지, Active Directory 공격 체인 완전 정복, Kerberos 위임(Unconstrained/Constrained/RBCD) 공격 체인

---

## 04. 리버스 엔지니어링

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md        ← x86/x64 어셈블리, 레지스터, 스택 프레임
├── 02_ollydbg_practical.md             ← x64dbg 실전 분석
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
├── 04_waf_bypass_advanced_web.md  ← WAF 탐지·우회 완전 치트시트, Cache Poisoning
└── 06_web_ctf_practical_lab.md    ← CTF 실습 랩
```

**핵심 내용:** OWASP Top 10 실습, SQL Injection 완전 정복, XSS/CSRF/파일 업로드/XXE/SSRF, WAF 우회 전기법 (Cloudflare/AWS WAF/ModSecurity), HTTP Request Smuggling, Web Cache Poisoning

---

## 06. 악성코드 분석

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← 분류, 분석 환경, 정적/동적 분석, YARA
├── 02_memory_forensics_malware.md    ← Volatility 완전 정복, 코드 인젝션 탐지
├── 03_android_malware_analysis.md    ← APK 분석, Frida 후킹, MobSF
└── 04_yara_and_detection.md          ← YARA 룰 작성, 탐지 자동화
```

**핵심 내용:** 정적·동적·메모리 분석 전 과정, Volatility 플러그인, 안드로이드 악성코드

---

## 07. 디지털 포렌식

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← 포렌식 원칙, 증거 수집, 이미지 분석
├── 02_windows_forensics_artifacts.md     ← 레지스트리, 이벤트 로그, Prefetch, 브라우저
├── 03_network_forensics.md               ← Wireshark, Zeek, Suricata, 침해 대응
└── 04_advanced_memory_forensics.md       ← Volatility3 심화 플러그인, 커널 루트킷 분석
```

**핵심 내용:** 증거 수집 절차, Windows 아티팩트 완전 분석, 네트워크 포렌식, 타임라인 분석

---

## 08. 파이썬 해킹

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← 포트 스캐너·스니퍼·백도어 등 30가지 예제
├── 02_python_network_scanner.md     ← 멀티스레드 스캐너, ARP, DNS 열거, SSH 브루트포서
├── 03_python_web_exploitation.md    ← 웹 크롤러, SQLi 자동화, XSS 스캐너, 보고서 생성
└── 04_python_forensics_toolkit.md   ← 포렌식 자동화, 파일 카빙, 해시 검증 CLI
```

**핵심 내용:** Scapy, paramiko, requests 활용 보안 도구 개발, 완전 동작하는 코드 50+

---

## 09. 익스플로잇 기법

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain, Heap Spray, SEH, Win32 셸코딩
├── 02_linux_exploitation.md      ← Linux BOF, Ret2Libc, 포맷 스트링, 권한 상승
├── 03_heap_exploitation.md       ← tcache 포이즈닝, UAF, House of 시리즈, pwndbg
└── 04_kernel_exploitation.md     ← 커널 취약점 기초, 드라이버 익스플로잇, LPE
```

**핵심 내용:** DEP/ASLR/NX 우회, ROP 체인 구성, 포맷 스트링 익스플로잇, 힙 익스플로잇 완전 정복

---

## 10. 침투 테스트 방법론

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← 전체 모의해킹 절차, MITRE ATT&CK, 보고서 작성
├── 02_osint_recon.md           ← Google Dorks, Shodan, 서브도메인 열거, GitHub 비밀 탐지
├── 03_report_writing.md        ← 전문 보고서 작성, CVSS 산정, PoC 작성 템플릿
└── 04_post_exploitation.md     ← 사후 익스플로잇, 횡이동, 지속성 확보
```

**핵심 내용:** 체계적 침투 테스트 방법론, OSINT 도구 완전 활용, 전문 보고서 작성 (CVSS·PoC·규정 준수 포함)

---

## 11. AI 기반 사이버보안

> **2026년 현재, AI가 사이버보안의 판도를 바꾸고 있다.**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Claude Opus 4·GPT-4o·내부 연구 프로그램 전체 지형도
├── 02_llm_vulnerability_research.md   ← LLM으로 제로데이 발견, AI 퍼징, 코드 분석 자동화
├── 03_ai_assisted_pentesting.md       ← AI 보조 침투 테스트 워크플로우, 프롬프트 엔지니어링
└── 04_ai_ctf_automation.md            ← CTF 자동화 AI 에이전트, 전문 서브에이전트
```

| 모델 | 주체 | 능력 | 접근 방법 |
|:----:|:----:|------|:--------:|
| **Claude Opus 4** | Anthropic | 17년 된 FreeBSD RCE 자율 발견, 수천 개 제로데이 | 내부 연구 프로그램 |
| **GPT-4o** | OpenAI | 바이너리 리버싱, CTF 76% 자율 해결, YARA 생성 |  |
| **Claude Opus 4.6** | Anthropic | 코드 취약점 분석, CTF 보조, YARA 자동화 | 일반 접근 가능 |

**핵심 내용:** AI 보안 생태계 완전 분석, Claude API 기반 취약점 스캐너, AI 보조 침투 테스트 자동화, CTF 풀이 AI 에이전트

---

## 12. 버그바운티

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd 방법론, IDOR, XSS 우회, 자동화
├── 02_burp_suite_advanced.md      ← Burp Suite 완전 정복, JWT 공격, Request Smuggling
├── 03_bug_bounty_automation.md    ← Nuclei, ffuf, dalfox, 자동화 파이프라인
└── 04_api_security_testing.md     ← OWASP API Top 10 (2023), GraphQL 공격, BOLA 자동화
```

**핵심 내용:** 버그바운티 전체 워크플로우, Burp Suite 고급 기능, 정찰→취약점→보고서 자동화, OWASP API Security Top 10 전 취약점 실습

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md          ← SOC 구조, 인시던트 대응, 핵심 이벤트 ID, EDR
├── 02_splunk_siem_analysis.md      ← Splunk SPL 완전 정복, 100+ 탐지 쿼리
├── 03_threat_hunting.md            ← 위협 헌팅, 랜섬웨어 침해 조사, APT 추적
└── 04_qradar_xdr_blue_team.md      ← IBM QRadar AQL 심화 + Sentinel KQL + XDR 비교
```

**핵심 내용:** SOC 티어별 역할, 공격 탐지 패턴 100+, Splunk/QRadar/Sentinel/Cortex XQL 쿼리, XDR 플랫폼(CrowdStrike/SentinelOne/Defender XDR)

---

## 14. 클라우드 보안

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s 공격 벡터 완전 분석
├── 02_aws_pentest.md                 ← AWS 침투 테스트 방법론, 권한 상승, 자동화
├── 03_cloud_security_checklist.md    ← CIS 체크리스트, Terraform, SCP 정책
└── 04_cloud_native_attacks.md        ← 서버리스 공격, CSPM, 클라우드 IR
```

**핵심 내용:** IAM 권한 남용, S3 오설정, 컨테이너 이스케이프, Kubernetes 공격, 클라우드 보안 체크리스트

---

## 15. WiFi 해킹

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3 이론, aircrack-ng 기초
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack, PMKID 공격, 워드리스트 최적화
├── 03_advanced_wifi_attacks.md       ← Evil Twin, KARMA, Bettercap, Scapy 조작
└── 04_wifi_defense.md                ← 무선 IDS, 802.1X, WIPS 구성
```

**핵심 내용:** 4-Way Handshake, PMKID 수집, GPU 크래킹, Evil Twin 구축, 무선 자동화

---

## 16. 암호학

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AES 모드 공격, RSA 취약점, XOR 크래킹
├── 02_hash_attacks.md               ← MD5 충돌, 레인보우 테이블, Kerberoasting
├── 03_applied_cryptography.md       ← Padding Oracle, ECDSA 논스 재사용, JWT 공격
└── 04_pqc_and_modern_crypto.md      ← 후양자 암호학, CRYSTALS-Kyber/Dilithium
```

**핵심 내용:** 암호 구현 취약점, CTF 암호학 문제 패턴, 안전한 암호화 구현 가이드

---

## 17. 레드팀 운영

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← 운영 구조, Cobalt Strike/Havoc, AV/EDR 우회
├── 02_phishing_and_social_engineering.md ← GoPhish, Evilginx2, 스피어피싱, BEC
├── 03_api_hacking.md                     ← OWASP API Top 10, GraphQL, 퍼저 개발
└── 04_red_team_reporting.md              ← 레드팀 보고서, MITRE ATT&CK 매핑
```

**핵심 내용:** 레드팀 vs 펜테스트 차이, C2 프레임워크 운영, 피싱 인프라, API 취약점 완전 정복

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left, Semgrep, SonarQube, Snyk, ZAP
├── 02_container_security.md        ← Dockerfile 보안, Trivy, Falco, K8s RBAC, cosign
├── 03_github_actions_security.md   ← CI/CD 보안, OIDC, SHA 핀닝, 전체 보안 파이프라인
└── 04_iac_security.md              ← Terraform 보안, Checkov, tfsec, KICS
```

**핵심 내용:** 보안 내재화(Shift Left), SAST/SCA/DAST/IaC 스캔 자동화, 컨테이너 런타임 탐지, GitLab/Jenkins/GitHub Actions 보안 파이프라인

---

## 19. 어셈블리 언어

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← 레지스터, 명령어, 스택 프레임, 호출 규약
├── 02_Shellcode_Development.md  ← 셸코드 작성, bad byte 제거, ctypes 실행 테스트
├── 03_Disassembly_Analysis.md   ← GDB/pwndbg, IDA/Ghidra, Capstone 자동화
└── 04_NASM_Advanced.md          ← NASM 고급, 위치 독립 코드, 셸코드 인코더
```

**핵심 내용:** x86/x64 레지스터 완전 정복, NASM 코딩, 64비트 execve 셸코드 구현, Capstone 기반 자동 디스어셈블러

---

## 20. 셸 스크립팅

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← 변수/배열/조건/반복/함수, awk/sed, 포트 스캐너
├── 02_Pentest_Automation.md          ← 정찰 자동화, 서브도메인 열거, 취약점 스캔 래퍼
├── 03_Post_Exploitation_Scripts.md   ← 리버스 셸, 지속성 확보, Python C2 소켓 구현
└── 04_bash_obfuscation.md            ← 셸스크립트 난독화, 탐지 우회 기법
```

**핵심 내용:** Bash 실전 스크립팅, 정찰~사후 익스플로잇 전 과정 자동화, 리버스 셸 원라이너 7종

---

## 21. Windows 익스플로잇

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PE 포맷, PEB/TEB, WinAPI 핵심 함수, PE 파서
├── 02_Windows_Privilege_Escalation.md   ← 서비스/레지스트리/DLL 하이재킹, UAC 바이패스
├── 03_Defense_Evasion.md                ← AMSI/ETW 우회, 프로세스 인젝션 6종, LOLBAS
└── 04_windows_persistence.md            ← 레지스트리/WMI/스케줄러/서비스 지속성
```

**핵심 내용:** Windows 내부 구조 심층 분석, 권한 상승 완전 정복, AMSI/AV/EDR 우회 기법

---

## 22. 패스워드 크래킹

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← 해시 알고리즘 비교, hashid, CeWL/Crunch/CUPP
├── 02_Hashcat_and_John.md              ← 전체 공격 모드, 해시 타입별 모드 번호, 규칙 작성
├── 03_Advanced_Cracking_Techniques.md  ← 레인보우 테이블, PRINCE, 패스워드 스프레이
└── 04_credential_attacks.md            ← Credential Stuffing, 브루트포스 자동화
```

**핵심 내용:** NTLM/WPA/ZIP/PDF 크래킹 전략, GPU 최적화, 레이트 리밋 우회 패스워드 스프레이 자동화

---

## 23. Database Hacking

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL 공격 벡터, 블라인드 SQLi, OOB 추출
├── 02_db_privilege_escalation.md   ← DB 사용자 권한 상승, 저장 프로시저 악용, UDF 인젝션
├── 03_db_forensics_defense.md      ← 데이터베이스 포렌식, 감사 로그, 쿼리 모니터링
└── 04_nosql_attacks.md             ← MongoDB 인젝션, Redis 공격, CouchDB 취약점
```

**핵심 내용:** 다중 DB 공격 체인, DB 엔진 경유 권한 상승, 포렌식 분석 및 방어 강화

---

## 24. 네트워크 인프라 보안

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNS 하이재킹, 영역 전송, 캐시 포이즈닝, DNSSEC 우회
├── 02_mail_server_security.md              ← SPF/DKIM/DMARC 우회, 메일 서버 침해, 이메일 스푸핑
├── 03_ssh_tunneling_port_forwarding.md     ← SSH 터널링, 동적 포트 포워딩, SOCKS 프록시, 피버팅
└── 04_network_automation_attacks.md        ← 네트워크 자동화 도구 공격, Ansible/Netmiko 취약점
```

**핵심 내용:** DNS/메일/SSH 인프라 레벨 공격, 서비스 익스플로잇, 피버팅을 통한 횡이동

---

## 25. 위협 인텔리전스

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTI 프레임워크(MITRE ATT&CK/STIX/TAXII), 위협 행위자 프로파일링
├── 02_osint_for_threat_intel.md    ← Shodan/Censys 자동화, 다크웹 OSINT, IOC 수집 파이프라인
├── 03_incident_response.md         ← IR 플레이북, 증거 수집, 악성코드 트리아지, 허니팟
└── 04_cti_platform_automation.md   ← MISP 연동, 위협 피드 자동화, IoC 관리 파이프라인
```

**핵심 내용:** CTI 라이프사이클, 위협 행위자 귀속 분석, IOC 관리, 자동화 인시던트 대응 절차

---

## 26. Linux Hardening

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufw 규칙, 방화벽 감사
├── 02_pam_and_auth_hardening.md         ← PAM 설정, SSH 하드닝, MFA 구성, sudo 정책
├── 03_kisa_vulnerability_assessment.md  ← KISA 보안 체크리스트, CIS 벤치마크, 자동화 평가
└── 04_linux_audit_selinux.md            ← auditd, SELinux/AppArmor, 실시간 이상 탐지
```

**핵심 내용:** 방화벽 규칙 설계, 인증 강화, KISA/CIS 준수 자동화 보안 평가

---

## 27. IoT 해킹

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← IoT 공격 면 분석, OWASP IoT Top 10, Shodan/Censys 스캐닝
├── 02_firmware_analysis.md     ← 펌웨어 추출·분석, binwalk/Ghidra, 하드코딩 취약점 탐지
├── 03_iot_exploitation.md      ← UART/JTAG 접근, 임베디드 익스플로잇, 실전 공격 시나리오
└── 04_iot_network_attacks.md   ← Zigbee/Z-Wave/BLE 프로토콜 공격
```

**핵심 내용:** OWASP IoT Top 10 기반 공격 면 분석, 펌웨어 역공학(binwalk·Ghidra), UART/JTAG 하드웨어 해킹

---

## 28. 모바일 해킹

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK 분석, ADB 루팅, Frida 동적 계측, SSL Pinning 우회
├── 02_ios_pentesting.md            ← IPA 추출, Objective-C/Swift 리버싱, Jailbreak 탐지 우회
├── 03_mobile_traffic_analysis.md   ← Burp Suite 모바일 프록시, 인증서 고정 우회, API 퍼징
└── 04_mobile_malware_analysis.md   ← 모바일 악성코드 분석, C2 탐지, 행위 분석
```

**핵심 내용:** Android/iOS 완전 분석 파이프라인, Frida 기반 런타임 계측, 모바일 트래픽 중간자 공격

---

## 29. 컨테이너/쿠버네티스 보안

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Docker 보안 설정, 컨테이너 탈출 기법, 이미지 취약점 스캐닝
├── 02_kubernetes_attack.md    ← RBAC 권한 상승, etcd 탈취, Kubernetes 공격 벡터 완전 분석
├── 03_container_escape.md     ← cgroup/namespace 탈출, runc 취약점, 실전 컨테이너 탈출 PoC
└── 04_k8s_defense.md          ← OPA Gatekeeper, Falco, Network Policy, RBAC 최소권한
```

**핵심 내용:** Docker/Kubernetes 공격·방어 전략, RBAC 권한 상승, 컨테이너 탈출 기법, Trivy·Falco 기반 런타임 보안

---

## 30. 취약점 연구

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz, 커버리지 기반 퍼징, 네트워크 퍼징
├── 02_vulnerability_analysis.md        ← CVSS 분석, CWE 분류, 정적/동적 분석, 소스 코드 감사
├── 03_exploit_development_advanced.md  ← 고급 힙 익스플로잇, 브라우저 익스플로잇, 커널 취약점
└── 04_responsible_disclosure.md        ← CVE 신청, 책임있는 공개 절차, 버그바운티 보고서
```

**핵심 내용:** AFL++/libFuzzer 기반 자동화 취약점 탐지, CVSS·CWE 체계적 분석, 고급 힙/브라우저/커널 익스플로잇 개발

---

## 31. AI/ML 시스템 보안

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W, 전이 공격, adversarial training
├── 02_prompt_injection_jailbreak.md   ← 직접·간접 프롬프트 인젝션, 탈옥, garak/PyRIT
├── 03_model_extraction_inversion.md   ← 모델 추출, 멤버십 추론(LiRA), 학습 데이터 재구성
└── 04_llm_agent_security.md           ← 도구 호출 SSRF/RCE, RAG 인덱스 오염, MCP 보안
```

**관점:** 섹션 11이 "AI를 공격 도구로 활용"이라면, 섹션 31은 **AI/ML 시스템 자체가 표적**인 공격과 방어. OWASP LLM Top 10·NIST AI 100-2·MITRE ATLAS 기반.

---

## 32. 네트워크 장비 해킹

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE 구조, 장비 핑거프린팅
├── 02_layer2_attacks.md                  ← VLAN hopping, STP/DHCP 공격, CAM overflow
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP 경로 주입, HSRP/VRRP 하이재킹
└── 04_management_plane_exploitation.md   ← SNMP·TACACS+·NETCONF·설정 파일 추출
```

**핵심 내용:** 라우터·스위치 관리/제어/데이터 평면 직접 공격. 2025–2026 Cisco CVE 재현 PoC, GNS3·EVE-NG 실습 토폴로지 포함.

---

## 33. OSINT & 소셜 엔지니어링

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← 정보 수집 방법론, Shodan/Censys/FOFA, dorking 고급
├── 02_target_profiling.md              ← 인물·조직 프로파일링, SNS 분석, 이메일 검증
├── 03_social_engineering_attacks.md    ← 피싱·스피어피싱·비싱·스미싱, BEC, 프리텍스팅
└── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2 인프라, URL 우회, 안티피싱 탐지 우회
```

**핵심 내용:** OSINT를 공격 체인의 정찰 단계로 활용. Shodan·FOFA 쿼리 자동화, 타겟 프로파일링, GoPhish·Evilginx2 인프라 구축.

---

## 34. 하드웨어 해킹

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md    ← UART/JTAG/SPI/I²C 인터페이스 식별·덤프
├── 02_firmware_analysis.md               ← binwalk 추출, 파일시스템 분석, 하드코딩 비밀
├── 03_side_channel_and_fault_injection.md ← 전력 분석(SPA/DPA), 타이밍 공격, ChipWhisperer
└── README.md
```

**핵심 내용:** UART 시리얼 콘솔 root 셸 획득, JTAG 펌웨어 덤프, 사이드채널 분석, OpenOCD·ChipWhisperer 실전.

---

## 35. 공급망 공격

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← 오픈소스 패키지 독화, typosquatting, 의존성 혼동 공격
├── 02_build_and_ci_poisoning.md  ← CI/CD 파이프라인 침해, GitHub Actions 악용, SolarWinds·XZ 패턴
└── README.md
```

**핵심 내용:** SolarWinds·XZ Utils·3CX 사례 해부, PyPI·npm·Maven 패키지 독화, GitHub Actions 워크플로 탈취.

---

## 36. 자동차 해킹

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CAN 버스 구조, OBD-II 진단, 메시지 스니핑·재전송
├── 02_ecu_exploitation.md           ← ECU 펌웨어 분석, UDS 진단 프로토콜 악용, 리맵핑
├── 03_telematics_and_ota_attacks.md ← V2X 통신, 텔레매틱스 유닛 침투, OTA 업데이트 가로채기
└── README.md
```

**핵심 내용:** CAN 버스 스니핑, UDS 진단 프로토콜 악용, 텔레매틱스 원격 공격. Jeep Cherokee·Tesla 해킹 재현, python-can·Scapy·CANalyzer 활용.

---

## 37. ICS/SCADA 보안

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP, Shodan 정찰
├── 02_scada_exploitation.md       ← HMI/Historian/PLC 취약점, TRITON·INDUSTROYER 분석
├── 03_ot_network_attacks.md       ← Purdue 계층별 공격, IT→OT 횡이동, OT 토폴로지 매퍼
└── README.md
```

**핵심 내용:** Stuxnet·TRITON·INDUSTROYER·PIPEDREAM 사이버 무기 해부, Modbus 코일 강제 쓰기, PLC DB 블록 패치, OT 전용 토폴로지 자동 매핑.

---

## 38. Cloud Native 보안

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE 위협 모델, CNAPP, 컨테이너·서버리스 위협
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium, eBPF 기반 런타임 탐지
├── 03_image_hardening_supply_chain.md   ← Trivy/Grype 이미지 스캔, Cosign 서명, SBOM
└── 04_cloud_native_attack_techniques.md ← 컨테이너 탈출, 서비스메시 MITM, 서버리스 이벤트 주입
```

**핵심 내용:** eBPF 기반 런타임 보안(Falco/Tetragon), 컨테이너 이미지 서명·SBOM, OPA 정책 게이트웨이, CNAPP 관점 전체 공격·방어.

---

## 39. Zero Trust 아키텍처

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorp 모델, NIST SP 800-207, ZTA 성숙도 모델
├── 02_identity_and_device_trust.md     ← IdP/MFA/패스키, 장치 신뢰(MDM/EDR), SCIM
├── 03_microsegmentation_and_network.md ← 마이크로세그멘테이션, mTLS, SASE/SD-WAN
└── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp 구현, ZTA 감사
```

**핵심 내용:** NIST SP 800-207 기반 Zero Trust 실무 적용, BeyondCorp 사례, 아이덴티티·장치 신뢰 체계, SASE 도입 가이드.

---

## 40. 위협 헌팅

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← 헌팅 사이클, 가설 기반 헌팅, PEAK 프레임워크
├── 02_mitre_attack_hunting.md        ← ATT&CK 전술별 헌팅 시나리오, Atomic Red Team
├── 03_hunting_queries_kql_spl.md     ← Sentinel KQL/Splunk SPL 헌팅 쿼리 100+
└── 04_automated_threat_hunting.md    ← SOAR 자동화, ML 기반 이상 탐지
```

**핵심 내용:** PEAK 프레임워크 기반 가설 설정, MITRE ATT&CK 전술별 헌팅, KQL/SPL 쿼리 100+, SOAR 기반 자동화 플레이북.

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

**핵심 내용:** 한국 정보보안기사·ISMS-P, 국제 자격증(CISSP/CEH/OSCP/CISA), 법령·컴플라이언스 완전 정리.

---

## 42. 블록체인/Web3 보안

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md  ← EVM 구조, UTXO vs 계정 모델, 51% 공격
├── 02_smart_contract_auditing.md              ← 재진입·오버플로우·delegatecall 취약점, Slither/Mythril
├── 03_defi_protocol_attacks.md               ← Flash Loan 공격, 오라클 조작, MEV 샌드위치
└── 04_web3_pentest_tools.md                  ← Foundry/Cast/Anvil, RPC 보안 평가, CTF 이더리움
```

**핵심 내용:** EVM 스토리지 레이아웃, 스마트 컨트랙트 자동 감사(Slither), Flash Loan 공격, Foundry 기반 PoC 작성.

---

## 43. 물리적 침투 테스트

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md         ← PTES 물리 도메인, 허가서 구성
├── 02_lock_bypass_and_access_control.md       ← 락피킹·범핑, REX 센서 공격
├── 03_rfid_nfc_cloning.md                    ← EM4100/HID Proxmark3 클로닝, MIFARE nested 공격
└── 04_physical_recon_and_social_engineering.md ← OSINT 정찰, 테일게이팅, 프리텍스팅
```

**핵심 내용:** PTES 방법론, 잠금장치 우회, RFID/NFC 클로닝(Proxmark3/FlipperZero), 접근 제어 로그 이상 탐지.

---

## 44. 인시던트 대응/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md         ← NIST SP 800-61r2, 랜섬웨어·피싱 플레이북
├── 02_memory_and_disk_forensics.md            ← Volatility3, MFT 분석, 의심 프로세스 자동 플래깅
├── 03_network_forensics_and_log_analysis.md   ← Zeek 로그, Windows 이벤트 ID, PCAP C2 IOC 추출
└── 04_threat_containment_and_eradication.md   ← 격리·박멸·복구, VSS 복원, 지속성 수집
```

**핵심 내용:** NIST 기반 플레이북, Volatility3 메모리 포렌식, Zeek/Sysmon 로그 분석, PCAP C2 탐지, 랜섬웨어 복구 절차.

---

## 45. 악성코드 개발

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PE 파일 구조, IAT 분석, 엔트로피 탐지
├── 02_shellcode_and_injection_techniques.md    ← PIC 셸코드, XOR 인코더, 프로세스 인젝션 기법
├── 03_c2_framework_development.md              ← HTTP C2 서버·에이전트, DNS 터널링
└── 04_av_edr_evasion.md                       ← 직접 시스템콜, NTDLL 언훅, ETW/AMSI 패치
```

**핵심 내용:** PE 구조 분석, 셸코드 인코딩, 다양한 프로세스 인젝션 기법, Python HTTP C2 구현, AV/EDR 우회. (허가된 레드팀·CTF·보안 연구 목적)

---

## 46. CTF 기법

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md     ← CTF 유형, 분야별 도구셋, Docker pwnbox, 노트 자동화
├── 02_pwn_and_rev_ctf.md               ← ret2win/ret2libc/ROP/힙, pwntools 완전 템플릿, angr
├── 03_web_and_crypto_ctf.md            ← 블라인드 SQLi 자동화, SSTI, JWT, RSA CTF 솔버
├── 04_ctf_automation_and_frameworks.md ← DynELF, angr 자동화, Frida, 포렌식 파이프라인
└── 06_ctf_practical_lab.md             ← CTF 실전 랩
```

**핵심 내용:** CTF 분야별 도구 체계, pwntools 완성형 익스플로잇 템플릿, angr/z3 심볼릭 실행, Frida 동적 계측, CTFd API 자동화.

---

## 47. 모바일 포렌식

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Android 파일시스템·ADB 포렌식·SQLite 아티팩트
├── 02_ios_forensics.md              ← iOS APFS 구조·iTunes 백업 파싱·iMessage/Health 추출
├── 03_mobile_evidence_extraction.md ← 논리/파일시스템/물리 추출·해시 무결성
└── 04_mobile_forensics_tools.md     ← Autopsy·MVT·Frida·jadx·APK 자동 분석
```

**핵심 내용:** Android/iOS 기기 포렌식 전 과정, iTunes 백업 복호화, MVT로 Pegasus 스파이웨어 탐지.

---

## 48. 위협 모델링

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE 6범주·DFD 작성·신뢰경계·자동 분석
├── 02_pasta_dread_attack_trees.md   ← PASTA 7단계·DREAD 점수·Attack Tree·Kill Chain
├── 03_threat_modeling_tools.md      ← MS TMT·Threat Dragon·IriusRisk·CI/CD 통합
└── 04_threat_modeling_practice.md   ← 전자상거래/모바일뱅킹/K8s 실전 시나리오
```

**핵심 내용:** STRIDE·PASTA·DREAD 방법론 실전 적용. DFD 작성부터 CI/CD 통합까지 Python CLI 한 줄로 자동화.

---

## 49. 레드팀 인프라

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md              ← Cobalt Strike/Sliver/Havoc 구조·HTTP C2 구현·탐지 규칙
├── 02_domain_fronting_redirectors.md ← CDN 프론팅·Apache/Nginx 리다이렉터·DNS 터널링
├── 03_opsec_infrastructure.md       ← OPSEC 5단계·Long/Short Haul 분리·CT 로그·자동 OPSEC 점검
└── 04_red_team_automation.md        ← Ansible/Terraform 인프라·페이로드 파이프라인
```

**핵심 내용:** C2 인프라 구축과 OPSEC. Sliver/Havoc 프레임워크, Apache 리다이렉터, Terraform AWS 인프라 자동화. (허가된 레드팀·CTF·보안 연구 목적)

---

## 50. 게임 해킹

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← 게임 메모리 구조·ReadProcessMemory·AOB 스캔·포인터체인
├── 02_cheat_engine_advanced.md      ← CE Lua 스크립팅·자동어셈블러·구조체 분석
├── 03_packet_manipulation.md        ← 게임 패킷 캡처·mitmproxy·protobuf 역분석
└── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye 구조·탐지 기법·프로세스 분석
```

**핵심 내용:** Cheat Engine 메모리 조작, 패킷 중간자 분석, 안티치트 동작 원리. (교육·CTF·보안 연구 목적)

---

## 51. 브라우저 확장 보안

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md       ← MV2/V3 비교·Background/Content Script·CSP
├── 02_malicious_extension_analysis.md ← 악성 확장 유형·IOC·난독화 분석·CRX 자동 분석
├── 03_extension_pentesting.md         ← Content Script XSS·Cross-extension 공격·Selenium 자동 스캔
└── 04_extension_security_hardening.md ← MV3 보안 강화·최소권한·기업 GPO·위험도 평가
```

**핵심 내용:** Chrome/Firefox 확장 보안 전반, 악성 확장 탐지, CRX 자동 분석, Selenium 기반 동적 취약점 스캐너.

---

## 52. API 보안

```
52_API_Security/
├── 01_rest_api_security.md         ← OWASP API Top 10·BOLA 스캐너·JWT 취약점 분석
├── 02_graphql_security.md          ← 인트로스펙션·배치 쿼리·깊이 공격·스키마 자동 분석
├── 03_api_fuzzing.md               ← ffuf·OpenAPI 기반 자동 퍼저·파라미터 오염·응답 분석
└── 04_api_security_hardening.md    ← OAuth2 PKCE·Rate Limiting·Kong/NGINX 게이트웨이
```

**핵심 내용:** REST·GraphQL API 취약점 전반. BOLA 자동 스캐너, JWT 위조·크래킹, OAuth2 PKCE 구현, API 게이트웨이 보안.

---

## 53. 서버리스 보안

```
53_Serverless_Security/
├── 01_lambda_function_attacks.md   ← 환경 변수 탈취·IMDSv1 SSRF·이벤트 인젝션
├── 02_serverless_injection.md      ← SQS/S3 이벤트 인젝션·타이포스쿼팅·커맨드 인젝션 정적 분석
├── 03_serverless_iam_abuse.md      ← 역할 과다 권한·AssumeRole 체인·최소 권한 정책 자동 생성
└── 04_serverless_hardening.md      ← IaC 보안 스캔·Terraform 보안 설정·Lambda Extension
```

**핵심 내용:** AWS Lambda 서버리스 환경 공격·방어. IMDSv1 SSRF, 이벤트 소스 인젝션, IAM 역할 남용, IaC(Checkov/cfn-guard) 스캔.

---

## 54. Active Directory 공격

```
54_Active_Directory_Attacks/
├── 01_ad_enumeration.md            ← BloodHound·LDAP 열거·SPN/AS-REP 계정 자동 열거
├── 02_kerberos_attacks.md          ← Kerberoasting·AS-REP Roasting·Pass-the-Ticket
├── 03_lateral_movement_ad.md       ← PtH·NTLM 릴레이·DCSync·다중 호스트 횡이동
└── 04_ad_persistence.md            ← Golden Ticket·Shadow Credentials·ACL 남용·지속성 탐지
```

**핵심 내용:** BloodHound 수집·Cypher 쿼리, Kerberoasting/AS-REP Roasting 자동화, NTLM 릴레이·DCSync, Golden/Silver Ticket, AdminSDHolder·Shadow Credentials 지속성.

---

## 55. 탐지 우회 기법

```
55_Evasion_Techniques/
├── 01_av_evasion.md                ← XOR 인코더·샌드박스 탐지·프로세스 인젝션·AMSI 우회
├── 02_ids_ips_evasion.md           ← 패킷 단편화·DNS 터널링·트래픽 위장·Snort 룰 분석
├── 03_edr_bypass.md                ← 직접 syscall·NTDLL 후킹 탐지·메모리 인젝션 탐지
└── 04_log_evasion.md               ← 이벤트 로그 조작·타임스탬프 위조·흔적 제거 자동화
```

**핵심 내용:** AV/EDR/IDS 우회 기법 전반. XOR/AES 페이로드 인코더, 직접/간접 syscall, NTDLL 후킹 탐지, DNS/ICMP 터널링, C2 트래픽 위장, 침투 후 흔적 제거 체크리스트.

---

## 56. AI 레드팀

```
56_AI_Red_Teaming/
├── 01_ai_red_team_basics.md        ← AI 공격 기초, 공격 표면, 위협 모델링
├── 02_prompt_injection_advanced.md ← 직접·간접·다중 모달 인젝션, 탈옥 기법
├── 03_model_extraction_attacks.md  ← 모델 추출, 쿼리 기반 공격, 적대적 입력
├── 04_adversarial_examples_ml.md   ← FGSM/PGD, 전이 공격, 방어 기법
└── 05_ai_red_team_defense.md       ← 모델 강화, 입력 검증, AI 보안 아키텍처
```

**핵심 내용:** AI 시스템 레드팀 방법론, 프롬프트 인젝션 자동화, 모델 추출 공격, 방어 기법.

---

## 57. 양자 암호학

```
57_Quantum_Cryptography/
├── 01_quantum_computing_basics.md  ← 양자 컴퓨팅, Grover/Shor 알고리즘, 암호학 영향
├── 02_quantum_key_distribution.md  ← QKD 프로토콜(BB84/E91), 양자 채널 공격
├── 03_post_quantum_algorithms.md   ← CRYSTALS-Kyber/Dilithium, SPHINCS+, 구현 가이드
├── 04_nist_pqc_standard.md         ← NIST PQC 표준화 과정, 알고리즘 선정 이유
└── 05_pqc_migration.md             ← 하이브리드 암호화, 마이그레이션 전략, 타임라인
```

**핵심 내용:** 양자 컴퓨팅이 RSA/ECC에 미치는 영향, NIST PQC 표준 알고리즘, 후양자 암호로의 마이그레이션 전략.

---

## 58. 클라우드 침해 대응

```
58_Cloud_Incident_Response/
├── 01_cloud_ir_methodology.md      ← Cloud IR 프레임워크, AWS/Azure/GCP 침해 지표
├── 02_aws_forensics.md             ← CloudTrail 분석, S3/EC2 포렌식, GuardDuty 연동
├── 03_azure_gcp_forensics.md       ← Azure Sentinel 조사, GCP Chronicle, 멀티클라우드 IR
├── 04_cloud_threat_hunting.md      ← 클라우드 위협 헌팅, 이상 탐지, KQL 쿼리
└── 05_cloud_eradication.md         ← 격리·박멸·복구, 재침해 방지, PIR 템플릿
```

**핵심 내용:** Cloud IR 전 과정. CloudTrail/Activity Log 분석, 클라우드 환경 포렌식, 위협 헌팅 자동화.

---

## 59. 공급망 보안

```
59_Supply_Chain_Security/
├── 01_supply_chain_attacks.md      ← 공급망 공격 유형, 침해 지표, 탐지 전략
├── 02_software_composition.md      ← SBOM 생성·관리, 의존성 취약점 스캔
├── 03_dependency_confusion.md      ← 의존성 혼동 공격, 타이포스쿼팅, 방어
├── 04_build_integrity.md           ← 빌드 무결성 검증, 서명, SLSA 프레임워크
└── 05_vendor_risk_management.md    ← 벤더 보안 평가, 계약 요건, 지속 모니터링
```

**핵심 내용:** 소프트웨어 공급망 전 과정 보안. SBOM, 의존성 혼동, SLSA 프레임워크, 벤더 위험 관리.

---

## 60. 브라우저 보안 심화

```
60_Browser_Security_Advanced/
├── 01_browser_attack_surface.md    ← 브라우저 공격 표면, 취약점 유형, 방어 모델
├── 02_js_engine_exploitation.md    ← V8/SpiderMonkey 취약점, JIT 컴파일러 버그
├── 03_sandbox_escape.md            ← 샌드박스 탈출 기법, 프로세스 격리 우회
├── 04_extension_security.md        ← 악성 확장 분석, MV3 보안 모델
├── 05_browser_hardening.md         ← 브라우저 보안 설정, 엔터프라이즈 정책
└── 06_browser_ctf.md               ← 브라우저 보안 CTF 풀이
```

**핵심 내용:** JS 엔진 취약점(V8/SpiderMonkey), 샌드박스 탈출, 브라우저 프로세스 모델, Chrome/Firefox 버그 패턴.

---

## 61. 펌웨어 해킹

```
61_Firmware_Hacking/
├── 01_firmware_basics.md           ← 펌웨어 유형, 추출 방법, 분석 환경 구성
├── 02_firmware_extraction.md       ← JTAG/UART/SPI 덤프, binwalk 추출, 파일시스템 마운트
├── 03_static_analysis.md           ← Ghidra 역분석, 취약 함수 탐지, 하드코딩 비밀
├── 04_qemu_emulation.md            ← QEMU 에뮬레이션, firmwalker, 동적 분석
└── 05_firmware_exploitation.md     ← 버퍼 오버플로, 커맨드 인젝션, 웹 인터페이스 공격
```

**핵심 내용:** 펌웨어 전 과정 분석. 하드웨어 덤프부터 Ghidra 역분석, QEMU 에뮬레이션, 취약점 익스플로잇까지.

---

## 62. 자동차 보안

```
62_Automotive_Security/
├── 01_automotive_basics.md         ← 자동차 네트워크 아키텍처, CAN/LIN/FlexRay 프로토콜
├── 02_can_bus_hacking.md           ← CAN 버스 스니핑, 메시지 재전송, 퍼징 자동화
├── 03_ecu_analysis.md              ← ECU 펌웨어 추출, UDS 진단, 파라미터 조작
├── 04_v2x_security.md              ← V2X 통신 보안, DSRC/C-V2X 취약점
└── 05_automotive_pentest.md        ← 자동차 침투 테스트 방법론, 보고서 작성
```

**핵심 내용:** CAN 버스 스니핑·조작, ECU 펌웨어 분석, UDS 진단 프로토콜 악용, V2X/OTA 공격. python-can·Scapy·CANalyzer 실전.

---

## 63. OT/ICS 심화

```
63_OT_ICS_Advanced/
├── 01_ot_ics_basics.md             ← OT/ICS 아키텍처, Purdue 모델, 주요 프로토콜
├── 02_scada_attacks.md             ← HMI 공격, SCADA 서버 취약점, 실제 사례 분석
├── 03_plc_exploitation.md          ← PLC 프로그래밍 취약점, 사다리 로직 조작, 익스플로잇
├── 04_industrial_protocols.md      ← Modbus/DNP3/IEC 104 프로토콜 공격, 트래픽 분석
└── 05_ot_defense.md                ← OT 보안 아키텍처, 네트워크 분리, 이상 탐지
```

**핵심 내용:** Stuxnet·TRITON·INDUSTROYER·PIPEDREAM 실제 사이버 무기 해부. Modbus 강제 쓰기, PLC 조작, OT 전용 방어 아키텍처.

---

## 64. 위협 인텔리전스 플랫폼

```
64_Threat_Intel_Platform/
├── 01_tip_basics.md                ← TIP 아키텍처, 데이터 모델(STIX 2.1), 플랫폼 비교
├── 02_misp_operations.md           ← MISP 설치·운영, 이벤트 관리, API 자동화
├── 03_threat_feeds.md              ← 무료·유료 위협 피드, 품질 평가, 자동 수집 파이프라인
├── 04_ioc_management.md            ← IOC 라이프사이클, 노이즈 감소, TAXII 연동
└── 05_tip_automation.md            ← SOAR 연동, 자동 대응, 위협 피드 오케스트레이션
```

**핵심 내용:** TIP 플랫폼(MISP/OpenCTI) 구축·운영, 위협 피드 자동화, IOC 관리, SOAR 연동 자동 대응.

---

## 🧪 CTF 실습 환경 (labs/)

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

5개 도커 기반 CTF 취약 환경 — 웹·바이너리·네트워크·클라우드·통합 시나리오를 로컬에서 즉시 실습. 플래그 12개, `start_lab.sh` 한 번으로 전체 환경 기동.

---

## ⚠️ 법적 고지

```diff
- [!] 경고: 이 저장소의 모든 기법은 반드시 허가된 환경에서만 사용해야 합니다.
+ [✓] CTF, 버그바운티, 계약된 모의해킹 범위 내에서만 활용
+ [✓] 취약점 발견 시 Responsible Disclosure 원칙 준수
- [!] 무단 시스템 접근은 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 위반
```

---

## 🤝 기여 & 커뮤니티

**이 레포가 도움이 됐다면 ⭐ Star를 눌러주세요 — 더 많은 사람이 발견할 수 있습니다.**

| 기여 방법 | 바로가기 |
|----------|---------|
| 오탈자·오류 수정 | [이슈 열기](https://github.com/lsszz2100/VibeHacking/issues/new) |
| 새 내용 제안 | [Discussion 시작](https://github.com/lsszz2100/VibeHacking/discussions) |
| 기여 가이드 | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| 행동 강령 | [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) |
| 보안 정책 | [SECURITY.md](./SECURITY.md) |

> 처음 기여하시나요? `good first issue` 라벨이 붙은 이슈부터 시작해보세요.

---

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,50:003300,100:0d0d0d&height=100&section=footer&text=Hack+Smart.+Defend+Hard.&fontSize=20&fontColor=00FF41&animation=fadeIn&fontAlignY=65" width="100%" />
