> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 사용 가이드 — vhack CLI 명령어 레퍼런스

## 목차

1. [vhack 개요](#1-vhack-개요)
2. [vhack list — 섹션 목록](#2-vhack-list--섹션-목록)
3. [vhack study — 학습 내용 읽기](#3-vhack-study--학습-내용-읽기)
4. [vhack lab — 실습 환경 관리](#4-vhack-lab--실습-환경-관리)
5. [vhack search — 전체 문서 검색](#5-vhack-search--전체-문서-검색)
6. [vhack info — 섹션 상세 정보](#6-vhack-info--섹션-상세-정보)
7. [vhack update — 업데이트](#7-vhack-update--업데이트)
8. [학습 로드맵 예시](#8-학습-로드맵-예시)
9. [실습 시나리오 예시](#9-실습-시나리오-예시)

---

## 1. vhack 개요

```
vhack — VibeHacking CLI
사이버보안 학습 자료 탐색 + Docker 실습 환경 관리

사용법:
  python3 vhack.py <명령어> [옵션]

명령어:
  list      전체 64개 섹션 목록 표시
  study     섹션 파일 열람
  lab       Docker 실습 환경 관리
  search    전체 마크다운 문서 검색
  info      섹션 상세 정보
  update    git pull로 최신 버전 업데이트
```

### 설치 & 전역 사용

```bash
# 방법 1: python3으로 직접 실행 (설치 불필요)
python3 vhack.py list

# 방법 2: alias 등록 후 vhack 으로 사용
echo 'alias vhack="python3 /path/to/VibeHacking/vhack.py"' >> ~/.bashrc
source ~/.bashrc
vhack list
```

---

## 2. vhack list — 섹션 목록

```
사용법: vhack list [--search <키워드>]

옵션:
  --search <키워드>   섹션명(영어/한국어)으로 필터링
```

### 예시

```bash
# 전체 64개 섹션 목록 표시
vhack list

# "web" 포함 섹션만 표시
vhack list --search web

# "AI" 관련 섹션 검색
vhack list --search AI

# "포렌식" 관련 섹션 검색
vhack list --search 포렌식
```

### 출력 예시

```
📚 VibeHacking 섹션 목록

  #   섹션명                                     한국어 설명
  ──────────────────────────────────────────────────────────────────────
    1  🐧 01_Linux_Basics                        리눅스 기초 [4파일]
    2  🌐 02_Network_Hacking                     네트워크 해킹 [4파일]
    5  🕷️ 05_Web_Hacking                         웹 해킹 [4파일]
   ...
   64  📊 64_Threat_Intel_Platform               위협 인텔 플랫폼 [5파일]

  총 64개 섹션
```

---

## 3. vhack study — 학습 내용 읽기

```
사용법:
  vhack study <섹션번호>             섹션 파일 목록 표시
  vhack study <섹션번호> <파일번호>   해당 파일 내용 읽기

인자:
  섹션번호   1~64 (vhack list 로 확인)
  파일번호   1~5 (생략 시 파일 목록만 표시)
```

### 예시

```bash
# 섹션 5 (웹 해킹) 파일 목록 보기
vhack study 5

# 섹션 5의 첫 번째 파일 읽기 (OWASP Top 10)
vhack study 5 1

# 섹션 54 (Active Directory 공격) 파일 목록
vhack study 54

# 섹션 46 (CTF 기법) 두 번째 파일 읽기
vhack study 46 2
```

### 파일 목록 출력 예시

```
🕷️ 섹션 05: 웹 해킹 (Web_Hacking)

  #   파일명
  ────────────────────────────────────────────────────────────
    1  ● 01_owasp_top10.md                            45KB
    2  ● 02_sql_injection_advanced.md                 38KB
    3  ● 03_xss_csrf_file_upload.md                   42KB
    4  ● 04_waf_bypass_advanced_web.md                35KB

  ● = 초보자 가이드 포함

  사용법: vhack study 5 <파일번호>  예: vhack study 5 1
```

### 파일 내용 읽기 조작

파일을 열면 터미널 페이지 모드로 표시됩니다:

```
-- Enter: 다음 페이지 | q: 종료 --
```

- `Enter` — 다음 페이지
- `q` → 종료
- `Ctrl+C` → 강제 종료

### 초보자 가이드 (`## 0.` 섹션)

모든 파일 시작 부분에 `## 0. 초보자를 위한 개념 이해` 섹션이 있습니다:
- 해당 주제가 무엇인지 쉬운 설명
- 왜 배우는가 (실제 활용 사례)
- 핵심 개념 ASCII 다이어그램
- 필요한 도구 목록
- 바로 실행 가능한 예제 코드

---

## 4. vhack lab — 실습 환경 관리

```
사용법:
  vhack lab ls                  실습 환경 목록 (설명 + URL)
  vhack lab start <번호>        실습 환경 Docker 시작
  vhack lab stop <번호>         실습 환경 종료
  vhack lab stop --all          모든 실습 환경 종료
  vhack lab status              실행 중인 컨테이너 목록
  vhack lab logs <번호>         특정 랩 로그 실시간 보기

전제: Docker + Docker Compose 설치 필요 → INSTALL.md 참조
```

### 4-1. 실습 환경 목록 (`lab ls`)

```bash
vhack lab ls
```

```
🔬 실습 환경 목록

  #     이름                       난이도   설명
  ───────────────────────────────────────────────────────────────────────────
   01   🧪 웹 해킹 랩               ★★☆   DVWA · Juice Shop · WebGoat — SQLi, XSS, IDOR, 인증 우회
         URL: http://localhost:8080   관련 섹션: 5, 12, 23

   02   🧪 바이너리 익스플로잇 랩    ★★★   BOF · ret2libc · ROP · fmtstr · tcache heap
         URL: nc localhost 10001~10005  관련 섹션: 9, 19, 3

   03   🧪 네트워크 해킹 랩          ★★☆   SSH · FTP · DNS zone transfer · SMTP relay · 피벗
         URL: docker exec -it net_lab_attacker bash  관련 섹션: 2, 24, 10

   04   🧪 클라우드/컨테이너 보안 랩  ★★★   AWS IMDS · SSRF → 자격증명 탈취 · K8s 탈출 · 컨테이너 탈출
         URL: http://localhost:8080 (SSRF target)  관련 섹션: 14, 29, 38

   05   🧪 전체 시나리오 통합 랩      ★★★★  APT 체인 · 외부 웹 → 내부망 이동 → DB 침투 → 데이터 탈취
         URL: http://localhost:8888  관련 섹션: 10, 17, 44
```

### 4-2. 실습 환경 시작 (`lab start`)

```bash
# 웹 해킹 랩 시작
vhack lab start 01

# 출력:
# 🚀 웹 해킹 랩 시작 중...
# [+] Building ...  (최초 실행 시 이미지 다운로드, 5~10분)
# ✓ 웹 해킹 랩 시작 완료!
#   접근: http://localhost:8080
#   로그: vhack lab logs 01
#   종료: vhack lab stop 01
```

**최초 실행 시 Docker 이미지 다운로드 시간:**
- Lab 01 (웹): 약 2~5분 (이미지 총 ~2GB)
- Lab 02 (pwn): 약 3~5분
- Lab 03 (네트워크): 약 3~5분
- Lab 04 (클라우드): 약 5~8분
- Lab 05 (통합): 약 8~15분

### 4-3. 실습 환경 접속

| 랩 | 접속 방법 | 기본 계정 |
|----|----------|----------|
| **Lab 01 — 웹** | http://localhost:8080 | admin / password |
| **DVWA** | http://localhost:8080/dvwa | admin / password |
| **Juice Shop** | http://localhost:3000 | (회원가입) |
| **WebGoat** | http://localhost:8081/WebGoat | (회원가입) |
| **Lab 02 — pwn** | `nc localhost 10001` (BOF), `10002` (ROP) | — |
| **Lab 03 — 네트워크** | `docker exec -it net_lab_attacker bash` | — |
| **Lab 04 — 클라우드** | http://localhost:8080/ssrf | — |
| **Lab 05 — 통합** | http://localhost:8888 | admin / admin123 |

### 4-4. 실습 환경 종료

```bash
# 특정 랩 종료
vhack lab stop 01

# 모든 랩 종료 (학습 완료 후 필수!)
vhack lab stop --all
```

### 4-5. 실행 중인 컨테이너 확인

```bash
vhack lab status

# 출력:
# 📊 실행 중인 랩 컨테이너
#
#   NAMES               STATUS         PORTS
#   web_lab_dvwa        Up 2 hours     172.16.0.10/tcp
#   web_lab_juiceshop   Up 2 hours     172.16.0.20/tcp
#   web_lab_nginx       Up 2 hours     0.0.0.0:8080->80/tcp
```

### 4-6. 실시간 로그 보기

```bash
vhack lab logs 01   # 웹 해킹 랩 로그 (Ctrl+C로 종료)
```

---

## 5. vhack search — 전체 문서 검색

```
사용법: vhack search <키워드>

인자:
  키워드   검색할 문자열 (한국어, 영어 모두 가능)
```

### 예시

```bash
# "Kerberoasting" 검색
vhack search Kerberoasting

# "SQL 인젝션" 검색
vhack search "SQL 인젝션"

# "CVSS" 관련 내용 검색
vhack search CVSS

# "reverse shell" 검색
vhack search "reverse shell"

# 특정 도구 사용법 검색
vhack search mimikatz
vhack search "burp suite"
```

### 출력 예시

```
🔎 'Kerberoasting' 검색 중...

  📄 54_Active_Directory_Attacks/02_kerberos_attacks.md
     45: Kerberoasting은 SPN이 설정된 서비스 계정의 TGS 티켓을 요청해
     46: Kerberoasting 도구: GetUserSPNs.py (Impacket), Rubeus
     89: # Kerberoasting (허가된 AD 환경에서만!)

  📄 10_Pentest_Methodology/01_pentest_methodology.md
     234: Kerberoasting → 서비스 계정 비밀번호 획득
     ... 및 2개 더

  총 2개 파일에서 발견
```

---

## 6. vhack info — 섹션 상세 정보

```
사용법: vhack info <섹션번호>
```

### 예시

```bash
# 섹션 54 (AD 공격) 상세 정보
vhack info 54

# 출력:
# 🏢 섹션 54: 액티브 디렉토리 공격
#
#   이름 (영어): Active_Directory_Attacks
#   파일 수:     5개
#   총 라인:     3,241줄
#   총 크기:     198 KB
#
#   파일 목록:
#     1. 01_ad_enumeration.md      38KB
#     2. 02_kerberos_attacks.md    42KB
#     3. 03_lateral_movement_ad.md 40KB
#     4. 04_ad_persistence.md      45KB
#     5. 05_ad_defense_and_detection.md 33KB
#
#   연관 실습 환경:
#     → 없음 (Lab 03 네트워크 랩 활용 권장)
```

---

## 7. vhack update — 업데이트

```bash
# 최신 학습 자료 업데이트 (git pull)
vhack update

# 출력:
# 🔄 최신 버전으로 업데이트 중...
# From https://github.com/lsszz2100/VibeHacking
#   86066c1..0f361dc  main -> origin/main
# ✓ 업데이트 완료!
```

---

## 8. 학습 로드맵 예시

### 초보자 로드맵 (6개월)

```
1개월: 기초 다지기
  vhack study 1    # Linux 기초
  vhack study 20   # 셸 스크립팅
  vhack study 16   # 암호학

2개월: 웹 해킹
  vhack lab start 01   # 웹 해킹 랩 시작
  vhack study 5        # 웹 해킹 이론 학습
  vhack study 12       # 버그 바운티

3개월: 네트워크/시스템
  vhack lab start 03   # 네트워크 랩
  vhack study 2        # 네트워크 해킹
  vhack study 3        # 시스템 해킹

4개월: 바이너리 분석
  vhack lab start 02   # pwn 랩
  vhack study 4        # 리버스 엔지니어링
  vhack study 9        # 익스플로잇 기법

5개월: 고급 주제
  vhack study 17   # 레드팀 작전
  vhack study 54   # AD 공격
  vhack study 46   # CTF 기법

6개월: 통합 실습
  vhack lab start 05   # 전체 시나리오 랩
  vhack study 10       # 침투 테스트 방법론
  vhack study 44       # 사고 대응
```

### 자격증 준비 로드맵

```bash
# 정보보안기사 (한국)
vhack study 41 1    # 필기 완전 정복
vhack study 41 2    # 실기 대비
vhack study 41 5    # 법령

# CEH (국제)
vhack study 10      # 침투 테스트 방법론
vhack study 33      # OSINT/사회공학
vhack study 15      # WiFi 해킹

# OSCP 준비
vhack lab start 02  # 바이너리 익스플로잇
vhack lab start 05  # 통합 시나리오
vhack study 9       # 익스플로잇 기법
vhack study 21      # 윈도우 익스플로잇
```

---

## 9. 실습 시나리오 예시

### 시나리오 1: 웹 해킹 기초 (Lab 01)

```bash
# 1. 웹 해킹 이론 학습
vhack study 5 1    # OWASP Top 10 읽기

# 2. 실습 환경 시작
vhack lab start 01

# 3. DVWA 접속 후 난이도 설정
# → http://localhost:8080/dvwa
# → Security: Low → 실습 시작

# 4. SQL 인젝션 실습
vhack study 5 2    # SQL 인젝션 심화 학습 병행

# 5. 종료
vhack lab stop 01
```

### 시나리오 2: AD 공격 학습 (Lab 03 활용)

```bash
# 1. 이론 먼저
vhack study 54     # AD 공격 섹션 파일 목록
vhack study 54 1   # AD 열거
vhack study 54 2   # Kerberos 공격

# 2. 관련 도구 검색
vhack search "BloodHound"
vhack search "Impacket"

# 3. 네트워크 랩으로 실습 (AD 없지만 기초 훈련)
vhack lab start 03

# 4. 내부에서 도구 연습
docker exec -it net_lab_attacker bash
# → nmap, hashcat, impacket 실습
```

### 시나리오 3: CTF 준비

```bash
# CTF 기법 학습
vhack study 46 1   # CTF 방법론과 도구
vhack study 46 2   # Pwn & Rev CTF
vhack study 46 3   # Web & Crypto CTF

# pwn 랩으로 직접 실습
vhack lab start 02
nc localhost 10001  # BOF 챌린지

# 웹 CTF
vhack lab start 01
# Juice Shop에서 CTF 스타일 문제 풀기
```

---

> ⚠️ **법적 주의사항**
>
> 이 저장소의 모든 내용은 **합법적인 보안 학습 및 연구** 목적으로만 사용하세요.
> - 허가 없이 타인의 시스템에 적용하는 것은 **불법**입니다.
> - 실습 환경은 격리된 로컬 환경에서만 실행하세요.
> - CTF, 버그 바운티, 허가된 침투 테스트에만 활용하세요.

---

<a name="english"></a>

# Usage Guide — vhack CLI Command Reference

## Quick Reference

```bash
# View all 64 sections
python3 vhack.py list
python3 vhack.py list --search web      # Filter sections

# Study content
python3 vhack.py study 5               # Section 5 file list
python3 vhack.py study 5 1             # Read first file

# Manage lab environments (requires Docker)
python3 vhack.py lab ls                # List available labs
python3 vhack.py lab start 01          # Start web hacking lab
python3 vhack.py lab stop 01           # Stop web hacking lab
python3 vhack.py lab stop --all        # Stop all labs
python3 vhack.py lab status            # Running containers
python3 vhack.py lab logs 01           # Live logs

# Search & info
python3 vhack.py search "SQL injection"  # Search all docs
python3 vhack.py info 54                 # Section details
python3 vhack.py update                  # Git pull
```

## Lab Quick Access

| Lab | Start | Access | Topics |
|-----|-------|--------|--------|
| 01 Web | `vhack lab start 01` | http://localhost:8080 | SQLi, XSS, CSRF |
| 02 Pwn | `vhack lab start 02` | `nc localhost 10001` | BOF, ROP, heap |
| 03 Network | `vhack lab start 03` | `docker exec -it net_lab_attacker bash` | SSH, FTP, DNS |
| 04 Cloud | `vhack lab start 04` | http://localhost:8080 | SSRF, K8s, containers |
| 05 Full | `vhack lab start 05` | http://localhost:8888 | APT chain simulation |

## Study Tips

1. **Start with section 0** — Every file begins with `## 0. 초보자를 위한 개념 이해` (Beginner Guide) — plain-language explanations with ASCII diagrams
2. **Learn → Practice** — Read the theory (`vhack study`), then start the related lab (`vhack lab start`)
3. **Search first** — Use `vhack search` to find relevant content before diving into a section
4. **Stop labs when done** — `vhack lab stop --all` frees up resources

> ⚠️ **Legal Notice**: Use all content for authorized security research, CTF competitions, and learning only. Unauthorized use against real systems is illegal.
