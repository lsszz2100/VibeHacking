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
7. [vhack alias — 셸 alias 등록](#7-vhack-alias--셸-alias-등록)
8. [vhack update — 업데이트](#8-vhack-update--업데이트)
9. [학습 로드맵 예시](#9-학습-로드맵-예시)
10. [실습 시나리오 예시](#10-실습-시나리오-예시)
11. [브라우저 워게임 — 침투 콘솔](#11-브라우저-워게임--침투-콘솔)

---

## 1. vhack 개요

```
vhack — VibeHacking CLI
사이버보안 학습 자료 탐색 + Docker 실습 환경 관리

사용법:
  python3 vhack.py <명령어> [옵션]

명령어:
  list      전체 75개 섹션 목록 표시
  study     섹션 파일 열람
  lab       Docker 실습 환경 관리
  search    전체 마크다운 문서 검색
  info      섹션 상세 정보
  alias     셸 alias 자동 등록/제거/확인
  update    git pull로 최신 버전 업데이트
```

### 설치 & 전역 사용

```bash
# 방법 1: python3으로 직접 실행 (설치 불필요)
python3 vhack.py list

# 방법 2: alias 자동 등록 → vhack 으로 바로 사용 (권장)
python3 vhack.py alias install
source ~/.bashrc   # 현재 세션에 즉시 적용
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
# 전체 75개 섹션 목록 표시
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

  총 75개 섹션
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

   06   🧪 펌웨어 해킹 랩            ★★★   binwalk 추출 · QEMU ARM 에뮬레이션 · 하드코딩 자격증명 발견 CTF
         URL: http://localhost:8062 (웹 패널) · docker exec -it firmware_analyzer bash  관련 섹션: 61, 27, 65

   07   🧪 모바일 보안 랩            ★★★   APK 정적 분석(jadx·apktool) · Frida 동적 분석 · JWT alg:none 우회
         URL: http://localhost:8072 (취약 API) · docker exec -it apk_analyzer bash  관련 섹션: 28, 52, 47
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
- Lab 06 (펌웨어): 약 2~4분 (ubuntu + python slim)
- Lab 07 (모바일): 약 3~6분 (default-jdk 포함)

### 4-3. 실습 환경 접속

| 랩 | 접속 방법 | 기본 계정 |
|----|----------|----------|
| **Lab 01 — 웹** | http://localhost:8080 (허브 페이지) | — |
| **DVWA** | http://localhost:8080/dvwa/ ⚠ DB 초기화 필요 | admin / password |
| **Juice Shop** | http://localhost:3001 | (회원가입) |
| **WebGoat** | http://localhost:8081/WebGoat | (회원가입) |
| **SQLi 타겟** | http://localhost:8080/sqli/ | — |
| **Lab 02 — pwn** | `nc localhost 10001` (BOF) · `10002` (ret2libc) · `10003` (ROP) · `10004` (fmtstr) · `10005` (heap) | — |
| **Lab 03 — 네트워크** | `docker exec -it net_lab_attacker bash` | — |
| **Lab 04 — 클라우드** | http://localhost:8080 (SSRF) · http://localhost:8443 (K8s) · http://localhost:5000 (Registry) | — |
| **Lab 05 — 통합** | http://localhost:8888 | admin / admin123 |
| **Lab 06 — 펌웨어** | http://localhost:8062 (웹 패널) · `docker exec -it firmware_analyzer bash` (binwalk 분석) | admin / firmware_admin_2024 |
| **Lab 07 — 모바일** | http://localhost:8072 (취약 API) · `docker exec -it apk_analyzer bash` (jadx·frida) | API 키: sk-mobile-dev-key-2024-insecure |

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

## 7. vhack alias — 셸 alias 등록

```
사용법:
  vhack alias install [--profile <파일경로>]   셸 프로파일에 alias 등록
  vhack alias remove                           등록된 alias 제거
  vhack alias status                           설치 현황 확인

지원 셸: bash · zsh · fish · sh · PowerShell(pwsh)
```

### 7-1. alias 설치 (`alias install`)

`$SHELL` 환경변수로 현재 셸을 자동 감지하고, 홈 디렉토리의 RC 파일에 alias 줄을 추가합니다.
이후 `vhack` 만 입력하면 어느 디렉토리에서든 CLI를 실행할 수 있습니다.

```bash
# 자동 감지 설치 (권장)
python3 vhack.py alias install

# 출력 예시:
# 🔗 vhack alias 설치
#
#   ✓ [bash] 설치 완료: /home/user/.bashrc
#       추가된 줄: alias vhack="python3 /path/to/vhack.py"  # vhack-alias
#
# ✓ 설치 완료!
#   지금 바로 적용하려면 아래 명령어를 실행하세요:
#     source /home/user/.bashrc

# 현재 세션에 즉시 적용
source ~/.bashrc   # bash
source ~/.zshrc    # zsh
```

```bash
# 특정 프로파일에만 설치
python3 vhack.py alias install --profile ~/.zshrc
python3 vhack.py alias install --profile ~/.bash_profile
```

**셸별 자동 감지 파일:**

| 셸 | 탐색 파일 (우선순위 순) |
|----|------------------------|
| bash | `~/.bashrc` → `~/.bash_profile` → `~/.profile` |
| zsh  | `~/.zshrc` |
| fish | `~/.config/fish/config.fish` |
| PowerShell | `$PROFILE` (pwsh 실행 경로 자동 탐지) |

> 이미 설치된 프로파일은 건너뜁니다 — 중복 실행해도 안전합니다.

### 7-2. alias 제거 (`alias remove`)

모든 프로파일에서 등록된 alias 줄을 찾아 삭제합니다.

```bash
vhack alias remove

# 출력 예시:
# 🗑️  vhack alias 제거
#   ✓ 제거 완료: /home/user/.bashrc
# ✓ 제거 완료!
```

### 7-3. 설치 현황 확인 (`alias status`)

어떤 프로파일에 alias가 등록됐는지, 현재 세션에서 활성화됐는지 확인합니다.

```bash
vhack alias status

# 출력 예시 (설치 후):
# 📋 vhack alias 설치 현황
#
#   ● /home/user/.bashrc  설치됨
#       alias vhack="python3 /path/to/vhack.py"  # vhack-alias
#   ○ /home/user/.profile  미설치
#
#   ✓ 현재 세션에서 사용 가능: /usr/local/bin/vhack

# 출력 예시 (미설치):
# 📋 vhack alias 설치 현황
#   ○ /home/user/.bashrc  미설치
#   설치된 alias가 없습니다.
#   설치: python3 vhack.py alias install
```

### 7-4. 빠른 참고

```bash
python3 vhack.py alias install          # 자동 감지 설치
python3 vhack.py alias install --profile ~/.zshrc  # 파일 직접 지정
python3 vhack.py alias status           # 현황 확인
python3 vhack.py alias remove           # 제거
```

---

## 8. vhack update — 업데이트

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

## 9. 학습 로드맵 예시

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

## 10. 실습 시나리오 예시

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

## 11. 브라우저 워게임 — 침투 콘솔

이론·실습과 별개로, **설치 없이 브라우저에서 바로** 실력을 점검하는 터미널형 CTF 워게임이 함께 제공됩니다. 가짜 셸로 표적 `vibe.corp`의 보안 계층 5개를 한 겹씩 침투합니다.

🔗 **바로 플레이:** `https://lsszz2100.github.io/VibeHacking/`
🔗 **로컬 실행:** `cd wargame && python3 -m http.server 8000` → `http://localhost:8000`

```text
root@vibe:~$ connect perimeter       # 첫 계층 침투
root@vibe:/perimeter$ cat 1          # 1번 잠금장치(문제) 열기
root@vibe:/perimeter$ submit FLAG{...}   # 정답 제출 → ACCESS GRANTED
```

| 명령 | 설명 |
|------|------|
| `help` / `ls` / `map` | 명령 목록 / 현재 위치 / 침투 경로 지도 |
| `connect <노드>` | 계층 접속 (perimeter→webserver→internal→vault→core) |
| `cat <번호>` | 잠금장치(문제) 열기 |
| `submit <flag>` | 플래그 제출 (또는 그냥 입력) |
| `hint` | 힌트 공개 (점수 −20%/개) |
| `status` / `lang` / `sound` | 진행도 / 한·영 전환 / 사운드 토글 |

- **5계층 350문제**, 한 계층의 요구 개수를 풀면 `LAYER BREACHED` 로 다음 계층이 열립니다.
- 정답은 **SHA-256 해시로만** 저장되어(평문 없음) 브라우저 안에서 검증됩니다 — 교육용, 외부 시스템 공격 금지.
- 각 문제는 본 레포의 75개 섹션 주제와 연결됩니다. 자세한 안내는 [`wargame/README.md`](wargame/README.md) 참고.
- 💡 첫 플래그는 페이지 소스(`Ctrl+U`)에 숨어 있습니다. AI CLI에게 "워게임 N번 힌트만 줘"처럼 물어볼 수도 있습니다.

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
# View all 75 sections
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

# Shell alias (run vhack from anywhere)
python3 vhack.py alias install           # Auto-detect shell → register alias
python3 vhack.py alias install --profile ~/.zshrc  # Target specific file
python3 vhack.py alias status            # Check installation
python3 vhack.py alias remove            # Unregister alias

# Search & info
python3 vhack.py search "SQL injection"  # Search all docs
python3 vhack.py info 54                 # Section details
python3 vhack.py update                  # Git pull
```

## Alias Quick Reference

```bash
# After install, use vhack from any directory
python3 vhack.py alias install   # installs → alias vhack="python3 /path/vhack.py"
source ~/.bashrc                  # apply to current session
vhack list                        # no more "python3 vhack.py" needed
```

| Command | Description |
|---------|-------------|
| `alias install` | Detect shell, add alias to RC file. Idempotent. |
| `alias install --profile <path>` | Target a specific profile file |
| `alias status` | Show which profiles have the alias; whether active in current session |
| `alias remove` | Remove alias from all profiles |

**Supported shells:** bash · zsh · fish · sh · PowerShell (pwsh)

## Lab Quick Access

| Lab | Start | Access | Topics |
|-----|-------|--------|--------|
| 01 Web | `vhack lab start 01` | http://localhost:8080 | SQLi, XSS, CSRF |
| 02 Pwn | `vhack lab start 02` | `nc localhost 10001~10005` | BOF, ret2libc, ROP, fmtstr, heap |
| 03 Network | `vhack lab start 03` | `docker exec -it net_lab_attacker bash` | SSH, FTP, DNS |
| 04 Cloud | `vhack lab start 04` | http://localhost:8080 | SSRF, K8s, containers |
| 05 Full | `vhack lab start 05` | http://localhost:8888 | APT chain simulation |

## Study Tips

1. **Register alias first** — Run `python3 vhack.py alias install` once, then use `vhack` everywhere
2. **Start with section 0** — Every file begins with `## 0. 초보자를 위한 개념 이해` (Beginner Guide) — plain-language explanations with ASCII diagrams
3. **Learn → Practice** — Read the theory (`vhack study`), then start the related lab (`vhack lab start`)
4. **Search first** — Use `vhack search` to find relevant content before diving into a section
5. **Stop labs when done** — `vhack lab stop --all` frees up resources

## Browser Wargame — Infiltration Console

Beyond the CLI and labs, a **zero-install, browser-based** terminal CTF ships with the repo. Drive a fake shell to breach the five security layers of `vibe.corp`, one at a time.

🔗 **Play now:** `https://lsszz2100.github.io/VibeHacking/`
🔗 **Run locally:** `cd wargame && python3 -m http.server 8000` → `http://localhost:8000`

```text
root@vibe:~$ connect perimeter        # breach the first layer
root@vibe:/perimeter$ cat 1           # open lock #1 (a challenge)
root@vibe:/perimeter$ submit FLAG{...} # submit → ACCESS GRANTED
```

| Command | Description |
|---------|-------------|
| `help` / `ls` / `map` | commands / list here / infiltration map |
| `connect <node>` | connect to a layer (perimeter→webserver→internal→vault→core) |
| `cat <n>` | open a lock (challenge) |
| `submit <flag>` | submit a flag (or just type it) |
| `hint` | reveal a hint (−20% each) |
| `status` / `lang` / `sound` | progress / toggle language / toggle sound |

- **5 layers, 350 challenges.** Clearing a layer's quota fires `LAYER BREACHED` and unlocks the next.
- Answers are stored as **SHA-256 hashes only** (no plaintext) and verified in the browser — educational, never attack external systems.
- Each challenge maps to a topic from the repo's 75 sections. See [`wargame/README.md`](wargame/README.md) for details.
- 💡 The first flag hides in the page source (`Ctrl+U`). You can even ask an AI CLI for "just a hint on wargame #N".

> ⚠️ **Legal Notice**: Use all content for authorized security research, CTF competitions, and learning only. Unauthorized use against real systems is illegal.
