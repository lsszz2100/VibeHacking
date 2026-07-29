# ⚔️ Vibe Hacking Wargame — Infiltration Terminal

브라우저 안의 **가짜 셸로 표적 네트워크에 침투하는** 단계별 사이버보안 워게임입니다. 백엔드 없이 100% 클라이언트 측에서 동작하며, `vibe.corp`의 보안 계층 5개(외곽→웹서버→내부망→금고→코어)를 한 계층씩 뚫어 코어에 도달합니다.

A browser-based, **terminal-style infiltration wargame**. You drive a fake shell to breach 5 security layers of `vibe.corp` — perimeter → web server → internal → vault → core. 100% client-side, no backend.

🔗 **플레이 / Play:** `https://lsszz2100.github.io/VibeHacking/`
*(GitHub Pages 활성화 후 접속 가능 / available once GitHub Pages is enabled — see below)*

---

## 🎮 어떻게 플레이하나요 / How to play

사이트를 열면 부팅 시퀀스 후 **침투 콘솔**이 뜹니다. 마우스가 아니라 **명령**으로 플레이합니다 — `help` 를 입력해 시작하세요.

Opening the site runs a boot sequence and drops you into an **infiltration console**. You play with **commands**, not the mouse — type `help` to begin.

| 명령 / command | 설명 / description |
|----------------|------|
| `help` | 명령 목록 / list all commands |
| `ls` | 현재 위치 목록 (계층 또는 잠금장치) / list here (layers or locks) |
| `map` | 침투 경로 지도 — 어떤 계층이 뚫렸는지 / infiltration map |
| `connect <노드>` | 계층에 접속 / connect to a layer (e.g. `connect perimeter`) |
| `cat <번호>` | 잠금장치(문제)를 열어 표적 설정 / open a lock as target (e.g. `cat 1`) |
| `hint` | 현재 표적 힌트 공개 (점수 −20%/개) / reveal a hint (−20% each) |
| `submit <flag>` | 플래그 제출 / submit a flag (or just type it when a target is open) |
| `status` | 점수·등급·계층별 진행도 / score, rank, per-layer progress |
| `lang` / `sound` | 한·영 전환 / 사운드 토글 · toggle language / sound |
| `clear` / `reset` | 화면 지우기 / 진행도 초기화 · clear screen / reset progress |

**플레이 순서 (KO)**

1. **`connect perimeter`** 로 첫 계층에 침투 → **`cat 1`** 로 첫 잠금장치(문제)를 엽니다.
2. 정답(플래그 `FLAG{...}` 또는 단답)을 입력하면 **`ACCESS GRANTED`**, 틀리면 **`ACCESS DENIED`**.
3. 한 계층에서 요구 개수(아래 표)를 풀면 **`LAYER BREACHED`** — 다음 계층이 열립니다.
4. 진행도·점수·언어·사운드는 브라우저 `localStorage`에 자동 저장됩니다.
5. 상단 상태바에 점수·등급(🥚→👑)·침투 진행률이 실시간 표시됩니다.

**How to play (EN)**

1. `connect perimeter` to breach the first layer → `cat 1` to open the first lock (challenge).
2. Enter the answer (flag `FLAG{...}` or a short answer) → `ACCESS GRANTED`, or `ACCESS DENIED` if wrong.
3. Clear a layer's quota (see table) to trigger `LAYER BREACHED` and unlock the next layer.
4. Progress, score, language and sound auto-save to `localStorage`.
5. The top status bar shows score, rank (🥚→👑) and breach progress live.

> 💡 첫 플래그는 **이 페이지의 소스**에 숨어 있습니다. `Ctrl+U` 를 눌러 보세요. 콘솔(F12)·쿠키·숨겨진 DOM에도 심어진 플래그가 있습니다.
> The first flag hides in **this page's source** — press `Ctrl+U`. More flags are planted in the console (F12), a cookie, and a hidden DOM node.

### 보안 계층(티어) — 한 계층씩 침투 / Security layers (tiers) — breach one at a time

| 계층 / node | 티어 / tier | 주제 / topics | 문제 / count | 통과 / breach |
|------|:---:|------|:------:|:--------:|
| `perimeter` 외곽 | **0** | 페이지 소스·개발자도구·기본 인코딩 디코딩·이진수·역순/URL/NATO·메타태그·해시 종류 식별·헥스 덤프·리눅스 기본 명령·스크립트 첫 줄 규약·클라우드 권한·네트워크·지리 단위 기초·계정 보호 통제·시그널·디스크 이미징·증거 무결성 보존 하드웨어·시스템 정보 조회 명령 / page source, devtools, basic decoding, binary, reverse/URL/NATO, meta tags, hash identification, hex dumps, core Linux commands, script header convention, cloud identity, networking and geography basics, account protection, signals, disk imaging, evidence-integrity preservation hardware, system-info command | 24 | 4 |
| `webserver` 웹서버 | **1** | 고전 암호(ROT13/Hex/Caesar/Morse/Atbash/A1Z26), 쿠키, HTTP, Basic 인증, 포트 스캐닝, 클라우드 리소스 식별·시점 백업, 심볼릭 링크, 트래픽 분산, 패킷 캡처·수집 도구, 증거 관리 절차, 동적 링크 확인, 바이트 순서, 컨테이너 이미지 정의, PE 실행파일 매직, 안드로이드 바이트코드 포맷, ELF 헤더·심볼 조회·역어셈블 도구 / classic ciphers, cookies, HTTP, Basic auth, port scanning, cloud resource naming & point-in-time backups, symlinks, traffic distribution, packet capture tooling, evidence handling, dynamic-link inspection, byte order, container image definition, PE executable magic, Android bytecode format, ELF header/symbol inspection & disassembly tooling | 29 | 6 |
| `internal` 내부망 | **2** | SQLi·XSS·JWT·해시·Base32/58·Unicode·Vigenère·LFI·접근제어 우회·리버싱·클라우드 객체 스토리지·K8s 기초·프로세스/파일 모니터링 도구·디버거 사용법·파일 카빙·NTFS 은닉 스트림·K8s 권한 모델·보안그룹 CIDR·악성코드 패커 회피·섹션 무작위도 분석·시스템 콜 추적 | 30 | 9 |
| `vault` 금고 | **3** | XOR(단일/반복키)·ROT47·Base85·포맷스트링·SSTI·탐지 규칙 언어·AD·ELF매직·메시지 인증 코드·IMDS·STS 임시 자격증명·클라우드 오설정 감시·동적 링크 테이블 덮어쓰기·도커 소켓 마운트·IMDSv2 토큰·프로세스 이미지 치환 인젝션·위치 독립 실행파일 | 30 | 7 |
| `core` 코어 | **4** | 체인/이중·3중 디코딩, Vigenère, 컨테이너 탈출, K8s 시크릿 저장 방식, AES-GCM, JWT, AI 보안, 윈도우 실행 흔적, 메모리 포렌식, 메모리 보호기법, 코드 재사용·해제 후 사용 익스플로잇, 서버리스 초기화 지연, USB 장치 흔적, NTFS 메타데이터, 타임스탬프 조작, 글리브 힙 캐시 poisoning / chained decoding, Vigenère, container escape, how K8s stores secrets, AES-GCM, JWT, AI security, Windows execution artifacts, memory forensics, memory protections, code-reuse & use-after-free exploitation, serverless init latency, USB device artifacts, NTFS metadata, timestamp tampering, glibc heap-cache poisoning | 29 | 5 |

총 **175문제**(분야: 웹 35 · 암호 35 · 시스템 35 · 포렌식 35 · 클라우드/AI 35). 각 문제는 [Vibe Hacking 본 레포](../README.md)의 75개 섹션 주제와 연결됩니다.

Total **175 challenges** (web 35 · crypto 35 · system 35 · forensics 35 · cloud/AI 35); each maps to a topic from the [main repo](../README.md)'s 75 sections.

---

## 🔒 보안 설계 / Security design

- 정답 플래그는 파일에 **SHA-256 해시로만** 저장됩니다(평문 없음). 입력값을 브라우저에서 해시해 비교합니다.
- "페이지에 숨긴" 유형(소스 주석·쿠키·전역변수·숨겨진 DOM)은 의도적으로 발견 가능하게 심어져 있습니다 — 그게 학습 포인트입니다.
- 보안 컨텍스트(HTTPS/localhost)에서는 Web Crypto `crypto.subtle`을, 그 외(`file://`)에서는 내장 순수 JS SHA-256 폴백을 사용합니다.
- ⚠️ **교육용입니다.** 모든 도전은 브라우저 안에서 끝납니다. 실제 외부 시스템을 공격하지 마세요.

---

## 🚀 로컬 실행 / Run locally

```bash
cd wargame
python3 -m http.server 8000
# 브라우저에서 http://localhost:8000 접속
```

`file://`로 직접 열어도 동작하지만(순수 JS 해시 폴백), 로컬 서버 사용을 권장합니다.

---

## ⚙️ GitHub Pages 배포 / Deployment

`.github/workflows/deploy-wargame.yml` 가 `wargame/` 변경 시 자동으로 Pages에 배포합니다. 배포 전 `validate` 잡이 네 가지 검사를 돌리고, 하나라도 실패하면 배포가 차단됩니다.

| 스크립트 | 검사 내용 |
|---|---|
| `verify.js` | 구조 — id 중복, 해시 형식, 존재하지 않는 tier/track, 자기 프롬프트에 정답 노출, index.html HUD·README 문제 수 불일치 |
| `leakscan.js` | 한 문제의 정답이 **다른 문제**의 프롬프트·힌트에 평문으로 들어있는지 (n-gram 해시 대조) |
| `audit.js --strict` | `fmt`가 약속한 형식(길이·`$` 같은 마커)을 채점기가 실제로 받아주는지 `[G]`, 아래 계층표의 주제 열이 어느 문제의 정답을 그대로 적어 스포일하는지 `[F]` |
| `solve-derivable.js` | 암호문·심어둔 플래그가 있는 문제를 **프롬프트만 보고 실제로 풀어** 앱 채점 규칙에 제출 |

앞의 셋은 정적 검사이고, `solve-derivable.js`는 실제로 게임을 플레이합니다. 안내대로 따라 풀었는데 오답 처리되는 문제(정답 형식 모순, 깨진 암호문, 사라진 아티팩트)는 이 검사만 잡을 수 있습니다. 네 스크립트 모두 평문 정답을 저장하지 않고 출력하지도 않아 공개 CI에서도 안전합니다.

`.github/workflows/deploy-wargame.yml` auto-deploys to Pages on `wargame/` changes. Before deploying, a `validate` job runs four checks and blocks the deployment if any of them fails.

| Script | What it checks |
|---|---|
| `verify.js` | Structure — duplicate ids, malformed hashes, dangling tier/track refs, an answer leaked into its own prompt, HUD/README counts drifting apart |
| `leakscan.js` | One challenge's answer sitting in plain text in **another** challenge's prompt or hints (n-gram hash lookup) |
| `audit.js --strict` | Whether the grader really accepts the format `fmt` promises — declared length, markers like `$` `[G]` — and whether the tier table above hands a player an answer as a topic `[F]` |
| `solve-derivable.js` | Actually solves every challenge that ships a ciphertext or a planted flag **from its own prompt** and submits it to the app's grading rule |

The first three are static; the last one plays the game. A challenge where following the stated instructions gets you marked wrong — a format contradiction, a corrupted ciphertext, a plant that went missing — is only catchable that way. None of the four stores or prints a plaintext answer, so all are safe in public CI.

**최초 1회 설정** (저장소 소유자):
1. 저장소 **Settings → Pages → Build and deployment → Source** 를 **"GitHub Actions"** 로 설정.
2. (워크플로의 `configure-pages` 가 자동 활성화를 시도하므로 보통 위 단계도 자동 처리됩니다.)
3. `Actions` 탭에서 **Deploy Wargame** 워크플로가 성공하면 `https://lsszz2100.github.io/VibeHacking/` 에서 플레이 가능.

---

## 🛠️ 문제 추가 / Adding challenges

문제 데이터는 `assets/challenges.js`(자동 생성, 해시만 포함)에 있습니다. 평문 정답이 노출되지 않도록 생성기로 만드는 것을 권장합니다. 새 문제는 `id`, `tier`, `cat`, `points`, `hash`(정답 SHA-256), `title/prompt/hints`(ko·en) 필드를 가집니다.
