# ⚔️ Vibe Hacking Wargame — Infiltration Terminal

브라우저 안의 **가짜 셸로 표적 네트워크에 침투하는** 단계별 사이버보안 워게임입니다. 백엔드 없이 100% 클라이언트 측에서 동작하며, `vibe.corp`의 보안 계층 5개(외곽→웹서버→내부망→금고→코어)를 한 계층씩 뚫어 코어에 도달합니다.

A browser-based, **terminal-style infiltration wargame**. You drive a fake shell to breach 5 security layers of `vibe.corp` — perimeter → web server → internal → vault → core. 100% client-side, no backend.

🔗 **플레이 / Play:** `https://lsszz2100.github.io/VibeHacking/`
*(GitHub Pages 활성화 후 접속 가능 / available once GitHub Pages is enabled — see below)*

---

## 🎮 어떻게 플레이하나요 / How to play

사이트를 열면 부팅 시퀀스 후 **침투 콘솔**이 뜹니다. 마우스가 아니라 **명령**으로 플레이합니다 — `help` 를 입력해 시작하세요.

| 명령 / command | 설명 |
|----------------|------|
| `help` | 명령 목록 / list commands |
| `ls` | 현재 위치 목록 (계층 또는 잠금장치) |
| `map` | 침투 경로 지도 — 어떤 계층이 뚫렸는지 |
| `connect <노드>` | 계층에 접속 (예: `connect perimeter`) |
| `cat <번호>` | 잠금장치(문제)를 열어 표적으로 설정 (예: `cat 1`) |
| `hint` | 현재 표적 힌트 공개 — 1개당 점수 20% 차감 |
| `submit <flag>` | 플래그 제출 (또는 표적이 열린 상태에서 그냥 입력) |
| `status` | 점수·등급·계층별 진행도 |
| `lang` / `sound` | 한·영 전환 / 사운드 토글 |
| `clear` / `reset` | 화면 지우기 / 진행도 초기화 |

1. **`connect perimeter`** 로 첫 계층에 침투 → **`cat 1`** 로 첫 잠금장치(문제)를 엽니다.
2. 정답(플래그 `FLAG{...}` 또는 단답)을 입력하면 **`ACCESS GRANTED`**, 틀리면 **`ACCESS DENIED`**.
3. 한 계층에서 요구 개수(아래 표)를 풀면 **`LAYER BREACHED`** — 다음 계층이 열립니다.
4. 진행도·점수·언어·사운드는 브라우저 `localStorage`에 자동 저장됩니다.
5. 상단 상태바에 점수·등급(🥚→👑)·침투 진행률이 실시간 표시됩니다.

> 💡 첫 플래그는 **이 페이지의 소스**에 숨어 있습니다. `Ctrl+U` 를 눌러 보세요. 콘솔(F12)·쿠키·숨겨진 DOM에도 심어진 플래그가 있습니다.

### 보안 계층(티어) — 한 계층씩 침투

| 계층 / node | 티어 | 주제 | 문제 수 | 통과(breach) |
|------|:---:|------|:------:|:--------:|
| `perimeter` 외곽 | **0** | 소스 보기, 개발자도구, Base64, 바이너리 | 6 | 4 |
| `webserver` 웹서버 | **1** | 고전 암호(ROT13/Hex/Caesar/Morse), 쿠키, HTTP, nmap | 10 | 6 |
| `internal` 내부망 | **2** | SQLi·XSS·JWT·해시·Base32·LFI·리버싱·S3·K8s | 15 | 9 |
| `vault` 금고 | **3** | XOR/ROT47, 포맷스트링, SSTI, YARA, AD, NOP, IMDS | 12 | 7 |
| `core` 코어 | **4** | 체인/이중 디코딩, 컨테이너 탈출, AES-GCM, JWT, AI 보안 | 7 | 5 |

총 **50문제**(분야: 웹 14 · 암호 15 · 시스템 8 · 포렌식 7 · 클라우드/AI 6). 각 문제는 [Vibe Hacking 본 레포](../README.md)의 75개 섹션 주제와 연결됩니다.

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

`.github/workflows/deploy-wargame.yml` 가 `wargame/` 변경 시 자동으로 Pages에 배포합니다.

**최초 1회 설정** (저장소 소유자):
1. 저장소 **Settings → Pages → Build and deployment → Source** 를 **"GitHub Actions"** 로 설정.
2. (워크플로의 `configure-pages` 가 자동 활성화를 시도하므로 보통 위 단계도 자동 처리됩니다.)
3. `Actions` 탭에서 **Deploy Wargame** 워크플로가 성공하면 `https://lsszz2100.github.io/VibeHacking/` 에서 플레이 가능.

---

## 🛠️ 문제 추가 / Adding challenges

문제 데이터는 `assets/challenges.js`(자동 생성, 해시만 포함)에 있습니다. 평문 정답이 노출되지 않도록 생성기로 만드는 것을 권장합니다. 새 문제는 `id`, `tier`, `cat`, `points`, `hash`(정답 SHA-256), `title/prompt/hints`(ko·en) 필드를 가집니다.
