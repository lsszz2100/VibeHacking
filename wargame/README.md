# ⚔️ Vibe Hacking Wargame

브라우저에서 바로 플레이하는 **단계별 사이버보안 워게임**입니다. 백엔드 없이 100% 클라이언트 측에서 동작하며, 입문부터 전문가까지 5개 티어를 힌트와 함께 단계적으로 클리어합니다.

A browser-based, **staged cybersecurity wargame**. 100% client-side (no backend), with 5 tiers from novice to expert, hints, and exam-style progression.

🔗 **플레이 / Play:** `https://lsszz2100.github.io/VibeHacking/`
*(GitHub Pages 활성화 후 접속 가능 / available once GitHub Pages is enabled — see below)*

---

## 🎮 어떻게 플레이하나요 / How to play

1. 사이트를 열면 **TIER 0 (입문)** 만 열려 있습니다.
2. 각 문제의 설명을 읽고 정답(플래그 `FLAG{...}` 또는 단답)을 입력합니다.
3. 막히면 **힌트**를 단계별로 열 수 있습니다 — 단, 힌트 1개당 점수 20% 차감.
4. 한 티어에서 요구 개수(예: 4문제)를 풀면 **다음 티어가 잠금 해제**됩니다.
5. 진행도·점수는 브라우저 `localStorage`에 자동 저장됩니다. 우상단 🌐로 한/영 전환, **초기화** 버튼으로 리셋.

| 티어 | 주제 | 통과 조건 |
|------|------|-----------|
| **0 입문** | 소스 보기, 개발자도구, Base64 | 3 / 4 |
| **1 기초** | 고전 암호(ROT13/Hex), 쿠키, HTTP | 4 / 5 |
| **2 중급** | SQLi·XSS·JWT·해시·리버싱 | 4 / 6 |
| **3 고급** | XOR 암호, 포맷스트링, AD, 포렌식 | 3 / 5 |
| **4 전문가** | 체인 디코딩, 컨테이너 탈출, AI 보안 | 4 / 4 |

총 **24문제**. 각 문제는 [Vibe Hacking 본 레포](../README.md)의 75개 섹션 주제와 연결됩니다.

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
