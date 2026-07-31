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

### 등급 / Ranks

등급 기준은 **전체 문제 수에 대한 비율**입니다 — 문제가 늘어도 기준이 저절로 따라옵니다. 현재 필요한 정확한 문제 수는 `status` 명령으로 확인하세요.
Rank thresholds are **shares of the challenge pool**, so they scale with it as the pool grows. Run `status` for the exact counts you need right now.

| 등급 / rank | 🥚 알 / Egg | 🐣 뉴비 / Newbie | 🦊 수습 / Apprentice | 🐺 해커 / Hacker | 🦅 엘리트 / Elite | 👑 레전드 / Legend |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| 필요 / required | 0 | 첫 1문제 / first solve | 20% | 43% | 69% | 93% |

> 💡 첫 플래그는 **이 페이지의 소스**에 숨어 있습니다. `Ctrl+U` 를 눌러 보세요. 콘솔(F12)·쿠키·숨겨진 DOM에도 심어진 플래그가 있습니다.
> The first flag hides in **this page's source** — press `Ctrl+U`. More flags are planted in the console (F12), a cookie, and a hidden DOM node.

### 보안 계층(티어) — 한 계층씩 침투 / Security layers (tiers) — breach one at a time

| 계층 / node | 티어 / tier | 주제 / topics | 문제 / count | 통과 / breach |
|------|:---:|------|:------:|:--------:|
| `perimeter` 외곽 | **0** | 페이지 소스·개발자도구·기본 인코딩 디코딩·이진수·역순/URL/NATO·메타태그·해시 종류 식별·헥스 덤프·리눅스 기본 명령·스크립트 첫 줄 규약·클라우드 권한·네트워크·지리 단위 기초·계정 보호 통제·시그널·디스크 이미징·증거 무결성 보존 하드웨어·시스템 정보 조회 명령·AI 기본 어휘(근거 없는 생성·정책 검사 계층·학습 이후 실행 단계·학습 자료·텍스트 분할·재현용 난수 값·의도 정합)·네트워크 기본(에코 요청 도구·암호화 웹의 기본 포트·주소 자동 임대 프로토콜·기본 출구 인터페이스·프레임 최대 페이로드·자기 자신으로 되돌아오는 인터페이스·계층 참조 모델) / page source, devtools, basic decoding, binary, reverse/URL/NATO, meta tags, hash identification, hex dumps, core Linux commands, script header convention, cloud identity, networking and geography basics, account protection, signals, disk imaging, evidence-integrity preservation hardware, system-info command, AI vocabulary (ungrounded generation, the policy-checking layer, the post-training runtime stage, training material, text splitting, reproducibility values, intent tuning), networking basics (the echo probe, the default port of the encrypted web, automatic address leasing, the default exit interface, maximum frame payload, the interface that returns to itself, the layered reference model) | 46 | 4 |
| `webserver` 웹서버 | **1** | 고전 암호(ROT13/Hex/Caesar/Morse/Atbash/A1Z26), 쿠키, HTTP, Basic 인증, 포트 스캐닝, 클라우드 리소스 식별·시점 백업, 심볼릭 링크, 트래픽 분산, 패킷 캡처·수집 도구, 증거 관리 절차, 동적 링크 확인, 바이트 순서, 컨테이너 이미지 정의, PE 실행파일 매직, 안드로이드 바이트코드 포맷, ELF 헤더·심볼 조회·역어셈블 도구·검색 증강 구조·의미 벡터 표현·도구 연결 프로토콜·저계수 경량 조정·안전한 가중치 포맷·정규화 이전 원시 점수·비트 정밀도 축소·주소 해석 프로토콜·제어와 오류 메시지 프로토콜·메일 서버 지정 레코드·스위치 논리 분할·경로 추적 명령·사설과 공인 주소 변환·도메인 등록정보 조회 / classic ciphers, cookies, HTTP, Basic auth, port scanning, cloud resource naming & point-in-time backups, symlinks, traffic distribution, packet capture tooling, evidence handling, dynamic-link inspection, byte order, container image definition, PE executable magic, Android bytecode format, ELF header/symbol inspection & disassembly tooling, retrieval-augmented design, semantic vectors, the tool-connection protocol, low-rank light tuning, the safe weights format, pre-normalization raw scores, bit-precision reduction, address resolution on a segment, the control-and-error protocol, the mail-server record, switch-level logical segmentation, path tracing, private-to-public address translation, domain registration lookup | 49 | 6 |
| `internal` 내부망 | **2** | SQLi·XSS·JWT·해시·Base32/58·Unicode·Vigenère·LFI·접근제어 우회·리버싱·클라우드 객체 스토리지·K8s 기초·프로세스/파일 모니터링 도구·디버거 사용법·파일 카빙·NTFS 은닉 스트림·K8s 권한 모델·보안그룹 CIDR·악성코드 패커 회피·섹션 무작위도 분석·시스템 콜 추적·모델이 나중에 읽는 자료에 심는 인젝션·자료와 지시의 구분 표시·입력 경계 표기·학습 포함 여부를 캐내는 공격·역할극 우회·렌더링을 통한 유출·과도한 도구 권한·TLS 평문 이름 확장·네트워크 계층 보안 프로토콜 모음·가짜 무선 AP·관리 프레임 위조로 끊기·깨진 초기 무선 암호·장비 관리 프로토콜의 기본 공유 문자열·무차별 수신 모드 | 50 | 9 |
| `vault` 금고 | **3** | XOR(단일/반복키)·ROT47·Base85·포맷스트링·SSTI·탐지 규칙 언어·AD·ELF매직·메시지 인증 코드·IMDS·STS 임시 자격증명·클라우드 오설정 감시·동적 링크 테이블 덮어쓰기·도커 소켓 마운트·IMDSv2 토큰·프로세스 이미지 치환 인젝션·위치 독립 실행파일·단일 스텝/반복형 적대적 예제 생성·섭동 예산·출력에서 학습 데이터 복원·대리 모델 학습·최적화된 덧붙임 문구·모델 간 전이 성질·응답 주소를 바꿔 같은 출처를 유지하는 공격·질의 대비 응답 증폭 DDoS·저대역 연결 고갈·장악한 장비를 경유한 내부 확산·닫힌 포트 순서로 여는 은닉·TLS 핸드셰이크 지문·경로 광고 프로토콜과 하이재킹 | 50 | 7 |
| `core` 코어 | **4** | 체인/이중·3중 디코딩, Vigenère, 컨테이너 탈출, K8s 시크릿 저장 방식, AES-GCM, JWT, AI 보안, 윈도우 실행 흔적, 메모리 포렌식, 메모리 보호기법, 코드 재사용·해제 후 사용 익스플로잇, 서버리스 초기화 지연, USB 장치 흔적, NTFS 메타데이터, 타임스탬프 조작, 글리브 힙 캐시 poisoning·무작위 잡음 기반 인증 방어·교사→학생 지식 이전·역직렬화 공급망 위험·기울기 기반 자동 우회 탐색·다중 턴 점증 유도·대리 권한 혼동 문제·특정 데이터 영향 제거·UDP 위 다중화 전송·HTTPS로 감싼 이름 해석·경로 광고 서명 검증 체계·인증서 폐기 실시간 조회·키 재설치 무선 공격·대화 단위 흐름 레코드·커널 내 경량 VPN / chained decoding, Vigenère, container escape, how K8s stores secrets, AES-GCM, JWT, AI security, Windows execution artifacts, memory forensics, memory protections, code-reuse & use-after-free exploitation, serverless init latency, USB device artifacts, NTFS metadata, timestamp tampering, glibc heap-cache poisoning, certified defense via random noise, teacher-to-student knowledge transfer, deserialization supply-chain risk, gradient-driven automated bypass search, multi-turn escalation, the confused-authority problem, removing one record's influence, multiplexed transport over UDP, name resolution wrapped in HTTPS, signed route-origin validation, real-time certificate revocation lookup, the key-reinstallation wireless attack, per-conversation flow records, the in-kernel lightweight VPN | 50 | 5 |

총 **245문제**(분야: 웹 35 · 암호 35 · 시스템 35 · 포렌식 35 · 클라우드/컨테이너 35 · AI/LLM 35 · 네트워크 35). 각 문제는 [Vibe Hacking 본 레포](../README.md)의 75개 섹션 주제와 연결됩니다.

Total **245 challenges** (web 35 · crypto 35 · system 35 · forensics 35 · cloud/container 35 · AI/LLM 35 · network 35); each maps to a topic from the [main repo](../README.md)'s 75 sections.

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
| `audit.js --strict` | `fmt`가 약속한 형식(길이·`$` 같은 마커)을 채점기가 실제로 받아주는지 `[G]`, 위 계층표의 주제 열이 어느 문제의 정답을 그대로 적어 스포일하는지 `[F]`, `fmt`가 표기 규약을 지키고 표기가 갈리는 정답의 길이를 공개하는지 `[H]`, 교재 492개 장이 그 정답을 다른 표기로 더 자주 쓰는데 `fmt`가 침묵하는지 `[I]` |
| `solve-derivable.js` | 암호문·심어둔 플래그가 있는 문제를 **프롬프트만 보고 실제로 풀어** 앱 채점 규칙에 제출 |

앞의 셋은 정적 검사이고, `solve-derivable.js`는 실제로 게임을 플레이합니다. 안내대로 따라 풀었는데 오답 처리되는 문제(정답 형식 모순, 깨진 암호문, 사라진 아티팩트)는 이 검사만 잡을 수 있습니다. 네 스크립트 모두 평문 정답을 저장하지 않고 출력하지도 않아 공개 CI에서도 안전합니다.

`.github/workflows/deploy-wargame.yml` auto-deploys to Pages on `wargame/` changes. Before deploying, a `validate` job runs four checks and blocks the deployment if any of them fails.

| Script | What it checks |
|---|---|
| `verify.js` | Structure — duplicate ids, malformed hashes, dangling tier/track refs, an answer leaked into its own prompt, HUD/README counts drifting apart |
| `leakscan.js` | One challenge's answer sitting in plain text in **another** challenge's prompt or hints (n-gram hash lookup) |
| `audit.js --strict` | Whether the grader really accepts the format `fmt` promises — declared length, markers like `$` `[G]` — whether the tier table above hands a player an answer as a topic `[F]`, whether `fmt` follows the notation rules and discloses a length wherever the answer's spelling is ambiguous `[H]`, and whether the repo's own 492 chapters spell that answer another way at least as often while `fmt` stays silent `[I]` |
| `solve-derivable.js` | Actually solves every challenge that ships a ciphertext or a planted flag **from its own prompt** and submits it to the app's grading rule |

The first three are static; the last one plays the game. A challenge where following the stated instructions gets you marked wrong — a format contradiction, a corrupted ciphertext, a plant that went missing — is only catchable that way. None of the four stores or prints a plaintext answer, so all are safe in public CI.

**최초 1회 설정** (저장소 소유자):
1. 저장소 **Settings → Pages → Build and deployment → Source** 를 **"GitHub Actions"** 로 설정.
2. (워크플로의 `configure-pages` 가 자동 활성화를 시도하므로 보통 위 단계도 자동 처리됩니다.)
3. `Actions` 탭에서 **Deploy Wargame** 워크플로가 성공하면 `https://lsszz2100.github.io/VibeHacking/` 에서 플레이 가능.

---

## 🛠️ 문제 추가 / Adding challenges

문제 데이터는 `assets/challenges.js`(자동 생성, 해시만 포함)에 있습니다. 평문 정답이 노출되지 않도록 생성기로 만드는 것을 권장합니다. 새 문제는 `id`, `tier`, `cat`, `points`, `hash`(정답 SHA-256), `title/prompt/hints`(ko·en) 필드를 가집니다.

### `fmt` 표기 규약 / Answer-format notation

`fmt`는 문제 카드에 그대로 표시되어 **"무엇을 답하는가"가 아니라 "어떻게 입력하는가"**를 알려줍니다. 정답을 알아도 표기가 어긋나 오답 처리되는 일을 막는 것이 목적이므로, 아래 규약을 따르고 `audit.js --strict`의 `[H]`가 이를 강제합니다.

`fmt` is shown verbatim on the challenge card. It tells the player **how to type the answer, never what it is** — its whole job is to stop someone who knows the answer from being marked wrong over spelling. `audit.js --strict` enforces the rules below in `[H]`.

1. **기본형은 승인된 어휘만 / Use an approved base.** `한 단어 / one word`, `약어 / acronym`, `명령어 / command`, `도구 이름 / tool name` 등 35종. 같은 뜻을 약자·약어·약칭처럼 제각기 쓰지 않습니다. The lexicon lives in `audit.js`; a new category must be added there deliberately, not invented inline.
2. **수식어는 괄호 하나에, 항상 이중언어 / Qualifiers go in one parenthesis, always bilingual.** `(3글자 / 3 chars)`, `(하이픈 없이 / no hyphen)`, `($ 제외 / no $)`, `(예: AB.CD / e.g. AB.CD)`. 둘 이상은 쉼표로 구분합니다. 한국어와 영어가 서로 다른 말을 하면(`(3글자 / 4 chars)`) 실패합니다.
3. **표기가 갈릴 수 있으면 길이를 선언 / Declare the length when the spelling is ambiguous.** 정답이 구분자(`-` `.` `_` `/` `:` 공백)를 품고 있거나 문자 뒤에 숫자가 바로 붙는 형태(`SHA1` 부류)라면, 플레이어가 하이픈이나 공백을 끼워 넣을 수 있습니다. 구분자를 넣으면 길이가 반드시 달라지므로 **길이 선언 하나로 잘못된 표기가 배제되며, 정답 자체는 조금도 누설되지 않습니다.** `[H]`는 열거로 복원되는 정답을 모두 훑어 이 선언이 빠진 문제를 찾아냅니다.
4. **선언한 길이는 사실이어야 함 / A declared length must be true.** `[G]`가 저장된 해시로부터 정답의 형태를 복원해 대조합니다.
5. **`fmt`가 정답을 적지 말 것 / Never spell the answer in `fmt`.** `leakscan.js`는 `title`·`prompt`·`hints`만 보므로 `[H]`가 `fmt`를 따로 검사합니다.
6. **교재가 다르게 적는 표기라면 밝힐 것 / Disclose it when the chapters spell it another way.** 정답이 교재 492개 장에 나오는 여러 어절짜리 용어라면, 교재가 그 용어를 붙여서·하이픈으로·띄어서 쓰는 빈도를 `[I]`가 세어 **채점 표기만큼 자주 다르게 적는지** 확인합니다. 그렇다면 `한 단어 / one word`, `두 단어 / two words`, `(하이픈 없이 / no hyphen)`, `(- 포함 / include -)` 가운데 그 둘을 갈라 주는 표기를 달아야 합니다. 여기서 배운 대로 입력한 사람이 오답이 되어서는 안 되기 때문입니다. **길이는 붙여쓰기와 분리 표기를 갈라 주지만 하이픈과 공백은 길이가 같으므로, 그 둘 사이에서는 길이 선언이 소용없습니다.** `[I]` counts how this repo's own chapters render the term; if they write it the other way at least as often, `fmt` must say which rendering the grader takes.

> 이 규약은 실제 사고에서 나왔습니다. `t4_mft`는 `$`를 붙이라고 안내하면서 채점은 `$` 없는 형태만 받았고, `t2_sha1`은 힌트가 `SHA-256`이라 적어 놓고 하이픈 있는 답을 거부했습니다. 앱은 문제당 정답 해시를 하나만 갖기 때문에 변형을 함께 수용할 수 없고, 따라서 **표기는 `fmt`가 책임져야 합니다.**
> Both rules 3 and 4 exist because of real bugs: `t4_mft` told players to type a `$` its grader rejected, and `t2_sha1` printed `SHA-256` in its own hints while refusing a hyphen. One challenge stores exactly one answer hash, so variants cannot be accepted — the notation has to carry that weight.
>
> 6번은 3번의 사각지대를 메웁니다. `fine-tuning`을 붙여 쓴 정답은 구분자도 없고 문자+숫자 복합도 아니라 3번이 길이를 요구하지 않지만, 통용 표기는 하이픈이라 그대로 입력한 사람이 틀립니다. 그런 정답은 열거로 복원하기엔 너무 길어 `[H]`가 형태조차 알 수 없으므로, 후보를 교재에서 가져옵니다.
> Rule 6 covers rule 3's blind spot: an answer like `finetuning` carries no separator and is not letters-run-into-digits, so nothing asks it to declare a length — yet the usual rendering is hyphenated. Answers that long are past what enumeration can reach, so the candidates come from the chapters instead.
