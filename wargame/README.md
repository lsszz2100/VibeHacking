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
| 필요 / required | 0 | 첫 1문제 / first solve | 12% | 43% | 69% | 85% |

> 💡 첫 플래그는 **이 페이지의 소스**에 숨어 있습니다. `Ctrl+U` 를 눌러 보세요. 콘솔(F12)·쿠키·숨겨진 DOM에도 심어진 플래그가 있습니다.
> The first flag hides in **this page's source** — press `Ctrl+U`. More flags are planted in the console (F12), a cookie, and a hidden DOM node.

### 보안 계층(티어) — 한 계층씩 침투 / Security layers (tiers) — breach one at a time

통과 기준도 **그 계층 문제 수에 대한 비율**입니다 — 계층이 커져도 기준이 저절로 따라옵니다. 다만 입구인 `perimeter`(티어 0)는 예외입니다. 트랙이 늘 때마다 워밍업 문제가 같이 붙는 자리라 비율로 두면 입문에서만 수십 문제를 요구하게 되어, 같은 기준점(6문제 중 4문제)에서 출발하되 풀보다 **완만하게 자라는 곡선**을 씁니다. 지금 필요한 정확한 개수는 `nodes`·`status` 에 표시됩니다.
A layer's breach quota is likewise a **share of that layer's own pool**, so it scales as the layer grows. The entrance is the exception: `perimeter` (tier 0) collects a few warm-ups every time a new track arrives, so a flat share would turn the tutorial into dozens of solves. It starts from the same anchor (4 of 6) but grows **sub-linearly** with the pool instead. `nodes` and `status` show the exact count you need right now.

| 계층 / node | 티어 / tier | 문제 / count | 통과 / breach |
|------|:---:|:------:|:--------:|
| `perimeter` 외곽 | **0** | 61 | 48% |
| `webserver` 웹서버 | **1** | 80 | 60% |
| `internal` 내부망 | **2** | 89 | 60% |
| `vault` 금고 | **3** | 93 | 58% |
| `core` 코어 | **4** | 97 | 71% |

<details>
<summary><b>계층별 주제 펼쳐 보기 / topics by layer</b></summary>

#### `perimeter` 외곽 — 티어 0 / tier 0

| 트랙 / track | 주제 / topics |
|------|------|
| `web` 🌐 웹 해킹 (5) | 페이지 소스·개발자도구·문서 제목·주소 인코딩·메타태그 / page source, devtools, the document title, URL encoding, meta tags |
| `crypto` 🔐 암호·인코딩 (6) | 기본 인코딩 디코딩·이진수·역순 뒤집기·십진 표기·8진 표기·음성 문자 알파벳 / basic decoding, binary, reversing a string, base-ten notation, octal notation, the phonetic alphabet |
| `system` 💻 시스템·리버싱·Pwn (7) | 리눅스 기본 명령·현재 사용자·현재 경로·스크립트 첫 줄 규약·시그널·시스템 정보 조회·프로세스 목록 / core Linux commands, the current user, the current path, the script header convention, signals, system-info lookup, listing processes |
| `forensics` 🔍 포렌식·멀웨어·네트워크 (7) | 해시 종류 식별·헥스 덤프·디스크 이미징·증거 무결성 보존 하드웨어·침해 흔적 지표·휘발성 메모리 / hash identification, hex dumps, disk imaging, evidence-integrity preservation hardware, indicators left by a breach, volatile memory |
| `cloud` ☁️ 클라우드·AI (7) | 클라우드 권한·가상 사설 네트워크 경계·지리적 배치 단위·콘텐츠 전송망·계정 보호 통제·서비스형 소프트웨어·책임 공유 모델 / cloud identity, the virtual private network boundary, the geographic placement unit, the content delivery layer, account protection, software as a service, the shared responsibility model |
| `ai` 🤖 AI·LLM 보안 (7) | 근거 없는 생성·정책 검사 계층·학습 이후 실행 단계·학습 자료·텍스트 분할·재현용 난수 값·의도 정합 / ungrounded generation, the policy-checking layer, the post-training runtime stage, training material, text splitting, reproducibility values, intent tuning |
| `network` 🛰️ 네트워크·프로토콜 (7) | 에코 요청 도구·암호화 웹의 기본 포트·주소 자동 임대 프로토콜·기본 출구 인터페이스·프레임 최대 페이로드·자기 자신으로 되돌아오는 인터페이스·계층 참조 모델 / the echo probe, the default port of the encrypted web, automatic address leasing, the default exit interface, maximum frame payload, the interface that returns to itself, the layered reference model |
| `mobile` 📱 모바일 보안 (7) | 단말과 PC를 잇는 디버그 다리·기기가 남기는 로그 열람·애플 쪽 앱 배포 꾸러미·애플 설정 파일 형식·단말에 새겨진 고유 번호·앱이 쓰는 내장 데이터베이스·문자로 오는 미끼 / the debug bridge between handset and PC, reading what the device logs, Apple's app bundle, Apple's settings file format, the number burned into the handset, the embedded database apps keep everything in, bait that arrives by text |
| `hardware` 🔌 하드웨어·IoT (2) | 열린 기기를 미리 색인해 둔 검색 서비스·라벨 없는 네 개의 패드로 나오는 직렬 단자 / the search service that already indexed exposed devices, the serial header hiding behind four unlabelled pads |
| `blueteam` 🛡️ 블루팀 탐지·대응 (2) | 장비마다 흩어진 기록을 한곳에 모아 규칙으로 엮는 관제 중심 시스템·경보를 24시간 지켜보는 조직이자 그 관제실 / the system that pulls scattered records into one place and ties them together with rules, the round-the-clock watch team and the room it sits in |
| `physical` 🚪 물리 보안 침투 (2) | 자격 증명 없이 인가자를 바로 뒤따라 통제 구역에 들어가기·몰래 리더를 대어 지갑 속 출입 카드를 본인 모르게 읽어 복제를 준비하기 / stepping into a controlled area right behind an authorised person with nothing of your own, covertly holding a reader to a card in someone's pocket to read it and prepare a copy |
| `automotive` 🚗 자동차 해킹 (2) | 1986년 그 차량 버스를 발표한 부품 회사·인터페이스의 모든 프레임을 터미널에 찍어 주는 can-utils 명령 / the parts company that published that vehicle bus in 1986, the can-utils command that prints every frame on an interface to the terminal |

#### `webserver` 웹서버 — 티어 1 / tier 1

| 트랙 / track | 주제 / topics |
|------|------|
| `web` 🌐 웹 해킹 (7) | 쿠키·농담으로 들어간 상태 코드·요소를 숨기는 스타일·크롤러 안내 파일·Basic 인증·주소 넘김·기본 자격증명 / cookies, the joke status code, styling that hides an element, the crawler guidance file, Basic auth, redirects, the login every fresh install ships with |
| `crypto` 🔐 암호·인코딩 (7) | 고전 암호 — 자리 이동·16진 표기·울타리 전치·시저·모스 부호·역순 치환·글자에 번호 매기기 / classic ciphers — letter rotation, hex notation, the rail-fence transposition, Caesar, Morse, the reversing substitution, letters given numbers |
| `system` 💻 시스템·리버싱·Pwn (7) | 권한 비트 변경·동적 링크 확인·바이트 순서·심볼릭 링크·ELF 헤더 조회·역어셈블 도구·소유자 변경 / changing permission bits, dynamic-link inspection, byte order, symlinks, ELF header inspection, disassembly tooling, changing the owner |
| `forensics` 🔍 포렌식·멀웨어·네트워크 (7) | 포트 스캐닝·패킷 캡처 파일·증거 관리 절차·터미널에서 뜨는 캡처 도구·PE 실행파일 매직·안드로이드 바이트코드 포맷·소켓 상태 조회 / port scanning, the packet capture file, evidence handling, the capture tool you run in a terminal, PE executable magic, the Android bytecode format, socket state lookup |
| `cloud` ☁️ 클라우드·AI (7) | 클라우드 리소스 식별자·시점 백업·트래픽 분산·컨테이너 이미지 정의·코드로 세우는 인프라·선언형 프로비저닝 도구·쿠버네티스 패키지 관리자 / the cloud resource identifier, point-in-time backups, traffic distribution, container image definition, infrastructure as code, the declarative provisioning tool, the Kubernetes package manager |
| `ai` 🤖 AI·LLM 보안 (7) | 검색 증강 구조·의미 벡터 표현·도구 연결 프로토콜·저계수 경량 조정·안전한 가중치 포맷·정규화 이전 원시 점수·비트 정밀도 축소 / retrieval-augmented design, semantic vectors, the tool-connection protocol, low-rank light tuning, the safe weights format, pre-normalization raw scores, bit-precision reduction |
| `network` 🛰️ 네트워크·프로토콜 (7) | 주소 해석 프로토콜·제어와 오류 메시지 프로토콜·메일 서버 지정 레코드·스위치 논리 분할·경로 추적 명령·사설과 공인 주소 변환·도메인 등록정보 조회 / address resolution on a segment, the control-and-error protocol, the mail-server record, switch-level logical segmentation, path tracing, private-to-public address translation, domain registration lookup |
| `mobile` 📱 모바일 보안 (7) | 실행 중인 앱에 손을 넣는 계측 도구·안드로이드 바이트코드의 사람이 읽는 표기·시스템을 건드리지 않는 루팅·올리면 알아서 훑는 자동 정적분석 프레임워크·파이썬으로 패키지를 뜯는 라이브러리·재빌드 없이 앱을 바꾸는 후킹 프레임워크·검토자가 제일 먼저 여는 앱 선언 파일 / reaching into a running app, the readable form of Android bytecode, rooting without touching the system, the upload-and-it-reads-everything static framework, taking a package apart in Python, changing an app without rebuilding it, the first file a reviewer opens |
| `hardware` 🔌 하드웨어·IoT (6) | 펌웨어 이미지를 훑어 뜯어내는 도구·1883번 포트의 게시·구독 프로토콜·클럭을 함께 쓰는 네 가닥 버스·두 가닥이면 되는 버스·용도가 정해지지 않은 핀·한 파일에 담긴 임베디드 도구 상자 / walking a firmware image and pulling its parts out, the publish-subscribe protocol behind port 1883, the four-wire bus with a shared clock, the bus that needs only two wires, pins with no fixed job, the toolbox packed into a single binary |
| `blueteam` 🛡️ 블루팀 탐지·대응 (6) | 단말에서 벌어진 일을 남기고 되돌려 보는 대응 도구·유닉스가 오래 써 온 514번 포트의 기록 전송 규약·색인해 검색어로 파고드는 상용 로그 분석 제품·쏟아지는 경보를 급한 순서로 갈라내는 첫 판단·사고 때 따라갈 순서를 미리 적어 둔 대본·돼지를 마스코트로 삼은 원조 네트워크 침입 탐지기 / the tool that records and replays what happened on an endpoint, the record-shipping protocol Unix has used on port 514, the commercial log product you index and then search, the first pass that sorts a flood of alarms by urgency, the script written in advance for an incident, the original network intrusion detector whose mascot is a pig |
| `physical` 🚪 물리 보안 침투 (6) | 리더와 컨트롤러 사이에 암호 없이 배지 번호를 흘리는 고전 배선·저주파와 고주파 배지를 모두 읽고 흉내 내는 오픈소스 연구 장비·홈을 최대 깊이로 깎아 충격으로 여는 특수 날·스프링이 없어 플라스틱 카드로 못 미는 빗장·조직이 버린 것에서 정보를 줍는 정찰·복제한 저주파 배지를 써 넣는 재기록 칩 / the classic wiring that leaks the badge number between reader and controller with no cipher, the open-source research device that reads and mimics both low- and high-frequency badges, the specially cut blade opened by a sharp impact, the spring-less bar a plastic card cannot push, the recon that harvests what an organisation discards, the rewritable chip a copied low-frequency badge is written to |
| `automotive` 🚗 자동차 해킹 (6) | CAN 을 네트워크 인터페이스로 노출하는 리눅스 서브시스템·가장 낮은 식별자가 손실 없이 버스를 차지하는 비트 경쟁·아무도 구동하지 않을 때의 기본 비트 상태·싸구려 진단 동글이 흉내 내는 인터프리터 IC·확장 프레임 식별자의 비트 수·트랜스폰더 키가 있어야 시동이 걸리게 하는 도난 방지 장치 / the Linux subsystem that exposes CAN as a network interface, the bit contest where the lowest identifier takes the bus with nothing lost, the default bit state when nothing is driving, the interpreter IC a cheap diagnostic dongle imitates, the bit width of an extended frame identifier, the anti-theft device that needs a transponder key before the engine will start |

#### `internal` 내부망 — 티어 2 / tier 2

| 트랙 / track | 주제 / topics |
|------|------|
| `web` 🌐 웹 해킹 (8) | 질의 결과를 이어 붙이는 인젝션·서명 토큰 다루기·주소 인코딩 우회·스크립트 삽입·지역 파일 포함·유니코드 정규화·SQL 주석 처리·직접 객체 참조 우회 / the injection that welds two result sets together, working with signed tokens, URL-encoded bypasses, script injection, local file inclusion, Unicode normalisation, SQL comment syntax, insecure direct object references |
| `crypto` 🔐 암호·인코딩 (7) | 해시 크래킹·Base32·다이제스트 길이 비교·공개키 암호·격자 좌표 치환·반복 키 다표식 암호·Base58 / hash cracking, Base32, comparing digest lengths, public-key cryptography, the grid-coordinate substitution, the repeating-key polyalphabetic cipher, Base58 |
| `system` 💻 시스템·리버싱·Pwn (7) | 리버싱·문자열 추출·디버거 사용법·프로세스와 파일 감시 도구·열린 파일 조회·시스템 콜 추적·심볼 목록 조회 / reversing, pulling printable text out of a binary, using a debugger, process and file monitoring tooling, listing open files, tracing system calls, listing symbols |
| `forensics` 🔍 포렌식·멀웨어·네트워크 (7) | 패킷 분석 GUI·사진에 남는 촬영 메타데이터·파일 카빙·NTFS 은닉 스트림·악성코드 패커 회피·섹션 무작위도 분석·그림 속에 감추기 / the packet analysis GUI, the capture metadata a photo carries, pulling deleted files out of raw disk space, NTFS hidden streams, malware packer evasion, section randomness analysis, hiding data inside a picture |
| `cloud` ☁️ 클라우드·AI (7) | 클라우드 객체 스토리지·관리형 쿠버네티스·최소 배포 단위·모델 제약 풀기·K8s 권한 모델·보안그룹 CIDR·외부 유입 라우팅 규칙 / cloud object storage, managed Kubernetes, the smallest deployable unit, breaking a model out of its constraints, the K8s authorization model, security-group CIDRs, the inbound routing rule |
| `ai` 🤖 AI·LLM 보안 (7) | 모델이 나중에 읽는 자료에 심는 인젝션·자료와 지시의 구분 표시·입력 경계 표기·학습 포함 여부를 캐내는 공격·역할극 우회·렌더링을 통한 유출·과도한 도구 권한 / the injection planted in material the model will read later, marking data so it can't pass as an instruction, input boundary notation, probing whether a record was in the training set, the role-play bypass, exfiltration through rendering, excessive tool authority |
| `network` 🛰️ 네트워크·프로토콜 (7) | TLS 평문 이름 확장·네트워크 계층 보안 프로토콜 모음·가짜 무선 AP·관리 프레임 위조로 끊기·깨진 초기 무선 암호·장비 관리 프로토콜의 기본 공유 문자열·무차별 수신 모드 / the cleartext name extension in TLS, the network-layer security protocol suite, the rogue wireless access point, knocking clients off with forged management frames, the broken first-generation wireless cipher, the default shared string of the device management protocol, the capture mode that keeps every frame on the wire |
| `mobile` 📱 모바일 보안 (7) | 바깥으로 열린 컴포넌트 속성·출시본에 남은 디버그 스위치·아이폰이 비밀을 넣어두는 저장소·키를 꺼내지 않고 쓰는 하드웨어 저장소·앱 속에 박힌 브라우저 컴포넌트·터미널에서 트래픽을 가로채는 프록시·스크립트 없이 바로 쓰는 계측 프런트엔드 / the component attribute that opens it to the outside, the debug switch left in a shipping build, where iPhones keep their secrets, the hardware store that uses a key without handing it over, the browser component embedded in an app, the terminal proxy that intercepts traffic, the instrumentation front-end you use without writing scripts |
| `hardware` 🔌 하드웨어·IoT (8) | 눌러 담은 읽기 전용 파일시스템·공장 초기화가 지우는 설정 저장 영역·자동 부팅을 멈추라고 재촉하는 부트로더·벌의 춤에서 이름을 딴 저전력 메시·광고 채널 37·38·39를 쓰는 저전력 무선·알아서 포트를 여는 홈네트워크 규약·전지 없이 대답하는 카드·1979년에 태어난 산업용 프로토콜 / the squeezed read-only filesystem, the settings area a factory reset wipes, the bootloader begging you to stop the autoboot, the low-power mesh named after a bee's dance, the low-energy radio that advertises on channels 37, 38 and 39, the home-network convention that opens ports by itself, the card that answers with no battery, the industrial protocol born in 1979 |
| `blueteam` 🛡️ 블루팀 탐지·대응 (8) | 제품에 묶이지 않게 YAML 로 적는 공개 탐지 규칙 형식·윈도우 기본 감사보다 촘촘히 남기는 무료 계측 도구·멀티스레드로 다시 쓴 후발 네트워크 탐지 엔진·패킷을 사건 기록으로 바꿔 주는 네트워크 분석 프레임워크·리눅스 커널 감사 규칙을 받아 적는 데몬·수집·색인·시각화 세 도구를 묶어 부르던 오픈소스 조합·감염 단말을 망에서 떼어 가두는 조치·누구나 합법적으로 볼 수 있는 자료만 엮어 만드는 정보 / the vendor-neutral detection rule format written in YAML, the free instrumentation that records far more than the built-in Windows auditing, the later multi-threaded network detection engine, the framework that turns packets into event records, the daemon that takes the Linux kernel's audit rules, the open-source trio of collect, index and visualise, cutting an infected endpoint off and penning it in, intelligence built only on what anyone may lawfully see |
| `physical` 🚪 물리 보안 침투 (8) | 잡아낸 26비트 배지 프레임에서 시설 코드 읽기·네 바이트 일련번호를 닫는 XOR 검사 바이트·고전 교통 카드가 인증에 쓰는 48비트 스트림 암호·복제용으로 UID 블록까지 다시 쓸 수 있게 만든 특수 카드·문틈 도구로 오작동하는 퇴실 감지기·문 잡아달라 부탁해 함께 들어가기·카드로 경사 걸쇠를 밀어 넘기기·바꾸지 않고 방치되는 공장 출하 인증값 / reading the site code out of a captured 26-bit badge frame, the XOR check byte that closes a four-byte serial number, the 48-bit stream cipher a classic transit card authenticates with, the special card built so even the UID block can be rewritten for cloning, the exit detector a tool under the door can fool, asking someone to hold the door and walking in with them, sliding a card past a bevelled catch, the factory authentication value left unchanged |
| `automotive` 🚗 자동차 해킹 (8) | 진단 식별자로 나간 프레임 페이로드를 ASCII 로 이어 붙여 감춰진 문자열 얻기·페이로드 바이트들의 XOR 검사 바이트 계산·회전수 응답 두 바이트 디코딩·첫 프레임이 알리는 다중 프레임 메시지 전체 길이·시간 트리거 이중 채널 X-by-wire 버스·미러와 창문용 단선 곁버스·오류 카운터가 넘쳐 노드가 회선에서 떨어져 나가는 상태·원시 바이트를 이름 붙은 신호로 푸는 Vector 데이터베이스 파일 / concatenate the ASCII payload of frames on the diagnostic identifier to recover a hidden string, work out the XOR check byte over a payload, decode the two-byte engine-speed reply, the whole length a multi-frame message announces in its first frame, the time-triggered dual-channel X-by-wire bus, the single-wire side bus for mirrors and windows, the condition where an overflowing error counter drops a node off the wire, the Vector database file that turns raw bytes into named signals |

#### `vault` 금고 — 티어 3 / tier 3

| 트랙 / track | 주제 / topics |
|------|------|
| `web` 🌐 웹 해킹 (8) | 서버측 템플릿 인젝션·토큰 페이로드 디코딩·프로토타입 오염·템플릿에서 전역 객체로 건너뛰기·서명 알고리즘 무력화·서버측 요청 위조·NoSQL 인젝션·교차 출처 정책 오설정 / server-side template injection, decoding a token payload, prototype pollution, climbing out of a template into global objects, defeating the algorithm that signs the token, server-side request forgery, NoSQL injection, a misconfigured cross-origin policy |
| `crypto` 🔐 암호·인코딩 (7) | XOR(단일 키·반복 키)·ROT47·Base85·메시지 인증 코드·블록 연결 모드·해시에 섞는 무작위 값 / XOR with a single key and with a repeating key, ROT47, Base85, message authentication codes, the block chaining mode, the random value mixed into a hash |
| `system` 💻 시스템·리버싱·Pwn (7) | AD 인증 티켓·포맷스트링·권한 상승 비트·아무 일도 하지 않는 명령 슬라이드·동적 링크 테이블 덮어쓰기·위치 독립 실행파일·프로세스를 들여다보는 시스템 콜 / AD authentication tickets, the printf-style format bug, the privilege-raising bit, the slide of instructions that do nothing, overwriting the dynamic link table, position-independent executables, the system call that looks inside a process |
| `forensics` 🔍 포렌식·멀웨어·네트워크 (7) | 탐지 규칙 언어·파일 시그니처·반쯤 여는 스캔·다중 엔진 평판 조회·ELF 매직·프로세스 이미지 치환 인젝션·감염 단말이 지시를 받아 오는 채널 / the detection rule language, file signatures, the half-open scan, multi-engine reputation lookup, ELF magic, the injection that swaps a process image out, the channel that hands an infected endpoint its orders |
| `cloud` ☁️ 클라우드·AI (7) | IMDS·STS 임시 자격증명·클라우드 오설정 감시·남의 자원으로 채굴하기·도커 소켓 마운트·IMDSv2 토큰·클라우드 권한 상승 / IMDS, STS temporary access tokens, cloud misconfiguration monitoring, mining on somebody else's resources, mounting the Docker socket, IMDSv2 tokens, cloud privilege escalation |
| `ai` 🤖 AI·LLM 보안 (7) | 단일 스텝·반복형 적대적 예제 생성·섭동 예산·출력에서 학습 데이터 복원·대리 모델 학습·최적화된 덧붙임 문구·모델 간 전이 성질 / single-step and iterative adversarial example generation, the perturbation budget, pulling training data back out of outputs, training a stand-in model to approximate the target, the optimized appended phrase, how well an attack carries over between models |
| `network` 🛰️ 네트워크·프로토콜 (7) | 응답 주소를 바꿔 같은 출처를 유지하는 공격·질의 대비 응답 증폭 DDoS·저대역 연결 고갈·장악한 장비를 경유한 내부 확산·닫힌 포트 순서로 여는 은닉·TLS 핸드셰이크 지문·경로 광고 프로토콜과 하이재킹 / swapping the answer address while keeping the same origin, the flood that turns a small query into a huge reply, exhausting connections on a trickle of bandwidth, spreading inward through a machine you already hold, opening a door with a sequence of closed ports, the TLS handshake fingerprint, the route advertisement protocol and its hijacking |
| `mobile` 📱 모바일 보안 (7) | 파일을 가져가도 못 읽는 암호화 내장 임베디드 DB·플래시를 위해 새로 짠 애플 파일시스템·모든 앱이 갈라져 나오는 부모 프로세스·진짜 화면 위에 덧씌운 가짜 창·장애인을 돕던 권한의 악용·앱의 데이터를 내주는 창구 컴포넌트·아이폰 백업의 파일 색인 / the embedded database whose file is useless once stolen, the Apple filesystem rewritten for flash, the parent process every app forks out of, the fake window laid over the real screen, abusing the permission built to help disabled users, the component that hands an app's data out, the file index inside an iPhone backup |
| `hardware` 🔌 하드웨어·IoT (9) | 회로 대신 코드로 만든 무전기·공장 바닥의 제어 컨트롤러·관제실에서 내려다보는 감시 계층·공중으로 오는 펌웨어 갱신·48비트 독자 암호로 지킨 비접촉 카드·자외선 창이 달렸던 칩의 후예·900MHz 대역의 이웃 메시·차 한 대에 든 수십 개의 제어 유닛·덧붙여 쓰는 로그 구조 플래시 파일시스템 / the radio built in code instead of circuits, the controller on the factory floor, the supervisory layer that watches over the control room, the firmware update that arrives over the air, the contactless card guarded by a 48-bit in-house cipher, the descendant of the chip with a UV window, the neighbouring mesh in the 900MHz band, the dozens of control units inside one car, the append-only log-structured flash filesystem |
| `blueteam` 🛡️ 블루팀 탐지·대응 (9) | 위협 정보를 객체와 관계로 적는 표준 표현 형식·그것을 HTTPS 로 실어 나르는 전송 규약·여러 조직이 사건과 속성을 나눠 보는 오픈소스 공유 플랫폼·자료가 아니라 판단까지 담아야 하는 정보 분야·바꾸기 가장 힘든 공격자의 일하는 방식·eBPF 로 시스템 호출을 지켜보는 컨테이너 런타임 탐지 도구·윈도우가 스스로 흘려보내는 기본 계측 통로·스크립트를 실행 직전 평문으로 검사시키는 표준 창구·서명되어 기본 탑재된 실행 파일만으로 해내는 방식과 그 공개 목록 / the standard way of writing threat information as objects and relationships, the protocol that carries it over HTTPS, the open-source platform where organisations share events and attributes, the discipline that has to deliver judgement rather than data, the adversary habits that are hardest to change, the container runtime detector watching system calls with eBPF, the built-in Windows pipe that emits on its own, the standard doorway that inspects a script in cleartext just before it runs, working only with signed binaries that already ship, and the public catalogue of them |
| `physical` 🚪 물리 보안 침투 (9) | 같은 26비트 프레임에서 카드 번호 읽기·아무 실마리도 없을 때의 논스 통계 공격·주머니 속 카드 신호를 게이트까지 실어 나르기·고전 카드를 대체하는 AES-128 배지 제품군·마스터 인증값이 유출됐던 DES 기반 리더 제품군·평문 배선을 대체하는 암호화 양방향 리더 표준·꽂으면 키보드로 인식돼 입력을 쏟는 USB 장치·문 밑으로 밀어 넣어 안쪽 레버를 거는 도구·잠깐 자리를 비운 기기의 부팅 사슬 변조 / reading the card number out of the same 26-bit frame, the nonce-statistics attack for when nothing is known to begin with, carrying the pocketed card signal all the way to the gate, the AES-128 badge family that supersedes the classic one, the DES-based reader family whose master authentication value leaked, the encrypted two-way reader standard that supersedes the plaintext wiring, the USB stick seen as a keyboard that pours in keystrokes, the tool pushed under a door to catch the inside lever, tampering with an unattended device boot chain in a brief window |
| `automotive` 🚗 자동차 해킹 (9) | 펌웨어에서 밝혀낸 XOR 알고리즘으로 SecurityAccess 응답 키 계산·재생을 막으려 MAC 에 함께 넣는 단조 증가 값·주머니 속 키 신호를 증폭해 뚫는 무선 출입·롤링 코드를 방해·녹음했다 나중에 재사용·2015년 원격 Jeep 침투의 발판이 된 인포테인먼트 헤드유닛·스푸핑 대상이 되는 위성 항법 시스템 통칭·프레임이 64바이트로 늘어난 고전 버스 확장·ISO/SAE 21434 의 위협·위험 분석 활동·정비소 스캐너가 먼저 뽑는 저장된 고장 코드 / work out the SecurityAccess response key with an XOR algorithm lifted out of firmware, the monotonic value folded into the MAC to stop replay, the keyless entry broken by amplifying the key's pocket signal, jamming and recording a rolling code to reuse it later, the infotainment head unit that was the foothold in the 2015 remote Jeep break-in, the umbrella name for the satellite navigation systems a spoofer targets, the classic-bus extension whose frames grew to 64 bytes, the threat-and-risk analysis activity of ISO/SAE 21434, the stored fault codes a workshop scanner pulls first |

#### `core` 코어 — 티어 4 / tier 4

| 트랙 / track | 주제 / topics |
|------|------|
| `web` 🌐 웹 해킹 (7) | 토큰 서명 위조·템플릿에서 메서드 결정 순서 타고 오르기·GraphQL 질의 남용·여러 단계로 이어지는 웹 체인·요청 밀반입·인가 위임 흐름 악용·캐시 오염 / forging what signs the token, climbing the method resolution order out of a template, GraphQL query abuse, a web chain of several stages, request smuggling, abusing the delegated authorization flow, cache poisoning |
| `crypto` 🔐 암호·인코딩 (8) | 체인·이중·3중 디코딩·인증 태그가 붙는 블록 모드·여러 겹을 잇는 대형 체인·마무리 종합 문제·다표식 암호·반복 키 XOR 코어 / chained, doubled and tripled decoding, the block mode that carries an authentication tag, a long chain of many layers, the capstone exercise, polyalphabetic ciphers, the repeating-key XOR core |
| `system` 💻 시스템·리버싱·Pwn (7) | 주소 공간 무작위화·스택 보호 값·코드 재사용 공격·해제 후 사용·글리브 힙 캐시 poisoning·라이브러리 함수로 되돌리기·시스템 콜 필터 / address space randomization, the stack guard value, code-reuse attacks, use-after-free, glibc heap-cache poisoning, returning into a library function, the system call filter |
| `forensics` 🔍 포렌식·멀웨어·네트워크 (7) | 윈도우 실행 흔적·메모리 포렌식·USB 장치 흔적·NTFS 메타데이터·타임스탬프 조작·커널에 숨는 은닉 도구·호환성 캐시에 남는 실행 기록 / Windows execution artifacts, memory forensics, USB device artifacts, NTFS metadata, timestamp tampering, the toolkit that hides in the kernel, the execution record left in the compatibility cache |
| `cloud` ☁️ 클라우드·AI (7) | 컨테이너 탈출·강력한 커널 권한 부여·모델을 붙인 애플리케이션의 위험·K8s 시크릿 저장 방식·서버리스 초기화 지연·학습 자료 오염·사용자 공간 커널 샌드박스 / container escape, granting the sweeping kernel capability, the risk of an application with a model wired into it, how K8s stores secrets, serverless init latency, poisoning the training material, the user-space kernel sandbox |
| `ai` 🤖 AI·LLM 보안 (7) | 무작위 잡음 기반 인증 방어·교사에서 학생으로 지식 이전·역직렬화 공급망 위험·기울기 기반 자동 우회 탐색·다중 턴 점증 유도·대리 권한 혼동 문제·특정 데이터 영향 제거 / certified defense via random noise, teacher-to-student knowledge transfer, deserialization supply-chain risk, gradient-driven automated bypass search, multi-turn escalation, the confused-authority problem, removing one record's influence |
| `network` 🛰️ 네트워크·프로토콜 (7) | UDP 위 다중화 전송·HTTPS로 감싼 이름 해석·경로 광고 서명 검증 체계·인증서 폐기 실시간 조회·키 재설치 무선 공격·대화 단위 흐름 레코드·커널 내 경량 VPN / multiplexed transport over UDP, name resolution wrapped in HTTPS, signed route-origin validation, real-time certificate revocation lookup, the key-reinstallation wireless attack, per-conversation flow records, the in-kernel lightweight VPN |
| `mobile` 📱 모바일 보안 (7) | 기기가 진짜인지 서버가 묻는 원격 증명·파일마다 열쇠가 다른 암호화·법정으로 가는 상용 모바일 포렌식 장비·본체가 뚫려도 열리지 않는 격리 보안 영역·플래시를 물리적으로 떼어내는 마지막 수단·클릭 없이 들어오는 상용 스파이웨어·기판에 남겨진 시험용 포트 표준 / the server asking whether the device is real, a different key for every file, the commercial forensics box that goes to court, the subsystem sealed even when the main OS falls, physically lifting the flash off the board as a last resort, spyware that arrives without a click, the test port the board maker left behind |
| `hardware` 🔌 하드웨어·IoT (10) | 정비소가 쓰는 진단 통신 규약·쌓아 두었다 보고하는 원격 감시 프로토콜·저전력 무선의 서비스와 특성 계층·102번 포트 위의 산업 제어 대화·공정 기록을 보관하는 시계열 시스템·레벨 0에서 5까지의 참조 모델·원심분리기를 겨눈 코드·3333번과 4444번을 여는 디버그 서버·칩을 통째로 읽고 되쓰는 도구·퓨즈에 새긴 신뢰 사슬 / the diagnostic protocol a workshop speaks, the outstation that buffers events before reporting, the service-and-characteristic layer of low-energy radio, the industrial conversation over port 102, the time-series keeper of the plant record, the reference model spanning levels 0 through 5, the code that aimed at centrifuges, the debug server listening on 3333 and 4444, reading a chip whole and writing it back, the chain of trust burned into a fuse |
| `blueteam` 🛡️ 블루팀 탐지·대응 (10) | 사람과 개체의 평소 모습을 학습해 벗어남에 점수를 매기는 분석·여러 제품을 하나의 흐름으로 엮어 자동으로 대응하는 계층·침입부터 알아챌 때까지의 평균 시간·알아챈 뒤 정상으로 되돌리기까지의 평균 시간·기법 격자를 색칠해 못 보는 구멍을 찾는 공식 웹 도구·특정 공격 집단의 순서를 그대로 재현하는 훈련·공격과 방어를 한 방에 앉히는 방식과 두 색을 섞은 이름·사고 대응을 네 단계 바퀴로 정리한 미국 표준 기관·규칙적인 통신 박자를 지우려 잠드는 시간을 흩뜨리는 것·그래프 데이터베이스에 지식을 쌓는 프랑스발 오픈소스 위협 정보 플랫폼 / learning what each person and entity normally looks like and scoring the departures, the layer that stitches several products into one automated response flow, the average gap between an intrusion starting and someone noticing it, the average gap between noticing and being back to normal, the official web tool that colours the technique grid to find the holes, the exercise that reproduces one group's sequence step for step, seating attack and defence in one room and the name you get by mixing their two colours, the US standards institute that laid incident response out as a four-stage wheel, scattering the sleep interval to erase a regular callback rhythm, the French open-source intelligence platform that stacks knowledge in a graph database |
| `physical` 🚪 물리 보안 침투 (10) | 배지 프레임을 끝까지 읽어 시설 코드와 카드 번호를 밝히기·너무 멀어 걸어갈 수 없는 두 곳에서 쓰인 같은 배지·출입 로그에서 가장 바짝 붙은 무단 진입자 찾기·전원 인가 후 시간으로 값이 정해지는 약한 난수원·AES-128에 공개키 기반구조를 얹은 크리덴셜·앞문이 닫혀야 뒷문이 열리는 이중문·왕복 시간을 재 근접을 증명하는 프로토콜 계열·침투 절차 전반을 일곱 단계로 적은 실행 표준·저주파 태그 ID의 하위 32비트를 십진수 값으로·정전이면 풀리는 전자석 잠금 / reading a badge frame end to end to name its site code and card number, the same badge used at two points too far apart to walk between in the time elapsed, finding the closest unbadged follower in an access log, the weak randomness whose output is fixed by the time since power-on, the credential that layers a public-key infrastructure over AES-128, the interlocked pair of doors that admits one person at a time, the protocol family that proves closeness by timing the round trip, the execution standard that lays out the whole testing procedure in seven phases, the lower 32 bits of a low-frequency tag id as a base-ten number, the electromagnet lock that lets go on power loss |
| `automotive` 🚗 자동차 해킹 (10) | OBD 응답 프레임에서 차속과 회전수를 읽어 감춰진 문자열 조립·J1939 매개변수 그룹 번호를 10진수로·잘린 MAC 과 재생 방지 값을 프레임에 붙이는 자동차 보안 통신 계층·10Hz 로 위치를 방송하는 V2X 안전 메시지·단기 익명 인증서를 발급·폐기하는 V2X 공개키 체계·한 장치가 여러 차량 정체성을 지어내는 공격·인증된 관리체계를 형식 승인 조건으로 만든 UNECE 규정·서명 키를 담는 제어 유닛 안 변조 방지 하드웨어 블록·완성차·부품사가 함께 쓰는 표준 계층 소프트웨어 아키텍처·셀룰러와 CAN 을 잇는 텔레매틱스 상자 / assemble a hidden string out of the speed and revs in OBD reply frames, the J1939 parameter group number in base ten, the automotive secure-communication layer that adds a truncated MAC and an anti-replay value to a frame, the roughly 10 Hz V2X safety message that broadcasts position, the V2X public-key scheme that issues and revokes short-lived anonymous certificates, the attack where one device invents many vehicle identities, the UNECE regulation that made a certified management system a condition of type approval, the tamper-resistant hardware block inside a controller that holds signing keys, the standard layered software architecture carmakers and suppliers share, the telematics box that bridges cellular to CAN |

</details>

총 **420문제**(분야: 웹 35 · 암호 35 · 시스템 35 · 포렌식 35 · 클라우드/컨테이너 35 · AI/LLM 35 · 네트워크 35 · 모바일 35 · 하드웨어·IoT 35 · 블루팀 탐지·대응 35 · 물리 보안 침투 35 · 자동차 해킹 35). 각 문제는 [Vibe Hacking 본 레포](../README.md)의 75개 섹션 주제와 연결됩니다.

Total **420 challenges** (web 35 · crypto 35 · system 35 · forensics 35 · cloud/container 35 · AI/LLM 35 · network 35 · mobile 35 · hardware & IoT 35 · blue team & detection 35 · physical security 35 · automotive 35); each maps to a topic from the [main repo](../README.md)'s 75 sections.

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
| `audit.js --strict` | 페이지에서 읽어 답하는 문제(제목·`<meta>`·주석·숨긴 요소·쿠키·`window.__hint`)가 **빠짐없이 선언돼 있고 `solve-derivable.js`에 그 플랜트를 실제로 증명하는 솔버가 있는지** `[A]` — 새 문제가 페이지를 읽게 만들어졌는데 솔버가 없으면 지식 문제인 척 조용히 섞여 들어가므로, `fmt`가 약속한 형식(길이·`$` 같은 마커)을 채점기가 실제로 받아주는지 `[G]`, 위 계층표의 주제 열이 어느 문제의 정답을 그대로 적어 스포일하는지 `[F]`, `fmt`가 표기 규약을 지키고 표기가 갈리는 정답의 길이를 공개하는지 `[H]`, 교재 492개 장이 그 정답을 다른 표기로 더 자주 쓰는데 `fmt`가 침묵하는지 `[I]`, 교재나 문제 자신의 텍스트가 그 정답을 **같은 낱말의 다른 꼴**로 쓰는데 `fmt`가 갈라 주지 않는지 `[J]` |
| `solve-derivable.js` | 암호문·심어둔 플래그가 있는 문제를 **프롬프트만 보고 실제로 풀어** 앱 채점 규칙에 제출 |

앞의 셋은 정적 검사이고, `solve-derivable.js`는 실제로 게임을 플레이합니다. 안내대로 따라 풀었는데 오답 처리되는 문제(정답 형식 모순, 깨진 암호문, 사라진 아티팩트)는 이 검사만 잡을 수 있습니다. 네 스크립트 모두 평문 정답을 저장하지 않고 출력하지도 않아 공개 CI에서도 안전합니다.

`.github/workflows/deploy-wargame.yml` auto-deploys to Pages on `wargame/` changes. Before deploying, a `validate` job runs four checks and blocks the deployment if any of them fails.

| Script | What it checks |
|---|---|
| `verify.js` | Structure — duplicate ids, malformed hashes, dangling tier/track refs, an answer leaked into its own prompt, HUD/README counts drifting apart |
| `leakscan.js` | One challenge's answer sitting in plain text in **another** challenge's prompt or hints (n-gram hash lookup) |
| `audit.js --strict` | Whether every challenge answered by reading this page — the title, a `<meta>`, an HTML comment, a hidden element, a cookie, `window.__hint` — **is declared and carries a `solve-derivable.js` solver that proves the plant is still there** `[A]`, since a new page-reading challenge with no solver would otherwise pass as one more knowledge question, whether the grader really accepts the format `fmt` promises — declared length, markers like `$` `[G]` — whether the tier table above hands a player an answer as a topic `[F]`, whether `fmt` follows the notation rules and discloses a length wherever the answer's spelling is ambiguous `[H]`, whether the repo's own 492 chapters spell that answer another way at least as often while `fmt` stays silent `[I]`, and whether the chapters or the challenge's own text write it in **another form of the same word** that `fmt` never separates `[J]` |
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
7. **어형이 갈리면 그것도 밝힐 것 / Disclose the word-form too.** 같은 낱말의 다른 꼴 — 행위(`-ing`)와 장치(`-er`), 단수와 복수, 동사와 그 과거분사 — 은 **띄어쓰기도 단어 수도 같아서 `한 단어 / one word`가 조금도 갈라 주지 못합니다.** `[J]`는 교재 492개 장을 어간별로 묶어 채점 표기만큼 자주 쓰이는 다른 꼴이 있는지 보고, **문제 자신의 프롬프트·힌트가 다른 꼴을 쓰고 있는지**도 함께 봅니다. 걸리면 길이(`(9글자 / 9 chars)`)나 `(-ing으로 끝남 / ends in -ing)`으로 갈라 주어야 합니다 — 어형을 가르는 것은 이 둘뿐입니다. 문제 자신이 쓴 낱말이 정답과 길이까지 같다면 길이로는 못 가르므로 **그때는 `fmt`가 아니라 그 문장을 고칩니다.** 암호문이나 심어둔 플래그에서 답을 **도출**하는 문제(`solve-derivable.js`가 푸는 46개)는 애초에 낱말을 떠올릴 일이 없으므로 면제됩니다. `[J]` groups the chapters by stem and reads the challenge's own text as well; only a declared length or the `-ing` qualifier tells two forms of one word apart.

> 이 규약은 실제 사고에서 나왔습니다. `t4_mft`는 `$`를 붙이라고 안내하면서 채점은 `$` 없는 형태만 받았고, `t2_sha1`은 힌트가 `SHA-256`이라 적어 놓고 하이픈 있는 답을 거부했습니다. 앱은 문제당 정답 해시를 하나만 갖기 때문에 변형을 함께 수용할 수 없고, 따라서 **표기는 `fmt`가 책임져야 합니다.**
> Both rules 3 and 4 exist because of real bugs: `t4_mft` told players to type a `$` its grader rejected, and `t2_sha1` printed `SHA-256` in its own hints while refusing a hyphen. One challenge stores exactly one answer hash, so variants cannot be accepted — the notation has to carry that weight.
>
> 6번은 3번의 사각지대를 메웁니다. `fine-tuning`을 붙여 쓴 정답은 구분자도 없고 문자+숫자 복합도 아니라 3번이 길이를 요구하지 않지만, 통용 표기는 하이픈이라 그대로 입력한 사람이 틀립니다. 그런 정답은 열거로 복원하기엔 너무 길어 `[H]`가 형태조차 알 수 없으므로, 후보를 교재에서 가져옵니다.
> Rule 6 covers rule 3's blind spot: an answer like `finetuning` carries no separator and is not letters-run-into-digits, so nothing asks it to declare a length — yet the usual rendering is hyphenated. Answers that long are past what enumeration can reach, so the candidates come from the chapters instead.
>
> 7번은 `t1_lb`에서 나왔습니다. 프롬프트는 **장치**의 이름을 물었는데 힌트가 '짐을 나누다'라며 행위를 가리켜, **힌트를 산 사람이 바로 그 힌트 때문에** 다른 꼴을 적고 틀렸습니다. 3·6번이 다루는 축은 낱말을 **어떻게 끊어 쓰는가**여서, 두 꼴이 똑같이 한 단어인 이 경우에는 `[H]`도 `[I]`도 볼 것이 없었습니다. 다만 7번도 만능은 아닙니다 — **어간을 공유하지 않는 의역**(`t1_lb`의 '짐을 나누다'가 정확히 그 경우이고, 교재는 `load balancing`을 한 번도 쓰지 않습니다)은 `[J]`에도 보이지 않으므로 그건 여전히 사람이 읽어야 합니다.
> Rule 7 comes from `t1_lb`, which asked for the device and glossed the act, so the player who paid for the hint was misled by it. Rules 3 and 6 are about where a word is broken up, and both forms here are one unbroken word, so neither `[H]` nor `[I]` had anything to look at. `[J]` is not a cure-all either: a gloss that paraphrases the other form without sharing its stem — exactly `t1_lb`'s — stays invisible, and only a reader catches it.
