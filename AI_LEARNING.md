> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english) | [🇯🇵 日本語](#japanese) | [🇨🇳 中文](#chinese)

---

<a name="한국어"></a>

# AI CLI로 VibeHacking 학습하기

> 클론 한 번, 질문 한 번 — AI가 75개 섹션의 튜터가 됩니다.

## 핵심 아이디어

`claude`, `codex`, `gemini` 같은 AI CLI 도구를 **레포 디렉토리 안에서** 실행하면, AI가 모든 마크다운 파일을 문맥으로 읽고 자연어로 질문에 답합니다.

```
VibeHacking 레포 디렉토리
├── 모든 .md 파일 (학습 자료)  ← AI가 읽는 컨텍스트
└── labs/ (Docker 실습 환경)   ← AI가 대신 실행
```

별도의 검색 없이 **"SQL 인젝션 실습 도와줘"** 한 마디면:
- 관련 섹션 찾아서 설명
- 실습 환경 자동 시작
- 단계별 실습 안내

> 🎮 **워게임으로 점검**: 이론을 익혔다면 [브라우저 워게임](wargame/README.md)(`https://lsszz2100.github.io/VibeHacking/`)에서 실력을 확인하세요. 가짜 셸로 5개 보안 계층을 침투하는 터미널형 CTF 455문제 — AI CLI에게 "워게임 N번 힌트만 줘"처럼 물어볼 수도 있습니다.

---

## 목차

1. [Claude Code](#1-claude-code)
2. [OpenAI Codex CLI](#2-openai-codex-cli)
3. [Gemini CLI](#3-gemini-cli)
4. [공통 학습 프롬프트 템플릿](#4-공통-학습-프롬프트-템플릿)
5. [AI 활용 학습 시나리오](#5-ai-활용-학습-시나리오)

---

## 1. Claude Code

Claude Code는 파일 읽기·명령어 실행·코드 작성을 결합한 터미널 AI 에이전트입니다.  
VibeHacking 디렉토리에서 실행하면 전체 자료를 컨텍스트로 활용합니다.

### 설치

```bash
npm install -g @anthropic-ai/claude-code
```

### 기본 흐름

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
claude
```

### 학습 예시 프롬프트

```
# 입문 경로 추천
"보안을 처음 배우는데 이 레포에서 어떤 순서로 공부해야 해?"

# 개념 설명
"SQL 인젝션이 뭔지 초보자에게 설명해줘.
 05_Web_Hacking 폴더 내용을 참고해서"

# 파일 직접 읽기 + 요약
"02_sql_injection_advanced.md 읽고 핵심 공격 기법 5개 정리해줘"

# 실습 시작까지 자동화
"웹 해킹 랩 환경을 시작하고 DVWA에서
 SQL 인젝션 초급 실습을 단계별로 안내해줘"

# CTF 문제 풀기
"labs/01_web_hacking_lab 에 CTF 형식 문제가 있어.
 힌트만 줘, 풀이는 스스로 해볼게"

# 코드 해석
"08_Python_Hacking/01_python_hacking_tools.md 의
 포트 스캐너 코드가 어떻게 작동하는지 설명해줘"
```

### Claude Code만의 강점

| 기능 | 설명 |
|------|------|
| **파일 직접 읽기** | `@파일명` 없이도 디렉토리 구조를 파악해 관련 파일 자동 참조 |
| **명령어 실행** | Docker 랩 시작·종료를 대화 중 직접 실행 |
| **코드 작성** | 학습 중 파이썬 익스플로잇 코드를 즉석에서 작성·수정 |
| **멀티파일 분석** | 여러 섹션을 동시에 읽어 교차 분석 |

---

## 2. OpenAI Codex CLI

OpenAI의 터미널 에이전트입니다. 코드 생성·설명·실행에 특화되어 있습니다.

### 설치

```bash
npm install -g @openai/codex
```

### 기본 흐름

```bash
cd VibeHacking
codex
```

### 학습 예시 프롬프트

```
# 섹션 요약
"19_Assembly_Language 폴더를 훑어보고
 x86 어셈블리 학습 순서를 알려줘"

# 취약점 코드 분석
"09_Exploit_Techniques/03_heap_exploitation.md 의
 힙 오버플로 예제 코드를 줄마다 설명해줘"

# 익스플로잇 스크립트 작성
"pwntools로 스택 오버플로 익스플로잇 스크립트를 작성해줘.
 19_Assembly_Language 를 참고해서"

# 실습 환경 구성 도움
"labs/02_pwn_lab 환경을 시작하고
 BOF 챌린지에서 리턴 주소를 찾는 방법을 안내해줘"

# 개념 → 코드 연결
"Kerberoasting 공격 원리를 설명하고
 54_Active_Directory_Attacks 에 나온 impacket 명령어를 같이 보여줘"
```

---

## 3. Gemini CLI

Google의 터미널 AI 에이전트입니다. 대용량 컨텍스트 처리에 강점이 있습니다.

### 설치

```bash
npm install -g @google/gemini-cli
```

### 기본 흐름

```bash
cd VibeHacking
gemini
```

### 학습 예시 프롬프트

```
# 대용량 자료 한 번에 분석
"이 레포 전체를 분석해서 보안 학습 6개월 로드맵을 만들어줘.
 난 CTF 입문자야"

# 비교 분석
"16_Cryptography 와 57_Quantum_Cryptography 섹션을 비교해서
 현재 암호 기술이 양자컴퓨터에 어떤 위협을 받는지 설명해줘"

# 자격증 연계 학습
"정보보안기사 실기 준비를 위해
 41_Korean_Certifications 를 기반으로 학습 계획 짜줘"

# 최신 기법 설명
"56_AI_Red_Teaming 섹션 읽고
 AI 기반 보안 공격이 기존 공격과 어떻게 다른지 설명해줘"
```

---

## 4. 공통 학습 프롬프트 템플릿

어떤 AI CLI든 아래 템플릿을 그대로 붙여넣어 사용할 수 있습니다.

### 📚 학습 경로 추천

```
내 상황: [현재 실력 — 예: 리눅스 기초만 앎 / 웹개발 경력 2년 / CTF 입문]
목표: [예: 버그 바운티 시작 / OSCP 취득 / CTF 실력 향상]

이 레포에서 나에게 맞는 학습 순서를 추천해줘.
각 섹션에서 먼저 읽어야 할 파일도 알려줘.
```

### 🔍 개념 이해

```
[섹션명 또는 파일명]을 읽고:
1. 핵심 개념을 초보자도 이해할 수 있게 설명해줘
2. 실제 공격/방어에서 어떻게 쓰이는지 예시를 들어줘
3. 이 개념을 연습할 수 있는 실습 환경은 뭐야?
```

### 🧪 실습 안내

```
[랩 번호 또는 주제] 실습을 하고 싶어.
1. 필요한 배경 지식을 먼저 설명해줘
2. 실습 환경 시작 방법을 알려줘
3. 단계별로 실습을 안내해줘
4. 막히면 힌트를 줘 (풀이는 바로 알려주지 마)
```

### 🚩 CTF 도움 (힌트만)

```
[문제 설명 또는 파일명]
이 CTF 문제를 풀고 싶어.
직접적인 풀이 말고, 어떤 방향으로 접근해야 할지 힌트만 줘.
관련 학습 자료도 이 레포에서 찾아줘.
```

### 🔎 코드 분석

```
[파일명 또는 코드 붙여넣기]
이 코드를:
1. 한 줄씩 주석으로 설명해줘
2. 보안적으로 취약한 부분이 있으면 알려줘
3. Python 3.10+ 스타일로 개선해줘
```

### 📝 개념 테스트

```
[섹션명]을 공부했어.
내가 제대로 이해했는지 확인할 수 있도록
난이도별 퀴즈 5문제를 내줘.
(객관식 2개, 단답형 2개, 서술형 1개)
```

---

## 5. AI 활용 학습 시나리오

### 시나리오 A: 완전 초보자의 첫 날

```bash
cd VibeHacking
claude   # 또는 codex / gemini

# 1. 현재 상황 설명
"나는 보안을 처음 공부하는 대학생이야.
 이 레포가 뭔지, 어디서 시작해야 하는지 알려줘"

# 2. 첫 번째 파일 읽기
"01_Linux_Basics/01_linux_essential_commands.md 읽고
 오늘 당장 외워야 할 명령어 TOP 10을 정리해줘"

# 3. 직접 실습
"지금 내 터미널에서 연습할 수 있는
 리눅스 기초 실습을 5가지 내줘"
```

### 시나리오 B: 웹 해킹 집중 공략

```bash
cd VibeHacking
claude

# 1. 이론 파악
"05_Web_Hacking 섹션 전체를 스캔해서
 OWASP Top 10 각 항목을 한 줄로 요약해줘"

# 2. 실습 환경 시작
"Lab 01 웹 해킹 환경을 시작하고
 Docker 컨테이너가 정상 실행됐는지 확인해줘"

# 3. 실전 실습
"DVWA에서 SQL 인젝션 Low 난이도 실습을 단계별로 안내해줘.
 각 단계에서 어떤 원리가 작동하는지 설명하면서"

# 4. 심화
"방금 한 SQL 인젝션 공격을 방어하는 코드를 작성해줘.
 Prepared Statement 방식으로"
```

### 시나리오 C: CTF 대회 준비

```bash
cd VibeHacking
codex

# 1. 분야별 핵심 파악
"46_CTF_Techniques 섹션을 읽고
 Pwn / Web / Crypto / Forensics 각 분야의
 필수 도구와 기법을 표로 정리해줘"

# 2. 취약점 랩 실습
"labs/02_pwn_lab 시작하고
 BOF-01 문제에서 오프셋을 찾는 방법만 힌트로 알려줘"

# 3. 도구 사용법
"pwntools로 64비트 바이너리 익스플로잇 스크립트
 기본 템플릿을 작성해줘"
```

### 시나리오 D: 자격증 준비 (정보보안기사)

```bash
cd VibeHacking
gemini

# 1. 출제 범위 파악
"41_Korean_Certifications/01_information_security_engineer.md 읽고
 필기 5과목 핵심 키워드를 과목별로 정리해줘"

# 2. 취약 파트 집중
"암호학 파트가 약한데
 16_Cryptography 섹션에서 시험에 자주 나오는 내용만 추려줘"

# 3. 모의고사
"정보보안기사 필기 스타일로
 네트워크 보안 단원 10문제를 내줘"
```

---

## AI CLI별 특성 비교

| | Claude Code | Codex CLI | Gemini CLI |
|--|:-----------:|:---------:|:----------:|
| **코드 실행** | ✅ 직접 실행 | ✅ 직접 실행 | ✅ 직접 실행 |
| **파일 읽기** | ✅ 자동 탐색 | ✅ 자동 탐색 | ✅ 자동 탐색 |
| **컨텍스트 창** | 대용량 | 대용량 | 최대 (100만 토큰+) |
| **코드 특화** | ✅ 강함 | ✅ 매우 강함 | ✅ 강함 |
| **한국어** | ✅ 자연스러움 | ✅ 양호 | ✅ 양호 |
| **Docker 연동** | ✅ 명령어 실행 | ✅ 명령어 실행 | ✅ 명령어 실행 |

> **추천**: 처음엔 어떤 도구든 상관없습니다.  
> VibeHacking 디렉토리에서 실행하고 자연어로 질문하면 됩니다.

---

## 팁

**레포를 항상 최신으로 유지하세요**

```bash
# AI CLI 시작 전 항상 업데이트
git pull origin main
# 또는
vhack update
```

**첫 질문은 구체적일수록 좋습니다**

```
❌ "보안 알려줘"
✅ "SQL 인젝션이 처음인데, 05_Web_Hacking/02_sql_injection_advanced.md를
    읽고 핵심 개념 3가지와 실습 방법을 알려줘"
```

**모르는 게 생기면 즉시 물어보세요**

```
"방금 설명한 ASLR 우회에서 leak이 왜 필요한지 더 쉽게 설명해줘"
"이 명령어에서 -p 옵션이 뭔지 모르겠어"
```

---

> 📖 설치 가이드 → [INSTALL.md](./INSTALL.md)
> 📘 vhack CLI 명령어 → [USAGE.md](./USAGE.md)

---

<a name="english"></a>

# Learning VibeHacking with AI CLIs

> Clone once, ask anything — AI becomes your tutor for all 75 sections.

## The Core Idea

Run `claude`, `codex`, or `gemini` **inside the repo directory** and the AI reads all markdown files as context, answering questions in natural language.

```
VibeHacking repo directory
├── All .md files (learning material)  ← AI reads as context
└── labs/ (Docker lab environments)    ← AI can run for you
```

One sentence — *"walk me through a SQL injection lab"* — and the AI will:
- Find the relevant section and explain it
- Start the lab environment
- Guide you step-by-step

> 🎮 **Test yourself in the wargame**: once you've learned the theory, check your skills in the [browser wargame](wargame/README.md) (`https://lsszz2100.github.io/VibeHacking/`) — a terminal-style CTF where you breach five security layers via a fake shell, 455 challenges. You can even ask an AI CLI for "just a hint on wargame #N".

---

## 1. Claude Code

```bash
npm install -g @anthropic-ai/claude-code
cd VibeHacking
claude
```

**Example prompts:**
```
"I'm a beginner. What order should I study this repo in?"
"Read 05_Web_Hacking/01_owasp_top10.md and explain the top 3 vulns"
"Start Lab 01 and guide me through a SQL injection exercise on DVWA"
"Explain the heap exploitation code in 09_Exploit_Techniques/03_heap_exploitation.md line by line"
"Give me 5 quiz questions on buffer overflows to test my understanding"
```

---

## 2. OpenAI Codex CLI

```bash
npm install -g @openai/codex
cd VibeHacking
codex
```

**Example prompts:**
```
"Summarize the 19_Assembly_Language section and suggest a learning order"
"Write a pwntools exploit script for a basic stack overflow, referencing the Assembly section"
"Start labs/02_pwn_lab and give me hints (not solutions) for the BOF challenge"
```

---

## 3. Gemini CLI

```bash
npm install -g @google/gemini-cli
cd VibeHacking
gemini
```

**Example prompts:**
```
"Analyze this entire repo and create a 6-month learning roadmap for a CTF beginner"
"Compare 16_Cryptography and 57_Quantum_Cryptography — how does quantum computing threaten current crypto?"
"Read 56_AI_Red_Teaming and explain how AI-powered attacks differ from traditional ones"
```

---

## Universal Prompt Templates

### Learning Path
```
My background: [e.g., know basic Linux / 2 years web dev / CTF beginner]
Goal: [e.g., start bug bounty / pass OSCP / improve CTF skills]
Recommend a study order from this repo with specific files to start with.
```

### Concept Deep-Dive
```
Read [section/file] and:
1. Explain the core concept for a beginner
2. Give a real-world attack/defense example
3. Which lab environment can I practice this in?
```

### Guided Practice
```
I want to practice [topic/lab number].
1. Give me background knowledge first
2. Tell me how to start the lab
3. Guide me step by step
4. Give hints only if I get stuck — don't spoil the solution
```

### CTF Hints Only
```
[Problem description]
I want to solve this CTF challenge myself.
Give me only the approach/direction, not the solution.
Find related study material in this repo too.
```

### Code Test
```
Quiz me on [section name] with 5 questions:
2 multiple choice, 2 short answer, 1 essay.
I just finished studying it.
```

---

## AI CLI Comparison

| | Claude Code | Codex CLI | Gemini CLI |
|--|:-----------:|:---------:|:----------:|
| **Execute commands** | ✅ | ✅ | ✅ |
| **Read files** | ✅ auto | ✅ auto | ✅ auto |
| **Context window** | Large | Large | Largest (1M+ tokens) |
| **Code focus** | ✅ Strong | ✅ Very strong | ✅ Strong |
| **Docker integration** | ✅ | ✅ | ✅ |

> **Recommendation:** Any tool works. The key is running it inside the VibeHacking directory and asking in natural language.

---

## Tips

```bash
# Always pull latest content before starting
git pull origin main
```

```
❌ "teach me security"
✅ "Read 05_Web_Hacking/02_sql_injection_advanced.md
    and explain the 3 core concepts + how to practice them"
```

> 📖 Installation guide → [INSTALL.md](./INSTALL.md)
> 📘 vhack CLI reference → [USAGE.md](./USAGE.md)

---

<a name="japanese"></a>

# AI CLIでVibeHackingを学ぶ

> 1回クローン、1回質問 — AIが75セクション全てのチューターになります。

## 核心アイデア

`claude`・`codex`・`gemini` などのAI CLIツールを**レポジトリのディレクトリ内で**実行すると、AIが全マークダウンファイルをコンテキストとして読み込み、自然言語で質問に答えます。

```
VibeHacking レポジトリ
├── 全 .md ファイル (学習資料)   ← AIが読むコンテキスト
└── labs/ (Docker 実習環境)      ← AIが代わりに実行
```

ファイルを手動で探さなくても **「SQL インジェクション実習を案内して」** の一言で：
- 関連セクションを自動検索して説明
- 実習環境を自動起動
- ステップごとに実習を案内

> 🎮 **ワーゲームで力試し**: 理論を学んだら[ブラウザワーゲーム](wargame/README.md)（`https://lsszz2100.github.io/VibeHacking/`）で腕試しを。偽シェルで5つのセキュリティ層を突破するターミナル型CTF、全455問。AI CLIに「ワーゲームN番のヒントだけ」と聞くこともできます。

---

## 目次

1. [Claude Code](#claude-code-ja)
2. [OpenAI Codex CLI](#codex-cli-ja)
3. [Gemini CLI](#gemini-cli-ja)
4. [共通プロンプトテンプレート](#prompt-templates-ja)
5. [AI活用学習シナリオ](#scenarios-ja)

---

<a name="claude-code-ja"></a>

## 1. Claude Code

ファイル読み取り・コマンド実行・コード作成を組み合わせたターミナルAIエージェントです。VibeHackingディレクトリで実行すると、全資料をコンテキストとして活用します。

### インストール

```bash
npm install -g @anthropic-ai/claude-code
```

### 基本フロー

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
claude
```

### 学習プロンプト例

```
# 入門経路の推薦
「セキュリティを初めて学ぶのですが、このリポジトリでどんな順番で学べばいいですか？」

# 概念説明
「SQL インジェクションとは何か、初心者にわかるように説明してください。
 05_Web_Hacking フォルダの内容を参考にして」

# ファイルを直接読んで要約
「02_sql_injection_advanced.md を読んで、核心的な攻撃技法を5つ整理して」

# 実習開始まで自動化
「Webハッキングラボ環境を起動して、DVWAでSQL インジェクション初級実習を
 ステップごとに案内してください」

# CTF問題を解く
「labs/01_web_hacking_lab にCTF形式の問題があります。
 ヒントだけ教えてください。解答は自分でやります」

# コード解説
「08_Python_Hacking/01_python_hacking_tools.md の
 ポートスキャナコードがどのように動作するか説明して」
```

### Claude Code だけの強み

| 機能 | 説明 |
|------|------|
| **ファイル自動参照** | `@ファイル名` なしでもディレクトリ構造を把握し関連ファイルを自動参照 |
| **コマンド実行** | Dockerラボの起動・停止を会話中に直接実行 |
| **コード作成** | 学習中にPythonエクスプロイトコードをその場で作成・修正 |
| **マルチファイル分析** | 複数セクションを同時に読んでクロス分析 |

---

<a name="codex-cli-ja"></a>

## 2. OpenAI Codex CLI

OpenAIのターミナルエージェントです。コード生成・解説・実行に特化しています。

### インストール

```bash
npm install -g @openai/codex
```

### 基本フロー

```bash
cd VibeHacking
codex
```

### 学習プロンプト例

```
# セクション要約
「19_Assembly_Language フォルダを確認して
 x86 アセンブリの学習順序を教えて」

# 脆弱性コード解析
「09_Exploit_Techniques/03_heap_exploitation.md の
 ヒープオーバーフローのサンプルコードを一行ずつ説明して」

# エクスプロイトスクリプト作成
「pwntools でスタックオーバーフローエクスプロイトスクリプトを書いて。
 19_Assembly_Language を参考にして」

# 実習環境構成
「labs/02_pwn_lab を起動して
 BOFチャレンジでリターンアドレスを見つける方法をヒントだけ教えて」

# 概念 → コード連携
「Kerberoasting攻撃の原理を説明して
 54_Active_Directory_Attacks に載っているimpacketコマンドも見せて」
```

---

<a name="gemini-cli-ja"></a>

## 3. Gemini CLI

Googleのターミナルエージェントです。大容量コンテキスト処理に強みがあります。

### インストール

```bash
npm install -g @google/gemini-cli
```

### 基本フロー

```bash
cd VibeHacking
gemini
```

### 学習プロンプト例

```
# 大容量資料を一度に分析
「このリポジトリ全体を分析して、セキュリティ学習6ヶ月のロードマップを作って。
 私はCTF入門者です」

# 比較分析
「16_Cryptography と 57_Quantum_Cryptography セクションを比較して
 現在の暗号技術が量子コンピュータにどんな脅威を受けるか説明して」

# 資格試験連携学習
「情報処理安全確保支援士の試験対策として
 41_Korean_Certifications を参考に学習計画を立てて」

# 最新技法の説明
「56_AI_Red_Teaming セクションを読んで
 AIを使ったセキュリティ攻撃が従来の攻撃とどう違うか説明して」
```

---

<a name="prompt-templates-ja"></a>

## 4. 共通プロンプトテンプレート

どのAI CLIでもそのまま貼り付けて使えます。

### 📚 学習経路の推薦

```
私の状況: [現在のスキル — 例: Linuxの基礎のみ / Web開発2年経験 / CTF入門]
目標: [例: バグバウンティを始める / OSCP取得 / CTFスキル向上]

このリポジトリから私に合った学習順序を推薦してください。
各セクションで最初に読むべきファイルも教えてください。
```

### 🔍 概念理解

```
[セクション名またはファイル名]を読んで：
1. 核心概念を初心者にもわかるように説明して
2. 実際の攻撃/防御でどう使われるか例を挙げて
3. この概念を練習できる実習環境はどれ？
```

### 🧪 実習案内

```
[ラボ番号またはテーマ] の実習をやりたい。
1. 必要な前提知識を先に説明して
2. 実習環境の起動方法を教えて
3. ステップごとに実習を案内して
4. 詰まったらヒントを教えて (解答はすぐに教えないで)
```

### 🚩 CTFヒントのみ

```
[問題の説明またはファイル名]
このCTF問題を自分で解きたい。
直接的な解答ではなく、どの方向で攻略すればいいかヒントだけ教えて。
このリポジトリ内の関連学習資料も探して。
```

### 🔎 コード分析

```
[ファイル名またはコードの貼り付け]
このコードを：
1. 一行ずつコメントで説明して
2. セキュリティ上の脆弱な部分があれば教えて
3. Python 3.10+ スタイルで改善して
```

### 📝 理解度テスト

```
[セクション名]を勉強しました。
正しく理解できているか確認するために
難易度別のクイズを5問出してください。
(択一式2問、短答式2問、記述式1問)
```

---

<a name="scenarios-ja"></a>

## 5. AI活用学習シナリオ

### シナリオA: 完全初心者の初日

```bash
cd VibeHacking
claude

「セキュリティを初めて勉強する大学生です。
 このリポジトリが何で、どこから始めればいいか教えてください」

「01_Linux_Basics/01_linux_essential_commands.md を読んで
 今日絶対に覚えるべきコマンドTOP10をまとめて」

「今の自分のターミナルで練習できる
 Linuxの基礎実習を5つ出して」
```

### シナリオB: Webハッキング集中攻略

```bash
cd VibeHacking
claude

「05_Web_Hacking セクション全体をスキャンして
 OWASP Top 10の各項目を一行で要約して」

「Lab 01 Webハッキング環境を起動して
 Dockerコンテナが正常に動いているか確認して」

「DVWAでSQL インジェクション Low難易度実習をステップごとに案内して。
 各ステップでどんな原理が動いているか説明しながら」
```

### シナリオC: CTF大会準備

```bash
cd VibeHacking
codex

「46_CTF_Techniques セクションを読んで
 Pwn / Web / Crypto / Forensics 各分野の
 必須ツールと技法を表にまとめて」

「labs/02_pwn_lab を起動して
 BOF-01問題でオフセットを見つける方法だけヒントで教えて」

「pwntools で64ビットバイナリエクスプロイトスクリプトの
 基本テンプレートを書いて」
```

### シナリオD: 資格試験対策

```bash
cd VibeHacking
gemini

「41_Korean_Certifications/01_information_security_engineer.md を読んで
 5科目の核心キーワードを科目別にまとめて」

「暗号学が苦手なので
 16_Cryptography セクションから試験に頻出の内容だけ抜き出して」

「情報処理安全確保支援士スタイルで
 ネットワークセキュリティの問題を10問出して」
```

---

## AI CLI 特性比較

| | Claude Code | Codex CLI | Gemini CLI |
|--|:-----------:|:---------:|:----------:|
| **コマンド実行** | ✅ 直接実行 | ✅ 直接実行 | ✅ 直接実行 |
| **ファイル読み取り** | ✅ 自動探索 | ✅ 自動探索 | ✅ 自動探索 |
| **コンテキスト窓** | 大容量 | 大容量 | 最大 (100万トークン+) |
| **コード特化** | ✅ 強い | ✅ 非常に強い | ✅ 強い |
| **日本語対応** | ✅ 自然 | ✅ 良好 | ✅ 良好 |
| **Docker連携** | ✅ | ✅ | ✅ |

> **推薦**: どのツールでも構いません。  
> VibeHackingディレクトリで実行して自然言語で質問するだけです。

---

## ヒント

**リポジトリを常に最新にしてください**

```bash
git pull origin main
# または
vhack update
```

**最初の質問は具体的なほど良いです**

```
❌ 「セキュリティを教えて」
✅ 「05_Web_Hacking/02_sql_injection_advanced.md を読んで
    核心概念3つと実習方法を教えて」
```

---

> 📖 インストールガイド → [INSTALL.md](./INSTALL.md)
> 📘 vhack CLI リファレンス → [USAGE.md](./USAGE.md)

---

<a name="chinese"></a>

# 用 AI CLI 学习 VibeHacking

> 克隆一次，提问一次 — AI 成为 75 个章节的专属导师。

## 核心理念

在**仓库目录内**运行 `claude`、`codex`、`gemini` 等 AI CLI 工具，AI 会将所有 Markdown 文件作为上下文读取，并用自然语言回答问题。

```
VibeHacking 仓库目录
├── 全部 .md 文件 (学习资料)   ← AI 读取的上下文
└── labs/ (Docker 实验环境)    ← AI 可以代为执行
```

无需手动搜索文件，只需一句话 **「帮我进行 SQL 注入实验」**，AI 就会：
- 自动找到相关章节并进行讲解
- 自动启动实验环境
- 逐步引导实践

> 🎮 **用战争游戏检验**：学完理论后，在[浏览器战争游戏](wargame/README.md)（`https://lsszz2100.github.io/VibeHacking/`）中检验自己 —— 用伪 Shell 攻破五道安全层的终端式 CTF，共 455 题。你甚至可以让 AI CLI「只给战争游戏第 N 题一个提示」。

---

## 目录

1. [Claude Code](#claude-code-zh)
2. [OpenAI Codex CLI](#codex-cli-zh)
3. [Gemini CLI](#gemini-cli-zh)
4. [通用提示词模板](#prompt-templates-zh)
5. [AI 辅助学习场景](#scenarios-zh)

---

<a name="claude-code-zh"></a>

## 1. Claude Code

结合文件读取、命令执行和代码编写的终端 AI 代理。在 VibeHacking 目录下运行，可将全部资料作为上下文使用。

### 安装

```bash
npm install -g @anthropic-ai/claude-code
```

### 基本流程

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
claude
```

### 学习提示词示例

```
# 推荐入门路径
「我是完全的安全初学者，这个仓库应该按什么顺序学习？」

# 概念讲解
「请用初学者能理解的方式解释 SQL 注入。
 参考 05_Web_Hacking 文件夹的内容」

# 直接读取文件并总结
「读取 02_sql_injection_advanced.md，整理核心攻击技术 5 个」

# 自动化到实验开始
「启动 Web 渗透实验室环境，一步步引导我在 DVWA 上完成
 SQL 注入初级实验」

# CTF 解题
「labs/01_web_hacking_lab 里有 CTF 格式的题目。
 只给我提示，解答我自己来」

# 代码解读
「解释 08_Python_Hacking/01_python_hacking_tools.md 中的
 端口扫描器代码是如何工作的」
```

### Claude Code 独有优势

| 功能 | 说明 |
|------|------|
| **文件自动参考** | 无需 `@文件名`，自动掌握目录结构并参考相关文件 |
| **命令执行** | 在对话中直接启动/停止 Docker 实验室 |
| **代码编写** | 学习过程中即时编写并修改 Python 漏洞利用代码 |
| **多文件分析** | 同时读取多个章节进行交叉分析 |

---

<a name="codex-cli-zh"></a>

## 2. OpenAI Codex CLI

OpenAI 的终端代理，专注于代码生成、解说和执行。

### 安装

```bash
npm install -g @openai/codex
```

### 基本流程

```bash
cd VibeHacking
codex
```

### 学习提示词示例

```
# 章节摘要
「浏览 19_Assembly_Language 文件夹，告诉我 x86 汇编的学习顺序」

# 漏洞代码分析
「逐行解释 09_Exploit_Techniques/03_heap_exploitation.md 中
 堆溢出的示例代码」

# 编写利用脚本
「用 pwntools 编写栈溢出利用脚本，参考 19_Assembly_Language」

# 实验环境配置
「启动 labs/02_pwn_lab，只给我提示如何在 BOF 挑战中找到返回地址」

# 概念 → 代码联动
「解释 Kerberoasting 攻击原理，并展示
 54_Active_Directory_Attacks 中的 impacket 命令」
```

---

<a name="gemini-cli-zh"></a>

## 3. Gemini CLI

Google 的终端 AI 代理，在处理大容量上下文方面具有优势。

### 安装

```bash
npm install -g @google/gemini-cli
```

### 基本流程

```bash
cd VibeHacking
gemini
```

### 学习提示词示例

```
# 一次分析大量资料
「分析整个仓库，为 CTF 入门者制定 6 个月学习路线图」

# 对比分析
「对比 16_Cryptography 和 57_Quantum_Cryptography 章节，
 解释量子计算机对当前密码技术构成怎样的威胁」

# 认证考试联动学习
「基于 41_Korean_Certifications 内容，制定备考计划」

# 最新技术讲解
「读取 56_AI_Red_Teaming，解释 AI 驱动的安全攻击与传统攻击有何不同」
```

---

<a name="prompt-templates-zh"></a>

## 4. 通用提示词模板

任何 AI CLI 均可直接复制使用。

### 📚 学习路径推荐

```
我的情况: [当前水平 — 例：只懂 Linux 基础 / 两年 Web 开发经验 / CTF 入门]
目标: [例：开始漏洞赏金 / 备考 OSCP / 提升 CTF 水平]

请推荐这个仓库中适合我的学习顺序，并告诉我每个章节最先应该读哪些文件。
```

### 🔍 概念理解

```
读取 [章节名或文件名]，并：
1. 用初学者能理解的方式解释核心概念
2. 举例说明它在实际攻击/防御中如何使用
3. 我可以在哪个实验环境中练习这个概念？
```

### 🧪 实验引导

```
我想进行 [实验编号或主题] 的实验。
1. 先给我讲解必要的背景知识
2. 告诉我如何启动实验环境
3. 逐步引导我完成实验
4. 卡住时给我提示（不要直接给解答）
```

### 🚩 CTF 仅提示

```
[题目描述或文件名]
我想自己解这道 CTF 题。
只告诉我解题方向，不要直接给出解答。
也帮我在仓库里找相关学习资料。
```

### 🔎 代码分析

```
[文件名或粘贴代码]
请对这段代码：
1. 逐行添加注释说明
2. 指出存在安全漏洞的部分
3. 用 Python 3.10+ 风格进行改进
```

### 📝 理解度测试

```
我刚学完 [章节名]。
请出 5 道题测试我是否真正理解：
（选择题 2 道、简答题 2 道、论述题 1 道）
```

---

<a name="scenarios-zh"></a>

## 5. AI 辅助学习场景

### 场景 A：完全初学者的第一天

```bash
cd VibeHacking
claude

「我是刚开始学安全的大学生。
 请告诉我这个仓库是什么、应该从哪里开始」

「读取 01_Linux_Basics/01_linux_essential_commands.md，
 整理今天必须记住的命令 TOP 10」

「出 5 道我现在就能在终端上练习的 Linux 基础实验题」
```

### 场景 B：Web 渗透集中突破

```bash
cd VibeHacking
claude

「扫描整个 05_Web_Hacking 章节，用一句话总结 OWASP Top 10 每一项」

「启动 Lab 01 Web 渗透环境，并确认 Docker 容器是否正常运行」

「一步步引导我在 DVWA 上完成 SQL 注入 Low 难度实验，
 并在每个步骤解释其中的原理」
```

### 场景 C：CTF 备赛

```bash
cd VibeHacking
codex

「读取 46_CTF_Techniques，用表格整理
 Pwn / Web / Crypto / Forensics 各方向的必备工具和技术」

「启动 labs/02_pwn_lab，只给我提示如何在 BOF-01 题目中找到偏移量」

「用 pwntools 写一个 64 位二进制利用脚本的基础模板」
```

### 场景 D：备考认证

```bash
cd VibeHacking
gemini

「读取 41_Korean_Certifications/01_information_security_engineer.md，
 按科目整理 5 门课程的核心关键词」

「密码学部分比较薄弱，
 从 16_Cryptography 中筛选出考试高频内容」

「用信息安全工程师考试风格出 10 道网络安全单元题」
```

---

## AI CLI 特性对比

| | Claude Code | Codex CLI | Gemini CLI |
|--|:-----------:|:---------:|:----------:|
| **执行命令** | ✅ 直接执行 | ✅ 直接执行 | ✅ 直接执行 |
| **读取文件** | ✅ 自动探索 | ✅ 自动探索 | ✅ 自动探索 |
| **上下文窗口** | 大容量 | 大容量 | 最大 (100万+ token) |
| **代码专精** | ✅ 强 | ✅ 非常强 | ✅ 强 |
| **中文支持** | ✅ 流畅 | ✅ 良好 | ✅ 良好 |
| **Docker 集成** | ✅ | ✅ | ✅ |

> **推荐**：使用哪个工具都可以。  
> 在 VibeHacking 目录中运行，用自然语言提问即可。

---

## 使用技巧

**保持仓库最新**

```bash
git pull origin main
# 或
vhack update
```

**第一个问题越具体越好**

```
❌ 「教我安全知识」
✅ 「读取 05_Web_Hacking/02_sql_injection_advanced.md，
    解释 3 个核心概念和练习方法」
```

---

> 📖 安装指南 → [INSTALL.md](./INSTALL.md)
> 📘 vhack CLI 参考 → [USAGE.md](./USAGE.md)
