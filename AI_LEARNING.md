> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AI CLI로 VibeHacking 학습하기

> 클론 한 번, 질문 한 번 — AI가 64개 섹션의 튜터가 됩니다.

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

> Clone once, ask anything — AI becomes your tutor for all 64 sections.

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
