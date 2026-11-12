# 69. LLM 보안 (LLM_Security)

> 🗣️ **VibeHacking 교재 섹션 69**
> - **CLI 학습**: `python3 vhack.py study 69`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_llm_security_fundamentals.md](./01_llm_security_fundamentals.md) | **LLM 보안 기초** — 비유: LLM(Large Language Model)은 인터넷에 있는 수조 개의 문장을 읽고, 다음에 올 단어가 무엇인지 확률로 예측하는 통계 기계다. 사람처럼 "이... |
| [02_prompt_injection.md](./02_prompt_injection.md) | **프롬프트 인젝션 공격** — 비유: SQL 인젝션처럼, 사용자가 입력한 텍스트가 LLM의 "명령어 영역"과 구분 없이 처리되어 의도치 않은 동작을 유발하는 공격이다. LLM은 시스템 프롬프트와 ... |
| [03_model_extraction_and_inversion.md](./03_model_extraction_and_inversion.md) | **모델 추출 및 역공학** — 비유: 레스토랑에서 음식을 계속 주문하며 조리법을 역추적하는 것과 같다. 모델에 수천 번의 쿼리를 날려 입력-출력 쌍을 수집하고, 이를 바탕으로 "대리 모델(surr... |
| [04_adversarial_attacks_on_llm.md](./04_adversarial_attacks_on_llm.md) | **LLM 적대적 공격** — 비유: 정지 표지판에 작은 스티커를 붙이면 사람 눈에는 정지 표지판이지만, AI 카메라는 "속도 제한 45" 표지판으로 인식한다. LLM에서도 사람이 인식하기 어려운... |
| [05_llm_security_defense.md](./05_llm_security_defense.md) | **LLM 보안 방어 전략** — 비유: LLM을 은행 금고에 비유하면, 방어 레이어는 금고 앞의 보안 검색대(입력 필터), 은행 직원의 신분 확인(출력 검증), CCTV 로깅(감사 로그)과 같다. ... |
| [06_llm_security_ctf_lab.md](./06_llm_security_ctf_lab.md) | **LLM 보안 CTF 실습 랩** — 이 랩은 실제 LLM API 없이 로컬에서 LLM 보안 공격 기법을 실습한다. llm_ctf.py 스크립트가 챌린지 로직을 시뮬레이션하며, 플래그를 발견하면 SHA-256 해시로 검증한다. |
| [07_mcp_agent_tool_poisoning_and_sandbox_deepdive.md](./07_mcp_agent_tool_poisoning_and_sandbox_deepdive.md) | **제69장 LLM 보안 심층: AI 에이전트 & MCP 툴 포이즈닝·탈취 및 샌드박싱 방어 (Deep-dive)** — 2026년 현재 Claude Opus 4, GPT-4o, 오픈소스 에이전트 프레임워크는 단순 질의응답을 넘어 Model Context Protocol (MCP) 및 Function C... |
| [08_ai_agent_sandbox_escape_and_landlock_defense_deepdive.md](./08_ai_agent_sandbox_escape_and_landlock_defense_deepdive.md) | **제69장 LLM 보안 심층: AI 에이전트 탈출 공격·Landlock LSM 비특권 샌드박스 & eBPF 듀얼 런타임 방어 (Deep-dive)** — 2026년 기업 환경에 배포되는 자율 AI 에이전트(Autonomous AI Agents)는 단순한 텍스트 생성을 넘어, Model Context Protocol (MCP) 및 표준 ... |

## 🎯 학습 목표

- LLM 보안 기초 원리 및 실전 공격/방어 기법 습득
- 프롬프트 인젝션 공격 원리 및 실전 공격/방어 기법 습득
- 모델 추출 및 역공학 원리 및 실전 공격/방어 기법 습득
- LLM 적대적 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 69 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
