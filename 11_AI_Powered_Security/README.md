# 11. AI 기반 사이버보안 — 새로운 시대

## 목차

| 파일 | 내용 |
|------|------|
| [01_ai_security_landscape_2026.md](./01_ai_security_landscape_2026.md) | Claude Opus 5.5, Fable 5.2, GPT-6.1, Gemini 4 Pro, Gemini 3.8 Flash — AI 보안 생태계 전체 지형도 |
| [02_llm_vulnerability_research.md](./02_llm_vulnerability_research.md) | LLM으로 제로데이 발견, 코드 취약점 분석, AI 퍼징 |
| [03_ai_assisted_pentesting.md](./03_ai_assisted_pentesting.md) | AI를 활용한 침투 테스트 워크플로우, 프롬프트 엔지니어링, 실전 활용 |
| [04_ai_ctf_automation.md](./04_ai_ctf_automation.md) | AI 기반 CTF 자동화 — 웹/바이너리/포렌식/크립토 전 분야 |
| [05_claude_gpt_cyber_integration.md](./05_claude_gpt_cyber_integration.md) | Claude + GPT-6.1-Codex / GPT-5.6 통합 활용 — TAC 접근법, 이중 분석 파이프라인 |
| [06_ai_security_ctf_lab.md](./06_ai_security_ctf_lab.md) | **CTF 스타일 AI 보안 실습** — docker --version |

## 학습 목표
- 2026년 AI 보안 생태계와 주요 모델 이해
- LLM을 취약점 연구 보조 도구로 활용하는 방법
- AI 기반 자동화 보안 테스트 워크플로우 구성
- Claude Opus 5.5, Fable 5.2, GPT-6.1, Gemini 4 Pro / 3.8 Flash, Gemini Carbon/Hydrogen 등 최신 보안 AI 모델 활용

## 왜 지금 중요한가

```
2026년 4월 기준:

Anthropic Claude   → Claude Mythos 5.1 / Fable 5.2: 17년 된 FreeBSD RCE 취약점 자율 발견/익스플로잇
                   → Claude Opus 5.5: 대규모 코드베이스 취약점 정밀 분석 및 자율 에이전트 구동
                   → 인간 최고수 버그헌터도 못 찾는 취약점 수만 개 식별

OpenAI GPT-6.1 / GPT-5.6 → CTF 성능 27% → ~58% → 76%+ (GPT-5.4 → GPT-5.6 → GPT-6.1-Codex)
                     → GPT-5.6: 심층 추론, 취약점 분류, SIEM/YARA 자동화 및 방어 파이프라인
                     → GPT-6.1-Codex: 컴파일된 바이너리 심층 리버싱 및 자율 익스플로잇 공학
                     → 소스코드 없이 컴파일된 바이너리 심층 리버싱
                     → YARA / Sigma 룰 자동 생성 및 실시간 검증

Google Gemini      → Gemini 4 Pro: 심층 추론 기반 소스코드 취약점 및 로직 결함 전수 감사
                   → Gemini 3.8 Flash: 초고속 실시간 보안 이벤트 스트리밍 및 퍼징 루프 자동화
                   → Gemini Carbon / Hydrogen: 멀티모달 대규모 컨텍스트 및 분산 에이전트 위협 분석

결론: AI가 공격/방어 모두에서 인간을 앞서기 시작한 변곡점
```
