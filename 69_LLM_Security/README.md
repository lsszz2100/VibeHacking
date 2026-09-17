# 69. LLM 보안 (LLM_Security)

> 🗣️ **VibeHacking 교재 섹션 69**
> - **CLI 학습**: `python3 vhack.py study 69`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_llm_security_fundamentals.md](./01_llm_security_fundamentals.md) | **LLM 보안 기초** — pip install openai anthropic |
| [02_prompt_injection.md](./02_prompt_injection.md) | **프롬프트 인젝션 공격** — pip install garak          # LLM 취약점 스캐너(프롬프트 인젝션·탈옥 등 자동 점검) |
| [03_model_extraction_and_inversion.md](./03_model_extraction_and_inversion.md) | **모델 추출 및 역공학** — pip install numpy scikit-learn   # 대리 모델 학습·유사도 측정 |
| [04_adversarial_attacks_on_llm.md](./04_adversarial_attacks_on_llm.md) | **LLM 적대적 공격** — pip install transformers torch   # 대상 모델 + perplexity 측정 |
| [05_llm_security_defense.md](./05_llm_security_defense.md) | **LLM 보안 방어 전략** — pip install llm-guard            # 입력 검증·출력 필터 등 다계층 가드레일 |
| [06_llm_security_ctf_lab.md](./06_llm_security_ctf_lab.md) | **LLM 보안 CTF 실습 랩** — 이 랩은 실제 LLM API 없이 로컬에서 LLM 보안 공격 기법을 실습한다. llm_ctf.py 스크립트가 챌린지 로직을 시뮬레이션하며, 플래그를 발견하면 SHA-256 해시로 검증한다. |

## 🎯 학습 목표

- LLM 보안 기초 원리 및 실전 공격/방어 기법 습득
- 프롬프트 인젝션 공격 원리 및 실전 공격/방어 기법 습득
- 모델 추출 및 역공학 원리 및 실전 공격/방어 기법 습득
- LLM 적대적 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 69 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
