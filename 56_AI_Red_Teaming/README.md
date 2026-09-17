# 56. AI 레드팀 (AI_Red_Teaming)

> 🤺 **VibeHacking 교재 섹션 56**
> - **CLI 학습**: `python3 vhack.py study 56`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_ai_attack_fundamentals.md](./01_ai_attack_fundamentals.md) | **AI 공격 기초 (AI Attack Fundamentals)** — AI 시스템 도입 급증: |
| [02_prompt_injection.md](./02_prompt_injection.md) | **프롬프트 인젝션 (Prompt Injection)** — 프롬프트 인젝션은 AI 언어 모델에게 내려진 원래 지시(시스템 프롬프트)를 공격자가 악의적인 입력으로 덮어쓰거나 무시하게 만드는 공격이다. 마치 음식에 독을 섞듯, AI의 입력창에 몰... |
| [03_model_extraction.md](./03_model_extraction.md) | **모델 탈취 및 멤버십 추론 (Model Extraction & Membership Inference)** — 모델 추출은 유료 AI 서비스의 API를 반복 호출하여 그 응답 패턴을 학습함으로써, 원래 모델과 비슷하게 동작하는 복제 모델을 만드는 공격이다. 마치 식당의 레시피를 모르는 상태에서... |
| [04_adversarial_examples.md](./04_adversarial_examples.md) | **적대적 예제 (Adversarial Examples)** — 적대적 예제는 사람의 눈에는 원본과 거의 동일하게 보이지만, AI 모델은 완전히 다르게 분류하도록 정교하게 조작된 입력 데이터이다. 예를 들어 고양이 사진에 사람이 알아볼 수 없는 미... |
| [05_ai_red_team_defense.md](./05_ai_red_team_defense.md) | **AI 레드팀 방어 (AI Red Team Defense)** — AI 레드팀 방어는 AI 시스템에 대한 공격 기법을 연구하고, 발견된 취약점을 기반으로 방어 체계를 구축하는 활동이다. 일반 소프트웨어 보안과 달리 AI는 학습 데이터, 모델 가중치,... |
| [06_ai_red_team_ctf_lab.md](./06_ai_red_team_ctf_lab.md) | **AI 레드팀 CTF 실습 랩** — AI 보안 취약점을 CTF 형식으로 학습한다. 프롬프트 인젝션, 모델 추출, 적대적 입력 등 AI 공격 기법을 실습한다. |

## 🎯 학습 목표

- AI 공격 기초 (AI Attack Fundamentals) 원리 및 실전 공격/방어 기법 습득
- 프롬프트 인젝션 (Prompt Injection) 원리 및 실전 공격/방어 기법 습득
- 모델 탈취 및 멤버십 추론 (Model Extraction & Membership Inference) 원리 및 실전 공격/방어 기법 습득
- 적대적 예제 (Adversarial Examples) 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 56 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
