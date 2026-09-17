# 53. 서버리스 보안 (Serverless_Security)

> ⚡ **VibeHacking 교재 섹션 53**
> - **CLI 학습**: `python3 vhack.py study 53`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_lambda_function_attacks.md](./01_lambda_function_attacks.md) | **AWS Lambda 함수 공격 기법** — Lambda 실행 흐름: |
| [02_serverless_injection.md](./02_serverless_injection.md) | **서버리스 인젝션 — 이벤트 주입·의존성 공격·탐지** — 서버리스는 "서버가 없다"는 뜻이 아니라, 개발자가 서버를 직접 관리하지 않는다는 뜻입니다. AWS Lambda, Azure Functions, Google Cloud Function... |
| [03_serverless_iam_abuse.md](./03_serverless_iam_abuse.md) | **서버리스 IAM 권한 남용 — 역할 체인·권한 상승·분석 CLI** — 서버리스 IAM 문제: |
| [04_serverless_hardening.md](./04_serverless_hardening.md) | **서버리스 보안 강화 — SAST·런타임 보호·자동 감사** — 전통적 보안: |
| [05_serverless_incident_response.md](./05_serverless_incident_response.md) | **서버리스 사고 대응** — 1. 준비 (Preparation) |
| [06_serverless_ctf_lab.md](./06_serverless_ctf_lab.md) | **서버리스 보안 CTF 실습 랩** — pip install boto3 aws-lambda-powertools moto requests |

## 🎯 학습 목표

- AWS Lambda 함수 공격 기법 원리 및 실전 공격/방어 기법 습득
- 서버리스 인젝션 — 이벤트 주입·의존성 공격·탐지 원리 및 실전 공격/방어 기법 습득
- 서버리스 IAM 권한 남용 — 역할 체인·권한 상승·분석 CLI 원리 및 실전 공격/방어 기법 습득
- 서버리스 보안 강화 — SAST·런타임 보호·자동 감사 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 53 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
