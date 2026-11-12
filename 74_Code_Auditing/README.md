# 74. 코드 감사 (Code_Auditing)

> 📖 **VibeHacking 교재 섹션 74**
> - **CLI 학습**: `python3 vhack.py study 74`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_code_audit_fundamentals.md](./01_code_audit_fundamentals.md) | **코드 감사(Code Auditing) 기초** — 코드 감사(Code Auditing)란 소프트웨어의 소스코드를 체계적으로 검토하여 보안 취약점, 논리적 오류, 설계 결함을 찾아내는 과정입니다. 병원에서 환자의 X-... |
| [02_vulnerability_patterns.md](./02_vulnerability_patterns.md) | **취약점 코드 패턴 식별** — 코드 감사에서 가장 중요한 기술은 위험한 패턴을 눈으로 알아보는 능력입니다. 숙련된 감사자는 코드를 읽을 때 특정 함수나 구조를 보는 순간 "여기 위험할 수 있다"고... |
| [03_static_analysis_tools.md](./03_static_analysis_tools.md) | **정적 분석 도구 활용** — 정적 분석(Static Analysis)은 프로그램을 실행하지 않고 소스코드를 분석하여 취약점을 찾는 기법입니다. 코드를 직접 읽는 수동 리뷰보다 빠르게 넓은 범위를... |
| [04_manual_review_techniques.md](./04_manual_review_techniques.md) | **수동 코드 리뷰 기법** — 정적 분석 도구는 강력하지만 한계가 있습니다. 비즈니스 로직 취약점, 접근 제어 오류, 복잡한 다단계 인증 우회 같은 문제는 도구가 잘 잡지 못합니다. 사람의 눈과 추론이 필요한 이유... |
| [05_sast_cicd_integration.md](./05_sast_cicd_integration.md) | **CI/CD 파이프라인에 SAST 통합** — SAST(Static Application Security Testing)를 CI/CD 파이프라인에 통합하면 코드가 배포되기 전에 자동으로 보안 검사를 수행할 수 있... |
| [06_code_audit_ctf_lab.md](./06_code_audit_ctf_lab.md) | **CTF 스타일 코드 감사 실습 랩** — 이 랩은 CTF(Capture The Flag) 방식으로 실제 취약점을 발견하고 분석하는 실습입니다. 세 가지 시나리오를 통해 코드 감사의 전체 흐름 — 취약한 코드 발견 → 분석 →... |

## 🎯 학습 목표

- 코드 감사(Code Auditing) 기초 원리 및 실전 공격/방어 기법 습득
- 취약점 코드 패턴 식별 원리 및 실전 공격/방어 기법 습득
- 정적 분석 도구 활용 원리 및 실전 공격/방어 기법 습득
- 수동 코드 리뷰 기법 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 74 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
