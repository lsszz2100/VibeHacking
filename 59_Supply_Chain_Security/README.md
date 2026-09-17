# 59. 공급망 보안 (Supply_Chain_Security)

> 🔗 **VibeHacking 교재 섹션 59**
> - **CLI 학습**: `python3 vhack.py study 59`
> - **연계 실습 랩**: [Lab 12: CI/CD & 소프트웨어 공급망 침투 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_supply_chain_fundamentals.md](./01_supply_chain_fundamentals.md) | **소프트웨어 공급망 보안 기초** — 소프트웨어 공급망 보안은 개발자가 사용하는 오픈소스 라이브러리부터 빌드 도구, CI/CD 파이프라인, 배포 시스템에 이르기까지 소프트웨어가 만들어지고 전달되는 전체 과정을 공격으로부터... |
| [02_software_supply_chain_attacks.md](./02_software_supply_chain_attacks.md) | **소프트웨어 공급망 공격 분석** — 소프트웨어 공급망 공격은 최종 타겟을 직접 공격하는 대신, 타겟이 신뢰하는 소프트웨어 공급업체나 오픈소스 라이브러리를 먼저 침해하여 악성 코드를 심는 간접 공격 방식이다. 타겟 회사의... |
| [03_dependency_confusion.md](./03_dependency_confusion.md) | **의존성 혼란 공격 (Dependency Confusion)** — 의존성 혼란은 기업이 내부적으로만 사용하는 비공개 패키지 이름을 공개 패키지 레지스트리(PyPI, npm 등)에 더 높은 버전 번호로 업로드하는 공격이다. 빌드 도구가 내부 레지스트리... |
| [04_build_integrity.md](./04_build_integrity.md) | **빌드 무결성 검증 (Build Integrity Verification)** — 빌드 무결성은 소프트웨어가 선언된 소스코드에서 변조 없이 정확하게 만들어졌다는 것을 암호학적으로 증명하는 속성이다. 공격자가 빌드 서버나 배포 서버에 침투해 바이너리를 변조하더라도, ... |
| [05_supply_chain_defense.md](./05_supply_chain_defense.md) | **공급망 방어 전략 (Supply Chain Defense Strategy)** — 공급망 방어 전략은 소프트웨어 개발 및 배포 파이프라인 전반에 걸쳐 공격을 예방·탐지·대응하기 위한 체계적 접근 방식이다. 단순한 취약점 패치를 넘어 SBOM 관리, 의존성 검증, 빌... |
| [06_supply_chain_ctf_lab.md](./06_supply_chain_ctf_lab.md) | **공급망 보안 CTF 실습 랩** — 소프트웨어 공급망은 하나의 앱이 만들어지기까지 사용되는 모든 구성 요소의 연쇄다. 직접 작성한 코드만이 아니라, 외부에서 가져온 라이브러리, 빌드 도구, CI/CD 파이프라인까지 포함된다. |

## 🎯 학습 목표

- 소프트웨어 공급망 보안 기초 원리 및 실전 공격/방어 기법 습득
- 소프트웨어 공급망 공격 분석 원리 및 실전 공격/방어 기법 습득
- 의존성 혼란 공격 (Dependency Confusion) 원리 및 실전 공격/방어 기법 습득
- 빌드 무결성 검증 (Build Integrity Verification) 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 59 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
