# 18. 데브섹옵스 (DevSecOps)

> ⚙️ **VibeHacking 교재 섹션 18**
> - **CLI 학습**: `python3 vhack.py study 18`
> - **연계 실습 랩**: [Lab 12: CI/CD & 소프트웨어 공급망 침투 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_devsecops_fundamentals.md](./01_devsecops_fundamentals.md) | **DevSecOps 핵심 원칙 및 보안 자동화** — DevSecOps는 개발(Dev)·보안(Sec)·운영(Ops)을 통합하는 문화와 방법론으로, 개발 초기부터 보안을 자동화된 파이프라인에 내재화합니다. 기존에는 개발 완료 후 보안 검토... |
| [02_container_security.md](./02_container_security.md) | **컨테이너 보안 완전 가이드** — 컨테이너(Docker, Kubernetes)는 현대 인프라의 표준이지만, 잘못된 설정은 컨테이너 탈출(Host 권한 획득), 비밀 키 노출, 이미지 취약점 등 심각한 보안 위협을 만들... |
| [03_github_actions_security.md](./03_github_actions_security.md) | **GitHub Actions & CI/CD 파이프라인 보안** — CI/CD(지속적 통합/배포) 파이프라인은 코드 커밋부터 프로덕션 배포까지 자동화된 빌드·테스트·배포 체계입니다. GitHub Actions 같은 파이프라인은 소스코드, API 키, ... |
| [04_Secret_Detection_and_SBOM.md](./04_Secret_Detection_and_SBOM.md) | **시크릿 탐지 및 SBOM(소프트웨어 자재 명세)** — 시크릿 탐지는 소스코드, git 히스토리, 컨테이너 이미지에 숨겨진 API 키, 패스워드, 인증서 등을 자동으로 찾는 활동입니다. SBOM(Software Bill of Materia... |
| [05_supply_chain_security.md](./05_supply_chain_security.md) | **공급망 보안 — 의존성 공격·SLSA·서명 검증** — 소프트웨어 공급망 보안은 우리가 사용하는 오픈소스 라이브러리, 빌드 도구, CI/CD 시스템 등 개발 생태계 전체의 신뢰성을 보장하는 분야입니다. SolarWinds(2020)·XZ ... |
| [06_devsecops_ctf_lab.md](./06_devsecops_ctf_lab.md) | **DevSecOps CTF 실습 랩** — docker network create devsecops-lab --subnet=172.31.0.0/24 |

## 🎯 학습 목표

- DevSecOps 핵심 원칙 및 보안 자동화 원리 및 실전 공격/방어 기법 습득
- 컨테이너 보안 완전 가이드 원리 및 실전 공격/방어 기법 습득
- GitHub Actions & CI/CD 파이프라인 보안 원리 및 실전 공격/방어 기법 습득
- 시크릿 탐지 및 SBOM(소프트웨어 자재 명세) 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 18 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
