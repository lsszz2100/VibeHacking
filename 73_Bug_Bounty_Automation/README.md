# 73. 버그 바운티 자동화 (Bug_Bounty_Automation)

> 🤑 **VibeHacking 교재 섹션 73**
> - **CLI 학습**: `python3 vhack.py study 73`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_bug_bounty_fundamentals.md](./01_bug_bounty_fundamentals.md) | **버그바운티 기초: 해커로 돈 버는 합법적인 방법** — 버그바운티(Bug Bounty)는 기업이 외부 보안 연구자들에게 자사 시스템의 취약점을 찾아 신고해 달라고 공개적으로 의뢰하는 프로그램입니다. 쉽게 말하면 "우리 서비스에서 버그를 찾... |
| [02_recon_automation.md](./02_recon_automation.md) | **정찰(Reconnaissance) 자동화: 공격 전 지도 그리기** — 버그바운티에서 성공적인 헌터와 그렇지 않은 헌터의 가장 큰 차이는 정찰의 깊이입니다. 빙산처럼, 기업의 공격 표면(Attack Surface) 중 눈에 보이는 부분은 전체의 10%에 ... |
| [03_vulnerability_scanning.md](./03_vulnerability_scanning.md) | **취약점 스캐닝 자동화: Nuclei와 Python으로 빠르게 버그 찾기** — Nuclei는 ProjectDiscovery에서 만든 오픈소스 취약점 스캐너입니다. 핵심 특징은 템플릿(Template) 기반이라는 점입니다. YAML 파일로 취약점 탐지 로직을 정의... |
| [04_report_writing.md](./04_report_writing.md) | **버그바운티 리포트 작성법: 돈을 받는 리포트 vs 거절당하는 리포트** — 버그바운티에서 많은 초보자가 빠지는 함정이 있습니다. 실제로 취약점을 발견했음에도 불구하고 리포트가 엉망이어서 "Informative"(보상 없음) 또는 "N/A"(관련 없음)로 처리... |
| [05_advanced_techniques.md](./05_advanced_techniques.md) | **고급 버그바운티 기법: 취약점 체이닝과 API 퍼징** — 단일 취약점으로는 "Low" 혹은 "Informational" 수준에 그치는 버그들을 조합하면 "Critical"이 되는 경우가 있습니다. 이것이 취약점 체이닝(Vulnerabilit... |
| [06_bug_bounty_ctf_lab.md](./06_bug_bounty_ctf_lab.md) | **버그바운티 CTF 실습 랩: 직접 해보는 취약점 탐지** — 이 문서는 실제 버그바운티 시나리오를 모방한 3개의 실습 문제를 제공합니다. 각 실습은 Docker 환경에서 실행 가능하며, 목표 → 힌트 → 상세 풀이 순서로 구성되어 있습니다. |

## 🎯 학습 목표

- 버그바운티 기초: 해커로 돈 버는 합법적인 방법 원리 및 실전 공격/방어 기법 습득
- 정찰(Reconnaissance) 자동화: 공격 전 지도 그리기 원리 및 실전 공격/방어 기법 습득
- 취약점 스캐닝 자동화: Nuclei와 Python으로 빠르게 버그 찾기 원리 및 실전 공격/방어 기법 습득
- 버그바운티 리포트 작성법: 돈을 받는 리포트 vs 거절당하는 리포트 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 73 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
