# 49. 레드팀 인프라 (Red_Team_Infrastructure)

> 🏰 **VibeHacking 교재 섹션 49**
> - **CLI 학습**: `python3 vhack.py study 49`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_c2_frameworks.md](./01_c2_frameworks.md) | **C2 프레임워크 (Command & Control Frameworks)** — C2(Command & Control) 프레임워크는 레드팀이 침투한 시스템들을 원격으로 제어하고 관리하는 인프라다. 공격자 관점에서는 감염된 피해 시스템(에이전트)이 C2 서버에 주기... |
| [02_domain_fronting_redirectors.md](./02_domain_fronting_redirectors.md) | **도메인 프론팅 및 리다이렉터 구축** — 도메인 프론팅(Domain Fronting)은 CDN(콘텐츠 전송 네트워크)의 구조적 특성을 이용해 실제 C2 서버 위치를 숨기는 기법이다. 리다이렉터(Redirector)는 에이전트... |
| [03_opsec_infrastructure.md](./03_opsec_infrastructure.md) | **OPSEC 인프라 관리** — OPSEC(Operations Security, 작전 보안)은 레드팀 작전 중 공격자(레드팀)의 신원, 위치, 방법론이 방어자(블루팀)에게 노출되지 않도록 관리하는 원칙이다. 실제 A... |
| [04_red_team_automation.md](./04_red_team_automation.md) | **레드팀 자동화** — 수동 레드팀: |
| [05_red_team_detection_evasion.md](./05_red_team_detection_evasion.md) | **레드팀 인프라 탐지 우회 (방어자 관점)** — 블루팀 입장: |
| [06_red_team_infra_ctf_lab.md](./06_red_team_infra_ctf_lab.md) | **레드팀 인프라 CTF 실습 랩** — pip install requests dnspython paramiko cryptography |

## 🎯 학습 목표

- C2 프레임워크 (Command & Control Frameworks) 원리 및 실전 공격/방어 기법 습득
- 도메인 프론팅 및 리다이렉터 구축 원리 및 실전 공격/방어 기법 습득
- OPSEC 인프라 관리 원리 및 실전 공격/방어 기법 습득
- 레드팀 자동화 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 49 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
