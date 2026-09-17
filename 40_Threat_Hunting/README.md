# 40. 위협 헌팅 (Threat_Hunting)

> 🎣 **VibeHacking 교재 섹션 40**
> - **CLI 학습**: `python3 vhack.py study 40`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_threat_hunting_methodology.md](./01_threat_hunting_methodology.md) | **위협 헌팅 방법론 (Threat Hunting Methodology)** — 위협 헌팅(Threat Hunting)은 기존 SIEM 알림이나 AV 탐지를 기다리지 않고, 보안 분석가가 직접 가설을 세우고 데이터를 분석해 숨겨진 위협을 능동적으로 찾아내는 활동이... |
| [02_mitre_attack_hunting.md](./02_mitre_attack_hunting.md) | **MITRE ATT&CK 기반 위협 헌팅** — MITRE ATT&CK는 실제 관찰된 공격자의 전술(Tactics)·기법(Techniques)·세부 기법(Sub-techniques)을 정리한 공개 지식 베이스다. 위협 헌팅에서는 이... |
| [03_hunting_queries_kql_spl.md](./03_hunting_queries_kql_spl.md) | **헌팅 쿼리 — KQL 및 SPL 실전 가이드** — KQL(Kusto Query Language)은 Microsoft Azure Sentinel/Log Analytics에서 사용하는 쿼리 언어이고, SPL(Search Processin... |
| [04_automated_threat_hunting.md](./04_automated_threat_hunting.md) | **자동화 위협 헌팅** — 자동화 위협 헌팅은 수동 분석가 중심의 헌팅을 자동화 파이프라인, 머신러닝, 위협 인텔리전스 플랫폼과 결합해 확장하는 접근 방식이다. OpenCTI(위협 인텔리전스 관리), MISP(... |
| [05_threat_hunting_program.md](./05_threat_hunting_program.md) | **— 위협 헌팅 프로그램 운영** — 위협 헌팅 프로그램은 일회성 헌팅 활동을 조직적·반복적·측정 가능한 보안 운영 체계로 발전시킨 것이다. 헌팅 팀 구성, 인텔리전스 수집 체계, 가설 관리 프로세스, 결과 피드백 루프,... |
| [06_threat_hunting_ctf_lab.md](./06_threat_hunting_ctf_lab.md) | **위협 헌팅 CTF 랩** — 이 랩은 실제 공격자의 행동 패턴을 로그에서 직접 찾아내는 위협 헌팅(Threat Hunting) CTF 실습입니다. KQL/SPL을 활용한 PowerShell 다운로드 크래들 탐지,... |

## 🎯 학습 목표

- 위협 헌팅 방법론 (Threat Hunting Methodology) 원리 및 실전 공격/방어 기법 습득
- MITRE ATT&CK 기반 위협 헌팅 원리 및 실전 공격/방어 기법 습득
- 헌팅 쿼리 — KQL 및 SPL 실전 가이드 원리 및 실전 공격/방어 기법 습득
- 자동화 위협 헌팅 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 40 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
