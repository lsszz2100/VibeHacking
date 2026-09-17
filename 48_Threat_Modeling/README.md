# 48. 위협 모델링 (Threat_Modeling)

> 🗂️ **VibeHacking 교재 섹션 48**
> - **CLI 학습**: `python3 vhack.py study 48`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_stride_methodology.md](./01_stride_methodology.md) | **STRIDE 위협 모델링 방법론** — STRIDE는 소프트웨어 시스템을 설계할 때 발생할 수 있는 보안 위협을 6가지 범주로 체계적으로 찾아내는 프레임워크다. Microsoft가 개발했으며 현재 업계 표준으로 사용된다. ... |
| [02_pasta_dread_attack_trees.md](./02_pasta_dread_attack_trees.md) | **PASTA, DREAD, Attack Trees, Kill Chain** — 이 세 가지는 보안 위협을 분석하고 우선순위를 결정하는 보완적인 방법론이다. PASTA는 비즈니스 영향을 중심으로 한 7단계 위협 분석 프로세스, DREAD는 위협의 심각도를 수치화하... |
| [03_threat_modeling_tools.md](./03_threat_modeling_tools.md) | **위협 모델링 도구 및 자동화** — 위협 모델링 도구는 DFD(데이터 흐름 다이어그램) 작성과 STRIDE 위협 분석을 자동화하는 소프트웨어다. 수작업으로 하던 위협 분류와 완화 방법 도출을 자동화해 시간을 단축하고, ... |
| [04_threat_modeling_practice.md](./04_threat_modeling_practice.md) | **위협 모델링 실전 연습** — 이론으로 배운 STRIDE, DREAD, Attack Trees를 실제 시스템에 적용하는 실습이다. 전자상거래 사이트, 모바일 뱅킹 앱, Kubernetes 클러스터 등 현실적인 시스... |
| [05_ai_system_threat_modeling.md](./05_ai_system_threat_modeling.md) | **AI 시스템 위협 모델링** — AI 시스템은 전통적인 소프트웨어와 다른 특유의 취약점을 가진다. 프롬프트 인젝션, 학습 데이터 오염, 모델 추출, 적대적 예제 등은 기존 보안 도구로 탐지하기 어렵다. AI 시스템 ... |
| [06_threat_modeling_ctf_lab.md](./06_threat_modeling_ctf_lab.md) | **위협 모델링 CTF 실습 랩** — pip install matplotlib networkx graphviz |

## 🎯 학습 목표

- STRIDE 위협 모델링 방법론 원리 및 실전 공격/방어 기법 습득
- PASTA, DREAD, Attack Trees, Kill Chain 원리 및 실전 공격/방어 기법 습득
- 위협 모델링 도구 및 자동화 원리 및 실전 공격/방어 기법 습득
- 위협 모델링 실전 연습 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 48 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
