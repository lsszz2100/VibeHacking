# 13. SOC/블루팀 (SOC_Blue_Team)

> 🛡️ **VibeHacking 교재 섹션 13**
> - **CLI 학습**: `python3 vhack.py study 13`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_soc_fundamentals.md](./01_soc_fundamentals.md) | **SOC 핵심 개념 및 Blue Team 기초** — SOC(Security Operations Center)는 조직의 IT 시스템을 24시간 모니터링하고 사이버 위협에 대응하는 전담 보안 팀입니다. 공격자(Red Team)와 반대로, ... |
| [02_splunk_siem_analysis.md](./02_splunk_siem_analysis.md) | **Splunk & SIEM 실전 분석** — SIEM(Security Information and Event Management)은 조직 전체의 로그를 수집·분석하여 보안 위협을 실시간으로 탐지하는 플랫폼입니다. Splunk는 ... |
| [03_threat_hunting.md](./03_threat_hunting.md) | **위협 헌팅 & 랜섬웨어 침해 대응** — 위협 헌팅(Threat Hunting)은 "공격자가 이미 내부에 있다"는 가정 하에 탐지 시스템이 놓친 침해 흔적을 사람이 능동적으로 찾는 활동입니다. 알림 대기(수동 방어)와 달리,... |
| [04_qradar_xdr_blue_team.md](./04_qradar_xdr_blue_team.md) | **IBM QRadar & Azure Sentinel KQL & XDR 블루팀 실전** — IBM QRadar는 기업 환경에서 가장 많이 사용되는 엔터프라이즈 SIEM 중 하나로, 수십만 개의 이벤트를 실시간으로 수집·상관 분석합니다. Microsoft Azure Senti... |
| [05_detection_engineering.md](./05_detection_engineering.md) | **탐지 엔지니어링 — Sigma·MITRE ATT&CK 기반 룰 개발** — 탐지 엔지니어링(Detection Engineering)은 공격 기법을 분석하고 이를 탐지하는 규칙과 로직을 체계적으로 개발하는 전문 분야입니다. 단순히 알림 모니터링을 넘어, 새로운... |
| [06_soc_ctf_lab.md](./06_soc_ctf_lab.md) | **SOC/블루팀 CTF 실습 랩** — 이 랩은 SIEM 분석, IOC 추출, 래터럴 무브먼트 탐지 등 실제 SOC 환경에서 마주치는 시나리오를 CTF 형식으로 재현합니다. Splunk SPL 쿼리 작성부터 알림 룰 설계까... |

## 🎯 학습 목표

- SOC 핵심 개념 및 Blue Team 기초 원리 및 실전 공격/방어 기법 습득
- Splunk & SIEM 실전 분석 원리 및 실전 공격/방어 기법 습득
- 위협 헌팅 & 랜섬웨어 침해 대응 원리 및 실전 공격/방어 기법 습득
- IBM QRadar & Azure Sentinel KQL & XDR 블루팀 실전 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 13 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
