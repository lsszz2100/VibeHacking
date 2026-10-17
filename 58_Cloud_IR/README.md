# 58. 클라우드 사고 대응 (Cloud_IR)

> 🌤️ **VibeHacking 교재 섹션 58**
> - **CLI 학습**: `python3 vhack.py study 58`
> - **연계 실습 랩**: [Lab 43: 클라우드 사고 대응 & 위협 헌팅 랩](../labs/43_cloud_incident_response_lab/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_cloud_ir_fundamentals.md](./01_cloud_ir_fundamentals.md) | **클라우드 사고 대응(IR) 기초** — 클라우드 사고 대응(Cloud Incident Response, Cloud IR)은 AWS·Azure·GCP 같은 클라우드 환경에서 발생한 보안 침해 사고를 탐지하고, 원인을 분석하며... |
| [02_aws_forensics.md](./02_aws_forensics.md) | **AWS 포렌식** — AWS 포렌식은 Amazon Web Services 환경에서 발생한 보안 사고의 증거를 수집하고 분석하는 기술이다. 물리적 서버 대신 CloudTrail(API 감사 로그), VPC ... |
| [03_azure_forensics.md](./03_azure_forensics.md) | **Azure 포렌식** — Azure 포렌식은 Microsoft Azure 클라우드 환경에서 발생한 보안 사고를 조사하는 기술이다. Azure Activity Log, Microsoft Entra ID(구 Az... |
| [04_gcp_forensics.md](./04_gcp_forensics.md) | **GCP 포렌식** — GCP 포렌식은 Google Cloud Platform 환경에서 발생한 보안 사고를 조사하는 기술이다. Cloud Audit Logs, Cloud Logging, Security Co... |
| [05_cloud_threat_hunting.md](./05_cloud_threat_hunting.md) | **클라우드 위협 헌팅** — 클라우드 위협 헌팅은 자동화된 보안 탐지 시스템이 놓쳤을 수 있는 고도화된 공격자를 사람이 직접 능동적으로 찾아내는 활동이다. 경보가 없어도 "혹시 공격자가 이미 들어와 있지 않을까?... |
| [06_cloud_ir_ctf_lab.md](./06_cloud_ir_ctf_lab.md) | **클라우드 침해 대응 CTF 실습 랩** — 이 실습을 마치면 다음을 할 수 있다: |
| [07_enterprise_cloudtrail_and_vpc_flow_logs_forensics_deepdive.md](./07_enterprise_cloudtrail_and_vpc_flow_logs_forensics_deepdive.md) | **클라우드 침해사고 대응(IR) 심층 분석: CloudTrail 감사, STS 자격증명 유출, VPC Flow Logs C2 상관분석 및 SOAR 자동 격리** — CloudTrail 관리 감사 로그 분석, STS 세션 토큰 유출 포렌식, VPC Flow Logs C2 비콘 상관분석, GuardDuty 연동 자동화 SOAR 봉쇄 |

## 🎯 학습 목표

- 클라우드 사고 대응(IR) 기초 원리 및 실전 공격/방어 기법 습득
- AWS 포렌식 원리 및 실전 공격/방어 기법 습득
- Azure 포렌식 원리 및 실전 공격/방어 기법 습득
- GCP 포렌식 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 58 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
