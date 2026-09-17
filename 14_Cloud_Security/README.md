# 14. 클라우드 보안 (Cloud_Security)

> ☁️ **VibeHacking 교재 섹션 14**
> - **CLI 학습**: `python3 vhack.py study 14`
> - **연계 실습 랩**: [Lab 04: 클라우드/컨테이너 보안 랩](../labs/), [Lab 10: Kubernetes & 컨테이너 보안 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_cloud_attack_vectors.md](./01_cloud_attack_vectors.md) | **클라우드 공격 벡터 완전 분석** — 클라우드 공격 벡터는 AWS, Azure, GCP 같은 클라우드 환경에서 공격자가 시스템에 침투하거나 데이터를 탈취하는 경로를 의미합니다. 전통적인 온프레미스 환경과 달리 클라우드는 ... |
| [02_aws_pentest.md](./02_aws_pentest.md) | **AWS 침투 테스트 완전 가이드** — AWS 침투 테스트는 Amazon Web Services 클라우드 환경에서 잘못된 IAM 설정, 공개된 S3 버킷, 취약한 EC2 인스턴스 등을 합법적으로 탐색하는 보안 활동입니다. ... |
| [03_cloud_security_checklist.md](./03_cloud_security_checklist.md) | **클라우드 보안 체크리스트 & 아키텍처** — 클라우드 보안 체크리스트는 AWS/Azure/GCP 환경에서 흔히 발생하는 보안 설정 오류를 체계적으로 점검하는 목록입니다. "공동 책임 모델(Shared Responsibility ... |
| [04_GCP_Azure_Pentest.md](./04_GCP_Azure_Pentest.md) | **GCP 및 Azure 침투테스트** — GCP(Google Cloud Platform)와 Microsoft Azure는 AWS와 함께 전 세계 클라우드 시장을 이끄는 주요 플랫폼입니다. 각 플랫폼은 고유한 인증 체계, 권한... |
| [05_cloud_lateral_movement.md](./05_cloud_lateral_movement.md) | **클라우드 횡이동 — 계정 피버팅·서비스 간 이동·탐지** — 클라우드 횡이동(Cloud Lateral Movement)은 초기 침투 후 공격자가 하나의 클라우드 서비스에서 다른 서비스로 권한을 확장하며 이동하는 기법입니다. 온프레미스에서 서버에... |
| [06_cloud_security_ctf_lab.md](./06_cloud_security_ctf_lab.md) | **클라우드 보안 CTF 실습 랩** — version: "3.9" |

## 🎯 학습 목표

- 클라우드 공격 벡터 완전 분석 원리 및 실전 공격/방어 기법 습득
- AWS 침투 테스트 완전 가이드 원리 및 실전 공격/방어 기법 습득
- 클라우드 보안 체크리스트 & 아키텍처 원리 및 실전 공격/방어 기법 습득
- GCP 및 Azure 침투테스트 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 14 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
