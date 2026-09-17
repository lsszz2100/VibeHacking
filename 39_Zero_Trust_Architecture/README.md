# 39. 제로 트러스트 (Zero_Trust_Architecture)

> 🚫 **VibeHacking 교재 섹션 39**
> - **CLI 학습**: `python3 vhack.py study 39`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_zero_trust_principles.md](./01_zero_trust_principles.md) | **Zero Trust 아키텍처 원칙** — Zero Trust(제로 트러스트)는 "절대 신뢰 없음, 항상 검증(Never Trust, Always Verify)"을 핵심 철학으로 하는 현대 보안 패러다임이다. 전통적 보안은 내... |
| [02_identity_and_device_trust.md](./02_identity_and_device_trust.md) | **신원 및 기기 신뢰 (Identity & Device Trust)** — Zero Trust에서 "신원(Identity)"은 새로운 경계선이다. 전통적 방화벽 대신, 누가(사용자 신원) 어떤 기기로(기기 신뢰) 접근하는지를 모든 접근의 기준으로 삼는다. I... |
| [03_microsegmentation_and_network.md](./03_microsegmentation_and_network.md) | **마이크로세그멘테이션과 네트워크 보안** — 마이크로세그멘테이션(Microsegmentation)은 네트워크를 매우 작은 보안 구역으로 분리하고, 각 구역 간 통신을 세밀하게 제어하는 기술이다. 전통적인 VLAN 기반 세그멘테이... |
| [04_zero_trust_implementation.md](./04_zero_trust_implementation.md) | **Zero Trust 구현 전략** — Zero Trust 구현은 하나의 제품을 설치하는 것이 아니라 보안 철학과 아키텍처의 전환이다. CISA(미국 사이버보안 인프라 보안국)는 5단계 성숙도 모델을 제시하며, 조직의 현재... |
| [05_zero_trust_maturity.md](./05_zero_trust_maturity.md) | **— Zero Trust 성숙도 평가 및 운영** — Zero Trust 성숙도 평가는 조직이 Zero Trust 원칙을 얼마나 잘 구현하고 있는지 측정하는 체계적인 프레임워크다. CISA(미국 사이버보안 인프라 보안국)의 Zero Tr... |
| [06_zero_trust_ctf_lab.md](./06_zero_trust_ctf_lab.md) | **제로 트러스트 아키텍처 CTF 랩** — 이 랩은 제로 트러스트(Zero Trust) 원칙을 실제로 구현하고 우회 취약점을 찾는 CTF 실습입니다. mTLS 인증서 기반 서비스 간 인증, 네트워크 미세분할 정책 설계, 디바이... |

## 🎯 학습 목표

- Zero Trust 아키텍처 원칙 원리 및 실전 공격/방어 기법 습득
- 신원 및 기기 신뢰 (Identity & Device Trust) 원리 및 실전 공격/방어 기법 습득
- 마이크로세그멘테이션과 네트워크 보안 원리 및 실전 공격/방어 기법 습득
- Zero Trust 구현 전략 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 39 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
