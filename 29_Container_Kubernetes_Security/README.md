# 29. 컨테이너/쿠버네티스 (Container_Kubernetes_Security)

> 🐳 **VibeHacking 교재 섹션 29**
> - **CLI 학습**: `python3 vhack.py study 29`
> - **연계 실습 랩**: [Lab 04: 클라우드/컨테이너 보안 랩](../labs/), [Lab 10: Kubernetes & 컨테이너 보안 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_docker_security.md](./01_docker_security.md) | **Docker 보안: 컨테이너 탈출 및 취약점 분석** — Docker는 애플리케이션을 "컨테이너"라는 격리된 환경에서 실행하는 기술이다. 가상 머신(VM)과 달리 OS 커널을 호스트와 공유하기 때문에 훨씬 가볍지만, 이 공유 구조가 보안상 ... |
| [02_kubernetes_attack.md](./02_kubernetes_attack.md) | **Kubernetes 공격: 클러스터 침투 및 권한 탈취** — Kubernetes(K8s)는 컨테이너를 대규모로 관리하는 오케스트레이션 플랫폼이다. 수십에서 수천 개의 컨테이너를 자동으로 배포·확장·관리한다. Kubernetes 보안은 클러스터 ... |
| [03_container_escape.md](./03_container_escape.md) | **컨테이너 탈출 심화: 커널 취약점 및 네임스페이스 탈출** — 컨테이너 탈출(Container Escape)은 컨테이너 내부에서 격리 경계를 돌파하여 호스트 시스템에 접근하는 기법이다. 컨테이너는 완전한 격리를 제공하지 않으며, 잘못된 설정이나 ... |
| [04_Service_Mesh_API_Gateway_Attacks.md](./04_Service_Mesh_API_Gateway_Attacks.md) | **서비스 메시 및 API 게이트웨이 공격** — 마이크로서비스 환경에서 수십~수백 개의 서비스가 서로 통신할 때, 각 서비스마다 인증·암호화·재시도 로직을 구현하기는 어렵다. 서비스 메시(Istio, Linkerd)는 이를 인프라 ... |
| [05_kubernetes_rbac_audit.md](./05_kubernetes_rbac_audit.md) | **Kubernetes RBAC 감사 — 권한 분석·과도한 권한 탐지·정책 강화** — RBAC(Role-Based Access Control)은 Kubernetes에서 "누가 어떤 리소스에 어떤 작업을 할 수 있는가"를 제어하는 권한 관리 시스템이다. RBAC이 잘못 ... |
| [06_container_ctf_lab.md](./06_container_ctf_lab.md) | **컨테이너 & 쿠버네티스 보안 CTF 실습 랩** — version: "3.9" |

## 🎯 학습 목표

- Docker 보안: 컨테이너 탈출 및 취약점 분석 원리 및 실전 공격/방어 기법 습득
- Kubernetes 공격: 클러스터 침투 및 권한 탈취 원리 및 실전 공격/방어 기법 습득
- 컨테이너 탈출 심화: 커널 취약점 및 네임스페이스 탈출 원리 및 실전 공격/방어 기법 습득
- 서비스 메시 및 API 게이트웨이 공격 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 29 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
