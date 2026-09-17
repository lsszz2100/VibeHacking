# 38. 클라우드 네이티브 보안 (Cloud_Native_Security)

> 🌩️ **VibeHacking 교재 섹션 38**
> - **CLI 학습**: `python3 vhack.py study 38`
> - **연계 실습 랩**: [Lab 04: 클라우드/컨테이너 보안 랩](../labs/), [Lab 10: Kubernetes & 컨테이너 보안 랩](../labs/)

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_cloud_native_threat_model.md](./01_cloud_native_threat_model.md) | **Cloud Native 보안 위협 모델** — Cloud Native 환경은 컨테이너(Docker), 오케스트레이션(Kubernetes), 마이크로서비스, CI/CD 파이프라인이 결합된 현대적 소프트웨어 배포 방식이다. 위협 모델... |
| [02_ebpf_runtime_security.md](./02_ebpf_runtime_security.md) | **eBPF 런타임 보안** — eBPF(Extended Berkeley Packet Filter)는 Linux 커널 내에서 안전한 샌드박스 프로그램을 실행할 수 있는 기술이다. 원래 네트워크 패킷 필터링을 위해 만... |
| [03_image_hardening_supply_chain.md](./03_image_hardening_supply_chain.md) | **컨테이너 이미지 강화 및 공급망 보안** — 컨테이너 이미지 강화(Image Hardening)는 Docker 이미지에 포함된 불필요한 패키지, 취약한 라이브러리, 과도한 권한 등을 제거해 공격 표면을 최소화하는 과정이다. 공급... |
| [04_cloud_native_attack_techniques.md](./04_cloud_native_attack_techniques.md) | **Cloud Native 공격 기법** — Cloud Native 공격 기법은 Kubernetes 클러스터, 컨테이너 환경, 클라우드 인프라를 목표로 하는 특화된 공격 방법론이다. 전통적인 서버 해킹과 달리 API 서버, RB... |
| [05_cloud_native_defense.md](./05_cloud_native_defense.md) | **— Cloud Native 보안 방어 체계** — Cloud Native 보안 방어 체계는 컨테이너, Kubernetes, 클라우드 인프라를 종합적으로 보호하기 위한 다층 방어 전략이다. 단일 보안 제품으로 해결할 수 없으며, 코드 ... |
| [06_cloud_native_ctf_lab.md](./06_cloud_native_ctf_lab.md) | **클라우드 네이티브 보안 CTF 랩** — 이 랩은 클라우드 네이티브 환경에서 발생하는 보안 위협을 직접 탐지하고 대응하는 실전형 CTF(Capture The Flag) 실습입니다. eBPF 기반 런타임 탐지, OPA Gate... |

## 🎯 학습 목표

- Cloud Native 보안 위협 모델 원리 및 실전 공격/방어 기법 습득
- eBPF 런타임 보안 원리 및 실전 공격/방어 기법 습득
- 컨테이너 이미지 강화 및 공급망 보안 원리 및 실전 공격/방어 기법 습득
- Cloud Native 공격 기법 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 38 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
