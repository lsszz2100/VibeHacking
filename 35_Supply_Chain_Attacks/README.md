# 35 — Supply Chain Attacks

## 섹션 개요

공급망 공격(Supply Chain Attack)은 최종 목표 시스템을 직접 공격하는 대신, 그 시스템이 신뢰하는 소프트웨어·하드웨어·서비스 제공자를 먼저 침해한 후 신뢰 관계를 통해 피해를 확산시키는 공격 방식이다. 단일 침해 지점으로 수천~수만 개의 다운스트림 조직을 동시에 공격할 수 있어 공격 대비 피해 규모 비율이 극단적으로 높다.

이 섹션은 실전 공격 벡터 분석, 탐지 방법론, 방어 아키텍처, 그리고 직접 실행 가능한 Python 도구를 다룬다.

---

## 공급망 공격 분류

### 1. 소프트웨어 공급망 공격 (Software Supply Chain)

소프트웨어 개발·배포 파이프라인의 어느 단계든 침해 대상이 될 수 있다.

#### 1-1. 패키지 저장소 공격
- **타이포스쿼팅(Typosquatting)**: 인기 패키지와 유사한 이름으로 악성 패키지 배포
  - 예: `requests` → `requets`, `numpy` → `nunpy`
- **의존성 혼동(Dependency Confusion)**: 내부 패키지 이름을 공개 저장소에 선점 등록
  - 패키지 관리자가 외부 저장소를 내부보다 우선 조회하는 특성 악용
- **계정 탈취**: 정상 패키지 관리자의 자격증명 탈취 후 악성 업데이트 배포
- **악성 코드 삽입(Code Injection)**: 정상 패키지 빌드 과정에 백도어 삽입

#### 1-2. 빌드 시스템 공격
- CI/CD 파이프라인 침해 (GitHub Actions, Jenkins, GitLab CI)
- 빌드 캐시 포이즈닝
- 악성 빌드 스크립트 주입

#### 1-3. 코드 저장소 공격
- 오픈소스 기여자 위장 (XZ Utils 사례)
- Pull Request를 통한 악성 코드 삽입
- 비밀 키/토큰 하드코딩 후 제거 위장

---

### 2. 하드웨어 공급망 공격 (Hardware Supply Chain)

#### 2-1. 하드웨어 임플란트
- 제조 과정에서 메인보드/칩에 스파이 칩 삽입
- 네트워크 장비 내 백도어 하드웨어 (Bloomberg Supermicro 보도 기반)
- USB 케이블·저장장치에 숨겨진 악성 컨트롤러 (O.MG Cable 등)

#### 2-2. 펌웨어 공격
- 펌웨어 서명 검증 우회
- UEFI/BIOS 레벨 루트킷 (LoJax, MosaicRegressor 등)
- 네트워크 장비 펌웨어 변조

#### 2-3. SBOM 위협
- 부품 표준 인증서 위조
- 불량 부품(Counterfeit Components) 삽입
- 공급자 이중 생산(Gray Market) 문제

---

### 3. 서비스 공급망 공격 (Service Supply Chain)

#### 3-1. MSP(관리형 서비스 제공자) 공격
- SolarWinds Orion: 업데이트 서버 침해로 18,000개 조직 감염
- Kaseya VSA: 랜섬웨어 배포를 위한 MSP 인프라 침해

#### 3-2. CDN·서드파티 스크립트 공격
- Polyfill.io: CDN 서비스 인수 후 악성 스크립트 주입
- Magecart: 결제 페이지에 카드 스키머 삽입

#### 3-3. 클라우드 서비스 공격
- OAuth 토큰 탈취를 통한 SaaS 연동 서비스 침해
- 클라우드 IAM 역할 체인 악용

---

## 실습 환경

### 필수 도구

```bash
# Python 환경 (3.10+ 필수)
python3 --version  # 3.10 이상 확인

# 패키지 설치
pip install httpx requests rich packaging semver yara-python

# 오픈소스 도구
# syft — SBOM 생성
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# grype — 취약점 스캐너
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# cosign — 컨테이너 서명 검증
brew install cosign  # macOS
# 또는
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# in-toto 검증
pip install in-toto
```

### 실습 격리 환경

```bash
# Docker 기반 격리 환경
docker run -it --rm \
  --network none \
  python:3.11-slim bash

# 가상환경 분리
python3 -m venv /tmp/supply-chain-lab
source /tmp/supply-chain-lab/bin/activate
```

### 주의사항

- 모든 악성 패키지 분석은 격리된 환경(샌드박스, VM)에서 실행
- 실제 공격 재현 실험은 허가된 테스트 환경에서만 수행
- 발견된 악성 패키지는 즉시 저장소 보안팀에 신고

---

## 실제 사례 요약

### SolarWinds Orion (2020)

- **공격자**: Cozy Bear (APT29, SVR)
- **방법**: SolarWinds 빌드 서버 침해 → Orion 업데이트에 SUNBURST 백도어 삽입
- **피해**: 미국 재무부·국무부·NSA 등 18,000개 이상 조직
- **특징**: 14개월 이상 탐지 회피, 코드 서명 정상 통과

### XZ Utils CVE-2024-3094 (2024)

- **공격자**: "Jia Tan" (미상, 국가 지원 의혹)
- **방법**: 2년간 오픈소스 기여자로 신뢰 구축 → liblzma에 백도어 삽입 → systemd-sshd SSH 인증 우회
- **피해**: Debian/Fedora 테스팅 브랜치 배포, 정식 릴리즈 전 Andres Freund가 발견
- **특징**: 빌드 스크립트(configure.ac, Makefile.am)에 오브젝트 파일 주입

### 3CX Desktop App (2023)

- **공격자**: Lazarus Group (북한)
- **방법**: Trading Technologies 소프트웨어 공급망 침해 → 3CX 빌드 환경 감염 → Windows/Mac 앱에 ICONIC 백도어 삽입
- **피해**: 전 세계 3CX 고객사 (600,000개 기업)
- **특징**: 이중 공급망 공격 (upstream → downstream)

### Polyfill.io (2024)

- **공격자**: 중국 기업 Funnull이 cdn.polyfill.io 도메인 인수
- **방법**: CDN 서비스 인수 → 방문자 기기에 맞춤형 악성 스크립트 주입
- **피해**: 100,000개 이상 웹사이트 (Hulu, Mercedes-Benz 등)
- **특징**: 모바일 기기 및 특정 시간대에만 페이로드 활성화

---

## 파일 구성

| 파일 | 내용 |
|------|------|
| `01_software_supply_chain.md` | 패키지 저장소 공격, SolarWinds/XZ Utils 분석, SLSA/Sigstore, Python 스캐너 |
| `02_build_and_ci_poisoning.md` | CI/CD 파이프라인 침해, 빌드 환경 공격, Python 감사 도구 |
| `03_hardware_and_firmware_supply_chain.md` | 하드웨어 임플란트, 펌웨어 공격, SBOM, Python 검증기 |
| `04_detection_and_defense.md` | 탐지 기법, 제로트러스트 아키텍처, 인시던트 대응, Python SBOM diff |

---

## 참고 프레임워크 및 표준

- **SLSA (Supply-chain Levels for Software Artifacts)**: Google이 제안한 공급망 보안 레벨 프레임워크
- **SSDF (Secure Software Development Framework)**: NIST SP 800-218
- **in-toto**: 소프트웨어 공급망 전 단계 무결성 보장 프레임워크
- **Sigstore**: 소프트웨어 서명·검증을 위한 퍼블릭 인프라
- **SBOM (Software Bill of Materials)**: EO 14028 (2021) 이후 미 정부 조달 필수 요건
- **CISA 공급망 리스크 관리 가이드**: https://www.cisa.gov/supply-chain
