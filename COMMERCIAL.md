# VibeHacking Enterprise & Commercial Program
(전사 B2B 엔터프라이즈 사이버보안 솔루션 & 교육 플랫폼)

---

## 1. Executive Summary (개요)

**VibeHacking(바이브해킹)**은 기초 시스템 원리부터 최신 포스트 양자 암호(PQC), 실리콘 포토닉스/QKD, AI 에이전트 자율 방어, 저궤도 위성 광통신(SatCom Laser QKD)에 이르는 **실전 풀스택 사이버보안 연구·실습·평가 플랫폼**입니다.

VibeHacking은 개인 연구원과 학생을 위한 **100% 영구 무료 오픈소스(Community Edition)**를 기반으로, 방위산업·금융·국가기반시설 및 빅테크 기업을 위한 **B2B 엔터프라이즈 상용 라이선스 & 사이버 훈련장(Cyber Range)** 패키지를 제공합니다.

---

## 2. Edition Matrix (에디션 비교 체계)

| 구분 | Community Edition (오픈소스) | Enterprise Edition (B2B 상용) | Defense & Critical Infra (국방/망분리) |
| :--- | :--- | :--- | :--- |
| **비용 / 라이선스** | 100% 무료 (Apache-2.0) | 유료 구독 / 영구 라이선스 | 맞춤형 계약 / 폐쇄망 영구 라이선스 |
| **교재 커리큘럼** | 75개 전 섹션 / 492개 챕터 (Docsify 웹) | 492개 챕터 단행본 PDF/e-Book + 사내 LMS 연동 | 폐쇄망 사내 LMS 패키지 + 맞춤형 챕터 저작 |
| **핸즈온 실습 랩** | 77개 Docker 랩 (로컬 127.0.0.1 단일 사용자) | 78개 랩 멀티테넌트 쿠버네티스(K8s) 오케스트레이션 | 에어갭(Air-Gapped) 완전 격리형 오프라인 랩 번들 |
| **워게임 / CTF** | 90개 트랙 3,115개 브라우저 가상 셸 | 중앙 집중식 사내 사내 CTF 대회 운영 엔진 + 실시간 관제 | 폐쇄망 독립 CTF 서버 + 맞춤형 산업별 플래그 셋 |
| **시뮬레이터** | 44대 단독 실행형 인터랙티브 웹 시뮬레이터 | 44대 시뮬레이터 + 강사 대시보드 및 원격 원격 평가 | 보안 감사관 전용 시뮬레이터 로그 분석기 |
| **보안 진단 리포트** | 수동 Markdown 리포트 | KISA ISMS-P, NIST CSF 2.0, OWASP 10, CVSS 3.1 원클릭 PDF/Excel | 국방 보안 규격 및 망분리 적합성 검증 감사 모듈 |
| **AI 에이전트 평가** | CLI 기반 단일 실행 | Agent-Eval 2.0 엔터프라이즈 모니터링 & LLM 가드레일 감사 | 폐쇄망 로컬 LLM(GPT-OSS, Llama 3) 전용 평가 엔진 |
| **기술 지원 (SLA)** | GitHub Issues & Community | 영업일 8시간 이내 전담 엔지니어 기술 지원 (SLA) | 24/7 비상 대응 지원 + 사내 방문 교육 세미나 |

---

## 3. Core Enterprise Modules (상용 핵심 솔루션)

### 3.1. Air-Gapped Offline Defense Bundle (에어갭 폐쇄망 무결성 번들)
- **적용 대상**: 국방망, 금융망, 발전소/철도 등 국가 주요 정보통신기반시설.
- **특징**:
  - 외부 인터넷 연결 0% 환경에서 100% 가동되는 자립형 아카이브 (`release/v2.28.0/vibe-hacking-v2.28.0-offline.tar.gz`).
  - 암호학적 SHA-256 무결성 검증 및 7단계 자동 스모크 테스트(`tools/verify_offline_deployment.sh`) 보증.
  - 내장 Docsify 오프라인 엔진, 로컬 Docker 이미지 레지스트리, 정적 자산 로컬 캐시 탑재.

### 3.2. Enterprise Cyber Range & Multi-tenant CTF (기업 실전 침투 훈련장)
- 사내 임직원 및 보안 담당자를 위한 대규모 동시 접속 침투 훈련장.
- 실시간 리더보드, 팀별 진척도 모니터링, 취약점 패치 검증, 치팅 방지 안티 플래그 공유 알고리즘.
- 43대 인터랙티브 시뮬레이터를 활용한 노코드/로우코드 시각화 공격-방어(Attack-Defense) 시나리오.

### 3.3. Automated Compliance & Vulnerability Audit Engine (자동 규제 준수 엔진)
- 사내 시스템 진단 후 KISA ISMS-P 80개 통제 항목, NIST CSF 2.0 6대 기능, OWASP Top 10, CVSS 3.1 점수 자동 환산.
- 엔터프라이즈 감사용 다중 포맷(PDF, DOCX, CSV, JSON) 리포트 자동 생성 (`tools/report_generator.py`).

### 3.4. Frontier AI Agent Benchmark & Guardrail Audit (Agent-Eval 2.0)
- 기업 내 도입 중인 LLM 에이전트(OpenAI GPT, Claude, Gemini, 자체 파인튜닝 모델)의 보안 취약점 전수 진단.
- 78개 랩 / 90개 트랙 3,115개 과제를 기반으로 자율 공격 탐지율, 방어 복원력, 프롬프트 인젝션 방어율 정량 산출.

---

## 4. B2B Engagement & Contact (도입 및 라이선스 문의)

- **공식 저장소**: [GitHub Repository](https://github.com/lsszz2100/VibeHacking)
- **포털 사이트**: [VibeHacking Official Portal](https://lsszz2100.github.io/VibeHacking/)
- **기업 도입 및 기술 협력 문의**:
  - 엔터프라이즈 라이선스, 온프레미스 구축 및 오프라인 번들 견적
  - 임직원 대상 사이버보안 워크숍 및 침투 모의훈련 컨설팅
  - 이메일: `contact@vibehacking.io` (또는 GitHub Organization 비공개 문의)
