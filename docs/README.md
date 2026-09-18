# 🛡️ VibeHacking — 사이버보안 & 해킹 종합 바이블 포털

[![Sections](https://img.shields.io/badge/Chapters-75_Complete-brightgreen)](#)
[![Interactive Labs](https://img.shields.io/badge/Docker_Labs-16_Active-blue)](#/labs/README)
[![Wargame](https://img.shields.io/badge/Wargame-1085+_Challenges-orange)](/wargame/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-100%25_Passing-brightgreen)](#)
[![Languages](https://img.shields.io/badge/Languages-KO_|_EN_|_JA_|_ZH-purple)](#)

> **실전 침투 테스트, 취약점 연구, 레드팀 작전, 블루팀 관제, AI 보안, 클라우드/컨테이너 및 블록체인까지 망라한 75개 섹션 오픈소스 종합 사이버보안 학습 플랫폼입니다.**

---

## ⚡ 빠른 시작 안내 (Quick Start)

### 1. 📖 교재 탐색 (Web Reader)
좌측 사이드바의 8대 핵심 보안 도메인(01~75장)을 클릭하여 각 챕터의 상세 개념, 실전 익스플로잇 코드, 방어 가이드, 다국어 번역본을 읽을 수 있습니다. 상단 검색창에서 원하는 키워드(예: `SQL 인젝션`, `ROP`, `Volatility`, `eBPF`)를 검색하세요.

### 2. 🧪 Docker 실습 랩 (Labs 01~16)
각 장과 연계된 16개의 격리된 Docker 실전 침투 환경을 로컬 터미널에서 즉시 실행할 수 있습니다:

```bash
# 원하는 실습 환경 시작
vhack lab start 01    # 웹 해킹 랩 (포트 8080)
vhack lab start 15    # Web3 스마트컨트랙트 랩 (포트 8015)
vhack lab start 16    # 메모리 포렌식 & Volatility 랩 (포트 8016)

# 전체 랩 상태 및 자동 검증
vhack lab status
vhack lab test --all
```

### 3. 🎮 브라우저 터미널 워게임 (Wargame 1,085제)
31개 전문 보안 트랙, 5단계 티어(Tier 0~4)로 구성된 인터랙티브 워게임을 브라우저에서 바로 플레이할 수 있습니다:

```bash
# 로컬 워게임 서버 및 PWA 실행
vhack wargame
```

---

## 🗺️ 8대 핵심 보안 도메인 분류

```
├── 1. 시스템 & 저수준 보안       : 01 리눅스, 03 시스템해킹, 04 리버싱, 19 어셈블리, 21 윈도우, 65/66 익스플로잇
├── 2. 웹 & API & 클라우드 보안   : 05 웹해킹, 14 클라우드, 23 DB, 29 K8s, 38 클라우드네이티브, 52 API, 60 브라우저
├── 3. 네트워크 & 인프라 보안     : 02 네트워크, 15 WiFi, 22 비밀번호, 24 인프라, 26 하드닝, 32 장비, 71 블루투스
├── 4. 악성코드 & 포렌식 & DFIR   : 06 악성코드, 07 디지털포렌식, 44 사고대응, 45/67 악성코드개발, 47 모바일포렌식, 72 샌드박스
├── 5. AI & 미래 신기술 보안      : 11 AI보안, 31 AI/ML, 42 Web3, 56 AI레드팀, 57 양자암호, 69 LLM보안
├── 6. 임베디드 / IoT / OT 보안   : 09/37/63 ICS·SCADA, 27 IoT, 28 모바일, 34 하드웨어, 36/62 자동차, 61 펌웨어
├── 7. 레드팀 & 침투 & DevSecOps  : 10 방법론, 12 버그바운티, 17 레드팀, 18 데브섹옵스, 35/59 공급망, 49 인프라, 54 AD
└── 8. 블루팀 & 거버넌스 & 인텔   : 13 SOC, 16 암호학, 25/64 위협인텔, 39 제로트러스트, 40 위협헌팅, 41 한국자격증, 68 퍼플팀
```
