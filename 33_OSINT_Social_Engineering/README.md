# 33. OSINT와 사회공학 — 사람과 흔적이 가장 약한 고리다

> **이 섹션이 다루는 것**: 기술적 취약점이 아니라 **공개 정보(OSINT)**와 **사람의 의사결정 과정**을 노리는 공격·방어. 검색 엔진·SNS·코드 저장소·DNS·인증서 투명성 로그가 흘려보내는 디지털 흔적을 모아 표적 프로파일을 완성하고, 이를 기반으로 피싱·비싱·프리텍스팅을 설계하는 흐름을 한국어 실무 관점에서 정리합니다.
> 섹션 17(레드팀 운영)이 캠페인 전 과정의 운영 관점이라면, 이 섹션은 **표적 정찰과 휴먼 익스플로잇 그 자체에 집중**합니다.

## 왜 이 주제가 따로 있어야 하는가

2024년 Verizon DBIR, 2025년 Microsoft Digital Defense Report, 2026년 KISA 침해사고 통계 모두 공통적으로 지적합니다.

- **초기 침투의 60% 이상은 휴먼 요소**(피싱, 자격증명 재사용, 사회공학)
- 평균적으로 **OSINT 단계만으로도 외부 공격자가 직원의 70%까지 식별** 가능
- **MFA 우회 피싱 키트(evilginx, NakedPages 등)** 의 등장으로 "MFA만 켜두면 안전"이 더 이상 통하지 않음
- AI 합성 음성·영상(2026년 기준 Meta SeamlessM4T-v3, ElevenLabs v3 수준)으로 **CEO 사칭 비싱 공격 단가가 급격히 하락**

OSINT와 사회공학은 "사람을 속이는 기법"이라는 통념을 넘어서, **자동화·AI·인프라가 결합된 산업급 공격 표면**으로 진화했습니다. 이 섹션은 그 변화를 따라잡는 데 목표를 둡니다.

## 목차

| # | 파일 | 주제 | 난이도 |
|---|------|------|--------|
| 01 | [osint_methodology_and_search.md](01_osint_methodology_and_search.md) | OSINT 사이클, 고급 검색 연산자, Shodan/Censys/FOFA, 인증서 투명성 로그 | ★★ |
| 02 | [target_profiling.md](02_target_profiling.md) | LinkedIn/GitHub/SNS 추적, theHarvester·Sherlock·Maltego, 이메일·도메인·인물 자동화 | ★★★ |
| 03 | [social_engineering_attacks.md](03_social_engineering_attacks.md) | 피싱/비싱/스미싱/프리텍스팅/USB 드롭, 심리 트리거(Cialdini), 사회공학 사이클 | ★★★ |
| 04 | [phishing_infra_and_evasion.md](04_phishing_infra_and_evasion.md) | GoPhish·evilginx2(MFA 우회), 도메인 squatting, SPF/DKIM 정상화, SEG·EDR 탐지 회피 | ★★★★ |

## 17번 섹션과의 차이

| 관점 | 17. 레드팀 운영 | 33. OSINT·사회공학 |
|------|-----------------|---------------------|
| 초점 | 캠페인 운영, C2 인프라, 작전 전체 흐름 | **표적 정찰 + 사람을 속이는 단계 그 자체** |
| 주 기법 | 페이로드·라테럴 무브먼트·지속성 | OSINT 자동화·심리 공학·피싱 인프라 |
| 도구 | Cobalt Strike·Sliver·Mythic | theHarvester·Maltego·GoPhish·evilginx2 |
| 결과물 | 침투 보고서 (전체) | 표적 프로파일 + 피싱 캠페인 결과 (입구) |

쉽게 말해 **17번이 "방 안으로 들어가서 무엇을 하는가"라면, 33번은 "어떻게 문 앞에 서고, 그 문을 열게 만드는가"** 입니다.

## 선수 지식

- 도메인·DNS·이메일 헤더 기본 (SPF, DKIM, DMARC 의미)
- Python 3.10+ requests/asyncio 사용 경험
- 웹 인증·세션 쿠키·OAuth 2.0 흐름의 큰 그림
- 24번 섹션(네트워크 인프라 보안)에서 메일 보안 챕터를 먼저 보고 오면 04번 본문이 훨씬 쉽게 읽힙니다

## 실습 환경

OSINT는 외부 데이터를 수집하는 작업이라 가상 환경 구축이 사실상 필수는 아니지만, **수집한 데이터를 안전하게 격리**하고 **출처를 흐리지 않기 위해** 다음 구성을 권장합니다.

### 권장 스택 (2026년 기준)

| 구성요소 | 선택 |
|----------|------|
| 워크스테이션 | Kali Linux 2026.x 또는 Ubuntu 24.04 + Tor Browser + Mullvad VPN |
| 식별성 격리 | Whonix Workstation VM (Tor를 강제하는 게이트웨이 분리) |
| OSINT 도구 모음 | OSINT Framework, SpiderFoot HX, Maltego CE, Recon-ng |
| 노트/그래프 | Obsidian + Maltego, JSON 포맷으로 표적 카드 관리 |
| 피싱 랩 | 격리된 도메인(랩 전용 .test/.example) + GoPhish + 메일캐처 |
| 합성 음성 실습 | OpenAI Voice / ElevenLabs (테스트 계정), 윤리 전제 필수 |

### 법적·윤리적 전제

이 섹션의 모든 기법은 **공개 데이터 활용** 또는 **명시적 허가가 있는 표적**에만 적용해야 합니다. 한국 기준:

- **개인정보 보호법** — 수집·이용에 동의 없이 식별 정보를 결합하면 위반 소지
- **정보통신망법 70조** — 정보통신망 이용 사기, 명의 도용은 형사 처벌
- **전기통신금융사기 특별법** — 비싱·스미싱은 기수 여부와 무관하게 처벌
- **HackerOne·Bugcrowd·KrCERT 책임공개 프로그램**의 사회공학 범위는 매우 제한적이며, 시작 전 반드시 확인

## 이 섹션에서 다루는 2024–2026 실제 사건

이론보다 **사건 기반 학습**이 효과적입니다. 본문 곳곳에서 등장합니다.

| 연도 | 사건 | 핵심 |
|------|------|------|
| 2024 | Snowflake 고객사 165곳 침해 | 인포스틸러로 수집된 자격증명 + MFA 미적용 |
| 2024 | Arup CFO 딥페이크 비싱 | 영상통화에 합성 영상 사용, 약 2,500만 USD 송금 |
| 2025 | Coinbase 내부자 매수형 OSINT 결합 | LinkedIn 추적 + 외주 직원 매수, 고객 데이터 유출 |
| 2025 | OAuth 동의 피싱 (M365 illicit consent) | 정상 도메인의 OAuth 앱 등록을 악용, MFA 무력화 |
| 2026 | 국내 모 통신사 협력사 피싱 | 외주직원 LinkedIn → 도메인 squatting → 협력사 VPN 자격증명 탈취 |

## 도구 사전 준비

```bash
# OSINT 핵심 도구 모음 (Kali/Ubuntu 24.04 기준)

# theHarvester — 이메일·하위도메인·호스트 정찰
sudo apt install theharvester

# Sherlock — 사용자명을 SNS·웹 서비스 400+ 곳에서 일괄 조회
pipx install sherlock-project

# SpiderFoot — 자동화된 OSINT 그래프 수집
pipx install spiderfoot

# Recon-ng — 모듈식 OSINT 프레임워크
pipx install recon-ng

# Maltego CE — 그래프 시각화 (GUI)
sudo apt install maltego

# Photon — 웹사이트에서 이메일·소셜링크·키 자동 수집
pipx install photon

# Holehe — 이메일이 어떤 서비스에 가입돼 있는지 조회
pipx install holehe

# crt.sh CLI — 인증서 투명성 로그에서 하위도메인 수집
pip install crtsh-cli

# GoPhish — 오픈소스 피싱 캠페인 프레임워크 (실습용)
# https://getgophish.com/  바이너리 직접 다운로드

# evilginx2 — MFA 우회 피싱 프록시 (실습 환경에서만)
# https://github.com/kgretzky/evilginx2
```

## 학습 목표

이 섹션을 끝내면 다음을 직접 수행할 수 있습니다.

- **OSINT 사이클**(요구사항 정의 → 수집 → 처리 → 분석 → 배포)을 자기 워크플로에 맞춰 설계한다.
- 하나의 표적 도메인에서 시작해 **이메일/하위도메인/직원 명단/기술 스택까지 자동화 파이프라인**으로 추출한다.
- **theHarvester + Sherlock + Holehe + crt.sh** 결과를 한 JSON으로 합치는 Python 스크립트를 작성한다.
- 사회공학 시나리오 4종(피싱·비싱·스미싱·프리텍스팅)을 각각의 **심리 트리거와 측정 지표**까지 정리해 캠페인 기획서로 만든다.
- **GoPhish 캠페인 + evilginx2 MFA 우회 랩**을 격리 환경에서 구축해 본다.
- 메일 인프라의 **SPF/DKIM/DMARC를 합법적으로 통과**시키면서 SEG·EDR을 회피하는 기술의 한계를 이해하고, 방어 측 탐지 레시피를 작성한다.
- 위 전 과정을 **법·윤리 체크리스트**로 통제한다.

## 관련 섹션

- [10. 침투 테스트 방법론](../10_Pentest_Methodology/) — OSINT가 정찰 단계에서 어떻게 위치하는가
- [12. 버그바운티](../12_Bug_Bounty/) — 책임공개 프로그램에서의 OSINT 한계와 모범 사례
- [17. 레드팀 운영](../17_Red_Team_Operations/) — 사회공학 + C2 + 라테럴 무브먼트 결합
- [22. 패스워드 크래킹](../22_Password_Cracking/) — OSINT로 수집한 인적 정보로 워드리스트 생성
- [24. 네트워크 인프라 보안](../24_Network_Infrastructure_Security/) — SPF/DKIM/DMARC 방어 측 설정
- [25. 위협 인텔리전스](../25_Threat_Intelligence/) — OSINT를 IOC·TTP 수집으로 전환
