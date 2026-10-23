> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 🛡️ VibeHacking 보안 정책 및 윤리 지침 (Security Policy & Ethics)

**최종 개정일**: 2026년 10월 23일  
**적용 범위**: VibeHacking 저장소, CLI 도구(`vhack.py`), 실습 랩 환경(`labs/`), 워게임 엔진(`wargame/`), 웹 리더 포털(`docs/`), CTF 및 포털 서버(`ctf/`, `portal/`)

---

## 1. 정책 개요 및 원칙

VibeHacking은 대한민국 및 글로벌 정보보안 생태계의 방어 역량을 향상시키고, 차세대 화이트햇 해커와 보안 연구원을 양성하기 위해 제작된 오픈소스 보안 학습 플랫폼입니다.

본 프로젝트는 **"Hack Smart. Defend Hard."** 철학에 기반하며, 다음 핵심 원칙을 엄격히 준수합니다:
* **방어 지향성 (Defensive Orientation)**: 공격 기법의 학습은 오직 시스템을 견고하게 방어하고 취약점을 선제적으로 조치하기 위한 목적으로만 이루어집니다.
* **합법성 및 윤리성 (Legality & Ethics)**: 모든 실습과 연구는 법적 테두리 내에서 소유자의 사전 승인이 확보된 환경에서만 수행되어야 합니다.
* **책임 있는 공개 (Responsible Disclosure)**: 발견된 취약점은 악용되지 않고 제조사 및 관리자가 패치할 수 있도록 공조 공개 절차를 따릅니다.

---

## 2. 취약점 제보 및 공조 공개 정책 (Coordinated Vulnerability Disclosure)

VibeHacking 프로젝트 자체의 소스코드나 배포 인프라에서 보안 취약점을 발견하신 경우, 프로젝트 보안팀에 즉시 제보해 주시기 바랍니다.

### 2.1 제보 대상 (In Scope)
* **CLI 및 유틸리티 도구**: `vhack.py`, `tools/` 내 스크립트의 명령 인젝션, 경로 이탈(Path Traversal), 임의 코드 실행(RCE)
* **웹 포털 및 서버**: `docs/`, `wargame/`, `portal/server.py`, `ctf/server.py`의 미승인 호스트 침해, 인증 우회, 세션 하이재킹
* **실습 랩 격리 침해**: `labs/` 환경에서 컨테이너 탈출(Container Escape)을 통해 호스트 머신을 무단 장악할 수 있는 인프라 결함
* **자격증명 및 시크릿 누출**: 저장소 내 하드코딩된 실제 유효 API 키, 개인키, 토큰 누출

### 2.2 제보 제외 대상 (Out of Scope)
* `labs/` 내의 실습용 타깃 컨테이너 자체에 의도적으로 심어진 교육용 취약점 (예: DVWA의 SQLi, 랩의 버퍼 오버플로우 등 — 이는 교육을 위한 정상 설계입니다)
* 워게임 문제 플래그의 정상적인 풀이 과정
* DoS/DDoS 공격을 통한 로컬 개발 서버 다운
* 소셜 엔지니어링, 피싱 등 비기술적 공격

### 2.3 제보 채널 및 절차
* **보안 전용 이메일**: [leemanrank@gmail.com](mailto:leemanrank@gmail.com)
* **GitHub 보안 권고문**: [GitHub Security Advisories](https://github.com/lsszz2100/VibeHacking/security/advisories/new) (비공개 리포트 권장)
* **제보 시 권장 포함 정보**:
  1. 취약점의 유형 및 심각도 (CVSS 3.1 기준 추정)
  2. 취약점이 존재하는 파일 경로 및 라인 번호
  3. 상세 재현 절차 (Step-by-Step Reproduction Steps)
  4. 개념 증명(PoC) 코드 또는 스크린샷/로그
  5. 제안하는 패치 또는 완화 방안 (선택 사항)

### 2.4 대응 타임라인 및 SLA
* **1차 접수 확인**: 제보 접수 후 **48시간 이내** 확인 회신
* **심각도 평가 및 트리아지**: **5영업일 이내** 취약점 유효성 판정 및 대응 계획 통보
* **패치 릴리스 및 배포**: 통상 **30일 이내** 핫픽스 브랜치 커밋 및 릴리스 배포
* **공개 조율**: 패치가 적용되어 배포된 후 제보자와 조율하여 보안 권고문 및 크레딧(Hall of Fame) 공개

### 2.5 선의의 연구자 보호 (Safe Harbor Statement)
본 보안 정책을 성실히 준수하고, 시스템 안정성을 훼손하지 않으며, 데이터를 무단 유출하거나 제3자에게 악용 가능한 형태로 사전 공개하지 않은 선의(Good-faith)의 보안 연구원에 대해서는 **어떠한 민형사상 법적 조치도 취하지 않으며, GitHub 계정 제재를 요청하지 않습니다.**

---

## 3. 저장소 보안 하드닝 및 시큐어 코딩 기준 (Security Hardening Standards)

VibeHacking 저장소는 다음 자체 보안 통제를 준수합니다:

1. **로컬호스트(127.0.0.1) 격리 바인딩**:
   - `vhack docs`, `vhack wargame`, `vhack portal`, `vhack ctf` 등 모든 로컬 웹 데몬은 기본적으로 루프백 인터페이스(`127.0.0.1`)에만 바인딩되며, 외부 공용망(`0.0.0.0`) 바인딩 시 명시적 보안 경고를 표시합니다.
2. **비밀정보 노출 방지 (Secret Leakage Prevention)**:
   - Git 저장소 내 `.env`, 개인키(`*.key`, `*.pem`, `*.id_rsa`), 클라우드 자격증명(`credentials.csv`, `kubeconfig`), 토큰류의 커밋을 차단하기 위한 `.gitignore` 및 GitHub Actions 시크릿 스캐닝 정책을 상시 가동합니다.
3. **입력값 검증 및 경로 이탈(Path Traversal) 방지**:
   - CLI 파일 읽기 및 문서 렌더링 시 절대경로 정규화(`resolve()`) 및 상위 디렉토리 탈출(`../`) 차단 검증을 수행합니다.
4. **자동화 보안 감사 (CI Security Audits)**:
   - GitHub Actions CI를 통해 워게임 플래그 무결성, 정적 분석(SAST), 의존성 취약점(Dependabot)을 주기적으로 점검합니다.

---

## 4. 허용된 사용 및 금지된 사용 (Permitted vs Prohibited Use)

### ✅ 허용된 사용 (Permitted)
* 공식 개최된 CTF(Capture The Flag) 대회 및 워게임 참가
* 사전 공지된 스코프 내에서의 합법적 공인 버그 바운티(Bug Bounty) 참여
* 의뢰인의 명시적 사전 서면 계약(RoE)에 기반한 합법적인 모의해킹(Penetration Testing)
* 개인 소유의 테스트베드 및 로컬 가상머신, 본 저장소의 `labs/` 도커 환경에서의 자율 학습
* 취약점 메커니즘 분석 및 블루팀/보안관제(SOC) 방어 룰셋(Snort/Suricata/YARA/Sigma) 개발

### ❌ 엄격히 금지된 사용 (Strictly Prohibited)
* 사전 서면 허가 없는 제3자 시스템, 네트워크, 서버, IoT 기기에 대한 스캐닝, 열거, 침투 시도
* 개인정보, 인증 토큰, 기밀 데이터의 무단 수집, 탈취, 열람, 유포
* 서비스 거부(DoS / DDoS) 공격을 통한 네트워크 또는 서버 장애 유발
* 금전적 이득(랜섬웨어, 익스플로잇 판매, 사기 등)을 목적으로 한 악의적 무기화
* 악성코드 작성, 무단 전파, 봇넷 구축 및 C2 인프라 운용
* 본 저장소의 코드를 변조하여 악의적 사이버 공격 도구로 재배포하는 행위

---

## 5. 법적 근거 및 형사처벌 조항 (Legal Statutes)

본 저장소의 기법을 허가 없이 악용하는 경우, 각국 법률에 따라 중범죄로 다루어집니다:

* **대한민국**:
  * **정보통신망 이용촉진 및 정보보호 등에 관한 법률 제48조, 제48조의2, 제49조, 제71조, 제72조** (최대 7년 이하 징역 또는 7천만 원 이하 벌금)
  * **정보통신기반 보호법 제12조, 제28조** (최대 10년 이하 징역 또는 1억 원 이하 벌금)
  * **형법 제314조 (컴퓨터등장애업무방해), 제316조 (비밀침해)** (최대 5년 이하 징역 또는 1천500만 원 이하 벌금)
  * **개인정보 보호법 제71조** (최대 5년 이하 징역 또는 5천만 원 이하 벌금)
* **미국**: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), Electronic Communications Privacy Act (ECPA)
* **유럽연합 및 영국**: Directive 2013/40/EU on attacks against information systems, UK Computer Misuse Act 1990
* **일본**: 不正アクセス行為の禁止等に関する法律, 刑法 第234条の2

상세한 면책 조항 및 법적 고지는 [DISCLAIMER.md](./DISCLAIMER.md)를 반드시 확인하시기 바랍니다.

---

## 6. 실습 환경(Labs) 격리 및 안전 운영 수칙

1. **컨테이너 격리 보장**:
   - `labs/`의 46개 도커 실습 환경은 취약점이 실제로 존재하는 애플리케이션을 호스팅합니다.
   - 포트를 외부 공용망(공공 장소의 공유 Wi-Fi, 클라우드 공인 IP 등)으로 포워딩하지 마십시오.
2. **안전한 모니터링**:
   - `vhack lab status` 및 `vhack lab logs <ID>` 명령어를 활용하여 의도하지 않은 비정상 트래픽이나 포트 개방 여부를 상시 감시하십시오.
   - 실습이 종료되면 즉시 `vhack lab stop <ID>` 또는 `vhack lab stop --all` 명령으로 컨테이너를 안전하게 중지하십시오.

---

## 7. 문의 및 연락처

보안 정책, 윤리적 질의, 콘텐츠 관련 문의는 아래 채널로 연락해 주시기 바랍니다:

| 채널 | 용도 | 링크 |
|------|------|------|
| 📧 이메일 | 보안 취약점 제보, 협업, 정책 문의 | [leemanrank@gmail.com](mailto:leemanrank@gmail.com) |
| 💬 카카오톡 오픈채팅 | 인공지능 및 보안 학습 자료 공유 커뮤니티 | [오픈채팅 참여하기](https://open.kakao.com/o/sv3aJD4h) |
| 🐛 GitHub Issues | 교재 오류, 일반 버그 제보 | [이슈 열기](https://github.com/lsszz2100/VibeHacking/issues/new) |

---

<a name="english"></a>

# 🛡️ Security Policy & Ethical Guidelines

**Last Revised**: October 23, 2026  
**Applicable Scope**: VibeHacking Repository, `vhack.py` CLI, `labs/`, `wargame/`, `docs/`, `ctf/`, `portal/`.

---

## 1. Overview & Core Philosophy

VibeHacking is an open-source cybersecurity education and research platform designed to strengthen defensive capabilities across the global security community. Guided by our motto **"Hack Smart. Defend Hard."**, we operate under three pillars:
* **Defensive Purpose**: Offensive techniques are studied exclusively to understand adversarial mechanics and build resilient defenses.
* **Ethics & Legality**: All research and experimentation must strictly occur within authorized, legal boundaries.
* **Responsible Disclosure**: Discovered vulnerabilities must be handled with care to protect end users.

---

## 2. Coordinated Vulnerability Disclosure (CVD) Policy

If you identify a security vulnerability within the VibeHacking codebase, tools, or infrastructure, please notify us immediately.

### 2.1 In Scope
* **CLI & Utilities**: RCE, path traversal, or command injection in `vhack.py` or `tools/` scripts.
* **Web Services & Portals**: Host compromise, authentication bypass, or session hijacking in `docs/`, `wargame/`, `portal/server.py`, `ctf/server.py`.
* **Lab Isolation Breaches**: Container escape vulnerabilities in `labs/` that compromise the underlying host system.
* **Credentials & Secrets**: Real, active API keys, private keys, or tokens accidentally committed.

### 2.2 Out of Scope
* Intentionally vulnerable applications designed inside `labs/` for educational purposes (e.g., SQLi inside DVWA).
* Normal challenge-solving in CTF/Wargame tiers.
* Denial-of-Service against local developer tools.
* Social engineering or phishing attempts.

### 2.3 Reporting Channel & Format
* **Security Contact**: [leemanrank@gmail.com](mailto:leemanrank@gmail.com)
* **GitHub Private Advisory**: [Create Security Advisory](https://github.com/lsszz2100/VibeHacking/security/advisories/new)
* **Submission Details**:
  1. Summary and estimated severity (CVSS 3.1)
  2. Affected file paths and line numbers
  3. Step-by-step reproduction guide
  4. Proof of Concept (PoC) code or logs
  5. Remediation advice (optional)

### 2.4 Response SLA
* **Initial Acknowledgment**: Within **48 hours**
* **Triage & Assessment**: Within **5 business days**
* **Patch Release**: Typically within **30 days**
* **Coordinated Advisory**: Credit and disclosure coordinated with reporter upon fix deployment.

### 2.5 Safe Harbor Statement
We will not initiate legal action or request GitHub account sanctions against security researchers who conduct good-faith vulnerability research in compliance with this policy.

---

## 3. Repository Hardening Standards

* **Localhost Binding (127.0.0.1)**: All local HTTP and API servers bind to `127.0.0.1` by default; binding to `0.0.0.0` issues an explicit security warning.
* **Secret Leak Prevention**: Strict `.gitignore` rules and automated CI scanning to prevent committing credentials, keys, and tokens.
* **Path Traversal Protection**: All CLI file readers validate and normalize paths against the repository root.
* **Automated CI Audits**: Continuous integration workflows audit dependencies, challenge integrity, and security regressions.

---

## 4. Permitted vs. Prohibited Actions

### ✅ Permitted
* Participation in sanctioned CTFs and wargames
* Bug bounty research within authorized scope
* Contracted penetration tests under approved Rules of Engagement (RoE)
* Study on self-owned virtual machines and local `labs/` containers
* Developing defensive detections (Snort, Suricata, YARA, Sigma)

### ❌ Strictly Prohibited
* Scanning, probing, or attacking third-party systems without prior written authorization
* Data theft, exfiltration, or unauthorized disclosure
* Denial of Service (DoS/DDoS) attacks
* Weaponization for financial gain, ransomware, or extortion
* Malware development and deployment against unauthorized targets

---

## 5. Governing Legal Statutes

Misuse of the materials in this repository constitutes a serious crime under international and domestic laws:
* **South Korea**: Network Act (Articles 48, 48-2, 49, 71, 72), Critical Infrastructure Protection Act (Articles 12, 28), Criminal Act (Articles 314, 316).
* **United States**: CFAA (18 U.S.C. § 1030), ECPA (18 U.S.C. § 2510).
* **EU & UK**: Directive 2013/40/EU, UK Computer Misuse Act 1990.
* **Japan**: Unauthorized Computer Access Act.

For complete legal terms, review [DISCLAIMER.md](./DISCLAIMER.md).

---

## 6. Lab Isolation & Defensive Operations

* `labs/` containers contain deliberately vulnerable software. Never bind lab ports to public network interfaces.
* Run live exploit testing inside isolated virtual machines.
* Regularly execute `vhack lab status` and stop containers with `vhack lab stop --all` when not in use.

---

## 7. Contact Information

| Channel | Purpose | Link |
|---------|---------|------|
| 📧 Email | Security reports, inquiries, collaborations | [leemanrank@gmail.com](mailto:leemanrank@gmail.com) |
| 💬 KakaoTalk Open Chat | Community discussion & AI/Security resource sharing | [Join Chat](https://open.kakao.com/o/sv3aJD4h) |
| 🐛 GitHub Issues | Bug reports and content errata | [Open Issue](https://github.com/lsszz2100/VibeHacking/issues/new) |
