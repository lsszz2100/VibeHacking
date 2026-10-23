> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ⚖️ 법적 고지 및 면책조항 (Legal Notice & Disclaimer)

**최종 개정일**: 2026년 10월 23일  
**적용 대상**: VibeHacking 프로젝트(저장소, 교재 75개 섹션, 484개 심층 챕터, 46개 실습 랩, 워게임 터미널 침투 콘솔, vhack CLI 도구 및 관련 코드 일체)

---

## 1. 목적 및 교육 한정 원칙 (Educational & Research Purpose Only)

1. **교육 및 학술 연구 한정**:
   - VibeHacking 프로젝트에 포함된 모든 기술 문서, 개념 증명(PoC, Proof of Concept) 코드, 실습용 취약 환경(Docker Labs), CTF 워게임 시나리오 및 관리 CLI 도구(`vhack`)는 **오직 사이버보안 교육, 학술 연구, 화이트햇(White Hat) 방어 역량 강화, 버그 바운티(Bug Bounty) 및 합법적 모의해킹(Penetration Testing) 훈련**을 목적으로만 제작·배포되었습니다.
2. **방어 역량 강화 목적**:
   - 본 자료의 궁극적인 목표는 공격 기법의 메커니즘을 심층 이해함으로써 기업 및 기관의 시스템·네트워크·클라우드·애플리케이션을 외부 침해 위협으로부터 사전에 방어하고, 보안 정책 및 침해사고 대응(DFIR) 프로세스를 고도화하는 데 있습니다.

---

## 2. 엄격한 사전 서면 인가 원칙 (Strict Authorization Requirement)

1. **무단 접근의 절대 금지**:
   - 시스템 소유자(소유 기업, 기관 또는 개인)의 **명시적인 사전 서면 승인(Prior Written Authorization)** 없이 본 저장소의 기법, 스크립트, 페이로드 또는 도구를 제3자의 시스템, 서버, 네트워크, 웹 애플리케이션, 데이터베이스, IoT 기기, 무선 AP, 클라우드 인프라 등에 적용하거나 시도하는 행위는 **어떠한 이유로도 정당화될 수 없으며 명백한 불법 행위**에 해당합니다.
2. **허가된 실습 환경의 범위**:
   - 본 저장소의 기법 및 도구는 반드시 아래의 명시적으로 승인된 격리 환경에서만 사용해야 합니다:
     - 본 프로젝트에서 제공하는 로컬 가상 실습 환경(`labs/` 도커 컨테이너)
     - 사용자 본인이 완전한 관리 권한을 소유한 독립 격리 연구 환경(Local VM / 에어갭 랩)
     - 주최 측의 공식 규칙 및 범위(Scope)가 명시된 CTF(Capture The Flag) 대회
     - 사전 정의된 룰(Program Policy / Scope) 내에서 진행되는 공인 버그 바운티 프로그램
     - 유효한 계약서 및 사전 승인 범위(Rules of Engagement, RoE)가 체결된 합법적 모의해킹 프로젝트

---

## 3. 관련 국내외 법령 및 형사처벌 규정 (Governing Cybercrime Laws)

본 자료를 악용하여 인가되지 않은 시스템에 접근하거나 피해를 야기할 경우, 각국 법률에 따라 중대한 형사 처벌 및 민사상 손해배상 책임이 부과됩니다.

### 대한민국 법령
* **「정보통신망 이용촉진 및 정보보호 등에 관한 법률」(정보통신망법)**
  * **제48조 (정보통신망 침해행위 등의 금지)**: 정당한 접근권한 없이 또는 허용된 접근권한을 넘어 정보통신망에 침입하는 행위 금지
  * **제48조의2 (악성프로그램 등의 유포 금지)**: 정당한 사유 없이 악성프로그램을 작성·배포·유포하는 행위 금지
  * **제49조 (비밀 등의 보호)**: 정보통신망에 의해 처리·보관·전송되는 타인의 정보를 훼손하거나 타인의 비밀을 침해·도용 또는 누설하는 행위 금지
  * **제70조의2, 제71조, 제72조 (벌칙)**: 위반 시 **최대 7년 이하의 징역 또는 7천만 원 이하의 벌금**
* **「정보통신기반 보호법」**
  * **제12조 (주요정보통신기반시설 침해행위의 금지)**: 주요정보통신기반시설에 대한 무단 접근, 교란, 마비, 파괴 행위 금지
  * **제28조 (벌칙)**: 위반 시 **10년 이하의 징역 또는 1억 원 이하의 벌금**
* **「형법」**
  * **제314조 (업무방해 및 컴퓨터등장애업무방해)**: 정보처리장치에 허위 정보나 부정한 명령을 입력하거나 장애를 발생시켜 업무를 방해한 자는 **5년 이하의 징역 또는 1천500만 원 이하의 벌금**
  * **제316조 (비밀침해)**: 전자기록 등 특수매체기록을 기술적 수단을 이용해 침해한 자는 **3년 이하의 징역이나 금고 또는 500만 원 이하의 벌금**
* **「개인정보 보호법」**
  * **제71조 (벌칙)**: 부정한 수단이나 방법으로 개인정보를 취득하거나 제3자에게 누출한 자는 **5년 이하의 징역 또는 5천만 원 이하의 벌금**

### 주요 국제 법령
* **미국 (United States)**:
  * **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**: 미승인 컴퓨터 접근 및 손상 행위에 대해 엄격한 연방 범죄 규정 적용 (중대 침해 시 최대 20년 징역)
  * **Electronic Communications Privacy Act (ECPA, 18 U.S.C. § 2510 et seq.)**: 전자 통신 도청 및 불법 패킷 캡처 처벌
* **유럽연합 (European Union & UK)**:
  * **EU Directive 2013/40/EU**: 정보시스템 침해 범죄 처벌 및 네트워크 공격 규제 지침
  * **General Data Protection Regulation (GDPR)**: 개인정보 불법 접근 및 침해에 대한 대규모 과징금 부과
  * **영국 Computer Misuse Act 1990 (Section 1~3ZA)**: 무단 시스템 접근 및 데이터 변경에 대해 최대 10년 징역 또는 무기징역
* **일본 (Japan)**:
  * **不正アクセス行為の禁止等に関する法律 (不正アクセス禁止法)**: 타인의 비밀번호 도용 및 취약점 악용 무단 접속 처벌
  * **刑法 第234条の2 (電子計算機損壊等業務妨害罪)**: 전자계산기 손괴 및 업무방해 처벌

---

## 4. 보증의 전면 부인 (Disclaimer of Warranties - "AS IS")

1. **있는 그대로의 제공**:
   - 본 저장소의 모든 코드, 가이드 문서, 익스플로잇 PoC, 스크립트, 환경 설정 및 도구는 **"있는 그대로(AS IS)"** 그리고 **"결함이 있는 상태 그대로(WITH ALL FAULTS)"** 제공됩니다.
2. **보증의 배제**:
   - 프로젝트 관리자, 원작자 및 모든 기여자는 본 저장소의 정보나 코드의 **상업성(Merchantability), 특정 목적에의 적합성(Fitness for a Particular Purpose), 정확성, 최신성, 완전성, 무결성, 비침해성(Non-infringement)**에 대해 어떠한 명시적 또는 묵시적 보증도 하지 않습니다.
3. **오작동 및 시스템 위험성**:
   - 시스템 환경 및 설정 차이에 따라 본 자료의 코드나 실습 환경이 예기치 못한 시스템 충돌, 데이터 손실, 네트워크 불안정을 유발할 수 있으며, 이에 대한 사전 예방 및 테스트 책임은 전적으로 사용자에게 있습니다.

---

## 5. 법적 책임의 전적인 귀속 및 제한 (Limitation of Liability)

1. **사용자의 전적인 책임**:
   - 본 저장소의 자료나 도구를 열람, 다운로드, 수정, 실행 또는 제3자에게 전달함으로써 발생하는 **모든 법적·민사적·형사적·행정적 책임은 전적으로 행위자(사용자 본인)에게 귀속**됩니다.
2. **제작자 및 기여자의 면책**:
   - 어떠한 경우에도 본 프로젝트의 제작자, 관리자, 유지보수자 및 기여자는 본 자료의 사용, 오용, 악용, 오작동 또는 사용 불능으로 인하여 발생한 **직접 손해, 간접 손해, 부수적 손해, 특별 손해, 징벌적 손해 또는 결과적 손해**(데이터 손실, 시스템 장애, 업무 중단, 하드웨어 파손, 법적 처벌, 영업 이익 손실 등을 포함하되 이에 국한되지 않음)에 대해 계약, 불법행위(과실 포함), 엄격 책임 등 어떠한 법적 법리하에서도 책임을 지지 않습니다.

---

## 6. 사용자의 면책 및 배상 의무 (Indemnification)

사용자는 본 저장소의 자료, 코드, 도구를 본 면책조항 및 보안 정책에 반하여 오용하거나, 제3자의 권리를 침해하거나, 관련 법률을 위반함으로써 발생하는 모든 청구, 소송, 조사, 손실, 손해, 부채, 판결, 합의금 및 합리적인 변호사 비용을 포함한 제반 비용으로부터 **프로젝트 제작자 및 기여자를 완전히 면책하고 방어하며 배상할 것에 동의**합니다.

---

## 7. 이중 용도 기술 및 수출 통제 준수 (Dual-Use Technology & Export Compliance)

1. **이중 용도 기술의 특성**:
   - 사이버보안 기술, 침투 테스트 도구 및 취약점 분석 메커니즘은 보안 방어와 공격 모두에 적용 가능한 **이중 용도(Dual-Use) 기술**입니다.
2. **바세나르 협정(Wassenaar Arrangement) 및 관련 규정 준수**:
   - 본 프로젝트의 공개 자료는 공공의 이익과 방어적 보안 연구 역량 강화를 위해 제공되며, 침해 도구의 군사적·악의적 무기화(Weaponization) 및 관련 국제 수출 통제 규정을 위반하는 불법 전용을 엄격히 금지합니다.

---

## 8. 실습 환경(Labs) 격리 및 안전 운영 수칙 (Lab Operational Security)

1. **네트워크 격리 의무**:
   - `labs/` 디렉토리에 수록된 46개 실습 랩은 교육을 위해 의도적으로 보안 취약점(취약한 데몬, SQLi, 미인증 RCE, 커널 취약점 등)을 포함하고 있습니다.
   - 본 실습 컨테이너들을 **공용 Wi-Fi, 외부 인터넷, 사내 내부망 등 신뢰할 수 없는 네트워크에 포트 포워딩하거나 외부 인터페이스(`0.0.0.0`)로 노출해서는 절대로 안 됩니다.**
2. **안전 권장 수칙**:
   - 실습 시 반드시 로컬 루프백 인터페이스(`127.0.0.1`)에 바인딩하거나 격리된 가상머신(Host-Only Network) 내부에서만 구동하십시오.
   - 악성코드 분석 및 동적 디버깅 실습은 네트워크 어댑터가 분리된 샌드박스 환경에서 수행하십시오.

---

## 9. 동의의 효력 (Acknowledgment & Acceptance)

본 저장소의 파일을 클론(Git Clone), 포크(Fork), 다운로드, 열람, 참조하거나 `vhack` 도구를 실행하는 것은 **상기 모든 법적 고지, 면책조항, 이용 조건에 온전히 동의한 것으로 간주**됩니다. 만약 본 조항의 내용 중 일부라도 동의하지 않는 경우, 본 저장소의 모든 자료 및 파일의 사용을 즉시 중단하고 삭제하여야 합니다.

---

<a name="english"></a>

# ⚖️ Legal Notice & Disclaimer

**Last Revised**: October 23, 2026  
**Scope**: Entire VibeHacking Project (Repository, 75 Sections, 484 Deep-Dive Chapters, 46 Hands-on Labs, Terminal Wargame Console, vhack CLI Tool, and all related source code).

---

## 1. Educational & Defensive Research Purpose Only

1. **Strictly Educational**:
   - All technical documentation, Proof-of-Concept (PoC) exploit scripts, vulnerable lab environments (`labs/`), CTF wargame challenges, and CLI utilities (`vhack`) in this repository are developed and provided **solely for educational, academic research, White Hat defensive skill building, Bug Bounty readiness, and legitimate penetration testing training**.
2. **Defensive Empowerment**:
   - The primary objective of this project is to empower security professionals, engineers, and researchers to understand attack mechanisms in depth so that they can effectively defend infrastructure, systems, and applications against modern cyber threats.

---

## 2. Explicit Prior Written Authorization Required

1. **Absolute Prohibition of Unauthorized Access**:
   - Applying any technique, script, payload, or tool from this repository against any third-party system, server, network, application, database, IoT device, or cloud infrastructure **without the explicit, prior written authorization from the legitimate system owner is strictly prohibited and constitutes a serious criminal offense**.
2. **Authorized Environments Only**:
   - Usage of these materials is strictly confined to explicitly authorized environments:
     - The localized Docker container labs provided within this repository (`labs/`)
     - Personal isolated lab environments completely owned and operated by the user (Host-Only VMs / Air-gapped networks)
     - Officially organized CTF (Capture The Flag) competitions
     - Public or private Bug Bounty programs within their explicitly stated scope and rules
     - Authorized commercial penetration tests governed by formal contracts and Rules of Engagement (RoE)

---

## 3. Governing Cybercrime Laws & Criminal Liability

Unauthorized computer intrusions, disruptions, or data theft carry severe criminal penalties and civil liability worldwide:

### Republic of Korea
* **Act on Promotion of Information and Communications Network Utilization and Information Protection**:
  * **Article 48**: Prohibition of unauthorized intrusion into information and communications networks
  * **Article 48-2**: Prohibition of unauthorized creation/distribution of malicious programs
  * **Article 49**: Protection of secrets transmitted or stored in networks
  * **Penalties (Articles 70-2, 71, 72)**: Imprisonment for up to **7 years** or fines up to **KRW 70,000,000**.
* **Act on the Protection of Information and Communications Infrastructure**:
  * **Article 12 & 28**: Intrusions into critical infrastructure carry imprisonment up to **10 years** or fines up to **KRW 100,000,000**.
* **Criminal Act (Articles 314 & 316)**: Obstruction of business through computer disruption and violation of digital secrecy.
* **Personal Information Protection Act (Article 71)**: Unauthorized leakage of personal data punishable by up to 5 years imprisonment.

### United States
* **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**: Federal penalties for unauthorized access or damage to protected computers (up to 20 years for severe offenses).
* **Electronic Communications Privacy Act (ECPA, 18 U.S.C. § 2510 et seq.)**: Criminalizes unauthorized interception of electronic communications.

### European Union & United Kingdom
* **EU Directive 2013/40/EU**: Framework on attacks against information systems.
* **General Data Protection Regulation (GDPR)**: Massive civil liability and fines for data breaches.
* **UK Computer Misuse Act 1990 (Sections 1–3ZA)**: Unauthorized access or modification carries up to life imprisonment for catastrophic infrastructure attacks.

### Japan
* **Unauthorized Computer Access Act (不正アクセス禁止法)**: Strict criminal penalties for unauthorized logins and vulnerability exploitation.
* **Penal Code Article 234-2**: Obstruction of business by destruction of computers.

---

## 4. Disclaimer of Warranties ("AS IS")

1. **Provided "AS IS"**:
   - All materials, software, scripts, configurations, and documentation are provided on an **"AS IS"** and **"WITH ALL FAULTS"** basis.
2. **No Warranties**:
   - The authors, maintainers, and contributors make **no representations or warranties of any kind**, express or implied, including but not limited to the implied warranties of **merchantability, fitness for a particular purpose, accuracy, completeness, or non-infringement**.
3. **Operational Risks**:
   - Exploitation scripts and lab setups may cause unintended system crashes, kernel panics, or data corruption in misconfigured environments. The risk rests entirely with the user.

---

## 5. Limitation of Liability

1. **Sole User Responsibility**:
   - Any and all legal, ethical, civil, criminal, and financial responsibility arising from the use, misuse, modification, or distribution of these materials rests solely with the user.
2. **Total Exemption of Authors & Contributors**:
   - In no event shall the authors, maintainers, or contributors be held liable for any direct, indirect, incidental, special, exemplary, punitive, or consequential damages (including loss of data, loss of profits, system downtime, hardware damage, or legal prosecution) arising out of or in connection with the use or inability to use this repository.

---

## 6. User Indemnification

You agree to indemnify, defend, and hold harmless the authors, maintainers, and contributors from and against any and all claims, liabilities, damages, losses, costs, or expenses (including reasonable attorney's fees) arising out of your misuse of the materials, violation of these terms, or infringement of any third-party rights or applicable laws.

---

## 7. Dual-Use Technology & International Controls

Cybersecurity testing methodologies and vulnerability research constitute **dual-use technology** under international conventions (such as the Wassenaar Arrangement). Weaponization, offensive malicious deployment, or violation of applicable export and defense trade regulations is strictly forbidden.

---

## 8. Lab Isolation & Operational Safety Guidelines

1. **Mandatory Isolation**:
   - The 46 Docker labs (`labs/`) contain intentionally vulnerable software (e.g., exposed RCE, unauthenticated DBs, outdated kernels).
   - **Never expose, bridge, or port-forward lab containers to public networks, public Wi-Fi, or corporate production LANs (`0.0.0.0`).**
2. **Defensive OpSec**:
   - Always bind lab services to loopback (`127.0.0.1`) or an isolated internal virtual bridge network.
   - Conduct live malware or binary exploit experiments in dedicated, non-networked virtual machines.

---

## 9. Acknowledgment & Binding Agreement

By cloning, downloading, reading, or executing any file or script from this repository, you explicitly acknowledge that you have read, understood, and agreed to be fully bound by this Legal Notice and Disclaimer. If you do not agree, you must delete and discontinue using all materials immediately.
