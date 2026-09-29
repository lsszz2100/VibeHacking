# Lab 29: CertPwn - AD CS & Kerberos Delegation 침투 및 방어 실전 랩

## 1. 랩 개요 (Overview)
본 실습 환경은 엔터프라이즈 Active Directory 환경의 핵심 침투 벡터인 **AD CS(Active Directory Certificate Services) 오설정(ESC1~ESC8)**과 **Kerberos 위임(Unconstrained, Constrained S4U2Self/S4U2Proxy, RBCD)** 공격 체인을 시뮬레이션하고, 이에 대한 심층 방어(Hardening) 기술을 체득할 수 있는 핸즈온 보안 랩입니다.

- **포트**: `http://localhost:8029`
- **타깃 도메인**: `CORP.LOCAL` (도메인 컨트롤러 및 KDC: `10.0.0.10`)
- **인증 기관 (CA)**: `CORP-DC-CA\corp-DC-CA`
- **취약 템플릿**: `ESC1_WebAuth` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 활성화, Client Authentication EKU 포함)
- **공격 시나리오**: 도메인 일반 사용자(`user1@corp.local`) -> ESC1 템플릿 탐색 및 Administrator SAN 인증서 발급 -> PKINIT AS-REQ 인증을 통한 Domain Admin TGT 티켓 획득 -> S4U2Self/S4U2Proxy 제약 위임 악용을 통한 중요 서버 장악 -> Protected Users 및 AD CS 템플릿 하드닝

---

## 2. 3단계 CTF 챌린지 (Challenges)

### Step 1: AD CS ESC1 템플릿 탐색 및 Domain Admin SAN 인증서 발급
- **취약점**: `ESC1_WebAuth` 인증서 템플릿의 `msPKI-Certificate-Name-Flag`에 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)` 플래그가 설정되어 있어, 신청자(Enrollee)가 임의의 SAN(Subject Alternative Name)을 지정할 수 있습니다.
- **공격 목표**: `Domain Users` 권한으로 `administrator@corp.local`의 UPN을 담은 SAN 인증서를 요청하고 `.pfx` 개인키/인증서 아카이브를 추출합니다.
- **플래그 1**: `FLAG{adcs_esc1_enrollee_supplies_san_admin_cert_issued_8029}`

### Step 2: PKINIT 인증을 통한 Kerberos TGT 획득 & Pass-the-Certificate
- **취약점**: 발급된 인증서에 `Client Authentication (1.3.6.1.5.5.7.3.2)` EKU가 포함되어 있어 Kerberos PKINIT(RFC 4556, `pA-PK-AS-REQ`) 인증에 사용될 수 있습니다.
- **공격 목표**: KDC에 인증서를 제출하여 도메인 관리자 명의의 TGT(Ticket Granting Ticket, `.ccache`) 및 NTLM 해시를 추출하고 Pass-the-Certificate 공격을 완성합니다.
- **플래그 2**: `FLAG{pkinit_tgt_acquired_pass_the_certificate_domain_admin_5921}`

### Step 3: Kerberos Constrained Delegation (S4U2Self / S4U2Proxy) 악용 & 엔터프라이즈 하드닝
- **취약점**: 웹 서비스 계정(`svc_web$`)이 `msDS-AllowedToDelegateTo = cifs/fileserver.corp.local` 속성을 보유할 때, S4U2Self로 임의 관리자 Impersonation 티켓을 위조하고 S4U2Proxy로 파일 서버를 무인증 장악할 수 있습니다.
- **방어 목표**:
  1. 관리자 계정에 `Account is sensitive and cannot be delegated` 플래그 설정
  2. 도메인 관리자 계정을 `Protected Users` 보안 그룹에 강제 등록
  3. AD CS 템플릿에서 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 제거 및 CA 관리자 승인 필수화
  4. AD CS 웹 등록(CES/NDES)에 EPA(확장 인증 보호) 강제 적용 및 HTTP 비활성화 (ESC8 NTLM Relay 원천 차단)
- **플래그 3**: `FLAG{kerberos_delegation_s4u_rbcd_hardened_protected_users_9312}`

---

## 3. API 엔드포인트 명세 (API Endpoints)

| 메소드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/health` | 랩 상태 및 포트 8029 헬스체크 |
| `GET` | `/api/adcs/templates` | AD CS 인증서 템플릿 목록 및 취약성 플래그 점검 |
| `POST` | `/api/adcs/cert/request` | ESC1 취약 템플릿 악용 Domain Admin SAN 인증서 발급 |
| `POST` | `/api/adcs/pkinit/auth` | 발급된 인증서를 이용한 PKINIT TGT 획득 및 PAC 분석 |
| `POST` | `/api/adcs/delegation/simulate` | S4U2Self / S4U2Proxy 제약 위임 공격 시뮬레이션 |
| `POST` | `/api/adcs/delegation/harden` | Protected Users 등록, Delegation 제한, AD CS 하드닝 적용 |
| `POST` | `/api/adcs/reset` | 실습 상태 초기화 |
