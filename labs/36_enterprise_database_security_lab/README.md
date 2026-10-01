# Lab 36: 엔터프라이즈 데이터베이스 보안 & 권한 탈취/하드닝 랩 (DBShield)

> **포트**: `8036` | **대상**: RDBMS 침투 분석관, DB 관리자(DBA), 보안 엔지니어  
> **연계 교재**: `23_Database_Hacking/07_enterprise_rdbms_privilege_escalation_and_injection_deepdive.md`  
> **연계 워게임 트랙**: `dbsec` (트랙 50)

---

## 1. 랩 개요

기업 환경에서 데이터베이스는 비즈니스 자산의 핵심 집약체입니다. 본 실습 랩에서는 1차 웹 입력 필터를 우회하여 저장된 후 내부 신뢰 쿼리에서 실행되는 **2차 SQL 인젝션(Second-Order SQLi)** 과, 고권한 DB 계정을 탈취하여 악성 공유 라이브러리를 동적 적재하는 **MySQL UDF(User-Defined Function) 바이너리 인젝션 RCE**, 그리고 이를 원천 무력화하는 **엔터프라이즈 다계층 하드닝(파라미터화 쿼리, secure_file_priv=NULL, 최소 권한 RBAC, FGA 세밀 감사)** 체계를 실습합니다.

---

## 2. 실습 단계 및 플래그

| 단계 | 침투 / 방어 주제 | 획득 플래그 |
| :---: | :--- | :--- |
| **Step 1** | 2차 SQL 인젝션을 통한 DBA 메타데이터 및 암호 해시 탈취 | `FLAG{DB_SECOND_ORDER_SQLI_METADATA_EXFIL_8831}` |
| **Step 2** | MySQL UDF 라이브러리 로드 및 시스템 루트 OS 커맨드 실행 (RCE) | `FLAG{DB_UDF_LIBRARY_INJECTION_ROOT_RCE_7492}` |
| **Step 3** | 엔터프라이즈 DB 하드닝 (파라미터화 쿼리, 파일시스템 격리, FGA 감사) | `FLAG{DB_AUDIT_LOG_TDE_LEAST_PRIVILEGE_SECURED_3914}` |

---

## 3. 실습 가이드

### Step 1: 2차 SQL 인젝션 (Second-Order SQLi)
1. 신규 프로필 등록 엔드포인트(`POST /api/db/register`)를 통해 닉네임 필드에 SQLi 페이로드를 전달합니다:
   ```json
   {
     "username": "attacker",
     "nickname_payload": "admin' OR 1=1 --",
     "email": "attacker@vibe.local"
   }
   ```
2. 비밀번호 재설정 모듈(`POST /api/db/password-reset`)을 트리거합니다:
   ```json
   {
     "username": "attacker"
   }
   ```
3. 저장되어 있던 닉네임 페이로드가 내부 `SELECT` 쿼리에 동적 결합되어 DBA의 비밀번호 해시 및 플래그를 탈취합니다.

### Step 2: UDF 바이너리 인젝션 & RCE
1. UDF 라이브러리 설치 엔드포인트(`POST /api/db/udf-install`)를 호출하여 악성 공유 객체(`raptor_udf2.so`)를 MySQL 플러그인 공간에 등록합니다:
   ```json
   {
     "function_name": "sys_eval",
     "library_name": "raptor_udf2.so"
   }
   ```
2. UDF 실행 엔드포인트(`POST /api/db/udf-exec`)로 시스템 명령(`whoami` 또는 `id`)을 전송하여 호스트 root 권한을 증명하고 플래그를 획득합니다.

### Step 3: 엔터프라이즈 DB 다계층 하드닝
1. 보안 하드닝 엔드포인트(`POST /api/db/harden`)를 호출하여 모든 통제 정책을 활성화합니다:
   ```json
   {
     "enable_prepared_statements": true,
     "enforce_secure_file_priv": true,
     "isolate_least_privilege": true,
     "enable_fga_audit": true
   }
   ```
2. 이후 인젝션 및 UDF 실행이 모두 차단됨을 확인하고 방어 완료 플래그를 획득합니다.
