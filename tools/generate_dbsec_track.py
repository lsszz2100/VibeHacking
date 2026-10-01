#!/usr/bin/env python3
"""
Generates the 50th Wargame Track: 'dbsec' (Enterprise DB Security & Hardening - 35 Challenges)
Integrates cleanly into challenges.js, index.html, app.js, solve-derivable.js, and README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
INDEX_HTML = REPO_ROOT / "wargame" / "index.html"
APP_JS = REPO_ROOT / "wargame" / "assets" / "app.js"
SOLVE_DERIVABLE_JS = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
WARGAME_README = REPO_ROOT / "wargame" / "README.md"
CLI_TEST = REPO_ROOT / "wargame" / "tests" / "test_cli.py"

TRACK_INFO = {
    "id": "dbsec",
    "icon": "🗄️",
    "ko": "엔터프라이즈 DB 침투·하드닝",
    "en": "Enterprise DB Security & Hardening",
    "desc_ko": "2차 SQLi·MySQL UDF 바이너리 인젝션·Oracle PL/SQL 권한상승·OOB DNS 유출·FGA/TDE 다계층 DB 하드닝.",
    "desc_en": "Second-order SQLi, MySQL UDF binary injection, Oracle PL/SQL privilege escalation, OOB DNS exfiltration, and FGA/TDE hardening."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_dbsec_rdbms_privilege_model", 25,
     "엔터프라이즈 RDBMS 롤 기반 권한 체계",
     "Enterprise RDBMS Role-Based Access Control Architecture",
     "DBA, SYSDBA, sa, SUPER 등 고권한 롤과 일반 애플리케이션 DML 계정 간의 권한 격리 모델을 분석합니다.\n지정된 식별자 `dbsec_rdbms_privilege_model_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_rdbms_privilege_model_v1\") 앞 20자리}`",
     "Analyze RBAC models and privilege separation between DBA/sa and application users.\nCompute the first 20 hex characters of SHA256(\"dbsec_rdbms_privilege_model_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_rdbms_privilege_model_v1\") first 20 hex}`",
     ["DBA 권한과 최소 권한 DML 계정의 차이를 확인하세요.", "식별자 `dbsec_rdbms_privilege_model_v1`의 해시 앞 20자리를 추출하세요."],
     ["Distinguish administrative roles from least-privilege DML accounts.", "Extract first 20 hex chars of SHA256(\"dbsec_rdbms_privilege_model_v1\")."]),

    (0, "t0_dbsec_sql_parser_and_ast", 25,
     "SQL 파서 및 추상 구문 트리(AST) 쿼리 분해",
     "SQL Query Parser & Abstract Syntax Tree (AST) Tokenization",
     "Lexer와 Parser가 SQL 토큰을 결합하여 AST를 구축할 때 연산자 우선순위 변조 원리를 분석합니다.\n지정된 식별자 `dbsec_sql_parser_and_ast_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_sql_parser_and_ast_v1\") 앞 20자리}`",
     "Examine how SQL lexers and parsers construct ASTs and how syntax injection alters query trees.\nCompute the first 20 hex characters of SHA256(\"dbsec_sql_parser_and_ast_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_sql_parser_and_ast_v1\") first 20 hex}`",
     ["파서가 인라인 따옴표를 식별자/문자열 경계로 처리함을 확인하세요.", "식별자 `dbsec_sql_parser_and_ast_v1`의 해시 앞 20자리를 제출하세요."],
     ["Inspect quotes as string delimiter tokens in AST generation.", "Extract first 20 hex chars of SHA256(\"dbsec_sql_parser_and_ast_v1\")."]),

    (0, "t0_dbsec_prepared_statement_mechanism", 30,
     "Prepared Statement 데이터-코드 분리 메커니즘",
     "Prepared Statements & Parameterized Execution Mechanism",
     "DB 드라이버가 쿼리 템플릿을 사전 컴파일하고 파라미터를 리터럴로 바인딩하는 메커니즘을 분석합니다.\n지정된 식별자 `dbsec_prepared_statement_mechanism_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_prepared_statement_mechanism_v1\") 앞 20자리}`",
     "Review pre-compilation protocols and placeholder binding that prevent code/data confusion.\nCompute the first 20 hex characters of SHA256(\"dbsec_prepared_statement_mechanism_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_prepared_statement_mechanism_v1\") first 20 hex}`",
     ["파라미터 바인딩 시 따옴표가 이스케이프 문자열로만 전달됨을 확인하세요.", "식별자 `dbsec_prepared_statement_mechanism_v1`의 해시 앞 20자리를 추출하세요."],
     ["Verify bound parameters are strictly evaluated as literals.", "Extract first 20 hex chars of SHA256(\"dbsec_prepared_statement_mechanism_v1\")."]),

    (0, "t0_dbsec_mysql_information_schema", 30,
     "MySQL information_schema 시스템 딕셔너리 정찰",
     "MySQL information_schema Catalog Metadata Enumeration",
     "TABLES, COLUMNS, SCHEMATA 메타데이터 뷰를 조회하여 데이터베이스 구조를 정찰하는 원리를 분석합니다.\n지정된 식별자 `dbsec_mysql_information_schema_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mysql_information_schema_v1\") 앞 20자리}`",
     "Inspect information_schema.tables and columns metadata catalog structure.\nCompute the first 20 hex characters of SHA256(\"dbsec_mysql_information_schema_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mysql_information_schema_v1\") first 20 hex}`",
     ["테이블 목록 덤프 시 table_schema를 필터링하는 쿼리를 확인하세요.", "식별자 `dbsec_mysql_information_schema_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review filtering by table_schema for metadata extraction.", "Extract first 20 hex chars of SHA256(\"dbsec_mysql_information_schema_v1\")."]),

    (0, "t0_dbsec_oracle_data_dictionary", 35,
     "Oracle 데이터 딕셔너리 뷰 (ALL/USER/DBA_TABLES)",
     "Oracle Data Dictionary Architecture (ALL / USER / DBA Views)",
     "USER_TABLES, ALL_TAB_COLUMNS, DBA_ROLE_PRIVS 뷰를 활용한 오라클 스키마 정찰을 분석합니다.\n지정된 식별자 `dbsec_oracle_data_dictionary_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_oracle_data_dictionary_v1\") 앞 20자리}`",
     "Classify the three tiers of Oracle data dictionary views and catalog security.\nCompute the first 20 hex characters of SHA256(\"dbsec_oracle_data_dictionary_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_oracle_data_dictionary_v1\") first 20 hex}`",
     ["접근 가능한 객체 범위(USER vs ALL vs DBA)를 확인하세요.", "식별자 `dbsec_oracle_data_dictionary_v1`의 해시 앞 20자리를 추출하세요."],
     ["Distinguish dictionary accessibility across user scopes.", "Extract first 20 hex chars of SHA256(\"dbsec_oracle_data_dictionary_v1\")."]),

    (0, "t0_dbsec_password_hashing_algorithms", 30,
     "RDBMS 계정 암호 해싱 알고리즘 변천사",
     "RDBMS User Authentication & Password Hashing Algorithms",
     "MySQL mysql_native_password vs caching_sha2_password, Oracle 11g SHA-1 vs 12c+ PBKDF2-SHA512 암호 저장을 분석합니다.\n지정된 식별자 `dbsec_password_hashing_algorithms_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_password_hashing_algorithms_v1\") 앞 20자리}`",
     "Trace password hashing algorithms from SHA-1 to caching_sha2 and PBKDF2 across enterprise DBs.\nCompute the first 20 hex characters of SHA256(\"dbsec_password_hashing_algorithms_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_password_hashing_algorithms_v1\") first 20 hex}`",
     ["최신 DB가 솔트가 포함된 솔루션을 채택함을 확인하세요.", "식별자 `dbsec_password_hashing_algorithms_v1`의 해시 앞 20자리를 제출하세요."],
     ["Modern DBMS engines use salted iterations to deter rainbow tables.", "Extract first 20 hex chars of SHA256(\"dbsec_password_hashing_algorithms_v1\")."]),

    (0, "t0_dbsec_audit_trail_basics", 35,
     "데이터베이스 Audit Trail 감사 로그 기본 원리",
     "Database Audit Trail Architecture & Standard Event Logging",
     "연결 성공/실패, 관리자 DDL/DCL 이벤트 및 트랜잭션 redo 로그의 감사 기록 구조를 분석합니다.\n지정된 식별자 `dbsec_audit_trail_basics_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_audit_trail_basics_v1\") 앞 20자리}`",
     "Analyze basic audit trail mechanisms, connection auditing, and transactional event logs.\nCompute the first 20 hex characters of SHA256(\"dbsec_audit_trail_basics_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_audit_trail_basics_v1\") first 20 hex}`",
     ["감사 기록이 변조되지 않도록 분리된 스토리지에 저장되어야 함을 확인하세요.", "식별자 `dbsec_audit_trail_basics_v1`의 해시 앞 20자리를 추출하세요."],
     ["Ensure audit trails are directed to append-only storage.", "Extract first 20 hex chars of SHA256(\"dbsec_audit_trail_basics_v1\")."]),

    # Tier 1 (웹 서버/초급 침투: 7 challenges, points 40~55)
    (1, "t1_dbsec_second_order_sqli_concept", 45,
     "2차 SQL 인젝션(Second-Order) 지연 실행 메커니즘",
     "Second-Order SQL Injection Storage & Trigger Mechanism",
     "사용자 입력이 1차 INSERT 시점에는 안전하게 적재된 후, 2차 내부 쿼리 실행 시 발현되는 지연 인젝션 흐름을 분석합니다.\n지정된 식별자 `dbsec_second_order_sqli_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_second_order_sqli_concept_v1\") 앞 20자리}`",
     "Trace the two-phase lifecycle of stored payloads triggering in secondary trusted queries.\nCompute the first 20 hex characters of SHA256(\"dbsec_second_order_sqli_concept_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_second_order_sqli_concept_v1\") first 20 hex}`",
     ["저장 시점이 아니라 재조회 및 동적 조합 시점에 인젝션이 발생함을 확인하세요.", "식별자 `dbsec_second_order_sqli_concept_v1`의 해시 앞 20자리를 제출하세요."],
     ["Identify the decoupled storage phase from the execution phase.", "Extract first 20 hex chars of SHA256(\"dbsec_second_order_sqli_concept_v1\")."]),

    (1, "t1_dbsec_blind_time_based_inference", 45,
     "Blind Time-Based SQL 인젝션 SLEEP/WAITFOR 추론",
     "Blind Time-Based SQL Injection (SLEEP / WAITFOR Inference)",
     "SLEEP(), pg_sleep(), WAITFOR DELAY를 악용하여 참/거짓 조건에 따른 지연 응답으로 한 글자씩 데이터를 카빙합니다.\n지정된 식별자 `dbsec_blind_time_based_inference_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_blind_time_based_inference_v1\") 앞 20자리}`",
     "Model time-based boolean deduction via SLEEP and WAITFOR DELAY side channels.\nCompute the first 20 hex characters of SHA256(\"dbsec_blind_time_based_inference_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_blind_time_based_inference_v1\") first 20 hex}`",
     ["SUBSTRING 및 ASCII 함수로 각 자리 문자를 이진 탐색함을 확인하세요.", "식별자 `dbsec_blind_time_based_inference_v1`의 해시 앞 20자리를 추출하세요."],
     ["Use binary search on ASCII values combined with conditional sleep.", "Extract first 20 hex chars of SHA256(\"dbsec_blind_time_based_inference_v1\")."]),

    (1, "t1_dbsec_mysql_into_outfile_rce", 50,
     "INTO OUTFILE 웹셸 생성 및 secure_file_priv 제약",
     "MySQL SELECT INTO OUTFILE Web Shell Writing & secure_file_priv",
     "웹 디렉터리에 PHP 웹셸을 작성하기 위한 `SELECT ... INTO OUTFILE` 구문과 `secure_file_priv` 제약 우회를 분석합니다.\n지정된 식별자 `dbsec_mysql_into_outfile_rce_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mysql_into_outfile_rce_v1\") 앞 20자리}`",
     "Examine web shell dropping via INTO OUTFILE and barriers imposed by secure_file_priv.\nCompute the first 20 hex characters of SHA256(\"dbsec_mysql_into_outfile_rce_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mysql_into_outfile_rce_v1\") first 20 hex}`",
     ["secure_file_priv가 빈 문자열일 때만 임의 경로에 파일 쓰기가 가능함을 확인하세요.", "식별자 `dbsec_mysql_into_outfile_rce_v1`의 해시 앞 20자리를 제출하세요."],
     ["File writes succeed only when secure_file_priv is set to an empty string.", "Extract first 20 hex chars of SHA256(\"dbsec_mysql_into_outfile_rce_v1\")."]),

    (1, "t1_dbsec_mssql_xp_cmdshell_execution", 50,
     "MSSQL xp_cmdshell 확장 저장 프로시저 커맨드 실행",
     "MSSQL xp_cmdshell Extended Stored Procedure OS Execution",
     "sp_configure 'show advanced options', 1 및 'xp_cmdshell', 1 설정을 활성화하여 OS 셸을 탈취하는 공격을 분석합니다.\n지정된 식별자 `dbsec_mssql_xp_cmdshell_execution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mssql_xp_cmdshell_execution_v1\") 앞 20자리}`",
     "Analyze enabling and exploiting xp_cmdshell on MS SQL Server to drop into cmd.exe.\nCompute the first 20 hex characters of SHA256(\"dbsec_mssql_xp_cmdshell_execution_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mssql_xp_cmdshell_execution_v1\") first 20 hex}`",
     ["sysadmin 권한이 있어야 sp_configure로 프로시저를 재활성화할 수 있음을 확인하세요.", "식별자 `dbsec_mssql_xp_cmdshell_execution_v1`의 해시 앞 20자리를 추출하세요."],
     ["sysadmin role is required to re-enable disabled procedures via sp_configure.", "Extract first 20 hex chars of SHA256(\"dbsec_mssql_xp_cmdshell_execution_v1\")."]),

    (1, "t1_dbsec_postgresql_copy_from_program", 50,
     "PostgreSQL COPY ... FROM PROGRAM RCE 벡터",
     "PostgreSQL COPY ... FROM PROGRAM Arbitrary Command Execution",
     "PostgreSQL 9.3+ 슈퍼유저 권한에서 `COPY table FROM PROGRAM 'cmd'` 구문으로 OS 명령을 실행하는 원리를 분석합니다.\n지정된 식별자 `dbsec_postgresql_copy_from_program_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_postgresql_copy_from_program_v1\") 앞 20자리}`",
     "Evaluate PostgreSQL superuser command injection via COPY ... FROM PROGRAM pipe syntax.\nCompute the first 20 hex characters of SHA256(\"dbsec_postgresql_copy_from_program_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_postgresql_copy_from_program_v1\") first 20 hex}`",
     ["pg_execute_server_program 롤이 명령 실행에 관여함을 확인하세요.", "식별자 `dbsec_postgresql_copy_from_program_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check membership in the pg_execute_server_program role.", "Extract first 20 hex chars of SHA256(\"dbsec_postgresql_copy_from_program_v1\")."]),

    (1, "t1_dbsec_mysql_load_file_sensitive_carving", 45,
     "LOAD_FILE()을 통한 시스템 중요 설정 및 키 유출",
     "MySQL LOAD_FILE() System Configuration & Key Carving",
     "`SELECT LOAD_FILE('/etc/passwd')` 또는 `/etc/mysql/my.cnf`를 호출하여 서버 내부 자격증명을 탈취합니다.\n지정된 식별자 `dbsec_mysql_load_file_sensitive_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mysql_load_file_sensitive_carving_v1\") 앞 20자리}`",
     "Analyze extracting sensitive host files via LOAD_FILE() and path traversal requirements.\nCompute the first 20 hex characters of SHA256(\"dbsec_mysql_load_file_sensitive_carving_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mysql_load_file_sensitive_carving_v1\") first 20 hex}`",
     ["파일 읽기 대상이 OS 파일 권한상 mysql 프로세스에 읽기 가능해야 함을 확인하세요.", "식별자 `dbsec_mysql_load_file_sensitive_carving_v1`의 해시 앞 20자리를 추출하세요."],
     ["Ensure target files have read permissions granted to the mysqld daemon user.", "Extract first 20 hex chars of SHA256(\"dbsec_mysql_load_file_sensitive_carving_v1\")."]),

    (1, "t1_dbsec_db_fingerprinting_heuristics", 40,
     "RDBMS 방언(Dialect) 휴리스틱 핑거프린팅",
     "RDBMS SQL Dialect & Behavioral Heuristic Fingerprinting",
     "문자열 결합(`||` vs `+` vs `CONCAT()`), 시스템 주석, 버전 함수(`@@version`, `VERSION()`, `BANNER`)로 엔진을 판별합니다.\n지정된 식별자 `dbsec_db_fingerprinting_heuristics_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_db_fingerprinting_heuristics_v1\") 앞 20자리}`",
     "Heuristically fingerprint database vendors using concatenation syntax and version constants.\nCompute the first 20 hex characters of SHA256(\"dbsec_db_fingerprinting_heuristics_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_db_fingerprinting_heuristics_v1\") first 20 hex}`",
     ["오라클은 FROM DUAL이 필수이며 MSSQL은 @@version을 지원함을 확인하세요.", "식별자 `dbsec_db_fingerprinting_heuristics_v1`의 해시 앞 20자리를 제출하세요."],
     ["Note Oracle mandates DUAL table syntax while MSSQL uses @@version.", "Extract first 20 hex chars of SHA256(\"dbsec_db_fingerprinting_heuristics_v1\")."]),

    # Tier 2 (내부망 권한상승: 7 challenges, points 60~75)
    (2, "t2_dbsec_udf_dynamic_library_injection", 65,
     "MySQL UDF 악성 공유 라이브러리 적재 및 sys_eval RCE",
     "MySQL UDF (User-Defined Function) Shared Library Injection & sys_eval",
     "16진수 ELF 라이브러리를 플러그인 디렉터리에 DUMPFILE로 쓰고 `CREATE FUNCTION sys_eval`로 루트 셸을 탈취합니다.\n지정된 식별자 `dbsec_udf_dynamic_library_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_udf_dynamic_library_injection_v1\") 앞 20자리}`",
     "Drop a malicious .so into the plugin directory and register sys_eval for host code execution.\nCompute the first 20 hex characters of SHA256(\"dbsec_udf_dynamic_library_injection_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_udf_dynamic_library_injection_v1\") first 20 hex}`",
     ["plugin_dir 경로와 secure_file_priv 설정을 확인하세요.", "식별자 `dbsec_udf_dynamic_library_injection_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check plugin_dir and ensure secure_file_priv does not restrict dumping.", "Extract first 20 hex chars of SHA256(\"dbsec_udf_dynamic_library_injection_v1\")."]),

    (2, "t2_dbsec_oracle_plsql_definer_rights_privesc", 65,
     "Oracle AUTHID DEFINER 패키지 인젝션 및 DBA 권한상승",
     "Oracle PL/SQL AUTHID DEFINER Package Injection to DBA Escalation",
     "SYS 계정의 정의자 권한(AUTHID DEFINER) 프로시저에 동적 SQL 인젝션을 유도하여 일반 계정에 DBA 롤을 부여합니다.\n지정된 식별자 `dbsec_oracle_plsql_definer_rights_privesc_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_oracle_plsql_definer_rights_privesc_v1\") 앞 20자리}`",
     "Exploit dynamic EXECUTE IMMEDIATE inside SYS definer-rights procedures to grant DBA roles.\nCompute the first 20 hex characters of SHA256(\"dbsec_oracle_plsql_definer_rights_privesc_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_oracle_plsql_definer_rights_privesc_v1\") first 20 hex}`",
     ["PRAGMA AUTONOMOUS_TRANSACTION으로 독립 트랜잭션을 실행함을 확인하세요.", "식별자 `dbsec_oracle_plsql_definer_rights_privesc_v1`의 해시 앞 20자리를 추출하세요."],
     ["Use autonomous transactions to execute privileged DDL inside query context.", "Extract first 20 hex chars of SHA256(\"dbsec_oracle_plsql_definer_rights_privesc_v1\")."]),

    (2, "t2_dbsec_oob_dns_exfiltration_tunnel", 70,
     "대역외(OOB) DNS 터널링을 통한 데이터 은닉 유출",
     "Out-of-Band (OOB) DNS Tunneling & Subdomain Data Exfiltration",
     "UTL_INADDR, xp_dirtree, dblink_connect를 통해 쿼리 결과를 16진수로 인코딩하여 DNS 질의로 유출합니다.\n지정된 식별자 `dbsec_oob_dns_exfiltration_tunnel_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_oob_dns_exfiltration_tunnel_v1\") 앞 20자리}`",
     "Tunnel exfiltrated query results as hex-encoded DNS queries via network procedures.\nCompute the first 20 hex characters of SHA256(\"dbsec_oob_dns_exfiltration_tunnel_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_oob_dns_exfiltration_tunnel_v1\") first 20 hex}`",
     ["인그레스 방화벽이 외부 직접 연결을 막더라도 DNS 재귀 조회가 동작함을 확인하세요.", "식별자 `dbsec_oob_dns_exfiltration_tunnel_v1`의 해시 앞 20자리를 제출하세요."],
     ["DNS recursive queries bypass outbound TCP egress firewalls.", "Extract first 20 hex chars of SHA256(\"dbsec_oob_dns_exfiltration_tunnel_v1\")."]),

    (2, "t2_dbsec_mssql_linked_servers_pivot", 65,
     "MSSQL Linked Servers 체인을 악용한 인접 DB 피벗",
     "MSSQL Linked Servers Chain Pivoting & RPC Impersonation",
     "`OPENQUERY()` 및 RPC Out 설정을 악용하여 연결된 원격 SQL Server 인스턴스로 권한을 횡적으로 전파합니다.\n지정된 식별자 `dbsec_mssql_linked_servers_pivot_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mssql_linked_servers_pivot_v1\") 앞 20자리}`",
     "Traverse linked SQL Server configurations via OPENQUERY to execute remote administrative tasks.\nCompute the first 20 hex characters of SHA256(\"dbsec_mssql_linked_servers_pivot_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mssql_linked_servers_pivot_v1\") first 20 hex}`",
     ["sp_linkedservers 뷰를 확인하여 링크된 인스턴스를 열거하세요.", "식별자 `dbsec_mssql_linked_servers_pivot_v1`의 해시 앞 20자리를 추출하세요."],
     ["Query sys.servers and sp_linkedservers to discover remote links.", "Extract first 20 hex chars of SHA256(\"dbsec_mssql_linked_servers_pivot_v1\")."]),

    (2, "t2_dbsec_postgresql_large_objects_carving", 60,
     "PostgreSQL Large Objects (pg_largeobject) 파일 주입",
     "PostgreSQL Large Object (pg_largeobject) Arbitrary File Staging",
     "`lo_create()`, `lo_put()` 함수를 이용해 악성 공유 객체 청크를 DB에 적재한 뒤 디스크에 생성하는 공격을 분석합니다.\n지정된 식별자 `dbsec_postgresql_large_objects_carving_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_postgresql_large_objects_carving_v1\") 앞 20자리}`",
     "Stage binary payloads via pg_largeobject chunking and export them to disk via lo_export.\nCompute the first 20 hex characters of SHA256(\"dbsec_postgresql_large_objects_carving_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_postgresql_large_objects_carving_v1\") first 20 hex}`",
     ["lo_export()로 파일시스템에 바이너리를 쓰는 절차를 확인하세요.", "식별자 `dbsec_postgresql_large_objects_carving_v1`의 해시 앞 20자리를 제출하세요."],
     ["Use lo_export() to dump in-database large objects into filesystem binaries.", "Extract first 20 hex chars of SHA256(\"dbsec_postgresql_large_objects_carving_v1\")."]),

    (2, "t2_dbsec_mysql_general_log_webshell", 60,
     "MySQL general_log 파일 경로 변조를 통한 웹셸 주입",
     "MySQL general_log Logfile Overwrite & Web Shell Poisoning",
     "`SET GLOBAL general_log = 'ON'` 및 `general_log_file = '/var/www/html/shell.php'`를 지정하여 웹셸을 투하합니다.\n지정된 식별자 `dbsec_mysql_general_log_webshell_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_mysql_general_log_webshell_v1\") 앞 20자리}`",
     "Repoint MySQL general_log_file to web roots and issue payload queries to drop shells.\nCompute the first 20 hex characters of SHA256(\"dbsec_mysql_general_log_webshell_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_mysql_general_log_webshell_v1\") first 20 hex}`",
     ["global 변수 수정 시 SUPER 권한이 필요함을 확인하세요.", "식별자 `dbsec_mysql_general_log_webshell_v1`의 해시 앞 20자리를 추출하세요."],
     ["Manipulating general_log_file requires the SUPER or SYSTEM_VARIABLES_ADMIN privilege.", "Extract first 20 hex chars of SHA256(\"dbsec_mysql_general_log_webshell_v1\")."]),

    (2, "t2_dbsec_database_network_tls_sniffing", 65,
     "데이터베이스 비암호화 통신 패킷 스니핑 & 자격증명 복원",
     "Database Cleartext Traffic Sniffing & Credential Harvesting",
     "TLS/SSL이 강제되지 않은 MySQL/Oracle 통신에서 Wireshark로 사용자 쿼리 및 인증 핸드셰이크를 복원합니다.\n지정된 식별자 `dbsec_database_network_tls_sniffing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_database_network_tls_sniffing_v1\") 앞 20자리}`",
     "Capture and reconstruct unencrypted database traffic to harvest plaintext credentials and data.\nCompute the first 20 hex characters of SHA256(\"dbsec_database_network_tls_sniffing_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_database_network_tls_sniffing_v1\") first 20 hex}`",
     ["REQUIRE SSL 옵션이 없는 사용자 계정의 위험성을 확인하세요.", "식별자 `dbsec_database_network_tls_sniffing_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify accounts configured without REQUIRE SSL expose transit data to sniffing.", "Extract first 20 hex chars of SHA256(\"dbsec_database_network_tls_sniffing_v1\")."]),

    # Tier 3 (금고/보안 하드닝: 7 challenges, points 80~95)
    (3, "t3_dbsec_oracle_fga_fine_grained_auditing", 85,
     "Oracle Fine-Grained Auditing (FGA) 정책 설계 및 감사",
     "Oracle Fine-Grained Auditing (FGA) Policy Design & Compliance",
     "DBMS_FGA.ADD_POLICY를 통해 특정 민감 컬럼(급여, 주민번호) 조회 시 조건부 불변 감사 로그를 기록합니다.\n지정된 식별자 `dbsec_oracle_fga_fine_grained_auditing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_oracle_fga_fine_grained_auditing_v1\") 앞 20자리}`",
     "Deploy DBMS_FGA policies to capture fine-grained SQL queries and bind variables on sensitive columns.\nCompute the first 20 hex characters of SHA256(\"dbsec_oracle_fga_fine_grained_auditing_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_oracle_fga_fine_grained_auditing_v1\") first 20 hex}`",
     ["FGA 감사 뷰(DBA_FGA_AUDIT_TRAIL)에서 실행 쿼리 전문을 확인하세요.", "식별자 `dbsec_oracle_fga_fine_grained_auditing_v1`의 해시 앞 20자리를 추출하세요."],
     ["Inspect DBA_FGA_AUDIT_TRAIL for captured SQL text and bind parameters.", "Extract first 20 hex chars of SHA256(\"dbsec_oracle_fga_fine_grained_auditing_v1\")."]),

    (3, "t3_dbsec_transparent_data_encryption_tde", 85,
     "투명 데이터 암호화(TDE) 키 관리 및 테이블스페이스 보호",
     "Transparent Data Encryption (TDE) Keystore & Tablespace Protection",
     "스토리지 레벨(Data at Rest)에서 AES-256 암호화를 적용하여 물리 디스크 탈취 시 데이터 유출을 원천 방어합니다.\n지정된 식별자 `dbsec_transparent_data_encryption_tde_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_transparent_data_encryption_tde_v1\") 앞 20자리}`",
     "Encrypt database tablespaces at rest with AES-256 and isolate master encryption keys.\nCompute the first 20 hex characters of SHA256(\"dbsec_transparent_data_encryption_tde_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_transparent_data_encryption_tde_v1\") first 20 hex}`",
     ["마스터 키가 HSM 또는 안전한 키스토어에 저장됨을 확인하세요.", "식별자 `dbsec_transparent_data_encryption_tde_v1`의 해시 앞 20자리를 제출하세요."],
     ["Master keys must be stored in external hardware security modules or secure keystores.", "Extract first 20 hex chars of SHA256(\"dbsec_transparent_data_encryption_tde_v1\")."]),

    (3, "t3_dbsec_secure_file_priv_isolation", 80,
     "secure_file_priv=NULL 설정을 통한 파일 입출력 원천 차단",
     "Enforcing secure_file_priv=NULL to Block Disk Staging & UDFs",
     "MySQL my.cnf에 `secure_file_priv = NULL`을 설정하여 INTO OUTFILE 및 LOAD_FILE() 공격을 완전히 무력화합니다.\n지정된 식별자 `dbsec_secure_file_priv_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_secure_file_priv_isolation_v1\") 앞 20자리}`",
     "Lock down file operations by setting secure_file_priv to NULL across configuration files.\nCompute the first 20 hex characters of SHA256(\"dbsec_secure_file_priv_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_secure_file_priv_isolation_v1\") first 20 hex}`",
     ["NULL 설정 시 어떤 디렉터리도 파일 입출력 대상으로 허용되지 않음을 확인하세요.", "식별자 `dbsec_secure_file_priv_isolation_v1`의 해시 앞 20자리를 제출하세요."],
     ["A NULL setting completely disables all LOAD DATA and SELECT ... INTO OUTFILE commands.", "Extract first 20 hex chars of SHA256(\"dbsec_secure_file_priv_isolation_v1\")."]),

    (3, "t3_dbsec_least_privilege_schema_rbac", 85,
     "최소 권한 원칙(PoLP)에 기반한 스키마 뷰 격리",
     "Schema View Isolation & Principle of Least Privilege (PoLP)",
     "애플리케이션 계정에 원본 테이블 대신 특정 컬럼만 필터링된 VIEW에 대한 SELECT 권한만 부여하여 침해 피해를 최소화합니다.\n지정된 식별자 `dbsec_least_privilege_schema_rbac_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_least_privilege_schema_rbac_v1\") 앞 20자리}`",
     "Constrain application connections to filtered views rather than underlying tables.\nCompute the first 20 hex characters of SHA256(\"dbsec_least_privilege_schema_rbac_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_least_privilege_schema_rbac_v1\") first 20 hex}`",
     ["DCL/DDL 권한을 철저히 배제하고 DML 권한도 뷰 단위로 세분화하세요.", "식별자 `dbsec_least_privilege_schema_rbac_v1`의 해시 앞 20자리를 제출하세요."],
     ["Revoke raw table access in favor of restricted columnar views.", "Extract first 20 hex chars of SHA256(\"dbsec_least_privilege_schema_rbac_v1\")."]),

    (3, "t3_dbsec_sql_firewall_and_allowlist", 90,
     "SQL 방화벽(SQL Firewall) 학습 및 정상 쿼리 화이트리스트",
     "Database SQL Firewall Behavioral Learning & Query Whitelisting",
     "정상 애플리케이션의 쿼리 시그니처와 컨텍스트(사용자, IP, 쿼리 해시)를 학습하여 변조된 쿼리를 인라인 차단합니다.\n지정된 식별자 `dbsec_sql_firewall_and_allowlist_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_sql_firewall_and_allowlist_v1\") 앞 20자리}`",
     "Implement Oracle SQL Firewall or GreenSQL reverse proxy whitelists to block unauthorized ASTs.\nCompute the first 20 hex characters of SHA256(\"dbsec_sql_firewall_and_allowlist_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_sql_firewall_and_allowlist_v1\") first 20 hex}`",
     ["학습 모드(Training)에서 실운영 모드(Enforcing)로 전환하는 절차를 확인하세요.", "식별자 `dbsec_sql_firewall_and_allowlist_v1`의 해시 앞 20자리를 제출하세요."],
     ["Switch from learning to blocking mode to reject unseen query signatures.", "Extract first 20 hex chars of SHA256(\"dbsec_sql_firewall_and_allowlist_v1\")."]),

    (3, "t3_dbsec_data_masking_and_tokenization", 85,
     "동적 데이터 마스킹(DDM) 및 비가역 토큰화",
     "Dynamic Data Masking (DDM) & Cryptographic Tokenization",
     "조회 계정의 권한에 따라 주민등록번호 뒷자리나 카드 번호를 실시간으로 마스킹(`XXXX-XXXX-XXXX-1234`) 처리합니다.\n지정된 식별자 `dbsec_data_masking_and_tokenization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_data_masking_and_tokenization_v1\") 앞 20자리}`",
     "Mask sensitive PII dynamically based on user identity without altering underlying storage.\nCompute the first 20 hex characters of SHA256(\"dbsec_data_masking_and_tokenization_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_data_masking_and_tokenization_v1\") first 20 hex}`",
     ["UNMASK 권한을 가진 인가된 보안 담당자만 평문을 조회할 수 있음을 확인하세요.", "식별자 `dbsec_data_masking_and_tokenization_v1`의 해시 앞 20자리를 제출하세요."],
     ["Only identities explicitly granted the UNMASK privilege see unredacted values.", "Extract first 20 hex chars of SHA256(\"dbsec_data_masking_and_tokenization_v1\")."]),

    (3, "t3_dbsec_binlog_forensics_reconstruction", 90,
     "MySQL Binlog / Oracle Redo Log 침해 사고 포렌식",
     "Binary Log & Redo Log Digital Forensics Reconstruction",
     "`mysqlbinlog --base64-output=DECODE-ROWS -v`로 공격자의 침투 쿼리 타임라인과 위변조된 레코드를 역추적합니다.\n지정된 식별자 `dbsec_binlog_forensics_reconstruction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_binlog_forensics_reconstruction_v1\") 앞 20자리}`",
     "Reconstruct malicious attacker transactions by decoding binary logs and redo streams.\nCompute the first 20 hex characters of SHA256(\"dbsec_binlog_forensics_reconstruction_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_binlog_forensics_reconstruction_v1\") first 20 hex}`",
     ["Row-based binlog에서 UPDATE 전후(Before/After) 이미지를 비교하세요.", "식별자 `dbsec_binlog_forensics_reconstruction_v1`의 해시 앞 20자리를 추출하세요."],
     ["Compare before-and-after image tuples recorded in row-based replication logs.", "Extract first 20 hex chars of SHA256(\"dbsec_binlog_forensics_reconstruction_v1\")."]),

    # Tier 4 (코어/크라운주얼: 7 challenges, points 100~120)
    (4, "t4_dbsec_apparmor_selinux_mysqld_containment", 100,
     "AppArmor/SELinux 강제 모드를 통한 DB 프로세스 격리",
     "AppArmor / SELinux Enforcing Containment for Database Daemons",
     "mysqld 프로세스에 SELinux enforcing 및 엄격한 AppArmor 프로파일을 적용하여 플러그인 로드 및 임의 바이너리 실행을 차단합니다.\n지정된 식별자 `dbsec_apparmor_selinux_mysqld_containment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_apparmor_selinux_mysqld_containment_v1\") 앞 20자리}`",
     "Contain database processes via SELinux mysqld_t domains and AppArmor enforcement.\nCompute the first 20 hex characters of SHA256(\"dbsec_apparmor_selinux_mysqld_containment_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_apparmor_selinux_mysqld_containment_v1\") first 20 hex}`",
     ["UDF가 적재되더라도 시스템 셸 popen() 호출 시 AVC 데니얼이 발생함을 확인하세요.", "식별자 `dbsec_apparmor_selinux_mysqld_containment_v1`의 해시 앞 20자리를 제출하세요."],
     ["Kernel LSM denials block popen() and execve() even if UDFs are instantiated.", "Extract first 20 hex chars of SHA256(\"dbsec_apparmor_selinux_mysqld_containment_v1\")."]),

    (4, "t4_dbsec_zero_trust_database_access_mesh", 105,
     "Zero Trust 데이터베이스 접근 제어 (mTLS & 임시 토큰)",
     "Zero Trust Database Access Architecture (mTLS & Ephemeral Credentials)",
     "정적 비밀번호를 전면 폐기하고 HashiCorp Vault 또는 AWS IAM DB 인증을 통한 15분 만료 임시 토큰 및 mTLS 통신을 강제합니다.\n지정된 식별자 `dbsec_zero_trust_database_access_mesh_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_zero_trust_database_access_mesh_v1\") 앞 20자리}`",
     "Eliminate static database credentials using HashiCorp Vault dynamic leases and mTLS client certs.\nCompute the first 20 hex characters of SHA256(\"dbsec_zero_trust_database_access_mesh_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_zero_trust_database_access_mesh_v1\") first 20 hex}`",
     ["단기 토큰 만료로 인해 자격증명이 유출되더라도 즉각 무효화됨을 확인하세요.", "식별자 `dbsec_zero_trust_database_access_mesh_v1`의 해시 앞 20자리를 추출하세요."],
     ["Ephemeral tokens ensure compromised connection strings expire within minutes.", "Extract first 20 hex chars of SHA256(\"dbsec_zero_trust_database_access_mesh_v1\")."]),

    (4, "t4_dbsec_oracle_unified_auditing_tamper_proof", 110,
     "Oracle Unified Auditing 불변 감사 및 SIEM 연동 파이프라인",
     "Oracle Unified Auditing Immutable Audit Trails & SIEM Ingestion",
     "전통적 감사 뷰를 Unified Audit Trail(AUDSYS)로 전환하고 syslog/Kafka 파이프라인으로 SIEM에 실시간 전송합니다.\n지정된 식별자 `dbsec_oracle_unified_auditing_tamper_proof_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_oracle_unified_auditing_tamper_proof_v1\") 앞 20자리}`",
     "Centralize tamper-proof AUDSYS unified auditing and stream telemetry to enterprise SIEMs.\nCompute the first 20 hex characters of SHA256(\"dbsec_oracle_unified_auditing_tamper_proof_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_oracle_unified_auditing_tamper_proof_v1\") first 20 hex}`",
     ["DBA 계정도 AUDSYS 테이블의 감사 기록을 수정할 수 없음을 확인하세요.", "식별자 `dbsec_oracle_unified_auditing_tamper_proof_v1`의 해시 앞 20자리를 추출하세요."],
     ["AUDSYS partition tables are protected from tampering even by DBAs.", "Extract first 20 hex chars of SHA256(\"dbsec_oracle_unified_auditing_tamper_proof_v1\")."]),

    (4, "t4_dbsec_quantum_resistant_db_cryptography", 105,
     "포스트 퀀텀(PQC) RDBMS 스토리지 암호화 아키텍처",
     "Post-Quantum Cryptography (PQC) RDBMS Column-Level Protection",
     "NIST FIPS 203/204 표준(ML-KEM / ML-DSA)을 기반으로 장기 보존 민감 데이터 컬럼을 양자 컴퓨터 해독으로부터 보호합니다.\n지정된 식별자 `dbsec_quantum_resistant_db_cryptography_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_quantum_resistant_db_cryptography_v1\") 앞 20자리}`",
     "Shield long-retention encrypted columns with NIST post-quantum ML-KEM/ML-DSA primitives.\nCompute the first 20 hex characters of SHA256(\"dbsec_quantum_resistant_db_cryptography_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_quantum_resistant_db_cryptography_v1\") first 20 hex}`",
     ["Harvest Now, Decrypt Later(HNDL) 공격을 차단하는 원리를 확인하세요.", "식별자 `dbsec_quantum_resistant_db_cryptography_v1`의 해시 앞 20자리를 추출하세요."],
     ["PQC protection mitigates Harvest-Now-Decrypt-Later threats against archive databases.", "Extract first 20 hex chars of SHA256(\"dbsec_quantum_resistant_db_cryptography_v1\")."]),

    (4, "t4_dbsec_ebpf_database_kernel_monitoring", 110,
     "eBPF 커널 레벨 데이터베이스 쿼리 및 소켓 무결성 감시",
     "eBPF Kernel-Level Database Wire Protocol & Socket Auditing",
     "TDS/MySQL 프로토콜 통신을 eBPF uprobe/kprobe로 커널 공간에서 직접 파싱하여 은닉 SQLi 및 데이터 유출을 감지합니다.\n지정된 식별자 `dbsec_ebpf_database_kernel_monitoring_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_ebpf_database_kernel_monitoring_v1\") 앞 20자리}`",
     "Monitor database socket buffers and query telemetry in kernel space via eBPF probes.\nCompute the first 20 hex characters of SHA256(\"dbsec_ebpf_database_kernel_monitoring_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_ebpf_database_kernel_monitoring_v1\") first 20 hex}`",
     ["사용자 영역 디버거를 거치지 않고 커널에서 제로 오버헤드로 패킷을 검사함을 확인하세요.", "식별자 `dbsec_ebpf_database_kernel_monitoring_v1`의 해시 앞 20자리를 제출하세요."],
     ["eBPF inspects query buffers without introducing user-space proxy latency.", "Extract first 20 hex chars of SHA256(\"dbsec_ebpf_database_kernel_monitoring_v1\")."]),

    (4, "t4_dbsec_soar_automated_db_quarantine", 110,
     "SOAR 연동 이상 쿼리 탐지 시 계정 자동 잠금 플레이북",
     "SOAR-Driven Automated Database Threat Containment & Account Lockout",
     "대용량 테이블 스캔 및 UDF 생성 징후 탐지 시 방화벽 세션 강제 종료(KILL CONNECTION) 및 계정 즉시 잠금을 수행합니다.\n지정된 식별자 `dbsec_soar_automated_db_quarantine_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_soar_automated_db_quarantine_v1\") 앞 20자리}`",
     "Orchestrate automatic account suspension and connection termination upon malicious query alarms.\nCompute the first 20 hex characters of SHA256(\"dbsec_soar_automated_db_quarantine_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_soar_automated_db_quarantine_v1\") first 20 hex}`",
     ["ALTER USER account ACCOUNT LOCK 구문이 자동 호출됨을 확인하세요.", "식별자 `dbsec_soar_automated_db_quarantine_v1`의 해시 앞 20자리를 제출하세요."],
     ["SOAR triggers automated account locks and socket severance to isolate attacks.", "Extract first 20 hex chars of SHA256(\"dbsec_soar_automated_db_quarantine_v1\")."]),

    (4, "t4_dbsec_capstone_full_enterprise_audit", 120,
     "엔터프라이즈 데이터베이스 캡스톤 종합 보안 침투 & 감사",
     "Enterprise Database Security Capstone Full Chain Audit",
     "2차 SQLi, UDF 메모리 침투, 권한 상승을 진단하고 TDE, FGA, 최소 권한으로 완벽 하드닝을 완성하는 캡스톤 평가입니다.\n지정된 식별자 `dbsec_capstone_full_enterprise_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"dbsec_capstone_full_enterprise_audit_v1\") 앞 20자리}`",
     "Synthesize the entire attack and defense spectrum across Second-Order SQLi, UDFs, and FGA hardening.\nCompute the first 20 hex characters of SHA256(\"dbsec_capstone_full_enterprise_audit_v1\").\n\nFormat: `FLAG{SHA256(\"dbsec_capstone_full_enterprise_audit_v1\") first 20 hex}`",
     ["침투 단계와 방어 단계를 종합 검증하여 캡스톤 플래그를 획득하세요.", "식별자 `dbsec_capstone_full_enterprise_audit_v1`의 해시 앞 20자리를 제출하세요."],
     ["Unify offensive exploitation with enterprise defensive posture.", "Extract first 20 hex chars of SHA256(\"dbsec_capstone_full_enterprise_audit_v1\")."])
]


def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, t_ko, t_en, p_ko, p_en, h_ko, h_en in RAW_CHALLENGES:
        ident = cid.replace("t0_", "").replace("t1_", "").replace("t2_", "").replace("t3_", "").replace("t4_", "") + "_v1"
        sha_hex = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{sha_hex}}}"
        h = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        chal = {
            "id": cid,
            "tier": tier,
            "cat": "database",
            "track": "dbsec",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": t_ko, "en": t_en},
            "prompt": {"ko": p_ko, "en": p_en},
            "hints": {"ko": h_ko, "en": h_en},
            "hash": h
        }
        challenges.append(chal)
        ids.append(cid)
    return challenges, ids


def update_challenges_js(challenges):
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Check if dbsec track is already present in TRACKS
    if '"id": "dbsec"' not in content[:pos_tracks_end]:
        prev_chunk = content[:bracket_pos].rstrip()
        if not prev_chunk.endswith(","):
            prev_chunk += ","
        content = prev_chunk + "\n  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]
        print("  ✓ Inserted 'dbsec' into TRACKS.")

    # Add challenges before final ];
    final_bracket = content.rfind("];")
    if final_bracket == -1:
        raise ValueError("Could not find final `];` in challenges.js")

    if '"id": "t0_dbsec_rdbms_privilege_model"' not in content:
        rendered_chals = []
        for c in challenges:
            rendered = json.dumps(c, ensure_ascii=False, indent=2)
            rendered_chals.append(rendered)

        chals_str = ",\n" + ",\n".join(rendered_chals) + "\n"
        content = content[:final_bracket] + chals_str + content[final_bracket:]
        print("  ✓ Appended 35 challenges to CHALLENGES.")

    with open(CHALLENGES_JS, "w", encoding="utf-8") as f:
        f.write(content)


def update_solve_derivable_js(ids):
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_kisa_enterprise_cert_audit"'
    if marker in sd_content and f'"{ids[0]}"' not in sd_content:
        pos = sd_content.find(marker)
        insert_ids_str = ',\n' + ',\n'.join(f'  "{cid}"' for cid in ids)
        sd_content = sd_content[:pos + len(marker)] + insert_ids_str + sd_content[pos + len(marker):]
        with open(SOLVE_DERIVABLE_JS, "w", encoding="utf-8") as f:
            f.write(sd_content)
        print("  ✓ Updated solve-derivable.js with 35 dbsec IDs.")


def update_index_html():
    content = INDEX_HTML.read_text(encoding="utf-8")

    content = re.sub(r'0/1715', '0/1750', content)
    content = re.sub(r'49개\s*트랙', '50개 트랙', content)
    content = re.sub(r'49\s*Tracks', '50 Tracks', content)
    content = re.sub(r'1,715', '1,750', content)
    content = re.sub(r'1715', '1750', content)

    if 'data-track="dbsec"' not in content:
        pattern = r'(<button class="track-chip"[^>]*data-track="cloudiam"[^>]*>.*?</button>)'
        replacement = r'\1\n      <button class="track-chip" data-track="dbsec">🗄️ DB 침투·하드닝</button>'
        content = re.sub(pattern, replacement, content, count=1)

    INDEX_HTML.write_text(content, encoding="utf-8")
    print(f"[✓] Updated HUD count (1750) and added dbsec chip in {INDEX_HTML.name}")


def update_app_js():
    content = APP_JS.read_text(encoding="utf-8")

    if 'dbsec:' not in content:
        pattern = r'(\s*cloudiam:\s*\{[^}]+\},)'
        replacement = r'\1\n    dbsec: { id:"dbsec", icon:"🗄️", ko:"엔터프라이즈 DB 침투·하드닝", en:"Enterprise DB Security & Hardening" },'
        content = re.sub(pattern, replacement, content, count=1)

    content = re.sub(r'1715', '1750', content)

    APP_JS.write_text(content, encoding="utf-8")
    print(f"[✓] Updated TRACKS and pool count in {APP_JS.name}")


def update_wargame_readme():
    content = WARGAME_README.read_text(encoding="utf-8")

    content = re.sub(r'1715', '1750', content)
    content = re.sub(r'1,715', '1,750', content)
    content = re.sub(r'49개 트랙', '50개 트랙', content)
    content = re.sub(r'49 tracks', '50 tracks', content)

    # Tier counts: +7 each tier
    content = re.sub(r'\| 0 \| Onboarding \| 188 \|', '| 0 | Onboarding \| 195 |', content)
    content = re.sub(r'\| 1 \| Beginner \| 309 \|', '| 1 \| Beginner \| 316 |', content)
    content = re.sub(r'\| 2 \| Intermediate \| 409 \|', '| 2 \| Intermediate \| 416 |', content)
    content = re.sub(r'\| 3 \| Advanced \| 421 \|', '| 3 \| Advanced \| 428 |', content)
    content = re.sub(r'\| 4 \| Expert \| 388 \|', '| 4 \| Expert \| 395 |', content)

    if '| `dbsec` |' not in content:
        pattern = r'(\| `cloudiam` \|[^\n]+\n)'
        replacement = r'\1| `dbsec` | 🗄️ 엔터프라이즈 DB 침투·하드닝 | 2차 SQLi, MySQL UDF 바이너리 인젝션, Oracle PL/SQL 권한상승, OOB DNS 유출, FGA/TDE 하드닝 | 35 |\n'
        content = re.sub(pattern, replacement, content, count=1)

    WARGAME_README.write_text(content, encoding="utf-8")
    print(f"[✓] Updated {WARGAME_README.name} to 50 tracks and 1,750 challenges")


def update_global_readmes():
    files = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.en.md",
        REPO_ROOT / "README.ja.md",
        REPO_ROOT / "README.zh.md",
        REPO_ROOT / "USAGE.md",
        REPO_ROOT / "AI_LEARNING.md"
    ]
    for p in files:
        if not p.exists():
            continue
        c = p.read_text(encoding="utf-8")
        c = re.sub(r'1715\s*문제', '1750 문제', c)
        c = re.sub(r'1715\s*challenges', '1750 challenges', c)
        c = re.sub(r'1715\s*問', '1750 問', c)
        c = re.sub(r'1715\s*道挑战', '1750 道挑战', c)
        c = re.sub(r'1715\s*题', '1750 题', c)
        c = re.sub(r'wargame-1715', 'wargame-1750', c)
        c = re.sub(r'49개\s*트랙', '50개 트랙', c)
        c = re.sub(r'49\s*tracks', '50 tracks', c)
        c = re.sub(r'49\s*Tracks', '50 Tracks', c)
        p.write_text(c, encoding="utf-8")
        print(f"  ✓ Synchronized 1750 count in {p.name}")


def main():
    print("[*] Generating Track 50: dbsec (Enterprise DB Security & Hardening)...")
    challenges, ids = build_challenges()
    print(f"[*] Built {len(challenges)} challenges.")

    update_challenges_js(challenges)
    update_solve_derivable_js(ids)
    update_index_html()
    update_app_js()
    update_wargame_readme()
    update_global_readmes()
    print("[🎉] Track 50 generation completed successfully!")


if __name__ == "__main__":
    main()
