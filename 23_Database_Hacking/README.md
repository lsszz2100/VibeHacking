# 23. Database Hacking — Oracle / MySQL / MSSQL

## 목차

| 파일 | 내용 |
|------|------|
| [01_oracle_mysql_attack.md](./01_oracle_mysql_attack.md) | Oracle TNS 공격, MySQL UDF 셸, 해시 크랙, 포트 스캔 자동화 |
| [02_db_privilege_escalation.md](./02_db_privilege_escalation.md) | DB 권한 상승 — 저권한 계정 → DBA → OS 쉘 전 과정 |
| [03_db_forensics_defense.md](./03_db_forensics_defense.md) | DB 포렌식, Binlog/Redo Log 분석, 실시간 침해 탐지 자동화 |
| [04_nosql_and_cloud_db_attacks.md](./04_nosql_and_cloud_db_attacks.md) | **NoSQL 및 클라우드 DB 공격** — 관계형 DB (SQL): |
| [05_database_defense_and_hardening.md](./05_database_defense_and_hardening.md) | **DB 방어 및 하드닝** — 데이터베이스는 조직의 핵심 자산(개인정보, 금융 데이터, 영업 기밀)을 저장합니다. DB가 침해되면 단순한 시스템 침해와 달리 데이터 자체가 유출되므로 복구가 불가능한 피해가 발생합니다. |
| [06_database_ctf_lab.md](./06_database_ctf_lab.md) | **데이터베이스 해킹 CTF 실습 랩** — SQL 인젝션, 권한 상승, NoSQL 인젝션, 데이터베이스 포렌식을 실습하는 CTF 환경입니다. |

## 학습 목표

- Oracle/MySQL/MSSQL 각 DB의 공격 진입점 이해
- 저권한 DB 계정에서 OS 쉘까지 권한 상승 경로 파악
- 침해 사고 후 DB 로그 및 트랜잭션 기록으로 포렌식 수행
- 실시간 감사 모니터링 구축

## 핵심 개념

```
공격 흐름:
  포트 스캔 → 기본 계정 브루트포스 → 저권한 접근
      → UDF/xp_cmdshell/DBMS_SCHEDULER → OS 명령 실행
      → 리버스 쉘 → 로컬 권한 상승

방어 흐름:
  최소 권한 원칙 → 감사 로그 활성화 → 이상 쿼리 모니터링
      → binlog/audit trail 분석 → 침해 타임라인 재구성
```
