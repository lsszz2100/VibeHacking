# 23. Database Hacking — Oracle / MySQL / MSSQL

## 목차

| 파일 | 내용 |
|------|------|
| [01_oracle_mysql_attack.md](./01_oracle_mysql_attack.md) | Oracle TNS 공격, MySQL UDF 셸, 해시 크랙, 포트 스캔 자동화 |
| [02_db_privilege_escalation.md](./02_db_privilege_escalation.md) | DB 권한 상승 — 저권한 계정 → DBA → OS 쉘 전 과정 |
| [03_db_forensics_defense.md](./03_db_forensics_defense.md) | DB 포렌식, Binlog/Redo Log 분석, 실시간 침해 탐지 자동화 |

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
