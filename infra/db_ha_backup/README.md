# 🏛️ 엔터프라이즈 DB 및 백업 이중화 관리 시스템
**High Availability (HA) & Multi-Tier Backup Redundancy Manager**

본 패키지는 설계 핵심 요약(1. DB 고가용성, 2. 다계층 백업 이중화, 3. 상시 복원 검증 가드)을 실체화하여 구축된 엔터프라이즈급 데이터 가용성 및 재해 복구(DR) 시스템입니다.

---

## 1. 아키텍처 개요

```
[ 클라이언트 애플리케이션 ]
        │
        ▼ (R/W 라우팅 & VIP)
┌────────────────────────────────────────────────────────┐
│  HAProxy / PgBouncer L4/L7 라우터                      │
│   - Write: Port 5000 ──▶ Primary Node (Leader)         │
│   - Read:  Port 5001 ──▶ Standby Nodes (Load Balanced) │
└────────────────────────────────────────────────────────┘
        │
        ├──────────────────────┬──────────────────────┐
        ▼                      ▼                      ▼
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ Primary (Node1)│     │ Standby (Node2)│     │ Standby (Node3)│
│ [R/W, Quorum]  │====▶│ [Sync Standby] │───▶ │ [Async Standby]│
└────────────────┘     └────────────────┘     └────────────────┘
        │ (WAL 스트리밍 & Quorum 동기 복제: Zero Data Loss)
        ▼
┌────────────────────────────────────────────────────────┐
│ 3-2-1-1-0 다계층 백업 이중화 파이프라인 (pgBackRest)   │
├─────────────────┬──────────────────┬───────────────────┤
│ Tier 1: Hot     │ Tier 2: Warm     │ Tier 3: WORM Cold │
│ 로컬 NVMe 캐시  │ 온프레미스 스토리지 │ AWS S3 Object Lock│
│ (RTO 즉시)      │ (사내 DR 분산망) │ (불변 컴플라이언스)│
└─────────────────┴──────────────────┴───────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ 🛡️ 상시 복원 검증 가드 (Schrödinger's Backup 차단)    │
│   - 임시 격리 샌드박스 자동 복원                       │
│   - SHA-256 체크섬 & DB 페이지 무결성 스캔            │
│   - RTO (< 30초) 계측 및 이상 시 긴급 경고            │
└────────────────────────────────────────────────────────┘
```

---

## 2. 3대 핵심 구현 요소

### 1) DB 고가용성 클러스터 (Zero Loss HA)
- **분산 합의 (Raft / etcd Quorum)**: 과반수(2/3) 노드 합의 기반 스플릿 브레인(Split-Brain) 원천 차단.
- **동기식 스트리밍 복제**: Primary에 트랜잭션 기록 시 최소 1개 Sync Standby 복제 확인 후 커밋 (RPO = 0초 보장).
- **자동 페일오버**: Primary 장애 감지 시 0.05초 이내 최신 LSN 보유 Standby를 신규 Primary로 자동 승격.
- **프로덕션 명세**: `config/patroni-cluster.yml`, `config/haproxy.cfg` 제공.

### 2) 다계층 백업 이중화 (3-2-1-1-0 전략)
- **3개 복사본**: 원본 1개 + 백업본 2개(Warm, Cold).
- **2개 상이 매체**: 로컬 블록 스토리지 + 오브젝트 스토리지.
- **1개 오프사이트**: 원격/타 리전 스토리지 분산 보관.
- **1개 불변(WORM) 스토리지**: S3 Object Lock Compliance 모드를 적용하여 관리자/랜섬웨어도 삭제/변조 불가능.
- **0개 에러 (PITR 초 단위 복구)**: 연속 WAL 아카이빙을 통해 장애 발생 직전 1초 전 상태로 무손실 시점 복원.
- **프로덕션 명세**: `config/pgbackrest.conf` 제공.

### 3) 상시 복원 검증 가드 (Automated Verification)
- "복원 테스트를 거치지 않은 백업은 백업이 아니다" 원칙 실현.
- 매 백업 후 독립 격리 샌드박스에서 자동 복원 시뮬레이션.
- SHA-256 체크섬 대조, DB 페이지 무결성(`PRAGMA integrity_check`), 스모크 쿼리 검증.
- 복구 시간(RTO) 실시간 측정 및 SLA 충족 여부 자동 리포트.

---

## 3. CLI 사용법

```bash
# 1. 클러스터 상태 및 노드 헬스체크
python3 infra/db_ha_backup/cli.py status

# 2. 트랜잭션 쓰기 (Primary 기록 + Sync 복제 + 연속 WAL 아카이빙)
python3 infra/db_ha_backup/cli.py write --type "ORDER" --payload "User: Alice, Amount: $500"

# 3. 데이터 읽기 (Standby 복제본으로 자동 라우팅)
python3 infra/db_ha_backup/cli.py read

# 4. 3-2-1-1-0 다계층 백업 생성 (Hot, Warm, WORM Cold 동시 스냅샷)
python3 infra/db_ha_backup/cli.py backup

# 5. 백업 자동 복원 검증 가드 실행 (샌드박스 무결성 & RTO 계측)
python3 infra/db_ha_backup/cli.py verify

# 6. Primary 장애 시뮬레이션 및 자동 페일오버 트리거
python3 infra/db_ha_backup/cli.py failover

# 7. 초 단위 시점 복구 (PITR)
python3 infra/db_ha_backup/cli.py pitr --timestamp 1789393160.0
```

---

## 4. 자동화 테스트 스위트 실행

```bash
python3 -m unittest infra/db_ha_backup/tests/test_ha_backup.py -v
```

- `test_01_ha_sync_replication_and_failover`: Quorum 동기 복제, R/W 분리, 페일오버, 쿼럼 손실 쓰기 차단, 복구 노드 동기화 검증.
- `test_02_backup_tiers_and_pitr`: 3-2-1-1-0 스토리지 검증, WORM 불변성(임의 삭제 차단) 검증, 초 단위 PITR 검증.
- `test_03_verification_guard_and_mutation`: 자동 복원 검증 PASS 실증 및 인위적 파일 훼손(Mutation) 시 즉각 FAIL 탐지 검증.
