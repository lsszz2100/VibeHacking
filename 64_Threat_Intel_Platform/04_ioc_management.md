> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇴🇸 English](#english)

---

<a name="한국어"></a>

# IoC 관리 및 운영

## 0. 초보자를 위한 개념 이해

### IOC 관리가 중요한 이유

**IOC(침해 지표)**는 시간이 지나면 유효하지 않게 됩니다.

```
IOC의 TTL (Time-To-Live):

IP 주소:     7~30일 (공격자가 빠르게 바꿈)
도메인:      30~90일 (등록 갱신 필요)
URL:         14~30일
파일 해시:   90~365일 (파일 재컴파일 필요)
TTP:         수개월~수년 (행동 패턴 바꾸기 어려움)

만료된 IOC 문제:
  2020년 공격에 사용된 IP를 2026년에도 차단 중
  → 그 IP가 현재는 무고한 서비스
  → 사용자들이 불필요하게 차단됨 (서비스 장애)
```

### IOC 품질 관리

```
나쁜 IOC:
  신뢰도 낮음 (단일 소스, 검증 안 됨)
  유효하지 않음 (만료됨)
  너무 광범위 (전체 AS 차단 → 오탐 多)
  
좋은 IOC:
  여러 소스에서 검증됨
  유효 기간 명시됨
  정밀함 (특정 IP, 도메인, 해시)
  컨텍스트 포함 (어떤 캠페인, 어떤 그룹)
```

### IOC 신뢰도 점수

```
IOC를 자동으로 차단하기 전에 신뢰도 평가:

90-100점: 즉시 차단 (여러 소스 확인, 최신)
70-89점: 경보만 발생 (수동 검토 후 차단)
50-69점: 모니터링 목록 (주의 대상)
0-49점: 참고 정보 (차단하지 않음)

신뢰도 높이는 요소:
  + 여러 피드에서 동시에 보고됨
  + 최근 24-72시간 내 확인됨
  + VirusTotal 탐지율 70%+
  + 알려진 APT 그룹과 연관됨
  
신뢰도 낮추는 요소:
  - 단일 소스만 보고
  - 오래된 IOC (30일+)
  - 클라우드 서비스 IP (false positive 가능성)
```

---

## IoC 수명주기 관리

```
IoC 수명주기
수집 → 검증 → 강화 → 배포 → 탐지 활성화 → 노후화 → 만료

노후화 기준 (유형별)
├── IP 주소       : 7~30일 (빠른 재사용)
├── 도메인        : 30~90일
├── URL           : 14~30일
├── 파일 해시     : 90~365일
├── 인증서 지문   : 만료일까지
└── TTPs (YARA/Sigma) : 수개월~수년
```

## IoC 데이터베이스

```python
#!/usr/bin/env python3
"""IoC 데이터베이스 관리 시스템."""

import argparse
import sqlite3
import json
import hashlib
import time
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict


@dataclass
class IOC:
    ioc_id: str
    value: str
    ioc_type: str
    source: str
    confidence: int
    first_seen: str
    last_seen: str
    expiry: str
    tags: str  # JSON 배열 문자열
    description: str
    active: int = 1
    fp_reported: int = 0  # False Positive 신고 수


def generate_ioc_id(ioc_type: str, value: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]


def get_default_expiry(ioc_type: str) -> str:
    days_map = {
        "ip-src": 14,
        "ip-dst": 14,
        "domain": 60,
        "hostname": 60,
        "url": 21,
        "md5": 180,
        "sha1": 180,
        "sha256": 180,
        "email-src": 90,
        "yara": 365,
    }
    days = days_map.get(ioc_type, 30)
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return expiry.isoformat()


class IOCDatabase:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id      TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                ioc_type    TEXT NOT NULL,
                source      TEXT,
                confidence  INTEGER DEFAULT 50,
                first_seen  TEXT,
                last_seen   TEXT,
                expiry      TEXT,
                tags        TEXT DEFAULT '[]',
                description TEXT DEFAULT '',
                active      INTEGER DEFAULT 1,
                fp_reported INTEGER DEFAULT 0
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_value ON iocs(value);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_type ON iocs(ioc_type);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_active ON iocs(active);
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fp_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id      TEXT NOT NULL,
                reporter    TEXT,
                reason      TEXT,
                reported_at TEXT,
                FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
            )
        """)
        self.conn.commit()

    def add_ioc(self, ioc: IOC) -> bool:
        """IoC 추가 또는 업데이트."""
        existing = self.get_by_value(ioc.value, ioc.ioc_type)
        now = datetime.now(timezone.utc).isoformat()

        if existing:
            # 기존 IoC 업데이트 (last_seen, confidence 최대값)
            new_conf = max(existing["confidence"], ioc.confidence)
            self.conn.execute("""
                UPDATE iocs SET
                    last_seen = ?,
                    confidence = ?,
                    source = ?,
                    active = 1
                WHERE ioc_id = ?
            """, (now, new_conf, ioc.source, existing["ioc_id"]))
        else:
            self.conn.execute("""
                INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ioc.ioc_id, ioc.value, ioc.ioc_type, ioc.source,
                ioc.confidence, ioc.first_seen, ioc.last_seen,
                ioc.expiry, ioc.tags, ioc.description,
                ioc.active, ioc.fp_reported,
            ))
        self.conn.commit()
        return True

    def add_batch(self, iocs: list[IOC]) -> int:
        """IoC 배치 추가."""
        count = 0
        for ioc in iocs:
            if self.add_ioc(ioc):
                count += 1
        return count

    def get_by_value(
        self, value: str, ioc_type: str | None = None
    ) -> sqlite3.Row | None:
        if ioc_type:
            return self.conn.execute(
                "SELECT * FROM iocs WHERE value = ? AND ioc_type = ?",
                (value, ioc_type),
            ).fetchone()
        return self.conn.execute(
            "SELECT * FROM iocs WHERE value = ?", (value,)
        ).fetchone()

    def search(
        self,
        query: str,
        ioc_type: str | None = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        conditions = ["value LIKE ?"]
        params: list = [f"%{query}%"]
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        if active_only:
            conditions.append("active = 1")
        where = " AND ".join(conditions)
        return self.conn.execute(
            f"SELECT * FROM iocs WHERE {where} LIMIT ?",
            params + [limit],
        ).fetchall()

    def expire_old_iocs(self) -> int:
        """만료된 IoC 비활성화."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "UPDATE iocs SET active = 0 WHERE expiry < ? AND active = 1",
            (now,),
        )
        self.conn.commit()
        return cursor.rowcount

    def report_false_positive(
        self, value: str, ioc_type: str, reporter: str, reason: str
    ) -> bool:
        row = self.get_by_value(value, ioc_type)
        if not row:
            return False
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO fp_reports (ioc_id, reporter, reason, reported_at) VALUES (?,?,?,?)",
            (row["ioc_id"], reporter, reason, now),
        )
        self.conn.execute(
            "UPDATE iocs SET fp_reported = fp_reported + 1 WHERE ioc_id = ?",
            (row["ioc_id"],),
        )
        # FP 3회 이상 → 자동 비활성화
        updated = self.conn.execute(
            "SELECT fp_reported FROM iocs WHERE ioc_id = ?",
            (row["ioc_id"],),
        ).fetchone()
        if updated and updated["fp_reported"] >= 3:
            self.conn.execute(
                "UPDATE iocs SET active = 0 WHERE ioc_id = ?",
                (row["ioc_id"],),
            )
        self.conn.commit()
        return True

    def export_to_siem(
        self, ioc_type: str | None = None, format: str = "csv"
    ) -> str:
        conditions = ["active = 1"]
        params: list = []
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        rows = self.conn.execute(
            f"SELECT * FROM iocs WHERE {' AND '.join(conditions)}",
            params,
        ).fetchall()

        if format == "csv":
            lines = ["value,ioc_type,confidence,source,tags"]
            for r in rows:
                tags = ",".join(json.loads(r["tags"]))
                lines.append(f"{r['value']},{r['ioc_type']},"
                             f"{r['confidence']},{r['source']},{tags}")
            return "\n".join(lines)

        elif format == "json":
            data = [dict(r) for r in rows]
            return json.dumps(data, indent=2)

        elif format == "txt":
            return "\n".join(r["value"] for r in rows)

        return ""

    def get_stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        active = self.conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE active = 1"
        ).fetchone()[0]
        by_type = self.conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM iocs WHERE active = 1 GROUP BY ioc_type"
        ).fetchall()
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
        }

    def close(self) -> None:
        self.conn.close()


def import_from_csv(db: IOCDatabase, csv_path: Path, source: str) -> int:
    import csv
    count = 0
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            value = row.get("value", "").strip()
            ioc_type = row.get("ioc_type", "").strip()
            if not value or not ioc_type:
                continue
            now = datetime.now(timezone.utc).isoformat()
            ioc = IOC(
                ioc_id=generate_ioc_id(ioc_type, value),
                value=value,
                ioc_type=ioc_type,
                source=row.get("source", source),
                confidence=int(row.get("confidence", 70)),
                first_seen=now,
                last_seen=now,
                expiry=get_default_expiry(ioc_type),
                tags=json.dumps(row.get("tags", "").split(",") if row.get("tags") else []),
                description=row.get("description", ""),
            )
            if db.add_ioc(ioc):
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="IoC 데이터베이스 관리")
    parser.add_argument("--db", type=Path, default=Path("ioc.db"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 가져오기
    imp = sub.add_parser("import", help="CSV에서 IoC 가져오기")
    imp.add_argument("csv_path", type=Path)
    imp.add_argument("--source", default="manual")

    # 검색
    srch = sub.add_parser("search", help="IoC 검색")
    srch.add_argument("query")
    srch.add_argument("--type")

    # 내보내기
    exp = sub.add_parser("export", help="SIEM용 IoC 내보내기")
    exp.add_argument("--type")
    exp.add_argument("--format", choices=["csv", "json", "txt"], default="csv")
    exp.add_argument("-o", "--output", type=Path)

    # 만료 처리
    sub.add_parser("expire", help="만료 IoC 비활성화")

    # 통계
    sub.add_parser("stats", help="통계 출력")

    # FP 신고
    fp = sub.add_parser("fp", help="False Positive 신고")
    fp.add_argument("value")
    fp.add_argument("--type", required=True)
    fp.add_argument("--reporter", default="analyst")
    fp.add_argument("--reason", default="")

    args = parser.parse_args()
    db = IOCDatabase(args.db)

    try:
        if args.cmd == "import":
            count = import_from_csv(db, args.csv_path, args.source)
            print(f"[+] {count}개 IoC 가져오기 완료")

        elif args.cmd == "search":
            results = db.search(args.query, args.type)
            print(f"[+] 결과: {len(results)}개")
            for r in results[:20]:
                print(f"  [{r['ioc_type']:15s}] {r['value']:50s} "
                      f"신뢰도:{r['confidence']}%")

        elif args.cmd == "export":
            output = db.export_to_siem(args.type, args.format)
            if args.output:
                args.output.write_text(output)
                print(f"[+] 저장: {args.output}")
            else:
                print(output)

        elif args.cmd == "expire":
            count = db.expire_old_iocs()
            print(f"[+] {count}개 IoC 만료 처리")

        elif args.cmd == "stats":
            stats = db.get_stats()
            print(f"IoC 통계:")
            print(f"  전체: {stats['total']}개")
            print(f"  활성: {stats['active']}개")
            print(f"  만료: {stats['inactive']}개")
            print(f"  유형별:")
            for t, cnt in sorted(stats["by_type"].items()):
                print(f"    {t:20s}: {cnt}")

        elif args.cmd == "fp":
            ok = db.report_false_positive(
                args.value, args.type, args.reporter, args.reason
            )
            print(f"[{'+'if ok else'!'}] FP 신고: {args.value}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
```

## SIEM 연동

```bash
# Splunk 룩업 테이블 자동 생성
python3 ioc_manager.py --db ioc.db export \
    --format csv -o /opt/splunk/etc/apps/local/lookups/ioc_list.csv

# Splunk 검색 (IoC 매칭)
index=* [inputlookup ioc_list.csv
         | where ioc_type="ip-dst"
         | rename value as dest_ip
         | fields dest_ip]
| stats count by dest_ip, src_ip, _time

# Elastic SIEM 연동
# → threat.indicator.ip, threat.indicator.domain 필드 활용

# QRadar 참조 세트에 업로드
python3 ioc_manager.py --db ioc.db export \
    --type ip-dst --format txt | \
    while read ip; do
        curl -s -X POST "https://qradar/api/reference_data/sets/malicious_ips/bulk_load" \
             --data "[\"$ip\"]"
    done
```

다음 파일에서 TIP 자동화 워크플로우를 다룬다.

---

<a name="english"></a>

# IoC Management and Operations

## IoC Lifecycle Management

```
IoC lifecycle
Collect → Validate → Enrich → Deploy → Activate detection → Age → Expire

Aging criteria (by type)
├── IP address        : 7–30 days (fast reuse)
├── Domain            : 30–90 days
├── URL               : 14–30 days
├── File hash         : 90–365 days
├── Certificate fingerprint : until expiry date
└── TTPs (YARA/Sigma) : months to years
```

## IoC Database

```python
#!/usr/bin/env python3
"""IoC database management system."""

import argparse
import sqlite3
import json
import hashlib
import time
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict


@dataclass
class IOC:
    ioc_id: str
    value: str
    ioc_type: str
    source: str
    confidence: int
    first_seen: str
    last_seen: str
    expiry: str
    tags: str  # JSON array string
    description: str
    active: int = 1
    fp_reported: int = 0  # Number of false positive reports


def generate_ioc_id(ioc_type: str, value: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]


def get_default_expiry(ioc_type: str) -> str:
    days_map = {
        "ip-src": 14,
        "ip-dst": 14,
        "domain": 60,
        "hostname": 60,
        "url": 21,
        "md5": 180,
        "sha1": 180,
        "sha256": 180,
        "email-src": 90,
        "yara": 365,
    }
    days = days_map.get(ioc_type, 30)
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return expiry.isoformat()


class IOCDatabase:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id      TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                ioc_type    TEXT NOT NULL,
                source      TEXT,
                confidence  INTEGER DEFAULT 50,
                first_seen  TEXT,
                last_seen   TEXT,
                expiry      TEXT,
                tags        TEXT DEFAULT '[]',
                description TEXT DEFAULT '',
                active      INTEGER DEFAULT 1,
                fp_reported INTEGER DEFAULT 0
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_value ON iocs(value);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_type ON iocs(ioc_type);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_active ON iocs(active);
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fp_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id      TEXT NOT NULL,
                reporter    TEXT,
                reason      TEXT,
                reported_at TEXT,
                FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
            )
        """)
        self.conn.commit()

    def add_ioc(self, ioc: IOC) -> bool:
        """Add or update an IoC."""
        existing = self.get_by_value(ioc.value, ioc.ioc_type)
        now = datetime.now(timezone.utc).isoformat()

        if existing:
            # Update existing IoC (last_seen, max confidence)
            new_conf = max(existing["confidence"], ioc.confidence)
            self.conn.execute("""
                UPDATE iocs SET
                    last_seen = ?,
                    confidence = ?,
                    source = ?,
                    active = 1
                WHERE ioc_id = ?
            """, (now, new_conf, ioc.source, existing["ioc_id"]))
        else:
            self.conn.execute("""
                INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ioc.ioc_id, ioc.value, ioc.ioc_type, ioc.source,
                ioc.confidence, ioc.first_seen, ioc.last_seen,
                ioc.expiry, ioc.tags, ioc.description,
                ioc.active, ioc.fp_reported,
            ))
        self.conn.commit()
        return True

    def add_batch(self, iocs: list[IOC]) -> int:
        """Add IoCs in batch."""
        count = 0
        for ioc in iocs:
            if self.add_ioc(ioc):
                count += 1
        return count

    def get_by_value(
        self, value: str, ioc_type: str | None = None
    ) -> sqlite3.Row | None:
        if ioc_type:
            return self.conn.execute(
                "SELECT * FROM iocs WHERE value = ? AND ioc_type = ?",
                (value, ioc_type),
            ).fetchone()
        return self.conn.execute(
            "SELECT * FROM iocs WHERE value = ?", (value,)
        ).fetchone()

    def search(
        self,
        query: str,
        ioc_type: str | None = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        conditions = ["value LIKE ?"]
        params: list = [f"%{query}%"]
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        if active_only:
            conditions.append("active = 1")
        where = " AND ".join(conditions)
        return self.conn.execute(
            f"SELECT * FROM iocs WHERE {where} LIMIT ?",
            params + [limit],
        ).fetchall()

    def expire_old_iocs(self) -> int:
        """Deactivate expired IoCs."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "UPDATE iocs SET active = 0 WHERE expiry < ? AND active = 1",
            (now,),
        )
        self.conn.commit()
        return cursor.rowcount

    def report_false_positive(
        self, value: str, ioc_type: str, reporter: str, reason: str
    ) -> bool:
        row = self.get_by_value(value, ioc_type)
        if not row:
            return False
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO fp_reports (ioc_id, reporter, reason, reported_at) VALUES (?,?,?,?)",
            (row["ioc_id"], reporter, reason, now),
        )
        self.conn.execute(
            "UPDATE iocs SET fp_reported = fp_reported + 1 WHERE ioc_id = ?",
            (row["ioc_id"],),
        )
        # 3 or more FP reports → auto-deactivate
        updated = self.conn.execute(
            "SELECT fp_reported FROM iocs WHERE ioc_id = ?",
            (row["ioc_id"],),
        ).fetchone()
        if updated and updated["fp_reported"] >= 3:
            self.conn.execute(
                "UPDATE iocs SET active = 0 WHERE ioc_id = ?",
                (row["ioc_id"],),
            )
        self.conn.commit()
        return True

    def export_to_siem(
        self, ioc_type: str | None = None, format: str = "csv"
    ) -> str:
        conditions = ["active = 1"]
        params: list = []
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type)
        rows = self.conn.execute(
            f"SELECT * FROM iocs WHERE {' AND '.join(conditions)}",
            params,
        ).fetchall()

        if format == "csv":
            lines = ["value,ioc_type,confidence,source,tags"]
            for r in rows:
                tags = ",".join(json.loads(r["tags"]))
                lines.append(f"{r['value']},{r['ioc_type']},"
                             f"{r['confidence']},{r['source']},{tags}")
            return "\n".join(lines)

        elif format == "json":
            data = [dict(r) for r in rows]
            return json.dumps(data, indent=2)

        elif format == "txt":
            return "\n".join(r["value"] for r in rows)

        return ""

    def get_stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        active = self.conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE active = 1"
        ).fetchone()[0]
        by_type = self.conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM iocs WHERE active = 1 GROUP BY ioc_type"
        ).fetchall()
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
        }

    def close(self) -> None:
        self.conn.close()


def import_from_csv(db: IOCDatabase, csv_path: Path, source: str) -> int:
    import csv
    count = 0
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            value = row.get("value", "").strip()
            ioc_type = row.get("ioc_type", "").strip()
            if not value or not ioc_type:
                continue
            now = datetime.now(timezone.utc).isoformat()
            ioc = IOC(
                ioc_id=generate_ioc_id(ioc_type, value),
                value=value,
                ioc_type=ioc_type,
                source=row.get("source", source),
                confidence=int(row.get("confidence", 70)),
                first_seen=now,
                last_seen=now,
                expiry=get_default_expiry(ioc_type),
                tags=json.dumps(row.get("tags", "").split(",") if row.get("tags") else []),
                description=row.get("description", ""),
            )
            if db.add_ioc(ioc):
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="IoC database management")
    parser.add_argument("--db", type=Path, default=Path("ioc.db"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Import
    imp = sub.add_parser("import", help="Import IoCs from CSV")
    imp.add_argument("csv_path", type=Path)
    imp.add_argument("--source", default="manual")

    # Search
    srch = sub.add_parser("search", help="Search IoCs")
    srch.add_argument("query")
    srch.add_argument("--type")

    # Export
    exp = sub.add_parser("export", help="Export IoCs for SIEM")
    exp.add_argument("--type")
    exp.add_argument("--format", choices=["csv", "json", "txt"], default="csv")
    exp.add_argument("-o", "--output", type=Path)

    # Expire
    sub.add_parser("expire", help="Deactivate expired IoCs")

    # Stats
    sub.add_parser("stats", help="Print statistics")

    # FP report
    fp = sub.add_parser("fp", help="Report false positive")
    fp.add_argument("value")
    fp.add_argument("--type", required=True)
    fp.add_argument("--reporter", default="analyst")
    fp.add_argument("--reason", default="")

    args = parser.parse_args()
    db = IOCDatabase(args.db)

    try:
        if args.cmd == "import":
            count = import_from_csv(db, args.csv_path, args.source)
            print(f"[+] {count} IoCs imported successfully")

        elif args.cmd == "search":
            results = db.search(args.query, args.type)
            print(f"[+] Results: {len(results)}")
            for r in results[:20]:
                print(f"  [{r['ioc_type']:15s}] {r['value']:50s} "
                      f"confidence:{r['confidence']}%")

        elif args.cmd == "export":
            output = db.export_to_siem(args.type, args.format)
            if args.output:
                args.output.write_text(output)
                print(f"[+] Saved: {args.output}")
            else:
                print(output)

        elif args.cmd == "expire":
            count = db.expire_old_iocs()
            print(f"[+] {count} IoCs expired")

        elif args.cmd == "stats":
            stats = db.get_stats()
            print(f"IoC statistics:")
            print(f"  Total:    {stats['total']}")
            print(f"  Active:   {stats['active']}")
            print(f"  Inactive: {stats['inactive']}")
            print(f"  By type:")
            for t, cnt in sorted(stats["by_type"].items()):
                print(f"    {t:20s}: {cnt}")

        elif args.cmd == "fp":
            ok = db.report_false_positive(
                args.value, args.type, args.reporter, args.reason
            )
            print(f"[{'+'if ok else'!'}] FP reported: {args.value}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
```

## SIEM Integration

```bash
# Auto-generate Splunk lookup table
python3 ioc_manager.py --db ioc.db export \
    --format csv -o /opt/splunk/etc/apps/local/lookups/ioc_list.csv

# Splunk search (IoC matching)
index=* [inputlookup ioc_list.csv
         | where ioc_type="ip-dst"
         | rename value as dest_ip
         | fields dest_ip]
| stats count by dest_ip, src_ip, _time

# Elastic SIEM integration
# → Use threat.indicator.ip and threat.indicator.domain fields

# Upload to QRadar reference set
python3 ioc_manager.py --db ioc.db export \
    --type ip-dst --format txt | \
    while read ip; do
        curl -s -X POST "https://qradar/api/reference_data/sets/malicious_ips/bulk_load" \
             --data "[\"$ip\"]"
    done
```

The next file covers TIP automation workflows.
