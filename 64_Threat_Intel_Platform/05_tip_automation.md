# TIP 자동화 워크플로우

## 자동화 아키텍처

```
위협 인텔리전스 자동화 파이프라인

외부 피드 → 수집기 → 정규화 → 강화 → 중복제거 → 검증
                                                    ↓
배포 ← 만료 관리 ← IoC DB ← 신뢰도 스코어링 ← 컨텍스트화
↓
SIEM 룩업 / SOAR 플레이북 / 방화벽 차단 / MISP 공유
```

## 통합 TIP 자동화 파이프라인

```python
#!/usr/bin/env python3
"""통합 위협 인텔리전스 자동화 파이프라인."""

import argparse
import json
import logging
import sqlite3
import time
import urllib.request
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    db_path: Path = Path("tip.db")
    output_dir: Path = Path("output")
    vt_api_key: str = ""
    abuse_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    min_confidence: int = 60
    max_fp_reports: int = 3
    auto_expire: bool = True
    siem_export_formats: list[str] = field(default_factory=lambda: ["csv", "txt"])


@dataclass
class PipelineResult:
    pipeline_id: str
    start_time: float
    end_time: float
    total_collected: int
    after_dedup: int
    after_enrichment: int
    after_validation: int
    distributed: int
    errors: list[str] = field(default_factory=list)


class TIPPipeline:
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._hooks: dict[str, list[Callable]] = {
            "pre_collect": [],
            "post_collect": [],
            "post_enrich": [],
            "post_distribute": [],
        }

    def _init_db(self) -> None:
        self.conn = sqlite3.connect(str(self.config.db_path))
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id          TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                ioc_type    TEXT NOT NULL,
                source      TEXT,
                confidence  INTEGER,
                first_seen  TEXT,
                last_seen   TEXT,
                expiry      TEXT,
                tags        TEXT,
                enriched    INTEGER DEFAULT 0,
                fp_count    INTEGER DEFAULT 0,
                active      INTEGER DEFAULT 1
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id      TEXT PRIMARY KEY,
                start_time  TEXT,
                end_time    TEXT,
                collected   INTEGER,
                distributed INTEGER,
                errors      TEXT
            )
        """)
        self.conn.commit()

    def register_hook(self, event: str, fn: Callable) -> None:
        """파이프라인 훅 등록."""
        if event in self._hooks:
            self._hooks[event].append(fn)

    def _fire_hooks(self, event: str, data: object) -> None:
        for fn in self._hooks.get(event, []):
            try:
                fn(data)
            except Exception as e:
                logger.warning(f"훅 오류 [{event}]: {e}")

    def collect(self) -> list[dict]:
        """모든 피드에서 IoC 수집."""
        self._fire_hooks("pre_collect", None)

        feeds = [
            {
                "name": "FeodoTracker_C2",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "type": "ip-dst",
                "format": "txt",
                "confidence": 90,
            },
            {
                "name": "URLhaus_URLs",
                "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
                "type": "url",
                "format": "txt",
                "confidence": 85,
            },
            {
                "name": "MalwareBazaar_Hashes",
                "url": "https://mb-api.abuse.ch/downloads/misp.json",
                "type": "sha256",
                "format": "misp_json",
                "confidence": 90,
            },
        ]

        all_iocs: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        def fetch_feed(feed: dict) -> list[dict]:
            try:
                req = urllib.request.Request(
                    feed["url"],
                    headers={"User-Agent": "TIPPipeline/1.0"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()

                iocs: list[dict] = []
                if feed["format"] == "txt":
                    for line in raw.decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            iocs.append({
                                "value": line,
                                "ioc_type": feed["type"],
                                "source": feed["name"],
                                "confidence": feed["confidence"],
                                "first_seen": now,
                                "last_seen": now,
                            })
                elif feed["format"] == "misp_json":
                    data = json.loads(raw)
                    for event in data.get("response", [])[:500]:
                        for attr in event.get("Attribute", []):
                            if attr.get("type") == "sha256":
                                iocs.append({
                                    "value": attr["value"],
                                    "ioc_type": "sha256",
                                    "source": feed["name"],
                                    "confidence": feed["confidence"],
                                    "first_seen": now,
                                    "last_seen": now,
                                })
                logger.info(f"[{feed['name']}] {len(iocs)}개 수집")
                return iocs
            except Exception as e:
                logger.warning(f"[{feed['name']}] 수집 실패: {e}")
                return []

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(fetch_feed, f) for f in feeds]
            for fut in as_completed(futures):
                all_iocs.extend(fut.result())

        self._fire_hooks("post_collect", all_iocs)
        return all_iocs

    def deduplicate(self, iocs: list[dict]) -> list[dict]:
        """중복 제거."""
        seen: dict[str, dict] = {}
        for ioc in iocs:
            key = f"{ioc['ioc_type']}:{ioc['value']}"
            if key not in seen:
                seen[key] = ioc
            elif ioc["confidence"] > seen[key]["confidence"]:
                seen[key] = ioc
        return list(seen.values())

    def enrich(self, iocs: list[dict]) -> list[dict]:
        """IoC 강화 (VirusTotal 등)."""
        if not self.config.vt_api_key:
            return iocs

        enriched: list[dict] = []
        # 무료 VT API: 분당 4회 제한
        for i, ioc in enumerate(iocs[:50]):  # 처음 50개만 강화
            if i > 0 and i % 4 == 0:
                time.sleep(60)  # 분당 제한 대기

            vt_url = f"https://www.virustotal.com/api/v3/"
            ioc_type = ioc["ioc_type"]

            endpoint = ""
            if ioc_type in ("ip-src", "ip-dst"):
                endpoint = f"ip_addresses/{ioc['value']}"
            elif ioc_type in ("domain", "hostname"):
                endpoint = f"domains/{ioc['value']}"
            elif ioc_type == "sha256":
                endpoint = f"files/{ioc['value']}"

            if not endpoint:
                enriched.append(ioc)
                continue

            req = urllib.request.Request(
                vt_url + endpoint,
                headers={"x-apikey": self.config.vt_api_key},
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    ioc["vt_score"] = f"{malicious}/{total}"
                    ioc["vt_malicious"] = malicious > 3
                    # 악성으로 확인되면 신뢰도 상향
                    if malicious > 10:
                        ioc["confidence"] = min(100, ioc["confidence"] + 20)
            except Exception:
                pass

            enriched.append(ioc)

        return enriched + iocs[50:]

    def validate(self, iocs: list[dict]) -> list[dict]:
        """IoC 검증 (최소 신뢰도, FP 체크)."""
        valid: list[dict] = []
        for ioc in iocs:
            if ioc["confidence"] < self.config.min_confidence:
                continue
            # DB에서 FP 신고 수 확인
            row = self.conn.execute(
                "SELECT fp_count FROM iocs WHERE value = ? AND ioc_type = ?",
                (ioc["value"], ioc["ioc_type"]),
            ).fetchone()
            if row and row[0] >= self.config.max_fp_reports:
                continue
            valid.append(ioc)
        return valid

    def store(self, iocs: list[dict]) -> int:
        """IoC를 DB에 저장."""
        count = 0
        for ioc in iocs:
            ioc_id = hashlib.sha256(
                f"{ioc['ioc_type']}:{ioc['value']}".encode()
            ).hexdigest()[:16]
            days_map = {"ip-dst": 14, "ip-src": 14, "domain": 60,
                        "url": 21, "sha256": 180}
            days = days_map.get(ioc["ioc_type"], 30)
            expiry = (
                datetime.now(timezone.utc) + timedelta(days=days)
            ).isoformat()

            existing = self.conn.execute(
                "SELECT ioc_id FROM iocs WHERE value = ? AND ioc_type = ?",
                (ioc["value"], ioc["ioc_type"]),
            ).fetchone()

            if existing:
                self.conn.execute(
                    "UPDATE iocs SET last_seen = ?, confidence = max(confidence, ?), active = 1 WHERE ioc_id = ?",
                    (ioc["last_seen"], ioc["confidence"], existing[0]),
                )
            else:
                self.conn.execute(
                    "INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ioc_id, ioc["value"], ioc["ioc_type"],
                        ioc.get("source", ""), ioc["confidence"],
                        ioc["first_seen"], ioc["last_seen"],
                        expiry, json.dumps(ioc.get("tags", [])),
                        1, 0, 1,
                    ),
                )
                count += 1
        self.conn.commit()
        return count

    def distribute(self) -> dict[str, int]:
        """활성 IoC를 각 대상으로 배포."""
        results: dict[str, int] = {}
        rows = self.conn.execute(
            "SELECT * FROM iocs WHERE active = 1"
        ).fetchall()

        iocs_by_type: dict[str, list[str]] = {}
        for row in rows:
            t = row[2]  # ioc_type
            if t not in iocs_by_type:
                iocs_by_type[t] = []
            iocs_by_type[t].append(row[1])  # value

        for fmt in self.config.siem_export_formats:
            out_path = self.config.output_dir / f"iocs.{fmt}"
            if fmt == "txt":
                all_ips = iocs_by_type.get("ip-dst", []) + \
                          iocs_by_type.get("ip-src", [])
                out_path.write_text("\n".join(all_ips))
                results["txt"] = len(all_ips)
            elif fmt == "csv":
                lines = ["value,ioc_type,confidence"]
                for row in rows:
                    lines.append(f"{row[1]},{row[2]},{row[4]}")
                out_path.write_text("\n".join(lines))
                results["csv"] = len(rows)

        self._fire_hooks("post_distribute", results)
        return results

    def expire_old(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "UPDATE iocs SET active = 0 WHERE expiry < ? AND active = 1",
            (now,),
        )
        self.conn.commit()
        return cursor.rowcount

    def run(self) -> PipelineResult:
        """전체 파이프라인 실행."""
        run_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        start = time.time()
        errors: list[str] = []

        logger.info(f"[파이프라인 {run_id}] 시작")

        logger.info("1/5 수집...")
        collected = self.collect()
        logger.info(f"   {len(collected)}개 수집")

        logger.info("2/5 중복 제거...")
        deduped = self.deduplicate(collected)
        logger.info(f"   {len(deduped)}개 (중복 제거 후)")

        logger.info("3/5 강화...")
        enriched = self.enrich(deduped)

        logger.info("4/5 검증...")
        validated = self.validate(enriched)
        logger.info(f"   {len(validated)}개 유효")

        logger.info("5/5 저장 및 배포...")
        new_count = self.store(validated)
        distributed = self.distribute()
        expired = self.expire_old() if self.config.auto_expire else 0

        end = time.time()
        result = PipelineResult(
            pipeline_id=run_id,
            start_time=start,
            end_time=end,
            total_collected=len(collected),
            after_dedup=len(deduped),
            after_enrichment=len(enriched),
            after_validation=len(validated),
            distributed=sum(distributed.values()),
            errors=errors,
        )

        logger.info(f"[파이프라인 {run_id}] 완료 — {end - start:.1f}초")
        logger.info(f"   신규: {new_count}개 | 만료: {expired}개 | 배포: {result.distributed}개")
        return result

    def close(self) -> None:
        self.conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="TIP 자동화 파이프라인")
    parser.add_argument("--db", type=Path, default=Path("tip.db"))
    parser.add_argument("-o", "--output", type=Path, default=Path("output"))
    parser.add_argument("--vt-key", default="", help="VirusTotal API 키")
    parser.add_argument("--min-confidence", type=int, default=60)
    parser.add_argument("--formats", nargs="*", default=["csv", "txt"])
    parser.add_argument("--daemon", action="store_true",
                        help="주기적 실행 (1시간 간격)")
    parser.add_argument("--interval", type=int, default=3600,
                        help="데몬 간격 (초)")
    args = parser.parse_args()

    config = PipelineConfig(
        db_path=args.db,
        output_dir=args.output,
        vt_api_key=args.vt_key,
        min_confidence=args.min_confidence,
        siem_export_formats=args.formats,
    )

    if args.daemon:
        logger.info(f"데몬 모드: {args.interval}초 간격")
        while True:
            pipeline = TIPPipeline(config)
            try:
                result = pipeline.run()
                logger.info(f"결과: {result.after_validation}개 유효 IoC")
            finally:
                pipeline.close()
            time.sleep(args.interval)
    else:
        pipeline = TIPPipeline(config)
        try:
            result = pipeline.run()
            print(f"\n[결과]")
            print(f"  수집: {result.total_collected}개")
            print(f"  중복제거: {result.after_dedup}개")
            print(f"  검증: {result.after_validation}개")
            print(f"  배포: {result.distributed}개")
            print(f"  소요: {result.end_time - result.start_time:.1f}초")
        finally:
            pipeline.close()


if __name__ == "__main__":
    main()
```

## SOAR 연동

```python
#!/usr/bin/env python3
"""SOAR 플레이북 연동 — Shuffle 예시."""

import json
import urllib.request


def trigger_soar_workflow(
    shuffle_url: str,
    api_key: str,
    workflow_id: str,
    ioc: str,
    ioc_type: str,
) -> dict | None:
    """Shuffle SOAR 워크플로우 트리거."""
    payload = json.dumps({
        "execution_argument": json.dumps({
            "ioc": ioc,
            "ioc_type": ioc_type,
            "source": "TIP_Pipeline",
        })
    }).encode()
    req = urllib.request.Request(
        f"{shuffle_url}/api/v1/workflows/{workflow_id}/execute",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[!] SOAR 트리거 실패: {e}")
        return None
```

## 운영 체크리스트

```
일일 작업
☐ 피드 자동 수집 실행 확인
☐ 신규 IoC SIEM 반영 확인
☐ FP 신고 검토
☐ 만료 IoC 정리

주간 작업
☐ 피드 품질 평가 (FP율, 커버리지)
☐ 새로운 위협 행위자 추적 업데이트
☐ SIEM 탐지 규칙 효용성 검토
☐ 위협 인텔리전스 보고서 작성

월간 작업
☐ TIP 피드 추가/제거 검토
☐ 인텔리전스 요구사항 (PIR) 업데이트
☐ 수집한 인텔리전스 ROI 평가
☐ 다른 조직과 인텔리전스 공유 (ISAC)
```

위협 인텔리전스 플랫폼은 단순한 IoC 수집기가 아니라, **조직의 위협 인식 능력을 높이는 전략적 자산**이다. 자동화는 반복 작업을 줄이되, 분석가의 맥락적 판단은 여전히 핵심이다.
