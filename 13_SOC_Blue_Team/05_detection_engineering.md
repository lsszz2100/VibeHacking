# 탐지 엔지니어링 — Sigma·MITRE ATT&CK 기반 룰 개발

## 1. 탐지 엔지니어링 개요

탐지 엔지니어링은 공격 기법을 분석하고 이를 탐지하는 규칙·로직을 체계적으로 개발하는 분야다.

```
공격 기법 연구 (ATT&CK 매핑)
    │
    ▼
데이터 소스 식별
    │  - 어떤 로그/이벤트가 필요한가
    ▼
탐지 가설 수립
    │  - 공격 시 어떤 이상 패턴이 나타나는가
    ▼
Sigma 룰 개발
    │  - 플랫폼 독립적 탐지 룰
    ▼
SIEM 변환 및 검증
    │  - Splunk/Elastic/QRadar SPL/EQL/AQL
    ▼
False Positive 튜닝
    │  - 화이트리스트·임계값 조정
    ▼
Purple Team 검증
```

---

## 2. Sigma 룰 개발

```yaml
# sigma_lateral_movement_psexec.yml
title: PsExec 기반 횡이동 탐지
id: a8bfb3d8-ca43-4e5a-b2c5-3b0f90e23f1a
status: production
description: PsExec를 이용한 원격 서비스 생성 탐지 (Event ID 7045)
author: security_team
date: 2026/01/01
references:
  - https://attack.mitre.org/techniques/T1569/002/
tags:
  - attack.lateral_movement
  - attack.t1569.002
  - attack.execution
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceName|contains:
      - 'PSEXESVC'
      - 'psexec'
  filter:
    CurrentDirectory|contains:
      - 'C:\Windows\PSEXESVC'
  condition: selection and not filter
falsepositives:
  - 합법적인 관리자의 PsExec 사용
  - Sysinternals 도구 정상 사용
level: high
```

```yaml
# sigma_kerberoasting.yml
title: Kerberoasting 탐지 — TGS 요청 급증
id: b32f3d55-7def-4e8a-b654-9c234f890abc
status: production
description: 비정상적인 Kerberos TGS 요청으로 Kerberoasting 공격 탐지
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'  # RC4-HMAC (약한 암호화)
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'     # 컴퓨터 계정 제외
  timeframe: 5m
  condition: selection | count() by SubjectUserName > 10
  # 5분 내 동일 사용자가 10개 이상 TGS 요청 → 의심
falsepositives:
  - 서비스 계정이 많은 환경에서 정상 서비스 시작 시
level: high
```

```yaml
# sigma_dns_tunneling.yml
title: DNS 터널링 탐지
id: c1234abc-def0-1234-5678-abcdef012345
status: experimental
description: DNS 쿼리 길이·빈도 이상으로 DNS 터널링 탐지
tags:
  - attack.exfiltration
  - attack.t1048.001
logsource:
  category: dns
detection:
  selection:
    QueryType: 'TXT'
  long_query:
    QueryName|re: '.{50,}'  # 50자 이상 도메인
  high_freq:
    QueryName|contains:
      - '.chunk'
      - 'b64'
      - 'base32'
  condition: selection and (long_query or high_freq)
falsepositives:
  - SPF·DKIM 레코드 조회
  - CDN 서비스
level: medium
```

---

## 3. Sigma → SIEM 변환 CLI

```python
#!/usr/bin/env python3
"""Sigma 룰을 다양한 SIEM 쿼리로 자동 변환."""

import argparse
import subprocess
import sys
from pathlib import Path


SIGMA_BACKENDS = {
    "splunk": "splunk",
    "elastic": "es-ecs",
    "qradar": "qradar",
    "azure": "azure-monitor",
    "chronicle": "chronicle",
    "loki": "loki",
}


def convert_sigma_rule(
    rule_file: Path,
    backend: str,
    config: str | None = None,
) -> str | None:
    """sigmac/sigma-cli로 룰 변환."""
    cmd = ["sigma", "convert"]

    if config:
        cmd.extend(["-c", config])

    cmd.extend(["-t", SIGMA_BACKENDS.get(backend, backend), str(rule_file)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"변환 오류: {result.stderr}", file=sys.stderr)
    except FileNotFoundError:
        print("sigma-cli가 설치되지 않음. pip install sigma-cli", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("변환 타임아웃", file=sys.stderr)

    return None


def batch_convert(
    rules_dir: Path,
    backend: str,
    output_dir: Path,
    config: str | None = None,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    converted = 0

    for rule_file in rules_dir.rglob("*.yml"):
        query = convert_sigma_rule(rule_file, backend, config)
        if query:
            output_file = output_dir / f"{rule_file.stem}.{backend}.txt"
            output_file.write_text(query)
            converted += 1
            print(f"[+] {rule_file.name} → {output_file.name}")

    return converted


def validate_sigma_rule(rule_file: Path) -> dict:
    """Sigma 룰 유효성 검증."""
    import yaml

    try:
        with rule_file.open() as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return {"valid": False, "error": f"YAML 파싱 오류: {e}"}

    required_fields = ["title", "status", "logsource", "detection"]
    missing = [f for f in required_fields if f not in rule]

    if missing:
        return {"valid": False, "error": f"필수 필드 누락: {missing}"}

    # 감지 조건 검증
    detection = rule.get("detection", {})
    if "condition" not in detection:
        return {"valid": False, "error": "detection.condition 누락"}

    return {
        "valid": True,
        "title": rule.get("title"),
        "level": rule.get("level"),
        "tags": rule.get("tags", []),
        "status": rule.get("status"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sigma 룰 변환 및 검증")
    sub = parser.add_subparsers(dest="cmd", required=True)

    convert_p = sub.add_parser("convert", help="룰 변환")
    convert_p.add_argument("rule", type=Path, help="Sigma 룰 파일")
    convert_p.add_argument("-b", "--backend", required=True,
                           choices=list(SIGMA_BACKENDS.keys()))
    convert_p.add_argument("-c", "--config", help="sigma-cli 설정 파일")

    batch_p = sub.add_parser("batch", help="디렉터리 일괄 변환")
    batch_p.add_argument("rules_dir", type=Path)
    batch_p.add_argument("-b", "--backend", required=True)
    batch_p.add_argument("-o", "--output", type=Path, default=Path("./converted"))

    validate_p = sub.add_parser("validate", help="룰 유효성 검증")
    validate_p.add_argument("rule", type=Path)

    args = parser.parse_args()

    import json

    match args.cmd:
        case "convert":
            query = convert_sigma_rule(args.rule, args.backend, args.config)
            if query:
                print(query)

        case "batch":
            count = batch_convert(args.rules_dir, args.backend, args.output)
            print(f"\n변환 완료: {count}개 룰")

        case "validate":
            result = validate_sigma_rule(args.rule)
            print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 4. ATT&CK 기반 탐지 커버리지 분석

```python
#!/usr/bin/env python3
"""MITRE ATT&CK 커버리지 분석 — 탐지 룰 매핑 시각화."""

import argparse
import json
from collections import defaultdict
from pathlib import Path
import yaml


def load_sigma_tags(rules_dir: Path) -> dict[str, list[str]]:
    """Sigma 룰에서 ATT&CK 태그 추출."""
    coverage: dict[str, list[str]] = defaultdict(list)

    for rule_file in rules_dir.rglob("*.yml"):
        try:
            with rule_file.open() as f:
                rule = yaml.safe_load(f)
            tags = rule.get("tags", [])
            for tag in tags:
                if tag.startswith("attack.t"):
                    technique_id = tag.replace("attack.", "").upper()
                    coverage[technique_id].append(rule.get("title", str(rule_file.name)))
        except Exception:
            pass

    return dict(coverage)


def calculate_coverage_score(
    covered_techniques: set[str],
    total_techniques: int = 196,  # ATT&CK Enterprise 기준
) -> float:
    return len(covered_techniques) / total_techniques * 100


def generate_coverage_report(
    rules_dir: Path,
    output: Path | None = None,
) -> dict:
    coverage = load_sigma_tags(rules_dir)

    report = {
        "total_rules": sum(len(v) for v in coverage.values()),
        "covered_techniques": len(coverage),
        "coverage_score_pct": round(calculate_coverage_score(set(coverage.keys())), 1),
        "top_covered": sorted(
            coverage.items(), key=lambda x: len(x[1]), reverse=True
        )[:10],
        "techniques": coverage,
    }

    print(f"\n=== ATT&CK 커버리지 분석 ===")
    print(f"총 탐지 룰: {report['total_rules']}개")
    print(f"커버된 기법: {report['covered_techniques']}개")
    print(f"커버리지: {report['coverage_score_pct']}%")
    print(f"\n상위 커버된 기법:")
    for tech, rules in report["top_covered"]:
        print(f"  {tech}: {len(rules)}개 룰")

    if output:
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK 탐지 커버리지 분석")
    parser.add_argument("rules_dir", type=Path, help="Sigma 룰 디렉터리")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    generate_coverage_report(args.rules_dir, args.output)


if __name__ == "__main__":
    main()
```

---

## 5. False Positive 튜닝 자동화

```python
#!/usr/bin/env python3
"""탐지 룰 False Positive 분석 — 베이스라인 기반 자동 튜닝."""

import argparse
import json
from collections import Counter
from pathlib import Path
from datetime import datetime, timedelta


def analyze_false_positives(
    alert_log: Path,
    lookback_days: int = 30,
    threshold: int = 5,
) -> dict[str, list[str]]:
    """알림 로그에서 반복 발생하는 FP 패턴 탐지."""
    alerts: list[dict] = []
    with alert_log.open() as f:
        for line in f:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    cutoff = datetime.now() - timedelta(days=lookback_days)
    fp_candidates: dict[str, Counter] = {}

    for alert in alerts:
        # 타임스탬프 파싱
        ts_str = alert.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts < cutoff:
                continue
        except ValueError:
            continue

        rule = alert.get("rule_title", "unknown")
        fp_candidates.setdefault(rule, Counter())

        # 화이트리스트 후보 추출
        src_ip = alert.get("src_ip", "")
        user = alert.get("user", "")
        process = alert.get("process_name", "")

        if src_ip:
            fp_candidates[rule][f"src_ip:{src_ip}"] += 1
        if user:
            fp_candidates[rule][f"user:{user}"] += 1
        if process:
            fp_candidates[rule][f"process:{process}"] += 1

    # 임계값 초과 패턴 추출
    whitelist_candidates: dict[str, list[str]] = {}
    for rule, counter in fp_candidates.items():
        candidates = [
            entity for entity, count in counter.items() if count >= threshold
        ]
        if candidates:
            whitelist_candidates[rule] = candidates

    return whitelist_candidates


def main() -> None:
    parser = argparse.ArgumentParser(description="FP 튜닝 분석")
    parser.add_argument("alert_log", type=Path, help="JSONL 형식 알림 로그")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--threshold", type=int, default=5,
                        help="FP 후보 임계값 (회 이상)")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    candidates = analyze_false_positives(args.alert_log, args.days, args.threshold)
    print(f"\n화이트리스트 후보 ({args.threshold}회 이상):")
    for rule, entities in candidates.items():
        print(f"\n  룰: {rule}")
        for e in entities:
            print(f"    → {e}")

    if args.output:
        args.output.write_text(json.dumps(candidates, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 6. 탐지 엔지니어링 도구

| 도구 | 용도 |
|------|------|
| `sigma-cli` | Sigma 룰 변환·검증 |
| `sigmac` | Sigma 레거시 변환기 |
| `Uncoder.IO` | 온라인 SIEM 쿼리 변환 |
| `MITRE ATT&CK Navigator` | 커버리지 시각화 |
| `Atomic Red Team` | 기법별 테스트 케이스 |
| `Caldera` | 자동화 에드버서리 에뮬레이션 |
| `Purple Teamer` | 탐지 검증 자동화 |
