> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 탐지 엔지니어링 — Sigma·MITRE ATT&CK 기반 룰 개발

## 0. 초보자를 위한 개념 이해

### 탐지 엔지니어링이란?

탐지 엔지니어링(Detection Engineering)은 공격 기법을 분석하고 이를 탐지하는 규칙과 로직을 체계적으로 개발하는 전문 분야입니다. 단순히 알림 모니터링을 넘어, 새로운 공격 기법에 대응하는 탐지 규칙을 직접 만들고 검증합니다. Sigma는 특정 SIEM에 종속되지 않는 표준 탐지 규칙 형식으로, 한 번 작성하면 Splunk/Elastic/QRadar 등에 자동 변환됩니다.

**왜 배우는가:**
```
탐지 엔지니어링의 가치:

  기존 SOC 분석가             탐지 엔지니어
  ──────────────────────────────────────────────────
  기존 알림 처리               새 탐지 규칙 개발
  vendor 제공 규칙 사용        맞춤형 탐지 로직 구축
  FP에 고통받음                FP 튜닝 및 최적화
  알려진 공격만 탐지           새 TTP 프로액티브 탐지

  Sigma 규칙의 강점:
    작성 1회 → 모든 SIEM 변환
    GitHub 공유 → 커뮤니티 협업
    ATT&CK 매핑 → 커버리지 시각화
```

### 핵심 개념 정리

```
Sigma 규칙 구조:

  title: 규칙 이름
  id: UUID
  status: experimental / test / stable / production
  description: 설명
  references: 참조 링크
  tags:
    - attack.technique_id      # ATT&CK 매핑
  logsource:
    category: process_creation  # 로그 유형
    product: windows
  detection:
    selection:
      Image|endswith: '\certutil.exe'
      CommandLine|contains: '-urlcache'
    condition: selection        # 탐지 조건
  falsepositives:
    - 정상 certutil 사용
  level: high                   # low/medium/high/critical

변환 도구:
  sigma-cli → Splunk/Elastic/QRadar SPL/EQL/AQL로 변환
```

### 필요한 도구 및 환경
- **sigma-cli**: Sigma 규칙을 SIEM 쿼리로 변환하는 공식 도구
- **SigmaHQ/sigma**: 공식 Sigma 규칙 저장소 (GitHub)
- **MITRE ATT&CK Navigator**: 탐지 커버리지 시각화
- **Atomic Red Team**: 공격 기법 시뮬레이션 (탐지 검증용)

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""Sigma 규칙 파서 — YAML 파일에서 탐지 조건 추출 및 검증."""

from pathlib import Path

import yaml


def parse_sigma_rule(rule_path: Path) -> dict:
    """Sigma YAML 규칙 파일을 파싱하여 핵심 정보를 추출합니다."""
    content = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    return {
        "title":       content.get("title", ""),
        "level":       content.get("level", ""),
        "status":      content.get("status", ""),
        "techniques":  [
            t for t in content.get("tags", [])
            if t.startswith("attack.t")
        ],
        "logsource":   content.get("logsource", {}),
        "detection":   content.get("detection", {}),
    }


def generate_splunk_spl(rule: dict) -> str:
    """간단한 Sigma 규칙을 Splunk SPL로 변환 (단순 선택 조건만)."""
    detection = rule["detection"]
    selection = detection.get("selection", {})
    conditions: list[str] = []
    for field, value in selection.items():
        if "|endswith" in field:
            real_field = field.replace("|endswith", "")
            conditions.append(f'{real_field}="*{value}"')
        elif "|contains" in field:
            real_field = field.replace("|contains", "")
            conditions.append(f'{real_field}="*{value}*"')
        else:
            conditions.append(f'{field}="{value}"')
    spl = "index=windows " + " ".join(conditions)
    return spl


if __name__ == "__main__":
    # 예제: certutil 악용 탐지 규칙
    sample_rule = {
        "title": "Certutil URL Download",
        "level": "high",
        "status": "stable",
        "detection": {
            "selection": {
                "Image|endswith": "\\certutil.exe",
                "CommandLine|contains": "-urlcache",
            },
        },
    }
    spl = generate_splunk_spl(sample_rule)
    print(f"Splunk SPL:\n{spl}")
```

---

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

---

<a name="english"></a>

# Detection Engineering — Sigma & MITRE ATT&CK Based Rule Development

## 1. Detection Engineering Overview

Detection engineering is the field of systematically developing rules and logic to analyze attack techniques and detect them.

```
Detection Engineering Lifecycle:
  Intelligence → Hypothesis → Rule Development → Testing → Deployment → Tuning

Key Standards:
  MITRE ATT&CK — Attack technique taxonomy
  Sigma        — SIEM-agnostic rule format
  YARA         — File/memory pattern matching
  Snort/Suricata — Network intrusion detection
```

---

## 2. Sigma Rule Development

### Sigma Rule Structure

```yaml
title: Suspicious PowerShell Encoded Command
id: a2a4b2c3-d4e5-f6g7-h8i9-j0k1l2m3n4o5
status: experimental
description: Detects PowerShell execution with encoded commands that may indicate malicious activity
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Detection Engineering Team
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|all:
      - '-enc'
      - '-nop'
  condition: selection
falsepositives:
  - Legitimate automation scripts
  - Software deployment tools
level: medium
```

### Sigma Rule Conversion

```bash
# Convert to Splunk SPL
sigma convert -t splunk rule.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch-eql rule.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rule.yml

# Validate rule
sigma check rule.yml

# Batch conversion
sigma convert -t splunk ./rules/ -o converted_rules/
```

---

## 3. MITRE ATT&CK Framework

### Technique Coverage Matrix

```
MITRE ATT&CK Tactics (in order):
  TA0001 Initial Access        - T1190 Exploit Public-Facing Application
  TA0002 Execution             - T1059 Command and Scripting Interpreter
  TA0003 Persistence           - T1053 Scheduled Task/Job
  TA0004 Privilege Escalation  - T1068 Exploitation for Privilege Escalation
  TA0005 Defense Evasion       - T1055 Process Injection
  TA0006 Credential Access     - T1003 OS Credential Dumping
  TA0007 Discovery             - T1082 System Information Discovery
  TA0008 Lateral Movement      - T1021 Remote Services
  TA0009 Collection            - T1005 Data from Local System
  TA0010 Exfiltration          - T1041 Exfiltration Over C2 Channel
  TA0011 Command and Control   - T1071 Application Layer Protocol
```

---

## 4. Detection Rule Development Process

### Step 1: Threat Intelligence Analysis

```python
#!/usr/bin/env python3
"""
Detection rule auto-generation from threat intelligence
"""
import anthropic
import json

client = anthropic.Anthropic()

def generate_detection_rule(ttp_description: str, log_sample: str = "") -> dict:
    """Generate Sigma rule from ATT&CK technique description"""
    
    prompt = f"""
You are a detection engineering expert.
Create a Sigma detection rule for the following ATT&CK technique.

Technique description: {ttp_description}

{f"Log sample: {log_sample}" if log_sample else ""}

Requirements:
1. YAML format Sigma rule
2. Appropriate log source (windows/linux/network)
3. False positive minimization
4. Include ATT&CK tags (attack.tXXXX)
5. Include testing notes

Respond in JSON format:
{{
  "sigma_rule": "YAML content",
  "description": "rule description",
  "false_positives": ["FP1", "FP2"],
  "test_commands": ["command1", "command2"],
  "mitre_technique": "TXXXX"
}}
"""
    
    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    
    try:
        return json.loads(resp.content[0].text)
    except:
        return {"raw": resp.content[0].text}

# Usage example
result = generate_detection_rule(
    ttp_description="T1003.001 - LSASS Memory Dump using procdump or mimikatz",
    log_sample="EventID=10 TargetImage=C:\\Windows\\System32\\lsass.exe"
)
```

### Step 2: Rule Testing

```bash
# Test with Atomic Red Team
# https://github.com/redcanaryco/atomic-red-team

# Execute technique T1059.001 (PowerShell)
Invoke-AtomicTest T1059.001

# Check if detection rule triggers
# If no detection: Rule tuning needed
# If detected: Rule valid

# Cleanup
Invoke-AtomicTest T1059.001 -Cleanup
```

---

## 5. Detection Rule Quality Metrics

```
Detection Rule Evaluation Criteria:

True Positive Rate (TPR):
  = Actual attacks detected / Total actual attacks
  Target: > 90%

False Positive Rate (FPR):
  = Legitimate activity flagged / Total legitimate activity
  Target: < 5%

Mean Time to Detect (MTTD):
  = Average time from attack start to detection
  Target: < 1 hour for critical techniques

Coverage Score (ATT&CK):
  = Detected techniques / Total ATT&CK techniques
  Goal: 80%+ coverage for tier 1 techniques

Rule Maintenance:
  - Weekly: Review false positive rate
  - Monthly: Add new threat intelligence
  - Quarterly: Coverage gap analysis
```

---

## 6. Key Tools

| Tool | Purpose |
|------|---------|
| `sigma-cli` | Sigma rule conversion and validation |
| `sigmac` | Sigma legacy converter |
| `Uncoder.IO` | Online SIEM query conversion |
| `MITRE ATT&CK Navigator` | Coverage visualization |
| `Atomic Red Team` | Test cases per technique |
| `Caldera` | Automated adversary emulation |
| `Purple Teamer` | Detection validation automation |
