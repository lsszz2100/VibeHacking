> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 탐지 공학 (Detection Engineering)

## 개념 소개

탐지 공학은 위협을 자동으로 발견하는 룰과 로직을 체계적으로 설계·개발·검증하는 학문입니다. 마치 건물의 화재 감지기를 설계하는 것처럼, 어떤 조건에서 알람이 울려야 하는지(임계값), 어떻게 오탐을 줄일지를 공학적으로 접근합니다.

---

## 탐지 룰 프레임워크

### Sigma

벤더 독립적인 SIEM 룰 포맷입니다.

```yaml
title: PowerShell 인코딩 실행 탐지
status: experimental
description: 인코딩된 PowerShell 명령 실행 탐지
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

### Snort/Suricata (네트워크)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"Suspicious Beacon Pattern";
    flow:established,to_server;
    content:"User-Agent|3a 20|Go-http-client";
    sid:1000001;
)
```

### YARA (파일/메모리)

바이너리 패턴 매칭 룰 언어입니다.

---

## SIEM 쿼리 최적화

| 최적화 전략 | 설명 |
|---|---|
| 인덱스 필드 우선 | 인덱싱된 필드 먼저 필터링 |
| 시간 범위 축소 | 불필요하게 긴 기간 조회 지양 |
| 와일드카드 최소화 | `*keyword*` 대신 `keyword*` |
| 집계 쿼리 분리 | 탐지와 통계는 별도 쿼리 |
| 알림 임계값 조정 | N건/시간 조건으로 오탐 감소 |

---

## Python 실습: Sigma 룰 파서 + 로그 이벤트 매처

```python
#!/usr/bin/env python3
"""
Sigma 룰(YAML)을 파싱하고 로그 이벤트(JSON)에 매칭합니다.
실제 SIEM 없이 탐지 룰 동작을 검증합니다.
"""

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SigmaDetection:
    name: str
    conditions: dict[str, Any]


@dataclass
class SigmaRule:
    title: str
    description: str
    level: str
    tags: list[str]
    logsource: dict[str, str]
    detection: SigmaDetection
    raw: str


@dataclass
class MatchEvent:
    rule_title: str
    level: str
    event: dict
    matched_fields: list[str]


def parse_sigma_yaml(yaml_text: str) -> SigmaRule | None:
    """간이 YAML 파서 (PyYAML 없이 정규식 기반)."""
    def get_field(text: str, key: str) -> str:
        m = re.search(rf"^{key}:\s*(.+)$", text, re.MULTILINE)
        return m.group(1).strip().strip("'\"") if m else ""

    def get_list(text: str, key: str) -> list[str]:
        block_m = re.search(rf"^{key}:\s*\n((?:\s+-\s*.+\n?)+)", text, re.MULTILINE)
        if not block_m:
            return []
        return [
            re.sub(r"^\s+-\s*", "", line).strip()
            for line in block_m.group(1).splitlines()
            if line.strip()
        ]

    # detection 블록 파싱
    det_block_m = re.search(r"^detection:\s*\n((?:\s+.+\n?)+)", yaml_text, re.MULTILINE)
    if not det_block_m:
        return None

    det_text = det_block_m.group(1)
    conditions: dict[str, Any] = {}

    # selection 블록 파싱
    sel_m = re.search(r"^\s+selection:\s*\n((?:\s{8,}.+\n?)+)", det_text, re.MULTILINE)
    if sel_m:
        sel_dict: dict[str, Any] = {}
        for line in sel_m.group(1).splitlines():
            kv = re.match(r"\s+(\S+?):\s*(.+)$", line)
            if kv:
                key = kv.group(1)
                val = kv.group(2).strip().strip("'\"")
                sel_dict[key] = val
        conditions["selection"] = sel_dict

    # filter 블록 파싱
    fil_m = re.search(r"^\s+filter:\s*\n((?:\s{8,}.+\n?)+)", det_text, re.MULTILINE)
    if fil_m:
        fil_dict: dict[str, Any] = {}
        for line in fil_m.group(1).splitlines():
            kv = re.match(r"\s+(\S+?):\s*(.+)$", line)
            if kv:
                key = kv.group(1)
                val = kv.group(2).strip().strip("'\"")
                fil_dict[key] = val
        conditions["filter"] = fil_dict

    cond_line_m = re.search(r"^\s+condition:\s*(.+)$", det_text, re.MULTILINE)
    conditions["condition"] = cond_line_m.group(1).strip() if cond_line_m else "selection"

    logsource: dict[str, str] = {}
    ls_m = re.search(r"^logsource:\s*\n((?:\s+.+\n?)+)", yaml_text, re.MULTILINE)
    if ls_m:
        for line in ls_m.group(1).splitlines():
            kv = re.match(r"\s+(\S+):\s*(.+)$", line)
            if kv:
                logsource[kv.group(1)] = kv.group(2).strip().strip("'\"")

    return SigmaRule(
        title=get_field(yaml_text, "title"),
        description=get_field(yaml_text, "description"),
        level=get_field(yaml_text, "level"),
        tags=get_list(yaml_text, "tags"),
        logsource=logsource,
        detection=SigmaDetection(name="detection", conditions=conditions),
        raw=yaml_text,
    )


def match_condition(
    field_key: str,
    field_val: str,
    event: dict,
) -> tuple[bool, str]:
    """단일 필드 조건을 이벤트에 매칭합니다."""
    # 필드 변환자 파싱: EventID, Image|endswith, CommandLine|contains
    parts = field_key.split("|")
    field_name = parts[0]
    modifier = parts[1] if len(parts) > 1 else "equals"

    # 이벤트에서 값 가져오기 (대소문자 비민감)
    event_val = ""
    for k, v in event.items():
        if k.lower() == field_name.lower():
            event_val = str(v)
            break

    if not event_val:
        return False, field_key

    if modifier == "equals":
        matched = event_val == field_val
    elif modifier == "endswith":
        matched = event_val.lower().endswith(field_val.lower())
    elif modifier == "startswith":
        matched = event_val.lower().startswith(field_val.lower())
    elif modifier == "contains":
        matched = field_val.lower() in event_val.lower()
    elif modifier == "re":
        matched = bool(re.search(field_val, event_val, re.IGNORECASE))
    else:
        matched = event_val == field_val

    return matched, field_key


def apply_rule(rule: SigmaRule, event: dict) -> MatchEvent | None:
    """이벤트에 Sigma 룰을 적용합니다."""
    conditions = rule.detection.conditions
    condition_str = conditions.get("condition", "selection").strip()

    def eval_block(block_name: str) -> tuple[bool, list[str]]:
        block = conditions.get(block_name, {})
        matched_fields: list[str] = []
        for fkey, fval in block.items():
            ok, fname = match_condition(fkey, str(fval), event)
            if not ok:
                return False, []
            matched_fields.append(fname)
        return True, matched_fields

    # condition 평가
    if condition_str == "selection":
        ok, fields = eval_block("selection")
        if ok:
            return MatchEvent(
                rule_title=rule.title, level=rule.level,
                event=event, matched_fields=fields,
            )

    elif "not filter" in condition_str:
        sel_ok, sel_fields = eval_block("selection")
        if not sel_ok:
            return None
        fil_ok, _ = eval_block("filter")
        if not fil_ok:  # filter 미매칭 = 알림 발생
            return MatchEvent(
                rule_title=rule.title, level=rule.level,
                event=event, matched_fields=sel_fields,
            )

    elif "or" in condition_str.lower():
        for block in ["selection", "selection1", "selection2"]:
            ok, fields = eval_block(block)
            if ok:
                return MatchEvent(
                    rule_title=rule.title, level=rule.level,
                    event=event, matched_fields=fields,
                )

    return None


# 내장 Sigma 룰 예시
BUILTIN_RULES = [
    """
title: PowerShell 인코딩 명령 실행
description: 인코딩된 PowerShell 명령 실행 탐지 (T1059.001)
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: \\powershell.exe
        CommandLine|contains: -EncodedCommand
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
""",
    """
title: 의심스러운 Scheduled Task 생성
description: 작업 스케줄러를 통한 지속성 확보 (T1053.005)
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
        TaskName|contains: Backdoor
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1053.005
""",
    """
title: LSASS 메모리 접근 탐지
description: 자격증명 덤프를 위한 LSASS 접근 (T1003.001)
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: \\lsass.exe
    filter:
        SourceImage|startswith: C:\\Windows\\System32
    condition: selection and not filter
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
""",
]

# 테스트 로그 이벤트 예시
SAMPLE_EVENTS = [
    {
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA...",
        "User": "DOMAIN\\victim",
    },
    {
        "EventID": "4698",
        "TaskName": "BackdoorTask",
        "SubjectUserName": "admin",
    },
    {
        "EventID": "10",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "SourceImage": "C:\\Users\\attacker\\procdump.exe",
        "GrantedAccess": "0x1410",
    },
    {
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir /s",
        "User": "DOMAIN\\normal_user",
    },
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Sigma 룰 파서 + 로그 이벤트 매처")
    parser.add_argument("--rules", "-r", type=Path, help="Sigma 룰 파일 (없으면 내장 사용)")
    parser.add_argument("--events", "-e", type=Path, help="로그 이벤트 JSON 파일")
    parser.add_argument("--demo", action="store_true", help="내장 룰/이벤트로 데모 실행")
    args = parser.parse_args()

    # 룰 로드
    rules: list[SigmaRule] = []
    rule_texts = BUILTIN_RULES
    if args.rules:
        rule_texts = [args.rules.read_text()]
    for rt in rule_texts:
        parsed = parse_sigma_yaml(rt)
        if parsed:
            rules.append(parsed)
    print(f"로드된 Sigma 룰: {len(rules)}개")

    # 이벤트 로드
    events: list[dict] = SAMPLE_EVENTS
    if args.events:
        events = json.loads(args.events.read_text())

    # 매칭
    total_matches = 0
    for i, event in enumerate(events):
        for rule in rules:
            match = apply_rule(rule, event)
            if match:
                total_matches += 1
                print(f"\n[매치] 이벤트 #{i+1} → 룰: {match.rule_title}")
                print(f"  심각도: {match.level}")
                print(f"  매칭 필드: {', '.join(match.matched_fields)}")

    print(f"\n{'='*50}")
    print(f"총 {len(events)}개 이벤트, {len(rules)}개 룰 → {total_matches}건 매치")


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **탐지 룰 개발**: 새로운 위협 TTP에 맞는 Sigma 룰 작성 후 검증
2. **SIEM 마이그레이션**: Sigma 룰을 다른 플랫폼 쿼리로 변환
3. **룰 품질 관리**: 오탐(FP) 비율 측정 및 필터 조건 조정

---

## 요약

| 룰 유형 | 대상 | 언어 |
|---|---|---|
| Sigma | SIEM 로그 | YAML |
| Snort/Suricata | 네트워크 패킷 | 전용 DSL |
| YARA | 파일/메모리 | YARA |
| KQL | Azure Sentinel | Kusto QL |
| SPL | Splunk | 전용 SPL |

---

<a name="english"></a>

# Detection Engineering

## Concept Overview

Detection engineering systematically designs, develops, and validates rules and logic that automatically discover threats — like engineering fire detectors: precisely defining what conditions trigger an alarm and how to minimize false positives.

---

## Detection Rule Frameworks

### Sigma
Vendor-independent SIEM rule format in YAML.

### SIEM Query Optimization

| Strategy | Description |
|---|---|
| Indexed fields first | Filter on indexed fields before others |
| Narrow time range | Avoid unnecessarily long query windows |
| Minimize wildcards | Use `keyword*` over `*keyword*` |
| Separate aggregation | Keep detection and stats queries separate |
| Alert thresholds | N events/hour to reduce false positives |

---

## Summary Table

| Rule Type | Target | Language |
|---|---|---|
| Sigma | SIEM logs | YAML |
| Snort/Suricata | Network packets | DSL |
| YARA | Files/memory | YARA |
| KQL | Azure Sentinel | Kusto QL |
| SPL | Splunk | SPL |
