> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 탐지 공학 (Detection Engineering)

## 실습 환경 준비

> 탐지 룰 작성·변환·검증 도구가 필요합니다.

```bash
pip install sigma-cli            # Sigma 룰 변환:  sigma convert ...
sudo apt install yara suricata   # 파일/네트워크 탐지
pip install yara-python

# 백엔드(택1): Elastic Stack 또는 Splunk(무료 평가판)
# Sigma 공개 룰셋: https://github.com/SigmaHQ/sigma
```

> 검증 팁: 같은 룰을 공격 시간창과 정상 시간창에 각각 돌려 TP/FP를 함께 측정하세요. TP가 낮으면 미탐(룰 약함), FP가 높으면 경보 피로 → 튜닝 대상입니다.
> ⚠️ **격리 필수**: 테스트 로그/대상은 격리 환경에서.
> 🧪 별도 컨테이너 랩 없음 — SIEM + Sigma/YARA로 직접 구성.

---

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

## 탐지 룰 견고성: 회피 저항성 (Pyramid of Pain)

David Bianco의 "Pyramid of Pain"은 어떤 지표로 탐지하느냐에 따라 공격자가 우회하기 위해 치러야 할 비용이 달라진다는 통찰을 줍니다. 견고한 탐지는 바꾸기 어려운 상위 계층을 노립니다.

| 계층 | 탐지 대상 | 공격자 우회 비용 | 예시 |
|---|---|---|---|
| 해시값 | 파일 MD5/SHA256 | 사소함 (1바이트 변경) | YARA 해시 룰 |
| IP/도메인 | C2 인프라 | 낮음 (재배포) | IOC 차단 |
| 아티팩트 | 레지스트리·파일명 | 중간 | Sigma 셀렉션 |
| 도구 | 사용 툴 시그니처 | 높음 (재작성) | 행위 룰 |
| **TTP** | **공격 행위 패턴** | **매우 높음** | **상위 수준 행위 탐지** |

> 함정: `CommandLine|contains: -EncodedCommand` 같은 룰은 `-enc`, `-e`, 대소문자 혼합, 공백 삽입으로 쉽게 우회됩니다. 견고한 룰은 인코딩된 base64의 디코딩 결과·부모-자식 프로세스 관계·드물게 발생하는 행위 자체를 노립니다. 퍼플팀은 동일 기법의 여러 변종을 실행해 룰이 "문자열"이 아니라 "행위"를 잡는지 검증해야 합니다.

---

## 탐지 룰 수명주기와 품질 측정

탐지 룰은 배포로 끝나지 않습니다. 데이터 소스 변경·정상 행위 변화로 룰은 노후화(rule decay)합니다.

| 단계 | 활동 | 측정 지표 |
|---|---|---|
| 작성 | 가설 → 룰 → 테스트 케이스 | 테스트 통과 여부 |
| 검증 | 퍼플팀 시뮬로 정탐 확인 | 정탐율(TP rate) |
| 튜닝 | 오탐 원인 분석 → 필터 추가 | 오탐율(FP rate), 정밀도 |
| 운영 | 알람 분류 추적 | 알람당 처리 시간 |
| 폐기/갱신 | 노후 룰 식별·교체 | 무발동 기간, 커버리지 변화 |

핵심 트레이드오프: 룰을 넓게 잡으면 미탐(false negative)은 줄지만 오탐(false positive)이 늘어 분석가 피로를 유발합니다. 좁게 잡으면 그 반대입니다. 퍼플팀 데이터(실행 vs 탐지)는 이 균형점을 추측이 아닌 측정으로 잡게 해줍니다.

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

<!-- detect-validate-68 -->
## 공격 탐지와 방어 검증

탐지 엔지니어링의 종착점은 "룰을 배포했다"가 아니라 "공격을 실행했을 때 그 룰이 발화하고, 정상 트래픽엔 안 뜬다"를 증명하는 것이다(정탐·오탐 동시 측정).

### 공격 → 계층 → 통제(탐지 룰) → 탐지 신호

| 공격 | 노리는 계층 | 탐지 룰(예) | 탐지 신호 |
|---|---|---|---|
| 인코딩 PowerShell | 스크립트 실행 | Sigma: `EncodedCommand` | 4104 ScriptBlock + `-enc` |
| LSASS 덤프 | 자격증명 | Sigma: lsass 핸들 접근 | Sysmon 10 GrantedAccess 0x1010 |
| 의심 예약작업 | 지속성 | Sigma: schtasks 생성 | 4698 + 비표준 바이너리 경로 |
| C2 비커닝 | 네트워크 | Suricata: 주기적 비컨 | 균일 간격 아웃바운드 |

### 방어 검증 (직접 확인)

```bash
# 1) 룰이 공격에 '발화'하는지: 해당 기법을 실행하고 룰 매칭 확인
Invoke-AtomicTest T1059.001 -TestNumbers 1
# 2) 정탐/오탐을 함께 측정 (히스토리 로그로 회귀)
#    공격 윈도우 vs 정상 윈도우에 같은 룰을 돌려 TP/FP 집계
sigma convert -t splunk rule.yml > rule.spl     # 룰을 SIEM 쿼리로 변환
#   TP = 공격 시간창 매칭 수 / 실행 횟수
#   FP = 정상 시간창 매칭 수 / 정상 이벤트 수
# 통과: TP가 기준 이상이면서 FP가 분석가 허용 한도 이하
# 취약: TP 낮으면 미탐(룰 약함), FP 높으면 경보 피로 → 튜닝 필요
```

> 검증은 반드시 **승인된 범위·통제된 환경에서만** 수행한다. 룰은 배포로 끝나지 않으며, 데이터 소스가 바뀔 때마다 정탐·오탐을 재측정해 노후(rule decay)를 잡아야 한다([[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- Detection-as-Code 파이프라인(Sigma→SIEM 백엔드, pySigma/sigma-cli)에 룰 단위테스트·회귀검사를 CI로 결합 — 정탐/오탐 표본 코퍼스를 룰 변경마다 재실행
- ATT&CK 커버리지 정량화 도구(DeTT&CT·VECTR)로 탐지 갭을 가시화하고, 행위·ML 기반 분석은 데이터소스 드리프트 시 오탐 재기준선화가 필수([[13_SOC_Blue_Team]])

---

<a name="english"></a>

# Detection Engineering

## Lab Environment Setup

> You need tooling to author, convert and validate detection rules.

```bash
pip install sigma-cli            # convert rules:  sigma convert ...
sudo apt install yara suricata   # file / network detection
pip install yara-python
# Backend (pick one): Elastic Stack or Splunk (free trial)
# Public Sigma ruleset: https://github.com/SigmaHQ/sigma
```

> Validation tip: run the same rule over an attack window and a normal window to measure TP/FP together. Low TP = misses (weak rule); high FP = alert fatigue → tune.
> ⚠️ **Isolation required**: keep test logs/targets in an isolated env.
> 🧪 No container lab — build SIEM + Sigma/YARA yourself.

---

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

### Detection Robustness: The Pyramid of Pain

David Bianco's "Pyramid of Pain" shows that the indicator you detect on dictates the cost an attacker pays to evade. Robust detection targets the hard-to-change upper layers.

| Layer | Detects on | Evasion cost | Example |
|---|---|---|---|
| Hash | File MD5/SHA256 | Trivial (1-byte change) | YARA hash rule |
| IP/domain | C2 infra | Low (redeploy) | IOC block |
| Artifact | Registry/filename | Medium | Sigma selection |
| Tool | Tool signature | High (rewrite) | Behavior rule |
| **TTP** | **Behavioral pattern** | **Very high** | **High-level behavior detection** |

> Pitfall: a rule like `CommandLine|contains: -EncodedCommand` is trivially bypassed by `-enc`, `-e`, mixed case, or inserted whitespace. Robust rules target the decoded base64 result, parent-child process relationships, or the rarity of the behavior itself. Purple teams run multiple variants of the same technique to verify a rule catches *behavior*, not a *string*.

### Detection Rule Lifecycle and Quality Metrics

Rules don't end at deployment — they decay as data sources and normal behavior change.

| Stage | Activity | Metric |
|---|---|---|
| Author | Hypothesis → rule → test case | Test pass/fail |
| Validate | Confirm true positive via purple sim | TP rate |
| Tune | Analyze FP cause → add filter | FP rate, precision |
| Operate | Track alert triage | Time per alert |
| Retire/refresh | Identify and replace stale rules | Dormant period, coverage change |

Core trade-off: broad rules reduce false negatives but raise false positives (analyst fatigue); narrow rules do the opposite. Purple team data (executed vs detected) lets you find that balance by measurement, not guesswork.

## Summary Table

| Rule Type | Target | Language |
|---|---|---|
| Sigma | SIEM logs | YAML |
| Snort/Suricata | Network packets | DSL |
| YARA | Files/memory | YARA |
| KQL | Azure Sentinel | Kusto QL |
| SPL | Splunk | SPL |

---

## Attack Detection and Defense Validation

The endpoint of detection engineering is not "the rule is deployed" but "it fires when the attack runs and stays quiet on benign traffic" (measure true and false positives together).

### Attack -> layer -> control (detection rule) -> detection signal

| Attack | Target layer | Detection rule (example) | Detection signal |
|---|---|---|---|
| Encoded PowerShell | Script execution | Sigma: `EncodedCommand` | 4104 ScriptBlock + `-enc` |
| LSASS dump | Credentials | Sigma: lsass handle access | Sysmon 10 GrantedAccess 0x1010 |
| Suspicious scheduled task | Persistence | Sigma: schtasks creation | 4698 + nonstandard binary path |
| C2 beaconing | Network | Suricata: periodic beacon | Uniform-interval outbound |

### Defense validation (verify yourself)

```bash
# 1) Does the rule 'fire' on the attack: run the technique and check the rule match
Invoke-AtomicTest T1059.001 -TestNumbers 1
# 2) Measure TP/FP together (regress over historical logs)
#    Run the same rule over the attack window vs a benign window and tally TP/FP
sigma convert -t splunk rule.yml > rule.spl     # convert the rule to a SIEM query
#   TP = matches in the attack window / executions
#   FP = matches in the benign window / benign events
# Pass: TP above threshold while FP stays under the analyst's tolerance
# Weak: low TP means false negatives (weak rule); high FP means alert fatigue -> tune
```

> Run validation only within an **authorized scope, in a controlled environment**. A rule isn't finished at deployment — re-measure TP/FP whenever data sources change to catch rule decay (see [[13_SOC_Blue_Team]]).
