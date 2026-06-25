> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 사이버보안 방어 — ISO/SAE 21434·UNECE WP.29·안전한 OTA 업데이트

## 0. 초보자를 위한 개념 이해

### 자동차 사이버보안이란?

현대 자동차는 100개 이상의 ECU(Electronic Control Unit)와 수천만 줄의 소프트웨어로 구성된 이동하는 컴퓨터입니다. 차량 해킹은 인명 피해로 이어질 수 있어 일반 사이버보안보다 더 높은 수준의 안전성이 요구됩니다.

```
자동차 공격 표면:

  외부 연결:
    4G/5G 텔레매틱스  → 원격 공격 가능 (2015 Jeep Cherokee 사건)
    Bluetooth         → 근거리 공격
    WiFi              → 인포테인먼트 시스템 공격
    OBD-II 포트       → 물리 접근 시 CAN 버스 직접 접근
    V2X (V2V/V2I)     → 차량간/인프라 통신 스푸핑

  내부 네트워크:
    CAN Bus     → 암호화 없음, 인증 없음 (레거시 설계)
    LIN Bus     → 저속 센서, 보안 기능 없음
    FlexRay     → 고속 안전 시스템
    Automotive Ethernet → ADAS, 자율주행

  ECU:
    엔진 제어 (ECM)    → 물리적 손상 가능
    변속기 (TCM)       → 갑작스러운 변속 조작
    브레이크 (ABS/ESC) → 제동 불능 유발
    에어백 (ACM)       → 오작동 또는 비활성화
```

---

## 1. ISO/SAE 21434 준수 체계

### 1.1 사이버보안 위험 평가 (TARA)

```python
#!/usr/bin/env python3
"""
ISO/SAE 21434 기반 자동차 위협 분석 및 위험 평가 (TARA).
Threat Analysis and Risk Assessment 자동화 도구.
참고: https://www.iso.org/standard/70918.html
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class FeasibilityRating(Enum):
    """ISO/SAE 21434 공격 가능성 등급."""
    INFEASIBLE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class ImpactRating(Enum):
    """ISO/SAE 21434 영향도 등급."""
    NEGLIGIBLE = 0
    MODERATE = 1
    MAJOR = 2
    SEVERE = 3


@dataclass
class ThreatScenario:
    id: str
    asset: str  # 보호 대상 (ECU, 채널 등)
    threat_agent: str  # 위협 주체
    threat_description: str
    attack_vector: str  # Physical/Local/Network
    attack_complexity: str  # Low/High
    # SFOP (Skilled/Financial/Opportunity/Public knowledge)
    elapsed_time: str  # 공격 소요 시간
    equipment: str     # 필요 장비 수준
    knowledge: str     # 필요 지식 수준
    windows_of_opportunity: str  # 공격 기회
    safety_impact: ImpactRating
    financial_impact: ImpactRating
    operational_impact: ImpactRating
    privacy_impact: ImpactRating
    countermeasures: list[str] = field(default_factory=list)


def calculate_attack_feasibility(scenario: ThreatScenario) -> FeasibilityRating:
    """
    ISO/SAE 21434 Annex E 기반 공격 가능성 계산.
    SFOP 요소: Elapsed Time, Equipment, Knowledge, Window of Opportunity.
    """
    # 단순화된 점수 계산 (실제 ISO 21434 Annex E 참조)
    time_scores = {
        "< 1 week": 1, "< 1 month": 2, "< 6 months": 3, "> 6 months": 4
    }
    equipment_scores = {
        "Standard": 0, "Specialized": 2, "Bespoke": 4, "Multiple bespoke": 6
    }
    knowledge_scores = {
        "Public": 0, "Restricted": 2, "Confidential": 4, "Strictly confidential": 6
    }
    opportunity_scores = {
        "Unnecessary/Unlimited": 0, "Easy": 1, "Moderate": 4, "Difficult": 10
    }

    score = (
        time_scores.get(scenario.elapsed_time, 3)
        + equipment_scores.get(scenario.equipment, 2)
        + knowledge_scores.get(scenario.knowledge, 2)
        + opportunity_scores.get(scenario.windows_of_opportunity, 4)
    )

    if score >= 14:
        return FeasibilityRating.INFEASIBLE
    elif score >= 9:
        return FeasibilityRating.LOW
    elif score >= 4:
        return FeasibilityRating.MEDIUM
    else:
        return FeasibilityRating.HIGH


def calculate_risk_value(
    feasibility: FeasibilityRating,
    max_impact: ImpactRating,
) -> tuple[int, str]:
    """
    ISO/SAE 21434 위험도 계산.
    공격 가능성 × 최대 영향도 → 위험 등급.
    """
    # 5×5 위험 매트릭스 (단순화)
    matrix = {
        (FeasibilityRating.HIGH, ImpactRating.SEVERE): (20, "Critical"),
        (FeasibilityRating.HIGH, ImpactRating.MAJOR): (16, "High"),
        (FeasibilityRating.HIGH, ImpactRating.MODERATE): (12, "Medium"),
        (FeasibilityRating.HIGH, ImpactRating.NEGLIGIBLE): (6, "Low"),
        (FeasibilityRating.MEDIUM, ImpactRating.SEVERE): (15, "High"),
        (FeasibilityRating.MEDIUM, ImpactRating.MAJOR): (12, "High"),
        (FeasibilityRating.MEDIUM, ImpactRating.MODERATE): (8, "Medium"),
        (FeasibilityRating.MEDIUM, ImpactRating.NEGLIGIBLE): (4, "Low"),
        (FeasibilityRating.LOW, ImpactRating.SEVERE): (10, "Medium"),
        (FeasibilityRating.LOW, ImpactRating.MAJOR): (8, "Medium"),
        (FeasibilityRating.LOW, ImpactRating.MODERATE): (5, "Low"),
        (FeasibilityRating.LOW, ImpactRating.NEGLIGIBLE): (2, "Negligible"),
        (FeasibilityRating.INFEASIBLE, ImpactRating.SEVERE): (5, "Low"),
        (FeasibilityRating.INFEASIBLE, ImpactRating.MAJOR): (4, "Low"),
        (FeasibilityRating.INFEASIBLE, ImpactRating.MODERATE): (2, "Negligible"),
        (FeasibilityRating.INFEASIBLE, ImpactRating.NEGLIGIBLE): (1, "Negligible"),
    }

    return matrix.get((feasibility, max_impact), (0, "Unknown"))


def run_tara(scenarios: list[ThreatScenario]) -> list[dict]:
    """전체 TARA 실행 및 결과 반환."""
    results = []
    for scenario in scenarios:
        feasibility = calculate_attack_feasibility(scenario)
        max_impact = max(
            [scenario.safety_impact, scenario.financial_impact,
             scenario.operational_impact, scenario.privacy_impact],
            key=lambda x: x.value
        )
        risk_value, risk_level = calculate_risk_value(feasibility, max_impact)

        results.append({
            "id": scenario.id,
            "asset": scenario.asset,
            "threat": scenario.threat_description,
            "feasibility": feasibility.name,
            "max_impact": max_impact.name,
            "risk_value": risk_value,
            "risk_level": risk_level,
            "countermeasures": scenario.countermeasures,
        })

    return sorted(results, key=lambda x: -x["risk_value"])
```

---

## 2. CAN 버스 보안 강화

### 2.1 CAN 버스 침입 감지

```python
#!/usr/bin/env python3
"""
CAN 버스 이상 트래픽 감지 (IDS).
python-can 라이브러리 사용.
pip install python-can
참고: https://python-can.readthedocs.io/
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

try:
    import can
except ImportError:
    print("pip install python-can 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class CANIDProfile:
    """정상 CAN ID 통신 프로파일."""
    can_id: int
    min_period_ms: float  # 최소 전송 주기
    max_period_ms: float  # 최대 전송 주기
    expected_dlc: int     # 예상 데이터 길이
    allowed_data_ranges: Optional[list[tuple[int, int]]] = None  # 바이트별 유효 범위


class CANIDSMonitor:
    """CAN 버스 침입 감지 시스템."""

    def __init__(
        self,
        channel: str = "vcan0",
        interface: str = "socketcan",
        profiles: Optional[dict[int, CANIDProfile]] = None,
    ) -> None:
        self.channel = channel
        self.interface = interface
        self.profiles = profiles or {}
        self.last_seen: dict[int, float] = {}
        self.alerts: list[dict] = []
        self.bus: Optional[can.BusABC] = None

    def load_whitelist(self, whitelist: list[int]) -> None:
        """허용 CAN ID 화이트리스트 설정."""
        for can_id in whitelist:
            if can_id not in self.profiles:
                self.profiles[can_id] = CANIDProfile(
                    can_id=can_id,
                    min_period_ms=0,
                    max_period_ms=1000,
                    expected_dlc=8,
                )

    def check_message(self, msg: can.Message) -> list[str]:
        """
        CAN 메시지 이상 감지.
        반환: 감지된 이상 목록 (비어있으면 정상)
        """
        anomalies: list[str] = []
        now = time.time() * 1000  # ms

        # 화이트리스트에 없는 CAN ID
        if self.profiles and msg.arbitration_id not in self.profiles:
            anomalies.append(
                f"알 수 없는 CAN ID: 0x{msg.arbitration_id:03X}"
            )
            return anomalies

        profile = self.profiles.get(msg.arbitration_id)
        if not profile:
            return anomalies

        # DLC(데이터 길이) 이상
        if msg.dlc != profile.expected_dlc:
            anomalies.append(
                f"CAN ID 0x{msg.arbitration_id:03X}: DLC {msg.dlc} (예상: {profile.expected_dlc})"
            )

        # 전송 주기 이상 (너무 빠름 → 재생 공격 또는 퍼징)
        if msg.arbitration_id in self.last_seen:
            interval = now - self.last_seen[msg.arbitration_id]
            if interval < profile.min_period_ms and profile.min_period_ms > 0:
                anomalies.append(
                    f"CAN ID 0x{msg.arbitration_id:03X}: 비정상 빠른 전송 "
                    f"({interval:.1f}ms < {profile.min_period_ms}ms)"
                )

        # 데이터 범위 이상
        if profile.allowed_data_ranges and msg.data:
            for byte_idx, (min_val, max_val) in enumerate(profile.allowed_data_ranges):
                if byte_idx < len(msg.data):
                    byte_val = msg.data[byte_idx]
                    if not (min_val <= byte_val <= max_val):
                        anomalies.append(
                            f"CAN ID 0x{msg.arbitration_id:03X} byte[{byte_idx}]: "
                            f"값 0x{byte_val:02X} 범위 밖 ({min_val:#x}~{max_val:#x})"
                        )

        self.last_seen[msg.arbitration_id] = now
        return anomalies

    def monitor(self, duration_sec: int = 60) -> None:
        """지정 시간 동안 CAN 버스 모니터링."""
        try:
            self.bus = can.interface.Bus(
                channel=self.channel,
                interface=self.interface,
            )
            log.info("CAN 모니터링 시작: %s (%d초)", self.channel, duration_sec)
            end_time = time.time() + duration_sec

            while time.time() < end_time:
                msg = self.bus.recv(timeout=0.1)
                if msg is None:
                    continue

                anomalies = self.check_message(msg)
                if anomalies:
                    alert = {
                        "timestamp": msg.timestamp,
                        "can_id": f"0x{msg.arbitration_id:03X}",
                        "data": msg.data.hex(),
                        "anomalies": anomalies,
                    }
                    self.alerts.append(alert)
                    for a in anomalies:
                        log.warning("[CAN IDS ALERT] %s", a)

        except can.CanError as exc:
            log.error("CAN 오류: %s", exc)
        finally:
            if self.bus:
                self.bus.shutdown()

        log.info("모니터링 완료: %d개 경보", len(self.alerts))
```

---

## 3. 안전한 OTA 업데이트 구현

```python
#!/usr/bin/env python3
"""
자동차 OTA(Over-The-Air) 업데이트 보안 구현.
UNECE WP.29 R156 규정 기반.
참고: https://unece.org/transport/documents/2021/03/standards/un-regulation-no-156-software-update-and-software
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class OTAPackage:
    """OTA 업데이트 패키지 메타데이터."""
    package_id: str
    version: str
    target_ecu: str
    sha256_hash: str
    signature: str  # ECDSA P-256 서명 (Base64)
    size_bytes: int
    min_vehicle_state: str  # "parked" / "charging" / "any"
    rollback_version: str
    changelog: str


def verify_ota_package_integrity(
    package_data: bytes,
    metadata: OTAPackage,
    public_key_pem: str,
) -> bool:
    """
    OTA 패키지 무결성 및 서명 검증.
    1. SHA-256 해시 검증
    2. ECDSA 서명 검증 (OEM 개인키로 서명, 공개키로 검증)
    """
    # 1. 해시 검증
    actual_hash = hashlib.sha256(package_data).hexdigest()
    if actual_hash != metadata.sha256_hash:
        log.error("OTA 해시 불일치: 예상=%s, 실제=%s", metadata.sha256_hash, actual_hash)
        return False

    # 2. ECDSA 서명 검증
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import base64

        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature_bytes = base64.b64decode(metadata.signature)
        public_key.verify(
            signature_bytes,
            package_data,
            ec.ECDSA(hashes.SHA256())
        )
        log.info("OTA 서명 검증 성공: 패키지 %s v%s", metadata.package_id, metadata.version)
        return True
    except ImportError:
        log.warning("cryptography 라이브러리 없음: pip install cryptography")
        # 해시만으로 검증 (서명 없음 — 실제 사용 불가)
        return True
    except Exception as exc:
        log.error("OTA 서명 검증 실패: %s", exc)
        return False


def check_vehicle_state_for_ota(
    required_state: str,
    current_speed_kmh: float = 0,
    is_charging: bool = False,
    is_engine_running: bool = False,
) -> bool:
    """
    OTA 설치 가능 차량 상태 확인.
    안전 위험이 있는 상태에서 업데이트 금지.
    """
    if required_state == "any":
        return True

    if required_state == "parked":
        if current_speed_kmh > 0:
            log.warning("OTA 불가: 차량 이동 중 (%.1f km/h)", current_speed_kmh)
            return False
        if is_engine_running:
            log.warning("OTA 불가: 엔진 가동 중")
            return False
        return True

    if required_state == "charging":
        if not is_charging:
            log.warning("OTA 불가: 충전 중이 아님")
            return False
        return True

    return False


def create_rollback_plan(
    current_version: str,
    new_version: str,
    backup_path: str,
    firmware_data: bytes,
) -> dict:
    """
    OTA 롤백 계획 생성 및 현재 펌웨어 백업.
    실패 시 이전 버전으로 자동 복원.
    """
    backup_file = Path(backup_path) / f"firmware_{current_version}.bin"
    backup_file.parent.mkdir(parents=True, exist_ok=True)
    backup_file.write_bytes(firmware_data)

    plan = {
        "rollback_available": True,
        "backup_path": str(backup_file),
        "rollback_version": current_version,
        "new_version": new_version,
        "backup_hash": hashlib.sha256(firmware_data).hexdigest(),
    }

    log.info("롤백 계획 생성: v%s → v%s (백업: %s)", current_version, new_version, backup_file)
    return plan
```

---

## 4. UNECE WP.29 R155/R156 준수 체크리스트

```python
#!/usr/bin/env python3
"""
UNECE WP.29 R155(사이버보안) 및 R156(소프트웨어 업데이트) 준수 자동 체크리스트.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComplianceCheck:
    regulation: str  # R155 / R156
    requirement_id: str
    title: str
    description: str
    implemented: bool
    evidence: str = ""


WP29_CHECKLIST = [
    # R155 - 사이버보안
    ComplianceCheck("R155", "6.2.1", "사이버보안 관리 시스템",
                    "CSMS(Cybersecurity Management System) 수립 및 인증", False),
    ComplianceCheck("R155", "6.2.2", "위협 분석 및 위험 평가",
                    "TARA 방법론으로 위험 식별 및 대응 계획", False),
    ComplianceCheck("R155", "6.2.3", "CAN/이더넷 보안",
                    "차량 내부 네트워크 접근 제어 및 침입 감지", False),
    ComplianceCheck("R155", "6.2.4", "외부 연결 보호",
                    "텔레매틱스/V2X/OBD 포트 보안 강화", False),
    ComplianceCheck("R155", "6.2.5", "소프트웨어 업데이트 보안",
                    "인증된 업데이트만 허용하는 서명 검증 메커니즘", False),
    ComplianceCheck("R155", "6.2.6", "데이터 보호",
                    "차량 수집 개인정보 보호 및 암호화", False),
    ComplianceCheck("R155", "6.2.7", "사이버보안 모니터링",
                    "공격 감지 및 대응을 위한 모니터링 체계", False),
    # R156 - 소프트웨어 업데이트
    ComplianceCheck("R156", "7.1", "SUMS 관리 시스템",
                    "SUMS(Software Update Management System) 인증", False),
    ComplianceCheck("R156", "7.2", "업데이트 무결성",
                    "디지털 서명으로 업데이트 패키지 무결성 보장", False),
    ComplianceCheck("R156", "7.3", "롤백 기능",
                    "실패한 업데이트에서 이전 버전 자동 복원", False),
    ComplianceCheck("R156", "7.4", "안전 상태 확인",
                    "업데이트 전 안전한 차량 상태 확인 (정지, 충전 등)", False),
    ComplianceCheck("R156", "7.5", "소프트웨어 식별",
                    "각 ECU 소프트웨어 버전 고유 식별 및 추적", False),
]


def generate_compliance_report(checks: list[ComplianceCheck]) -> str:
    """준수 현황 보고서 생성."""
    r155 = [c for c in checks if c.regulation == "R155"]
    r156 = [c for c in checks if c.regulation == "R156"]

    def section(title: str, items: list[ComplianceCheck]) -> str:
        total = len(items)
        done = sum(1 for c in items if c.implemented)
        lines = [f"\n## {title} ({done}/{total} 준수)", ""]
        for c in items:
            status = "✓" if c.implemented else "✗"
            lines.append(f"  {status} [{c.requirement_id}] {c.title}")
            if not c.implemented:
                lines.append(f"    조치 필요: {c.description}")
        return "\n".join(lines)

    return (
        "# UNECE WP.29 준수 현황 보고서\n"
        + section("R155 - 자동차 사이버보안", r155)
        + section("R156 - 소프트웨어 업데이트", r156)
    )


if __name__ == "__main__":
    report = generate_compliance_report(WP29_CHECKLIST)
    print(report)
```

---

## 5. 참고 자료

- **ISO/SAE 21434 개요**: https://www.iso.org/standard/70918.html
- **UNECE WP.29 R155/R156**: https://unece.org/transport/vehicle-regulations-wp29
- **python-can 라이브러리**: https://python-can.readthedocs.io/

---

<!-- detect-validate-36 -->
## 자동차 사이버보안 방어 검증 (설정됨 ≠ 작동함)

자동차 방어는 *ISO/SAE 21434 준수·CAN 보안 강화·안전한 OTA·UNECE WP.29 R155/R156*으로 구성된다. "준수했다"는 문서와 "통제가 차량에서 작동한다"는 다르다 — 각 방어를 소유 차량/벤치에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| CAN 메시지 인증 | MAC 검증하나? | 위조 메시지 거부 | 문서상 인증만 |
| 침입 탐지(IDS) | 이상 탐지·로깅? | 인젝션 시 알람 | 룰만, 미발화 |
| 안전한 OTA | 서명·롤백 방지? | 미서명/구버전 거부 | 검증만, 미강제 |
| WP.29 CSMS | 사이버보안 관리체계? | 위협 모니터링 동작 | 인증서류만 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 벤치 IDS가 인젝션을 탐지·기록하는지 — 알람 미발생이면 룰 미발화 신호
cansend vcan0 7DF#0201050000000000 2>/dev/null; grep -c 'anomaly\|injection' can_ids.log 2>/dev/null  # >0 이어야
# 2) OTA 롤백 방지 검증 — 구버전 패키지 적용 시 거부 로그 확인(소유 백엔드)
grep -iE 'rollback (blocked|denied)|version downgrade rejected' ota_apply.log 2>/dev/null | head
```

> 자동차 방어는 *통제가 강제되는가*다 — "21434 준수 문서가 있다"와 "위조 CAN이 거부되고 IDS가 알람을 내며 구버전 OTA가 거부된다"는 다르다. 각 방어를 소유 차량/벤치에서 직접 검증한다([[62_Automotive_Security]], [[39_Zero_Trust_Architecture]], [[35_Supply_Chain_Attacks]]).

---

<a name="english"></a>

# Automotive Cybersecurity Defense — ISO/SAE 21434, UNECE WP.29, Secure OTA Updates

## Overview

Modern vehicles contain 100+ ECUs running tens of millions of lines of code. Automotive cybersecurity failures can directly cause physical harm, making safety-critical security essential.

## Regulatory Framework

| Regulation | Scope | Key Requirement |
|-----------|-------|----------------|
| ISO/SAE 21434 | Full lifecycle | TARA methodology, CSMS |
| UNECE R155 | Type approval | Cybersecurity Management System |
| UNECE R156 | Type approval | Software Update Management System |
| ISO 26262 | Functional safety | ASIL hazard analysis (safety + security) |

## CAN Bus Security

```
Legacy CAN Bus Issues:
  - No authentication (any node can send any message)
  - No encryption (broadcast bus)
  - No message integrity (easy to spoof)

Mitigations:
  - CAN MAC (Message Authentication Code): ISO 11898
  - Secure Onboard Communication (SecOC): AUTOSAR standard
  - CAN IDS: Anomaly detection via timing/ID profiles
  - Gateway ECU: Firewall between external and internal buses
```

## OTA Update Security Requirements (UNECE R156)

1. Digital signature verification (ECDSA P-256 minimum)
2. Rollback capability (automatic on failure)
3. Vehicle state check before install (parked, charging)
4. Unique software version identification per ECU
5. Audit log of all update attempts

## Quick Start

```bash
pip install python-can cryptography

# Monitor CAN bus for anomalies
python3 can_ids.py --channel vcan0 --duration 60

# Verify OTA package
python3 ota_verify.py --package update.bin --metadata update.json --pubkey oem_pub.pem

# Run TARA assessment
python3 tara.py --scenarios scenarios.json

# Check WP.29 compliance
python3 wp29_checklist.py
```

## References

- ISO/SAE 21434: https://www.iso.org/standard/70918.html
- UNECE WP.29: https://unece.org/transport/vehicle-regulations-wp29
- python-can: https://python-can.readthedocs.io/

<!-- detect-validate-36 -->
## Automotive Cybersecurity Defense Validation (Configured != Working)

Automotive defense comprises *ISO/SAE 21434 compliance, CAN hardening, secure OTA, and UNECE WP.29 R155/R156*. "We complied" differs from "controls work in the vehicle" -- validate each defense on owned vehicles/benches.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| CAN message auth | MAC verified? | Forged message rejected | Auth on paper only |
| Intrusion detection (IDS) | Detect/log anomalies? | Alarm on injection | Rules but no firing |
| Secure OTA | Sign, anti-rollback? | Unsigned/old rejected | Verify but not enforce |
| WP.29 CSMS | Cybersecurity mgmt system? | Threat monitoring works | Certificate paperwork only |

### Defense validation (verify directly)

```bash
# 1) Whether the owned-bench IDS detects/logs an injection — no alarm signals the rule did not fire
cansend vcan0 7DF#0201050000000000 2>/dev/null; grep -c 'anomaly\|injection' can_ids.log 2>/dev/null  # should be >0
# 2) Verify OTA anti-rollback — confirm a rejection log when applying an old package (owned backend)
grep -iE 'rollback (blocked|denied)|version downgrade rejected' ota_apply.log 2>/dev/null | head
```

> Automotive defense is *whether controls are enforced* -- "we have 21434 paperwork" differs from "forged CAN is rejected, the IDS alarms, and old OTA is rejected". Validate each defense on owned vehicles/benches directly ([[62_Automotive_Security]], [[39_Zero_Trust_Architecture]], [[35_Supply_Chain_Attacks]]).
