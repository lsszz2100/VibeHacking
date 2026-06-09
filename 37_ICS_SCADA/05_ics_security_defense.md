> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# ICS/SCADA 보안 방어 — IEC 62443·네트워크 분리·OT 모니터링

## 0. 초보자를 위한 개념 이해

### ICS/SCADA 보안이란?

산업 제어 시스템(ICS)과 SCADA는 발전소, 수처리장, 제조 시설 등 핵심 인프라를 제어합니다. 사이버 공격으로 물리적 피해, 인명 피해, 환경 오염이 발생할 수 있어 IT 보안과 다른 접근이 필요합니다.

```
IT vs OT 보안 비교:

  IT (정보 기술):
    우선순위: 기밀성 → 무결성 → 가용성 (CIA)
    패치 주기: 즉각 적용 가능
    재시작: 언제든 가능

  OT (운영 기술):
    우선순위: 가용성 → 무결성 → 기밀성 (AIC)
    패치 주기: 계획 정비 기간에만 (수개월~수년)
    재시작: 생산 중단 = 수억 원 손실

  ICS 특수 위협:
    Stuxnet      → 이란 핵 원심분리기 물리 파괴 (2010)
    INDUSTROYER  → 우크라이나 전력망 공격 (2016)
    TRITON       → 안전 시스템(SIS) 공격 (2017)
    Industroyer2 → 우크라이나 전력 (2022)
```

---

## 1. IEC 62443 보안 아키텍처

### 1.1 보안 영역 및 도관 설계 (Zones & Conduits)

```
IEC 62443 보안 영역 모델:

  영역 4: 기업 IT 네트워크
    └─[방화벽/DMZ]─
  영역 3: 제어실/SCADA 서버
    └─[데이터 다이오드]─
  영역 2: 제어 시스템 (DCS, SCADA HMI)
    └─[ICS 방화벽]─
  영역 1: 기본 제어 (PLC, RTU, DCS 제어기)
    └─[직렬/필드버스]─
  영역 0: 현장 장치 (센서, 액추에이터)

  도관(Conduit): 영역 간 통신 채널
    - 모든 도관은 명시적 정의 및 승인 필요
    - 허용된 프로토콜과 방향만 통과 가능
    - 단방향 데이터 흐름 → 데이터 다이오드 사용

  SL (Security Level):
    SL-1: 우발적 침해 방어
    SL-2: 의도적이지만 기초적인 공격 방어 (목표 ICS)
    SL-3: 정교한 공격자 방어
    SL-4: 국가급 위협 방어
```

### 1.2 ICS 방화벽 규칙 자동화

```python
#!/usr/bin/env python3
"""
ICS 방화벽 규칙 생성 자동화.
IEC 62443 Zone/Conduit 모델 기반.
Modbus/DNP3/EtherNet/IP 프로토콜 화이트리스트 방식.
참고: https://www.iec.ch/iec62443
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class ICSZone:
    name: str
    security_level: int  # SL-1~4
    network_cidr: str
    allowed_protocols: list[str]
    allowed_remote_zones: list[str]


@dataclass
class FirewallRule:
    rule_id: str
    zone_from: str
    zone_to: str
    protocol: str
    port: int
    direction: str  # unidirectional/bidirectional
    action: str     # allow/deny
    description: str


# ICS 프로토콜 포트 정의
ICS_PROTOCOL_PORTS = {
    "Modbus_TCP": 502,
    "DNP3": 20000,
    "EtherNet/IP": 44818,
    "IEC_61850_MMS": 102,
    "IEC_60870_5_104": 2404,
    "OPC_UA": 4840,
    "PROFINET": 34964,
    "BACnet": 47808,
}


def generate_zone_firewall_rules(
    zones: list[ICSZone],
) -> list[FirewallRule]:
    """
    Zone/Conduit 정의에서 방화벽 규칙 자동 생성.
    최소 권한 원칙: 명시적으로 허용된 것만 통과.
    """
    rules: list[FirewallRule] = []
    rule_counter = 1

    zone_map = {z.name: z for z in zones}

    for zone in zones:
        for remote_zone_name in zone.allowed_remote_zones:
            remote_zone = zone_map.get(remote_zone_name)
            if not remote_zone:
                continue

            for protocol in zone.allowed_protocols:
                port = ICS_PROTOCOL_PORTS.get(protocol)
                if not port:
                    continue

                # 상위 영역에서 하위 영역으로 단방향 제어 (IEC 62443 원칙)
                rules.append(FirewallRule(
                    rule_id=f"RULE-{rule_counter:04d}",
                    zone_from=zone.name,
                    zone_to=remote_zone_name,
                    protocol=protocol,
                    port=port,
                    direction="unidirectional",
                    action="allow",
                    description=f"{zone.name} → {remote_zone_name}: {protocol}({port}/tcp)",
                ))
                rule_counter += 1

    # 기본 거부 규칙 (Deny All)
    rules.append(FirewallRule(
        rule_id=f"RULE-{rule_counter:04d}",
        zone_from="any",
        zone_to="any",
        protocol="any",
        port=0,
        direction="bidirectional",
        action="deny",
        description="기본 거부 규칙 (IEC 62443 최소 접근 원칙)",
    ))

    log.info("방화벽 규칙 생성: %d개", len(rules))
    return rules


def export_iptables_rules(rules: list[FirewallRule]) -> str:
    """생성된 규칙을 iptables 형식으로 변환."""
    lines = [
        "#!/bin/bash",
        "# ICS 방화벽 규칙 (IEC 62443 기반)",
        "# 자동 생성 — 수동 수정 금지",
        "",
        "iptables -F FORWARD",
        "iptables -P FORWARD DROP",
        "",
    ]

    for rule in rules:
        if rule.action == "deny" and rule.zone_from == "any":
            continue  # 기본 DROP은 정책으로 이미 설정
        if rule.port == 0:
            continue

        proto = "tcp" if "TCP" in rule.protocol or rule.protocol in ["Modbus_TCP", "DNP3", "OPC_UA"] else "tcp"
        lines.append(
            f"# {rule.description}"
        )
        lines.append(
            f"iptables -A FORWARD -p {proto} --dport {rule.port} "
            f"-j ACCEPT  # {rule.rule_id}"
        )

    return "\n".join(lines)
```

---

## 2. OT 네트워크 이상 탐지

### 2.1 Modbus/DNP3 트래픽 이상 감지

```python
#!/usr/bin/env python3
"""
OT 프로토콜 이상 감지 시스템.
Modbus TCP/DNP3 프로토콜 파싱 및 이상 행위 탐지.
pip install pymodbus scapy
"""
from __future__ import annotations

import logging
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class ModbusAlert:
    timestamp: float
    src_ip: str
    dst_ip: str
    function_code: int
    alert_type: str
    details: str


# Modbus 함수 코드 정의
MODBUS_FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    43: "Read Device Identification",
}

# 쓰기 기능 코드 (공격 가능성 높음)
WRITE_FUNCTION_CODES = {5, 6, 15, 16}
# 진단 기능 코드
DIAGNOSTIC_FUNCTION_CODES = {8, 43}


class ModbusIDSAnalyzer:
    """Modbus TCP 이상 탐지 분석기."""

    def __init__(self) -> None:
        self.baseline: dict[str, set] = defaultdict(set)  # IP당 허용 FC 집합
        self.request_counts: dict[str, int] = defaultdict(int)
        self.alerts: list[ModbusAlert] = []
        self.trained = False

    def train_baseline(self, traffic_samples: list[dict]) -> None:
        """
        정상 트래픽 프로파일 학습.
        각 소스 IP가 사용하는 정상 함수 코드 집합 구축.
        """
        for sample in traffic_samples:
            src = sample.get("src_ip", "")
            fc = sample.get("function_code", 0)
            if src and fc:
                self.baseline[src].add(fc)

        self.trained = True
        log.info("Modbus 베이스라인 학습 완료: %d개 IP 프로파일", len(self.baseline))

    def analyze_packet(
        self,
        src_ip: str,
        dst_ip: str,
        modbus_payload: bytes,
    ) -> list[ModbusAlert]:
        """Modbus TCP 패킷 이상 분석."""
        alerts: list[ModbusAlert] = []
        now = time.time()

        if len(modbus_payload) < 8:
            return alerts

        # Modbus TCP 헤더 파싱
        # [Transaction ID: 2] [Protocol ID: 2] [Length: 2] [Unit ID: 1] [FC: 1] [Data: N]
        try:
            trans_id, proto_id, length, unit_id, fc = struct.unpack(">HHHBB", modbus_payload[:8])
        except struct.error:
            return alerts

        # 프로토콜 ID는 0이어야 함
        if proto_id != 0:
            alerts.append(ModbusAlert(
                timestamp=now, src_ip=src_ip, dst_ip=dst_ip,
                function_code=fc,
                alert_type="INVALID_PROTOCOL_ID",
                details=f"Modbus 프로토콜 ID 이상: {proto_id} (0이어야 함)",
            ))

        # 알 수 없는 함수 코드
        if fc not in MODBUS_FUNCTION_CODES and fc < 0x80:
            alerts.append(ModbusAlert(
                timestamp=now, src_ip=src_ip, dst_ip=dst_ip,
                function_code=fc,
                alert_type="UNKNOWN_FUNCTION_CODE",
                details=f"알 수 없는 Modbus FC: {fc:#04x}",
            ))

        # 쓰기 명령 감지
        if fc in WRITE_FUNCTION_CODES:
            log.warning("Modbus 쓰기 명령: %s → %s FC=%d (%s)",
                        src_ip, dst_ip, fc, MODBUS_FUNCTION_CODES.get(fc, "Unknown"))
            alerts.append(ModbusAlert(
                timestamp=now, src_ip=src_ip, dst_ip=dst_ip,
                function_code=fc,
                alert_type="WRITE_COMMAND",
                details=f"Modbus 쓰기 명령 감지: {MODBUS_FUNCTION_CODES.get(fc, 'Unknown')}",
            ))

        # 베이스라인 이탈 감지
        if self.trained and src_ip in self.baseline:
            if fc not in self.baseline[src_ip] and fc < 0x80:
                alerts.append(ModbusAlert(
                    timestamp=now, src_ip=src_ip, dst_ip=dst_ip,
                    function_code=fc,
                    alert_type="BASELINE_DEVIATION",
                    details=f"비정상 함수 코드: {src_ip}은 FC {fc}를 사용하지 않음",
                ))

        # 요청 속도 제한 (DoS 감지)
        self.request_counts[src_ip] += 1
        # 간단한 속도 제한 (실제로는 슬라이딩 윈도우 필요)
        if self.request_counts[src_ip] > 1000:
            alerts.append(ModbusAlert(
                timestamp=now, src_ip=src_ip, dst_ip=dst_ip,
                function_code=fc,
                alert_type="HIGH_REQUEST_RATE",
                details=f"Modbus DoS 의심: {src_ip}에서 {self.request_counts[src_ip]}회 요청",
            ))
            self.request_counts[src_ip] = 0

        self.alerts.extend(alerts)
        return alerts
```

---

## 3. 데이터 다이오드 및 단방향 게이트웨이

```bash
# 데이터 다이오드 소프트웨어 구현 (Owl Cyber Defense 방식 참고)
# 실제 데이터 다이오드는 하드웨어 솔루션 사용 권장

# netcat 기반 단방향 UDP 데이터 전송 (개념 시연)
# OT 측 → IT 측으로만 데이터 전송 (반대 방향 물리적 불가)

# 송신 측 (OT 네트워크)
cat /var/log/scada_data.log | nc -u -w1 10.0.0.100 5000

# 수신 측 (IT/DMZ 네트워크)
nc -u -l -p 5000 >> /var/log/received_ot_data.log

# 실제 환경에서는 Waterfall Security, Owl Cyber Defense 등
# 하드웨어 데이터 다이오드 제품 사용
```

```python
#!/usr/bin/env python3
"""
소프트웨어 기반 단방향 데이터 복제 게이트웨이.
OT 네트워크 → DMZ → IT 네트워크로 단방향 데이터 전달.
실제 보안 환경에서는 하드웨어 데이터 다이오드 사용 권장.
"""
from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class DataDiodeConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 5000
    forward_host: str = "10.0.1.100"  # IT 네트워크
    forward_port: int = 5001
    max_packet_size: int = 65535
    allowed_src_networks: list[str] = None  # None = 모든 OT 네트워크


class SoftwareDataDiode:
    """
    소프트웨어 단방향 게이트웨이.
    UDP: 응답 없음 → 단방향 보장.
    """

    def __init__(self, config: DataDiodeConfig) -> None:
        self.config = config
        self.running = False
        self.packets_forwarded = 0

    def validate_source(self, src_ip: str) -> bool:
        """OT 측 허용 소스 IP 검증."""
        if not self.config.allowed_src_networks:
            return True
        import ipaddress
        try:
            src = ipaddress.ip_address(src_ip)
            return any(
                src in ipaddress.ip_network(net)
                for net in self.config.allowed_src_networks
            )
        except ValueError:
            return False

    def start(self) -> None:
        """단방향 포워딩 시작."""
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.bind((self.config.listen_host, self.config.listen_port))

        fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.running = True
        log.info("데이터 다이오드 시작: *:%d → %s:%d",
                 self.config.listen_port,
                 self.config.forward_host, self.config.forward_port)

        try:
            while self.running:
                try:
                    data, addr = recv_sock.recvfrom(self.config.max_packet_size)
                    src_ip = addr[0]

                    if not self.validate_source(src_ip):
                        log.warning("허용되지 않은 소스 IP: %s", src_ip)
                        continue

                    # 단방향 포워딩 (응답 없음 → TCP 불가, UDP만)
                    fwd_sock.sendto(data, (self.config.forward_host, self.config.forward_port))
                    self.packets_forwarded += 1

                    if self.packets_forwarded % 1000 == 0:
                        log.info("포워딩 패킷: %d개", self.packets_forwarded)

                except socket.timeout:
                    continue
        finally:
            recv_sock.close()
            fwd_sock.close()
```

---

## 4. ICS 보안 패치 관리

```python
#!/usr/bin/env python3
"""
ICS/OT 환경 패치 관리 자동화.
가용성 우선 원칙에 따른 위험 기반 패치 우선순위.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ICSTVAsset:
    asset_id: str
    name: str
    vendor: str
    model: str
    firmware_version: str
    os_version: str
    criticality: str  # Production-Critical/Safety-Critical/Support
    maintenance_window: str  # cron 형식 또는 설명
    last_patched: Optional[str] = None
    pending_patches: list[dict] = field(default_factory=list)


def prioritize_ics_patches(assets: list[ICSTVAsset]) -> list[dict]:
    """
    ICS 패치 우선순위 결정.
    OT 원칙: 안전 시스템 > 생산 시스템 > 지원 시스템.
    CVSS 점수 + 자산 임계도 + 보상 통제 유무 고려.
    """
    patch_queue = []

    for asset in assets:
        for patch in asset.pending_patches:
            cvss = patch.get("cvss_score", 0)
            # 안전 시스템은 CVSS 4.0 이상도 긴급 처리
            if asset.criticality == "Safety-Critical" and cvss >= 4.0:
                priority = "Immediate"
            elif asset.criticality == "Production-Critical" and cvss >= 7.0:
                priority = "High"
            elif cvss >= 9.0:
                priority = "High"
            elif cvss >= 4.0:
                priority = "Medium"
            else:
                priority = "Low"

            patch_queue.append({
                "asset_id": asset.asset_id,
                "asset_name": asset.name,
                "criticality": asset.criticality,
                "cve": patch.get("cve_id"),
                "cvss": cvss,
                "priority": priority,
                "maintenance_window": asset.maintenance_window,
                "compensating_controls": patch.get("compensating_controls", []),
            })

    priority_order = {"Immediate": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(patch_queue, key=lambda x: (priority_order.get(x["priority"], 4), -x["cvss"]))
```

---

## 5. 참고 자료

- **IEC 62443 표준 개요**: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- **CISA ICS 보안 가이드**: https://www.cisa.gov/ics
- **SANS ICS 보안 커리큘럼**: https://www.sans.org/industrial-control-systems-security/

---

<a name="english"></a>

# ICS/SCADA Security Defense — IEC 62443, Network Segmentation, OT Monitoring

## Overview

Industrial Control Systems protect critical infrastructure. Unlike IT security, OT security prioritizes **Availability → Integrity → Confidentiality** because downtime means production loss or physical damage.

## IEC 62443 Zone Model

```
Zone 4: Corporate IT Network
    ↕ [Firewall + DMZ]
Zone 3: Control Room / SCADA Servers
    ↕ [Data Diode (unidirectional)]
Zone 2: DCS / SCADA HMI
    ↕ [ICS Firewall]
Zone 1: PLCs / RTUs / Field Controllers
    ↕ [Serial / Fieldbus]
Zone 0: Physical Process (Sensors, Actuators)
```

## Key Protections

| Control | Implementation | IEC 62443 Reference |
|---------|---------------|-------------------|
| Network segmentation | Zone/Conduit model | Section 4.1 |
| Unidirectional gateway | Hardware data diode | Conduit SL-3+ |
| Protocol whitelisting | Modbus/DNP3 firewall | Section 5.3 |
| Anomaly detection | Modbus IDS | Section 6.2 |
| Patch management | Risk-based scheduling | Section 4.2 |

## OT-Specific Considerations

- **Never patch without testing** — test in offline replica first
- **Maintain offline backups** of PLC/RTU configurations
- **Document all changes** — change control is mandatory
- **Use jump servers** with MFA for remote OT access
- **Monitor but don't block** — false positives in OT can cause production loss

## References

- IEC 62443 overview: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- CISA ICS security: https://www.cisa.gov/ics
- SANS ICS curriculum: https://www.sans.org/industrial-control-systems-security/
