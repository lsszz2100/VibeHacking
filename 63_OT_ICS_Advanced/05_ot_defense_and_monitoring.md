> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# OT/ICS 방어 및 모니터링

## 0. 초보자를 위한 개념 이해

### OT 보안이 일반 IT 보안과 다른 이유

OT/ICS 환경에서 보안을 적용할 때는 IT 보안과 전혀 다른 접근법이 필요합니다.

**IT와 OT 보안의 근본적 차이:**
```
IT 보안 적용 시:
  발견 즉시 패치 → 시스템 재부팅
  → OT에서는: 생산 중단 = 수억 원 손실
  
  방화벽으로 통신 차단
  → OT에서는: PLC가 센서 데이터 못 받음 = 공정 이상

OT 보안의 제약:
  1. 가용성 최우선 (99.999% 가동률)
  2. 테스트 환경 구축 어려움 (실제 장비가 필요)
  3. 실시간 특성 (지연 허용 불가)
  4. 레거시 시스템 (Windows XP가 현역)
```

### OT 보안의 세 가지 핵심 원칙

```
1. 모니터링 우선 (Monitor First)
   OT 환경에서는 능동적 차단보다 수동 모니터링 우선
   → 오탐으로 인한 생산 중단 위험 최소화
   
2. 최소 접근 (Least Access)
   유지보수 시에만 접근, 작업 후 즉시 차단
   → USB 포트 물리적 잠금, 원격 접속 시간 제한
   
3. 격리 (Isolation)
   IT와 OT 네트워크 강력 분리
   → 데이터 다이오드로 단방향 통신만 허용
```

### OT 전용 보안 도구

```
IT vs OT 보안 도구 차이:
  IT: Nessus, Qualys → 능동적 스캔 (패킷 전송)
  OT: Claroty, Dragos, Nozomi → 수동 모니터링 (트래픽만 분석)
  
  이유: 능동 스캔 패킷이 PLC를 재부팅시키는 사례 있음
  
OT 전용 IDS (수동):
  - Claroty: OT 트래픽 분석 + 이상 탐지
  - Dragos: 산업 사이버 위협 전문
  - Nozomi Networks: 자산 발견 + 이상 탐지
  - Microsoft Defender for IoT: Azure IoT/OT 통합
```

### 데이터 다이오드란?

```
데이터 다이오드 (Data Diode):
  단방향 통신만 허용하는 하드웨어 장치
  
  OT 네트워크 → [데이터 다이오드] → IT 네트워크
                   (데이터만 통과)
                   ← (역방향 통신 물리적 불가)

장점:
  공격자가 IT에서 OT로 접근 물리적으로 불가능
  OT 데이터는 IT로 전송 가능 (히스토리안 데이터 등)
  
사용처:
  원자력 발전소, 군사 시설, 금융 인프라
```

---

## OT 보안 아키텍처 설계

### 심층 방어 (Defense in Depth)
```
레이어 7 — 정책/절차: CSMS, 사고 대응, 교육
레이어 6 — 물리 보안: 시설 접근 통제, 잠금 장치
레이어 5 — 경계 보안: 방화벽, DMZ, 데이터 다이오드
레이어 4 — 네트워크 세분화: VLAN, 구역 분리
레이어 3 — 호스트 보안: 화이트리스트, 패치 관리
레이어 2 — 응용 보안: 인증, 암호화, 검증
레이어 1 — 장치 보안: 펌웨어 서명, 보안 부팅
```

### 네트워크 구역화 (IEC 62443)
```
Security Zone 개념
├── Zone: 동일한 보안 요구사항을 가진 자산 그룹
├── Conduit: Zone 간 통신 경로 (방화벽/DMZ)
└── Security Level (SL): 0~4 (SL2 이상 권장)

일반적인 Zone 구성
Zone A — Enterprise IT (SL1)
Zone B — IT/OT DMZ (SL2)
Zone C — SCADA/DCS 네트워크 (SL3)
Zone D — 제어 네트워크 (SL3)
Zone E — 현장 장치 (SL2)
Zone F — 안전 계장 (SL4)
```

## OT 특화 IDS/IPS

### 탐지 접근 방식
```
화이트리스트 기반 (OT에 권장)
├── 정상 통신 패턴 프로파일링
├── 비정상 명령 즉시 경보
└── 낮은 오탐률 (프로세스 중단 방지)

시그니처 기반
├── 알려진 OT 악성코드 패턴
├── 취약점 익스플로잇 시그니처
└── 빠른 탐지 but 변종 놓침

이상 탐지 (ML 기반)
├── 네트워크 베이스라인 학습
├── 통계적 이상 탐지
└── OT 프로세스 맥락 이해 필요
```

### OT IDS 구현

```python
#!/usr/bin/env python3
"""OT/ICS 네트워크 이상 탐지 시스템."""

import argparse
import socket
import struct
import time
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread, Event
import queue


@dataclass
class OTEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    function_code: int
    address: int
    value: int | None
    severity: str
    message: str


@dataclass
class ModbusStats:
    src_ip: str
    function_codes: dict[int, int] = field(default_factory=dict)
    write_addresses: set[int] = field(default_factory=set)
    read_rate: float = 0.0
    write_rate: float = 0.0
    last_seen: float = field(default_factory=time.time)


class OTIDSRules:
    """OT IDS 탐지 규칙 엔진."""

    DANGEROUS_FC = {
        0x05: "코일 쓰기 (디지털 출력 변경)",
        0x06: "레지스터 쓰기 (아날로그 출력 변경)",
        0x0F: "다중 코일 쓰기",
        0x10: "다중 레지스터 쓰기",
    }

    def __init__(self, whitelist_path: Path | None = None):
        self.whitelist: dict[str, list[int]] = {}
        self.alert_queue: queue.Queue[OTEvent] = queue.Queue()
        if whitelist_path and whitelist_path.exists():
            self._load_whitelist(whitelist_path)

    def _load_whitelist(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text())
            self.whitelist = data.get("allowed_sources", {})
        except Exception:
            pass

    def check_modbus(
        self,
        src_ip: str,
        dst_ip: str,
        raw: bytes,
    ) -> list[OTEvent]:
        events: list[OTEvent] = []
        if len(raw) < 8:
            return events

        fc = raw[7]
        now = time.time()

        # 쓰기 명령 탐지
        if fc in self.DANGEROUS_FC:
            severity = "HIGH"
            # 화이트리스트 확인
            if src_ip in self.whitelist:
                if fc in self.whitelist[src_ip]:
                    severity = "INFO"

            address = 0
            value = None
            if len(raw) >= 10:
                address = struct.unpack(">H", raw[8:10])[0]
            if len(raw) >= 12:
                value = struct.unpack(">H", raw[10:12])[0]

            events.append(OTEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="Modbus",
                function_code=fc,
                address=address,
                value=value,
                severity=severity,
                message=f"Modbus 쓰기: {self.DANGEROUS_FC[fc]} "
                        f"주소={address} 값={value}",
            ))

        # 스캔 탐지 (많은 FC 시도)
        if fc == 0x2B:  # 장치 식별
            events.append(OTEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="Modbus",
                function_code=fc,
                address=0,
                value=None,
                severity="MEDIUM",
                message=f"Modbus 장치 식별 요청 from {src_ip}",
            ))

        return events

    def check_rate_anomaly(
        self,
        src_ip: str,
        stats: ModbusStats,
        threshold: float = 100.0,
    ) -> OTEvent | None:
        """요청 속도 이상 탐지."""
        if stats.write_rate > threshold:
            return OTEvent(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip="N/A",
                protocol="Modbus",
                function_code=0,
                address=0,
                value=None,
                severity="HIGH",
                message=f"비정상 쓰기 속도: {stats.write_rate:.1f}/s (임계: {threshold})",
            )
        return None


class OTPacketCapture:
    """간단한 OT 패킷 캡처 (Modbus TCP)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 502):
        self.host = host
        self.port = port
        self._stop = Event()

    def start_capture(
        self, callback, duration: float = 60.0
    ) -> None:
        """TCP 소켓에서 Modbus 패킷 캡처."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        server.settimeout(1.0)

        end = time.time() + duration
        print(f"[*] 캡처 시작: {self.host}:{self.port}")

        while time.time() < end and not self._stop.is_set():
            try:
                conn, addr = server.accept()
                Thread(
                    target=self._handle_client,
                    args=(conn, addr, callback),
                    daemon=True,
                ).start()
            except TimeoutError:
                continue
        server.close()

    def _handle_client(
        self, conn: socket.socket, addr: tuple, callback
    ) -> None:
        src_ip = addr[0]
        try:
            while not self._stop.is_set():
                data = conn.recv(512)
                if not data:
                    break
                callback(src_ip, data)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()


class OTIDS:
    """OT/ICS 침입 탐지 시스템."""

    def __init__(
        self,
        whitelist_path: Path | None = None,
        log_path: Path | None = None,
    ):
        self.rules = OTIDSRules(whitelist_path)
        self.stats: dict[str, ModbusStats] = defaultdict(
            lambda: ModbusStats(src_ip="")
        )
        self.events: list[OTEvent] = []
        self.log_path = log_path
        self._rate_window: dict[str, list[float]] = defaultdict(list)

    def process_packet(self, src_ip: str, raw: bytes) -> None:
        """패킷 처리 및 이상 탐지."""
        # Modbus TCP 검증
        if len(raw) < 8:
            return

        # 통계 업데이트
        now = time.time()
        stat = self.stats[src_ip]
        stat.src_ip = src_ip
        stat.last_seen = now

        fc = raw[7]
        stat.function_codes[fc] = stat.function_codes.get(fc, 0) + 1

        # 쓰기 속도 계산
        if fc in OTIDSRules.DANGEROUS_FC:
            self._rate_window[src_ip].append(now)
            cutoff = now - 1.0
            self._rate_window[src_ip] = [
                t for t in self._rate_window[src_ip] if t > cutoff
            ]
            stat.write_rate = len(self._rate_window[src_ip])

        # 규칙 평가
        events = self.rules.check_modbus(src_ip, "PLC", raw)
        rate_event = self.rules.check_rate_anomaly(src_ip, stat)
        if rate_event:
            events.append(rate_event)

        for event in events:
            self.events.append(event)
            self._alert(event)

    def _alert(self, event: OTEvent) -> None:
        severity_icons = {
            "CRITICAL": "[!!]",
            "HIGH": "[! ]",
            "MEDIUM": "[* ]",
            "LOW": "[- ]",
            "INFO": "[i ]",
        }
        icon = severity_icons.get(event.severity, "[?]")
        print(
            f"{icon} {time.strftime('%H:%M:%S', time.localtime(event.timestamp))} "
            f"| {event.src_ip:15s} | {event.message}"
        )

        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps({
                    "time": event.timestamp,
                    "src": event.src_ip,
                    "severity": event.severity,
                    "msg": event.message,
                }) + "\n")

    def report(self) -> None:
        print(f"\n{'='*60}")
        print(f"탐지 보고서")
        print(f"{'='*60}")
        print(f"이벤트 총계: {len(self.events)}개")
        by_severity: dict[str, int] = defaultdict(int)
        for e in self.events:
            by_severity[e.severity] += 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if by_severity[sev]:
                print(f"  {sev:10s}: {by_severity[sev]}개")

        print(f"\n통신 통계:")
        for ip, stat in self.stats.items():
            print(f"  {ip:15s} | FC 분포: {stat.function_codes}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS 침입 탐지 시스템")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus 수신 포트")
    parser.add_argument("-t", "--time", type=float, default=60.0,
                        help="캡처 시간 (초)")
    parser.add_argument("-w", "--whitelist", type=Path,
                        help="화이트리스트 JSON 파일")
    parser.add_argument("-l", "--log", type=Path,
                        help="이벤트 로그 파일")
    args = parser.parse_args()

    ids = OTIDS(args.whitelist, args.log)
    capture = OTPacketCapture(port=args.port)

    print(f"[*] OT IDS 시작 (포트: {args.port}, 시간: {args.time}s)")
    try:
        capture.start_capture(ids.process_packet, args.time)
    except KeyboardInterrupt:
        capture.stop()

    ids.report()


if __name__ == "__main__":
    main()
```

## OT 보안 모니터링 도구

```bash
# Zeek (Bro) OT 프로토콜 파서
zeek -i eth0 -C icsnpp-modbus icsnpp-dnp3 icsnpp-s7comm

# Wireshark OT 필터
# Modbus: modbus
# DNP3: dnp3
# S7comm: s7comm
# EtherNet/IP: enip
# OPC-UA: opcua

# OT 특화 상용 솔루션
Claroty    — OT 가시성 및 탐지
Dragos     — OT 위협 인텔리전스
Nozomi     — OT 자산 관리
Armis      — 에이전트 없는 OT 보안
Microsoft Defender for IoT — 통합 OT 보안
```

## 사고 대응 OT 특성

```
OT 사고 대응 우선순위
1. 인명 안전 확보 (물리적 공정 안전 먼저)
2. 환경 피해 방지
3. 프로세스 안정화 (비정상 중단 방지)
4. 증거 수집
5. 시스템 복구

OT 포렌식 특수성
├── 실시간 데이터 덮어쓰기 → 빠른 수집 필요
├── PLC 메모리 덤프 (래더 로직)
├── 히스토리안 데이터 (공정 이력)
├── 네트워크 패킷 캡처
└── HMI 이벤트 로그

복구 절차
1. 클린 이미지에서 재구성 (오염된 시스템 사용 금지)
2. 알려진 좋은 상태 백업 복원
3. 취약점 패치 후 재가동
4. 모니터링 강화 후 운영 재개
```

## IEC 62443 준수 점검

```python
#!/usr/bin/env python3
"""IEC 62443 OT 보안 요구사항 자가 점검 도구."""

from dataclasses import dataclass


@dataclass
class SecurityRequirement:
    id: str
    description: str
    sl_level: int
    met: bool | None = None
    notes: str = ""


REQUIREMENTS = [
    SecurityRequirement("IAC-1", "사용자 식별 및 인증 요구", 1),
    SecurityRequirement("IAC-2", "강력한 패스워드 정책", 2),
    SecurityRequirement("IAC-3", "다중 인증 (MFA)", 3),
    SecurityRequirement("UC-1", "계정 잠금 메커니즘", 1),
    SecurityRequirement("UC-2", "최소 권한 원칙 적용", 2),
    SecurityRequirement("SI-1", "통신 무결성 (체크섬/해시)", 1),
    SecurityRequirement("SI-2", "악성 코드 보호", 2),
    SecurityRequirement("DC-1", "데이터 기밀성 (암호화)", 2),
    SecurityRequirement("RDF-1", "감사 로그 수집", 1),
    SecurityRequirement("RDF-2", "이상 탐지 시스템", 2),
    SecurityRequirement("NM-1", "네트워크 세분화", 1),
    SecurityRequirement("NM-2", "무선 접근 제어", 2),
    SecurityRequirement("RA-1", "위험 평가 수행", 1),
    SecurityRequirement("RM-1", "취약점 패치 관리", 2),
    SecurityRequirement("SWM-1", "소프트웨어 변경 제어", 2),
]


def run_assessment(target_sl: int = 2) -> None:
    print(f"IEC 62443 보안 자가 점검 (목표 SL: {target_sl})")
    print("=" * 60)

    applicable = [r for r in REQUIREMENTS if r.sl_level <= target_sl]

    for req in applicable:
        ans = input(f"[{req.id}] {req.description}? (y/n): ").strip().lower()
        req.met = ans == "y"

    met = [r for r in applicable if r.met]
    not_met = [r for r in applicable if not r.met]

    print(f"\n결과: {len(met)}/{len(applicable)} 충족")
    score = len(met) / len(applicable) * 100
    print(f"점수: {score:.0f}%")

    if not_met:
        print(f"\n미충족 요구사항 ({len(not_met)}개):")
        for r in not_met:
            print(f"  [{r.id}] {r.description}")


if __name__ == "__main__":
    run_assessment()
```

OT 보안은 기술적 대책 외에 **운영 절차, 직원 교육, 공급망 관리**가 동등하게 중요하다. 모든 변경사항은 MOC(Management of Change) 프로세스를 거쳐야 한다.


<!-- detect-validate-63 -->
## OT 모니터링 검증 — 비정상 명령이 실제로 탐지되는가

OT 방어는 *모니터링을 깔았다*가 아니라 **패시브 OT IDS가 정상 베이스라인을 학습하고, 비정상 명령·신규 자산·프로토콜 위반을 실제 탐지·경보하며, 가용성을 해치지 않는가**로 판정한다. 검증은 **소유 OT 랩**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 베이스라인 | 미학습 | 정상 트래픽 학습 확인 | 자산·통신 베이스라인 |
| 이상 탐지 | 무탐지 | 비정상 명령 주입(랩) | 경보 발생 |
| 패시브성 | 능동 간섭 | TAP/SPAN 확인 | 비간섭 수집 |
| 신규 자산 | 미상 장비 방치 | 자산 변동 모니터 | 신규자산 알림 |

### 방어 검증 (직접 확인)

```bash
# 1) OT 센서가 SPAN/TAP로 비간섭 수집하는지(능동 스캔은 OT에서 위험) — 소유 랩에서만
ip -s link show 2>/dev/null | grep -A1 -iE 'mirror|span|monitor' || echo "confirm passive TAP/SPAN, not active polling, for OT collection"
# 2) 비정상 기능코드/신규 자산 주입 시 IDS 경보가 실제 발생하는지(랩 재현)
grep -REi 'modbus|dnp3|anomaly|new.?asset|unauthorized' /var/log/ot-ids/ 2>/dev/null | tail || echo "inject a benign anomaly on owned lab and confirm alert"
```

> 검증은 반드시 **소유 OT 랩**에서만 한다. 가동망에서 능동 스캔 금지. "모니터링을 깔았다"와 "비정상이 실제 탐지된다"는 다르다 — 이상 주입·경보로 직접 확인한다([[13_SOC_Blue_Team]], [[40_Threat_Hunting]]).

---

<a name="english"></a>

# OT/ICS Defense and Monitoring

## OT Security Architecture Design

### Defense in Depth
```
Layer 7 — Policy/Procedures: CSMS, incident response, training
Layer 6 — Physical Security: facility access control, locks
Layer 5 — Perimeter Security: firewalls, DMZ, data diodes
Layer 4 — Network Segmentation: VLAN, zone separation
Layer 3 — Host Security: whitelisting, patch management
Layer 2 — Application Security: authentication, encryption, validation
Layer 1 — Device Security: firmware signing, secure boot
```

### Network Zoning (IEC 62443)
```
Security Zone concepts
├── Zone: A group of assets with the same security requirements
├── Conduit: Communication path between zones (firewall/DMZ)
└── Security Level (SL): 0–4 (SL2 or higher recommended)

Typical Zone configuration
Zone A — Enterprise IT (SL1)
Zone B — IT/OT DMZ (SL2)
Zone C — SCADA/DCS network (SL3)
Zone D — Control network (SL3)
Zone E — Field devices (SL2)
Zone F — Safety instrumented systems (SL4)
```

## OT-Specific IDS/IPS

### Detection Approaches
```
Whitelist-based (recommended for OT)
├── Profiling normal communication patterns
├── Immediate alert on abnormal commands
└── Low false-positive rate (prevents process disruption)

Signature-based
├── Known OT malware patterns
├── Vulnerability exploit signatures
└── Fast detection but misses variants

Anomaly detection (ML-based)
├── Network baseline learning
├── Statistical anomaly detection
└── Requires understanding of OT process context
```

### OT IDS Implementation

```python
#!/usr/bin/env python3
"""OT/ICS network anomaly detection system."""

import argparse
import socket
import struct
import time
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Thread, Event
import queue


@dataclass
class OTEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    function_code: int
    address: int
    value: int | None
    severity: str
    message: str


@dataclass
class ModbusStats:
    src_ip: str
    function_codes: dict[int, int] = field(default_factory=dict)
    write_addresses: set[int] = field(default_factory=set)
    read_rate: float = 0.0
    write_rate: float = 0.0
    last_seen: float = field(default_factory=time.time)


class OTIDSRules:
    """OT IDS detection rule engine."""

    DANGEROUS_FC = {
        0x05: "Write Coil (change digital output)",
        0x06: "Write Register (change analog output)",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
    }

    def __init__(self, whitelist_path: Path | None = None):
        self.whitelist: dict[str, list[int]] = {}
        self.alert_queue: queue.Queue[OTEvent] = queue.Queue()
        if whitelist_path and whitelist_path.exists():
            self._load_whitelist(whitelist_path)

    def _load_whitelist(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text())
            self.whitelist = data.get("allowed_sources", {})
        except Exception:
            pass

    def check_modbus(
        self,
        src_ip: str,
        dst_ip: str,
        raw: bytes,
    ) -> list[OTEvent]:
        events: list[OTEvent] = []
        if len(raw) < 8:
            return events

        fc = raw[7]
        now = time.time()

        # Detect write commands
        if fc in self.DANGEROUS_FC:
            severity = "HIGH"
            # Check whitelist
            if src_ip in self.whitelist:
                if fc in self.whitelist[src_ip]:
                    severity = "INFO"

            address = 0
            value = None
            if len(raw) >= 10:
                address = struct.unpack(">H", raw[8:10])[0]
            if len(raw) >= 12:
                value = struct.unpack(">H", raw[10:12])[0]

            events.append(OTEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="Modbus",
                function_code=fc,
                address=address,
                value=value,
                severity=severity,
                message=f"Modbus write: {self.DANGEROUS_FC[fc]} "
                        f"address={address} value={value}",
            ))

        # Scan detection (many FC attempts)
        if fc == 0x2B:  # Device identification
            events.append(OTEvent(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="Modbus",
                function_code=fc,
                address=0,
                value=None,
                severity="MEDIUM",
                message=f"Modbus device identification request from {src_ip}",
            ))

        return events

    def check_rate_anomaly(
        self,
        src_ip: str,
        stats: ModbusStats,
        threshold: float = 100.0,
    ) -> OTEvent | None:
        """Detect request rate anomalies."""
        if stats.write_rate > threshold:
            return OTEvent(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip="N/A",
                protocol="Modbus",
                function_code=0,
                address=0,
                value=None,
                severity="HIGH",
                message=f"Abnormal write rate: {stats.write_rate:.1f}/s (threshold: {threshold})",
            )
        return None


class OTPacketCapture:
    """Simple OT packet capture (Modbus TCP)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 502):
        self.host = host
        self.port = port
        self._stop = Event()

    def start_capture(
        self, callback, duration: float = 60.0
    ) -> None:
        """Capture Modbus packets from a TCP socket."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        server.settimeout(1.0)

        end = time.time() + duration
        print(f"[*] Capture started: {self.host}:{self.port}")

        while time.time() < end and not self._stop.is_set():
            try:
                conn, addr = server.accept()
                Thread(
                    target=self._handle_client,
                    args=(conn, addr, callback),
                    daemon=True,
                ).start()
            except TimeoutError:
                continue
        server.close()

    def _handle_client(
        self, conn: socket.socket, addr: tuple, callback
    ) -> None:
        src_ip = addr[0]
        try:
            while not self._stop.is_set():
                data = conn.recv(512)
                if not data:
                    break
                callback(src_ip, data)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()


class OTIDS:
    """OT/ICS Intrusion Detection System."""

    def __init__(
        self,
        whitelist_path: Path | None = None,
        log_path: Path | None = None,
    ):
        self.rules = OTIDSRules(whitelist_path)
        self.stats: dict[str, ModbusStats] = defaultdict(
            lambda: ModbusStats(src_ip="")
        )
        self.events: list[OTEvent] = []
        self.log_path = log_path
        self._rate_window: dict[str, list[float]] = defaultdict(list)

    def process_packet(self, src_ip: str, raw: bytes) -> None:
        """Process packet and perform anomaly detection."""
        # Validate Modbus TCP
        if len(raw) < 8:
            return

        # Update statistics
        now = time.time()
        stat = self.stats[src_ip]
        stat.src_ip = src_ip
        stat.last_seen = now

        fc = raw[7]
        stat.function_codes[fc] = stat.function_codes.get(fc, 0) + 1

        # Calculate write rate
        if fc in OTIDSRules.DANGEROUS_FC:
            self._rate_window[src_ip].append(now)
            cutoff = now - 1.0
            self._rate_window[src_ip] = [
                t for t in self._rate_window[src_ip] if t > cutoff
            ]
            stat.write_rate = len(self._rate_window[src_ip])

        # Evaluate rules
        events = self.rules.check_modbus(src_ip, "PLC", raw)
        rate_event = self.rules.check_rate_anomaly(src_ip, stat)
        if rate_event:
            events.append(rate_event)

        for event in events:
            self.events.append(event)
            self._alert(event)

    def _alert(self, event: OTEvent) -> None:
        severity_icons = {
            "CRITICAL": "[!!]",
            "HIGH": "[! ]",
            "MEDIUM": "[* ]",
            "LOW": "[- ]",
            "INFO": "[i ]",
        }
        icon = severity_icons.get(event.severity, "[?]")
        print(
            f"{icon} {time.strftime('%H:%M:%S', time.localtime(event.timestamp))} "
            f"| {event.src_ip:15s} | {event.message}"
        )

        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps({
                    "time": event.timestamp,
                    "src": event.src_ip,
                    "severity": event.severity,
                    "msg": event.message,
                }) + "\n")

    def report(self) -> None:
        print(f"\n{'='*60}")
        print(f"Detection Report")
        print(f"{'='*60}")
        print(f"Total events: {len(self.events)}")
        by_severity: dict[str, int] = defaultdict(int)
        for e in self.events:
            by_severity[e.severity] += 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if by_severity[sev]:
                print(f"  {sev:10s}: {by_severity[sev]}")

        print(f"\nCommunication statistics:")
        for ip, stat in self.stats.items():
            print(f"  {ip:15s} | FC distribution: {stat.function_codes}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS Intrusion Detection System")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus listening port")
    parser.add_argument("-t", "--time", type=float, default=60.0,
                        help="Capture duration (seconds)")
    parser.add_argument("-w", "--whitelist", type=Path,
                        help="Whitelist JSON file")
    parser.add_argument("-l", "--log", type=Path,
                        help="Event log file")
    args = parser.parse_args()

    ids = OTIDS(args.whitelist, args.log)
    capture = OTPacketCapture(port=args.port)

    print(f"[*] OT IDS started (port: {args.port}, duration: {args.time}s)")
    try:
        capture.start_capture(ids.process_packet, args.time)
    except KeyboardInterrupt:
        capture.stop()

    ids.report()


if __name__ == "__main__":
    main()
```

## OT Security Monitoring Tools

```bash
# Zeek (Bro) OT protocol parsers
zeek -i eth0 -C icsnpp-modbus icsnpp-dnp3 icsnpp-s7comm

# Wireshark OT filters
# Modbus: modbus
# DNP3: dnp3
# S7comm: s7comm
# EtherNet/IP: enip
# OPC-UA: opcua

# OT-specific commercial solutions
Claroty    — OT visibility and detection
Dragos     — OT threat intelligence
Nozomi     — OT asset management
Armis      — Agentless OT security
Microsoft Defender for IoT — Integrated OT security
```

## Incident Response for OT Environments

```
OT Incident Response Priorities
1. Ensure human safety (physical process safety first)
2. Prevent environmental damage
3. Stabilize the process (prevent unplanned shutdowns)
4. Collect evidence
5. Restore systems

OT Forensics Specifics
├── Real-time data overwriting → fast collection required
├── PLC memory dump (ladder logic)
├── Historian data (process history)
├── Network packet capture
└── HMI event logs

Recovery Procedure
1. Rebuild from a clean image (do not use contaminated systems)
2. Restore backup from a known-good state
3. Patch vulnerabilities before restarting
4. Resume operations with enhanced monitoring
```

## IEC 62443 Compliance Assessment

```python
#!/usr/bin/env python3
"""IEC 62443 OT security requirements self-assessment tool."""

from dataclasses import dataclass


@dataclass
class SecurityRequirement:
    id: str
    description: str
    sl_level: int
    met: bool | None = None
    notes: str = ""


REQUIREMENTS = [
    SecurityRequirement("IAC-1", "User identification and authentication required", 1),
    SecurityRequirement("IAC-2", "Strong password policy", 2),
    SecurityRequirement("IAC-3", "Multi-factor authentication (MFA)", 3),
    SecurityRequirement("UC-1", "Account lockout mechanism", 1),
    SecurityRequirement("UC-2", "Least privilege principle applied", 2),
    SecurityRequirement("SI-1", "Communication integrity (checksum/hash)", 1),
    SecurityRequirement("SI-2", "Malicious code protection", 2),
    SecurityRequirement("DC-1", "Data confidentiality (encryption)", 2),
    SecurityRequirement("RDF-1", "Audit log collection", 1),
    SecurityRequirement("RDF-2", "Anomaly detection system", 2),
    SecurityRequirement("NM-1", "Network segmentation", 1),
    SecurityRequirement("NM-2", "Wireless access control", 2),
    SecurityRequirement("RA-1", "Risk assessment conducted", 1),
    SecurityRequirement("RM-1", "Vulnerability patch management", 2),
    SecurityRequirement("SWM-1", "Software change control", 2),
]


def run_assessment(target_sl: int = 2) -> None:
    print(f"IEC 62443 Security Self-Assessment (Target SL: {target_sl})")
    print("=" * 60)

    applicable = [r for r in REQUIREMENTS if r.sl_level <= target_sl]

    for req in applicable:
        ans = input(f"[{req.id}] {req.description}? (y/n): ").strip().lower()
        req.met = ans == "y"

    met = [r for r in applicable if r.met]
    not_met = [r for r in applicable if not r.met]

    print(f"\nResult: {len(met)}/{len(applicable)} satisfied")
    score = len(met) / len(applicable) * 100
    print(f"Score: {score:.0f}%")

    if not_met:
        print(f"\nUnmet requirements ({len(not_met)}):")
        for r in not_met:
            print(f"  [{r.id}] {r.description}")


if __name__ == "__main__":
    run_assessment()
```

In OT security, **operational procedures, employee training, and supply chain management** are equally important alongside technical controls. All changes must go through a MOC (Management of Change) process.

<!-- detect-validate-63 -->
## OT-Monitoring Validation — Are Abnormal Commands Actually Detected?

OT defense is judged not by *having deployed monitoring* but by **whether a passive OT IDS learns a normal baseline and actually detects/alerts on abnormal commands, new assets, and protocol violations without harming availability**. Validate only on **owned OT labs**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Baseline | Not learned | Confirm normal-traffic learning | Asset/comm baseline |
| Anomaly detection | No detection | Inject abnormal command (lab) | Alert raised |
| Passivity | Active interference | Check TAP/SPAN | Non-intrusive collection |
| New asset | Unknown device ignored | Monitor asset changes | New-asset alert |

### Defense validation (verify directly)

```bash
# 1) Whether the OT sensor collects non-intrusively via SPAN/TAP (active scanning is risky in OT) — owned lab only
ip -s link show 2>/dev/null | grep -A1 -iE 'mirror|span|monitor' || echo "confirm passive TAP/SPAN, not active polling, for OT collection"
# 2) Whether the IDS actually alerts on an injected abnormal function code / new asset (lab reproduction)
grep -REi 'modbus|dnp3|anomaly|new.?asset|unauthorized' /var/log/ot-ids/ 2>/dev/null | tail || echo "inject a benign anomaly on owned lab and confirm alert"
```

> Validate only on **owned OT labs** — never active-scan a production network. "Deployed monitoring" differs from "anomalies are actually detected" — confirm directly via anomaly injection and alerting ([[13_SOC_Blue_Team]], [[40_Threat_Hunting]]).
