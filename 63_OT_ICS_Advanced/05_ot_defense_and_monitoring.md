# OT/ICS 방어 및 모니터링

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
