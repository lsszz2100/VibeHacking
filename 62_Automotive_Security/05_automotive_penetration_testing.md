> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 침투 테스트

## 0. 초보자를 위한 개념 이해

### 자동차 침투 테스트란?

**자동차 침투 테스트(Automotive Penetration Testing)**는 차량의 사이버 보안 취약점을 체계적으로 찾아내는 전문화된 보안 평가입니다. 제조사와 계약 후 수행하며, 공개된 취약점은 패치 배포 후 공개됩니다.

**왜 배우는가:**
```
자동차 보안 규정 강화:
  UN WP.29 R155/R156: 2022년부터 신차 의무화
  ISO/SAE 21434: 차량 사이버보안 표준
  → 완성차·부품업체 보안 수요 폭증

취업 기회:
  현대/기아, BMW, Mercedes, Tesla 등
  → 차량 보안 연구팀 채용 증가
  → CTF AutoSecurity 분야 성장
```

### 자동차 침투 테스트 범위

```
1. 외부 공격 표면
   텔레매틱스 (인터넷 연결 모듈)
     → OTA 업데이트, 원격 진단
   V2X 통신 (무선 메시지)
   블루투스/WiFi 페어링
   스마트폰 앱 ↔ 차량 API

2. 내부 네트워크
   CAN 버스 (주 통신 네트워크)
   OBD-II 포트 (물리 접근 진단)
   이더넷 (고급 차량)
   ECU 간 통신

3. ECU 분석
   펌웨어 역공학
   부트로더 보안
   디버그 포트 노출

방법론:
  TARA (Threat Analysis & Risk Assessment)
    → ISO 21434 기반 위협 분석
```

### 필요한 도구
- **can-utils**: CAN 버스 분석 Linux 도구
- **Scapy**: 커스텀 차량 네트워크 패킷 생성
- **Triton (코드명)**: 차량 ECU 퍼저

### 기초 실습 예제
```python
# 차량 침투 테스트 체크리스트
test_areas = {
    "OBD-II / 물리 접근": [
        "OBD-II 포트 노출 여부",
        "진단 명령 인증 확인",
        "UDS (ISO 14229) 서비스 열거",
        "Seed-Key 알고리즘 취약성",
    ],
    "텔레매틱스": [
        "인터넷 노출 포트 스캔",
        "TLS 인증서 유효성",
        "OTA 업데이트 서명 검증",
        "API 인증 토큰 취약성",
    ],
    "블루투스": [
        "페어링 프로세스 취약점",
        "이전 페어링 기기 목록 노출",
        "AT 명령 인젝션",
    ],
}

print("자동차 침투 테스트 체크리스트\n")
for area, items in test_areas.items():
    print(f"[{area}]")
    for item in items:
        print(f"  ☐ {item}")
    print()
```

---

## 방법론

자동차 침투 테스트는 ISO/SAE 21434의 TARA(위협 분석 및 리스크 평가)와 연동한다.

```
자동차 침투 테스트 단계
1. 범위 정의 및 위협 모델링
2. 공격 표면 매핑
3. 수동 정찰
4. 자동화 스캐닝
5. 취약점 익스플로잇
6. 영향도 검증
7. 보고 및 개선 권고
```

## 테스트 환경 구성

```bash
# HIL (Hardware-In-the-Loop) 테스트 벤치
# - 실제 ECU + 시뮬레이션 환경
# - 실제 차량 위험 없이 테스트

# 필요 장비
# 1. OBD-II → USB 어댑터 (ELM327, Kvaser, PEAK PCAN)
# 2. CAN 버스 분석기 (CANalyzer, Wireshark + can-utils)
# 3. 무선 분석 (SDR, WiFi Pineapple, Bluetooth 어댑터)
# 4. 소프트웨어 (Wireshark, UDS Explorer, CANdb++)

# 가상 테스트 환경
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
```

## 공격 표면별 테스트

### OBD-II 포트 테스트

```python
#!/usr/bin/env python3
"""자동차 침투 테스트 자동화 프레임워크."""

import argparse
import can
import time
import sys
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str


@dataclass
class PentestReport:
    target: str
    start_time: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        icon = {
            Severity.CRITICAL: "[!!]",
            Severity.HIGH: "[!]",
            Severity.MEDIUM: "[*]",
            Severity.LOW: "[-]",
            Severity.INFO: "[i]",
        }[finding.severity]
        print(f"  {icon} {finding.severity.value}: {finding.title}")

    def summary(self) -> str:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        lines = [
            f"\n{'='*60}",
            f"침투 테스트 결과: {self.target}",
            f"{'='*60}",
            f"총 발견사항: {len(self.findings)}개",
        ]
        for sev in Severity:
            if counts[sev]:
                lines.append(f"  {sev.value:10s}: {counts[sev]}개")
        return "\n".join(lines)


def test_unauthenticated_services(
    bus: can.Bus,
    report: PentestReport,
    tx_id: int = 0x7E0,
    rx_id: int = 0x7E8,
) -> None:
    """인증 없이 접근 가능한 UDS 서비스 테스트."""

    def send_recv(data: bytes, timeout: float = 1.0) -> bytes | None:
        frame = can.Message(
            arbitration_id=tx_id,
            data=bytes([len(data)]) + data + bytes(7 - len(data)),
            is_extended_id=False,
        )
        bus.send(frame)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                return bytes(msg.data)
        return None

    # 확장 세션 비인증 접근
    resp = send_recv(bytes([0x10, 0x03]))  # 확장 진단 세션
    if resp and resp[1] == 0x50:
        report.add(Finding(
            title="비인증 확장 진단 세션 접근",
            severity=Severity.HIGH,
            description="인증 없이 확장 진단 세션(0x03) 진입 가능",
            evidence=f"응답: {resp.hex()}",
            recommendation="세션 접근에 SecurityAccess(0x27) 선행 요구",
        ))

    # 쓰기 DID 비인증 테스트
    test_dids = [0xF190, 0xF197, 0x0101, 0x0102]
    for did in test_dids:
        write_req = bytes([0x2E, did >> 8, did & 0xFF, 0x00])
        resp = send_recv(write_req)
        if resp and resp[1] != 0x7F:
            report.add(Finding(
                title=f"DID 0x{did:04X} 비인증 쓰기 가능",
                severity=Severity.CRITICAL,
                description=f"보안 접근 없이 DID {did:04X} 쓰기 허용",
                evidence=f"응답: {resp.hex()}",
                recommendation="WriteDataByIdentifier에 보안 접근 필수화",
            ))

    # RoutineControl 비인증 테스트
    routines = [0x0203, 0xFF00, 0x0101]
    for routine in routines:
        req = bytes([0x31, 0x01, routine >> 8, routine & 0xFF])
        resp = send_recv(req)
        if resp and resp[1] == 0x71:  # RoutineControl 긍정 응답
            report.add(Finding(
                title=f"루틴 0x{routine:04X} 비인증 실행",
                severity=Severity.HIGH,
                description="보안 접근 없이 루틴 실행 가능",
                evidence=f"응답: {resp.hex()}",
                recommendation="RoutineControl 보안 레벨 상향",
            ))


def test_can_injection(
    bus: can.Bus,
    report: PentestReport,
    duration: float = 5.0,
) -> None:
    """CAN 메시지 인젝션 가능성 테스트."""

    # 유효한 것처럼 보이는 임의 메시지 전송
    test_ids = [0x018, 0x244, 0x3B2, 0x5A1]
    for can_id in test_ids:
        frame = can.Message(
            arbitration_id=can_id,
            data=bytes([0xFF] * 8),
            is_extended_id=False,
        )
        try:
            bus.send(frame)
            report.add(Finding(
                title=f"CAN ID 0x{can_id:03X} 인젝션 가능",
                severity=Severity.MEDIUM,
                description="임의 CAN 메시지 전송 가능 (인증 없음)",
                evidence=f"CAN ID 0x{can_id:03X} 전송 성공",
                recommendation="게이트웨이 ECU에서 메시지 출처 검증 및 서명 적용",
            ))
        except can.CanError:
            pass


def test_firmware_update(
    bus: can.Bus,
    report: PentestReport,
    tx_id: int = 0x7E0,
    rx_id: int = 0x7E8,
) -> None:
    """펌웨어 업데이트 프로세스 보안 테스트."""

    def send_recv(data: bytes, timeout: float = 1.0) -> bytes | None:
        frame = can.Message(
            arbitration_id=tx_id,
            data=bytes([len(data)]) + data + bytes(7 - len(data)),
            is_extended_id=False,
        )
        bus.send(frame)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                return bytes(msg.data)
        return None

    # 프로그래밍 세션 비인증 접근
    resp = send_recv(bytes([0x10, 0x02]))  # 프로그래밍 세션
    if resp and resp[1] == 0x50:
        report.add(Finding(
            title="프로그래밍 세션 비인증 접근",
            severity=Severity.CRITICAL,
            description="인증 없이 프로그래밍 세션 진입 → 펌웨어 플래시 가능",
            evidence=f"응답: {resp.hex()}",
            recommendation="프로그래밍 세션에 멀티팩터 SecurityAccess 요구",
        ))

    # RequestDownload 비인증 테스트
    resp = send_recv(bytes([0x34, 0x00, 0x44, 0x00, 0x00, 0x00]))
    if resp and resp[1] != 0x7F:
        report.add(Finding(
            title="비인증 펌웨어 다운로드 요청 허용",
            severity=Severity.CRITICAL,
            description="서명 검증 없는 펌웨어 다운로드 허용 → RCE 가능",
            evidence=f"응답: {resp.hex()}",
            recommendation="ECDSA 서명 검증, 루트 CA 기반 인증서 체인 적용",
        ))


def test_wireless_interfaces(report: PentestReport, host: str) -> None:
    """무선 인터페이스 보안 테스트 (WiFi, Bluetooth)."""
    import subprocess

    # Wi-Fi 스캔
    result = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi"],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if host.lower() in line.lower():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] in ("--", "WEP", ""):
                report.add(Finding(
                    title=f"취약한 Wi-Fi 보안: {parts[0]}",
                    severity=Severity.HIGH,
                    description=f"Wi-Fi '{parts[0]}' 취약한 암호화 또는 개방형",
                    evidence=line,
                    recommendation="WPA3 Enterprise 또는 WPA2-AES 적용",
                ))


def main() -> None:
    parser = argparse.ArgumentParser(description="자동차 침투 테스트 프레임워크")
    parser.add_argument("interface", help="CAN 인터페이스")
    parser.add_argument("--target", default="Unknown Vehicle",
                        help="테스트 대상 이름")
    parser.add_argument("--tx-id", type=lambda x: int(x, 16), default=0x7E0)
    parser.add_argument("--rx-id", type=lambda x: int(x, 16), default=0x7E8)
    parser.add_argument("--all", action="store_true", help="전체 테스트")
    args = parser.parse_args()

    report = PentestReport(target=args.target)
    bus = can.interface.Bus(args.interface, interface="socketcan")

    print(f"[*] 자동차 침투 테스트 시작: {args.target}")
    print(f"[*] CAN 인터페이스: {args.interface}")
    print(f"[*] TX: 0x{args.tx_id:03X} | RX: 0x{args.rx_id:03X}\n")

    try:
        print("[*] 1. 비인증 UDS 서비스 테스트...")
        test_unauthenticated_services(bus, report, args.tx_id, args.rx_id)

        print("\n[*] 2. CAN 인젝션 테스트...")
        test_can_injection(bus, report)

        print("\n[*] 3. 펌웨어 업데이트 보안 테스트...")
        test_firmware_update(bus, report, args.tx_id, args.rx_id)

        print(report.summary())

        if report.findings:
            print(f"\n[상세 발견사항]")
            for i, f in enumerate(report.findings, 1):
                print(f"\n{i}. [{f.severity.value}] {f.title}")
                print(f"   설명: {f.description}")
                print(f"   권고: {f.recommendation}")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
```

## 보고서 작성 템플릿

```markdown
# 자동차 사이버보안 침투 테스트 보고서

## 요약
- **대상**: [차량 모델/ECU]
- **테스트 기간**: [날짜]
- **위험도 분포**: CRITICAL N, HIGH N, MEDIUM N

## 주요 발견사항
### [CRITICAL] 비인증 펌웨어 업데이트
**CVSS**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**영향**: 원격 코드 실행, 차량 제어권 탈취 가능
**재현 절차**: ...
**권고**: ECDSA 서명 검증 적용

## ISO/SAE 21434 매핑
| 발견사항 | TARA 위협 | ASIL 레벨 | 우선순위 |
```

## 취약점 영향도 평가 (EVITA)

```
EVITA (E-safety Vehicle Intrusion proTected Applications)
보안 레벨:
  HIGH   — 생명 안전 위협 (브레이크, 스티어링)
  MEDIUM — 재산 피해 (엔진, 변속기)
  LOW    — 불편 초래 (인포테인먼트, 조명)

SFOP (Safety, Financial, Operational, Privacy)
각 차원별 영향도 1~3 평가 → 종합 위험도 산출
```

자동차 보안은 가장 높은 윤리적 책임이 요구되는 분야다. 모든 테스트는 통제된 환경에서, 명시적 승인하에 수행해야 한다.


## CAN 프레임 주기 이상 탐지 — 주입 프레임을 타이밍으로 잡는다

CAN 버스에는 인증·암호화가 거의 없어, 공격자는 정상 ECU와 같은 arbitration ID로 위조 프레임을 주입할 수 있다(예: 조향·제동 명령 스푸핑). 그러나 대부분의 주기적 CAN 메시지는 **일정한 사이클 타임**(예: 10ms마다)으로 송신되므로, 주입 공격은 필연적으로 **비정상적으로 짧은 프레임 간격**(정상 프레임과 위조 프레임이 겹쳐 두 배 빈도로 관측)을 만든다. 각 ID의 정상 사이클 타임 기준선을 학습해 두면, 기준보다 뚜렷이 빠른 프레임을 통계적으로 잡아낼 수 있다. 이는 IDS(침입탐지)용 방어 로직이며 소유 차량·벤치에서만 검증한다.

```python
#!/usr/bin/env python3
"""CAN 프레임 타임스탬프에서 주입 공격을 주기 이상으로 탐지한다.
각 arbitration ID의 정상 사이클 타임을 학습 → 관측 간격이 기준보다
뚜렷이 짧으면(위조+정상 프레임 중첩) 이상으로 표시. IDS 방어 로직."""
from statistics import mean, pstdev

Frame = tuple[float, int]   # (timestamp_sec, arbitration_id)


def learn_baseline(frames: list[Frame]) -> dict[int, float]:
    """ID별 정상 프레임 간격(사이클 타임)의 평균을 학습."""
    times: dict[int, list[float]] = {}
    for ts, cid in frames:
        times.setdefault(cid, []).append(ts)
    baseline = {}
    for cid, ts_list in times.items():
        gaps = [b - a for a, b in zip(ts_list, ts_list[1:])]
        if len(gaps) >= 5:
            baseline[cid] = mean(gaps)
    return baseline


def detect_injection(frames: list[Frame], baseline: dict[int, float]) -> list[dict]:
    anomalies, last = [], {}
    for ts, cid in frames:
        if cid in baseline and cid in last:
            gap = ts - last[cid]
            # 정상 사이클의 절반보다 짧은 간격 = 위조 프레임 중첩 의심
            if gap < baseline[cid] * 0.5:
                anomalies.append({"id": hex(cid), "gap_ms": round(gap * 1000, 2),
                                  "expected_ms": round(baseline[cid] * 1000, 2)})
        last[cid] = ts
    return anomalies
```

| 신호 | 설명 | 오탐/보정 요인 |
|------|------|----------------|
| 사이클 타임 절반 이하 간격 | 위조+정상 프레임 중첩 = 주입 의심 | 이벤트성(비주기) ID는 기준 학습 대상에서 제외 |
| ID별 송신 빈도 급증 | 스푸핑이 정상보다 자주 송신 | 버스 부하 변동·정상 버스트와 구분 필요 |
| 예상 못한 소스의 ID 등장 | 원래 특정 ECU만 쓰는 ID를 타 노드가 사용 | 게이트웨이 재전송·진단 세션은 정당 |

**탐지/방어**: 타이밍 기반 탐지는 주기적 메시지에만 유효하므로 **이벤트성 ID는 기준 학습에서 제외**하고, 빈도·소스 신호와 결합해 오탐을 낮춘다. 성숙한 접근은 여기에 **CAN 메시지 인증(예: AUTOSAR SecOC)**을 더해 근본 완화를 하고, IDS는 탐지·경보 계층으로 둔다. 자동차는 안전 직결 분야이므로 모든 검증은 **소유 차량·격리 벤치**에서 명시적 승인하에만 수행한다([[63_OT_ICS_Advanced]], [[48_Threat_Modeling]]).

<!-- detect-validate-62 -->
## 차량 펜테스트 검증 — 위협 시나리오가 실제로 재현·완화 입증되는가

차량 펜테스트는 *TARA를 작성했다*가 아니라 **식별된 위협 시나리오가 벤치에서 실제 재현되고, 적용한 완화가 동일 시나리오를 차단함을 재시험으로 입증하는가**로 판정한다. 검증은 **소유 차량·벤치**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 시나리오 재현 | 추정 위협 | 벤치 재현 시험 | 실제 재현 확인 |
| 완화 실증 | 완화 미검증 | 완화 후 재시험 | 시나리오 차단 확인 |
| 공격면 범위 | 누락 인터페이스 | 인터페이스 인벤토리 | 전 인터페이스 평가 |
| 안전 통제 | 위험한 실차 시험 | 격리·세이프가드 | 안전조치 준수 |

### 방어 검증 (직접 확인)

```bash
# 1) 노출된 차량 인터페이스(텔레매틱스/Wi-Fi/BT)가 실제 떠 있는지 — 소유 차량에서만
nmap -Pn -sV 192.168.x.x 2>/dev/null | grep -E 'open' | head || echo "scan the head-unit/telematics interface on owned vehicle"
# 2) 완화 적용 전후로 동일 PoC가 차단되는지 재시험 기록(증적)
echo "Record PoC result pre-mitigation vs post-mitigation; healthy = same attack blocked after fix (owned bench)"
```

> 검증은 반드시 **소유 차량·벤치**에서만 한다. 안전계 시험은 격리·세이프가드 하에서만. "TARA를 작성했다"와 "시나리오가 재현·차단된다"는 다르다 — 재현·재시험으로 직접 확인한다([[10_Pentest_Methodology]], [[17_Red_Team_Operations]]).

**최신 기법·통제 (2025–2026):**
- ISO 21434 기반 체계적 평가가 표준 — 검증: 통제가 실제 공격을 저지하는지 재현(소유 벤치)([[48_Threat_Modeling]])
- SOC 연계 모니터링 — 강제되는지 확인

---

<a name="english"></a>

# Automotive Penetration Testing

## Methodology

Automotive penetration testing integrates with the TARA (Threat Analysis and Risk Assessment) framework defined in ISO/SAE 21434.

```
Automotive Penetration Testing Phases
1. Scope definition and threat modeling
2. Attack surface mapping
3. Passive reconnaissance
4. Automated scanning
5. Vulnerability exploitation
6. Impact verification
7. Reporting and remediation recommendations
```

## Test Environment Setup

```bash
# HIL (Hardware-In-the-Loop) test bench
# - Real ECU + simulation environment
# - Test without risk to a real vehicle

# Required equipment
# 1. OBD-II → USB adapter (ELM327, Kvaser, PEAK PCAN)
# 2. CAN bus analyzer (CANalyzer, Wireshark + can-utils)
# 3. Wireless analysis (SDR, WiFi Pineapple, Bluetooth adapter)
# 4. Software (Wireshark, UDS Explorer, CANdb++)

# Virtual test environment
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
```

## Attack Surface Testing

### OBD-II Port Testing

```python
#!/usr/bin/env python3
"""Automotive Penetration Testing Automation Framework."""

import argparse
import can
import time
import sys
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str


@dataclass
class PentestReport:
    target: str
    start_time: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        icon = {
            Severity.CRITICAL: "[!!]",
            Severity.HIGH: "[!]",
            Severity.MEDIUM: "[*]",
            Severity.LOW: "[-]",
            Severity.INFO: "[i]",
        }[finding.severity]
        print(f"  {icon} {finding.severity.value}: {finding.title}")

    def summary(self) -> str:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        lines = [
            f"\n{'='*60}",
            f"Penetration Test Results: {self.target}",
            f"{'='*60}",
            f"Total findings: {len(self.findings)}",
        ]
        for sev in Severity:
            if counts[sev]:
                lines.append(f"  {sev.value:10s}: {counts[sev]}")
        return "\n".join(lines)


def test_unauthenticated_services(
    bus: can.Bus,
    report: PentestReport,
    tx_id: int = 0x7E0,
    rx_id: int = 0x7E8,
) -> None:
    """Test UDS services accessible without authentication."""

    def send_recv(data: bytes, timeout: float = 1.0) -> bytes | None:
        frame = can.Message(
            arbitration_id=tx_id,
            data=bytes([len(data)]) + data + bytes(7 - len(data)),
            is_extended_id=False,
        )
        bus.send(frame)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                return bytes(msg.data)
        return None

    # Unauthenticated access to extended session
    resp = send_recv(bytes([0x10, 0x03]))  # Extended diagnostic session
    if resp and resp[1] == 0x50:
        report.add(Finding(
            title="Unauthenticated Extended Diagnostic Session Access",
            severity=Severity.HIGH,
            description="Extended diagnostic session (0x03) accessible without authentication",
            evidence=f"Response: {resp.hex()}",
            recommendation="Require SecurityAccess (0x27) before granting session access",
        ))

    # Unauthenticated write DID test
    test_dids = [0xF190, 0xF197, 0x0101, 0x0102]
    for did in test_dids:
        write_req = bytes([0x2E, did >> 8, did & 0xFF, 0x00])
        resp = send_recv(write_req)
        if resp and resp[1] != 0x7F:
            report.add(Finding(
                title=f"Unauthenticated Write to DID 0x{did:04X}",
                severity=Severity.CRITICAL,
                description=f"DID {did:04X} write allowed without security access",
                evidence=f"Response: {resp.hex()}",
                recommendation="Require security access for WriteDataByIdentifier",
            ))

    # Unauthenticated RoutineControl test
    routines = [0x0203, 0xFF00, 0x0101]
    for routine in routines:
        req = bytes([0x31, 0x01, routine >> 8, routine & 0xFF])
        resp = send_recv(req)
        if resp and resp[1] == 0x71:  # RoutineControl positive response
            report.add(Finding(
                title=f"Unauthenticated Execution of Routine 0x{routine:04X}",
                severity=Severity.HIGH,
                description="Routine can be executed without security access",
                evidence=f"Response: {resp.hex()}",
                recommendation="Elevate security level for RoutineControl",
            ))


def test_can_injection(
    bus: can.Bus,
    report: PentestReport,
    duration: float = 5.0,
) -> None:
    """Test CAN message injection possibility."""

    # Send arbitrary messages that appear valid
    test_ids = [0x018, 0x244, 0x3B2, 0x5A1]
    for can_id in test_ids:
        frame = can.Message(
            arbitration_id=can_id,
            data=bytes([0xFF] * 8),
            is_extended_id=False,
        )
        try:
            bus.send(frame)
            report.add(Finding(
                title=f"CAN ID 0x{can_id:03X} Injection Possible",
                severity=Severity.MEDIUM,
                description="Arbitrary CAN messages can be sent (no authentication)",
                evidence=f"CAN ID 0x{can_id:03X} sent successfully",
                recommendation="Apply message source validation and signing at gateway ECU",
            ))
        except can.CanError:
            pass


def test_firmware_update(
    bus: can.Bus,
    report: PentestReport,
    tx_id: int = 0x7E0,
    rx_id: int = 0x7E8,
) -> None:
    """Security test of the firmware update process."""

    def send_recv(data: bytes, timeout: float = 1.0) -> bytes | None:
        frame = can.Message(
            arbitration_id=tx_id,
            data=bytes([len(data)]) + data + bytes(7 - len(data)),
            is_extended_id=False,
        )
        bus.send(frame)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == rx_id:
                return bytes(msg.data)
        return None

    # Unauthenticated programming session access
    resp = send_recv(bytes([0x10, 0x02]))  # Programming session
    if resp and resp[1] == 0x50:
        report.add(Finding(
            title="Unauthenticated Programming Session Access",
            severity=Severity.CRITICAL,
            description="Programming session accessible without authentication → firmware flash possible",
            evidence=f"Response: {resp.hex()}",
            recommendation="Require multi-factor SecurityAccess for programming session",
        ))

    # Unauthenticated RequestDownload test
    resp = send_recv(bytes([0x34, 0x00, 0x44, 0x00, 0x00, 0x00]))
    if resp and resp[1] != 0x7F:
        report.add(Finding(
            title="Unauthenticated Firmware Download Request Allowed",
            severity=Severity.CRITICAL,
            description="Firmware download without signature verification → RCE possible",
            evidence=f"Response: {resp.hex()}",
            recommendation="Apply ECDSA signature verification and root CA-based certificate chain",
        ))


def test_wireless_interfaces(report: PentestReport, host: str) -> None:
    """Security test of wireless interfaces (WiFi, Bluetooth)."""
    import subprocess

    # Wi-Fi scan
    result = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi"],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if host.lower() in line.lower():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] in ("--", "WEP", ""):
                report.add(Finding(
                    title=f"Weak Wi-Fi Security: {parts[0]}",
                    severity=Severity.HIGH,
                    description=f"Wi-Fi '{parts[0]}' uses weak encryption or is open",
                    evidence=line,
                    recommendation="Apply WPA3 Enterprise or WPA2-AES",
                ))


def main() -> None:
    parser = argparse.ArgumentParser(description="Automotive Penetration Testing Framework")
    parser.add_argument("interface", help="CAN interface")
    parser.add_argument("--target", default="Unknown Vehicle",
                        help="Target name")
    parser.add_argument("--tx-id", type=lambda x: int(x, 16), default=0x7E0)
    parser.add_argument("--rx-id", type=lambda x: int(x, 16), default=0x7E8)
    parser.add_argument("--all", action="store_true", help="Run all tests")
    args = parser.parse_args()

    report = PentestReport(target=args.target)
    bus = can.interface.Bus(args.interface, interface="socketcan")

    print(f"[*] Starting automotive penetration test: {args.target}")
    print(f"[*] CAN interface: {args.interface}")
    print(f"[*] TX: 0x{args.tx_id:03X} | RX: 0x{args.rx_id:03X}\n")

    try:
        print("[*] 1. Testing unauthenticated UDS services...")
        test_unauthenticated_services(bus, report, args.tx_id, args.rx_id)

        print("\n[*] 2. Testing CAN injection...")
        test_can_injection(bus, report)

        print("\n[*] 3. Testing firmware update security...")
        test_firmware_update(bus, report, args.tx_id, args.rx_id)

        print(report.summary())

        if report.findings:
            print(f"\n[Detailed Findings]")
            for i, f in enumerate(report.findings, 1):
                print(f"\n{i}. [{f.severity.value}] {f.title}")
                print(f"   Description: {f.description}")
                print(f"   Recommendation: {f.recommendation}")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
```

## Report Template

```markdown
# Automotive Cybersecurity Penetration Test Report

## Summary
- **Target**: [Vehicle model/ECU]
- **Test period**: [Date]
- **Risk distribution**: CRITICAL N, HIGH N, MEDIUM N

## Key Findings
### [CRITICAL] Unauthenticated Firmware Update
**CVSS**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**Impact**: Remote code execution, possible takeover of vehicle control
**Reproduction steps**: ...
**Recommendation**: Apply ECDSA signature verification

## ISO/SAE 21434 Mapping
| Finding | TARA Threat | ASIL Level | Priority |
```

## Vulnerability Impact Assessment (EVITA)

```
EVITA (E-safety Vehicle Intrusion proTected Applications)
Security levels:
  HIGH   — Life safety threat (brakes, steering)
  MEDIUM — Property damage (engine, transmission)
  LOW    — Inconvenience (infotainment, lighting)

SFOP (Safety, Financial, Operational, Privacy)
Impact rated 1~3 for each dimension → overall risk score calculated
```

Automotive security is the field that demands the highest level of ethical responsibility. All tests must be performed in a controlled environment with explicit authorization.

## CAN Frame Cycle-Time Anomaly Detection — Catching Injected Frames by Timing

The CAN bus has almost no authentication or encryption, so an attacker can inject forged frames with the same arbitration ID as a legitimate ECU (e.g., spoofing steering/braking commands). However, most periodic CAN messages are sent at a **fixed cycle time** (e.g., every 10 ms), so an injection attack inevitably produces **abnormally short inter-frame gaps** (the forged and legitimate frames overlap, observed at roughly double the frequency). If you learn each ID's normal cycle-time baseline, you can statistically catch frames arriving markedly faster than baseline. This is defensive IDS logic, validated only on owned vehicles/benches.

```python
#!/usr/bin/env python3
"""Detect injection attacks from CAN frame timestamps as cycle-time anomalies. Learn each
arbitration ID's normal cycle time -> flag when an observed gap is markedly shorter than
baseline (forged + legitimate frames overlapping). Defensive IDS logic."""
from statistics import mean, pstdev

Frame = tuple[float, int]   # (timestamp_sec, arbitration_id)


def learn_baseline(frames: list[Frame]) -> dict[int, float]:
    """Learn the mean normal inter-frame gap (cycle time) per ID."""
    times: dict[int, list[float]] = {}
    for ts, cid in frames:
        times.setdefault(cid, []).append(ts)
    baseline = {}
    for cid, ts_list in times.items():
        gaps = [b - a for a, b in zip(ts_list, ts_list[1:])]
        if len(gaps) >= 5:
            baseline[cid] = mean(gaps)
    return baseline


def detect_injection(frames: list[Frame], baseline: dict[int, float]) -> list[dict]:
    anomalies, last = [], {}
    for ts, cid in frames:
        if cid in baseline and cid in last:
            gap = ts - last[cid]
            # gap shorter than half the normal cycle = suspected forged-frame overlap
            if gap < baseline[cid] * 0.5:
                anomalies.append({"id": hex(cid), "gap_ms": round(gap * 1000, 2),
                                  "expected_ms": round(baseline[cid] * 1000, 2)})
        last[cid] = ts
    return anomalies
```

| Signal | Description | False-Positive / Adjustment Factor |
|--------|-------------|------------------------------------|
| Gap under half the cycle time | Forged + legitimate frame overlap = suspected injection | Exclude event-driven (aperiodic) IDs from baseline learning |
| Sudden spike in per-ID frequency | Spoofing sends more often than normal | Must be distinguished from bus-load variation / normal bursts |
| ID appears from an unexpected source | An ID normally used only by one ECU used by another node | Gateway re-transmission and diagnostic sessions are legitimate |

**Detection/Defense**: Timing-based detection is valid only for periodic messages, so **exclude event-driven IDs from baseline learning** and combine with frequency/source signals to reduce false positives. A mature approach adds **CAN message authentication (e.g., AUTOSAR SecOC)** for root mitigation and keeps the IDS as a detection/alerting layer. Because automotive is safety-critical, perform all validation only on **owned vehicles / isolated benches** under explicit authorization ([[63_OT_ICS_Advanced]], [[48_Threat_Modeling]]).

<!-- detect-validate-62 -->
## Automotive Pentest Validation — Are Threat Scenarios Actually Reproduced and Mitigations Proven?

Automotive pentesting is judged not by *having written a TARA* but by **whether identified threat scenarios are actually reproduced on a bench and applied mitigations are proven to block the same scenario on retest**. Validate only on **owned vehicles / benches**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Scenario reproduction | Assumed threat | Reproduce on bench | Real reproduction confirmed |
| Mitigation proof | Mitigation unverified | Retest after fix | Scenario blocked |
| Attack-surface scope | Missed interfaces | Interface inventory | All interfaces assessed |
| Safety controls | Unsafe live test | Isolation/safeguards | Safety measures honored |

### Defense validation (verify directly)

```bash
# 1) Whether exposed vehicle interfaces (telematics/Wi-Fi/BT) are actually up — owned vehicle only
nmap -Pn -sV 192.168.x.x 2>/dev/null | grep -E 'open' | head || echo "scan the head-unit/telematics interface on owned vehicle"
# 2) Retest record showing the same PoC is blocked after mitigation (evidence)
echo "Record PoC result pre-mitigation vs post-mitigation; healthy = same attack blocked after fix (owned bench)"
```

> Validate only on **owned vehicles / benches** — test safety domains only under isolation and safeguards. "Wrote a TARA" differs from "scenarios are reproduced and blocked" — confirm directly via reproduction and retest ([[10_Pentest_Methodology]], [[17_Red_Team_Operations]]).
