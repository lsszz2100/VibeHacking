# ECU 분석 및 펌웨어 해킹

## ECU 하드웨어 분석

### 일반적인 ECU 아키텍처
```
ECU 보드 구성
├── 마이크로컨트롤러 (MCU)
│   ├── Renesas RH850, RL78
│   ├── NXP S32K, MPC57xx
│   ├── Infineon TC2xx, TC3xx (TriCore)
│   └── STMicroelectronics SPC5xx
├── 플래시 메모리 (1~32MB)
├── EEPROM (설정 저장)
├── CAN 트랜시버
├── LIN 트랜시버 (선택)
└── 전원 관리 IC
```

### 물리적 접근 방법
```bash
# 1. JTAG/SWD 디버그 인터페이스
#    — 핀 탐색 (로직 분석기, 멀티미터)
#    — OpenOCD로 연결
#    — 플래시 덤프, 메모리 접근

# 2. 부트로더 모드 진입
#    — BOOT 핀을 특정 레벨로 설정
#    — CAN/LIN/FlexRay 부트로더 프로토콜

# 3. 플래시 칩 직접 읽기
#    — 칩 탈납 또는 클립 연결
#    — SPI 플래시: flashrom으로 읽기

# 4. 진단 포트 접근 (CAN via OBD-II)
#    — UDS 프로토콜 활용
```

## 펌웨어 덤프

### JTAG를 통한 덤프
```bash
# OpenOCD 설정 (Renesas RH850 예시)
cat > openocd.cfg <<'EOF'
interface ftdi
ftdi_device_desc "FTDI USB Serial"
ftdi_vid_pid 0x0403 0x6010
adapter_khz 1000

set CHIP_NAME R7F701035
source [find target/renesas_rh850.cfg]
EOF

openocd -f openocd.cfg

# 다른 터미널에서
telnet localhost 4444
> halt
> dump_image ecu_firmware.bin 0x00000000 0x200000
> resume
```

### UDS 메모리 읽기
```python
#!/usr/bin/env python3
"""UDS 프로토콜을 통한 ECU 데이터 읽기."""

import argparse
import can
import time
import sys
from dataclasses import dataclass


# UDS 서비스 ID
SID_DIAG_SESSION = 0x10
SID_SECURITY_ACCESS = 0x27
SID_READ_DATA = 0x22
SID_WRITE_DATA = 0x2E
SID_READ_MEMORY = 0x23
SID_REQUEST_DOWNLOAD = 0x34
SID_TRANSFER_DATA = 0x36
SID_TESTER_PRESENT = 0x3E

# UDS 세션 타입
SESSION_DEFAULT = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED = 0x03


@dataclass
class UDSResponse:
    service_id: int
    data: bytes
    is_positive: bool
    nrc: int = 0  # Negative Response Code


def send_uds(
    bus: can.Bus,
    tx_id: int,
    rx_id: int,
    request: bytes,
    timeout: float = 2.0,
) -> UDSResponse | None:
    """UDS 요청 전송 및 응답 수신."""
    # ISO-TP 단일 프레임 (SF): 데이터 길이 ≤ 7
    if len(request) <= 7:
        frame_data = bytes([len(request)]) + request + bytes(7 - len(request))
        frame = can.Message(
            arbitration_id=tx_id,
            data=frame_data,
            is_extended_id=False,
        )
        bus.send(frame)
    else:
        # 멀티프레임 필요 (간략화 — 실제로는 ISO-TP 라이브러리 사용)
        print("[!] 멀티프레임 미지원 — isotp 라이브러리 사용 권장", file=sys.stderr)
        return None

    # 응답 대기
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = bus.recv(timeout=0.1)
        if msg and msg.arbitration_id == rx_id:
            data = bytes(msg.data)
            length = data[0] & 0x0F
            payload = data[1:1 + length]

            if payload[0] == 0x7F:  # 부정 응답
                return UDSResponse(
                    service_id=payload[1],
                    data=payload,
                    is_positive=False,
                    nrc=payload[2] if len(payload) > 2 else 0,
                )
            return UDSResponse(
                service_id=payload[0],
                data=payload[1:],
                is_positive=True,
            )
    return None


def change_session(
    bus: can.Bus, tx_id: int, rx_id: int, session: int
) -> bool:
    resp = send_uds(bus, tx_id, rx_id,
                    bytes([SID_DIAG_SESSION, session]))
    return resp is not None and resp.is_positive


def security_access(
    bus: can.Bus, tx_id: int, rx_id: int, level: int
) -> bool:
    """시드-키 보안 접근 (키 알고리즘은 제조사마다 다름)."""
    # 시드 요청
    resp = send_uds(bus, tx_id, rx_id,
                    bytes([SID_SECURITY_ACCESS, level]))
    if not resp or not resp.is_positive or len(resp.data) < 4:
        print(f"[!] 시드 요청 실패")
        return False

    seed = resp.data[:4]
    print(f"[*] 시드: {seed.hex().upper()}")

    # 키 계산 (예시: 간단한 XOR — 실제는 역공학 필요)
    key = bytes(b ^ 0xFF for b in seed)
    print(f"[*] 키 (추정): {key.hex().upper()}")

    # 키 전송
    resp2 = send_uds(bus, tx_id, rx_id,
                     bytes([SID_SECURITY_ACCESS, level + 1]) + key)
    if resp2 and resp2.is_positive:
        print("[+] 보안 접근 성공!")
        return True
    nrc = resp2.nrc if resp2 else 0
    print(f"[-] 보안 접근 실패 (NRC: 0x{nrc:02X})")
    return False


def read_data_by_id(
    bus: can.Bus, tx_id: int, rx_id: int, did: int
) -> bytes | None:
    """데이터 식별자(DID)로 ECU 데이터 읽기."""
    resp = send_uds(bus, tx_id, rx_id,
                    bytes([SID_READ_DATA,
                           (did >> 8) & 0xFF,
                           did & 0xFF]))
    if resp and resp.is_positive:
        return resp.data[2:]  # DID 에코 건너뜀
    return None


def enumerate_dids(
    bus: can.Bus, tx_id: int, rx_id: int,
    start: int = 0xF100, end: int = 0xF1FF,
) -> dict[int, bytes]:
    """DID 열거 — 제조사 데이터 발견."""
    found: dict[int, bytes] = {}
    print(f"[*] DID 열거: 0x{start:04X}~0x{end:04X}")
    for did in range(start, end + 1):
        data = read_data_by_id(bus, tx_id, rx_id, did)
        if data:
            found[did] = data
            printable = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in data
            )
            print(f"  DID 0x{did:04X}: {data.hex()} | {printable}")
        time.sleep(0.05)
    return found


NRC_CODES = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="UDS ECU 분석 도구")
    parser.add_argument("interface", help="CAN 인터페이스 (vcan0)")
    parser.add_argument("--tx-id", type=lambda x: int(x, 16),
                        default=0x7E0, help="송신 CAN ID (기본: 0x7E0)")
    parser.add_argument("--rx-id", type=lambda x: int(x, 16),
                        default=0x7E8, help="수신 CAN ID (기본: 0x7E8)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("session", help="확장 세션 전환 테스트")
    
    sec_p = sub.add_parser("security", help="보안 접근 테스트")
    sec_p.add_argument("--level", type=int, default=1)

    enum_p = sub.add_parser("enum-did", help="DID 열거")
    enum_p.add_argument("--start", type=lambda x: int(x, 16), default=0xF100)
    enum_p.add_argument("--end", type=lambda x: int(x, 16), default=0xF1FF)

    read_p = sub.add_parser("read-did", help="DID 읽기")
    read_p.add_argument("did", type=lambda x: int(x, 16))

    args = parser.parse_args()

    bus = can.interface.Bus(args.interface, interface="socketcan")
    try:
        if args.cmd == "session":
            for session_name, session_id in [
                ("Default", SESSION_DEFAULT),
                ("Programming", SESSION_PROGRAMMING),
                ("Extended", SESSION_EXTENDED),
            ]:
                ok = change_session(bus, args.tx_id, args.rx_id, session_id)
                print(f"  세션 {session_name} (0x{session_id:02X}): "
                      f"{'✓' if ok else '✗'}")

        elif args.cmd == "security":
            change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
            security_access(bus, args.tx_id, args.rx_id, args.level)

        elif args.cmd == "enum-did":
            change_session(bus, args.tx_id, args.rx_id, SESSION_EXTENDED)
            found = enumerate_dids(bus, args.tx_id, args.rx_id,
                                   args.start, args.end)
            print(f"\n[+] 발견된 DID: {len(found)}개")

        elif args.cmd == "read-did":
            data = read_data_by_id(bus, args.tx_id, args.rx_id, args.did)
            if data:
                print(f"[+] DID 0x{args.did:04X}: {data.hex()} "
                      f"| {data.decode(errors='replace')}")
            else:
                print(f"[-] DID 0x{args.did:04X}: 응답 없음")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
```

## 펌웨어 리버싱 (TriCore 예시)

```bash
# Ghidra에 TriCore 프로세서 추가
# TriCore 플러그인 설치 후

# IDA Pro로 RH850 분석
# 프로세서 모듈: Renesas RH850

# 공통 분석 포인트
# 1. 인터럽트 벡터 테이블
# 2. CAN 수신 핸들러
# 3. UDS 서비스 디스패처
# 4. 보안 접근 키 알고리즘

# 키 알고리즘 역공학
# SecurityAccess 서브루틴 탐색
grep -r "SecurityAccess\|0x27" ghidra_export/ 2>/dev/null
```

다음 파일에서 V2X 통신 보안을 다룬다.
