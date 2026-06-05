> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 자동차 보안 CTF 실습 랩

## 랩 개요

자동차 사이버 보안 취약점을 CTF 형식으로 학습한다. CAN 버스 분석, UDS 진단 프로토콜 공격, OBD-II 데이터 조작, V2X 통신 서명 우회 등 실제 차량 공격 기법을 실습한다.

## 실습 환경 설정

```bash
# 필수 도구 설치
pip install python-can scapy

# CAN 버스 가상 인터페이스 (Linux)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# CTF 도구 실행
python3 automotive_ctf.py --help
```

```python
#!/usr/bin/env python3
"""자동차 보안 CTF 실습 도구 — automotive_ctf.py"""

import argparse
import hashlib
import struct
import time
from dataclasses import dataclass, field


@dataclass
class AutomotiveChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: AutomotiveChallenge) -> bool:
    """제출 플래그 검증."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, AutomotiveChallenge] = {
    "can_decode": AutomotiveChallenge(
        name="CAN 버스 패킷 디코딩",
        category="CAN Bus",
        points=100,
        description="""
제공된 CAN 버스 캡처 파일 'capture.log'에 숨겨진 플래그가 있다.
특정 CAN ID(0x7FF)로 전송된 8바이트 페이로드를 ASCII로 디코딩하면
플래그가 나타난다. 여러 프레임에 나뉘어 전송될 수 있다.

캡처 형식: candump 로그 형식
  (타임스탬프) vcan0 CAN_ID#페이로드
""",
        flag="CTF{c4n_bu5_d3c0d3d}",
        hints=[
            "candump 또는 python-can 으로 캡처 파일 파싱",
            "CAN ID 0x7FF 필터링: can_id == 0x7FF",
            "페이로드 바이트를 순서대로 조합 후 ASCII 변환",
        ],
    ),
    "uds_access": AutomotiveChallenge(
        name="UDS 진단 권한 없는 서비스 접근",
        category="UDS Protocol",
        points=200,
        description="""
ECU가 UDS(Unified Diagnostic Services) 진단 서버를 실행 중이다.
Security Access 서비스(0x27)를 우회하거나,
숨겨진 진단 세션(DiagnosticSessionControl 0x10)을 발견하여
플래그가 저장된 ReadDataByIdentifier(0x22) 서비스에 접근하라.

타겟 ECU: 127.0.0.1:8080 (시뮬레이션)
DID(Data Identifier): 0xF190 (VIN) — 숨겨진 DID 탐색 필요
""",
        flag="CTF{ud5_s3cur1ty_4cc3ss_byp4ss}",
        hints=[
            "UDS SecurityAccess: 시드 XOR 0xAA 가 키 공식",
            "DiagnosticSessionControl 0x10 0x03 (extendedDiagnosticSession)",
            "DID 브루트포스: 0xF100~0xF1FF 범위 스캔",
        ],
    ),
    "obd_extract": AutomotiveChallenge(
        name="OBD-II 데이터에서 숨겨진 메시지 추출",
        category="OBD-II",
        points=150,
        description="""
OBD-II 포트에서 수집한 PID 응답 데이터에 숨겨진 메시지가 있다.
비표준 PID(Mode 0x09, PID 0x0A 이후)에 ASCII 문자가 숨겨져 있다.
각 응답의 특정 바이트 위치에서 문자를 추출하면 플래그가 완성된다.

데이터 파일: obd_responses.json
""",
        flag="CTF{0bd_h1dd3n_m3ss4g3}",
        hints=[
            "Mode 09 PID 는 차량 정보 (VIN, calibration ID 등)",
            "각 PID 응답 바이트 2 (오프셋 2)를 추출하여 조합",
            "비표준 PID 0x20~0x2F 범위에 플래그 분산",
        ],
    ),
    "v2x_bypass": AutomotiveChallenge(
        name="V2X 통신 서명 검증 우회",
        category="V2X Security",
        points=300,
        description="""
V2X(Vehicle-to-Everything) BSM(Basic Safety Message)이 ECDSA 서명으로 보호된다.
검증 서버가 서명 검증 시 타임스탬프 검사를 누락했다.
리플레이 공격으로 이전 유효 메시지를 재전송하거나,
서명 검증 로직의 결함을 이용하여 플래그 포함 메시지를 주입하라.

BSM 형식: [8바이트 타임스탬프] [위도 4바이트] [경도 4바이트] [속도 2바이트] [서명 64바이트]
검증 서버: http://localhost:9001/v2x/verify
""",
        flag="CTF{v2x_r3pl4y_4tt4ck_succ3ss}",
        hints=[
            "타임스탬프 검증 없음 → 이전 캡처 메시지 그대로 재전송",
            "서명은 메시지 앞 18바이트에 대한 ECDSA (취약: r=0 허용)",
            "null 서명(r=0, s=0) 으로 일부 구현 우회 가능",
        ],
    ),
}
```

## 챌린지 1: CAN 버스 패킷 파서

```python
#!/usr/bin/env python3
"""CAN 버스 패킷 파서 및 플래그 추출 도구."""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CANFrame:
    timestamp: float
    interface: str
    can_id: int
    data: bytes

    @property
    def data_hex(self) -> str:
        return self.data.hex().upper()

    @property
    def data_ascii(self) -> str:
        return "".join(
            chr(b) if 32 <= b < 127 else "." for b in self.data
        )


def parse_candump_log(log_text: str) -> list[CANFrame]:
    """candump 형식 로그 파싱."""
    # 형식: (1234567890.123456) vcan0 7FF#4354467B...
    pattern = re.compile(
        r"\((\d+\.\d+)\)\s+(\w+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)"
    )
    frames: list[CANFrame] = []
    for line in log_text.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        ts, iface, can_id_str, data_str = m.groups()
        frames.append(CANFrame(
            timestamp=float(ts),
            interface=iface,
            can_id=int(can_id_str, 16),
            data=bytes.fromhex(data_str) if data_str else b"",
        ))
    return frames


def generate_sample_log() -> str:
    """CTF용 샘플 CAN 로그 생성 (플래그 숨김)."""
    # 플래그: CTF{c4n_bu5_d3c0d3d} — 0x7FF ID로 분산 전송
    flag_bytes = b"CTF{c4n_bu5_d3c0d3d}"
    lines = []
    base_ts = 1700000000.0

    # 노이즈 프레임
    noise_ids = [0x100, 0x200, 0x300, 0x1A0, 0x2B0]
    for i, nid in enumerate(noise_ids):
        noise_data = bytes([i * 0x11] * 8)
        lines.append(f"({base_ts + i * 0.01:.6f}) vcan0 {nid:03X}#{noise_data.hex().upper()}")

    # 플래그 프레임 (8바이트씩 분할)
    for chunk_idx in range(0, len(flag_bytes), 8):
        chunk = flag_bytes[chunk_idx:chunk_idx + 8].ljust(8, b"\x00")
        ts = base_ts + 0.1 + chunk_idx * 0.05
        lines.append(f"({ts:.6f}) vcan0 7FF#{chunk.hex().upper()}")
        # 노이즈 삽입
        lines.append(f"({ts + 0.01:.6f}) vcan0 050#{bytes(8).hex().upper()}")

    return "\n".join(lines)


def extract_flag_from_can(frames: list[CANFrame], target_id: int = 0x7FF) -> str:
    """특정 CAN ID 프레임에서 플래그 추출."""
    flag_data = bytearray()
    for frame in sorted(frames, key=lambda f: f.timestamp):
        if frame.can_id == target_id:
            flag_data.extend(frame.data)
    # 널 패딩 제거
    decoded = flag_data.rstrip(b"\x00").decode("ascii", errors="ignore")
    return decoded


def analyze_can_traffic(frames: list[CANFrame]) -> None:
    """CAN 트래픽 통계 분석."""
    id_counts: dict[int, int] = {}
    for f in frames:
        id_counts[f.can_id] = id_counts.get(f.can_id, 0) + 1

    print(f"[*] 총 프레임: {len(frames)}")
    print(f"[*] 고유 CAN ID: {len(id_counts)}")
    print("\n[*] ID별 프레임 수 (상위 10개):")
    for can_id, count in sorted(id_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  0x{can_id:03X}: {count}개")


def main() -> None:
    parser = argparse.ArgumentParser(description="CAN 버스 CTF 분석 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    parse_p = sub.add_parser("parse", help="CAN 로그 파싱 및 분석")
    parse_p.add_argument("log_file", type=Path, nargs="?", help="candump 로그 파일")
    parse_p.add_argument("--id", type=lambda x: int(x, 16), default=0x7FF,
                         help="필터링할 CAN ID (hex, 기본값: 0x7FF)")

    sub.add_parser("sample", help="샘플 CAN 로그 생성")

    sub.add_parser("solve", help="자동 플래그 추출 시연")

    args = parser.parse_args()

    if args.cmd == "sample":
        log = generate_sample_log()
        out = Path("capture.log")
        out.write_text(log)
        print(f"[+] 샘플 CAN 로그 생성: {out}")
        print(f"    총 {len(log.splitlines())}개 프레임")

    elif args.cmd == "parse":
        if args.log_file and args.log_file.exists():
            log_text = args.log_file.read_text()
        else:
            print("[!] 로그 파일 없음. 샘플 생성 중...")
            log_text = generate_sample_log()

        frames = parse_candump_log(log_text)
        analyze_can_traffic(frames)

        target = getattr(args, "id", 0x7FF)
        filtered = [f for f in frames if f.can_id == target]
        print(f"\n[*] CAN ID 0x{target:03X} 프레임 {len(filtered)}개:")
        for f in filtered:
            print(f"  {f.timestamp:.6f}  {f.data_hex}  |{f.data_ascii}|")

    elif args.cmd == "solve":
        print("[*] CAN 버스 플래그 자동 추출\n")
        log_text = generate_sample_log()
        frames = parse_candump_log(log_text)
        flag = extract_flag_from_can(frames, 0x7FF)
        if flag.startswith("CTF{"):
            print(f"[+] 플래그 발견: {flag}")
        else:
            print(f"[?] 추출 결과: {flag!r}")


if __name__ == "__main__":
    main()
```

## 챌린지 2: UDS 진단 프로토콜 시뮬레이터

```python
#!/usr/bin/env python3
"""UDS 진단 서버 시뮬레이션 및 취약점 실습."""

import argparse
import json
import struct
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer


# UDS 서비스 ID
SVC_DIAGNOSTIC_SESSION = 0x10
SVC_SECURITY_ACCESS    = 0x27
SVC_READ_DATA_BY_ID    = 0x22
SVC_NEGATIVE_RESPONSE  = 0x7F

# 세션 유형
SESSION_DEFAULT    = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED   = 0x03

# 오류 코드
NRC_SERVICE_NOT_SUPPORTED  = 0x11
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_INVALID_KEY            = 0x35
NRC_EXCEEDED_NUMBER        = 0x36

# 숨겨진 DID — 플래그 저장
HIDDEN_DID = 0xF1A5
FLAG_DID_VALUE = b"CTF{ud5_s3cur1ty_4cc3ss_byp4ss}"


@dataclass
class UDSServer:
    """취약한 UDS ECU 시뮬레이터."""
    current_session: int = SESSION_DEFAULT
    security_level: int = 0          # 0=잠금, 1=레벨1 해제
    pending_seed: int | None = None
    access_attempt_count: int = 0

    DATA_BY_ID: dict[int, bytes] = field(default_factory=lambda: {
        0xF190: b"1HGBH41JXMN109186",   # VIN (표준)
        0xF18C: b"ECU_SERIAL_001",       # ECU 시리얼
        0xF187: b"SW_VER_2.3.1",         # SW 버전
        HIDDEN_DID: FLAG_DID_VALUE,      # 숨겨진 플래그 DID
    })

    def process_request(self, request: bytes) -> bytes:
        """UDS 요청 처리 (취약한 구현)."""
        if not request:
            return self._negative(0x00, NRC_SERVICE_NOT_SUPPORTED)

        service_id = request[0]

        if service_id == SVC_DIAGNOSTIC_SESSION:
            return self._handle_session_control(request)
        elif service_id == SVC_SECURITY_ACCESS:
            return self._handle_security_access(request)
        elif service_id == SVC_READ_DATA_BY_ID:
            return self._handle_read_data(request)
        else:
            return self._negative(service_id, NRC_SERVICE_NOT_SUPPORTED)

    def _handle_session_control(self, req: bytes) -> bytes:
        if len(req) < 2:
            return self._negative(SVC_DIAGNOSTIC_SESSION, NRC_CONDITIONS_NOT_CORRECT)
        session_type = req[1]
        self.current_session = session_type
        # 취약점: 세션 전환 시 보안 레벨 초기화 안 함
        return bytes([0x50, session_type, 0x00, 0x19, 0x01, 0xF4])

    def _handle_security_access(self, req: bytes) -> bytes:
        if len(req) < 2:
            return self._negative(SVC_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)

        sub_func = req[1]
        if sub_func == 0x01:  # 시드 요청
            import random
            seed = random.randint(0x1000, 0xFFFF)
            self.pending_seed = seed
            return bytes([0x67, 0x01]) + struct.pack(">H", seed)
        elif sub_func == 0x02:  # 키 전송
            if self.pending_seed is None:
                return self._negative(SVC_SECURITY_ACCESS, NRC_REQUEST_SEQUENCE_ERROR)
            if len(req) < 4:
                return self._negative(SVC_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
            submitted_key = struct.unpack(">H", req[2:4])[0]
            # 취약한 키 공식: key = seed XOR 0xAAAA
            expected_key = self.pending_seed ^ 0xAAAA
            if submitted_key == expected_key:
                self.security_level = 1
                self.pending_seed = None
                return bytes([0x67, 0x02])
            else:
                self.access_attempt_count += 1
                return self._negative(SVC_SECURITY_ACCESS, NRC_INVALID_KEY)
        else:
            return self._negative(SVC_SECURITY_ACCESS, NRC_SERVICE_NOT_SUPPORTED)

    def _handle_read_data(self, req: bytes) -> bytes:
        if len(req) < 3:
            return self._negative(SVC_READ_DATA_BY_ID, NRC_CONDITIONS_NOT_CORRECT)
        did = struct.unpack(">H", req[1:3])[0]
        if did == HIDDEN_DID and self.security_level < 1:
            return self._negative(SVC_READ_DATA_BY_ID, NRC_CONDITIONS_NOT_CORRECT)
        value = self.DATA_BY_ID.get(did)
        if value is None:
            return self._negative(SVC_READ_DATA_BY_ID, 0x31)  # requestOutOfRange
        return bytes([0x62]) + req[1:3] + value

    def _negative(self, service: int, nrc: int) -> bytes:
        return bytes([SVC_NEGATIVE_RESPONSE, service, nrc])


ECU = UDSServer()


class UDSHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
            request_hex = data.get("request", "")
            request_bytes = bytes.fromhex(request_hex)
            response = ECU.process_request(request_bytes)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "response": response.hex(),
                "session": ECU.current_session,
                "security_level": ECU.security_level,
            }).encode())
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def log_message(self, *args) -> None:
        pass


def solve_uds_demo() -> None:
    """UDS 취약점 익스플로잇 시연 (로컬 시뮬레이션)."""
    ecu = UDSServer()
    print("[*] UDS 취약점 익스플로잇 시연\n")

    # 1단계: 확장 진단 세션 진입
    req1 = bytes([SVC_DIAGNOSTIC_SESSION, SESSION_EXTENDED])
    resp1 = ecu.process_request(req1)
    print(f"1) 확장 세션 진입: {resp1.hex()} ({'성공' if resp1[0] == 0x50 else '실패'})")

    # 2단계: 시드 요청
    req2 = bytes([SVC_SECURITY_ACCESS, 0x01])
    resp2 = ecu.process_request(req2)
    seed = struct.unpack(">H", resp2[2:4])[0]
    print(f"2) 시드 획득: 0x{seed:04X}")

    # 3단계: 취약한 키 공식 적용
    key = seed ^ 0xAAAA
    req3 = bytes([SVC_SECURITY_ACCESS, 0x02]) + struct.pack(">H", key)
    resp3 = ecu.process_request(req3)
    unlocked = resp3[0] == 0x67
    print(f"3) 보안 해제: {'성공' if unlocked else '실패'} (키=0x{key:04X})")

    # 4단계: 숨겨진 DID 읽기
    req4 = bytes([SVC_READ_DATA_BY_ID]) + struct.pack(">H", HIDDEN_DID)
    resp4 = ecu.process_request(req4)
    if resp4[0] == 0x62:
        flag = resp4[3:].decode("ascii", errors="ignore")
        print(f"4) 플래그 DID(0x{HIDDEN_DID:04X}): {flag}")
    else:
        print(f"4) 실패: NRC=0x{resp4[2]:02X}")


def main() -> None:
    parser = argparse.ArgumentParser(description="자동차 보안 CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    srv_p = sub.add_parser("server", help="UDS ECU 시뮬레이터 서버")
    srv_p.add_argument("-p", "--port", type=int, default=8080)

    sub.add_parser("solve", help="UDS 취약점 자동 익스플로잇 시연")

    list_p = sub.add_parser("list", help="CTF 챌린지 목록")

    submit_p = sub.add_parser("submit", help="플래그 제출")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "server":
        server = HTTPServer(("0.0.0.0", args.port), UDSHandler)
        print(f"[*] UDS ECU 시뮬레이터: http://localhost:{args.port}")
        print(f"    POST {{\"request\": \"<hex>\"}} 형식으로 요청")
        server.serve_forever()

    elif args.cmd == "solve":
        solve_uds_demo()

    elif args.cmd == "list":
        print("자동차 보안 CTF 챌린지 목록:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         카테고리: {ch.category}")
            print()

    elif args.cmd == "submit":
        ch = CHALLENGES[args.challenge_id]
        if verify_flag(args.flag, ch):
            print(f"[+] 정답! {ch.points}점 획득")
        else:
            print("[-] 오답. 힌트:")
            for i, hint in enumerate(ch.hints, 1):
                print(f"    {i}. {hint}")


if __name__ == "__main__":
    main()
```

## 챌린지 3: V2X 통신 서명 검증 우회

```python
#!/usr/bin/env python3
"""V2X BSM 메시지 생성 및 서명 우회 시뮬레이션."""

import argparse
import hashlib
import struct
import time
from dataclasses import dataclass


@dataclass
class BSMMessage:
    """Basic Safety Message (V2X)."""
    timestamp: int        # 8바이트 Unix timestamp (ms)
    latitude: int         # 4바이트 고정소수점 (× 1e7)
    longitude: int        # 4바이트 고정소수점 (× 1e7)
    speed: int            # 2바이트 (0.02m/s 단위)
    signature_r: bytes    # ECDSA r (32바이트)
    signature_s: bytes    # ECDSA s (32바이트)

    def encode(self) -> bytes:
        header = struct.pack(">QiiH",
            self.timestamp, self.latitude, self.longitude, self.speed)
        return header + self.signature_r + self.signature_s

    @classmethod
    def decode(cls, data: bytes) -> "BSMMessage":
        if len(data) < 82:
            raise ValueError(f"BSM 데이터 너무 짧음: {len(data)} < 82")
        ts, lat, lon, spd = struct.unpack(">QiiH", data[:18])
        r = data[18:50]
        s = data[50:82]
        return cls(timestamp=ts, latitude=lat, longitude=lon,
                   speed=spd, signature_r=r, signature_s=s)

    def message_bytes(self) -> bytes:
        """서명 대상 바이트 (헤더만)."""
        return struct.pack(">QiiH",
            self.timestamp, self.latitude, self.longitude, self.speed)


FLAG_V2X = "CTF{v2x_r3pl4y_4tt4ck_succ3ss}"


def verify_bsm_vulnerable(msg: BSMMessage) -> dict[str, object]:
    """
    취약한 BSM 검증:
    - 타임스탬프 신선도 검사 없음 (리플레이 공격 가능)
    - ECDSA r=0 허용 (null 서명 허용)
    """
    result: dict[str, object] = {"valid": False, "reason": ""}

    # 취약점 1: r=0인 null 서명 허용
    if msg.signature_r == b"\x00" * 32:
        result["valid"] = True
        result["reason"] = "Null signature accepted (r=0)"
        result["flag"] = FLAG_V2X
        return result

    # 취약점 2: 타임스탬프 검사 없음 → 임의 오래된 메시지 허용
    # (실제로는 몇 초 이내만 허용해야 함)
    msg_hash = hashlib.sha256(msg.message_bytes()).hexdigest()
    result["valid"] = True
    result["reason"] = f"Timestamp not verified (hash: {msg_hash[:8]}...)"
    result["flag"] = FLAG_V2X
    return result


def create_null_signature_bsm() -> BSMMessage:
    """Null 서명(r=0) BSM 메시지 생성 — 취약한 검증기 우회."""
    return BSMMessage(
        timestamp=int(time.time() * 1000),
        latitude=int(37.5665 * 1e7),   # 서울
        longitude=int(126.9780 * 1e7),
        speed=100,
        signature_r=b"\x00" * 32,      # r=0 (null 서명)
        signature_s=b"\x00" * 32,
    )


def create_replay_bsm(original_ts: int = 0) -> BSMMessage:
    """리플레이 공격 — 오래된 타임스탬프로 메시지 생성."""
    return BSMMessage(
        timestamp=original_ts or (int(time.time() * 1000) - 86400000),
        latitude=int(37.5665 * 1e7),
        longitude=int(126.9780 * 1e7),
        speed=80,
        signature_r=bytes(range(32)),   # 임의 서명값
        signature_s=bytes(range(32, 64)),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="V2X 보안 CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("null-sig", help="Null 서명 공격 시연")
    sub.add_parser("replay", help="리플레이 공격 시연")

    args = parser.parse_args()

    if args.cmd == "null-sig":
        print("[*] V2X Null 서명 공격\n")
        msg = create_null_signature_bsm()
        encoded = msg.encode()
        print(f"    BSM 크기: {len(encoded)} bytes")
        print(f"    서명 r: {msg.signature_r.hex()}")
        result = verify_bsm_vulnerable(msg)
        print(f"    검증 결과: {'통과' if result['valid'] else '실패'}")
        print(f"    이유: {result['reason']}")
        if "flag" in result:
            print(f"    플래그: {result['flag']}")

    elif args.cmd == "replay":
        print("[*] V2X 리플레이 공격\n")
        old_ts = int(time.time() * 1000) - 3600000  # 1시간 전
        msg = create_replay_bsm(old_ts)
        result = verify_bsm_vulnerable(msg)
        print(f"    타임스탬프: {old_ts} (1시간 전)")
        print(f"    검증 결과: {'통과' if result['valid'] else '실패'}")
        if "flag" in result:
            print(f"    플래그: {result['flag']}")


if __name__ == "__main__":
    main()
```

## CTF 풀이 가이드

```
CAN 버스 분석 전략
├── candump -l vcan0  →  캡처 파일 생성
├── ID 필터링 → 비정상 ID 탐지 (0x7E0~0x7FF: OBD/UDS)
├── 페이로드 엔트로피 분석 → 낮은 엔트로피 = 반복 패턴
└── ASCII 변환 → 각 프레임 페이로드를 문자로 해석

UDS 공격 흐름
├── 0x10 0x03 (확장 세션) 진입
├── 0x27 0x01 (시드 요청) → 시드값 획득
├── 키 역산: XOR, NOT, ADD 등 단순 연산 시도
├── 0x27 0x02 + 키 → 보안 해제
└── 0x22 + DID 브루트포스 → 숨겨진 데이터 탐색

V2X 서명 우회 기법
├── 리플레이: 이전 캡처 메시지 그대로 재사용
├── Null 서명: ECDSA r=0 또는 s=0
├── 공개 키 위조: 검증 서버가 공개 키를 메시지에서 추출할 경우
└── 타임스탬프 조작: 미래 시간 설정으로 유효 기간 연장
```

## 심화 도전

1. **퍼징**: python-can + Scapy로 CAN 버스 퍼저 구현, ECU 크래시 유발
2. **UDS 전수조사**: 전체 서비스 ID(0x00~0xFF)와 서브 함수 조합 자동 스캔
3. **OTA 가로채기**: 차량 OTA 업데이트 Wi-Fi 트래픽 캡처 후 펌웨어 추출
4. **인포테인먼트 공격**: 미디어 메타데이터 버퍼 오버플로 → CAN 버스 접근

---

<a name="english"></a>

# Automotive Security CTF Lab

## Lab Overview

Learn automotive cybersecurity vulnerabilities in CTF format. Practice real-world vehicle attack techniques including CAN bus analysis, UDS diagnostic protocol attacks, OBD-II data manipulation, and V2X communication signature bypass.

## Lab Environment Setup

```bash
# Install required tools
pip install python-can scapy

# Virtual CAN interface (Linux)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Run CTF tool
python3 automotive_ctf.py --help
```

```python
#!/usr/bin/env python3
"""Automotive security CTF lab tool — automotive_ctf.py"""

import argparse
import hashlib
import struct
import time
from dataclasses import dataclass, field


@dataclass
class AutomotiveChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: AutomotiveChallenge) -> bool:
    """Verify submitted flag."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, AutomotiveChallenge] = {
    "can_decode": AutomotiveChallenge(
        name="CAN Bus Packet Decoding",
        category="CAN Bus",
        points=100,
        description="""
A hidden flag is embedded in the CAN bus capture file 'capture.log'.
Decode the 8-byte payload sent on CAN ID 0x7FF to ASCII to reveal the flag.
It may be split across multiple frames.

Capture format: candump log format
  (timestamp) vcan0 CAN_ID#PAYLOAD
""",
        flag="CTF{c4n_bu5_d3c0d3d}",
        hints=[
            "Parse the capture file using candump or python-can",
            "Filter CAN ID 0x7FF: can_id == 0x7FF",
            "Concatenate payload bytes in order and convert to ASCII",
        ],
    ),
    "uds_access": AutomotiveChallenge(
        name="UDS Unauthorized Service Access",
        category="UDS Protocol",
        points=200,
        description="""
An ECU is running a UDS (Unified Diagnostic Services) server.
Bypass the Security Access service (0x27) or discover a hidden
diagnostic session (DiagnosticSessionControl 0x10) to access
ReadDataByIdentifier (0x22) where the flag is stored.

Target ECU: 127.0.0.1:8080 (simulation)
DID: 0xF190 (VIN) — scan for hidden DIDs
""",
        flag="CTF{ud5_s3cur1ty_4cc3ss_byp4ss}",
        hints=[
            "UDS SecurityAccess: key formula is seed XOR 0xAA",
            "DiagnosticSessionControl 0x10 0x03 (extendedDiagnosticSession)",
            "Brute-force DID range 0xF100~0xF1FF",
        ],
    ),
    "obd_extract": AutomotiveChallenge(
        name="Hidden Message Extraction from OBD-II Data",
        category="OBD-II",
        points=150,
        description="""
PID response data collected from an OBD-II port contains a hidden message.
Non-standard PIDs (Mode 0x09, PID 0x0A and beyond) contain hidden ASCII characters.
Extract characters from specific byte offsets in each response to build the flag.

Data file: obd_responses.json
""",
        flag="CTF{0bd_h1dd3n_m3ss4g3}",
        hints=[
            "Mode 09 PIDs contain vehicle info (VIN, calibration ID, etc.)",
            "Extract byte at offset 2 from each PID response and concatenate",
            "Flag is distributed across non-standard PIDs 0x20~0x2F",
        ],
    ),
    "v2x_bypass": AutomotiveChallenge(
        name="V2X Communication Signature Bypass",
        category="V2X Security",
        points=300,
        description="""
V2X (Vehicle-to-Everything) BSM (Basic Safety Message) is protected by ECDSA signatures.
The verification server omits timestamp freshness checking.
Use a replay attack to retransmit a previously valid message,
or exploit a flaw in the signature verification logic to inject a flag-containing message.

BSM format: [8-byte timestamp] [4-byte latitude] [4-byte longitude] [2-byte speed] [64-byte signature]
Verification server: http://localhost:9001/v2x/verify
""",
        flag="CTF{v2x_r3pl4y_4tt4ck_succ3ss}",
        hints=[
            "No timestamp verification → replay a previously captured message as-is",
            "Signature is ECDSA over first 18 bytes (vulnerable: r=0 accepted)",
            "Some implementations can be bypassed with a null signature (r=0, s=0)",
        ],
    ),
}
```

## Challenge 1: CAN Bus Packet Parser

```python
#!/usr/bin/env python3
"""CAN bus packet parser and flag extraction tool."""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CANFrame:
    timestamp: float
    interface: str
    can_id: int
    data: bytes

    @property
    def data_hex(self) -> str:
        return self.data.hex().upper()

    @property
    def data_ascii(self) -> str:
        return "".join(
            chr(b) if 32 <= b < 127 else "." for b in self.data
        )


def parse_candump_log(log_text: str) -> list[CANFrame]:
    """Parse candump log format."""
    pattern = re.compile(
        r"\((\d+\.\d+)\)\s+(\w+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)"
    )
    frames: list[CANFrame] = []
    for line in log_text.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        ts, iface, can_id_str, data_str = m.groups()
        frames.append(CANFrame(
            timestamp=float(ts),
            interface=iface,
            can_id=int(can_id_str, 16),
            data=bytes.fromhex(data_str) if data_str else b"",
        ))
    return frames


def generate_sample_log() -> str:
    """Generate sample CAN log with hidden flag for CTF."""
    flag_bytes = b"CTF{c4n_bu5_d3c0d3d}"
    lines = []
    base_ts = 1700000000.0

    noise_ids = [0x100, 0x200, 0x300, 0x1A0, 0x2B0]
    for i, nid in enumerate(noise_ids):
        noise_data = bytes([i * 0x11] * 8)
        lines.append(f"({base_ts + i * 0.01:.6f}) vcan0 {nid:03X}#{noise_data.hex().upper()}")

    for chunk_idx in range(0, len(flag_bytes), 8):
        chunk = flag_bytes[chunk_idx:chunk_idx + 8].ljust(8, b"\x00")
        ts = base_ts + 0.1 + chunk_idx * 0.05
        lines.append(f"({ts:.6f}) vcan0 7FF#{chunk.hex().upper()}")
        lines.append(f"({ts + 0.01:.6f}) vcan0 050#{bytes(8).hex().upper()}")

    return "\n".join(lines)


def extract_flag_from_can(frames: list[CANFrame], target_id: int = 0x7FF) -> str:
    """Extract flag from frames with a specific CAN ID."""
    flag_data = bytearray()
    for frame in sorted(frames, key=lambda f: f.timestamp):
        if frame.can_id == target_id:
            flag_data.extend(frame.data)
    return flag_data.rstrip(b"\x00").decode("ascii", errors="ignore")


def analyze_can_traffic(frames: list[CANFrame]) -> None:
    """Analyze CAN traffic statistics."""
    id_counts: dict[int, int] = {}
    for f in frames:
        id_counts[f.can_id] = id_counts.get(f.can_id, 0) + 1

    print(f"[*] Total frames: {len(frames)}")
    print(f"[*] Unique CAN IDs: {len(id_counts)}")
    print("\n[*] Top 10 IDs by frame count:")
    for can_id, count in sorted(id_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  0x{can_id:03X}: {count} frames")


def main() -> None:
    parser = argparse.ArgumentParser(description="CAN Bus CTF Analysis Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    parse_p = sub.add_parser("parse", help="Parse and analyze CAN log")
    parse_p.add_argument("log_file", type=Path, nargs="?", help="candump log file")
    parse_p.add_argument("--id", type=lambda x: int(x, 16), default=0x7FF,
                         help="CAN ID to filter (hex, default: 0x7FF)")

    sub.add_parser("sample", help="Generate sample CAN log")
    sub.add_parser("solve", help="Demonstrate automatic flag extraction")

    args = parser.parse_args()

    if args.cmd == "sample":
        log = generate_sample_log()
        out = Path("capture.log")
        out.write_text(log)
        print(f"[+] Sample CAN log created: {out}")
        print(f"    Total {len(log.splitlines())} frames")

    elif args.cmd == "parse":
        if args.log_file and args.log_file.exists():
            log_text = args.log_file.read_text()
        else:
            print("[!] No log file. Generating sample...")
            log_text = generate_sample_log()

        frames = parse_candump_log(log_text)
        analyze_can_traffic(frames)

        target = getattr(args, "id", 0x7FF)
        filtered = [f for f in frames if f.can_id == target]
        print(f"\n[*] CAN ID 0x{target:03X}: {len(filtered)} frames")
        for f in filtered:
            print(f"  {f.timestamp:.6f}  {f.data_hex}  |{f.data_ascii}|")

    elif args.cmd == "solve":
        print("[*] Automatic CAN bus flag extraction\n")
        log_text = generate_sample_log()
        frames = parse_candump_log(log_text)
        flag = extract_flag_from_can(frames, 0x7FF)
        if flag.startswith("CTF{"):
            print(f"[+] Flag found: {flag}")
        else:
            print(f"[?] Extracted: {flag!r}")


if __name__ == "__main__":
    main()
```

## Challenge 2: UDS Protocol Simulator

```python
#!/usr/bin/env python3
"""UDS diagnostic server simulation and vulnerability practice."""

import argparse
import json
import struct
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer


SVC_DIAGNOSTIC_SESSION = 0x10
SVC_SECURITY_ACCESS    = 0x27
SVC_READ_DATA_BY_ID    = 0x22
SVC_NEGATIVE_RESPONSE  = 0x7F

SESSION_DEFAULT    = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED   = 0x03

NRC_SERVICE_NOT_SUPPORTED  = 0x11
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_INVALID_KEY            = 0x35

HIDDEN_DID = 0xF1A5
FLAG_DID_VALUE = b"CTF{ud5_s3cur1ty_4cc3ss_byp4ss}"


@dataclass
class UDSServer:
    """Vulnerable UDS ECU simulator."""
    current_session: int = SESSION_DEFAULT
    security_level: int = 0
    pending_seed: int | None = None

    DATA_BY_ID: dict[int, bytes] = field(default_factory=lambda: {
        0xF190: b"1HGBH41JXMN109186",
        0xF18C: b"ECU_SERIAL_001",
        0xF187: b"SW_VER_2.3.1",
        HIDDEN_DID: FLAG_DID_VALUE,
    })

    def process_request(self, request: bytes) -> bytes:
        if not request:
            return self._negative(0x00, NRC_SERVICE_NOT_SUPPORTED)
        service_id = request[0]
        if service_id == SVC_DIAGNOSTIC_SESSION:
            return self._handle_session_control(request)
        elif service_id == SVC_SECURITY_ACCESS:
            return self._handle_security_access(request)
        elif service_id == SVC_READ_DATA_BY_ID:
            return self._handle_read_data(request)
        return self._negative(service_id, NRC_SERVICE_NOT_SUPPORTED)

    def _handle_session_control(self, req: bytes) -> bytes:
        if len(req) < 2:
            return self._negative(SVC_DIAGNOSTIC_SESSION, NRC_CONDITIONS_NOT_CORRECT)
        self.current_session = req[1]
        return bytes([0x50, req[1], 0x00, 0x19, 0x01, 0xF4])

    def _handle_security_access(self, req: bytes) -> bytes:
        if len(req) < 2:
            return self._negative(SVC_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
        sub_func = req[1]
        if sub_func == 0x01:
            import random
            seed = random.randint(0x1000, 0xFFFF)
            self.pending_seed = seed
            return bytes([0x67, 0x01]) + struct.pack(">H", seed)
        elif sub_func == 0x02:
            if self.pending_seed is None:
                return self._negative(SVC_SECURITY_ACCESS, NRC_REQUEST_SEQUENCE_ERROR)
            if len(req) < 4:
                return self._negative(SVC_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
            submitted_key = struct.unpack(">H", req[2:4])[0]
            expected_key = self.pending_seed ^ 0xAAAA
            if submitted_key == expected_key:
                self.security_level = 1
                self.pending_seed = None
                return bytes([0x67, 0x02])
            return self._negative(SVC_SECURITY_ACCESS, NRC_INVALID_KEY)
        return self._negative(SVC_SECURITY_ACCESS, NRC_SERVICE_NOT_SUPPORTED)

    def _handle_read_data(self, req: bytes) -> bytes:
        if len(req) < 3:
            return self._negative(SVC_READ_DATA_BY_ID, NRC_CONDITIONS_NOT_CORRECT)
        did = struct.unpack(">H", req[1:3])[0]
        if did == HIDDEN_DID and self.security_level < 1:
            return self._negative(SVC_READ_DATA_BY_ID, NRC_CONDITIONS_NOT_CORRECT)
        value = self.DATA_BY_ID.get(did)
        if value is None:
            return self._negative(SVC_READ_DATA_BY_ID, 0x31)
        return bytes([0x62]) + req[1:3] + value

    def _negative(self, service: int, nrc: int) -> bytes:
        return bytes([SVC_NEGATIVE_RESPONSE, service, nrc])


def solve_uds_demo() -> None:
    """Demonstrate UDS vulnerability exploitation locally."""
    ecu = UDSServer()
    print("[*] UDS vulnerability exploit demo\n")

    req1 = bytes([SVC_DIAGNOSTIC_SESSION, SESSION_EXTENDED])
    resp1 = ecu.process_request(req1)
    print(f"1) Extended session: {resp1.hex()} ({'OK' if resp1[0] == 0x50 else 'FAIL'})")

    req2 = bytes([SVC_SECURITY_ACCESS, 0x01])
    resp2 = ecu.process_request(req2)
    seed = struct.unpack(">H", resp2[2:4])[0]
    print(f"2) Seed obtained: 0x{seed:04X}")

    key = seed ^ 0xAAAA
    req3 = bytes([SVC_SECURITY_ACCESS, 0x02]) + struct.pack(">H", key)
    resp3 = ecu.process_request(req3)
    unlocked = resp3[0] == 0x67
    print(f"3) Security unlocked: {'OK' if unlocked else 'FAIL'} (key=0x{key:04X})")

    req4 = bytes([SVC_READ_DATA_BY_ID]) + struct.pack(">H", HIDDEN_DID)
    resp4 = ecu.process_request(req4)
    if resp4[0] == 0x62:
        flag = resp4[3:].decode("ascii", errors="ignore")
        print(f"4) Flag DID(0x{HIDDEN_DID:04X}): {flag}")
    else:
        print(f"4) Failed: NRC=0x{resp4[2]:02X}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Automotive Security CTF Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    srv_p = sub.add_parser("server", help="UDS ECU simulator server")
    srv_p.add_argument("-p", "--port", type=int, default=8080)

    sub.add_parser("solve", help="Automated UDS exploit demo")
    sub.add_parser("list", help="List CTF challenges")

    submit_p = sub.add_parser("submit", help="Submit flag")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "server":
        ECU = UDSServer()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body)
                    req_bytes = bytes.fromhex(data.get("request", ""))
                    resp = ECU.process_request(req_bytes)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"response": resp.hex()}).encode())
                except Exception as e:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())

            def log_message(self, *args) -> None:
                pass

        server = HTTPServer(("0.0.0.0", args.port), Handler)
        print(f"[*] UDS ECU Simulator: http://localhost:{args.port}")
        server.serve_forever()

    elif args.cmd == "solve":
        solve_uds_demo()

    elif args.cmd == "list":
        print("Automotive Security CTF Challenges:\n")
        for cid, ch in CHALLENGES.items():
            print(f"  [{ch.points}pt] {ch.name}  (ID: {cid})")
            print(f"         Category: {ch.category}")
            print()

    elif args.cmd == "submit":
        ch = CHALLENGES[args.challenge_id]
        if verify_flag(args.flag, ch):
            print(f"[+] Correct! {ch.points} points earned")
        else:
            print("[-] Wrong answer. Hints:")
            for i, hint in enumerate(ch.hints, 1):
                print(f"    {i}. {hint}")


if __name__ == "__main__":
    main()
```

## CTF Solving Guide

```
CAN Bus Analysis Strategy
├── candump -l vcan0  →  create capture file
├── Filter by ID → detect anomalous IDs (0x7E0~0x7FF: OBD/UDS)
├── Payload entropy analysis → low entropy = repeating patterns
└── ASCII conversion → interpret each frame payload as characters

UDS Attack Flow
├── 0x10 0x03 (extended session) entry
├── 0x27 0x01 (seed request) → obtain seed value
├── Reverse key formula: try XOR, NOT, ADD simple operations
├── 0x27 0x02 + key → unlock security
└── 0x22 + DID brute-force → discover hidden data identifiers

V2X Signature Bypass Techniques
├── Replay: reuse a previously captured message as-is
├── Null signature: ECDSA r=0 or s=0
├── Public key spoofing: if server extracts public key from message
└── Timestamp manipulation: set future time to extend validity window
```

## Advanced Challenges

1. **Fuzzing**: Implement a CAN bus fuzzer with python-can + Scapy to trigger ECU crashes
2. **UDS Enumeration**: Automatically scan all service IDs (0x00~0xFF) and sub-function combinations
3. **OTA Interception**: Capture vehicle OTA update Wi-Fi traffic and extract firmware
4. **Infotainment Attack**: Media metadata buffer overflow → CAN bus access
