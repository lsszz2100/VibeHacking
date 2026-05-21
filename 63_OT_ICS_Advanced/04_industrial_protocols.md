# 산업용 프로토콜 보안

## EtherNet/IP (CIP)

### 프로토콜 개요
```
EtherNet/IP = Ethernet + CIP (Common Industrial Protocol)
포트: TCP 44818 (명시적), UDP 2222 (암묵적)

CIP 서비스 코드
0x01 — Get_Attributes_All
0x0E — Get_Attribute_Single
0x10 — Set_Attribute_Single
0x4B — Execute_Program  (PLC 실행)
0x4C — Get_Attribute_List
0x52 — Read_Tag
0x53 — Write_Tag
0x54 — Read_Tag_Fragmented
0x55 — Write_Tag_Fragmented

클래스 코드
0x01 — Identity (장치 정보)
0x64 — Tag (Logix5000 태그)
```

### EtherNet/IP 분석
```python
#!/usr/bin/env python3
"""EtherNet/IP / CIP 프로토콜 분석."""

import socket
import struct
import argparse
from dataclasses import dataclass


EIP_REGISTER_SESSION = 0x0065
EIP_LIST_IDENTITY = 0x0063
EIP_SEND_RR_DATA = 0x0065


@dataclass
class EIPSession:
    host: str
    port: int
    session_handle: int = 0


def list_identity(host: str, port: int = 44818) -> dict | None:
    """장치 정보 조회 (List Identity)."""
    request = struct.pack("<HHIIQII",
        EIP_LIST_IDENTITY,  # Command
        0x0000,             # Length
        0x00000000,         # Session Handle
        0x00000000,         # Status
        0x0000000000000000, # Sender Context
        0x00000000,         # Options
        0x00000000,         # Interface Handle
    )
    # 실제로는 24바이트 헤더
    request = struct.pack("<HHI8sII",
        0x0063, 0, 0,
        b'\x00' * 8,
        0, 0,
    )
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(request)
            resp = s.recv(512)
            if len(resp) < 24:
                return None
            cmd, length, sess, status = struct.unpack("<HHII", resp[:12])
            if cmd == 0x0063 and length > 0:
                # 응답 파싱 (간략화)
                return {
                    "command": f"0x{cmd:04X}",
                    "length": length,
                    "raw": resp[24:].hex(),
                }
    except Exception:
        pass
    return None


def register_session(host: str, port: int = 44818) -> int | None:
    """EIP 세션 등록."""
    request = struct.pack("<HHI8sIIHH",
        0x0065,     # Register Session
        4,          # Length
        0,          # Session Handle (초기 0)
        b'\x00' * 8,  # Sender Context
        0, 0,       # Options, Interface Handle
        1,          # Protocol Version
        0,          # Option Flags
    )
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(request)
            resp = s.recv(256)
            if len(resp) >= 8:
                session_handle = struct.unpack("<I", resp[4:8])[0]
                return session_handle
    except Exception:
        pass
    return None


def read_tag(
    host: str,
    port: int,
    session: int,
    tag_name: str,
    count: int = 1,
) -> bytes | None:
    """Logix5000 태그 읽기 (CIP Read Tag Service)."""
    # 태그 이름 인코딩
    name_encoded = tag_name.encode("ascii")
    request_path = bytes([
        0x91,                    # ANSI Extended Symbol
        len(name_encoded),       # 심볼 길이
    ]) + name_encoded
    if len(request_path) % 2:
        request_path += b'\x00'  # 패딩

    cip_req = bytes([
        0x4C,                    # Read Tag Service
        len(request_path) // 2, # 경로 크기 (워드)
    ]) + request_path + struct.pack("<H", count)

    # CIP 캡슐화
    encap = struct.pack("<HHIIII",
        0x0070,     # Interface Handle (CIP)
        0x000A,     # Timeout
        0x0002,     # Item Count
        0x0000,     # Type: Null Address
        0x0000,     # Length: 0
        0x00B2,     # Type: Unconnected Data
    ) + struct.pack("<H", len(cip_req)) + cip_req

    eip_header = struct.pack("<HHI8sII",
        0x006F,         # Send RR Data
        len(encap),
        session,
        b'\x00' * 8,
        0, 0,
    )

    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(eip_header + encap)
            resp = s.recv(512)
            # 응답 파싱 (Service + 데이터)
            if len(resp) > 40 and resp[40] == 0xCC:  # Read Tag Response
                data_type = struct.unpack("<H", resp[44:46])[0]
                data = resp[46:]
                return data
    except Exception:
        pass
    return None


def enumerate_tags(host: str, port: int = 44818) -> list[str]:
    """Logix5000 태그 열거 (Get Instance List)."""
    # 실제 구현은 CIP Class 0x6B (Symbol) 순회
    return []  # 간략화


def main() -> None:
    parser = argparse.ArgumentParser(description="EtherNet/IP 분석 도구")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=44818)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("identity", help="장치 정보 조회")
    sub.add_parser("session", help="세션 등록")
    
    rt = sub.add_parser("read-tag", help="태그 읽기")
    rt.add_argument("tag", help="태그 이름")
    rt.add_argument("-n", "--count", type=int, default=1)

    args = parser.parse_args()

    if args.cmd == "identity":
        info = list_identity(args.host, args.port)
        if info:
            print(f"[+] 장치 정보: {info}")
        else:
            print("[-] 응답 없음")

    elif args.cmd == "session":
        sess = register_session(args.host, args.port)
        if sess:
            print(f"[+] 세션: 0x{sess:08X}")
        else:
            print("[-] 세션 등록 실패")

    elif args.cmd == "read-tag":
        sess = register_session(args.host, args.port)
        if not sess:
            print("[-] 세션 실패")
            return
        data = read_tag(args.host, args.port, sess, args.tag, args.count)
        if data:
            print(f"[+] 태그 '{args.tag}': {data.hex()} | {data}")
        else:
            print(f"[-] 읽기 실패: {args.tag}")


if __name__ == "__main__":
    main()
```

## OPC-UA 보안

```python
#!/usr/bin/env python3
"""OPC-UA 서버 탐지 및 보안 점검."""

import socket
import struct
import argparse


OPC_UA_PORT = 4840
OPC_UA_MAGIC = b"HELF"  # Hello 메시지 매직


def send_opcua_hello(host: str, port: int = 4840) -> bytes | None:
    """OPC-UA Hello 메시지 전송."""
    # OPC-UA Hello 메시지
    endpoint_url = b"opc.tcp://" + host.encode() + f":{port}".encode()
    hello = struct.pack("<4sBIIIII",
        b"HEL",       # 메시지 유형
        b"F",         # 최종 청크
        28 + len(endpoint_url),  # 메시지 크기
        0,            # 프로토콜 버전
        65536,        # Receive Buffer Size
        65536,        # Send Buffer Size
        4096,         # Max Message Size
        512,          # Max Chunk Count
    ) + struct.pack("<I", len(endpoint_url)) + endpoint_url

    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.send(hello)
            resp = s.recv(512)
            return resp
    except Exception:
        pass
    return None


def check_opcua_security(host: str, port: int = 4840) -> dict:
    """OPC-UA 보안 설정 점검."""
    results: dict = {
        "host": host,
        "port": port,
        "responds": False,
        "security_mode": "Unknown",
        "anonymous_allowed": False,
    }

    resp = send_opcua_hello(host, port)
    if resp and resp[:3] == b"ACK":
        results["responds"] = True
        print(f"  [+] OPC-UA 서버 응답: {resp[:20].hex()}")

    # GetEndpoints 요청으로 보안 정책 열거
    # (실제 구현은 asyncua 라이브러리 사용 권장)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC-UA 보안 점검")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=4840)
    args = parser.parse_args()

    print(f"[*] OPC-UA 점검: {args.host}:{args.port}")
    results = check_opcua_security(args.host, args.port)

    if results["responds"]:
        print(f"[+] OPC-UA 서버 활성")
        if results["anonymous_allowed"]:
            print(f"[!] 익명 접근 허용 — 취약점!")
    else:
        print(f"[-] 응답 없음")

    print(f"\n[!] 보안 권고:")
    print(f"  - SignAndEncrypt 모드 사용 (None/Sign 금지)")
    print(f"  - 익명 접근 비활성화")
    print(f"  - 사용자 인증 강제화")
    print(f"  - OPC-UA 방화벽 정책 적용")


if __name__ == "__main__":
    main()
```

## BACnet 공격 (빌딩 자동화)

```bash
# BACnet 스캐닝 (포트 47808 UDP)
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Who-Is 브로드캐스트 (모든 BACnet 장치 탐지)
# BACnet/IP Who-Is 패킷
echo -n "810b000c0120ffff00ffc40b010000" | xxd -r -p | \
    nc -u -w1 255.255.255.255 47808

# BACnet 취약점
# - 인증 없음 (BACnet 원래 설계)
# - Read-Property: 임의 객체 읽기
# - Write-Property: 설정 변경 (온도, 조명, 접근 제어)
# - BBMD (BACnet Broadcast Management Device) 남용
```

## 프로토콜 변환기 공격

```
OT DMZ의 프로토콜 변환기 취약점
├── Modbus → OPC-UA 게이트웨이
├── DNP3 → IEC 60870-5-104 변환
└── 시리얼 → Ethernet 변환기

공격 시나리오
1. 취약한 게이트웨이 웹 인터페이스 익스플로잇
2. 게이트웨이 펌웨어 조작
3. 프로토콜 변환 과정에서 명령 인젝션
```

다음 파일에서 OT 방어 및 모니터링을 다룬다.
