> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 산업용 프로토콜 보안

## 0. 초보자를 위한 개념 이해

### 산업용 프로토콜이란?

공장, 발전소, 정수처리장 같은 산업 시설에서는 일반 IT 네트워크와 다른 특수 프로토콜을 사용합니다.

```
일반 IT 프로토콜:
  HTTP, HTTPS, SSH, TCP/IP
  설계 목표: 유연성, 호환성
  보안 고려: 있음 (TLS 등)

산업용 OT 프로토콜:
  Modbus, DNP3, EtherNet/IP, S7comm, BACnet
  설계 목표: 실시간성, 신뢰성, 결정론적 동작
  보안 고려: 거의 없음 (1970~90년대 설계)
```

**비유:** 
- HTTP = 일반 도로 (다양한 차량)
- Modbus = 철도 (정해진 규격, 정해진 선로)

### 왜 산업용 프로토콜이 위험한가?

```
1. 인증 없음
   Modbus: 누구든 명령을 보내면 PLC가 실행
   DNP3: 평문 통신, 인증 옵션 있지만 미사용 많음

2. 암호화 없음
   모든 명령이 평문으로 전송
   → 스니핑으로 내용 확인 가능

3. 검증 없음
   "모터를 최대 속도로 돌려라" 명령을 받으면
   → 보내는 쪽이 정당한지 확인 안 함

4. 구형 시스템
   20~30년 된 장비가 현역
   → 패치, 업그레이드 어려움
   → 취약점이 알려져도 수정 불가
```

### 주요 산업용 프로토콜 비교

| 프로토콜 | 개발 연도 | 주요 사용처 | 포트 | 보안 |
|----------|-----------|------------|------|------|
| Modbus TCP | 1979 | 범용 PLC/센서 | 502/TCP | 없음 |
| DNP3 | 1993 | 전력/수자원 SCADA | 20000/TCP | 선택적 인증 |
| EtherNet/IP | 2001 | Allen-Bradley PLC | 44818/TCP | 없음 |
| S7comm | 1994 | Siemens PLC | 102/TCP | 없음 |
| BACnet | 1995 | 빌딩 자동화 | 47808/UDP | 선택적 |
| IEC 61850 | 2003 | 변전소 자동화 | 102/TCP | 있음 |

### 실제 공격 사례

```
2010년 Stuxnet:
  이란 우라늄 농축 시설 공격
  Siemens S7 PLC에 악성코드 심어
  원심분리기를 과속/과부하로 물리적 파괴
  → 산업용 프로토콜 공격의 첫 사례

2021년 Oldsmar 수자원 처리장:
  플로리다 정수처리장 HMI(Human Machine Interface) 해킹
  염소(수산화나트륨) 농도를 111ppm → 11,100ppm으로 조작 시도
  → 직원이 원격으로 변경되는 것을 목격, 즉시 차단

2015/2016년 우크라이나 전력망:
  BlackEnergy/Industroyer 악성코드
  변전소 차단기를 원격 조작 → 정전 발생
```

---

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


<!-- detect-validate-63 -->
## 산업 프로토콜 검증 — 무인증 프로토콜에 통제가 실제로 덧대졌는가

산업 프로토콜 보안은 *Modbus/DNP3가 무인증임을 안다*가 아니라 **본질적으로 무인증인 프로토콜에 세그멘테이션·허용목록·보안 게이트웨이(또는 Secure 변형)가 실제 적용돼 비인가 쓰기 명령이 차단되는가**로 판정한다. 검증은 **소유 OT 랩**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 쓰기 통제 | 누구나 write | 쓰기 기능코드 점검 | 쓰기 출처 제한 |
| 세그멘테이션 | 평면 접근 | 마스터 화이트리스트 | 인가 마스터만 |
| 보안 변형 | 평문만 | DNP3-SA/암호화 확인 | 인증·무결성 적용 |
| 명령 모니터 | 무탐지 | 비정상 기능코드 모니터 | 이상명령 탐지 |

### 방어 검증 (직접 확인)

```bash
# 1) Modbus 등에서 쓰기 기능코드(05/06/0F/10)가 인가 마스터 외에서도 먹는지 — 소유 랩에서만
nmap -Pn -p 502 --script modbus-discover lab-plc 2>/dev/null | head || echo "probe Modbus only on owned lab device"
# 2) 인가된 마스터 IP만 502/20000으로 접근 가능한지(세그멘테이션 확인)
iptables -S 2>/dev/null | grep -E '502|20000' | head || echo "verify allowlist for industrial protocol ports"
```

> 검증은 반드시 **소유 OT 랩**에서만 한다. 가동 플랜트에 쓰기 명령 금지. "무인증임을 안다"와 "통제가 실제 덧대졌다"는 다르다 — 쓰기 통제·세그멘테이션으로 직접 확인한다([[02_Network_Hacking]], [[37_ICS_SCADA]]).

**최신 기법·통제 (2025–2026):**
- Modbus/DNP3/S7/OPC-UA는 인증 편차 — OPC-UA 보안모드·게이트웨이 인증으로 방어. 검증: 비인가 명령이 거부되는지 재현(소유 랩)([[37_ICS_SCADA]])
- 비침습 이상탐지 — 강제되는지 확인

---

<a name="english"></a>

# Industrial Protocol Security

## EtherNet/IP (CIP)

### Protocol Overview
```
EtherNet/IP = Ethernet + CIP (Common Industrial Protocol)
Ports: TCP 44818 (explicit), UDP 2222 (implicit)

CIP Service Codes
0x01 — Get_Attributes_All
0x0E — Get_Attribute_Single
0x10 — Set_Attribute_Single
0x4B — Execute_Program  (PLC execution)
0x4C — Get_Attribute_List
0x52 — Read_Tag
0x53 — Write_Tag
0x54 — Read_Tag_Fragmented
0x55 — Write_Tag_Fragmented

Class Codes
0x01 — Identity (device information)
0x64 — Tag (Logix5000 tags)
```

### EtherNet/IP Analysis
```python
#!/usr/bin/env python3
"""EtherNet/IP / CIP protocol analysis."""

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
    """Query device information (List Identity)."""
    request = struct.pack("<HHIIQII",
        EIP_LIST_IDENTITY,  # Command
        0x0000,             # Length
        0x00000000,         # Session Handle
        0x00000000,         # Status
        0x0000000000000000, # Sender Context
        0x00000000,         # Options
        0x00000000,         # Interface Handle
    )
    # In practice, this is a 24-byte header
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
                # Parse response (simplified)
                return {
                    "command": f"0x{cmd:04X}",
                    "length": length,
                    "raw": resp[24:].hex(),
                }
    except Exception:
        pass
    return None


def register_session(host: str, port: int = 44818) -> int | None:
    """Register an EIP session."""
    request = struct.pack("<HHI8sIIHH",
        0x0065,     # Register Session
        4,          # Length
        0,          # Session Handle (initially 0)
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
    """Read a Logix5000 tag (CIP Read Tag Service)."""
    # Encode tag name
    name_encoded = tag_name.encode("ascii")
    request_path = bytes([
        0x91,                    # ANSI Extended Symbol
        len(name_encoded),       # Symbol length
    ]) + name_encoded
    if len(request_path) % 2:
        request_path += b'\x00'  # Padding

    cip_req = bytes([
        0x4C,                    # Read Tag Service
        len(request_path) // 2, # Path size (words)
    ]) + request_path + struct.pack("<H", count)

    # CIP encapsulation
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
            # Parse response (Service + data)
            if len(resp) > 40 and resp[40] == 0xCC:  # Read Tag Response
                data_type = struct.unpack("<H", resp[44:46])[0]
                data = resp[46:]
                return data
    except Exception:
        pass
    return None


def enumerate_tags(host: str, port: int = 44818) -> list[str]:
    """Enumerate Logix5000 tags (Get Instance List)."""
    # Full implementation iterates CIP Class 0x6B (Symbol)
    return []  # Simplified


def main() -> None:
    parser = argparse.ArgumentParser(description="EtherNet/IP analysis tool")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=44818)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("identity", help="Query device information")
    sub.add_parser("session", help="Register session")
    
    rt = sub.add_parser("read-tag", help="Read tag")
    rt.add_argument("tag", help="Tag name")
    rt.add_argument("-n", "--count", type=int, default=1)

    args = parser.parse_args()

    if args.cmd == "identity":
        info = list_identity(args.host, args.port)
        if info:
            print(f"[+] Device info: {info}")
        else:
            print("[-] No response")

    elif args.cmd == "session":
        sess = register_session(args.host, args.port)
        if sess:
            print(f"[+] Session: 0x{sess:08X}")
        else:
            print("[-] Session registration failed")

    elif args.cmd == "read-tag":
        sess = register_session(args.host, args.port)
        if not sess:
            print("[-] Session failed")
            return
        data = read_tag(args.host, args.port, sess, args.tag, args.count)
        if data:
            print(f"[+] Tag '{args.tag}': {data.hex()} | {data}")
        else:
            print(f"[-] Read failed: {args.tag}")


if __name__ == "__main__":
    main()
```

## OPC-UA Security

```python
#!/usr/bin/env python3
"""OPC-UA server detection and security assessment."""

import socket
import struct
import argparse


OPC_UA_PORT = 4840
OPC_UA_MAGIC = b"HELF"  # Hello message magic


def send_opcua_hello(host: str, port: int = 4840) -> bytes | None:
    """Send an OPC-UA Hello message."""
    # OPC-UA Hello message
    endpoint_url = b"opc.tcp://" + host.encode() + f":{port}".encode()
    hello = struct.pack("<4sBIIIII",
        b"HEL",       # Message type
        b"F",         # Final chunk
        28 + len(endpoint_url),  # Message size
        0,            # Protocol version
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
    """Check OPC-UA security configuration."""
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
        print(f"  [+] OPC-UA server response: {resp[:20].hex()}")

    # Enumerate security policies via GetEndpoints request
    # (for full implementation, use the asyncua library)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC-UA security assessment")
    parser.add_argument("host")
    parser.add_argument("-p", "--port", type=int, default=4840)
    args = parser.parse_args()

    print(f"[*] OPC-UA check: {args.host}:{args.port}")
    results = check_opcua_security(args.host, args.port)

    if results["responds"]:
        print(f"[+] OPC-UA server active")
        if results["anonymous_allowed"]:
            print(f"[!] Anonymous access allowed — vulnerability!")
    else:
        print(f"[-] No response")

    print(f"\n[!] Security recommendations:")
    print(f"  - Use SignAndEncrypt mode (None/Sign prohibited)")
    print(f"  - Disable anonymous access")
    print(f"  - Enforce user authentication")
    print(f"  - Apply OPC-UA firewall policy")


if __name__ == "__main__":
    main()
```

## BACnet Attacks (Building Automation)

```bash
# BACnet scanning (UDP port 47808)
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Who-Is broadcast (discover all BACnet devices)
# BACnet/IP Who-Is packet
echo -n "810b000c0120ffff00ffc40b010000" | xxd -r -p | \
    nc -u -w1 255.255.255.255 47808

# BACnet vulnerabilities
# - No authentication (original BACnet design)
# - Read-Property: read arbitrary objects
# - Write-Property: change settings (temperature, lighting, access control)
# - BBMD (BACnet Broadcast Management Device) abuse
```

## Protocol Converter Attacks

```
Protocol converter vulnerabilities in the OT DMZ
├── Modbus → OPC-UA gateway
├── DNP3 → IEC 60870-5-104 conversion
└── Serial → Ethernet converters

Attack scenarios
1. Exploit vulnerable gateway web interface
2. Manipulate gateway firmware
3. Command injection during protocol conversion
```

The next file covers OT defense and monitoring.

<!-- detect-validate-63 -->
## Industrial-Protocol Validation — Are Controls Actually Wrapped Around Unauthenticated Protocols?

Industrial-protocol security is judged not by *knowing Modbus/DNP3 are unauthenticated* but by **whether segmentation, allowlists, and security gateways (or Secure variants) are actually applied around inherently unauthenticated protocols so unauthorized write commands are blocked**. Validate only on **owned OT labs**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Write control | Anyone can write | Check write function codes | Write source restricted |
| Segmentation | Flat access | Master allowlist | Authorized master only |
| Secure variant | Plaintext only | Check DNP3-SA/encryption | Auth/integrity applied |
| Command monitor | Undetected | Monitor abnormal func codes | Anomalous command detected |

### Defense validation (verify directly)

```bash
# 1) Whether Modbus write function codes (05/06/0F/10) work from non-authorized masters — owned lab only
nmap -Pn -p 502 --script modbus-discover lab-plc 2>/dev/null | head || echo "probe Modbus only on owned lab device"
# 2) Whether only authorized master IPs can reach 502/20000 (segmentation check)
iptables -S 2>/dev/null | grep -E '502|20000' | head || echo "verify allowlist for industrial protocol ports"
```

> Validate only on **owned OT labs** — never issue write commands to a running plant. "Knowing it's unauthenticated" differs from "controls are actually wrapped around it" — confirm directly via write control and segmentation ([[02_Network_Hacking]], [[37_ICS_SCADA]]).
