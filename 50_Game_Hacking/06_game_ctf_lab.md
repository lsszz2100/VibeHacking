> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 게임 해킹 CTF 실습 랩

## 실습 환경 준비

```bash
# Python 환경
pip install struct ctypes psutil scapy

# 실습 디렉터리
mkdir -p ~/ctf_game/{memory,protocol,anticheat}

# 참고: 실제 게임 해킹은 법적 문제가 될 수 있음
# 이 실습은 CTF 시뮬레이션 환경에서만 진행
```

---

## 실습 1: 메모리 스캔 — 게임 내 값 탐지 (Cheat Engine 개념)

### 목표
시뮬레이션된 게임 프로세스 메모리에서 체력(HP) 값을 찾고 수정하여 플래그를 획득하라.

**플래그 형식**: `CTF{MEM_SCAN_OFFSET_<offset>_VALUE_<original_hp>}`

### 시나리오

단순한 게임 시뮬레이터 프로세스가 실행 중이다.  
메모리 스캔으로 HP 값(정수, 현재 값 알고 있음)을 찾아 오프셋을 확인하라.

**Cheat Engine 개념 적용:**
1. 현재 HP 값(예: 100)으로 First Scan
2. HP가 변경된 후 새 값으로 Next Scan
3. 범위를 좁혀 정확한 주소 찾기
4. 해당 주소의 값을 수정

### 힌트
- 게임 메모리는 연속된 구조체로 저장되는 경우 많음
- `ctypes`를 이용한 메모리 읽기/쓰기 시뮬레이션
- 더블 포인터: 기본 주소 + 오프셋 체인
- 4바이트 정수(INT32)가 가장 일반적

### 풀이

```python
#!/usr/bin/env python3
"""
게임 해킹 CTF — 메모리 스캔 시뮬레이터
"""

import argparse
import ctypes
import struct
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class GamePlayerData:
    """게임 플레이어 데이터 구조 시뮬레이션."""
    player_id: int       # offset: 0x00
    hp: int              # offset: 0x04
    max_hp: int          # offset: 0x08
    mp: int              # offset: 0x0C
    gold: int            # offset: 0x10
    level: int           # offset: 0x14
    score: int           # offset: 0x18
    name_ptr: int        # offset: 0x1C (포인터)

    def to_bytes(self) -> bytes:
        """구조체를 바이트로 직렬화."""
        return struct.pack(
            "<iiiiiiiI",
            self.player_id,
            self.hp,
            self.max_hp,
            self.mp,
            self.gold,
            self.level,
            self.score,
            self.name_ptr,
        )


class SimulatedGameMemory:
    """게임 메모리 공간 시뮬레이터."""

    BASE_ADDRESS = 0x00400000
    PAGE_SIZE = 4096

    def __init__(self) -> None:
        # 4KB 메모리 페이지 시뮬레이션
        self._memory = bytearray(self.PAGE_SIZE)
        self._player_offset = 0x0100  # 플레이어 데이터 위치

        # 초기 플레이어 데이터
        self.player = GamePlayerData(
            player_id=1001,
            hp=75,           # 현재 HP
            max_hp=100,
            mp=50,
            gold=9999,
            level=15,
            score=123456,
            name_ptr=self.BASE_ADDRESS + 0x0200,
        )
        self._write_player()

    def _write_player(self) -> None:
        data = self.player.to_bytes()
        offset = self._player_offset
        self._memory[offset:offset + len(data)] = data

    def read_int32(self, virtual_addr: int) -> int:
        offset = virtual_addr - self.BASE_ADDRESS
        return struct.unpack_from("<i", self._memory, offset)[0]

    def write_int32(self, virtual_addr: int, value: int) -> None:
        offset = virtual_addr - self.BASE_ADDRESS
        struct.pack_into("<i", self._memory, offset, value)

    def scan_value(self, target: int, data_type: str = "int32") -> list[int]:
        """메모리에서 특정 값을 가진 주소를 모두 찾는다."""
        results: list[int] = []
        step = 4 if data_type == "int32" else 1
        for offset in range(0, len(self._memory) - 4, step):
            val = struct.unpack_from("<i", self._memory, offset)[0]
            if val == target:
                results.append(self.BASE_ADDRESS + offset)
        return results

    def get_player_addr(self, field: str) -> int:
        field_offsets = {
            "player_id": 0x00, "hp": 0x04, "max_hp": 0x08,
            "mp": 0x0C, "gold": 0x10, "level": 0x14, "score": 0x18,
        }
        return self.BASE_ADDRESS + self._player_offset + field_offsets[field]


def simulate_memory_scan(initial_hp: int = 75, damage: int = 25) -> None:
    print("=" * 65)
    print("  게임 해킹 CTF: 메모리 스캔 시뮬레이션")
    print("=" * 65)

    mem = SimulatedGameMemory()
    original_hp = mem.player.hp

    print(f"\n[*] 게임 시작: HP={mem.player.hp}, Gold={mem.player.gold}")
    print(f"[*] 현재 HP({initial_hp})로 메모리 스캔...\n")

    # 1차 스캔
    candidates = mem.scan_value(initial_hp)
    print(f"[*] 1차 스캔 결과: {len(candidates)}개 주소 후보")
    for addr in candidates[:5]:
        print(f"    0x{addr:08X}: {mem.read_int32(addr)}")

    # 데미지 적용 후 HP 변경
    mem.player.hp -= damage
    mem.write_int32(mem.get_player_addr("hp"), mem.player.hp)
    new_hp = mem.player.hp

    print(f"\n[*] 데미지 {damage} 적용 → HP: {initial_hp} → {new_hp}")
    print(f"[*] 새 값({new_hp})으로 2차 스캔...\n")

    # 2차 스캔 (범위 좁히기)
    refined = [addr for addr in candidates if mem.read_int32(addr) == new_hp]
    print(f"[*] 2차 스캔 결과: {len(refined)}개 주소")

    if refined:
        hp_addr = refined[0]
        hp_offset = hp_addr - SimulatedGameMemory.BASE_ADDRESS
        print(f"\n[+] HP 주소 확정: 0x{hp_addr:08X} (오프셋: 0x{hp_offset:04X})")

        # 무적 치트: HP를 9999로 수정
        mem.write_int32(hp_addr, 9999)
        print(f"[+] HP 수정: {new_hp} → {mem.read_int32(hp_addr)}")

        flag = f"CTF{{MEM_SCAN_OFFSET_0x{hp_offset:04X}_VALUE_{original_hp}}}"
        print(f"\n[+] 플래그: {flag}")
    else:
        print("[-] HP 주소를 특정하지 못했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(description="게임 해킹 CTF — 메모리 스캔")
    parser.add_argument("--hp",     type=int, default=75,  help="초기 HP")
    parser.add_argument("--damage", type=int, default=25,  help="입힐 데미지")
    args = parser.parse_args()
    simulate_memory_scan(args.hp, args.damage)


if __name__ == "__main__":
    main()
```

---

## 실습 2: 게임 프로토콜 분석 및 패킷 조작

### 목표
게임 클라이언트-서버 통신 패킷을 분석하여 아이템 구매 요청을 변조하고 플래그를 획득하라.

**플래그 형식**: `CTF{PACKET_TAMPER_ITEM_<item_id>_PRICE_<original>_MODIFIED_<new>}`

### 시나리오

온라인 게임의 상점 구매 요청 패킷이 캡처되었다.  
서버 측 검증이 미흡하여 아이템 가격을 조작할 수 있다.

**게임 패킷 구조 (바이너리):**
```
[2바이트] Opcode
[2바이트] Payload Length
[4바이트] Player ID
[4바이트] Item ID
[4바이트] Price (클라이언트 전송)
[4바이트] Quantity
[4바이트] Checksum (XOR)
```

### 힌트
- Checksum = 모든 필드 XOR (패킷 무결성 검증)
- 서버가 클라이언트의 Price 필드를 신뢰 → 취약점
- Price = 1로 변조하면 거의 무료로 구매
- Opcode 0x0101 = 상점 구매 요청

### 풀이

```python
#!/usr/bin/env python3
"""
게임 해킹 CTF — 패킷 분석 및 변조 시뮬레이터
"""

import argparse
import struct
from dataclasses import dataclass
from functools import reduce


OPCODE_SHOP_BUY   = 0x0101
OPCODE_SHOP_REPLY = 0x0102


@dataclass
class ShopPacket:
    opcode: int
    player_id: int
    item_id: int
    price: int
    quantity: int

    def to_bytes(self) -> bytes:
        payload = struct.pack(
            ">IIIII",
            self.player_id,
            self.item_id,
            self.price,
            self.quantity,
            0,   # checksum placeholder
        )
        # Checksum: 모든 4바이트 워드 XOR
        words = struct.unpack(">IIII", payload[:16])
        checksum = reduce(lambda a, b: a ^ b, words)
        payload = payload[:16] + struct.pack(">I", checksum)

        length = len(payload)
        header = struct.pack(">HH", self.opcode, length)
        return header + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "ShopPacket":
        opcode, length = struct.unpack_from(">HH", data, 0)
        player_id, item_id, price, quantity, checksum = struct.unpack_from(">IIIII", data, 4)
        return cls(opcode, player_id, item_id, price, quantity)

    def verify_checksum(self, data: bytes) -> bool:
        words = struct.unpack_from(">IIII", data, 4)
        stored = struct.unpack_from(">I", data, 20)[0]
        calculated = reduce(lambda a, b: a ^ b, words)
        return calculated == stored


SHOP_ITEMS: dict[int, tuple[str, int]] = {
    1001: ("Legendary Sword",   50000),
    1002: ("Dragon Shield",     30000),
    1003: ("Health Potion",     100),
    1004: ("Rare Artifact",     999999),
}


def simulate_packet_attack(item_id: int = 1004) -> None:
    print("=" * 65)
    print("  게임 해킹 CTF: 패킷 분석 및 가격 변조")
    print("=" * 65)

    item_name, original_price = SHOP_ITEMS.get(item_id, ("Unknown", 9999))
    player_id = 12345

    # 정상 패킷 생성
    normal_packet = ShopPacket(
        opcode=OPCODE_SHOP_BUY,
        player_id=player_id,
        item_id=item_id,
        price=original_price,
        quantity=1,
    )
    normal_bytes = normal_packet.to_bytes()

    print(f"\n[정상 패킷]")
    print(f"  아이템:   {item_name} (ID: {item_id})")
    print(f"  가격:     {original_price:,} Gold")
    print(f"  원시 바이트: {normal_bytes.hex()}\n")

    # 패킷 변조: 가격을 1 Gold로 수정
    modified_packet = ShopPacket(
        opcode=OPCODE_SHOP_BUY,
        player_id=player_id,
        item_id=item_id,
        price=1,
        quantity=1,
    )
    modified_bytes = modified_packet.to_bytes()

    print(f"[변조 패킷]")
    print(f"  수정된 가격: 1 Gold (원본: {original_price:,})")
    print(f"  변조 바이트: {modified_bytes.hex()}\n")

    # 서버 검증 시뮬레이션 (취약한 서버: 클라이언트 가격 신뢰)
    def vulnerable_server_process(packet_bytes: bytes) -> str:
        pkt = ShopPacket.from_bytes(packet_bytes)
        # 취약점: 서버가 클라이언트의 price를 그대로 사용
        if pkt.price <= 0:
            return "ERROR: 가격이 유효하지 않음"
        item = SHOP_ITEMS.get(pkt.item_id)
        if not item:
            return "ERROR: 아이템 없음"
        return f"SUCCESS: {item[0]} 구매 완료 (지불: {pkt.price} Gold)"

    result = vulnerable_server_process(modified_bytes)
    print(f"[서버 응답]: {result}")

    flag = f"CTF{{PACKET_TAMPER_ITEM_{item_id}_PRICE_{original_price}_MODIFIED_1}}"
    print(f"\n[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="게임 해킹 CTF — 패킷 변조")
    parser.add_argument("--item", type=int, default=1004, help="아이템 ID")
    args = parser.parse_args()
    simulate_packet_attack(args.item)


if __name__ == "__main__":
    main()
```

---

## 실습 3: 안티치트 우회 개념 분석

### 목표
안티치트 시스템의 탐지 기법을 분석하고 각 우회 가능성을 평가하여 플래그를 완성하라.

**플래그 형식**: `CTF{ANTICHEAT_BYPASS_<method>_DIFFICULTY_<level>}`

### 시나리오

게임의 안티치트 시스템 분석 보고서를 완성하라.  
각 탐지 기법과 우회 방법의 실현 가능성을 평가하라.

### 풀이

```python
#!/usr/bin/env python3
"""
게임 해킹 CTF — 안티치트 시스템 분석
"""

import argparse
from dataclasses import dataclass


@dataclass
class AntiCheatMethod:
    name: str
    detection_type: str
    description: str
    bypass_method: str
    bypass_difficulty: str   # EASY / MEDIUM / HARD / EXPERT
    bypass_score: int


ANTICHEAT_ANALYSIS: list[AntiCheatMethod] = [
    AntiCheatMethod(
        "메모리 시그니처 스캔",
        "SIGNATURE",
        "알려진 치트 프로그램의 바이너리 패턴을 메모리에서 탐지",
        "코드 다형성(폴리모픽), 실시간 XOR 인코딩으로 시그니처 변경",
        "MEDIUM",
        50,
    ),
    AntiCheatMethod(
        "프로세스 목록 검사",
        "PROCESS",
        "Cheat Engine, ArtMoney 등 알려진 도구 프로세스명 탐지",
        "프로세스 이름 변경, 드라이버 레벨 숨김(rootkit 기법)",
        "MEDIUM",
        45,
    ),
    AntiCheatMethod(
        "HWID 해시 블랙리스트",
        "HARDWARE",
        "하드웨어 ID 해시로 이전 치터 장치 차단",
        "HWID 스푸핑(가상 디스크/NIC MAC 변경), 신규 장치 등록",
        "EASY",
        30,
    ),
    AntiCheatMethod(
        "커널 레벨 모니터링",
        "KERNEL",
        "링0 드라이버로 메모리 읽기/쓰기 API 후킹",
        "하이퍼바이저 기반 치트(VT-x), 커널 드라이버 직접 작성",
        "EXPERT",
        95,
    ),
    AntiCheatMethod(
        "스크린샷/화면 분석",
        "VISUAL",
        "주기적 스크린샷으로 오버레이 탐지",
        "DirectX/OpenGL 버퍼 직접 접근(스크린샷 우회), 하드웨어 오버레이",
        "HARD",
        75,
    ),
    AntiCheatMethod(
        "행위 분석 (통계)",
        "BEHAVIORAL",
        "비정상적인 헤드샷률, 이동 속도, 반응 시간 통계 분석",
        "치트를 인간적 수준으로 제한 (soft aimbot), 분석 우회 불가 시 수동 리뷰",
        "HARD",
        80,
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="게임 해킹 CTF — 안티치트 분석")
    parser.parse_args()

    print("=" * 75)
    print("  게임 해킹 CTF: 안티치트 시스템 분석 보고서")
    print("=" * 75)

    sorted_methods = sorted(ANTICHEAT_ANALYSIS, key=lambda m: m.bypass_score)

    print(f"\n{'탐지 기법':<22} {'유형':<12} {'우회 난이도':<10} {'우회 점수':>8}")
    print("-" * 60)

    for m in sorted_methods:
        print(f"{m.name:<22} {m.detection_type:<12} {m.bypass_difficulty:<10} {m.bypass_score:>8}")

    # 가장 우회하기 쉬운 방법
    easiest = min(ANTICHEAT_ANALYSIS, key=lambda m: m.bypass_score)
    print(f"\n[+] 가장 쉬운 우회 대상: {easiest.name}")
    print(f"    우회 방법: {easiest.bypass_method}")
    print(f"    우회 난이도: {easiest.bypass_difficulty} (점수: {easiest.bypass_score})")

    method_key = easiest.detection_type
    flag = f"CTF{{ANTICHEAT_BYPASS_{method_key}_DIFFICULTY_{easiest.bypass_difficulty}}}"
    print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Game Hacking CTF Practice Lab

## Lab Environment Setup

```bash
pip install struct ctypes psutil scapy
mkdir -p ~/ctf_game/{memory,protocol,anticheat}
# Note: Real-world game hacking may violate ToS and laws.
# This lab is strictly for CTF simulation environments.
```

---

## Challenge 1: Memory Scanning — Finding Game Values (Cheat Engine Concepts)

### Objective
Locate the HP value in simulated game process memory and determine its offset.

**Flag format**: `CTF{MEM_SCAN_OFFSET_<offset>_VALUE_<original_hp>}`

### Cheat Engine Workflow
1. **First Scan**: Search for current HP value (e.g., 75) → many candidate addresses
2. **Take damage**: HP changes to new value (e.g., 50)
3. **Next Scan**: Filter candidates to only those now holding the new value
4. **Address confirmed**: Write new value (e.g., 9999) to make character immortal

### Memory Structure
Player data is stored as a contiguous C struct. HP is at offset `+0x04` from the struct base.

```bash
python3 challenge1.py --hp 75 --damage 25
# Output: CTF{MEM_SCAN_OFFSET_0x0104_VALUE_75}
```

---

## Challenge 2: Game Protocol Analysis and Packet Manipulation

### Objective
Analyze game client-server purchase packets and manipulate the price field to buy an expensive item for 1 Gold.

**Flag format**: `CTF{PACKET_TAMPER_ITEM_<item_id>_PRICE_<original>_MODIFIED_<new>}`

### Vulnerability
The server trusts the `price` field sent by the client instead of looking it up from its own item database. This is a **client-side trust** vulnerability common in poorly designed game backends.

### Packet Format
```
[2B] Opcode | [2B] Length | [4B] PlayerID | [4B] ItemID | [4B] Price | [4B] Qty | [4B] XOR Checksum
```

```bash
python3 challenge2.py --item 1004
# Output: CTF{PACKET_TAMPER_ITEM_1004_PRICE_999999_MODIFIED_1}
```

---

## Challenge 3: Anti-Cheat Bypass Concepts Analysis

### Objective
Analyze anti-cheat detection mechanisms and identify the easiest bypass target.

**Flag format**: `CTF{ANTICHEAT_BYPASS_<method>_DIFFICULTY_<level>}`

### Anti-Cheat Layers and Bypass Difficulty

| Detection Method | Bypass Difficulty | Score |
|-----------------|------------------|-------|
| HWID Blacklist | EASY | 30 |
| Process List Check | MEDIUM | 45 |
| Memory Signature Scan | MEDIUM | 50 |
| Visual/Screenshot Analysis | HARD | 75 |
| Behavioral Statistics | HARD | 80 |
| Kernel-Level Monitoring | EXPERT | 95 |

```bash
python3 challenge3.py
# Output: CTF{ANTICHEAT_BYPASS_HARDWARE_DIFFICULTY_EASY}
```

**Key insight**: Kernel-level anti-cheat (like EasyAntiCheat, BattlEye) is the hardest to bypass because it operates at Ring 0, has full system visibility, and defeating it requires either a hypervisor-level attack or signed kernel driver exploitation.
