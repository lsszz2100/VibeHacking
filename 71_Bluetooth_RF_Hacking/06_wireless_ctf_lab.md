> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 블루투스/RF CTF 실습 랩

## 0. 소개

이 랩은 실제 블루투스/RF 하드웨어 없이도 무선 보안 공격 개념을 체험할 수 있는 **소프트웨어 시뮬레이션** CTF입니다. Python으로 작성된 `wireless_ctf.py`를 로컬에서 실행하면 됩니다.

```
챌린지 목록:

  C01: BLE GATT 취약 특성에서 플래그 읽기       (★☆☆) 입문
  C02: 블루투스 페어링 PIN 브루트포스            (★★☆) 중급
  C03: RF 리플레이 공격 시뮬레이션               (★★☆) 중급
  C04: Zigbee 네트워크 키 크래킹                 (★★★) 고급
```

---

## 1. 설치 및 실행

```bash
# 의존성 설치 (Python 3.10+ 필요)
pip install pycryptodome

# CTF 스크립트 실행
python3 wireless_ctf.py --list               # 챌린지 목록
python3 wireless_ctf.py --challenge C01      # C01 실행
python3 wireless_ctf.py --challenge C02      # C02 실행
python3 wireless_ctf.py --challenge C03      # C03 실행
python3 wireless_ctf.py --challenge C04      # C04 실행
python3 wireless_ctf.py --challenge all      # 전체 실행
python3 wireless_ctf.py --validate FLAG{...} # 플래그 검증
```

---

## 2. wireless_ctf.py 전체 스크립트

```python
#!/usr/bin/env python3
"""
wireless_ctf.py — 블루투스/RF/Zigbee 보안 CTF 시뮬레이터
Python 3.10+ 필요 | pip install pycryptodome

챌린지:
  C01: BLE GATT 취약 특성 읽기       (★☆☆)
  C02: 블루투스 PIN 브루트포스       (★★☆)
  C03: RF 리플레이 공격 시뮬레이션   (★★☆)
  C04: Zigbee 네트워크 키 크래킹     (★★★)
"""

import argparse
import hashlib
import hmac
import json
import random
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any


# ─── 플래그 생성 (SHA-256 기반) ───────────────────────────────────────────────

SECRET_SEED = b"wireless_ctf_2025_seed_v1"

def derive_flag(challenge_id: str, answer: str) -> str:
    """정답 + 시드로 플래그 파생 (SHA-256)"""
    data = f"{challenge_id}:{answer}:{SECRET_SEED.decode()}".encode()
    digest = hashlib.sha256(data).hexdigest()[:24]
    return f"FLAG{{{challenge_id}_{digest}}}"

# 각 챌린지의 정답 기반 플래그
CORRECT_FLAGS: dict[str, str] = {
    "C01": derive_flag("C01", "GATT_READ_NO_AUTH"),
    "C02": derive_flag("C02", "PIN_8472"),
    "C03": derive_flag("C03", "REPLAY_FIXED_CODE"),
    "C04": derive_flag("C04", "ZIGBEE_DEFAULT_KEY"),
}


# ─── 유틸리티 ─────────────────────────────────────────────────────────────────

def slow_print(text: str, delay: float = 0.02) -> None:
    """타이핑 효과 출력"""
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


def print_banner() -> None:
    banner = """
╔══════════════════════════════════════════════════════════╗
║     블루투스 / RF / Zigbee 보안 CTF 시뮬레이터          ║
║     Bluetooth / RF / Zigbee Security CTF Simulator       ║
╚══════════════════════════════════════════════════════════╝
  ⚠ 교육 목적 전용 | For educational purposes only
"""
    print(banner)


def print_divider(char: str = "─", width: int = 60) -> None:
    print(char * width)


# ─── C01: BLE GATT 취약 특성 읽기 ────────────────────────────────────────────

@dataclass
class GATTCharacteristic:
    handle: int
    uuid: str
    properties: list[str]
    requires_auth: bool
    value: bytes
    description: str


class BLEDeviceSimulator:
    """취약한 스마트 자물쇠 BLE 기기 시뮬레이터"""

    DEVICE_NAME = "SmartLock-VulnDemo"
    MAC_ADDRESS = "DE:AD:BE:EF:CA:FE"

    def __init__(self) -> None:
        self.characteristics = self._build_service()

    def _build_service(self) -> list[GATTCharacteristic]:
        # 일부러 인증 없는 특성에 플래그 숨김
        hidden_flag_bytes = CORRECT_FLAGS["C01"].encode()
        return [
            GATTCharacteristic(
                handle=0x0001,
                uuid="00001800-0000-1000-8000-00805f9b34fb",
                properties=["read"],
                requires_auth=False,
                value=b"SmartLock-VulnDemo",
                description="Device Name",
            ),
            GATTCharacteristic(
                handle=0x0003,
                uuid="0000180F-0000-1000-8000-00805f9b34fb",
                properties=["read"],
                requires_auth=False,
                value=bytes([72]),  # 72% 배터리
                description="Battery Level",
            ),
            GATTCharacteristic(
                handle=0x0010,
                uuid="12345678-0001-0000-ABCD-ABCDEF123456",
                properties=["write-without-response"],
                requires_auth=False,  # 취약: 인증 없이 잠금 제어 가능
                value=bytes([0x00]),
                description="Lock Control (VULNERABLE - no auth!)",
            ),
            GATTCharacteristic(
                handle=0x0012,
                uuid="12345678-0002-0000-ABCD-ABCDEF123456",
                properties=["read"],
                requires_auth=False,  # 취약: 인증 없이 내부 설정 읽기 가능
                value=hidden_flag_bytes,
                description="Internal Config (VULNERABLE - flag here!)",
            ),
            GATTCharacteristic(
                handle=0x0014,
                uuid="12345678-0003-0000-ABCD-ABCDEF123456",
                properties=["read", "write"],
                requires_auth=True,  # 올바른 설계: 인증 필요
                value=b"admin_config_encrypted",
                description="Admin Config (auth required)",
            ),
        ]

    def scan_response(self) -> dict[str, Any]:
        return {
            "address": self.MAC_ADDRESS,
            "name": self.DEVICE_NAME,
            "rssi": -58,
            "services": [
                "00001800-0000-1000-8000-00805f9b34fb",
                "12345678-0001-0000-ABCD-ABCDEF123456",
            ],
        }

    def enumerate_characteristics(self) -> list[dict[str, Any]]:
        return [
            {
                "handle": f"0x{c.handle:04X}",
                "uuid": c.uuid,
                "properties": c.properties,
                "auth_required": c.requires_auth,
                "description": c.description,
            }
            for c in self.characteristics
        ]

    def read_characteristic(self, handle: int) -> bytes | None:
        for char in self.characteristics:
            if char.handle == handle:
                if char.requires_auth:
                    return None  # 인증 필요
                return char.value
        return None


def challenge_c01() -> None:
    """C01: BLE GATT 취약 특성에서 플래그 읽기 (★☆☆)"""
    print_divider("═")
    print("  챌린지 C01: BLE GATT 취약 특성 읽기  ★☆☆")
    print_divider("═")
    print()
    print("  [시나리오]")
    print("  근처에서 'SmartLock-VulnDemo' BLE 기기를 발견했습니다.")
    print("  이 기기의 GATT 특성을 열거하고 인증 없이 읽을 수 있는")
    print("  특성 중 플래그가 숨겨진 것을 찾아 읽으세요.")
    print()

    device = BLEDeviceSimulator()

    # 1단계: 스캔
    input("  [1단계] BLE 스캔 시작... (Enter)")
    scan_result = device.scan_response()
    print(f"\n  [스캔 결과]")
    print(f"    기기명: {scan_result['name']}")
    print(f"    주소:   {scan_result['address']}")
    print(f"    RSSI:   {scan_result['rssi']} dBm")
    print()

    # 2단계: GATT 열거
    input("  [2단계] GATT 특성 열거... (Enter)")
    print("\n  [발견된 특성 목록]")
    chars = device.enumerate_characteristics()
    for char in chars:
        auth_str = "인증 필요" if char["auth_required"] else "인증 없음 ⚠"
        print(f"    핸들 {char['handle']}: {char['description']}")
        print(f"      UUID: {char['uuid']}")
        print(f"      속성: {', '.join(char['properties'])} | {auth_str}")
    print()

    # 3단계: 특성 읽기 시도
    input("  [3단계] 인증 없는 특성 읽기 시도... (Enter)")
    print("\n  [읽기 시도]")
    for char in device.characteristics:
        if not char.requires_auth and "read" in char.properties:
            result = device.read_characteristic(char.handle)
            if result:
                try:
                    decoded = result.decode("utf-8")
                    print(f"    핸들 0x{char.handle:04X} ({char.description}):")
                    print(f"      값: {decoded}")
                    if decoded.startswith("FLAG{"):
                        print()
                        print("  ┌─────────────────────────────────────────┐")
                        print(f"  │ 🎉 플래그 발견!                         │")
                        print(f"  │ {decoded:<41}│")
                        print("  └─────────────────────────────────────────┘")
                except UnicodeDecodeError:
                    print(f"    핸들 0x{char.handle:04X}: {result.hex()}")
    print()
    print("  [학습 포인트]")
    print("  → 'read' 속성 + 인증 없음 = 누구나 값 읽기 가능")
    print("  → 민감한 특성은 반드시 Security Level 3+ 설정 필요")
    print()


# ─── C02: 블루투스 PIN 브루트포스 ────────────────────────────────────────────

class BTLegacyPairingSimulator:
    """레거시 블루투스 PIN 페어링 시뮬레이터"""

    def __init__(self, secret_pin: str) -> None:
        self._pin_hash = hashlib.sha256(secret_pin.encode()).hexdigest()
        self.attempt_count = 0
        self.max_attempts = 10000

    def try_pin(self, pin: str) -> bool:
        self.attempt_count += 1
        if self.attempt_count > self.max_attempts:
            raise RuntimeError("최대 시도 횟수 초과")
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        # 타이밍 안전 비교
        return hmac.compare_digest(pin_hash, self._pin_hash)


def challenge_c02() -> None:
    """C02: 블루투스 페어링 PIN 브루트포스 (★★☆)"""
    print_divider("═")
    print("  챌린지 C02: 블루투스 페어링 PIN 브루트포스  ★★☆")
    print_divider("═")
    print()
    print("  [시나리오]")
    print("  구형 블루투스 헤드셋이 4자리 숫자 PIN을 사용합니다.")
    print("  PIN을 브루트포스로 찾아 연결을 완성하세요.")
    print("  힌트: PIN은 4자리 숫자 (0000~9999)")
    print()

    # 정답 PIN: 8472
    simulator = BTLegacyPairingSimulator("8472")

    input("  [브루트포스 시작] Enter를 눌러 실행...")
    print()

    found_pin: str | None = None
    start_time = time.time()

    print("  [*] 0000부터 9999까지 순서대로 시도 중...")

    # 진행 표시 (100 단위)
    for i in range(10000):
        pin = f"{i:04d}"
        if simulator.try_pin(pin):
            found_pin = pin
            break
        if i % 1000 == 0 and i > 0:
            elapsed = time.time() - start_time
            progress = i / 10000 * 100
            print(f"    {i:>5}번 시도 ({progress:.0f}%) - 경과 {elapsed:.1f}초")

    elapsed = time.time() - start_time

    if found_pin:
        print()
        print(f"  [+] PIN 발견: {found_pin} ({simulator.attempt_count}번 시도, {elapsed:.2f}초)")
        flag = CORRECT_FLAGS["C02"]
        print()
        print("  ┌─────────────────────────────────────────┐")
        print(f"  │ 🎉 챌린지 C02 완료!                     │")
        print(f"  │ PIN: {found_pin}                              │")
        print(f"  │ {flag:<41}│")
        print("  └─────────────────────────────────────────┘")
    else:
        print("  [!] PIN을 찾지 못함")

    print()
    print("  [학습 포인트]")
    print("  → 4자리 PIN = 10,000가지 = 초당 수천 번 시도 시 수초 내 크랙")
    print("  → 6자리 Numeric Comparison은 MitM 방어하지만 브루트포스엔 약함")
    print("  → Secure Simple Pairing의 Passkey는 20비트 (0~999999)")
    print()


# ─── C03: RF 리플레이 공격 시뮬레이션 ───────────────────────────────────────

@dataclass
class RFPacket:
    frequency_mhz: float
    raw_bytes: bytes
    timestamp: float
    description: str


class RFReplaySimulator:
    """RF 리플레이 공격 시뮬레이터 (고정 코드 차고 도어 시뮬레이션)"""

    GARAGE_FREQUENCY = 315.0  # MHz
    DOOR_CODE = bytes([0xA3, 0xF7, 0x2C, 0x10])  # 고정 코드 (취약)

    def __init__(self) -> None:
        self._captured_packets: list[RFPacket] = []
        self._door_open = False

    def transmit_open(self) -> RFPacket:
        """원래 리모컨이 신호 전송 (시뮬레이션)"""
        pkt = RFPacket(
            frequency_mhz=self.GARAGE_FREQUENCY,
            raw_bytes=self.DOOR_CODE,
            timestamp=time.time(),
            description="GARAGE_DOOR_OPEN",
        )
        return pkt

    def capture_signal(self, packet: RFPacket) -> None:
        """RTL-SDR로 신호 캡처 (시뮬레이션)"""
        self._captured_packets.append(packet)

    def replay_signal(self, packet: RFPacket) -> bool:
        """캡처된 신호 재전송"""
        # 고정 코드이므로 유효함 (롤링 코드였다면 False)
        if packet.raw_bytes == self.DOOR_CODE:
            self._door_open = True
            return True
        return False

    @property
    def door_open(self) -> bool:
        return self._door_open


def challenge_c03() -> None:
    """C03: RF 리플레이 공격 시뮬레이션 (★★☆)"""
    print_divider("═")
    print("  챌린지 C03: RF 리플레이 공격 시뮬레이션  ★★☆")
    print_divider("═")
    print()
    print("  [시나리오]")
    print("  315 MHz 대역 구형 차고 도어 시스템을 발견했습니다.")
    print("  이 시스템은 고정 코드(Fixed Code)를 사용합니다.")
    print("  RTL-SDR로 신호를 캡처하고, 나중에 재전송하여 문을 여세요.")
    print()

    sim = RFReplaySimulator()

    # 1단계: 피해자 신호 관찰
    input("  [1단계] 피해자가 리모컨 누르는 것을 기다림... (Enter)")
    print()
    print("  [*] 315.0 MHz 대역 모니터링 중...")
    time.sleep(0.5)
    original_packet = sim.transmit_open()
    print(f"  [+] 신호 감지!")
    print(f"      주파수:   {original_packet.frequency_mhz} MHz")
    print(f"      원시 데이터: {original_packet.raw_bytes.hex().upper()}")
    print(f"      설명:     {original_packet.description}")
    print()

    # 2단계: 신호 캡처
    input("  [2단계] 신호 캡처... (Enter)")
    sim.capture_signal(original_packet)
    print(f"  [+] 캡처 완료! 저장된 패킷: {original_packet.raw_bytes.hex().upper()}")
    print()

    # 3단계: 리플레이
    input("  [3단계] 피해자가 자리를 떠난 후, 신호 재전송... (Enter)")
    print()
    print("  [*] 315.0 MHz로 캡처된 신호 재전송 중...")
    time.sleep(0.8)
    success = sim.replay_signal(original_packet)

    if success:
        print("  [+] 차고 문 열림! 리플레이 공격 성공!")
        flag = CORRECT_FLAGS["C03"]
        print()
        print("  ┌─────────────────────────────────────────┐")
        print(f"  │ 🎉 챌린지 C03 완료!                     │")
        print(f"  │ {flag:<41}│")
        print("  └─────────────────────────────────────────┘")
    else:
        print("  [!] 실패 (롤링 코드 시스템)")

    print()
    print("  [학습 포인트]")
    print("  → 고정 코드 RF 시스템 = 캡처 후 무제한 재사용")
    print("  → 롤링 코드(KeeLoq 등)는 각 전송마다 코드 변경")
    print("  → RollJam 공격: 재밍 + 캡처로 롤링 코드도 우회 가능")
    print("  → 방어: 롤링 코드 + 시간 기반 유효성 검증")
    print()


# ─── C04: Zigbee 네트워크 키 크래킹 ─────────────────────────────────────────

class ZigbeeNetworkKeySimulator:
    """Zigbee S0 기본 키 취약점 시뮬레이터"""

    # 실제 Zigbee 표준에 정의된 기본 TC Link Key
    DEFAULT_TC_LINK_KEY = b"ZigBeeAlliance09"

    # 시뮬레이션: 기본 키로 암호화된 네트워크 키
    # (실제로는 AES-128 CCM 사용; 여기서는 XOR으로 간략화)
    TRUE_NETWORK_KEY = bytes([
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
    ])

    def __init__(self) -> None:
        # 네트워크 키를 TC Link Key와 XOR으로 "암호화" (교육용 단순화)
        self._encrypted_network_key = self._simple_encrypt(
            self.TRUE_NETWORK_KEY,
            self.DEFAULT_TC_LINK_KEY,
        )

    @staticmethod
    def _simple_encrypt(data: bytes, key: bytes) -> bytes:
        """교육용 단순 XOR 암호화 (실제 Zigbee는 AES-128-CCM 사용)"""
        key_cycle = (key * ((len(data) // len(key)) + 1))[: len(data)]
        return bytes(a ^ b for a, b in zip(data, key_cycle))

    def get_captured_join_packet(self) -> dict[str, Any]:
        """페어링(Join) 패킷 캡처 시뮬레이션"""
        return {
            "type": "Transport-Key",
            "pan_id": "0xABCD",
            "source": "00:11:22:33:44:55:66:77",  # 코디네이터
            "destination": "FF:FF:FF:FF:FF:FF:FF:FF",  # 새 기기
            "encrypted_network_key": self._encrypted_network_key.hex().upper(),
            "key_sequence_number": 0,
            "note": "TC Link Key로 암호화된 Network Key",
        }

    def attempt_decrypt(self, candidate_key: bytes) -> bytes | None:
        """후보 TC Link Key로 네트워크 키 복호화 시도"""
        decrypted = self._simple_encrypt(
            self._encrypted_network_key, candidate_key
        )
        # 올바른 키면 알려진 패턴 확인 (실제: CRC 검증)
        if decrypted == self.TRUE_NETWORK_KEY:
            return decrypted
        return None

    def verify_network_key(self, candidate_network_key: bytes) -> bool:
        """복호화된 네트워크 키로 테스트 패킷 복호화 가능한지 확인"""
        return candidate_network_key == self.TRUE_NETWORK_KEY


def challenge_c04() -> None:
    """C04: Zigbee 네트워크 키 크래킹 (★★★)"""
    print_divider("═")
    print("  챌린지 C04: Zigbee 네트워크 키 크래킹  ★★★")
    print_divider("═")
    print()
    print("  [시나리오]")
    print("  Zigbee 네트워크의 새 기기 페어링(Join) 패킷을 캡처했습니다.")
    print("  이 네트워크는 기본 Trust Center Link Key를 사용합니다.")
    print("  기본 키로 네트워크 키를 복호화하고, 플래그를 획득하세요.")
    print()
    print("  힌트: Zigbee 표준(ZigBee Specification r21)에 기본 키가 정의되어 있습니다.")
    print()

    sim = ZigbeeNetworkKeySimulator()

    # 1단계: 캡처된 패킷 분석
    input("  [1단계] 캡처된 Join 패킷 분석... (Enter)")
    packet = sim.get_captured_join_packet()
    print("\n  [캡처된 Zigbee 패킷]")
    for k, v in packet.items():
        print(f"    {k}: {v}")
    print()

    # 2단계: 기본 키 시도
    input("  [2단계] 알려진 기본 TC Link Key 목록으로 복호화 시도... (Enter)")
    print()

    # 실제 공격에서 사용하는 알려진 기본 키 목록
    known_default_keys: list[tuple[str, bytes]] = [
        ("ZigBeeAlliance09 (Zigbee 표준 기본값)",
         b"ZigBeeAlliance09"),
        ("HomeAutomation (HA 프로파일 기본)",
         b"homeautomation "),  # 16바이트 맞춤
        ("AllZeros (일부 구형 기기)",
         bytes(16)),
    ]

    found_network_key: bytes | None = None

    for key_name, tc_key in known_default_keys:
        padded_key = (tc_key + bytes(16))[:16]  # 16바이트 맞춤
        result = sim.attempt_decrypt(padded_key)
        if result:
            print(f"  [+] 성공! TC Link Key: '{key_name}'")
            print(f"      복호화된 Network Key: {result.hex().upper()}")
            found_network_key = result
            break
        else:
            print(f"  [-] 실패: {key_name}")

    if not found_network_key:
        print("  [!] 알려진 기본 키 실패. 추가 분석 필요.")
        return

    print()

    # 3단계: 네트워크 키 검증
    input("  [3단계] 복호화된 키 검증... (Enter)")
    if sim.verify_network_key(found_network_key):
        print("  [+] 네트워크 키 검증 성공!")
        print("  [+] 이 키로 해당 Zigbee 네트워크의 모든 트래픽 복호화 가능")
        flag = CORRECT_FLAGS["C04"]
        print()
        print("  ┌─────────────────────────────────────────┐")
        print(f"  │ 🎉 챌린지 C04 완료!                     │")
        print(f"  │ {flag:<41}│")
        print("  └─────────────────────────────────────────┘")
    else:
        print("  [!] 네트워크 키 검증 실패")

    print()
    print("  [학습 포인트]")
    print("  → 기본 TC Link Key = 공개된 비밀 → 즉시 변경 필수")
    print("  → 실제 Zigbee는 AES-128-CCM 사용 (여기서는 교육용 단순화)")
    print("  → 방어: Zigbee2MQTT에서 랜덤 network_key 설정")
    print("  → 방어: 기기 조인은 짧은 시간만 허용 (permit_join 타이머)")
    print()


# ─── 플래그 검증 ──────────────────────────────────────────────────────────────

def validate_flag(flag: str) -> None:
    """입력된 플래그 검증"""
    print(f"\n[*] 플래그 검증: {flag}")
    for challenge_id, correct_flag in CORRECT_FLAGS.items():
        if hmac.compare_digest(flag.strip(), correct_flag):
            print(f"[+] 정답! 챌린지 {challenge_id} 플래그가 맞습니다.")
            return
    print("[!] 오답. 다시 시도하세요.")


def list_challenges() -> None:
    """챌린지 목록 출력"""
    print_banner()
    print("  챌린지 목록:\n")
    challenges = [
        ("C01", "BLE GATT 취약 특성 읽기",       "★☆☆", "bleak, BLE GATT, 인증 우회"),
        ("C02", "블루투스 PIN 브루트포스",         "★★☆", "PIN 취약성, 브루트포스"),
        ("C03", "RF 리플레이 공격 시뮬레이션",     "★★☆", "고정 코드, RTL-SDR, 리플레이"),
        ("C04", "Zigbee 네트워크 키 크래킹",       "★★★", "기본 TC Link Key, AES"),
    ]
    for cid, name, stars, tags in challenges:
        print(f"  {cid} [{stars}] {name}")
        print(f"       주제: {tags}")
        print()


# ─── 메인 ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="블루투스/RF/Zigbee CTF 시뮬레이터"
    )
    parser.add_argument(
        "--challenge",
        choices=["C01", "C02", "C03", "C04", "all"],
        help="실행할 챌린지 ID"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="챌린지 목록 표시"
    )
    parser.add_argument(
        "--validate",
        type=str,
        metavar="FLAG",
        help="획득한 플래그 검증"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list:
        list_challenges()
        return

    if args.validate:
        validate_flag(args.validate)
        return

    if not args.challenge:
        print("사용법: python3 wireless_ctf.py --help")
        print("       python3 wireless_ctf.py --list")
        sys.exit(0)

    print_banner()

    if args.challenge in ("C01", "all"):
        challenge_c01()
    if args.challenge in ("C02", "all"):
        challenge_c02()
    if args.challenge in ("C03", "all"):
        challenge_c03()
    if args.challenge in ("C04", "all"):
        challenge_c04()

    if args.challenge == "all":
        print_divider("═")
        print("  🏆 모든 챌린지 완료!")
        print("  획득한 플래그:")
        for cid, flag in CORRECT_FLAGS.items():
            print(f"    {cid}: {flag}")
        print_divider("═")

    print("\n[!] 이 시뮬레이터는 교육 목적으로만 사용하세요.")
    print("    실제 기기에 대한 무단 접근은 불법입니다.")


if __name__ == "__main__":
    main()
```

---

## 3. 실행 예시

```bash
# 설치 (pycryptodome은 선택적, 기본 기능은 표준 라이브러리만 필요)
python3 -m pip install pycryptodome

# 챌린지 목록 보기
python3 wireless_ctf.py --list

# 개별 챌린지 실행
python3 wireless_ctf.py --challenge C01
python3 wireless_ctf.py --challenge C02
python3 wireless_ctf.py --challenge C03
python3 wireless_ctf.py --challenge C04

# 전체 실행 (순서대로)
python3 wireless_ctf.py --challenge all

# 플래그 검증
python3 wireless_ctf.py --validate "FLAG{C01_abcd1234...}"
```

---

## 4. 실습 도구 설치 방법 (실제 환경)

### BLE 실습 환경

```bash
# Ubuntu/Kali 기준
sudo apt update
sudo apt install -y bluez bluez-tools python3-pip

# Python BLE 라이브러리
pip3 install bleak paho-mqtt

# 블루투스 권한 설정
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
```

### RF/SDR 실습 환경

```bash
# RTL-SDR 드라이버
sudo apt install -y rtl-sdr gqrx-sdr gnuradio

# Python SDR 라이브러리
pip3 install pyrtlsdr numpy scipy matplotlib

# RTL-SDR 인식 확인
rtl_test -t
```

### Zigbee 실습 환경

```bash
# Node.js (Zigbee2MQTT 용)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# MQTT 브로커
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable --now mosquitto

# Python MQTT 클라이언트
pip3 install paho-mqtt
```

---

## 5. 추가 도전: 실제 하드웨어 확장 실습

```
실제 장비가 있다면 다음으로 확장:

  C01 확장:
    → bleak 로 실제 BLE 기기 GATT 열거
    → nRF Connect 앱으로 스마트폰에서 직접 확인

  C02 확장:
    → bluetoothctl 로 실제 구형 기기 페어링 PIN 테스트
    → Ubertooth One으로 페어링 패킷 캡처

  C03 확장:
    → RTL-SDR로 433 MHz 무선 온도계 신호 캡처
    → Universal Radio Hacker (URH)로 신호 분석

  C04 확장:
    → CC2531 동글 + Wireshark으로 Zigbee 패킷 캡처
    → Zigbee2MQTT permit_join 켜고 페어링 패킷 관찰
```

---

<a name="english"></a>

# Bluetooth/RF CTF Practice Lab

## 0. Introduction

This lab is a **software simulation CTF** — no real Bluetooth or RF hardware required. Run `wireless_ctf.py` locally to experience wireless security attack concepts.

```
Challenges:

  C01: Read a flag from a vulnerable BLE GATT characteristic  (★☆☆)
  C02: Bluetooth legacy pairing PIN brute-force               (★★☆)
  C03: RF replay attack simulation                            (★★☆)
  C04: Zigbee network key cracking                            (★★★)
```

---

## 1. Installation and Usage

```bash
# Python 3.10+ required
# No extra packages needed for core functionality
python3 wireless_ctf.py --list
python3 wireless_ctf.py --challenge C01
python3 wireless_ctf.py --challenge all
python3 wireless_ctf.py --validate "FLAG{...}"
```

---

## 2. Challenge Descriptions

### C01 — BLE GATT Unauthenticated Read (★☆☆)

```
Scenario:
  A "SmartLock-VulnDemo" BLE device is nearby.
  Enumerate its GATT characteristics and read the one
  that has no authentication required — it contains the flag.

Key concept:
  Properties: read | requires_auth: False
  → Anyone within range can read the value
  → Sensitive characteristics MUST require Security Level 3+
```

### C02 — Bluetooth PIN Brute-Force (★★☆)

```
Scenario:
  A legacy Bluetooth headset uses a 4-digit numeric PIN.
  Brute-force 0000–9999 to find the correct PIN.

Key concept:
  4-digit PIN = 10,000 combinations
  At thousands of attempts/second → cracked in seconds
  Modern SSP Numeric Comparison defends against MitM but
  still uses only a 6-digit (20-bit) Passkey space.
```

### C03 — RF Replay Attack (★★☆)

```
Scenario:
  A 315 MHz garage door system uses a FIXED code (no rolling).
  Capture the owner's transmission, then replay it later to open the door.

Key concept:
  Fixed-code systems → captured signal is reusable forever
  Rolling codes (KeeLoq) change with each press
  RollJam attack bypasses rolling codes via jamming + capture
```

### C04 — Zigbee Network Key Cracking (★★★)

```
Scenario:
  A Zigbee Join packet was captured.
  The network uses the default Trust Center Link Key.
  Decrypt the Network Key and validate it to get the flag.

Key concept:
  Default TC Link Key "ZigBeeAlliance09" is PUBLIC (in the spec)
  → Decrypt network key → read all traffic
  Defense: generate a random network_key in Zigbee2MQTT config
```

---

## 3. All Flags Use SHA-256

```
# Flag derivation (see source for details)
# flag = "FLAG{" + challenge_id + "_" + sha256(challenge_id + answer + seed)[:24] + "}"
```

Flags are validated with `hmac.compare_digest` (timing-safe comparison).

---

## 4. Real Hardware Extension Labs

```
C01 extension: Use bleak to enumerate real BLE devices
C02 extension: Use bluetoothctl to test real legacy pairing
C03 extension: Use RTL-SDR + URH to capture real 433 MHz sensors
C04 extension: Use CC2531 dongle + Wireshark to capture Zigbee join packets

Tool stack:
  BLE:    bleak, bluetoothctl, nRF Connect app
  RF:     RTL-SDR, GQRX, Universal Radio Hacker
  Zigbee: CC2531 USB dongle, Zigbee2MQTT, Wireshark
```

---

## 5. Setup

```bash
# BLE lab
sudo apt install -y bluez python3-pip
pip3 install bleak paho-mqtt

# RF/SDR lab
sudo apt install -y rtl-sdr gqrx-sdr gnuradio
pip3 install pyrtlsdr numpy scipy matplotlib

# Zigbee lab
sudo apt install -y mosquitto mosquitto-clients
pip3 install paho-mqtt
```
