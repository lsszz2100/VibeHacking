> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Zigbee/Z-Wave IoT 무선 공격

## 0. 초보자를 위한 개념 이해

### Zigbee란 무엇인가?

Zigbee를 처음 배우는 분을 위한 비유: Zigbee는 **스마트홈의 우체부 시스템**입니다. WiFi가 모든 편지를 중앙 우체국(공유기)을 통해 보내는 것과 달리, Zigbee는 이웃 집을 거쳐서 목적지까지 배달합니다. 전구 → 스위치 → 허브 → 허브 순으로 "메쉬 네트워크"를 형성합니다.

```
스마트홈 무선 프로토콜 비교:

  WiFi      → 많은 데이터, 높은 전력, 직접 인터넷 연결
  블루투스  → 1:1 연결, 중거리, 오디오/웨어러블
  Zigbee    → 낮은 전력, 메쉬 네트워크, 스마트홈 핵심
  Z-Wave    → Zigbee와 유사, 900 MHz 대역 사용
  Thread    → IPv6 기반 메쉬, Matter 프로토콜 기반
  LoRa      → 초원거리 (수km), 느림, 스마트 시티/농업
```

---

## 1. Zigbee 아키텍처

### 세 가지 역할

```
Zigbee 네트워크 구성:

  [코디네이터] ─── 허브, 라우터
  (Coordinator)     1개만 존재
  삼성 SmartThings, 필립스 Hue 브리지
  → 네트워크 생성, PAN ID 할당, 보안 키 분배

  [라우터] ─────── 전구, 스마트 플러그 등 (AC 전원)
  (Router)          항상 켜있는 기기
  → 패킷 릴레이, 메쉬 확장

  [엔드 디바이스] → 배터리 기기 (센서, 도어 센서, 리모컨)
  (End Device)      대부분의 시간 잠자기(sleep)
  → 코디네이터/라우터에게만 통신

실제 메쉬 예시:
  [도어 센서] ─→ [전구(라우터)] ─→ [플러그(라우터)] ─→ [SmartThings 허브]
                                                          ↑
                                                    (코디네이터)
```

### Zigbee 채널과 주파수

```
Zigbee 채널 구성 (IEEE 802.15.4):
  - 2.4 GHz 대역: 채널 11~26 (16개 채널)
  - 각 채널 대역폭: 5 MHz
  - 채널 간격: 5 MHz
  - 통신 속도: 250 kbps

  채널과 WiFi 간섭:
    Zigbee 11~13 ← WiFi 1번 채널과 겹침
    Zigbee 15~22 ← WiFi 6번 채널 영역
    Zigbee 25~26 ← WiFi 11번 채널과 겹침 (최소)
    → Zigbee 25, 26번 사용 권장

채널 11: 2405 MHz
채널 15: 2425 MHz
채널 20: 2450 MHz
채널 25: 2475 MHz  ← 권장
채널 26: 2480 MHz  ← 권장
```

---

## 2. Zigbee 보안 구조와 취약점

### 보안 키 유형

```
Zigbee 키 종류:

1. Trust Center Link Key (마스터 키)
   - 코디네이터(Trust Center)와 각 기기 간 암호화 채널
   - 기기 조인 시 사용
   - 기본값 문제: 많은 기기가 "ZigBeeAlliance09" 사용!
     → 공개된 기본 키 = 네트워크 도청 가능

2. Network Key (네트워크 키)
   - 실제 데이터 암호화에 사용 (AES-128)
   - 모든 기기가 동일한 키 공유
   - Trust Center Link Key로 암호화해서 전송

3. Application Link Key
   - 기기 간 직접 통신에 사용 (선택적)
```

### 주요 취약점

```
취약점 1: 기본 Trust Center Link Key
  "ZigBeeAlliance09" 키가 표준에 정의됨
  → 공격자가 이 키로 네트워크 키 복호화 가능
  → 네트워크 트래픽 완전 도청

취약점 2: Insecure Rejoin
  기기가 네트워크 재참가(rejoin) 시 
  일부 구현에서 인증 없이 허용
  → 공격자 기기가 정상 기기인 척 네트워크 참가

취약점 3: 패킷 재전송(Replay)
  카운터 검증이 약한 구현에서
  이전 캡처한 패킷 재전송 가능
  → 스마트홈 기기 오동작 유발

취약점 4: 허브 취약점
  Zigbee 허브(SmartThings, Hue 브리지)의 
  웹/API 취약점으로 전체 네트워크 장악
```

---

## 3. Zigbee 패킷 캡처 실습

### 3-1. 필요 하드웨어

```
옵션 A (저렴, $30): CC2531 USB 동글
  - Texas Instruments CC2531 칩
  - Zigbee 스니퍼 펌웨어 플래시 필요
  - Wireshark와 연동 가능

옵션 B (권장, $35+): Zigbee2MQTT + 지원 어댑터
  - SONOFF Zigbee 3.0 USB Dongle Plus (약 $20)
  - CC2652P 칩 기반, 펌웨어 직접 플래시 불필요
  - Zigbee2MQTT로 편리한 관리

옵션 C (고급): Ubertooth One (블루투스/Zigbee 양용)
```

### 3-2. Zigbee2MQTT 설치 및 패킷 모니터링

```bash
# Node.js 설치
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Zigbee2MQTT 설치
sudo mkdir /opt/zigbee2mqtt
sudo chown -R $USER: /opt/zigbee2mqtt
git clone --depth 1 https://github.com/Koenkk/zigbee2mqtt.git /opt/zigbee2mqtt
cd /opt/zigbee2mqtt
npm ci

# MQTT 브로커 설치 (Zigbee2MQTT 메시지 수신용)
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl start mosquitto

# USB 어댑터 포트 확인
ls /dev/ttyACM* /dev/ttyUSB*

# 설정 파일 작성
cat > /opt/zigbee2mqtt/data/configuration.yaml << 'EOF'
homeassistant: false
permit_join: true
mqtt:
  base_topic: zigbee2mqtt
  server: mqtt://localhost
serial:
  port: /dev/ttyACM0  # USB 어댑터 포트
advanced:
  log_level: debug
  channel: 11  # 모니터링할 채널
EOF

# Zigbee2MQTT 실행
cd /opt/zigbee2mqtt && npm start

# 다른 터미널에서 MQTT 메시지 수신
mosquitto_sub -t "zigbee2mqtt/#" -v
```

### 3-3. 채널 스캔 Python 스크립트

```python
#!/usr/bin/env python3
"""
zigbee_scanner.py — Zigbee 채널 스캔 및 네트워크 탐지
사용법:
  python3 zigbee_scanner.py --scan-channels
  python3 zigbee_scanner.py --monitor-mqtt --broker localhost
  python3 zigbee_scanner.py --analyze-devices
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ZigbeeDevice:
    ieee_addr: str
    network_addr: str
    friendly_name: str
    model: str = "Unknown"
    vendor: str = "Unknown"
    power_source: str = "Unknown"
    last_seen: str = ""
    messages: list[dict] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zigbee 네트워크 스캐너/분석기")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--scan-channels",
        action="store_true",
        help="Zigbee 채널 11-26 스캔 (채널별 활성 기기 수 측정)"
    )
    group.add_argument(
        "--monitor-mqtt",
        action="store_true",
        help="MQTT를 통한 Zigbee2MQTT 메시지 모니터링"
    )
    group.add_argument(
        "--analyze-devices",
        action="store_true",
        help="발견된 기기 취약점 분석"
    )
    parser.add_argument("--broker", default="localhost", help="MQTT 브로커 주소")
    parser.add_argument("--port", type=int, default=1883, help="MQTT 포트")
    parser.add_argument("--duration", type=int, default=60, help="모니터링 시간(초)")
    parser.add_argument("--output", type=str, help="결과 저장 JSON 파일")
    return parser.parse_args()


def scan_channels() -> None:
    """Zigbee 채널 11-26 정보 출력"""
    channels = {
        11: 2405, 12: 2410, 13: 2415, 14: 2420, 15: 2425,
        16: 2430, 17: 2435, 18: 2440, 19: 2445, 20: 2450,
        21: 2455, 22: 2460, 23: 2465, 24: 2470, 25: 2475, 26: 2480,
    }
    wifi_interference = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}

    print("[*] Zigbee 채널 정보\n")
    print(f"  {'채널':>4}  {'주파수':>8}  {'WiFi 간섭':>10}  상태")
    print(f"  {'─'*4}  {'─'*8}  {'─'*10}  {'─'*10}")

    for ch, freq in channels.items():
        wifi_warn = "⚠ 간섭 가능" if ch in wifi_interference else "✓ 안전"
        recommended = " ← 권장" if ch in (25, 26) else ""
        print(f"  {ch:>4}  {freq:>6} MHz  {wifi_warn:>10}{recommended}")

    print()
    print("[*] 채널 스캔은 Zigbee2MQTT + USB 어댑터가 필요합니다.")
    print("    configuration.yaml 의 'channel' 값을 변경 후 재시작하세요.")
    print()
    print("[*] 실제 채널 스캔 명령 (CC2531 기반):")
    print("    sudo whsniff -c 11 | wireshark -k -i -   # 채널 11 캡처")
    print("    sudo whsniff -c 25 | wireshark -k -i -   # 채널 25 캡처")


def monitor_mqtt_messages(broker: str, port: int, duration: int) -> list[ZigbeeDevice]:
    """MQTT로 Zigbee2MQTT 메시지 수신 및 기기 파악"""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("[!] paho-mqtt 미설치: pip install paho-mqtt")
        sys.exit(1)

    devices: dict[str, ZigbeeDevice] = {}
    messages_received = 0

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"[+] MQTT 연결 성공 ({broker}:{port})")
            client.subscribe("zigbee2mqtt/#")
        else:
            print(f"[!] MQTT 연결 실패: rc={rc}")

    def on_message(client, userdata, msg):
        nonlocal messages_received
        topic = msg.topic
        messages_received += 1

        # 기기 목록 토픽 파싱
        if topic == "zigbee2mqtt/bridge/devices":
            try:
                device_list = json.loads(msg.payload)
                for dev_info in device_list:
                    ieee = dev_info.get("ieee_address", "")
                    if ieee and ieee not in devices:
                        devices[ieee] = ZigbeeDevice(
                            ieee_addr=ieee,
                            network_addr=dev_info.get("network_address", ""),
                            friendly_name=dev_info.get("friendly_name", ieee),
                            model=dev_info.get("definition", {}).get("model", "Unknown"),
                            vendor=dev_info.get("definition", {}).get("vendor", "Unknown"),
                            power_source=dev_info.get("power_source", "Unknown"),
                        )
                        print(f"  [기기 발견] {devices[ieee].friendly_name} "
                              f"({devices[ieee].vendor} {devices[ieee].model})")
            except (json.JSONDecodeError, AttributeError):
                pass

        # 기기 메시지 캡처
        elif topic.startswith("zigbee2mqtt/") and not "bridge" in topic:
            device_name = topic.replace("zigbee2mqtt/", "")
            try:
                payload = json.loads(msg.payload)
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"  [{timestamp}] {device_name}: {json.dumps(payload, ensure_ascii=False)}")

                # 관련 기기에 메시지 저장
                for dev in devices.values():
                    if dev.friendly_name == device_name:
                        dev.messages.append({"time": timestamp, "data": payload})
            except (json.JSONDecodeError, AttributeError):
                pass

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[*] MQTT 모니터링 시작 ({duration}초)...")
    try:
        client.connect(broker, port, 60)
        client.loop_start()
        time.sleep(duration)
        client.loop_stop()
        client.disconnect()
    except ConnectionRefusedError:
        print(f"[!] MQTT 브로커 연결 거부. {broker}:{port} 확인")
        print("    sudo systemctl start mosquitto")
        sys.exit(1)

    print(f"\n[+] 총 {messages_received}개 메시지 수신, {len(devices)}개 기기 발견")
    return list(devices.values())


def analyze_devices(devices: list[ZigbeeDevice]) -> None:
    """발견된 기기 보안 분석"""
    print("\n[*] 보안 분석 결과\n")

    if not devices:
        print("  분석할 기기 없음 (먼저 --monitor-mqtt 실행)")
        return

    security_issues: list[str] = []

    for dev in devices:
        print(f"  [기기] {dev.friendly_name}")
        print(f"    IEEE 주소: {dev.ieee_addr}")
        print(f"    모델: {dev.vendor} {dev.model}")
        print(f"    전원: {dev.power_source}")

        # 취약점 분석
        if dev.power_source.lower() in ("battery", "unknown"):
            print(f"    ℹ 배터리 기기 → 보안 업데이트 빈도 낮을 수 있음")

        if dev.model == "Unknown":
            print(f"    ⚠ 알 수 없는 모델 → 펌웨어 보안 수준 불명확")
            security_issues.append(f"{dev.friendly_name}: 미확인 기기")

        if len(dev.messages) > 0:
            # 민감 데이터 패턴 확인
            for msg in dev.messages:
                data = msg.get("data", {})
                if isinstance(data, dict):
                    sensitive_keys = {"contact", "occupancy", "motion", "tamper"}
                    found = sensitive_keys & set(data.keys())
                    if found:
                        print(f"    ⚠ 민감 데이터 평문 전송 감지: {found}")
                        security_issues.append(
                            f"{dev.friendly_name}: 민감 상태 평문 노출 ({found})"
                        )
        print()

    if security_issues:
        print("[!] 발견된 보안 이슈:")
        for issue in security_issues:
            print(f"    - {issue}")
    else:
        print("[+] 명백한 보안 이슈 없음 (더 심층 분석 필요)")


def main() -> None:
    args = parse_args()

    if args.scan_channels:
        scan_channels()

    elif args.monitor_mqtt:
        devices = monitor_mqtt_messages(args.broker, args.port, args.duration)
        if args.output and devices:
            import json
            data = [
                {
                    "ieee_addr": d.ieee_addr,
                    "friendly_name": d.friendly_name,
                    "model": d.model,
                    "vendor": d.vendor,
                    "power_source": d.power_source,
                    "message_count": len(d.messages),
                }
                for d in devices
            ]
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[+] 결과 저장: {args.output}")

    elif args.analyze_devices:
        if args.output:
            try:
                import json
                with open(args.output, encoding="utf-8") as f:
                    raw = json.load(f)
                devices = [
                    ZigbeeDevice(
                        ieee_addr=d["ieee_addr"],
                        network_addr="",
                        friendly_name=d["friendly_name"],
                        model=d.get("model", "Unknown"),
                        vendor=d.get("vendor", "Unknown"),
                        power_source=d.get("power_source", "Unknown"),
                    )
                    for d in raw
                ]
                analyze_devices(devices)
            except FileNotFoundError:
                print(f"[!] 파일 없음: {args.output}")
        else:
            print("[!] --analyze-devices 는 --output 파일 경로 필요")

    print("\n[!] 교육 목적으로만 사용. 타인의 Zigbee 네트워크 무단 접근은 불법입니다.")


if __name__ == "__main__":
    main()
```

### 3-4. 실행 방법

```bash
# 의존성 설치
pip install paho-mqtt

# 1. 채널 정보 확인
python3 zigbee_scanner.py --scan-channels

# 2. Zigbee2MQTT 실행 후 MQTT 모니터링 (60초)
python3 zigbee_scanner.py --monitor-mqtt --duration 60 --output devices.json

# 3. 저장된 기기 분석
python3 zigbee_scanner.py --analyze-devices --output devices.json
```

---

## 4. Z-Wave 프로토콜 취약점

### Z-Wave 개요

```
Z-Wave 특징:
  - 주파수: 868 MHz (유럽), 908 MHz (미국), 916 MHz (한국)
  - 범위: ~30m 실내, 100m 야외
  - 메쉬 네트워크 지원
  - 주요 업체: Sigma Designs → Silicon Labs 인수

Z-Wave 보안 수준:
  Security 0 (S0, 구형):
    → AES-128 사용하지만 키 교환 과정 취약
    → 재전송 공격 가능
    → 현재 권장하지 않음

  Security 2 (S2, 현대):
    → ECDH 기반 키 교환 (훨씬 안전)
    → 세 가지 보안 클래스:
       S2 Unauthenticated, S2 Authenticated, S2 Access Control
```

### Z-Wave S0 취약점 개념

```
S0 키 교환 취약점:
  1. 새 기기 페어링 시 네트워크 키를 
     "All Zeros" TEK (임시 암호화 키)로 암호화해 전송
  2. 공격자가 페어링 패킷 캡처
  3. All Zeros 키로 복호화 → 네트워크 키 획득
  4. 이후 모든 통신 복호화 가능

Z-Wave 공격 도구:
  - Z-Wave Sniffer (Silicon Labs Z-Wave 개발 키트)
  - EcoSmart (구형 오픈소스 Z-Wave 도구)
```

---

## 5. 스마트홈 기기 공격 시나리오

```
시나리오: 임대 아파트 스마트 도어락 해킹

  환경: Z-Wave S0 기반 구형 도어락

  1. 단계: 정찰
     → Z-Wave 신호 탐지 (908 MHz 대역)
     → 키 교환 패킷 캡처 시도 (페어링 타이밍 필요)

  2. 단계: 복호화
     → S0 취약점으로 네트워크 키 추출
     → 이후 모든 잠금/해제 명령 복호화

  3. 단계: 재전송
     → 이전 "잠금 해제" 명령 재전송
     → 문 열림

  방어: Z-Wave S2로 업그레이드, 설치 시 RF 차폐 환경 확인
```

---

<a name="english"></a>

# Zigbee/Z-Wave IoT Wireless Attacks

## 0. Beginner Concepts

### What Is Zigbee?

Think of Zigbee as a **smart home postal relay network**. Unlike WiFi (all mail goes through the central post office/router), Zigbee delivers messages neighbor-to-neighbor: bulb → switch → hub. This forms a self-healing mesh network.

```
Smart Home Wireless Protocol Comparison:

  WiFi      → High bandwidth, high power, direct internet
  Bluetooth → 1:1 connections, audio/wearables
  Zigbee    → Low power, mesh network, smart home core
  Z-Wave    → Similar to Zigbee, uses 900 MHz band
  Thread    → IPv6-based mesh, foundation of Matter protocol
  LoRa      → Multi-km range, slow, smart city / agriculture
```

---

## 1. Zigbee Architecture

### Three Device Roles

```
Coordinator (1 per network):
  - Creates the network, assigns PAN ID, distributes security keys
  - Examples: Samsung SmartThings, Philips Hue Bridge

Router (AC-powered devices):
  - Relays packets, extends mesh
  - Examples: smart bulbs, smart plugs

End Device (battery-powered):
  - Mostly sleeping; only communicates with coordinator/router
  - Examples: door sensors, motion detectors, remotes
```

### Channels and Frequencies

```
Zigbee uses IEEE 802.15.4 at 2.4 GHz:
  Channels 11–26 (16 channels, 5 MHz spacing, 250 kbps)

  WiFi interference:
    Channels 11–22 overlap with WiFi channels 1, 6, 11
    → Recommended: channels 25 or 26 (least interference)
```

---

## 2. Zigbee Security and Vulnerabilities

### Security Keys

```
1. Trust Center Link Key:
   - Shared between coordinator and each joining device
   - DEFAULT KEY: "ZigBeeAlliance09" (published in the standard!)
   - If unchanged → attacker can decrypt the Network Key handshake

2. Network Key (AES-128):
   - Encrypts actual data traffic
   - Shared by all devices; distributed via TC Link Key

3. Application Link Key (optional):
   - Per-pair encryption between specific devices
```

### Key Vulnerabilities

```
1. Default Trust Center Link Key
   → "ZigBeeAlliance09" is publicly known
   → Decrypt Network Key → read all traffic

2. Insecure Rejoin
   → Some implementations allow devices to rejoin without auth
   → Rogue device joins as a legitimate node

3. Replay Attack
   → Weak counter validation → replay captured packets
   → Causes smart home devices to misbehave

4. Hub Vulnerabilities
   → Web/API flaws in SmartThings, Hue Bridge
   → Compromise hub = compromise entire network
```

---

## 3. Lab: Zigbee2MQTT Packet Monitoring

### Required Hardware

```
Option A ($30): CC2531 USB dongle
  - Requires flashing sniffer firmware
  - Works with Wireshark

Option B (recommended, $20): SONOFF Zigbee 3.0 USB Dongle Plus
  - CC2652P chip — no manual firmware flash needed
  - Works seamlessly with Zigbee2MQTT
```

### Zigbee2MQTT Setup

```bash
# Install Node.js and Zigbee2MQTT
sudo mkdir /opt/zigbee2mqtt
sudo chown -R $USER: /opt/zigbee2mqtt
git clone --depth 1 https://github.com/Koenkk/zigbee2mqtt.git /opt/zigbee2mqtt
cd /opt/zigbee2mqtt && npm ci

# Install MQTT broker
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl start mosquitto

# Run Zigbee2MQTT
cd /opt/zigbee2mqtt && npm start

# Listen for all Zigbee messages
mosquitto_sub -t "zigbee2mqtt/#" -v
```

### Python Scanner

```bash
pip install paho-mqtt

# Scan channels (info + recommendations)
python3 zigbee_scanner.py --scan-channels

# Monitor Zigbee2MQTT messages for 60 seconds
python3 zigbee_scanner.py --monitor-mqtt --duration 60 --output devices.json

# Analyze discovered devices for security issues
python3 zigbee_scanner.py --analyze-devices --output devices.json
```

See the Korean section for the complete Python 3.10+ script with type hints.

---

## 4. Z-Wave Protocol Vulnerabilities

```
Z-Wave Security 0 (S0) Key Exchange Flaw:
  1. During pairing, network key is encrypted with all-zeros TEK
  2. Attacker captures the pairing packet
  3. Decrypts with all-zeros key → obtains network key
  4. All future traffic decryptable

  Fix: Upgrade to Z-Wave Security 2 (S2) using ECDH key exchange

Z-Wave frequencies by region:
  EU: 868 MHz  |  US: 908 MHz  |  Korea: 916 MHz
```

---

## 5. Smart Home Attack Scenario

```
Scenario: Smart door lock on Z-Wave S0 (legacy)

  Step 1: Reconnaissance
    → Detect Z-Wave signals at 908 MHz
    → Capture key exchange during pairing window

  Step 2: Decryption
    → Use S0 flaw to extract Network Key
    → Decrypt all lock/unlock commands

  Step 3: Replay
    → Replay captured "unlock" command
    → Door opens

  Defense: Upgrade to Z-Wave S2; shield RF during installation
```
