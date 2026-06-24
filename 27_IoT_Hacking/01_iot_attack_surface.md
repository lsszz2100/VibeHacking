> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01. IoT 공격 면 분석 (Attack Surface Analysis)

## 0. 초보자를 위한 개념 이해

### IoT 공격 면이란?

IoT(Internet of Things)는 인터넷에 연결된 스마트 기기들의 집합이다. 공격 면(Attack Surface)은 공격자가 기기에 침투할 수 있는 모든 진입점의 총합이다. 일반 PC와 달리 IoT 기기는 펌웨어 업데이트가 어렵고, 기본 자격증명이 변경되지 않는 경우가 많으며, 물리적 인터페이스(UART, JTAG)가 노출되어 있는 경우가 많다.

**왜 배우는가:**
```
IoT 기기의 독특한 보안 문제

[일반 PC]
  OS 자동 업데이트 가능
  보안 소프트웨어 설치 가능
  사용자가 보안 인식 있음

[IoT 기기]
  펌웨어 업데이트 수동/불가능 → 취약점 방치
  기본 ID/PW 변경 안 함     → admin/admin
  물리적 포트 노출           → UART로 직접 셸 접근
  인터넷 직접 연결           → Shodan으로 발견 가능
  수명 10년+                 → 지원 종료 후에도 운영
```

### 핵심 개념 정리

```
IoT 공격 벡터 분류

공격 경로          구체적 방법              필요 장비
─────────────────────────────────────────────────────
물리 (UART)        디버그 콘솔 접근          USB-UART 어댑터
물리 (JTAG)        메모리 직접 읽기/쓰기     JTAG 디버거
네트워크           텔넷/SSH 기본 자격증명    네트워크 접근
웹 인터페이스      관리 페이지 취약점        브라우저
무선 (RF/Zigbee)   신호 스니핑·재전송        SDR 하드웨어
클라우드 API       인증 취약점               인터넷 접근
모바일 앱          APK 분석, API 엔드포인트  Android 기기
```

### 필요한 도구 및 환경
- **USB-UART 어댑터**: CH340, CP2102, FTDI 계열 (약 2,000~5,000원)
- **minicom / screen**: UART 터미널 (`apt install minicom`)
- **nmap**: 네트워크 서비스 스캔
- **binwalk**: 펌웨어 분석 (`pip install binwalk`)

### 기초 실습 예제
```bash
# 1. 네트워크의 IoT 기기 발견 (안전 — 자신의 네트워크)
# 텔넷(23), SSH(22), HTTP(80), HTTPS(443), MQTT(1883) 스캔
nmap -T4 -p 22,23,80,443,1883,8080,8883 192.168.1.0/24

# 2. 기본 자격증명 테스트 (Telnet)
# 실제로는 자신의 기기에서만 테스트
# telnet <기기 IP>
# 로그인: admin/admin, admin/password, root/root 등 시도

# 3. HTTP 관리 페이지 접근 확인
curl -s http://192.168.1.1/          # 공유기 관리 페이지
curl -s http://192.168.1.1/cgi-bin/  # CGI 엔드포인트

# 4. MQTT 브로커 접근 테스트
# mqtt-explorer (GUI) 또는 mosquitto_sub
mosquitto_sub -h <IP> -t "#" -v     # 모든 토픽 구독
```

---

## 개요

IoT 기기는 임베디드 OS, 독점 프로토콜, 취약한 기본 설정이 결합되어 광범위한 공격 면을 가진다.
분석 대상: 펌웨어, 물리 인터페이스(UART/JTAG), 네트워크 프로토콜(MQTT/CoAP), 클라우드 API, 모바일 앱 연동.

---

## 1. 물리 인터페이스 공격 면

### 1.1 UART (Universal Asynchronous Receiver-Transmitter)

UART는 임베디드 기기에서 디버그 콘솔로 가장 흔하게 노출된다.

```
# 필요 장비: USB-UART 어댑터 (CH340, CP2102, FTDI)
# 일반 전압: 3.3V (일부 기기 1.8V - 반드시 확인)

# 보드 핀 식별
# - GND: 멀티미터로 연속성 테스트
# - VCC: 3.3V 또는 5V
# - TX: 데이터 송신 (오실로스코프로 신호 확인)
# - RX: 데이터 수신

# minicom 연결
minicom -D /dev/ttyUSB0 -b 115200

# screen 연결
screen /dev/ttyUSB0 115200

# 일반 UART 보드레이트
# 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600

# 보드레이트 자동 탐지 (여러 속도 시도)
for baud in 9600 19200 38400 57600 115200 230400; do
    echo "Testing $baud..."
    timeout 3 stty -F /dev/ttyUSB0 $baud && \
    timeout 3 cat /dev/ttyUSB0 | xxd | head -5
done
```

### 1.2 JTAG (Joint Test Action Group)

JTAG는 칩 레벨 디버깅 인터페이스로 메모리 읽기/쓰기, 실행 제어가 가능하다.

```
# OpenOCD로 JTAG 연결
# 설정 파일 예시: target.cfg
# source [find interface/ftdi/jlink.cfg]
# transport select jtag
# source [find target/at91sam9g20.cfg]

openocd -f interface/jlink.cfg -f target/stm32f1x.cfg

# Telnet으로 OpenOCD 제어
telnet localhost 4444

# 메모리 덤프
> dump_image /tmp/firmware.bin 0x08000000 0x100000

# 레지스터 읽기
> reg

# 실행 중단
> halt

# 단계 실행
> step

# JTAG 핀 탐지 도구: JTAGulator
# https://github.com/grandideastudio/jtagulator
```

### 1.3 SPI/I2C 플래시 메모리 직접 덤프

```
# flashrom으로 SPI 플래시 읽기
flashrom -p ch341a_spi -r firmware_dump.bin

# 특정 칩 지정
flashrom -p ch341a_spi -c "W25Q64BV/W25Q64CV" -r firmware_dump.bin

# I2C EEPROM 읽기
i2cdump -y 1 0x50
i2cget -y 1 0x50 0x00 w
```

---

## 2. 펌웨어 추출 — binwalk 실전

### 2.1 기본 분석

```bash
# 펌웨어 정보 스캔
binwalk firmware.bin

# 재귀 추출 (자동으로 내부 파일시스템 추출)
binwalk -e --run-as=root firmware.bin

# 엔트로피 분석 (암호화/압축 영역 탐지)
binwalk -E firmware.bin

# 서명 스캔 + 추출 + 재귀
binwalk -Me firmware.bin

# 예시 출력 해석:
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           DLOB firmware header
# 116       0x74          LZMA compressed data
# 1048576   0x100000      Squashfs filesystem, LE, v4.0
```

### 2.2 파일시스템 마운트

```bash
# squashfs 마운트
unsquashfs -d /tmp/squashfs_root squashfs.img
mount -o loop squashfs.img /mnt/squashfs  # 대안

# cramfs 마운트
mount -t cramfs -o loop cramfs.img /mnt/cramfs

# JFFS2 마운트
modprobe mtdram total_size=65536 erase_size=256
modprobe mtdblock
dd if=jffs2.img of=/dev/mtd0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2

# ubifs (NAND 플래시)
modprobe ubi mtd=/dev/mtd0
ubiattach /dev/ubi_ctrl -m 0
mount -t ubifs /dev/ubi0_0 /mnt/ubifs
```

---

## 3. 기본 자격증명 스캔

### 3.1 알려진 IoT 기본 자격증명 목록

```
admin:admin
admin:password
admin:1234
admin:12345
admin:(blank)
root:root
root:toor
root:alpine
root:admin
user:user
guest:guest
support:support
telnetadmin:telnetadmin
```

### 3.2 Telnet/SSH 자격증명 테스트

```bash
# nmap으로 Telnet/SSH 서비스 탐지
nmap -p 22,23,80,443,8080 192.168.1.0/24 --open -sV

# hydra로 SSH 브루트포스 (알려진 자격증명)
hydra -L iot_users.txt -P iot_passwords.txt ssh://192.168.1.1

# hydra로 Telnet 브루트포스
hydra -L iot_users.txt -P iot_passwords.txt telnet://192.168.1.1

# medusa 대안
medusa -h 192.168.1.1 -U iot_users.txt -P iot_passwords.txt -M telnet
```

---

## 4. Shodan IoT 검색

### 4.1 Shodan 검색 쿼리 (Dorks)

```
# 기본 IoT 장치 검색
port:23 telnet                          # 텔넷 노출
port:8080 login                         # 웹 인터페이스
"Server: GoAhead-Webs"                  # 임베디드 웹 서버
"Server: thttpd"                        # 경량 HTTP
"default password" port:80              # 기본 패스워드 언급

# 카메라
"webcamXP" port:8080
"IP Camera" port:554                    # RTSP
"/view/view.shtml" port:80              # Axis 카메라
"Server: DVRDVS-Webs" port:80          # DVR

# 라우터/공유기
"Router" port:80 country:KR
"DD-WRT" port:80
"OpenWrt" port:80
"MikroTik" port:8291                    # Winbox

# 산업용 제어 시스템
port:502                                # Modbus
port:102                                # Siemens S7
port:44818                              # EtherNet/IP
"SCADA" port:80

# MQTT 브로커
port:1883                               # MQTT (비인증)
port:8883                               # MQTT over TLS

# CoAP
port:5683                               # CoAP UDP

# Zigbee/Z-Wave 게이트웨이
"Zigbee2MQTT" port:8080
"Home Assistant" port:8123
```

---

## 5. MQTT 프로토콜 취약점

### 5.1 MQTT 기초

```
MQTT 토픽 구조:
home/livingroom/temperature
home/+/temperature       # + : 단일 레벨 와일드카드
home/#                   # # : 다중 레벨 와일드카드
$SYS/#                   # 브로커 시스템 정보
```

### 5.2 mosquitto_sub/pub 실전

```bash
# 익명 연결 (인증 없음)
mosquitto_sub -h 192.168.1.100 -p 1883 -t '#' -v

# 모든 토픽 구독 (취약한 브로커)
mosquitto_sub -h target.com -t '#' -v --retained-only

# $SYS 토픽으로 브로커 정보 수집
mosquitto_sub -h 192.168.1.100 -t '$SYS/#' -v

# 메시지 발행 (명령 주입 시도)
mosquitto_pub -h 192.168.1.100 -t 'home/switch/set' -m 'ON'

# 자격증명 사용
mosquitto_sub -h target.com -u admin -P admin123 -t '#' -v

# TLS 연결
mosquitto_sub -h target.com -p 8883 --cafile ca.crt -t '#' -v
```

### 5.3 CoAP 취약점 탐지

```bash
# libcoap 설치 후
# coap-client 사용

# 리소스 탐색 (CoAP 디스커버리)
coap-client -m get coap://192.168.1.1/.well-known/core

# GET 요청
coap-client -m get coap://192.168.1.1/sensors/temperature

# PUT으로 설정 변경
coap-client -m put -e '{"value": "OFF"}' coap://192.168.1.1/actuators/switch

# 관찰(Observe) - 지속 모니터링
coap-client -m get -s 60 coap://192.168.1.1/sensors/temperature
```

---

## 6. Python CLI 도구 — IoT 공격 면 스캐너

### 6.1 Shodan IoT 스캐너

```python
#!/usr/bin/env python3
"""
IoT Attack Surface Scanner — Shodan 기반 IoT 장치 열거 도구
사용법: python3 iot_scanner.py shodan --query "port:1883" --api-key YOUR_KEY
"""

import argparse
import json
import sys
import time
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class IoTDevice:
    ip: str
    port: int
    hostname: str = ""
    org: str = ""
    country: str = ""
    product: str = ""
    version: str = ""
    cpe: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    risk_score: int = 0
    findings: list[str] = field(default_factory=list)


@dataclass
class MQTTBrokerInfo:
    ip: str
    port: int
    anonymous_access: bool = False
    broker_version: str = ""
    topics_discovered: list[str] = field(default_factory=list)
    sys_info: dict[str, str] = field(default_factory=dict)
    risk_level: str = "unknown"


# ── Shodan 스캐너 ─────────────────────────────────────────────────────────────

class ShodanIoTScanner:
    """Shodan API를 이용한 IoT 장치 열거"""

    RISK_INDICATORS = {
        "telnet": 8,
        "default password": 9,
        "admin:admin": 10,
        "GoAhead-Webs": 6,
        "thttpd": 5,
        "boa": 5,
        "lighttpd": 3,
        "DVRDVS": 7,
        "webcam": 6,
        "SCADA": 9,
        "Modbus": 9,
        "BACnet": 8,
    }

    IOT_QUERIES = {
        "mqtt_open":      "port:1883",
        "telnet_iot":     "port:23 telnet",
        "cameras":        '"IP Camera" port:554',
        "routers":        '"Router Webserver" port:80',
        "embedded_web":   '"Server: GoAhead-Webs"',
        "dvr":            '"DVRDVS-Webs" port:80',
        "home_assistant": '"Home Assistant" port:8123',
        "upnp":           'port:1900 "UPnP"',
        "modbus":         "port:502",
        "s7":             "port:102",
    }

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._shodan = None

    def _get_shodan(self):
        if self._shodan is None:
            try:
                import shodan
            except ImportError:
                print("[!] shodan 라이브러리 없음: pip install shodan", file=sys.stderr)
                sys.exit(1)
            self._shodan = shodan.Shodan(self.api_key)
        return self._shodan

    def _calculate_risk(self, device_data: dict) -> tuple[int, list[str]]:
        score = 0
        findings: list[str] = []
        banner = str(device_data.get("data", "")).lower()
        product = str(device_data.get("product", "")).lower()

        for indicator, weight in self.RISK_INDICATORS.items():
            if indicator.lower() in banner or indicator.lower() in product:
                score += weight
                findings.append(f"위험 지표 발견: '{indicator}' (점수 +{weight})")

        port = device_data.get("port", 0)
        if port == 23:
            score += 8
            findings.append("Telnet 포트 23 노출 (암호화 없음)")
        if port == 502:
            score += 9
            findings.append("Modbus/TCP 포트 502 노출 (ICS 프로토콜)")
        if port == 102:
            score += 9
            findings.append("Siemens S7 포트 102 노출")

        vulns = device_data.get("vulns", {})
        if vulns:
            score += len(vulns) * 3
            findings.append(f"알려진 CVE {len(vulns)}개: {', '.join(list(vulns.keys())[:5])}")

        return min(score, 10), findings

    def search(self, query: str, limit: int = 100) -> list[IoTDevice]:
        api = self._get_shodan()
        devices: list[IoTDevice] = []

        try:
            print(f"[*] Shodan 검색: {query}")
            results = api.search(query, limit=limit)
            total = results.get("total", 0)
            print(f"[*] 총 {total}개 결과 (최대 {limit}개 처리)")

            for match in results.get("matches", []):
                risk_score, findings = self._calculate_risk(match)
                device = IoTDevice(
                    ip=match.get("ip_str", ""),
                    port=match.get("port", 0),
                    hostname=", ".join(match.get("hostnames", [])),
                    org=match.get("org", ""),
                    country=match.get("location", {}).get("country_name", ""),
                    product=match.get("product", ""),
                    version=match.get("version", ""),
                    cpe=match.get("cpe", []),
                    vulns=list(match.get("vulns", {}).keys()),
                    risk_score=risk_score,
                    findings=findings,
                )
                devices.append(device)

        except Exception as exc:
            print(f"[!] Shodan 오류: {exc}", file=sys.stderr)

        return sorted(devices, key=lambda d: d.risk_score, reverse=True)

    def search_preset(self, preset: str, limit: int = 100) -> list[IoTDevice]:
        if preset not in self.IOT_QUERIES:
            available = ", ".join(self.IOT_QUERIES.keys())
            print(f"[!] 알 수 없는 프리셋: {preset}\n사용 가능: {available}")
            sys.exit(1)
        return self.search(self.IOT_QUERIES[preset], limit=limit)

    def get_host_details(self, ip: str) -> dict:
        api = self._get_shodan()
        try:
            return api.host(ip)
        except Exception as exc:
            print(f"[!] 호스트 조회 실패 {ip}: {exc}", file=sys.stderr)
            return {}


# ── MQTT 브로커 열거 ──────────────────────────────────────────────────────────

class MQTTEnumerator:
    """MQTT 브로커 취약점 열거 도구"""

    CONNECT_PACKET = bytes([
        0x10,       # CONNECT 패킷 타입
        0x1b,       # Remaining Length = 27
        0x00, 0x04, # Protocol Name Length
        0x4d, 0x51, 0x54, 0x54,  # "MQTT"
        0x04,       # Protocol Level (3.1.1)
        0x02,       # Connect Flags (Clean Session)
        0x00, 0x3c, # Keep Alive = 60s
        0x00, 0x0f, # Client ID Length
        0x69, 0x6f, 0x74, 0x5f, 0x73, 0x63, 0x61,
        0x6e, 0x6e, 0x65, 0x72, 0x5f, 0x30, 0x30, 0x31,  # "iot_scanner_001"
    ])

    SUBSCRIBE_ALL = bytes([
        0x82,       # SUBSCRIBE 패킷
        0x08,       # Remaining Length
        0x00, 0x01, # Packet ID
        0x00, 0x01, # Topic Filter Length
        0x23,       # '#' (와일드카드)
        0x00,       # QoS 0
    ])

    SUBSCRIBE_SYS = bytes([
        0x82,       # SUBSCRIBE 패킷
        0x0c,       # Remaining Length
        0x00, 0x02, # Packet ID
        0x00, 0x05, # Topic Filter Length
        0x24, 0x53, 0x59, 0x53, 0x2f,  # "$SYS/"
        0x23,       # '#'
        0x00,       # QoS 0
    ])

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _raw_connect(self, ip: str, port: int) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(self.CONNECT_PACKET)
            response = sock.recv(4)
            # CONNACK: 0x20 0x02 0x00 0x00 (연결 수락)
            if len(response) >= 4 and response[0] == 0x20 and response[3] == 0x00:
                return sock
            sock.close()
            return None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _parse_publish(self, data: bytes) -> Optional[tuple[str, bytes]]:
        """PUBLISH 패킷 파싱 → (topic, payload)"""
        if not data or data[0] != 0x30 and (data[0] & 0xF0) != 0x30:
            return None
        try:
            idx = 1
            multiplier, remaining = 1, 0
            while True:
                byte = data[idx]; idx += 1
                remaining += (byte & 0x7F) * multiplier
                multiplier *= 128
                if not (byte & 0x80):
                    break
            topic_len = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2
            topic = data[idx:idx+topic_len].decode("utf-8", errors="replace")
            idx += topic_len
            payload = data[idx:idx+remaining]
            return topic, payload
        except Exception:
            return None

    def check_anonymous(self, ip: str, port: int = 1883) -> bool:
        sock = self._raw_connect(ip, port)
        if sock:
            sock.close()
            return True
        return False

    def enumerate_topics(self, ip: str, port: int = 1883,
                         duration: float = 10.0) -> MQTTBrokerInfo:
        info = MQTTBrokerInfo(ip=ip, port=port)
        sock = self._raw_connect(ip, port)

        if not sock:
            info.risk_level = "inaccessible"
            return info

        info.anonymous_access = True
        topics_seen: set[str] = set()

        try:
            sock.sendall(self.SUBSCRIBE_ALL)
            sock.sendall(self.SUBSCRIBE_SYS)
            sock.settimeout(2.0)

            end_time = time.monotonic() + duration
            buffer = b""

            while time.monotonic() < end_time:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk

                    while len(buffer) >= 2:
                        result = self._parse_publish(buffer)
                        if result:
                            topic, payload = result
                            topics_seen.add(topic)
                            if topic.startswith("$SYS/"):
                                key = topic.split("/")[-1]
                                info.sys_info[key] = payload.decode("utf-8", errors="replace")[:200]
                            # 다음 패킷으로 이동 (단순 구현)
                            buffer = buffer[max(4, len(buffer)//2):]
                        else:
                            break
                except socket.timeout:
                    continue

        except OSError:
            pass
        finally:
            sock.close()

        info.topics_discovered = sorted(topics_seen)
        info.broker_version = info.sys_info.get("version", "unknown")

        if info.anonymous_access and len(info.topics_discovered) > 10:
            info.risk_level = "critical"
        elif info.anonymous_access:
            info.risk_level = "high"
        else:
            info.risk_level = "medium"

        return info

    def scan_range(self, cidr: str, port: int = 1883,
                   workers: int = 50) -> list[MQTTBrokerInfo]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            print(f"[!] 잘못된 CIDR: {exc}", file=sys.stderr)
            sys.exit(1)

        hosts = list(network.hosts())
        print(f"[*] MQTT 스캔: {cidr} ({len(hosts)}개 호스트, 포트 {port})")
        results: list[MQTTBrokerInfo] = []

        def check_host(ip_obj) -> Optional[MQTTBrokerInfo]:
            ip = str(ip_obj)
            if self.check_anonymous(ip, port):
                print(f"  [+] MQTT 브로커 발견: {ip}:{port}")
                return self.enumerate_topics(ip, port, duration=5.0)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_host, h): h for h in hosts}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    results.append(result)

        return sorted(results, key=lambda r: len(r.topics_discovered), reverse=True)


# ── 출력 포맷터 ───────────────────────────────────────────────────────────────

def print_device_table(devices: list[IoTDevice]) -> None:
    if not devices:
        print("[*] 결과 없음")
        return
    print(f"\n{'IP':18} {'포트':6} {'위험':5} {'제품':25} {'국가':12} {'CVE':6}")
    print("-" * 80)
    for d in devices:
        cve_cnt = len(d.vulns)
        print(f"{d.ip:18} {d.port:<6} {d.risk_score:<5} {d.product[:25]:25} {d.country[:12]:12} {cve_cnt:<6}")
    print(f"\n총 {len(devices)}개 장치")


def print_mqtt_info(info: MQTTBrokerInfo) -> None:
    risk_colors = {"critical": "위험", "high": "높음", "medium": "보통", "inaccessible": "접근불가"}
    print(f"\n[MQTT 브로커] {info.ip}:{info.port}")
    print(f"  익명 접근: {'가능' if info.anonymous_access else '불가'}")
    print(f"  위험 수준: {risk_colors.get(info.risk_level, info.risk_level)}")
    print(f"  버전: {info.broker_version}")
    print(f"  발견 토픽 수: {len(info.topics_discovered)}")
    if info.topics_discovered[:20]:
        print("  토픽 (최대 20개):")
        for t in info.topics_discovered[:20]:
            print(f"    - {t}")
    if info.sys_info:
        print("  $SYS 정보:")
        for k, v in list(info.sys_info.items())[:10]:
            print(f"    {k}: {v}")


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iot_scanner",
        description="IoT 공격 면 스캐너 — Shodan 검색 & MQTT 브로커 열거",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # shodan 서브커맨드
    p_shodan = sub.add_parser("shodan", help="Shodan으로 IoT 장치 검색")
    p_shodan.add_argument("--api-key", required=True, help="Shodan API 키")
    p_shodan.add_argument("--query", help="커스텀 Shodan 검색 쿼리")
    p_shodan.add_argument("--preset", choices=[
        "mqtt_open", "telnet_iot", "cameras", "routers",
        "embedded_web", "dvr", "home_assistant", "upnp", "modbus", "s7"
    ], help="사전 정의 검색 프리셋")
    p_shodan.add_argument("--limit", type=int, default=100, help="최대 결과 수 (기본 100)")
    p_shodan.add_argument("--output", choices=["table", "json"], default="table")
    p_shodan.add_argument("--save", help="JSON 결과 저장 경로")

    # mqtt 서브커맨드
    p_mqtt = sub.add_parser("mqtt", help="MQTT 브로커 열거")
    p_mqtt.add_argument("--target", required=True, help="단일 IP 또는 CIDR (예: 192.168.1.0/24)")
    p_mqtt.add_argument("--port", type=int, default=1883, help="MQTT 포트 (기본 1883)")
    p_mqtt.add_argument("--duration", type=float, default=10.0, help="토픽 수집 시간(초)")
    p_mqtt.add_argument("--workers", type=int, default=50, help="병렬 스캔 워커 수")
    p_mqtt.add_argument("--timeout", type=float, default=3.0, help="소켓 타임아웃(초)")
    p_mqtt.add_argument("--output", choices=["text", "json"], default="text")
    p_mqtt.add_argument("--save", help="JSON 결과 저장 경로")

    return parser


def cmd_shodan(args: argparse.Namespace) -> None:
    scanner = ShodanIoTScanner(args.api_key)
    if args.query:
        devices = scanner.search(args.query, limit=args.limit)
    elif args.preset:
        devices = scanner.search_preset(args.preset, limit=args.limit)
    else:
        print("[!] --query 또는 --preset 중 하나를 지정하세요.", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(json.dumps([asdict(d) for d in devices], ensure_ascii=False, indent=2))
    else:
        print_device_table(devices)
        for d in devices:
            if d.findings:
                print(f"\n[{d.ip}:{d.port}] 발견 사항:")
                for f in d.findings:
                    print(f"  - {f}")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fp:
            json.dump([asdict(d) for d in devices], fp, ensure_ascii=False, indent=2)
        print(f"\n[*] 결과 저장: {args.save}")


def cmd_mqtt(args: argparse.Namespace) -> None:
    enumerator = MQTTEnumerator(timeout=args.timeout)

    # 단일 IP vs CIDR 판별
    try:
        ipaddress.ip_address(args.target)
        is_single = True
    except ValueError:
        is_single = False

    results: list[MQTTBrokerInfo] = []

    if is_single:
        print(f"[*] 단일 MQTT 브로커 열거: {args.target}:{args.port}")
        info = enumerator.enumerate_topics(args.target, args.port, args.duration)
        results.append(info)
    else:
        results = enumerator.scan_range(args.target, args.port, args.workers)

    if args.output == "json":
        print(json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2))
    else:
        for info in results:
            print_mqtt_info(info)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fp:
            json.dump([asdict(r) for r in results], fp, ensure_ascii=False, indent=2)
        print(f"\n[*] 결과 저장: {args.save}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "shodan": cmd_shodan,
        "mqtt": cmd_mqtt,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
```

### 6.2 실행 예시

```bash
# 설치
pip install shodan paho-mqtt

# Shodan — 오픈 MQTT 브로커 검색
python3 iot_scanner.py shodan \
    --api-key YOUR_SHODAN_KEY \
    --preset mqtt_open \
    --limit 200 \
    --output table \
    --save mqtt_results.json

# Shodan — 커스텀 쿼리
python3 iot_scanner.py shodan \
    --api-key YOUR_SHODAN_KEY \
    --query 'port:23 country:KR "login"' \
    --limit 50

# MQTT — 단일 브로커 열거 (10초간 토픽 수집)
python3 iot_scanner.py mqtt \
    --target 192.168.1.100 \
    --port 1883 \
    --duration 10.0 \
    --output text

# MQTT — 서브넷 전체 스캔
python3 iot_scanner.py mqtt \
    --target 10.0.0.0/24 \
    --port 1883 \
    --workers 100 \
    --save mqtt_scan.json

# 결과 JSON 분석
python3 -c "
import json
with open('mqtt_results.json') as f:
    data = json.load(f)
critical = [d for d in data if d.get('risk_level') == 'critical']
print(f'위험(Critical) 브로커: {len(critical)}개')
for d in critical:
    print(f'  {d[\"ip\"]}:{d[\"port\"]} — 토픽 {len(d[\"topics_discovered\"])}개')
"
```

---

## 7. 공격 면 체크리스트

```
물리 인터페이스
□ UART 포트 식별 및 접근 시도
□ JTAG 핀 탐지 (JTAGulator 사용)
□ SPI/I2C 플래시 메모리 직접 덤프
□ 디버그 패드 노출 여부

네트워크 서비스
□ 개방 포트 스캔 (nmap -sV -p- target)
□ Telnet(23), SSH(22), HTTP(80/8080), HTTPS(443) 확인
□ MQTT(1883), CoAP(5683), UPnP(1900) 확인
□ 기본 자격증명 테스트

펌웨어
□ 펌웨어 다운로드 가능 여부 (공개 소스)
□ binwalk 분석 — 파일시스템 유형
□ 하드코딩된 자격증명 검색
□ 개인키/인증서 포함 여부

클라우드/API
□ 모바일 앱 API 엔드포인트 분석
□ 인증 토큰 처리 방식
□ TLS 설정 검증 (인증서 검증 우회 여부)
□ API 인증 없이 접근 가능한 엔드포인트

업데이트 메커니즘
□ OTA 업데이트 서명 검증 여부
□ HTTP로 펌웨어 다운로드 시 MITM 가능성
□ 롤백 방지 메커니즘 존재 여부
```

---

## 참고 명령어 모음

```bash
# 네트워크 IoT 장치 빠른 탐지
nmap -sV -p 22,23,80,443,1883,5683,8080,8443,8883 --open 192.168.1.0/24

# UPnP 장치 탐색
nmap -sU -p 1900 --script upnp-info 192.168.1.0/24

# RTSP 카메라 스트림 탐지
nmap -p 554 --script rtsp-url-brute 192.168.1.0/24

# SNMP 커뮤니티 문자열 브루트포스
nmap -sU -p 161 --script snmp-brute 192.168.1.1

# WPS 취약점 스캔 (무선 라우터)
wash -i wlan0mon

# 블루투스 LE 장치 스캔
hcitool lescan
gatttool -b AA:BB:CC:DD:EE:FF --interactive
```

---

<!-- detect-validate-27 -->
## IoT 공격면 탐지와 방어 검증

IoT는 *기본 자격증명·노출 서비스·평문 통신·미갱신 펌웨어*로 공격면이 넓다. 방어자는 **자체 디바이스의 노출 표면과 통신이 안전한가**를 검증해야 한다. 검증은 **소유 디바이스/망**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 기본 자격증명 | 미변경 비번 | 강제 변경·고유 키 | 기본계정 로그인 시도 |
| 노출 서비스(telnet/UPnP) | 불필요 포트 | 포트 최소화·격리 | 외부서 23/1900 응답 |
| 평문 통신 | 암호화 부재 | TLS·VPN | 평문 자격증명 캡처 |
| 미갱신 펌웨어 | 알려진 CVE | OTA 갱신·SBOM | 구버전 배너 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 IoT 노출 표면 점검(소유 망) — telnet/UPnP 등 불필요 서비스
nmap -sV -p 23,80,1900,5000,8080 --open 192.168.1.0/24 2>/dev/null | grep -iE "open|telnet|upnp"
# 2) 평문 자격증명 노출 점검 — 디바이스 트래픽에 평문 인증이 흐르는지(소유 망)
sudo tshark -i eth0 -Y "http.authorization || telnet" -a duration:20 2>/dev/null | head
```

> IoT 방어는 *노출 표면이 좁고 통신이 암호화됐는가*다 — "디바이스 동작한다"와 "telnet이 닫혀 있고 평문 자격증명이 안 흐른다"는 다르다. 소유 망에서 노출 포트·평문 인증을 직접 확인한다([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# 01. IoT Attack Surface Analysis

## Overview

IoT devices have a broad attack surface due to the combination of embedded OS, proprietary protocols, and weak default configurations. Analysis targets include: firmware, physical interfaces (UART/JTAG), network protocols (MQTT/CoAP), cloud APIs, and mobile app integration.

---

## 1. Physical Interface Attack Surface

### 1.1 UART (Universal Asynchronous Receiver-Transmitter)

UART is most commonly exposed as a debug console in embedded devices.

```
# Required hardware: USB-UART adapter (CH340, CP2102, FTDI)
# Common voltage: 3.3V (some devices use 1.8V — verify first)

# Board pin identification
# - GND: Continuity test with multimeter
# - VCC: 3.3V or 5V
# - TX: Data transmit (check signal with oscilloscope)
# - RX: Data receive

# Connect with minicom
minicom -D /dev/ttyUSB0 -b 115200

# Connect with screen
screen /dev/ttyUSB0 115200

# Common UART baud rates
# 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600

# Auto-detect baud rate (try multiple speeds)
for baud in 9600 19200 38400 57600 115200 230400; do
    echo "Testing $baud..."
    timeout 3 stty -F /dev/ttyUSB0 $baud && \
    timeout 3 cat /dev/ttyUSB0 | xxd | head -5
done
```

### 1.2 JTAG (Joint Test Action Group)

JTAG is a chip-level debugging interface that allows reading/writing memory and controlling execution.

```
# Connect JTAG with OpenOCD
# Example config file: target.cfg
# source [find interface/ftdi/jlink.cfg]
# transport select jtag
# source [find target/at91sam9g20.cfg]

openocd -f interface/jlink.cfg -f target/stm32f1x.cfg

# Control OpenOCD via Telnet
telnet localhost 4444

# Dump memory
> dump_image /tmp/firmware.bin 0x08000000 0x100000

# Read registers
> reg

# Halt execution
> halt

# Step execution
> step

# JTAG pin detection tool: JTAGulator
# https://github.com/grandideastudio/jtagulator
```

### 1.3 SPI/I2C Flash Memory Direct Dump

```
# Read SPI flash with flashrom
flashrom -p ch341a_spi -r firmware_dump.bin

# Specify chip
flashrom -p ch341a_spi -c "W25Q64BV/W25Q64CV" -r firmware_dump.bin

# Read I2C EEPROM
i2cdump -y 1 0x50
i2cget -y 1 0x50 0x00 w
```

---

## 2. Firmware Extraction — binwalk in Practice

### 2.1 Basic Analysis

```bash
# Scan firmware information
binwalk firmware.bin

# Recursive extraction (automatically extracts internal filesystems)
binwalk -e --run-as=root firmware.bin

# Entropy analysis (detects encrypted/compressed regions)
binwalk -E firmware.bin

# Signature scan + extract + recursive
binwalk -Me firmware.bin

# Example output interpretation:
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           DLOB firmware header
# 116       0x74          LZMA compressed data
# 1048576   0x100000      Squashfs filesystem, LE, v4.0
```

### 2.2 Filesystem Mounting

```bash
# Mount squashfs
unsquashfs -d /tmp/squashfs_root squashfs.img
mount -o loop squashfs.img /mnt/squashfs  # alternative

# Mount cramfs
mount -t cramfs -o loop cramfs.img /mnt/cramfs

# Mount JFFS2
modprobe mtdram total_size=65536 erase_size=256
modprobe mtdblock
dd if=jffs2.img of=/dev/mtd0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2

# ubifs (NAND flash)
modprobe ubi mtd=/dev/mtd0
ubiattach /dev/ubi_ctrl -m 0
mount -t ubifs /dev/ubi0_0 /mnt/ubifs
```

---

## 3. Default Credential Scanning

### 3.1 Known IoT Default Credentials

```
admin:admin
admin:password
admin:1234
admin:12345
admin:(blank)
root:root
root:toor
root:alpine
root:admin
user:user
guest:guest
support:support
telnetadmin:telnetadmin
```

### 3.2 Telnet/SSH Credential Testing

```bash
# Detect Telnet/SSH services with nmap
nmap -p 22,23,80,443,8080 192.168.1.0/24 --open -sV

# SSH brute force with hydra (known credentials)
hydra -L iot_users.txt -P iot_passwords.txt ssh://192.168.1.1

# Telnet brute force with hydra
hydra -L iot_users.txt -P iot_passwords.txt telnet://192.168.1.1

# medusa alternative
medusa -h 192.168.1.1 -U iot_users.txt -P iot_passwords.txt -M telnet
```

---

## 4. Shodan IoT Search

### 4.1 Shodan Search Queries (Dorks)

```
# Basic IoT device search
port:23 telnet                          # Telnet exposed
port:8080 login                         # Web interface
"Server: GoAhead-Webs"                  # Embedded web server
"Server: thttpd"                        # Lightweight HTTP
"default password" port:80              # Default password mention

# Cameras
"webcamXP" port:8080
"IP Camera" port:554                    # RTSP
"/view/view.shtml" port:80              # Axis cameras
"Server: DVRDVS-Webs" port:80          # DVR

# Routers
"Router" port:80 country:KR
"DD-WRT" port:80
"OpenWrt" port:80
"MikroTik" port:8291                    # Winbox

# Industrial Control Systems
port:502                                # Modbus
port:102                                # Siemens S7
port:44818                              # EtherNet/IP
"SCADA" port:80

# MQTT brokers
port:1883                               # MQTT (unauthenticated)
port:8883                               # MQTT over TLS

# CoAP
port:5683                               # CoAP UDP

# Zigbee/Z-Wave gateways
"Zigbee2MQTT" port:8080
"Home Assistant" port:8123
```

---

## 5. MQTT Protocol Vulnerabilities

### 5.1 MQTT Basics

```
MQTT Topic Structure:
home/livingroom/temperature
home/+/temperature       # + : single-level wildcard
home/#                   # # : multi-level wildcard
$SYS/#                   # broker system information
```

### 5.2 mosquitto_sub/pub in Practice

```bash
# Anonymous connection (no authentication)
mosquitto_sub -h 192.168.1.100 -p 1883 -t '#' -v

# Subscribe to all topics (vulnerable broker)
mosquitto_sub -h target.com -t '#' -v --retained-only

# Collect broker information via $SYS topics
mosquitto_sub -h 192.168.1.100 -t '$SYS/#' -v

# Publish a message (attempt command injection)
mosquitto_pub -h 192.168.1.100 -t 'home/switch/set' -m 'ON'

# With credentials
mosquitto_sub -h target.com -u admin -P admin123 -t '#' -v

# TLS connection
mosquitto_sub -h target.com -p 8883 --cafile ca.crt -t '#' -v
```

### 5.3 CoAP Vulnerability Detection

```bash
# After installing libcoap
# Use coap-client

# Resource discovery (CoAP discovery)
coap-client -m get coap://192.168.1.1/.well-known/core

# GET request
coap-client -m get coap://192.168.1.1/sensors/temperature

# Change configuration via PUT
coap-client -m put -e '{"value": "OFF"}' coap://192.168.1.1/actuators/switch

# Observe - continuous monitoring
coap-client -m get -s 60 coap://192.168.1.1/sensors/temperature
```

---

## 7. Attack Surface Checklist

```
Physical Interfaces
□ Identify UART ports and attempt access
□ Detect JTAG pins (use JTAGulator)
□ Direct SPI/I2C flash memory dump
□ Check for exposed debug pads

Network Services
□ Open port scan (nmap -sV -p- target)
□ Check Telnet(23), SSH(22), HTTP(80/8080), HTTPS(443)
□ Check MQTT(1883), CoAP(5683), UPnP(1900)
□ Test default credentials

Firmware
□ Check if firmware can be downloaded (public sources)
□ binwalk analysis — filesystem type
□ Search for hardcoded credentials
□ Check for included private keys/certificates

Cloud/API
□ Analyze mobile app API endpoints
□ Authentication token handling
□ TLS configuration validation (certificate validation bypass)
□ Endpoints accessible without API authentication

Update Mechanism
□ OTA update signature verification
□ MITM possibility when firmware downloaded via HTTP
□ Rollback prevention mechanism presence
```

---

## Reference Command Summary

```bash
# Quick IoT device detection
nmap -sV -p 22,23,80,443,1883,5683,8080,8443,8883 --open 192.168.1.0/24

# UPnP device discovery
nmap -sU -p 1900 --script upnp-info 192.168.1.0/24

# RTSP camera stream detection
nmap -p 554 --script rtsp-url-brute 192.168.1.0/24

# SNMP community string brute force
nmap -sU -p 161 --script snmp-brute 192.168.1.1

# WPS vulnerability scan (wireless routers)
wash -i wlan0mon

# Bluetooth LE device scan
hcitool lescan
gatttool -b AA:BB:CC:DD:EE:FF --interactive
```

<!-- detect-validate-27 -->
## IoT Attack Surface Detection and Defense Validation

IoT has a wide attack surface via *default credentials, exposed services, plaintext comms, and unpatched firmware*. Defenders must verify **whether their devices' exposure and comms are safe**. Validate only on **owned devices/networks**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Default credentials | Unchanged password | Forced change, unique keys | Default-account login attempts |
| Exposed services (telnet/UPnP) | Unneeded ports | Minimize ports, segment | 23/1900 responding externally |
| Plaintext comms | No encryption | TLS, VPN | Plaintext credential capture |
| Unpatched firmware | Known CVEs | OTA updates, SBOM | Old-version banner |

### Defense validation (verify directly)

```bash
# 1) Check your IoT exposure surface (owned network) — telnet/UPnP and other unneeded services
nmap -sV -p 23,80,1900,5000,8080 --open 192.168.1.0/24 2>/dev/null | grep -iE "open|telnet|upnp"
# 2) Check plaintext-credential exposure — whether device traffic carries plaintext auth (owned network)
sudo tshark -i eth0 -Y "http.authorization || telnet" -a duration:20 2>/dev/null | head
```

> IoT defense is *whether the exposure is narrow and comms encrypted* -- "the device works" differs from "telnet is closed and no plaintext credentials flow". Confirm exposed ports and plaintext auth on owned networks directly ([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).
