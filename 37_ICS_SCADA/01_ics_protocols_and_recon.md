> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 01 — ICS 프로토콜 심화 및 정찰

## 0. 초보자를 위한 개념 이해

### 왜 ICS 프로토콜 정찰이 필요한가?

ICS/OT 환경을 공격하기 전에 공격자는 반드시 정찰 단계를 거칩니다. 어떤 장치가 있는지, 어떤 프로토콜을 쓰는지 파악해야 합니다.

**정찰 단계의 중요성:**
```
정찰 없이 공격 시도:
  PLC에 무작위 Modbus 명령 전송
  → PLC 예상치 못한 상태 진입
  → 공장 전체 비상 정지
  → 공격 의도가 없어도 결과는 재앙
  
정찰 후 공격:
  PLC 모델, 펌웨어 버전 파악
  → 해당 버전의 취약점 확인
  → 정밀한 명령 전송
  → 원하는 효과만 발생
```

### ICS 정찰 도구들

```
인터넷 스캐닝:
  Shodan: 인터넷에 노출된 ICS 장치 검색
  Censys: 인터넷 스캔 데이터베이스
  FOFA: 중국의 인터넷 자산 검색 엔진
  
  검색 예시:
    shodan search "port:502 modbus"
    → 인터넷에 노출된 Modbus 장치 발견
    
내부망 스캐닝 (인가된 테스트):
  nmap + ICS NSE 스크립트
  S7scan (Siemens S7 전용)
  redpoint (ICS 프로토콜 핑거프린팅)
  pymodbus (Modbus 직접 통신)
```

### 프로토콜별 기본 포트

| 프로토콜 | 포트 | 사용처 |
|----------|------|--------|
| Modbus TCP | 502/TCP | 범용 PLC/센서 |
| DNP3 | 20000/TCP | 전력/수자원 SCADA |
| S7comm | 102/TCP | Siemens PLC |
| EtherNet/IP | 44818/TCP | Allen-Bradley |
| BACnet/IP | 47808/UDP | 빌딩 자동화 |
| IEC 61850 | 102/TCP | 변전소 자동화 |

> ⚠️ 허가 없는 ICS 시스템 스캔은 불법이며, 물리적 피해를 초래할 수 있습니다.

---

## 목차
1. Modbus 프로토콜 심화
2. DNP3 프로토콜 심화
3. IEC 61850 프로토콜
4. EtherNet/IP 프로토콜
5. Shodan ICS 정찰
6. S7scan 및 Redpoint NSE
7. PLC 핑거프린팅 및 태그 열거
8. Python 도구: Modbus 풀 스캐너

---

## 1. Modbus 프로토콜 심화

### 프로토콜 구조

Modbus는 1979년 Modicon이 개발한 직렬 통신 프로토콜로, ICS 환경에서 가장 광범위하게 사용된다. TCP 포트 502번을 사용하며 **인증 기능이 전혀 없다**.

```
[MBAP 헤더 (7바이트)] + [PDU (최대 253바이트)]

MBAP 헤더:
  트랜잭션 ID  : 2바이트
  프로토콜 ID  : 2바이트 (항상 0x0000)
  길이         : 2바이트 (이후 바이트 수)
  유닛 ID      : 1바이트 (슬레이브 주소)

PDU:
  기능 코드    : 1바이트
  데이터       : 가변
```

### 기능 코드(Function Code) 완전 목록

| FC | 명칭 | 데이터 유형 | 읽기/쓰기 |
|----|------|------------|----------|
| 0x01 | Read Coils | 디지털 출력 | 읽기 |
| 0x02 | Read Discrete Inputs | 디지털 입력 | 읽기 |
| 0x03 | Read Holding Registers | 아날로그 출력 | 읽기 |
| 0x04 | Read Input Registers | 아날로그 입력 | 읽기 |
| 0x05 | Write Single Coil | 디지털 출력 | 쓰기 |
| 0x06 | Write Single Register | 아날로그 출력 | 쓰기 |
| 0x0F | Write Multiple Coils | 디지털 출력 | 쓰기 |
| 0x10 | Write Multiple Registers | 아날로그 출력 | 쓰기 |
| 0x14 | Read File Record | 파일 | 읽기 |
| 0x15 | Write File Record | 파일 | 쓰기 |
| 0x16 | Mask Write Register | 아날로그 출력 | 쓰기 |
| 0x17 | Read/Write Multiple Registers | 아날로그 | 읽기/쓰기 |
| 0x2B | Encapsulated Interface Transport | 장치 식별 | 읽기 |

### 장치 식별 읽기 (FC 0x2B)

```python
# Modbus 장치 ID 읽기 — 제조사, 모델 정보 획득
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# FC 0x2B / MEI Type 0x0E: 장치 식별
# Object ID: 0x00=VendorName, 0x01=ProductCode, 0x02=MajorMinorRevision
#            0x03=VendorURL, 0x04=ProductName, 0x05=ModelName
rr = client.read_device_information(read_code=0x01, object_id=0x00)
if not rr.isError():
    for obj_id, value in rr.information.items():
        print(f"Object 0x{obj_id:02X}: {value}")
client.close()
```

### Modbus 원시 패킷 분석

```bash
# tcpdump로 Modbus 트래픽 캡처
tcpdump -i eth0 -w modbus.pcap 'tcp port 502'

# Modbus 요청 패킷 수동 구성 (FC03, 주소 0, 10개 레지스터)
# 00 01 00 00 00 06 01 03 00 00 00 0A
# [TID=1][PROT=0][LEN=6][UID=1][FC=3][ADDR=0][COUNT=10]

# Python으로 원시 소켓 전송
python3 -c "
import socket
req = bytes([0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x0A])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.100', 502))
s.send(req)
resp = s.recv(1024)
print(resp.hex())
s.close()
"
```

---

## 2. DNP3 프로토콜 심화

### 프로토콜 개요

DNP3(Distributed Network Protocol 3)은 전력, 수도, 가스 등 공익 설비 SCADA에서 광범위하게 사용된다. TCP 포트 20000번을 사용한다. 초기 IEC 60870-5 표준 작업에서 파생됐으며 현재 IEEE 1815로 표준화되어 있다.

```
DNP3 패킷 구조:
[데이터 링크 레이어] — 10바이트 (시작, 길이, 제어, 목적지, 출발지, CRC)
[전송 레이어]        — 1바이트 (FIR/FIN 플래그, 시퀀스)
[응용 레이어]        — 가변 (제어, 기능 코드, 오브젝트)
```

### DNP3 기능 코드

| 코드 | 명칭 | 용도 |
|------|------|------|
| 0x01 | READ | 데이터 읽기 |
| 0x02 | WRITE | 데이터 쓰기 |
| 0x03 | SELECT | CROB 선택 단계 |
| 0x04 | OPERATE | CROB 실행 단계 |
| 0x05 | DIRECT_OPERATE | 즉시 제어 |
| 0x0D | COLD_RESTART | 장치 재시작 |
| 0x0E | WARM_RESTART | 설정 유지 재시작 |
| 0x81 | RESPONSE | 응답 |
| 0x82 | UNSOLICITED_RESPONSE | 비요청 응답 |

### DNP3 취약점 분석

```bash
# Nmap DNP3 스캔
nmap -p 20000 --script dnp3-info 192.168.1.0/24

# DNP3 비인증 재시작 명령 전송 (Wireshark로 패킷 분석 후)
# 아래는 테스트 환경에서의 패킷 구조 예시
python3 -c "
import socket
# DNP3 COLD_RESTART 패킷 (마스터→슬레이브)
# 데이터 링크: 05 64 08 44 03 00 01 00 [CRC]
# 전송: C0
# 응용: C0 0D (FC=13=COLD_RESTART)
# 실제 CRC 계산 필요 — 교육 목적 패킷 구조 표시
pkt = bytes.fromhex('056408440300010000C0C00D')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('192.168.1.100', 20000))
    s.send(pkt)
    resp = s.recv(1024)
    print('응답:', resp.hex())
except Exception as e:
    print(f'오류: {e}')
finally:
    s.close()
"
```

---

## 3. IEC 61850 프로토콜

### 구성 요소

IEC 61850은 변전소 자동화를 위한 국제 표준으로, 여러 서브프로토콜로 구성된다:

- **MMS (Manufacturing Message Specification)**: TCP 포트 102, SCADA ↔ IED 통신
- **GOOSE (Generic Object Oriented Substation Event)**: 멀티캐스트, 차단기 상태 이벤트
- **SV (Sampled Values)**: 멀티캐스트, 전류/전압 측정값
- **CID 파일**: Substation Configuration Language(SCL)로 기술된 장치 설정

### MMS 서비스 열거

```bash
# IEC 61850 MMS 스캔
nmap -p 102 --script mms-identify 192.168.1.0/24

# Python으로 MMS 연결 및 서버 디렉터리 열거
pip install python-iec61850

python3 -c "
# libiec61850 Python 바인딩 사용
import iec61850

con = iec61850.IedConnection_create()
err = iec61850.IedClientError()
iec61850.IedConnection_connect(con, err, '192.168.1.100', 102)

if err.value == iec61850.IED_ERROR_OK:
    # 논리 장치 목록 조회
    device_list = iec61850.IedConnection_getLogicalDeviceList(con, err)
    print('논리 장치:', device_list)
    
    # 첫 번째 논리 장치의 논리 노드 조회
    ln_list = iec61850.IedConnection_getLogicalDeviceDirectory(con, err, 'IED_CTRL/LLN0')
    print('논리 노드:', ln_list)

iec61850.IedConnection_close(con)
iec61850.IedConnection_destroy(con)
"
```

### GOOSE 패킷 스니핑

```bash
# GOOSE는 이더넷 멀티캐스트로 전송됨 (EtherType 0x88B8)
tcpdump -i eth0 -w goose.pcap 'ether proto 0x88B8'

# Wireshark 필터
# goose.stNum > 0 (상태 변화 감지)
# goose.allData (모든 GOOSE 데이터)
```

---

## 4. EtherNet/IP 프로토콜

### 프로토콜 구조

EtherNet/IP(Ethernet Industrial Protocol)는 Rockwell Automation이 개발한 산업용 이더넷 프로토콜로, Allen-Bradley PLC의 기본 통신 방식이다.

- **TCP 포트 44818**: 명시적 메시징 (설정, 프로그래밍)
- **UDP 포트 2222**: 암시적 메시징 (실시간 I/O)
- **CIP(Common Industrial Protocol)** 위에서 동작

```
EtherNet/IP 패킷:
[EIP 헤더 24바이트]
  명령(2B) + 길이(2B) + 세션 핸들(4B) + 상태(4B)
  발신자 컨텍스트(8B) + 옵션(4B)
[CIP 데이터]
```

### EtherNet/IP 열거

```bash
# Nmap EtherNet/IP 스캔
nmap -p 44818 --script enip-info 192.168.1.0/24

# 결과 예시:
# 44818/tcp open  EtherNet/IP
# | enip-info:
# |   Vendor: Rockwell Automation/Allen-Bradley
# |   Product Name: 1769-L33ER/A LOGIX5333ER
# |   Serial: 0x60A57B10
# |   IP: 192.168.1.50

# CIPster 도구로 태그 목록 조회
git clone https://github.com/nothings/stb.git  # 예시
pip install pycomm3

python3 -c "
from pycomm3 import LogixDriver
with LogixDriver('192.168.1.50') as plc:
    print('태그 목록:')
    tags = plc.get_tag_list()
    for tag in tags[:20]:
        print(f'  {tag[\"tag_name\"]} : {tag[\"data_type\"]}')
"
```

---

## 5. Shodan ICS 정찰

### 효과적인 Shodan 쿼리

```bash
# Shodan CLI 설치 및 초기화
pip install shodan
shodan init YOUR_API_KEY

# Modbus 장치 (포트 502)
shodan search "port:502 modbus" --limit 100

# Siemens S7 PLC
shodan search 'port:102 "S7"'
shodan search '"Siemens" port:102'

# Allen-Bradley EtherNet/IP
shodan search 'port:44818 "Allen-Bradley"'
shodan search 'port:44818 "ControlLogix"'

# DNP3 (전력/수도)
shodan search 'port:20000 "DNP3"'

# IEC 104 (전력망 RTU)
shodan search 'port:2404 "IEC-104"'

# GE SRTP (GE PLC)
shodan search 'port:18245 "GE"'

# BACnet (빌딩 자동화)
shodan search 'port:47808 "BACnet"'

# SCADA 서버 (WinCC, iFIX 등)
shodan search '"SCADA" country:KR'
shodan search '"Wonderware" port:135'

# 특정 국가 ICS 자산
shodan search 'tag:ics country:KR'
shodan search 'tag:scada country:KR'

# Shodan Python API로 자동화
python3 -c "
import shodan
api = shodan.Shodan('YOUR_API_KEY')

# ICS 관련 Modbus 장치 검색
results = api.search('port:502 modbus', limit=50)
print(f'총 결과: {results[\"total\"]}')
for r in results['matches']:
    print(f'{r[\"ip_str\"]}:{r.get(\"port\",502)} - {r.get(\"org\",\"Unknown\")} [{r.get(\"country_name\",\"?\")}]')
    if 'modbus' in r:
        md = r['modbus']
        print(f'  장치: {md.get(\"device_id\",{})}')
"
```

### Censys ICS 검색

```bash
# Censys CLI
pip install censys
censys config  # API ID/Secret 입력

# ICS 장치 검색
censys search "services.port=502" --index hosts
censys search "services.port=102 AND services.banner:S7" --index hosts
censys search "services.port=44818" --index hosts

# 결과 JSON 파싱
censys search "services.port=502" --index hosts --output-fields \
    "ip,location.country,autonomous_system.name,services.port" \
    | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line.strip())
    print(f'{d[\"ip\"]} [{d.get(\"location\",{}).get(\"country\",\"?\")}] AS:{d.get(\"autonomous_system\",{}).get(\"name\",\"?\")}')
"
```

---

## 6. S7scan 및 Redpoint NSE 스크립트

### S7scan 사용법

```bash
# s7scan 설치
git clone https://github.com/klsecservices/s7scan.git
cd s7scan
pip install -r requirements.txt

# 단일 IP 스캔
python3 s7scan.py -H 192.168.1.100

# 서브넷 스캔
python3 s7scan.py -H 192.168.1.0/24

# 결과 예시:
# [+] 192.168.1.100 포트 102 열림
# [+] PLC 정보:
#     시스템명  : PLC-REACTOR-01
#     모듈 유형 : 6ES7 315-2EH14-0AB0
#     시리얼    : S C-E3A1827F
#     AS명      : REACTOR_CTRL
#     모듈명    : CPU 315-2 PN/DP
#     플랜트 ID : PLANT_A
#     저작권    : Original Siemens Equipment
#     펌웨어    : V3.2.6
```

### Nmap Redpoint NSE 스크립트

```bash
# Redpoint ICS NSE 스크립트 다운로드
git clone https://github.com/digitalbond/Redpoint.git /usr/share/nmap/scripts/redpoint/
cd /usr/share/nmap/scripts/redpoint/
cp *.nse /usr/share/nmap/scripts/
nmap --script-updatedb

# Modbus 장치 식별
nmap -sV -p 502 --script modbus-discover 192.168.1.0/24

# EtherNet/IP 상세 정보
nmap -p 44818 --script enip-info 192.168.1.100

# DNP3 배너 정보
nmap -p 20000 --script dnp3-info 192.168.1.100

# Siemens S7 정보 (s7-info.nse)
nmap -p 102 --script s7-info 192.168.1.100

# GE SRTP
nmap -p 18245 --script ge-srtp-info 192.168.1.100

# BACnet 장치 정보
nmap -p 47808/udp --script bacnet-info 192.168.1.0/24

# 전체 ICS 스캔 파이프라인
nmap -sS -sU -p T:102,502,20000,44818,102,2222,4840 \
     -p U:47808,20000 \
     --script modbus-discover,s7-info,enip-info,dnp3-info,bacnet-info \
     -oX ics_scan.xml \
     192.168.1.0/24

# XML 결과 파싱
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('ics_scan.xml')
root = tree.getroot()
for host in root.findall('host'):
    addr = host.find('address').get('addr')
    for port in host.findall('.//port'):
        portid = port.get('portid')
        state = port.find('state').get('state')
        if state == 'open':
            print(f'{addr}:{portid}')
            for script in port.findall('script'):
                print(f'  [{script.get(\"id\")}] {script.get(\"output\")[:100]}')
"
```

---

## 7. PLC 핑거프린팅 및 태그 열거

### Siemens S7 핑거프린팅

```python
# snap7를 이용한 S7 PLC 핑거프린팅
import snap7
from snap7.util import get_int, get_real, get_string
import snap7.types as types

client = snap7.client.Client()
client.connect('192.168.1.100', 0, 1)  # IP, rack, slot

# CPU 정보 읽기
cpu_info = client.get_cpu_info()
print(f"모듈명     : {cpu_info.ModuleTypeName.decode()}")
print(f"시리얼 번호: {cpu_info.SerialNumber.decode()}")
print(f"AS명       : {cpu_info.ASName.decode()}")
print(f"Copyright  : {cpu_info.Copyright.decode()}")
print(f"모듈       : {cpu_info.ModuleName.decode()}")

# CPU 상태 읽기 (RUN/STOP)
cpu_state = client.get_cpu_state()
states = {0: 'UNKNOWN', 4: 'STOP', 8: 'RUN'}
print(f"CPU 상태   : {states.get(cpu_state, f'코드:{cpu_state}')}")

# 주문 코드 (모델 식별)
order_code = client.get_order_code()
print(f"주문 코드  : {order_code.Code.decode()}")

client.disconnect()
```

### Allen-Bradley 태그 열거

```python
from pycomm3 import LogixDriver

def enumerate_ab_plc(ip: str) -> None:
    with LogixDriver(ip) as plc:
        # 기본 정보
        info = plc.info
        print(f"제품명   : {info.get('product_name')}")
        print(f"시리얼   : {info.get('serial')}")
        print(f"펌웨어   : {info.get('revision')}")
        
        # 태그 목록 전체 열거
        tags = plc.get_tag_list()
        print(f"\n총 태그 수: {len(tags)}")
        
        # 타입별 분류
        for tag in tags:
            name = tag['tag_name']
            dtype = tag['data_type']
            dim = tag.get('dimensions', [])
            print(f"  {name:40s} {dtype:20s} {dim}")
        
        # 프로그램 목록
        programs = plc.get_program_list()
        print(f"\n프로그램: {programs}")
        
        # 특정 태그 값 읽기
        interesting = [t for t in tags if any(
            kw in t['tag_name'].upper() 
            for kw in ['SPEED', 'PRESSURE', 'TEMP', 'VALVE', 'PUMP']
        )]
        for tag in interesting[:10]:
            val = plc.read(tag['tag_name'])
            print(f"  {tag['tag_name']} = {val.value}")

enumerate_ab_plc('192.168.1.50')
```

### Schneider Modicon 열거

```bash
# Unity Pro 연결 없이 Modbus TCP로 직접 열거
python3 -c "
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.200', port=502)
client.connect()

# Holding Register 0-99 읽기 (설정값, 파라미터)
regs = client.read_holding_registers(0, 100, slave=255)
if not regs.isError():
    for i, v in enumerate(regs.registers):
        if v != 0:
            print(f'HR[{i:4d}] = {v:6d} (0x{v:04X})')

# Input Register 0-99 읽기 (센서값, 측정값)
iregs = client.read_input_registers(0, 100, slave=255)
if not iregs.isError():
    for i, v in enumerate(iregs.registers):
        if v != 0:
            print(f'IR[{i:4d}] = {v:6d}')

client.close()
"
```

---

## 8. Python 도구: Modbus 풀 스캐너

Modbus 장치의 모든 코일, 레지스터를 열거하고 결과를 JSON/CSV로 저장하는 완전한 CLI 도구.

```python
#!/usr/bin/env python3
"""
Modbus 풀 스캐너 — 코일/레지스터 전체 열거 CLI
요구사항: pip install pymodbus
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pymodbus.client import ModbusTcpClient, ModbusUdpClient
from pymodbus.exceptions import ModbusException

# 로깅 설정
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 데이터 모델
# ─────────────────────────────────────────────

@dataclass
class ScanResult:
    host: str
    port: int
    slave_id: int
    data_type: str          # coil / discrete / holding / input
    address: int
    value: int | bool
    raw_hex: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(self.timestamp)
        )
        return d


@dataclass
class DeviceInfo:
    host: str
    port: int
    slave_id: int
    vendor_name: str = ""
    product_code: str = ""
    revision: str = ""
    vendor_url: str = ""
    product_name: str = ""
    model_name: str = ""
    user_application: str = ""
    error: str = ""


# ─────────────────────────────────────────────
# 핵심 스캐너 클래스
# ─────────────────────────────────────────────

class ModbusScanner:
    """Modbus TCP/UDP 장치 풀 스캐너."""

    CHUNK_SIZE = 125  # Modbus 단일 요청 최대 레지스터 수

    def __init__(
        self,
        host: str,
        port: int = 502,
        slave_id: int = 1,
        timeout: float = 3.0,
        retries: int = 2,
        use_udp: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.slave_id = slave_id
        self.timeout = timeout
        self.retries = retries
        self.use_udp = use_udp
        self._client: ModbusTcpClient | ModbusUdpClient | None = None

    def _get_client(self) -> ModbusTcpClient | ModbusUdpClient:
        if self.use_udp:
            return ModbusUdpClient(
                host=self.host,
                port=self.port,
                timeout=self.timeout,
                retries=self.retries,
            )
        return ModbusTcpClient(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
            retries=self.retries,
        )

    def connect(self) -> bool:
        self._client = self._get_client()
        connected = self._client.connect()
        if connected:
            logger.info("연결 성공: %s:%d", self.host, self.port)
        else:
            logger.warning("연결 실패: %s:%d", self.host, self.port)
        return connected

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def read_device_info(self) -> DeviceInfo:
        """FC 0x2B MEI 0x0E 장치 식별 정보 읽기."""
        info = DeviceInfo(host=self.host, port=self.port, slave_id=self.slave_id)
        if not self._client:
            info.error = "연결되지 않음"
            return info

        object_names = {
            0x00: "vendor_name",
            0x01: "product_code",
            0x02: "revision",
            0x03: "vendor_url",
            0x04: "product_name",
            0x05: "model_name",
            0x06: "user_application",
        }
        try:
            rr = self._client.read_device_information(
                read_code=0x01, object_id=0x00, slave=self.slave_id
            )
            if not rr.isError():
                for obj_id, name in object_names.items():
                    if obj_id in rr.information:
                        val = rr.information[obj_id]
                        if isinstance(val, (bytes, bytearray)):
                            val = val.decode("utf-8", errors="replace")
                        setattr(info, name, str(val))
        except (ModbusException, Exception) as exc:
            info.error = str(exc)
        return info

    def _read_coils_chunk(
        self, start: int, count: int
    ) -> list[ScanResult]:
        """코일(FC 0x01) 청크 읽기."""
        results: list[ScanResult] = []
        if not self._client:
            return results
        try:
            rr = self._client.read_coils(start, count, slave=self.slave_id)
            if not rr.isError():
                for i, bit in enumerate(rr.bits[:count]):
                    results.append(ScanResult(
                        host=self.host,
                        port=self.port,
                        slave_id=self.slave_id,
                        data_type="coil",
                        address=start + i,
                        value=int(bit),
                        raw_hex=f"0x{int(bit):02X}",
                    ))
        except (ModbusException, Exception) as exc:
            logger.debug("코일 읽기 오류 addr=%d: %s", start, exc)
        return results

    def _read_discrete_chunk(
        self, start: int, count: int
    ) -> list[ScanResult]:
        """디스크리트 입력(FC 0x02) 청크 읽기."""
        results: list[ScanResult] = []
        if not self._client:
            return results
        try:
            rr = self._client.read_discrete_inputs(start, count, slave=self.slave_id)
            if not rr.isError():
                for i, bit in enumerate(rr.bits[:count]):
                    results.append(ScanResult(
                        host=self.host,
                        port=self.port,
                        slave_id=self.slave_id,
                        data_type="discrete",
                        address=start + i,
                        value=int(bit),
                        raw_hex=f"0x{int(bit):02X}",
                    ))
        except (ModbusException, Exception) as exc:
            logger.debug("디스크리트 읽기 오류 addr=%d: %s", start, exc)
        return results

    def _read_holding_chunk(
        self, start: int, count: int
    ) -> list[ScanResult]:
        """홀딩 레지스터(FC 0x03) 청크 읽기."""
        results: list[ScanResult] = []
        if not self._client:
            return results
        try:
            rr = self._client.read_holding_registers(start, count, slave=self.slave_id)
            if not rr.isError():
                for i, reg in enumerate(rr.registers):
                    results.append(ScanResult(
                        host=self.host,
                        port=self.port,
                        slave_id=self.slave_id,
                        data_type="holding",
                        address=start + i,
                        value=reg,
                        raw_hex=f"0x{reg:04X}",
                    ))
        except (ModbusException, Exception) as exc:
            logger.debug("홀딩 레지스터 읽기 오류 addr=%d: %s", start, exc)
        return results

    def _read_input_chunk(
        self, start: int, count: int
    ) -> list[ScanResult]:
        """입력 레지스터(FC 0x04) 청크 읽기."""
        results: list[ScanResult] = []
        if not self._client:
            return results
        try:
            rr = self._client.read_input_registers(start, count, slave=self.slave_id)
            if not rr.isError():
                for i, reg in enumerate(rr.registers):
                    results.append(ScanResult(
                        host=self.host,
                        port=self.port,
                        slave_id=self.slave_id,
                        data_type="input",
                        address=start + i,
                        value=reg,
                        raw_hex=f"0x{reg:04X}",
                    ))
        except (ModbusException, Exception) as exc:
            logger.debug("입력 레지스터 읽기 오류 addr=%d: %s", start, exc)
        return results

    def scan_range(
        self,
        data_types: list[str],
        start_addr: int,
        end_addr: int,
        max_workers: int = 4,
        skip_zeros: bool = False,
    ) -> list[ScanResult]:
        """지정한 주소 범위를 병렬로 스캔."""
        all_results: list[ScanResult] = []
        tasks: list[tuple[str, int, int]] = []

        for dtype in data_types:
            addr = start_addr
            while addr <= end_addr:
                chunk = min(self.CHUNK_SIZE, end_addr - addr + 1)
                tasks.append((dtype, addr, chunk))
                addr += chunk

        reader_map = {
            "coil":     self._read_coils_chunk,
            "discrete": self._read_discrete_chunk,
            "holding":  self._read_holding_chunk,
            "input":    self._read_input_chunk,
        }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(reader_map[dtype], start, count): (dtype, start)
                for dtype, start, count in tasks
                if dtype in reader_map
            }
            for future in as_completed(future_map):
                dtype, start = future_map[future]
                try:
                    chunk_results = future.result()
                    if skip_zeros:
                        chunk_results = [r for r in chunk_results if r.value != 0]
                    all_results.extend(chunk_results)
                except Exception as exc:
                    logger.warning("%s addr=%d 읽기 실패: %s", dtype, start, exc)

        all_results.sort(key=lambda r: (r.data_type, r.address))
        return all_results


# ─────────────────────────────────────────────
# 다중 호스트 스캐너
# ─────────────────────────────────────────────

def scan_host(args_tuple: tuple) -> dict[str, Any]:
    """단일 호스트 스캔 (멀티스레드 타겟용)."""
    (
        host, port, slave_id, timeout, retries,
        data_types, start_addr, end_addr,
        max_workers, skip_zeros, use_udp
    ) = args_tuple

    scanner = ModbusScanner(
        host=host,
        port=port,
        slave_id=slave_id,
        timeout=timeout,
        retries=retries,
        use_udp=use_udp,
    )

    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "slave_id": slave_id,
        "reachable": False,
        "device_info": {},
        "scan_results": [],
        "error": "",
    }

    if not scanner.connect():
        result["error"] = "연결 실패"
        return result

    result["reachable"] = True

    try:
        dev_info = scanner.read_device_info()
        result["device_info"] = asdict(dev_info)

        scan_res = scanner.scan_range(
            data_types=data_types,
            start_addr=start_addr,
            end_addr=end_addr,
            max_workers=max_workers,
            skip_zeros=skip_zeros,
        )
        result["scan_results"] = [r.to_dict() for r in scan_res]
        result["total_registers"] = len(scan_res)
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        scanner.disconnect()

    return result


# ─────────────────────────────────────────────
# 출력 포맷터
# ─────────────────────────────────────────────

def print_table(results: list[ScanResult], host: str) -> None:
    """터미널 테이블 형식으로 출력."""
    print(f"\n{'='*70}")
    print(f"호스트: {host}")
    print(f"{'='*70}")
    print(f"{'타입':<12} {'주소':>8} {'값':>8} {'HEX':>8}")
    print(f"{'-'*70}")

    prev_type = ""
    for r in results:
        if r.data_type != prev_type:
            if prev_type:
                print()
            print(f"[{r.data_type.upper()}]")
            prev_type = r.data_type
        print(f"  {r.data_type:<10} {r.address:>8} {r.value:>8} {r.raw_hex:>8}")


def save_json(host_results: list[dict[str, Any]], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(host_results, f, ensure_ascii=False, indent=2)
    print(f"[+] JSON 저장: {output_path}")


def save_csv(host_results: list[dict[str, Any]], output_path: Path) -> None:
    fieldnames = ["host", "port", "slave_id", "data_type", "address", "value", "raw_hex", "timestamp"]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for hr in host_results:
            for sr in hr.get("scan_results", []):
                writer.writerow(sr)
    print(f"[+] CSV 저장: {output_path}")


# ─────────────────────────────────────────────
# CLI 인수 파서
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modbus_scanner",
        description="Modbus TCP/UDP 장치 코일·레지스터 전체 열거 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 단일 호스트 전체 스캔
  python3 modbus_scanner.py -t 192.168.1.100

  # 여러 호스트, 홀딩/입력 레지스터만, 주소 0-499
  python3 modbus_scanner.py -t 192.168.1.100 192.168.1.101 \\
      --types holding input --start 0 --end 499

  # 파일에서 호스트 목록 읽기, JSON 출력
  python3 modbus_scanner.py -f hosts.txt -o results.json --format json

  # 0이 아닌 값만 출력, 슬레이브 ID 2, 타임아웃 5초
  python3 modbus_scanner.py -t 192.168.1.100 --slave 2 \\
      --skip-zeros --timeout 5.0

  # 포트 스위핑 (여러 슬레이브 ID)
  python3 modbus_scanner.py -t 192.168.1.100 --slave-range 1 10
        """,
    )

    # 타겟 지정
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--targets", nargs="+", metavar="IP",
        help="스캔 대상 IP 주소(들)"
    )
    target_group.add_argument(
        "-f", "--target-file", type=Path, metavar="FILE",
        help="스캔 대상 IP 목록 파일 (한 줄에 하나)"
    )

    # 연결 설정
    conn_group = parser.add_argument_group("연결 설정")
    conn_group.add_argument(
        "-p", "--port", type=int, default=502,
        help="Modbus TCP 포트 (기본값: 502)"
    )
    conn_group.add_argument(
        "--slave", type=int, default=1,
        help="Modbus 슬레이브 ID (기본값: 1)"
    )
    conn_group.add_argument(
        "--slave-range", nargs=2, type=int, metavar=("START", "END"),
        help="슬레이브 ID 범위 스위핑 (예: 1 247)"
    )
    conn_group.add_argument(
        "--timeout", type=float, default=3.0,
        help="연결 타임아웃 초 (기본값: 3.0)"
    )
    conn_group.add_argument(
        "--retries", type=int, default=2,
        help="재시도 횟수 (기본값: 2)"
    )
    conn_group.add_argument(
        "--udp", action="store_true",
        help="Modbus UDP 사용"
    )

    # 스캔 범위
    scan_group = parser.add_argument_group("스캔 범위")
    scan_group.add_argument(
        "--types", nargs="+",
        choices=["coil", "discrete", "holding", "input"],
        default=["coil", "discrete", "holding", "input"],
        help="스캔할 데이터 유형 (기본값: 전체)"
    )
    scan_group.add_argument(
        "--start", type=int, default=0,
        help="시작 주소 (기본값: 0)"
    )
    scan_group.add_argument(
        "--end", type=int, default=9999,
        help="끝 주소 (기본값: 9999)"
    )
    scan_group.add_argument(
        "--skip-zeros", action="store_true",
        help="값이 0인 레지스터 결과 제외"
    )

    # 성능
    perf_group = parser.add_argument_group("성능 설정")
    perf_group.add_argument(
        "--workers", type=int, default=4,
        help="청크 병렬 처리 워커 수 (기본값: 4)"
    )
    perf_group.add_argument(
        "--host-workers", type=int, default=8,
        help="호스트 병렬 스캔 워커 수 (기본값: 8)"
    )

    # 출력
    out_group = parser.add_argument_group("출력 설정")
    out_group.add_argument(
        "-o", "--output", type=Path, metavar="FILE",
        help="결과 저장 파일 경로"
    )
    out_group.add_argument(
        "--format", choices=["table", "json", "csv", "all"],
        default="table",
        help="출력 형식 (기본값: table)"
    )
    out_group.add_argument(
        "--device-info-only", action="store_true",
        help="장치 식별 정보만 출력 (레지스터 스캔 생략)"
    )
    out_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="상세 로그 출력"
    )

    return parser


# ─────────────────────────────────────────────
# 메인 진입점
# ─────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 타겟 목록 구성
    targets: list[str] = []
    if args.targets:
        targets = args.targets
    elif args.target_file:
        if not args.target_file.exists():
            print(f"[!] 파일 없음: {args.target_file}", file=sys.stderr)
            return 1
        targets = [
            line.strip()
            for line in args.target_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not targets:
        print("[!] 스캔 대상이 없습니다.", file=sys.stderr)
        return 1

    # 슬레이브 ID 목록
    if args.slave_range:
        slave_ids = list(range(args.slave_range[0], args.slave_range[1] + 1))
    else:
        slave_ids = [args.slave]

    # 스캔 태스크 구성
    scan_tasks: list[tuple] = []
    for host in targets:
        for sid in slave_ids:
            scan_tasks.append((
                host, args.port, sid, args.timeout, args.retries,
                [] if args.device_info_only else args.types,
                args.start, args.end,
                args.workers, args.skip_zeros, args.udp,
            ))

    print(f"[*] 스캔 시작: {len(targets)}개 호스트 × {len(slave_ids)}개 슬레이브 ID")
    print(f"[*] 주소 범위: {args.start} ~ {args.end}")
    print(f"[*] 데이터 유형: {args.types if not args.device_info_only else '장치 정보만'}")

    start_time = time.time()
    host_results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=args.host_workers) as executor:
        futures = {executor.submit(scan_host, task): task[0] for task in scan_tasks}
        done_count = 0
        for future in as_completed(futures):
            host = futures[future]
            done_count += 1
            try:
                result = future.result()
                host_results.append(result)

                # 실시간 진행 상황 출력
                status = "[+] 온라인" if result["reachable"] else "[-] 오프라인"
                total = result.get("total_registers", 0)
                print(
                    f"  [{done_count}/{len(scan_tasks)}] "
                    f"{host}:{args.port} "
                    f"{status} "
                    f"(레지스터: {total})"
                )

                if result["reachable"] and result["device_info"]:
                    di = result["device_info"]
                    if di.get("vendor_name"):
                        print(f"    제조사: {di['vendor_name']}")
                    if di.get("product_name"):
                        print(f"    제품명: {di['product_name']}")
                    if di.get("revision"):
                        print(f"    버전  : {di['revision']}")

            except Exception as exc:
                print(f"  [!] {host} 스캔 오류: {exc}", file=sys.stderr)

    elapsed = time.time() - start_time
    online = sum(1 for r in host_results if r["reachable"])
    total_regs = sum(r.get("total_registers", 0) for r in host_results)

    print(f"\n[*] 완료: {elapsed:.1f}초, 온라인 {online}/{len(scan_tasks)}, 총 레지스터 {total_regs}개")

    # 터미널 테이블 출력
    if args.format in ("table", "all"):
        for hr in host_results:
            if hr["reachable"] and hr["scan_results"]:
                results_objs = [
                    ScanResult(
                        host=r["host"], port=r["port"], slave_id=r["slave_id"],
                        data_type=r["data_type"], address=r["address"],
                        value=r["value"], raw_hex=r["raw_hex"],
                    )
                    for r in hr["scan_results"]
                ]
                print_table(results_objs, hr["host"])

    # 파일 저장
    if args.output:
        if args.format in ("json", "all"):
            json_path = args.output.with_suffix(".json") if args.format == "all" else args.output
            save_json(host_results, json_path)
        if args.format in ("csv", "all"):
            csv_path = args.output.with_suffix(".csv") if args.format == "all" else args.output
            save_csv(host_results, csv_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 사용 예시

```bash
# 기본 전체 스캔
python3 modbus_scanner.py -t 192.168.1.100

# 특정 데이터 타입만, 0 제외
python3 modbus_scanner.py -t 192.168.1.100 \
    --types holding input \
    --start 0 --end 999 \
    --skip-zeros

# 서브넷 다중 호스트 스캔
python3 modbus_scanner.py \
    -t 192.168.1.1 192.168.1.2 192.168.1.50 \
    --host-workers 16 \
    --workers 8 \
    -o scan_results.json \
    --format json

# 슬레이브 ID 1-10 범위 스위핑
python3 modbus_scanner.py -t 192.168.1.100 \
    --slave-range 1 10 \
    --types holding \
    --skip-zeros \
    -o slave_sweep.csv \
    --format csv

# 장치 정보만 빠르게 수집
python3 modbus_scanner.py -t 192.168.1.100 \
    --device-info-only \
    --format json \
    -o device_info.json

# 파일 기반 대규모 스캔
python3 modbus_scanner.py \
    -f /tmp/ics_hosts.txt \
    --host-workers 32 \
    --workers 8 \
    --timeout 2.0 \
    --skip-zeros \
    -o full_scan.json \
    --format all \
    -v
```

### nmap + 스캐너 파이프라인

```bash
# 1단계: nmap으로 포트 502 열린 호스트 발견
nmap -sS -p 502 --open -oG - 192.168.1.0/24 \
    | awk '/^Host/{print $2}' > modbus_hosts.txt

# 2단계: Modbus 스캐너로 전체 열거
python3 modbus_scanner.py \
    -f modbus_hosts.txt \
    --host-workers 20 \
    --skip-zeros \
    -o modbus_full.json \
    --format all

# 3단계: 결과 분석 — 위험 레지스터 탐색
python3 -c "
import json
with open('modbus_full.json') as f:
    data = json.load(f)
for host_data in data:
    host = host_data['host']
    for reg in host_data.get('scan_results', []):
        if reg['data_type'] == 'holding' and reg['value'] > 0:
            # 일반적인 위험 레지스터 범위 확인
            addr = reg['address']
            val = reg['value']
            if 40001 <= addr <= 40100:
                print(f'[경고] {host} HR[{addr}]={val} — 설정값 범위')
            elif val > 32767:
                print(f'[주의] {host} HR[{addr}]={val} — 비정상 고값')
"
```

---

## 참고 문헌

- Modbus Application Protocol Specification V1.1b3 (modbus.org)
- DNP3 Technical Bulletin (Triangle MicroWorks)
- IEC 61850 Edition 2.0 (IEC TC57)
- NIST SP 800-82 Rev.3: Guide to OT Security
- Project Redpoint — Digital Bond (github.com/digitalbond/Redpoint)

---

<!-- detect-validate-37 -->
## ICS 정찰 탐지와 프로토콜 노출 검증

ICS 정찰은 *Modbus/DNP3/IEC 61850/EtherNet-IP 스캐닝·Shodan 노출·S7 열거*로 제어 시스템을 식별한다. OT 프로토콜은 인증이 약하므로 방어자는 **제어망이 인터넷에 노출되지 않고 정찰 트래픽이 탐지되는가**를 검증해야 한다. 검증은 **소유 OT 랩/세그먼트**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| Modbus 스캔 | 인증 없는 질의 | 세그먼트·ACL | 외부발 502/tcp |
| Shodan 노출 | 인터넷 직결 | OT 인터넷 차단 | 공개 OT 배너 |
| 디바이스 열거 | 식별 정보 응답 | 패시브 모니터 | 비정상 식별 질의 |
| 프로토콜 스캐닝 | 평문 프로토콜 | 수동 자산 인벤토리 | 신규 스캔 소스 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 OT 세그먼트가 외부에서 도달 가능한지 — Modbus/502 응답 시 노출 신호(소유 IP만)
nmap -Pn -p 502,20000,44818,102 --open ot-lab.example.internal 2>/dev/null | grep -E 'open|502'
# 2) OT 캡처에서 비인가 정찰/식별 질의 — 외부 소스의 디바이스 ID 읽기 신호
tshark -r ot_capture.pcap -Y 'modbus.func_code==43 || mbtcp' -T fields -e ip.src 2>/dev/null | sort | uniq -c | head
```

> ICS 정찰 방어는 *제어망이 안 보이는가*다 — "PLC가 동작한다"와 "OT가 인터넷에 노출 안 되고 외부 정찰 질의가 패시브 모니터에 잡힌다"는 다르다. 소유 OT 랩에서 노출 표면을 직접 확인한다([[63_OT_ICS_Advanced]], [[02_Network_Hacking]], [[27_IoT_Hacking]]).

---

<a name="english"></a>

# 01 — ICS Protocols Deep Dive and Reconnaissance

## Table of Contents
1. Modbus Protocol In-Depth
2. DNP3 Protocol In-Depth
3. IEC 61850 Protocol
4. EtherNet/IP Protocol
5. Shodan ICS Reconnaissance
6. S7scan and Redpoint NSE Scripts
7. PLC Fingerprinting and Tag Enumeration
8. Python Tool: Modbus Full Scanner

---

## 1. Modbus Protocol In-Depth

### Protocol Structure

Modbus is a serial communication protocol developed by Modicon in 1979, and is the most widely used protocol in ICS environments. It uses TCP port 502 and has **no authentication whatsoever**.

```
[MBAP Header (7 bytes)] + [PDU (max 253 bytes)]

MBAP Header:
  Transaction ID : 2 bytes
  Protocol ID   : 2 bytes (always 0x0000)
  Length        : 2 bytes (byte count that follows)
  Unit ID       : 1 byte (slave address)

PDU:
  Function Code : 1 byte
  Data          : variable
```

### Complete Function Code (FC) List

| FC | Name | Data Type | Read/Write |
|----|------|-----------|------------|
| 0x01 | Read Coils | Digital Output | Read |
| 0x02 | Read Discrete Inputs | Digital Input | Read |
| 0x03 | Read Holding Registers | Analog Output | Read |
| 0x04 | Read Input Registers | Analog Input | Read |
| 0x05 | Write Single Coil | Digital Output | Write |
| 0x06 | Write Single Register | Analog Output | Write |
| 0x0F | Write Multiple Coils | Digital Output | Write |
| 0x10 | Write Multiple Registers | Analog Output | Write |

---

## 2. DNP3 Protocol In-Depth

DNP3 (Distributed Network Protocol 3) is widely used in SCADA for utilities such as electricity, water, and gas. It uses TCP port 20000. Key function codes include READ (0x01), WRITE (0x02), DIRECT_OPERATE (0x05), and COLD_RESTART (0x0D). The protocol lacks encryption and authentication in many implementations.

---

## 3. IEC 61850 Protocol

IEC 61850 is an international standard for substation automation comprising multiple sub-protocols:

- **MMS (Manufacturing Message Specification)**: TCP port 102, SCADA ↔ IED communication
- **GOOSE (Generic Object Oriented Substation Event)**: Multicast, circuit breaker state events
- **SV (Sampled Values)**: Multicast, current/voltage measurements
- **CID files**: Device configuration described in Substation Configuration Language (SCL)

---

## 4. EtherNet/IP Protocol

EtherNet/IP (Ethernet Industrial Protocol) is an industrial Ethernet protocol developed by Rockwell Automation, and the default communication method for Allen-Bradley PLCs.

- **TCP port 44818**: Explicit messaging (configuration, programming)
- **UDP port 2222**: Implicit messaging (real-time I/O)
- Operates over **CIP (Common Industrial Protocol)**

---

## 5. Shodan ICS Reconnaissance

Effective Shodan queries for ICS asset discovery:
- `port:502 modbus` — Modbus devices
- `port:102 "S7"` — Siemens S7 PLCs
- `port:44818 "Allen-Bradley"` — EtherNet/IP devices
- `port:20000 "DNP3"` — DNP3 RTUs
- `tag:ics country:KR` — Korean ICS assets

---

## 6. S7scan and Redpoint NSE Scripts

S7scan enumerates Siemens S7 PLC information including system name, module type, serial number, AS name, firmware version, and plant ID. Nmap Redpoint NSE scripts support modbus-discover, s7-info, enip-info, dnp3-info, and bacnet-info for comprehensive ICS scanning.

---

## 7. PLC Fingerprinting and Tag Enumeration

- **Siemens S7**: Use python-snap7 to read CPU info (module name, serial number, AS name, CPU state)
- **Allen-Bradley**: Use pycomm3 LogixDriver to list all tags, data types, and program names, then read values
- **Schneider Modicon**: Use pymodbus to read holding registers and input registers directly via Modbus TCP

---

## 8. Python Tool: Modbus Full Scanner

A complete CLI tool that enumerates all coils and registers of a Modbus device and saves results as JSON/CSV. Features include multi-host scanning with thread pools, slave ID range sweeping, zero-value filtering, device identification (FC 0x2B), and parallel chunk reading.

### Usage Examples

```bash
# Basic full scan of single host
python3 modbus_scanner.py -t 192.168.1.100

# Holding/input registers only, skip zeros
python3 modbus_scanner.py -t 192.168.1.100 \
    --types holding input --start 0 --end 999 --skip-zeros

# Subnet multi-host scan
python3 modbus_scanner.py \
    -t 192.168.1.1 192.168.1.2 192.168.1.50 \
    --host-workers 16 --workers 8 \
    -o scan_results.json --format json
```

---

## References

- Modbus Application Protocol Specification V1.1b3 (modbus.org)
- DNP3 Technical Bulletin (Triangle MicroWorks)
- IEC 61850 Edition 2.0 (IEC TC57)
- NIST SP 800-82 Rev.3: Guide to OT Security
- Project Redpoint — Digital Bond (github.com/digitalbond/Redpoint)

<!-- detect-validate-37 -->
## ICS Recon Detection and Protocol-Exposure Validation

ICS recon identifies control systems via *Modbus/DNP3/IEC 61850/EtherNet-IP scanning, Shodan exposure, and S7 enumeration*. OT protocols are weakly authenticated, so defenders must verify **whether the control network is not internet-exposed and recon traffic is detected**. Validate only on **owned OT labs/segments**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Modbus scan | Unauthenticated query | Segment, ACL | External 502/tcp |
| Shodan exposure | Direct internet | Block OT internet | Public OT banner |
| Device enumeration | Identity responses | Passive monitor | Anomalous identity query |
| Protocol scanning | Plaintext protocol | Passive asset inventory | New scan source |

### Defense validation (verify directly)

```bash
# 1) Whether the owned OT segment is externally reachable — a Modbus/502 response signals exposure (owned IPs only)
nmap -Pn -p 502,20000,44818,102 --open ot-lab.example.internal 2>/dev/null | grep -E 'open|502'
# 2) Unauthorized recon/identity queries in OT capture — external-source device-ID reads are the signal
tshark -r ot_capture.pcap -Y 'modbus.func_code==43 || mbtcp' -T fields -e ip.src 2>/dev/null | sort | uniq -c | head
```

> ICS recon defense is *whether the control network is invisible* -- "the PLC works" differs from "OT is not internet-exposed and external recon queries are caught by passive monitoring". Confirm the exposure surface on owned OT labs directly ([[63_OT_ICS_Advanced]], [[02_Network_Hacking]], [[27_IoT_Hacking]]).
