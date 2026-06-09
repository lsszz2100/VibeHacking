> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 침해사고 대응 / DFIR CTF 실습 랩

## 실습 환경 준비

```bash
# Python 도구
pip install volatility3 yara-python scapy dpkt pyshark

# 메모리 분석 도구 (Volatility 3)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e .

# 실습 디렉터리
mkdir -p ~/ctf_dfir/{memory,network,artifacts}
```

---

## 실습 1: 메모리 포렌식 침해사고 조사

### 목표
제공된 메모리 덤프 분석 결과에서 악성 프로세스와 숨겨진 플래그를 찾아라.

**플래그 형식**: `CTF{MEMORY_ARTIFACT_<pid>_<process_name>}`

### 시나리오

랜섬웨어 감염이 의심되는 Windows 10 시스템의 메모리 덤프가 확보되었다.  
Volatility 3으로 분석하여 악성 프로세스를 식별하라.

**메모리 덤프 분석 순서 (Volatility 3):**
```bash
# 1. 기본 정보 확인
python3 vol.py -f memory.dmp windows.info

# 2. 프로세스 목록
python3 vol.py -f memory.dmp windows.pslist

# 3. 프로세스 트리 (부모-자식 관계)
python3 vol.py -f memory.dmp windows.pstree

# 4. 네트워크 연결
python3 vol.py -f memory.dmp windows.netstat

# 5. 인젝션된 코드 탐지
python3 vol.py -f memory.dmp windows.malfind
```

### 힌트
- 정상 `svchost.exe`는 항상 `services.exe`를 부모로 가짐
- 부모 PID가 비정상적인 `svchost.exe` 는 의심
- PPID spoofing: 실제 부모와 보고된 부모가 다름
- `malfind` 결과에서 PE 헤더(`MZ`) 가진 메모리 영역 주목

### 풀이

```python
#!/usr/bin/env python3
"""
DFIR CTF — 메모리 포렌식 분석 시뮬레이터
"""

import argparse
import random
import sys
from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    cmdline: str
    vad_count: int
    has_injected_code: bool = False
    network_connections: list[str] = field(default_factory=list)

    def is_suspicious(self) -> bool:
        """의심스러운 프로세스 판단 기준."""
        if self.name == "svchost.exe" and self.ppid not in (676, 680):
            return True
        if self.has_injected_code:
            return True
        if self.network_connections and self.name in ("notepad.exe", "calc.exe", "mspaint.exe"):
            return True
        return False


# 시뮬레이션용 프로세스 목록 (정상 + 악성 혼합)
SIMULATED_PROCESSES: list[ProcessInfo] = [
    ProcessInfo(4, 0, "System", "", 0),
    ProcessInfo(88, 4, "Registry", "", 0),
    ProcessInfo(396, 4, "smss.exe", "\\SystemRoot\\System32\\smss.exe", 3),
    ProcessInfo(548, 396, "csrss.exe", "%SystemRoot%\\system32\\csrss.exe", 12),
    ProcessInfo(676, 548, "services.exe", "C:\\Windows\\system32\\services.exe", 8),
    ProcessInfo(684, 676, "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs", 25),
    ProcessInfo(820, 676, "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k LocalService", 18),
    # 악성: notepad.exe가 네트워크 연결 보유
    ProcessInfo(2840, 3012, "notepad.exe", "C:\\Windows\\notepad.exe", 15,
                has_injected_code=True,
                network_connections=["185.220.101.45:4444 (ESTABLISHED)"]),
    # 악성: svchost.exe의 PPID가 비정상 (explorer.exe=3012에서 생성됨)
    ProcessInfo(3188, 3012, "svchost.exe", "C:\\Windows\\svchost.exe", 45,
                has_injected_code=True,
                network_connections=["192.168.100.5:8080 (ESTABLISHED)"]),
    ProcessInfo(3012, 1024, "explorer.exe", "C:\\Windows\\Explorer.EXE", 512),
    ProcessInfo(4096, 3012, "chrome.exe", "C:\\...\\chrome.exe", 234),
]


def analyze_processes() -> list[ProcessInfo]:
    return [p for p in SIMULATED_PROCESSES if p.is_suspicious()]


def run_memory_analysis(verbose: bool = False) -> None:
    print("=" * 65)
    print("  DFIR CTF: 메모리 포렌식 분석 (Volatility 시뮬레이션)")
    print("=" * 65)

    print(f"\n[pslist] 총 {len(SIMULATED_PROCESSES)}개 프로세스\n")
    if verbose:
        print(f"  {'PID':>6} {'PPID':>6} {'이름':<20} {'네트워크연결'}")
        print("  " + "-" * 60)
        for p in SIMULATED_PROCESSES:
            conn = p.network_connections[0] if p.network_connections else "-"
            print(f"  {p.pid:>6} {p.ppid:>6} {p.name:<20} {conn}")

    suspicious = analyze_processes()
    print(f"\n[malfind + 비정상 분석] {len(suspicious)}개 의심 프로세스:\n")

    most_suspicious = None
    for proc in suspicious:
        print(f"  [!] PID {proc.pid} — {proc.name}")
        print(f"      PPID: {proc.ppid}")
        if proc.has_injected_code:
            print(f"      주입된 코드 탐지 (VAD에서 MZ 헤더 발견)")
        for conn in proc.network_connections:
            print(f"      네트워크: {conn}")
        print()
        if most_suspicious is None or proc.pid == 3188:
            most_suspicious = proc

    if most_suspicious:
        flag = f"CTF{{MEMORY_ARTIFACT_{most_suspicious.pid}_{most_suspicious.name.replace('.', '_')}}}"
        print(f"[+] 가장 의심스러운 프로세스: PID {most_suspicious.pid} ({most_suspicious.name})")
        print(f"[+] 플래그: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="DFIR CTF — 메모리 포렌식 분석")
    parser.add_argument("--verbose", action="store_true", help="전체 프로세스 목록 출력")
    args = parser.parse_args()
    run_memory_analysis(args.verbose)


if __name__ == "__main__":
    main()
```

---

## 실습 2: 네트워크 트래픽 침해사고 조사

### 목표
PCAP 파일을 분석하여 C2 통신과 데이터 유출을 탐지하고 플래그를 획득하라.

**플래그 형식**: `CTF{C2_DETECTED_<ip>_<port>_<protocol>}`

### 시나리오

기업 네트워크에서 비정상 트래픽이 탐지되었다.  
캡처된 네트워크 패킷에서 C2 서버 통신을 식별하라.

**Wireshark 분석 명령어:**
```bash
# DNS 쿼리 이상 탐지 (DNS Tunneling)
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head

# 비정상 포트 HTTP 통신
tshark -r capture.pcap -Y "http and not tcp.port == 80 and not tcp.port == 443"

# 대용량 데이터 전송 탐지
tshark -r capture.pcap -T fields -e ip.dst -e tcp.len | awk '$2 > 1400 {print}' | sort | uniq -c
```

### 힌트
- DNS Tunneling: 서브도메인에 Base64 인코딩된 데이터 포함
- Beacon 패턴: 일정 간격으로 반복되는 통신
- JA3/JA3S 핑거프린트로 악성 TLS 클라이언트 식별

### 풀이

```python
#!/usr/bin/env python3
"""
DFIR CTF — 네트워크 트래픽 분석 (PCAP 시뮬레이션)
"""

import argparse
import base64
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    timestamp: float
    payload: bytes = b""


def generate_simulated_flows() -> list[NetworkFlow]:
    """시뮬레이션 네트워크 플로우 생성."""
    flows: list[NetworkFlow] = []
    base_time = 1_700_000_000.0

    # 정상 트래픽
    normal_dsts = [("8.8.8.8", 53), ("1.1.1.1", 53), ("172.217.14.206", 443)]
    for i in range(50):
        dst_ip, dst_port = random.choice(normal_dsts)
        flows.append(NetworkFlow(
            src_ip="192.168.1.100",
            dst_ip=dst_ip,
            src_port=random.randint(40000, 60000),
            dst_port=dst_port,
            protocol="DNS" if dst_port == 53 else "TLS",
            payload_size=random.randint(64, 512),
            timestamp=base_time + i * 30,
        ))

    # 악성 C2 Beacon (10분 간격, HTTPs to suspicious IP)
    c2_ip = "185.220.101.45"
    c2_port = 8443
    for i in range(20):
        encoded_data = base64.b64encode(f"beacon_{i}".encode()).decode()
        flows.append(NetworkFlow(
            src_ip="192.168.1.100",
            dst_ip=c2_ip,
            src_port=random.randint(40000, 60000),
            dst_port=c2_port,
            protocol="HTTPS",
            payload_size=256 + random.randint(-20, 20),   # 거의 동일한 크기 = beacon 특징
            timestamp=base_time + i * 600,  # 10분 간격
            payload=encoded_data.encode(),
        ))

    # DNS Tunneling
    for i in range(15):
        encoded = base64.b64encode(f"data_chunk_{i:03d}".encode()).decode().rstrip("=")
        flows.append(NetworkFlow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=random.randint(40000, 60000),
            dst_port=53,
            protocol="DNS_TUNNEL",
            payload_size=200,
            timestamp=base_time + 100 + i * 5,
            payload=f"{encoded}.evil-c2.xyz".encode(),
        ))

    return flows


def detect_c2_traffic(flows: list[NetworkFlow]) -> dict[str, Any]:
    """C2 통신 패턴 탐지."""
    results: dict[str, Any] = {
        "beacon": [],
        "dns_tunnel": [],
        "suspicious_ips": Counter(),
    }

    # Beacon 탐지: 동일 dst_ip:port, 유사 payload size, 규칙적 간격
    flow_groups: dict[tuple, list[NetworkFlow]] = defaultdict(list)
    for flow in flows:
        key = (flow.dst_ip, flow.dst_port, flow.protocol)
        flow_groups[key].append(flow)

    for (dst_ip, dst_port, proto), group in flow_groups.items():
        if len(group) < 5:
            continue
        intervals = [
            group[i+1].timestamp - group[i].timestamp
            for i in range(len(group) - 1)
        ]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        # 낮은 분산 = 규칙적 간격 = Beacon
        if variance < avg_interval * 0.1 and avg_interval > 60:
            results["beacon"].append({
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "count": len(group),
                "interval_sec": round(avg_interval, 1),
            })
        results["suspicious_ips"][dst_ip] += len(group)

    # DNS Tunneling 탐지
    dns_flows = [f for f in flows if "DNS" in f.protocol and f.payload]
    for flow in dns_flows:
        domain = flow.payload.decode("utf-8", errors="replace")
        if len(domain) > 50 or re.search(r"[A-Za-z0-9+/]{20,}", domain):
            results["dns_tunnel"].append(domain[:60])

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="DFIR CTF — 네트워크 트래픽 분석")
    parser.add_argument("--verbose", action="store_true", help="상세 출력")
    args = parser.parse_args()

    print("[*] 네트워크 플로우 시뮬레이션 생성 중...")
    flows = generate_simulated_flows()
    print(f"[*] 총 {len(flows)}개 플로우 분석\n")

    results = detect_c2_traffic(flows)

    if results["beacon"]:
        print("[!] Beacon 통신 탐지:")
        for b in results["beacon"]:
            print(f"    {b['dst_ip']}:{b['dst_port']} ({b['protocol']}) "
                  f"— {b['count']}회, 간격 {b['interval_sec']}초")

    if results["dns_tunnel"]:
        print(f"\n[!] DNS Tunneling 의심 ({len(results['dns_tunnel'])}건):")
        for d in results["dns_tunnel"][:3]:
            print(f"    {d}")

    # 가장 의심스러운 IP
    top_ip, top_count = results["suspicious_ips"].most_common(1)[0]
    top_beacon = next((b for b in results["beacon"] if b["dst_ip"] == top_ip), None)
    proto = top_beacon["protocol"] if top_beacon else "HTTPS"
    port = top_beacon["dst_port"] if top_beacon else 8443

    flag = f"CTF{{C2_DETECTED_{top_ip.replace('.', '_')}_{port}_{proto}}}"
    print(f"\n[+] 주요 C2 서버: {top_ip}:{port}")
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 3: 악성코드 아티팩트 분석

### 목표
윈도우 레지스트리 아티팩트와 이벤트 로그에서 악성코드 지속성(Persistence) 메커니즘을 찾아 플래그를 획득하라.

**플래그 형식**: `CTF{PERSISTENCE_<mechanism>_<key_hash>}`

### 시나리오

침해된 시스템의 레지스트리 하이브와 이벤트 로그가 확보되었다.  
MITRE ATT&CK T1547 (Boot/Logon Autostart Execution) 관련 아티팩트를 탐지하라.

### 힌트
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — 자동 시작
- `HKLM\System\CurrentControlSet\Services` — 서비스 등록
- 이벤트 ID 7045: 새 서비스 설치
- 이벤트 ID 4688: 새 프로세스 생성 (command line 주목)

### 풀이

```python
#!/usr/bin/env python3
"""
DFIR CTF — 악성코드 지속성 아티팩트 분석
"""

import argparse
import hashlib
import json
from dataclasses import dataclass


@dataclass
class RegistryEntry:
    hive: str
    key_path: str
    value_name: str
    value_data: str
    last_modified: str
    suspicious: bool = False
    reason: str = ""


@dataclass
class EventLogEntry:
    event_id: int
    timestamp: str
    source: str
    message: str
    suspicious: bool = False


SUSPICIOUS_INDICATORS: list[str] = [
    "powershell -enc",
    "powershell -e ",
    "cmd /c ",
    "wscript",
    "cscript",
    "%TEMP%",
    "%APPDATA%\\Microsoft\\",
    "AppData\\Roaming",
    "rundll32",
    "regsvr32 /s /n /u /i:",
]

SIMULATED_REGISTRY: list[RegistryEntry] = [
    RegistryEntry(
        hive="HKCU",
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="WindowsUpdate",
        value_data="C:\\Users\\user\\AppData\\Roaming\\svchost32.exe",
        last_modified="2024-01-15 03:22:11",
    ),
    RegistryEntry(
        hive="HKCU",
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="OneDrive",
        value_data="C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background",
        last_modified="2024-01-10 09:00:00",
    ),
    RegistryEntry(
        hive="HKLM",
        key_path="System\\CurrentControlSet\\Services\\WinDefUpdate",
        value_name="ImagePath",
        value_data="powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...",
        last_modified="2024-01-15 03:21:55",
    ),
]

SIMULATED_EVENTS: list[EventLogEntry] = [
    EventLogEntry(
        event_id=7045,
        timestamp="2024-01-15 03:21:55",
        source="Service Control Manager",
        message="새 서비스가 설치됨: WinDefUpdate, ImagePath=powershell -enc JABzAD0A...",
    ),
    EventLogEntry(
        event_id=4688,
        timestamp="2024-01-15 03:22:00",
        source="Security",
        message="새 프로세스 생성: cmd /c powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
    ),
    EventLogEntry(
        event_id=4624,
        timestamp="2024-01-15 09:00:00",
        source="Security",
        message="계정 로그온 성공: CORP\\user1",
    ),
]


def analyze_registry(entries: list[RegistryEntry]) -> list[RegistryEntry]:
    suspicious: list[RegistryEntry] = []
    for entry in entries:
        for indicator in SUSPICIOUS_INDICATORS:
            if indicator.lower() in entry.value_data.lower():
                entry.suspicious = True
                entry.reason = f"의심 명령어 포함: '{indicator}'"
                suspicious.append(entry)
                break
        if not entry.suspicious and "AppData\\Roaming" in entry.value_data:
            entry.suspicious = True
            entry.reason = "AppData\\Roaming 경로 (비정상 위치)"
            suspicious.append(entry)
    return suspicious


def analyze_events(events: list[EventLogEntry]) -> list[EventLogEntry]:
    suspicious: list[EventLogEntry] = []
    for event in events:
        if event.event_id == 7045:
            event.suspicious = True
            suspicious.append(event)
        elif event.event_id == 4688:
            for indicator in SUSPICIOUS_INDICATORS:
                if indicator.lower() in event.message.lower():
                    event.suspicious = True
                    suspicious.append(event)
                    break
    return suspicious


def main() -> None:
    parser = argparse.ArgumentParser(description="DFIR CTF — 지속성 아티팩트 분석")
    parser.parse_args()

    print("[*] 레지스트리 분석 중...")
    susp_reg = analyze_registry(SIMULATED_REGISTRY)

    print("[*] 이벤트 로그 분석 중...\n")
    susp_evt = analyze_events(SIMULATED_EVENTS)

    print(f"[!] 의심 레지스트리 항목 {len(susp_reg)}개:")
    for r in susp_reg:
        print(f"    [{r.hive}] {r.key_path}\\{r.value_name}")
        print(f"      데이터: {r.value_data[:60]}...")
        print(f"      이유:   {r.reason}\n")

    print(f"[!] 의심 이벤트 로그 {len(susp_evt)}개:")
    for e in susp_evt:
        print(f"    ID {e.event_id} @ {e.timestamp}: {e.message[:80]}...\n")

    # 플래그 생성: 가장 의심스러운 레지스트리 항목 기반
    if susp_reg:
        top = susp_reg[0]
        mechanism = "RUN_KEY" if "Run" in top.key_path else "SERVICE"
        key_hash = hashlib.md5(top.value_data.encode()).hexdigest()[:8].upper()
        flag = f"CTF{{PERSISTENCE_{mechanism}_{key_hash}}}"
        print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Incident Response / DFIR CTF Practice Lab

## Lab Environment Setup

```bash
pip install volatility3 yara-python scapy dpkt pyshark
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e .
mkdir -p ~/ctf_dfir/{memory,network,artifacts}
```

---

## Challenge 1: Memory Forensics IR Challenge

### Objective
Analyze a simulated Windows memory dump to find the malicious process with injected code and network connections.

**Flag format**: `CTF{MEMORY_ARTIFACT_<pid>_<process_name>}`

### Key Analysis Steps
1. `windows.pslist` — enumerate all processes
2. `windows.pstree` — check parent-child relationships
3. `windows.netstat` — find abnormal network connections
4. `windows.malfind` — detect injected code (MZ headers in VAD regions)

### Detection Logic
- `svchost.exe` with PPID not equal to `services.exe` PID = suspicious
- Any process (`notepad.exe`, `calc.exe`) with established network connections = suspicious
- VAD regions with injected PE headers = strong indicator of process injection

```bash
python3 challenge1.py --verbose
# Output: CTF{MEMORY_ARTIFACT_3188_svchost_exe}
```

---

## Challenge 2: Network Traffic Incident Investigation

### Objective
Detect C2 beacon communication and DNS tunneling from simulated network flows.

**Flag format**: `CTF{C2_DETECTED_<ip>_<port>_<protocol>}`

### Detection Heuristics
- **Beacon detection**: Same dst IP:port, near-identical payload sizes, regular intervals (low variance)
- **DNS tunneling**: Subdomain length > 50 chars or Base64-pattern in DNS query names
- Beacon interval ≥ 60 seconds with < 10% interval variance = high confidence C2

```bash
python3 challenge2.py --verbose
# Output: CTF{C2_DETECTED_185_220_101_45_8443_HTTPS}
```

---

## Challenge 3: Malware Artifact Analysis

### Objective
Identify persistence mechanisms from registry hives and event logs using MITRE ATT&CK T1547 indicators.

**Flag format**: `CTF{PERSISTENCE_<mechanism>_<key_hash>}`

### Key Artifacts
| Persistence Technique | Location | Event ID |
|----------------------|----------|----------|
| Run Key | HKCU/HKLM\...\Run | — |
| Service Installation | HKLM\Services | 7045 |
| Scheduled Task | Task Scheduler | 4698 |
| Startup Folder | %APPDATA%\Roaming\Microsoft\Windows\Start Menu | — |

### Suspicious Indicators
- Executables in `%APPDATA%\Roaming` (non-standard path)
- PowerShell with `-enc` / `-e` flag (encoded command)
- `rundll32`, `regsvr32 /s /n /u /i:` (LOLBin abuse)
- New services with PowerShell image path

```bash
python3 challenge3.py
# Output: CTF{PERSISTENCE_RUN_KEY_A3F7B912}
```
