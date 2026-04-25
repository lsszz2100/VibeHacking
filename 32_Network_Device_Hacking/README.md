# 32. 네트워크 장비 해킹 — 라우터·스위치의 관리 평면을 직접 노린다

> **이 섹션이 다루는 것**: 엔드포인트나 서버가 아니라 **네트워크 장비 그 자체** — Cisco IOS/IOS XE/NX-OS, Juniper, FRRouting이 돌아가는 라우터·스위치를 표적으로 하는 공격과 방어.
> 섹션 02(네트워크 해킹)는 트래픽을 스니핑·MITM 하는 관점, 섹션 24(네트워크 인프라 보안)는 DNS·메일·SSH 같은 서비스 레벨 관점인 반면, 이 섹션은 **장비의 관리 평면(management plane)**·**제어 평면(control plane)**·**데이터 평면(data plane)** 공격을 체계적으로 다룹니다.

## 왜 이 주제가 중요한가

대부분의 기업 침해 리포트에서 라우터·스위치는 "잊혀진 장비"로 등장합니다. 10년간 한 번도 IOS 업데이트를 못 받은 기업 에지 라우터, 공장 출하 상태의 SNMP 커뮤니티 스트링 `public`, 관리 VLAN이 분리되지 않은 ACL. 공격자가 이 한 대를 잡으면:

- 내부 네트워크 전체 트래픽 **미러링·리다이렉션**
- 방화벽 ACL을 **돌려서 통과**
- BGP·OSPF 경로를 조작해 **전 세계 라우팅을 기울이기** (2008년 파키스탄 BGP 유출, 2024년 미국 통신사 BGP 하이재킹 사건 참고)
- **지속성(persistence)** 확보에 이상적 — EDR이 설치되지 않는 곳

2025년만 해도 Cisco가 반기 보안 번들에서 발표한 IOS/IOS XE 취약점이 수십 건에 달하고, 그 중 다수가 **인증 없이 원격 공격이 가능**합니다. 업계에서 "망 장비는 한 번 설치하면 끝"이라는 문화가 여전하기 때문에 패치 지연이 곧 공격면입니다.

## 목차

| # | 파일 | 주제 | 난이도 |
|---|------|------|--------|
| 01 | [ios_fundamentals_and_recon.md](01_ios_fundamentals_and_recon.md) | IOS/IOS XE 구조, 장비 핑거프린팅, 관리 프로토콜 정찰 | ★★ |
| 02 | [layer2_attacks.md](02_layer2_attacks.md) | VLAN hopping, STP/DHCP 공격, CAM overflow, DAI 우회 | ★★★ |
| 03 | [routing_protocol_attacks.md](03_routing_protocol_attacks.md) | OSPF/EIGRP/BGP 경로 주입, HSRP/VRRP 하이재킹 | ★★★★ |
| 04 | [management_plane_exploitation.md](04_management_plane_exploitation.md) | SNMP·TACACS+·NETCONF·설정 파일 추출, 장비 백도어 식별 | ★★★★ |

## 선수 지식

- **OSI 2–3계층 프로토콜**: Ethernet, 802.1Q, ARP, ICMP, IP, TCP/UDP 기본
- **라우팅 기초**: 라우팅 테이블, 스태틱/다이내믹 라우팅 개념
- **Cisco CLI 기초**: `show running-config`, `configure terminal`, 인터페이스 모드 전환
- **Python 3.10+**: Scapy로 Layer 2 프레임을 짜본 경험이 있으면 체감 난이도가 크게 낮아집니다

## 실습 환경 구성 — GNS3 또는 EVE-NG 필수

네트워크 장비 공격은 **실제 트래픽 흐름**을 재현해야 감을 잡을 수 있고, 다행히 요즘은 가상 장비 이미지로 노트북 한 대에 복합 토폴로지를 올릴 수 있습니다.

### 권장 스택

| 구성요소 | 선택 |
|----------|------|
| 에뮬레이터 | **GNS3** (오픈소스, 초심자 친화) 또는 **EVE-NG Community** (대규모 토폴로지) |
| 라우터 이미지 | Cisco IOSv / IOSvL2 (가상 스위치), FRRouting (Linux 기반 오픈 라우터) |
| 공격자 VM | Kali Linux 2026.x 또는 Ubuntu 24.04 + scapy, yersinia, ettercap |
| 타깃 서브넷 | 공격자·피해자·관리 VLAN 최소 3개 |

### 최소 토폴로지 예시

```
                    ┌──────────────┐
                    │ Core Router  │  (IOSv, BGP 스피커)
                    │  R1          │
                    └───────┬──────┘
                            │ trunk
                 ┌──────────┼──────────┐
                 │                     │
         ┌───────┴──────┐       ┌──────┴───────┐
         │  Switch SW1  │       │  Switch SW2  │ (IOSvL2)
         └───────┬──────┘       └──────┬───────┘
                 │                     │
     ┌───────────┴───┐           ┌─────┴─────┐
     │ Victim VLAN10 │           │ Mgmt VLAN │
     │ (Win/Linux)   │           │ 관리자 PC │
     └───────────────┘           └───────────┘
                 │
         ┌───────┴──────┐
         │ Attacker     │  ← 우리가 점유한 노드 (Kali)
         │ VLAN10       │
         └──────────────┘
```

### 법적·윤리적 전제

- 이 섹션의 모든 기법은 **본인이 소유하거나 명시적으로 허가받은 환경**에서만 수행합니다.
- 실제 운영망에서의 ARP 스푸핑·BGP 주입은 통신망법 위반입니다.
- 공개 CTF·버그바운티 프로그램(HackerOne, Bugcrowd의 네트워크 장비 범위), 업무상 모의해킹 계약이 있는 경우에만 실제 기법 시연이 가능합니다.

## 이 섹션에서 다루는 2024–2026년 실제 취약점

학습만으로는 부족하고, **작동 사례**를 알아야 설계가 보입니다. 최신 CVE들이 본문 곳곳에 등장합니다.

| CVE | 제품 | 요약 |
|-----|------|------|
| CVE-2026-20084 | Cisco Catalyst 9000 | DHCP Snooping BOOTP VLAN Leakage (CVSS 8.6) |
| CVE-2025-20188 | Cisco IOS XE Wireless | WLC 원격 RCE (CVSS 10.0) |
| CVE-2025-20115 | Cisco IOS XR | BGP confederation을 통한 BGP 프로세스 크래시 |
| CVE-2025-61105 | FRRouting | OSPF 디버그 덤프 처리 중 원격 DoS |
| CVE-2023-20198 | Cisco IOS XE | Web UI 인증 우회 → 최고권한 계정 생성 (실제 대규모 악용) |
| CVE-2012-1675 | Oracle TNS | (섹션 23과 연계) 레거시 네트워크에 여전히 살아있음 |

## 도구 사전 준비

```bash
# 주요 공격 도구 (Kali Linux 기준, Ubuntu도 대부분 동일)

# Scapy — Layer 2~4 프레임을 원하는 대로 만들어 쏠 수 있는 파이썬 라이브러리
pip install scapy

# Yersinia — 스위치 공격 특화 (STP/CDP/DTP/HSRP/DHCP 페이로드 생성기)
sudo apt install yersinia

# Ettercap — ARP 스푸핑/중간자 공격, 필터 스크립팅 지원
sudo apt install ettercap-text-only

# Loki — 라우팅 프로토콜 공격 특화 (OSPF/BGP/RIP/HSRP 페이로드)
git clone https://github.com/raizo62/loki_on_kali.git

# onesixtyone — 빠른 SNMP 커뮤니티 스트링 브루트포스
sudo apt install onesixtyone

# snmpwalk (net-snmp) — SNMP OID 탐색용 기본 도구
sudo apt install snmp

# nmap — 네트워크 장비 지문 감식에 필수
sudo apt install nmap
```

## 학습 목표

이 섹션을 끝내면 다음을 직접 수행할 수 있습니다.

- 네트워크 장비의 **관리·제어·데이터 평면을 구분**해 위협을 모델링한다.
- Scapy로 **커스텀 802.1Q 더블태깅 프레임**을 만들어 VLAN hopping을 재현한다.
- FRRouting 또는 스캐피로 **OSPF 가짜 LSA**를 주입해 라우팅 테이블을 오염시키고, 방어로 OSPF 인증·area filter를 구성한다.
- **SNMP v1/v2c의 약점을 공격 측면에서 재현**하고, SNMPv3 + VACM으로 강화한다.
- 라우터 설정 파일에 남은 **type 7 / type 5 / type 8 패스워드 해시를 식별하고 크래킹 가능성을 판단**한다.
- 네트워크 장비 **강화(hardening) 체크리스트**를 작성해 팀 플레이북에 반영한다.

## 관련 섹션

- [02. 네트워크 해킹](../02_Network_Hacking/) — 트래픽 스니핑·MITM 기본
- [22. 패스워드 크래킹](../22_Password_Cracking/) — Cisco type 7/5/8 해시 크래킹
- [24. 네트워크 인프라 보안](../24_Network_Infrastructure_Security/) — 서비스 레벨 (DNS·메일·SSH)
- [25. 위협 인텔리전스](../25_Threat_Intelligence/) — 네트워크 장비 침해 IOC 수집
