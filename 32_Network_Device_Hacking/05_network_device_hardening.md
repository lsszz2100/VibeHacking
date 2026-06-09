> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 장비 보안 강화 — Cisco·Juniper 보안 설정·네트워크 장비 모니터링

## 0. 초보자를 위한 개념 이해

### 네트워크 장비 보안이란?

라우터, 스위치, 방화벽은 네트워크의 핵심이지만 종종 보안 설정이 소홀합니다. 기본 커뮤니티 문자열(public/private), 텔넷 사용, 불필요한 서비스 활성화 등이 흔한 문제입니다.

```
네트워크 장비 보안 위협:

  인증:
    기본 자격증명       → admin/admin, cisco/cisco
    SNMP public 커뮤니티 → 전체 MIB 읽기 가능
    텔넷 사용           → 평문 자격증명 스니핑

  프로토콜:
    OSPF/BGP 인증 없음  → 라우팅 테이블 조작
    CDP 활성화          → 장비 정보 노출
    DTP 활성화          → VLAN 호핑 공격

  관리:
    HTTP 관리 인터페이스  → 암호화 없는 관리
    미패치 IOS/JunOS     → 알려진 취약점
    로그 없음            → 침해 탐지 불가
```

---

## 1. Cisco IOS 보안 강화

### 1.1 기본 Cisco IOS 강화 설정

```
! Cisco IOS 보안 강화 설정 템플릿
! 실제 환경에 맞게 IP, 인터페이스 이름 수정 필요

! ─── 1. 호스트명 및 도메인 설정 ───────────────────────────
hostname ROUTER-01
ip domain-name corp.internal

! ─── 2. 암호화 키 생성 (SSH 용) ──────────────────────────
crypto key generate rsa modulus 4096

! ─── 3. 패스워드 보안 ────────────────────────────────────
! 약한 enable password 대신 enable secret 사용 (MD5 해시)
enable secret 9 [type9-hash-here]
! Type 9 = scrypt 해시 (IOS 15.3+)
! 생성: enable algorithm-type scrypt secret MyStr0ngPass!

! 서비스 패스워드 암호화 (설정 파일 내 평문 방지)
service password-encryption

! 패스워드 최소 길이 설정
security passwords min-length 12

! ─── 4. SSH 설정 (텔넷 비활성화) ─────────────────────────
! 텔넷 완전 비활성화
no service telnet

! SSH v2만 허용
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
ip ssh maxstartups 4

! VTY 라인 SSH만 허용
line vty 0 15
 transport input ssh
 login local
 exec-timeout 10 0
 logging synchronous

! ─── 5. 콘솔 보안 ────────────────────────────────────────
line con 0
 login local
 exec-timeout 5 0
 logging synchronous

! ─── 6. AAA 설정 (RADIUS/TACACS+) ────────────────────────
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+

tacacs server TACACS-SERVER
 address ipv4 10.0.0.100
 key 7 [encrypted-key]

! ─── 7. SNMP 보안 ────────────────────────────────────────
! 기본 커뮤니티 비활성화
no snmp-server community public RO
no snmp-server community private RW

! SNMPv3 설정 (강력한 인증+암호화)
snmp-server group SNMPV3GROUP v3 priv
snmp-server user SNMPUSER SNMPV3GROUP v3 auth sha AuthPass123! priv aes 256 PrivPass456!
snmp-server host 10.0.0.200 version 3 priv SNMPUSER

! ─── 8. 불필요한 서비스 비활성화 ────────────────────────
no service finger
no service pad
no service udp-small-servers
no service tcp-small-servers
no ip bootp server
no ip http server
no ip http secure-server
no ip source-route
no ip proxy-arp
no cdp run               ! CDP (Cisco Discovery Protocol) 비활성화
no lldp run

! ─── 9. 인터페이스 보안 ──────────────────────────────────
interface GigabitEthernet0/0
 ! 사용하지 않는 인터페이스 차단
 shutdown
 no ip proxy-arp
 no ip redirects
 no ip unreachables
 no cdp enable

! ─── 10. 로깅 설정 ────────────────────────────────────────
logging buffered 65536
logging trap informational
logging host 10.0.0.200
service timestamps log datetime msec localtime show-timezone
service timestamps debug datetime msec localtime

! ─── 11. NTP 보안 ────────────────────────────────────────
ntp authenticate
ntp authentication-key 1 md5 NTPKey!2024
ntp trusted-key 1
ntp server 10.0.0.50 key 1

! ─── 12. 액세스 제한 (ACL) ──────────────────────────────
ip access-list standard MGMT-ACL
 permit 10.10.1.0 0.0.0.255    ! 관리 네트워크만 허용
 deny   any log

line vty 0 15
 access-class MGMT-ACL in
```

### 1.2 BGP 라우팅 보안 강화

```
! BGP 피어 인증 (MD5)
router bgp 65001
 neighbor 203.0.113.1 password BGPSecret!2024
 
 ! 최대 경로 수 제한 (BGP 루트 플루딩 방지)
 neighbor 203.0.113.1 maximum-prefix 500 80 restart 30

 ! BGP TTL 보안 (GTSM)
 neighbor 203.0.113.1 ttl-security hops 1

 ! BGP 커뮤니티 필터링
 neighbor 203.0.113.1 route-map FILTER-IN in

! RPKI 검증 (BGP 하이재킹 방지)
router bgp 65001
 bgp rpki server tcp 10.0.0.100 port 3323 refresh 3600
```

---

## 2. Juniper Junos 보안 강화

```
# Juniper Junos 보안 강화 설정 (set 형식)

# ─── 1. 시스템 기본 보안 ──────────────────────────────────
set system host-name SRX-FIREWALL-01
set system domain-name corp.internal

# 루트 패스워드 (평문 대신 암호화 해시 사용)
set system root-authentication encrypted-password "$6$salt$hash"

# ─── 2. SSH 설정 ──────────────────────────────────────────
set system services ssh protocol-version v2
set system services ssh max-sessions-per-connection 1
set system services ssh rate-limit 5
set system services ssh connection-limit 5
set system services ssh root-login deny

# 텔넷 비활성화 (기본 비활성화지만 명시적 설정)
delete system services telnet

# ─── 3. SNMP 보안 ────────────────────────────────────────
# SNMPv1/v2 기본 커뮤니티 제거
delete snmp community public
delete snmp community private

# SNMPv3 설정
set snmp v3 usm local-engine user SNMPV3USER
set snmp v3 usm local-engine user SNMPV3USER authentication-sha authentication-password "AuthPass!123"
set snmp v3 usm local-engine user SNMPV3USER privacy-aes128 privacy-password "PrivPass!456"
set snmp v3 vacm access group SNMPV3GROUP default-context-prefix security-model usm security-level privacy
set snmp trap-group ALERTS version v3
set snmp trap-group ALERTS targets 10.0.0.200

# ─── 4. 불필요한 서비스 비활성화 ─────────────────────────
delete system services web-management http
delete system services web-management https  # GUI 불필요시
set system services web-management https interface ge-0/0/0.0  # 특정 인터페이스만

# ─── 5. 관리 인터페이스 제한 ─────────────────────────────
set system management-instance

# 관리 접근 제한 방화벽 필터
set firewall family inet filter MGMT-FILTER term ALLOW-MGMT from source-address 10.10.1.0/24
set firewall family inet filter MGMT-FILTER term ALLOW-MGMT then accept
set firewall family inet filter MGMT-FILTER term DENY-ALL then reject

# ─── 6. 로깅 ──────────────────────────────────────────────
set system syslog host 10.0.0.200 any info
set system syslog host 10.0.0.200 interactive-commands any
set system syslog file messages any notice
set system syslog file interactive-commands interactive-commands any

# ─── 7. NTP 인증 ──────────────────────────────────────────
set system ntp authentication-key 1 type md5 value "NTPSecret!2024"
set system ntp server 10.0.0.50 key 1
set system ntp trusted-key 1
```

---

## 3. 네트워크 장비 자동화 감사

```python
#!/usr/bin/env python3
"""
Netmiko/Paramiko를 이용한 네트워크 장비 보안 감사 자동화.
pip install netmiko
참고: https://github.com/ktbyers/netmiko
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    print("pip install netmiko 필요")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class DeviceFinding:
    device: str
    check: str
    severity: str
    details: str
    remediation: str


def audit_cisco_ios(
    host: str,
    username: str,
    key_file: str,
    device_type: str = "cisco_ios",
) -> list[DeviceFinding]:
    """
    Cisco IOS 장비 보안 감사.
    SSH 키 기반 인증 사용.
    """
    findings: list[DeviceFinding] = []
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "use_keys": True,
        "key_file": key_file,
        "conn_timeout": 10,
    }

    try:
        with ConnectHandler(**device_params) as conn:
            log.info("연결 성공: %s", host)

            # show running-config 수집
            config = conn.send_command("show running-config")

            # ─── 텔넷 활성화 확인 ─────────────────────────
            for line in config.splitlines():
                if "transport input telnet" in line.lower():
                    findings.append(DeviceFinding(
                        device=host, check="텔넷 활성화",
                        severity="High",
                        details="VTY 라인에서 텔넷 허용됨",
                        remediation="transport input ssh 설정",
                    ))
                    break

            # ─── SNMP 기본 커뮤니티 확인 ──────────────────
            for community in ["public", "private"]:
                if f"snmp-server community {community}" in config.lower():
                    findings.append(DeviceFinding(
                        device=host, check=f"SNMP 기본 커뮤니티 '{community}'",
                        severity="Critical",
                        details=f"SNMP 기본 커뮤니티 문자열 사용 중",
                        remediation=f"no snmp-server community {community}",
                    ))

            # ─── CDP 활성화 확인 ───────────────────────────
            if "no cdp run" not in config and "cdp run" in config:
                findings.append(DeviceFinding(
                    device=host, check="CDP 전역 활성화",
                    severity="Medium",
                    details="Cisco Discovery Protocol이 전역 활성화됨",
                    remediation="no cdp run",
                ))

            # ─── enable password (약한) vs enable secret ──
            if "enable password" in config and "enable secret" not in config:
                findings.append(DeviceFinding(
                    device=host, check="약한 enable password 사용",
                    severity="High",
                    details="enable password (MD5 없음) 사용 중",
                    remediation="enable secret로 교체",
                ))

            # ─── HTTP 서버 확인 ────────────────────────────
            if "ip http server" in config and "no ip http server" not in config:
                findings.append(DeviceFinding(
                    device=host, check="HTTP 서버 활성화",
                    severity="High",
                    details="평문 HTTP 관리 인터페이스 활성화",
                    remediation="no ip http server",
                ))

            # ─── Exec Timeout 확인 ────────────────────────
            if "exec-timeout 0 0" in config:
                findings.append(DeviceFinding(
                    device=host, check="세션 타임아웃 없음",
                    severity="Medium",
                    details="exec-timeout 0 0 → 세션이 영구 지속",
                    remediation="exec-timeout 10 0 설정",
                ))

            log.info("감사 완료 %s: %d개 발견", host, len(findings))

    except NetmikoTimeoutException:
        log.error("연결 타임아웃: %s", host)
    except NetmikoAuthenticationException:
        log.error("인증 실패: %s", host)

    return findings


def batch_audit_devices(
    devices: list[dict[str, str]],
    key_file: str,
) -> dict[str, list[DeviceFinding]]:
    """여러 네트워크 장비 일괄 감사."""
    results: dict[str, list[DeviceFinding]] = {}
    for device in devices:
        host = device["host"]
        username = device.get("username", "admin")
        dtype = device.get("type", "cisco_ios")
        findings = audit_cisco_ios(host, username, key_file, dtype)
        results[host] = findings
    return results


def generate_audit_report(
    findings: dict[str, list[DeviceFinding]],
) -> str:
    """감사 결과 텍스트 보고서 생성."""
    lines = ["네트워크 장비 보안 감사 보고서", "=" * 50, ""]
    total = sum(len(v) for v in findings.values())
    lines.append(f"총 장비: {len(findings)}개 | 총 발견사항: {total}개\n")

    for host, device_findings in findings.items():
        lines.append(f"[ {host} ] — {len(device_findings)}개 발견사항")
        for f in sorted(device_findings, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.severity, 4)):
            lines.append(f"  [{f.severity}] {f.check}")
            lines.append(f"    조치: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="네트워크 장비 보안 감사")
    parser.add_argument("host", help="장비 IP 또는 호스트명")
    parser.add_argument("-u", "--user", default="admin", help="사용자명")
    parser.add_argument("-k", "--key", required=True, help="SSH 개인키 경로")
    parser.add_argument("--type", default="cisco_ios", help="장비 유형")
    args = parser.parse_args()

    findings = audit_cisco_ios(args.host, args.user, args.key, args.type)
    for f in findings:
        print(f"[{f.severity}] {f.check}: {f.details}")
    print(f"\n총 {len(findings)}개 발견사항")
```

---

## 4. 참고 자료

- **Cisco 보안 가이드**: https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- **CIS Cisco IOS 벤치마크**: https://www.cisecurity.org/benchmark/cisco
- **Netmiko 공식 문서**: https://github.com/ktbyers/netmiko

---

<a name="english"></a>

# Network Device Hardening — Cisco/Juniper Security Configs, Network Device Monitoring

## Overview

Routers, switches, and firewalls are high-value targets. Default credentials, telnet, and SNMP community strings are the most common vulnerabilities.

## Critical Hardening Steps

| Priority | Control | Cisco Command |
|----------|---------|--------------|
| Critical | Replace default SNMP | `no snmp-server community public` |
| Critical | Disable telnet | `transport input ssh` |
| High | Enable SSH v2 only | `ip ssh version 2` |
| High | Use enable secret | `enable secret 9 [hash]` |
| High | Disable CDP globally | `no cdp run` |
| High | Disable HTTP server | `no ip http server` |
| Medium | Set exec-timeout | `exec-timeout 10 0` |
| Medium | Enable AAA logging | `aaa accounting exec default` |

## Automated Audit

```bash
# Install dependencies
pip install netmiko

# Audit a single device
python3 device_audit.py 192.168.1.1 -u admin -k ~/.ssh/id_rsa --type cisco_ios

# Bulk audit from JSON inventory
python3 batch_audit.py --inventory devices.json -k ~/.ssh/id_rsa
```

## References

- Cisco security hardening: https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- CIS Cisco IOS Benchmark: https://www.cisecurity.org/benchmark/cisco
- Netmiko documentation: https://github.com/ktbyers/netmiko
