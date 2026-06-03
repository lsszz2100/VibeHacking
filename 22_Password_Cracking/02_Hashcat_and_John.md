> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 02 Hashcat and John the Ripper

## 0. 초보자를 위한 개념 이해

### Hashcat과 John the Ripper란?

Hashcat과 John the Ripper(이하 JtR)는 세계에서 가장 널리 사용되는 패스워드 크래킹 도구다. 해시값을 입력받아 다양한 방법으로 원래 비밀번호를 역추적한다. 보안 담당자는 이 도구로 자사 시스템에서 사용 중인 비밀번호의 강도를 테스트하고, 취약한 비밀번호를 사용하는 계정을 찾아낸다.

**왜 배우는가:**
```
크래킹 도구 활용 목적

[공격적 활용 — 모의침투]      [방어적 활용]
획득한 해시 덤프 크래킹  →   자사 해시 강도 감사
침투 테스트 중 자격증명  →   취약 비밀번호 계정 강제 변경
CTF 문제 풀이            →   비밀번호 정책 효과 검증

Hashcat vs JtR 선택 기준:
  Hashcat — GPU 사용, 빠름, 지원 해시 종류 많음
  JtR     — CPU/클라우드 환경, 자동 해시 탐지, 규칙 기능 강력
```

### 핵심 개념 정리

```
패스워드 크래킹 공격 방법 비교

방법              속도   성공률  메모리  특징
─────────────────────────────────────────────────
사전 공격         빠름   중간    낮음   wordlist 직접 대입
브루트포스        느림   높음    낮음   모든 조합 시도
마스크 공격       빠름   높음    낮음   패턴 지정 (예: ?l?l?d?d)
규칙 기반         빠름   높음    낮음   단어 변형 (p@ssw0rd 등)
레인보우 테이블   매우빠름 중간  매우높음 사전 계산 (솔트 있으면 무효)
```

### 필요한 도구 및 환경
- **hashcat**: `apt install hashcat` 또는 공식 사이트 다운로드
- **john**: `apt install john`
- **rockyou.txt**: 대표 워드리스트 (`/usr/share/wordlists/rockyou.txt`)
- **GPU**: hashcat 성능 극대화 (CPU로도 동작)

### 기초 실습 예제
```bash
# 1. 해시 파일 생성 (테스트용)
echo -n "password123" | md5sum | awk '{print $1}' > test.hash
cat test.hash  # 482c811da5d5b4bc6d497ffa98491e38

# 2. hashcat — 사전 공격 (모드 0, MD5)
hashcat -m 0 -a 0 test.hash /usr/share/wordlists/rockyou.txt
# -m 0 : MD5 해시 모드
# -a 0 : 사전 공격 모드

# 3. hashcat — 브루트포스 (4자리 숫자만)
hashcat -m 0 -a 3 test.hash "?d?d?d?d"
# ?d = 숫자(digit), ?l = 소문자, ?u = 대문자

# 4. John the Ripper — 자동 해시 감지 후 사전 공격
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
john --show test.hash  # 크래킹 결과 확인
```

---

## hashcat 공격 모드 전체

| 모드 번호 | 이름 | 설명 |
|---------|------|------|
| 0 | Straight (Dictionary) | 워드리스트 직접 대입 |
| 1 | Combination | 두 워드리스트 조합 |
| 3 | Brute-force / Mask | 마스크 패턴으로 전수조사 |
| 6 | Hybrid Wordlist + Mask | 단어 뒤에 마스크 붙임 |
| 7 | Hybrid Mask + Wordlist | 마스크 앞에 단어 붙임 |
| 9 | Association | 후보 리스트 연관 공격 |

hashcat의 전체 공격 모드를 설명합니다. 0(Straight), 1(Combination), 3(Brute-Force), 6/7(Hybrid), 9(Association) 등 각 모드의 특징과 사용법입니다.

```bash
# 공격 모드 지정 옵션
hashcat -a 0   # Straight
hashcat -a 1   # Combination
hashcat -a 3   # Brute-force/Mask
hashcat -a 6   # Hybrid WL+Mask
hashcat -a 7   # Hybrid Mask+WL
```

---

## 주요 해시 타입별 hashcat 모드 번호

| 해시 타입 | 모드 | 예시 해시 형태 |
|---------|------|-------------|
| MD5 | 0 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| MD4 | 900 | `8846f7eaee8fb117ad06bdd830b7586c` |
| SHA-1 | 100 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA-256 | 1400 | `5e884898da28...` |
| SHA-512 | 1700 | `b109f3bbbc24...` |
| SHA-512crypt ($6$) | 1800 | `$6$salt$hash` |
| MD5crypt ($1$) | 500 | `$1$salt$hash` |
| bcrypt ($2*$) | 3200 | `$2b$10$...` |
| NTLM | 1000 | `8846f7eaee8fb117ad06bdd830b7586c` |
| NetNTLMv1 | 5500 | `user::domain:challenge:hash` |
| NetNTLMv2 | 5600 | `user::domain:challenge:NTProofStr:blob` |
| WPA/WPA2 (hc22000) | 22000 | `.hc22000` 파일 |
| WPA/WPA2 (PMKID) | 22001 | PMKID 라인 |
| ZIP (PKZIP) | 17200 | 헤더 추출 |
| ZIP (WinZip AES) | 13600 | 헤더 추출 |
| PDF 1.1-1.3 | 10400 | 헤더 추출 |
| PDF 1.4-1.6 | 10500 | 헤더 추출 |
| SSH (RSA) | 22921 | id_rsa 추출 |
| KeePass 1.x | 13400 | DB 헤더 추출 |
| KeePass 2.x | 13400 | DB 헤더 추출 |
| MSSQL 2012+ | 1731 | `0x02...` |
| MySQL SHA1 | 300 | `*hash` |
| PostgreSQL MD5 | 11100 | `$postgres$user*salt*hash` |
| Django PBKDF2 | 10000 | `pbkdf2_sha256$...` |
| DPAPI masterkey | 15910 | 헤더 추출 |

---

## hashcat 기본 사용법

### 모드 0: 워드리스트 공격 (Straight)

hashcat 모드 0(직선 공격)으로 워드리스트를 이용한 사전 공격을 수행합니다. -a 0 옵션과 해시 파일, 워드리스트를 지정합니다.

```bash
# 기본 워드리스트 공격
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# 출력 파일 지정
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt

# 출력 형식: hash:plain 또는 plain만
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt --outfile-format=2

# 상태 주기적 출력 (초 단위)
hashcat -m 0 -a 0 hashes.txt rockyou.txt --status --status-timer=5

# 특정 해시만 크래킹 (이미 크래킹된 것 건너뜀)
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt --potfile-path=./my.pot
```

### 모드 1: 조합 공격 (Combination)


조합 공격(Combination)은 두 개의 워드리스트에서 단어를 조합합니다. 첫 번째 파일의 각 단어 뒤에 두 번째 파일의 모든 단어를 연결하여 후보를 생성하므로, 패스워드가 두 단어의 조합인 경우 효과적입니다.

```bash
# 두 워드리스트의 모든 조합
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt

# 예: "admin" + "123" → "admin123"
hashcat -m 0 -a 1 hash.txt names.txt suffixes.txt
```

### 모드 3: 마스크 공격 (Brute-force)


마스크 공격(-a 3)은 문자 집합과 길이를 지정하여 모든 가능한 조합을 시도합니다. `?u`(대문자), `?l`(소문자), `?d`(숫자), `?s`(특수문자) 마스크 문자로 패스워드 패턴을 표현합니다. 예: `?u?l?l?l?d?d?d` = 대문자+소문자3+숫자3.

```bash
# 마스크 문자셋
# ?l = 소문자 (a-z)
# ?u = 대문자 (A-Z)
# ?d = 숫자 (0-9)
# ?s = 특수문자 (!@#$ 등)
# ?a = ?l+?u+?d+?s 전체
# ?b = 0x00-0xFF

# 4자리 숫자 PIN
hashcat -m 0 -a 3 hash.txt ?d?d?d?d

# 8자 소문자+숫자
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?d?d

# 대문자 시작, 소문자, 숫자 2개, 특수문자 1개 (8자)
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d?s

# 커스텀 문자셋 정의
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1?1?1

# 여러 길이 시도 (--increment)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a --increment --increment-min=4

# 특정 커스텀 문자셋
hashcat -m 0 -a 3 hash.txt -1 'abcdefABCDEF0123456789!@#$' ?1?1?1?1?1?1?1?1
```

### 모드 6/7: 하이브리드 공격

```bash
# 모드 6: 단어 + 마스크 (단어 뒤에 붙임)
# "password" + "123" → "password123"
hashcat -m 0 -a 6 hash.txt rockyou.txt ?d?d?d?d

# "admin" + "!" → "admin!"
hashcat -m 0 -a 6 hash.txt wordlist.txt ?s

# 모드 7: 마스크 + 단어 (단어 앞에 붙임)
# "2024" + "password" → "2024password"
hashcat -m 0 -a 7 hash.txt ?d?d?d?d rockyou.txt

# "!@" + "Password" → "!@Password"
hashcat -m 0 -a 7 hash.txt ?s?s rockyou.txt
```

---

## 규칙(Rule) 기반 공격

```bash
# 내장 규칙 파일 목록
ls /usr/share/hashcat/rules/
# best64.rule  combinator.rule  d3ad0ne.rule  dive.rule
# generated.rule  hob064.rule  leetspeak.rule  oscommerce.rule
# rockyou-30000.rule  specific.rule  T0XlC.rule  toggles*.rule

# 규칙 적용 워드리스트 공격
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 여러 규칙 동시 적용
hashcat -m 0 -a 0 hash.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/toggles1.rule

# 유명 규칙 세트 OneRuleToRuleThemAll
wget https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule
hashcat -m 0 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

### 커스텀 규칙 작성

커스텀 규칙 파일을 작성합니다. 각 줄이 하나의 규칙이며 l(소문자), u(대문자), $1(숫자 추가), ^!(앞에 특수문자 추가) 등을 조합합니다.

```bash
# 규칙 파일 예시 (myrules.rule)
cat << 'EOF' > myrules.rule
# 그대로
:
# 전부 대문자
u
# 전부 소문자
l
# 첫 글자 대문자
c
# 끝에 숫자 추가
$1
$2
$3
$1$2$3
$2$0$2$4
# 앞에 숫자 추가
^1
^2
# 끝에 특수문자
$!
$@
$#
# 앞뒤에 추가
^!$1
# 역순
r
# 반복
d
# 숫자 변형 (leetspeak)
sa4
se3
si1
so0
# 조합
c$1$2$3
c$2$0$2$4
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r myrules.rule
```

### 규칙 생성 도구 PACK

```bash
# PACK — Password Analysis and Cracking Kit
git clone https://github.com/iphelix/pack /opt/pack

# 크래킹된 패스워드로부터 규칙 분석
python3 /opt/pack/statsgen.py cracked_passwords.txt -o analysis.txt

# 마스크 생성
python3 /opt/pack/maskgen.py analysis.txt --targettime 3600 -o masks.hcmask

# 규칙 생성
python3 /opt/pack/rulegen.py -w wordlist.txt cracked_passwords.txt -o rules.rule
```

---

## GPU 최적화 옵션

hashcat에서 사용 가능한 GPU 장치를 확인하고 최적화 옵션을 설정합니다. -O(최적화 커널), -w 3(공격성 설정)으로 크래킹 속도를 높입니다.

```bash
# 사용 가능한 OpenCL/CUDA 장치 확인
hashcat -I

# 특정 GPU 지정 (장치 ID 1)
hashcat -m 0 -a 0 hash.txt rockyou.txt -d 1

# 여러 GPU 사용
hashcat -m 0 -a 0 hash.txt rockyou.txt -d 1,2

# 워크로드 프로파일 (-w)
# 1: 저전력  2: 기본  3: 고성능  4: 나이트메어(온도 위험)
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 3

# 커널 루프 최적화
hashcat -m 0 -a 0 hash.txt rockyou.txt --kernel-accel=64 --kernel-loops=256

# 자동 최적화 (느린 알고리즘에서 속도↑)
hashcat -m 3200 -a 0 hash.txt rockyou.txt -O

# 온도 제한 설정 (°C)
hashcat -m 0 -a 0 hash.txt rockyou.txt --gpu-temp-abort=90

# 벤치마크
hashcat -b -m 0     # MD5 벤치마크
hashcat -b -m 1000  # NTLM 벤치마크
hashcat -b -m 3200  # bcrypt 벤치마크
hashcat -b          # 전체 벤치마크
```

---

## 세션 저장 및 복구

```bash
# 세션 이름 지정하여 시작
hashcat -m 0 -a 0 hash.txt rockyou.txt --session=mysession

# 세션 일시정지 (실행 중 'p' 키 또는 Ctrl+C)
# 자동으로 .restore 파일 생성

# 세션 복구
hashcat --restore --session=mysession

# 세션 파일 위치
ls ~/.hashcat/sessions/

# 포트파일 확인 (이미 크래킹된 해시)
cat ~/.hashcat/hashcat.potfile
hashcat -m 0 --show hashes.txt   # potfile 기반 결과 표시

# potfile 비활성화 (재크래킹 필요할 때)
hashcat -m 0 -a 0 hash.txt rockyou.txt --potfile-disable
```

---

## John the Ripper 사용법

### 기본 사용법

```bash
# 자동 해시 감지 + 크래킹
john hashes.txt

# 워드리스트 모드
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 포맷 명시
john --format=NT hashes.txt
john --format=sha512crypt hashes.txt
john --format=bcrypt hashes.txt

# 지원 포맷 목록
john --list=formats
john --list=formats | grep -i ntlm
john --list=formats | grep -i sha

# 이미 크래킹된 것 표시
john --show hashes.txt
john --show --format=NT hashes.txt

# 진행 상황 확인 (실행 중 'status' 입력 또는)
john --status
```

### John 설정 파일과 규칙

john.conf 설정 파일에서 규칙과 단어 목록을 관리합니다. 커스텀 크래킹 규칙을 추가하여 특정 패턴의 비밀번호 크래킹 성능을 향상시킵니다.

```bash
# 설정 파일 위치
/etc/john/john.conf          # 시스템 전체
~/.john/john.conf            # 사용자별

# 내장 규칙 사용
john --wordlist=rockyou.txt --rules hashes.txt
john --wordlist=rockyou.txt --rules=All hashes.txt
john --wordlist=rockyou.txt --rules=KoreLogic hashes.txt

# 규칙 목록 확인
john --list=rules

# 싱글 크래킹 모드 (사용자명 기반 변형)
john --single hashes.txt
john --single --format=NT hashes.txt

# 마스크 모드 (john의 --mask)
john --mask='?l?l?l?l?d?d?d?d' hashes.txt
john --mask='?u?l?l?l?l?d?d' --min-length=6 --max-length=8 hashes.txt
```

### john.conf 커스텀 규칙 작성

john.conf에 추가하는 커스텀 규칙 섹션입니다. Wordlist 섹션 아래에 변형 규칙을 정의하여 사전 공격의 변형 패턴을 확장합니다.

```ini
# john.conf 에 추가할 커스텀 규칙 섹션 예시
[List.Rules:CustomRules]
# 원본 그대로
:
# 첫 글자 대문자
c
# 전부 대문자
u
# 끝에 연도 추가
Az"2023"
Az"2024"
Az"2025"
# 앞에 추가
^z"!"
# leetspeak
s@4
s@3s$l$
# 숫자 추가
Az"1" Az"2" Az"123" Az"!"
# 역순 + 숫자
r Az"1"
# 첫글자 대문자 + 연도
c Az"2024"
c Az"2024!"
```

```bash
# 커스텀 규칙 적용
john --wordlist=rockyou.txt --rules=CustomRules hashes.txt
```

---

## 실전 크래킹 워크플로우

### NTLM 해시 크래킹

Windows SAM 데이터베이스에서 NTLM 해시를 추출하고 hashcat으로 크래킹합니다. Pass-the-Hash 공격에도 사용할 수 있습니다.

```bash
# 1. secretsdump로 NTLM 해시 덤프 (도메인 환경)
impacket-secretsdump -just-dc-ntlm domain/user:pass@dc-ip

# 또는 로컬 SAM 덤프
impacket-secretsdump -sam sam.bak -system system.bak LOCAL

# 2. 포맷 확인 (user:id:LM:NTLM:::)
# LM 파트는 aad3b435b51404eeaad3b435b51404ee (빈 LM)

# 3. NTLM 해시만 추출
cut -d: -f4 secretsdump_output.txt > ntlm_hashes.txt

# 4. hashcat으로 크래킹
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt -O
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule -O

# 5. 결과 확인
hashcat -m 1000 --show ntlm_hashes.txt
```

### WPA/WPA2 크래킹

```bash
# 1. 핸드셰이크 캡처 (hcxdumptool 또는 airodump-ng)
sudo hcxdumptool -i wlan0 -o capture.pcapng --enable-status=1

# 또는 airodump-ng
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0

# 2. hc22000 포맷으로 변환
hcxpcapngtool -o capture.hc22000 capture.pcapng

# 또는 cap2hccapx
cap2hccapx capture.cap capture.hccapx

# 3. PMKID 확인
cat capture.hc22000 | head -5

# 4. hashcat 크래킹
hashcat -m 22000 -a 0 capture.hc22000 /usr/share/wordlists/rockyou.txt

# 5. 마스크 공격 (8자리 숫자 라우터 기본 비번)
hashcat -m 22000 -a 3 capture.hc22000 ?d?d?d?d?d?d?d?d

# 6. 하이브리드
hashcat -m 22000 -a 6 capture.hc22000 rockyou.txt ?d?d?d?d
```

### ZIP 파일 크래킹

zip2john으로 암호화된 ZIP 파일의 해시를 추출하고 John으로 크래킹합니다. RAR, 7z, PDF 등 다양한 형식도 같은 방식으로 크래킹합니다.

```bash
# 1. 해시 추출
zip2john protected.zip > zip_hash.txt
cat zip_hash.txt

# 2. john으로 크래킹
john --wordlist=rockyou.txt zip_hash.txt

# 3. 결과 확인
john --show zip_hash.txt

# 4. hashcat으로 크래킹 (PKZIP)
# zip_hash.txt에서 해시 부분만 추출
grep -oP '\$pkzip2\$.*\$/pkzip2\$' zip_hash.txt > hash_only.txt
hashcat -m 17200 -a 0 hash_only.txt rockyou.txt

# WinZip AES 암호화
hashcat -m 13600 -a 0 hash_only.txt rockyou.txt
```

### PDF 파일 크래킹

pdf2john으로 암호화된 PDF의 해시를 추출합니다. 문서 암호화 버전에 따라 RC4(구버전)나 AES(신버전)로 보호됩니다.

```bash
# 1. 해시 추출
pdf2john.pl protected.pdf > pdf_hash.txt
# 또는
pdf2john protected.pdf > pdf_hash.txt

# 2. john으로 크래킹
john --wordlist=rockyou.txt pdf_hash.txt
john --show pdf_hash.txt

# 3. hashcat
# PDF 버전 확인 후 모드 선택
# 1.1-1.3 → 10400, 1.4-1.6 → 10500, 1.7 → 10600/10700
hashcat -m 10500 -a 0 pdf_hash_only.txt rockyou.txt
```

### SSH 개인키 크래킹

ssh2john으로 암호화된 SSH 개인키의 해시를 추출합니다. 개인키 파일을 탈취했을 때 암호 문구(passphrase)를 크래킹하여 사용합니다.

```bash
# 1. 해시 추출
ssh2john id_rsa > ssh_hash.txt
python3 /usr/share/john/ssh2john.py id_rsa > ssh_hash.txt

# 2. john으로 크래킹
john --wordlist=rockyou.txt ssh_hash.txt
john --show ssh_hash.txt

# 3. hashcat (OpenSSH 형식에 따라 모드 다름)
# RSA/DSA/EC → 22921
hashcat -m 22921 -a 0 ssh_hash.txt rockyou.txt

# 4. 크래킹 성공 후 사용
ssh -i id_rsa user@target  # passphrase 입력
```

---

## 실전 팁

hashcat 실전 성능 팁과 벤치마크 데이터입니다. GPU 모델별 WPA2 크래킹 속도를 참고하여 예상 크래킹 시간을 계산합니다.

```bash
# 크래킹 속도 비교 (GPU에 따라 다름, RTX 3090 기준 대략)
# MD5:    ~68 GH/s
# NTLM:   ~122 GH/s
# SHA-256: ~8 GH/s
# bcrypt:  ~10 KH/s
# WPA2:    ~300 KH/s

# 대용량 해시 파일 분할 처리
split -l 10000 big_hashes.txt chunk_
for f in chunk_*; do
  hashcat -m 1000 -a 0 "$f" rockyou.txt -o cracked_all.txt --outfile-format=2
done

# 크래킹된 해시 제외하고 남은 것만 추출
hashcat -m 1000 --left ntlm_hashes.txt > uncracked.txt

# 진행 상황 실시간 모니터링
watch -n 5 'hashcat -m 1000 --status --status-timer=1 2>/dev/null | tail -20'
```

---

<a name="english"></a>

# 02 Hashcat and John the Ripper

## All hashcat Attack Modes

| Mode Number | Name | Description |
|-------------|------|-------------|
| 0 | Straight (Dictionary) | Direct wordlist substitution |
| 1 | Combination | Combine two wordlists |
| 3 | Brute-force / Mask | Exhaustive search with mask pattern |
| 6 | Hybrid Wordlist + Mask | Append mask after word |
| 7 | Hybrid Mask + Wordlist | Prepend mask before word |
| 9 | Association | Associated candidate list attack |

This covers all hashcat attack modes: 0 (Straight), 1 (Combination), 3 (Brute-Force), 6/7 (Hybrid), 9 (Association) — their characteristics and usage.

```bash
# Attack mode selection options
hashcat -a 0   # Straight
hashcat -a 1   # Combination
hashcat -a 3   # Brute-force/Mask
hashcat -a 6   # Hybrid WL+Mask
hashcat -a 7   # Hybrid Mask+WL
```

---

## hashcat Mode Numbers by Hash Type

| Hash Type | Mode | Example Hash Format |
|-----------|------|---------------------|
| MD5 | 0 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| MD4 | 900 | `8846f7eaee8fb117ad06bdd830b7586c` |
| SHA-1 | 100 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA-256 | 1400 | `5e884898da28...` |
| SHA-512 | 1700 | `b109f3bbbc24...` |
| SHA-512crypt ($6$) | 1800 | `$6$salt$hash` |
| MD5crypt ($1$) | 500 | `$1$salt$hash` |
| bcrypt ($2*$) | 3200 | `$2b$10$...` |
| NTLM | 1000 | `8846f7eaee8fb117ad06bdd830b7586c` |
| NetNTLMv1 | 5500 | `user::domain:challenge:hash` |
| NetNTLMv2 | 5600 | `user::domain:challenge:NTProofStr:blob` |
| WPA/WPA2 (hc22000) | 22000 | `.hc22000` file |
| WPA/WPA2 (PMKID) | 22001 | PMKID line |
| ZIP (PKZIP) | 17200 | Header extraction |
| ZIP (WinZip AES) | 13600 | Header extraction |
| PDF 1.1-1.3 | 10400 | Header extraction |
| PDF 1.4-1.6 | 10500 | Header extraction |
| SSH (RSA) | 22921 | id_rsa extraction |
| KeePass 1.x | 13400 | DB header extraction |
| KeePass 2.x | 13400 | DB header extraction |
| MSSQL 2012+ | 1731 | `0x02...` |
| MySQL SHA1 | 300 | `*hash` |
| PostgreSQL MD5 | 11100 | `$postgres$user*salt*hash` |
| Django PBKDF2 | 10000 | `pbkdf2_sha256$...` |
| DPAPI masterkey | 15910 | Header extraction |

---

## hashcat Basic Usage

### Mode 0: Wordlist Attack (Straight)

Performs a dictionary attack using a wordlist with hashcat mode 0 (straight attack). Specify the -a 0 option along with the hash file and wordlist.

```bash
# Basic wordlist attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Specify output file
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt

# Output format: hash:plain or plain only
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt --outfile-format=2

# Periodic status output (in seconds)
hashcat -m 0 -a 0 hashes.txt rockyou.txt --status --status-timer=5

# Crack specific hashes (skip already cracked)
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt --potfile-path=./my.pot
```

### Mode 1: Combination Attack

The Combination attack combines words from two wordlists. It appends every word from the second file to each word in the first file to generate candidates — effective when the password is a combination of two words.

```bash
# All combinations of two wordlists
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt

# Example: "admin" + "123" → "admin123"
hashcat -m 0 -a 1 hash.txt names.txt suffixes.txt
```

### Mode 3: Mask Attack (Brute-force)

The mask attack (-a 3) tries all possible combinations by specifying a character set and length. Password patterns are expressed using mask characters: `?u` (uppercase), `?l` (lowercase), `?d` (digit), `?s` (special character). Example: `?u?l?l?l?d?d?d` = uppercase + 3 lowercase + 3 digits.

```bash
# Mask character sets
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digit (0-9)
# ?s = special characters (!@#$ etc.)
# ?a = all of ?l+?u+?d+?s
# ?b = 0x00-0xFF

# 4-digit numeric PIN
hashcat -m 0 -a 3 hash.txt ?d?d?d?d

# 8-character lowercase + digits
hashcat -m 0 -a 3 hash.txt ?l?l?l?l?l?l?d?d

# Uppercase start, lowercase, 2 digits, 1 special (8 chars)
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d?s

# Define custom character set
hashcat -m 0 -a 3 hash.txt -1 ?l?d ?1?1?1?1?1?1?1?1

# Try multiple lengths (--increment)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a --increment --increment-min=4

# Specific custom character set
hashcat -m 0 -a 3 hash.txt -1 'abcdefABCDEF0123456789!@#$' ?1?1?1?1?1?1?1?1
```

### Mode 6/7: Hybrid Attack

```bash
# Mode 6: Word + Mask (append mask after word)
# "password" + "123" → "password123"
hashcat -m 0 -a 6 hash.txt rockyou.txt ?d?d?d?d

# "admin" + "!" → "admin!"
hashcat -m 0 -a 6 hash.txt wordlist.txt ?s

# Mode 7: Mask + Word (prepend mask before word)
# "2024" + "password" → "2024password"
hashcat -m 0 -a 7 hash.txt ?d?d?d?d rockyou.txt

# "!@" + "Password" → "!@Password"
hashcat -m 0 -a 7 hash.txt ?s?s rockyou.txt
```

---

## Rule-Based Attack

```bash
# List built-in rule files
ls /usr/share/hashcat/rules/
# best64.rule  combinator.rule  d3ad0ne.rule  dive.rule
# generated.rule  hob064.rule  leetspeak.rule  oscommerce.rule
# rockyou-30000.rule  specific.rule  T0XlC.rule  toggles*.rule

# Apply rules to wordlist attack
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Apply multiple rules simultaneously
hashcat -m 0 -a 0 hash.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/toggles1.rule

# Popular rule set: OneRuleToRuleThemAll
wget https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule
hashcat -m 0 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

### Writing Custom Rules

Write a custom rule file. Each line is one rule — combine l (lowercase), u (uppercase), $1 (append digit), ^! (prepend special character), etc.

```bash
# Rule file example (myrules.rule)
cat << 'EOF' > myrules.rule
# As-is
:
# All uppercase
u
# All lowercase
l
# Capitalize first letter
c
# Append digits
$1
$2
$3
$1$2$3
$2$0$2$4
# Prepend digits
^1
^2
# Append special characters
$!
$@
$#
# Prepend and append
^!$1
# Reverse
r
# Duplicate
d
# Digit substitution (leetspeak)
sa4
se3
si1
so0
# Combined
c$1$2$3
c$2$0$2$4
EOF

hashcat -m 0 -a 0 hash.txt wordlist.txt -r myrules.rule
```

### Rule Generation Tool PACK

```bash
# PACK — Password Analysis and Cracking Kit
git clone https://github.com/iphelix/pack /opt/pack

# Analyze rules from cracked passwords
python3 /opt/pack/statsgen.py cracked_passwords.txt -o analysis.txt

# Generate masks
python3 /opt/pack/maskgen.py analysis.txt --targettime 3600 -o masks.hcmask

# Generate rules
python3 /opt/pack/rulegen.py -w wordlist.txt cracked_passwords.txt -o rules.rule
```

---

## GPU Optimization Options

Check available GPU devices in hashcat and configure optimization options. Use -O (optimized kernel) and -w 3 (aggressiveness setting) to increase cracking speed.

```bash
# Check available OpenCL/CUDA devices
hashcat -I

# Specify a particular GPU (device ID 1)
hashcat -m 0 -a 0 hash.txt rockyou.txt -d 1

# Use multiple GPUs
hashcat -m 0 -a 0 hash.txt rockyou.txt -d 1,2

# Workload profile (-w)
# 1: Low power  2: Default  3: High performance  4: Nightmare (temperature risk)
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 3

# Kernel loop optimization
hashcat -m 0 -a 0 hash.txt rockyou.txt --kernel-accel=64 --kernel-loops=256

# Auto-optimization (speed boost for slow algorithms)
hashcat -m 3200 -a 0 hash.txt rockyou.txt -O

# Set temperature limit (°C)
hashcat -m 0 -a 0 hash.txt rockyou.txt --gpu-temp-abort=90

# Benchmarks
hashcat -b -m 0     # MD5 benchmark
hashcat -b -m 1000  # NTLM benchmark
hashcat -b -m 3200  # bcrypt benchmark
hashcat -b          # Full benchmark
```

---

## Session Save and Recovery

```bash
# Start with a named session
hashcat -m 0 -a 0 hash.txt rockyou.txt --session=mysession

# Pause session (press 'p' during run or Ctrl+C)
# Automatically creates a .restore file

# Restore session
hashcat --restore --session=mysession

# Session file location
ls ~/.hashcat/sessions/

# Check potfile (already cracked hashes)
cat ~/.hashcat/hashcat.potfile
hashcat -m 0 --show hashes.txt   # Show results based on potfile

# Disable potfile (when re-cracking is needed)
hashcat -m 0 -a 0 hash.txt rockyou.txt --potfile-disable
```

---

## John the Ripper Usage

### Basic Usage

```bash
# Auto hash detection + cracking
john hashes.txt

# Wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify format
john --format=NT hashes.txt
john --format=sha512crypt hashes.txt
john --format=bcrypt hashes.txt

# List supported formats
john --list=formats
john --list=formats | grep -i ntlm
john --list=formats | grep -i sha

# Show already cracked entries
john --show hashes.txt
john --show --format=NT hashes.txt

# Check progress (type 'status' during run or)
john --status
```

### John Configuration File and Rules

Manage rules and word lists in the john.conf configuration file. Add custom cracking rules to improve performance for specific password patterns.

```bash
# Configuration file locations
/etc/john/john.conf          # System-wide
~/.john/john.conf            # Per-user

# Use built-in rules
john --wordlist=rockyou.txt --rules hashes.txt
john --wordlist=rockyou.txt --rules=All hashes.txt
john --wordlist=rockyou.txt --rules=KoreLogic hashes.txt

# List available rules
john --list=rules

# Single cracking mode (username-based variations)
john --single hashes.txt
john --single --format=NT hashes.txt

# Mask mode (john's --mask)
john --mask='?l?l?l?l?d?d?d?d' hashes.txt
john --mask='?u?l?l?l?l?d?d' --min-length=6 --max-length=8 hashes.txt
```

### Writing Custom Rules in john.conf

This is a custom rules section added to john.conf. Define transformation rules under the Wordlist section to expand variation patterns for dictionary attacks.

```ini
# Example custom rules section to add to john.conf
[List.Rules:CustomRules]
# Original as-is
:
# Capitalize first letter
c
# All uppercase
u
# Append year
Az"2023"
Az"2024"
Az"2025"
# Prepend
^z"!"
# Leetspeak
s@4
s@3s$l$
# Add numbers
Az"1" Az"2" Az"123" Az"!"
# Reverse + digit
r Az"1"
# Capitalize + year
c Az"2024"
c Az"2024!"
```

```bash
# Apply custom rules
john --wordlist=rockyou.txt --rules=CustomRules hashes.txt
```

---

## Real-World Cracking Workflows

### NTLM Hash Cracking

Extract NTLM hashes from the Windows SAM database and crack them with hashcat. Can also be used for Pass-the-Hash attacks.

```bash
# 1. Dump NTLM hashes with secretsdump (domain environment)
impacket-secretsdump -just-dc-ntlm domain/user:pass@dc-ip

# Or local SAM dump
impacket-secretsdump -sam sam.bak -system system.bak LOCAL

# 2. Check format (user:id:LM:NTLM:::)
# LM part is aad3b435b51404eeaad3b435b51404ee (empty LM)

# 3. Extract NTLM hashes only
cut -d: -f4 secretsdump_output.txt > ntlm_hashes.txt

# 4. Crack with hashcat
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt -O
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule -O

# 5. Show results
hashcat -m 1000 --show ntlm_hashes.txt
```

### WPA/WPA2 Cracking

```bash
# 1. Capture handshake (hcxdumptool or airodump-ng)
sudo hcxdumptool -i wlan0 -o capture.pcapng --enable-status=1

# Or airodump-ng
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0

# 2. Convert to hc22000 format
hcxpcapngtool -o capture.hc22000 capture.pcapng

# Or cap2hccapx
cap2hccapx capture.cap capture.hccapx

# 3. Check PMKID
cat capture.hc22000 | head -5

# 4. Crack with hashcat
hashcat -m 22000 -a 0 capture.hc22000 /usr/share/wordlists/rockyou.txt

# 5. Mask attack (8-digit number — common router default password)
hashcat -m 22000 -a 3 capture.hc22000 ?d?d?d?d?d?d?d?d

# 6. Hybrid
hashcat -m 22000 -a 6 capture.hc22000 rockyou.txt ?d?d?d?d
```

### ZIP File Cracking

Extract the hash from an encrypted ZIP file using zip2john, then crack it with John. The same approach works for RAR, 7z, PDF, and other formats.

```bash
# 1. Extract hash
zip2john protected.zip > zip_hash.txt
cat zip_hash.txt

# 2. Crack with john
john --wordlist=rockyou.txt zip_hash.txt

# 3. Show results
john --show zip_hash.txt

# 4. Crack with hashcat (PKZIP)
# Extract only the hash portion from zip_hash.txt
grep -oP '\$pkzip2\$.*\$/pkzip2\$' zip_hash.txt > hash_only.txt
hashcat -m 17200 -a 0 hash_only.txt rockyou.txt

# WinZip AES encryption
hashcat -m 13600 -a 0 hash_only.txt rockyou.txt
```

### PDF File Cracking

Extract the hash from an encrypted PDF using pdf2john. Depending on the document encryption version, it may be protected with RC4 (old) or AES (new).

```bash
# 1. Extract hash
pdf2john.pl protected.pdf > pdf_hash.txt
# Or
pdf2john protected.pdf > pdf_hash.txt

# 2. Crack with john
john --wordlist=rockyou.txt pdf_hash.txt
john --show pdf_hash.txt

# 3. hashcat
# Check PDF version and select mode
# 1.1-1.3 → 10400, 1.4-1.6 → 10500, 1.7 → 10600/10700
hashcat -m 10500 -a 0 pdf_hash_only.txt rockyou.txt
```

### SSH Private Key Cracking

Extract the hash from an encrypted SSH private key using ssh2john. After obtaining a private key file, crack the passphrase to use it.

```bash
# 1. Extract hash
ssh2john id_rsa > ssh_hash.txt
python3 /usr/share/john/ssh2john.py id_rsa > ssh_hash.txt

# 2. Crack with john
john --wordlist=rockyou.txt ssh_hash.txt
john --show ssh_hash.txt

# 3. hashcat (mode varies by OpenSSH format)
# RSA/DSA/EC → 22921
hashcat -m 22921 -a 0 ssh_hash.txt rockyou.txt

# 4. Use after successful crack
ssh -i id_rsa user@target  # enter passphrase
```

---

## Practical Tips

Real-world hashcat performance tips and benchmark data. Refer to WPA2 cracking speeds by GPU model to estimate expected cracking time.

```bash
# Speed comparison (varies by GPU, approximate for RTX 3090)
# MD5:    ~68 GH/s
# NTLM:   ~122 GH/s
# SHA-256: ~8 GH/s
# bcrypt:  ~10 KH/s
# WPA2:    ~300 KH/s

# Process large hash files in chunks
split -l 10000 big_hashes.txt chunk_
for f in chunk_*; do
  hashcat -m 1000 -a 0 "$f" rockyou.txt -o cracked_all.txt --outfile-format=2
done

# Extract only uncracked hashes (exclude cracked ones)
hashcat -m 1000 --left ntlm_hashes.txt > uncracked.txt

# Real-time progress monitoring
watch -n 5 'hashcat -m 1000 --status --status-timer=1 2>/dev/null | tail -20'
```
