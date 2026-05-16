# 01. 게임 메모리 조작 (Game Memory Manipulation)

게임 해킹의 가장 기본적인 기법은 프로세스 메모리를 직접 읽고 쓰는 것이다. 이 문서는 Windows 환경에서 게임 메모리 구조를 이해하고 조작하는 방법을 다룬다. 모든 내용은 CTF, 보안 연구, 취약점 분석 목적으로 작성되었다.

---

## 1. 게임 메모리 구조 이해

### 1.1 메모리 영역 분류

게임 프로세스의 메모리는 크게 4가지 영역으로 나뉜다.

```
가상 주소 공간 (32비트: 4GB, 64비트: 128TB)
┌─────────────────────────────────┐
│  텍스트 세그먼트 (코드)           │  .text — 실행 가능한 명령어
├─────────────────────────────────┤
│  데이터 세그먼트 (초기화된 전역)   │  .data — 전역/정적 변수
├─────────────────────────────────┤
│  BSS 세그먼트 (미초기화 전역)     │  .bss — 0으로 초기화됨
├─────────────────────────────────┤
│  힙 (Heap)                      │  동적 할당 (malloc/new)
│  ↓ 증가 방향                    │
├─────────────────────────────────┤
│  (빈 공간)                      │
├─────────────────────────────────┤
│  ↑ 증가 방향                    │
│  스택 (Stack)                   │  지역 변수, 함수 호출 프레임
└─────────────────────────────────┘
```

**정적 메모리 (Static Memory)**
- `.data` / `.bss` 세그먼트에 위치
- 프로그램 실행 시 주소 고정 (ASLR 미적용 시)
- 전역 변수, 정적 변수 저장
- Cheat Engine에서 `모듈명+오프셋` 형태로 접근

**힙 메모리 (Heap Memory)**
- `malloc`, `new` 등으로 동적 할당
- 매 실행마다 주소 변경
- 게임 오브젝트(플레이어, 아이템 등)가 여기에 위치
- 포인터 체인으로 추적 필요

**스택 메모리 (Stack Memory)**
- 함수 실행 중에만 유효
- 지역 변수, 매개변수 저장
- 함수 종료 시 소멸되므로 해킹 대상으로 부적합

### 1.2 포인터 체인 (Pointer Chain)

힙에 할당된 게임 오브젝트는 직접 참조가 불가능하므로 포인터 체인으로 추적한다.

```
정적 주소 (베이스 포인터)
    │  [게임.exe + 0x00A1B2C3]
    ▼
힙 주소 A (플레이어 매니저)
    │  + 0x10 오프셋
    ▼
힙 주소 B (로컬 플레이어)
    │  + 0x5C 오프셋
    ▼
힙 주소 C (체력 구조체)
    │  + 0x08 오프셋
    ▼
체력 값 (float/int)
```

표기법: `[[[게임.exe + 0xA1B2C3] + 0x10] + 0x5C] + 0x08`

---

## 2. Cheat Engine 기초 사용법

### 2.1 값 검색 (Value Scan)

```
1. 대상 프로세스 선택 (Process List에서 게임 선택)
2. Value Type 설정 (4 Bytes / Float / Double 등)
3. 초기 검색 (First Scan) — 현재 체력이 100이면 100 입력
4. 게임 내에서 값 변화 (체력 감소 후)
5. 재검색 (Next Scan) — "Decreased Value" 또는 현재 값 입력
6. 반복하여 후보 주소 좁히기
7. 주소를 하단 목록에 추가 → 값 수정
```

### 2.2 포인터 스캔 (Pointer Scan)

```
1. 목표 값의 주소를 이미 찾은 상태에서 시작
2. 주소 우클릭 → "Pointer scan for this address"
3. 스캔 옵션:
   - Max level: 5~7 (포인터 체인 깊이)
   - Max offset: 0x1000 (각 레벨 최대 오프셋)
4. 스캔 후 결과 저장 (.PTR 파일)
5. 게임 재시작 후 필터링:
   - "Rescan memory" → 동일 주소를 가리키는 포인터만 남김
6. [게임.exe + 오프셋] 형태의 정적 포인터 선택
```

### 2.3 AOB 스캔 (Array of Bytes Scan)

코드 패턴을 바이트 배열로 검색한다.

```
1. Cheat Engine → "Memory View" → Ctrl+B (Byte Array Scan)
2. 검색할 바이트 패턴 입력:
   - 예: 89 45 F8 8B 4D F8 — 특정 명령어 시퀀스
   - 와일드카드: ?? 사용 (예: 89 45 ?? 8B 4D ??)
3. 결과 주소로 이동하여 코드 컨텍스트 확인
4. 디스어셈블리 창에서 구조 파악
```

---

## 3. Windows 메모리 API

### 3.1 핵심 API 함수

```c
// 프로세스 핸들 획득
HANDLE OpenProcess(
    DWORD dwDesiredAccess,   // PROCESS_ALL_ACCESS 또는 세분화된 권한
    BOOL  bInheritHandle,    // 핸들 상속 여부
    DWORD dwProcessId        // 대상 PID
);

// 메모리 읽기
BOOL ReadProcessMemory(
    HANDLE  hProcess,            // 프로세스 핸들
    LPCVOID lpBaseAddress,       // 읽을 주소
    LPVOID  lpBuffer,            // 결과를 저장할 버퍼
    SIZE_T  nSize,               // 읽을 바이트 수
    SIZE_T  *lpNumberOfBytesRead // 실제 읽힌 바이트 수
);

// 메모리 쓰기
BOOL WriteProcessMemory(
    HANDLE  hProcess,               // 프로세스 핸들
    LPVOID  lpBaseAddress,          // 쓸 주소
    LPCVOID lpBuffer,               // 쓸 데이터
    SIZE_T  nSize,                  // 쓸 바이트 수
    SIZE_T  *lpNumberOfBytesWritten // 실제 쓰인 바이트 수
);

// 모듈 베이스 주소 획득
HMODULE GetModuleHandle(LPCWSTR lpModuleName);

// 가상 메모리 보호 속성 변경
BOOL VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,   // PAGE_EXECUTE_READWRITE 등
    PDWORD lpflOldProtect  // 이전 보호 속성 저장
);
```

### 3.2 C 예제 — 기본 메모리 읽기/쓰기

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

// 프로세스 이름으로 PID 획득
DWORD get_pid_by_name(const char* proc_name) {
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, proc_name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// 모듈 베이스 주소 획득
uintptr_t get_module_base(DWORD pid, const char* module_name) {
    MODULEENTRY32 entry = { sizeof(MODULEENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Module32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szModule, module_name) == 0) {
                CloseHandle(snapshot);
                return (uintptr_t)entry.modBaseAddr;
            }
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// 포인터 체인 역참조
uintptr_t resolve_pointer_chain(HANDLE hProc, uintptr_t base, 
                                 int* offsets, int offset_count) {
    uintptr_t addr = base;

    for (int i = 0; i < offset_count - 1; i++) {
        uintptr_t ptr = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(addr + offsets[i]), 
                               &ptr, sizeof(ptr), NULL)) {
            return 0;
        }
        addr = ptr;
        if (addr == 0) return 0;
    }

    return addr + offsets[offset_count - 1];
}

int main(void) {
    const char* game_name = "game.exe";
    DWORD pid = get_pid_by_name(game_name);

    if (pid == 0) {
        fprintf(stderr, "프로세스를 찾을 수 없음: %s\n", game_name);
        return 1;
    }
    printf("[*] PID: %lu\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "프로세스 열기 실패 (관리자 권한 필요)\n");
        return 1;
    }

    uintptr_t base = get_module_base(pid, game_name);
    printf("[*] 베이스 주소: 0x%llX\n", (unsigned long long)base);

    // 포인터 체인: [base + 0xA1B2C3] + 0x10 + 0x5C + 0x08
    int offsets[] = { 0xA1B2C3, 0x10, 0x5C, 0x08 };
    int offset_count = sizeof(offsets) / sizeof(offsets[0]);

    uintptr_t hp_addr = resolve_pointer_chain(hProc, base, offsets, offset_count);
    if (hp_addr == 0) {
        fprintf(stderr, "포인터 체인 해결 실패\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[*] 체력 주소: 0x%llX\n", (unsigned long long)hp_addr);

    // 현재 체력 읽기
    float hp = 0.0f;
    ReadProcessMemory(hProc, (LPCVOID)hp_addr, &hp, sizeof(hp), NULL);
    printf("[*] 현재 체력: %.1f\n", hp);

    // 체력을 9999로 패치
    float new_hp = 9999.0f;
    DWORD old_protect = 0;
    VirtualProtectEx(hProc, (LPVOID)hp_addr, sizeof(new_hp), PAGE_EXECUTE_READWRITE, &old_protect);
    WriteProcessMemory(hProc, (LPVOID)hp_addr, &new_hp, sizeof(new_hp), NULL);
    VirtualProtectEx(hProc, (LPVOID)hp_addr, sizeof(new_hp), old_protect, &old_protect);
    printf("[+] 체력 패치 완료: %.1f\n", new_hp);

    CloseHandle(hProc);
    return 0;
}
```

---

## 4. Python ctypes를 이용한 메모리 조작

### 4.1 완성형 메모리 읽기/쓰기 스크립트

```python
#!/usr/bin/env python3
"""
게임 메모리 조작 도구 (CTF/보안 연구 목적)
Windows ReadProcessMemory/WriteProcessMemory API를 ctypes로 래핑
"""

import ctypes
import ctypes.wintypes as wt
import argparse
import struct
import sys
from typing import Optional
from enum import IntFlag


# Windows API 상수
PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PAGE_EXECUTE_READWRITE = 0x40


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wt.DWORD),
        ("cntUsage",            wt.DWORD),
        ("th32ProcessID",       wt.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wt.DWORD),
        ("cntThreads",          wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wt.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wt.DWORD),
        ("th32ModuleID",  wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage",  wt.DWORD),
        ("ProccntUsage",  wt.DWORD),
        ("modBaseAddr",   ctypes.POINTER(wt.BYTE)),
        ("modBaseSize",   wt.DWORD),
        ("hModule",       wt.HMODULE),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


class GameMemory:
    """게임 프로세스 메모리 읽기/쓰기 클래스"""

    def __init__(self, process_name: str) -> None:
        self.process_name = process_name
        self.pid: int = 0
        self.handle: Optional[wt.HANDLE] = None
        self.base_address: int = 0

        self._kernel32 = ctypes.windll.kernel32  # type: ignore
        self._setup_api()

    def _setup_api(self) -> None:
        """ctypes API 시그니처 설정"""
        k32 = self._kernel32

        k32.OpenProcess.restype = wt.HANDLE
        k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

        k32.ReadProcessMemory.restype = wt.BOOL
        k32.ReadProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]

        k32.WriteProcessMemory.restype = wt.BOOL
        k32.WriteProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]

        k32.VirtualProtectEx.restype = wt.BOOL
        k32.VirtualProtectEx.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
            wt.DWORD, ctypes.POINTER(wt.DWORD)
        ]

        k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]

        k32.Process32First.restype = wt.BOOL
        k32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

        k32.Process32Next.restype = wt.BOOL
        k32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

        k32.Module32First.restype = wt.BOOL
        k32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]

        k32.Module32Next.restype = wt.BOOL
        k32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]

    def find_pid(self) -> int:
        """프로세스 이름으로 PID 탐색"""
        snapshot = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise RuntimeError("스냅샷 생성 실패")

        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if self._kernel32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.szExeFile.decode("utf-8", errors="ignore").lower() == \
                       self.process_name.lower():
                        self.pid = entry.th32ProcessID
                        return self.pid
                    if not self._kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        raise RuntimeError(f"프로세스 미발견: {self.process_name}")

    def open(self) -> None:
        """프로세스 핸들 획득"""
        if self.pid == 0:
            self.find_pid()

        self.handle = self._kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.handle:
            raise PermissionError(f"프로세스 열기 실패 (관리자 권한 필요), PID={self.pid}")

        self.base_address = self._get_module_base(self.process_name)
        print(f"[*] PID: {self.pid} | 베이스: 0x{self.base_address:016X}")

    def _get_module_base(self, module_name: str) -> int:
        """모듈 베이스 주소 탐색"""
        flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        snapshot = self._kernel32.CreateToolhelp32Snapshot(flags, self.pid)
        if snapshot == ctypes.c_void_p(-1).value:
            raise RuntimeError("모듈 스냅샷 생성 실패")

        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        try:
            if self._kernel32.Module32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szModule.decode("utf-8", errors="ignore").lower()
                    if name == module_name.lower():
                        return ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                    if not self._kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        raise RuntimeError(f"모듈 미발견: {module_name}")

    def read_bytes(self, address: int, size: int) -> bytes:
        """지정 주소에서 바이트 읽기"""
        if not self.handle:
            raise RuntimeError("프로세스가 열려있지 않음")

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        result = self._kernel32.ReadProcessMemory(
            self.handle, address, buffer, size, ctypes.byref(bytes_read)
        )
        if not result:
            raise OSError(f"메모리 읽기 실패: 주소 0x{address:X}")

        return bytes(buffer.raw[:bytes_read.value])

    def write_bytes(self, address: int, data: bytes) -> None:
        """지정 주소에 바이트 쓰기"""
        if not self.handle:
            raise RuntimeError("프로세스가 열려있지 않음")

        old_protect = wt.DWORD(0)
        self._kernel32.VirtualProtectEx(
            self.handle, address, len(data),
            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
        )

        buffer = ctypes.create_string_buffer(data)
        bytes_written = ctypes.c_size_t(0)
        result = self._kernel32.WriteProcessMemory(
            self.handle, address, buffer, len(data), ctypes.byref(bytes_written)
        )

        # 보호 속성 복원
        self._kernel32.VirtualProtectEx(
            self.handle, address, len(data),
            old_protect.value, ctypes.byref(old_protect)
        )

        if not result:
            raise OSError(f"메모리 쓰기 실패: 주소 0x{address:X}")

    def read_int32(self, address: int) -> int:
        return struct.unpack("<i", self.read_bytes(address, 4))[0]

    def read_uint32(self, address: int) -> int:
        return struct.unpack("<I", self.read_bytes(address, 4))[0]

    def read_int64(self, address: int) -> int:
        return struct.unpack("<q", self.read_bytes(address, 8))[0]

    def read_float(self, address: int) -> float:
        return struct.unpack("<f", self.read_bytes(address, 4))[0]

    def read_double(self, address: int) -> float:
        return struct.unpack("<d", self.read_bytes(address, 8))[0]

    def read_pointer(self, address: int) -> int:
        """64비트 포인터 읽기"""
        return struct.unpack("<Q", self.read_bytes(address, 8))[0]

    def write_float(self, address: int, value: float) -> None:
        self.write_bytes(address, struct.pack("<f", value))

    def write_int32(self, address: int, value: int) -> None:
        self.write_bytes(address, struct.pack("<i", value))

    def resolve_pointer_chain(self, base_offset: int, offsets: list[int]) -> int:
        """포인터 체인 자동 해결"""
        addr = self.base_address + base_offset
        for i, offset in enumerate(offsets[:-1]):
            ptr = self.read_pointer(addr + offset)
            if ptr == 0:
                raise ValueError(f"레벨 {i} 에서 NULL 포인터: 0x{addr + offset:X}")
            addr = ptr
        return addr + offsets[-1]

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


# ─── AOB 스캐너 ──────────────────────────────────────────────────────────────

class AOBScanner:
    """Array of Bytes 패턴 스캐너"""

    def __init__(self, mem: GameMemory) -> None:
        self.mem = mem

    def scan(self, pattern: str, start: int = 0, size: int = 0x7FFFFFFF) -> list[int]:
        """
        패턴 문자열로 AOB 스캔
        pattern 예시: "89 45 ?? 8B 4D ?? 83 C1 01"
        """
        pat_bytes = []
        mask = []
        for token in pattern.strip().split():
            if token == "??":
                pat_bytes.append(0x00)
                mask.append(False)
            else:
                pat_bytes.append(int(token, 16))
                mask.append(True)

        results: list[int] = []
        chunk_size = 0x10000  # 64KB씩 청크 읽기
        addr = start

        while addr < start + size:
            try:
                chunk = self.mem.read_bytes(addr, min(chunk_size, start + size - addr))
            except OSError:
                addr += chunk_size
                continue

            for i in range(len(chunk) - len(pat_bytes) + 1):
                match = all(
                    not mask[j] or chunk[i + j] == pat_bytes[j]
                    for j in range(len(pat_bytes))
                )
                if match:
                    results.append(addr + i)

            addr += chunk_size

        return results


# ─── 메인 CLI ────────────────────────────────────────────────────────────────

def cmd_read(args: argparse.Namespace, mem: GameMemory) -> None:
    """메모리 읽기 커맨드"""
    if args.chain:
        offsets = [int(x, 16) for x in args.chain.split(",")]
        addr = mem.resolve_pointer_chain(offsets[0], offsets[1:])
        print(f"[*] 해결된 주소: 0x{addr:016X}")
    else:
        addr = int(args.address, 16)

    raw = mem.read_bytes(addr, args.size)
    print(f"[*] 0x{addr:016X}: {raw.hex(' ')}")

    if args.type == "float":
        print(f"    float  = {struct.unpack('<f', raw[:4])[0]}")
    elif args.type == "int32":
        print(f"    int32  = {struct.unpack('<i', raw[:4])[0]}")
    elif args.type == "int64":
        print(f"    int64  = {struct.unpack('<q', raw[:8])[0]}")


def cmd_write(args: argparse.Namespace, mem: GameMemory) -> None:
    """메모리 쓰기 커맨드"""
    addr = int(args.address, 16)

    if args.type == "float":
        data = struct.pack("<f", float(args.value))
    elif args.type == "int32":
        data = struct.pack("<i", int(args.value))
    elif args.type == "bytes":
        data = bytes.fromhex(args.value.replace(" ", ""))
    else:
        raise ValueError(f"알 수 없는 타입: {args.type}")

    mem.write_bytes(addr, data)
    print(f"[+] 0x{addr:016X} 에 {data.hex(' ')} 쓰기 완료")


def cmd_aob(args: argparse.Namespace, mem: GameMemory) -> None:
    """AOB 스캔 커맨드"""
    scanner = AOBScanner(mem)
    print(f"[*] 패턴 스캔 중: {args.pattern}")
    results = scanner.scan(args.pattern)
    print(f"[*] 발견된 주소 수: {len(results)}")
    for addr in results:
        print(f"    0x{addr:016X}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="게임 메모리 조작 도구 (CTF/보안 연구 목적)"
    )
    parser.add_argument("process", help="대상 프로세스 이름 (예: game.exe)")

    sub = parser.add_subparsers(dest="command", required=True)

    # read 서브커맨드
    p_read = sub.add_parser("read", help="메모리 읽기")
    p_read.add_argument("--address", "-a", help="16진수 주소 (예: 0x1A2B3C)")
    p_read.add_argument("--chain", "-c", help="포인터 체인 (예: A1B2C3,10,5C,08)")
    p_read.add_argument("--size", "-s", type=int, default=16, help="읽을 바이트 수")
    p_read.add_argument("--type", "-t", choices=["float", "int32", "int64", "raw"],
                        default="raw", help="해석 타입")

    # write 서브커맨드
    p_write = sub.add_parser("write", help="메모리 쓰기")
    p_write.add_argument("address", help="16진수 주소")
    p_write.add_argument("value", help="쓸 값")
    p_write.add_argument("--type", "-t", choices=["float", "int32", "bytes"],
                         default="float", help="값 타입")

    # aob 서브커맨드
    p_aob = sub.add_parser("aob", help="바이트 패턴 스캔")
    p_aob.add_argument("pattern", help="AOB 패턴 (예: '89 45 ?? 8B 4D ??')")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    mem = GameMemory(args.process)
    try:
        mem.open()
    except (RuntimeError, PermissionError) as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == "read":
            cmd_read(args, mem)
        elif args.command == "write":
            cmd_write(args, mem)
        elif args.command == "aob":
            cmd_aob(args, mem)
    except Exception as e:
        print(f"[!] 실행 오류: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        mem.close()


if __name__ == "__main__":
    main()
```

### 4.2 포인터 체인 자동 해결 스크립트

```python
#!/usr/bin/env python3
"""
포인터 체인 자동 탐색기
여러 포인터 체인 후보를 로드하고 유효한 것을 필터링한다.
"""

import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class PointerPath:
    base_offset: int
    offsets: list[int]
    description: str = ""
    last_resolved: int = 0
    valid: bool = False


def load_pointer_paths(filepath: str) -> list[PointerPath]:
    """JSON 파일에서 포인터 경로 목록 로드

    JSON 형식:
    [
      {"base_offset": "0xA1B2C3", "offsets": ["0x10", "0x5C", "0x08"], "description": "체력"},
      ...
    ]
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"파일 미발견: {filepath}")

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    results = []
    for item in data:
        base = int(item["base_offset"], 16)
        offsets = [int(o, 16) for o in item["offsets"]]
        desc = item.get("description", "")
        results.append(PointerPath(base_offset=base, offsets=offsets, description=desc))

    return results


def validate_and_resolve(mem: "GameMemory", paths: list[PointerPath]) -> list[PointerPath]:
    """포인터 경로 목록 검증 및 주소 해결"""
    valid_paths = []

    for path in paths:
        try:
            resolved = mem.resolve_pointer_chain(path.base_offset, path.offsets)
            # 해결된 주소가 유효한 범위인지 확인
            test_read = mem.read_bytes(resolved, 4)
            path.last_resolved = resolved
            path.valid = True
            valid_paths.append(path)
            chain_str = f"0x{path.base_offset:X} -> " + " -> ".join(f"0x{o:X}" for o in path.offsets)
            print(f"[+] 유효: {path.description} | {chain_str} => 0x{resolved:X}")
        except (ValueError, OSError):
            path.valid = False
            print(f"[-] 무효: {path.description}")

    return valid_paths


def save_results(paths: list[PointerPath], output: str) -> None:
    """결과를 JSON으로 저장"""
    data = [
        {
            "base_offset": hex(p.base_offset),
            "offsets": [hex(o) for o in p.offsets],
            "description": p.description,
            "resolved_address": hex(p.last_resolved),
            "valid": p.valid,
        }
        for p in paths
    ]

    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[*] 결과 저장: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="포인터 체인 자동 검증기")
    parser.add_argument("process", help="대상 프로세스 이름")
    parser.add_argument("input", help="포인터 경로 JSON 파일")
    parser.add_argument("--output", "-o", default="resolved.json", help="결과 저장 경로")
    args = parser.parse_args()

    # GameMemory 클래스는 01_memory_manipulation.md 의 구현체 사용
    try:
        from game_memory import GameMemory  # type: ignore
    except ImportError:
        print("[!] game_memory 모듈 필요. 위 스크립트를 game_memory.py로 저장하세요.")
        sys.exit(1)

    paths = load_pointer_paths(args.input)
    print(f"[*] 포인터 경로 {len(paths)}개 로드됨")

    mem = GameMemory(args.process)
    mem.open()

    try:
        valid = validate_and_resolve(mem, paths)
        print(f"\n[*] 유효한 경로: {len(valid)}/{len(paths)}")
        save_results(paths, args.output)
    finally:
        mem.close()


if __name__ == "__main__":
    main()
```

---

## 5. 메모리 패치 자동화

### 5.1 NOP 패치 (코드 비활성화)

특정 코드 블록을 NOP(0x90)으로 채워 실행되지 않도록 한다.

```python
#!/usr/bin/env python3
"""메모리 NOP 패처 — 특정 코드 블록을 NOP으로 대체"""

import argparse
import sys
import struct
from pathlib import Path


def nop_patch(mem: "GameMemory", address: int, size: int) -> bytes:
    """지정 주소를 NOP으로 패치, 원본 바이트 반환"""
    original = mem.read_bytes(address, size)
    mem.write_bytes(address, b"\x90" * size)
    print(f"[+] NOP 패치: 0x{address:X} ({size}바이트)")
    print(f"    원본: {original.hex(' ')}")
    print(f"    패치: {b'90' * size}")
    return original


def restore_patch(mem: "GameMemory", address: int, original: bytes) -> None:
    """NOP 패치 복원"""
    mem.write_bytes(address, original)
    print(f"[+] 복원 완료: 0x{address:X}")


def load_patch_script(filepath: str) -> list[dict]:
    """패치 스크립트 로드 (JSON)

    형식:
    [
      {"address": "0x1A2B3C", "patch": "90 90 90 90 90", "description": "무적 NOP"},
      {"address": "0x1A2B40", "patch": "B8 FF FF FF 7F", "description": "데미지 무력화"}
    ]
    """
    import json
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def apply_patch_script(mem: "GameMemory", patches: list[dict]) -> dict[str, bytes]:
    """패치 스크립트 일괄 적용, 원본 저장"""
    originals: dict[str, bytes] = {}

    for patch in patches:
        addr = int(patch["address"], 16)
        data = bytes.fromhex(patch["patch"].replace(" ", ""))
        desc = patch.get("description", "")

        original = mem.read_bytes(addr, len(data))
        originals[patch["address"]] = original
        mem.write_bytes(addr, data)
        print(f"[+] 패치 적용: {desc} @ 0x{addr:X}")

    return originals


def main() -> None:
    parser = argparse.ArgumentParser(description="메모리 패치 자동화 도구")
    parser.add_argument("process", help="대상 프로세스")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_nop = sub.add_parser("nop", help="NOP 패치")
    p_nop.add_argument("address", help="패치 주소 (16진수)")
    p_nop.add_argument("size", type=int, help="NOP 바이트 수")

    p_script = sub.add_parser("script", help="패치 스크립트 실행")
    p_script.add_argument("file", help="패치 JSON 파일")

    args = parser.parse_args()

    try:
        from game_memory import GameMemory  # type: ignore
    except ImportError:
        print("[!] game_memory 모듈 필요")
        sys.exit(1)

    mem = GameMemory(args.process)
    mem.open()

    try:
        if args.cmd == "nop":
            nop_patch(mem, int(args.address, 16), args.size)
        elif args.cmd == "script":
            patches = load_patch_script(args.file)
            apply_patch_script(mem, patches)
    finally:
        mem.close()


if __name__ == "__main__":
    main()
```

---

## 6. 실전 팁

### 6.1 ASLR 우회

현대 게임은 ASLR(Address Space Layout Randomization)이 적용되어 있으므로 정적 주소 대신 `모듈베이스 + 오프셋` 방식을 사용해야 한다.

```
실제 체력 주소 = GetModuleBase("game.exe") + 0xA1B2C3 + 포인터 역참조...
```

### 6.2 값 타입 식별

| 값 종류     | 타입      | 크기  | Cheat Engine 설정 |
|------------|-----------|-------|-------------------|
| 체력/마나    | float     | 4바이트 | Float            |
| 골드/경험치  | int32/int64 | 4/8바이트 | 4 Bytes / 8 Bytes |
| 좌표         | double    | 8바이트 | Double           |
| 레벨         | byte/short | 1/2바이트 | Byte / 2 Bytes  |

### 6.3 멀티레벨 포인터 스캔 팁

```
1. 값 주소 발견 후 포인터 스캔 실행
2. 게임 재시작 → 같은 값 주소 재탐색
3. "Rescan saved pointers" → 이전 스캔 결과에서 현재 주소를 가리키는 포인터만 남김
4. 2~3회 반복으로 신뢰도 높은 포인터 체인 확보
5. [게임.exe + 오프셋] 형태만 선택 (정적 포인터)
```

### 6.4 주요 사용 시나리오 (CTF)

```
# 1. 스캔 후 포인터 체인 해결
python mem_tool.py game.exe read --chain A1B2C3,10,5C,08 --type float

# 2. 체력 무한 패치
python mem_tool.py game.exe write 0x1A2B3C 9999.0 --type float

# 3. 특정 코드 NOP 처리
python mem_tool.py game.exe nop 0x1A2B40 5

# 4. AOB 패턴 스캔
python mem_tool.py game.exe aob "89 45 ?? 8B 4D ??"
```
