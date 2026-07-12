> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 04. 안티치트 분석 (Anti-Cheat Analysis)

## 0. 초보자를 위한 개념 이해

### 안티치트란?

**안티치트(Anti-Cheat)**는 게임에서 부정 행위(치트)를 탐지·차단하는 보안 시스템입니다. 보안 연구자는 이 시스템의 동작 원리를 이해하고 취약점을 찾아 개발사에 보고합니다.

**왜 배우는가:**
```
보안 연구 가치:
  안티치트 = 보안 소프트웨어
  → 커널 드라이버, 프로세스 보호, 메모리 무결성 검사
  → 이 기술들이 EDR/AV에도 동일하게 적용됨

게임 보안 직업:
  대형 게임사의 안티치트 팀 (Riot, Blizzard, EA)
  → 치트 탐지 엔지니어, 역공학 전문가
```

### 핵심 안티치트 기법

```
주요 안티치트 시스템:
  BattlEye    → PUBG, Fortnite 등 (커널 드라이버)
  EAC (Easy Anti-Cheat) → Apex, Fortnite
  Vanguard    → Valorant (부팅 시부터 실행)
  VAC         → Valve 게임 (행동 기반 탐지)

탐지 방법:
  1. 메모리 스캔
     알려진 치트 패턴 → 게임 프로세스 메모리 검사
  2. API 훅 탐지
     CreateRemoteThread, WriteProcessMemory 모니터링
  3. 커널 레벨 모니터링
     드라이버로 OS 레벨 접근 → 치트 도구 탐지
  4. 행동 분석
     에임 조정 속도, 패턴 → 에임봇 탐지
```

### 필요한 도구
- **x64dbg + ScyllaHide**: 안티디버깅 우회
- **Cheat Engine + 드라이버 모드**: 커널 레벨 메모리 접근
- **Procmon / Sysmon**: 프로세스 행동 모니터링

### 기초 실습 예제
```python
# 안티치트 탐지 기법 분류
anti_cheat_methods = [
    ("메모리 스캔", "알려진 패턴 해시 비교", "패턴 변경으로 우회 가능"),
    ("API 후킹 탐지", "SSDT/IAT 훅 탐지", "커널 레벨 훅은 탐지 어려움"),
    ("타임스탬프", "게임플레이 타이밍 이상 감지", "정교한 우회 가능"),
    ("원격 분석", "서버 사이드 행동 AI 분석", "우회 매우 어려움"),
    ("하이퍼바이저", "VM 내 실행 탐지", "특정 치트 방어에 효과적"),
]

print("안티치트 탐지 기법 분석\n")
for method, how, bypass in anti_cheat_methods:
    print(f"기법: {method}")
    print(f"  원리: {how}")
    print(f"  한계: {bypass}\n")
```

---

## 1. 안티치트 시스템 종류

### 1.1 주요 안티치트 비교

| 안티치트  | 게임 예시            | 방식                 | 커널 드라이버 | 클라우드 연동 |
|---------|---------------------|---------------------|-------------|------------|
| VAC     | CS2, Dota2          | 서버사이드, 후처리   | 없음         | 있음        |
| EAC     | Fortnite, Apex      | 클라이언트, 실시간   | 있음 (선택)  | 있음        |
| BattlEye| PUBG, DayZ          | 클라이언트, 실시간   | 있음         | 있음        |
| FACEIT  | CS2 (3rd party)     | 커널 + 클라우드      | 있음         | 있음        |
| Vanguard| Valorant            | 커널 Ring-0, 부팅 시 | 있음 (필수)  | 있음        |
| nProtect| 한국 MMORPG         | 커널, 로컬           | 있음         | 부분        |
| XIGNCODE| 아시아 MMORPG       | 커널, 로컬           | 있음         | 부분        |

### 1.2 동작 레이어 분류

```
Ring 3 (사용자 모드)
  ├── 메모리 스캐너 — 알려진 치트 시그니처 검색
  ├── 프로세스 모니터 — 의심 프로세스 목록 확인
  ├── 파일 스캐너 — 게임 파일 무결성 검증
  └── 타이밍 체크 — 비정상적인 프레임 속도 감지

Ring 0 (커널 모드)
  ├── DKOM 탐지 — 숨겨진 프로세스/드라이버 탐지
  ├── 콜백 등록 — PsSetCreateProcessNotifyRoutine
  ├── SSDT 훅 탐지 — 시스템 콜 테이블 변조 감지
  └── 페이지 테이블 스캔 — 메모리 위장 탐지
```

---

## 2. 커널 레벨 안티치트 동작 원리

### 2.1 Windows 커널 드라이버 메커니즘

```c
// 안티치트 드라이버가 사용하는 주요 API (개념 설명용)

// 1. 프로세스 생성 콜백 등록
PsSetCreateProcessNotifyRoutineEx(MyProcessCreateCallback, FALSE);

// 2. 이미지(DLL/EXE) 로드 콜백
PsSetLoadImageNotifyRoutine(MyImageLoadCallback);

// 3. 스레드 생성 콜백
PsSetCreateThreadNotifyRoutine(MyThreadCreateCallback);

// 4. 오브젝트 핸들 콜백 (OpenProcess 가로채기)
ObRegisterCallbacks(&registration, &handle);

// 5. EPROCESS 구조체 직접 접근으로 프로세스 정보 수집
PEPROCESS target = PsGetCurrentProcess();
```

### 2.2 탐지 기법 분류

**시그니처 탐지 (Signature Detection)**
```
알려진 치트 도구의 바이트 패턴을 메모리/파일에서 검색
- 장점: 빠르고 정확
- 단점: 패턴 변경으로 우회 가능 (패커, 폴리모픽)
```

**행위 탐지 (Behavioral Detection)**
```
의심스러운 API 호출 패턴 모니터링
- ReadProcessMemory 호출 빈도
- VirtualAllocEx 후 WriteProcessMemory + CreateRemoteThread
- 게임 내 비정상 정확도 (에임봇 탐지)
```

**무결성 검사 (Integrity Check)**
```
게임 파일 및 메모리의 체크섬 지속 검증
- 실행 파일 해시 비교
- 인메모리 코드 섹션 검증 (IAT 후킹, 인라인 후킹 탐지)
```

**타이밍 체크 (Timing Check)**
```
비정상적인 반응 속도 감지
- 인간이 불가능한 수준의 조준 속도
- 일정한 반응 시간 패턴 (매크로 탐지)
```

---

## 3. Python 게임 프로세스 분석 도구

### 3.1 완성형 프로세스 분석기

```python
#!/usr/bin/env python3
"""
게임 프로세스 분석 도구 (CTF/보안 연구 목적)
모듈 목록, 핸들, 훅, 인젝션된 DLL 탐지
"""

import ctypes
import ctypes.wintypes as wt
import argparse
import sys
import struct
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Windows API 상수
TH32CS_SNAPALL       = 0x0000001F
TH32CS_SNAPPROCESS   = 0x00000002
TH32CS_SNAPMODULE    = 0x00000008
TH32CS_SNAPMODULE32  = 0x00000010
TH32CS_SNAPTHREAD    = 0x00000004
PROCESS_ALL_ACCESS   = 0x1F0FFF
PAGE_EXECUTE         = 0x10
PAGE_EXECUTE_READ    = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT           = 0x1000
MEM_IMAGE            = 0x1000000
MEM_MAPPED           = 0x40000
MEM_PRIVATE          = 0x20000


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


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",             wt.DWORD),
        ("cntUsage",           wt.DWORD),
        ("th32ThreadID",       wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri",          ctypes.c_long),
        ("tpDeltaPri",         ctypes.c_long),
        ("dwFlags",            wt.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId",       wt.WORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
    ]


@dataclass
class ModuleInfo:
    name: str
    path: str
    base_address: int
    size: int
    is_suspicious: bool = False
    reason: str = ""


@dataclass
class MemoryRegion:
    base: int
    size: int
    protect: int
    state: int
    mem_type: int
    is_executable: bool = False
    is_private_exec: bool = False


@dataclass
class ProcessAnalysis:
    pid: int
    name: str
    modules: list[ModuleInfo] = field(default_factory=list)
    threads: list[dict] = field(default_factory=list)
    memory_regions: list[MemoryRegion] = field(default_factory=list)
    suspicious_modules: list[ModuleInfo] = field(default_factory=list)
    private_exec_regions: list[MemoryRegion] = field(default_factory=list)


class GameProcessAnalyzer:
    """게임 프로세스 분석기"""

    # 알려진 치트 도구 DLL 시그니처 (일부)
    SUSPICIOUS_MODULES: set[str] = {
        "speedhack.dll",
        "cheatengine",
        "injector",
        "trainer",
        "hack",
        "aimbot",
        "esp",
        "wallhack",
        "triggerbot",
        "bhop",
    }

    # 정상 시스템 DLL 화이트리스트 (일부)
    KNOWN_SYSTEM_DLLS: set[str] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll",
        "user32.dll", "gdi32.dll", "advapi32.dll",
        "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll",
        "d3d11.dll", "d3d12.dll", "dxgi.dll",
        "opengl32.dll", "vulkan-1.dll",
        "ws2_32.dll", "wininet.dll",
    }

    def __init__(self, process_name_or_pid: str) -> None:
        self._target = process_name_or_pid
        self._k32 = ctypes.windll.kernel32  # type: ignore
        self._pid: int = 0
        self._handle: Optional[wt.HANDLE] = None
        self._setup_api()

    def _setup_api(self) -> None:
        k32 = self._k32
        k32.OpenProcess.restype = wt.HANDLE
        k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k32.ReadProcessMemory.restype = wt.BOOL
        k32.ReadProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        k32.VirtualQueryEx.argtypes = [
            wt.HANDLE, ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t
        ]

    def _find_pid(self) -> int:
        """프로세스 이름 또는 PID 문자열로 PID 반환"""
        try:
            return int(self._target)
        except ValueError:
            pass

        snapshot = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if self._k32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
                    if name == self._target.lower():
                        return entry.th32ProcessID
                    if not self._k32.Process32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        raise RuntimeError(f"프로세스 미발견: {self._target}")

    def open(self) -> None:
        self._pid = self._find_pid()
        self._handle = self._k32.OpenProcess(PROCESS_ALL_ACCESS, False, self._pid)
        if not self._handle:
            raise PermissionError(f"프로세스 열기 실패 (관리자 권한 필요), PID={self._pid}")
        print(f"[*] 프로세스 열기 성공: PID={self._pid}")

    def get_modules(self) -> list[ModuleInfo]:
        """로드된 모듈 목록 수집"""
        modules: list[ModuleInfo] = []
        flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        snapshot = self._k32.CreateToolhelp32Snapshot(flags, self._pid)
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        try:
            if self._k32.Module32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szModule.decode("utf-8", errors="ignore")
                    path = entry.szExePath.decode("utf-8", errors="ignore")
                    base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0

                    mod = ModuleInfo(
                        name=name,
                        path=path,
                        base_address=base,
                        size=entry.modBaseSize,
                    )

                    # 의심 모듈 판단
                    name_lower = name.lower()
                    if any(keyword in name_lower for keyword in self.SUSPICIOUS_MODULES):
                        mod.is_suspicious = True
                        mod.reason = "알려진 치트 도구 키워드 포함"
                    elif name_lower not in self.KNOWN_SYSTEM_DLLS:
                        path_lower = path.lower()
                        if "system32" not in path_lower and "syswow64" not in path_lower:
                            mod.is_suspicious = True
                            mod.reason = "비시스템 경로의 미확인 DLL"

                    modules.append(mod)
                    if not self._k32.Module32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        return modules

    def get_threads(self) -> list[dict]:
        """프로세스 스레드 목록"""
        threads: list[dict] = []
        snapshot = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        try:
            if self._k32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == self._pid:
                        threads.append({
                            "tid": entry.th32ThreadID,
                            "base_priority": entry.tpBasePri,
                        })
                    if not self._k32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        return threads

    def scan_memory_regions(self) -> list[MemoryRegion]:
        """메모리 영역 스캔 — 실행 가능한 비공개 영역 탐지"""
        if not self._handle:
            raise RuntimeError("프로세스 열려있지 않음")

        regions: list[MemoryRegion] = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0

        exec_flags = (
            PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )

        while True:
            result = self._k32.VirtualQueryEx(
                self._handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if result == 0:
                break

            if mbi.State == MEM_COMMIT:
                is_exec = bool(mbi.Protect & exec_flags)
                is_private = mbi.Type == MEM_PRIVATE

                region = MemoryRegion(
                    base=mbi.BaseAddress or 0,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    state=mbi.State,
                    mem_type=mbi.Type,
                    is_executable=is_exec,
                    is_private_exec=is_exec and is_private,
                )
                regions.append(region)

            next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_addr <= addr:
                break
            addr = next_addr

        return regions

    def check_iat_hooks(self, module_base: int, module_size: int) -> list[dict]:
        """IAT(Import Address Table) 후킹 탐지"""
        if not self._handle:
            return []

        hooks: list[dict] = []

        try:
            # PE 헤더 읽기
            buf_size = min(module_size, 0x1000)
            buffer = ctypes.create_string_buffer(buf_size)
            bytes_read = ctypes.c_size_t(0)
            self._k32.ReadProcessMemory(
                self._handle, module_base, buffer, buf_size, ctypes.byref(bytes_read)
            )
            data = bytes(buffer.raw)

            # DOS 헤더 → PE 헤더
            if data[:2] != b"MZ":
                return []

            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return []

            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []

            # 머신 타입 확인 (x64: 0x8664, x86: 0x014C)
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            is_64bit = machine == 0x8664

            optional_offset = pe_offset + 24
            if is_64bit:
                # 64비트: import directory RVA는 Optional Header +104
                import_dir_rva = struct.unpack_from("<I", data, optional_offset + 104)[0]
            else:
                # 32비트: import directory RVA는 Optional Header +80
                import_dir_rva = struct.unpack_from("<I", data, optional_offset + 80)[0]

            # 간단한 후킹 탐지: IAT 엔트리가 알려진 시스템 모듈 범위를 벗어나는지 확인
            # (실제 구현은 훨씬 복잡하므로 여기서는 개념 시연)
            if import_dir_rva > 0:
                hooks.append({
                    "type": "IAT_CHECK",
                    "module_base": hex(module_base),
                    "import_dir_rva": hex(import_dir_rva),
                    "status": "IAT 구조 발견 (상세 분석 필요)",
                })

        except Exception as e:
            hooks.append({"error": str(e)})

        return hooks

    def analyze(self) -> ProcessAnalysis:
        """전체 분석 실행"""
        analysis = ProcessAnalysis(pid=self._pid, name=self._target)

        print("[*] 모듈 목록 수집 중...")
        analysis.modules = self.get_modules()
        analysis.suspicious_modules = [m for m in analysis.modules if m.is_suspicious]

        print("[*] 스레드 목록 수집 중...")
        analysis.threads = self.get_threads()

        print("[*] 메모리 영역 스캔 중...")
        try:
            analysis.memory_regions = self.scan_memory_regions()
            analysis.private_exec_regions = [
                r for r in analysis.memory_regions if r.is_private_exec
            ]
        except Exception as e:
            print(f"[!] 메모리 스캔 오류: {e}")

        return analysis

    def close(self) -> None:
        if self._handle:
            self._k32.CloseHandle(self._handle)
            self._handle = None


def print_analysis_report(analysis: ProcessAnalysis) -> None:
    """분석 결과 출력"""
    print(f"\n{'='*60}")
    print(f"  프로세스 분석 보고서")
    print(f"  PID: {analysis.pid}  이름: {analysis.name}")
    print(f"{'='*60}")

    print(f"\n[모듈 목록] 총 {len(analysis.modules)}개")
    for mod in analysis.modules:
        flag = " [!]" if mod.is_suspicious else ""
        print(f"  0x{mod.base_address:016X}  {mod.size:>10,} bytes  "
              f"{mod.name:<40}{flag}")
        if mod.is_suspicious:
            print(f"      └ 이유: {mod.reason}")

    if analysis.suspicious_modules:
        print(f"\n[의심 모듈] {len(analysis.suspicious_modules)}개 탐지")
        for mod in analysis.suspicious_modules:
            print(f"  [!] {mod.name}")
            print(f"      경로: {mod.path}")
            print(f"      이유: {mod.reason}")
    else:
        print("\n[의심 모듈] 없음")

    print(f"\n[스레드] 총 {len(analysis.threads)}개")
    for t in analysis.threads[:10]:
        print(f"  TID={t['tid']}  우선순위={t['base_priority']}")
    if len(analysis.threads) > 10:
        print(f"  ... (+{len(analysis.threads) - 10}개)")

    if analysis.private_exec_regions:
        print(f"\n[실행 가능 비공개 메모리 영역] {len(analysis.private_exec_regions)}개 탐지")
        print("  (DLL 인젝션 또는 셸코드 주입 의심)")
        for r in analysis.private_exec_regions[:10]:
            print(f"  0x{r.base:016X}  크기={r.size:>10,} bytes  "
                  f"보호={r.protect:#010x}")
    else:
        print("\n[실행 가능 비공개 메모리] 없음")

    print(f"\n[메모리 영역] 총 {len(analysis.memory_regions)}개 커밋됨")
    exec_count = sum(1 for r in analysis.memory_regions if r.is_executable)
    print(f"  실행 가능 영역: {exec_count}개")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="게임 프로세스 분석 도구 (CTF/보안 연구)")
    parser.add_argument("target", help="프로세스 이름 또는 PID")
    parser.add_argument("--output", "-o", help="JSON 결과 저장 경로")
    parser.add_argument("--modules-only", action="store_true", help="모듈 목록만 출력")
    args = parser.parse_args()

    analyzer = GameProcessAnalyzer(args.target)
    try:
        analyzer.open()
    except (RuntimeError, PermissionError) as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        analysis = analyzer.analyze()
        print_analysis_report(analysis)

        if args.output:
            data = {
                "pid": analysis.pid,
                "name": analysis.name,
                "modules": [asdict(m) for m in analysis.modules],
                "suspicious_modules": [asdict(m) for m in analysis.suspicious_modules],
                "threads": analysis.threads,
                "private_exec_regions": [asdict(r) for r in analysis.private_exec_regions],
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n[*] 결과 저장: {args.output}")
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
```

---

## 4. DLL 인젝션 탐지 개념

### 4.1 DLL 인젝션 방법론 (탐지 관점)

```
방법 1: CreateRemoteThread + LoadLibrary
  탐지: CreateRemoteThread API 모니터링
        원격 메모리에 DLL 경로 문자열 존재 여부

방법 2: SetWindowsHookEx
  탐지: 등록된 훅 목록에서 알려진 게임 프로세스로의 훅 확인
        EnumWindows + GetWindowThreadProcessId 조합

방법 3: 프로세스 홀로잉 (Process Hollowing)
  탐지: 실제 파일과 메모리 내 이미지 해시 불일치
        PE 헤더 내 원본 경로와 실제 로드 경로 불일치

방법 4: 매뉴얼 매핑 (Manual Map)
  탐지: 파일에 없는 실행 가능 메모리 영역 (private exec)
        PEB LDR에 미등록된 모듈
```

### 4.2 PEB에서 모듈 목록 읽기 (직접 접근)

```c
// NtQueryInformationProcess로 PEB 접근 (탐지 우회 감지용)
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

void enumerate_peb_modules(HANDLE hProc) {
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret_len = 0;
    NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);

    // PEB 읽기
    PEB peb = {0};
    ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);

    // LDR 데이터 읽기
    PEB_LDR_DATA ldr_data = {0};
    ReadProcessMemory(hProc, peb.Ldr, &ldr_data, sizeof(ldr_data), NULL);

    // 모듈 목록 순회 (InMemoryOrderModuleList)
    LIST_ENTRY* head = &ldr_data.InMemoryOrderModuleList;
    LIST_ENTRY entry = {0};
    ReadProcessMemory(hProc, head->Flink, &entry, sizeof(entry), NULL);

    while (entry.Flink != head->Flink) {
        LDR_DATA_TABLE_ENTRY mod_entry = {0};
        ReadProcessMemory(
            hProc,
            CONTAINING_RECORD(entry.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &mod_entry, sizeof(mod_entry), NULL
        );
        // mod_entry.BaseDllName, mod_entry.DllBase 출력 가능
        // ... 
        ReadProcessMemory(hProc, entry.Flink, &entry, sizeof(entry), NULL);
    }
}
```

---

## 5. 안티치트 우회 연구 방법론 (CTF/보안 연구 관점)

### 5.1 연구 환경 구성

```
1. 격리된 VM 환경 (Hyper-V, VMware) 사용 필수
   - 스냅샷 기능으로 안전한 실험 환경 구성
   - 네트워크 격리로 실제 게임 서버 영향 차단

2. 분석 도구 설치
   - WinDbg + Symbol Server 설정
   - x64dbg / OllyDbg
   - Process Hacker / Process Monitor
   - Wireshark / Fiddler

3. 커널 디버깅 환경
   - 테스트 서명 모드 활성화
   - KDNET 설정 (원격 커널 디버깅)
```

### 5.2 CTF 게임 해킹 챌린지 유형별 접근법

**유형 1: 메모리 값 변조**
```
목표: 특정 값을 변경하여 플래그 획득
접근:
  1. Cheat Engine 으로 값 스캔
  2. 포인터 체인 추적
  3. 값 수정 후 게임 이벤트 트리거
  4. 또는 Python ctypes 스크립트로 자동화

예시 CTF 문제:
  - 게임 내 체력 1000 달성 → 플래그 출력
  - 골드를 특정 값으로 설정 → 특수 아이템 구매 가능 → 플래그
```

**유형 2: 패킷 조작**
```
목표: 네트워크 패킷을 수정하여 서버사이드 이벤트 트리거
접근:
  1. Wireshark로 트래픽 캡처
  2. 프로토콜 구조 분석 (헤더 + 페이로드)
  3. mitmproxy로 실시간 수정
  4. 또는 커스텀 패킷 직접 전송

예시 CTF 문제:
  - 퀘스트 완료 패킷에 보상값 조작 → 과다 보상 → 플래그
  - 로그인 응답 패킷에서 권한 레벨 변조 → 관리자 메뉴 → 플래그
```

**유형 3: 리버싱 + 코드 패치**
```
목표: 게임 실행 파일의 특정 검증 로직 우회
접근:
  1. x64dbg / IDA로 바이너리 분석
  2. 조건 분기 (JZ, JNZ 등) 탐색
  3. NOP 또는 JMP 패치로 우회
  4. 또는 AOB 패턴 패치 자동화

예시 CTF 문제:
  - "점수 검증" 루틴 우회 → 임의 점수 설정 → 플래그
  - "구매 가능 여부" 체크 NOP → 무료 구매 → 특수 아이템 → 플래그
```

**유형 4: 프로토콜 역분석**
```
목표: 독자적인 암호화/직렬화 프로토콜 해독
접근:
  1. Wireshark로 패킷 수집
  2. 엔트로피 분석 (암호화 여부 판단)
  3. 키 교환 로직 탐색 (핸드셰이크 단계)
  4. 또는 클라이언트 코드에서 암복호화 함수 탐색

예시 CTF 문제:
  - XOR 키로 암호화된 패킷 해독 → 서버 명령 파악 → 플래그 패킷 전송
  - 커스텀 직렬화 포맷 파싱 → 특정 플래그 필드 설정 → 서버 응답에 플래그
```

---

## 6. Python 안티치트 시뮬레이터 (학습용)

```python
#!/usr/bin/env python3
"""
간단한 안티치트 시뮬레이터 (학습/연구 목적)
메모리 무결성 검사, 프로세스 모니터링 개념 구현
"""

import hashlib
import time
import threading
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class IntegrityRecord:
    """파일 무결성 레코드"""
    path: str
    sha256: str
    size: int
    last_checked: float = 0.0
    is_tampered: bool = False


class FileIntegrityMonitor:
    """파일 무결성 모니터"""

    def __init__(self, check_interval: float = 5.0) -> None:
        self.check_interval = check_interval
        self._records: dict[str, IntegrityRecord] = {}
        self._running = False
        self._on_tamper: list[Callable[[IntegrityRecord], None]] = []

    def register(self, filepath: str) -> None:
        """파일 등록 (초기 해시 계산)"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"파일 미발견: {filepath}")

        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        record = IntegrityRecord(
            path=filepath,
            sha256=sha256,
            size=len(data),
            last_checked=time.time(),
        )
        self._records[filepath] = record
        print(f"[*] 등록: {path.name}  SHA256={sha256[:16]}...")

    def on_tamper(self, callback: Callable[[IntegrityRecord], None]) -> None:
        """변조 탐지 콜백 등록"""
        self._on_tamper.append(callback)

    def check_once(self) -> list[IntegrityRecord]:
        """한 번 검사, 변조된 레코드 반환"""
        tampered: list[IntegrityRecord] = []

        for filepath, record in self._records.items():
            path = Path(filepath)
            if not path.exists():
                record.is_tampered = True
                tampered.append(record)
                continue

            data = path.read_bytes()
            current_hash = hashlib.sha256(data).hexdigest()
            record.last_checked = time.time()

            if current_hash != record.sha256 or len(data) != record.size:
                record.is_tampered = True
                tampered.append(record)
                for cb in self._on_tamper:
                    cb(record)
            else:
                record.is_tampered = False

        return tampered

    def start_monitoring(self) -> None:
        """백그라운드 모니터링 시작"""
        self._running = True
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()
        print(f"[*] 파일 무결성 모니터링 시작 (간격: {self.check_interval}s)")

    def _monitor_loop(self) -> None:
        while self._running:
            tampered = self.check_once()
            if tampered:
                for r in tampered:
                    print(f"[!] 변조 탐지: {r.path}")
            time.sleep(self.check_interval)

    def stop(self) -> None:
        self._running = False


class ProcessWhitelist:
    """프로세스 화이트리스트 체크"""

    BLACKLISTED_PROCESSES: set[str] = {
        "cheatengine-x86_64.exe",
        "cheatengine-x86_64-SSE4-AVX2.exe",
        "processhacker.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida64.exe",
        "idaq64.exe",
        "wireshark.exe",
        "fiddler.exe",
        "artmoney.exe",
        "tsearch.exe",
    }

    def check(self) -> list[str]:
        """실행 중인 블랙리스트 프로세스 반환"""
        import ctypes
        import ctypes.wintypes as wt

        found: list[str] = []

        try:
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wt.DWORD),
                    ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wt.DWORD),
                    ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            k32 = ctypes.windll.kernel32  # type: ignore
            snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

            try:
                if k32.Process32First(snapshot, ctypes.byref(entry)):
                    while True:
                        name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
                        if name in self.BLACKLISTED_PROCESSES:
                            found.append(name)
                        if not k32.Process32Next(snapshot, ctypes.byref(entry)):
                            break
            finally:
                k32.CloseHandle(snapshot)

        except Exception as e:
            print(f"[!] 프로세스 열거 오류: {e}", file=sys.stderr)

        return found


def main() -> None:
    parser = argparse.ArgumentParser(description="안티치트 시뮬레이터 (학습/연구용)")
    sub = parser.add_subparsers(dest="command", required=True)

    # 파일 무결성 모니터
    p_fim = sub.add_parser("fim", help="파일 무결성 모니터링")
    p_fim.add_argument("files", nargs="+", help="모니터링할 파일 경로")
    p_fim.add_argument("--interval", type=float, default=5.0, help="검사 간격(초)")

    # 블랙리스트 프로세스 체크
    sub.add_parser("proccheck", help="블랙리스트 프로세스 탐지")

    args = parser.parse_args()

    if args.command == "fim":
        monitor = FileIntegrityMonitor(check_interval=args.interval)
        monitor.on_tamper(lambda r: print(f"[경고] 변조 감지: {r.path}"))

        for f in args.files:
            try:
                monitor.register(f)
            except FileNotFoundError as e:
                print(f"[!] {e}", file=sys.stderr)

        monitor.start_monitoring()
        print("[*] Ctrl+C로 중지")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
            print("\n[*] 모니터링 중지")

    elif args.command == "proccheck":
        wl = ProcessWhitelist()
        found = wl.check()
        if found:
            print(f"[!] 블랙리스트 프로세스 탐지: {len(found)}개")
            for name in found:
                print(f"    - {name}")
        else:
            print("[*] 블랙리스트 프로세스 없음")


if __name__ == "__main__":
    main()
```

---

## 7. 게임 보안 강화 권고사항 (개발자 관점)

### 7.1 클라이언트사이드 보안

```
1. 서버사이드 검증 우선
   - 모든 게임 상태(체력, 점수, 위치)는 서버에서 최종 결정
   - 클라이언트는 디스플레이 목적으로만 사용

2. 입력 값 범위 검증
   - 이동 속도: 정상 최대치 + 허용 오차 이내만 수용
   - 데미지: 캐릭터 스탯 기반 최대치 계산 후 검증
   - 거래 가격: 서버 DB의 실제 가격으로 검증

3. 타이밍 검증
   - 공격 쿨타임을 서버에서 추적
   - 비정상 빠른 연속 행동 탐지

4. 암호화 통신
   - TLS 1.3 사용 (패킷 스니핑 방어)
   - 세션별 고유 키 사용 (replay attack 방어)
   - 패킷 시퀀스 번호 + 타임스탬프로 재전송 방지
```

### 7.2 안티탬퍼링

```
5. 코드 서명 검증
   - 실행 파일의 디지털 서명 부팅 시 검증
   - 인메모리 코드 섹션 주기적 해시 비교

6. 난독화
   - 주요 검증 함수 난독화
   - 문자열 암호화로 정적 분석 난이도 향상

7. 안티디버깅
   - IsDebuggerPresent / CheckRemoteDebuggerPresent
   - 타이밍 기반 디버거 탐지 (RDTSC 기법)
   - Exception-based 탐지
```

### 7.3 모니터링 및 대응

```
8. 행위 로깅
   - 의심 패턴 서버사이드 기록 및 분석
   - 통계적 이상치 탐지 (AimBot: 조준 정확도 > 99%)

9. 소프트 밴 전략
   - 즉시 밴 대신 일정 기간 관찰 후 일괄 밴
   - 치터 오탐 피해 최소화

10. 취약점 보고 프로그램
    - 책임 있는 공개(Responsible Disclosure) 정책 수립
    - 버그 바운티로 보안 연구자와 협력
```

---

## 8. 실전 CTF 도전 — 풀이 흐름

```bash
# 1. 게임 프로세스 분석
python process_analyzer.py game.exe

# 2. 로드된 모듈 확인 (의심 DLL 탐지)
python process_analyzer.py game.exe --output report.json

# 3. 특정 값 스캔 (Cheat Engine 대신)
python mem_tool.py game.exe aob "89 45 ?? 8B 4D ??"

# 4. 패킷 캡처 + 분석
python packet_tool.py sniff eth0 7777 -d 60 -o capture.json
python packet_tool.py pcap capture.pcap --output packets.json

# 5. 프로토버프 역분석
python proto_decode.py --hex "0a0548656c6c6f"

# 6. 파일 무결성 모니터링 (안티치트 학습)
python anticheat_sim.py fim game.exe game_data.dat

# 7. 블랙리스트 프로세스 체크 (탐지 회피 연구)
python anticheat_sim.py proccheck
```

---

<!-- detect-validate-50 -->
## 안티치트 효과 검증 (배포됨 ≠ 탐지함)

안티치트(커널 레벨·DLL 인젝션 탐지·무결성 검사)는 *조작 탐지·차단*을 목표로 한다. "안티치트를 배포했다"는 설정과 "실제 조작을 탐지·차단한다"는 다르다 — 각 탐지를 소유 테스트 환경에서 검증한다(CTF/보안 연구 관점).

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| 인젝션 탐지 | DLL 주입 잡나? | 테스트 주입 시 플래그 | 우회 모듈 미탐 |
| 무결성 검사 | 코드 변조 탐지? | .text 패치 시 알람 | 주기적 미검사 |
| 메모리 스캔 | 시그니처 탐지? | 알려진 치트 패턴 발견 | 난독화 회피 |
| 서버 연계 | 탐지→조치? | 플래그→서버 제재 | 로컬만, 미보고 |

### 효과 검증 (직접 확인)

```bash
# 1) 소유 테스트 환경에서 안티치트가 모듈 주입을 탐지·기록하는지 — 미탐이면 탐지 갭 신호
grep -icE 'injection detected|unauthorized module|integrity violation' anticheat.log 2>/dev/null  # >0 이어야
# 2) 코드 무결성 검사 발화 — 테스트 패치 후 변조 탐지 로그 확인(소유 환경)
sha256sum /proc/$(pgrep -n testgame)/exe 2>/dev/null; grep -c 'tamper' anticheat.log 2>/dev/null
```

> 안티치트는 *조작을 탐지하는가*다 — "커널 안티치트가 있다"와 "테스트 주입이 플래그되고 코드 변조가 알람을 내며 서버로 보고된다"는 다르다. 각 탐지를 소유 테스트 환경에서 직접 검증한다([[55_Evasion_Techniques]], [[04_Reverse_Engineering]], [[40_Threat_Hunting]]).

**최신 기법·통제 (2025–2026):**
- 커널모드 안티치트·행위 텔레메트리·서버측 통계탐지가 표준 — 검증: 치트 신호가 서버 이상탐지에서 드러나는지 재현([[40_Threat_Hunting]])
- 순수 탐지 관점(우회기법 아님) — 텔레메트리에 남는 흔적 중심

---

<a name="english"></a>

# 04. Anti-Cheat Analysis

This section covers how to understand the operating principles of anti-cheat systems and how to analyze them from a security research and CTF perspective. It also includes hardening recommendations from the defender (developer) point of view.

---

## 1. Types of Anti-Cheat Systems

### 1.1 Major Anti-Cheat Comparison

| Anti-Cheat | Game Examples        | Method                    | Kernel Driver      | Cloud Integration |
|------------|---------------------|---------------------------|--------------------|-------------------|
| VAC        | CS2, Dota2          | Server-side, post-process | None               | Yes               |
| EAC        | Fortnite, Apex      | Client-side, real-time    | Yes (optional)     | Yes               |
| BattlEye   | PUBG, DayZ          | Client-side, real-time    | Yes                | Yes               |
| FACEIT     | CS2 (3rd party)     | Kernel + cloud            | Yes                | Yes               |
| Vanguard   | Valorant            | Kernel Ring-0, at boot    | Yes (required)     | Yes               |
| nProtect   | Korean MMORPGs      | Kernel, local             | Yes                | Partial           |
| XIGNCODE   | Asian MMORPGs       | Kernel, local             | Yes                | Partial           |

### 1.2 Operating Layer Classification

```
Ring 3 (User Mode)
  ├── Memory Scanner — searches for known cheat signatures
  ├── Process Monitor — checks list of suspicious processes
  ├── File Scanner — verifies game file integrity
  └── Timing Check — detects abnormal frame rates

Ring 0 (Kernel Mode)
  ├── DKOM Detection — detects hidden processes/drivers
  ├── Callback Registration — PsSetCreateProcessNotifyRoutine
  ├── SSDT Hook Detection — detects system call table tampering
  └── Page Table Scan — detects memory disguise
```

---

## 2. Kernel-Level Anti-Cheat Operating Principles

### 2.1 Windows Kernel Driver Mechanisms

```c
// Key APIs used by anti-cheat drivers (for conceptual explanation)

// 1. Register process creation callback
PsSetCreateProcessNotifyRoutineEx(MyProcessCreateCallback, FALSE);

// 2. Image (DLL/EXE) load callback
PsSetLoadImageNotifyRoutine(MyImageLoadCallback);

// 3. Thread creation callback
PsSetCreateThreadNotifyRoutine(MyThreadCreateCallback);

// 4. Object handle callback (intercept OpenProcess)
ObRegisterCallbacks(&registration, &handle);

// 5. Collect process info via direct EPROCESS struct access
PEPROCESS target = PsGetCurrentProcess();
```

### 2.2 Detection Technique Classification

**Signature Detection**
```
Searches memory/files for byte patterns of known cheat tools
- Advantage: Fast and accurate
- Disadvantage: Can be bypassed by changing patterns (packers, polymorphic)
```

**Behavioral Detection**
```
Monitors suspicious API call patterns
- Frequency of ReadProcessMemory calls
- VirtualAllocEx followed by WriteProcessMemory + CreateRemoteThread
- Abnormal accuracy in-game (aimbot detection)
```

**Integrity Check**
```
Continuously verifies checksums of game files and memory
- Executable file hash comparison
- In-memory code section verification (IAT hook, inline hook detection)
```

**Timing Check**
```
Detects abnormal reaction speeds
- Aiming speed beyond human capability
- Consistent reaction time patterns (macro detection)
```

---

## 3. Python Game Process Analysis Tool

### 3.1 Complete Process Analyzer

```python
#!/usr/bin/env python3
"""
Game process analysis tool (for CTF/security research purposes)
Detects module list, handles, hooks, and injected DLLs
"""

import ctypes
import ctypes.wintypes as wt
import argparse
import sys
import struct
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Windows API constants
TH32CS_SNAPALL       = 0x0000001F
TH32CS_SNAPPROCESS   = 0x00000002
TH32CS_SNAPMODULE    = 0x00000008
TH32CS_SNAPMODULE32  = 0x00000010
TH32CS_SNAPTHREAD    = 0x00000004
PROCESS_ALL_ACCESS   = 0x1F0FFF
PAGE_EXECUTE         = 0x10
PAGE_EXECUTE_READ    = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT           = 0x1000
MEM_IMAGE            = 0x1000000
MEM_MAPPED           = 0x40000
MEM_PRIVATE          = 0x20000


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


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",             wt.DWORD),
        ("cntUsage",           wt.DWORD),
        ("th32ThreadID",       wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri",          ctypes.c_long),
        ("tpDeltaPri",         ctypes.c_long),
        ("dwFlags",            wt.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId",       wt.WORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
    ]


@dataclass
class ModuleInfo:
    name: str
    path: str
    base_address: int
    size: int
    is_suspicious: bool = False
    reason: str = ""


@dataclass
class MemoryRegion:
    base: int
    size: int
    protect: int
    state: int
    mem_type: int
    is_executable: bool = False
    is_private_exec: bool = False


@dataclass
class ProcessAnalysis:
    pid: int
    name: str
    modules: list[ModuleInfo] = field(default_factory=list)
    threads: list[dict] = field(default_factory=list)
    memory_regions: list[MemoryRegion] = field(default_factory=list)
    suspicious_modules: list[ModuleInfo] = field(default_factory=list)
    private_exec_regions: list[MemoryRegion] = field(default_factory=list)


class GameProcessAnalyzer:
    """Game process analyzer"""

    # Known cheat tool DLL signatures (partial)
    SUSPICIOUS_MODULES: set[str] = {
        "speedhack.dll",
        "cheatengine",
        "injector",
        "trainer",
        "hack",
        "aimbot",
        "esp",
        "wallhack",
        "triggerbot",
        "bhop",
    }

    # Known system DLL whitelist (partial)
    KNOWN_SYSTEM_DLLS: set[str] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll",
        "user32.dll", "gdi32.dll", "advapi32.dll",
        "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll",
        "d3d11.dll", "d3d12.dll", "dxgi.dll",
        "opengl32.dll", "vulkan-1.dll",
        "ws2_32.dll", "wininet.dll",
    }

    def __init__(self, process_name_or_pid: str) -> None:
        self._target = process_name_or_pid
        self._k32 = ctypes.windll.kernel32  # type: ignore
        self._pid: int = 0
        self._handle: Optional[wt.HANDLE] = None
        self._setup_api()

    def _setup_api(self) -> None:
        k32 = self._k32
        k32.OpenProcess.restype = wt.HANDLE
        k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k32.ReadProcessMemory.restype = wt.BOOL
        k32.ReadProcessMemory.argtypes = [
            wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        k32.VirtualQueryEx.argtypes = [
            wt.HANDLE, ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t
        ]

    def _find_pid(self) -> int:
        """Return PID from process name or PID string"""
        try:
            return int(self._target)
        except ValueError:
            pass

        snapshot = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if self._k32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
                    if name == self._target.lower():
                        return entry.th32ProcessID
                    if not self._k32.Process32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        raise RuntimeError(f"Process not found: {self._target}")

    def open(self) -> None:
        self._pid = self._find_pid()
        self._handle = self._k32.OpenProcess(PROCESS_ALL_ACCESS, False, self._pid)
        if not self._handle:
            raise PermissionError(f"Failed to open process (admin rights required), PID={self._pid}")
        print(f"[*] Successfully opened process: PID={self._pid}")

    def get_modules(self) -> list[ModuleInfo]:
        """Collect list of loaded modules"""
        modules: list[ModuleInfo] = []
        flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        snapshot = self._k32.CreateToolhelp32Snapshot(flags, self._pid)
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        try:
            if self._k32.Module32First(snapshot, ctypes.byref(entry)):
                while True:
                    name = entry.szModule.decode("utf-8", errors="ignore")
                    path = entry.szExePath.decode("utf-8", errors="ignore")
                    base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0

                    mod = ModuleInfo(
                        name=name,
                        path=path,
                        base_address=base,
                        size=entry.modBaseSize,
                    )

                    # Determine if module is suspicious
                    name_lower = name.lower()
                    if any(keyword in name_lower for keyword in self.SUSPICIOUS_MODULES):
                        mod.is_suspicious = True
                        mod.reason = "Contains known cheat tool keyword"
                    elif name_lower not in self.KNOWN_SYSTEM_DLLS:
                        path_lower = path.lower()
                        if "system32" not in path_lower and "syswow64" not in path_lower:
                            mod.is_suspicious = True
                            mod.reason = "Unverified DLL from non-system path"

                    modules.append(mod)
                    if not self._k32.Module32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        return modules

    def get_threads(self) -> list[dict]:
        """List of process threads"""
        threads: list[dict] = []
        snapshot = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        try:
            if self._k32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == self._pid:
                        threads.append({
                            "tid": entry.th32ThreadID,
                            "base_priority": entry.tpBasePri,
                        })
                    if not self._k32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self._k32.CloseHandle(snapshot)

        return threads

    def scan_memory_regions(self) -> list[MemoryRegion]:
        """Scan memory regions — detect executable private regions"""
        if not self._handle:
            raise RuntimeError("Process is not open")

        regions: list[MemoryRegion] = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0

        exec_flags = (
            PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )

        while True:
            result = self._k32.VirtualQueryEx(
                self._handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if result == 0:
                break

            if mbi.State == MEM_COMMIT:
                is_exec = bool(mbi.Protect & exec_flags)
                is_private = mbi.Type == MEM_PRIVATE

                region = MemoryRegion(
                    base=mbi.BaseAddress or 0,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    state=mbi.State,
                    mem_type=mbi.Type,
                    is_executable=is_exec,
                    is_private_exec=is_exec and is_private,
                )
                regions.append(region)

            next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_addr <= addr:
                break
            addr = next_addr

        return regions

    def check_iat_hooks(self, module_base: int, module_size: int) -> list[dict]:
        """Detect IAT (Import Address Table) hooking"""
        if not self._handle:
            return []

        hooks: list[dict] = []

        try:
            # Read PE header
            buf_size = min(module_size, 0x1000)
            buffer = ctypes.create_string_buffer(buf_size)
            bytes_read = ctypes.c_size_t(0)
            self._k32.ReadProcessMemory(
                self._handle, module_base, buffer, buf_size, ctypes.byref(bytes_read)
            )
            data = bytes(buffer.raw)

            # DOS header → PE header
            if data[:2] != b"MZ":
                return []

            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return []

            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []

            # Check machine type (x64: 0x8664, x86: 0x014C)
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            is_64bit = machine == 0x8664

            optional_offset = pe_offset + 24
            if is_64bit:
                # 64-bit: import directory RVA is at Optional Header +104
                import_dir_rva = struct.unpack_from("<I", data, optional_offset + 104)[0]
            else:
                # 32-bit: import directory RVA is at Optional Header +80
                import_dir_rva = struct.unpack_from("<I", data, optional_offset + 80)[0]

            # Simple hook detection: check if IAT entries fall outside known system module ranges
            # (actual implementation is far more complex; this is a conceptual demonstration)
            if import_dir_rva > 0:
                hooks.append({
                    "type": "IAT_CHECK",
                    "module_base": hex(module_base),
                    "import_dir_rva": hex(import_dir_rva),
                    "status": "IAT structure found (detailed analysis required)",
                })

        except Exception as e:
            hooks.append({"error": str(e)})

        return hooks

    def analyze(self) -> ProcessAnalysis:
        """Run full analysis"""
        analysis = ProcessAnalysis(pid=self._pid, name=self._target)

        print("[*] Collecting module list...")
        analysis.modules = self.get_modules()
        analysis.suspicious_modules = [m for m in analysis.modules if m.is_suspicious]

        print("[*] Collecting thread list...")
        analysis.threads = self.get_threads()

        print("[*] Scanning memory regions...")
        try:
            analysis.memory_regions = self.scan_memory_regions()
            analysis.private_exec_regions = [
                r for r in analysis.memory_regions if r.is_private_exec
            ]
        except Exception as e:
            print(f"[!] Memory scan error: {e}")

        return analysis

    def close(self) -> None:
        if self._handle:
            self._k32.CloseHandle(self._handle)
            self._handle = None


def print_analysis_report(analysis: ProcessAnalysis) -> None:
    """Print analysis results"""
    print(f"\n{'='*60}")
    print(f"  Process Analysis Report")
    print(f"  PID: {analysis.pid}  Name: {analysis.name}")
    print(f"{'='*60}")

    print(f"\n[Module List] Total: {len(analysis.modules)}")
    for mod in analysis.modules:
        flag = " [!]" if mod.is_suspicious else ""
        print(f"  0x{mod.base_address:016X}  {mod.size:>10,} bytes  "
              f"{mod.name:<40}{flag}")
        if mod.is_suspicious:
            print(f"      └ Reason: {mod.reason}")

    if analysis.suspicious_modules:
        print(f"\n[Suspicious Modules] {len(analysis.suspicious_modules)} detected")
        for mod in analysis.suspicious_modules:
            print(f"  [!] {mod.name}")
            print(f"      Path: {mod.path}")
            print(f"      Reason: {mod.reason}")
    else:
        print("\n[Suspicious Modules] None")

    print(f"\n[Threads] Total: {len(analysis.threads)}")
    for t in analysis.threads[:10]:
        print(f"  TID={t['tid']}  Priority={t['base_priority']}")
    if len(analysis.threads) > 10:
        print(f"  ... (+{len(analysis.threads) - 10} more)")

    if analysis.private_exec_regions:
        print(f"\n[Executable Private Memory Regions] {len(analysis.private_exec_regions)} detected")
        print("  (Suspected DLL injection or shellcode injection)")
        for r in analysis.private_exec_regions[:10]:
            print(f"  0x{r.base:016X}  Size={r.size:>10,} bytes  "
                  f"Protect={r.protect:#010x}")
    else:
        print("\n[Executable Private Memory] None")

    print(f"\n[Memory Regions] Total committed: {len(analysis.memory_regions)}")
    exec_count = sum(1 for r in analysis.memory_regions if r.is_executable)
    print(f"  Executable regions: {exec_count}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Game process analysis tool (CTF/security research)")
    parser.add_argument("target", help="Process name or PID")
    parser.add_argument("--output", "-o", help="Path to save JSON results")
    parser.add_argument("--modules-only", action="store_true", help="Print module list only")
    args = parser.parse_args()

    analyzer = GameProcessAnalyzer(args.target)
    try:
        analyzer.open()
    except (RuntimeError, PermissionError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        analysis = analyzer.analyze()
        print_analysis_report(analysis)

        if args.output:
            data = {
                "pid": analysis.pid,
                "name": analysis.name,
                "modules": [asdict(m) for m in analysis.modules],
                "suspicious_modules": [asdict(m) for m in analysis.suspicious_modules],
                "threads": analysis.threads,
                "private_exec_regions": [asdict(r) for r in analysis.private_exec_regions],
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n[*] Results saved: {args.output}")
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
```

---

## 4. DLL Injection Detection Concepts

### 4.1 DLL Injection Methodologies (Detection Perspective)

```
Method 1: CreateRemoteThread + LoadLibrary
  Detection: Monitor CreateRemoteThread API
             Check for DLL path strings in remote memory

Method 2: SetWindowsHookEx
  Detection: Check registered hook list for hooks targeting known game processes
             Combine EnumWindows + GetWindowThreadProcessId

Method 3: Process Hollowing
  Detection: Hash mismatch between actual file and in-memory image
             Mismatch between original path in PE header and actual load path

Method 4: Manual Mapping
  Detection: Executable memory regions not backed by a file (private exec)
             Modules not registered in PEB LDR
```

### 4.2 Reading Module List from PEB (Direct Access)

```c
// Access PEB via NtQueryInformationProcess (for detecting detection bypass)
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

void enumerate_peb_modules(HANDLE hProc) {
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret_len = 0;
    NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);

    // Read PEB
    PEB peb = {0};
    ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);

    // Read LDR data
    PEB_LDR_DATA ldr_data = {0};
    ReadProcessMemory(hProc, peb.Ldr, &ldr_data, sizeof(ldr_data), NULL);

    // Traverse module list (InMemoryOrderModuleList)
    LIST_ENTRY* head = &ldr_data.InMemoryOrderModuleList;
    LIST_ENTRY entry = {0};
    ReadProcessMemory(hProc, head->Flink, &entry, sizeof(entry), NULL);

    while (entry.Flink != head->Flink) {
        LDR_DATA_TABLE_ENTRY mod_entry = {0};
        ReadProcessMemory(
            hProc,
            CONTAINING_RECORD(entry.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &mod_entry, sizeof(mod_entry), NULL
        );
        // Can print mod_entry.BaseDllName, mod_entry.DllBase
        // ... 
        ReadProcessMemory(hProc, entry.Flink, &entry, sizeof(entry), NULL);
    }
}
```

---

## 5. Anti-Cheat Bypass Research Methodology (CTF/Security Research Perspective)

### 5.1 Setting Up a Research Environment

```
1. Isolated VM environment (Hyper-V, VMware) is mandatory
   - Use snapshot functionality to set up a safe experimental environment
   - Network isolation to prevent impact on real game servers

2. Install analysis tools
   - WinDbg + Symbol Server configuration
   - x64dbg / OllyDbg
   - Process Hacker / Process Monitor
   - Wireshark / Fiddler

3. Kernel debugging environment
   - Enable test signing mode
   - Configure KDNET (remote kernel debugging)
```

### 5.2 Approach by CTF Game Hacking Challenge Type

**Type 1: Memory Value Modification**
```
Goal: Obtain the flag by changing a specific value
Approach:
  1. Scan values with Cheat Engine
  2. Trace pointer chains
  3. Modify value then trigger game event
  4. Or automate with Python ctypes script

Example CTF problems:
  - Reach 1000 HP in-game → print flag
  - Set gold to a specific value → unlock special item purchase → flag
```

**Type 2: Packet Manipulation**
```
Goal: Trigger server-side event by modifying network packets
Approach:
  1. Capture traffic with Wireshark
  2. Analyze protocol structure (header + payload)
  3. Modify in real-time with mitmproxy
  4. Or send custom packets directly

Example CTF problems:
  - Manipulate reward value in quest completion packet → excess reward → flag
  - Modify privilege level in login response packet → admin menu → flag
```

**Type 3: Reversing + Code Patching**
```
Goal: Bypass specific validation logic in game executable
Approach:
  1. Analyze binary with x64dbg / IDA
  2. Search for conditional branches (JZ, JNZ, etc.)
  3. Bypass with NOP or JMP patch
  4. Or automate AOB pattern patching

Example CTF problems:
  - Bypass "score validation" routine → set arbitrary score → flag
  - NOP "purchase availability" check → free purchase → special item → flag
```

**Type 4: Protocol Reverse Engineering**
```
Goal: Decrypt a proprietary encryption/serialization protocol
Approach:
  1. Collect packets with Wireshark
  2. Entropy analysis (determine if encrypted)
  3. Search for key exchange logic (handshake phase)
  4. Or search for encrypt/decrypt functions in client code

Example CTF problems:
  - Decrypt XOR-encrypted packets → understand server commands → send flag packet
  - Parse custom serialization format → set specific flag field → server responds with flag
```

---

## 6. Python Anti-Cheat Simulator (Educational)

```python
#!/usr/bin/env python3
"""
Simple anti-cheat simulator (for learning/research purposes)
Implements concepts of memory integrity checking and process monitoring
"""

import hashlib
import time
import threading
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class IntegrityRecord:
    """File integrity record"""
    path: str
    sha256: str
    size: int
    last_checked: float = 0.0
    is_tampered: bool = False


class FileIntegrityMonitor:
    """File integrity monitor"""

    def __init__(self, check_interval: float = 5.0) -> None:
        self.check_interval = check_interval
        self._records: dict[str, IntegrityRecord] = {}
        self._running = False
        self._on_tamper: list[Callable[[IntegrityRecord], None]] = []

    def register(self, filepath: str) -> None:
        """Register file (compute initial hash)"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        record = IntegrityRecord(
            path=filepath,
            sha256=sha256,
            size=len(data),
            last_checked=time.time(),
        )
        self._records[filepath] = record
        print(f"[*] Registered: {path.name}  SHA256={sha256[:16]}...")

    def on_tamper(self, callback: Callable[[IntegrityRecord], None]) -> None:
        """Register tampering detection callback"""
        self._on_tamper.append(callback)

    def check_once(self) -> list[IntegrityRecord]:
        """Check once, return tampered records"""
        tampered: list[IntegrityRecord] = []

        for filepath, record in self._records.items():
            path = Path(filepath)
            if not path.exists():
                record.is_tampered = True
                tampered.append(record)
                continue

            data = path.read_bytes()
            current_hash = hashlib.sha256(data).hexdigest()
            record.last_checked = time.time()

            if current_hash != record.sha256 or len(data) != record.size:
                record.is_tampered = True
                tampered.append(record)
                for cb in self._on_tamper:
                    cb(record)
            else:
                record.is_tampered = False

        return tampered

    def start_monitoring(self) -> None:
        """Start background monitoring"""
        self._running = True
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()
        print(f"[*] File integrity monitoring started (interval: {self.check_interval}s)")

    def _monitor_loop(self) -> None:
        while self._running:
            tampered = self.check_once()
            if tampered:
                for r in tampered:
                    print(f"[!] Tampering detected: {r.path}")
            time.sleep(self.check_interval)

    def stop(self) -> None:
        self._running = False


class ProcessWhitelist:
    """Process whitelist check"""

    BLACKLISTED_PROCESSES: set[str] = {
        "cheatengine-x86_64.exe",
        "cheatengine-x86_64-SSE4-AVX2.exe",
        "processhacker.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida64.exe",
        "idaq64.exe",
        "wireshark.exe",
        "fiddler.exe",
        "artmoney.exe",
        "tsearch.exe",
    }

    def check(self) -> list[str]:
        """Return running blacklisted processes"""
        import ctypes
        import ctypes.wintypes as wt

        found: list[str] = []

        try:
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wt.DWORD),
                    ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wt.DWORD),
                    ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            k32 = ctypes.windll.kernel32  # type: ignore
            snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

            try:
                if k32.Process32First(snapshot, ctypes.byref(entry)):
                    while True:
                        name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
                        if name in self.BLACKLISTED_PROCESSES:
                            found.append(name)
                        if not k32.Process32Next(snapshot, ctypes.byref(entry)):
                            break
            finally:
                k32.CloseHandle(snapshot)

        except Exception as e:
            print(f"[!] Process enumeration error: {e}", file=sys.stderr)

        return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Anti-cheat simulator (for learning/research)")
    sub = parser.add_subparsers(dest="command", required=True)

    # File integrity monitor
    p_fim = sub.add_parser("fim", help="File integrity monitoring")
    p_fim.add_argument("files", nargs="+", help="File paths to monitor")
    p_fim.add_argument("--interval", type=float, default=5.0, help="Check interval (seconds)")

    # Blacklist process check
    sub.add_parser("proccheck", help="Detect blacklisted processes")

    args = parser.parse_args()

    if args.command == "fim":
        monitor = FileIntegrityMonitor(check_interval=args.interval)
        monitor.on_tamper(lambda r: print(f"[WARNING] Tampering detected: {r.path}"))

        for f in args.files:
            try:
                monitor.register(f)
            except FileNotFoundError as e:
                print(f"[!] {e}", file=sys.stderr)

        monitor.start_monitoring()
        print("[*] Press Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
            print("\n[*] Monitoring stopped")

    elif args.command == "proccheck":
        wl = ProcessWhitelist()
        found = wl.check()
        if found:
            print(f"[!] Blacklisted processes detected: {len(found)}")
            for name in found:
                print(f"    - {name}")
        else:
            print("[*] No blacklisted processes found")


if __name__ == "__main__":
    main()
```

---

## 7. Game Security Hardening Recommendations (Developer Perspective)

### 7.1 Client-Side Security

```
1. Prioritize server-side validation
   - All game state (HP, score, position) is finalized on the server
   - Client is used for display purposes only

2. Input value range validation
   - Movement speed: accept only within normal maximum + allowed tolerance
   - Damage: calculate maximum based on character stats, then validate
   - Trade price: validate against actual price in server DB

3. Timing validation
   - Track attack cooldowns on the server
   - Detect abnormally rapid consecutive actions

4. Encrypted communication
   - Use TLS 1.3 (defense against packet sniffing)
   - Use unique keys per session (defense against replay attacks)
   - Prevent retransmission with packet sequence numbers + timestamps
```

### 7.2 Anti-Tampering

```
5. Code signature verification
   - Verify digital signature of executable at boot time
   - Periodically hash-compare in-memory code sections

6. Obfuscation
   - Obfuscate key validation functions
   - String encryption to increase static analysis difficulty

7. Anti-debugging
   - IsDebuggerPresent / CheckRemoteDebuggerPresent
   - Timing-based debugger detection (RDTSC technique)
   - Exception-based detection
```

### 7.3 Monitoring and Response

```
8. Behavioral logging
   - Record and analyze suspicious patterns server-side
   - Statistical outlier detection (AimBot: aiming accuracy > 99%)

9. Soft ban strategy
   - Observe for a period instead of immediate ban, then batch ban
   - Minimize false positive damage to legitimate players

10. Vulnerability reporting program
    - Establish a Responsible Disclosure policy
    - Collaborate with security researchers via bug bounty
```

---

## 8. Practical CTF Challenge — Solution Workflow

```bash
# 1. Analyze game process
python process_analyzer.py game.exe

# 2. Check loaded modules (detect suspicious DLLs)
python process_analyzer.py game.exe --output report.json

# 3. Scan for specific values (instead of Cheat Engine)
python mem_tool.py game.exe aob "89 45 ?? 8B 4D ??"

# 4. Capture + analyze packets
python packet_tool.py sniff eth0 7777 -d 60 -o capture.json
python packet_tool.py pcap capture.pcap --output packets.json

# 5. Reverse engineer protobuf
python proto_decode.py --hex "0a0548656c6c6f"

# 6. File integrity monitoring (anti-cheat learning)
python anticheat_sim.py fim game.exe game_data.dat

# 7. Blacklist process check (detection evasion research)
python anticheat_sim.py proccheck
```

<!-- detect-validate-50 -->
## Anti-Cheat Effectiveness Validation (Deployed != Detecting)

Anti-cheat (kernel-level, DLL-injection detection, integrity checks) aims to *detect and block tampering*. "We deployed anti-cheat" differs from "it actually detects/blocks real tampering" -- validate each detection on owned test environments (from a CTF/security-research perspective).

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| Injection detection | Catch DLL injection? | Flag on test injection | Misses bypass module |
| Integrity check | Detect code tampering? | Alarm on .text patch | No periodic check |
| Memory scan | Detect signatures? | Known cheat pattern found | Obfuscation evades |
| Server linkage | Detect->act? | Flag -> server sanction | Local only, not reported |

### Effectiveness validation (verify directly)

```bash
# 1) Whether anti-cheat detects/logs a module injection on an owned test env — a miss signals a detection gap
grep -icE 'injection detected|unauthorized module|integrity violation' anticheat.log 2>/dev/null  # should be >0
# 2) Code-integrity check firing — confirm a tamper-detection log after a test patch (owned env)
sha256sum /proc/$(pgrep -n testgame)/exe 2>/dev/null; grep -c 'tamper' anticheat.log 2>/dev/null
```

> Anti-cheat is *whether it detects tampering* -- "we have kernel anti-cheat" differs from "a test injection is flagged, code tampering alarms, and it is reported to the server". Validate each detection on owned test environments directly ([[55_Evasion_Techniques]], [[04_Reverse_Engineering]], [[40_Threat_Hunting]]).
