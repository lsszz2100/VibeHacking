> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# PE 구조 & Windows 내부 구조

## 1. PE (Portable Executable) 파일 구조

### PE 파일이란?
Windows 실행 파일(.exe, .dll, .sys 등)의 파일 포맷.
리버싱과 악성코드 분석의 핵심 이해 대상.

### PE 파일 헤더 구조
```
┌─────────────────────────────────────┐
│  DOS Header (64 bytes)              │ ← MZ 시그니처 (0x4D5A)
│  DOS Stub                           │ ← "This program cannot run in DOS"
├─────────────────────────────────────┤
│  PE Header (Signature: "PE\0\0")    │ ← 0x00004550
│  ├── File Header (COFF Header)      │
│  │   ├── Machine (CPU 타입)         │
│  │   ├── NumberOfSections (섹션 수) │
│  │   ├── TimeDateStamp (컴파일 시간)│
│  │   └── Characteristics           │
│  └── Optional Header               │
│       ├── Magic (PE32/PE32+)        │
│       ├── AddressOfEntryPoint       │ ← 프로그램 시작 주소
│       ├── ImageBase                 │ ← 메모리 로드 기준 주소
│       ├── SectionAlignment          │
│       ├── FileAlignment             │
│       └── DataDirectory[16]         │ ← Import, Export 등
├─────────────────────────────────────┤
│  Section Table (섹션 헤더 배열)      │
├─────────────────────────────────────┤
│  .text  섹션 (코드)                  │ ← 실행 코드
│  .data  섹션 (초기화 데이터)         │ ← 전역 변수
│  .rdata 섹션 (읽기 전용 데이터)      │ ← 문자열 상수, Import 정보
│  .bss   섹션 (비초기화 데이터)       │ ← 초기화 안 된 전역 변수
│  .rsrc  섹션 (리소스)               │ ← 아이콘, 다이얼로그
│  .reloc 섹션 (재배치 정보)           │
└─────────────────────────────────────┘
```

### MZ 헤더 (DOS Header)

PE 파일은 `MZ`(0x4D5A) 시그니처로 시작하는 DOS 헤더로 시작합니다. `e_lfanew` 필드가 실제 PE 헤더의 파일 오프셋을 가리키며, 악성코드 분석 시 헥스 에디터로 이 구조를 확인하는 것이 첫 단계입니다.

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;    // "MZ" = 0x4D5A (Mark Zbikowski)
    WORD  e_cblp;
    // ... (여러 필드)
    LONG  e_lfanew;   // PE Header의 파일 오프셋 (중요!)
} IMAGE_DOS_HEADER;
```
```
파일 헥스덤프 확인:
Offset 0x00: 4D 5A 90 00 03 00 ...  → MZ (실행 파일 시그니처)
Offset 0x3C: XX XX XX XX            → e_lfanew (PE Header 위치)
```

---

## 2. 가상 주소 공간 (Virtual Address Space)

### Windows 프로세스 메모리 레이아웃 (32비트)
```
0xFFFFFFFF ────────────────────────────────
           │ 커널 영역 (2GB, Ring 0 전용)   │
0x80000000 ────────────────────────────────
           │                               │
           │ 사용자 영역 (2GB)              │
           │                               │
           │ Stack (하향 성장)              │
           │    ↓                          │
           │                               │
           │    ↑                          │
           │ Heap (상향 성장)               │
           │                               │
           │ .bss / .data / .rdata / .text │
           │ (프로그램 이미지)              │
           │                               │
0x00010000 │ (최하위 사용 가능 영역)        │
0x00000000 ────────────────────────────────
```

### ImageBase (이미지 기준 주소)
```
.exe의 기본 ImageBase: 0x00400000
.dll의 기본 ImageBase: 0x10000000

ImageBase + RVA = VA (Virtual Address)
RVA: 파일 내부의 상대 주소
VA:  실제 메모리 주소

예시:
ImageBase = 0x00400000
RVA = 0x00001000 (EntryPoint)
VA  = 0x00401000 (실제 시작 주소)
```

---

## 3. Import Table (IAT) — 악성코드 분석 핵심

### Import Address Table이란?
프로그램이 사용하는 외부 DLL 함수 목록.
악성코드 분석에서 IAT를 보면 프로그램의 의도를 파악 가능.

### IAT에서 알 수 있는 것들
```
악성코드 의심 API 목록:

[네트워크]
- WSAStartup, WSAConnect, send, recv
- InternetOpen, InternetConnect
- URLDownloadToFile

[파일 시스템]
- CreateFile, WriteFile, ReadFile
- CopyFile, DeleteFile
- FindFirstFile (파일 탐색)

[프로세스/코드 인젝션]
- CreateProcess, OpenProcess
- VirtualAllocEx, WriteProcessMemory
- CreateRemoteThread

[레지스트리 (지속성 유지)]
- RegOpenKey, RegSetValue
- RegCreateKey

[안티 분석]
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- QueryPerformanceCounter (타이밍 체크)

[암호화]
- CryptEncrypt, CryptDecrypt
- CryptGenKey
```

### IAT 확인 도구

`dumpbin`(Windows) 또는 `objdump`(Linux)로 PE 파일의 임포트/익스포트 테이블, 섹션 정보, 헤더 상세를 출력합니다. 임포트 함수 목록만 봐도 악성코드의 주요 기능을 빠르게 파악할 수 있습니다.

```bash
# Windows에서 (Visual Studio 빌드 도구)
dumpbin /imports malware.exe

# Linux에서 (GNU binutils)
objdump -x binary | grep -A5 "Import"
readelf -d binary | grep NEEDED
```

```python
#!/usr/bin/env python3
"""
pefile + hashlib을 이용한 PE 파일 종합 분석기
사용법: python3 pe_analyzer.py <PE파일> [--virustotal]
"""
import sys
import hashlib
import argparse
import math
import struct
from pathlib import Path

try:
    import pefile
except ImportError:
    print("pip install pefile")
    sys.exit(1)

SUSPICIOUS_APIS: dict[str, list[str]] = {
    "네트워크":    ["WSAStartup", "WSAConnect", "connect", "send", "recv",
                  "URLDownloadToFile", "InternetOpenA", "InternetConnectA",
                  "HttpOpenRequestA", "HttpSendRequestA"],
    "코드인젝션":  ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                  "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
                  "RtlCreateUserThread"],
    "지속성":      ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                  "CreateServiceA", "StartServiceA", "SHFileOperationA"],
    "안티분석":    ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                  "NtQueryInformationProcess", "FindWindowA", "GetTickCount",
                  "QueryPerformanceCounter", "OutputDebugStringA"],
    "자격증명/암호": ["CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
                   "CryptDeriveKey", "BCryptEncrypt"],
    "파일은닉":    ["NtSetInformationFile", "SetFileAttributesA",
                  "MoveFileExA", "CopyFileA"],
}


def entropy(data: bytes) -> float:
    """섀넌 엔트로피 계산 (7.0 이상이면 패킹/암호화 의심)"""
    if not data:
        return 0.0
    freq = [data.count(bytes([b])) / len(data) for b in range(256)]
    return -sum(p * math.log2(p) for p in freq if p > 0)


def file_hashes(path: str) -> dict[str, str]:
    data = Path(path).read_bytes()
    return {
        "MD5":    hashlib.md5(data).hexdigest(),
        "SHA1":   hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "Size":   f"{len(data):,} bytes",
    }


def analyze_pe(path: str) -> None:
    print(f"\n{'='*60}")
    print(f"[*] PE 분석: {path}")
    print(f"{'='*60}")

    # 해시 출력
    hashes = file_hashes(path)
    print("\n[해시]")
    for k, v in hashes.items():
        print(f"  {k:<8}: {v}")

    pe = pefile.PE(path)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    # 기본 헤더 정보
    machine_map = {0x014C: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)",
                   0x01C4: "ARM Thumb-2", 0xAA64: "ARM64"}
    print("\n[PE 헤더]")
    print(f"  Machine:         {machine_map.get(fh.Machine, hex(fh.Machine))}")
    print(f"  NumberOfSections:{fh.NumberOfSections}")
    print(f"  TimeDateStamp:   {fh.dump_dict()['TimeDateStamp']['Value']}")
    print(f"  EntryPoint (RVA):{hex(oh.AddressOfEntryPoint)}")
    print(f"  ImageBase:       {hex(oh.ImageBase)}")
    print(f"  ImageSize:       {oh.SizeOfImage:,} bytes")
    magic_str = "PE32+" if oh.Magic == 0x20B else "PE32"
    print(f"  Magic:           {magic_str}")

    # 섹션 분석
    print("\n[섹션 엔트로피]")
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        data = sec.get_data()
        ent = entropy(data)
        flag = " ← 패킹/암호화 의심!" if ent > 7.0 else ""
        print(f"  {name:<10} VA:{hex(sec.VirtualAddress)}  "
              f"크기:{sec.SizeOfRawData:>8,}  엔트로피:{ent:.2f}{flag}")

    # IAT 분석 + 의심 API 탐지
    found: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("\n[임포트 DLL]")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            funcs = [
                imp.name.decode(errors="replace")
                for imp in entry.imports
                if imp.name
            ]
            print(f"  {dll}  ({len(funcs)}개 함수)")
            for func in funcs:
                for cat, apis in SUSPICIOUS_APIS.items():
                    if func in apis:
                        found.setdefault(cat, []).append(f"{dll}!{func}")

    if found:
        print("\n[!] 의심 API 탐지:")
        for cat, apis in found.items():
            print(f"  [{cat}]")
            for api in apis:
                print(f"    - {api}")
    else:
        print("\n[+] 의심 API 없음")

    # 익스포트 확인 (DLL 분석 시)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
        print(f"\n[익스포트] {len(exports)}개")
        for sym in exports[:10]:
            name = sym.name.decode(errors="replace") if sym.name else f"ord_{sym.ordinal}"
            print(f"  {name}")
        if len(exports) > 10:
            print(f"  ... 외 {len(exports)-10}개")

    pe.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="PE 파일 종합 분석기")
    parser.add_argument("pe_file", help="분석할 PE 파일 경로")
    args = parser.parse_args()

    if not Path(args.pe_file).exists():
        print(f"[-] 파일 없음: {args.pe_file}")
        sys.exit(1)
    analyze_pe(args.pe_file)


if __name__ == "__main__":
    main()
```

---

## 4. DLL (Dynamic Link Library)

### 명시적 로딩 vs 암시적 로딩
```c
// 암시적 로딩 (컴파일 시 자동 링크)
#include <windows.h>
MessageBox(NULL, "Hello", "Title", MB_OK);

// 명시적 로딩 (실행 중 동적 로드 - 분석 어려움)
HMODULE hModule = LoadLibrary("user32.dll");
typedef int (WINAPI *pMessageBox)(HWND, LPCSTR, LPCSTR, UINT);
pMessageBox pMB = (pMessageBox)GetProcAddress(hModule, "MessageBoxA");
pMB(NULL, "Hello", "Title", MB_OK);
```

### PE 공유 메모리 (DLL 공유)
```
여러 프로세스가 동일 DLL 사용 시:
- 코드(.text) 섹션: 물리 메모리 공유 (읽기 전용)
- 데이터(.data) 섹션: 프로세스별 별도 복사본 (Copy-on-Write)

장점: 메모리 절약
```

### Memory Mapped File (MMF)

Memory Mapped File(MMF)로 파일을 메모리에 직접 매핑합니다. PE 분석 도구에서 파일을 효율적으로 읽고 수정하는 데 사용합니다.

```c
// 파일을 메모리에 직접 매핑
HANDLE hFile = CreateFile("data.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID lpView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// 이제 lpView로 파일 내용에 직접 접근
// 대용량 파일 처리, PE 분석 도구에서 많이 사용
```

---

## 5. 프로세스와 스레드 구조

### Windows 프로세스 생성 흐름
```
사용자가 .exe 실행
    ↓
Windows Loader가 PE 파싱
    ↓
메모리에 섹션 매핑 (ImageBase 기준)
    ↓
Import Table 처리 (필요한 DLL 로드)
    ↓
재배치 처리 (필요시, ASLR 때문)
    ↓
TLS 콜백 실행 (있을 경우)
    ↓
AddressOfEntryPoint에서 실행 시작
    ↓
CRT 초기화 → main() 또는 WinMain()
```

### 프로세스 내부 구조
```
PEB (Process Environment Block):
- 프로세스 관련 정보 저장
- DLL 목록, 커맨드 라인, 환경 변수 등
- 디버거 탐지에 활용 됨 (IsDebugged 필드)

TEB (Thread Environment Block):
- 스레드별 정보 저장
- FS:[18h] = TEB 자기 참조
- FS:[0h]  = SEH 체인 (예외 처리)
```

---

## 6. Windows 파일시스템 구조 분석

### NTFS 주요 특성
```
MFT (Master File Table):
- 모든 파일/폴더의 메타데이터 저장
- 각 항목은 MFT 레코드 (1KB)
- 파일명, 크기, 타임스탬프, 데이터 위치

타임스탬프 (MACE):
- M: Modified (수정 시간)
- A: Accessed (접근 시간)
- C: Changed (MFT 변경 시간, 이동/이름변경 포함)
- E: Entry Modified (MFT 항목 변경)

포렌식 중요성:
- 타임스탬프 조작 탐지 (Timestomping)
- 삭제된 파일 복구 (MFT 항목이 남아있을 경우)
- 파일 접근 이력 추적
```

### NTFS 데이터 스트림 (ADS)

NTFS의 대체 데이터 스트림(ADS)으로 파일 안에 파일을 숨깁니다. 악성코드가 탐지를 피하기 위해 ADS에 페이로드를 숨기는 기법입니다.

```bash
# ADS (Alternate Data Stream) — 파일 숨기기 기법
# 정상 파일에 숨겨진 데이터 첨부 가능

# Windows에서 ADS 생성
echo "hidden data" > visible.txt:hidden_stream

# ADS 내용 읽기
more < visible.txt:hidden_stream

# ADS 탐지
dir /r  # /r 옵션으로 ADS 표시
streams.exe visible.txt  # Sysinternals 도구

# 악성코드가 ADS에 숨는 경우:
# 정상 파일:숨겨진_실행파일 형태로 은닉
```

### FAT32 구조
```
FAT32 영역 구성:
1. 예약 영역 (Boot Sector 포함)
2. FAT 테이블 영역 (파일 클러스터 연결 정보)
3. 루트 디렉토리 영역
4. 데이터 영역

FAT 테이블 값:
- 0x00000000: 빈 클러스터 (사용 가능)
- 0x0FFFFFF8 이상: 파일 끝 (EOF)
- 기타 값: 다음 클러스터 번호

삭제된 파일 복구:
- FAT 항목이 0으로 초기화되어도 데이터는 남아있음
- 디렉토리 항목의 첫 글자가 0xE5로 변경됨
- 데이터가 덮어쓰이기 전까지 복구 가능
```

---

## 7. Windows 레지스트리

### 주요 레지스트리 하이브
```
HKEY_LOCAL_MACHINE (HKLM):
- 시스템 전체 설정
- HKLM\SOFTWARE: 설치된 소프트웨어
- HKLM\SYSTEM: 시스템 설정, 드라이버

HKEY_CURRENT_USER (HKCU):
- 현재 로그인 사용자 설정

HKEY_CLASSES_ROOT (HKCR):
- 파일 연결 정보, COM 클래스

HKEY_USERS (HKU):
- 모든 사용자 프로필

주요 경로 (악성코드 분석/포렌식):
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    ← 시작 프로그램 (지속성)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    ← 사용자별 시작 프로그램
HKLM\SYSTEM\CurrentControlSet\Services               ← 서비스 (악성 서비스)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon ← 로그온 설정
```

### 레지스트리 파일 위치 (SAM/SYSTEM)
```
C:\Windows\System32\config\
├── SAM      ← 로컬 계정 해시 (로그인 크래킹 대상)
├── SYSTEM   ← 부팅 키 (SAM 복호화에 필요)
├── SOFTWARE ← 소프트웨어 설정
├── SECURITY ← 보안 정책
└── DEFAULT  ← 기본 사용자 설정
```

### 포렌식 관점 레지스트리 분석

Windows 레지스트리를 포렌식 관점에서 분석합니다. 소프트웨어 설치 기록, 자동 실행 항목, 사용자 활동 흔적을 확인합니다.

```bash
# Windows 내에서
regedit.exe       # GUI 레지스터 편집기
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Linux에서 오프라인 분석 (reglookup, hivex)
apt-get install libhivex-bin
hivexls SAM
hivexregedit SAM  # 레지스트리 탐색
```

---

## 8. PE 가상 주소 공간 (VAS) 심화

### 가상 주소 공간 개요

VA(Virtual Address)는 프로세스 메모리에서의 절대 주소이며, RVA(Relative Virtual Address)는 ImageBase를 기준으로 한 상대 주소입니다. ASLR 환경에서는 ImageBase가 실행마다 달라지므로 RVA 기반으로 분석해야 합니다.

```
VAS (Virtual Address Space):
- 각 프로세스는 독립된 4GB 가상 주소 공간을 갖는다
- 실제 물리 메모리와 별개로, OS가 가상→물리 매핑을 관리
- 프로세스 간 메모리 격리 → 한 프로세스 버그가 다른 프로세스에 영향 없음

32비트 Windows 분할:
  0x00000000 ~ 0x7FFFFFFF : 사용자 공간 (2GB)
  0x80000000 ~ 0xFFFFFFFF : 커널 공간 (2GB, Ring 0 전용)
```

### RVA / VA / 파일 오프셋 변환
```
핵심 주소 개념:
  VA  (Virtual Address)    : 실제 메모리에 로드된 후의 주소
  RVA (Relative VA)        : ImageBase를 기준으로 한 상대 주소
  File Offset              : 파일 내 물리적 위치 (디스크에서)

변환 공식:
  VA = ImageBase + RVA
  File Offset = RVA - VirtualAddress(섹션) + PointerToRawData(섹션)

예시:
  ImageBase = 0x00400000
  .text 섹션 VirtualAddress = 0x1000
  .text 섹션 PointerToRawData = 0x400

  VA  0x00401234 → RVA = 0x1234
  File Offset = 0x1234 - 0x1000 + 0x400 = 0x634
```

---

## 9. PE 공유 메모리와 DLL 메모리 구조

### 여러 프로세스의 DLL 공유 방식
```
프로세스 A           프로세스 B
  ┌─────────┐          ┌─────────┐
  │VAS (2GB)│          │VAS (2GB)│
  │         │          │         │
  │user32.dll─────────→│user32.dll (동일 물리 페이지)
  │ .text   │  공유     │ .text   │ ← 코드는 공유 (읽기 전용)
  │ .data   │ 별도      │ .data   │ ← 데이터는 각자 복사본 (CoW)
  └─────────┘          └─────────┘

Copy-on-Write (CoW):
- 데이터 섹션은 처음에 동일 물리 페이지를 참조
- 한 프로세스가 쓰기를 시도하면 해당 페이지만 복사 후 수정
- 메모리 절약 + 프로세스 격리 동시 달성
```

### Memory Mapped File (MMF) 분석 활용
```c
// PE 분석 도구에서 MMF를 사용하는 이유:
// - 파일 전체를 메모리에 로드하지 않아도 대용량 파일 처리 가능
// - OS의 페이지 캐시를 이용하므로 효율적

HANDLE hFile = CreateFile("target.exe", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID base  = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// base 포인터로 PE 헤더 직접 파싱
PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)base;
PIMAGE_NT_HEADERS ntHdr  = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHdr->e_lfanew);
```

```python
#!/usr/bin/env python3
"""
RVA ↔ File Offset ↔ VA 주소 변환 계산기
사용법: python3 rva_calc.py <PE파일> <주소> [--type rva|va|offset]
"""
import sys
import argparse
import pefile


def rva_to_offset(pe: pefile.PE, rva: int) -> int | None:
    for sec in pe.sections:
        start = sec.VirtualAddress
        end   = start + sec.Misc_VirtualSize
        if start <= rva < end:
            return rva - start + sec.PointerToRawData
    return None


def offset_to_rva(pe: pefile.PE, offset: int) -> int | None:
    for sec in pe.sections:
        start = sec.PointerToRawData
        end   = start + sec.SizeOfRawData
        if start <= offset < end:
            return offset - start + sec.VirtualAddress
    return None


def convert_address(path: str, addr: int, addr_type: str) -> None:
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase

    if addr_type == "va":
        rva    = addr - base
        offset = rva_to_offset(pe, rva)
        print(f"VA     = {hex(addr)}")
        print(f"RVA    = {hex(rva)}")
        print(f"Offset = {hex(offset) if offset is not None else 'N/A (헤더 영역)'}")

    elif addr_type == "rva":
        va     = addr + base
        offset = rva_to_offset(pe, addr)
        print(f"RVA    = {hex(addr)}")
        print(f"VA     = {hex(va)}")
        print(f"Offset = {hex(offset) if offset is not None else 'N/A (헤더 영역)'}")

    elif addr_type == "offset":
        rva = offset_to_rva(pe, addr)
        va  = (rva + base) if rva is not None else None
        print(f"Offset = {hex(addr)}")
        print(f"RVA    = {hex(rva) if rva is not None else 'N/A'}")
        print(f"VA     = {hex(va) if va is not None else 'N/A'}")

    # 어느 섹션에 속하는지 표시
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        rva_check = addr - base if addr_type == "va" else addr
        if addr_type == "offset":
            rva_check = offset_to_rva(pe, addr) or 0
        if sec.VirtualAddress <= rva_check < sec.VirtualAddress + sec.Misc_VirtualSize:
            print(f"\n섹션: {name}  "
                  f"VA:[{hex(base+sec.VirtualAddress)}~{hex(base+sec.VirtualAddress+sec.Misc_VirtualSize)}]  "
                  f"Raw:[{hex(sec.PointerToRawData)}~{hex(sec.PointerToRawData+sec.SizeOfRawData)}]")
            break

    pe.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="PE 주소 변환기")
    parser.add_argument("pe_file", help="PE 파일 경로")
    parser.add_argument("address", help="변환할 주소 (0x 접두어 지원)")
    parser.add_argument("--type", choices=["rva", "va", "offset"],
                        default="va", help="주소 타입 (기본: va)")
    args = parser.parse_args()

    addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address, 0)
    convert_address(args.pe_file, addr, args.type)


if __name__ == "__main__":
    main()
```

---

## 10. DLL 명시적/암시적 로딩 상세

### 암시적 로딩 (Implicit Loading)
```
- 컴파일 시 import library(.lib)를 링크
- 프로그램 시작 시 Windows Loader가 자동으로 DLL 로드
- IAT(Import Address Table)에 함수 주소 채워짐
- 분석 용이: dumpbin /imports로 바로 확인 가능
```

### 명시적 로딩 (Explicit Loading)

런타임에 LoadLibrary/GetProcAddress로 DLL을 동적으로 로드합니다. 악성코드가 정적 분석을 어렵게 만들기 위해 자주 사용하는 기법입니다.

```c
// 실행 중 동적으로 DLL 로드 — 분석을 어렵게 만드는 기법
HMODULE hDll = LoadLibrary("악성DLL.dll");
if (hDll) {
    // 문자열을 동적으로 구성하여 GetProcAddress 호출
    char funcName[] = {'C','r','e','a','t','e','\0'};
    FARPROC func = GetProcAddress(hDll, funcName);
    if (func) func(...);
    FreeLibrary(hDll);
}

// 악성코드는 LoadLibrary + GetProcAddress 패턴을 자주 사용
// OllyDbg에서: LoadLibrary / GetProcAddress에 BP 설정하면 탐지 가능
```

OllyDbg에서 동적 DLL 로딩 패턴을 탐지합니다. LoadLibraryA/GetProcAddress 호출 시 브레이크포인트를 설정하여 로드되는 DLL을 파악합니다.

```asm
; OllyDbg에서 동적 로딩 탐지
; CALL DWORD PTR [<&KERNEL32.LoadLibraryA>]  에 BP → 로드되는 DLL 확인
; CALL DWORD PTR [<&KERNEL32.GetProcAddress>] 에 BP → 로드하는 함수명 확인
; 스택 창에서 인자(DLL명, 함수명) 확인
```

---

## 11. Tiny PE — 최소 크기 PE 파일

### PE 파일 크기 최적화 원리
PE 파일 스펙의 많은 필드는 0이어도 동작한다.
불필요한 헤더 필드를 제거하고 섹션들을 겹치게 배치하면
극단적으로 작은 실행 파일을 만들 수 있다.

```
일반적인 최소화 과정:
45056byte (정상 .exe)
→ 1024byte (불필요 섹션 제거)
→  486byte (헤더 일부 겹치기)
→  356byte (섹션 헤더 최소화)
→  296byte (Optional Header 축소)
→  168byte (DOS Stub 제거)
→   97byte (현재 알려진 최소 PE)

97byte PE 구조:
- DOS Header 크기 축소 (e_lfanew 직후 PE 시작)
- PE Header와 코드 섹션 겹치기
- 섹션 정렬 무시 (SectionAlignment = FileAlignment = 4)
```

### PE 분석 시 확인 포인트
```
헥스 에디터로 확인해야 할 오프셋:
  0x00: 4D 5A           → MZ 시그니처
  0x3C: [4바이트]        → PE 헤더 오프셋 (e_lfanew)
  [e_lfanew+0]: 50 45 00 00 → PE 시그니처
  [e_lfanew+4]: [2바이트] → Machine (0x014C = x86, 0x8664 = x64)
  [e_lfanew+6]: [2바이트] → NumberOfSections (섹션 수)
  [Optional+16]: [4바이트] → AddressOfEntryPoint (진입점 RVA)
  [Optional+28]: [4바이트] → ImageBase
```

---

## 12. EXT2 (Linux) vs NTFS vs FAT32 비교

| 특성 | FAT32 | NTFS | EXT2 |
|------|-------|------|------|
| OS | Windows 9x, USB | Windows XP+ | Linux |
| 최대 파일 크기 | 4GB | 16TB+ | 2TB |
| 저널링 | 없음 | 있음 | 없음 (EXT3부터) |
| 권한 관리 | 없음 | ACL 지원 | Unix 권한 |
| 포렌식 복구 | FAT 테이블로 추적 | MFT 항목 분석 | inode 분석 |

### EXT2 (Linux) 파일시스템 구조
```
EXT2 레이아웃:
  ┌──────────────┬──────────────┬──────────────┬───────────┐
  │ Boot Block   │ Block Group 0│ Block Group 1 │    ...    │
  └──────────────┴──────────────┴──────────────┴───────────┘

Block Group 내부:
  ┌────────────┬────────────┬──────────┬──────────┬────────────┐
  │ Superblock │ Group Desc │ Block    │ Inode    │ Data       │
  │            │ Table      │ Bitmap   │ Bitmap   │ Blocks     │
  └────────────┴────────────┴──────────┴──────────┴────────────┘

Inode:
  - 파일의 메타데이터 저장 (권한, 크기, 타임스탬프, 데이터 블록 포인터)
  - 파일명은 inode에 없음 → 디렉토리 항목(dentry)에 저장
  - 삭제 시: inode가 초기화됨, 데이터 블록은 남아있을 수 있음 (복구 가능)

포렌식 관점:
  - inode 타임스탬프: atime (접근), mtime (수정), ctime (변경)
  - 'debugfs' 도구로 삭제된 inode 확인 가능
  - 저널링 없으므로 삭제 후 데이터 복구 확률이 NTFS보다 높음
```

---

<a name="english"></a>

# PE Structure & Windows Internals

## 1. PE (Portable Executable) File Structure

### What is a PE File?
The file format for Windows executables (.exe, .dll, .sys, etc.).
The core subject to understand for reverse engineering and malware analysis.

### PE File Header Structure
```
┌─────────────────────────────────────┐
│  DOS Header (64 bytes)              │ ← MZ signature (0x4D5A)
│  DOS Stub                           │ ← "This program cannot run in DOS"
├─────────────────────────────────────┤
│  PE Header (Signature: "PE\0\0")    │ ← 0x00004550
│  ├── File Header (COFF Header)      │
│  │   ├── Machine (CPU type)         │
│  │   ├── NumberOfSections           │
│  │   ├── TimeDateStamp (compile time)│
│  │   └── Characteristics           │
│  └── Optional Header               │
│       ├── Magic (PE32/PE32+)        │
│       ├── AddressOfEntryPoint       │ ← Program entry address
│       ├── ImageBase                 │ ← Memory load base address
│       ├── SectionAlignment          │
│       ├── FileAlignment             │
│       └── DataDirectory[16]         │ ← Import, Export, etc.
├─────────────────────────────────────┤
│  Section Table (section header array)│
├─────────────────────────────────────┤
│  .text  section (code)              │ ← Executable code
│  .data  section (initialized data)  │ ← Global variables
│  .rdata section (read-only data)    │ ← String constants, Import info
│  .bss   section (uninitialized data)│ ← Uninitialized global variables
│  .rsrc  section (resources)         │ ← Icons, dialogs
│  .reloc section (relocation info)   │
└─────────────────────────────────────┘
```

### MZ Header (DOS Header)

A PE file starts with a DOS header beginning with the `MZ` (0x4D5A) signature. The `e_lfanew` field points to the file offset of the actual PE header. Checking this structure with a hex editor is the first step in malware analysis.

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;    // "MZ" = 0x4D5A (Mark Zbikowski)
    WORD  e_cblp;
    // ... (various fields)
    LONG  e_lfanew;   // File offset of PE Header (important!)
} IMAGE_DOS_HEADER;
```
```
File hex dump check:
Offset 0x00: 4D 5A 90 00 03 00 ...  → MZ (executable signature)
Offset 0x3C: XX XX XX XX            → e_lfanew (PE Header location)
```

---

## 2. Virtual Address Space (VAS)

### Windows Process Memory Layout (32-bit)
```
0xFFFFFFFF ────────────────────────────────
           │ Kernel space (2GB, Ring 0 only) │
0x80000000 ────────────────────────────────
           │                               │
           │ User space (2GB)              │
           │                               │
           │ Stack (grows downward)        │
           │    ↓                          │
           │                               │
           │    ↑                          │
           │ Heap (grows upward)           │
           │                               │
           │ .bss / .data / .rdata / .text │
           │ (program image)               │
           │                               │
0x00010000 │ (lowest usable region)        │
0x00000000 ────────────────────────────────
```

### ImageBase (Image Base Address)
```
Default ImageBase for .exe: 0x00400000
Default ImageBase for .dll: 0x10000000

ImageBase + RVA = VA (Virtual Address)
RVA: Relative address within the file
VA:  Actual memory address

Example:
ImageBase = 0x00400000
RVA = 0x00001000 (EntryPoint)
VA  = 0x00401000 (actual start address)
```

---

## 3. Import Table (IAT) — Core of Malware Analysis

### What is the Import Address Table?
The list of external DLL functions used by the program.
In malware analysis, examining the IAT reveals the program's intent.

### What Can Be Learned from the IAT
```
Suspicious API list for malware:

[Network]
- WSAStartup, WSAConnect, send, recv
- InternetOpen, InternetConnect
- URLDownloadToFile

[File System]
- CreateFile, WriteFile, ReadFile
- CopyFile, DeleteFile
- FindFirstFile (file search)

[Process / Code Injection]
- CreateProcess, OpenProcess
- VirtualAllocEx, WriteProcessMemory
- CreateRemoteThread

[Registry (Persistence)]
- RegOpenKey, RegSetValue
- RegCreateKey

[Anti-Analysis]
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- QueryPerformanceCounter (timing check)

[Encryption]
- CryptEncrypt, CryptDecrypt
- CryptGenKey
```

### IAT Inspection Tools

Use `dumpbin` (Windows) or `objdump` (Linux) to print a PE file's import/export tables, section info, and header details. Reviewing just the list of imported functions gives a quick grasp of a malware sample's main capabilities.

```bash
# On Windows (Visual Studio build tools)
dumpbin /imports malware.exe

# On Linux (GNU binutils)
objdump -x binary | grep -A5 "Import"
readelf -d binary | grep NEEDED
```

```python
#!/usr/bin/env python3
"""
Comprehensive PE file analyzer using pefile + hashlib
Usage: python3 pe_analyzer.py <PE_file> [--virustotal]
"""
import sys
import hashlib
import argparse
import math
import struct
from pathlib import Path

try:
    import pefile
except ImportError:
    print("pip install pefile")
    sys.exit(1)

SUSPICIOUS_APIS: dict[str, list[str]] = {
    "Network":       ["WSAStartup", "WSAConnect", "connect", "send", "recv",
                      "URLDownloadToFile", "InternetOpenA", "InternetConnectA",
                      "HttpOpenRequestA", "HttpSendRequestA"],
    "CodeInjection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                      "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
                      "RtlCreateUserThread"],
    "Persistence":   ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                      "CreateServiceA", "StartServiceA", "SHFileOperationA"],
    "AntiAnalysis":  ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                      "NtQueryInformationProcess", "FindWindowA", "GetTickCount",
                      "QueryPerformanceCounter", "OutputDebugStringA"],
    "Crypto":        ["CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
                      "CryptDeriveKey", "BCryptEncrypt"],
    "FileHiding":    ["NtSetInformationFile", "SetFileAttributesA",
                      "MoveFileExA", "CopyFileA"],
}


def entropy(data: bytes) -> float:
    """Shannon entropy (>7.0 suggests packing/encryption)"""
    if not data:
        return 0.0
    freq = [data.count(bytes([b])) / len(data) for b in range(256)]
    return -sum(p * math.log2(p) for p in freq if p > 0)


def file_hashes(path: str) -> dict[str, str]:
    data = Path(path).read_bytes()
    return {
        "MD5":    hashlib.md5(data).hexdigest(),
        "SHA1":   hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "Size":   f"{len(data):,} bytes",
    }


def analyze_pe(path: str) -> None:
    print(f"\n{'='*60}")
    print(f"[*] PE Analysis: {path}")
    print(f"{'='*60}")

    # Print hashes
    hashes = file_hashes(path)
    print("\n[Hashes]")
    for k, v in hashes.items():
        print(f"  {k:<8}: {v}")

    pe = pefile.PE(path)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    # Basic header info
    machine_map = {0x014C: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)",
                   0x01C4: "ARM Thumb-2", 0xAA64: "ARM64"}
    print("\n[PE Header]")
    print(f"  Machine:         {machine_map.get(fh.Machine, hex(fh.Machine))}")
    print(f"  NumberOfSections:{fh.NumberOfSections}")
    print(f"  TimeDateStamp:   {fh.dump_dict()['TimeDateStamp']['Value']}")
    print(f"  EntryPoint (RVA):{hex(oh.AddressOfEntryPoint)}")
    print(f"  ImageBase:       {hex(oh.ImageBase)}")
    print(f"  ImageSize:       {oh.SizeOfImage:,} bytes")
    magic_str = "PE32+" if oh.Magic == 0x20B else "PE32"
    print(f"  Magic:           {magic_str}")

    # Section analysis
    print("\n[Section Entropy]")
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        data = sec.get_data()
        ent = entropy(data)
        flag = " ← Packing/encryption suspected!" if ent > 7.0 else ""
        print(f"  {name:<10} VA:{hex(sec.VirtualAddress)}  "
              f"Size:{sec.SizeOfRawData:>8,}  Entropy:{ent:.2f}{flag}")

    # IAT analysis + suspicious API detection
    found: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("\n[Imported DLLs]")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")
            funcs = [
                imp.name.decode(errors="replace")
                for imp in entry.imports
                if imp.name
            ]
            print(f"  {dll}  ({len(funcs)} functions)")
            for func in funcs:
                for cat, apis in SUSPICIOUS_APIS.items():
                    if func in apis:
                        found.setdefault(cat, []).append(f"{dll}!{func}")

    if found:
        print("\n[!] Suspicious APIs detected:")
        for cat, apis in found.items():
            print(f"  [{cat}]")
            for api in apis:
                print(f"    - {api}")
    else:
        print("\n[+] No suspicious APIs found")

    # Export check (for DLL analysis)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
        print(f"\n[Exports] {len(exports)} entries")
        for sym in exports[:10]:
            name = sym.name.decode(errors="replace") if sym.name else f"ord_{sym.ordinal}"
            print(f"  {name}")
        if len(exports) > 10:
            print(f"  ... and {len(exports)-10} more")

    pe.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Comprehensive PE file analyzer")
    parser.add_argument("pe_file", help="Path to PE file")
    args = parser.parse_args()

    if not Path(args.pe_file).exists():
        print(f"[-] File not found: {args.pe_file}")
        sys.exit(1)
    analyze_pe(args.pe_file)


if __name__ == "__main__":
    main()
```

---

## 4. DLL (Dynamic Link Library)

### Explicit vs. Implicit Loading
```c
// Implicit loading (linked automatically at compile time)
#include <windows.h>
MessageBox(NULL, "Hello", "Title", MB_OK);

// Explicit loading (dynamically loaded at runtime — harder to analyze)
HMODULE hModule = LoadLibrary("user32.dll");
typedef int (WINAPI *pMessageBox)(HWND, LPCSTR, LPCSTR, UINT);
pMessageBox pMB = (pMessageBox)GetProcAddress(hModule, "MessageBoxA");
pMB(NULL, "Hello", "Title", MB_OK);
```

### PE Shared Memory (DLL Sharing)
```
When multiple processes use the same DLL:
- Code (.text) section: shared physical memory (read-only)
- Data (.data) section: per-process separate copy (Copy-on-Write)

Benefit: memory savings
```

### Memory Mapped File (MMF)

Memory Mapped File (MMF) maps a file directly into memory. Used by PE analysis tools to efficiently read and modify files.

```c
// Map a file directly into memory
HANDLE hFile = CreateFile("data.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID lpView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// Now access file content directly via lpView
// Widely used in PE analysis tools for large file processing
```

---

## 5. Process and Thread Structure

### Windows Process Creation Flow
```
User runs .exe
    ↓
Windows Loader parses PE
    ↓
Maps sections into memory (based on ImageBase)
    ↓
Processes Import Table (loads required DLLs)
    ↓
Handles relocations (if needed, due to ASLR)
    ↓
Executes TLS callbacks (if any)
    ↓
Starts execution at AddressOfEntryPoint
    ↓
CRT initialization → main() or WinMain()
```

### Process Internal Structure
```
PEB (Process Environment Block):
- Stores process-related information
- DLL list, command line, environment variables, etc.
- Used for debugger detection (IsDebugged field)

TEB (Thread Environment Block):
- Stores per-thread information
- FS:[18h] = TEB self-reference
- FS:[0h]  = SEH chain (exception handling)
```

---

## 6. Windows Filesystem Structure Analysis

### Key NTFS Characteristics
```
MFT (Master File Table):
- Stores metadata for all files/folders
- Each entry is an MFT record (1KB)
- Filename, size, timestamps, data location

Timestamps (MACE):
- M: Modified (last write time)
- A: Accessed (last access time)
- C: Changed (MFT change time, includes move/rename)
- E: Entry Modified (MFT entry change)

Forensic importance:
- Detecting timestamp tampering (Timestomping)
- Recovering deleted files (if MFT entry remains)
- Tracking file access history
```

### NTFS Data Streams (ADS)

NTFS Alternate Data Streams (ADS) allow hiding data within files. Malware uses ADS to hide payloads and evade detection.

```bash
# ADS (Alternate Data Stream) — file hiding technique
# Hidden data can be attached to normal files

# Create ADS on Windows
echo "hidden data" > visible.txt:hidden_stream

# Read ADS content
more < visible.txt:hidden_stream

# Detect ADS
dir /r  # /r option shows ADS
streams.exe visible.txt  # Sysinternals tool

# When malware hides in ADS:
# Concealed as normal_file:hidden_executable
```

### FAT32 Structure
```
FAT32 Area Layout:
1. Reserved area (including Boot Sector)
2. FAT table area (file cluster chain info)
3. Root directory area
4. Data area

FAT table values:
- 0x00000000: Empty cluster (available)
- 0x0FFFFFF8 or higher: End of file (EOF)
- Other values: Next cluster number

Recovering deleted files:
- Even after FAT entry is zeroed, data remains
- First character of directory entry changes to 0xE5
- Recoverable until data is overwritten
```

---

## 7. Windows Registry

### Key Registry Hives
```
HKEY_LOCAL_MACHINE (HKLM):
- System-wide settings
- HKLM\SOFTWARE: Installed software
- HKLM\SYSTEM: System settings, drivers

HKEY_CURRENT_USER (HKCU):
- Settings for the currently logged-in user

HKEY_CLASSES_ROOT (HKCR):
- File associations, COM classes

HKEY_USERS (HKU):
- All user profiles

Key paths (for malware analysis / forensics):
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    ← Startup programs (persistence)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    ← Per-user startup programs
HKLM\SYSTEM\CurrentControlSet\Services               ← Services (malicious services)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon ← Logon settings
```

### Registry File Locations (SAM/SYSTEM)
```
C:\Windows\System32\config\
├── SAM      ← Local account hashes (target for cracking)
├── SYSTEM   ← Boot key (needed to decrypt SAM)
├── SOFTWARE ← Software settings
├── SECURITY ← Security policies
└── DEFAULT  ← Default user settings
```

### Forensic Registry Analysis

Analyzing the Windows registry from a forensic perspective. Check software installation records, autorun entries, and traces of user activity.

```bash
# On Windows
regedit.exe       # GUI registry editor
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Offline analysis on Linux (reglookup, hivex)
apt-get install libhivex-bin
hivexls SAM
hivexregedit SAM  # Browse registry
```

---

## 8. PE Virtual Address Space (VAS) Deep Dive

### Virtual Address Space Overview

VA (Virtual Address) is an absolute address in process memory, while RVA (Relative Virtual Address) is a relative address based on ImageBase. In ASLR environments, ImageBase changes on each run, so analysis should be RVA-based.

```
VAS (Virtual Address Space):
- Each process has an independent 4GB virtual address space
- Separate from physical memory; the OS manages virtual-to-physical mapping
- Memory isolation between processes → a bug in one process doesn't affect others

32-bit Windows split:
  0x00000000 ~ 0x7FFFFFFF : User space (2GB)
  0x80000000 ~ 0xFFFFFFFF : Kernel space (2GB, Ring 0 only)
```

### RVA / VA / File Offset Conversion
```
Core address concepts:
  VA  (Virtual Address)    : Address after loading into actual memory
  RVA (Relative VA)        : Relative address based on ImageBase
  File Offset              : Physical position in file (on disk)

Conversion formulas:
  VA = ImageBase + RVA
  File Offset = RVA - VirtualAddress(section) + PointerToRawData(section)

Example:
  ImageBase = 0x00400000
  .text section VirtualAddress = 0x1000
  .text section PointerToRawData = 0x400

  VA  0x00401234 → RVA = 0x1234
  File Offset = 0x1234 - 0x1000 + 0x400 = 0x634
```

---

## 9. PE Shared Memory and DLL Memory Structure

### How Multiple Processes Share DLLs
```
Process A           Process B
  ┌─────────┐          ┌─────────┐
  │VAS (2GB)│          │VAS (2GB)│
  │         │          │         │
  │user32.dll─────────→│user32.dll (same physical pages)
  │ .text   │  shared  │ .text   │ ← Code is shared (read-only)
  │ .data   │ separate │ .data   │ ← Data has separate copy per process (CoW)
  └─────────┘          └─────────┘

Copy-on-Write (CoW):
- Data sections initially reference the same physical page
- When one process attempts to write, only that page is copied and modified
- Achieves both memory savings and process isolation simultaneously
```

### Memory Mapped File (MMF) in Analysis
```c
// Reason PE analysis tools use MMF:
// - Can process large files without loading the entire file into memory
// - Efficient because it uses OS page cache

HANDLE hFile = CreateFile("target.exe", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
LPVOID base  = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

// Parse PE header directly via base pointer
PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)base;
PIMAGE_NT_HEADERS ntHdr  = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHdr->e_lfanew);
```

```python
#!/usr/bin/env python3
"""
RVA ↔ File Offset ↔ VA address conversion calculator
Usage: python3 rva_calc.py <PE_file> <address> [--type rva|va|offset]
"""
import sys
import argparse
import pefile


def rva_to_offset(pe: pefile.PE, rva: int) -> int | None:
    for sec in pe.sections:
        start = sec.VirtualAddress
        end   = start + sec.Misc_VirtualSize
        if start <= rva < end:
            return rva - start + sec.PointerToRawData
    return None


def offset_to_rva(pe: pefile.PE, offset: int) -> int | None:
    for sec in pe.sections:
        start = sec.PointerToRawData
        end   = start + sec.SizeOfRawData
        if start <= offset < end:
            return offset - start + sec.VirtualAddress
    return None


def convert_address(path: str, addr: int, addr_type: str) -> None:
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase

    if addr_type == "va":
        rva    = addr - base
        offset = rva_to_offset(pe, rva)
        print(f"VA     = {hex(addr)}")
        print(f"RVA    = {hex(rva)}")
        print(f"Offset = {hex(offset) if offset is not None else 'N/A (header region)'}")

    elif addr_type == "rva":
        va     = addr + base
        offset = rva_to_offset(pe, addr)
        print(f"RVA    = {hex(addr)}")
        print(f"VA     = {hex(va)}")
        print(f"Offset = {hex(offset) if offset is not None else 'N/A (header region)'}")

    elif addr_type == "offset":
        rva = offset_to_rva(pe, addr)
        va  = (rva + base) if rva is not None else None
        print(f"Offset = {hex(addr)}")
        print(f"RVA    = {hex(rva) if rva is not None else 'N/A'}")
        print(f"VA     = {hex(va) if va is not None else 'N/A'}")

    # Show which section the address belongs to
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        rva_check = addr - base if addr_type == "va" else addr
        if addr_type == "offset":
            rva_check = offset_to_rva(pe, addr) or 0
        if sec.VirtualAddress <= rva_check < sec.VirtualAddress + sec.Misc_VirtualSize:
            print(f"\nSection: {name}  "
                  f"VA:[{hex(base+sec.VirtualAddress)}~{hex(base+sec.VirtualAddress+sec.Misc_VirtualSize)}]  "
                  f"Raw:[{hex(sec.PointerToRawData)}~{hex(sec.PointerToRawData+sec.SizeOfRawData)}]")
            break

    pe.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="PE Address Converter")
    parser.add_argument("pe_file", help="PE file path")
    parser.add_argument("address", help="Address to convert (0x prefix supported)")
    parser.add_argument("--type", choices=["rva", "va", "offset"],
                        default="va", help="Address type (default: va)")
    args = parser.parse_args()

    addr = int(args.address, 16) if args.address.startswith("0x") else int(args.address, 0)
    convert_address(args.pe_file, addr, args.type)


if __name__ == "__main__":
    main()
```

---

## 10. DLL Explicit / Implicit Loading Details

### Implicit Loading
```
- Links import library (.lib) at compile time
- Windows Loader automatically loads DLL at program start
- Function addresses filled in IAT (Import Address Table)
- Easy to analyze: visible directly with dumpbin /imports
```

### Explicit Loading

Dynamically loads DLL at runtime using LoadLibrary/GetProcAddress. Frequently used by malware to make static analysis harder.

```c
// Dynamically load DLL at runtime — technique to complicate analysis
HMODULE hDll = LoadLibrary("MaliciousDLL.dll");
if (hDll) {
    // Dynamically construct string then call GetProcAddress
    char funcName[] = {'C','r','e','a','t','e','\0'};
    FARPROC func = GetProcAddress(hDll, funcName);
    if (func) func(...);
    FreeLibrary(hDll);
}

// Malware frequently uses LoadLibrary + GetProcAddress pattern
// In OllyDbg: set BP on LoadLibrary / GetProcAddress to detect
```

Detecting dynamic DLL loading patterns in OllyDbg. Set breakpoints on LoadLibraryA/GetProcAddress calls to identify which DLLs are being loaded.

```asm
; Detecting dynamic loading in OllyDbg
; CALL DWORD PTR [<&KERNEL32.LoadLibraryA>]  → BP here to see loaded DLL
; CALL DWORD PTR [<&KERNEL32.GetProcAddress>] → BP here to see loaded function name
; Check stack window for arguments (DLL name, function name)
```

---

## 11. Tiny PE — Minimum Size PE File

### PE File Size Optimization Principle
Many fields in the PE file spec work even when set to 0.
By removing unnecessary header fields and overlapping sections,
extremely small executables can be created.

```
Typical minimization process:
45056 bytes (normal .exe)
→  1024 bytes (remove unnecessary sections)
→   486 bytes (overlap part of headers)
→   356 bytes (minimize section headers)
→   296 bytes (shrink Optional Header)
→   168 bytes (remove DOS Stub)
→    97 bytes (smallest known PE)

97-byte PE structure:
- DOS Header size reduced (PE starts immediately after e_lfanew)
- Overlapping PE Header with code section
- Ignoring section alignment (SectionAlignment = FileAlignment = 4)
```

### Key Check Points During PE Analysis
```
Offsets to check with a hex editor:
  0x00: 4D 5A           → MZ signature
  0x3C: [4 bytes]        → PE header offset (e_lfanew)
  [e_lfanew+0]: 50 45 00 00 → PE signature
  [e_lfanew+4]: [2 bytes] → Machine (0x014C = x86, 0x8664 = x64)
  [e_lfanew+6]: [2 bytes] → NumberOfSections
  [Optional+16]: [4 bytes] → AddressOfEntryPoint (entry point RVA)
  [Optional+28]: [4 bytes] → ImageBase
```

---

## 12. EXT2 (Linux) vs NTFS vs FAT32 Comparison

| Feature | FAT32 | NTFS | EXT2 |
|---------|-------|------|------|
| OS | Windows 9x, USB | Windows XP+ | Linux |
| Max file size | 4GB | 16TB+ | 2TB |
| Journaling | None | Yes | None (from EXT3) |
| Permission management | None | ACL support | Unix permissions |
| Forensic recovery | Track via FAT table | Analyze MFT entries | Analyze inodes |

### EXT2 (Linux) Filesystem Structure
```
EXT2 Layout:
  ┌──────────────┬──────────────┬──────────────┬───────────┐
  │ Boot Block   │ Block Group 0│ Block Group 1 │    ...    │
  └──────────────┴──────────────┴──────────────┴───────────┘

Inside a Block Group:
  ┌────────────┬────────────┬──────────┬──────────┬────────────┐
  │ Superblock │ Group Desc │ Block    │ Inode    │ Data       │
  │            │ Table      │ Bitmap   │ Bitmap   │ Blocks     │
  └────────────┴────────────┴──────────┴──────────┴────────────┘

Inode:
  - Stores file metadata (permissions, size, timestamps, data block pointers)
  - Filename is NOT in inode → stored in directory entry (dentry)
  - On deletion: inode is cleared, data blocks may remain (recoverable)

Forensic perspective:
  - inode timestamps: atime (access), mtime (modify), ctime (change)
  - 'debugfs' tool can view deleted inodes
  - No journaling means higher chance of data recovery after deletion than NTFS
```
