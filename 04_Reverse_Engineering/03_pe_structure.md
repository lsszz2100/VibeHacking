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
```bash
# Windows에서
dumpbin /imports malware.exe

# Linux에서
objdump -x binary | grep IMPORT
readelf -d binary

# Python으로 PE 파싱
pip install pefile
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for imp in entry.imports:
        print('  ', imp.name)
"
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
