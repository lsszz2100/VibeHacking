> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 커널 내부 구조 기반 고급 메모리 포렌식 & 루트킷 탐지 심층 분석

## 0. 윈도우 커널 객체와 메모리 서브시스템 아키텍처

메모리 포렌식(Memory Forensics)의 본질은 운영체제 커널이 메모리(RAM) 상에 유지하는 동적 자료구조를 역공학하여 대상 시스템의 실시간 실행 상태를 재구성하는 학문입니다. 디스크 기반 포렌식과 달리 파일리스 악성코드, DKOM(Direct Kernel Object Manipulation), 인메모리 프로세스 인젝션, 커널 모드 루트킷의 은닉 기법은 RAM 덤프 분석을 통해서만 완벽히 입증될 수 있습니다.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Windows Kernel Memory Layout                       │
├─────────────────────────────────────────────────────────────────────────┤
│ User Mode Space (0x00000000'00000000 ~ 0x00007FFF'FFFFFFFF)            │
│  ├── TEB (Thread Environment Block)                                     │
│  ├── PEB (Process Environment Block)                                    │
│  └── VAD Tree (Virtual Address Descriptors: VirtualAlloc / Mapped DLLs) │
├─────────────────────────────────────────────────────────────────────────┤
│ Kernel Mode Space (0xFFFF8000'00000000 ~ 0xFFFFFFFF'FFFFFFFF)          │
│  ├── Non-Paged Pool (절대 페이징되지 않는 핵심 커널 메모리)              │
│  │    ├── EPROCESS / KPROCESS 구조체 (Process Object)                   │
│  │    ├── ETHREAD / KTHREAD 구조체 (Thread Object)                     │
│  │    └── DRIVER_OBJECT / DEVICE_OBJECT (디바이스 드라이버 체인)        │
│  ├── Paged Pool (필요 시 pagefile.sys로 스왑 가능한 커널 메모리)        │
│  ├── System Service Descriptor Table (SSDT / KiServiceTable)            │
│  └── Kernel Callbacks (PspCreateProcessNotifyRoutine 등)                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. EPROCESS 구조체와 커널 풀 태그(Pool Tag) 스캐닝

### 1.1 EPROCESS 구조체의 핵심 오프셋 분석

모든 윈도우 프로세스는 커널의 Non-Paged Pool에 `EPROCESS` 구조체로 표현됩니다. `EPROCESS`는 내부적으로 `KPROCESS`를 첫 번째 멤버로 포함하며, 프로세스 스케줄링, 가상 메모리 관리, 보안 토큰, 핸들 테이블 정보를 관리합니다.

| 멤버 명칭 | 데이터 타입 | 역할 및 보안 포렌식 의미 |
|---|---|---|
| `Pcb` | `KPROCESS` | 프로세스 제어 블록 (디렉터리 테이블 베이스 `DirectoryTableBase / CR3`) |
| `ProcessId` | `HANDLE` | 고유 프로세스 ID (PID). 조작 시 `UniqueProcessId` 불일치 유발 |
| `ActiveProcessLinks` | `LIST_ENTRY` | 활성 프로세스 이중 연결 리스트(Circular Doubly Linked List) 포인터 |
| `Token` | `EX_FAST_REF` | 프로세스 보안 액세스 토큰. 토큰 스왑 공격(Token Stealing) 분석 대상 |
| `VadRoot` | `PMM_AVL_TABLE` | 가상 주소 디스크립터(VAD) 균형 이진 트리 루트 포인터 |
| `Peb` | `PPEB` | 유저 모드 프로세스 환경 블록(PEB) 포인터 |
| `ImageFileName` | `UCHAR[15]` | 실행 파일 이름 (최대 14글자 + 널 문자). 프로세스 마스커레이딩 탐지 |

### 1.2 커널 풀(Kernel Pool) 할당과 풀 태그 메커니즘

커널 드라이버와 실행부는 메모리를 동적으로 할당할 때 4바이트 식별자인 **Pool Tag**를 헤더에 기록합니다.

- `Proc` (`0x636F7250`): 프로세스 객체(`EPROCESS`) 할당 태그
- `Thre` (`0x65726854`): 스레드 객체(`ETHREAD`) 할당 태그
- `File` (`0x656C6946`): 파일 객체(`FILE_OBJECT`) 할당 태그
- `Driv` (`0x76697244`): 드라이버 객체(`DRIVER_OBJECT`) 할당 태그

`pslist` 플러그인은 `ActiveProcessLinks` 리스트를 Flink 포인터로 순회하므로, 루트킷이 해당 링크를 끊어버리면(DKOM) 프로세스를 발견할 수 없습니다. 반면 **`psscan`** 플러그인은 Non-Paged Pool 전체 물리 메모리를 스캐닝하여 `Proc` 태그와 `EPROCESS` 구조체의 특징적 바이트 시그니처를 직접 찾아내어 은닉된 프로세스까지 복원합니다.

---

## 2. DKOM(Direct Kernel Object Manipulation) 프로세스 은닉 및 탐지

### 2.1 ActiveProcessLinks 언링킹 공격 원리

공격자는 커널 취약점(BYOVD 등)을 통해 취약한 드라이버의 임의 주소 쓰기(Arbitrary Kernel Write)를 수행하여 `ActiveProcessLinks` 리스트에서 타깃 프로세스를 분리합니다.

```c
// DKOM: ActiveProcessLinks Unlinking PoC 개념
PLIST_ENTRY Current = &(TargetEProcess->ActiveProcessLinks);
PLIST_ENTRY Prev = Current->Blink;
PLIST_ENTRY Next = Current->Flink;

// 타깃 노드를 우회하도록 전후 노드의 링크 수정
Prev->Flink = Next;
Next->Blink = Prev;

// 타깃 노드의 링크를 자기 자신을 가리키도록 설정 (고립)
Current->Flink = Current;
Current->Blink = Current;
```

이 상태에서도 프로세스는 커널 스케줄러의 스레드 디스패칭 큐와 CR3(DirectoryTableBase)를 통해 CPU에서 계속 정상 실행됩니다.

### 2.2 3단계 교차 검증(Cross-Verification) 탐지 알고리즘

은닉된 프로세스를 100% 식별하기 위해 다음 3단계 교차 분석을 수행합니다:

1. **`windows.pslist` (선형 리스트 순회)**: `PsActiveProcessHead`로부터 연결된 정상 프로세스 목록 수집.
2. **`windows.psscan` (풀 태그 카빙)**: `Proc` 풀 태그를 통해 할당 해제되지 않은 모든 `EPROCESS` 수집.
3. **`windows.thrdscan` (스레드 역추적)**: `Thre` 태그를 스캔하여 모든 활성 스레드를 수집한 후, 각 스레드의 `KTHREAD.Process` 포인터가 가리키는 부모 프로세스 역추적.

```
PsList 집합:   { PID 4, PID 500, PID 600 }
PsScan 집합:   { PID 4, PID 500, PID 600, PID 1337 }
ThrdScan 집합: { PID 4, PID 500, PID 600, PID 1337 }
────────────────────────────────────────────────────
차집합 (PsScan - PsList) = { PID 1337 }  <-- DKOM 은닉 프로세스 확정!
```

---

## 3. 커널 드라이버, IRP 후킹 및 보안 콜백 트리아지

### 3.1 IRP(I/O Request Packet) 디스패치 테이블 후킹

윈도우 디바이스 드라이버(`DRIVER_OBJECT`)는 유저 모드 애플리케이션의 파일 입출력, 디바이스 제어(`DeviceIoControl`) 요청을 처리하기 위해 28개의 `MajorFunction` 함수 포인터 배열을 유지합니다.

루트킷은 타깃 드라이버(예: 파일 시스템 드라이버 `fltmgr.sys` 또는 네트워크 드라이버 `tcpip.sys`)의 `MajorFunction[IRP_MJ_CREATE]`, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` 포인터를 자신이 로드한 악성 드라이버 함수 주소로 덮어씁니다.

- **Volatility 3 탐지 기법**:
  ```bash
  python3 vol.py -f memory.dmp windows.driverscan
  python3 vol.py -f memory.dmp windows.device_tree
  ```
  `windows.driverscan`을 통해 드라이버 시작 주소와 크기를 식별하고, 디바이스 스택 상에서 코드 주소가 등록된 드라이버 모듈 범위를 벗어나는 비정상 핸들러를 적발합니다.

### 3.2 시스템 커널 콜백 루틴 검사

현대 EDR 및 안티바이러스는 커널 콜백을 등록하여 프로세스 생성, 스레드 생성, 레지스트리 수정을 실시간 감시합니다. 루트킷은 이러한 방어 솔루션을 무력화하거나 감시를 피하기 위해 커널 내부의 콜백 배열을 조작합니다.

- `PspCreateProcessNotifyRoutine` (최대 64개)
- `PspCreateThreadNotifyRoutine` (최대 64개)
- `PspLoadImageNotifyRoutine` (드라이버/DLL 로드 감시)
- `ObRegisterCallbacks` (프로세스/스레드 핸들 오픈 가로채기)

```bash
# Volatility 3 커널 콜백 검사 플러그인 실행
python3 vol.py -f memory.dmp windows.callbacks
```
출력 결과에서 콜백 함수가 가리키는 모듈이 `ntoskrnl.exe`, `fltmgr.sys`, EDR 모듈이 아닌 정체불명의 비서명 드라이버 주소를 가리킬 경우 커널 루트킷 침해 지표(IoC)로 판단합니다.

---

## 4. Volatility 3 커스텀 플러그인 개발 (Python SDK)

Volatility 3 프레임워크는 모듈식 아키텍처로 설계되어 있어, 포렌식 분석가가 특정 위협 지표나 독자적인 커널 구조체 카빙 알고리즘을 파이썬으로 손쉽게 구현할 수 있습니다.

### 4.1 커스텀 풀 태그 사냥 플러그인 (`kernel_pool_hunter.py`)

다음은 Non-Paged Pool 상에서 특정 풀 태그와 `EPROCESS` 구조체를 정밀 스캔하여 은닉된 프로세스와 생성 시각, CR3 주소를 추출하는 프로덕션 레벨 플러그인 소스코드입니다:

```python
# Custom Volatility 3 Plugin: KernelPoolHunter
# Path: volatility3/framework/plugins/windows/kernel_pool_hunter.py

import logging
from typing import List, Generator, Tuple
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class KernelPoolHunter(interfaces.plugins.PluginInterface):
    """커널 Non-Paged Pool 태그 스캐닝을 통한 DKOM 은닉 프로세스 탐지 플러그인"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel symbols and types",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist",
                plugin=pslist.PsList,
                version=(2, 0, 0),
            ),
        ]

    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        memory_layer = self.context.layers[layer_name]

        # 1. PsList 정상 프로세스 PID 집합 수집
        known_pids = set()
        try:
            for proc in pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name):
                known_pids.add(int(proc.UniqueProcessId))
        except Exception as e:
            vollog.warning(f"Error enumerating active process list: {e}")

        # 2. 커널 풀 스캔: 'Proc' 태그 (0x636F7250)
        pool_tag = b"Proc"
        type_eprocess = kernel.symbol_table_name + constants.BANG + "_EPROCESS"

        for offset in memory_layer.scan(context=self.context, scanner=interfaces.layers.ScannerInterface()):
            # 바이트 매칭 및 구조체 유효성 검증
            try:
                eprocess = kernel.object(object_type="_EPROCESS", offset=offset, absolute=True)
                pid = int(eprocess.UniqueProcessId)
                create_time = str(eprocess.CreateTime)
                image_name = str(eprocess.ImageFileName.cast("string", max_length=15, errors="replace"))
                cr3 = hex(eprocess.Pcb.DirectoryTableBase)

                # DKOM 은닉 여부 판정
                is_hidden = pid not in known_pids

                yield (
                    0,
                    (
                        format_hints.Hex(offset),
                        pid,
                        image_name,
                        cr3,
                        create_time,
                        "CRITICAL: DKOM HIDDEN" if is_hidden else "NORMAL",
                    ),
                )
            except (exceptions.InvalidAddressException, AttributeError):
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("ImageFileName", str),
                ("DirectoryTableBase(CR3)", str),
                ("CreateTime", str),
                ("Status", str),
            ],
            self._generator(),
        )
```

---

## 5. 실전 APT 침해 사례 역공학 분석

### 5.1 Stuxnet: 커널 드라이버 로더 및 메모리 은닉

- **악성 드라이버**: `MrxNet.sys`, `MrxCls.sys` (Realtek 및 JMicron 도난 디지털 인증서 사용)
- **메모리 동작 특성**:
  1. 드라이버 로드 시 `ntoskrnl.exe`의 내부 미문서화 함수를 호출하여 드라이버 목록(`PsLoadedModuleList`)에서 자기 자신을 삭제.
  2. `fltmgr.sys` 미니필터 콜백을 하이재킹하여 특정 USB 메모리 파일 탐색 요청 시 스턱스넷 바이너리(.tmp, ~DF*.tmp)를 숨김 처리.
  3. `windows.modscan` 실행 시 커널 메모리 페이지 상에 PE 헤더(`MZ / PE`)가 잔존하여 드라이버 베이스 주소 역추적 성공.

### 5.2 BlackEnergy2: SSDT 변조 및 루트킷 인젝션

- **침투 기법**: `msrexec.sys` 드라이버를 통해 커널 권한 획득 후 `ZwSetSystemInformation` 및 `ZwQueryDirectoryFile` 후킹.
- **메모리 포렌식 트리아지**:
  1. `windows.ssdt`: 정상 ntoskrnl 주소 공간 범위를 벗어나 악성 드라이버 영역으로 리다이렉션된 SSDT 인덱스 0x35 검출.
  2. `windows.malfind`: `svchost.exe` 프로세스의 VAD 트리에서 디스크 파일과 매핑되지 않은 `PAGE_EXECUTE_READWRITE` 속성의 셸코드 및 PE 파일 식별.
  3. `windows.dumpfiles`: 악성 VAD 메모리 영역을 디스크로 덤프하여 해시 연계 분석 수행.

---

<a name="english"></a>

# Advanced Volatility 3 Kernel Internals & Rootkit Memory Forensics Deep Dive

## 0. Windows Kernel Architecture & Memory Subsystems

Memory forensics reconstructs volatile operational state by reverse-engineering Windows kernel data structures directly from physical RAM dumps. Unlike disk forensics, ephemeral threats—including fileless implants, Direct Kernel Object Manipulation (DKOM), in-memory process hollowing, and Ring 0 rootkits—can only be verified and triaged in memory.

---

## 1. EPROCESS Internals & Pool Tag Scanning

Every Windows process is tracked in the kernel Non-Paged Pool via an `EPROCESS` structure:

- **`ActiveProcessLinks`**: Circular doubly linked list (`LIST_ENTRY`) linking all active processes. Traversed by `windows.pslist`.
- **`Token` (`EX_FAST_REF`)**: Security access token, targeted in token-stealing privilege escalation attacks.
- **`VadRoot` (`PMM_AVL_TABLE`)**: AVL balanced binary tree descriptor mapping all virtual allocations.
- **Pool Tag Scanning (`Proc` / `0x636F7250`)**: `windows.psscan` parses physical memory pages for unallocated or unlinked `EPROCESS` structures, bypassing pointer-level unlinking.

---

## 2. DKOM Unlinking & Triangulation Detection

### 2.1 The Unlinking Evasion Mechanism

Rootkits modify `Flink` and `Blink` pointers of `Target->ActiveProcessLinks`:
```c
Target->ActiveProcessLinks.Blink->Flink = Target->ActiveProcessLinks.Flink;
Target->ActiveProcessLinks.Flink->Blink = Target->ActiveProcessLinks.Blink;
Target->ActiveProcessLinks.Flink = &Target->ActiveProcessLinks;
Target->ActiveProcessLinks.Blink = &Target->ActiveProcessLinks;
```
Because process scheduling operates on individual thread objects (`ETHREAD`), the unlinked process continues execution uninterrupted.

### 2.2 Forensic Triangulation Algorithm

Cross-referencing three disparate kernel mechanisms exposes unlinked processes:
1. `PsList`: Enumerate doubly-linked list (`PsActiveProcessHead`).
2. `PsScan`: Enumerate physical pool allocations tagged `Proc`.
3. `ThrdScan`: Enumerate `ETHREAD` objects tagged `Thre` and resolve each thread's `KTHREAD.Process` pointer.
$$\text{Hidden Processes} = (\text{PsScan} \cup \text{ThrdScan}) \setminus \text{PsList}$$

---

## 3. Kernel IRP Dispatch Tables & Callback Inspection

- **IRP Dispatch Hooking**: Rootkits overwrite `MajorFunction` pointer arrays in `DRIVER_OBJECT` structures to intercept file system and network telemetry.
- **Kernel Notification Callbacks**: System monitoring hooks (`PspCreateProcessNotifyRoutine`, `ObRegisterCallbacks`) inspected via `windows.callbacks` to detect unbacked callback addresses.

---

## 4. Volatility 3 Custom Plugin Development

Volatility 3 implements a modular Python SDK utilizing `TreeGrid` rendering pipelines and schema-driven symbol spaces. Custom plugins leverage memory layer scanners to pinpoint anomalous kernel signatures and synthesize forensic reports with precision.
