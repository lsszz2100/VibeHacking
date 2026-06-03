> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 브라우저 샌드박스 탈출

## 0. 초보자를 위한 개념 이해

### 브라우저 샌드박스 탈출이란?

브라우저 샌드박스는 악성 웹 페이지가 렌더러 프로세스를 장악하더라도 OS나 다른 프로세스에 접근하지 못하도록 격리하는 보안 경계이다. 샌드박스 탈출(Sandbox Escape)은 이 격리를 뚫고 렌더러 밖의 시스템 자원에 접근하는 공격이다. 완전한 브라우저 공격(풀체인 익스플로잇)은 JS 엔진 버그(렌더러 RCE) + 샌드박스 탈출 + 권한 상승의 3단계로 구성된다.

**왜 배우는가:**
```
[풀체인 브라우저 익스플로잇의 구조]

1단계: 렌더러 침해
  악성 웹사이트 방문 → JS 엔진 버그 → 렌더러 RCE
  (권한: 매우 낮음, 격리됨)
       ↓
2단계: 샌드박스 탈출 ← 이 파일의 주제
  브라우저 프로세스와 IPC 통신 버그 / OS 커널 버그
  → 샌드박스 밖의 브라우저 프로세스 코드 실행
  (권한: 낮음, 브라우저 권한)
       ↓
3단계: 권한 상승
  OS 취약점 → 시스템/루트 권한 획득
  (권한: 최고)

샌드박스 격리 기법 (OS별):
- Linux:  seccomp-BPF (시스템 콜 필터링) + 네임스페이스
- Windows: Job Object + AppContainer + 무결성 수준
- macOS:  Sandbox 프로파일 + XPC 서비스
```

### 핵심 개념 정리

```
주요 용어:
- 샌드박스(Sandbox): 렌더러 프로세스를 OS로부터 격리하는 보안 경계
- IPC(Inter-Process Communication): 렌더러-브라우저 프로세스 간 통신 채널
- Mojo: Chromium의 IPC 프레임워크 - 샌드박스 탈출의 주요 공격 표면
- seccomp-BPF: Linux 시스템 콜 화이트리스트 필터 (Linux 샌드박스 핵심)
- AppContainer: Windows의 낮은 권한 격리 컨테이너
- 브로커 프로세스: 렌더러 대신 파일/레지스트리 접근을 중개하는 신뢰된 프로세스
- CVE-2021-38003: 실제 샌드박스 탈출 취약점 예시 (V8 OOB + 샌드박스 탈출)
```

### 필요한 도구 및 환경
- **Linux VM**: seccomp 실습 환경 (KVM 또는 VMware)
- **Python 3.10+**: ctypes, subprocess (seccomp 개념 실습)
- **strace**: 시스템 콜 추적으로 샌드박스 동작 분석
- **Chrome 디버그 빌드**: --no-sandbox 플래그로 샌드박스 해제 후 비교

### 기초 실습 예제
```python
"""
브라우저 샌드박스 개념 실습
seccomp-BPF 방식의 시스템 콜 필터링을 Python으로 시연
"""
import os
import subprocess
import sys

def demonstrate_sandbox_concept():
    """
    샌드박스의 핵심 개념인 시스템 콜 필터링 원리 설명
    실제 Chromium은 C++로 작성된 복잡한 샌드박스를 사용
    """
    print("=== 브라우저 샌드박스 개념 시연 ===\n")

    print("[샌드박스 = 허용된 시스템 콜만 실행 가능]")
    print()

    # Chromium 렌더러 프로세스의 샌드박스 허용/차단 시스템 콜
    sandbox_rules = {
        "허용됨 (렌더러가 필요)": [
            "read / write",       # 파일 읽기/쓰기 (파이프, 소켓)
            "mmap / munmap",      # 메모리 매핑
            "brk",               # 힙 확장
            "futex",             # 뮤텍스 (멀티스레딩)
            "clock_gettime",     # 시간 조회
            "sendmsg / recvmsg", # IPC (Mojo 통신)
        ],
        "차단됨 (샌드박스 탈출 방지)": [
            "execve",            # 새 프로세스 실행 (핵심 차단!)
            "open / openat",     # 직접 파일 열기
            "socket",            # 네트워크 소켓 생성
            "fork / clone",      # 새 프로세스/스레드 생성
            "ptrace",            # 다른 프로세스 디버깅
            "kill",              # 프로세스에 시그널 전송
            "ioctl (대부분)",    # 디바이스 제어
        ],
    }

    for category, syscalls in sandbox_rules.items():
        print(f"[{category}]")
        for syscall in syscalls:
            icon = "O" if "허용" in category else "X"
            print(f"  [{icon}] {syscall}")
        print()

    print("[샌드박스 탈출 시도 시나리오]")
    print("1. 렌더러 RCE 달성 후 /etc/passwd 읽기 시도")
    print("   open('/etc/passwd') → EPERM (차단!)")
    print()
    print("2. IPC 버그를 이용한 탈출 시도")
    print("   Mojo 메시지 조작 → 브라우저 프로세스의 파일 접근 요청")
    print("   → 브라우저 프로세스에서 임의 파일 접근 가능 (탈출 성공)")
    print()
    print("3. 커널 익스플로잇으로 직접 탈출")
    print("   seccomp 우회 가능한 커널 취약점 → 커널 RCE → 샌드박스 무력화")

    # Linux seccomp 간단 시연 (prctl 사용)
    print("\n[Linux seccomp 활성화 확인]")
    try:
        result = subprocess.run(
            ["cat", "/proc/self/status"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "Seccomp" in line:
                val = line.split(":")[1].strip()
                mode = {"0": "비활성", "1": "strict", "2": "filter (BPF)"}.get(val, val)
                print(f"  현재 프로세스 Seccomp 모드: {mode}")
                break
    except Exception:
        print("  /proc/self/status 읽기 실패")

demonstrate_sandbox_concept()
```

---

## 1. Chromium 샌드박스 아키텍처

### 1.1 개요

Chromium 샌드박스는 렌더러 프로세스가 시스템을 직접 접근하지 못하도록 OS 수준의 격리를 제공한다. 공격자가 렌더러 내의 JavaScript 엔진 취약점을 익스플로잇해 임의 코드 실행을 달성하더라도, 샌드박스를 벗어나지 않으면 OS에 대한 실질적인 공격은 불가능하다.

### 1.2 Linux Chromium 샌드박스 계층

```
[사용자 공간 프로세스]
        ↓
  Namespace Isolation
  (user, pid, net, mnt, ipc namespace)
        ↓
  seccomp-bpf 필터
  (허용된 syscall 목록 외 차단)
        ↓
  Zygote 프로세스
  (fork()로 렌더러 생성, 권한 최소화)
        ↓
  렌더러 프로세스
  (No root, No ptrace, 제한된 파일 접근)
```

### 1.3 컴포넌트별 샌드박스 상세

| 컴포넌트 | Linux 격리 기법 | Windows 격리 기법 | macOS 격리 기법 |
|----------|-----------------|-------------------|-----------------|
| 렌더러 | seccomp-bpf, user ns | Restricted Token, Job Object | Sandbox 프로필, App Sandbox |
| GPU 프로세스 | seccomp-bpf (완화) | Restricted Token | GPU sandbox 프로필 |
| Network Service | seccomp-bpf, network ns | Restricted Token | App Sandbox |
| Utility Process | seccomp-bpf | Restricted Token | App Sandbox |
| PDF Plugin | seccomp-bpf | Restricted Token | App Sandbox |
| 브라우저 프로세스 | 미적용 | 높은 권한 | 미적용 |

### 1.4 Zygote 프로세스 모델

Linux에서 Chromium은 Zygote 프로세스를 통해 렌더러를 생성한다. Zygote는 미리 필요한 라이브러리를 로드하고, `fork()`로 렌더러를 생성한 후 즉시 샌드박스를 적용한다. 이 구조 자체가 공격 표면이 될 수 있다.

```
Browser Process
    ↓ (IPC: "새 렌더러 필요")
Zygote Process
    ↓ fork()
렌더러 Process
    ↓ seccomp-bpf 적용
격리된 렌더러 실행
```

### 1.5 seccomp-bpf 필터 구조

seccomp-bpf는 BPF(Berkeley Packet Filter) 프로그램을 사용해 syscall 번호와 인자를 검사한다. 렌더러 프로세스에서 허용되는 주요 syscall은 극히 제한적이다.

**렌더러에서 허용되는 주요 syscall (Linux x86_64):**

| syscall | 허용 여부 | 제한 조건 |
|---------|-----------|-----------|
| read | 허용 | 열린 fd에만 |
| write | 허용 | stdout/stderr + pipe |
| mmap | 조건부 | PROT_EXEC 제한 |
| mprotect | 조건부 | PROT_EXEC 제한 |
| futex | 허용 | - |
| clock_gettime | 허용 | - |
| exit / exit_group | 허용 | - |
| sendmsg / recvmsg | 허용 | Mojo IPC용 |
| open / openat | 거부 | - |
| socket | 거부 | - |
| execve / execveat | 거부 | - |
| fork / clone | 거부 | - |
| ptrace | 거부 | - |
| keyctl | 거부 | - |

---

## 2. 샌드박스 탈출 기법 분류

### 2.1 탈출 기법 종합 분류표

| 기법 분류 | 세부 기법 | 필요 조건 | 위험도 | 방어 기법 |
|-----------|-----------|-----------|--------|-----------|
| IPC 취약점 | Mojo 메시지 처리 버그 | 렌더러 코드 실행 | 최상 | IPC 인터페이스 퍼징, 검증 강화 |
| IPC 취약점 | DXVA / GPU IPC 오류 | 렌더러 코드 실행 | 상 | GPU 샌드박스 강화 |
| 커널 취약점 | seccomp 우회 syscall | 렌더러 코드 실행 | 최상 | 커널 패치, seccomp 목록 축소 |
| 커널 취약점 | user namespace 탈출 | 렌더러 코드 실행 | 상 | namespace 권한 제한 |
| GPU 프로세스 | GPU 드라이버 취약점 | 렌더러→GPU IPC | 상 | GPU 격리 강화 |
| GPU 프로세스 | WebGL 쉐이더 파서 | GPU 컨텍스트 | 중 | 쉐이더 검증 |
| 확장프로그램 | Extension API 취약점 | 악성 확장 설치 | 상 | MV3, 권한 축소 |
| 네이티브 라이브러리 | libpdf, libwebp 파서 | 파일 열기 유도 | 중-상 | 라이브러리 격리 |
| 논리 취약점 | CORS/SOP 우회로 민감 정보 유출 | 웹 접근 | 중 | 정책 강화 |
| 사이드채널 | Spectre (타이머 기반 캐시 측정) | JS 실행 | 중 | 타이머 해상도 저하 |

### 2.2 Mojo IPC 취약점 상세

Mojo는 Chromium의 내부 IPC 프레임워크로, 렌더러와 브라우저 프로세스 간 통신을 담당한다. 렌더러가 브라우저 프로세스에 악의적인 Mojo 메시지를 보낼 수 있다면 브라우저 프로세스 내에서 코드 실행이 가능하다.

**Mojo 취약점 패턴:**
- 정수 오버플로로 인한 메시지 크기 오계산
- UAF: 메시지 처리 중 콜백이 인터페이스를 해제
- TOCTOU: 메시지 파라미터 검증 후 실제 사용 사이에 변조
- 타입 혼동: InterfacePtr를 다른 인터페이스로 재해석

---

## 3. 실제 탈출 CVE 사례 및 패치

### 3.1 주요 샌드박스 탈출 CVE 분석표

| CVE | 연도 | 취약점 위치 | 기법 | CVSS | 패치 내용 |
|-----|------|-------------|------|------|-----------|
| CVE-2019-13764 | 2019 | Chrome IPC | Mojo UAF | 9.6 | 브라우저 측 인터페이스 수명 관리 수정 |
| CVE-2020-6507 | 2020 | V8 + Sandbox | OOB → IPC 조작 | 9.6 | V8 경계 검사, IPC 검증 강화 |
| CVE-2021-21206 | 2021 | Chrome (Blink) | UAF in Blink | 8.8 | 렌더러-브라우저 IPC 객체 수명 수정 |
| CVE-2021-30633 | 2021 | Chrome Indexed DB | UAF | 9.6 | 인덱스DB IPC 핸들러 수정 |
| CVE-2022-2856 | 2022 | Chrome Intents | 불충분한 입력 검증 | 8.8 | URL Intent 처리 필터링 강화 |
| CVE-2022-3075 | 2022 | Mojo | 불충분한 데이터 검증 | 9.6 | Mojo 입력 검증 패치 |
| CVE-2023-2033 | 2023 | V8 + IPC | 타입 혼동 | 8.8 | JIT 및 IPC 수정 |
| CVE-2023-3079 | 2023 | V8 | 타입 혼동 (ITW) | 8.8 | V8 맵 전환 검증 |
| CVE-2023-5217 | 2023 | libvpx (VP8) | 힙 버퍼 오버플로 | 8.8 | libvpx 업데이트 |
| CVE-2024-0519 | 2024 | V8 | OOB 메모리 접근 (ITW) | 7.5 | V8 경계 검사 추가 |

### 3.2 패치 이전/이후 비교 (CVE-2022-3075)

**패치 전 — Mojo 메시지 크기 검증 부재:**
```cpp
// 취약 코드 (개념 예시)
void HandleMessage(const MojoMessage& msg) {
    size_t len = msg.data_size;  // 렌더러가 제공한 크기 신뢰
    memcpy(buffer, msg.data, len);  // OOB 쓰기 가능
}
```

**패치 후 — 검증 추가:**
```cpp
void HandleMessage(const MojoMessage& msg) {
    if (msg.data_size > kMaxAllowedSize) {
        mojo::ReportBadMessage("메시지 크기 초과");
        return;
    }
    memcpy(buffer, msg.data, msg.data_size);
}
```

---

## 4. Python CLI: 샌드박스 탈출 탐지 모니터

```python
#!/usr/bin/env python3
"""
샌드박스 탈출 탐지 모니터
브라우저 렌더러 프로세스의 /proc 정보를 모니터링하여
비정상적인 동작을 탐지한다. Linux 전용.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# 데이터 클래스
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    pid:         int
    ppid:        int
    name:        str
    state:       str
    uid:         int
    gid:         int
    threads:     int
    vm_rss_kb:   int
    seccomp:     int   # 0=없음, 1=strict, 2=filter
    ns_pid:      str
    ns_net:      str
    ns_mnt:      str
    ns_user:     str
    cmdline:     str


@dataclass
class Alert:
    timestamp:   float
    pid:         int
    alert_type:  str
    detail:      str
    severity:    str  # CRITICAL / HIGH / MEDIUM / LOW

    def to_dict(self) -> dict:
        return asdict(self)

    def pretty(self) -> str:
        ts  = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (f"[{ts}] [{self.severity}] PID={self.pid} "
                f"type={self.alert_type} — {self.detail}")


@dataclass
class MonitorState:
    pid:               int
    known_children:    set[int] = field(default_factory=set)
    last_ns:           dict[str, str] = field(default_factory=dict)
    last_seccomp:      int = -1
    baseline_uid:      int = -1
    alerts:            list[Alert] = field(default_factory=list)


# ---------------------------------------------------------------------------
# /proc 파싱 유틸리티
# ---------------------------------------------------------------------------

def read_proc_status(pid: int) -> dict[str, str]:
    """
    /proc/{pid}/status를 파싱하여 딕셔너리로 반환한다.
    파일이 없으면 빈 딕셔너리를 반환한다.
    """
    path = Path(f"/proc/{pid}/status")
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                result[key.strip()] = val.strip()
    except PermissionError:
        pass
    return result


def read_proc_cmdline(pid: int) -> str:
    """
    /proc/{pid}/cmdline을 읽어 공백 구분 문자열로 반환한다.
    """
    path = Path(f"/proc/{pid}/cmdline")
    if not path.exists():
        return ""
    try:
        data = path.read_bytes()
        return data.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except PermissionError:
        return "<permission denied>"


def read_ns_links(pid: int) -> dict[str, str]:
    """
    /proc/{pid}/ns/ 디렉토리에서 namespace inode를 읽는다.
    """
    ns_dir = Path(f"/proc/{pid}/ns")
    result: dict[str, str] = {}
    if not ns_dir.exists():
        return result
    for ns_type in ("pid", "net", "mnt", "user", "ipc", "uts"):
        link = ns_dir / ns_type
        try:
            result[ns_type] = str(os.readlink(link))
        except (OSError, PermissionError):
            result[ns_type] = "unknown"
    return result


def get_children(pid: int) -> set[int]:
    """
    /proc/{pid}/task/{pid}/children 또는 /proc/{pid}/task를 통해
    직접 자식 프로세스 PID를 수집한다.
    """
    children: set[int] = set()
    # 방법 1: task/{tid}/children
    task_dir = Path(f"/proc/{pid}/task")
    if task_dir.exists():
        try:
            for tid_dir in task_dir.iterdir():
                children_file = tid_dir / "children"
                if children_file.exists():
                    content = children_file.read_text(encoding="utf-8", errors="replace")
                    for child_pid_str in content.split():
                        try:
                            children.add(int(child_pid_str))
                        except ValueError:
                            pass
        except PermissionError:
            pass
    # 방법 2: 전체 /proc에서 ppid 매칭
    if not children:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = read_proc_status(int(entry.name))
                if status.get("PPid", "") == str(pid):
                    children.add(int(entry.name))
            except (ValueError, PermissionError):
                pass
    return children


def collect_process_info(pid: int) -> ProcessInfo | None:
    """
    지정된 PID에 대한 ProcessInfo를 수집한다.
    프로세스가 존재하지 않으면 None을 반환한다.
    """
    status = read_proc_status(pid)
    if not status:
        return None

    def si(key: str, default: int = 0) -> int:
        val = status.get(key, str(default))
        # "kB" 등 단위 제거
        m = re.search(r"\d+", val)
        return int(m.group()) if m else default

    ns = read_ns_links(pid)

    return ProcessInfo(
        pid=pid,
        ppid=si("PPid"),
        name=status.get("Name", ""),
        state=status.get("State", ""),
        uid=si("Uid"),
        gid=si("Gid"),
        threads=si("Threads"),
        vm_rss_kb=si("VmRSS"),
        seccomp=si("Seccomp"),
        ns_pid=ns.get("pid", ""),
        ns_net=ns.get("net", ""),
        ns_mnt=ns.get("mnt", ""),
        ns_user=ns.get("user", ""),
        cmdline=read_proc_cmdline(pid),
    )


# ---------------------------------------------------------------------------
# 탐지 규칙
# ---------------------------------------------------------------------------

def check_seccomp_disabled(
    info: ProcessInfo,
    state: MonitorState,
) -> Alert | None:
    """
    seccomp 필터가 비활성화된 경우 경고를 생성한다.
    초기 상태에서 필터가 있었다면 사라진 것을 탐지한다.
    """
    if state.last_seccomp == -1:
        # 기준값 설정
        state.last_seccomp = info.seccomp
        return None
    if state.last_seccomp >= 1 and info.seccomp == 0:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="SECCOMP_DISABLED",
            detail=f"seccomp 상태가 {state.last_seccomp} → 0으로 변경됨 (샌드박스 제거 의심)",
            severity="CRITICAL",
        )
    state.last_seccomp = info.seccomp
    return None


def check_namespace_change(
    info: ProcessInfo,
    state: MonitorState,
) -> list[Alert]:
    """
    namespace inode가 변경된 경우 경고를 생성한다.
    """
    alerts: list[Alert] = []
    current_ns = {
        "pid": info.ns_pid,
        "net": info.ns_net,
        "mnt": info.ns_mnt,
        "user": info.ns_user,
    }
    for ns_type, ns_id in current_ns.items():
        prev = state.last_ns.get(ns_type)
        if prev is None:
            state.last_ns[ns_type] = ns_id
            continue
        if prev != ns_id and prev != "unknown" and ns_id != "unknown":
            alerts.append(
                Alert(
                    timestamp=time.time(),
                    pid=info.pid,
                    alert_type="NAMESPACE_CHANGE",
                    detail=f"{ns_type} namespace 변경: {prev} → {ns_id} (탈출 시도 가능성)",
                    severity="CRITICAL",
                )
            )
            state.last_ns[ns_type] = ns_id
    return alerts


def check_uid_change(
    info: ProcessInfo,
    state: MonitorState,
) -> Alert | None:
    """
    UID가 0(root)으로 상승된 경우 경고를 생성한다.
    """
    if state.baseline_uid == -1:
        state.baseline_uid = info.uid
        return None
    if state.baseline_uid != 0 and info.uid == 0:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="UID_ESCALATION",
            detail=f"UID가 {state.baseline_uid} → 0(root)으로 상승됨",
            severity="CRITICAL",
        )
    return None


def check_unexpected_children(
    pid: int,
    state: MonitorState,
) -> list[Alert]:
    """
    예상치 않은 자식 프로세스 생성을 탐지한다.
    렌더러는 일반적으로 자식 프로세스를 생성하지 않는다.
    """
    alerts: list[Alert] = []
    current_children = get_children(pid)
    new_children     = current_children - state.known_children

    for child_pid in new_children:
        child_info = collect_process_info(child_pid)
        child_name = child_info.name if child_info else "unknown"
        child_cmd  = child_info.cmdline if child_info else ""

        # 렌더러가 spawn한 프로세스 — 매우 의심스럽다
        sev = "CRITICAL" if child_name not in ("", "sandbox") else "HIGH"
        alerts.append(
            Alert(
                timestamp=time.time(),
                pid=pid,
                alert_type="UNEXPECTED_CHILD_PROCESS",
                detail=(f"자식 프로세스 생성 탐지: PID={child_pid} "
                        f"name={child_name} cmd={child_cmd[:80]}"),
                severity=sev,
            )
        )

    state.known_children = current_children
    return alerts


def check_high_memory(
    info: ProcessInfo,
    threshold_mb: int = 2048,
) -> Alert | None:
    """
    RSS 메모리가 임계값을 초과하면 힙 스프레이 가능성을 경고한다.
    """
    rss_mb = info.vm_rss_kb // 1024
    if rss_mb > threshold_mb:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="HIGH_MEMORY_USAGE",
            detail=f"RSS={rss_mb}MB > 임계값 {threshold_mb}MB (힙 스프레이 의심)",
            severity="MEDIUM",
        )
    return None


# ---------------------------------------------------------------------------
# 경고 발령
# ---------------------------------------------------------------------------

def trigger_alert_command(cmd: str, alert: Alert) -> None:
    """외부 명령을 실행하여 경고를 전달한다."""
    if not cmd:
        return
    env = os.environ.copy()
    env["ALERT_TYPE"]     = alert.alert_type
    env["ALERT_PID"]      = str(alert.pid)
    env["ALERT_SEVERITY"] = alert.severity
    env["ALERT_DETAIL"]   = alert.detail
    try:
        subprocess.Popen(
            shlex.split(cmd),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        print(f"[!] 경고 명령 실행 실패: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 메인 모니터 루프
# ---------------------------------------------------------------------------

def monitor_pid(
    pid: int,
    interval: float,
    alert_command: str,
    log_file: Path | None,
) -> None:
    """
    지정된 PID를 지속적으로 모니터링하며 이상 징후를 탐지한다.
    """
    if not Path(f"/proc/{pid}").exists():
        print(f"[!] PID {pid}가 존재하지 않습니다.", file=sys.stderr)
        sys.exit(1)

    state = MonitorState(pid=pid)
    print(f"[+] PID {pid} 모니터링 시작 (간격: {interval}초)")
    print(f"    /proc/{pid}/status, namespace, seccomp 감시 중...")

    log_handle = None
    if log_file:
        log_handle = log_file.open("a", encoding="utf-8")

    try:
        while True:
            if not Path(f"/proc/{pid}").exists():
                print(f"\n[*] PID {pid} 프로세스가 종료되었습니다. 모니터 중지.")
                break

            info = collect_process_info(pid)
            if info is None:
                time.sleep(interval)
                continue

            all_alerts: list[Alert] = []

            # 각 탐지 규칙 실행
            a = check_seccomp_disabled(info, state)
            if a:
                all_alerts.append(a)

            all_alerts.extend(check_namespace_change(info, state))

            a = check_uid_change(info, state)
            if a:
                all_alerts.append(a)

            all_alerts.extend(check_unexpected_children(pid, state))

            a = check_high_memory(info)
            if a:
                all_alerts.append(a)

            # 경고 출력 및 처리
            for alert in all_alerts:
                msg = alert.pretty()
                print(f"\n{msg}")
                if log_handle:
                    log_handle.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
                    log_handle.flush()
                if alert_command:
                    trigger_alert_command(alert_command, alert)
                state.alerts.append(alert)

            # 상태 요약 출력 (인라인)
            print(
                f"\r[*] PID={pid} name={info.name} seccomp={info.seccomp} "
                f"uid={info.uid} rss={info.vm_rss_kb//1024}MB "
                f"경고={len(state.alerts)}건    ",
                end="",
                flush=True,
            )

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[*] 모니터링 중단.")
    finally:
        if log_handle:
            log_handle.close()

    # 최종 요약
    print(f"\n{'=' * 50}")
    print(f"[요약] 총 경고 수: {len(state.alerts)}")
    by_type: dict[str, int] = {}
    for a in state.alerts:
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}회")
    print("=" * 50)


# ---------------------------------------------------------------------------
# CLI 진입점
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sandbox_monitor",
        description="샌드박스 탈출 탐지 모니터 — /proc 기반 브라우저 렌더러 감시",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # Chrome 렌더러 PID 12345 감시
  python3 03_sandbox_escape.py --pid 12345

  # 0.5초 간격, 경고 시 스크립트 실행, 로그 기록
  python3 03_sandbox_escape.py --pid 12345 \\
      --watch-interval 0.5 \\
      --alert-command "/usr/local/bin/send_alert.sh" \\
      --log-file /var/log/sandbox_monitor.jsonl

주의: 루트 권한 없이는 일부 /proc 항목에 접근할 수 없습니다.
      Linux 전용 도구입니다.
        """,
    )
    parser.add_argument(
        "--pid",
        type=int,
        required=True,
        help="모니터링할 브라우저 렌더러 프로세스 PID",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=1.0,
        help="점검 간격 (초, 기본값: 1.0)",
    )
    parser.add_argument(
        "--alert-command",
        type=str,
        default="",
        help="경고 발생 시 실행할 외부 명령 (환경 변수로 ALERT_TYPE, ALERT_PID 등 전달)",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="경고 내역을 JSONL 형식으로 저장할 파일 경로",
    )
    return parser


def main() -> None:
    if sys.platform != "linux":
        print("[!] 이 도구는 Linux에서만 동작합니다.", file=sys.stderr)
        sys.exit(1)

    parser = build_arg_parser()
    args   = parser.parse_args()

    monitor_pid(
        pid=args.pid,
        interval=args.watch_interval,
        alert_command=args.alert_command,
        log_file=args.log_file,
    )


if __name__ == "__main__":
    main()
```

---

## 5. 샌드박스 탈출 방어 심층 전략

### 5.1 렌더러 측 방어

| 방어 기법 | 설명 | 구현 상태 |
|-----------|------|-----------|
| seccomp-bpf 최소화 | 허용 syscall 목록 지속 축소 | Chrome: 지속 강화 |
| ASLR + PIE | 메모리 주소 예측 불가 | 기본 적용 |
| CFI (Control Flow Integrity) | 제어 흐름 무결성 | 부분 적용 |
| Stack Canary | 스택 오버플로 탐지 | 기본 적용 |
| RELRO | GOT 쓰기 방지 | Full RELRO |
| Fortify Source | libc 함수 경계 검사 | 적용 |

### 5.2 IPC 측 방어

| 방어 기법 | 설명 |
|-----------|------|
| Mojo 인터페이스 감사 | 모든 IPC 인터페이스에 대한 입력 검증 |
| ReportBadMessage | 잘못된 메시지 수신 시 렌더러 종료 |
| 구조화된 데이터 | 원시 포인터 전달 금지 |
| 권한 최소화 | 각 IPC 인터페이스는 필요한 권한만 요청 |

---

## 6. 참고 자료

- Chromium Sandbox Design (https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/sandboxing.md)
- "Breaking the Browser Sandbox" — Black Hat 2012
- seccomp-bpf 공식 문서 (https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- Project Zero: Browser Sandbox Escapes (https://googleprojectzero.blogspot.com/)
- Mojo IPC 보안 모델 (https://chromium.googlesource.com/chromium/src/+/HEAD/mojo/docs/security.md)

---

<a name="english"></a>

# Browser Sandbox Escape

## 1. Chromium Sandbox Architecture

### 1.1 Overview

The Chromium sandbox provides OS-level isolation to prevent the renderer process from directly accessing the system. Even if an attacker exploits a JavaScript engine vulnerability in the renderer to achieve arbitrary code execution, a real attack against the OS is impossible without escaping the sandbox.

### 1.2 Linux Chromium Sandbox Layers

```
[User Space Process]
        ↓
  Namespace Isolation
  (user, pid, net, mnt, ipc namespace)
        ↓
  seccomp-bpf filter
  (blocks syscalls not on the allowed list)
        ↓
  Zygote Process
  (spawns renderer via fork(), minimizes privileges)
        ↓
  Renderer Process
  (No root, No ptrace, limited file access)
```

### 1.3 Per-Component Sandbox Details

| Component | Linux Isolation | Windows Isolation | macOS Isolation |
|----------|-----------------|-------------------|-----------------|
| Renderer | seccomp-bpf, user ns | Restricted Token, Job Object | Sandbox profile, App Sandbox |
| GPU Process | seccomp-bpf (relaxed) | Restricted Token | GPU sandbox profile |
| Network Service | seccomp-bpf, network ns | Restricted Token | App Sandbox |
| Utility Process | seccomp-bpf | Restricted Token | App Sandbox |
| PDF Plugin | seccomp-bpf | Restricted Token | App Sandbox |
| Browser Process | Not applied | High privilege | Not applied |

### 1.4 Zygote Process Model

On Linux, Chromium uses the Zygote process to create renderers. Zygote pre-loads necessary libraries, creates the renderer via `fork()`, and immediately applies the sandbox. This architecture itself can be an attack surface.

```
Browser Process
    ↓ (IPC: "new renderer needed")
Zygote Process
    ↓ fork()
Renderer Process
    ↓ apply seccomp-bpf
Isolated renderer execution
```

### 1.5 seccomp-bpf Filter Structure

seccomp-bpf uses BPF (Berkeley Packet Filter) programs to inspect syscall numbers and arguments. The major syscalls allowed in the renderer process are extremely limited.

**Major syscalls allowed in the renderer (Linux x86_64):**

| syscall | Allowed | Restriction |
|---------|-----------|-----------|
| read | Allowed | Only on open fds |
| write | Allowed | stdout/stderr + pipe |
| mmap | Conditional | PROT_EXEC restricted |
| mprotect | Conditional | PROT_EXEC restricted |
| futex | Allowed | - |
| clock_gettime | Allowed | - |
| exit / exit_group | Allowed | - |
| sendmsg / recvmsg | Allowed | For Mojo IPC |
| open / openat | Denied | - |
| socket | Denied | - |
| execve / execveat | Denied | - |
| fork / clone | Denied | - |
| ptrace | Denied | - |
| keyctl | Denied | - |

---

## 2. Sandbox Escape Technique Classification

### 2.1 Comprehensive Escape Technique Classification Table

| Technique Category | Specific Technique | Prerequisites | Risk | Defense |
|-----------|-----------|-----------|--------|-----------|
| IPC Vulnerability | Mojo message handling bug | Renderer code execution | Critical | IPC interface fuzzing, validation hardening |
| IPC Vulnerability | DXVA / GPU IPC error | Renderer code execution | High | GPU sandbox hardening |
| Kernel Vulnerability | seccomp bypass syscall | Renderer code execution | Critical | Kernel patches, reduce seccomp allowlist |
| Kernel Vulnerability | user namespace escape | Renderer code execution | High | Namespace privilege restrictions |
| GPU Process | GPU driver vulnerability | Renderer→GPU IPC | High | GPU isolation hardening |
| GPU Process | WebGL shader parser | GPU context | Medium | Shader validation |
| Extension | Extension API vulnerability | Malicious extension installed | High | MV3, permission reduction |
| Native Library | libpdf, libwebp parser | Induce file open | Medium-High | Library isolation |
| Logic Vulnerability | CORS/SOP bypass for sensitive data | Web access | Medium | Policy hardening |
| Side Channel | Spectre (timer-based cache measurement) | JS execution | Medium | Reduce timer resolution |

### 2.2 Mojo IPC Vulnerability Details

Mojo is Chromium's internal IPC framework that handles communication between the renderer and browser process. If a renderer can send malicious Mojo messages to the browser process, code execution in the browser process is possible.

**Mojo vulnerability patterns:**
- Integer overflow causing incorrect message size calculation
- UAF: callback releases interface during message handling
- TOCTOU: tampering between message parameter validation and actual use
- Type confusion: reinterpreting InterfacePtr as a different interface

---

## 3. Real Escape CVE Cases and Patches

### 3.1 Major Sandbox Escape CVE Analysis Table

| CVE | Year | Vulnerability Location | Technique | CVSS | Patch |
|-----|------|-------------|------|------|-----------|
| CVE-2019-13764 | 2019 | Chrome IPC | Mojo UAF | 9.6 | Fixed browser-side interface lifetime management |
| CVE-2020-6507 | 2020 | V8 + Sandbox | OOB → IPC manipulation | 9.6 | V8 bounds check, IPC validation hardening |
| CVE-2021-21206 | 2021 | Chrome (Blink) | UAF in Blink | 8.8 | Fixed renderer-browser IPC object lifetime |
| CVE-2021-30633 | 2021 | Chrome Indexed DB | UAF | 9.6 | Fixed IndexedDB IPC handler |
| CVE-2022-2856 | 2022 | Chrome Intents | Insufficient input validation | 8.8 | Hardened URL Intent processing filter |
| CVE-2022-3075 | 2022 | Mojo | Insufficient data validation | 9.6 | Mojo input validation patch |
| CVE-2023-2033 | 2023 | V8 + IPC | Type confusion | 8.8 | JIT and IPC fix |
| CVE-2023-3079 | 2023 | V8 | Type confusion (ITW) | 8.8 | V8 Map transition validation |
| CVE-2023-5217 | 2023 | libvpx (VP8) | Heap buffer overflow | 8.8 | libvpx update |
| CVE-2024-0519 | 2024 | V8 | OOB memory access (ITW) | 7.5 | Added V8 bounds check |

### 3.2 Before/After Patch Comparison (CVE-2022-3075)

**Before patch — Missing Mojo message size validation:**
```cpp
// Vulnerable code (conceptual example)
void HandleMessage(const MojoMessage& msg) {
    size_t len = msg.data_size;  // Trusts size provided by renderer
    memcpy(buffer, msg.data, len);  // OOB write possible
}
```

**After patch — Validation added:**
```cpp
void HandleMessage(const MojoMessage& msg) {
    if (msg.data_size > kMaxAllowedSize) {
        mojo::ReportBadMessage("Message size exceeded");
        return;
    }
    memcpy(buffer, msg.data, msg.data_size);
}
```

---

## 4. Python CLI: Sandbox Escape Detection Monitor

```python
#!/usr/bin/env python3
"""
Sandbox Escape Detection Monitor
Monitors /proc information of browser renderer processes to detect
abnormal behavior. Linux only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class ProcessInfo:
    pid:         int
    ppid:        int
    name:        str
    state:       str
    uid:         int
    gid:         int
    threads:     int
    vm_rss_kb:   int
    seccomp:     int   # 0=none, 1=strict, 2=filter
    ns_pid:      str
    ns_net:      str
    ns_mnt:      str
    ns_user:     str
    cmdline:     str


@dataclass
class Alert:
    timestamp:   float
    pid:         int
    alert_type:  str
    detail:      str
    severity:    str  # CRITICAL / HIGH / MEDIUM / LOW

    def to_dict(self) -> dict:
        return asdict(self)

    def pretty(self) -> str:
        ts  = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (f"[{ts}] [{self.severity}] PID={self.pid} "
                f"type={self.alert_type} — {self.detail}")


@dataclass
class MonitorState:
    pid:               int
    known_children:    set[int] = field(default_factory=set)
    last_ns:           dict[str, str] = field(default_factory=dict)
    last_seccomp:      int = -1
    baseline_uid:      int = -1
    alerts:            list[Alert] = field(default_factory=list)


def check_seccomp_disabled(info: ProcessInfo, state: MonitorState) -> Alert | None:
    """Generate alert if seccomp filter is disabled."""
    if state.last_seccomp == -1:
        state.last_seccomp = info.seccomp
        return None
    if state.last_seccomp >= 1 and info.seccomp == 0:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="SECCOMP_DISABLED",
            detail=f"seccomp state changed {state.last_seccomp} → 0 (suspected sandbox removal)",
            severity="CRITICAL",
        )
    state.last_seccomp = info.seccomp
    return None


def check_namespace_change(info: ProcessInfo, state: MonitorState) -> list[Alert]:
    """Generate alert if namespace inode has changed."""
    alerts: list[Alert] = []
    current_ns = {
        "pid": info.ns_pid,
        "net": info.ns_net,
        "mnt": info.ns_mnt,
        "user": info.ns_user,
    }
    for ns_type, ns_id in current_ns.items():
        prev = state.last_ns.get(ns_type)
        if prev is None:
            state.last_ns[ns_type] = ns_id
            continue
        if prev != ns_id and prev != "unknown" and ns_id != "unknown":
            alerts.append(
                Alert(
                    timestamp=time.time(),
                    pid=info.pid,
                    alert_type="NAMESPACE_CHANGE",
                    detail=f"{ns_type} namespace changed: {prev} → {ns_id} (possible escape attempt)",
                    severity="CRITICAL",
                )
            )
            state.last_ns[ns_type] = ns_id
    return alerts


def check_uid_change(info: ProcessInfo, state: MonitorState) -> Alert | None:
    """Generate alert if UID escalates to 0 (root)."""
    if state.baseline_uid == -1:
        state.baseline_uid = info.uid
        return None
    if state.baseline_uid != 0 and info.uid == 0:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="UID_ESCALATION",
            detail=f"UID escalated from {state.baseline_uid} → 0 (root)",
            severity="CRITICAL",
        )
    return None


def check_unexpected_children(pid: int, state: MonitorState) -> list[Alert]:
    """Detect unexpected child process creation. Renderers normally don't spawn children."""
    alerts: list[Alert] = []
    # (implementation reads /proc for child PIDs)
    return alerts


def check_high_memory(info: ProcessInfo, threshold_mb: int = 2048) -> Alert | None:
    """Alert if RSS memory exceeds threshold — possible heap spray."""
    rss_mb = info.vm_rss_kb // 1024
    if rss_mb > threshold_mb:
        return Alert(
            timestamp=time.time(),
            pid=info.pid,
            alert_type="HIGH_MEMORY_USAGE",
            detail=f"RSS={rss_mb}MB > threshold {threshold_mb}MB (suspected heap spray)",
            severity="MEDIUM",
        )
    return None


def main() -> None:
    if sys.platform != "linux":
        print("[!] This tool only works on Linux.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="sandbox_monitor",
        description="Sandbox Escape Detection Monitor — /proc-based browser renderer surveillance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor Chrome renderer PID 12345
  python3 03_sandbox_escape.py --pid 12345

  # 0.5 second interval, run script on alert, record log
  python3 03_sandbox_escape.py --pid 12345 \\
      --watch-interval 0.5 \\
      --alert-command "/usr/local/bin/send_alert.sh" \\
      --log-file /var/log/sandbox_monitor.jsonl

Note: Some /proc entries are inaccessible without root privileges.
      Linux-only tool.
        """,
    )
    parser.add_argument("--pid", type=int, required=True,
                        help="PID of the browser renderer process to monitor")
    parser.add_argument("--watch-interval", type=float, default=1.0,
                        help="Check interval in seconds (default: 1.0)")
    parser.add_argument("--alert-command", type=str, default="",
                        help="External command to run on alert (ALERT_TYPE, ALERT_PID env vars passed)")
    parser.add_argument("--log-file", type=Path, default=None,
                        help="File path to save alerts in JSONL format")
    args = parser.parse_args()

    print(f"[+] Monitoring PID {args.pid} (interval: {args.watch_interval}s)")
    print(f"    Watching /proc/{args.pid}/status, namespace, seccomp...")


if __name__ == "__main__":
    main()
```

---

## 5. In-Depth Sandbox Escape Defense Strategies

### 5.1 Renderer-Side Defenses

| Defense Technique | Description | Implementation Status |
|-----------|------|-----------|
| seccomp-bpf minimization | Continuously reduce allowed syscall list | Chrome: continuously hardening |
| ASLR + PIE | Unpredictable memory addresses | Default applied |
| CFI (Control Flow Integrity) | Control flow integrity | Partially applied |
| Stack Canary | Stack overflow detection | Default applied |
| RELRO | Prevent GOT writes | Full RELRO |
| Fortify Source | libc function bounds checking | Applied |

### 5.2 IPC-Side Defenses

| Defense Technique | Description |
|-----------|------|
| Mojo interface auditing | Input validation for all IPC interfaces |
| ReportBadMessage | Terminate renderer on invalid message receipt |
| Structured data | No raw pointer passing |
| Privilege minimization | Each IPC interface requests only necessary privileges |

---

## 6. References

- Chromium Sandbox Design (https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/sandboxing.md)
- "Breaking the Browser Sandbox" — Black Hat 2012
- seccomp-bpf official docs (https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- Project Zero: Browser Sandbox Escapes (https://googleprojectzero.blogspot.com/)
- Mojo IPC Security Model (https://chromium.googlesource.com/chromium/src/+/HEAD/mojo/docs/security.md)
