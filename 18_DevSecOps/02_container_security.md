> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 컨테이너 보안 완전 가이드

## 0. 초보자를 위한 개념 이해

### 컨테이너 보안이란?

컨테이너(Docker, Kubernetes)는 현대 인프라의 표준이지만, 잘못된 설정은 컨테이너 탈출(Host 권한 획득), 비밀 키 노출, 이미지 취약점 등 심각한 보안 위협을 만들어냅니다. 컨테이너 보안은 이미지 빌드 단계부터 런타임, 오케스트레이션(K8s)까지 전 레이어를 포함합니다. DevSecOps 파이프라인에서 컨테이너 이미지 스캔은 필수 단계입니다.

**왜 배우는가:**
```
컨테이너 보안 취약점의 실제 사례:

  Docker --privileged 실행
    → 컨테이너가 호스트 파일시스템 전체 접근
    → cgroup 탈출로 호스트 셸 획득

  Docker 소켓 마운트 (-v /var/run/docker.sock)
    → 컨테이너 내에서 호스트의 모든 컨테이너 제어
    → 새 --privileged 컨테이너 생성으로 호스트 장악

  Kubernetes RBAC 오설정
    → ServiceAccount에 cluster-admin 부여
    → 파드에서 K8s API로 전체 클러스터 제어

  공개 Docker Hub 이미지
    → CVE 수백 개 포함 가능
    → 악성 코드 삽입된 이미지 게시 사례
```

### 핵심 개념 정리

```
컨테이너 보안 핵심 원칙:

  이미지 보안
    □ 최소 기반 이미지 (alpine, distroless)
    □ 비루트 사용자 실행 (USER appuser)
    □ 읽기 전용 파일시스템 (--read-only)
    □ 정기적 취약점 스캔 (Trivy, Grype)

  런타임 보안
    □ --privileged 절대 금지
    □ 도커 소켓 마운트 금지
    □ capabilities 최소화 (--cap-drop ALL)
    □ seccomp 프로파일 적용

  Kubernetes 보안
    □ RBAC 최소 권한 (ServiceAccount별 분리)
    □ NetworkPolicy로 파드 간 통신 제한
    □ PodSecurityContext runAsNonRoot: true
    □ Secret 암호화 (etcd at-rest encryption)
```

### 필요한 도구 및 환경
- **Trivy**: 컨테이너 이미지 및 파일시스템 취약점 스캐너
- **Falco**: 런타임 컨테이너 이상 행위 탐지
- **kube-bench**: Kubernetes CIS 벤치마크 자동 점검
- **Docker Desktop**: 로컬 컨테이너 개발 환경

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""Docker 컨테이너 보안 설정 감사 — 위험 설정 자동 탐지."""

import subprocess
import json
from dataclasses import dataclass, field


@dataclass
class ContainerAuditResult:
    container_id: str
    container_name: str
    risks: list[str] = field(default_factory=list)
    risk_level: str = "low"


def audit_container(container_id: str) -> ContainerAuditResult:
    """실행 중인 컨테이너의 보안 설정을 감사합니다."""
    result_raw = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True, text=True,
    )
    if result_raw.returncode != 0:
        return ContainerAuditResult(container_id, "unknown", ["inspect 실패"])

    info = json.loads(result_raw.stdout)[0]
    name = info.get("Name", "").lstrip("/")
    audit = ContainerAuditResult(container_id=container_id, container_name=name)

    host_config = info.get("HostConfig", {})

    # 1. Privileged 모드 확인
    if host_config.get("Privileged", False):
        audit.risks.append("[Critical] Privileged 모드 실행!")
        audit.risk_level = "critical"

    # 2. Docker 소켓 마운트 확인
    binds = host_config.get("Binds") or []
    for bind in binds:
        if "docker.sock" in bind:
            audit.risks.append("[Critical] Docker 소켓 마운트!")
            audit.risk_level = "critical"

    # 3. root 사용자 실행 확인
    user = info.get("Config", {}).get("User", "")
    if not user or user == "root" or user == "0":
        audit.risks.append("[High] root 사용자로 실행 중")
        if audit.risk_level not in ("critical",):
            audit.risk_level = "high"

    # 4. 읽기-쓰기 파일시스템 확인
    if not host_config.get("ReadonlyRootfs", False):
        audit.risks.append("[Medium] 쓰기 가능한 루트 파일시스템")

    return audit


if __name__ == "__main__":
    # 실행 중인 컨테이너 목록 가져오기
    ps = subprocess.run(
        ["docker", "ps", "-q"],
        capture_output=True, text=True,
    )
    container_ids = ps.stdout.strip().splitlines()
    if not container_ids:
        print("실행 중인 컨테이너 없음. Docker 환경에서 실행하세요.")
    else:
        for cid in container_ids:
            result = audit_container(cid)
            print(f"\n[{result.risk_level.upper()}] {result.container_name}")
            for risk in result.risks:
                print(f"  {risk}")
```

---

## 컨테이너 보안 위협 모델

```
컨테이너 공격 표면
─────────────────────────────────────────
이미지 레이어          런타임 환경         오케스트레이션
    │                      │                    │
취약한 베이스          컨테이너 이스케이프   K8s RBAC 오설정
하드코딩 시크릿        특권 실행            노출된 API 서버
악성 레이어 삽입       Host 마운트          etcd 평문 저장
─────────────────────────────────────────
```

---

## 1. Docker 이미지 보안

### 안전한 Dockerfile 작성


컨테이너 보안 점검 명령어입니다. 컨테이너는 경량화 환경이지만 잘못 설정된 권한, 불필요한 capabilities, 루트 실행 등이 탈출 취약점으로 이어질 수 있습니다.

```dockerfile
# ✅ 보안 강화된 Dockerfile

# 1. 공식 최소 베이스 이미지 사용 (alpine/distroless)
FROM python:3.12-slim AS builder

# 2. 비루트 사용자 생성
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 3. 패키지 설치 후 캐시 정리
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# 4. 의존성 먼저 복사 (레이어 캐시 활용)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 소스 복사
COPY --chown=appuser:appuser . .

# 6. 멀티스테이지 빌드 (빌드 도구 제거)
FROM python:3.12-slim AS runtime

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder --chown=appuser:appuser /app .

# 7. 비루트 실행
USER appuser

# 8. 읽기 전용 파일시스템 (런타임 설정)
# --read-only 플래그로 실행

# 9. 헬스체크
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Dockerfile로 컨테이너 이미지를 정의합니다. 보안 관점에서 최소 권한 원칙을 적용하여 불필요한 패키지와 루트 실행을 피해야 합니다.

```dockerfile
# ❌ 취약한 Dockerfile 예시
FROM ubuntu:latest          # 최신 태그 - 불안정
RUN apt-get install -y wget curl git  # 불필요한 도구
ADD . /app                  # ADD 대신 COPY 사용
WORKDIR /app
RUN pip install -r requirements.txt
ENV DB_PASSWORD="secret123"  # 시크릿 하드코딩!
EXPOSE 22                   # SSH 노출
USER root                   # 루트 실행!
CMD ["python", "app.py"]
```

### Trivy — 이미지 취약점 스캔


컨테이너 이미지 취약점 스캐너입니다. `trivy image`로 도커 이미지 내 OS 패키지와 언어 라이브러리의 알려진 CVE를 검사하여 CI/CD 파이프라인에 통합할 수 있습니다.

```bash
# ── Trivy 설치 ────────────────────────────────────────────────
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── 이미지 취약점 스캔 ───────────────────────────────────────
# 기본 스캔
trivy image nginx:latest

# 심각도 필터 (CRITICAL, HIGH 만)
trivy image --severity CRITICAL,HIGH python:3.12-slim

# JSON 출력 (파이프라인 연동)
trivy image --format json --output trivy-results.json myapp:v1.0

# SARIF 출력 (GitHub Security 탭 업로드)
trivy image --format sarif --output trivy-results.sarif \
    --severity CRITICAL,HIGH myapp:latest

# Critical 발견 시 exit-code 1 (CI 빌드 실패)
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# ── 파일시스템 / Dockerfile / IaC 스캔 ──────────────────────
# 소스코드 전체 (취약 의존성 + 시크릿 + 설정 오류)
trivy fs --scanners vuln,secret,misconfig ./

# Dockerfile 설정 분석
trivy config Dockerfile

# Terraform / Kubernetes 매니페스트
trivy config ./terraform/
trivy config ./k8s/

# ── SBOM 생성 + 취약점 스캔 ─────────────────────────────────
# Syft로 SBOM 생성
syft myapp:v1.0 -o spdx-json=sbom.spdx.json

# SBOM 기반 취약점 스캔 (Grype)
grype sbom:sbom.spdx.json
grype myapp:v1.0 --output json --file grype-results.json

# ── 결과 파싱 Python 스크립트 ────────────────────────────────
python3 - << 'EOF'
import json, sys
with open("trivy-results.json") as f:
    data = json.load(f)

crit = high = 0
for result in data.get("Results", []):
    for v in result.get("Vulnerabilities") or []:
        sev = v.get("Severity", "")
        if sev == "CRITICAL": crit += 1
        elif sev == "HIGH":   high += 1
        if sev in ("CRITICAL", "HIGH"):
            print(f"[{sev}] {v.get('VulnerabilityID')} "
                  f"{v.get('PkgName')}@{v.get('InstalledVersion')} "
                  f"→ fix: {v.get('FixedVersion','N/A')}")

print(f"\nCRITICAL={crit}  HIGH={high}")
if crit > 0:
    sys.exit(1)   # CI 게이트
EOF
```

### Docker Bench Security


컨테이너 보안 점검 명령어입니다. 컨테이너는 경량화 환경이지만 잘못 설정된 권한, 불필요한 capabilities, 루트 실행 등이 탈출 취약점으로 이어질 수 있습니다.

```bash
# CIS Docker 벤치마크 자동 검사
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh

# 결과 분류:
# [PASS] - 설정 양호
# [WARN] - 검토 필요
# [INFO] - 정보
# [NOTE] - 권고사항

# 주요 점검 항목:
# 1.1 Docker 호스트 전용 OS 사용
# 2.1 컨테이너 간 네트워크 트래픽 제한
# 2.2 로깅 레벨 설정
# 2.14 live restore 활성화
# 4.1 루트가 아닌 사용자로 실행
# 4.5 Content Trust 활성화
# 5.3 특권 컨테이너 금지
# 5.4 민감 호스트 디렉토리 마운트 금지
```

---

## 2. 런타임 보안

### Docker 런타임 보안 옵션

```bash
# 보안 강화 실행 옵션
docker run \
    --read-only \                          # 읽기 전용 루트 파일시스템
    --tmpfs /tmp \                         # tmpfs로 임시 파일 허용
    --no-new-privileges \                  # 권한 상승 금지
    --security-opt=no-new-privileges \
    --security-opt seccomp=seccomp.json \  # Seccomp 프로필
    --cap-drop=ALL \                       # 모든 Capability 제거
    --cap-add=NET_BIND_SERVICE \          # 필요한 것만 추가
    --user 1000:1000 \                    # 비루트 사용자
    --memory=512m \                       # 메모리 제한
    --cpus=0.5 \                          # CPU 제한
    --network=internal \                  # 격리된 네트워크
    myapp:latest

# Seccomp 프로필 생성
cat > seccomp.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": ["read", "write", "open", "close", "stat", 
                     "fstat", "lstat", "poll", "lseek", "mmap",
                     "mprotect", "munmap", "brk", "rt_sigaction",
                     "rt_sigprocmask", "ioctl", "access", "pipe",
                     "select", "sched_yield", "mremap", "msync",
                     "mincore", "madvise", "dup", "dup2", "nanosleep",
                     "getitimer", "alarm", "setitimer", "getpid",
                     "sendfile", "socket", "connect", "accept",
                     "sendto", "recvfrom", "sendmsg", "recvmsg",
                     "shutdown", "bind", "listen", "getsockname",
                     "getpeername", "socketpair", "setsockopt",
                     "getsockopt", "clone", "fork", "vfork",
                     "execve", "exit", "wait4", "kill", "uname",
                     "fcntl", "flock", "fsync", "fdatasync",
                     "truncate", "ftruncate", "getdents", "getcwd",
                     "chdir", "rename", "mkdir", "rmdir", "creat",
                     "link", "unlink", "symlink", "readlink", "chmod",
                     "fchmod", "chown", "fchown", "lchown", "umask",
                     "gettimeofday", "getrlimit", "getrusage",
                     "sysinfo", "times", "ptrace", "getuid", "syslog",
                     "getgid", "setuid", "setgid", "geteuid",
                     "getegid", "setpgid", "getppid", "getpgrp",
                     "setsid", "setreuid", "setregid", "getgroups",
                     "setgroups", "setresuid", "getresuid",
                     "setresgid", "getresgid", "getpgid", "setfsuid",
                     "setfsgid", "getsid", "capget", "capset",
                     "rt_sigpending", "rt_sigtimedwait",
                     "rt_sigqueueinfo", "rt_sigsuspend",
                     "sigaltstack", "utime", "mknod", "uselib",
                     "personality", "ustat", "statfs", "fstatfs",
                     "sysfs", "getpriority", "setpriority",
                     "sched_setparam", "sched_getparam",
                     "sched_setscheduler", "sched_getscheduler",
                     "sched_get_priority_max",
                     "sched_get_priority_min",
                     "sched_rr_get_interval", "mlock", "munlock",
                     "mlockall", "munlockall", "vhangup", "modify_ldt",
                     "pivot_root", "_sysctl", "prctl", "arch_prctl",
                     "adjtimex", "setrlimit", "chroot", "sync",
                     "acct", "settimeofday", "mount", "umount2",
                     "swapon", "swapoff", "reboot", "sethostname",
                     "setdomainname", "iopl", "ioperm",
                     "create_module", "init_module", "delete_module",
                     "get_kernel_syms", "query_module", "quotactl",
                     "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
                     "tuxcall", "security", "gettid", "readahead",
                     "setxattr", "lsetxattr", "fsetxattr", "getxattr",
                     "lgetxattr", "fgetxattr", "listxattr",
                     "llistxattr", "flistxattr", "removexattr",
                     "lremovexattr", "fremovexattr", "tkill", "time",
                     "futex", "sched_setaffinity", "sched_getaffinity",
                     "set_thread_area", "io_setup", "io_destroy",
                     "io_getevents", "io_submit", "io_cancel",
                     "get_thread_area", "lookup_dcookie",
                     "epoll_create", "epoll_ctl_old",
                     "epoll_wait_old", "remap_file_pages",
                     "getdents64", "set_tid_address", "restart_syscall",
                     "semtimedop", "fadvise64", "timer_create",
                     "timer_settime", "timer_gettime",
                     "timer_getoverrun", "timer_delete",
                     "clock_settime", "clock_gettime",
                     "clock_getres", "clock_nanosleep",
                     "exit_group", "epoll_wait", "epoll_ctl",
                     "tgkill", "utimes", "vserver", "mbind",
                     "set_mempolicy", "get_mempolicy",
                     "mq_open", "mq_unlink", "mq_timedsend",
                     "mq_timedreceive", "mq_notify",
                     "mq_getsetattr", "kexec_load", "waitid",
                     "add_key", "request_key", "keyctl",
                     "ioprio_set", "ioprio_get", "inotify_init",
                     "inotify_add_watch", "inotify_rm_watch",
                     "migrate_pages", "openat", "mkdirat",
                     "mknodat", "fchownat", "futimesat",
                     "newfstatat", "unlinkat", "renameat",
                     "linkat", "symlinkat", "readlinkat",
                     "fchmodat", "faccessat", "pselect6",
                     "ppoll", "unshare", "set_robust_list",
                     "get_robust_list", "splice", "tee",
                     "sync_file_range", "vmsplice",
                     "move_pages", "utimensat",
                     "epoll_pwait", "signalfd",
                     "timerfd_create", "eventfd",
                     "fallocate", "timerfd_settime",
                     "timerfd_gettime", "accept4", "signalfd4",
                     "eventfd2", "epoll_create1", "dup3",
                     "pipe2", "inotify_init1", "preadv",
                     "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
                     "recvmmsg", "fanotify_init",
                     "fanotify_mark", "prlimit64", "name_to_handle_at",
                     "open_by_handle_at", "clock_adjtime", "syncfs",
                     "sendmmsg", "setns", "getcpu",
                     "process_vm_readv", "process_vm_writev",
                     "kcmp", "finit_module"],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
EOF
```

### Falco — 런타임 위협 탐지

```bash
# Falco 설치
curl -s https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor | \
    sudo tee /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
    https://download.falco.org/packages/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco

# Falco 규칙 예시
```

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# custom_falco_rules.yaml
- rule: 컨테이너 내 쉘 실행
  desc: 컨테이너 안에서 쉘이 실행됨 (침해 지표)
  condition: >
    spawned_process and
    container and
    not container.image.repository in (allowed_shell_containers) and
    proc.name in (shell_binaries)
  output: >
    컨테이너 내 쉘 실행 (user=%user.name container=%container.id 
    image=%container.image.repository cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, shell]

- rule: 민감 파일 접근
  desc: /etc/shadow, /etc/passwd 등 민감 파일 읽기
  condition: >
    open_read and
    container and
    fd.name in (/etc/shadow, /etc/sudoers, /root/.ssh/authorized_keys)
  output: >
    민감 파일 접근 (user=%user.name container=%container.id 
    file=%fd.name)
  priority: ERROR
  tags: [container, filesystem]

- rule: 외부 네트워크 연결 (예상치 못한)
  desc: 허가되지 않은 외부 IP 연결
  condition: >
    outbound and
    container and
    not fd.rip in (allowed_outbound_ips) and
    not fd.rport in (80, 443, 53)
  output: >
    예상치 못한 외부 연결 (container=%container.id 
    dst=%fd.rip:%fd.rport)
  priority: WARNING
  tags: [network, container]
```

```bash
# Falco 실행 (커스텀 규칙 포함)
sudo falco -r custom_falco_rules.yaml

# Kubernetes에서 Falco (Helm)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
    --set driver.kind=ebpf \
    --set falcosidekick.enabled=true \
    --set falcosidekick.config.slack.webhookurl=SLACK_HOOK

# Falco 실시간 알림 수신 (Python)
# falcosidekick → webhook → 아래 스크립트로 Slack/PagerDuty 전달
```

```python
#!/usr/bin/env python3
"""
Falco 알림 Webhook 수신 서버 + 심각도 기반 자동 대응
사용: python3 falco_webhook.py --port 2802 --slack-url https://hooks.slack.com/...
      환경변수: SLACK_WEBHOOK_URL, PAGERDUTY_KEY

Falco → falcosidekick → POST http://this-server:2802/falco
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("falco-webhook")

# ── 설정 (환경변수 또는 CLI) ──────────────────────────────────

SLACK_URL      = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_KEY  = os.getenv("PAGERDUTY_KEY", "")
ALERT_HISTORY: list[dict] = []


# ── 대응 함수 ─────────────────────────────────────────────────

def send_slack(event: dict, slack_url: str) -> None:
    priority = event.get("priority", "").upper()
    name     = event.get("rule", "Unknown Rule")
    output   = event.get("output", "")
    ts       = event.get("time", datetime.utcnow().isoformat())

    color = {"CRITICAL": "#FF0000", "ERROR": "#FF6600",
             "WARNING": "#FFCC00"}.get(priority, "#999999")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"[Falco {priority}] {name}",
            "text": output[:500],
            "footer": f"Container Security | {ts}",
        }]
    }
    try:
        requests.post(slack_url, json=payload, timeout=10)
        logger.info("Slack 알림 전송: %s", name)
    except requests.RequestException as e:
        logger.error("Slack 전송 실패: %s", e)


def trigger_pagerduty(event: dict, key: str) -> None:
    """CRITICAL 이벤트를 PagerDuty 인시던트로 에스컬레이션"""
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "dedup_key": event.get("rule", "falco") + "_" + event.get("hostname", ""),
        "payload": {
            "summary": f"[Falco CRITICAL] {event.get('rule','?')}",
            "severity": "critical",
            "source": event.get("hostname", "unknown"),
            "custom_details": event,
        },
    }
    try:
        requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload, timeout=10,
        )
        logger.info("PagerDuty 에스컬레이션: %s", event.get("rule"))
    except requests.RequestException as e:
        logger.error("PagerDuty 실패: %s", e)


def handle_event(event: dict, slack_url: str, pd_key: str) -> None:
    priority = event.get("priority", "").upper()
    ALERT_HISTORY.append({"time": datetime.utcnow().isoformat(),
                           "priority": priority,
                           "rule": event.get("rule", "")})

    logger.warning("[%s] %s | %s",
                   priority, event.get("rule"), event.get("output", "")[:120])

    if priority in ("WARNING", "ERROR", "CRITICAL") and slack_url:
        send_slack(event, slack_url)

    if priority == "CRITICAL" and pd_key:
        trigger_pagerduty(event, pd_key)


# ── HTTP 핸들러 ───────────────────────────────────────────────

def make_handler(slack_url: str, pd_key: str) -> type:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            pass  # 기본 로그 억제

        def do_POST(self) -> None:
            if self.path != "/falco":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                event = json.loads(body)
                handle_event(event, slack_url, pd_key)
                self.send_response(200)
            except (json.JSONDecodeError, Exception) as e:
                logger.error("이벤트 파싱 오류: %s", e)
                self.send_response(400)
            self.end_headers()

        def do_GET(self) -> None:
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            elif self.path == "/stats":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                from collections import Counter
                cnt = Counter(a["priority"] for a in ALERT_HISTORY)
                self.wfile.write(
                    json.dumps({"total": len(ALERT_HISTORY),
                                "by_priority": dict(cnt)}).encode()
                )
            else:
                self.send_response(404)
                self.end_headers()

    return Handler


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Falco Webhook 수신 서버")
    parser.add_argument("--port",      type=int, default=2802)
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--slack-url", default=SLACK_URL)
    parser.add_argument("--pd-key",    default=PAGERDUTY_KEY,
                        help="PagerDuty Routing Key")
    args = parser.parse_args()

    handler = make_handler(args.slack_url, args.pd_key)
    server  = HTTPServer((args.host, args.port), handler)

    logger.info("Falco Webhook 서버 시작: %s:%d", args.host, args.port)
    if args.slack_url:
        logger.info("Slack 알림: 활성화")
    if args.pd_key:
        logger.info("PagerDuty 에스컬레이션: 활성화")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("서버 종료")


if __name__ == "__main__":
    main()
```

---

## 3. Kubernetes 보안 강화

### Pod Security Standards

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# namespace-security.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Baseline: 기본 보안 (특권 컨테이너 금지)
    # Restricted: 최고 보안 (권장)
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# restricted Pod 요구사항
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault  # 기본 Seccomp 프로필
  
  containers:
  - name: app
    image: myapp:1.0.0  # latest 태그 금지
    
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
    
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "250m"
    
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  
  automountServiceAccountToken: false  # SA 토큰 자동 마운트 비활성화
```

### RBAC 최소 권한 설정

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# rbac-minimal.yaml
# 최소 권한 ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
---
# 읽기 전용 Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: myapp-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]  # 읽기만
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["myapp-secret"]  # 특정 시크릿만
  verbs: ["get"]
---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: myapp-rolebinding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: myapp-role
subjects:
- kind: ServiceAccount
  name: myapp-sa
  namespace: production
```

### NetworkPolicy — 마이크로세그멘테이션

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# network-policy.yaml
# 기본: 모든 인바운드/아웃바운드 차단
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# API 서버만 DB 접근 허용
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-server
    ports:
    - protocol: TCP
      port: 5432
---
# 외부 DNS/HTTPS만 허용
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53       # DNS
      protocol: UDP
    - port: 443      # HTTPS
      protocol: TCP
```

---

## 4. 이미지 공급망 보안

### Cosign — 이미지 서명

```bash
# cosign 설치
curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.2.0/cosign-linux-amd64 \
    -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

# 키 생성
cosign generate-key-pair

# 이미지 서명
cosign sign --key cosign.key registry.io/myapp:v1.0

# 서명 검증
cosign verify --key cosign.pub registry.io/myapp:v1.0

# Keyless 서명 (Sigstore/OIDC)
COSIGN_EXPERIMENTAL=1 cosign sign registry.io/myapp:v1.0
COSIGN_EXPERIMENTAL=1 cosign verify registry.io/myapp:v1.0

# Kubernetes에서 서명 검증 강제 (policy-controller)
helm install policy-controller sigstore/policy-controller
```

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# cluster-image-policy.yaml - 서명된 이미지만 허용
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images-only
spec:
  images:
  - glob: "registry.io/**"
  authorities:
  - key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
        -----END PUBLIC KEY-----
```

### SBOM (Software Bill of Materials)

```bash
# Syft로 SBOM 생성
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 이미지 SBOM
syft registry.io/myapp:v1.0 -o spdx-json=sbom.spdx.json

# Grype로 SBOM 취약점 스캔
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

grype sbom:sbom.spdx.json
grype registry.io/myapp:v1.0
```

---

## 5. Docker Compose 보안 설정


컨테이너 보안 점검 명령어입니다. 컨테이너는 경량화 환경이지만 잘못 설정된 권한, 불필요한 capabilities, 루트 실행 등이 탈출 취약점으로 이어질 수 있습니다.

```yaml
# docker-compose.secure.yml
version: '3.8'

services:
  app:
    image: myapp:1.0.0
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp
      - /var/cache
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # 필요 시만
    networks:
      - internal
    environment:
      - APP_ENV=production
    secrets:
      - db_password
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  db:
    image: postgres:16-alpine
    user: "999:999"
    read_only: true
    tmpfs:
      - /tmp
      - /run/postgresql
    environment:
      - POSTGRES_DB=mydb
      - POSTGRES_USER_FILE=/run/secrets/db_user
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - type: volume
        source: db_data
        target: /var/lib/postgresql/data
        read_only: false
    networks:
      - internal
    secrets:
      - db_user
      - db_password
    security_opt:
      - no-new-privileges:true

networks:
  internal:
    internal: true  # 외부 연결 차단
  external:
    driver: bridge

volumes:
  db_data:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
  db_user:
    file: ./secrets/db_user.txt
```

---

<a name="english"></a>

# Complete Guide to Container Security

## Container Security Threat Model

```
Container Attack Surface
─────────────────────────────────────────
Image Layers           Runtime Environment    Orchestration
    │                        │                     │
Vulnerable base image   Container escape      K8s RBAC misconfiguration
Hardcoded secrets       Privileged execution  Exposed API server
Malicious layer inject  Host mount            etcd plaintext storage
─────────────────────────────────────────
```

---

## 1. Docker Image Security

### Writing a Secure Dockerfile

Container security check commands. Although containers are lightweight environments, misconfigured permissions, unnecessary capabilities, and running as root can lead to container escape vulnerabilities.

```dockerfile
# ✅ Security-hardened Dockerfile

# 1. Use official minimal base image (alpine/distroless)
FROM python:3.12-slim AS builder

# 2. Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 3. Clean up package cache after installation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# 4. Copy dependencies first (leverage layer cache)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy source code
COPY --chown=appuser:appuser . .

# 6. Multi-stage build (remove build tools)
FROM python:3.12-slim AS runtime

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder --chown=appuser:appuser /app .

# 7. Run as non-root user
USER appuser

# 8. Read-only filesystem (runtime config)
# Run with --read-only flag

# 9. Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

A Dockerfile defines a container image. From a security perspective, apply the principle of least privilege by avoiding unnecessary packages and root execution.

```dockerfile
# ❌ Vulnerable Dockerfile example
FROM ubuntu:latest          # latest tag - unstable
RUN apt-get install -y wget curl git  # unnecessary tools
ADD . /app                  # use COPY instead of ADD
WORKDIR /app
RUN pip install -r requirements.txt
ENV DB_PASSWORD="secret123"  # hardcoded secret!
EXPOSE 22                   # SSH exposed
USER root                   # running as root!
CMD ["python", "app.py"]
```

### Trivy — Image Vulnerability Scanning

Container image vulnerability scanner. Use `trivy image` to check known CVEs in OS packages and language libraries within Docker images; it can be integrated into CI/CD pipelines.

```bash
# ── Install Trivy ────────────────────────────────────────────
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Image vulnerability scan ─────────────────────────────────
# Basic scan
trivy image nginx:latest

# Severity filter (CRITICAL and HIGH only)
trivy image --severity CRITICAL,HIGH python:3.12-slim

# JSON output (pipeline integration)
trivy image --format json --output trivy-results.json myapp:v1.0

# SARIF output (upload to GitHub Security tab)
trivy image --format sarif --output trivy-results.sarif \
    --severity CRITICAL,HIGH myapp:latest

# Exit code 1 on CRITICAL findings (fail CI build)
trivy image --exit-code 1 --severity CRITICAL myapp:latest

# ── Filesystem / Dockerfile / IaC scan ──────────────────────
# Full source scan (vulnerable dependencies + secrets + misconfig)
trivy fs --scanners vuln,secret,misconfig ./

# Dockerfile configuration analysis
trivy config Dockerfile

# Terraform / Kubernetes manifests
trivy config ./terraform/
trivy config ./k8s/

# ── SBOM generation + vulnerability scan ─────────────────────
# Generate SBOM with Syft
syft myapp:v1.0 -o spdx-json=sbom.spdx.json

# SBOM-based vulnerability scan (Grype)
grype sbom:sbom.spdx.json
grype myapp:v1.0 --output json --file grype-results.json

# ── Python script to parse results ───────────────────────────
python3 - << 'EOF'
import json, sys
with open("trivy-results.json") as f:
    data = json.load(f)

crit = high = 0
for result in data.get("Results", []):
    for v in result.get("Vulnerabilities") or []:
        sev = v.get("Severity", "")
        if sev == "CRITICAL": crit += 1
        elif sev == "HIGH":   high += 1
        if sev in ("CRITICAL", "HIGH"):
            print(f"[{sev}] {v.get('VulnerabilityID')} "
                  f"{v.get('PkgName')}@{v.get('InstalledVersion')} "
                  f"→ fix: {v.get('FixedVersion','N/A')}")

print(f"\nCRITICAL={crit}  HIGH={high}")
if crit > 0:
    sys.exit(1)   # CI gate
EOF
```

### Docker Bench Security

Container security check commands. Although containers are lightweight environments, misconfigured permissions, unnecessary capabilities, and running as root can lead to container escape vulnerabilities.

```bash
# Automated CIS Docker benchmark check
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh

# Result classification:
# [PASS] - Configuration is good
# [WARN] - Needs review
# [INFO] - Informational
# [NOTE] - Recommendation

# Key check items:
# 1.1 Use a dedicated OS for the Docker host
# 2.1 Restrict network traffic between containers
# 2.2 Configure logging level
# 2.14 Enable live restore
# 4.1 Run as a non-root user
# 4.5 Enable Content Trust
# 5.3 Prohibit privileged containers
# 5.4 Prohibit mounting sensitive host directories
```

---

## 2. Runtime Security

### Docker Runtime Security Options

```bash
# Security-hardened run options
docker run \
    --read-only \                          # Read-only root filesystem
    --tmpfs /tmp \                         # Allow temp files via tmpfs
    --no-new-privileges \                  # Prohibit privilege escalation
    --security-opt=no-new-privileges \
    --security-opt seccomp=seccomp.json \  # Seccomp profile
    --cap-drop=ALL \                       # Drop all capabilities
    --cap-add=NET_BIND_SERVICE \          # Add only what's needed
    --user 1000:1000 \                    # Non-root user
    --memory=512m \                       # Memory limit
    --cpus=0.5 \                          # CPU limit
    --network=internal \                  # Isolated network
    myapp:latest

# Create Seccomp profile
cat > seccomp.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": ["read", "write", "open", "close", "stat", 
                     "fstat", "lstat", "poll", "lseek", "mmap",
                     "mprotect", "munmap", "brk", "rt_sigaction",
                     "rt_sigprocmask", "ioctl", "access", "pipe",
                     "select", "sched_yield", "mremap", "msync",
                     "mincore", "madvise", "dup", "dup2", "nanosleep",
                     "getitimer", "alarm", "setitimer", "getpid",
                     "sendfile", "socket", "connect", "accept",
                     "sendto", "recvfrom", "sendmsg", "recvmsg",
                     "shutdown", "bind", "listen", "getsockname",
                     "getpeername", "socketpair", "setsockopt",
                     "getsockopt", "clone", "fork", "vfork",
                     "execve", "exit", "wait4", "kill", "uname",
                     "fcntl", "flock", "fsync", "fdatasync",
                     "truncate", "ftruncate", "getdents", "getcwd",
                     "chdir", "rename", "mkdir", "rmdir", "creat",
                     "link", "unlink", "symlink", "readlink", "chmod",
                     "fchmod", "chown", "fchown", "lchown", "umask",
                     "gettimeofday", "getrlimit", "getrusage",
                     "sysinfo", "times", "ptrace", "getuid", "syslog",
                     "getgid", "setuid", "setgid", "geteuid",
                     "getegid", "setpgid", "getppid", "getpgrp",
                     "setsid", "setreuid", "setregid", "getgroups",
                     "setgroups", "setresuid", "getresuid",
                     "setresgid", "getresgid", "getpgid", "setfsuid",
                     "setfsgid", "getsid", "capget", "capset",
                     "rt_sigpending", "rt_sigtimedwait",
                     "rt_sigqueueinfo", "rt_sigsuspend",
                     "sigaltstack", "utime", "mknod", "uselib",
                     "personality", "ustat", "statfs", "fstatfs",
                     "sysfs", "getpriority", "setpriority",
                     "sched_setparam", "sched_getparam",
                     "sched_setscheduler", "sched_getscheduler",
                     "sched_get_priority_max",
                     "sched_get_priority_min",
                     "sched_rr_get_interval", "mlock", "munlock",
                     "mlockall", "munlockall", "vhangup", "modify_ldt",
                     "pivot_root", "_sysctl", "prctl", "arch_prctl",
                     "adjtimex", "setrlimit", "chroot", "sync",
                     "acct", "settimeofday", "mount", "umount2",
                     "swapon", "swapoff", "reboot", "sethostname",
                     "setdomainname", "iopl", "ioperm",
                     "create_module", "init_module", "delete_module",
                     "get_kernel_syms", "query_module", "quotactl",
                     "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
                     "tuxcall", "security", "gettid", "readahead",
                     "setxattr", "lsetxattr", "fsetxattr", "getxattr",
                     "lgetxattr", "fgetxattr", "listxattr",
                     "llistxattr", "flistxattr", "removexattr",
                     "lremovexattr", "fremovexattr", "tkill", "time",
                     "futex", "sched_setaffinity", "sched_getaffinity",
                     "set_thread_area", "io_setup", "io_destroy",
                     "io_getevents", "io_submit", "io_cancel",
                     "get_thread_area", "lookup_dcookie",
                     "epoll_create", "epoll_ctl_old",
                     "epoll_wait_old", "remap_file_pages",
                     "getdents64", "set_tid_address", "restart_syscall",
                     "semtimedop", "fadvise64", "timer_create",
                     "timer_settime", "timer_gettime",
                     "timer_getoverrun", "timer_delete",
                     "clock_settime", "clock_gettime",
                     "clock_getres", "clock_nanosleep",
                     "exit_group", "epoll_wait", "epoll_ctl",
                     "tgkill", "utimes", "vserver", "mbind",
                     "set_mempolicy", "get_mempolicy",
                     "mq_open", "mq_unlink", "mq_timedsend",
                     "mq_timedreceive", "mq_notify",
                     "mq_getsetattr", "kexec_load", "waitid",
                     "add_key", "request_key", "keyctl",
                     "ioprio_set", "ioprio_get", "inotify_init",
                     "inotify_add_watch", "inotify_rm_watch",
                     "migrate_pages", "openat", "mkdirat",
                     "mknodat", "fchownat", "futimesat",
                     "newfstatat", "unlinkat", "renameat",
                     "linkat", "symlinkat", "readlinkat",
                     "fchmodat", "faccessat", "pselect6",
                     "ppoll", "unshare", "set_robust_list",
                     "get_robust_list", "splice", "tee",
                     "sync_file_range", "vmsplice",
                     "move_pages", "utimensat",
                     "epoll_pwait", "signalfd",
                     "timerfd_create", "eventfd",
                     "fallocate", "timerfd_settime",
                     "timerfd_gettime", "accept4", "signalfd4",
                     "eventfd2", "epoll_create1", "dup3",
                     "pipe2", "inotify_init1", "preadv",
                     "pwritev", "rt_tgsigqueueinfo", "perf_event_open",
                     "recvmmsg", "fanotify_init",
                     "fanotify_mark", "prlimit64", "name_to_handle_at",
                     "open_by_handle_at", "clock_adjtime", "syncfs",
                     "sendmmsg", "setns", "getcpu",
                     "process_vm_readv", "process_vm_writev",
                     "kcmp", "finit_module"],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
EOF
```

### Falco — Runtime Threat Detection

```bash
# Install Falco
curl -s https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor | \
    sudo tee /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
    https://download.falco.org/packages/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco

# Falco rule examples
```

YAML configuration file. Widely used in Kubernetes, CI/CD pipelines, and security tool configurations; misconfiguration can lead to security vulnerabilities.

```yaml
# custom_falco_rules.yaml
- rule: Shell Executed in Container
  desc: A shell was spawned inside a container (indicator of compromise)
  condition: >
    spawned_process and
    container and
    not container.image.repository in (allowed_shell_containers) and
    proc.name in (shell_binaries)
  output: >
    Shell executed in container (user=%user.name container=%container.id 
    image=%container.image.repository cmd=%proc.cmdline)
  priority: WARNING
  tags: [container, shell]

- rule: Sensitive File Access
  desc: Read of sensitive files such as /etc/shadow, /etc/passwd
  condition: >
    open_read and
    container and
    fd.name in (/etc/shadow, /etc/sudoers, /root/.ssh/authorized_keys)
  output: >
    Sensitive file access (user=%user.name container=%container.id 
    file=%fd.name)
  priority: ERROR
  tags: [container, filesystem]

- rule: Unexpected Outbound Network Connection
  desc: Unauthorized connection to external IP
  condition: >
    outbound and
    container and
    not fd.rip in (allowed_outbound_ips) and
    not fd.rport in (80, 443, 53)
  output: >
    Unexpected outbound connection (container=%container.id 
    dst=%fd.rip:%fd.rport)
  priority: WARNING
  tags: [network, container]
```

```bash
# Run Falco with custom rules
sudo falco -r custom_falco_rules.yaml

# Falco on Kubernetes (Helm)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
    --set driver.kind=ebpf \
    --set falcosidekick.enabled=true \
    --set falcosidekick.config.slack.webhookurl=SLACK_HOOK

# Receive Falco real-time alerts (Python)
# falcosidekick → webhook → script below forwards to Slack/PagerDuty
```

```python
#!/usr/bin/env python3
"""
Falco Alert Webhook Receiver Server + Severity-based Auto Response
Usage: python3 falco_webhook.py --port 2802 --slack-url https://hooks.slack.com/...
       Environment variables: SLACK_WEBHOOK_URL, PAGERDUTY_KEY

Falco → falcosidekick → POST http://this-server:2802/falco
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("falco-webhook")

# ── Configuration (environment variables or CLI) ──────────────

SLACK_URL      = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_KEY  = os.getenv("PAGERDUTY_KEY", "")
ALERT_HISTORY: list[dict] = []


# ── Response functions ────────────────────────────────────────

def send_slack(event: dict, slack_url: str) -> None:
    priority = event.get("priority", "").upper()
    name     = event.get("rule", "Unknown Rule")
    output   = event.get("output", "")
    ts       = event.get("time", datetime.utcnow().isoformat())

    color = {"CRITICAL": "#FF0000", "ERROR": "#FF6600",
             "WARNING": "#FFCC00"}.get(priority, "#999999")

    payload = {
        "attachments": [{
            "color": color,
            "title": f"[Falco {priority}] {name}",
            "text": output[:500],
            "footer": f"Container Security | {ts}",
        }]
    }
    try:
        requests.post(slack_url, json=payload, timeout=10)
        logger.info("Slack alert sent: %s", name)
    except requests.RequestException as e:
        logger.error("Slack send failed: %s", e)


def trigger_pagerduty(event: dict, key: str) -> None:
    """Escalate CRITICAL events to PagerDuty incidents."""
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "dedup_key": event.get("rule", "falco") + "_" + event.get("hostname", ""),
        "payload": {
            "summary": f"[Falco CRITICAL] {event.get('rule','?')}",
            "severity": "critical",
            "source": event.get("hostname", "unknown"),
            "custom_details": event,
        },
    }
    try:
        requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload, timeout=10,
        )
        logger.info("PagerDuty escalation: %s", event.get("rule"))
    except requests.RequestException as e:
        logger.error("PagerDuty failed: %s", e)


def handle_event(event: dict, slack_url: str, pd_key: str) -> None:
    priority = event.get("priority", "").upper()
    ALERT_HISTORY.append({"time": datetime.utcnow().isoformat(),
                           "priority": priority,
                           "rule": event.get("rule", "")})

    logger.warning("[%s] %s | %s",
                   priority, event.get("rule"), event.get("output", "")[:120])

    if priority in ("WARNING", "ERROR", "CRITICAL") and slack_url:
        send_slack(event, slack_url)

    if priority == "CRITICAL" and pd_key:
        trigger_pagerduty(event, pd_key)


# ── HTTP handler ──────────────────────────────────────────────

def make_handler(slack_url: str, pd_key: str) -> type:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            pass  # suppress default logs

        def do_POST(self) -> None:
            if self.path != "/falco":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                event = json.loads(body)
                handle_event(event, slack_url, pd_key)
                self.send_response(200)
            except (json.JSONDecodeError, Exception) as e:
                logger.error("Event parse error: %s", e)
                self.send_response(400)
            self.end_headers()

        def do_GET(self) -> None:
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            elif self.path == "/stats":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                from collections import Counter
                cnt = Counter(a["priority"] for a in ALERT_HISTORY)
                self.wfile.write(
                    json.dumps({"total": len(ALERT_HISTORY),
                                "by_priority": dict(cnt)}).encode()
                )
            else:
                self.send_response(404)
                self.end_headers()

    return Handler


# ── CLI ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Falco Webhook Receiver Server")
    parser.add_argument("--port",      type=int, default=2802)
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--slack-url", default=SLACK_URL)
    parser.add_argument("--pd-key",    default=PAGERDUTY_KEY,
                        help="PagerDuty Routing Key")
    args = parser.parse_args()

    handler = make_handler(args.slack_url, args.pd_key)
    server  = HTTPServer((args.host, args.port), handler)

    logger.info("Falco Webhook server started: %s:%d", args.host, args.port)
    if args.slack_url:
        logger.info("Slack alerts: enabled")
    if args.pd_key:
        logger.info("PagerDuty escalation: enabled")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
```

---

## 3. Kubernetes Security Hardening

### Pod Security Standards

YAML configuration file. Widely used in Kubernetes, CI/CD pipelines, and security tool configurations; misconfiguration can lead to security vulnerabilities.

```yaml
# namespace-security.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # Baseline: basic security (prohibit privileged containers)
    # Restricted: highest security (recommended)
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Requirements for restricted Pods
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault  # default Seccomp profile
  
  containers:
  - name: app
    image: myapp:1.0.0  # latest tag prohibited
    
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
    
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "250m"
    
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  
  automountServiceAccountToken: false  # disable auto-mounting SA token
```

### RBAC Least Privilege Configuration

YAML configuration file. Widely used in Kubernetes, CI/CD pipelines, and security tool configurations; misconfiguration can lead to security vulnerabilities.

```yaml
# rbac-minimal.yaml
# Least-privilege ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
---
# Read-only Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: myapp-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]  # read only
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["myapp-secret"]  # specific secret only
  verbs: ["get"]
---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: myapp-rolebinding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: myapp-role
subjects:
- kind: ServiceAccount
  name: myapp-sa
  namespace: production
```

### NetworkPolicy — Microsegmentation

YAML configuration file. Widely used in Kubernetes, CI/CD pipelines, and security tool configurations; misconfiguration can lead to security vulnerabilities.

```yaml
# network-policy.yaml
# Default: deny all inbound/outbound traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow only API server to access DB
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-server
    ports:
    - protocol: TCP
      port: 5432
---
# Allow only external DNS/HTTPS
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53       # DNS
      protocol: UDP
    - port: 443      # HTTPS
      protocol: TCP
```

---

## 4. Image Supply Chain Security

### Cosign — Image Signing

```bash
# Install cosign
curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.2.0/cosign-linux-amd64 \
    -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key registry.io/myapp:v1.0

# Verify signature
cosign verify --key cosign.pub registry.io/myapp:v1.0

# Keyless signing (Sigstore/OIDC)
COSIGN_EXPERIMENTAL=1 cosign sign registry.io/myapp:v1.0
COSIGN_EXPERIMENTAL=1 cosign verify registry.io/myapp:v1.0

# Enforce signature verification in Kubernetes (policy-controller)
helm install policy-controller sigstore/policy-controller
```

YAML configuration file. Widely used in Kubernetes, CI/CD pipelines, and security tool configurations; misconfiguration can lead to security vulnerabilities.

```yaml
# cluster-image-policy.yaml - allow signed images only
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images-only
spec:
  images:
  - glob: "registry.io/**"
  authorities:
  - key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
        -----END PUBLIC KEY-----
```

### SBOM (Software Bill of Materials)

```bash
# Generate SBOM with Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Image SBOM
syft registry.io/myapp:v1.0 -o spdx-json=sbom.spdx.json

# Scan SBOM for vulnerabilities with Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

grype sbom:sbom.spdx.json
grype registry.io/myapp:v1.0
```

---

## 5. Docker Compose Security Configuration

Container security check commands. Although containers are lightweight environments, misconfigured permissions, unnecessary capabilities, and running as root can lead to container escape vulnerabilities.

```yaml
# docker-compose.secure.yml
version: '3.8'

services:
  app:
    image: myapp:1.0.0
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp
      - /var/cache
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # only when needed
    networks:
      - internal
    environment:
      - APP_ENV=production
    secrets:
      - db_password
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  db:
    image: postgres:16-alpine
    user: "999:999"
    read_only: true
    tmpfs:
      - /tmp
      - /run/postgresql
    environment:
      - POSTGRES_DB=mydb
      - POSTGRES_USER_FILE=/run/secrets/db_user
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - type: volume
        source: db_data
        target: /var/lib/postgresql/data
        read_only: false
    networks:
      - internal
    secrets:
      - db_user
      - db_password
    security_opt:
      - no-new-privileges:true

networks:
  internal:
    internal: true  # block external connections
  external:
    driver: bridge

volumes:
  db_data:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
  db_user:
    file: ./secrets/db_user.txt
```
