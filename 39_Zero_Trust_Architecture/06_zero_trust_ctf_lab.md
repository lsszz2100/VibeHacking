> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 제로 트러스트 아키텍처 CTF 랩

## 개요

이 랩은 제로 트러스트(Zero Trust) 원칙을 실제로 구현하고 우회 취약점을 찾는 CTF 실습입니다. mTLS 인증서 기반 서비스 간 인증, 네트워크 미세분할 정책 설계, 디바이스 신뢰 수준에 따른 접근 제어의 세 시나리오를 통해 "절대 신뢰하지 말고 항상 검증하라(Never Trust, Always Verify)" 원칙을 체화합니다.

**선수 지식**: TLS/PKI 기초, 네트워크 방화벽 개념, 인증/인가 기초  
**소요 시간**: 약 3~4시간  
**난이도**: 중급 (Intermediate)

---

## 실습 1: mTLS 인증서 기반 서비스 간 인증 구현

### 목표

단방향 TLS가 아닌 mTLS(Mutual TLS)를 구현하여 서버와 클라이언트 양쪽이 인증서를 교환하고 서로를 인증하는 시스템을 구축합니다. 인증서 없이 서비스에 접근하는 공격을 차단하고, 유효한 클라이언트 인증서로만 플래그를 획득할 수 있습니다.

### 배경 지식

mTLS 핸드셰이크 흐름:
```
클라이언트                     서버
    |                            |
    |------ ClientHello -------->|
    |<----- ServerHello ---------|
    |<----- Certificate ---------|  (서버 인증서)
    |<----- CertificateRequest --|  ← 핵심: 클라이언트 인증서 요청
    |------ Certificate -------->|  (클라이언트 인증서)
    |------ CertificateVerify -->|
    |<----- Finished ------------|
    |------ Finished ----------->|
         mTLS 연결 완료
```

제로 트러스트에서 mTLS의 역할:
- 네트워크 경계 없이 모든 서비스 간 통신 암호화
- IP 주소가 아닌 인증서 기반 서비스 식별
- SPIFFE/SPIRE를 통한 workload identity 관리

### 힌트

1. CA 인증서, 서버 인증서, 클라이언트 인증서를 각각 생성해야 합니다. OpenSSL `v3_ext` 설정에서 `subjectAltName`을 올바르게 설정하세요.
2. 서버에서 `ssl.CERT_REQUIRED`로 클라이언트 인증서를 요구하도록 설정하세요.
3. 플래그는 유효한 클라이언트 인증서로 `/flag` 엔드포인트에 접근했을 때 반환됩니다.
4. 인증서의 Common Name(CN) 또는 SAN에 특정 값이 포함되어야 플래그가 공개됩니다.

### 실습 환경 구성

```bash
# PKI 디렉토리 구조 생성
mkdir -p /tmp/ctf-mtls/{ca,server,client}

# 1. CA 키 및 인증서 생성
openssl genrsa -out /tmp/ctf-mtls/ca/ca.key 4096
openssl req -new -x509 -days 365 \
  -key /tmp/ctf-mtls/ca/ca.key \
  -out /tmp/ctf-mtls/ca/ca.crt \
  -subj "/CN=CTF-CA/O=VibeSecurity/C=KR"

# 2. 서버 키 및 CSR 생성
openssl genrsa -out /tmp/ctf-mtls/server/server.key 2048
openssl req -new \
  -key /tmp/ctf-mtls/server/server.key \
  -out /tmp/ctf-mtls/server/server.csr \
  -subj "/CN=ctf-server/O=VibeSecurity/C=KR"

# 3. 서버 인증서 서명
openssl x509 -req -days 365 \
  -in /tmp/ctf-mtls/server/server.csr \
  -CA /tmp/ctf-mtls/ca/ca.crt \
  -CAkey /tmp/ctf-mtls/ca/ca.key \
  -CAcreateserial \
  -out /tmp/ctf-mtls/server/server.crt \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:ctf-server,IP:127.0.0.1")
```

### 풀이

**Step 1: mTLS 서버 구현**

```python
#!/usr/bin/env python3
"""
mTLS 인증 서버 - 제로 트러스트 CTF 실습
"""

import argparse
import ssl
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

SECRET_FLAG = "CTF_FLAG{mtls_mutual_auth_zero_trust}"
REQUIRED_CLIENT_CN = "ctf-client-authorized"

class MTLSHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._respond(200, {"status": "ok", "message": "mTLS 서버 정상 동작"})
            return

        if self.path == "/flag":
            client_cert = self.connection.getpeercert()
            if not client_cert:
                self._respond(403, {"error": "클라이언트 인증서 없음"})
                return

            subject = dict(x[0] for x in client_cert.get("subject", []))
            cn = subject.get("commonName", "")

            if cn == REQUIRED_CLIENT_CN:
                self._respond(200, {
                    "flag": SECRET_FLAG,
                    "message": f"환영합니다, {cn}! 제로 트러스트 인증 성공.",
                    "cert_info": {
                        "cn": cn,
                        "issuer": dict(x[0] for x in client_cert.get("issuer", []))
                    }
                })
            else:
                self._respond(403, {
                    "error": f"인가되지 않은 클라이언트: {cn}",
                    "hint": "올바른 CN을 가진 클라이언트 인증서가 필요합니다"
                })
            return

        self._respond(404, {"error": "엔드포인트를 찾을 수 없습니다"})

    def _respond(self, code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        peer = self.connection.getpeername()
        cert = self.connection.getpeercert()
        cn = "인증서없음"
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "알수없음")
        print(f"[{peer[0]}:{peer[1]}] CN={cn} {fmt % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="mTLS 인증 서버 (제로 트러스트 CTF)"
    )
    parser.add_argument("--host", default="0.0.0.0", help="바인딩 주소")
    parser.add_argument("--port", "-p", type=int, default=8443, help="포트 번호")
    parser.add_argument("--ca-cert", required=True, help="CA 인증서 경로")
    parser.add_argument("--server-cert", required=True, help="서버 인증서 경로")
    parser.add_argument("--server-key", required=True, help="서버 개인키 경로")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(args.ca_cert)
    ctx.load_cert_chain(args.server_cert, args.server_key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    server = HTTPServer((args.host, args.port), MTLSHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[*] mTLS 서버 시작: https://{args.host}:{args.port}")
    print(f"[*] 필요한 클라이언트 CN: {REQUIRED_CLIENT_CN}")
    print("[*] 인증서 없는 요청은 자동으로 거부됩니다")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 서버 종료")


if __name__ == "__main__":
    main()
```

**Step 2: 올바른 클라이언트 인증서 생성 및 플래그 획득**

```bash
# 클라이언트 키 및 CSR 생성 (CN이 중요!)
openssl genrsa -out /tmp/ctf-mtls/client/client.key 2048
openssl req -new \
  -key /tmp/ctf-mtls/client/client.key \
  -out /tmp/ctf-mtls/client/client.csr \
  -subj "/CN=ctf-client-authorized/O=VibeSecurity/C=KR"

# CA로 서명
openssl x509 -req -days 30 \
  -in /tmp/ctf-mtls/client/client.csr \
  -CA /tmp/ctf-mtls/ca/ca.crt \
  -CAkey /tmp/ctf-mtls/ca/ca.key \
  -CAcreateserial \
  -out /tmp/ctf-mtls/client/client.crt

# 서버 시작 (별도 터미널)
python3 mtls_server.py \
  --ca-cert /tmp/ctf-mtls/ca/ca.crt \
  --server-cert /tmp/ctf-mtls/server/server.crt \
  --server-key /tmp/ctf-mtls/server/server.key

# 플래그 획득
curl --cacert /tmp/ctf-mtls/ca/ca.crt \
     --cert /tmp/ctf-mtls/client/client.crt \
     --key /tmp/ctf-mtls/client/client.key \
     https://localhost:8443/flag
# 출력: {"flag": "CTF_FLAG{mtls_mutual_auth_zero_trust}", ...}
```

**플래그**: `CTF_FLAG{mtls_mutual_auth_zero_trust}`

---

## 실습 2: 네트워크 미세분할 정책 설계 (허용/차단 매트릭스)

### 목표

제로 트러스트 원칙에 따라 최소 권한 네트워크 정책을 설계합니다. 주어진 마이크로서비스 아키텍처에서 필요한 통신 경로만 허용하고 나머지는 모두 차단하는 허용/차단 매트릭스를 완성한 뒤, Kubernetes NetworkPolicy로 구현하면 플래그를 획득합니다.

### 배경 지식

미세분할(Microsegmentation)의 핵심 원칙:
- 기본 거부(Default Deny): 명시적으로 허용되지 않은 모든 트래픽 차단
- 최소 권한(Least Privilege): 필요한 포트와 프로토콜만 허용
- 동서 트래픽 통제: 내부 서비스 간 트래픽도 검사 및 제어
- 레이블 기반 정책: IP 주소 대신 애플리케이션 레이블로 정책 적용

### 힌트

1. `kubectl get networkpolicy -A`로 현재 정책 확인 후, 어떤 통신이 누락되었는지 분석하세요.
2. `deny-all` 정책이 이미 적용된 상태에서 필요한 허용 규칙을 추가하는 방식으로 접근하세요.
3. 각 서비스의 포트 번호와 레이블을 정확히 파악하는 것이 핵심입니다.
4. 플래그 서버는 오직 `role: flag-requester` 레이블을 가진 Pod에서만 접근 가능합니다.

### 실습 환경 구성

```
마이크로서비스 아키텍처:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │───>│   Backend   │───>│  Database   │
│  :80        │    │  :8080      │    │  :5432      │
│  (web)      │    │  (api)      │    │  (db)       │
└─────────────┘    └─────────────┘    └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │  Flag-Svc   │ ← 여기에 플래그가 있음
                   │  :9999      │
                   └─────────────┘

허용 매트릭스 (완성해야 함):
출발 \ 도착   | Frontend | Backend | Database | Flag-Svc
-----------  +----------+---------+----------+---------
Frontend     |    -     |   허용   |   차단   |   차단
Backend      |   차단   |    -    |   허용   |   차단
Database     |   차단   |   차단   |    -    |   차단
flag-requester|  차단   |   차단   |   차단   |   허용  ← 플래그 획득 경로
```

### 풀이

**Step 1: NetworkPolicy 자동 생성기**

```python
#!/usr/bin/env python3
"""
제로 트러스트 네트워크 미세분할 정책 생성기
"""

import argparse
import json
import sys
from typing import Any

SERVICES: dict[str, dict[str, Any]] = {
    "frontend": {"port": 80, "labels": {"app": "frontend", "role": "web"}},
    "backend": {"port": 8080, "labels": {"app": "backend", "role": "api"}},
    "database": {"port": 5432, "labels": {"app": "database", "role": "db"}},
    "flag-svc": {"port": 9999, "labels": {"app": "flag-svc", "role": "secret"}},
}

ALLOW_MATRIX: dict[str, list[str]] = {
    "frontend": ["backend"],
    "backend": ["database"],
    "flag-requester": ["flag-svc"],
}

def generate_deny_all(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "default-deny-all",
            "namespace": namespace
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"]
        }
    }

def generate_allow_policy(
    source: str,
    destination: str,
    namespace: str
) -> dict[str, Any] | None:
    if destination not in SERVICES:
        return None
    dest_svc = SERVICES[destination]
    src_labels: dict[str, str] = {}
    if source in SERVICES:
        src_labels = SERVICES[source]["labels"]
    else:
        src_labels = {"role": source}

    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"allow-{source}-to-{destination}",
            "namespace": namespace
        },
        "spec": {
            "podSelector": {"matchLabels": dest_svc["labels"]},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": src_labels}}],
                "ports": [{"protocol": "TCP", "port": dest_svc["port"]}]
            }]
        }
    }

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="제로 트러스트 NetworkPolicy 생성기"
    )
    parser.add_argument(
        "--namespace", "-n",
        default="ctf-zt",
        help="Kubernetes 네임스페이스"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["yaml", "json"],
        default="yaml",
        help="출력 형식"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="정책 검증 모드"
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    policies: list[dict[str, Any]] = [generate_deny_all(args.namespace)]

    for source, destinations in ALLOW_MATRIX.items():
        for dest in destinations:
            policy = generate_allow_policy(source, dest, args.namespace)
            if policy:
                policies.append(policy)

    if args.output == "json":
        print(json.dumps(policies, ensure_ascii=False, indent=2))
    else:
        import yaml
        for policy in policies:
            print("---")
            print(yaml.dump(policy, default_flow_style=False, allow_unicode=True))

    if args.verify:
        print("\n[*] 정책 검증:")
        print(f"  - 총 {len(policies)}개 정책 생성")
        print(f"  - deny-all 정책: 적용됨")
        print(f"  - 허용 정책: {len(policies)-1}개")
        print("  - flag-requester → flag-svc: 허용됨 (플래그 경로)")
        print("\n[*] 정책 적용 명령:")
        print(f"  kubectl apply -f network-policies.yaml -n {args.namespace}")

if __name__ == "__main__":
    main()
```

**Step 2: 정책 적용 및 플래그 획득**

```bash
# 정책 생성
python3 microseg_generator.py --namespace ctf-zt --output yaml > network-policies.yaml

# 네임스페이스 및 정책 생성
kubectl create namespace ctf-zt
kubectl apply -f network-policies.yaml

# flag-requester Pod 배포
kubectl run flag-requester \
  --image=curlimages/curl:latest \
  --labels="app=flag-requester,role=flag-requester" \
  -n ctf-zt \
  --restart=Never \
  -- curl http://flag-svc:9999/flag

# 플래그 확인
kubectl logs flag-requester -n ctf-zt
# 출력: CTF_FLAG{microsegmentation_default_deny}
```

**플래그**: `CTF_FLAG{microsegmentation_default_deny}`

---

## 실습 3: 디바이스 신뢰 수준에 따른 접근 제어 시뮬레이션

### 목표

디바이스의 보안 상태(패치 수준, 보안 소프트웨어 설치 여부, 위치 정보 등)에 따라 접근 가능한 리소스가 달라지는 제로 트러스트 접근 제어 시스템을 시뮬레이션합니다. 낮은 신뢰 수준의 디바이스에서도 특정 취약점을 통해 높은 신뢰 리소스에 접근하는 방법을 찾습니다.

### 배경 지식

디바이스 신뢰 점수 계산 요소:
| 요소 | 가중치 | 설명 |
|------|--------|------|
| OS 패치 수준 | 30% | 최신 보안 패치 적용 여부 |
| 보안 소프트웨어 | 25% | AV, EDR 설치 및 최신화 |
| 디스크 암호화 | 20% | BitLocker/FileVault 활성화 |
| 인증서 유효성 | 15% | 기업 MDM 등록 인증서 |
| 위치/네트워크 | 10% | 기업 네트워크 또는 VPN |

신뢰 수준별 접근 가능 리소스:
- `HIGH (80-100)`: 모든 내부 시스템 접근
- `MEDIUM (50-79)`: 일반 업무 시스템만 접근
- `LOW (0-49)`: 인터넷 전용, 내부 시스템 차단

### 힌트

1. 디바이스 신뢰 점수는 헤더(`X-Device-Trust-Score`)로 전달되며 서버가 검증합니다. 헤더를 조작해보세요.
2. `X-Device-Certificate` 헤더에는 Base64로 인코딩된 인증서 정보가 포함됩니다.
3. 특정 User-Agent 패턴이 신뢰 점수 보정에 영향을 줍니다.
4. 플래그는 신뢰 점수 85 이상 + 유효한 MDM 인증서를 제시했을 때 공개됩니다.

### 풀이

**Step 1: 디바이스 신뢰 평가 서버**

```python
#!/usr/bin/env python3
"""
디바이스 신뢰 수준 기반 접근 제어 시뮬레이터
"""

import argparse
import base64
import json
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass, field

FLAG = "CTF_FLAG{device_trust_context_aware_access}"
MDM_CERT_HASH = hashlib.sha256(b"CTF-MDM-CERT-VALID").hexdigest()

@dataclass
class DeviceContext:
    ip: str
    user_agent: str
    trust_score: int = 0
    cert_valid: bool = False
    factors: dict[str, int] = field(default_factory=dict)

    def evaluate(self, headers: dict[str, str]) -> None:
        raw_score = int(headers.get("X-Device-Trust-Score", "0"))
        self.trust_score = max(0, min(100, raw_score))

        cert_b64 = headers.get("X-Device-Certificate", "")
        if cert_b64:
            try:
                cert_data = base64.b64decode(cert_b64)
                cert_hash = hashlib.sha256(cert_data).hexdigest()
                self.cert_valid = cert_hash == MDM_CERT_HASH
            except Exception:
                self.cert_valid = False

        if "ZeroTrustClient/2.0" in self.user_agent:
            self.trust_score = min(100, self.trust_score + 5)

    @property
    def trust_level(self) -> str:
        if self.trust_score >= 80:
            return "HIGH"
        elif self.trust_score >= 50:
            return "MEDIUM"
        return "LOW"

    def can_access_flag(self) -> bool:
        return self.trust_score >= 85 and self.cert_valid


class TrustHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        headers = {k: v for k, v in self.headers.items()}
        ctx = DeviceContext(
            ip=self.client_address[0],
            user_agent=headers.get("User-Agent", "")
        )
        ctx.evaluate(headers)

        if self.path == "/trust-check":
            self._respond(200, {
                "trust_score": ctx.trust_score,
                "trust_level": ctx.trust_level,
                "cert_valid": ctx.cert_valid,
                "message": f"디바이스 신뢰 수준: {ctx.trust_level}"
            })

        elif self.path == "/flag":
            if ctx.can_access_flag():
                self._respond(200, {
                    "flag": FLAG,
                    "trust_score": ctx.trust_score,
                    "message": "높은 신뢰 수준 디바이스 접근 승인"
                })
            else:
                missing = []
                if ctx.trust_score < 85:
                    missing.append(f"신뢰 점수 부족 (현재: {ctx.trust_score}, 필요: 85)")
                if not ctx.cert_valid:
                    missing.append("유효한 MDM 인증서 필요")
                self._respond(403, {
                    "error": "접근 거부",
                    "reason": missing,
                    "trust_score": ctx.trust_score
                })
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args) -> None:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="디바이스 신뢰 수준 접근 제어 시뮬레이터"
    )
    parser.add_argument("--port", "-p", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = HTTPServer((args.host, args.port), TrustHandler)
    print(f"[*] 신뢰 기반 접근 제어 서버: http://{args.host}:{args.port}")
    print(f"[*] MDM 인증서 해시: {MDM_CERT_HASH[:16]}...")
    print("[*] /trust-check: 현재 신뢰 수준 확인")
    print("[*] /flag: 높은 신뢰 수준 전용 리소스")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 서버 종료")


if __name__ == "__main__":
    main()
```

**Step 2: 신뢰 점수 조작 및 플래그 획득**

```python
#!/usr/bin/env python3
"""
디바이스 신뢰 점수 조작 CTF 솔버
"""

import argparse
import base64
import hashlib
import requests

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ZT CTF 솔버")
    parser.add_argument("--target", default="http://127.0.0.1:8080")
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    mdm_cert_data = b"CTF-MDM-CERT-VALID"
    cert_b64 = base64.b64encode(mdm_cert_data).decode()

    headers = {
        "X-Device-Trust-Score": "90",
        "X-Device-Certificate": cert_b64,
        "User-Agent": "ZeroTrustClient/2.0 CTFSolver",
    }

    print("[*] 신뢰 점수 확인 중...")
    r = requests.get(f"{args.target}/trust-check", headers=headers)
    print(f"    {r.json()}")

    print("\n[*] 플래그 요청 중...")
    r = requests.get(f"{args.target}/flag", headers=headers)
    data = r.json()
    if "flag" in data:
        print(f"[+] 플래그 획득: {data['flag']}")
    else:
        print(f"[-] 실패: {data}")

if __name__ == "__main__":
    main()
```

**플래그**: `CTF_FLAG{device_trust_context_aware_access}`

---

## 정리 및 핵심 요약

| 실습 | 기술 | 플래그 |
|------|------|--------|
| 실습 1 | mTLS 인증서 기반 인증 | `CTF_FLAG{mtls_mutual_auth_zero_trust}` |
| 실습 2 | 네트워크 미세분할 | `CTF_FLAG{microsegmentation_default_deny}` |
| 실습 3 | 디바이스 신뢰 기반 접근 제어 | `CTF_FLAG{device_trust_context_aware_access}` |

**참고 자료**
- [NIST SP 800-207 Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207)
- [SPIFFE/SPIRE 공식 문서](https://spiffe.io/docs/latest/)

---

<a name="english"></a>
# Zero Trust Architecture CTF Lab

## Overview

This lab provides CTF exercises for implementing Zero Trust principles and finding bypass vulnerabilities. Through three scenarios—mTLS certificate-based service authentication, network microsegmentation policy design, and device trust-level access control—you will internalize the "Never Trust, Always Verify" principle.

**Prerequisites**: TLS/PKI basics, network firewall concepts, authentication/authorization fundamentals  
**Estimated Time**: 3–4 hours  
**Difficulty**: Intermediate

---

## Lab 1: Implementing mTLS Certificate-Based Service Authentication

### Objective

Implement mTLS (Mutual TLS) so that both server and client exchange certificates and authenticate each other, rather than using one-way TLS. Block attacks that attempt to access services without certificates, and capture the flag only with a valid client certificate.

### Hints

1. You must generate a CA certificate, server certificate, and client certificate separately. Set `subjectAltName` correctly in the OpenSSL `v3_ext` configuration.
2. Configure the server to require client certificates using `ssl.CERT_REQUIRED`.
3. The flag is returned when accessing the `/flag` endpoint with a valid client certificate.
4. The CN (Common Name) in the certificate must be `ctf-client-authorized` for the flag to be revealed.

### Solution

Generate the client certificate with the correct CN, then use it to access the flag endpoint:

```bash
curl --cacert /tmp/ctf-mtls/ca/ca.crt \
     --cert /tmp/ctf-mtls/client/client.crt \
     --key /tmp/ctf-mtls/client/client.key \
     https://localhost:8443/flag
# Output: {"flag": "CTF_FLAG{mtls_mutual_auth_zero_trust}", ...}
```

**Flag**: `CTF_FLAG{mtls_mutual_auth_zero_trust}`

---

## Lab 2: Network Microsegmentation Policy Design

### Objective

Design a least-privilege network policy following Zero Trust principles. Complete a permit/deny matrix that allows only necessary communication paths and blocks everything else, then implement it as Kubernetes NetworkPolicy to capture the flag.

### Key Principles

- **Default Deny**: Block all traffic not explicitly permitted
- **Least Privilege**: Allow only required ports and protocols
- **East-West Traffic Control**: Inspect and control inter-service traffic
- **Label-Based Policies**: Use application labels instead of IP addresses

### Hints

1. Check current policies with `kubectl get networkpolicy -A`, then analyze what communication is missing.
2. Start from a `deny-all` policy already in place and add only necessary allow rules.
3. The key is knowing the exact port numbers and labels for each service.
4. The flag server is only accessible from Pods with the `role: flag-requester` label.

### Solution

```bash
python3 microseg_generator.py --namespace ctf-zt --output yaml > network-policies.yaml
kubectl apply -f network-policies.yaml
kubectl run flag-requester \
  --labels="app=flag-requester,role=flag-requester" \
  -n ctf-zt -- curl http://flag-svc:9999/flag
kubectl logs flag-requester -n ctf-zt
# Output: CTF_FLAG{microsegmentation_default_deny}
```

**Flag**: `CTF_FLAG{microsegmentation_default_deny}`

---

## Lab 3: Device Trust Level Access Control Simulation

### Objective

Simulate a Zero Trust access control system where accessible resources vary based on device security posture (patch level, security software installation, location, etc.). Find a way to access high-trust resources from a low-trust device through specific vulnerabilities.

### Trust Score Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| OS Patch Level | 30% | Security patches applied |
| Security Software | 25% | AV/EDR installed and current |
| Disk Encryption | 20% | BitLocker/FileVault enabled |
| Certificate Validity | 15% | MDM enrollment certificate |
| Location/Network | 10% | Corporate network or VPN |

### Hints

1. Device trust score is passed via `X-Device-Trust-Score` header and validated by the server. Try manipulating the header.
2. The `X-Device-Certificate` header contains Base64-encoded certificate information.
3. Specific User-Agent patterns affect trust score adjustment.
4. The flag is revealed when trust score ≥ 85 and a valid MDM certificate is presented.

### Solution

```python
headers = {
    "X-Device-Trust-Score": "90",
    "X-Device-Certificate": base64.b64encode(b"CTF-MDM-CERT-VALID").decode(),
    "User-Agent": "ZeroTrustClient/2.0 CTFSolver",
}
response = requests.get("http://127.0.0.1:8080/flag", headers=headers)
# Output: {"flag": "CTF_FLAG{device_trust_context_aware_access}", ...}
```

**Flag**: `CTF_FLAG{device_trust_context_aware_access}`

---

## Summary

| Lab | Technique | Flag |
|-----|-----------|------|
| Lab 1 | mTLS Certificate Authentication | `CTF_FLAG{mtls_mutual_auth_zero_trust}` |
| Lab 2 | Network Microsegmentation | `CTF_FLAG{microsegmentation_default_deny}` |
| Lab 3 | Device Trust-Based Access Control | `CTF_FLAG{device_trust_context_aware_access}` |

**References**
- [NIST SP 800-207 Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207)
- [SPIFFE/SPIRE Official Documentation](https://spiffe.io/docs/latest/)
