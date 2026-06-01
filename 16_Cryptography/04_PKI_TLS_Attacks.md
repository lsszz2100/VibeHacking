> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# PKI 인프라 및 TLS/SSL 공격

## 개요

TLS/SSL은 인터넷 보안의 근간이지만, 구현 결함과 설정 오류로 인해 다양한 공격이 가능하다. PKI(Public Key Infrastructure)의 신뢰 체계를 이해하고 공격자 관점에서 분석한다.

---

## 1. TLS 핸드셰이크 구조

```
클라이언트                              서버
    │                                    │
    │──── ClientHello ──────────────────►│
    │     (지원 암호화 스위트, 랜덤)        │
    │                                    │
    │◄─── ServerHello ──────────────────│
    │     (선택된 암호화 스위트, 랜덤)      │
    │                                    │
    │◄─── Certificate ──────────────────│
    │     (서버 인증서 체인)                │
    │                                    │
    │◄─── ServerHelloDone ──────────────│
    │                                    │
    │──── ClientKeyExchange ───────────►│
    │     (PMS 암호화 또는 ECDHE)          │
    │                                    │
    │──── ChangeCipherSpec ────────────►│
    │──── Finished ────────────────────►│
    │                                    │
    │◄─── ChangeCipherSpec ─────────────│
    │◄─── Finished ─────────────────────│
    │                                    │
    │◄══════ 암호화된 애플리케이션 데이터 ══►│
```

---

## 2. 주요 TLS 취약점

### BEAST (CVE-2011-3389)
- TLS 1.0 CBC 모드의 IV 예측 가능성
- 공격자가 같은 IV 재사용을 통해 평문 추측

### CRIME (CVE-2012-4929)
- TLS 압축 + 선택적 평문 공격
- 쿠키 같은 비밀값을 압축 크기 변화로 추출

### POODLE (CVE-2014-3566)
- SSLv3 CBC 패딩 오라클
- MITM이 클라이언트를 SSLv3로 다운그레이드

### Heartbleed (CVE-2014-0160)
- OpenSSL HeartBeat 확장의 경계 검사 누락
- 서버 메모리에서 개인키, 세션 쿠키 추출 가능

### DROWN (CVE-2016-0800)
- SSLv2가 활성화된 서버에서 TLS 세션 복호화
- RSA 키를 재사용하면 TLS 1.2 서버도 피해

---

## 3. TLS 취약점 스캐닝

```bash
# sslyze — Python 기반 TLS 분석
pip install sslyze
sslyze example.com:443
sslyze --regular example.com:443

# sslscan
apt install sslscan
sslscan example.com

# testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
./testssl.sh example.com

# nmap TLS 스크립트
nmap --script ssl-enum-ciphers -p 443 example.com
nmap --script ssl-heartbleed -p 443 example.com
nmap --script ssl-poodle -p 443 example.com
nmap --script ssl-dh-params -p 443 example.com
```

---

## 4. Certificate Transparency 서브도메인 열거

```bash
# crt.sh API
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for cert in data:
    for name in cert.get('name_value','').split('\n'):
        names.add(name.strip().lstrip('*.'))
for n in sorted(names):
    print(n)
"

# certspotter API
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
    python3 -c "
import sys, json
for cert in json.load(sys.stdin):
    for name in cert.get('dns_names', []):
        print(name)
" | sort -u
```

---

## 5. mitmproxy TLS 인터셉트

```bash
# 기본 프록시 (8080)
mitmproxy

# 투명 프록시 모드
mitmproxy --mode transparent

# 클라이언트 인증서 없이 서버에 연결
mitmproxy --ssl-insecure

# 스크립트로 트래픽 수정
cat > modify_response.py << 'EOF'
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "api" in flow.request.pretty_url:
        flow.response.headers["X-Intercepted"] = "true"
        print(f"[*] {flow.request.method} {flow.request.pretty_url}")
EOF

mitmproxy -s modify_response.py
```

---

## 6. 커스텀 CA 및 인증서 생성

```bash
# 루트 CA 생성
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
    -out rootCA.crt \
    -subj "/C=KR/ST=Seoul/O=PentestCA/CN=Pentest Root CA"

# 서버 인증서 서명 요청 (CSR)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=example.com"

# SAN(Subject Alternative Name) 설정
cat > san.ext << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = *.example.com
IP.1 = 192.168.1.100
EOF

# CA로 서버 인증서 서명
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server.crt -days 365 \
    -sha256 -extfile san.ext
```

---

## 7. Python TLS 지문분석 도구

```python
#!/usr/bin/env python3
"""TLS 서버 인증서 및 설정 분석 CLI."""

import argparse
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TLSInfo:
    host: str
    port: int
    tls_version: str = ""
    cipher_suite: str = ""
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_san: list[str] = field(default_factory=list)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_days_remaining: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    supports_tls10: bool = False
    supports_tls11: bool = False
    supports_tls12: bool = False
    supports_tls13: bool = False


def check_tls_version(host: str, port: int, version: int) -> bool:
    """특정 TLS 버전 지원 여부 확인."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        match version:
            case 10:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            case 11:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            case 12:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            case 13:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        return False

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, ConnectionRefusedError):
        return False


def analyze_tls(host: str, port: int = 443) -> TLSInfo:
    info = TLSInfo(host=host, port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.tls_version = ssock.version() or ""
                cipher = ssock.cipher()
                info.cipher_suite = cipher[0] if cipher else ""

                cert = ssock.getpeercert()
                if cert:
                    info.cert_subject = dict(x[0] for x in cert.get("subject", []))
                    info.cert_issuer  = dict(x[0] for x in cert.get("issuer", []))

                    # SAN 추출
                    for san_type, san_value in cert.get("subjectAltName", []):
                        info.cert_san.append(f"{san_type}:{san_value}")

                    # 유효 기간
                    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
                    not_after  = ssl.cert_time_to_seconds(cert["notAfter"])
                    now        = datetime.now(tz=timezone.utc).timestamp()

                    info.cert_not_before = cert["notBefore"]
                    info.cert_not_after  = cert["notAfter"]
                    info.cert_days_remaining = int((not_after - now) / 86400)
                    info.is_expired = now > not_after

                    # 자체 서명 확인
                    info.is_self_signed = (info.cert_subject == info.cert_issuer)

    except (ssl.SSLError, OSError) as e:
        print(f"[!] 연결 오류: {e}")

    # 구버전 TLS 지원 확인
    info.supports_tls10 = check_tls_version(host, port, 10)
    info.supports_tls11 = check_tls_version(host, port, 11)
    info.supports_tls12 = check_tls_version(host, port, 12)
    info.supports_tls13 = check_tls_version(host, port, 13)

    return info


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS 서버 분석 도구")
    parser.add_argument("host", help="대상 호스트")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()

    info = analyze_tls(args.host, args.port)

    print(f"\n=== TLS 분석: {info.host}:{info.port} ===\n")
    print(f"TLS 버전: {info.tls_version}")
    print(f"암호화 스위트: {info.cipher_suite}")
    print(f"\n인증서 주체: {info.cert_subject.get('commonName', '?')}")
    print(f"발급 기관: {info.cert_issuer.get('commonName', '?')}")
    print(f"SAN: {', '.join(info.cert_san[:5])}")
    print(f"만료일: {info.cert_not_after}")
    print(f"남은 일수: {info.cert_days_remaining}일")

    print(f"\n취약점 지표:")
    print(f"  TLS 1.0 지원: {'[취약]' if info.supports_tls10 else '[-]'}")
    print(f"  TLS 1.1 지원: {'[취약]' if info.supports_tls11 else '[-]'}")
    print(f"  TLS 1.2 지원: {'[+]' if info.supports_tls12 else '[-]'}")
    print(f"  TLS 1.3 지원: {'[+]' if info.supports_tls13 else '[-]'}")
    print(f"  자체 서명: {'[경고]' if info.is_self_signed else '[-]'}")
    print(f"  인증서 만료: {'[만료]' if info.is_expired else '[-]'}")


if __name__ == "__main__":
    main()
```

---

## 8. TLS 보안 감사 체크리스트

| 항목 | 권장 설정 | 확인 방법 |
|------|-----------|-----------|
| 최소 TLS 버전 | TLS 1.2 이상 | testssl.sh |
| 인증서 유효 기간 | 398일 이하 | openssl x509 |
| 인증서 서명 알고리즘 | SHA-256 이상 | sslyze |
| 키 강도 | RSA 2048+, ECDSA 256+ | openssl x509 |
| HSTS 헤더 | Strict-Transport-Security 필수 | curl -I |
| OCSP Stapling | 활성화 권장 | openssl s_client |
| Forward Secrecy | ECDHE/DHE 우선 | nmap ssl-enum-ciphers |
| 취약 암호화 스위트 | RC4, DES, NULL 제외 | sslyze |
| 인증서 투명성 | CT 로그 제출 | crt.sh |
| HPKP 대체 | Certificate Pinning (앱) | 코드 리뷰 |

---

## 9. Nginx TLS 강화 설정 예시

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.crt;
    ssl_certificate_key /etc/ssl/private/example.key;

    # TLS 버전 제한 (1.2 이상만)
    ssl_protocols TLSv1.2 TLSv1.3;

    # 강력한 암호화 스위트
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;  # TLS 1.3에서는 off 권장

    # HSTS (2년)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    # DH 파라미터
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    # 세션 캐시
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
}
```

---

<a name="english"></a>

# PKI Infrastructure and TLS/SSL Attacks

## Overview

TLS/SSL is the foundation of internet security, but various attacks are possible due to implementation flaws and configuration errors. We analyze the PKI (Public Key Infrastructure) trust model from an attacker's perspective.

---

## 1. TLS Handshake Structure

```
Client                                  Server
    │                                    │
    │──── ClientHello ──────────────────►│
    │     (supported cipher suites,       │
    │      random value)                  │
    │                                    │
    │◄─── ServerHello ──────────────────│
    │     (selected cipher suite, random) │
    │                                    │
    │◄─── Certificate ──────────────────│
    │     (server certificate chain)     │
    │                                    │
    │◄─── ServerHelloDone ──────────────│
    │                                    │
    │──── ClientKeyExchange ───────────►│
    │     (encrypted PMS or ECDHE)       │
    │                                    │
    │──── ChangeCipherSpec ────────────►│
    │──── Finished ────────────────────►│
    │                                    │
    │◄─── ChangeCipherSpec ─────────────│
    │◄─── Finished ─────────────────────│
    │                                    │
    │◄══════ Encrypted application data ══►│
```

---

## 2. Major TLS Vulnerabilities

### BEAST (CVE-2011-3389)
- Predictable IV in TLS 1.0 CBC mode
- Attacker can guess plaintext by exploiting IV reuse

### CRIME (CVE-2012-4929)
- TLS compression + chosen plaintext attack
- Extracts secret values like cookies through compression size changes

### POODLE (CVE-2014-3566)
- SSLv3 CBC padding oracle
- MITM downgrades client connection to SSLv3

### Heartbleed (CVE-2014-0160)
- Missing bounds check in OpenSSL HeartBeat extension
- Can extract private keys and session cookies from server memory

### DROWN (CVE-2016-0800)
- Decrypts TLS sessions on servers with SSLv2 enabled
- TLS 1.2 servers also vulnerable if RSA key is reused

---

## 3. TLS Vulnerability Scanning

```bash
# sslyze — Python-based TLS analysis
pip install sslyze
sslyze example.com:443
sslyze --regular example.com:443

# sslscan
apt install sslscan
sslscan example.com

# testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
./testssl.sh example.com

# nmap TLS scripts
nmap --script ssl-enum-ciphers -p 443 example.com
nmap --script ssl-heartbleed -p 443 example.com
nmap --script ssl-poodle -p 443 example.com
nmap --script ssl-dh-params -p 443 example.com
```

---

## 4. Certificate Transparency Subdomain Enumeration

```bash
# crt.sh API
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for cert in data:
    for name in cert.get('name_value','').split('\n'):
        names.add(name.strip().lstrip('*.'))
for n in sorted(names):
    print(n)
"

# certspotter API
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
    python3 -c "
import sys, json
for cert in json.load(sys.stdin):
    for name in cert.get('dns_names', []):
        print(name)
" | sort -u
```

---

## 5. mitmproxy TLS Intercept

```bash
# Basic proxy (8080)
mitmproxy

# Transparent proxy mode
mitmproxy --mode transparent

# Connect to server without client certificate
mitmproxy --ssl-insecure

# Modify traffic with script
cat > modify_response.py << 'EOF'
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "api" in flow.request.pretty_url:
        flow.response.headers["X-Intercepted"] = "true"
        print(f"[*] {flow.request.method} {flow.request.pretty_url}")
EOF

mitmproxy -s modify_response.py
```

---

## 6. Custom CA and Certificate Generation

```bash
# Create root CA
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
    -out rootCA.crt \
    -subj "/C=KR/ST=Seoul/O=PentestCA/CN=Pentest Root CA"

# Server certificate signing request (CSR)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=example.com"

# Configure SAN (Subject Alternative Name)
cat > san.ext << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = *.example.com
IP.1 = 192.168.1.100
EOF

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server.crt -days 365 \
    -sha256 -extfile san.ext
```

---

## 7. Python TLS Fingerprinting Tool

```python
#!/usr/bin/env python3
"""TLS server certificate and configuration analysis CLI."""

import argparse
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class TLSInfo:
    host: str
    port: int
    tls_version: str = ""
    cipher_suite: str = ""
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_san: list[str] = field(default_factory=list)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_days_remaining: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    supports_tls10: bool = False
    supports_tls11: bool = False
    supports_tls12: bool = False
    supports_tls13: bool = False


def check_tls_version(host: str, port: int, version: int) -> bool:
    """Check if a specific TLS version is supported."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        match version:
            case 10:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            case 11:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            case 12:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            case 13:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        return False

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, ConnectionRefusedError):
        return False


def analyze_tls(host: str, port: int = 443) -> TLSInfo:
    info = TLSInfo(host=host, port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.tls_version = ssock.version() or ""
                cipher = ssock.cipher()
                info.cipher_suite = cipher[0] if cipher else ""

                cert = ssock.getpeercert()
                if cert:
                    info.cert_subject = dict(x[0] for x in cert.get("subject", []))
                    info.cert_issuer  = dict(x[0] for x in cert.get("issuer", []))

                    # Extract SAN
                    for san_type, san_value in cert.get("subjectAltName", []):
                        info.cert_san.append(f"{san_type}:{san_value}")

                    # Validity period
                    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
                    not_after  = ssl.cert_time_to_seconds(cert["notAfter"])
                    now        = datetime.now(tz=timezone.utc).timestamp()

                    info.cert_not_before = cert["notBefore"]
                    info.cert_not_after  = cert["notAfter"]
                    info.cert_days_remaining = int((not_after - now) / 86400)
                    info.is_expired = now > not_after

                    # Check self-signed
                    info.is_self_signed = (info.cert_subject == info.cert_issuer)

    except (ssl.SSLError, OSError) as e:
        print(f"[!] Connection error: {e}")

    # Check legacy TLS version support
    info.supports_tls10 = check_tls_version(host, port, 10)
    info.supports_tls11 = check_tls_version(host, port, 11)
    info.supports_tls12 = check_tls_version(host, port, 12)
    info.supports_tls13 = check_tls_version(host, port, 13)

    return info


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS server analysis tool")
    parser.add_argument("host", help="Target host")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()

    info = analyze_tls(args.host, args.port)

    print(f"\n=== TLS Analysis: {info.host}:{info.port} ===\n")
    print(f"TLS Version: {info.tls_version}")
    print(f"Cipher Suite: {info.cipher_suite}")
    print(f"\nCertificate Subject: {info.cert_subject.get('commonName', '?')}")
    print(f"Issuer: {info.cert_issuer.get('commonName', '?')}")
    print(f"SAN: {', '.join(info.cert_san[:5])}")
    print(f"Expiry: {info.cert_not_after}")
    print(f"Days remaining: {info.cert_days_remaining}")

    print(f"\nVulnerability indicators:")
    print(f"  TLS 1.0 supported: {'[VULNERABLE]' if info.supports_tls10 else '[-]'}")
    print(f"  TLS 1.1 supported: {'[VULNERABLE]' if info.supports_tls11 else '[-]'}")
    print(f"  TLS 1.2 supported: {'[+]' if info.supports_tls12 else '[-]'}")
    print(f"  TLS 1.3 supported: {'[+]' if info.supports_tls13 else '[-]'}")
    print(f"  Self-signed: {'[WARNING]' if info.is_self_signed else '[-]'}")
    print(f"  Certificate expired: {'[EXPIRED]' if info.is_expired else '[-]'}")


if __name__ == "__main__":
    main()
```

---

## 8. TLS Security Audit Checklist

| Item | Recommended Setting | Verification Method |
|------|---------------------|---------------------|
| Minimum TLS version | TLS 1.2 or higher | testssl.sh |
| Certificate validity period | 398 days or less | openssl x509 |
| Certificate signature algorithm | SHA-256 or higher | sslyze |
| Key strength | RSA 2048+, ECDSA 256+ | openssl x509 |
| HSTS header | Strict-Transport-Security required | curl -I |
| OCSP Stapling | Recommended to enable | openssl s_client |
| Forward Secrecy | Prefer ECDHE/DHE | nmap ssl-enum-ciphers |
| Weak cipher suites | Exclude RC4, DES, NULL | sslyze |
| Certificate transparency | Submit to CT logs | crt.sh |
| HPKP alternative | Certificate Pinning (apps) | Code review |

---

## 9. Nginx TLS Hardening Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.crt;
    ssl_certificate_key /etc/ssl/private/example.key;

    # Restrict TLS versions (1.2+ only)
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;  # Recommended off for TLS 1.3

    # HSTS (2 years)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    # DH parameters
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    # Session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
}
```
