# PKI 인프라 및 TLS/SSL 공격

## 개요

TLS/SSL은 인터넷 보안의 근간이지만, 구현 결함과 설정 오류로 인해 다양한 공격이 가능하다. PKI(Public Key Infrastructure)의 신뢰 체계를 이해하고 공격자 관점에서 분석한다.

---

## TLS 핸드셰이크 구조 복습

```
클라이언트                              서버
   |── ClientHello (암호 스위트 목록) ──→|
   |←─ ServerHello (선택된 암호 스위트) ─|
   |←─ Certificate (서버 인증서)         |
   |←─ ServerHelloDone                   |
   |── ClientKeyExchange ───────────────→|
   |── ChangeCipherSpec ────────────────→|
   |── Finished ───────────────────────→|
   |←─ ChangeCipherSpec                  |
   |←─ Finished                          |
   |═══════════ 암호화 통신 ════════════|
```

---

## 역사적 TLS 취약점

### BEAST (Browser Exploit Against SSL/TLS)
- **CVE**: CVE-2011-3389
- **영향**: TLS 1.0, CBC 모드 암호
- **원리**: IV 예측 가능성으로 블록 암호 공격
- **방어**: TLS 1.1+ 사용, RC4 우선(당시), 현재는 TLS 1.2+ 사용

### CRIME (Compression Ratio Info-leak Made Easy)
- **CVE**: CVE-2012-4929
- **원리**: TLS 압축 + 세션 쿠키 추측으로 압축률 측정
- **방어**: TLS 압축 비활성화 (`ssl_no_compression`)

### POODLE (Padding Oracle On Downgraded Legacy Encryption)
- **CVE**: CVE-2014-3566
- **영향**: SSLv3, CBC 패딩
- **원리**: 패딩 오라클로 암호문 복호화
- **방어**: SSLv3 완전 비활성화

### Heartbleed
- **CVE**: CVE-2014-0160
- **영향**: OpenSSL 1.0.1 ~ 1.0.1f
- **원리**: TLS Heartbeat 확장의 길이 검증 미흡으로 서버 메모리 노출
- **방어**: OpenSSL 1.0.1g+ 업데이트

```bash
# Heartbleed 테스트 (이미 패치된 서버 대상 학습용)
nmap --script ssl-heartbleed -p 443 TARGET_HOST

# sslyze로 Heartbleed 확인
sslyze TARGET_HOST:443 --heartbleed
```

### DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
- **CVE**: CVE-2016-0800
- **원리**: SSLv2 오라클로 현대 TLS 세션 복호화
- **영향**: 같은 RSA 키를 SSLv2 서버와 공유 시

---

## SSLScan 및 TLS 분석

### sslyze 사용법

```bash
# 기본 스캔
sslyze TARGET_HOST:443

# 상세 스캔 (모든 취약점 확인)
sslyze TARGET_HOST:443 \
  --robot \
  --heartbleed \
  --openssl_ccs_injection \
  --fallback_scsv \
  --reneg \
  --certinfo \
  --elliptic_curves

# JSON 출력
sslyze TARGET_HOST:443 --json_out results.json
```

### sslscan 사용법

```bash
# 기본 스캔
sslscan TARGET_HOST:443

# 특정 프로토콜 강제
sslscan --tls10 --tls11 TARGET_HOST:443

# 취약한 암호 스위트 확인
sslscan TARGET_HOST:443 | grep -E "SSL|TLS|Preferred|NULL|EXPORT|DES|RC4|MD5"
```

### testssl.sh 종합 테스트

```bash
# 설치
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh

# 전체 취약점 테스트
./testssl.sh TARGET_HOST:443

# 특정 취약점만
./testssl.sh --beast --crime --poodle --heartbleed TARGET_HOST:443

# HTML 리포트 생성
./testssl.sh --htmlfile report.html TARGET_HOST:443
```

---

## 인증서 투명성(CT) 로그 활용

Certificate Transparency는 CA가 발급한 모든 인증서를 공개 로그에 기록하는 제도로, 서브도메인 열거에 매우 효과적이다.

```bash
# crt.sh 검색 (웹)
# https://crt.sh/?q=%.example.com

# 커맨드라인으로 crt.sh API 사용
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
domains = {entry['name_value'] for entry in data}
print('\n'.join(sorted(domains)))
"

# subfinder로 CT 로그 기반 서브도메인 열거
subfinder -d example.com -all -recursive

# amass로 CT 로그 포함 종합 열거
amass enum -d example.com -src
```

---

## MITM을 통한 TLS 인터셉트

### mitmproxy 사용

```bash
# 설치
pip install mitmproxy

# HTTP/HTTPS 프록시 실행 (포트 8080)
mitmproxy -p 8080

# 인터랙티브 없이 덤프만
mitmdump -p 8080 -w capture.pcap

# 스크립트로 특정 요청 수정
mitmdump -p 8080 -s intercept_script.py
```

```python
# intercept_script.py - 요청/응답 인터셉트
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if "Authorization" in flow.request.headers:
        print(f"[CRED] {flow.request.url}")
        print(f"       Auth: {flow.request.headers['Authorization']}")

def response(flow: http.HTTPFlow) -> None:
    if "Set-Cookie" in flow.response.headers:
        print(f"[COOKIE] {flow.response.headers['Set-Cookie']}")
```

### 자체 CA 구축으로 인증서 위조

```bash
# 루트 CA 생성
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes \
  -key rootCA.key \
  -sha256 -days 1024 \
  -out rootCA.pem \
  -subj "/C=KR/O=Evil CA/CN=Root CA"

# 사이트별 위조 인증서 생성
DOMAIN="target.example.com"

openssl genrsa -out ${DOMAIN}.key 2048
openssl req -new -key ${DOMAIN}.key \
  -out ${DOMAIN}.csr \
  -subj "/CN=${DOMAIN}"

# SAN(Subject Alternative Name) 포함 서명
cat > san.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = www.${DOMAIN}
EOF

openssl x509 -req -in ${DOMAIN}.csr \
  -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out ${DOMAIN}.crt \
  -days 365 -sha256 -extfile san.ext
```

---

## Python TLS 지문채취 도구

```python
#!/usr/bin/env python3
"""
TLS Fingerprinter - TLS 설정 분석 및 취약점 탐지
사용법: python3 tls_fingerprint.py --host example.com --port 443
"""

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: str = ""
    cipher_suite: str = ""
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_expiry: str = ""
    cert_san: list[str] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "anon",
    "MD5", "ADH", "AECDH", "eNULL", "aNULL",
]

PROTOCOL_MAP = {
    "ssl2": ssl.PROTOCOL_TLS_CLIENT,
    "ssl3": ssl.PROTOCOL_TLS_CLIENT,
    "tls10": ssl.PROTOCOL_TLS_CLIENT,
    "tls11": ssl.PROTOCOL_TLS_CLIENT,
    "tls12": ssl.PROTOCOL_TLS_CLIENT,
    "tls13": ssl.PROTOCOL_TLS_CLIENT,
}

PROTOCOL_VERSION_MAP = {
    "ssl3": ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
    "tls10": ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
    "tls11": ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3,
    "tls12": ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3,
    "tls13": ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2,
}


def get_tls_info(host: str, port: int, timeout: float = 10.0) -> TLSInfo:
    info = TLSInfo(host=host, port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.protocol = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]

                cert = ssock.getpeercert()
                if cert:
                    info.cert_subject = dict(x[0] for x in cert.get("subject", []))
                    info.cert_issuer = dict(x[0] for x in cert.get("issuer", []))
                    info.cert_expiry = cert.get("notAfter", "")

                    san_list = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        san_list.append(f"{san_type}:{san_value}")
                    info.cert_san = san_list

    except (ssl.SSLError, ConnectionRefusedError, socket.timeout) as e:
        info.vulnerabilities.append(f"연결 실패: {e}")
        return info

    # 취약한 프로토콜 버전 지원 여부 확인
    for proto_name in ["tls10", "tls11"]:
        if _test_protocol_version(host, port, proto_name, timeout):
            info.supported_protocols.append(proto_name.upper())
            if proto_name in ("tls10", "tls11"):
                info.vulnerabilities.append(f"취약 프로토콜 지원: {proto_name.upper()}")

    # 현재 암호 스위트에 약한 알고리즘 포함 여부
    for weak in WEAK_CIPHERS:
        if weak in info.cipher_suite:
            info.weak_ciphers.append(info.cipher_suite)
            info.vulnerabilities.append(f"취약 암호 스위트: {info.cipher_suite}")
            break

    return info


def _test_protocol_version(host: str, port: int, proto: str, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    options = PROTOCOL_VERSION_MAP.get(proto, 0)
    ctx.options |= options

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def scan_hosts(
    targets: list[tuple[str, int]],
    max_workers: int = 10,
) -> list[TLSInfo]:
    results: list[TLSInfo] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_tls_info, host, port): (host, port)
            for host, port in targets
        }
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                result = future.result()
                results.append(result)
                if result.vulnerabilities:
                    print(f"[!] {host}:{port} — 취약점 {len(result.vulnerabilities)}개")
                else:
                    print(f"[+] {host}:{port} — OK")
            except Exception as e:
                print(f"[-] {host}:{port} — 오류: {e}", file=sys.stderr)

    return results


def print_report(info: TLSInfo) -> None:
    print(f"\n{'='*60}")
    print(f"호스트: {info.host}:{info.port}")
    print(f"{'='*60}")
    print(f"  프로토콜:    {info.protocol}")
    print(f"  암호 스위트: {info.cipher_suite}")
    print(f"  인증서 CN:   {info.cert_subject.get('commonName', 'N/A')}")
    print(f"  발급자:      {info.cert_issuer.get('organizationName', 'N/A')}")
    print(f"  만료일:      {info.cert_expiry}")

    if info.cert_san:
        print(f"  SAN ({len(info.cert_san)}개): {', '.join(info.cert_san[:3])}")

    if info.vulnerabilities:
        print(f"\n  ⚠ 취약점 ({len(info.vulnerabilities)}개):")
        for v in info.vulnerabilities:
            print(f"    - {v}")
    else:
        print("\n  ✓ 취약점 미발견")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TLS Fingerprinter - TLS 설정 분석 및 취약점 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 tls_fingerprint.py --host example.com
  python3 tls_fingerprint.py --host example.com --port 8443
  python3 tls_fingerprint.py --file hosts.txt --workers 20
  python3 tls_fingerprint.py --host example.com --json
        """,
    )
    parser.add_argument("--host", help="단일 호스트")
    parser.add_argument("--port", type=int, default=443, help="포트 (기본: 443)")
    parser.add_argument("--file", help="호스트 목록 파일 (host:port 형식)")
    parser.add_argument("--workers", type=int, default=10, help="병렬 작업 수")
    parser.add_argument("--json", action="store_true", help="JSON 출력")
    parser.add_argument("--timeout", type=float, default=10.0, help="타임아웃 (초)")

    args = parser.parse_args()

    targets: list[tuple[str, int]] = []

    if args.host:
        targets.append((args.host, args.port))
    elif args.file:
        from pathlib import Path
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                h, p = line.rsplit(":", 1)
                targets.append((h, int(p)))
            else:
                targets.append((line, 443))
    else:
        parser.print_help()
        sys.exit(1)

    results = scan_hosts(targets, max_workers=args.workers)

    if args.json:
        import dataclasses
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    else:
        for result in results:
            print_report(result)

    vuln_count = sum(1 for r in results if r.vulnerabilities)
    print(f"\n총 {len(results)}개 호스트 스캔 완료 — 취약점 발견: {vuln_count}개")
    sys.exit(1 if vuln_count > 0 else 0)


if __name__ == "__main__":
    main()
```

---

## 실전 체크리스트

### TLS 설정 감사
- [ ] SSLv2/SSLv3 비활성화 확인
- [ ] TLS 1.0/1.1 비활성화 확인
- [ ] RC4, DES, EXPORT 암호 비활성화
- [ ] Perfect Forward Secrecy(ECDHE) 지원 여부
- [ ] HSTS(HTTP Strict Transport Security) 설정
- [ ] 인증서 만료 모니터링 자동화
- [ ] CT 로그 모니터링 (인가되지 않은 인증서 발급 탐지)

### Nginx TLS 보안 설정 예시
```nginx
server {
    listen 443 ssl http2;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    ssl_stapling on;
    ssl_stapling_verify on;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```
