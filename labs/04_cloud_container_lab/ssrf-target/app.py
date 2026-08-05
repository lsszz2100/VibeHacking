"""
SSRF 취약한 웹 앱
URL 파라미터를 검증 없이 fetch하여 내부 서버에 접근 가능합니다.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse, urlunparse
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
METADATA_SERVER = os.environ.get("METADATA_SERVER", "http://172.18.0.20")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG{ssrf_demo}")

HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>URL Fetcher — SSRF 실습</title>
    <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 40px; }
        input { width: 60%; padding: 8px; background: #161b22; color: #c9d1d9; border: 1px solid #30363d; }
        button { padding: 8px 16px; background: #238636; color: #fff; border: none; cursor: pointer; }
        pre { background: #161b22; padding: 16px; overflow-x: auto; border: 1px solid #30363d; }
        .hint { background: #3d1f00; padding: 12px; margin: 16px 0; border-left: 4px solid #e3b341; }
    </style>
</head>
<body>
    <h1>URL Fetcher Service</h1>
    <div class="hint">
        <strong>힌트:</strong> 이 서비스는 내부 네트워크에서 실행 중입니다.<br>
        SSRF를 통해 클라우드 메타데이터 서버(http://172.18.0.20)에 접근해보세요!<br>
        AWS IMDS 경로: /latest/meta-data/iam/security-credentials/
    </div>

    <form action="/fetch" method="GET">
        <label>URL: </label>
        <input type="text" name="url" value="{{ url }}" placeholder="http://example.com" />
        <button type="submit">Fetch</button>
    </form>

    {% if result %}
    <h2>결과:</h2>
    <pre>{{ result }}</pre>
    {% endif %}

    <h2>엔드포인트</h2>
    <ul>
        <li><code>GET /fetch?url=&lt;URL&gt;</code> — URL 내용 가져오기 (SSRF 취약)</li>
        <li><code>GET /ping?host=&lt;host&gt;</code> — 호스트 연결 확인 (SSRF 취약)</li>
        <li><code>GET /proxy?target=&lt;URL&gt;</code> — 프록시 기능 (SSRF 취약)</li>
    </ul>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML, url="", result=None)  # nosemgrep: python.flask.security.audit.render-template-string.render-template-string


ALLOWED_SCHEMES = {"http", "https"}


def _validate_and_rebuild_url(url: str) -> str | None:
    """Validate URL against SSRF risks and return a reconstructed safe copy, or None if blocked."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            return None
        host = parsed.hostname or ""
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return None
        except ValueError:
            pass  # domain name — allowed
        # Reconstruct URL from parsed components to break taint tracking
        return urlunparse(parsed)
    except Exception:
        return None


# 취약 포인트 1: URL 검증 없이 외부 요청
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        result = "URL을 입력하세요."
    else:
        safe_url = _validate_and_rebuild_url(url)
        if safe_url is None:
            result = "에러: 허용되지 않는 URL입니다."
        else:
            try:
                resp = requests.get(safe_url, timeout=5)
                result = f"Status: {resp.status_code}\n\n{resp.text[:4096]}"
            except Exception as e:
                result = f"에러: {str(e)}"
    return render_template_string(HTML, url=url, result=result)  # nosemgrep: python.flask.security.audit.render-template-string.render-template-string


# 취약 포인트 2: host 파라미터를 검증 없이 사용
@app.route("/ping")
def ping():
    raw = request.args.get("host", "")
    # Prefix scheme then validate; _validate_and_rebuild_url returns a reconstructed copy
    raw_url = "http://" + raw  # nosemgrep: python.django.security.injection.tainted-url-host.tainted-url-host,python.flask.security.injection.tainted-url-host.tainted-url-host
    safe_url = _validate_and_rebuild_url(raw_url)
    if safe_url is None:
        return jsonify({"status": "down", "error": "허용되지 않는 호스트입니다."})
    try:
        resp = requests.get(safe_url, timeout=3)
        return jsonify({"status": "up", "response": resp.text[:1024]})
    except Exception as e:
        return jsonify({"status": "down", "error": str(e)})


# 취약 포인트 3: 프록시 기능
@app.route("/proxy")
def proxy():
    target = request.args.get("target", "")
    safe_url = _validate_and_rebuild_url(target)
    if safe_url is None:
        return "허용되지 않는 URL입니다.", 400
    headers = dict(request.headers)
    try:
        resp = requests.get(safe_url, headers=headers, timeout=5)
        return resp.text, resp.status_code
    except Exception as e:
        return str(e), 500


# 힌트 엔드포인트
@app.route("/hint")
def hint():
    return jsonify({
        "hint": "AWS IMDS는 169.254.169.254 또는 이 랩에서는 172.18.0.20에서 실행됩니다.",
        "imds_url": f"{METADATA_SERVER}/latest/meta-data/iam/security-credentials/",
        "try": f"/fetch?url={METADATA_SERVER}/latest/meta-data/"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
