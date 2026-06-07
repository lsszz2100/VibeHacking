"""
DMZ 웹 앱 — SSRF + XXE 취약점
전체 시나리오 랩의 진입점
"""
from __future__ import annotations

import os
import requests
from lxml import etree
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
INTERNAL_API = os.environ.get("INTERNAL_API", "http://172.30.2.20")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG{dmz_demo}")

HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Corp Demo — 내부 시스템</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; padding: 40px; }
        .card { background: #fff; border-radius: 8px; padding: 24px; margin: 16px 0; box-shadow: 0 2px 8px rgba(0,0,0,.1); }
        input, textarea { width: 100%; padding: 8px; margin: 4px 0; box-sizing: border-box; }
        button { padding: 8px 24px; background: #1a73e8; color: #fff; border: none; cursor: pointer; border-radius: 4px; }
        pre { background: #f8f9fa; padding: 12px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Corp Demo Application</h1>

    <div class="card">
        <h2>URL 미리보기 서비스</h2>
        <form action="/preview" method="GET">
            <input type="text" name="url" placeholder="URL 입력..." />
            <button type="submit">미리보기</button>
        </form>
    </div>

    <div class="card">
        <h2>XML 데이터 처리</h2>
        <form action="/parse-xml" method="POST">
            <textarea name="xml" rows="8" placeholder="XML 데이터 입력..."></textarea>
            <button type="submit">처리</button>
        </form>
    </div>

    <div class="card">
        <h2>내부 API 상태 확인</h2>
        <a href="/internal-status">상태 확인</a>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


# 취약 포인트 1: SSRF — URL 검증 없이 내부 요청
@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if not url:
        return "URL을 입력하세요.", 400
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return jsonify({
            "status_code": resp.status_code,
            "content": resp.text[:8192],
            "headers": dict(resp.headers)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 취약 포인트 2: XXE — 외부 엔티티 처리 허용
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.form.get("xml", "") or request.data.decode()
    if not xml_data:
        return "XML 데이터 없음", 400
    try:
        # 취약: resolve_entities=True (기본값), external entity 허용
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(xml_data.encode(), parser)
        result = etree.tostring(root, pretty_print=True).decode()
        return jsonify({"parsed": result, "tag": root.tag, "text": root.text})
    except Exception as e:
        return jsonify({"error": str(e), "raw_xml": xml_data[:512]}), 400


# SSRF로 내부 API 상태 확인
@app.route("/internal-status")
def internal_status():
    try:
        resp = requests.get(f"{INTERNAL_API}/health", timeout=3)
        return jsonify({"internal_api": resp.json()})
    except Exception as e:
        return jsonify({"error": str(e)})


# 관리자 페이지 (숨겨진 엔드포인트)
@app.route("/admin")
def admin():
    token = request.headers.get("X-Admin-Token", "")
    if token != "admin_secret_token_2024":
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "flag": SECRET_FLAG,
        "internal_api": INTERNAL_API,
        "db_host": os.environ.get("DB_HOST", ""),
        "env": dict(os.environ)  # 취약: 전체 환경변수 노출
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
