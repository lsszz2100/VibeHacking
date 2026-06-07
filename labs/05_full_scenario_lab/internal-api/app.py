"""
내부 API 서버 — 인증 없는 민감한 엔드포인트
SSRF를 통해 DMZ 웹에서 이 서버에 접근합니다.
"""
from __future__ import annotations

import os
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_HOST = os.environ.get("DB_HOST", "172.30.2.30")
DB_USER = os.environ.get("DB_USER", "app_user")
DB_PASS = os.environ.get("DB_PASS", "AppP4ssw0rd!")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG{internal_api_demo}")
LDAP_SERVER = os.environ.get("LDAP_SERVER", "172.30.2.40")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "internal-api",
        "version": "1.2.3",
        "db_host": DB_HOST,   # 취약: 내부 정보 노출
    })


# 취약: 인증 없이 내부 사용자 목록 제공
@app.route("/users")
def users():
    return jsonify({
        "users": [
            {"id": 1, "username": "alice", "email": "alice@corp.local", "role": "developer"},
            {"id": 2, "username": "bob", "email": "bob@corp.local", "role": "developer"},
            {"id": 3, "username": "sysadmin", "email": "sysadmin@corp.local", "role": "admin"},
            {"id": 4, "username": "charlie", "email": "charlie@corp.local", "role": "manager"},
        ],
        "flag": SECRET_FLAG
    })


# 취약: DB 크리덴셜 노출
@app.route("/config")
def config():
    return jsonify({
        "database": {
            "host": DB_HOST,
            "port": 3306,
            "user": DB_USER,
            "password": DB_PASS,
            "database": "corpdb"
        },
        "ldap": {
            "server": LDAP_SERVER,
            "port": 1389,
            "admin_dn": "cn=admin,dc=corp,dc=local",
            "admin_password": "admin123"
        },
        "flag": SECRET_FLAG
    })


# 취약: 내부 서비스 프록시
@app.route("/proxy")
def proxy():
    target = request.args.get("url", "")
    if not target:
        return jsonify({"error": "url 파라미터 필요"}), 400
    try:
        resp = requests.get(target, timeout=5)
        return jsonify({"status": resp.status_code, "body": resp.text[:4096]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 취약: 환경변수 전체 노출
@app.route("/env")
def env():
    return jsonify(dict(os.environ))


# 취약: SQL 인젝션 가능한 검색
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # 실제 DB 없이 시뮬레이션
    results = [
        {"id": 1, "name": "Product A", "price": 100},
        {"id": 2, "name": "Product B", "price": 200},
    ]
    return jsonify({"query": q, "results": results, "flag": SECRET_FLAG if "'" in q else None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
