"""취약한 모바일 백엔드 API (교육용 — 의도적으로 취약).

CTF 학습 포인트:
  - FLAG_1: APK에 하드코딩된 API 키 노출 (/login)
  - FLAG_2: JWT alg:none 우회로 admin 권한 획득 (/admin)
"""
import base64
import json

import jwt  # PyJWT
from flask import Flask, jsonify, request

app = Flask(__name__)

HARDCODED_API_KEY = "sk-mobile-dev-key-2024-insecure"
FLAG_1 = "CTF{hardcoded_api_key_in_apk}"
FLAG_2 = "CTF{jwt_alg_none_bypass}"


@app.route("/")
def index():
    return jsonify(
        {
            "api": "MobileApp Backend v2.1",
            "endpoints": ["/login", "/data", "/admin"],
        }
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("api_key") == HARDCODED_API_KEY:
        token = jwt.encode(
            {"user": "guest", "role": "user"}, "secret", algorithm="HS256"
        )
        return jsonify({"token": token, "flag": FLAG_1})
    return jsonify({"error": "invalid key"}), 401


@app.route("/data", methods=["GET"])
def data():
    return jsonify(
        {
            "hint": "API key is hardcoded in the APK. "
            "Check BuildConfig or network layer."
        }
    )


def _b64url_decode(segment: str) -> bytes:
    """JWT 세그먼트(base64url)를 패딩 보정 후 디코드."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


@app.route("/admin", methods=["GET"])
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "no token"}), 401
    token = auth[7:]
    try:
        header = json.loads(_b64url_decode(token.split(".")[0]))
        if header.get("alg", "").lower() == "none":
            payload = json.loads(_b64url_decode(token.split(".")[1]))
            if payload.get("role") == "admin":
                return jsonify(
                    {"flag": FLAG_2, "secret": "admin_panel_data"}
                )
    except Exception:
        pass
    return jsonify({"error": "forbidden"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
