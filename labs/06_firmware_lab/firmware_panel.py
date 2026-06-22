"""취약한 펌웨어 업데이트 웹 패널 (교육용 — 의도적으로 취약).

하드코딩된 자격증명(admin:firmware_admin_2024)을 노출하는 CTF 대상.
펌웨어 바이너리에서 자격증명을 추출해 /login 으로 플래그를 획득한다.
"""
import hashlib  # noqa: F401  (학습용 — 펌웨어 해시 검증 데모에서 사용)
import os  # noqa: F401

from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET = "admin:firmware_admin_2024"
FLAG = "CTF{firmware_hardcoded_cred_found}"


@app.route("/")
def index():
    return (
        "<h1>Firmware Update Panel v1.0</h1>"
        "<p>POST /upload to update firmware</p>"
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("user") == "admin" and data.get("pass") == "firmware_admin_2024":
        return jsonify({"status": "ok", "flag": FLAG})
    return jsonify({"status": "fail"}), 401


@app.route("/upload", methods=["POST"])
def upload():
    return jsonify(
        {
            "status": "uploaded",
            "hint": "Try to find credentials in firmware binary",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
