"""
취약한 Kubernetes API 서버 시뮬레이터
실제 K8s API 형식을 모방하며, 의도적으로 인증이 취약합니다.
"""
from __future__ import annotations

import os
from flask import Flask, jsonify, request

app = Flask(__name__)
ADMIN_TOKEN = os.environ.get("K8S_ADMIN_TOKEN", "DEMO_TOKEN")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG{k8s_demo}")

# 가짜 시크릿 데이터
SECRETS = {
    "default": {
        "db-credentials": {
            "username": "dbadmin",
            "password": "Pr0d_P4ssw0rd!",
            "host": "db.internal.corp.local",
        },
        "aws-credentials": {
            "access_key": "FAKEKEYEXAMPLE000000",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "admin-token": {"token": ADMIN_TOKEN, "flag": SECRET_FLAG},
    }
}


def check_auth() -> bool:
    """취약한 인증: 토큰이 없거나 잘못된 형식도 통과"""
    auth = request.headers.get("Authorization", "")
    # 취약 포인트: 인증 헤더가 있으면 무조건 통과
    if auth:
        return True
    # anonymous 접근도 일부 엔드포인트 허용
    return False


# API 서버 버전 정보 (익명 접근 허용 — 실제 K8s에서도 종종 허용됨)
@app.route("/version")
def version():
    return jsonify({
        "major": "1",
        "minor": "28",
        "gitVersion": "v1.28.0",
        "platform": "linux/amd64",
        "flag_hint": "다른 엔드포인트를 탐색해보세요!"
    })


# 네임스페이스 목록 (취약: 인증 없이 접근 가능)
@app.route("/api/v1/namespaces")
def list_namespaces():
    return jsonify({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "production"}},
            {"metadata": {"name": "staging"}},
        ]
    })


# 시크릿 목록 (취약: 약한 인증)
@app.route("/api/v1/namespaces/<namespace>/secrets")
def list_secrets(namespace):
    if not check_auth():
        # 익명으로도 목록은 볼 수 있음 (취약 설정)
        pass
    ns_secrets = SECRETS.get(namespace, {})
    return jsonify({
        "apiVersion": "v1",
        "kind": "SecretList",
        "items": [
            {"metadata": {"name": k}, "type": "Opaque"}
            for k in ns_secrets.keys()
        ]
    })


# 특정 시크릿 조회 (취약: base64 인코딩이지만 평문 노출)
@app.route("/api/v1/namespaces/<namespace>/secrets/<name>")
def get_secret(namespace, name):
    ns_secrets = SECRETS.get(namespace, {})
    secret = ns_secrets.get(name)
    if not secret:
        return jsonify({"message": "not found"}), 404
    import base64
    encoded = {k: base64.b64encode(v.encode()).decode() for k, v in secret.items()}
    return jsonify({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "data": encoded,
        "_raw": secret  # 취약 포인트: 평문도 함께 노출
    })


# 파드 목록
@app.route("/api/v1/namespaces/<namespace>/pods")
def list_pods(namespace):
    return jsonify({
        "apiVersion": "v1",
        "kind": "PodList",
        "items": [
            {
                "metadata": {"name": "web-app-7d9f8b-xk2p9"},
                "spec": {
                    "serviceAccountName": "default",
                    "containers": [{"name": "web", "image": "nginx:latest"}]
                },
                "status": {"phase": "Running", "podIP": "10.244.0.5"}
            },
            {
                "metadata": {"name": "db-primary-0"},
                "spec": {
                    "serviceAccountName": "db-sa",
                    "containers": [{"name": "mysql", "image": "mysql:8.0"}]
                },
                "status": {"phase": "Running", "podIP": "10.244.0.6"}
            }
        ]
    })


# 서비스 계정 토큰 탈취 (핵심 취약점)
@app.route("/api/v1/namespaces/<namespace>/serviceaccounts/<sa>/token", methods=["POST"])
def get_sa_token(namespace, sa):
    return jsonify({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "status": {
            "token": f"eyJhbGciOiJSUzI1NiJ9.{namespace}.{sa}.FAKE_SA_TOKEN",
            "expirationTimestamp": "2099-01-01T00:00:00Z",
            "flag": SECRET_FLAG
        }
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, debug=False)
