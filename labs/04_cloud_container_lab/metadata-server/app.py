"""
AWS IMDS (Instance Metadata Service) 시뮬레이터
실제 AWS IMDSv1 API를 모방합니다.
SSRF 취약점을 통해 이 서버에 접근하여 자격증명을 탈취하는 실습용입니다.
"""
from __future__ import annotations

import os
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "FAKEKEYEXAMPLE000000")
SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
SESSION_TOKEN = os.environ.get("AWS_SESSION_TOKEN", "AQoDYXdzEJr...EXAMPLETOKEN")
INSTANCE_ID = os.environ.get("INSTANCE_ID", "i-1234567890abcdef0")
REGION = os.environ.get("REGION", "ap-northeast-2")
ROLE_NAME = os.environ.get("ROLE_NAME", "ec2-prod-role")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG{imds_demo}")


# IMDSv1 — 토큰 없이 접근 가능 (취약)
# IMDSv2 — PUT /latest/api/token 필요

@app.route("/latest/meta-data/")
def metadata_root():
    return Response(
        "ami-id\nami-launch-index\nami-manifest-path\n"
        "hostname\niam/\ninstance-id\ninstance-type\n"
        "local-ipv4\nplacement/\npublic-ipv4\n",
        mimetype="text/plain"
    )


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return Response(INSTANCE_ID, mimetype="text/plain")


@app.route("/latest/meta-data/instance-type")
def instance_type():
    return Response("t2.micro", mimetype="text/plain")


@app.route("/latest/meta-data/local-ipv4")
def local_ipv4():
    return Response("172.18.0.20", mimetype="text/plain")


@app.route("/latest/meta-data/hostname")
def hostname():
    return Response(f"ip-172-18-0-20.{REGION}.compute.internal", mimetype="text/plain")


@app.route("/latest/meta-data/placement/region")
def placement_region():
    return Response(REGION, mimetype="text/plain")


@app.route("/latest/meta-data/iam/")
def iam_root():
    return Response("info\nsecurity-credentials/\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/info")
def iam_info():
    return jsonify({
        "Code": "Success",
        "LastUpdated": "2024-01-01T00:00:00Z",
        "InstanceProfileArn": f"arn:aws:iam::123456789012:instance-profile/{ROLE_NAME}",
        "InstanceProfileId": "AIPAIOSFODNN7EXAMPLE"
    })


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_credentials_list():
    return Response(f"{ROLE_NAME}\n", mimetype="text/plain")


# 핵심 엔드포인트: 임시 자격증명 제공
@app.route("/latest/meta-data/iam/security-credentials/<role>")
def iam_credentials(role):
    return jsonify({
        "Code": "Success",
        "LastUpdated": "2024-01-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": ACCESS_KEY,
        "SecretAccessKey": SECRET_KEY,
        "Token": SESSION_TOKEN,
        "Expiration": "2099-01-01T00:00:00Z",
        "Flag": SECRET_FLAG
    })


@app.route("/latest/user-data")
def user_data():
    return Response(
        "#!/bin/bash\n"
        "# 초기화 스크립트\n"
        f"echo 'DB_PASSWORD=Pr0d_DB_P4ss!' >> /etc/environment\n"
        f"# Internal API: http://internal-api.corp.local\n",
        mimetype="text/plain"
    )


@app.route("/latest/dynamic/instance-identity/document")
def identity_document():
    return jsonify({
        "accountId": "123456789012",
        "architecture": "x86_64",
        "availabilityZone": f"{REGION}a",
        "instanceId": INSTANCE_ID,
        "instanceType": "t2.micro",
        "region": REGION,
        "privateIp": "172.18.0.20"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
