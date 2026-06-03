> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 05 — Cloud Native 보안 방어 체계

## 0. 초보자를 위한 개념 이해

### Cloud Native 보안 방어 체계란?

Cloud Native 보안 방어 체계는 컨테이너, Kubernetes, 클라우드 인프라를 종합적으로 보호하기 위한 다층 방어 전략이다. 단일 보안 제품으로 해결할 수 없으며, 코드 작성 단계부터 배포, 런타임까지 각 레이어에 보안을 내재화(Security by Design)하는 접근이 필요하다. CNCF(Cloud Native Computing Foundation)가 권장하는 4C 모델을 기반으로 각 레이어의 방어 기법을 학습한다.

**왜 배우는가:**
```
[방어 없는 Kubernetes 클러스터의 취약점]

  ★ 기본 설정으로 생성한 클러스터의 문제점:
  - API 서버: 익명 접근 허용 가능
  - etcd: 시크릿 평문 저장 (기본)
  - 컨테이너: root로 실행
  - 네트워크: 모든 Pod 간 통신 허용
  - RBAC: default SA에 과도한 권한

  [방어 체계 도입 후 효과]
  etcd 암호화 → 시크릿 탈취해도 평문 불가
  네트워크 정책 → 컨테이너 간 횡적 이동 차단
  PodSecurity → 특권 컨테이너 실행 거부
  Falco → 의심 행동 실시간 탐지·알림
```

### 핵심 개념 정리

```
[Cloud Native 방어 핵심 요소]

1. 시크릿 관리
   ❌ 환경 변수에 비밀번호 직접 입력
   ✅ HashiCorp Vault, AWS Secrets Manager
   ✅ Kubernetes Secrets (etcd 암호화 필수)
   ✅ External Secrets Operator

2. 네트워크 정책 (Network Policy)
   기본: 모든 Pod 간 통신 허용 (위험!)
   개선: 명시적 허용 목록만 통신 가능
   도구: Calico, Cilium, WeaveNet

3. Pod 보안 (PodSecurityAdmission)
   privileged: false
   runAsNonRoot: true
   readOnlyRootFilesystem: true
   allowPrivilegeEscalation: false

4. 공급망 보안 (SLSA)
   Level 1: 빌드 프로세스 문서화
   Level 2: 서명된 Provenance 생성
   Level 3: 격리된 빌드 환경
   Level 4: 재현 가능한 빌드

5. 보안 태세 관리 (CSPM)
   Kube-bench: CIS 벤치마크 자동 점검
   Trivy: 취약점 지속 스캔
   OPA/Gatekeeper: 정책 강제 적용
```

### 필요한 도구 및 환경
- **kube-bench**: CIS Kubernetes Benchmark 자동 점검 도구
- **OPA Gatekeeper**: Kubernetes Admission Controller로 정책 강제
- **HashiCorp Vault**: 시크릿 중앙 관리 및 동적 자격증명
- **Falco**: eBPF 기반 런타임 이상 탐지

### 기초 실습 예제
```python
import subprocess
import json
from pathlib import Path

def generate_network_policy(
    app_name: str,
    allowed_ingress_ports: list[int],
    allowed_egress_ports: list[int] = [443, 53]
) -> str:
    """
    최소 권한 원칙에 따른 Kubernetes NetworkPolicy YAML을 생성한다.
    """
    ingress_rules = "\n".join([
        f"  - ports:\n    - port: {port}" for port in allowed_ingress_ports
    ])
    egress_rules = "\n".join([
        f"  - ports:\n    - port: {port}" for port in allowed_egress_ports
    ])

    policy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {app_name}-netpol
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: {app_name}
  policyTypes:
  - Ingress
  - Egress
  ingress:
{ingress_rules}
  egress:
{egress_rules}
  # DNS(53) 항상 허용 - 서비스 디스커버리에 필수
"""
    return policy

# 사용 예시
policy_yaml = generate_network_policy(
    app_name="my-web-app",
    allowed_ingress_ports=[80, 443],
    allowed_egress_ports=[443, 53, 5432]  # HTTPS + DNS + PostgreSQL
)
print(policy_yaml)
# 적용: kubectl apply -f - <<< "$policy_yaml"
```

---

## 목차
1. Cloud Native 보안 프레임워크
2. 런타임 보안 (Falco·eBPF)
3. 시크릿 관리 및 암호화
4. 공급망 보안 (SLSA·Sigstore)
5. 클라우드 보안 태세 관리 (CSPM)
6. Kubernetes 감사 및 컴플라이언스
7. Python 도구: K8s 보안 설정 자동 감사기
8. Cloud Native 보안 성숙도 모델

---

## 1. Cloud Native 보안 프레임워크

### 1.1 4C 보안 모델

Cloud Native Computing Foundation(CNCF)이 정의한 계층별 보안 모델.

```
┌───────────────────────────────────────────────┐
│  Code (코드)                                   │
│  └── 정적 분석, 의존성 스캐닝, SAST/DAST       │
├───────────────────────────────────────────────┤
│  Container (컨테이너)                           │
│  └── 이미지 스캔, 런타임 보호, 최소 권한        │
├───────────────────────────────────────────────┤
│  Cluster (클러스터)                             │
│  └── RBAC, 네트워크 정책, 감사 로그, OPA       │
├───────────────────────────────────────────────┤
│  Cloud (클라우드)                               │
│  └── IAM, 인프라 설정 감사, 데이터 암호화       │
└───────────────────────────────────────────────┘
```

### 1.2 CNCF 보안 기술 레이더

| 레이어 | 도구 | 목적 |
|--------|------|------|
| 공급망 | Cosign, Syft, Grype | 이미지 서명, SBOM, 취약점 |
| 런타임 | Falco, Tetragon | 이상 행동 탐지 |
| 네트워크 | Cilium, Calico | eBPF 기반 정책 집행 |
| 시크릿 | Vault, External Secrets | 동적 자격증명 관리 |
| 태세 관리 | Trivy, kube-bench | 설정 감사, CIS 준수 |
| 정책 | OPA Gatekeeper, Kyverno | 어드미션 컨트롤 |

---

## 2. 런타임 보안 (Falco · eBPF)

### 2.1 Falco 룰 작성

Falco는 커널 시스템 콜을 후킹해 컨테이너 런타임 이상을 탐지한다.

```yaml
# /etc/falco/rules.d/ics-custom.yaml

# 컨테이너 내 셸 실행 탐지
- rule: Shell in Container
  desc: 컨테이너 내에서 셸이 실행됨 (공격자 초기 접근 가능성)
  condition: >
    spawned_process and container
    and shell_procs
    and not container.image.repository in (trusted_images)
  output: >
    컨테이너에서 셸 실행 (user=%user.name cmd=%proc.cmdline
    container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution]

# /etc/shadow 읽기 시도
- rule: Read Sensitive File Untrusted
  desc: 비신뢰 프로세스가 민감 파일 접근
  condition: >
    open_read and sensitive_files
    and not proc.name in (trusted_file_readers)
    and not container.image.repository in (trusted_images)
  output: >
    민감 파일 읽기 시도 (user=%user.name file=%fd.name
    proc=%proc.name container=%container.name)
  priority: ERROR
  tags: [filesystem, mitre_credential_access]

# 네트워크 도구 실행 탐지
- rule: Network Tool in Container
  desc: 컨테이너 내 네트워크 정찰 도구 실행
  condition: >
    spawned_process and container
    and proc.name in (network_tools)
  output: >
    컨테이너 내 네트워크 도구 (tool=%proc.name
    container=%container.name image=%container.image.repository
    cmd=%proc.cmdline)
  priority: NOTICE
  tags: [network, container, mitre_discovery]

- list: network_tools
  items: [nmap, masscan, nc, netcat, ncat, tcpdump, tshark, curl, wget]

- list: trusted_images
  items: [monitoring/prometheus, grafana/grafana]
```

### 2.2 Tetragon (eBPF 런타임 집행)

Cilium Tetragon은 eBPF 기반으로 커널 레벨에서 정책을 집행(강제 종료)할 수 있다.

```yaml
# TracingPolicy: /etc/shadow 읽기 시 프로세스 종료
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-shadow-read
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    return: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Postfix"
        values: ["/etc/shadow"]
      matchActions:
      - action: Sigkill   # 즉시 프로세스 종료
```

---

## 3. 시크릿 관리 및 암호화

### 3.1 HashiCorp Vault 동적 시크릿

```
정적 시크릿 (위험):                  Vault 동적 시크릿 (권장):
─────────────────                  ──────────────────────────
.env 파일에 DB 비밀번호 저장         앱 → Vault에 토큰으로 인증
→ 유출 시 영구 접근 가능             → Vault가 임시 DB 자격증명 발급
→ 로테이션 어려움                    → TTL 만료 시 자동 폐기
                                    → 감사 로그에 발급 기록
```

```bash
# Vault Kubernetes 인증 설정
vault auth enable kubernetes

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 역할 생성: app-role은 production 네임스페이스 app SA에만 허용
vault write auth/kubernetes/role/app-role \
  bound_service_account_names=app-service-account \
  bound_service_account_namespaces=production \
  policies=app-policy \
  ttl=1h

# 앱에서 시크릿 읽기
VAULT_TOKEN=$(vault write -field=token \
  auth/kubernetes/login \
  role=app-role \
  jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token))

DB_PASSWORD=$(VAULT_TOKEN=$VAULT_TOKEN vault kv get \
  -field=password secret/database)
```

### 3.2 External Secrets Operator

Kubernetes Secret을 외부 시크릿 저장소(Vault, AWS SM, GCP SM)와 동기화.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: db-secret          # 생성될 K8s Secret 이름
    creationPolicy: Owner
  data:
  - secretKey: DB_PASSWORD
    remoteRef:
      key: secret/database
      property: password
  - secretKey: DB_USERNAME
    remoteRef:
      key: secret/database
      property: username
```

### 3.3 Sealed Secrets (Git 저장 가능한 암호화)

```bash
# Sealed Secrets Controller 설치
helm install sealed-secrets \
  sealed-secrets/sealed-secrets \
  -n kube-system

# 시크릿 암호화 (공개키로)
kubectl create secret generic db-secret \
  --from-literal=password=SuperSecret123 \
  --dry-run=client -o yaml | \
  kubeseal --format yaml > sealed-db-secret.yaml

# Git에 sealed-db-secret.yaml 저장 가능 (개인키 없이 복호화 불가)
git add sealed-db-secret.yaml
```

---

## 4. 공급망 보안 (SLSA · Sigstore)

### 4.1 SLSA 프레임워크

Supply-chain Levels for Software Artifacts — 빌드 무결성 보장.

```
SLSA 레벨:
  Level 0: 보장 없음
  Level 1: 빌드 프로세스 문서화, 출처(provenance) 생성
  Level 2: 버전 관리 + 서명된 출처
  Level 3: 격리된 빌드 환경, 검증 가능한 출처
  Level 4: 두 사람 검토, 밀폐된(hermetic) 빌드
```

### 4.2 Cosign으로 이미지 서명 및 검증

```bash
# 이미지 서명 (키리스 — OIDC 기반)
cosign sign \
  --identity-token=$(gcloud auth print-identity-token) \
  gcr.io/myproject/myapp:v1.0.0

# 서명 검증
cosign verify \
  --certificate-identity=ci@myproject.iam.gserviceaccount.com \
  --certificate-oidc-issuer=https://accounts.google.com \
  gcr.io/myproject/myapp:v1.0.0

# Kyverno 정책: 서명된 이미지만 배포 허용
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-image-signature
    match:
      any:
      - resources:
          kinds: [Pod]
    verifyImages:
    - imageReferences: ["gcr.io/myproject/*"]
      attestors:
      - count: 1
        entries:
        - keyless:
            subject: "ci@myproject.iam.gserviceaccount.com"
            issuer: "https://accounts.google.com"
```

### 4.3 SBOM (Software Bill of Materials)

```bash
# Syft로 컨테이너 이미지 SBOM 생성
syft gcr.io/myproject/myapp:v1.0.0 \
  -o spdx-json > sbom.spdx.json

# Grype로 SBOM 취약점 스캔
grype sbom:./sbom.spdx.json

# SBOM을 이미지에 어테스트
cosign attest \
  --predicate sbom.spdx.json \
  --type spdxjson \
  gcr.io/myproject/myapp:v1.0.0
```

---

## 5. 클라우드 보안 태세 관리 (CSPM)

### 5.1 주요 CSPM 도구

| 도구 | 특징 | 대상 |
|------|------|------|
| Trivy | 올인원 (이미지+IaC+SBOM+시크릿) | 범용 |
| kube-bench | CIS Kubernetes Benchmark | K8s 클러스터 |
| Checkov | IaC 정적 분석 (Terraform, K8s YAML) | DevSecOps |
| Prowler | AWS/Azure/GCP 설정 감사 | 클라우드 |
| ScoutSuite | 멀티클라우드 감사 | 클라우드 |

### 5.2 Trivy 통합 스캐닝

```bash
# 이미지 취약점 + 시크릿 스캔
trivy image \
  --severity HIGH,CRITICAL \
  --scanners vuln,secret \
  gcr.io/myproject/myapp:v1.0.0

# Kubernetes 클러스터 전체 스캔
trivy k8s --report summary cluster

# IaC 스캔 (Terraform/K8s YAML)
trivy config ./k8s-manifests/

# CI/CD 파이프라인 통합 (GitHub Actions)
# .github/workflows/security.yml
# - name: Trivy scan
#   uses: aquasecurity/trivy-action@master
#   with:
#     image-ref: ${{ env.IMAGE }}
#     format: sarif
#     output: trivy-results.sarif
#     severity: CRITICAL,HIGH
```

---

## 6. Kubernetes 감사 및 컴플라이언스

### 6.1 감사 정책 설정

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# 시크릿/ConfigMap 접근 상세 로깅
- level: Metadata
  resources:
  - group: ""
    resources: [secrets, configmaps]

# 파드 exec/attach 완전 로깅
- level: RequestResponse
  resources:
  - group: ""
    resources: [pods/exec, pods/attach, pods/portforward]

# ClusterRole 바인딩 변경 로깅
- level: RequestResponse
  resources:
  - group: rbac.authorization.k8s.io
    resources: [clusterrolebindings, rolebindings]

# 기타 메타데이터만
- level: Metadata
```

### 6.2 OPA Gatekeeper 정책

```yaml
# ConstraintTemplate: 특권 컨테이너 차단
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snoroot
spec:
  crd:
    spec:
      names:
        kind: K8sNoRoot
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8snoroot

      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        container.securityContext.runAsNonRoot != true
        msg := sprintf("컨테이너 %v는 non-root로 실행해야 합니다", [container.name])
      }

---
# Constraint 적용
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoRoot
metadata:
  name: require-non-root
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: [Pod]
    namespaces: [production, staging]
```

---

## 7. Python 도구: K8s 보안 설정 자동 감사기

```python
#!/usr/bin/env python3
"""
K8s Security Auditor
Kubernetes 매니페스트 YAML의 보안 설정 오류를 자동 탐지
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("[오류] pyyaml 설치 필요: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


@dataclass
class Finding:
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    resource: str
    check: str
    message: str
    remediation: str


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, resource: str, check: str,
            message: str, remediation: str) -> None:
        self.findings.append(Finding(severity, resource, check, message, remediation))

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in self.findings:
            counts[f.severity] += 1
        return counts


def audit_pod_spec(spec: dict[str, Any], resource_name: str,
                   result: AuditResult) -> None:
    """Pod spec 보안 설정 검사"""
    containers = spec.get("containers", []) + spec.get("initContainers", [])

    for container in containers:
        name = container.get("name", "unknown")
        resource_id = f"{resource_name}/container:{name}"
        sc = container.get("securityContext", {})

        # 루트 실행 검사
        if sc.get("runAsUser") == 0:
            result.add("CRITICAL", resource_id, "RootUser",
                       "컨테이너가 root(UID 0)로 실행됩니다",
                       "securityContext.runAsNonRoot: true 및 runAsUser: 1000+ 설정")

        if not sc.get("runAsNonRoot"):
            result.add("HIGH", resource_id, "MissingRunAsNonRoot",
                       "runAsNonRoot가 설정되지 않았습니다",
                       "securityContext.runAsNonRoot: true 추가")

        # 특권 컨테이너 검사
        if sc.get("privileged"):
            result.add("CRITICAL", resource_id, "PrivilegedContainer",
                       "특권(privileged) 컨테이너입니다",
                       "privileged: false 설정 또는 제거")

        # capabilities 검사
        caps = sc.get("capabilities", {})
        dangerous_caps = {
            "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
            "DAC_OVERRIDE", "NET_RAW", "SYS_CHROOT",
        }
        added = set(caps.get("add", []))
        bad_caps = added & dangerous_caps
        if bad_caps:
            result.add("HIGH", resource_id, "DangerousCapabilities",
                       f"위험한 Linux capabilities 추가됨: {bad_caps}",
                       "필요한 최소 capabilities만 허용, drop: [ALL] 추가")

        if "ALL" not in caps.get("drop", []):
            result.add("MEDIUM", resource_id, "CapsNotDroppedAll",
                       "capabilities.drop: [ALL]이 설정되지 않았습니다",
                       "securityContext.capabilities.drop: [ALL] 추가")

        # allowPrivilegeEscalation 검사
        if sc.get("allowPrivilegeEscalation", True):
            result.add("HIGH", resource_id, "PrivilegeEscalation",
                       "권한 에스컬레이션이 허용됩니다",
                       "securityContext.allowPrivilegeEscalation: false 설정")

        # 읽기 전용 루트 파일시스템
        if not sc.get("readOnlyRootFilesystem"):
            result.add("MEDIUM", resource_id, "WritableRootFS",
                       "루트 파일시스템이 쓰기 가능 상태입니다",
                       "securityContext.readOnlyRootFilesystem: true 설정")

        # 리소스 제한
        resources = container.get("resources", {})
        if not resources.get("limits", {}).get("cpu"):
            result.add("LOW", resource_id, "NoCpuLimit",
                       "CPU 제한이 설정되지 않았습니다",
                       "resources.limits.cpu 설정 (예: 500m)")
        if not resources.get("limits", {}).get("memory"):
            result.add("LOW", resource_id, "NoMemoryLimit",
                       "메모리 제한이 설정되지 않았습니다",
                       "resources.limits.memory 설정 (예: 256Mi)")

        # 이미지 태그 검사
        image = container.get("image", "")
        if image.endswith(":latest") or ":" not in image:
            result.add("MEDIUM", resource_id, "LatestImageTag",
                       f"latest 또는 태그 없는 이미지 사용: {image}",
                       "특정 버전 태그 또는 이미지 다이제스트 사용")

    # Pod 레벨 보안 컨텍스트
    pod_sc = spec.get("securityContext", {})
    if not pod_sc.get("runAsNonRoot"):
        result.add("HIGH", resource_name, "PodMissingRunAsNonRoot",
                   "Pod 레벨에 runAsNonRoot 설정이 없습니다",
                   "spec.securityContext.runAsNonRoot: true 추가")

    # automountServiceAccountToken
    if spec.get("automountServiceAccountToken", True):
        result.add("MEDIUM", resource_name, "ServiceAccountTokenMounted",
                   "서비스 어카운트 토큰이 자동 마운트됩니다",
                   "automountServiceAccountToken: false 설정 (API 미사용 시)")

    # hostPath 볼륨
    for vol in spec.get("volumes", []):
        if "hostPath" in vol:
            result.add("HIGH", resource_name, "HostPathVolume",
                       f"hostPath 볼륨 사용: {vol.get('hostPath', {}).get('path')}",
                       "hostPath 대신 PersistentVolumeClaim 사용")

    # hostPID, hostNetwork
    if spec.get("hostPID"):
        result.add("CRITICAL", resource_name, "HostPID",
                   "호스트 PID 네임스페이스 공유됨",
                   "hostPID: false 설정")
    if spec.get("hostNetwork"):
        result.add("HIGH", resource_name, "HostNetwork",
                   "호스트 네트워크 네임스페이스 공유됨",
                   "hostNetwork: false 설정")


def audit_manifest(doc: dict[str, Any], result: AuditResult) -> None:
    """K8s 리소스 매니페스트 감사"""
    kind = doc.get("kind", "")
    name = doc.get("metadata", {}).get("name", "unknown")
    namespace = doc.get("metadata", {}).get("namespace", "default")
    resource_name = f"{kind}/{namespace}/{name}"

    if kind in ("Pod",):
        audit_pod_spec(doc.get("spec", {}), resource_name, result)

    elif kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
        template = doc.get("spec", {}).get("template", {})
        if kind == "CronJob":
            template = doc.get("spec", {}).get("jobTemplate", {}).get(
                "spec", {}).get("template", {})
        audit_pod_spec(template.get("spec", {}), resource_name, result)

    elif kind == "ClusterRoleBinding":
        subjects = doc.get("subjects", [])
        for subj in subjects:
            if subj.get("name") == "system:unauthenticated":
                result.add("CRITICAL", resource_name, "UnauthenticatedBinding",
                           "비인증 사용자에게 ClusterRole 바인딩됨",
                           "즉시 ClusterRoleBinding 삭제")

    elif kind == "NetworkPolicy":
        # NetworkPolicy가 있는 것은 긍정 신호
        result.add("INFO", resource_name, "NetworkPolicyPresent",
                   "NetworkPolicy가 설정되어 있습니다", "")


def format_report(result: AuditResult, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            [vars(f) for f in result.findings],
            ensure_ascii=False, indent=2,
        )

    lines: list[str] = ["=" * 65, "Kubernetes 보안 감사 결과", "=" * 65]
    summary = result.summary
    total = sum(summary.values())
    lines.append(f"\n총 발견: {total}개")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if summary[sev]:
            lines.append(f"  {sev:8s}: {summary[sev]}개")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(result.findings,
                             key=lambda f: sev_order.get(f.severity, 5))

    lines.append("\n[발견 사항 상세]")
    lines.append("-" * 65)
    for f in sorted_findings:
        lines.append(f"\n[{f.severity}] {f.check}")
        lines.append(f"  리소스: {f.resource}")
        lines.append(f"  설명  : {f.message}")
        if f.remediation:
            lines.append(f"  조치  : {f.remediation}")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes 보안 설정 자동 감사기 — YAML 매니페스트 분석",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="감사할 YAML 파일 또는 디렉터리",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="최소 심각도 필터",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="결과 저장 파일",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM"],
        help="이 심각도 이상 발견 시 exit code 1 반환 (CI 통합용)",
    )
    return parser.parse_args()


def collect_yaml_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(path.rglob("*.yaml"))
            files.extend(path.rglob("*.yml"))
        elif path.is_file():
            files.append(path)
    return files


def main() -> None:
    args = parse_args()
    result = AuditResult()

    yaml_files = collect_yaml_files(args.paths)
    if not yaml_files:
        print("[경고] YAML 파일을 찾을 수 없습니다.", file=sys.stderr)
        sys.exit(0)

    for yaml_file in yaml_files:
        try:
            docs = list(yaml.safe_load_all(yaml_file.read_text(encoding="utf-8")))
            for doc in docs:
                if isinstance(doc, dict):
                    audit_manifest(doc, result)
        except yaml.YAMLError as e:
            print(f"[경고] YAML 파싱 실패 ({yaml_file}): {e}", file=sys.stderr)
        except Exception as e:
            print(f"[경고] 파일 처리 오류 ({yaml_file}): {e}", file=sys.stderr)

    # 심각도 필터 적용
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_rank = sev_order[args.min_severity]
    result.findings = [
        f for f in result.findings
        if sev_order.get(f.severity, 4) <= min_rank
    ]

    report = format_report(result, args.format)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"[완료] 결과 저장: {args.output}")
    else:
        print(report)

    # CI 실패 조건
    if args.fail_on:
        fail_rank = sev_order[args.fail_on]
        has_fail = any(
            sev_order.get(f.severity, 4) <= fail_rank
            for f in result.findings
        )
        if has_fail:
            sys.exit(1)


if __name__ == "__main__":
    main()
```

**사용 예시:**

```bash
# 단일 파일 감사
python k8s_security_auditor.py deployment.yaml

# 디렉터리 전체 감사 (HIGH 이상만)
python k8s_security_auditor.py ./k8s-manifests/ --min-severity HIGH

# CI/CD: CRITICAL 발견 시 파이프라인 실패
python k8s_security_auditor.py ./manifests/ --fail-on CRITICAL --format json -o audit.json
```

---

## 8. Cloud Native 보안 성숙도 모델

### 8.1 CNCF 클라우드 네이티브 보안 성숙도 모델

```
레벨 1 — 기초 (Baseline)
  □ 기본 RBAC 설정
  □ 이미지 취약점 스캔 (수동)
  □ 네트워크 정책 없음
  □ 시크릿을 K8s Secret으로 관리

레벨 2 — 중급 (Intermediate)
  □ OPA/Kyverno 어드미션 정책
  □ CI/CD에 이미지 스캔 통합
  □ 네트워크 정책으로 트래픽 제한
  □ Falco 런타임 모니터링
  □ 감사 로그 SIEM 수집

레벨 3 — 고급 (Advanced)
  □ 이미지 서명 및 검증 (Cosign)
  □ SBOM 생성 및 관리
  □ Vault 동적 시크릿
  □ eBPF 기반 런타임 집행 (Tetragon)
  □ GitOps + IaC 보안 스캔

레벨 4 — 최적화 (Optimized)
  □ SLSA 레벨 3+ 달성
  □ 제로 트러스트 서비스 메시 (mTLS 전체)
  □ 자동화된 취약점 대응
  □ 카오스 엔지니어링으로 보안 검증
  □ 지속적 컴플라이언스 자동화
```

### 8.2 DevSecOps 파이프라인 통합

```
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  코드   │  │  빌드    │  │  배포    │  │  운영    │
│  단계   │  │  단계    │  │  단계    │  │  단계    │
├─────────┤  ├──────────┤  ├──────────┤  ├──────────┤
│ SAST    │→ │이미지 빌드│→ │ OPA 검증 │→ │ Falco    │
│ SCA     │  │취약점 스캔│  │ 서명 검증│  │ CSPM     │
│ IaC 스캔│  │SBOM 생성 │  │ 정책 집행│  │ 감사 로그│
│ 시크릿  │  │이미지 서명│  │ GitOps  │  │ 인시던트 │
│ 탐지    │  │          │  │         │  │ 대응     │
└─────────┘  └──────────┘  └──────────┘  └──────────┘
   Checkov     Trivy/Grype   Kyverno      Tetragon
   Semgrep     Cosign/Syft   ArgoCD       Prometheus
```

---

## 참고 자료

- **CNCF Cloud Native Security Whitepaper** — 공식 보안 가이드
- **CIS Kubernetes Benchmark** — [https://www.cisecurity.org](https://www.cisecurity.org)
- **NSA/CISA K8s Hardening Guide** — NSA 공식 K8s 보안 지침
- **Falco Rules Library** — [https://github.com/falcosecurity/rules](https://github.com/falcosecurity/rules)
- **SLSA Framework** — [https://slsa.dev](https://slsa.dev)

---

<a name="english"></a>

# 05 — Cloud Native Security Defense Framework

## 1. Cloud Native Security Framework

### 1.1 4C Security Model

The CNCF-defined layered security model:

```
Code        → SAST/DAST, dependency scanning, static analysis
Container   → Image scanning, runtime protection, least privilege
Cluster     → RBAC, network policies, audit logs, OPA
Cloud       → IAM, infrastructure config audit, data encryption
```

### 1.2 CNCF Security Technology Radar

| Layer | Tools | Purpose |
|-------|-------|---------|
| Supply Chain | Cosign, Syft, Grype | Image signing, SBOM, vulnerabilities |
| Runtime | Falco, Tetragon | Anomaly behavior detection |
| Network | Cilium, Calico | eBPF-based policy enforcement |
| Secrets | Vault, External Secrets | Dynamic credential management |
| Posture Management | Trivy, kube-bench | Config audit, CIS compliance |
| Policy | OPA Gatekeeper, Kyverno | Admission control |

---

## 2. Runtime Security (Falco / eBPF)

### 2.1 Falco Rule Writing

Custom Falco rules for cloud-native environments include:
- **Shell in Container**: Detects shell execution in containers not in trusted image list — WARNING priority, tags [container, shell, mitre_execution]
- **Read Sensitive File Untrusted**: Detects untrusted processes accessing sensitive files — ERROR priority, tags [filesystem, mitre_credential_access]
- **Network Tool in Container**: Detects network reconnaissance tools (nmap, nc, tcpdump, curl, wget) — NOTICE priority, tags [network, container, mitre_discovery]

### 2.2 Tetragon (eBPF Runtime Enforcement)

Cilium Tetragon can enforce policies at the kernel level using eBPF. TracingPolicy example: terminates processes that attempt to read /etc/shadow using `action: Sigkill` on the `fd_install` kprobe.

---

## 3. Secret Management and Encryption

### HashiCorp Vault Dynamic Secrets

Static secrets in .env files risk permanent access on leak. Vault dynamic secrets:
- App authenticates to Vault with a token → Vault issues temporary DB credentials
- TTL auto-expiry → automatic revocation
- Audit log records all issuance

Kubernetes authentication setup: enable kubernetes auth method, configure cluster CA cert, create roles binding service accounts to Vault policies with 1h TTL.

### External Secrets Operator

Synchronizes Kubernetes Secrets with external secret stores (Vault, AWS SM, GCP SM). Configures `ExternalSecret` resources with `refreshInterval`, `secretStoreRef`, and field mappings.

### Sealed Secrets

Allows encrypting secrets with a public key and safely committing `SealedSecret` YAMLs to Git. Only the controller with the private key can decrypt them.

---

## 4. Supply Chain Security (SLSA / Sigstore)

### SLSA Framework Levels

- Level 0: No guarantees
- Level 1: Documented build process, provenance generated
- Level 2: Version control + signed provenance
- Level 3: Isolated build environment, verifiable provenance
- Level 4: Two-person review, hermetic build

### Cosign Image Signing and Verification

```bash
# Sign image (keyless — OIDC-based)
cosign sign --identity-token=$(gcloud auth print-identity-token) gcr.io/myproject/myapp:v1.0.0

# Verify signature
cosign verify --certificate-identity=ci@myproject.iam.gserviceaccount.com gcr.io/myproject/myapp:v1.0.0
```

Kyverno policy `verify-image-signature` enforces that only signed images from approved identities can be deployed.

### SBOM (Software Bill of Materials)

Generate SBOMs with Syft, scan for vulnerabilities with Grype, and attest SBOMs to images with Cosign for complete supply chain transparency.

---

## 5. Cloud Security Posture Management (CSPM)

| Tool | Key Features | Target |
|------|-------------|--------|
| Trivy | All-in-one (image+IaC+SBOM+secret) | General purpose |
| kube-bench | CIS Kubernetes Benchmark | K8s cluster |
| Checkov | IaC static analysis (Terraform, K8s YAML) | DevSecOps |
| Prowler | AWS/Azure/GCP config audit | Cloud |
| ScoutSuite | Multi-cloud audit | Cloud |

---

## 6. Kubernetes Audit and Compliance

Audit policy configuration: Metadata level for secrets/configmaps and network policy access; RequestResponse level for pod exec/attach/portforward and ClusterRole binding changes.

OPA Gatekeeper `K8sNoRoot` constraint template rejects containers where `securityContext.runAsNonRoot != true`, applied to production and staging namespaces.

---

## 7. Python Tool: K8s Security Configuration Auditor

Automatically audits Kubernetes manifest YAML files for security misconfigurations. Checks include:

**Container-level**: root user (UID 0), missing `runAsNonRoot`, privileged containers, dangerous Linux capabilities, missing `drop: [ALL]`, `allowPrivilegeEscalation: true`, writable root filesystem, missing CPU/memory limits, `latest` image tags

**Pod-level**: missing pod-level `runAsNonRoot`, auto-mounted service account tokens, `hostPath` volumes, `hostPID`, `hostNetwork`

**Resource-level**: `ClusterRoleBinding` to `system:unauthenticated`

Supports text and JSON output formats, minimum severity filtering, and CI exit code 1 on configurable severity threshold.

---

## 8. Cloud Native Security Maturity Model

### CNCF Cloud Native Security Maturity Levels

```
Level 1 — Baseline:    Basic RBAC, manual image scanning, K8s Secrets
Level 2 — Intermediate: OPA/Kyverno admission policies, CI image scanning, Falco runtime monitoring, audit logs to SIEM
Level 3 — Advanced:    Image signing (Cosign), SBOM management, Vault dynamic secrets, Tetragon eBPF enforcement, GitOps + IaC security scanning
Level 4 — Optimized:   SLSA Level 3+, zero-trust service mesh (mTLS everywhere), automated vulnerability response, chaos engineering security validation, continuous compliance automation
```

### DevSecOps Pipeline Integration

```
Code → Build → Deploy → Operate
SAST   Image Build  OPA Validation  Falco
SCA    Vuln Scan    Signature Check CSPM
IaC    SBOM         Policy Enforce  Audit Logs
Secret Image Sign   GitOps          Incident Response
```

---

## References

- **CNCF Cloud Native Security Whitepaper** — Official security guide
- **CIS Kubernetes Benchmark** — https://www.cisecurity.org
- **NSA/CISA K8s Hardening Guide** — Official K8s security guidelines
- **Falco Rules Library** — https://github.com/falcosecurity/rules
- **SLSA Framework** — https://slsa.dev
