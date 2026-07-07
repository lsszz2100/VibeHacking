> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Kubernetes RBAC 감사 — 권한 분석·과도한 권한 탐지·정책 강화

## 0. 초보자를 위한 개념 이해

### Kubernetes RBAC이란?

RBAC(Role-Based Access Control)은 Kubernetes에서 "누가 어떤 리소스에 어떤 작업을 할 수 있는가"를 제어하는 권한 관리 시스템이다. RBAC이 잘못 설정되면 일반 사용자나 침해된 Pod가 시크릿을 읽거나, 다른 Pod를 삭제하거나, 심지어 클러스터 관리자 권한을 얻을 수 있다.

**왜 배우는가:**
```
RBAC 잘못된 설정의 결과

과도한 ClusterRole:
  verb: ["*"], resource: ["*"]  → 클러스터 전체 관리자 수준
  → 침해된 Pod가 시크릿 전부 읽고 다른 Pod 삭제 가능

ServiceAccount 토큰 탈취:
  Pod 내 토큰 → API 서버 요청 → 권한에 따라 무제한 접근

권한 상승 체인:
  create pod 권한 → hostPID Pod 생성 → 노드 프로세스 접근
  bind ClusterRole 권한 → 자신에게 cluster-admin 부여
```

### 핵심 개념 정리

```
RBAC 구성 요소

Role          — 특정 네임스페이스 내 권한 묶음
ClusterRole   — 클러스터 전체 범위 권한 묶음
RoleBinding   — Role을 사용자/그룹/SA에 연결
ClusterRoleBinding — ClusterRole을 전체 범위로 연결

ServiceAccount — Pod의 신원 (토큰이 자동 마운트)

위험 패턴:
  wildcards(*): verb/resource 전부 허용
  get secrets: 모든 시크릿 읽기
  bind: 다른 권한 부여 가능 → 권한 상승
  impersonate: 다른 사용자로 위장
```

### 필요한 도구 및 환경
- **kubectl**: RBAC 조회 및 관리
- **rbac-lookup**: RBAC 관계 시각화 (`krew install rbac-lookup`)
- **audit2rbac**: 감사 로그로 최소 권한 RBAC 자동 생성
- **rakkess**: 권한 행렬 시각화

### 기초 실습 예제
```bash
# 1. 현재 서비스 계정 권한 확인
kubectl auth can-i --list -n default
kubectl auth can-i --list -n kube-system

# 2. ClusterRoleBinding 목록 — 강력한 권한 확인
kubectl get clusterrolebinding -o wide | grep -E "cluster-admin|system:masters"

# 3. 와일드카드 권한이 있는 Role 찾기
kubectl get clusterrole -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    for rule in item.get('rules', []):
        if '*' in rule.get('verbs', []) or '*' in rule.get('resources', []):
            print(f'[위험] ClusterRole {name}: 와일드카드 권한')
            break
"

# 4. 모든 ServiceAccount의 시크릿 읽기 권한 확인
kubectl get rolebinding,clusterrolebinding -A -o json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    kind = item['kind']
    name = item['metadata']['name']
    print(f'{kind}: {name}')
"
```

---

## 1. Kubernetes RBAC 취약점 구조

```
K8s RBAC 공격 경로
    │
    ├── 과도한 ClusterRole 권한
    │     wildcards (*), create/delete pods
    │     get secrets (모든 네임스페이스)
    │
    ├── ServiceAccount 토큰 탈취
    │     Pod 내 /var/run/secrets/kubernetes.io/serviceaccount/token
    │     → API 서버 직접 접근
    │
    ├── 권한 상승 체인
    │     create pod → hostPID/hostNetwork → 노드 탈출
    │     bind ClusterRole → 자신에게 권한 부여
    │
    └── 잘못된 네임스페이스 격리
          cross-namespace secret 접근
          default SA 과도한 권한
```

---

## 2. RBAC 권한 감사 CLI

```python
#!/usr/bin/env python3
"""Kubernetes RBAC 감사 — 과도한 권한·위험 설정 탐지."""

import argparse
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


DANGEROUS_VERBS = {"*", "create", "delete", "patch", "update", "bind", "escalate", "impersonate"}
DANGEROUS_RESOURCES = {
    "*", "secrets", "pods", "deployments", "clusterroles",
    "clusterrolebindings", "roles", "rolebindings",
    "nodes", "persistentvolumes", "serviceaccounts",
}
DANGEROUS_API_GROUPS = {"*"}


@dataclass
class RBACFinding:
    kind: str          # ClusterRole / Role
    name: str
    namespace: str
    subject: str       # 연결된 주체 (SA/User/Group)
    reason: str
    severity: str      # CRITICAL / HIGH / MEDIUM


def kubectl(args: list[str]) -> dict | list | None:
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def get_all_cluster_roles() -> list[dict]:
    data = kubectl(["get", "clusterroles"])
    return data.get("items", []) if data else []


def get_all_role_bindings() -> list[dict]:
    data = kubectl(["get", "rolebindings", "--all-namespaces"])
    return data.get("items", []) if data else []


def get_all_cluster_role_bindings() -> list[dict]:
    data = kubectl(["get", "clusterrolebindings"])
    return data.get("items", []) if data else []


def analyze_role_rules(rules: list[dict]) -> list[str]:
    """RBAC 규칙에서 위험 권한 탐지."""
    issues = []
    for rule in rules:
        verbs = set(rule.get("verbs", []))
        resources = set(rule.get("resources", []))
        api_groups = set(rule.get("apiGroups", []))

        dangerous_verb_match = verbs & DANGEROUS_VERBS
        dangerous_resource_match = resources & DANGEROUS_RESOURCES

        if "*" in verbs and "*" in resources:
            issues.append("전체 와일드카드 권한 (verbs=* resources=*) — 관리자 수준")
        elif "*" in verbs:
            issues.append(f"와일드카드 동사 허용: resources={list(resources)[:3]}")
        elif dangerous_verb_match and dangerous_resource_match:
            issues.append(
                f"위험 권한: {list(dangerous_verb_match)} on {list(dangerous_resource_match)[:3]}"
            )

        if "secrets" in resources and ("get" in verbs or "list" in verbs or "*" in verbs):
            issues.append("secrets 읽기 권한")

        if "bind" in verbs or "escalate" in verbs:
            issues.append("권한 상승(bind/escalate) 허용 — 권한 탈취 가능")

        if "impersonate" in verbs:
            issues.append("impersonate 권한 — 다른 사용자 사칭 가능")

    return issues


def audit_rbac() -> list[RBACFinding]:
    findings: list[RBACFinding] = []

    # ClusterRole 분석
    cluster_roles = get_all_cluster_roles()
    role_issues: dict[str, list[str]] = {}

    for role in cluster_roles:
        name = role["metadata"]["name"]
        if name.startswith("system:"):
            continue  # 시스템 역할 제외
        rules = role.get("rules", [])
        issues = analyze_role_rules(rules)
        if issues:
            role_issues[name] = issues

    # ClusterRoleBinding과 연결
    crbs = get_all_cluster_role_bindings()
    for crb in crbs:
        role_ref = crb.get("roleRef", {})
        role_name = role_ref.get("name", "")
        subjects = crb.get("subjects", [])

        if role_name in role_issues:
            for subject in subjects:
                subj_str = f"{subject.get('kind')}/{subject.get('name')}"
                for issue in role_issues[role_name]:
                    severity = "CRITICAL" if "와일드카드" in issue or "secrets" in issue else "HIGH"
                    findings.append(RBACFinding(
                        kind="ClusterRole",
                        name=role_name,
                        namespace="cluster-wide",
                        subject=subj_str,
                        reason=issue,
                        severity=severity,
                    ))

    # default ServiceAccount 권한 확인
    for crb in crbs:
        subjects = crb.get("subjects", [])
        for subj in subjects:
            if subj.get("kind") == "ServiceAccount" and subj.get("name") == "default":
                role_name = crb.get("roleRef", {}).get("name", "")
                findings.append(RBACFinding(
                    kind="ClusterRoleBinding",
                    name=crb["metadata"]["name"],
                    namespace=subj.get("namespace", ""),
                    subject="ServiceAccount/default",
                    reason=f"default SA에 {role_name} 역할 연결 — 최소 권한 위반",
                    severity="HIGH",
                ))

    return findings


def check_pod_security(namespace: str = "default") -> list[dict]:
    """Pod의 위험 보안 설정 탐지."""
    data = kubectl(["get", "pods", "-n", namespace])
    issues = []

    if not data:
        return issues

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        spec = pod.get("spec", {})

        # hostPID/hostNetwork/hostIPC
        for flag in ["hostPID", "hostNetwork", "hostIPC"]:
            if spec.get(flag):
                issues.append({
                    "pod": pod_name,
                    "issue": f"{flag}=true — 노드 탈출 위험",
                    "severity": "CRITICAL",
                })

        # privileged 컨테이너
        for container in spec.get("containers", []):
            sec_ctx = container.get("securityContext", {})
            if sec_ctx.get("privileged"):
                issues.append({
                    "pod": pod_name,
                    "container": container["name"],
                    "issue": "privileged=true — 컨테이너 탈출 가능",
                    "severity": "CRITICAL",
                })
            if sec_ctx.get("allowPrivilegeEscalation", True):
                issues.append({
                    "pod": pod_name,
                    "container": container["name"],
                    "issue": "allowPrivilegeEscalation 미비활성화",
                    "severity": "MEDIUM",
                })

    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes RBAC 감사")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rbac_p = sub.add_parser("rbac", help="RBAC 권한 감사")
    rbac_p.add_argument("-o", "--output", type=Path)

    pod_p = sub.add_parser("pods", help="Pod 보안 설정 감사")
    pod_p.add_argument("-n", "--namespace", default="default")

    all_p = sub.add_parser("all", help="전체 감사")
    all_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "rbac":
            findings = audit_rbac()
            critical = [f for f in findings if f.severity == "CRITICAL"]
            print(f"RBAC 위험 발견: {len(findings)}개 (CRITICAL: {len(critical)})")
            for f in sorted(findings, key=lambda x: x.severity):
                print(f"\n  [{f.severity}] {f.kind}/{f.name}")
                print(f"  주체: {f.subject} | 네임스페이스: {f.namespace}")
                print(f"  이유: {f.reason}")
            if args.output:
                args.output.write_text(json.dumps([vars(f) for f in findings], indent=2, ensure_ascii=False))

        case "pods":
            issues = check_pod_security(args.namespace)
            for issue in issues:
                print(f"[{issue['severity']}] {issue['pod']}: {issue['issue']}")

        case "all":
            rbac_findings = audit_rbac()
            pod_issues = check_pod_security()
            result = {
                "rbac_findings": [vars(f) for f in rbac_findings],
                "pod_issues": pod_issues,
            }
            print(f"RBAC 발견: {len(rbac_findings)}개, Pod 이슈: {len(pod_issues)}개")
            if args.output:
                args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 3. 네트워크 정책 감사

```python
#!/usr/bin/env python3
"""Kubernetes NetworkPolicy 감사 — 과도한 트래픽 허용 탐지."""

import argparse
import json
import subprocess
from pathlib import Path


def get_network_policies(namespace: str = "--all-namespaces") -> list[dict]:
    try:
        cmd = ["kubectl", "get", "networkpolicies", "-o", "json"]
        if namespace == "--all-namespaces":
            cmd.append("--all-namespaces")
        else:
            cmd += ["-n", namespace]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return json.loads(result.stdout).get("items", [])
    except Exception:
        return []


def audit_network_policies(policies: list[dict]) -> list[dict]:
    findings = []

    # 네임스페이스별 정책 확인
    namespaces_with_policy: set[str] = set()
    for policy in policies:
        ns = policy["metadata"]["namespace"]
        namespaces_with_policy.add(ns)

        spec = policy.get("spec", {})
        ingress = spec.get("ingress", [])
        egress = spec.get("egress", [])

        # 빈 ingress/egress 규칙 = 모든 트래픽 허용
        for rule_set, direction in [(ingress, "ingress"), (egress, "egress")]:
            for rule in rule_set:
                if rule == {}:  # 빈 규칙 = 전체 허용
                    findings.append({
                        "namespace": ns,
                        "policy": policy["metadata"]["name"],
                        "issue": f"{direction} 전체 허용 규칙 존재",
                        "severity": "HIGH",
                    })

    return findings


def find_unprotected_namespaces() -> list[str]:
    """NetworkPolicy가 없는 네임스페이스 탐지."""
    try:
        ns_result = subprocess.run(
            ["kubectl", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True, timeout=10,
        )
        all_ns = ns_result.stdout.split()

        np_result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "--all-namespaces",
             "-o", "jsonpath={.items[*].metadata.namespace}"],
            capture_output=True, text=True, timeout=10,
        )
        protected_ns = set(np_result.stdout.split())
        system_ns = {"kube-system", "kube-public", "kube-node-lease"}

        return [ns for ns in all_ns if ns not in protected_ns and ns not in system_ns]
    except Exception:
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="K8s NetworkPolicy 감사")
    parser.add_argument("-n", "--namespace", default="--all-namespaces")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    policies = get_network_policies(args.namespace)
    findings = audit_network_policies(policies)
    unprotected = find_unprotected_namespaces()

    print(f"[*] NetworkPolicy {len(policies)}개 분석")
    print(f"[!] 보호되지 않은 네임스페이스 {len(unprotected)}개: {unprotected}")

    for f in findings:
        print(f"  [{f['severity']}] {f['namespace']}/{f['policy']}: {f['issue']}")

    if args.output:
        args.output.write_text(json.dumps(
            {"findings": findings, "unprotected_namespaces": unprotected},
            indent=2, ensure_ascii=False,
        ))


if __name__ == "__main__":
    main()
```

---

## 4. RBAC 보안 강화 권고사항

| 위험 설정 | 강화 방법 | 도구 |
|-----------|-----------|------|
| 와일드카드 권한 | 최소 권한 원칙 적용 | rbac-audit, rakkess |
| default SA 권한 | automountServiceAccountToken: false | OPA Gatekeeper |
| privileged Pod | PodSecurityAdmission 적용 | PSA (Baseline/Restricted) |
| 미암호화 etcd | etcd TLS + 데이터 암호화 | K8s encryption at rest |
| 네임스페이스 격리 없음 | NetworkPolicy 강제 | Calico, Cilium |
| 익명 API 접근 | --anonymous-auth=false | kube-apiserver 설정 |

---

## 3.5 OPA/Gatekeeper Admission Control 정책 검증

RBAC(1~3절)가 "누가 어떤 리소스에 접근 가능한가"를 통제한다면, OPA(Open Policy Agent) Gatekeeper는 그보다 한 단계 앞서 **리소스가 클러스터에 생성되는 시점에 정책 위반을 아예 막는** Admission Controller다. "privileged 컨테이너 금지", "특정 레지스트리 이미지만 허용" 같은 조직 정책을 Rego 언어로 작성해 강제한다.

```yaml
# ConstraintTemplate — privileged 컨테이너 생성을 막는 정책 템플릿
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivileged
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged == true
          msg := sprintf("privileged container %v is not allowed", [c.name])
        }
---
# Constraint — 위 템플릿을 실제로 적용
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPrivileged
metadata:
  name: deny-privileged-containers
spec:
  enforcementAction: deny  # dryrun으로 먼저 검증 후 deny로 전환 권장
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```python
#!/usr/bin/env python3
"""Gatekeeper 위반(constraint violation) 이벤트를 조회해 정책이 실제로 작동 중인지 확인."""
import json
import subprocess


def check_gatekeeper_violations() -> None:
    result = subprocess.run(
        ["kubectl", "get", "constraints", "-o", "json"],
        capture_output=True, text=True,
    )
    constraints = json.loads(result.stdout).get("items", [])

    for c in constraints:
        name = c["metadata"]["name"]
        status = c.get("status", {})
        violations = status.get("violations", [])
        enforcement = c["spec"].get("enforcementAction", "deny")
        print(f"[{name}] enforcementAction={enforcement}, 위반 {len(violations)}건")
        for v in violations[:5]:
            print(f"    - {v.get('message')}")


if __name__ == "__main__":
    check_gatekeeper_violations()
```

**핵심**: 새 정책은 처음부터 `enforcementAction: deny`로 배포하지 말고, 반드시 `dryrun`으로 먼저 얼마나 많은 기존 리소스가 위반하는지 확인한 뒤(레거시 워크로드 대량 차단 방지) 단계적으로 `warn` → `deny`로 전환한다. RBAC은 "누가"를, Gatekeeper는 "무엇이 배포될 수 있는가"를 통제하므로 두 계층을 함께 감사해야 privileged 컨테이너·호스트 네트워크 사용 같은 RBAC만으로는 못 막는 위험을 커버할 수 있다.

---

<!-- detect-validate-29 -->
## Kubernetes RBAC 감사 작동 검증과 회귀

RBAC 감사는 *돌렸다*가 아니라 *과도한 권한을 실제로 잡고 정책이 강제되는가*로 가치가 갈린다. 방어자는 **감사가 와일드카드·escalation 경로를 빠짐없이 잡는가**를 검증해야 한다. 검증은 **소유 클러스터**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| cluster-admin 남발 | 과권한 바인딩을 잡나? | admin 주체 수 | 그룹 경유 누락 |
| 와일드카드 권한 | verbs/resources `*`를 잡나? | 와일드카드 룰 수 | 네임스페이스 한정 착시 |
| escalation 경로 | bind/escalate/impersonate를 잡나? | 위험 verb 보유 | 간접 경로 무시 |
| 서비스어카운트 | 기본 SA 과권한인가? | SA 토큰 권한 | 자동 마운트 방치 |

### 방어 검증 (직접 확인)

```bash
# 1) 위험 권한(와일드카드·escalation) 보유 롤 점검(소유 클러스터)
kubectl get clusterroles -o json 2>/dev/null | jq -r '.items[] | select(.rules[]? | (.verbs[]?=="*") or (.verbs[]?=="impersonate") or (.verbs[]?=="escalate")) | .metadata.name' | sort -u | head
# 2) 특정 주체가 실제로 무엇을 할 수 있는지 재현 — 과권한 검증
kubectl auth can-i --list --as=system:serviceaccount:default:default 2>/dev/null | head
```

> RBAC 감사 검증은 *돌렸는가*가 아니라 *과권한·escalation을 잡는가*다 — "RBAC 정의했다"와 "와일드카드·impersonate 권한이 빠짐없이 잡히고 SA 과권한이 재현된다"는 다르다. 소유 클러스터에서 위험 verb·실효 권한을 직접 확인한다([[70_Kubernetes_Security]], [[18_DevSecOps]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# Kubernetes RBAC Audit — Permission Analysis, Excessive Privilege Detection, Policy Hardening

## 1. Kubernetes RBAC Vulnerability Structure

```
K8s RBAC Attack Paths
    │
    ├── Excessive ClusterRole Permissions
    │     wildcards (*), create/delete pods
    │     get secrets (all namespaces)
    │
    ├── ServiceAccount Token Theft
    │     /var/run/secrets/kubernetes.io/serviceaccount/token inside Pod
    │     → Direct API server access
    │
    ├── Privilege Escalation Chain
    │     create pod → hostPID/hostNetwork → node escape
    │     bind ClusterRole → grant permissions to self
    │
    └── Improper Namespace Isolation
          cross-namespace secret access
          default SA with excessive permissions
```

---

## 2. RBAC Permission Audit CLI

```python
#!/usr/bin/env python3
"""Kubernetes RBAC audit — detecting excessive permissions and dangerous configurations."""

import argparse
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


DANGEROUS_VERBS = {"*", "create", "delete", "patch", "update", "bind", "escalate", "impersonate"}
DANGEROUS_RESOURCES = {
    "*", "secrets", "pods", "deployments", "clusterroles",
    "clusterrolebindings", "roles", "rolebindings",
    "nodes", "persistentvolumes", "serviceaccounts",
}
DANGEROUS_API_GROUPS = {"*"}


@dataclass
class RBACFinding:
    kind: str          # ClusterRole / Role
    name: str
    namespace: str
    subject: str       # Bound subject (SA/User/Group)
    reason: str
    severity: str      # CRITICAL / HIGH / MEDIUM


def kubectl(args: list[str]) -> dict | list | None:
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def get_all_cluster_roles() -> list[dict]:
    data = kubectl(["get", "clusterroles"])
    return data.get("items", []) if data else []


def get_all_role_bindings() -> list[dict]:
    data = kubectl(["get", "rolebindings", "--all-namespaces"])
    return data.get("items", []) if data else []


def get_all_cluster_role_bindings() -> list[dict]:
    data = kubectl(["get", "clusterrolebindings"])
    return data.get("items", []) if data else []


def analyze_role_rules(rules: list[dict]) -> list[str]:
    """Detect dangerous permissions in RBAC rules."""
    issues = []
    for rule in rules:
        verbs = set(rule.get("verbs", []))
        resources = set(rule.get("resources", []))
        api_groups = set(rule.get("apiGroups", []))

        dangerous_verb_match = verbs & DANGEROUS_VERBS
        dangerous_resource_match = resources & DANGEROUS_RESOURCES

        if "*" in verbs and "*" in resources:
            issues.append("Full wildcard permission (verbs=* resources=*) — administrator level")
        elif "*" in verbs:
            issues.append(f"Wildcard verb allowed: resources={list(resources)[:3]}")
        elif dangerous_verb_match and dangerous_resource_match:
            issues.append(
                f"Dangerous permission: {list(dangerous_verb_match)} on {list(dangerous_resource_match)[:3]}"
            )

        if "secrets" in resources and ("get" in verbs or "list" in verbs or "*" in verbs):
            issues.append("secrets read permission")

        if "bind" in verbs or "escalate" in verbs:
            issues.append("Privilege escalation (bind/escalate) allowed — permission hijacking possible")

        if "impersonate" in verbs:
            issues.append("impersonate permission — can impersonate other users")

    return issues


def audit_rbac() -> list[RBACFinding]:
    findings: list[RBACFinding] = []

    # Analyze ClusterRoles
    cluster_roles = get_all_cluster_roles()
    role_issues: dict[str, list[str]] = {}

    for role in cluster_roles:
        name = role["metadata"]["name"]
        if name.startswith("system:"):
            continue  # Exclude system roles
        rules = role.get("rules", [])
        issues = analyze_role_rules(rules)
        if issues:
            role_issues[name] = issues

    # Link with ClusterRoleBindings
    crbs = get_all_cluster_role_bindings()
    for crb in crbs:
        role_ref = crb.get("roleRef", {})
        role_name = role_ref.get("name", "")
        subjects = crb.get("subjects", [])

        if role_name in role_issues:
            for subject in subjects:
                subj_str = f"{subject.get('kind')}/{subject.get('name')}"
                for issue in role_issues[role_name]:
                    severity = "CRITICAL" if "wildcard" in issue.lower() or "secrets" in issue else "HIGH"
                    findings.append(RBACFinding(
                        kind="ClusterRole",
                        name=role_name,
                        namespace="cluster-wide",
                        subject=subj_str,
                        reason=issue,
                        severity=severity,
                    ))

    # Check default ServiceAccount permissions
    for crb in crbs:
        subjects = crb.get("subjects", [])
        for subj in subjects:
            if subj.get("kind") == "ServiceAccount" and subj.get("name") == "default":
                role_name = crb.get("roleRef", {}).get("name", "")
                findings.append(RBACFinding(
                    kind="ClusterRoleBinding",
                    name=crb["metadata"]["name"],
                    namespace=subj.get("namespace", ""),
                    subject="ServiceAccount/default",
                    reason=f"default SA bound to {role_name} role — least privilege violation",
                    severity="HIGH",
                ))

    return findings


def check_pod_security(namespace: str = "default") -> list[dict]:
    """Detect dangerous security configurations in Pods."""
    data = kubectl(["get", "pods", "-n", namespace])
    issues = []

    if not data:
        return issues

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        spec = pod.get("spec", {})

        # hostPID/hostNetwork/hostIPC
        for flag in ["hostPID", "hostNetwork", "hostIPC"]:
            if spec.get(flag):
                issues.append({
                    "pod": pod_name,
                    "issue": f"{flag}=true — node escape risk",
                    "severity": "CRITICAL",
                })

        # Privileged containers
        for container in spec.get("containers", []):
            sec_ctx = container.get("securityContext", {})
            if sec_ctx.get("privileged"):
                issues.append({
                    "pod": pod_name,
                    "container": container["name"],
                    "issue": "privileged=true — container escape possible",
                    "severity": "CRITICAL",
                })
            if sec_ctx.get("allowPrivilegeEscalation", True):
                issues.append({
                    "pod": pod_name,
                    "container": container["name"],
                    "issue": "allowPrivilegeEscalation not disabled",
                    "severity": "MEDIUM",
                })

    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Audit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rbac_p = sub.add_parser("rbac", help="RBAC permission audit")
    rbac_p.add_argument("-o", "--output", type=Path)

    pod_p = sub.add_parser("pods", help="Pod security configuration audit")
    pod_p.add_argument("-n", "--namespace", default="default")

    all_p = sub.add_parser("all", help="Full audit")
    all_p.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()

    match args.cmd:
        case "rbac":
            findings = audit_rbac()
            critical = [f for f in findings if f.severity == "CRITICAL"]
            print(f"RBAC risks found: {len(findings)} (CRITICAL: {len(critical)})")
            for f in sorted(findings, key=lambda x: x.severity):
                print(f"\n  [{f.severity}] {f.kind}/{f.name}")
                print(f"  Subject: {f.subject} | Namespace: {f.namespace}")
                print(f"  Reason: {f.reason}")
            if args.output:
                args.output.write_text(json.dumps([vars(f) for f in findings], indent=2, ensure_ascii=False))

        case "pods":
            issues = check_pod_security(args.namespace)
            for issue in issues:
                print(f"[{issue['severity']}] {issue['pod']}: {issue['issue']}")

        case "all":
            rbac_findings = audit_rbac()
            pod_issues = check_pod_security()
            result = {
                "rbac_findings": [vars(f) for f in rbac_findings],
                "pod_issues": pod_issues,
            }
            print(f"RBAC findings: {len(rbac_findings)}, Pod issues: {len(pod_issues)}")
            if args.output:
                args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 3. Network Policy Audit

```python
#!/usr/bin/env python3
"""Kubernetes NetworkPolicy audit — detecting overly permissive traffic rules."""

import argparse
import json
import subprocess
from pathlib import Path


def get_network_policies(namespace: str = "--all-namespaces") -> list[dict]:
    try:
        cmd = ["kubectl", "get", "networkpolicies", "-o", "json"]
        if namespace == "--all-namespaces":
            cmd.append("--all-namespaces")
        else:
            cmd += ["-n", namespace]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return json.loads(result.stdout).get("items", [])
    except Exception:
        return []


def audit_network_policies(policies: list[dict]) -> list[dict]:
    findings = []

    # Check policies per namespace
    namespaces_with_policy: set[str] = set()
    for policy in policies:
        ns = policy["metadata"]["namespace"]
        namespaces_with_policy.add(ns)

        spec = policy.get("spec", {})
        ingress = spec.get("ingress", [])
        egress = spec.get("egress", [])

        # Empty ingress/egress rules = allow all traffic
        for rule_set, direction in [(ingress, "ingress"), (egress, "egress")]:
            for rule in rule_set:
                if rule == {}:  # Empty rule = allow all
                    findings.append({
                        "namespace": ns,
                        "policy": policy["metadata"]["name"],
                        "issue": f"{direction} allow-all rule exists",
                        "severity": "HIGH",
                    })

    return findings


def find_unprotected_namespaces() -> list[str]:
    """Detect namespaces without NetworkPolicy."""
    try:
        ns_result = subprocess.run(
            ["kubectl", "get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True, timeout=10,
        )
        all_ns = ns_result.stdout.split()

        np_result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "--all-namespaces",
             "-o", "jsonpath={.items[*].metadata.namespace}"],
            capture_output=True, text=True, timeout=10,
        )
        protected_ns = set(np_result.stdout.split())
        system_ns = {"kube-system", "kube-public", "kube-node-lease"}

        return [ns for ns in all_ns if ns not in protected_ns and ns not in system_ns]
    except Exception:
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="K8s NetworkPolicy Audit")
    parser.add_argument("-n", "--namespace", default="--all-namespaces")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    policies = get_network_policies(args.namespace)
    findings = audit_network_policies(policies)
    unprotected = find_unprotected_namespaces()

    print(f"[*] Analyzed {len(policies)} NetworkPolicies")
    print(f"[!] {len(unprotected)} unprotected namespaces: {unprotected}")

    for f in findings:
        print(f"  [{f['severity']}] {f['namespace']}/{f['policy']}: {f['issue']}")

    if args.output:
        args.output.write_text(json.dumps(
            {"findings": findings, "unprotected_namespaces": unprotected},
            indent=2, ensure_ascii=False,
        ))


if __name__ == "__main__":
    main()
```

---

## 4. RBAC Security Hardening Recommendations

| Dangerous Configuration | Hardening Method | Tool |
|------------------------|-----------------|------|
| Wildcard permissions | Apply principle of least privilege | rbac-audit, rakkess |
| default SA permissions | automountServiceAccountToken: false | OPA Gatekeeper |
| Privileged Pod | Apply PodSecurityAdmission | PSA (Baseline/Restricted) |
| Unencrypted etcd | etcd TLS + data encryption | K8s encryption at rest |
| No namespace isolation | Enforce NetworkPolicy | Calico, Cilium |
| Anonymous API access | --anonymous-auth=false | kube-apiserver configuration |

---

## 3.5 OPA/Gatekeeper Admission Control Policy Verification

If RBAC (sections 1-3) controls "who can access which resources," OPA (Open Policy Agent) Gatekeeper works a step earlier as an Admission Controller that **blocks policy violations at the moment a resource is created in the cluster**. Organizational rules like "no privileged containers" or "only images from an approved registry" get written in the Rego language and enforced there.

```yaml
# ConstraintTemplate -- a policy template that blocks creation of privileged containers
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivileged
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged == true
          msg := sprintf("privileged container %v is not allowed", [c.name])
        }
---
# Constraint -- actually applies the template above
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPrivileged
metadata:
  name: deny-privileged-containers
spec:
  enforcementAction: deny  # recommended to validate with dryrun first, then switch to deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```python
#!/usr/bin/env python3
"""Query Gatekeeper constraint-violation events to confirm the policy is actually working."""
import json
import subprocess


def check_gatekeeper_violations() -> None:
    result = subprocess.run(
        ["kubectl", "get", "constraints", "-o", "json"],
        capture_output=True, text=True,
    )
    constraints = json.loads(result.stdout).get("items", [])

    for c in constraints:
        name = c["metadata"]["name"]
        status = c.get("status", {})
        violations = status.get("violations", [])
        enforcement = c["spec"].get("enforcementAction", "deny")
        print(f"[{name}] enforcementAction={enforcement}, {len(violations)} violation(s)")
        for v in violations[:5]:
            print(f"    - {v.get('message')}")


if __name__ == "__main__":
    check_gatekeeper_violations()
```

**Key point**: don't ship a new policy with `enforcementAction: deny` from day one — always validate first with `dryrun` to see how many existing resources would violate it (to avoid mass-blocking legacy workloads), then roll it forward in stages from `warn` to `deny`. RBAC governs "who," Gatekeeper governs "what can be deployed," so auditing both layers together is what covers risks — like privileged containers or host-network usage — that RBAC alone can't stop.

---

<!-- detect-validate-29 -->
## Kubernetes RBAC Audit Effectiveness Validation and Regression

RBAC auditing's value comes not from *whether it ran* but from *whether it actually catches excessive privilege and policy is enforced*. Defenders must verify **whether the audit catches every wildcard/escalation path**. Validate only on **owned clusters**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| cluster-admin sprawl | Does it catch over-privileged bindings? | admin subject count | Missing group-mediated grants |
| Wildcard permissions | Does it catch verbs/resources `*`? | Wildcard rule count | Namespace-scope illusion |
| Escalation paths | Does it catch bind/escalate/impersonate? | Dangerous verb holders | Ignoring indirect paths |
| Service accounts | Are default SAs over-privileged? | SA token permissions | Leaving auto-mount on |

### Defense validation (verify directly)

```bash
# 1) Check roles holding dangerous verbs (wildcard/escalation) (owned cluster)
kubectl get clusterroles -o json 2>/dev/null | jq -r '.items[] | select(.rules[]? | (.verbs[]?=="*") or (.verbs[]?=="impersonate") or (.verbs[]?=="escalate")) | .metadata.name' | sort -u | head
# 2) Reproduce what a subject can actually do — verify over-privilege
kubectl auth can-i --list --as=system:serviceaccount:default:default 2>/dev/null | head
```

> RBAC-audit validation is *whether it catches over-privilege and escalation*, not *whether it ran* -- "we defined RBAC" differs from "every wildcard/impersonate grant is caught and SA over-privilege reproduces". Confirm dangerous verbs and effective permissions on owned clusters directly ([[70_Kubernetes_Security]], [[18_DevSecOps]], [[13_SOC_Blue_Team]]).
