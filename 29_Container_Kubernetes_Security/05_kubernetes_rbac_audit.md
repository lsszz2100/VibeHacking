> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Kubernetes RBAC 감사 — 권한 분석·과도한 권한 탐지·정책 강화

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
