> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 쿠버네티스 보안 강화

## 보안 강화란?

공격 표면을 줄이고, 공격자가 침입하더라도 피해를 최소화하는 작업입니다. 집에 비유하면 자물쇠 교체(인증 강화), 방마다 잠금 장치(네임스페이스 격리), CCTV 설치(감사 로그), 방화(데이터 암호화) 등과 같습니다.

---

## 1. CIS Kubernetes Benchmark

**CIS(Center for Internet Security) K8s Benchmark**는 쿠버네티스 보안 설정의 산업 표준입니다. 약 200개 이상의 항목을 체크하며, 크게 다음 영역으로 구분됩니다.

### 주요 CIS 항목

| 카테고리 | 핵심 항목 | 위험도 |
|---------|---------|-------|
| API Server | `--anonymous-auth=false` | HIGH |
| API Server | `--authorization-mode=Node,RBAC` | HIGH |
| API Server | `--audit-log-path` 설정 | MEDIUM |
| etcd | `--cert-file`, `--key-file` (TLS) | HIGH |
| kubelet | `--anonymous-auth=false` | HIGH |
| kubelet | `--authorization-mode=Webhook` | HIGH |
| 네트워크 | Network Policy 적용 | MEDIUM |
| 파드 | `runAsNonRoot: true` | MEDIUM |

### kube-bench로 자동 점검

```bash
# Docker로 kube-bench 실행 (minikube 환경)
docker run --rm \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run:/var/run:ro \
  -v /usr/bin:/usr/bin:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  --net=host \
  --pid=host \
  aquasec/kube-bench:latest \
  --benchmark cis-1.8

# 또는 쿠버네티스 Job으로 실행
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job.batch/kube-bench
kubectl delete job kube-bench
```

---

## 2. Pod Security Standards (PSS)

PSS는 파드 실행 시 보안 수준을 강제하는 쿠버네티스 내장 기능입니다(v1.25+에서 안정화). 세 가지 수준이 있습니다.

```
Privileged (제한 없음)
    ↓
Baseline (기본 위험 방지)
    ↓
Restricted (강력한 제한, 프로덕션 권장)
```

### PSS 적용 방법

```bash
# 네임스페이스에 Restricted 정책 적용
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# 확인
kubectl get namespace production --show-labels
```

### Restricted 정책에서 허용되지 않는 것들

```yaml
# 이 설정들은 restricted 네임스페이스에서 파드 생성 실패
spec:
  hostPID: true              # 금지
  hostNetwork: true          # 금지
  containers:
  - securityContext:
      privileged: true       # 금지
      runAsUser: 0           # 금지 (root)
      allowPrivilegeEscalation: true  # 금지
```

```yaml
# restricted 네임스페이스에서 파드 생성 성공 예시
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

---

## 3. OPA Gatekeeper — 커스텀 정책 엔진

OPA(Open Policy Agent) Gatekeeper는 쿠버네티스에 커스텀 정책을 강제하는 Admission Controller입니다. "이미지 태그로 `latest` 금지", "특정 레지스트리만 허용" 같은 정책을 선언적으로 정의합니다.

### Gatekeeper 설치

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Gatekeeper 파드 상태 확인
kubectl get pods -n gatekeeper-system
```

### 정책 예시 1: latest 태그 금지

```yaml
# ConstraintTemplate 정의
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sbanlatestimage
spec:
  crd:
    spec:
      names:
        kind: K8sBanLatestImage
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sbanlatestimage
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        endswith(container.image, ":latest")
        msg := sprintf("'latest' 태그 이미지 금지: %v", [container.image])
      }
---
# 정책 적용
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBanLatestImage
metadata:
  name: ban-latest-image
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

### 정책 예시 2: 승인된 레지스트리만 허용

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        openAPIV3Schema:
          type: object
          properties:
            repos:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sallowedrepos
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        satisfied := [allowed |
          repo := input.parameters.repos[_]
          allowed := startswith(container.image, repo)
        ]
        not any(satisfied)
        msg := sprintf("허용되지 않은 레지스트리: %v", [container.image])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: allowed-repos
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    repos:
    - "gcr.io/my-company/"
    - "registry.internal.com/"
```

---

## 4. 시크릿 관리 — Vault 연동

쿠버네티스 내장 Secret은 Base64 인코딩(암호화 아님!)에 etcd에 평문 저장됩니다. HashiCorp Vault를 사용하면 암호화된 동적 시크릿 관리가 가능합니다.

### K8s 내장 Secret의 문제점

```bash
# Secret 생성
kubectl create secret generic db-creds \
  --from-literal=password=supersecret123

# Base64 디코딩으로 바로 노출됨
kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d
# 출력: supersecret123
```

### etcd 저장 시 암호화 설정 (At-Rest Encryption)

```yaml
# /etc/kubernetes/enc/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>  # openssl rand -base64 32
  - identity: {}  # 암호화 안 된 기존 데이터 읽기용
```

```bash
# API Server 시작 옵션에 추가
# --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml

# 기존 시크릿 재암호화
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

---

## 5. 실습: kube-bench 실행해서 취약점 확인

### 5.1 minikube에서 kube-bench 실행

```bash
# minikube가 실행 중인지 확인
minikube status

# kube-bench Job 실행
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
spec:
  template:
    spec:
      hostPID: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      restartPolicy: Never
      volumes:
      - name: var-lib-etcd
        hostPath:
          path: /var/lib/etcd
      - name: var-lib-kubelet
        hostPath:
          path: /var/lib/kubelet
      - name: var-lib-kube-scheduler
        hostPath:
          path: /var/lib/kube-scheduler
      - name: var-lib-kube-controller-manager
        hostPath:
          path: /var/lib/kube-controller-manager
      - name: etc-systemd
        hostPath:
          path: /etc/systemd
      - name: lib-systemd
        hostPath:
          path: /lib/systemd
      - name: srv-kubernetes
        hostPath:
          path: /srv/kubernetes
      - name: etc-kubernetes
        hostPath:
          path: /etc/kubernetes
      - name: usr-bin
        hostPath:
          path: /usr/bin
      - name: etc-cni-netd
        hostPath:
          path: /etc/cni/net.d/
      - name: opt-cni-bin
        hostPath:
          path: /opt/cni/bin/
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:latest
        command: ["kube-bench"]
        volumeMounts:
        - name: var-lib-etcd
          mountPath: /var/lib/etcd
          readOnly: true
        - name: var-lib-kubelet
          mountPath: /var/lib/kubelet
          readOnly: true
        - name: etc-kubernetes
          mountPath: /etc/kubernetes
          readOnly: true
        - name: usr-bin
          mountPath: /usr/local/mount-from-host/bin
          readOnly: true
EOF

# 완료 대기 및 결과 확인
kubectl wait --for=condition=complete job/kube-bench --timeout=120s
kubectl logs job/kube-bench | head -100
```

### 5.2 결과 분석 Python 스크립트

```python
#!/usr/bin/env python3
"""
kube-bench 결과 파싱 및 우선순위 분류 도구
사용법:
  kubectl logs job/kube-bench | python3 kubebench_parser.py
  python3 kubebench_parser.py --file kube-bench-output.txt
  python3 kubebench_parser.py --only-fail
"""
import argparse
import sys
import re
from dataclasses import dataclass
from collections import Counter


@dataclass
class BenchFinding:
    check_id: str
    status: str   # PASS / FAIL / WARN / INFO
    description: str


def parse_kube_bench_output(text: str) -> list[BenchFinding]:
    findings = []
    # kube-bench 출력 패턴: [PASS] 1.1.1 API server ...
    pattern = re.compile(r"\[(PASS|FAIL|WARN|INFO)\]\s+(\d[\d.]*)\s+(.+)")
    for line in text.splitlines():
        m = pattern.search(line)
        if m:
            findings.append(BenchFinding(
                status=m.group(1),
                check_id=m.group(2),
                description=m.group(3).strip()
            ))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="kube-bench 결과 파싱 및 우선순위 분류 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  kubectl logs job/kube-bench | python3 kubebench_parser.py\n  python3 kubebench_parser.py --file output.txt --only-fail"
    )
    parser.add_argument(
        "--file", "-f", default=None,
        help="kube-bench 출력 파일 경로 (기본값: stdin)"
    )
    parser.add_argument(
        "--only-fail", action="store_true",
        help="FAIL 항목만 출력"
    )
    args = parser.parse_args()

    if args.file:
        try:
            text = open(args.file, encoding="utf-8").read()
        except OSError as e:
            print(f"[오류] 파일 읽기 실패: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        text = sys.stdin.read()
    if not text.strip():
        print("[오류] stdin에서 kube-bench 출력을 읽을 수 없습니다.")
        print("사용법: kubectl logs job/kube-bench | python3 kubebench_parser.py")
        sys.exit(1)

    findings = parse_kube_bench_output(text)
    if not findings:
        print("[경고] 파싱된 항목 없음. kube-bench 출력 형식을 확인하세요.")
        print("원본 출력 (처음 20줄):")
        for line in text.splitlines()[:20]:
            print(f"  {line}")
        sys.exit(1)

    counts = Counter(f.status for f in findings)

    if not args.only_fail:
        print("\n[*] kube-bench 결과 요약")
        print("=" * 60)
        print(f"  PASS : {counts.get('PASS', 0)}개")
        print(f"  FAIL : {counts.get('FAIL', 0)}개  ← 즉시 수정 필요")
        print(f"  WARN : {counts.get('WARN', 0)}개  ← 검토 필요")
        print(f"  INFO : {counts.get('INFO', 0)}개")
        print(f"  합계 : {len(findings)}개")

    # FAIL 항목 출력
    failed = [f for f in findings if f.status == "FAIL"]
    if failed:
        print(f"\n[!] FAIL 항목 ({len(failed)}개) — 즉시 조치 필요:")
        print("-" * 60)
        for f in failed:
            print(f"  [{f.check_id}] {f.description}")
    else:
        print("\n[+] FAIL 항목 없음!")

    # WARN 항목 (--only-fail 아닐 때만)
    if not args.only_fail:
        warned = [f for f in findings if f.status == "WARN"]
        if warned:
            print(f"\n[~] WARN 항목 ({len(warned)}개) — 검토 필요:")
            print("-" * 60)
            for f in warned[:10]:  # 처음 10개만
                print(f"  [{f.check_id}] {f.description}")
            if len(warned) > 10:
                print(f"  ... 외 {len(warned) - 10}개")

    print("\n" + "=" * 60)
    fail_rate = counts.get("FAIL", 0) / len(findings) * 100 if findings else 0
    print(f"[결과] 실패율: {fail_rate:.1f}%")
    if fail_rate > 30:
        print("[판정] 보안 수준: 위험 — 즉각적인 강화 필요")
    elif fail_rate > 10:
        print("[판정] 보안 수준: 주의 — 개선 필요")
    else:
        print("[판정] 보안 수준: 양호 — 지속적인 모니터링 유지")


if __name__ == "__main__":
    main()
```

### 5.3 결과 분석 실행

```bash
# kube-bench 결과 파싱
kubectl logs job/kube-bench | python3 kubebench_parser.py

# 정리
kubectl delete job kube-bench
```

---

## 6. 보안 강화 체크리스트

```bash
# 빠른 보안 점검 명령어 모음
echo "=== API Server 익명 인증 확인 ==="
kubectl get pod kube-apiserver-minikube -n kube-system -o yaml | grep anonymous

echo "=== RBAC 활성화 확인 ==="
kubectl get pod kube-apiserver-minikube -n kube-system -o yaml | grep authorization-mode

echo "=== 기본 SA에 과도한 권한 없는지 확인 ==="
kubectl auth can-i --list --as=system:serviceaccount:default:default

echo "=== Network Policy 적용 현황 ==="
kubectl get networkpolicies --all-namespaces

echo "=== PSS 라벨 확인 ==="
kubectl get namespaces --show-labels | grep pod-security
```

---

<a name="english"></a>

# Kubernetes Security Hardening

## 1. CIS Kubernetes Benchmark

The CIS K8s Benchmark is the industry standard for Kubernetes security configuration (~200+ checks).

```bash
# Run kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench
```

Key items:
- `--anonymous-auth=false` on API server and kubelet
- `--authorization-mode=Node,RBAC` on API server
- TLS for etcd (`--cert-file`, `--key-file`)
- Audit logging enabled

---

## 2. Pod Security Standards

PSS (stable since K8s v1.25) enforces security levels at the namespace level.

```bash
# Apply Restricted policy to a namespace
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Restricted prohibits: `hostPID`, `hostNetwork`, `privileged`, root user, privilege escalation.

---

## 3. OPA Gatekeeper

Policy engine for custom admission control. Examples:
- Ban `:latest` image tags
- Allow only trusted registries
- Require resource limits on all containers

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml
```

---

## 4. Secret Management

Kubernetes Secrets are only Base64-encoded, not encrypted. Use etcd encryption at rest or HashiCorp Vault for production.

```bash
# Demonstrate the risk
kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d
```

---

## 5. Lab: Run kube-bench and Analyze Results

```bash
# Run kube-bench as a Kubernetes Job
kubectl apply -f kube-bench-job.yaml
kubectl wait --for=condition=complete job/kube-bench --timeout=120s

# Parse results
kubectl logs job/kube-bench | python3 kubebench_parser.py
kubectl delete job kube-bench
```

---

## 6. Hardening Quick Checklist

| Area | Command to Verify |
|------|-------------------|
| API Server auth | `kubectl get pod kube-apiserver-* -n kube-system -o yaml \| grep anonymous` |
| RBAC active | `kubectl get pod kube-apiserver-* -n kube-system -o yaml \| grep authorization-mode` |
| Default SA perms | `kubectl auth can-i --list --as=system:serviceaccount:default:default` |
| Network Policies | `kubectl get networkpolicies --all-namespaces` |
| PSS labels | `kubectl get namespaces --show-labels \| grep pod-security` |
