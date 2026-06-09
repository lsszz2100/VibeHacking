> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# 클라우드 네이티브 보안 CTF 랩

## 개요

이 랩은 클라우드 네이티브 환경에서 발생하는 보안 위협을 직접 탐지하고 대응하는 실전형 CTF(Capture The Flag) 실습입니다. eBPF 기반 런타임 탐지, OPA Gatekeeper 정책 적용, 취약한 Helm 차트 분석의 세 가지 시나리오를 통해 현대 클라우드 환경의 공격 벡터와 방어 기법을 체득합니다.

**선수 지식**: Docker, Kubernetes 기초, Linux 커맨드라인  
**소요 시간**: 약 3~4시간  
**난이도**: 중급 (Intermediate)

---

## 실습 1: eBPF 기반 컨테이너 런타임 이상행위 탐지

### 목표

eBPF(extended Berkeley Packet Filter)를 활용하여 컨테이너 내부에서 발생하는 비정상적인 시스템 콜 패턴을 실시간으로 탐지합니다. 공격자가 컨테이너를 탈출하거나 권한을 상승시키려 할 때 나타나는 특징적인 syscall 시퀀스를 식별하는 것이 목표입니다.

### 배경 지식

eBPF는 리눅스 커널에서 동작하는 샌드박스 프로그램으로, 커널 코드를 수정하지 않고도 커널 이벤트를 관찰하고 필터링할 수 있습니다. Falco, Tetragon 같은 클라우드 네이티브 보안 도구는 eBPF를 사용하여 컨테이너 런타임 보안을 강화합니다.

컨테이너 탈출 시 자주 관찰되는 syscall 패턴:
- `ptrace` 호출 (다른 프로세스 제어)
- `mount` 시스템 콜 (호스트 파일시스템 마운트 시도)
- `setns` 호출 (네임스페이스 전환)
- `capset` 호출 (권한 상승 시도)

### 힌트

1. Falco의 기본 룰 파일(`/etc/falco/falco_rules.yaml`)에서 컨테이너 탈출 관련 룰을 확인하세요.
2. `bpftrace`로 특정 syscall을 추적할 때는 `tracepoint:syscalls:sys_enter_<syscall명>` 형식을 사용합니다.
3. 의심스러운 프로세스가 `/proc/self/cgroup`을 읽으면 컨테이너 환경인지 확인하려는 시도일 수 있습니다.
4. 플래그는 이상행위 탐지 룰을 올바르게 트리거했을 때 로그에서 발견됩니다.

### 실습 환경 구성

```bash
# Falco 설치 (Helm 사용)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --namespace falco \
  --create-namespace

# 실습용 취약 컨테이너 배포
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ctf-target-pod
  namespace: default
spec:
  containers:
  - name: target
    image: ubuntu:22.04
    command: ["/bin/bash", "-c", "sleep infinity"]
    securityContext:
      privileged: true
EOF
```

### 풀이

**Step 1: Falco 커스텀 룰 작성**

```yaml
# /etc/falco/custom_rules.yaml
- rule: CTF Container Escape Attempt
  desc: 컨테이너 탈출 시도 탐지
  condition: >
    spawned_process and container and
    (proc.name in (nsenter, unshare) or
     (proc.name = mount and not proc.args contains "proc") or
     syscall.type = setns)
  output: >
    CTF_FLAG{ebpf_runtime_detection_success} 컨테이너 탈출 시도 감지!
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [ctf, container_escape, runtime_security]

- rule: CTF Privilege Escalation via Capabilities
  desc: 컨테이너 내 권한 상승 탐지
  condition: >
    container and
    (syscall.type = capset or
     (proc.name = setuid and user.uid != 0))
  output: >
    권한 상승 시도 탐지 (user=%user.name proc=%proc.name caps=%proc.caps)
  priority: WARNING
  tags: [ctf, privilege_escalation]
```

**Step 2: bpftrace로 실시간 syscall 모니터링**

```python
#!/usr/bin/env python3
"""
eBPF 기반 컨테이너 런타임 이상행위 탐지 시뮬레이터
Python 3.10+ 필요
"""

import argparse
import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import NamedTuple

class SyscallEvent(NamedTuple):
    timestamp: str
    pid: int
    comm: str
    syscall: str
    container_id: str | None

SUSPICIOUS_SYSCALLS = {
    "ptrace": "프로세스 제어 시도",
    "mount": "파일시스템 마운트 시도",
    "setns": "네임스페이스 전환 시도",
    "capset": "권한 상승 시도",
    "unshare": "네임스페이스 분리 시도",
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="eBPF 기반 컨테이너 런타임 이상행위 탐지기"
    )
    parser.add_argument(
        "--namespace", "-n",
        default="default",
        help="모니터링할 Kubernetes 네임스페이스 (기본값: default)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "text"],
        default="text",
        help="출력 형식 (기본값: text)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=3,
        help="알림 임계값: 동일 syscall 반복 횟수 (기본값: 3)"
    )
    return parser.parse_args()

def get_container_cgroup(pid: int) -> str | None:
    """프로세스의 cgroup에서 컨테이너 ID 추출"""
    cgroup_path = Path(f"/proc/{pid}/cgroup")
    if not cgroup_path.exists():
        return None
    content = cgroup_path.read_text()
    for line in content.splitlines():
        if "docker" in line or "containerd" in line:
            parts = line.split("/")
            if len(parts) > 1:
                return parts[-1][:12]
    return None

def analyze_syscall_log(log_line: str) -> SyscallEvent | None:
    """Falco JSON 로그 파싱"""
    try:
        data = json.loads(log_line)
        output = data.get("output", "")
        priority = data.get("priority", "")
        if priority not in ("CRITICAL", "WARNING", "ERROR"):
            return None
        return SyscallEvent(
            timestamp=data.get("time", datetime.now().isoformat()),
            pid=data.get("output_fields", {}).get("proc.pid", 0),
            comm=data.get("output_fields", {}).get("proc.name", "unknown"),
            syscall=data.get("rule", "unknown"),
            container_id=data.get("output_fields", {}).get("container.id"),
        )
    except (json.JSONDecodeError, KeyError):
        return None

def monitor_falco_logs(args: argparse.Namespace) -> None:
    """Falco 로그 실시간 모니터링"""
    print(f"[*] Falco 로그 모니터링 시작 (네임스페이스: {args.namespace})")
    print(f"[*] 알림 임계값: {args.threshold}회")
    print("-" * 60)

    syscall_counter: dict[str, int] = {}

    cmd = [
        "kubectl", "logs", "-f",
        "-n", "falco",
        "-l", "app.kubernetes.io/name=falco",
        "--container", "falco"
    ]

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ) as proc:
            for line in proc.stdout:
                event = analyze_syscall_log(line.strip())
                if event is None:
                    continue

                syscall_counter[event.syscall] = (
                    syscall_counter.get(event.syscall, 0) + 1
                )

                if args.output == "json":
                    print(json.dumps(event._asdict(), ensure_ascii=False))
                else:
                    desc = SUSPICIOUS_SYSCALLS.get(event.syscall, "알 수 없는 이벤트")
                    print(
                        f"[{event.timestamp}] "
                        f"PID={event.pid} "
                        f"COMM={event.comm} "
                        f"EVENT={event.syscall} "
                        f"DESC={desc}"
                    )

                if syscall_counter[event.syscall] >= args.threshold:
                    print(f"\n[!] 경고: '{event.syscall}' 이벤트 {args.threshold}회 이상 감지!")
                    print(f"[!] 컨테이너 ID: {event.container_id or 'N/A'}")
                    print("[!] 즉시 조사 필요\n")

    except KeyboardInterrupt:
        print("\n[*] 모니터링 종료")
        print(f"[*] 탐지 요약: {syscall_counter}")

def main() -> None:
    args = parse_args()
    monitor_falco_logs(args)

if __name__ == "__main__":
    main()
```

**Step 3: 공격 시뮬레이션 및 플래그 획득**

```bash
# 취약 컨테이너에 접속
kubectl exec -it ctf-target-pod -- /bin/bash

# 컨테이너 내부에서 탈출 시도 (Falco가 탐지)
# 이 명령은 Falco 룰을 트리거합니다
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Falco 로그에서 플래그 확인
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "CTF_FLAG"
# 출력: CTF_FLAG{ebpf_runtime_detection_success}
```

**플래그**: `CTF_FLAG{ebpf_runtime_detection_success}`

---

## 실습 2: OPA Gatekeeper로 금지된 컨테이너 배포 차단

### 목표

Open Policy Agent(OPA) Gatekeeper를 사용하여 보안 정책을 위반하는 컨테이너 배포를 Kubernetes admission 단계에서 차단합니다. 특권(privileged) 컨테이너, root 실행 컨테이너, 금지된 이미지 레지스트리 사용을 탐지하고 플래그를 획득합니다.

### 배경 지식

OPA Gatekeeper는 Kubernetes의 Admission Webhook을 활용하여 클러스터에 배포되는 리소스가 정의된 정책을 준수하는지 실시간으로 검증합니다. Rego 언어로 정책을 작성하며, ConstraintTemplate과 Constraint 두 가지 리소스로 구성됩니다.

```
배포 요청 흐름:
사용자 kubectl apply → API Server → Admission Webhook → OPA Gatekeeper
                                                           ↓
                                                    정책 검증 (Rego)
                                                    ↓           ↓
                                                  허용         거부
```

### 힌트

1. `kubectl get constrainttemplates` 명령으로 설치된 정책 템플릿을 확인하세요.
2. 정책 위반 메시지에는 힌트가 포함되어 있습니다. `kubectl describe` 출력을 주의 깊게 읽으세요.
3. Rego 정책에서 `deny` 블록의 조건을 역으로 분석하면 허용 조건을 파악할 수 있습니다.
4. 플래그는 특정 라벨이 붙은 Pod를 성공적으로 배포했을 때 ConfigMap에 저장됩니다.

### 실습 환경 구성

```bash
# OPA Gatekeeper 설치
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# CTF 정책 템플릿 배포
kubectl apply -f - <<EOF
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: ctfcontainersecurity
spec:
  crd:
    spec:
      names:
        kind: CTFContainerSecurity
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedRegistries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package ctfcontainersecurity

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := "VIOLATION: 특권 컨테이너 금지. 힌트: securityContext.privileged=false 설정 필요"
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.runAsNonRoot
          msg := "VIOLATION: root 실행 금지. runAsNonRoot: true 설정 필요"
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          allowed := input.parameters.allowedRegistries
          not any_prefix_match(image, allowed)
          msg := sprintf("VIOLATION: 허가되지 않은 레지스트리. 허용 목록: %v", [allowed])
        }

        any_prefix_match(str, prefixes) {
          prefix := prefixes[_]
          startswith(str, prefix)
        }
EOF
```

### 풀이

**Step 1: 현재 정책 분석**

```python
#!/usr/bin/env python3
"""
OPA Gatekeeper 정책 분석 및 준수 Pod 생성기
"""

import argparse
import subprocess
import json
import sys
import yaml
from typing import Any

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OPA Gatekeeper 정책 분석 및 준수 매니페스트 생성기"
    )
    parser.add_argument(
        "--analyze", "-a",
        action="store_true",
        help="현재 Gatekeeper 정책 분석"
    )
    parser.add_argument(
        "--generate", "-g",
        action="store_true",
        help="정책 준수 Pod 매니페스트 생성"
    )
    parser.add_argument(
        "--namespace", "-n",
        default="ctf-lab",
        help="대상 네임스페이스 (기본값: ctf-lab)"
    )
    parser.add_argument(
        "--image",
        default="gcr.io/distroless/static:nonroot",
        help="컨테이너 이미지"
    )
    return parser.parse_args()

def get_constraint_templates() -> list[dict[str, Any]]:
    """설치된 ConstraintTemplate 목록 조회"""
    result = subprocess.run(
        ["kubectl", "get", "constrainttemplates", "-o", "json"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[!] 오류: {result.stderr}", file=sys.stderr)
        return []
    data = json.loads(result.stdout)
    return data.get("items", [])

def analyze_rego_policy(rego_code: str) -> list[str]:
    """Rego 정책에서 위반 조건 추출"""
    violations = []
    lines = rego_code.splitlines()
    in_violation = False
    current_violation: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("violation"):
            in_violation = True
            current_violation = []
        elif in_violation:
            if stripped == "}":
                violations.append("\n".join(current_violation))
                in_violation = False
                current_violation = []
            else:
                current_violation.append(stripped)
    return violations

def generate_compliant_manifest(namespace: str, image: str) -> dict[str, Any]:
    """OPA 정책을 준수하는 Pod 매니페스트 생성"""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "ctf-compliant-pod",
            "namespace": namespace,
            "labels": {
                "ctf": "flag-hunter",
                "security": "compliant"
            }
        },
        "spec": {
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"}
            },
            "containers": [{
                "name": "compliant-container",
                "image": image,
                "command": ["/bin/sh", "-c", "echo CTF_FLAG{opa_policy_bypass_success}"],
                "securityContext": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "runAsNonRoot": True,
                    "capabilities": {"drop": ["ALL"]}
                },
                "resources": {
                    "limits": {"memory": "64Mi", "cpu": "100m"},
                    "requests": {"memory": "32Mi", "cpu": "50m"}
                }
            }]
        }
    }

def main() -> None:
    args = parse_args()

    if args.analyze:
        print("[*] OPA Gatekeeper 정책 분석 중...")
        templates = get_constraint_templates()
        for tmpl in templates:
            name = tmpl["metadata"]["name"]
            print(f"\n[+] ConstraintTemplate: {name}")
            targets = tmpl.get("spec", {}).get("targets", [])
            for target in targets:
                rego = target.get("rego", "")
                violations = analyze_rego_policy(rego)
                print(f"    위반 조건 수: {len(violations)}")
                for i, v in enumerate(violations, 1):
                    print(f"    [{i}] {v[:100]}...")

    if args.generate:
        manifest = generate_compliant_manifest(args.namespace, args.image)
        print("[*] 정책 준수 Pod 매니페스트:")
        print(yaml.dump(manifest, default_flow_style=False, allow_unicode=True))

        with open("/tmp/compliant_pod.yaml", "w") as f:
            yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True)
        print("[+] /tmp/compliant_pod.yaml 저장 완료")

if __name__ == "__main__":
    main()
```

**Step 2: 정책 준수 Pod 배포 및 플래그 획득**

```bash
# 정책 분석
python3 gatekeeper_analyzer.py --analyze

# 준수 매니페스트 생성
python3 gatekeeper_analyzer.py --generate --namespace ctf-lab

# Pod 배포
kubectl create namespace ctf-lab
kubectl apply -f /tmp/compliant_pod.yaml

# 로그에서 플래그 확인
kubectl logs ctf-compliant-pod -n ctf-lab
# 출력: CTF_FLAG{opa_policy_bypass_success}
```

**플래그**: `CTF_FLAG{opa_policy_bypass_success}`

---

## 실습 3: 취약한 Helm 차트 분석 → 보안 설정 수정

### 목표

보안 취약점이 포함된 Helm 차트를 분석하고, 취약한 설정을 식별한 뒤 안전한 버전으로 수정합니다. 수정된 차트를 배포하면 숨겨진 플래그를 획득할 수 있습니다.

### 배경 지식

Helm 차트의 일반적인 보안 취약점:
- `hostNetwork: true` (호스트 네트워크 노출)
- `hostPID: true` (호스트 PID 네임스페이스 공유)
- `privileged: true` (특권 컨테이너)
- RBAC 과도한 권한 부여 (`ClusterAdmin` 남용)
- 시크릿 하드코딩 (values.yaml에 패스워드 평문 저장)
- `imagePullPolicy: Always` 누락으로 인한 이미지 무결성 검증 불가

### 힌트

1. `helm lint` 명령은 구문 오류는 찾지만 보안 취약점은 탐지하지 못합니다. `checkov` 또는 `trivy` 사용을 검토하세요.
2. `values.yaml`에서 `password`, `secret`, `key` 키워드를 검색하세요.
3. RBAC Role의 `verbs: ["*"]`와 `resources: ["*"]`는 과도한 권한입니다.
4. 플래그는 7개 이상의 취약점을 수정하고 차트를 성공적으로 배포했을 때 획득합니다.

### 취약한 Helm 차트 구조

```
ctf-vulnerable-chart/
├── Chart.yaml
├── values.yaml          ← 하드코딩된 시크릿
├── templates/
│   ├── deployment.yaml  ← 특권 컨테이너, hostNetwork
│   ├── rbac.yaml        ← 과도한 RBAC 권한
│   ├── service.yaml
│   └── secret.yaml      ← Base64로만 인코딩된 시크릿
└── .helmignore
```

### 풀이

**Step 1: 취약한 차트 분석 스크립트**

```python
#!/usr/bin/env python3
"""
Helm 차트 보안 취약점 스캐너
"""

import argparse
import sys
from pathlib import Path
import yaml
import re

VULNERABILITY_RULES: list[dict] = [
    {
        "id": "HELM-001",
        "name": "특권 컨테이너",
        "pattern": r"privileged:\s*true",
        "severity": "CRITICAL",
        "fix": "securityContext.privileged: false",
    },
    {
        "id": "HELM-002",
        "name": "호스트 네트워크 사용",
        "pattern": r"hostNetwork:\s*true",
        "severity": "HIGH",
        "fix": "hostNetwork: false",
    },
    {
        "id": "HELM-003",
        "name": "호스트 PID 네임스페이스",
        "pattern": r"hostPID:\s*true",
        "severity": "HIGH",
        "fix": "hostPID: false",
    },
    {
        "id": "HELM-004",
        "name": "루트로 실행",
        "pattern": r"runAsUser:\s*0",
        "severity": "HIGH",
        "fix": "runAsUser: 1000 이상의 값 사용",
    },
    {
        "id": "HELM-005",
        "name": "하드코딩된 시크릿",
        "pattern": r"(password|secret|apikey|token):\s*['\"]?[a-zA-Z0-9+/]{8,}",
        "severity": "CRITICAL",
        "fix": "Kubernetes Secret 또는 Vault 사용",
    },
    {
        "id": "HELM-006",
        "name": "과도한 RBAC 권한",
        "pattern": r'verbs:\s*\[.*"\*".*\]',
        "severity": "HIGH",
        "fix": "최소 권한 원칙 적용",
    },
    {
        "id": "HELM-007",
        "name": "읽기 전용 루트 파일시스템 미설정",
        "pattern": r"readOnlyRootFilesystem:\s*false",
        "severity": "MEDIUM",
        "fix": "readOnlyRootFilesystem: true",
    },
]

class HelmChartScanner:
    def __init__(self, chart_path: Path) -> None:
        self.chart_path = chart_path
        self.findings: list[dict] = []

    def scan_file(self, file_path: Path) -> None:
        content = file_path.read_text()
        for rule in VULNERABILITY_RULES:
            matches = re.findall(rule["pattern"], content, re.IGNORECASE)
            if matches:
                self.findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": str(file_path.relative_to(self.chart_path)),
                    "fix": rule["fix"],
                    "match_count": len(matches),
                })

    def scan_chart(self) -> list[dict]:
        yaml_files = list(self.chart_path.rglob("*.yaml")) + \
                     list(self.chart_path.rglob("*.yml"))
        for f in yaml_files:
            self.scan_file(f)
        return self.findings

    def report(self) -> None:
        if not self.findings:
            print("[+] 취약점 없음")
            return

        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high = [f for f in self.findings if f["severity"] == "HIGH"]
        medium = [f for f in self.findings if f["severity"] == "MEDIUM"]

        print(f"\n[!] 취약점 발견: CRITICAL={len(critical)}, HIGH={len(high)}, MEDIUM={len(medium)}")
        print("=" * 60)
        for finding in self.findings:
            print(f"[{finding['severity']}] {finding['rule_id']}: {finding['name']}")
            print(f"  파일: {finding['file']}")
            print(f"  수정 방법: {finding['fix']}")
            print()

        vuln_count = len(self.findings)
        if vuln_count >= 7:
            print(f"[*] {vuln_count}개 취약점을 모두 수정하면 플래그를 획득할 수 있습니다.")
        else:
            print(f"[*] 현재 {vuln_count}개 취약점 발견. 7개 이상 수정 필요.")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Helm 차트 보안 취약점 스캐너"
    )
    parser.add_argument(
        "chart_path",
        help="스캔할 Helm 차트 디렉토리 경로"
    )
    parser.add_argument(
        "--fix", "-f",
        action="store_true",
        help="자동 수정 시도"
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    chart_path = Path(args.chart_path)
    if not chart_path.is_dir():
        print(f"[!] 오류: {chart_path} 디렉토리가 없습니다.", file=sys.stderr)
        sys.exit(1)

    scanner = HelmChartScanner(chart_path)
    scanner.scan_chart()
    scanner.report()

    if len(scanner.findings) >= 7:
        print("\n[+] 충분한 취약점이 발견되었습니다. 수정 후 배포하면 플래그를 획득합니다.")
        print("    helm upgrade --install ctf-app ./ctf-fixed-chart")
        print("    kubectl logs -l app=ctf-app | grep CTF_FLAG")

if __name__ == "__main__":
    main()
```

**Step 2: 수정 및 플래그 획득**

```bash
# 차트 스캔
python3 helm_scanner.py ./ctf-vulnerable-chart

# 7개 취약점 수정 후 배포
helm upgrade --install ctf-app ./ctf-fixed-chart \
  --set securityContext.privileged=false \
  --set securityContext.runAsNonRoot=true \
  --set securityContext.readOnlyRootFilesystem=true

# 플래그 확인
kubectl logs -l app=ctf-app | grep CTF_FLAG
# 출력: CTF_FLAG{helm_chart_security_hardening_complete}
```

**플래그**: `CTF_FLAG{helm_chart_security_hardening_complete}`

---

## 정리 및 핵심 요약

| 실습 | 기술 | 플래그 |
|------|------|--------|
| 실습 1 | eBPF/Falco 런타임 탐지 | `CTF_FLAG{ebpf_runtime_detection_success}` |
| 실습 2 | OPA Gatekeeper 정책 | `CTF_FLAG{opa_policy_bypass_success}` |
| 실습 3 | Helm 차트 보안 강화 | `CTF_FLAG{helm_chart_security_hardening_complete}` |

**참고 자료**
- [Falco 공식 문서](https://falco.org/docs/)
- [OPA Gatekeeper GitHub](https://github.com/open-policy-agent/gatekeeper)

---

<a name="english"></a>
# Cloud Native Security CTF Lab

## Overview

This lab provides hands-on CTF (Capture The Flag) exercises for detecting and responding to security threats in cloud-native environments. Through three scenarios—eBPF-based runtime detection, OPA Gatekeeper policy enforcement, and vulnerable Helm chart analysis—you will master attack vectors and defensive techniques in modern cloud environments.

**Prerequisites**: Docker, Kubernetes basics, Linux command line  
**Estimated Time**: 3–4 hours  
**Difficulty**: Intermediate

---

## Lab 1: eBPF-Based Container Runtime Anomaly Detection

### Objective

Use eBPF (extended Berkeley Packet Filter) to detect abnormal system call patterns occurring inside containers in real time. The goal is to identify characteristic syscall sequences that appear when attackers attempt container escapes or privilege escalation.

### Background

eBPF is a sandbox program running in the Linux kernel that can observe and filter kernel events without modifying kernel code. Cloud-native security tools like Falco and Tetragon use eBPF to strengthen container runtime security.

Common syscall patterns observed during container escapes:
- `ptrace` calls (controlling other processes)
- `mount` syscalls (attempting to mount host filesystem)
- `setns` calls (namespace switching)
- `capset` calls (privilege escalation attempts)

### Hints

1. Check the Falco default rules file (`/etc/falco/falco_rules.yaml`) for container escape-related rules.
2. When tracing specific syscalls with `bpftrace`, use the `tracepoint:syscalls:sys_enter_<syscall_name>` format.
3. If a suspicious process reads `/proc/self/cgroup`, it may be attempting to detect whether it is inside a container.
4. The flag appears in logs when the anomaly detection rule is correctly triggered.

### Solution

**Step 1: Write Falco Custom Rules**

```yaml
# /etc/falco/custom_rules.yaml
- rule: CTF Container Escape Attempt
  desc: Detect container escape attempts
  condition: >
    spawned_process and container and
    (proc.name in (nsenter, unshare) or
     (proc.name = mount and not proc.args contains "proc") or
     syscall.type = setns)
  output: >
    CTF_FLAG{ebpf_runtime_detection_success} Container escape detected!
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [ctf, container_escape, runtime_security]
```

**Step 2: Trigger Detection and Capture Flag**

```bash
# Enter vulnerable container
kubectl exec -it ctf-target-pod -- /bin/bash

# Trigger Falco rule with escape attempt
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Retrieve flag from Falco logs
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "CTF_FLAG"
# Output: CTF_FLAG{ebpf_runtime_detection_success}
```

**Flag**: `CTF_FLAG{ebpf_runtime_detection_success}`

---

## Lab 2: Blocking Forbidden Container Deployments with OPA Gatekeeper

### Objective

Use Open Policy Agent (OPA) Gatekeeper to block container deployments that violate security policies at the Kubernetes admission stage. Detect privileged containers, root-running containers, and forbidden image registries, then capture the flag.

### Hints

1. Use `kubectl get constrainttemplates` to see installed policy templates.
2. Policy violation messages contain hints—read `kubectl describe` output carefully.
3. Analyze the `deny` block conditions in Rego policies in reverse to determine what is allowed.
4. The flag is stored in a ConfigMap when a Pod with a specific label is successfully deployed.

### Solution

Deploy a policy-compliant Pod that satisfies all Gatekeeper constraints:
- `securityContext.privileged: false`
- `securityContext.runAsNonRoot: true`
- `securityContext.readOnlyRootFilesystem: true`
- Image from an allowed registry (e.g., `gcr.io/distroless/`)

```bash
kubectl apply -f compliant_pod.yaml
kubectl logs ctf-compliant-pod -n ctf-lab
# Output: CTF_FLAG{opa_policy_bypass_success}
```

**Flag**: `CTF_FLAG{opa_policy_bypass_success}`

---

## Lab 3: Analyze Vulnerable Helm Chart → Fix Security Settings

### Objective

Analyze a Helm chart containing security vulnerabilities, identify the vulnerable settings, then fix them and deploy the corrected version to capture the hidden flag.

### Common Helm Chart Security Issues

- `hostNetwork: true` (host network exposure)
- `hostPID: true` (host PID namespace sharing)
- `privileged: true` (privileged containers)
- Excessive RBAC permissions (`ClusterAdmin` abuse)
- Hardcoded secrets (plaintext passwords in `values.yaml`)
- Missing `readOnlyRootFilesystem: true`

### Hints

1. `helm lint` finds syntax errors but not security vulnerabilities. Consider using `checkov` or `trivy`.
2. Search `values.yaml` for `password`, `secret`, and `key` keywords.
3. `verbs: ["*"]` and `resources: ["*"]` in RBAC Roles are excessive permissions.
4. The flag is obtained when 7 or more vulnerabilities are fixed and the chart deploys successfully.

### Solution

```bash
# Scan the vulnerable chart
python3 helm_scanner.py ./ctf-vulnerable-chart

# After fixing 7+ vulnerabilities, deploy
helm upgrade --install ctf-app ./ctf-fixed-chart \
  --set securityContext.privileged=false \
  --set securityContext.runAsNonRoot=true

# Capture the flag
kubectl logs -l app=ctf-app | grep CTF_FLAG
# Output: CTF_FLAG{helm_chart_security_hardening_complete}
```

**Flag**: `CTF_FLAG{helm_chart_security_hardening_complete}`

---

## Summary

| Lab | Technique | Flag |
|-----|-----------|------|
| Lab 1 | eBPF/Falco Runtime Detection | `CTF_FLAG{ebpf_runtime_detection_success}` |
| Lab 2 | OPA Gatekeeper Policy | `CTF_FLAG{opa_policy_bypass_success}` |
| Lab 3 | Helm Chart Security Hardening | `CTF_FLAG{helm_chart_security_hardening_complete}` |

**References**
- [Falco Official Documentation](https://falco.org/docs/)
- [OPA Gatekeeper GitHub](https://github.com/open-policy-agent/gatekeeper)
