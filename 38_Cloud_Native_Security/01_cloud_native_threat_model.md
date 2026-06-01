> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Cloud Native 보안 위협 모델

## 목차
1. Cloud Native 보안 개요
2. STRIDE 위협 모델 적용
3. MITRE ATT&CK for Containers
4. CNAPP(Cloud Native Application Protection Platform)
5. CSPM / CWPP / CIEM 비교
6. 컨테이너 위협 모델
7. Kubernetes 공격 매트릭스
8. Python: Kubernetes 보안 감사 자동화 도구

---

## 1. Cloud Native 보안 개요

Cloud Native 환경은 컨테이너, 마이크로서비스, 오케스트레이션(Kubernetes), 서버리스, CI/CD 파이프라인이
결합된 복잡한 생태계입니다. 전통적인 경계 보안(Perimeter Security) 모델은 이 환경에서 동작하지 않으며,
새로운 위협 모델과 대응 방법론이 필요합니다.

### Cloud Native 보안의 4C 계층

```
┌─────────────────────────────────┐
│           Code (코드)           │  ← 애플리케이션 취약점, SAST/DAST
├─────────────────────────────────┤
│       Container (컨테이너)      │  ← 이미지 취약점, 런타임 보안
├─────────────────────────────────┤
│        Cluster (클러스터)       │  ← Kubernetes RBAC, 네트워크 정책
├─────────────────────────────────┤
│          Cloud (클라우드)       │  ← IAM, 네트워크, 스토리지 보안
└─────────────────────────────────┘
```

각 계층은 하위 계층의 보안을 신뢰하므로, 하위 계층이 침해되면 상위 계층도 위험에 노출됩니다.

---

## 2. STRIDE 위협 모델 적용

STRIDE는 Microsoft에서 개발한 위협 모델링 방법론으로, Cloud Native 환경에 다음과 같이 적용됩니다.

### S - Spoofing (위장)
- **위협**: 악의적 컨테이너가 신뢰된 서비스로 위장
- **사례**: 서비스 어카운트 토큰 도용, mTLS 인증서 위조
- **대응**: mTLS 강제 적용(Istio/Linkerd), 서비스 어카운트 최소 권한

### T - Tampering (변조)
- **위협**: 컨테이너 이미지, 설정 파일, etcd 데이터 변조
- **사례**: 공급망 공격으로 악성 이미지 배포, etcd 직접 접근
- **대응**: 이미지 서명(Cosign), etcd 암호화, GitOps 무결성 검증

### R - Repudiation (부인)
- **위협**: 공격자가 악성 행위를 부인할 수 있는 감사 로그 부재
- **사례**: 컨테이너 내부에서의 lateral movement 추적 불가
- **대응**: 중앙화된 로깅(EFK/Loki), 불변 감사 로그, eBPF 기반 syscall 추적

### I - Information Disclosure (정보 유출)
- **위협**: 시크릿 노출, 네트워크 트래픽 스니핑
- **사례**: 환경 변수로 저장된 DB 패스워드, 암호화되지 않은 Pod 간 통신
- **대응**: Kubernetes Secrets 암호화, HashiCorp Vault, 네트워크 암호화

### D - Denial of Service (서비스 거부)
- **위협**: 리소스 고갈로 인한 서비스 중단
- **사례**: 컨테이너 리소스 제한 없이 CPU/메모리 무한 소비, etcd 용량 포화
- **대응**: ResourceQuota, LimitRange, PodDisruptionBudget 적용

### E - Elevation of Privilege (권한 상승)
- **위협**: 컨테이너 탈출, RBAC 에스컬레이션
- **사례**: privileged 컨테이너에서 호스트 접근, ClusterAdmin 권한 획득
- **대응**: Pod Security Standards, RBAC 최소 권한, OPA Gatekeeper

---

## 3. MITRE ATT&CK for Containers

MITRE ATT&CK for Containers는 컨테이너 환경에 특화된 공격 전술과 기법을 체계화한 프레임워크입니다.

### 전술(Tactics) 및 주요 기법

#### TA0001 - Initial Access (초기 접근)
| 기법 ID | 기법명 | 설명 |
|---------|--------|------|
| T1190 | Public-Facing Application Exploit | 노출된 Kubernetes Dashboard, API 서버 악용 |
| T1078 | Valid Accounts | 탈취된 클라우드 자격증명 사용 |
| T1195.002 | Supply Chain Compromise | 악성 컨테이너 이미지 배포 |

#### TA0002 - Execution (실행)
| 기법 ID | 기법명 | 설명 |
|---------|--------|------|
| T1609 | Container Administration Command | kubectl exec, docker exec 악용 |
| T1610 | Deploy Container | 악성 컨테이너 신규 배포 |
| T1059 | Command Interpreter | 컨테이너 내 쉘 실행 |

#### TA0004 - Privilege Escalation (권한 상승)
| 기법 ID | 기법명 | 설명 |
|---------|--------|------|
| T1611 | Escape to Host | 컨테이너 탈출 기법 |
| T1078.001 | Default Accounts | 기본 서비스 어카운트 토큰 악용 |
| T1548 | Abuse Elevation Control | RBAC 정책 우회 |

#### TA0008 - Lateral Movement (수평 이동)
| 기법 ID | 기법명 | 설명 |
|---------|--------|------|
| T1210 | Exploitation of Remote Services | 내부 서비스 취약점 악용 |
| T1552.007 | Container API | 내부 Kubernetes API를 통한 이동 |

#### TA0010 - Exfiltration (데이터 유출)
| 기법 ID | 기법명 | 설명 |
|---------|--------|------|
| T1537 | Transfer Data to Cloud Account | 클라우드 스토리지로 데이터 전송 |
| T1041 | Exfiltration Over C2 Channel | C&C 채널을 통한 데이터 유출 |

---

## 4. CNAPP (Cloud Native Application Protection Platform)

CNAPP은 클라우드 네이티브 애플리케이션을 빌드부터 런타임까지 통합 보호하는 플랫폼입니다.
Gartner가 2021년에 처음 정의하였으며, CSPM, CWPP, CIEM 기능을 통합합니다.

### CNAPP 아키텍처

```
┌────────────────────────────────────────────────────────┐
│                      CNAPP                             │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  CSPM    │  │  CWPP    │  │  CIEM    │            │
│  │(클라우드  │  │(워크로드  │  │(ID/접근  │            │
│  │ 보안상태) │  │  보호)   │  │  관리)   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                        │
│  ┌────────────────────────────────────────┐           │
│  │        CI/CD Pipeline Security         │           │
│  │    (IaC 스캔, 이미지 스캔, SAST)       │           │
│  └────────────────────────────────────────┘           │
└────────────────────────────────────────────────────────┘
```

### 주요 CNAPP 솔루션
- **Prisma Cloud (Palo Alto Networks)**: 가장 포괄적인 CNAPP
- **Wiz**: 에이전트리스 접근 방식, 빠른 배포
- **Lacework**: AI 기반 이상 탐지
- **Aqua Security**: 컨테이너 특화 보안
- **SentinelOne Singularity Cloud**: EDR 기반 CNAPP

---

## 5. CSPM / CWPP / CIEM 비교

### CSPM (Cloud Security Posture Management)

**목적**: 클라우드 인프라 설정 오류 탐지 및 규정 준수 확인

**주요 기능**:
- AWS S3 버킷 공개 노출 탐지
- 보안 그룹 과도한 허용 규칙 탐지
- 멀티 클라우드 규정 준수 (CIS Benchmark, SOC2, PCI-DSS)
- IaC (Terraform, CloudFormation) 정적 분석

**대표 도구**: Prowler, ScoutSuite, CloudSploit, Wiz

```bash
# Prowler를 이용한 AWS 보안 감사 예시
prowler aws -c check11,check12 -r us-east-1
```

### CWPP (Cloud Workload Protection Platform)

**목적**: 컨테이너, VM, 서버리스 워크로드 런타임 보호

**주요 기능**:
- 컨테이너 런타임 이상 탐지 (비정상 프로세스, 파일 접근)
- 취약점 스캔 (이미지 레이어, 패키지)
- 네트워크 마이크로세그멘테이션
- 드리프트 탐지 (실행 중 컨테이너 변경 감지)

**대표 도구**: Falco, Aqua, Sysdig Secure

### CIEM (Cloud Infrastructure Entitlement Management)

**목적**: 클라우드 ID와 권한의 과잉 부여 탐지 및 관리

**주요 기능**:
- IAM 정책 분석 (실제 사용 vs 부여된 권한)
- 미사용 권한 탐지 및 제거 권고
- 권한 에스컬레이션 경로 시각화
- Just-In-Time 접근 제어

**대표 도구**: Ermetic, CloudKnox, AWS IAM Access Analyzer

### 비교 표

| 기준 | CSPM | CWPP | CIEM |
|------|------|------|------|
| 초점 | 인프라 설정 | 워크로드 런타임 | ID/권한 |
| 시점 | 빌드/배포 | 런타임 | 지속적 |
| 에이전트 필요 | 불필요 | 필요 | 불필요 |
| 주요 위협 | 설정 오류 | 런타임 공격 | 권한 남용 |

---

## 6. 컨테이너 위협 모델

### 6.1 이미지 취약점

컨테이너 이미지는 수백 개의 패키지와 라이브러리를 포함하며, 각각이 취약점의 공격 표면이 됩니다.

```
이미지 레이어 구조:
┌─────────────────────────────┐
│   애플리케이션 코드 레이어  │  ← SAST, SCA
├─────────────────────────────┤
│   런타임 의존성 레이어      │  ← 패키지 취약점 스캔
├─────────────────────────────┤
│   OS 패키지 레이어          │  ← CVE 데이터베이스 매핑
├─────────────────────────────┤
│   베이스 이미지 레이어      │  ← 최소화(Distroless/Scratch)
└─────────────────────────────┘
```

**주요 공격 시나리오**:
1. **오래된 베이스 이미지**: ubuntu:18.04에 수백 개의 CVE
2. **Log4Shell (CVE-2021-44228)**: Log4j 취약점이 포함된 이미지 대량 배포
3. **악성 이미지**: Docker Hub의 typosquatting 이미지 (nginx vs. ngnix)

### 6.2 런타임 공격

런타임에서의 공격은 컨테이너가 실행 중일 때 발생합니다.

**컨테이너 탈출 기법**:
1. **privileged 컨테이너 악용**: 호스트 장치에 직접 접근
2. **호스트 경로 마운트**: 호스트 파일시스템 접근
3. **취약한 런타임**: runc CVE-2019-5736 (runC 취약점)
4. **커널 취약점**: 호스트 커널 공유로 인한 권한 상승

```yaml
# 위험한 Pod 설정 예시
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  hostPID: true           # 호스트 PID 네임스페이스 공유 (위험!)
  hostNetwork: true       # 호스트 네트워크 공유 (위험!)
  containers:
  - name: app
    securityContext:
      privileged: true    # 특권 컨테이너 (위험!)
      runAsRoot: true     # root 실행 (위험!)
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /             # 호스트 루트 마운트 (매우 위험!)
```

### 6.3 네트워크 이동 (Lateral Movement)

**Pod 간 통신 공격**:
- 기본 Kubernetes는 모든 Pod 간 통신을 허용
- 네트워크 정책 없으면 내부 서비스 스캔 가능
- CoreDNS를 이용한 서비스 디스커버리

```
공격자 Pod → 내부 서비스 스캔 → API 서버 접근 → 시크릿 탈취
           → etcd 직접 접근 → 전체 클러스터 장악
```

---

## 7. Kubernetes 공격 매트릭스 (Microsoft)

Microsoft Azure Security Center에서 제공하는 Kubernetes 공격 매트릭스:

### 초기 접근 (Initial Access)
- **Using Cloud Credentials**: 클라우드 자격증명으로 클러스터 접근
- **Compromised Image in Registry**: 악성 이미지 레지스트리 사용
- **Kubeconfig File**: kubeconfig 파일 탈취
- **Exposed Dashboard**: 보안되지 않은 Kubernetes Dashboard
- **Exposed Sensitive Interfaces**: Kubelet API, etcd 직접 노출

### 실행 (Execution)
- **Exec into Container**: kubectl exec 악용
- **New Container**: 악성 컨테이너 신규 생성
- **Application Exploit**: 컨테이너 내 앱 취약점 악용
- **SSH Server Running in Container**: 컨테이너 내 SSH 서버 실행

### 지속성 (Persistence)
- **Backdoor Container**: 백도어 이미지로 교체
- **Writable hostPath Mount**: 호스트 파일시스템에 크론탭 등록
- **Kubernetes CronJob**: 악성 CronJob 생성
- **Malicious Admission Controller**: 악성 Webhook 등록

### 권한 상승 (Privilege Escalation)
- **Privileged Container**: 특권 컨테이너로 호스트 접근
- **Cluster-admin Binding**: ClusterRoleBinding 생성
- **hostPath Mount**: /etc/cron.d, /var/spool/cron 접근
- **Access Cloud Resources**: 메타데이터 API를 통한 IAM 권한

### 방어 우회 (Defense Evasion)
- **Clear Container Logs**: 컨테이너 로그 삭제
- **Delete K8s Events**: Kubernetes 이벤트 삭제
- **Pod/Container Name Similarity**: 정상 Pod와 유사한 이름
- **Connect from Proxy Server**: Proxy를 통한 익명 접근

---

## 8. Python: Kubernetes 보안 감사 자동화 도구

```python
#!/usr/bin/env python3
"""
Kubernetes 보안 감사 체크리스트 자동화 도구
Cloud Native 환경의 보안 설정을 자동으로 검사합니다.
"""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    namespace: str
    description: str
    remediation: str
    passed: bool = False


@dataclass
class AuditResult:
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.total_checks += 1
        if finding.passed:
            self.passed += 1
        else:
            self.failed += 1
            self.findings.append(finding)


def run_kubectl(args: list[str], namespace: str | None = None) -> dict[str, Any] | None:
    """kubectl 명령 실행 및 JSON 결과 반환."""
    cmd = ["kubectl"] + args + ["-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[경고] kubectl 오류: {e.stderr.strip()}", file=sys.stderr)
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(f"[경고] 명령 실패: {e}", file=sys.stderr)
        return None


def check_privileged_containers(namespace: str) -> list[Finding]:
    """특권(privileged) 컨테이너 검사."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for container in pod["spec"].get("containers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged", False):
                findings.append(
                    Finding(
                        check_id="K8S-001",
                        title="특권 컨테이너 감지",
                        severity=Severity.CRITICAL,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description=(
                            f"컨테이너 '{container['name']}'이 privileged=true로 실행 중입니다. "
                            "호스트 커널에 대한 완전한 접근 권한을 가집니다."
                        ),
                        remediation="securityContext.privileged를 false로 설정하거나 제거하세요.",
                        passed=False,
                    )
                )
    return findings


def check_host_path_mounts(namespace: str) -> list[Finding]:
    """hostPath 볼륨 마운트 검사."""
    findings: list[Finding] = []
    dangerous_paths = ["/", "/etc", "/var/run", "/proc", "/sys", "/root"]
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for volume in pod["spec"].get("volumes", []):
            if "hostPath" in volume:
                host_path = volume["hostPath"].get("path", "")
                is_dangerous = any(
                    host_path == dp or host_path.startswith(dp + "/")
                    for dp in dangerous_paths
                )
                severity = Severity.CRITICAL if is_dangerous else Severity.HIGH
                findings.append(
                    Finding(
                        check_id="K8S-002",
                        title="위험한 hostPath 마운트 감지",
                        severity=severity,
                        resource=f"Pod/{pod_name}",
                        namespace=ns,
                        description=(
                            f"볼륨 '{volume['name']}'이 호스트 경로 '{host_path}'를 마운트합니다."
                        ),
                        remediation="hostPath 마운트를 제거하거나 읽기 전용으로 제한하세요.",
                        passed=False,
                    )
                )
    return findings


def check_root_containers(namespace: str) -> list[Finding]:
    """root 사용자로 실행되는 컨테이너 검사."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        pod_sc = pod["spec"].get("securityContext", {})
        for container in pod["spec"].get("containers", []):
            c_sc = container.get("securityContext", {})
            run_as_user = c_sc.get("runAsUser", pod_sc.get("runAsUser", None))
            run_as_non_root = c_sc.get(
                "runAsNonRoot", pod_sc.get("runAsNonRoot", False)
            )
            if run_as_user == 0 or (run_as_user is None and not run_as_non_root):
                findings.append(
                    Finding(
                        check_id="K8S-003",
                        title="root 권한 컨테이너 실행",
                        severity=Severity.HIGH,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description="컨테이너가 root(UID=0) 또는 미지정 사용자로 실행됩니다.",
                        remediation=(
                            "securityContext.runAsNonRoot=true 및 "
                            "runAsUser=1000 이상으로 설정하세요."
                        ),
                        passed=False,
                    )
                )
    return findings


def check_rbac_cluster_admin(namespace: str) -> list[Finding]:
    """ClusterAdmin 권한 바인딩 검사 (namespace 무관)."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "clusterrolebindings"])
    if not data:
        return findings

    for binding in data.get("items", []):
        binding_name = binding["metadata"]["name"]
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            subjects = binding.get("subjects", [])
            for subject in subjects:
                if subject.get("kind") in ("ServiceAccount", "User", "Group"):
                    findings.append(
                        Finding(
                            check_id="K8S-004",
                            title="cluster-admin 권한 바인딩 감지",
                            severity=Severity.CRITICAL,
                            resource=f"ClusterRoleBinding/{binding_name}",
                            namespace="cluster-wide",
                            description=(
                                f"'{subject.get('name')}'({subject.get('kind')})에 "
                                "cluster-admin 권한이 부여되어 있습니다."
                            ),
                            remediation="최소 권한 원칙을 적용하여 필요한 권한만 부여하세요.",
                            passed=False,
                        )
                    )
    return findings


def check_default_service_account(namespace: str) -> list[Finding]:
    """default 서비스 어카운트 토큰 자동 마운트 검사."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        sa_name = pod["spec"].get("serviceAccountName", "default")
        auto_mount = pod["spec"].get("automountServiceAccountToken", True)
        if sa_name == "default" and auto_mount:
            findings.append(
                Finding(
                    check_id="K8S-005",
                    title="default 서비스 어카운트 토큰 자동 마운트",
                    severity=Severity.MEDIUM,
                    resource=f"Pod/{pod_name}",
                    namespace=ns,
                    description=(
                        "Pod가 default 서비스 어카운트를 사용하며 "
                        "토큰이 자동 마운트됩니다."
                    ),
                    remediation=(
                        "automountServiceAccountToken: false 설정 또는 "
                        "전용 서비스 어카운트 사용"
                    ),
                    passed=False,
                )
            )
    return findings


def check_resource_limits(namespace: str) -> list[Finding]:
    """리소스 제한(limits) 미설정 컨테이너 검사."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for container in pod["spec"].get("containers", []):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    Finding(
                        check_id="K8S-006",
                        title="리소스 제한 미설정",
                        severity=Severity.MEDIUM,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description="CPU 또는 메모리 limits가 설정되지 않았습니다.",
                        remediation=(
                            "resources.limits.cpu 및 resources.limits.memory를 설정하세요."
                        ),
                        passed=False,
                    )
                )
    return findings


def check_network_policies(namespace: str) -> list[Finding]:
    """NetworkPolicy 적용 여부 검사."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "networkpolicies"], namespace=namespace)
    if data is None:
        return findings

    policies = data.get("items", [])
    if not policies:
        findings.append(
            Finding(
                check_id="K8S-007",
                title="NetworkPolicy 미적용",
                severity=Severity.HIGH,
                resource="Namespace",
                namespace=namespace,
                description=(
                    f"네임스페이스 '{namespace}'에 NetworkPolicy가 없습니다. "
                    "모든 Pod 간 통신이 허용됩니다."
                ),
                remediation="기본 deny-all NetworkPolicy를 적용하고 필요한 트래픽만 허용하세요.",
                passed=False,
            )
        )
    return findings


def audit_namespace(namespace: str) -> AuditResult:
    """특정 네임스페이스에 대한 보안 감사 실행."""
    result = AuditResult()
    check_functions = [
        check_privileged_containers,
        check_host_path_mounts,
        check_root_containers,
        check_default_service_account,
        check_resource_limits,
        check_network_policies,
    ]

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fn, namespace): fn.__name__
            for fn in check_functions
        }
        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                findings = future.result()
                for finding in findings:
                    result.add_finding(finding)
            except Exception as e:
                print(f"[오류] {fn_name} 실패: {e}", file=sys.stderr)

    # ClusterAdmin 검사는 별도 실행 (namespace 무관)
    ca_findings = check_rbac_cluster_admin(namespace)
    for finding in ca_findings:
        result.add_finding(finding)

    return result


def print_report(result: AuditResult, output_format: str) -> None:
    """감사 결과 출력."""
    if output_format == "json":
        report = {
            "summary": {
                "total_checks": result.total_checks,
                "passed": result.passed,
                "failed": result.failed,
            },
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "resource": f.resource,
                    "namespace": f.namespace,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 텍스트 출력
    print("\n" + "=" * 70)
    print("  Kubernetes 보안 감사 결과")
    print("=" * 70)
    print(f"  전체 검사: {result.total_checks}")
    print(f"  통과:      {result.passed}")
    print(f"  실패:      {result.failed}")
    print("=" * 70)

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.severity),
    )

    for finding in sorted_findings:
        severity_colors = {
            Severity.CRITICAL: "\033[91m",
            Severity.HIGH: "\033[93m",
            Severity.MEDIUM: "\033[94m",
            Severity.LOW: "\033[92m",
            Severity.INFO: "\033[0m",
        }
        color = severity_colors.get(finding.severity, "\033[0m")
        reset = "\033[0m"

        print(f"\n{color}[{finding.severity.value}]{reset} {finding.check_id}: {finding.title}")
        print(f"  리소스:   {finding.resource} ({finding.namespace})")
        print(f"  설명:     {finding.description}")
        print(f"  조치:     {finding.remediation}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes 보안 감사 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s -n default
  %(prog)s -n kube-system --format json
  %(prog)s -n default -n production --format json
        """,
    )
    parser.add_argument(
        "-n",
        "--namespace",
        action="append",
        dest="namespaces",
        default=["default"],
        help="감사할 네임스페이스 (기본: default, 반복 사용 가능)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "--all-namespaces",
        action="store_true",
        help="모든 네임스페이스 감사",
    )
    return parser.parse_args()


def get_all_namespaces() -> list[str]:
    """클러스터의 모든 네임스페이스 목록 조회."""
    data = run_kubectl(["get", "namespaces"])
    if not data:
        return ["default"]
    return [
        ns["metadata"]["name"]
        for ns in data.get("items", [])
    ]


def main() -> int:
    args = parse_args()

    namespaces = args.namespaces
    if args.all_namespaces:
        namespaces = get_all_namespaces()
        print(f"[정보] {len(namespaces)}개 네임스페이스 감사 시작...")

    combined_result = AuditResult()
    for namespace in namespaces:
        print(f"[정보] 네임스페이스 '{namespace}' 감사 중...", file=sys.stderr)
        result = audit_namespace(namespace)
        combined_result.total_checks += result.total_checks
        combined_result.passed += result.passed
        combined_result.failed += result.failed
        combined_result.findings.extend(result.findings)

    print_report(combined_result, args.format)
    return 0 if combined_result.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```

### 도구 사용법

```bash
# 기본 사용 (default 네임스페이스)
python k8s_audit.py

# 특정 네임스페이스 감사
python k8s_audit.py -n production

# 여러 네임스페이스 동시 감사
python k8s_audit.py -n default -n kube-system -n production

# JSON 형식으로 출력 (CI/CD 통합)
python k8s_audit.py --all-namespaces --format json | jq '.findings[] | select(.severity == "CRITICAL")'

# 심각도별 필터링
python k8s_audit.py --format json | jq '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
```

---

## 참고 자료

- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Kubernetes Threat Matrix](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/CNCF_cloud-native-security-whitepaper-Nov2020.pdf)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)

---

<a name="english"></a>

# Cloud Native Security Threat Model

## Table of Contents
1. Cloud Native Security Overview
2. Applying the STRIDE Threat Model
3. MITRE ATT&CK for Containers
4. CNAPP (Cloud Native Application Protection Platform)
5. CSPM / CWPP / CIEM Comparison
6. Container Threat Model
7. Kubernetes Attack Matrix
8. Python: Kubernetes Security Audit Automation Tool

---

## 1. Cloud Native Security Overview

The Cloud Native environment is a complex ecosystem combining containers, microservices, orchestration (Kubernetes), serverless, and CI/CD pipelines. Traditional perimeter security models do not work in this environment, and new threat models and response methodologies are required.

### The 4C Layers of Cloud Native Security

```
┌─────────────────────────────────┐
│           Code                  │  ← Application vulnerabilities, SAST/DAST
├─────────────────────────────────┤
│       Container                 │  ← Image vulnerabilities, runtime security
├─────────────────────────────────┤
│        Cluster                  │  ← Kubernetes RBAC, network policies
├─────────────────────────────────┤
│          Cloud                  │  ← IAM, network, storage security
└─────────────────────────────────┘
```

Each layer trusts the security of the layer below it, so if a lower layer is compromised, the upper layers are also exposed to risk.

---

## 2. Applying the STRIDE Threat Model

STRIDE is a threat modeling methodology developed by Microsoft. It applies to Cloud Native environments as follows.

### S - Spoofing
- **Threat**: A malicious container masquerading as a trusted service
- **Examples**: Service account token theft, mTLS certificate forgery
- **Mitigation**: Enforce mTLS (Istio/Linkerd), least-privilege service accounts

### T - Tampering
- **Threat**: Tampering with container images, configuration files, or etcd data
- **Examples**: Deploying malicious images via supply chain attacks, direct etcd access
- **Mitigation**: Image signing (Cosign), etcd encryption, GitOps integrity verification

### R - Repudiation
- **Threat**: Absence of audit logs that allows attackers to deny malicious actions
- **Examples**: Unable to trace lateral movement inside containers
- **Mitigation**: Centralized logging (EFK/Loki), immutable audit logs, eBPF-based syscall tracing

### I - Information Disclosure
- **Threat**: Secret exposure, network traffic sniffing
- **Examples**: DB passwords stored as environment variables, unencrypted inter-Pod communication
- **Mitigation**: Kubernetes Secrets encryption, HashiCorp Vault, network encryption

### D - Denial of Service
- **Threat**: Service disruption due to resource exhaustion
- **Examples**: Unlimited CPU/memory consumption without container resource limits, etcd capacity saturation
- **Mitigation**: Apply ResourceQuota, LimitRange, PodDisruptionBudget

### E - Elevation of Privilege
- **Threat**: Container escape, RBAC escalation
- **Examples**: Accessing the host from a privileged container, obtaining ClusterAdmin rights
- **Mitigation**: Pod Security Standards, RBAC least privilege, OPA Gatekeeper

---

## 3. MITRE ATT&CK for Containers

MITRE ATT&CK for Containers is a framework that systematizes attack tactics and techniques specific to container environments.

### Tactics and Key Techniques

#### TA0001 - Initial Access
| Technique ID | Technique Name | Description |
|---------|--------|------|
| T1190 | Public-Facing Application Exploit | Exploiting exposed Kubernetes Dashboard, API server |
| T1078 | Valid Accounts | Using stolen cloud credentials |
| T1195.002 | Supply Chain Compromise | Distributing malicious container images |

#### TA0002 - Execution
| Technique ID | Technique Name | Description |
|---------|--------|------|
| T1609 | Container Administration Command | Abusing kubectl exec, docker exec |
| T1610 | Deploy Container | Deploying new malicious containers |
| T1059 | Command Interpreter | Executing a shell inside a container |

#### TA0004 - Privilege Escalation
| Technique ID | Technique Name | Description |
|---------|--------|------|
| T1611 | Escape to Host | Container escape techniques |
| T1078.001 | Default Accounts | Abusing default service account tokens |
| T1548 | Abuse Elevation Control | Bypassing RBAC policies |

#### TA0008 - Lateral Movement
| Technique ID | Technique Name | Description |
|---------|--------|------|
| T1210 | Exploitation of Remote Services | Exploiting internal service vulnerabilities |
| T1552.007 | Container API | Moving via the internal Kubernetes API |

#### TA0010 - Exfiltration
| Technique ID | Technique Name | Description |
|---------|--------|------|
| T1537 | Transfer Data to Cloud Account | Transferring data to cloud storage |
| T1041 | Exfiltration Over C2 Channel | Exfiltrating data through C&C channels |

---

## 4. CNAPP (Cloud Native Application Protection Platform)

CNAPP is a platform that provides unified protection for cloud-native applications from build time to runtime. First defined by Gartner in 2021, it integrates CSPM, CWPP, and CIEM capabilities.

### CNAPP Architecture

```
┌────────────────────────────────────────────────────────┐
│                      CNAPP                             │
│                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  CSPM    │  │  CWPP    │  │  CIEM    │            │
│  │ (Cloud   │  │(Workload │  │(Identity/│            │
│  │ Posture) │  │Protection│  │  Access) │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                        │
│  ┌────────────────────────────────────────┐           │
│  │        CI/CD Pipeline Security         │           │
│  │    (IaC scanning, image scanning, SAST)│           │
│  └────────────────────────────────────────┘           │
└────────────────────────────────────────────────────────┘
```

### Key CNAPP Solutions
- **Prisma Cloud (Palo Alto Networks)**: Most comprehensive CNAPP offering
- **Wiz**: Agentless approach, rapid deployment
- **Lacework**: AI-based anomaly detection
- **Aqua Security**: Container-specialized security
- **SentinelOne Singularity Cloud**: EDR-based CNAPP

---

## 5. CSPM / CWPP / CIEM Comparison

### CSPM (Cloud Security Posture Management)

**Purpose**: Detect cloud infrastructure misconfigurations and verify regulatory compliance

**Key Features**:
- Detecting publicly exposed AWS S3 buckets
- Detecting overly permissive security group rules
- Multi-cloud compliance (CIS Benchmark, SOC2, PCI-DSS)
- Static analysis of IaC (Terraform, CloudFormation)

**Representative Tools**: Prowler, ScoutSuite, CloudSploit, Wiz

```bash
# Example AWS security audit using Prowler
prowler aws -c check11,check12 -r us-east-1
```

### CWPP (Cloud Workload Protection Platform)

**Purpose**: Runtime protection for container, VM, and serverless workloads

**Key Features**:
- Container runtime anomaly detection (abnormal processes, file access)
- Vulnerability scanning (image layers, packages)
- Network microsegmentation
- Drift detection (detecting changes to running containers)

**Representative Tools**: Falco, Aqua, Sysdig Secure

### CIEM (Cloud Infrastructure Entitlement Management)

**Purpose**: Detect and manage over-provisioned cloud identities and permissions

**Key Features**:
- IAM policy analysis (actual usage vs. granted permissions)
- Detection and removal recommendations for unused permissions
- Visualization of privilege escalation paths
- Just-In-Time access control

**Representative Tools**: Ermetic, CloudKnox, AWS IAM Access Analyzer

### Comparison Table

| Criteria | CSPM | CWPP | CIEM |
|------|------|------|------|
| Focus | Infrastructure configuration | Workload runtime | Identity/permissions |
| Timing | Build/deploy | Runtime | Continuous |
| Agent required | No | Yes | No |
| Primary threats | Misconfigurations | Runtime attacks | Permission abuse |

---

## 6. Container Threat Model

### 6.1 Image Vulnerabilities

Container images contain hundreds of packages and libraries, each of which becomes an attack surface for vulnerabilities.

```
Image Layer Structure:
┌─────────────────────────────┐
│   Application Code Layer    │  ← SAST, SCA
├─────────────────────────────┤
│   Runtime Dependency Layer  │  ← Package vulnerability scanning
├─────────────────────────────┤
│   OS Package Layer          │  ← CVE database mapping
├─────────────────────────────┤
│   Base Image Layer          │  ← Minimization (Distroless/Scratch)
└─────────────────────────────┘
```

**Key Attack Scenarios**:
1. **Outdated base images**: Hundreds of CVEs in ubuntu:18.04
2. **Log4Shell (CVE-2021-44228)**: Mass deployment of images containing the Log4j vulnerability
3. **Malicious images**: Typosquatting images on Docker Hub (nginx vs. ngnix)

### 6.2 Runtime Attacks

Runtime attacks occur while a container is running.

**Container Escape Techniques**:
1. **Abusing privileged containers**: Direct access to host devices
2. **Host path mounts**: Access to the host filesystem
3. **Vulnerable runtime**: runc CVE-2019-5736 (runC vulnerability)
4. **Kernel vulnerabilities**: Privilege escalation due to shared host kernel

```yaml
# Example of a dangerous Pod configuration
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  hostPID: true           # Share host PID namespace (DANGEROUS!)
  hostNetwork: true       # Share host network (DANGEROUS!)
  containers:
  - name: app
    securityContext:
      privileged: true    # Privileged container (DANGEROUS!)
      runAsRoot: true     # Run as root (DANGEROUS!)
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /             # Mount host root (VERY DANGEROUS!)
```

### 6.3 Lateral Movement

**Inter-Pod Communication Attacks**:
- Default Kubernetes allows all communication between Pods
- Without network policies, internal services can be scanned
- Service discovery via CoreDNS

```
Attacker Pod → Internal service scan → API server access → Secret theft
             → Direct etcd access → Full cluster takeover
```

---

## 7. Kubernetes Attack Matrix (Microsoft)

The Kubernetes attack matrix provided by Microsoft Azure Security Center:

### Initial Access
- **Using Cloud Credentials**: Accessing the cluster with cloud credentials
- **Compromised Image in Registry**: Using a malicious image registry
- **Kubeconfig File**: Stealing the kubeconfig file
- **Exposed Dashboard**: An unsecured Kubernetes Dashboard
- **Exposed Sensitive Interfaces**: Direct exposure of the Kubelet API, etcd

### Execution
- **Exec into Container**: Abusing kubectl exec
- **New Container**: Creating a new malicious container
- **Application Exploit**: Exploiting app vulnerabilities inside a container
- **SSH Server Running in Container**: Running an SSH server inside a container

### Persistence
- **Backdoor Container**: Replacing with a backdoored image
- **Writable hostPath Mount**: Registering a crontab on the host filesystem
- **Kubernetes CronJob**: Creating a malicious CronJob
- **Malicious Admission Controller**: Registering a malicious Webhook

### Privilege Escalation
- **Privileged Container**: Accessing the host from a privileged container
- **Cluster-admin Binding**: Creating a ClusterRoleBinding
- **hostPath Mount**: Accessing /etc/cron.d, /var/spool/cron
- **Access Cloud Resources**: IAM permissions via the metadata API

### Defense Evasion
- **Clear Container Logs**: Deleting container logs
- **Delete K8s Events**: Deleting Kubernetes events
- **Pod/Container Name Similarity**: Using names similar to legitimate Pods
- **Connect from Proxy Server**: Anonymous access through a proxy

---

## 8. Python: Kubernetes Security Audit Automation Tool

```python
#!/usr/bin/env python3
"""
Kubernetes Security Audit Checklist Automation Tool
Automatically inspects security configurations in Cloud Native environments.
"""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    namespace: str
    description: str
    remediation: str
    passed: bool = False


@dataclass
class AuditResult:
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.total_checks += 1
        if finding.passed:
            self.passed += 1
        else:
            self.failed += 1
            self.findings.append(finding)


def run_kubectl(args: list[str], namespace: str | None = None) -> dict[str, Any] | None:
    """Execute a kubectl command and return the JSON result."""
    cmd = ["kubectl"] + args + ["-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] kubectl error: {e.stderr.strip()}", file=sys.stderr)
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(f"[WARNING] Command failed: {e}", file=sys.stderr)
        return None


def check_privileged_containers(namespace: str) -> list[Finding]:
    """Check for privileged containers."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for container in pod["spec"].get("containers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged", False):
                findings.append(
                    Finding(
                        check_id="K8S-001",
                        title="Privileged Container Detected",
                        severity=Severity.CRITICAL,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description=(
                            f"Container '{container['name']}' is running with privileged=true. "
                            "It has full access to the host kernel."
                        ),
                        remediation="Set or remove securityContext.privileged to false.",
                        passed=False,
                    )
                )
    return findings


def check_host_path_mounts(namespace: str) -> list[Finding]:
    """Check for hostPath volume mounts."""
    findings: list[Finding] = []
    dangerous_paths = ["/", "/etc", "/var/run", "/proc", "/sys", "/root"]
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for volume in pod["spec"].get("volumes", []):
            if "hostPath" in volume:
                host_path = volume["hostPath"].get("path", "")
                is_dangerous = any(
                    host_path == dp or host_path.startswith(dp + "/")
                    for dp in dangerous_paths
                )
                severity = Severity.CRITICAL if is_dangerous else Severity.HIGH
                findings.append(
                    Finding(
                        check_id="K8S-002",
                        title="Dangerous hostPath Mount Detected",
                        severity=severity,
                        resource=f"Pod/{pod_name}",
                        namespace=ns,
                        description=(
                            f"Volume '{volume['name']}' mounts host path '{host_path}'."
                        ),
                        remediation="Remove the hostPath mount or restrict it to read-only.",
                        passed=False,
                    )
                )
    return findings


def check_root_containers(namespace: str) -> list[Finding]:
    """Check for containers running as the root user."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        pod_sc = pod["spec"].get("securityContext", {})
        for container in pod["spec"].get("containers", []):
            c_sc = container.get("securityContext", {})
            run_as_user = c_sc.get("runAsUser", pod_sc.get("runAsUser", None))
            run_as_non_root = c_sc.get(
                "runAsNonRoot", pod_sc.get("runAsNonRoot", False)
            )
            if run_as_user == 0 or (run_as_user is None and not run_as_non_root):
                findings.append(
                    Finding(
                        check_id="K8S-003",
                        title="Container Running as Root",
                        severity=Severity.HIGH,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description="Container is running as root (UID=0) or with an unspecified user.",
                        remediation=(
                            "Set securityContext.runAsNonRoot=true and "
                            "runAsUser to 1000 or higher."
                        ),
                        passed=False,
                    )
                )
    return findings


def check_rbac_cluster_admin(namespace: str) -> list[Finding]:
    """Check for ClusterAdmin role bindings (namespace-independent)."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "clusterrolebindings"])
    if not data:
        return findings

    for binding in data.get("items", []):
        binding_name = binding["metadata"]["name"]
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            subjects = binding.get("subjects", [])
            for subject in subjects:
                if subject.get("kind") in ("ServiceAccount", "User", "Group"):
                    findings.append(
                        Finding(
                            check_id="K8S-004",
                            title="cluster-admin Role Binding Detected",
                            severity=Severity.CRITICAL,
                            resource=f"ClusterRoleBinding/{binding_name}",
                            namespace="cluster-wide",
                            description=(
                                f"'{subject.get('name')}' ({subject.get('kind')}) "
                                "has been granted cluster-admin privileges."
                            ),
                            remediation="Apply the principle of least privilege and grant only necessary permissions.",
                            passed=False,
                        )
                    )
    return findings


def check_default_service_account(namespace: str) -> list[Finding]:
    """Check for automatic mounting of the default service account token."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        sa_name = pod["spec"].get("serviceAccountName", "default")
        auto_mount = pod["spec"].get("automountServiceAccountToken", True)
        if sa_name == "default" and auto_mount:
            findings.append(
                Finding(
                    check_id="K8S-005",
                    title="Default Service Account Token Auto-Mounted",
                    severity=Severity.MEDIUM,
                    resource=f"Pod/{pod_name}",
                    namespace=ns,
                    description=(
                        "The Pod uses the default service account and "
                        "the token is auto-mounted."
                    ),
                    remediation=(
                        "Set automountServiceAccountToken: false or "
                        "use a dedicated service account."
                    ),
                    passed=False,
                )
            )
    return findings


def check_resource_limits(namespace: str) -> list[Finding]:
    """Check for containers with no resource limits set."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "pods"], namespace=namespace)
    if not data:
        return findings

    for pod in data.get("items", []):
        pod_name = pod["metadata"]["name"]
        ns = pod["metadata"]["namespace"]
        for container in pod["spec"].get("containers", []):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    Finding(
                        check_id="K8S-006",
                        title="Resource Limits Not Set",
                        severity=Severity.MEDIUM,
                        resource=f"Pod/{pod_name}/{container['name']}",
                        namespace=ns,
                        description="CPU or memory limits are not configured.",
                        remediation=(
                            "Set resources.limits.cpu and resources.limits.memory."
                        ),
                        passed=False,
                    )
                )
    return findings


def check_network_policies(namespace: str) -> list[Finding]:
    """Check whether NetworkPolicies are applied."""
    findings: list[Finding] = []
    data = run_kubectl(["get", "networkpolicies"], namespace=namespace)
    if data is None:
        return findings

    policies = data.get("items", [])
    if not policies:
        findings.append(
            Finding(
                check_id="K8S-007",
                title="NetworkPolicy Not Applied",
                severity=Severity.HIGH,
                resource="Namespace",
                namespace=namespace,
                description=(
                    f"Namespace '{namespace}' has no NetworkPolicy. "
                    "All inter-Pod communication is allowed."
                ),
                remediation="Apply a default deny-all NetworkPolicy and allow only required traffic.",
                passed=False,
            )
        )
    return findings


def audit_namespace(namespace: str) -> AuditResult:
    """Run a security audit for a specific namespace."""
    result = AuditResult()
    check_functions = [
        check_privileged_containers,
        check_host_path_mounts,
        check_root_containers,
        check_default_service_account,
        check_resource_limits,
        check_network_policies,
    ]

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fn, namespace): fn.__name__
            for fn in check_functions
        }
        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                findings = future.result()
                for finding in findings:
                    result.add_finding(finding)
            except Exception as e:
                print(f"[ERROR] {fn_name} failed: {e}", file=sys.stderr)

    # ClusterAdmin check runs separately (namespace-independent)
    ca_findings = check_rbac_cluster_admin(namespace)
    for finding in ca_findings:
        result.add_finding(finding)

    return result


def print_report(result: AuditResult, output_format: str) -> None:
    """Print audit results."""
    if output_format == "json":
        report = {
            "summary": {
                "total_checks": result.total_checks,
                "passed": result.passed,
                "failed": result.failed,
            },
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "resource": f.resource,
                    "namespace": f.namespace,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # Text output
    print("\n" + "=" * 70)
    print("  Kubernetes Security Audit Results")
    print("=" * 70)
    print(f"  Total Checks: {result.total_checks}")
    print(f"  Passed:       {result.passed}")
    print(f"  Failed:       {result.failed}")
    print("=" * 70)

    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.severity),
    )

    for finding in sorted_findings:
        severity_colors = {
            Severity.CRITICAL: "\033[91m",
            Severity.HIGH: "\033[93m",
            Severity.MEDIUM: "\033[94m",
            Severity.LOW: "\033[92m",
            Severity.INFO: "\033[0m",
        }
        color = severity_colors.get(finding.severity, "\033[0m")
        reset = "\033[0m"

        print(f"\n{color}[{finding.severity.value}]{reset} {finding.check_id}: {finding.title}")
        print(f"  Resource:     {finding.resource} ({finding.namespace})")
        print(f"  Description:  {finding.description}")
        print(f"  Remediation:  {finding.remediation}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kubernetes Security Audit Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  %(prog)s -n default
  %(prog)s -n kube-system --format json
  %(prog)s -n default -n production --format json
        """,
    )
    parser.add_argument(
        "-n",
        "--namespace",
        action="append",
        dest="namespaces",
        default=["default"],
        help="Namespace to audit (default: default, can be repeated)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--all-namespaces",
        action="store_true",
        help="Audit all namespaces",
    )
    return parser.parse_args()


def get_all_namespaces() -> list[str]:
    """Retrieve a list of all namespaces in the cluster."""
    data = run_kubectl(["get", "namespaces"])
    if not data:
        return ["default"]
    return [
        ns["metadata"]["name"]
        for ns in data.get("items", [])
    ]


def main() -> int:
    args = parse_args()

    namespaces = args.namespaces
    if args.all_namespaces:
        namespaces = get_all_namespaces()
        print(f"[INFO] Starting audit of {len(namespaces)} namespaces...")

    combined_result = AuditResult()
    for namespace in namespaces:
        print(f"[INFO] Auditing namespace '{namespace}'...", file=sys.stderr)
        result = audit_namespace(namespace)
        combined_result.total_checks += result.total_checks
        combined_result.passed += result.passed
        combined_result.failed += result.failed
        combined_result.findings.extend(result.findings)

    print_report(combined_result, args.format)
    return 0 if combined_result.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```

### Tool Usage

```bash
# Basic usage (default namespace)
python k8s_audit.py

# Audit a specific namespace
python k8s_audit.py -n production

# Audit multiple namespaces simultaneously
python k8s_audit.py -n default -n kube-system -n production

# Output in JSON format (for CI/CD integration)
python k8s_audit.py --all-namespaces --format json | jq '.findings[] | select(.severity == "CRITICAL")'

# Filter by severity
python k8s_audit.py --format json | jq '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
```

---

## References

- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Kubernetes Threat Matrix](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/CNCF_cloud-native-security-whitepaper-Nov2020.pdf)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
