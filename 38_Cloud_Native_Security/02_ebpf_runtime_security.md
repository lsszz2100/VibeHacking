> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# eBPF 런타임 보안

## 목차
1. eBPF 개요
2. 런타임 보안 도구 비교 (Falco, Tetragon, Tracee)
3. Falco 규칙 작성 및 배포
4. 시스콜 기반 이상 탐지
5. eBPF 네트워크 패킷 필터링
6. Python: Falco 알림 파서 및 자동 대응 도구

---

## 1. eBPF 개요

### eBPF(Extended Berkeley Packet Filter)란?

eBPF는 Linux 커널 내에서 샌드박스 프로그램을 실행할 수 있는 혁신적인 기술입니다.
커널 소스 코드를 수정하거나 커널 모듈을 로드하지 않고도 커널의 동작을 안전하게 관찰하고
수정할 수 있습니다.

### 전통적 방식 vs eBPF

```
전통적 방식 (커널 모듈):
┌──────────────────────────────────────┐
│         User Space                   │
│  모니터링 도구 → 커널 모듈 로드 →   │
│  커널 수정 (안정성 위험!)            │
└──────────────────────────────────────┘

eBPF 방식:
┌──────────────────────────────────────┐
│         User Space                   │
│  eBPF 프로그램 작성 → 컴파일 →     │
│  Verifier 검증 → 안전한 커널 실행   │
└──────────────────────────────────────┘
```

### eBPF 동작 원리

1. **eBPF 프로그램 작성**: C 또는 Rust로 작성 (제한된 문법)
2. **LLVM 컴파일**: eBPF 바이트코드로 컴파일
3. **Verifier 검증**: 커널이 안전성 검사 (무한루프, 메모리 접근 검증)
4. **JIT 컴파일**: 네이티브 기계어로 변환
5. **Hook 연결**: 커널 이벤트에 프로그램 연결
6. **맵(Map) 통신**: 커널-사용자 공간 간 데이터 공유

### eBPF Hook 포인트

| Hook 유형 | 용도 |
|-----------|------|
| kprobe/kretprobe | 커널 함수 진입/반환 |
| uprobe/uretprobe | 사용자 함수 추적 |
| tracepoint | 정적 커널 추적점 |
| XDP (eXpress Data Path) | 네트워크 패킷 최조속 처리 |
| TC (Traffic Control) | 네트워크 트래픽 제어 |
| LSM | Linux Security Module 보안 정책 |
| Cgroup | 컨테이너 리소스 제어 |

### 보안 관점에서의 eBPF

```
eBPF 보안 활용:
├── 관찰성(Observability)
│   ├── 시스콜 모니터링
│   ├── 파일 접근 추적
│   ├── 네트워크 연결 기록
│   └── 프로세스 계보 추적
├── 정책 강제(Policy Enforcement)
│   ├── 네트워크 패킷 필터링
│   ├── 시스콜 차단
│   └── 파일 접근 제어
└── 포렌식(Forensics)
    ├── 실시간 이벤트 기록
    └── 컨테이너별 격리된 추적
```

---

## 2. 런타임 보안 도구 비교

### 2.1 Falco (CNCF 졸업 프로젝트)

Sysdig가 개발하고 CNCF에 기증한 런타임 보안 도구입니다.

**특징**:
- 시스콜 기반 이상 행동 탐지
- YAML 기반 규칙 언어 (이해하기 쉬움)
- 다양한 출력 채널 (stdout, Slack, PagerDuty, Kafka)
- Kubernetes 이벤트와 연동

**동작 방식**:
```
시스콜 발생 → libscap(캡처) → libsinsp(파싱/컨텍스트) → 
Falco 엔진(규칙 평가) → 알림 출력
```

**설치**:
```bash
# Helm으로 Kubernetes에 설치
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --namespace falco \
  --create-namespace
```

### 2.2 Tetragon (Cilium 프로젝트)

Isovalent(Cilium 개발사)가 만든 eBPF 기반 보안 도구입니다.

**특징**:
- 커널 수준에서 직접 이벤트 처리 (커널 레이어에서 차단 가능)
- 낮은 오버헤드 (eBPF 최적화)
- TracingPolicy CRD로 정책 정의
- Cilium과 통합 시 강력한 네트워크 보안

**TracingPolicy 예시**:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write-shell"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Postfix"
        values:
        - "/etc/passwd"
        - "/etc/shadow"
      matchActions:
      - action: Sigkill  # 프로세스 즉시 종료
```

### 2.3 Tracee (Aqua Security)

Aqua Security가 개발한 eBPF 기반 런타임 보안 및 포렌식 도구입니다.

**특징**:
- 400개 이상의 이벤트 추적
- OPA(Open Policy Agent) 기반 정책
- 컨테이너 이미지 분석 통합
- Go 기반으로 작성

**실행 예시**:
```bash
# Docker로 실행
docker run --name tracee --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest \
  --event execve,execveat,openat

# 특정 컨테이너 이벤트만 추적
tracee --event execve --containers
```

### 도구 비교 표

| 기준 | Falco | Tetragon | Tracee |
|------|-------|----------|--------|
| 기반 기술 | eBPF/커널 모듈 | eBPF | eBPF |
| 실시간 차단 | 미지원 | 지원 | 미지원 |
| 규칙 언어 | YAML | CRD | Rego/OPA |
| Kubernetes 통합 | 우수 | 우수 | 좋음 |
| 성능 오버헤드 | 중간 | 낮음 | 낮음 |
| 커뮤니티 | CNCF 졸업 | 활성화 | 활성화 |
| 학습 곡선 | 낮음 | 중간 | 중간 |

---

## 3. Falco 규칙 작성 및 배포

### 규칙 구조

```yaml
# Falco 규칙 기본 구조
- rule: 규칙_이름
  desc: 규칙 설명
  condition: 이벤트_필터_조건
  output: 알림_메시지_형식
  priority: CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|DEBUG
  tags: [태그1, 태그2]
```

### 내장 매크로 및 리스트

```yaml
# 리스트 정의
- list: shell_binaries
  items: [bash, zsh, sh, ksh, fish, tcsh, dash]

- list: sensitive_files
  items:
    - /etc/passwd
    - /etc/shadow
    - /etc/sudoers
    - /root/.ssh/authorized_keys
    - /etc/kubernetes/admin.conf

# 매크로 정의
- macro: spawned_process
  condition: evt.type = execve and evt.dir = <

- macro: container
  condition: (container.id != host)

- macro: interactive
  condition: >
    ((proc.aname=sshd and proc.name != sshd) or
     proc.name = bash or proc.name = sudo)
```

### 실전 Falco 규칙 예시

```yaml
# 1. 컨테이너 내 쉘 실행 탐지
- rule: Terminal Shell in Container
  desc: 실행 중인 컨테이너에서 터미널 쉘이 시작되었습니다
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    proc.tty != 0 and
    not proc.pname in (shell_binaries)
  output: >
    컨테이너에서 쉘 시작 감지 (user=%user.name user_loginuid=%user.loginuid
    %container.info shell=%proc.name parent=%proc.pname
    cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id
    image=%container.image.repository:%container.image.tag)
  priority: NOTICE
  tags: [container, shell, T1059]

# 2. 민감한 파일 접근 탐지
- rule: Read sensitive file untrusted
  desc: 신뢰되지 않은 프로세스가 민감한 파일에 접근했습니다
  condition: >
    open_read and
    sensitive_files and
    not proc.name in (trusted_binaries) and
    not user.name = root and
    container
  output: >
    민감한 파일 읽기 시도 (user=%user.name user_loginuid=%user.loginuid
    command=%proc.cmdline file=%fd.name
    container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [filesystem, T1552]

# 3. 새 파일 실행 탐지 (드리프트 감지)
- rule: Drift Detected (chmod +x)
  desc: 컨테이너 실행 후 새로운 실행 파일 생성 감지
  condition: >
    chmod and
    container and
    evt.arg.mode contains "x" and
    not proc.name in (package_managers)
  output: >
    실행 가능 파일 생성 감지 (user=%user.name
    command=%proc.cmdline file=%fd.name
    container_id=%container.id)
  priority: ERROR
  tags: [container, drift, T1222]

# 4. 컨테이너 탈출 시도 탐지
- rule: Container Escape via nsenter
  desc: nsenter를 이용한 컨테이너 탈출 시도
  condition: >
    spawned_process and
    proc.name = nsenter and
    container
  output: >
    nsenter로 컨테이너 탈출 시도 감지 (user=%user.name
    command=%proc.cmdline container_id=%container.id)
  priority: CRITICAL
  tags: [container, escape, T1611]

# 5. Kubernetes API 서버 접근 탐지
- rule: Contact K8s API Server From Container
  desc: 컨테이너에서 K8s API 서버로 직접 접근
  condition: >
    outbound and
    container and
    fd.sip = "kubernetes.default.svc.cluster.local" and
    not proc.name in (kubectl, curl) and
    evt.type = connect
  output: >
    컨테이너에서 K8s API 서버 접근 (user=%user.name
    command=%proc.cmdline container_id=%container.id
    connection=%fd.name)
  priority: WARNING
  tags: [k8s, api, T1552.007]
```

### Falco Kubernetes 배포 설정

```yaml
# falco-values.yaml
falco:
  rules_file:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/falco_rules.local.yaml
    - /etc/falco/k8s_audit_rules.yaml

  json_output: true
  json_include_output_property: true

  http_output:
    enabled: true
    url: "http://falcosidekick:2801"

falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      minimumpriority: "warning"
    webhook:
      address: "http://incident-response-api:8080/falco"
```

---

## 4. 시스콜 기반 이상 탐지

### 주요 모니터링 대상 시스콜

```
보안 관련 핵심 시스콜:
├── 프로세스
│   ├── execve/execveat  - 프로세스 실행
│   ├── fork/clone       - 프로세스 생성
│   └── ptrace           - 프로세스 추적 (디버거)
├── 파일 시스템
│   ├── open/openat      - 파일 열기
│   ├── write            - 파일 쓰기
│   ├── chmod/chown      - 권한 변경
│   └── unlink           - 파일 삭제
├── 네트워크
│   ├── connect          - 아웃바운드 연결
│   ├── accept           - 인바운드 연결
│   ├── bind             - 포트 바인딩
│   └── sendto/recvfrom  - 데이터 전송
└── 권한
    ├── setuid/setgid    - 사용자/그룹 변경
    ├── capset           - 캐퍼빌리티 설정
    └── chroot           - 루트 디렉토리 변경
```

### 이상 탐지 패턴

**1. 예상치 못한 외부 연결**
```
정상 패턴: 웹서버 컨테이너 → 80/443 포트 수신
이상 패턴: 웹서버 컨테이너 → 외부 IP 4444 포트 연결 (리버스 쉘!)
```

**2. 파일 시스템 드리프트**
```
정상 패턴: 컨테이너 이미지의 읽기 전용 레이어만 접근
이상 패턴: /tmp에 실행 파일 생성 후 실행 (dropper 악성코드)
```

**3. 권한 상승 시도**
```
정상 패턴: 일반 사용자(UID 1000)로 실행
이상 패턴: setuid(0) 호출 또는 /usr/bin/sudo 실행
```

---

## 5. eBPF 네트워크 패킷 필터링

### XDP (eXpress Data Path)

XDP는 네트워크 드라이버 레이어에서 동작하여 패킷을 커널 스택에 올라오기 전에 처리합니다.

```
패킷 도착 → NIC → XDP 프로그램 → 결정
                              ├── XDP_PASS   (커널 스택으로 전달)
                              ├── XDP_DROP   (패킷 드롭)
                              ├── XDP_TX     (동일 인터페이스로 재전송)
                              ├── XDP_REDIRECT (다른 인터페이스로)
                              └── XDP_ABORTED (오류)
```

### eBPF 기반 컨테이너 네트워크 보안

Cilium은 eBPF를 사용하여 Kubernetes 네트워크 정책을 커널 레벨에서 강제 적용합니다:

```yaml
# Cilium Network Policy 예시 (L7 HTTP 정책)
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "api-server-policy"
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/api/v1/.*"
        - method: "POST"
          path: "/api/v1/data"
```

---

## 6. Python: Falco 알림 파서 및 자동 대응 도구

```python
#!/usr/bin/env python3
"""
Falco 알림 파서 및 자동 대응 도구

Falco에서 발생하는 보안 이벤트를 파싱하고,
심각도에 따라 자동으로 대응 조치를 수행합니다.
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError


# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class Priority(Enum):
    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


@dataclass
class FalcoAlert:
    rule: str
    priority: Priority
    output: str
    time: datetime
    output_fields: dict[str, Any] = field(default_factory=dict)
    container_id: str | None = None
    namespace: str | None = None
    pod_name: str | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FalcoAlert":
        """Falco JSON 알림에서 FalcoAlert 객체 생성."""
        try:
            priority = Priority(data.get("priority", "INFORMATIONAL").upper())
        except ValueError:
            priority = Priority.INFORMATIONAL

        output_fields = data.get("output_fields", {})
        return cls(
            rule=data.get("rule", "Unknown"),
            priority=priority,
            output=data.get("output", ""),
            time=datetime.fromisoformat(
                data.get("time", datetime.now().isoformat()).replace("Z", "+00:00")
            ),
            output_fields=output_fields,
            container_id=output_fields.get("container.id"),
            namespace=output_fields.get("k8s.ns.name"),
            pod_name=output_fields.get("k8s.pod.name"),
        )


@dataclass
class ResponseAction:
    action_type: str
    target: str
    success: bool
    message: str
    timestamp: datetime = field(default_factory=datetime.now)


class KubernetesResponder:
    """Kubernetes 자동 대응 클래스."""

    @staticmethod
    def _run_kubectl(args: list[str]) -> tuple[bool, str]:
        """kubectl 명령 실행."""
        try:
            result = subprocess.run(
                ["kubectl"] + args,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            return True, result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return False, e.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "명령 타임아웃"

    def delete_pod(self, pod_name: str, namespace: str) -> ResponseAction:
        """위험한 Pod 삭제."""
        logger.warning(f"Pod 삭제 시도: {namespace}/{pod_name}")
        success, msg = self._run_kubectl(
            ["delete", "pod", pod_name, "-n", namespace, "--grace-period=0"]
        )
        return ResponseAction(
            action_type="delete_pod",
            target=f"{namespace}/{pod_name}",
            success=success,
            message=msg,
        )

    def isolate_pod(self, pod_name: str, namespace: str) -> ResponseAction:
        """Pod를 NetworkPolicy로 격리."""
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"isolate-{pod_name}",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"incident-isolated": "true"}
                },
                "policyTypes": ["Ingress", "Egress"],
            },
        }

        # 라벨 추가
        success1, msg1 = self._run_kubectl([
            "label", "pod", pod_name,
            "-n", namespace,
            "incident-isolated=true",
            "--overwrite",
        ])

        if not success1:
            return ResponseAction(
                action_type="isolate_pod",
                target=f"{namespace}/{pod_name}",
                success=False,
                message=f"라벨 추가 실패: {msg1}",
            )

        # NetworkPolicy 적용
        policy_json = json.dumps(policy)
        try:
            result = subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=policy_json,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            return ResponseAction(
                action_type="isolate_pod",
                target=f"{namespace}/{pod_name}",
                success=True,
                message=f"Pod 격리 완료: {result.stdout.strip()}",
            )
        except subprocess.CalledProcessError as e:
            return ResponseAction(
                action_type="isolate_pod",
                target=f"{namespace}/{pod_name}",
                success=False,
                message=f"NetworkPolicy 적용 실패: {e.stderr.strip()}",
            )

    def capture_pod_state(self, pod_name: str, namespace: str) -> ResponseAction:
        """Pod 상태 및 로그 캡처 (포렌식)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"/tmp/incident_{pod_name}_{timestamp}.json"

        pod_info: dict[str, Any] = {}

        # Pod 설명 정보
        success, pod_desc = self._run_kubectl([
            "get", "pod", pod_name, "-n", namespace, "-o", "json"
        ])
        if success:
            try:
                pod_info["pod_spec"] = json.loads(pod_desc)
            except json.JSONDecodeError:
                pod_info["pod_spec"] = pod_desc

        # Pod 로그
        success, logs = self._run_kubectl([
            "logs", pod_name, "-n", namespace, "--tail=500"
        ])
        if success:
            pod_info["recent_logs"] = logs

        # 이벤트
        success, events = self._run_kubectl([
            "get", "events", "-n", namespace,
            "--field-selector", f"involvedObject.name={pod_name}",
            "-o", "json"
        ])
        if success:
            try:
                pod_info["events"] = json.loads(events)
            except json.JSONDecodeError:
                pod_info["events"] = events

        pod_info["capture_time"] = datetime.now().isoformat()

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(pod_info, f, ensure_ascii=False, indent=2, default=str)
            return ResponseAction(
                action_type="capture_state",
                target=f"{namespace}/{pod_name}",
                success=True,
                message=f"포렌식 데이터 저장: {output_file}",
            )
        except OSError as e:
            return ResponseAction(
                action_type="capture_state",
                target=f"{namespace}/{pod_name}",
                success=False,
                message=f"파일 저장 실패: {e}",
            )


class AlertHandler:
    """Falco 알림 처리 및 대응 조율 클래스."""

    # 자동 대응 규칙 매핑
    RESPONSE_RULES: dict[str, list[str]] = {
        "Terminal Shell in Container": ["capture", "notify"],
        "Container Escape via nsenter": ["capture", "isolate", "notify"],
        "Contact K8s API Server From Container": ["capture", "notify"],
        "Drift Detected (chmod +x)": ["capture", "notify"],
        "Read sensitive file untrusted": ["notify"],
        "Sudo Potential Privilege Escalation": ["capture", "isolate", "notify"],
    }

    # 심각도별 자동 삭제 규칙
    AUTO_DELETE_PRIORITIES = {Priority.EMERGENCY, Priority.ALERT}

    def __init__(
        self,
        slack_webhook: str | None = None,
        auto_respond: bool = False,
    ) -> None:
        self.responder = KubernetesResponder()
        self.slack_webhook = slack_webhook
        self.auto_respond = auto_respond
        self.alert_history: list[FalcoAlert] = []

    def handle_alert(self, alert: FalcoAlert) -> list[ResponseAction]:
        """알림 처리 및 대응 조치 실행."""
        self.alert_history.append(alert)
        actions: list[ResponseAction] = []

        logger.info(
            f"알림 수신: [{alert.priority.value}] {alert.rule} "
            f"| Pod: {alert.pod_name} | NS: {alert.namespace}"
        )

        if not self.auto_respond:
            self._send_slack_notification(alert, actions)
            return actions

        # 자동 대응 실행
        response_actions = self.RESPONSE_RULES.get(alert.rule, ["notify"])

        # 심각도가 높으면 자동 삭제
        if alert.priority in self.AUTO_DELETE_PRIORITIES:
            response_actions = ["capture", "delete", "notify"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            for action_type in response_actions:
                if action_type == "capture" and alert.pod_name and alert.namespace:
                    futures.append(
                        executor.submit(
                            self.responder.capture_pod_state,
                            alert.pod_name,
                            alert.namespace,
                        )
                    )
                elif action_type == "isolate" and alert.pod_name and alert.namespace:
                    futures.append(
                        executor.submit(
                            self.responder.isolate_pod,
                            alert.pod_name,
                            alert.namespace,
                        )
                    )
                elif action_type == "delete" and alert.pod_name and alert.namespace:
                    futures.append(
                        executor.submit(
                            self.responder.delete_pod,
                            alert.pod_name,
                            alert.namespace,
                        )
                    )

            for future in as_completed(futures):
                try:
                    action = future.result()
                    actions.append(action)
                    status = "성공" if action.success else "실패"
                    logger.info(f"대응 조치 {status}: {action.action_type} - {action.message}")
                except Exception as e:
                    logger.error(f"대응 조치 실행 오류: {e}")

        self._send_slack_notification(alert, actions)
        return actions

    def _send_slack_notification(
        self, alert: FalcoAlert, actions: list[ResponseAction]
    ) -> None:
        """Slack 웹훅으로 알림 전송."""
        if not self.slack_webhook:
            return

        priority_emoji = {
            Priority.EMERGENCY: ":rotating_light:",
            Priority.ALERT: ":red_circle:",
            Priority.CRITICAL: ":red_circle:",
            Priority.ERROR: ":orange_circle:",
            Priority.WARNING: ":yellow_circle:",
            Priority.NOTICE: ":blue_circle:",
            Priority.INFORMATIONAL: ":white_circle:",
            Priority.DEBUG: ":white_circle:",
        }
        emoji = priority_emoji.get(alert.priority, ":white_circle:")

        action_text = ""
        if actions:
            action_lines = [
                f"• {a.action_type}: {'성공' if a.success else '실패'} - {a.message}"
                for a in actions
            ]
            action_text = "\n*자동 대응 조치:*\n" + "\n".join(action_lines)

        payload = {
            "text": f"{emoji} *Falco 보안 알림*",
            "attachments": [
                {
                    "color": "danger" if alert.priority in (
                        Priority.CRITICAL, Priority.EMERGENCY, Priority.ALERT
                    ) else "warning",
                    "fields": [
                        {"title": "규칙", "value": alert.rule, "short": True},
                        {"title": "심각도", "value": alert.priority.value, "short": True},
                        {"title": "Pod", "value": alert.pod_name or "N/A", "short": True},
                        {"title": "네임스페이스", "value": alert.namespace or "N/A", "short": True},
                        {"title": "상세", "value": alert.output[:500]},
                    ],
                    "footer": f"시간: {alert.time.strftime('%Y-%m-%d %H:%M:%S')}",
                    "text": action_text,
                }
            ],
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = Request(
                self.slack_webhook,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            urlopen(req, timeout=10)
            logger.info("Slack 알림 전송 성공")
        except URLError as e:
            logger.error(f"Slack 알림 전송 실패: {e}")


class FalcoWebhookServer(BaseHTTPRequestHandler):
    """Falco 웹훅 수신 HTTP 서버."""

    handler: AlertHandler | None = None

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            data = json.loads(raw_body.decode("utf-8"))
            alert = FalcoAlert.from_json(data)

            if self.handler:
                self.handler.handle_alert(alert)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"알림 파싱 오류: {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"status": "error"}')

    def log_message(self, fmt: str, *args: Any) -> None:
        # 기본 HTTP 로그 억제
        pass


def parse_falco_log_file(log_file: str, handler: AlertHandler) -> int:
    """Falco JSON 로그 파일 파싱."""
    processed = 0
    try:
        with open(log_file, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    alert = FalcoAlert.from_json(data)
                    handler.handle_alert(alert)
                    processed += 1
                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug(f"라인 {line_num} 파싱 실패: {e}")
    except FileNotFoundError:
        logger.error(f"파일을 찾을 수 없음: {log_file}")
        return 0
    except OSError as e:
        logger.error(f"파일 읽기 오류: {e}")
        return 0
    return processed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Falco 알림 파서 및 자동 대응 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 웹훅 서버 모드 (Falco에서 HTTP 알림 수신)
  %(prog)s --mode server --port 8080

  # 로그 파일 분석 모드
  %(prog)s --mode file --log-file /var/log/falco.json

  # 자동 대응 활성화 (주의: 실제 Pod 삭제/격리 수행)
  %(prog)s --mode server --auto-respond

  # Slack 알림 포함
  %(prog)s --mode server --slack-webhook https://hooks.slack.com/...
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["server", "file"],
        default="server",
        help="동작 모드 (server: 웹훅 수신, file: 로그 파일 분석)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2802,
        help="웹훅 서버 포트 (기본: 2802)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="웹훅 서버 바인드 주소 (기본: 0.0.0.0)",
    )
    parser.add_argument(
        "--log-file",
        help="분석할 Falco JSON 로그 파일 경로",
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack 웹훅 URL (알림 전송용)",
    )
    parser.add_argument(
        "--auto-respond",
        action="store_true",
        help="자동 대응 활성화 (Pod 격리/삭제 수행, 주의 필요)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="로그 레벨 (기본: INFO)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    handler = AlertHandler(
        slack_webhook=args.slack_webhook,
        auto_respond=args.auto_respond,
    )

    if args.auto_respond:
        logger.warning(
            "자동 대응 모드 활성화됨. 심각한 알림 발생 시 Pod가 자동으로 격리/삭제됩니다."
        )

    if args.mode == "file":
        if not args.log_file:
            logger.error("--log-file 인수가 필요합니다.")
            return 1
        logger.info(f"로그 파일 분석 시작: {args.log_file}")
        count = parse_falco_log_file(args.log_file, handler)
        logger.info(f"분석 완료: {count}개 알림 처리됨")
        logger.info(
            f"요약 - 전체: {len(handler.alert_history)}, "
            f"CRITICAL 이상: {sum(1 for a in handler.alert_history if a.priority in (Priority.CRITICAL, Priority.ALERT, Priority.EMERGENCY))}"
        )
        return 0

    # 웹훅 서버 모드
    FalcoWebhookServer.handler = handler
    server = HTTPServer((args.host, args.port), FalcoWebhookServer)
    logger.info(f"Falco 웹훅 서버 시작: http://{args.host}:{args.port}")
    logger.info("Falco 설정에서 http_output.url을 이 주소로 설정하세요.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("서버 종료 중...")
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 도구 배포 및 사용법

```bash
# Falco와 연동하여 웹훅 서버 실행
python falco_responder.py --mode server --port 8080

# 자동 대응 모드 (주의: 실제 Pod 격리/삭제)
python falco_responder.py --mode server --auto-respond --slack-webhook "$SLACK_WEBHOOK"

# 기존 Falco 로그 파일 분석
python falco_responder.py --mode file --log-file /var/log/falco/falco.json

# Falco 설정에서 웹훅 출력 활성화
# falco.yaml:
# http_output:
#   enabled: true
#   url: "http://localhost:8080"
```

---

## 참고 자료

- [eBPF 공식 문서](https://ebpf.io/)
- [Falco 문서](https://falco.org/docs/)
- [Tetragon GitHub](https://github.com/cilium/tetragon)
- [Tracee GitHub](https://github.com/aquasecurity/tracee)
- [Cilium eBPF 라이브러리](https://github.com/cilium/ebpf)
- [Linux man pages - syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html)

---

<a name="english"></a>

# eBPF Runtime Security

## 1. eBPF Overview

### What is eBPF (Extended Berkeley Packet Filter)?

eBPF is a revolutionary technology that enables sandboxed programs to run inside the Linux kernel. It allows safely observing and modifying kernel behavior without modifying kernel source code or loading kernel modules.

### How eBPF Works

1. **Write eBPF Program**: Written in C or Rust with restricted syntax
2. **LLVM Compilation**: Compiled to eBPF bytecode
3. **Verifier Validation**: Kernel performs safety checks (no infinite loops, memory access validation)
4. **JIT Compilation**: Converted to native machine code
5. **Hook Attachment**: Program connected to kernel events
6. **Map Communication**: Data sharing between kernel and user space

### eBPF Hook Points

| Hook Type | Purpose |
|-----------|---------|
| kprobe/kretprobe | Kernel function entry/return |
| uprobe/uretprobe | User function tracing |
| tracepoint | Static kernel trace points |
| XDP (eXpress Data Path) | Ultra-fast network packet processing |
| TC (Traffic Control) | Network traffic control |
| LSM | Linux Security Module security policies |
| Cgroup | Container resource control |

---

## 2. Runtime Security Tool Comparison

### Falco (CNCF Graduated Project)

Developed by Sysdig and donated to CNCF. Detects abnormal container runtime behavior based on system calls using YAML-based rule language. Supports multiple output channels (stdout, Slack, PagerDuty, Kafka) and integrates with Kubernetes events.

### Tetragon (Cilium Project)

eBPF-based security tool by Isovalent. Processes events directly at the kernel level (can block at the kernel layer), has low overhead, defines policies using TracingPolicy CRD, and when integrated with Cilium provides powerful network security.

### Tracee (Aqua Security)

eBPF-based runtime security and forensics tool by Aqua Security. Tracks 400+ events, uses OPA (Open Policy Agent) based policies, integrates container image analysis, written in Go.

| Criterion | Falco | Tetragon | Tracee |
|-----------|-------|----------|--------|
| Technology | eBPF/kernel module | eBPF | eBPF |
| Real-time Blocking | Not supported | Supported | Not supported |
| Rule Language | YAML | CRD | Rego/OPA |
| K8s Integration | Excellent | Excellent | Good |
| Performance Overhead | Medium | Low | Low |

---

## 3. Falco Rule Writing and Deployment

### Rule Structure

```yaml
- rule: rule_name
  desc: rule description
  condition: event_filter_condition
  output: alert_message_format
  priority: CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|DEBUG
  tags: [tag1, tag2]
```

### Key Falco Rules

1. **Terminal Shell in Container**: Detects shell execution within running containers — priority NOTICE, tags [container, shell, T1059]
2. **Read Sensitive File Untrusted**: Detects untrusted process accessing /etc/passwd, /etc/shadow, etc. — priority WARNING, tags [filesystem, T1552]
3. **Drift Detected (chmod +x)**: Detects new executable creation in containers — priority ERROR, tags [container, drift, T1222]
4. **Container Escape via nsenter**: Detects nsenter-based container escape attempts — priority CRITICAL, tags [container, escape, T1611]
5. **Contact K8s API Server From Container**: Detects direct K8s API server access from containers — priority WARNING, tags [k8s, api, T1552.007]

---

## 4. Syscall-Based Anomaly Detection

### Key Monitored Syscalls

- **Process**: execve/execveat (process execution), fork/clone (process creation), ptrace (debugger)
- **Filesystem**: open/openat (file open), write (file write), chmod/chown (permission change)
- **Network**: connect (outbound), accept (inbound), bind (port binding)
- **Privileges**: setuid/setgid (user/group change), capset (capability setting), chroot

### Anomaly Detection Patterns

1. **Unexpected External Connection**: Web server container connecting outbound to port 4444 (reverse shell)
2. **Filesystem Drift**: Creating and executing a file in /tmp (dropper malware)
3. **Privilege Escalation Attempt**: setuid(0) call or /usr/bin/sudo execution

---

## 5. eBPF Network Packet Filtering

### XDP (eXpress Data Path)

XDP operates at the network driver layer, processing packets before they reach the kernel stack:
- **XDP_PASS**: Forward to kernel stack
- **XDP_DROP**: Drop packet
- **XDP_TX**: Retransmit on same interface
- **XDP_REDIRECT**: Forward to different interface

Cilium uses eBPF to enforce Kubernetes network policies at the kernel level, supporting L7 HTTP policy enforcement with method and path matching.

---

## 6. Python Tool: Falco Alert Parser and Auto-Response

A webhook server and log file parser for Falco security events that automatically responds based on severity. Features:

- **Alert Handler**: Maps rules to response actions (capture, isolate, notify, delete)
- **Kubernetes Responder**: Executes kubectl commands to delete pods, isolate with NetworkPolicy, or capture pod state/logs for forensics
- **Slack Integration**: Sends formatted notifications with alert details and response action results
- **Auto-Delete**: Automatically deletes pods for EMERGENCY/ALERT priority events when auto-respond mode is enabled

### Deployment

```bash
# Webhook server mode
python falco_responder.py --mode server --port 8080

# Auto-respond mode (caution: actual Pod isolation/deletion)
python falco_responder.py --mode server --auto-respond --slack-webhook "$SLACK_WEBHOOK"

# Analyze existing Falco log file
python falco_responder.py --mode file --log-file /var/log/falco/falco.json
```

---

## References

- [eBPF Official Documentation](https://ebpf.io/)
- [Falco Documentation](https://falco.org/docs/)
- [Tetragon GitHub](https://github.com/cilium/tetragon)
- [Tracee GitHub](https://github.com/aquasecurity/tracee)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux man pages - syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html)
