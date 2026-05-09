# 마이크로세그멘테이션과 네트워크 보안

## 1. 마이크로세그멘테이션 개념

### 1.1 정의

마이크로세그멘테이션(Microsegmentation)은 데이터센터와 클라우드 환경을 작은 보안 구역으로 분리하여
각 워크로드, 애플리케이션, 서비스 간 트래픽을 세밀하게 제어하는 기술이다.

기존 VLAN 기반 세그멘테이션이 네트워크 레이어에서만 동작하는 것과 달리,
마이크로세그멘테이션은 워크로드 수준에서 정책을 적용한다.

```
전통적 세그멘테이션:
┌──────────────────────────────────────┐
│  내부 네트워크 (VLAN 10)              │
│  ┌──────┐  ┌──────┐  ┌──────┐       │
│  │ Web  │  │ App  │  │  DB  │       │
│  │서버  │◀▶│서버  │◀▶│서버  │       │
│  └──────┘  └──────┘  └──────┘       │
│   같은 VLAN = 자유로운 통신           │
└──────────────────────────────────────┘

마이크로세그멘테이션:
┌──────────────────────────────────────┐
│  ┌────────┐   허용된 포트만   ┌─────┐│
│  │  Web   │──────────────────▶│ App ││
│  │ (80,443│   80→8080만 허용  │서버 ││
│  └────────┘                   └──┬──┘│
│                                  │   │
│                            3306만 허용│
│                                  │   │
│                              ┌───▼──┐│
│                              │  DB  ││
│                              └──────┘│
└──────────────────────────────────────┘
```

### 1.2 마이크로세그멘테이션의 장점

| 장점 | 설명 |
|------|------|
| 측면 이동 차단 | 공격자가 한 서버 침해 후 다른 서버로 이동 불가 |
| 세밀한 접근 제어 | 포트, 프로토콜, IP 단위 정책 |
| 가시성 향상 | East-West 트래픽 완전 가시화 |
| 컴플라이언스 | PCI DSS, HIPAA 격리 요구사항 충족 |
| 폭발 반경 최소화 | 침해 발생 시 영향 범위 제한 |

---

## 2. 주요 마이크로세그멘테이션 기술

### 2.1 VMware NSX

VMware NSX는 하이퍼바이저 레이어에서 동작하는 네트워크 가상화 플랫폼이다.

**핵심 기능:**
```
분산 방화벽 (Distributed Firewall, DFW):
- 각 VM의 vNIC 수준에서 동작
- 하이퍼바이저 커널에 내장 → 성능 저하 최소화
- 단방향/양방향 규칙 지원
- 애플리케이션 레이어 인식 (Layer 7)

마이크로세그멘테이션 정책 예시:
Rule 1: Web-Tier → App-Tier, TCP:8080, ALLOW
Rule 2: App-Tier → DB-Tier, TCP:3306, ALLOW
Rule 3: ANY → DB-Tier, ANY, DENY (기본 거부)
```

**NSX-T 아키텍처:**
```
┌─────────────────────────────────┐
│        NSX Manager (중앙 관리)   │
└──────────────┬──────────────────┘
               │
        ┌──────▼──────┐
        │ NSX Controller│
        └──────┬───────┘
               │
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│ESXi-1 │ │ESXi-2 │ │ESXi-3 │
│ DFW   │ │ DFW   │ │ DFW   │
│ VM1   │ │ VM3   │ │ VM5   │
│ VM2   │ │ VM4   │ │ VM6   │
└───────┘ └───────┘ └───────┘
```

### 2.2 Calico (Kubernetes)

Calico는 Kubernetes 환경에서 가장 널리 사용되는 네트워크 정책 솔루션이다.

**네트워크 정책 모드:**
- **Standard Kubernetes NetworkPolicy**: 기본 Pod 네트워크 정책
- **Calico GlobalNetworkPolicy**: 클러스터 전체 정책
- **Calico NetworkSet**: 외부 IP/CIDR 그룹 관리
- **eBPF 데이터플레인**: 커널 레벨 고성능 처리

**Calico NetworkPolicy 예시:**
```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-web-to-app
  namespace: production
spec:
  selector: app == 'app-server'
  types:
    - Ingress
    - Egress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app == 'web-server'
      destination:
        ports:
          - 8080
  egress:
    - action: Allow
      protocol: TCP
      destination:
        selector: app == 'db-server'
        ports:
          - 5432
---
# 기본 거부 정책
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types:
    - Ingress
    - Egress
  ingress:
    - action: Deny
  egress:
    - action: Deny
```

### 2.3 Cilium

Cilium은 eBPF(extended Berkeley Packet Filter) 기반의 차세대 Kubernetes 네트워크 솔루션이다.

**eBPF의 장점:**
```
기존 방식: 커널 모듈 → 시스템 콜 오버헤드
eBPF:      커널 내 안전한 프로그램 실행 → 오버헤드 최소

성능 비교:
iptables 기반: 1M 규칙 시 선형 검색 O(n)
eBPF 기반:     해시맵 룩업 O(1)
```

**Cilium 주요 기능:**
```
- L3/L4 네트워크 정책 (IP, 포트)
- L7 정책 (HTTP, Kafka, gRPC, DNS)
- 서비스 메시 없이 mTLS 지원
- Hubble: 실시간 네트워크 가시성
- BGP 지원: 네이티브 라우팅
- Cluster Mesh: 멀티 클러스터 연결
```

**Cilium L7 정책 예시 (HTTP):**
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-api-access
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web-frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/public.*"
              - method: "POST"
                path: "/api/v1/data"
                headers:
                  - "X-API-Key: .*"
```

---

## 3. East-West 트래픽 제어

### 3.1 East-West vs North-South 트래픽

```
North-South 트래픽 (기존 보안 초점):
[인터넷] ←→ [경계 방화벽] ←→ [내부 네트워크]
                                     ↑ ↓

East-West 트래픽 (마이크로세그멘테이션 초점):
내부 네트워크 서버간 통신:
[서버A] ←→ [서버B] ←→ [서버C]
```

**통계적 사실:**
- 현대 기업 트래픽의 75-80%가 East-West
- 침해 후 측면 이동은 100% East-West 트래픽 활용
- 기존 경계 방화벽은 East-West 트래픽을 볼 수 없음

### 3.2 서비스 메시 (Service Mesh)

서비스 메시는 마이크로서비스 간 통신을 투명하게 제어한다.

**Istio 아키텍처:**
```
컨트롤 플레인 (Control Plane):
┌─────────────────────────────────┐
│  istiod                         │
│  ├── Pilot (트래픽 관리)         │
│  ├── Citadel (인증서 관리)       │
│  └── Galley (설정 검증)         │
└─────────────────────────────────┘
              │ xDS API
데이터 플레인 (Data Plane):
┌─────────────────────────────────┐
│  Pod A                Pod B     │
│  ┌────┐ ┌─────────┐  ┌────┐   │
│  │App │◀│ Envoy   │  │App │   │
│  │    │ │ Sidecar │  │    │   │
│  └────┘ └─────────┘  └────┘   │
└─────────────────────────────────┘
```

**Istio 트래픽 제어 기능:**
```yaml
# mTLS 전체 강제 적용
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# 서비스 간 권한 부여
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend-to-api
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/frontend-sa"
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/*"]
```

---

## 4. Software-Defined Perimeter (SDP)

### 4.1 SDP 개념

SDP는 Cloud Security Alliance(CSA)가 정의한 네트워크 보안 아키텍처로,
인프라를 인터넷에서 숨기고 인가된 사용자만 접근하게 한다.

**핵심 원칙:**
- 인증 전까지 서버/서비스 존재 자체가 보이지 않음 (Dark Cloud)
- 단일 패킷 인증 (Single Packet Authorization, SPA)
- 동적으로 생성되는 일대일 네트워크 연결
- mTLS 기반 암호화 통신

### 4.2 SDP 작동 원리

```
1. SPA (Single Packet Authorization):
   [클라이언트] → SPA 패킷 전송 (암호화된 인증 정보)
   [SDP 컨트롤러] → SPA 패킷 검증
   [방화벽] → 포트 hidden (기본 DROP, 보이지 않음)

2. 인증 성공 시:
   [컨트롤러] → 임시 방화벽 규칙 생성
   [컨트롤러] → 클라이언트 IP만 허용
   [클라이언트] ←→ [게이트웨이] mTLS 터널 수립

3. 세션 종료:
   [컨트롤러] → 방화벽 규칙 삭제
   [서버] → 다시 인터넷에서 보이지 않음
```

**SPA 패킷 구조:**
```
SPA 패킷 (단일 UDP 패킷):
├── 타임스탬프 (재전송 공격 방지)
├── 사용자 ID
├── 요청한 서비스
├── HMAC 서명 (사전 공유 키로)
└── 암호화 (AES-256)
```

### 4.3 오픈소스 SDP 구현: fwknop

```bash
# 서버 설정 (/etc/fwknop/fwknopd.conf)
PCAP_INTF eth0;
ENABLE_IPT_FORWARDING Y;

# 클라이언트에서 SPA 패킷 전송
fwknop -A tcp/22 -a <YOUR_IP> -D server.example.com \
    --key-gen --use-hmac

# 성공 시 SSH 접속 (30초 내)
ssh user@server.example.com
```

---

## 5. ZTNA vs VPN

### 5.1 전통적 VPN의 한계

```
VPN 모델:
[원격 사용자] → [VPN 터널] → [내부 네트워크 전체]
                               └── 모든 서버 접근 가능
                               └── 측면 이동 위험
                               └── 과도한 접근 권한
```

**VPN 주요 문제점:**
1. **네트워크 레벨 접근**: 특정 앱이 아닌 전체 네트워크 접근
2. **성능 병목**: 모든 트래픽이 VPN 게이트웨이 통과
3. **크리덴셜 탈취**: VPN 계정 탈취 = 내부망 전체 접근
4. **가시성 부족**: 접속 후 활동 모니터링 어려움
5. **스플릿 터널링 위험**: 분리 설정 시 보안 구멍 발생

### 5.2 ZTNA (Zero Trust Network Access)

```
ZTNA 모델:
[원격 사용자] → [ZTNA 컨트롤러]
                      │
              신원 + 기기 + 컨텍스트 검증
                      │
              허가된 앱에만 연결
                      │
         [앱 A만]  [앱 B만]  [앱 C만]
```

**ZTNA 작동 방식:**

**에이전트 기반 ZTNA (Agent-based):**
```
1. 기기에 ZTNA 에이전트 설치
2. 에이전트 → 컨트롤러에 신원 + 기기 상태 전송
3. 컨트롤러 → 정책 평가 → 접근 허가
4. 에이전트 → 앱별 암호화 터널 수립
5. 사용자 → 직접 앱 접근 (네트워크는 보이지 않음)
```

**에이전트리스 ZTNA (Agentless):**
```
1. 사용자 → 브라우저로 접근
2. ZTNA 프록시 → IdP 인증 리디렉션
3. 인증 완료 → 프록시가 앱 대신 응답
4. 앱은 인터넷에 직접 노출되지 않음
```

### 5.3 ZTNA vs VPN 비교

| 특성 | 전통 VPN | ZTNA |
|------|----------|------|
| 접근 단위 | 네트워크 전체 | 개별 애플리케이션 |
| 인증 | 비밀번호/인증서 | 신원+기기+컨텍스트 |
| 가시성 | 제한적 | 세밀한 세션 로그 |
| 성능 | 중앙 집중 병목 | 분산 처리 |
| 측면 이동 | 허용 | 차단 |
| 설치 | 복잡 (서버 필요) | 클라우드 기반 |
| 레거시 앱 지원 | 좋음 | 제한적 |
| 사용자 경험 | 보통 | 우수 (투명한 접근) |

---

## 6. 애플리케이션 레이어 접근 제어

### 6.1 API 게이트웨이

```
API 게이트웨이 기능:
├── 인증/인가 (JWT, OAuth2 토큰 검증)
├── Rate Limiting (과도한 요청 차단)
├── 입력 검증 (Payload 검사)
├── 트래픽 로깅 (감사 추적)
├── API 버전 관리
└── 서킷 브레이커 (장애 격리)

구현 예시:
[클라이언트] → [API 게이트웨이 (Kong/AWS API GW)] → [백엔드 서비스]
                    │
              토큰 검증 (IdP)
              정책 적용 (OPA)
              로깅 (SIEM)
```

### 6.2 OPA (Open Policy Agent)

OPA는 통합 정책 엔진으로 코드로 정책을 정의한다.

```rego
# OPA Rego 정책 예시: API 접근 제어
package authz

import future.keywords.if
import future.keywords.in

default allow := false

# 기본 허용 조건
allow if {
    # 사용자가 올바른 역할을 가짐
    user_has_role(input.user, required_role)

    # 기기가 규정을 준수함
    input.device.is_compliant == true

    # MFA가 검증됨
    input.user.mfa_verified == true

    # 업무 시간 내 접근
    is_business_hours
}

# 역할 확인
user_has_role(user, role) if {
    role in user.roles
}

# 업무 시간 확인 (KST 9-18시, 평일)
is_business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 18
    day := time.weekday(time.now_ns())
    day != "Saturday"
    day != "Sunday"
}

# 필요 역할 (리소스 경로 기반)
required_role := "admin" if {
    startswith(input.resource.path, "/admin/")
}

required_role := "analyst" if {
    startswith(input.resource.path, "/api/analytics/")
}

required_role := "user" if {
    startswith(input.resource.path, "/api/")
}
```

---

## 7. 실전 Python 도구: 네트워크 세그멘테이션 정책 검증

```python
#!/usr/bin/env python3
"""
네트워크 세그멘테이션 정책 검증 도구

정의된 Zero Trust 세그멘테이션 정책에 따라 허용/거부 트래픽을 검증합니다.

사용법:
    python segmentation_validator.py --policy policy.yaml --test-cases tests.json
    python segmentation_validator.py --policy policy.yaml --interactive
    python segmentation_validator.py --policy policy.yaml --scan-topology
    python segmentation_validator.py --generate-template
"""

import argparse
import json
import sys
import logging
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from enum import Enum

# PyYAML 의존성 (없으면 JSON 폴백)
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class Action(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG = "LOG"


@dataclass
class Segment:
    """네트워크 세그먼트 정의"""
    name: str
    subnets: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class PolicyRule:
    """세그멘테이션 정책 규칙"""
    name: str
    source_segment: str
    destination_segment: str
    protocol: str = "tcp"          # tcp, udp, icmp, any
    ports: list[int] = field(default_factory=list)
    action: Action = Action.DENY
    description: str = ""
    priority: int = 1000


@dataclass
class SegmentationPolicy:
    """전체 세그멘테이션 정책"""
    name: str = "default"
    version: str = "1.0"
    default_action: Action = Action.DENY
    segments: list[Segment] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass
class TrafficFlow:
    """검증할 트래픽 흐름"""
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    description: str = ""


@dataclass
class ValidationResult:
    """정책 검증 결과"""
    flow: TrafficFlow
    expected_action: Action | None = None
    actual_action: Action = Action.DENY
    matched_rule: str | None = None
    passed: bool = False
    reason: str = ""


@dataclass
class ValidationReport:
    """전체 검증 보고서"""
    policy_name: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    results: list[ValidationResult] = field(default_factory=list)
    policy_issues: list[str] = field(default_factory=list)


class PolicyEngine:
    """세그멘테이션 정책 평가 엔진"""

    def __init__(self, policy: SegmentationPolicy):
        self.policy = policy
        self._segment_map: dict[str, Segment] = {
            seg.name: seg for seg in policy.segments
        }
        self._sorted_rules = sorted(policy.rules, key=lambda r: r.priority)

    def find_segment_for_ip(self, ip: str) -> Segment | None:
        """IP 주소가 속한 세그먼트 찾기"""
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"유효하지 않은 IP 주소: {ip}")
            return None

        for segment in self.policy.segments:
            for subnet_str in segment.subnets:
                try:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                    if target in network:
                        return segment
                except ValueError:
                    continue

        return None

    def evaluate_flow(self, flow: TrafficFlow) -> tuple[Action, str]:
        """트래픽 흐름 정책 평가"""
        src_segment = self.find_segment_for_ip(flow.source_ip)
        dst_segment = self.find_segment_for_ip(flow.destination_ip)

        if src_segment is None:
            return Action.DENY, f"출발지 IP({flow.source_ip})가 정의된 세그먼트에 없음"

        if dst_segment is None:
            return Action.DENY, f"목적지 IP({flow.destination_ip})가 정의된 세그먼트에 없음"

        # 같은 세그먼트 내 통신
        if src_segment.name == dst_segment.name:
            return Action.ALLOW, f"같은 세그먼트 내 통신: {src_segment.name}"

        # 규칙 순차 평가 (우선순위 낮은 숫자 = 높은 우선순위)
        for rule in self._sorted_rules:
            if self._rule_matches(rule, src_segment, dst_segment, flow):
                return rule.action, f"규칙 '{rule.name}' 매칭"

        # 기본 정책 적용
        return self.policy.default_action, f"기본 정책: {self.policy.default_action.value}"

    def _rule_matches(
        self,
        rule: PolicyRule,
        src_segment: Segment,
        dst_segment: Segment,
        flow: TrafficFlow,
    ) -> bool:
        """규칙 매칭 여부 확인"""
        # 세그먼트 매칭
        if rule.source_segment != "*" and rule.source_segment != src_segment.name:
            return False
        if rule.destination_segment != "*" and rule.destination_segment != dst_segment.name:
            return False

        # 프로토콜 매칭
        if rule.protocol != "any" and rule.protocol.lower() != flow.protocol.lower():
            return False

        # 포트 매칭 (비어있으면 모든 포트)
        if rule.ports and flow.port not in rule.ports:
            return False

        return True

    def validate_policy_consistency(self) -> list[str]:
        """정책 일관성 검증"""
        issues: list[str] = []

        # 중복 규칙 감지
        seen_rules: set[tuple[str, str, str]] = set()
        for rule in self._sorted_rules:
            key = (rule.source_segment, rule.destination_segment, rule.protocol)
            if key in seen_rules:
                issues.append(
                    f"중복 규칙 가능성: {rule.source_segment} → {rule.destination_segment} "
                    f"({rule.protocol}) - 규칙: '{rule.name}'"
                )
            seen_rules.add(key)

        # 세그먼트 참조 무결성
        segment_names = {seg.name for seg in self.policy.segments}
        for rule in self.policy.rules:
            if rule.source_segment != "*" and rule.source_segment not in segment_names:
                issues.append(f"규칙 '{rule.name}': 존재하지 않는 소스 세그먼트 '{rule.source_segment}'")
            if rule.destination_segment != "*" and rule.destination_segment not in segment_names:
                issues.append(
                    f"규칙 '{rule.name}': 존재하지 않는 대상 세그먼트 '{rule.destination_segment}'"
                )

        # 서브넷 중복 감지
        all_networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for seg in self.policy.segments:
            for subnet_str in seg.subnets:
                try:
                    net = ipaddress.ip_network(subnet_str, strict=False)
                    for existing_name, existing_net in all_networks:
                        if net.overlaps(existing_net):
                            issues.append(
                                f"서브넷 중복: {seg.name}({subnet_str}) 와 "
                                f"{existing_name}({existing_net})"
                            )
                    all_networks.append((seg.name, net))
                except ValueError:
                    issues.append(f"잘못된 서브넷 형식: {seg.name} - {subnet_str}")

        return issues


class PolicyLoader:
    """정책 파일 로더"""

    @staticmethod
    def load_from_dict(data: dict[str, Any]) -> SegmentationPolicy:
        """딕셔너리에서 정책 로드"""
        policy = SegmentationPolicy(
            name=data.get("name", "default"),
            version=data.get("version", "1.0"),
            default_action=Action(data.get("default_action", "DENY")),
        )

        for seg_data in data.get("segments", []):
            policy.segments.append(Segment(
                name=seg_data["name"],
                subnets=seg_data.get("subnets", []),
                labels=seg_data.get("labels", {}),
                description=seg_data.get("description", ""),
            ))

        for rule_data in data.get("rules", []):
            action_str = rule_data.get("action", "DENY")
            policy.rules.append(PolicyRule(
                name=rule_data["name"],
                source_segment=rule_data["source_segment"],
                destination_segment=rule_data["destination_segment"],
                protocol=rule_data.get("protocol", "tcp"),
                ports=rule_data.get("ports", []),
                action=Action(action_str),
                description=rule_data.get("description", ""),
                priority=rule_data.get("priority", 1000),
            ))

        return policy

    @staticmethod
    def load_from_file(file_path: str) -> SegmentationPolicy:
        """파일에서 정책 로드 (JSON 또는 YAML)"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"정책 파일을 찾을 수 없습니다: {file_path}")

        with open(path, encoding="utf-8") as f:
            if path.suffix in (".yaml", ".yml") and HAS_YAML:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        return PolicyLoader.load_from_dict(data)


def generate_sample_policy() -> dict[str, Any]:
    """샘플 정책 템플릿 생성"""
    return {
        "name": "zero-trust-segmentation-policy",
        "version": "1.0",
        "default_action": "DENY",
        "segments": [
            {
                "name": "web-tier",
                "subnets": ["10.0.1.0/24"],
                "description": "웹 서버 계층",
                "labels": {"tier": "web", "env": "production"},
            },
            {
                "name": "app-tier",
                "subnets": ["10.0.2.0/24"],
                "description": "애플리케이션 서버 계층",
                "labels": {"tier": "app", "env": "production"},
            },
            {
                "name": "db-tier",
                "subnets": ["10.0.3.0/24"],
                "description": "데이터베이스 계층",
                "labels": {"tier": "db", "env": "production"},
            },
            {
                "name": "management",
                "subnets": ["10.0.100.0/24"],
                "description": "관리자 네트워크",
                "labels": {"tier": "mgmt"},
            },
        ],
        "rules": [
            {
                "name": "allow-web-to-app",
                "source_segment": "web-tier",
                "destination_segment": "app-tier",
                "protocol": "tcp",
                "ports": [8080, 8443],
                "action": "ALLOW",
                "priority": 100,
                "description": "웹에서 앱 서버로의 HTTP/HTTPS 허용",
            },
            {
                "name": "allow-app-to-db",
                "source_segment": "app-tier",
                "destination_segment": "db-tier",
                "protocol": "tcp",
                "ports": [5432, 3306],
                "action": "ALLOW",
                "priority": 100,
                "description": "앱에서 DB로의 데이터베이스 포트 허용",
            },
            {
                "name": "allow-mgmt-all",
                "source_segment": "management",
                "destination_segment": "*",
                "protocol": "any",
                "ports": [],
                "action": "ALLOW",
                "priority": 50,
                "description": "관리자 네트워크에서 모든 세그먼트 접근 허용",
            },
            {
                "name": "deny-web-to-db",
                "source_segment": "web-tier",
                "destination_segment": "db-tier",
                "protocol": "any",
                "ports": [],
                "action": "DENY",
                "priority": 200,
                "description": "웹에서 DB 직접 접근 차단",
            },
        ],
    }


def run_validation_tests(
    engine: PolicyEngine,
    test_cases: list[dict[str, Any]],
    max_workers: int = 4,
) -> ValidationReport:
    """병렬 정책 검증 테스트 실행"""
    report = ValidationReport(policy_name=engine.policy.name)
    report.policy_issues = engine.validate_policy_consistency()

    def validate_single(tc: dict[str, Any]) -> ValidationResult:
        flow = TrafficFlow(
            source_ip=tc["source_ip"],
            destination_ip=tc["destination_ip"],
            protocol=tc.get("protocol", "tcp"),
            port=tc.get("port", 80),
            description=tc.get("description", ""),
        )
        expected = Action(tc["expected"]) if "expected" in tc else None
        actual_action, reason = engine.evaluate_flow(flow)

        passed = expected is None or actual_action == expected

        return ValidationResult(
            flow=flow,
            expected_action=expected,
            actual_action=actual_action,
            matched_rule=reason,
            passed=passed,
            reason=reason,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(validate_single, tc): tc for tc in test_cases}

        for future in as_completed(futures):
            result = future.result()
            report.results.append(result)
            report.total_tests += 1

            if result.passed:
                report.passed += 1
            else:
                report.failed += 1

    return report


def print_report(report: ValidationReport) -> None:
    """검증 보고서 출력"""
    print("\n" + "=" * 65)
    print(f"세그멘테이션 정책 검증 보고서: {report.policy_name}")
    print("=" * 65)
    print(f"검증 시간  : {report.timestamp}")
    print(f"총 테스트  : {report.total_tests}")
    print(f"통과       : {report.passed}")
    print(f"실패       : {report.failed}")

    if report.policy_issues:
        print(f"\n정책 일관성 문제 ({len(report.policy_issues)}개):")
        for issue in report.policy_issues:
            print(f"  [!] {issue}")

    if report.failed > 0:
        print(f"\n실패한 테스트 ({report.failed}개):")
        for r in report.results:
            if not r.passed:
                print(
                    f"  FAIL: {r.flow.source_ip} → {r.flow.destination_ip} "
                    f":{r.flow.port}/{r.flow.protocol}"
                )
                print(f"        예상: {r.expected_action}, 실제: {r.actual_action}")
                print(f"        이유: {r.reason}")

    print("\n모든 테스트 결과:")
    for r in sorted(report.results, key=lambda x: x.flow.source_ip):
        status = "PASS" if r.passed else "FAIL"
        print(
            f"  [{status}] {r.flow.source_ip} → {r.flow.destination_ip} "
            f":{r.flow.port}/{r.flow.protocol} → {r.actual_action.value}"
        )

    print("=" * 65)


def run_interactive_mode(engine: PolicyEngine) -> None:
    """대화형 정책 검증 모드"""
    print("\n=== 세그멘테이션 정책 대화형 검증 ===")
    print(f"정책: {engine.policy.name}")
    print(f"세그먼트: {', '.join(s.name for s in engine.policy.segments)}")
    print("종료: Ctrl+C\n")

    while True:
        try:
            src = input("출발지 IP: ").strip()
            dst = input("목적지 IP: ").strip()
            proto = input("프로토콜 (tcp/udp/icmp) [tcp]: ").strip() or "tcp"
            port_str = input("목적지 포트 [80]: ").strip() or "80"

            try:
                port = int(port_str)
            except ValueError:
                print("유효한 포트 번호를 입력하세요.\n")
                continue

            flow = TrafficFlow(source_ip=src, destination_ip=dst, protocol=proto, port=port)
            action, reason = engine.evaluate_flow(flow)

            print(f"\n결과: {action.value}")
            print(f"이유: {reason}\n")

        except KeyboardInterrupt:
            print("\n종료합니다.")
            break
        except Exception as e:
            print(f"오류: {e}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="네트워크 세그멘테이션 정책 검증 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 정책 파일로 테스트 케이스 검증
  python segmentation_validator.py --policy policy.json --test-cases tests.json

  # 대화형 모드
  python segmentation_validator.py --policy policy.json --interactive

  # 샘플 정책 템플릿 생성
  python segmentation_validator.py --generate-template

  # 결과를 JSON으로 저장
  python segmentation_validator.py --policy policy.json --test-cases tests.json --output report.json
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--test-cases", metavar="FILE", help="테스트 케이스 JSON 파일")
    mode.add_argument("--interactive", action="store_true", help="대화형 검증 모드")
    mode.add_argument("--generate-template", action="store_true", help="샘플 정책 템플릿 출력")

    parser.add_argument("--policy", metavar="FILE", help="정책 파일 (JSON/YAML)")
    parser.add_argument("--output", metavar="FILE", help="보고서 저장 파일")
    parser.add_argument("--workers", type=int, default=4, help="병렬 워커 수 (기본: 4)")
    parser.add_argument("--verbose", action="store_true", help="상세 로그 출력")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.generate_template:
        template = generate_sample_policy()
        print(json.dumps(template, ensure_ascii=False, indent=2))
        return

    if not args.policy:
        logger.error("--policy 옵션이 필요합니다.")
        sys.exit(1)

    try:
        policy = PolicyLoader.load_from_file(args.policy)
    except Exception as e:
        logger.error(f"정책 로드 실패: {e}")
        sys.exit(1)

    engine = PolicyEngine(policy)
    logger.info(f"정책 로드 완료: {policy.name} (세그먼트: {len(policy.segments)}, 규칙: {len(policy.rules)})")

    if args.interactive:
        run_interactive_mode(engine)
        return

    # 테스트 케이스 로드
    test_path = Path(args.test_cases)
    if not test_path.exists():
        logger.error(f"테스트 파일 없음: {args.test_cases}")
        sys.exit(1)

    with open(test_path, encoding="utf-8") as f:
        test_cases = json.load(f)

    if not isinstance(test_cases, list):
        test_cases = [test_cases]

    logger.info(f"{len(test_cases)}개 테스트 케이스 검증 시작...")
    report = run_validation_tests(engine, test_cases, args.workers)
    print_report(report)

    if args.output:
        output_data = {
            "report": {
                "policy_name": report.policy_name,
                "timestamp": report.timestamp,
                "total_tests": report.total_tests,
                "passed": report.passed,
                "failed": report.failed,
                "policy_issues": report.policy_issues,
                "results": [asdict(r) for r in report.results],
            }
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        logger.info(f"보고서 저장: {args.output}")

    sys.exit(0 if report.failed == 0 else 1)


if __name__ == "__main__":
    main()
```

---

## 8. 마이크로세그멘테이션 설계 원칙

### 8.1 계층별 접근법

```
1단계: 환경 분리 (가장 쉬움)
   Production | Staging | Development | DMZ

2단계: 애플리케이션 계층 분리
   Web-Tier | App-Tier | DB-Tier

3단계: 워크로드 분리 (마이크로세그멘테이션)
   각 서비스/Pod/VM 수준 정책

4단계: 프로세스 수준 분리 (최고 수준)
   Host-based 방화벽, eBPF
```

### 8.2 Zero Trust 세그멘테이션 원칙

1. **기본 거부 (Default Deny)**: 명시적으로 허용되지 않은 모든 트래픽 차단
2. **최소 연결 (Least Connection)**: 필요한 포트/프로토콜만 허용
3. **양방향 정책**: 허용 방향 명시 (Ingress/Egress 구분)
4. **지속적 검증**: 정책이 실제로 적용되는지 주기적 검증
5. **변경 관리**: 모든 정책 변경의 감사 추적

---

## 9. 참고 자료

- Cloud Security Alliance: Software Defined Perimeter Specification v2.0
- NIST SP 800-207: Zero Trust Architecture
- VMware NSX-T Data Center Administration Guide
- Calico: Network Policy Documentation
- Cilium: Network Policy Concepts
- Istio: Security Best Practices
- fwknop: Single Packet Authorization
- CISA: Zero Trust Architecture Technical Reference Model

---

*최종 업데이트: 2024년*
