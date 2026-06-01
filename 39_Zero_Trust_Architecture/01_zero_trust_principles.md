> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Zero Trust 아키텍처 원칙

## 1. Zero Trust란 무엇인가

Zero Trust는 "절대 신뢰 없음, 항상 검증(Never Trust, Always Verify)"을 핵심 철학으로 삼는 보안 패러다임이다.
전통적인 경계 기반 보안 모델이 내부 네트워크를 신뢰하는 것과 달리, Zero Trust는 위치(내부/외부)에 관계없이
모든 접근 요청을 적대적인 것으로 간주하고 지속적으로 검증한다.

### 핵심 철학

| 원칙 | 설명 |
|------|------|
| 절대 신뢰 없음 | 내부 네트워크에 있다고 해서 신뢰하지 않음 |
| 항상 검증 | 모든 요청은 신원, 기기, 컨텍스트 기반으로 검증 |
| 최소 권한 | 필요한 최소한의 리소스에만 접근 허용 |
| 침해 가정 | 이미 침해된 것으로 가정하고 설계 |
| 명시적 검증 | 가용한 모든 데이터 포인트를 사용해 검증 |

---

## 2. 기존 경계 보안 모델의 한계

### 2.1 성 해자(Castle-and-Moat) 모델

전통적인 네트워크 보안은 방화벽, DMZ, VPN으로 내부 네트워크를 보호하는 방식이다.
한번 내부에 들어오면 광범위한 신뢰를 받는다.

```
[인터넷] → [방화벽] → [내부 네트워크: 모든 것이 신뢰됨]
```

### 2.2 경계 모델의 주요 한계점

**1) 내부자 위협 (Insider Threat)**
- 내부 직원의 악의적 행위
- 계정 탈취 후 내부에서 자유롭게 이동
- 2023년 보안 침해의 약 34%가 내부자 관련

**2) 측면 이동 (Lateral Movement)**
- 공격자가 한 시스템 침해 후 내부망 자유 이동
- 내부 신뢰로 인해 감지 어려움
- APT 공격의 핵심 전술

**3) 클라우드/모바일 환경 부적합**
- 네트워크 경계가 사실상 사라짐
- BYOD, 재택근무, 멀티클라우드 환경
- SaaS 서비스는 경계 밖에 존재

**4) VPN의 한계**
- 모든 트래픽을 중앙으로 라우팅 → 성능 저하
- VPN 크리덴셜 탈취 시 전체 내부망 노출
- 세밀한 접근 제어 어려움

### 2.3 실제 사례

```
2020년 SolarWinds 공격:
- VPN으로 내부망 접근
- 내부 신뢰를 이용해 수평 이동
- 18,000개 조직에 악성 업데이트 배포
- 기존 경계 보안으로는 탐지 불가

2021년 Colonial Pipeline:
- VPN 계정 탈취로 내부망 진입
- 랜섬웨어 배포 후 운영 중단
- 4,400만 달러 랜섬 지불
```

---

## 3. NIST SP 800-207 Zero Trust 아키텍처

미국 국립표준기술연구소(NIST)는 2020년 SP 800-207을 발간해 Zero Trust 아키텍처의 공식 프레임워크를 제시했다.

### 3.1 핵심 구성 요소

```
┌─────────────────────────────────────────────────────────┐
│                    Zero Trust 아키텍처                    │
│                                                         │
│  ┌──────────────┐         ┌──────────────────────────┐  │
│  │   주체       │──요청──▶│    정책 결정 포인트(PDP)  │  │
│  │  (Subject)   │         │    - 정책 엔진(PE)        │  │
│  └──────────────┘         │    - 정책 관리자(PA)      │  │
│                           └──────────┬───────────────┘  │
│                                      │ 허가/거부         │
│  ┌──────────────────────────────────▼───────────────┐   │
│  │              정책 집행 포인트(PEP)                 │   │
│  └──────────────────────────────────────────────────┘   │
│                           │                             │
│                    ┌──────▼──────┐                      │
│                    │  엔터프라이즈│                      │
│                    │   리소스    │                      │
│                    └─────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

### 3.2 NIST 7대 Zero Trust 원칙

1. **모든 데이터 소스와 컴퓨팅 서비스를 리소스로 간주**
2. **네트워크 위치에 관계없이 모든 통신 보안 유지**
3. **개별 기업 리소스에 대한 접근은 세션 단위로 허가**
4. **리소스 접근은 클라이언트 신원, 애플리케이션/서비스, 요청 자산의 관찰 가능 상태로 결정**
5. **모든 자산의 무결성과 보안 태세를 모니터링하고 측정**
6. **모든 리소스 인증과 권한 부여는 동적이며 엄격하게 집행**
7. **자산, 네트워크 인프라, 통신에 대한 정보를 수집하고 보안 태세 개선에 활용**

---

## 4. 5대 핵심 구성요소

### 4.1 신원 (Identity)

신원은 Zero Trust의 새로운 경계다. 사람뿐 아니라 기기, 서비스, 애플리케이션도 신원을 가진다.

**구성 요소:**
- 강력한 인증 (MFA, 패스키)
- 신원 거버넌스 (IGA)
- 특권 접근 관리 (PAM)
- 서비스 계정/API 키 관리

**검증 항목:**
```
사용자 신원 검증:
├── 비밀번호 (지식 기반)
├── MFA 토큰 (소유 기반)
├── 생체인식 (고유 기반)
└── 행동 분석 (지속적 검증)
```

### 4.2 기기 (Device)

접근하는 기기의 보안 상태를 지속적으로 평가한다.

**평가 항목:**
- OS 버전 및 패치 상태
- 엔드포인트 보안 솔루션 실행 여부
- MDM 등록 여부
- 디스크 암호화 상태
- 보안 부팅(Secure Boot) 활성화

**기기 신뢰 등급:**
```
완전 신뢰: MDM 등록 + 최신 패치 + EDR 실행 + 암호화
부분 신뢰: 일부 조건 충족 → 제한된 접근
비신뢰: 조건 미충족 → 접근 거부 또는 격리 환경
```

### 4.3 네트워크 (Network)

네트워크는 더 이상 신뢰의 기준이 아니다. 모든 네트워크 트래픽을 암호화하고 세분화한다.

**핵심 기술:**
- 마이크로세그멘테이션
- Software-Defined Perimeter (SDP)
- ZTNA (Zero Trust Network Access)
- 암호화된 통신 (TLS 1.3+)

### 4.4 워크로드 (Workload)

클라우드, 컨테이너, 서버리스 등 모든 컴퓨팅 워크로드를 보호한다.

**보호 대상:**
- 가상머신 (VM)
- 컨테이너 (Docker, Kubernetes)
- 서버리스 함수 (Lambda, Cloud Functions)
- API 및 마이크로서비스

**접근 방식:**
```
워크로드 보안:
├── 이미지 서명 및 검증
├── 런타임 보안 (Falco, Sysdig)
├── 서비스 메시 (Istio, Linkerd)
└── API 게이트웨이 접근 제어
```

### 4.5 데이터 (Data)

데이터 중심 보안: 데이터가 어디에 있든 분류하고 보호한다.

**데이터 보호 전략:**
- 데이터 분류 (공개/내부/기밀/극비)
- 암호화 (저장, 전송, 사용 중)
- DLP (Data Loss Prevention)
- 데이터 접근 감사

---

## 5. BeyondCorp 모델 (Google 사례)

### 5.1 배경

Google은 2009년 Operation Aurora 사이버 공격 이후 VPN 없이 직원이 어디서든 안전하게 업무할 수 있는 새로운 모델을 개발했다. 이것이 BeyondCorp이다.

### 5.2 핵심 원칙

1. **접근은 네트워크가 아닌 기기와 사용자 신원을 기반으로 한다**
2. **모든 접근은 암호화된다**
3. **기업 애플리케이션은 인터넷에 노출되며 신뢰할 수 없는 네트워크에서도 접근 가능**
4. **접근 제어는 동적이며 컨텍스트를 인식한다**

### 5.3 구성 요소

```
BeyondCorp 아키텍처:

[사용자] → [Access Proxy] → [Access Control Engine]
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                  │
             [기기 인벤토리]   [사용자 디렉토리]  [신뢰 추론기]
```

**기기 인벤토리 데이터베이스:**
- 관리 기기 목록
- 기기 인증서
- 보안 상태 정보

**신뢰 추론기 (Trust Inferrer):**
- 기기 신뢰 계층 결정
- 사용자 역할 결합
- 접근 정책 적용

### 5.4 BeyondCorp Enterprise (현재)

Google Cloud의 상용 솔루션으로 진화:
- Chrome Enterprise Premium과 통합
- Context-Aware Access 정책
- Threat and Data Protection
- App Connector (온프레미스 앱 연결)

---

## 6. 실전 Python 도구: 접근 요청 리스크 스코어링

```python
#!/usr/bin/env python3
"""
Zero Trust 접근 요청 리스크 스코어링 도구

사용법:
    python risk_scorer.py --user-id user123 --device-id dev456 --resource api/finance
    python risk_scorer.py --batch requests.json --output report.json
    python risk_scorer.py --interactive
"""

import argparse
import json
import sys
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessDecision(Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_MFA = "ALLOW_WITH_MFA"
    ALLOW_LIMITED = "ALLOW_LIMITED"
    DENY = "DENY"


@dataclass
class UserContext:
    user_id: str
    department: str = "unknown"
    role: str = "user"
    mfa_enabled: bool = False
    mfa_verified: bool = False
    last_password_change_days: int = 999
    failed_login_attempts: int = 0
    is_privileged: bool = False
    location_country: str = "KR"
    is_travel_mode: bool = False


@dataclass
class DeviceContext:
    device_id: str
    os_type: str = "unknown"
    os_version: str = "unknown"
    is_managed: bool = False
    is_encrypted: bool = False
    is_compliant: bool = False
    antivirus_active: bool = False
    last_scan_days: int = 999
    patch_level: str = "unknown"
    secure_boot: bool = False
    certificate_valid: bool = False


@dataclass
class NetworkContext:
    source_ip: str = "0.0.0.0"
    is_corporate_network: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter_ip: bool = False
    threat_intel_score: int = 0  # 0-100, 높을수록 위험
    geo_country: str = "KR"
    unusual_location: bool = False


@dataclass
class ResourceContext:
    resource_path: str = "/"
    sensitivity_level: int = 1  # 1-5
    requires_mfa: bool = False
    allowed_roles: list[str] = field(default_factory=list)
    business_hours_only: bool = False
    max_risk_score: int = 70


@dataclass
class RiskScore:
    total_score: int = 0
    user_score: int = 0
    device_score: int = 0
    network_score: int = 0
    behavioral_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    decision: AccessDecision = AccessDecision.ALLOW
    factors: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RiskScorer:
    """Zero Trust 접근 요청 리스크 스코어링 엔진"""

    CORPORATE_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    KNOWN_TOR_INDICATORS = ["tor", "onion", "proxy"]

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.weight_user = self.config.get("weight_user", 0.30)
        self.weight_device = self.config.get("weight_device", 0.35)
        self.weight_network = self.config.get("weight_network", 0.20)
        self.weight_behavioral = self.config.get("weight_behavioral", 0.15)

    def score_user(self, user: UserContext) -> tuple[int, list[str]]:
        """사용자 컨텍스트 리스크 점수 계산 (0-100)"""
        score = 0
        factors: list[str] = []

        # MFA 상태
        if not user.mfa_enabled:
            score += 40
            factors.append("MFA 비활성화 (-40점)")
        elif not user.mfa_verified:
            score += 20
            factors.append("MFA 미검증 세션 (-20점)")

        # 비밀번호 나이
        if user.last_password_change_days > 180:
            score += 20
            factors.append(f"비밀번호 {user.last_password_change_days}일 미변경 (-20점)")
        elif user.last_password_change_days > 90:
            score += 10
            factors.append(f"비밀번호 {user.last_password_change_days}일 미변경 (-10점)")

        # 로그인 실패 시도
        if user.failed_login_attempts >= 5:
            score += 25
            factors.append(f"로그인 실패 {user.failed_login_attempts}회 (-25점)")
        elif user.failed_login_attempts >= 3:
            score += 15
            factors.append(f"로그인 실패 {user.failed_login_attempts}회 (-15점)")

        # 비정상 위치
        if user.is_travel_mode and user.location_country != "KR":
            score += 10
            factors.append(f"해외 접속 ({user.location_country}) (-10점)")

        # 특권 계정
        if user.is_privileged:
            score += 5
            factors.append("특권 계정 접근 (-5점 추가)")

        return min(score, 100), factors

    def score_device(self, device: DeviceContext) -> tuple[int, list[str]]:
        """기기 컨텍스트 리스크 점수 계산 (0-100)"""
        score = 0
        factors: list[str] = []

        # 관리 기기 여부
        if not device.is_managed:
            score += 35
            factors.append("비관리 기기 (-35점)")

        # 암호화
        if not device.is_encrypted:
            score += 20
            factors.append("디스크 암호화 비활성 (-20점)")

        # 보안 소프트웨어
        if not device.antivirus_active:
            score += 15
            factors.append("안티바이러스 비실행 (-15점)")

        # 패치 상태
        if device.patch_level == "critical_missing":
            score += 25
            factors.append("심각한 패치 누락 (-25점)")
        elif device.patch_level == "outdated":
            score += 15
            factors.append("패치 최신화 필요 (-15점)")

        # 마지막 검사
        if device.last_scan_days > 30:
            score += 10
            factors.append(f"마지막 보안 검사 {device.last_scan_days}일 경과 (-10점)")

        # 인증서
        if not device.certificate_valid:
            score += 20
            factors.append("기기 인증서 무효 (-20점)")

        # Secure Boot
        if not device.secure_boot:
            score += 10
            factors.append("Secure Boot 비활성 (-10점)")

        return min(score, 100), factors

    def score_network(self, network: NetworkContext) -> tuple[int, list[str]]:
        """네트워크 컨텍스트 리스크 점수 계산 (0-100)"""
        score = 0
        factors: list[str] = []

        # Tor 사용
        if network.is_tor:
            score += 50
            factors.append("Tor 네트워크 감지 (-50점)")

        # 위협 인텔리전스
        if network.threat_intel_score >= 80:
            score += 40
            factors.append(f"위협 인텔리전스 고위험 ({network.threat_intel_score}) (-40점)")
        elif network.threat_intel_score >= 50:
            score += 20
            factors.append(f"위협 인텔리전스 중위험 ({network.threat_intel_score}) (-20점)")

        # 비정상 위치
        if network.unusual_location:
            score += 25
            factors.append("비정상 접속 위치 (-25점)")

        # 데이터센터 IP (봇/스크립트 가능성)
        if network.is_datacenter_ip and not network.is_vpn:
            score += 15
            factors.append("데이터센터 IP 감지 (-15점)")

        # 기업 네트워크 외부
        if not network.is_corporate_network and not network.is_vpn:
            score += 10
            factors.append("외부 네트워크 접속 (-10점)")

        return min(score, 100), factors

    def score_behavioral(
        self,
        user: UserContext,
        resource: ResourceContext,
        timestamp: datetime
    ) -> tuple[int, list[str]]:
        """행동 패턴 리스크 점수 계산 (0-100)"""
        score = 0
        factors: list[str] = []

        # 업무 시간 외 접근
        hour = timestamp.hour
        is_business_hours = 9 <= hour <= 18
        weekday = timestamp.weekday()
        is_weekday = weekday < 5

        if resource.business_hours_only and (not is_business_hours or not is_weekday):
            score += 30
            factors.append("업무 시간 외 민감 리소스 접근 (-30점)")
        elif not is_business_hours:
            score += 10
            factors.append("업무 시간 외 접근 (-10점)")

        # 역할 기반 접근
        if resource.allowed_roles and user.role not in resource.allowed_roles:
            score += 40
            factors.append(f"허용되지 않은 역할({user.role})의 리소스 접근 (-40점)")

        # 고감도 리소스
        if resource.sensitivity_level >= 4:
            score += 15
            factors.append(f"고감도 리소스 접근 (레벨 {resource.sensitivity_level}) (-15점)")

        return min(score, 100), factors

    def calculate_total_risk(
        self,
        user: UserContext,
        device: DeviceContext,
        network: NetworkContext,
        resource: ResourceContext,
        timestamp: datetime | None = None,
    ) -> RiskScore:
        """전체 리스크 점수 계산 및 접근 결정"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        result = RiskScore()

        # 각 영역 점수 계산
        result.user_score, user_factors = self.score_user(user)
        result.device_score, device_factors = self.score_device(device)
        result.network_score, network_factors = self.score_network(network)
        result.behavioral_score, behavioral_factors = self.score_behavioral(user, resource, timestamp)

        # 모든 팩터 합산
        result.factors = user_factors + device_factors + network_factors + behavioral_factors

        # 가중 평균 계산
        result.total_score = int(
            result.user_score * self.weight_user
            + result.device_score * self.weight_device
            + result.network_score * self.weight_network
            + result.behavioral_score * self.weight_behavioral
        )

        # 리스크 레벨 결정
        if result.total_score >= 75:
            result.risk_level = RiskLevel.CRITICAL
        elif result.total_score >= 50:
            result.risk_level = RiskLevel.HIGH
        elif result.total_score >= 25:
            result.risk_level = RiskLevel.MEDIUM
        else:
            result.risk_level = RiskLevel.LOW

        # 접근 결정
        result.decision = self._make_decision(result, user, resource)

        # 권고사항 생성
        result.recommendations = self._generate_recommendations(result, user, device, network)

        return result

    def _make_decision(
        self,
        score: RiskScore,
        user: UserContext,
        resource: ResourceContext,
    ) -> AccessDecision:
        """리스크 점수 기반 접근 결정"""

        # 즉시 거부 조건
        if score.total_score > resource.max_risk_score:
            return AccessDecision.DENY

        if score.risk_level == RiskLevel.CRITICAL:
            return AccessDecision.DENY

        # MFA 요구 조건
        if resource.requires_mfa and not user.mfa_verified:
            return AccessDecision.ALLOW_WITH_MFA

        if score.risk_level == RiskLevel.HIGH and not user.mfa_verified:
            return AccessDecision.ALLOW_WITH_MFA

        # 제한적 허용
        if score.risk_level == RiskLevel.MEDIUM:
            return AccessDecision.ALLOW_LIMITED

        return AccessDecision.ALLOW

    def _generate_recommendations(
        self,
        score: RiskScore,
        user: UserContext,
        device: DeviceContext,
        network: NetworkContext,
    ) -> list[str]:
        """개선 권고사항 생성"""
        recommendations: list[str] = []

        if not user.mfa_enabled:
            recommendations.append("즉시 MFA를 활성화하세요")

        if user.last_password_change_days > 90:
            recommendations.append("비밀번호를 변경하세요 (90일 이상 경과)")

        if not device.is_managed:
            recommendations.append("기기를 MDM에 등록하세요")

        if not device.is_encrypted:
            recommendations.append("디스크 암호화를 활성화하세요")

        if device.patch_level in ("critical_missing", "outdated"):
            recommendations.append("보안 패치를 즉시 적용하세요")

        if network.is_tor:
            recommendations.append("Tor 네트워크 사용은 정책에 위반됩니다")

        if score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recommendations.append("보안팀에 즉시 연락하세요")

        return recommendations


def process_single_request(
    request_data: dict[str, Any],
    scorer: RiskScorer,
) -> dict[str, Any]:
    """단일 접근 요청 처리"""
    try:
        user = UserContext(**request_data.get("user", {}))
        device = DeviceContext(**request_data.get("device", {}))
        network = NetworkContext(**request_data.get("network", {}))
        resource = ResourceContext(**request_data.get("resource", {}))

        ts_str = request_data.get("timestamp")
        timestamp = datetime.fromisoformat(ts_str) if ts_str else None

        result = scorer.calculate_total_risk(user, device, network, resource, timestamp)

        return {
            "request_id": request_data.get("request_id", "unknown"),
            "user_id": user.user_id,
            "resource": resource.resource_path,
            "result": asdict(result),
        }
    except Exception as e:
        logger.error(f"요청 처리 중 오류: {e}")
        return {
            "request_id": request_data.get("request_id", "unknown"),
            "error": str(e),
        }


def create_sample_request() -> dict[str, Any]:
    """샘플 요청 데이터 생성"""
    return {
        "request_id": "req_" + hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
        "user": {
            "user_id": "user_123",
            "department": "finance",
            "role": "analyst",
            "mfa_enabled": True,
            "mfa_verified": False,
            "last_password_change_days": 95,
            "failed_login_attempts": 2,
            "is_privileged": False,
            "location_country": "KR",
        },
        "device": {
            "device_id": "dev_456",
            "os_type": "Windows",
            "os_version": "11",
            "is_managed": True,
            "is_encrypted": True,
            "is_compliant": False,
            "antivirus_active": True,
            "last_scan_days": 3,
            "patch_level": "outdated",
            "secure_boot": True,
            "certificate_valid": True,
        },
        "network": {
            "source_ip": "192.168.1.100",
            "is_corporate_network": True,
            "is_vpn": False,
            "is_tor": False,
            "is_datacenter_ip": False,
            "threat_intel_score": 10,
            "geo_country": "KR",
            "unusual_location": False,
        },
        "resource": {
            "resource_path": "api/finance/reports",
            "sensitivity_level": 4,
            "requires_mfa": True,
            "allowed_roles": ["analyst", "manager", "admin"],
            "business_hours_only": True,
            "max_risk_score": 60,
        },
    }


def run_interactive_mode(scorer: RiskScorer) -> None:
    """대화형 모드 실행"""
    print("\n=== Zero Trust 접근 요청 리스크 스코어링 (대화형) ===\n")

    sample = create_sample_request()
    print("샘플 요청 데이터를 사용합니다.")
    print(json.dumps(sample, ensure_ascii=False, indent=2))
    print()

    result = process_single_request(sample, scorer)
    print("\n=== 분석 결과 ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))


def run_batch_mode(
    input_file: str,
    output_file: str | None,
    scorer: RiskScorer,
    max_workers: int = 4,
) -> None:
    """배치 처리 모드 실행"""
    input_path = Path(input_file)
    if not input_path.exists():
        logger.error(f"입력 파일을 찾을 수 없습니다: {input_file}")
        sys.exit(1)

    with open(input_path, encoding="utf-8") as f:
        requests = json.load(f)

    if not isinstance(requests, list):
        requests = [requests]

    logger.info(f"{len(requests)}개 요청 처리 시작 (워커: {max_workers})")

    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_request, req, scorer): req
            for req in requests
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            logger.info(
                f"처리 완료: {result.get('request_id')} - "
                f"{result.get('result', {}).get('decision', 'ERROR')}"
            )

    summary = {
        "total": len(results),
        "allow": sum(1 for r in results if r.get("result", {}).get("decision") == "ALLOW"),
        "allow_with_mfa": sum(1 for r in results if r.get("result", {}).get("decision") == "ALLOW_WITH_MFA"),
        "allow_limited": sum(1 for r in results if r.get("result", {}).get("decision") == "ALLOW_LIMITED"),
        "deny": sum(1 for r in results if r.get("result", {}).get("decision") == "DENY"),
        "errors": sum(1 for r in results if "error" in r),
    }

    output = {"summary": summary, "results": results}

    if output_file:
        output_path = Path(output_file)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        logger.info(f"결과 저장 완료: {output_file}")
    else:
        print(json.dumps(output, ensure_ascii=False, indent=2))


def run_single_mode(args: argparse.Namespace, scorer: RiskScorer) -> None:
    """단일 요청 처리 모드"""
    request = {
        "request_id": f"req_{args.user_id}_{args.resource}",
        "user": {"user_id": args.user_id},
        "device": {"device_id": args.device_id},
        "network": {},
        "resource": {"resource_path": args.resource},
    }

    result = process_single_request(request, scorer)

    print("\n=== 리스크 분석 결과 ===")
    res = result.get("result", {})
    print(f"요청 ID      : {result.get('request_id')}")
    print(f"사용자 ID    : {result.get('user_id')}")
    print(f"리소스       : {result.get('resource')}")
    print(f"총 리스크 점수: {res.get('total_score')}/100")
    print(f"  - 사용자    : {res.get('user_score')}")
    print(f"  - 기기      : {res.get('device_score')}")
    print(f"  - 네트워크  : {res.get('network_score')}")
    print(f"  - 행동      : {res.get('behavioral_score')}")
    print(f"리스크 레벨  : {res.get('risk_level')}")
    print(f"접근 결정    : {res.get('decision')}")

    factors = res.get("factors", [])
    if factors:
        print("\n위험 요인:")
        for f in factors:
            print(f"  - {f}")

    recommendations = res.get("recommendations", [])
    if recommendations:
        print("\n권고사항:")
        for r in recommendations:
            print(f"  * {r}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero Trust 접근 요청 리스크 스코어링 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 단일 요청 분석
  python risk_scorer.py --user-id user123 --device-id dev456 --resource api/finance

  # 배치 처리
  python risk_scorer.py --batch requests.json --output report.json

  # 대화형 모드 (샘플 데이터)
  python risk_scorer.py --interactive

  # 병렬 워커 수 조정
  python risk_scorer.py --batch requests.json --workers 8
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--interactive", action="store_true", help="대화형 모드 (샘플 데이터 사용)")
    mode.add_argument("--batch", metavar="INPUT_JSON", help="배치 처리 모드 (JSON 파일)")
    mode.add_argument("--user-id", metavar="USER_ID", help="단일 요청 모드 - 사용자 ID")

    parser.add_argument("--device-id", metavar="DEVICE_ID", default="unknown", help="기기 ID")
    parser.add_argument("--resource", metavar="RESOURCE", default="/", help="대상 리소스 경로")
    parser.add_argument("--output", metavar="OUTPUT_JSON", help="결과 출력 파일")
    parser.add_argument("--workers", type=int, default=4, help="배치 처리 병렬 워커 수 (기본: 4)")
    parser.add_argument("--config", metavar="CONFIG_JSON", help="스코어링 설정 파일")
    parser.add_argument("--verbose", action="store_true", help="상세 로그 출력")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config: dict[str, Any] = {}
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"설정 파일 로드 실패: {e}")
            sys.exit(1)

    scorer = RiskScorer(config)

    if args.interactive:
        run_interactive_mode(scorer)
    elif args.batch:
        run_batch_mode(args.batch, args.output, scorer, args.workers)
    else:
        run_single_mode(args, scorer)


if __name__ == "__main__":
    main()
```

---

## 7. Zero Trust 도입 효과

### 7.1 보안 효과

| 지표 | 기존 모델 | Zero Trust |
|------|----------|------------|
| 침해 감지 시간 | 평균 207일 | 수분~수시간 |
| 측면 이동 방지 | 제한적 | 마이크로세그멘테이션으로 차단 |
| 내부자 위협 | 탐지 어려움 | 행동 분석으로 탐지 |
| 클라우드 보안 | 취약 | 네이티브 지원 |

### 7.2 비즈니스 효과

- 재택/원격 근무 보안 확보
- 클라우드 전환 가속화
- 컴플라이언스 준수 용이
- 보안 사고 대응 비용 절감

### 7.3 IBM 연구 (2023년 Cost of Data Breach)

```
Zero Trust 미성숙 조직: 평균 침해 비용 $5.04M
Zero Trust 성숙 조직:   평균 침해 비용 $3.28M
절감 효과:              약 35% 감소
```

---

## 8. 참고 자료

- NIST SP 800-207: Zero Trust Architecture (2020)
- Google BeyondCorp 논문 시리즈 (2014-2020)
- Forrester Zero Trust eXtended (ZTX) Framework
- CISA Zero Trust Maturity Model (2023)
- Cloud Security Alliance: Software Defined Perimeter Specification
- Gartner: Zero Trust Network Access Market Guide

---

*최종 업데이트: 2024년*

---

<a name="english"></a>

# Zero Trust Architecture Principles

## 1. What is Zero Trust?

Zero Trust is a security paradigm with "Never Trust, Always Verify" as its core philosophy. Unlike traditional perimeter-based security models that trust internal networks, Zero Trust treats all access requests as adversarial regardless of location (internal/external) and continuously verifies them.

### Core Principles

| Principle | Description |
|-----------|-------------|
| Never Trust | Internal network location does not imply trust |
| Always Verify | All requests are verified based on identity, device, and context |
| Least Privilege | Access only to the minimum necessary resources |
| Assume Breach | Designed assuming a breach has already occurred |
| Explicit Verification | Use all available data points to verify |

---

## 2. Limitations of Traditional Perimeter Security

### Castle-and-Moat Model Shortcomings

1. **Insider Threat**: Malicious employee actions; account takeover with free internal movement; ~34% of 2023 breaches involved insiders
2. **Lateral Movement**: Attacker moves freely within internal network after compromising one system; hard to detect due to internal trust
3. **Cloud/Mobile Environment Mismatch**: Network perimeters have effectively disappeared with BYOD, remote work, multi-cloud, and SaaS
4. **VPN Limitations**: All traffic routed centrally → performance degradation; VPN credential theft exposes entire internal network

Real-world examples:
- **2020 SolarWinds**: VPN access → lateral movement exploiting internal trust → malicious updates to 18,000 organizations
- **2021 Colonial Pipeline**: VPN account theft → ransomware deployment → $44M ransom paid

---

## 3. NIST SP 800-207 Zero Trust Architecture

### Core Components

```
Subject (User/Device/Service)
    → Request →
Policy Decision Point (PDP)
    ├── Policy Engine (PE)
    └── Policy Administrator (PA)
        → Allow/Deny →
Policy Enforcement Point (PEP)
    → Access →
Enterprise Resources
```

### NIST 7 Zero Trust Tenets

1. All data sources and computing services are considered resources
2. All communications are secured regardless of network location
3. Access to individual enterprise resources is granted per-session
4. Resource access is determined by client identity, application/service, and observable asset state
5. Monitor and measure the integrity and security posture of all assets
6. All resource authentication and authorization is dynamic and strictly enforced
7. Collect information about assets, network infrastructure, and communications to improve security posture

---

## 4. Five Core Components

### 4.1 Identity (New Perimeter)

Covers people, devices, services, and applications. Components: strong authentication (MFA, passkeys), Identity Governance (IGA), Privileged Access Management (PAM), service account/API key management.

### 4.2 Device

Continuously evaluate device security posture: OS version/patches, endpoint security solutions, MDM enrollment, disk encryption, Secure Boot.
- **Full Trust**: MDM enrolled + latest patches + EDR running + encryption
- **Partial Trust**: Some conditions met → limited access
- **Untrusted**: Conditions not met → access denied or isolated environment

### 4.3 Network

No longer the basis of trust. All traffic encrypted (TLS 1.3+), microsegmentation, Software-Defined Perimeter (SDP), ZTNA.

### 4.4 Workload

Protect all computing workloads (VMs, containers, serverless functions, APIs): image signing/verification, runtime security (Falco, Sysdig), service mesh (Istio, Linkerd), API gateway access control.

### 4.5 Data

Data-centric security: classify (public/internal/confidential/restricted), encrypt (at rest, in transit, in use), DLP, data access auditing.

---

## 5. BeyondCorp Model (Google Case Study)

Developed after the 2009 Operation Aurora cyberattack to enable secure employee work from anywhere without VPN.

**Core Principles**:
1. Access is based on device and user identity, not network location
2. All access is encrypted
3. Corporate applications are exposed to the internet and accessible from untrusted networks
4. Access control is dynamic and context-aware

**Components**: Access Proxy, Access Control Engine, Device Inventory Database (managed device list, device certificates, security status), Trust Inferrer (determines device trust level, combines with user role, applies access policy).

---

## 6. Python Tool: Access Request Risk Scoring

A Zero Trust risk scoring engine that evaluates access requests across four dimensions:
- **User Score** (30%): MFA status, password age, failed login attempts, travel mode
- **Device Score** (35%): MDM enrollment, encryption, antivirus, patch level, certificate validity, Secure Boot
- **Network Score** (20%): Tor detection, threat intelligence score, unusual location, datacenter IP
- **Behavioral Score** (15%): Business hours check, role-based access validation, resource sensitivity level

Access decisions: ALLOW, ALLOW_WITH_MFA, ALLOW_LIMITED, or DENY based on total risk score and resource-specific thresholds.

---

## 7. Zero Trust Adoption Impact

| Metric | Traditional Model | Zero Trust |
|--------|-----------------|------------|
| Breach detection time | Average 207 days | Minutes to hours |
| Lateral movement prevention | Limited | Blocked by microsegmentation |
| Insider threat detection | Difficult | Detected via behavioral analysis |
| Cloud security | Weak | Native support |

IBM 2023 Cost of Data Breach: Zero Trust immature organizations average $5.04M vs. mature organizations $3.28M — approximately 35% reduction.

---

## References

- NIST SP 800-207: Zero Trust Architecture (2020)
- Google BeyondCorp Paper Series (2014-2020)
- Forrester Zero Trust eXtended (ZTX) Framework
- CISA Zero Trust Maturity Model (2023)
- Cloud Security Alliance: Software Defined Perimeter Specification
- Gartner: Zero Trust Network Access Market Guide
