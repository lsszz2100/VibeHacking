> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 신원 및 기기 신뢰 (Identity & Device Trust)

## 1. 신원 제공자 (Identity Provider, IdP) 연동

### 1.1 IdP의 역할

Zero Trust에서 IdP는 "새로운 경계"의 핵심 구성요소다.
모든 사용자, 기기, 서비스의 신원을 발급하고 검증하는 중앙 권한 기관이다.

```
┌──────────────────────────────────────────────────────────┐
│                   IdP 에코시스템                          │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │  Okta    │    │ Azure AD │    │  Google Workspace │   │
│  │          │    │  (Entra) │    │       IdP        │   │
│  └─────┬────┘    └────┬─────┘    └────────┬─────────┘   │
│        └──────────────┼──────────────────┘             │
│                       │ SAML / OIDC / OAuth2            │
│                  ┌────▼──────┐                          │
│                  │  SP/RP    │ (서비스 제공자/의존 당사자)│
│                  │ (앱/서비스)│                          │
│                  └───────────┘                          │
└──────────────────────────────────────────────────────────┘
```

### 1.2 주요 IdP 솔루션 비교

#### Okta

**강점:**
- 중립적 플랫폼 (특정 클라우드 비종속)
- 6,500개 이상의 앱 통합
- 강력한 MFA 옵션
- Okta Verify, FIDO2 지원
- Workforce Identity + Customer Identity 제공

**주요 기능:**
```
- Universal Directory: 모든 사용자/그룹 통합 관리
- Adaptive MFA: 리스크 기반 MFA 강화
- Lifecycle Management: 자동 프로비저닝/디프로비저닝
- API Access Management: OAuth 서버 기능
- Device Trust: 기기 신뢰 정책 연동
```

#### Azure Active Directory (Microsoft Entra ID)

**강점:**
- Microsoft 365, Azure와 네이티브 통합
- 하이브리드 환경 (온프레미스 AD + 클라우드) 지원
- Conditional Access 정책 강력함
- Entra ID Protection으로 위험 기반 접근 제어

**주요 기능:**
```
- Conditional Access: 세밀한 접근 조건 정책
- PIM (Privileged Identity Management): JIT 특권 접근
- Identity Protection: ML 기반 위험 탐지
- B2B/B2C: 외부 파트너 및 고객 신원 관리
- Seamless SSO: 투명한 Single Sign-On
```

#### Google Workspace IdP

**강점:**
- BeyondCorp 기반 설계
- Context-Aware Access 내장
- Google Cloud 네이티브 통합

**주요 기능:**
```
- Google Sign-In / OIDC 지원
- Context-Aware Access: 기기 상태, 위치 기반 정책
- Cloud Identity: 독립 IdP 서비스
- BeyondCorp Enterprise: 완전한 Zero Trust 솔루션
```

---

## 2. MFA 및 패스키 (FIDO2) 강화

### 2.1 MFA 인증 요소

```
인증 요소 분류:
├── 지식 기반 (Something You Know)
│   ├── 비밀번호
│   ├── PIN
│   └── 보안 질문 (권장하지 않음)
│
├── 소유 기반 (Something You Have)
│   ├── TOTP (Google Authenticator, Authy)
│   ├── HOTP (하드웨어 토큰)
│   ├── SMS OTP (취약, 권장하지 않음)
│   ├── 푸시 알림 (Okta Verify, MS Authenticator)
│   └── 하드웨어 키 (YubiKey)
│
└── 고유 기반 (Something You Are)
    ├── 지문 인식
    ├── 얼굴 인식
    └── 망막/홍채 인식
```

### 2.2 FIDO2/패스키 (Passkey)

FIDO2는 피싱-저항성(Phishing-Resistant) MFA의 표준이다.

**구성 요소:**
- **WebAuthn**: W3C 표준, 브라우저-서버 프로토콜
- **CTAP2**: 인증자(Authenticator)-클라이언트 프로토콜

**패스키 작동 방식:**
```
1. 등록:
   [서버] → 챌린지 전송 → [인증자(패스키)]
   [인증자] → 공개키 쌍 생성 → 공개키 서버 저장
   [인증자] → 개인키 기기/클라우드에 저장

2. 인증:
   [서버] → 챌린지 전송 → [클라이언트]
   [클라이언트] → 생체인식/PIN으로 인증자 활성화
   [인증자] → 개인키로 챌린지 서명
   [서버] → 공개키로 서명 검증 → 인증 완료
```

**패스키의 장점:**
| 특성 | 비밀번호+OTP | 패스키 |
|------|-------------|--------|
| 피싱 저항성 | 낮음 | 매우 높음 (도메인 바인딩) |
| SIM 스와핑 취약성 | 있음 (SMS OTP) | 없음 |
| 사용자 편의성 | 보통 | 매우 높음 |
| 크리덴셜 재사용 | 가능 | 불가 |
| 서버 침해 시 | 해시 노출 위험 | 공개키만 노출 |

### 2.3 적응형 MFA (Adaptive MFA)

리스크 기반으로 MFA 강도를 동적으로 조정한다.

```
리스크 낮음 → 생체인식만 요구
리스크 중간 → TOTP 추가 요구
리스크 높음 → 하드웨어 키 요구 또는 거부
```

---

## 3. 기기 신뢰 평가

### 3.1 기기 신뢰 평가 프레임워크

```
기기 신뢰 평가 항목:
│
├── 관리 상태 (Managed State)
│   ├── MDM 등록 여부 (Intune, Jamf, Google MDM)
│   ├── EMM 정책 준수
│   └── MDM 인증서 유효성
│
├── OS 보안 상태 (OS Security Posture)
│   ├── OS 버전 (지원 종료 버전 감지)
│   ├── 보안 패치 레벨
│   ├── Secure Boot 활성화
│   └── 커널 무결성 보호
│
├── 엔드포인트 보안 (Endpoint Security)
│   ├── EDR/AV 실행 상태
│   ├── 마지막 스캔 시간
│   ├── 위협 감지 상태
│   └── 방화벽 활성화
│
├── 암호화 상태 (Encryption)
│   ├── 전체 디스크 암호화 (BitLocker/FileVault)
│   └── 스토리지 암호화 키 보호
│
└── 인증서 (Certificate)
    ├── 기기 인증서 유효성
    ├── 인증서 만료일
    └── PKI 체인 검증
```

### 3.2 MDM (Mobile Device Management)

#### Microsoft Intune
```
정책 예시:
- 최소 OS 버전: Windows 11 22H2+
- BitLocker 필수
- Windows Defender 실행 필수
- 화면 잠금: 5분 이내
- 비밀번호 복잡도: 8자 이상, 특수문자 포함
```

#### Jamf (macOS/iOS)
```
정책 예시:
- FileVault 필수
- 게이트키퍼 활성화
- SIP(System Integrity Protection) 비활성화 금지
- 인증된 앱만 설치 허용
```

### 3.3 기기 인증서 (Device Certificate)

```
PKI 기반 기기 신뢰:

CA (Certificate Authority)
└── Intermediate CA
    └── 기기 인증서 발급
        ├── Subject: CN=DEVICE-ID, O=CORP
        ├── 유효기간: 1년
        └── EKU: Client Authentication

기기 인증 흐름:
[기기] → TLS 클라이언트 인증서 제시
[서버] → 인증서 체인 검증 + CRL/OCSP 확인
[서버] → MDM 등록 상태 교차 검증
[서버] → 접근 허용/거부
```

---

## 4. 조건부 접근 정책 (Conditional Access)

### 4.1 개념

조건부 접근은 if-then 형태의 정책으로 접근을 제어한다.

```
IF (조건들이 모두 충족되면)
THEN (허용/거부/MFA 요구/세션 제한)
```

### 4.2 조건 유형

| 조건 범주 | 예시 |
|-----------|------|
| 사용자/그룹 | 특정 부서, 역할, 게스트 계정 |
| 애플리케이션 | 특정 SaaS 앱, 온프레미스 앱 |
| 위치 | 국가, IP 범위, Named Location |
| 기기 플랫폼 | Windows, macOS, iOS, Android |
| 기기 상태 | 규정 준수(Compliant), Hybrid AD Join |
| 클라이언트 앱 | 브라우저, 레거시 인증 클라이언트 |
| 로그인 위험 | Microsoft Entra ID Protection 위험 점수 |
| 사용자 위험 | 계정 침해 위험 점수 |

### 4.3 정책 예시

**예시 1: 외부 접속 시 MFA 강제**
```
IF 위치 = 기업 외부 네트워크
AND 앱 = Microsoft 365
THEN MFA 필수
```

**예시 2: 비규정 준수 기기 차단**
```
IF 기기 상태 ≠ 규정 준수
AND 앱 = 고감도 HR 시스템
THEN 차단
```

**예시 3: 레거시 인증 차단**
```
IF 클라이언트 앱 = 레거시 인증 (Basic Auth)
THEN 차단
```

**예시 4: 국가 기반 차단**
```
IF 위치 = [허용되지 않은 국가 목록]
THEN 차단
```

---

## 5. SAML, OAuth2, OIDC 비교

### 5.1 SAML 2.0 (Security Assertion Markup Language)

**목적:** SSO (Single Sign-On), 주로 엔터프라이즈 웹앱

**흐름:**
```
[사용자] → [SP (서비스 제공자)]
[SP] → SAML 요청 → [IdP]
[사용자] → IdP에서 인증
[IdP] → SAML Assertion (XML) → [SP]
[SP] → Assertion 검증 → 접근 허용
```

**특징:**
- XML 기반 (무거움)
- 주로 B2B 엔터프라이즈
- 세션 관리 포함
- 단점: 모바일/API에 부적합

### 5.2 OAuth 2.0

**목적:** 권한 위임 (Authorization), API 접근

**주요 그랜트 타입:**
```
Authorization Code (+ PKCE): 웹앱, 모바일 앱 (권장)
Client Credentials: 서버-서버 통신
Implicit: 레거시 SPA (더 이상 권장 안 함)
Device Code: TV, IoT 기기
```

**Authorization Code + PKCE 흐름:**
```
[클라이언트] → code_verifier 생성, code_challenge 계산
[클라이언트] → 인증 서버로 code_challenge + 권한 요청
[사용자] → 로그인 및 동의
[인증 서버] → Authorization Code 반환
[클라이언트] → code + code_verifier로 토큰 교환
[인증 서버] → Access Token + Refresh Token 반환
[클라이언트] → Access Token으로 API 호출
```

### 5.3 OIDC (OpenID Connect)

**목적:** 인증 (Authentication) - OAuth2 위에 구축

**OAuth2 vs OIDC:**
```
OAuth2: "이 앱이 당신의 데이터에 접근해도 됩니까?"
OIDC:   "당신이 누구인지 확인합니다" + OAuth2
```

**ID 토큰 (JWT):**
```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "client_id",
  "exp": 1735689600,
  "iat": 1735686000,
  "email": "user@example.com",
  "email_verified": true,
  "amr": ["mfa", "pwd", "hwk"],
  "acr": "urn:mace:incommon:iap:silver"
}
```

### 5.4 비교 요약

| 특성 | SAML 2.0 | OAuth 2.0 | OIDC |
|------|----------|-----------|------|
| 주 목적 | 인증+권한 (SSO) | 권한 위임 | 인증 |
| 데이터 형식 | XML | JSON/JWT | JSON/JWT |
| 모바일 적합성 | 낮음 | 높음 | 높음 |
| API 접근 | 부적합 | 적합 | 적합 |
| 복잡도 | 높음 | 중간 | 중간 |
| 엔터프라이즈 채택 | 매우 높음 | 높음 | 높음 |

---

## 6. 실전 Python 도구: 디바이스 신뢰 점수 계산

```python
#!/usr/bin/env python3
"""
Zero Trust 디바이스 신뢰 점수 계산 도구

시스템 실제 정보(CPU, OS, 패치 상태)를 수집하여 기기 신뢰 점수를 계산합니다.

사용법:
    python device_trust_scorer.py --scan
    python device_trust_scorer.py --scan --output report.json
    python device_trust_scorer.py --json-input device_info.json
    python device_trust_scorer.py --scan --verbose
"""

import argparse
import json
import sys
import logging
import platform
import subprocess
import shutil
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class OSInfo:
    system: str = "unknown"       # Windows, Linux, Darwin
    release: str = "unknown"      # 버전 번호
    version: str = "unknown"      # 상세 버전
    machine: str = "unknown"      # x86_64, arm64
    processor: str = "unknown"
    is_64bit: bool = False
    is_supported: bool = False    # EoL 여부


@dataclass
class PatchInfo:
    last_update_days: int = -1    # 마지막 업데이트 경과일
    pending_updates: int = -1     # 대기 중인 업데이트 수
    critical_missing: int = 0     # 미적용 중요 패치 수
    patch_level: str = "unknown"  # current/outdated/critical_missing


@dataclass
class SecuritySoftwareInfo:
    antivirus_running: bool = False
    antivirus_name: str = "unknown"
    firewall_enabled: bool = False
    encryption_enabled: bool = False
    edr_running: bool = False


@dataclass
class HardwareInfo:
    cpu_cores: int = 0
    total_memory_gb: float = 0.0
    free_memory_gb: float = 0.0
    disk_total_gb: float = 0.0
    disk_free_gb: float = 0.0


@dataclass
class DeviceScanResult:
    hostname: str = "unknown"
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    os_info: OSInfo = field(default_factory=OSInfo)
    patch_info: PatchInfo = field(default_factory=PatchInfo)
    security_software: SecuritySoftwareInfo = field(default_factory=SecuritySoftwareInfo)
    hardware: HardwareInfo = field(default_factory=HardwareInfo)
    raw_errors: list[str] = field(default_factory=list)


@dataclass
class TrustScore:
    total_score: int = 0          # 0-100, 높을수록 신뢰
    os_score: int = 0
    patch_score: int = 0
    security_score: int = 0
    hardware_score: int = 0
    trust_level: str = "UNTRUSTED"   # TRUSTED/PARTIAL/UNTRUSTED
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# 지원 종료(EoL) OS 목록
EOL_OS_VERSIONS: dict[str, list[str]] = {
    "Windows": ["7", "8", "8.1", "XP", "Vista", "10 1507", "10 1511"],
    "Linux": [],  # 배포판별로 다름
    "Darwin": ["10.13", "10.14", "10.15"],  # High Sierra, Mojave, Catalina
}

# 알려진 EDR 프로세스 이름
KNOWN_EDR_PROCESSES = [
    "MsMpEng",       # Windows Defender
    "CylanceSvc",    # Cylance
    "cb",            # Carbon Black
    "falcon",        # CrowdStrike Falcon
    "xagt",          # FireEye HX
    "ds_agent",      # Deep Security
    "SentinelAgent", # SentinelOne
    "Traps",         # Palo Alto Traps
]


class SystemInfoCollector:
    """시스템 정보 수집기"""

    def collect_os_info(self) -> tuple[OSInfo, list[str]]:
        """OS 정보 수집"""
        errors: list[str] = []
        info = OSInfo()

        try:
            info.system = platform.system()
            info.release = platform.release()
            info.version = platform.version()
            info.machine = platform.machine()
            info.processor = platform.processor()
            info.is_64bit = platform.architecture()[0] == "64bit"
            info.is_supported = self._check_os_supported(info.system, info.release)
        except Exception as e:
            errors.append(f"OS 정보 수집 실패: {e}")

        return info, errors

    def _check_os_supported(self, system: str, release: str) -> bool:
        """OS 지원 종료 여부 확인"""
        eol_versions = EOL_OS_VERSIONS.get(system, [])
        for eol in eol_versions:
            if eol.lower() in release.lower():
                return False
        return True

    def collect_patch_info(self) -> tuple[PatchInfo, list[str]]:
        """패치 상태 수집"""
        errors: list[str] = []
        info = PatchInfo()
        system = platform.system()

        try:
            if system == "Windows":
                info = self._collect_windows_patch_info(errors)
            elif system == "Linux":
                info = self._collect_linux_patch_info(errors)
            elif system == "Darwin":
                info = self._collect_macos_patch_info(errors)
        except Exception as e:
            errors.append(f"패치 정보 수집 실패: {e}")

        return info, errors

    def _collect_windows_patch_info(self, errors: list[str]) -> PatchInfo:
        """Windows 패치 정보"""
        info = PatchInfo()
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-HotFix | Sort-Object InstalledOn -Descending | "
                 "Select-Object -First 1 | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                hotfix_data = json.loads(result.stdout)
                installed_on = hotfix_data.get("InstalledOn", "")
                if installed_on:
                    installed_date = datetime.fromisoformat(installed_on.split("T")[0])
                    info.last_update_days = (datetime.now() - installed_date).days
        except Exception as e:
            errors.append(f"Windows 패치 정보 수집 실패: {e}")

        # 업데이트 수 확인
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(New-Object -ComObject Microsoft.Update.Session)"
                 ".CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                info.pending_updates = int(result.stdout.strip())
        except Exception as e:
            errors.append(f"Windows 대기 업데이트 수집 실패: {e}")

        info.patch_level = self._determine_patch_level(info)
        return info

    def _collect_linux_patch_info(self, errors: list[str]) -> PatchInfo:
        """Linux 패치 정보"""
        info = PatchInfo()

        # apt 기반 시스템
        if shutil.which("apt"):
            try:
                result = subprocess.run(
                    ["apt", "list", "--upgradable"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    lines = [l for l in result.stdout.splitlines() if "/" in l]
                    info.pending_updates = len(lines)
            except Exception as e:
                errors.append(f"apt 업데이트 정보 실패: {e}")

        # yum/dnf 기반 시스템
        elif shutil.which("dnf") or shutil.which("yum"):
            cmd = "dnf" if shutil.which("dnf") else "yum"
            try:
                result = subprocess.run(
                    [cmd, "check-update", "--quiet"],
                    capture_output=True, text=True, timeout=60
                )
                # yum check-update returns 100 when updates available
                if result.returncode in (0, 100):
                    lines = [l for l in result.stdout.splitlines() if l.strip()]
                    info.pending_updates = len(lines)
            except Exception as e:
                errors.append(f"{cmd} 업데이트 정보 실패: {e}")

        info.patch_level = self._determine_patch_level(info)
        return info

    def _collect_macos_patch_info(self, errors: list[str]) -> PatchInfo:
        """macOS 패치 정보"""
        info = PatchInfo()

        try:
            result = subprocess.run(
                ["softwareupdate", "--list"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                # 대기 중인 업데이트 수 계산
                lines = [l for l in result.stdout.splitlines() if "* " in l]
                info.pending_updates = len(lines)
        except Exception as e:
            errors.append(f"macOS 업데이트 정보 실패: {e}")

        info.patch_level = self._determine_patch_level(info)
        return info

    def _determine_patch_level(self, info: PatchInfo) -> str:
        """패치 레벨 결정"""
        if info.critical_missing > 0:
            return "critical_missing"
        if info.pending_updates > 10:
            return "outdated"
        if info.pending_updates > 0:
            return "updates_available"
        if info.last_update_days > 60:
            return "outdated"
        return "current"

    def collect_security_software(self) -> tuple[SecuritySoftwareInfo, list[str]]:
        """보안 소프트웨어 상태 수집"""
        errors: list[str] = []
        info = SecuritySoftwareInfo()
        system = platform.system()

        try:
            if system == "Windows":
                info = self._collect_windows_security(errors)
            elif system == "Darwin":
                info = self._collect_macos_security(errors)
            elif system == "Linux":
                info = self._collect_linux_security(errors)
        except Exception as e:
            errors.append(f"보안 소프트웨어 정보 수집 실패: {e}")

        # EDR 감지 (플랫폼 공통)
        info.edr_running = self._detect_edr(errors)

        return info, errors

    def _collect_windows_security(self, errors: list[str]) -> SecuritySoftwareInfo:
        """Windows 보안 상태"""
        info = SecuritySoftwareInfo()

        # Windows Defender 상태
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-MpComputerStatus | Select-Object AMRunningMode, "
                 "RealTimeProtectionEnabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                info.antivirus_running = data.get("RealTimeProtectionEnabled", False)
                info.antivirus_name = "Windows Defender"
        except Exception as e:
            errors.append(f"Windows Defender 상태 확인 실패: {e}")

        # BitLocker 상태
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                info.encryption_enabled = "On" in result.stdout
        except Exception as e:
            errors.append(f"BitLocker 상태 확인 실패: {e}")

        # Windows Firewall 상태
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(Get-NetFirewallProfile -Profile Domain).Enabled"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                info.firewall_enabled = "True" in result.stdout
        except Exception as e:
            errors.append(f"방화벽 상태 확인 실패: {e}")

        return info

    def _collect_macos_security(self, errors: list[str]) -> SecuritySoftwareInfo:
        """macOS 보안 상태"""
        info = SecuritySoftwareInfo()

        # FileVault 상태
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True, timeout=15
            )
            info.encryption_enabled = "On" in result.stdout
        except Exception as e:
            errors.append(f"FileVault 상태 확인 실패: {e}")

        # 방화벽 상태
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                info.firewall_enabled = result.stdout.strip() in ("1", "2")
        except Exception as e:
            errors.append(f"macOS 방화벽 상태 확인 실패: {e}")

        return info

    def _collect_linux_security(self, errors: list[str]) -> SecuritySoftwareInfo:
        """Linux 보안 상태"""
        info = SecuritySoftwareInfo()

        # UFW 방화벽
        if shutil.which("ufw"):
            try:
                result = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True, text=True, timeout=10
                )
                info.firewall_enabled = "active" in result.stdout.lower()
            except Exception as e:
                errors.append(f"UFW 상태 확인 실패: {e}")

        # LUKS 암호화 (블록 디바이스)
        try:
            result = subprocess.run(
                ["lsblk", "-o", "TYPE"],
                capture_output=True, text=True, timeout=10
            )
            info.encryption_enabled = "crypt" in result.stdout
        except Exception as e:
            errors.append(f"암호화 상태 확인 실패: {e}")

        # ClamAV
        if shutil.which("clamav") or shutil.which("clamd"):
            info.antivirus_running = True
            info.antivirus_name = "ClamAV"

        return info

    def _detect_edr(self, errors: list[str]) -> bool:
        """EDR 프로세스 감지"""
        system = platform.system()

        try:
            if system == "Windows":
                result = subprocess.run(
                    ["powershell", "-NonInteractive", "-Command",
                     "Get-Process | Select-Object -ExpandProperty Name"],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    running = result.stdout.lower()
                    return any(edr.lower() in running for edr in KNOWN_EDR_PROCESSES)
            else:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    running = result.stdout.lower()
                    return any(edr.lower() in running for edr in KNOWN_EDR_PROCESSES)
        except Exception as e:
            errors.append(f"EDR 감지 실패: {e}")

        return False

    def collect_hardware_info(self) -> tuple[HardwareInfo, list[str]]:
        """하드웨어 정보 수집"""
        errors: list[str] = []
        info = HardwareInfo()

        try:
            import os
            cpu_count = os.cpu_count()
            info.cpu_cores = cpu_count if cpu_count else 0
        except Exception as e:
            errors.append(f"CPU 정보 수집 실패: {e}")

        # psutil이 없는 환경을 위한 폴백
        try:
            import psutil
            mem = psutil.virtual_memory()
            info.total_memory_gb = round(mem.total / (1024**3), 2)
            info.free_memory_gb = round(mem.available / (1024**3), 2)
            disk = psutil.disk_usage("/")
            info.disk_total_gb = round(disk.total / (1024**3), 2)
            info.disk_free_gb = round(disk.free / (1024**3), 2)
        except ImportError:
            errors.append("psutil 미설치: 메모리/디스크 정보 수집 불가 (pip install psutil)")
        except Exception as e:
            errors.append(f"하드웨어 정보 수집 실패: {e}")

        return info, errors


class DeviceTrustScorer:
    """기기 신뢰 점수 계산기"""

    WEIGHTS = {
        "os": 0.25,
        "patch": 0.30,
        "security": 0.35,
        "hardware": 0.10,
    }

    def score_os(self, os_info: OSInfo) -> tuple[int, list[str], list[str]]:
        """OS 점수 계산 (0-100)"""
        score = 100
        issues: list[str] = []
        recommendations: list[str] = []

        if not os_info.is_64bit:
            score -= 20
            issues.append("32비트 OS 사용 중")
            recommendations.append("64비트 OS로 업그레이드 권장")

        if not os_info.is_supported:
            score -= 50
            issues.append(f"지원 종료 OS: {os_info.system} {os_info.release}")
            recommendations.append("지원되는 최신 OS 버전으로 업그레이드 필수")

        return max(score, 0), issues, recommendations

    def score_patch(self, patch_info: PatchInfo) -> tuple[int, list[str], list[str]]:
        """패치 점수 계산 (0-100)"""
        score = 100
        issues: list[str] = []
        recommendations: list[str] = []

        if patch_info.patch_level == "critical_missing":
            score -= 60
            issues.append(f"심각한 보안 패치 {patch_info.critical_missing}개 미적용")
            recommendations.append("즉시 보안 업데이트 적용 필요")
        elif patch_info.patch_level == "outdated":
            score -= 30
            issues.append(f"업데이트 {patch_info.pending_updates}개 대기 중")
            recommendations.append("보안 업데이트 적용 권장")
        elif patch_info.patch_level == "updates_available":
            score -= 15
            issues.append(f"업데이트 {patch_info.pending_updates}개 가능")
            recommendations.append("정기적인 업데이트 적용 권장")

        if patch_info.last_update_days > 60:
            score -= 20
            issues.append(f"마지막 업데이트 {patch_info.last_update_days}일 경과")

        return max(score, 0), issues, recommendations

    def score_security_software(
        self, sec: SecuritySoftwareInfo
    ) -> tuple[int, list[str], list[str]]:
        """보안 소프트웨어 점수 계산 (0-100)"""
        score = 0
        issues: list[str] = []
        recommendations: list[str] = []

        if sec.antivirus_running:
            score += 30
        else:
            issues.append("안티바이러스 미실행")
            recommendations.append("안티바이러스 활성화 필요")

        if sec.firewall_enabled:
            score += 25
        else:
            issues.append("방화벽 비활성화")
            recommendations.append("방화벽 활성화 필요")

        if sec.encryption_enabled:
            score += 30
        else:
            issues.append("디스크 암호화 비활성화")
            recommendations.append("전체 디스크 암호화 활성화 필요")

        if sec.edr_running:
            score += 15
        else:
            issues.append("EDR 솔루션 미감지")
            recommendations.append("EDR 솔루션 도입 권장")

        return score, issues, recommendations

    def score_hardware(self, hw: HardwareInfo) -> tuple[int, list[str], list[str]]:
        """하드웨어 점수 계산 (0-100)"""
        score = 100
        issues: list[str] = []
        recommendations: list[str] = []

        if hw.total_memory_gb > 0 and hw.free_memory_gb / hw.total_memory_gb < 0.1:
            score -= 20
            issues.append("메모리 사용량 90% 초과")
            recommendations.append("불필요한 프로세스 종료 권장")

        if hw.disk_total_gb > 0 and hw.disk_free_gb / hw.disk_total_gb < 0.1:
            score -= 20
            issues.append("디스크 사용량 90% 초과")
            recommendations.append("디스크 공간 확보 필요")

        return max(score, 0), issues, recommendations

    def calculate_trust_score(self, scan_result: DeviceScanResult) -> TrustScore:
        """전체 신뢰 점수 계산"""
        result = TrustScore()

        os_score, os_issues, os_recs = self.score_os(scan_result.os_info)
        patch_score, patch_issues, patch_recs = self.score_patch(scan_result.patch_info)
        sec_score, sec_issues, sec_recs = self.score_security_software(scan_result.security_software)
        hw_score, hw_issues, hw_recs = self.score_hardware(scan_result.hardware)

        result.os_score = os_score
        result.patch_score = patch_score
        result.security_score = sec_score
        result.hardware_score = hw_score

        result.total_score = int(
            os_score * self.WEIGHTS["os"]
            + patch_score * self.WEIGHTS["patch"]
            + sec_score * self.WEIGHTS["security"]
            + hw_score * self.WEIGHTS["hardware"]
        )

        result.issues = os_issues + patch_issues + sec_issues + hw_issues
        result.recommendations = os_recs + patch_recs + sec_recs + hw_recs

        if result.total_score >= 75:
            result.trust_level = "TRUSTED"
        elif result.total_score >= 40:
            result.trust_level = "PARTIAL"
        else:
            result.trust_level = "UNTRUSTED"

        return result


def scan_current_device(verbose: bool = False) -> tuple[DeviceScanResult, TrustScore]:
    """현재 기기 스캔 및 신뢰 점수 계산"""
    collector = SystemInfoCollector()
    scorer = DeviceTrustScorer()

    scan = DeviceScanResult()
    scan.hostname = platform.node()

    tasks = {
        "os": collector.collect_os_info,
        "patch": collector.collect_patch_info,
        "security": collector.collect_security_software,
        "hardware": collector.collect_hardware_info,
    }

    logger.info("기기 정보 수집 시작...")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}

        for future in as_completed(futures):
            name = futures[future]
            try:
                info, errors = future.result()
                scan.raw_errors.extend(errors)

                if name == "os":
                    scan.os_info = info
                elif name == "patch":
                    scan.patch_info = info
                elif name == "security":
                    scan.security_software = info
                elif name == "hardware":
                    scan.hardware = info

                if verbose and errors:
                    for err in errors:
                        logger.warning(f"[{name}] {err}")

                logger.info(f"수집 완료: {name}")
            except Exception as e:
                logger.error(f"{name} 수집 실패: {e}")
                scan.raw_errors.append(str(e))

    trust = scorer.calculate_trust_score(scan)
    return scan, trust


def print_report(scan: DeviceScanResult, trust: TrustScore) -> None:
    """분석 결과 출력"""
    print("\n" + "=" * 60)
    print("기기 신뢰 점수 분석 보고서")
    print("=" * 60)
    print(f"호스트명   : {scan.hostname}")
    print(f"스캔 시간  : {scan.scan_time}")
    print(f"OS         : {scan.os_info.system} {scan.os_info.release}")
    print()
    print(f"총 신뢰 점수 : {trust.total_score}/100 [{trust.trust_level}]")
    print(f"  OS 점수    : {trust.os_score} (가중치 25%)")
    print(f"  패치 점수  : {trust.patch_score} (가중치 30%)")
    print(f"  보안 점수  : {trust.security_score} (가중치 35%)")
    print(f"  하드웨어   : {trust.hardware_score} (가중치 10%)")
    print()
    print(f"보안 소프트웨어:")
    print(f"  안티바이러스 : {'실행 중' if scan.security_software.antivirus_running else '미실행'}")
    print(f"  방화벽       : {'활성' if scan.security_software.firewall_enabled else '비활성'}")
    print(f"  디스크 암호화: {'활성' if scan.security_software.encryption_enabled else '비활성'}")
    print(f"  EDR          : {'감지됨' if scan.security_software.edr_running else '미감지'}")

    if trust.issues:
        print("\n발견된 문제:")
        for issue in trust.issues:
            print(f"  [!] {issue}")

    if trust.recommendations:
        print("\n권고사항:")
        for rec in trust.recommendations:
            print(f"  --> {rec}")

    print("=" * 60)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero Trust 디바이스 신뢰 점수 계산 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 현재 기기 스캔
  python device_trust_scorer.py --scan

  # 스캔 결과를 JSON으로 저장
  python device_trust_scorer.py --scan --output report.json

  # 기존 스캔 데이터로 점수 계산
  python device_trust_scorer.py --json-input device_info.json

  # 상세 로그 포함 스캔
  python device_trust_scorer.py --scan --verbose
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan", action="store_true", help="현재 기기 스캔 및 점수 계산")
    mode.add_argument("--json-input", metavar="FILE", help="JSON 입력 파일로 점수 계산")

    parser.add_argument("--output", metavar="FILE", help="결과 JSON 저장 경로")
    parser.add_argument("--verbose", action="store_true", help="상세 로그 출력")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.scan:
        scan, trust = scan_current_device(verbose=args.verbose)
    else:
        input_path = Path(args.json_input)
        if not input_path.exists():
            logger.error(f"파일을 찾을 수 없습니다: {args.json_input}")
            sys.exit(1)

        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)

        scan_data = data.get("scan", data)
        scan = DeviceScanResult(
            hostname=scan_data.get("hostname", "unknown"),
            os_info=OSInfo(**scan_data.get("os_info", {})),
            patch_info=PatchInfo(**scan_data.get("patch_info", {})),
            security_software=SecuritySoftwareInfo(**scan_data.get("security_software", {})),
            hardware=HardwareInfo(**scan_data.get("hardware", {})),
        )
        scorer = DeviceTrustScorer()
        trust = scorer.calculate_trust_score(scan)

    print_report(scan, trust)

    if args.output:
        output_data = {
            "scan": asdict(scan),
            "trust": asdict(trust),
        }
        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        logger.info(f"결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 7. 신원 거버넌스 및 관리 (IGA)

### 7.1 IGA 핵심 기능

| 기능 | 설명 |
|------|------|
| 접근 요청/승인 | 셀프서비스 포털, 워크플로우 기반 승인 |
| 접근 인증 (Certification) | 정기적 접근 권한 검토 및 재승인 |
| 역할 관리 (RBAC) | 역할 기반 권한 정의 및 할당 |
| 분리 의무 (SoD) | 이해충돌 권한 자동 감지 |
| 프로비저닝/디프로비저닝 | 입사/퇴사 시 자동 권한 부여/회수 |

### 7.2 JIT (Just-In-Time) 접근

특권 접근을 필요할 때만, 필요한 시간만큼만 부여한다.

```
요청: "DB 서버에 10분간 관리자 접근 필요"
승인: 자동 (ITSM 티켓 연동) 또는 관리자 승인
부여: 임시 자격 증명 발급 (10분 TTL)
만료: 자동 회수, 세션 로그 저장
```

---

## 8. 참고 자료

- FIDO Alliance: FIDO2/WebAuthn 사양 (https://fidoalliance.org)
- NIST SP 800-63B: Digital Identity Guidelines - Authentication
- Microsoft: Zero Trust Deployment Guide
- Okta: Zero Trust Security Whitepaper
- Google: BeyondCorp Enterprise 기술 문서
- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7636: PKCE for OAuth Public Clients

---

*최종 업데이트: 2024년*

---

<a name="english"></a>

# Identity and Device Trust

## 1. Identity Provider (IdP) Integration

### 1.1 Role of IdP

In Zero Trust, the IdP is the core component of the "new perimeter." It is the central authority that issues and verifies the identity of all users, devices, and services.

```
┌──────────────────────────────────────────────────────────┐
│                   IdP Ecosystem                           │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │  Okta    │    │ Azure AD │    │  Google Workspace │   │
│  │          │    │  (Entra) │    │       IdP        │   │
│  └─────┬────┘    └────┬─────┘    └────────┬─────────┘   │
│        └──────────────┼──────────────────┘             │
│                       │ SAML / OIDC / OAuth2            │
│                  ┌────▼──────┐                          │
│                  │  SP/RP    │ (Service Provider/Relying Party)│
│                  │ (App/Service)│                         │
│                  └───────────┘                          │
└──────────────────────────────────────────────────────────┘
```

### 1.2 Comparison of Major IdP Solutions

#### Okta

**Strengths:**
- Platform-neutral (not tied to a specific cloud)
- Integration with 6,500+ apps
- Powerful MFA options
- Okta Verify, FIDO2 support
- Provides Workforce Identity + Customer Identity

**Key Features:**
```
- Universal Directory: Unified management of all users/groups
- Adaptive MFA: Risk-based MFA enforcement
- Lifecycle Management: Automatic provisioning/deprovisioning
- API Access Management: OAuth server functionality
- Device Trust: Device trust policy integration
```

#### Azure Active Directory (Microsoft Entra ID)

**Strengths:**
- Native integration with Microsoft 365 and Azure
- Supports hybrid environments (on-premises AD + cloud)
- Powerful Conditional Access policies
- Risk-based access control with Entra ID Protection

**Key Features:**
```
- Conditional Access: Fine-grained access condition policies
- PIM (Privileged Identity Management): JIT privileged access
- Identity Protection: ML-based risk detection
- B2B/B2C: External partner and customer identity management
- Seamless SSO: Transparent Single Sign-On
```

#### Google Workspace IdP

**Strengths:**
- BeyondCorp-based design
- Built-in Context-Aware Access
- Native Google Cloud integration

**Key Features:**
```
- Google Sign-In / OIDC support
- Context-Aware Access: Device state, location-based policies
- Cloud Identity: Standalone IdP service
- BeyondCorp Enterprise: Complete Zero Trust solution
```

---

## 2. MFA and Passkeys (FIDO2)

### 2.1 MFA Authentication Factors

```
Authentication Factor Classification:
├── Knowledge-based (Something You Know)
│   ├── Password
│   ├── PIN
│   └── Security questions (not recommended)
│
├── Possession-based (Something You Have)
│   ├── TOTP (Google Authenticator, Authy)
│   ├── HOTP (hardware tokens)
│   ├── SMS OTP (vulnerable, not recommended)
│   ├── Push notifications (Okta Verify, MS Authenticator)
│   └── Hardware keys (YubiKey)
│
└── Inherence-based (Something You Are)
    ├── Fingerprint recognition
    ├── Facial recognition
    └── Retina/iris recognition
```

### 2.2 FIDO2/Passkey

FIDO2 is the standard for phishing-resistant MFA.

**Components:**
- **WebAuthn**: W3C standard, browser-server protocol
- **CTAP2**: Authenticator-client protocol

**How Passkeys Work:**
```
1. Registration:
   [Server] → Send challenge → [Authenticator (passkey)]
   [Authenticator] → Generate public key pair → Store public key on server
   [Authenticator] → Store private key on device/cloud

2. Authentication:
   [Server] → Send challenge → [Client]
   [Client] → Activate authenticator with biometrics/PIN
   [Authenticator] → Sign challenge with private key
   [Server] → Verify signature with public key → Authentication complete
```

**Advantages of Passkeys:**
| Property | Password+OTP | Passkey |
|----------|-------------|---------|
| Phishing resistance | Low | Very high (domain binding) |
| SIM swapping vulnerability | Yes (SMS OTP) | No |
| User convenience | Moderate | Very high |
| Credential reuse | Possible | Impossible |
| On server breach | Hash exposure risk | Only public key exposed |

### 2.3 Adaptive MFA

Dynamically adjusts MFA strength based on risk.

```
Low risk → Require biometrics only
Medium risk → Require additional TOTP
High risk → Require hardware key or deny
```

---

## 3. Device Trust Assessment

### 3.1 Device Trust Assessment Framework

```
Device Trust Assessment Items:
│
├── Managed State
│   ├── MDM enrollment (Intune, Jamf, Google MDM)
│   ├── EMM policy compliance
│   └── MDM certificate validity
│
├── OS Security Posture
│   ├── OS version (EOL version detection)
│   ├── Security patch level
│   ├── Secure Boot activation
│   └── Kernel integrity protection
│
├── Endpoint Security
│   ├── EDR/AV running state
│   ├── Last scan time
│   ├── Threat detection state
│   └── Firewall activation
│
├── Encryption State
│   ├── Full disk encryption (BitLocker/FileVault)
│   └── Storage encryption key protection
│
└── Certificate
    ├── Device certificate validity
    ├── Certificate expiry date
    └── PKI chain verification
```

### 3.2 MDM (Mobile Device Management)

#### Microsoft Intune
```
Policy Examples:
- Minimum OS version: Windows 11 22H2+
- BitLocker required
- Windows Defender running required
- Screen lock: within 5 minutes
- Password complexity: 8+ chars, special characters required
```

#### Jamf (macOS/iOS)
```
Policy Examples:
- FileVault required
- Gatekeeper activation
- SIP (System Integrity Protection) disabling prohibited
- Only certified apps allowed
```

### 3.3 Device Certificate

```
PKI-Based Device Trust:

CA (Certificate Authority)
└── Intermediate CA
    └── Device certificate issued
        ├── Subject: CN=DEVICE-ID, O=CORP
        ├── Validity: 1 year
        └── EKU: Client Authentication

Device Authentication Flow:
[Device] → Present TLS client certificate
[Server] → Verify certificate chain + CRL/OCSP check
[Server] → Cross-validate MDM enrollment status
[Server] → Allow/deny access
```

---

## 4. Conditional Access Policy

### 4.1 Concept

Conditional access controls access using if-then policies.

```
IF (all conditions are met)
THEN (allow/deny/require MFA/limit session)
```

### 4.2 Condition Types

| Condition Category | Example |
|-------------------|---------|
| User/Group | Specific department, role, guest account |
| Application | Specific SaaS app, on-premises app |
| Location | Country, IP range, Named Location |
| Device Platform | Windows, macOS, iOS, Android |
| Device State | Compliant, Hybrid AD Join |
| Client App | Browser, legacy auth clients |
| Sign-in Risk | Microsoft Entra ID Protection risk score |
| User Risk | Account breach risk score |

### 4.3 Policy Examples

**Example 1: Force MFA for external access**
```
IF location = external corporate network
AND app = Microsoft 365
THEN MFA required
```

**Example 2: Block non-compliant devices**
```
IF device state ≠ compliant
AND app = sensitive HR system
THEN block
```

**Example 3: Block legacy authentication**
```
IF client app = legacy authentication (Basic Auth)
THEN block
```

**Example 4: Country-based blocking**
```
IF location = [list of unapproved countries]
THEN block
```

---

## 5. Comparison of SAML, OAuth2, OIDC

### 5.1 SAML 2.0 (Security Assertion Markup Language)

**Purpose:** SSO (Single Sign-On), primarily enterprise web apps

**Flow:**
```
[User] → [SP (Service Provider)]
[SP] → SAML request → [IdP]
[User] → Authenticates at IdP
[IdP] → SAML Assertion (XML) → [SP]
[SP] → Verify Assertion → Allow access
```

**Characteristics:**
- XML-based (heavy)
- Mainly B2B enterprise
- Includes session management
- Disadvantage: Not suitable for mobile/API

### 5.2 OAuth 2.0

**Purpose:** Authorization delegation, API access

**Key Grant Types:**
```
Authorization Code (+ PKCE): Web apps, mobile apps (recommended)
Client Credentials: Server-to-server communication
Implicit: Legacy SPA (no longer recommended)
Device Code: TV, IoT devices
```

### 5.3 OIDC (OpenID Connect)

**Purpose:** Authentication — built on top of OAuth2

**OAuth2 vs OIDC:**
```
OAuth2: "Is it OK for this app to access your data?"
OIDC:   "Verifying who you are" + OAuth2
```

### 5.4 Comparison Summary

| Property | SAML 2.0 | OAuth 2.0 | OIDC |
|----------|----------|-----------|------|
| Main purpose | Auth+authz (SSO) | Authorization delegation | Authentication |
| Data format | XML | JSON/JWT | JSON/JWT |
| Mobile suitability | Low | High | High |
| API access | Unsuitable | Suitable | Suitable |
| Complexity | High | Medium | Medium |
| Enterprise adoption | Very high | High | High |

---

## 6. Identity Governance and Administration (IGA)

### 6.1 Core IGA Functions

| Function | Description |
|----------|-------------|
| Access request/approval | Self-service portal, workflow-based approval |
| Access certification | Periodic access rights review and re-approval |
| Role management (RBAC) | Role-based permission definition and assignment |
| Separation of duties (SoD) | Automatic detection of conflicting permissions |
| Provisioning/deprovisioning | Automatic permission grant/revocation on join/leave |

### 6.2 JIT (Just-In-Time) Access

Grant privileged access only when needed and only for the required time.

```
Request: "Need admin access to DB server for 10 minutes"
Approval: Automatic (ITSM ticket integration) or admin approval
Grant: Issue temporary credentials (10-minute TTL)
Expiry: Automatic revocation, session log saved
```

---

## 7. References

- FIDO Alliance: FIDO2/WebAuthn specifications (https://fidoalliance.org)
- NIST SP 800-63B: Digital Identity Guidelines - Authentication
- Microsoft: Zero Trust Deployment Guide
- Okta: Zero Trust Security Whitepaper
- Google: BeyondCorp Enterprise technical documentation
- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7636: PKCE for OAuth Public Clients

---

*Last updated: 2024*
