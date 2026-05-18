# 05 — Zero Trust 성숙도 평가 및 운영

## 목차
1. Zero Trust 성숙도 모델 심화
2. ID 중심 Zero Trust 운영
3. 디바이스 신뢰 평가 체계
4. 네트워크 액세스 제어 고도화
5. 지속적 권한 검증 (CAE)
6. Zero Trust 운영 자동화
7. Python 도구: Zero Trust 설정 감사기
8. Zero Trust 성숙도 KPI 및 측정

---

## 1. Zero Trust 성숙도 모델 심화

### 1.1 CISA Zero Trust Maturity Model v2.0

미국 사이버보안 인프라 보안국(CISA) 2023년 v2.0 기준 5개 기둥(Pillar) × 4단계.

```
5개 기둥 (Pillars):
  1. Identity     (ID 및 인증)
  2. Devices      (디바이스 신뢰)
  3. Networks     (네트워크 마이크로세분화)
  4. Applications (앱 워크로드 보호)
  5. Data         (데이터 분류 및 보호)

4단계 성숙도:
  Traditional → Initial → Advanced → Optimal

크로스 커팅 기능 (모든 기둥에 적용):
  - Visibility and Analytics (가시성 및 분석)
  - Automation and Orchestration (자동화 및 오케스트레이션)
  - Governance (거버넌스)
```

### 1.2 기둥별 Optimal 수준 요구사항

| 기둥 | Traditional | Optimal |
|------|-------------|---------|
| Identity | 정적 비밀번호 | 리스크 기반 지속 인증 + 비밀번호 없음 |
| Devices | 도메인 가입만 | 실시간 포스처 검증 + EDR 필수 |
| Networks | 경계 방화벽 | 마이크로세분화 + BeyondProd 모델 |
| Applications | VPN 접근 | ZTNA + 인라인 위협 방지 |
| Data | 파일 서버 ACL | 동적 DLP + 암호화 + 분류 자동화 |

### 1.3 DoD Zero Trust Reference Architecture

미 국방부의 Zero Trust 7계층 모델 (2022):

```
사용자 ─────────────────────────────────────────►
  │  디바이스 → 앱/워크로드 → 데이터 → 네트워크
  │  자동화 및 오케스트레이션
  │  가시성 및 분석
  └─────────────────────────────────────────────
     거버넌스 및 컴플라이언스 (Cross-Cutting)
```

---

## 2. ID 중심 Zero Trust 운영

### 2.1 IDaaS 플랫폼 기능 요구사항

```
필수 기능:
  □ MFA (FIDO2/WebAuthn 우선)
  □ 조건부 접근 정책 (Conditional Access)
  □ 리스크 기반 인증 (Risk-Based Authentication)
  □ SSO + SAML 2.0 / OIDC
  □ 특권 접근 관리 (PAM) 통합
  □ 게스트/파트너 ID 수명주기

리스크 신호 소스:
  - 로그인 위치 이상 탐지
  - 불가능한 이동 (Impossible Travel)
  - 다크웹 자격증명 유출 모니터링
  - 디바이스 포스처 점수
  - 사용자 행동 분석 (UEBA)
```

### 2.2 조건부 접근 정책 예시 (Azure AD / Entra ID)

```
정책 1: 미관리 디바이스 → MFA 필수 + 앱 제한
  조건: device.isCompliant = false
  제어: MFA 요구 + 앱 보호 정책 적용

정책 2: 높은 리스크 로그인 → 비밀번호 재설정 강제
  조건: signInRiskLevel = high
  제어: 비밀번호 변경 후 세션 발급

정책 3: 레거시 인증 → 완전 차단
  조건: clientAppTypes = exchangeActiveSync, other
  제어: 차단 (Block)

정책 4: 관리자 계정 → 항상 MFA + Compliant 디바이스
  조건: userRole = GlobalAdmin OR SecurityAdmin
  제어: MFA + compliantDevice 모두 필요
```

### 2.3 FIDO2/WebAuthn 패스키(Passkey) 배포

```
패스키 장점:
  - 피싱 저항: 인증 바인딩 (Relying Party ID)
  - 비밀번호 없음: 생체인증 또는 PIN
  - MITM 방지: 서명 기반 챌린지-응답

배포 단계:
  1. IdP에서 FIDO2 활성화
  2. 사용자 패스키 등록 캠페인
  3. SMS OTP 폴백 비활성화
  4. 하드웨어 키 발급 (관리자 계정)
  5. 정기 패스키 회수 절차 수립
```

---

## 3. 디바이스 신뢰 평가 체계

### 3.1 디바이스 포스처 점수 구성

```
디바이스 신뢰 점수 = f(하드웨어, OS, 소프트웨어, 행동)

구성 요소:
  하드웨어 (25%):
    + TPM 2.0 존재: +10점
    + Secure Boot 활성화: +8점
    + BitLocker/FileVault 암호화: +7점

  OS 상태 (30%):
    + 최신 패치 (30일 이내): +15점
    + 방화벽 활성화: +8점
    + 최신 안티바이러스: +7점

  에이전트 상태 (25%):
    + EDR 에이전트 실행 중: +15점
    + MDM 등록됨: +10점

  행동 패턴 (20%):
    - 최근 이상 탐지: -10점/건
    - 비업무 시간 접근: -5점
```

### 3.2 MDM 정책 (Microsoft Intune 예시)

```
규정 준수 정책:
  OS 최소 버전: Windows 11 22H2+
  BitLocker: 필수
  Windows Defender: 실시간 보호 필수
  방화벽: 활성화 필수
  TPM: 2.0 필수

비규정 준수 시 조치:
  즉시: 이메일 알림 발송
  3일 후: 조건부 접근 차단
  7일 후: 디바이스 원격 초기화 (분실/도난 시)

앱 보호 정책 (MAM):
  - 앱 간 복붙 차단
  - 스크린샷 차단
  - PIN 요구 (5분 유휴 후)
  - 회사 데이터 원격 초기화 가능
```

---

## 4. 네트워크 액세스 제어 고도화

### 4.1 Software-Defined Perimeter (SDP)

```
전통 VPN vs SDP 비교:

VPN:                          SDP (ZTNA):
─────────────────            ─────────────────────────
IP 기반 터널                   앱별 마이크로터널
연결 후 광범위 접근             인증 후 특정 앱만 접근
항상 연결됨                    필요 시 연결 (Just-in-Time)
내부 네트워크 가시적             내부 인프라 숨김 (Dark Cloud)
단일 인증 포인트                지속적 인증
```

### 4.2 마이크로세분화 구현 패턴

```
패턴 1: 에이전트 기반 (Host-based)
  - 각 서버에 에이전트 설치
  - OS 방화벽 규칙 중앙 관리
  - 도구: Illumio, Guardicore (Akamai)
  - 장점: 클라우드/온프레미스 일관성
  - 단점: 에이전트 관리 오버헤드

패턴 2: 네트워크 기반 (Network Enforcement)
  - SDN 또는 스위치 레벨 정책
  - VLAN + ACL 동적 변경
  - 도구: Cisco SD-Access, VMware NSX
  - 장점: 에이전트 불필요
  - 단점: 물리 인프라 의존

패턴 3: 서비스 메시 (App/API 레벨)
  - 모든 서비스 통신에 mTLS
  - 사이드카 프록시 (Envoy)
  - 도구: Istio, Linkerd, Consul Connect
  - 장점: 앱 수준 가시성
  - 단점: 쿠버네티스 환경 의존
```

---

## 5. 지속적 권한 검증 (CAE)

### 5.1 Continuous Access Evaluation (CAE)

OAuth 2.0 기반 세션에서 이벤트 발생 시 즉시 토큰 무효화.

```
기존 모델:
  로그인 → 토큰 발급 (1시간) → 만료 전까지 유효
  문제: 계정 탈취 후 1시간 동안 접근 가능

CAE 모델:
  로그인 → 단기 토큰 발급 → CAE 이벤트 발생 시 즉시 재검증
  이벤트: 비밀번호 변경, 계정 비활성화, 리스크 상승, IP 변경
  결과: 실시간 세션 무효화 (< 1분)
```

### 5.2 JIT(Just-in-Time) 접근

```
일반 접근:
  사용자 → 항상 권한 보유 → 공격자도 항상 사용 가능

JIT 접근:
  사용자 → 접근 요청 → 승인 → 임시 권한 (30분) → 자동 만료
  
JIT 워크플로우:
  1. 사용자: 시스템 A 접근 요청 (사유, 기간)
  2. 관리자: Slack/이메일로 승인/거부
  3. 승인 시: IAM 정책 임시 추가 + 세션 기록 시작
  4. 만료 시: 권한 자동 제거 + 감사 로그 보존

도구:
  - CyberArk Endpoint Privilege Manager
  - BeyondTrust PAM
  - AWS IAM Identity Center (시간 제한 역할)
  - Microsoft PIM (Privileged Identity Management)
```

---

## 6. Zero Trust 운영 자동화

### 6.1 Zero Trust 오케스트레이션

```
트리거 → 탐지 → 자동 대응 워크플로우:

이벤트: 불가능한 이동 감지 (서울 로그인 → 5분 후 뉴욕 로그인)
  ↓
SIEM 알림 → SOAR 플레이북 실행
  ↓
1. 현재 세션 즉시 종료
2. 계정 임시 잠금 (2시간)
3. 사용자에게 SMS/이메일 알림
4. 보안팀 티켓 생성
5. 추가 MFA 요구 후 재로그인 허용
```

### 6.2 자동화 도구 스택

```
SIEM:       Splunk, Microsoft Sentinel, IBM QRadar
SOAR:       Palo Alto XSOAR, Splunk SOAR, IBM SOAR
IdP:        Okta, Azure AD (Entra), Ping Identity
PAM:        CyberArk, BeyondTrust, HashiCorp Vault
ZTNA:       Zscaler ZPA, Cloudflare Access, Palo Alto Prisma
MDM:        Microsoft Intune, Jamf, VMware Workspace ONE
Micro-seg:  Illumio, Guardicore, Prisma Cloud
```

---

## 7. Python 도구: Zero Trust 설정 감사기

```python
#!/usr/bin/env python3
"""
Zero Trust Policy Auditor
MFA, 조건부 접근, 권한 정책 설정의 Zero Trust 준수 여부 감사
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ZTFinding:
    pillar: str       # Identity | Devices | Network | Apps | Data
    severity: str     # CRITICAL | HIGH | MEDIUM | LOW
    check_id: str
    title: str
    description: str
    remediation: str
    reference: str = ""


@dataclass
class ZTAuditResult:
    findings: list[ZTFinding] = field(default_factory=list)

    def add(self, pillar: str, severity: str, check_id: str,
            title: str, description: str, remediation: str,
            reference: str = "") -> None:
        self.findings.append(ZTFinding(
            pillar, severity, check_id, title,
            description, remediation, reference,
        ))

    def score(self) -> int:
        """Zero Trust 성숙도 점수 (100점 만점, 발견사항으로 감점)"""
        deductions = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
        total = sum(deductions.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - total)


def audit_identity_config(cfg: dict[str, Any], result: ZTAuditResult) -> None:
    identity = cfg.get("identity", {})

    # MFA 설정
    mfa = identity.get("mfa", {})
    if not mfa.get("enabled"):
        result.add("Identity", "CRITICAL", "ID-001",
                   "MFA 비활성화",
                   "전체 사용자에게 MFA가 적용되지 않았습니다.",
                   "IdP에서 MFA를 전사 필수(Enforced)로 설정",
                   "CISA ZT Pillar: Identity — Initial 요건")

    # FIDO2 지원
    mfa_methods = mfa.get("methods", [])
    if "fido2" not in mfa_methods and "webauthn" not in mfa_methods:
        result.add("Identity", "HIGH", "ID-002",
                   "피싱 저항 MFA 미적용",
                   "FIDO2/WebAuthn이 MFA 방법에 포함되지 않았습니다. "
                   "SMS OTP/TOTP는 피싱에 취약합니다.",
                   "FIDO2 패스키 또는 하드웨어 키(YubiKey) 배포",
                   "NIST SP 800-63B AAL3")

    # SSO 설정
    if not identity.get("sso_enabled"):
        result.add("Identity", "HIGH", "ID-003",
                   "SSO 미적용",
                   "앱별 개별 인증으로 인해 자격증명 관리가 분산됩니다.",
                   "SAML 2.0 또는 OIDC 기반 SSO 도입")

    # 조건부 접근
    conditional_access = identity.get("conditional_access", {})
    if not conditional_access.get("enabled"):
        result.add("Identity", "HIGH", "ID-004",
                   "조건부 접근 정책 없음",
                   "리스크 기반 접근 제어가 없어 탈취된 자격증명 방어 불가.",
                   "리스크 레벨별 조건부 접근 정책 구성")

    # 특권 계정 관리
    pam = identity.get("pam", {})
    if not pam.get("jit_access"):
        result.add("Identity", "MEDIUM", "ID-005",
                   "JIT 특권 접근 미구현",
                   "관리자 계정이 항상 높은 권한을 보유합니다.",
                   "Microsoft PIM 또는 CyberArk PAM JIT 설정")

    # 레거시 인증 프로토콜
    if identity.get("legacy_auth_enabled"):
        result.add("Identity", "CRITICAL", "ID-006",
                   "레거시 인증 프로토콜 허용",
                   "Basic Auth, NTLM 등 레거시 프로토콜은 MFA 우회 가능.",
                   "Exchange 및 앱에서 레거시 인증 완전 차단")

    # 비밀번호 정책
    pw_policy = identity.get("password_policy", {})
    if pw_policy.get("min_length", 0) < 12:
        result.add("Identity", "MEDIUM", "ID-007",
                   "비밀번호 최소 길이 부족",
                   f"최소 길이 {pw_policy.get('min_length', 0)}자 — 권장: 12자 이상.",
                   "비밀번호 최소 12자, 복잡성 요건 강화")


def audit_device_config(cfg: dict[str, Any], result: ZTAuditResult) -> None:
    devices = cfg.get("devices", {})

    if not devices.get("mdm_enrolled_required"):
        result.add("Devices", "HIGH", "DEV-001",
                   "MDM 미등록 디바이스 접근 허용",
                   "관리되지 않는 디바이스에서 회사 리소스 접근 가능.",
                   "MDM 등록을 조건부 접근의 필수 조건으로 설정")

    if not devices.get("edr_required"):
        result.add("Devices", "HIGH", "DEV-002",
                   "EDR 에이전트 필수 요건 없음",
                   "엔드포인트 탐지/대응 솔루션 없이 접근 가능.",
                   "Defender for Endpoint/CrowdStrike 등 EDR 배포 필수화")

    if not devices.get("disk_encryption_required"):
        result.add("Devices", "HIGH", "DEV-003",
                   "디스크 암호화 미적용",
                   "분실/도난 시 데이터 노출 위험.",
                   "BitLocker(Windows)/FileVault(macOS) 필수 설정")

    compliance = devices.get("compliance_check", {})
    if not compliance.get("realtime"):
        result.add("Devices", "MEDIUM", "DEV-004",
                   "실시간 포스처 검증 없음",
                   "주기적 검사만으로는 공격 간격 동안 비규정 디바이스 접근 허용.",
                   "조건부 접근에 실시간 컴플라이언스 신호 연동")


def audit_network_config(cfg: dict[str, Any], result: ZTAuditResult) -> None:
    network = cfg.get("network", {})

    if not network.get("microsegmentation"):
        result.add("Network", "HIGH", "NET-001",
                   "마이크로세분화 미구현",
                   "플랫 네트워크 구조로 측면 이동(Lateral Movement) 용이.",
                   "워크로드별 마이크로세분화 정책 도입")

    if network.get("vpn_full_tunnel"):
        result.add("Network", "MEDIUM", "NET-002",
                   "VPN 풀 터널 사용",
                   "모든 트래픽이 VPN을 통해 내부 네트워크 전체에 접근 가능.",
                   "앱별 ZTNA로 전환하여 최소 접근 원칙 적용")

    if not network.get("dns_filtering"):
        result.add("Network", "MEDIUM", "NET-003",
                   "DNS 필터링 없음",
                   "악성 도메인으로의 통신이 탐지되지 않을 수 있음.",
                   "Umbrella/Cloudflare Gateway 등 DNS 필터링 도입")

    if not network.get("encrypted_internal_traffic"):
        result.add("Network", "HIGH", "NET-004",
                   "내부 트래픽 암호화 없음",
                   "내부 네트워크에서의 도청 가능.",
                   "서비스 메시(mTLS) 또는 IPsec으로 내부 암호화")


def audit_data_config(cfg: dict[str, Any], result: ZTAuditResult) -> None:
    data = cfg.get("data", {})

    if not data.get("classification_enabled"):
        result.add("Data", "HIGH", "DAT-001",
                   "데이터 분류 체계 없음",
                   "중요 데이터 식별 및 보호 정책 적용 불가.",
                   "데이터 분류 레이블 체계 구축 (공개/내부/기밀/극비)")

    if not data.get("dlp_enabled"):
        result.add("Data", "HIGH", "DAT-002",
                   "DLP(데이터 유출 방지) 미적용",
                   "중요 데이터의 비허가 외부 전송 탐지 불가.",
                   "Microsoft Purview DLP 또는 유사 솔루션 배포")

    if not data.get("encryption_at_rest"):
        result.add("Data", "CRITICAL", "DAT-003",
                   "저장 데이터 암호화 없음",
                   "스토리지 탈취 시 데이터 즉시 노출.",
                   "데이터베이스/스토리지 레벨 암호화 적용")

    if not data.get("backup_encrypted"):
        result.add("Data", "HIGH", "DAT-004",
                   "백업 데이터 암호화 없음",
                   "백업 탈취 시 데이터 복원 후 노출 가능.",
                   "백업에 AES-256 암호화 적용 및 오프사이트 저장")


def generate_report(result: ZTAuditResult, fmt: str) -> str:
    score = result.score()
    findings_by_pillar: dict[str, list[ZTFinding]] = {}
    for f in result.findings:
        findings_by_pillar.setdefault(f.pillar, []).append(f)

    if fmt == "json":
        return json.dumps({
            "zt_maturity_score": score,
            "maturity_level": _score_to_level(score),
            "total_findings": len(result.findings),
            "findings": [vars(f) for f in result.findings],
        }, ensure_ascii=False, indent=2)

    lines: list[str] = []
    lines.append("=" * 68)
    lines.append("Zero Trust 성숙도 감사 결과")
    lines.append("=" * 68)
    lines.append(f"\nZero Trust 성숙도 점수: {score}/100")
    lines.append(f"성숙도 레벨: {_score_to_level(score)}")
    lines.append(f"총 발견: {len(result.findings)}개\n")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for pillar in ("Identity", "Devices", "Network", "Apps", "Data"):
        pillar_findings = findings_by_pillar.get(pillar, [])
        if not pillar_findings:
            lines.append(f"[{pillar}] ✓ 문제 없음")
            continue

        lines.append(f"\n[{pillar} 기둥] {len(pillar_findings)}개 발견")
        lines.append("-" * 68)
        for f in sorted(pillar_findings, key=lambda x: sev_order.get(x.severity, 4)):
            lines.append(f"  [{f.severity}] {f.check_id}: {f.title}")
            lines.append(f"    설명: {f.description}")
            lines.append(f"    조치: {f.remediation}")

    return "\n".join(lines)


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "Advanced (고급)"
    if score >= 60:
        return "Intermediate (중급)"
    if score >= 40:
        return "Initial (초기)"
    return "Traditional (미적용)"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero Trust 설정 감사기 — 5개 기둥 준수 여부 분석",
    )
    parser.add_argument(
        "config",
        type=Path,
        help="Zero Trust 설정 파일 (JSON)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="결과 저장 파일",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.config.exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {args.config}", file=sys.stderr)
        sys.exit(1)

    try:
        cfg = json.loads(args.config.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[오류] JSON 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)

    result = ZTAuditResult()
    audit_identity_config(cfg, result)
    audit_device_config(cfg, result)
    audit_network_config(cfg, result)
    audit_data_config(cfg, result)

    report = generate_report(result, args.format)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"[완료] 결과 저장: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
```

**설정 파일 예시 (`zt_config.json`):**

```json
{
  "identity": {
    "mfa": {"enabled": true, "methods": ["totp", "sms"]},
    "sso_enabled": true,
    "conditional_access": {"enabled": false},
    "pam": {"jit_access": false},
    "legacy_auth_enabled": true,
    "password_policy": {"min_length": 8}
  },
  "devices": {
    "mdm_enrolled_required": true,
    "edr_required": false,
    "disk_encryption_required": true,
    "compliance_check": {"realtime": false}
  },
  "network": {
    "microsegmentation": false,
    "vpn_full_tunnel": true,
    "dns_filtering": false,
    "encrypted_internal_traffic": false
  },
  "data": {
    "classification_enabled": false,
    "dlp_enabled": false,
    "encryption_at_rest": true,
    "backup_encrypted": true
  }
}
```

---

## 8. Zero Trust 성숙도 KPI 및 측정

### 8.1 핵심 성과 지표

| KPI | 측정 방법 | 목표값 |
|-----|-----------|--------|
| MFA 커버리지 | MFA 적용 계정 / 전체 계정 | > 99% |
| 기기 관리 비율 | MDM 등록 기기 / 전체 기기 | > 95% |
| 레거시 인증 차단률 | 차단된 레거시 인증 / 전체 시도 | > 99% |
| 평균 세션 수명 | 활성 세션 평균 TTL | < 8시간 |
| JIT 접근 비율 | JIT 세션 / 전체 관리자 세션 | > 80% |
| 마이크로세분화 범위 | 정책 적용 워크로드 / 전체 | > 90% |
| 조건부 접근 차단 건수 | 월간 정책 차단 이벤트 | 추이 모니터링 |

### 8.2 Zero Trust 로드맵 단계

```
Phase 1 (0~3개월): 기반 구축
  □ 자산/ID 인벤토리 완성
  □ 전사 MFA 롤아웃
  □ MDM 등록 강제화
  □ 레거시 인증 차단

Phase 2 (3~6개월): 가시성 확보
  □ 조건부 접근 정책 구성
  □ SIEM 통합 및 대시보드
  □ 디바이스 포스처 점수 도입
  □ 네트워크 트래픽 가시성

Phase 3 (6~12개월): 정책 집행
  □ 마이크로세분화 파일럿
  □ JIT 특권 접근 도입
  □ ZTNA로 VPN 전환
  □ 데이터 분류 체계 적용

Phase 4 (12개월+): 최적화
  □ AI 기반 이상 탐지
  □ 완전 비밀번호 없는 인증
  □ 자동화 오케스트레이션
  □ 지속적 컴플라이언스 측정
```

---

## 참고 자료

- **CISA Zero Trust Maturity Model v2.0** — [https://www.cisa.gov/zero-trust-maturity-model](https://www.cisa.gov/zero-trust-maturity-model)
- **NIST SP 800-207** — Zero Trust Architecture 공식 문서
- **DoD Zero Trust Reference Architecture v2.0** — 미 국방부 ZTA 가이드
- **Google BeyondCorp** — 기업 네트워크 없는 Zero Trust 사례
- **Microsoft Zero Trust Guidance** — [https://aka.ms/zerotrust](https://aka.ms/zerotrust)
