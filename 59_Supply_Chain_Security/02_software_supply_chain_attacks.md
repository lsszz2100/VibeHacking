> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 소프트웨어 공급망 공격 분석

## 0. 초보자를 위한 개념 이해

### 소프트웨어 공급망 공격이란?

소프트웨어 공급망 공격은 최종 타겟을 직접 공격하는 대신, 타겟이 신뢰하는 소프트웨어 공급업체나 오픈소스 라이브러리를 먼저 침해하여 악성 코드를 심는 간접 공격 방식이다. 타겟 회사의 보안이 아무리 뛰어나도, 신뢰하는 외부 소프트웨어가 이미 감염된 경우 막을 방법이 없다는 점에서 매우 위험하다.

**왜 배우는가:**
```
[공급망 공격의 전형적인 흐름]

공격자 목표: 대기업 A의 내부망 침투

직접 공격 (어려움):
공격자 → [대기업 A 방화벽/EDR/SOC] → 차단됨

공급망 공격 (우회):
공격자 → [소규모 소프트웨어 업체 B 침해]
           │ (보안이 약함, 공격 성공)
           ↓
       B의 업데이트 서버에 악성코드 삽입
           │
           ↓ (자동 업데이트)
대기업 A → "신뢰된 소프트웨어 업데이트" 설치
           │
           ↓
       내부망 침투 성공 (방화벽 우회)

결과: 신뢰 관계가 곧 공격 경로
```

### 핵심 개념 정리

```
주요 용어:
- 업스트림 공격: 소프트웨어 개발 상류(소스코드·빌드서버)를 침해하는 공격
- 업데이트 메커니즘 공격: 소프트웨어 업데이트 과정에 악성코드를 삽입
- 오픈소스 타이포스쿼팅: 유명 패키지 이름의 오타를 노린 악성 패키지 배포
- 악성 기여자(Malicious Maintainer): 오픈소스 관리자가 직접 악성코드 삽입
- 소셜 엔지니어링: 오픈소스 관리자를 속여 악성 PR을 병합하게 유도
- XZ Utils 사건(2024): 2년에 걸쳐 신뢰를 쌓은 후 백도어를 삽입한 사례
- 이벤트 스트림 사건(2018): npm 패키지 관리권 양도 후 악성코드 삽입 사례
```

### 필요한 도구 및 환경
- **Python 3.10+**: 패키지 메타데이터 분석
- **pip-audit / safety**: Python 패키지 취약점 검사
- **OSS Index**: 오픈소스 컴포넌트 취약점 데이터베이스
- **Snyk**: 오픈소스 보안 취약점 자동 탐지

### 기초 실습 예제
```python
import re
import hashlib
import json
from pathlib import Path

def analyze_package_risk(package_name: str, package_info: dict) -> dict:
    """
    패키지 위험 지표 분석 (공급망 공격 탐지 관점)
    실제 환경: PyPI API (https://pypi.org/pypi/{name}/json)로 조회
    """
    risk_indicators = []
    risk_score = 0

    # 1. 타이포스쿼팅 탐지 (유명 패키지와 유사한 이름)
    popular_packages = ["requests", "numpy", "pandas", "flask", "django",
                        "boto3", "cryptography", "pillow", "pyyaml"]
    for popular in popular_packages:
        # 레벤슈타인 거리 1~2인 경우 타이포스쿼팅 의심
        if (package_name != popular and
            abs(len(package_name) - len(popular)) <= 2 and
            sum(a != b for a, b in zip(package_name, popular)) <= 2):
            risk_indicators.append(f"타이포스쿼팅 의심: '{popular}'과 유사")
            risk_score += 40

    # 2. 신생 패키지 (출시 30일 미만)
    age_days = package_info.get("age_days", 100)
    if age_days < 30:
        risk_indicators.append(f"신생 패키지 ({age_days}일)")
        risk_score += 20

    # 3. 높은 권한 요청 (setup.py에 subprocess/os 사용)
    if package_info.get("uses_subprocess"):
        risk_indicators.append("설치 시 시스템 명령 실행")
        risk_score += 30

    # 4. 관리자 단독 (유지자 1명)
    maintainers = package_info.get("maintainers", 1)
    if maintainers == 1:
        risk_indicators.append("단일 관리자 (관리권 탈취 위험)")
        risk_score += 10

    # 5. 최근 갑작스러운 버전 업로드
    if package_info.get("sudden_update"):
        risk_indicators.append("갑작스러운 버전 업데이트")
        risk_score += 25

    return {
        "package": package_name,
        "risk_score": min(risk_score, 100),
        "risk_level": "높음" if risk_score >= 50 else "중간" if risk_score >= 20 else "낮음",
        "indicators": risk_indicators,
    }

# 테스트 샘플
test_packages = [
    ("requests",    {"age_days": 4000, "maintainers": 5,  "uses_subprocess": False}),
    ("requsets",    {"age_days": 5,    "maintainers": 1,  "uses_subprocess": True}),   # 타이포
    ("numpy",       {"age_days": 5000, "maintainers": 20, "uses_subprocess": False}),
    ("numpay",      {"age_days": 10,   "maintainers": 1,  "uses_subprocess": True}),   # 타이포
    ("mylib-utils", {"age_days": 15,   "maintainers": 1,  "sudden_update": True}),
]

print("=== 패키지 공급망 위험 분석 ===\n")
for pkg_name, pkg_info in test_packages:
    result = analyze_package_risk(pkg_name, pkg_info)
    print(f"패키지: {result['package']:<20} | 위험도: {result['risk_level']:<4} ({result['risk_score']}점)")
    for indicator in result["indicators"]:
        print(f"  ⚠ {indicator}")
    if result["indicators"]:
        print()
```

---

## 1. 실제 공급망 공격 사례 분석

### 1.1 주요 사건 연표

| 연도 | 사건명 | 공격 유형 | 피해 규모 | 공격 기법 |
|------|--------|-----------|-----------|-----------|
| 2017 | NotPetya (M.E.Doc) | 업데이트 메커니즘 침해 | 전 세계 $10B 이상 | 우크라이나 회계 SW 업데이트 서버 침해 |
| 2018 | event-stream (npm) | 오픈소스 패키지 악성 코드 | 수백만 다운로드 | 유지관리자 계정 이전 후 악성 코드 삽입 |
| 2020 | SolarWinds SUNBURST | 빌드 시스템 침해 | 18,000+ 조직 | Orion 빌드 프로세스에 백도어 삽입 |
| 2020 | Octopus Scanner | CI/CD 공격 | GitHub 프로젝트 26개 | Maven 빌드 파일을 통한 확산 |
| 2021 | Codecov bash uploader | CI/CD 스크립트 변조 | 수천 개 회사 | bash uploader 스크립트에 환경 변수 탈취 코드 |
| 2021 | Kaseya VSA | RMM 소프트웨어 공격 | 1,500+ 기업 | 제로데이 취약점 + 자동 업데이트 악용 |
| 2021 | ua-parser-js (npm) | 계정 탈취 | 주간 8M 다운로드 | npm 계정 탈취 후 크립토마이너/백도어 삽입 |
| 2022 | PyTorch nightly (pip) | 의존성 혼란 | PyTorch 사용자 | torchtriton 내부 패키지명 PyPI 선점 |
| 2023 | 3CX Desktop App | 이중 공급망 공격 | 수만 개 기업 | X_TRADER 소프트웨어 통해 3CX 빌드 환경 침투 |
| 2024 | XZ Utils (liblzma) | 오픈소스 기여자 잠입 | systemd 기반 Linux | 사회공학으로 신뢰 획득 후 SSH 백도어 삽입 |

### 1.2 SolarWinds SUNBURST 상세 분석

| 항목 | 내용 |
|------|------|
| **공격 그룹** | APT29 (Cozy Bear, 러시아 SVR) |
| **침투 시점** | 2019년 10월 (탐지: 2020년 12월) |
| **공격 벡터** | SolarWinds Orion 빌드 환경 침해 |
| **지속 기간** | 약 14개월 |
| **피해 조직** | 미국 재무부, 국무부, NSA, FireEye 등 |
| **탐지 방법** | FireEye 자체 레드팀 도구 도난 탐지 |
| **핵심 기법** | DLL 사이드로딩, 도메인 생성 알고리즘, 합법적 트래픽 위장 |

### 1.3 XZ Utils 백도어 (CVE-2024-3094) 상세 분석

| 항목 | 내용 |
|------|------|
| **공격 그룹** | "Jia Tan" (신원 미상, 국가급 수준 의심) |
| **침투 방법** | 2년간 오픈소스 기여를 통해 신뢰 구축 |
| **악성 코드 위치** | liblzma 빌드 스크립트 (tarball에만 존재) |
| **영향 대상** | glibc 기반 systemd 시스템의 OpenSSH |
| **공격 효과** | 특정 RSA 키로 인증 없이 SSH 접근 가능 |
| **탐지 계기** | Andres Freund가 SSH 속도 저하 이상 발견 |
| **CVSS 점수** | 10.0 (Critical) |

---

## 2. 빌드 파이프라인 공격 벡터

| 공격 벡터 | 설명 | 탐지 지표 | 방어 방법 |
|-----------|------|-----------|-----------|
| **소스 코드 저장소 침해** | Git 저장소 직접 수정 | 비정상적인 커밋, 서명 없는 커밋 | Signed commits, branch protection |
| **빌드 스크립트 변조** | Makefile, CMakeLists, build.gradle 수정 | 스크립트 해시 변경 | 빌드 파일 무결성 검증 |
| **빌드 서버 침해** | CI/CD 서버 자체 루트킷 설치 | 비정상 프로세스, 외부 연결 | 격리된 빌드 환경, 에페머럴 빌더 |
| **외부 스크립트 인라인 실행** | `curl \| bash` 패턴 | 네트워크 연결 중 코드 실행 | 허용 목록 기반 외부 의존성 |
| **환경 변수 탈취** | CI 시크릿 환경 변수 exfiltration | 아웃바운드 연결, 시크릿 접근 로그 | 시크릿 마스킹, 최소 권한 |
| **아티팩트 저장소 오염** | 빌드 결과물 변조 후 배포 | 체크섬 불일치 | 아티팩트 서명 및 검증 |
| **의존성 캐시 포이즈닝** | CI 캐시에 악성 패키지 삽입 | 캐시 무결성 오류 | 캐시 키 해시 검증 |

---

## 3. CI/CD 시스템별 취약점

### 3.1 GitHub Actions

| 취약점 유형 | 설명 | 위험도 | 예시 |
|-------------|------|--------|------|
| **스크립트 인젝션** | PR 제목/브랜치명이 run 명령에 그대로 삽입 | 높음 | `run: echo "${{ github.event.pull_request.title }}"` |
| **타사 액션 신뢰** | 검증되지 않은 Actions 사용 | 높음 | `uses: random-user/action@main` |
| **GITHUB_TOKEN 과다 권한** | 불필요한 write 권한 부여 | 중간 | `permissions: write-all` |
| **self-hosted runner 오염** | 공유 러너 환경 지속성 | 높음 | 이전 워크플로우 아티팩트 잔존 |
| **환경 변수 마스킹 우회** | 인코딩을 통한 시크릿 출력 | 중간 | base64/hex 인코딩으로 출력 |
| **워크플로우 파일 변조** | 포크 PR을 통한 `.github/workflows` 수정 | 중간 | pull_request_target 오용 |

### 3.2 Jenkins

| 취약점 유형 | 위험도 | 설명 |
|-------------|--------|------|
| **Groovy 스크립트 실행** | 매우 높음 | 파이프라인 스크립트가 Groovy로 마스터에서 실행 |
| **플러그인 취약점** | 높음 | 오래된 플러그인의 알려진 CVE |
| **자격증명 관리 취약점** | 높음 | Credentials Plugin 암호화 우회 |
| **빌드 로그 노출** | 중간 | 환경 변수가 로그에 기록 |
| **워크스페이스 공유** | 중간 | 다중 빌드 간 아티팩트 잔존 |

### 3.3 GitLab CI

| 취약점 유형 | 위험도 | 설명 |
|-------------|--------|------|
| **include 지시자 남용** | 높음 | 외부 YAML 파일 무제한 포함 |
| **러너 토큰 노출** | 높음 | 등록 토큰 CI 변수 노출 |
| **protected 변수 우회** | 중간 | 보호되지 않은 브랜치로 변수 접근 |
| **아티팩트 경로 순회** | 중간 | 아티팩트 경로에 `../` 포함 |

---

## 4. Python CLI: CI/CD 파이프라인 보안 스캐너

```python
#!/usr/bin/env python3
"""
CI/CD 파이프라인 보안 스캐너
지원 대상: GitHub Actions, Jenkins, GitLab CI
탐지 항목: 악성 패턴, 시크릿 노출, 과다 권한, 스크립트 인젝션
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ─────────────────────────── 데이터 클래스 ───────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    """보안 취약점 발견 항목"""
    file_path: Path
    line_number: int
    severity: Severity
    rule_id: str
    title: str
    description: str
    snippet: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    """스캔 결과 전체"""
    scan_type: str
    repo_path: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scan_errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


# ─────────────────────────── 탐지 규칙 ───────────────────────────

@dataclass
class Rule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    remediation: str


COMMON_RULES: list[Rule] = [
    Rule(
        rule_id="SC001",
        title="curl|bash 파이프 패턴 탐지",
        pattern=re.compile(
            r"curl\s+.*\|\s*(bash|sh|zsh|fish|python|perl|ruby)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="원격 스크립트를 검증 없이 직접 실행합니다. 공급망 공격의 주요 진입점입니다.",
        remediation="스크립트를 먼저 다운로드하고 체크섬/서명 검증 후 실행하세요.",
    ),
    Rule(
        rule_id="SC002",
        title="wget|bash 파이프 패턴 탐지",
        pattern=re.compile(
            r"wget\s+.*\|\s*(bash|sh|zsh|python|perl)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="wget으로 내려받은 스크립트를 즉시 실행합니다.",
        remediation="먼저 파일로 저장하고 무결성 검증 후 실행하세요.",
    ),
    Rule(
        rule_id="SC003",
        title="하드코딩된 비밀키 패턴",
        pattern=re.compile(
            r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
            r"\s*[=:]\s*['\"]?[A-Za-z0-9+/=_\-]{8,}['\"]?",
        ),
        severity=Severity.HIGH,
        description="평문 비밀값이 CI/CD 설정 파일에 하드코딩되어 있습니다.",
        remediation="CI/CD 플랫폼의 시크릿/환경 변수 기능을 사용하세요.",
    ),
    Rule(
        rule_id="SC004",
        title="eval 동적 코드 실행",
        pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
        severity=Severity.HIGH,
        description="eval을 이용한 동적 코드 실행은 인젝션 공격에 취약합니다.",
        remediation="eval 사용을 피하고 직접적인 명령 실행을 사용하세요.",
    ),
    Rule(
        rule_id="SC005",
        title="sudo 비밀번호 없는 실행",
        pattern=re.compile(r"sudo\s+.*--no-password|-n\s+sudo|NOPASSWD"),
        severity=Severity.MEDIUM,
        description="비밀번호 없는 sudo는 권한 상승 공격에 악용될 수 있습니다.",
        remediation="최소 권한 원칙을 적용하고 sudo 범위를 최소화하세요.",
    ),
    Rule(
        rule_id="SC006",
        title="AWS 자격증명 패턴",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        description="AWS 액세스 키 ID가 노출되었습니다.",
        remediation="즉시 해당 키를 무효화하고 IAM 역할/OIDC를 사용하세요.",
    ),
    Rule(
        rule_id="SC007",
        title="GitHub PAT 패턴",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        severity=Severity.CRITICAL,
        description="GitHub Personal Access Token이 노출되었습니다.",
        remediation="즉시 토큰을 revoke하고 GitHub Secrets를 사용하세요.",
    ),
    Rule(
        rule_id="SC008",
        title="chmod 777 위험한 권한",
        pattern=re.compile(r"chmod\s+([-]?R\s+)?777"),
        severity=Severity.MEDIUM,
        description="chmod 777은 모든 사용자에게 실행 권한을 부여합니다.",
        remediation="최소 필요 권한만 부여하세요 (예: 755 또는 644).",
    ),
]

GITHUB_ACTIONS_RULES: list[Rule] = [
    Rule(
        rule_id="GHA001",
        title="스크립트 인젝션 위험: github.event 변수 직접 사용",
        pattern=re.compile(
            r"\$\{\{\s*github\.event\.(pull_request\.(title|body|head\.ref)|"
            r"issue\.(title|body)|comment\.body)\s*\}\}",
        ),
        severity=Severity.HIGH,
        description="사용자 입력값이 run 명령에 직접 삽입되어 스크립트 인젝션이 가능합니다.",
        remediation="환경 변수로 먼저 받고 쉘에서 사용하거나 toJSON()으로 이스케이프하세요.",
    ),
    Rule(
        rule_id="GHA002",
        title="타사 Action 버전 미고정 (latest/main)",
        pattern=re.compile(
            r"uses:\s+[^/]+/[^@]+@(?:main|master|latest|v\d+\s*$)",
            re.MULTILINE,
        ),
        severity=Severity.HIGH,
        description="가변 태그(main, master, latest)를 사용하면 액션이 예고 없이 변경될 수 있습니다.",
        remediation="커밋 SHA 해시로 버전을 고정하세요. 예: uses: actions/checkout@8ade135",
    ),
    Rule(
        rule_id="GHA003",
        title="write-all 권한 부여",
        pattern=re.compile(r"permissions:\s*write-all", re.IGNORECASE),
        severity=Severity.HIGH,
        description="모든 GITHUB_TOKEN 권한을 허용하는 것은 최소 권한 원칙 위반입니다.",
        remediation="필요한 최소 권한만 명시적으로 부여하세요.",
    ),
    Rule(
        rule_id="GHA004",
        title="pull_request_target + 체크아웃 위험 조합",
        pattern=re.compile(
            r"on:\s*.*pull_request_target.*\n.*\n.*checkout.*ref.*github\.event",
            re.DOTALL,
        ),
        severity=Severity.CRITICAL,
        description="pull_request_target에서 PR 코드를 체크아웃하면 시크릿 노출 위험이 있습니다.",
        remediation="pull_request_target 워크플로우에서는 PR 코드를 체크아웃하지 마세요.",
    ),
]

GITLAB_CI_RULES: list[Rule] = [
    Rule(
        rule_id="GL001",
        title="외부 include 파일 사용",
        pattern=re.compile(r"include:\s*\n\s*-?\s*remote:", re.MULTILINE),
        severity=Severity.MEDIUM,
        description="원격 파일 포함은 외부 의존성을 만들고 변조 위험이 있습니다.",
        remediation="내부 저장소의 파일을 사용하거나 파일 해시를 검증하세요.",
    ),
    Rule(
        rule_id="GL002",
        title="allow_failure: true 남용",
        pattern=re.compile(r"allow_failure:\s*true", re.IGNORECASE),
        severity=Severity.LOW,
        description="보안 스캔 단계에서 실패 허용 시 취약점이 무시될 수 있습니다.",
        remediation="보안 관련 job에는 allow_failure: false를 명시적으로 설정하세요.",
    ),
]

JENKINS_RULES: list[Rule] = [
    Rule(
        rule_id="JK001",
        title="sh 명령에 변수 직접 보간",
        pattern=re.compile(r'sh\s+["\'].*\$\{[^}]+\}.*["\']'),
        severity=Severity.HIGH,
        description="Groovy 변수가 sh 명령에 직접 보간되어 인젝션 위험이 있습니다.",
        remediation="withEnv를 사용하거나 변수를 적절히 이스케이프하세요.",
    ),
    Rule(
        rule_id="JK002",
        title="credentials 평문 사용",
        pattern=re.compile(r"withCredentials.*string.*variable.*="),
        severity=Severity.INFO,
        description="자격증명 변수 사용을 확인하세요. 출력/로깅 여부를 점검하세요.",
        remediation="자격증명이 로그에 출력되지 않도록 마스킹을 확인하세요.",
    ),
]


# ─────────────────────────── 스캐너 ───────────────────────────

class BaseScanner:
    """스캐너 기본 클래스"""

    def __init__(self, repo_path: Path, extra_rules: list[Rule] | None = None):
        self.repo_path = repo_path
        self.rules = COMMON_RULES + (extra_rules or [])

    def scan_text(self, text: str, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line_number=line_no,
                            severity=rule.severity,
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=rule.description,
                            snippet=line.strip()[:200],
                            remediation=rule.remediation,
                        )
                    )
        return findings

    def scan_files(self, glob_pattern: str) -> ScanResult:
        result = ScanResult(scan_type=self.__class__.__name__, repo_path=self.repo_path)
        for file_path in self.repo_path.rglob(glob_pattern):
            if any(
                part.startswith(".") or part in ("node_modules", "__pycache__", "vendor")
                for part in file_path.parts
                if part != file_path.parts[0]
            ):
                continue
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
                result.findings.extend(self.scan_text(text, file_path))
                result.scanned_files += 1
            except OSError as exc:
                result.scan_errors.append(f"{file_path}: {exc}")
        return result


class GitHubActionsScanner(BaseScanner):
    def __init__(self, repo_path: Path):
        super().__init__(repo_path, GITHUB_ACTIONS_RULES)

    def scan(self) -> ScanResult:
        result = ScanResult(scan_type="github-actions", repo_path=self.repo_path)
        workflow_dir = self.repo_path / ".github" / "workflows"
        if not workflow_dir.exists():
            result.scan_errors.append(f".github/workflows 디렉토리 없음: {workflow_dir}")
            return result

        for yml_file in list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")):
            try:
                text = yml_file.read_text(encoding="utf-8")
                result.findings.extend(self.scan_text(text, yml_file))
                result.scanned_files += 1
            except OSError as exc:
                result.scan_errors.append(str(exc))
        return result


class JenkinsScanner(BaseScanner):
    def __init__(self, repo_path: Path):
        super().__init__(repo_path, JENKINS_RULES)

    def scan(self) -> ScanResult:
        result = ScanResult(scan_type="jenkins", repo_path=self.repo_path)
        for pattern in ("Jenkinsfile", "*.jenkinsfile", "Jenkinsfile.*"):
            for jfile in self.repo_path.rglob(pattern):
                try:
                    text = jfile.read_text(encoding="utf-8")
                    result.findings.extend(self.scan_text(text, jfile))
                    result.scanned_files += 1
                except OSError as exc:
                    result.scan_errors.append(str(exc))
        return result


class GitLabCIScanner(BaseScanner):
    def __init__(self, repo_path: Path):
        super().__init__(repo_path, GITLAB_CI_RULES)

    def scan(self) -> ScanResult:
        result = ScanResult(scan_type="gitlab", repo_path=self.repo_path)
        for pattern in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            ci_file = self.repo_path / pattern
            if ci_file.exists():
                try:
                    text = ci_file.read_text(encoding="utf-8")
                    result.findings.extend(self.scan_text(text, ci_file))
                    result.scanned_files += 1
                except OSError as exc:
                    result.scan_errors.append(str(exc))
        return result


# ─────────────────────────── 보고서 출력 ───────────────────────────

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",  # 빨간색
    Severity.HIGH:     "\033[93m",  # 노란색
    Severity.MEDIUM:   "\033[94m",  # 파란색
    Severity.LOW:      "\033[96m",  # 청록색
    Severity.INFO:     "\033[97m",  # 흰색
}
RESET = "\033[0m"


def print_findings(result: ScanResult, use_color: bool = True) -> None:
    print(f"\n{'='*60}")
    print(f"CI/CD 보안 스캔 결과 ({result.scan_type})")
    print(f"저장소: {result.repo_path}")
    print(f"스캔 파일 수: {result.scanned_files}")
    print(f"{'='*60}\n")

    if not result.findings:
        print("[OK] 탐지된 취약점 없음\n")
    else:
        for finding in sorted(result.findings, key=lambda f: list(Severity)[0:].index(f.severity)):
            color = SEVERITY_COLOR.get(finding.severity, "") if use_color else ""
            reset = RESET if use_color else ""
            rel_path = finding.file_path.relative_to(result.repo_path) \
                if finding.file_path.is_relative_to(result.repo_path) \
                else finding.file_path
            print(f"{color}[{finding.severity.value}]{reset} {finding.rule_id}: {finding.title}")
            print(f"  파일: {rel_path}:{finding.line_number}")
            print(f"  설명: {finding.description}")
            if finding.snippet:
                print(f"  코드: {finding.snippet}")
            print(f"  조치: {finding.remediation}")
            print()

    summary = result.summary()
    print("─" * 40)
    print("심각도별 요약:")
    for sev in Severity:
        count = summary[sev.value]
        if count > 0:
            color = SEVERITY_COLOR.get(sev, "") if use_color else ""
            reset = RESET if use_color else ""
            print(f"  {color}{sev.value:10s}{reset}: {count}건")
    print(f"  {'합계':10s}: {len(result.findings)}건")

    if result.scan_errors:
        print("\n[오류 목록]")
        for err in result.scan_errors:
            print(f"  - {err}")


def export_json(result: ScanResult) -> str:
    data: dict[str, Any] = {
        "scan_type": result.scan_type,
        "repo_path": str(result.repo_path),
        "scanned_files": result.scanned_files,
        "summary": result.summary(),
        "findings": [
            {
                "file": str(f.file_path),
                "line": f.line_number,
                "severity": f.severity.value,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "snippet": f.snippet,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "errors": result.scan_errors,
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─────────────────────────── CLI ───────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cicd-scanner",
        description="CI/CD 파이프라인 보안 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 02_software_supply_chain_attacks.py --repo-path .
  python3 02_software_supply_chain_attacks.py --repo-path /srv/repo --scan-type github-actions
  python3 02_software_supply_chain_attacks.py --repo-path . --output-json report.json
        """,
    )
    parser.add_argument(
        "--repo-path",
        type=Path,
        default=Path("."),
        metavar="PATH",
        help="스캔할 저장소 경로 (기본값: 현재 디렉토리)",
    )
    parser.add_argument(
        "--scan-type",
        choices=["github-actions", "jenkins", "gitlab", "all"],
        default="all",
        metavar="TYPE",
        help="스캔 유형 (github-actions | jenkins | gitlab | all)",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="JSON 형식 보고서 출력 파일",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="색상 출력 비활성화",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "any"],
        default=None,
        metavar="SEVERITY",
        help="해당 심각도 이상 발견 시 종료 코드 1 반환",
    )
    return parser


def severity_meets_threshold(findings: list[Finding], threshold: str) -> bool:
    threshold_order = ["low", "medium", "high", "critical"]
    if threshold == "any":
        return len(findings) > 0
    threshold_idx = threshold_order.index(threshold)
    for f in findings:
        finding_idx = threshold_order.index(f.severity.value.lower())
        if finding_idx >= threshold_idx:
            return True
    return False


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    repo_path: Path = args.repo_path.resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"[오류] 유효하지 않은 저장소 경로: {repo_path}", file=sys.stderr)
        return 1

    scanners: dict[str, type[BaseScanner]] = {
        "github-actions": GitHubActionsScanner,
        "jenkins": JenkinsScanner,
        "gitlab": GitLabCIScanner,
    }

    to_run = list(scanners.keys()) if args.scan_type == "all" else [args.scan_type]
    all_findings: list[Finding] = []
    combined_result = ScanResult(scan_type=args.scan_type, repo_path=repo_path)

    for scan_name in to_run:
        scanner = scanners[scan_name](repo_path)  # type: ignore[abstract]
        result = scanner.scan()  # type: ignore[union-attr]
        combined_result.findings.extend(result.findings)
        combined_result.scanned_files += result.scanned_files
        combined_result.scan_errors.extend(result.scan_errors)
        all_findings.extend(result.findings)

    print_findings(combined_result, use_color=not args.no_color)

    if args.output_json:
        try:
            args.output_json.write_text(export_json(combined_result), encoding="utf-8")
            print(f"\n[저장] JSON 보고서: {args.output_json}", file=sys.stderr)
        except OSError as exc:
            print(f"[오류] JSON 저장 실패: {exc}", file=sys.stderr)

    if args.fail_on and severity_meets_threshold(all_findings, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. 빌드 파이프라인 보안 강화 체크리스트

| 범주 | 점검 항목 | 우선순위 |
|------|-----------|----------|
| **소스 제어** | 모든 커밋 서명 (GPG/SSH) 요구 | 높음 |
| **소스 제어** | 브랜치 보호 규칙 + 최소 2인 리뷰 | 높음 |
| **빌드 환경** | 에페머럴(일회성) 빌드 환경 사용 | 높음 |
| **빌드 환경** | 재현 가능한 빌드(Reproducible Build) 구현 | 중간 |
| **의존성** | 허용 목록 기반 의존성 레지스트리 | 높음 |
| **의존성** | 의존성 버전 고정 + 체크섬 검증 | 높음 |
| **시크릿 관리** | CI 환경 변수 최소화 + 마스킹 | 높음 |
| **시크릿 관리** | 단기 자격증명(OIDC) 사용 | 중간 |
| **아티팩트** | 빌드 아티팩트 서명 | 중간 |
| **아티팩트** | SLSA Provenance 생성 | 중간 |
| **모니터링** | 빌드 로그 이상 행위 탐지 | 중간 |
| **거버넌스** | 외부 Action/플러그인 승인 프로세스 | 낮음 |


<!-- detect-validate-59 -->
## 변조 탐지 검증 — 산출물 무결성이 실제로 검증되는가

공급망 공격 대응은 *사례를 안다*가 아니라 **배포 패키지·이미지의 해시/서명이 설치 시점에 실제 검증되고, 변조본이 거부되는가**로 판정한다. 검증은 **소유 파이프라인**에서만.

### 항목 → 실패 모드 → 검증 방법 → 양호 신호

| 항목 | 실패 모드 | 검증 방법 | 양호 신호 |
|---|---|---|---|
| 해시 고정 | 미고정 다운로드 | 설치 매니페스트 확인 | 무결성 다이제스트 강제 |
| 서명 검증 | 서명 미확인 | cosign verify | 신뢰서명만 통과 |
| 빌드 재현성 | 비결정 빌드 | 2회 빌드 비교 | 동일 다이제스트 |
| 변조 거부 | 경고만 출력 | 변조본 주입(테스트) | 설치 실패 처리 |

### 방어 검증 (직접 확인)

```bash
# 1) 컨테이너 이미지 서명이 실제 검증되는지 — 소유 레지스트리에서만
cosign verify --key cosign.pub registry.local/app:tag 2>&1 | grep -Ei 'verified|error' || echo "wire cosign verify into deploy"
# 2) 의존성이 무결성 다이제스트로 고정됐는지(미고정이면 변조 무방비)
grep -E 'integrity|sha512-|sha256:' package-lock.json 2>/dev/null | head || echo "no integrity hashes pinned"
```

> 검증은 반드시 **소유 파이프라인**에서만 한다. "공급망 공격을 안다"와 "변조본이 거부된다"는 다르다 — 서명·해시 검증으로 직접 확인한다([[35_Supply_Chain_Attacks]], [[06_Malware_Analysis]]).

---

<a name="english"></a>

# Software Supply Chain Attack Analysis

## 1. Real-World Supply Chain Attack Case Analysis

### 1.1 Key Incident Timeline

| Year | Incident | Attack Type | Impact | Technique |
|------|---------|-------------|--------|-----------|
| 2017 | NotPetya (M.E.Doc) | Update mechanism compromise | $10B+ worldwide | Compromised update server of Ukrainian accounting SW |
| 2018 | event-stream (npm) | Malicious code in open-source package | Millions of downloads | Malicious code inserted after maintainer account transfer |
| 2020 | SolarWinds SUNBURST | Build system compromise | 18,000+ organizations | Backdoor injected into Orion build process |
| 2020 | Octopus Scanner | CI/CD attack | 26 GitHub projects | Spread via Maven build files |
| 2021 | Codecov bash uploader | CI/CD script tampering | Thousands of companies | Env variable exfiltration code in bash uploader script |
| 2021 | Kaseya VSA | RMM software attack | 1,500+ companies | Zero-day + auto-update abuse |
| 2021 | ua-parser-js (npm) | Account takeover | 8M weekly downloads | Crypto miner/backdoor inserted after npm account hijack |
| 2022 | PyTorch nightly (pip) | Dependency confusion | PyTorch users | Internal package name `torchtriton` preempted on PyPI |
| 2023 | 3CX Desktop App | Double supply chain attack | Tens of thousands of companies | 3CX build environment compromised via X_TRADER software |
| 2024 | XZ Utils (liblzma) | Open-source contributor infiltration | glibc-based Linux with systemd | SSH backdoor inserted after gaining trust through social engineering |

### 1.2 SolarWinds SUNBURST Detailed Analysis

| Aspect | Details |
|--------|---------|
| **Attack Group** | APT29 (Cozy Bear, Russian SVR) |
| **Breach Time** | October 2019 (detected: December 2020) |
| **Attack Vector** | SolarWinds Orion build environment compromise |
| **Duration** | Approximately 14 months |
| **Affected Organizations** | US Treasury, State Department, NSA, FireEye, etc. |
| **Detection Method** | FireEye detected theft of their own red team tools |
| **Key Techniques** | DLL sideloading, domain generation algorithm, legitimate traffic masquerade |

### 1.3 XZ Utils Backdoor (CVE-2024-3094) Detailed Analysis

| Aspect | Details |
|--------|---------|
| **Attack Group** | "Jia Tan" (unknown identity, suspected nation-state level) |
| **Infiltration Method** | Built trust through 2 years of open-source contributions |
| **Malware Location** | liblzma build script (only in tarball) |
| **Affected Targets** | OpenSSH on glibc-based systemd systems |
| **Attack Effect** | SSH access without authentication using a specific RSA key |
| **Detection** | Andres Freund noticed abnormal SSH slowdown |
| **CVSS Score** | 10.0 (Critical) |

---

## 2. Build Pipeline Attack Vectors

| Attack Vector | Description | Detection Indicators | Defense Methods |
|--------------|-------------|---------------------|-----------------|
| **Source code repository compromise** | Direct modification of Git repository | Abnormal commits, unsigned commits | Signed commits, branch protection |
| **Build script tampering** | Modification of Makefile, CMakeLists, build.gradle | Build file hash changes | Build file integrity verification |
| **Build server compromise** | Rootkit installation on CI/CD server itself | Abnormal processes, external connections | Isolated build environments, ephemeral builders |
| **Inline execution of external scripts** | `curl \| bash` pattern | Code execution during network connection | Allowlist-based external dependencies |
| **Environment variable exfiltration** | CI secret environment variable exfiltration | Outbound connections, secret access logs | Secret masking, least privilege |
| **Artifact repository poisoning** | Tampered build artifacts released | Checksum mismatch | Artifact signing and verification |
| **Dependency cache poisoning** | Malicious package inserted into CI cache | Cache integrity errors | Cache key hash verification |

---

## 3. Vulnerabilities by CI/CD System

See the Korean section for detailed tool-specific vulnerabilities and Python code.

---

## 5. Build Pipeline Security Hardening Checklist

| Category | Check Item | Priority |
|----------|-----------|----------|
| **Source Control** | Require all commits to be signed (GPG/SSH) | High |
| **Source Control** | Branch protection rules + minimum 2-person review | High |
| **Build Environment** | Use ephemeral (one-time) build environments | High |
| **Build Environment** | Implement reproducible builds | Medium |
| **Dependencies** | Allowlist-based dependency registry | High |
| **Dependencies** | Pin dependency versions + checksum verification | High |
| **Secret Management** | Minimize CI environment variables + masking | High |
| **Secret Management** | Use short-lived credentials (OIDC) | Medium |
| **Artifacts** | Sign build artifacts | Medium |
| **Artifacts** | Generate SLSA Provenance | Medium |
| **Monitoring** | Detect anomalous behavior in build logs | Medium |
| **Governance** | Approval process for external Actions/plugins | Low |

<!-- detect-validate-59 -->
## Tamper-Detection Validation — Is Artifact Integrity Actually Verified?

Defending against supply-chain attacks is judged not by *knowing the case studies* but by **whether package/image hashes and signatures are actually verified at install time and tampered artifacts are rejected**. Validate only on **owned pipelines**.

### Item -> Failure mode -> Validation method -> Healthy signal

| Item | Failure mode | Validation method | Healthy signal |
|---|---|---|---|
| Hash pinning | Unpinned download | Check install manifest | Integrity digest enforced |
| Signature verify | Signature unchecked | cosign verify | Only trusted sig passes |
| Reproducibility | Non-deterministic build | Build twice, compare | Identical digest |
| Tamper reject | Warns only | Inject tampered (test) | Install fails closed |

### Defense validation (verify directly)

```bash
# 1) Whether the container image signature is actually verified — owned registry only
cosign verify --key cosign.pub registry.local/app:tag 2>&1 | grep -Ei 'verified|error' || echo "wire cosign verify into deploy"
# 2) Whether deps are pinned by integrity digest (unpinned = open to tampering)
grep -E 'integrity|sha512-|sha256:' package-lock.json 2>/dev/null | head || echo "no integrity hashes pinned"
```

> Validate only on **owned pipelines**. "Knowing the attack" differs from "tampered artifacts get rejected" — confirm directly via signature/hash verification ([[35_Supply_Chain_Attacks]], [[06_Malware_Analysis]]).
