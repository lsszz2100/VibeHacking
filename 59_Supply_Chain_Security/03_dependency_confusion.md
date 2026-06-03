> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 의존성 혼란 공격 (Dependency Confusion)

## 0. 초보자를 위한 개념 이해

### 의존성 혼란 공격이란?

의존성 혼란은 기업이 내부적으로만 사용하는 비공개 패키지 이름을 공개 패키지 레지스트리(PyPI, npm 등)에 더 높은 버전 번호로 업로드하는 공격이다. 빌드 도구가 내부 레지스트리보다 공개 레지스트리를 우선하면, 개발자가 모르는 사이에 공격자의 악성 패키지가 자동으로 설치된다. Alex Birsan이 2021년 이 기법으로 Apple, Microsoft, PayPal 등 35개 이상의 대기업 침투에 성공했다.

**왜 배우는가:**
```
[의존성 혼란 공격 원리]

기업 내부:
  requirements.txt → internal-utils==1.0 (내부 레지스트리에만 존재)

공격자:
  1. 기업 코드에서 내부 패키지명 발견 (에러 메시지, 공개 코드 등)
  2. PyPI에 "internal-utils==9.9.9" 악성 패키지 업로드

빌드 시스템:
  pip install internal-utils
  → 내부 레지스트리: 1.0 발견
  → PyPI: 9.9.9 발견 (버전이 높음!)
  → 공격자 패키지 설치 ← 자동으로 침해 발생

피해: 빌드 서버 RCE, 내부망 접근, 자격증명 탈취
```

### 핵심 개념 정리

```
주요 용어:
- 의존성 혼란(Dependency Confusion): 내부 패키지와 동일명의 공개 악성 패키지 충돌 공격
- 버전 우선순위 혼동: pip/npm이 더 높은 버전을 자동 선택하는 동작 악용
- 네임스페이스(Namespace): npm의 @company/package처럼 패키지 소속을 구분하는 접두사
- 패키지 레지스트리: PyPI(Python), npm(Node.js), NuGet(.NET), RubyGems(Ruby)
- 타이포스쿼팅과의 차이: 오타가 아닌 정확히 같은 이름으로 공개 등록
- 내부 레지스트리: 기업 내부에서만 접근 가능한 프라이빗 패키지 저장소
```

### 필요한 도구 및 환경
- **Python 3.10+**: pip, requests 라이브러리
- **pip-audit**: 설치된 패키지 중 의심스러운 패키지 탐지
- **Artifactory / Nexus**: 프라이빗 레지스트리 (방어 도구)
- **pip 설정**: --index-url, --extra-index-url 옵션 이해

### 기초 실습 예제
```python
import requests
import json
import subprocess
import sys

def check_dependency_confusion_risk(package_names: list[str],
                                     internal_registry: str = None) -> None:
    """
    내부 패키지 이름들이 공개 레지스트리에 존재하는지 확인
    존재한다면 의존성 혼란 공격 위험 가능성 탐지
    """
    print("=== 의존성 혼란 위험 점검 ===\n")
    print(f"점검 대상 패키지: {len(package_names)}개\n")

    for pkg_name in package_names:
        # PyPI에 동일 이름 패키지가 존재하는지 확인
        pypi_url = f"https://pypi.org/pypi/{pkg_name}/json"

        try:
            response = requests.get(pypi_url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                info = data["info"]
                latest_version = info["version"]
                author = info.get("author", "Unknown")
                upload_date = data["releases"].get(latest_version, [{}])[0].get(
                    "upload_time", "Unknown"
                ) if data["releases"].get(latest_version) else "Unknown"

                print(f"[위험] {pkg_name}")
                print(f"       PyPI에 동일명 패키지 존재!")
                print(f"       버전: {latest_version} | 작성자: {author}")
                print(f"       업로드: {upload_date[:10] if upload_date != 'Unknown' else 'Unknown'}")
                print(f"       대응: pip install --index-url <내부레지스트리> {pkg_name}")
                print()
            elif response.status_code == 404:
                print(f"[안전] {pkg_name} - PyPI에 없음 (의존성 혼란 위험 낮음)")

        except requests.RequestException:
            print(f"[확인불가] {pkg_name} - 네트워크 오류")

    print("\n=== 의존성 혼란 방어 방법 ===")
    print("1. pip.conf에 내부 레지스트리만 사용하도록 설정:")
    print("   [global]")
    print("   index-url = https://내부레지스트리/simple/")
    print("   # extra-index-url 제거!")
    print()
    print("2. npm .npmrc 설정:")
    print("   registry=https://내부레지스트리")
    print("   @회사스코프:registry=https://내부레지스트리")
    print()
    print("3. 내부 패키지에 네임스페이스 사용:")
    print("   Python: mycompany-internal-utils (하이픈으로 명확한 구분)")
    print("   npm: @mycompany/internal-utils (공식 스코프 사용)")

# 가상의 내부 패키지명 목록으로 테스트
# (실제 존재하는 내부 패키지명을 외부에 노출하지 말 것)
test_internal_packages = [
    "internal-utils",    # 일반적인 내부 패키지 예시
    "company-auth",      # 가상 내부 패키지
    "requests",          # 실제 공개 패키지 (위험 확인용)
]

check_dependency_confusion_risk(test_internal_packages)
```

---

## 1. 의존성 혼란이란

의존성 혼란(Dependency Confusion) 공격은 Alex Birsan이 2021년에 공개한 공급망 공격 기법입니다.
기업이 내부적으로 사용하는 패키지 이름과 동일한 이름으로 공개 레지스트리(PyPI, npm, NuGet 등)에
악성 패키지를 업로드하는 공격입니다. 빌드 도구가 내부 레지스트리보다 공개 레지스트리를 우선하면
자동으로 악성 패키지가 설치됩니다.

---

## 2. 의존성 혼란 vs 타이포스쿼팅 비교

| 비교 항목 | 의존성 혼란 (Dependency Confusion) | 타이포스쿼팅 (Typosquatting) |
|-----------|-------------------------------------|------------------------------|
| **공격 방식** | 내부 패키지명과 동일한 이름으로 공개 레지스트리 선점 | 인기 패키지명과 유사한 철자로 등록 |
| **대상** | 내부 패키지를 사용하는 특정 기업 | 실수로 잘못 입력하는 불특정 개발자 |
| **패키지명 발견** | 빌드 로그, GitHub 유출, 구인 공고 등 분석 | 인기 패키지 목록 + 일반적인 오타 패턴 |
| **성공 조건** | 빌드 도구가 공개 레지스트리 우선 설정 | 개발자가 오타를 인식하지 못함 |
| **피해 규모** | 특정 기업 집중 타격, 고가치 표적 | 광범위한 무작위 피해 |
| **탐지 난이도** | 높음 (정상 이름, 내부 설정 문제) | 중간 (유사 이름 탐지 가능) |
| **대표 사례** | Birsan 연구 (Apple, Microsoft, PayPal) | colourama, python-dateutil 위장 패키지 |
| **방어 방법** | 내부 이름 공개 등록, 스코프 사용, 레지스트리 우선순위 고정 | 정확한 패키지명 확인, 다운로드 수 확인 |

---

## 3. 패키지 레지스트리별 공격 사례

### 3.1 PyPI (Python)

| 사례 | 연도 | 내용 | 영향 |
|------|------|------|------|
| **PyTorch nightly torchtriton** | 2022 | torchtriton 내부 패키지명을 PyPI에 선점, 크립토마이너 삽입 | PyTorch nightly 사용자 |
| **ctx/phpass** | 2022 | 유지관리 중단 패키지 인수, 환경 변수 탈취 코드 삽입 | 해당 패키지 사용자 |
| **requests-html 위장** | 2023 | requests-html과 유사한 이름 다수 등록 | 오타 입력 개발자 |
| **Birsan 연구용 패키지** | 2021 | 내부 패키지명 15개 선점, DNS 핑백 확인 | Apple, Microsoft, PayPal 등 |

### 3.2 npm (Node.js)

| 사례 | 연도 | 내용 | 영향 |
|------|------|------|------|
| **event-stream** | 2018 | 유지관리자 이전 후 flatmap-stream 악성 의존성 추가 | 수백만 다운로드 |
| **ua-parser-js** | 2021 | 계정 탈취 후 크립토마이너, XMRig 삽입 | 주간 8M 다운로드 |
| **node-ipc (protestware)** | 2022 | 러시아/벨라루스 IP에 파일 삭제 실행 | vue-cli 생태계 |
| **@azure/내부패키지 선점** | 2021 | Azure 내부 npm 스코프 이름 선점 | Azure 사용 기업 |

### 3.3 NuGet (.NET)

| 사례 | 연도 | 내용 | 영향 |
|------|------|------|------|
| **Birsan NuGet 연구** | 2021 | 내부 .NET 패키지명 NuGet 선점 | 대형 기술 기업 |
| **Malicious NuGet 패키지 다수** | 2023 | 인기 패키지 위장 크립토마이너 | .NET 개발자 |

---

## 4. 의존성 혼란 취약점 발생 메커니즘

### 4.1 pip (Python) 취약 설정 예시

```ini
# pip.conf (취약한 설정)
[global]
index-url = https://internal.company.com/pypi/simple/
extra-index-url = https://pypi.org/simple/
# 문제: extra-index-url의 패키지가 더 높은 버전이면 우선 설치됨
```

### 4.2 npm 취약 설정 예시

```json
// .npmrc (취약한 설정)
// 공개 레지스트리가 기본값이므로 내부 패키지명이 공개에 있으면 우선 설치됨
registry=https://registry.npmjs.org/
@mycompany:registry=https://internal.company.com/npm/
// 문제: @mycompany 스코프가 없는 내부 패키지는 보호되지 않음
```

---

## 5. 내부 패키지 보호 전략

| 전략 | 설명 | 효과 | 구현 난이도 |
|------|------|------|-------------|
| **공개 레지스트리 이름 선점** | 내부 패키지명을 공개 레지스트리에 빈 패키지로 등록 | 높음 | 낮음 |
| **스코프/네임스페이스 사용** | `@mycompany/` (npm) 또는 `mycompany-` 접두사 | 높음 | 중간 |
| **레지스트리 우선순위 고정** | 내부 레지스트리만 사용하고 공개 레지스트리 제외 | 매우 높음 | 중간 |
| **허용 목록 기반 설치** | 승인된 패키지만 설치 허용 | 매우 높음 | 높음 |
| **버전 고정 (pinning)** | 정확한 버전 + 해시 체크섬 고정 | 높음 | 낮음 |
| **프록시 레지스트리** | 공개 레지스트리 프록시를 통해 감사 | 높음 | 높음 |
| **SBOM + 의존성 감사** | 모든 의존성 출처 추적 및 검토 | 중간 | 중간 |

---

## 6. 레지스트리별 방어 설정

### 6.1 pip 안전한 설정

```ini
# pip.conf (안전한 설정)
[global]
index-url = https://internal.company.com/pypi/simple/
# extra-index-url 제거: 내부 레지스트리만 사용
# 공개 패키지는 내부 레지스트리에서 미러링

# 또는 해시 검증 활성화
[install]
require-hashes = true
```

### 6.2 npm 안전한 설정

```ini
# .npmrc (안전한 설정)
# 전체 레지스트리를 내부로 변경
registry=https://internal.company.com/npm/

# 또는 패키지 잠금 파일 + integrity 해시 사용 (package-lock.json)
```

---

## 7. Python CLI: 의존성 혼란 취약성 검사기

```python
#!/usr/bin/env python3
"""
의존성 혼란(Dependency Confusion) 취약성 검사기
대상: requirements.txt, package.json, packages.config
PyPI/npm 공개 레지스트리에서 내부 패키지명 등록 여부 확인
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ─────────────────────────── 데이터 클래스 ───────────────────────────

class RiskLevel(str, Enum):
    CRITICAL  = "CRITICAL"   # 공개 레지스트리에 동일 이름 패키지 존재
    HIGH      = "HIGH"       # 높은 버전으로 공개 등록됨 (자동 업그레이드 위험)
    MEDIUM    = "MEDIUM"     # 공개 등록은 없으나 이름 패턴 위험
    LOW       = "LOW"        # 낮은 위험
    SAFE      = "SAFE"       # 안전 (미등록)


@dataclass
class PackageCheckResult:
    """패키지 검사 결과"""
    name: str
    version: str
    source_file: Path
    package_manager: str
    public_exists: bool = False
    public_version: str = ""
    public_higher: bool = False
    risk_level: RiskLevel = RiskLevel.SAFE
    detail: str = ""
    check_error: str = ""


@dataclass
class ConfusionScanResult:
    """전체 스캔 결과"""
    requirements_file: Path
    private_registry: str
    results: list[PackageCheckResult] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
    check_count: int = 0

    def risk_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {r.value: 0 for r in RiskLevel}
        for r in self.results:
            counts[r.risk_level.value] += 1
        return counts

    def risky_packages(self) -> list[PackageCheckResult]:
        return [r for r in self.results
                if r.risk_level not in (RiskLevel.SAFE, RiskLevel.LOW)]


# ─────────────────────────── 의존성 파싱 ───────────────────────────

@dataclass
class PackageEntry:
    name: str
    version: str
    source_file: Path
    package_manager: str


def parse_requirements_txt(file_path: Path) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    comment_re = re.compile(r"#.*$")
    version_re = re.compile(
        r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~^]+\s*([\d\.]+[\w\.\-]*))?.*$"
    )
    try:
        for raw_line in file_path.read_text(encoding="utf-8").splitlines():
            line = comment_re.sub("", raw_line).strip()
            if not line or line.startswith(("-", "--")):
                continue
            # extras 제거
            line = re.sub(r"\[.*?\]", "", line)
            m = version_re.match(line)
            if m:
                entries.append(PackageEntry(
                    name=m.group(1).strip(),
                    version=(m.group(2) or "unknown").strip(),
                    source_file=file_path,
                    package_manager="pip",
                ))
    except OSError as exc:
        print(f"[오류] {file_path}: {exc}", file=sys.stderr)
    return entries


def parse_package_json(file_path: Path) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    try:
        data: dict[str, Any] = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[오류] {file_path}: {exc}", file=sys.stderr)
        return entries

    all_deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        all_deps.update(data.get(key, {}))

    for name, ver_range in all_deps.items():
        # 스코프 패키지(@company/pkg)는 기본적으로 낮은 위험
        version = re.sub(r"[^0-9\.]", "", ver_range) or ver_range
        entries.append(PackageEntry(
            name=name,
            version=version,
            source_file=file_path,
            package_manager="npm",
        ))
    return entries


# ─────────────────────────── 레지스트리 검사기 ───────────────────────────

class PyPIChecker:
    """PyPI 공개 레지스트리 존재 여부 확인"""

    BASE_URL = "https://pypi.org/pypi/{name}/json"
    REQUEST_DELAY = 0.5  # 초 단위 요청 간격 (API 레이트 리밋 방지)

    def check(self, package_name: str) -> tuple[bool, str]:
        """
        반환: (존재 여부, 최신 버전)
        """
        url = self.BASE_URL.format(name=urllib.parse.quote(package_name))
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "dependency-confusion-checker/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                latest_version = data.get("info", {}).get("version", "unknown")
                return True, latest_version
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False, ""
            raise
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return False, ""
        finally:
            time.sleep(self.REQUEST_DELAY)


class NpmChecker:
    """npm 공개 레지스트리 존재 여부 확인"""

    BASE_URL = "https://registry.npmjs.org/{name}"
    REQUEST_DELAY = 0.5

    def check(self, package_name: str) -> tuple[bool, str]:
        url = self.BASE_URL.format(name=urllib.parse.quote(package_name, safe="@/"))
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "dependency-confusion-checker/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                dist_tags = data.get("dist-tags", {})
                latest_version = dist_tags.get("latest", "unknown")
                return True, latest_version
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False, ""
            raise
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return False, ""
        finally:
            time.sleep(self.REQUEST_DELAY)


# urllib.parse는 표준 라이브러리에 포함
import urllib.parse


# ─────────────────────────── 위험도 분류기 ───────────────────────────

def _version_tuple(version_str: str) -> tuple[int, ...]:
    """버전 문자열을 비교 가능한 튜플로 변환"""
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", version_str) if x.isdigit())
    except (ValueError, AttributeError):
        return (0,)


def assess_risk(
    package: PackageEntry,
    public_exists: bool,
    public_version: str,
    private_registry: str,
) -> tuple[RiskLevel, str]:
    """위험도 평가"""
    if not public_exists:
        return RiskLevel.SAFE, "공개 레지스트리에 미등록"

    local_ver = _version_tuple(package.version)
    public_ver = _version_tuple(public_version)

    if public_ver > local_ver:
        detail = (
            f"공개 레지스트리 버전({public_version})이 "
            f"내부 버전({package.version})보다 높음 → 자동 업그레이드 위험"
        )
        return RiskLevel.CRITICAL, detail

    if public_ver == local_ver:
        detail = f"공개 레지스트리에 동일 버전({public_version}) 존재"
        return RiskLevel.HIGH, detail

    detail = f"공개 레지스트리에 낮은 버전({public_version}) 존재"
    return RiskLevel.MEDIUM, detail


# ─────────────────────────── 스캐너 메인 ───────────────────────────

class DependencyConfusionScanner:
    """의존성 혼란 취약성 스캐너"""

    def __init__(
        self,
        requirements_file: Path,
        private_registry: str,
        dry_run: bool = False,
    ):
        self.requirements_file = requirements_file
        self.private_registry = private_registry
        self.dry_run = dry_run
        self._pypi = PyPIChecker()
        self._npm = NpmChecker()

    def _detect_file_type(self) -> str:
        name = self.requirements_file.name.lower()
        if "requirements" in name and name.endswith(".txt"):
            return "pip"
        if name == "package.json":
            return "npm"
        return "unknown"

    def _load_packages(self) -> list[PackageEntry]:
        file_type = self._detect_file_type()
        if file_type == "pip":
            return parse_requirements_txt(self.requirements_file)
        elif file_type == "npm":
            return parse_package_json(self.requirements_file)
        else:
            print(f"[경고] 지원하지 않는 파일 형식: {self.requirements_file.name}",
                  file=sys.stderr)
            return []

    def _check_package(self, pkg: PackageEntry) -> PackageCheckResult:
        result = PackageCheckResult(
            name=pkg.name,
            version=pkg.version,
            source_file=pkg.source_file,
            package_manager=pkg.package_manager,
        )

        # 스코프 패키지는 기본적으로 안전 (단, 확인은 수행)
        is_scoped = pkg.name.startswith("@")

        if self.dry_run:
            result.risk_level = RiskLevel.SAFE
            result.detail = "[드라이런] 실제 API 호출 없음"
            return result

        try:
            if pkg.package_manager == "pip":
                exists, public_ver = self._pypi.check(pkg.name)
            elif pkg.package_manager == "npm":
                exists, public_ver = self._npm.check(pkg.name)
            else:
                result.detail = "지원하지 않는 패키지 관리자"
                return result

            result.public_exists = exists
            result.public_version = public_ver

            if is_scoped and not exists:
                result.risk_level = RiskLevel.SAFE
                result.detail = "스코프 패키지, 공개 미등록"
                return result

            risk, detail = assess_risk(pkg, exists, public_ver, self.private_registry)
            result.risk_level = risk
            result.detail = detail

        except Exception as exc:  # noqa: BLE001
            result.check_error = str(exc)
            result.risk_level = RiskLevel.LOW
            result.detail = f"확인 오류: {exc}"

        return result

    def scan(self, max_packages: int | None = None) -> ConfusionScanResult:
        scan_result = ConfusionScanResult(
            requirements_file=self.requirements_file,
            private_registry=self.private_registry,
        )

        packages = self._load_packages()
        if max_packages:
            packages = packages[:max_packages]

        print(
            f"[시작] {len(packages)}개 패키지 검사 중 "
            f"({'드라이런' if self.dry_run else '실제 API 호출'})...",
            file=sys.stderr,
        )

        for i, pkg in enumerate(packages, start=1):
            print(
                f"  [{i:3d}/{len(packages)}] {pkg.name}=={pkg.version}",
                end="\r",
                file=sys.stderr,
            )
            result = self._check_package(pkg)
            scan_result.results.append(result)
            scan_result.check_count += 1

        print(file=sys.stderr)  # 개행
        return scan_result


# ─────────────────────────── 보고서 출력 ───────────────────────────

RISK_COLORS = {
    RiskLevel.CRITICAL: "\033[91m",
    RiskLevel.HIGH:     "\033[93m",
    RiskLevel.MEDIUM:   "\033[94m",
    RiskLevel.LOW:      "\033[96m",
    RiskLevel.SAFE:     "\033[92m",
}
RESET = "\033[0m"


def print_report(scan: ConfusionScanResult, show_safe: bool = False, use_color: bool = True) -> None:
    print(f"\n{'='*60}")
    print("의존성 혼란 취약성 검사 결과")
    print(f"파일: {scan.requirements_file}")
    print(f"내부 레지스트리: {scan.private_registry}")
    print(f"검사 패키지 수: {scan.check_count}")
    print(f"{'='*60}\n")

    risky = scan.risky_packages()
    if not risky:
        print("[OK] 의존성 혼란 취약점 미탐지\n")
    else:
        print(f"[경고] {len(risky)}개 위험 패키지 발견:\n")
        for r in sorted(risky, key=lambda x: list(RiskLevel)[0:].index(x.risk_level)):
            color = RISK_COLORS.get(r.risk_level, "") if use_color else ""
            reset = RESET if use_color else ""
            print(f"{color}[{r.risk_level.value}]{reset} {r.name}=={r.version}")
            print(f"  공개 버전: {r.public_version or '없음'}")
            print(f"  평가: {r.detail}")
            print()

    if show_safe:
        safe = [r for r in scan.results if r.risk_level == RiskLevel.SAFE]
        if safe:
            print(f"[안전] {len(safe)}개 패키지 (공개 미등록):")
            for r in safe:
                print(f"  - {r.name}=={r.version}")
            print()

    summary = scan.risk_summary()
    print("─" * 40)
    print("위험도별 요약:")
    for level in RiskLevel:
        count = summary[level.value]
        if count > 0 or level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            color = RISK_COLORS.get(level, "") if use_color else ""
            reset = RESET if use_color else ""
            print(f"  {color}{level.value:10s}{reset}: {count}개")

    if scan.scan_errors:
        print("\n[오류]")
        for err in scan.scan_errors:
            print(f"  - {err}")


def export_json_report(scan: ConfusionScanResult) -> str:
    data = {
        "requirements_file": str(scan.requirements_file),
        "private_registry": scan.private_registry,
        "check_count": scan.check_count,
        "risk_summary": scan.risk_summary(),
        "risky_packages": [
            {
                "name": r.name,
                "version": r.version,
                "package_manager": r.package_manager,
                "public_exists": r.public_exists,
                "public_version": r.public_version,
                "risk_level": r.risk_level.value,
                "detail": r.detail,
            }
            for r in scan.risky_packages()
        ],
        "all_results": [
            {
                "name": r.name,
                "version": r.version,
                "risk_level": r.risk_level.value,
                "public_version": r.public_version,
            }
            for r in scan.results
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─────────────────────────── CLI ───────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-confusion-checker",
        description="의존성 혼란 취약성 검사기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 03_dependency_confusion.py --requirements-file requirements.txt
  python3 03_dependency_confusion.py --requirements-file requirements.txt \\
      --private-registry https://internal.company.com/pypi
  python3 03_dependency_confusion.py --requirements-file package.json \\
      --output report.json --max-packages 50
  python3 03_dependency_confusion.py --requirements-file requirements.txt \\
      --dry-run --show-safe
        """,
    )
    parser.add_argument(
        "--requirements-file",
        type=Path,
        required=True,
        metavar="FILE",
        help="검사할 의존성 파일 (requirements.txt 또는 package.json)",
    )
    parser.add_argument(
        "--private-registry",
        type=str,
        default="https://internal.example.com/pypi",
        metavar="URL",
        help="내부(사설) 패키지 레지스트리 URL",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="JSON 보고서 출력 파일 경로",
    )
    parser.add_argument(
        "--max-packages",
        type=int,
        default=None,
        metavar="N",
        help="검사할 최대 패키지 수 (테스트용)",
    )
    parser.add_argument(
        "--show-safe",
        action="store_true",
        help="안전한 패키지도 결과에 포함",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="실제 API 호출 없이 파싱만 수행",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="색상 출력 비활성화",
    )
    parser.add_argument(
        "--fail-on-risk",
        choices=["critical", "high", "medium"],
        default=None,
        metavar="LEVEL",
        help="해당 위험도 이상 발견 시 종료 코드 1 반환",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    req_file: Path = args.requirements_file.resolve()
    if not req_file.exists():
        print(f"[오류] 파일이 존재하지 않습니다: {req_file}", file=sys.stderr)
        return 1

    scanner = DependencyConfusionScanner(
        requirements_file=req_file,
        private_registry=args.private_registry,
        dry_run=args.dry_run,
    )

    scan_result = scanner.scan(max_packages=args.max_packages)
    print_report(scan_result, show_safe=args.show_safe, use_color=not args.no_color)

    if args.output:
        try:
            args.output.write_text(export_json_report(scan_result), encoding="utf-8")
            print(f"\n[저장] JSON 보고서: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[오류] 파일 저장 실패: {exc}", file=sys.stderr)

    if args.fail_on_risk:
        threshold_map = {
            "medium": {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL},
            "high": {RiskLevel.HIGH, RiskLevel.CRITICAL},
            "critical": {RiskLevel.CRITICAL},
        }
        threshold_set = threshold_map[args.fail_on_risk]
        if any(r.risk_level in threshold_set for r in scan_result.results):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 8. 의존성 혼란 방어 체크리스트

| 범주 | 점검 항목 | 구현 방법 |
|------|-----------|-----------|
| **패키지명 관리** | 모든 내부 패키지명을 공개 레지스트리에 빈 패키지로 예약 | 자동화된 예약 스크립트 |
| **네임스페이스** | `@company/` 스코프 또는 `company-` 접두사 의무화 | 패키지 정책 수립 |
| **레지스트리 설정** | 내부 레지스트리만 사용, 공개 레지스트리 폴백 제거 | pip.conf, .npmrc 감사 |
| **버전 고정** | 정확한 버전 + SHA 해시 체크섬 고정 | `pip install --require-hashes` |
| **프록시 레지스트리** | 공개 패키지를 내부 프록시(Nexus, Artifactory)를 통해 제공 | 인프라 구성 |
| **CI/CD 검증** | 빌드 시 의존성 혼란 자동 검사 실행 | 이 스크립트를 CI에 통합 |
| **모니터링** | 새 내부 패키지 추가 시 공개 등록 여부 자동 알림 | 웹훅 + 스크립트 |

---

<a name="english"></a>

# Dependency Confusion Attack

## 1. What Is Dependency Confusion

The Dependency Confusion attack is a supply chain attack technique disclosed by Alex Birsan in 2021. It involves uploading a malicious package to a public registry (PyPI, npm, NuGet, etc.) with the same name as a package used internally by a company. If the build tool prioritizes public registries over internal ones, the malicious package is automatically installed.

---

## 2. Dependency Confusion vs Typosquatting Comparison

| Comparison | Dependency Confusion | Typosquatting |
|-----------|---------------------|---------------|
| **Attack Method** | Register same name as internal package on public registry | Register similarly spelled name to popular package |
| **Target** | Specific company using internal packages | Random developers who mistype package names |
| **Package Name Discovery** | Analysis of build logs, GitHub leaks, job postings | Popular package list + common typo patterns |
| **Success Condition** | Build tool configured to prefer public registry | Developer doesn't notice the typo |
| **Impact Scale** | Targeted attack on specific company, high-value target | Widespread random victims |
| **Detection Difficulty** | High (legitimate name, internal config issue) | Medium (similar names can be detected) |
| **Representative Cases** | Birsan research (Apple, Microsoft, PayPal) | colourama, python-dateutil disguised packages |
| **Defense Methods** | Reserve internal names on public registry, use scopes, fix registry priority | Verify exact package name, check download count |

---

## 3. Attack Cases by Package Registry

### 3.1 PyPI (Python)

| Case | Year | Content | Impact |
|------|------|---------|--------|
| **PyTorch nightly torchtriton** | 2022 | Internal package name `torchtriton` preempted on PyPI; crypto miner inserted | PyTorch nightly users |
| **ctx/phpass** | 2022 | Abandoned package acquired; environment variable exfiltration code inserted | Package users |
| **requests-html impersonation** | 2023 | Multiple similarly named packages registered | Developers with typos |
| **Birsan research packages** | 2021 | 15 internal package names preempted; DNS pingback confirmed | Apple, Microsoft, PayPal, etc. |

### 3.2 npm (Node.js)

| Case | Year | Content | Impact |
|------|------|---------|--------|
| **event-stream** | 2018 | Malicious dependency `flatmap-stream` added after maintainer transfer | Millions of downloads |
| **ua-parser-js** | 2021 | Crypto miner, XMRig inserted after account takeover | 8M weekly downloads |
| **node-ipc (protestware)** | 2022 | File deletion executed on Russian/Belarusian IPs | vue-cli ecosystem |
| **@azure/internal package preemption** | 2021 | Azure internal npm scope names preempted | Companies using Azure |

### 3.3 NuGet (.NET)

| Case | Year | Content | Impact |
|------|------|---------|--------|
| **Birsan NuGet research** | 2021 | Internal .NET package names preempted on NuGet | Large technology companies |
| **Malicious NuGet packages** | 2023 | Crypto miners disguised as popular packages | .NET developers |

---

## 4. How Dependency Confusion Vulnerabilities Arise

See the Korean section for detailed pip/npm/NuGet configuration examples and the Python CLI tool.

---

## 8. Dependency Confusion Defense Checklist

| Category | Check Item | Implementation Method |
|----------|-----------|----------------------|
| **Package Name Management** | Reserve all internal package names on public registries with empty packages | Automated reservation script |
| **Namespacing** | Mandate `@company/` scope or `company-` prefix | Package policy establishment |
| **Registry Configuration** | Use only internal registry, remove public registry fallback | Audit pip.conf, .npmrc |
| **Version Pinning** | Exact version + SHA hash checksum pinning | `pip install --require-hashes` |
| **Proxy Registry** | Serve public packages through internal proxy (Nexus, Artifactory) | Infrastructure configuration |
| **CI/CD Validation** | Run automated dependency confusion checks at build time | Integrate this script into CI |
| **Monitoring** | Automatic alert when a new internal package is added to public registry | Webhook + script |
