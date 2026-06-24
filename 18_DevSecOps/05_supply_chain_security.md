> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 공급망 보안 — 의존성 공격·SLSA·서명 검증

## 0. 초보자를 위한 개념 이해

### 소프트웨어 공급망 보안이란?

소프트웨어 공급망 보안은 우리가 사용하는 오픈소스 라이브러리, 빌드 도구, CI/CD 시스템 등 개발 생태계 전체의 신뢰성을 보장하는 분야입니다. SolarWinds(2020)·XZ Utils(2024) 같은 공급망 공격은 수천 개의 조직을 동시에 침해합니다. 타이포스쿼팅(오타 패키지)과 의존성 혼동(Dependency Confusion) 공격은 npm install 한 번으로 악성코드가 실행될 수 있음을 보여줍니다.

**왜 배우는가:**
```
공급망 공격의 파급 효과:

  SolarWinds (2020)
    → 빌드 서버 침해 → 악성 업데이트 서명
    → 18,000개+ 고객사 자동 업데이트 설치
    → 미국 정부기관 다수 침해

  XZ Utils (2024, CVE-2024-3094)
    → 2년간 신뢰 쌓은 후 악성 백도어 삽입
    → systemd 통한 SSH 서버 원격 접근
    → 발견되지 않았다면 수억 대 Linux 서버 영향

  의존성 혼동
    → 사설 패키지명을 공개 PyPI/npm에 등록
    → pip install → 공개 레지스트리 우선 설치
    → Apple·Microsoft·Shopify 모두 영향받음
```

### 핵심 개념 정리

```
주요 공급망 공격 유형:

  타이포스쿼팅
    requests → reqeusts (오타)
    numpy    → nunpy
    방어: 패키지명 철자 재확인, 화이트리스트

  의존성 혼동 (Dependency Confusion)
    사내 패키지 'company-utils'
    공격자가 PyPI/npm에 동일명 등록
    → 버전 숫자 더 높게 → 자동 설치됨
    방어: 사설 레지스트리 우선 설정

  악성 패키지 업로드
    합법 패키지 유지자 계정 탈취
    소규모 패키지 인수 후 악성코드 삽입

  SLSA (Supply chain Levels for Software Artifacts)
    Google이 제안한 공급망 보안 프레임워크
    Level 1~4: 빌드 출처 검증 수준
```

### 필요한 도구 및 환경
- **pip-audit / npm audit**: 의존성 취약점 점검 명령어
- **Sigstore / cosign**: 소프트웨어 아티팩트 서명 및 검증
- **syft + grype**: SBOM 생성 + CVE 매핑
- **SLSA verifier**: 빌드 출처 검증 도구

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""의존성 혼동 취약점 탐지 — 사설 패키지가 공개 레지스트리에 존재하는지 확인."""

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class DependencyCheck:
    package_name: str
    version: str | None
    exists_on_pypi: bool
    pypi_version: str | None
    is_confusion_risk: bool


async def check_pypi_existence(
    client: httpx.AsyncClient,
    package_name: str,
) -> tuple[bool, str | None]:
    """PyPI에 해당 패키지가 존재하는지 확인합니다."""
    try:
        resp = await client.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            latest = data["info"]["version"]
            return True, latest
    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    return False, None


async def audit_private_dependencies(
    private_packages: list[tuple[str, str]],  # (name, version)
) -> list[DependencyCheck]:
    """사내 패키지 목록을 PyPI에서 확인하여 의존성 혼동 위험을 탐지합니다."""
    results: list[DependencyCheck] = []
    async with httpx.AsyncClient() as client:
        for name, version in private_packages:
            exists, pypi_ver = await check_pypi_existence(client, name)
            results.append(DependencyCheck(
                package_name=name,
                version=version,
                exists_on_pypi=exists,
                pypi_version=pypi_ver,
                is_confusion_risk=exists,  # 공개 레지스트리에 있으면 위험
            ))
    return results


if __name__ == "__main__":
    # 사내에서 사용 중인 패키지 목록 (실제로는 requirements.txt에서 파싱)
    internal_packages = [
        ("requests", "2.31.0"),     # 공개 패키지 (정상)
        ("company-utils", "1.0.0"), # 사내 패키지 (PyPI에 없어야 함)
        ("myorg-auth", "2.1.0"),    # 사내 패키지
    ]
    results = asyncio.run(audit_private_dependencies(internal_packages))
    for r in results:
        tag = "[위험!]" if r.is_confusion_risk else "[정상]"
        pypi_info = f"PyPI: {r.pypi_version}" if r.exists_on_pypi else "PyPI: 없음"
        print(f"{tag} {r.package_name}=={r.version}  |  {pypi_info}")
```

---

## 1. 소프트웨어 공급망 공격 유형

```
공급망 공격 벡터
    │
    ├── 의존성 혼동 (Dependency Confusion)
    │     → 사설 패키지명을 공개 레지스트리에 등록
    │
    ├── 타이포스쿼팅 (Typosquatting)
    │     → requests → reqeusts, numpy → nunpy
    │
    ├── 악성 패키지 업로드
    │     → 합법 패키지 유지자 계정 탈취 후 악성코드 삽입
    │
    ├── CI/CD 파이프라인 침해
    │     → 빌드 서버 접근 → 아티팩트 수정
    │
    └── 빌드 시스템 조작
          → Makefile, setup.py, postinstall 스크립트 악용
```

---

## 2. 의존성 혼동 공격 탐지

```python
#!/usr/bin/env python3
"""의존성 혼동 취약점 탐지 — 사설 패키지가 공개 레지스트리에 존재하는지 확인."""

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class PackageCheckResult:
    name: str
    version: str | None
    exists_on_pypi: bool
    exists_on_npm: bool
    pypi_version: str | None
    npm_version: str | None
    risk: str  # HIGH / MEDIUM / LOW


async def check_pypi(client: httpx.AsyncClient, package: str) -> tuple[bool, str | None]:
    try:
        resp = await client.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            version = data["info"]["version"]
            return True, version
    except httpx.RequestError:
        pass
    return False, None


async def check_npm(client: httpx.AsyncClient, package: str) -> tuple[bool, str | None]:
    try:
        resp = await client.get(
            f"https://registry.npmjs.org/{package}/latest",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return True, data.get("version")
    except httpx.RequestError:
        pass
    return False, None


async def scan_package(
    client: httpx.AsyncClient,
    name: str,
    internal_version: str | None = None,
) -> PackageCheckResult:
    pypi_exists, pypi_ver = await check_pypi(client, name)
    npm_exists, npm_ver = await check_npm(client, name)

    # 위험도 평가
    if pypi_exists or npm_exists:
        if internal_version and pypi_ver and internal_version != pypi_ver:
            risk = "HIGH"  # 버전 불일치 → 혼동 공격 가능성
        else:
            risk = "MEDIUM"  # 공개 레지스트리에 동일 이름 존재
    else:
        risk = "LOW"  # 공개에 없음 → 상대적으로 안전

    return PackageCheckResult(
        name=name,
        version=internal_version,
        exists_on_pypi=pypi_exists,
        exists_on_npm=npm_exists,
        pypi_version=pypi_ver,
        npm_version=npm_ver,
        risk=risk,
    )


def parse_requirements_txt(req_file: Path) -> list[tuple[str, str | None]]:
    packages = []
    for line in req_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            packages.append((name.strip(), ver.strip()))
        else:
            packages.append((line.split(">")[0].split("<")[0].strip(), None))
    return packages


def parse_package_json(pkg_file: Path) -> list[tuple[str, str | None]]:
    data = json.loads(pkg_file.read_text())
    packages = []
    for section in ["dependencies", "devDependencies"]:
        for name, ver in data.get(section, {}).items():
            packages.append((name, ver.lstrip("^~")))
    return packages


async def scan_all(packages: list[tuple[str, str | None]], concurrency: int = 10) -> list[PackageCheckResult]:
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def bounded_scan(name: str, ver: str | None) -> None:
        async with semaphore:
            result = await scan_package(client, name, ver)
            results.append(result)
            risk_icon = {"HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[ ]"}.get(result.risk, "[?]")
            print(f"{risk_icon} {name}: PyPI={result.exists_on_pypi}({result.pypi_version}), "
                  f"npm={result.exists_on_npm}({result.npm_version})")

    async with httpx.AsyncClient() as client:
        await asyncio.gather(*[bounded_scan(n, v) for n, v in packages])

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="의존성 혼동 취약점 탐지")
    parser.add_argument("file", type=Path, help="requirements.txt 또는 package.json")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("-c", "--concurrency", type=int, default=10)
    args = parser.parse_args()

    file = args.file
    if file.name == "requirements.txt" or file.suffix == ".txt":
        packages = parse_requirements_txt(file)
    elif file.name == "package.json":
        packages = parse_package_json(file)
    else:
        print("지원 형식: requirements.txt, package.json")
        return

    print(f"[*] {len(packages)}개 패키지 스캔 중...\n")
    results = asyncio.run(scan_all(packages, args.concurrency))

    high_risk = [r for r in results if r.risk == "HIGH"]
    print(f"\n=== 결과 ===")
    print(f"총 패키지: {len(results)}, 고위험: {len(high_risk)}")

    if args.output:
        args.output.write_text(json.dumps(
            [vars(r) for r in results], indent=2, ensure_ascii=False
        ))


if __name__ == "__main__":
    main()
```

---

## 3. SLSA 레벨 자동 평가

```python
#!/usr/bin/env python3
"""SLSA (Supply-chain Levels for Software Artifacts) 준수 평가 CLI."""

import argparse
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SLSACheck:
    name: str
    level: int  # 1~4
    passed: bool
    detail: str


@dataclass
class SLSAReport:
    repo: str
    checks: list[SLSACheck] = field(default_factory=list)

    def achieved_level(self) -> int:
        for lvl in [4, 3, 2, 1]:
            required = [c for c in self.checks if c.level <= lvl]
            if all(c.passed for c in required):
                return lvl
        return 0


def run_git(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True, text=True, cwd=cwd, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def check_slsa(repo_path: Path) -> SLSAReport:
    report = SLSAReport(repo=str(repo_path))

    # Level 1: 빌드 스크립트 존재
    has_ci = any([
        (repo_path / ".github/workflows").exists(),
        (repo_path / ".gitlab-ci.yml").exists(),
        (repo_path / "Jenkinsfile").exists(),
    ])
    report.checks.append(SLSACheck(
        name="CI/CD 파이프라인",
        level=1,
        passed=has_ci,
        detail="GitHub Actions / GitLab CI / Jenkins 설정 파일 존재",
    ))

    # Level 1: 버전 태그 존재
    tags = run_git(["tag", "--list"], repo_path)
    has_tags = bool(tags)
    report.checks.append(SLSACheck(
        name="버전 태그",
        level=1,
        passed=has_tags,
        detail=f"태그 {len(tags.splitlines())}개" if has_tags else "태그 없음",
    ))

    # Level 2: 서명된 커밋
    log = run_git(["log", "--format=%G?", "-10"], repo_path)
    signed_commits = sum(1 for line in log.splitlines() if line in ("G", "U"))
    has_signed = signed_commits > 0
    report.checks.append(SLSACheck(
        name="서명된 커밋",
        level=2,
        passed=has_signed,
        detail=f"최근 10커밋 중 서명 {signed_commits}개",
    ))

    # Level 2: 브랜치 보호
    # .github 폴더 내 CODEOWNERS 파일 확인
    has_codeowners = (repo_path / ".github/CODEOWNERS").exists() or \
                     (repo_path / "CODEOWNERS").exists()
    report.checks.append(SLSACheck(
        name="CODEOWNERS 설정",
        level=2,
        passed=has_codeowners,
        detail="CODEOWNERS 파일 존재" if has_codeowners else "미설정",
    ))

    # Level 3: SBOM 생성
    has_sbom = any([
        (repo_path / "sbom.json").exists(),
        (repo_path / "sbom.spdx").exists(),
        list(repo_path.glob("*.sbom*")),
    ])
    report.checks.append(SLSACheck(
        name="SBOM 생성",
        level=3,
        passed=bool(has_sbom),
        detail="SBOM 파일 존재" if has_sbom else "SBOM 미생성",
    ))

    # Level 3: 아티팩트 서명 (cosign)
    has_cosign = any(repo_path.glob("**/*.sig")) or \
                 any("cosign" in str(f) for f in repo_path.rglob("*.yml"))
    report.checks.append(SLSACheck(
        name="아티팩트 서명 (cosign)",
        level=3,
        passed=has_cosign,
        detail="cosign 서명 설정 감지" if has_cosign else "서명 미설정",
    ))

    # Level 4: 재현 가능한 빌드 (Dockerfile 또는 Nix)
    has_reproducible = (repo_path / "Dockerfile").exists() or \
                       any(repo_path.glob("*.nix"))
    report.checks.append(SLSACheck(
        name="재현 가능한 빌드",
        level=4,
        passed=has_reproducible,
        detail="Dockerfile/Nix 존재" if has_reproducible else "미확인",
    ))

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="SLSA 준수 평가")
    parser.add_argument("repo", type=Path, help="평가할 저장소 경로")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    report = check_slsa(args.repo)
    achieved = report.achieved_level()

    print(f"\n=== SLSA 평가: {report.repo} ===\n")
    for check in report.checks:
        icon = "[+]" if check.passed else "[-]"
        print(f"Level {check.level} {icon} {check.name}")
        print(f"         {check.detail}")

    print(f"\n달성 레벨: SLSA Level {achieved} / 4")

    if args.output:
        result = {
            "repo": report.repo,
            "slsa_level": achieved,
            "checks": [vars(c) for c in report.checks],
        }
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

---

## 4. 악성 패키지 스크립트 탐지

```python
#!/usr/bin/env python3
"""패키지 설치 스크립트 악성 행위 정적 탐지."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


SUSPICIOUS_PATTERNS = [
    (r"subprocess|os\.system|exec\(|eval\(", "코드 실행"),
    (r"socket|urllib|requests|httpx|curl|wget", "네트워크 통신"),
    (r"base64\.b64decode|codecs\.decode", "인코딩된 페이로드"),
    (r"open\(.+['\"]w['\"]", "파일 쓰기"),
    (r"environ|os\.getenv", "환경 변수 접근"),
    (r"shutil\.rmtree|os\.remove|os\.unlink", "파일 삭제"),
    (r"/etc/passwd|/etc/shadow|\.ssh", "민감 경로 접근"),
    (r"sys\.path\.insert|site-packages", "Python 경로 조작"),
]


def analyze_setup_script(file_path: Path) -> list[dict]:
    findings = []
    content = file_path.read_text(errors="ignore")
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, category in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "file": str(file_path),
                    "line": lineno,
                    "category": category,
                    "code": stripped[:120],
                })

    return findings


def scan_package_dir(package_dir: Path) -> None:
    target_files = [
        "setup.py", "setup.cfg",
        "__init__.py", "postinstall.py", "preinstall.py",
    ]
    all_findings = []

    for target in target_files:
        for match in package_dir.rglob(target):
            findings = analyze_setup_script(match)
            all_findings.extend(findings)

    if all_findings:
        print(f"[!] 의심 동작 {len(all_findings)}개 발견:")
        for f in all_findings:
            print(f"\n  {f['file']}:{f['line']} [{f['category']}]")
            print(f"  {f['code']}")
    else:
        print("[+] 의심 동작 미발견")


def main() -> None:
    parser = argparse.ArgumentParser(description="악성 패키지 스크립트 탐지")
    parser.add_argument("path", type=Path, help="패키지 디렉터리 또는 setup.py 파일")
    args = parser.parse_args()

    if args.path.is_file():
        findings = analyze_setup_script(args.path)
        if findings:
            for f in findings:
                print(f"  [{f['category']}] 줄 {f['line']}: {f['code']}")
        else:
            print("[+] 이상 없음")
    else:
        scan_package_dir(args.path)


if __name__ == "__main__":
    main()
```

---

## 5. 공급망 보안 방어 대책

| 위협 | 대책 | 도구 |
|------|------|------|
| 타이포스쿼팅 | 패키지명 검증, 허용 목록 관리 | pip-audit, npm audit |
| 의존성 혼동 | 내부 레지스트리 우선 설정 | Artifactory, Nexus |
| 악성 패키지 | 설치 전 정적 분석 | Bandit, semgrep |
| 빌드 무결성 | SLSA 준수, 아티팩트 서명 | cosign, sigstore |
| 취약한 의존성 | 주기적 CVE 스캔 | Dependabot, Snyk |
| CI/CD 침해 | 비밀 스캔, 최소 권한 | gitleaks, trufflehog |
| SBOM 부재 | 의존성 트리 자동 생성 | syft, cyclonedx |

---

<!-- detect-validate-18 -->
## 공급망 공격 탐지와 방어 검증

공급망 공격은 *의존성 혼동·타이포스쿼팅·악성 설치 스크립트·빌드 변조*를 노린다. 방어자는 **내부 패키지명 선점·스크립트 격리·프로비넌스 검증이 실제로 작동하는가**를 검증해야 한다. 검증은 **소유 빌드**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 의존성 혼동 | 공개 등록소 우선 해석 | 스코프·내부 레지스트리 우선 | 공개 등록소의 내부 패키지명 |
| 타이포스쿼팅 | 유사 패키지명 | 락파일·허용목록 | 신규·저평판 의존성 추가 |
| 악성 설치 스크립트 | postinstall 임의실행 | --ignore-scripts·격리 빌드 | 설치 중 네트워크/파일 접근 |
| 빌드 변조 | 산출물 무결성 미검증 | SLSA 프로비넌스·서명 | 산출물 해시 불일치 |

### 방어 검증 (직접 확인)

```bash
# 1) 내부 패키지명이 공개 레지스트리에 선점됐는지 확인 — 의존성 혼동 표면
npm view "@yourscope/internal-pkg" version 2>/dev/null && echo "공개 등록소에 존재 — 혼동 위험 점검"
# 2) 설치 스크립트가 임의 코드를 돌리지 못하게 격리되는지(소유 빌드)
npm ci --ignore-scripts && echo "스크립트 차단 설치 OK — postinstall 악용 표면 축소"
#   재현 빌드의 산출물 해시를 비교해 변조 여부를 사실로 확인한다
```

> 공급망 방어는 *대책이 있는가*가 아니라 *작동하는가*다 — "검증한다"와 "내부명 선점·악성 스크립트·변조를 실제로 막고 드러낸다"는 다르다. 소유 빌드에서 격리 설치·프로비넌스·해시 대조를 직접 확인한다([[35_Supply_Chain_Attacks]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).

---

<a name="english"></a>

# Supply Chain Security — Dependency Attacks, SLSA, Signature Verification

## 1. Software Supply Chain Attack Types

```
Supply Chain Attack Categories:

Source Code Attacks:
  - Compromised developer accounts
  - Malicious code injection into open source
  - Typosquatting (e.g., "requets" instead of "requests")

Build System Attacks:
  - Compromised build servers
  - Malicious build scripts
  - Artifact tampering

Dependency Attacks:
  - Dependency confusion
  - Version pinning bypass
  - Transitive dependency exploitation

Distribution Attacks:
  - Package registry compromise
  - Man-in-the-middle during download
  - Update mechanism hijacking

Real-world examples:
  SolarWinds (2020) — Build system backdoor
  Log4Shell (2021) — Critical library vulnerability
  XZ Utils (2024) — Long-term supply chain infiltration
```

---

## 2. Dependency Confusion Attack

```
How Dependency Confusion Works:

Organization has internal package: "@company/auth-lib"
Published on internal npm registry

Attacker publishes malicious package: "company-auth-lib"
on public npm with higher version number

When npm resolves packages:
  - Checks public registry first
  - Finds higher version on public npm
  - Installs malicious package instead!

Defense:
  - Use scoped packages (@company/)
  - Configure npm to use internal registry
  - Use .npmrc or pip.conf to pin registries
```

```bash
# Python: Pin to internal registry
# pip.conf
[global]
index-url = https://internal.company.com/simple/
extra-index-url = https://pypi.org/simple/

# npm: Pin to internal registry
# .npmrc
@company:registry=https://internal.company.com/npm/
always-auth=true

# Verify package source
pip show requests | grep Location
npm info lodash dist.tarball
```

---

## 3. SLSA Framework (Supply Chain Levels for Software Artifacts)

```
SLSA Levels:

Level 1 — Provenance
  - Build process documented
  - Who built it, when, from what source

Level 2 — Signed Provenance
  - Provenance signed by build service
  - Hosted build service used

Level 3 — Hardened Builds
  - Source and build platform meet audit requirements
  - Non-falsifiable provenance

Level 4 — Reproducible Builds
  - Hermetic (isolated) builds
  - Reproducible build process

Implementation:
  GitHub Actions → SLSA GitHub Generator → Signed provenance
```

### SLSA with GitHub Actions

```yaml
# Generate SLSA provenance
name: SLSA Build

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digests: ${{ steps.hash.outputs.digests }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build binary
        run: make release
      
      - name: Generate hash
        id: hash
        run: |
          sha256sum ./dist/app > checksums.txt
          echo "digests=$(cat checksums.txt | base64 -w0)" >> $GITHUB_OUTPUT
  
  provenance:
    needs: build
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
    with:
      base64-subjects: ${{ needs.build.outputs.digests }}
    permissions:
      actions: read
      id-token: write
      contents: write
```

---

## 4. Artifact Signing with Sigstore/Cosign

```bash
# Sign container image
cosign sign --key cosign.key myimage:latest

# Verify signature
cosign verify --key cosign.pub myimage:latest

# Keyless signing (using OIDC identity)
cosign sign myimage:latest  # Uses GitHub Actions OIDC token

# Sign and verify artifact with certificate
cosign sign-blob --key cosign.key ./dist/app.tar.gz

# Verify signed artifact
cosign verify-blob --key cosign.pub \
  --signature app.tar.gz.sig ./dist/app.tar.gz

# Generate and sign SBOM
syft myimage:latest -o cyclonedx-json > sbom.json
cosign attest --key cosign.key --predicate sbom.json myimage:latest
```

---

## 5. Dependency Security Automation

```python
#!/usr/bin/env python3
"""
Automated dependency vulnerability scanner
Integrates with CI/CD to block vulnerable dependencies
"""
import subprocess
import json
import sys

def check_python_dependencies() -> list:
    """Check Python dependencies for vulnerabilities"""
    result = subprocess.run(
        ["pip-audit", "--format=json", "--output=/dev/stdout"],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        return []
    
    try:
        vulns = json.loads(result.stdout)
        return [v for v in vulns if v.get("vulns")]
    except:
        return []

def check_node_dependencies() -> dict:
    """Check Node.js dependencies"""
    result = subprocess.run(
        ["npm", "audit", "--json"],
        capture_output=True, text=True
    )
    
    try:
        audit_data = json.loads(result.stdout)
        return audit_data.get("metadata", {}).get("vulnerabilities", {})
    except:
        return {}

def gate_build(allow_severity: list = ["low", "moderate"]) -> bool:
    """Block build if critical vulnerabilities found"""
    
    python_vulns = check_python_dependencies()
    node_vulns = check_node_dependencies()
    
    # Check for critical/high vulnerabilities
    critical_found = False
    
    for vuln in python_vulns:
        for v in vuln.get("vulns", []):
            severity = v.get("fix_versions", [])
            # Logic to check severity
    
    high_count = node_vulns.get("high", 0)
    critical_count = node_vulns.get("critical", 0)
    
    if critical_count > 0 or high_count > 5:
        print(f"[FAIL] Build blocked: {critical_count} critical, {high_count} high vulnerabilities")
        return False
    
    print("[PASS] No blocking vulnerabilities found")
    return True

if __name__ == "__main__":
    if not gate_build():
        sys.exit(1)
```

---

## 6. Supply Chain Security Countermeasures Summary

| Threat | Countermeasure | Tool |
|--------|---------------|------|
| Typosquatting | Package name validation, allowlist management | pip-audit, npm audit |
| Dependency confusion | Internal registry priority configuration | Artifactory, Nexus |
| Malicious packages | Static analysis before installation | Bandit, semgrep |
| Build integrity | SLSA compliance, artifact signing | cosign, sigstore |
| Vulnerable dependencies | Regular CVE scanning | Dependabot, Snyk |
| CI/CD compromise | Secret scanning, least privilege | gitleaks, trufflehog |
| Missing SBOM | Automated dependency tree generation | syft, cyclonedx |

<!-- detect-validate-18 -->
## Supply Chain Attack Detection and Defense Validation

Supply-chain attacks target *dependency confusion, typosquatting, malicious install scripts, and build tampering*. Defenders must verify **whether internal-name squatting, script isolation, and provenance verification actually work**. Validate only on **owned builds**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Dependency confusion | Public registry resolved first | Scope, internal registry priority | Internal package name on public registry |
| Typosquatting | Look-alike package names | Lockfile, allowlist | New/low-reputation dependency added |
| Malicious install script | postinstall arbitrary exec | --ignore-scripts, isolated build | Network/file access during install |
| Build tampering | Unverified artifact integrity | SLSA provenance, signing | Artifact hash mismatch |

### Defense validation (verify directly)

```bash
# 1) Check whether an internal package name is squatted on a public registry — confusion surface
npm view "@yourscope/internal-pkg" version 2>/dev/null && echo "exists publicly -- review confusion risk"
# 2) Confirm install scripts cannot run arbitrary code (own build)
npm ci --ignore-scripts && echo "scriptless install OK -- shrinks postinstall abuse surface"
#   Compare reproducible-build artifact hashes to confirm tampering as fact
```

> Supply-chain defense is about *whether it works*, not *whether a control exists* -- "we verify" differs from "we actually block and surface name-squatting, malicious scripts, and tampering". Confirm isolated install, provenance, and hash comparison directly on owned builds ([[35_Supply_Chain_Attacks]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).
