# 공급망 보안 — 의존성 공격·SLSA·서명 검증

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
