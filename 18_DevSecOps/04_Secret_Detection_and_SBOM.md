> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 시크릿 탐지 및 SBOM(소프트웨어 자재 명세)

## 개요

소스코드와 git 히스토리에 숨겨진 API 키, 패스워드, 인증서는 가장 흔한 보안 사고 원인 중 하나다. SBOM은 소프트웨어에 포함된 모든 컴포넌트를 추적하여 의존성 취약점을 관리한다.

---

## 시크릿 탐지

### 시크릿이 노출되는 경로

```
1. 코드에 하드코딩 → 커밋 → GitHub 공개 레포
2. .env 파일 실수로 커밋
3. 로그 파일에 패스워드 출력
4. Docker 이미지 레이어에 빌드 시 포함
5. 환경변수를 echo로 출력
6. CI/CD 파이프라인 로그에 노출
```

### TruffleHog - git 히스토리 스캔

```bash
# 설치
pip install trufflehog3
# 또는 최신 버전
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

# 로컬 레포 전체 히스토리 스캔
trufflehog git file://. --only-verified

# GitHub 레포 스캔 (공개)
trufflehog github --repo https://github.com/TARGET/REPO

# 조직 전체 스캔
trufflehog github --org TARGET_ORG --token GITHUB_TOKEN

# Docker 이미지 스캔
trufflehog docker --image ubuntu:latest

# 특정 커밋 범위만
trufflehog git file://. --since-commit HEAD~100 --branch main
```

### Gitleaks - 정규식 기반 탐지

```bash
# 설치
brew install gitleaks  # macOS
apt install gitleaks   # Kali

# 현재 레포 스캔
gitleaks detect --source . --report-format json --report-path leaks.json

# 특정 커밋 범위
gitleaks detect --source . --log-opts="HEAD~50..HEAD"

# CI에서 staged 변경사항만 확인
gitleaks protect --staged

# 상세 출력
gitleaks detect --source . --verbose --no-git
```

### 커스텀 gitleaks 규칙

```toml
# .gitleaks.toml
title = "Custom Secret Rules"

[[rules]]
id = "internal-api-key"
description = "Internal API Key Pattern"
regex = '''CORP_[A-Z0-9]{32}'''
tags = ["api", "key"]

[[rules]]
id = "private-key-begin"
description = "Private Key"
regex = '''-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'''
tags = ["key", "private"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[allowlist]
paths = [
    '''tests/fixtures/.*''',
    '''\.md$''',
]
```

---

## 주요 API 키 패턴 (정규식)

```python
import re

SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}",
    "GitHub Token":        r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token":         r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "Stripe Secret":       r"sk_(live|test)_[0-9a-zA-Z]{24,}",
    "Private Key":         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY",
    "Database URL":        r"(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+/\w+",
    "JWT Token":           r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "Generic Password":    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
}
```

---

## SBOM(Software Bill of Materials) 생성

SBOM은 소프트웨어에 포함된 모든 컴포넌트(오픈소스 라이브러리, 의존성)를 목록화한 문서다.

### Syft로 SBOM 생성

```bash
# 설치
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# 로컬 디렉토리 스캔 (Python 프로젝트)
syft dir:. -o cyclonedx-json > sbom.json
syft dir:. -o spdx-json > sbom_spdx.json

# Docker 이미지 SBOM
syft ubuntu:latest -o table
syft python:3.11-slim -o cyclonedx-json > image_sbom.json

# 파일 출력 형식
syft dir:. -o spdx-tag-value > sbom.spdx
syft dir:. -o cyclonedx-xml > sbom.xml
```

### OWASP Dependency-Check

```bash
# 설치 (Java 필요)
wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.0/dependency-check-9.0.0-release.zip
unzip dependency-check-9.0.0-release.zip

# Python 프로젝트 스캔
./dependency-check/bin/dependency-check.sh \
  --project MyProject \
  --scan /path/to/project \
  --out reports/ \
  --format HTML,JSON \
  --enableExperimental

# requirements.txt 직접 스캔
./dependency-check/bin/dependency-check.sh \
  --project MyApp \
  --scan requirements.txt \
  --out /tmp/reports
```

### pip-audit (Python 의존성 취약점)

```bash
# 설치
pip install pip-audit

# 현재 환경 스캔
pip-audit

# requirements.txt 스캔
pip-audit -r requirements.txt

# JSON 출력
pip-audit -r requirements.txt -f json -o audit.json

# 특정 패키지만
pip-audit --package requests==2.25.0
```

---

## CI/CD 파이프라인 통합

### GitHub Actions - 시크릿 탐지

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sbom-and-vuln:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: Scan SBOM for vulnerabilities
        uses: anchore/scan-action@v3
        with:
          sbom: sbom.json
          fail-build: true
          severity-cutoff: high

      - name: Python dependency audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt -f json -o pip-audit.json
          cat pip-audit.json | python3 -c "
          import json, sys
          data = json.load(sys.stdin)
          vulns = data.get('dependencies', [])
          found = [v for v in vulns if v.get('vulns')]
          if found:
              print(f'취약점 발견: {len(found)}개')
              sys.exit(1)
          "
```

---

## Python 시크릿 스캐너 구현

```python
#!/usr/bin/env python3
"""
Git Secret Scanner - git 로그에서 시크릿 탐지
사용법: python3 git_secret_scan.py --repo /path/to/repo --since 100
"""

import argparse
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token":     re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "Google API Key":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Private Key":      re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY"),
    "Database URL":     re.compile(r"(?:postgres|mysql|mongodb)://[^:]+:[^@]+@"),
    "Generic Password": re.compile(r"(?i)(?:password|passwd|secret|api_key)\s*[=:]\s*['\"]([^'\"]{8,})"),
    "JWT Token":        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

EXCLUDE_EXTENSIONS = {".lock", ".sum", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff"}
EXCLUDE_PATHS = {"node_modules", "vendor", ".git", "__pycache__"}


@dataclass
class SecretFinding:
    commit_hash: str
    file_path: str
    line_number: int
    secret_type: str
    line_content: str

    def __str__(self) -> str:
        preview = self.line_content[:80].strip()
        return (
            f"[{self.secret_type}]\n"
            f"  커밋: {self.commit_hash[:8]}\n"
            f"  파일: {self.file_path}:{self.line_number}\n"
            f"  내용: {preview}"
        )


def get_commits(repo_path: Path, since_count: int) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "log",
         f"-{since_count}", "--format=%H"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return []
    return result.stdout.strip().split("\n")


def get_commit_diff(repo_path: Path, commit_hash: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "show",
         "--unified=0", commit_hash],
        capture_output=True,
        text=True,
        timeout=30,
        errors="replace",
    )
    return result.stdout if result.returncode == 0 else ""


def scan_diff(commit_hash: str, diff_text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    current_file = ""
    line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else ""
            line_num = 0
            continue

        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_num = int(match.group(1)) if match else 0
            continue

        # 추가된 라인만 검사 (+로 시작)
        if not line.startswith("+") or line.startswith("+++"):
            continue

        # 제외 경로/확장자 필터
        if any(excl in current_file for excl in EXCLUDE_PATHS):
            continue
        ext = Path(current_file).suffix
        if ext in EXCLUDE_EXTENSIONS:
            continue

        content = line[1:]  # '+' 제거

        for secret_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                findings.append(
                    SecretFinding(
                        commit_hash=commit_hash,
                        file_path=current_file,
                        line_number=line_num,
                        secret_type=secret_type,
                        line_content=content,
                    )
                )
                break  # 하나의 라인에서 첫 매칭만

        line_num += 1

    return findings


def scan_repo(repo_path: Path, since_count: int, workers: int) -> list[SecretFinding]:
    commits = get_commits(repo_path, since_count)
    if not commits:
        print("[-] 커밋을 찾을 수 없음", file=sys.stderr)
        return []

    print(f"[*] {len(commits)}개 커밋 스캔 시작...")
    all_findings: list[SecretFinding] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_commit = {
            executor.submit(get_commit_diff, repo_path, c): c
            for c in commits
        }
        for future in as_completed(future_to_commit):
            commit = future_to_commit[future]
            try:
                diff = future.result()
                findings = scan_diff(commit, diff)
                all_findings.extend(findings)
                if findings:
                    print(f"  [!] {commit[:8]} — {len(findings)}개 발견")
            except Exception as e:
                print(f"  [-] {commit[:8]} 오류: {e}", file=sys.stderr)

    return all_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git Secret Scanner - git 히스토리 시크릿 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 git_secret_scan.py --repo .
  python3 git_secret_scan.py --repo /path/to/repo --since 500 --workers 20
  python3 git_secret_scan.py --repo . --since 100 --output findings.txt
        """,
    )
    parser.add_argument("--repo", type=Path, default=Path("."), help="레포 경로")
    parser.add_argument("--since", type=int, default=100, help="검사할 최근 커밋 수")
    parser.add_argument("--workers", type=int, default=8, help="병렬 작업 수")
    parser.add_argument("--output", type=Path, help="결과 저장 파일")

    args = parser.parse_args()

    if not (args.repo / ".git").exists():
        print(f"[-] git 레포가 아님: {args.repo}", file=sys.stderr)
        sys.exit(1)

    findings = scan_repo(args.repo, args.since, args.workers)

    if not findings:
        print("[+] 시크릿 미발견")
        sys.exit(0)

    print(f"\n{'='*60}")
    print(f"발견된 시크릿: {len(findings)}개")
    print(f"{'='*60}\n")

    output_lines: list[str] = []
    for finding in findings:
        output_lines.append(str(finding))
        print(finding)
        print()

    if args.output:
        args.output.write_text("\n\n".join(output_lines))
        print(f"[+] 결과 저장: {args.output}")

    sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 실전 체크리스트

### 사전 커밋 방지 (pre-commit hook)
```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

```bash
# 설치 및 활성화
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

<a name="english"></a>

# Secret Detection and SBOM (Software Bill of Materials)

## Overview

API keys, passwords, and certificates hidden in source code and git history are among the most common security incident causes. SBOM tracks all components included in software to manage dependency vulnerabilities.

---

## 1. Secret Detection Tools

### GitLeaks — Git History Scanning

```bash
# Scan current repository
gitleaks detect --source=. --verbose

# Scan specific git range
gitleaks detect --source=. --log-opts="HEAD~100..HEAD"

# Scan remote repository
gitleaks detect --source=https://github.com/org/repo

# Generate report
gitleaks detect --source=. --report-format json --report-path leaks.json

# Custom rules (.gitleaks.toml)
[[rules]]
id = "custom-db-password"
description = "Database password in config"
regex = '''(?i)(db_pass|database_password)\s*=\s*['"]?([^\s'"]{8,})'''
tags = ["database", "password"]
```

### TruffleHog — High Entropy Detection

```bash
# Git repository scan (verify mode - only real secrets)
trufflehog git https://github.com/org/repo --only-verified

# Local filesystem scan
trufflehog filesystem --path=./source --only-verified

# S3 bucket scan
trufflehog s3 --bucket=my-bucket --only-verified

# Docker image scan
trufflehog docker --image=myimage:latest

# GitHub organization scan
trufflehog github --org=myorg --only-verified
```

---

## 2. SBOM (Software Bill of Materials)

### What is SBOM?

```
SBOM = Complete inventory of software components

Required by:
  - US Executive Order on Cybersecurity (May 2021)
  - NTIA Minimum Elements for SBOM
  - FDA for medical devices
  - Financial sector regulators

SBOM Formats:
  - SPDX (Software Package Data Exchange) — Linux Foundation standard
  - CycloneDX — OWASP standard (more security-focused)
  - SWID (Software Identification Tags)
```

### Generating SBOM

```bash
# Syft — generate SBOM from container or filesystem
syft alpine:latest -o cyclonedx-json > sbom.json
syft dir:./project -o spdx-json > sbom.spdx.json

# Trivy — generate SBOM
trivy image --format cyclonedx --output sbom.json myimage:latest

# For Python project
pip-audit --format=json > dependencies.json

# For Node.js project
npm sbom --sbom-format cyclonedx > sbom.json
```

### Vulnerability Scanning with SBOM

```bash
# Grype — scan SBOM for vulnerabilities
grype sbom:./sbom.json
grype myimage:latest --output table

# OWASP Dependency-Check
dependency-check --project "My App" --scan ./libs \
  --format JSON --out ./reports

# Trivy SBOM scan
trivy sbom ./sbom.json --severity HIGH,CRITICAL
```

---

## 3. Dependency Management

### Python

```bash
# pip-audit — Python dependency vulnerability check
pip install pip-audit
pip-audit
pip-audit --requirement requirements.txt

# safety — another Python security checker
pip install safety
safety check
safety check -r requirements.txt --full-report
```

### JavaScript/Node.js

```bash
# npm audit
npm audit
npm audit fix          # Auto-fix where possible
npm audit fix --force  # Force fixes (may break changes)

# Snyk
snyk test
snyk monitor  # Continuous monitoring

# Retire.js — vulnerable library detection
retire --path ./js-files
```

### Container Images

```bash
# Trivy — container vulnerability scanner
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myimage:latest

# Clair — another container scanner
# Anchore — enterprise container security

# Best practices for base images
FROM python:3.12-slim        # Use specific version
# NOT: FROM python:latest   # Avoid latest tag

# Run as non-root user
RUN useradd -m appuser
USER appuser
```

---

## 4. Pre-commit Hooks for Secret Prevention

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
  
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.0
    hooks:
      - id: trufflehog
        args: ['--only-verified']
```

```bash
# Install and activate
pip install pre-commit
pre-commit install
pre-commit run --all-files
```
