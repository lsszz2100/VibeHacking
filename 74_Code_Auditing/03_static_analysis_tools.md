> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 정적 분석 도구 활용

## 개요

**정적 분석(Static Analysis)**은 프로그램을 실행하지 않고 소스코드를 분석하여 취약점을 찾는 기법입니다. 코드를 직접 읽는 수동 리뷰보다 빠르게 넓은 범위를 커버할 수 있지만, 오탐(False Positive)이 발생하므로 수동 리뷰와 병행해야 합니다.

---

## 1. Semgrep: 규칙 기반 정적 분석

Semgrep은 코드 패턴을 정의하고 일치하는 코드를 찾아주는 도구입니다. grep보다 훨씬 스마트하게 구문(syntax)을 이해합니다.

### 설치

```bash
pip install semgrep
# 또는
brew install semgrep
```

### 기본 사용법

```bash
# OWASP 규칙셋으로 Python 코드 스캔
semgrep --config=p/owasp-top-ten path/to/project

# 특정 언어 규칙
semgrep --config=p/python path/to/project

# JSON 형식으로 결과 저장
semgrep --config=p/security-audit --json -o results.json path/to/project
```

### 커스텀 Semgrep 규칙 작성

Semgrep 규칙은 YAML 형식으로 작성합니다.

```yaml
# rules/custom_security.yaml
rules:
  - id: python-sql-injection-fstring
    message: |
      f-string을 사용한 SQL 쿼리 구성은 SQL Injection에 취약합니다.
      파라미터화된 쿼리를 사용하세요.
    severity: ERROR
    languages: [python]
    pattern: |
      cursor.execute(f"...{...}...")

  - id: python-eval-usage
    message: "eval()은 임의 코드를 실행할 수 있습니다."
    severity: ERROR
    languages: [python]
    pattern: eval(...)

  - id: python-hardcoded-secret
    message: "하드코딩된 시크릿 키가 감지되었습니다."
    severity: WARNING
    languages: [python]
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(password|secret|api_key|token|passwd)

  - id: python-subprocess-shell-true
    message: "shell=True는 커맨드 인젝션에 취약합니다."
    severity: ERROR
    languages: [python]
    pattern: subprocess.run(..., shell=True, ...)
```

```bash
# 커스텀 규칙 적용
semgrep --config=rules/custom_security.yaml ./src
```

---

## 2. Bandit: Python 전용 보안 스캐너

Bandit은 Python 코드에 특화된 보안 분석 도구로, AST(추상 구문 트리)를 분석합니다.

### 설치 및 사용

```bash
pip install bandit

# 기본 스캔
bandit -r ./src

# 심각도/신뢰도 필터
bandit -r ./src -l -i  # 중간 이상 심각도, 중간 이상 신뢰도

# JSON 출력 및 특정 테스트 제외
bandit -r ./src -f json -o bandit_report.json --skip B101,B601
```

### Bandit 주요 체크 항목

```
B101: assert 문 사용 (테스트 코드에서만 허용)
B102: exec 사용
B103: 파일 권한 설정 (chmod)
B104: 0.0.0.0 바인딩 (모든 인터페이스)
B105~107: 하드코딩된 패스워드
B201: Flask 디버그 모드
B301: pickle 역직렬화
B302: marshal 사용
B303: MD2/MD4/MD5 해시 (취약한 알고리즘)
B304~B305: 취약한 암호화 알고리즘
B307: eval 사용
B311: 의사 난수 (random 모듈)
B501~B507: SSL/TLS 설정 취약점
B601~B603: subprocess, os.system 관련
B701~B703: Jinja2, Mako 템플릿 인젝션
```

---

## 3. CodeQL: 깊은 의미론적 코드 분석

CodeQL은 코드를 데이터베이스로 변환한 뒤 쿼리를 실행하여 취약점을 찾습니다. GitHub Actions와 통합하면 PR마다 자동 분석이 가능합니다.

### GitHub Actions 연동 (.github/workflows/codeql.yml)

```yaml
name: CodeQL Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # 매주 월요일 오전 6시

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      matrix:
        language: [python, javascript]

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### CodeQL 커스텀 쿼리 (QL 언어)

```ql
/**
 * @name SQL query built from user-controlled sources
 * @kind path-problem
 * @severity error
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunction().getName() = "execute" and
      sink.asExpr() = call.getArg(0)
    )
  }
}
```

---

## 4. SonarQube: 엔터프라이즈 코드 품질/보안 분석

SonarQube는 지속적인 코드 품질 관리를 위한 플랫폼으로, 보안 취약점과 코드 스멜(Code Smell)을 함께 분석합니다.

### Docker로 SonarQube 실행

```bash
# SonarQube 서버 시작
docker run -d \
  --name sonarqube \
  -p 9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  sonarqube:community

# 기본 접속: http://localhost:9000
# 기본 계정: admin / admin
```

### Python 프로젝트 분석 (sonar-project.properties)

```properties
sonar.projectKey=my-python-project
sonar.projectName=My Python Project
sonar.sources=src
sonar.tests=tests
sonar.python.coverage.reportPaths=coverage.xml
sonar.python.version=3.10
```

```bash
# SonarScanner 실행
docker run \
  --rm \
  --network host \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=<token>
```

---

## 5. 도구 결과 통합 및 보고서 생성

여러 도구의 결과를 하나의 보고서로 통합하는 Python 스크립트입니다.

```python
#!/usr/bin/env python3
"""
정적 분석 도구 결과 통합 보고서 생성기
Semgrep, Bandit 결과를 파싱하여 통합 HTML 보고서 생성
Python 3.10+, 타입 힌트, argparse 포함
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


@dataclass
class Vulnerability:
    tool: str
    severity: str
    rule_id: str
    message: str
    file_path: str
    line: int
    code_snippet: str = ""


@dataclass
class Report:
    project: str
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in self.vulnerabilities:
            sev = v.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


def parse_semgrep(json_path: Path) -> list[Vulnerability]:
    """Semgrep JSON 결과 파싱"""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Semgrep 결과 파싱 실패: {e}", file=sys.stderr)
        return []

    results: list[Vulnerability] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        severity_map = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }
        raw_sev = extra.get("severity", "INFO").upper()
        results.append(
            Vulnerability(
                tool="Semgrep",
                severity=severity_map.get(raw_sev, "LOW"),
                rule_id=item.get("check_id", "unknown"),
                message=extra.get("message", ""),
                file_path=item.get("path", ""),
                line=item.get("start", {}).get("line", 0),
                code_snippet=extra.get("lines", ""),
            )
        )
    return results


def parse_bandit(json_path: Path) -> list[Vulnerability]:
    """Bandit JSON 결과 파싱"""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Bandit 결과 파싱 실패: {e}", file=sys.stderr)
        return []

    severity_map = {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    results: list[Vulnerability] = []
    for issue in data.get("results", []):
        results.append(
            Vulnerability(
                tool="Bandit",
                severity=severity_map.get(issue.get("issue_severity", "LOW"), "LOW"),
                rule_id=issue.get("test_id", "unknown"),
                message=issue.get("issue_text", ""),
                file_path=issue.get("filename", ""),
                line=issue.get("line_number", 0),
                code_snippet=issue.get("code", ""),
            )
        )
    return results


def generate_html_report(report: Report) -> str:
    """HTML 보고서 생성"""
    summary = report.summary
    vuln_rows = ""
    severity_colors = {
        "HIGH": "#ff4444",
        "MEDIUM": "#ffaa00",
        "LOW": "#44aaff",
        "INFO": "#888888",
    }

    for v in sorted(
        report.vulnerabilities,
        key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}.get(x.severity, 9),
    ):
        color = severity_colors.get(v.severity, "#888")
        vuln_rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{v.severity}</span></td>
          <td>{v.tool}</td>
          <td>{v.rule_id}</td>
          <td>{v.message[:100]}</td>
          <td>{v.file_path}:{v.line}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>보안 감사 보고서 — {report.project}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a1a; color: #eee; padding: 20px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
    th {{ background: #333; }}
    tr:nth-child(even) {{ background: #222; }}
    .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
    .card {{ background: #333; padding: 15px; border-radius: 8px; min-width: 100px; }}
  </style>
</head>
<body>
  <h1>보안 감사 보고서</h1>
  <p>프로젝트: {report.project} | 생성 시간: {report.generated_at}</p>
  <div class="summary">
    <div class="card"><strong style="color:#ff4444">HIGH</strong><br>{summary.get("HIGH", 0)}</div>
    <div class="card"><strong style="color:#ffaa00">MEDIUM</strong><br>{summary.get("MEDIUM", 0)}</div>
    <div class="card"><strong style="color:#44aaff">LOW</strong><br>{summary.get("LOW", 0)}</div>
  </div>
  <table>
    <tr><th>심각도</th><th>도구</th><th>규칙 ID</th><th>메시지</th><th>위치</th></tr>
    {vuln_rows}
  </table>
</body>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="정적 분석 결과 통합 보고서 생성기")
    parser.add_argument("--project", required=True, help="프로젝트 이름")
    parser.add_argument("--semgrep", help="Semgrep JSON 결과 파일")
    parser.add_argument("--bandit", help="Bandit JSON 결과 파일")
    parser.add_argument("--output", default="security_report.html", help="출력 HTML 파일")
    args = parser.parse_args()

    report = Report(project=args.project)

    if args.semgrep:
        vulns = parse_semgrep(Path(args.semgrep))
        report.vulnerabilities.extend(vulns)
        print(f"[+] Semgrep: {len(vulns)}개 발견")

    if args.bandit:
        vulns = parse_bandit(Path(args.bandit))
        report.vulnerabilities.extend(vulns)
        print(f"[+] Bandit: {len(vulns)}개 발견")

    if not report.vulnerabilities:
        print("[!] 분석할 결과 파일이 없습니다. --semgrep 또는 --bandit 옵션을 사용하세요.")
        sys.exit(1)

    html = generate_html_report(report)
    output = Path(args.output)
    try:
        output.write_text(html, encoding="utf-8")
        print(f"[+] 보고서 저장: {output}")
        print(f"[*] 요약: {report.summary}")
    except OSError as e:
        print(f"[-] 보고서 저장 실패: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 사용 예시

```bash
# 1. 각 도구 실행
semgrep --config=p/security-audit --json -o semgrep.json ./src
bandit -r ./src -f json -o bandit.json

# 2. 통합 보고서 생성
python3 sast_reporter.py \
    --project "MyWebApp" \
    --semgrep semgrep.json \
    --bandit bandit.json \
    --output security_report.html
```

---

<!-- validate-74 -->
## 도구 노이즈 튜닝과 결과 검증

SAST 도구는 **대량의 경고를 쏟아내고 상당수가 오탐**입니다. 튜닝 없이 전부 처리하려 하면 진짜 결함이 노이즈에 묻힙니다. 노이즈를 줄이고 검증하는 절차가 필요합니다.

| 문제 | 증상 | 대응 |
|---|---|---|
| 오탐 폭주 | 수천 경고, 대부분 무의미 | 베이스라인 설정, 알려진 FP 억제 규칙 |
| 우선순위 부재 | 중요/사소 구분 안 됨 | 심각도×신뢰도×도달성으로 정렬 |
| 중복 도구 | 같은 이슈 여러 번 | 결과 정규화·중복 제거(03장 통합) |
| 검증 생략 | 도구 결과 그대로 보고 | 상위 항목은 수동 재현 |

### 결과 검증 (직접)

```text
SAST 결과 트리아지:
  □ 베이스라인 대비 '신규' 경고만 우선 검토하는가?
  □ 심각도×신뢰도 상위부터 보는가?
  □ 상위 후보는 코드를 직접 열어 도달성을 확인했는가?
  □ 억제(suppress)한 항목에 근거를 남겼는가?
```

> 핵심: SAST의 가치는 경고 수가 아니라 **신호 대 잡음비**입니다. 베이스라인으로 노이즈를 걷어내고, 상위 후보를 사람이 검증해야 도구가 실제로 결함을 잡습니다([[68_Purple_Team]]).

---

## 참고 자료

- Semgrep GitHub: https://github.com/semgrep/semgrep

---

<a name="english"></a>

# Static Analysis Tools

## Overview

**Static Analysis** examines source code without executing it to find vulnerabilities. It covers a wider area faster than manual review, but produces false positives, so it should always be paired with manual review.

---

## 1. Semgrep: Pattern-Based Static Analysis

Semgrep finds code matching defined patterns. It understands syntax far better than grep.

### Installation

```bash
pip install semgrep
```

### Basic Usage

```bash
# Scan with OWASP ruleset
semgrep --config=p/owasp-top-ten path/to/project

# Save results as JSON
semgrep --config=p/security-audit --json -o results.json path/to/project
```

### Writing Custom Semgrep Rules

```yaml
# rules/custom_security.yaml
rules:
  - id: python-sql-injection-fstring
    message: |
      Building SQL queries with f-strings is vulnerable to SQL Injection.
      Use parameterized queries instead.
    severity: ERROR
    languages: [python]
    pattern: cursor.execute(f"...{...}...")

  - id: python-eval-usage
    message: "eval() can execute arbitrary code."
    severity: ERROR
    languages: [python]
    pattern: eval(...)

  - id: python-hardcoded-secret
    message: "Hardcoded secret detected."
    severity: WARNING
    languages: [python]
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(password|secret|api_key|token|passwd)
```

---

## 2. Bandit: Python Security Scanner

Bandit is a Python-specific security tool that analyzes the AST (Abstract Syntax Tree).

### Installation and Usage

```bash
pip install bandit

# Basic scan
bandit -r ./src

# JSON output
bandit -r ./src -f json -o bandit_report.json
```

### Key Bandit Checks

```
B301: pickle deserialization
B303: MD5/MD4 weak hashing
B307: eval() usage
B311: pseudo-random numbers (random module)
B501-B507: SSL/TLS misconfigurations
B601-B603: subprocess, os.system
```

---

## 3. CodeQL: Deep Semantic Analysis

CodeQL converts code into a database and runs queries to find vulnerabilities. It integrates with GitHub Actions for automatic PR analysis.

### GitHub Actions Integration

```yaml
name: CodeQL Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
          queries: security-extended
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Perform Analysis
        uses: github/codeql-action/analyze@v3
```

---

## 4. Unified Report Generator

```python
#!/usr/bin/env python3
"""
Static analysis results aggregator — generates a unified HTML report
from Semgrep and Bandit JSON outputs.
Python 3.10+, with type hints and argparse
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


@dataclass
class Vulnerability:
    tool: str
    severity: str
    rule_id: str
    message: str
    file_path: str
    line: int


@dataclass
class Report:
    project: str
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            sev = v.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


def parse_semgrep(json_path: Path) -> list[Vulnerability]:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Failed to parse Semgrep results: {e}", file=sys.stderr)
        return []

    severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    return [
        Vulnerability(
            tool="Semgrep",
            severity=severity_map.get(r.get("extra", {}).get("severity", "INFO").upper(), "LOW"),
            rule_id=r.get("check_id", "unknown"),
            message=r.get("extra", {}).get("message", ""),
            file_path=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
        )
        for r in data.get("results", [])
    ]


def parse_bandit(json_path: Path) -> list[Vulnerability]:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Failed to parse Bandit results: {e}", file=sys.stderr)
        return []

    return [
        Vulnerability(
            tool="Bandit",
            severity=issue.get("issue_severity", "LOW").upper(),
            rule_id=issue.get("test_id", "unknown"),
            message=issue.get("issue_text", ""),
            file_path=issue.get("filename", ""),
            line=issue.get("line_number", 0),
        )
        for issue in data.get("results", [])
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Static analysis results aggregator")
    parser.add_argument("--project", required=True, help="Project name")
    parser.add_argument("--semgrep", help="Semgrep JSON output file")
    parser.add_argument("--bandit", help="Bandit JSON output file")
    parser.add_argument("--output", default="security_report.html")
    args = parser.parse_args()

    report = Report(project=args.project)

    if args.semgrep:
        vulns = parse_semgrep(Path(args.semgrep))
        report.vulnerabilities.extend(vulns)
        print(f"[+] Semgrep: {len(vulns)} findings")

    if args.bandit:
        vulns = parse_bandit(Path(args.bandit))
        report.vulnerabilities.extend(vulns)
        print(f"[+] Bandit: {len(vulns)} findings")

    if not report.vulnerabilities:
        print("[!] No result files provided. Use --semgrep or --bandit.")
        sys.exit(1)

    print(f"[*] Total findings: {len(report.vulnerabilities)}")
    print(f"[*] Summary: {report.summary}")
    print(f"[+] Report would be saved to: {args.output}")


if __name__ == "__main__":
    main()
```

---

## References

- Semgrep GitHub: https://github.com/semgrep/semgrep

## Tuning Tool Noise and Validating Results

SAST tools **emit a flood of warnings, many of them false positives**. Trying to process them all without tuning buries real defects in noise. You need a process to reduce noise and validate.

| Problem | Symptom | Response |
|---|---|---|
| FP flood | Thousands of warnings, mostly meaningless | Set a baseline, suppress known-FP rules |
| No prioritization | Critical/trivial not separated | Sort by severity x confidence x reachability |
| Duplicate tools | Same issue multiple times | Normalize/deduplicate results (section 3 integration) |
| Skipped validation | Reporting tool output as-is | Manually reproduce top items |

### Result validation (do it yourself)

```text
SAST result triage:
  [ ] Review only 'new' warnings vs the baseline first?
  [ ] Look at top severity x confidence first?
  [ ] Open the code to confirm reachability for top candidates?
  [ ] Leave a rationale for suppressed items?
```

> Core: SAST's value is not warning count but **signal-to-noise**. Strip noise with a baseline and have a human validate top candidates so the tool actually catches defects (see [[68_Purple_Team]]).
