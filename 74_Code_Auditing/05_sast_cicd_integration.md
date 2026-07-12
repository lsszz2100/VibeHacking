> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# CI/CD 파이프라인에 SAST 통합

## 실습 환경 준비

> SAST 도구 + CI 러너가 필요합니다. Python 3.10+ 환경:

```bash
pip install semgrep bandit       # 파이프라인에 넣을 스캐너
pip install pre-commit           # 커밋 단계 게이트(선택)

# CI: GitHub Actions(.github/workflows) 또는 GitLab CI(.gitlab-ci.yml)
# 로컬 재현: act(https://github.com/nektos/act) 로 워크플로 로컬 실행
```

> 검증 팁: 파이프라인 게이트가 **실제로 빌드를 실패시키는지** 일부러 취약 코드를 커밋해 확인하세요. 통과해버리면 게이트 임계값/심각도 설정이 잘못된 것입니다.
> ⚠️ SARIF/스캔 리포트에 비밀이 포함될 수 있으니 아티팩트 접근 권한을 제한하세요.
> 🧪 별도 컨테이너 랩 없음 — 본인 레포 + CI로 구성.

---

## 개요

**SAST(Static Application Security Testing)**를 CI/CD 파이프라인에 통합하면 코드가 배포되기 전에 자동으로 보안 검사를 수행할 수 있습니다. "보안 좌편향(Shift Left Security)"의 핵심 실천법으로, 배포 후 취약점을 수정하는 것보다 훨씬 저렴하고 빠릅니다.

```
개발자 코드 작성
      ↓
Pre-commit Hook (로컬 보안 검사)
      ↓
Pull Request 생성
      ↓
CI/CD 파이프라인 자동 실행
  ├─ Semgrep 스캔
  ├─ Bandit 스캔
  ├─ CodeQL 분석
  └─ 보안 게이트 판단 (통과/실패)
      ↓
실패 시: PR 차단, 개발자에게 알림
통과 시: 다음 단계 (테스트, 빌드, 배포)
```

---

## 1. Pre-commit Hook 설정

Pre-commit Hook은 커밋 전에 자동으로 보안 검사를 실행합니다.

### .pre-commit-config.yaml

```yaml
# 프로젝트 루트에 .pre-commit-config.yaml 생성
repos:
  # Python 보안 스캔 — Bandit
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
        args: ["-r", ".", "--skip", "B101"]
        exclude: tests/

  # 일반 시크릿 탐지 — detect-secrets
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]

  # Semgrep 보안 규칙
  - repo: https://github.com/semgrep/semgrep
    rev: v1.72.0
    hooks:
      - id: semgrep
        args:
          - --config=p/python
          - --config=p/security-audit
          - --error  # 발견 시 exit code 1
        exclude: tests/

  # 기본 파일 검사 (대용량 파일, trailing whitespace 등)
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-added-large-files
        args: ["--maxkb=1024"]
      - id: detect-private-key
      - id: check-merge-conflict
```

### Pre-commit 설치 및 활성화

```bash
# pre-commit 설치
pip install pre-commit

# 현재 프로젝트에 훅 설치
pre-commit install

# 모든 파일에 대해 수동 실행
pre-commit run --all-files

# 특정 훅만 실행
pre-commit run bandit --all-files
```

---

## 2. GitHub Actions SAST 파이프라인

### .github/workflows/sast.yml

```yaml
name: SAST Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  # ─────────────────────────────────────────
  # Job 1: Bandit — Python 보안 스캔
  # ─────────────────────────────────────────
  bandit-scan:
    name: Bandit Python Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Bandit
        run: pip install bandit[toml]

      - name: Run Bandit
        run: |
          bandit -r ./src \
            -f json \
            -o bandit-results.json \
            --severity-level medium \
            --confidence-level medium \
            || true  # 발견이 있어도 계속 진행 (보고서 업로드 위해)

      - name: Upload Bandit results
        uses: actions/upload-artifact@v4
        with:
          name: bandit-results
          path: bandit-results.json

  # ─────────────────────────────────────────
  # Job 2: Semgrep — 규칙 기반 스캔
  # ─────────────────────────────────────────
  semgrep-scan:
    name: Semgrep Security Scan
    runs-on: ubuntu-latest
    container:
      image: returntocorp/semgrep
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          semgrep \
            --config=p/owasp-top-ten \
            --config=p/python \
            --json \
            --output=semgrep-results.json \
            ./src

      - name: Upload Semgrep results (SARIF)
        run: |
          semgrep \
            --config=p/owasp-top-ten \
            --sarif \
            --output=semgrep.sarif \
            ./src

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

      - name: Upload JSON results
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-results
          path: semgrep-results.json

  # ─────────────────────────────────────────
  # Job 3: CodeQL
  # ─────────────────────────────────────────
  codeql-scan:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
          queries: security-extended

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  # ─────────────────────────────────────────
  # Job 4: 보안 게이트 — 모든 스캔 결과 평가
  # ─────────────────────────────────────────
  security-gate:
    name: Security Gate
    runs-on: ubuntu-latest
    needs: [bandit-scan, semgrep-scan]
    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Evaluate security gate
        run: |
          python3 - << 'PYTHON_SCRIPT'
          import json, sys, os

          HIGH_THRESHOLD = 0    # HIGH 취약점 허용 개수
          MEDIUM_THRESHOLD = 5  # MEDIUM 취약점 허용 개수

          total_high = 0
          total_medium = 0

          # Bandit 결과 파싱
          bandit_file = "bandit-results/bandit-results.json"
          if os.path.exists(bandit_file):
              with open(bandit_file) as f:
                  data = json.load(f)
              for issue in data.get("results", []):
                  sev = issue.get("issue_severity", "").upper()
                  if sev == "HIGH":
                      total_high += 1
                  elif sev == "MEDIUM":
                      total_medium += 1

          # Semgrep 결과 파싱
          semgrep_file = "semgrep-results/semgrep-results.json"
          if os.path.exists(semgrep_file):
              with open(semgrep_file) as f:
                  data = json.load(f)
              for result in data.get("results", []):
                  sev = result.get("extra", {}).get("severity", "").upper()
                  if sev == "ERROR":
                      total_high += 1
                  elif sev == "WARNING":
                      total_medium += 1

          print(f"HIGH 취약점: {total_high} (허용 한도: {HIGH_THRESHOLD})")
          print(f"MEDIUM 취약점: {total_medium} (허용 한도: {MEDIUM_THRESHOLD})")

          failed = False
          if total_high > HIGH_THRESHOLD:
              print(f"보안 게이트 실패: HIGH 취약점이 {HIGH_THRESHOLD}개를 초과합니다.")
              failed = True
          if total_medium > MEDIUM_THRESHOLD:
              print(f"보안 게이트 실패: MEDIUM 취약점이 {MEDIUM_THRESHOLD}개를 초과합니다.")
              failed = True

          if failed:
              sys.exit(1)
          else:
              print("보안 게이트 통과!")
          PYTHON_SCRIPT
```

---

## 3. SARIF 형식 결과 처리

SARIF(Static Analysis Results Interchange Format)는 여러 도구의 결과를 표준화된 형식으로 표현합니다. GitHub는 SARIF를 지원하여 Security 탭에서 결과를 시각화합니다.

```python
#!/usr/bin/env python3
"""
SARIF 결과 파일을 파싱하고 요약 보고서를 생성하는 도구
Python 3.10+, 타입 힌트, argparse 포함
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SarifFinding:
    rule_id: str
    level: str          # error, warning, note
    message: str
    file_path: str
    start_line: int
    tool_name: str


@dataclass
class SarifReport:
    tool_name: str
    findings: list[SarifFinding] = field(default_factory=list)

    @property
    def counts_by_level(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.level] = counts.get(f.level, 0) + 1
        return counts


def parse_sarif(sarif_path: Path) -> list[SarifReport]:
    """SARIF JSON 파일 파싱"""
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] SARIF 파싱 실패 {sarif_path}: {e}", file=sys.stderr)
        return []

    reports: list[SarifReport] = []

    for run in data.get("runs", []):
        tool_name = (
            run.get("tool", {})
               .get("driver", {})
               .get("name", "unknown")
        )
        report = SarifReport(tool_name=tool_name)

        for result in run.get("results", []):
            # 위치 정보 추출
            locations = result.get("locations", [])
            file_path = ""
            start_line = 0
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                file_path = artifact.get("uri", "")
                region = physical.get("region", {})
                start_line = region.get("startLine", 0)

            # 메시지 추출
            message_obj = result.get("message", {})
            message = message_obj.get("text", "") if isinstance(message_obj, dict) else str(message_obj)

            report.findings.append(
                SarifFinding(
                    rule_id=result.get("ruleId", "unknown"),
                    level=result.get("level", "warning"),
                    message=message[:200],
                    file_path=file_path,
                    start_line=start_line,
                    tool_name=tool_name,
                )
            )

        reports.append(report)

    return reports


def print_summary(reports: list[SarifReport], verbose: bool = False) -> bool:
    """결과 요약 출력 — 보안 게이트 실패 여부 반환"""
    total_errors = 0

    for report in reports:
        counts = report.counts_by_level
        print(f"\n[도구] {report.tool_name}")
        print(f"  오류(error):    {counts.get('error', 0)}")
        print(f"  경고(warning):  {counts.get('warning', 0)}")
        print(f"  메모(note):     {counts.get('note', 0)}")

        total_errors += counts.get("error", 0)

        if verbose:
            for finding in report.findings:
                if finding.level == "error":
                    print(f"\n  [{finding.level.upper()}] {finding.rule_id}")
                    print(f"    위치: {finding.file_path}:{finding.start_line}")
                    print(f"    메시지: {finding.message}")

    print(f"\n{'='*50}")
    print(f"총 오류(error): {total_errors}")
    return total_errors > 0  # True = 보안 게이트 실패


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SARIF 결과 파일 파서 및 보안 게이트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sarif_file", help="파싱할 SARIF 파일 경로")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="오류 상세 정보 출력"
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="오류 발견 시 exit code 1 반환 (CI/CD 게이트용)",
    )
    args = parser.parse_args()

    sarif_path = Path(args.sarif_file)
    if not sarif_path.exists():
        print(f"[-] 파일을 찾을 수 없습니다: {sarif_path}", file=sys.stderr)
        sys.exit(1)

    reports = parse_sarif(sarif_path)
    if not reports:
        print("[!] SARIF 데이터를 파싱하지 못했습니다.")
        sys.exit(1)

    has_errors = print_summary(reports, verbose=args.verbose)

    if args.fail_on_error and has_errors:
        print("\n보안 게이트 실패 — 오류 수준 취약점이 발견되었습니다.")
        sys.exit(1)
    elif not has_errors:
        print("\n보안 게이트 통과!")


if __name__ == "__main__":
    main()
```

### 사용 예시

```bash
# Semgrep SARIF 결과 파싱 및 게이트 평가
semgrep --config=p/security-audit --sarif -o results.sarif ./src

python3 sarif_gate.py results.sarif --verbose --fail-on-error
```

---

## 4. 결과 분류: True Positive vs False Positive

SAST 도구는 오탐(False Positive)을 생성할 수 있습니다. 효율적인 분류가 중요합니다.

```python
#!/usr/bin/env python3
"""
SAST 결과 트리아지(분류) 추적기
발견된 취약점을 TP/FP로 분류하고 추적합니다.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from datetime import datetime


class Classification(Enum):
    UNREVIEWED = "unreviewed"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class TriageEntry:
    finding_id: str
    tool: str
    rule_id: str
    file_path: str
    line: int
    classification: str = Classification.UNREVIEWED.value
    reviewer: str = ""
    note: str = ""
    reviewed_at: str = ""


@dataclass
class TriageDB:
    entries: list[TriageEntry] = field(default_factory=list)

    def find(self, finding_id: str) -> TriageEntry | None:
        return next((e for e in self.entries if e.finding_id == finding_id), None)

    def add_or_update(self, entry: TriageEntry) -> None:
        existing = self.find(entry.finding_id)
        if existing:
            idx = self.entries.index(existing)
            self.entries[idx] = entry
        else:
            self.entries.append(entry)


def load_db(db_path: Path) -> TriageDB:
    if not db_path.exists():
        return TriageDB()
    try:
        data = json.loads(db_path.read_text(encoding="utf-8"))
        entries = [TriageEntry(**e) for e in data.get("entries", [])]
        return TriageDB(entries=entries)
    except (OSError, json.JSONDecodeError, TypeError) as e:
        print(f"[!] DB 로드 실패: {e}", file=sys.stderr)
        return TriageDB()


def save_db(db: TriageDB, db_path: Path) -> None:
    data = {"entries": [asdict(e) for e in db.entries]}
    try:
        db_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"[-] DB 저장 실패: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_classify(args: argparse.Namespace, db: TriageDB) -> None:
    """발견 항목 분류"""
    valid_classes = [c.value for c in Classification]
    if args.classification not in valid_classes:
        print(f"[-] 유효하지 않은 분류: {args.classification}")
        print(f"    사용 가능: {', '.join(valid_classes)}")
        sys.exit(1)

    entry = db.find(args.finding_id)
    if entry is None:
        # 새 항목 추가
        entry = TriageEntry(
            finding_id=args.finding_id,
            tool=args.tool or "unknown",
            rule_id=args.rule_id or "unknown",
            file_path=args.file_path or "",
            line=args.line or 0,
        )

    entry.classification = args.classification
    entry.reviewer = args.reviewer or "anonymous"
    entry.note = args.note or ""
    entry.reviewed_at = datetime.now().isoformat()
    db.add_or_update(entry)
    print(f"[+] 분류 완료: {args.finding_id} → {args.classification}")


def cmd_summary(db: TriageDB) -> None:
    """분류 현황 요약"""
    counts: dict[str, int] = {}
    for entry in db.entries:
        counts[entry.classification] = counts.get(entry.classification, 0) + 1

    print("\n[*] 트리아지 현황")
    for cls in Classification:
        print(f"  {cls.value:20s}: {counts.get(cls.value, 0)}")
    print(f"  {'합계':20s}: {len(db.entries)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SAST 결과 트리아지 추적기")
    parser.add_argument("--db", default="triage.json", help="트리아지 DB 파일")
    subparsers = parser.add_subparsers(dest="command")

    # classify 명령
    classify_parser = subparsers.add_parser("classify", help="발견 항목 분류")
    classify_parser.add_argument("finding_id", help="발견 항목 ID")
    classify_parser.add_argument(
        "classification",
        help=f"분류: {', '.join(c.value for c in Classification)}",
    )
    classify_parser.add_argument("--tool", help="도구 이름")
    classify_parser.add_argument("--rule-id", help="규칙 ID")
    classify_parser.add_argument("--file-path", help="파일 경로")
    classify_parser.add_argument("--line", type=int, help="라인 번호")
    classify_parser.add_argument("--reviewer", help="검토자 이름")
    classify_parser.add_argument("--note", help="메모")

    # summary 명령
    subparsers.add_parser("summary", help="분류 현황 출력")

    args = parser.parse_args()

    db_path = Path(args.db)
    db = load_db(db_path)

    match args.command:
        case "classify":
            cmd_classify(args, db)
            save_db(db, db_path)
        case "summary":
            cmd_summary(db)
        case _:
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## Diff 인지 SAST 게이팅 — 신규 유입 발견만 차단해 경보 피로 줄이기

레거시 코드베이스에 SAST를 처음 켜면 수백 건의 기존 발견이 쏟아져 **모든 것을 막으면 개발이 멈추고, 아무것도 안 막으면 게이트가 무의미**해진다. 실용적 머지 게이트는 절대량이 아니라 **이번 변경으로 새로 유입된 발견**만 실패시키고 기존 발견은 리포트-전용으로 둔다 — 회귀 도입은 차단하면서 정리는 별도 백로그로 미룬다. 위치 이동에 강인한 지문으로 베이스라인과 대조하는 것이 핵심이다.

```python
#!/usr/bin/env python3
"""SAST 결과를 베이스라인 지문 집합과 대조해 이번 변경으로 '새로 유입된' 발견만
빌드 실패로 게이트하고, 기존 발견은 리포트-전용으로 둔다. 경보 피로를 줄이고
회귀 도입을 차단하는 머지 게이트."""
import hashlib


def fingerprint(finding: dict) -> str:
    """규칙ID+파일+정규화 코드조각으로 위치 이동에 강인한 지문 생성(라인번호 제외)."""
    key = "|".join([
        finding.get("rule_id", ""),
        finding.get("file", ""),
        (finding.get("snippet", "") or "").strip(),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def gate(current: list[dict], baseline_fps: set[str]) -> dict:
    new, preexisting = [], []
    for f in current:
        (new if fingerprint(f) not in baseline_fps else preexisting).append(f)
    block = any(f.get("severity") in ("high", "critical") for f in new)
    return {"new_findings": new, "preexisting_count": len(preexisting), "block_merge": block}
```

| 신호 | 설명 | 오탐/보정 요인 |
|------|------|----------------|
| 신규 고/치명 발견 | 이번 변경이 취약점 유입 — 머지 차단 | 규칙 업데이트로 기존 코드가 새로 매칭되면 오탐 |
| 지문 미스매치(위치만 이동) | 코드 이동을 신규로 오인 가능 | 라인번호 제외·코드조각 정규화로 완화 |
| 베이스라인 급증 | 대량 리팩터/규칙 변경 신호 | 베이스라인 재기준선(rebaseline) 필요 |

**탐지/방어**: 게이트는 **신규 회귀 차단 + 기존 정리 백로그 분리**가 목적이다 — 규칙셋 버전을 고정해 규칙 변경발 오탐 급증을 막고, 베이스라인 갱신은 승인 흐름을 거쳐 부채가 조용히 리셋되지 않게 한다. 지문에 라인번호를 넣지 말고 규칙ID+정규화 스니펫으로 위치 이동에 강인하게 만든다([[18_DevSecOps]], [[13_SOC_Blue_Team]]). 검증은 **소유 리포지토리 CI**에서만.

---

<!-- validate-74 -->
## CI 게이팅 안전과 비밀정보 취급

SAST를 CI에 넣을 때 두 가지를 자주 놓칩니다. **빌드를 깨지 않으면서 의미 있게 게이팅**하는 정책과, **CI 로그·아티팩트에 비밀정보·취약점 상세를 흘리지 않는** 것입니다.

| 위험 | 문제 | 대응 |
|---|---|---|
| 과도한 게이팅 | 기존 이슈로 모든 빌드 실패 → 무력화 | 베이스라인 후 '신규 High'만 차단 |
| 게이팅 부재 | 경고가 무시되어 누적 | 신규 심각 이슈는 PR 차단 |
| 로그 노출 | SARIF·로그에 토큰/경로/취약상세 | 아티팩트 접근 제한, 비밀 마스킹 |
| 파이프라인 자체 | CI 권한·시크릿 탈취 표적 | 최소권한 토큰, 포크 PR 시크릿 차단 |

### 게이팅 정책 검증 (직접)

```yaml
# 개념: 기존 부채로 빌드를 깨지 않고 '신규 High'만 차단
sast_gate:
  baseline: known_issues.sarif      # 기존 이슈는 통과(부채로 추적)
  fail_on:
    severity: high                  # 신규 high 이상만 실패
    new_only: true                  # 베이스라인 대비 신규만
  redact_secrets_in_logs: true      # 로그/아티팩트에 비밀 노출 금지
```

> 핵심: 좋은 SAST 게이트는 "모두 빨강"이 아니라 **신규 심각 이슈만 막고 기존 부채는 추적**하는 것입니다. 동시에 CI 로그·아티팩트는 공격자에게 취약점 지도와 시크릿을 줄 수 있으니, 노출 면을 함께 잠그세요([[68_Purple_Team]]).

---

## 참고 자료

- CodeQL Action GitHub: https://github.com/github/codeql-action

**최신 기법·통제 (2025–2026):**
- SAST/SCA를 CI 게이트로 통합하되 신규회귀만 차단(백로그 분리)해 경보피로 방지 — 검증: 신규 취약 도입 PR이 실제 실패하는가
- SBOM·서명·프로버넌스(SLSA)로 공급망 무결성 — 파이프라인에서 강제되는지 확인([[35_Supply_Chain_Attacks]])

---

<a name="english"></a>

# Integrating SAST into CI/CD Pipelines

## Lab Environment Setup

> You need SAST tools + a CI runner. On Python 3.10+:

```bash
pip install semgrep bandit       # scanners to wire into the pipeline
pip install pre-commit           # commit-stage gate (optional)
# CI: GitHub Actions (.github/workflows) or GitLab CI (.gitlab-ci.yml)
# Local repro: act (https://github.com/nektos/act) runs workflows locally
```

> Validation tip: confirm the pipeline gate **actually fails the build** by committing deliberately vulnerable code. If it passes, your threshold/severity config is wrong.
> ⚠️ SARIF/scan reports may contain secrets — restrict artifact access.
> 🧪 No container lab — build it with your own repo + CI.

---

## Overview

Integrating **SAST (Static Application Security Testing)** into your CI/CD pipeline enables automatic security checks before code is deployed. This is the core practice of "Shift Left Security" — far cheaper and faster than fixing vulnerabilities after deployment.

```
Developer writes code
      ↓
Pre-commit Hook (local security check)
      ↓
Pull Request created
      ↓
CI/CD pipeline runs automatically
  ├─ Semgrep scan
  ├─ Bandit scan
  ├─ CodeQL analysis
  └─ Security gate evaluation (pass/fail)
      ↓
Fail: PR blocked, developer notified
Pass: Proceed to tests, build, deploy
```

---

## 1. Pre-commit Hook Setup

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
        args: ["-r", ".", "--skip", "B101"]
        exclude: tests/

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ["--maxkb=1024"]
```

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## 2. GitHub Actions SAST Pipeline

```yaml
name: SAST Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  bandit-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install bandit
      - run: |
          bandit -r ./src -f json -o bandit-results.json \
            --severity-level medium || true
      - uses: actions/upload-artifact@v4
        with:
          name: bandit-results
          path: bandit-results.json

  semgrep-scan:
    runs-on: ubuntu-latest
    container:
      image: returntocorp/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: |
          semgrep --config=p/owasp-top-ten \
            --sarif --output=semgrep.sarif ./src
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif

  security-gate:
    runs-on: ubuntu-latest
    needs: [bandit-scan, semgrep-scan]
    steps:
      - uses: actions/download-artifact@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Evaluate security gate
        run: |
          python3 - << 'EOF'
          import json, sys, os

          HIGH_THRESHOLD = 0
          MEDIUM_THRESHOLD = 5
          total_high = total_medium = 0

          bandit_file = "bandit-results/bandit-results.json"
          if os.path.exists(bandit_file):
              data = json.load(open(bandit_file))
              for issue in data.get("results", []):
                  sev = issue.get("issue_severity", "").upper()
                  if sev == "HIGH": total_high += 1
                  elif sev == "MEDIUM": total_medium += 1

          print(f"HIGH: {total_high} (limit: {HIGH_THRESHOLD})")
          print(f"MEDIUM: {total_medium} (limit: {MEDIUM_THRESHOLD})")

          failed = total_high > HIGH_THRESHOLD or total_medium > MEDIUM_THRESHOLD
          if failed:
              print("Security gate FAILED")
              sys.exit(1)
          print("Security gate PASSED")
          EOF
```

---

## 3. SARIF Result Processor

```python
#!/usr/bin/env python3
"""
SARIF file parser and security gate evaluator.
Python 3.10+, with type hints and argparse.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SarifFinding:
    rule_id: str
    level: str
    message: str
    file_path: str
    start_line: int
    tool_name: str


@dataclass
class SarifReport:
    tool_name: str
    findings: list[SarifFinding] = field(default_factory=list)

    @property
    def counts_by_level(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.level] = counts.get(f.level, 0) + 1
        return counts


def parse_sarif(sarif_path: Path) -> list[SarifReport]:
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] SARIF parse failed: {e}", file=sys.stderr)
        return []

    reports: list[SarifReport] = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        report = SarifReport(tool_name=tool_name)

        for result in run.get("results", []):
            locations = result.get("locations", [])
            file_path, start_line = "", 0
            if locations:
                physical = locations[0].get("physicalLocation", {})
                file_path = physical.get("artifactLocation", {}).get("uri", "")
                start_line = physical.get("region", {}).get("startLine", 0)

            msg = result.get("message", {})
            message = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            report.findings.append(
                SarifFinding(
                    rule_id=result.get("ruleId", "unknown"),
                    level=result.get("level", "warning"),
                    message=message[:200],
                    file_path=file_path,
                    start_line=start_line,
                    tool_name=tool_name,
                )
            )
        reports.append(report)
    return reports


def main() -> None:
    parser = argparse.ArgumentParser(description="SARIF result parser and security gate")
    parser.add_argument("sarif_file", help="Path to SARIF file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--fail-on-error", action="store_true",
                        help="Exit with code 1 if errors found (for CI/CD gate)")
    args = parser.parse_args()

    sarif_path = Path(args.sarif_file)
    if not sarif_path.exists():
        print(f"[-] File not found: {sarif_path}", file=sys.stderr)
        sys.exit(1)

    reports = parse_sarif(sarif_path)
    total_errors = 0

    for report in reports:
        counts = report.counts_by_level
        print(f"\n[Tool] {report.tool_name}")
        print(f"  errors:   {counts.get('error', 0)}")
        print(f"  warnings: {counts.get('warning', 0)}")
        print(f"  notes:    {counts.get('note', 0)}")
        total_errors += counts.get("error", 0)

        if args.verbose:
            for f in report.findings:
                if f.level == "error":
                    print(f"\n  [ERROR] {f.rule_id}")
                    print(f"    Location: {f.file_path}:{f.start_line}")
                    print(f"    Message: {f.message}")

    print(f"\nTotal errors: {total_errors}")
    if args.fail_on_error and total_errors > 0:
        print("Security gate FAILED")
        sys.exit(1)
    print("Security gate PASSED")


if __name__ == "__main__":
    main()
```

---

## References

- CodeQL Action GitHub: https://github.com/github/codeql-action

## Diff-Aware SAST Gating — Blocking Only Newly-Introduced Findings to Cut Alert Fatigue

Turning SAST on for a legacy codebase for the first time floods hundreds of pre-existing findings, so **blocking everything halts development while blocking nothing makes the gate meaningless**. A practical merge gate fails only on **findings newly introduced by the current change**, keeping pre-existing ones report-only — it blocks regression introduction while deferring cleanup to a separate backlog. The key is comparing against a baseline using fingerprints robust to code movement.

```python
#!/usr/bin/env python3
"""Compare SAST results against a baseline fingerprint set to gate (fail the build on)
only findings newly introduced by the current change, keeping pre-existing ones
report-only. A merge gate that cuts alert fatigue while blocking regression introduction."""
import hashlib


def fingerprint(finding: dict) -> str:
    """Build a move-robust fingerprint from rule ID + file + normalized snippet (no line no.)."""
    key = "|".join([
        finding.get("rule_id", ""),
        finding.get("file", ""),
        (finding.get("snippet", "") or "").strip(),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def gate(current: list[dict], baseline_fps: set[str]) -> dict:
    new, preexisting = [], []
    for f in current:
        (new if fingerprint(f) not in baseline_fps else preexisting).append(f)
    block = any(f.get("severity") in ("high", "critical") for f in new)
    return {"new_findings": new, "preexisting_count": len(preexisting), "block_merge": block}
```

| Signal | Meaning | False-positive / adjustment factor |
|--------|---------|-------------------------------------|
| New high/critical finding | The change introduced a vulnerability — block merge | A rule update newly matching old code is a false positive |
| Fingerprint mismatch (moved only) | Moved code may be misread as new | Mitigated by excluding line numbers and normalizing the snippet |
| Baseline surge | Signals a large refactor / rule change | A rebaseline is needed |

**Detection/defense**: The gate's purpose is to **block new regressions while separating existing cleanup into a backlog** — pin the ruleset version to avoid a false-positive surge from rule changes, and route baseline updates through an approval flow so debt isn't silently reset. Keep line numbers out of the fingerprint and use rule ID + normalized snippet so it is robust to code movement ([[18_DevSecOps]], [[13_SOC_Blue_Team]]). Validate only in **owned-repository CI**.

---

## CI Gating Safety and Secret Handling

Two things are often missed when putting SAST in CI: a policy that **gates meaningfully without breaking builds**, and **not leaking secrets or vulnerability detail into CI logs/artifacts**.

| Risk | Problem | Response |
|---|---|---|
| Over-gating | Every build fails on existing issues -> gate gets disabled | After a baseline, block only 'new High' |
| No gating | Warnings ignored and accumulate | Block PRs on new critical issues |
| Log exposure | Tokens/paths/vuln detail in SARIF/logs | Restrict artifact access, mask secrets |
| Pipeline itself | CI permissions/secrets are a target | Least-privilege tokens, block fork-PR secrets |

### Gating-policy validation (do it yourself)

```yaml
# Concept: don't break builds on existing debt; block only 'new High'
sast_gate:
  baseline: known_issues.sarif      # existing issues pass (tracked as debt)
  fail_on:
    severity: high                  # fail only on new high+
    new_only: true                  # only new vs the baseline
  redact_secrets_in_logs: true      # no secret exposure in logs/artifacts
```

> Core: a good SAST gate is not "all red" but **blocking only new critical issues while tracking existing debt**. At the same time, CI logs/artifacts can hand an attacker a vulnerability map and secrets — lock that exposure down too (see [[68_Purple_Team]]).
