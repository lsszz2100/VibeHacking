# DevSecOps 핵심 원칙 및 보안 자동화

## DevSecOps란

```
기존 DevOps:
  Dev (개발) ──► Ops (운영)
  보안은 배포 직전 단계에서만 검토

DevSecOps:
  Dev ──► Security ──► Ops
  보안을 개발 초기(Shift Left)부터 통합

"Security as Code" — 보안 정책도 코드로 관리
```

---

## 1. Shift Left 보안

### 보안 테스트 단계

```
코드 작성 단계:
  IDE 플러그인 (실시간 취약점 탐지)
  ├── SonarLint
  ├── Snyk IntelliJ/VSCode
  └── Semgrep

커밋 단계 (Pre-commit Hook):
  ├── gitleaks (시크릿 탐지)
  ├── detect-secrets
  └── talisman

CI/CD 파이프라인:
  ├── SAST (정적 분석) — 코드 스캔
  ├── SCA (의존성 분석) — 취약한 라이브러리
  ├── DAST (동적 분석) — 실행 중 앱 스캔
  ├── Container Scan — 이미지 취약점
  └── IaC Scan — 인프라 코드 보안

배포 단계:
  ├── RASP (실행 시 앱 보호)
  └── WAF, API Gateway

운영 단계:
  ├── SIEM 모니터링
  └── 취약점 관리
```

---

## 2. SAST (정적 애플리케이션 보안 테스트)

### Semgrep — 코드 패턴 분석

```bash
# 설치
pip install semgrep

# 기본 스캔 (OWASP Top 10)
semgrep --config=p/owasp-top-ten .

# 언어별 규칙
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .
semgrep --config=p/go .

# 커스텀 규칙
semgrep --config=custom_rules.yml .

# CI 통합
semgrep --config=auto --json --output=results.json .
```

```yaml
# custom_rules.yml — 커스텀 보안 규칙
rules:
  - id: hardcoded-password
    patterns:
      - pattern: |
          $X = "..."
      - metavariable-regex:
          metavariable: $X
          regex: (password|passwd|pwd|secret|api_key)
    message: "하드코딩된 자격증명 발견: $X"
    languages: [python, javascript, java]
    severity: ERROR

  - id: sql-injection-python
    patterns:
      - pattern: |
          cursor.execute("..." % $USER_INPUT)
      - pattern: |
          cursor.execute("..." + $USER_INPUT)
    message: "SQL 인젝션 취약점: f-string 또는 파라미터 바인딩 사용"
    languages: [python]
    severity: ERROR

  - id: command-injection
    pattern: |
      subprocess.call($CMD, shell=True)
    message: "커맨드 인젝션 위험: shell=True 사용 금지"
    languages: [python]
    severity: ERROR

  - id: insecure-deserialization
    pattern: |
      pickle.loads($DATA)
    message: "안전하지 않은 역직렬화"
    languages: [python]
    severity: WARNING
```

### SonarQube — 엔터프라이즈 코드 품질

```bash
# Docker로 SonarQube 실행
docker run -d --name sonarqube \
    -p 9000:9000 \
    -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
    sonarqube:community

# 초기 접속: http://localhost:9000 (admin/admin)

# 프로젝트 스캔
# Maven
mvn sonar:sonar \
    -Dsonar.host.url=http://localhost:9000 \
    -Dsonar.login=TOKEN

# Python
sonar-scanner \
    -Dsonar.projectKey=my-project \
    -Dsonar.sources=. \
    -Dsonar.host.url=http://localhost:9000 \
    -Dsonar.login=TOKEN

# 품질 게이트 설정
# New Code 기준:
#   Coverage >= 80%
#   Duplicated Lines <= 3%
#   Maintainability Rating = A
#   Reliability Rating = A
#   Security Rating = A
#   Security Hotspots Reviewed = 100%
```

### Bandit — Python 보안 분석

```bash
# 설치
pip install bandit

# 전체 프로젝트 스캔
bandit -r ./src

# 심각도 필터
bandit -r ./src -l HIGH -c MEDIUM

# CI용 JSON 출력
bandit -r ./src -f json -o bandit_results.json

# 특정 취약점 제외 (FP)
bandit -r ./src -s B105,B106  # 약한 비밀번호 체크 제외

# 예시 탐지 결과
# [B602] subprocess_popen_with_shell_equals_true
# [B501] request_with_no_cert_validation
# [B311] random (비암호학적 난수)
# [B105] hardcoded_password_string
```

---

## 3. SCA (소프트웨어 구성 분석)

### Snyk — 의존성 취약점 스캔

```bash
# 설치
npm install -g snyk

# 인증
snyk auth

# 스캔
snyk test                  # 현재 디렉토리
snyk test --all-projects   # 모든 서브프로젝트
snyk test --json           # JSON 출력

# 자동 수정
snyk fix

# Docker 이미지 스캔
snyk container test nginx:latest
snyk container test my-app:1.0

# IaC 스캔
snyk iac test ./terraform/
snyk iac test ./k8s/

# 모니터링 (지속적 알림)
snyk monitor
```

### OWASP Dependency-Check

```bash
# 설치
wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
unzip dependency-check-*.zip

# Java 프로젝트 스캔
./dependency-check.sh \
    --project "MyApp" \
    --scan ./target/ \
    --format HTML \
    --out ./report/

# Python
./dependency-check.sh \
    --project "MyPython" \
    --scan ./requirements.txt \
    --enableExperimental

# NVD API 키로 최신 CVE 조회
./dependency-check.sh \
    --nvdApiKey YOUR_NVD_KEY \
    --project "MyApp" \
    --scan ./ \
    --format JSON
```

### pip-audit (Python)

```bash
pip install pip-audit

# 현재 환경 스캔
pip-audit

# requirements.txt 스캔
pip-audit -r requirements.txt

# JSON 출력
pip-audit -r requirements.txt -f json -o audit.json

# 수정 제안
pip-audit -r requirements.txt --fix --dry-run
```

---

## 4. CI/CD 파이프라인 보안

### GitHub Actions 보안 파이프라인

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Semgrep SAST
      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/python
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_TOKEN }}

      # Gitleaks 시크릿 탐지
      - name: Gitleaks Secret Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Bandit (Python)
      - name: Bandit Security Scan
        run: |
          pip install bandit
          bandit -r ./src -f json -o bandit.json || true
      
      - name: Upload Bandit Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit.json

  sca:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt -f json -o pip-audit.json

      - name: Snyk Dependency Check
        uses: snyk/actions/python@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  container:
    name: Container Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker Image
        run: docker build -t myapp:test .

      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:test'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif

  iac:
    name: Infrastructure as Code Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Checkov IaC Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

  dast:
    name: Dynamic Analysis
    runs-on: ubuntu-latest
    needs: [sast, sca]
    steps:
      - name: Start App
        run: docker-compose up -d

      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

### GitLab CI/CD 보안 파이프라인

```yaml
# .gitlab-ci.yml
stages:
  - test
  - sast
  - dependency_scan
  - container_scan
  - dast
  - deploy

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml

# GitLab Ultimate에서는 자동 취약점 보고서 생성
# Security Dashboard에서 통합 관리

variables:
  SECURE_LOG_LEVEL: "debug"
  DS_EXCLUDED_PATHS: "tests/"
  SAST_EXCLUDED_PATHS: "tests/, docs/"

# 커스텀 Semgrep 규칙
semgrep-sast:
  extends: .sast-analyzer
  variables:
    SEMGREP_RULES: >-
      p/security-audit
      p/owasp-top-ten
    SEMGREP_TIMEOUT: 300
```

---

## 5. 시크릿 관리

### Vault by HashiCorp

```bash
# Vault 설치 및 개발 서버 시작
vault server -dev

# 환경 변수 설정
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'  # 개발 환경만

# KV 시크릿 저장
vault kv put secret/myapp \
    db_password="StrongPass123!" \
    api_key="abc123secret"

# 시크릿 조회
vault kv get secret/myapp
vault kv get -field=db_password secret/myapp

# 동적 자격증명 (데이터베이스)
vault secrets enable database
vault write database/config/mydb \
    plugin_name=mysql-database-plugin \
    connection_url="{{username}}:{{password}}@tcp(db:3306)/" \
    allowed_roles="myapp-role" \
    username="vault-admin" \
    password="vault-admin-pass"

# 역할 설정 (임시 자격증명)
vault write database/roles/myapp-role \
    db_name=mydb \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT ON mydb.* TO '{{name}}'@'%';" \
    default_ttl="1h" \
    max_ttl="24h"

# 임시 자격증명 발급
vault read database/creds/myapp-role
```

```python
# Python에서 Vault 사용
import hvac

client = hvac.Client(
    url='https://vault.company.com',
    token='YOUR_TOKEN'  # Kubernetes SA 토큰으로 대체 가능
)

# 시크릿 읽기
secret = client.secrets.kv.v2.read_secret_version(
    path='myapp',
    mount_point='secret'
)
db_password = secret['data']['data']['db_password']

# Kubernetes에서 Vault Agent 사용 (권장)
# Pod에 Vault Agent Sidecar 주입
# → 자동으로 시크릿을 파일로 마운트
# → 토큰 갱신 자동화
```

### Pre-commit 훅 설정

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
        name: 시크릿 탐지 (Gitleaks)
        description: 커밋 전 시크릿 스캔

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        name: 민감 데이터 탐지
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        name: Python 보안 분석
        args: ["-r", "src/", "-l", "HIGH"]

  - repo: https://github.com/semgrep/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        name: Semgrep SAST
        args: ["--config", "p/security-audit", "--error"]
```

```bash
# pre-commit 설치 및 활성화
pip install pre-commit
pre-commit install
pre-commit run --all-files  # 전체 파일 검사
```

---

## 6. DAST (동적 애플리케이션 보안 테스트)

### OWASP ZAP 자동화

```python
#!/usr/bin/env python3
"""
OWASP ZAP DAST 자동화 스캐너 CLI
사전 조건: ZAP 데몬 실행 → docker run -d -p 8080:8080 \
              ghcr.io/zaproxy/zaproxy:stable \
              zap.sh -daemon -port 8080 -host 0.0.0.0 \
              -config api.key=zap-api-key -config api.addrs.addr.name=.* \
              -config api.addrs.addr.enabled=true

사용: python3 zap_scan.py scan   --target http://app:8000 --output zap.json
      python3 zap_scan.py openapi --target http://app:8000 \
                                   --spec http://app:8000/v3/api-docs
      python3 zap_scan.py report  --input zap.json --format html
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("pip install requests")


class ZAPClient:
    def __init__(self, zap_url: str = "http://localhost:8080",
                 api_key: str = "zap-api-key") -> None:
        self.base  = zap_url.rstrip("/")
        self.key   = api_key
        self.sess  = requests.Session()
        self.sess.headers["X-ZAP-API-Key"] = api_key

    def _get(self, path: str, **params) -> dict:
        params.setdefault("apikey", self.key)
        r = self.sess.get(f"{self.base}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    # ── 세션 초기화 ────────────────────────────────────────

    def new_session(self) -> None:
        self._get("/JSON/core/action/newSession/", overwrite="true")
        print("[*] ZAP 세션 초기화")

    # ── 인증 설정 (Bearer 토큰) ──────────────────────────────

    def set_bearer_token(self, token: str) -> None:
        self._get("/JSON/script/action/enable/",
                  scriptName="JWT Header")
        # 대안: replacer 규칙으로 Authorization 헤더 삽입
        self._get("/JSON/replacer/action/addRule/",
                  description="Bearer Token",
                  enabled="true",
                  matchType="REQ_HEADER",
                  matchString="Authorization",
                  matchRegex="false",
                  replacement=f"Bearer {token}")
        print("[*] Bearer 토큰 설정 완료")

    # ── 스파이더 ────────────────────────────────────────────

    def spider(self, target: str, max_depth: int = 5) -> None:
        print("[*] 스파이더 크롤링 시작...")
        resp = self._get("/JSON/spider/action/scan/",
                         url=target, maxChildren=50, recurse="true",
                         subtreeOnly="true")
        scan_id = resp["scan"]
        while True:
            status = int(self._get("/JSON/spider/view/status/",
                                   scanId=scan_id)["status"])
            print(f"\r    진행률: {status}%", end="", flush=True)
            if status >= 100:
                break
            time.sleep(2)
        print(f"\n[+] 스파이더 완료")

    def ajax_spider(self, target: str, duration: int = 60) -> None:
        """Ajax Spider (SPA 크롤링)"""
        print("[*] Ajax 스파이더 시작...")
        self._get("/JSON/ajaxSpider/action/scan/", url=target)
        deadline = time.time() + duration
        while time.time() < deadline:
            status = self._get("/JSON/ajaxSpider/view/status/")["status"]
            if status == "stopped":
                break
            time.sleep(5)
        self._get("/JSON/ajaxSpider/action/stop/")
        print("[+] Ajax 스파이더 완료")

    # ── OpenAPI 가져오기 ─────────────────────────────────────

    def import_openapi(self, spec_url: str, target: str) -> None:
        print(f"[*] OpenAPI 스펙 가져오기: {spec_url}")
        self._get("/JSON/openapi/action/importUrl/",
                  url=spec_url, hostOverride=target)

    # ── 능동 스캔 ────────────────────────────────────────────

    def active_scan(self, target: str, policy: str = "") -> None:
        print("[*] 능동 스캔 시작...")
        resp = self._get("/JSON/ascan/action/scan/",
                         url=target, recurse="true",
                         scanPolicyName=policy)
        scan_id = resp["scan"]
        while True:
            status = int(self._get("/JSON/ascan/view/status/",
                                   scanId=scan_id)["status"])
            print(f"\r    능동 스캔: {status}%", end="", flush=True)
            if status >= 100:
                break
            time.sleep(5)
        print("\n[+] 능동 스캔 완료")

    # ── 결과 수집 ────────────────────────────────────────────

    def get_alerts(self, target: str | None = None) -> list[dict]:
        params: dict = {}
        if target:
            params["baseurl"] = target
        return self._get("/JSON/alert/view/alerts/", **params).get("alerts", [])

    def get_html_report(self) -> bytes:
        r = self.sess.get(f"{self.base}/OTHER/core/other/htmlreport/",
                          params={"apikey": self.key}, timeout=60)
        r.raise_for_status()
        return r.content

    def get_json_report(self) -> bytes:
        r = self.sess.get(f"{self.base}/OTHER/core/other/jsonreport/",
                          params={"apikey": self.key}, timeout=60)
        r.raise_for_status()
        return r.content


# ── CLI 명령 ──────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> None:
    zap = ZAPClient(args.zap_url, args.api_key)
    zap.new_session()
    if args.token:
        zap.set_bearer_token(args.token)

    zap.spider(args.target)
    if args.ajax:
        zap.ajax_spider(args.target, duration=args.ajax_duration)
    zap.active_scan(args.target)

    alerts = zap.get_alerts(args.target)
    high   = [a for a in alerts if a.get("risk") in ("High", "Critical")]

    print(f"\n[결과] 총 {len(alerts)}개  High/Critical: {len(high)}개")
    for a in sorted(high, key=lambda x: x.get("risk", "")):
        print(f"  [{a.get('risk')}] {a.get('name')} — {a.get('url','')[:80]}")

    if args.output:
        Path(args.output).write_bytes(zap.get_json_report())
        print(f"[+] JSON 보고서 저장: {args.output}")
    if args.html:
        Path(args.html).write_bytes(zap.get_html_report())
        print(f"[+] HTML 보고서 저장: {args.html}")

    if args.fail_on_high and high:
        print("[FAIL] High/Critical 취약점 발견 — 빌드 실패")
        sys.exit(1)


def cmd_openapi(args: argparse.Namespace) -> None:
    zap = ZAPClient(args.zap_url, args.api_key)
    zap.new_session()
    if args.token:
        zap.set_bearer_token(args.token)

    zap.import_openapi(args.spec, args.target)
    zap.active_scan(args.target)

    alerts = zap.get_alerts(args.target)
    high   = [a for a in alerts if a.get("risk") in ("High", "Critical")]
    print(f"\n[결과] 총 {len(alerts)}개  High/Critical: {len(high)}개")

    if args.output:
        Path(args.output).write_bytes(zap.get_json_report())
        print(f"[+] 보고서 저장: {args.output}")

    if args.fail_on_high and high:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="ZAP DAST 자동화 스캐너")
    parser.add_argument("--zap-url",  default="http://localhost:8080")
    parser.add_argument("--api-key",  default="zap-api-key")
    parser.add_argument("--token",    help="Bearer 토큰 (인증된 스캔)")
    parser.add_argument("--fail-on-high", action="store_true",
                        help="High 이상 발견 시 exit(1)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="전체 스파이더 + 능동 스캔")
    sc.add_argument("--target",       required=True)
    sc.add_argument("--ajax",         action="store_true")
    sc.add_argument("--ajax-duration",type=int, default=60)
    sc.add_argument("--output",       help="JSON 보고서 경로")
    sc.add_argument("--html",         help="HTML 보고서 경로")

    oa = sub.add_parser("openapi", help="OpenAPI 스펙 기반 스캔")
    oa.add_argument("--target",  required=True)
    oa.add_argument("--spec",    required=True, help="OpenAPI URL 또는 파일")
    oa.add_argument("--output",  help="JSON 보고서 경로")

    args = parser.parse_args()
    {"scan": cmd_scan, "openapi": cmd_openapi}[args.cmd](args)


if __name__ == "__main__":
    main()
```

---

## 7. 보안 정책 as Code

### OPA (Open Policy Agent)

```rego
# policy.rego — Kubernetes 보안 정책
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    
    # 특권 컨테이너 거부
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    
    msg := sprintf("특권 컨테이너 금지: %v", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    
    # 루트 실행 거부
    container := input.request.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    
    msg := sprintf("루트 실행 금지: %v", [container.name])
}

deny[msg] {
    input.request.kind.kind == "Deployment"
    
    # 최신 태그 이미지 거부
    container := input.request.object.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    
    msg := sprintf("latest 태그 금지: %v", [container.image])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    
    # 읽기 전용 루트 파일시스템 강제
    container := input.request.object.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    
    msg := sprintf("읽기 전용 파일시스템 필요: %v", [container.name])
}
```

```bash
# OPA Gatekeeper (Kubernetes)
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# 정책 템플릿 적용
kubectl apply -f constraint_templates/
kubectl apply -f constraints/
```

---

## 8. 취약점 관리 자동화

```python
#!/usr/bin/env python3
"""
통합 보안 스캔 결과 집계 및 보고서 생성 CLI
지원 도구: Trivy, Semgrep, Bandit, pip-audit, Gitleaks

사용: python3 vuln_manager.py aggregate \
          --trivy trivy.json --semgrep semgrep.json \
          --bandit bandit.json --pip-audit pip_audit.json \
          --output report.json
      python3 vuln_manager.py report --input report.json --format markdown
      python3 vuln_manager.py gate  --input report.json \
          --max-critical 0 --max-high 5
"""

from __future__ import annotations
import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
             "INFO": 4, "UNKNOWN": 5}


@dataclass
class Vuln:
    tool: str
    vuln_id: str
    severity: str
    title: str
    location: str          # 파일:줄 또는 패키지@버전
    fix: str = ""
    url: str = ""

    @property
    def sev_order(self) -> int:
        return SEV_ORDER.get(self.severity.upper(), 5)


# ── 로더 ─────────────────────────────────────────────────────

def load_trivy(path: Path) -> list[Vuln]:
    data = json.loads(path.read_text())
    vulns: list[Vuln] = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            vulns.append(Vuln(
                tool="trivy",
                vuln_id=v.get("VulnerabilityID", ""),
                severity=v.get("Severity", "UNKNOWN").upper(),
                title=v.get("Title", v.get("Description", "")[:80]),
                location=f"{target}: {v.get('PkgName','?')}@{v.get('InstalledVersion','?')}",
                fix=v.get("FixedVersion", ""),
                url=v.get("PrimaryURL", ""),
            ))
    return vulns


def load_semgrep(path: Path) -> list[Vuln]:
    data = json.loads(path.read_text())
    vulns: list[Vuln] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta  = extra.get("metadata", {})
        sev   = extra.get("severity", "MEDIUM").upper()
        line  = r.get("start", {}).get("line", 0)
        vulns.append(Vuln(
            tool="semgrep",
            vuln_id=r.get("check_id", ""),
            severity=sev,
            title=extra.get("message", "")[:120],
            location=f"{r.get('path', '?')}:{line}",
            url=meta.get("references", [""])[0] if meta.get("references") else "",
        ))
    return vulns


def load_bandit(path: Path) -> list[Vuln]:
    data = json.loads(path.read_text())
    vulns: list[Vuln] = []
    sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for r in data.get("results", []):
        sev = sev_map.get(r.get("issue_severity", "").upper(), "LOW")
        vulns.append(Vuln(
            tool="bandit",
            vuln_id=r.get("test_id", ""),
            severity=sev,
            title=r.get("issue_text", "")[:120],
            location=f"{r.get('filename','?')}:{r.get('line_number',0)}",
            url=r.get("more_info", ""),
        ))
    return vulns


def load_pip_audit(path: Path) -> list[Vuln]:
    data = json.loads(path.read_text())
    vulns: list[Vuln] = []
    # pip-audit JSON: {"dependencies": [{"name":..., "vulns":[...]}]}
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            cvss = v.get("fix_versions", [])
            vulns.append(Vuln(
                tool="pip-audit",
                vuln_id=v.get("id", ""),
                severity="HIGH",   # pip-audit은 severity 없음 → HIGH 기본
                title=v.get("description", "")[:120],
                location=f"{dep.get('name','?')}@{dep.get('version','?')}",
                fix=", ".join(cvss) if cvss else "",
                url=f"https://osv.dev/vulnerability/{v.get('id','')}",
            ))
    return vulns


def load_gitleaks(path: Path) -> list[Vuln]:
    """Gitleaks JSON 결과 (배열 형식)"""
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    return [
        Vuln(
            tool="gitleaks",
            vuln_id=r.get("RuleID", ""),
            severity="CRITICAL",
            title=f"Secret detected: {r.get('Description', '')}",
            location=f"{r.get('File','?')}:{r.get('StartLine',0)}",
        )
        for r in data
    ]


LOADERS = {
    "trivy":     load_trivy,
    "semgrep":   load_semgrep,
    "bandit":    load_bandit,
    "pip-audit": load_pip_audit,
    "gitleaks":  load_gitleaks,
}


# ── 보고서 생성 ──────────────────────────────────────────────

def build_summary(vulns: list[Vuln]) -> dict[str, int]:
    summary: dict[str, int] = defaultdict(int)
    for v in vulns:
        summary[v.severity] += 1
    return dict(summary)


def render_markdown(vulns: list[Vuln], status: str) -> str:
    summary = build_summary(vulns)
    lines = [
        f"# 통합 보안 스캔 보고서",
        f"날짜: {datetime.now().strftime('%Y-%m-%d %H:%M')}  상태: **{status}**\n",
        "## 심각도별 요약",
        "| 심각도 | 건수 |",
        "|--------|------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = summary.get(sev, 0)
        if cnt:
            lines.append(f"| {sev} | {cnt} |")
    lines.append(f"\n총 {len(vulns)}건\n")

    for sev in ["CRITICAL", "HIGH"]:
        items = [v for v in vulns if v.severity == sev]
        if items:
            lines.append(f"## {sev} 취약점")
            for v in items:
                ref = f"  [{v.url}]" if v.url else ""
                fix = f"  → fix: {v.fix}" if v.fix else ""
                lines.append(
                    f"- **[{v.vuln_id}]** ({v.tool}) {v.title[:80]}\n"
                    f"  `{v.location}`{fix}{ref}"
                )
            lines.append("")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────

def cmd_aggregate(args: argparse.Namespace) -> None:
    all_vulns: list[Vuln] = []
    for tool, loader in LOADERS.items():
        attr = tool.replace("-", "_")
        path_val = getattr(args, attr, None)
        if path_val:
            p = Path(path_val)
            if p.exists():
                loaded = loader(p)
                all_vulns.extend(loaded)
                print(f"[*] {tool}: {len(loaded)}건")
            else:
                print(f"[-] {tool} 파일 없음: {p}", file=sys.stderr)

    all_vulns.sort(key=lambda v: v.sev_order)
    out = Path(args.output)
    out.write_text(
        json.dumps([asdict(v) for v in all_vulns],
                   indent=2, ensure_ascii=False)
    )
    print(f"[+] 집계 완료: {len(all_vulns)}건 → {out}")


def cmd_report(args: argparse.Namespace) -> None:
    vulns = [Vuln(**v) for v in json.loads(Path(args.input).read_text())]
    summary = build_summary(vulns)
    has_critical = summary.get("CRITICAL", 0) > 0
    has_high     = summary.get("HIGH", 0) > 0
    status = "FAIL" if has_critical else ("WARN" if has_high else "PASS")

    if args.format == "markdown":
        report = render_markdown(vulns, status)
    else:
        report = json.dumps({"status": status, "summary": summary,
                              "findings": [asdict(v) for v in vulns]},
                            indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(report)
        print(f"[+] 보고서 저장: {args.output}")
    else:
        print(report)


def cmd_gate(args: argparse.Namespace) -> None:
    """품질 게이트 — 임계값 초과 시 exit(1)"""
    vulns   = [Vuln(**v) for v in json.loads(Path(args.input).read_text())]
    summary = build_summary(vulns)
    critical = summary.get("CRITICAL", 0)
    high     = summary.get("HIGH", 0)

    print(f"[Gate] CRITICAL={critical}/{args.max_critical}  HIGH={high}/{args.max_high}")
    if critical > args.max_critical or high > args.max_high:
        print("[FAIL] 품질 게이트 실패 — 빌드를 중단합니다")
        sys.exit(1)
    print("[PASS] 품질 게이트 통과")


def main() -> None:
    parser = argparse.ArgumentParser(description="통합 보안 스캔 집계 도구")
    sub = parser.add_subparsers(dest="cmd", required=True)

    agg = sub.add_parser("aggregate", help="여러 도구 결과 통합")
    agg.add_argument("--trivy")
    agg.add_argument("--semgrep")
    agg.add_argument("--bandit")
    agg.add_argument("--pip_audit", "--pip-audit")
    agg.add_argument("--gitleaks")
    agg.add_argument("--output", default="findings.json")

    rep = sub.add_parser("report", help="보고서 생성")
    rep.add_argument("--input", required=True)
    rep.add_argument("--format", choices=["markdown", "json"], default="markdown")
    rep.add_argument("--output")

    gate = sub.add_parser("gate", help="품질 게이트 (CI 빌드 실패 판단)")
    gate.add_argument("--input",       required=True)
    gate.add_argument("--max-critical", type=int, default=0)
    gate.add_argument("--max-high",     type=int, default=5)

    args = parser.parse_args()
    {"aggregate": cmd_aggregate, "report": cmd_report,
     "gate": cmd_gate}[args.cmd](args)


if __name__ == "__main__":
    main()
```

---

## 9. DevSecOps 보안 체크리스트

### 코드 및 의존성 보안
```
소스코드:
  □ 하드코딩된 자격증명 없음 (gitleaks 검사)
  □ SAST 도구 통과 (Semgrep/SonarQube/Bandit)
  □ 안전하지 않은 함수 미사용 (strcpy, system 등)
  □ SQL/커맨드 인젝션 방어 코드
  □ 입력 검증 및 출력 인코딩

의존성:
  □ SCA 도구로 알려진 CVE 없음 (Snyk/Dependency-Check)
  □ 최신 버전 의존성 사용
  □ 라이선스 컴플라이언스 확인
  □ 서드파티 라이브러리 출처 신뢰 확인

컨테이너:
  □ 공식 베이스 이미지 사용 (alpine, slim 권장)
  □ Trivy/Grype로 이미지 취약점 스캔
  □ 루트가 아닌 사용자로 실행 (USER 지시어)
  □ 읽기 전용 파일시스템 설정
  □ 최소 capabilities만 허용
  □ latest 태그 사용 금지 (버전 고정)
```

### 인프라 및 배포 보안
```
인프라 as Code:
  □ Checkov/tfsec으로 Terraform 코드 점검
  □ kube-bench로 Kubernetes CIS 벤치마크 점검
  □ 퍼블릭 노출 리소스 최소화
  □ 암호화 설정 (저장소, 전송 중)

배포 파이프라인:
  □ CI/CD 파이프라인 접근 제어
  □ 빌드 아티팩트 서명 (cosign)
  □ 배포 승인 프로세스 (Change Management)
  □ 롤백 절차 문서화 및 테스트

운영:
  □ RBAC (역할 기반 접근 제어) 적용
  □ 네트워크 정책 (Network Policy) 설정
  □ 시크릿은 Vault/환경변수 아닌 시크릿 관리자 사용
  □ 로그 중앙 집중화 (ELK, Splunk 등)
  □ 알림 및 인시던트 대응 절차
```

### 보안 테스트 체크리스트
```
SAST (정적):
  □ 코드 커밋 시 자동 실행
  □ PR 차단 정책 (HIGH/CRITICAL)
  □ False Positive 관리 (suppress 정책)

DAST (동적):
  □ 스테이징 환경에서 정기 실행
  □ 인증된 스캔 (로그인 세션 포함)
  □ API 엔드포인트 커버리지

침투 테스트:
  □ 연 1회 이상 외부 전문가 테스트
  □ 주요 변경 시 집중 테스트
  □ 발견사항 추적 및 재테스트
```

---

## 10. NIST Cybersecurity Framework (CSF) 적용

### CSF 5대 핵심 기능

```
IDENTIFY (식별)
  - 자산 관리: 하드웨어/소프트웨어/데이터 인벤토리
  - 비즈니스 환경 이해
  - 위험 평가 및 위험 관리 전략
  - 공급망 위험 관리

PROTECT (보호)
  - 접근 제어 (IAM, MFA, 최소 권한)
  - 인식 제고 및 훈련
  - 데이터 보안 (암호화, DLP)
  - 정보 보호 프로세스 및 절차
  - 유지 관리
  - 보호 기술 (방화벽, AV, EDR)

DETECT (탐지)
  - 이상 및 이벤트 탐지
  - 보안 모니터링 (SIEM)
  - 탐지 프로세스

RESPOND (대응)
  - 대응 계획 수립
  - 커뮤니케이션 (내부/외부)
  - 분석 (포렌식, 영향 평가)
  - 완화 조치
  - 개선

RECOVER (복구)
  - 복구 계획
  - 개선 (교훈 적용)
  - 커뮤니케이션 (이해관계자)
```

### DevSecOps와 CSF 매핑
```
개발 단계             CSF 기능         DevSecOps 도구
─────────────────────────────────────────────────────────
요구사항 분석    →   IDENTIFY      →  위험 분류, 데이터 분류
코드 작성        →   PROTECT       →  SAST, Pre-commit Hook
CI/CD 파이프라인 →   DETECT        →  SCA, DAST, Container Scan
스테이징 배포    →   DETECT/PROTECT →  Pen Test, IaC Scan
프로덕션 운영    →   DETECT/RESPOND →  SIEM, EDR, WAF
인시던트 발생    →   RESPOND/RECOVER→  SOAR, 포렌식, 복구 절차
```

### 성숙도 측정 (CSF 구현 티어)
```
Tier 1 (부분적):
  - 비공식적 프로세스
  - 위험 인식 부족
  - 사후 대응

Tier 2 (위험 인지):
  - 위험 관리 프로세스 존재
  - 외부 정보 일부 활용

Tier 3 (반복 가능):
  - 공식 정책 및 절차
  - 위험 기반 의사결정
  - 외부 파트너 협력

Tier 4 (적응):
  - 지속적 개선
  - 위협 인텔리전스 통합
  - 자동화된 대응
```

---

## 11. 컨테이너 보안 강화 (Hardening)

### Dockerfile 보안 모범 사례
```dockerfile
# 나쁜 예
FROM ubuntu:latest
RUN apt-get install -y curl wget git
COPY . /app
CMD ["python", "app.py"]

# 좋은 예
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim
# 루트가 아닌 사용자 생성
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app
COPY --from=builder /app /app
# 소유권 설정
RUN chown -R appuser:appuser /app
# 루트가 아닌 사용자로 실행
USER appuser
# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
EXPOSE 8080
CMD ["python", "-m", "gunicorn", "app:app"]
```

### Kubernetes 보안 컨텍스트
```yaml
# Pod 보안 설정 예시
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  # 서비스 계정 토큰 자동 마운트 비활성화
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:1.2.3  # 명시적 버전 태그
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

---

## 12. DevSecOps 확장 체크리스트

### 개발 프로세스 보안
```
개발 단계:
  □ 보안을 기능 요구사항과 동일한 우선순위로 처리
  □ 보안 컨트롤 및 자동화 프로세스 추가
  □ 알려진 취약점을 개발 초기에 해결
  □ "Yes, let's figure out how to do this securely" 문화 조성
    (보안이 저지하는 역할이 아닌 가능하게 하는 역할)

지속적 테스트:
  □ 앱, API, 컨테이너, 데이터, 마이크로서비스 전체 테스트
  □ Pre-commit, commit-time, build-time, test-time, deploy-time 검사
  □ SAST(정적) + DAST(동적) 통합 적용

자동화:
  □ 기능적/비기능적 보안 테스트 자동화
  □ 인프라 설정 및 컨피규레이션 관리 자동화
  □ Puppet, Chef, Ansible 등 DSC 도구 활용
```

### API 보안 체크리스트
```
인증/인가:
  □ API ID/키로 사용자·장치·앱 식별
  □ OAuth 프레임워크로 접근 제어
  □ 모든 API 엔드포인트에 인증 강제

보안 정책:
  □ 요청 정보 전송 시 암호화
  □ API 오류 메시지에 민감 정보 노출 금지
  □ ID, 키, 토큰, 인증서 정책 로그/감사

전송 보안:
  □ 모든 연결 암호화 (Man-in-the-Middle 방지)
  □ SSL/TLS 강제 (HTTPS Only)
  □ 오래된 TLS 버전(1.0, 1.1) 비활성화
```

### 혼돈 엔지니어링 (Chaos Engineering)
```
목적:
  - 예기치 않은 운영 환경에서 시스템 보안 준비성 테스트
  - "Moving Target Defense" 구축

실행 방법:
  - 서버 인스턴스 무작위 종료 스크립트
  - 컨테이너 무작위 중단
  - 특정 서비스 장애 유발
  - 네트워크 단절 시뮬레이션

도구:
  - Netflix Chaos Monkey
  - Gremlin
  - AWS Fault Injection Simulator

기대 효과:
  - 보안 탄력성 검증
  - 예상치 못한 공격 시나리오 대비
  - 인시던트 대응 자동화 검증
```

### Security-as-Code 원칙
```
"보안을 나중에 추가하는 것이 아니라 코드에 내재화"

실천 방법:
  □ 보안 요구사항을 코드 레벨에서 적용
  □ 개발자가 보안 결정을 쉽게 내릴 수 있는 환경 조성
  □ 안전한 선택이 가장 쉬운 선택이 되도록 설계

오픈소스/서드파티 의존성:
  □ 항상 최신 버전 유지
  □ 정기적 취약점 확인 (CVE 체크)
  □ 라이선스 컴플라이언스 확인
  □ dependabot 등으로 자동 업데이트 알림

보안 분석 프로그램 지표:
  □ 심각한 취약점 수 및 잔존 기간 추적
  □ 자동화 테스트 범위 및 빈도
  □ 앱에 대한 공격 횟수 및 유형
```
