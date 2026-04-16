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
"""ZAP API를 통한 자동화 스캔"""

import time
import requests

ZAP_URL = "http://localhost:8080"
API_KEY = "your-zap-api-key"
TARGET = "http://app:8000"

def run_zap_scan(target_url: str) -> dict:
    """ZAP 기본 스캔 실행"""
    
    # 스파이더 실행
    print("[*] 스파이더 실행...")
    resp = requests.get(f"{ZAP_URL}/JSON/spider/action/scan/",
                       params={"apikey": API_KEY, "url": target_url})
    scan_id = resp.json()["scan"]
    
    # 스파이더 완료 대기
    while True:
        prog = requests.get(f"{ZAP_URL}/JSON/spider/view/status/",
                           params={"apikey": API_KEY, "scanId": scan_id})
        if int(prog.json()["status"]) >= 100:
            break
        time.sleep(2)
    
    # 능동 스캔
    print("[*] 능동 스캔 실행...")
    resp = requests.get(f"{ZAP_URL}/JSON/ascan/action/scan/",
                       params={"apikey": API_KEY, "url": target_url,
                               "recurse": "true", "scanPolicyName": ""})
    scan_id = resp.json()["scan"]
    
    # 능동 스캔 완료 대기
    while True:
        prog = requests.get(f"{ZAP_URL}/JSON/ascan/view/status/",
                           params={"apikey": API_KEY, "scanId": scan_id})
        status = int(prog.json()["status"])
        print(f"\r[*] 진행률: {status}%", end="", flush=True)
        if status >= 100:
            break
        time.sleep(5)
    
    print("\n[*] 결과 수집...")
    alerts = requests.get(f"{ZAP_URL}/JSON/alert/view/alerts/",
                         params={"apikey": API_KEY, "baseurl": target_url})
    
    return alerts.json()

def generate_report(alerts: dict, output_file: str = "zap_report.html"):
    resp = requests.get(f"{ZAP_URL}/OTHER/core/other/htmlreport/",
                       params={"apikey": API_KEY})
    with open(output_file, "wb") as f:
        f.write(resp.content)
    print(f"[+] 보고서 저장: {output_file}")

if __name__ == "__main__":
    results = run_zap_scan(TARGET)
    high_alerts = [a for a in results["alerts"] 
                   if a["risk"] in ["High", "Critical"]]
    
    print(f"\n[결과] 총 {len(results['alerts'])}개 취약점")
    print(f"  High/Critical: {len(high_alerts)}개")
    
    generate_report(results)
    
    # CI에서 High 이상 발견 시 빌드 실패
    if len(high_alerts) > 0:
        exit(1)
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
"""취약점 관리 대시보드 생성"""

import json
from collections import defaultdict
from datetime import datetime

class VulnManager:
    def __init__(self):
        self.vulnerabilities = []
    
    def load_trivy(self, file: str):
        """Trivy JSON 결과 로드"""
        with open(file) as f:
            data = json.load(f)
        
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                self.vulnerabilities.append({
                    "tool": "trivy",
                    "id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "severity": vuln.get("Severity"),
                    "title": vuln.get("Title"),
                    "fix_version": vuln.get("FixedVersion"),
                })
    
    def load_semgrep(self, file: str):
        """Semgrep JSON 결과 로드"""
        with open(file) as f:
            data = json.load(f)
        
        for result in data.get("results", []):
            self.vulnerabilities.append({
                "tool": "semgrep",
                "id": result.get("check_id"),
                "file": result.get("path"),
                "line": result.get("start", {}).get("line"),
                "severity": result.get("extra", {}).get("severity", "MEDIUM"),
                "message": result.get("extra", {}).get("message", ""),
            })
    
    def get_summary(self) -> dict:
        by_severity = defaultdict(int)
        for v in self.vulnerabilities:
            by_severity[v.get("severity", "UNKNOWN")] += 1
        return dict(by_severity)
    
    def generate_report(self) -> str:
        summary = self.get_summary()
        
        critical = summary.get("CRITICAL", 0)
        high = summary.get("HIGH", 0)
        
        status = "FAIL" if critical > 0 or high > 5 else "PASS"
        
        report = f"""
# 보안 스캔 결과 보고서
날짜: {datetime.now().strftime('%Y-%m-%d %H:%M')}
상태: {status}

## 요약
| 심각도 | 수 |
|--------|---|
"""
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = summary.get(sev, 0)
            report += f"| {sev} | {count} |\n"
        
        report += f"\n총 발견: {len(self.vulnerabilities)}개\n"
        
        if critical > 0:
            report += "\n## Critical 취약점 (즉시 수정 필요)\n"
            for v in self.vulnerabilities:
                if v.get("severity") == "CRITICAL":
                    report += f"- [{v.get('id')}] {v.get('package', v.get('file'))}: {v.get('title', v.get('message', ''))[:80]}\n"
        
        return report

if __name__ == "__main__":
    mgr = VulnManager()
    mgr.load_trivy("trivy-results.json")
    mgr.load_semgrep("semgrep-results.json")
    
    report = mgr.generate_report()
    print(report)
    
    with open("security-report.md", "w") as f:
        f.write(report)
    
    # 심각 취약점 있으면 빌드 실패
    summary = mgr.get_summary()
    if summary.get("CRITICAL", 0) > 0:
        exit(1)
```
