> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# GitHub Actions & CI/CD 파이프라인 보안

## CI/CD 파이프라인 공격 벡터

```
공급망 공격 경로:
  의존성 패키지 오염
       │
  악성 GitHub Actions
       │
  소스 코드 저장소 침해
       │
  빌드 서버 RCE
       │
  서명된 악성 아티팩트 배포
       │
  프로덕션 환경 감염
```

---

## 1. GitHub Actions 보안 강화

### 시크릿 관리


GitHub Actions 워크플로우에서 보안 모범 사례를 적용한 설정입니다. 최소 권한 원칙(`permissions`), 시크릿 사용(`${{ secrets }}`), 액션 버전 고정(SHA 해시)으로 공급망 공격과 시크릿 유출을 방지합니다.

```yaml
# ✅ 올바른 시크릿 사용
name: Secure Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    # 최소 권한 토큰
    permissions:
      contents: read
      packages: write
    
    steps:
      - uses: actions/checkout@v4
      
      # 시크릿은 환경변수로 전달
      - name: Configure AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: aws s3 ls
      
      # 절대 로그에 시크릿 출력 금지
      - name: Print safe info
        run: echo "Deploying to ${{ vars.ENVIRONMENT }}"  # vars는 공개
```

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# ❌ 취약한 시크릿 사용
steps:
  - name: Deploy (위험!)
    run: |
      echo "API Key: ${{ secrets.API_KEY }}"  # 로그에 노출!
      export API_KEY=${{ secrets.API_KEY }}    # 쉘 히스토리에 저장
      curl -H "Authorization: $API_KEY" ...

# ── GitHub Actions 시크릿 탐지 스크립트 ────────────────────
# 아래 Python 스크립트로 로컬/CI에서 워크플로우 파일의
# 시크릿 오용 패턴을 사전에 탐지

```python
#!/usr/bin/env python3
"""
GitHub Actions 워크플로우 파일 보안 감사 도구
사용: python3 actions_audit.py --dir .github/workflows
      python3 actions_audit.py --file .github/workflows/deploy.yml
      python3 actions_audit.py --dir .github/workflows --output audit.json
"""

from __future__ import annotations
import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

import yaml  # pip install pyyaml


# ── 위험 패턴 정의 ────────────────────────────────────────────

@dataclass
class AuditFinding:
    file: str
    line: int
    rule: str
    severity: str
    detail: str


RULES: list[tuple[str, str, str, str]] = [
    # (rule_id, severity, pattern, description)
    ("SEC001", "CRITICAL",
     r"echo\s+.*\$\{\{\s*secrets\.",
     "시크릿을 echo/print — 로그에 노출"),
    ("SEC002", "CRITICAL",
     r"run:\s*\|[^|]*\$\{\{\s*secrets\.[^}]+\}\}\s*\n",
     "run 블록에서 시크릿 직접 인라인 사용"),
    ("SEC003", "HIGH",
     r"uses:\s+\S+@(main|master|HEAD|latest)",
     "Actions 버전이 SHA가 아닌 브랜치/태그 참조"),
    ("SEC004", "HIGH",
     r"permissions:\s*write-all",
     "과도한 GITHUB_TOKEN 권한 (write-all)"),
    ("SEC005", "MEDIUM",
     r"pull_request_target:",
     "pull_request_target 트리거 — fork PR 공격 가능"),
    ("SEC006", "MEDIUM",
     r"\$\{\{\s*github\.event\.(issue|comment|pull_request)\.body",
     "사용자 제공 데이터 직접 사용 — 스크립트 인젝션 위험"),
    ("SEC007", "MEDIUM",
     r"ACTIONS_ALLOW_UNSECURE_COMMANDS.*true",
     "구형 명령 방식 활성화 — 환경변수 인젝션 가능"),
    ("SEC008", "LOW",
     r"curl\s+.*\|\s*(bash|sh)",
     "인터넷에서 다운로드 후 파이프 실행"),
    ("SEC009", "LOW",
     r"--privileged",
     "특권 컨테이너 실행"),
]


def scan_file(path: Path) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    lines = text.splitlines()

    for rule_id, severity, pattern, desc in RULES:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(AuditFinding(
                    file=str(path),
                    line=i,
                    rule=rule_id,
                    severity=severity,
                    detail=f"{desc} | {line.strip()[:120]}",
                ))

    # YAML 구조적 분석 (permissions 누락 체크)
    try:
        wf = yaml.safe_load(text)
        if isinstance(wf, dict):
            # 최상위 permissions 없으면 기본 write 권한
            if "permissions" not in wf:
                findings.append(AuditFinding(
                    file=str(path), line=1, rule="SEC010",
                    severity="MEDIUM",
                    detail="워크플로우 수준 permissions 미설정 — 기본값은 write",
                ))
            # environment protection 없는 production 배포
            for job_name, job in (wf.get("jobs") or {}).items():
                if isinstance(job, dict):
                    env = job.get("environment")
                    if env and isinstance(env, str) and "prod" in env.lower():
                        if not job.get("permissions"):
                            findings.append(AuditFinding(
                                file=str(path), line=1, rule="SEC011",
                                severity="LOW",
                                detail=f"프로덕션 배포 잡 '{job_name}'에 permissions 미설정",
                            ))
    except yaml.YAMLError:
        pass

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GitHub Actions 워크플로우 보안 감사"
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--dir",  type=Path, help="워크플로우 디렉토리")
    grp.add_argument("--file", type=Path, help="단일 워크플로우 파일")
    parser.add_argument("--output", type=Path, help="결과 JSON 저장")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM"],
                        default="HIGH", help="이 이상 심각도 발견 시 exit(1)")
    args = parser.parse_args()

    files: list[Path] = []
    if args.file:
        files = [args.file]
    else:
        files = list(args.dir.rglob("*.yml")) + list(args.dir.rglob("*.yaml"))

    all_findings: list[AuditFinding] = []
    for f in files:
        found = scan_file(f)
        all_findings.extend(found)

    # 결과 출력
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: sev_order.get(x.severity, 9))

    for f in all_findings:
        print(f"[{f.severity:8s}] {f.rule}  {f.file}:{f.line}")
        print(f"           {f.detail}")

    print(f"\n[요약] 파일 {len(files)}개 스캔, 발견 {len(all_findings)}건")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = sum(1 for x in all_findings if x.severity == sev)
        if cnt:
            print(f"  {sev}: {cnt}")

    if args.output:
        args.output.write_text(
            json.dumps([asdict(f) for f in all_findings],
                       indent=2, ensure_ascii=False)
        )
        print(f"[*] 결과 저장: {args.output}")

    # 품질 게이트
    fail_sevs = [s for s in ["CRITICAL", "HIGH", "MEDIUM"]
                 if sev_order.get(s, 9) <= sev_order.get(args.fail_on, 9)]
    if any(f.severity in fail_sevs for f in all_findings):
        print(f"[FAIL] {args.fail_on} 이상 발견 — 빌드 실패")
        sys.exit(1)
    print("[PASS] 보안 감사 통과")


if __name__ == "__main__":
    main()
```

### GITHUB_TOKEN 최소 권한

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# 기본 권한을 읽기 전용으로 설정
permissions: read-all

# 또는 워크플로우 수준
name: My Workflow
permissions:
  contents: read        # 저장소 읽기만
  pull-requests: write  # PR 댓글 가능
  issues: none          # 이슈 접근 없음

jobs:
  build:
    permissions:
      contents: read    # 잡 수준에서 오버라이드
```

### Actions 버전 고정 (공급망 공격 방지)

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# ❌ 취약: 태그는 덮어쓰기 가능
- uses: actions/checkout@v4
- uses: actions/setup-python@main  # main 브랜치는 항상 최신 = 위험

# ✅ 안전: SHA 커밋으로 고정
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: actions/setup-python@0a5c61591373683505ea898e09424558529e0ce4  # v5.0.0

# 의존봇으로 자동 업데이트
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns:
          - "actions/*"
```

### OIDC로 클라우드 인증 (장기 자격증명 불필요)

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# AWS OIDC 연동 (시크릿 없이 AWS 인증)
name: Deploy to AWS

on:
  push:
    branches: [main]

permissions:
  id-token: write  # OIDC 토큰 요청 권한
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/GitHubActionsRole
          aws-region: ap-northeast-2
          # 시크릿 없이 OIDC 토큰으로 임시 자격증명 발급!

      - name: Deploy to S3
        run: aws s3 sync ./dist s3://my-bucket
```

```json
// AWS IAM 역할 신뢰 정책
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

---

## 2. 전체 보안 파이프라인

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# .github/workflows/full-security-pipeline.yml
name: Full Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write  # Security 탭 업로드
  actions: read

jobs:
  # ===== 시크릿 탐지 =====
  secrets:
    name: Secret Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0  # 전체 히스토리 스캔

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  # ===== SAST =====
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python,javascript

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:python"

      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/python
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_TOKEN }}

  # ===== SCA =====
  sca:
    name: Dependency Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Set up Python
        uses: actions/setup-python@0a5c61591373683505ea898e09424558529e0ce4
        with:
          python-version: '3.12'

      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt \
            -f sarif \
            -o pip-audit.sarif

      - name: Upload pip-audit results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pip-audit.sarif

  # ===== 컨테이너 스캔 =====
  container:
    name: Container Security
    runs-on: ubuntu-latest
    needs: [sast, sca]
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Critical/High 발견 시 실패

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

  # ===== IaC 보안 =====
  iac:
    name: IaC Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Checkov Terraform
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif

      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: terraform/

      - name: Kubesec K8s YAML
        run: |
          docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < k8s/deployment.yaml

  # ===== 배포 (모든 보안 검사 통과 후) =====
  deploy:
    name: Deploy
    runs-on: ubuntu-latest
    needs: [secrets, sast, sca, container, iac]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    
    environment:
      name: production
      url: https://myapp.com
    
    permissions:
      id-token: write
      contents: read
    
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Configure AWS (OIDC)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ap-northeast-2

      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@062b18b96a7aff071d4dc91bc00c4c1a7945b076

      - name: Sign and Push Image (cosign)
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
        run: |
          docker tag myapp:${{ github.sha }} \
            ${{ steps.login-ecr.outputs.registry }}/myapp:${{ github.sha }}
          docker push ${{ steps.login-ecr.outputs.registry }}/myapp:${{ github.sha }}
          
          # 이미지 서명
          cosign sign --key env://COSIGN_PRIVATE_KEY \
            ${{ steps.login-ecr.outputs.registry }}/myapp:${{ github.sha }}
```

---

## 3. GitLab CI/CD 보안

YAML 설정 파일입니다. 쿠버네티스, CI/CD 파이프라인, 보안 도구 설정에 널리 사용되며 잘못된 설정이 보안 취약점으로 이어질 수 있습니다.

```yaml
# .gitlab-ci.yml 보안 강화 버전
stages:
  - validate
  - security
  - build
  - deploy

variables:
  DOCKER_BUILDKIT: 1
  SECURE_LOG_LEVEL: info

# 공통 보안 설정
.security_defaults:
  tags:
    - secure-runner
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

# SAST 자동 통합 (GitLab Ultimate)
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

# 커스텀 Trivy 스캔
trivy-scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: false
  artifacts:
    reports:
      container_scanning: trivy-results.json

# 보안 검사 후 배포
deploy-production:
  stage: deploy
  environment:
    name: production
    url: https://myapp.com
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  needs:
    - job: trivy-scan
    - job: sast
    - job: secret_detection
  script:
    - echo "보안 검사 통과 후 배포 실행"
    - kubectl apply -f k8s/
```

---

## 4. Jenkins 파이프라인 보안

```groovy
// Jenkinsfile — 보안 강화 파이프라인 (SAST + Container + DAST)
pipeline {
    agent {
        kubernetes {
            yaml """
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: builder
    image: maven:3.9-eclipse-temurin-17
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
"""
        }
    }

    environment {
        AWS_CREDS    = credentials('aws-credentials')
        SONAR_TOKEN  = credentials('sonar-token')
        SNYK_TOKEN   = credentials('snyk-token')
        SLACK_HOOK   = credentials('slack-webhook')
        IMAGE_NAME   = "myapp:${BUILD_NUMBER}"
    }

    options {
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('SAST + SCA') {
            parallel {
                stage('SonarQube') {
                    steps {
                        withSonarQubeEnv('SonarQube') {
                            sh 'mvn -B sonar:sonar -Dsonar.login=$SONAR_TOKEN'
                        }
                        timeout(time: 5, unit: 'MINUTES') {
                            waitForQualityGate abortPipeline: true
                        }
                    }
                }
                stage('Snyk SCA') {
                    steps {
                        sh """
                            snyk auth \$SNYK_TOKEN
                            snyk test --all-projects \
                                      --severity-threshold=high \
                                      --json > snyk-results.json || true
                            snyk-to-html -i snyk-results.json -o snyk-report.html || true
                        """
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'snyk-report.html',
                                             allowEmptyArchive: true
                        }
                    }
                }
                stage('Semgrep') {
                    steps {
                        sh """
                            pip install semgrep --quiet
                            semgrep --config=p/security-audit \
                                    --config=p/owasp-top-ten \
                                    --json --output=semgrep.json . || true
                        """
                    }
                }
                stage('Gitleaks') {
                    steps {
                        sh """
                            docker run --rm -v \$(pwd):/repo \
                                zricethezav/gitleaks:latest detect \
                                --source /repo --report-format json \
                                --report-path /repo/gitleaks.json \
                                --exit-code 0
                        """
                    }
                }
            }
        }

        stage('Build Image') {
            steps {
                sh 'docker build --no-cache -t $IMAGE_NAME .'
            }
        }

        stage('Container Security') {
            parallel {
                stage('Trivy') {
                    steps {
                        sh """
                            trivy image --exit-code 1 \
                                        --severity CRITICAL \
                                        --format sarif \
                                        --output trivy.sarif \
                                        \$IMAGE_NAME
                        """
                    }
                }
                stage('Docker Bench') {
                    steps {
                        sh """
                            docker run --rm --net host --pid host --userns host \
                                --cap-add audit_control \
                                -v /etc:/etc:ro \
                                -v /usr/bin/containerd:/usr/bin/containerd:ro \
                                -v /var/lib:/var/lib:ro \
                                -v /var/run/docker.sock:/var/run/docker.sock:ro \
                                docker/docker-bench-security \
                                2>&1 | tee docker-bench.txt || true
                        """
                    }
                }
            }
        }

        stage('DAST') {
            when { branch 'main' }
            steps {
                sh 'docker compose up -d --wait'
                sh """
                    docker run --rm --network host \
                        -v \$(pwd)/.zap:/zap/wrk:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-api-scan.py \
                        -t http://localhost:8080/v3/api-docs \
                        -f openapi \
                        -J zap-report.json \
                        -r zap-report.html \
                        -x zap-report.xml \
                        -z "-config scanner.strength=HIGH" \
                        -I
                """
            }
            post {
                always {
                    sh 'docker compose down'
                    archiveArtifacts artifacts: 'zap-report.*',
                                     allowEmptyArchive: true
                    // SARIF 업로드 (Jenkins + GitHub 연동)
                    recordIssues tools: [
                        sarif(id: 'zap', name: 'ZAP DAST',
                              pattern: 'zap-report.xml')
                    ]
                }
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            steps {
                withAWS(credentials: 'aws-credentials', region: 'ap-northeast-2') {
                    sh """
                        aws ecr get-login-password | \
                            docker login --username AWS \
                            --password-stdin \$AWS_ACCOUNT.dkr.ecr.ap-northeast-2.amazonaws.com
                        docker tag \$IMAGE_NAME \$ECR_REPO:\$BUILD_NUMBER
                        docker push \$ECR_REPO:\$BUILD_NUMBER
                        aws eks update-kubeconfig --name my-cluster
                        kubectl set image deployment/myapp \
                            myapp=\$ECR_REPO:\$BUILD_NUMBER
                        kubectl rollout status deployment/myapp --timeout=120s
                    """
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '**/*.json,**/*.sarif,**/*.html',
                             allowEmptyArchive: true
        }
        failure {
            script {
                def msg = "빌드 실패: ${JOB_NAME} #${BUILD_NUMBER} — ${BUILD_URL}"
                sh "curl -s -X POST -H 'Content-type: application/json' " +
                   "--data '{\"text\":\"${msg}\"}' \$SLACK_HOOK"
            }
        }
        success {
            script {
                def msg = "빌드 성공: ${JOB_NAME} #${BUILD_NUMBER} (보안 검사 모두 통과)"
                sh "curl -s -X POST -H 'Content-type: application/json' " +
                   "--data '{\"text\":\"${msg}\"}' \$SLACK_HOOK"
            }
        }
    }
}
```

---

## 5. 보안 DevSecOps 체크리스트

```
저장소 보안:
  □ Branch Protection Rules (main/master)
  □ 코드 리뷰 필수 (최소 1명)
  □ CODEOWNERS 파일 설정
  □ 서명된 커밋 강제 (GPG/SSH)
  □ .gitignore 시크릿 파일 제외
  □ Dependabot 활성화

파이프라인 보안:
  □ Actions 버전 SHA로 고정
  □ GITHUB_TOKEN 최소 권한
  □ 환경 보호 규칙 (production 수동 승인)
  □ OIDC로 클라우드 인증 (장기 자격증명 제거)
  □ 시크릿 마스킹 확인

보안 스캔 통합:
  □ 시크릿 탐지 (Gitleaks/detect-secrets)
  □ SAST (Semgrep/CodeQL/Bandit)
  □ SCA (Snyk/pip-audit/Dependabot)
  □ 컨테이너 스캔 (Trivy)
  □ IaC 스캔 (Checkov/tfsec)
  □ DAST (ZAP, 스테이징 환경)

아티팩트 보안:
  □ 이미지 서명 (cosign)
  □ SBOM 생성 (syft)
  □ 아티팩트 무결성 (SHA256 체크섬)
  □ 이미지 레지스트리 액세스 제어
  □ 취약한 이미지 자동 차단

모니터링:
  □ 파이프라인 실패 알림
  □ 보안 스캔 결과 Security 탭 통합
  □ 주기적 의존성 업데이트
  □ 비밀 키 교체 일정
```

---

<a name="english"></a>

# GitHub Actions & CI/CD Pipeline Security

## CI/CD Pipeline Attack Vectors

```
Common CI/CD Attack Vectors:

Code-Level:
  - Malicious dependency injection (dependency confusion)
  - Compromised third-party GitHub Actions
  - Secrets exposed in logs or artifacts

Configuration-Level:
  - Overly permissive GITHUB_TOKEN
  - Unprotected branches with auto-merge
  - Environment variable injection
  - Workflow injection via PR titles/issues

Infrastructure-Level:
  - Compromised self-hosted runners
  - Container registry poisoning
  - Artifact tampering
```

---

## 1. GitHub Actions Security Hardening

### Secure Workflow Template

```yaml
name: Secure CI Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read        # Minimal permissions
  security-events: write  # For SARIF upload only

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secret scanning
      
      # Pin actions to specific commit SHA (not tags)
      - uses: github/codeql-action/init@v3
        with:
          languages: python, javascript
      
      - name: Build
        run: make build
      
      - uses: github/codeql-action/analyze@v3
```

### Workflow Injection Prevention

```yaml
# VULNERABLE: Using PR title directly in shell
- name: Check PR
  run: echo "PR: ${{ github.event.pull_request.title }}"
  # If title contains: $(malicious_command) → Command injection!

# SECURE: Use environment variable to prevent injection
- name: Check PR (safe)
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR: $PR_TITLE"
  # Environment variable assignment prevents injection
```

---

## 2. Secrets Management

### GitHub Secrets Best Practices

```yaml
# In workflow file
- name: Deploy
  env:
    API_KEY: ${{ secrets.API_KEY }}    # From GitHub Secrets
    DB_PASS: ${{ secrets.DB_PASSWORD }} # Never hardcode!
  run: ./deploy.sh
  
# Never do this:
# run: API_KEY=hardcoded_value ./deploy.sh
# run: echo "${{ secrets.API_KEY }}"  # Leaks to logs!
```

### Secret Scanning

```bash
# GitLeaks — scan for secrets in git history
gitleaks detect --source=. --verbose

# truffleHog — high entropy string detection
trufflehog git file://. --only-verified

# GitHub native secret scanning
# Settings → Security → Secret scanning → Enable

# Custom secret patterns (gitleaks config)
# .gitleaks.toml
[[rules]]
id = "company-api-key"
description = "Company internal API key"
regex = '''COMPANY_[A-Z]{3}_[a-zA-Z0-9]{32}'''
tags = ["api", "company"]
```

---

## 3. Supply Chain Security

### Dependency Confusion Attack Prevention

```bash
# Check for internal packages that could be confused
# A package named 'internal-utils' on npm could be hijacked
# if the attacker publishes a higher version to public npm

# Solution: Use scoped packages
# "@company/internal-utils" instead of "internal-utils"

# Verify package integrity
npm audit
pip-audit
snyk test
```

### Pinning GitHub Actions

```yaml
# INSECURE: Using mutable tag
- uses: actions/checkout@v4

# SECURE: Pin to specific commit SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

# Use Dependabot to auto-update pinned SHA
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## 4. SAST/DAST in CI/CD

### SAST Integration

```yaml
# CodeQL SAST
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python
    queries: security-extended  # More comprehensive checks

# Semgrep SAST
- name: Semgrep SAST
  uses: semgrep/semgrep-action@v1
  with:
    config: >
      p/default
      p/owasp-top-ten
      p/secrets
```

### Container Security

```yaml
# Trivy container scanning
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@0.28.0
  with:
    image-ref: 'my-image:latest'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'

- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

---

## 5. Security Checklist

```
Repository Configuration:
  □ Branch protection rules enabled
  □ Required PR reviews before merge
  □ Status checks required
  □ Signed commits enforced

Workflow Security:
  □ Minimal GITHUB_TOKEN permissions
  □ Actions pinned to commit SHA
  □ No secrets in workflow files
  □ Workflow injection prevention (env vars)

Scanning:
  □ SAST enabled (CodeQL/Semgrep)
  □ Secret scanning enabled
  □ Dependency scanning enabled
  □ Container scanning enabled

Monitoring:
  □ Pipeline failure notifications
  □ Security scan results integrated in Security tab
  □ Regular dependency updates
  □ Secret rotation schedule
```
