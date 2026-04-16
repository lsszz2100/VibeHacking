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

```yaml
# ❌ 취약한 시크릿 사용
steps:
  - name: Deploy (위험!)
    run: |
      echo "API Key: ${{ secrets.API_KEY }}"  # 로그에 노출!
      export API_KEY=${{ secrets.API_KEY }}    # 쉘 히스토리에 저장
      curl -H "Authorization: $API_KEY" ...
```

### GITHUB_TOKEN 최소 권한

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
// Jenkinsfile
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
"""
        }
    }
    
    environment {
        // 시크릿은 Credentials에서 로드
        AWS_CREDS = credentials('aws-credentials')
        SONAR_TOKEN = credentials('sonar-token')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('SAST') {
            parallel {
                stage('SonarQube') {
                    steps {
                        withSonarQubeEnv('SonarQube') {
                            sh 'mvn sonar:sonar -Dsonar.login=$SONAR_TOKEN'
                        }
                    }
                }
                stage('OWASP DepCheck') {
                    steps {
                        dependencyCheck additionalArguments: 
                            '--enableExperimental --suppression suppression.xml',
                            odcInstallation: 'OWASP-DC'
                        dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Build & Scan Image') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
                sh 'trivy image --exit-code 1 --severity CRITICAL myapp:${BUILD_NUMBER}'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                withAWS(credentials: 'aws-credentials', region: 'ap-northeast-2') {
                    sh 'aws eks update-kubeconfig --name my-cluster'
                    sh 'kubectl apply -f k8s/'
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                reportDir: 'target/site/jacoco',
                reportFiles: 'index.html',
                reportName: 'Coverage Report'
            ])
        }
        failure {
            slackSend(
                channel: '#security-alerts',
                message: "빌드 실패: ${JOB_NAME} #${BUILD_NUMBER}"
            )
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
