> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 컨테이너 이미지 강화 및 공급망 보안

## 목차
1. 컨테이너 이미지 취약점 스캔 도구
2. Distroless / Scratch 베이스 이미지
3. 이미지 서명 (Cosign, Sigstore)
4. OPA / Gatekeeper 정책 강제
5. SBOM 생성 및 이미지 공급망 보안
6. Python: 이미지 레이어 보안 분석 도구

---

## 1. 컨테이너 이미지 취약점 스캔 도구

### 1.1 Trivy (Aqua Security)

Trivy는 가장 널리 사용되는 오픈소스 컨테이너 취약점 스캐너입니다.

**스캔 대상**:
- 컨테이너 이미지 (OS 패키지, 언어 의존성)
- 파일시스템
- Git 리포지토리
- IaC (Terraform, CloudFormation, Kubernetes YAML)
- SBOM

```bash
# 이미지 스캔
trivy image nginx:latest

# 심각도 필터링 (CRITICAL, HIGH만)
trivy image --severity CRITICAL,HIGH nginx:latest

# JSON 출력 (CI/CD 통합)
trivy image --format json --output report.json nginx:latest

# Kubernetes 클러스터 스캔
trivy k8s --report summary cluster

# IaC 스캔
trivy config ./terraform/

# SBOM 생성
trivy image --format cyclonedx nginx:latest -o sbom.json
```

**설정 파일 (trivy.yaml)**:
```yaml
severity:
  - CRITICAL
  - HIGH

exit-code: 1  # 취약점 발견 시 비정상 종료 (CI/CD 차단)

ignore-unfixed: true  # 패치 없는 취약점 무시

skip-dirs:
  - usr/share/doc

vulnerability:
  type:
    - os
    - library
```

### 1.2 Grype (Anchore)

Grype는 Syft와 함께 사용하도록 설계된 취약점 스캐너입니다.

```bash
# 이미지 스캔
grype nginx:latest

# SBOM에서 스캔 (Syft로 먼저 생성)
syft nginx:latest -o json > sbom.json
grype sbom:sbom.json

# 심각도 기준 실패 처리
grype nginx:latest --fail-on critical

# 특정 취약점 무시 (.grype.yaml)
```

```yaml
# .grype.yaml
ignore:
  - vulnerability: CVE-2020-14145
    reason: "해당 기능 미사용"
  - fix-state: wont-fix
```

### 1.3 Snyk Container

Snyk은 개발자 친화적 인터페이스와 자동 수정 PR 기능을 제공합니다.

```bash
# CLI 스캔
snyk container test nginx:latest

# Dockerfile 스캔 (베이스 이미지 권고 포함)
snyk container test nginx:latest --file=Dockerfile

# 모니터링 (지속적 스캔)
snyk container monitor nginx:latest --project-name=my-app
```

### 취약점 스캐너 비교

| 기준 | Trivy | Grype | Snyk |
|------|-------|-------|------|
| 오픈소스 | 완전 오픈소스 | 완전 오픈소스 | 제한적 무료 |
| SBOM 지원 | CycloneDX, SPDX | SPDX | CycloneDX |
| IaC 스캔 | 지원 | 미지원 | 지원 |
| 자동 수정 | 미지원 | 미지원 | PR 생성 |
| 업데이트 주기 | 6시간 | 24시간 | 실시간 |
| CI/CD 통합 | 매우 쉬움 | 쉬움 | 중간 |

---

## 2. Distroless / Scratch 베이스 이미지

### 2.1 Distroless 이미지란?

Google이 만든 Distroless 이미지는 애플리케이션과 런타임 의존성만 포함하고
패키지 관리자, 쉘, 유틸리티를 제거한 최소화 이미지입니다.

**공격 표면 축소 효과**:
```
일반 ubuntu:22.04:   ~400 OS 패키지, bash, apt, curl 등 포함
Distroless Python:   ~30 패키지, 쉘 없음, 패키지 관리자 없음
Scratch (빈 이미지): 0 패키지 (정적 바이너리만 가능)
```

### 2.2 Distroless 이미지 사용

```dockerfile
# 다단계 빌드로 Distroless 사용
# 빌드 스테이지
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/packages -r requirements.txt
COPY app.py .

# 실행 스테이지 (Distroless)
FROM gcr.io/distroless/python3-debian12
WORKDIR /app
COPY --from=builder /app/packages /app/packages
COPY --from=builder /app/app.py .
ENV PYTHONPATH=/app/packages
USER nonroot:nonroot
CMD ["app.py"]
```

```dockerfile
# Go 정적 바이너리 - Scratch 이미지 사용
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

FROM scratch
COPY --from=builder /app/server /server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 65534:65534  # nobody
ENTRYPOINT ["/server"]
```

### 2.3 보안 강화 Dockerfile 모범 사례

```dockerfile
FROM python:3.12-slim

# 불필요한 권한 도구 제거
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/wget /usr/bin/curl

# 전용 비root 사용자 생성
RUN groupadd -r appgroup --gid=1001 && \
    useradd -r -g appgroup --uid=1001 --no-log-init appuser

WORKDIR /app

# 의존성 먼저 복사 (레이어 캐싱 최적화)
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup . .

# 비root 사용자로 전환
USER appuser

# 읽기 전용 파일시스템 (runAsReadOnlyRootFilesystem: true 와 연계)
VOLUME ["/tmp", "/var/cache"]

EXPOSE 8080
ENTRYPOINT ["python", "app.py"]
```

---

## 3. 이미지 서명 (Cosign, Sigstore)

### 3.1 Sigstore 생태계

Sigstore는 소프트웨어 아티팩트(이미지, 바이너리, SBOM)에 서명하고 검증하는
무료 오픈소스 인프라입니다.

**구성 요소**:
```
Sigstore 생태계:
├── Cosign    - 컨테이너 이미지 서명/검증
├── Fulcio    - 단기 서명 인증서 CA
├── Rekor     - 변경 불가능한 투명성 로그
└── Gitsign   - Git 커밋 서명
```

### 3.2 Cosign으로 이미지 서명

```bash
# 1. 키 페어 생성
cosign generate-key-pair

# 2. 이미지 서명 (키 기반)
cosign sign --key cosign.key registry.example.com/myapp:v1.0.0

# 3. OIDC 기반 서명 (키리스 - CI/CD 환경)
# GitHub Actions에서:
cosign sign --yes registry.example.com/myapp:v1.0.0

# 4. 서명 검증
cosign verify \
  --key cosign.pub \
  registry.example.com/myapp:v1.0.0

# 5. SBOM 첨부 및 서명
cosign attach sbom --sbom sbom.cyclonedx.json \
  registry.example.com/myapp:v1.0.0

cosign sign --key cosign.key \
  --attachment sbom \
  registry.example.com/myapp:v1.0.0
```

### 3.3 GitHub Actions CI/CD 통합

```yaml
# .github/workflows/build-sign.yml
name: Build and Sign Container Image

on:
  push:
    tags: ['v*']

jobs:
  build-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # OIDC 서명을 위해 필요

    steps:
    - uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Login to GHCR
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Build and Push
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

    - name: Install Cosign
      uses: sigstore/cosign-installer@v3

    - name: Sign Image (Keyless)
      run: |
        cosign sign --yes \
          ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

    - name: Scan with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'
```

---

## 4. OPA / Gatekeeper 정책 강제

### 4.1 OPA (Open Policy Agent)

OPA는 통합 정책 엔진으로, Rego 언어를 사용하여 정책을 작성합니다.

```rego
# Rego 정책: 루트 컨테이너 차단
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf(
        "Pod '%v'의 컨테이너 '%v'가 root(UID=0)로 실행됩니다. 거부됩니다.",
        [input.request.object.metadata.name, container.name]
    )
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "컨테이너 '%v'에 privileged=true가 설정되어 있습니다.",
        [container.name]
    )
}
```

### 4.2 Gatekeeper (OPA for Kubernetes)

```bash
# Gatekeeper 설치
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper \
  --name-template=gatekeeper \
  --namespace gatekeeper-system \
  --create-namespace \
  --set replicas=2
```

```yaml
# ConstraintTemplate: 서명된 이미지만 허용
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsignedimages
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSignedImages
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedRegistries:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredsignedimages

      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not starts_with_allowed_registry(container.image)
        msg := sprintf(
          "이미지 '%v'는 허용된 레지스트리에서 오지 않았습니다.",
          [container.image]
        )
      }

      starts_with_allowed_registry(image) {
        registry := input.parameters.allowedRegistries[_]
        startswith(image, registry)
      }

---
# Constraint: 정책 적용
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredSignedImages
metadata:
  name: require-signed-images
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces:
    - production
  parameters:
    allowedRegistries:
    - "registry.company.com/"
    - "ghcr.io/myorg/"
```

```yaml
# Gatekeeper Mutation: 보안 기본값 자동 주입
apiVersion: mutations.gatekeeper.sh/v1
kind: AssignMetadata
metadata:
  name: add-security-labels
spec:
  match:
    scope: Namespaced
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
  location: "metadata.labels.security-scanned"
  parameters:
    assign:
      value: "true"
```

---

## 5. SBOM 생성 및 이미지 공급망 보안

### 5.1 SBOM (Software Bill of Materials)

SBOM은 소프트웨어에 포함된 모든 구성 요소의 목록입니다.
미국 행정명령 EO 14028 이후 공급망 보안의 핵심 요소가 되었습니다.

**표준 형식**:
- **CycloneDX**: OWASP 주도, 보안 중심
- **SPDX**: Linux Foundation 주도, 라이선스 중심
- **SWID**: ISO/IEC 표준

```bash
# Syft로 SBOM 생성
syft nginx:latest -o cyclonedx-json > nginx-sbom.cyclonedx.json
syft nginx:latest -o spdx-json > nginx-sbom.spdx.json

# Trivy로 SBOM 생성
trivy image --format cyclonedx nginx:latest -o nginx-sbom.json

# SBOM 기반 취약점 스캔
grype sbom:nginx-sbom.cyclonedx.json
```

### 5.2 공급망 공격 시나리오

**시나리오 1: Typosquatting**
```
공격자: ngnix (오타) 이미지 Docker Hub에 업로드
피해자: docker pull ngnix:latest (오타로 인해 악성 이미지 다운로드)
```

**시나리오 2: Base Image Poisoning**
```
공격자: 인기 있는 베이스 이미지(python:3.12)에 백도어 삽입
파급: 해당 이미지를 사용하는 모든 앱에 백도어 전파
```

**시나리오 3: Build Pipeline Compromise**
```
공격자: CI/CD 파이프라인에 악성 코드 주입
결과: 빌드 시점에 이미지에 악성 코드 포함
```

### 5.3 공급망 보안 강화 전략

```
공급망 보안 계층:
├── 1단계: 소스 코드
│   ├── 브랜치 보호 (Signed Commits)
│   ├── SAST (Semgrep, SonarQube)
│   └── 의존성 검토 (Dependabot)
│
├── 2단계: 빌드
│   ├── 빌드 환경 격리 (에페머럴 환경)
│   ├── 재현 가능한 빌드 (Reproducible Builds)
│   └── SLSA (Supply chain Levels for Software Artifacts)
│
├── 3단계: 이미지 레지스트리
│   ├── 이미지 서명 강제 (Cosign)
│   ├── 이미지 스캔 (Trivy)
│   └── 허용 레지스트리 목록
│
└── 4단계: 배포
    ├── 서명 검증 (Admission Controller)
    ├── Gatekeeper 정책
    └── 런타임 모니터링 (Falco)
```

---

## 6. Python: 이미지 레이어 보안 분석 도구

```python
#!/usr/bin/env python3
"""
컨테이너 이미지 레이어 보안 분석 도구

컨테이너 이미지의 각 레이어를 분석하여 보안 위험 요소를 탐지합니다.
"""

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class LayerFinding:
    layer_id: str
    layer_index: int
    risk_level: RiskLevel
    category: str
    description: str
    command: str
    recommendation: str


@dataclass
class ImageAnalysisResult:
    image: str
    total_layers: int
    total_size_mb: float
    findings: list[LayerFinding] = field(default_factory=list)
    exposed_ports: list[int] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)
    user: str = "root"
    has_healthcheck: bool = False
    trivy_critical: int = 0
    trivy_high: int = 0

    def summary(self) -> dict[str, Any]:
        findings_by_level: dict[str, int] = {}
        for f in self.findings:
            findings_by_level[f.risk_level.value] = (
                findings_by_level.get(f.risk_level.value, 0) + 1
            )
        return {
            "image": self.image,
            "total_layers": self.total_layers,
            "size_mb": round(self.total_size_mb, 2),
            "user": self.user,
            "has_healthcheck": self.has_healthcheck,
            "exposed_ports": self.exposed_ports,
            "findings_count": findings_by_level,
            "trivy_critical": self.trivy_critical,
            "trivy_high": self.trivy_high,
        }


def run_docker(args: list[str]) -> dict[str, Any] | list[Any] | str | None:
    """docker 명령 실행."""
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[경고] docker 오류: {e.stderr.strip()}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[경고] docker 명령 타임아웃", file=sys.stderr)
        return None


def get_image_inspect(image: str) -> dict[str, Any] | None:
    """docker inspect로 이미지 정보 조회."""
    raw = run_docker(["inspect", image])
    if not raw:
        return None
    try:
        data = json.loads(str(raw))
        return data[0] if isinstance(data, list) and data else None
    except (json.JSONDecodeError, IndexError):
        return None


def get_image_history(image: str) -> list[dict[str, Any]]:
    """이미지 레이어 히스토리 조회."""
    raw = run_docker(["history", "--format", "json", "--no-trunc", image])
    if not raw:
        return []
    try:
        lines = str(raw).strip().split("\n")
        return [json.loads(line) for line in lines if line.strip()]
    except json.JSONDecodeError:
        return []


def analyze_layer_commands(
    history: list[dict[str, Any]]
) -> list[LayerFinding]:
    """레이어 명령어에서 보안 위험 탐지."""
    findings: list[LayerFinding] = []

    # 위험 패턴 정의
    risk_patterns = [
        (
            RiskLevel.CRITICAL,
            "비밀키 노출",
            re.compile(
                r"(password|passwd|secret|api_key|private_key|token)\s*[=:]\s*\S+",
                re.IGNORECASE,
            ),
            "환경 변수 또는 ARG로 전달하고 멀티스테이지 빌드를 사용하세요.",
        ),
        (
            RiskLevel.CRITICAL,
            "SSH 개인키 복사",
            re.compile(r"COPY.*\.pem|COPY.*id_rsa|ADD.*\.key"),
            "빌드 시크릿(--secret)을 사용하고 최종 이미지에 키를 포함시키지 마세요.",
        ),
        (
            RiskLevel.HIGH,
            "패키지 캐시 미삭제",
            re.compile(r"apt-get install(?!.*rm -rf /var/lib/apt)"),
            "RUN apt-get install && rm -rf /var/lib/apt/lists/* 로 캐시를 삭제하세요.",
        ),
        (
            RiskLevel.HIGH,
            "curl | bash 패턴",
            re.compile(r"curl.*\|.*bash|wget.*\|.*sh"),
            "스크립트를 먼저 다운로드하여 검토한 후 실행하세요.",
        ),
        (
            RiskLevel.HIGH,
            "ADD로 원격 URL 사용",
            re.compile(r"^ADD\s+https?://"),
            "ADD 대신 COPY를 사용하고 wget/curl로 다운로드 후 체크섬을 검증하세요.",
        ),
        (
            RiskLevel.MEDIUM,
            "chmod 777 사용",
            re.compile(r"chmod\s+777|chmod\s+-R\s+777"),
            "최소 필요 권한을 사용하세요 (755 또는 644).",
        ),
        (
            RiskLevel.MEDIUM,
            "setuid/setgid 바이너리",
            re.compile(r"chmod\s+[0-9]*[46][0-9]*|chmod.*[su]"),
            "setuid/setgid 비트가 필요한지 검토하고 불필요하면 제거하세요.",
        ),
        (
            RiskLevel.MEDIUM,
            "sudo 설치",
            re.compile(r"apt-get install.*sudo|yum install.*sudo"),
            "컨테이너에서는 sudo가 불필요합니다. USER 지시어로 권한을 관리하세요.",
        ),
        (
            RiskLevel.LOW,
            "버전 고정 없는 패키지 설치",
            re.compile(r"apt-get install -y (?!--no-install-recommends)"),
            "--no-install-recommends 플래그를 사용하고 버전을 고정하세요.",
        ),
        (
            RiskLevel.INFO,
            "최신 태그 사용",
            re.compile(r"FROM\s+\w+:latest"),
            "latest 대신 특정 다이제스트나 버전 태그를 사용하세요.",
        ),
    ]

    for idx, layer in enumerate(history):
        cmd = layer.get("CreatedBy", "")
        layer_id = layer.get("ID", f"layer-{idx}")[:12]

        for risk_level, category, pattern, recommendation in risk_patterns:
            if pattern.search(cmd):
                findings.append(
                    LayerFinding(
                        layer_id=layer_id,
                        layer_index=idx,
                        risk_level=risk_level,
                        category=category,
                        description=f"레이어 {idx}에서 위험 패턴 탐지: {category}",
                        command=cmd[:200],
                        recommendation=recommendation,
                    )
                )

    return findings


def analyze_image_config(inspect: dict[str, Any]) -> list[LayerFinding]:
    """이미지 설정에서 보안 위험 탐지."""
    findings: list[LayerFinding] = []
    config = inspect.get("Config", {})

    # User 검사
    user = config.get("User", "")
    if not user or user in ("root", "0", "0:0"):
        findings.append(
            LayerFinding(
                layer_id="config",
                layer_index=-1,
                risk_level=RiskLevel.HIGH,
                category="root 실행",
                description="이미지가 root 사용자로 실행되도록 설정되어 있습니다.",
                command=f"USER {user or '(미설정)'}",
                recommendation="Dockerfile에 USER nonroot 또는 USER 1000:1000을 추가하세요.",
            )
        )

    # Healthcheck 검사
    if not config.get("Healthcheck"):
        findings.append(
            LayerFinding(
                layer_id="config",
                layer_index=-1,
                risk_level=RiskLevel.LOW,
                category="Healthcheck 미설정",
                description="컨테이너 상태 확인을 위한 HEALTHCHECK가 설정되지 않았습니다.",
                command="HEALTHCHECK 없음",
                recommendation=(
                    "HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1"
                ),
            )
        )

    # 환경 변수 민감 정보 검사
    env_vars = config.get("Env", [])
    sensitive_env_pattern = re.compile(
        r"(password|secret|key|token|credential)=",
        re.IGNORECASE,
    )
    for env_var in env_vars:
        if sensitive_env_pattern.search(env_var):
            var_name = env_var.split("=")[0]
            findings.append(
                LayerFinding(
                    layer_id="config",
                    layer_index=-1,
                    risk_level=RiskLevel.CRITICAL,
                    category="민감한 환경 변수",
                    description=f"민감한 정보가 환경 변수에 하드코딩될 수 있습니다: {var_name}",
                    command=f"ENV {var_name}=***",
                    recommendation=(
                        "런타임에 Kubernetes Secret 또는 HashiCorp Vault로 주입하세요."
                    ),
                )
            )

    # 노출 포트 검사
    exposed_ports = list(config.get("ExposedPorts", {}).keys())
    for port in exposed_ports:
        port_num = int(port.split("/")[0])
        if port_num < 1024:
            findings.append(
                LayerFinding(
                    layer_id="config",
                    layer_index=-1,
                    risk_level=RiskLevel.MEDIUM,
                    category="권한 포트 사용",
                    description=f"1024 미만의 포트({port})가 노출됩니다. root 권한이 필요합니다.",
                    command=f"EXPOSE {port}",
                    recommendation=(
                        f"포트를 {port_num + 8000}와 같은 높은 포트로 변경하고 "
                        "Kubernetes Service로 포워딩하세요."
                    ),
                )
            )

    return findings


def run_trivy_scan(image: str) -> tuple[int, int]:
    """Trivy로 CVE 스캔 실행."""
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--quiet",
                "--severity", "CRITICAL,HIGH",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode not in (0, 1):
            return 0, 0

        data = json.loads(result.stdout)
        critical = high = 0
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                if vuln.get("Severity") == "CRITICAL":
                    critical += 1
                elif vuln.get("Severity") == "HIGH":
                    high += 1
        return critical, high
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return 0, 0


def analyze_image(image: str, skip_trivy: bool = False) -> ImageAnalysisResult:
    """이미지 종합 보안 분석."""
    print(f"[정보] 이미지 분석 중: {image}", file=sys.stderr)

    # 이미지 정보 수집
    inspect = get_image_inspect(image)
    history = get_image_history(image)

    if not inspect:
        print(f"[오류] 이미지를 찾을 수 없습니다: {image}", file=sys.stderr)
        sys.exit(1)

    # 이미지 크기 계산
    size_bytes = inspect.get("Size", 0)
    size_mb = size_bytes / (1024 * 1024)

    # 설정 정보 추출
    config = inspect.get("Config", {})
    user = config.get("User", "root")
    has_healthcheck = bool(config.get("Healthcheck"))
    exposed_ports = [
        int(p.split("/")[0])
        for p in config.get("ExposedPorts", {}).keys()
    ]
    env_vars = config.get("Env", [])

    result = ImageAnalysisResult(
        image=image,
        total_layers=len(history),
        total_size_mb=size_mb,
        user=user or "root",
        has_healthcheck=has_healthcheck,
        exposed_ports=exposed_ports,
        env_vars=env_vars,
    )

    # 병렬로 분석 실행
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(analyze_layer_commands, history): "layer",
            executor.submit(analyze_image_config, inspect): "config",
        }
        if not skip_trivy:
            futures[executor.submit(run_trivy_scan, image)] = "trivy"

        for future in as_completed(futures):
            analysis_type = futures[future]
            try:
                res = future.result()
                if analysis_type in ("layer", "config"):
                    result.findings.extend(res)
                elif analysis_type == "trivy":
                    result.trivy_critical, result.trivy_high = res
            except Exception as e:
                print(f"[경고] {analysis_type} 분석 실패: {e}", file=sys.stderr)

    return result


def print_analysis_report(result: ImageAnalysisResult, fmt: str) -> None:
    """분석 결과 출력."""
    if fmt == "json":
        report = {
            "summary": result.summary(),
            "findings": [
                {
                    "layer_id": f.layer_id,
                    "layer_index": f.layer_index,
                    "risk_level": f.risk_level.value,
                    "category": f.category,
                    "description": f.description,
                    "command": f.command,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 텍스트 보고서
    print("\n" + "=" * 70)
    print(f"  이미지 레이어 보안 분석 결과: {result.image}")
    print("=" * 70)
    print(f"  레이어 수:    {result.total_layers}")
    print(f"  이미지 크기:  {result.total_size_mb:.1f} MB")
    print(f"  실행 사용자:  {result.user}")
    print(f"  Healthcheck: {'설정됨' if result.has_healthcheck else '미설정'}")
    print(f"  노출 포트:    {result.exposed_ports or '없음'}")

    if result.trivy_critical > 0 or result.trivy_high > 0:
        print(f"\n  CVE 취약점:")
        print(f"    CRITICAL: {result.trivy_critical}")
        print(f"    HIGH:     {result.trivy_high}")

    print("\n" + "-" * 70)
    print(f"  발견된 문제: {len(result.findings)}개")
    print("-" * 70)

    severity_order = [
        RiskLevel.CRITICAL, RiskLevel.HIGH,
        RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO,
    ]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.risk_level),
    )

    colors = {
        RiskLevel.CRITICAL: "\033[91m",
        RiskLevel.HIGH: "\033[93m",
        RiskLevel.MEDIUM: "\033[94m",
        RiskLevel.LOW: "\033[92m",
        RiskLevel.INFO: "\033[0m",
    }
    reset = "\033[0m"

    for finding in sorted_findings:
        color = colors.get(finding.risk_level, reset)
        print(
            f"\n{color}[{finding.risk_level.value}]{reset} "
            f"{finding.category} (레이어: {finding.layer_id})"
        )
        print(f"  설명: {finding.description}")
        print(f"  명령: {finding.command[:100]}...")
        print(f"  조치: {finding.recommendation}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="컨테이너 이미지 레이어 보안 분석 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  %(prog)s nginx:latest
  %(prog)s python:3.12-slim --format json
  %(prog)s myapp:v1.0 --skip-trivy
  %(prog)s alpine:3.18 --format json | jq '.findings[] | select(.risk_level == "CRITICAL")'
        """,
    )
    parser.add_argument("image", help="분석할 컨테이너 이미지 (예: nginx:latest)")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="출력 형식 (기본: text)",
    )
    parser.add_argument(
        "--skip-trivy",
        action="store_true",
        help="Trivy CVE 스캔 건너뛰기 (Trivy 미설치 환경)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = analyze_image(args.image, skip_trivy=args.skip_trivy)
    print_analysis_report(result, args.format)

    # CRITICAL 발견 시 비정상 종료 (CI/CD 차단 가능)
    critical_count = sum(
        1 for f in result.findings
        if f.risk_level == RiskLevel.CRITICAL
    )
    return 1 if critical_count > 0 or result.trivy_critical > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

### 도구 사용법

```bash
# 단일 이미지 분석
python image_security_analyzer.py nginx:latest

# JSON 출력 (CI/CD 통합)
python image_security_analyzer.py myapp:v1.0 --format json

# Trivy 없는 환경에서 실행
python image_security_analyzer.py alpine:3.18 --skip-trivy

# CI/CD 파이프라인에서 사용 (CRITICAL 발견 시 빌드 실패)
python image_security_analyzer.py $IMAGE_TAG || exit 1

# CRITICAL 항목만 필터링
python image_security_analyzer.py nginx:latest --format json | \
  jq '.findings[] | select(.risk_level == "CRITICAL")'
```

---

## 참고 자료

- [Trivy 문서](https://aquasecurity.github.io/trivy/)
- [Grype GitHub](https://github.com/anchore/grype)
- [Cosign 문서](https://docs.sigstore.dev/cosign/overview/)
- [Google Distroless 이미지](https://github.com/GoogleContainerTools/distroless)
- [OPA/Gatekeeper 문서](https://open-policy-agent.github.io/gatekeeper/)
- [CISA SBOM 가이드라인](https://www.cisa.gov/sbom)
- [SLSA 프레임워크](https://slsa.dev/)
- [Docker 보안 모범 사례](https://docs.docker.com/develop/security-best-practices/)

---

<a name="english"></a>

# Container Image Hardening and Supply Chain Security

## Table of Contents
1. Container Image Vulnerability Scanning Tools
2. Distroless / Scratch Base Images
3. Image Signing (Cosign, Sigstore)
4. OPA / Gatekeeper Policy Enforcement
5. SBOM Generation and Image Supply Chain Security
6. Python: Image Layer Security Analysis Tool

---

## 1. Container Image Vulnerability Scanning Tools

### 1.1 Trivy (Aqua Security)

Trivy is the most widely used open-source container vulnerability scanner.

**Scan targets**:
- Container images (OS packages, language dependencies)
- Filesystems
- Git repositories
- IaC (Terraform, CloudFormation, Kubernetes YAML)
- SBOM

```bash
# Scan an image
trivy image nginx:latest

# Filter by severity (CRITICAL and HIGH only)
trivy image --severity CRITICAL,HIGH nginx:latest

# JSON output (CI/CD integration)
trivy image --format json --output report.json nginx:latest

# Scan a Kubernetes cluster
trivy k8s --report summary cluster

# Scan IaC
trivy config ./terraform/

# Generate SBOM
trivy image --format cyclonedx nginx:latest -o sbom.json
```

**Configuration file (trivy.yaml)**:
```yaml
severity:
  - CRITICAL
  - HIGH

exit-code: 1  # Exit with non-zero code when vulnerabilities found (blocks CI/CD)

ignore-unfixed: true  # Ignore vulnerabilities with no available patch

skip-dirs:
  - usr/share/doc

vulnerability:
  type:
    - os
    - library
```

### 1.2 Grype (Anchore)

Grype is a vulnerability scanner designed to work alongside Syft.

```bash
# Scan an image
grype nginx:latest

# Scan from SBOM (generate with Syft first)
syft nginx:latest -o json > sbom.json
grype sbom:sbom.json

# Fail based on severity threshold
grype nginx:latest --fail-on critical

# Ignore specific vulnerabilities (.grype.yaml)
```

```yaml
# .grype.yaml
ignore:
  - vulnerability: CVE-2020-14145
    reason: "Feature not in use"
  - fix-state: wont-fix
```

### 1.3 Snyk Container

Snyk provides a developer-friendly interface with automatic fix PR capabilities.

```bash
# CLI scan
snyk container test nginx:latest

# Scan Dockerfile (includes base image recommendations)
snyk container test nginx:latest --file=Dockerfile

# Monitor (continuous scanning)
snyk container monitor nginx:latest --project-name=my-app
```

### Vulnerability Scanner Comparison

| Criteria | Trivy | Grype | Snyk |
|----------|-------|-------|------|
| Open source | Fully open source | Fully open source | Limited free tier |
| SBOM support | CycloneDX, SPDX | SPDX | CycloneDX |
| IaC scanning | Supported | Not supported | Supported |
| Auto fix | Not supported | Not supported | Creates PR |
| Update frequency | 6 hours | 24 hours | Real-time |
| CI/CD integration | Very easy | Easy | Moderate |

---

## 2. Distroless / Scratch Base Images

### 2.1 What Are Distroless Images?

Distroless images, created by Google, contain only the application and its runtime dependencies,
removing package managers, shells, and utilities — resulting in a minimized image.

**Attack surface reduction effect**:
```
Standard ubuntu:22.04:  ~400 OS packages, bash, apt, curl, etc.
Distroless Python:      ~30 packages, no shell, no package manager
Scratch (empty image):  0 packages (static binaries only)
```

### 2.2 Using Distroless Images

```dockerfile
# Multi-stage build using Distroless
# Build stage
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/packages -r requirements.txt
COPY app.py .

# Runtime stage (Distroless)
FROM gcr.io/distroless/python3-debian12
WORKDIR /app
COPY --from=builder /app/packages /app/packages
COPY --from=builder /app/app.py .
ENV PYTHONPATH=/app/packages
USER nonroot:nonroot
CMD ["app.py"]
```

```dockerfile
# Go static binary - using Scratch image
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

FROM scratch
COPY --from=builder /app/server /server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 65534:65534  # nobody
ENTRYPOINT ["/server"]
```

### 2.3 Security-Hardened Dockerfile Best Practices

```dockerfile
FROM python:3.12-slim

# Remove unnecessary privileged tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgomp1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/bin/wget /usr/bin/curl

# Create a dedicated non-root user
RUN groupadd -r appgroup --gid=1001 && \
    useradd -r -g appgroup --uid=1001 --no-log-init appuser

WORKDIR /app

# Copy dependencies first (layer caching optimization)
COPY --chown=appuser:appgroup requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Read-only filesystem (pairs with runAsReadOnlyRootFilesystem: true)
VOLUME ["/tmp", "/var/cache"]

EXPOSE 8080
ENTRYPOINT ["python", "app.py"]
```

---

## 3. Image Signing (Cosign, Sigstore)

### 3.1 The Sigstore Ecosystem

Sigstore is a free, open-source infrastructure for signing and verifying
software artifacts (images, binaries, SBOMs).

**Components**:
```
Sigstore Ecosystem:
├── Cosign    - Container image signing/verification
├── Fulcio    - Short-lived signing certificate CA
├── Rekor     - Immutable transparency log
└── Gitsign   - Git commit signing
```

### 3.2 Signing Images with Cosign

```bash
# 1. Generate a key pair
cosign generate-key-pair

# 2. Sign an image (key-based)
cosign sign --key cosign.key registry.example.com/myapp:v1.0.0

# 3. OIDC-based signing (keyless - for CI/CD environments)
# In GitHub Actions:
cosign sign --yes registry.example.com/myapp:v1.0.0

# 4. Verify a signature
cosign verify \
  --key cosign.pub \
  registry.example.com/myapp:v1.0.0

# 5. Attach and sign an SBOM
cosign attach sbom --sbom sbom.cyclonedx.json \
  registry.example.com/myapp:v1.0.0

cosign sign --key cosign.key \
  --attachment sbom \
  registry.example.com/myapp:v1.0.0
```

### 3.3 GitHub Actions CI/CD Integration

```yaml
# .github/workflows/build-sign.yml
name: Build and Sign Container Image

on:
  push:
    tags: ['v*']

jobs:
  build-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # Required for OIDC signing

    steps:
    - uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Login to GHCR
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Build and Push
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}

    - name: Install Cosign
      uses: sigstore/cosign-installer@v3

    - name: Sign Image (Keyless)
      run: |
        cosign sign --yes \
          ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

    - name: Scan with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'
```

---

## 4. OPA / Gatekeeper Policy Enforcement

### 4.1 OPA (Open Policy Agent)

OPA is a unified policy engine that uses the Rego language to define policies.

```rego
# Rego policy: Block root containers
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf(
        "Container '%v' in Pod '%v' runs as root (UID=0). Denied.",
        [container.name, input.request.object.metadata.name]
    )
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "Container '%v' has privileged=true set.",
        [container.name]
    )
}
```

### 4.2 Gatekeeper (OPA for Kubernetes)

```bash
# Install Gatekeeper
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper \
  --name-template=gatekeeper \
  --namespace gatekeeper-system \
  --create-namespace \
  --set replicas=2
```

```yaml
# ConstraintTemplate: Allow only signed images
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsignedimages
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSignedImages
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedRegistries:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredsignedimages

      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not starts_with_allowed_registry(container.image)
        msg := sprintf(
          "Image '%v' does not come from an allowed registry.",
          [container.image]
        )
      }

      starts_with_allowed_registry(image) {
        registry := input.parameters.allowedRegistries[_]
        startswith(image, registry)
      }

---
# Constraint: Apply the policy
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredSignedImages
metadata:
  name: require-signed-images
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces:
    - production
  parameters:
    allowedRegistries:
    - "registry.company.com/"
    - "ghcr.io/myorg/"
```

```yaml
# Gatekeeper Mutation: Auto-inject security defaults
apiVersion: mutations.gatekeeper.sh/v1
kind: AssignMetadata
metadata:
  name: add-security-labels
spec:
  match:
    scope: Namespaced
    kinds:
    - apiGroups: ["*"]
      kinds: ["Pod"]
  location: "metadata.labels.security-scanned"
  parameters:
    assign:
      value: "true"
```

---

## 5. SBOM Generation and Image Supply Chain Security

### 5.1 SBOM (Software Bill of Materials)

An SBOM is a complete list of all components included in a piece of software.
Since the U.S. Executive Order EO 14028, it has become a core element of supply chain security.

**Standard formats**:
- **CycloneDX**: Led by OWASP, security-focused
- **SPDX**: Led by Linux Foundation, license-focused
- **SWID**: ISO/IEC standard

```bash
# Generate SBOM with Syft
syft nginx:latest -o cyclonedx-json > nginx-sbom.cyclonedx.json
syft nginx:latest -o spdx-json > nginx-sbom.spdx.json

# Generate SBOM with Trivy
trivy image --format cyclonedx nginx:latest -o nginx-sbom.json

# Vulnerability scan from SBOM
grype sbom:nginx-sbom.cyclonedx.json
```

### 5.2 Supply Chain Attack Scenarios

**Scenario 1: Typosquatting**
```
Attacker: Uploads a malicious image named "ngnix" (typo) to Docker Hub
Victim: docker pull ngnix:latest (downloads malicious image due to typo)
```

**Scenario 2: Base Image Poisoning**
```
Attacker: Inserts a backdoor into a popular base image (python:3.12)
Impact: Backdoor propagates to all apps using that image
```

**Scenario 3: Build Pipeline Compromise**
```
Attacker: Injects malicious code into the CI/CD pipeline
Result: Malicious code is included in the image at build time
```

### 5.3 Supply Chain Security Hardening Strategy

```
Supply Chain Security Layers:
├── Stage 1: Source Code
│   ├── Branch protection (Signed Commits)
│   ├── SAST (Semgrep, SonarQube)
│   └── Dependency review (Dependabot)
│
├── Stage 2: Build
│   ├── Build environment isolation (Ephemeral environments)
│   ├── Reproducible Builds
│   └── SLSA (Supply chain Levels for Software Artifacts)
│
├── Stage 3: Image Registry
│   ├── Enforce image signing (Cosign)
│   ├── Image scanning (Trivy)
│   └── Allowed registry list
│
└── Stage 4: Deployment
    ├── Signature verification (Admission Controller)
    ├── Gatekeeper policies
    └── Runtime monitoring (Falco)
```

---

## 6. Python: Image Layer Security Analysis Tool

```python
#!/usr/bin/env python3
"""
Container Image Layer Security Analysis Tool

Analyzes each layer of a container image to detect security risks.
"""

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class LayerFinding:
    layer_id: str
    layer_index: int
    risk_level: RiskLevel
    category: str
    description: str
    command: str
    recommendation: str


@dataclass
class ImageAnalysisResult:
    image: str
    total_layers: int
    total_size_mb: float
    findings: list[LayerFinding] = field(default_factory=list)
    exposed_ports: list[int] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)
    user: str = "root"
    has_healthcheck: bool = False
    trivy_critical: int = 0
    trivy_high: int = 0

    def summary(self) -> dict[str, Any]:
        findings_by_level: dict[str, int] = {}
        for f in self.findings:
            findings_by_level[f.risk_level.value] = (
                findings_by_level.get(f.risk_level.value, 0) + 1
            )
        return {
            "image": self.image,
            "total_layers": self.total_layers,
            "size_mb": round(self.total_size_mb, 2),
            "user": self.user,
            "has_healthcheck": self.has_healthcheck,
            "exposed_ports": self.exposed_ports,
            "findings_count": findings_by_level,
            "trivy_critical": self.trivy_critical,
            "trivy_high": self.trivy_high,
        }


def run_docker(args: list[str]) -> dict[str, Any] | list[Any] | str | None:
    """Execute a docker command."""
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] docker error: {e.stderr.strip()}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[WARNING] docker command timed out", file=sys.stderr)
        return None


def get_image_inspect(image: str) -> dict[str, Any] | None:
    """Retrieve image information via docker inspect."""
    raw = run_docker(["inspect", image])
    if not raw:
        return None
    try:
        data = json.loads(str(raw))
        return data[0] if isinstance(data, list) and data else None
    except (json.JSONDecodeError, IndexError):
        return None


def get_image_history(image: str) -> list[dict[str, Any]]:
    """Retrieve image layer history."""
    raw = run_docker(["history", "--format", "json", "--no-trunc", image])
    if not raw:
        return []
    try:
        lines = str(raw).strip().split("\n")
        return [json.loads(line) for line in lines if line.strip()]
    except json.JSONDecodeError:
        return []


def analyze_layer_commands(
    history: list[dict[str, Any]]
) -> list[LayerFinding]:
    """Detect security risks from layer commands."""
    findings: list[LayerFinding] = []

    # Define risk patterns
    risk_patterns = [
        (
            RiskLevel.CRITICAL,
            "Secret key exposure",
            re.compile(
                r"(password|passwd|secret|api_key|private_key|token)\s*[=:]\s*\S+",
                re.IGNORECASE,
            ),
            "Pass via environment variables or ARG and use multi-stage builds.",
        ),
        (
            RiskLevel.CRITICAL,
            "SSH private key copy",
            re.compile(r"COPY.*\.pem|COPY.*id_rsa|ADD.*\.key"),
            "Use build secrets (--secret) and do not include keys in the final image.",
        ),
        (
            RiskLevel.HIGH,
            "Package cache not cleaned",
            re.compile(r"apt-get install(?!.*rm -rf /var/lib/apt)"),
            "Use RUN apt-get install && rm -rf /var/lib/apt/lists/* to clean the cache.",
        ),
        (
            RiskLevel.HIGH,
            "curl | bash pattern",
            re.compile(r"curl.*\|.*bash|wget.*\|.*sh"),
            "Download the script first, review it, then execute.",
        ),
        (
            RiskLevel.HIGH,
            "ADD with remote URL",
            re.compile(r"^ADD\s+https?://"),
            "Use COPY instead of ADD; download with wget/curl and verify checksums.",
        ),
        (
            RiskLevel.MEDIUM,
            "chmod 777 usage",
            re.compile(r"chmod\s+777|chmod\s+-R\s+777"),
            "Use the minimum required permissions (755 or 644).",
        ),
        (
            RiskLevel.MEDIUM,
            "setuid/setgid binaries",
            re.compile(r"chmod\s+[0-9]*[46][0-9]*|chmod.*[su]"),
            "Review whether setuid/setgid bits are necessary and remove them if not.",
        ),
        (
            RiskLevel.MEDIUM,
            "sudo installation",
            re.compile(r"apt-get install.*sudo|yum install.*sudo"),
            "sudo is unnecessary in containers. Manage permissions via the USER directive.",
        ),
        (
            RiskLevel.LOW,
            "Package installation without version pinning",
            re.compile(r"apt-get install -y (?!--no-install-recommends)"),
            "Use the --no-install-recommends flag and pin versions.",
        ),
        (
            RiskLevel.INFO,
            "Latest tag usage",
            re.compile(r"FROM\s+\w+:latest"),
            "Use a specific digest or version tag instead of latest.",
        ),
    ]

    for idx, layer in enumerate(history):
        cmd = layer.get("CreatedBy", "")
        layer_id = layer.get("ID", f"layer-{idx}")[:12]

        for risk_level, category, pattern, recommendation in risk_patterns:
            if pattern.search(cmd):
                findings.append(
                    LayerFinding(
                        layer_id=layer_id,
                        layer_index=idx,
                        risk_level=risk_level,
                        category=category,
                        description=f"Risk pattern detected in layer {idx}: {category}",
                        command=cmd[:200],
                        recommendation=recommendation,
                    )
                )

    return findings


def analyze_image_config(inspect: dict[str, Any]) -> list[LayerFinding]:
    """Detect security risks from image configuration."""
    findings: list[LayerFinding] = []
    config = inspect.get("Config", {})

    # Check User
    user = config.get("User", "")
    if not user or user in ("root", "0", "0:0"):
        findings.append(
            LayerFinding(
                layer_id="config",
                layer_index=-1,
                risk_level=RiskLevel.HIGH,
                category="Running as root",
                description="The image is configured to run as the root user.",
                command=f"USER {user or '(not set)'}",
                recommendation="Add USER nonroot or USER 1000:1000 to the Dockerfile.",
            )
        )

    # Check Healthcheck
    if not config.get("Healthcheck"):
        findings.append(
            LayerFinding(
                layer_id="config",
                layer_index=-1,
                risk_level=RiskLevel.LOW,
                category="No HEALTHCHECK configured",
                description="No HEALTHCHECK has been configured for container health monitoring.",
                command="No HEALTHCHECK",
                recommendation=(
                    "HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1"
                ),
            )
        )

    # Check environment variables for sensitive information
    env_vars = config.get("Env", [])
    sensitive_env_pattern = re.compile(
        r"(password|secret|key|token|credential)=",
        re.IGNORECASE,
    )
    for env_var in env_vars:
        if sensitive_env_pattern.search(env_var):
            var_name = env_var.split("=")[0]
            findings.append(
                LayerFinding(
                    layer_id="config",
                    layer_index=-1,
                    risk_level=RiskLevel.CRITICAL,
                    category="Sensitive environment variable",
                    description=f"Sensitive information may be hardcoded in an environment variable: {var_name}",
                    command=f"ENV {var_name}=***",
                    recommendation=(
                        "Inject at runtime using Kubernetes Secrets or HashiCorp Vault."
                    ),
                )
            )

    # Check exposed ports
    exposed_ports = list(config.get("ExposedPorts", {}).keys())
    for port in exposed_ports:
        port_num = int(port.split("/")[0])
        if port_num < 1024:
            findings.append(
                LayerFinding(
                    layer_id="config",
                    layer_index=-1,
                    risk_level=RiskLevel.MEDIUM,
                    category="Privileged port usage",
                    description=f"Port below 1024 ({port}) is exposed. Requires root privileges.",
                    command=f"EXPOSE {port}",
                    recommendation=(
                        f"Change to a higher port such as {port_num + 8000} "
                        "and forward via a Kubernetes Service."
                    ),
                )
            )

    return findings


def run_trivy_scan(image: str) -> tuple[int, int]:
    """Run CVE scan with Trivy."""
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",
                "--quiet",
                "--severity", "CRITICAL,HIGH",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode not in (0, 1):
            return 0, 0

        data = json.loads(result.stdout)
        critical = high = 0
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                if vuln.get("Severity") == "CRITICAL":
                    critical += 1
                elif vuln.get("Severity") == "HIGH":
                    high += 1
        return critical, high
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return 0, 0


def analyze_image(image: str, skip_trivy: bool = False) -> ImageAnalysisResult:
    """Comprehensive image security analysis."""
    print(f"[INFO] Analyzing image: {image}", file=sys.stderr)

    # Collect image information
    inspect = get_image_inspect(image)
    history = get_image_history(image)

    if not inspect:
        print(f"[ERROR] Image not found: {image}", file=sys.stderr)
        sys.exit(1)

    # Calculate image size
    size_bytes = inspect.get("Size", 0)
    size_mb = size_bytes / (1024 * 1024)

    # Extract configuration
    config = inspect.get("Config", {})
    user = config.get("User", "root")
    has_healthcheck = bool(config.get("Healthcheck"))
    exposed_ports = [
        int(p.split("/")[0])
        for p in config.get("ExposedPorts", {}).keys()
    ]
    env_vars = config.get("Env", [])

    result = ImageAnalysisResult(
        image=image,
        total_layers=len(history),
        total_size_mb=size_mb,
        user=user or "root",
        has_healthcheck=has_healthcheck,
        exposed_ports=exposed_ports,
        env_vars=env_vars,
    )

    # Run analyses in parallel
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(analyze_layer_commands, history): "layer",
            executor.submit(analyze_image_config, inspect): "config",
        }
        if not skip_trivy:
            futures[executor.submit(run_trivy_scan, image)] = "trivy"

        for future in as_completed(futures):
            analysis_type = futures[future]
            try:
                res = future.result()
                if analysis_type in ("layer", "config"):
                    result.findings.extend(res)
                elif analysis_type == "trivy":
                    result.trivy_critical, result.trivy_high = res
            except Exception as e:
                print(f"[WARNING] {analysis_type} analysis failed: {e}", file=sys.stderr)

    return result


def print_analysis_report(result: ImageAnalysisResult, fmt: str) -> None:
    """Print the analysis report."""
    if fmt == "json":
        report = {
            "summary": result.summary(),
            "findings": [
                {
                    "layer_id": f.layer_id,
                    "layer_index": f.layer_index,
                    "risk_level": f.risk_level.value,
                    "category": f.category,
                    "description": f.description,
                    "command": f.command,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # Text report
    print("\n" + "=" * 70)
    print(f"  Image Layer Security Analysis Result: {result.image}")
    print("=" * 70)
    print(f"  Layers:       {result.total_layers}")
    print(f"  Image size:   {result.total_size_mb:.1f} MB")
    print(f"  Run as user:  {result.user}")
    print(f"  Healthcheck:  {'Configured' if result.has_healthcheck else 'Not configured'}")
    print(f"  Exposed ports:{result.exposed_ports or 'None'}")

    if result.trivy_critical > 0 or result.trivy_high > 0:
        print(f"\n  CVE Vulnerabilities:")
        print(f"    CRITICAL: {result.trivy_critical}")
        print(f"    HIGH:     {result.trivy_high}")

    print("\n" + "-" * 70)
    print(f"  Issues found: {len(result.findings)}")
    print("-" * 70)

    severity_order = [
        RiskLevel.CRITICAL, RiskLevel.HIGH,
        RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO,
    ]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.risk_level),
    )

    colors = {
        RiskLevel.CRITICAL: "\033[91m",
        RiskLevel.HIGH: "\033[93m",
        RiskLevel.MEDIUM: "\033[94m",
        RiskLevel.LOW: "\033[92m",
        RiskLevel.INFO: "\033[0m",
    }
    reset = "\033[0m"

    for finding in sorted_findings:
        color = colors.get(finding.risk_level, reset)
        print(
            f"\n{color}[{finding.risk_level.value}]{reset} "
            f"{finding.category} (layer: {finding.layer_id})"
        )
        print(f"  Description: {finding.description}")
        print(f"  Command:     {finding.command[:100]}...")
        print(f"  Action:      {finding.recommendation}")

    print("\n" + "=" * 70)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Container image layer security analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s nginx:latest
  %(prog)s python:3.12-slim --format json
  %(prog)s myapp:v1.0 --skip-trivy
  %(prog)s alpine:3.18 --format json | jq '.findings[] | select(.risk_level == "CRITICAL")'
        """,
    )
    parser.add_argument("image", help="Container image to analyze (e.g., nginx:latest)")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--skip-trivy",
        action="store_true",
        help="Skip Trivy CVE scan (for environments without Trivy installed)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = analyze_image(args.image, skip_trivy=args.skip_trivy)
    print_analysis_report(result, args.format)

    # Exit with non-zero code when CRITICAL findings exist (can block CI/CD)
    critical_count = sum(
        1 for f in result.findings
        if f.risk_level == RiskLevel.CRITICAL
    )
    return 1 if critical_count > 0 or result.trivy_critical > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

### Tool Usage

```bash
# Analyze a single image
python image_security_analyzer.py nginx:latest

# JSON output (CI/CD integration)
python image_security_analyzer.py myapp:v1.0 --format json

# Run in an environment without Trivy
python image_security_analyzer.py alpine:3.18 --skip-trivy

# Use in a CI/CD pipeline (fail build on CRITICAL findings)
python image_security_analyzer.py $IMAGE_TAG || exit 1

# Filter CRITICAL items only
python image_security_analyzer.py nginx:latest --format json | \
  jq '.findings[] | select(.risk_level == "CRITICAL")'
```

---

## References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype GitHub](https://github.com/anchore/grype)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Google Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [OPA/Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/)
- [CISA SBOM Guidelines](https://www.cisa.gov/sbom)
- [SLSA Framework](https://slsa.dev/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
