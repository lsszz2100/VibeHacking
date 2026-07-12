> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 공급망 보안 방어 — SBOM·의존성 스캔·벤더 위험 관리

## 0. 초보자를 위한 개념 이해

### 공급망 공격이란?

공급망 공격은 직접 표적을 공격하는 대신, 표적이 신뢰하는 소프트웨어/하드웨어 공급자를 공격합니다. SolarWinds(2020), Log4Shell(2021), XZ Utils(2024) 사건이 대표적입니다.

```
공급망 공격 유형:

  소프트웨어 공급망:
    오픈소스 패키지 오염  → npm 악성 패키지, typosquatting
    업스트림 소스 코드 변조 → XZ Utils (CVE-2024-3094)
    업데이트 메커니즘 탈취 → SolarWinds SUNBURST
    CI/CD 파이프라인 공격 → 빌드 서버 해킹

  하드웨어 공급망:
    위조 부품              → 가짜 칩/모듈
    제조 과정 변조         → 백도어 하드웨어
    펌웨어 오염            → 공장 출하 시 악성 펌웨어

  공격 흐름:
  공급업체 해킹 → 소프트웨어/업데이트에 악성코드 삽입
      → 표적이 신뢰하는 업데이트 자동 설치
      → 표적 시스템 침해
```

---

## 1. SBOM (Software Bill of Materials)

### 1.1 SBOM 생성

```python
#!/usr/bin/env python3
"""
SBOM 생성 및 취약점 매핑 자동화.
pip install cyclonedx-bom syrupy
참고: https://cyclonedx.org/
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class Component:
    name: str
    version: str
    type: str  # library/framework/tool
    purl: str  # Package URL (pkg:npm/lodash@4.17.21)
    license: str = "unknown"
    cves: list[str] = field(default_factory=list)


@dataclass
class SBOM:
    metadata_component: str  # 소프트웨어 이름
    version: str
    generated_at: str
    components: list[Component] = field(default_factory=list)
    format: str = "CycloneDX"
    spec_version: str = "1.5"


def generate_python_sbom(project_dir: str) -> SBOM:
    """
    Python 프로젝트 SBOM 생성.
    pip list --format=json에서 패키지 목록 추출.
    """
    sbom = SBOM(
        metadata_component=Path(project_dir).name,
        version="1.0.0",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, check=True,
            cwd=project_dir,
        )
        packages = json.loads(result.stdout)

        for pkg in packages:
            name = pkg["name"]
            version = pkg["version"]
            purl = f"pkg:pypi/{name.lower()}@{version}"

            # 라이선스 정보 조회 (pip show)
            show_result = subprocess.run(
                [sys.executable, "-m", "pip", "show", name],
                capture_output=True, text=True, check=False
            )
            license_info = "unknown"
            for line in show_result.stdout.splitlines():
                if line.startswith("License:"):
                    license_info = line.split(":", 1)[1].strip()
                    break

            sbom.components.append(Component(
                name=name, version=version,
                type="library", purl=purl, license=license_info,
            ))

        log.info("Python SBOM 생성: %d개 컴포넌트", len(sbom.components))
    except Exception as exc:
        log.error("SBOM 생성 실패: %s", exc)

    return sbom


def generate_npm_sbom(project_dir: str) -> SBOM:
    """Node.js 프로젝트 SBOM 생성 (package-lock.json 파싱)."""
    sbom = SBOM(
        metadata_component=Path(project_dir).name,
        version="1.0.0",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    lock_file = Path(project_dir) / "package-lock.json"
    if not lock_file.exists():
        log.warning("package-lock.json 없음: %s", project_dir)
        return sbom

    lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    packages = lock_data.get("packages", lock_data.get("dependencies", {}))

    for pkg_path, pkg_info in packages.items():
        if not pkg_path:
            continue
        name = pkg_path.split("node_modules/")[-1]
        version = pkg_info.get("version", "unknown")
        purl = f"pkg:npm/{name}@{version}"
        sbom.components.append(Component(
            name=name, version=version,
            type="library", purl=purl,
            license=pkg_info.get("license", "unknown"),
        ))

    log.info("npm SBOM 생성: %d개 컴포넌트", len(sbom.components))
    return sbom


def export_sbom_cyclonedx_json(sbom: SBOM, output_path: str) -> None:
    """CycloneDX 1.5 JSON 형식으로 SBOM 내보내기."""
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": sbom.spec_version,
        "serialNumber": f"urn:uuid:{__import__('uuid').uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": sbom.generated_at,
            "component": {
                "type": "application",
                "name": sbom.metadata_component,
                "version": sbom.version,
            },
        },
        "components": [
            {
                "type": c.type,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "licenses": [{"license": {"name": c.license}}] if c.license != "unknown" else [],
            }
            for c in sbom.components
        ],
    }
    Path(output_path).write_text(
        json.dumps(cdx, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log.info("CycloneDX SBOM 저장: %s (%d 컴포넌트)", output_path, len(sbom.components))
```

---

## 2. 의존성 취약점 스캔 자동화

### 2.1 다중 스캐너 통합

```python
#!/usr/bin/env python3
"""
의존성 취약점 다중 스캐너 통합.
pip-audit, npm audit, grype, Trivy 결과 통합.
"""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    package: str
    version: str
    vuln_id: str  # CVE-2024-xxxxx 또는 GHSA-xxxxx
    severity: str  # Critical/High/Medium/Low
    fixed_version: Optional[str]
    description: str
    source: str  # pip-audit/npm-audit/trivy


def scan_python_deps(requirements_file: str = "requirements.txt") -> list[Vulnerability]:
    """pip-audit로 Python 의존성 취약점 스캔."""
    vulns: list[Vulnerability] = []
    try:
        result = subprocess.run(
            ["pip-audit", "--format=json", "-r", requirements_file],
            capture_output=True, text=True, check=False
        )
        # pip-audit가 없으면 설치 안내
        if result.returncode == 127:
            log.error("pip-audit 없음: pip install pip-audit")
            return vulns

        data = json.loads(result.stdout or "[]")
        for item in data:
            for vuln in item.get("vulns", []):
                vulns.append(Vulnerability(
                    package=item.get("name", ""),
                    version=item.get("version", ""),
                    vuln_id=vuln.get("id", ""),
                    severity=vuln.get("fix_versions", [{}])[0] and "Medium" or "Unknown",
                    fixed_version=vuln.get("fix_versions", [None])[0],
                    description=vuln.get("description", "")[:200],
                    source="pip-audit",
                ))
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        log.error("pip-audit 실패: %s", exc)
    return vulns


def scan_npm_deps(project_dir: str = ".") -> list[Vulnerability]:
    """npm audit로 Node.js 의존성 취약점 스캔."""
    vulns: list[Vulnerability] = []
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, check=False, cwd=project_dir
        )
        data = json.loads(result.stdout or "{}")
        vulnerabilities = data.get("vulnerabilities", {})

        for pkg_name, pkg_vuln in vulnerabilities.items():
            severity = pkg_vuln.get("severity", "unknown").capitalize()
            via = pkg_vuln.get("via", [])
            cve = ""
            if via and isinstance(via[0], dict):
                cve = via[0].get("url", "").split("/")[-1]

            vulns.append(Vulnerability(
                package=pkg_name,
                version=pkg_vuln.get("range", ""),
                vuln_id=cve or f"NPMSA-{pkg_name}",
                severity=severity,
                fixed_version=pkg_vuln.get("fixAvailable", {}).get("version"),
                description=str(via[0].get("title", ""))[:200] if via and isinstance(via[0], dict) else "",
                source="npm-audit",
            ))
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        log.error("npm audit 실패: %s", exc)
    return vulns


def scan_container_image(image: str) -> list[Vulnerability]:
    """Trivy로 컨테이너 이미지 취약점 스캔."""
    vulns: list[Vulnerability] = []
    try:
        result = subprocess.run(
            ["trivy", "image", "--format=json", "--quiet", image],
            capture_output=True, text=True, check=False, timeout=300
        )
        data = json.loads(result.stdout or "{}")
        for scan_result in data.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").capitalize()
                if severity in ("Critical", "High", "Medium", "Low"):
                    vulns.append(Vulnerability(
                        package=vuln.get("PkgName", ""),
                        version=vuln.get("InstalledVersion", ""),
                        vuln_id=vuln.get("VulnerabilityID", ""),
                        severity=severity,
                        fixed_version=vuln.get("FixedVersion"),
                        description=vuln.get("Description", "")[:200],
                        source="trivy",
                    ))
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        log.error("Trivy 스캔 실패: %s", exc)
    return vulns


def generate_vuln_report(vulns: list[Vulnerability], output_path: str = "") -> str:
    """취약점 보고서 생성."""
    from collections import Counter
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))

    counts = Counter(v.severity for v in vulns)
    lines = [
        "# 의존성 취약점 스캔 보고서",
        "",
        f"| 위험도 | 건수 |",
        f"|--------|------|",
    ]
    for sev in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    lines += ["", "## 상세 취약점 목록", ""]
    for v in sorted_vulns[:50]:  # 최대 50개
        fix = f" → fix: {v.fixed_version}" if v.fixed_version else ""
        lines.append(f"- [{v.severity}] **{v.vuln_id}** {v.package}@{v.version}{fix}")
        if v.description:
            lines.append(f"  - {v.description[:100]}")

    report = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
    return report
```

---

## 3. 벤더 위험 관리

```python
#!/usr/bin/env python3
"""
서드파티 벤더 위험 평가 자동화.
TPRM (Third-Party Risk Management) 보조 도구.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VendorRisk:
    vendor_name: str
    product: str
    criticality: str  # Critical/High/Medium/Low
    data_access: list[str]  # 접근하는 데이터 유형
    network_access: bool
    code_execution: bool  # 코드 실행 권한 보유 여부
    soc2_certified: bool
    last_audit_date: str
    known_incidents: list[str] = field(default_factory=list)
    risk_score: float = 0.0


def calculate_vendor_risk_score(vendor: VendorRisk) -> float:
    """
    벤더 위험 점수 계산 (0-100, 높을수록 위험).
    TPRM 표준 기반 점수 산출.
    """
    score = 0.0

    # 임계도 기반 기본 점수
    criticality_scores = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10}
    score += criticality_scores.get(vendor.criticality, 20)

    # 데이터 접근 위험도
    sensitive_data_types = {
        "PII", "PHI", "PCI", "credentials", "financial", "IP", "classified"
    }
    data_risk = len(set(vendor.data_access) & sensitive_data_types) * 5
    score += min(data_risk, 20)

    # 네트워크/코드 실행 권한
    if vendor.network_access:
        score += 10
    if vendor.code_execution:
        score += 15

    # 인증서/감사 경감 요소
    if vendor.soc2_certified:
        score -= 10

    # 과거 사고 기록
    score += len(vendor.known_incidents) * 5

    return max(0.0, min(100.0, score))


def generate_vendor_risk_matrix(
    vendors: list[VendorRisk],
    output_path: str = "vendor_risk_matrix.json",
) -> dict:
    """벤더 위험 매트릭스 생성."""
    for vendor in vendors:
        vendor.risk_score = calculate_vendor_risk_score(vendor)

    high_risk = [v for v in vendors if v.risk_score >= 70]
    medium_risk = [v for v in vendors if 40 <= v.risk_score < 70]
    low_risk = [v for v in vendors if v.risk_score < 40]

    matrix = {
        "total_vendors": len(vendors),
        "high_risk_count": len(high_risk),
        "medium_risk_count": len(medium_risk),
        "low_risk_count": len(low_risk),
        "high_risk_vendors": [
            {"name": v.vendor_name, "product": v.product, "score": v.risk_score}
            for v in sorted(high_risk, key=lambda x: -x.risk_score)
        ],
    }

    Path(output_path).write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return matrix


# 의존성 혼동(Dependency Confusion) 공격 탐지
def check_dependency_confusion(
    internal_packages: list[str],
    registries: Optional[list[str]] = None,
) -> list[dict]:
    """
    의존성 혼동 공격 감지.
    내부 패키지 이름이 공개 npm/PyPI에 존재하는지 확인.
    """
    import urllib.request

    if registries is None:
        registries = ["pypi", "npm"]

    findings = []
    for pkg in internal_packages:
        for registry in registries:
            if registry == "pypi":
                url = f"https://pypi.org/pypi/{pkg}/json"
            elif registry == "npm":
                url = f"https://registry.npmjs.org/{pkg}"
            else:
                continue

            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SecurityAudit/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        findings.append({
                            "package": pkg,
                            "registry": registry,
                            "risk": "HIGH",
                            "message": f"내부 패키지 '{pkg}'가 공개 {registry}에 존재 — 의존성 혼동 위험",
                            "recommendation": f"비공개 레지스트리 우선 사용 및 스코프 지정",
                        })
            except Exception:
                pass  # 404 → 안전

    return findings
```

---

## 4. CI/CD 파이프라인 보안

```yaml
# .github/workflows/supply_chain_security.yml
# GitHub Actions 공급망 보안 자동화

name: 공급망 보안 검사

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # 매주 월요일 02:00 정기 스캔

jobs:
  sbom-generation:
    name: SBOM 생성
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: CycloneDX Python SBOM 생성
        run: |
          pip install cyclonedx-bom
          cyclonedx-py environment -o sbom.json --schema-version 1.5

      - name: SBOM 아티팩트 저장
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json

  dependency-scan:
    name: 의존성 취약점 스캔
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: pip-audit 스캔
        run: |
          pip install pip-audit
          pip-audit --format=json -o pip-audit-results.json || true

      - name: Trivy 파일시스템 스캔
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'json'
          output: 'trivy-results.json'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

  secret-scanning:
    name: 하드코딩된 시크릿 스캔
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks 스캔
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  container-scan:
    name: 컨테이너 이미지 취약점 스캔
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4

      - name: 이미지 빌드
        run: docker build -t app:${{ github.sha }} .

      - name: Trivy 이미지 스캔
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-image.sarif'
```

---

## 4.5 빌드 재현성(Reproducible Builds) 검증 자동화

SLSA provenance·서명(18장 참조)이 "이 산출물이 주장하는 파이프라인에서 나왔다"는 것을 증명한다면, 재현 가능한 빌드는 한 걸음 더 나아가 "**같은 소스로 다시 빌드하면 바이트 단위로 동일한 결과가 나온다**"는 것을 제3자가 독립적으로 검증할 수 있게 한다. 빌드 시스템이 침해돼 소스코드는 그대로인데 산출물에만 백도어가 심긴 경우(예: SolarWinds류 공격), provenance 서명만으로는 못 잡아도 재현 빌드 대조로는 즉시 드러난다.

```bash
# 1. 공식 릴리스 아티팩트와 해시 기록
sha256sum official-release-v1.2.3.tar.gz > official.sha256

# 2. 동일 커밋·동일 툴체인 버전으로 독립 환경에서 재빌드
git clone --branch v1.2.3 https://github.com/org/project.git
cd project
docker run --rm -v "$(pwd):/src" -w /src \
  toolchain-pinned:1.2.3 ./build.sh --reproducible

# 3. 재빌드 결과와 공식 릴리스 해시 대조
sha256sum dist/output.tar.gz | diff - official.sha256 && \
  echo "[+] 재현성 검증 통과 — 빌드 파이프라인 무결" || \
  echo "[!] 해시 불일치 — 빌드 조작 또는 비결정적 빌드 의심"
```

```python
#!/usr/bin/env python3
"""여러 독립 빌더의 재현 빌드 결과를 대조해 다수결로 신뢰 여부 판단 (reproducible-builds.org 방식)."""
import hashlib
from collections import Counter
from pathlib import Path


def hash_artifact(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_by_consensus(artifact_paths: list[Path], threshold: int = 2) -> bool:
    """서로 다른 조직/개인이 독립적으로 빌드한 결과물 여러 개를 비교."""
    hashes = [hash_artifact(p) for p in artifact_paths]
    counts = Counter(hashes)
    majority_hash, majority_count = counts.most_common(1)[0]

    print(f"[*] {len(artifact_paths)}개 독립 빌드 중 {majority_count}개가 동일 해시")
    if majority_count >= threshold:
        print(f"[+] 재현성 합의 통과: {majority_hash[:16]}...")
        return True

    print("[!] 재현성 합의 실패 — 빌드 결과가 빌더마다 다름 (비결정적 빌드 또는 조작 의심)")
    return False


if __name__ == "__main__":
    builds = [Path("build_org_a.tar.gz"), Path("build_org_b.tar.gz"), Path("build_official.tar.gz")]
    verify_by_consensus(builds)
```

**한계와 실전 팁**: 완벽한 재현성은 타임스탬프·빌드 경로·파일 순회 순서 같은 비결정적 요소를 전부 고정해야 해서 구현 난이도가 높다 — Debian, Tor Browser, F-Droid 등이 이미 재현 빌드를 실전 운영 중이니 참고할 만하다. 처음부터 완벽을 목표로 하기보다, 먼저 "빌드 결과물의 어느 부분이 비결정적인가"를 `diffoscope` 같은 도구로 찾아내고 단계적으로 고정해나가는 것이 현실적이다.

---

## 5. 참고 자료

- **CycloneDX SBOM 명세**: https://cyclonedx.org/specification/overview/
- **SLSA (Supply-chain Levels for Software Artifacts)**: https://slsa.dev/
- **CISA 공급망 보안 가이드**: https://www.cisa.gov/supply-chain

---

<!-- detect-validate-35 -->
## 공급망 방어 검증 (설정됨 ≠ 작동함)

공급망 방어는 *SBOM·의존성 스캔·벤더 위험 관리·CI 보안*으로 구성된다. "도구를 도입했다"는 설정과 "취약/악성 컴포넌트를 실제로 차단한다"는 다르다 — 각 통제를 소유 빌드에서 검증한다.

### 검증 항목 → 확인 질문 → 측정 신호 → 함정

| 검증 항목 | 확인 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| SBOM | 모든 컴포넌트 망라? | SBOM↔락파일 일치 | 일부 의존성 누락 |
| 의존성 스캔 | 게이트가 막나? | 취약 시 빌드 실패 | 리포트만, 비차단 |
| 서명 검증 | 미서명 거부? | 서명 없으면 배포 거부 | 검증만, 미강제 |
| 벤더 위험 | 신규 의존성 검토? | 신규 메인테이너 알림 | 자동 업데이트 무검토 |

### 방어 검증 (직접 확인)

```bash
# 1) 의존성 스캔이 게이트로 작동하는지(소유 트리) — 취약 발견 시 비0 종료여야 함
trivy fs --exit-code 1 --severity HIGH,CRITICAL . >/dev/null 2>&1; echo "exit=$?  (취약 시 1)"
# 2) SBOM이 락파일을 망라하는지 — SBOM 미포함 의존성이 사각 신호
comm -23 <(jq -r '.packages|keys[]' package-lock.json 2>/dev/null|sort -u) <(jq -r '.components[].name' sbom.json 2>/dev/null|sort -u) | head
```

> 공급망 방어는 *통제가 강제되는가*다 — "SBOM이 있다"와 "SBOM이 모든 의존성을 망라하고 취약 시 빌드가 실패하며 미서명 산출물이 거부된다"는 다르다. 각 통제를 소유 빌드에서 직접 검증한다([[18_DevSecOps]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).

**최신 기법·통제 (2025–2026):**
- in-toto·SLSA·서명 검증·SBOM·admission 정책이 통합 방어 — 검증: 각 통제가 파이프라인에서 강제되는지 재현([[18_DevSecOps]])
- 유출 시크릿 회전·모니터링 — 강제되는지 확인

---

<a name="english"></a>

# Supply Chain Security Defense — SBOM, Dependency Scanning, Vendor Risk Management

## Overview

Supply chain attacks target trusted software/hardware providers instead of attacking the target directly. SolarWinds (2020), Log4Shell (2021), and XZ Utils (2024) are prominent examples.

## Defense Framework

```
SLSA Framework (Supply-chain Levels for Software Artifacts):

  Level 1: Build process documented
  Level 2: Tamper-evident build service
  Level 3: Hardened build environment (no persistent credentials)
  Level 4: Two-person review + reproducible builds
```

## Key Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| cyclonedx-bom | SBOM generation | `pip install cyclonedx-bom` |
| pip-audit | Python vuln scan | `pip install pip-audit` |
| Trivy | Container/FS scan | `brew install trivy` |
| Gitleaks | Secret scanning | `brew install gitleaks` |
| Dependabot | Auto PR for vulns | GitHub built-in |

## Quick Start

```bash
# Generate Python SBOM
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json

# Scan Python dependencies
pip install pip-audit
pip-audit -r requirements.txt

# Scan container image
trivy image myapp:latest --severity CRITICAL,HIGH

# Check for hardcoded secrets
gitleaks detect --source . --report-path gitleaks-report.json

# Check for dependency confusion
python3 dep_confusion_check.py --internal-packages internal_package_list.txt
```

## Reproducible Builds Verification Automation

If SLSA provenance and signing (see chapter 18) proves "this artifact came from the pipeline it claims to," reproducible builds go a step further, letting a third party independently verify that **rebuilding from the same source produces a byte-for-byte identical result**. If the build system is compromised so that a backdoor gets inserted only into the artifact while the source stays clean (a SolarWinds-style attack), provenance signing alone won't catch it — but a reproducible-build comparison exposes it immediately.

```bash
# 1. Record the hash of the official release artifact
sha256sum official-release-v1.2.3.tar.gz > official.sha256

# 2. Rebuild independently from the same commit and toolchain version
git clone --branch v1.2.3 https://github.com/org/project.git
cd project
docker run --rm -v "$(pwd):/src" -w /src \
  toolchain-pinned:1.2.3 ./build.sh --reproducible

# 3. Compare the rebuild's hash against the official release hash
sha256sum dist/output.tar.gz | diff - official.sha256 && \
  echo "[+] Reproducibility check passed -- build pipeline intact" || \
  echo "[!] Hash mismatch -- suspect build tampering or a non-deterministic build"
```

```python
#!/usr/bin/env python3
"""Compare reproduced-build results from multiple independent builders and decide trust by majority vote (the reproducible-builds.org approach)."""
import hashlib
from collections import Counter
from pathlib import Path


def hash_artifact(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_by_consensus(artifact_paths: list[Path], threshold: int = 2) -> bool:
    """Compare multiple build outputs produced independently by different organizations/individuals."""
    hashes = [hash_artifact(p) for p in artifact_paths]
    counts = Counter(hashes)
    majority_hash, majority_count = counts.most_common(1)[0]

    print(f"[*] {majority_count} of {len(artifact_paths)} independent builds share the same hash")
    if majority_count >= threshold:
        print(f"[+] Reproducibility consensus passed: {majority_hash[:16]}...")
        return True

    print("[!] Reproducibility consensus failed -- build results differ between builders (non-deterministic build or tampering suspected)")
    return False


if __name__ == "__main__":
    builds = [Path("build_org_a.tar.gz"), Path("build_org_b.tar.gz"), Path("build_official.tar.gz")]
    verify_by_consensus(builds)
```

**Limitations and practical tips**: achieving perfect reproducibility means pinning down every non-deterministic factor -- timestamps, build paths, file traversal order -- which is genuinely hard; Debian, Tor Browser, and F-Droid already run reproducible builds in production and are worth studying. Rather than aiming for perfection from day one, it's more realistic to first identify which parts of the build output are non-deterministic using a tool like `diffoscope`, then pin them down incrementally.

## References

- CycloneDX: https://cyclonedx.org/specification/overview/
- SLSA: https://slsa.dev/
- CISA Supply Chain: https://www.cisa.gov/supply-chain

<!-- detect-validate-35 -->
## Supply-Chain Defense Validation (Configured != Working)

Supply-chain defense comprises *SBOM, dependency scanning, vendor risk management, and CI security*. "We adopted a tool" differs from "it actually blocks vulnerable/malicious components" -- validate each control on owned builds.

### Validation item -> Question -> Measured signal -> Pitfall

| Validation item | Question | Measured signal | Pitfall |
|---|---|---|---|
| SBOM | All components covered? | SBOM matches lockfile | Some deps missing |
| Dependency scan | Does the gate block? | Build fails on vuln | Report only, non-blocking |
| Signature verify | Unsigned rejected? | Deploy refused without sig | Verify but not enforce |
| Vendor risk | New deps reviewed? | Alert on new maintainer | Auto-update unreviewed |

### Defense validation (verify directly)

```bash
# 1) Whether the dependency scan acts as a gate (owned tree) — should exit non-zero when vulns are found
trivy fs --exit-code 1 --severity HIGH,CRITICAL . >/dev/null 2>&1; echo "exit=$?  (1 when vulnerable)"
# 2) Whether the SBOM covers the lockfile — deps absent from SBOM are a blind spot signal
comm -23 <(jq -r '.packages|keys[]' package-lock.json 2>/dev/null|sort -u) <(jq -r '.components[].name' sbom.json 2>/dev/null|sort -u) | head
```

> Supply-chain defense is *whether controls are enforced* -- "we have an SBOM" differs from "the SBOM covers every dependency, the build fails on a vuln, and unsigned artifacts are rejected". Validate each control on owned builds directly ([[18_DevSecOps]], [[59_Supply_Chain_Security]], [[74_Code_Auditing]]).
