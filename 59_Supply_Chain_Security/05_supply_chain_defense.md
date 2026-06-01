# 공급망 방어 전략 (Supply Chain Defense Strategy)

## 1. 공급망 보안 성숙도 모델

| 성숙도 수준 | 명칭 | 특징 | 주요 역량 | 측정 지표 |
|-------------|------|------|-----------|-----------|
| **수준 0** | 미인지 | 공급망 보안 개념 없음 | 없음 | SBOM 없음, CVE 추적 없음 |
| **수준 1** | 초기 | 반응적 보안 | 수동 취약점 패치, 기본 목록 관리 | 패치 평균 소요 시간 >30일 |
| **수준 2** | 반복 가능 | 프로세스 정의 | 의존성 스캐닝 자동화, 정책 수립 | 패치 소요 <14일, SBOM 생성 |
| **수준 3** | 정의됨 | 조직 전반 표준화 | SBOM 관리, 벤더 평가, CI 통합 | 패치 소요 <7일, SLSA L2 |
| **수준 4** | 측정됨 | 측정 기반 개선 | 공급망 리스크 대시보드, KPI 추적 | 평균 노출 시간(MTET) 측정 |
| **수준 5** | 최적화 | 지속적 혁신 | 재현 가능 빌드, SLSA L3+, 자동화 | MTET <24h, 자동 롤백 |

---

## 2. 공급망 보안 전략 계층

| 계층 | 전략 | 대표 도구/방법 | 비용 | 효과 |
|------|------|----------------|------|------|
| **예방** | 의존성 최소화 | 필수 패키지만 사용, 정기 정리 | 낮음 | 높음 |
| **예방** | 허용 목록 레지스트리 | Artifactory, Nexus 사설 미러 | 중간 | 매우 높음 |
| **예방** | 코드 서명 의무화 | Sigstore, GPG 서명 + CI 검증 | 중간 | 높음 |
| **탐지** | SBOM 기반 CVE 추적 | Dependency-Track, Grype | 중간 | 높음 |
| **탐지** | 런타임 무결성 감시 | Falco, Tetragon, eBPF | 높음 | 매우 높음 |
| **탐지** | 행위 기반 이상 탐지 | ML 기반 이상 탐지 | 높음 | 높음 |
| **대응** | 자동 패치 PR | Dependabot, Renovate | 낮음 | 중간 |
| **대응** | 취약 빌드 자동 차단 | CI 게이트, OPA 정책 | 중간 | 높음 |
| **복구** | 불변 아티팩트 저장 | 아티팩트 버전 관리 + 서명 | 중간 | 중간 |
| **복구** | 롤백 자동화 | GitOps + ArgoCD | 높음 | 높음 |

---

## 3. 벤더/오픈소스 평가 체크리스트

### 3.1 오픈소스 패키지 평가

| 평가 항목 | 기준 | 위험 신호 |
|-----------|------|-----------|
| **유지관리 활성도** | 최근 6개월 내 커밋 | 1년 이상 비활성 |
| **유지관리자 수** | 최소 2인 이상 | 단일 유지관리자 |
| **다운로드 추이** | 안정적 성장 | 갑작스러운 급증 |
| **이슈 대응 시간** | 보안 이슈 72시간 내 반응 | 무응답 |
| **테스트 커버리지** | 80% 이상 | 테스트 없음 |
| **보안 정책** | SECURITY.md 존재 | 보안 연락처 없음 |
| **의존성 수** | 최소화 | 불필요한 의존성 다수 |
| **설치 스크립트** | 없거나 최소화 | postinstall 스크립트 실행 |
| **커밋 서명** | GPG 서명 필수 | 서명되지 않은 커밋 |
| **라이선스** | 알려진 오픈소스 라이선스 | 알 수 없는 라이선스 |

### 3.2 소프트웨어 벤더 평가

| 평가 항목 | 가중치 | 우수 | 보통 | 불량 |
|-----------|--------|------|------|------|
| **보안 개발 수명주기** | 25% | SDL 공식 인증 | 내부 프로세스만 | SDL 없음 |
| **취약점 공개 정책** | 20% | 명확한 CVD + 버그 바운티 | 공개 정책만 | 정책 없음 |
| **SBOM 제공** | 15% | 각 릴리스 SBOM 자동 제공 | 요청 시 제공 | 제공 불가 |
| **침해사고 이력** | 20% | 이력 없음 | 공개 대응 이력 | 대응 없는 이력 |
| **감사 인증** | 10% | SOC2 Type II, ISO 27001 | 자체 감사 | 없음 |
| **업데이트 서명** | 10% | 모든 업데이트 서명 | 일부 서명 | 서명 없음 |

---

## 4. 런타임 무결성 모니터링

### 4.1 eBPF 기반 런타임 감시 항목

| 감시 이벤트 | 탐지 목적 | 도구 |
|-------------|-----------|------|
| **프로세스 실행** | 허가되지 않은 바이너리 실행 탐지 | Falco, Tetragon |
| **파일 시스템 접근** | 중요 파일 변조 탐지 | inotify, eBPF |
| **네트워크 연결** | 예상치 못한 아웃바운드 연결 | Cilium, Tetragon |
| **시스템 콜 필터링** | Seccomp 정책 위반 탐지 | seccomp-bpf |
| **라이브러리 로드** | 알려지지 않은 공유 라이브러리 로드 | LD_PRELOAD 탐지 |
| **환경 변수 접근** | 시크릿 환경 변수 탈취 시도 | eBPF uprobe |

### 4.2 컨테이너 런타임 보안

| 보안 계층 | 도구 | 설정 항목 |
|-----------|------|-----------|
| **이미지 서명** | cosign + Kyverno | 서명된 이미지만 허용 |
| **런타임 정책** | Falco | 이상 행위 규칙 |
| **네트워크 정책** | Cilium/Calico | Egress/Ingress 제한 |
| **비루트 실행** | PodSecurityStandard | runAsNonRoot: true |
| **읽기 전용 루트** | SecurityContext | readOnlyRootFilesystem: true |
| **Capability 제거** | SecurityContext | ALL capabilities drop |

---

## 5. OSV(Open Source Vulnerability) API 개요

| 항목 | 내용 |
|------|------|
| **운영** | Google |
| **URL** | https://api.osv.dev/v1 |
| **인증** | 불필요 (공개 API) |
| **지원 생태계** | PyPI, npm, Maven, NuGet, Go, Rust, Debian, Alpine 등 |
| **쿼리 방식** | 패키지명+버전 또는 commit hash |
| **응답 형식** | JSON |
| **데이터 출처** | GitHub Advisory, NVD, 각 생태계 어드바이저리 |

---

## 6. Python CLI: 공급망 리스크 대시보드

```python
#!/usr/bin/env python3
"""
공급망 리스크 대시보드
기능:
  - requirements.txt / package.json 의존성 CVE 조회 (OSV API)
  - 공급업체 리스크 점수 계산
  - HTML / 마크다운 보고서 생성
  - 임계값 기반 알림
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─────────────────────────── 설정 ───────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "ecosystems": {
        "pip": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "nuget": "NuGet",
        "cargo": "crates.io",
    },
    "severity_weights": {
        "CRITICAL": 10.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 1.0,
        "UNKNOWN": 2.0,
    },
    "alert_threshold": 50.0,
    "request_delay": 0.3,
    "max_retries": 3,
}


# ─────────────────────────── 데이터 클래스 ───────────────────────────

@dataclass
class VulnerabilityInfo:
    """CVE/취약점 정보"""
    vuln_id: str
    summary: str
    severity: str
    cvss_score: float
    affected_versions: list[str] = field(default_factory=list)
    fixed_version: str = ""
    published: str = ""
    aliases: list[str] = field(default_factory=list)


@dataclass
class PackageRisk:
    """패키지별 리스크 정보"""
    name: str
    version: str
    ecosystem: str
    vulnerabilities: list[VulnerabilityInfo] = field(default_factory=list)
    risk_score: float = 0.0
    query_error: str = ""

    def has_critical(self) -> bool:
        return any(v.severity == "CRITICAL" for v in self.vulnerabilities)

    def highest_cvss(self) -> float:
        if not self.vulnerabilities:
            return 0.0
        return max(v.cvss_score for v in self.vulnerabilities)


@dataclass
class SupplierRisk:
    """공급업체 리스크 정보"""
    name: str
    packages: list[PackageRisk] = field(default_factory=list)
    total_score: float = 0.0
    vuln_count: int = 0
    critical_count: int = 0

    def calculate_score(self, weights: dict[str, float]) -> None:
        score = 0.0
        vuln_count = 0
        critical_count = 0
        for pkg in self.packages:
            for vuln in pkg.vulnerabilities:
                w = weights.get(vuln.severity, weights.get("UNKNOWN", 2.0))
                score += w * (1 + vuln.cvss_score / 10.0)
                vuln_count += 1
                if vuln.severity == "CRITICAL":
                    critical_count += 1
        self.total_score = round(score, 2)
        self.vuln_count = vuln_count
        self.critical_count = critical_count


@dataclass
class DashboardData:
    """전체 대시보드 데이터"""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    project_name: str = ""
    total_packages: int = 0
    vulnerable_packages: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_score: float = 0.0
    package_risks: list[PackageRisk] = field(default_factory=list)
    supplier_risks: list[SupplierRisk] = field(default_factory=list)
    alert_triggered: bool = False


# ─────────────────────────── 의존성 로더 ───────────────────────────

def load_packages_from_requirements(
    file_path: Path,
) -> list[tuple[str, str, str]]:
    """
    requirements.txt 로드
    반환: [(name, version, ecosystem), ...]
    """
    import re
    entries: list[tuple[str, str, str]] = []
    comment_re = re.compile(r"#.*$")
    version_re = re.compile(
        r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~^]+\s*([\d\.]+[\w\.\-]*))?.*$"
    )
    try:
        for raw in file_path.read_text(encoding="utf-8").splitlines():
            line = comment_re.sub("", raw).strip()
            if not line or line.startswith(("-", "--")):
                continue
            line = re.sub(r"\[.*?\]", "", line)
            m = version_re.match(line)
            if m:
                entries.append((
                    m.group(1).strip(),
                    (m.group(2) or "").strip(),
                    "PyPI",
                ))
    except OSError as exc:
        print(f"[오류] {file_path}: {exc}", file=sys.stderr)
    return entries


def load_packages_from_package_json(
    file_path: Path,
) -> list[tuple[str, str, str]]:
    """package.json 로드"""
    import re
    entries: list[tuple[str, str, str]] = []
    try:
        data: dict[str, Any] = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[오류] {file_path}: {exc}", file=sys.stderr)
        return entries

    for key in ("dependencies", "devDependencies"):
        for name, ver_range in data.get(key, {}).items():
            version = re.sub(r"[^0-9\.]", "", ver_range).lstrip(".") or ver_range
            entries.append((name, version, "npm"))
    return entries


def detect_and_load(file_path: Path) -> list[tuple[str, str, str]]:
    name = file_path.name.lower()
    if "requirements" in name:
        return load_packages_from_requirements(file_path)
    elif name == "package.json":
        return load_packages_from_package_json(file_path)
    else:
        print(f"[경고] 지원하지 않는 파일: {file_path}", file=sys.stderr)
        return []


# ─────────────────────────── OSV API 클라이언트 ───────────────────────────

class OSVClient:
    """OSV(Open Source Vulnerability) API 클라이언트"""

    QUERY_URL = "https://api.osv.dev/v1/query"
    BATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, delay: float = 0.3, max_retries: int = 3):
        self.delay = delay
        self.max_retries = max_retries

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "supply-chain-dashboard/1.0",
            },
            method="POST",
        )
        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 429:  # 레이트 리밋
                    wait = 2 ** attempt
                    time.sleep(wait)
                    continue
                return None
            except (urllib.error.URLError, json.JSONDecodeError, OSError):
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                    continue
                return None
        return None

    def query_package(self, name: str, version: str, ecosystem: str) -> list[VulnerabilityInfo]:
        """단일 패키지 CVE 조회"""
        payload: dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
        }
        if version:
            payload["version"] = version

        time.sleep(self.delay)
        response = self._post_json(self.QUERY_URL, payload)
        if not response:
            return []

        vulns: list[VulnerabilityInfo] = []
        for vuln_data in response.get("vulns", []):
            vuln = self._parse_vuln(vuln_data)
            vulns.append(vuln)
        return vulns

    def query_batch(
        self, packages: list[tuple[str, str, str]]
    ) -> list[list[VulnerabilityInfo]]:
        """배치 조회 (최대 1000개)"""
        queries = [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                **({"version": version} if version else {}),
            }
            for name, version, ecosystem in packages
        ]
        payload = {"queries": queries}
        time.sleep(self.delay)
        response = self._post_json(self.BATCH_URL, payload)
        if not response:
            return [[] for _ in packages]

        results: list[list[VulnerabilityInfo]] = []
        for result_item in response.get("results", []):
            vulns = [self._parse_vuln(v) for v in result_item.get("vulns", [])]
            results.append(vulns)

        # 결과 수가 부족한 경우 빈 리스트로 채움
        while len(results) < len(packages):
            results.append([])
        return results

    def _parse_vuln(self, data: dict[str, Any]) -> VulnerabilityInfo:
        """OSV 취약점 데이터 파싱"""
        vuln_id = data.get("id", "UNKNOWN")
        summary = data.get("summary", "")
        published = data.get("published", "")
        aliases = data.get("aliases", [])

        # 심각도 파싱
        severity = "UNKNOWN"
        cvss_score = 0.0
        for sev_item in data.get("severity", []):
            sev_type = sev_item.get("type", "")
            sev_score = sev_item.get("score", "")
            if "CVSS" in sev_type:
                # CVSS 벡터에서 점수 추출 시도
                try:
                    # 간단한 점수 추출 (AV:N/AC:L 형태에서 숫자 점수 추출 불가 시 기본값)
                    cvss_score = float(sev_score) if sev_score.replace(".", "").isdigit() else 0.0
                except (ValueError, AttributeError):
                    pass

        # database_specific에서 심각도 파싱
        db_specific = data.get("database_specific", {})
        if "severity" in db_specific:
            severity = db_specific["severity"].upper()

        # ecosystem_specific에서 심각도 파싱
        affected_list = data.get("affected", [])
        fixed_version = ""
        affected_versions: list[str] = []
        for affected in affected_list:
            eco_specific = affected.get("ecosystem_specific", {})
            if "severity" in eco_specific and severity == "UNKNOWN":
                severity = eco_specific["severity"].upper()
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "introduced" in event:
                        affected_versions.append(f">={event['introduced']}")
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        affected_versions.append(f"<{event['fixed']}")

        # CVSS 점수 심각도 매핑 (점수가 있는 경우)
        if cvss_score > 0 and severity == "UNKNOWN":
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        return VulnerabilityInfo(
            vuln_id=vuln_id,
            summary=summary[:200],
            severity=severity,
            cvss_score=cvss_score,
            affected_versions=affected_versions[:5],
            fixed_version=fixed_version,
            published=published,
            aliases=[a for a in aliases if a.startswith("CVE-")][:3],
        )


# ─────────────────────────── 대시보드 생성기 ───────────────────────────

class RiskDashboard:
    """공급망 리스크 대시보드"""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        alert_threshold: float | None = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.weights: dict[str, float] = self.config["severity_weights"]
        self.alert_threshold = alert_threshold or self.config["alert_threshold"]
        self.osv = OSVClient(
            delay=self.config.get("request_delay", 0.3),
            max_retries=self.config.get("max_retries", 3),
        )

    def build_dashboard(
        self,
        packages: list[tuple[str, str, str]],
        project_name: str = "project",
        use_batch: bool = True,
    ) -> DashboardData:
        dashboard = DashboardData(project_name=project_name)
        dashboard.total_packages = len(packages)

        print(f"[시작] {len(packages)}개 패키지 CVE 조회 중...", file=sys.stderr)

        if use_batch and len(packages) <= 1000:
            all_vulns = self.osv.query_batch(packages)
        else:
            all_vulns = []
            for i, (name, version, eco) in enumerate(packages, 1):
                print(f"  [{i:3d}/{len(packages)}] {name}", end="\r", file=sys.stderr)
                vulns = self.osv.query_package(name, version, eco)
                all_vulns.append(vulns)
            print(file=sys.stderr)

        # 패키지별 리스크 계산
        for (name, version, eco), vulns in zip(packages, all_vulns):
            pkg_risk = PackageRisk(name=name, version=version, ecosystem=eco, vulnerabilities=vulns)
            # 리스크 점수 계산
            score = 0.0
            for v in vulns:
                w = self.weights.get(v.severity, self.weights.get("UNKNOWN", 2.0))
                score += w * (1 + v.cvss_score / 10.0)
            pkg_risk.risk_score = round(score, 2)
            dashboard.package_risks.append(pkg_risk)

        # 전체 통계 집계
        self._aggregate_stats(dashboard)

        # 알림 임계값 확인
        dashboard.alert_triggered = dashboard.overall_risk_score >= self.alert_threshold

        return dashboard

    def _aggregate_stats(self, dashboard: DashboardData) -> None:
        total_score = 0.0
        for pkg in dashboard.package_risks:
            if pkg.vulnerabilities:
                dashboard.vulnerable_packages += 1
            for v in pkg.vulnerabilities:
                dashboard.total_vulnerabilities += 1
                total_score += self.weights.get(v.severity, 2.0)
                sev = v.severity
                if sev == "CRITICAL":
                    dashboard.critical_count += 1
                elif sev == "HIGH":
                    dashboard.high_count += 1
                elif sev == "MEDIUM":
                    dashboard.medium_count += 1
                elif sev == "LOW":
                    dashboard.low_count += 1

        dashboard.overall_risk_score = round(total_score, 2)


# ─────────────────────────── 보고서 포맷터 ───────────────────────────

class MarkdownFormatter:
    """마크다운 보고서 생성"""

    def format(self, data: DashboardData) -> str:
        lines: list[str] = [
            f"# 공급망 리스크 대시보드: {data.project_name}",
            f"",
            f"생성 시각: {data.generated_at}",
            f"",
            f"## 요약",
            f"",
            f"| 항목 | 값 |",
            f"|------|-----|",
            f"| 전체 패키지 수 | {data.total_packages} |",
            f"| 취약 패키지 수 | {data.vulnerable_packages} |",
            f"| 전체 취약점 수 | {data.total_vulnerabilities} |",
            f"| 긴급(CRITICAL) | {data.critical_count} |",
            f"| 높음(HIGH) | {data.high_count} |",
            f"| 중간(MEDIUM) | {data.medium_count} |",
            f"| 낮음(LOW) | {data.low_count} |",
            f"| 리스크 점수 | {data.overall_risk_score} |",
            f"| 알림 발동 | {'**예**' if data.alert_triggered else '아니오'} |",
            f"",
        ]

        if data.alert_triggered:
            lines += [
                f"> **[경고]** 리스크 점수({data.overall_risk_score})가 임계값을 초과했습니다.",
                f"",
            ]

        # 취약 패키지 목록
        vulnerable = [p for p in data.package_risks if p.vulnerabilities]
        if vulnerable:
            lines += [
                f"## 취약 패키지 목록",
                f"",
                f"| 패키지 | 버전 | 취약점 수 | 최고 CVSS | 리스크 점수 |",
                f"|--------|------|-----------|-----------|-------------|",
            ]
            for pkg in sorted(vulnerable, key=lambda p: p.risk_score, reverse=True):
                lines.append(
                    f"| {pkg.name} | {pkg.version} | "
                    f"{len(pkg.vulnerabilities)} | "
                    f"{pkg.highest_cvss():.1f} | "
                    f"{pkg.risk_score:.2f} |"
                )
            lines.append("")

            # 상위 취약점 상세
            lines += ["## 주요 취약점 상세", ""]
            shown = 0
            for pkg in sorted(vulnerable, key=lambda p: p.risk_score, reverse=True):
                if shown >= 10:
                    break
                for vuln in sorted(
                    pkg.vulnerabilities,
                    key=lambda v: v.cvss_score,
                    reverse=True,
                )[:3]:
                    cve_refs = ", ".join(vuln.aliases) or vuln.vuln_id
                    lines += [
                        f"### {vuln.vuln_id} ({pkg.name})",
                        f"",
                        f"- **심각도**: {vuln.severity}",
                        f"- **CVSS**: {vuln.cvss_score}",
                        f"- **참조**: {cve_refs}",
                        f"- **요약**: {vuln.summary}",
                        f"- **수정 버전**: {vuln.fixed_version or '미공개'}",
                        f"",
                    ]
                    shown += 1

        return "\n".join(lines)


class HTMLFormatter:
    """HTML 보고서 생성"""

    SEVERITY_CLASS = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "UNKNOWN": "unknown",
    }

    def format(self, data: DashboardData) -> str:
        alert_banner = ""
        if data.alert_triggered:
            alert_banner = (
                f'<div class="alert">'
                f'경고: 리스크 점수({data.overall_risk_score})가 임계값을 초과했습니다!'
                f'</div>'
            )

        vuln_rows = ""
        for pkg in sorted(
            [p for p in data.package_risks if p.vulnerabilities],
            key=lambda p: p.risk_score,
            reverse=True,
        ):
            for vuln in pkg.vulnerabilities[:5]:
                sev_cls = self.SEVERITY_CLASS.get(vuln.severity, "unknown")
                cve = ", ".join(vuln.aliases) or vuln.vuln_id
                vuln_rows += (
                    f"<tr>"
                    f"<td>{pkg.name}</td>"
                    f"<td>{pkg.version}</td>"
                    f'<td><span class="badge {sev_cls}">{vuln.severity}</span></td>'
                    f"<td>{vuln.cvss_score:.1f}</td>"
                    f"<td>{cve}</td>"
                    f"<td>{vuln.summary[:80]}...</td>"
                    f"<td>{vuln.fixed_version or 'N/A'}</td>"
                    f"</tr>\n"
                )

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>공급망 리스크 대시보드 - {data.project_name}</title>
  <style>
    body {{ font-family: 'Nanum Gothic', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
    h1 {{ color: #333; }}
    .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }}
    .card {{ background: white; border-radius: 8px; padding: 16px 24px;
             box-shadow: 0 2px 4px rgba(0,0,0,.1); min-width: 140px; text-align: center; }}
    .card .value {{ font-size: 2em; font-weight: bold; color: #333; }}
    .card .label {{ color: #666; font-size: 0.9em; }}
    .alert {{ background: #fee; border-left: 4px solid #c00; padding: 12px 16px;
              margin: 16px 0; color: #900; border-radius: 4px; }}
    table {{ border-collapse: collapse; width: 100%; background: white;
             border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,.1); }}
    th {{ background: #444; color: white; padding: 10px 12px; text-align: left; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
    tr:hover {{ background: #f9f9f9; }}
    .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
    .critical {{ background: #fee; color: #c00; }}
    .high {{ background: #fff3cd; color: #856404; }}
    .medium {{ background: #cce5ff; color: #004085; }}
    .low {{ background: #d4edda; color: #155724; }}
    .unknown {{ background: #e2e3e5; color: #383d41; }}
    .meta {{ color: #666; font-size: 0.85em; margin-bottom: 16px; }}
  </style>
</head>
<body>
  <h1>공급망 리스크 대시보드</h1>
  <p class="meta">프로젝트: {data.project_name} | 생성: {data.generated_at}</p>
  {alert_banner}
  <div class="summary">
    <div class="card"><div class="value">{data.total_packages}</div><div class="label">전체 패키지</div></div>
    <div class="card"><div class="value" style="color:#c00">{data.vulnerable_packages}</div><div class="label">취약 패키지</div></div>
    <div class="card"><div class="value">{data.total_vulnerabilities}</div><div class="label">총 취약점</div></div>
    <div class="card"><div class="value" style="color:#c00">{data.critical_count}</div><div class="label">CRITICAL</div></div>
    <div class="card"><div class="value" style="color:#856404">{data.high_count}</div><div class="label">HIGH</div></div>
    <div class="card"><div class="value" style="color:#004085">{data.medium_count}</div><div class="label">MEDIUM</div></div>
    <div class="card"><div class="value">{data.overall_risk_score:.1f}</div><div class="label">리스크 점수</div></div>
  </div>
  <h2>취약점 상세</h2>
  <table>
    <thead>
      <tr>
        <th>패키지</th><th>버전</th><th>심각도</th>
        <th>CVSS</th><th>CVE</th><th>요약</th><th>수정 버전</th>
      </tr>
    </thead>
    <tbody>
      {vuln_rows or '<tr><td colspan="7" style="text-align:center">취약점 없음</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


# ─────────────────────────── CLI ───────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supply-chain-dashboard",
        description="공급망 리스크 대시보드 생성기 (OSV API 활용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 05_supply_chain_defense.py --config requirements.txt
  python3 05_supply_chain_defense.py --config requirements.txt \\
      --output-format html --output dashboard.html
  python3 05_supply_chain_defense.py --config package.json \\
      --alert-threshold 30 --output-format markdown
        """,
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        metavar="FILE",
        help="의존성 파일 (requirements.txt 또는 package.json)",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "markdown", "html"],
        default="markdown",
        metavar="FORMAT",
        help="출력 형식 (json | markdown | html, 기본값: markdown)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="출력 파일 경로 (미지정 시 표준 출력)",
    )
    parser.add_argument(
        "--alert-threshold",
        type=float,
        default=50.0,
        metavar="SCORE",
        help="알림 발동 리스크 점수 임계값 (기본값: 50.0)",
    )
    parser.add_argument(
        "--project-name",
        type=str,
        default=None,
        metavar="NAME",
        help="프로젝트 이름 (기본값: 파일명)",
    )
    parser.add_argument(
        "--max-packages",
        type=int,
        default=None,
        metavar="N",
        help="최대 검사 패키지 수 (테스트용)",
    )
    parser.add_argument(
        "--no-batch",
        action="store_true",
        help="배치 API 사용 안 함 (개별 요청)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config_file: Path = args.config.resolve()
    if not config_file.exists():
        print(f"[오류] 파일이 존재하지 않습니다: {config_file}", file=sys.stderr)
        return 1

    packages = detect_and_load(config_file)
    if not packages:
        print("[오류] 패키지를 로드하지 못했습니다.", file=sys.stderr)
        return 1

    if args.max_packages:
        packages = packages[: args.max_packages]

    project_name = args.project_name or config_file.stem

    dashboard = RiskDashboard(alert_threshold=args.alert_threshold)
    data = dashboard.build_dashboard(
        packages=packages,
        project_name=project_name,
        use_batch=not args.no_batch,
    )

    # 보고서 생성
    if args.output_format == "json":
        output_text = json.dumps(
            {
                "generated_at": data.generated_at,
                "project": data.project_name,
                "summary": {
                    "total_packages": data.total_packages,
                    "vulnerable_packages": data.vulnerable_packages,
                    "total_vulnerabilities": data.total_vulnerabilities,
                    "critical": data.critical_count,
                    "high": data.high_count,
                    "medium": data.medium_count,
                    "low": data.low_count,
                    "risk_score": data.overall_risk_score,
                    "alert_triggered": data.alert_triggered,
                },
                "packages": [
                    {
                        "name": p.name,
                        "version": p.version,
                        "ecosystem": p.ecosystem,
                        "risk_score": p.risk_score,
                        "vulnerabilities": [
                            {
                                "id": v.vuln_id,
                                "severity": v.severity,
                                "cvss": v.cvss_score,
                                "summary": v.summary,
                                "fixed": v.fixed_version,
                                "cves": v.aliases,
                            }
                            for v in p.vulnerabilities
                        ],
                    }
                    for p in data.package_risks
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    elif args.output_format == "html":
        output_text = HTMLFormatter().format(data)
    else:
        output_text = MarkdownFormatter().format(data)

    if args.output:
        try:
            args.output.write_text(output_text, encoding="utf-8")
            print(f"[완료] 보고서 저장: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[오류] 저장 실패: {exc}", file=sys.stderr)
            return 1
    else:
        print(output_text)

    # 콘솔 요약
    print(f"\n[요약] 패키지: {data.total_packages}, "
          f"취약: {data.vulnerable_packages}, "
          f"CVE: {data.total_vulnerabilities}, "
          f"점수: {data.overall_risk_score:.1f}",
          file=sys.stderr)

    if data.alert_triggered:
        print(f"[경고] 리스크 점수 임계값 초과 ({data.overall_risk_score} >= {args.alert_threshold})",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 공급망 보안 KPI 및 측정 지표

| KPI | 정의 | 목표값 | 측정 주기 |
|-----|------|--------|-----------|
| **MTET** (평균 노출 시간) | CVE 공개 → 패치 완료까지 평균 시간 | <7일 (Critical) | 월간 |
| **SBOM 커버리지** | SBOM 생성 파이프라인 적용 비율 | >95% | 분기 |
| **의존성 최신화율** | 최신 버전 사용 중인 의존성 비율 | >80% | 월간 |
| **서명 적용률** | 서명된 릴리스 아티팩트 비율 | 100% | 릴리스마다 |
| **취약 패키지 밀도** | 1,000 의존성당 CRITICAL CVE 수 | <5 | 주간 |
| **공급업체 리스크 점수** | 3rd party 평균 리스크 점수 | <30 | 분기 |
| **CI 게이트 통과율** | 보안 게이트 통과한 빌드 비율 | >98% | 주간 |
| **Provenance 생성율** | SLSA Provenance 포함 릴리스 비율 | 100% | 릴리스마다 |

---

## 8. 공급망 보안 정책 템플릿

| 정책 항목 | 요구사항 | 예외 처리 |
|-----------|----------|-----------|
| **신규 의존성 추가** | 보안팀 검토 필수, SBOM 자동 업데이트 | 긴급 패치는 사후 검토 허용 |
| **CRITICAL CVE 패치** | 발견 후 72시간 내 패치 | 패치 불가 시 임시 완화 조치 |
| **HIGH CVE 패치** | 발견 후 7일 내 패치 | 비즈니스 영향 고려 연장 가능 |
| **의존성 버전 고정** | 정확한 버전 + 해시 고정 필수 | 개발 환경 제외 |
| **코드 서명** | 모든 프로덕션 릴리스 서명 필수 | 내부 개발 빌드 제외 |
| **벤더 평가** | 신규 벤더 도입 시 공급망 보안 평가 | 평가 완료 전 PoC 허용 |
| **사고 대응** | 공급망 침해 의심 시 즉시 격리 | 자동화된 격리 트리거 구성 |

---

<a name="english"></a>

# Supply Chain Defense Strategy

## 1. Supply Chain Security Maturity Model

| Maturity Level | Name | Characteristics | Key Capabilities | Metrics |
|----------------|------|-----------------|------------------|---------|
| **Level 0** | Unaware | No supply chain security concept | None | No SBOM, no CVE tracking |
| **Level 1** | Initial | Reactive security | Manual vulnerability patching, basic inventory | Patch time >30 days |
| **Level 2** | Repeatable | Defined processes | Automated dependency scanning, policy establishment | Patch time <14 days, SBOM generation |
| **Level 3** | Defined | Organization-wide standardization | SBOM management, vendor evaluation, CI integration | Patch time <7 days, SLSA L2 |
| **Level 4** | Measured | Measurement-based improvement | Supply chain risk dashboard, KPI tracking | MTET measurement |
| **Level 5** | Optimized | Continuous innovation | Reproducible builds, SLSA L3+, automation | MTET <24h, auto-rollback |

---

## 2. Supply Chain Security Strategy Layers

| Layer | Strategy | Representative Tools/Methods | Cost | Effect |
|-------|----------|------------------------------|------|--------|
| **Prevention** | Minimize dependencies | Use only essential packages, regular cleanup | Low | High |
| **Prevention** | Allowlist registry | Artifactory, Nexus private mirrors | Medium | Very High |
| **Prevention** | Mandatory code signing | Sigstore, GPG signing + CI verification | Medium | High |
| **Detection** | SBOM-based CVE tracking | Dependency-Track, Grype | Medium | High |
| **Detection** | Runtime integrity monitoring | Falco, Tetragon, eBPF | High | Very High |
| **Detection** | Behavior-based anomaly detection | ML-based anomaly detection | High | High |
| **Response** | Automated patch PRs | Dependabot, Renovate | Low | Medium |
| **Response** | Automatic blocking of vulnerable builds | CI gate, OPA policy | Medium | High |
| **Recovery** | Immutable artifact storage | Artifact versioning + signing | Medium | Medium |
| **Recovery** | Rollback automation | GitOps + ArgoCD | High | High |

---

## 3. Vendor/Open Source Evaluation Checklist

### 3.1 Open Source Package Evaluation

| Evaluation Item | Criteria | Red Flags |
|-----------------|----------|-----------|
| **Maintenance activity** | Commits within last 6 months | Inactive for 1+ year |
| **Number of maintainers** | At least 2 | Single maintainer |
| **Download trend** | Stable growth | Sudden spike |
| **Issue response time** | Response to security issues within 72 hours | No response |
| **Test coverage** | 80%+ | No tests |
| **Security policy** | SECURITY.md present | No security contact |
| **Number of dependencies** | Minimized | Many unnecessary dependencies |
| **Install scripts** | None or minimal | postinstall script execution |
| **Commit signing** | GPG signing required | Unsigned commits |
| **License** | Known open source license | Unknown license |

### 3.2 Software Vendor Evaluation

| Evaluation Item | Weight | Excellent | Average | Poor |
|-----------------|--------|-----------|---------|------|
| **Secure Development Lifecycle** | 25% | Official SDL certification | Internal process only | No SDL |
| **Vulnerability disclosure policy** | 20% | Clear CVD + bug bounty | Disclosure policy only | No policy |
| **SBOM provision** | 15% | Automatic SBOM per release | Provided on request | Cannot provide |
| **Incident history** | 20% | No history | Public response history | History with no response |
| **Audit certification** | 10% | SOC2 Type II, ISO 27001 | Self-audit | None |
| **Update signing** | 10% | All updates signed | Some signed | No signing |

---

## 4. Runtime Integrity Monitoring

### 4.1 eBPF-based Runtime Monitoring Events

| Monitored Event | Detection Purpose | Tool |
|-----------------|------------------|-------|
| **Process execution** | Detect unauthorized binary execution | Falco, Tetragon |
| **Filesystem access** | Detect critical file tampering | inotify, eBPF |
| **Network connections** | Detect unexpected outbound connections | Cilium, Tetragon |
| **Syscall filtering** | Detect seccomp policy violations | seccomp-bpf |
| **Library loading** | Detect unknown shared library loading | LD_PRELOAD detection |
| **Environment variable access** | Detect secret environment variable theft attempts | eBPF uprobe |

### 4.2 Container Runtime Security

| Security Layer | Tool | Configuration |
|----------------|------|---------------|
| **Image signing** | cosign + Kyverno | Allow signed images only |
| **Runtime policy** | Falco | Anomalous behavior rules |
| **Network policy** | Cilium/Calico | Egress/Ingress restrictions |
| **Non-root execution** | PodSecurityStandard | runAsNonRoot: true |
| **Read-only root** | SecurityContext | readOnlyRootFilesystem: true |
| **Capability removal** | SecurityContext | Drop ALL capabilities |

---

## 5. OSV (Open Source Vulnerability) API Overview

| Item | Content |
|------|---------|
| **Operated by** | Google |
| **URL** | https://api.osv.dev/v1 |
| **Authentication** | Not required (public API) |
| **Supported ecosystems** | PyPI, npm, Maven, NuGet, Go, Rust, Debian, Alpine, etc. |
| **Query method** | Package name + version, or commit hash |
| **Response format** | JSON |
| **Data sources** | GitHub Advisory, NVD, ecosystem advisories |

---

## 6. Python CLI: Supply Chain Risk Dashboard

(See code block above)

---

## 7. Supply Chain Security KPIs and Metrics

| KPI | Definition | Target | Measurement Period |
|-----|------------|--------|-------------------|
| **MTET** (Mean Time to Exposure) | Average time from CVE disclosure to patch completion | <7 days (Critical) | Monthly |
| **SBOM coverage** | Ratio of pipelines with SBOM generation applied | >95% | Quarterly |
| **Dependency freshness rate** | Ratio of dependencies using latest versions | >80% | Monthly |
| **Signing adoption rate** | Ratio of signed release artifacts | 100% | Per release |
| **Vulnerable package density** | CRITICAL CVEs per 1,000 dependencies | <5 | Weekly |
| **Vendor risk score** | Average risk score for 3rd party dependencies | <30 | Quarterly |
| **CI gate pass rate** | Ratio of builds passing security gate | >98% | Weekly |
| **Provenance generation rate** | Ratio of releases including SLSA Provenance | 100% | Per release |

---

## 8. Supply Chain Security Policy Template

| Policy Item | Requirement | Exception Handling |
|-------------|-------------|-------------------|
| **Adding new dependencies** | Security team review required, automatic SBOM update | Post-review allowed for emergency patches |
| **CRITICAL CVE patching** | Patch within 72 hours of discovery | Temporary mitigation if patching is not possible |
| **HIGH CVE patching** | Patch within 7 days of discovery | Extension possible considering business impact |
| **Dependency version pinning** | Exact version + hash pinning required | Except development environments |
| **Code signing** | Signing required for all production releases | Except internal development builds |
| **Vendor evaluation** | Supply chain security evaluation when introducing new vendors | PoC allowed before evaluation completion |
| **Incident response** | Immediately isolate if supply chain compromise is suspected | Configure automated isolation triggers |
