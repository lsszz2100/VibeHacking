# 소프트웨어 공급망 보안 기초

## 1. 소프트웨어 공급망이란

소프트웨어 공급망(Software Supply Chain)은 코드 작성부터 최종 사용자 배포까지의 전체 프로세스를 의미합니다.
오픈소스 라이브러리, 빌드 도구, CI/CD 파이프라인, 배포 인프라, 업데이트 메커니즘이 모두 포함됩니다.
공격자는 이 체인의 어느 지점에든 침투하여 신뢰된 소프트웨어에 악성 코드를 삽입할 수 있습니다.

---

## 2. 공급망 공격 분류 표

| 공격 단계 | 공격 유형 | 대표 사례 | 영향 범위 | 탐지 난이도 |
|-----------|-----------|-----------|-----------|-------------|
| **소스코드** | 오픈소스 패키지 악성 코드 삽입 | event-stream, XZ Utils | 해당 패키지 사용자 전체 | 높음 |
| **소스코드** | 타이포스쿼팅 | colourama vs colorama | 실수로 설치한 사용자 | 중간 |
| **소스코드** | 의존성 혼란 | Alex Birsan 연구 (2021) | 내부 패키지명 사용 기업 | 높음 |
| **소스코드** | 계정 탈취 | ua-parser-js (npm) | 수백만 다운로드 패키지 | 매우 높음 |
| **빌드** | 빌드 서버 침해 | SolarWinds SUNBURST | 18,000개 이상 조직 | 매우 높음 |
| **빌드** | 컴파일러 백도어 | Ken Thompson의 Trusting Trust | 모든 컴파일된 소프트웨어 | 극히 높음 |
| **빌드** | CI/CD 파이프라인 공격 | Codecov bash uploader | CI 환경 변수 탈취 | 높음 |
| **빌드** | 아티팩트 위변조 | 체크섬 우회 | 배포 전 단계 | 중간 |
| **배포** | 패키지 레지스트리 침해 | PyPI 악성 패키지 | 해당 패키지 다운로드 사용자 | 중간 |
| **배포** | CDN/미러 서버 공격 | 패키지 미러 침해 | 미러 사용자 | 높음 |
| **배포** | 서명 키 탈취 | 코드서명 인증서 도용 | 서명 검증 우회 | 높음 |
| **업데이트** | 자동 업데이트 메커니즘 악용 | NotPetya (M.E.Doc) | 우크라이나 기업 | 높음 |
| **업데이트** | 롤백 공격 | 구버전 취약점 재활용 | 업데이트 시스템 | 중간 |
| **업데이트** | 중간자 공격 | TLS 우회 업데이트 | 암호화 미적용 시스템 | 낮음 |

---

## 3. SLSA 프레임워크 레벨

SLSA(Supply chain Levels for Software Artifacts)는 Google이 제안한 공급망 보안 프레임워크입니다.
소프트웨어 아티팩트의 무결성을 보장하기 위한 단계적 보안 요구사항을 정의합니다.

| SLSA 레벨 | 명칭 | 핵심 요구사항 | 주요 보호 대상 | 달성 난이도 |
|-----------|------|---------------|----------------|-------------|
| **Level 0** | 없음 | SLSA 미적용 | 없음 | N/A |
| **Level 1** | 문서화 | 빌드 프로세스 완전 자동화, Provenance 생성 | 실수에 의한 변조 | 낮음 |
| **Level 2** | 검증됨 | 검증된 호스팅 빌드 서비스, 서명된 Provenance | 단일 내부자 위협 | 중간 |
| **Level 3** | 강화됨 | 강화된 빌드 환경, 비변경 Provenance | 복잡한 내부자 위협 | 높음 |
| **Level 4** | 최고 강화** | 두 사람 검토 필수, 밀폐형 재현 빌드 | 고도화된 공급망 공격 | 매우 높음 |

> **참고**: SLSA v1.0부터 Level 4는 별도의 트랙으로 재편되었습니다.

### 3.1 SLSA Provenance 필수 요소

| 요소 | 설명 | 예시 |
|------|------|------|
| `buildType` | 빌드 시스템 식별자 | `https://github.com/slsa-framework/slsa-github-generator` |
| `builder.id` | 빌드 수행자 URI | 검증된 CI/CD 서비스 ID |
| `invocation.configSource` | 빌드 설정 출처 | 특정 커밋의 `.github/workflows/release.yml` |
| `materials` | 입력 아티팩트 목록 | 소스 코드 해시, 의존성 해시 |
| `buildStartedOn` | 빌드 시작 타임스탬프 | ISO 8601 형식 |
| `completeness` | Provenance 완전성 표시 | parameters, environment, materials |

---

## 4. 공급망 위협 행위자 분류

| 행위자 유형 | 목적 | 기술 수준 | 대표 사례 | 주요 TTPs |
|-------------|------|-----------|-----------|-----------|
| **국가급 APT** | 정보 수집, 사보타지 | 최고 | Lazarus Group, APT29 | 빌드 시스템 침해, 장기 잠복 |
| **사이버 범죄 조직** | 금전적 이익 | 높음 | Cl0p, LockBit 관련 그룹 | 랜섬웨어 배포, 자격증명 탈취 |
| **핵티비스트** | 정치적 메시지 전달 | 중간 | Anonymous 관련 그룹 | 웹사이트 변조, DDoS |
| **내부자** | 개인적 이익/불만 | 가변적 | 퇴직 직원, 불만 직원 | 소스코드 유출, 백도어 삽입 |
| **악의적 오픈소스 기여자** | 다양함 | 중간~높음 | XZ Utils 공격자 | 신뢰 구축 후 악성 코드 삽입 |
| **연구자** | 취약점 발견/공개 | 높음 | Alex Birsan | 의존성 혼란 PoC |

---

## 5. SBOM(Software Bill of Materials) 개요

SBOM은 소프트웨어에 포함된 모든 구성요소의 목록입니다.
식품의 성분표와 같이 소프트웨어의 모든 라이브러리, 버전, 라이선스 정보를 기록합니다.

### 5.1 주요 SBOM 표준

| 표준 | 운영 기관 | 형식 | 주요 특징 |
|------|-----------|------|-----------|
| **SPDX** | Linux Foundation | JSON, YAML, RDF, TV | ISO 표준(ISO/IEC 5962:2021), 라이선스 중심 |
| **CycloneDX** | OWASP | JSON, XML | 보안 중심, VEX 지원 |
| **SWID** | ISO/IEC | XML | 엔터프라이즈 자산 관리 중심 |

---

## 6. Python CLI: SBOM 생성기

```python
#!/usr/bin/env python3
"""
SBOM(Software Bill of Materials) 생성기
지원 형식: SPDX, CycloneDX, JSON
지원 파일: requirements.txt, package.json, pom.xml
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─────────────────────────── 데이터 클래스 ───────────────────────────

@dataclass
class Component:
    """소프트웨어 구성 요소"""
    name: str
    version: str
    package_manager: str           # pip, npm, maven
    license_info: str = "NOASSERTION"
    purl: str = ""                 # Package URL
    checksum_sha256: str = ""
    homepage: str = ""
    description: str = ""
    dependencies: list[str] = field(default_factory=list)

    def to_purl(self) -> str:
        """Package URL 생성"""
        pm_map = {
            "pip": "pypi",
            "npm": "npm",
            "maven": "maven",
        }
        pkg_type = pm_map.get(self.package_manager, self.package_manager)
        return f"pkg:{pkg_type}/{self.name}@{self.version}"


@dataclass
class SBOMDocument:
    """SBOM 문서"""
    document_name: str
    document_namespace: str
    spdx_version: str = "SPDX-2.3"
    data_license: str = "CC0-1.0"
    created: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    components: list[Component] = field(default_factory=list)
    project_path: Path = field(default_factory=Path)


# ─────────────────────────── 파서 ───────────────────────────

class RequirementsTxtParser:
    """requirements.txt 파싱"""

    COMMENT_RE = re.compile(r"#.*$")
    VERSION_SPEC_RE = re.compile(
        r"^([A-Za-z0-9_\-\.]+)\s*([><=!~^]+\s*[\d\.]+[\w\.\-\*]*)?.*$"
    )
    EXTRAS_RE = re.compile(r"\[.*?\]")

    def parse(self, file_path: Path) -> list[Component]:
        components: list[Component] = []
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[오류] {file_path} 읽기 실패: {exc}", file=sys.stderr)
            return components

        for raw_line in text.splitlines():
            line = self.COMMENT_RE.sub("", raw_line).strip()
            if not line or line.startswith(("-r", "-c", "--")):
                continue
            line = self.EXTRAS_RE.sub("", line)
            m = self.VERSION_SPEC_RE.match(line)
            if not m:
                continue
            name = m.group(1).strip()
            version_spec = (m.group(2) or "").strip()
            version = re.sub(r"[><=!~^]", "", version_spec).strip() or "unknown"
            comp = Component(
                name=name,
                version=version,
                package_manager="pip",
            )
            comp.purl = comp.to_purl()
            components.append(comp)
        return components


class PackageJsonParser:
    """package.json 파싱"""

    def parse(self, file_path: Path) -> list[Component]:
        components: list[Component] = []
        try:
            data: dict[str, Any] = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[오류] {file_path} 파싱 실패: {exc}", file=sys.stderr)
            return components

        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            all_deps.update(data.get(key, {}))

        for name, version_range in all_deps.items():
            version = re.sub(r"[^0-9\.]", "", version_range) or version_range
            comp = Component(
                name=name,
                version=version,
                package_manager="npm",
            )
            comp.purl = comp.to_purl()
            components.append(comp)
        return components


class PomXmlParser:
    """pom.xml 파싱 (Maven)"""

    NS = {"mvn": "http://maven.apache.org/POM/4.0.0"}

    def parse(self, file_path: Path) -> list[Component]:
        components: list[Component] = []
        try:
            tree = ET.parse(file_path)
        except (OSError, ET.ParseError) as exc:
            print(f"[오류] {file_path} 파싱 실패: {exc}", file=sys.stderr)
            return components

        root = tree.getroot()
        # namespace 자동 감지
        ns_match = re.match(r"\{(.*?)\}", root.tag)
        ns = {"mvn": ns_match.group(1)} if ns_match else {}
        tag = lambda t: f"mvn:{t}" if ns else t  # noqa: E731

        deps_elem = root.find(f".//{tag('dependencies')}", ns)
        if deps_elem is None:
            return components

        for dep in deps_elem.findall(tag("dependency"), ns):
            group_id_elem = dep.find(tag("groupId"), ns)
            artifact_elem = dep.find(tag("artifactId"), ns)
            version_elem = dep.find(tag("version"), ns)

            group_id = group_id_elem.text.strip() if group_id_elem is not None else ""
            artifact_id = artifact_elem.text.strip() if artifact_elem is not None else ""
            version = version_elem.text.strip() if version_elem is not None else "unknown"

            if not artifact_id:
                continue

            name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            comp = Component(
                name=name,
                version=version,
                package_manager="maven",
            )
            comp.purl = comp.to_purl()
            components.append(comp)
        return components


# ─────────────────────────── SBOM 생성기 ───────────────────────────

class SBOMGenerator:
    """SBOM 생성기 메인 클래스"""

    PARSERS = {
        "requirements.txt": RequirementsTxtParser,
        "package.json": PackageJsonParser,
        "pom.xml": PomXmlParser,
    }

    def __init__(self, project_path: Path):
        self.project_path = project_path

    def discover_manifest_files(self) -> list[tuple[str, Path]]:
        """프로젝트 내 의존성 매니페스트 파일 탐색"""
        found: list[tuple[str, Path]] = []
        for manifest_name in self.PARSERS:
            for manifest_path in self.project_path.rglob(manifest_name):
                # node_modules, .git 등 제외
                if any(part.startswith(".") or part in ("node_modules", "__pycache__")
                       for part in manifest_path.parts):
                    continue
                found.append((manifest_name, manifest_path))
        return found

    def collect_components(self) -> list[Component]:
        """모든 매니페스트에서 구성요소 수집"""
        all_components: list[Component] = []
        manifest_files = self.discover_manifest_files()

        if not manifest_files:
            print("[경고] 의존성 파일을 찾지 못했습니다.", file=sys.stderr)
            return all_components

        for manifest_name, manifest_path in manifest_files:
            print(f"[탐지] {manifest_path}", file=sys.stderr)
            parser_cls = self.PARSERS[manifest_name]
            parser = parser_cls()
            components = parser.parse(manifest_path)
            print(f"  → {len(components)}개 구성요소 발견", file=sys.stderr)
            all_components.extend(components)

        # 중복 제거 (name + version + package_manager 기준)
        seen: set[tuple[str, str, str]] = set()
        unique: list[Component] = []
        for comp in all_components:
            key = (comp.name, comp.version, comp.package_manager)
            if key not in seen:
                seen.add(key)
                unique.append(comp)
        return unique

    def build_document(self) -> SBOMDocument:
        """SBOM 문서 생성"""
        components = self.collect_components()
        doc = SBOMDocument(
            document_name=self.project_path.name,
            document_namespace=f"https://sbom.example.com/{uuid.uuid4()}",
            project_path=self.project_path,
            components=components,
        )
        return doc


# ─────────────────────────── 출력 포맷터 ───────────────────────────

class SPDXFormatter:
    """SPDX 2.3 형식 출력"""

    def format(self, doc: SBOMDocument) -> str:
        lines: list[str] = [
            f"SPDXVersion: {doc.spdx_version}",
            f"DataLicense: {doc.data_license}",
            f"SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: {doc.document_name}",
            f"DocumentNamespace: {doc.document_namespace}",
            f"Created: {doc.created}",
            f"Creator: Tool: sbom-generator-py",
            "",
        ]
        for i, comp in enumerate(doc.components, start=1):
            pkg_id = f"SPDXRef-Package-{i}"
            lines += [
                f"PackageName: {comp.name}",
                f"SPDXID: {pkg_id}",
                f"PackageVersion: {comp.version}",
                f"PackageDownloadLocation: NOASSERTION",
                f"FilesAnalyzed: false",
                f"PackageLicenseConcluded: {comp.license_info}",
                f"PackageLicenseDeclared: {comp.license_info}",
                f"PackageCopyrightText: NOASSERTION",
            ]
            if comp.purl:
                lines.append(f"ExternalRef: PACKAGE-MANAGER purl {comp.purl}")
            lines.append("")
        return "\n".join(lines)


class CycloneDXFormatter:
    """CycloneDX 1.4 JSON 형식 출력"""

    def format(self, doc: SBOMDocument) -> str:
        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": doc.created,
                "tools": [{"name": "sbom-generator-py", "version": "1.0.0"}],
                "component": {
                    "type": "application",
                    "name": doc.document_name,
                },
            },
            "components": [],
        }
        for comp in doc.components:
            entry: dict[str, Any] = {
                "type": "library",
                "name": comp.name,
                "version": comp.version,
                "licenses": [{"expression": comp.license_info}],
            }
            if comp.purl:
                entry["purl"] = comp.purl
            if comp.checksum_sha256:
                entry["hashes"] = [{"alg": "SHA-256", "content": comp.checksum_sha256}]
            bom["components"].append(entry)
        return json.dumps(bom, ensure_ascii=False, indent=2)


class JSONFormatter:
    """단순 JSON 형식 출력"""

    def format(self, doc: SBOMDocument) -> str:
        result: dict[str, Any] = {
            "document": {
                "name": doc.document_name,
                "namespace": doc.document_namespace,
                "created": doc.created,
                "generator": "sbom-generator-py",
            },
            "statistics": {
                "total_components": len(doc.components),
                "by_package_manager": self._count_by_pm(doc.components),
            },
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "package_manager": c.package_manager,
                    "purl": c.purl,
                    "license": c.license_info,
                }
                for c in doc.components
            ],
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    def _count_by_pm(self, components: list[Component]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for comp in components:
            counts[comp.package_manager] = counts.get(comp.package_manager, 0) + 1
        return counts


FORMATTERS = {
    "spdx": SPDXFormatter,
    "cyclonedx": CycloneDXFormatter,
    "json": JSONFormatter,
}


# ─────────────────────────── CLI ───────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-generator",
        description="소프트웨어 공급망 SBOM 생성기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 01_supply_chain_fundamentals.py --project-path ./myproject
  python3 01_supply_chain_fundamentals.py --project-path . --output-format cyclonedx
  python3 01_supply_chain_fundamentals.py --project-path . --output-format spdx --output sbom.spdx
        """,
    )
    parser.add_argument(
        "--project-path",
        type=Path,
        default=Path("."),
        metavar="PATH",
        help="분석할 프로젝트 경로 (기본값: 현재 디렉토리)",
    )
    parser.add_argument(
        "--output-format",
        choices=["spdx", "cyclonedx", "json"],
        default="json",
        metavar="FORMAT",
        help="출력 형식 (spdx | cyclonedx | json, 기본값: json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="출력 파일 경로 (미지정 시 표준 출력)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="상세 로그 출력",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    project_path: Path = args.project_path.resolve()
    if not project_path.exists():
        print(f"[오류] 경로가 존재하지 않습니다: {project_path}", file=sys.stderr)
        return 1
    if not project_path.is_dir():
        print(f"[오류] 디렉토리가 아닙니다: {project_path}", file=sys.stderr)
        return 1

    print(f"[시작] 프로젝트 분석: {project_path}", file=sys.stderr)

    generator = SBOMGenerator(project_path)
    doc = generator.build_document()

    formatter_cls = FORMATTERS[args.output_format]
    formatter = formatter_cls()
    output_text = formatter.format(doc)

    if args.output:
        try:
            args.output.write_text(output_text, encoding="utf-8")
            print(f"[완료] SBOM 저장: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[오류] 파일 저장 실패: {exc}", file=sys.stderr)
            return 1
    else:
        print(output_text)

    print(
        f"[요약] 총 {len(doc.components)}개 구성요소 분석 완료 "
        f"(형식: {args.output_format})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 공급망 보안 도입 로드맵

| 단계 | 활동 | 기간 | 우선순위 |
|------|------|------|----------|
| **1단계: 가시성 확보** | SBOM 생성 자동화, 의존성 목록 파악 | 1~2개월 | 긴급 |
| **2단계: 취약점 관리** | CVE 스캐닝, 패치 프로세스 수립 | 2~3개월 | 높음 |
| **3단계: 빌드 강화** | 재현 가능 빌드, Provenance 생성 | 3~6개월 | 높음 |
| **4단계: 서명 체계** | 코드 서명, 아티팩트 서명 도입 | 4~8개월 | 중간 |
| **5단계: 지속 모니터링** | 런타임 검증, 공급업체 평가 | 지속 | 중간 |

---

## 8. 핵심 참고 자료

| 자료 | 운영 기관 | URL |
|------|-----------|-----|
| SLSA 프레임워크 | OpenSSF | https://slsa.dev |
| SPDX 표준 | Linux Foundation | https://spdx.dev |
| CycloneDX | OWASP | https://cyclonedx.org |
| in-toto 프레임워크 | NYU/Cloud Native | https://in-toto.io |
| SSDF (SP 800-218) | NIST | https://csrc.nist.gov/Projects/ssdf |
| OSV 취약점 DB | Google | https://osv.dev |
