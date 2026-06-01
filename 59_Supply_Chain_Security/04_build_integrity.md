# 빌드 무결성 검증 (Build Integrity Verification)

## 1. 빌드 무결성이란

빌드 무결성(Build Integrity)은 소프트웨어 아티팩트가 선언된 소스 코드에서 검증된 빌드 프로세스를 통해
변조 없이 생성되었음을 보증하는 속성입니다. 공격자가 빌드 과정에 개입하더라도 최종 사용자가
이를 탐지할 수 있도록 암호학적 증거(Provenance, 서명)를 제공합니다.

---

## 2. 코드 서명 체계 비교

| 항목 | Sigstore / Cosign | GPG 서명 | Notary v2 (TUF) |
|------|-------------------|----------|-----------------|
| **목적** | 아티팩트 서명 및 투명성 로그 | 파일/태그 서명 | 컨테이너 이미지 서명 |
| **키 관리** | 키리스(OIDC 기반, 단기 인증서) | 장기 개인키 관리 | 역할 기반 키 계층 |
| **투명성 로그** | Rekor (불변 로그) | 없음 | TUF 메타데이터 |
| **인프라 의존성** | Fulcio CA + Rekor | SKS/HKP 키서버 | Notary 서버 |
| **사용 편의성** | 높음 (GitHub Actions 통합) | 중간 (키 관리 필요) | 중간 (설정 복잡) |
| **대표 사용처** | npm, PyPI, OCI 이미지 | Git 태그, 데비안 패키지 | Docker Hub, GHCR |
| **오프라인 검증** | 불가 (Rekor 조회 필요) | 가능 (공개키만 있으면) | 가능 (메타데이터 캐시) |
| **표준** | OpenSSF Sigstore | RFC 4880 | OCI Spec + TUF |
| **채택 현황** | 빠르게 확산 중 | 광범위하게 사용 | 컨테이너 생태계 |

---

## 3. SLSA Provenance 검증 절차

### 3.1 SLSA Provenance JSON 구조

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "myapp-1.2.3.tar.gz",
      "digest": {
        "sha256": "abc123...def456"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/actions/runner"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/...",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/org/repo@refs/heads/main",
        "digest": { "sha1": "aabbcc..." },
        "entryPoint": ".github/workflows/release.yml"
      }
    },
    "metadata": {
      "buildStartedOn": "2024-01-01T00:00:00Z",
      "buildFinishedOn": "2024-01-01T00:10:00Z",
      "completeness": {
        "parameters": true,
        "environment": false,
        "materials": true
      }
    },
    "materials": [
      {
        "uri": "git+https://github.com/org/repo",
        "digest": { "sha1": "aabbcc..." }
      }
    ]
  }
}
```

### 3.2 SLSA 검증 단계

| 단계 | 검증 항목 | 검증 방법 | 실패 시 처리 |
|------|-----------|-----------|--------------|
| **1단계** | 아티팩트 해시 일치 | SHA-256 재계산 후 Provenance와 비교 | 즉시 거부 |
| **2단계** | Provenance 서명 검증 | Cosign/GPG 서명 확인 | 즉시 거부 |
| **3단계** | 빌더 ID 신뢰 | 허용된 빌더 목록과 대조 | 정책에 따라 거부 |
| **4단계** | 소스 저장소 검증 | URI + 커밋 해시 확인 | 정책에 따라 거부 |
| **5단계** | 완전성 확인 | completeness 필드 검토 | 경고 또는 거부 |
| **6단계** | 타임스탬프 확인 | 빌드 시간과 배포 시간 간격 | 이상 시 경고 |

---

## 4. in-toto 프레임워크 개요

in-toto는 소프트웨어 공급망의 각 단계(링크)를 암호학적으로 연결하는 프레임워크입니다.

### 4.1 핵심 개념

| 개념 | 설명 |
|------|------|
| **Layout** | 공급망 전체 정의 (단계, 담당자, 규칙) |
| **Link** | 각 단계의 실행 증거 (입력/출력 해시 + 서명) |
| **Step** | 개별 공급망 단계 (클론, 빌드, 테스트, 패키징) |
| **Inspection** | 최종 검증 시 수행하는 추가 확인 |
| **Functionary** | 각 단계를 수행하는 주체 (공개키로 식별) |

### 4.2 in-toto 레이아웃 예시

```json
{
  "_type": "layout",
  "expires": "2025-12-31T00:00:00Z",
  "keys": {
    "developer-key-id": { "keytype": "ed25519", "keyval": {} }
  },
  "steps": [
    {
      "name": "clone",
      "pubkeys": ["developer-key-id"],
      "expected_materials": [],
      "expected_products": [
        ["CREATE", "src/*"],
        ["DISALLOW", "*"]
      ]
    },
    {
      "name": "build",
      "pubkeys": ["ci-builder-key-id"],
      "expected_materials": [
        ["MATCH", "src/*", "WITH", "PRODUCTS", "FROM", "clone"]
      ],
      "expected_products": [
        ["CREATE", "dist/myapp.tar.gz"]
      ]
    }
  ],
  "inspect": [
    {
      "name": "verify-package",
      "run": ["tar", "tzf", "dist/myapp.tar.gz"],
      "expected_materials": [
        ["MATCH", "dist/myapp.tar.gz", "WITH", "PRODUCTS", "FROM", "build"]
      ]
    }
  ]
}
```

---

## 5. 재현 가능한 빌드 (Reproducible Builds)

| 조건 | 문제 원인 | 해결 방법 |
|------|-----------|-----------|
| **타임스탬프 제거** | 빌드 시간이 바이너리에 포함됨 | `SOURCE_DATE_EPOCH` 환경 변수 설정 |
| **경로 제거** | 빌드 머신 경로가 디버그 정보에 포함 | `-fdebug-prefix-map` 컴파일러 플래그 |
| **정렬된 파일 처리** | 파일시스템 순서에 따른 비결정성 | 정렬된 글로브 패턴 사용 |
| **로케일 고정** | 로케일에 따른 문자열 정렬 차이 | `LC_ALL=C` 설정 |
| **도구 버전 고정** | 컴파일러/링커 버전 차이 | 컨테이너 기반 빌드 환경 |
| **난수 제거** | UUID/난수가 바이너리에 포함 | 결정론적 난수 시드 사용 |

---

## 6. Python CLI: 빌드 아티팩트 무결성 검증기

```python
#!/usr/bin/env python3
"""
빌드 아티팩트 무결성 검증기
기능:
  - SHA-256 해시 검증
  - SLSA Provenance JSON 파싱 및 검증
  - GPG 서명 검증 (gpg 명령 필요)
  - 빌더 신뢰 정책 적용
  - 검증 체인 출력
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ─────────────────────────── 데이터 클래스 ───────────────────────────

class VerificationStatus(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    SKIP    = "SKIP"
    WARNING = "WARNING"


@dataclass
class VerificationStep:
    """단일 검증 단계"""
    name: str
    status: VerificationStatus
    message: str
    detail: str = ""


@dataclass
class ProvenanceInfo:
    """파싱된 Provenance 정보"""
    builder_id: str = ""
    build_type: str = ""
    source_uri: str = ""
    source_digest: str = ""
    entry_point: str = ""
    build_started: str = ""
    build_finished: str = ""
    materials: list[dict[str, Any]] = field(default_factory=list)
    subject_name: str = ""
    subject_sha256: str = ""
    completeness_parameters: bool = False
    completeness_materials: bool = False


@dataclass
class IntegrityReport:
    """무결성 검증 최종 보고서"""
    artifact_path: Path
    provenance_path: Path | None
    overall_status: VerificationStatus
    steps: list[VerificationStep] = field(default_factory=list)
    provenance: ProvenanceInfo | None = None
    verified_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def passed(self) -> bool:
        return self.overall_status == VerificationStatus.PASS

    def add_step(self, step: VerificationStep) -> None:
        self.steps.append(step)
        # FAIL이 하나라도 있으면 전체 FAIL
        if step.status == VerificationStatus.FAIL:
            self.overall_status = VerificationStatus.FAIL
        elif step.status == VerificationStatus.WARNING and \
                self.overall_status == VerificationStatus.PASS:
            self.overall_status = VerificationStatus.WARNING


# ─────────────────────────── 해시 검증 ───────────────────────────

def compute_sha256(file_path: Path) -> str:
    """파일의 SHA-256 해시 계산"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as exc:
        raise OSError(f"해시 계산 실패: {exc}") from exc


def verify_hash(
    artifact_path: Path,
    expected_hash: str,
    algorithm: str = "sha256",
) -> VerificationStep:
    """아티팩트 해시 검증"""
    step_name = f"{algorithm.upper()} 해시 검증"
    if not artifact_path.exists():
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=f"아티팩트 파일 없음: {artifact_path}",
        )

    try:
        if algorithm == "sha256":
            actual_hash = compute_sha256(artifact_path)
        else:
            return VerificationStep(
                name=step_name,
                status=VerificationStatus.FAIL,
                message=f"지원하지 않는 해시 알고리즘: {algorithm}",
            )
    except OSError as exc:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=str(exc),
        )

    if actual_hash.lower() == expected_hash.lower():
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.PASS,
            message="해시 일치",
            detail=f"{algorithm.upper()}: {actual_hash}",
        )
    else:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message="해시 불일치 - 아티팩트가 변조되었을 수 있습니다",
            detail=f"기대값: {expected_hash}\n실제값: {actual_hash}",
        )


# ─────────────────────────── Provenance 파싱 ───────────────────────────

def parse_provenance(provenance_path: Path) -> tuple[ProvenanceInfo | None, str]:
    """
    SLSA Provenance JSON 파싱
    반환: (ProvenanceInfo, 오류 메시지)
    """
    try:
        raw = provenance_path.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Provenance 파싱 실패: {exc}"

    info = ProvenanceInfo()

    # 주체(subject) 파싱
    subjects: list[dict[str, Any]] = data.get("subject", [])
    if subjects:
        first_subject = subjects[0]
        info.subject_name = first_subject.get("name", "")
        digest = first_subject.get("digest", {})
        info.subject_sha256 = digest.get("sha256", "")

    # predicate 파싱
    predicate: dict[str, Any] = data.get("predicate", {})

    builder = predicate.get("builder", {})
    info.builder_id = builder.get("id", "")
    info.build_type = predicate.get("buildType", "")

    invocation = predicate.get("invocation", {})
    config_source = invocation.get("configSource", {})
    info.source_uri = config_source.get("uri", "")
    src_digest = config_source.get("digest", {})
    info.source_digest = src_digest.get("sha1", "") or src_digest.get("sha256", "")
    info.entry_point = config_source.get("entryPoint", "")

    metadata = predicate.get("metadata", {})
    info.build_started = metadata.get("buildStartedOn", "")
    info.build_finished = metadata.get("buildFinishedOn", "")
    completeness = metadata.get("completeness", {})
    info.completeness_parameters = completeness.get("parameters", False)
    info.completeness_materials = completeness.get("materials", False)

    info.materials = predicate.get("materials", [])

    return info, ""


def verify_provenance_structure(provenance_path: Path) -> VerificationStep:
    """Provenance JSON 구조 검증"""
    step_name = "Provenance 구조 검증"
    info, err = parse_provenance(provenance_path)
    if err:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=err,
        )

    missing_fields: list[str] = []
    if not info.builder_id:
        missing_fields.append("builder.id")
    if not info.build_type:
        missing_fields.append("buildType")
    if not info.source_uri:
        missing_fields.append("invocation.configSource.uri")

    if missing_fields:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.WARNING,
            message="필수 필드 누락",
            detail=f"누락 필드: {', '.join(missing_fields)}",
        )

    return VerificationStep(
        name=step_name,
        status=VerificationStatus.PASS,
        message="Provenance 구조 유효",
        detail=f"빌더: {info.builder_id}\n소스: {info.source_uri}",
    )


def verify_artifact_in_provenance(
    artifact_path: Path,
    provenance_path: Path,
) -> VerificationStep:
    """아티팩트 해시와 Provenance의 subject 해시 비교"""
    step_name = "아티팩트-Provenance 연결 검증"

    info, err = parse_provenance(provenance_path)
    if err or info is None:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=f"Provenance 로드 실패: {err}",
        )

    if not info.subject_sha256:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.SKIP,
            message="Provenance에 subject 해시 없음",
        )

    try:
        actual_hash = compute_sha256(artifact_path)
    except OSError as exc:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=str(exc),
        )

    if actual_hash.lower() == info.subject_sha256.lower():
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.PASS,
            message="아티팩트 해시가 Provenance subject와 일치",
            detail=f"SHA-256: {actual_hash}",
        )
    else:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message="아티팩트 해시가 Provenance subject와 불일치",
            detail=(
                f"아티팩트 SHA-256: {actual_hash}\n"
                f"Provenance subject SHA-256: {info.subject_sha256}"
            ),
        )


def verify_builder_trust(
    provenance_path: Path,
    trusted_builders: list[str],
) -> VerificationStep:
    """빌더 ID가 신뢰 목록에 있는지 검증"""
    step_name = "빌더 신뢰 검증"

    if not trusted_builders:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.SKIP,
            message="신뢰 빌더 목록 미지정",
        )

    info, err = parse_provenance(provenance_path)
    if err or info is None:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message=f"Provenance 로드 실패: {err}",
        )

    builder_id = info.builder_id
    for trusted in trusted_builders:
        if builder_id.startswith(trusted) or trusted in builder_id:
            return VerificationStep(
                name=step_name,
                status=VerificationStatus.PASS,
                message="신뢰된 빌더 확인",
                detail=f"빌더 ID: {builder_id}",
            )

    return VerificationStep(
        name=step_name,
        status=VerificationStatus.FAIL,
        message="신뢰되지 않은 빌더",
        detail=f"빌더 ID: {builder_id}\n신뢰 목록: {trusted_builders}",
    )


# ─────────────────────────── GPG 서명 검증 ───────────────────────────

def verify_gpg_signature(
    artifact_path: Path,
    signature_path: Path,
    public_key_path: Path | None = None,
) -> VerificationStep:
    """GPG 서명 검증 (gpg 명령 활용)"""
    step_name = "GPG 서명 검증"

    if not signature_path.exists():
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.SKIP,
            message=f"서명 파일 없음: {signature_path}",
        )

    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.SKIP,
            message="gpg 명령을 찾을 수 없음. GPG 서명 검증 건너뜀.",
        )

    cmd: list[str] = ["gpg", "--status-fd", "1"]

    if public_key_path and public_key_path.exists():
        # 임시 키링에 공개키 임포트 후 검증
        with tempfile.TemporaryDirectory() as tmpdir:
            keyring = Path(tmpdir) / "keyring.gpg"
            try:
                subprocess.run(
                    ["gpg", "--no-default-keyring", "--keyring", str(keyring),
                     "--import", str(public_key_path)],
                    capture_output=True, check=True,
                )
                verify_cmd = [
                    "gpg", "--no-default-keyring", "--keyring", str(keyring),
                    "--status-fd", "1", "--verify",
                    str(signature_path), str(artifact_path),
                ]
                result = subprocess.run(verify_cmd, capture_output=True, text=True)
            except subprocess.SubprocessError as exc:
                return VerificationStep(
                    name=step_name,
                    status=VerificationStatus.FAIL,
                    message=f"GPG 실행 오류: {exc}",
                )
    else:
        cmd += ["--verify", str(signature_path), str(artifact_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except subprocess.SubprocessError as exc:
            return VerificationStep(
                name=step_name,
                status=VerificationStatus.FAIL,
                message=f"GPG 실행 오류: {exc}",
            )

    if result.returncode == 0 and "GOODSIG" in (result.stdout + result.stderr):
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.PASS,
            message="GPG 서명 유효",
            detail=result.stdout.strip()[:300],
        )
    else:
        return VerificationStep(
            name=step_name,
            status=VerificationStatus.FAIL,
            message="GPG 서명 검증 실패",
            detail=(result.stderr + result.stdout).strip()[:300],
        )


# ─────────────────────────── 메인 검증기 ───────────────────────────

class BuildIntegrityVerifier:
    """빌드 아티팩트 무결성 검증기"""

    DEFAULT_TRUSTED_BUILDERS = [
        "https://github.com/actions/runner",
        "https://github.com/slsa-framework/slsa-github-generator",
        "https://cloudbuild.googleapis.com/GoogleHostedWorker",
    ]

    def __init__(
        self,
        artifact: Path,
        provenance_json: Path | None = None,
        public_key: Path | None = None,
        signature_file: Path | None = None,
        trusted_builders: list[str] | None = None,
        expected_hash: str | None = None,
    ):
        self.artifact = artifact
        self.provenance_json = provenance_json
        self.public_key = public_key
        self.signature_file = signature_file
        self.trusted_builders = trusted_builders or self.DEFAULT_TRUSTED_BUILDERS
        self.expected_hash = expected_hash

    def verify(self) -> IntegrityReport:
        report = IntegrityReport(
            artifact_path=self.artifact,
            provenance_path=self.provenance_json,
            overall_status=VerificationStatus.PASS,
        )

        # 1단계: 아티팩트 존재 확인
        if not self.artifact.exists():
            report.add_step(VerificationStep(
                name="아티팩트 존재 확인",
                status=VerificationStatus.FAIL,
                message=f"아티팩트 파일 없음: {self.artifact}",
            ))
            return report

        report.add_step(VerificationStep(
            name="아티팩트 존재 확인",
            status=VerificationStatus.PASS,
            message=f"크기: {self.artifact.stat().st_size:,} bytes",
        ))

        # 2단계: SHA-256 해시 검증 (expected_hash 지정 시)
        if self.expected_hash:
            report.add_step(verify_hash(self.artifact, self.expected_hash))
        else:
            computed = compute_sha256(self.artifact)
            report.add_step(VerificationStep(
                name="SHA-256 해시 계산",
                status=VerificationStatus.INFO if False else VerificationStatus.PASS,
                message="해시 계산 완료 (기준값 없음, 참고용)",
                detail=f"SHA-256: {computed}",
            ))

        # 3단계: Provenance 검증
        if self.provenance_json:
            report.add_step(verify_provenance_structure(self.provenance_json))
            report.add_step(
                verify_artifact_in_provenance(self.artifact, self.provenance_json)
            )
            report.add_step(
                verify_builder_trust(self.provenance_json, self.trusted_builders)
            )

            # Provenance 정보 저장
            info, _ = parse_provenance(self.provenance_json)
            report.provenance = info

        else:
            report.add_step(VerificationStep(
                name="Provenance 검증",
                status=VerificationStatus.SKIP,
                message="Provenance 파일 미지정",
            ))

        # 4단계: GPG 서명 검증
        if self.signature_file:
            report.add_step(
                verify_gpg_signature(self.artifact, self.signature_file, self.public_key)
            )
        else:
            # .sig, .asc 자동 탐지
            for ext in (".sig", ".asc", ".gpg"):
                auto_sig = self.artifact.with_suffix(self.artifact.suffix + ext)
                if auto_sig.exists():
                    report.add_step(
                        verify_gpg_signature(self.artifact, auto_sig, self.public_key)
                    )
                    break
            else:
                report.add_step(VerificationStep(
                    name="GPG 서명 검증",
                    status=VerificationStatus.SKIP,
                    message="서명 파일 미지정 및 자동 탐지 실패",
                ))

        return report


# ─────────────────────────── 보고서 출력 ───────────────────────────

STATUS_COLORS = {
    VerificationStatus.PASS:    "\033[92m",
    VerificationStatus.FAIL:    "\033[91m",
    VerificationStatus.WARNING: "\033[93m",
    VerificationStatus.SKIP:    "\033[90m",
}
RESET = "\033[0m"


def print_report(report: IntegrityReport, use_color: bool = True) -> None:
    def color(status: VerificationStatus, text: str) -> str:
        if not use_color:
            return text
        return f"{STATUS_COLORS.get(status, '')}{text}{RESET}"

    print(f"\n{'='*60}")
    print("빌드 아티팩트 무결성 검증 보고서")
    print(f"{'='*60}")
    print(f"아티팩트: {report.artifact_path}")
    if report.provenance_path:
        print(f"Provenance: {report.provenance_path}")
    print(f"검증 시각: {report.verified_at}")
    overall = color(report.overall_status, f"[{report.overall_status.value}]")
    print(f"최종 결과: {overall}")
    print()

    print("검증 단계별 결과:")
    print("─" * 50)
    for i, step in enumerate(report.steps, start=1):
        status_str = color(step.status, f"[{step.status.value:7s}]")
        print(f"{i:2d}. {status_str} {step.name}")
        print(f"       {step.message}")
        if step.detail:
            for line in step.detail.splitlines():
                print(f"       {line}")
        print()

    if report.provenance:
        p = report.provenance
        print("Provenance 정보:")
        print("─" * 50)
        if p.builder_id:
            print(f"  빌더: {p.builder_id}")
        if p.source_uri:
            print(f"  소스: {p.source_uri}")
        if p.source_digest:
            print(f"  소스 해시: {p.source_digest}")
        if p.entry_point:
            print(f"  진입점: {p.entry_point}")
        if p.build_started:
            print(f"  빌드 시작: {p.build_started}")
        print(f"  재료 수: {len(p.materials)}개")


def export_json_report(report: IntegrityReport) -> str:
    data: dict[str, Any] = {
        "artifact": str(report.artifact_path),
        "provenance": str(report.provenance_path) if report.provenance_path else None,
        "verified_at": report.verified_at,
        "overall_status": report.overall_status.value,
        "passed": report.passed(),
        "steps": [
            {
                "name": s.name,
                "status": s.status.value,
                "message": s.message,
                "detail": s.detail,
            }
            for s in report.steps
        ],
    }
    if report.provenance:
        p = report.provenance
        data["provenance_info"] = {
            "builder_id": p.builder_id,
            "source_uri": p.source_uri,
            "source_digest": p.source_digest,
            "entry_point": p.entry_point,
            "build_started": p.build_started,
            "materials_count": len(p.materials),
        }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─────────────────────────── CLI ───────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build-integrity-verifier",
        description="빌드 아티팩트 무결성 검증기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python3 04_build_integrity.py --artifact myapp-1.0.tar.gz
  python3 04_build_integrity.py --artifact myapp.tar.gz \\
      --provenance-json provenance.json \\
      --expected-hash abc123...
  python3 04_build_integrity.py --artifact myapp.tar.gz \\
      --provenance-json provenance.json \\
      --public-key signer.pub --output report.json
        """,
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        required=True,
        metavar="FILE",
        help="검증할 빌드 아티팩트 파일",
    )
    parser.add_argument(
        "--provenance-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="SLSA Provenance JSON 파일",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        metavar="FILE",
        help="GPG 공개키 파일 (서명 검증용)",
    )
    parser.add_argument(
        "--signature",
        type=Path,
        default=None,
        metavar="FILE",
        help="GPG 서명 파일 (.sig/.asc, 미지정 시 자동 탐지)",
    )
    parser.add_argument(
        "--expected-hash",
        type=str,
        default=None,
        metavar="SHA256",
        help="기대 SHA-256 해시값",
    )
    parser.add_argument(
        "--trusted-builder",
        action="append",
        dest="trusted_builders",
        default=None,
        metavar="URL",
        help="신뢰할 빌더 ID (복수 지정 가능)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="JSON 보고서 출력 파일",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="색상 출력 비활성화",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    verifier = BuildIntegrityVerifier(
        artifact=args.artifact.resolve(),
        provenance_json=args.provenance_json.resolve() if args.provenance_json else None,
        public_key=args.public_key.resolve() if args.public_key else None,
        signature_file=args.signature.resolve() if args.signature else None,
        trusted_builders=args.trusted_builders,
        expected_hash=args.expected_hash,
    )

    report = verifier.verify()
    print_report(report, use_color=not args.no_color)

    if args.output:
        try:
            args.output.write_text(export_json_report(report), encoding="utf-8")
            print(f"\n[저장] JSON 보고서: {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[오류] 파일 저장 실패: {exc}", file=sys.stderr)

    return 0 if report.passed() else 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## 7. 빌드 무결성 도구 비교

| 도구 | 용도 | 라이선스 | 주요 언어 |
|------|------|----------|-----------|
| **cosign** | 컨테이너/아티팩트 서명 | Apache 2.0 | Go |
| **slsa-verifier** | SLSA Provenance 검증 | Apache 2.0 | Go |
| **in-toto-run** | in-toto 링크 생성 | Apache 2.0 | Python |
| **rekor-cli** | 투명성 로그 조회 | Apache 2.0 | Go |
| **syft** | SBOM 생성 | Apache 2.0 | Go |
| **grype** | 아티팩트 취약점 스캔 | Apache 2.0 | Go |
| **trivy** | 컨테이너/코드 취약점 스캔 | Apache 2.0 | Go |

---

<a name="english"></a>

# Build Integrity Verification

## 1. What is Build Integrity?

Build Integrity is the property that guarantees a software artifact was produced from its declared source code through a verified build process without tampering. It provides cryptographic evidence (Provenance, signatures) so that end users can detect any attacker interference in the build process.

---

## 2. Code Signing System Comparison

| Item | Sigstore / Cosign | GPG Signing | Notary v2 (TUF) |
|------|-------------------|-------------|-----------------|
| **Purpose** | Artifact signing and transparency log | File/tag signing | Container image signing |
| **Key management** | Keyless (OIDC-based, short-lived certs) | Long-term private key management | Role-based key hierarchy |
| **Transparency log** | Rekor (immutable log) | None | TUF metadata |
| **Infrastructure dependency** | Fulcio CA + Rekor | SKS/HKP key servers | Notary server |
| **Ease of use** | High (GitHub Actions integration) | Medium (key management required) | Medium (complex setup) |
| **Representative use** | npm, PyPI, OCI images | Git tags, Debian packages | Docker Hub, GHCR |
| **Offline verification** | Not possible (requires Rekor query) | Possible (public key only) | Possible (metadata cache) |
| **Standard** | OpenSSF Sigstore | RFC 4880 | OCI Spec + TUF |
| **Adoption** | Rapidly expanding | Widely used | Container ecosystem |

---

## 3. SLSA Provenance Verification Procedure

### 3.1 SLSA Provenance JSON Structure

(See code block above — content is identical)

### 3.2 SLSA Verification Steps

| Step | Verification Item | Verification Method | Action on Failure |
|------|-------------------|---------------------|-------------------|
| **Step 1** | Artifact hash match | Recalculate SHA-256 and compare with Provenance | Reject immediately |
| **Step 2** | Provenance signature verification | Verify Cosign/GPG signature | Reject immediately |
| **Step 3** | Builder ID trust | Compare with trusted builder list | Reject per policy |
| **Step 4** | Source repository verification | Verify URI + commit hash | Reject per policy |
| **Step 5** | Completeness check | Review completeness field | Warn or reject |
| **Step 6** | Timestamp check | Check interval between build and deployment time | Warn if anomalous |

---

## 4. in-toto Framework Overview

in-toto is a framework that cryptographically chains each step (link) in the software supply chain.

### 4.1 Core Concepts

| Concept | Description |
|---------|-------------|
| **Layout** | Defines the entire supply chain (steps, owners, rules) |
| **Link** | Execution evidence for each step (input/output hashes + signature) |
| **Step** | Individual supply chain steps (clone, build, test, package) |
| **Inspection** | Additional checks performed during final verification |
| **Functionary** | Entity that performs each step (identified by public key) |

### 4.2 in-toto Layout Example

(See code block above)

---

## 5. Reproducible Builds

| Condition | Problem Cause | Solution |
|-----------|---------------|----------|
| **Remove timestamps** | Build time embedded in binary | Set `SOURCE_DATE_EPOCH` environment variable |
| **Remove paths** | Build machine path included in debug info | `-fdebug-prefix-map` compiler flag |
| **Sorted file processing** | Non-determinism from filesystem ordering | Use sorted glob patterns |
| **Fixed locale** | String sort differences by locale | Set `LC_ALL=C` |
| **Fixed tool versions** | Compiler/linker version differences | Container-based build environment |
| **Remove random values** | UUID/random values embedded in binary | Use deterministic random seed |

---

## 6. Python CLI: Build Artifact Integrity Verifier

(See code block above)

---

## 7. Build Integrity Tool Comparison

| Tool | Purpose | License | Primary Language |
|------|---------|---------|-----------------|
| **cosign** | Container/artifact signing | Apache 2.0 | Go |
| **slsa-verifier** | SLSA Provenance verification | Apache 2.0 | Go |
| **in-toto-run** | in-toto link generation | Apache 2.0 | Python |
| **rekor-cli** | Transparency log queries | Apache 2.0 | Go |
| **syft** | SBOM generation | Apache 2.0 | Go |
| **grype** | Artifact vulnerability scanning | Apache 2.0 | Go |
| **trivy** | Container/code vulnerability scanning | Apache 2.0 | Go |
