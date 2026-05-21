# AI 공격 기초 (AI Attack Fundamentals)

## 개요

AI/ML 시스템에 대한 공격은 전통적인 사이버보안 공격과 근본적으로 다른 특성을 가진다. 모델의 학습 데이터, 추론 과정, 출력 생성 메커니즘 각각이 고유한 공격 벡터가 된다. 이 문서는 AI 레드팀 활동의 기초가 되는 위협 모델, 공격 분류 체계, 그리고 실습 도구를 다룬다.

---

## 1. AI/ML 위협 모델 분류

### 1.1 공격자 목표 × 접근 권한 매트릭스

| 공격자 목표 \ 접근 권한 | 화이트박스 (내부 완전접근) | 그레이박스 (부분접근) | 블랙박스 (API만) |
|---|---|---|---|
| **기밀성 침해** | 가중치 직접 탈취, 학습 데이터 추출 | 부분 파라미터 기반 멤버십 추론 | 쿼리 기반 모델 복제, 멤버십 추론 |
| **무결성 침해** | 백도어 삽입, 가중치 조작 | 그라디언트 추정 기반 적대적 예제 | 블랙박스 적대적 예제, 프롬프트 인젝션 |
| **가용성 침해** | 모델 파괴, 학습 방해 | 선택적 입력 차단 우회 | 서비스 거부(입력 범람), 슬로다운 공격 |
| **책임 추적 회피** | 로그 조작, 감사 우회 | 분류 경계 탐색 | 출력 속성 위장, 워터마크 제거 |
| **프라이버시 침해** | 학습셋 직접 접근 | 그라디언트 기반 데이터 재구성 | 모델 역전 공격, 속성 추론 |

### 1.2 공격 단계별 분류

| 단계 | 공격명 | 타겟 | 효과 |
|---|---|---|---|
| 학습 전 | 데이터 포이즈닝 | 학습 데이터셋 | 모델 성능 저하 또는 백도어 삽입 |
| 학습 중 | 가중치 조작 | 체크포인트 파일 | 특정 입력에 대한 의도적 오분류 |
| 추론 시 | 적대적 예제 | 입력 데이터 | 오분류 유도 |
| 추론 시 | 프롬프트 인젝션 | LLM 입력 | 의도치 않은 동작 유발 |
| 배포 후 | 모델 추출 | API 쿼리 응답 | 독점 모델 복제 |
| 배포 후 | 멤버십 추론 | API 신뢰도 점수 | 학습 데이터 포함 여부 판별 |

---

## 2. 공격 접근 방식 분류

### 2.1 화이트박스 공격 (White-box Attack)

공격자가 모델의 아키텍처, 가중치, 학습 데이터, 하이퍼파라미터에 완전히 접근 가능한 시나리오다.

**특징:**
- 그라디언트를 직접 계산하여 최적화된 적대적 예제 생성 가능
- 가장 강력하지만 현실적으로 드문 시나리오
- 내부자 위협, 공급망 공격, 모델 파일 유출 시 적용 가능

**대표 기법:**
- FGSM (Fast Gradient Sign Method): 손실 함수 그라디언트 방향으로 입력 조작
- PGD (Projected Gradient Descent): 반복적 그라디언트 기반 최적화
- CW (Carlini & Wagner): L2/Linf/L0 노름 최소화 기반

### 2.2 그레이박스 공격 (Grey-box Attack)

공격자가 모델 아키텍처는 알지만 가중치나 학습 데이터에는 접근하지 못하는 중간 시나리오다.

**특징:**
- 구조 정보를 활용한 부분 최적화 가능
- 오픈소스 기반 모델(BERT, ResNet 등) 배포 시 흔한 시나리오
- 전이 가능성(transferability)을 활용한 공격에 효과적

**대표 기법:**
- 대체 모델(surrogate model) 학습 후 화이트박스 공격 수행
- 그라디언트 추정(Finite Differences) 기반 접근

### 2.3 블랙박스 공격 (Black-box Attack)

공격자가 API를 통해 입력-출력만 관찰 가능한 가장 현실적인 시나리오다.

**특징:**
- 대부분의 프로덕션 AI 서비스 공격에 해당
- 쿼리 수에 제한이 있어 효율적인 탐색 전략 필요
- 전이 공격(transfer attack)과 쿼리 기반 공격으로 나뉨

**대표 기법:**
- 쿼리 기반 모델 추출 → 대체 모델로 화이트박스 공격
- 자연어 변환(paraphrasing) 기반 프롬프트 인젝션
- Score 기반: 출력 신뢰도 점수 활용
- Decision 기반: 최종 분류 결과만 활용

---

## 3. MITRE ATLAS 전술 프레임워크

MITRE ATLAS(Adversarial Threat Landscape for Artificial-Intelligence Systems)는 AI 시스템에 특화된 전술-기법-절차(TTP) 프레임워크다.

### 3.1 전술 목록

| 전술 ID | 전술명 | 설명 | 예시 기법 |
|---|---|---|---|
| AML.TA0001 | ML 공격 준비 | 타겟 AI 시스템 정보 수집 | 공개 모델 카드 분석, API 탐색 |
| AML.TA0002 | ML 공격 실행 | 적대적 입력 생성 및 주입 | 적대적 예제 생성, 프롬프트 인젝션 |
| AML.TA0003 | ML 영향 | 모델 동작 변경 또는 추출 | 오분류 유도, 모델 탈취 |
| AML.TA0004 | 자격증명 접근 | ML 인프라 접근 권한 획득 | MLflow 토큰 탈취, API 키 유출 |
| AML.TA0005 | 방어 우회 | 탐지 시스템 회피 | 입력 변형, 쿼리 속도 조절 |
| AML.TA0006 | 발견 | 시스템 구조 파악 | 모델 아키텍처 추론, 학습 데이터 추정 |
| AML.TA0007 | 수집 | 민감 정보 수집 | 학습 데이터 복원, 속성 추론 |
| AML.TA0008 | 데이터 조작 | 학습/추론 데이터 변조 | 데이터 포이즈닝, 레이블 플리핑 |
| AML.TA0009 | 모델 조작 | 모델 파라미터 직접 변조 | 백도어 삽입, 뉴런 비활성화 |
| AML.TA0010 | 유출 | 모델 또는 데이터 외부 전송 | 모델 파일 유출, 쿼리 로그 탈취 |

### 3.2 기법-전술 매핑 예시

| 기법 ID | 기법명 | 관련 전술 | 완화 방법 |
|---|---|---|---|
| AML.T0000 | 공개 ML 아티팩트 악용 | TA0001 | 모델 카드 정보 최소화 |
| AML.T0006 | 학습 데이터 오염 | TA0008 | 데이터 출처 검증, 이상 탐지 |
| AML.T0020 | 적대적 예제 | TA0002 | 적대적 학습, 입력 전처리 |
| AML.T0025 | 모델 추출 | TA0007 | 쿼리 속도 제한, 출력 정밀도 감소 |
| AML.T0043 | 백도어 ML 모델 | TA0009 | 공급망 검증, 모델 감사 |
| AML.T0054 | LLM 프롬프트 인젝션 | TA0002 | 입력 검증, 출력 필터링 |

---

## 4. MLflow 모델 정보 수집 CLI

```python
#!/usr/bin/env python3
"""
MLflow 모델 레지스트리 정보 수집 도구
AI 레드팀 정찰 단계에서 타겟 MLflow 서버의 모델 정보를 수집한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
import urllib.request
import urllib.error


@dataclass
class ModelInfo:
    name: str
    latest_version: str
    stage: str
    description: str
    tags: dict[str, str] = field(default_factory=dict)
    run_id: str = ""
    artifact_uri: str = ""
    creation_timestamp: int = 0
    last_updated_timestamp: int = 0


@dataclass
class ExperimentInfo:
    experiment_id: str
    name: str
    artifact_location: str
    lifecycle_stage: str
    tags: dict[str, str] = field(default_factory=dict)
    run_count: int = 0


@dataclass
class ScanResult:
    target_url: str
    scan_timestamp: float
    server_reachable: bool
    models: list[ModelInfo] = field(default_factory=list)
    experiments: list[ExperimentInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_endpoints: dict[str, Any] = field(default_factory=dict)


def make_request(
    url: str,
    token: str | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """MLflow REST API에 GET 요청을 보내고 JSON 응답을 반환한다."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason} — {url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"연결 실패: {e.reason} — {url}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"JSON 파싱 오류: {e}") from e


def probe_server(base_url: str, token: str | None, timeout: int) -> bool:
    """MLflow 서버 접근 가능 여부를 확인한다."""
    health_url = urljoin(base_url, "api/2.0/mlflow/experiments/list")
    try:
        make_request(health_url, token, timeout)
        return True
    except RuntimeError:
        return False


def collect_models(
    base_url: str,
    token: str | None,
    timeout: int,
    errors: list[str],
) -> list[ModelInfo]:
    """모델 레지스트리에서 등록된 모든 모델 정보를 수집한다."""
    models: list[ModelInfo] = []
    url = urljoin(base_url, "api/2.0/mlflow/registered-models/list")

    try:
        data = make_request(url, token, timeout)
        raw_models = data.get("registered_models", [])

        for rm in raw_models:
            latest_versions = rm.get("latest_versions", [{}])
            latest = latest_versions[0] if latest_versions else {}

            model = ModelInfo(
                name=rm.get("name", ""),
                latest_version=latest.get("version", "0"),
                stage=latest.get("current_stage", "None"),
                description=rm.get("description", ""),
                tags={t["key"]: t["value"] for t in rm.get("tags", [])},
                run_id=latest.get("run_id", ""),
                artifact_uri=latest.get("source", ""),
                creation_timestamp=rm.get("creation_timestamp", 0),
                last_updated_timestamp=rm.get("last_updated_timestamp", 0),
            )
            models.append(model)
    except RuntimeError as e:
        errors.append(f"모델 수집 오류: {e}")

    return models


def collect_experiments(
    base_url: str,
    token: str | None,
    timeout: int,
    errors: list[str],
) -> list[ExperimentInfo]:
    """실험 목록과 각 실험의 런 수를 수집한다."""
    experiments: list[ExperimentInfo] = []
    url = urljoin(base_url, "api/2.0/mlflow/experiments/list")

    try:
        data = make_request(url, token, timeout)
        raw_exps = data.get("experiments", [])

        for exp in raw_exps:
            exp_id = exp.get("experiment_id", "")
            run_count = 0

            # 각 실험의 런 수 조회
            try:
                runs_url = urljoin(
                    base_url,
                    f"api/2.0/mlflow/runs/search"
                )
                runs_req_url = f"{runs_url}?experiment_ids={exp_id}&max_results=1"
                runs_data = make_request(runs_req_url, token, timeout)
                # 전체 수 대신 존재 여부만 확인
                run_count = len(runs_data.get("runs", []))
            except RuntimeError:
                pass

            experiment = ExperimentInfo(
                experiment_id=exp_id,
                name=exp.get("name", ""),
                artifact_location=exp.get("artifact_location", ""),
                lifecycle_stage=exp.get("lifecycle_stage", ""),
                tags={t["key"]: t["value"] for t in exp.get("tags", [])},
                run_count=run_count,
            )
            experiments.append(experiment)
    except RuntimeError as e:
        errors.append(f"실험 수집 오류: {e}")

    return experiments


def probe_additional_endpoints(
    base_url: str,
    token: str | None,
    timeout: int,
) -> dict[str, Any]:
    """추가적인 정보 노출 엔드포인트를 탐색한다."""
    endpoints = {
        "metrics_list": "api/2.0/mlflow/metrics/get-history",
        "model_versions": "api/2.0/mlflow/model-versions/search",
        "artifacts": "api/2.0/mlflow/artifacts/list",
    }

    results: dict[str, Any] = {}
    for name, path in endpoints.items():
        url = urljoin(base_url, path)
        try:
            data = make_request(url, token, timeout)
            results[name] = {"accessible": True, "keys": list(data.keys())}
        except RuntimeError as e:
            results[name] = {"accessible": False, "error": str(e)}

    return results


def format_report(result: ScanResult, verbose: bool) -> str:
    """스캔 결과를 사람이 읽기 쉬운 형식으로 변환한다."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("MLflow 정찰 스캔 결과")
    lines.append("=" * 60)
    lines.append(f"타겟 URL   : {result.target_url}")
    lines.append(f"스캔 시각  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.scan_timestamp))}")
    lines.append(f"서버 접근  : {'가능' if result.server_reachable else '불가'}")
    lines.append("")

    if not result.server_reachable:
        lines.append("[!] 서버에 접근할 수 없습니다.")
        return "\n".join(lines)

    lines.append(f"[모델 레지스트리] {len(result.models)}개 발견")
    lines.append("-" * 40)
    for model in result.models:
        lines.append(f"  - {model.name} (v{model.latest_version}, {model.stage})")
        if model.description:
            lines.append(f"    설명: {model.description[:80]}")
        if model.artifact_uri and verbose:
            lines.append(f"    아티팩트: {model.artifact_uri}")
        if model.run_id and verbose:
            lines.append(f"    Run ID: {model.run_id}")
        if model.tags and verbose:
            lines.append(f"    태그: {model.tags}")

    lines.append("")
    lines.append(f"[실험] {len(result.experiments)}개 발견")
    lines.append("-" * 40)
    for exp in result.experiments:
        lines.append(f"  - [{exp.experiment_id}] {exp.name} ({exp.lifecycle_stage})")
        if exp.artifact_location and verbose:
            lines.append(f"    아티팩트 위치: {exp.artifact_location}")

    if result.errors:
        lines.append("")
        lines.append("[오류]")
        for err in result.errors:
            lines.append(f"  ! {err}")

    if verbose and result.raw_endpoints:
        lines.append("")
        lines.append("[추가 엔드포인트 탐색]")
        for ep_name, ep_data in result.raw_endpoints.items():
            status = "접근 가능" if ep_data.get("accessible") else "차단"
            lines.append(f"  - {ep_name}: {status}")

    lines.append("=" * 60)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mlflow-recon",
        description="MLflow 서버 정찰 도구 — AI 레드팀 정보 수집 단계",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 01_ai_attack_fundamentals.md --target http://mlflow.internal:5000
  python 01_ai_attack_fundamentals.md --target http://mlflow.internal:5000 --verbose
  python 01_ai_attack_fundamentals.md --target http://mlflow.internal:5000 --output result.json
        """,
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="MLflow 서버 기본 URL (예: http://localhost:5000)",
    )
    parser.add_argument(
        "--token",
        default=None,
        metavar="TOKEN",
        help="MLflow 인증 토큰 (선택사항)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="요청 타임아웃 초 (기본값: 10)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="결과를 JSON 파일로 저장",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 정보 출력",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    base_url = args.target.rstrip("/") + "/"
    errors: list[str] = []

    print(f"[*] 타겟 스캔 시작: {base_url}")

    # 서버 접근 가능 여부 확인
    reachable = probe_server(base_url, args.token, args.timeout)

    result = ScanResult(
        target_url=args.target,
        scan_timestamp=time.time(),
        server_reachable=reachable,
        errors=errors,
    )

    if reachable:
        print("[*] 서버 접근 확인 — 정보 수집 중...")
        result.models = collect_models(base_url, args.token, args.timeout, errors)
        print(f"    모델: {len(result.models)}개")
        result.experiments = collect_experiments(base_url, args.token, args.timeout, errors)
        print(f"    실험: {len(result.experiments)}개")

        if args.verbose:
            result.raw_endpoints = probe_additional_endpoints(
                base_url, args.token, args.timeout
            )
    else:
        print("[!] 서버에 접근할 수 없습니다.")

    # 결과 출력
    report = format_report(result, args.verbose)
    print(report)

    # JSON 파일 저장
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as f:
            json.dump(asdict(result), f, ensure_ascii=False, indent=2)
        print(f"[+] 결과 저장: {args.output}")

    return 0 if reachable else 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. AI 취약점 스캐너

```python
#!/usr/bin/env python3
"""
AI 엔드포인트 취약점 스캐너
OpenAI 호환 API 및 HuggingFace 추론 엔드포인트의 보안 설정 미비를 탐지한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import urllib.request
import urllib.error


@dataclass
class VulnerabilityFinding:
    endpoint: str
    vuln_type: str
    severity: str  # critical / high / medium / low / info
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class EndpointScanResult:
    url: str
    endpoint_type: str  # openai / huggingface / unknown
    reachable: bool
    auth_required: bool
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    response_time_ms: float = 0.0


def detect_endpoint_type(url: str) -> str:
    """URL 패턴으로 엔드포인트 유형을 판별한다."""
    lower = url.lower()
    if "huggingface" in lower or "hf.co" in lower or "/models/" in lower:
        return "huggingface"
    if "openai" in lower or "/v1/chat" in lower or "/v1/completions" in lower:
        return "openai"
    return "unknown"


def check_openai_endpoint(
    url: str,
    token: str | None,
    timeout: int,
) -> EndpointScanResult:
    """OpenAI 호환 엔드포인트의 보안 설정을 검사한다."""
    findings: list[VulnerabilityFinding] = []
    start = time.time()

    # 인증 없이 접근 시도
    test_payload = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "test"}],
        "max_tokens": 1,
    }).encode()

    req_no_auth = urllib.request.Request(
        url,
        data=test_payload,
        method="POST",
    )
    req_no_auth.add_header("Content-Type", "application/json")

    auth_required = True
    reachable = False

    try:
        with urllib.request.urlopen(req_no_auth, timeout=timeout) as resp:
            reachable = True
            if resp.status == 200:
                auth_required = False
                findings.append(VulnerabilityFinding(
                    endpoint=url,
                    vuln_type="인증 우회",
                    severity="critical",
                    description="인증 없이 API 호출이 허용됩니다.",
                    evidence="HTTP 200 응답 (인증 토큰 없음)",
                    recommendation="API 키 또는 Bearer 토큰 인증을 필수로 설정하세요.",
                ))
    except urllib.error.HTTPError as e:
        reachable = True
        if e.code == 401:
            auth_required = True
        elif e.code == 403:
            findings.append(VulnerabilityFinding(
                endpoint=url,
                vuln_type="접근 제어 설정",
                severity="info",
                description="IP 기반 접근 제어가 적용된 것으로 보입니다.",
                evidence=f"HTTP 403 응답",
                recommendation="추가 인증 레이어와 병행하여 사용하세요.",
            ))
        elif e.code == 429:
            findings.append(VulnerabilityFinding(
                endpoint=url,
                vuln_type="속도 제한",
                severity="info",
                description="속도 제한이 적용되어 있습니다.",
                evidence="HTTP 429 응답",
                recommendation="모델 추출 공격 방어에 효과적입니다.",
            ))
    except urllib.error.URLError:
        reachable = False

    elapsed = (time.time() - start) * 1000

    # CORS 헤더 검사 (OPTIONS 요청)
    if reachable:
        cors_req = urllib.request.Request(url, method="OPTIONS")
        try:
            with urllib.request.urlopen(cors_req, timeout=timeout) as resp:
                allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*":
                    findings.append(VulnerabilityFinding(
                        endpoint=url,
                        vuln_type="CORS 와일드카드",
                        severity="medium",
                        description="CORS 정책이 모든 출처를 허용합니다.",
                        evidence=f"Access-Control-Allow-Origin: *",
                        recommendation="신뢰할 수 있는 출처만 명시적으로 허용하세요.",
                    ))
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass

    return EndpointScanResult(
        url=url,
        endpoint_type="openai",
        reachable=reachable,
        auth_required=auth_required,
        findings=findings,
        response_time_ms=elapsed,
    )


def check_huggingface_endpoint(
    url: str,
    token: str | None,
    timeout: int,
) -> EndpointScanResult:
    """HuggingFace 추론 엔드포인트의 보안 설정을 검사한다."""
    findings: list[VulnerabilityFinding] = []
    start = time.time()

    test_payload = json.dumps({"inputs": "test"}).encode()
    req = urllib.request.Request(url, data=test_payload, method="POST")
    req.add_header("Content-Type", "application/json")

    reachable = False
    auth_required = True

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            reachable = True
            if resp.status == 200:
                auth_required = False
                findings.append(VulnerabilityFinding(
                    endpoint=url,
                    vuln_type="공개 추론 엔드포인트",
                    severity="high",
                    description="인증 없이 모델 추론이 가능합니다.",
                    evidence="HTTP 200 응답 (인증 없음)",
                    recommendation="HuggingFace 토큰 인증을 적용하고 엔드포인트를 비공개로 설정하세요.",
                ))
    except urllib.error.HTTPError as e:
        reachable = True
        if e.code not in (401, 403):
            findings.append(VulnerabilityFinding(
                endpoint=url,
                vuln_type="예상치 못한 응답 코드",
                severity="low",
                description=f"비표준 HTTP 오류 코드: {e.code}",
                evidence=f"HTTP {e.code}: {e.reason}",
                recommendation="표준 인증 오류(401)를 반환하도록 설정하세요.",
            ))
    except urllib.error.URLError:
        reachable = False

    elapsed = (time.time() - start) * 1000

    return EndpointScanResult(
        url=url,
        endpoint_type="huggingface",
        reachable=reachable,
        auth_required=auth_required,
        findings=findings,
        response_time_ms=elapsed,
    )


def scan_endpoint(
    url: str,
    token: str | None,
    timeout: int,
) -> EndpointScanResult:
    """엔드포인트 유형을 탐지하고 적절한 검사를 수행한다."""
    ep_type = detect_endpoint_type(url)
    if ep_type == "huggingface":
        return check_huggingface_endpoint(url, token, timeout)
    return check_openai_endpoint(url, token, timeout)


def severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def print_scan_results(results: list[EndpointScanResult]) -> None:
    """스캔 결과를 콘솔에 출력한다."""
    total_findings = sum(len(r.findings) for r in results)
    critical = sum(
        1 for r in results
        for f in r.findings if f.severity == "critical"
    )

    print("\n" + "=" * 60)
    print("AI 엔드포인트 취약점 스캔 결과")
    print("=" * 60)
    print(f"스캔 대상: {len(results)}개 | 발견: {total_findings}건 | 치명적: {critical}건")
    print()

    for result in results:
        status = "접근 가능" if result.reachable else "접근 불가"
        auth = "인증 필요" if result.auth_required else "인증 불필요(!)"
        print(f"[{result.endpoint_type.upper()}] {result.url}")
        print(f"  상태: {status} | 인증: {auth} | 응답시간: {result.response_time_ms:.1f}ms")

        sorted_findings = sorted(result.findings, key=lambda f: severity_order(f.severity))
        for finding in sorted_findings:
            sev_icon = {"critical": "[!]", "high": "[H]", "medium": "[M]", "low": "[L]", "info": "[I]"}.get(
                finding.severity, "[?]"
            )
            print(f"  {sev_icon} {finding.vuln_type}: {finding.description}")
            if finding.recommendation:
                print(f"     권고: {finding.recommendation}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-vuln-scanner",
        description="AI 엔드포인트 취약점 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        metavar="URL",
        help="스캔할 엔드포인트 URL 목록",
    )
    parser.add_argument(
        "--targets-file",
        type=Path,
        metavar="FILE",
        help="스캔 대상 URL 목록 파일 (한 줄에 하나)",
    )
    parser.add_argument(
        "--token",
        default=None,
        metavar="TOKEN",
        help="API 인증 토큰",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="요청 타임아웃 (기본값: 10)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="병렬 스캔 워커 수 (기본값: 4)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="결과 JSON 저장 경로",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    urls: list[str] = []
    if args.targets:
        urls.extend(args.targets)
    if args.targets_file:
        if not args.targets_file.exists():
            print(f"[!] 파일을 찾을 수 없습니다: {args.targets_file}", file=sys.stderr)
            return 1
        urls.extend(
            line.strip()
            for line in args.targets_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )

    if not urls:
        print("[!] 스캔 대상이 없습니다. --targets 또는 --targets-file을 지정하세요.", file=sys.stderr)
        return 1

    print(f"[*] {len(urls)}개 엔드포인트 스캔 시작 (워커: {args.workers}개)")

    results: list[EndpointScanResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(scan_endpoint, url, args.token, args.timeout): url
            for url in urls
        }
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                result = future.result()
                results.append(result)
                print(f"  [완료] {url} — {len(result.findings)}건 발견")
            except Exception as e:
                print(f"  [오류] {url}: {e}", file=sys.stderr)

    print_scan_results(results)

    if args.output:
        import dataclasses
        args.output.parent.mkdir(parents=True, exist_ok=True)
        serialized = [dataclasses.asdict(r) for r in results]
        with args.output.open("w", encoding="utf-8") as f:
            json.dump(serialized, f, ensure_ascii=False, indent=2)
        print(f"[+] 결과 저장: {args.output}")

    critical_count = sum(
        1 for r in results for f in r.findings if f.severity == "critical"
    )
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. AI 레드팀 정찰 체크리스트

| 항목 | 확인 내용 | 우선순위 |
|---|---|---|
| 공개 모델 카드 분석 | 학습 데이터, 아키텍처 힌트, 성능 지표 | 높음 |
| API 엔드포인트 탐색 | 인증 필요 여부, 속도 제한, 오류 메시지 | 높음 |
| 모델 레지스트리 접근 | MLflow, W&B, Neptune 노출 여부 | 높음 |
| 아티팩트 저장소 검사 | S3/GCS 버킷 공개 여부, 모델 파일 접근성 | 높음 |
| CI/CD 파이프라인 분석 | 학습 스크립트, 데이터 처리 코드 노출 | 중간 |
| 모니터링 대시보드 | Grafana, Prometheus 공개 여부 | 중간 |
| 출력 분석 | 신뢰도 점수 노출 수준, 응답 정밀도 | 중간 |
| 오류 메시지 분석 | 스택 트레이스, 내부 경로 노출 | 낮음 |

---

## 참고 자료

- MITRE ATLAS: https://atlas.mitre.org/
- OWASP Machine Learning Security Top 10
- NIST AI Risk Management Framework (AI RMF)
- "Adversarial Machine Learning: A Taxonomy and Terminology" (NIST IR 8269)
