# 모델 탈취 및 멤버십 추론 (Model Extraction & Membership Inference)

## 개요

모델 추출(Model Extraction) 공격은 공개 API를 통해 타겟 모델과 기능적으로 동등한 대체 모델을 구성하는 공격이다. 멤버십 추론(Membership Inference) 공격은 특정 데이터 포인트가 모델의 학습 데이터에 포함되었는지를 판별한다. 두 공격 모두 모델의 출력(신뢰도 점수, 분류 결과)만으로 수행 가능하다는 점에서 심각한 지식재산권 침해 및 프라이버시 위협이 된다.

---

## 1. 모델 추출 공격 원리

### 1.1 공격 개요

| 단계 | 설명 | 필요 자원 |
|---|---|---|
| **쿼리 생성** | 타겟 모델 입력 공간을 커버하는 쿼리 집합 생성 | 도메인 지식, 쿼리 예산 |
| **응답 수집** | 각 쿼리에 대한 타겟 모델 응답(레이블/확률) 수집 | API 접근권, 비용 |
| **대체 모델 학습** | 수집된 (쿼리, 응답) 쌍으로 대체 모델(surrogate) 학습 | 컴퓨팅 자원 |
| **정확도 검증** | 대체 모델과 타겟 모델의 출력 일치율 측정 | 검증 데이터 |
| **반복 개선** | 불일치 영역을 집중 쿼리하여 대체 모델 개선 | 추가 쿼리 예산 |

### 1.2 쿼리 전략 비교

| 전략 | 방법 | 효율성 | 필요 쿼리 수 |
|---|---|---|---|
| **무작위 샘플링** | 입력 공간에서 무작위 쿼리 | 낮음 | 수십만 |
| **도메인 기반** | 실제 사용 패턴과 유사한 쿼리 | 중간 | 수만 |
| **능동 학습** | 불확실한 경계 영역 집중 쿼리 | 높음 | 수천 |
| **합성 데이터** | GAN/VAE로 대표 쿼리 생성 | 높음 | 수천 |
| **전이 학습 기반** | 공개 데이터셋 + 소수 쿼리 | 매우 높음 | 수백 |

### 1.3 공격 대상별 위협 수준

| 모델 유형 | 위협 수준 | 주요 이유 |
|---|---|---|
| 텍스트 분류기 | 높음 | 입력/출력 공간이 단순, 쿼리 효율 높음 |
| 이미지 분류기 | 높음 | 연속적 입력, 그라디언트 전이 가능 |
| 임베딩 모델 | 중간 | 고차원 출력이지만 구조 예측 가능 |
| 생성 LLM | 낮음 | 출력 공간이 방대, 완전 복제 어려움 |
| 추천 시스템 | 중간 | 사용자 패턴 통해 선호도 모델 추출 |

---

## 2. 멤버십 추론 공격

### 2.1 공격 원리

과적합된 모델은 학습 데이터에 대해 더 높은 신뢰도 점수를 출력하는 경향이 있다. 공격자는 이 차이를 이용하여 타겟 데이터 포인트가 학습셋에 포함되었는지 판별한다.

**공격 유형:**

| 유형 | 접근법 | 필요 정보 | 정확도 |
|---|---|---|---|
| **신뢰도 기반** | 정답 클래스 신뢰도가 임계값 초과 시 멤버로 판정 | Softmax 확률 벡터 | 중간 |
| **섀도 모델** | 동일 분포 데이터로 섀도 모델 학습, 공격 분류기 학습 | 추가 데이터, 구조 힌트 | 높음 |
| **경사 기반** | 학습 데이터는 손실이 낮고 그라디언트가 작음 | 화이트박스 접근 | 매우 높음 |
| **결정 경계** | 학습 데이터는 결정 경계에서 멀리 위치 | 추가 쿼리 | 낮음 |

### 2.2 공격 성능에 영향을 주는 요소

| 요소 | 취약성 증가 방향 | 설명 |
|---|---|---|
| 과적합 정도 | 과적합 심할수록 | train/test 정확도 차이가 클수록 공격 정확도 높음 |
| 신뢰도 출력 정밀도 | 높은 정밀도 | 소수점 이하 자릿수가 많을수록 정보 유출 증가 |
| 모델 복잡도 | 복잡할수록 | 더 많은 학습 데이터 특성을 기억 |
| 데이터셋 크기 | 작을수록 | 샘플당 더 많이 학습됨 |
| 클래스 불균형 | 불균형 심할수록 | 소수 클래스 멤버 탐지 쉬움 |

---

## 3. 모델 반전 공격 (Model Inversion)

### 3.1 개요

모델 반전 공격은 모델의 출력으로부터 학습 데이터의 대표 샘플을 복원하는 공격이다. 특히 얼굴 인식 모델에서 특정 인물의 얼굴 이미지를 재구성하는 데 사용된다.

| 공격명 | 대상 모델 | 복원 대상 | 방어 방법 |
|---|---|---|---|
| 기울기 역전 | 분류기 | 학습 이미지 | 차분 프라이버시 |
| 특성 추론 | 분류기 | 민감 속성 | 속성 제거 |
| GAN 기반 복원 | 생성 모델 | 학습 분포 | 멤버십 쿼리 제한 |
| 협업 필터링 반전 | 추천 모델 | 사용자 선호도 | 노이즈 추가 |

---

## 4. 블랙박스 모델 추출 시뮬레이터 CLI

```python
#!/usr/bin/env python3
"""
블랙박스 모델 추출 시뮬레이터
타겟 분류 API에 쿼리를 보내 대체 모델을 학습하고 추출 성공률을 측정한다.
scikit-learn으로 대체 모델을 구성하고 ThreadPoolExecutor로 병렬 쿼리를 실행한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import urllib.request
import urllib.error


# scikit-learn은 선택적 import
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


@dataclass
class QueryResult:
    """단일 쿼리 결과."""
    query_id: int
    input_features: list[float]
    predicted_label: str
    confidence_scores: dict[str, float]
    latency_ms: float
    error: str = ""


@dataclass
class ExtractionSession:
    """모델 추출 세션 전체 상태."""
    target_url: str
    total_queries: int
    successful_queries: int
    failed_queries: int
    query_results: list[QueryResult] = field(default_factory=list)
    surrogate_accuracy: float = 0.0
    agreement_rate: float = 0.0  # 타겟-대체 모델 출력 일치율
    extraction_duration_sec: float = 0.0


def send_classification_query(
    url: str,
    features: list[float],
    headers: dict[str, str],
    timeout: int,
    query_id: int,
) -> QueryResult:
    """타겟 분류 API에 단일 쿼리를 전송한다."""
    payload = json.dumps({"features": features, "query_id": query_id}).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.time() - start) * 1000
            data = json.loads(resp.read().decode())

            label = data.get("label", data.get("prediction", "unknown"))
            scores = data.get("scores", data.get("probabilities", {}))

            return QueryResult(
                query_id=query_id,
                input_features=features,
                predicted_label=str(label),
                confidence_scores=scores if isinstance(scores, dict) else {},
                latency_ms=elapsed,
            )
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start) * 1000
        return QueryResult(
            query_id=query_id,
            input_features=features,
            predicted_label="",
            confidence_scores={},
            latency_ms=elapsed,
            error=f"HTTP {e.code}: {e.reason}",
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return QueryResult(
            query_id=query_id,
            input_features=features,
            predicted_label="",
            confidence_scores={},
            latency_ms=elapsed,
            error=str(e),
        )


def generate_queries(
    n_queries: int,
    n_features: int,
    feature_min: float,
    feature_max: float,
    seed: int,
) -> list[list[float]]:
    """
    균일 분포로 쿼리 특성 벡터를 생성한다.
    numpy가 없으면 표준 라이브러리의 random 모듈을 사용한다.
    """
    if HAS_SKLEARN:
        rng = np.random.default_rng(seed)
        samples = rng.uniform(feature_min, feature_max, (n_queries, n_features))
        return samples.tolist()
    else:
        import random
        rng = random.Random(seed)
        return [
            [rng.uniform(feature_min, feature_max) for _ in range(n_features)]
            for _ in range(n_queries)
        ]


def run_parallel_queries(
    target_url: str,
    queries: list[list[float]],
    headers: dict[str, str],
    timeout: int,
    workers: int,
    delay: float,
) -> list[QueryResult]:
    """ThreadPoolExecutor로 병렬 쿼리를 실행한다."""
    results: list[QueryResult] = []
    total = len(queries)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                send_classification_query,
                target_url,
                query,
                headers,
                timeout,
                i,
            ): i
            for i, query in enumerate(queries)
        }

        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            completed += 1

            if completed % 50 == 0 or completed == total:
                success_count = sum(1 for r in results if not r.error)
                print(f"  진행: {completed}/{total} | 성공: {success_count}")

            if delay > 0 and completed < total:
                time.sleep(delay)

    # query_id 순서로 정렬
    results.sort(key=lambda r: r.query_id)
    return results


def train_surrogate_model(
    results: list[QueryResult],
    model_type: str,
) -> tuple[Any, LabelEncoder, float]:
    """
    수집된 (입력, 레이블) 쌍으로 대체 모델을 학습한다.
    반환값: (학습된 모델, 레이블 인코더, 테스트 정확도)
    """
    if not HAS_SKLEARN:
        raise RuntimeError(
            "scikit-learn이 필요합니다: pip install scikit-learn numpy"
        )

    # 유효한 결과만 필터링
    valid = [r for r in results if r.predicted_label and not r.error]
    if len(valid) < 10:
        raise ValueError(f"유효한 쿼리 결과가 너무 적습니다: {len(valid)}개")

    X = np.array([r.input_features for r in valid])
    y_raw = [r.predicted_label for r in valid]

    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "gradient_boost": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "logistic": LogisticRegression(max_iter=1000, random_state=42),
    }

    if model_type not in models:
        raise ValueError(f"지원하지 않는 모델 유형: {model_type}. 선택: {list(models.keys())}")

    clf = models[model_type]
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    return clf, le, acc


def measure_agreement_rate(
    clf,
    le: LabelEncoder,
    results: list[QueryResult],
) -> float:
    """대체 모델과 타겟 모델의 출력 일치율을 계산한다."""
    if not HAS_SKLEARN:
        return 0.0

    valid = [r for r in results if r.predicted_label and not r.error]
    if not valid:
        return 0.0

    X = np.array([r.input_features for r in valid])
    y_surrogate = le.inverse_transform(clf.predict(X))
    y_target = [r.predicted_label for r in valid]

    matches = sum(s == t for s, t in zip(y_surrogate, y_target))
    return matches / len(valid)


def save_model(clf, le: LabelEncoder, output_path: Path) -> None:
    """학습된 대체 모델을 파일로 저장한다."""
    try:
        import pickle
        model_data = {"classifier": clf, "label_encoder": le}
        with output_path.open("wb") as f:
            pickle.dump(model_data, f)
        print(f"[+] 대체 모델 저장: {output_path}")
    except Exception as e:
        print(f"[!] 모델 저장 실패: {e}", file=sys.stderr)


def print_extraction_report(session: ExtractionSession) -> None:
    """추출 세션 결과를 출력한다."""
    print("\n" + "=" * 60)
    print("모델 추출 시뮬레이션 결과")
    print("=" * 60)
    print(f"타겟 URL       : {session.target_url}")
    print(f"총 쿼리        : {session.total_queries}개")
    print(f"성공 쿼리      : {session.successful_queries}개")
    print(f"실패 쿼리      : {session.failed_queries}개")
    print(f"소요 시간      : {session.extraction_duration_sec:.1f}초")
    print()
    if session.surrogate_accuracy > 0:
        print(f"대체 모델 정확도  : {session.surrogate_accuracy * 100:.1f}%")
        print(f"타겟-대체 일치율  : {session.agreement_rate * 100:.1f}%")
        print()
        if session.agreement_rate >= 0.9:
            print("[!] 높은 일치율 — 모델 추출 성공 가능성 높음")
        elif session.agreement_rate >= 0.7:
            print("[~] 중간 일치율 — 추가 쿼리로 개선 가능")
        else:
            print("[ ] 낮은 일치율 — 더 많은 쿼리 또는 다른 전략 필요")
    print("=" * 60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="model-extractor",
        description="블랙박스 모델 추출 시뮬레이터",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python 03_model_extraction.py \\
      --target-url http://ml-api.internal/predict \\
      --queries 1000 \\
      --n-features 10 \\
      --output-model surrogate.pkl

  python 03_model_extraction.py \\
      --target-url http://ml-api.internal/predict \\
      --queries 5000 \\
      --workers 8 \\
      --surrogate-type gradient_boost \\
      --output-model surrogate.pkl \\
      --output-data collected_queries.json
        """,
    )
    parser.add_argument(
        "--target-url",
        required=True,
        metavar="URL",
        help="타겟 분류 API 엔드포인트",
    )
    parser.add_argument(
        "--queries",
        type=int,
        default=500,
        metavar="N",
        help="총 쿼리 수 (기본값: 500)",
    )
    parser.add_argument(
        "--n-features",
        type=int,
        default=10,
        metavar="N",
        help="입력 특성 벡터 차원 수 (기본값: 10)",
    )
    parser.add_argument(
        "--feature-min",
        type=float,
        default=0.0,
        metavar="VAL",
        help="특성 값 최솟값 (기본값: 0.0)",
    )
    parser.add_argument(
        "--feature-max",
        type=float,
        default=1.0,
        metavar="VAL",
        help="특성 값 최댓값 (기본값: 1.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="병렬 워커 수 (기본값: 4)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="요청 타임아웃 (기본값: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        metavar="SEC",
        help="요청 간 지연 시간 (기본값: 0.1)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API 인증 키",
    )
    parser.add_argument(
        "--surrogate-type",
        choices=["random_forest", "gradient_boost", "logistic"],
        default="random_forest",
        help="대체 모델 유형 (기본값: random_forest)",
    )
    parser.add_argument(
        "--output-model",
        type=Path,
        default=None,
        metavar="FILE",
        help="대체 모델 저장 경로 (.pkl)",
    )
    parser.add_argument(
        "--output-data",
        type=Path,
        default=None,
        metavar="FILE",
        help="수집된 쿼리 데이터 저장 경로 (.json)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        metavar="N",
        help="난수 시드 (기본값: 42)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    print(f"[*] 모델 추출 시뮬레이션 시작")
    print(f"    타겟: {args.target_url}")
    print(f"    쿼리: {args.queries}개 | 특성: {args.n_features}차원 | 워커: {args.workers}개")

    # 쿼리 생성
    print("[*] 쿼리 생성 중...")
    queries = generate_queries(
        args.queries, args.n_features,
        args.feature_min, args.feature_max, args.seed
    )

    # 병렬 쿼리 실행
    print("[*] 타겟 API 쿼리 중...")
    start_time = time.time()
    results = run_parallel_queries(
        args.target_url, queries, headers,
        args.timeout, args.workers, args.delay
    )
    elapsed = time.time() - start_time

    successful = [r for r in results if not r.error]
    failed = [r for r in results if r.error]

    session = ExtractionSession(
        target_url=args.target_url,
        total_queries=len(results),
        successful_queries=len(successful),
        failed_queries=len(failed),
        query_results=results,
        extraction_duration_sec=elapsed,
    )

    # 수집 데이터 저장
    if args.output_data:
        args.output_data.parent.mkdir(parents=True, exist_ok=True)
        serialized = [asdict(r) for r in results]
        with args.output_data.open("w", encoding="utf-8") as f:
            json.dump(serialized, f, ensure_ascii=False, indent=2)
        print(f"[+] 쿼리 데이터 저장: {args.output_data}")

    # 대체 모델 학습
    if HAS_SKLEARN and len(successful) >= 10:
        print(f"\n[*] 대체 모델 학습 중 ({args.surrogate_type})...")
        try:
            clf, le, acc = train_surrogate_model(successful, args.surrogate_type)
            session.surrogate_accuracy = acc
            session.agreement_rate = measure_agreement_rate(clf, le, successful)

            if args.output_model:
                save_model(clf, le, args.output_model)
        except (ValueError, RuntimeError) as e:
            print(f"[!] 모델 학습 실패: {e}", file=sys.stderr)
    elif not HAS_SKLEARN:
        print("[!] scikit-learn 미설치 — 모델 학습 건너뜀")
    else:
        print(f"[!] 유효한 결과 부족 ({len(successful)}개) — 모델 학습 건너뜀")

    print_extraction_report(session)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. 멤버십 추론 테스터

```python
#!/usr/bin/env python3
"""
멤버십 추론 공격 테스터
타겟 모델의 출력 신뢰도를 분석하여 특정 샘플이 학습 데이터에
포함되었는지를 판별하는 섀도 모델 기반 공격을 시뮬레이션한다.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import urllib.request
import urllib.error


@dataclass
class MembershipQuery:
    """멤버십 추론 쿼리."""
    sample_id: str
    features: list[float]
    is_member: bool | None = None  # 실제 멤버십 (검증용, 실제 공격에서는 None)


@dataclass
class MembershipResult:
    """멤버십 추론 결과."""
    sample_id: str
    features: list[float]
    max_confidence: float
    predicted_member: bool
    true_member: bool | None
    correct: bool | None  # true_member가 있을 때만 유효
    confidence_gap: float  # max - second_max
    error: str = ""


def query_confidence(
    url: str,
    features: list[float],
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    """타겟 모델에 쿼리하여 신뢰도 점수를 반환한다."""
    payload = json.dumps({"features": features}).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"연결 오류: {e.reason}")


def infer_membership(
    url: str,
    query: MembershipQuery,
    headers: dict[str, str],
    timeout: int,
    threshold: float,
) -> MembershipResult:
    """
    신뢰도 임계값 기반 멤버십 추론을 수행한다.
    최고 신뢰도가 임계값을 초과하면 멤버로 판정한다.
    """
    try:
        response = query_confidence(url, query.features, headers, timeout)
        scores = response.get("scores", response.get("probabilities", {}))

        if not scores:
            # 단일 신뢰도 값인 경우
            confidence = float(response.get("confidence", response.get("score", 0.0)))
            max_conf = confidence
            second_max = 0.0
        else:
            if isinstance(scores, list):
                score_values = [float(s) for s in scores]
            elif isinstance(scores, dict):
                score_values = [float(v) for v in scores.values()]
            else:
                score_values = [0.0]

            score_values.sort(reverse=True)
            max_conf = score_values[0] if score_values else 0.0
            second_max = score_values[1] if len(score_values) > 1 else 0.0

        predicted_member = max_conf >= threshold
        correct = None
        if query.is_member is not None:
            correct = (predicted_member == query.is_member)

        return MembershipResult(
            sample_id=query.sample_id,
            features=query.features,
            max_confidence=max_conf,
            predicted_member=predicted_member,
            true_member=query.is_member,
            correct=correct,
            confidence_gap=max_conf - second_max,
        )
    except RuntimeError as e:
        return MembershipResult(
            sample_id=query.sample_id,
            features=query.features,
            max_confidence=0.0,
            predicted_member=False,
            true_member=query.is_member,
            correct=None,
            confidence_gap=0.0,
            error=str(e),
        )


def load_samples_from_json(path: Path) -> list[MembershipQuery]:
    """JSON 파일에서 샘플 목록을 로드한다."""
    data = json.loads(path.read_text(encoding="utf-8"))
    queries: list[MembershipQuery] = []
    for item in data:
        queries.append(MembershipQuery(
            sample_id=str(item.get("id", len(queries))),
            features=item["features"],
            is_member=item.get("is_member"),  # 검증용 레이블 (optional)
        ))
    return queries


def print_membership_report(results: list[MembershipResult], threshold: float) -> None:
    """멤버십 추론 결과를 출력한다."""
    valid = [r for r in results if not r.error]
    members = [r for r in valid if r.predicted_member]
    non_members = [r for r in valid if not r.predicted_member]

    print("\n" + "=" * 60)
    print("멤버십 추론 공격 결과")
    print("=" * 60)
    print(f"임계값         : {threshold:.2f}")
    print(f"총 샘플        : {len(results)}개")
    print(f"멤버 예측      : {len(members)}개")
    print(f"비멤버 예측    : {len(non_members)}개")
    print(f"오류           : {sum(1 for r in results if r.error)}개")

    # 실제 레이블이 있는 경우 정확도 계산
    labeled = [r for r in valid if r.true_member is not None]
    if labeled:
        correct = [r for r in labeled if r.correct]
        acc = len(correct) / len(labeled) if labeled else 0
        tp = sum(1 for r in labeled if r.predicted_member and r.true_member)
        fp = sum(1 for r in labeled if r.predicted_member and not r.true_member)
        tn = sum(1 for r in labeled if not r.predicted_member and not r.true_member)
        fn = sum(1 for r in labeled if not r.predicted_member and r.true_member)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0

        print()
        print("[검증 결과 (레이블 보유 샘플)]")
        print(f"  전체 정확도 : {acc * 100:.1f}%")
        print(f"  정밀도      : {precision * 100:.1f}%")
        print(f"  재현율      : {recall * 100:.1f}%")
        print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")

    # 상위 신뢰도 멤버 샘플 목록
    if members:
        print()
        print("[높은 신뢰도 멤버 예측 (상위 5개)]")
        top_members = sorted(members, key=lambda r: r.max_confidence, reverse=True)[:5]
        for r in top_members:
            print(f"  [{r.sample_id}] 신뢰도={r.max_confidence:.4f} | 격차={r.confidence_gap:.4f}")

    print("=" * 60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="membership-inference",
        description="멤버십 추론 공격 테스터",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target-url",
        required=True,
        metavar="URL",
        help="타겟 모델 API 엔드포인트",
    )
    parser.add_argument(
        "--samples-file",
        type=Path,
        required=True,
        metavar="FILE",
        help="샘플 JSON 파일 경로",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.8,
        metavar="FLOAT",
        help="멤버십 판정 신뢰도 임계값 (기본값: 0.8)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="병렬 워커 수 (기본값: 4)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="요청 타임아웃 (기본값: 10)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API 인증 키",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="결과 JSON 저장 경로",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.samples_file.exists():
        print(f"[!] 샘플 파일을 찾을 수 없습니다: {args.samples_file}", file=sys.stderr)
        return 1

    try:
        queries = load_samples_from_json(args.samples_file)
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[!] 샘플 파일 파싱 오류: {e}", file=sys.stderr)
        return 1

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    print(f"[*] 멤버십 추론 시작: {len(queries)}개 샘플")

    results: list[MembershipResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(
                infer_membership,
                args.target_url,
                query,
                headers,
                args.timeout,
                args.threshold,
            ): query.sample_id
            for query in queries
        }
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)

    print_membership_report(results, args.threshold)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import dataclasses
        with args.output.open("w", encoding="utf-8") as f:
            json.dump([dataclasses.asdict(r) for r in results], f, ensure_ascii=False, indent=2)
        print(f"[+] 결과 저장: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 6. 방어 전략

| 방어 기법 | 대응 공격 | 구현 비용 | 성능 영향 |
|---|---|---|---|
| **쿼리 속도 제한** | 모델 추출 | 낮음 | 없음 |
| **출력 정밀도 감소** | 멤버십 추론, 모델 추출 | 낮음 | 낮음 |
| **차분 프라이버시** | 멤버십 추론, 모델 역전 | 높음 | 중간 |
| **출력 노이즈 추가** | 멤버십 추론 | 낮음 | 낮음 |
| **예측 앙상블** | 모델 추출 | 중간 | 중간 |
| **워터마킹** | 모델 추출 탐지 | 중간 | 낮음 |
| **이상 쿼리 탐지** | 모델 추출 | 중간 | 없음 |
| **API 접근 인증** | 모든 공격 | 낮음 | 없음 |

---

## 참고 자료

- "Stealing Machine Learning Models via Prediction APIs" (Tramèr et al., 2016)
- "Membership Inference Attacks Against Machine Learning Models" (Shokri et al., 2017)
- "Model Inversion Attacks that Exploit Confidence Information and Basic Countermeasures" (Fredrikson et al., 2015)
- MLSecurity.org — 모델 보안 연구 동향
