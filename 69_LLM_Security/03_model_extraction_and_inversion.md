> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 모델 추출 및 역공학

## 모델 추출 공격이란?

**비유:** 레스토랑에서 음식을 계속 주문하며 조리법을 역추적하는 것과 같다. 모델에 수천 번의 쿼리를 날려 입력-출력 쌍을 수집하고, 이를 바탕으로 "대리 모델(surrogate model)"을 훈련시켜 원본 모델의 동작을 복제한다.

---

## 공격 유형

### 1. 모델 추출 (Model Extraction)
공격자가 API를 반복 호출하여 입출력 쌍을 대량 수집한다. 수집된 데이터로 경량 모델을 파인튜닝하면 원본 모델의 기능을 저비용으로 복제할 수 있다.

```
공격 흐름:
공격자 ──[쿼리 1000+번]──▶ LLM API
         ◀──[응답 수집]──
공격자 ──[수집 데이터로 학습]──▶ 대리 모델 생성
```

**피해:** 지적재산 도용, API 비용 폭증, 안전장치 없는 클론 모델 생성

### 2. 훈련 데이터 유출 (Training Data Memorization)
LLM은 훈련 데이터를 일부 "암기"한다. 특정 프리픽스를 제공하면 모델이 훈련 데이터 중 해당 패턴과 일치하는 텍스트를 재생성할 수 있다.

```
공격자 입력: "주민등록번호: 900101-"
모델 출력:   "900101-1234567" (훈련 데이터에 포함된 경우)
```

### 3. 임베딩 역공학 (Embedding Inversion)
텍스트 임베딩 벡터를 원문 텍스트로 역변환하려는 시도다. 최근 연구에서 임베딩만으로 원문의 상당 부분을 복원할 수 있음이 밝혀졌다.

```
원문 텍스트 → [임베딩 모델] → 벡터 [0.23, -0.17, 0.88, ...]
                                        ↓ (역공학 시도)
                               복원 텍스트: "원문과 유사한 텍스트"
```

---

## 방어 전략

| 위협 | 방어책 |
|------|--------|
| 모델 추출 | API 속도 제한, 쿼리 수 제한, 응답 다양화, 워터마킹 |
| 데이터 유출 | 훈련 전 PII 제거, 차등 프라이버시(DP) 적용 |
| 임베딩 역공학 | 임베딩 차원 축소, 노이즈 추가, 접근 제어 |

---

## 실습 코드: 모델 응답 유사도 분석기 + 멤버십 추론 시뮬레이터

```python
#!/usr/bin/env python3
"""
모델 추출 및 역공학 실습 도구
사용법: python3 03_model_extraction_and_inversion.py --mode similarity --text1 "A" --text2 "B"
        python3 03_model_extraction_and_inversion.py --mode membership --corpus corpus.txt --query "검사할 문장"
        python3 03_model_extraction_and_inversion.py --mode extraction --queries queries.txt --output results.json
"""

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# ── 텍스트 유사도 계산 ────────────────────────────────────────────────────────

def tokenize(text: str) -> list[str]:
    """간단한 n-gram 기반 토크나이저"""
    text = text.lower()
    tokens = re.findall(r"\b\w+\b", text)
    return tokens


def tf_idf_vector(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = Counter(tokens)
    total = len(tokens) or 1
    return {t: (c / total) * idf.get(t, 1.0) for t, c in tf.items()}


def cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    keys = set(vec_a) | set(vec_b)
    dot = sum(vec_a.get(k, 0.0) * vec_b.get(k, 0.0) for k in keys)
    norm_a = math.sqrt(sum(v ** 2 for v in vec_a.values())) or 1e-9
    norm_b = math.sqrt(sum(v ** 2 for v in vec_b.values())) or 1e-9
    return dot / (norm_a * norm_b)


def compute_similarity(text_a: str, text_b: str) -> float:
    tokens_a = tokenize(text_a)
    tokens_b = tokenize(text_b)
    all_tokens = set(tokens_a) | set(tokens_b)
    idf = {t: 1.0 for t in all_tokens}  # 단순화된 IDF
    vec_a = tf_idf_vector(tokens_a, idf)
    vec_b = tf_idf_vector(tokens_b, idf)
    return cosine_similarity(vec_a, vec_b)


# ── 멤버십 추론 시뮬레이터 ───────────────────────────────────────────────────

@dataclass
class MembershipResult:
    query: str
    max_similarity: float
    best_match: str
    is_likely_member: bool
    confidence: str

    def display(self) -> None:
        print(f"\n[멤버십 추론 결과]")
        print(f"  쿼리          : {self.query[:60]}")
        print(f"  최대 유사도   : {self.max_similarity:.4f}")
        print(f"  가장 유사한 문장: {self.best_match[:60]}")
        print(f"  훈련 데이터 포함 가능성: {'높음' if self.is_likely_member else '낮음'}")
        print(f"  신뢰도        : {self.confidence}")


def membership_inference(query: str, corpus: list[str], threshold: float = 0.85) -> MembershipResult:
    """
    멤버십 추론 공격 시뮬레이션:
    쿼리가 코퍼스(훈련 데이터)에 포함되었을 가능성을 유사도로 추정한다.
    """
    if not corpus:
        return MembershipResult(query, 0.0, "", False, "N/A")

    similarities = [(compute_similarity(query, doc), doc) for doc in corpus]
    similarities.sort(key=lambda x: x[0], reverse=True)
    max_sim, best_doc = similarities[0]

    is_member = max_sim >= threshold
    if max_sim >= 0.95:
        confidence = "매우 높음"
    elif max_sim >= 0.85:
        confidence = "높음"
    elif max_sim >= 0.70:
        confidence = "중간"
    else:
        confidence = "낮음"

    return MembershipResult(
        query=query,
        max_similarity=round(max_sim, 4),
        best_match=best_doc,
        is_likely_member=is_member,
        confidence=confidence,
    )


# ── 모델 추출 시뮬레이터 ─────────────────────────────────────────────────────

@dataclass
class QueryRecord:
    query: str
    response: str
    similarity_to_prev: float = 0.0
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.fingerprint = hashlib.sha256(
            (self.query + self.response).encode()
        ).hexdigest()[:16]


@dataclass
class ExtractionSession:
    records: list[QueryRecord] = field(default_factory=list)
    unique_responses: int = 0
    diversity_score: float = 0.0

    def add_record(self, query: str, response: str) -> QueryRecord:
        sim = 0.0
        if self.records:
            sim = compute_similarity(response, self.records[-1].response)
        record = QueryRecord(query=query, response=response, similarity_to_prev=sim)
        self.records.append(record)
        self._update_stats()
        return record

    def _update_stats(self) -> None:
        fps = {r.fingerprint for r in self.records}
        self.unique_responses = len(fps)
        if len(self.records) > 1:
            sims = [r.similarity_to_prev for r in self.records[1:]]
            avg_sim = sum(sims) / len(sims)
            self.diversity_score = round(1.0 - avg_sim, 4)
        else:
            self.diversity_score = 1.0

    def extraction_risk_score(self) -> float:
        """
        추출 공격 위험도 점수 (0.0 ~ 1.0)
        - 쿼리 수가 많을수록
        - 응답 다양성이 높을수록
        위험도 증가
        """
        query_factor = min(len(self.records) / 1000.0, 1.0)
        diversity_factor = self.diversity_score
        return round((query_factor * 0.6 + diversity_factor * 0.4), 4)

    def summary(self) -> str:
        return (
            f"[모델 추출 세션 요약]\n"
            f"  총 쿼리 수       : {len(self.records)}\n"
            f"  고유 응답 수     : {self.unique_responses}\n"
            f"  응답 다양성 점수 : {self.diversity_score}\n"
            f"  추출 위험도      : {self.extraction_risk_score()}\n"
        )


def load_queries_file(path: Path) -> list[str]:
    if not path.exists():
        print(f"[오류] 파일 없음: {path}", file=sys.stderr)
        sys.exit(1)
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def simulate_model_response(query: str) -> str:
    """
    실제 LLM API 없이 로컬에서 결정론적 응답 시뮬레이션
    (테스트/교육 목적)
    """
    h = int(hashlib.md5(query.encode()).hexdigest(), 16)
    templates = [
        f"'{query}'에 대한 응답입니다. 이 주제는 {len(query)}글자로 구성되어 있습니다.",
        f"질문을 분석한 결과, 핵심 키워드는 '{query.split()[0] if query.split() else query}'입니다.",
        f"제공된 정보를 바탕으로, '{query[:20]}...'에 대해 설명하겠습니다.",
        f"이 쿼리({len(query.split())}개 단어)의 답변: 더 많은 컨텍스트가 필요합니다.",
    ]
    return templates[h % len(templates)]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="모델 추출 및 역공학 실습 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # 유사도 분석 모드
    p_sim = sub.add_parser("similarity", help="두 텍스트 유사도 계산")
    p_sim.add_argument("--text1", required=True, help="첫 번째 텍스트")
    p_sim.add_argument("--text2", required=True, help="두 번째 텍스트")

    # 멤버십 추론 모드
    p_mem = sub.add_parser("membership", help="훈련 데이터 포함 여부 추론")
    p_mem.add_argument("--corpus", type=Path, required=True, help="코퍼스 파일 (한 줄 = 한 문장)")
    p_mem.add_argument("--query", required=True, help="추론할 쿼리 텍스트")
    p_mem.add_argument("--threshold", type=float, default=0.85, help="멤버 판정 임계값 (기본: 0.85)")

    # 모델 추출 시뮬레이션 모드
    p_ext = sub.add_parser("extraction", help="모델 추출 공격 시뮬레이션")
    p_ext.add_argument("--queries", type=Path, required=True, help="쿼리 목록 파일")
    p_ext.add_argument("--output", type=Path, default=Path("extraction_results.json"), help="결과 저장 파일")

    args = parser.parse_args()

    match args.mode:
        case "similarity":
            sim = compute_similarity(args.text1, args.text2)
            print(f"\n[유사도 분석]")
            print(f"  텍스트 A: {args.text1[:50]}")
            print(f"  텍스트 B: {args.text2[:50]}")
            print(f"  코사인 유사도: {sim:.4f}")
            if sim > 0.9:
                print("  → 매우 유사 (모델 응답 중복 가능성 높음)")
            elif sim > 0.7:
                print("  → 유사 (동일 의미일 수 있음)")
            else:
                print("  → 상이 (다른 주제)")

        case "membership":
            corpus_lines = load_queries_file(args.corpus)
            result = membership_inference(args.query, corpus_lines, args.threshold)
            result.display()

        case "extraction":
            queries = load_queries_file(args.queries)
            session = ExtractionSession()
            print(f"\n[모델 추출 시뮬레이션] {len(queries)}개 쿼리 처리 중...")
            for q in queries:
                resp = simulate_model_response(q)
                rec = session.add_record(q, resp)
                print(f"  [{rec.fingerprint}] {q[:40]!r} → {resp[:40]!r}")

            print(f"\n{session.summary()}")
            risk = session.extraction_risk_score()
            if risk > 0.7:
                print("[경고] 높은 추출 위험도 감지! 속도 제한 강화 권장.")

            output_data = {
                "total_queries": len(session.records),
                "unique_responses": session.unique_responses,
                "diversity_score": session.diversity_score,
                "extraction_risk": risk,
                "records": [asdict(r) for r in session.records],
            }
            args.output.write_text(json.dumps(output_data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"결과 저장됨: {args.output}")

        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# Model Extraction and Inversion

## What is Model Extraction?

**Analogy:** Imagine ordering every dish at a restaurant hundreds of times to reverse-engineer the recipes. An attacker sends thousands of queries to an LLM API, collects input-output pairs, and fine-tunes a cheap surrogate model that mimics the original — stealing its capabilities at a fraction of the cost.

---

## Attack Types

### Model Extraction
Repeatedly querying the API to collect (input, output) pairs. The attacker trains a surrogate model on these pairs, reproducing the target model's behavior.

**Impact:** IP theft, API cost explosion, safety-guideline-free clone models.

### Training Data Memorization
LLMs memorize portions of their training data. Providing a specific prefix can cause the model to regenerate verbatim text — including PII, credentials, or copyrighted content — if it appeared in training.

### Embedding Inversion
Recent research shows that embedding vectors can be partially inverted to recover the original text. Systems exposing raw embeddings via API are vulnerable to this attack.

---

## Defense Strategies

| Threat | Countermeasure |
|--------|----------------|
| Model extraction | Rate limiting, query caps, output randomization, model watermarking |
| Data memorization | Pre-training PII scrubbing, differential privacy (DP-SGD) |
| Embedding inversion | Dimensionality reduction before exposure, add Gaussian noise, strict access control |

---

## Tool Usage

The Python tool above provides three sub-commands:

```bash
# Measure cosine similarity between two model responses
python3 03_model_extraction_and_inversion.py similarity \
  --text1 "The sky is blue" --text2 "The sky appears blue"

# Membership inference: did this sentence appear in the training corpus?
python3 03_model_extraction_and_inversion.py membership \
  --corpus training_data.txt --query "John Doe's SSN is 123-45-6789" \
  --threshold 0.85

# Simulate a model extraction session from a query list
python3 03_model_extraction_and_inversion.py extraction \
  --queries attack_queries.txt --output session_results.json
```

The extraction risk score formula weighs query volume (60%) and response diversity (40%), giving defenders a metric to trigger rate-limiting or alerting.
