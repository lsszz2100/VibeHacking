> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 31-03. 모델 추출·멤버십 추론·데이터 재구성 — 모델에서 새어 나오는 것들

## 0. 초보자를 위한 개념 이해

### AI 모델에서 "정보가 새어나간다"는 것은?

AI/ML 모델은 단순한 수식이 아닙니다. 학습 데이터의 패턴을 "기억"하고 있습니다. 이 기억에서 정보를 추출하는 공격들입니다.

```
비유: 의사가 환자 정보를 학습한 AI
  환자 A의 혈압, 심박수, 나이... 수천 명 학습
  
  공격자가 물어봄:
  "이 혈압 데이터로 환자 A가 당뇨병인지 예측해줘"
  → AI가 학습 데이터를 기반으로 응답
  → 실제 환자 A의 의료 정보가 유추됨 (멤버십 추론)
```

### 세 가지 주요 공격 이해

**1. 모델 추출 (Model Extraction):**
```
대기업이 수년간 학습시킨 AI 모델 (수억 원 가치)
→ 공격자가 API로 수천 번 질문
→ 응답 패턴에서 모델 복제
→ 무료로 비슷한 모델 획득
```

**2. 멤버십 추론 (Membership Inference):**
```
병원 AI가 환자 데이터로 학습됨
→ "이 사람이 학습 데이터에 있었나?"를 추론
→ 그 환자가 그 병원을 방문했다는 사실 유출
→ 프라이버시 침해 (GDPR 위반 가능)
```

**3. 학습 데이터 추출:**
```
GPT 같은 언어 모델에게 반복 질문
→ "당신이 학습한 내용을 그대로 말해줘"
→ 저작권 있는 텍스트, 개인정보가 그대로 나옴
→ 실제 ChatGPT에서 개인정보 유출 사례 있음
```

> **관점 전환**: 지금까지는 "모델을 속이는" 공격이었다면, 여기서부터는 **"모델에서 뭔가를 빼내는"** 공격이다.
> 가중치, 학습 데이터, 프라이버시. 가장 조용하면서 가장 비싼 피해를 낸다.

## 1. 공격 분류 — 뭘 빼내는가

| 공격 | 훔치는 것 | 공격자 필요 조건 |
|------|-----------|------------------|
| **Model Extraction** | 모델 자체 (복제) | 쿼리 API 접근 |
| **Membership Inference** | 특정 샘플이 학습셋에 있었는지 Yes/No | 예측 확률 또는 신뢰도 |
| **Attribute Inference** | 샘플에 대한 숨겨진 속성 (예: 성별) | 부분 샘플 + 쿼리 |
| **Training Data Extraction** | 학습 데이터 원본 조각 | 생성형 모델 접근 |
| **Model Inversion** | 특정 클래스의 대표 샘플 재구성 | 기울기 또는 확률 |

실무적 비중: **멤버십 추론 ≫ 모델 추출 ≫ 데이터 재구성** 순서로 현실적이다.

## 2. 모델 추출 (Model Extraction / Stealing)

### 2.1 공격 원리

Tramer et al. (2016)의 핵심 관찰: 충분히 많은 입출력 쌍 $(x_i, f(x_i))$ 만 있으면, 공격자는 **지도 학습으로 원본 모델을 근사**할 수 있다. 표적 모델이 블랙박스여도 상관없다.

현대 LLM/비전 API에 대한 공격은:
1. **대용량 공개 데이터셋**에서 샘플을 뽑아 표적 API로 레이블을 얻는다.
2. 얻은 (입력, 확률) 쌍으로 **대체 모델(surrogate)** 을 학습한다.
3. 대체 모델로 적대적 예제·데이터 분석·내부 구조 추정까지 이어간다.

### 2.2 재현용 데모 — 작은 분류기 복제

CIFAR-10 분류기를 "블랙박스 API"로 두고, 다른 네트워크로 복제한다.

```python
#!/usr/bin/env python3
"""model_extraction_demo.py — 블랙박스 분류기를 쿼리해 대체 모델을 학습한다."""
from __future__ import annotations

import argparse

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from torchvision import datasets, transforms


class Victim(nn.Module):
    """학습된 '피해자' 모델을 외부에서는 블랙박스로만 본다고 가정."""
    def __init__(self) -> None:
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
        )
        self.fc = nn.Sequential(nn.Flatten(), nn.Linear(128 * 8 * 8, 256), nn.ReLU(), nn.Linear(256, 10))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(self.conv(x))


class Surrogate(nn.Module):
    """공격자가 학습시키는 대체 모델. 피해자와 구조가 달라도 된다."""
    def __init__(self) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Flatten(), nn.Linear(64 * 8 * 8, 128), nn.ReLU(), nn.Linear(128, 10),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def query_victim(victim: nn.Module, x: torch.Tensor, soft_labels: bool) -> torch.Tensor:
    victim.eval()
    with torch.no_grad():
        logits = victim(x)
        return F.softmax(logits, dim=1) if soft_labels else logits.argmax(1)


def extract(
    victim: nn.Module,
    query_budget: int,
    soft_labels: bool,
    device: torch.device,
    epochs: int = 20,
) -> Surrogate:
    tfm = transforms.Compose([transforms.ToTensor()])
    pool = datasets.CIFAR10("./data", train=True, download=True, transform=tfm)

    # 공격자는 쿼리 예산만큼만 피해자에 질의
    idx = torch.randperm(len(pool))[:query_budget]
    x_queries = torch.stack([pool[i][0] for i in idx]).to(device)
    y_stolen = query_victim(victim.to(device), x_queries, soft_labels)

    loader = DataLoader(TensorDataset(x_queries.cpu(), y_stolen.cpu()), batch_size=128, shuffle=True)
    surrogate = Surrogate().to(device)
    optim = torch.optim.Adam(surrogate.parameters(), lr=1e-3)
    loss_fn = (lambda p, t: F.kl_div(F.log_softmax(p, 1), t, reduction="batchmean")) if soft_labels \
              else F.cross_entropy

    for epoch in range(epochs):
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            loss = loss_fn(surrogate(xb), yb)
            optim.zero_grad(); loss.backward(); optim.step()
        print(f"  epoch {epoch+1:2d}  loss={loss.item():.4f}")
    return surrogate


def fidelity(victim: nn.Module, surrogate: nn.Module, device: torch.device) -> float:
    tfm = transforms.Compose([transforms.ToTensor()])
    test = datasets.CIFAR10("./data", train=False, download=True, transform=tfm)
    loader = DataLoader(test, batch_size=256)
    agree = total = 0
    victim.eval(); surrogate.eval()
    with torch.no_grad():
        for xb, _ in loader:
            xb = xb.to(device)
            agree += (victim(xb).argmax(1) == surrogate(xb).argmax(1)).sum().item()
            total += xb.size(0)
    return agree / total


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=5000, help="쿼리 예산")
    ap.add_argument("--soft", action="store_true", help="소프트 레이블(확률) 추출")
    ap.add_argument("--victim-ckpt", type=str, required=True, help="사전학습된 피해자 체크포인트")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    victim = Victim().to(device)
    victim.load_state_dict(torch.load(args.victim_ckpt, map_location=device))

    surrogate = extract(victim, args.budget, args.soft, device)
    fid = fidelity(victim, surrogate, device)
    print(f"\n[+] Fidelity (agreement on test set): {fid:.2%}")


if __name__ == "__main__":
    main()
```

**경험적 감각**:
- 소프트 레이블(확률 벡터)로 추출하면 **1/10 예산으로 같은 충실도**가 나온다.
- 하드 레이블만 반환해도 쿼리가 많으면 결국 복제된다.
- "우리 API는 top-1 라벨만 반환하니까 안전하다"는 흔한 오해. 충분히 조금만 막는다.

### 2.3 방어

- **예측 확률 왜곡**: Top-k 마스킹, 라벨 스무딩, 가우시안 노이즈 추가
- **쿼리 레이트 제한 & 이상 탐지**: 동일 IP/토큰이 분포 밖 입력을 대량 질의하면 flag
- **가상 예산**: 토큰당 쿼리 예산 + 이상 사용 과금
- **워터마킹**: 특정 트리거 입력에 대해 모델이 고유한 서명을 남기도록 학습시키고, 의심 모델에 같은 트리거를 넣어 복제 여부 탐지

학계 벤치마크: PRADA, VarDetect, SEAT 등. 방어는 아직 공격 우위다.

## 3. 멤버십 추론 (Membership Inference Attack, MIA)

### 3.1 왜 위험한가

"이 환자 기록이 학습 데이터에 있었는가?" 라는 질문이 Yes/No로 답해지면 **프라이버시 규제(GDPR, 개인정보보호법) 위반**으로 직결된다. 기업 입장에서는 집단소송 리스크.

### 3.2 기본 원리 — Shokri et al. (2017)

학습에 사용된 샘플은 loss가 **더 낮고, 확률이 더 뾰족**하다. 이 통계적 차이를 분류기로 학습해 member/non-member를 구분한다.

### 3.3 최소 재현 코드 — 임계값 기반 공격 (Yeom et al., 2018)

```python
#!/usr/bin/env python3
"""mia_threshold.py — 손실 기반 멤버십 추론."""
from __future__ import annotations

import argparse
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score
from torch.utils.data import DataLoader
from torchvision import datasets, transforms


@torch.no_grad()
def per_sample_loss(model: torch.nn.Module, loader: DataLoader, device: torch.device) -> np.ndarray:
    model.eval()
    losses: list[float] = []
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        logits = model(xb)
        l = F.cross_entropy(logits, yb, reduction="none")
        losses.extend(l.cpu().numpy())
    return np.asarray(losses)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", required=True, help="타깃 모델 체크포인트 (CIFAR-10)")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    tfm = transforms.Compose([transforms.ToTensor()])

    # 공격자는 학습셋/비학습셋 혼합 대조군을 갖는다고 가정
    train = datasets.CIFAR10("./data", train=True, download=True, transform=tfm)
    test = datasets.CIFAR10("./data", train=False, download=True, transform=tfm)

    model = torch.load(args.ckpt, map_location=device)
    ltrain = per_sample_loss(model, DataLoader(train, batch_size=256), device)
    ltest = per_sample_loss(model, DataLoader(test, batch_size=256), device)

    labels = np.concatenate([np.ones_like(ltrain), np.zeros_like(ltest)])
    scores = -np.concatenate([ltrain, ltest])  # 낮은 loss = 멤버일 확률 ↑
    auc = roc_auc_score(labels, scores)
    print(f"MIA AUC = {auc:.4f}   (0.5=random, >0.6=leak)")


if __name__ == "__main__":
    main()
```

**해석**:
- AUC 0.5 → 구분 불가 (좋음)
- AUC 0.6~0.7 → 과적합 + 프라이버시 누수 의심
- AUC > 0.8 → 심각. 학습 데이터에 PII가 있으면 고지 의무 발생 가능

### 3.4 LiRA — 현재의 강력한 베이스라인

Carlini et al. (2022)의 **Likelihood Ratio Attack**:
공격자가 **섀도우 모델**을 여러 개 학습시켜 각 샘플 $x$의 loss 분포를 "멤버일 때"와 "비멤버일 때"로 구한 뒤, 표적 모델의 loss를 두 분포에 대한 likelihood ratio로 평가한다. 이전 임계값 공격보다 훨씬 강하다.

```bash
pip install adversarial-robustness-toolbox
```
ART의 `art.attacks.inference.membership_inference.ShadowModels` 구현이 있다.

### 3.5 방어 — 차분 프라이버시(DP-SGD)

```python
from opacus import PrivacyEngine

model = ...
optimizer = torch.optim.SGD(model.parameters(), lr=0.05)
loader = ...

privacy_engine = PrivacyEngine()
model, optimizer, loader = privacy_engine.make_private_with_epsilon(
    module=model, optimizer=optimizer, data_loader=loader,
    target_epsilon=3.0, target_delta=1e-5,
    epochs=50, max_grad_norm=1.0,
)

# 이후 일반 학습 루프 그대로
```

**현실적 트레이드오프**:
- ε=3 수준이면 정확도 2–10%p 하락
- 하지만 MIA AUC가 0.5 근처로 회귀
- 민감 데이터(의료, 금융)에선 필수적으로 검토

## 4. 학습 데이터 추출 — 생성형 모델의 특수 위협

### 4.1 Carlini et al. (2021) 공격

GPT-2에서 **학습에 썼던 개인의 이름, 이메일, 전화번호**가 특정 프롬프트에 재생성되는 걸 보였다. 이후 GPT-3, Codex, Stable Diffusion에서도 유사 현상이 관측됨.

핵심 관찰:
1. 반복 등장하는 텍스트(URL, 코드, 라이선스 문구)는 **암기(memorization)** 된다.
2. 적절한 **접두사(prefix)** 를 주면 모델이 원본을 그대로 완성한다.

### 4.2 미니 재현 — 코드 암기 탐지

```python
#!/usr/bin/env python3
"""memorization_probe.py — 사전학습 모델이 공개 GitHub 코드를 얼마나 기억하는지 측정."""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

from transformers import AutoModelForCausalLM, AutoTokenizer


def n_gram_match(generated: str, reference: str, n: int = 50) -> bool:
    """reference에 있는 n-gram이 generated에 그대로 등장하는지."""
    if len(reference) < n:
        return False
    for i in range(0, len(reference) - n, 10):
        if reference[i:i + n] in generated:
            return True
    return False


def probe(model_name: str, corpus_dir: Path, prefix_len: int = 100, gen_len: int = 200) -> None:
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto")

    files = list(corpus_dir.rglob("*.py"))
    hits = 0
    samples = random.sample(files, min(50, len(files)))
    for f in samples:
        text = f.read_text(errors="ignore")
        if len(text) < prefix_len + 50:
            continue
        start = random.randint(0, len(text) - prefix_len - 50)
        prefix = text[start:start + prefix_len]
        expected = text[start + prefix_len : start + prefix_len + gen_len]

        ids = tok(prefix, return_tensors="pt").to(model.device)
        out = model.generate(**ids, max_new_tokens=gen_len, do_sample=False, temperature=0.0)
        generated = tok.decode(out[0], skip_special_tokens=True)

        if n_gram_match(generated, expected, n=50):
            hits += 1
            print(f"  [MEMORIZED] {f} @ offset {start}")
    print(f"\nmemorization rate: {hits}/{len(samples)} = {hits / len(samples):.2%}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt2")
    ap.add_argument("--corpus", type=Path, required=True)
    probe(ap.parse_args().model, ap.parse_args().corpus)
```

**실무적 함의**:
- 파인튜닝 셋에 **민감 고객 데이터**가 있으면 생성 중 노출 가능
- 공개 코드로만 학습해도 **라이선스 위반 생성**이 문제 (GPL 코드 유출)
- 방어: DP 학습 + 출력 필터 + 학습 데이터 중복 제거(dedup)

## 5. Model Inversion — 클래스를 보고 얼굴을 복원한다

Fredrikson et al. (2015). 얼굴 인식 API에 "Alice" 라벨의 확률을 최대화하는 입력을 **기울기 상승**으로 찾으면, **Alice의 얼굴 평균**에 해당하는 이미지가 복원된다.

```python
# 개념 코드
target_class = 42  # 예: "Alice"
x = torch.randn(1, 3, 224, 224, requires_grad=True)
optimizer = torch.optim.Adam([x], lr=0.05)

for _ in range(2000):
    logits = model(x)
    loss = -logits[0, target_class] + 0.001 * x.pow(2).sum()  # L2 정규화
    optimizer.zero_grad(); loss.backward(); optimizer.step()

save_image(x)  # target class의 평균적 '얼굴'
```

2026년 기준으로는 **분산 학습·Federated Learning의 기울기 업로드**가 더 심각한 벡터다. *Deep Leakage from Gradients* (Zhu et al., 2019) — 한 스텝의 기울기만 있으면 원본 학습 배치를 복원 가능.

## 6. 종합 방어 전략 — "뭘 포기할 것인가"

| 공격 | 완화책 | 비용 |
|------|--------|------|
| Model Extraction | Top-k 마스킹, 확률 교란, 쿼리 제한 | UX 약간 저하 |
| Membership Inference | DP-SGD (ε=3~8), 적절한 정규화 | 정확도 2–10%p↓ |
| Training Data Extraction | 학습 데이터 dedup, 출력 필터, 파인튜닝 시 DP | 데이터 파이프라인 재설계 |
| Model Inversion | 기울기 노이즈, Federated에선 secure aggregation | 통신 비용 ↑ |

**현실적 우선순위**:
1. **정기 MIA 측정**을 하라. AUC 기준선을 갖고 있어야 규제 대응이 된다.
2. 공개 API라면 **top-k + 확률 양자화**만 해도 모델 추출 비용이 10배 오른다.
3. 파인튜닝 데이터에 PII가 있다면 **dedup과 DP-SGD는 타협 불가**.

## 7. 참고 자료

- Shokri et al., *Membership Inference Attacks Against Machine Learning Models* (S&P 2017)
- Tramer et al., *Stealing Machine Learning Models via Prediction APIs* (USENIX 2016)
- Carlini et al., *Extracting Training Data from Large Language Models* (USENIX 2021)
- Carlini et al., *Membership Inference Attacks From First Principles* (S&P 2022) — LiRA
- Yeom et al., *Privacy Risk in Machine Learning* (CSF 2018)
- Zhu et al., *Deep Leakage from Gradients* (NeurIPS 2019)

---

<!-- detect-validate-31 -->
## 모델 추출·추론 공격 탐지와 방어 검증

모델에서는 *대량 쿼리 추출·멤버십 추론·데이터 재구성*으로 파라미터·학습데이터가 샌다. 방어자는 **자체 모델이 과다 쿼리·신뢰도 누출을 막는가**를 검증해야 한다. 검증은 **소유 모델**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 모델 추출 | 무제한 쿼리·로짓 노출 | 레이트 제한·출력 라운딩 | 체계적 경계 탐색 쿼리 |
| 멤버십 추론 | 신뢰도 누출 | 신뢰도 캡·정규화 | 멤버 vs 비멤버 신뢰도 격차 |
| 모델 인버전 | 그래디언트/출력 누출 | DP·출력 제한 | 재구성형 입력 쿼리 |
| 워터마크 회피 | 추출 모델 배포 | 워터마킹·핑거프린트 | 워터마크 불일치 |

### 방어 검증 (직접 확인)

```bash
# 1) 추출 신호 — 단일 클라이언트의 비정상 쿼리량/경계 탐색(소유 추론 로그)
awk '{print $1}' inference.log 2>/dev/null | sort | uniq -c | sort -rn | head
# 2) 신뢰도 노출 점검 — 응답이 raw 확률/로짓을 그대로 노출하는지(소유 API)
curl -s https://api.example.com/predict -d '{"x":[0]}' 2>/dev/null | grep -oE "0\.[0-9]{4,}" | head
```

> 추출/추론 방어는 *모델이 새지 않는가*다 — "API 있다"와 "과다 쿼리가 제한되고 raw 신뢰도가 노출되지 않는다"는 다르다. 소유 추론 로그·API 응답에서 쿼리량·신뢰도 노출을 직접 확인한다([[56_AI_Red_Teaming]], [[69_LLM_Security]], [[13_SOC_Blue_Team]]).

---

<a name="english"></a>

# 31-03. Model Extraction, Membership Inference, and Data Reconstruction — What Leaks from Models

> **Perspective shift**: Until now we've looked at "deceiving models." From here we turn to **"extracting something from models"** — weights, training data, privacy. The quietest and most expensive attacks.

## 1. Attack Classification — What Gets Stolen

| Attack | What's Stolen | Attacker Requirements |
|--------|---------------|----------------------|
| **Model Extraction** | The model itself (clone) | Query API access |
| **Membership Inference** | Yes/No whether a sample was in the training set | Prediction probabilities or confidence scores |
| **Attribute Inference** | Hidden attributes of a sample (e.g., gender) | Partial sample + queries |
| **Training Data Extraction** | Raw fragments of training data | Access to generative model |
| **Model Inversion** | Reconstruction of representative samples for a class | Gradients or probabilities |

Practical priority: **Membership Inference >> Model Extraction >> Data Reconstruction**

## 2. Model Extraction (Model Stealing)

### 2.1 Attack Principle

Tramer et al. (2016) key observation: given enough input-output pairs $(x_i, f(x_i))$, an attacker can **approximate the original model with supervised learning** — even if it's a black box.

Modern attacks against LLM/vision APIs:
1. Sample from **large public datasets** and get labels from the target API.
2. Train a **surrogate model** on obtained (input, probability) pairs.
3. Use surrogate for adversarial examples, data analysis, and internal structure estimation.

### 2.2 Demo — Cloning a Small Classifier

Using a CIFAR-10 classifier as a "black-box API" and cloning it with another network.

```python
#!/usr/bin/env python3
"""model_extraction_demo.py — Learn a surrogate model by querying a black-box classifier."""
from __future__ import annotations

import argparse

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from torchvision import datasets, transforms


class Victim(nn.Module):
    """The trained 'victim' model — assumed to be black-box externally."""
    def __init__(self) -> None:
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
        )
        self.fc = nn.Sequential(nn.Flatten(), nn.Linear(128 * 8 * 8, 256), nn.ReLU(), nn.Linear(256, 10))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(self.conv(x))


class Surrogate(nn.Module):
    """Surrogate model trained by the attacker. Can have different architecture."""
    def __init__(self) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Flatten(), nn.Linear(64 * 8 * 8, 128), nn.ReLU(), nn.Linear(128, 10),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def query_victim(victim: nn.Module, x: torch.Tensor, soft_labels: bool) -> torch.Tensor:
    victim.eval()
    with torch.no_grad():
        logits = victim(x)
        return F.softmax(logits, dim=1) if soft_labels else logits.argmax(1)


def extract(
    victim: nn.Module,
    query_budget: int,
    soft_labels: bool,
    device: torch.device,
    epochs: int = 20,
) -> Surrogate:
    tfm = transforms.Compose([transforms.ToTensor()])
    pool = datasets.CIFAR10("./data", train=True, download=True, transform=tfm)

    idx = torch.randperm(len(pool))[:query_budget]
    x_queries = torch.stack([pool[i][0] for i in idx]).to(device)
    y_stolen = query_victim(victim.to(device), x_queries, soft_labels)

    loader = DataLoader(TensorDataset(x_queries.cpu(), y_stolen.cpu()), batch_size=128, shuffle=True)
    surrogate = Surrogate().to(device)
    optim = torch.optim.Adam(surrogate.parameters(), lr=1e-3)
    loss_fn = (lambda p, t: F.kl_div(F.log_softmax(p, 1), t, reduction="batchmean")) if soft_labels \
              else F.cross_entropy

    for epoch in range(epochs):
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            loss = loss_fn(surrogate(xb), yb)
            optim.zero_grad(); loss.backward(); optim.step()
        print(f"  epoch {epoch+1:2d}  loss={loss.item():.4f}")
    return surrogate


def fidelity(victim: nn.Module, surrogate: nn.Module, device: torch.device) -> float:
    tfm = transforms.Compose([transforms.ToTensor()])
    test = datasets.CIFAR10("./data", train=False, download=True, transform=tfm)
    loader = DataLoader(test, batch_size=256)
    agree = total = 0
    victim.eval(); surrogate.eval()
    with torch.no_grad():
        for xb, _ in loader:
            xb = xb.to(device)
            agree += (victim(xb).argmax(1) == surrogate(xb).argmax(1)).sum().item()
            total += xb.size(0)
    return agree / total


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=5000, help="query budget")
    ap.add_argument("--soft", action="store_true", help="extract soft labels (probabilities)")
    ap.add_argument("--victim-ckpt", type=str, required=True, help="pretrained victim checkpoint")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    victim = Victim().to(device)
    victim.load_state_dict(torch.load(args.victim_ckpt, map_location=device))

    surrogate = extract(victim, args.budget, args.soft, device)
    fid = fidelity(victim, surrogate, device)
    print(f"\n[+] Fidelity (agreement on test set): {fid:.2%}")


if __name__ == "__main__":
    main()
```

**Practical intuitions**:
- Extracting with soft labels (probability vectors) achieves **same fidelity with 1/10 the budget**.
- Even with hard labels only, enough queries will eventually clone the model.
- "Our API only returns top-1 label so we're safe" is a common misconception. It only slightly raises the bar.

### 2.3 Defenses

- **Prediction probability distortion**: Top-k masking, label smoothing, adding Gaussian noise
- **Query rate limiting & anomaly detection**: Flag IPs/tokens making large out-of-distribution queries
- **Virtual budget**: Per-token query budget + anomaly billing
- **Watermarking**: Train model to leave unique signature for specific trigger inputs; test suspect models to detect cloning

Academic benchmarks: PRADA, VarDetect, SEAT. Defenses still lag behind attacks.

## 3. Membership Inference Attack (MIA)

### 3.1 Why It's Dangerous

If "Was this patient record in the training data?" can be answered Yes/No, this directly constitutes **violation of privacy regulations (GDPR, Personal Information Protection Act)**. For companies, this means class action risk.

### 3.2 Basic Principle — Shokri et al. (2017)

Samples used in training have **lower loss and sharper probability distributions**. A classifier trained on this statistical difference can distinguish members from non-members.

### 3.3 Minimum Reproduction — Threshold-based Attack (Yeom et al., 2018)

```python
#!/usr/bin/env python3
"""mia_threshold.py — Loss-based membership inference."""
from __future__ import annotations

import argparse
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score
from torch.utils.data import DataLoader
from torchvision import datasets, transforms


@torch.no_grad()
def per_sample_loss(model: torch.nn.Module, loader: DataLoader, device: torch.device) -> np.ndarray:
    model.eval()
    losses: list[float] = []
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        logits = model(xb)
        l = F.cross_entropy(logits, yb, reduction="none")
        losses.extend(l.cpu().numpy())
    return np.asarray(losses)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", required=True, help="target model checkpoint (CIFAR-10)")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    tfm = transforms.Compose([transforms.ToTensor()])

    train = datasets.CIFAR10("./data", train=True, download=True, transform=tfm)
    test = datasets.CIFAR10("./data", train=False, download=True, transform=tfm)

    model = torch.load(args.ckpt, map_location=device)
    ltrain = per_sample_loss(model, DataLoader(train, batch_size=256), device)
    ltest = per_sample_loss(model, DataLoader(test, batch_size=256), device)

    labels = np.concatenate([np.ones_like(ltrain), np.zeros_like(ltest)])
    scores = -np.concatenate([ltrain, ltest])  # lower loss = higher member probability
    auc = roc_auc_score(labels, scores)
    print(f"MIA AUC = {auc:.4f}   (0.5=random, >0.6=leak)")


if __name__ == "__main__":
    main()
```

**Interpretation**:
- AUC 0.5 → indistinguishable (good)
- AUC 0.6~0.7 → overfitting + suspected privacy leakage
- AUC > 0.8 → serious. If training data contains PII, disclosure obligations may apply

### 3.4 LiRA — Current Strong Baseline

Carlini et al. (2022) **Likelihood Ratio Attack**:
The attacker trains multiple **shadow models** to get the loss distribution of each sample $x$ "when it's a member" vs "when it's not", then evaluates the target model's loss as a likelihood ratio against these two distributions. Much stronger than previous threshold attacks.

```bash
pip install adversarial-robustness-toolbox
```
ART has `art.attacks.inference.membership_inference.ShadowModels` implementation.

### 3.5 Defense — Differential Privacy (DP-SGD)

```python
from opacus import PrivacyEngine

model = ...
optimizer = torch.optim.SGD(model.parameters(), lr=0.05)
loader = ...

privacy_engine = PrivacyEngine()
model, optimizer, loader = privacy_engine.make_private_with_epsilon(
    module=model, optimizer=optimizer, data_loader=loader,
    target_epsilon=3.0, target_delta=1e-5,
    epochs=50, max_grad_norm=1.0,
)

# Normal training loop continues here
```

**Realistic trade-offs**:
- At ε=3, accuracy drops 2–10%p
- But MIA AUC returns close to 0.5
- Essential consideration for sensitive data (medical, financial)

## 4. Training Data Extraction — Special Threat of Generative Models

### 4.1 Carlini et al. (2021) Attack

Demonstrated that GPT-2 regenerates **names, emails, and phone numbers** of individuals from training data when given specific prompts. Similar phenomena observed in GPT-3, Codex, and Stable Diffusion.

Key observations:
1. Repeatedly appearing text (URLs, code, license text) gets **memorized**.
2. The right **prefix** makes the model complete the original text verbatim.

### 4.2 Mini Reproduction — Code Memorization Detection

```python
#!/usr/bin/env python3
"""memorization_probe.py — Measure how much a pretrained model remembers public GitHub code."""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

from transformers import AutoModelForCausalLM, AutoTokenizer


def n_gram_match(generated: str, reference: str, n: int = 50) -> bool:
    """Check if an n-gram from reference appears verbatim in generated."""
    if len(reference) < n:
        return False
    for i in range(0, len(reference) - n, 10):
        if reference[i:i + n] in generated:
            return True
    return False


def probe(model_name: str, corpus_dir: Path, prefix_len: int = 100, gen_len: int = 200) -> None:
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto")

    files = list(corpus_dir.rglob("*.py"))
    hits = 0
    samples = random.sample(files, min(50, len(files)))
    for f in samples:
        text = f.read_text(errors="ignore")
        if len(text) < prefix_len + 50:
            continue
        start = random.randint(0, len(text) - prefix_len - 50)
        prefix = text[start:start + prefix_len]
        expected = text[start + prefix_len : start + prefix_len + gen_len]

        ids = tok(prefix, return_tensors="pt").to(model.device)
        out = model.generate(**ids, max_new_tokens=gen_len, do_sample=False, temperature=0.0)
        generated = tok.decode(out[0], skip_special_tokens=True)

        if n_gram_match(generated, expected, n=50):
            hits += 1
            print(f"  [MEMORIZED] {f} @ offset {start}")
    print(f"\nmemorization rate: {hits}/{len(samples)} = {hits / len(samples):.2%}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt2")
    ap.add_argument("--corpus", type=Path, required=True)
    probe(ap.parse_args().model, ap.parse_args().corpus)
```

**Practical implications**:
- If fine-tuning data contains **sensitive customer data**, it can be exposed during generation
- Even training on public code can cause **license violation generation** (GPL code leakage)
- Defense: DP training + output filtering + training data deduplication

## 5. Model Inversion — Reconstructing a Face from a Class Label

Fredrikson et al. (2015). For face recognition APIs, using **gradient ascent** to find inputs that maximize the probability of label "Alice" reconstructs an image corresponding to **Alice's average face**.

```python
# Conceptual code
target_class = 42  # e.g., "Alice"
x = torch.randn(1, 3, 224, 224, requires_grad=True)
optimizer = torch.optim.Adam([x], lr=0.05)

for _ in range(2000):
    logits = model(x)
    loss = -logits[0, target_class] + 0.001 * x.pow(2).sum()  # L2 regularization
    optimizer.zero_grad(); loss.backward(); optimizer.step()

save_image(x)  # average 'face' of target class
```

As of 2026, **gradient uploads in distributed learning / Federated Learning** are an even more serious vector. *Deep Leakage from Gradients* (Zhu et al., 2019) — gradients from a single step are enough to reconstruct the original training batch.

## 6. Comprehensive Defense Strategy — "What Are You Willing to Trade Off?"

| Attack | Mitigation | Cost |
|--------|------------|------|
| Model Extraction | Top-k masking, probability perturbation, query rate limiting | Slight UX degradation |
| Membership Inference | DP-SGD (ε=3~8), proper regularization | Accuracy 2–10%p decrease |
| Training Data Extraction | Training data dedup, output filtering, DP during fine-tuning | Data pipeline redesign |
| Model Inversion | Gradient noise, secure aggregation in Federated settings | Increased communication cost |

**Realistic priorities**:
1. **Perform regular MIA measurements**. You need an AUC baseline to respond to regulations.
2. For public APIs, **top-k + probability quantization** alone raises model extraction cost by 10x.
3. If fine-tuning data contains PII, **dedup and DP-SGD are non-negotiable**.

## 7. References

- Shokri et al., *Membership Inference Attacks Against Machine Learning Models* (S&P 2017)
- Tramer et al., *Stealing Machine Learning Models via Prediction APIs* (USENIX 2016)
- Carlini et al., *Extracting Training Data from Large Language Models* (USENIX 2021)
- Carlini et al., *Membership Inference Attacks From First Principles* (S&P 2022) — LiRA
- Yeom et al., *Privacy Risk in Machine Learning* (CSF 2018)
- Zhu et al., *Deep Leakage from Gradients* (NeurIPS 2019)

<!-- detect-validate-31 -->
## Model Extraction and Inference Attack Detection and Defense Validation

Models leak parameters and training data via *high-volume query extraction, membership inference, and data reconstruction*. Defenders must verify **whether their model blocks excessive queries and confidence leakage**. Validate only on **owned models**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| Model extraction | Unlimited queries, logit exposure | Rate limit, output rounding | Systematic boundary-probing queries |
| Membership inference | Confidence leakage | Confidence cap, calibration | Member vs non-member confidence gap |
| Model inversion | Gradient/output leakage | DP, output limiting | Reconstruction-style input queries |
| Watermark evasion | Deploying extracted model | Watermarking, fingerprinting | Watermark mismatch |

### Defense validation (verify directly)

```bash
# 1) Extraction signal — abnormal query volume / boundary probing by a single client (owned inference log)
awk '{print $1}' inference.log 2>/dev/null | sort | uniq -c | sort -rn | head
# 2) Confidence-exposure check — whether responses expose raw probabilities/logits (owned API)
curl -s https://api.example.com/predict -d '{"x":[0]}' 2>/dev/null | grep -oE "0\.[0-9]{4,}" | head
```

> Extraction/inference defense is *whether the model doesn't leak* -- "we have an API" differs from "excessive queries are rate-limited and raw confidence isn't exposed". Confirm query volume and confidence exposure on owned logs/API directly ([[56_AI_Red_Teaming]], [[69_LLM_Security]], [[13_SOC_Blue_Team]]).
