> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 31-01. 적대적 예제 — 입력 단계에서 모델을 속이는 기술

> **한 줄 요약**: 학습된 모델의 결정 경계는 매끄럽지 않다. 경계에 직교하는 방향으로 아주 작은 벡터를 더하면 사람 눈엔 안 보이는데 모델만 완전히 잘못 본다.
> 이 문서는 FGSM → PGD → C&W로 이어지는 표준 공격 계보를 직접 구현하고, 방어까지 이어갑니다.

---

## 0. 초보자를 위한 개념 이해

### 적대적 예제란?

적대적 예제(Adversarial Example)는 인간이 보기에는 정상적이지만, AI/ML 모델이 잘못 분류하도록 정밀하게 조작된 입력 데이터다. 고양이 사진에 사람 눈에는 보이지 않는 아주 미세한 노이즈를 더하면 AI가 "타조"라고 분류하는 현상이다. 자율주행 자동차, 얼굴인식 보안 시스템, AI 의료 진단 등에서 실제 위협이 된다.

**왜 배우는가:**
```
적대적 공격이 위험한 실제 시나리오

[자율주행]
  정지 표지판 + 특수 스티커 → AI가 속도 제한 표지판으로 인식
  → 자동차가 정지하지 않음

[얼굴인식 보안]
  특수 패턴 안경 착용 → AI가 다른 사람으로 인식
  → 잠금 해제 또는 제3자 사칭

[AI 악성코드 탐지]
  악성코드 바이너리를 미세하게 변형 → AI 백신이 정상으로 분류
  → 탐지 우회

방어자가 배워야 할 이유:
  AI 시스템의 취약점을 이해 → 견고한 모델 설계
  적대적 학습(Adversarial Training)으로 방어
```

### 핵심 개념 정리

```
주요 적대적 공격 방법

FGSM (Fast Gradient Sign Method):
  손실 함수의 기울기 방향으로 픽셀 값을 epsilon만큼 이동
  빠름, 1회 계산, 전이성 높음

PGD (Projected Gradient Descent):
  FGSM을 여러 번 반복, 매번 epsilon 구 내로 투영
  더 강력, FGSM보다 성공률 높음

C&W (Carlini & Wagner):
  최소한의 섭동으로 최대 오분류 달성
  현재까지 가장 강력한 공격 중 하나
```

### 필요한 도구 및 환경
- **PyTorch / TensorFlow**: 딥러닝 프레임워크 (`pip install torch`)
- **ART (Adversarial Robustness Toolbox)**: IBM의 적대적 공격/방어 라이브러리
- **CleverHans**: Google의 적대적 예제 라이브러리

### 기초 실습 예제
```python
#!/usr/bin/env python3
"""FGSM 공격 개념 이해 — NumPy만 사용한 단순화 예제"""
import numpy as np

def fgsm_concept(image: np.ndarray, gradient: np.ndarray,
                 epsilon: float = 0.01) -> np.ndarray:
    """FGSM 핵심 원리: 손실을 최대화하는 방향으로 미세 조정
    
    adversarial = image + epsilon * sign(gradient)
    """
    perturbation = epsilon * np.sign(gradient)
    adversarial = image + perturbation
    # 픽셀 값 범위 유지 [0, 1]
    return np.clip(adversarial, 0.0, 1.0)

# 개념 시연
image = np.array([0.5, 0.3, 0.8])       # 원본 픽셀 (정규화)
gradient = np.array([0.2, -0.5, 0.1])   # 가상 기울기

adv = fgsm_concept(image, gradient, epsilon=0.05)
perturbation = adv - image
print(f"원본:    {image}")
print(f"섭동:    {perturbation}")       # 매우 작은 값
print(f"적대적: {adv}")
print(f"최대 변화량: {np.max(np.abs(perturbation)):.4f} (사람 눈에 안 보임)")
```

---

## 직관적 설명 — "AI 눈을 속이는 마법의 먼지"

**비유**: 사람이 고양이 사진을 볼 때, 우리 뇌는 "귀, 수염, 털"을 종합적으로 판단한다. 그런데 AI는 수백만 개의 픽셀 값을 수학적으로 처리한다. 각 픽셀을 아주 조금씩 (사람 눈엔 보이지 않는 수준으로) 바꾸면, AI의 수학적 계산 결과가 완전히 다른 답을 내게 할 수 있다.

```
원본 이미지:    고양이 (신뢰도 99.7%)
          +
섭동 (노이즈):  각 픽셀을 ±8/255 (약 3%) 수준으로 조정
          =
적대적 예제:    타조 (신뢰도 87.3%)  ← AI만 속는다
```

사람이 두 이미지를 나란히 놓으면 **완전히 동일하게 보인다**. 그러나 AI는 다른 답을 낸다.

---

## 왜 이것이 가능한가?

### 고차원 공간의 기하학

28×28 MNIST 이미지: 784차원 공간의 한 점
224×224 RGB ImageNet: 150,528차원 공간의 한 점

**고차원의 반직관적 성질**:
- 고차원 구(sphere)에서 부피의 대부분은 **표면 근처에 집중**된다
- 임의의 방향으로 조금만 이동해도 상당한 거리를 이동하는 효과
- 입력 공간이 넓을수록 "사람은 못 보지만 AI는 탐지하는" 방향이 존재할 가능성이 높아짐

### 신경망의 선형성

ReLU 활성화 함수 구간마다 신경망은 **국소적으로 선형**이다.

```
f(x + δ) ≈ f(x) + J_f(x) · δ

J_f: 야코비안 행렬 (입력의 각 방향이 출력에 미치는 영향)
δ:   우리가 추가하는 섭동

손실이 증가하는 방향: δ = ε · sign(∇_x L)
이것이 FGSM의 전부다
```

---

## 실제 사례들

### 사례 1: 테슬라 오토파일럿 속이기

```
연구: McAfee Advanced Threat Research (2020)

공격 방법:
- 속도 제한 표지판에 검은 스티커 2개 부착
- 35mph 표지판이 85mph로 오인식

결과:
- 테슬라 오토파일럿이 갑자기 속도 증가
- 실제 물리 세계 공격 (디지털 편집 없음)

교훈: 물리 세계에서도 적대적 공격이 가능
```

### 사례 2: 안면 인식 우회

```
연구: Carnegie Mellon University (2016) — "Accessorize to a Crime"

공격 방법:
- 특수 프린트된 안경 착용
- 인쇄된 패턴이 안면 인식 시스템에 적대적 섭동으로 작용

결과:
- 다른 사람으로 오인식 (targeted attack)
- 또는 아무도 아닌 것으로 오인식 (dodging attack)

교훈: 물리 세계 인쇄물로도 안면 인식 우회 가능
```

### 사례 3: 자율주행차 정지 표지판 오인식

```
연구: UW/Michigan/UC Berkeley (2017)

공격 방법:
- Stop 표지판에 그래피티처럼 보이는 스티커 부착
- 실제로는 정밀 계산된 적대적 패치

결과:
- 표준 딥러닝 모델이 "속도 제한 45mph"로 오인식
- 보행자와 차량이 표지판이 손상됐다고만 생각함

교훈: 물리적 패치 공격은 탐지가 극히 어려움
```

---

## 1. 적대적 예제가 왜 가능한가 — 선형성 가설

Goodfellow et al. (2014)의 직관: 현대 신경망은 **국소적으로 거의 선형**이다.
고차원 입력 공간에서 작은 ε을 손실 기울기 방향으로 한 걸음만 가도, 출력 로짓(logit)은 선형적으로 훌쩍 움직인다.

$$
\mathcal{L}(\theta, x + \eta, y) \approx \mathcal{L}(\theta, x, y) + \eta^\top \nabla_x \mathcal{L}
$$

즉 $\eta = \varepsilon \cdot \mathrm{sign}(\nabla_x \mathcal{L})$ 로 정하면 손실이 가장 빨리 증가하고, 이는 곧 오분류로 이어진다. 이게 **FGSM**(Fast Gradient Sign Method)의 전부다.

---

## 2. 위협 모델 정리 — "뭘 알고 있는 공격자인가"

| 차원 | 화이트박스 | 블랙박스 (쿼리) | 블랙박스 (전이) |
|------|-----------|-----------------|-----------------|
| 공격자가 아는 것 | 모델 구조·가중치 | 질의 결과만 (라벨 또는 확률) | 유사 데이터셋만 |
| 대표 공격 | FGSM, PGD, C&W | HSJA, SquareAttack | 전이 공격 (substitute model) |
| 실제 위협도 | 모델을 직접 가진 내부자 | 공개 API를 때리는 외부자 | 오픈 가중치 기반 공격 |

**Untargeted**(어떤 라벨이든 틀리게) vs **Targeted**(특정 라벨 T로 유도) 도 구분해야 한다. Targeted가 훨씬 어렵다.

**제약(distortion) 메트릭**:
- $L_\infty$ — 픽셀 하나당 최대 변화. `ε=8/255` 가 표준 벤치마크.
- $L_2$ — 전체 섭동의 유클리드 크기. 공간적으로 집중된 변화.
- $L_0$ — 바꾼 픽셀 수. 스티커·패치 공격용.

---

## 3. FGSM vs PGD 비교표

| 항목 | FGSM | PGD |
|------|------|-----|
| 이름 | Fast Gradient Sign Method | Projected Gradient Descent |
| 제안 | Goodfellow et al. (2014) | Madry et al. (2017) |
| 스텝 수 | 1회 | 10~100회 |
| 속도 | 매우 빠름 | 느림 (스텝 × 역전파) |
| 공격 강도 | 약함~중간 | 강함 (현재 표준) |
| Random Start | 없음 | 있음 (ε-ball 내 랜덤 시작) |
| 활용 | 빠른 데이터 증강, 대략적 평가 | 강건성 벤치마크, Adversarial Training |
| adversarial training | 비교적 약한 방어 생성 | 강건한 방어 생성 (Madry AT) |
| 수식 | $x' = \text{clip}(x + \epsilon \cdot \text{sign}(\nabla_x L))$ | $x^{t+1} = \Pi_{B_\epsilon}(x^t + \alpha \cdot \text{sign}(\nabla_x L))$ |

---

## 4. FGSM — 한 방 공격 (PyTorch 완성본)

ImageNet 사전학습 ResNet50에 대해 FGSM 섭동을 생성하고, **공격 전/후 top-1 예측**을 비교하는 재현 스크립트다.

```python
#!/usr/bin/env python3
"""fgsm_attack.py — 단일 이미지에 FGSM 섭동을 적용해 오분류를 유도한다.

사용 예:
    python fgsm_attack.py --image cat.jpg --epsilon 0.03 --out adv.png
"""
from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn.functional as F
import torchvision.transforms as T
from PIL import Image
from torchvision.models import ResNet50_Weights, resnet50


IMAGENET_MEAN = torch.tensor([0.485, 0.456, 0.406]).view(1, 3, 1, 1)
IMAGENET_STD = torch.tensor([0.229, 0.224, 0.225]).view(1, 3, 1, 1)


def load_model(device: torch.device) -> tuple[torch.nn.Module, list[str]]:
    weights = ResNet50_Weights.IMAGENET1K_V2
    model = resnet50(weights=weights).to(device).eval()
    categories = weights.meta["categories"]
    return model, categories


def load_image(path: Path, device: torch.device) -> torch.Tensor:
    pil = Image.open(path).convert("RGB").resize((224, 224))
    transform = T.ToTensor()
    return transform(pil).unsqueeze(0).to(device)


def normalize(x: torch.Tensor) -> torch.Tensor:
    return (x - IMAGENET_MEAN.to(x.device)) / IMAGENET_STD.to(x.device)


def fgsm(
    model: torch.nn.Module,
    x: torch.Tensor,
    y_true: torch.Tensor,
    epsilon: float,
) -> torch.Tensor:
    """FGSM 섭동 생성. 입력은 [0,1] 픽셀 공간에서 작업한다."""
    x_adv = x.clone().detach().requires_grad_(True)
    logits = model(normalize(x_adv))
    loss = F.cross_entropy(logits, y_true)
    model.zero_grad()
    loss.backward()
    eta = epsilon * x_adv.grad.sign()
    x_adv = torch.clamp(x_adv + eta, 0.0, 1.0).detach()
    return x_adv


def top1(model: torch.nn.Module, x: torch.Tensor, categories: list[str]) -> tuple[int, float, str]:
    with torch.no_grad():
        probs = model(normalize(x)).softmax(dim=1)
    conf, idx = probs[0].max(0)
    return int(idx), float(conf), categories[int(idx)]


def main() -> None:
    ap = argparse.ArgumentParser(description="Single-step FGSM on ImageNet ResNet50")
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--epsilon", type=float, default=8 / 255, help="L_inf budget in [0,1]")
    ap.add_argument("--out", type=Path, default=Path("adv.png"))
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    model, cats = load_model(device)
    x = load_image(args.image, device)

    orig_idx, orig_conf, orig_name = top1(model, x, cats)
    print(f"[clean]  top-1: {orig_name!r} ({orig_conf:.2%})")

    y = torch.tensor([orig_idx], device=device)
    x_adv = fgsm(model, x, y, args.epsilon)

    adv_idx, adv_conf, adv_name = top1(model, x_adv, cats)
    print(f"[attack] ε={args.epsilon:.4f} → {adv_name!r} ({adv_conf:.2%})")
    print(f"         misclassified: {adv_idx != orig_idx}")
    print(f"         L∞ distortion: {(x_adv - x).abs().max().item():.4f}")

    T.ToPILImage()(x_adv.squeeze(0).cpu()).save(args.out)
    print(f"         wrote: {args.out}")


if __name__ == "__main__":
    main()
```

**재현 팁**:
- ResNet50은 ε=8/255에서 대부분 오분류된다. ε=1/255만 되어도 상위 예측이 흔들린다.
- 정규화를 **공격 함수 바깥에서** 처리해야 입력이 [0,1] 픽셀 공간에 머물러 clamp가 의미를 갖는다. 구현 실수가 가장 많이 나는 지점이다.

---

## 5. PGD — 여러 걸음으로 최적화 (표준 벤치마크)

FGSM은 한 방이라 국소 최적에 쉽게 빠진다. PGD(Projected Gradient Descent)는 ε-볼 안에서 여러 번 기울기 스텝을 밟고, 매 스텝 **ε-볼로 사영(project)** 해 예산을 지킨다.

$$
x^{t+1} = \Pi_{B_\varepsilon(x)}\left( x^t + \alpha \cdot \mathrm{sign}(\nabla_x \mathcal{L}) \right)
$$

2017년 Madry 팀이 제안한 이후 **사실상 모든 강건성 벤치마크의 기준선**이다.

```python
#!/usr/bin/env python3
"""pgd_attack.py — L_inf PGD (Madry et al., 2017)."""
from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn.functional as F
from torchvision.models import ResNet50_Weights, resnet50

from fgsm_attack import IMAGENET_MEAN, IMAGENET_STD, load_image, normalize, top1


def pgd_linf(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    alpha: float,
    steps: int,
    random_start: bool = True,
) -> torch.Tensor:
    x_adv = x.clone().detach()
    if random_start:
        x_adv = x_adv + torch.empty_like(x_adv).uniform_(-epsilon, epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

    for _ in range(steps):
        x_adv = x_adv.detach().requires_grad_(True)
        loss = F.cross_entropy(model(normalize(x_adv)), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv.detach() + alpha * grad.sign()
        x_adv = torch.max(torch.min(x_adv, x + epsilon), x - epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)
    return x_adv.detach()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--epsilon", type=float, default=8 / 255)
    ap.add_argument("--alpha", type=float, default=2 / 255)
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--target", type=int, default=None, help="targeted label id")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    weights = ResNet50_Weights.IMAGENET1K_V2
    model = resnet50(weights=weights).to(device).eval()
    cats = weights.meta["categories"]
    x = load_image(args.image, device)

    orig_idx, _, orig_name = top1(model, x, cats)
    if args.target is None:
        y = torch.tensor([orig_idx], device=device)
        x_adv = pgd_linf(model, x, y, args.epsilon, args.alpha, args.steps)
    else:
        # Targeted: loss 부호 반전
        y = torch.tensor([args.target], device=device)
        x_adv = pgd_linf_targeted(model, x, y, args.epsilon, args.alpha, args.steps)

    adv_idx, adv_conf, adv_name = top1(model, x_adv, cats)
    print(f"clean:  {orig_name}")
    print(f"PGD-{args.steps}: {adv_name} ({adv_conf:.2%})")


def pgd_linf_targeted(model, x, y_target, epsilon, alpha, steps):
    x_adv = x.clone().detach() + torch.empty_like(x).uniform_(-epsilon, epsilon)
    x_adv = torch.clamp(x_adv, 0.0, 1.0)
    for _ in range(steps):
        x_adv = x_adv.detach().requires_grad_(True)
        loss = -F.cross_entropy(model(normalize(x_adv)), y_target)  # minimize for target
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv.detach() + alpha * grad.sign()
        x_adv = torch.max(torch.min(x_adv, x + epsilon), x - epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)
    return x_adv.detach()


if __name__ == "__main__":
    main()
```

**PGD 하이퍼파라미터 감각**:
- `steps=40`, `alpha=2/255`, `epsilon=8/255` → ResNet50 강건성 ≈ 0% (비강건 모델 기준)
- adversarial training된 모델은 같은 조건에서 50% 이상 버틴다.

---

## 6. FGSM 수학적 원리 — 초보자를 위한 단계별 설명

### Step 1: 신경망이 이미지를 판단하는 방법

```
이미지 x (픽셀 값들)
    │
    ▼
신경망 f(x) 실행
    │
    ▼
각 클래스에 대한 점수 (logits)
[고양이: 8.5, 개: 2.1, 타조: 0.3, ...]
    │
    ▼
Softmax → 확률
[고양이: 99.7%, 개: 0.2%, 타조: 0.1%]
    │
    ▼
가장 높은 확률의 클래스 선택
"고양이"
```

### Step 2: 손실 함수란?

```
손실(Loss) = 모델이 얼마나 틀렸는지
  - 정답이 "고양이"인데 고양이 점수가 낮을수록 손실 ↑
  - Cross-Entropy Loss: L = -log(P(정답 클래스))
```

### Step 3: 기울기(Gradient)의 의미

```
∇_x L = 입력 x의 각 픽셀을 어떤 방향으로 바꾸면
         손실이 증가하는가?

즉: 어떻게 픽셀을 바꾸면 모델이 더 틀리게 되는가?
```

### Step 4: FGSM 공식 해석

```python
# 수식: x_adv = x + ε * sign(∇_x L)

# 단계별:
# 1. ∇_x L 계산 (역전파)
loss.backward()
gradient = x.grad  # 각 픽셀의 기울기

# 2. sign() 적용: 부호만 취함 (+1 또는 -1)
# 기울기가 +이면 픽셀 증가, -이면 감소
direction = gradient.sign()

# 3. ε 스케일링: 최대 변화량 제한
perturbation = epsilon * direction

# 4. 적용 및 범위 제한 (픽셀은 0~1 사이)
x_adv = torch.clamp(x + perturbation, 0.0, 1.0)
```

### Step 5: 왜 sign()을 쓰는가?

```
L_∞ 예산(ε)을 가장 효율적으로 사용하기 위해:
- 모든 픽셀에 동등하게 ε을 할당
- 기울기 크기(magnitude)가 아닌 방향만 사용
- 이렇게 하면 고차원에서 더 강력한 공격이 됨

수학적으로: 
L_∞ 제약 하에서 손실 증가를 최대화하는 해법이
η = ε · sign(∇_x L) 임을 증명할 수 있다
```

---

## 7. C&W 공격 — 최소 왜곡으로 집요하게

Carlini & Wagner (2017)의 $L_2$ 공격은 **정확히 경계를 넘으면서 왜곡을 최소화**하는 최적화다.
FGSM/PGD는 "예산 ε 안에서 얼마나 공격적으로?"가 목표, C&W는 "성공시키되 얼마나 덜 움직일 수 있는가?"가 목표다.

목적 함수(핵심):

$$
\min_{\delta} \|\delta\|_2^2 + c \cdot f(x + \delta),\quad f(x') = \max\!\left( \max_{i \ne t} Z(x')_i - Z(x')_t, -\kappa \right)
$$

여기서 $Z(\cdot)$은 로짓, $t$는 타깃 라벨, $\kappa$는 confidence margin. $c$는 binary-search로 찾는다.

직접 구현하지 말고, 잘 검증된 구현을 쓰는 걸 추천한다.

```python
from art.attacks.evasion import CarliniL2Method
from art.estimators.classification import PyTorchClassifier

classifier = PyTorchClassifier(
    model=model, loss=torch.nn.CrossEntropyLoss(),
    input_shape=(3, 224, 224), nb_classes=1000,
    clip_values=(0.0, 1.0),
    preprocessing=(IMAGENET_MEAN.numpy().squeeze(), IMAGENET_STD.numpy().squeeze()),
)
attack = CarliniL2Method(classifier=classifier, confidence=0.0, max_iter=100, binary_search_steps=9)
x_adv = attack.generate(x=x.cpu().numpy())
```

---

## 8. 완전한 실습 스크립트 — 배치 공격 및 평가

```python
#!/usr/bin/env python3
"""adversarial_bench.py — FGSM/PGD 공격 및 강건성 평가 통합 CLI.

설치:
    pip install torch torchvision Pillow

사용법:
    python adversarial_bench.py attack --image cat.jpg --method fgsm --epsilon 0.03
    python adversarial_bench.py evaluate --image cat.jpg --epsilons 0 0.01 0.03 0.05
    python adversarial_bench.py compare --image cat.jpg
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable

import torch
import torch.nn.functional as F
import torchvision.transforms as T
from PIL import Image
from torchvision.models import ResNet50_Weights, resnet50


# ImageNet 정규화 상수
MEAN = torch.tensor([0.485, 0.456, 0.406]).view(1, 3, 1, 1)
STD  = torch.tensor([0.229, 0.224, 0.225]).view(1, 3, 1, 1)


def load_model(device: torch.device) -> tuple[torch.nn.Module, list[str]]:
    """ResNet50 (ImageNet 사전학습) 로드."""
    w = ResNet50_Weights.IMAGENET1K_V2
    model = resnet50(weights=w).to(device).eval()
    return model, w.meta["categories"]


def load_image(path: Path, device: torch.device) -> torch.Tensor:
    """PIL 이미지 → [1,3,224,224] float32 텐서 (값 범위 [0,1])."""
    img = Image.open(path).convert("RGB").resize((224, 224))
    return T.ToTensor()(img).unsqueeze(0).to(device)


def normalize(x: torch.Tensor) -> torch.Tensor:
    return (x - MEAN.to(x.device)) / STD.to(x.device)


def predict_top1(model: torch.nn.Module, x: torch.Tensor, cats: list[str]) -> tuple[int, float, str]:
    with torch.no_grad():
        probs = model(normalize(x)).softmax(1)
    conf, idx = probs[0].max(0)
    return int(idx), float(conf), cats[int(idx)]


# ---------------------------------------------------------------------------
# 공격 함수들
# ---------------------------------------------------------------------------

def attack_fgsm(
    model: torch.nn.Module, x: torch.Tensor, y: torch.Tensor, epsilon: float
) -> torch.Tensor:
    """Fast Gradient Sign Method (단일 스텝)."""
    x_adv = x.clone().detach().requires_grad_(True)
    loss = F.cross_entropy(model(normalize(x_adv)), y)
    loss.backward()
    with torch.no_grad():
        x_adv = torch.clamp(x_adv + epsilon * x_adv.grad.sign(), 0.0, 1.0)
    return x_adv.detach()


def attack_pgd(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    alpha: float = 2 / 255,
    steps: int = 40,
    random_start: bool = True,
) -> torch.Tensor:
    """Projected Gradient Descent (다중 스텝, L_inf)."""
    x_adv = x.clone().detach()
    if random_start:
        x_adv = x_adv + torch.empty_like(x_adv).uniform_(-epsilon, epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(normalize(x_adv)), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        with torch.no_grad():
            x_adv = x_adv.detach() + alpha * grad.sign()
            x_adv = torch.clamp(x_adv, x - epsilon, x + epsilon)
            x_adv = torch.clamp(x_adv, 0.0, 1.0)

    return x_adv.detach()


def attack_bim(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    alpha: float = 1 / 255,
    steps: int = 10,
) -> torch.Tensor:
    """Basic Iterative Method (no random start PGD)."""
    return attack_pgd(model, x, y, epsilon, alpha, steps, random_start=False)


# ---------------------------------------------------------------------------
# 입력 전처리 방어
# ---------------------------------------------------------------------------

def defense_jpeg(x: torch.Tensor, quality: int = 75) -> torch.Tensor:
    """JPEG 재압축으로 섭동 완화."""
    from io import BytesIO
    images = []
    for img_tensor in x:
        pil = T.ToPILImage()(img_tensor.cpu())
        buf = BytesIO()
        pil.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        images.append(T.ToTensor()(Image.open(buf)))
    return torch.stack(images).to(x.device)


def defense_random_crop_resize(x: torch.Tensor, target_size: int = 224) -> torch.Tensor:
    """랜덤 크롭 후 리사이즈로 섭동 완화."""
    transform = T.Compose([
        T.RandomCrop(int(target_size * 0.9)),
        T.Resize(target_size),
    ])
    return torch.stack([transform(img) for img in x]).to(x.device)


def defense_smoothing(x: torch.Tensor, sigma: float = 0.1, n: int = 20) -> torch.Tensor:
    """Randomized smoothing — 가우시안 노이즈 평균."""
    votes = []
    for _ in range(n):
        noisy = torch.clamp(x + torch.randn_like(x) * sigma, 0.0, 1.0)
        votes.append(noisy)
    return torch.stack(votes).mean(0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_attack(args: argparse.Namespace) -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, cats = load_model(device)
    x = load_image(args.image, device)

    orig_idx, orig_conf, orig_name = predict_top1(model, x, cats)
    print(f"[원본]  {orig_name!r} ({orig_conf:.1%})")

    y = torch.tensor([orig_idx], device=device)
    eps = args.epsilon

    if args.method == "fgsm":
        x_adv = attack_fgsm(model, x, y, eps)
    elif args.method == "pgd":
        x_adv = attack_pgd(model, x, y, eps, steps=args.steps)
    else:  # bim
        x_adv = attack_bim(model, x, y, eps, steps=args.steps)

    adv_idx, adv_conf, adv_name = predict_top1(model, x_adv, cats)
    success = adv_idx != orig_idx
    linf = (x_adv - x).abs().max().item()
    l2   = (x_adv - x).norm().item()

    print(f"[공격]  {args.method.upper()} ε={eps:.4f}")
    print(f"        결과: {adv_name!r} ({adv_conf:.1%})")
    print(f"        성공: {success}")
    print(f"        L∞={linf:.4f}, L2={l2:.4f}")

    if args.output:
        T.ToPILImage()(x_adv.squeeze(0).cpu()).save(args.output)
        print(f"        저장: {args.output}")


def cmd_evaluate(args: argparse.Namespace) -> None:
    """여러 ε 값에서 공격 성공률 평가."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, cats = load_model(device)
    x = load_image(args.image, device)

    orig_idx, _, orig_name = predict_top1(model, x, cats)
    y = torch.tensor([orig_idx], device=device)

    print(f"원본: {orig_name!r}")
    print(f"{'ε':>8} | {'FGSM':>20} | {'PGD-40':>20} | {'L∞ 왜곡':>10}")
    print("-" * 65)

    for eps in args.epsilons:
        x_fgsm = attack_fgsm(model, x, y, eps)
        x_pgd  = attack_pgd(model, x, y, eps, steps=40)

        _, cf, nf = predict_top1(model, x_fgsm, cats)
        _, cp, np_ = predict_top1(model, x_pgd, cats)

        fgsm_ok = "✓ " + nf if nf != orig_name else "✗ " + nf
        pgd_ok  = "✓ " + np_ if np_ != orig_name else "✗ " + np_
        linf = (x_pgd - x).abs().max().item()

        print(f"{eps:>8.4f} | {fgsm_ok[:20]:>20} | {pgd_ok[:20]:>20} | {linf:>10.4f}")


def cmd_compare(args: argparse.Namespace) -> None:
    """다양한 방어 기법 비교."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, cats = load_model(device)
    x = load_image(args.image, device)

    orig_idx, _, orig_name = predict_top1(model, x, cats)
    y = torch.tensor([orig_idx], device=device)
    x_adv = attack_pgd(model, x, y, epsilon=8/255, steps=40)

    print(f"원본: {orig_name!r}")
    adv_idx, adv_conf, adv_name = predict_top1(model, x_adv, cats)
    print(f"\n[PGD-40 공격 후]")
    print(f"  결과: {adv_name!r} ({adv_conf:.1%})")

    print(f"\n[방어 후 예측]")
    for name, defended in [
        ("JPEG 재압축 (q=75)", defense_jpeg(x_adv, quality=75)),
        ("랜덤 크롭+리사이즈", defense_random_crop_resize(x_adv)),
        ("Randomized Smoothing", defense_smoothing(x_adv)),
    ]:
        _, dc, dn = predict_top1(model, defended, cats)
        status = "성공 (방어됨)" if dn == orig_name else "실패 (여전히 속음)"
        print(f"  {name}: {dn!r} ({dc:.1%}) — {status}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="적대적 예제 공격 및 방어 벤치마크",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # attack 서브커맨드
    p_att = sub.add_parser("attack", help="단일 이미지 공격")
    p_att.add_argument("--image", type=Path, required=True)
    p_att.add_argument("--method", choices=["fgsm", "pgd", "bim"], default="fgsm")
    p_att.add_argument("--epsilon", type=float, default=8/255)
    p_att.add_argument("--steps", type=int, default=40)
    p_att.add_argument("--output", type=Path)

    # evaluate 서브커맨드
    p_eval = sub.add_parser("evaluate", help="여러 ε에서 공격 성공률 평가")
    p_eval.add_argument("--image", type=Path, required=True)
    p_eval.add_argument("--epsilons", nargs="+", type=float,
                        default=[0.0, 1/255, 4/255, 8/255, 16/255])

    # compare 서브커맨드
    p_cmp = sub.add_parser("compare", help="방어 기법 비교")
    p_cmp.add_argument("--image", type=Path, required=True)

    args = ap.parse_args()

    match args.cmd:
        case "attack":    cmd_attack(args)
        case "evaluate":  cmd_evaluate(args)
        case "compare":   cmd_compare(args)


if __name__ == "__main__":
    main()
```

---

## 9. 전이 공격 — 블랙박스 환경에서 진짜 무서운 것

실제 방어 관점에서 가장 까다로운 건 **전이(transfer)** 다. 공격자는 오픈 가중치 모델에서 적대적 예제를 만들고, 그걸 피해자 모델에 그대로 쏜다.

**경험적 관찰**:
- 같은 구조(예: ResNet → ResNet): 전이율 60–80%
- 다른 구조(ResNet → ViT): 전이율 30–50%
- **앙상블 공격(여러 모델의 기울기 평균)**: 전이율 80–95%

방어자 관점에서 "우리 모델이 공개되지 않았으니 안전하다"는 가정은 위험하다. 공격자는 ImageNet 같은 공개 데이터로 대체 모델(substitute model)을 학습시킨 뒤 공격한다.

---

## 10. 방어 전략

### 10.1 Adversarial Training — 가장 실전적인 방어

Madry et al.의 min-max 최적화:

$$
\min_\theta \mathbb{E}_{(x,y) \sim \mathcal{D}} \left[ \max_{\|\delta\|_\infty \le \varepsilon} \mathcal{L}(f_\theta(x + \delta), y) \right]
$$

**의사코드**:

```python
for epoch in range(EPOCHS):
    for x, y in loader:
        x_adv = pgd_linf(model, x, y, eps=8/255, alpha=2/255, steps=7)  # 7-step은 실무 기본값
        loss = F.cross_entropy(model(x_adv), y)
        loss.backward(); optim.step(); optim.zero_grad()
```

**현실적인 비용·이득**:
- 학습 시간 ≈ 일반 학습의 **5–10배**
- 깨끗한 정확도(clean accuracy)는 보통 **2–5%p 하락**
- 대신 PGD-40 공격 하에서의 정확도가 0% → 50%+ 로 반등
- TRADES, MART 같은 개선판이 있지만 기본 PGD-AT가 여전히 강력하다

### 10.2 Randomized Smoothing — 인증된(certified) 방어

입력에 가우시안 노이즈를 섞어 여러 번 평가한 뒤 다수결.
Cohen et al. (2019)은 **$L_2$ 반경 $R$ 안에서 수학적으로 증명된 강건성**을 보장한다.

```python
def smoothed_predict(model, x, sigma=0.25, n=100):
    preds = []
    for _ in range(n):
        noise = torch.randn_like(x) * sigma
        preds.append(model(x + noise).argmax(1))
    return torch.mode(torch.stack(preds), 0).values
```

인증 가능하지만 느리고, $L_\infty$에선 보장이 약해진다.

### 10.3 입력 전처리 방어 — "깨는 쪽이 이긴다"

JPEG 재압축·랜덤 크롭·비트 깊이 감소 같은 전처리는 **적응적 공격(adaptive attack)** 에 대부분 뚫린다. Athalye et al. (2018)의 *Obfuscated Gradients* 논문이 대부분의 전처리 방어를 깨부순 이후, 학계 기준에선 PGD-AT와 randomized smoothing만 사실상 인정받는다.

### 10.4 방어 기법 비교 요약

| 방어 기법 | 강건성 수준 | 정확도 손실 | 인증 가능 | 비용 |
|---------|-----------|-----------|---------|------|
| Adversarial Training (PGD-AT) | 높음 | 2~5%p | 아니오 | 학습 5~10배 |
| TRADES | 높음 | 1~3%p | 아니오 | 학습 5~10배 |
| Randomized Smoothing | 중간 (L2) | 5~15%p | 예 (L2) | 추론 N배 |
| JPEG 압축 | 낮음 | 1~2%p | 아니오 | 매우 낮음 |
| 입력 정규화 | 매우 낮음 | 거의 없음 | 아니오 | 없음 |

---

## 11. 평가 프로토콜 — "강건하다" 주장 전에 반드시 체크

실무에서 강건성 평가가 엉터리인 경우가 많다. 최소 체크리스트:

- [ ] **적응적 공격**으로 평가했는가? (방어를 아는 공격자를 가정)
- [ ] PGD step을 충분히(≥40) 돌렸는가?
- [ ] random restart를 10회 이상 했는가?
- [ ] **AutoAttack** (Croce & Hein, 2020)을 돌렸는가? 현재 de-facto 표준.
- [ ] clean accuracy와 robust accuracy를 **같은 표**에 붙였는가?

```bash
pip install autoattack
```

```python
from autoattack import AutoAttack
aa = AutoAttack(model, norm="Linf", eps=8/255, version="standard")
x_adv = aa.run_standard_evaluation(x, y, bs=64)
```

---

## 12. 마무리 — 방어자 체크리스트

프로덕션 분류기를 서비스하는 팀이라면:

1. **위협 모델 먼저 적는다**: 누가, 무엇을 알고, 어떤 L-norm 예산을 갖는가?
2. **오픈 벤치마크에서 AutoAttack 결과**를 측정한다. 공격 복잡도 대비 강건성 곡선을 그린다.
3. **PGD-AT**를 베이스라인으로 학습한다. TRADES는 clean accuracy 손실이 덜하다.
4. **입력 sanity check**: 확률 최댓값이 너무 낮거나 엔트로피가 튀는 샘플은 flag.
5. **쿼리 레이트 제한**: 블랙박스 공격의 기본 비용이 된다. IP당 분당 N회, 이상 패턴 감지.
6. **모니터링**: adversarial 샘플 후보를 로깅하고 수동 검토 큐에 넣는다.

적대적 예제는 "완전히 없애는" 문제가 아니라 **공격자의 비용을 올리는** 문제다. 비용이 ROI를 넘기도록 설계한다.

---

<!-- detect-validate-31 -->
## 적대적 예제 탐지와 방어 검증

적대적 예제는 *입력 섭동·전이성·물리적 패치·쿼리 기반 탐색*으로 모델 판단을 뒤집는다. 방어자는 **자체 모델이 섭동에 견디고 이상 입력이 탐지되는가**를 검증해야 한다. 검증은 **소유 모델/데이터**에서만.

### 공격 → 노리는 약점 → 1차 통제(방어자) → 탐지 신호

| 기법 | 노리는 약점 | 1차 통제(방어자) | 탐지 신호 |
|---|---|---|---|
| 화이트박스 섭동(FGSM/PGD) | 그래디언트 접근 | 적대적 훈련 | 섭동셋 정확도 급락 |
| 전이 공격 | 대체 모델 | 앙상블·입력 변환 | 높은 전이율 |
| 물리적 패치 | 강건성 부족 | 무작위화·탐지기 | 비정상 패턴 영역 |
| 쿼리 기반(블랙박스) | 무제한 쿼리 | 레이트 제한·쿼리 모니터 | 유사 입력 반복 쿼리 |

### 방어 검증 (직접 확인)

```bash
# 1) 자체 모델 강건성 평가(소유 모델) — 깨끗한 입력 vs PGD 정확도 격차로 측정
python3 -c "import art; print('use art.attacks.evasion.ProjectedGradientDescent on owned model; robustness = clean_acc - adv_acc')" 2>&1 | head
# 2) 쿼리 기반 공격 신호 — 유사 입력의 고빈도 반복 쿼리(소유 추론 로그)
awk '{print $NF}' inference.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> 적대적 견고성은 *섭동을 견디는가*다 — "정확도 높다"와 "섭동 입력에서도 정확도가 안 무너지고 쿼리 공격이 탐지된다"는 다르다. 소유 모델에서 clean-adv 격차·반복 쿼리를 직접 확인한다([[56_AI_Red_Teaming]], [[11_AI_Powered_Security]], [[13_SOC_Blue_Team]]).

**최신 기법·통제 (2025–2026):**
- 적대적 예제(회피·전이·패치 공격)가 비전/멀웨어 분류기를 오도 — 적대적 학습·입력 정제·앙상블로 방어. 검증: 강건성이 최신 공격 스위트로 정량 측정되는가([[69_LLM_Security]])
- 물리적 적대예제(스티커 등) — 배포 환경에서 강건성이 유지되는지 확인

---

<a name="english"></a>

# 31-01. Adversarial Examples — Techniques for Deceiving Models at the Input Stage

> **One-line summary**: The decision boundaries of trained models are not smooth. Adding a tiny vector orthogonal to the boundary creates perturbations invisible to humans that completely fool the model.
> This document implements the standard attack lineage from FGSM → PGD → C&W, and extends to defenses.

---

## Intuitive Explanation — "Magic Dust That Fools AI Eyes"

**Analogy**: When a person sees a photo of a cat, our brain synthesizes "ears, whiskers, fur" holistically. But AI processes millions of pixel values mathematically. By changing each pixel ever so slightly (imperceptible to human eyes), the AI's mathematical computation can produce a completely different answer.

```
Original image:    Cat (confidence 99.7%)
          +
Perturbation:      Adjust each pixel by ±8/255 (~3%)
          =
Adversarial image: Ostrich (confidence 87.3%)  ← Only AI is fooled
```

When a human places the two images side by side, they look **completely identical**. Yet the AI gives a different answer.

---

## Why Is This Possible?

### Geometry of High-Dimensional Spaces

28×28 MNIST image: a point in 784-dimensional space
224×224 RGB ImageNet: a point in 150,528-dimensional space

**Counter-intuitive properties of high dimensions**:
- In a high-dimensional sphere, most of the volume concentrates **near the surface**
- Moving in any random direction by a small amount covers significant distance
- The larger the input space, the more likely there exist directions "invisible to humans but detectable by AI"

### Linearity of Neural Networks

Across each ReLU activation region, neural networks are **locally linear**.

```
f(x + δ) ≈ f(x) + J_f(x) · δ

J_f: Jacobian matrix (how each input direction affects output)
δ:   the perturbation we add

Direction to increase loss: δ = ε · sign(∇_x L)
This is all FGSM does
```

---

## Real-World Cases

### Case 1: Fooling Tesla Autopilot

```
Research: McAfee Advanced Threat Research (2020)

Attack method:
- Two black stickers placed on a speed limit sign
- 35mph sign misread as 85mph

Result:
- Tesla autopilot suddenly accelerated
- Physical world attack (no digital editing)

Lesson: Adversarial attacks work in the real world
```

### Case 2: Facial Recognition Bypass

```
Research: Carnegie Mellon University (2016) — "Accessorize to a Crime"

Attack method:
- Wearing specially printed glasses
- Printed pattern acts as adversarial perturbation for facial recognition

Result:
- Misidentified as another person (targeted attack)
- Or not recognized at all (dodging attack)

Lesson: Printed physical objects can bypass facial recognition
```

### Case 3: Stop Sign Misclassification

```
Research: UW/Michigan/UC Berkeley (2017)

Attack method:
- Stickers placed on stop sign (appearing as graffiti)
- Actually precisely calculated adversarial patches

Result:
- Standard deep learning model classified as "Speed Limit 45mph"
- Pedestrians and drivers only thought the sign was damaged

Lesson: Physical patch attacks are extremely hard to detect
```

---

## 1. Why Adversarial Examples Are Possible — The Linearity Hypothesis

Goodfellow et al. (2014)'s intuition: modern neural networks are **locally almost linear**.
In high-dimensional input space, taking just one step in the direction of the loss gradient by a small ε causes the output logits to shift linearly by a large amount.

## 2. FGSM vs PGD Comparison

| Property | FGSM | PGD |
|----------|------|-----|
| Full Name | Fast Gradient Sign Method | Projected Gradient Descent |
| Proposed | Goodfellow et al. (2014) | Madry et al. (2017) |
| Steps | 1 | 10–100 |
| Speed | Very fast | Slow (steps × backprop) |
| Attack Strength | Weak–Medium | Strong (current standard) |
| Random Start | No | Yes (random start within ε-ball) |
| Use Case | Quick data augmentation, rough evaluation | Robustness benchmark, Adversarial Training |
| Formula | $x' = \text{clip}(x + \epsilon \cdot \text{sign}(\nabla_x L))$ | $x^{t+1} = \Pi_{B_\epsilon}(x^t + \alpha \cdot \text{sign}(\nabla_x L))$ |

---

## 3. FGSM Math Explained Step by Step for Beginners

### Step 1: How a Neural Network Judges an Image

```
Image x (pixel values)
    │
    ▼
Run neural network f(x)
    │
    ▼
Scores for each class (logits)
[Cat: 8.5, Dog: 2.1, Ostrich: 0.3, ...]
    │
    ▼
Softmax → Probabilities
[Cat: 99.7%, Dog: 0.2%, Ostrich: 0.1%]
    │
    ▼
Select highest probability class
"Cat"
```

### Step 2: What Is a Loss Function?

```
Loss = How wrong the model is
  - The lower the cat score when the answer is "cat", the higher the loss
  - Cross-Entropy Loss: L = -log(P(correct class))
```

### Step 3: What Does the Gradient Mean?

```
∇_x L = In which direction should we change each pixel of input x
         to increase the loss?

In other words: How should we change pixels to make the model more wrong?
```

### Step 4: Interpreting the FGSM Formula

```python
# Formula: x_adv = x + ε * sign(∇_x L)

# Step by step:
# 1. Calculate ∇_x L (backpropagation)
loss.backward()
gradient = x.grad  # gradient for each pixel

# 2. Apply sign(): take only the sign (+1 or -1)
# Positive gradient → increase pixel, negative → decrease
direction = gradient.sign()

# 3. Scale by ε: limit maximum change
perturbation = epsilon * direction

# 4. Apply and clamp range (pixels must be in 0–1)
x_adv = torch.clamp(x + perturbation, 0.0, 1.0)
```

### Step 5: Why Use sign()?

```
To most efficiently use the L_∞ budget (ε):
- Allocate ε equally to all pixels
- Use only the direction, not the magnitude, of the gradient
- This creates a stronger attack in high dimensions

Mathematically:
The solution that maximizes loss increase under L_∞ constraint
is proven to be: η = ε · sign(∇_x L)
```

---

## 4. FGSM — Single-Step Attack (PyTorch Implementation)

```python
#!/usr/bin/env python3
"""fgsm_attack.py — Apply FGSM perturbation to a single image.

Usage:
    python fgsm_attack.py --image cat.jpg --epsilon 0.03 --out adv.png
"""
from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn.functional as F
import torchvision.transforms as T
from PIL import Image
from torchvision.models import ResNet50_Weights, resnet50


IMAGENET_MEAN = torch.tensor([0.485, 0.456, 0.406]).view(1, 3, 1, 1)
IMAGENET_STD = torch.tensor([0.229, 0.224, 0.225]).view(1, 3, 1, 1)


def load_model(device: torch.device) -> tuple[torch.nn.Module, list[str]]:
    weights = ResNet50_Weights.IMAGENET1K_V2
    model = resnet50(weights=weights).to(device).eval()
    categories = weights.meta["categories"]
    return model, categories


def load_image(path: Path, device: torch.device) -> torch.Tensor:
    pil = Image.open(path).convert("RGB").resize((224, 224))
    return T.ToTensor()(pil).unsqueeze(0).to(device)


def normalize(x: torch.Tensor) -> torch.Tensor:
    return (x - IMAGENET_MEAN.to(x.device)) / IMAGENET_STD.to(x.device)


def fgsm(model, x, y_true, epsilon):
    x_adv = x.clone().detach().requires_grad_(True)
    loss = F.cross_entropy(model(normalize(x_adv)), y_true)
    model.zero_grad()
    loss.backward()
    return torch.clamp(x_adv + epsilon * x_adv.grad.sign(), 0.0, 1.0).detach()


def top1(model, x, categories):
    with torch.no_grad():
        probs = model(normalize(x)).softmax(dim=1)
    conf, idx = probs[0].max(0)
    return int(idx), float(conf), categories[int(idx)]


def main() -> None:
    ap = argparse.ArgumentParser(description="FGSM attack on ImageNet ResNet50")
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--epsilon", type=float, default=8 / 255)
    ap.add_argument("--out", type=Path, default=Path("adv.png"))
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    model, cats = load_model(device)
    x = load_image(args.image, device)

    orig_idx, orig_conf, orig_name = top1(model, x, cats)
    print(f"[clean]  top-1: {orig_name!r} ({orig_conf:.2%})")

    y = torch.tensor([orig_idx], device=device)
    x_adv = fgsm(model, x, y, args.epsilon)

    adv_idx, adv_conf, adv_name = top1(model, x_adv, cats)
    print(f"[attack] ε={args.epsilon:.4f} → {adv_name!r} ({adv_conf:.2%})")
    print(f"         misclassified: {adv_idx != orig_idx}")
    print(f"         L∞ distortion: {(x_adv - x).abs().max().item():.4f}")

    T.ToPILImage()(x_adv.squeeze(0).cpu()).save(args.out)
    print(f"         wrote: {args.out}")


if __name__ == "__main__":
    main()
```

---

## 5. PGD — Multi-Step Optimization (Standard Benchmark)

```python
#!/usr/bin/env python3
"""pgd_attack.py — L_inf PGD (Madry et al., 2017)."""
from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn.functional as F
from torchvision.models import ResNet50_Weights, resnet50

from fgsm_attack import load_image, normalize, top1


def pgd_linf(model, x, y, epsilon, alpha=2/255, steps=40, random_start=True):
    x_adv = x.clone().detach()
    if random_start:
        x_adv += torch.empty_like(x_adv).uniform_(-epsilon, epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

    for _ in range(steps):
        x_adv = x_adv.detach().requires_grad_(True)
        loss = F.cross_entropy(model(normalize(x_adv)), y)
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv.detach() + alpha * grad.sign()
        x_adv = torch.clamp(x_adv, x - epsilon, x + epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

    return x_adv.detach()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--epsilon", type=float, default=8 / 255)
    ap.add_argument("--alpha",   type=float, default=2 / 255)
    ap.add_argument("--steps",   type=int,   default=40)
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    device = torch.device(args.device)
    weights = ResNet50_Weights.IMAGENET1K_V2
    model = resnet50(weights=weights).to(device).eval()
    cats = weights.meta["categories"]
    x = load_image(args.image, device)

    orig_idx, _, orig_name = top1(model, x, cats)
    y = torch.tensor([orig_idx], device=device)
    x_adv = pgd_linf(model, x, y, args.epsilon, args.alpha, args.steps)

    adv_idx, adv_conf, adv_name = top1(model, x_adv, cats)
    print(f"clean:    {orig_name}")
    print(f"PGD-{args.steps}: {adv_name} ({adv_conf:.2%})")
    print(f"success:  {adv_idx != orig_idx}")


if __name__ == "__main__":
    main()
```

---

## 6. Defense Mechanisms

### 6.1 Adversarial Training — Most Practical Defense

```python
# Adversarial training loop
for epoch in range(EPOCHS):
    for x, y in loader:
        # Generate adversarial examples during training
        x_adv = pgd_linf(model, x, y, eps=8/255, alpha=2/255, steps=7)
        loss = F.cross_entropy(model(x_adv), y)
        loss.backward()
        optim.step()
        optim.zero_grad()
```

**Practical cost vs. benefit**:
- Training time ≈ **5–10× longer** than normal training
- Clean accuracy typically drops **2–5 percentage points**
- But robust accuracy under PGD-40 jumps from 0% → 50%+

### 6.2 Defense Comparison

| Defense Method | Robustness Level | Accuracy Loss | Certifiable | Cost |
|---------------|-----------------|---------------|-------------|------|
| PGD Adversarial Training | High | 2–5%p | No | 5–10× training |
| TRADES | High | 1–3%p | No | 5–10× training |
| Randomized Smoothing | Medium (L2) | 5–15%p | Yes (L2) | N× inference |
| JPEG Compression | Low | 1–2%p | No | Very low |
| Input normalization | Very low | Minimal | No | None |

---

## 7. Evaluation Protocol — Must-Check Before Claiming "Robust"

Minimum checklist:

- [ ] Evaluated with **adaptive attacks**? (assumes attacker knows the defense)
- [ ] Ran PGD with enough steps (≥40)?
- [ ] Applied 10+ random restarts?
- [ ] Ran **AutoAttack** (Croce & Hein, 2020)? Current de facto standard.
- [ ] Reported clean accuracy and robust accuracy **in the same table**?

```bash
pip install autoattack
```

```python
from autoattack import AutoAttack
aa = AutoAttack(model, norm="Linf", eps=8/255, version="standard")
x_adv = aa.run_standard_evaluation(x, y, bs=64)
```

---

## 8. Practical Defense Guidance

For teams serving production classifiers:

1. **Write a threat model first**: Who knows what, and what L-norm budget do they have?
2. **Measure AutoAttack results on open benchmarks**. Draw a robustness curve against attack complexity.
3. **Train with PGD-AT as a baseline**. TRADES suffers less clean accuracy loss.
4. **Input sanity check**: Flag samples where the max probability is too low or entropy spikes.
5. **Query rate limiting**: This becomes the baseline cost for black-box attacks. N requests per IP per minute, detect anomalous patterns.
6. **Monitoring**: Log adversarial sample candidates and put them in a manual review queue.

Adversarial examples are not a problem of "completely eliminating" but of **raising the attacker's cost**. Design so the cost exceeds ROI.

<!-- detect-validate-31 -->
## Adversarial Examples Detection and Defense Validation

Adversarial examples flip model decisions via *input perturbation, transferability, physical patches, and query-based search*. Defenders must verify **whether their model resists perturbation and abnormal inputs are detected**. Validate only on **owned models/data**.

### Attack -> Targeted weakness -> Primary control (defender) -> Detection signal

| Technique | Targeted weakness | Primary control (defender) | Detection signal |
|---|---|---|---|
| White-box perturbation (FGSM/PGD) | Gradient access | Adversarial training | Accuracy collapse on perturbed set |
| Transfer attack | Substitute model | Ensemble, input transform | High transfer rate |
| Physical patch | Lack of robustness | Randomization, detector | Abnormal pattern region |
| Query-based (black-box) | Unlimited queries | Rate limit, query monitoring | Repeated near-duplicate queries |

### Defense validation (verify directly)

```bash
# 1) Evaluate your model's robustness (owned model) — measure via clean vs PGD accuracy gap
python3 -c "import art; print('use art.attacks.evasion.ProjectedGradientDescent on owned model; robustness = clean_acc - adv_acc')" 2>&1 | head
# 2) Query-based attack signal — high-frequency repeated near-duplicate queries (owned inference log)
awk '{print $NF}' inference.log 2>/dev/null | sort | uniq -c | sort -rn | head
```

> Adversarial robustness is *whether it resists perturbation* -- "accuracy is high" differs from "accuracy holds even on perturbed inputs and query attacks are detected". Confirm the clean-adv gap and repeated queries on owned models directly ([[56_AI_Red_Teaming]], [[11_AI_Powered_Security]], [[13_SOC_Blue_Team]]).
