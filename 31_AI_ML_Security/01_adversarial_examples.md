# 31-01. 적대적 예제 — 입력 단계에서 모델을 속이는 기술

> **한 줄 요약**: 학습된 모델의 결정 경계는 매끄럽지 않다. 경계에 직교하는 방향으로 아주 작은 벡터를 더하면 사람 눈엔 안 보이는데 모델만 완전히 잘못 본다.
> 이 문서는 FGSM → PGD → C&W로 이어지는 표준 공격 계보를 직접 구현하고, 방어까지 이어갑니다.

## 1. 적대적 예제가 왜 가능한가 — 선형성 가설

Goodfellow et al. (2014)의 직관: 현대 신경망은 **국소적으로 거의 선형**이다.
고차원 입력 공간에서 작은 ε을 손실 기울기 방향으로 한 걸음만 가도, 출력 로짓(logit)은 선형적으로 훌쩍 움직인다.

$$
\mathcal{L}(\theta, x + \eta, y) \approx \mathcal{L}(\theta, x, y) + \eta^\top \nabla_x \mathcal{L}
$$

즉 $\eta = \varepsilon \cdot \mathrm{sign}(\nabla_x \mathcal{L})$ 로 정하면 손실이 가장 빨리 증가하고, 이는 곧 오분류로 이어진다. 이게 **FGSM**(Fast Gradient Sign Method)의 전부다.

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

## 3. FGSM — 한 방 공격 (PyTorch 완성본)

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

## 4. PGD — 여러 걸음으로 최적화 (표준 벤치마크)

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

## 5. C&W 공격 — 최소 왜곡으로 집요하게

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

## 6. 전이 공격 — 블랙박스 환경에서 진짜 무서운 것

실제 방어 관점에서 가장 까다로운 건 **전이(transfer)** 다. 공격자는 오픈 가중치 모델에서 적대적 예제를 만들고, 그걸 피해자 모델에 그대로 쏜다.

**경험적 관찰**:
- 같은 구조(예: ResNet → ResNet): 전이율 60–80%
- 다른 구조(ResNet → ViT): 전이율 30–50%
- **앙상블 공격(여러 모델의 기울기 평균)**: 전이율 80–95%

방어자 관점에서 "우리 모델이 공개되지 않았으니 안전하다"는 가정은 위험하다. 공격자는 ImageNet 같은 공개 데이터로 대체 모델(substitute model)을 학습시킨 뒤 공격한다.

## 7. 방어 전략

### 7.1 Adversarial Training — 가장 실전적인 방어

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

### 7.2 Randomized Smoothing — 인증된(certified) 방어

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

### 7.3 입력 전처리 방어 — "깨는 쪽이 이긴다"

JPEG 재압축·랜덤 크롭·비트 깊이 감소 같은 전처리는 **적응적 공격(adaptive attack)** 에 대부분 뚫린다. Athalye et al. (2018)의 *Obfuscated Gradients* 논문이 대부분의 전처리 방어를 깨부순 이후, 학계 기준에선 PGD-AT와 randomized smoothing만 사실상 인정받는다.

## 8. 평가 프로토콜 — "강건하다" 주장 전에 반드시 체크

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

## 9. 마무리 — 방어자 체크리스트

프로덕션 분류기를 서비스하는 팀이라면:

1. **위협 모델 먼저 적는다**: 누가, 무엇을 알고, 어떤 L-norm 예산을 갖는가?
2. **오픈 벤치마크에서 AutoAttack 결과**를 측정한다. 공격 복잡도 대비 강건성 곡선을 그린다.
3. **PGD-AT**를 베이스라인으로 학습한다. TRADES는 clean accuracy 손실이 덜하다.
4. **입력 sanity check**: 확률 최댓값이 너무 낮거나 엔트로피가 튀는 샘플은 flag.
5. **쿼리 레이트 제한**: 블랙박스 공격의 기본 비용이 된다. IP당 분당 N회, 이상 패턴 감지.
6. **모니터링**: adversarial 샘플 후보를 로깅하고 수동 검토 큐에 넣는다.

적대적 예제는 "완전히 없애는" 문제가 아니라 **공격자의 비용을 올리는** 문제다. 비용이 ROI를 넘기도록 설계한다.
