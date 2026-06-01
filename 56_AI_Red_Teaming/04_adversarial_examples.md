> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 적대적 예제 (Adversarial Examples)

## 개요

적대적 예제(Adversarial Examples)는 사람이 인지하기 어려운 미세한 변형이 가해진 입력으로, 머신러닝 모델을 오분류하도록 유도한다. 픽셀 단위의 작은 노이즈가 "고양이"를 "비행기"로, "정지 신호"를 "속도 제한" 표지판으로 잘못 인식하게 만들 수 있다. 이 취약점은 이미지, 텍스트, 음성 등 모든 모달리티에 존재한다.

---

## 1. 주요 적대적 공격 기법

### 1.1 이미지 분야 공격 비교

| 기법 | 전체 명칭 | 유형 | 쿼리 수 | 계산 비용 | 전이성 |
|---|---|---|---|---|---|
| **FGSM** | Fast Gradient Sign Method | 화이트박스, 단일 단계 | 1 | 매우 낮음 | 중간 |
| **I-FGSM** | Iterative FGSM | 화이트박스, 반복 | n | 낮음 | 낮음 |
| **PGD** | Projected Gradient Descent | 화이트박스, 반복 | n | 낮음 | 중간 |
| **CW** | Carlini & Wagner | 화이트박스, 최적화 | 매우 많음 | 높음 | 높음 |
| **DeepFool** | DeepFool | 화이트박스, 반복 | 중간 | 중간 | 중간 |
| **Square** | Square Attack | 블랙박스, 반복 | 많음 | 중간 | 낮음 |
| **NES** | Natural Evolution Strategies | 블랙박스 | 많음 | 높음 | 낮음 |
| **Boundary** | Boundary Attack | 블랙박스, Decision-based | 매우 많음 | 높음 | 낮음 |

### 1.2 FGSM 공격 원리

FGSM은 모델의 손실 함수에 대한 입력의 그라디언트 부호를 이용한다.

```
x_adv = x + ε × sign(∇_x J(θ, x, y))
```

- `x`: 원본 입력
- `ε`: 교란 강도 (epsilon)
- `∇_x J(θ, x, y)`: 입력에 대한 손실 그라디언트
- `sign()`: 부호 함수 (-1 또는 +1)

### 1.3 PGD 공격 원리

PGD는 FGSM을 반복적으로 적용하며, 각 단계에서 교란을 ε-볼 안에 투영(projection)한다.

```
x_adv^{t+1} = Clip_{x,ε}(x_adv^t + α × sign(∇_x J(θ, x_adv^t, y)))
```

- `α`: 각 단계 크기 (step size)
- `Clip_{x,ε}`: x를 중심으로 반경 ε 이내로 클리핑

### 1.4 CW 공격 원리

CW 공격은 다음 최적화 문제를 풀어 최소 교란의 적대적 예제를 생성한다.

```
minimize ‖δ‖_p + c × f(x + δ)
subject to x + δ ∈ [0, 1]^n
```

- `δ`: 교란 벡터
- `‖δ‖_p`: Lp 노름 (L0, L2, L∞)
- `f()`: 오분류를 위한 신뢰도 기반 손실 함수

---

## 2. 물리적 적대적 패치

물리적 세계에서도 적대적 예제가 효과를 발휘한다는 것이 연구로 증명되었다.

| 공격 방법 | 대상 | 특징 |
|---|---|---|
| **적대적 안경** | 얼굴 인식 | 특수 패턴의 안경으로 신원 오인식 유발 |
| **적대적 티셔츠** | 보행자 검출 | 사람 검출 모델 회피 |
| **적대적 패치** | 교통 표지판 분류 | 정지 표지에 스티커 부착으로 오분류 |
| **적대적 조명** | CCTV 시스템 | 특수 조명 패턴으로 얼굴 인식 방해 |
| **적대적 화장** | 얼굴 인식 | 분장/화장으로 신원 회피 |
| **적대적 레이저** | 카메라 기반 시스템 | 저전력 레이저로 센서 교란 |

물리적 공격은 다음 조건을 충족해야 한다.
- 인쇄 과정에서 색상 변환 후에도 효과 유지
- 다양한 각도, 거리, 조명에서 효과 유지
- 사람이 이상하게 인식하지 못하는 수준

---

## 3. 음성 인식 적대적 예제

### 3.1 음향 적대적 공격 분류

| 공격명 | 공격 방법 | 대상 시스템 | 탐지 가능성 |
|---|---|---|---|
| **초음파 공격** | 20kHz 이상 주파수로 명령 전송 | 스마트 스피커, 음성 비서 | 낮음 |
| **사이코어쿠스틱 공격** | 사람 청각 마스킹 현상 이용 | 음성 인식 API | 매우 낮음 |
| **음악 속 명령** | 음악에 음성 명령을 숨김 | 스마트 디바이스 | 낮음 |
| **백마스킹** | 역방향 재생 시 명령 포함 | 음성 인식 모델 | 낮음 |
| **화자 스푸핑** | 합성 음성으로 화자 인증 우회 | 화자 인증 시스템 | 중간 |

### 3.2 공격 원리 (사이코어쿠스틱)

사람의 청각은 큰 소리 옆의 작은 소리를 인식하지 못한다(음향 마스킹 효과). 이를 이용하여 원본 음성에 청각적으로 마스킹된 적대적 신호를 추가한다.

```
x_adv = x_original + δ
where δ는 사람의 청각 임계값 미만이지만 ASR 모델을 오인식시키는 신호
```

---

## 4. FGSM 적대적 예제 생성기 CLI

```python
#!/usr/bin/env python3
"""
FGSM 적대적 예제 생성기
numpy와 PIL만으로 FGSM 기반 적대적 예제를 생성한다.
torch 없이 수동 그라디언트 근사를 사용하며 배치 처리를 지원한다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


try:
    import numpy as np
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


@dataclass
class AdversarialConfig:
    """적대적 예제 생성 설정."""
    epsilon: float = 0.03          # 교란 강도 (0~1 범위, 픽셀값 기준)
    iterations: int = 1            # 반복 횟수 (1=FGSM, >1=I-FGSM)
    step_size: float | None = None # 반복당 크기 (None이면 epsilon/iterations)
    norm: str = "linf"             # 노름 유형: linf / l2
    clip_min: float = 0.0
    clip_max: float = 1.0
    targeted: bool = False         # True이면 특정 클래스로 유도하는 타겟 공격


@dataclass
class GenerationResult:
    """단일 이미지에 대한 적대적 예제 생성 결과."""
    input_path: str
    output_path: str
    original_shape: tuple[int, ...]
    epsilon_used: float
    l_inf_norm: float              # 실제 적용된 교란의 L∞ 노름
    l2_norm: float                 # 실제 적용된 교란의 L2 노름
    success: bool
    error: str = ""
    duration_ms: float = 0.0


def load_image_as_array(path: Path) -> np.ndarray:
    """이미지를 [0, 1] 범위의 float32 배열로 로드한다."""
    if not HAS_PIL:
        raise RuntimeError("PIL이 필요합니다: pip install Pillow numpy")
    img = Image.open(path).convert("RGB")
    arr = np.array(img, dtype=np.float32) / 255.0
    return arr  # shape: (H, W, 3)


def save_array_as_image(arr: np.ndarray, path: Path) -> None:
    """[0, 1] 범위의 float32 배열을 이미지 파일로 저장한다."""
    clipped = np.clip(arr * 255.0, 0, 255).astype(np.uint8)
    img = Image.fromarray(clipped)
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)


def estimate_gradient_sign(
    image: np.ndarray,
    true_class: int,
    n_classes: int,
    probe_epsilon: float = 1e-4,
) -> np.ndarray:
    """
    손실 함수 그라디언트 부호를 유한 차분법으로 근사한다.
    실제 환경에서는 모델 API에 쿼리하여 신뢰도를 얻는다.

    여기서는 데모 목적으로 더 높은 주파수 성분 방향을 그라디언트로 사용한다.
    (실제 공격에서는 타겟 모델의 신뢰도 차이로 대체)
    """
    # 채널별 Sobel 에지 검출을 그라디언트 근사로 활용 (데모)
    H, W, C = image.shape
    grad_sign = np.zeros_like(image)

    for c in range(C):
        channel = image[:, :, c]
        # 수평 그라디언트
        gx = np.zeros_like(channel)
        gx[:, :-1] = channel[:, 1:] - channel[:, :-1]
        # 수직 그라디언트
        gy = np.zeros_like(channel)
        gy[:-1, :] = channel[1:, :] - channel[:-1, :]

        grad_magnitude = np.sqrt(gx**2 + gy**2)
        # 그라디언트 부호 결정 (에지 방향 기반)
        grad_sign[:, :, c] = np.where(grad_magnitude > probe_epsilon, 1.0, -1.0)

    return grad_sign


def apply_fgsm(
    image: np.ndarray,
    grad_sign: np.ndarray,
    epsilon: float,
    targeted: bool,
    clip_min: float,
    clip_max: float,
) -> np.ndarray:
    """FGSM 교란을 적용한다."""
    direction = -1.0 if targeted else 1.0  # 타겟 공격: 손실 최소화 방향
    perturbation = direction * epsilon * grad_sign
    adversarial = image + perturbation
    return np.clip(adversarial, clip_min, clip_max)


def apply_ifgsm(
    image: np.ndarray,
    grad_sign: np.ndarray,
    config: AdversarialConfig,
) -> np.ndarray:
    """
    I-FGSM(반복적 FGSM)을 적용한다.
    각 단계에서 epsilon 볼 안에 결과를 투영한다.
    """
    step = config.step_size or (config.epsilon / config.iterations)
    direction = -1.0 if config.targeted else 1.0

    x_adv = image.copy()
    for _ in range(config.iterations):
        # 단일 단계 교란
        perturbation = direction * step * grad_sign
        x_adv = x_adv + perturbation

        # epsilon 볼 안에 투영 (L∞ 기준)
        delta = x_adv - image
        delta_clipped = np.clip(delta, -config.epsilon, config.epsilon)
        x_adv = image + delta_clipped

        # 유효 픽셀 범위로 클리핑
        x_adv = np.clip(x_adv, config.clip_min, config.clip_max)

    return x_adv


def compute_perturbation_stats(
    original: np.ndarray,
    adversarial: np.ndarray,
) -> tuple[float, float]:
    """교란의 L∞ 및 L2 노름을 계산한다."""
    delta = adversarial - original
    l_inf = float(np.max(np.abs(delta)))
    l2 = float(np.sqrt(np.sum(delta**2)))
    return l_inf, l2


def add_visual_marker(
    image: np.ndarray,
    l_inf: float,
    epsilon: float,
) -> np.ndarray:
    """
    분석 목적으로 이미지 우측 하단에 교란 강도 정보를 표시한다.
    실제 공격용 예제에는 포함하지 않는다.
    """
    marked = image.copy()
    # 우측 하단 10x10 픽셀을 교란 비율에 따라 색상 표시
    ratio = min(l_inf / epsilon, 1.0) if epsilon > 0 else 0.0
    H, W = marked.shape[:2]
    marked[H-10:H, W-10:W, 0] = ratio       # 빨간 채널
    marked[H-10:H, W-10:W, 1] = 1.0 - ratio  # 녹색 채널
    marked[H-10:H, W-10:W, 2] = 0.0
    return marked


def generate_adversarial_single(
    input_path: Path,
    output_path: Path,
    config: AdversarialConfig,
    true_class: int,
    n_classes: int,
    add_marker: bool,
) -> GenerationResult:
    """단일 이미지에 대한 적대적 예제를 생성한다."""
    start = time.time()

    if not input_path.exists():
        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=(),
            epsilon_used=config.epsilon,
            l_inf_norm=0.0,
            l2_norm=0.0,
            success=False,
            error=f"파일을 찾을 수 없습니다: {input_path}",
        )

    try:
        original = load_image_as_array(input_path)
        grad_sign = estimate_gradient_sign(original, true_class, n_classes)

        if config.iterations <= 1:
            adversarial = apply_fgsm(
                original, grad_sign, config.epsilon,
                config.targeted, config.clip_min, config.clip_max
            )
        else:
            adversarial = apply_ifgsm(original, grad_sign, config)

        if add_marker:
            l_inf_check, _ = compute_perturbation_stats(original, adversarial)
            adversarial = add_visual_marker(adversarial, l_inf_check, config.epsilon)

        save_array_as_image(adversarial, output_path)

        l_inf, l2 = compute_perturbation_stats(original, adversarial)
        elapsed = (time.time() - start) * 1000

        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=original.shape,
            epsilon_used=config.epsilon,
            l_inf_norm=l_inf,
            l2_norm=l2,
            success=True,
            duration_ms=elapsed,
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=(),
            epsilon_used=config.epsilon,
            l_inf_norm=0.0,
            l2_norm=0.0,
            success=False,
            error=str(e),
            duration_ms=elapsed,
        )


def collect_image_paths(source: Path, extensions: set[str]) -> list[Path]:
    """디렉토리 또는 단일 파일에서 이미지 경로를 수집한다."""
    if source.is_file():
        return [source]
    if source.is_dir():
        paths: list[Path] = []
        for ext in extensions:
            paths.extend(source.rglob(f"*.{ext}"))
            paths.extend(source.rglob(f"*.{ext.upper()}"))
        return sorted(paths)
    return []


def build_output_path(
    input_path: Path,
    input_base: Path,
    output_dir: Path,
    suffix: str,
) -> Path:
    """입력 경로 구조를 유지하면서 출력 경로를 계산한다."""
    try:
        relative = input_path.relative_to(input_base)
    except ValueError:
        relative = Path(input_path.name)

    stem = relative.stem
    ext = relative.suffix
    new_name = f"{stem}{suffix}{ext}"
    return output_dir / relative.parent / new_name


def print_batch_summary(results: list[GenerationResult]) -> None:
    """배치 처리 결과 요약을 출력한다."""
    total = len(results)
    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    avg_l_inf = sum(r.l_inf_norm for r in success) / len(success) if success else 0
    avg_l2 = sum(r.l2_norm for r in success) / len(success) if success else 0
    avg_ms = sum(r.duration_ms for r in success) / len(success) if success else 0

    print("\n" + "=" * 60)
    print("적대적 예제 배치 생성 결과")
    print("=" * 60)
    print(f"총 이미지      : {total}개")
    print(f"성공           : {len(success)}개")
    print(f"실패           : {len(failed)}개")
    print(f"평균 L∞ 노름  : {avg_l_inf:.4f}")
    print(f"평균 L2 노름  : {avg_l2:.4f}")
    print(f"평균 처리 시간 : {avg_ms:.1f}ms/이미지")

    if failed:
        print()
        print("[실패 목록]")
        for r in failed[:5]:
            print(f"  {r.input_path}: {r.error}")
        if len(failed) > 5:
            print(f"  ... 외 {len(failed) - 5}개")

    print("=" * 60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fgsm-generator",
        description="FGSM 적대적 예제 생성기 (numpy/PIL 기반, torch 불필요)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 단일 이미지
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image cat.jpg \\
      --epsilon 0.05 \\
      --output adversarial_cat.jpg

  # 배치 처리 (디렉토리 전체)
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image ./dataset/images/ \\
      --epsilon 0.03 \\
      --output ./adversarial_output/ \\
      --iterations 10 \\
      --workers 4

  # 강한 교란 (시각적 확인용)
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image stop_sign.jpg \\
      --epsilon 0.2 \\
      --output adversarial_stop.jpg \\
      --add-marker
        """,
    )
    parser.add_argument(
        "--model",
        default="dummy",
        metavar="MODEL",
        help="타겟 모델 식별자 (현재는 그라디언트 근사 사용, 기본값: dummy)",
    )
    parser.add_argument(
        "--image",
        required=True,
        type=Path,
        metavar="PATH",
        help="입력 이미지 파일 또는 디렉토리",
    )
    parser.add_argument(
        "--epsilon",
        type=float,
        default=0.03,
        metavar="FLOAT",
        help="교란 강도 (0~1 범위, 기본값: 0.03)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        metavar="PATH",
        help="출력 이미지 파일 또는 디렉토리",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        metavar="N",
        help="반복 횟수 (1=FGSM, >1=I-FGSM, 기본값: 1)",
    )
    parser.add_argument(
        "--step-size",
        type=float,
        default=None,
        metavar="FLOAT",
        help="반복 공격 시 단계 크기 (기본값: epsilon/iterations)",
    )
    parser.add_argument(
        "--norm",
        choices=["linf", "l2"],
        default="linf",
        help="교란 노름 유형 (기본값: linf)",
    )
    parser.add_argument(
        "--targeted",
        action="store_true",
        help="타겟 공격 모드 (손실 최소화 방향)",
    )
    parser.add_argument(
        "--true-class",
        type=int,
        default=0,
        metavar="N",
        help="원본 이미지의 실제 클래스 인덱스 (기본값: 0)",
    )
    parser.add_argument(
        "--n-classes",
        type=int,
        default=1000,
        metavar="N",
        help="모델의 전체 클래스 수 (기본값: 1000)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        metavar="N",
        help="병렬 처리 프로세스 수 (기본값: 2)",
    )
    parser.add_argument(
        "--suffix",
        default="_adv",
        metavar="STR",
        help="배치 모드에서 출력 파일명 접미사 (기본값: _adv)",
    )
    parser.add_argument(
        "--add-marker",
        action="store_true",
        help="분석용 교란 강도 시각 마커 추가",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="결과 JSON 저장 경로",
    )
    return parser


def main() -> int:
    if not HAS_PIL:
        print("[!] 필수 패키지가 없습니다: pip install Pillow numpy", file=sys.stderr)
        return 1

    parser = build_parser()
    args = parser.parse_args()

    if args.epsilon <= 0 or args.epsilon > 1:
        print(f"[!] epsilon은 0~1 범위여야 합니다: {args.epsilon}", file=sys.stderr)
        return 1

    config = AdversarialConfig(
        epsilon=args.epsilon,
        iterations=args.iterations,
        step_size=args.step_size,
        norm=args.norm,
        targeted=args.targeted,
    )

    IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "bmp", "webp"}
    image_paths = collect_image_paths(args.image, IMAGE_EXTENSIONS)

    if not image_paths:
        print(f"[!] 이미지를 찾을 수 없습니다: {args.image}", file=sys.stderr)
        return 1

    # 단일 파일 vs 배치 모드 판별
    is_batch = len(image_paths) > 1 or args.image.is_dir()

    print(f"[*] FGSM 적대적 예제 생성 시작")
    print(f"    이미지: {len(image_paths)}개 | ε={args.epsilon} | 반복={args.iterations} | 노름={args.norm}")

    # 출력 경로 결정
    if is_batch:
        input_base = args.image if args.image.is_dir() else args.image.parent
        output_paths = [
            build_output_path(p, input_base, args.output, args.suffix)
            for p in image_paths
        ]
    else:
        output_paths = [args.output]

    # 배치 처리
    results: list[GenerationResult] = []
    tasks = list(zip(image_paths, output_paths))

    if args.workers > 1 and len(tasks) > 1:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(
                    generate_adversarial_single,
                    inp, out, config,
                    args.true_class, args.n_classes, args.add_marker
                ): (inp, out)
                for inp, out in tasks
            }
            completed = 0
            for future in as_completed(future_map):
                result = future.result()
                results.append(result)
                completed += 1
                status = "완료" if result.success else "실패"
                print(f"  [{completed}/{len(tasks)}] {status}: {result.input_path}")
    else:
        for i, (inp, out) in enumerate(tasks, 1):
            result = generate_adversarial_single(
                inp, out, config,
                args.true_class, args.n_classes, args.add_marker
            )
            results.append(result)
            status = "완료" if result.success else "실패"
            print(f"  [{i}/{len(tasks)}] {status}: {inp.name}")
            if not result.success:
                print(f"    오류: {result.error}")

    print_batch_summary(results)

    if args.output_json:
        import dataclasses
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with args.output_json.open("w", encoding="utf-8") as f:
            serialized = [dataclasses.asdict(r) for r in results]
            json.dump(serialized, f, ensure_ascii=False, indent=2)
        print(f"[+] 결과 JSON 저장: {args.output_json}")

    failed_count = sum(1 for r in results if not r.success)
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. 적대적 강건성 평가 지표

| 지표 | 설명 | 계산 방법 |
|---|---|---|
| **강건 정확도** | 적대적 공격 하에서의 분류 정확도 | 공격 후 정확 분류 수 / 전체 샘플 수 |
| **공격 성공률** | 오분류를 유발한 비율 | 오분류 수 / 전체 공격 수 |
| **최소 교란** | 오분류 유발에 필요한 최소 ε | 이분법 탐색으로 최소 epsilon 탐색 |
| **전이율** | 다른 모델에서 생성한 공격의 성공률 | 타겟 모델에서의 공격 성공률 |
| **인지 가능성** | 사람이 변형을 인지할 수 있는 정도 | SSIM, LPIPS, 사용자 연구 |

---

## 6. 방어 기법 비교

| 방어 기법 | 원리 | 장점 | 단점 |
|---|---|---|---|
| **적대적 학습** | 공격 예제를 학습 데이터에 포함 | 가장 효과적 | 학습 비용 증가, 미지 공격에 취약 |
| **입력 전처리** | JPEG 압축, 스무딩으로 교란 제거 | 구현 쉬움 | 강한 공격에 효과 미비 |
| **차분 프라이버시** | 학습 시 가우시안 노이즈 추가 | 이론적 보장 | 정확도 손실 |
| **랜덤화 스무딩** | 추론 시 랜덤 노이즈 추가 + 다수결 | L2 강건성 인증 가능 | 계산 비용, L∞ 미지원 |
| **탐지기 추가** | 별도 신경망으로 적대적 예제 탐지 | 탐지 후 거부 가능 | 탐지기 자체도 공격 가능 |
| **입력 변환 앙상블** | 다양한 전처리 후 앙상블 | 적응형 공격에 부분 저항 | 계산 비용 |

---

## 참고 자료

- "Explaining and Harnessing Adversarial Examples" (Goodfellow et al., 2014) — FGSM 원논문
- "Towards Evaluating the Robustness of Neural Networks" (Carlini & Wagner, 2016) — CW 공격
- "Towards Deep Learning Models Resistant to Adversarial Attacks" (Madry et al., 2017) — PGD 공격
- "Adversarial Patch" (Brown et al., 2017) — 물리적 패치 공격
- "Hidden Voice Commands" (Carlini et al., 2016) — 음성 적대적 예제
- CleverHans 라이브러리: https://github.com/cleverhans-lab/cleverhans
- ART(Adversarial Robustness Toolbox): https://github.com/Trusted-AI/adversarial-robustness-toolbox

---

<a name="english"></a>

# Adversarial Examples

## Overview

Adversarial examples are inputs with subtle perturbations that are imperceptible to humans, yet cause machine learning models to misclassify them. A small pixel-level noise can make a model mistake "cat" for "airplane", or a "stop sign" for a "speed limit" sign. This vulnerability exists across all modalities — images, text, and audio.

---

## 1. Major Adversarial Attack Techniques

### 1.1 Image Attack Comparison

| Technique | Full Name | Type | Queries | Compute Cost | Transferability |
|---|---|---|---|---|---|
| **FGSM** | Fast Gradient Sign Method | White-box, single-step | 1 | Very low | Medium |
| **I-FGSM** | Iterative FGSM | White-box, iterative | n | Low | Low |
| **PGD** | Projected Gradient Descent | White-box, iterative | n | Low | Medium |
| **CW** | Carlini & Wagner | White-box, optimization | Very many | High | High |
| **DeepFool** | DeepFool | White-box, iterative | Medium | Medium | Medium |
| **Square** | Square Attack | Black-box, iterative | Many | Medium | Low |
| **NES** | Natural Evolution Strategies | Black-box | Many | High | Low |
| **Boundary** | Boundary Attack | Black-box, decision-based | Very many | High | Low |

### 1.2 FGSM Attack Principle

FGSM uses the sign of the gradient of the model's loss function with respect to the input.

```
x_adv = x + ε × sign(∇_x J(θ, x, y))
```

- `x`: original input
- `ε`: perturbation magnitude (epsilon)
- `∇_x J(θ, x, y)`: loss gradient with respect to the input
- `sign()`: sign function (-1 or +1)

### 1.3 PGD Attack Principle

PGD applies FGSM iteratively, projecting the perturbation back into the ε-ball at each step.

```
x_adv^{t+1} = Clip_{x,ε}(x_adv^t + α × sign(∇_x J(θ, x_adv^t, y)))
```

- `α`: step size per iteration
- `Clip_{x,ε}`: clipping within radius ε around x

### 1.4 CW Attack Principle

The CW attack generates adversarial examples with minimal perturbation by solving the following optimization problem.

```
minimize ‖δ‖_p + c × f(x + δ)
subject to x + δ ∈ [0, 1]^n
```

- `δ`: perturbation vector
- `‖δ‖_p`: Lp norm (L0, L2, L∞)
- `f()`: confidence-based loss function for misclassification

---

## 2. Physical Adversarial Patches

Research has demonstrated that adversarial examples can also be effective in the physical world.

| Attack Method | Target | Characteristics |
|---|---|---|
| **Adversarial glasses** | Face recognition | Induces identity misrecognition with specially patterned glasses |
| **Adversarial t-shirt** | Pedestrian detection | Evades human detection models |
| **Adversarial patch** | Traffic sign classification | Causes misclassification by attaching a sticker to a stop sign |
| **Adversarial lighting** | CCTV systems | Disrupts face recognition with special lighting patterns |
| **Adversarial makeup** | Face recognition | Evades identity recognition through makeup/disguise |
| **Adversarial laser** | Camera-based systems | Disrupts sensors with low-power lasers |

Physical attacks must satisfy the following conditions:
- Effectiveness must persist after color transformation during printing
- Effectiveness must hold across various angles, distances, and lighting conditions
- Must not appear suspicious to a human observer

---

## 3. Audio Adversarial Examples

### 3.1 Acoustic Adversarial Attack Categories

| Attack Name | Attack Method | Target System | Detectability |
|---|---|---|---|
| **Ultrasonic attack** | Commands sent via frequencies above 20kHz | Smart speakers, voice assistants | Low |
| **Psychoacoustic attack** | Exploits human auditory masking | Speech recognition APIs | Very low |
| **Commands in music** | Hides voice commands inside music | Smart devices | Low |
| **Backmasking** | Commands embedded in reverse playback | Speech recognition models | Low |
| **Speaker spoofing** | Bypasses speaker authentication with synthetic voice | Speaker verification systems | Medium |

### 3.2 Attack Principle (Psychoacoustic)

The human auditory system fails to perceive a quiet sound next to a loud one (acoustic masking effect). This is exploited by adding an adversarially masked signal to the original audio.

```
x_adv = x_original + δ
where δ is a signal below the human auditory threshold but causes ASR model misrecognition
```

---

## 4. FGSM Adversarial Example Generator CLI

```python
#!/usr/bin/env python3
"""
FGSM Adversarial Example Generator
Generates FGSM-based adversarial examples using only numpy and PIL.
Uses manual gradient approximation without torch, and supports batch processing.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


try:
    import numpy as np
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


@dataclass
class AdversarialConfig:
    """Adversarial example generation configuration."""
    epsilon: float = 0.03          # Perturbation magnitude (0~1 range, pixel value scale)
    iterations: int = 1            # Number of iterations (1=FGSM, >1=I-FGSM)
    step_size: float | None = None # Step size per iteration (None = epsilon/iterations)
    norm: str = "linf"             # Norm type: linf / l2
    clip_min: float = 0.0
    clip_max: float = 1.0
    targeted: bool = False         # If True, targeted attack steering toward a specific class


@dataclass
class GenerationResult:
    """Adversarial example generation result for a single image."""
    input_path: str
    output_path: str
    original_shape: tuple[int, ...]
    epsilon_used: float
    l_inf_norm: float              # L∞ norm of the applied perturbation
    l2_norm: float                 # L2 norm of the applied perturbation
    success: bool
    error: str = ""
    duration_ms: float = 0.0


def load_image_as_array(path: Path) -> np.ndarray:
    """Load an image as a float32 array in the [0, 1] range."""
    if not HAS_PIL:
        raise RuntimeError("PIL is required: pip install Pillow numpy")
    img = Image.open(path).convert("RGB")
    arr = np.array(img, dtype=np.float32) / 255.0
    return arr  # shape: (H, W, 3)


def save_array_as_image(arr: np.ndarray, path: Path) -> None:
    """Save a float32 array in [0, 1] range as an image file."""
    clipped = np.clip(arr * 255.0, 0, 255).astype(np.uint8)
    img = Image.fromarray(clipped)
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path)


def estimate_gradient_sign(
    image: np.ndarray,
    true_class: int,
    n_classes: int,
    probe_epsilon: float = 1e-4,
) -> np.ndarray:
    """
    Approximate the sign of the loss gradient using finite differences.
    In a real environment, model confidence is obtained by querying the model API.

    Here, for demo purposes, the direction of higher-frequency components is used as the gradient.
    (In a real attack, this would be replaced by confidence differences from the target model.)
    """
    # Use per-channel Sobel edge detection as gradient approximation (demo)
    H, W, C = image.shape
    grad_sign = np.zeros_like(image)

    for c in range(C):
        channel = image[:, :, c]
        # Horizontal gradient
        gx = np.zeros_like(channel)
        gx[:, :-1] = channel[:, 1:] - channel[:, :-1]
        # Vertical gradient
        gy = np.zeros_like(channel)
        gy[:-1, :] = channel[1:, :] - channel[:-1, :]

        grad_magnitude = np.sqrt(gx**2 + gy**2)
        # Determine gradient sign (based on edge direction)
        grad_sign[:, :, c] = np.where(grad_magnitude > probe_epsilon, 1.0, -1.0)

    return grad_sign


def apply_fgsm(
    image: np.ndarray,
    grad_sign: np.ndarray,
    epsilon: float,
    targeted: bool,
    clip_min: float,
    clip_max: float,
) -> np.ndarray:
    """Apply FGSM perturbation."""
    direction = -1.0 if targeted else 1.0  # Targeted attack: minimize loss direction
    perturbation = direction * epsilon * grad_sign
    adversarial = image + perturbation
    return np.clip(adversarial, clip_min, clip_max)


def apply_ifgsm(
    image: np.ndarray,
    grad_sign: np.ndarray,
    config: AdversarialConfig,
) -> np.ndarray:
    """
    Apply I-FGSM (Iterative FGSM).
    Projects the result into the epsilon ball at each step.
    """
    step = config.step_size or (config.epsilon / config.iterations)
    direction = -1.0 if config.targeted else 1.0

    x_adv = image.copy()
    for _ in range(config.iterations):
        # Single-step perturbation
        perturbation = direction * step * grad_sign
        x_adv = x_adv + perturbation

        # Project into epsilon ball (L∞ norm)
        delta = x_adv - image
        delta_clipped = np.clip(delta, -config.epsilon, config.epsilon)
        x_adv = image + delta_clipped

        # Clip to valid pixel range
        x_adv = np.clip(x_adv, config.clip_min, config.clip_max)

    return x_adv


def compute_perturbation_stats(
    original: np.ndarray,
    adversarial: np.ndarray,
) -> tuple[float, float]:
    """Compute the L∞ and L2 norms of the perturbation."""
    delta = adversarial - original
    l_inf = float(np.max(np.abs(delta)))
    l2 = float(np.sqrt(np.sum(delta**2)))
    return l_inf, l2


def add_visual_marker(
    image: np.ndarray,
    l_inf: float,
    epsilon: float,
) -> np.ndarray:
    """
    Display perturbation magnitude information at the bottom-right of the image for analysis.
    Not included in actual attack examples.
    """
    marked = image.copy()
    # Color the bottom-right 10x10 pixels according to perturbation ratio
    ratio = min(l_inf / epsilon, 1.0) if epsilon > 0 else 0.0
    H, W = marked.shape[:2]
    marked[H-10:H, W-10:W, 0] = ratio       # Red channel
    marked[H-10:H, W-10:W, 1] = 1.0 - ratio  # Green channel
    marked[H-10:H, W-10:W, 2] = 0.0
    return marked


def generate_adversarial_single(
    input_path: Path,
    output_path: Path,
    config: AdversarialConfig,
    true_class: int,
    n_classes: int,
    add_marker: bool,
) -> GenerationResult:
    """Generate an adversarial example for a single image."""
    start = time.time()

    if not input_path.exists():
        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=(),
            epsilon_used=config.epsilon,
            l_inf_norm=0.0,
            l2_norm=0.0,
            success=False,
            error=f"File not found: {input_path}",
        )

    try:
        original = load_image_as_array(input_path)
        grad_sign = estimate_gradient_sign(original, true_class, n_classes)

        if config.iterations <= 1:
            adversarial = apply_fgsm(
                original, grad_sign, config.epsilon,
                config.targeted, config.clip_min, config.clip_max
            )
        else:
            adversarial = apply_ifgsm(original, grad_sign, config)

        if add_marker:
            l_inf_check, _ = compute_perturbation_stats(original, adversarial)
            adversarial = add_visual_marker(adversarial, l_inf_check, config.epsilon)

        save_array_as_image(adversarial, output_path)

        l_inf, l2 = compute_perturbation_stats(original, adversarial)
        elapsed = (time.time() - start) * 1000

        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=original.shape,
            epsilon_used=config.epsilon,
            l_inf_norm=l_inf,
            l2_norm=l2,
            success=True,
            duration_ms=elapsed,
        )
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return GenerationResult(
            input_path=str(input_path),
            output_path=str(output_path),
            original_shape=(),
            epsilon_used=config.epsilon,
            l_inf_norm=0.0,
            l2_norm=0.0,
            success=False,
            error=str(e),
            duration_ms=elapsed,
        )


def collect_image_paths(source: Path, extensions: set[str]) -> list[Path]:
    """Collect image paths from a directory or a single file."""
    if source.is_file():
        return [source]
    if source.is_dir():
        paths: list[Path] = []
        for ext in extensions:
            paths.extend(source.rglob(f"*.{ext}"))
            paths.extend(source.rglob(f"*.{ext.upper()}"))
        return sorted(paths)
    return []


def build_output_path(
    input_path: Path,
    input_base: Path,
    output_dir: Path,
    suffix: str,
) -> Path:
    """Compute the output path while preserving the input directory structure."""
    try:
        relative = input_path.relative_to(input_base)
    except ValueError:
        relative = Path(input_path.name)

    stem = relative.stem
    ext = relative.suffix
    new_name = f"{stem}{suffix}{ext}"
    return output_dir / relative.parent / new_name


def print_batch_summary(results: list[GenerationResult]) -> None:
    """Print a summary of batch processing results."""
    total = len(results)
    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    avg_l_inf = sum(r.l_inf_norm for r in success) / len(success) if success else 0
    avg_l2 = sum(r.l2_norm for r in success) / len(success) if success else 0
    avg_ms = sum(r.duration_ms for r in success) / len(success) if success else 0

    print("\n" + "=" * 60)
    print("Adversarial Example Batch Generation Results")
    print("=" * 60)
    print(f"Total images    : {total}")
    print(f"Succeeded       : {len(success)}")
    print(f"Failed          : {len(failed)}")
    print(f"Avg L∞ norm     : {avg_l_inf:.4f}")
    print(f"Avg L2 norm     : {avg_l2:.4f}")
    print(f"Avg process time: {avg_ms:.1f}ms/image")

    if failed:
        print()
        print("[Failed list]")
        for r in failed[:5]:
            print(f"  {r.input_path}: {r.error}")
        if len(failed) > 5:
            print(f"  ... and {len(failed) - 5} more")

    print("=" * 60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fgsm-generator",
        description="FGSM Adversarial Example Generator (numpy/PIL based, no torch required)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Single image
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image cat.jpg \\
      --epsilon 0.05 \\
      --output adversarial_cat.jpg

  # Batch processing (entire directory)
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image ./dataset/images/ \\
      --epsilon 0.03 \\
      --output ./adversarial_output/ \\
      --iterations 10 \\
      --workers 4

  # Strong perturbation (for visual inspection)
  python 04_adversarial_examples.py \\
      --model dummy \\
      --image stop_sign.jpg \\
      --epsilon 0.2 \\
      --output adversarial_stop.jpg \\
      --add-marker
        """,
    )
    parser.add_argument(
        "--model",
        default="dummy",
        metavar="MODEL",
        help="Target model identifier (currently uses gradient approximation, default: dummy)",
    )
    parser.add_argument(
        "--image",
        required=True,
        type=Path,
        metavar="PATH",
        help="Input image file or directory",
    )
    parser.add_argument(
        "--epsilon",
        type=float,
        default=0.03,
        metavar="FLOAT",
        help="Perturbation magnitude (0~1 range, default: 0.03)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        metavar="PATH",
        help="Output image file or directory",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        metavar="N",
        help="Number of iterations (1=FGSM, >1=I-FGSM, default: 1)",
    )
    parser.add_argument(
        "--step-size",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Step size for iterative attack (default: epsilon/iterations)",
    )
    parser.add_argument(
        "--norm",
        choices=["linf", "l2"],
        default="linf",
        help="Perturbation norm type (default: linf)",
    )
    parser.add_argument(
        "--targeted",
        action="store_true",
        help="Targeted attack mode (loss minimization direction)",
    )
    parser.add_argument(
        "--true-class",
        type=int,
        default=0,
        metavar="N",
        help="True class index of the original image (default: 0)",
    )
    parser.add_argument(
        "--n-classes",
        type=int,
        default=1000,
        metavar="N",
        help="Total number of model classes (default: 1000)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        metavar="N",
        help="Number of parallel worker processes (default: 2)",
    )
    parser.add_argument(
        "--suffix",
        default="_adv",
        metavar="STR",
        help="Output filename suffix in batch mode (default: _adv)",
    )
    parser.add_argument(
        "--add-marker",
        action="store_true",
        help="Add visual perturbation magnitude marker for analysis",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        metavar="FILE",
        help="Path to save result JSON",
    )
    return parser


def main() -> int:
    if not HAS_PIL:
        print("[!] Required packages missing: pip install Pillow numpy", file=sys.stderr)
        return 1

    parser = build_parser()
    args = parser.parse_args()

    if args.epsilon <= 0 or args.epsilon > 1:
        print(f"[!] epsilon must be in range 0~1: {args.epsilon}", file=sys.stderr)
        return 1

    config = AdversarialConfig(
        epsilon=args.epsilon,
        iterations=args.iterations,
        step_size=args.step_size,
        norm=args.norm,
        targeted=args.targeted,
    )

    IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "bmp", "webp"}
    image_paths = collect_image_paths(args.image, IMAGE_EXTENSIONS)

    if not image_paths:
        print(f"[!] No images found: {args.image}", file=sys.stderr)
        return 1

    # Determine single file vs batch mode
    is_batch = len(image_paths) > 1 or args.image.is_dir()

    print(f"[*] Starting FGSM adversarial example generation")
    print(f"    Images: {len(image_paths)} | ε={args.epsilon} | iterations={args.iterations} | norm={args.norm}")

    # Determine output paths
    if is_batch:
        input_base = args.image if args.image.is_dir() else args.image.parent
        output_paths = [
            build_output_path(p, input_base, args.output, args.suffix)
            for p in image_paths
        ]
    else:
        output_paths = [args.output]

    # Batch processing
    results: list[GenerationResult] = []
    tasks = list(zip(image_paths, output_paths))

    if args.workers > 1 and len(tasks) > 1:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(
                    generate_adversarial_single,
                    inp, out, config,
                    args.true_class, args.n_classes, args.add_marker
                ): (inp, out)
                for inp, out in tasks
            }
            completed = 0
            for future in as_completed(future_map):
                result = future.result()
                results.append(result)
                completed += 1
                status = "done" if result.success else "failed"
                print(f"  [{completed}/{len(tasks)}] {status}: {result.input_path}")
    else:
        for i, (inp, out) in enumerate(tasks, 1):
            result = generate_adversarial_single(
                inp, out, config,
                args.true_class, args.n_classes, args.add_marker
            )
            results.append(result)
            status = "done" if result.success else "failed"
            print(f"  [{i}/{len(tasks)}] {status}: {inp.name}")
            if not result.success:
                print(f"    error: {result.error}")

    print_batch_summary(results)

    if args.output_json:
        import dataclasses
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with args.output_json.open("w", encoding="utf-8") as f:
            serialized = [dataclasses.asdict(r) for r in results]
            json.dump(serialized, f, ensure_ascii=False, indent=2)
        print(f"[+] Result JSON saved: {args.output_json}")

    failed_count = sum(1 for r in results if not r.success)
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. Adversarial Robustness Evaluation Metrics

| Metric | Description | Calculation Method |
|---|---|---|
| **Robust accuracy** | Classification accuracy under adversarial attack | Correctly classified count after attack / total samples |
| **Attack success rate** | Rate of induced misclassifications | Misclassified count / total attacks |
| **Minimum perturbation** | Minimum ε needed to cause misclassification | Binary search for minimum epsilon |
| **Transfer rate** | Success rate of attacks generated on other models | Attack success rate on the target model |
| **Perceptibility** | Degree to which humans can perceive the modification | SSIM, LPIPS, user studies |

---

## 6. Defense Technique Comparison

| Defense Technique | Principle | Advantages | Disadvantages |
|---|---|---|---|
| **Adversarial training** | Include attack examples in training data | Most effective | Increased training cost, vulnerable to unseen attacks |
| **Input preprocessing** | Remove perturbations via JPEG compression, smoothing | Easy to implement | Ineffective against strong attacks |
| **Differential privacy** | Add Gaussian noise during training | Theoretical guarantees | Accuracy loss |
| **Randomized smoothing** | Add random noise at inference + majority vote | Can certify L2 robustness | Compute cost, no L∞ support |
| **Detector addition** | Detect adversarial examples with a separate neural network | Can reject after detection | Detector itself can be attacked |
| **Input transformation ensemble** | Ensemble after various preprocessing steps | Partially resistant to adaptive attacks | Compute cost |

---

## References

- "Explaining and Harnessing Adversarial Examples" (Goodfellow et al., 2014) — Original FGSM paper
- "Towards Evaluating the Robustness of Neural Networks" (Carlini & Wagner, 2016) — CW attack
- "Towards Deep Learning Models Resistant to Adversarial Attacks" (Madry et al., 2017) — PGD attack
- "Adversarial Patch" (Brown et al., 2017) — Physical patch attack
- "Hidden Voice Commands" (Carlini et al., 2016) — Audio adversarial examples
- CleverHans library: https://github.com/cleverhans-lab/cleverhans
- ART (Adversarial Robustness Toolbox): https://github.com/Trusted-AI/adversarial-robustness-toolbox
