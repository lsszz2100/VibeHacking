#!/usr/bin/env python3
"""
Adds Track 90: fedsec (Federated Learning Model Poisoning & Privacy Defense)
to wargame/assets/challenges.js, wargame/scripts/solve-derivable.js, and wargame/README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# 1. 35 Challenge definitions for Track 90
CHALLENGE_SPECS = [
    # Tier 0 (7 challenges, points 15-25)
    (0, "t0_fedsec_federated_learning_distributed_ai_architecture", 15,
     "연합 학습 분산 AI 아키텍처 및 FedAvg 원리",
     "Federated Learning Distributed AI Architecture and FedAvg Fundamentals",
     "중앙 서버와 분산 에지 워커 간 원시 데이터 비공개 상태에서 가중치 그래디언트만 교환하는 연합 학습(Federated Learning)의 기본 FedAvg 아키텍처와 라운드 수렴 메커니즘을 분석합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_federated_learning_distributed_ai_architecture``\n\n[문제 안내]\n해당 연합 학습 분산 아키텍처 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Analyze the core FedAvg architecture and round convergence mechanics of Federated Learning where clients exchange weight gradients without exposing raw local data.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_federated_learning_distributed_ai_architecture``\n\n[Task]\nAnalyze the federated distributed architecture specification, then derive and submit the flag."),
    
    (0, "t0_fedsec_byzantine_fault_tolerance_and_sybil_threats", 20,
     "비잔틴 결함 내성 및 시빌 공격 위협 개요",
     "Byzantine Fault Tolerance and Sybil Attack Threat Landscape",
     "악의적 또는 결함이 있는 워커가 임의의 가중치 잡음을 제출하거나 공모하여 글로벌 모델 수렴을 파괴하는 비잔틴 결함(Byzantine Fault) 및 시빌(Sybil) 공격 위협 모델을 식별합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_byzantine_fault_tolerance_and_sybil_threats``\n\n[문제 안내]\n해당 비잔틴 결함 내성 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Identify Byzantine fault and Sybil attack threat models where malicious or compromised workers submit fabricated gradients or collude to prevent global convergence.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_byzantine_fault_tolerance_and_sybil_threats``\n\n[Task]\nAnalyze the Byzantine fault tolerance specification, then derive and submit the flag."),

    (0, "t0_fedsec_gradient_explosion_and_norm_clipping_basics", 20,
     "그래디언트 폭발 및 L2-Norm 클리핑 기초",
     "Gradient Explosion and L2-Norm Clipping Fundamentals",
     "단일 악성 클라이언트가 비정상적으로 거대한 그래디언트 벡터를 전송하여 글로벌 모델 가중치를 급격하게 오염시키는 그래디언트 폭발 공격과 L2-Norm 클리핑 방어 원리를 학습합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_gradient_explosion_and_norm_clipping_basics``\n\n[문제 안내]\n해당 그래디언트 L2 클리핑 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Understand gradient explosion attacks where an adversary sends disproportionately large gradient vectors to corrupt global weights, and study L2-norm clipping defense basics.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_gradient_explosion_and_norm_clipping_basics``\n\n[Task]\nAnalyze the gradient L2 clipping specification, then derive and submit the flag."),

    (0, "t0_fedsec_cosine_similarity_directional_alignment_concepts", 25,
     "코사인 유사도 방향 정렬 원리",
     "Cosine Similarity Directional Alignment Concepts",
     "클라이언트 그래디언트의 크기뿐만 아니라 업데이트 방향이 이전 라운드 전역 모델 진행 방향과 반대로 역주행하는 이상치를 식별하기 위한 코사인 유사도 벡터 정렬 원리를 파악합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_cosine_similarity_directional_alignment_concepts``\n\n[문제 안내]\n해당 코사인 유사도 정렬 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Explore cosine similarity directional alignment to detect anomalous gradient updates whose trajectories reverse or diverge from the historic global model momentum.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_cosine_similarity_directional_alignment_concepts``\n\n[Task]\nAnalyze the cosine similarity alignment specification, then derive and submit the flag."),

    (0, "t0_fedsec_differential_privacy_dpsgd_fundamentals", 25,
     "차분 프라이버시 DP-SGD 기초 이론",
     "Differential Privacy DP-SGD Mathematical Foundations",
     "공유된 그래디언트 정보로부터 개별 참여자의 사설 데이터가 복원되지 않도록 수학적으로 보증하는 차분 프라이버시(DP-SGD)의 엡실론(Epsilon) 및 델타(Delta) 매개변수를 분석합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_differential_privacy_dpsgd_fundamentals``\n\n[문제 안내]\n해당 차분 프라이버시 DP-SGD 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Analyze the mathematical foundations of Differential Privacy (DP-SGD) with epsilon and delta parameters to prevent reconstruction of private training records.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_differential_privacy_dpsgd_fundamentals``\n\n[Task]\nAnalyze the DP-SGD specification, then derive and submit the flag."),

    (0, "t0_fedsec_membership_inference_attack_vector_mechanics", 25,
     "멤버십 추론 공격 메커니즘 분석",
     "Membership Inference Attack Vector Mechanics",
     "학습된 모델의 손실 함수 및 신뢰도 점수 이상치를 분석하여 특정 개인 데이터 레코드가 학습 데이터셋에 포함되었는지 여부를 역추적하는 멤버십 추론 공격(MIA) 원리를 진단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_membership_inference_attack_vector_mechanics``\n\n[문제 안내]\n해당 멤버십 추론 공격 메커니즘 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Examine Membership Inference Attacks (MIA) where an attacker infers whether a specific target record was part of the training set by evaluating model confidence distributions.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_membership_inference_attack_vector_mechanics``\n\n[Task]\nAnalyze the MIA attack mechanism specification, then derive and submit the flag."),

    (0, "t0_fedsec_secure_multi_party_computation_mpc_introduction", 25,
     "다자간 안전 계산 SMPC 기초",
     "Secure Multi-Party Computation SMPC Introduction",
     "집계 서버조차 개별 참여자의 그래디언트 원본을 직접 열람할 수 없도록 마스킹하는 다자간 안전 계산(Secure MPC) 및 암호학적 영합 비밀 분할(Secret Sharing) 개념을 정립합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_secure_multi_party_computation_mpc_introduction``\n\n[문제 안내]\n해당 다자간 안전 계산 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Establish fundamentals of Secure Multi-Party Computation (SMPC) and cryptographic zero-sum secret sharing where the aggregator inspects only composite sums, never individual gradients.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t0_fedsec_secure_multi_party_computation_mpc_introduction``\n\n[Task]\nAnalyze the secure multi-party computation specification, then derive and submit the flag."),

    # Tier 1 (7 challenges, points 50-75)
    (1, "t1_fedsec_client_gradient_l2_norm_clipping_enforcement", 50,
     "클라이언트 그래디언트 L2-Norm 클리핑 구현",
     "Client Gradient L2-Norm Clipping Enforcement",
     "각 클라이언트가 업로드하는 그래디언트 벡터의 L2-Norm을 임계값 C=1.0으로 강제 클리핑하여 단일 노드의 극단적 가중치 편향 공격을 수학적으로 무력화합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_client_gradient_l2_norm_clipping_enforcement``\n\n[문제 안내]\n해당 L2-Norm 클리핑 구현 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce strict L2-norm clipping on client gradient updates with clipping bound C=1.0 to neutralize single-node weight explosion attempts.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_client_gradient_l2_norm_clipping_enforcement``\n\n[Task]\nAnalyze the L2-norm clipping enforcement specification, then derive and submit the flag."),

    (1, "t1_fedsec_cosine_similarity_anomaly_score_filtering", 55,
     "코사인 유사도 이상치 점수 필터링",
     "Cosine Similarity Anomaly Score Filtering",
     "글로벌 모델 업데이트 벡터와 각 클라이언트 업데이트 간의 코사인 유사도를 계산하여 유사도 임계치 0.85 미만인 악의적 역방향 그래디언트를 사전 차단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_cosine_similarity_anomaly_score_filtering``\n\n[문제 안내]\n해당 코사인 유사도 이상치 필터링 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Compute directional cosine similarity between client updates and historical global vectors, filtering out anomalous updates falling below threshold 0.85.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_cosine_similarity_anomaly_score_filtering``\n\n[Task]\nAnalyze the cosine anomaly score filtering specification, then derive and submit the flag."),

    (1, "t1_fedsec_trimmed_mean_coordinate_wise_aggregation", 60,
     "좌표별 트림드 평균 집계 방어",
     "Coordinate-wise Trimmed-Mean Aggregation Defense",
     "모든 클라이언트의 각 파라미터 좌표별 값 중 상하위 β 비율(예: 10%)의 극단값을 제거한 후 산술 평균을 계산하는 트림드 평균 집계 방어 알고리즘을 구축합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_trimmed_mean_coordinate_wise_aggregation``\n\n[문제 안내]\n해당 트림드 평균 집계 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Build a coordinate-wise Trimmed-Mean aggregation defense that discards the lowest and highest beta percentiles of parameter updates before computing the mean.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_trimmed_mean_coordinate_wise_aggregation``\n\n[Task]\nAnalyze the trimmed-mean aggregation specification, then derive and submit the flag."),

    (1, "t1_fedsec_multi_krum_byzantine_resilient_candidate_selection", 65,
     "Multi-Krum 비잔틴 견고 후보 선출",
     "Multi-Krum Byzantine-Resilient Candidate Selection",
     "전체 n개 클라이언트 중 f개 비잔틴 노드를 견디기 위해 다른 노드들과의 유클리드 거리 합이 가장 작은 m개 우수 클라이언트를 선출하여 평균하는 Multi-Krum을 실행합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_multi_krum_byzantine_resilient_candidate_selection``\n\n[문제 안내]\n해당 Multi-Krum 집계 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Execute Multi-Krum selection to aggregate m candidate updates possessing the lowest Euclidean distance scores relative to their peers under f Byzantine faults.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_multi_krum_byzantine_resilient_candidate_selection``\n\n[Task]\nAnalyze the Multi-Krum candidate selection specification, then derive and submit the flag."),

    (1, "t1_fedsec_renyi_differential_privacy_gaussian_noise_injection", 70,
     "르니 차분 프라이버시 가우시안 노이즈 주입",
     "Rényi Differential Privacy Gaussian Noise Injection",
     "클리핑된 그래디언트에 보정된 분산 σ=1.45의 가우시안 잡음을 주입하여 엄격한 르니 차분 프라이버시(RDP) 수학적 개인정보 보호 보장을 실증합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_renyi_differential_privacy_gaussian_noise_injection``\n\n[문제 안내]\n해당 RDP 가우시안 노이즈 주입 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Inject calibrated Gaussian noise with standard deviation sigma=1.45 into clipped gradients to mathematically guarantee Rényi Differential Privacy (RDP).\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_renyi_differential_privacy_gaussian_noise_injection``\n\n[Task]\nAnalyze the RDP noise injection specification, then derive and submit the flag."),

    (1, "t1_fedsec_privacy_budget_epsilon_accounting_and_clamping", 70,
     "프라이버시 예산 엡실론 회계 및 클램핑",
     "Privacy Budget Epsilon Accounting and Clamping",
     "연합 학습 라운드가 진행됨에 따라 누적되는 프라이버시 손실 엡실론(ε)을 모먼트 어카운턴트(Moments Accountant)로 추적하여 상한선 ε<=3.0 도달 시 조기 종료합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_privacy_budget_epsilon_accounting_and_clamping``\n\n[문제 안내]\n해당 엡실론 프라이버시 회계 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Track cumulative privacy loss epsilon using the Moments Accountant, enforcing early stopping or rate-limiting when total epsilon approaches bound 3.0.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_privacy_budget_epsilon_accounting_and_clamping``\n\n[Task]\nAnalyze the epsilon privacy accounting specification, then derive and submit the flag."),

    (1, "t1_fedsec_pairwise_zero_sum_secret_masking", 75,
     "클라이언트 간 영합 비밀 마스킹",
     "Pairwise Zero-Sum Secret Masking",
     "참여 노드 쌍(u, v) 간에 공유된 난수 시드를 기반으로 합산 시 서로 상쇄되는 영합(Zero-Sum) 마스크 벡터를 생성하여 서버의 개별 가중치 열람을 원천 봉쇄합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_pairwise_zero_sum_secret_masking``\n\n[문제 안내]\n해당 영합 마스킹 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Generate pairwise pseudo-random zero-sum masks that cancel out upon global summation, completely preventing the server from inspecting individual updates.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t1_fedsec_pairwise_zero_sum_secret_masking``\n\n[Task]\nAnalyze the zero-sum secret masking specification, then derive and submit the flag."),

    # Tier 2 (7 challenges, points 100-125)
    (2, "t2_fedsec_byzantine_gradient_scaling_attack_detection", 100,
     "비잔틴 그래디언트 스케일링 공격 탐지",
     "Byzantine Gradient Scaling Attack Detection",
     "비잔틴 공격자가 가중치 업데이트 크기를 미세하게 부풀리거나 축소하여 모델 학습 속도를 지연시키는 스케일링 조작을 분산 및 엔트로피 통계로 탐지합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_byzantine_gradient_scaling_attack_detection``\n\n[문제 안내]\n해당 그래디언트 스케일링 탐지 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Detect stealthy Byzantine gradient scaling attacks where compromised workers amplify or dampen gradient magnitude to derail convergence using variance heuristics.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_byzantine_gradient_scaling_attack_detection``\n\n[Task]\nAnalyze the gradient scaling attack detection specification, then derive and submit the flag."),

    (2, "t2_fedsec_bulyan_aggregation_for_byzantine_resilience", 105,
     "Bulyan 비잔틴 결함 내성 집계",
     "Bulyan Byzantine-Resilient Aggregation",
     "Krum 알고리즘과 트림드 평균을 결합하여 고차원 비잔틴 공모 공격(f < n/4)에서도 엄격한 통계적 견고성을 보장하는 Bulyan 집계 방어 파이프라인을 구축합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_bulyan_aggregation_for_byzantine_resilience``\n\n[문제 안내]\n해당 Bulyan 집계 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Deploy the Bulyan aggregation framework combining Krum and coordinate-wise trimmed-mean to guarantee robustness against colluding Byzantine adversaries.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_bulyan_aggregation_for_byzantine_resilience``\n\n[Task]\nAnalyze the Bulyan aggregation specification, then derive and submit the flag."),

    (2, "t2_fedsec_adaptive_clipping_bound_estimation", 110,
     "적응형 클리핑 임계값 추정",
     "Adaptive Gradient Clipping Bound Estimation",
     "고정된 L2-Norm 클리핑 대신 매 라운드 참여 클라이언트의 그래디언트 분위수(Quantile)를 비공개 방식으로 추정하여 유효 정보 손실 없이 클리핑 경계를 동적 튜닝합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_adaptive_clipping_bound_estimation``\n\n[문제 안내]\n해당 적응형 클리핑 추정 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Dynamically estimate the L2-norm clipping bound using differentially private quantile estimation to minimize useful gradient truncation while suppressing outliers.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_adaptive_clipping_bound_estimation``\n\n[Task]\nAnalyze the adaptive clipping estimation specification, then derive and submit the flag."),

    (2, "t2_fedsec_fips204_mldsa87_client_signature_validation", 115,
     "FIPS 204 ML-DSA-87 클라이언트 서명 검증",
     "NIST FIPS 204 ML-DSA-87 Client Signature Validation",
     "연합 학습 노드가 제출하는 마스킹된 그래디언트 페이로드에 대해 양자 내성 FIPS 204 ML-DSA-87 전자서명을 강제 검증하여 미승인 섀도우 노드의 주입을 차단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_fips204_mldsa87_client_signature_validation``\n\n[문제 안내]\n해당 ML-DSA-87 서명 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Validate NIST FIPS 204 ML-DSA-87 post-quantum digital signatures on masked client payloads to reject unauthorized shadow worker contributions.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_fips204_mldsa87_client_signature_validation``\n\n[Task]\nAnalyze the ML-DSA-87 signature validation specification, then derive and submit the flag."),

    (2, "t2_fedsec_federated_unlearning_and_backdoor_erasure", 120,
     "연합 언러닝 및 백도어 가중치 소거",
     "Federated Unlearning and Backdoor Weight Erasure",
     "특정 참여 노드가 사후 악성 노드로 판명되었을 때, 전체 재학습 없이 해당 노드의 기여분을 역그래디언트 프로젝션으로 신속하게 소거하는 연합 언러닝을 실증합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_federated_unlearning_and_backdoor_erasure``\n\n[문제 안내]\n해당 연합 언러닝 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Execute federated machine unlearning via reverse gradient projection to expunge contributions of retroactive malicious participants without full model retraining.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_federated_unlearning_and_backdoor_erasure``\n\n[Task]\nAnalyze the federated unlearning specification, then derive and submit the flag."),

    (2, "t2_fedsec_local_differential_privacy_laplace_perturbation", 120,
     "로컬 차분 프라이버시 라플라스 섭동",
     "Local Differential Privacy Laplace Perturbation",
     "중앙 집계 서버조차 신뢰하지 않는 완전 비신뢰 모델에서 각 클라이언트가 로컬 라플라스 메커니즘을 적용하여 데이터를 섭동하는 로컬 차분 프라이버시(LDP)를 구축합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_local_differential_privacy_laplace_perturbation``\n\n[문제 안내]\n해당 로컬 차분 프라이버시 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Implement Local Differential Privacy (LDP) where each client perturbs local vectors using Laplace mechanisms prior to transmission under zero-trust aggregator assumptions.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_local_differential_privacy_laplace_perturbation``\n\n[Task]\nAnalyze the local differential privacy specification, then derive and submit the flag."),

    (2, "t2_fedsec_secure_aggregation_quorum_consensus_verification", 125,
     "안전 집계 쿼럼 합의 검증",
     "Secure Aggregation Quorum Consensus Verification",
     "비잔틴 이탈 노드로 인한 마스크 불균형을 해결하기 위해 최소 쿼럼(Quorum >= 7) 이상의 생존 노드가 암호학적 합의 서명에 도달해야만 집계를 인가합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_secure_aggregation_quorum_consensus_verification``\n\n[문제 안내]\n해당 쿼럼 합의 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Verify cryptographic quorum consensus where aggregation proceeds only when active worker surviving nodes exceed quorum threshold (>= 7) to reconcile dropouts.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t2_fedsec_secure_aggregation_quorum_consensus_verification``\n\n[Task]\nAnalyze the quorum consensus verification specification, then derive and submit the flag."),

    # Tier 3 (7 challenges, points 150-200)
    (3, "t3_fedsec_adversarial_backdoor_trigger_injection_in_federated_ai", 150,
     "연합 AI 적대적 백도어 트리거 주입 탐지",
     "Adversarial Backdoor Trigger Injection in Federated AI",
     "정상 훈련 데이터와 구분되지 않는 특정 픽셀 패턴 트리거가 입력될 때만 오분류를 유도하는 연합 AI 타깃 백도어 주입 공격을 가중치 활성화 클러스터링으로 감지합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_adversarial_backdoor_trigger_injection_in_federated_ai``\n\n[문제 안내]\n해당 백도어 트리거 탐지 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Detect targeted federated backdoor triggers activating misclassifications only on tailored pixel patterns by inspecting latent activation clustering anomalies.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_adversarial_backdoor_trigger_injection_in_federated_ai``\n\n[Task]\nAnalyze the backdoor trigger injection specification, then derive and submit the flag."),

    (3, "t3_fedsec_multi_party_shamir_secret_sharing_reconstruction", 160,
     "샤미르 비밀 분할 다자간 가중치 재구성",
     "Multi-Party Shamir Secret Sharing Reconstruction",
     "참여 클라이언트의 오프라인 이탈 시 마스킹 키를 복원하기 위해 (k, n) 샤미르 비밀 분할(Shamir's Secret Sharing) 다항식 보간법 기반 키 복구 프로토콜을 수행합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_multi_party_shamir_secret_sharing_reconstruction``\n\n[문제 안내]\n해당 샤미르 비밀 분할 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Execute (k, n) Shamir Secret Sharing polynomial interpolation to reconstruct dropout client mask seeds without revealing operational gradients.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_multi_party_shamir_secret_sharing_reconstruction``\n\n[Task]\nAnalyze the Shamir secret sharing reconstruction specification, then derive and submit the flag."),

    (3, "t3_fedsec_hardware_tee_intel_tdx_enclave_worker_attestation", 170,
     "하드웨어 TEE 엔클레이브 워커 원격 증명",
     "Hardware TEE Enclave Federated Worker Attestation",
     "각 연합 에지 노드가 하드웨어 기밀 가상머신(Intel TDX / AMD SEV-SNP) 내부에서 변조되지 않은 훈련 코드를 실행하고 있음을 Quote PCR 원격 증명으로 검증합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_hardware_tee_intel_tdx_enclave_worker_attestation``\n\n[문제 안내]\n해당 하드웨어 TEE 원격 증명 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Verify hardware TEE Quote PCR reports confirming edge nodes execute untampered training runtimes inside isolated confidential enclaves.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_hardware_tee_intel_tdx_enclave_worker_attestation``\n\n[Task]\nAnalyze the hardware TEE worker attestation specification, then derive and submit the flag."),

    (3, "t3_fedsec_model_inversion_defense_with_differential_privacy", 180,
     "차분 프라이버시 기반 모델 역변환 방어",
     "Model Inversion Defense with Differential Privacy",
     "공격자가 전역 모델 파라미터 경사 하강법을 역수행하여 얼굴 이미지나 의료 기록 원본을 복원하는 모델 역변환 공격(Model Inversion)을 가우시안 섭동으로 차단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_model_inversion_defense_with_differential_privacy``\n\n[문제 안내]\n해당 모델 역변환 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Block model inversion attacks attempting gradient descent reconstruction of raw private biometric or medical records by tuning differential privacy parameters.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_model_inversion_defense_with_differential_privacy``\n\n[Task]\nAnalyze the model inversion defense specification, then derive and submit the flag."),

    (3, "t3_fedsec_cross_silo_federated_learning_spiffe_mesh_auth", 185,
     "크로스 사일로 SPIFFE 연합 인증 메시",
     "Cross-Silo Federated Learning SPIFFE Mesh Authentication",
     "금융·의료 기관 간 대규모 크로스 사일로(Cross-Silo) 연합 네트워크에서 SPIFFE/SPIRE 기반 암호학적 워크로드 ID 및 상호 mTLS 인증 터널을 확립합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_cross_silo_federated_learning_spiffe_mesh_auth``\n\n[문제 안내]\n해당 SPIFFE 연합 메시 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Establish zero-trust SPIFFE/SPIRE workload cryptographic identity and mTLS mesh tunnels across institutional cross-silo federated learning clusters.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_cross_silo_federated_learning_spiffe_mesh_auth``\n\n[Task]\nAnalyze the cross-silo SPIFFE mesh specification, then derive and submit the flag."),

    (3, "t3_fedsec_byzantine_robust_median_aggregation_defense", 190,
     "비잔틴 견고 메디안 집계 방어",
     "Byzantine Robust Geometric Median Aggregation Defense",
     "유클리드 공간 상에서 비잔틴 노드의 악의적 이상치 영향력을 통계적으로 최소화하는 기하학적 메디안(Geometric Median) Weiszfeld 알고리즘 기반 집계를 구현합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_byzantine_robust_median_aggregation_defense``\n\n[문제 안내]\n해당 기하학적 메디안 집계 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Implement geometric median aggregation via Weiszfeld iterative minimization to bound the influence of Byzantine nodes in high-dimensional parameter spaces.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_byzantine_robust_median_aggregation_defense``\n\n[Task]\nAnalyze the robust median aggregation specification, then derive and submit the flag."),

    (3, "t3_fedsec_autonomous_federated_drift_anomaly_isolation", 200,
     "자율 연합 가중치 드리프트 이상 노드 격리",
     "Autonomous Federated Drift Anomaly Worker Isolation",
     "정상 클라이언트의 로컬 데이터 이질성(Non-IID)과 악의적 포이즈닝 드리프트를 실시간 분류기 손실 함수로 판별하여 비잔틴 노드를 자동 사살 격리합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_autonomous_federated_drift_anomaly_isolation``\n\n[문제 안내]\n해당 가중치 드리프트 격리 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Distinguish natural Non-IID statistical data heterogeneity from deliberate poisoning drift, automatically quarantining detected Byzantine nodes in real time.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t3_fedsec_autonomous_federated_drift_anomaly_isolation``\n\n[Task]\nAnalyze the federated drift anomaly isolation specification, then derive and submit the flag."),

    # Tier 4 (7 challenges, points 250-450)
    (4, "t4_fedsec_sybil_swarm_collusion_poisoning_defense", 250,
     "시빌 스웜 공모 모델 중독 방어",
     "Sybil Swarm Collusion Model Poisoning Defense",
     "다수의 가짜 워커 노드가 연합 네트워크에 동시 침투하여 정교하게 공모하는 스웜 비잔틴 공격에 대응하여 그래프 스펙트럴 클러스터링 기반 공모 탐지를 수행합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_sybil_swarm_collusion_poisoning_defense``\n\n[문제 안내]\n해당 시빌 스웜 공모 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Defend against Sybil swarm collusion poisoning where multiple coordinated rogue workers manipulate aggregation by deploying spectral graph clustering defense.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_sybil_swarm_collusion_poisoning_defense``\n\n[Task]\nAnalyze the Sybil swarm collusion defense specification, then derive and submit the flag."),

    (4, "t4_fedsec_deep_leakage_from_gradients_dlg_reconstruction_shield", 280,
     "그래디언트 심층 유출 DLG 원본 복원 차단",
     "Deep Leakage from Gradients DLG Reconstruction Shield",
     "서버가 수신된 그래디언트와 더미 입력 간의 유클리드 거리를 역최적화하여 원본 훈련 픽셀을 100% 복원하는 DLG 공격을 DP-SGD 노이즈 마스킹으로 차단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_deep_leakage_from_gradients_dlg_reconstruction_shield``\n\n[문제 안내]\n해당 DLG 원본 복원 차단 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Neutralize Deep Leakage from Gradients (DLG) pixel-level input reconstruction attacks by combining DP-SGD calibrated noise with zero-sum cryptographic masking.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_deep_leakage_from_gradients_dlg_reconstruction_shield``\n\n[Task]\nAnalyze the DLG reconstruction shield specification, then derive and submit the flag."),

    (4, "t4_fedsec_zero_knowledge_proof_zkp_client_update_verification", 300,
     "영지식 증명 ZKP 기반 클라이언트 업데이트 검증",
     "Zero-Knowledge Proof ZKP Client Update Verification",
     "클라이언트가 평문 그래디언트를 공개하지 않고도 해당 업데이트가 올바른 규격(L2-norm <= C 및 유효 훈련 연산)을 준수했음을 zk-SNARKs 증명으로 보증합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_zero_knowledge_proof_zkp_client_update_verification``\n\n[문제 안내]\n해당 영지식 증명 업데이트 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Verify zk-SNARK zero-knowledge proofs ensuring client updates strictly comply with L2-norm bounds and valid backpropagation without disclosing plaintext weights.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_zero_knowledge_proof_zkp_client_update_verification``\n\n[Task]\nAnalyze the zero-knowledge proof client verification specification, then derive and submit the flag."),

    (4, "t4_fedsec_quantum_resistant_hybrid_kem_fl_secure_channel", 320,
     "양자 내성 하이브리드 KEM 연합 보안 채널",
     "Quantum-Resistant Hybrid KEM Federated Secure Channel",
     "미래 양자 컴퓨터 도청 공격에 대비하여 FIPS 203 ML-KEM-1024 및 X25519 하이브리드 키 캡슐화로 연합 워커 간 비밀 분할 키 채널을 양자 암호학적으로 하드닝합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_quantum_resistant_hybrid_kem_fl_secure_channel``\n\n[문제 안내]\n해당 양자 내성 KEM 채널 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Harden federated secret sharing channels against post-quantum intercept threats by deploying hybrid FIPS 203 ML-KEM-1024 and X25519 key encapsulation.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_quantum_resistant_hybrid_kem_fl_secure_channel``\n\n[Task]\nAnalyze the quantum-resistant KEM federated channel specification, then derive and submit the flag."),

    (4, "t4_fedsec_byzantine_resilient_fedprox_straggler_mitigation", 350,
     "비잔틴 내결함 FedProx 지연자 완화",
     "Byzantine-Resilient FedProx Straggler Mitigation",
     "연합 클러스터 내 지연 노드(Straggler) 및 이질적 시스템 리소스 환경에서 프록시멀 항(Proximal Term)을 결합하여 비잔틴 공격 내성과 동적 수렴 안정성을 동시에 달성합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_byzantine_resilient_fedprox_straggler_mitigation``\n\n[문제 안내]\n해당 FedProx 비잔틴 방어 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Couple proximal regularization terms with robust aggregation to reconcile straggler nodes and preserve convergence stability under Byzantine perturbations.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_byzantine_resilient_fedprox_straggler_mitigation``\n\n[Task]\nAnalyze the Byzantine FedProx straggler mitigation specification, then derive and submit the flag."),

    (4, "t4_fedsec_hardware_tpm_quote_live_fl_pcr_verification", 380,
     "하드웨어 TPM Quote 라이브 연합 PCR 검증",
     "Hardware TPM Quote Live Federated PCR Verification",
     "연합 노드 부팅 펌웨어 및 커널 무결성을 하드웨어 TPM 2.0 Quote PCR 다이제스트 검증으로 실시간 대조하여 손상된 하드웨어 노드의 가중치 집계 참여를 물리 차단합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_hardware_tpm_quote_live_fl_pcr_verification``\n\n[문제 안내]\n해당 하드웨어 TPM 연합 검증 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Enforce live hardware TPM 2.0 Quote PCR digest attestation across federated workers to physically isolate compromised host platforms from participating in aggregation.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_hardware_tpm_quote_live_fl_pcr_verification``\n\n[Task]\nAnalyze the hardware TPM federated PCR verification specification, then derive and submit the flag."),

    (4, "t4_fedsec_sovereign_federated_ai_poisoning_and_privacy_defense_capstone", 450,
     "주권 연합 AI 모델 중독 및 프라이버시 방어 종합 캡스톤",
     "Sovereign Federated AI Poisoning and Privacy Defense Capstone",
     "L2-Norm 클리핑, Multi-Krum 비잔틴 내결함 집계, DP-SGD 가우시안 엡실론 통제, 비밀 분할 안전 집계 및 FIPS 204 ML-DSA-87 하드웨어 TEE 원격 증명을 결합한 종합 실전 방어 캡스톤을 완결합니다.\n\n[챌린지 식별자]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_sovereign_federated_ai_poisoning_and_privacy_defense_capstone``\n\n[문제 안내]\n해당 주권 연합 AI 방어 캡스톤 명세를 분석하고 올바른 플래그를 도출하여 제출하십시오.",
     "Execute the end-to-end sovereign federated AI cyber defense capstone uniting L2 clipping, Multi-Krum aggregation, DP-SGD, secure MPC, and FIPS 204 attestation.\n\n[Challenge Identifier]\n`FEDSEC_CHALLENGE_ID: `t4_fedsec_sovereign_federated_ai_poisoning_and_privacy_defense_capstone``\n\n[Task]\nAnalyze the sovereign federated AI capstone specification, then derive and submit the flag.")
]

def main():
    print("[*] Generating Track 90: fedsec challenges...")

    # 1. Format challenges for wargame/assets/challenges.js
    formatted_challenges = []
    challenge_ids = []
    for tier, cid, pts, title_ko, title_en, prompt_ko, prompt_en in CHALLENGE_SPECS:
        challenge_ids.append(cid)
        # Deterministic flag: FLAG{<sha256(cid + '_vibe_fedsec_2026')[:20]>}
        flag_seed = cid + "_vibe_fedsec_2026"
        flag_hash = hashlib.sha256(flag_seed.encode()).hexdigest()[:20]
        flag = f"FLAG{{{flag_hash}}}"
        ch_hash = hashlib.sha256(flag.encode()).hexdigest()

        ch_obj = {
            "id": cid,
            "tier": tier,
            "cat": "ai",
            "track": "fedsec",
            "points": pts,
            "ci": False,
            "hash": ch_hash,
            "fmt": "FLAG{...}",
            "title": {
                "ko": title_ko,
                "en": title_en
            },
            "prompt": {
                "ko": prompt_ko,
                "en": prompt_en
            },
            "hints": {
                "ko": [
                    f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
                ],
                "en": [
                    f"This challenge derives a deterministic flag from identifier `{cid}`."
                ]
            }
        }
        formatted_challenges.append(ch_obj)

    print(f"[+] Created {len(formatted_challenges)} challenge objects.")

    # 2. Update wargame/assets/challenges.js
    chall_file = REPO_ROOT / "wargame" / "assets" / "challenges.js"
    content = chall_file.read_text(encoding="utf-8")

    # Add track definition if not present
    if '"id": "fedsec"' not in content:
        track_def = """  },
  {
    "id": "fedsec",
    "icon": "🤖",
    "ko": "연합 학습 모델 중독 & 프라이버시 방어",
    "en": "Federated AI Poisoning & Privacy Defense",
    "desc_ko": "연합 학습(Federated Learning) 비잔틴 클라이언트 가중치 폭탄 투하 차단, L2-Norm 클리핑 및 코사인 유사도 이상치 검출, Multi-Krum/Trimmed-Mean 견고 집계, 차분 프라이버시(DP-SGD) 가우시안 노이즈 주입 및 엡실론 예산 통제, 비밀 분할 안전 집계 및 NIST FIPS 204 ML-DSA-87 하드웨어 원격 증명.",
    "desc_en": "Federated Learning Byzantine model poisoning mitigation, gradient L2-norm clipping, cosine similarity alignment, Multi-Krum and Trimmed-Mean robust aggregation, DP-SGD Gaussian noise differential privacy budget clamping, and NIST FIPS 204 ML-DSA-87 hardware attestation."
  }
];"""
        content = content.replace("  }\n];\n\nconst CHALLENGES =", track_def + "\n\nconst CHALLENGES =")

    # Append challenges before the closing bracket of CHALLENGES array
    if f'"id": "{CHALLENGE_SPECS[0][1]}"' not in content:
        # Format json for each challenge
        ch_json_lines = []
        for ch in formatted_challenges:
            ch_json_lines.append("  " + json.dumps(ch, ensure_ascii=False, indent=2).replace("\n", "\n  "))
        
        insert_text = ",\n" + ",\n".join(ch_json_lines) + "\n];"
        # Replace the last "];"
        last_bracket_idx = content.rfind("];")
        if last_bracket_idx != -1:
            content = content[:last_bracket_idx] + insert_text + content[last_bracket_idx+2:]
            chall_file.write_text(content, encoding="utf-8")
            print("[+] Successfully added 35 challenges to wargame/assets/challenges.js")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_file = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
    s_content = solve_file.read_text(encoding="utf-8")
    if "FEDSEC_IDS" not in s_content:
        fedsec_ids_code = f"""
const FEDSEC_IDS = [
""" + ",\n".join([f'  "{cid}"' for cid in challenge_ids]) + """
];

for (const id of FEDSEC_IDS) {
  SOLVERS.set(id, {
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/FEDSEC_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_fedsec_2026').digest('hex').slice(0, 20);
      return `FLAG{${hash}}`;
    }
  });
}
"""
        # Insert before DECLINED
        declined_idx = s_content.find("const DECLINED =")
        if declined_idx != -1:
            s_content = s_content[:declined_idx] + fedsec_ids_code + "\n" + s_content[declined_idx:]
            solve_file.write_text(s_content, encoding="utf-8")
            print("[+] Successfully added fedsec solvers to wargame/scripts/solve-derivable.js")

    # 4. Update wargame/README.md with per-tier topic rows for fedsec
    readme_file = REPO_ROOT / "wargame" / "README.md"
    r_content = readme_file.read_text(encoding="utf-8")
    if "`fedsec`" not in r_content:
        tier_topics = {
            0: "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) | 연합 학습 분산 AI 아키텍처 · FedAvg 원리 · 비잔틴 결함 내성 개요 · 시빌 공격 위협 모델 · 그래디언트 폭발 원리 · L2-Norm 클리핑 기초 · 코사인 유사도 벡터 정렬 · 차분 프라이버시 수학 기초 · 멤버십 추론 공격 메커니즘 · 다자간 안전 계산 SMPC / Federated Learning distributed architecture, FedAvg foundations, Byzantine fault tolerance overview, Sybil threat models, gradient explosion, L2-norm clipping basics, cosine similarity alignment, differential privacy foundations, membership inference attack mechanics, and secure multi-party computation SMPC |",
            1: "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) | 클라이언트 그래디언트 L2 클리핑 · 코사인 유사도 이상치 필터링 · 좌표별 트림드 평균 집계 · Multi-Krum 비잔틴 견고 후보 선출 · 르니 차분 프라이버시 RDP 가우시안 잡음 · 모먼트 어카운턴트 엡실론 회계 · 클라이언트 간 영합 비밀 마스킹 / Client gradient L2-norm clipping, cosine similarity anomaly filtering, coordinate-wise trimmed-mean aggregation, Multi-Krum candidate selection, Rényi differential privacy Gaussian noise, Moments Accountant epsilon tracking, and zero-sum pairwise secret masking |",
            2: "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) | 비잔틴 그래디언트 스케일링 탐지 · Bulyan 집계 프레임워크 · 적응형 클리핑 경계 추정 · FIPS 204 ML-DSA-87 서명 인가 · 역그래디언트 연합 언러닝 백도어 소거 · 로컬 차분 프라이버시 LDP 라플라스 섭동 · 안전 집계 생존 쿼럼 합의 검증 / Byzantine gradient scaling attack detection, Bulyan robust aggregation, differentially private adaptive clipping, FIPS 204 ML-DSA-87 signature verification, federated unlearning backdoor erasure, local differential privacy Laplace perturbation, and secure aggregation quorum consensus |",
            3: "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) | 잠재 활성화 타깃 백도어 트리거 감지 · 샤미르 비밀 분할 다항식 복원 · 인텔 TDX 하드웨어 TEE PCR 인클레이브 원격 증명 · 경사 하강 모델 역변환 방어 · 크로스 사일로 SPIFFE 워크로드 ID 메시 · 바이스펠트 기하학적 메디안 집계 · 비IID 데이터 이질성과 악의적 드리프트 분류 격리 / Targeted backdoor trigger detection, Shamir secret sharing polynomial recovery, Intel TDX hardware TEE PCR enclave attestation, model inversion defense, cross-silo SPIFFE workload identity mesh, Weiszfeld geometric median aggregation, and Non-IID heterogeneity versus malicious drift isolation |",
            4: "| `fedsec` 🤖 연합 학습 모델 중독 & 프라이버시 방어 (7) | 스펙트럴 그래프 시빌 스웜 공모 방어 · DLG 픽셀 그래디언트 복원 차단 · zk-SNARKs 영지식 증명 클라이언트 검증 · FIPS 203 ML-KEM-1024 양자 내성 보안 채널 · 프록시멀 항 결합 비잔틴 지연자 완화 · 하드웨어 TPM 2.0 Quote PCR 라이브 검증 · 주권 연합 AI 모델 중독 및 프라이버시 방어 캡스톤 / Spectral graph Sybil swarm collusion defense, Deep Leakage from Gradients pixel reconstruction shield, zk-SNARKs client update verification, FIPS 203 ML-KEM-1024 post-quantum channel, Byzantine FedProx straggler mitigation, hardware TPM 2.0 Quote PCR verification, and sovereign federated AI defense capstone |"
        }

        # Insert each tier topic after satcomqkd row in each tier section
        lines = r_content.splitlines()
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if "`satcomqkd`" in line and "(7)" in line:
                for t in range(5):
                    if t in tier_topics:
                        # Check context by looking backwards for tier heading
                        # Just insert the matching tier based on occurrences
                        pass

        # Instead of fuzzy matching, find satcomqkd rows and append corresponding fedsec rows
        parts = r_content.split("| `satcomqkd` 🛰️ 저궤도 위성 광통신 & 우주 QKD (7) |")
        if len(parts) == 6:
            reconstructed = parts[0]
            for i in range(5):
                reconstructed += "| `satcomqkd` 🛰️ 저궤도 위성 광통신 & 우주 QKD (7) |" + parts[i+1].split("\n", 1)[0] + "\n" + tier_topics[i] + parts[i+1][len(parts[i+1].split("\n", 1)[0]):]
            r_content = reconstructed

            # Also update 3115 -> 3150 in wargame/README.md
            r_content = r_content.replace("총 **3115문제**", "총 **3150문제**")
            r_content = r_content.replace("Total **3115 challenges**", "Total **3150 challenges**")
            readme_file.write_text(r_content, encoding="utf-8")
            print("[+] Successfully updated wargame/README.md with fedsec topics and 3150 challenges.")

    # 5. Update wargame/index.html HUD & challenge count
    index_file = REPO_ROOT / "wargame" / "index.html"
    idx_content = index_file.read_text(encoding="utf-8")
    if "3115" in idx_content:
        idx_content = idx_content.replace("3115", "3150")
        index_file.write_text(idx_content, encoding="utf-8")
        print("[+] Successfully updated wargame/index.html to 3150 challenges.")

if __name__ == "__main__":
    main()
