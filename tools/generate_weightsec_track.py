#!/usr/bin/env python3
"""
Generator for Track 81: weightsec (Neural Weight Steganography, SafeTensors Hardening & Sigstore Cosign)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,835 challenges milestone across 81 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "pickle_vs_safetensors_threat_model",
        "title_ko": "레거시 Pickle 바이트코드 위험과 SafeTensors 제로 역직렬화 위협 모델",
        "title_en": "Legacy Pickle Bytecode Risks & SafeTensors Zero-Deserialization Threat Model",
        "desc_ko": "PyTorch 가중치 저장 포맷(.pt/.bin)의 임의 코드 실행 위험과 SafeTensors의 제로 역직렬화 안전 모델을 비교 분석합니다.",
        "desc_en": "Compare arbitrary code execution risks of PyTorch legacy formats (.pt/.bin) with SafeTensors zero-deserialization guarantees."
    },
    {
        "tier": 0, "points": 25, "slug": "neural_weight_lsb_stego_concepts",
        "title_ko": "신경망 가중치 부동소수점 가수부 LSB 은닉 채널 개념",
        "title_en": "Neural Network Float32 Mantissa LSB Covert Channel Concepts",
        "desc_ko": "딥러닝 가중치 부동소수점 최하위 비트에 모델 출력 손실 없이 악성 셸코드나 C2 주소를 은닉하는 원리를 학습합니다.",
        "desc_en": "Study the principles of embedding covert shellcode or C2 payloads into floating-point mantissa least significant bits."
    },
    {
        "tier": 0, "points": 25, "slug": "model_supply_chain_poisoning_vectors",
        "title_ko": "모델 레지스트리 가중치 오염 및 비인가 가중치 주입 공격 표면",
        "title_en": "Model Registry Supply Chain Poisoning & Weight Injection Surfaces",
        "desc_ko": "Hugging Face 등 오픈소스 허브에서 서명되지 않은 가중치 체크포인트를 배포하여 시스템을 장악하는 공격 경로를 검토합니다.",
        "desc_en": "Analyze attack pathways exploiting unsigned model checkpoints across open-source hubs to compromise downstream systems."
    },
    {
        "tier": 0, "points": 25, "slug": "weight_quantization_bitmask_theory",
        "title_ko": "FP8/INT8 동적 양자화 및 비트마스크 살균 방어 이론",
        "title_en": "FP8/INT8 Dynamic Quantization & Bitmask Sanitization Defense Theory",
        "desc_ko": "부동소수점 정밀도를 양자화하거나 가수부 하위 비트를 강제 마스킹하여 은닉 채널을 무력화하는 방어 메커니즘을 학습합니다.",
        "desc_en": "Learn defense mechanisms eliminating covert channels via dynamic quantization and mantissa low-bit masking."
    },
    {
        "tier": 0, "points": 25, "slug": "gaussian_weight_distribution_metrics",
        "title_ko": "정규분포 가중치 통계 지표 및 분산 이상치 분석 원리",
        "title_en": "Gaussian Weight Distribution Metrics & Variance Anomaly Detection",
        "desc_ko": "사전학습된 신경망 가중치의 평균, 표준편차, 첨도 지표를 기준으로 인위적 조작 패턴을 색출하는 통계 원리를 분석합니다.",
        "desc_en": "Analyze statistical metrics (mean, stddev, kurtosis) in pre-trained weights to detect artificial tampering patterns."
    },
    {
        "tier": 0, "points": 25, "slug": "sigstore_cosign_provenance_fundamentals",
        "title_ko": "Sigstore Cosign 및 Rekor 투명성 원장 모델 출처 증명 기초",
        "title_en": "Sigstore Cosign & Rekor Transparency Log Model Provenance Fundamentals",
        "desc_ko": "OIDC 기반 무키 서명(Keyless Signing)과 Rekor 투명성 감사 원장을 활용하여 모델 출처를 암호학적으로 검증하는 원리를 학습합니다.",
        "desc_en": "Study cryptographic model provenance verification using OIDC keyless signing and Rekor transparency logs."
    },
    {
        "tier": 0, "points": 25, "slug": "huggingface_hub_model_audit_principles",
        "title_ko": "공개 모델 허브 체크포인트 보안 감사 원칙",
        "title_en": "Open Model Hub Checkpoint Security Audit Principles",
        "desc_ko": "외부 레지스트리에서 다운로드한 사전학습 가중치 파일의 해시 무결성과 악성 파이썬 실행 가능성을 선제 평가하는 감사 수칙을 정립합니다.",
        "desc_en": "Establish security audit guidelines evaluating hash integrity and Python bytecode execution in downloaded checkpoints."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "safetensors_header_json_boundary_audit",
        "title_ko": "SafeTensors 8바이트 헤더 크기 및 JSON 메타데이터 경계 감사",
        "title_en": "SafeTensors 8-Byte Header Size & JSON Metadata Boundary Audit",
        "desc_ko": "SafeTensors 파일 선두 8바이트(u64 little-endian) 길이 필드와 JSON 메타데이터 버퍼 오버플로우 경계를 정밀 검증합니다.",
        "desc_en": "Audit the 8-byte u64 little-endian header length field and JSON metadata buffer boundaries in SafeTensors binaries."
    },
    {
        "tier": 1, "points": 50, "slug": "pickle_magic_byte_disassembly_inspection",
        "title_ko": "Pickle 매직 바이트 및 위험 오프코드 디스어셈블리 검사",
        "title_en": "Pickle Magic Bytes & Dangerous Opcode Disassembly Inspection",
        "desc_ko": "바이너리 스트림에서 0x80 매직 바이트를 감지하고 pickletools 디스어셈블러로 REDUCE(R), GLOBAL(c), BUILD(b) 명령어를 색출합니다.",
        "desc_en": "Detect 0x80 magic bytes and parse pickletools disassembly to isolate REDUCE, GLOBAL, and BUILD opcodes."
    },
    {
        "tier": 1, "points": 50, "slug": "float32_mantissa_lsb_extraction",
        "title_ko": "Float32 가수부 최하위 비트(LSB) 은닉 페이로드 정밀 추출",
        "title_en": "Float32 Mantissa Least Significant Bit Covert Payload Extraction",
        "desc_ko": "IEEE 754 float32 비트 표현식에서 가수부(mantissa) 23비트 중 최하위 1~2비트를 연속 비트 스트림으로 디코딩하여 은닉 데이터를 복원합니다.",
        "desc_en": "Extract the lowest 1-2 bits from the 23-bit mantissa of IEEE 754 float32 weights to reconstruct embedded covert streams."
    },
    {
        "tier": 1, "points": 50, "slug": "quantization_clipping_weight_sanitization",
        "title_ko": "동적 양자화 클리핑을 통한 부동소수점 미세 노이즈 제거",
        "title_en": "Dynamic Quantization Clipping Weight Noise Sanitization",
        "desc_ko": "텐서 가중치를 대칭형 INT8/FP8 범위로 동적 양자화 후 역양자화하여 가수부 미세 은닉 노이즈를 완전 소멸시킵니다.",
        "desc_en": "Quantize weights dynamically to symmetric INT8/FP8 and dequantize back to eliminate subtle mantissa covert noise."
    },
    {
        "tier": 1, "points": 50, "slug": "shannon_entropy_bit_distribution_audit",
        "title_ko": "텐서 비트 샤논 엔트로피(H <= 7.92) 측정 및 이상치 감사",
        "title_en": "Tensor Bit Shannon Entropy Measurement & Anomaly Audit",
        "desc_ko": "가중치 바이트 분포의 샤논 엔트로피를 계산하여 정상 가우스 분포(7.2~7.8)를 초과하는 압축/암호화 은닉 블록을 색출합니다.",
        "desc_en": "Calculate Shannon entropy across weight bytes to identify compressed or encrypted covert blocks exceeding Gaussian baselines."
    },
    {
        "tier": 1, "points": 50, "slug": "rekor_transparency_log_inclusion_verification",
        "title_ko": "Rekor 투명성 로그 머클 포함 증명 검증",
        "title_en": "Rekor Transparency Log Merkle Inclusion Proof Verification",
        "desc_ko": "Sigstore Rekor REST API로부터 모델 아티팩트의 로그 인덱스와 머클 트리 포함 증명(Inclusion Proof)을 감사하여 위조 배포를 차단합니다.",
        "desc_en": "Verify Merkle inclusion proofs and log indices from the Sigstore Rekor transparency ledger to block rogue distributions."
    },
    {
        "tier": 1, "points": 50, "slug": "ed25519_model_weight_signature_validation",
        "title_ko": "Ed25519 디지털 서명 기반 모델 가중치 파일 무결성 감사",
        "title_en": "Ed25519 Digital Signature Model Weight File Integrity Audit",
        "desc_ko": "공식 모델 릴리즈 체크포인트의 SHA-256 해시를 추출하고 Ed25519 공개키를 통해 서명 일치 여부를 단일 턴으로 검증합니다.",
        "desc_en": "Compute SHA-256 digests of release checkpoints and validate Ed25519 digital signatures against verified public keys."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "zero_deserialization_safetensors_enforcer",
        "title_ko": "역직렬화 없는 직접 메모리 맵(mmap) SafeTensors 텐서 로더 구현",
        "title_en": "Zero-Deserialization Direct mmap SafeTensors Tensor Loader",
        "desc_ko": "파이썬 객체 인스턴스화 없이 커널 mmap을 통해 가중치 바이너리를 가상 메모리에 직접 매핑하는 무역직렬화 로더를 구성합니다.",
        "desc_en": "Implement a memory-mapped SafeTensors loader mapping raw tensor buffers directly without Python object deserialization."
    },
    {
        "tier": 2, "points": 100, "slug": "anti_pickle_rce_bytecode_firewall",
        "title_ko": "Pickle 가상머신(PVM) 바이트코드 정적 분석 인라인 방화벽",
        "title_en": "Pickle Virtual Machine (PVM) Bytecode Static Analysis Firewall",
        "desc_ko": "임의의 pickle 스트림을 디스패치하기 전에 위험 모듈(os, subprocess, builtins) 로드 요청을 인라인 차단하는 PVM 방화벽을 적용합니다.",
        "desc_en": "Deploy an inline PVM firewall intercepting unpickler dispatch to block dangerous modules before opcode evaluation."
    },
    {
        "tier": 2, "points": 100, "slug": "lsb_bitmask_sanitizer_pipeline",
        "title_ko": "텐서별 가중치 가수부 하위 비트 강제 0 마스킹 살균 파이프라인",
        "title_en": "Per-Tensor Weight Mantissa LSB Zero-Masking Sanitizer Pipeline",
        "desc_ko": "신경망 모델의 각 레이어 가중치 텐서에 대해 비트마스크(0xFFFFFFFC) 연산을 적용하여 LSB 2비트를 결정론적으로 초기화합니다.",
        "desc_en": "Apply deterministic bitmask (0xFFFFFFFC) operations across all layer weight tensors to zero out 2 LSB bits."
    },
    {
        "tier": 2, "points": 100, "slug": "chi_square_goodness_of_fit_sentinel",
        "title_ko": "가우스 정규분포 적합도 카이제곱 검정(p >= 0.05) 센티널",
        "title_en": "Gaussian Goodness-of-Fit Chi-Square Sentinel (p >= 0.05)",
        "desc_ko": "레이어 가중치 빈(bin) 빈도수를 이론적 정규분포 기대치와 비교하여 카이제곱 유의확률이 0.05 미만인 조작 텐서를 자동 격리합니다.",
        "desc_en": "Compare tensor frequency bins with theoretical Gaussian distributions, quarantining layers with Chi-Square p < 0.05."
    },
    {
        "tier": 2, "points": 100, "slug": "layer_variance_anomaly_filtering",
        "title_ko": "레이어별 가중치 분산 이상치(3-시그마) 탐지 및 자동 격리",
        "title_en": "Layer-Wise Weight Variance Anomaly Detection & Auto-Quarantine",
        "desc_ko": "트랜스포머 어텐션 프로젝션 레이어의 가중치 분산이 모델 전체 평균 편차의 3-시그마를 초과할 경우 이상치로 판정합니다.",
        "desc_en": "Evaluate layer weight variances across attention projections, isolating layers deviating beyond 3-sigma thresholds."
    },
    {
        "tier": 2, "points": 100, "slug": "cosign_bundle_fulcio_cert_chain_validation",
        "title_ko": "Cosign 번들 내 Fulcio X.509 OIDC 인증서 체인 검증",
        "title_en": "Cosign Bundle Fulcio X.509 OIDC Certificate Chain Validation",
        "desc_ko": "Sigstore Fulcio 루트 CA로부터 발급된 서명자 OIDC ID(GitHub Actions 워크플로 URI)와 SCT 무결성을 정밀 감사합니다.",
        "desc_en": "Audit signer OIDC identities (GitHub Actions workflow URIs) and SCT integrity within Fulcio-issued X.509 cert chains."
    },
    {
        "tier": 2, "points": 100, "slug": "model_provenance_immutable_attestation",
        "title_ko": "소프트웨어 공급망 보안 기준(SLSA Level 3) 모델 출처 불변 증명",
        "title_en": "SLSA Level 3 Software Supply Chain Model Provenance Attestation",
        "desc_ko": "빌드 환경, 소스 커밋 해시, 훈련 데이터 다이제스트가 기록된 in-toto attestation JSON 메타데이터를 정밀 파싱하고 검증합니다.",
        "desc_en": "Parse and cryptographically verify in-toto attestation JSON metadata containing source commit and training hashes."
    },

    # Tier 3 (7 challenges, 150 points each)
    {
        "tier": 3, "points": 150, "slug": "in_kernel_safetensors_integrity_guard",
        "title_ko": "eBPF LSM 기반 SafeTensors 파일 I/O 변조 방지 실시간 감시",
        "title_en": "eBPF LSM SafeTensors File I/O Anti-Tampering Realtime Guard",
        "desc_ko": "가중치 파일이 메모리에 로딩된 이후 프로세스 외부에서 파일 디스크립터를 수정하려는 무단 쓰기 시도를 eBPF LSM으로 즉각 차단합니다.",
        "desc_en": "Deploy eBPF LSM security hooks intercepting unauthorized write syscalls targeting open SafeTensors file descriptors."
    },
    {
        "tier": 3, "points": 150, "slug": "covert_weight_channel_differential_analyzer",
        "title_ko": "원본 모델 대비 양자화 전후 가중치 편차 기반 은닉 채널 차분 분석",
        "title_en": "Pre/Post-Quantization Weight Deviation Differential Analyzer",
        "desc_ko": "가중치 행렬의 부동소수점 차분 맵(Delta Matrix)을 생성하여 의도적인 규칙성을 갖는 LSB 스트림을 통계적으로 분리합니다.",
        "desc_en": "Generate floating-point delta matrices across quantization steps to isolate deterministic patterns in LSB streams."
    },
    {
        "tier": 3, "points": 150, "slug": "multimodal_tensor_entropy_anomaly_scanner",
        "title_ko": "텍스트/비전 복합 트랜스포머 레이어 전수 엔트로피 스캐너",
        "title_en": "Multimodal Transformer Layer Full-Spectrum Entropy Scanner",
        "desc_ko": "비전 인코더 및 언어 디코더 전 레이어(수억 개 파라미터)의 비트 레벨 엔트로피를 병렬 계산하여 국소적 이상 블록을 색출합니다.",
        "desc_en": "Compute bit-level entropy across all vision and language layers in parallel to pinpoint localized anomalies."
    },
    {
        "tier": 3, "points": 150, "slug": "adversarial_weight_backdoor_trigger_mitigation",
        "title_ko": "가중치 트리거 백도어 뉴런 가중치 클리핑 방어",
        "title_en": "Adversarial Weight Backdoor Trigger Neuron Clipping Defense",
        "desc_ko": "특정 입력 트리거에만 비정상 활성화되는 백도어 가중치를 탐지하고 activation-aware weight clipping(AWAC) 기법으로 무력화합니다.",
        "desc_en": "Detect dormant backdoor weights activated by specific triggers and neutralize them using activation-aware weight clipping."
    },
    {
        "tier": 3, "points": 150, "slug": "sigstore_rekor_merkle_root_cross_verifier",
        "title_ko": "Rekor 분산 투명성 원장 머클 루트 해시 교차 검증 파이프라인",
        "title_en": "Rekor Distributed Transparency Merkle Root Cross-Verification Pipeline",
        "desc_ko": "여러 독립된 Rekor 모니터 노드로부터 서명된 트리 헤드(Signed Tree Head, STH)를 수집하여 분산 합의 일치 여부를 감사합니다.",
        "desc_en": "Aggregate Signed Tree Heads (STH) from independent Rekor monitors to verify cross-node consensus integrity."
    },
    {
        "tier": 3, "points": 150, "slug": "ephemeral_key_kdf_weight_decryption",
        "title_ko": "임시 KDF 세션키 기반 엔클레이브 내 모델 가중치 불변 복호화",
        "title_en": "Ephemeral KDF Session Key In-Enclave Weight Decryption",
        "desc_ko": "하드웨어 보안 엔클레이브(TEE) 내부에서만 HKDF-SHA256으로 파생된 30초 휘발성 키로 SafeTensors 텐서를 안전하게 복호화합니다.",
        "desc_en": "Decrypt SafeTensors buffers within hardware TEE enclaves using ephemeral HKDF-derived 30-second session keys."
    },
    {
        "tier": 3, "points": 150, "slug": "automated_model_registry_quarantine_daemon",
        "title_ko": "변조 가중치 감지 즉시 레지스트리 비공개 전환 및 격리 데몬",
        "title_en": "Automated Model Registry Quarantine & Access Revocation Daemon",
        "desc_ko": "무결성 감사에 실패한 체크포인트의 다운로드 엔드포인트를 0.5초 이내에 차단하고 보안 팀에 격리 텔레메트리를 발송합니다.",
        "desc_en": "Revoke public download endpoints within 500ms upon integrity audit failure and dispatch quarantine telemetry."
    },

    # Tier 4 (7 challenges, 200 points each)
    {
        "tier": 4, "points": 200, "slug": "full_spectrum_neural_weight_defense_mesh",
        "title_ko": "가중치 수집부터 서빙까지 전주기 신경망 무결성 방어 메시",
        "title_en": "Full-Spectrum Neural Weight Integrity Defense Mesh",
        "desc_ko": "SafeTensors 포맷 강제, LSB 비트마스크 살균, 카이제곱 통계 센티널, Cosign 서명 검증을 결합한 통합 무결성 방어망을 구축합니다.",
        "desc_en": "Construct an end-to-end defense mesh coupling SafeTensors, LSB bitmasking, Chi-Square telemetry, and Cosign attestation."
    },
    {
        "tier": 4, "points": 200, "slug": "hardware_enclave_safetensors_attestation",
        "title_ko": "AMD SEV-SNP/TDX TEE 내부 SafeTensors 로딩 및 메모리 암호화",
        "title_en": "Hardware Enclave SafeTensors Loading & Memory Encryption",
        "desc_ko": "호스트 OS 커널조차 가중치 메모리를 덤프할 수 없도록 SEV-SNP/TDX 하드웨어 암호화 페이지에 SafeTensors를 안전하게 바인딩합니다.",
        "desc_en": "Bind SafeTensors memory into SEV-SNP/TDX hardware-encrypted pages preventing host kernel memory snooping."
    },
    {
        "tier": 4, "points": 200, "slug": "zero_leak_weight_steganography_neutralizer",
        "title_ko": "추론 정확도 손실 0% 부동소수점 완전 살균 엔진",
        "title_en": "Zero-Accuracy-Loss Floating-Point Sanitization Engine",
        "desc_ko": "GLUE 및 MMLU 벤치마크 정확도 하락(0.01% 이하) 없이 은닉 바이트를 완전히 소멸시키는 수학적 무작위화 디더링을 적용합니다.",
        "desc_en": "Apply mathematical randomization dithering completely eradicating covert bytes with <0.01% downstream accuracy impact."
    },
    {
        "tier": 4, "points": 200, "slug": "decentralized_merkle_provenance_blockchain",
        "title_ko": "모델 체크포인트 불변 분산 머클 감사 원장 연동",
        "title_en": "Decentralized Merkle Model Provenance Blockchain Ledger",
        "desc_ko": "모든 모델 버전의 가중치 루트 해시와 감사 이력을 단일 장애점이 없는 분산 머클 투명성 원장에 영구 기록합니다.",
        "desc_en": "Record weight root hashes and audit events onto a decentralized Merkle transparency ledger without single points of failure."
    },
    {
        "tier": 4, "points": 200, "slug": "autonomous_ai_security_weight_auditor",
        "title_ko": "AI 에이전트 자율 신경망 가중치 역공학 및 변조 탐지 시스템",
        "title_en": "Autonomous AI Security Agent Neural Weight Reverse Engineering",
        "desc_ko": "자율 보안 에이전트가 텐서 구조를 분석하고 은닉된 C2 도메인 및 셸코드를 사람 개입 없이 자율 추출·보고하는 파이프라인을 운영합니다.",
        "desc_en": "Deploy autonomous security agents automatically disassembling tensors and carving covert C2 strings without human intervention."
    },
    {
        "tier": 4, "points": 200, "slug": "capstone_safe_ai_model_supply_chain_defense",
        "title_ko": "[Capstone] SafeTensors + LSB 살균 + 카이제곱 + Sigstore 통합 방어체계",
        "title_en": "[Capstone] Unified SafeTensors, LSB Sanitization, Chi-Square & Sigstore Defense",
        "desc_ko": "복합 모델 공급망 침투 시나리오에서 4단계 전주기 방어 파이프라인을 가동하여 0-결함 방어 플래그를 도출합니다.",
        "desc_en": "Execute a 4-phase comprehensive defense pipeline across composite supply chain attacks to retrieve the verified flag."
    },
    {
        "tier": 4, "points": 200, "slug": "capstone_weightsec_sovereign_ai_assurance",
        "title_ko": "[Capstone] 국가 전략급 주권 AI 모델 무결성·출처 보증 아키텍처",
        "title_en": "[Capstone] Strategic Sovereign AI Model Integrity & Provenance Assurance",
        "desc_ko": "국가 주요 기반시설 및 국방 AI 시스템을 위한 최고 등급의 신경망 가중치 무결성, 하드웨어 증명, 영지식 공급망 보증 체계를 완결합니다.",
        "desc_en": "Finalize national strategic-grade neural weight integrity, hardware attestation, and zero-knowledge supply chain assurance."
    }
]

def main():
    root_dir = Path(__file__).resolve().parent.parent
    wargame_dir = root_dir / "wargame"
    challenges_js_path = wargame_dir / "assets" / "challenges.js"
    solve_derivable_path = wargame_dir / "scripts" / "solve-derivable.js"
    readme_path = wargame_dir / "README.md"
    index_html_path = wargame_dir / "index.html"
    root_index_html_path = root_dir / "index.html"

    print("=== Generating Track 81: weightsec (35 challenges, Total 2,835 milestone) ===")

    # 1. Prepare challenges objects
    new_challenges = []
    for cdata in CHALLENGES_DATA:
        cid = f"t{cdata['tier']}_weightsec_{cdata['slug']}"
        flag_hash = hashlib.sha256(f"{cid}_vibe_weightsec_2026".encode("utf-8")).hexdigest()[:20]
        ch_hash = hashlib.sha256(f"FLAG{{{flag_hash}}}".encode("utf-8")).hexdigest()

        prompt_ko = (
            f"AI 모델 신경망 가중치 스테가노그래피 및 SafeTensors 공급망 방어 실무를 수행합니다.\n\n"
            f"주제: {cdata['title_ko']}\n"
            f"상세 분석 지침:\n"
            f"- {cdata['desc_ko']}\n"
            f"- 신경망 가중치 텐서 및 SafeTensors 공급망 무결성을 정밀 감사하십시오.\n"
            f"- 검증 식별자 WEIGHTSEC_CHALLENGE_ID: `{cid}`\n"
            f"- 보안 정책 및 무결성 검증을 충족하여 정상 플래그를 획득하십시오."
        )

        prompt_en = (
            f"Conduct technical hands-on verification of neural weight steganography and SafeTensors supply chain defense.\n\n"
            f"Topic: {cdata['title_en']}\n"
            f"Analysis Requirements:\n"
            f"- {cdata['desc_en']}\n"
            f"- Thoroughly audit neural weight tensors and SafeTensors supply chain integrity.\n"
            f"- Verification Identifier WEIGHTSEC_CHALLENGE_ID: `{cid}`\n"
            f"- Satisfy the security parameters and retrieve the authorized flag."
        )

        ch = {
            "id": cid,
            "tier": cdata["tier"],
            "cat": "ai",
            "track": "weightsec",
            "points": cdata["points"],
            "ci": False,
            "hash": ch_hash,
            "fmt": "FLAG{...}",
            "title": {
                "ko": cdata["title_ko"],
                "en": cdata["title_en"]
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
        new_challenges.append(ch)

    print(f"[+] Prepared {len(new_challenges)} challenges for Track 81 (weightsec).")

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")

    # Check if TRACK 81 already in TRACKS
    if '"id": "weightsec"' in content:
        print("[-] Track 81 (weightsec) already in TRACKS.")
    else:
        track_entry = """,
  {
    "id": "weightsec",
    "icon": "⚖️",
    "ko": "AI 신경망 가중치 스테가노그래피 & SafeTensors 공급망 방어",
    "en": "Neural Weight Steganography, SafeTensors Hardening & Sigstore Cosign",
    "desc_ko": "Pickle RCE 역직렬화 차단·SafeTensors 헤더 무결성 검증·가중치 가수부 LSB 스테가노그래피 은닉 탐지 & 비트마스크 양자화 살균·카이제곱 적합도 검정 및 샤논 엔트로피 이상치 감사·Sigstore Cosign 머클 트리 원격 증명 및 모델 출처 불변성 검증.",
    "desc_en": "Pickle deserialization RCE mitigation, SafeTensors header integrity validation, weight mantissa LSB steganography detection and quantization sanitization, Chi-Square goodness-of-fit and Shannon entropy anomaly auditing, and Sigstore Cosign Merkle tree attestation."
  }"""
        swarmsentry_track_needle = '    "id": "swarmsentry",\n    "icon": "🐝",\n    "ko": "자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어",\n    "en": "Autonomous Multi-Agent Swarm Security & Byzantine Defense",\n    "desc_ko": "사칭 워커 에이전트 등록 차단·X.509 mTLS/SPIFFE ID 상호 인증·PBFT 비잔틴 합의 오염 방어·Landlock LSM 공유 메모리 격리·Cilium Tetragon eBPF 0ms SIGKILL 즉시 사살.",\n    "desc_en": "Rogue worker agent registration denial, X.509 mTLS/SPIFFE ID mutual authentication, PBFT Byzantine consensus defense, Landlock LSM shared memory isolation, and Cilium Tetragon eBPF 0ms SIGKILL containment."\n  }\n];'
        
        if swarmsentry_track_needle in content:
            replacement = swarmsentry_track_needle[:-3] + track_entry + "\n];"
            content = content.replace(swarmsentry_track_needle, replacement, 1)
            print("[+] Inserted Track 81 definition into TRACKS.")
        else:
            m = re.search(r'("id":\s*"swarmsentry"[\s\S]*?\n  }\n)(];)', content)
            assert m, "Could not locate swarmsentry track in TRACKS array"
            content = content[:m.end(1)] + track_entry + "\n" + content[m.start(2):]
            print("[+] Inserted Track 81 definition into TRACKS via regex.")

    # Check if challenges already present
    existing_cids = set(re.findall(r'"id":\s*"(t\d_weightsec_[^"]+)"', content))
    if existing_cids:
        print(f"[*] Removing {len(existing_cids)} old weightsec challenges from challenges.js...")
        m_start = re.search(r',\s*\{\s*"id":\s*"t0_weightsec_[^"]+"', content)
        if m_start:
            target_challs_end = "\n];"
            idx_end = content.rfind(target_challs_end)
            content = content[:m_start.start()] + content[idx_end:]

    target_challs_end = "\n];"
    formatted_challs = []
    for ch in new_challenges:
        ch_str = json.dumps(ch, ensure_ascii=False, indent=2)
        formatted_challs.append("  " + ch_str.replace("\n", "\n  "))
    challs_block = ",\n" + ",\n".join(formatted_challs)
    idx = content.rfind(target_challs_end)
    assert idx != -1, "Could not find end of CHALLENGES in challenges.js"
    content = content[:idx] + challs_block + "\n];" + content[idx + len(target_challs_end):]
    print("[+] Appended 35 weightsec challenges to CHALLENGES array with proper hints object.")

    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Wrote updated {challenges_js_path}")

    # 3. Update solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    weightsec_ids = [ch["id"] for ch in new_challenges]
    ids_js = ",\n  ".join([f'"{cid}"' for cid in weightsec_ids])
    derivable_code = """const WEIGHTSEC_IDS = [
  """ + ids_js + """
];

for (const id of WEIGHTSEC_IDS) {
  SOLVERS.set(id, {
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/WEIGHTSEC_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_weightsec_2026').digest('hex').slice(0, 20);
      return `FLAG{${hash}}`;
    }
  });
}
"""
    if "const WEIGHTSEC_IDS = [" in solve_content:
        solve_content = re.sub(r'const WEIGHTSEC_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing WEIGHTSEC_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added weightsec derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/README.md
    readme_text = readme_path.read_text(encoding="utf-8")
    readme_text = readme_text.replace("총 2800문제", "총 2835문제")
    readme_text = readme_text.replace("총 **2800문제**", "총 **2835문제**")
    readme_text = readme_text.replace("80개 트랙", "81개 트랙")
    readme_text = readme_text.replace("80개 섹션", "81개 섹션")
    readme_text = readme_text.replace("Total **2800 challenges**", "Total **2835 challenges**")

    # Update tier counts table (+7 each tier)
    readme_text = readme_text.replace("| `perimeter` 외곽 | **0** | 315 |", "| `perimeter` 외곽 | **0** | 322 |")
    readme_text = readme_text.replace("| `webserver` 웹서버 | **1** | 524 |", "| `webserver` 웹서버 | **1** | 531 |")
    readme_text = readme_text.replace("| `internal` 내부망 | **2** | 676 |", "| `internal` 내부망 | **2** | 683 |")
    readme_text = readme_text.replace("| `vault` 금고 | **3** | 666 |", "| `vault` 금고 | **3** | 673 |")
    readme_text = readme_text.replace("| `core` 코어 | **4** | 619 |", "| `core` 코어 | **4** | 626 |")

    # Update English summary list
    old_en_tail = "autonomous multi-agent swarm security & Byzantine defense 35); each maps to a topic from the [main repo](../README.md)'s 80 tracks."
    new_en_tail = "autonomous multi-agent swarm security & Byzantine defense 35 · neural weight steganography, SafeTensors hardening & Sigstore Cosign 35); each maps to a topic from the [main repo](../README.md)'s 81 tracks."
    if old_en_tail in readme_text:
        readme_text = readme_text.replace(old_en_tail, new_en_tail)

    tier0_row = "| `weightsec` ⚖️ AI 가중치 스테가노그래피 & SafeTensors 공급망 방어 (7) | SafeTensors 위협 모델 · 가수부 LSB 은닉 채널 · 가중치 오염 표면 · FP8 양자화 이론 / SafeTensors threat model, float32 mantissa LSB covert channels, weight poisoning surfaces, and FP8 quantization theory |"
    tier1_row = "| `weightsec` ⚖️ AI 가중치 스테가노그래피 & SafeTensors 공급망 방어 (7) | SafeTensors 헤더 경계 감사 · Pickle 오프코드 검사 · LSB 페이로드 추출 · 샤논 엔트로피 감사 / SafeTensors header audit, pickle opcode inspection, LSB payload extraction, and Shannon entropy audit |"
    tier2_row = "| `weightsec` ⚖️ AI 가중치 스테가노그래피 & SafeTensors 공급망 방어 (7) | mmap 무역직렬화 로더 · Pickle 방화벽 · 비트마스크 살균 · 카이제곱 적합도 검정 / mmap zero-deserialization loader, pickle firewall, bitmask sanitization, and Chi-Square goodness-of-fit |"
    tier3_row = "| `weightsec` ⚖️ AI 가중치 스테가노그래피 & SafeTensors 공급망 방어 (7) | eBPF 가중치 I/O 가드 · 양자화 차분 분석 · 전수 엔트로피 스캐너 · Rekor 머클 검증 / eBPF weight I/O guard, quantization differential analysis, full-spectrum entropy scanner, and Rekor Merkle verification |"
    tier4_row = "| `weightsec` ⚖️ AI 가중치 스테가노그래피 & SafeTensors 공급망 방어 (7) | 신경망 방어 메시 · TEE SafeTensors 증명 · 정확도 무손실 살균 · 가중치 보안 캡스톤 / Neural defense mesh, TEE SafeTensors attestation, zero-loss sanitization, and weightsec capstone |"

    swarmsentry_t0 = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | 스웜 위협 모델 · 사칭 워커 등록 위협 · 비잔틴 합의 이론 · 공유 메모리 위험 / Swarm threat model, rogue worker spoofing, Byzantine consensus theory, and shared memory risks |"
    swarmsentry_t1 = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | X.509 mTLS 상호 인증 감사 · JWT-SVID 서명 검증 · 이상 가중치 필터링 · Landlock 스냅샷 / X.509 mTLS mutual auth audit, JWT-SVID signature validation, anomaly weight filtering, and Landlock snapshots |"
    swarmsentry_t2 = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | PBFT 3단계 합의 검증 · 워커 즉시 축출 · 간접 프롬프트 주입 살균 · eBPF sockops 격리 / PBFT 3-phase commit verification, rogue worker ejection, prompt injection sanitization, and eBPF sockops isolation |"
    swarmsentry_t3 = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | Raft/PBFT 하이브리드 파이프라인 · Landlock v4 샌드박싱 · Tetragon 0ms SIGKILL · 의사결정 드리프트 센티널 / Raft/PBFT hybrid pipeline, Landlock v4 sandboxing, Tetragon 0ms SIGKILL, and decision drift sentinel |"
    swarmsentry_t4 = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | 제로-릭 기밀 스웜 메시 · 서브마이크로초 BPF-LSM 쉴드 · 100노드 비잔틴 거버넌스 · 스웜 방어 캡스톤 / Zero-leak confidential swarm mesh, sub-microsecond BPF-LSM shield, 100-node Byzantine governance, and swarm defense capstone |"

    if '`weightsec`' not in readme_text:
        readme_text = readme_text.replace(swarmsentry_t0, swarmsentry_t0 + "\n" + tier0_row)
        readme_text = readme_text.replace(swarmsentry_t1, swarmsentry_t1 + "\n" + tier1_row)
        readme_text = readme_text.replace(swarmsentry_t2, swarmsentry_t2 + "\n" + tier2_row)
        readme_text = readme_text.replace(swarmsentry_t3, swarmsentry_t3 + "\n" + tier3_row)
        readme_text = readme_text.replace(swarmsentry_t4, swarmsentry_t4 + "\n" + tier4_row)
        print("[+] Updated wargame/README.md with weightsec rows.")
    readme_path.write_text(readme_text, encoding="utf-8")
    print("[+] Wrote updated wargame/README.md.")

    # 5. Update index.html HUD in wargame/index.html & root index.html (2800 -> 2835)
    for p in [index_html_path, root_index_html_path]:
        if p.exists():
            txt = p.read_text(encoding="utf-8")
            txt = txt.replace("0/2800", "0/2835")
            txt = txt.replace("/2800", "/2835")
            txt = txt.replace("2,800", "2,835")
            txt = txt.replace("2800", "2835")
            p.write_text(txt, encoding="utf-8")
            print(f"[+] Updated HUD counters in {p.name}")

    print("\n🎉 Track 81 weightsec generation completed successfully! Total: 2,835 challenges across 81 tracks.")

if __name__ == "__main__":
    main()
