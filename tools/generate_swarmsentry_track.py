#!/usr/bin/env python3
"""
Generator for Track 80: swarmsentry (Autonomous Multi-Agent Swarm Security & Byzantine Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,800 challenges milestone across 80 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "swarm_architecture_threat_model",
        "title_ko": "자율 멀티에이전트 스웜 아키텍처와 위협 모델",
        "title_en": "Autonomous Multi-Agent Swarm Architecture & Threat Model",
        "desc_ko": "분산 협업 멀티에이전트 시스템에서 오케스트레이터와 워커 간 신뢰 경계 및 위협 표면을 분석합니다.",
        "desc_en": "Analyze trust boundaries and threat surfaces between orchestrators and distributed worker agents in multi-agent swarms."
    },
    {
        "tier": 0, "points": 25, "slug": "agent_identity_spoofing_vectors",
        "title_ko": "사칭 워커 에이전트와 위조된 RPC 등록 위협",
        "title_en": "Rogue Worker Agent Spoofing & RPC Registration Vectors",
        "desc_ko": "악의적 엔터티가 비인가 워커를 스웜 클러스터에 무단 등록하여 의사결정을 왜곡하는 공격 벡터를 학습합니다.",
        "desc_en": "Study rogue agent registration vectors where unauthenticated workers join the cluster to manipulate collective outputs."
    },
    {
        "tier": 0, "points": 25, "slug": "byzantine_consensus_poisoning_theory",
        "title_ko": "분산 스웜 의사결정과 비잔틴 고장 모델",
        "title_en": "Distributed Swarm Decision Quorums & Byzantine Fault Model",
        "desc_ko": "일부 에이전트가 거짓 정보를 고의로 제출할 때 정족수(3f+1)를 유지하여 합의를 보호하는 비잔틴 내성 원리를 검토합니다.",
        "desc_en": "Examine Byzantine fault tolerance mechanisms ensuring swarm consensus despite malicious coordinated worker dissent."
    },
    {
        "tier": 0, "points": 25, "slug": "shared_context_window_memory_risks",
        "title_ko": "공유 컨텍스트 윈도우 및 메모리 버퍼 오염 위험",
        "title_en": "Shared Context Window & Swarm Memory Buffer Poisoning Risks",
        "desc_ko": "에이전트 간 공유되는 프롬프트 컨텍스트 윈도우 및 캐시 메모리가 오염될 때 발생하는 연쇄 오작동을 분석합니다.",
        "desc_en": "Analyze cross-agent context contamination risks where malicious inputs into shared context windows alter swarm behavior."
    },
    {
        "tier": 0, "points": 25, "slug": "cascading_lateral_movement_in_swarms",
        "title_ko": "워커 에이전트 간 연쇄 횡적 이동 위협 표면",
        "title_en": "Cascading Lateral Movement Vectors Across Swarm Nodes",
        "desc_ko": "하나의 워커 에이전트 침해가 로컬 IPC 및 네트워크 메시를 통해 인접 노드로 연쇄 전파되는 경로를 분석합니다.",
        "desc_en": "Examine propagation paths where compromise of a single worker cascades across local IPC and peer mesh networks."
    },
    {
        "tier": 0, "points": 25, "slug": "spiffe_spire_workload_mesh_principles",
        "title_ko": "SPIFFE/SPIRE 기반 에이전트 워크로드 신원 증명 원리",
        "title_en": "SPIFFE/SPIRE Workload Attestation Principles for Agents",
        "desc_ko": "동적으로 스케일링되는 에이전트 프로세스에 암호학적 X.509 SVID를 자동 발급하는 제로트러스트 신원 체계를 학습합니다.",
        "desc_en": "Study automated X.509 SVID issuance and zero-trust workload attestation for ephemeral autonomous agent workers."
    },
    {
        "tier": 0, "points": 25, "slug": "ebpf_lsm_swarm_runtime_containment",
        "title_ko": "eBPF LSM 기반 멀티에이전트 런타임 봉쇄 개요",
        "title_en": "eBPF LSM Multi-Agent Runtime Containment Overview",
        "desc_ko": "커널 레벨에서 비인가 소켓 생성 및 IPC 통신을 실시간 인터셉트하여 사살하는 eBPF 인커널 격리 원리를 검토합니다.",
        "desc_en": "Review kernel-level eBPF interception mechanisms enforcing in-line termination of unauthorized inter-agent sockets."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "x509_mtls_worker_identity_verification",
        "title_ko": "워커 에이전트 X.509 mTLS 상호 인증 및 인증서 핑거프린트 감사",
        "title_en": "Worker Agent X.509 mTLS Mutual Authentication Audit",
        "desc_ko": "스웜 오케스트레이터 연결 시 상호 TLS 핸드셰이크와 클라이언트 인증서 SHA-256 핑거프린트를 정밀 검증합니다.",
        "desc_en": "Audit mutual TLS handshakes and SHA-256 certificate fingerprints on all worker connections to the orchestrator."
    },
    {
        "tier": 1, "points": 50, "slug": "spiffe_id_jwt_svid_cryptographic_audit",
        "title_ko": "SPIFFE ID 및 JWT-SVID 암호학적 서명 유효성 검증",
        "title_en": "SPIFFE ID & JWT-SVID Cryptographic Signature Validation",
        "desc_ko": "에이전트 RPC 페이로드에 동봉된 JWT-SVID 토큰의 OIDC 공개키 서명 및 만료 시간을 감사하여 위조 토큰을 차단합니다.",
        "desc_en": "Validate JWT-SVID cryptographic signatures and expiration timestamps against the SPIRE OIDC keyset."
    },
    {
        "tier": 1, "points": 50, "slug": "byzantine_anomaly_weight_filtering",
        "title_ko": "워커 에이전트 제출 가중치 이상치 탐지 및 초기 격리",
        "title_en": "Worker Weight Anomaly Detection & Outlier Isolation",
        "desc_ko": "스웜 합의 투표에서 표준 편차 3-시그마를 초과하는 비정상 가중치 벡터를 탐지하여 합의 집계에서 배제합니다.",
        "desc_en": "Detect and quarantine statistical outlier votes exceeding 3-sigma variance in distributed consensus rounds."
    },
    {
        "tier": 1, "points": 50, "slug": "unprivileged_landlock_context_snapshot",
        "title_ko": "Linux Landlock LSM을 통한 컨텍스트 읽기 전용 스냅샷 강제",
        "title_en": "Unprivileged Landlock LSM Read-Only Snapshot Enforcement",
        "desc_ko": "루트 권한 없이도 프로세스 스스로 공유 메모리 및 컨텍스트 버퍼를 읽기 전용으로 고정하는 Landlock 정책을 적용합니다.",
        "desc_en": "Enforce unprivileged Landlock LSM rules locking shared context memory regions into immutable read-only states."
    },
    {
        "tier": 1, "points": 50, "slug": "inter_agent_rpc_input_schema_validation",
        "title_ko": "워커 간 RPC 메시지 입력 스키마 및 엄격 타입 검증",
        "title_en": "Inter-Agent RPC Input Schema & Type Strictness Audit",
        "desc_ko": "에이전트 간 통신에 사용되는 JSON-RPC 페이로드의 Pydantic 스키마 무결성을 검증하여 오염 입력을 차단합니다.",
        "desc_en": "Enforce strict Pydantic schema validation on all inter-worker JSON-RPC payloads to reject malformed injections."
    },
    {
        "tier": 1, "points": 50, "slug": "cilium_tetragon_swarm_ipc_tracing",
        "title_ko": "Cilium Tetragon eBPF 시스템콜 추적 정책 수립",
        "title_en": "Cilium Tetragon eBPF IPC Syscall Tracing Policy Setup",
        "desc_ko": "에이전트 프로세스가 호출하는 sys_enter_connect 및 sys_enter_execve 이벤트를 실시간 로깅하는 정책을 구성합니다.",
        "desc_en": "Deploy Tetragon TracingPolicy catching sys_enter_connect and execve syscalls initiated by agent processes."
    },
    {
        "tier": 1, "points": 50, "slug": "ephemeral_swarm_session_token_rotation",
        "title_ko": "30초 단위 스웜 워커 기능 토큰 암호학적 회전",
        "title_en": "30-Second Ephemeral Swarm Capability Token Rotation",
        "desc_ko": "워커 에이전트의 도구 실행 토큰 수명을 30초로 제한하고 HMAC 기반으로 자동 갱신하여 탈취 토큰의 재사용을 차단합니다.",
        "desc_en": "Rotate ephemeral worker tool capability tokens every 30 seconds via HMAC derivation to prevent token replay."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "pbft_three_phase_commit_verification",
        "title_ko": "PBFT Pre-Prepare/Prepare/Commit 3단계 합의 검증",
        "title_en": "PBFT Three-Phase Commit Protocol Verification",
        "desc_ko": "스웜 리더의 제안(Pre-Prepare)과 워커들의 2/3 다수결 검증(Prepare/Commit) 상태 전이를 정밀 검증합니다.",
        "desc_en": "Formally verify PBFT state transitions across Pre-Prepare, Prepare, and Commit phases requiring 2/3 quorum confirmation."
    },
    {
        "tier": 2, "points": 100, "slug": "rogue_worker_ejection_and_revocation",
        "title_ko": "이상 행동 워커 에이전트 즉시 축출 및 인증서 폐기",
        "title_en": "Rogue Worker Ejection & Certificate Revocation Pipeline",
        "desc_ko": "비정상 응답을 반복하는 워커의 세션을 즉시 종료하고 클러스터 CRL에 등재하여 재접속을 차단합니다.",
        "desc_en": "Automate instant session termination and CRL revocation for workers demonstrating malicious or anomalous voting."
    },
    {
        "tier": 2, "points": 100, "slug": "cross_agent_prompt_injection_sanitization",
        "title_ko": "에이전트 간 메시지 전달 시 간접 프롬프트 주입 살균",
        "title_en": "Cross-Agent Prompt Injection Dual-Pass Sanitization",
        "desc_ko": "선행 에이전트의 출력이 후속 에이전트의 시스템 지시사항을 무력화하지 못하도록 가드레일 필터를 적용합니다.",
        "desc_en": "Implement dual-pass sanitization stripping indirect injection payloads from upstream agent completions."
    },
    {
        "tier": 2, "points": 100, "slug": "ebpf_sockops_zero_trust_mesh_enforcement",
        "title_ko": "eBPF sockops 기반 소켓 레벨 제로 트러스트 메시 강제",
        "title_en": "eBPF sockops Socket-Level Zero Trust Mesh Enforcement",
        "desc_ko": "커널 소켓 계층에서 BPF sock_ops 프로그램을 실행하여 승인된 워커 간 포트 통신만을 허용합니다.",
        "desc_en": "Run kernel-level BPF sock_ops programs restricting TCP connections strictly to approved peer port pairs."
    },
    {
        "tier": 2, "points": 100, "slug": "isolated_worker_memory_namespaces",
        "title_ko": "개별 워커 에이전트 전용 휘발성 메모리 네임스페이스 분리",
        "title_en": "Isolated Worker Volatile Memory Namespace Partitioning",
        "desc_ko": "각 워커 에이전트가 다른 워커의 중간 추론 텐서나 API 토큰을 읽을 수 없도록 프로세스 네임스페이스를 분리합니다.",
        "desc_en": "Partition Linux process and IPC namespaces ensuring workers cannot access peer memory buffers or token caches."
    },
    {
        "tier": 2, "points": 100, "slug": "distributed_byzantine_fault_injection_test",
        "title_ko": "비잔틴 고장 주입 시뮬레이션을 통한 쿼럼 안정성 검증",
        "title_en": "Distributed Byzantine Fault Injection & Quorum Stability Test",
        "desc_ko": "f개의 악의적 노드가 임의의 거짓 투표를 제출하는 시나리오에서 스웜 전체의 합의 무결성을 스트레스 테스트합니다.",
        "desc_en": "Stress-test swarm consensus stability under active Byzantine fault injection where f out of 3f+1 nodes act maliciously."
    },
    {
        "tier": 2, "points": 100, "slug": "cryptographic_audit_ledger_for_agent_actions",
        "title_ko": "스웜 에이전트 실행 내역 암호학적 감사 원장 기록",
        "title_en": "Cryptographic Audit Ledger for Swarm Agent Executions",
        "desc_ko": "모든 워커의 도구 호출 및 결정 내역을 해시 체인 머클 트리 구조로 직렬화하여 부인 방지를 보장합니다.",
        "desc_en": "Serialize agent tool invocations and voting outcomes into a cryptographic Merkle-hashed audit log for non-repudiation."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "raft_pbft_hybrid_fault_tolerance_pipeline",
        "title_ko": "Raft/PBFT 하이브리드 고장 감내 합의 파이프라인",
        "title_en": "Raft/PBFT Hybrid Fault-Tolerant Consensus Pipeline",
        "desc_ko": "고속 로그 복제(Raft)와 비잔틴 방어(PBFT)를 계층적으로 결합하여 처리량과 보안성을 동시에 확보합니다.",
        "desc_en": "Architect a tiered consensus pipeline pairing Raft high-throughput log replication with PBFT Byzantine validation."
    },
    {
        "tier": 3, "points": 200, "slug": "landlock_abi_v4_file_and_network_sandboxing",
        "title_ko": "Landlock ABI v4 기반 파일 및 네트워크 소켓 샌드박싱",
        "title_en": "Landlock ABI v4 File & Network Socket Sandboxing",
        "desc_ko": "최신 Linux 6.7+ Landlock ABI v4 규칙을 적용하여 파일시스템과 TCP 바인드/연결을 프로세스 레벨에서 완벽 격리합니다.",
        "desc_en": "Deploy Linux Landlock ABI v4 rules restricting filesystem write access and outbound TCP socket bindings."
    },
    {
        "tier": 3, "points": 200, "slug": "tetragon_sigkill_on_unauthorized_ipc",
        "title_ko": "비인가 워커 간 IPC 연결 시 Tetragon 0ms SIGKILL 즉시 사살",
        "title_en": "Tetragon In-Kernel 0ms SIGKILL on Unauthorized IPC",
        "desc_ko": "격리 정책을 우회하여 로컬 도메인 소켓 연결을 시도하는 프로세스를 Tetragon 인커널 액션으로 즉각 종료합니다.",
        "desc_en": "Configure in-kernel Tetragon actions delivering instantaneous SIGKILL upon unauthorized AF_UNIX socket connections."
    },
    {
        "tier": 3, "points": 200, "slug": "model_decision_drift_statistical_sentinel",
        "title_ko": "다중 에이전트 추론 결과 통계적 드리프트 탐지 센티널",
        "title_en": "Model Decision Drift Statistical Sentinel",
        "desc_ko": "워커 에이전트들의 추론 편향 및 은닉된 탈옥 시도를 엔트로피와 코사인 유사도 분석으로 실시간 감시합니다.",
        "desc_en": "Monitor entropy and cosine similarity distributions across agent completions to catch stealthy jailbreak drift."
    },
    {
        "tier": 3, "points": 200, "slug": "spire_agent_tpm_quote_live_attestation",
        "title_ko": "물리 TPM Quote 기반 SPIRE 에이전트 라이브 원격 증명",
        "title_en": "Physical TPM Quote Live Remote Attestation for SPIRE",
        "desc_ko": "호스트 하드웨어 TPM 2.0 PCR 측정치를 SPIRE 서버에 제출하여 하드웨어 신뢰점 기반 SVID를 발급받습니다.",
        "desc_en": "Submit hardware TPM 2.0 PCR quotes to SPIRE servers verifying physical node integrity prior to SVID issuance."
    },
    {
        "tier": 3, "points": 200, "slug": "swarm_consensus_rollback_and_state_recovery",
        "title_ko": "오염된 합의 상태의 암호학적 롤백 및 상태 복구",
        "title_en": "Swarm Consensus Cryptographic Rollback & State Recovery",
        "desc_ko": "비잔틴 공격으로 오염된 스웜 상태를 마지막 검증된 암호학적 체크포인트로 안전하게 롤백하고 재합의를 유도합니다.",
        "desc_en": "Execute state rollbacks to cryptographically signed checkpoints when consensus poisoning is detected post-facto."
    },
    {
        "tier": 3, "points": 200, "slug": "post_quantum_mTLS_for_swarm_mesh",
        "title_ko": "ML-KEM-768 기반 양자 내성 하이브리드 스웜 mTLS 통신",
        "title_en": "ML-KEM-768 Post-Quantum Hybrid mTLS for Swarm Mesh",
        "desc_ko": "에이전트 간 통신에 FIPS 203 ML-KEM-768 키 교환을 적용하여 미래의 양자 컴퓨터 도청 공격에 대비합니다.",
        "desc_en": "Deploy FIPS 203 ML-KEM-768 post-quantum hybrid key exchange protecting inter-agent communication against harvest-now attacks."
    },

    # Tier 4 (7 challenges, 400 points each)
    {
        "tier": 4, "points": 400, "slug": "zero_leak_multi_agent_confidential_mesh",
        "title_ko": "제로-릭 멀티에이전트 기밀 컴퓨팅 메시 아키텍처",
        "title_en": "Zero-Leak Multi-Agent Confidential Computing Mesh",
        "desc_ko": "모든 워커 에이전트가 개별 TEE 엔클레이브 내에서 구동되며 엔드투엔드 암호화된 메시로만 협업하는 설계를 완성합니다.",
        "desc_en": "Engineer an end-to-end confidential mesh where every swarm agent executes inside dedicated hardware TEE enclaves."
    },
    {
        "tier": 4, "points": 400, "slug": "sub_microsecond_tetragon_bpf_lsm_shield",
        "title_ko": "서브마이크로초 Tetragon BPF-LSM 커널 방어 쉴드",
        "title_en": "Sub-Microsecond Tetragon BPF-LSM Kernel Defense Shield",
        "desc_ko": "커널 레벨 BPF-LSM 훅을 활용하여 비인가 에이전트 프로세스 생성을 서브마이크로초 단위로 사전 차단합니다.",
        "desc_en": "Enforce sub-microsecond pre-execution blocking of unvetted agent binaries via kernel-level BPF-LSM hooks."
    },
    {
        "tier": 4, "points": 400, "slug": "byzantine_resilient_distributed_governance",
        "title_ko": "100 노드 규모 분산 비잔틴 내성 합의 거버넌스",
        "title_en": "100-Node Byzantine-Resilient Distributed Swarm Governance",
        "desc_ko": "100개 이상의 자율 에이전트가 참여하는 대규모 클러스터에서 33%의 악의적 노드 공격을 방어하는 거버넌스를 구축합니다.",
        "desc_en": "Deploy resilient consensus governance maintaining 99.99% decision integrity across 100+ distributed worker nodes."
    },
    {
        "tier": 4, "points": 400, "slug": "cross_cloud_autonomous_agent_zero_trust",
        "title_ko": "멀티클라우드 자율 에이전트 스웜 제로 트러스트 연계",
        "title_en": "Cross-Cloud Autonomous Agent Swarm Zero Trust Federation",
        "desc_ko": "AWS, GCP, 온프레미스에 분산된 에이전트 클러스터 간 신원을 SPIFFE Federation과 mTLS로 통합 관리합니다.",
        "desc_en": "Federate multi-cloud agent swarms across AWS, GCP, and on-premises using SPIFFE multi-trust domain federation."
    },
    {
        "tier": 4, "points": 400, "slug": "tamper_evident_blockchain_swarm_ledger",
        "title_ko": "변조 방지 블록체인 기반 스웜 의사결정 원장",
        "title_en": "Tamper-Evident Blockchain Swarm Decision Ledger",
        "desc_ko": "스웜이 내린 주요 보안 의사결정을 분산 불변 원장에 실시간 기록하여 사후 포렌식 및 무결성을 완벽 보장합니다.",
        "desc_en": "Anchor critical swarm orchestrator policy updates and worker outputs into an immutable distributed ledger."
    },
    {
        "tier": 4, "points": 400, "slug": "autonomous_ai_security_agent_adversarial_drill",
        "title_ko": "자율 AI 보안 에이전트 간 적대적 공방전 훈련",
        "title_en": "Autonomous AI Security Agent Adversarial Drill",
        "desc_ko": "공격 에이전트 스웜(Red Swarm)과 방어 에이전트 스웜(Blue Swarm)이 자율적으로 공방전을 수행하는 모의 훈련을 집행합니다.",
        "desc_en": "Execute autonomous multi-agent cyber battle drills pitting autonomous red swarms against blue defense swarms."
    },
    {
        "tier": 4, "points": 400, "slug": "capstone_full_spectrum_swarm_defense",
        "title_ko": "80개 트랙 통합 자율 에이전트 스웜 방어 캡스톤",
        "title_en": "Capstone: Full-Spectrum Autonomous Swarm Defense",
        "desc_ko": "신원 인증, 비잔틴 합의, Landlock 메모리 격리, eBPF 사살, TEE 기밀 연계를 총망라한 엔터프라이즈 스웜 방어를 완성합니다.",
        "desc_en": "Synthesize mTLS identity, PBFT consensus, Landlock isolation, eBPF Tetragon containment, and TEE mesh defense."
    }
]

def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = repo_root / "wargame" / "README.md"
    index_html_path = repo_root / "wargame" / "index.html"
    root_index_html_path = repo_root / "index.html"

    print("=== Generating Track 80: swarmsentry (35 challenges, Total 2,800 milestone) ===")

    # 1. Prepare new challenges with zero-defect deterministic flags
    new_challenges = []
    for cdata in CHALLENGES_DATA:
        cid = f"t{cdata['tier']}_swarmsentry_{cdata['slug']}"
        flag_hash = hashlib.sha256(f"{cid}_vibe_swarmsentry_2026".encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{flag_hash}}}"
        ch_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        prompt_ko = (
            f"분산 자율 에이전트 스웜 및 비잔틴 고장 방어 실무를 수행합니다.\n\n"
            f"주제: {cdata['title_ko']}\n"
            f"상세 분석 지침:\n"
            f"- {cdata['desc_ko']}\n"
            f"- 스웜 오케스트레이터 및 워커 에이전트의 신원과 권한을 정밀 감사하십시오.\n"
            f"- 검증 식별자 SWARMSENTRY_CHALLENGE_ID: `{cid}`\n"
            f"- 보안 정책 및 합의 쿼럼을 충족하여 정상 플래그를 획득하십시오."
        )

        prompt_en = (
            f"Conduct technical hands-on verification of autonomous agent swarm and Byzantine defense.\n\n"
            f"Topic: {cdata['title_en']}\n"
            f"Analysis Requirements:\n"
            f"- {cdata['desc_en']}\n"
            f"- Thoroughly audit identity, memory, and consensus controls across the swarm.\n"
            f"- Verification Identifier SWARMSENTRY_CHALLENGE_ID: `{cid}`\n"
            f"- Satisfy the security parameters and retrieve the authorized flag."
        )

        ch = {
            "id": cid,
            "tier": cdata["tier"],
            "cat": "ai",
            "track": "swarmsentry",
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

    print(f"[+] Prepared {len(new_challenges)} challenges for Track 80 (swarmsentry).")

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")

    # Check if TRACK 80 already in TRACKS
    if '"id": "swarmsentry"' in content:
        print("[-] Track 80 (swarmsentry) already in TRACKS.")
    else:
        track_entry = """,
  {
    "id": "swarmsentry",
    "icon": "🐝",
    "ko": "자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어",
    "en": "Autonomous Multi-Agent Swarm Security & Byzantine Defense",
    "desc_ko": "사칭 워커 에이전트 등록 차단·X.509 mTLS/SPIFFE ID 상호 인증·PBFT 비잔틴 합의 오염 방어·Landlock LSM 공유 메모리 격리·Cilium Tetragon eBPF 0ms SIGKILL 즉시 사살.",
    "desc_en": "Rogue worker agent registration denial, X.509 mTLS/SPIFFE ID mutual authentication, PBFT Byzantine consensus defense, Landlock LSM shared memory isolation, and Cilium Tetragon eBPF 0ms SIGKILL containment."
  }"""
        teeai_track_needle = '    "id": "teeai",\n    "icon": "🔒",\n    "ko": "기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명",\n    "en": "Confidential AI & Hardware TEE Enclave Attestation",\n    "desc_ko": "AMD SEV-SNP/Intel TDX 하드웨어 TEE 원격 증명·VCEK 인증서 체인 및 PCR0 무결성·엔클레이브 내 AES-256-XTS 가중치 복호화·Flush+Reload 캐시 타이밍 부채널 방어·TPM AIK 암호학적 서명.",\n    "desc_en": "AMD SEV-SNP/Intel TDX hardware TEE remote attestation, VCEK certificate chain and PCR0 measurement integrity, in-enclave AES-256-XTS weight sealing, Flush+Reload cache timing side-channel mitigation, and TPM AIK cryptographic signatures."\n  }\n];'
        
        if teeai_track_needle in content:
            replacement = teeai_track_needle[:-3] + track_entry + "\n];"
            content = content.replace(teeai_track_needle, replacement, 1)
            print("[+] Inserted Track 80 definition into TRACKS.")
        else:
            m = re.search(r'("id":\s*"teeai"[\s\S]*?\n  }\n)(];)', content)
            assert m, "Could not locate teeai track in TRACKS array"
            content = content[:m.end(1)] + track_entry + "\n" + content[m.start(2):]
            print("[+] Inserted Track 80 definition into TRACKS via regex.")

    # Check if challenges already present
    existing_cids = set(re.findall(r'"id":\s*"(t\d_swarmsentry_[^"]+)"', content))
    if existing_cids:
        print(f"[*] Removing {len(existing_cids)} old swarmsentry challenges from challenges.js...")
        m_start = re.search(r',\s*\{\s*"id":\s*"t0_swarmsentry_[^"]+"', content)
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
    print("[+] Appended 35 swarmsentry challenges to CHALLENGES array with proper hints object.")

    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Wrote updated {challenges_js_path}")

    # 3. Update solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    swarmsentry_ids = [ch["id"] for ch in new_challenges]
    ids_js = ",\n  ".join([f'"{cid}"' for cid in swarmsentry_ids])
    derivable_code = f"""const SWARMSENTRY_IDS = [
  {ids_js}
];

for (const id of SWARMSENTRY_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/SWARMSENTRY_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_swarmsentry_2026').digest('hex').slice(0, 20);
      return `FLAG{${{hash}}}`;
    }}
  }});
}}
"""
    if "const SWARMSENTRY_IDS = [" in solve_content:
        solve_content = re.sub(r'const SWARMSENTRY_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing SWARMSENTRY_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added swarmsentry derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update wargame/README.md
    readme_text = readme_path.read_text(encoding="utf-8")
    readme_text = readme_text.replace("총 2765문제", "총 2800문제")
    readme_text = readme_text.replace("총 **2765문제**", "총 **2800문제**")
    readme_text = readme_text.replace("79개 트랙", "80개 트랙")
    readme_text = readme_text.replace("79개 섹션", "80개 섹션")
    readme_text = readme_text.replace("Total **2765 challenges**", "Total **2800 challenges**")

    # Update tier counts table
    readme_text = readme_text.replace("| `perimeter` 외곽 | **0** | 308 |", "| `perimeter` 외곽 | **0** | 315 |")
    readme_text = readme_text.replace("| `webserver` 웹서버 | **1** | 517 |", "| `webserver` 웹서버 | **1** | 524 |")
    readme_text = readme_text.replace("| `internal` 내부망 | **2** | 669 |", "| `internal` 내부망 | **2** | 676 |")
    readme_text = readme_text.replace("| `vault` 금고 | **3** | 659 |", "| `vault` 금고 | **3** | 666 |")
    readme_text = readme_text.replace("| `core` 코어 | **4** | 612 |", "| `core` 코어 | **4** | 619 |")

    # Update English summary list
    old_en_tail = "AI agent sandbox escape & supply chain security 35 · confidential AI & hardware TEE attestation 35); each maps to a topic from the [main repo](../README.md)'s 79 sections."
    new_en_tail = "AI agent sandbox escape & supply chain security 35 · confidential AI & hardware TEE attestation 35 · autonomous multi-agent swarm security & Byzantine defense 35); each maps to a topic from the [main repo](../README.md)'s 80 tracks."
    readme_text = readme_text.replace(old_en_tail, new_en_tail)

    tier0_row = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | 스웜 위협 모델 · 사칭 워커 등록 위협 · 비잔틴 합의 이론 · 공유 메모리 위험 / Swarm threat model, rogue worker spoofing, Byzantine consensus theory, and shared memory risks |"
    tier1_row = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | X.509 mTLS 상호 인증 감사 · JWT-SVID 서명 검증 · 이상 가중치 필터링 · Landlock 스냅샷 / X.509 mTLS mutual auth audit, JWT-SVID signature validation, anomaly weight filtering, and Landlock snapshots |"
    tier2_row = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | PBFT 3단계 합의 검증 · 워커 즉시 축출 · 간접 프롬프트 주입 살균 · eBPF sockops 격리 / PBFT 3-phase commit verification, rogue worker ejection, prompt injection sanitization, and eBPF sockops isolation |"
    tier3_row = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | Raft/PBFT 하이브리드 파이프라인 · Landlock v4 샌드박싱 · Tetragon 0ms SIGKILL · 의사결정 드리프트 센티널 / Raft/PBFT hybrid pipeline, Landlock v4 sandboxing, Tetragon 0ms SIGKILL, and decision drift sentinel |"
    tier4_row = "| `swarmsentry` 🐝 자율 멀티에이전트 스웜 침투 & 비잔틴 분산 방어 (7) | 제로-릭 기밀 스웜 메시 · 서브마이크로초 BPF-LSM 쉴드 · 100노드 비잔틴 거버넌스 · 스웜 방어 캡스톤 / Zero-leak confidential swarm mesh, sub-microsecond BPF-LSM shield, 100-node Byzantine governance, and swarm defense capstone |"

    teeai_t0 = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | TEE 위협 모델 · 하드웨어 격리 아키텍처 · 원격 증명 PCR0 원리 · 가중치 보호 모델 / TEE threat model, hardware isolation architecture, remote attestation PCR0 principles, and weight protection model |"
    teeai_t1 = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | VCEK 인증서 체인 감사 · TDX Quote 생성 검증 · AES 메모리 암호화 감사 · KDF 가중치 복호화 / VCEK certificate chain audit, TDX quote validation, AES memory encryption audit, and KDF weight decryption |"
    teeai_t2 = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | Flush+Reload 부채널 차단 · Prime+Probe 캐시 감시 · 페이지 폴트 추적 방어 · 종단간 ECDH 교환 / Flush+Reload side-channel mitigation, Prime+Probe cache monitoring, page fault tracking defense, and end-to-end ECDH exchange |"
    teeai_t3 = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | 상수시간 GEMM 하드닝 · ORAM 메모리 접근 은닉 · TDX SEPT 위반 트랩 · 30초 세션키 롤오버 / Constant-time GEMM hardening, ORAM memory access shuffling, TDX SEPT violation trapping, and 30s session key rollover |"
    teeai_t4 = "| `teeai` 🔒 기밀 AI & 하드웨어 TEE 엔클레이브 원격 증명 (7) | 제로-릭 GPU 파이프라인 · 서브나노초 타이밍 지터 · 물리 TPM 롤링 검증 · 기밀 AI TEE 방어 캡스톤 / Zero-leak GPU pipeline, sub-nanosecond timing jitter, physical TPM rolling audit, and confidential AI TEE defense capstone |"

    if '`swarmsentry`' not in readme_text:
        readme_text = readme_text.replace(teeai_t0, teeai_t0 + "\n" + tier0_row)
        readme_text = readme_text.replace(teeai_t1, teeai_t1 + "\n" + tier1_row)
        readme_text = readme_text.replace(teeai_t2, teeai_t2 + "\n" + tier2_row)
        readme_text = readme_text.replace(teeai_t3, teeai_t3 + "\n" + tier3_row)
        readme_text = readme_text.replace(teeai_t4, teeai_t4 + "\n" + tier4_row)
        print("[+] Updated wargame/README.md with swarmsentry rows.")
    readme_path.write_text(readme_text, encoding="utf-8")
    print("[+] Wrote updated wargame/README.md.")

    # 5. Update index.html HUD in wargame/index.html & root index.html (2765 -> 2800)
    for p in [index_html_path, root_index_html_path]:
        if p.exists():
            txt = p.read_text(encoding="utf-8")
            txt = txt.replace("0/2765", "0/2800")
            txt = txt.replace("/2765", "/2800")
            txt = txt.replace("2,765", "2,800")
            txt = txt.replace("2765", "2800")
            p.write_text(txt, encoding="utf-8")
            print(f"[+] Updated HUD counters in {p.name}")

    print("\n🎉 Track 80 swarmsentry generation completed successfully! Total: 2,800 challenges across 80 tracks.")

if __name__ == "__main__":
    main()
