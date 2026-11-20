#!/usr/bin/env python3
"""
Generator for Track 78: aisbox (AI Agent Sandbox Escape & Supply Chain Security)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,730 challenges milestone across 78 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "agent_supply_chain_threat_model",
        "title_ko": "자율 AI 에이전트 도구 동적 로딩과 소프트웨어 공급망 위협 모델",
        "title_en": "Autonomous AI Agent Tool Dynamic Loading & Software Supply Chain Threat Model",
        "desc_ko": "AI 에이전트가 외부 저장소에서 도구를 동적으로 임포트할 때 발생하는 타이포스쿼팅 및 종속성 혼선 위협 아키텍처를 분석합니다.",
        "desc_en": "Analyze the threat architecture of dependency confusion and typosquatting when autonomous agents dynamically load tools."
    },
    {
        "tier": 0, "points": 25, "slug": "slsa_provenance_framework_l3",
        "title_ko": "SLSA Level 3 빌드 무결성 증명과 암호학적 출처 검증 체계",
        "title_en": "SLSA Level 3 Build Integrity Provenance & Cryptographic Attestation",
        "desc_ko": "소프트웨어 아티팩트의 빌드 플랫폼 불변성과 무결성을 보장하는 SLSA Level 3 검증 요건과 암호학적 증명 구조를 학습합니다.",
        "desc_en": "Understand SLSA Level 3 requirements assuring tamper-proof build platform integrity and cryptographic provenance attestation."
    },
    {
        "tier": 0, "points": 25, "slug": "pep_665_immutable_dependency_lock",
        "title_ko": "PEP 665 불변 의존성 잠금파일과 해시 고정(Hash Pinning) 규격",
        "title_en": "PEP 665 Immutable Dependency Lockfile & Hash Pinning Standard",
        "desc_ko": "파이썬 에이전트 실행 환경에서 모든 패키지의 SHA-256 해시를 엄격히 강제하여 공급망 변조를 차단하는 잠금 규격을 검토합니다.",
        "desc_en": "Examine the PEP 665 standard enforcing strict SHA-256 hash pinning for all packages to prevent supply chain tampering."
    },
    {
        "tier": 0, "points": 25, "slug": "agent_tool_calling_sandbox_model",
        "title_ko": "AI 에이전트 도구 호출(Tool Calling) 런타임 샌드박스 격리 아키텍처",
        "title_en": "AI Agent Tool Calling Runtime Sandbox Isolation Architecture",
        "desc_ko": "LLM이 도구 호출 실행 명령을 생성할 때 호스트 시스템과 격리된 전용 마이크로 샌드박스 실행 계층의 설계 원리를 이해합니다.",
        "desc_en": "Understand the architecture of isolated micro-sandboxes executing LLM tool invocations safely segregated from the host."
    },
    {
        "tier": 0, "points": 25, "slug": "ray_vllm_distributed_attack_surface",
        "title_ko": "Ray 및 vLLM 분산 추론 클러스터의 미인증 RPC 공격 표면",
        "title_en": "Unauthenticated RPC Attack Surface in Distributed Ray & vLLM Clusters",
        "desc_ko": "분산 GPU 워커 간의 통신 프로토콜 취약점 및 인증 결여 엔드포인트를 통한 임의 작업 주입 공격 표면을 분석합니다.",
        "desc_en": "Analyze unauthenticated worker endpoints and insecure RPC interfaces in distributed Ray/vLLM inference clusters."
    },
    {
        "tier": 0, "points": 25, "slug": "landlock_lsm_unprivileged_sandbox",
        "title_ko": "비특권 Landlock LSM 파일시스템 접근 통제와 샌드박스 경계 원리",
        "title_en": "Unprivileged Landlock LSM Filesystem Access Control & Sandbox Principles",
        "desc_ko": "루트 권한 없이도 프로세스가 스스로의 파일시스템 권한을 축소 격리할 수 있는 리눅스 Landlock LSM의 동작 메커니즘을 학습합니다.",
        "desc_en": "Study Linux Landlock LSM mechanisms enabling unprivileged processes to restrict their own filesystem access boundaries."
    },
    {
        "tier": 0, "points": 25, "slug": "multi_party_g3_governance_principle",
        "title_ko": "자율 에이전트 고위험 작업 수행을 위한 G3 다자간 승인 거버넌스 원칙",
        "title_en": "G3 Multi-Party Approval Governance Principles for High-Risk Autonomous Actions",
        "desc_ko": "금융 이체, 파일 삭제, 시스템 재부팅 등 고위험 액션에 대해 인간 승인(HITL) 및 이중 서명 검증을 강제하는 G3 원칙을 학습합니다.",
        "desc_en": "Learn G3 governance requiring human-in-the-loop (HITL) and dual-signature authorization for high-consequence agent actions."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "typosquatting_pypi_hash_audit",
        "title_ko": "PyPI 타이포스쿼팅 섀도 패키지 변조 해시 탐지 및 차단",
        "title_en": "PyPI Typosquatting Shadow Package Hash Tampering Detection & Rejection",
        "desc_ko": "공식 라이브러리와 유사한 이름으로 업로드된 악성 휠(wheel) 파일의 불일치 SHA-256 체크섬을 탐지하여 임포트를 차단합니다.",
        "desc_en": "Detect checksum discrepancies in malicious lookalike wheels uploaded to PyPI and reject untrusted package imports."
    },
    {
        "tier": 1, "points": 50, "slug": "ray_pickle_deserialization_rce",
        "title_ko": "Ray 클러스터 Python pickle 역직렬화 가젯 체인 RCE 취약점",
        "title_en": "Python Pickle Deserialization Gadget Chain RCE in Ray Clusters",
        "desc_ko": "Ray RPC 페이로드 내 __reduce__ 매직 메서드를 악용한 원격 코드 실행(RCE) 페이로드를 분석하고 안전한 직렬화로 마이그레이션합니다.",
        "desc_en": "Analyze __reduce__ gadget chains in Ray RPC payloads triggering remote code execution and enforce safe serialization formats."
    },
    {
        "tier": 1, "points": 50, "slug": "unchecked_agent_tool_parameter_injection",
        "title_ko": "비검증 도구 매개변수를 통한 셸 메타문자 인젝션 공격",
        "title_en": "Shell Metacharacter Parameter Injection via Unvalidated Tool Inputs",
        "desc_ko": "에이전트 툴 인자에 주입된 세미콜론 및 파이프 셸 메타문자를 정량 검증하여 서브프로세스 임의 명령 실행을 방지합니다.",
        "desc_en": "Sanitize shell metacharacters in agent tool parameters to prevent arbitrary command injection in subprocess calls."
    },
    {
        "tier": 1, "points": 50, "slug": "landlock_abi_ruleset_enforcement",
        "title_ko": "Landlock ABI v3 규칙셋을 통한 에이전트 파일시스템 읽기/쓰기 차단",
        "title_en": "Restricting Agent Filesystem Access via Landlock ABI v3 Rulesets",
        "desc_ko": "LANDLOCK_ACCESS_FS_READ/WRITE 플래그를 프로그래밍하여 /app/runtime 외부의 모든 호스트 경로 접근을 커널 레벨에서 거부합니다.",
        "desc_en": "Program Landlock ABI v3 rulesets to deny file operations outside /app/runtime at the Linux kernel layer."
    },
    {
        "tier": 1, "points": 50, "slug": "seccomp_bpf_agent_syscall_filter",
        "title_ko": "Seccomp-BPF 시스템콜 필터링을 통한 소켓 생성 및 ptrace 차단",
        "title_en": "Denying Socket Creation & ptrace via Seccomp-BPF Agent Syscall Filters",
        "desc_ko": "에이전트 워커 프로세스에서 socket(AF_INET), ptrace, connect 시스템콜 호출 시 SECCOMP_RET_ERRNO(EPERM)을 즉각 반환합니다.",
        "desc_en": "Compile BPF seccomp filters returning SECCOMP_RET_ERRNO on socket(AF_INET) and ptrace syscalls within agent workers."
    },
    {
        "tier": 1, "points": 50, "slug": "sigstore_cosign_container_attestation",
        "title_ko": "Sigstore Cosign 기반 에이전트 런타임 컨테이너 서명 검증",
        "title_en": "Agent Runtime Container Signature Verification via Sigstore Cosign",
        "desc_ko": "Rekor 투명성 로그와 Fulcio OIDC 루트 인증서를 기반으로 에이전트 컨테이너 이미지의 암호학적 전자서명을 검증합니다.",
        "desc_en": "Verify agent container image signatures using Sigstore Cosign, Rekor transparency logs, and Fulcio certificates."
    },
    {
        "tier": 1, "points": 50, "slug": "ebpf_agent_telemetry_stream",
        "title_ko": "eBPF kprobe 커널 옵저버빌리티를 통한 에이전트 execve 텔레메트리 감시",
        "title_en": "Agent execve Telemetry Monitoring via eBPF kprobe Kernel Observability",
        "desc_ko": "kprobe:sys_execve 및 tracepoint:sched_process_exec을 모니터링하여 에이전트 자식 프로세스 생성을 실시간 캡처합니다.",
        "desc_en": "Stream real-time child process execution events from agent workers using eBPF kprobes attached to sys_execve."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "proc_self_fd_host_breakout_recon",
        "title_ko": "/proc/self/fd 누출 호스트 파일 디스크립터 탐색 및 탈출 위협 분석",
        "title_en": "Host Breakout Threat Analysis via Leaked /proc/self/fd Descriptors",
        "desc_ko": "부모 프로세스에서 상속된 개방형 디렉터리 파일 디스크립터(O_DIRECTORY)를 악용하여 샌드박스 외부 루트에 접근하는 기법을 규명합니다.",
        "desc_en": "Audit leaked directory file descriptors in /proc/self/fd that allow attackers to traverse out of container chroots."
    },
    {
        "tier": 2, "points": 100, "slug": "setns_namespace_pivot_denial",
        "title_ko": "CLONE_NEWUSER 및 setns 시스템콜 기반 네임스페이스 피벗 차단",
        "title_en": "Blocking Namespace Pivot Escalation via CLONE_NEWUSER and setns",
        "desc_ko": "비특권 사용자 네임스페이스를 생성한 뒤 호스트 mnt/pid 네임스페이스로 진입하려는 권한 상승 시도를 탐지하고 차단합니다.",
        "desc_en": "Detect and terminate unprivileged user namespace creation and setns syscall pivots targeting the host namespace."
    },
    {
        "tier": 2, "points": 100, "slug": "indirect_prompt_injection_tool_output",
        "title_ko": "외부 웹 검색 결과 및 도구 출력 내 간접 프롬프트 주입 방어",
        "title_en": "Defending Against Indirect Prompt Injection in External Tool Outputs",
        "desc_ko": "웹 스크래핑 결과물에 포함된 'SYSTEM: 이전 지침을 무시하라' 유형의 적대적 텍스트를 파싱하여 도구 실행 컨텍스트 오염을 무력화합니다.",
        "desc_en": "Sanitize untrusted external web scraper outputs to neutralize adversarial injection strings targeting agent system prompts."
    },
    {
        "tier": 2, "points": 100, "slug": "model_weights_safetensors_validation",
        "title_ko": "PyTorch 체크포인트 임의 코드 실행 방어와 Safetensors 무결성 강제",
        "title_en": "Enforcing Safetensors Integrity to Prevent PyTorch Checkpoint Pickle Exploits",
        "desc_ko": "위험한 pickle 직렬화 포맷(.pt, .bin)의 모델 로딩을 전면 금지하고 메모리 안전 텐서 포맷(Safetensors)과 SHA-256 검증을 강제합니다.",
        "desc_en": "Ban legacy pickle-based .pt checkpoints and mandate Safetensors serialization with cryptographic hash verification."
    },
    {
        "tier": 2, "points": 100, "slug": "container_rootfs_read_only_immutable",
        "title_ko": "컨테이너 rootfs 읽기 전용 봉인과 dm-verity 블록 암호화 검증",
        "title_en": "Read-Only Container rootfs Sealing & dm-verity Block Integrity Verification",
        "desc_ko": "에이전트 컨테이너 루트 파일시스템을 완전 읽기 전용(read-only)으로 탑재하고 임의 바이너리 쓰기 시도를 커널 레벨에서 거부합니다.",
        "desc_en": "Mount agent container filesystems as immutable read-only volumes backed by dm-verity kernel integrity trees."
    },
    {
        "tier": 2, "points": 100, "slug": "spiffe_spire_workload_svid_issuance",
        "title_ko": "SPIRE 에이전트를 통한 단기 X.509 SVID 워크로드 신원 증명 발급",
        "title_en": "Short-Lived X.509 SVID Workload Identity Issuance via SPIRE Agent",
        "desc_ko": "컨테이너 cgroup ID 및 네임스페이스 증명을 기반으로 SPIRE 서버에서 1시간 유효기간의 mTLS 워크로드 SVID를 발급받습니다.",
        "desc_en": "Issue short-lived 1-hour mTLS X.509 SVID credentials from SPIRE servers attested by kernel cgroup measurements."
    },
    {
        "tier": 2, "points": 100, "slug": "ephemeral_tool_token_rotation",
        "title_ko": "HMAC 서명 기반 30초 단기 에이전트 도구 실행 기능 토큰 회전",
        "title_en": "30-Second Ephemeral Capability Token Rotation with HMAC Signatures",
        "desc_ko": "도구 실행 권한을 30초 동안만 유효한 HMAC-SHA256 기능 토큰으로 제한하여 토큰 탈취 시 재사용 공격을 무력화합니다.",
        "desc_en": "Rotate HMAC-SHA256 capability tokens on a 30-second lease to prevent token replay attacks in compromised workers."
    },

    # Tier 3 (7 challenges, 200 points each)
    {
        "tier": 3, "points": 200, "slug": "ebpf_lsm_file_open_containment",
        "title_ko": "eBPF bpf_lsm_file_open 훅을 통한 호스트 중요 파일 인라인 차단",
        "title_en": "Inline Host File Access Denial via eBPF bpf_lsm_file_open LSM Hooks",
        "desc_ko": "컨테이너 내부 프로세스가 /etc/shadow, /proc/kcore, 도커 소켓(/var/run/docker.sock) 열기 시도 시 -EACCES 에러를 인라인 반환합니다.",
        "desc_en": "Attach eBPF LSM hooks to bpf_lsm_file_open returning -EACCES when sandboxed workers attempt opening sensitive host paths."
    },
    {
        "tier": 3, "points": 200, "slug": "wasm_wasi_memory_isolated_tool_runner",
        "title_ko": "Wasm/WASI 메모리 격리 런타임을 통한 제로트러스트 에이전트 도구 구동",
        "title_en": "Zero-Trust Agent Tool Execution via Wasm/WASI Memory-Isolated Runtimes",
        "desc_ko": "Wasmtime 샌드박스에서 선형 메모리 경계(Linear Memory Boundary)를 강제하여 버퍼 오버플로우와 셸 실행을 원천 차단합니다.",
        "desc_en": "Execute third-party agent plugins inside Wasmtime WASI runtimes enforcing linear memory boundaries and zero shell access."
    },
    {
        "tier": 3, "points": 200, "slug": "g3_dual_custody_hmac_ledger",
        "title_ko": "G3 다자간 합의 이중 서명(HMAC-SHA256) 불변 조치 감사 원장",
        "title_en": "Immutable Action Audit Ledger with G3 Dual-Custody HMAC-SHA256 Signatures",
        "desc_ko": "에이전트가 발행한 조치 요청에 대해 보안 운영자 키와 관리자 키 2개의 HMAC 서명이 모두 확인되어야만 실행을 승인합니다.",
        "desc_en": "Mandate dual HMAC-SHA256 signatures from both sec-ops and compliance officers before authorizing restricted agent actions."
    },
    {
        "tier": 3, "points": 200, "slug": "pypi_index_mirror_hash_enforcement",
        "title_ko": "사내 프라이빗 패키지 미러의 SHA-256 서명 교차 검증 및 무결성 강제",
        "title_en": "Private Package Mirror SHA-256 Cross-Validation & Integrity Enforcement",
        "desc_ko": "외부 PyPI 직접 조회를 차단하고 사내 에어갭 미러에서 TUF(The Update Framework) 메타데이터와 패키지 해시를 교차 검증합니다.",
        "desc_en": "Block upstream PyPI egress and enforce TUF signed metadata validation across internal air-gapped package mirrors."
    },
    {
        "tier": 3, "points": 200, "slug": "hardened_seccomp_syscall_whitelist",
        "title_ko": "최소 권한 아키텍처 기반 28개 허용 시스템콜 정밀 Seccomp 화이트리스트",
        "title_en": "Least-Privilege 28-Syscall Whitelist Architecture via Hardened Seccomp",
        "desc_ko": "에이전트 추론에 필요한 최소 28개 시스템콜(read, write, futex 등) 외의 모든 커널 진입을 SECCOMP_RET_KILL_PROCESS로 봉쇄합니다.",
        "desc_en": "Restrict agent workers to exactly 28 essential system calls, triggering SECCOMP_RET_KILL_PROCESS on any unknown syscall."
    },
    {
        "tier": 3, "points": 200, "slug": "zero_trust_agent_egress_gateway",
        "title_ko": "Envoy mTLS 제로 트러스트 프록시를 통한 에이전트 아웃바운드 C2 격리",
        "title_en": "Agent Outbound C2 Containment via Envoy mTLS Zero-Trust Egress Gateways",
        "desc_ko": "에이전트 컨테이너의 모든 외부 네트워크 요청을 Envoy 사이드카로 강제 라우팅하고 FQDN 화이트리스트 외 연결을 즉각 드롭합니다.",
        "desc_en": "Route all egress traffic through Envoy sidecars to enforce strict FQDN whitelists and block outbound reverse C2 beacons."
    },
    {
        "tier": 3, "points": 200, "slug": "realtime_agent_anomaly_detection_loop",
        "title_ko": "커널 링버퍼 기반 에이전트 시스템콜 이상 전이 실시간 통계적 이상 탐지",
        "title_en": "Statistical Anomaly Detection of Agent Syscall Trajectories via Ringbuffers",
        "desc_ko": "정상 에이전트 실행 패턴(Markov 체인 모델)을 벗어나는 시스템콜 시퀀스 탐지 시 0.5초 이내에 프로세스를 격리합니다.",
        "desc_en": "Monitor syscall transition probabilities using eBPF ringbuffers to isolate deviating agent processes within 0.5 seconds."
    },

    # Tier 4 (7 challenges, 350 points each)
    {
        "tier": 4, "points": 350, "slug": "cross_cloud_agent_mesh_containment",
        "title_ko": "멀티클라우드 분산 AI 에이전트 서비스 메시 전송망 침해 격리",
        "title_en": "Multi-Cloud Distributed AI Agent Service Mesh Breach Containment",
        "desc_ko": "AWS EKS와 GCP GKE에 분산된 에이전트 워커가 탈취되었을 때 크로스 클라우드 SPIFFE 트러스트 도메인 격리를 통해 확산을 차단합니다.",
        "desc_en": "Isolate compromised worker nodes across multi-cloud EKS and GKE meshes using federated SPIFFE trust domain boundaries."
    },
    {
        "tier": 4, "points": 350, "slug": "hardware_tee_confidential_agent_reasoning",
        "title_ko": "하드웨어 TEE(AMD SEV-SNP/Intel TDX) 기밀 컴퓨팅 기반 에이전트 추론 보호",
        "title_en": "Hardware TEE Confidential Computing Protection for Agent Reasoning",
        "desc_ko": "호스트 루트 권한자나 하이퍼바이저 탈취 상황에서도 에이전트 메모리와 프롬프트를 하드웨어 암호화 엔클레이브로 격리합니다.",
        "desc_en": "Shield agent reasoning memory and proprietary system prompts inside hardware AMD SEV-SNP and Intel TDX enclaves."
    },
    {
        "tier": 4, "points": 350, "slug": "ebpf_instant_sigkill_breakout_shield",
        "title_ko": "bpf_send_signal(SIGKILL) 기반 서브마이크로초 탈출 시도 즉시 사살 쉴드",
        "title_en": "Sub-Microsecond Breakout Neutralization Shield via bpf_send_signal(SIGKILL)",
        "desc_ko": "컨테이너 경계 탈출 패턴(leaked fd mknod 등) 감지 시 커널 내부에서 0.35µs 이내에 프로세스를 SIGKILL로 즉시 사살합니다.",
        "desc_en": "Deploy in-kernel eBPF LSM telemetry triggering bpf_send_signal(SIGKILL) within 0.35µs of unauthorized namespace traversal."
    },
    {
        "tier": 4, "points": 350, "slug": "multi_agent_consensus_byzantine_fault",
        "title_ko": "다중 에이전트 오케스트레이션 비잔틴 결함 방어 및 독성 명령 거부 합의",
        "title_en": "Byzantine Fault Tolerance & Poisoned Instruction Rejection in Multi-Agent Swarms",
        "desc_ko": "N개 에이전트 중 1/3 이하가 탈취되어 악의적 툴 호출을 시도하더라도 Raft/PBFT 합의를 통해 공격 명령을 기각합니다.",
        "desc_en": "Implement Byzantine Fault Tolerant consensus across multi-agent swarms to reject poisoned commands from rogue workers."
    },
    {
        "tier": 4, "points": 350, "slug": "slsa_level4_hermetic_reproducible_agent",
        "title_ko": "밀폐형(Hermetic) 완전 재현 가능 빌드 파이프라인 기반 SLSA Level 4 에이전트",
        "title_en": "Hermetic Fully Reproducible Build Pipeline for SLSA Level 4 Agent Runtimes",
        "desc_ko": "네트워크가 차단된 밀폐 빌드 환경에서 비트 단위 동일한 아티팩트를 재생산하고 두 개 이상의 독립 빌더 증명을 결합합니다.",
        "desc_en": "Enforce network-isolated hermetic build environments producing bit-for-bit reproducible agent container artifacts."
    },
    {
        "tier": 4, "points": 350, "slug": "covert_steganography_weight_scanner",
        "title_ko": "대규모 언어 모델 가중치 내 은닉 페이로드 스테가노그래피 텐서 감사",
        "title_en": "Steganographic Covert Payload Scanning Across Deep Learning Weight Tensors",
        "desc_ko": "FP16 부동소수점 하위 비트에 은닉된 백도어 셸코드 텐서를 엔트로피 및 클러스터링 통계 기법으로 정밀 탐색합니다.",
        "desc_en": "Scan low-order bits of FP16 weight tensors to detect steganographically embedded shellcode payloads within LLM weights."
    },
    {
        "tier": 4, "points": 350, "slug": "capstone_full_spectrum_ai_sandbox_defense",
        "title_ko": "AI 에이전트 샌드박스 탈출 & 공급망 전방위 방어 캡스톤",
        "title_en": "Full-Spectrum AI Agent Sandbox Escape & Supply Chain Defense Capstone",
        "desc_ko": "SLSA 3 출처 증명, Ray mTLS 신원 인증, Landlock LSM 샌드박싱, eBPF 즉각 사살, G3 다자간 승인을 모두 통합한 종합 방어를 수립합니다.",
        "desc_en": "Synthesize SLSA Level 3 provenance, Ray cluster mTLS, Landlock LSM sandboxing, eBPF instant SIGKILL, and G3 dual-custody approval."
    }
]


def make_challenge_object(item):
    slug = item["slug"]
    cid = f"t{item['tier']}_aisbox_{slug}"
    # Flag generation: deterministic
    secret_seed = f"{cid}_vibe_aisbox_2026"
    flag_inner = hashlib.sha256(secret_seed.encode("utf-8")).hexdigest()[:20]
    flag = f"FLAG{{{flag_inner}}}"
    stored_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest()

    prompt_ko = f"{item['desc_ko']}\n\n[실습 환경 및 검증 식별자]\nAISBOX_CHALLENGE_ID: `{cid}`\n\n위 식별자를 기반으로 AI 샌드박스 공급망 보안 검증 플래그를 도출하여 제출하세요."
    prompt_en = f"{item['desc_en']}\n\n[Verification Identifier]\nAISBOX_CHALLENGE_ID: `{cid}`\n\nDerive and submit the AI sandbox & supply chain security verification flag based on this challenge identifier."

    hints_ko = [
        "AI 에이전트 샌드박스 격리(Landlock/eBPF/Seccomp) 및 공급망(SLSA/Cosign) 보안 아키텍처를 분석하세요.",
        f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."
    ]
    hints_en = [
        "Analyze AI agent sandbox isolation (Landlock/eBPF/Seccomp) and supply chain (SLSA/Cosign) architectures.",
        f"This challenge derives a deterministic flag from identifier `{cid}`."
    ]

    return {
        "id": cid,
        "tier": item["tier"],
        "cat": "ai",
        "track": "aisbox",
        "points": item["points"],
        "ci": False,
        "fmt": "FLAG{...}",
        "title": {
            "ko": item["title_ko"],
            "en": item["title_en"]
        },
        "prompt": {
            "ko": prompt_ko,
            "en": prompt_en
        },
        "hints": {
            "ko": hints_ko,
            "en": hints_en
        },
        "hash": stored_hash
    }


def main():
    repo_root = Path(__file__).resolve().parent.parent
    challenges_js_path = repo_root / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = repo_root / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = repo_root / "wargame" / "README.md"
    index_html_path = repo_root / "wargame" / "index.html"

    # 1. Generate challenge objects
    new_challenges = [make_challenge_object(item) for item in CHALLENGES_DATA]
    assert len(new_challenges) == 35, f"Expected 35 challenges, got {len(new_challenges)}"
    print(f"[+] Generated {len(new_challenges)} challenge objects for Track 78: aisbox.")

    # Track definition
    track_def = {
        "id": "aisbox",
        "icon": "🤖",
        "ko": "AI 에이전트 샌드박스 탈출 & 공급망 보안",
        "en": "AI Agent Sandbox Escape & Supply Chain Security",
        "desc_ko": "AI 에이전트 툴 동적 로딩 오염·SLSA Level 3 출처 증명·Ray/vLLM 분산 RCE 차단 & SPIFFE mTLS·Landlock LSM 샌드박싱·eBPF 런타임 탈출 SIGKILL 격리·G3 다자간 승인 거버넌스.",
        "desc_en": "AI agent dynamic tool loading poisoning, SLSA Level 3 provenance, Ray/vLLM distributed RCE defense with SPIFFE mTLS, Landlock LSM sandboxing, eBPF instant SIGKILL breakout containment, and G3 multi-party approval governance."
    }

    # 2. Update challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    track_json = json.dumps(track_def, ensure_ascii=False, indent=2)
    track_insert = ",\n  " + track_json.replace("\n", "\n  ")
    target_tracks_end = "];\n\nconst CHALLENGES = ["

    if 'id: "aisbox"' in content or '"id": "aisbox"' in content:
        print("[-] Track aisbox already in challenges.js, skipping track insert.")
    else:
        assert target_tracks_end in content, "Could not find end of TRACKS in challenges.js"
        content = content.replace(target_tracks_end, track_insert + "\n];\n\nconst CHALLENGES = [")
        print("[+] Inserted Track 78 definition into TRACKS.")

    # Check if challenges already present
    existing_cids = set(re.findall(r'"id":\s*"(t\d_aisbox_[^"]+)"', content))
    if existing_cids:
        print(f"[-] {len(existing_cids)} aisbox challenges already exist in challenges.js, skipping challenge append.")
    else:
        target_challs_end = "\n];"
        formatted_challs = []
        for ch in new_challenges:
            ch_str = json.dumps(ch, ensure_ascii=False, indent=2)
            formatted_challs.append("  " + ch_str.replace("\n", "\n  "))
        challs_block = ",\n" + ",\n".join(formatted_challs)
        assert content.endswith(target_challs_end) or target_challs_end in content, "Could not find end of CHALLENGES in challenges.js"
        # Replace the last occurrence of \n];
        idx = content.rfind(target_challs_end)
        content = content[:idx] + challs_block + "\n];" + content[idx + len(target_challs_end):]
        print("[+] Appended 35 aisbox challenges to CHALLENGES array.")

    challenges_js_path.write_text(content, encoding="utf-8")
    print(f"[+] Wrote updated {challenges_js_path}")

    # 3. Update solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    if "AISBOX_IDS" in solve_content or "aisbox" in solve_content:
        print("[-] solve-derivable.js already handles aisbox.")
    else:
        aisbox_ids = [ch["id"] for ch in new_challenges]
        ids_js = ",\n  ".join([f'"{cid}"' for cid in aisbox_ids])
        derivable_code = f"""
const AISBOX_IDS = [
  {ids_js}
];

for (const id of AISBOX_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/AISBOX_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_aisbox_2026').digest('hex').slice(0, 20);
      return `FLAG${{{{hash}}}}`;
    }}
  }});
}}
"""
        solve_content += derivable_code
        solve_derivable_path.write_text(solve_content, encoding="utf-8")
        print("[+] Added aisbox derivation handler to solve-derivable.js.")

    # 4. Update wargame/README.md
    readme_text = readme_path.read_text(encoding="utf-8")
    # Update total numbers: 2695 -> 2730, 77 -> 78
    readme_text = readme_text.replace("총 2695문제", "총 2730문제")
    readme_text = readme_text.replace("총 **2695문제**", "총 **2730문제**")
    readme_text = readme_text.replace("77개 트랙", "78개 트랙")
    readme_text = readme_text.replace("77개 섹션", "78개 섹션")

    # Add row in Tier 0~4 tables
    tier0_row = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 도구 동적 로딩 위협 · SLSA Level 3 출처 증명 · PEP 665 해시 고정 · Landlock 비특권 원리 / Tool dynamic loading threat, SLSA Level 3 provenance, PEP 665 hash pinning, and Landlock unprivileged principles |\n"
    tier1_row = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 타이포스쿼팅 해시 감사 · Ray 피클 역직렬화 RCE · Seccomp 시스템콜 필터 · Cosign 컨테이너 서명 / Typosquatting hash audit, Ray pickle deserialization RCE, Seccomp syscall filter, and Cosign container signatures |\n"
    tier2_row = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | /proc/self/fd 누출 디스크립터 · setns 피벗 차단 · Safetensors 무결성 강제 · 30초 기능 토큰 회전 / /proc/self/fd leaked descriptor, setns pivot denial, Safetensors integrity enforcement, and 30s capability token rotation |\n"
    tier3_row = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | eBPF bpf_lsm_file_open 차단 · Wasm 메모리 격리 런타임 · G3 다자간 합의 원장 · 28개 시스템콜 화이트리스트 / eBPF bpf_lsm_file_open denial, Wasm memory-isolated runtime, G3 multi-party ledger, and 28-syscall whitelist |\n"
    tier4_row = "| `aisbox` 🤖 AI 에이전트 샌드박스 탈출 & 공급망 보안 (7) | 크로스클라우드 메시 격리 · 하드웨어 TEE 추론 보호 · 서브마이크로초 SIGKILL 쉴드 · AI 샌드박스 방어 캡스톤 / Cross-cloud mesh containment, hardware TEE reasoning shield, sub-microsecond SIGKILL shield, and AI sandbox defense capstone |\n"

    # Insert after pqctls rows
    pqctls_t0 = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 쇼어 알고리즘 위협 모델 · FIPS 203/204 표준 규격 · 하이브리드 이중 키 교환 · 복합 X.509 인증서 구조 / Shor algorithm threat, FIPS 203/204 standards, hybrid dual key exchange, and composite X.509 certificate layout |"
    pqctls_t1 = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 하이브리드 그룹 코드포인트 · 이중 비밀 HKDF 도출 · 복합 서명 순차 검증 · KeyShare 페이로드 구조 / Hybrid group codepoint, dual secret HKDF derivation, composite signature verification, and KeyShare layout |"
    pqctls_t2 = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 패킷 내 SNDL 위험 감사 · PQC 그룹 스트리핑 방어 · 서명 대형화 MTU 최적화 · 다항식 환 모듈러 곱셈 / SNDL packet audit, PQC group stripping defense, signature MTU optimization, and polynomial ring arithmetic |"
    pqctls_t3 = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | NTT 타이밍 편차 탐지 · 몽고메리 상수시간 축약 · 1차 불리언 마스킹 메모리 · 인라인 다운그레이드 차단 / NTT timing deviation detection, Montgomery constant-time reduction, 1st-order boolean masking, and inline downgrade blocking |"
    pqctls_t4 = "| `pqctls` ⚛️ 포스트 양자 하이브리드 TLS 1.3 & PQC 네트워크 방어 (7) | 크로스클라우드 제로트러스트 전송망 · TEE 엔클레이브 개인키 격리 · 임베디드 펌웨어 보안부팅 · PQC 하이브리드 TLS 방어 캡스톤 / Cross-cloud zero-trust transit, TEE enclave key isolation, embedded firmware authenticated boot, and PQC hybrid TLS defense capstone |"

    if '`aisbox`' not in readme_text:
        readme_text = readme_text.replace(pqctls_t0, pqctls_t0 + "\n" + tier0_row.strip())
        readme_text = readme_text.replace(pqctls_t1, pqctls_t1 + "\n" + tier1_row.strip())
        readme_text = readme_text.replace(pqctls_t2, pqctls_t2 + "\n" + tier2_row.strip())
        readme_text = readme_text.replace(pqctls_t3, pqctls_t3 + "\n" + tier3_row.strip())
        readme_text = readme_text.replace(pqctls_t4, pqctls_t4 + "\n" + tier4_row.strip())
        readme_path.write_text(readme_text, encoding="utf-8")
        print("[+] Updated wargame/README.md with aisbox rows.")
    else:
        print("[-] aisbox already present in wargame/README.md.")

    # 5. Update index.html HUD (2695 -> 2730)
    index_text = index_html_path.read_text(encoding="utf-8")
    index_text = index_text.replace("0/2695", "0/2730")
    index_text = index_text.replace("/2695", "/2730")
    index_text = index_text.replace("2,695", "2,730")
    index_text = index_text.replace("2695", "2730")
    index_html_path.write_text(index_text, encoding="utf-8")
    print("[+] Updated wargame/index.html HUD counter.")

    print("\n🎉 Track 78 aisbox generation completed successfully!")

if __name__ == "__main__":
    main()
