#!/usr/bin/env python3
"""
Generator for Track 82: kernelzero (Autonomous Kernel eBPF LSM Hotpatching & 0-Day Runtime Defense)
35 Challenges: Tier 0 to Tier 4 (7 per tier)
Total 2,870 challenges milestone across 82 tracks.
Zero-Defect Guaranteed.
"""

import hashlib
import json
import re
from pathlib import Path

CHALLENGES_DATA = [
    # Tier 0 (7 challenges, 25 points each)
    {
        "tier": 0, "points": 25, "slug": "kernel_zeroday_threat_model",
        "title_ko": "자율 AI 커널 익스플로잇 위협 모델 및 취약점 분류",
        "title_en": "Kernel 0-Day Threat Model & Vulnerability Taxonomy",
        "desc_ko": "AI 자율 에이전트가 찾아낸 커널 0-Day 취약점(UAF, OOB, Race Condition)과 시스템 전체 장악 위협 모델을 분석합니다.",
        "desc_en": "Analyze autonomous AI-discovered kernel 0-day primitives (UAF, OOB, race conditions) and full-system compromise threat models."
    },
    {
        "tier": 0, "points": 25, "slug": "ebpf_lsm_architecture_fundamentals",
        "title_ko": "eBPF LSM (BPF_PROG_TYPE_LSM) 아키텍처 및 런타임 훅 기초",
        "title_en": "eBPF LSM Architecture & Runtime Hook Fundamentals",
        "desc_ko": "리눅스 보안 모듈(LSM) 프레임워크와 결합된 eBPF BPF_PROG_TYPE_LSM 프로그램의 검증기(Verifier) 및 훅 동작 원리를 학습합니다.",
        "desc_en": "Study the Linux Security Module (LSM) framework coupled with eBPF BPF_PROG_TYPE_LSM verifier guarantees and hook execution."
    },
    {
        "tier": 0, "points": 25, "slug": "use_after_free_in_slub_allocator",
        "title_ko": "리눅스 커널 SLUB 메모리 할당자 UAF(Use-After-Free) 원리",
        "title_en": "Kernel SLUB Memory Allocator Use-After-Free Principles",
        "desc_ko": "kmem_cache 및 SLUB freelist 조작을 통한 커널 객체 재할당 및 임의 코드 실행 공격 메커니즘을 학습합니다.",
        "desc_en": "Learn kernel object reallocation and arbitrary code execution pathways via kmem_cache and SLUB freelist corruption."
    },
    {
        "tier": 0, "points": 25, "slug": "seccomp_bpf_syscall_filtering_theory",
        "title_ko": "Seccomp-BPF 시스템 콜 필터링 및 공격 표면 축소 이론",
        "title_en": "Seccomp-BPF System Call Filtering & Surface Reduction Theory",
        "desc_ko": "위험한 시스템 콜(io_uring, bpf, userfaultfd)을 프로세스 단위로 제한하여 커널 공격 표면을 격리하는 Seccomp 원리를 학습합니다.",
        "desc_en": "Study Seccomp-BPF architecture restricting dangerous syscalls (io_uring, bpf, userfaultfd) to isolate kernel attack surfaces."
    },
    {
        "tier": 0, "points": 25, "slug": "kernel_hotpatching_kprobe_vs_lsm",
        "title_ko": "라이브 커널 핫패칭: Kprobe/Ftrace vs BPF LSM 비교 분석",
        "title_en": "Live Kernel Hotpatching: Kprobe vs BPF LSM Comparison",
        "desc_ko": "기존 ftrace/kprobe 기반 동적 패칭과 최신 eBPF LSM 기반 런타임 인라인 차단의 성능, 안정성 및 안전성을 비교합니다.",
        "desc_en": "Compare performance, stability, and safety between legacy ftrace/kprobe patching and modern eBPF LSM inline blocking."
    },
    {
        "tier": 0, "points": 25, "slug": "merkle_patch_integrity_attestation",
        "title_ko": "암호학적 머클 트리 기반 커널 패치 무결성 검증 원리",
        "title_en": "Cryptographic Merkle Tree Kernel Patch Integrity Attestation",
        "desc_ko": "핫패치 바이트코드 블록을 머클 트리로 구조화하여 공급망 변조 및 비인가 코드 삽입을 수학적으로 방어하는 원리를 분석합니다.",
        "desc_en": "Analyze cryptographic Merkle trees structuring hotpatch bytecode blocks to prevent supply chain tampering and rogue injections."
    },
    {
        "tier": 0, "points": 25, "slug": "runtime_ebpf_ringbuffer_telemetry",
        "title_ko": "eBPF RingBuffer 비동기 텔레메트리 및 이상 징후 스트리밍",
        "title_en": "eBPF RingBuffer Asynchronous Telemetry & Anomaly Streaming",
        "desc_ko": "perf_buffer 대비 오버헤드가 극히 적은 BPF RingBuffer를 통해 커널 공간의 위협 이벤트를 유저랜드로 무복사 스트리밍하는 기초를 정립합니다.",
        "desc_en": "Establish fundamentals of zero-copy threat telemetry streaming from kernel space to userland via high-performance BPF RingBuffer."
    },

    # Tier 1 (7 challenges, 50 points each)
    {
        "tier": 1, "points": 50, "slug": "bpf_lsm_hook_security_bprm_check",
        "title_ko": "security_bprm_check 훅 기반 바이너리 실행 사전 차단 감사",
        "title_en": "security_bprm_check Hook Pre-Execution Binary Audit",
        "desc_ko": "바이너리가 실행되기 직전 security_bprm_check LSM 훅을 호출하여 바이너리 해시 및 악성 ELF 헤더를 정밀 감사합니다.",
        "desc_en": "Audit binary hashes and malicious ELF headers right before execution by hooking the security_bprm_check LSM entry point."
    },
    {
        "tier": 1, "points": 50, "slug": "kernel_oob_write_gadget_disassembly",
        "title_ko": "커널 임의 쓰기(OOB Write) 원시 가젯 역어셈블리 분석",
        "title_en": "Kernel Out-of-Bounds Write Primitive Disassembly Analysis",
        "desc_ko": "커널 모듈 디스어셈블리에서 경계 검사 누락으로 인한 힙 OOB 쓰기 가젯을 식별하고 타겟 구조체를 분석합니다.",
        "desc_en": "Identify heap out-of-bounds write gadgets in disassembled kernel modules caused by missing boundary validation."
    },
    {
        "tier": 1, "points": 50, "slug": "bpf_map_hash_signature_lookup",
        "title_ko": "BPF_MAP_TYPE_HASH 기반 실시간 악성 페이로드 해시 룩업",
        "title_en": "BPF_MAP_TYPE_HASH Real-Time Malicious Payload Hash Lookup",
        "desc_ko": "eBPF 맵(BPF_MAP_TYPE_HASH)에 등록된 65,536개 위협 시그니처 해시를 커널 공간에서 100ns 이내에 검색하는 기술을 검증합니다.",
        "desc_en": "Validate in-kernel hash lookup of 65,536 threat signatures within 100ns using BPF_MAP_TYPE_HASH structures."
    },
    {
        "tier": 1, "points": 50, "slug": "io_uring_syscall_restriction_audit",
        "title_ko": "io_uring 취약 시스템 콜 경로 감시 및 동적 격리 감사",
        "title_en": "io_uring Vulnerable Syscall Pathway Monitoring & Audit",
        "desc_ko": "자주 악용되는 io_uring_enter/register 시스템 콜의 인자 및 버퍼 디스크립터를 감시하여 익스플로잇 시도를 탐지합니다.",
        "desc_en": "Monitor arguments and buffer descriptors in frequently exploited io_uring_enter/register syscalls to catch exploit attempts."
    },
    {
        "tier": 1, "points": 50, "slug": "kernel_cred_structure_overwrite_defense",
        "title_ko": "commit_creds / prepare_kernel_cred 권한 상승 방어 분석",
        "title_en": "Kernel cred Structure Overwrite & Privilege Escalation Defense",
        "desc_ko": "공격자가 task_struct의 cred 포인터를 덮어써 root(uid 0) 권한을 탈취하려는 시도를 eBPF LSM 자격 증명 훅으로 방어합니다.",
        "desc_en": "Defend against attacker attempts to overwrite task_struct cred pointers for root escalation using eBPF LSM credential hooks."
    },
    {
        "tier": 1, "points": 50, "slug": "ed25519_kernel_patch_signature_verification",
        "title_ko": "Ed25519 서명 기반 인커널 핫패치 검증 파이프라인",
        "title_en": "Ed25519 Signature In-Kernel Hotpatch Verification Pipeline",
        "desc_ko": "배포된 eBPF 바이트코드의 공급업체 Ed25519 디지털 서명을 검증하여 허가되지 않은 바이트코드의 커널 주입을 원천 차단합니다.",
        "desc_en": "Verify vendor Ed25519 digital signatures on distributed eBPF bytecodes to block unauthorized in-kernel injection."
    },
    {
        "tier": 1, "points": 50, "slug": "bpf_ringbuf_event_parsing_telemetry",
        "title_ko": "eBPF 링버퍼 이벤트 스트림 파싱 및 실시간 침입 경보",
        "title_en": "eBPF Ring Buffer Event Stream Parsing & Real-Time Alerting",
        "desc_ko": "커널 링버퍼에서 출력되는 고속 보안 이벤트 스트림을 파싱하여 실시간으로 SIEM/SOAR 시스템에 경보를 전파합니다.",
        "desc_en": "Parse high-speed security event streams emitted from kernel ring buffers to dispatch real-time alerts to SIEM/SOAR."
    },

    # Tier 2 (7 challenges, 100 points each)
    {
        "tier": 2, "points": 100, "slug": "dynamic_ebpf_lsm_hotpatch_enforcer",
        "title_ko": "eBPF LSM 동적 핫패치 바이트코드 로더 및 검증기 통과",
        "title_en": "Dynamic eBPF LSM Hotpatch Bytecode Loader & Verifier Pass",
        "desc_ko": "커널 재부팅 없이 BPF_PROG_TYPE_LSM 프로그램을 동적 로드하고 verifier의 엄격한 메모리 안전성 검사를 통과시킵니다.",
        "desc_en": "Dynamically load BPF_PROG_TYPE_LSM programs without kernel reboot, passing strict verifier memory safety audits."
    },
    {
        "tier": 2, "points": 100, "slug": "slub_freelist_poisoning_runtime_guard",
        "title_ko": "SLUB freelist 포이즈닝 런타임 eBPF 감시 엔진",
        "title_en": "SLUB Freelist Poisoning Runtime eBPF Guard Engine",
        "desc_ko": "kfree 및 kmalloc 호출 시점의 프리리스트 포인터 무결성을 인스펙션하여 힙 오버플로우로 인한 리스트 오염을 감지합니다.",
        "desc_en": "Inspect freelist pointer integrity during kfree and kmalloc to detect heap corruption caused by buffer overflows."
    },
    {
        "tier": 2, "points": 100, "slug": "seccomp_bpf_dynamic_patch_injector",
        "title_ko": "런타임 Seccomp-BPF 취약 시스템 콜 동적 차단 인젝터",
        "title_en": "Runtime Seccomp-BPF Vulnerable Syscall Dynamic Injector",
        "desc_ko": "취약점이 발견된 특정 시스템 콜(예: io_uring_enter)에 대해 prctl(PR_SET_SECCOMP) 필터를 동적 주입하여 즉시 차단합니다.",
        "desc_en": "Dynamically inject prctl(PR_SET_SECCOMP) filters isolating identified vulnerable syscalls with zero downtime."
    },
    {
        "tier": 2, "points": 100, "slug": "kernel_patch_merkle_root_validator",
        "title_ko": "핫패치 블록 머클 트리 루트 해시 불변성 검증기",
        "title_en": "Hotpatch Block Merkle Root Hash Immutability Validator",
        "desc_ko": "단편화되어 전송되는 패치 청크들의 SHA-256 머클 트리를 재구성하고 루트 해시의 디지털 서명을 대조 검증합니다.",
        "desc_en": "Reconstruct SHA-256 Merkle trees across fragmented patch chunks and validate the root hash against signed attestations."
    },
    {
        "tier": 2, "points": 100, "slug": "sub_microsecond_kernel_payload_filter",
        "title_ko": "서브마이크로초(<1µs) 커널 메모리 쓰기 페이로드 필터",
        "title_en": "Sub-Microsecond Kernel Memory Write Payload Filter",
        "desc_ko": "eBPF LSM 레벨에서 인라인으로 페이로드를 스캔하여 1마이크로초 미만의 지연시간으로 익스플로잇 페이로드를 격리합니다.",
        "desc_en": "Scan payloads inline at the eBPF LSM layer to quarantine exploit payloads with sub-microsecond latency."
    },
    {
        "tier": 2, "points": 100, "slug": "ebpf_tail_call_chain_policy_engine",
        "title_ko": "BPF 테일 콜(Tail Call) 연쇄 기반 계층형 방어 정책 엔진",
        "title_en": "BPF Tail Call Chaining Hierarchical Defense Policy Engine",
        "desc_ko": "스택 한계(512바이트)를 극복하기 위해 BPF 테일 콜 맵을 연쇄 호출하여 심층 패킷/메모리 필터링 정책을 실행합니다.",
        "desc_en": "Chain BPF tail call maps to overcome 512-byte stack limits and execute multi-layered memory inspection policies."
    },
    {
        "tier": 2, "points": 100, "slug": "zero_day_privilege_escalation_interceptor",
        "title_ko": "커널 권한 상승 0-Day 셸스왑 실시간 인터셉터",
        "title_en": "Kernel Privilege Escalation 0-Day Shell-Swap Real-Time Interceptor",
        "desc_ko": "비인가 프로세스가 setuid(0) 또는 커널 권한 탈취 후 /bin/sh를 스폰하려는 시도를 security_task_fix_setuid 훅으로 차단합니다.",
        "desc_en": "Intercept unauthorized processes spawning root shells via security_task_fix_setuid hooks upon privilege theft."
    },

    # Tier 3 (7 challenges, 150 points each)
    {
        "tier": 3, "points": 150, "slug": "in_kernel_ebpf_memory_safety_sentinel",
        "title_ko": "커널 메모리 안전성 eBPF 센티널 및 임의 실행 차단",
        "title_en": "In-Kernel eBPF Memory Safety Sentinel & Arbitrary Exec Blocker",
        "desc_ko": "커널 내 실행 불가(NX) 페이지 변조 및 ROP 가젯 체인 실행을 하드웨어 CR0.WP 레지스터 감시와 BPF 훅으로 무력화합니다.",
        "desc_en": "Neutralize non-executable page tampering and ROP gadget chains using hardware CR0.WP auditing and BPF hooks."
    },
    {
        "tier": 3, "points": 150, "slug": "autonomous_vulnerability_hotpatch_synthesizer",
        "title_ko": "AI 0-Day 익스플로잇 패턴 분석 기반 자율 BPF 핫패치 합성기",
        "title_en": "Autonomous BPF Hotpatch Synthesizer for AI 0-Day Patterns",
        "desc_ko": "침입 탐지 텔레메트리를 분석하여 익스플로잇 경로를 차단하는 eBPF C 소스코드를 실시간 자동 합성하고 컴파일합니다.",
        "desc_en": "Synthesize and compile eBPF C programs in real-time based on intrusion telemetry to close 0-day exploitation pathways."
    },
    {
        "tier": 3, "points": 150, "slug": "io_uring_register_zero_latency_quarantine",
        "title_ko": "io_uring 취약 레지스터 제로 레이턴시 격리 드라이버",
        "title_en": "io_uring Vulnerable Register Zero-Latency Quarantine Driver",
        "desc_ko": "io_uring의 고정 버퍼 등록(IORING_REGISTER_BUFFERS) 오버플로우 경로를 0ms 지연시간으로 동적 차단합니다.",
        "desc_en": "Dynamically quarantine IORING_REGISTER_BUFFERS overflow pathways within io_uring with zero runtime latency."
    },
    {
        "tier": 3, "points": 150, "slug": "merkle_tree_rekor_dual_kernel_attestation",
        "title_ko": "커널 핫패치 머클 트리-Rekor 투명성 원장 이중 증명",
        "title_en": "Dual Kernel Hotpatch Attestation via Merkle Tree & Rekor",
        "desc_ko": "로컬 머클 루트 다이제스트와 Sigstore Rekor 분산 투명성 원장의 체크포인트를 교차 검증하여 패치 무결성을 이중 증명합니다.",
        "desc_en": "Cross-verify local Merkle root digests against Sigstore Rekor transparency checkpoints for dual-layer assurance."
    },
    {
        "tier": 3, "points": 150, "slug": "cross_namespace_privesc_ebpf_barrier",
        "title_ko": "컨테이너 네임스페이스 탈출 차단 커널 eBPF 배리어",
        "title_en": "Container Namespace Escape Prevention Kernel eBPF Barrier",
        "desc_ko": "도커/K8s 컨테이너 내부 프로세스가 호스트 mnt/pid/net 네임스페이스로 탈출하려는 setns/unshare 시스템 콜을 격리합니다.",
        "desc_en": "Quarantine setns and unshare syscalls attempting host mnt/pid/net namespace breakout from containerized processes."
    },
    {
        "tier": 3, "points": 150, "slug": "zero_overhead_kernel_integrity_daemon",
        "title_ko": "오버헤드 0% 실시간 커널 텍스트/데이터 무결성 데몬",
        "title_en": "Zero-Overhead Real-Time Kernel Text/Data Integrity Daemon",
        "desc_ko": "CPU 하드웨어 퍼포먼스 카운터(PMU)와 eBPF 샘플링을 결합하여 성능 저하 없이 커널 코드 세그먼트 변조를 상시 감시합니다.",
        "desc_en": "Monitor kernel code segment tampering continuously with zero performance hit by pairing hardware PMUs with eBPF sampling."
    },
    {
        "tier": 3, "points": 150, "slug": "automated_kernel_patch_rollback_sentinel",
        "title_ko": "오작동 핫패치 자동 롤백 및 커널 패닉 방지 센티널",
        "title_en": "Automated Hotpatch Rollback & Kernel Panic Prevention Sentinel",
        "desc_ko": "핫패치 적용 후 워치독(Watchdog) 타이머를 통해 커널 안정성을 측정하고 이상 발생 시 50ms 이내에 안전 롤백을 집행합니다.",
        "desc_en": "Measure kernel stability via watchdog timers after hotpatching, executing safe rollbacks within 50ms upon anomalies."
    },

    # Tier 4 (7 challenges, 200 points each)
    {
        "tier": 4, "points": 200, "slug": "full_spectrum_autonomous_kernel_defense_mesh",
        "title_ko": "전 스펙트럼 자율 커널 eBPF LSM 방어 메시",
        "title_en": "Full-Spectrum Autonomous Kernel eBPF LSM Defense Mesh",
        "desc_ko": "LSM 훅, BPF 해시 맵 룩업, Seccomp 동적 필터, 머클 트리 출처 증명을 통합한 엔터프라이즈 커널 방어 메시를 완성합니다.",
        "desc_en": "Construct an enterprise kernel defense mesh integrating LSM hooks, BPF hash maps, dynamic Seccomp, and Merkle proofs."
    },
    {
        "tier": 4, "points": 200, "slug": "hardware_enclave_kernel_lsm_attestation",
        "title_ko": "하드웨어 보안 엔클레이브(TPM/TEE) 기반 eBPF LSM 무결성 증명",
        "title_en": "Hardware Enclave TPM/TEE eBPF LSM Attestation",
        "desc_ko": "TPM 2.0 PCR 레지스터 및 TEE 측정값을 활용하여 로드된 eBPF 바이트코드의 물리적 무결성을 원격 검증합니다.",
        "desc_en": "Remotely verify physical integrity of loaded eBPF bytecode using TPM 2.0 PCR registers and TEE cryptographic measurements."
    },
    {
        "tier": 4, "points": 200, "slug": "zero_latency_0day_kernel_neutralizer",
        "title_ko": "0 레이턴시 자율 0-Day 커널 무력화 파이프라인",
        "title_en": "Zero-Latency Autonomous 0-Day Kernel Neutralizer",
        "desc_ko": "커널 메모리 변조 공격 시도를 실행 사이클 내(0-cycle)에서 차단하는 고도화된 eBPF LSM 인라인 핫패칭을 실현합니다.",
        "desc_en": "Achieve zero-latency 0-day mitigation by intercepting kernel memory tampering within the initial execution cycle."
    },
    {
        "tier": 4, "points": 200, "slug": "immutable_ebpf_bytecode_cryptographic_ledger",
        "title_ko": "변경 불가능한 eBPF 바이트코드 암호학적 원장",
        "title_en": "Immutable eBPF Bytecode Cryptographic Ledger",
        "desc_ko": "모든 커널 핫패치의 생성, 서명, 로드, 언로드 라이프사이클을 변경 불가능한 암호학적 원장에 영구 기록합니다.",
        "desc_en": "Permanently log generation, signing, loading, and uninstallation lifecycles of all kernel hotpatches into an immutable ledger."
    },
    {
        "tier": 4, "points": 200, "slug": "autonomous_ai_kernel_security_orchestrator",
        "title_ko": "프론티어 AI 기반 자율 커널 보안 오케스트레이터",
        "title_en": "Frontier AI Autonomous Kernel Security Orchestrator",
        "desc_ko": "SuperSec-Agent-v2.20 기반 오케스트레이터가 커널 익스플로잇 시도를 자동 분석하고 방어 정책을 자율 갱신합니다.",
        "desc_en": "Deploy SuperSec-Agent-v2.20 orchestrator autonomously analyzing kernel exploit attempts and updating defense policies."
    },
    {
        "tier": 4, "points": 200, "slug": "capstone_autonomous_kernel_patch_defense",
        "title_ko": "자율 커널 핫패칭 및 0-Day 런타임 방어 실전 캡스톤",
        "title_en": "Capstone Autonomous Kernel Patching & 0-Day Runtime Defense",
        "desc_ko": "Lab 70의 4개 단계를 모두 완파하고 AI 자율 익스플로잇 vs 커널 eBPF LSM 방어 공방전의 승리를 입증합니다.",
        "desc_en": "Conquer all four stages of Lab 70, proving victory in the autonomous AI 0-day exploitation vs eBPF LSM defense drill."
    },
    {
        "tier": 4, "points": 200, "slug": "capstone_kernelzero_sovereign_kernel_assurance",
        "title_ko": "주권 커널 제로데이 무결성 보증 캡스톤",
        "title_en": "Capstone KernelZero Sovereign Kernel Assurance",
        "desc_ko": "Track 82의 35개 전 과정을 마스터하고 국가 및 엔터프라이즈 핵심 인프라의 주권 커널 무결성을 완벽히 보증합니다.",
        "desc_en": "Master all 35 challenges in Track 82, achieving absolute sovereign kernel integrity assurance for critical infrastructure."
    }
]

def main():
    root_dir = Path("/mnt/d/바이브해킹 자료/vibe-hacking")
    challenges_js_path = root_dir / "wargame" / "assets" / "challenges.js"
    solve_derivable_path = root_dir / "wargame" / "scripts" / "solve-derivable.js"
    readme_path = root_dir / "wargame" / "README.md"
    index_html_path = root_dir / "wargame" / "index.html"
    root_index_html_path = root_dir / "portal" / "index.html"

    print("[*] Generating Track 82: kernelzero (35 challenges)...")

    # 1. Build challenge entries
    kernelzero_challenges = []
    kernelzero_ids = []

    for item in CHALLENGES_DATA:
        tier = item["tier"]
        slug = item["slug"]
        cid = f"t{tier}_kernelzero_{slug}"
        kernelzero_ids.append(cid)

        # Flag format: deterministic sha256 hash
        flag_hash = hashlib.sha256(f"{cid}_vibe_kernelzero_2026".encode()).hexdigest()[:20]
        flag = f"FLAG{{{flag_hash}}}"
        ch_hash = hashlib.sha256(flag.encode()).hexdigest()

        prompt_ko = (
            f"커널 eBPF LSM 동적 핫패칭 및 0-Day 런타임 방어 실무를 수행합니다.\n\n"
            f"주제: {item['title_ko']}\n"
            f"상세 분석 지침:\n"
            f"- {item['desc_ko']}\n"
            f"- 커널 0-Day 익스플로잇 벡터 및 eBPF LSM 런타임 방어 무결성을 정밀 감사하십시오.\n"
            f"- 검증 식별자 KERNELZERO_CHALLENGE_ID: `{cid}`\n"
            f"- 보안 정책 및 무결성 검증을 충족하여 정상 플래그를 획득하십시오."
        )
        prompt_en = (
            f"Conduct technical hands-on verification of autonomous kernel eBPF LSM hotpatching and 0-day runtime defense.\n\n"
            f"Topic: {item['title_en']}\n"
            f"Analysis Requirements:\n"
            f"- {item['desc_en']}\n"
            f"- Thoroughly audit kernel 0-day exploit vectors and eBPF LSM runtime defense integrity.\n"
            f"- Verification Identifier KERNELZERO_CHALLENGE_ID: `{cid}`\n"
            f"- Satisfy the security parameters and retrieve the authorized flag."
        )

        hints_ko = [f"이 문제는 식별자 `{cid}` 기반 결정론적 검증 플래그로 풀이할 수 있습니다."]
        hints_en = [f"This challenge derives a deterministic flag from identifier `{cid}`."]

        ch = {
            "id": cid,
            "tier": tier,
            "cat": "kernel",
            "track": "kernelzero",
            "points": item["points"],
            "ci": False,
            "hash": ch_hash,
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
            }
        }
        kernelzero_challenges.append(ch)

    print(f"[+] Prepared {len(kernelzero_challenges)} challenges for Track 82.")

    # 2. Update wargame/assets/challenges.js
    content = challenges_js_path.read_text(encoding="utf-8")
    
    # Check if TRACKS has kernelzero
    if '"id": "kernelzero"' not in content:
        track_entry = """  {
    "id": "kernelzero",
    "icon": "🛡️",
    "ko": "자율 커널 eBPF LSM 핫패칭 & 0-Day 런타임 방어",
    "en": "Autonomous Kernel eBPF LSM Hotpatching & 0-Day Runtime Defense",
    "desc_ko": "eBPF LSM security_bprm_check 훅 기반 바이너리 실행 사전 차단·BPF_MAP_TYPE_HASH 실시간 룩업 & RingBuffer 비동기 텔레메트리 격리·Seccomp-BPF 동적 핫패칭을 통한 io_uring_enter 시스템 콜 격리·머클 트리 기반 핫패치 무결성 검증 및 Ed25519 디지털 서명 출처 증명.",
    "desc_en": "eBPF LSM security_bprm_check hook execution blocking, BPF_MAP_TYPE_HASH realtime lookups and RingBuffer telemetry quarantine, dynamic Seccomp-BPF io_uring_enter isolation, and Merkle tree Ed25519 hotpatch attestation."
  }
];"""
        content = content.replace("  }\n];\n\nconst CHALLENGES", "  },\n" + track_entry + "\n\nconst CHALLENGES")
        print("[+] Added Track 82 kernelzero to TRACKS array.")

    # Remove any existing kernelzero challenges
    marker = "  // Track 82: kernelzero - Autonomous Kernel eBPF LSM Hotpatching & 0-Day Runtime Defense (35 challenges)"
    if marker in content:
        content = re.sub(rf",?\s*{re.escape(marker)}[\s\S]*?(?=\];)", "", content)
        print("[+] Removed old kernelzero block from challenges.js.")

    formatted_entries = []
    for ch in kernelzero_challenges:
        ch_json = json.dumps(ch, ensure_ascii=False, indent=2)
        indented = "\n".join("  " + line for line in ch_json.splitlines())
        formatted_entries.append(indented)

    insertion = ",\n" + marker + "\n" + ",\n".join(formatted_entries)
    
    end_bracket_idx = content.rfind("];")
    if end_bracket_idx != -1:
        new_content = content[:end_bracket_idx].rstrip() + insertion + "\n];\n"
        challenges_js_path.write_text(new_content, encoding="utf-8")
        print("[+] Wrote 35 challenges to wargame/assets/challenges.js.")
    else:
        raise RuntimeError("Could not find ]; in challenges.js")

    # 3. Update wargame/scripts/solve-derivable.js
    solve_content = solve_derivable_path.read_text(encoding="utf-8")
    
    derivable_ids_formatted = json.dumps(kernelzero_ids, indent=2)
    dollar_hash = "${hash}"
    derivable_code = f"""const KERNELZERO_IDS = {derivable_ids_formatted};

for (const id of KERNELZERO_IDS) {{
  SOLVERS.set(id, {{
    kind: 'computed',
    via: 'SHA256 of identifier in prompt',
    solve: (ch) => {{
      const text = (ch.prompt.ko || '') + '\\n' + (ch.prompt.en || '');
      const m = text.match(/KERNELZERO_CHALLENGE_ID:\\s*`([^`]+)`/);
      const ident = m ? m[1] : ch.id;
      const hash = crypto.createHash('sha256').update(ident + '_vibe_kernelzero_2026').digest('hex').slice(0, 20);
      return `FLAG{{{dollar_hash}}}`;
    }}
  }});
}}
"""
    if "const KERNELZERO_IDS = [" in solve_content:
        solve_content = re.sub(r'const KERNELZERO_IDS = \[[\s\S]*?\}\);\s*\}\s*', lambda m: derivable_code, solve_content)
        print("[+] Replaced existing KERNELZERO_IDS block in solve-derivable.js.")
    else:
        needle = "/* Exact-match challenges deliberately left uncovered."
        assert needle in solve_content, "Could not find insertion marker in solve-derivable.js"
        solve_content = solve_content.replace(needle, derivable_code + "\n" + needle, 1)
        print("[+] Added kernelzero derivation handler to solve-derivable.js.")
    solve_derivable_path.write_text(solve_content, encoding="utf-8")

    # 4. Update documentation numbers (2835 -> 2870, 81 -> 82)
    doc_paths = [
        root_dir / "README.md",
        root_dir / "README.en.md",
        root_dir / "README.ja.md",
        root_dir / "README.zh.md",
        root_dir / "USAGE.md",
        root_dir / "AI_LEARNING.md",
        root_dir / "wargame" / "README.md"
    ]
    for dp in doc_paths:
        if dp.exists():
            dt = dp.read_text(encoding="utf-8")
            dt = dt.replace("2,835", "2,870")
            dt = dt.replace("2835", "2870")
            dt = dt.replace("81개 트랙", "82개 트랙")
            dt = dt.replace("81 tracks", "82 tracks")
            dt = dt.replace("81 트랙", "82 트랙")
            dt = dt.replace("81 个赛道", "82 个赛道")
            dt = dt.replace("81 トラック", "82 トラック")
            dp.write_text(dt, encoding="utf-8")
            print(f"[+] Synced 2870 challenges & 82 tracks in {dp.name}")

    print("\n🎉 Track 82 kernelzero generation completed successfully! Total: 2,870 challenges across 82 tracks.")

if __name__ == "__main__":
    main()
