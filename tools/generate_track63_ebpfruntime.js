#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeHash(id) {
  const ident = id.replace(/^t\d_/, '') + "_v1";
  const flag = "FLAG{" + crypto.createHash('sha256').update(ident).digest('hex').substring(0, 20) + "}";
  return crypto.createHash('sha256').update(flag).digest('hex');
}

const challengesDef = [
  // Tier 0 (2)
  {
    id: "t0_ebpfruntime_fundamentals_kernel_vm_architecture",
    tier: 0, cat: "ebpf", track: "ebpfruntime", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF 커널 가상머신 구조와 11개 64비트 레지스터 체계", en: "eBPF Kernel VM Architecture & 11 64-bit Register System" },
    prompt: {
      ko: "Linux 커널 내부의 샌드박스 가상머신(eBPF VM)에서 R0~R10 레지스터 역할 및 안전한 바이트코드 실행 원리를 분석합니다.\n지정된 식별자 `ebpfruntime_fundamentals_kernel_vm_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_fundamentals_kernel_vm_architecture_v1\") 앞 20자리}`",
      en: "Examine the eBPF sandboxed virtual machine inside the Linux kernel, analyzing R0-R10 registers and safe bytecode execution.\nCompute the first 20 hex characters of SHA256(\"ebpfruntime_fundamentals_kernel_vm_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_fundamentals_kernel_vm_architecture_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["R0은 반환값, R1~R5는 함수 인자, R10은 읽기 전용 스택 포인터입니다.", "식별자 `ebpfruntime_fundamentals_kernel_vm_architecture_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["R0 stores return values, R1-R5 are call args, and R10 is the read-only frame pointer.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_fundamentals_kernel_vm_architecture_v1\")."]
    }
  },
  {
    id: "t0_ebpfruntime_verifier_safety_guarantees",
    tier: 0, cat: "verifier", track: "ebpfruntime", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF Verifier 정적 검증과 무한루프 및 커널 패닉 차단 원리", en: "eBPF Verifier Static Analysis & Loop/Panic Prevention Principles" },
    prompt: {
      ko: "eBPF 바이트코드가 로드될 때 모든 실행 경로(DAG)를 시뮬레이션하여 메모리 접근 위반과 미초기화 변수를 차단하는 Verifier 원리를 분석합니다.\n지정된 식별자 `ebpfruntime_verifier_safety_guarantees_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_verifier_safety_guarantees_v1\") 앞 20자리}`",
      en: "Analyze how the eBPF Verifier statically simulates all Directed Acyclic Graph paths to prevent out-of-bounds access and kernel panics.\nCompute the first 20 hex characters of SHA256(\"ebpfruntime_verifier_safety_guarantees_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_verifier_safety_guarantees_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Verifier는 커널 메모리 안전성을 보장하기 위해 프로그램 복잡도와 스택 사용량을 엄격히 제한합니다.", "식별자 `ebpfruntime_verifier_safety_guarantees_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The verifier enforces complexity limits and stack bound checks to prevent kernel crashes.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_verifier_safety_guarantees_v1\")."]
    }
  },

  // Tier 1 (8)
  {
    id: "t1_ebpfruntime_kprobe_dynamic_tracing",
    tier: 1, cat: "kprobe", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "kprobe/kretprobe를 통한 동적 커널 함수 진입 및 반환 인터셉트", en: "Dynamic Kernel Function Interception via kprobe/kretprobe" },
    prompt: {
      ko: "kprobe를 활용하여 임의의 커널 함수 진입점에 브레이크포인트를 삽입하고 레지스터 상태를 추출하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_kprobe_dynamic_tracing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_kprobe_dynamic_tracing_v1\") 앞 20자리}`",
      en: "Examine how kprobes insert dynamic breakpoints at arbitrary kernel function entrypoints to capture telemetry.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_kprobe_dynamic_tracing_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_kprobe_dynamic_tracing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["kprobe는 시스템콜 외에도 커널 내부 서브시스템의 비공개 심볼을 계측할 수 있습니다.", "식별자 `ebpfruntime_kprobe_dynamic_tracing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["kprobes allow instrumentation of internal non-exported kernel symbols.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_kprobe_dynamic_tracing_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_tracepoint_static_syscall_telemetry",
    tier: 1, cat: "tracepoint", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "tracepoint 정적 시스템콜 계측 및 sys_enter_execve 감시", en: "Static Syscall Instrumentation & sys_enter_execve Tracing" },
    prompt: {
      ko: "커널 소스에 정의된 안정적인 tracepoint를 통해 커널 버전 간 ABI 호환성을 유지하며 `sys_enter_execve` 이벤트를 캡처하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_tracepoint_static_syscall_telemetry_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_tracepoint_static_syscall_telemetry_v1\") 앞 20자리}`",
      en: "Analyze tracepoint stability across kernel versions when capturing `sys_enter_execve` execution parameters.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_tracepoint_static_syscall_telemetry_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_tracepoint_static_syscall_telemetry_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tracepoint는 브레이크포인트 인터럽트 오버헤드 없이 고속 실행을 보장합니다.", "식별자 `ebpfruntime_tracepoint_static_syscall_telemetry_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Tracepoints offer high performance without breakpoint trap overhead.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_tracepoint_static_syscall_telemetry_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_fentry_fexit_trampoline_performance",
    tier: 1, cat: "fentry", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "fentry/fexit BPF 트램펄린 기술과 Zero-Overhead 함수 후킹", en: "fentry/fexit BPF Trampoline & Zero-Overhead Function Hooking" },
    prompt: {
      ko: "BPF 트램펄린을 통해 kprobe의 INT3 인터럽트 지연을 제거하고 네이티브 직접 호출 성능을 제공하는 fentry/fexit 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_fentry_fexit_trampoline_performance_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_fentry_fexit_trampoline_performance_v1\") 앞 20자리}`",
      en: "Investigate how fentry/fexit harnesses BPF trampolines to achieve zero-overhead native function interception.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_fentry_fexit_trampoline_performance_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_fentry_fexit_trampoline_performance_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["fentry는 커널 함수 인자를 x86 레지스터 규약에 맞춰 직접 읽을 수 있습니다.", "식별자 `ebpfruntime_fentry_fexit_trampoline_performance_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["fentry accesses function arguments directly according to native calling conventions.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_fentry_fexit_trampoline_performance_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_bpf_maps_array_hash_storage",
    tier: 1, cat: "bpfmap", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "BPF Map 메모리 모델: Hash, Array, RingBuffer 상태 공유", en: "BPF Map Memory Models: Hash, Array & State Sharing" },
    prompt: {
      ko: "커널 eBPF 프로그램과 사용자 공간 보안 데몬 간에 상태를 양방향으로 공유하는 BPF_MAP_TYPE_HASH 및 ARRAY 맵 구조를 분석합니다.\n지정된 식별자 `ebpfruntime_bpf_maps_array_hash_storage_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpf_maps_array_hash_storage_v1\") 앞 20자리}`",
      en: "Examine BPF map types (HASH, ARRAY) used for bidirectional communication between kernel space and user space.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpf_maps_array_hash_storage_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpf_maps_array_hash_storage_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["BPF 맵은 `bpf_map_lookup_elem`, `bpf_map_update_elem` 헬퍼 함수를 통해 접근합니다.", "식별자 `ebpfruntime_bpf_maps_array_hash_storage_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["BPF maps are queried via `bpf_map_lookup_elem` and updated safely.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpf_maps_array_hash_storage_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_bpf_ring_buffer_event_streaming",
    tier: 1, cat: "ringbuf", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "BPF Ring Buffer 저지연 다중 CPU 제로카피 이벤트 스트리밍", en: "BPF Ring Buffer Low-Latency Multi-CPU Zero-Copy Event Streaming" },
    prompt: {
      ko: "기존 perf buffer의 CPU별 메모리 낭비와 이벤트 순서 역전문제를 해결한 BPF RingBuffer 메모리 공유 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_bpf_ring_buffer_event_streaming_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpf_ring_buffer_event_streaming_v1\") 앞 20자리}`",
      en: "Analyze BPF ring buffers providing ordered, zero-copy event streaming across multi-core systems.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpf_ring_buffer_event_streaming_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpf_ring_buffer_event_streaming_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["RingBuffer는 epoll과 연동되어 유저 공간 대기 지연을 극적으로 단축합니다.", "식별자 `ebpfruntime_bpf_ring_buffer_event_streaming_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Ring buffers integrate with epoll for efficient user-space event consumption.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpf_ring_buffer_event_streaming_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_lsm_bpf_security_module_hooks",
    tier: 1, cat: "lsm", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Linux Security Module (LSM) BPF 프로그래머블 보안 후킹 인터페이스", en: "Linux Security Module (LSM) BPF Programmable Security Hooks" },
    prompt: {
      ko: "커널 5.7+에 도입된 eBPF LSM을 활용하여 커널 보안 후크 지점에서 정책 판정을 내리고 `-EPERM`을 반환하는 메커니즘을 분석합니다.\n지정된 식별자 `ebpfruntime_lsm_bpf_security_module_hooks_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_lsm_bpf_security_module_hooks_v1\") 앞 20자리}`",
      en: "Investigate eBPF LSM hooks (Linux 5.7+) allowing arbitrary in-kernel security decisions and returning `-EPERM`.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_lsm_bpf_security_module_hooks_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_lsm_bpf_security_module_hooks_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LSM BPF는 `bpf_lsm_*` 함수군을 통해 파일 오픈, 태스크 실행, 소켓 바인딩을 통제합니다.", "식별자 `ebpfruntime_lsm_bpf_security_module_hooks_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["LSM BPF intercepts file opening, task creation, and network binding.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_lsm_bpf_security_module_hooks_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_xdp_packet_filtering_driver_level",
    tier: 1, cat: "xdp", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "XDP(eXpress Data Path) 네트워크 드라이버 레벨 인라인 패킷 필터링", en: "XDP (eXpress Data Path) Driver-Level Inline Packet Filtering" },
    prompt: {
      ko: "sk_buff 소켓 버퍼 할당 이전 NIC 드라이버 수신 링에서 즉시 패킷을 파싱하고 `XDP_DROP`을 수행하는 초고속 방어 원리를 분석합니다.\n지정된 식별자 `ebpfruntime_xdp_packet_filtering_driver_level_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_xdp_packet_filtering_driver_level_v1\") 앞 20자리}`",
      en: "Examine XDP packet filtering at the network driver ring before `sk_buff` allocation, executing line-rate `XDP_DROP`.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_xdp_packet_filtering_driver_level_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_xdp_packet_filtering_driver_level_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["XDP는 테라비트급 DoS/DDoS 공격 패킷을 커널 네트워크 스택 진입 전에 차단합니다.", "식별자 `ebpfruntime_xdp_packet_filtering_driver_level_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["XDP drops multi-gigabit volumetric attack traffic before kernel processing.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_xdp_packet_filtering_driver_level_v1\")."]
    }
  },
  {
    id: "t1_ebpfruntime_tc_traffic_control_egress_inspection",
    tier: 1, cat: "tc", track: "ebpfruntime", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Traffic Control(TC) BPF 서브시스템과 이그레스 데이터 유출 제어", en: "Traffic Control (TC) BPF Subsystem & Egress Exfiltration Control" },
    prompt: {
      ko: "리눅스 qdisc 계층에 부착되어 인그레스뿐 아니라 이그레스 트래픽까지 완벽히 검사하고 C2 비콘 통신을 차단하는 TC BPF 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_tc_traffic_control_egress_inspection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_tc_traffic_control_egress_inspection_v1\") 앞 20자리}`",
      en: "Analyze TC BPF attached to qdisc layers for comprehensive ingress/egress filtering and C2 beacon blocking.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_tc_traffic_control_egress_inspection_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_tc_traffic_control_egress_inspection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TC BPF는 `TC_ACT_SHOT` 반환을 통해 악성 유출 패킷을 즉시 폐기합니다.", "식별자 `ebpfruntime_tc_traffic_control_egress_inspection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["TC BPF drops exfiltrated packets via `TC_ACT_SHOT` return codes.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_tc_traffic_control_egress_inspection_v1\")."]
    }
  },

  // Tier 2 (12)
  {
    id: "t2_ebpfruntime_falco_rule_engine_userspace_ringbuf",
    tier: 2, cat: "falco", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Falco 룰 엔진의 eBPF 링버퍼 기반 비동기 위협 탐지 모델", en: "Falco Rule Engine Asynchronous Threat Detection Model" },
    prompt: {
      ko: "Sysdig Falco가 eBPF 프로브로부터 시스템콜을 수집하여 사용자 공간 YAML 룰 엔진에서 처리하는 파이프라인과 비동기 지연 한계를 분석합니다.\n지정된 식별자 `ebpfruntime_falco_rule_engine_userspace_ringbuf_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_falco_rule_engine_userspace_ringbuf_v1\") 앞 20자리}`",
      en: "Examine Falco's event pipeline consuming eBPF ring buffers in user space, analyzing asynchronous alert latency.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_falco_rule_engine_userspace_ringbuf_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_falco_rule_engine_userspace_ringbuf_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Falco는 풍부한 필터 매크로를 제공하지만 인커널 동기 차단 기능은 제한적입니다.", "식별자 `ebpfruntime_falco_rule_engine_userspace_ringbuf_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Falco excels at flexible rule syntax while synchronous in-kernel enforcement requires Tetragon.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_falco_rule_engine_userspace_ringbuf_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_tetragon_in_kernel_synchronous_enforce",
    tier: 2, cat: "tetragon", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Cilium Tetragon 인커널 실시간 동기 차단 엔진 아키텍처", en: "Cilium Tetragon In-Kernel Synchronous Enforcement Architecture" },
    prompt: {
      ko: "Tetragon이 사용자 공간 컨텍스트 전환 없이 커널 eBPF 가상머신 내부에서 보안 정책을 즉시 평가하고 차단하는 실시간 엔진 구조를 분석합니다.\n지정된 식별자 `ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1\") 앞 20자리}`",
      en: "Analyze how Cilium Tetragon evaluates security policies directly inside the kernel eBPF VM without user-space delays.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tetragon은 공격자가 이벤트를 지우거나 우회하기 전에 인커널에서 동기식으로 무력화합니다.", "식별자 `ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Tetragon eliminates TOCTOU race conditions by executing inline kernel verdicts.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_tetragon_in_kernel_synchronous_enforce_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_tracing_policy_crd_manifest",
    tier: 2, cat: "tracingpolicy", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Kubernetes TracingPolicy CRD 매니페스트 설계 및 셀렉터 구성", en: "Kubernetes TracingPolicy CRD Manifest Design & Selectors" },
    prompt: {
      ko: "Kubernetes 환경에서 네임스페이스 및 파드 셀렉터를 기반으로 동적 kprobe/tracepoint를 배포하는 TracingPolicy CRD 사양을 분석합니다.\n지정된 식별자 `ebpfruntime_tracing_policy_crd_manifest_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_tracing_policy_crd_manifest_v1\") 앞 20자리}`",
      en: "Examine TracingPolicy CRD manifests deploying namespace-aware kprobe/tracepoint filters across K8s clusters.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_tracing_policy_crd_manifest_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_tracing_policy_crd_manifest_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TracingPolicy는 kprobes 섹션에 call 심볼과 matchArgs 셀렉터를 정의합니다.", "식별자 `ebpfruntime_tracing_policy_crd_manifest_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["TracingPolicy CRDs specify target symbols, argument matches, and namespace scopes.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_tracing_policy_crd_manifest_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_sigkill_in_kernel_process_termination",
    tier: 2, cat: "sigkill", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "인커널 SIGKILL 사살 메커니즘과 권한 상승 프로세스 강제 종료", en: "In-Kernel SIGKILL Mechanism & Privilege Escalation Termination" },
    prompt: {
      ko: "eBPF 헬퍼 `bpf_send_signal`을 호출하여 악성 권한 상승을 시도하는 프로세스를 시그널 핸들러 가로채기 없이 즉각 사살하는 원리를 분석합니다.\n지정된 식별자 `ebpfruntime_sigkill_in_kernel_process_termination_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_sigkill_in_kernel_process_termination_v1\") 앞 20자리}`",
      en: "Analyze the in-kernel `bpf_send_signal(SIGKILL)` mechanism immediately terminating processes upon privilege escalation.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_sigkill_in_kernel_process_termination_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_sigkill_in_kernel_process_termination_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SIGKILL(9)은 사용자 공간 프로세스에서 무시하거나 캐치할 수 없는 강제 종료 시그널입니다.", "식별자 `ebpfruntime_sigkill_in_kernel_process_termination_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SIGKILL cannot be caught or ignored by user processes.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_sigkill_in_kernel_process_termination_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_lsm_file_open_credential_containment",
    tier: 2, cat: "lsmcontain", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "bpf_lsm_file_open 커널 훅을 통한 /etc/shadow 및 SSH 키 무단 접근 봉쇄", en: "bpf_lsm_file_open Kernel Hook Blocking /etc/shadow Access" },
    prompt: {
      ko: "VFS 계층에서 `file_open` LSM 훅을 가로채어 컨테이너 보안 컨텍스트에 속하지 않은 프로세스가 호스트 `/etc/shadow`를 열 때 `-EPERM`을 강제하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_lsm_file_open_credential_containment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_lsm_file_open_credential_containment_v1\") 앞 20자리}`",
      en: "Investigate `bpf_lsm_file_open` blocking unauthorized reads of `/etc/shadow` by returning `-EPERM` at the VFS layer.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_lsm_file_open_credential_containment_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_lsm_file_open_credential_containment_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LSM 훅은 프로세스의 자격증명(cred) 구조체와 파일 inode 경로를 대조합니다.", "식별자 `ebpfruntime_lsm_file_open_credential_containment_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The LSM hook cross-checks the task credentials with the requested file inode.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_lsm_file_open_credential_containment_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_namespace_escape_mitigation_setns",
    tier: 2, cat: "nsescape", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "sys_enter_setns 시스템콜 후킹을 통한 컨테이너 네임스페이스 이탈 탐지", en: "sys_enter_setns Syscall Hooking Preventing Namespace Breakouts" },
    prompt: {
      ko: "특권 컨테이너에서 `setns` 시스템콜을 호출하여 호스트 PID 또는 마운트 네임스페이스로 탈출하려는 공격 패턴을 eBPF로 차단하는 원리를 분석합니다.\n지정된 식별자 `ebpfruntime_namespace_escape_mitigation_setns_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_namespace_escape_mitigation_setns_v1\") 앞 20자리}`",
      en: "Analyze eBPF mitigation intercepting `setns` syscalls when privileged containers attempt to break into the host namespace.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_namespace_escape_mitigation_setns_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_namespace_escape_mitigation_setns_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["네임스페이스 전환 인자(nstype)와 타깃 fd의 네임스페이스 ID를 비교 검증합니다.", "식별자 `ebpfruntime_namespace_escape_mitigation_setns_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Validates target fd namespace IDs against the caller's restricted container namespace.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_namespace_escape_mitigation_setns_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_reverse_shell_telemetry_parent_child",
    tier: 2, cat: "revshell", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "부모-자식 프로세스 트리 역추적을 통한 컨테이너 내부 리버스 셸 탐지", en: "Reverse Shell Detection via Parent-Child Process Lineage Tracing" },
    prompt: {
      ko: "웹 서버(nginx, gunicorn) 프로세스가 예기치 않게 대화형 셸(`/bin/sh`, `/bin/bash`)을 스폰하는 변칙 실행 계통을 실시간으로 추적하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_reverse_shell_telemetry_parent_child_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_reverse_shell_telemetry_parent_child_v1\") 앞 20자리}`",
      en: "Examine how eBPF traces process lineage to detect anomalous interactive shell spawns from daemon parents.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_reverse_shell_telemetry_parent_child_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_reverse_shell_telemetry_parent_child_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`bpf_get_current_task()`를 통해 부모 프로세스의 task_struct와 커맨드라인을 역산합니다.", "식별자 `ebpfruntime_reverse_shell_telemetry_parent_child_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["eBPF traverses task_struct pointers to inspect parent process credentials and executable paths.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_reverse_shell_telemetry_parent_child_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_privilege_escalation_commit_creds",
    tier: 2, cat: "commitcreds", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "commit_creds 커널 심볼 계측 및 루트 자격증명 변조 차단", en: "commit_creds Kernel Symbol Instrumentation Blocking Credential Tampering" },
    prompt: {
      ko: "권한 상승 익스플로잇이 `commit_creds(prepare_kernel_cred(0))`를 호출하여 UID 0으로 전환하기 직전에 인자 구조체를 검증하고 차단하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_privilege_escalation_commit_creds_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_privilege_escalation_commit_creds_v1\") 앞 20자리}`",
      en: "Analyze kernel symbol interception on `commit_creds` thwarting root credential assignments before exploitation finishes.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_privilege_escalation_commit_creds_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_privilege_escalation_commit_creds_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tetragon TracingPolicy는 `commit_creds`의 첫 번째 인자(cred_struct)를 직접 검사합니다.", "식별자 `ebpfruntime_privilege_escalation_commit_creds_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The policy inspects the cred_struct pointer argument before permission transition.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_privilege_escalation_commit_creds_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_co_re_btf_portable_programs",
    tier: 2, cat: "corebtf", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "CO-RE(Compile Once - Run Everywhere)와 BTF(BPF Type Format) 이식성", en: "CO-RE (Compile Once - Run Everywhere) & BTF Portability" },
    prompt: {
      ko: "커널 헤더 없이도 Clang과 BTF를 활용하여 다양한 커널 구조체 오프셋에 자동으로 리로케이션하는 CO-RE 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_co_re_btf_portable_programs_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_co_re_btf_portable_programs_v1\") 앞 20자리}`",
      en: "Investigate CO-RE and BTF enabling eBPF programs to relocate struct offsets dynamically across heterogeneous Linux kernels.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_co_re_btf_portable_programs_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_co_re_btf_portable_programs_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`BPF_CORE_READ` 매크로는 커널 구조체 필드 위치가 바뀌어도 안전하게 역참조합니다.", "식별자 `ebpfruntime_co_re_btf_portable_programs_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["`BPF_CORE_READ` transparently handles varying struct member offsets at runtime.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_co_re_btf_portable_programs_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_bpftool_prog_dump_memory_audit",
    tier: 2, cat: "progdump", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "bpftool prog dump를 통한 활성 BPF 바이트코드 디스어셈블리 감사", en: "bpftool prog dump Active BPF Bytecode Disassembly Audit" },
    prompt: {
      ko: "시스템에 로드된 모든 BPF 프로그램의 JIT 기계어 및 eBPF 인스트럭션을 추출하여 악성 후킹 코드를 식별하는 메모리 포렌식 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_bpftool_prog_dump_memory_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpftool_prog_dump_memory_audit_v1\") 앞 20자리}`",
      en: "Examine memory triage using `bpftool prog dump xlated` to inspect loaded eBPF instructions for unauthorized hooks.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpftool_prog_dump_memory_audit_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpftool_prog_dump_memory_audit_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`bpftool prog show`로 프로그램 ID를 확인한 후 `prog dump jited`로 디어셈블할 수 있습니다.", "식별자 `ebpfruntime_bpftool_prog_dump_memory_audit_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Identify target prog IDs via `bpftool prog show` and disassemble instructions.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpftool_prog_dump_memory_audit_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_bpftool_map_dump_kernel_inspection",
    tier: 2, cat: "mapdump", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "bpftool map dump를 통한 은닉 BPF 맵 키-값 엔트리 추출", en: "bpftool map dump Carving Hidden BPF Map Key-Value Entries" },
    prompt: {
      ko: "BPF 맵 내부의 은닉 프로세스 화이트리스트, 필터링 문자열, C2 통신 파라미터를 덤프하여 메모리 변조 흔적을 역추적하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_bpftool_map_dump_kernel_inspection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpftool_map_dump_kernel_inspection_v1\") 앞 20자리}`",
      en: "Analyze techniques dumping BPF map entries to uncover hidden process whitelists and C2 parameters.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpftool_map_dump_kernel_inspection_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpftool_map_dump_kernel_inspection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`bpftool map dump id <ID>` 명령어로 맵의 모든 키와 페이로드를 JSON/HEX로 열람합니다.", "식별자 `ebpfruntime_bpftool_map_dump_kernel_inspection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inspect map keys and values formatted in JSON via `bpftool map dump`.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpftool_map_dump_kernel_inspection_v1\")."]
    }
  },
  {
    id: "t2_ebpfruntime_cgroup_bpf_container_confinement",
    tier: 2, cat: "cgroupbpf", track: "ebpfruntime", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "cgroup-bpf 기반 계층적 컨테이너 네트워크 및 시스템콜 구속", en: "cgroup-bpf Hierarchical Container Network & Syscall Confinement" },
    prompt: {
      ko: "특정 cgroup v2 디렉터리에 eBPF 프로그램을 부착하여 컨테이너 워크로드 단위로 egress/ingress 네트워크 및 소켓 생성을 엄격히 제한하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_cgroup_bpf_container_confinement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_cgroup_bpf_container_confinement_v1\") 앞 20자리}`",
      en: "Examine cgroup-bpf attachments to cgroup v2 hierarchies enforcing egress/ingress restrictions on container pods.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_cgroup_bpf_container_confinement_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_cgroup_bpf_container_confinement_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["cgroup-bpf는 하위 프로세스로 상속되므로 자식 프로세스의 무단 포트 바인딩도 통제됩니다.", "식별자 `ebpfruntime_cgroup_bpf_container_confinement_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["cgroup-bpf filters inherit to child processes, securing ephemeral sockets.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_cgroup_bpf_container_confinement_v1\")."]
    }
  },

  // Tier 3 (8)
  {
    id: "t3_ebpfruntime_shadow_rootkit_getdents64_cloaking",
    tier: 3, cat: "rootkit", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "sys_enter_getdents64 디렉터리 엔트리 변조 및 Shadow BPF Rootkit 해부", en: "sys_enter_getdents64 Directory Cloaking & Shadow BPF Rootkit Triage" },
    prompt: {
      ko: "`getdents64` 시스템콜 반환 시점에 `linux_dirent64` 레코드 오프셋을 건너뛰어 백도어 파일과 프로세스를 은닉하는 Shadow Rootkit 구조를 분석합니다.\n지정된 식별자 `ebpfruntime_shadow_rootkit_getdents64_cloaking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_shadow_rootkit_getdents64_cloaking_v1\") 앞 20자리}`",
      en: "Analyze shadow eBPF rootkits tampering with `linux_dirent64` buffers to conceal stealth implants from directory listings.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_shadow_rootkit_getdents64_cloaking_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_shadow_rootkit_getdents64_cloaking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["루트킷은 `bpf_probe_write_user` 또는 kretprobe 메모리 패칭을 통해 버퍼를 조작합니다.", "식별자 `ebpfruntime_shadow_rootkit_getdents64_cloaking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Rootkits rewrite directory entry lengths in user memory before returning.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_shadow_rootkit_getdents64_cloaking_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_bpfdoor_packet_sniffing_raw_socket",
    tier: 3, cat: "bpfdoor", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "BPFdoor 원시 소켓 매직 패킷 감지 및 방화벽 우회 백도어 분석", en: "BPFdoor Raw Socket Magic Packet Sniffing & Firewall Evasion" },
    prompt: {
      ko: "호스트 iptables 방화벽 규칙 이전에 raw 소켓에 cBPF/eBPF 필터를 부착하여 매직 바이트 시퀀스를 수신하고 역접속을 생성하는 BPFdoor 메커니즘을 분석합니다.\n지정된 식별자 `ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1\") 앞 20자리}`",
      en: "Investigate BPFdoor sniffing raw sockets before iptables evaluation to trigger covert reverse shells.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["BPFdoor는 개방된 수신 포트(Listening Port) 없이도 모든 인바운드 트래픽을 가로챕니다.", "식별자 `ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["BPFdoor operates without open listening ports by filtering raw packet streams.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpfdoor_packet_sniffing_raw_socket_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_kernel_lockdown_integrity_enforcement",
    tier: 3, cat: "lockdown", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Linux Kernel Lockdown 모드와 비특권 BPF 원천 비활성화 하드닝", en: "Linux Kernel Lockdown Mode & Unprivileged BPF Hardening" },
    prompt: {
      ko: "`kernel.unprivileged_bpf_disabled=1` 및 Lockdown 무결성 모드를 통해 kprobe 임의 쓰기 및 BPF 악용 공격 표면을 차단하는 하드닝 정책을 분석합니다.\n지정된 식별자 `ebpfruntime_kernel_lockdown_integrity_enforcement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_kernel_lockdown_integrity_enforcement_v1\") 앞 20자리}`",
      en: "Analyze hardening configurations combining Kernel Lockdown with `kernel.unprivileged_bpf_disabled=1`.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_kernel_lockdown_integrity_enforcement_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_kernel_lockdown_integrity_enforcement_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Lockdown 모드는 루트 사용자라도 커널 메모리를 조작하는 BPF 프로그램 적재를 불허합니다.", "식별자 `ebpfruntime_kernel_lockdown_integrity_enforcement_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Kernel Lockdown prevents even root from loading BPF programs that modify kernel memory.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_kernel_lockdown_integrity_enforcement_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_bpf_cookie_multi_probe_attribution",
    tier: 3, cat: "bpfcookie", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "bpf_cookie를 활용한 다중 프로브 인스턴스 위협 귀속 및 컨텍스트 추적", en: "bpf_cookie Multi-Probe Threat Attribution & Context Tracking" },
    prompt: {
      ko: "동일한 eBPF 핸들러가 여러 kprobe/uprobe에 부착되었을 때 `bpf_get_attach_cookie()`를 호출하여 고유 인스턴스 ID를 구별하는 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_bpf_cookie_multi_probe_attribution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_bpf_cookie_multi_probe_attribution_v1\") 앞 20자리}`",
      en: "Examine `bpf_cookie` usage enabling a single eBPF function to disambiguate multiple probe attachment origins.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_bpf_cookie_multi_probe_attribution_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_bpf_cookie_multi_probe_attribution_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["bpf_cookie는 64비트 사용자 정의 메타데이터를 프로브 링크에 바인딩합니다.", "식별자 `ebpfruntime_bpf_cookie_multi_probe_attribution_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["bpf_cookie binds 64-bit arbitrary identifiers to BPF link attachments.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_bpf_cookie_multi_probe_attribution_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_unpinned_bpf_prog_detection",
    tier: 3, cat: "unpinned", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "익명 및 언핀된(Unpinned) Shadow BPF 프로그램의 커널 메모리 적출", en: "Anonymous & Unpinned Shadow BPF Program Detection in Memory" },
    prompt: {
      ko: "파일시스템(`/sys/fs/bpf`)에 핀되지 않고 열린 파일 디스크립터(fd) 또는 익명 BPF 링크로 잔존하는 은닉 프로그램을 식별하는 포렌식 기법을 분석합니다.\n지정된 식별자 `ebpfruntime_unpinned_bpf_prog_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_unpinned_bpf_prog_detection_v1\") 앞 20자리}`",
      en: "Investigate carving unpinned, anonymous BPF programs persisting in memory through orphaned file descriptors.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_unpinned_bpf_prog_detection_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_unpinned_bpf_prog_detection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`bpftool prog show --json` 출력을 파일시스템 핀 목록과 diff하여 고아 프로그램을 찾습니다.", "식별자 `ebpfruntime_unpinned_bpf_prog_detection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Cross-reference `bpftool prog show` with bpffs pinned objects to triangulate shadow progs.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_unpinned_bpf_prog_detection_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_tail_call_prog_chain_complexity",
    tier: 3, cat: "tailcall", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "BPF Tail Call 체이닝 공격 표면과 최대 호출 깊이(33회) 제약", en: "BPF Tail Call Chaining Attack Surfaces & 33-Call Depth Constraints" },
    prompt: {
      ko: "`bpf_tail_call`을 통해 프로그램을 연속 점프시키며 탐지를 우회하거나 Verifier 검증 경계를 분할하는 기법과 최대 33회 호출 제한을 분석합니다.\n지정된 식별자 `ebpfruntime_tail_call_prog_chain_complexity_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_tail_call_prog_chain_complexity_v1\") 앞 20자리}`",
      en: "Analyze BPF tail calls chained across multiple programs and the kernel's 33-tail-call depth safety limit.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_tail_call_prog_chain_complexity_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_tail_call_prog_chain_complexity_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tail call은 스택 프레임을 재사용하므로 무한 재귀 공격을 방지하기 위해 카운터를 둡니다.", "식별자 `ebpfruntime_tail_call_prog_chain_complexity_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Tail calls reuse stack frames, bounded by kernel call counters to prevent stack exhaustion.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_tail_call_prog_chain_complexity_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_mitre_attck_matrix_ebpf_mapping",
    tier: 3, cat: "mitre", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "MITRE ATT&CK T1055.001 프로세스 인젝션 및 T1611 탈출 매핑", en: "MITRE ATT&CK T1055.001 & T1611 Container Escape Mapping" },
    prompt: {
      ko: "eBPF 센서 이벤트를 MITRE ATT&CK T1055.001(DLL 인젝션) 및 T1611(Escape to Host) 기법에 실시간 매핑하여 관제하는 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1\") 앞 20자리}`",
      en: "Map eBPF telemetry events to MITRE ATT&CK T1055.001 (Process Injection) and T1611 (Escape to Host) techniques.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`ptrace` 호출 및 `bpf_lsm_file_open` 거부 이벤트를 SIEM에 실시간 연동합니다.", "식별자 `ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Correlation rules translate denied kernel operations directly into ATT&CK tactic tags.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_mitre_attck_matrix_ebpf_mapping_v1\")."]
    }
  },
  {
    id: "t3_ebpfruntime_soar_automated_quarantine_playbook",
    tier: 3, cat: "soar", track: "ebpfruntime", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF 위협 이벤트 기반 SOAR 워크로드 자동 네트워크 격리 플레이북", en: "eBPF Event-Driven SOAR Automated Workload Isolation Playbook" },
    prompt: {
      ko: "Tetragon이 보안 위배 이벤트를 감지했을 때 Kubernetes NetworkPolicy를 동적으로 패치하여 감염된 파드를 0초 만에 격리하는 플레이북을 분석합니다.\n지정된 식별자 `ebpfruntime_soar_automated_quarantine_playbook_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_soar_automated_quarantine_playbook_v1\") 앞 20자리}`",
      en: "Investigate event-driven SOAR playbooks dynamically applying K8s NetworkPolicies to isolate breached pods upon eBPF signals.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_soar_automated_quarantine_playbook_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_soar_automated_quarantine_playbook_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SOAR 엔진은 Tetragon JSON 이벤트를 웹훅으로 수신하고 즉시 격리 라벨을 부여합니다.", "식별자 `ebpfruntime_soar_automated_quarantine_playbook_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The SOAR webhook receives Tetragon telemetry and tags infected pods with isolation labels.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_soar_automated_quarantine_playbook_v1\")."]
    }
  },

  // Tier 4 (5)
  {
    id: "t4_ebpfruntime_full_kernel_rootkit_carve_pipeline",
    tier: 4, cat: "carve", track: "ebpfruntime", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "인커널 은닉 eBPF 바이트코드 메모리 카빙 및 복원 파이프라인", en: "In-Kernel Hidden eBPF Bytecode Memory Carving & Recovery Pipeline" },
    prompt: {
      ko: "커널 메모리에서 unlinked BPF 프로그램 구조체를 스캔하여 악성 JIT 기계어를 카빙하고 바이트코드를 재구성하는 엔드포인트 포렌식 파이프라인을 분석합니다.\n지정된 식별자 `ebpfruntime_full_kernel_rootkit_carve_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_full_kernel_rootkit_carve_pipeline_v1\") 앞 20자리}`",
      en: "Analyze memory forensics pipelines scanning kernel memory to carve unlinked eBPF programs and reconstruct bytecode.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_full_kernel_rootkit_carve_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_full_kernel_rootkit_carve_pipeline_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`struct bpf_prog` 헤더의 매직 넘버와 태그 해시를 기반으로 커널 슬랩 메모리를 스캔합니다.", "식별자 `ebpfruntime_full_kernel_rootkit_carve_pipeline_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Scans kernel slab memory matching `struct bpf_prog` header descriptors.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_full_kernel_rootkit_carve_pipeline_v1\")."]
    }
  },
  {
    id: "t4_ebpfruntime_runtime_lsm_zero_trust_mesh",
    tier: 4, cat: "mesh", track: "ebpfruntime", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF LSM 기반 클라우드 네이티브 제로트러스트 런타임 서비스 메시", en: "eBPF LSM Cloud-Native Zero Trust Runtime Service Mesh" },
    prompt: {
      ko: "사이드카 프록시(Envoy) 없이 커널 레벨 eBPF 소켓 계층에서 상호 mTLS 인증 및 암호화를 투명하게 처리하는 제로트러스트 서비스 메시 아키텍처를 분석합니다.\n지정된 식별자 `ebpfruntime_runtime_lsm_zero_trust_mesh_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_runtime_lsm_zero_trust_mesh_v1\") 앞 20자리}`",
      en: "Investigate sidecarless zero-trust service meshes offloading mTLS and microsegmentation directly to kernel eBPF.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_runtime_lsm_zero_trust_mesh_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_runtime_lsm_zero_trust_mesh_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Cilium eBPF는 `sockmap` 및 `sk_msg` 프로그램을 통해 TCP 소켓 버퍼를 제로카피 리다이렉션합니다.", "식별자 `ebpfruntime_runtime_lsm_zero_trust_mesh_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Utilizes `sockmap` and `sk_msg` programs for zero-copy socket redirection in kernel space.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_runtime_lsm_zero_trust_mesh_v1\")."]
    }
  },
  {
    id: "t4_ebpfruntime_kernel_verifier_bypass_cve_analysis",
    tier: 4, cat: "cve", track: "ebpfruntime", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF Verifier 취약점(CVE-2021-3490 등) 포인터 연산 결함 심층 분석", en: "eBPF Verifier Vulnerability (CVE-2021-3490) Pointer Arithmetic Analysis" },
    prompt: {
      ko: "Verifier의 32비트/64비트 ALU 연산 부호 확장(Sign Extension) 버그로 인해 포인터 경계 검증을 우회하고 커널 임의 읽기/쓰기를 달성한 CVE 메커니즘을 분석합니다.\n지정된 식별자 `ebpfruntime_kernel_verifier_bypass_cve_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_kernel_verifier_bypass_cve_analysis_v1\") 앞 20자리}`",
      en: "Examine eBPF Verifier bugs (such as CVE-2021-3490) in 32-bit/64-bit ALU bounds tracking allowing arbitrary kernel R/W.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_kernel_verifier_bypass_cve_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_kernel_verifier_bypass_cve_analysis_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["`tnum_intersect` 및 `scalar32_min_max_sub` 연산 결함이 악용되었습니다.", "식별자 `ebpfruntime_kernel_verifier_bypass_cve_analysis_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Root cause stems from incorrect 32-bit scalar min/max bound updates during ALU operations.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_kernel_verifier_bypass_cve_analysis_v1\")."]
    }
  },
  {
    id: "t4_ebpfruntime_autonomous_ebpf_threat_hunting_agent",
    tier: 4, cat: "agent", track: "ebpfruntime", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "자율 커널 위협 헌팅 에이전트와 동적 eBPF 센서 자율 생성 아키텍처", en: "Autonomous Kernel Threat Hunting Agent & Dynamic eBPF Synthesis" },
    prompt: {
      ko: "AI 보안 에이전트가 런타임 이상 징후를 감지하고 즉석에서 특화된 eBPF 센서 C 코드를 컴파일하여 커널에 동적 배포하는 차세대 능동 방어 체계를 분석합니다.\n지정된 식별자 `ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1\") 앞 20자리}`",
      en: "Analyze autonomous defense agents synthesizing and compiling targeted eBPF probes on the fly upon anomaly detection.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["에이전트는 LLVM/Clang libbpf API를 호출하여 즉각 커널 훅을 로드하고 증거를 수집합니다.", "식별자 `ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The agent invokes libbpf programmatically to attach targeted probes and stream artifacts.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_autonomous_ebpf_threat_hunting_agent_v1\")."]
    }
  },
  {
    id: "t4_ebpfruntime_capstone_full_spectrum_runtime_defense",
    tier: 4, cat: "capstone", track: "ebpfruntime", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "클라우드 네이티브 eBPF 엔터프라이즈 런타임 보안 캡스톤 종합 분석", en: "Cloud-Native eBPF Enterprise Runtime Defense Capstone" },
    prompt: {
      ko: "kprobe 시스템콜 텔레메트리, LSM 실시간 파일 차단, Tetragon TracingPolicy 권한 상승 차단, Shadow Rootkit 무결성 감사를 융합한 엔터프라이즈 전면 방어 캡스톤을 분석합니다.\n지정된 식별자 `ebpfruntime_capstone_full_spectrum_runtime_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"ebpfruntime_capstone_full_spectrum_runtime_defense_v1\") 앞 20자리}`",
      en: "Synthesize syscall telemetry, eBPF LSM containment, Tetragon TracingPolicy SIGKILL, and shadow rootkit audit into unified enterprise defense.\nCompute first 20 hex chars of SHA256(\"ebpfruntime_capstone_full_spectrum_runtime_defense_v1\").\n\nFormat: `FLAG{SHA256(\"ebpfruntime_capstone_full_spectrum_runtime_defense_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["커널 옵저버빌리티와 인라인 차단, 포렌식 감사가 결합된 다계층 eBPF 방어 체계입니다.", "식별자 `ebpfruntime_capstone_full_spectrum_runtime_defense_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Integrates multi-layer kernel observability, proactive enforcement, and forensic integrity audits.", "Extract first 20 hex chars of SHA256(\"ebpfruntime_capstone_full_spectrum_runtime_defense_v1\")."]
    }
  }
];

// Compute hashes
for (const ch of challengesDef) {
  ch.hash = computeHash(ch.id);
}

const outputPath = path.join(__dirname, 'track63_challenges.json');
fs.writeFileSync(outputPath, JSON.stringify(challengesDef, null, 2), 'utf8');
console.log(`Generated ${challengesDef.length} challenges for Track 63 (ebpfruntime) -> ${outputPath}`);
