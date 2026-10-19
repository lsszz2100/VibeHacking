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
    id: "t0_linuxhard_kernel_user_space_boundary_isolation",
    tier: 0, cat: "kspp", track: "linuxhard", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "리눅스 커널-유저 공간 경계 분리와 시스템콜 게이트웨이", en: "Linux Kernel-User Space Boundary & Syscall Gateway Isolation" },
    prompt: {
      ko: "CPU 링 0(커널 모드)과 링 3(유저 모드) 간의 특권 분리 아키텍처 및 시스템콜 진입점 인터럽트 게이트웨이 보안 메커니즘을 분석합니다.\n지정된 식별자 `linuxhard_kernel_user_space_boundary_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kernel_user_space_boundary_isolation_v1\") 앞 20자리}`",
      en: "Analyze CPU Ring 0 (kernel space) vs Ring 3 (user space) hardware privilege isolation and the syscall gate dispatch security architecture.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kernel_user_space_boundary_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kernel_user_space_boundary_isolation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["유저 프로세스는 syscall 명령어를 통해서만 커널 공간으로 안전하게 컨텍스트를 전환할 수 있습니다.", "식별자 `linuxhard_kernel_user_space_boundary_isolation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["User processes transition execution context into kernel space strictly through supervised syscall gates.", "Extract first 20 hex chars of SHA256(\"linuxhard_kernel_user_space_boundary_isolation_v1\")."]
    }
  },
  {
    id: "t0_linuxhard_seccomp_strict_vs_filter_mode",
    tier: 0, cat: "seccomp", track: "linuxhard", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "Seccomp Strict 모드와 BPF 필터 모드의 동작 원리 비교", en: "Seccomp Strict Mode vs BPF Filter Mode Operational Comparison" },
    prompt: {
      ko: "오직 read, write, _exit, sigreturn만 허용하는 Seccomp Mode 1(Strict)과 cBPF 바이트코드로 임의 시스템콜을 필터링하는 Mode 2(Filter)를 분석합니다.\n지정된 식별자 `linuxhard_seccomp_strict_vs_filter_mode_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_seccomp_strict_vs_filter_mode_v1\") 앞 20자리}`",
      en: "Compare Seccomp Mode 1 (strict: read, write, exit, sigreturn) with Mode 2 (seccomp-bpf: arbitrary syscall filtering via cBPF programs).\nCompute the first 20 hex characters of SHA256(\"linuxhard_seccomp_strict_vs_filter_mode_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_seccomp_strict_vs_filter_mode_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["prctl PR_SET_SECCOMP 또는 seccomp() 시스템콜을 사용하여 필터 정책을 스레드에 영구 적용합니다.", "식별자 `linuxhard_seccomp_strict_vs_filter_mode_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Seccomp filter policies are permanently attached to threads using prctl(PR_SET_SECCOMP) or seccomp() syscall.", "Extract first 20 hex chars of SHA256(\"linuxhard_seccomp_strict_vs_filter_mode_v1\")."]
    }
  },

  // Tier 1 (6)
  {
    id: "t1_linuxhard_bpf_instruction_set_in_seccomp",
    tier: 1, cat: "seccomp", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Seccomp-BPF 클래식 BPF 명령어 셋과 반환 액션 코드", en: "Seccomp-BPF Classic BPF Instruction Set & Return Actions" },
    prompt: {
      ko: "seccomp_data 구조체에서 시스템콜 번호와 아키텍처를 검증하고 SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS를 반환하는 BPF 프로그램을 분석합니다.\n지정된 식별자 `linuxhard_bpf_instruction_set_in_seccomp_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_bpf_instruction_set_in_seccomp_v1\") 앞 20자리}`",
      en: "Evaluate the classic BPF bytecode inspecting seccomp_data headers and returning SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, or SECCOMP_RET_KILL_PROCESS.\nCompute the first 20 hex characters of SHA256(\"linuxhard_bpf_instruction_set_in_seccomp_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_bpf_instruction_set_in_seccomp_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["BPF 프로그램은 BPF_LD, BPF_JEQ 등 누산기 레지스터 기반 명령어로 시스템콜 번호를 판정합니다.", "식별자 `linuxhard_bpf_instruction_set_in_seccomp_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Classic BPF evaluates architecture and syscall numbers using register accumulator instructions.", "Extract first 20 hex chars of SHA256(\"linuxhard_bpf_instruction_set_in_seccomp_v1\")."]
    }
  },
  {
    id: "t1_linuxhard_landlock_unprivileged_sandboxing_model",
    tier: 1, cat: "landlock", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Landlock LSM 비특권 샌드박싱과 룰셋 아키텍처", en: "Landlock LSM Unprivileged Sandboxing & Ruleset Architecture" },
    prompt: {
      ko: "루트 권한(CAP_SYS_ADMIN) 없이도 일반 유저 프로세스가 자체적으로 파일시스템 접근 범위를 제한할 수 있는 Landlock LSM의 샌드박싱 구조를 분석합니다.\n지정된 식별자 `linuxhard_landlock_unprivileged_sandboxing_model_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_unprivileged_sandboxing_model_v1\") 앞 20자리}`",
      en: "Investigate Landlock LSM allowing unprivileged user applications to restrict their own filesystem and network scope without CAP_SYS_ADMIN.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_unprivileged_sandboxing_model_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_unprivileged_sandboxing_model_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["landlock_create_ruleset과 landlock_restrict_self 시스템콜을 통해 프로세스 계층에 적용됩니다.", "식별자 `linuxhard_landlock_unprivileged_sandboxing_model_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Rulesets are instantiated via landlock_create_ruleset and applied across the process tree using landlock_restrict_self.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_unprivileged_sandboxing_model_v1\")."]
    }
  },
  {
    id: "t1_linuxhard_ima_integrity_measurement_architecture_core",
    tier: 1, cat: "ima", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "무결성 측정 아키텍처(IMA)의 측정 및 평가 원리", en: "Integrity Measurement Architecture (IMA) Core Appraisal Principles" },
    prompt: {
      ko: "리눅스 커널이 파일 실행 및 읽기 시 SHA-256 해시를 계산하여 TPM PCR 및 커널 런타임 로그에 기록하고 인가 여부를 평가하는 IMA 동작을 분석합니다.\n지정된 식별자 `linuxhard_ima_integrity_measurement_architecture_core_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ima_integrity_measurement_architecture_core_v1\") 앞 20자리}`",
      en: "Examine Linux kernel IMA hashing executable and library contents into TPM PCR 10 and ascii_runtime_measurements for tamper detection.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ima_integrity_measurement_architecture_core_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ima_integrity_measurement_architecture_core_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["IMA는 파일이 변조되었을 경우 커널 레벨에서 실행(bprm_check)을 즉시 거부(EACCES)할 수 있습니다.", "식별자 `linuxhard_ima_integrity_measurement_architecture_core_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["IMA appraisal blocks execution with EACCES whenever on-disk file digest fails validation against signed metadata.", "Extract first 20 hex chars of SHA256(\"linuxhard_ima_integrity_measurement_architecture_core_v1\")."]
    }
  },
  {
    id: "t1_linuxhard_evm_extended_verification_module_xattr",
    tier: 1, cat: "ima", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "확장 검증 모듈(EVM)과 보안 확장 속성(xattr) 무결성 보호", en: "Extended Verification Module (EVM) Security xattr Protection" },
    prompt: {
      ko: "security.ima, security.selinux, POSIX ACL 등 보안 확장 속성에 대한 오프라인 변조를 방지하기 위해 HMAC/RSA 서명을 검증하는 EVM 구조를 분석합니다.\n지정된 식별자 `linuxhard_evm_extended_verification_module_xattr_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_evm_extended_verification_module_xattr_v1\") 앞 20자리}`",
      en: "Analyze Extended Verification Module (EVM) cryptographic signatures preventing offline tampering of security extended attributes like security.selinux.\nCompute the first 20 hex characters of SHA256(\"linuxhard_evm_extended_verification_module_xattr_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_evm_extended_verification_module_xattr_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["EVM은 파일의 inode, generation, uid, gid 및 보안 xattr들을 통합 바인딩하여 계산합니다.", "식별자 `linuxhard_evm_extended_verification_module_xattr_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["EVM binds inode metadata, file ownership, and security xattr values into a consolidated HMAC/signature.", "Extract first 20 hex chars of SHA256(\"linuxhard_evm_extended_verification_module_xattr_v1\")."]
    }
  },
  {
    id: "t1_linuxhard_kspp_stack_canaries_and_shadow_stack",
    tier: 1, cat: "kspp", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 스택 카나리와 하드웨어 섀도 스택 방어", en: "Kernel Stack Canaries & Hardware Shadow Stack Defense" },
    prompt: {
      ko: "CONFIG_STACKPROTECTOR_STRONG 컴파일러 카나리와 인텔 CET 하드웨어 섀도 스택을 통한 커널 스택 버퍼 오버플로 및 ROP 체인 차단 메커니즘을 분석합니다.\n지정된 식별자 `linuxhard_kspp_stack_canaries_and_shadow_stack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_stack_canaries_and_shadow_stack_v1\") 앞 20자리}`",
      en: "Review CONFIG_STACKPROTECTOR_STRONG kernel canaries and Intel CET hardware shadow stacks preventing ROP return address manipulation.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_stack_canaries_and_shadow_stack_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_stack_canaries_and_shadow_stack_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["함수 반환 주소 직전에 카나리 값을 삽입하여 에필로그 시 변조가 감지되면 커널 패닉을 유발합니다.", "식별자 `linuxhard_kspp_stack_canaries_and_shadow_stack_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Kernel canaries placed before return addresses trigger an immediate panic if overwritten by buffer overflows.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_stack_canaries_and_shadow_stack_v1\")."]
    }
  },
  {
    id: "t1_linuxhard_kernel_address_space_layout_randomization_kaslr",
    tier: 1, cat: "kspp", track: "linuxhard", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 주소 공간 배치 난수화(KASLR)와 부트 타임 엔트로피", en: "Kernel Address Space Layout Randomization (KASLR) Boot Entropy" },
    prompt: {
      ko: "부팅 시 커널 코드 베이스 주소를 랜덤화하여 고정 오프셋 기반 커널 익스플로잇 및 ROP 가젯 주소 특정을 무력화하는 KASLR 메커니즘을 분석합니다.\n지정된 식별자 `linuxhard_kernel_address_space_layout_randomization_kaslr_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kernel_address_space_layout_randomization_kaslr_v1\") 앞 20자리}`",
      en: "Analyze KASLR randomizing the base virtual address of kernel code sections at boot time to thwart fixed-offset gadget exploitation.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kernel_address_space_layout_randomization_kaslr_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kernel_address_space_layout_randomization_kaslr_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자는 KASLR을 우회하기 위해 커널 포인터 정보 누설(Info Leak) 취약점을 선행 익스플로잇해야 합니다.", "식별자 `linuxhard_kernel_address_space_layout_randomization_kaslr_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Adversaries must acquire a kernel pointer disclosure primitive (infoleak) before defeating KASLR offsets.", "Extract first 20 hex chars of SHA256(\"linuxhard_kernel_address_space_layout_randomization_kaslr_v1\")."]
    }
  },

  // Tier 2 (8)
  {
    id: "t2_linuxhard_seccomp_bpf_argument_filtering_toctou_hazard",
    tier: 2, cat: "seccomp", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Seccomp-BPF 포인터 인자 검증 한계와 TOCTOU 취약점", en: "Seccomp-BPF Pointer Argument Limitation & TOCTOU Hazards" },
    prompt: {
      ko: "Seccomp 필터가 포인터 인자가 가리키는 유저 공간 메모리 내용을 직접 역참조할 수 없어 발생하는 TOCTOU(Time-of-Check to Time-of-Use) 레이스 컨디션을 분석합니다.\n지정된 식별자 `linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1\") 앞 20자리}`",
      en: "Examine TOCTOU race conditions arising because classic Seccomp cannot dereference user-space pointer strings like openat pathname.\nCompute the first 20 hex characters of SHA256(\"linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["다른 스레드가 필터 검증 시점과 커널 복사 시점 사이에 포인터 버퍼의 경로명을 조작할 수 있습니다.", "식별자 `linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Concurrent threads can alter pointer contents between filter evaluation and kernel copy_from_user invocation.", "Extract first 20 hex chars of SHA256(\"linuxhard_seccomp_bpf_argument_filtering_toctou_hazard_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_prctl_set_no_new_privs_security_gate",
    tier: 2, cat: "seccomp", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "prctl PR_SET_NO_NEW_PRIVS와 execve 권한 상승 봉쇄", en: "prctl PR_SET_NO_NEW_PRIVS & Privilege Escalation Mitigation" },
    prompt: {
      ko: "비특권 프로세스가 Seccomp 필터를 장착하기 위해 반드시 설정해야 하며 execve 호출 시 setuid/setgid 비트 실행을 무효화하는 NO_NEW_PRIVS 플래그를 분석합니다.\n지정된 식별자 `linuxhard_prctl_set_no_new_privs_security_gate_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_prctl_set_no_new_privs_security_gate_v1\") 앞 20자리}`",
      en: "Audit prctl(PR_SET_NO_NEW_PRIVS, 1) ensuring execve ignores setuid/setgid bits and prevents privilege escalation under sandboxing.\nCompute the first 20 hex characters of SHA256(\"linuxhard_prctl_set_no_new_privs_security_gate_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_prctl_set_no_new_privs_security_gate_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["이 플래그가 한 번 1로 설정되면 프로세스 및 모든 자식 프로세스에서 다시 해제(0)할 수 없습니다.", "식별자 `linuxhard_prctl_set_no_new_privs_security_gate_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Once enabled, PR_SET_NO_NEW_PRIVS is irreversibly inherited by all future child processes.", "Extract first 20 hex chars of SHA256(\"linuxhard_prctl_set_no_new_privs_security_gate_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_landlock_filesystem_access_rights_matrix",
    tier: 2, cat: "landlock", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Landlock 파일시스템 세분화 권한 매트릭스 제어", en: "Landlock Filesystem Granular Access Rights Matrix" },
    prompt: {
      ko: "LANDLOCK_ACCESS_FS_EXECUTE, READ_FILE, WRITE_FILE, MAKE_REG, REFER 등 디렉터리 트리별 권한 마스크를 구성하여 최소 권한을 격리하는 구조를 분석합니다.\n지정된 식별자 `linuxhard_landlock_filesystem_access_rights_matrix_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_filesystem_access_rights_matrix_v1\") 앞 20자리}`",
      en: "Deconstruct Landlock bitmasks (LANDLOCK_ACCESS_FS_EXECUTE, READ_FILE, WRITE_FILE, MAKE_REG) scoping granular access per directory tree.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_filesystem_access_rights_matrix_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_filesystem_access_rights_matrix_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["랜드록 룰에 명시되지 않은 파일시스템 작업은 샌드박스 내부에서 커널에 의해 EACCES로 즉시 거부됩니다.", "식별자 `linuxhard_landlock_filesystem_access_rights_matrix_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unlisted filesystem operations within restricted trees return EACCES without affecting other processes.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_filesystem_access_rights_matrix_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_landlock_network_tcp_bind_connect_restriction",
    tier: 2, cat: "landlock", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Landlock 네트워크 TCP 바인드 및 연결 소켓 격리", en: "Landlock Network TCP Bind & Connect Port Restrictions" },
    prompt: {
      ko: "Landlock ABI v4+에서 지원하는 LANDLOCK_ACCESS_NET_BIND_TCP 및 CONNECT_TCP를 통해 특정 TCP 포트 외의 통신을 커널 레벨에서 원천 차단하는 기술을 분석합니다.\n지정된 식별자 `linuxhard_landlock_network_tcp_bind_connect_restriction_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_network_tcp_bind_connect_restriction_v1\") 앞 20자리}`",
      en: "Analyze Landlock ABI v4 network restrictions enforcing LANDLOCK_ACCESS_NET_BIND_TCP and CONNECT_TCP port allowlists.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_network_tcp_bind_connect_restriction_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_network_tcp_bind_connect_restriction_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["비인가 포트로의 connect() 호출 시 EACCES를 반환하여 리버스 쉘 및 C2 통신을 차단합니다.", "식별자 `linuxhard_landlock_network_tcp_bind_connect_restriction_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unauthorized connect calls to unlisted ports fail with EACCES, blocking outbound reverse shells.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_network_tcp_bind_connect_restriction_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_ima_appraisal_policy_enforcement_rules",
    tier: 2, cat: "ima", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "IMA 평가 정책(ima-policy) 문법과 강제 규칙 구성", en: "IMA Appraisal Policy Syntax & Enforcement Rules" },
    prompt: {
      ko: "/etc/ima/ima-policy 파일에서 BPRM_CHECK, MODULE_CHECK, FILE_CHECK 및 appraise_type=imasig 기반으로 서명되지 않은 바이너리 실행을 차단하는 규칙을 분석합니다.\n지정된 식별자 `linuxhard_ima_appraisal_policy_enforcement_rules_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ima_appraisal_policy_enforcement_rules_v1\") 앞 20자리}`",
      en: "Audit /etc/ima/ima-policy rules applying appraise func=BPRM_CHECK and appraise_type=imasig to mandate cryptographic binary signatures.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ima_appraisal_policy_enforcement_rules_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ima_appraisal_policy_enforcement_rules_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ima-policy는 sysfs (/sys/kernel/security/ima/policy)에 단 한 번 작성되며 이후 수정이 불가능합니다.", "식별자 `linuxhard_ima_appraisal_policy_enforcement_rules_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Once written to /sys/kernel/security/ima/policy, appraisal rules cannot be overwritten until reboot.", "Extract first 20 hex chars of SHA256(\"linuxhard_ima_appraisal_policy_enforcement_rules_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_evm_trusted_key_and_tpm_integration",
    tier: 2, cat: "ima", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "EVM 신뢰 키링과 TPM 봉인 마스터 키 아키텍처", en: "EVM Trusted Keyring & TPM Sealed Master Key Architecture" },
    prompt: {
      ko: "TPM 2.0에 암호학적으로 봉인(Sealed)된 대칭 키를 커널 키링(.evm)에 로드하여 파일시스템 메타데이터 HMAC을 생성 및 검증하는 아키텍처를 분석합니다.\n지정된 식별자 `linuxhard_evm_trusted_key_and_tpm_integration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_evm_trusted_key_and_tpm_integration_v1\") 앞 20자리}`",
      en: "Examine TPM 2.0 sealed master keys unsealed into the kernel .evm keyring for validating filesystem metadata HMACs.\nCompute the first 20 hex characters of SHA256(\"linuxhard_evm_trusted_key_and_tpm_integration_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_evm_trusted_key_and_tpm_integration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TPM 봉인은 플랫폼 부팅 상태(PCR 값)가 무결할 때만 마스터 키의 복호화를 허용합니다.", "식별자 `linuxhard_evm_trusted_key_and_tpm_integration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["TPM unsealing releases EVM HMAC keys only if PCR measurements match authorized platform states.", "Extract first 20 hex chars of SHA256(\"linuxhard_evm_trusted_key_and_tpm_integration_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_kspp_smep_and_smap_cpu_enforcement",
    tier: 2, cat: "kspp", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "CR4 레지스터 SMEP 및 SMAP 하드웨어 CPU 완화", en: "CR4 Register SMEP & SMAP Hardware CPU Mitigations" },
    prompt: {
      ko: "커널 모드에서 유저 공간 메모리 코드 실행을 차단하는 SMEP와 유저 공간 데이터 직접 읽기/쓰기를 차단하는 SMAP의 하드웨어 보안 기능을 분석합니다.\n지정된 식별자 `linuxhard_kspp_smep_and_smap_cpu_enforcement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_smep_and_smap_cpu_enforcement_v1\") 앞 20자리}`",
      en: "Assess x86_64 CR4 register protections: SMEP preventing user-space execution and SMAP preventing unintended user-space memory access.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_smep_and_smap_cpu_enforcement_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_smep_and_smap_cpu_enforcement_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["SMEP/SMAP는 유저 공간에 쉘코드를 배치하고 커널 EIP/RIP를 점프시키는 ret2usr 공격을 완벽히 차단합니다.", "식별자 `linuxhard_kspp_smep_and_smap_cpu_enforcement_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SMEP/SMAP defeats ret2usr exploitation by faulting whenever Ring 0 executes or dereferences user pages without stac.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_smep_and_smap_cpu_enforcement_v1\")."]
    }
  },
  {
    id: "t2_linuxhard_kspp_slub_freelist_hardening_and_randomization",
    tier: 2, cat: "kspp", track: "linuxhard", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "SLUB 프리리스트 난수화와 포인터 XOR 난독화 하드닝", en: "SLUB Freelist Hardening & Pointer XOR Obfuscation" },
    prompt: {
      ko: "CONFIG_SLAB_FREELIST_HARDENED 및 RANDOM 옵션을 통해 커널 힙 프리리스트 포인터를 XOR 마스킹하고 순서를 셔플하여 Use-After-Free를 방어하는 기법을 분석합니다.\n지정된 식별자 `linuxhard_kspp_slub_freelist_hardening_and_randomization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_slub_freelist_hardening_and_randomization_v1\") 앞 20자리}`",
      en: "Review CONFIG_SLAB_FREELIST_HARDENED and RANDOM obfuscating kernel heap next-pointers via secret XOR and randomized allocation orders.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_slub_freelist_hardening_and_randomization_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_slub_freelist_hardening_and_randomization_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["포인터 손상 검증 시 불일치가 발생하면 BUG() 또는 패닉을 발생시켜 힙 익스플로잇 체인을 차단합니다.", "식별자 `linuxhard_kspp_slub_freelist_hardening_and_randomization_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Freelist corruption checks verify pointer integrity before allocating, triggering kernel panics on tampering.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_slub_freelist_hardening_and_randomization_v1\")."]
    }
  },

  // Tier 3 (9)
  {
    id: "t3_linuxhard_seccomp_user_notification_secnotif_architecture",
    tier: 3, cat: "seccomp", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Seccomp 유저스페이스 알림(SECCOMP_RET_USER_NOTIF) 아키텍처", en: "Seccomp Userspace Notification (SECCOMP_RET_USER_NOTIF) Architecture" },
    prompt: {
      ko: "비특권 컨테이너가 차단된 시스템콜을 유저스페이스 관리자 데몬에 전달하여 안전하게 프록시 에뮬레이션할 수 있는 SECCOMP_RET_USER_NOTIF을 분석합니다.\n지정된 식별자 `linuxhard_seccomp_user_notification_secnotif_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_seccomp_user_notification_secnotif_architecture_v1\") 앞 20자리}`",
      en: "Analyze SECCOMP_RET_USER_NOTIF passing intercepted syscall events via file descriptor ioctls to unprivileged emulator supervisors.\nCompute the first 20 hex characters of SHA256(\"linuxhard_seccomp_user_notification_secnotif_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_seccomp_user_notification_secnotif_architecture_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["관리 프로세스는 SECCOMP_IOCTL_NOTIF_RECV 및 RESP ioctl을 통해 시스템콜 결과를 주입합니다.", "식별자 `linuxhard_seccomp_user_notification_secnotif_architecture_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Supervisors handle intercepted syscalls through SECCOMP_IOCTL_NOTIF_RECV and respond with NOTIF_RESP.", "Extract first 20 hex chars of SHA256(\"linuxhard_seccomp_user_notification_secnotif_architecture_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard",
    tier: 3, cat: "seccomp", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Seccomp 노티파이어와 pidfd/process_vm_readv TOCTOU 방어", en: "Seccomp Notifier, pidfd & process_vm_readv TOCTOU Defenses" },
    prompt: {
      ko: "유저 알림 수신자가 타깃 프로세스의 메모리를 읽을 때 PID 재사용 및 레이스 컨디션을 방지하기 위해 pidfd_open과 SECCOMP_IOCTL_NOTIF_ID_VALID를 결합하는 기법을 분석합니다.\n지정된 식별자 `linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1\") 앞 20자리}`",
      en: "Investigate supervisor memory auditing using pidfd_open and SECCOMP_IOCTL_NOTIF_ID_VALID to prevent PID recycling and TOCTOU attacks.\nCompute the first 20 hex characters of SHA256(\"linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["알림 ID가 유효한 상태에서 process_vm_readv를 호출해야 안전하게 타깃 포인터 인자를 검사할 수 있습니다.", "식별자 `linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The supervisor verifies notification id validity before reading target process arguments via process_vm_readv.", "Extract first 20 hex chars of SHA256(\"linuxhard_seccomp_notify_pidfd_and_proc_mem_safeguard_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_landlock_ruleset_nesting_and_layering",
    tier: 3, cat: "landlock", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Landlock 룰셋 중첩(Nesting)과 단조 감소 권한 모델", en: "Landlock Ruleset Nesting & Monotonic Restriction Layering" },
    prompt: {
      ko: "자식 프로세스가 부모 샌드박스의 제한을 해제할 수 없으며 추가 룰셋을 적용할수록 허용 범위가 단조 감소(Monotonic Restriction)하는 중첩 메커니즘을 분석합니다.\n지정된 식별자 `linuxhard_landlock_ruleset_nesting_and_layering_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_ruleset_nesting_and_layering_v1\") 앞 20자리}`",
      en: "Examine Landlock ruleset layering where multiple restrictions compose monotonically and child domains cannot widen parent boundaries.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_ruleset_nesting_and_layering_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_ruleset_nesting_and_layering_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["모든 샌드박스 레이어의 권한 교집합(AND)이 최종 유효 권한으로 커널에 의해 적용됩니다.", "식별자 `linuxhard_landlock_ruleset_nesting_and_layering_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The effective permission is strictly the intersection (AND) of all stacked Landlock domains in the process hierarchy.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_ruleset_nesting_and_layering_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_landlock_scoped_abstract_unix_sockets",
    tier: 3, cat: "landlock", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Landlock ABI v5+ 스코핑과 추상 유닉스 소켓 격리", en: "Landlock ABI v5+ Scoping & Abstract UNIX Domain Socket Isolation" },
    prompt: {
      ko: "샌드박스 내부 프로세스가 외부 추상 유닉스 소켓(Abstract UNIX Socket)이나 시그널(Signal)을 통해 샌드박스를 우회 탈출하는 것을 차단하는 스코핑 기능을 분석합니다.\n지정된 식별자 `linuxhard_landlock_scoped_abstract_unix_sockets_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_scoped_abstract_unix_sockets_v1\") 앞 20자리}`",
      en: "Audit Landlock ABI v5 scoped restrictions mitigating sandbox escapes via abstract UNIX domain sockets or cross-domain signals.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_scoped_abstract_unix_sockets_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_scoped_abstract_unix_sockets_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET 플래그는 동일 샌드박스 도메인 외의 소켓 바인드/연결을 격리합니다.", "식별자 `linuxhard_landlock_scoped_abstract_unix_sockets_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET isolates non-filesystem abstract sockets across domain boundaries.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_scoped_abstract_unix_sockets_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_ima_custom_appraise_digest_lists",
    tier: 3, cat: "ima", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "IMA 다이제스트 리스트 사전 로드와 고속 무결성 검증", en: "IMA Preloaded Digest Lists & Fast Integrity Appraisal" },
    prompt: {
      ko: "수십만 개의 패키지 파일에 일일이 xattr를 쓰는 대신 RPM/DEB 패키지 다이제스트 목록을 커널에 사전 로드하여 파일 무결성을 초고속 검증하는 구조를 분석합니다.\n지정된 식별자 `linuxhard_ima_custom_appraise_digest_lists_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ima_custom_appraise_digest_lists_v1\") 앞 20자리}`",
      en: "Analyze IMA digest lists caching package hashes in kernel memory to enable rapid appraisal without writing individual extended attributes.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ima_custom_appraise_digest_lists_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ima_custom_appraise_digest_lists_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["커널 해시 테이블에 패키지 다이제스트를 상주시켜 파일 open 시 즉시 O(1)에 가깝게 대조합니다.", "식별자 `linuxhard_ima_custom_appraise_digest_lists_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Preloaded digest lists allow the kernel to appraise unmodified distribution packages at near O(1) overhead.", "Extract first 20 hex chars of SHA256(\"linuxhard_ima_custom_appraise_digest_lists_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_ima_tpm_pcr10_quote_and_remote_attestation",
    tier: 3, cat: "ima", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "TPM PCR 10 인용(Quote)과 IMA 원격 무결성 검증(Attestation)", en: "TPM PCR 10 Quote & IMA Remote Integrity Attestation" },
    prompt: {
      ko: "호스트가 측정한 IMA 런타임 이벤트 로그와 TPM PCR 10 인용(Quote) 서명을 원격 검증 서버에 전송하여 커널 및 바이너리 무결성을 인증받는 구조를 분석합니다.\n지정된 식별자 `linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1\") 앞 20자리}`",
      en: "Examine remote attestation flows where verifiers validate TPM PCR 10 Quote cryptographic signatures against IMA runtime measurement logs.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["검증 서버는 전달받은 이벤트 로그를 순서대로 SHA-256 재연산(Replay)하여 PCR 10 값과 일치하는지 대조합니다.", "식별자 `linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Attestation verifiers replay recorded log hashes to confirm they reconstruct the exact hardware PCR 10 digest.", "Extract first 20 hex chars of SHA256(\"linuxhard_ima_tpm_pcr10_quote_and_remote_attestation_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_kspp_page_table_isolation_kpti_meltdown",
    tier: 3, cat: "kspp", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 페이지 테이블 격리(KPTI)와 멜트다운 부채널 완화", en: "Kernel Page Table Isolation (KPTI) & Meltdown Mitigation" },
    prompt: {
      ko: "유저 공간 실행 시 커널 메모리 매핑을 페이지 테이블에서 완전히 분리(듀얼 CR3)하여 멜트다운(Meltdown, CVE-2017-5754) 공격을 원천 차단한 KPTI를 분석합니다.\n지정된 식별자 `linuxhard_kspp_page_table_isolation_kpti_meltdown_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_page_table_isolation_kpti_meltdown_v1\") 앞 20자리}`",
      en: "Deconstruct KPTI maintaining separate user and kernel CR3 page tables to defeat Meltdown speculative microarchitectural data leaks.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_page_table_isolation_kpti_meltdown_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_page_table_isolation_kpti_meltdown_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["KPTI 환경에서는 유저 모드에서 커널 메모리가 매핑되지 않으므로 투기적 실행으로도 주소 데이터를 읽을 수 없습니다.", "식별자 `linuxhard_kspp_page_table_isolation_kpti_meltdown_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["KPTI unmaps sensitive kernel address ranges while in user context, preventing speculative cache loading.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_page_table_isolation_kpti_meltdown_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_kspp_control_flow_integrity_kcfi",
    tier: 3, cat: "kspp", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Clang 커널 제어 흐름 무결성(kCFI)과 간접 호출 검증", en: "Clang Kernel Control Flow Integrity (kCFI) & Indirect Call Verification" },
    prompt: {
      ko: "컴파일 타임에 함수 시그니처 해시를 함수 프롤로그 앞에 삽입하고 간접 호출 직전에 타깃 해시를 비교하여 하이재킹을 차단하는 Forward-Edge kCFI를 분석합니다.\n지정된 식별자 `linuxhard_kspp_control_flow_integrity_kcfi_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_control_flow_integrity_kcfi_v1\") 앞 20자리}`",
      en: "Review forward-edge kCFI injecting function type hashes before function entry points to validate indirect branch targets.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_control_flow_integrity_kcfi_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_control_flow_integrity_kcfi_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자가 함수 포인터를 변조하더라도 타깃 함수의 프로토타입 시그니처가 일치하지 않으면 트랩(#UD)이 발생합니다.", "식별자 `linuxhard_kspp_control_flow_integrity_kcfi_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Mismatched indirect call targets trigger an immediate undefined instruction trap (#UD) before execution.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_control_flow_integrity_kcfi_v1\")."]
    }
  },
  {
    id: "t3_linuxhard_kspp_init_on_alloc_and_init_on_free",
    tier: 3, cat: "kspp", track: "linuxhard", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 메모리 자동 제로화(init_on_alloc & init_on_free)", en: "Kernel Memory Automatic Zeroing (init_on_alloc & init_on_free)" },
    prompt: {
      ko: "커널 힙 및 페이지 할당/해제 시 메모리를 자동으로 0으로 초기화하여 미초기화 변수 누설(Uninitialized Use)과 정보 유출을 차단하는 하드닝을 분석합니다.\n지정된 식별자 `linuxhard_kspp_init_on_alloc_and_init_on_free_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_init_on_alloc_and_init_on_free_v1\") 앞 20자리}`",
      en: "Analyze CONFIG_INIT_ON_ALLOC_DEFAULT_ON and CONFIG_INIT_ON_FREE_DEFAULT_ON zeroing slab pages to eradicate uninitialized heap disclosure.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_init_on_alloc_and_init_on_free_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_init_on_alloc_and_init_on_free_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["해제된 힙 버퍼에 잔존하는 비밀 키, 토큰, 커널 포인터 잔재를 즉시 소거(Purge)합니다.", "식별자 `linuxhard_kspp_init_on_alloc_and_init_on_free_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Zero-on-free purges stale cryptographic keys and kernel pointers before memory recycling.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_init_on_alloc_and_init_on_free_v1\")."]
    }
  },

  // Tier 4 (10)
  {
    id: "t4_linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking",
    tier: 4, cat: "seccomp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF LSM(BPF_PROG_TYPE_LSM) 동적 보안 정책 프로그래밍", en: "eBPF LSM (BPF_PROG_TYPE_LSM) Dynamic Security Instrumentation" },
    prompt: {
      ko: "BPF_PROG_TYPE_LSM 프로그램을 컴파일하여 security_bprm_check, security_file_open 등 LSM 후크에 부착해 런타임 보안 정책을 동적 집행하는 기술을 분석합니다.\n지정된 식별자 `linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1\") 앞 20자리}`",
      en: "Evaluate eBPF LSM attaching safe bytecode directly into kernel LSM hooks like security_file_open for dynamic zero-trust enforcement.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["eBPF 검증기(Verifier)는 후크 프로그램이 커널 크래시나 무한 루프를 발생시키지 않음을 사전에 보증합니다.", "식별자 `linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The kernel BPF verifier guarantees safety and bounded termination before attaching LSM hook bytecode.", "Extract first 20 hex chars of SHA256(\"linuxhard_ebpf_lsm_bpf_program_type_runtime_hooking_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_landlock_container_runc_integration_oci",
    tier: 4, cat: "landlock", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "OCI 컨테이너 런타임(runc/crun)과 Landlock 통합 샌드박싱", en: "OCI Container Runtime (runc/crun) & Landlock Integrated Sandboxing" },
    prompt: {
      ko: "컨테이너 격리 계층에서 runc/crun이 루트리스 컨테이너 구동 시 Landlock LSM을 적용하여 호스트 마운트 탈출(Container Escape)을 원천 차단하는 모델을 분석합니다.\n지정된 식별자 `linuxhard_landlock_container_runc_integration_oci_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_landlock_container_runc_integration_oci_v1\") 앞 20자리}`",
      en: "Audit Landlock integration within OCI runtimes (runc/crun) isolating rootless container rootfs trees to block host container breakouts.\nCompute the first 20 hex characters of SHA256(\"linuxhard_landlock_container_runc_integration_oci_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_landlock_container_runc_integration_oci_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["컨테이너 프로세스가 루트 권한을 획득하더라도 Landlock이 호스트 디렉터리 접근을 봉쇄합니다.", "식별자 `linuxhard_landlock_container_runc_integration_oci_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Even if container processes gain internal root UID, Landlock denies traversing outside assigned host mounts.", "Extract first 20 hex chars of SHA256(\"linuxhard_landlock_container_runc_integration_oci_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_ima_evm_secure_boot_unified_kernel_image",
    tier: 4, cat: "ima", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "UEFI 보안 부트, UKI 및 IMA/EVM 통합 부트 무결성 체인", en: "UEFI Secure Boot, UKI & IMA/EVM Unified Boot Integrity Chain" },
    prompt: {
      ko: "UEFI Secure Boot로 서명된 UKI(Unified Kernel Image)를 부팅하고, initramfs 단계에서 TPM 비밀키를 복원하여 IMA/EVM을 강제 집행하는 통합 체인을 분석합니다.\n지정된 식별자 `linuxhard_ima_evm_secure_boot_unified_kernel_image_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_ima_evm_secure_boot_unified_kernel_image_v1\") 앞 20자리}`",
      en: "Synthesize full-chain boot integrity combining UEFI Secure Boot, Unified Kernel Images (UKI), TPM2 unsealing, and strict IMA/EVM enforcement.\nCompute the first 20 hex characters of SHA256(\"linuxhard_ima_evm_secure_boot_unified_kernel_image_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_ima_evm_secure_boot_unified_kernel_image_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["하드웨어 펌웨어부터 커널, 루트 파일시스템까지 일체의 비인가 수정이나 부트킷 감염을 완벽히 방어합니다.", "식별자 `linuxhard_ima_evm_secure_boot_unified_kernel_image_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unified integrity chains guarantee that untrusted bootloaders or modified root partitions fail platform startup.", "Extract first 20 hex chars of SHA256(\"linuxhard_ima_evm_secure_boot_unified_kernel_image_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_kspp_retpoline_and_speculative_execution_mitigations",
    tier: 4, cat: "kspp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "스펙터(Spectre) v2 방어를 위한 Retpoline과 eIBRS 투기적 실행 완화", en: "Spectre v2 Retpoline, eIBRS & Speculative Execution Mitigations" },
    prompt: {
      ko: "간접 분기 대상 예측(BTB) 오염을 통한 투기적 코드 실행 결함(Spectre v2)을 방어하기 위해 리턴 트램펄린(Retpoline)과 eIBRS를 적용하는 구조를 분석합니다.\n지정된 식별자 `linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1\") 앞 20자리}`",
      en: "Analyze Retpoline return trampolines and enhanced IBRS (eIBRS) mitigating Branch Target Buffer poisonings under Spectre v2.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Retpoline은 간접 점프를 일시 중단된 'pause; lfence' 루프를 가진 call-ret 시퀀스로 치환하여 투기를 격리합니다.", "식별자 `linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Retpolines trap CPU speculative execution pipelines into infinite return loops until the real branch target resolves.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_retpoline_and_speculative_execution_mitigations_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_kspp_fortify_source_and_bounds_checking",
    tier: 4, cat: "kspp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "CONFIG_FORTIFY_SOURCE 버퍼 경계 검증과 memcpy 오버플로 방어", en: "CONFIG_FORTIFY_SOURCE Buffer Bounds Checking & Overflow Mitigations" },
    prompt: {
      ko: "커널 메모리 복사 함수(memcpy, memset, strcpy) 호출 시 컴파일러 __builtin_object_size를 통해 대상 구조체 크기 초과를 감지하고 트랩을 유발하는 기법을 분석합니다.\n지정된 식별자 `linuxhard_kspp_fortify_source_and_bounds_checking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_fortify_source_and_bounds_checking_v1\") 앞 20자리}`",
      en: "Review CONFIG_FORTIFY_SOURCE instrumenting memcpy/strcpy calls with object size bounds to trap intra-object buffer overflows.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_fortify_source_and_bounds_checking_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_fortify_source_and_bounds_checking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["복사 대상 버퍼의 정적/동적 크기를 초과하는 바이트 복사 시도 시 즉시 커널 패닉을 발생시킵니다.", "식별자 `linuxhard_kspp_fortify_source_and_bounds_checking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["FORTIFY_SOURCE intercepts oversized memory transfers before adjacent struct members or pointers can be corrupted.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_fortify_source_and_bounds_checking_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_kspp_module_signature_enforcement_and_lockdown",
    tier: 4, cat: "kspp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "커널 모듈 서명 강제와 커널 록다운(Kernel Lockdown) 모드", en: "Kernel Module Signature Enforcement & Kernel Lockdown Modes" },
    prompt: {
      ko: "CONFIG_MODULE_SIG_FORCE와 커널 록다운 모드(Integrity vs Confidentiality)를 통해 루트 유저의 /dev/mem 조작 및 비인가 커널 모듈 적재를 원천 봉쇄하는 체계를 분석합니다.\n지정된 식별자 `linuxhard_kspp_module_signature_enforcement_and_lockdown_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_kspp_module_signature_enforcement_and_lockdown_v1\") 앞 20자리}`",
      en: "Analyze CONFIG_MODULE_SIG_FORCE and Kernel Lockdown modes (Integrity and Confidentiality) barring root from modifying live kernel memory.\nCompute the first 20 hex characters of SHA256(\"linuxhard_kspp_module_signature_enforcement_and_lockdown_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_kspp_module_signature_enforcement_and_lockdown_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Lockdown 모드가 활성화되면 루트 권한을 가진 공격자라도 kexec_file_load, ioperm, /dev/kmem 접근이 불가능합니다.", "식별자 `linuxhard_kspp_module_signature_enforcement_and_lockdown_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Kernel Lockdown blocks root processes from inspecting or rewriting Ring 0 memory structures via /dev/mem or raw IO.", "Extract first 20 hex chars of SHA256(\"linuxhard_kspp_module_signature_enforcement_and_lockdown_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_namespace_sandbox_user_mount_pid_isolation",
    tier: 4, cat: "landlock", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "네임스페이스 샌드박싱과 유저/마운트/PID 격리 심층 방어", en: "Namespace Sandboxing & User/Mount/PID Defense-in-Depth Isolation" },
    prompt: {
      ko: "unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)와 pivot_root를 결합하여 호스트 시스템과의 상호작용을 완전히 고립시키는 샌드박스 메커니즘을 분석합니다.\n지정된 식별자 `linuxhard_namespace_sandbox_user_mount_pid_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_namespace_sandbox_user_mount_pid_isolation_v1\") 앞 20자리}`",
      en: "Examine unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) combined with pivot_root establishing zero-privilege namespace isolation.\nCompute the first 20 hex characters of SHA256(\"linuxhard_namespace_sandbox_user_mount_pid_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_namespace_sandbox_user_mount_pid_isolation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["네임스페이스 내부에서 UID 0을 갖더라도 외부 호스트 네임스페이스에서는 권한 없는 일반 유저로 매핑됩니다.", "식별자 `linuxhard_namespace_sandbox_user_mount_pid_isolation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["UID 0 inside a user namespace maps to an unprivileged subordinate UID in the initial root namespace.", "Extract first 20 hex chars of SHA256(\"linuxhard_namespace_sandbox_user_mount_pid_isolation_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_krsi_kernel_runtime_security_instrumentation",
    tier: 4, cat: "kspp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "KRSI 커널 런타임 보안 계측과 실시간 침해 탐지 연계", en: "KRSI Kernel Runtime Security Instrumentation & Real-Time EDR" },
    prompt: {
      ko: "리눅스 커널 보안 후크를 eBPF로 계측하여 성능 저하 없이 악성 프로세스 행위를 실시간 추적하고 차단하는 KRSI(Kernel Runtime Security Instrumentation)를 분석합니다.\n지정된 식별자 `linuxhard_krsi_kernel_runtime_security_instrumentation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_krsi_kernel_runtime_security_instrumentation_v1\") 앞 20자리}`",
      en: "Analyze KRSI (Kernel Runtime Security Instrumentation) leveraging eBPF telemetry hooks to detect privilege abuse without auditd overhead.\nCompute the first 20 hex characters of SHA256(\"linuxhard_krsi_kernel_runtime_security_instrumentation_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_krsi_kernel_runtime_security_instrumentation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Tetragon 및 Falco와 같은 클라우드 네이티브 런타임 보안 엔진의 핵심 커널 백엔드로 활용됩니다.", "식별자 `linuxhard_krsi_kernel_runtime_security_instrumentation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["KRSI serves as the kernel foundation for cloud-native runtime enforcement engines like Tetragon.", "Extract first 20 hex chars of SHA256(\"linuxhard_krsi_kernel_runtime_security_instrumentation_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_seccomp_bpf_assembler_jit_spray_mitigation",
    tier: 4, cat: "seccomp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "BPF JIT 스프레이 방어와 상수 블라인딩(Constant Blinding)", en: "BPF JIT Spray Mitigations & Constant Blinding Defense" },
    prompt: {
      ko: "BPF 바이트코드의 즉시값(Immediate Constant)에 쉘코드를 은닉하여 실행 가능한 JIT 영역으로 점프하는 공격을 차단하는 bpf_jit_harden 상수 블라인딩 기법을 분석합니다.\n지정된 식별자 `linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1\") 앞 20자리}`",
      en: "Examine BPF JIT spraying defenses including net.core.bpf_jit_harden constant blinding randomizing immediate opcode values.\nCompute the first 20 hex characters of SHA256(\"linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["상수 블라인딩은 모든 사용자 제공 상수를 랜덤 키와 XOR 분할하여 JIT 컴파일된 머신코드에서 페이로드 가젯 생성을 방지합니다.", "식별자 `linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Constant blinding splits user immediates with random XOR masks, disrupting unintended machine code gadgets.", "Extract first 20 hex chars of SHA256(\"linuxhard_seccomp_bpf_assembler_jit_spray_mitigation_v1\")."]
    }
  },
  {
    id: "t4_linuxhard_capstone_full_spectrum_kernel_runtime_defense",
    tier: 4, cat: "kspp", track: "linuxhard", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "엔터프라이즈 리눅스 커널 하드닝 & 런타임 제로 트러스트 캡스톤 아키텍처", en: "Capstone: Enterprise Linux Kernel Hardening & Runtime Zero Trust Architecture" },
    prompt: {
      ko: "Seccomp-BPF 시스템콜 격리, Landlock 비특권 샌드박싱, IMA/EVM 무결성 평가, KSPP 커널 자가 보호를 모두 통합 집행하는 전사 프로덕션 리눅스 방어 아키텍처를 완성합니다.\n지정된 식별자 `linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1\") 앞 20자리}`",
      en: "Synthesize full-spectrum enterprise Linux kernel defense integrating Seccomp-BPF, Landlock LSM, IMA/EVM, and KSPP runtime hardening.\nCompute the first 20 hex characters of SHA256(\"linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1\").\n\nFormat: `FLAG{SHA256(\"linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["심층 방어 아키텍처는 공격자가 애플리케이션 RCE를 획득하더라도 시스템콜, 파일시스템, 커널 공간 침투를 단계별로 봉쇄합니다.", "식별자 `linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Defense-in-depth ensures application-level code execution remains strictly trapped within sandboxed user boundaries.", "Extract first 20 hex chars of SHA256(\"linuxhard_capstone_full_spectrum_kernel_runtime_defense_v1\")."]
    }
  }
];

// Attach computed hashes
const challengesWithHash = challengesDef.map(ch => ({
  ...ch,
  hash: computeHash(ch.id)
}));

console.log(`Generated ${challengesWithHash.length} challenges for Track 60 (linuxhard)`);
fs.writeFileSync(path.join(__dirname, 'track60_challenges.json'), JSON.stringify(challengesWithHash, null, 2), 'utf8');
console.log('Saved to tools/track60_challenges.json');
