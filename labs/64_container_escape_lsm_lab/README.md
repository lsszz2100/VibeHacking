# Lab 64: eBPF LSM Container Escape & Kernel Runtime Shield Lab

## 1. 개요 (Overview)
- **대상 포트**: `8064` (`127.0.0.1:8064`)
- **컨테이너 이름**: `vhack-lab64-container-escape-lsm`
- **핵심 목표**: Linux 커널 eBPF LSM(Linux Security Module)을 통해 비특권 컨테이너 탈출 기법(User Namespace 에스컬레이션, cgroup v2 release_agent, runc CVE-2024-21626 유출 파일 디스크립터 마운트 탈출)을 커널 인라인에서 실시간 탐지하고 `bpf_send_signal(SIGKILL)`을 통해 0.4 µs 내 능동 격리하는 제로 트러스트 런타임 방어 실습.

## 2. 4단계 실습 구조 (4-Stage Pipeline)
1. **Stage 1: User Namespace Privileged Capability Escalation & eBPF LSM Hook**
   - 취약점: `unshare(CLONE_NEWUSER)` 호출로 차일드 사용자 네임스페이스 내 `CAP_SYS_ADMIN` 권한 획득 후 호스트 커널 취약점 공격.
   - 방어책: eBPF LSM `bpf_lsm_userns_create` 및 `bpf_lsm_capable` 훅을 통해 비인가 cgroup의 사용자 네임스페이스 생성을 즉시 `-EPERM` 거부.
   - 플래그: `FLAG{lsm_userns_capability_sandbox_enforced}`
2. **Stage 2: Cgroup v2 Release Agent & Procfs Kernel Overwrite**
   - 취약점: 쓰기 가능한 cgroup 마운트의 `release_agent` 또는 `/proc/sys/kernel/core_pattern` 변조를 통한 호스트 루트 권한 코드 실행.
   - 방어책: eBPF LSM `bpf_lsm_file_open` 및 `bpf_lsm_inode_permission` W^X 정책 강제로 민감한 의사 파일시스템 쓰기 차단 (`-EACCES`).
   - 플래그: `FLAG{lsm_cgroup_procfs_w_xor_x_shielded}`
3. **Stage 3: Leaked Host File Descriptor & Mount Traversal (CVE-2024-21626)**
   - 취약점: runc 등 런타임이 누출한 호스트 파일 디스크립터(`/proc/self/fd/7`)를 통한 컨테이너 루트 디렉터리 탈출 및 호스트 `/etc/shadow` 접근.
   - 방어책: eBPF LSM `bpf_lsm_path_link` 및 `resolve_beneath` 검증으로 컨테이너 마운트 네임스페이스 외부를 가리키는 경로 탐색을 트랩 및 격리.
   - 플래그: `FLAG{lsm_fd_leaks_resolve_beneath_quarantined}`
4. **Stage 4: Autonomous Kernel Runtime Zero-Trust Shield & Immediate Killswitch**
   - 취약점: 다단계 복합 시스템 콜 시퀀스(`unshare` + `pivot_root` + `setns`)를 통한 호스트 `init_pid_ns` 탈출 시도.
   - 방어책: 커널 링버퍼 기반 이상 네임스페이스 전이 감지 즉시 `bpf_send_signal(SIGKILL)`을 발송하여 공격 프로세스 트리를 즉각 사살하고 cgroup을 동결.
   - 플래그: `FLAG{lsm_runtime_sigkill_containment_sealed}`

## 3. 컴플라이언스 매핑
- **KISA ISMS-P**: 2.10.1 (보안 시스템 운영 관리), 2.10.5 (단말 및 런타임 보안)
- **NIST CSF 2.0**: PR.PS-01 (플랫폼 보안 강화), DE.CM-01 (런타임 이상 행위 모니터링)
- **OWASP Kubernetes Top 10**: K01:2025 (Insecure Workload Configurations), K04:2025 (Inadequate Sandboxing)
- **CVSS 3.1 Score**: 8.8 (High) / `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
