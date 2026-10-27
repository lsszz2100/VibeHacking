# 26. Linux Hardening — 서버 보안 강화

## 목차

| 파일 | 내용 |
|------|------|
| [01_firewall_and_iptables.md](./01_firewall_and_iptables.md) | iptables/nftables/firewalld 설정, 브루트포스·스캔 차단, 커널 파라미터 |
| [02_pam_and_auth_hardening.md](./02_pam_and_auth_hardening.md) | PAM 구조, 패스워드 정책, 계정 잠금, SSH 강화, auditd 감사 로깅 |
| [03_kisa_vulnerability_assessment.md](./03_kisa_vulnerability_assessment.md) | KISA 취약점 점검 항목, CVSS 평가, 자동화 점검 스크립트, 보고서 구조 |
| [04_linux_security_auditing.md](./04_linux_security_auditing.md) | **Linux 보안 감사** — 보안 감사 vs 침투 테스트: |
| [05_linux_hardening_automation.md](./05_linux_hardening_automation.md) | **Linux 보안 강화 자동화 — CIS 벤치마크·Ansible·감사 스크립트** — 새로 설치된 Linux 서버는 기본 설정으로는 보안에 취약합니다. 불필요한 서비스 실행, 약한 패스워드 정책, 넓은 파일 권한 등이 문제입니다. 보안 강화는 이를 체계적으로 개선하는 ... |
| [06_linux_hardening_ctf_lab.md](./06_linux_hardening_ctf_lab.md) | **Linux 하드닝 CTF 실습 랩** — version: "3.9" |
| [07_linux_kernel_hardening_and_runtime_defense_deepdive.md](./07_linux_kernel_hardening_and_runtime_defense_deepdive.md) | **리눅스 커널 하드닝 & 런타임 방어 심층 분석** — Seccomp-BPF 시스템콜 필터링, Landlock 비특권 샌드박싱, IMA/EVM 무결성 측정, KSPP 커널 자체 보호 완화 기법 |
| [08_ebpf_runtime_observability_and_tetragon_deepdive.md](./08_ebpf_runtime_observability_and_tetragon_deepdive.md) | **클라우드 네이티브 eBPF 런타임 보안 & 커널 옵저버빌리티 심층 분석: Cilium Tetragon, Falco eBPF LSM, TracingPolicy 및 Shadow Rootkit 무결성 감사** — 전통적인 호스트 보안 에이전트(Auditd, Syslog, ptrace 기반 디버거)는 고부하 클라우드 네이티브 워크로드에서 치명적인 I/O 병목을 유발하거나, 사용자 공간(User ... |

## 학습 목표

- iptables/nftables로 호스트 기반 방화벽 구축
- PAM으로 패스워드 복잡도·만료·잠금 정책 시행
- SSH 키 인증 전용 + 2FA 설정
- KISA 가이드 기반 취약점 점검 자동화
- CVSS로 발견된 취약점 위험도 산정

## 핵심 점검 순서

```
1. 방화벽: 기본 DROP 정책 → 필요 포트만 ALLOW
2. 계정:   빈 패스워드 제거 → 만료 정책 → 잠금 임계값
3. SSH:    키 인증 전용 → root 로그인 금지 → 포워딩 차단
4. 감사:   auditd 활성화 → 중요 파일 변경 감사
5. 점검:   KISA 체크리스트 자동화 → CVSS 평가 → 보고서
```
