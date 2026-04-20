# 26. Linux Hardening — 서버 보안 강화

## 목차

| 파일 | 내용 |
|------|------|
| [01_firewall_and_iptables.md](./01_firewall_and_iptables.md) | iptables/nftables/firewalld 설정, 브루트포스·스캔 차단, 커널 파라미터 |
| [02_pam_and_auth_hardening.md](./02_pam_and_auth_hardening.md) | PAM 구조, 패스워드 정책, 계정 잠금, SSH 강화, auditd 감사 로깅 |
| [03_kisa_vulnerability_assessment.md](./03_kisa_vulnerability_assessment.md) | KISA 취약점 점검 항목, CVSS 평가, 자동화 점검 스크립트, 보고서 구조 |

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
