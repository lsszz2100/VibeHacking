# 24. Network Infrastructure Security

## 목차

| 파일 | 내용 |
|------|------|
| [01_dns_attack_defense.md](./01_dns_attack_defense.md) | Zone Transfer, Cache Poisoning, DNS Tunneling, Subdomain Takeover, DNSSEC |
| [02_mail_server_security.md](./02_mail_server_security.md) | SPF/DKIM/DMARC 설정·분석, 오픈 릴레이, 스푸핑 탐지 자동화 |
| [03_ssh_tunneling_port_forwarding.md](./03_ssh_tunneling_port_forwarding.md) | SSH -L/-R/-D, Chisel HTTP 터널, 다중 홉 피벗, 터널 탐지·차단 |

## 학습 목표

- DNS 인프라 공격 기법과 DNSSEC/Zone Transfer 방어 설정
- 이메일 인증 체계(SPF/DKIM/DMARC) 구축 및 스푸핑 탐지
- SSH 터널링으로 방화벽 우회, 다중 홉 피벗 구성
- 네트워크 인프라 이상 징후 자동 탐지

## 핵심 포인트

```
DNS: Zone Transfer 차단 → DNSSEC 배포 → DNS 터널링 로그 분석
메일: SPF(-all) → DKIM 서명 → DMARC(reject) 순으로 단계적 강화
SSH:  AllowTcpForwarding no + 키 인증 전용 + 출발지 IP 제한
```
