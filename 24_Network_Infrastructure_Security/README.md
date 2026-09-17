# 24. Network Infrastructure Security

## 목차

| 파일 | 내용 |
|------|------|
| [01_dns_attack_defense.md](./01_dns_attack_defense.md) | Zone Transfer, Cache Poisoning, DNS Tunneling, Subdomain Takeover, DNSSEC |
| [02_mail_server_security.md](./02_mail_server_security.md) | SPF/DKIM/DMARC 설정·분석, 오픈 릴레이, 스푸핑 탐지 자동화 |
| [03_ssh_tunneling_port_forwarding.md](./03_ssh_tunneling_port_forwarding.md) | SSH -L/-R/-D, Chisel HTTP 터널, 다중 홉 피벗, 터널 탐지·차단 |
| [04_network_security_automation.md](./04_network_security_automation.md) | **네트워크 보안 자동화** — 네트워크 보안 자동화는 포트 스캔, 취약점 검색, 방화벽 규칙 감사, 패킷 분석 등 반복적인 보안 작업을 코드로 자동화하는 것이다. 수백 대의 서버를 수작업으로 점검하는 것은 불가능하... |
| [05_network_defense_automation.md](./05_network_defense_automation.md) | **네트워크 방어 자동화 — IDS/IPS 튜닝·방화벽 자동화·네트워크 모니터링** — 현대 기업 네트워크는 초당 수백만 건의 패킷이 흐릅니다. 사람이 모든 트래픽을 분석하는 것은 불가능하므로, 자동화된 감지·차단·대응 체계가 필수입니다. |
| [06_network_infra_ctf_lab.md](./06_network_infra_ctf_lab.md) | **네트워크 인프라 CTF 실습 랩** — DNS 공격, BGP 하이재킹, 네트워크 피버팅 기법을 실습하는 CTF 환경입니다. |

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
