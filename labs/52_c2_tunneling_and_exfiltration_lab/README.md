# Lab 52: C2TunnelGuard — C2 네트워크 터널링 및 은닉 채널 방어 실습

## 실습 개요
C2(Command and Control) 네트워크 터널링, 프록시 피보팅 및 은닉 데이터 유출(Covert Exfiltration)의 공격 기법을 분석하고, Shannon 엔트로피 분석, 역방향 SOCKS5 차단, Malleable C2 지터 비콘 탐지 및 Zeek/Suricata 심층 패킷 검사(DPI)를 통한 다계층 능동 방어를 실습합니다.

- **기본 포트**: `8052`
- **카테고리**: `network` / `redteam` / `detection`
- **난이도**: ★★★★★

## 실습 단계 (Stages)
1. **Stage 1 (DNS Tunneling Entropy Analysis)**:
   - DNS 쿼리(TXT/A) FQDN 페이로드 엔트로피 측정 ($H \ge 3.8$) 및 Base32/Base64 청크 식별
   - 플래그: `FLAG{DNS_TUNNEL_SHANNON_ENTROPY_EXFIL_8841}`
2. **Stage 2 (Reverse SOCKS5 / Chisel Dynamic Pivoting Defense)**:
   - 역방향 SSH/Chisel 터널을 통한 비인가 내부망 접근 시도 차단 및 다중 홉 격리
   - 플래그: `FLAG{SOCKS5_CHISEL_REVERSE_PIVOT_BLOCKED_4129}`
3. **Stage 3 (Malleable C2 Jitter & Beacon Profile Fingerprinting)**:
   - 푸아송 분포 지터 비콘 패킷 간격(IAT) 분산 분석 및 Cobalt Strike Malleable 프로필 식별
   - 플래그: `FLAG{C2_MALLEABLE_JITTER_BEACON_NEUTRALIZED_9502}`
4. **Stage 4 (Inline DPI & Suricata/Zeek Behavioral Defense)**:
   - Zeek DNS 터널링 휴리스틱 스크립트 및 Suricata Flowbits 상태 기반 인라인 드롭 룰 활성화
   - 플래그: `FLAG{INLINE_SURICATA_ZEEK_FLOWBITS_DROPPED_7730}`

## 빠른 실행
```bash
python3 vhack.py lab start 52
# 웹 콘솔: http://localhost:8052
```
