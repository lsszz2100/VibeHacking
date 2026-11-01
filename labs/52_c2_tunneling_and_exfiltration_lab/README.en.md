# Lab 52: C2TunnelGuard — C2 Network Tunneling & Covert Channel Defense Lab

## Overview
Analyze command and control (C2) network tunneling, proxy pivoting, and covert exfiltration techniques. Master multi-layered defense using Shannon entropy analysis, reverse SOCKS5 blocking, Malleable C2 jitter beacon detection, and Zeek/Suricata deep packet inspection (DPI).

- **Default Port**: `8052`
- **Category**: `network` / `redteam` / `detection`
- **Difficulty**: ★★★★★

## Stages
1. **Stage 1 (DNS Tunneling Entropy Analysis)**:
   - Measure FQDN Shannon entropy ($H \ge 3.8$) in DNS queries (TXT/A) and identify Base32/Base64 exfiltration chunks.
   - Flag: `FLAG{DNS_TUNNEL_SHANNON_ENTROPY_EXFIL_8841}`
2. **Stage 2 (Reverse SOCKS5 / Chisel Dynamic Pivoting Defense)**:
   - Thwart unauthorized lateral movement and multi-hop pivoting via reverse SSH/Chisel tunnels.
   - Flag: `FLAG{SOCKS5_CHISEL_REVERSE_PIVOT_BLOCKED_4129}`
3. **Stage 3 (Malleable C2 Jitter & Beacon Profile Fingerprinting)**:
   - Statistically analyze inter-packet arrival time (IAT) variance and fingerprint Cobalt Strike Malleable C2 profiles.
   - Flag: `FLAG{C2_MALLEABLE_JITTER_BEACON_NEUTRALIZED_9502}`
4. **Stage 4 (Inline DPI & Suricata/Zeek Behavioral Defense)**:
   - Enforce Zeek DNS heuristics and stateful Suricata flowbits inline drop rules.
   - Flag: `FLAG{INLINE_SURICATA_ZEEK_FLOWBITS_DROPPED_7730}`

## Quick Start
```bash
python3 vhack.py lab start 52
# Web Console: http://localhost:8052
```
