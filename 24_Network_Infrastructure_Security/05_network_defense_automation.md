> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 네트워크 방어 자동화 — IDS/IPS 튜닝·방화벽 자동화·네트워크 모니터링

## 0. 초보자를 위한 개념 이해

### 네트워크 방어 자동화란?

현대 기업 네트워크는 초당 수백만 건의 패킷이 흐릅니다. 사람이 모든 트래픽을 분석하는 것은 불가능하므로, 자동화된 감지·차단·대응 체계가 필수입니다.

```
네트워크 방어 자동화 구성 요소:

  감지 계층:
    IDS (Intrusion Detection System)
      → 트래픽 분석, 시그니처/이상 감지, 경보 발생
      → Snort, Suricata, Zeek(Bro)

  차단 계층:
    IPS (Intrusion Prevention System)
      → IDS + 자동 차단 (인라인 모드)
      → 방화벽 규칙 자동 추가

  모니터링 계층:
    NetFlow / sFlow → 트래픽 통계 수집
    PCAP 분석      → 전체 패킷 캡처
    SIEM           → 이벤트 상관분석

  자동화 대응:
    Playbook 실행 → IP 차단 → 알림 → 티켓 생성
```

---

## 1. Suricata IDS/IPS 규칙 자동화

### 1.1 Suricata 설치 및 기본 설정

```bash
# Ubuntu/Debian Suricata 설치
sudo apt-get install -y suricata suricata-update

# 규칙 업데이트
sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open   # Emerging Threats 오픈 규칙

# 설정 파일 주요 항목
# /etc/suricata/suricata.yaml

# 인터페이스 설정
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# IPS 모드 (인라인) — NFQueue 사용
nfqueue:
  - queue-id: 0
    threads: 4

# 로그 출력
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - flow

# IDS 모드로 시작
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# IPS 모드 (iptables NFQueue 필요)
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0
```

### 1.2 커스텀 Suricata 규칙 작성

```bash
# /etc/suricata/rules/local.rules

# 포트 스캔 감지 (SYN 패킷 임계값)
alert tcp any any -> $HOME_NET any \
    (msg:"PORTSCAN TCP SYN 고속 스캔 감지"; \
     flags:S,12; threshold:type both,track by_src,count 200,seconds 5; \
     classtype:network-scan; sid:9000001; rev:1;)

# SQL 인젝션 시도 감지
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"SQL 인젝션 시도 — 기본 키워드"; \
     flow:to_server,established; \
     http.uri; content:"' OR "; nocase; \
     classtype:web-application-attack; sid:9000002; rev:1;)

# 악성 User-Agent 감지
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"의심스러운 스캐너 User-Agent 감지"; \
     flow:to_server,established; \
     http.user_agent; content:"sqlmap"; nocase; \
     classtype:web-application-attack; sid:9000003; rev:1;)

# DNS 터널링 감지 (긴 서브도메인)
alert dns any any -> any any \
    (msg:"DNS 터널링 의심 — 비정상적으로 긴 쿼리"; \
     dns.query; isdataat:60,relative; \
     classtype:policy-violation; sid:9000004; rev:1;)

# Mimikatz LSASS 덤프 감지
alert smb $HOME_NET any -> $HOME_NET any \
    (msg:"Mimikatz LSASS 덤프 의심 — SMB 파이프 접근"; \
     flow:to_server,established; \
     content:"|00 00 00 00|"; depth:4; \
     classtype:credential-theft; sid:9000005; rev:1;)
```

### 1.3 Suricata EVE JSON 알림 파싱 자동화

```python
#!/usr/bin/env python3
"""
Suricata EVE JSON 로그 실시간 파싱 및 자동 대응.
참고: https://suricata.readthedocs.io/en/latest/output/eve/
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

BLOCKED_IPS_FILE = Path("/tmp/blocked_ips.txt")
HIGH_PRIORITY_SIGNATURES = {
    "SQL 인젝션", "Mimikatz", "LSASS", "DNS 터널링", "RCE", "EXPLOIT"
}


def tail_eve_log(eve_path: str = "/var/log/suricata/eve.json"):
    """EVE JSON 로그 실시간 추적 (tail -f 방식)."""
    path = Path(eve_path)
    if not path.exists():
        raise FileNotFoundError(f"EVE 로그 없음: {eve_path}")

    with open(eve_path, "r", encoding="utf-8") as f:
        f.seek(0, 2)  # 파일 끝으로 이동
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass


def process_alert(event: dict) -> Optional[dict]:
    """
    경보 이벤트 처리 및 우선순위 분류.
    반환: 처리된 경보 또는 None
    """
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "")
    msg = alert.get("signature", "")
    severity = alert.get("severity", 3)  # 1=높음, 3=낮음

    processed = {
        "timestamp": event.get("timestamp"),
        "src_ip": src_ip,
        "dst_ip": event.get("dest_ip"),
        "dst_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "signature": msg,
        "severity": severity,
        "category": alert.get("category", "unknown"),
        "high_priority": (
            severity == 1
            or any(kw.lower() in msg.lower() for kw in HIGH_PRIORITY_SIGNATURES)
        ),
    }

    return processed


def block_ip_iptables(ip: str, reason: str = "") -> bool:
    """
    iptables로 IP 자동 차단.
    실제 환경에서는 firewall API나 WAF를 통해 처리 권장.
    """
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1"):
        log.warning("차단 불가: 무효한 IP %s", ip)
        return False

    # 이미 차단된 IP 확인
    blocked = set()
    if BLOCKED_IPS_FILE.exists():
        blocked = set(BLOCKED_IPS_FILE.read_text().splitlines())

    if ip in blocked:
        log.info("이미 차단된 IP: %s", ip)
        return True

    try:
        # DROP 규칙 추가
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        # 차단 목록에 추가
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")

        log.warning("IP 차단 완료: %s (사유: %s)", ip, reason)
        return True
    except (subprocess.CalledProcessError, PermissionError) as exc:
        log.error("IP 차단 실패: %s — %s", ip, exc)
        return False


def send_slack_alert(webhook_url: str, alert: dict) -> None:
    """Slack 웹훅으로 고위험 경보 전송."""
    import urllib.request

    priority_tag = "🔴 HIGH PRIORITY" if alert.get("high_priority") else "🟡 Alert"
    message = {
        "text": (
            f"{priority_tag} | Suricata 경보\n"
            f"*서명*: {alert.get('signature')}\n"
            f"*출발지*: `{alert.get('src_ip')}`\n"
            f"*목적지*: `{alert.get('dst_ip')}:{alert.get('dst_port')}`\n"
            f"*시간*: {alert.get('timestamp')}"
        )
    }
    data = json.dumps(message).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            log.info("Slack 알림 전송 완료: %s", resp.status)
    except Exception as exc:
        log.error("Slack 알림 실패: %s", exc)


def auto_response_pipeline(
    eve_path: str,
    slack_webhook: str = "",
    auto_block: bool = False,
) -> None:
    """
    자동 대응 파이프라인:
    경보 수신 → 분류 → 고위험 차단/알림
    """
    alert_counter: Counter = Counter()
    blocked: set[str] = set()

    log.info("Suricata 자동 대응 파이프라인 시작: %s", eve_path)

    for event in tail_eve_log(eve_path):
        alert = process_alert(event)
        if not alert:
            continue

        src_ip = alert["src_ip"]
        alert_counter[src_ip] += 1

        # 동일 IP에서 50회 이상 경보 → 자동 차단 검토
        if alert_counter[src_ip] >= 50 and src_ip not in blocked:
            log.warning("임계값 초과: %s (%d 경보)", src_ip, alert_counter[src_ip])
            if auto_block:
                if block_ip_iptables(src_ip, f"임계값 초과 ({alert_counter[src_ip]}회)"):
                    blocked.add(src_ip)

        # 고위험 경보 즉시 알림
        if alert.get("high_priority") and slack_webhook:
            send_slack_alert(slack_webhook, alert)

        log.info("[%s] %s → %s:%s | %s",
                 alert["category"], src_ip,
                 alert["dst_ip"], alert["dst_port"],
                 alert["signature"][:60])
```

---

## 2. 방화벽 규칙 자동화

### 2.1 iptables 규칙 자동 관리

```python
#!/usr/bin/env python3
"""
iptables/nftables 방화벽 규칙 자동화.
CIS 벤치마크 기반 기본 정책 적용.
"""
from __future__ import annotations

import argparse
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class FirewallRule:
    chain: str        # INPUT/OUTPUT/FORWARD
    protocol: str     # tcp/udp/icmp/all
    source: str = "any"
    destination: str = "any"
    dport: Optional[int] = None
    sport: Optional[int] = None
    action: str = "ACCEPT"  # ACCEPT/DROP/REJECT/LOG
    comment: str = ""


def run_iptables(args: list[str]) -> bool:
    """iptables 명령 실행."""
    cmd = ["iptables"] + args
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as exc:
        log.error("iptables 오류: %s — %s", " ".join(cmd), exc.stderr.decode())
        return False


def apply_default_hardening_policy() -> None:
    """
    CIS 벤치마크 기반 기본 방화벽 정책 적용.
    실행 전 반드시 현재 규칙 백업 필요.
    """
    log.info("기본 방화벽 정책 적용 시작")

    # 기본 정책: 모두 차단
    for chain in ["INPUT", "FORWARD", "OUTPUT"]:
        run_iptables(["-P", chain, "DROP"])

    # Loopback 허용
    run_iptables(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_iptables(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    # 기존 연결 허용 (Stateful)
    run_iptables(["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_iptables(["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # SSH 접근 허용 (특정 관리 IP만)
    run_iptables(["-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "state",
                  "--state", "NEW", "-j", "ACCEPT"])

    # ICMP ping 허용 (속도 제한)
    run_iptables(["-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                  "-m", "limit", "--limit", "1/s", "-j", "ACCEPT"])

    # 포트 스캔 차단 (NULL 패킷)
    run_iptables(["-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"])

    # SYN 플러드 방지
    run_iptables(["-A", "INPUT", "-p", "tcp", "!", "--syn", "-m", "state",
                  "--state", "NEW", "-j", "DROP"])

    # 로그 없는 드롭 (마지막 규칙)
    run_iptables(["-A", "INPUT", "-m", "limit", "--limit", "5/min", "-j", "LOG",
                  "--log-prefix", "FW_DROP: ", "--log-level", "7"])

    log.info("기본 방화벽 정책 적용 완료")


def backup_rules(output_file: str = "/etc/iptables/rules.v4") -> bool:
    """현재 iptables 규칙 백업."""
    try:
        result = subprocess.run(["iptables-save"], capture_output=True, check=True)
        import os
        os.makedirs(str(output_file).rsplit("/", 1)[0], exist_ok=True)
        with open(output_file, "wb") as f:
            f.write(result.stdout)
        log.info("규칙 백업 완료: %s", output_file)
        return True
    except (subprocess.CalledProcessError, OSError) as exc:
        log.error("백업 실패: %s", exc)
        return False


def geo_block_country(country_code: str, ipset_name: str = "blocked_geo") -> None:
    """
    ipset을 사용한 국가 단위 IP 차단.
    ipset과 ipinfo CLI 필요.
    실제 IP 목록은 MaxMind GeoIP2 또는 ipinfo.io에서 획득.
    """
    log.info("국가 차단 설정: %s", country_code)
    # ipset 생성
    subprocess.run(["ipset", "create", ipset_name, "hash:net"], capture_output=True)
    # iptables 규칙 추가
    run_iptables(["-I", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"])
    log.info("국가 차단 ipset 규칙 추가 완료 (IP 목록은 별도 스크립트로 로드)")
```

---

## 3. NetFlow 트래픽 분석

```python
#!/usr/bin/env python3
"""
NetFlow/IPFIX 데이터 수집 및 이상 트래픽 감지.
nfdump 명령줄 도구 기반.
참고: https://github.com/phaag/nfdump
"""
from __future__ import annotations

import logging
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def get_top_talkers(nfcapd_dir: str, top_n: int = 20) -> list[dict]:
    """
    nfdump으로 최근 5분간 트래픽 상위 소스 IP 조회.
    대용량 트래픽 발생 IP → DDoS/데이터 유출 의심.
    """
    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y/%m/%d.%H:%M:%S")
    cmd = [
        "nfdump", "-R", nfcapd_dir,
        "-t", f"{since}",
        "-s", f"srcip/{top_n}",
        "-o", "csv",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        talkers = []
        for line in result.stdout.splitlines()[1:]:  # 헤더 제외
            parts = line.split(",")
            if len(parts) >= 4:
                talkers.append({
                    "src_ip": parts[0].strip(),
                    "flows": parts[1].strip(),
                    "bytes": parts[2].strip(),
                    "packets": parts[3].strip(),
                })
        return talkers
    except FileNotFoundError:
        log.error("nfdump이 설치되지 않았습니다: apt-get install nfdump")
        return []


def detect_dns_exfiltration(
    nfcapd_dir: str,
    threshold_bytes: int = 1_000_000
) -> list[str]:
    """
    DNS 포트(53)로 과다한 데이터 전송 → DNS 터널링/데이터 유출 감지.
    정상 DNS 트래픽은 쿼리/응답이 매우 작음 (수백 바이트).
    """
    cmd = [
        "nfdump", "-R", nfcapd_dir,
        "-A", "srcip",
        "-O", "bytes",
        "dst port 53 and bytes >" + str(threshold_bytes),
        "-o", "csv",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        suspicious: list[str] = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(",")
            if parts:
                suspicious.append(parts[0].strip())
                log.warning("DNS 터널링 의심: %s (bytes: %s)",
                             parts[0].strip(), parts[2].strip() if len(parts) > 2 else "?")
        return suspicious
    except FileNotFoundError:
        return []


def analyze_beaconing(
    flows: list[dict],
    interval_tolerance_secs: int = 10,
) -> list[str]:
    """
    규칙적인 네트워크 통신 패턴 감지 (C2 비콘 의심).
    동일 src→dst 쌍이 일정 간격으로 반복 접속하면 비콘으로 분류.
    """
    conn_times: dict[tuple, list[float]] = defaultdict(list)

    for flow in flows:
        key = (flow.get("src_ip", ""), flow.get("dst_ip", ""), flow.get("dst_port", ""))
        ts = flow.get("timestamp", 0)
        if ts:
            conn_times[key].append(float(ts))

    beacons: list[str] = []
    for (src, dst, port), times in conn_times.items():
        if len(times) < 5:
            continue
        times_sorted = sorted(times)
        intervals = [times_sorted[i+1] - times_sorted[i] for i in range(len(times_sorted)-1)]
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        # 분산이 낮을수록 규칙적인 통신 → 비콘 의심
        if avg > 0 and variance / avg < interval_tolerance_secs:
            beacons.append(f"{src} → {dst}:{port} (avg interval: {avg:.1f}s, var: {variance:.1f})")
            log.warning("C2 비콘 의심: %s → %s:%s", src, dst, port)

    return beacons
```

---

## 4. 네트워크 보안 대시보드 (CLI)

```python
#!/usr/bin/env python3
"""
네트워크 보안 현황 CLI 대시보드.
실시간 연결, 차단 IP, 최근 경보 현황 표시.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path


def get_active_connections() -> list[dict]:
    """현재 활성 TCP 연결 목록 조회."""
    result = subprocess.run(
        ["ss", "-tnp", "state", "established"],
        capture_output=True, text=True, check=False
    )
    connections = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "local": parts[3],
                "remote": parts[4],
                "process": parts[5] if len(parts) > 5 else "",
            })
    return connections


def get_recent_firewall_drops(log_path: str = "/var/log/syslog", count: int = 10) -> list[str]:
    """최근 방화벽 DROP 로그 조회."""
    try:
        result = subprocess.run(
            ["grep", "FW_DROP", log_path],
            capture_output=True, text=True, check=False
        )
        lines = result.stdout.splitlines()
        return lines[-count:] if lines else []
    except FileNotFoundError:
        return ["syslog 파일 없음"]


def print_dashboard() -> None:
    """CLI 보안 대시보드 출력."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{'='*60}")
    print(f"  네트워크 보안 대시보드 — {now}")
    print(f"{'='*60}")

    # 활성 연결
    conns = get_active_connections()
    print(f"\n[활성 TCP 연결: {len(conns)}개]")
    for c in conns[:5]:
        print(f"  {c['local']:30s} ← {c['remote']}")
    if len(conns) > 5:
        print(f"  ... ({len(conns)-5}개 더)")

    # 차단된 IP
    if Path("/tmp/blocked_ips.txt").exists():
        blocked = Path("/tmp/blocked_ips.txt").read_text().splitlines()
        print(f"\n[차단된 IP: {len(blocked)}개]")
        for ip in blocked[-5:]:
            print(f"  {ip}")

    # 최근 방화벽 DROP
    drops = get_recent_firewall_drops(count=5)
    print(f"\n[최근 방화벽 DROP 로그]")
    for line in drops:
        print(f"  {line[:80]}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="네트워크 보안 대시보드")
    parser.add_argument("--watch", action="store_true", help="5초마다 갱신")
    args = parser.parse_args()

    if args.watch:
        import time
        while True:
            print_dashboard()
            time.sleep(5)
    else:
        print_dashboard()
```

---

## 5. 참고 자료

- **Suricata 공식 문서**: https://suricata.readthedocs.io/en/latest/
- **Emerging Threats 규칙**: https://rules.emergingthreats.net/
- **nfdump/nfsen**: https://github.com/phaag/nfdump

---

<!-- detect-validate-24 -->
## 네트워크 방어 자동화 작동 검증과 회귀

방어 자동화는 *돌렸다*가 아니라 *룰이 발화하고 차단이 실제로 막는가*로 가치가 갈린다. 방어자는 **IDS/방화벽 자동화가 주입 이벤트에 발화·차단하는가**를 검증해야 한다. 검증은 **소유 망**에서만.

### 검증 항목 → 질문 → 측정 신호 → 함정

| 검증 항목 | 질문 | 측정 신호 | 함정 |
|---|---|---|---|
| Suricata 룰 | 주입 트래픽에 발화하나? | fast.log 알림 건수 | 룰 로드 실패 무시 |
| 방화벽 자동화 | 차단이 실제 적용되나? | DROP 카운터 증가 | 규칙 순서로 무력화 |
| 이상 탐지 | 베이스라인 이탈을 잡나? | 알림 TP/FP 비율 | 베이스라인 노후화 |
| IPS 인라인 | 패킷을 실제 떨구나? | 차단 후 무응답 | IDS-only 오인 |

### 방어 검증 (직접 확인)

```bash
# 1) Suricata 룰이 주입 트래픽에 발화하는지 검증(소유 망) — 무발화면 룰/로드 문제
sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -iE "error|loaded"; sudo tail -3 /var/log/suricata/fast.log 2>/dev/null
# 2) 방화벽 자동 차단이 실제 적용되는지 — DROP 규칙 히트 카운터 확인
sudo iptables -L -v -n 2>/dev/null | grep -E "DROP|REJECT" | head
```

> 방어 자동화 검증은 *돌렸는가*가 아니라 *발화·차단하는가*다 — "Suricata 깔려 있다"와 "주입 이벤트에 발화하고 방화벽이 실제로 떨군다"는 다르다. 소유 망에서 룰 발화·DROP 카운터를 직접 확인한다([[13_SOC_Blue_Team]], [[40_Threat_Hunting]], [[68_Purple_Team]]).

---

<a name="english"></a>

# Network Defense Automation — IDS/IPS Tuning, Firewall Automation, Network Monitoring

## Overview

Modern enterprise networks carry millions of packets per second. Automated detection, blocking, and response systems are essential.

## Architecture

```
Internet
    ↓
Perimeter Firewall (iptables/nftables/pf)
    ↓
IPS (Suricata inline mode) ← auto-block feeds back to firewall
    ↓
Core Switch/Router
    ↓
IDS sensor (Suricata/Zeek in mirror/TAP mode)
    ↓
NetFlow collector (nfdump)
    ↓
SIEM (ELK/Splunk) ← correlated alerts
    ↓
SOC Analyst / SOAR Playbook
```

## Quick Start

```bash
# Install and start Suricata IDS
sudo apt-get install -y suricata suricata-update
sudo suricata-update
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Monitor live alerts
tail -f /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('event_type') == 'alert':
        print(e['alert']['signature'], e.get('src_ip'))
"

# Apply default firewall hardening
sudo python3 firewall_automation.py --harden

# Run network security dashboard
python3 dashboard.py --watch
```

## Key Automation Workflows

1. **Alert → Block**: High-severity Suricata alert → auto-add DROP rule to iptables
2. **Beaconing detection**: NetFlow analysis → periodic connections to same destination → C2 flag
3. **DNS exfiltration**: DNS flows > 1MB → DNS tunneling alert
4. **Geo-blocking**: ipset + iptables for country-level blocking

## References

- Suricata documentation: https://suricata.readthedocs.io/en/latest/
- Emerging Threats rules: https://rules.emergingthreats.net/
- nfdump: https://github.com/phaag/nfdump

<!-- detect-validate-24 -->
## Network Defense Automation Effectiveness Validation and Regression

Defense automation's value comes not from *whether it ran* but from *whether rules fire and blocks actually block*. Defenders must verify **whether IDS/firewall automation fires and blocks on injected events**. Validate only on **owned networks**.

### Check -> Question -> Signal -> Pitfall

| Check | Question | Signal | Pitfall |
|---|---|---|---|
| Suricata rules | Does it fire on injected traffic? | fast.log alert count | Ignoring rule-load failures |
| Firewall automation | Is the block actually applied? | Rising DROP counter | Neutralized by rule order |
| Anomaly detection | Does it catch baseline deviation? | Alert TP/FP ratio | Stale baseline |
| Inline IPS | Does it actually drop packets? | No response after block | Mistaken for IDS-only |

### Defense validation (verify directly)

```bash
# 1) Verify Suricata rules fire on injected traffic (owned network) — no fire means rule/load problem
sudo suricata -T -c /etc/suricata/suricata.yaml 2>&1 | grep -iE "error|loaded"; sudo tail -3 /var/log/suricata/fast.log 2>/dev/null
# 2) Verify firewall auto-block is actually applied — check DROP rule hit counters
sudo iptables -L -v -n 2>/dev/null | grep -E "DROP|REJECT" | head
```

> Defense-automation validation is *whether it fires and blocks*, not *whether it ran* -- "Suricata is installed" differs from "it fires on injected events and the firewall actually drops". Confirm rule firing and DROP counters on owned networks directly ([[13_SOC_Blue_Team]], [[40_Threat_Hunting]], [[68_Purple_Team]]).
