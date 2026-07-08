> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 레드팀 인프라 탐지 우회 (방어자 관점)

## 0. 초보자를 위한 개념 이해

### 레드팀 탐지 우회란?

**레드팀 탐지 우회(Detection Evasion)**는 공격 활동이 보안 솔루션(IDS, EDR, SIEM)에 탐지되지 않도록 하는 기술입니다. 방어자(블루팀) 관점에서는 이 기법을 이해해야 더 효과적인 탐지 룰을 만들 수 있습니다.

> 📌 이 문서는 **방어자가 공격자 TTP를 이해하고 탐지를 강화**하는 목적으로 작성됐습니다.

**왜 배우는가:**
```
블루팀 입장:
  공격자가 어떻게 우회하는지 모르면 → 탐지 룰 허점 발생

레드팀 입장:
  현실적인 위협 시뮬레이션 → 방어 수준 정확히 평가

균형:
  탐지 우회 기법 이해 = 더 강한 탐지 시스템 구축 가능
```

### 핵심 우회 기법 개요

```
1. 네트워크 트래픽 위장
   - C2 통신을 HTTPS처럼 보이게 (도메인 프론팅)
   - Malleable C2 Profile: Cobalt Strike 트래픽 위장
   - DNS over HTTPS (DoH) 터널링

2. 메모리 내 실행 (Fileless)
   - 디스크에 파일 없이 메모리에서만 실행
   - PowerShell IEX (Invoke-Expression)
   - Process Injection (다른 프로세스 메모리에 코드 삽입)

3. Living Off the Land (LOTL)
   - 시스템 기본 도구만 사용
   - certutil.exe, wmic.exe, mshta.exe
   - EDR이 정상 도구로 인식 → 탐지 어려움

4. 타임스탬프 조작
   - 파일 생성·수정 시간 변경
   - 정상 시스템 파일과 같은 시간대로 변경
```

### 필요한 도구
- **Cobalt Strike Malleable C2**: C2 트래픽 위장
- **Sysmon + ELK**: 공격 탐지 테스트 환경

### 기초 실습 예제
```python
# 탐지 우회 기법 분류 및 MITRE ATT&CK 매핑
evasion_techniques = [
    ("T1055", "Process Injection", "High", "EDR 프로세스 모니터링 강화"),
    ("T1140", "Deobfuscate/Decode Files", "Medium", "난독화 패턴 시그니처 추가"),
    ("T1218", "System Binary Proxy Execution", "High", "LOTL 도구 실행 로깅"),
    ("T1071", "Application Layer Protocol", "Medium", "비정상 HTTPS 패턴 탐지"),
]

print("MITRE ATT&CK 탐지 우회 기법\n")
print(f"{'ID':<8} {'기법':<35} {'위험도':<8} {'대응'}")
print("-" * 80)
for tid, name, risk, response in evasion_techniques:
    print(f"{tid:<8} {name:<35} {risk:<8} {response}")
```

---

## 1. C2 트래픽 위장 탐지

### 1.1 Domain Fronting 탐지

Domain Fronting은 CDN 도메인을 SNI에, 실제 C2를 Host 헤더에 사용하는 기법이다. 방어자는 SNI와 Host 헤더 불일치를 탐지할 수 있다.

```python
#!/usr/bin/env python3
"""CDN Domain Fronting 탐지 시스템"""
import argparse
from scapy.all import TLS, IP, TCP, sniff
import re


class DomainFrontingDetector:
    CDN_PROVIDERS = {
        "cloudfront.net", "azureedge.net", "akamaiedge.net",
        "fastly.net", "cloudflare.com", "cdn.jsdelivr.net",
    }

    def __init__(self) -> None:
        self.alerts: list[dict] = []

    def extract_sni(self, pkt) -> str | None:
        if not (pkt.haslayer(TLS) and pkt.haslayer(IP)):
            return None
        try:
            # TLS ClientHello SNI 추출
            tls = pkt[TLS]
            payload = bytes(tls)
            sni_match = re.search(b"\x00\x00(.{2})([\w\.\-]+)", payload)
            if sni_match:
                return sni_match.group(2).decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    def extract_http_host(self, pkt) -> str | None:
        if not pkt.haslayer(TCP):
            return None
        try:
            payload = bytes(pkt[TCP].payload)
            host_match = re.search(rb"Host: ([^\r\n]+)", payload, re.IGNORECASE)
            if host_match:
                return host_match.group(1).decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    def check_fronting(self, pkt) -> None:
        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        sni = self.extract_sni(pkt)
        host = self.extract_http_host(pkt)

        if sni and host and sni != host:
            sni_is_cdn = any(cdn in sni for cdn in self.CDN_PROVIDERS)
            if sni_is_cdn:
                alert = {
                    "src": src,
                    "sni": sni,
                    "host": host,
                    "alert": "Domain Fronting 의심",
                }
                self.alerts.append(alert)
                print(f"[!] Domain Fronting: {src} | SNI={sni} | Host={host}")

    def start(self, iface: str = "eth0") -> None:
        print(f"[*] Domain Fronting 탐지 시작: {iface}")
        sniff(iface=iface, filter="tcp port 443", prn=self.check_fronting, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Domain Fronting 탐지")
    parser.add_argument("-i", "--interface", default="eth0")
    args = parser.parse_args()
    DomainFrontingDetector().start(args.interface)


if __name__ == "__main__":
    main()
```

### 1.2 C2 프로파일 기반 탐지 (Malleable C2)

Cobalt Strike Malleable C2 프로파일을 모방한 트래픽 특성을 탐지한다.

```python
#!/usr/bin/env python3
"""Cobalt Strike C2 트래픽 패턴 탐지"""
import re
from dataclasses import dataclass


@dataclass
class C2Profile:
    name: str
    uri_patterns: list[str]
    user_agent_patterns: list[str]
    header_indicators: list[str]


KNOWN_CS_PROFILES: list[C2Profile] = [
    C2Profile(
        "jQuery",
        ["/jquery-3.3.1.slim.min.js", "/jquery-3.3.2.min.js"],
        ["Mozilla/5.0.*jQuery"],
        ["__utmc=", "MUID="],
    ),
    C2Profile(
        "Office365",
        ["/owa/auth/", "/autodiscover/"],
        ["Microsoft Office.*"],
        ["X-MS-Exchange", "X-FEServer"],
    ),
    C2Profile(
        "Ocsp",
        ["/ocsp", "/ocsp/"],
        [""],
        ["Content-Type: application/ocsp-request"],
    ),
]


class MalleableC2Detector:
    def __init__(self) -> None:
        self.compiled_profiles = [
            (
                profile.name,
                [re.compile(p, re.IGNORECASE) for p in profile.uri_patterns if p],
                [re.compile(p, re.IGNORECASE) for p in profile.user_agent_patterns if p],
                profile.header_indicators,
            )
            for profile in KNOWN_CS_PROFILES
        ]

    def analyze_request(
        self,
        uri: str,
        user_agent: str,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> dict:
        matches = []

        for name, uri_pats, ua_pats, header_inds in self.compiled_profiles:
            uri_match = any(p.search(uri) for p in uri_pats)
            ua_match = any(p.search(user_agent) for p in ua_pats)
            header_match = any(ind in str(headers) for ind in header_inds)

            if uri_match or (ua_match and header_match):
                matches.append(name)

        # Cobalt Strike 비콘 특성 탐지
        cs_beacon_indicators = []
        if len(body) == 48 and not any(c > 127 for c in body[:4]):
            cs_beacon_indicators.append("CS 비콘 크기 (48바이트 체크인)")
        if "Pragma: no-cache" in str(headers) and "Cache-Control: no-cache" in str(headers):
            cs_beacon_indicators.append("CS 기본 캐시 헤더 패턴")

        return {
            "uri": uri,
            "matched_profiles": matches,
            "beacon_indicators": cs_beacon_indicators,
            "suspicious": bool(matches or cs_beacon_indicators),
        }
```

---

## 2. Living Off the Land 탐지

### 2.1 LOLBAS 이상 행위 탐지

```python
#!/usr/bin/env python3
"""LOLBAS(Living Off the Land Binaries) 이상 실행 탐지"""
import argparse
import re
from dataclasses import dataclass


@dataclass
class LOLBASRule:
    binary: str
    suspicious_args: list[str]
    normal_parent_processes: list[str]
    severity: str
    description: str
    mitre: str


LOLBAS_RULES: list[LOLBASRule] = [
    LOLBASRule(
        "certutil.exe",
        ["-decode", "-urlcache", "-f http", "-f ftp"],
        ["cmd.exe", "explorer.exe"],
        "High",
        "인증서 유틸리티를 파일 다운로드에 악용",
        "T1218.crt",
    ),
    LOLBASRule(
        "mshta.exe",
        ["http://", "https://", "javascript:", "vbscript:"],
        ["explorer.exe"],
        "Critical",
        "HTA 파일 실행으로 스크립트 실행",
        "T1218.005",
    ),
    LOLBASRule(
        "regsvr32.exe",
        ["/s /n /u /i:http", "scrobj.dll"],
        ["cmd.exe", "explorer.exe"],
        "Critical",
        "COM 객체를 통한 원격 스크립트 실행 (Squiblydoo)",
        "T1218.010",
    ),
    LOLBASRule(
        "wmic.exe",
        ["process call create", "/node:", "os get"],
        ["cmd.exe"],
        "High",
        "WMIC를 통한 원격 코드 실행",
        "T1047",
    ),
    LOLBASRule(
        "powershell.exe",
        ["-enc", "-EncodedCommand", "-nop -w hidden", "downloadstring", "iex("],
        ["cmd.exe", "explorer.exe", "winword.exe", "excel.exe"],
        "High",
        "PowerShell을 통한 인코딩된 명령 실행",
        "T1059.001",
    ),
    LOLBASRule(
        "bitsadmin.exe",
        ["/transfer", "/download", "/create"],
        ["cmd.exe"],
        "Medium",
        "BITS를 통한 파일 다운로드",
        "T1197",
    ),
    LOLBASRule(
        "rundll32.exe",
        ["javascript:", "vbscript:", "shell32.dll,ShellExec_RunDLL http"],
        ["cmd.exe", "explorer.exe"],
        "High",
        "rundll32를 통한 스크립트 실행",
        "T1218.011",
    ),
]


class LOLBASDetector:
    def __init__(self) -> None:
        self.rules_map = {rule.binary.lower(): rule for rule in LOLBAS_RULES}

    def analyze_process(
        self,
        image_name: str,
        command_line: str,
        parent_process: str,
    ) -> list[dict]:
        findings = []
        binary = image_name.lower().split("\\")[-1]  # 경로에서 파일명만 추출
        rule = self.rules_map.get(binary)

        if not rule:
            return findings

        for suspicious_arg in rule.suspicious_args:
            if suspicious_arg.lower() in command_line.lower():
                # 부모 프로세스가 비정상적인 경우 더 의심
                parent_suspicious = not any(
                    normal.lower() in parent_process.lower()
                    for normal in rule.normal_parent_processes
                )

                findings.append({
                    "binary": binary,
                    "technique": rule.mitre,
                    "severity": "Critical" if parent_suspicious else rule.severity,
                    "description": rule.description,
                    "command": command_line[:200],
                    "parent": parent_process,
                    "anomalous_parent": parent_suspicious,
                })
                break

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="LOLBAS 탐지 테스터")
    parser.add_argument("--image", required=True, help="프로세스 이미지 이름")
    parser.add_argument("--cmdline", required=True, help="커맨드라인")
    parser.add_argument("--parent", default="explorer.exe", help="부모 프로세스")
    args = parser.parse_args()

    detector = LOLBASDetector()
    findings = detector.analyze_process(args.image, args.cmdline, args.parent)

    if findings:
        for f in findings:
            print(f"[{f['severity']}] {f['binary']} — {f['technique']}: {f['description']}")
    else:
        print("[*] 탐지된 이상 행위 없음")


if __name__ == "__main__":
    main()
```

---

## 3. 리다이렉터 체인 탐지

### 3.1 멀티홉 C2 트래픽 그래프 분석

```python
#!/usr/bin/env python3
"""네트워크 흐름 기반 C2 리다이렉터 체인 탐지"""
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    dst_port: int
    bytes_sent: int
    bytes_recv: int
    duration: float
    protocol: str


class C2ChainDetector:
    def __init__(self) -> None:
        self.connection_graph: dict[str, set[str]] = defaultdict(set)
        self.flow_stats: dict[tuple, list[NetworkFlow]] = defaultdict(list)

    def add_flow(self, flow: NetworkFlow) -> None:
        self.connection_graph[flow.src_ip].add(flow.dst_ip)
        key = (flow.src_ip, flow.dst_ip)
        self.flow_stats[key].append(flow)

    def detect_beaconing(self, min_beacons: int = 10, jitter_threshold: float = 0.2) -> list[dict]:
        import statistics

        beaconing = []
        for (src, dst), flows in self.flow_stats.items():
            if len(flows) < min_beacons:
                continue

            # 연결 간격 분석
            flows_sorted = sorted(flows, key=lambda f: f.duration)
            intervals = [
                flows_sorted[i+1].duration - flows_sorted[i].duration
                for i in range(len(flows_sorted) - 1)
            ]

            if not intervals:
                continue

            avg_interval = statistics.mean(intervals)
            if avg_interval <= 0:
                continue

            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            jitter = std_interval / avg_interval

            if jitter < jitter_threshold:  # 일정한 간격 = 비콘 의심
                beaconing.append({
                    "src": src,
                    "dst": dst,
                    "beacon_count": len(flows),
                    "avg_interval_sec": round(avg_interval, 2),
                    "jitter": round(jitter, 3),
                    "confidence": "HIGH" if jitter < 0.1 else "MEDIUM",
                })

        return beaconing

    def detect_relay_chain(self) -> list[list[str]]:
        # 중간 리다이렉터 노드 탐지 (입출력 연결이 모두 있는 노드)
        all_sources = set(self.connection_graph.keys())
        all_destinations = {dst for dsts in self.connection_graph.values() for dst in dsts}

        relay_candidates = all_sources & all_destinations

        chains = []
        for relay in relay_candidates:
            inbound = [src for src, dsts in self.connection_graph.items() if relay in dsts]
            outbound = list(self.connection_graph[relay])

            if inbound and outbound:
                for src in inbound:
                    for dst in outbound:
                        chains.append([src, relay, dst])

        return chains


def parse_netflow(log_path: Path) -> list[NetworkFlow]:
    flows = []
    for line in log_path.read_text().splitlines()[1:]:  # 헤더 스킵
        parts = line.split(",")
        if len(parts) < 7:
            continue
        try:
            flows.append(NetworkFlow(
                src_ip=parts[0].strip(),
                dst_ip=parts[1].strip(),
                dst_port=int(parts[2].strip()),
                bytes_sent=int(parts[3].strip()),
                bytes_recv=int(parts[4].strip()),
                duration=float(parts[5].strip()),
                protocol=parts[6].strip(),
            ))
        except (ValueError, IndexError):
            continue
    return flows


def main() -> None:
    parser = argparse.ArgumentParser(description="C2 리다이렉터 체인 탐지")
    parser.add_argument("netflow_log", help="넷플로우 CSV 로그")
    parser.add_argument("--min-beacons", type=int, default=10)
    args = parser.parse_args()

    detector = C2ChainDetector()
    flows = parse_netflow(Path(args.netflow_log))

    for flow in flows:
        detector.add_flow(flow)

    print(f"[*] 비콘 탐지 중...")
    beacons = detector.detect_beaconing(args.min_beacons)
    for b in beacons:
        print(f"  [{b['confidence']}] {b['src']} → {b['dst']} | 간격: {b['avg_interval_sec']}초 | Jitter: {b['jitter']}")

    print(f"\n[*] 릴레이 체인 탐지 중...")
    chains = detector.detect_relay_chain()
    for chain in chains[:10]:
        print(f"  체인: {' → '.join(chain)}")


if __name__ == "__main__":
    main()
```

---

## 4. Sigma 룰 — 레드팀 TTP 탐지

```yaml
# 비콘 주기 탐지 (Zeek/Suricata)
title: Periodic C2 Beaconing Pattern
id: c3d4e5f6-a7b8-9012-cdef-012345678901
description: 일정한 간격으로 반복되는 외부 통신 — C2 비콘 의심
logsource:
  product: zeek
  service: conn
detection:
  selection:
    resp_bytes|lt: 1000    # 소량 데이터만 수신
    orig_bytes|lt: 500     # 소량 데이터만 전송
    duration|lt: 5         # 짧은 연결 시간
  condition: selection
falsepositives:
  - 정기적인 헬스체크, NTP, DNS 업데이트
level: medium


---
# PowerShell 인코딩 명령 실행
title: PowerShell Encoded Command with Suspicious Parent
id: d4e5f6a7-b8c9-0123-def0-123456789012
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  suspicious_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\acrobat.exe'
  condition: selection and suspicious_parent
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

---

## 5. 레드팀 TTP vs 블루팀 탐지 매트릭스

| 레드팀 기법 | 탐지 방법 | 탐지 난이도 | 데이터 소스 |
|-----------|---------|-----------|-----------|
| Domain Fronting | SNI/Host 헤더 불일치 | 중간 | 프록시 로그, TLS 인스펙션 |
| DNS C2 | 고엔트로피 서브도메인, TXT 레코드 | 높음 | DNS 쿼리 로그 |
| HTTPS C2 | 비콘 패턴, 인증서 분석 | 높음 | 넷플로우, TLS 로그 |
| LOLBAS | 프로세스 부모-자녀 관계 | 낮음 | Sysmon, EDR |
| 프로세스 인젝션 | API 호출 시퀀스 | 중간 | EDR, Sysmon |
| Pass-the-Hash | NTLM 인증 소스 IP 불일치 | 낮음 | 윈도우 이벤트 로그 |
| Kerberoasting | 서비스 티켓 대량 요청 | 낮음 | DC 이벤트 4769 |

---

## 6. DNS-over-HTTPS(DoH) 은닉 C2 채널 탐지

레드팀 인프라가 평문 DNS 대신 **DoH(DNS-over-HTTPS)**로 C2 조회를 감싸는 사례가 늘고 있다 — 전통적 DNS 로그(포트 53) 기반 탐지가 통째로 무력화되기 때문이다. DoH 트래픽은 일반 HTTPS(포트 443)와 구분이 안 되는 것처럼 보이지만, 실제로는 **알려진 DoH 리졸버 목록에 없는 목적지로 향하는 TLS 연결 중 SNI가 없거나(ECH) JA3/JA4 지문이 브라우저가 아닌 curl/사설 클라이언트 라이브러리와 일치하는 경우**가 강한 신호가 된다. 블루팀 관점에서는 "DoH 자체를 차단"이 아니라 "정책에 없는 DoH 사용을 식별"이 목표다(기업 대부분은 브라우저 내장 DoH를 정당하게 쓰기 때문에 전면 차단은 오탐 폭증).

```python
#!/usr/bin/env python3
"""넷플로우/프록시 로그에서 알려진 DoH 리졸버가 아닌 목적지로의 HTTPS 연결 중
비-브라우저 JA3/JA4 지문 + 규칙적 비콘 간격이 겹치는 세션을 DoH 기반 C2 의심으로 표시."""
from collections import defaultdict
from statistics import mean, pstdev

KNOWN_DOH_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
}
BROWSER_JA4_PREFIXES = {"t13d1516h2", "t13d1517h2"}  # 주요 브라우저 JA4 계열(예시)


def flag_doh_c2(flow_log: list[dict]) -> list[dict]:
    """flow_log 항목: {dst_ip, port, ja4, ts, bytes_out}"""
    sessions = defaultdict(list)
    for f in flow_log:
        if f["port"] == 443 and f["dst_ip"] not in KNOWN_DOH_RESOLVERS:
            sessions[(f["dst_ip"], f["ja4"])].append(f)

    suspects = []
    for (dst_ip, ja4), events in sessions.items():
        if len(events) < 5 or ja4 in BROWSER_JA4_PREFIXES:
            continue
        intervals = [b["ts"] - a["ts"] for a, b in zip(events, events[1:])]
        jitter = pstdev(intervals) / (mean(intervals) or 1)
        if jitter < 0.15:  # 낮은 지터 = 사람이 아닌 스케줄된 비콘
            suspects.append({"dst_ip": dst_ip, "ja4": ja4, "beacons": len(events), "jitter": round(jitter, 3)})
    return suspects
```

| 신호 | 설명 | 오탐 요인 |
|------|------|----------|
| 비-브라우저 JA4 지문 | curl/Python requests/사설 TLS 스택은 브라우저와 다른 JA4를 남김 | 사내 자동화 스크립트도 동일 지문 발생 가능 |
| 낮은 비콘 지터 | 사람의 브라우징은 불규칙, C2 폴링은 규칙적 | jitter 기능이 있는 최신 C2 프레임워크는 회피 가능 |
| 리졸버 목록 외 목적지 | 공개 DoH 리졸버가 아닌 자체 DoH 엔드포인트 운영 | 기업 자체 DoH 프록시 운영 시 화이트리스트 필요 |

**탐지/방어**: 위 표의 세 신호는 개별로는 오탐이 많아 **AND 조건**(비-브라우저 지문 + 낮은 지터 + 비표준 목적지)으로 결합해야 실전에서 쓸만한 정밀도가 나온다. 성숙한 블루팀은 여기에 더해 TLS 인스펙션 프록시로 SNI/ECH 여부까지 확인해 "정책에 허용되지 않은 DoH 사용" 자체를 별도 알림으로 분리 관리한다.

---

<!-- detect-validate-49 -->
## 공격 탐지와 방어 검증

이 단원은 회피 기법을 *방어자 관점*에서 다룬다. 핵심은 회피가 *가능한가*가 아니라 **성숙한 블루팀이 그 회피를 실제로 잡는가**를 퍼플팀 방식으로 검증하는 것이다.

### 공격 → 완화 계층 → 통제(방어자) → 탐지 신호

| 기법 | 노리는 완화 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 비콘 탐지 회피 | 네트워크 분석 | NDR, JA3, RITA 비콘 분석 | 비콘 규칙성/장기 연결 탐지 |
| 인프라 상관 회피 | 위협 인텔 | 인증서·IP 핑거프린팅 | 인프라 재사용 상관(crt.sh/Censys) |
| 로그/텔레메트리 회피 | EDR/SIEM | 중앙 로깅, 텔레메트리 무결성 | 로그 공백/텔레메트리 변조 알림 |

### 방어 검증 (직접 확인)

```bash
# 퍼플팀 검증: 회피 기법을 통제 환경에서 재현하고 블루팀이 잡는지 확인
# 1) C2 비콘을 RITA 로 돌려 규칙성이 탐지되는지
rita import conn.log dataset && rita show-beacons dataset | head
# 2) 인프라 인증서 핑거프린트가 위협인텔과 상관되는지 대조
# 3) 로그 공백/텔레메트리 변조가 SIEM 무결성 모니터링에 걸리는지
#    통과: 회피를 시도해도 위 신호 중 하나로 탐지됨 → 통제가 실효적
```

> 검증은 반드시 **소유한 시스템·통제된 환경**에서만 수행한다. 완화를 "설정했다"와 "런타임에 실제 막힌다"는 다르다 — PoC 를 재현해 완화가 차단하는지 확인해야 신뢰할 수 있다([[68_Purple_Team]]).

---


<a name="english"></a>

# Red Team Infrastructure Detection Evasion (Defender's Perspective)

This document analyzes C2 traffic disguise, redirector chains, and Living Off the Land techniques used by red teams from a defender's perspective. This material serves as a reference for blue teams to understand red team TTPs and build more effective detection rules.

---

## 1. C2 Traffic Disguise Detection

### 1.1 Domain Fronting Detection

Domain Fronting is a technique that uses a CDN domain in the SNI and the actual C2 in the Host header. Defenders can detect mismatches between SNI and Host headers.

```python
#!/usr/bin/env python3
"""CDN Domain Fronting Detection System"""
import argparse
from scapy.all import TLS, IP, TCP, sniff
import re


class DomainFrontingDetector:
    CDN_PROVIDERS = {
        "cloudfront.net", "azureedge.net", "akamaiedge.net",
        "fastly.net", "cloudflare.com", "cdn.jsdelivr.net",
    }

    def __init__(self) -> None:
        self.alerts: list[dict] = []

    def extract_sni(self, pkt) -> str | None:
        if not (pkt.haslayer(TLS) and pkt.haslayer(IP)):
            return None
        try:
            # Extract TLS ClientHello SNI
            tls = pkt[TLS]
            payload = bytes(tls)
            sni_match = re.search(b"\x00\x00(.{2})([\w\.\-]+)", payload)
            if sni_match:
                return sni_match.group(2).decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    def extract_http_host(self, pkt) -> str | None:
        if not pkt.haslayer(TCP):
            return None
        try:
            payload = bytes(pkt[TCP].payload)
            host_match = re.search(rb"Host: ([^\r\n]+)", payload, re.IGNORECASE)
            if host_match:
                return host_match.group(1).decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    def check_fronting(self, pkt) -> None:
        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        sni = self.extract_sni(pkt)
        host = self.extract_http_host(pkt)

        if sni and host and sni != host:
            sni_is_cdn = any(cdn in sni for cdn in self.CDN_PROVIDERS)
            if sni_is_cdn:
                alert = {
                    "src": src,
                    "sni": sni,
                    "host": host,
                    "alert": "Suspected Domain Fronting",
                }
                self.alerts.append(alert)
                print(f"[!] Domain Fronting: {src} | SNI={sni} | Host={host}")

    def start(self, iface: str = "eth0") -> None:
        print(f"[*] Domain Fronting detection started: {iface}")
        sniff(iface=iface, filter="tcp port 443", prn=self.check_fronting, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Domain Fronting Detection")
    parser.add_argument("-i", "--interface", default="eth0")
    args = parser.parse_args()
    DomainFrontingDetector().start(args.interface)


if __name__ == "__main__":
    main()
```

### 1.2 C2 Profile-Based Detection (Malleable C2)

Detects traffic characteristics that mimic Cobalt Strike Malleable C2 profiles.

```python
#!/usr/bin/env python3
"""Cobalt Strike C2 Traffic Pattern Detection"""
import re
from dataclasses import dataclass


@dataclass
class C2Profile:
    name: str
    uri_patterns: list[str]
    user_agent_patterns: list[str]
    header_indicators: list[str]


KNOWN_CS_PROFILES: list[C2Profile] = [
    C2Profile(
        "jQuery",
        ["/jquery-3.3.1.slim.min.js", "/jquery-3.3.2.min.js"],
        ["Mozilla/5.0.*jQuery"],
        ["__utmc=", "MUID="],
    ),
    C2Profile(
        "Office365",
        ["/owa/auth/", "/autodiscover/"],
        ["Microsoft Office.*"],
        ["X-MS-Exchange", "X-FEServer"],
    ),
    C2Profile(
        "Ocsp",
        ["/ocsp", "/ocsp/"],
        [""],
        ["Content-Type: application/ocsp-request"],
    ),
]


class MalleableC2Detector:
    def __init__(self) -> None:
        self.compiled_profiles = [
            (
                profile.name,
                [re.compile(p, re.IGNORECASE) for p in profile.uri_patterns if p],
                [re.compile(p, re.IGNORECASE) for p in profile.user_agent_patterns if p],
                profile.header_indicators,
            )
            for profile in KNOWN_CS_PROFILES
        ]

    def analyze_request(
        self,
        uri: str,
        user_agent: str,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> dict:
        matches = []

        for name, uri_pats, ua_pats, header_inds in self.compiled_profiles:
            uri_match = any(p.search(uri) for p in uri_pats)
            ua_match = any(p.search(user_agent) for p in ua_pats)
            header_match = any(ind in str(headers) for ind in header_inds)

            if uri_match or (ua_match and header_match):
                matches.append(name)

        # Cobalt Strike beacon characteristic detection
        cs_beacon_indicators = []
        if len(body) == 48 and not any(c > 127 for c in body[:4]):
            cs_beacon_indicators.append("CS beacon size (48-byte check-in)")
        if "Pragma: no-cache" in str(headers) and "Cache-Control: no-cache" in str(headers):
            cs_beacon_indicators.append("CS default cache header pattern")

        return {
            "uri": uri,
            "matched_profiles": matches,
            "beacon_indicators": cs_beacon_indicators,
            "suspicious": bool(matches or cs_beacon_indicators),
        }
```

---

## 2. Living Off the Land Detection

### 2.1 LOLBAS Anomalous Behavior Detection

```python
#!/usr/bin/env python3
"""LOLBAS (Living Off the Land Binaries) Anomalous Execution Detection"""
import argparse
import re
from dataclasses import dataclass


@dataclass
class LOLBASRule:
    binary: str
    suspicious_args: list[str]
    normal_parent_processes: list[str]
    severity: str
    description: str
    mitre: str


LOLBAS_RULES: list[LOLBASRule] = [
    LOLBASRule(
        "certutil.exe",
        ["-decode", "-urlcache", "-f http", "-f ftp"],
        ["cmd.exe", "explorer.exe"],
        "High",
        "Certificate utility abused for file download",
        "T1218.crt",
    ),
    LOLBASRule(
        "mshta.exe",
        ["http://", "https://", "javascript:", "vbscript:"],
        ["explorer.exe"],
        "Critical",
        "Script execution via HTA file execution",
        "T1218.005",
    ),
    LOLBASRule(
        "regsvr32.exe",
        ["/s /n /u /i:http", "scrobj.dll"],
        ["cmd.exe", "explorer.exe"],
        "Critical",
        "Remote script execution via COM object (Squiblydoo)",
        "T1218.010",
    ),
    LOLBASRule(
        "wmic.exe",
        ["process call create", "/node:", "os get"],
        ["cmd.exe"],
        "High",
        "Remote code execution via WMIC",
        "T1047",
    ),
    LOLBASRule(
        "powershell.exe",
        ["-enc", "-EncodedCommand", "-nop -w hidden", "downloadstring", "iex("],
        ["cmd.exe", "explorer.exe", "winword.exe", "excel.exe"],
        "High",
        "Encoded command execution via PowerShell",
        "T1059.001",
    ),
    LOLBASRule(
        "bitsadmin.exe",
        ["/transfer", "/download", "/create"],
        ["cmd.exe"],
        "Medium",
        "File download via BITS",
        "T1197",
    ),
    LOLBASRule(
        "rundll32.exe",
        ["javascript:", "vbscript:", "shell32.dll,ShellExec_RunDLL http"],
        ["cmd.exe", "explorer.exe"],
        "High",
        "Script execution via rundll32",
        "T1218.011",
    ),
]


class LOLBASDetector:
    def __init__(self) -> None:
        self.rules_map = {rule.binary.lower(): rule for rule in LOLBAS_RULES}

    def analyze_process(
        self,
        image_name: str,
        command_line: str,
        parent_process: str,
    ) -> list[dict]:
        findings = []
        binary = image_name.lower().split("\\")[-1]  # Extract filename from path
        rule = self.rules_map.get(binary)

        if not rule:
            return findings

        for suspicious_arg in rule.suspicious_args:
            if suspicious_arg.lower() in command_line.lower():
                # More suspicious if parent process is abnormal
                parent_suspicious = not any(
                    normal.lower() in parent_process.lower()
                    for normal in rule.normal_parent_processes
                )

                findings.append({
                    "binary": binary,
                    "technique": rule.mitre,
                    "severity": "Critical" if parent_suspicious else rule.severity,
                    "description": rule.description,
                    "command": command_line[:200],
                    "parent": parent_process,
                    "anomalous_parent": parent_suspicious,
                })
                break

        return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="LOLBAS Detection Tester")
    parser.add_argument("--image", required=True, help="Process image name")
    parser.add_argument("--cmdline", required=True, help="Command line")
    parser.add_argument("--parent", default="explorer.exe", help="Parent process")
    args = parser.parse_args()

    detector = LOLBASDetector()
    findings = detector.analyze_process(args.image, args.cmdline, args.parent)

    if findings:
        for f in findings:
            print(f"[{f['severity']}] {f['binary']} — {f['technique']}: {f['description']}")
    else:
        print("[*] No anomalous behavior detected")


if __name__ == "__main__":
    main()
```

---

## 3. Redirector Chain Detection

### 3.1 Multi-Hop C2 Traffic Graph Analysis

```python
#!/usr/bin/env python3
"""Network Flow-Based C2 Redirector Chain Detection"""
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    dst_port: int
    bytes_sent: int
    bytes_recv: int
    duration: float
    protocol: str


class C2ChainDetector:
    def __init__(self) -> None:
        self.connection_graph: dict[str, set[str]] = defaultdict(set)
        self.flow_stats: dict[tuple, list[NetworkFlow]] = defaultdict(list)

    def add_flow(self, flow: NetworkFlow) -> None:
        self.connection_graph[flow.src_ip].add(flow.dst_ip)
        key = (flow.src_ip, flow.dst_ip)
        self.flow_stats[key].append(flow)

    def detect_beaconing(self, min_beacons: int = 10, jitter_threshold: float = 0.2) -> list[dict]:
        import statistics

        beaconing = []
        for (src, dst), flows in self.flow_stats.items():
            if len(flows) < min_beacons:
                continue

            # Analyze connection intervals
            flows_sorted = sorted(flows, key=lambda f: f.duration)
            intervals = [
                flows_sorted[i+1].duration - flows_sorted[i].duration
                for i in range(len(flows_sorted) - 1)
            ]

            if not intervals:
                continue

            avg_interval = statistics.mean(intervals)
            if avg_interval <= 0:
                continue

            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            jitter = std_interval / avg_interval

            if jitter < jitter_threshold:  # Regular intervals = suspected beaconing
                beaconing.append({
                    "src": src,
                    "dst": dst,
                    "beacon_count": len(flows),
                    "avg_interval_sec": round(avg_interval, 2),
                    "jitter": round(jitter, 3),
                    "confidence": "HIGH" if jitter < 0.1 else "MEDIUM",
                })

        return beaconing

    def detect_relay_chain(self) -> list[list[str]]:
        # Detect intermediate redirector nodes (nodes with both inbound and outbound connections)
        all_sources = set(self.connection_graph.keys())
        all_destinations = {dst for dsts in self.connection_graph.values() for dst in dsts}

        relay_candidates = all_sources & all_destinations

        chains = []
        for relay in relay_candidates:
            inbound = [src for src, dsts in self.connection_graph.items() if relay in dsts]
            outbound = list(self.connection_graph[relay])

            if inbound and outbound:
                for src in inbound:
                    for dst in outbound:
                        chains.append([src, relay, dst])

        return chains


def parse_netflow(log_path: Path) -> list[NetworkFlow]:
    flows = []
    for line in log_path.read_text().splitlines()[1:]:  # Skip header
        parts = line.split(",")
        if len(parts) < 7:
            continue
        try:
            flows.append(NetworkFlow(
                src_ip=parts[0].strip(),
                dst_ip=parts[1].strip(),
                dst_port=int(parts[2].strip()),
                bytes_sent=int(parts[3].strip()),
                bytes_recv=int(parts[4].strip()),
                duration=float(parts[5].strip()),
                protocol=parts[6].strip(),
            ))
        except (ValueError, IndexError):
            continue
    return flows


def main() -> None:
    parser = argparse.ArgumentParser(description="C2 Redirector Chain Detection")
    parser.add_argument("netflow_log", help="NetFlow CSV log")
    parser.add_argument("--min-beacons", type=int, default=10)
    args = parser.parse_args()

    detector = C2ChainDetector()
    flows = parse_netflow(Path(args.netflow_log))

    for flow in flows:
        detector.add_flow(flow)

    print(f"[*] Detecting beaconing...")
    beacons = detector.detect_beaconing(args.min_beacons)
    for b in beacons:
        print(f"  [{b['confidence']}] {b['src']} → {b['dst']} | Interval: {b['avg_interval_sec']}s | Jitter: {b['jitter']}")

    print(f"\n[*] Detecting relay chains...")
    chains = detector.detect_relay_chain()
    for chain in chains[:10]:
        print(f"  Chain: {' → '.join(chain)}")


if __name__ == "__main__":
    main()
```

---

## 4. Sigma Rules — Red Team TTP Detection

```yaml
# Beaconing interval detection (Zeek/Suricata)
title: Periodic C2 Beaconing Pattern
id: c3d4e5f6-a7b8-9012-cdef-012345678901
description: Repeated external communication at regular intervals — suspected C2 beacon
logsource:
  product: zeek
  service: conn
detection:
  selection:
    resp_bytes|lt: 1000    # Only small amounts of data received
    orig_bytes|lt: 500     # Only small amounts of data sent
    duration|lt: 5         # Short connection duration
  condition: selection
falsepositives:
  - Regular health checks, NTP, DNS updates
level: medium


---
# PowerShell encoded command execution
title: PowerShell Encoded Command with Suspicious Parent
id: d4e5f6a7-b8c9-0123-def0-123456789012
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  suspicious_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\acrobat.exe'
  condition: selection and suspicious_parent
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

---

## 5. Red Team TTP vs Blue Team Detection Matrix

| Red Team Technique | Detection Method | Detection Difficulty | Data Sources |
|-----------|---------|-----------|-----------|
| Domain Fronting | SNI/Host header mismatch | Medium | Proxy logs, TLS inspection |
| DNS C2 | High-entropy subdomains, TXT records | High | DNS query logs |
| HTTPS C2 | Beacon patterns, certificate analysis | High | NetFlow, TLS logs |
| LOLBAS | Process parent-child relationships | Low | Sysmon, EDR |
| Process Injection | API call sequences | Medium | EDR, Sysmon |
| Pass-the-Hash | NTLM authentication source IP mismatch | Low | Windows Event Logs |
| Kerberoasting | Mass service ticket requests | Low | DC Event 4769 |

---

## 6. Detecting DNS-over-HTTPS (DoH) Covert C2 Channels

Red team infrastructure increasingly wraps C2 lookups in **DoH (DNS-over-HTTPS)** instead of plaintext DNS -- because it completely defeats detection based on traditional DNS logs (port 53). DoH traffic appears indistinguishable from ordinary HTTPS (port 443), but in practice, a strong signal is a TLS connection to a destination **not on the list of known DoH resolvers, where SNI is absent (ECH) or the JA3/JA4 fingerprint matches curl/a custom TLS client library rather than a browser**. From a blue-team standpoint, the goal isn't "block DoH outright" but "identify DoH usage outside policy" -- since most enterprises legitimately use browser built-in DoH, an outright block causes a false-positive explosion.

```python
#!/usr/bin/env python3
"""From NetFlow/proxy logs, flag HTTPS sessions to destinations that are not known DoH
resolvers, where a non-browser JA3/JA4 fingerprint overlaps with regular beacon-like
intervals, as suspected DoH-based C2."""
from collections import defaultdict
from statistics import mean, pstdev

KNOWN_DOH_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
}
BROWSER_JA4_PREFIXES = {"t13d1516h2", "t13d1517h2"}  # example major-browser JA4 family


def flag_doh_c2(flow_log: list[dict]) -> list[dict]:
    """flow_log entries: {dst_ip, port, ja4, ts, bytes_out}"""
    sessions = defaultdict(list)
    for f in flow_log:
        if f["port"] == 443 and f["dst_ip"] not in KNOWN_DOH_RESOLVERS:
            sessions[(f["dst_ip"], f["ja4"])].append(f)

    suspects = []
    for (dst_ip, ja4), events in sessions.items():
        if len(events) < 5 or ja4 in BROWSER_JA4_PREFIXES:
            continue
        intervals = [b["ts"] - a["ts"] for a, b in zip(events, events[1:])]
        jitter = pstdev(intervals) / (mean(intervals) or 1)
        if jitter < 0.15:  # low jitter = scheduled beacon, not a human
            suspects.append({"dst_ip": dst_ip, "ja4": ja4, "beacons": len(events), "jitter": round(jitter, 3)})
    return suspects
```

| Signal | Description | False-Positive Factor |
|--------|-------------|------------------------|
| Non-browser JA4 fingerprint | curl/Python requests/custom TLS stacks leave a JA4 different from browsers | In-house automation scripts can produce the same fingerprint |
| Low beacon jitter | Human browsing is irregular; C2 polling is regular | Modern C2 frameworks with a jitter feature can evade this |
| Destination outside resolver list | Running a private DoH endpoint instead of a public DoH resolver | Enterprises running their own DoH proxy need a whitelist |

**Detection/Defense**: each of the three signals above produces too many false positives on its own -- combining them with an **AND condition** (non-browser fingerprint + low jitter + non-standard destination) is what yields workable precision in practice. A mature blue team additionally checks SNI/ECH presence via a TLS inspection proxy, managing "DoH usage not permitted by policy" as its own separate alert.

---

## Attack Detection and Defense Validation

This unit covers evasion from the *defender's* perspective. The point is not *whether* evasion is possible, but verifying purple-team style **whether a mature blue team actually catches it**.

### Attack -> mitigation layer -> control (defender) -> detection signal

| Technique | Targeted mitigation | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Beacon detection evasion | Network analysis | NDR, JA3, RITA beacon analysis | Beacon regularity/long-lived connection detection |
| Infra correlation evasion | Threat intel | Cert/IP fingerprinting | Infra-reuse correlation (crt.sh/Censys) |
| Log/telemetry evasion | EDR/SIEM | Central logging, telemetry integrity | Log-gap/telemetry-tamper alerts |

### Defense validation (verify yourself)

```bash
# Purple-team validation: replay the evasion in a controlled env and confirm the blue team catches it
# 1) Run the C2 beacon through RITA and confirm regularity is detected
rita import conn.log dataset && rita show-beacons dataset | head
# 2) Cross-check infra cert fingerprints against threat intel for correlation
# 3) Confirm log-gap/telemetry-tamper trips SIEM integrity monitoring
#    Pass: even with evasion, one of the above signals fires -> the control is effective
```

> Run validation only on **systems you own, in a controlled environment**. "Configured" is not the same as "blocked at runtime" -- reproduce the PoC and confirm the mitigation stops it (see [[68_Purple_Team]]).
