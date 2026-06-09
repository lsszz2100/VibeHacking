> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>
# SOC/블루팀 CTF 실습 랩

## 개요

이 랩은 SIEM 분석, IOC 추출, 래터럴 무브먼트 탐지 등 실제 SOC 환경에서 마주치는 시나리오를 CTF 형식으로 재현합니다. Splunk SPL 쿼리 작성부터 알림 룰 설계까지 블루팀 핵심 역량을 훈련합니다.

---

## Docker 환경 설정

```yaml
# docker-compose.yml
version: "3.8"
services:
  splunk:
    image: splunk/splunk:9.1
    container_name: soc_splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=CTFlab2024!
      - SPLUNK_HEC_TOKEN=ctf-hec-token-001
    ports:
      - "8000:8000"   # Splunk Web UI
      - "8088:8088"   # HEC
      - "9997:9997"   # Indexer
    volumes:
      - splunk_data:/opt/splunk/var
      - ./logs:/tmp/ctf_logs:ro

  log_generator:
    image: python:3.11-slim
    container_name: soc_log_gen
    volumes:
      - ./logs:/output
      - ./scripts:/scripts
    command: python /scripts/generate_logs.py
    depends_on:
      - splunk

volumes:
  splunk_data:
```

```bash
# 환경 시작
docker compose up -d

# Splunk 준비 대기 (약 60초)
until curl -s -u admin:CTFlab2024! http://localhost:8000/en-US/account/login > /dev/null; do
    echo "Splunk 시작 중..."; sleep 5
done
echo "Splunk 준비 완료"

# 샘플 로그 업로드
curl -k https://localhost:8088/services/collector/event \
  -H "Authorization: Splunk ctf-hec-token-001" \
  -d @logs/auth_events.json
```

---

## 실습 1: Splunk SPL로 브루트포스 공격 탐지 쿼리 작성

### 목표

주어진 인증 로그에서 SPL(Search Processing Language) 쿼리를 작성하여 SSH/웹 로그인 브루트포스 공격을 탐지하고, 공격 소스 IP와 타깃 계정을 식별하는 플래그를 획득하세요.

**플래그 형식**: `CTF{<공격자_IP>_<가장많이시도된_계정>_<실패횟수>}`

### 시나리오 배경

야간에 여러 계정에 대한 반복 로그인 실패가 감지되었습니다. 로그는 Splunk 인덱스 `index=auth_logs`에 적재되어 있으며, 소스타입은 `linux_secure`입니다.

### 샘플 로그 데이터 생성 스크립트

```python
#!/usr/bin/env python3
"""브루트포스 시뮬레이션 로그 생성기"""

import json
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path


ATTACKER_IPS = ["192.168.100.55", "10.0.0.99", "172.16.50.200"]
VICTIM_ACCOUNTS = ["admin", "root", "ubuntu", "jenkins", "deploy"]
LEGIT_ACCOUNTS = ["alice", "bob", "charlie"]
LEGIT_IPS = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]


def generate_failed_login(
    timestamp: datetime,
    src_ip: str,
    username: str,
    service: str = "ssh",
) -> dict:
    return {
        "time": timestamp.isoformat(),
        "event": f"Failed password for {username} from {src_ip} port {random.randint(1024, 65535)} {service}",
        "sourcetype": "linux_secure",
        "index": "auth_logs",
        "host": "prod-server-01",
        "fields": {
            "action": "failure",
            "src_ip": src_ip,
            "user": username,
            "service": service,
            "app": "sshd",
        },
    }


def generate_success_login(
    timestamp: datetime,
    src_ip: str,
    username: str,
) -> dict:
    return {
        "time": timestamp.isoformat(),
        "event": f"Accepted password for {username} from {src_ip} port {random.randint(1024, 65535)} ssh2",
        "sourcetype": "linux_secure",
        "index": "auth_logs",
        "host": "prod-server-01",
        "fields": {
            "action": "success",
            "src_ip": src_ip,
            "user": username,
            "service": "ssh",
            "app": "sshd",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="브루트포스 로그 생성기")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/output/auth_events.json"),
        help="출력 파일 경로",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=500,
        help="생성할 이벤트 수 (기본값: 500)",
    )
    args = parser.parse_args()

    events: list[dict] = []
    base_time = datetime.now() - timedelta(hours=6)

    # 브루트포스 공격 시뮬레이션 (주요 공격자: 192.168.100.55)
    attacker_ip = "192.168.100.55"
    target_user = "admin"
    for i in range(320):
        ts = base_time + timedelta(seconds=i * 2)
        events.append(generate_failed_login(ts, attacker_ip, target_user))

    # 보조 공격자
    for i in range(80):
        ts = base_time + timedelta(minutes=30, seconds=i * 5)
        user = random.choice(VICTIM_ACCOUNTS[1:])
        events.append(generate_failed_login(ts, "10.0.0.99", user))

    # 정상 트래픽
    for i in range(100):
        ts = base_time + timedelta(minutes=random.randint(0, 360))
        ip = random.choice(LEGIT_IPS)
        user = random.choice(LEGIT_ACCOUNTS)
        if random.random() > 0.1:
            events.append(generate_success_login(ts, ip, user))
        else:
            events.append(generate_failed_login(ts, ip, user))

    # 시간순 정렬
    events.sort(key=lambda e: e["time"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"[+] {len(events)}개 이벤트 생성 완료: {args.output}")


if __name__ == "__main__":
    main()
```

### 힌트

```
힌트 1: SPL stats 명령어로 src_ip와 user 기준으로 failure 이벤트를 집계하세요.
힌트 2: where 절로 실패 횟수가 100회 이상인 소스만 필터링하세요.
힌트 3: sort -count 로 내림차순 정렬하면 최대 공격자가 상단에 노출됩니다.
```

### 풀이

```spl
/* 브루트포스 탐지 SPL 쿼리 */
index=auth_logs sourcetype=linux_secure action=failure
| stats count as fail_count by src_ip, user
| where fail_count >= 50
| sort -fail_count
| eval flag_candidate=src_ip + "_" + user + "_" + tostring(fail_count)
| table src_ip, user, fail_count, flag_candidate
```

**예상 결과**:
```
src_ip           user    fail_count   flag_candidate
192.168.100.55   admin   320          192.168.100.55_admin_320
10.0.0.99        root    80           10.0.0.99_root_80
```

**플래그**: `CTF{192.168.100.55_admin_320}`

```python
#!/usr/bin/env python3
"""Splunk API로 플래그 자동 검증"""

import argparse
import sys
import urllib.request
import urllib.parse
import json
import ssl
import time


def query_splunk(
    host: str,
    username: str,
    password: str,
    spl_query: str,
) -> list[dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 세션 토큰 획득
    login_url = f"https://{host}:8089/services/auth/login"
    login_data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(login_url, data=login_data)
    with urllib.request.urlopen(req, context=ctx) as resp:
        import xml.etree.ElementTree as ET
        tree = ET.parse(resp)
        session_key = tree.find(".//sessionKey").text

    headers = {"Authorization": f"Splunk {session_key}"}

    # 검색 작업 생성
    search_url = f"https://{host}:8089/services/search/jobs"
    search_data = urllib.parse.urlencode({"search": f"search {spl_query}"}).encode()
    req = urllib.request.Request(search_url, data=search_data, headers=headers)
    with urllib.request.urlopen(req, context=ctx) as resp:
        tree = ET.parse(resp)
        sid = tree.find(".//sid").text

    # 완료 대기
    status_url = f"https://{host}:8089/services/search/jobs/{sid}"
    while True:
        req = urllib.request.Request(status_url, headers=headers)
        with urllib.request.urlopen(req, context=ctx) as resp:
            content = resp.read().decode()
            if "isDone\" >1<" in content:
                break
        time.sleep(1)

    # 결과 조회
    results_url = f"https://{host}:8089/services/search/jobs/{sid}/results?output_mode=json"
    req = urllib.request.Request(results_url, headers=headers)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())["results"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Splunk 플래그 검증기")
    parser.add_argument("--host", default="localhost", help="Splunk 호스트")
    parser.add_argument("--user", default="admin", help="사용자명")
    parser.add_argument("--password", default="CTFlab2024!", help="비밀번호")
    args = parser.parse_args()

    spl = (
        "index=auth_logs sourcetype=linux_secure action=failure "
        "| stats count as fail_count by src_ip, user "
        "| where fail_count >= 100 "
        "| sort -fail_count "
        "| head 1"
    )

    results = query_splunk(args.host, args.user, args.password, spl)
    if not results:
        print("[-] 결과 없음. 로그가 올바르게 업로드되었는지 확인하세요.")
        sys.exit(1)

    top = results[0]
    flag = f"CTF{{{top['src_ip']}_{top['user']}_{top['fail_count']}}}"
    print(f"[+] 플래그: {flag}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: 악성 로그인 이벤트에서 IOC 추출 및 알림 룰 작성

### 목표

주어진 혼합 인증 로그(정상 + 악성)에서 IOC(Indicators of Compromise)를 추출하고, Splunk 알림 룰을 작성하세요. 악성 IP의 ASN 정보와 User-Agent 패턴으로 플래그를 구성합니다.

**플래그 형식**: `CTF{<악성_UA_해시>_<IOC_COUNT>}`

### IOC 추출 스크립트

```python
#!/usr/bin/env python3
"""로그에서 IOC 자동 추출 및 분류"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path


# 알려진 악성 User-Agent 패턴
MALICIOUS_UA_PATTERNS: list[str] = [
    r"python-requests/[0-9.]+",
    r"curl/[0-9.]+",
    r"Hydra",
    r"Medusa",
    r"nmap",
    r"sqlmap",
    r"nikto",
    r"masscan",
]

# 사설 IP 대역 (정상 내부 트래픽)
INTERNAL_CIDRS = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]


def is_suspicious_ua(ua: str) -> bool:
    for pattern in MALICIOUS_UA_PATTERNS:
        if re.search(pattern, ua, re.IGNORECASE):
            return True
    return False


def extract_iocs(log_file: Path) -> dict:
    iocs: dict = {
        "malicious_ips": set(),
        "malicious_uas": set(),
        "targeted_accounts": Counter(),
        "attack_timestamps": [],
    }

    with log_file.open(encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            fields = event.get("fields", {})
            action = fields.get("action", "")
            src_ip = fields.get("src_ip", "")
            user_agent = fields.get("user_agent", "")
            username = fields.get("user", "")

            if action == "failure":
                iocs["targeted_accounts"][username] += 1

            if is_suspicious_ua(user_agent):
                iocs["malicious_uas"].add(user_agent)
                iocs["malicious_ips"].add(src_ip)
                iocs["attack_timestamps"].append(event.get("time", ""))

    return iocs


def generate_splunk_alert(iocs: dict, output_path: Path) -> None:
    malicious_ips = list(iocs["malicious_ips"])
    ip_filter = " OR ".join(f'src_ip="{ip}"' for ip in malicious_ips)

    alert_spl = f"""
/* IOC 기반 실시간 알림 룰 */
index=auth_logs sourcetype=linux_secure
| where ({ip_filter})
| eval severity=case(
    action="failure" AND count > 10, "HIGH",
    action="failure", "MEDIUM",
    true(), "LOW"
)
| stats count as event_count, latest(_time) as last_seen by src_ip, user, severity
| where event_count > 5
| eval alert_message="IOC 탐지: " + src_ip + " → " + user + " (" + tostring(event_count) + "회)"
| table last_seen, src_ip, user, event_count, severity, alert_message
| sort -event_count
""".strip()

    output_path.write_text(alert_spl, encoding="utf-8")
    print(f"[+] 알림 룰 저장: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC 추출 및 Splunk 알림 룰 생성")
    parser.add_argument(
        "--log",
        type=Path,
        required=True,
        help="분석할 로그 파일 경로",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/alert_rule.spl"),
        help="SPL 알림 룰 출력 경로",
    )
    parser.add_argument(
        "--flag",
        action="store_true",
        help="플래그 계산 모드",
    )
    args = parser.parse_args()

    if not args.log.exists():
        print(f"[-] 로그 파일 없음: {args.log}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] IOC 추출 중: {args.log}")
    iocs = extract_iocs(args.log)

    print(f"[+] 악성 IP: {iocs['malicious_ips']}")
    print(f"[+] 악성 User-Agent: {iocs['malicious_uas']}")
    print(f"[+] 가장 많이 타깃된 계정: {iocs['targeted_accounts'].most_common(3)}")
    print(f"[+] IOC 총 개수: {len(iocs['malicious_ips']) + len(iocs['malicious_uas'])}")

    generate_splunk_alert(iocs, args.output)

    if args.flag:
        all_uas = sorted(iocs["malicious_uas"])
        ua_concat = "|".join(all_uas)
        ua_hash = hashlib.md5(ua_concat.encode()).hexdigest()[:8]
        ioc_count = len(iocs["malicious_ips"]) + len(iocs["malicious_uas"])
        print(f"\n[FLAG] CTF{{{ua_hash}_{ioc_count}}}")


if __name__ == "__main__":
    main()
```

### 힌트

```
힌트 1: User-Agent 필드에서 자동화 도구 패턴(python-requests, curl, Hydra)을 찾으세요.
힌트 2: 동일 소스에서 5분 내 20회 이상 실패 시 IOC로 분류합니다.
힌트 3: md5(정렬된_UA_목록)[:8] + "_" + 전체_IOC_수 = 플래그
```

### 풀이 검증

```spl
/* Splunk에서 User-Agent 기반 IOC 탐지 */
index=auth_logs
| eval is_malicious=if(match(user_agent, "python-requests|curl|Hydra|sqlmap"), 1, 0)
| where is_malicious=1
| stats dc(src_ip) as unique_ips, dc(user_agent) as unique_uas, count by user_agent
| eval ioc_type="malicious_user_agent"
| table user_agent, unique_ips, count, ioc_type
```

---

## 실습 3: SIEM에서 래터럴 무브먼트 패턴 탐지

### 목표

내부 네트워크 로그에서 래터럴 무브먼트(수평 이동) 패턴을 탐지하는 SPL 쿼리를 작성하고, 공격자가 침투한 경로(호스트 체인)를 재구성하여 플래그를 획득하세요.

**플래그 형식**: `CTF{<시작호스트>_<중간호스트>_<최종호스트>}`

### 래터럴 무브먼트 탐지 도구

```python
#!/usr/bin/env python3
"""래터럴 무브먼트 탐지 및 경로 재구성"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def build_movement_graph(log_file: Path) -> dict[str, list[str]]:
    """호스트 간 이동 그래프 구축"""
    graph: dict[str, list[str]] = defaultdict(list)

    with log_file.open(encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            fields = event.get("fields", {})
            src_host = fields.get("src_host", "")
            dst_host = fields.get("dst_host", "")
            action = fields.get("action", "")

            # 성공한 SSH 접속만 추적
            if action == "success" and src_host and dst_host and src_host != dst_host:
                if dst_host not in graph[src_host]:
                    graph[src_host].append(dst_host)

    return dict(graph)


def find_lateral_chains(
    graph: dict[str, list[str]],
    min_hops: int = 2,
) -> list[list[str]]:
    """최소 hop 수 이상의 이동 체인 탐지"""
    chains: list[list[str]] = []

    def dfs(node: str, path: list[str], visited: set[str]) -> None:
        if len(path) > min_hops:
            chains.append(list(path))
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                dfs(neighbor, path, visited)
                path.pop()
                visited.discard(neighbor)

    for start_node in graph:
        dfs(start_node, [start_node], {start_node})

    return sorted(chains, key=len, reverse=True)


def score_chain(chain: list[str], event_counts: dict[str, int]) -> float:
    """체인의 위험도 점수 계산"""
    total_events = sum(event_counts.get(h, 0) for h in chain)
    return len(chain) * 10 + total_events * 0.1


def main() -> None:
    parser = argparse.ArgumentParser(description="래터럴 무브먼트 탐지기")
    parser.add_argument(
        "--log",
        type=Path,
        required=True,
        help="네트워크 로그 파일",
    )
    parser.add_argument(
        "--min-hops",
        type=int,
        default=2,
        help="최소 이동 횟수 (기본값: 2)",
    )
    parser.add_argument(
        "--flag",
        action="store_true",
        help="플래그 출력 모드",
    )
    args = parser.parse_args()

    if not args.log.exists():
        print(f"[-] 파일 없음: {args.log}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 이동 그래프 구축 중...")
    graph = build_movement_graph(args.log)
    print(f"[+] 관련 호스트: {len(graph)}개")

    chains = find_lateral_chains(graph, args.min_hops)
    if not chains:
        print("[-] 래터럴 무브먼트 패턴 미탐지")
        sys.exit(0)

    print(f"\n[+] 탐지된 이동 체인 (상위 5개):")
    for i, chain in enumerate(chains[:5], 1):
        print(f"  {i}. {' → '.join(chain)} (hop: {len(chain)-1})")

    if args.flag:
        longest = chains[0]
        flag = f"CTF{{{longest[0]}_{longest[len(longest)//2]}_{longest[-1]}}}"
        print(f"\n[FLAG] {flag}")


if __name__ == "__main__":
    main()
```

### 탐지 SPL 쿼리

```spl
/* 래터럴 무브먼트 탐지: 동일 사용자의 다중 호스트 접속 */
index=auth_logs sourcetype=linux_secure action=success
| bin _time span=1h
| stats dc(host) as unique_hosts, values(host) as host_list by _time, user
| where unique_hosts >= 3
| eval lateral_movement_score = unique_hosts * 10
| sort -lateral_movement_score
| eval movement_path = mvjoin(host_list, " → ")
| table _time, user, unique_hosts, lateral_movement_score, movement_path
```

```spl
/* WMI/RPC 기반 래터럴 무브먼트 (Windows 이벤트 로그) */
index=wineventlog EventCode IN (4624, 4648)
| where Logon_Type IN (3, 10)
| stats count as logon_count, dc(ComputerName) as hosts_accessed,
        values(ComputerName) as host_list by Account_Name, src_ip
| where hosts_accessed >= 3
| eval flag_chain = mvindex(host_list, 0) + "_" + mvindex(host_list, 1) + "_" + mvindex(host_list, -1)
| table Account_Name, src_ip, hosts_accessed, logon_count, flag_chain
```

### 힌트

```
힌트 1: 동일 사용자 계정이 1시간 내 3개 이상 호스트에 SSH 접속하면 의심스럽습니다.
힌트 2: 이동 경로는 시간순으로 정렬된 host 목록에서 첫 번째, 중간, 마지막 호스트입니다.
힌트 3: SPL의 mvindex() 함수로 멀티밸류 필드에서 특정 인덱스 값을 추출하세요.
```

---

## 정리 및 핵심 개념

| 기법 | SPL 핵심 명령어 | 탐지 임계값 |
|------|----------------|------------|
| 브루트포스 | `stats count by src_ip, user` | 5분 내 50회 이상 실패 |
| 크리덴셜 스터핑 | `dc(user) by src_ip` | 단일 IP에서 10개 이상 계정 시도 |
| 래터럴 무브먼트 | `dc(host) by user` | 1시간 내 3개 이상 호스트 |
| IOC 매칭 | `lookup ioc_list src_ip` | 알려진 악성 IP/도메인 일치 |

**참고 자료**:
- [Splunk SPL 공식 문서](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

---

<a name="english"></a>
# SOC/Blue Team CTF Lab

## Overview

This lab recreates real-world SOC scenarios — SIEM analysis, IOC extraction, and lateral movement detection — in CTF format. You will train core blue team skills from writing Splunk SPL queries to designing alert rules.

---

## Docker Environment Setup

```yaml
# docker-compose.yml
version: "3.8"
services:
  splunk:
    image: splunk/splunk:9.1
    container_name: soc_splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=CTFlab2024!
      - SPLUNK_HEC_TOKEN=ctf-hec-token-001
    ports:
      - "8000:8000"   # Splunk Web UI
      - "8088:8088"   # HEC
      - "9997:9997"   # Indexer
    volumes:
      - splunk_data:/opt/splunk/var
      - ./logs:/tmp/ctf_logs:ro

  log_generator:
    image: python:3.11-slim
    container_name: soc_log_gen
    volumes:
      - ./logs:/output
      - ./scripts:/scripts
    command: python /scripts/generate_logs.py
    depends_on:
      - splunk

volumes:
  splunk_data:
```

```bash
# Start environment
docker compose up -d

# Wait for Splunk to be ready (~60 seconds)
until curl -s -u admin:CTFlab2024! http://localhost:8000/en-US/account/login > /dev/null; do
    echo "Waiting for Splunk..."; sleep 5
done
echo "Splunk ready"

# Upload sample logs
curl -k https://localhost:8088/services/collector/event \
  -H "Authorization: Splunk ctf-hec-token-001" \
  -d @logs/auth_events.json
```

---

## Lab 1: Write Brute Force Detection SPL Query in Splunk

### Objective

Write an SPL (Search Processing Language) query against the provided authentication logs to detect SSH/web login brute force attacks. Identify the attacking source IP and target account to obtain the flag.

**Flag format**: `CTF{<attacker_IP>_<most_targeted_account>_<failure_count>}`

### Scenario Background

Repeated login failures were detected against multiple accounts overnight. Logs are loaded into Splunk index `index=auth_logs` with sourcetype `linux_secure`.

### Hints

```
Hint 1: Use SPL stats command to aggregate failure events by src_ip and user.
Hint 2: Use a where clause to filter sources with 100+ failures.
Hint 3: sort -count descending will surface the top attacker.
```

### Solution

```spl
/* Brute force detection SPL query */
index=auth_logs sourcetype=linux_secure action=failure
| stats count as fail_count by src_ip, user
| where fail_count >= 50
| sort -fail_count
| eval flag_candidate=src_ip + "_" + user + "_" + tostring(fail_count)
| table src_ip, user, fail_count, flag_candidate
```

**Flag**: `CTF{192.168.100.55_admin_320}`

---

## Lab 2: Extract IOCs from Malicious Login Events and Write Alert Rules

### Objective

Extract IOCs (Indicators of Compromise) from mixed authentication logs (normal + malicious) and write a Splunk alert rule. The flag is composed from malicious User-Agent hash and IOC count.

**Flag format**: `CTF{<malicious_UA_hash>_<IOC_COUNT>}`

### Hints

```
Hint 1: Look for automation tool patterns in User-Agent fields (python-requests, curl, Hydra).
Hint 2: Classify as IOC if 20+ failures from the same source within 5 minutes.
Hint 3: md5(sorted_UA_list)[:8] + "_" + total_IOC_count = flag
```

### Solution SPL

```spl
/* User-Agent based IOC detection in Splunk */
index=auth_logs
| eval is_malicious=if(match(user_agent, "python-requests|curl|Hydra|sqlmap"), 1, 0)
| where is_malicious=1
| stats dc(src_ip) as unique_ips, dc(user_agent) as unique_uas, count by user_agent
| eval ioc_type="malicious_user_agent"
| table user_agent, unique_ips, count, ioc_type
```

---

## Lab 3: Detect Lateral Movement Patterns in SIEM

### Objective

Write SPL queries to detect lateral movement patterns in internal network logs. Reconstruct the attacker's traversal path (host chain) to obtain the flag.

**Flag format**: `CTF{<start_host>_<middle_host>_<final_host>}`

### Hints

```
Hint 1: The same user account accessing 3+ hosts within 1 hour is suspicious.
Hint 2: The movement path uses the first, middle, and last hosts in time-sorted order.
Hint 3: Use SPL's mvindex() function to extract specific index values from multi-value fields.
```

### Solution SPL

```spl
/* Lateral movement detection: same user accessing multiple hosts */
index=auth_logs sourcetype=linux_secure action=success
| bin _time span=1h
| stats dc(host) as unique_hosts, values(host) as host_list by _time, user
| where unique_hosts >= 3
| eval lateral_movement_score = unique_hosts * 10
| sort -lateral_movement_score
| eval movement_path = mvjoin(host_list, " → ")
| table _time, user, unique_hosts, lateral_movement_score, movement_path
```

---

## Summary

| Technique | Key SPL Command | Detection Threshold |
|-----------|----------------|---------------------|
| Brute Force | `stats count by src_ip, user` | 50+ failures in 5 min |
| Credential Stuffing | `dc(user) by src_ip` | 10+ accounts from one IP |
| Lateral Movement | `dc(host) by user` | 3+ hosts in 1 hour |
| IOC Matching | `lookup ioc_list src_ip` | Known malicious IP/domain match |

**References**:
- [Splunk SPL Official Docs](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
