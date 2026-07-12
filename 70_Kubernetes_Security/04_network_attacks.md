> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 쿠버네티스 네트워크 공격

## K8s 네트워크 모델 — 열린 사무실 비유

기본 쿠버네티스 네트워크 모델은 **열린 사무실(Open Office)**과 같습니다. 모든 파드는 서로 자유롭게 통신할 수 있습니다. 칸막이(Network Policy)를 치지 않으면, A팀 직원(파드)이 B팀 자리(파드)에 가서 파일을 마음대로 볼 수 있습니다.

핵심 원칙:
- 모든 파드는 NAT 없이 서로 직접 통신 가능 (기본값)
- Network Policy를 명시적으로 설정하지 않으면 격리 없음
- 공격자가 파드 하나를 장악하면 클러스터 내 다른 모든 파드에 접근 가능

---

## 1. 쿠버네티스 네트워크 구조

```
클러스터 네트워크 (예: 10.244.0.0/16)
│
├── 노드 1 (192.168.64.100)
│   ├── Pod A (10.244.1.2)  ←─ DB 파드
│   └── Pod B (10.244.1.3)  ←─ 백엔드 파드
│
└── 노드 2 (192.168.64.101)
    ├── Pod C (10.244.2.2)  ←─ 프론트엔드 파드 (공격자 장악)
    └── Pod D (10.244.2.3)  ←─ 어드민 파드

Network Policy 없으면:
Pod C → Pod A (DB) 직접 접속 가능!  ← 심각한 위험
Pod C → Pod D (Admin) 직접 접속 가능!
```

---

## 2. 공격 기법 1: 파드 간 횡적 이동 (Lateral Movement)

### 개념
공격자가 프론트엔드 파드를 장악했을 때, 내부 네트워크를 스캔하여 다른 서비스(DB, 어드민 패널 등)를 찾아 이동합니다.

### 실습: 파드 내부 네트워크 스캔

```bash
# 파드 내부에서 내부 네트워크 정보 수집
# 1. 클러스터 DNS로 서비스 목록 확인
cat /etc/resolv.conf               # DNS 서버 확인
nslookup kubernetes.default.svc    # K8s API 서버 DNS

# 2. 환경 변수에서 서비스 IP 찾기 (K8s가 자동 주입)
env | grep -E "_SERVICE_HOST|_SERVICE_PORT"
# 출력 예시:
# MYSQL_SERVICE_HOST=10.100.50.20
# MYSQL_SERVICE_PORT=3306

# 3. 기본 네트워크 도구로 스캔 (파드 내 설치 필요)
apt-get install -y nmap -q
nmap -sV 10.244.0.0/16 -p 80,443,3306,5432,6379,27017 --open -T4
```

---

## 3. 공격 기법 2: 트래픽 스니핑 (Pod-to-Pod Sniffing)

### 개념
같은 노드에 있는 파드들은 가상 이더넷(veth) 인터페이스로 연결됩니다. 특권 컨테이너에서 호스트 네트워크 인터페이스를 스니핑하면 다른 파드의 암호화되지 않은 트래픽을 도청할 수 있습니다.

### 시나리오 1: 같은 네임스페이스 내 스니핑

```bash
# privileged 파드 + hostNetwork 조합에서 가능
# 호스트 네트워크 인터페이스 목록 확인
ip link show

# tcpdump로 파드 간 트래픽 캡처
# 클러스터 네트워크 대역 (보통 10.244.x.x 또는 192.168.x.x)
tcpdump -i any -nn 'net 10.244.0.0/16' -w /tmp/pod_traffic.pcap

# HTTP 트래픽만 필터링
tcpdump -i any -nn -A 'tcp port 80 and net 10.244.0.0/16'

# DB 트래픽 캡처 (MySQL: 3306, PostgreSQL: 5432)
tcpdump -i any -nn 'tcp port 3306' -w /tmp/db_traffic.pcap
```

### 시나리오 2: ARP 스푸핑으로 중간자 공격

```bash
# 파드 내부에서 (같은 L2 네트워크)
apt-get install -y arpspoof dsniff -q

# 피해자 파드 IP와 게이트웨이 사이에서 중간자 역할
# 주의: 실습 환경에서만 수행
arpspoof -i eth0 -t 10.244.1.2 10.244.0.1   # 피해자 → 게이트웨이 방향 스푸핑
arpspoof -i eth0 -t 10.244.0.1 10.244.1.2   # 게이트웨이 → 피해자 방향 스푸핑
```

---

## 4. 공격 기법 3: DNS 스푸핑

### 개념
쿠버네티스의 내부 DNS는 CoreDNS가 담당합니다. 공격자가 파드 내에서 DNS 응답을 위조하면, 다른 파드를 가짜 서비스로 유도할 수 있습니다.

```bash
# CoreDNS 설정 확인
kubectl get configmap coredns -n kube-system -o yaml

# 파드 내 DNS 설정 확인
cat /etc/resolv.conf
# nameserver 10.96.0.10  ← CoreDNS 서비스 IP

# DNS 쿼리 모니터링 (privileged 파드에서)
tcpdump -i any -nn 'udp port 53'

# 내부 서비스 DNS 조회
nslookup myapp-service.default.svc.cluster.local
```

### DNS 스푸핑 방어 실습 (CoreDNS 정책 확인)

```bash
# CoreDNS 파드 상태 확인
kubectl get pods -n kube-system -l k8s-app=kube-dns

# DNS 쿼리 로깅 활성화
kubectl edit configmap coredns -n kube-system
# Corefile에 'log' 추가:
# .:53 {
#     log
#     errors
#     ...
# }
```

---

## 5. 실습: Network Policy 없는 환경에서 파드 간 통신 도청

### 5.1 취약한 환경 구성 (Network Policy 없음)

```bash
# 시크릿이 있는 DB 시뮬레이션 파드
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: db-simulator
  namespace: default
  labels:
    app: db
spec:
  containers:
  - name: db
    image: python:3.11-slim
    command: ["python3", "-m", "http.server", "8080"]
    ports:
    - containerPort: 8080
EOF

# 프론트엔드 시뮬레이션 파드 (공격자가 장악한 상황 가정)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  containers:
  - name: attacker
    image: ubuntu:22.04
    command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=Ready pod/db-simulator pod/attacker-pod --timeout=90s

# DB 파드 IP 확인
DB_IP=$(kubectl get pod db-simulator -o jsonpath='{.status.podIP}')
echo "DB Pod IP: $DB_IP"
```

### 5.2 네트워크 스캔 및 접근 확인

```bash
# 공격자 파드에서 DB에 접근 시도 (Network Policy 없으면 성공)
kubectl exec attacker-pod -- bash -c "
apt-get install -y curl netcat-openbsd -q 2>/dev/null
echo '[*] DB 파드에 직접 접근 시도...'
curl -s http://$DB_IP:8080 && echo '[!] 접근 성공! Network Policy가 없습니다.'
"
```

### 5.3 Python 네트워크 스캐너

```python
#!/usr/bin/env python3
"""
K8s 내부 네트워크 스캐너 — 파드 내부에서 실행
사용법: python3 k8s_net_scan.py --subnet 10.244.0.0/16 --ports 80,443,3306,5432,6379
"""
import argparse
import ipaddress
import socket
import concurrent.futures
from dataclasses import dataclass


@dataclass
class OpenPort:
    ip: str
    port: int
    service: str


COMMON_K8S_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2181: "Zookeeper",
    5601: "Kibana",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9090: "Prometheus",
    3000: "Grafana",
}


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_host(ip: str, ports: list[int]) -> list[OpenPort]:
    results = []
    for port in ports:
        if check_port(ip, port):
            service = COMMON_K8S_SERVICES.get(port, "unknown")
            results.append(OpenPort(ip=ip, port=port, service=service))
    return results


def parse_ports(ports_str: str) -> list[int]:
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="K8s 내부 네트워크 스캐너 (파드 내부 실행용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="예시: python3 k8s_net_scan.py --subnet 10.244.0.0/16 --ports 80,3306,6379"
    )
    parser.add_argument(
        "--subnet", required=True,
        help="스캔할 서브넷 (예: 10.244.0.0/16)"
    )
    parser.add_argument(
        "--ports", default="80,443,3306,5432,6379,8080,27017",
        help="스캔할 포트 (쉼표 구분, 기본값: 주요 서비스 포트)"
    )
    parser.add_argument(
        "--workers", type=int, default=50,
        help="동시 스캔 스레드 수 (기본값: 50)"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="연결 타임아웃 초 (기본값: 0.5)"
    )
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError as e:
        print(f"[오류] 잘못된 서브넷: {e}")
        return

    ports = parse_ports(args.ports)
    hosts = list(network.hosts())

    print(f"\n[*] 내부 네트워크 스캔 시작")
    print(f"    서브넷: {args.subnet} ({len(hosts)}개 호스트)")
    print(f"    포트  : {ports}")
    print(f"    스레드: {args.workers}")
    print("=" * 60)

    found: list[OpenPort] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_host, str(ip), ports): str(ip)
            for ip in hosts
        }
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            results = future.result()
            for r in results:
                print(f"  [열린 포트] {r.ip}:{r.port} ({r.service})")
                found.append(r)

    print("\n" + "=" * 60)
    print(f"[완료] {len(hosts)}개 호스트 스캔, {len(found)}개 열린 포트 발견")

    if found:
        print("\n[요약] 발견된 서비스:")
        for r in sorted(found, key=lambda x: (x.ip, x.port)):
            print(f"  {r.ip:20s} :{r.port:5d}  {r.service}")


if __name__ == "__main__":
    main()
```

### 5.4 Network Policy로 방어하기

```bash
# Network Policy 적용 — DB는 app=backend 레이블 파드만 접근 허용
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-allow-only-backend
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend   # backend 레이블 파드만 허용
    ports:
    - protocol: TCP
      port: 8080
EOF

# 정책 적용 후 다시 접근 시도 → 실패해야 함
kubectl exec attacker-pod -- curl -s --connect-timeout 3 http://$DB_IP:8080
```

### 5.5 정리

```bash
kubectl delete pod db-simulator attacker-pod
kubectl delete networkpolicy db-allow-only-backend 2>/dev/null || true
```

---

## 6. 방어 체크리스트

| 위협 | 방어책 |
|-----|-------|
| 파드 간 무제한 통신 | Network Policy로 필요한 통신만 허용 |
| DNS 스푸핑 | CoreDNS 감사 로그 활성화 |
| 내부 스니핑 | 파드 간 mTLS 적용 (Istio, Linkerd) |
| 횡적 이동 | 네임스페이스별 격리, 최소 권한 SA |
| 서비스 노출 | NodePort/LoadBalancer 최소화, Ingress 사용 |

### 횡적 이동 탐지: 기본 차단(default-deny)이 먼저

가장 강력한 네트워크 방어는 탐지가 아니라 **기본 차단**입니다. 모든 네임스페이스에 `default-deny` Network Policy를 깔면, 횡적 이동에 필요한 연결 자체가 정책 위반 신호가 됩니다.

```yaml
# 네임스페이스 전체 인그레스 기본 차단
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}        # 모든 파드에 적용
  policyTypes: [Ingress] # 명시적으로 허용하지 않은 인그레스는 차단
```

| 탐지 신호 | 의미하는 공격 | 신호원 |
|---|---|---|
| 정책에 없는 파드 간 연결 시도 | 횡적 이동 정찰 | CNI 흐름 로그(Cilium Hubble, Calico) |
| 단일 파드의 다수 대상 스캔 | 내부 포트 스캔 | 흐름 로그의 fan-out 패턴 |
| 비정상적으로 긴 DNS 쿼리 | DNS 터널링 유출 | CoreDNS 쿼리 로그 |
| 평문 파드 간 트래픽 | mTLS 미적용 구간 | 서비스 메시 텔레메트리 |

> 원칙: Network Policy를 적용했다고 끝이 아니다. CNI 흐름 로그(Hubble 등)로 "거부된 연결"을 모니터링해야, 공격자의 횡적 이동 정찰 시도를 실시간으로 관측할 수 있다. 거부 로그가 갑자기 늘면 침해 신호일 수 있다.

---

<!-- detect-validate-70 -->
## 공격 탐지와 방어 검증

위 신호 표가 "무엇이 보이는가"라면, 검증은 default-deny가 실제로 트래픽을 차단하는지와 그 거부가 흐름 로그에 잡히는지를 직접 확인하는 단계다.

### 공격 → 계층 → 통제(예방) → 탐지 신호

| 공격 | 노리는 계층 | 1차 통제(예방) | 탐지 신호 |
|---|---|---|---|
| 횡적 이동(파드 간 접근) | L3/L4 | default-deny NetworkPolicy | 흐름 로그의 정책 외 연결 시도 |
| 내부 포트 스캔 | L4 | 네임스페이스 분리 정책 | 단일 출발지 fan-out |
| DNS 스푸핑/터널링 | DNS | egress 제한·DNS 정책 | 비정상 긴 쿼리·외부 리졸버 |
| 평문 스니핑 | 전송 | 서비스 메시 mTLS | 메시 텔레메트리상 평문 구간 |

### 방어 검증 (직접 확인)

```bash
# 1) default-deny가 실제로 파드 간 통신을 막는지 재현
kubectl run a --image=nicolaka/netshoot --restart=Never -- sleep 1d
kubectl run b --image=nginx --restart=Never
kubectl exec a -- curl -s --max-time 3 http://<b-pod-ip> -o /dev/null -w "%{http_code}\n"
# 통과: 타임아웃/연결거부 → 정책이 횡적 통신 차단
# 취약: 200이면 NetworkPolicy 미적용 또는 CNI가 정책 미지원

# 2) 그 거부가 흐름 로그에 잡히는지 확인 (Cilium Hubble 예)
hubble observe --verdict DROPPED --since 2m | grep "<b-pod-ip>"
# 통과: DROPPED 이벤트가 관측됨 → 탐지 가시성 확보
# 취약: 로그 없으면 흐름 로깅 미적용(정찰 관측 불가)
```

> 검증은 반드시 **소유한 클러스터·통제된 환경에서만** 수행한다. "정책을 적용했다"가 아니라 차단이 재현되고 거부가 로그에 남는지 확인해야 한다 — CNI가 NetworkPolicy를 지원하는지도 함께 검증한다([[68_Purple_Team]]).

**최신 기법·통제 (2025–2026):**
- 기본 오픈 파드네트워크에서 횡이동·ARP스푸핑·서비스 스니핑 — NetworkPolicy(기본거부)·mTLS(서비스메시)로 격리. 검증: 격리 후 파드간 비인가 트래픽이 실제 차단되는지 재현
- DNS 스푸핑·노출 서비스(LoadBalancer/NodePort)로 노출면 확대 — 이그레스 통제·정책이 강제되는지 확인([[39_Zero_Trust_Architecture]])

---

<a name="english"></a>

# Kubernetes Network Attacks

## K8s Network Model — The Open Office Analogy

By default, Kubernetes uses a flat network model — every pod can talk to every other pod without NAT. Without Network Policies (cubicle dividers), an attacker who compromises one pod can freely reach all others.

---

## 1. Attack Technique 1: Lateral Movement

```bash
# Discover internal services via environment variables
env | grep -E "_SERVICE_HOST|_SERVICE_PORT"

# Scan internal network with nmap (from inside a pod)
nmap -sV 10.244.0.0/16 -p 80,443,3306,5432,6379 --open -T4
```

---

## 2. Attack Technique 2: Pod-to-Pod Traffic Sniffing

```bash
# From a privileged pod with hostNetwork
tcpdump -i any -nn -A 'tcp port 80 and net 10.244.0.0/16'
tcpdump -i any -nn 'tcp port 3306' -w /tmp/db_traffic.pcap
```

---

## 3. Attack Technique 3: DNS Spoofing

```bash
# Monitor DNS queries (from privileged pod)
tcpdump -i any -nn 'udp port 53'

# Check CoreDNS config
kubectl get configmap coredns -n kube-system -o yaml
```

---

## 4. Lab: Pod-to-Pod Communication Without Network Policy

```bash
# Deploy a "DB" pod and an "attacker" pod
# (see Korean section for full YAML)

# Confirm attacker can reach DB with no policy in place
kubectl exec attacker-pod -- curl -s http://$DB_IP:8080

# Apply Network Policy to restrict access
kubectl apply -f db-network-policy.yaml

# Verify access is now blocked
kubectl exec attacker-pod -- curl -s --connect-timeout 3 http://$DB_IP:8080
```

Use the `k8s_net_scan.py` script to enumerate open services from inside a compromised pod.

---

## 5. Defense Checklist

| Threat | Defense |
|--------|---------|
| Unrestricted pod-to-pod | Apply Network Policies (default-deny + allow rules) |
| DNS spoofing | Enable CoreDNS audit logs |
| Traffic sniffing | mTLS between pods (Istio, Linkerd) |
| Lateral movement | Namespace isolation + least-privilege service accounts |
| Exposed services | Minimize NodePort, use Ingress |

### Lateral Movement Detection: Default-Deny First

The strongest network defense is not detection but **default-deny**. Apply a `default-deny` Network Policy to every namespace so the connections needed for lateral movement become policy-violation signals.

```yaml
# Default-deny all ingress in a namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}        # applies to all pods
  policyTypes: [Ingress] # ingress not explicitly allowed is blocked
```

| Detection signal | Attack it implies | Source |
|---|---|---|
| Pod-to-pod connection not in policy | Lateral movement recon | CNI flow logs (Cilium Hubble, Calico) |
| One pod scanning many targets | Internal port scan | Fan-out pattern in flow logs |
| Unusually long DNS queries | DNS tunneling exfil | CoreDNS query logs |
| Plaintext pod-to-pod traffic | Segment without mTLS | Service mesh telemetry |

> Principle: applying Network Policy isn't the end. Monitor "denied connections" via CNI flow logs (e.g., Hubble) to observe an attacker's lateral-movement recon in real time. A sudden spike in deny logs can itself be a breach signal.

---

## Attack Detection and Defense Validation

If the signal table above is "what is visible," validation is where you directly confirm that default-deny actually blocks traffic and that the denial shows up in flow logs.

### Attack -> layer -> control (prevention) -> detection signal

| Attack | Target layer | Primary control (prevention) | Detection signal |
|---|---|---|---|
| Lateral movement (pod-to-pod) | L3/L4 | default-deny NetworkPolicy | Out-of-policy connection in flow logs |
| Internal port scan | L4 | Namespace isolation policy | Fan-out from a single source |
| DNS spoofing/tunneling | DNS | Egress restriction, DNS policy | Abnormally long queries, external resolver |
| Plaintext sniffing | Transport | Service-mesh mTLS | Plaintext segment in mesh telemetry |

### Defense validation (verify yourself)

```bash
# 1) Reproduce whether default-deny actually blocks pod-to-pod traffic
kubectl run a --image=nicolaka/netshoot --restart=Never -- sleep 1d
kubectl run b --image=nginx --restart=Never
kubectl exec a -- curl -s --max-time 3 http://<b-pod-ip> -o /dev/null -w "%{http_code}\n"
# Pass: timeout/connection refused -> policy blocks lateral traffic
# Weak: 200 means NetworkPolicy isn't applied or the CNI doesn't enforce it

# 2) Confirm the denial appears in flow logs (Cilium Hubble example)
hubble observe --verdict DROPPED --since 2m | grep "<b-pod-ip>"
# Pass: a DROPPED event is observed -> detection visibility exists
# Weak: no log means flow logging isn't enabled (no recon visibility)
```

> Run validation only on **clusters you own, in a controlled environment**. Confirm the block reproduces and the denial is logged — not just that you "applied the policy" — and verify your CNI actually supports NetworkPolicy (see [[68_Purple_Team]]).
