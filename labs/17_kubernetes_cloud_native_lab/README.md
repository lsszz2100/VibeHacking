# Lab 17: 클라우드 네이티브 & Kubernetes 보안 랩 (KubeShield)

[![Lab Status](https://img.shields.io/badge/Lab-17_Active-brightgreen)](http://localhost:8017)
[![Port](https://img.shields.io/badge/Port-8017-blue)](http://localhost:8017)
[![Difficulty](https://img.shields.io/badge/Difficulty-★★★★☆-orange)](#)

현대 엔터프라이즈 멀티 테넌트 클라우드 환경에서 발생하는 **Kubernetes 파드 탈출, RBAC 권한 상승, 클라우드 IMDS 탈취, 공급망 어드미션 제어**를 시뮬레이션하고 방어하는 실습 워크스테이션입니다.

---

## 🎯 학습 목표

1. **특권 컨테이너 탈출 & 호스트 장악 (Container Breakout)**:
   - `privileged: true`, `hostPID: true`, `hostPath: /host` 설정을 악용하여 컨테이너 네임스페이스를 탈출하고 호스트 OS 파일시스템(`/host/etc/shadow`)을 적출
   - Pod Security Admission (PSA) `enforce: restricted` 표준을 적용하여 특권 파드 배포를 원천 차단
2. **과도한 RBAC 권한 상승 (RBAC Privilege Escalation)**:
   - 파드 내 기본 마운트되는 ServiceAccount 토큰(`/var/run/secrets/kubernetes.io/serviceaccount/token`)의 와일드카드(`*.* / [*]`) ClusterRole 악용
   - `cluster-admin` RoleBinding 생성 및 악성 권한 상승 차단 (`automountServiceAccountToken: false` 및 최소 권한 원칙)
3. **클라우드 인스턴스 메타데이터(IMDS) 탈취 & 네트워크 정책 (SSRF vs IMDSv2)**:
   - 컨테이너 내부에서 AWS/클라우드 메타데이터 엔드포인트(`169.254.169.254`)를 향한 비인가 접근 및 노드 IAM 자격 증명 적출
   - IMDSv2 강제 적용(`HttpTokens=required`, `HopLimit=1`) 및 Calico/Cilium Egress NetworkPolicy 차단
4. **공급망 위조 이미지 침투 & Sigstore Cosign 검증 (Admission Webhook)**:
   - 서명되지 않은 악성 백도어 이미지의 무단 배포 차단
   - Kyverno/Gatekeeper ValidatingAdmissionWebhook 및 Sigstore Cosign 공개키 서명 검증 강제화

---

## 🚀 빠른 시작

```bash
# vhack CLI를 통한 랩 가동
vhack lab start 17

# 또는 Docker Compose 직접 실행
cd labs/17_kubernetes_cloud_native_lab
docker compose up -d --build

# 웹 콘솔 접속
# http://localhost:8017
```

---

## 🔬 4단계 공격 시나리오 & 플래그

| 단계 | 침해 / 보안 주제 | 핵심 기법 / 완화책 | 완료 플래그 |
| :---: | :--- | :--- | :--- |
| **Stage 1** | 특권 컨테이너 탈출 | `nsenter`, `hostPath`, PSA Restricted | `FLAG{k8s_c0nt41n3r_3sc4p3_h0st_9182}` |
| **Stage 2** | 과도한 RBAC 권한 상승 | SA Token, Wildcard ClusterRole, least-privilege | `FLAG{k8s_rb4c_clvst3r_4dm1n_pwn_4821}` |
| **Stage 3** | 클라우드 IMDS 탈취 | SSRF, AWS IAM Token, IMDSv2 Hop Limit 1, Egress Policy | `FLAG{k8s_1mdsv2_m3t4d4t4_sh13ld_6394}` |
| **Stage 4** | 공급망 위조 이미지 배포 | ValidatingAdmissionWebhook, Kyverno, Cosign Sign | `FLAG{k8s_4dm1ss10n_c0s1gn_v3r1fy_2048}` |

---

## 💻 가상 KubeShield 터미널 명령어

웹 콘솔 우측의 대화형 터미널에서 다음 명령어를 직접 실행할 수 있습니다:

```bash
kubectl get nodes                     # 클러스터 노드 상태 확인
kubectl get pods -A                   # 전체 네임스페이스 워크로드 파드 목록
kubectl auth can-i --list             # 현재 ServiceAccount의 RBAC 권한 매트릭스
curl http://169.254.169.254/...       # 노드 메타데이터 엔드포인트 쿼리
cosign verify <image>                 # 컨테이너 이미지 Sigstore 서명 검증
kubectl apply -f psa-restricted.yaml  # PSA Restricted 정책 적용
kubectl apply -f rbac-fix.yaml        # 최소 권한 RBAC 및 토큰 마운트 해제
status                                # 클러스터 보안 상태 및 랩 진행도
flags                                 # 획득 플래그 확인
help                                  # 터미널 명령어 도움말
```

---

## 🧪 자동화 검증

```bash
# Lab 17 단독 테스트
vhack lab test 17

# 전체 랩 통합 검증
vhack lab test --all
```
