#!/usr/bin/env python3
"""Lab 10: Kubernetes & Container Security Hands-on Lab.

Provides a virtual Kubernetes cluster environment, complete with an in-cluster
ServiceAccount token leak, overprivileged RBAC roles, hostPath volume mount escape,
and privileged container breakout simulation.
"""

import base64
import json
import os
import re
import shlex
import time
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="KubeShield - Kubernetes Security Hands-on Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Mock ServiceAccount Token (JWT format simulation)
MOCK_SA_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Imt1YmUtc2hpZWxkLWtleS0yMDI2In0."
    "eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJtb25pdG9yaW5nIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImNsdXN0ZXItbW9uaXRvci1zYS10b2tlbi05OGFmM2QiLCJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiY2x1c3Rlci1tb25pdG9yLXNhIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Om1vbml0b3Jpbmc6Y2x1c3Rlci1tb25pdG9yLXNhIn0."
    "c83b8a8f7c9e01f02a4d5b6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"
)

ROOT_SA_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Imt1YmUtc2hpZWxkLWtleS0yMDI2In0."
    "eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOm1hc3RlcnMiLCJyb2xlIjoiY2x1c3Rlci1hZG1pbiJ9."
    "0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e"
)

CA_CERT = """-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIUW5z...[MOCK K8S CLUSTER CA CERTIFICATE]...
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyv+hR8V7xN0k...
-----END CERTIFICATE-----"""

# Cluster State
class ClusterState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.nodes = [
            {"name": "k8s-control-plane-01", "status": "Ready", "roles": ["control-plane"], "ip": "10.244.0.1"},
            {"name": "k8s-worker-node-01", "status": "Ready", "roles": ["worker"], "ip": "10.244.0.11"},
            {"name": "k8s-worker-node-02", "status": "Ready", "roles": ["worker"], "ip": "10.244.0.12"},
        ]

        self.namespaces = ["default", "kube-system", "monitoring", "production"]

        self.pods = [
            {
                "name": "coredns-787d4945fb-2k8m9",
                "namespace": "kube-system",
                "status": "Running",
                "node": "k8s-control-plane-01",
                "ip": "10.244.1.2",
            },
            {
                "name": "kube-proxy-82hfl",
                "namespace": "kube-system",
                "status": "Running",
                "node": "k8s-worker-node-01",
                "ip": "10.244.1.3",
            },
            {
                "name": "prometheus-node-exporter-49xdf",
                "namespace": "monitoring",
                "status": "Running",
                "node": "k8s-worker-node-01",
                "ip": "10.244.1.20",
                "serviceAccount": "cluster-monitor-sa",
            },
            {
                "name": "payment-api-deployment-55d8f9974b-tr8zq",
                "namespace": "production",
                "status": "Running",
                "node": "k8s-worker-node-02",
                "ip": "10.244.2.15",
                "serviceAccount": "payment-sa",
            },
            {
                "name": "customer-db-postgresql-0",
                "namespace": "production",
                "status": "Running",
                "node": "k8s-worker-node-02",
                "ip": "10.244.2.18",
                "serviceAccount": "db-sa",
            },
        ]

        self.secrets = {
            "default": {
                "default-token-abc": {"token": base64.b64encode(b"dummy-token").decode()}
            },
            "kube-system": {
                "k8s-admin-bootstrap-token": {
                    "bootstrap.token": base64.b64encode(b"07401b.f395accdbe123456").decode(),
                    "cluster-signing-key": base64.b64encode(b"SEC_SIGNING_KEY_RSA4096_VALID").decode(),
                }
            },
            "monitoring": {
                "cluster-monitor-sa-token-98af3d": {
                    "token": base64.b64encode(MOCK_SA_TOKEN.encode()).decode(),
                    "ca.crt": base64.b64encode(CA_CERT.encode()).decode(),
                    "namespace": base64.b64encode(b"monitoring").decode(),
                }
            },
            "production": {
                "db-root-credentials": {
                    "POSTGRES_USER": base64.b64encode(b"postgres_admin").decode(),
                    "POSTGRES_PASSWORD": base64.b64encode(b"Sup3rS3cr3t_PgPass_2026!").decode(),
                    "FLAG_CH2": base64.b64encode(b"FLAG{K8S_RBAC_OVERPRIVILEGED_SECRET_DUMP}").decode(),
                },
                "stripe-api-master-key": {
                    "api_key": base64.b64encode(b"sk_live_992187391823791283").decode()
                }
            }
        }

        self.cluster_role_bindings = [
            {
                "name": "cluster-monitoring-binding",
                "roleRef": {"kind": "ClusterRole", "name": "cluster-monitor-role"},
                "subjects": [{"kind": "ServiceAccount", "name": "cluster-monitor-sa", "namespace": "monitoring"}],
            }
        ]

        self.cluster_roles = [
            {
                "name": "cluster-monitor-role",
                "rules": [
                    {"apiGroups": [""], "resources": ["pods", "nodes", "namespaces", "services"], "verbs": ["get", "list", "watch", "create"]},
                    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
                    {"apiGroups": ["apps"], "resources": ["deployments", "daemonsets"], "verbs": ["get", "list"]},
                ],
            }
        ]

        self.hostpath_pod_created = False
        self.privileged_pod_created = False
        self.cluster_takeover_achieved = False

        self.flags = {
            "ch1": "FLAG{K8S_SA_TOKEN_LEAKED_SECRET_RECON}",
            "ch2": "FLAG{K8S_RBAC_OVERPRIVILEGED_SECRET_DUMP}",
            "ch3": "FLAG{K8S_HOSTPATH_ESCAPE_NODE_ROOT_ACCESS}",
            "ch4": "FLAG{K8S_PRIVILEGED_POD_ESCAPE_CLUSTER_TAKEOVER}",
        }

        self.solved = {
            "ch1": False,
            "ch2": False,
            "ch3": False,
            "ch4": False,
        }

        # Terminal context: simulate current container state
        self.term_cwd = "/app"
        self.term_env = {
            "HOSTNAME": "prometheus-node-exporter-49xdf",
            "KUBERNETES_SERVICE_HOST": "10.96.0.1",
            "KUBERNETES_SERVICE_PORT": "443",
            "KUBERNETES_PORT": "tcp://10.96.0.1:443",
            "TERM": "xterm-256color",
            "USER": "root",
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }

cluster = ClusterState()


# Virtual File System inside the compromised pod
VIRTUAL_FS = {
    "/var/run/secrets/kubernetes.io/serviceaccount/token": MOCK_SA_TOKEN,
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt": CA_CERT,
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace": "monitoring",
    "/etc/hosts": "127.0.0.1 localhost\n10.244.1.20 prometheus-node-exporter-49xdf\n10.96.0.1 kubernetes.default.svc\n",
    "/etc/resolv.conf": "nameserver 10.96.0.10\nsearch monitoring.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n",
    "/app/config.yaml": "scrape_interval: 15s\nevaluation_interval: 15s\ncluster_name: corp-k8s-cluster.local\n",
    "/root/.bashrc": "export PS1='\\[\\033[01;31m\\]root@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]# '\n",
}

# Host filesystem accessible when hostPath is mounted
HOST_FS = {
    "/host/etc/shadow": (
        "root:$6$k8s$WqB8u0gXJ2m.9y8f3kLpQ0rA9...:19740:0:99999:7:::\n"
        "daemon:*:19740:0:99999:7:::\n"
        "bin:*:19740:0:99999:7:::\n"
        "kube:*:19740:0:99999:7:::\n"
    ),
    "/host/root/host_flag.txt": "FLAG{K8S_HOSTPATH_ESCAPE_NODE_ROOT_ACCESS}\n[!] Congratulations: You mounted the Node host filesystem into a pod!\n",
    "/host/etc/kubernetes/kubelet.conf": (
        "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.244.0.1:6443\n"
        "users:\n- name: system:node:k8s-worker-node-01\n  user:\n    client-certificate-data: LS0tLS1CRUdJTi...[NODE_CERT]\n"
    ),
}


# Authentication helper for API requests
def authenticate_request(auth_header: Optional[str]) -> Dict[str, Any]:
    if not auth_header:
        return {"authenticated": False, "user": "system:anonymous", "groups": ["system:unauthenticated"]}
    if not auth_header.startswith("Bearer "):
        return {"authenticated": False, "user": "system:anonymous", "groups": ["system:unauthenticated"]}
    token = auth_header.split(" ", 1)[1].strip()
    if token == MOCK_SA_TOKEN:
        cluster.solved["ch1"] = True
        return {
            "authenticated": True,
            "user": "system:serviceaccount:monitoring:cluster-monitor-sa",
            "namespace": "monitoring",
            "groups": ["system:serviceaccounts", "system:serviceaccounts:monitoring"],
            "role": "cluster-monitor-role",
        }
    elif token == ROOT_SA_TOKEN:
        return {
            "authenticated": True,
            "user": "system:admin",
            "groups": ["system:masters"],
            "role": "cluster-admin",
        }
    return {"authenticated": False, "user": "system:anonymous", "groups": ["system:unauthenticated"]}


# Standard Kubernetes API Emulation
@app.get("/version")
def get_cluster_version():
    return {
        "major": "1",
        "minor": "28",
        "gitVersion": "v1.28.3",
        "platform": "linux/amd64",
    }


@app.get("/api/v1/namespaces")
def list_namespaces(authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})
    return {
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "items": [
            {"metadata": {"name": ns, "creationTimestamp": "2026-01-01T00:00:00Z"}}
            for ns in cluster.namespaces
        ],
    }


@app.get("/api/v1/namespaces/{ns}/pods")
def list_pods(ns: str, authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})
    
    pods = [p for p in cluster.pods if p["namespace"] == ns or ns == "_all"]
    return {
        "kind": "PodList",
        "apiVersion": "v1",
        "items": [
            {
                "metadata": {"name": p["name"], "namespace": p["namespace"]},
                "status": {"phase": p["status"], "podIP": p.get("ip", "10.244.0.0")},
                "spec": {"nodeName": p.get("node", "k8s-worker-node-01")},
            }
            for p in pods
        ],
    }


@app.get("/api/v1/namespaces/{ns}/secrets")
def list_secrets(ns: str, authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})

    if ns not in cluster.secrets:
        return {"kind": "SecretList", "apiVersion": "v1", "items": []}

    cluster.solved["ch2"] = True
    items = []
    for sec_name, data in cluster.secrets[ns].items():
        items.append({
            "metadata": {"name": sec_name, "namespace": ns},
            "type": "Opaque",
            "data": data,
        })
    return {"kind": "SecretList", "apiVersion": "v1", "items": items}


@app.get("/api/v1/namespaces/{ns}/secrets/{name}")
def get_secret(ns: str, name: str, authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})

    sec_group = cluster.secrets.get(ns, {})
    if name not in sec_group:
        raise HTTPException(status_code=404, detail={"kind": "Status", "status": "Failure", "message": f"Secret '{name}' not found"})

    cluster.solved["ch2"] = True
    return {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {"name": name, "namespace": ns},
        "type": "Opaque",
        "data": sec_group[name],
    }


@app.post("/api/v1/namespaces/{ns}/pods")
async def create_pod(ns: str, request: Request, authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})

    body = await request.json()
    pod_name = body.get("metadata", {}).get("name", f"pod-{int(time.time())}")
    spec = body.get("spec", {})
    
    # Check for hostPath volume
    volumes = spec.get("volumes", [])
    has_hostpath = any("hostPath" in v for v in volumes)
    
    # Check for privileged securityContext
    containers = spec.get("containers", [])
    is_privileged = False
    has_hostpid = spec.get("hostPID", False)

    for c in containers:
        sec_ctx = c.get("securityContext", {})
        if sec_ctx.get("privileged", False):
            is_privileged = True
        caps = sec_ctx.get("capabilities", {}).get("add", [])
        if "SYS_ADMIN" in caps or "CAP_SYS_ADMIN" in caps:
            is_privileged = True

    new_pod = {
        "name": pod_name,
        "namespace": ns,
        "status": "Running",
        "node": "k8s-worker-node-01",
        "ip": f"10.244.1.{len(cluster.pods) + 30}",
    }
    cluster.pods.append(new_pod)

    msg = f"Pod {pod_name} created successfully."
    if has_hostpath:
        cluster.hostpath_pod_created = True
        cluster.solved["ch3"] = True
        msg += " [ALERT] HostPath volume detected: Root filesystem exposed at mount path!"

    if is_privileged or (has_hostpath and has_hostpid):
        cluster.privileged_pod_created = True
        cluster.cluster_takeover_achieved = True
        cluster.solved["ch4"] = True
        msg += " [ALERT] Privileged container detected: Host kernel capabilities granted (Escape possible)!"

    return {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": pod_name, "namespace": ns},
        "status": {"phase": "Running"},
        "message": msg,
    }


@app.get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
def list_clusterrolebindings(authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})
    return {
        "kind": "ClusterRoleBindingList",
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "items": cluster.cluster_role_bindings,
    }


@app.get("/apis/rbac.authorization.k8s.io/v1/clusterroles")
def list_clusterroles(authorization: Optional[str] = Header(None)):
    user = authenticate_request(authorization)
    if not user["authenticated"]:
        raise HTTPException(status_code=401, detail={"kind": "Status", "status": "Failure", "message": "Unauthorized"})
    return {
        "kind": "ClusterRoleList",
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "items": cluster.cluster_roles,
    }


# Terminal Command Execution Simulator
class ExecRequest(BaseModel):
    command: str

@app.post("/api/terminal/exec")
def terminal_exec(req: ExecRequest):
    cmd_raw = req.command.strip()
    if not cmd_raw:
        return {"output": "", "exit_code": 0}

    # Pipeline or multiple commands support
    if "&&" in cmd_raw:
        subcmds = cmd_raw.split("&&")
        out_total = []
        for sc in subcmds:
            res = execute_single_cmd(sc.strip())
            out_total.append(res["output"])
            if res["exit_code"] != 0:
                return {"output": "\n".join(out_total), "exit_code": res["exit_code"]}
        return {"output": "\n".join(out_total), "exit_code": 0}

    return execute_single_cmd(cmd_raw)


def execute_single_cmd(cmd: str) -> Dict[str, Any]:
    parts = shlex.split(cmd)
    if not parts:
        return {"output": "", "exit_code": 0}

    prog = parts[0]
    args = parts[1:]

    # whoami
    if prog == "whoami":
        return {"output": "root", "exit_code": 0}

    # id
    if prog == "id":
        return {"output": "uid=0(root) gid=0(root) groups=0(root)", "exit_code": 0}

    # pwd
    if prog == "pwd":
        return {"output": cluster.term_cwd, "exit_code": 0}

    # env
    if prog == "env":
        lines = [f"{k}={v}" for k, v in cluster.term_env.items()]
        return {"output": "\n".join(lines), "exit_code": 0}

    # hostname
    if prog == "hostname":
        return {"output": cluster.term_env["HOSTNAME"], "exit_code": 0}

    # ls
    if prog == "ls":
        target = args[0] if args and not args[0].startswith("-") else cluster.term_cwd
        if target.startswith("-") and len(args) > 1:
            target = args[1]
        
        # Check in virtual fs
        target = os.path.normpath(target)
        if target in ["/var/run/secrets/kubernetes.io/serviceaccount", "/run/secrets/kubernetes.io/serviceaccount"]:
            return {"output": "ca.crt\nnamespace\ntoken", "exit_code": 0}
        if target in ["/var/run/secrets/kubernetes.io", "/run/secrets/kubernetes.io"]:
            return {"output": "serviceaccount", "exit_code": 0}
        if target in ["/var/run/secrets", "/run/secrets"]:
            return {"output": "kubernetes.io", "exit_code": 0}
        if target in ["/var/run", "/run"]:
            return {"output": "secrets", "exit_code": 0}
        if target == "/app":
            return {"output": "config.yaml", "exit_code": 0}
        if target == "/root":
            return {"output": ".bashrc", "exit_code": 0}
        if target == "/":
            base = "app  bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
            if cluster.hostpath_pod_created:
                base += "  host"
            return {"output": base, "exit_code": 0}
        if target == "/host" or target.startswith("/host/"):
            if not cluster.hostpath_pod_created:
                return {"output": f"ls: cannot access '{target}': No such file or directory", "exit_code": 2}
            if target == "/host":
                return {"output": "bin  boot  dev  etc  home  lib  lib64  proc  root  sys  usr  var", "exit_code": 0}
            if target == "/host/root":
                return {"output": "host_flag.txt", "exit_code": 0}
            if target == "/host/etc":
                return {"output": "kubernetes  shadow  passwd  hosts  os-release", "exit_code": 0}
            if target == "/host/etc/kubernetes":
                return {"output": "kubelet.conf  pki", "exit_code": 0}

        # Fallback listing
        matches = [k for k in VIRTUAL_FS if k.startswith(target)]
        if matches:
            entries = set()
            for m in matches:
                rel = os.path.relpath(m, target)
                top = rel.split(os.sep)[0]
                if top != ".":
                    entries.add(top)
            return {"output": "\n".join(sorted(entries)), "exit_code": 0}
        return {"output": f"ls: cannot access '{target}': No such file or directory", "exit_code": 2}

    # cat
    if prog == "cat":
        if not args:
            return {"output": "cat: missing file operand", "exit_code": 1}
        filepath = os.path.normpath(args[0])
        
        # Check virtual fs
        if filepath in VIRTUAL_FS:
            content = VIRTUAL_FS[filepath]
            if "serviceaccount/token" in filepath:
                cluster.solved["ch1"] = True
            return {"output": content, "exit_code": 0}

        # Check host fs
        if filepath in HOST_FS:
            if not cluster.hostpath_pod_created:
                return {"output": f"cat: {filepath}: No such file or directory", "exit_code": 1}
            content = HOST_FS[filepath]
            if "host_flag.txt" in filepath:
                cluster.solved["ch3"] = True
            return {"output": content, "exit_code": 0}

        return {"output": f"cat: {filepath}: No such file or directory", "exit_code": 1}

    # curl simulation
    if prog == "curl":
        # Extract headers and URL
        url = ""
        auth = ""
        post_data = None
        method = "GET"

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ["-H", "--header"] and i + 1 < len(args):
                hdr = args[i + 1]
                if "Authorization:" in hdr:
                    auth = hdr.split("Authorization:", 1)[1].strip()
                i += 2
            elif arg in ["-X", "--request"] and i + 1 < len(args):
                method = args[i + 1].upper()
                i += 2
            elif arg in ["-d", "--data"] and i + 1 < len(args):
                post_data = args[i + 1]
                method = "POST"
                i += 2
            elif arg.startswith("http://") or arg.startswith("https://") or arg.startswith("/"):
                url = arg
                i += 1
            else:
                i += 1

        if not url:
            return {"output": "curl: no URL specified!", "exit_code": 2}

        # Normalize URL path
        url_path = url
        if "://" in url_path:
            url_path = "/" + url_path.split("://", 1)[1].split("/", 1)[1] if "/" in url_path.split("://", 1)[1] else "/"

        user = authenticate_request(auth)
        if not user["authenticated"]:
            err = {"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "Unauthorized", "code": 401}
            return {"output": json.dumps(err, indent=2), "exit_code": 0}

        # Route simulated curl endpoints
        if url_path == "/api/v1/namespaces":
            return {"output": json.dumps(list_namespaces(auth), indent=2), "exit_code": 0}
        
        m_pods = re.match(r"^/api/v1/namespaces/([^/]+)/pods$", url_path)
        if m_pods:
            ns = m_pods.group(1)
            return {"output": json.dumps(list_pods(ns, auth), indent=2), "exit_code": 0}

        m_sec = re.match(r"^/api/v1/namespaces/([^/]+)/secrets$", url_path)
        if m_sec:
            ns = m_sec.group(1)
            return {"output": json.dumps(list_secrets(ns, auth), indent=2), "exit_code": 0}

        m_sec_single = re.match(r"^/api/v1/namespaces/([^/]+)/secrets/([^/]+)$", url_path)
        if m_sec_single:
            ns, sec_name = m_sec_single.group(1), m_sec_single.group(2)
            try:
                res = get_secret(ns, sec_name, auth)
                return {"output": json.dumps(res, indent=2), "exit_code": 0}
            except HTTPException as ex:
                return {"output": json.dumps(ex.detail, indent=2), "exit_code": 0}

        if url_path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
            return {"output": json.dumps(list_clusterrolebindings(auth), indent=2), "exit_code": 0}

        if url_path == "/apis/rbac.authorization.k8s.io/v1/clusterroles":
            return {"output": json.dumps(list_clusterroles(auth), indent=2), "exit_code": 0}

        return {"output": f'{{"kind":"Status","status":"Failure","message":"Endpoint {url_path} not found","code":404}}', "exit_code": 0}

    # kubectl simulation
    if prog == "kubectl":
        if not args:
            return {"output": "kubectl controls the Kubernetes cluster manager.\nFind more information at: https://kubernetes.io/docs/reference/kubectl/", "exit_code": 0}

        action = args[0]
        # kubectl get
        if action == "get":
            res_type = args[1] if len(args) > 1 else ""
            res_type = res_type.lower()
            ns = "monitoring"
            all_ns = False

            # parse flags
            for idx, a in enumerate(args[2:], start=2):
                if a in ["-A", "--all-namespaces"]:
                    all_ns = True
                elif a in ["-n", "--namespace"] and idx + 1 < len(args):
                    ns = args[idx + 1]

            if res_type in ["pod", "pods", "po"]:
                pods_to_show = cluster.pods if all_ns else [p for p in cluster.pods if p["namespace"] == ns]
                header = f"{'NAMESPACE':<16} {'NAME':<45} {'READY':<8} {'STATUS':<10} {'RESTARTS':<10} {'AGE':<6}"
                rows = [header]
                for p in pods_to_show:
                    rows.append(f"{p['namespace']:<16} {p['name']:<45} 1/1      {p['status']:<10} 0          2d")
                return {"output": "\n".join(rows), "exit_code": 0}

            if res_type in ["secret", "secrets"]:
                cluster.solved["ch2"] = True
                target_ns = list(cluster.secrets.keys()) if all_ns else [ns]
                header = f"{'NAMESPACE':<16} {'NAME':<32} {'TYPE':<20} {'DATA':<6} {'AGE':<6}"
                rows = [header]
                for nspace in target_ns:
                    for sname, data in cluster.secrets.get(nspace, {}).items():
                        rows.append(f"{nspace:<16} {sname:<32} Opaque               {len(data)}      2d")
                return {"output": "\n".join(rows), "exit_code": 0}

            if res_type in ["node", "nodes", "no"]:
                header = f"{'NAME':<25} {'STATUS':<8} {'ROLES':<16} {'AGE':<6} {'VERSION':<10}"
                rows = [header]
                for nd in cluster.nodes:
                    roles = ",".join(nd["roles"])
                    rows.append(f"{nd['name']:<25} {nd['status']:<8} {roles:<16} 12d    v1.28.3")
                return {"output": "\n".join(rows), "exit_code": 0}

            if res_type in ["clusterrolebinding", "clusterrolebindings", "crb"]:
                header = f"{'NAME':<35} {'ROLE':<30} {'USERS':<25}"
                rows = [header]
                for crb in cluster.cluster_role_bindings:
                    subj = crb["subjects"][0]["name"]
                    rows.append(f"{crb['name']:<35} ClusterRole/{crb['roleRef']['name']:<18} ServiceAccount/{subj}")
                return {"output": "\n".join(rows), "exit_code": 0}

            if res_type in ["clusterrole", "clusterroles"]:
                header = f"{'NAME':<35} {'CREATED AT'}"
                rows = [header]
                for cr in cluster.cluster_roles:
                    rows.append(f"{cr['name']:<35} 2026-01-01T00:00:00Z")
                return {"output": "\n".join(rows), "exit_code": 0}

            return {"output": f"error: the server doesn't have a resource type \"{res_type}\"", "exit_code": 1}

        # kubectl apply -f
        if action == "apply":
            cluster.hostpath_pod_created = True
            cluster.privileged_pod_created = True
            cluster.cluster_takeover_achieved = True
            cluster.solved["ch3"] = True
            cluster.solved["ch4"] = True
            cluster.pods.append({
                "name": "escape-exploit-pod",
                "namespace": "default",
                "status": "Running",
                "node": "k8s-worker-node-01",
                "ip": "10.244.1.99",
            })
            return {
                "output": "pod/escape-exploit-pod created\n[!] HostPath / mounted to /host\n[!] privileged: true & hostPID: true granted\n[+] Exploitation Pod successfully deployed!",
                "exit_code": 0,
            }

        # kubectl exec
        if action == "exec":
            if "escape-exploit-pod" in " ".join(args):
                cluster.solved["ch3"] = True
                cluster.solved["ch4"] = True
                return {
                    "output": (
                        "root@k8s-worker-node-01:/# cat /host/root/host_flag.txt\n"
                        "FLAG{K8S_HOSTPATH_ESCAPE_NODE_ROOT_ACCESS}\n\n"
                        "root@k8s-worker-node-01:/# nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash\n"
                        "root@control-plane:/# cat /etc/kubernetes/admin.conf\n"
                        "FLAG{K8S_PRIVILEGED_POD_ESCAPE_CLUSTER_TAKEOVER}\n"
                        "[+] CLUSTER COMPROMISED: Full root access on node and cluster control plane!"
                    ),
                    "exit_code": 0,
                }
            return {"output": f"Executing command on target pod...", "exit_code": 0}

        return {"output": f"kubectl: action '{action}' completed.", "exit_code": 0}

    # nsenter or container escape command
    if prog == "nsenter" or "nsenter" in cmd:
        cluster.cluster_takeover_achieved = True
        cluster.solved["ch4"] = True
        return {
            "output": (
                "[+] Entering host PID 1 namespace...\n"
                "Linux k8s-worker-node-01 5.15.0-89-generic #99-Ubuntu SMP\n"
                "root@k8s-worker-node-01:~# whoami\nroot\n"
                "FLAG{K8S_PRIVILEGED_POD_ESCAPE_CLUSTER_TAKEOVER}\n"
            ),
            "exit_code": 0,
        }

    return {"output": f"bash: {prog}: command not found", "exit_code": 127}


# Challenge API & Flag Verification
@app.get("/api/challenges")
def get_challenges():
    return {
        "challenges": [
            {
                "id": "ch1",
                "title": "Stage 1: ServiceAccount Token Reconnaissance",
                "desc": "인-클러스터 Pod 내부의 기본 ServiceAccount 토큰(/var/run/secrets/kubernetes.io/serviceaccount/token)을 추출하고 K8s API 서버와 통신하십시오.",
                "hint": "cat /var/run/secrets/kubernetes.io/serviceaccount/token 또는 curl -H 'Authorization: Bearer <TOKEN>' http://localhost:8090/api/v1/namespaces/default/pods",
                "solved": cluster.solved["ch1"],
                "flag": cluster.flags["ch1"] if cluster.solved["ch1"] else None,
            },
            {
                "id": "ch2",
                "title": "Stage 2: Overprivileged RBAC Secret Dumping",
                "desc": "탈취한 SA의 과도한 RBAC 권한을 이용해 'production' 네임스페이스의 민감 Secret(db-root-credentials)을 덤프하고 플래그를 추출하십시오.",
                "hint": "kubectl get secrets -n production 또는 curl -H 'Authorization: Bearer <TOKEN>' http://localhost:8090/api/v1/namespaces/production/secrets/db-root-credentials",
                "solved": cluster.solved["ch2"],
                "flag": cluster.flags["ch2"] if cluster.solved["ch2"] else None,
            },
            {
                "id": "ch3",
                "title": "Stage 3: HostPath Volume Mount & Container Breakout",
                "desc": "과도한 Pod 생성 권한을 악용하여 노드 루트 파일시스템(/)을 hostPath로 마운트하는 Pod를 배포하고 /host/root/host_flag.txt를 획득하십시오.",
                "hint": "kubectl apply -f evil-pod.yaml (hostPath: path: /) 후 /host/root/host_flag.txt 확인",
                "solved": cluster.solved["ch3"],
                "flag": cluster.flags["ch3"] if cluster.solved["ch3"] else None,
            },
            {
                "id": "ch4",
                "title": "Stage 4: Privileged Pod Escape & Cluster Takeover",
                "desc": "privileged: true 및 hostPID 설정을 악용하여 호스트 네임스페이스로 탈출(nsenter)하고 클러스터 마스터 권한을 완전 장악하십시오.",
                "hint": "nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash 실행",
                "solved": cluster.solved["ch4"],
                "flag": cluster.flags["ch4"] if cluster.solved["ch4"] else None,
            },
        ],
        "cluster_status": {
            "node_count": len(cluster.nodes),
            "pod_count": len(cluster.pods),
            "hostpath_escaped": cluster.hostpath_pod_created,
            "cluster_takeover": cluster.cluster_takeover_achieved,
        }
    }


class FlagVerifyRequest(BaseModel):
    flag: str

@app.post("/api/verify_flag")
def verify_flag(req: FlagVerifyRequest):
    submitted = req.flag.strip()
    for ch_id, flg in cluster.flags.items():
        if submitted == flg:
            cluster.solved[ch_id] = True
            return {"success": True, "challenge": ch_id, "message": f"Correct! {ch_id.upper()} solved."}
    return {"success": False, "message": "Invalid flag."}


@app.post("/api/reset")
def reset_cluster():
    cluster.reset()
    return {"message": "Cluster environment reset to default initial state."}


@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>KubeShield Lab Running</h1>"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main.py:app", host="0.0.0.0", port=8090, reload=False)
