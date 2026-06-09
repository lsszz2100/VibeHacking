> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Linux 보안 강화 자동화 — CIS 벤치마크·Ansible·감사 스크립트

## 0. 초보자를 위한 개념 이해

### Linux 보안 강화(Hardening)란?

새로 설치된 Linux 서버는 기본 설정으로는 보안에 취약합니다. 불필요한 서비스 실행, 약한 패스워드 정책, 넓은 파일 권한 등이 문제입니다. 보안 강화는 이를 체계적으로 개선하는 과정입니다.

```
CIS (Center for Internet Security) 벤치마크 구조:

  Level 1 (기본 보안):
    → 대부분의 환경에 적용 가능
    → 운영 영향 최소화
    예: SSH 루트 로그인 차단, 불필요한 서비스 중지

  Level 2 (강화된 보안):
    → 고보안 환경 (금융, 의료, 정부)
    → 일부 기능 제한 가능
    예: SELinux Enforcing 모드, 모든 부팅 미디어 차단

  자동화 도구:
    Ansible       → 다중 서버 일괄 강화
    OpenSCAP      → CIS 벤치마크 자동 검사
    Lynis         → 로컬 보안 감사
    Chef InSpec   → 정책 코드화 및 검사
```

---

## 1. CIS 벤치마크 기반 보안 감사

### 1.1 Python 자동 감사 스크립트

```python
#!/usr/bin/env python3
"""
CIS Ubuntu Linux 22.04 LTS Benchmark v1.0 기반 자동 감사.
root 또는 sudo 권한 필요.
참고: https://www.cisecurity.org/benchmark/ubuntu_linux
"""
from __future__ import annotations

import grp
import logging
import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    check_id: str
    title: str
    level: int  # 1 또는 2
    passed: bool
    current_value: str
    expected_value: str
    remediation: str
    details: str = ""


def run_cmd(cmd: str) -> tuple[str, int]:
    """명령 실행 후 (stdout, 종료코드) 반환."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    )
    return result.stdout.strip(), result.returncode


# ─── CIS 검사 함수들 ─────────────────────────────────────────

def check_1_1_filesystem_tmp_partition() -> CheckResult:
    """CIS 1.1.2 - /tmp 파티션 분리 확인."""
    out, _ = run_cmd("findmnt /tmp")
    passed = bool(out)
    return CheckResult(
        check_id="1.1.2", title="/tmp 별도 파티션", level=1,
        passed=passed,
        current_value="별도 파티션 있음" if passed else "별도 파티션 없음",
        expected_value="별도 파티션",
        remediation="fstab에 /tmp 별도 파티션 추가 또는 tmpfs 마운트 설정",
    )


def check_1_5_bootloader_password() -> CheckResult:
    """CIS 1.5.1 - GRUB 부트로더 패스워드 설정 확인."""
    grub_cfg = Path("/boot/grub/grub.cfg")
    content = grub_cfg.read_text(errors="replace") if grub_cfg.exists() else ""
    has_pw = "password_pbkdf2" in content or "password" in content
    return CheckResult(
        check_id="1.5.1", title="GRUB 부트로더 패스워드 설정", level=1,
        passed=has_pw,
        current_value="패스워드 설정됨" if has_pw else "패스워드 없음",
        expected_value="password_pbkdf2 설정",
        remediation="grub-mkpasswd-pbkdf2로 해시 생성 후 /etc/grub.d/40_custom에 추가",
    )


def check_2_2_services() -> list[CheckResult]:
    """CIS 2.2 - 불필요한 서비스 비활성화 확인."""
    dangerous_services = [
        ("avahi-daemon", "2.2.2", "Avahi 서버 (mDNS)"),
        ("cups", "2.2.4", "CUPS 프린트 서버"),
        ("isc-dhcp-server", "2.2.5", "DHCP 서버"),
        ("slapd", "2.2.6", "LDAP 서버"),
        ("nfs-kernel-server", "2.2.7", "NFS 서버"),
        ("vsftpd", "2.2.9", "FTP 서버"),
        ("apache2", "2.2.10", "HTTP 서버"),
        ("xinetd", "2.2.13", "xinetd 슈퍼 서버"),
        ("telnet", "2.2.18", "telnet 서버"),
        ("tftp", "2.2.19", "TFTP 서버"),
    ]

    results = []
    for service, cis_id, desc in dangerous_services:
        out, rc = run_cmd(f"systemctl is-enabled {service} 2>/dev/null")
        is_enabled = out.strip() in {"enabled", "static"}
        results.append(CheckResult(
            check_id=cis_id, title=f"{desc} 비활성화", level=1,
            passed=not is_enabled,
            current_value="활성화" if is_enabled else "비활성화/없음",
            expected_value="비활성화",
            remediation=f"sudo systemctl disable --now {service}",
        ))
    return results


def check_3_1_packet_redirect() -> CheckResult:
    """CIS 3.1.1 - IP 패킷 포워딩 비활성화 확인."""
    out, _ = run_cmd("sysctl net.ipv4.ip_forward")
    value = out.split("=")[-1].strip() if "=" in out else "unknown"
    passed = value == "0"
    return CheckResult(
        check_id="3.1.1", title="IPv4 패킷 포워딩 비활성화", level=1,
        passed=passed,
        current_value=value,
        expected_value="0",
        remediation="echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-cis.conf && sysctl -p",
    )


def check_5_2_ssh_config() -> list[CheckResult]:
    """CIS 5.2 - SSH 서버 설정 검사."""
    sshd_config = Path("/etc/ssh/sshd_config")
    content = sshd_config.read_text(errors="replace") if sshd_config.exists() else ""

    checks = [
        ("5.2.5", "SSH MaxAuthTries ≤ 4", r"^MaxAuthTries\s+(\d+)", "4",
         "le", "MaxAuthTries 4 설정"),
        ("5.2.6", "SSH IgnoreRhosts yes", r"^IgnoreRhosts\s+(\w+)", "yes",
         "eq", "IgnoreRhosts yes 설정"),
        ("5.2.7", "SSH HostbasedAuthentication no", r"^HostbasedAuthentication\s+(\w+)", "no",
         "eq", "HostbasedAuthentication no 설정"),
        ("5.2.9", "SSH PermitRootLogin no", r"^PermitRootLogin\s+(\w+)", "no",
         "eq", "PermitRootLogin no 설정"),
        ("5.2.11", "SSH PermitEmptyPasswords no", r"^PermitEmptyPasswords\s+(\w+)", "no",
         "eq", "PermitEmptyPasswords no 설정"),
        ("5.2.14", "SSH LoginGraceTime ≤ 60", r"^LoginGraceTime\s+(\d+)", "60",
         "le", "LoginGraceTime 60 설정"),
    ]

    results = []
    for cis_id, title, pattern, expected, op, remediation in checks:
        current = "not set"
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("#"):
                m = re.match(pattern, line, re.IGNORECASE)
                if m:
                    current = m.group(1)
                    break

        if op == "eq":
            passed = current.lower() == expected.lower()
        elif op == "le":
            try:
                passed = int(current) <= int(expected)
            except ValueError:
                passed = False
        else:
            passed = current == expected

        results.append(CheckResult(
            check_id=cis_id, title=title, level=1,
            passed=passed,
            current_value=current,
            expected_value=expected,
            remediation=remediation,
        ))
    return results


def check_6_1_file_permissions() -> list[CheckResult]:
    """CIS 6.1 - 중요 파일 권한 확인."""
    file_checks = [
        ("/etc/passwd", "644", "6.1.2"),
        ("/etc/shadow", "640", "6.1.3"),
        ("/etc/group", "644", "6.1.4"),
        ("/etc/gshadow", "640", "6.1.5"),
        ("/etc/passwd-", "600", "6.1.6"),
        ("/etc/shadow-", "600", "6.1.7"),
    ]

    results = []
    for filepath, expected_perm, cis_id in file_checks:
        p = Path(filepath)
        if not p.exists():
            continue
        mode = oct(p.stat().st_mode)[-3:]
        # 실제 권한이 기대 권한보다 제한적이면 통과
        passed = int(mode, 8) <= int(expected_perm, 8)
        results.append(CheckResult(
            check_id=cis_id, title=f"{filepath} 권한 {expected_perm} 이하", level=1,
            passed=passed,
            current_value=mode,
            expected_value=f"≤ {expected_perm}",
            remediation=f"chmod {expected_perm} {filepath}",
        ))
    return results


def run_full_audit() -> list[CheckResult]:
    """전체 CIS 감사 실행."""
    all_results: list[CheckResult] = []
    all_results.append(check_1_1_filesystem_tmp_partition())
    all_results.append(check_1_5_bootloader_password())
    all_results.extend(check_2_2_services())
    all_results.append(check_3_1_packet_redirect())
    all_results.extend(check_5_2_ssh_config())
    all_results.extend(check_6_1_file_permissions())
    return all_results


def print_report(results: list[CheckResult]) -> None:
    """감사 결과 출력."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print(f"\n{'='*65}")
    print(f"  CIS Linux Benchmark 감사 결과")
    print(f"  통과: {passed}/{len(results)} | 실패: {failed}/{len(results)}")
    print(f"{'='*65}\n")

    for r in sorted(results, key=lambda x: (x.passed, x.check_id)):
        status = "✓ PASS" if r.passed else "✗ FAIL"
        print(f"  [{status}] CIS {r.check_id} — {r.title}")
        if not r.passed:
            print(f"           현재값: {r.current_value}")
            print(f"           권장값: {r.expected_value}")
            print(f"           조치:   {r.remediation}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CIS Linux Benchmark 자동 감사")
    parser.add_argument("--json", action="store_true", help="JSON 출력")
    args = parser.parse_args()

    results = run_full_audit()

    if args.json:
        import json
        from dataclasses import asdict
        print(json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2))
    else:
        print_report(results)
```

---

## 2. Ansible 보안 강화 플레이북

```yaml
# linux_hardening.yml
# 사용법: ansible-playbook -i inventory.ini linux_hardening.yml
# 참고: https://docs.ansible.com/

---
- name: CIS Level 1 Linux 보안 강화
  hosts: all
  become: true
  vars:
    ssh_port: 22
    allowed_ssh_users: []  # 허용할 SSH 사용자 목록

  tasks:
    # ─── 1. 시스템 업데이트 ───────────────────────────────
    - name: 시스템 패키지 최신 업데이트
      ansible.builtin.apt:
        update_cache: true
        upgrade: safe
        cache_valid_time: 3600
      when: ansible_os_family == "Debian"

    # ─── 2. 불필요한 서비스 비활성화 ──────────────────────
    - name: 불필요한 서비스 중지 및 비활성화
      ansible.builtin.systemd:
        name: "{{ item }}"
        state: stopped
        enabled: false
      loop:
        - avahi-daemon
        - cups
        - isc-dhcp-server
        - xinetd
        - telnet
        - vsftpd
      ignore_errors: true

    # ─── 3. SSH 보안 강화 ──────────────────────────────────
    - name: SSH 설정 보안 강화
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
        backup: true
      loop:
        - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^#?PermitEmptyPasswords', line: 'PermitEmptyPasswords no' }
        - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
        - { regexp: '^#?LoginGraceTime', line: 'LoginGraceTime 60' }
        - { regexp: '^#?X11Forwarding', line: 'X11Forwarding no' }
        - { regexp: '^#?ClientAliveInterval', line: 'ClientAliveInterval 300' }
        - { regexp: '^#?ClientAliveCountMax', line: 'ClientAliveCountMax 2' }
      notify: Restart SSH

    # ─── 4. 커널 보안 파라미터 설정 ───────────────────────
    - name: sysctl 보안 파라미터 설정
      ansible.posix.sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        sysctl_file: /etc/sysctl.d/99-cis-hardening.conf
        reload: true
      loop:
        - { name: 'net.ipv4.ip_forward', value: '0' }
        - { name: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.send_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { name: 'net.ipv4.tcp_syncookies', value: '1' }
        - { name: 'kernel.randomize_va_space', value: '2' }
        - { name: 'fs.suid_dumpable', value: '0' }
        - { name: 'kernel.core_uses_pid', value: '1' }

    # ─── 5. 패스워드 정책 ──────────────────────────────────
    - name: PAM 패스워드 정책 설정 (pwquality)
      ansible.builtin.lineinfile:
        path: /etc/security/pwquality.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        create: true
      loop:
        - { regexp: '^minlen', line: 'minlen = 14' }
        - { regexp: '^dcredit', line: 'dcredit = -1' }
        - { regexp: '^ucredit', line: 'ucredit = -1' }
        - { regexp: '^ocredit', line: 'ocredit = -1' }
        - { regexp: '^lcredit', line: 'lcredit = -1' }

    # ─── 6. 파일 권한 ──────────────────────────────────────
    - name: 중요 파일 권한 설정
      ansible.builtin.file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
        owner: root
        group: root
      loop:
        - { path: '/etc/passwd', mode: '0644' }
        - { path: '/etc/shadow', mode: '0640' }
        - { path: '/etc/group', mode: '0644' }
        - { path: '/etc/gshadow', mode: '0640' }
        - { path: '/etc/crontab', mode: '0600' }
        - { path: '/boot/grub/grub.cfg', mode: '0400' }

    # ─── 7. 감사 로깅 (auditd) ────────────────────────────
    - name: auditd 설치 및 활성화
      ansible.builtin.apt:
        name: auditd
        state: present
      when: ansible_os_family == "Debian"

    - name: auditd 규칙 설정
      ansible.builtin.copy:
        dest: /etc/audit/rules.d/99-cis.rules
        content: |
          # 중요 파일 변경 감사
          -w /etc/passwd -p wa -k identity
          -w /etc/shadow -p wa -k identity
          -w /etc/sudoers -p wa -k sudoers
          -w /var/log/sudo.log -p wa -k sudoers
          # 권한 상승 감사
          -a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=4294967295 -k setuid
          # 로그인/로그아웃 감사
          -w /var/log/lastlog -p wa -k logins
          -w /var/run/faillock -p wa -k logins
        owner: root
        group: root
        mode: '0640'
      notify: Restart auditd

  handlers:
    - name: Restart SSH
      ansible.builtin.systemd:
        name: ssh
        state: restarted

    - name: Restart auditd
      ansible.builtin.systemd:
        name: auditd
        state: restarted
        enabled: true
```

---

## 3. OpenSCAP 자동화 스캔

```bash
# OpenSCAP 설치
sudo apt-get install -y openscap-scanner scap-security-guide

# CIS Ubuntu 22.04 Level 1 스캔
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --results /tmp/scap_results.xml \
    --report /tmp/scap_report.html \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# 보고서 열기
firefox /tmp/scap_report.html
```

```python
#!/usr/bin/env python3
"""
OpenSCAP XML 결과 파싱 및 실패 항목 추출.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_scap_results(results_xml: str) -> list[dict]:
    """XCCDF 결과 XML 파싱 → 실패 항목 목록 반환."""
    tree = ET.parse(results_xml)
    root = tree.getroot()

    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    }

    failures = []
    for rule_result in root.iter("{http://checklists.nist.gov/xccdf/1.2}rule-result"):
        result_text = rule_result.findtext(
            "{http://checklists.nist.gov/xccdf/1.2}result", default=""
        )
        if result_text in ("fail", "error"):
            rule_id = rule_result.get("idref", "")
            failures.append({
                "rule_id": rule_id,
                "result": result_text,
            })

    return failures


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("사용법: python3 parse_scap.py results.xml")
        sys.exit(1)
    results = parse_scap_results(sys.argv[1])
    print(f"실패 항목: {len(results)}개")
    for r in results[:20]:
        print(f"  [{r['result'].upper()}] {r['rule_id']}")
```

---

## 4. 참고 자료

- **CIS 벤치마크 다운로드**: https://www.cisecurity.org/cis-benchmarks/
- **OpenSCAP / SCAP Security Guide**: https://www.open-scap.org/
- **Ansible 보안 강화 역할**: https://galaxy.ansible.com/devsec/hardening

---

<a name="english"></a>

# Linux Hardening Automation — CIS Benchmarks, Ansible Playbooks, Audit Scripts

## Overview

A default Linux installation is not secure. Hardening systematically addresses misconfigurations using frameworks like the CIS Benchmarks.

## Automation Tools Comparison

| Tool | Type | Best For |
|------|------|---------|
| Ansible | Remediation | Multi-server bulk hardening |
| OpenSCAP | Audit + Fix | CIS/STIG compliance scanning |
| Lynis | Audit | Local server assessment |
| Chef InSpec | Policy-as-code | Continuous compliance testing |

## Quick Start

```bash
# Local audit with Python script
sudo python3 cis_audit.py

# Ansible hardening (edit inventory.ini first)
ansible-playbook -i inventory.ini linux_hardening.yml --check  # dry run
ansible-playbook -i inventory.ini linux_hardening.yml           # apply

# OpenSCAP CIS Level 1 scan
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --report /tmp/report.html \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

## Critical CIS Controls (Level 1)

1. Disable unused services (avahi, cups, telnet, FTP)
2. Harden SSH (no root login, key auth only, MaxAuthTries 3)
3. Set kernel security parameters (ASLR, SYN cookies, no IP forwarding)
4. Enforce strong password policy (minlen=14, complexity requirements)
5. Set restrictive file permissions (/etc/shadow 640, /etc/crontab 600)
6. Enable auditd with identity and privilege escalation rules

## References

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- OpenSCAP: https://www.open-scap.org/
- Ansible hardening role: https://galaxy.ansible.com/devsec/hardening
