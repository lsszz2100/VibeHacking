> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# Linux 보안 감사

Lynis, OpenSCAP, CIS 벤치마크를 활용한 체계적인 Linux 보안 감사 방법과 Python 기반 자동화 도구를 다룬다. 감사 결과를 구조화된 보고서로 생성하고 지속적인 컴플라이언스 모니터링을 구축하는 방법을 정리한다.

---

## 1. Lynis 자동화 감사

### 1.1 Lynis 설치 및 실행

```bash
# 패키지 설치
apt-get install -y lynis

# 전체 시스템 감사
lynis audit system --quick --no-colors 2>/dev/null | tee lynis_report.txt

# 특정 카테고리만 감사
lynis audit system --tests-from-group authentication,networking,storage

# 상세 출력 (JSON 형식)
lynis audit system --output-file /tmp/lynis.json --quiet

# CI/CD 통합용 (비대화형)
lynis audit system --non-interactive --quiet --logfile /tmp/lynis.log
```

### 1.2 Lynis 결과 파싱 및 보고서 생성

```python
#!/usr/bin/env python3
"""Lynis 감사 결과 파싱 및 HTML 보고서 생성"""
import argparse
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LynisResult:
    score: int = 0
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    tests_performed: int = 0
    hardening_index: int = 0
    hostname: str = ""


def run_lynis() -> str:
    result = subprocess.run(
        ["lynis", "audit", "system", "--non-interactive", "--quiet", "--no-colors"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    return result.stdout + result.stderr


def parse_lynis_output(output: str) -> LynisResult:
    result = LynisResult()

    score_match = re.search(r"Hardening index\s+:\s+(\d+)", output)
    if score_match:
        result.hardening_index = int(score_match.group(1))

    tests_match = re.search(r"Tests performed\s+:\s+(\d+)", output)
    if tests_match:
        result.tests_performed = int(tests_match.group(1))

    hostname_match = re.search(r"Hostname\s+:\s+(\S+)", output)
    if hostname_match:
        result.hostname = hostname_match.group(1)

    # 경고 추출
    in_warnings = False
    for line in output.splitlines():
        if "Warnings" in line and "=" in line:
            in_warnings = True
        elif in_warnings and line.startswith("  !"):
            result.warnings.append(line.strip()[2:].strip())
        elif "Suggestions" in line and "=" in line:
            in_warnings = False
            in_suggestions = True
        elif line.startswith("  *"):
            result.suggestions.append(line.strip()[2:].strip())

    return result


def generate_html_report(result: LynisResult, output_path: Path) -> None:
    score_color = "green" if result.hardening_index >= 70 else "orange" if result.hardening_index >= 50 else "red"
    warnings_html = "\n".join(f"<li class='warning'>{w}</li>" for w in result.warnings)
    suggestions_html = "\n".join(f"<li>{s}</li>" for s in result.suggestions[:20])

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Lynis 보안 감사 보고서</title>
<style>
body {{ font-family: monospace; margin: 40px; }}
.score {{ font-size: 48px; color: {score_color}; font-weight: bold; }}
.warning {{ color: #cc0000; }}
li {{ margin: 5px 0; }}
</style>
</head>
<body>
<h1>Linux 보안 감사 보고서</h1>
<p>호스트: {result.hostname} | 감사일시: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p>수행된 테스트: {result.tests_performed}개</p>
<div class="score">보안 점수: {result.hardening_index}/100</div>
<h2>경고 ({len(result.warnings)}건)</h2>
<ul>{warnings_html}</ul>
<h2>제안사항 ({len(result.suggestions)}건, 상위 20개)</h2>
<ul>{suggestions_html}</ul>
</body>
</html>"""

    output_path.write_text(html)
    print(f"[+] HTML 보고서: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lynis 자동화 감사")
    parser.add_argument("-o", "--output", default="lynis_report.html")
    parser.add_argument("--input", help="기존 lynis 출력 파일 (없으면 직접 실행)")
    args = parser.parse_args()

    if args.input:
        output = Path(args.input).read_text()
    else:
        print("[*] Lynis 실행 중 (수 분 소요)...")
        output = run_lynis()

    result = parse_lynis_output(output)
    print(f"[+] 보안 점수: {result.hardening_index}/100")
    print(f"[+] 경고: {len(result.warnings)}건, 제안: {len(result.suggestions)}건")

    generate_html_report(result, Path(args.output))


if __name__ == "__main__":
    main()
```

---

## 2. CIS 벤치마크 자동 점검

### 2.1 CIS Level 1 핵심 항목 체크

```python
#!/usr/bin/env python3
"""CIS Ubuntu Linux 벤치마크 자동 점검"""
import argparse
import grp
import os
import pwd
import re
import stat
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NA = "N/A"


@dataclass
class CheckResult:
    cis_id: str
    title: str
    status: Status
    detail: str = ""


def run_cmd(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return ""


def check_filesystem_mounting() -> list[CheckResult]:
    results = []

    unused_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"]
    for fs in unused_fs:
        output = run_cmd(f"modprobe -n -v {fs} 2>&1")
        blacklisted = run_cmd(f"grep -r {fs} /etc/modprobe.d/ 2>/dev/null")
        if "install /bin/true" in output or blacklisted:
            results.append(CheckResult("1.1.x", f"{fs} 마운트 비활성화", Status.PASS))
        else:
            results.append(CheckResult("1.1.x", f"{fs} 마운트 비활성화", Status.FAIL,
                                       f"{fs}가 활성화될 수 있음"))

    return results


def check_filesystem_partitions() -> list[CheckResult]:
    results = []
    mounts = Path("/proc/mounts").read_text()
    fstab = Path("/etc/fstab").read_text() if Path("/etc/fstab").exists() else ""

    critical_mounts = {
        "/tmp": "nodev,nosuid,noexec",
        "/var/tmp": "nodev,nosuid,noexec",
        "/dev/shm": "nodev,nosuid,noexec",
        "/home": "nodev",
    }

    for mount_point, required_opts in critical_mounts.items():
        if mount_point in mounts:
            for opt in required_opts.split(","):
                if opt in mounts:
                    results.append(CheckResult("1.1.x", f"{mount_point} {opt} 옵션", Status.PASS))
                else:
                    results.append(CheckResult("1.1.x", f"{mount_point} {opt} 옵션", Status.FAIL,
                                               f"{opt} 옵션 누락"))

    return results


def check_software_updates() -> list[CheckResult]:
    results = []

    pkg_mgr = run_cmd("which apt-get || which yum || which dnf")
    if "apt" in pkg_mgr:
        updates = run_cmd("apt-get -s upgrade 2>/dev/null | grep '^[0-9]'")
        if "0 upgraded" in updates:
            results.append(CheckResult("1.9", "최신 패키지 업데이트", Status.PASS))
        else:
            results.append(CheckResult("1.9", "최신 패키지 업데이트", Status.FAIL, updates))

    return results


def check_network_parameters() -> list[CheckResult]:
    results = []
    kernel_params = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.tcp_syncookies": "1",
    }

    for param, expected in kernel_params.items():
        actual = run_cmd(f"sysctl -n {param}")
        if actual == expected:
            results.append(CheckResult("3.x", f"{param} = {expected}", Status.PASS))
        else:
            results.append(CheckResult("3.x", f"{param}", Status.FAIL,
                                       f"현재값: {actual}, 권장값: {expected}"))

    return results


def check_ssh_configuration() -> list[CheckResult]:
    results = []
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return [CheckResult("5.2", "SSH 설정", Status.NA, "sshd_config 없음")]

    config_text = sshd_config.read_text()

    checks = {
        r"^Protocol\s+2": ("5.2.1", "SSH Protocol 2 사용"),
        r"^LogLevel\s+(INFO|VERBOSE)": ("5.2.2", "SSH LogLevel"),
        r"^X11Forwarding\s+no": ("5.2.4", "X11 포워딩 비활성화"),
        r"^MaxAuthTries\s+[1-4]$": ("5.2.5", "MaxAuthTries ≤ 4"),
        r"^IgnoreRhosts\s+yes": ("5.2.6", "Rhosts 무시"),
        r"^HostbasedAuthentication\s+no": ("5.2.7", "호스트 기반 인증 비활성화"),
        r"^PermitRootLogin\s+no": ("5.2.8", "Root 로그인 금지"),
        r"^PermitEmptyPasswords\s+no": ("5.2.9", "빈 패스워드 금지"),
        r"^PermitUserEnvironment\s+no": ("5.2.10", "사용자 환경 변수 비활성화"),
        r"^ClientAliveInterval\s+[1-9]\d*": ("5.2.12", "SSH 타임아웃 설정"),
        r"^LoginGraceTime\s+[1-6][0-9]$": ("5.2.14", "로그인 유예 시간"),
    }

    for pattern, (cis_id, title) in checks.items():
        if re.search(pattern, config_text, re.MULTILINE):
            results.append(CheckResult(cis_id, title, Status.PASS))
        else:
            results.append(CheckResult(cis_id, title, Status.FAIL, f"설정 누락 또는 부적절"))

    return results


def check_password_policy() -> list[CheckResult]:
    results = []
    pwquality = Path("/etc/security/pwquality.conf")
    login_defs = Path("/etc/login.defs")

    if pwquality.exists():
        text = pwquality.read_text()
        if re.search(r"minlen\s*=\s*1[4-9]|[2-9]\d", text):
            results.append(CheckResult("5.4.1", "패스워드 최소 길이 14+", Status.PASS))
        else:
            results.append(CheckResult("5.4.1", "패스워드 최소 길이", Status.FAIL, "14자 미만"))

    if login_defs.exists():
        text = login_defs.read_text()
        if re.search(r"PASS_MAX_DAYS\s+([1-9][0-9]|[1-8][0-9]{2})$", text, re.MULTILINE):
            results.append(CheckResult("5.4.1.1", "패스워드 최대 유효기간", Status.PASS))
        else:
            results.append(CheckResult("5.4.1.1", "패스워드 최대 유효기간", Status.FAIL))

    return results


def print_summary(all_results: list[CheckResult]) -> None:
    passed = sum(1 for r in all_results if r.status == Status.PASS)
    failed = sum(1 for r in all_results if r.status == Status.FAIL)
    total = len(all_results)

    print(f"\n{'='*60}")
    print(f"CIS 벤치마크 감사 결과: {passed}/{total} 통과 ({passed/total*100:.1f}%)")
    print(f"{'='*60}")
    print(f"\n[실패 항목 ({failed}건)]")
    for r in all_results:
        if r.status == Status.FAIL:
            print(f"  [{r.cis_id}] {r.title}: {r.detail}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CIS 벤치마크 자동 점검")
    parser.add_argument("--category", choices=["all", "network", "ssh", "password", "filesystem"],
                        default="all")
    args = parser.parse_args()

    results = []
    if args.category in ("all", "filesystem"):
        results.extend(check_filesystem_mounting())
        results.extend(check_filesystem_partitions())
    if args.category in ("all", "network"):
        results.extend(check_network_parameters())
    if args.category in ("all", "ssh"):
        results.extend(check_ssh_configuration())
    if args.category in ("all", "password"):
        results.extend(check_password_policy())
        results.extend(check_software_updates())

    print_summary(results)


if __name__ == "__main__":
    main()
```

---

## 3. OpenSCAP 자동화

```bash
# OpenSCAP 설치 (Ubuntu)
apt-get install -y openscap-scanner ssg-base ssg-debderived

# CIS Level 1 프로파일로 스캔
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --report openscap_report.html \
  --results openscap_results.xml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# 결과에서 실패 항목만 추출
oscap xccdf generate guide \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# 자동 수정 (Ansible 플레이북 생성)
oscap xccdf generate fix \
  --fix-type ansible \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --output cis_remediation.yml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

```python
#!/usr/bin/env python3
"""OpenSCAP XML 결과 파싱"""
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_oscap_results(xml_path: Path) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

    results = {"pass": [], "fail": [], "error": [], "notchecked": []}

    for rule_result in root.findall(".//xccdf:rule-result", ns):
        rule_id = rule_result.get("idref", "")
        result_elem = rule_result.find("xccdf:result", ns)
        result_text = result_elem.text if result_elem is not None else "unknown"
        severity = rule_result.get("severity", "unknown")

        entry = {"id": rule_id, "severity": severity}
        if result_text in results:
            results[result_text].append(entry)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenSCAP 결과 분석")
    parser.add_argument("xml_file", help="OpenSCAP XML 결과 파일")
    args = parser.parse_args()

    results = parse_oscap_results(Path(args.xml_file))
    total = sum(len(v) for v in results.values())
    passed = len(results["pass"])

    print(f"[+] 전체: {total}개 | 통과: {passed}개 | 실패: {len(results['fail'])}개")
    print(f"\n[실패 항목 (상위 20개)]")
    for item in results["fail"][:20]:
        print(f"  [{item['severity'].upper()}] {item['id']}")


if __name__ == "__main__":
    main()
```

---

## 4. 핵심 보안 항목 수동 점검

```bash
# 1. SetUID/SetGID 파일 탐색
find / -perm /4000 -o -perm /2000 2>/dev/null | sort

# 2. 쓰기 가능한 전역 파일
find / -perm -002 -type f 2>/dev/null | grep -v /proc | grep -v /sys

# 3. 소유자 없는 파일
find / -nouser -o -nogroup 2>/dev/null | head -20

# 4. 크론 작업 검토
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null

# 5. 네트워크 연결 상태
ss -tlnp | grep -v 127.0.0.1

# 6. 활성 서비스
systemctl list-units --type=service --state=active | grep -v systemd

# 7. 열린 포트와 프로세스 매핑
ss -tlnp

# 8. 최근 로그인 기록
last -20
lastb -20   # 실패한 로그인

# 9. sudo 권한 검토
cat /etc/sudoers
find /etc/sudoers.d/ -type f -exec cat {} \;

# 10. 비어있지 않은 패스워드 없는 계정
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
```

---

## 5. 지속적 컴플라이언스 모니터링

### 5.1 감사 스케줄링 (cron)

```bash
# /etc/cron.d/security-audit
# 매일 새벽 2시 자동 감사
0 2 * * * root /usr/local/bin/security_audit.sh >> /var/log/security_audit.log 2>&1

# /usr/local/bin/security_audit.sh
#!/bin/bash
DATE=$(date +%Y%m%d)
lynis audit system --non-interactive --quiet --logfile /var/log/lynis_${DATE}.log
python3 /usr/local/bin/cis_benchmark.py --category all > /var/log/cis_${DATE}.txt
```

### 5.2 변경 탐지 (AIDE)

```bash
# AIDE 설치 및 초기화
apt-get install -y aide
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 주기적 무결성 검사
aide --check 2>&1 | grep -E "^(Changed|Added|Removed)"
```

| 도구 | 역할 | 자동화 방법 |
|------|------|-----------|
| Lynis | 종합 보안 감사 | 일별 cron + 보고서 생성 |
| OpenSCAP | CIS/STIG 컴플라이언스 | 주별 스캔 + HTML 보고서 |
| AIDE | 파일 무결성 감사 | 일별 검사 + 알림 |
| CIS 스크립트 | 특정 항목 세부 점검 | 이벤트 기반 실행 |

---

<a name="english"></a>

# Linux Security Auditing

Covers systematic Linux security auditing using Lynis, OpenSCAP, and CIS benchmarks, along with Python-based automation tools. Explains how to generate structured audit reports and build continuous compliance monitoring.

---

## 1. Lynis Automated Auditing

### 1.1 Installing and Running Lynis

```bash
# Install package
apt-get install -y lynis

# Full system audit
lynis audit system --quick --no-colors 2>/dev/null | tee lynis_report.txt

# Audit specific categories only
lynis audit system --tests-from-group authentication,networking,storage

# Detailed output (JSON format)
lynis audit system --output-file /tmp/lynis.json --quiet

# For CI/CD integration (non-interactive)
lynis audit system --non-interactive --quiet --logfile /tmp/lynis.log
```

### 1.2 Parsing Lynis Results and Generating Reports

```python
#!/usr/bin/env python3
"""Parse Lynis audit results and generate HTML report"""
import argparse
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LynisResult:
    score: int = 0
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    tests_performed: int = 0
    hardening_index: int = 0
    hostname: str = ""


def run_lynis() -> str:
    result = subprocess.run(
        ["lynis", "audit", "system", "--non-interactive", "--quiet", "--no-colors"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    return result.stdout + result.stderr


def parse_lynis_output(output: str) -> LynisResult:
    result = LynisResult()

    score_match = re.search(r"Hardening index\s+:\s+(\d+)", output)
    if score_match:
        result.hardening_index = int(score_match.group(1))

    tests_match = re.search(r"Tests performed\s+:\s+(\d+)", output)
    if tests_match:
        result.tests_performed = int(tests_match.group(1))

    hostname_match = re.search(r"Hostname\s+:\s+(\S+)", output)
    if hostname_match:
        result.hostname = hostname_match.group(1)

    # Extract warnings
    in_warnings = False
    for line in output.splitlines():
        if "Warnings" in line and "=" in line:
            in_warnings = True
        elif in_warnings and line.startswith("  !"):
            result.warnings.append(line.strip()[2:].strip())
        elif "Suggestions" in line and "=" in line:
            in_warnings = False
            in_suggestions = True
        elif line.startswith("  *"):
            result.suggestions.append(line.strip()[2:].strip())

    return result


def generate_html_report(result: LynisResult, output_path: Path) -> None:
    score_color = "green" if result.hardening_index >= 70 else "orange" if result.hardening_index >= 50 else "red"
    warnings_html = "\n".join(f"<li class='warning'>{w}</li>" for w in result.warnings)
    suggestions_html = "\n".join(f"<li>{s}</li>" for s in result.suggestions[:20])

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Lynis Security Audit Report</title>
<style>
body {{ font-family: monospace; margin: 40px; }}
.score {{ font-size: 48px; color: {score_color}; font-weight: bold; }}
.warning {{ color: #cc0000; }}
li {{ margin: 5px 0; }}
</style>
</head>
<body>
<h1>Linux Security Audit Report</h1>
<p>Host: {result.hostname} | Audit date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p>Tests performed: {result.tests_performed}</p>
<div class="score">Security Score: {result.hardening_index}/100</div>
<h2>Warnings ({len(result.warnings)})</h2>
<ul>{warnings_html}</ul>
<h2>Suggestions ({len(result.suggestions)}, top 20)</h2>
<ul>{suggestions_html}</ul>
</body>
</html>"""

    output_path.write_text(html)
    print(f"[+] HTML report: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lynis Automated Audit")
    parser.add_argument("-o", "--output", default="lynis_report.html")
    parser.add_argument("--input", help="Existing lynis output file (run directly if not specified)")
    args = parser.parse_args()

    if args.input:
        output = Path(args.input).read_text()
    else:
        print("[*] Running Lynis (may take several minutes)...")
        output = run_lynis()

    result = parse_lynis_output(output)
    print(f"[+] Security score: {result.hardening_index}/100")
    print(f"[+] Warnings: {len(result.warnings)}, Suggestions: {len(result.suggestions)}")

    generate_html_report(result, Path(args.output))


if __name__ == "__main__":
    main()
```

---

## 2. CIS Benchmark Automated Checking

### 2.1 CIS Level 1 Core Item Check

```python
#!/usr/bin/env python3
"""Automated CIS Ubuntu Linux benchmark checking"""
import argparse
import grp
import os
import pwd
import re
import stat
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NA = "N/A"


@dataclass
class CheckResult:
    cis_id: str
    title: str
    status: Status
    detail: str = ""


def run_cmd(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return ""


def check_filesystem_mounting() -> list[CheckResult]:
    results = []

    unused_fs = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"]
    for fs in unused_fs:
        output = run_cmd(f"modprobe -n -v {fs} 2>&1")
        blacklisted = run_cmd(f"grep -r {fs} /etc/modprobe.d/ 2>/dev/null")
        if "install /bin/true" in output or blacklisted:
            results.append(CheckResult("1.1.x", f"{fs} mounting disabled", Status.PASS))
        else:
            results.append(CheckResult("1.1.x", f"{fs} mounting disabled", Status.FAIL,
                                       f"{fs} may be loadable"))

    return results


def check_filesystem_partitions() -> list[CheckResult]:
    results = []
    mounts = Path("/proc/mounts").read_text()
    fstab = Path("/etc/fstab").read_text() if Path("/etc/fstab").exists() else ""

    critical_mounts = {
        "/tmp": "nodev,nosuid,noexec",
        "/var/tmp": "nodev,nosuid,noexec",
        "/dev/shm": "nodev,nosuid,noexec",
        "/home": "nodev",
    }

    for mount_point, required_opts in critical_mounts.items():
        if mount_point in mounts:
            for opt in required_opts.split(","):
                if opt in mounts:
                    results.append(CheckResult("1.1.x", f"{mount_point} {opt} option", Status.PASS))
                else:
                    results.append(CheckResult("1.1.x", f"{mount_point} {opt} option", Status.FAIL,
                                               f"{opt} option missing"))

    return results


def check_software_updates() -> list[CheckResult]:
    results = []

    pkg_mgr = run_cmd("which apt-get || which yum || which dnf")
    if "apt" in pkg_mgr:
        updates = run_cmd("apt-get -s upgrade 2>/dev/null | grep '^[0-9]'")
        if "0 upgraded" in updates:
            results.append(CheckResult("1.9", "Latest packages installed", Status.PASS))
        else:
            results.append(CheckResult("1.9", "Latest packages installed", Status.FAIL, updates))

    return results


def check_network_parameters() -> list[CheckResult]:
    results = []
    kernel_params = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.tcp_syncookies": "1",
    }

    for param, expected in kernel_params.items():
        actual = run_cmd(f"sysctl -n {param}")
        if actual == expected:
            results.append(CheckResult("3.x", f"{param} = {expected}", Status.PASS))
        else:
            results.append(CheckResult("3.x", f"{param}", Status.FAIL,
                                       f"Current: {actual}, Recommended: {expected}"))

    return results


def check_ssh_configuration() -> list[CheckResult]:
    results = []
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return [CheckResult("5.2", "SSH Configuration", Status.NA, "sshd_config not found")]

    config_text = sshd_config.read_text()

    checks = {
        r"^Protocol\s+2": ("5.2.1", "SSH Protocol 2 in use"),
        r"^LogLevel\s+(INFO|VERBOSE)": ("5.2.2", "SSH LogLevel"),
        r"^X11Forwarding\s+no": ("5.2.4", "X11 forwarding disabled"),
        r"^MaxAuthTries\s+[1-4]$": ("5.2.5", "MaxAuthTries <= 4"),
        r"^IgnoreRhosts\s+yes": ("5.2.6", "Rhosts ignored"),
        r"^HostbasedAuthentication\s+no": ("5.2.7", "Host-based authentication disabled"),
        r"^PermitRootLogin\s+no": ("5.2.8", "Root login prohibited"),
        r"^PermitEmptyPasswords\s+no": ("5.2.9", "Empty passwords prohibited"),
        r"^PermitUserEnvironment\s+no": ("5.2.10", "User environment variables disabled"),
        r"^ClientAliveInterval\s+[1-9]\d*": ("5.2.12", "SSH timeout configured"),
        r"^LoginGraceTime\s+[1-6][0-9]$": ("5.2.14", "Login grace time configured"),
    }

    for pattern, (cis_id, title) in checks.items():
        if re.search(pattern, config_text, re.MULTILINE):
            results.append(CheckResult(cis_id, title, Status.PASS))
        else:
            results.append(CheckResult(cis_id, title, Status.FAIL, "Setting missing or incorrect"))

    return results


def check_password_policy() -> list[CheckResult]:
    results = []
    pwquality = Path("/etc/security/pwquality.conf")
    login_defs = Path("/etc/login.defs")

    if pwquality.exists():
        text = pwquality.read_text()
        if re.search(r"minlen\s*=\s*1[4-9]|[2-9]\d", text):
            results.append(CheckResult("5.4.1", "Password minimum length 14+", Status.PASS))
        else:
            results.append(CheckResult("5.4.1", "Password minimum length", Status.FAIL, "Less than 14 characters"))

    if login_defs.exists():
        text = login_defs.read_text()
        if re.search(r"PASS_MAX_DAYS\s+([1-9][0-9]|[1-8][0-9]{2})$", text, re.MULTILINE):
            results.append(CheckResult("5.4.1.1", "Password maximum validity", Status.PASS))
        else:
            results.append(CheckResult("5.4.1.1", "Password maximum validity", Status.FAIL))

    return results


def print_summary(all_results: list[CheckResult]) -> None:
    passed = sum(1 for r in all_results if r.status == Status.PASS)
    failed = sum(1 for r in all_results if r.status == Status.FAIL)
    total = len(all_results)

    print(f"\n{'='*60}")
    print(f"CIS Benchmark Audit Results: {passed}/{total} passed ({passed/total*100:.1f}%)")
    print(f"{'='*60}")
    print(f"\n[Failed Items ({failed})]")
    for r in all_results:
        if r.status == Status.FAIL:
            print(f"  [{r.cis_id}] {r.title}: {r.detail}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CIS Benchmark Automated Check")
    parser.add_argument("--category", choices=["all", "network", "ssh", "password", "filesystem"],
                        default="all")
    args = parser.parse_args()

    results = []
    if args.category in ("all", "filesystem"):
        results.extend(check_filesystem_mounting())
        results.extend(check_filesystem_partitions())
    if args.category in ("all", "network"):
        results.extend(check_network_parameters())
    if args.category in ("all", "ssh"):
        results.extend(check_ssh_configuration())
    if args.category in ("all", "password"):
        results.extend(check_password_policy())
        results.extend(check_software_updates())

    print_summary(results)


if __name__ == "__main__":
    main()
```

---

## 3. OpenSCAP Automation

```bash
# Install OpenSCAP (Ubuntu)
apt-get install -y openscap-scanner ssg-base ssg-debderived

# Scan with CIS Level 1 profile
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --report openscap_report.html \
  --results openscap_results.xml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Extract only failed items from results
oscap xccdf generate guide \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Auto-remediation (generate Ansible playbook)
oscap xccdf generate fix \
  --fix-type ansible \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --output cis_remediation.yml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

```python
#!/usr/bin/env python3
"""Parse OpenSCAP XML results"""
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_oscap_results(xml_path: Path) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

    results = {"pass": [], "fail": [], "error": [], "notchecked": []}

    for rule_result in root.findall(".//xccdf:rule-result", ns):
        rule_id = rule_result.get("idref", "")
        result_elem = rule_result.find("xccdf:result", ns)
        result_text = result_elem.text if result_elem is not None else "unknown"
        severity = rule_result.get("severity", "unknown")

        entry = {"id": rule_id, "severity": severity}
        if result_text in results:
            results[result_text].append(entry)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze OpenSCAP Results")
    parser.add_argument("xml_file", help="OpenSCAP XML result file")
    args = parser.parse_args()

    results = parse_oscap_results(Path(args.xml_file))
    total = sum(len(v) for v in results.values())
    passed = len(results["pass"])

    print(f"[+] Total: {total} | Passed: {passed} | Failed: {len(results['fail'])}")
    print(f"\n[Failed Items (top 20)]")
    for item in results["fail"][:20]:
        print(f"  [{item['severity'].upper()}] {item['id']}")


if __name__ == "__main__":
    main()
```

---

## 4. Core Security Item Manual Inspection

```bash
# 1. Find SetUID/SetGID files
find / -perm /4000 -o -perm /2000 2>/dev/null | sort

# 2. World-writable files
find / -perm -002 -type f 2>/dev/null | grep -v /proc | grep -v /sys

# 3. Files without owner
find / -nouser -o -nogroup 2>/dev/null | head -20

# 4. Review cron jobs
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null

# 5. Network connection status
ss -tlnp | grep -v 127.0.0.1

# 6. Active services
systemctl list-units --type=service --state=active | grep -v systemd

# 7. Open ports and process mapping
ss -tlnp

# 8. Recent login records
last -20
lastb -20   # Failed logins

# 9. Review sudo privileges
cat /etc/sudoers
find /etc/sudoers.d/ -type f -exec cat {} \;

# 10. Accounts with no password (not empty)
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow
```

---

## 5. Continuous Compliance Monitoring

### 5.1 Audit Scheduling (cron)

```bash
# /etc/cron.d/security-audit
# Automated daily audit at 2 AM
0 2 * * * root /usr/local/bin/security_audit.sh >> /var/log/security_audit.log 2>&1

# /usr/local/bin/security_audit.sh
#!/bin/bash
DATE=$(date +%Y%m%d)
lynis audit system --non-interactive --quiet --logfile /var/log/lynis_${DATE}.log
python3 /usr/local/bin/cis_benchmark.py --category all > /var/log/cis_${DATE}.txt
```

### 5.2 Change Detection (AIDE)

```bash
# Install and initialize AIDE
apt-get install -y aide
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Periodic integrity check
aide --check 2>&1 | grep -E "^(Changed|Added|Removed)"
```

| Tool | Role | Automation Method |
|------|------|------------------|
| Lynis | Comprehensive security audit | Daily cron + report generation |
| OpenSCAP | CIS/STIG compliance | Weekly scan + HTML report |
| AIDE | File integrity audit | Daily check + alerts |
| CIS script | Detailed check of specific items | Event-driven execution |
