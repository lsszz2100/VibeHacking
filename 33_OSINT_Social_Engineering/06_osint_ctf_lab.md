> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# OSINT & 소셜 엔지니어링 CTF 실습 랩

## 실습 환경 준비

### Docker Compose 환경

```yaml
# docker-compose.yml
version: "3.9"

services:
  osint-target:
    image: python:3.11-slim
    container_name: osint-target
    ports:
      - "8080:8080"
    command: >
      sh -c "pip install flask -q && python3 /app/target_site.py"
    volumes:
      - ./target_site.py:/app/target_site.py

  metadata-server:
    image: python:3.11-slim
    container_name: metadata-server
    ports:
      - "8081:8081"
    command: >
      sh -c "pip install flask pillow -q && python3 /app/metadata_server.py"
    volumes:
      - ./metadata_server.py:/app/metadata_server.py

networks:
  default:
    driver: bridge
```

### 필수 도구 설치

```bash
pip install requests beautifulsoup4 exifread pillow dnspython
sudo apt install -y exiftool whois dig nmap
```

---

## 실습 1: 이메일 OSINT 및 GitHub 도킹

### 목표

이메일 주소와 GitHub 계정을 분석하여 숨겨진 민감 정보(API 키, 비밀번호, 플래그)를 발굴한다.

**플래그 형식**: `CTF{github_dork_<secret_type>_exposed}`

### 시나리오

개발자 `john.doe@ctfcorp.com`의 공개 GitHub 레포지토리를 분석하여 실수로 커밋된 비밀 정보를 찾아라.

### GitHub 도킹 대상 시뮬레이션

```python
#!/usr/bin/env python3
"""GitHub 도킹 실습용 가상 레포지토리 데이터 생성기"""

from pathlib import Path
import json


# 실수로 커밋된 비밀 정보를 포함한 가상 파일들
LEAKED_FILES = {
    "config.py": '''
# Application Configuration
import os

# Database credentials - DO NOT COMMIT
DB_HOST = "db.ctfcorp.internal"
DB_USER = "dbadmin"
DB_PASS = "Sup3rS3cret!DB2024"

# AWS credentials - REMOVE BEFORE PUSH
AWS_ACCESS_KEY = "FAKEKEYEXAMPLE000000"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API Keys
STRIPE_KEY = "sk_live_CTF{github_dork_api_key_exposed}"
SENDGRID_KEY = "SG.abcdefghijklmnop.QRSTUVWXYZ1234567890"

SECRET_KEY = "django-insecure-ctf-lab-2024-secret"
''',
    ".env": '''
# Environment variables - should be in .gitignore!
DATABASE_URL=postgresql://admin:password123@localhost/ctfdb
REDIS_URL=redis://:redissecret@localhost:6379
JWT_SECRET=jwt_super_secret_2024_ctf
ADMIN_EMAIL=admin@ctfcorp.com
ADMIN_PASSWORD=Admin@2024!
''',
    "docker-compose.yml": '''
version: "3.9"
services:
  db:
    image: postgres:14
    environment:
      POSTGRES_PASSWORD: "hardcoded_db_password"
      POSTGRES_USER: "ctfadmin"
      POSTGRES_DB: "ctfprod"
  app:
    build: .
    environment:
      SECRET: "CTF{github_dork_env_secret_exposed}"
''',
    "deploy.sh": '''#!/bin/bash
# Deployment script
TOKEN="FAKE_GH_PAT_FOR_CTF_LAB_DEMO_001"
curl -H "Authorization: token $TOKEN" https://api.github.com/repos/ctfcorp/app/issues
ssh deploy@prod.ctfcorp.com -i /tmp/deploy_key "sudo systemctl restart app"
''',
}

COMMIT_HISTORY = [
    {"hash": "a1b2c3d", "msg": "Add configuration files", "files": ["config.py"]},
    {"hash": "e4f5g6h", "msg": "Forgot to add .env to .gitignore", "files": [".env"]},
    {"hash": "i7j8k9l", "msg": "Update docker-compose", "files": ["docker-compose.yml"]},
    {"hash": "m0n1o2p", "msg": "Add deployment script", "files": ["deploy.sh"]},
    {"hash": "q3r4s5t", "msg": "HOTFIX: remove credentials", "files": ["config.py"]},
]


def create_github_sim_data(output_dir: str) -> None:
    Path(output_dir).mkdir(exist_ok=True)

    for filename, content in LEAKED_FILES.items():
        filepath = Path(output_dir) / filename.replace("/", "_")
        filepath.write_text(content.strip())

    history_path = Path(output_dir) / "commit_history.json"
    history_path.write_text(json.dumps(COMMIT_HISTORY, indent=2))

    print(f"[+] GitHub 시뮬레이션 데이터 생성: {output_dir}")
    print(f"    파일 수: {len(LEAKED_FILES)}")
    print(f"    커밋 수: {len(COMMIT_HISTORY)}")


if __name__ == "__main__":
    create_github_sim_data("github_sim")
```

### 힌트

1. GitHub 도킹 쿼리: `site:github.com "ctfcorp" "api_key" OR "password" OR "secret"`
2. `git log --all --full-history -- "*.env"` 로 삭제된 파일 커밋 확인
3. `truffleHog`, `gitleaks` 도구로 자동화

### 풀이

```python
#!/usr/bin/env python3
"""GitHub 도킹 및 비밀 정보 탐지 도구"""

import argparse
import json
import re
from pathlib import Path


SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"CTF\{[^}]+\}", "CTF 플래그"),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", "API 키"),
    (r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"]?(\S{8,})", "시크릿 키"),
    (r"(?i)(password|passwd)\s*[=:]\s*['\"]?(\S{6,})", "패스워드"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)sk[_-]live[_-][0-9a-zA-Z]{24,}", "Stripe 라이브 키"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)(jwt[_-]?secret|token)\s*[=:]\s*['\"]?(\S{10,})", "JWT 시크릿"),
]


def scan_file_for_secrets(filepath: Path) -> list[dict]:
    """파일에서 비밀 정보 탐지"""
    findings: list[dict] = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            for pattern, label in SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append({
                        "file": str(filepath),
                        "line": line_num,
                        "type": label,
                        "value": match.group()[:80],
                        "context": line.strip()[:100],
                    })
    except (PermissionError, IsADirectoryError):
        pass

    return findings


def scan_directory(target_dir: str) -> list[dict]:
    """디렉토리 전체 스캔"""
    all_findings: list[dict] = []
    target = Path(target_dir)

    if not target.exists():
        print(f"[-] 디렉토리 없음: {target_dir}")
        return all_findings

    for filepath in target.rglob("*"):
        if filepath.is_file() and filepath.suffix in [
            ".py", ".js", ".env", ".yml", ".yaml", ".json", ".sh", ".conf", ".cfg", ".ini", ""
        ]:
            findings = scan_file_for_secrets(filepath)
            all_findings.extend(findings)

    return all_findings


def analyze_commit_history(history_path: str) -> list[dict]:
    """커밋 이력 분석"""
    suspicious: list[dict] = []

    try:
        with open(history_path) as f:
            history = json.load(f)

        for commit in history:
            msg = commit.get("msg", "").lower()
            if any(kw in msg for kw in ["credential", "password", "secret", "token", "key", "remove", "forgot"]):
                suspicious.append(commit)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    return suspicious


def generate_github_dork_queries(target: str) -> list[str]:
    """GitHub 도킹 쿼리 생성"""
    queries = [
        f'site:github.com "{target}" "api_key"',
        f'site:github.com "{target}" "password" filename:.env',
        f'site:github.com "{target}" extension:pem',
        f'site:github.com "{target}" "AWS_SECRET"',
        f'"{target}" "BEGIN RSA PRIVATE KEY" site:github.com',
        f'"{target}" "db_password" OR "database_password" site:github.com',
    ]
    return queries


def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub 도킹 및 비밀 정보 탐지")
    parser.add_argument("target", help="스캔할 디렉토리 또는 조직명")
    parser.add_argument("--dorks", action="store_true", help="GitHub 도킹 쿼리 생성")
    parser.add_argument("--history", help="커밋 이력 JSON 파일")
    args = parser.parse_args()

    if args.dorks:
        queries = generate_github_dork_queries(args.target)
        print("=== GitHub 도킹 쿼리 ===")
        for q in queries:
            print(f"  {q}")
        return

    print(f"[*] 비밀 정보 스캔: {args.target}")
    findings = scan_directory(args.target)

    if findings:
        print(f"\n[!] {len(findings)}개 발견:")
        flags: list[str] = []
        for f in findings:
            print(f"  [{f['type']}] {f['file']}:{f['line']}")
            print(f"    값: {f['value']}")
            if f["type"] == "CTF 플래그":
                flags.append(f["value"])
        if flags:
            print(f"\n[+] 플래그: {flags[0]}")
    else:
        print("[-] 발견 없음")

    if args.history:
        suspicious = analyze_commit_history(args.history)
        if suspicious:
            print(f"\n[!] 의심스러운 커밋 {len(suspicious)}개:")
            for c in suspicious:
                print(f"  [{c['hash']}] {c['msg']}")


if __name__ == "__main__":
    main()
```

---

## 실습 2: 도메인 정찰 및 서브도메인 열거

### 목표

타겟 도메인에 대한 OSINT를 수행하여 서브도메인, DNS 레코드, WHOIS 정보를 수집하고 숨겨진 서비스를 발견한다.

**플래그 형식**: `CTF{domain_recon_<record_type>_<subdomain>_found}`

### 풀이

```python
#!/usr/bin/env python3
"""도메인 OSINT 정찰 도구"""

import argparse
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class DomainIntel:
    domain: str
    ip_addresses: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    whois_info: dict = field(default_factory=dict)


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "dev", "test", "staging",
    "api", "cdn", "blog", "vpn", "remote", "webmail", "portal",
    "gitlab", "jenkins", "jira", "confluence", "grafana",
    "prometheus", "kibana", "elastic", "db", "database",
    "backup", "old", "legacy", "beta", "alpha", "internal",
    "flag", "secret", "hidden", "ctf",
]


def resolve_host(hostname: str) -> str | None:
    """호스트명 DNS 해석"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_dns_records(domain: str, record_type: str) -> list[str]:
    """DNS 레코드 조회"""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, record_type],
            capture_output=True, text=True, timeout=10,
        )
        return [r.strip() for r in result.stdout.splitlines() if r.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:
    """서브도메인 열거"""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    found: list[str] = []

    def check_subdomain(sub: str) -> str | None:
        fqdn = f"{sub}.{domain}"
        if resolve_host(fqdn):
            return fqdn
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"  [+] 서브도메인: {result}")

    return found


def check_zone_transfer(domain: str, ns: str) -> list[str]:
    """DNS 존 전송 시도 (AXFR)"""
    try:
        result = subprocess.run(
            ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer"],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout and "Transfer failed" not in result.stdout:
            print(f"[!] 존 전송 성공: {ns}")
            return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def simulate_domain_recon(domain: str = "ctfcorp.com") -> DomainIntel:
    """도메인 OSINT 시뮬레이션 (실제 DNS 없이)"""
    intel = DomainIntel(domain=domain)

    # 시뮬레이션 데이터
    intel.ip_addresses = ["203.0.113.10", "203.0.113.11"]
    intel.subdomains = [
        f"www.{domain}", f"mail.{domain}", f"api.{domain}",
        f"admin.{domain}", f"dev.{domain}", f"jenkins.{domain}",
        f"flag.{domain}",  # 숨겨진 서브도메인
    ]
    intel.mx_records = [f"mail.{domain}"]
    intel.txt_records = [
        "v=spf1 include:sendgrid.net ~all",
        f"CTF{{domain_recon_TXT_flag_{domain.split('.')[0]}_found}}",
    ]
    intel.ns_records = [f"ns1.{domain}", f"ns2.{domain}"]

    return intel


def report_findings(intel: DomainIntel) -> None:
    """OSINT 수집 결과 보고"""
    import re

    print(f"\n=== 도메인 OSINT: {intel.domain} ===\n")
    print(f"IP 주소: {', '.join(intel.ip_addresses)}")
    print(f"네임서버: {', '.join(intel.ns_records)}")
    print(f"MX 레코드: {', '.join(intel.mx_records)}")

    print(f"\n서브도메인 ({len(intel.subdomains)}개):")
    for sub in intel.subdomains:
        print(f"  {sub}")

    print(f"\nTXT 레코드:")
    for txt in intel.txt_records:
        print(f"  {txt}")
        flags = re.findall(r"CTF\{[^}]+\}", txt)
        if flags:
            print(f"  [+] 플래그: {flags[0]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="도메인 OSINT 정찰 도구")
    parser.add_argument("domain", help="타겟 도메인")
    parser.add_argument("--simulate", action="store_true", help="시뮬레이션 모드")
    parser.add_argument("--subdomains", action="store_true", help="서브도메인 열거")
    parser.add_argument("--zone-transfer", action="store_true", help="존 전송 시도")
    args = parser.parse_args()

    if args.simulate:
        intel = simulate_domain_recon(args.domain)
        report_findings(intel)
    else:
        intel = DomainIntel(domain=args.domain)
        print(f"[*] 도메인 정찰: {args.domain}")

        intel.ip_addresses = [resolve_host(args.domain)] if resolve_host(args.domain) else []
        intel.txt_records = get_dns_records(args.domain, "TXT")
        intel.mx_records = get_dns_records(args.domain, "MX")
        intel.ns_records = get_dns_records(args.domain, "NS")

        if args.subdomains:
            print("\n[*] 서브도메인 열거 중...")
            intel.subdomains = enumerate_subdomains(args.domain)

        if args.zone_transfer and intel.ns_records:
            for ns in intel.ns_records[:2]:
                check_zone_transfer(args.domain, ns)

        report_findings(intel)


if __name__ == "__main__":
    main()
```

---

## 실습 3: 이미지 메타데이터 분석 (EXIF)

### 목표

제공된 이미지 파일의 EXIF 메타데이터를 분석하여 숨겨진 GPS 좌표, 장치 정보, 플래그를 추출한다.

**플래그 형식**: `CTF{exif_metadata_<tag_name>_location_revealed}`

### 풀이

```python
#!/usr/bin/env python3
"""EXIF 메타데이터 분석 도구"""

import argparse
import io
import json
import os
import struct
from pathlib import Path


def create_exif_challenge_image(output_path: str) -> None:
    """EXIF 데이터가 포함된 챌린지 이미지 생성"""
    try:
        from PIL import Image
        import piexif

        img = Image.new("RGB", (640, 480), color=(100, 150, 200))

        # EXIF 데이터 구성
        exif_dict: dict = {
            "0th": {
                piexif.ImageIFD.Make: b"CTF-Camera",
                piexif.ImageIFD.Model: b"Challenge-2024",
                piexif.ImageIFD.ImageDescription: b"CTF{exif_metadata_gps_location_revealed}",
                piexif.ImageIFD.Artist: b"ctf_player",
                piexif.ImageIFD.Copyright: b"CTF Labs 2024",
            },
            "Exif": {
                piexif.ExifIFD.UserComment: b"Flag: CTF{exif_metadata_gps_location_revealed}",
                piexif.ExifIFD.DateTimeOriginal: b"2024:06:01 14:30:00",
            },
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((37, 1), (33, 1), (5580, 100)),
                piexif.GPSIFD.GPSLongitudeRef: b"E",
                piexif.GPSIFD.GPSLongitude: ((126, 1), (58, 1), (4320, 100)),
                piexif.GPSIFD.GPSAltitude: (100, 1),
            },
        }

        exif_bytes = piexif.dump(exif_dict)
        img.save(output_path, exif=exif_bytes)
        print(f"[+] 챌린지 이미지 생성: {output_path}")

    except ImportError:
        # pillow/piexif 없는 경우 수동으로 최소 JPEG 생성
        print("[-] pillow/piexif 미설치. pip install pillow piexif")
        # 최소 JPEG 헤더 + EXIF 주석에 플래그 삽입
        jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE1])
        comment_flag = b"CTF{exif_metadata_comment_location_revealed}"
        comment_section = bytes([0xFF, 0xFE]) + struct.pack(">H", len(comment_flag) + 2) + comment_flag
        jpeg_footer = bytes([0xFF, 0xD9])

        with open(output_path, "wb") as f:
            f.write(jpeg_header + struct.pack(">H", 8) + b"\x00\x00\x00\x00" + comment_section + jpeg_footer)
        print(f"[+] 간단한 JPEG 생성: {output_path}")


def extract_exif_data(image_path: str) -> dict:
    """EXIF 메타데이터 추출"""
    metadata: dict = {}

    # exiftool 사용 (가장 강력)
    try:
        import subprocess
        result = subprocess.run(
            ["exiftool", "-json", image_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if data:
                metadata["exiftool"] = data[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # PIL/Pillow 사용
    try:
        from PIL import Image
        import piexif

        with Image.open(image_path) as img:
            exif_raw = img.info.get("exif", b"")
            if exif_raw:
                exif_dict = piexif.load(exif_raw)
                metadata["pil_exif"] = {
                    "0th": {str(k): str(v) for k, v in exif_dict.get("0th", {}).items()},
                    "GPS": {str(k): str(v) for k, v in exif_dict.get("GPS", {}).items()},
                    "Exif": {str(k): str(v) for k, v in exif_dict.get("Exif", {}).items()},
                }
    except (ImportError, Exception):
        pass

    # 이진 데이터에서 직접 패턴 추출
    try:
        with open(image_path, "rb") as f:
            raw = f.read()

        import re
        flags = re.findall(rb"CTF\{[^}]+\}", raw)
        if flags:
            metadata["embedded_flags"] = [f.decode("utf-8", errors="ignore") for f in flags]
    except Exception:
        pass

    return metadata


def convert_gps_to_decimal(gps_data: tuple) -> float:
    """GPS 좌표 변환 (도/분/초 -> 십진수)"""
    try:
        degrees = gps_data[0][0] / gps_data[0][1]
        minutes = gps_data[1][0] / gps_data[1][1] / 60
        seconds = gps_data[2][0] / gps_data[2][1] / 3600
        return degrees + minutes + seconds
    except (IndexError, ZeroDivisionError, TypeError):
        return 0.0


def analyze_image_metadata(image_path: str) -> None:
    import re

    path = Path(image_path)
    if not path.exists():
        print(f"[-] 파일 없음: {image_path}")
        return

    print(f"[*] 이미지 메타데이터 분석: {path.name}")
    print(f"    크기: {path.stat().st_size} bytes")

    metadata = extract_exif_data(image_path)

    if not metadata:
        print("[-] EXIF 데이터 없음")
        return

    print("\n=== EXIF 데이터 ===")
    for source, data in metadata.items():
        print(f"\n[{source}]")
        if isinstance(data, dict):
            for k, v in data.items():
                v_str = str(v)[:100]
                print(f"  {k}: {v_str}")
                flags = re.findall(r"CTF\{[^}]+\}", v_str)
                for flag in flags:
                    print(f"  [+] 플래그 발견: {flag}")
        elif isinstance(data, list):
            for item in data:
                print(f"  {item}")
                flags = re.findall(r"CTF\{[^}]+\}", str(item))
                for flag in flags:
                    print(f"  [+] 플래그 발견: {flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="EXIF 메타데이터 분석 도구")
    parser.add_argument("image", help="분석할 이미지 파일")
    parser.add_argument("--create", action="store_true", help="챌린지 이미지 생성")
    args = parser.parse_args()

    if args.create:
        create_exif_challenge_image(args.image)
    else:
        analyze_image_metadata(args.image)


if __name__ == "__main__":
    main()
```

---

<a name="english"></a>

# OSINT & Social Engineering CTF Practice Lab

## Lab Environment Setup

```bash
docker-compose up -d
pip install requests beautifulsoup4 exifread pillow piexif dnspython
sudo apt install -y exiftool whois
```

---

## Challenge 1: Email OSINT & GitHub Dorking

### Objective

Analyze a developer's public GitHub repositories to find accidentally committed secrets and the flag.

**Flag format**: `CTF{github_dork_<secret_type>_exposed}`

### Solution Steps

```bash
# Generate simulation data
python3 create_sim_data.py
# Creates github_sim/ directory with leaked files

# Scan for secrets
python3 github_dork.py github_sim/
# Finds: CTF{github_dork_api_key_exposed}

# Generate dork queries for real GitHub
python3 github_dork.py ctfcorp --dorks

# Using trufflehog (real tool)
trufflehog filesystem github_sim/
trufflehog git https://github.com/ctfcorp/app.git

# Using gitleaks
gitleaks detect --source=github_sim/ --report-format=json
```

### Key Findings

| File | Secret Type | Value |
|------|-------------|-------|
| `config.py` | API Key | `CTF{github_dork_api_key_exposed}` |
| `.env` | DB Password | `password123` |
| `docker-compose.yml` | Env Secret | `CTF{github_dork_env_secret_exposed}` |
| `deploy.sh` | GitHub Token | `ghp_FakeGitHub...` |

---

## Challenge 2: Domain Reconnaissance & Subdomain Enumeration

### Objective

Perform OSINT on a target domain to discover hidden subdomains and DNS records containing the flag.

**Flag format**: `CTF{domain_recon_<record_type>_<subdomain>_found}`

### Solution Steps

```bash
# Simulation (no real DNS needed)
python3 domain_recon.py ctfcorp.com --simulate
# Finds flag in TXT record

# Real domain enumeration
python3 domain_recon.py ctfcorp.com --subdomains --zone-transfer

# Manual techniques:
# DNS TXT records
dig TXT ctfcorp.com +short

# Subdomain brute-force
for sub in $(cat /usr/share/wordlists/subdomains.txt); do
  host "$sub.ctfcorp.com" 2>/dev/null | grep "has address"
done

# Certificate transparency logs
curl "https://crt.sh/?q=%.ctfcorp.com&output=json" | jq '.[].name_value'
```

---

## Challenge 3: Image Metadata Analysis (EXIF)

### Objective

Extract EXIF metadata from an image file to find hidden GPS coordinates and the flag.

**Flag format**: `CTF{exif_metadata_<tag_name>_location_revealed}`

### Solution Steps

```bash
# Create challenge image
python3 exif_analyzer.py challenge.jpg --create

# Analyze EXIF data
python3 exif_analyzer.py challenge.jpg

# Using exiftool (recommended)
exiftool challenge.jpg
exiftool -GPS:all challenge.jpg

# Extract GPS coordinates
exiftool -GPSLatitude -GPSLongitude challenge.jpg

# Search binary for flag pattern
strings challenge.jpg | grep "CTF{"
# CTF{exif_metadata_gps_location_revealed}
```

### EXIF Tags with Hidden Data

| Tag | Description | CTF Use Case |
|-----|-------------|--------------|
| `GPSLatitude/Longitude` | GPS coordinates | Location of secret facility |
| `UserComment` | Custom comment | Embedded flag |
| `ImageDescription` | Image description | Flag in plain sight |
| `Artist` | Author field | Username/identity leak |
| `XPComment` | Windows comment | Hidden instructions |
