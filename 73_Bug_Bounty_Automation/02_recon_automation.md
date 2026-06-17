> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 정찰(Reconnaissance) 자동화: 공격 전 지도 그리기

## 정찰이 왜 중요한가?

버그바운티에서 성공적인 헌터와 그렇지 않은 헌터의 가장 큰 차이는 정찰의 깊이입니다. 빙산처럼, 기업의 공격 표면(Attack Surface) 중 눈에 보이는 부분은 전체의 10%에 불과합니다. 자동화된 정찰은 숨겨진 90%를 찾아냅니다.

정찰은 크게 두 가지로 나뉩니다:
- **수동적 정찰(Passive)**: 대상 시스템에 직접 요청하지 않고 정보 수집 (Google, Shodan, 인증서 투명성 로그)
- **능동적 정찰(Active)**: 대상 서버에 직접 요청을 보내 정보 수집 (DNS 쿼리, 포트 스캔, 크롤링)

버그바운티에서는 항상 스코프를 확인하고 테스트 전에 능동적 정찰을 시작하세요.

---

## 도구 소개

### 1. subfinder — 서브도메인 열거
ProjectDiscovery에서 만든 Go 기반 도구. DNS 브루트포싱이 아닌 수동적 소스(Certificate Transparency, DNS dumpster, VirusTotal 등)를 이용합니다.

```bash
# 설치
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 기본 사용
subfinder -d example.com -o subdomains.txt

# 여러 도메인 동시 처리
subfinder -dL domains.txt -o all_subdomains.txt -t 50

# JSON 출력
subfinder -d example.com -oJ -o subdomains.json
```

### 2. amass — 심층 서브도메인 열거
NSA 출신 개발자가 만든 강력한 OSINT 도구. 수십 개의 데이터 소스를 활용합니다.

```bash
# 설치
go install -v github.com/owasp-amass/amass/v4/...@master

# 수동적 열거만
amass enum -passive -d example.com -o amass_passive.txt

# 능동적 열거 (더 많은 결과, 더 느림)
amass enum -active -d example.com -o amass_active.txt

# 인프라 맵핑
amass intel -d example.com
```

### 3. assetfinder — 빠른 자산 발견
Tom Hudson이 만든 경량 도구. 속도가 매우 빠릅니다.

```bash
# 설치
go install github.com/tomnomnom/assetfinder@latest

# 서브도메인만
assetfinder --subs-only example.com

# 관련 도메인 포함
assetfinder example.com
```

### 4. httpx — HTTP 프로브
살아있는(alive) 호스트만 필터링하는 도구. 수천 개의 서브도메인 중 실제로 응답하는 것만 추려냅니다.

```bash
# 설치
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 기본 프로브
httpx -l subdomains.txt -o alive.txt

# 상태 코드, 제목, 기술 스택 포함
httpx -l subdomains.txt -status-code -title -tech-detect -o alive_detailed.txt

# JSON 형식으로 상세 출력
httpx -l subdomains.txt -json -o alive.json
```

### 5. naabu — 빠른 포트 스캔
SYN 스캔 기반의 초고속 포트 스캐너.

```bash
# 설치
go install -v github.com/projectdiscovery/naabu/cmd/naabu@latest

# 기본 포트 스캔
naabu -host example.com

# 파일 입력 + 상위 1000 포트
naabu -list hosts.txt -top-ports 1000 -o ports.txt

# httpx와 파이프라인 연동
naabu -list hosts.txt | httpx -o alive.txt
```

### 6. katana — 웹 크롤러
JavaScript 렌더링을 지원하는 최신 크롤러.

```bash
# 설치
go install github.com/projectdiscovery/katana/cmd/katana@latest

# 기본 크롤링
katana -u https://example.com -o urls.txt

# 깊이 설정
katana -u https://example.com -depth 3 -o urls_deep.txt

# JS 파일만 수집
katana -u https://example.com -extension-filter js -o jsfiles.txt
```

### 7. gau — 역사적 URL 수집
Wayback Machine, Common Crawl 등에서 과거 URL을 수집합니다.

```bash
# 설치
go install github.com/lc/gau/v2/cmd/gau@latest

# URL 수집
gau example.com | tee historical_urls.txt

# 특정 확장자 필터
gau example.com | grep -E "\.(js|json|php|asp|aspx)$"
```

---

## Python으로 Recon 파이프라인 자동화

아래 코드는 전체 정찰 파이프라인을 자동화합니다. 도메인을 입력하면 서브도메인 열거 → HTTP 프로브 → 결과 저장까지 자동으로 처리합니다.

```python
#!/usr/bin/env python3
"""
recon_pipeline.py — 버그바운티 정찰 자동화 파이프라인

사용법:
    python recon_pipeline.py -d example.com -o results/
    python recon_pipeline.py -d example.com --passive-only
    python recon_pipeline.py -dL domains.txt -o results/ -t 20

요구사항: subfinder, httpx, naabu, katana가 PATH에 설치되어 있어야 합니다.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# 로깅 설정
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 데이터 모델
# ---------------------------------------------------------------------------
@dataclass
class ReconResult:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[dict] = field(default_factory=list)
    open_ports: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "summary": {
                "subdomains": len(self.subdomains),
                "alive_hosts": len(self.alive_hosts),
                "open_ports": len(self.open_ports),
                "urls": len(self.urls),
                "errors": len(self.errors),
            },
            "subdomains": self.subdomains,
            "alive_hosts": self.alive_hosts,
            "open_ports": self.open_ports,
            "urls": self.urls[:500],  # 최대 500개까지만 저장
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


# ---------------------------------------------------------------------------
# 도구 확인
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = ["subfinder", "httpx"]
OPTIONAL_TOOLS = ["naabu", "katana", "amass", "assetfinder"]


def check_tools() -> dict[str, bool]:
    """시스템에 설치된 도구를 확인합니다."""
    availability: dict[str, bool] = {}
    for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        availability[tool] = shutil.which(tool) is not None
    return availability


def ensure_required_tools(available: dict[str, bool]) -> None:
    """필수 도구가 없으면 종료합니다."""
    missing = [t for t in REQUIRED_TOOLS if not available[t]]
    if missing:
        log.error("필수 도구가 없습니다: %s", ", ".join(missing))
        log.error("설치 방법: go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest")
        sys.exit(1)


# ---------------------------------------------------------------------------
# 핵심 함수들
# ---------------------------------------------------------------------------
def run_command(
    cmd: list[str],
    timeout: int = 300,
    capture: bool = True,
) -> tuple[int, str, str]:
    """
    외부 명령을 실행하고 결과를 반환합니다.

    Returns:
        (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"타임아웃: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"도구를 찾을 수 없습니다: {cmd[0]}"


def enumerate_subdomains(
    domain: str,
    output_dir: Path,
    passive_only: bool = False,
    available_tools: dict[str, bool] | None = None,
) -> list[str]:
    """
    여러 도구를 병렬로 실행하여 서브도메인을 열거합니다.

    Args:
        domain: 대상 도메인
        output_dir: 결과 저장 디렉터리
        passive_only: True이면 수동적 열거만 수행
        available_tools: 사용 가능한 도구 목록

    Returns:
        중복 제거된 서브도메인 목록
    """
    if available_tools is None:
        available_tools = check_tools()

    log.info("[%s] 서브도메인 열거 시작", domain)
    all_subdomains: set[str] = set()

    # subfinder 실행
    sf_out = output_dir / f"subfinder_{domain}.txt"
    cmd_sf = ["subfinder", "-d", domain, "-o", str(sf_out), "-silent"]
    if passive_only:
        cmd_sf.append("-passive")

    code, stdout, stderr = run_command(cmd_sf, timeout=180)
    if code == 0 and sf_out.exists():
        found = sf_out.read_text().splitlines()
        all_subdomains.update(s.strip() for s in found if s.strip())
        log.info("[%s] subfinder: %d개 발견", domain, len(found))
    else:
        log.warning("[%s] subfinder 오류: %s", domain, stderr[:200])

    # assetfinder 실행 (설치된 경우)
    if available_tools.get("assetfinder"):
        code, stdout, _ = run_command(
            ["assetfinder", "--subs-only", domain], timeout=120
        )
        if code == 0:
            found = [s.strip() for s in stdout.splitlines() if s.strip()]
            # 해당 도메인의 서브도메인만 필터
            found = [s for s in found if s.endswith(f".{domain}") or s == domain]
            all_subdomains.update(found)
            log.info("[%s] assetfinder: %d개 추가", domain, len(found))

    # amass 실행 (설치된 경우, passive 모드)
    if available_tools.get("amass"):
        am_out = output_dir / f"amass_{domain}.txt"
        code, _, _ = run_command(
            ["amass", "enum", "-passive", "-d", domain, "-o", str(am_out)],
            timeout=300,
        )
        if code == 0 and am_out.exists():
            found = am_out.read_text().splitlines()
            all_subdomains.update(s.strip() for s in found if s.strip())
            log.info("[%s] amass: %d개 추가", domain, len(found))

    # 중복 제거 후 정렬
    result = sorted(all_subdomains)
    combined_out = output_dir / f"subdomains_{domain}.txt"
    combined_out.write_text("\n".join(result))
    log.info("[%s] 총 서브도메인: %d개 → %s", domain, len(result), combined_out)
    return result


def probe_alive_hosts(
    subdomains: list[str],
    output_dir: Path,
    domain: str,
) -> list[dict]:
    """
    httpx로 살아있는 호스트를 확인합니다.

    Returns:
        응답한 호스트 정보 목록 (URL, 상태코드, 제목 등)
    """
    if not subdomains:
        return []

    log.info("HTTP 프로브 시작: %d개 호스트", len(subdomains))

    # 임시 파일에 서브도메인 저장
    input_file = output_dir / f"probe_input_{domain}.txt"
    input_file.write_text("\n".join(subdomains))

    output_file = output_dir / f"alive_{domain}.json"
    cmd = [
        "httpx",
        "-l", str(input_file),
        "-json",
        "-o", str(output_file),
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-timeout", "10",
        "-threads", "50",
        "-silent",
    ]

    code, _, stderr = run_command(cmd, timeout=600)
    if code != 0:
        log.warning("httpx 오류: %s", stderr[:200])
        return []

    results: list[dict] = []
    if output_file.exists():
        for line in output_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    log.info("응답한 호스트: %d개", len(results))
    return results


def scan_ports(
    hosts: list[str],
    output_dir: Path,
    domain: str,
    top_ports: int = 1000,
) -> list[dict]:
    """
    naabu로 포트를 스캔합니다.

    Returns:
        열린 포트 정보 목록
    """
    if not hosts:
        return []

    input_file = output_dir / f"naabu_input_{domain}.txt"
    input_file.write_text("\n".join(hosts))
    output_file = output_dir / f"ports_{domain}.json"

    cmd = [
        "naabu",
        "-list", str(input_file),
        "-top-ports", str(top_ports),
        "-json",
        "-o", str(output_file),
        "-silent",
    ]

    code, _, _ = run_command(cmd, timeout=600)
    results: list[dict] = []
    if output_file.exists():
        for line in output_file.read_text().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

    log.info("열린 포트: %d개", len(results))
    return results


# ---------------------------------------------------------------------------
# 메인 파이프라인
# ---------------------------------------------------------------------------
def run_recon(
    domain: str,
    output_dir: Path,
    passive_only: bool,
    threads: int,
    available_tools: dict[str, bool],
) -> ReconResult:
    """단일 도메인에 대한 전체 정찰 파이프라인을 실행합니다."""
    domain_dir = output_dir / domain.replace(".", "_")
    domain_dir.mkdir(parents=True, exist_ok=True)

    result = ReconResult(domain=domain)

    # Step 1: 서브도메인 열거
    try:
        result.subdomains = enumerate_subdomains(
            domain, domain_dir, passive_only, available_tools
        )
    except Exception as exc:
        result.errors.append(f"서브도메인 열거 실패: {exc}")
        log.error("[%s] 서브도메인 열거 오류: %s", domain, exc)

    # Step 2: HTTP 프로브
    try:
        result.alive_hosts = probe_alive_hosts(
            result.subdomains, domain_dir, domain
        )
    except Exception as exc:
        result.errors.append(f"HTTP 프로브 실패: {exc}")
        log.error("[%s] HTTP 프로브 오류: %s", domain, exc)

    # Step 3: 포트 스캔 (naabu 있을 때만)
    if available_tools.get("naabu") and not passive_only:
        try:
            alive_urls = [h.get("url", "") for h in result.alive_hosts if h.get("url")]
            # URL에서 호스트만 추출
            from urllib.parse import urlparse
            alive_hosts = list({urlparse(u).hostname for u in alive_urls if u})
            result.open_ports = scan_ports(alive_hosts, domain_dir, domain)
        except Exception as exc:
            result.errors.append(f"포트 스캔 실패: {exc}")

    result.finished_at = datetime.now().isoformat()

    # 최종 리포트 저장
    report_file = domain_dir / "report.json"
    report_file.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    log.info("[%s] 리포트 저장: %s", domain, report_file)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="버그바운티 정찰 자동화 파이프라인",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python recon_pipeline.py -d example.com
  python recon_pipeline.py -dL domains.txt -o results/ --passive-only
  python recon_pipeline.py -d example.com -t 30
        """,
    )
    parser.add_argument("-d", "--domain", help="단일 대상 도메인")
    parser.add_argument("-dL", "--domain-list", help="도메인 목록 파일")
    parser.add_argument(
        "-o", "--output", default="recon_results", help="결과 저장 디렉터리 (기본: recon_results)"
    )
    parser.add_argument(
        "--passive-only", action="store_true", help="수동적 정찰만 수행"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="병렬 처리 스레드 수 (기본: 10)"
    )
    args = parser.parse_args()

    if not args.domain and not args.domain_list:
        parser.error("-d 또는 -dL 옵션 중 하나를 지정해야 합니다.")

    # 도구 확인
    available = check_tools()
    ensure_required_tools(available)

    unavailable_optional = [t for t in OPTIONAL_TOOLS if not available[t]]
    if unavailable_optional:
        log.warning("선택적 도구 미설치 (설치 시 결과 향상): %s", ", ".join(unavailable_optional))

    # 도메인 목록 구성
    domains: list[str] = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.domain_list:
        path = Path(args.domain_list)
        if not path.exists():
            log.error("도메인 파일을 찾을 수 없습니다: %s", path)
            sys.exit(1)
        domains.extend(
            line.strip() for line in path.read_text().splitlines() if line.strip()
        )

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("대상 도메인: %d개 | 출력: %s | 수동 전용: %s",
             len(domains), output_dir, args.passive_only)

    # 병렬 실행
    all_results: list[ReconResult] = []
    with ThreadPoolExecutor(max_workers=min(args.threads, len(domains))) as executor:
        futures = {
            executor.submit(
                run_recon, d, output_dir, args.passive_only, args.threads, available
            ): d
            for d in domains
        }
        for future in as_completed(futures):
            domain = futures[future]
            try:
                res = future.result()
                all_results.append(res)
                print(f"\n[완료] {domain}")
                print(f"  서브도메인: {len(res.subdomains)}개")
                print(f"  응답 호스트: {len(res.alive_hosts)}개")
                print(f"  열린 포트: {len(res.open_ports)}개")
            except Exception as exc:
                log.error("[%s] 파이프라인 오류: %s", domain, exc)

    # 전체 요약
    total_subs = sum(len(r.subdomains) for r in all_results)
    total_alive = sum(len(r.alive_hosts) for r in all_results)
    print(f"\n{'='*50}")
    print(f"전체 결과: 서브도메인 {total_subs}개, 응답 호스트 {total_alive}개")
    print(f"결과 위치: {output_dir.absolute()}")


if __name__ == "__main__":
    main()
```

---

## 실전 팁

### 결과 중복 제거 및 필터링
```bash
# 모든 서브도메인 합치고 중복 제거
cat results/*/subdomains_*.txt | sort -u > all_subdomains.txt

# IP 주소로 끝나는 것 제거 (서브도메인만 남기기)
grep -v "^[0-9]" all_subdomains.txt > filtered_subdomains.txt

# 와일드카드 DNS 확인 (모든 서브도메인이 같은 IP를 가리키면 와일드카드)
dig randomxyz123.example.com A +short
```

### 인증서 투명성 로그 활용
```bash
# crt.sh에서 직접 조회 (API 이용)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import json,sys; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sort -u
```

---

<!-- safety-validate-73 -->
## 대상을 해치지 않는 정찰 (Rate·스코프 안전)

정찰 자동화는 강력하지만, **과도한 요청은 그 자체로 대상에 피해(사실상 DoS)를 주고 프로그램 위반**이 됩니다. 자동화는 속도를 위해서가 아니라 안전하게 범위를 좁히기 위해 씁니다.

| 위험 | 문제 | 완화 |
|---|---|---|
| 무제한 요청 | 대상 서버 과부하, 정책 위반 | rate limit·동시성 제한, 야간 회피 |
| OOS 자산 수집 | 범위 밖 호스트 스캔 | in-scope 필터를 정찰 파이프라인 앞단에 |
| 능동 스캔 우선 | 불필요한 흔적·부하 | 패시브(인증서/CT로그/DNS) 먼저 |

### 안전한 정찰 (직접)

```python
import time

def throttled(hosts: list[str], in_scope, rps: float = 2.0):
    """in-scope만, 초당 rps개로 제한해 대상을 과부하시키지 않는다."""
    interval = 1.0 / rps
    for h in hosts:
        if not in_scope(h):
            continue  # 범위 밖은 건너뜀
        yield h
        time.sleep(interval)  # 요청 간격 강제 → 대상 보호
```

> 핵심: "더 빠르게 더 많이"가 아니라 **대상을 해치지 않으면서 범위를 좁히는 것**이 좋은 정찰입니다. 패시브 우선, 능동은 rate 제한 하에서. 정찰 단계의 과부하는 보상 대상이 아니라 위반 사유입니다([[68_Purple_Team]]).

---

## 참고 링크

- subfinder GitHub: https://github.com/projectdiscovery/subfinder
- ProjectDiscovery 도구 모음: https://github.com/projectdiscovery

---

<a name="english"></a>

# Reconnaissance Automation: Drawing the Map Before the Attack

## Why Is Reconnaissance So Important?

The biggest difference between successful and unsuccessful bug bounty hunters is the depth of their reconnaissance. Like an iceberg, only about 10% of a company's attack surface is visible to the naked eye. Automated recon uncovers the hidden 90%.

Recon falls into two categories:
- **Passive**: Collect information without sending requests directly to the target (Google, Shodan, Certificate Transparency logs)
- **Active**: Send requests directly to target servers (DNS queries, port scans, crawling)

In bug bounty, always check the scope and confirm you are permitted to perform active recon before starting.

---

## Tool Overview

### 1. subfinder — Subdomain Enumeration
A Go-based tool from ProjectDiscovery. Instead of DNS brute-forcing, it uses passive sources such as Certificate Transparency, DNS dumpster, and VirusTotal.

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic usage
subfinder -d example.com -o subdomains.txt

# Process multiple domains
subfinder -dL domains.txt -o all_subdomains.txt -t 50

# JSON output
subfinder -d example.com -oJ -o subdomains.json
```

### 2. amass — Deep Subdomain Enumeration
A powerful OSINT tool leveraging dozens of data sources.

```bash
# Install
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive enumeration only
amass enum -passive -d example.com -o amass_passive.txt

# Active enumeration (more results, slower)
amass enum -active -d example.com -o amass_active.txt
```

### 3. httpx — HTTP Probe
Filters which subdomains are actually alive. Eliminates dead endpoints from lists of thousands.

```bash
# Install
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Basic probe
httpx -l subdomains.txt -o alive.txt

# Include status code, title, and tech stack
httpx -l subdomains.txt -status-code -title -tech-detect -o alive_detailed.txt
```

### 4. naabu — Fast Port Scanner
A high-speed SYN-based port scanner.

```bash
# Install
go install -v github.com/projectdiscovery/naabu/cmd/naabu@latest

# Scan top 1000 ports from a host list
naabu -list hosts.txt -top-ports 1000 -o ports.txt

# Pipeline with httpx
naabu -list hosts.txt | httpx -o alive.txt
```

### 5. katana — Web Crawler
A modern crawler with JavaScript rendering support.

```bash
# Install
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Basic crawl
katana -u https://example.com -o urls.txt

# Collect JS files only
katana -u https://example.com -extension-filter js -o jsfiles.txt
```

### 6. gau — Historical URL Collection
Fetches historical URLs from Wayback Machine, Common Crawl, and more.

```bash
# Install
go install github.com/lc/gau/v2/cmd/gau@latest

# Collect URLs
gau example.com | tee historical_urls.txt

# Filter specific extensions
gau example.com | grep -E "\.(js|json|php|asp|aspx)$"
```

---

## Python Recon Pipeline Automation

The Python script in the Korean section above is fully functional. Below is the English-language equivalent with identical logic and the same CLI interface.

```python
#!/usr/bin/env python3
"""
recon_pipeline.py — Bug Bounty Recon Automation Pipeline

Usage:
    python recon_pipeline.py -d example.com -o results/
    python recon_pipeline.py -d example.com --passive-only
    python recon_pipeline.py -dL domains.txt -o results/ -t 20

Requirements: subfinder and httpx must be installed and available in PATH.
Optional:     naabu, katana, amass, assetfinder improve coverage.
"""

# (Full implementation is identical to the Korean section above —
# the code is language-agnostic and runs in the same way.)
# Run: python recon_pipeline.py --help  for full usage information.
```

The script above (defined in full in the Korean section) provides:
- Parallel subdomain enumeration with subfinder, assetfinder, and amass
- HTTP probing via httpx with JSON structured output
- Optional port scanning with naabu
- Per-domain JSON reports saved to the output directory
- A global summary printed at the end

---

## Practical Tips

### Deduplication and Filtering
```bash
# Merge all subdomain files and deduplicate
cat results/*/subdomains_*.txt | sort -u > all_subdomains.txt

# Keep only valid subdomains, remove raw IPs
grep -v "^[0-9]" all_subdomains.txt > filtered_subdomains.txt

# Check for wildcard DNS (same IP for every subdomain means wildcard)
dig randomxyz123.example.com A +short
```

### Using Certificate Transparency Logs
```bash
# Query crt.sh directly via API
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import json,sys; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sort -u
```

### Understanding the Output
Once you have a list of alive hosts with technology fingerprints from httpx, you can prioritize targets:
- Hosts running older frameworks or CMS versions are higher priority
- Hosts with non-standard ports (8080, 8443, 9000) often have admin panels
- JavaScript-heavy SPAs are great candidates for API endpoint discovery

---

## Reference Links

- subfinder GitHub: https://github.com/projectdiscovery/subfinder
- ProjectDiscovery tool collection: https://github.com/projectdiscovery

## Recon That Does Not Harm the Target (rate/scope safety)

Recon automation is powerful, but **excessive requests harm the target (effectively a DoS) and violate the program**. Use automation not for raw speed but to narrow scope safely.

| Risk | Problem | Mitigation |
|---|---|---|
| Unbounded requests | Overloads target server, policy violation | Rate/concurrency limits, avoid peak hours |
| Collecting OOS assets | Scanning out-of-scope hosts | Put an in-scope filter at the front of the pipeline |
| Active-first | Unnecessary noise and load | Passive first (certs/CT logs/DNS) |

### Safe recon (do it yourself)

```python
import time

def throttled(hosts: list[str], in_scope, rps: float = 2.0):
    """In-scope only, capped at rps/sec so the target isn't overloaded."""
    interval = 1.0 / rps
    for h in hosts:
        if not in_scope(h):
            continue  # skip out of scope
        yield h
        time.sleep(interval)  # enforce spacing -> protect the target
```

> Core: good recon is **narrowing scope without harming the target**, not "faster and more". Passive first; active only under a rate limit. Overloading during recon is grounds for violation, not reward (see [[68_Purple_Team]]).
