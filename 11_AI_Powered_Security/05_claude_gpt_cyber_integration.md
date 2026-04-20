# AI 통합 — Claude + GPT-5.4-Cyber 보안 분석 도구 활용법

## 1. 모델 선택 가이드

```
작업별 최적 모델:

┌─────────────────────────────┬──────────────────┬──────────────────┐
│ 작업                         │ 1순위            │ 2순위            │
├─────────────────────────────┼──────────────────┼──────────────────┤
│ 소스코드 취약점 분석           │ Claude Opus 4.6  │ GPT-5.4          │
│ 바이너리 리버스 엔지니어링      │ GPT-5.4-Cyber    │ Claude Opus 4.6  │
│ 악성코드 샘플 분석             │ GPT-5.4-Cyber    │ Claude Opus 4.6  │
│ YARA/Sigma 룰 작성            │ GPT-5.4-Cyber    │ Claude Opus 4.6  │
│ CTF — 웹/포렌식               │ Claude Opus 4.6  │ GPT-5.4          │
│ CTF — 리버싱/바이너리          │ GPT-5.4-Cyber    │ Claude Opus 4.6  │
│ 보안 코드 자동 리뷰 파이프라인   │ Claude Opus 4.6  │ —                │
│ SIEM 룰 생성 (Splunk/Sigma)   │ GPT-5.4-Cyber    │ Claude Opus 4.6  │
│ 침투 테스트 보고서 작성         │ Claude Opus 4.6  │ GPT-5.4          │
│ 제로데이 연구 (TAC 인증 후)     │ GPT-5.4-Cyber    │ Claude Mythos    │
└─────────────────────────────┴──────────────────┴──────────────────┘

접근 방법:
  Claude Opus 4.6  → claude.ai 또는 Anthropic API (누구나)
  GPT-5.4          → chatgpt.com (누구나)
  GPT-5.4-Cyber    → chatgpt.com/cyber (TAC 인증 필요)
  Claude Mythos    → Project Glasswing (기업 파트너 한정)
```

---

## 2. GPT-5.4-Cyber TAC 접근 방법

### 2-1. 개인 인증 (chatgpt.com/cyber)

```
필요 요건:
  - 보안 직업 자격 증명 (OSCP, CISSP, CEH, 버그바운티 프로필 등)
  - 정부 발급 신분증 (KYC 자동 검증)
  - 합법적 방어 목적 확인

인증 티어:
  Tier 1 — 기본 인증
    대상: 신원 확인된 개인 보안 전문가
    접근: 사이버 마찰이 낮은 기존 모델 버전
    방법: chatgpt.com/cyber 에서 자격 증명 제출

  Tier 2 — 고급 인증
    대상: Tier 1에서 추가 검증을 원하는 사람
    접근: GPT-5.4-Cyber 직접 접근
    방법: Tier 1 완료 후 추가 인증 요청

  Tier 3 — 엔터프라이즈
    대상: 보안 벤더, 리서치 기관, 대규모 팀
    접근: GPT-5.4-Cyber + 팀 단위 관리
    방법: OpenAI 영업 담당자 통해 신청

승인 후 사용 가능한 작업:
  ✔ 보안 교육 (Security Education)
  ✔ 방어 프로그래밍 (Defensive Programming)
  ✔ 책임있는 취약점 연구 (Responsible Vulnerability Research)
  ✔ 악성코드 샘플 분석 (허가된 환경)
  ✔ 바이너리 리버스 엔지니어링
  ✔ SIEM/IDS 룰 작성
```

### 2-2. 기업/팀 접근

```
OpenAI 담당자 통한 팀 신청:
  - 조직 단위로 TAC 접근 요청
  - 더 높은 사용량 한도
  - 전용 지원 채널
  - 제로 데이터 보유(ZDR) 옵션 (단, 일부 기능 제한)

주의: ZDR(Zero Data Retention) 배포 시
  - OpenAI가 사용자 의도를 파악하기 어려워짐
  - 일부 고급 Cyber 기능 접근 제한될 수 있음
```

---

## 3. Claude API로 보안 분석 도구 구축

### 3-1. 소스코드 취약점 자동 스캐너

```python
import anthropic
import subprocess
import json
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

client = anthropic.Anthropic()

VULN_SYSTEM_PROMPT = """당신은 전문 보안 코드 리뷰어입니다.
코드를 분석하여 OWASP Top 10, CWE Top 25, CVE 패턴에 근거한
취약점을 찾아냅니다.

응답 형식 (JSON):
{
  "vulnerabilities": [
    {
      "type": "취약점 유형",
      "cwe": "CWE-XXX",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "line": 줄번호,
      "description": "설명",
      "exploit_scenario": "익스플로잇 시나리오",
      "fix": "수정 방법"
    }
  ],
  "summary": "전체 요약"
}"""

def analyze_file(file_path: Path) -> dict:
    code = file_path.read_text(errors="replace")
    if len(code) > 50_000:
        code = code[:50_000] + "\n[잘림 — 파일 너무 큼]"

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        system=VULN_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"파일: {file_path.name}\n\n```\n{code}\n```"
        }]
    )
    try:
        return json.loads(resp.content[0].text)
    except json.JSONDecodeError:
        return {"raw": resp.content[0].text, "vulnerabilities": []}

def scan_directory(target_dir: str, extensions: list[str] | None = None) -> None:
    extensions = extensions or [".py", ".js", ".ts", ".php", ".go", ".java", ".c", ".cpp"]
    target = Path(target_dir)
    files = [f for f in target.rglob("*") if f.suffix in extensions]

    print(f"[*] {len(files)}개 파일 스캔 시작")
    all_vulns: list[dict] = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(analyze_file, f): f for f in files}
        for future in as_completed(futures):
            path = futures[future]
            result = future.result()
            vulns = result.get("vulnerabilities", [])
            if vulns:
                print(f"\n[!] {path.name} — {len(vulns)}개 취약점")
                for v in vulns:
                    sev = v.get("severity", "?")
                    vtype = v.get("type", "?")
                    cwe = v.get("cwe", "")
                    print(f"    [{sev}] {vtype} {cwe}")
                    print(f"    └─ {v.get('description', '')}")
                all_vulns.extend(
                    {"file": str(path), **v} for v in vulns
                )

    critical = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
    high     = [v for v in all_vulns if v.get("severity") == "HIGH"]
    print(f"\n[결과] CRITICAL: {len(critical)}, HIGH: {len(high)}, 총: {len(all_vulns)}")

if __name__ == "__main__":
    scan_directory(sys.argv[1] if len(sys.argv) > 1 else ".")
```

### 3-2. 악성코드 IOC 자동 추출기

```python
import anthropic
import re
import json
import argparse
from pathlib import Path

client = anthropic.Anthropic()

IOC_SYSTEM_PROMPT = """악성코드 분석 전문가입니다.
제공된 코드/문자열에서 IOC를 추출하고 분석합니다.

JSON 형식 응답:
{
  "iocs": {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": [],
    "registry_keys": [],
    "file_paths": [],
    "mutexes": []
  },
  "behavior": {
    "persistence": [],
    "c2_communication": [],
    "anti_analysis": [],
    "lateral_movement": []
  },
  "family": "악성코드 패밀리 추정",
  "confidence": "HIGH|MEDIUM|LOW"
}"""

def extract_iocs(sample_path: str) -> dict:
    content = Path(sample_path).read_text(errors="replace")

    # 정규식으로 1차 추출
    ips      = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    domains  = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', content)
    hashes   = re.findall(r'\b[a-fA-F0-9]{32,64}\b', content)

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        system=IOC_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                f"샘플 파일: {sample_path}\n\n"
                f"정규식 1차 추출:\nIPs: {ips[:20]}\nDomains: {domains[:20]}\nHashes: {hashes[:10]}\n\n"
                f"전체 내용:\n```\n{content[:8000]}\n```"
            )
        }]
    )

    try:
        result = json.loads(resp.content[0].text)
    except json.JSONDecodeError:
        result = {"raw": resp.content[0].text}

    result.setdefault("regex_extracted", {"ips": ips, "domains": domains, "hashes": hashes})
    return result

def main() -> None:
    parser = argparse.ArgumentParser(description="AI 기반 IOC 추출기")
    parser.add_argument("sample", help="분석할 파일 경로")
    parser.add_argument("--output", "-o", help="JSON 출력 파일")
    args = parser.parse_args()

    print(f"[*] IOC 추출 시작: {args.sample}")
    result = extract_iocs(args.sample)

    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(f"[+] 저장: {args.output}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
```

---

## 4. GPT-5.4-Cyber 활용 — 바이너리 분석 워크플로우

### 4-1. 바이너리 분석 프롬프트 패턴

```
[기본 바이너리 분석 요청]

사전 준비:
  $ objdump -d target_binary > disasm.txt
  $ strings target_binary > strings.txt
  $ readelf -a target_binary > elf_info.txt

GPT-5.4-Cyber 에 제출할 프롬프트 구조:

---
역할: 바이너리 리버스 엔지니어링 전문가

다음 바이너리 분석 결과를 바탕으로:
1. 악성코드 여부 판단
2. 취약점 클래스 식별 (BOF, UAF, 포맷스트링 등)
3. C2 통신 패턴 (있다면)
4. 안티분석 기법 식별
5. YARA 룰 생성

[disasm.txt 내용 붙여넣기]
[strings.txt 내용 붙여넣기]
---
```

### 4-2. YARA 룰 자동 생성 파이프라인

```python
import subprocess
import anthropic
import argparse
from pathlib import Path

client = anthropic.Anthropic()

YARA_SYSTEM = """악성코드 분석가입니다. 제공된 바이너리 분석 데이터로
정확한 YARA 룰을 생성합니다.

룰 형식:
rule MalwareName_Variant {
    meta:
        description = "..."
        author = "AI-Generated"
        date = "YYYY-MM-DD"
        hash = "..."
    strings:
        $s1 = "..."
        $hex1 = { ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}"""

def extract_binary_info(binary_path: str) -> dict[str, str]:
    results: dict[str, str] = {}
    cmds = {
        "strings": ["strings", "-n", "6", binary_path],
        "imports": ["objdump", "-p", binary_path],
        "sections": ["objdump", "-h", binary_path],
        "disasm":   ["objdump", "-d", "--no-show-raw-insn", binary_path],
    }
    for key, cmd in cmds.items():
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
            results[key] = out[:5000]
        except Exception as e:
            results[key] = f"실패: {e}"
    return results

def generate_yara_rule(binary_path: str) -> str:
    info = extract_binary_info(binary_path)
    prompt = "\n\n".join(
        f"### {k.upper()}\n{v}" for k, v in info.items()
    )

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,
        system=YARA_SYSTEM,
        messages=[{"role": "user", "content": f"바이너리: {binary_path}\n\n{prompt}"}]
    )
    return resp.content[0].text

def main() -> None:
    parser = argparse.ArgumentParser(description="YARA 룰 자동 생성기")
    parser.add_argument("binary", help="분석할 바이너리")
    parser.add_argument("--output", "-o", default="generated.yar")
    args = parser.parse_args()

    rule = generate_yara_rule(args.binary)
    Path(args.output).write_text(rule)
    print(rule)
    print(f"\n[+] YARA 룰 저장: {args.output}")

if __name__ == "__main__":
    main()
```

---

## 5. 두 모델 조합 — 분석 파이프라인

### 5-1. Claude(코드 분석) + GPT-5.4-Cyber(바이너리) 이중 분석

```
실전 워크플로우:

[1단계] Claude Opus 4.6 — 소스코드 리뷰
  → 소스가 있는 경우 코드베이스 전체 정적 분석
  → 취약한 함수 / 라인 식별
  → 수정 코드 자동 생성

[2단계] GPT-5.4-Cyber — 컴파일된 바이너리 교차 검증
  → 1단계에서 찾은 취약점이 컴파일 후에도 존재하는지 확인
  → 컴파일러 최적화로 인한 새 취약점 식별
  → 실제 익스플로잇 가능성 평가

[3단계] Claude Opus 4.6 — 보고서 작성
  → 두 분석 결과 통합
  → CVSS 점수 산정
  → 수정 우선순위 정렬
  → 경영진/개발팀 보고서 생성

이중 분석의 장점:
  - 정적 분석 + 바이너리 분석 = 더 높은 취약점 발견률
  - 오탐(False Positive) 교차 검증
  - 소스-바이너리 불일치 감지 (빌드 공급망 공격 탐지)
```

### 5-2. 자동화 스크립트 예시

```python
import anthropic
import subprocess
import sys
import json
from pathlib import Path

client = anthropic.Anthropic()

def dual_analysis(source_path: str | None, binary_path: str | None) -> dict:
    results: dict[str, object] = {}

    # Claude — 소스코드 분석
    if source_path and Path(source_path).exists():
        code = Path(source_path).read_text(errors="replace")[:30_000]
        resp = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            system="보안 코드 리뷰어. JSON으로 취약점 목록 반환.",
            messages=[{"role": "user", "content": f"```\n{code}\n```"}]
        )
        try:
            results["source_analysis"] = json.loads(resp.content[0].text)
        except json.JSONDecodeError:
            results["source_analysis"] = {"raw": resp.content[0].text}

    # 바이너리 정보 추출 (GPT-5.4-Cyber에 제출용)
    if binary_path and Path(binary_path).exists():
        strings_out = subprocess.run(
            ["strings", "-n", "6", binary_path],
            capture_output=True, text=True
        ).stdout[:5000]
        disasm_out = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", binary_path],
            capture_output=True, text=True
        ).stdout[:5000]
        results["binary_info"] = {
            "strings": strings_out,
            "disasm": disasm_out,
            "note": "이 데이터를 GPT-5.4-Cyber(chatgpt.com/cyber)에 제출하여 바이너리 분석 완료"
        }

    return results

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="이중 AI 보안 분석")
    parser.add_argument("--source", "-s", help="소스코드 경로")
    parser.add_argument("--binary", "-b", help="바이너리 경로")
    parser.add_argument("--output", "-o", default="dual_analysis.json")
    args = parser.parse_args()

    result = dual_analysis(args.source, args.binary)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"[+] 분석 완료 → {args.output}")

if __name__ == "__main__":
    main()
```

---

## 6. SIEM 룰 자동 생성 (Claude API)

```python
import anthropic
import argparse
from pathlib import Path

client = anthropic.Anthropic()

SIEM_SYSTEM = """SIEM 엔지니어. 악성 행위 설명을 Sigma 룰과 Splunk SPL로 변환합니다.

응답 형식:
## Sigma Rule
```yaml
[sigma 룰]
```

## Splunk SPL
```
[SPL 쿼리]
```

## 탐지 논리 설명
[설명]"""

def generate_siem_rule(behavior_desc: str, log_sample: str = "") -> str:
    content = f"악성 행위:\n{behavior_desc}"
    if log_sample:
        content += f"\n\n로그 샘플:\n```\n{log_sample[:3000]}\n```"

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=3000,
        system=SIEM_SYSTEM,
        messages=[{"role": "user", "content": content}]
    )
    return resp.content[0].text

def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM 룰 자동 생성기")
    parser.add_argument("behavior", help="탐지할 악성 행위 설명")
    parser.add_argument("--log-sample", "-l", help="로그 샘플 파일 경로")
    parser.add_argument("--output", "-o", help="출력 파일")
    args = parser.parse_args()

    log_sample = ""
    if args.log_sample:
        log_sample = Path(args.log_sample).read_text(errors="replace")

    rule = generate_siem_rule(args.behavior, log_sample)
    print(rule)

    if args.output:
        Path(args.output).write_text(rule)
        print(f"\n[+] 저장: {args.output}")

if __name__ == "__main__":
    main()
```

---

## 7. 주의사항 및 윤리 가이드라인

```
합법적 사용 범위:
  ✔ 허가받은 침투 테스트 (서면 계약 필수)
  ✔ 본인 소유 시스템 분석
  ✔ CTF 챌린지
  ✔ 버그바운티 (허가된 스코프만)
  ✔ 악성코드 샘플 분석 (격리된 환경)
  ✔ SIEM/IDS 룰 작성 (방어 목적)

절대 금지:
  ✗ 무단 외부 시스템 침투
  ✗ 취약점 정보 무단 공개 (Responsible Disclosure 필수)
  ✗ 데이터 유출 목적 사용
  ✗ 실제 공격 코드 생성 요청

TAC 접근 후에도:
  - 이용 약관 준수 의무 (GPT-5.4-Cyber도 동일)
  - 의심 활동 감지 시 자동으로 GPT-5.2로 강등
  - 심각한 위반 시 계정 영구 차단
```

---

## 8. 관련 리소스

| 리소스 | URL |
|--------|-----|
| GPT-5.4-Cyber 접근 (TAC 인증) | chatgpt.com/cyber |
| Claude API 공식 문서 | docs.anthropic.com |
| OpenAI TAC 공식 블로그 | openai.com/index/scaling-trusted-access-for-cyber-defense |
| Anthropic 레드팀 연구 | red.anthropic.com |
| Project Glasswing 문의 | glasswing@anthropic.com |
| OpenAI 기업 TAC 신청 | OpenAI 영업 담당자 통해 |
