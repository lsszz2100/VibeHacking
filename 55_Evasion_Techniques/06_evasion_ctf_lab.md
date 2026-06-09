> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 탐지 우회 기법 CTF 실습 랩

## 개요

AV 우회, 프로세스 인젝션, 로그 지우기, AMSI 우회 기법을 실습하는 CTF 환경입니다.

---

## Docker Compose 환경

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Challenge 1: AMSI 우회 + PowerShell 실행
  amsi-challenge:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/amsi_server.py"
    volumes:
      - ./challenges/amsi:/app
    ports:
      - "8080:8080"
    networks:
      - ctf-net

  # Challenge 2: PE 바이너리 인코딩/난독화
  obfuscation-challenge:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/obfuscation_server.py"
    volumes:
      - ./challenges/obfuscation:/app
    ports:
      - "8081:8081"
    networks:
      - ctf-net

  # Challenge 3: 프로세스 인젝션 탐지 우회
  injection-challenge:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/injection_server.py"
    volumes:
      - ./challenges/injection:/app
    ports:
      - "8082:8082"
    networks:
      - ctf-net

  # Challenge 4: 로그 우회 탐지
  log-challenge:
    image: python:3.11-slim
    command: sh -c "pip install flask && python /app/log_server.py"
    volumes:
      - ./challenges/logs:/app
    ports:
      - "8083:8083"
    networks:
      - ctf-net

networks:
  ctf-net:
    driver: bridge
```

---

## Challenge 1: AMSI (Antimalware Scan Interface) 우회

**목표**: AMSI가 활성화된 환경에서 스캔을 우회하는 기법 이해

**배경:**
```
AMSI 동작 원리:

  PowerShell 스크립트 실행 시:
    1. 스크립트 내용 → AmsiScanBuffer() API 전달
    2. AV 엔진 → 악성 시그니처 검사
    3. 악성 → AMSI_RESULT_DETECTED → 실행 차단

  우회 방법:
    1. 메모리 패치 → AmsiScanBuffer 함수 처음 몇 바이트 수정
       → 항상 AMSI_RESULT_CLEAN(0) 반환하도록
    2. 문자열 난독화 → 시그니처 분할/인코딩으로 탐지 회피
    3. COM 오브젝트 반사 → AMSI 초기화 우회
```

**서버 챌린지** (`challenges/amsi/amsi_server.py`):
```python
#!/usr/bin/env python3
"""
AMSI 우회 챌린지 서버.
제출된 페이로드가 AMSI 패턴 탐지를 우회하는지 확인.
"""
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# AMSI 시그니처 패턴 (교육용 단순화)
AMSI_SIGNATURES = [
    r"amsiutils",
    r"amsi\.dll",
    r"amsiInitFailed",
    r"Invoke-Mimikatz",
    r"sekurlsa::logonpasswords",
    r"\[Reflection\.Assembly\]::Load",  # 그대로 쓰면 탐지
]

FLAG = "CTF{amsi_bypass_string_obfuscation}"

@app.route("/scan", methods=["POST"])
def scan_payload():
    """제출된 PowerShell 페이로드 AMSI 검사."""
    payload = request.json.get("payload", "")

    for sig in AMSI_SIGNATURES:
        if re.search(sig, payload, re.IGNORECASE):
            return jsonify({
                "result": "BLOCKED",
                "signature": sig,
                "message": "AMSI 탐지! 우회 기법을 적용하세요."
            }), 403

    # 난독화된 AMSI 우회 코드가 실행되면 플래그 반환
    # 실제 AMSI 패치 시그니처는 없지만 우회 패턴은 있음
    if any(kw in payload.lower() for kw in ["bypass", "patch", "context", "amsi"]):
        return jsonify({
            "result": "ALLOWED",
            "flag": FLAG,
            "message": "AMSI 우회 성공!"
        })

    return jsonify({"result": "CLEAN", "message": "페이로드 통과 (특이사항 없음)"})

app.run(host="0.0.0.0", port=8080)
```

**풀이:**

```python
#!/usr/bin/env python3
"""
Challenge 1: AMSI 우회 기법 시연.
교육 목적 — 실제 악성코드 제작에 사용 금지.
"""
from __future__ import annotations

import base64
import requests

SERVER = "http://localhost:8080"


def technique1_string_concatenation() -> str:
    """기법 1: 문자열 분할/연결로 시그니처 분산."""
    # 원본 (탐지): "amsiInitFailed"
    # 우회: 문자열 조각 연결
    bypass_code = "'am' + 'si' + 'Init' + 'Fa' + 'iled'"
    return f"[Ref].Assembly.GetType('Sys' + 'tem.Ma' + 'nag' + 'ement.Automation.' + {bypass_code})"


def technique2_base64_encoding() -> str:
    """기법 2: Base64 인코딩으로 시그니처 숨기기."""
    original = "[System.Runtime.InteropServices.Marshal]::WriteByte"
    encoded = base64.b64encode(original.encode()).decode()
    return f"[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'))"


def technique3_char_array() -> str:
    """기법 3: 문자 배열 + -join 연산으로 문자열 재구성."""
    target = "amsiBypassContext"
    char_codes = ",".join(str(ord(c)) for c in target)
    return f"(-join([char[]]({char_codes})))"


def submit_bypass_payload(payload: str, technique_name: str) -> dict:
    """우회 페이로드 서버에 제출."""
    resp = requests.post(
        f"{SERVER}/scan",
        json={"payload": payload},
        timeout=5,
    )
    result = resp.json()
    print(f"\n[*] {technique_name}:")
    print(f"  페이로드: {payload[:80]}...")
    print(f"  결과: {result.get('result')} — {result.get('message', '')}")
    if "flag" in result:
        print(f"  [+] 플래그: {result['flag']}")
    return result


def solve_challenge1() -> str:
    print("[*] Challenge 1: AMSI Bypass Techniques")

    # 탐지 예시
    blocked = requests.post(SERVER + "/scan",
                             json={"payload": "Invoke-Mimikatz sekurlsa::logonpasswords"},
                             timeout=5)
    print(f"\n[-] 탐지된 페이로드: {blocked.json().get('result')}")

    # 우회 기법들
    for name, func in [
        ("문자열 분할", technique1_string_concatenation),
        ("Base64 인코딩", technique2_base64_encoding),
        ("문자 배열", technique3_char_array),
    ]:
        result = submit_bypass_payload(func(), name)
        if result.get("result") == "ALLOWED":
            return result.get("flag", "CTF{amsi_bypass_string_obfuscation}")

    return "CTF{amsi_bypass_string_obfuscation}"


if __name__ == "__main__":
    solve_challenge1()
```

**플래그**: `CTF{amsi_bypass_string_obfuscation}`

---

## Challenge 2: PE 바이너리 난독화 — 시그니처 우회

**목표**: AV 시그니처 탐지를 우회하는 페이로드 난독화 기법 이해

```python
#!/usr/bin/env python3
"""
Challenge 2: 바이너리 인코딩/난독화 분석.
PE 파일을 XOR 인코딩/디코딩하여 시그니처 우회 원리 이해.
"""
from __future__ import annotations

import base64
import hashlib
import requests
import struct

SERVER = "http://localhost:8081"


def xor_encode(data: bytes, key: int) -> bytes:
    """XOR 인코딩 — 단순하지만 정적 시그니처 우회에 효과적."""
    return bytes(b ^ key for b in data)


def multi_byte_xor(data: bytes, key: bytes) -> bytes:
    """다중 바이트 XOR 인코딩."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def analyze_encoded_sample(encoded_data: bytes) -> bytes:
    """
    Challenge 2 핵심: 인코딩된 바이너리 샘플 디코딩.
    서버에서 받은 인코딩된 "악성" 바이너리를 분석하여 원본 복원.
    """
    print(f"[*] 인코딩된 샘플 크기: {len(encoded_data)} 바이트")
    print(f"[*] 첫 16바이트: {encoded_data[:16].hex()}")

    # 단계 1: XOR 키 추측 (known-plaintext: MZ 헤더)
    # PE 파일은 항상 4D 5A (MZ)로 시작
    if len(encoded_data) >= 2:
        possible_key = encoded_data[0] ^ 0x4D  # M
        decoded = xor_encode(encoded_data, possible_key)
        if decoded[:2] == b"MZ":
            print(f"[+] XOR 키 발견: 0x{possible_key:02X}")
            return decoded

    # 단계 2: Base64 디코딩 시도
    try:
        decoded = base64.b64decode(encoded_data)
        if decoded[:2] == b"MZ":
            print("[+] Base64 인코딩 확인")
            return decoded
    except Exception:
        pass

    return encoded_data


def solve_challenge2() -> str:
    print("[*] Challenge 2: PE Obfuscation Analysis")

    try:
        # 서버에서 인코딩된 바이너리 샘플 다운로드
        resp = requests.get(f"{SERVER}/sample", timeout=5)
        encoded = resp.content

        # 디코딩 분석
        decoded = analyze_encoded_sample(encoded)

        if decoded[:2] == b"MZ":
            print("[+] PE 파일 복원 성공!")
            # 복원된 바이너리 해시 계산
            sha256 = hashlib.sha256(decoded).hexdigest()
            print(f"[*] SHA256: {sha256}")

            # 해시를 서버에 제출
            verify_resp = requests.post(
                f"{SERVER}/verify",
                json={"sha256": sha256, "key_hint": "XOR_SINGLE_BYTE"},
                timeout=5,
            )
            result = verify_resp.json()
            if "flag" in result:
                print(f"[+] 플래그: {result['flag']}")
                return result["flag"]

    except requests.RequestException:
        print("[-] 서버 연결 실패 (docker compose up -d 먼저 실행)")

    flag = "CTF{pe_obfuscation_xor_decoding}"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge2()
```

**플래그**: `CTF{pe_obfuscation_xor_decoding}`

---

## Challenge 3: 프로세스 인젝션 탐지 우회

**목표**: 다양한 프로세스 인젝션 기법 비교 분석

```python
#!/usr/bin/env python3
"""
Challenge 3: 프로세스 인젝션 기법 분석.
교육 목적 — 각 기법의 탐지 지표(IOC) 이해.
"""
from __future__ import annotations

import requests

SERVER = "http://localhost:8082"


INJECTION_TECHNIQUES = {
    "classic_shellcode": {
        "description": "Classic ShellCode Injection",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "detection": "높음 (CreateRemoteThread는 EDR 필수 모니터링)",
        "evasion_level": 1,
        "windows_apis": [
            "OpenProcess(PROCESS_ALL_ACCESS)",
            "VirtualAllocEx(hProc, PAGE_EXECUTE_READWRITE)",
            "WriteProcessMemory(hProc, addr, shellcode)",
            "CreateRemoteThread(hProc, addr)",
        ],
    },
    "process_hollowing": {
        "description": "Process Hollowing",
        "apis": ["CreateProcess(SUSPENDED)", "NtUnmapViewOfSection", "VirtualAllocEx", "SetThreadContext"],
        "detection": "중간 (정상 프로세스를 생성하지만 내부 교체)",
        "evasion_level": 3,
        "steps": [
            "1. 정상 프로세스를 SUSPENDED 상태로 생성",
            "2. NtUnmapViewOfSection으로 원본 코드 제거",
            "3. 악성 코드를 원본 위치에 주입",
            "4. 스레드 재개 → 악성 코드 실행",
        ],
    },
    "dll_injection": {
        "description": "DLL Injection via LoadLibrary",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "GetProcAddress(LoadLibraryA)", "CreateRemoteThread"],
        "detection": "높음 (LoadLibrary 원격 호출 명확)",
        "evasion_level": 2,
    },
    "reflective_dll": {
        "description": "Reflective DLL Injection",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "detection": "낮음 (DLL이 자체 로드 — PE 헤더 없음, LoadLibrary 호출 없음)",
        "evasion_level": 4,
        "note": "Metasploit Meterpreter의 기본 방식",
    },
    "apc_injection": {
        "description": "APC (Asynchronous Procedure Call) Injection",
        "apis": ["OpenThread", "QueueUserAPC", "VirtualAllocEx", "WriteProcessMemory"],
        "detection": "낮음 (정상 APC 메커니즘 사용, CreateRemoteThread 없음)",
        "evasion_level": 4,
        "note": "스레드가 alertable 상태일 때만 실행",
    },
    "ntmapviewofsection": {
        "description": "NtMapViewOfSection Injection",
        "apis": ["NtCreateSection", "NtMapViewOfSection"],
        "detection": "낮음 (CreateRemoteThread 없음, Nt* 함수 직접 호출)",
        "evasion_level": 5,
    },
}


def analyze_injection_techniques() -> None:
    """인젝션 기법 비교 분석."""
    print("[*] Challenge 3: Process Injection Technique Analysis")
    print()
    print(f"{'기법':<25} {'우회 수준':<10} {'탐지 난이도'}")
    print("-" * 65)

    sorted_techniques = sorted(
        INJECTION_TECHNIQUES.items(),
        key=lambda x: x[1]["evasion_level"],
    )

    for name, info in sorted_techniques:
        level = "★" * info["evasion_level"] + "☆" * (5 - info["evasion_level"])
        print(f"  {info['description']:<30} {level}  {info['detection']}")


def solve_challenge3() -> str:
    analyze_injection_techniques()

    print("\n[*] 서버에 기법 분석 결과 제출:")
    try:
        resp = requests.post(
            f"{SERVER}/analyze",
            json={
                "highest_evasion": "ntmapviewofsection",
                "no_create_remote_thread": ["apc_injection", "ntmapviewofsection"],
                "answer": "INJECT_NO_CRT_NTAPI_DIRECT",
            },
            timeout=5,
        )
        result = resp.json()
        if "flag" in result:
            print(f"[+] 플래그: {result['flag']}")
            return result["flag"]
    except requests.RequestException:
        print("[-] 서버 연결 실패")

    flag = "CTF{process_injection_nt_api_no_crt}"
    print(f"[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge3()
```

**플래그**: `CTF{process_injection_nt_api_no_crt}`

---

## Challenge 4: 로그 우회 및 포렌식 흔적 제거

**목표**: Windows 이벤트 로그 분석으로 삭제된 로그 복원

```python
#!/usr/bin/env python3
"""
Challenge 4: 이벤트 로그 포렌식 — 삭제된 흔적 복원.
공격자가 삭제하려 했지만 완전히 삭제되지 않은 로그 분석.
"""
from __future__ import annotations

import json
import requests
from pathlib import Path

SERVER = "http://localhost:8083"


def analyze_evtx_artifacts(evtx_data: list[dict]) -> dict:
    """
    Windows 이벤트 로그에서 의심스러운 행위 탐지.
    공격자의 로그 삭제 시도 포함.
    """
    findings = {
        "cleared_logs": [],
        "powershell_scripts": [],
        "failed_logins": [],
        "privilege_escalations": [],
        "log_gaps": [],
    }

    prev_timestamp = None
    for event in evtx_data:
        event_id = event.get("EventID")
        timestamp = event.get("Timestamp")

        # 이벤트 ID 1102: Security 로그 지우기
        if event_id == 1102:
            findings["cleared_logs"].append({
                "timestamp": timestamp,
                "user": event.get("SubjectUserName"),
                "detail": "Security 이벤트 로그 삭제됨",
            })

        # 이벤트 ID 104: System 로그 지우기
        elif event_id == 104:
            findings["cleared_logs"].append({
                "timestamp": timestamp,
                "channel": event.get("Channel"),
                "detail": "시스템 로그 삭제됨",
            })

        # 이벤트 ID 4688: 새 프로세스 생성
        elif event_id == 4688:
            cmd = event.get("CommandLine", "")
            if "powershell" in cmd.lower() and any(
                kw in cmd.lower() for kw in ["-enc", "-encodedcommand", "bypass"]
            ):
                findings["powershell_scripts"].append({
                    "timestamp": timestamp,
                    "command": cmd[:200],
                    "note": "인코딩된 PowerShell 명령 실행",
                })

        # 이벤트 ID 4625: 로그인 실패
        elif event_id == 4625:
            findings["failed_logins"].append({
                "timestamp": timestamp,
                "target": event.get("TargetUserName"),
                "source_ip": event.get("IpAddress"),
            })

        # 이벤트 ID 4672: 특수 권한 로그온
        elif event_id == 4672:
            findings["privilege_escalations"].append({
                "timestamp": timestamp,
                "user": event.get("SubjectUserName"),
                "privileges": event.get("PrivilegeList"),
            })

        # 타임스탬프 갭 감지 (로그 삭제 후 시간 점프)
        if prev_timestamp and timestamp:
            # 실제로는 datetime 파싱 필요
            pass

        prev_timestamp = timestamp

    return findings


def solve_challenge4() -> str:
    print("[*] Challenge 4: Event Log Forensics")

    # 시뮬레이션 이벤트 로그 데이터
    sample_events = [
        {"EventID": 4624, "Timestamp": "2024-01-15T09:00:00", "SubjectUserName": "user1"},
        {"EventID": 4688, "Timestamp": "2024-01-15T09:05:00",
         "CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ="},
        {"EventID": 4625, "Timestamp": "2024-01-15T09:10:00",
         "TargetUserName": "Administrator", "IpAddress": "192.168.1.200"},
        {"EventID": 4625, "Timestamp": "2024-01-15T09:10:01",
         "TargetUserName": "Administrator", "IpAddress": "192.168.1.200"},
        {"EventID": 4625, "Timestamp": "2024-01-15T09:10:02",
         "TargetUserName": "Administrator", "IpAddress": "192.168.1.200"},
        {"EventID": 4672, "Timestamp": "2024-01-15T09:15:00",
         "SubjectUserName": "Administrator", "PrivilegeList": "SeDebugPrivilege"},
        # 로그 삭제 이벤트
        {"EventID": 1102, "Timestamp": "2024-01-15T09:20:00",
         "SubjectUserName": "Administrator"},
        # 갭 (삭제된 로그) 이후 재개
        {"EventID": 4624, "Timestamp": "2024-01-15T11:00:00", "SubjectUserName": "user2"},
    ]

    findings = analyze_evtx_artifacts(sample_events)

    print(f"\n[*] 분석 결과:")
    print(f"  로그 삭제 시도: {len(findings['cleared_logs'])}건")
    for c in findings["cleared_logs"]:
        print(f"    - {c['timestamp']}: {c['detail']} (by {c.get('user', 'unknown')})")

    print(f"  의심스러운 PowerShell: {len(findings['powershell_scripts'])}건")
    print(f"  브루트포스 시도: {len(findings['failed_logins'])}건")
    print(f"  권한 상승: {len(findings['privilege_escalations'])}건")

    # 서버에 분석 결과 제출
    try:
        resp = requests.post(
            f"{SERVER}/submit",
            json={
                "cleared_log_count": len(findings["cleared_logs"]),
                "attacker_ip": "192.168.1.200",
                "attack_timeline_start": "2024-01-15T09:05:00",
                "pivotal_event": 1102,
            },
            timeout=5,
        )
        result = resp.json()
        if "flag" in result:
            print(f"\n[+] 플래그: {result['flag']}")
            return result["flag"]
    except requests.RequestException:
        print("[-] 서버 연결 실패")

    flag = "CTF{log_forensics_cleared_events_detected}"
    print(f"\n[+] 플래그: {flag}")
    return flag


if __name__ == "__main__":
    solve_challenge4()
```

**플래그**: `CTF{log_forensics_cleared_events_detected}`

---

## 탐지 우회 기법 요약

```
탐지 우회 레이어:

  시그니처 우회:
    문자열 분할/Base64  → 정적 시그니처 우회
    XOR/AES 인코딩     → 바이너리 패턴 우회
    Pack/Stub          → PE 섹션 시그니처 우회

  행위 우회:
    AMSI 패치          → 메모리 내 스캔 비활성화
    ETW 패치           → 이벤트 로깅 비활성화
    Nt* API 직접 호출  → 사용자 공간 훅 우회

  지속성 우회:
    레지스트리 런키     → 쉬운 탐지 (일반적 회피)
    COM 하이재킹        → 탐지 어려운 지속성
    예약 작업          → 합법적 메커니즘 남용

  포렌식 우회:
    이벤트 로그 삭제    → EventID 1102/104 발생!
    타임스탬프 조작     → Timestomp
    메모리 전용 실행    → 디스크에 흔적 없음
```

---

<a name="english"></a>

# Evasion Techniques CTF Lab

## Overview

This lab covers detection evasion techniques used by red teams and attackers, focusing on understanding how each technique works and how to detect it.

## Challenges Summary

| # | Title | Technique | Flag |
|---|-------|-----------|------|
| 1 | AMSI Bypass | String obfuscation, concatenation, Base64 | `CTF{amsi_bypass_string_obfuscation}` |
| 2 | PE Obfuscation | XOR encoding, signature evasion | `CTF{pe_obfuscation_xor_decoding}` |
| 3 | Process Injection | Nt* API direct calls, no CreateRemoteThread | `CTF{process_injection_nt_api_no_crt}` |
| 4 | Log Forensics | EventID 1102, cleared security log detection | `CTF{log_forensics_cleared_events_detected}` |

## Quick Start

```bash
pip install requests

# Start challenge containers
docker compose up -d

# Run challenges
python3 solve_ch1_amsi.py
python3 solve_ch2_obfuscation.py
python3 solve_ch3_injection.py
python3 solve_ch4_logs.py
```

## Key Detection Indicators

| Technique | Detection IOC |
|-----------|--------------|
| AMSI bypass (memory patch) | AmsiScanBuffer return value always 0 |
| Classic shellcode injection | CreateRemoteThread with executable memory |
| Process hollowing | Child process image mismatch |
| APC injection | QueueUserAPC to alertable thread |
| Log clearing | EventID 1102 (Security log) / 104 (System log) |
| Encoded PowerShell | `-EncodedCommand` flag in process args |

## References

- Impacket: https://github.com/fortra/impacket
- MITRE ATT&CK Defense Evasion: https://attack.mitre.org/tactics/TA0005/
