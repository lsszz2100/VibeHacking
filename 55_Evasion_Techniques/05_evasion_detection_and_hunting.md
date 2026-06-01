> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 탐지 회피 기법 사냥 (Threat Hunting)

공격자가 사용하는 탐지 회피 기법을 적극적으로 찾아내는 위협 헌팅 방법론을 다룬다. 가설 기반 헌팅, YARA/Sigma 룰 개발, 메모리 포렌식 기반 회피 기법 발견을 정리한다.

---

## 1. 위협 헌팅 방법론

### 1.1 헌팅 사이클

```
1. 가설 설정
   └── "공격자가 LOLBAS로 PowerShell 없이 실행할 것이다"
   └── "의심 프로세스가 certutil로 파일을 다운로드한다"

2. 데이터 수집
   └── Sysmon 로그, EDR 텔레메트리, 넷플로우

3. 분석 및 탐지
   └── 이상 기준선 비교, 클러스터링, 패턴 매칭

4. 결과 대응
   └── 탐지 룰 생성, 인시던트 에스컬레이션

5. 피드백 루프
   └── 놓친 기법 분석 → 다음 가설 수립
```

### 1.2 가설 기반 헌팅 예시

```python
#!/usr/bin/env python3
"""가설 기반 위협 헌팅 자동화 프레임워크"""
import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional


@dataclass
class HuntHypothesis:
    id: str
    title: str
    description: str
    mitre_attack: str
    data_sources: list[str]
    hunt_function: str  # 함수명 참조
    confidence: str     # High / Medium / Low


HUNT_HYPOTHESES: list[HuntHypothesis] = [
    HuntHypothesis(
        "H-001", "LOLBAS 파일 다운로드",
        "certutil, bitsadmin, mshta를 통한 원격 파일 다운로드",
        "T1218",
        ["Sysmon EventID 1", "CommandLine"],
        "hunt_lolbas_download",
        "High",
    ),
    HuntHypothesis(
        "H-002", "인코딩된 PowerShell 실행",
        "-EncodedCommand 또는 -enc 플래그로 숨겨진 PowerShell 실행",
        "T1059.001",
        ["Sysmon EventID 1", "ScriptBlock Logging"],
        "hunt_encoded_powershell",
        "High",
    ),
    HuntHypothesis(
        "H-003", "비정상적인 서비스 설치",
        "sc.exe 또는 API를 통한 의심 서비스 생성",
        "T1543.003",
        ["Windows EventID 7045", "Registry"],
        "hunt_suspicious_services",
        "Medium",
    ),
    HuntHypothesis(
        "H-004", "메모리 내 코드 실행",
        "디스크에 파일 없이 메모리에서 직접 코드 실행",
        "T1620",
        ["Sysmon EventID 8 (CreateRemoteThread)", "EDR"],
        "hunt_fileless_execution",
        "High",
    ),
    HuntHypothesis(
        "H-005", "자격증명 액세스",
        "LSASS 프로세스 메모리 덤프 시도",
        "T1003.001",
        ["Sysmon EventID 10 (ProcessAccess)", "EDR"],
        "hunt_lsass_access",
        "Critical",
    ),
]


class ThreatHunter:
    def __init__(self, logs_path: str) -> None:
        self.logs_path = logs_path
        self.results: list[dict] = []

    def load_logs(self) -> list[dict]:
        try:
            with open(self.logs_path) as f:
                return [json.loads(line) for line in f if line.strip()]
        except Exception:
            return []

    def hunt_lolbas_download(self, logs: list[dict]) -> list[dict]:
        findings = []
        lolbas_cmds = {
            "certutil.exe": ["-urlcache", "-f", "-decode"],
            "bitsadmin.exe": ["/transfer", "/download"],
            "mshta.exe": ["http://", "https://"],
            "regsvr32.exe": ["/s", "/u", "/i:http"],
        }

        for log in logs:
            event_id = log.get("EventID", 0)
            if event_id != 1:  # Sysmon Process Create
                continue

            image = log.get("Image", "").lower()
            cmdline = log.get("CommandLine", "").lower()

            for binary, patterns in lolbas_cmds.items():
                if binary in image:
                    matched = [p for p in patterns if p in cmdline]
                    if matched and ("http" in cmdline or "ftp" in cmdline):
                        findings.append({
                            "hypothesis": "H-001",
                            "timestamp": log.get("UtcTime", ""),
                            "binary": binary,
                            "cmdline": log.get("CommandLine", "")[:200],
                            "matched_patterns": matched,
                            "parent": log.get("ParentImage", ""),
                        })

        return findings

    def hunt_encoded_powershell(self, logs: list[dict]) -> list[dict]:
        import re
        import base64

        findings = []

        for log in logs:
            if log.get("EventID") != 1:
                continue

            cmdline = log.get("CommandLine", "")
            if "powershell" not in cmdline.lower():
                continue

            enc_match = re.search(
                r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)',
                cmdline, re.IGNORECASE
            )
            if enc_match:
                encoded = enc_match.group(1)
                try:
                    decoded = base64.b64decode(encoded).decode("utf-16le", errors="replace")
                    suspicious_kw = ["invoke-expression", "downloadstring", "iex(",
                                    "net.webclient", "bypass", "hidden"]
                    matched = [k for k in suspicious_kw if k in decoded.lower()]

                    if matched:
                        findings.append({
                            "hypothesis": "H-002",
                            "timestamp": log.get("UtcTime", ""),
                            "cmdline_preview": cmdline[:100],
                            "decoded_preview": decoded[:200],
                            "suspicious_keywords": matched,
                        })
                except Exception:
                    pass

        return findings

    def hunt_lsass_access(self, logs: list[dict]) -> list[dict]:
        findings = []

        for log in logs:
            if log.get("EventID") != 10:  # Sysmon ProcessAccess
                continue

            target = log.get("TargetImage", "").lower()
            if "lsass.exe" not in target:
                continue

            caller = log.get("SourceImage", "").lower()
            access_mask = log.get("GrantedAccess", "")

            # PROCESS_VM_READ + PROCESS_QUERY_INFORMATION
            suspicious_masks = ["0x1010", "0x1410", "0x1438", "0x143a"]
            known_safe = ["svchost.exe", "csrss.exe", "werfault.exe", "taskmgr.exe"]

            if access_mask in suspicious_masks and not any(s in caller for s in known_safe):
                findings.append({
                    "hypothesis": "H-005",
                    "timestamp": log.get("UtcTime", ""),
                    "caller": caller,
                    "access_mask": access_mask,
                    "severity": "Critical",
                })

        return findings

    def run_all_hunts(self) -> dict:
        logs = self.load_logs()
        print(f"[*] 로그 {len(logs)}개 로드")

        all_findings = []
        all_findings.extend(self.hunt_lolbas_download(logs))
        all_findings.extend(self.hunt_encoded_powershell(logs))
        all_findings.extend(self.hunt_lsass_access(logs))

        return {
            "total_logs": len(logs),
            "total_findings": len(all_findings),
            "findings": all_findings,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="위협 헌팅 자동화")
    parser.add_argument("logs", help="Sysmon 로그 파일 (JSONL 형식)")
    parser.add_argument("-o", "--output", help="결과 저장 파일")
    args = parser.parse_args()

    hunter = ThreatHunter(args.logs)
    results = hunter.run_all_hunts()

    print(f"\n[+] 헌팅 완료: {results['total_logs']}개 로그 분석, "
          f"{results['total_findings']}개 의심 활동 발견")

    for finding in results["findings"]:
        print(f"\n[{finding.get('hypothesis')}] {finding.get('timestamp')}")
        for k, v in finding.items():
            if k not in ("hypothesis", "timestamp"):
                print(f"  {k}: {str(v)[:100]}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
```

---

## 2. YARA 룰 — 회피 기법 탐지

```yara
rule Evasion_TimeStomp_Indicators
{
    meta:
        description = "타임스탬프 조작 도구 탐지"
        technique = "T1070.006"

    strings:
        $tool1 = "timestomp" ascii nocase
        $tool2 = "SetFileTime" ascii
        $tool3 = "BeyondCorp" ascii
        $api1 = { 48 8B C4 48 89 58 08 48 89 70 10 57 41 54 41 55 41 56 41 57 }

        // Meterpreter timestomp 패턴
        $meterp = "timestomp" wide ascii
        $meterp2 = "-z" wide ascii  // meterpreter -z flag

    condition:
        any of ($tool*, $meterp*)
}


rule Evasion_Parent_Process_Spoofing
{
    meta:
        description = "부모 프로세스 위장 (Process Parent Spoofing)"
        technique = "T1134.004"

    strings:
        // UpdateProcThreadAttribute API 사용
        $api1 = "UpdateProcThreadAttribute" ascii
        $api2 = "InitializeProcThreadAttributeList" ascii
        $const1 = { 20 00 02 00 }  // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

        // NtCreateProcess 직접 호출
        $syscall1 = "NtCreateUserProcess" ascii
        $syscall2 = "RtlCreateUserProcess" ascii

    condition:
        ($api1 and $api2 and $const1) or
        any of ($syscall*)
}


rule Evasion_Heaven_Gate_WOW64
{
    meta:
        description = "Heaven's Gate — 32비트 프로세스에서 64비트 코드 실행"
        technique = "T1055"

    strings:
        // 64비트 far call (0x33 세그먼트)
        $heavens_gate = { 6A 33 E8 00 00 00 00 83 04 24 05 CB }
        $heavens_gate2 = { EA ?? ?? ?? ?? 33 00 }

        // 64비트 NtCreateThread 직접 호출
        $nt_direct = { B8 ?? 00 00 00 49 89 CA 0F 05 }

    condition:
        any of them
}


rule Evasion_ETW_Patching
{
    meta:
        description = "ETW(Event Tracing for Windows) 패치 — 로깅 우회"
        technique = "T1562.006"

    strings:
        // EtwEventWrite 함수 주소 패치 (ret 명령어 삽입)
        $etw1 = "EtwEventWrite" ascii
        $etw_patch = { C3 }  // ret instruction (패치된 함수 앞 바이트)
        $etw2 = "ntdll.dll" ascii
        $etw3 = "EtwEventWriteFull" ascii

        // PowerShell AMSI bypass
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "amsiContext" ascii wide
        $amsi_bypass = { B8 57 00 07 80 C3 }  // mov eax, 0x80070057; ret

    condition:
        ($etw1 or $etw3) and $etw_patch or
        ($amsi1 and $amsi_bypass)
}


rule Hunting_Suspicious_Scheduled_Task
{
    meta:
        description = "은닉 예약 작업 생성 탐지"
        technique = "T1053.005"

    strings:
        $schtasks1 = "schtasks" ascii nocase
        $schtasks2 = "/create" ascii nocase
        $schtasks3 = "/tn" ascii nocase
        $sc1 = "/sc minute" ascii nocase
        $sc2 = "/sc onlogon" ascii nocase
        $hidden1 = "/f" ascii  // /force (기존 작업 덮어쓰기)

        $suspicious_cmd = "powershell" ascii nocase
        $suspicious_cmd2 = "cmd /c" ascii nocase
        $suspicious_cmd3 = "mshta" ascii nocase

    condition:
        $schtasks1 and $schtasks2 and $schtasks3 and
        any of ($sc*) and
        any of ($suspicious_cmd*)
}
```

---

## 3. 메모리 포렌식 기반 회피 탐지

### 3.1 비정상 메모리 영역 탐지

```python
#!/usr/bin/env python3
"""Volatility3 기반 회피 기법 메모리 헌팅"""
import argparse
import subprocess
import json
from pathlib import Path


class MemoryHunter:
    def __init__(self, image_path: str) -> None:
        self.image = image_path
        self.findings: list[dict] = []

    def run_vol(self, plugin: str, extra: str = "") -> list[dict]:
        cmd = f"vol -f {self.image} {plugin} {extra} --output-format json"
        try:
            output = subprocess.check_output(cmd, shell=True, text=True, timeout=180)
            return json.loads(output).get("rows", [])
        except Exception:
            return []

    def hunt_hollowing(self) -> list[dict]:
        """프로세스 할로잉 탐지 — 정상 프로세스에 악성 코드 주입"""
        findings = []
        processes = self.run_vol("windows.pslist")

        # 정상 시스템 프로세스 목록
        SYSTEM_PROCS = {
            "svchost.exe": r"C:\Windows\System32\svchost.exe",
            "explorer.exe": r"C:\Windows\explorer.exe",
            "notepad.exe": r"C:\Windows\System32\notepad.exe",
        }

        for proc in processes:
            name = proc.get("ImageFileName", "").lower()
            expected_path = SYSTEM_PROCS.get(name, "")

            if not expected_path:
                continue

            # VAD 플래그 분석
            vads = self.run_vol("windows.vadinfo", f"--pid {proc.get('PID')}")
            for vad in vads:
                protection = vad.get("Protection", "")
                if "EXECUTE_READWRITE" in protection:
                    findings.append({
                        "type": "프로세스 할로잉 의심",
                        "pid": proc.get("PID"),
                        "process": name,
                        "vad_start": vad.get("Start", ""),
                        "protection": protection,
                        "severity": "High",
                    })

        return findings

    def hunt_injected_threads(self) -> list[dict]:
        """원격 스레드 주입 탐지"""
        findings = []
        threads = self.run_vol("windows.cmdline")

        malfind = self.run_vol("windows.malfind")
        for item in malfind:
            findings.append({
                "type": "코드 인젝션 (malfind)",
                "pid": item.get("PID"),
                "process": item.get("Process", ""),
                "address": item.get("Address", ""),
                "protection": item.get("Protection", ""),
                "severity": "High",
            })

        return findings

    def hunt_rootkit(self) -> list[dict]:
        """루트킷 탐지 — 숨겨진 프로세스/드라이버"""
        findings = []

        pslist = {str(p.get("PID")) for p in self.run_vol("windows.pslist")}
        psscan = self.run_vol("windows.psscan")

        for proc in psscan:
            pid = str(proc.get("PID", ""))
            if pid not in pslist:
                findings.append({
                    "type": "숨겨진 프로세스 (루트킷 의심)",
                    "pid": pid,
                    "process": proc.get("ImageFileName", ""),
                    "create_time": proc.get("CreateTime", ""),
                    "severity": "Critical",
                })

        # 숨겨진 드라이버 탐지
        drv_modules = {d.get("Name") for d in self.run_vol("windows.modules")}
        drv_scan = self.run_vol("windows.driverscan")
        for drv in drv_scan:
            if drv.get("Name") not in drv_modules:
                findings.append({
                    "type": "숨겨진 드라이버 (DKOM 의심)",
                    "driver": drv.get("Name", ""),
                    "base": drv.get("Base", ""),
                    "severity": "Critical",
                })

        return findings

    def hunt_all(self) -> dict:
        print("[*] 프로세스 할로잉 헌팅...")
        hollowing = self.hunt_hollowing()

        print("[*] 코드 인젝션 헌팅...")
        injected = self.hunt_injected_threads()

        print("[*] 루트킷 헌팅...")
        rootkit = self.hunt_rootkit()

        all_findings = hollowing + injected + rootkit
        critical = [f for f in all_findings if f.get("severity") == "Critical"]

        return {
            "total": len(all_findings),
            "critical": len(critical),
            "findings": all_findings,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="메모리 회피 기법 헌팅")
    parser.add_argument("memory_image", help="메모리 이미지 파일")
    parser.add_argument("-o", "--output", default="memory_hunt_results.json")
    args = parser.parse_args()

    hunter = MemoryHunter(args.memory_image)
    results = hunter.hunt_all()

    print(f"\n[+] 발견: {results['total']}개 (Critical: {results['critical']}개)")
    for finding in sorted(results["findings"],
                          key=lambda x: {"Critical": 0, "High": 1, "Medium": 2}.get(x.get("severity", ""), 3)):
        print(f"  [{finding['severity']}] {finding['type']}: PID {finding.get('pid', 'N/A')}")

    Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"[+] 결과 저장: {args.output}")


if __name__ == "__main__":
    main()
```

---

## 4. 헌팅 가설 라이브러리

| 가설 ID | 가설 | 데이터 소스 | MITRE ATT&CK |
|--------|------|-----------|-------------|
| H-001 | LOLBAS 파일 다운로드 | Sysmon Event 1 | T1218 |
| H-002 | 인코딩 PowerShell 실행 | Sysmon Event 1, ScriptBlock | T1059.001 |
| H-003 | 비정상 서비스 설치 | Windows Event 7045 | T1543.003 |
| H-004 | ETW/AMSI 패치 | Sysmon Event 10 (kernel32) | T1562.006 |
| H-005 | LSASS 덤프 시도 | Sysmon Event 10 | T1003.001 |
| H-006 | 숨겨진 예약 작업 | Windows Event 4698, Registry | T1053.005 |
| H-007 | 부모 프로세스 위장 | Sysmon Event 1 (부모-자녀 관계) | T1134.004 |
| H-008 | Heaven's Gate | Sysmon Event 1, 8 | T1055 |
| H-009 | 타임스탬프 조작 | Sysmon Event 11, MFT 분석 | T1070.006 |
| H-010 | 프로세스 할로잉 | Sysmon Event 8, EDR | T1055.012 |

### 4.1 헌팅 자동화 스케줄

```bash
# 매시간 헌팅 실행 (cron)
0 * * * * python3 /opt/hunting/threat_hunter.py \
    /var/log/sysmon/sysmon.jsonl \
    -o /var/log/hunting/$(date +\%Y\%m\%d_\%H).json \
    2>> /var/log/hunting/errors.log

# 결과 대시보드로 전송
5 * * * * python3 /opt/hunting/send_to_siem.py \
    /var/log/hunting/$(date +\%Y\%m\%d_\%H).json
```

---

<a name="english"></a>

# Evasion Technique Detection and Threat Hunting

This section covers threat hunting methodologies for proactively detecting evasion techniques used by attackers. Topics include hypothesis-driven hunting, YARA/Sigma rule development, and memory forensics-based evasion technique discovery.

---

## 1. Threat Hunting Methodology

### 1.1 Hunting Cycle

```
1. Hypothesis Formulation
   └── "Attacker will execute without PowerShell using LOLBAS"
   └── "Suspicious process downloads files via certutil"

2. Data Collection
   └── Sysmon logs, EDR telemetry, NetFlow

3. Analysis and Detection
   └── Anomaly baseline comparison, clustering, pattern matching

4. Response to Findings
   └── Create detection rules, escalate incidents

5. Feedback Loop
   └── Analyze missed techniques → formulate next hypothesis
```

### 1.2 Hypothesis-Driven Hunting Examples

The Python code above implements an automated threat hunting framework. Key hypotheses include:

- **H-001**: LOLBAS file download (certutil, bitsadmin, mshta via T1218)
- **H-002**: Encoded PowerShell execution (-EncodedCommand/-enc flags via T1059.001)
- **H-003**: Suspicious service installation (sc.exe or API via T1543.003)
- **H-004**: In-memory code execution (fileless execution via T1620)
- **H-005**: Credential access (LSASS process memory dump via T1003.001)

---

## 2. YARA Rules — Evasion Technique Detection

### Key Rules

- **Evasion_TimeStomp_Indicators**: Detects timestamp manipulation tools (T1070.006) — looks for timestomp strings and Meterpreter patterns
- **Evasion_Parent_Process_Spoofing**: Detects parent process spoofing (T1134.004) — looks for UpdateProcThreadAttribute and NtCreateUserProcess calls
- **Evasion_Heaven_Gate_WOW64**: Detects Heaven's Gate technique (T1055) — 32-bit process executing 64-bit code via far call to segment 0x33
- **Evasion_ETW_Patching**: Detects ETW/AMSI patching (T1562.006) — looks for EtwEventWrite patches and AMSI bypass patterns
- **Hunting_Suspicious_Scheduled_Task**: Detects hidden scheduled task creation (T1053.005)

---

## 3. Memory Forensics-Based Evasion Detection

### 3.1 Detecting Abnormal Memory Regions

The `MemoryHunter` class uses Volatility3 to detect:

**Process Hollowing** (`hunt_hollowing`):
- Enumerates processes and checks VAD (Virtual Address Descriptor) flags
- Flags regions with `EXECUTE_READWRITE` protection in known system processes
- High severity finding indicating potential code injection

**Injected Threads** (`hunt_injected_threads`):
- Uses `windows.malfind` plugin to detect memory-injected code
- Identifies suspicious executable memory regions not backed by a file on disk

**Rootkit Detection** (`hunt_rootkit`):
- Cross-references `windows.pslist` vs `windows.psscan` — processes visible via scan but not in list indicate DKOM rootkits
- Cross-references `windows.modules` vs `windows.driverscan` for hidden kernel drivers

---

## 4. Hunt Hypothesis Library

| Hypothesis ID | Hypothesis | Data Sources | MITRE ATT&CK |
|--------|------|-----------|-------------|
| H-001 | LOLBAS File Download | Sysmon Event 1 | T1218 |
| H-002 | Encoded PowerShell Execution | Sysmon Event 1, ScriptBlock | T1059.001 |
| H-003 | Suspicious Service Installation | Windows Event 7045 | T1543.003 |
| H-004 | ETW/AMSI Patching | Sysmon Event 10 (kernel32) | T1562.006 |
| H-005 | LSASS Dump Attempt | Sysmon Event 10 | T1003.001 |
| H-006 | Hidden Scheduled Task | Windows Event 4698, Registry | T1053.005 |
| H-007 | Parent Process Spoofing | Sysmon Event 1 (parent-child relationship) | T1134.004 |
| H-008 | Heaven's Gate | Sysmon Event 1, 8 | T1055 |
| H-009 | Timestamp Manipulation | Sysmon Event 11, MFT Analysis | T1070.006 |
| H-010 | Process Hollowing | Sysmon Event 8, EDR | T1055.012 |

### 4.1 Automated Hunting Schedule

```bash
# Run hunting every hour (cron)
0 * * * * python3 /opt/hunting/threat_hunter.py \
    /var/log/sysmon/sysmon.jsonl \
    -o /var/log/hunting/$(date +\%Y\%m\%d_\%H).json \
    2>> /var/log/hunting/errors.log

# Send results to dashboard
5 * * * * python3 /opt/hunting/send_to_siem.py \
    /var/log/hunting/$(date +\%Y\%m\%d_\%H).json
```
