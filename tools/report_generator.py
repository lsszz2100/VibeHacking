#!/usr/bin/env python3
"""
VibeHacking Security Diagnostic Report Generator (보안 진단 보고서 생성기)
45개 실습 랩 및 CTF 환경의 취약점 데이터 기반 자동 진단 보고서 생성
- CVSS 3.1 Base Score & Vector 계산기
- MITRE ATT&CK 프레임워크 전술(Tactics) 및 기법(Techniques) 매핑
- 다중 출력 포맷: Markdown (.md), HTML5 (.html, 모던 반응형 테마), JSON (.json)
"""

from __future__ import annotations

import csv
import html
import io
import json
import math
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================================
# 1. CVSS 3.1 Base Score Calculation Engine (NIST / FIRST Standard)
# ============================================================================

class CVSS31Calculator:
    """NIST Special Publication 800-30 / FIRST CVSS v3.1 공식 계산기"""

    AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_MAP = {"L": 0.77, "H": 0.44}
    PR_MAP_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_MAP_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_MAP = {"N": 0.85, "R": 0.62}
    CIA_MAP = {"N": 0.0, "L": 0.22, "H": 0.56}

    @classmethod
    def roundup(cls, val: float) -> float:
        """CVSS 3.1 명세에 정의된 소수점 첫째 자리 올림 함수"""
        int_val = round(val * 100000)
        if int_val % 10000 == 0:
            return int_val / 100000.0
        return math.ceil(int_val / 10000.0) / 10.0

    @classmethod
    def parse_vector(cls, vector_str: str) -> Dict[str, str]:
        parts = vector_str.strip().split("/")
        metrics = {}
        for p in parts:
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()
        return metrics

    @classmethod
    def calculate(cls, vector_str: str) -> Dict[str, Any]:
        """
        CVSS:3.1 벡터를 파싱하여 base_score와 severity 산출
        예: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        metrics = cls.parse_vector(vector_str)
        av = cls.AV_MAP.get(metrics.get("AV", "N"), 0.85)
        ac = cls.AC_MAP.get(metrics.get("AC", "L"), 0.77)
        scope = metrics.get("S", "U")
        pr_map = cls.PR_MAP_C if scope == "C" else cls.PR_MAP_U
        pr = pr_map.get(metrics.get("PR", "N"), 0.85)
        ui = cls.UI_MAP.get(metrics.get("UI", "N"), 0.85)
        c = cls.CIA_MAP.get(metrics.get("C", "H"), 0.56)
        i = cls.CIA_MAP.get(metrics.get("I", "H"), 0.56)
        a = cls.CIA_MAP.get(metrics.get("A", "H"), 0.56)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if iss <= 0:
            impact = 0.0
        elif scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        else:
            if scope == "U":
                base_score = cls.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        base_score = min(max(base_score, 0.0), 10.0)

        if base_score >= 9.0:
            severity = "Critical"
        elif base_score >= 7.0:
            severity = "High"
        elif base_score >= 4.0:
            severity = "Medium"
        elif base_score >= 0.1:
            severity = "Low"
        else:
            severity = "None"

        return {
            "vector": vector_str,
            "base_score": base_score,
            "severity": severity,
            "impact_subscore": round(impact, 2),
            "exploitability_subscore": round(exploitability, 2),
            "scope": "Changed" if scope == "C" else "Unchanged"
        }


# ============================================================================
# 2. Comprehensive 45-Lab Vulnerability & MITRE ATT&CK Catalog
# ============================================================================

@dataclass
class VulnerabilityFinding:
    vuln_id: str
    lab_id: str
    lab_title: str
    name: str
    category: str
    cvss_vector: str
    mitre_id: str
    mitre_technique: str
    mitre_tactic: str
    impact: str
    description: str
    affected_component: str
    remediation: str
    calculated_score: float = 0.0
    severity: str = "Medium"
    live_active: bool = False

    def __post_init__(self):
        cvss_info = CVSS31Calculator.calculate(self.cvss_vector)
        self.calculated_score = cvss_info["base_score"]
        self.severity = cvss_info["severity"]


LAB_CATALOG: Dict[str, Dict[str, Any]] = {
    "01": {
        "title": "01 Web Vulnerabilities (DVWA/JuiceShop/WebGoat)",
        "category": "Web Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0101",
                "name": "SQL Injection & Stored Cross-Site Scripting (XSS)",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1190",
                "mitre_technique": "Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "impact": "Unrestricted backend database exfiltration, credential dumping, and administrative session hijacking.",
                "description": "User-supplied input is directly concatenated into SQL queries and rendered unescaped in HTML DOM.",
                "affected_component": "/vulnerabilities/sqli/ & /vulnerabilities/xss_s/",
                "remediation": "Apply parameterized prepared statements (PDO/PreparedStatement) and context-aware HTML entity encoding (DOMPurify)."
            }
        ]
    },
    "02": {
        "title": "02 Binary Exploitation & Memory Safety",
        "category": "Binary & System",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0201",
                "name": "Stack-based Buffer Overflow & ROP Chain Hijack",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1203",
                "mitre_technique": "Exploitation for Client Execution",
                "mitre_tactic": "Execution",
                "impact": "Remote code execution within the process context, arbitrary shellcode execution, and host compromise.",
                "description": "Unbounded gets() / strcpy() calls overwrite function return addresses allowing control flow hijacking.",
                "affected_component": "ELF binary pwn_server (ports 10001-10005)",
                "remediation": "Enable compiler mitigations (Canary -fstack-protector-all, PIE, Full RELRO) and bounds-checked string functions."
            }
        ]
    },
    "03": {
        "title": "03 Network Infrastructure & Protocol Pivot",
        "category": "Network Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0301",
                "name": "Insecure Service Configuration & Lateral Pivoting",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
                "mitre_id": "T1021",
                "mitre_technique": "Remote Services",
                "mitre_tactic": "Lateral Movement",
                "impact": "Unrestricted internal subnet reconnaissance and lateral movement across DMZ boundary.",
                "description": "Weak SSH credentials and permissive DNS AXFR zone transfer expose entire internal topology.",
                "affected_component": "Internal gateway router & BIND9 service",
                "remediation": "Disable anonymous DNS zone transfer, enforce public key SSH authentication, and segment network VLANs."
            }
        ]
    },
    "04": {
        "title": "04 Anti-Reverse Engineering & Obfuscation",
        "category": "Reverse Engineering",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0401",
                "name": "Dynamic Analysis Detection & Evasion Routines",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "mitre_id": "T1027",
                "mitre_technique": "Obfuscated Files or Information",
                "mitre_tactic": "Defense Evasion",
                "impact": "Security tool blinding, automated sandbox evasion, and undetected malware execution.",
                "description": "RDTSC timing checks, IsDebuggerPresent APIs, and control flow flattening thwart reverse engineering.",
                "affected_component": "Client license verification daemon",
                "remediation": "Deploy kernel-level hypervisor tracing and automated symbolic execution disassemblers."
            }
        ]
    },
    "05": {
        "title": "05 Linux Hardening & Privilege Escalation",
        "category": "System Hardening",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0501",
                "name": "Insecure SUID Binary & Cron Job Root Escalation",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1068",
                "mitre_technique": "Exploitation for Privilege Escalation",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Complete root compromise from an unprivileged shell account.",
                "description": "Custom SUID binary executes relative paths without sanitize_path, vulnerable to PATH hijacking.",
                "affected_component": "/usr/local/bin/backup_agent (SUID root)",
                "remediation": "Remove unneeded SUID flags (chmod u-s), audit crontab file permissions, and restrict sudo privileges."
            }
        ]
    },
    "06": {
        "title": "06 Malicious Document & Macro Analysis",
        "category": "Malware Analysis",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0601",
                "name": "VBA AutoOpen Macro Execution & Payload Drop",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "mitre_id": "T1204.002",
                "mitre_technique": "User Execution: Malicious File",
                "mitre_tactic": "Execution",
                "impact": "Remote endpoint infection via weaponized phishing attachments.",
                "description": "Embedded VBA macro executes shell strings upon document open to fetch external stager.",
                "affected_component": "Invoice_Q3_Review.docm",
                "remediation": "Block macros across all untrusted Office documents via Group Policy (Block macros from running in Office files from the Internet)."
            }
        ]
    },
    "07": {
        "title": "07 Digital Forensics & Volatility Memory Triage",
        "category": "Forensics",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0701",
                "name": "In-Memory Reflective DLL Injection & Process Hollowing",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1055.012",
                "mitre_technique": "Process Injection: Process Hollowing",
                "mitre_tactic": "Defense Evasion",
                "impact": "Stealthy execution of C2 agent masquerading as trusted svchost.exe without touching disk.",
                "description": "Unbacked memory pages with PAGE_EXECUTE_READWRITE permissions detected in memory dump.",
                "affected_component": "Target memory capture memory.raw",
                "remediation": "Enforce kernel driver signature verification, EDR memory threat protection, and periodic memory volatility triage."
            }
        ]
    },
    "08": {
        "title": "08 Python Security & Prototype Vulnerability",
        "category": "Application Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0801",
                "name": "Insecure Pickle Deserialization Remote Code Execution",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1059.006",
                "mitre_technique": "Command and Scripting Interpreter: Python",
                "mitre_tactic": "Execution",
                "impact": "Arbitrary OS command execution via untrusted object reconstruction (__reduce__ exploit).",
                "description": "Server deserializes client-supplied base64 session tokens directly with pickle.loads().",
                "affected_component": "/api/session/restore endpoint",
                "remediation": "Replace pickle with safe serializers (JSON, Protocol Buffers, or HMAC-signed tokens)."
            }
        ]
    },
    "09": {
        "title": "09 Advanced Exploit Engineering & Heap Feng Shui",
        "category": "Binary & System",
        "findings": [
            {
                "vuln_id": "VIBE-2026-0901",
                "name": "Glibc Tcache Poisoning & Arbitrary Write-What-Where",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1068",
                "mitre_technique": "Exploitation for Privilege Escalation",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Arbitrary code execution via heap pointer corruption and __free_hook overwriting.",
                "description": "Double free in user chunk allows poisoned tcache next pointer to point to arbitrary memory addresses.",
                "affected_component": "Heap manager chunk allocator",
                "remediation": "Upgrade glibc to >= 2.32 (with safe-linking pointer mangling) and nullify pointers immediately after free."
            }
        ]
    },
    "10": {
        "title": "10 Enterprise Penetration Testing & Methodology",
        "category": "Offensive Operations",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1001",
                "name": "Weak Domain Controller Delegation & AS-REP Roasting",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "mitre_id": "T1558.004",
                "mitre_technique": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
                "mitre_tactic": "Credential Access",
                "impact": "Offline password cracking of service accounts without pre-authentication.",
                "description": "Accounts configured with DONT_REQ_PREAUTH return encrypted TGTs to unauthenticated attackers.",
                "affected_component": "Active Directory Kerberos KDC (Port 88)",
                "remediation": "Enforce Kerberos pre-authentication across all domain accounts and mandate 25+ character complex passwords."
            }
        ]
    },
    "11": {
        "title": "11 AI/LLM Security & Prompt Injection",
        "category": "AI Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1101",
                "name": "Indirect Prompt Injection & Tool Calling Hijack",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
                "mitre_id": "T1059",
                "mitre_technique": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "impact": "Autonomous LLM agent executes unauthorized file modifications and exfiltrates internal credentials.",
                "description": "Untrusted external data processed by LLM overrides system prompt instructions and manipulates MCP tools.",
                "affected_component": "AI Assistant Agent & Tools Engine",
                "remediation": "Implement dual-LLM verification, strict JSON schema parameter validation, and user confirmation gates for critical tools."
            }
        ]
    },
    "12": {
        "title": "12 Bug Bounty Web Applications & Business Logic",
        "category": "Web Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1201",
                "name": "Insecure Direct Object Reference (IDOR) & Race Condition",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1078",
                "mitre_technique": "Valid Accounts",
                "mitre_tactic": "Defense Evasion",
                "impact": "Unauthorized access to other tenants' financial records and coupon double-spending via concurrency flaws.",
                "description": "API fails to verify user authorization on record identifiers and lacks database row locks during transaction processing.",
                "affected_component": "/api/v2/orders/{order_id} & /api/v2/coupons/redeem",
                "remediation": "Enforce object-level access control (ABAC/RBAC) and database pessimistic locking (SELECT FOR UPDATE)."
            }
        ]
    },
    "13": {
        "title": "13 SOC & Blue Team SIEM Threat Detection",
        "category": "Blue Team & SOC",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1301",
                "name": "Log Evasion & Unmonitored PowerShell Downgrade",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1059.001",
                "mitre_technique": "Command and Scripting Interpreter: PowerShell",
                "mitre_tactic": "Execution",
                "impact": "Silent execution of malicious scripts without generating Script Block Logging (EID 4104) telemetry.",
                "description": "Attacker invokes PowerShell version 2.0 (-Version 2) to bypass Script Block and Transcription logging.",
                "affected_component": "Windows PowerShell 2.0 Engine",
                "remediation": "Uninstall PowerShell 2.0 feature (Disable-WindowsOptionalFeature) and enforce AppLocker Constrained Language Mode."
            }
        ]
    },
    "14": {
        "title": "14 Cloud Security & Kubernetes Container Breakout",
        "category": "Cloud Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1401",
                "name": "Privileged Container Host Escape via cgroups release_agent",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1611",
                "mitre_technique": "Escape to Host",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Full host operating system takeover from within an isolated container pod.",
                "description": "Container running with --privileged flag mounts host cgroup hierarchy and configures release_agent script.",
                "affected_component": "Kubernetes worker node runtime",
                "remediation": "Disallow privileged containers via Kubernetes Pod Security Admission (restricted profile) and drop CAP_SYS_ADMIN."
            }
        ]
    },
    "15": {
        "title": "15 Wireless Security & WPA3 SAE Auditing",
        "category": "Wireless Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1501",
                "name": "WPA3 Transition Mode SAE Downgrade & Side-Channel Leak",
                "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "mitre_id": "T1557",
                "mitre_technique": "Adversary-in-the-Middle",
                "mitre_tactic": "Credential Access",
                "impact": "Recovery of Wi-Fi pre-shared key via hunting-and-pecking timing analysis.",
                "description": "WPA3 SAE transition mode allows Rogue APs to spoof SSID and force legacy WPA2 4-way handshakes.",
                "affected_component": "WPA3 Enterprise Access Point",
                "remediation": "Disable transition mode; enforce WPA3-Enterprise 192-bit only with 802.11w Protected Management Frames (PMF)."
            }
        ]
    },
    "16": {
        "title": "16 Cryptographic Engineering & Key Exchange",
        "category": "Cryptography",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1601",
                "name": "Weak Diffie-Hellman Group & Small Subgroup Confinement",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "mitre_id": "T1600",
                "mitre_technique": "Weaken Encryption",
                "mitre_tactic": "Defense Evasion",
                "impact": "Eavesdropping and offline recovery of shared session secrets across encrypted tunnels.",
                "description": "DH parameters use composite or non-safe primes, enabling attackers to confine keys to small subgroups.",
                "affected_component": "Custom TLS / IPsec Key Negotiation Daemon",
                "remediation": "Mandate standardized RFC 7919 FFDHE groups (>= 3072-bit) or Curve25519 / NIST P-256."
            }
        ]
    },
    "17": {
        "title": "17 Red Team Operations & C2 Infrastructure",
        "category": "Red Team",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1701",
                "name": "Domain Fronting & HTTPS Malleable C2 Beaconing",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "mitre_id": "T1071.001",
                "mitre_technique": "Application Layer Protocol: Web Protocols",
                "mitre_tactic": "Command and Control",
                "impact": "Long-term persistent remote command and control bypassing egress perimeter firewalls.",
                "description": "TLS SNI matches trusted CDN while HTTP Host header routes traffic to malicious hidden C2 backend.",
                "affected_component": "Corporate perimeter edge proxy",
                "remediation": "Deploy TLS interception with SNI-Host header consistency checks and high-entropy DNS/HTTP inspection."
            }
        ]
    },
    "18": {
        "title": "18 DevSecOps & CI/CD Pipeline Security",
        "category": "DevSecOps",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1801",
                "name": "GitHub Actions Workflow Poisoning (Pwn Request)",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                "mitre_id": "T1195.002",
                "mitre_technique": "Supply Chain Compromise: Compromise Software Supply Chain",
                "mitre_tactic": "Initial Access",
                "impact": "Extraction of production deployment cloud credentials and automated release poisoning.",
                "description": "Workflow triggers on pull_request_target and checks out untrusted fork code with privileged repository secrets.",
                "affected_component": ".github/workflows/deploy.yml",
                "remediation": "Never checkout pull request code with write tokens; use standard pull_request trigger or separate triage pipelines."
            }
        ]
    },
    "19": {
        "title": "19 Assembly Language & CPU Architecture",
        "category": "Binary & System",
        "findings": [
            {
                "vuln_id": "VIBE-2026-1901",
                "name": "Return-to-CSU & JOP (Jump-Oriented Programming)",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1055",
                "mitre_technique": "Process Injection",
                "mitre_tactic": "Defense Evasion",
                "impact": "Bypassing W^X / DEP protections using universal libc initialization gadgets.",
                "description": "Exploit chains __libc_csu_init functions to initialize register arguments (rdi, rsi, rdx) for arbitrary syscalls.",
                "affected_component": "Compiled x86_64 target binary",
                "remediation": "Compile with GCC 11+ which eliminates unused CSU stub routines, or enforce Intel CET / Shadow Stack."
            }
        ]
    },
    "20": {
        "title": "20 Shell Scripting Security & Command Injection",
        "category": "Application Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2001",
                "name": "Unquoted Variable Expansion & Argument Injection",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1059.004",
                "mitre_technique": "Command and Scripting Interpreter: Unix Shell",
                "mitre_tactic": "Execution",
                "impact": "Privilege escalation and arbitrary command execution through bash wildcard globbing.",
                "description": "Scripts use unquoted \"$@\" and \"*\" in tar or chown commands, vulnerable to option injection (--checkpoint-action).",
                "affected_component": "/usr/local/sbin/backup.sh",
                "remediation": "Always quote shell variables (\"$var\"), avoid passing wildcards to external commands, and use absolute paths."
            }
        ]
    },
    "21": {
        "title": "21 Windows Exploitation & Active Directory",
        "category": "Windows & AD",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2101",
                "name": "ZeroLogon (CVE-2020-1472) & Pass-the-Hash",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1210",
                "mitre_technique": "Exploitation of Remote Services",
                "mitre_tactic": "Lateral Movement",
                "impact": "Instant Domain Controller administrative takeover and NTDS.dit extraction.",
                "description": "Flawed AES-CFB8 implementation in Netlogon protocol allows setting machine account password to empty.",
                "affected_component": "Windows Netlogon Service (MS-NRPC)",
                "remediation": "Apply Microsoft security update MS-NRPC, enforce Secure RPC for all machine accounts, and monitor Event ID 5829."
            }
        ]
    },
    "22": {
        "title": "22 Password Security & Credential Dumping",
        "category": "Identity & Credential",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2201",
                "name": "LSASS Memory Dumping & DCSync Replication Abuse",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",
                "mitre_id": "T1003.001",
                "mitre_technique": "OS Credential Dumping: LSASS Memory",
                "mitre_tactic": "Credential Access",
                "impact": "Extraction of plaintext passwords, Kerberos tickets, and Golden Ticket forgery.",
                "description": "Mimikatz reads unencrypted credentials from LSASS memory via SeDebugPrivilege.",
                "affected_component": "Local Security Authority Subsystem Service (LSASS)",
                "remediation": "Enable LSA RunAsPPL (Protected Process Light) and Credential Guard (Virtualization-based Security)."
            }
        ]
    },
    "23": {
        "title": "23 Database Security & Privilege Escalation",
        "category": "Database Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2301",
                "name": "Database Superuser Misconfiguration & xp_cmdshell",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1059",
                "mitre_technique": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "impact": "Direct host operating system RCE via database administrative procedures.",
                "description": "MSSQL sa account enabled with xp_cmdshell allowed to invoke system commands under SYSTEM context.",
                "affected_component": "Microsoft SQL Server Master Database",
                "remediation": "Disable xp_cmdshell, enforce least privilege database service accounts, and revoke sa login."
            }
        ]
    },
    "24": {
        "title": "24 Network Infrastructure & Cisco Switch Security",
        "category": "Network Infrastructure",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2401",
                "name": "VLAN Hopping & STP Topology Manipulation",
                "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1557.002",
                "mitre_technique": "Adversary-in-the-Middle: ARP Poisoning",
                "mitre_tactic": "Credential Access",
                "impact": "Inter-VLAN bridge breakout, rogue root bridge injection, and traffic interception.",
                "description": "DTP (Dynamic Trunking Protocol) enabled by default on access ports allows attackers to negotiate 802.1Q trunks.",
                "affected_component": "Cisco Catalyst Switch Access Ports",
                "remediation": "Disable DTP (switchport nonegotiate), enable BPDU Guard, Port Security, and Dynamic ARP Inspection (DAI)."
            }
        ]
    },
    "25": {
        "title": "25 Threat Intelligence & STIX/TAXII Integration",
        "category": "Threat Intelligence",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2501",
                "name": "Indicator Poisoning & TAXII Server Impersonation",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H",
                "mitre_id": "T1566",
                "mitre_technique": "Phishing",
                "mitre_tactic": "Initial Access",
                "impact": "SIEM false positive storm, denial of service on SOC detection pipelines, and indicator suppression.",
                "description": "TAXII feed consumer accepts unverified HTTPS certificates, allowing MITM indicator injection.",
                "affected_component": "Threat Intel Automation Platform (STIX 2.1)",
                "remediation": "Enforce strict TLS certificate pinning and cryptographic signature verification on all incoming STIX bundles."
            }
        ]
    },
    "26": {
        "title": "26 Linux Hardening & CIS Benchmark Compliance",
        "category": "System Hardening",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2601",
                "name": "CIS Benchmark Non-Compliance & Insecure Sysctl Settings",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1562.001",
                "mitre_technique": "Impair Defenses: Disable or Modify Tools",
                "mitre_tactic": "Defense Evasion",
                "impact": "IP spoofing, ICMP redirect exploitation, and kernel core dump credential leaks.",
                "description": "Kernel variables net.ipv4.conf.all.accept_redirects=1 and fs.suid_dumpable=1 left at insecure defaults.",
                "affected_component": "/etc/sysctl.conf & Linux Kernel runtime",
                "remediation": "Apply CIS Distribution-Independent Linux Benchmark Level 2 Hardening profile."
            }
        ]
    },
    "27": {
        "title": "27 IoT Security & Firmware Emulation",
        "category": "IoT & Embedded",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2701",
                "name": "Hardcoded Firmware Backdoor & Unauthenticated Telnet",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1078.001",
                "mitre_technique": "Valid Accounts: Default Accounts",
                "mitre_tactic": "Initial Access",
                "impact": "Mass device recruitment into Mirai-style IoT botnet and remote root shell access.",
                "description": "Firmware root filesystem contains static root password hash in /etc/shadow and open telnet on port 23.",
                "affected_component": "Smart Router Firmware squashfs image",
                "remediation": "Remove default credentials, disable unencrypted telnet, and mandate unique per-device bootstrap passwords."
            }
        ]
    },
    "28": {
        "title": "28 Mobile Security & Android Reversing",
        "category": "Mobile Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2801",
                "name": "Exported Activity & Insecure Broadcast Receiver",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1404",
                "mitre_technique": "Exploitation for Privilege Escalation",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Malicious 3rd-party apps trigger internal banking money transfers without user consent.",
                "description": "AndroidManifest.xml declares com.bank.TransferActivity with android:exported=\"true\" without permission check.",
                "affected_component": "com.vibe.mobile.bank APK",
                "remediation": "Set android:exported=\"false\" on internal components or enforce custom signature-level permissions."
            }
        ]
    },
    "29": {
        "title": "29 Active Directory Certificate Services (AD CS)",
        "category": "Windows & AD",
        "findings": [
            {
                "vuln_id": "VIBE-2026-2901",
                "name": "AD CS ESC1 SAN Injection & Domain Admin Takeover",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1649",
                "mitre_technique": "Steal or Forge Authentication Certificates",
                "mitre_tactic": "Credential Access",
                "impact": "Instant elevation from low-priv user to Enterprise Domain Administrator via PKINIT certificate authentication.",
                "description": "Certificate template allows ENROLLEE_SUPPLIES_SAN and Client Authentication EKU with broad enrollment permissions.",
                "affected_component": "Active Directory Certificate Template 'UserWebServer'",
                "remediation": "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME on templates and require Manager Approval."
            }
        ]
    },
    "30": {
        "title": "30 Binary Analysis & Advanced Deobfuscation (Ghidra)",
        "category": "Reverse Engineering",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3001",
                "name": "Control Flow Flattening & Opaque Predicate Tampering",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "mitre_id": "T1027",
                "mitre_technique": "Obfuscated Files or Information",
                "mitre_tactic": "Defense Evasion",
                "impact": "Protection bypass in high-value intellectual property and proprietary licensing software.",
                "description": "Automated symbolic deobfuscation simplifies state variable dispatchers, revealing core cryptographic routines.",
                "affected_component": "Protected proprietary daemon (GhidraRev)",
                "remediation": "Adopt virtualization-based obfuscation (VMProtect) and server-side hardware-backed attestation."
            }
        ]
    },
    "31": {
        "title": "31 OAuth 2.0 & OIDC SSO Security",
        "category": "Web Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3101",
                "name": "Loose Regex Redirect URI & JWT Algorithm Confusion",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                "mitre_id": "T1556",
                "mitre_technique": "Modify Authentication Process",
                "mitre_tactic": "Credential Access",
                "impact": "Single Sign-On account takeover and authorization code leakage to attacker server.",
                "description": "Identity provider permits wildcard redirect URIs (oauth.example.com.attacker.com) and accepts HS256 with public RSA key.",
                "affected_component": "/oauth/authorize & /oauth/token endpoints",
                "remediation": "Enforce strict exact string match on redirect_uri and enforce asymmetric RS256/ES256 verification only."
            }
        ]
    },
    "32": {
        "title": "32 BGP Route Hijack & RPKI ROV Security",
        "category": "Network Infrastructure",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3201",
                "name": "BGP Sub-Prefix Hijacking & AS-Path Forgery",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1584.004",
                "mitre_technique": "Compromise Infrastructure: Server",
                "mitre_tactic": "Resource Development",
                "impact": "Global traffic redirection, man-in-the-middle decryption of financial traffic, and Internet blackout.",
                "description": "Rogue BGP peer advertises /24 sub-prefix overriding legitimate /23 route via Longest Prefix Match (LPM).",
                "affected_component": "Core Autonomous System (AS65001) BGP Peering Daemon",
                "remediation": "Deploy RPKI Route Origin Authorization (ROA) and drop RPKI Invalid routes at all border routers."
            }
        ]
    },
    "33": {
        "title": "33 KISA Infrastructure Audit & Hardening",
        "category": "Compliance & Audit",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3301",
                "name": "KISA Major Infrastructure Audit U-01~U-44 Failures",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1078",
                "mitre_technique": "Valid Accounts",
                "mitre_tactic": "Initial Access",
                "impact": "Non-compliance penalty, unauthenticated root shell, and anonymous file retrieval.",
                "description": "Root SSH login allowed over password, anonymous FTP write enabled, and weak password policy configured.",
                "affected_component": "Target infrastructure server (Linux)",
                "remediation": "Execute automated KISA U-01~U-72 baseline remediation script (PermitRootLogin no, Anonymous FTP disabled)."
            }
        ]
    },
    "34": {
        "title": "34 OSINT Attack Surface & Shadow IT",
        "category": "Offensive Operations",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3401",
                "name": "Exposed Shadow Database & Git History Secret Leakage",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "mitre_id": "T1552.001",
                "mitre_technique": "Unsecured Credentials: Credentials in Files",
                "mitre_tactic": "Credential Access",
                "impact": "Unrestricted exposure of production customer PII and long-lived cloud master API keys.",
                "description": "Staging Redis instance exposed to 0.0.0.0 without authentication; .git repository publicly accessible via web root.",
                "affected_component": "http://target:8034/.git/ & Redis:6379",
                "remediation": "Implement External Attack Surface Management (EASM), restrict cloud security groups, and run trufflehog in CI/CD."
            }
        ]
    },
    "35": {
        "title": "35 Cloud IAM Privilege Escalation & Governance",
        "category": "Cloud Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3501",
                "name": "iam:PassRole & ec2:RunInstances Escalation Chain",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1078.004",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Low-privilege cloud developer elevates directly to full Cloud Administrator privileges.",
                "description": "User has iam:PassRole on admin-role and ec2:RunInstances, allowing launch of EC2 instance with admin instance profile.",
                "affected_component": "AWS IAM Policies & EC2 Service",
                "remediation": "Enforce strict IAM Permissions Boundaries and Service Control Policies (SCPs) preventing unauthorized role assumption."
            }
        ]
    },
    "36": {
        "title": "36 Enterprise Database Security & UDF Root Escalation",
        "category": "Database Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3601",
                "name": "MySQL User-Defined Function (UDF) Dynamic Library Injection",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1059",
                "mitre_technique": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "impact": "Breakout from database engine to root-level host OS shell.",
                "description": "Attacker writes compiled shared object (.so) into /usr/lib/mysql/plugin via SQL injection and creates sys_eval() function.",
                "affected_component": "MySQL Server 8.0 Plugin Subsystem",
                "remediation": "Run database under dedicated non-root account, enable secure_file_priv, and revoke FILE / CREATE FUNCTION privileges."
            }
        ]
    },
    "37": {
        "title": "37 Bluetooth Low Energy (BLE) & SDR RF Security",
        "category": "Hardware & Wireless",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3701",
                "name": "BLE Legacy Just Works TK Cracking & Unauthorized Unlock",
                "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1557",
                "mitre_technique": "Adversary-in-the-Middle",
                "mitre_tactic": "Credential Access",
                "impact": "Physical security perimeter breach via unauthorized wireless smart lock actuation.",
                "description": "Smart lock uses unauthenticated GATT characteristic without pairing requirement, allowing replay attacks.",
                "affected_component": "SmartLock BLE GATT Service (UUID: 0xFFF0)",
                "remediation": "Enforce Bluetooth 5.x Secure Connections (LESC ECDH pairing) and cryptographic application-layer nonce challenges."
            }
        ]
    },
    "38": {
        "title": "38 EDR Evasion, Indirect Syscalls & Memory Patching",
        "category": "Malware & Evasion",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3801",
                "name": "AMSI/ETW In-Memory Patching & Indirect Syscall Evasion",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "mitre_id": "T1562.001",
                "mitre_technique": "Impair Defenses: Disable or Modify Tools",
                "mitre_tactic": "Defense Evasion",
                "impact": "Complete blinding of endpoint detection and response (EDR) userland sensors.",
                "description": "Payload unhooks ntdll .text section, overwrites AmsiScanBuffer with RET (0xC3), and uses Halo's Gate syscalls.",
                "affected_component": "Endpoint EDR Userland Sensor",
                "remediation": "Deploy kernel-level telemetry (ELAM / Microsoft-Windows-Threat-Intelligence ETW-TI) and synthetic stack trace verification."
            }
        ]
    },
    "39": {
        "title": "39 Modern Cryptography & Bleichenbacher Attack",
        "category": "Cryptography",
        "findings": [
            {
                "vuln_id": "VIBE-2026-3901",
                "name": "AES-CBC Padding Oracle & RSA Bleichenbacher Signature Forgery",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1600",
                "mitre_technique": "Weaken Encryption",
                "mitre_tactic": "Credential Access",
                "impact": "Decryption of AES ciphertext byte-by-byte and arbitrary administrative token forgery.",
                "description": "Application differentiates between padding errors and decryption errors; RSA parser neglects trailing garbage with e=3.",
                "affected_component": "Crypto Authentication Provider",
                "remediation": "Migrate to authenticated AEAD encryption (AES-256-GCM / ChaCha20-Poly1305) and enforce strict RSA-PSS signatures."
            }
        ]
    },
    "40": {
        "title": "40 Enterprise DFIR, MFT Timeline & Ransomware Containment",
        "category": "Incident Response",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4001",
                "name": "Ransomware Encryption Artifacts & Active C2 Beaconing",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1486",
                "mitre_technique": "Data Encrypted for Impact",
                "mitre_tactic": "Impact",
                "impact": "Widespread enterprise storage denial of service and data loss.",
                "description": "MFT forensic timeline reveals high-entropy mass file renaming (.locked) and periodic beaconing to dynamic IP.",
                "affected_component": "Enterprise Shared Storage & Domain Endpoints",
                "remediation": "Trigger SOAR automated network host isolation, preserve volume shadow copies, and rotate KRBTGT credentials."
            }
        ]
    },
    "41": {
        "title": "41 Software Supply Chain Security, SBOM & Sigstore",
        "category": "Supply Chain",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4101",
                "name": "Dependency Confusion & Unsigned Third-Party Artifact Injection",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1195.001",
                "mitre_technique": "Supply Chain Compromise: Compromise Software Dependencies",
                "mitre_tactic": "Initial Access",
                "impact": "Arbitrary code execution on developer machines and continuous deployment build servers.",
                "description": "Public package repository hosts malicious higher-version package with identical name to internal enterprise package.",
                "affected_component": "npm / PyPI package dependency resolution",
                "remediation": "Scope internal namespaces (@corp), generate CycloneDX SBOMs, and enforce SLSA Level 3 with Sigstore Cosign verification."
            }
        ]
    },
    "42": {
        "title": "42 Serverless Cloud Security & Event Injection",
        "category": "Serverless Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4201",
                "name": "S3 Event Notification Command Injection & Ephemeral Secret Theft",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1059",
                "mitre_technique": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "impact": "Remote code execution inside FaaS microVM and exfiltration of warm container AWS_SESSION_TOKEN.",
                "description": "Lambda function concatenates unvalidated S3 object key into subprocess shell command.",
                "affected_component": "AWS Lambda Image Processor (Port 8042)",
                "remediation": "Never invoke shell=True; use read-only root filesystems and enforce IAM least-privilege scoping."
            }
        ]
    },
    "43": {
        "title": "43 Cloud Incident Response & Threat Hunting",
        "category": "Cloud Incident Response",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4301",
                "name": "Unauthorized CloudTrail Policy Escalation & STS Exfiltration",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                "mitre_id": "T1078.004",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
                "mitre_tactic": "Privilege Escalation",
                "impact": "Full AWS account takeover and exfiltration of sensitive regulatory customer data from S3.",
                "description": "Compromised service account attached AdministratorAccess policy without MFA; STS session exfiltrated 47MB PII.",
                "affected_component": "AWS CloudTrail & S3 Data Storage (Port 8043)",
                "remediation": "Automate GuardDuty ASFF alert ingestion and trigger SOAR Lambda to revoke STS sessions and detach malicious policies."
            }
        ]
    },
    "44": {
        "title": "44 Browser Extension Security & Manifest V3",
        "category": "Browser Security",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4401",
                "name": "Manifest V3 Overprivileged Wildcard & WAR Token Leakage",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "mitre_id": "T1176",
                "mitre_technique": "Browser Extensions",
                "mitre_tactic": "Persistence",
                "impact": "Silent keystroke and password logging across all web domains, and secret key leakage to untrusted sites.",
                "description": "Extension requests <all_urls> and exposes auth_config.json via web_accessible_resources wildcard matches.",
                "affected_component": "Corporate Productivity Suite MV3 Extension (Port 8044)",
                "remediation": "Replace webRequestBlocking with Declarative Net Request (DNR), scope WAR matches strictly, and remove DOM innerHTML sinks."
            }
        ]
    },
    "45": {
        "title": "45 Post-Quantum Cryptography & PQC Migration",
        "category": "Quantum Cryptography",
        "findings": [
            {
                "vuln_id": "VIBE-2026-4501",
                "name": "Harvest Now Decrypt Later (HNDL) Hazard & Hybrid KEM Downgrade",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "mitre_id": "T1557",
                "mitre_technique": "Adversary-in-the-Middle",
                "mitre_tactic": "Credential Access",
                "impact": "Retroactive decryption of long-lived corporate secrets upon Q-Day and MitM downgrade to classical curves.",
                "description": "TLS handshake accepts classical-only X25519 fallback when ML-KEM-768 extension is stripped by intermediary.",
                "affected_component": "PQCShield Hybrid TLS Service (Port 8045)",
                "remediation": "Enforce NIST FIPS 203 ML-KEM-768 & FIPS 204 ML-DSA-65 with strict non-downgradable hybrid KDF policy."
            }
        ]
    }
}


# ============================================================================
# 3. Security Report Generator Engine (Markdown, HTML, JSON)
# ============================================================================

class SecurityReportGenerator:
    """45개 랩 취약점 데이터를 종합하여 표준화된 진단 보고서를 렌더링하는 엔진"""

    def __init__(
        self,
        selected_labs: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None,
        live_status: bool = False
    ):
        if not selected_labs:
            self.selected_lab_ids = sorted(LAB_CATALOG.keys(), key=lambda x: int(x))
        else:
            self.selected_lab_ids = [str(x).zfill(2) for x in selected_labs if str(x).zfill(2) in LAB_CATALOG]

        self.severity_filter = [s.capitalize() for s in severity_filter] if severity_filter else None
        self.live_status = live_status
        self.active_lab_ids = self._detect_active_labs() if live_status else set()

        self.findings: List[VulnerabilityFinding] = []
        for lid in self.selected_lab_ids:
            lab = LAB_CATALOG[lid]
            for f in lab.get("findings", []):
                finding = VulnerabilityFinding(
                    vuln_id=f["vuln_id"],
                    lab_id=lid,
                    lab_title=lab["title"],
                    name=f["name"],
                    category=lab["category"],
                    cvss_vector=f["cvss_vector"],
                    mitre_id=f["mitre_id"],
                    mitre_technique=f["mitre_technique"],
                    mitre_tactic=f["mitre_tactic"],
                    impact=f.get("impact", ""),
                    description=f.get("description", f.get("impact", "")),
                    affected_component=f.get("affected_component", f.get("component", "Core Application Service")),
                    remediation=f.get("remediation", ""),
                    live_active=(lid in self.active_lab_ids)
                )
                if self.severity_filter and finding.severity not in self.severity_filter:
                    continue
                self.findings.append(finding)

    def _detect_active_labs(self) -> set[str]:
        active = set()
        try:
            res = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    m = re.search(r"lab(\d{1,2})", line, re.IGNORECASE)
                    if m:
                        active.add(m.group(1).zfill(2))
        except Exception:
            pass
        return active

    def get_summary_stats(self) -> Dict[str, Any]:
        total_vulns = len(self.findings)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        tactic_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        total_score = 0.0

        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            tactic_counts[f.mitre_tactic] = tactic_counts.get(f.mitre_tactic, 0) + 1
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            total_score += f.calculated_score

        avg_score = round(total_score / total_vulns, 1) if total_vulns else 0.0

        return {
            "total_labs": len(self.selected_lab_ids),
            "total_findings": total_vulns,
            "average_cvss": avg_score,
            "severity_counts": severity_counts,
            "tactic_counts": tactic_counts,
            "category_counts": category_counts,
            "live_active_labs": len(self.active_lab_ids),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def to_csv(self) -> str:
        """감사팀 및 엑셀 보고서용 UTF-8 BOM CSV 생성"""
        output = io.StringIO()
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow([
            "Finding_ID", "Lab_ID", "Lab_Title", "Category", "Vulnerability_Name",
            "Severity", "CVSS_Score", "CVSS_Vector", "MITRE_ID", "MITRE_Technique",
            "MITRE_Tactic", "Affected_Component", "Live_Active", "Impact", "Remediation"
        ])
        for f in self.findings:
            writer.writerow([
                f.vuln_id, f.lab_id, f.lab_title, f.category, f.name,
                f.severity, f.calculated_score, f.cvss_vector, f.mitre_id, f.mitre_technique,
                f.mitre_tactic, f.affected_component, "Active" if f.live_active else "Inactive",
                f.impact, f.remediation
            ])
        return output.getvalue()

    def to_json(self) -> str:
        stats = self.get_summary_stats()
        data = {
            "report_title": "VibeHacking Enterprise Security Diagnostic & Threat Assessment Report",
            "metadata": stats,
            "findings": [asdict(f) for f in self.findings]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def to_markdown(self) -> str:
        stats = self.get_summary_stats()
        ts = stats["generated_at"]
        sev = stats["severity_counts"]

        lines = []
        lines.append("# 🛡️ VibeHacking Enterprise Security Diagnostic & Threat Assessment Report")
        lines.append(f"> **Generated at**: `{ts}` &nbsp;|&nbsp; **Target Scope**: `{stats['total_labs']} Labs` &nbsp;|&nbsp; **Standard**: `CVSS 3.1 & MITRE ATT&CK Enterprise Matrix`")
        if self.live_status:
            lines.append(f"> **Live Active Labs**: `{stats['live_active_labs']} Active Containers Running`")
        if self.severity_filter:
            lines.append(f"> **Severity Filter**: `{', '.join(self.severity_filter)}`")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary (경영진 요약)")
        lines.append("")
        lines.append(f"본 진단 보고서는 VibeHacking 플랫폼 내 총 **{stats['total_labs']}개 실습 랩** 전반에 걸쳐 식별된 **{stats['total_findings']}개 핵심 취약점**에 대한 보안 태세를 종합 진단한 결과입니다.")
        lines.append(f"- **평균 CVSS 3.1 Base Score**: **`{stats['average_cvss']} / 10.0`**")
        lines.append(f"- **취약점 심각도 분포**: 🚨 Critical: `{sev.get('Critical', 0)}` &nbsp;|&nbsp; ⚠️ High: `{sev.get('High', 0)}` &nbsp;|&nbsp; 🟡 Medium: `{sev.get('Medium', 0)}` &nbsp;|&nbsp; 🟢 Low: `{sev.get('Low', 0)}`")
        lines.append("")
        lines.append("### 📊 취약점 심각도 매트릭스 (Severity Matrix)")
        lines.append("| 심각도 (Severity) | 식별 건수 | 비율 | 대응 우선순위 |")
        lines.append("|---|---|---|---|")
        total = stats["total_findings"] or 1
        lines.append(f"| 🚨 **Critical** (9.0~10.0) | {sev.get('Critical', 0)} | {round(sev.get('Critical', 0) / total * 100, 1)}% | **P0 (즉시 긴급 패치 필요)** |")
        lines.append(f"| ⚠️ **High** (7.0~8.9) | {sev.get('High', 0)} | {round(sev.get('High', 0) / total * 100, 1)}% | **P1 (차기 스프린트 내 교정)** |")
        lines.append(f"| 🟡 **Medium** (4.0~6.9) | {sev.get('Medium', 0)} | {round(sev.get('Medium', 0) / total * 100, 1)}% | **P2 (정기 패치 주기 반영)** |")
        lines.append(f"| 🟢 **Low** (0.1~3.9) | {sev.get('Low', 0)} | {round(sev.get('Low', 0) / total * 100, 1)}% | **P3 (모니터링 및 하드닝 권고)** |")
        lines.append("")
        lines.append("### 🎯 MITRE ATT&CK 전술 분포 (Tactics Distribution)")
        lines.append("| MITRE 전술 (Tactic) | 매핑된 취약점 수 | 비중 |")
        lines.append("|---|---|---|")
        for tac, count in sorted(stats["tactic_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{tac}` | {count} | {round(count / total * 100, 1)}% |")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 2. Detailed Vulnerability Findings (취약점별 상세 진단서)")
        lines.append("")

        for idx, f in enumerate(self.findings, 1):
            badge = "🚨 CRITICAL" if f.severity == "Critical" else ("⚠️ HIGH" if f.severity == "High" else "🟡 MEDIUM")
            live_badge = " `[⚡ LIVE ACTIVE]`" if f.live_active else ""
            lines.append(f"### {idx}. [{f.vuln_id}] {f.name}{live_badge}")
            lines.append(f"- **대상 랩 / 환경**: `{f.lab_title}` (`Lab {f.lab_id}`)")
            lines.append(f"- **보안 분류**: `{f.category}`")
            lines.append(f"- **심각도**: **{badge}** (CVSS 3.1 Base Score: **`{f.calculated_score}`**)")
            lines.append(f"- **CVSS 3.1 Vector**: `{f.cvss_vector}`")
            lines.append(f"- **MITRE ATT&CK 매핑**: `{f.mitre_id}` — **{f.mitre_technique}** (전술: `{f.mitre_tactic}`)")
            lines.append(f"- **영향을 받는 컴포넌트**: `{f.affected_component}`")
            lines.append("")
            lines.append(f"**🔍 상세 취약점 분석 (Description)**:\n> {f.description}")
            lines.append("")
            lines.append(f"**💥 잠재적 보안 영향도 (Impact)**:\n> {f.impact}")
            lines.append("")
            lines.append(f"**🛡️ 권고 교정 방안 (Remediation)**:\n```text\n{f.remediation}\n```")
            lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("## 3. Recommended Remediation Roadmap (조치 우선순위 로드맵)")
        lines.append("1. **즉각 조치 (Phase 1, 0-24 Hours)**: Critical 등급 취약점 즉시 완화 (S3 Event Injection, Cloud IAM 권한 상승, AD CS ESC1, SQLi, Buffer Overflow).")
        lines.append("2. **단기 조치 (Phase 2, 1-2 Weeks)**: High 등급 취약점 교정 (EDR 후킹 우회, BLE Replay, Supply Chain Dependency Confusion, Hybrid TLS Downgrade).")
        lines.append("3. **중장기 조치 (Phase 3, 1-3 Months)**: 전사 PQC(양자 내성 암호) CBOM 목록화, RPKI ROV 배포, 제로 트러스트 서비스 메시 하드닝.")
        lines.append("")
        lines.append("*(End of Report)*")
        return "\n".join(lines)

    def to_html(self) -> str:
        stats = self.get_summary_stats()
        ts = stats["generated_at"]
        sev = stats["severity_counts"]

        # HTML 내장 템플릿 (XSS 방어 html.escape 적용, 다크 모드 & 반응형)
        findings_html = []
        for idx, f in enumerate(self.findings, 1):
            sev_class = html.escape(f.severity.lower())
            f_name = html.escape(f.name)
            f_vid = html.escape(f.vuln_id)
            f_title = html.escape(f.lab_title)
            f_cat = html.escape(f.category)
            f_mid = html.escape(f.mitre_id)
            f_mtech = html.escape(f.mitre_technique)
            f_mtac = html.escape(f.mitre_tactic)
            f_vec = html.escape(f.cvss_vector)
            f_desc = html.escape(f.description)
            f_imp = html.escape(f.impact)
            f_comp = html.escape(f.affected_component)
            f_rem = html.escape(f.remediation)
            live_indicator = '<span class="tag live-tag">LIVE ACTIVE</span>' if f.live_active else ''

            findings_html.append(f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <div class="finding-title-group">
                        <span class="finding-num">#{idx}</span>
                        <span class="badge {sev_class}">{html.escape(f.severity.upper())} {f.calculated_score}</span>
                        {live_indicator}
                        <h3 class="finding-title">{f_name}</h3>
                    </div>
                    <span class="vuln-id">{f_vid}</span>
                </div>
                <div class="finding-meta">
                    <span class="meta-item"><b>Target:</b> {f_title}</span>
                    <span class="meta-item"><b>Category:</b> {f_cat}</span>
                    <span class="meta-item"><b>MITRE:</b> <span class="tag">{f_mid}</span> {f_mtech} ({f_mtac})</span>
                </div>
                <div class="vector-box"><code>{f_vec}</code></div>
                <div class="finding-body">
                    <p><b>🔍 취약점 분석:</b> {f_desc}</p>
                    <p><b>💥 영향도:</b> {f_imp}</p>
                    <p><b>🎯 영향 컴포넌트:</b> <code>{f_comp}</code></p>
                </div>
                <div class="remediation-box">
                    <b>🛡️ 대응 권고사항 (Remediation):</b>
                    <pre>{f_rem}</pre>
                </div>
            </div>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeHacking Enterprise Security Diagnostic Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface-color: #121827;
            --surface-border: #1f293d;
            --text-main: #e2e8f0;
            --text-dim: #94a3b8;
            --accent-green: #10b981;
            --accent-blue: #38bdf8;
            --crit-color: #ef4444;
            --high-color: #f97316;
            --med-color: #eab308;
            --low-color: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }}
        body {{ background: var(--bg-color); color: var(--text-main); line-height: 1.6; padding: 24px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{ border-bottom: 2px solid var(--surface-border); padding-bottom: 20px; margin-bottom: 28px; }}
        h1 {{ font-size: 26px; color: #fff; margin-bottom: 8px; }}
        .header-meta {{ color: var(--text-dim); font-size: 14px; display: flex; gap: 16px; flex-wrap: wrap; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--crit-color); border: 1px solid var(--crit-color); }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--med-color); border: 1px solid var(--med-color); }}
        .badge.low {{ background: rgba(59, 130, 246, 0.2); color: var(--low-color); border: 1px solid var(--low-color); }}
        .live-tag {{ background: rgba(16, 185, 129, 0.2) !important; color: var(--accent-green) !important; border: 1px solid var(--accent-green); font-size: 11px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .stat-card {{ background: var(--surface-color); border: 1px solid var(--surface-border); border-radius: 8px; padding: 16px; text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; color: var(--accent-blue); margin-top: 4px; }}
        .stat-label {{ font-size: 13px; color: var(--text-dim); text-transform: uppercase; }}
        .section-title {{ font-size: 20px; margin-bottom: 16px; border-left: 4px solid var(--accent-green); padding-left: 10px; color: #fff; }}
        .finding-card {{ background: var(--surface-color); border: 1px solid var(--surface-border); border-radius: 8px; padding: 20px; margin-bottom: 20px; transition: transform 0.15s ease; }}
        .finding-card.critical {{ border-left: 4px solid var(--crit-color); }}
        .finding-card.high {{ border-left: 4px solid var(--high-color); }}
        .finding-card.medium {{ border-left: 4px solid var(--med-color); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }}
        .finding-title-group {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .finding-num {{ color: var(--text-dim); font-size: 14px; font-weight: bold; }}
        .finding-title {{ font-size: 17px; color: #fff; }}
        .vuln-id {{ font-size: 12px; color: var(--text-dim); background: #1a2234; padding: 2px 6px; border-radius: 4px; }}
        .finding-meta {{ font-size: 13px; color: var(--text-dim); margin-bottom: 12px; display: flex; gap: 16px; flex-wrap: wrap; }}
        .tag {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); padding: 1px 5px; border-radius: 3px; }}
        .vector-box {{ background: #080c14; padding: 6px 10px; border-radius: 4px; font-size: 12px; color: var(--text-dim); margin-bottom: 12px; overflow-x: auto; }}
        .finding-body {{ font-size: 14px; margin-bottom: 14px; }}
        .finding-body p {{ margin-bottom: 6px; }}
        .remediation-box {{ background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; padding: 12px; font-size: 13px; }}
        .remediation-box pre {{ margin-top: 6px; white-space: pre-wrap; color: #a7f3d0; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 14px; }}
        th, td {{ border: 1px solid var(--surface-border); padding: 10px; text-align: left; }}
        th {{ background: #161f33; color: var(--text-dim); font-weight: 600; }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .finding-card {{ border: 1px solid #ccc; break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ VibeHacking Enterprise Security Diagnostic Report</h1>
            <div class="header-meta">
                <span><b>Generated:</b> {ts}</span>
                <span><b>Assessment Scope:</b> {stats['total_labs']} Labs</span>
                <span><b>Total Vulnerabilities:</b> {stats['total_findings']} Findings</span>
                <span><b>Standard:</b> CVSS 3.1 &amp; MITRE ATT&CK</span>
            </div>
        </header>

        <section>
            <h2 class="section-title">1. Executive Dashboard (경영진 요약)</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Assessed Labs</div>
                    <div class="stat-value">{stats['total_labs']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Average CVSS</div>
                    <div class="stat-value">{stats['average_cvss']}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Critical Findings</div>
                    <div class="stat-value" style="color: var(--crit-color)">{sev.get('Critical', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">High Findings</div>
                    <div class="stat-value" style="color: var(--high-color)">{sev.get('High', 0)}</div>
                </div>
            </div>
        </section>

        <section>
            <h2 class="section-title">2. Detailed Findings ({len(self.findings)} Findings)</h2>
            {"".join(findings_html)}
        </section>
    </div>
</body>
</html>
"""
        return html_content


# ============================================================================
# 4. Standalone CLI Entry Point
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="VibeHacking Security Diagnostic Report Generator")
    parser.add_argument("--lab-id", nargs="*", help="Filter by specific lab IDs (e.g. 01 42 45)")
    parser.add_argument("--severity", nargs="*", help="Filter by severity levels (Critical High Medium Low)")
    parser.add_argument("--live", action="store_true", help="Probe running lab containers and mark active attack surfaces")
    parser.add_argument("--format", choices=["md", "html", "json", "csv"], default="md", help="Output format (default: md)")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--summary", action="store_true", help="Print summary stats only")

    args = parser.parse_args()

    gen = SecurityReportGenerator(
        selected_labs=args.lab_id,
        severity_filter=args.severity,
        live_status=args.live
    )

    if args.summary:
        stats = gen.get_summary_stats()
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return

    if args.format == "json":
        output_str = gen.to_json()
    elif args.format == "html":
        output_str = gen.to_html()
    elif args.format == "csv":
        output_str = gen.to_csv()
    else:
        output_str = gen.to_markdown()

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        print(f"✓ Security report generated successfully: {out_path} ({len(output_str)} bytes)")
    else:
        print(output_str)


if __name__ == "__main__":
    main()
