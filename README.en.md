<div align="center">

# ⚔️ VibeHacking

### Master Practical Cybersecurity — The Hacking Bible for the AI Era

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-33-blueviolet)](#table-of-contents)
[![Files](https://img.shields.io/badge/Docs-128%20Files-brightgreen)](#table-of-contents)
[![Lines](https://img.shields.io/badge/Lines-93%2C000%2B-orange)](#table-of-contents)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai-powered-cybersecurity)
[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-gray)](https://claude.ai/code)

<br/>

> A practical security knowledge repository — from theory to hands-on labs — ready for CTF, Bug Bounty, Penetration Testing, and Red Team operations.
> Complete coverage from AI-driven vulnerability research to cloud, wireless, and cryptography in the **2026 era of Mythos & GPT-5.4-Cyber**.

**🌐 Language / 言語 / 语言:**
[한국어](README.md) · [English](README.en.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## Why This Repository

Built for security learners who want real-world skills — every section includes copy-paste-ready commands, working code, and systematic methodologies.  
From CTF to Bug Bounty, Red Team to AI Security: a **practical, hands-on knowledge hub designed from scratch in multiple languages**.

**What makes VibeHacking stand out:**

- **Code-First** — Every section includes executable commands and ready-to-run code
- **AI-Integrated** — Learn how to use Claude/GPT-5.4-Cyber as security analysis tools
- **Cutting-Edge** — Reflects the 2026 AI security ecosystem including Anthropic Mythos and OpenAI GPT-5.4-Cyber
- **Multilingual** — Available in Korean, English, Japanese, and Chinese
- **Full Coverage** — Bug Bounty, SOC, Cloud, WiFi, Cryptography, Red Team, and more

---

## Table of Contents

| # | Section | Key Topics | Files |
|---|---------|-----------|-------|
| 01 | [Linux Basics & Kali Linux](#01-linux-basics--kali-linux) | Essential commands, Kali setup, Bash scripting | 3 |
| 02 | [Network Hacking](#02-network-hacking) | OSI/TCP-IP, packet analysis, wireless hacking | 3 |
| 03 | [System Hacking](#03-system-hacking) | Password cracking, Buffer Overflow | 2 |
| 04 | [Reverse Engineering](#04-reverse-engineering) | Assembly, OllyDbg, PE structure | 3 |
| 05 | [Web Hacking](#05-web-hacking) | OWASP Top 10, advanced SQLi, XSS/CSRF | 3 |
| 06 | [Malware Analysis](#06-malware-analysis) | Static/dynamic analysis, Volatility, Android | 3 |
| 07 | [Digital Forensics](#07-digital-forensics) | Forensics procedure, Windows artifacts, network | 3 |
| 08 | [Python Hacking](#08-python-hacking) | Tool development, network scanners, web automation | 3 |
| 09 | [Exploit Techniques](#09-exploit-techniques) | ROP Chain, SEH, Linux BOF, privilege escalation | 2 |
| 10 | [Pentest Methodology](#10-pentest-methodology) | Pentest workflow, OSINT recon, report writing | 3 |
| 11 | [**AI-Powered Security**](#11-ai-powered-cybersecurity) | Mythos, GPT-5.4-Cyber, LLM vulnerability research, CTF automation | 4 |
| 12 | [**Bug Bounty**](#12-bug-bounty) | Methodology, Burp Suite advanced, automation tools | 3 |
| 13 | [**SOC & Blue Team**](#13-soc--blue-team) | SOC operations, Splunk analysis, threat hunting | 3 |
| 14 | [**Cloud Security**](#14-cloud-security) | AWS/Azure/GCP attack vectors, pentesting, checklist | 3 |
| 15 | [**WiFi Hacking**](#15-wifi-hacking) | WPA2 cracking, PMKID, Evil Twin, automation | 3 |
| 16 | [**Cryptography**](#16-cryptography) | Cryptography for hackers, hash attacks, applied crypto | 3 |
| 17 | [**Red Team Operations**](#17-red-team-operations) | Playbook, phishing/social engineering, API hacking | 3 |
| 18 | [**DevSecOps**](#18-devsecops) | SAST/SCA/DAST, container security, CI/CD pipeline | 3 |

---

## Learning Roadmap

```
[Beginner]
  Linux Basics  ──►  Network Fundamentals  ──►  Web Hacking Intro
                                                        │
[Intermediate]                                          ▼
  System Hacking  ◄──  Python Automation  ◄──  Malware Analysis
        │
        ▼
[Advanced]
  Reverse Engineering  ──►  Exploit Development  ──►  Pentest Methodology
                                                              │
[Expert]                                                      ▼
  WiFi Hacking  ──►  Cloud Security  ──►  Red Team Ops  ──►  Bug Bounty
  Cryptography  ──►  SOC/Blue Team   ──►  AI Security   ──►  DevSecOps
```

---

## Lab Environment

| Component | Recommended |
|-----------|-------------|
| Attack Machine | Kali Linux 2024.x |
| Virtualization | VMware Workstation / VirtualBox |
| Vulnerable Targets | Metasploitable2, DVWA, HackTheBox, TryHackMe, CloudGoat |
| Analysis Tools | Wireshark, Burp Suite, IDA Pro / Ghidra, OllyDbg |
| Languages | Python 3.x, Bash, pwntools |
| AI Tools | Claude Opus 4.6, GPT-5.4-Cyber (TAC Certified) |
| Wireless | Alfa AWUS036ACH (2.4/5GHz monitor mode supported) |
| Cloud | AWS Free Tier, CloudGoat |

---

## 01. Linux Basics & Kali Linux

```
01_Linux_Basics/
├── 01_linux_essential_commands.md   ← File/process/network essential commands
├── 02_kali_linux_setup.md           ← Kali initial setup, tool installation
└── 03_bash_scripting.md             ← Automation scripting, practical examples
```

**Key Content:** File system, process management, network commands, permission management, 30+ Bash automation scripts

---

## 02. Network Hacking

```
02_Network_Hacking/
├── 01_osi_tcpip.md          ← OSI 7 layers, TCP/IP stack, protocol analysis
├── 02_packet_analysis.md    ← Wireshark practical, tcpdump, packet manipulation
└── 03_wireless_hacking.md   ← WEP/WPA2 cracking, Evil Twin, wireless hacking
```

**Key Content:** Packet capture & analysis, ARP spoofing, MITM, wireless network attacks, firewall bypass

---

## 03. System Hacking

```
03_System_Hacking/
├── 01_password_cracking.md       ← Hashcat, John, Rainbow Table, online cracking
├── 02_buffer_overflow.md         ← Stack BOF principles, shellcode, practical examples
└── 03_active_directory_attack.md ← AD attack complete guide, Kerberoasting, DCSync
```

**Key Content:** Hash cracking strategies, BOF from principles to exploit, complete Active Directory attack chain

---

## 04. Reverse Engineering

```
04_Reverse_Engineering/
├── 01_assembly_and_registers.md   ← x86/x64 assembly, registers, stack frames
├── 02_ollydbg_practical.md        ← OllyDbg/x64dbg practical analysis
└── 03_pe_structure.md             ← PE file structure, IAT/EAT, packing
```

**Key Content:** Assembly language, debugger usage, in-depth PE structure analysis, IDA Pro/Ghidra

---

## 05. Web Hacking

```
05_Web_Hacking/
├── 01_owasp_top10.md              ← OWASP Top 10 (2021), Burp Suite, Nikto
├── 02_sql_injection_advanced.md   ← Blind/Time-based SQLi, NoSQL, SQLMap practical
└── 03_xss_csrf_file_upload.md     ← Stored/Reflected/DOM XSS, CSRF, webshell
```

**Key Content:** OWASP Top 10 hands-on, SQL Injection mastery, XSS/CSRF/File Upload/XXE/SSRF

---

## 06. Malware Analysis

```
06_Malware_Analysis/
├── 01_malware_analysis.md            ← Classification, analysis env, static/dynamic, YARA
├── 02_memory_forensics_malware.md    ← Volatility complete guide, code injection detection
└── 03_android_malware_analysis.md    ← APK analysis, Frida hooking, MobSF
```

**Key Content:** Full static/dynamic/memory analysis workflow, Volatility plugins, Android malware

---

## 07. Digital Forensics

```
07_Digital_Forensics/
├── 01_digital_forensics.md               ← Forensics principles, evidence collection, image analysis
├── 02_windows_forensics_artifacts.md     ← Registry, event logs, Prefetch, browser artifacts
└── 03_network_forensics.md               ← Wireshark, Zeek, Suricata, incident response
```

**Key Content:** Evidence collection procedure, complete Windows artifact analysis, network forensics, timeline analysis

---

## 08. Python Hacking

```
08_Python_Hacking/
├── 01_python_hacking_tools.md       ← 30+ examples: port scanners, sniffers, backdoors
├── 02_python_network_scanner.md     ← Multi-thread scanner, ARP, DNS enumeration, SSH bruteforcer
└── 03_python_web_exploitation.md    ← Web crawler, SQLi automation, XSS scanner, report generation
```

**Key Content:** Scapy, paramiko, requests-based security tool development, 50+ fully working code examples

---

## 09. Exploit Techniques

```
09_Exploit_Techniques/
├── 01_advanced_exploitation.md   ← ROP Chain, Heap Spray, SEH, Win32 shellcoding
├── 02_linux_exploitation.md      ← Linux BOF, Ret2Libc, format string, privilege escalation
└── 03_heap_exploitation.md       ← tcache poisoning, UAF, House of series, pwndbg
```

**Key Content:** DEP/ASLR/NX bypass, ROP chain construction, format string exploit, heap exploitation mastery

---

## 10. Pentest Methodology

```
10_Pentest_Methodology/
├── 01_pentest_methodology.md   ← Full pentest procedure, MITRE ATT&CK, report writing
├── 02_osint_recon.md           ← Google Dorks, Shodan, subdomain enum, GitHub secret detection
└── 03_report_writing.md        ← Professional report writing, CVSS scoring, PoC, executive/tech templates
```

**Key Content:** Systematic penetration testing methodology, full OSINT tool usage, professional report writing (CVSS, PoC, compliance)

---

## 11. AI-Powered Cybersecurity

> **In 2026, AI is reshaping the cybersecurity landscape.**

```
11_AI_Powered_Security/
├── 01_ai_security_landscape_2026.md   ← Mythos, GPT-5.4-Cyber, Project Glasswing overview
├── 02_llm_vulnerability_research.md   ← Zero-day discovery with LLMs, AI fuzzing, code analysis automation
├── 03_ai_assisted_pentesting.md       ← AI-assisted pentest workflow, prompt engineering
└── 04_ai_ctf_automation.md            ← CTF automation AI agent, crypto/web/forensics sub-agents
```

### 2026 AI Security Landscape

| Model | Organization | Capability | Access |
|-------|-------------|-----------|--------|
| **Claude Mythos** | Anthropic | Autonomous discovery of 17-year-old FreeBSD RCE, thousands of zero-days | Project Glasswing (12 partners only) |
| **GPT-5.4-Cyber** | OpenAI | Binary reversing, 76% autonomous CTF solving, YARA generation | TAC Certified (chatgpt.com/cyber) |
| **Claude Opus 4.6** | Anthropic | Code vulnerability analysis, CTF assistance, YARA automation | Generally available |

**Key Content:** Complete AI security ecosystem analysis, Claude API-based vulnerability scanner implementation, AI-assisted pentest automation, CTF solving AI agent (crypto/web/forensics/reversing specialized sub-agents)

---

## 12. Bug Bounty

```
12_Bug_Bounty/
├── 01_bug_bounty_methodology.md   ← HackerOne/Bugcrowd methodology, IDOR, XSS bypass, automation
├── 02_burp_suite_advanced.md      ← Burp Suite mastery, JWT attacks, Request Smuggling
└── 03_bug_bounty_automation.md    ← Nuclei, ffuf, dalfox, automation pipeline
```

**Key Content:** Complete bug bounty workflow, advanced Burp Suite features, recon→vulnerability→report automation

---

## 13. SOC & Blue Team

```
13_SOC_Blue_Team/
├── 01_soc_fundamentals.md       ← SOC structure, incident response, key event IDs, EDR
├── 02_splunk_siem_analysis.md   ← Splunk SPL mastery, 100+ detection queries
└── 03_threat_hunting.md         ← Threat hunting, ransomware breach investigation, APT tracking
```

**Key Content:** SOC tier roles, 100+ attack detection patterns, Splunk/QRadar/ELK queries, threat hunting methodology

---

## 14. Cloud Security

```
14_Cloud_Security/
├── 01_cloud_attack_vectors.md        ← AWS/Azure/GCP/K8s attack vectors complete analysis
├── 02_aws_pentest.md                 ← AWS pentest methodology, privilege escalation, automation
└── 03_cloud_security_checklist.md    ← CIS checklist, Terraform, SCP policies
```

**Key Content:** IAM privilege abuse, S3 misconfiguration, container escape, Kubernetes attacks, cloud security checklist

---

## 15. WiFi Hacking

```
15_WiFi_Hacking/
├── 01_wifi_hacking_fundamentals.md   ← WEP/WPA/WPA2/WPA3 theory, aircrack-ng basics
├── 02_wpa2_cracking.md               ← Hashcat/Aircrack, PMKID attack, wordlist optimization
└── 03_advanced_wifi_attacks.md       ← Evil Twin, KARMA, Bettercap, Scapy manipulation
```

**Key Content:** 4-Way Handshake, PMKID capture, GPU cracking, Evil Twin setup, wireless automation

---

## 16. Cryptography

```
16_Cryptography/
├── 01_cryptography_for_hackers.md   ← AES mode attacks, RSA vulnerabilities, XOR cracking
├── 02_hash_attacks.md               ← MD5 collision, rainbow tables, Kerberoasting
└── 03_applied_cryptography.md       ← Padding Oracle, ECDSA nonce reuse, JWT attacks
```

**Key Content:** Cryptographic implementation vulnerabilities, CTF crypto problem patterns, secure encryption implementation guide

---

## 17. Red Team Operations

```
17_Red_Team_Operations/
├── 01_red_team_playbook.md               ← Operation structure, Cobalt Strike/Havoc, AV/EDR bypass
├── 02_phishing_and_social_engineering.md ← GoPhish, Evilginx2, spear phishing, BEC
└── 03_api_hacking.md                     ← OWASP API Top 10, GraphQL, fuzzer development
```

**Key Content:** Red team vs pentest differences, C2 framework operations, phishing infrastructure, API vulnerability mastery

---

## 18. DevSecOps

```
18_DevSecOps/
├── 01_devsecops_fundamentals.md    ← Shift Left, Semgrep, SonarQube, Snyk, ZAP
├── 02_container_security.md        ← Dockerfile security, Trivy, Falco, K8s RBAC, cosign
└── 03_github_actions_security.md   ← CI/CD security, OIDC, SHA pinning, complete security pipeline
```

**Key Content:** Security by design (Shift Left), SAST/SCA/DAST/IaC scan automation, container runtime detection, GitLab/Jenkins/GitHub Actions secure pipeline implementation

---

## Legal Notice

> **All techniques in this repository must only be used in authorized environments.**

- Use within CTF, Bug Bounty, or contracted penetration testing scope only
- Follow Responsible Disclosure principles when vulnerabilities are discovered
- Unauthorized system access violates applicable laws including the Computer Fraud and Abuse Act (CFAA) and equivalent statutes in your jurisdiction

---

<div align="center">

**⚔️ VibeHacking** — Your Journey to Becoming a Practical Security Professional

*Built with [Claude Code](https://claude.ai/code)*

</div>
