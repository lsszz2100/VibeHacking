<div align="center">

# ⚔️ VibeHacking

### Master Practical Cybersecurity — The Hacking Bible for the AI Era

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sections](https://img.shields.io/badge/Sections-64-blueviolet)](#table-of-contents)
[![Files](https://img.shields.io/badge/Docs-343%20Files-brightgreen)](#table-of-contents)
[![Lines](https://img.shields.io/badge/Lines-225%2C000%2B-orange)](#table-of-contents)
[![AI Powered](https://img.shields.io/badge/AI--Powered-Claude%20%2B%20GPT-red)](#11-ai-powered-cybersecurity)

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

## 🤖 Learn with AI CLI (Natural Language)

Run `claude` / `codex` / `gemini` **inside the repo directory** and the AI reads all 64 sections as context — becoming your interactive tutor. No need to search files manually; just ask in plain English.

```bash
cd VibeHacking
claude   # or: codex / gemini
```

| AI CLI | Install | Strength |
|--------|---------|----------|
| **Claude Code** | `npm i -g @anthropic-ai/claude-code` | File reading + command execution, natural language |
| **Codex CLI** | `npm i -g @openai/codex` | Code generation & analysis |
| **Gemini CLI** | `npm i -g @google/gemini-cli` | Largest context window (1M+ tokens) |

**Ready-to-use prompts:**

```
"I'm a complete beginner — what order should I study this repo in?"
"Read 05_Web_Hacking/02_sql_injection_advanced.md and explain the key techniques"
"Start web hacking Lab 01 and guide me through a DVWA SQL injection exercise step by step"
"Give me hints only for this CTF challenge — don't spoil the solution"
"Explain Kerberoasting and walk me through setting up the practice environment"
```

> 🤖 Full guide + 4 learning scenarios + prompt templates → **[AI_LEARNING.md](./AI_LEARNING.md)**

---

## 🛠️ CLI + Lab Environments — Get Started Now

### 1-Minute Setup

```bash
git clone https://github.com/lsszz2100/VibeHacking.git
cd VibeHacking
python3 vhack.py list        # Browse all 64 sections
```

> 📖 Full installation guide → **[INSTALL.md](./INSTALL.md)**
> 📘 Complete command reference → **[USAGE.md](./USAGE.md)**
> 🤖 Learn with AI CLI (natural language) → **[AI_LEARNING.md](./AI_LEARNING.md)**

### `vhack` Key Commands

```bash
# Browse & study
python3 vhack.py list                    # All 64 sections
python3 vhack.py list --search web       # Filter by keyword
python3 vhack.py study 5                 # Web Hacking section — file list
python3 vhack.py study 5 1               # Read OWASP Top 10 in terminal
python3 vhack.py search "Kerberoasting"  # Full-text search across all docs

# Docker lab management (requires Docker)
python3 vhack.py lab ls                  # List labs with access URLs
python3 vhack.py lab start 01            # Start web hacking lab → localhost:8080
python3 vhack.py lab start 02            # Start binary exploitation lab
python3 vhack.py lab status              # Show running containers
python3 vhack.py lab stop --all          # Stop all labs

# Shell alias — run vhack from anywhere (one-time setup)
python3 vhack.py alias install           # auto-detect shell → add to RC file
python3 vhack.py alias status            # check installation
python3 vhack.py alias remove            # unregister alias

# Update
python3 vhack.py update                  # git pull latest content
```

### Quick Reference

| Command | Description |
|---------|-------------|
| `vhack list` | List all 64 sections |
| `vhack list --search <kw>` | Filter by keyword |
| `vhack study <n>` | Section file list |
| `vhack study <n> <f>` | Read file in terminal |
| `vhack search <kw>` | Full-text search across all docs |
| `vhack info <n>` | Section details |
| `vhack lab ls` | List labs with access URLs |
| `vhack lab start <id>` | Start lab environment |
| `vhack lab stop <id>` | Stop lab environment |
| `vhack lab stop --all` | Stop all labs |
| `vhack lab status` | Show running containers |
| `vhack lab logs <id>` | Live log stream |
| `vhack alias install` | Register shell alias |
| `vhack alias install --profile <file>` | Target specific profile |
| `vhack alias status` | Check installation |
| `vhack alias remove` | Unregister alias |
| `vhack update` | `git pull` latest content |

### Lab Environments (Docker-based)

| # | Lab Name | Content | Access | Difficulty |
|:-:|----------|---------|--------|:----------:|
| **01** | Web Hacking Lab | DVWA · Juice Shop · WebGoat | http://localhost:8080 | ★★☆ |
| **02** | Binary Exploitation Lab | BOF · ret2libc · ROP · fmtstr · heap | nc localhost 10001~10005 | ★★★ |
| **03** | Network Hacking Lab | SSH · FTP · DNS · SMTP vulnerable services | docker exec shell | ★★☆ |
| **04** | Cloud/Container Security Lab | SSRF · AWS IMDS · K8s escape | http://localhost:8080 | ★★★ |
| **05** | Full Scenario Lab | APT attack chain simulation | http://localhost:8888 | ★★★★ |

```bash
# Quick practice example: Web Hacking
python3 vhack.py study 5 1        # ① Read OWASP Top 10 theory
python3 vhack.py lab start 01     # ② Start DVWA/Juice Shop lab
# ③ Open http://localhost:8080 and practice
python3 vhack.py lab stop 01      # ④ Stop when done
```

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
| 19 | [**Assembly Language**](#19-assembly-language) | x86/x64 fundamentals, shellcode development, disassembly analysis | 3 |
| 20 | [**Shell Scripting**](#20-shell-scripting) | Bash basics, pentest automation, post-exploitation scripts | 3 |
| 21 | [**Windows Exploitation**](#21-windows-exploitation) | Windows internals, privilege escalation, defense evasion | 3 |
| 22 | [**Password Cracking**](#22-password-cracking) | Hash types/wordlists, Hashcat/John, advanced techniques | 3 |
| 23 | [**Database Hacking**](#23-database-hacking) | Oracle/MySQL attacks, DB privilege escalation, forensics & auditing | 4 |
| 24 | [**Network Infrastructure Security**](#24-network-infrastructure-security) | DNS attacks, mail server (SPF/DKIM/DMARC), SSH tunneling | 4 |
| 25 | [**Threat Intelligence**](#25-threat-intelligence) | CTI fundamentals, OSINT/Shodan, incident response, honeypots | 4 |
| 26 | [**Linux Hardening**](#26-linux-hardening) | iptables/nftables, PAM authentication, KISA vulnerability assessment | 4 |
| 27 | [**IoT Hacking**](#27-iot-hacking) | Attack surface mapping, firmware analysis, IoT exploitation | 3 |
| 28 | [**Mobile Hacking**](#28-mobile-hacking) | Android pentesting, iOS pentesting, mobile traffic analysis | 3 |
| 29 | [**Container/Kubernetes Security**](#29-containerkubernetes-security) | Docker security, Kubernetes attacks, container escape | 3 |
| 30 | [**Vulnerability Research**](#30-vulnerability-research) | Fuzzing techniques, vulnerability analysis, advanced exploit development | 3 |
| 31 | [**AI/ML Security**](#31-aiml-security) | Adversarial examples, prompt injection, model extraction, agent security | 5 |
| 32 | [**Network Device Hacking**](#32-network-device-hacking) | IOS recon, L2 attacks, routing protocol manipulation, management plane exploit | 5 |
| 33 | [**OSINT & Social Engineering**](#33-osint--social-engineering) | Information gathering, target profiling, phishing infrastructure & evasion | 5 |
| 34 | [**Hardware Hacking**](#34-hardware-hacking) | Interface analysis (UART/JTAG/SPI), firmware extraction, side-channel & fault injection | 4 |
| 35 | [**Supply Chain Attacks**](#35-supply-chain-attacks) | Software supply chain compromise, CI/CD poisoning, SolarWinds/XZ patterns | 3 |
| 36 | [**Automotive Hacking**](#36-automotive-hacking) | CAN bus analysis, ECU exploitation, telematics & OTA attacks | 4 |
| 37 | [**ICS/SCADA Security**](#37-icsscada-security) | ICS protocol recon, SCADA exploitation, OT network attacks & defense | 4 |
| 38 | [**Cloud Native Security**](#38-cloud-native-security) | CNAPP, eBPF runtime security, image hardening, container escape | 4 |
| 39 | [**Zero Trust Architecture**](#39-zero-trust-architecture) | ZTA principles, identity/device trust, microsegmentation, SASE | 4 |
| 40 | [**Threat Hunting**](#40-threat-hunting) | Hunting methodology, MITRE ATT&CK scenarios, 100+ KQL/SPL queries, SOAR | 4 |
| 41 | [**Korean Security Certifications**](#41-korean-security-certifications) | 정보보안기사, ISMS-P, CISSP/OSCP roadmap, security laws | 5 |
| 42 | [**Blockchain/Web3 Security**](#42-blockchainweb3-security) | EVM structure, smart contract auditing, DeFi attacks, Web3 pentest tools | 4 |
| 43 | [**Physical Security Pentesting**](#43-physical-security-pentesting) | Physical pentest methodology, lock bypass, RFID cloning, social engineering | 4 |
| 44 | [**Incident Response/DFIR**](#44-incident-responsedfir) | IR playbooks, memory/disk forensics, network forensics, containment/eradication | 4 |
| 45 | [**Malware Development**](#45-malware-development) | PE structure, shellcode/injection, C2 framework, AV/EDR evasion | 4 |
| 46 | [**CTF Techniques**](#46-ctf-techniques) | CTF methodology/tools, PWN/REV, Web/Crypto, automation frameworks | 4 |
| 47 | [**Mobile Forensics**](#47-mobile-forensics) | Android/iOS forensics, evidence extraction, mobile forensic tools | 4 |
| 48 | [**Threat Modeling**](#48-threat-modeling) | STRIDE/PASTA/DREAD, Attack Trees, threat modeling tools | 4 |
| 49 | [**Red Team Infrastructure**](#49-red-team-infrastructure) | C2 frameworks, domain fronting, OPSEC, infrastructure automation | 4 |
| 50 | [**Game Hacking**](#50-game-hacking) | Memory manipulation, Cheat Engine, packet manipulation, anti-cheat analysis | 4 |
| 51 | [**Browser Extension Security**](#51-browser-extension-security) | MV2/V3, malicious extension analysis, Content Script XSS, hardening | 4 |
| 52 | [**API Security**](#52-api-security) | OWASP API Top 10, BOLA, GraphQL, fuzzing, OAuth2 | 4 |
| 53 | [**Serverless Security**](#53-serverless-security) | Lambda attacks, event injection, IAM abuse, IaC scanning | 4 |
| 54 | [**Active Directory Attacks**](#54-active-directory-attacks) | AD enumeration, Kerberoasting, DCSync, Golden Ticket | 4 |
| 55 | [**Evasion Techniques**](#55-evasion-techniques) | AV/EDR bypass, IDS/IPS evasion, syscall, trace removal | 4 |
| 🧪 | [**CTF Practice Labs (labs/)**](#ctf-practice-labs-labs) | Web/binary/network/cloud/full-scenario Docker CTF labs | 50 |

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

## 19. Assembly Language

```
19_Assembly_Language/
├── 01_x86_x64_Fundamentals.md   ← Registers, instructions, stack frames, calling conventions
├── 02_Shellcode_Development.md  ← Shellcode writing, bad byte removal, ctypes execution test
└── 03_Disassembly_Analysis.md   ← GDB/pwndbg, IDA/Ghidra, Capstone automation
```

**Key Content:** x86/x64 register mastery, NASM coding, 64-bit execve shellcode implementation, Capstone-based auto-disassembler

---

## 20. Shell Scripting

```
20_Shell_Scripting/
├── 01_Bash_Scripting_Basics.md       ← Variables/arrays/conditions/loops/functions, awk/sed, port scanner
├── 02_Pentest_Automation.md          ← Recon automation, subdomain enumeration, vulnerability scan wrappers
└── 03_Post_Exploitation_Scripts.md   ← Reverse shells, persistence, Python C2 socket implementation
```

**Key Content:** Practical Bash scripting, recon-to-post-exploitation full automation, 7 reverse shell one-liners, Python C2 implementation

---

## 21. Windows Exploitation

```
21_Windows_Exploitation/
├── 01_Windows_Internals.md              ← PE format, PEB/TEB, WinAPI core functions, PE parser code
├── 02_Windows_Privilege_Escalation.md   ← Service/registry/DLL hijacking, UAC bypass, token impersonation
└── 03_Defense_Evasion.md                ← AMSI/ETW bypass, 6 process injection types, LOLBAS, AES payload encryption
```

**Key Content:** Windows internals deep dive, privilege escalation mastery, AMSI/AV/EDR bypass techniques

---

## 22. Password Cracking

```
22_Password_Cracking/
├── 01_Hash_Types_and_Wordlists.md      ← Hash algorithm comparison, hashid, CeWL/Crunch/CUPP, Python cracker
├── 02_Hashcat_and_John.md              ← All attack modes, hash type mode numbers, rule writing, practical workflow
└── 03_Advanced_Cracking_Techniques.md  ← Rainbow tables, PRINCE, advanced masks, password spray tools
```

**Key Content:** NTLM/WPA/ZIP/PDF cracking strategies, GPU optimization, rate-limited password spray automation

---

## 23. Database Hacking

```
23_Database_Hacking/
├── 01_oracle_mysql_attack.md       ← Oracle/MySQL/MSSQL attack vectors, blind SQLi, out-of-band extraction
├── 02_db_privilege_escalation.md   ← DB user privesc, stored procedure abuse, UDF injection, linked servers
└── 03_db_forensics_defense.md      ← Database forensics, audit logging, query monitoring, hardening checklists
```

**Key Content:** Multi-DB attack chains, privilege escalation through DB engines, forensic analysis and defense hardening

---

## 24. Network Infrastructure Security

```
24_Network_Infrastructure_Security/
├── 01_dns_attack_defense.md                ← DNS hijacking, zone transfer, cache poisoning, DNSSEC bypass
├── 02_mail_server_security.md              ← SPF/DKIM/DMARC bypass, mail server exploitation, email spoofing
└── 03_ssh_tunneling_port_forwarding.md     ← SSH tunneling, dynamic port forwarding, SOCKS proxy, network pivoting
```

**Key Content:** DNS/mail/SSH infrastructure-level attacks, service exploitation, lateral movement via pivoting

---

## 25. Threat Intelligence

```
25_Threat_Intelligence/
├── 01_cti_fundamentals.md          ← CTI frameworks (MITRE ATT&CK/STIX/TAXII), threat actor profiling
├── 02_osint_for_threat_intel.md    ← Shodan/Censys automation, dark web OSINT, IOC collection pipeline
└── 03_incident_response.md         ← IR playbooks, forensic collection, malware triage workflow, honeypots
```

**Key Content:** CTI lifecycle, threat actor attribution, IOC management, automated incident response procedures

---

## 26. Linux Hardening

```
26_Linux_Hardening/
├── 01_firewall_and_iptables.md          ← iptables/nftables/ufw rules, firewall auditing, stateful filtering
├── 02_pam_and_auth_hardening.md         ← PAM configuration, SSH hardening, MFA setup, sudo policy
└── 03_kisa_vulnerability_assessment.md  ← KISA security checklist, CIS Benchmark, automated assessment scripts
```

**Key Content:** Firewall rule design, authentication hardening, KISA/CIS-compliant automated security assessment

---

## 27. IoT Hacking

```
27_IoT_Hacking/
├── 01_iot_attack_surface.md    ← Attack surface mapping, OWASP IoT Top 10, Shodan/Censys scanning
├── 02_firmware_analysis.md     ← Firmware extraction/analysis, binwalk/Ghidra, hardcoded credential detection
└── 03_iot_exploitation.md      ← UART/JTAG access, embedded exploitation, real-world attack scenarios
```

**Key Content:** OWASP IoT Top 10 attack surface analysis, firmware reverse engineering (binwalk/Ghidra), UART/JTAG hardware hacking, IoT device penetration

---

## 28. Mobile Hacking

```
28_Mobile_Hacking/
├── 01_android_pentesting.md        ← APK analysis, ADB rooting, Frida dynamic instrumentation, SSL pinning bypass
├── 02_ios_pentesting.md            ← IPA extraction, Objective-C/Swift reversing, jailbreak detection bypass
└── 03_mobile_traffic_analysis.md   ← Burp Suite mobile proxy, certificate pinning bypass, API fuzzing
```

**Key Content:** Android/iOS complete analysis pipeline, Frida-based runtime instrumentation, mobile MITM attacks, SSL pinning bypass techniques

---

## 29. Container/Kubernetes Security

```
29_Container_Kubernetes_Security/
├── 01_docker_security.md      ← Docker security config, container escape techniques, image vulnerability scanning
├── 02_kubernetes_attack.md    ← RBAC privilege escalation, etcd takeover, complete Kubernetes attack vectors
└── 03_container_escape.md     ← cgroup/namespace escape, runc vulnerabilities, real-world container escape PoC
```

**Key Content:** Docker/Kubernetes attack and defense strategies, RBAC privilege escalation, container escape techniques, Trivy/Falco-based runtime security

---

## 30. Vulnerability Research

```
30_Vulnerability_Research/
├── 01_fuzzing_techniques.md            ← AFL++/libFuzzer/Boofuzz, coverage-guided fuzzing, network fuzzing
├── 02_vulnerability_analysis.md        ← CVSS analysis, CWE classification, static/dynamic analysis, source code audit
└── 03_exploit_development_advanced.md  ← Advanced heap exploitation, browser exploitation, kernel vulnerability development
```

**Key Content:** AFL++/libFuzzer automated vulnerability discovery, systematic CVSS/CWE analysis, advanced heap/browser/kernel exploit development

---

## 31. AI/ML Security

```
31_AI_ML_Security/
├── 01_adversarial_examples.md         ← FGSM/PGD/C&W, transfer attacks, adversarial training & randomized smoothing
├── 02_prompt_injection_jailbreak.md   ← Direct/indirect prompt injection, jailbreaking, garak/PyRIT automated red-teaming
├── 03_model_extraction_inversion.md   ← Model extraction, membership inference (LiRA), training data reconstruction, DP-SGD
└── 04_llm_agent_security.md           ← Tool call SSRF/RCE, RAG index poisoning, MCP security, double LLM architecture
```

While Section 11 covers "using AI as an attack tool," Section 31 focuses on **AI/ML systems themselves as targets**. Based on OWASP LLM Top 10 / NIST AI 100-2 / MITRE ATLAS, with reproducible PyTorch/Anthropic SDK PoCs.

---

## 32. Network Device Hacking

```
32_Network_Device_Hacking/
├── 01_ios_fundamentals_and_recon.md      ← Cisco IOS/IOS XE structure, device fingerprinting, management protocol recon
├── 02_layer2_attacks.md                  ← VLAN hopping, STP/DHCP attacks, CAM overflow, DAI bypass
├── 03_routing_protocol_attacks.md        ← OSPF/EIGRP/BGP route injection, HSRP/VRRP hijacking
└── 04_management_plane_exploitation.md   ← SNMP/TACACS+/NETCONF exploitation, config file extraction, backdoor identification
```

While Section 02 focuses on traffic sniffing/MITM and Section 24 on DNS/mail/SSH services, Section 32 directly attacks **the management/control/data planes of routers and switches**. Includes 2025–2026 Cisco CVE PoCs (CVE-2025-20188, etc.) and GNS3/EVE-NG lab topologies.

---

## 33. OSINT & Social Engineering

```
33_OSINT_Social_Engineering/
├── 01_osint_methodology_and_search.md  ← Information gathering methodology, Shodan/Censys/FOFA, advanced dorking
├── 02_target_profiling.md              ← Person/organization profiling, SNS analysis, email verification, domain recon
├── 03_social_engineering_attacks.md    ← Phishing/spear phishing/vishing/smishing, BEC, pretexting
└── 04_phishing_infra_and_evasion.md    ← GoPhish/Evilginx2 infrastructure, URL bypass, anti-phishing detection evasion
```

Focuses on OSINT as the **reconnaissance phase of attack chains** rather than simple information search. Covers Shodan/FOFA/Censys query automation, LinkedIn/GitHub/SNS-based target profiling, and GoPhish/Evilginx2 phishing infrastructure from a red team perspective.

---

## 34. Hardware Hacking

```
34_Hardware_Hacking/
├── 01_hardware_recon_and_interfaces.md    ← UART/JTAG/SPI/I²C interface identification & dumping, pinout analysis
├── 02_firmware_analysis.md                ← binwalk extraction, filesystem analysis, hardcoded secrets, vulnerable function detection
└── 03_side_channel_and_fault_injection.md ← Power analysis (SPA/DPA), timing attacks, glitching, ChipWhisperer
```

Covers physical attack surfaces of electronic devices — from obtaining root shell via UART serial console, full firmware dump via JTAG, to extracting encryption keys through side-channel analysis. Core hardware security research using minicom, OpenOCD, binwalk, and ChipWhisperer.

---

## 35. Supply Chain Attacks

```
35_Supply_Chain_Attacks/
├── 01_software_supply_chain.md   ← Open-source package poisoning, typosquatting, dependency confusion attacks
└── 02_build_and_ci_poisoning.md  ← CI/CD pipeline compromise, GitHub Actions abuse, SolarWinds/XZ Utils pattern analysis
```

Dissects real supply chain breaches including SolarWinds, XZ Utils, and 3CX. Covers PyPI/npm/Maven package poisoning, GitHub Actions workflow privilege hijacking, and build system backdoor insertion — demonstrating that the entire software development pipeline is an attack surface.

---

## 36. Automotive Hacking

```
36_Automotive_Hacking/
├── 01_can_bus_analysis.md           ← CAN bus structure, OBD-II diagnostics, message sniffing & replay
├── 02_ecu_exploitation.md           ← ECU firmware analysis, UDS diagnostic protocol abuse, remapping
└── 03_telematics_and_ota_attacks.md ← V2X communication, telematics unit penetration, OTA update interception
```

Modern vehicles are mobile computers with 100+ ECUs and dozens of protocols. From CAN bus sniffing to UDS diagnostic protocol abuse, telematics remote attacks, and real-world Jeep Cherokee/Tesla hack reproductions — full-stack automotive security research using python-can, Scapy, and CANalyzer.

---

## 37. ICS/SCADA Security

```
37_ICS_SCADA/
├── 01_ics_protocols_and_recon.md  ← Modbus/DNP3/IEC 61850/EtherNet/IP deep dive, Shodan recon, multi-protocol scanner
├── 02_scada_exploitation.md       ← HMI/Historian/PLC vulnerabilities, TRITON/INDUSTROYER analysis, SCADA scanner
└── 03_ot_network_attacks.md       ← Purdue model layer attacks, IT→OT lateral movement, wireless OT, OT topology mapper
```

Analyzes ICS/OT environments controlling critical infrastructure (power plants, refineries, water treatment, railways). Dissects real cyber weapons including Stuxnet, TRITON, INDUSTROYER, and PIPEDREAM — covering Modbus coil forced writes to PLC DB block patching, Historian data injection, and OT topology auto-mapping.

---

## 38. Cloud Native Security

```
38_Cloud_Native_Security/
├── 01_cloud_native_threat_model.md      ← STRIDE threat modeling, CNAPP, container/serverless/service mesh threats
├── 02_ebpf_runtime_security.md          ← Falco/Tetragon/Cilium, eBPF-based runtime detection & network policy
├── 03_image_hardening_supply_chain.md   ← Trivy/Grype image scanning, Cosign signing, SBOM, OPA Gatekeeper
└── 04_cloud_native_attack_techniques.md ← Container escape, service mesh MITM, serverless event injection, KSPM
```

Covers attack and defense in Cloud Native environments (Kubernetes, serverless, service mesh). From eBPF-based runtime security (Falco/Tetragon), container image signing, SBOM, and OPA policy gateways to real container escape techniques, service mesh MITM, and AWS Lambda event injection — organized from a CNAPP perspective.

---

## 39. Zero Trust Architecture

```
39_Zero_Trust_Architecture/
├── 01_zero_trust_principles.md         ← BeyondCorp model, NIST SP 800-207, ZTA maturity model
├── 02_identity_and_device_trust.md     ← IdP/MFA/passkeys, device trust (MDM/EDR), SCIM provisioning
├── 03_microsegmentation_and_network.md ← Microsegmentation, mTLS, SASE/SD-WAN, eBPF network policy
└── 04_zero_trust_implementation.md     ← Cloudflare/Zscaler/BeyondCorp implementation, ZTA audit automation
```

"Never trust, always verify" — Zero Trust Architecture based on NIST SP 800-207 from a practical standpoint. Covers BeyondCorp case studies, identity/device trust frameworks, microsegmentation, SASE adoption, and ZTA maturity self-assessment tooling.

---

## 40. Threat Hunting

```
40_Threat_Hunting/
├── 01_threat_hunting_methodology.md  ← Hunting cycle, hypothesis-based hunting, PEAK framework, TTP drift
├── 02_mitre_attack_hunting.md        ← ATT&CK tactic hunting scenarios, group profiling, Atomic Red Team
├── 03_hunting_queries_kql_spl.md     ← 100+ Sentinel KQL/Splunk SPL hunting queries, anomaly detection patterns
└── 04_automated_threat_hunting.md    ← SOAR automation, ML-based anomaly detection, hunting playbook automation
```

Proactive threat hunting — finding what the logs won't tell you. Covers PEAK framework hypothesis building, MITRE ATT&CK tactic hunting scenarios, 100+ Sentinel KQL/Splunk SPL query examples, and SOAR-based automated playbooks ready for immediate SOC deployment.

---

## 41. Korean Security Certifications

```
41_Korean_Certifications/
├── 01_information_security_engineer.md           ← Information Security Engineer exam — 5 subject complete guide
├── 02_information_security_engineer_practical.md ← Practical exam types, cryptography/network/system labs
├── 03_ISMS_P_certification.md                    ← ISMS-P certification framework, 80 control items, audit prep
├── 04_international_certifications.md            ← CISSP/CEH/OSCP/CISA roadmap, domain comparison
└── 05_security_laws_and_compliance.md            ← Korean privacy/IT security laws, GDPR comparison
```

Korean security certifications (정보보안기사, ISMS-P) and international certifications (CISSP/CEH/OSCP/CISA) in one place. Includes Korean laws and compliance (Personal Information Protection Act, GDPR) — covering the regulatory foundations every Korean security practitioner must know.

---

## 42. Blockchain/Web3 Security

```
42_Blockchain_Web3_Security/
├── 01_blockchain_fundamentals_and_threats.md ← EVM architecture, UTXO vs account model, 51% attack, eclipse attack
├── 02_smart_contract_auditing.md             ← Reentrancy/overflow/tx.origin/delegatecall, Slither/Mythril/Echidna
├── 03_defi_protocol_attacks.md               ← Flash Loan, oracle manipulation, MEV sandwich, Rug Pull detection
└── 04_web3_pentest_tools.md                  ← Foundry (forge/cast/anvil/chisel), static analysis tools, RPC security
```

Blockchain fundamentals to DeFi attack analysis and smart contract auditing in one place. Uses web3.py 6.x and Foundry for hands-on PoC. Covers real-world incidents (Euler Finance $197M flash loan), MEV bot mechanics, Slither/Mythril vulnerability scanning, and live RPC endpoint security assessment.

---

## 43. Physical Security Pentesting

```
43_Physical_Security_Pentesting/
├── 01_physical_pentest_methodology.md    ← PTES physical domain 5-stage, authorization template, vulnerability checklist
├── 02_lock_bypass_and_access_control.md  ← Pin tumbler picking (SPP/raking/bumping), electronic access control flaws
├── 03_rfid_nfc_cloning.md                ← Proxmark3 LF/HF, MIFARE Classic nested attack, nfcpy NFC analysis
└── 04_physical_recon_and_social_engineering.md ← Passive recon, tailgating, pretexting, Cialdini's 6 principles
```

Physical penetration testing from methodology to execution. Covers lock picking, RFID/NFC cloning (Proxmark3), and social engineering using Cialdini's influence principles. Python CLIs for access control log anomaly detection and physical pentest report generation.

---

## 44. Incident Response/DFIR

```
44_Incident_Response_DFIR/
├── 01_ir_methodology_and_playbooks.md     ← NIST SP 800-61r2, PICERL, ransomware/phishing playbooks, log timeline
├── 02_memory_and_disk_forensics.md        ← Volatility3, MFT analysis, MACB timestamps, Plaso timeline
├── 03_network_forensics_and_log_analysis.md ← 100+ tshark filters, Zeek logs, Windows Event IDs, Sysmon, PCAP C2 IOC
└── 04_threat_containment_and_eradication.md ← Network isolation, persistence artifact collection, 5-Why analysis
```

Complete DFIR workflow: detection → analysis → containment → eradication → recovery. Python CLIs for suspicious process detection (whitelist comparison, name spoofing), PCAP-based C2 IOC extraction (beaconing/DNS tunneling), and Windows persistence artifact collection with risk scoring.

---

## 45. Malware Development

```
45_Malware_Development/
├── 01_malware_fundamentals_and_pe_structure.md ← PE file layout, IAT, Shannon entropy, suspicious API categorization
├── 02_shellcode_and_injection_techniques.md    ← PIC shellcode, XOR encoding, CreateRemoteThread/APC/process hollowing
├── 03_c2_framework_development.md              ← C2 architecture, HTTP C2 server+agent, DNS tunneling, commercial C2 comparison
└── 04_av_edr_evasion.md                        ← Direct syscalls, NTDLL unhooking, ETW/AMSI patching, sandbox detection
```

Malware development and defense evasion for red teamers and malware analysts. Python CLIs cover PE file analysis (entropy/API categorization), shellcode XOR encoding/disassembly, string obfuscation, and sandbox detection. Covers direct syscalls (NASM stub), NTDLL unhooking, ETW patching, and AMSI bypass concepts.

---

## 46. CTF Techniques

```
46_CTF_Techniques/
├── 01_ctf_methodology_and_tools.md        ← CTF types, tool ecosystem, Docker Pwnbox Dockerfile, CTF platform guide
├── 02_pwn_and_rev_ctf.md                  ← Complete pwntools template (ret2win/ret2libc/format string/heap), angr crackme
├── 03_web_and_crypto_ctf.md               ← Blind SQLi automation, SSTI exploitation, JWT attacks, RSA/AES/Hash attacks
└── 04_ctf_automation_and_frameworks.md    ← DynELF, GDB tmux split, angr automation, Frida Android, forensics pipeline
```

CTF from methodology to automation. Full pwntools exploit templates for every common binary challenge type, angr symbolic execution for reversing, Frida dynamic instrumentation for Android CTFs, and a forensics automation pipeline. Includes a CTFd API client for challenge tracking and flag submission.

---

## 47. Mobile Forensics

```
47_Mobile_Forensics/
├── 01_android_forensics.md          ← Android filesystem/ADB forensics/SQLite artifacts/backup parser CLI
├── 02_ios_forensics.md              ← iOS APFS structure/iTunes backup parsing/iMessage/Health data CLI
├── 03_mobile_evidence_extraction.md ← Logical/filesystem/physical extraction/hash integrity/evidence CLI
└── 04_mobile_forensics_tools.md     ← Autopsy/MVT/Frida/jadx/APK auto-analysis CLI
```

Complete mobile forensics for Android and iOS. ADB artifact extraction, iTunes backup decryption/parsing, Pegasus spyware detection with MVT, Frida dynamic analysis, APK reverse engineering — with legal evidence integrity procedures.

---

## 48. Threat Modeling

```
48_Threat_Modeling/
├── 01_stride_methodology.md         ← STRIDE 6 categories/DFD/trust boundaries/auto analysis CLI
├── 02_pasta_dread_attack_trees.md   ← PASTA 7 stages/DREAD scoring/Attack Trees/Kill Chain/ATT&CK
├── 03_threat_modeling_tools.md      ← MS TMT/Threat Dragon/IriusRisk/CI/CD integration/XML→HTML CLI
└── 04_threat_modeling_practice.md   ← E-commerce/mobile banking/K8s scenarios/full workflow CLI
```

Practical threat modeling with STRIDE, PASTA, and DREAD. From DFD creation to threat identification, mitigation controls, and CI/CD pipeline integration — automate the entire process with a single Python CLI.

---

## 49. Red Team Infrastructure

```
49_Red_Team_Infrastructure/
├── 01_c2_frameworks.md               ← Cobalt Strike/Sliver/Havoc structure/HTTP C2 impl/detection rules
├── 02_domain_fronting_redirectors.md ← CDN fronting/Apache/Nginx redirectors/DNS tunneling/traffic filter CLI
├── 03_opsec_infrastructure.md        ← OPSEC 5 steps/Long-Short Haul C2/CT logs/OPSEC audit CLI
└── 04_red_team_automation.md         ← Ansible/Terraform infra/payload pipeline/campaign management CLI
```

Red team C2 infrastructure and OPSEC. Sliver/Havoc frameworks, Apache redirectors, DNS tunneling, Terraform AWS automation — for authorized red team engagements, CTF, and security research.

---

## 50. Game Hacking

```
50_Game_Hacking/
├── 01_memory_manipulation.md        ← Game memory/ReadProcessMemory/AOB scan/pointer chain CLI
├── 02_cheat_engine_advanced.md      ← CE Lua scripting/auto assembler/struct dissect/CT file parser CLI
├── 03_packet_manipulation.md        ← Game packet capture/mitmproxy/protobuf reverse/replay CLI
└── 04_anti_cheat_analysis.md        ← VAC/EAC/BattlEye internals/detection techniques/process analysis CLI
```

Game security research and CTF game hacking. Cheat Engine memory manipulation, packet MITM analysis, anti-cheat internals — for educational, CTF, and security research purposes.

---

## 51. Browser Extension Security

```
51_Browser_Extension_Security/
├── 01_extension_architecture.md       ← MV2/V3 comparison/Background/Content Script/CSP/attack surface
├── 02_malicious_extension_analysis.md ← Malicious extension types/IOCs/obfuscation analysis/CRX analyzer CLI
├── 03_extension_pentesting.md         ← Content Script XSS/cross-extension attacks/Selenium auto-scan CLI
└── 04_extension_security_hardening.md ← MV3 hardening/least privilege/enterprise GPO/risk assessment CLI
```

Complete browser extension security. Malicious extension IOC detection, CRX auto-analysis, Content Script XSS and postMessage attacks, Selenium dynamic vulnerability scanner, enterprise policy management.

---

## 52. API Security

```
52_API_Security/
├── 01_rest_api_security.md         ← OWASP API Top 10/BOLA scanner/JWT vulnerability analysis CLI
├── 02_graphql_security.md          ← Introspection/batch query/depth DoS/schema auto-analysis CLI
├── 03_api_fuzzing.md               ← ffuf/OpenAPI-based auto-fuzzer/HPP/response analysis CLI
└── 04_api_security_hardening.md    ← OAuth2 PKCE/Rate Limiting/Kong/NGINX gateway/audit CLI
```

Complete REST/GraphQL API security. BOLA auto-scanner, JWT forgery/cracking, GraphQL batch attacks and depth DoS, OpenAPI-based fuzzer, OAuth2 PKCE implementation, API gateway security configuration.

---

## 53. Serverless Security

```
53_Serverless_Security/
├── 01_lambda_function_attacks.md   ← Env var exfil/IMDSv1 SSRF/event injection/runtime detection CLI
├── 02_serverless_injection.md      ← SQS/S3 event injection/typosquatting/command injection static analysis
├── 03_serverless_iam_abuse.md      ← Over-privileged roles/AssumeRole chaining/least privilege policy generator CLI
└── 04_serverless_hardening.md      ← IaC scanning/Terraform secure config/Lambda Extension/audit CLI
```

AWS Lambda serverless attack and defense. IMDSv1 SSRF, event source injection, IAM role abuse, typosquatting detection, IaC (Checkov/cfn-guard) scanning, Lambda Extension runtime protection.

---

## 54. Active Directory Attacks

```
54_Active_Directory_Attacks/
├── 01_ad_enumeration.md            ← BloodHound/LDAP enumeration/SPN/AS-REP account auto-enum CLI
├── 02_kerberos_attacks.md          ← Kerberoasting/AS-REP Roasting/Pass-the-Ticket/automation CLI
├── 03_lateral_movement_ad.md       ← PtH/NTLM relay/DCSync/multi-host lateral movement automation CLI
└── 04_ad_persistence.md            ← Golden Ticket/Shadow Credentials/ACL abuse/persistence detection CLI
```

Complete Active Directory attack chain. BloodHound collection and Cypher queries, Kerberoasting/AS-REP Roasting automation, NTLM relay/DCSync, Golden/Silver Ticket, AdminSDHolder/Shadow Credentials persistence.

---

## 55. Evasion Techniques

```
55_Evasion_Techniques/
├── 01_av_evasion.md                ← XOR encoder/sandbox detection/process injection/AMSI bypass CLI
├── 02_ids_ips_evasion.md           ← Packet fragmentation/DNS tunneling/traffic masquerade/Snort rule analysis CLI
├── 03_edr_bypass.md                ← Direct syscall/NTDLL hook detection/memory injection detection CLI
└── 04_log_evasion.md               ← Event log manipulation/timestomping/trace removal automation CLI
```

Complete AV/EDR/IDS evasion techniques. XOR/AES payload encoder, sandbox detection, direct/indirect syscall, NTDLL hook detection, DNS/ICMP tunneling, C2 traffic masquerading, post-exploitation cleanup checklist.

---

## CTF Practice Labs (labs/)

```
labs/
├── 01_web_hacking_lab/      ← SQLi/XSS/SSRF/JWT vulnerable Flask app (Docker-based)
├── 02_pwn_lab/              ← BOF/format string/heap exploit vulnerable binary environment
├── 03_network_lab/          ← Packet analysis/MITM/ARP spoofing pcap + practice environment
├── 04_cloud_container_lab/  ← Vulnerable Docker/K8s environment, container escape scenarios
├── 05_full_scenario_lab/    ← Recon→Intrusion→Lateral movement→Privilege escalation→Exfiltration
├── start_lab.sh             ← Full lab docker-compose up automation
└── stop_all.sh              ← Stop all labs
```

5 Docker-based CTF vulnerable environments — web, binary, network, cloud, and full scenario, ready for local practice. 12 flags total, one `start_lab.sh` command to spin up the entire environment.

---

## Legal Notice

> **All techniques in this repository must only be used in authorized environments.**

- Use within CTF, Bug Bounty, or contracted penetration testing scope only
- Follow Responsible Disclosure principles when vulnerabilities are discovered
- Unauthorized system access violates applicable laws including the Computer Fraud and Abuse Act (CFAA) and equivalent statutes in your jurisdiction

---

<div align="center">

**⚔️ VibeHacking** — Your Journey to Becoming a Practical Security Professional


</div>
