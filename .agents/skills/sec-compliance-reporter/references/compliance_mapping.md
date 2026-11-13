# Security Compliance Standards Mapping Reference

This document maps offensive/defensive scenarios in VibeHacking labs to national and international compliance frameworks: **KISA ISMS-P** and **NIST CSF 2.0**.

---

## 1. KISA ISMS-P Core Mapping

| ISMS-P Domain | Sub-Item | Relevant Labs & Scenarios |
| :--- | :--- | :--- |
| **2.6 접근통제** | 2.6.1 네트워크 접근통제 | Lab 03 (ARP Spoofing), Lab 24 (VLAN Hopping), Lab 32 (BGP Hijack) |
| | 2.6.2 사용자 인증 | Lab 10 (Password Cracking), Lab 21 (Kerberoasting), Lab 31 (OAuth2 CSRF) |
| | 2.6.5 시스템 접근통제 | Lab 05 (SUID PrivEsc), Lab 12 (Race Condition), Lab 22 (Mimikatz DCSync) |
| **2.7 암호화 적용** | 2.7.1 암호정책 적용 | Lab 04 (Padding Oracle), Lab 16 (PQC ML-KEM/Kyber), Lab 34 (Side-Channel) |
| | 2.7.2 암호키 관리 | Lab 26 (Hardcoded Secrets), Lab 29 (AD CS ESC1 Certs) |
| **2.8 개발보안** | 2.8.2 소프트웨어 개발 보안 | Lab 01 (SQLi), Lab 02 (Buffer Overflow), Lab 08 (Insecure Deserialization), Lab 09 (Heap Exploitation), Lab 11 (Prompt Injection) |
| **2.10 침해사고 관리** | 2.10.1 침해사고 예방 및 탐지 | Lab 06 (Process Injection), Lab 07 (Volatility Memory Forensics), Lab 17 (C2 Tunneling) |
| | 2.10.2 취약점 점검 및 조치 | Lab 23 (PostgreSQL RCE), Lab 25 (Shodan Recon), Lab 33 (Linux Hardening) |

---

## 2. NIST Cybersecurity Framework (CSF) 2.0 Mapping

| CSF 2.0 Function | Category / Subcategory | Lab Application |
| :--- | :--- | :--- |
| **GV (Govern)** | GV.RM-01 Risk Management & Model Integrity | Lab 11 & Lab 40 (AI Model Inversion, Agent Sandbox Escape) |
| **PR (Protect)** | PR.AA-01 Identity Management & Auth | Lab 21 (Kerberos), Lab 31 (OAuth2), Lab 29 (PKI/Certificates) |
| | PR.PS-01 Platform & Workload Security | Lab 02 (Binary NX/Canary/PIE), Lab 14 (Container Escape) |
| | PR.PS-05 Software Supply Chain Security | Lab 18 (CI/CD Pipeline Poisoning), Lab 28 (Typosquatting) |
| | PR.DS-02 Data-in-Transit Cryptography | Lab 04 (TLS/Crypto Failures), Lab 55 (Hybrid TLS 1.3 Post-Quantum) |
| **DE (Detect)** | DE.CM-01 Host & Network Telemetry | Lab 44 (eBPF Kernel Probing), Lab 45 (Zeek/Suricata C2 Analysis) |
| | DE.AE-02 Adverse Event Supertimeline | Lab 43 (SANS DFIR Plaso Supertimeline Analysis) |
| **RS (Respond)** | RS.MA-01 Incident Investigation | Lab 07 (Memory Forensics), Lab 38 (Cloud Incident Response) |

---

## 3. OWASP Top 10 (2021 & LLM 2025)
- **A01: Broken Access Control**: Labs 05, 12, 14, 22, 23, 31, 46.
- **A02: Cryptographic Failures**: Labs 04, 16, 26, 34, 55.
- **A03: Injection**: Labs 01, 11, 27, 40 (Prompt Injection & Tool Hijack).
- **A05: Security Misconfiguration**: Labs 13, 14, 24, 29, 30, 32.
- **A08: Software and Data Integrity**: Labs 08, 18, 28, 36.
