# Lab 40: IRShield — Enterprise DFIR & Incident Response Lab

## 📌 Overview
- **Lab ID**: `40`
- **Directory**: `labs/40_enterprise_dfir_ir_lab/`
- **Codename**: `IRShield`
- **Port**: `8040` (`http://localhost:8040`)
- **Difficulty**: ★★★★★
- **Related Sections**: `44_Incident_Response_DFIR`, `07_Digital_Forensics`, `23_SOC_Blue_Team`
- **Standards**: NIST SP 800-61 Rev 2 / RFC 3227 / CISA Incident Response Playbooks

---

## 🎯 Learning Objectives
1. **Live Process & Memory Triage**: Identify PPID spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) and unbacked executable memory (`PAGE_EXECUTE_READWRITE`).
2. **$MFT & Ransomware Artifact Forensics**: Analyze Volume Shadow Copy deletion (`vssadmin`), USN journal mass encryption timeline, and ransom notes.
3. **C2 Beacon Detection & Network Containment**: Uncover jitter-based periodic beaconing, DNS tunneling, and apply enterprise firewall isolation.
4. **SOAR Remediation & Integrity Verification**: Eradicate persistence mechanisms (Scheduled Tasks & WMI event subscriptions), restore immutable snapshots, and verify SHA-256 hashes.

---

## 🚀 Quick Start
```bash
# Direct Execution
cd labs/40_enterprise_dfir_ir_lab
docker compose up -d

# Control via vhack CLI
python vhack.py lab start 40
python vhack.py lab test 40
python vhack.py solve 40
```
