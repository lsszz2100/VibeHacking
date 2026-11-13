---
name: sec-compliance-reporter
description: Generates enterprise-grade security diagnostic and compliance reports mapped to KISA ISMS-P, NIST CSF 2.0, OWASP Top 10, MITRE ATT&CK, and CVSS 3.1. Supports Markdown, HTML, JSON, and CSV exports with active container live-probing capabilities. Use this skill whenever creating audit summaries, security assessment whitepapers, or enterprise compliance deliverables.
---

# Security Compliance Reporter Skill

Generates structured, executive-ready security diagnostic reports covering all 55+ interactive hands-on labs. Maps discovered attack vectors and security controls directly to national and international cybersecurity frameworks.

---

## 1. When to Use This Skill

- 📊 **Executive & C-Suite Briefings**: Producing comprehensive security audit reports with CVSS 3.1 severity distribution.
- 📜 **Compliance Audits**: Verifying adherence to **KISA ISMS-P** (Clause 2.6, 2.7, 2.8, 2.10) and **NIST CSF 2.0** (Govern, Protect, Detect, Respond).
- 🔍 **Live Surface Probing**: Detecting active, running lab environments on `127.0.0.1` and marking exposed vulnerabilities.
- 📑 **Multi-Format Export**: Generating reports in Markdown (`.md`), HTML (`.html`), JSON (`.json`), or CSV (`.csv`).

---

## 2. Directory Layout & Architecture

```
.agents/skills/sec-compliance-reporter/
├── SKILL.md                          # Main instructions (this file)
├── scripts/
│   └── render_report.py              # CLI report generator wrapper
├── references/
│   ├── compliance_mapping.md         # KISA ISMS-P & NIST CSF 2.0 mappings
│   └── cvss_scoring_guide.md         # CVSS 3.1 calculation and severity scale
└── assets/
    └── report_theme.css              # Dark mode & print-optimized report styling
```

---

## 3. Workflow & Usage

### 3.1 Summary Statistics
Quickly inspect the overall vulnerability landscape:
```bash
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --summary
```

### 3.2 Full Enterprise Report (Markdown)
Generate a comprehensive markdown report in `reports/`:
```bash
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --format md
```

### 3.3 HTML Report with Styling
Generate an HTML report suitable for browser viewing or PDF printing:
```bash
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --format html -o reports/audit_report.html
```

### 3.4 Filter by Severity or Lab
Target specific high-risk items:
```bash
# Only Critical and High severity findings
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --severity Critical High

# Filter specific labs (e.g., Lab 01, Lab 14, Lab 55)
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --lab-id 01 14 55
```

### 3.5 Live Container Attack Surface Probing
Probe active lab containers running on the local host:
```bash
python .agents/skills/sec-compliance-reporter/scripts/render_report.py --live --format md
```

---

## 4. Compliance Mappings
For detailed control IDs and framework breakdown, refer to:
- [references/compliance_mapping.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/.agents/skills/sec-compliance-reporter/references/compliance_mapping.md)
- [references/cvss_scoring_guide.md](file:///mnt/d/바이브해킹%20자료/vibe-hacking/.agents/skills/sec-compliance-reporter/references/cvss_scoring_guide.md)
