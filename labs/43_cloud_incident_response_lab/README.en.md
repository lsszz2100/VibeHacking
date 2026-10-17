# Lab 43: CloudIRShield — Cloud Incident Response & Threat Hunting Lab

An interactive hands-on lab simulating multi-cloud (AWS/hybrid) incident response, threat hunting, and automated containment.

## 🎯 Objectives
1. **Stage 1 (CloudTrail Anomaly Audit)**: Audit CloudTrail management events to pinpoint unauthorized privilege escalation (`AttachUserPolicy`) from an external IP.
2. **Stage 2 (STS & S3 Exfiltration Forensics)**: Trace compromised temporary STS session tokens (`ASIA...`) used for bulk data exfiltration from sensitive S3 vaults (`corp-customer-pii-vault`).
3. **Stage 3 (VPC Flow Logs Correlation)**: Analyze network interface flow logs to extract periodic C2 beaconing sessions from infected internal workloads (`10.0.4.15`).
4. **Stage 4 (GuardDuty Triage & Automated SOAR Containment)**: Triage high-severity GuardDuty alerts and trigger an automated multi-layer SOAR containment playbook.

## 🚀 Quick Start

### Local Execution (Python)
```bash
cd labs/43_cloud_incident_response_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8043
```

### Docker Execution
```bash
docker-compose up -d --build
```
Access `http://127.0.0.1:8043` in your browser.

## 🧪 Run Tests
```bash
pytest -v labs/43_cloud_incident_response_lab/tests/
```
