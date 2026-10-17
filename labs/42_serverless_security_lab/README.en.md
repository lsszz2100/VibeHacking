# Lab 42: ServerlessGuard — Serverless Security & Cloud Event Injection Lab

## 📌 Overview
- **Lab ID**: `42`
- **Directory**: `labs/42_serverless_security_lab/`
- **Codename**: `ServerlessGuard`
- **Port**: `8042` (`http://localhost:8042`)
- **Difficulty**: ★★★★★
- **Related Sections**: `53_Serverless_Security`, `14_Cloud_Security`, `48_Threat_Modeling`
- **Core Standards**: AWS Lambda Security Architecture / Ephemeral Storage Security / IAM Least Privilege / Cloud Event-Driven Threat Modeling

---

## 🎯 Learning Objectives
1. **Serverless Event Injection & Deserialization Analysis**: Exploit command execution vulnerabilities triggered by unsanitized S3 `ObjectCreated` event parameters (`s3.object.key`) in serverless handlers.
2. **Warm Container /tmp Persistence & State Leak**: Leverage execution environment reuse to carve sensitive AWS temporary session tokens and database credentials left in `/tmp`.
3. **Overprivileged IAM Execution Role & STS Escalation**: Abuse overpermissive wildcard `sts:AssumeRole` permissions to escalate privileges to the enterprise `CorpCloudAdminRole`.
4. **Serverless Runtime Hardening & Policy Lockdown**: Enforce read-only root filesystems, ephemeral storage scrubbing, strict event schema validation, and ARN-scoped IAM least privilege.

---

## 🔬 Stages & Flags
1. **Stage 1 (Event Injection & Deserialization)**: `POST /api/stage1/invoke-event`
   - Flag: `FLAG{serverless_event_injection_s3_key_rce_pwned}`
2. **Stage 2 (Warm Container /tmp Persistence)**: `POST /api/stage2/dump-secrets`
   - Flag: `FLAG{serverless_warm_container_tmp_persistence_token_leaked}`
3. **Stage 3 (Overprivileged IAM Execution Role & STS Escalation)**: `POST /api/stage3/escalate-iam`
   - Flag: `FLAG{serverless_iam_overprivileged_role_escalated}`
4. **Stage 4 (Serverless Runtime Hardening & Least Privilege)**: `POST /api/stage4/harden-runtime`
   - Flag: `FLAG{serverless_hardened_least_privilege_runtime_secured}`
