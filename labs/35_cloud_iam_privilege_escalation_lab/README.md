# Lab 35: Cloud IAM Privilege Escalation & Governance Lab (CloudPwnLab)

**Port**: `8035`  
**Container**: `vhack-lab35-cloudiam`  
**Domain**: AWS Cloud IAM, PassRole Escalation, Cross-Account AssumeRole, Service Control Policies (SCP)

---

## 🎯 Objectives

1. **Step 1: Compute Instance Launch & iam:PassRole Escalation**
   - Identify low-privilege developer permissions combined with `iam:PassRole` and `ec2:RunInstances`.
   - Pass the privileged `CloudSecAdminRole` to an EC2 instance, query IMDS, and escalate to `AdministratorAccess`.
   - Retrieve Step 1 Flag:  
     `FLAG{CLOUD_IAM_PASSROLE_EC2_PRIV_ESCALATED_1120}`

2. **Step 2: Cross-Account Wildcard Trust sts:AssumeRole Abuse**
   - Probe cross-account roles with insecure trust relationships (`Principal: {"AWS": "*"}`).
   - Assume `CrossAccountAuditRole` via AWS STS and extract session security tokens.
   - Retrieve Step 2 Flag:  
     `FLAG{CLOUD_STS_ASSUMEROLE_TRUST_POLICY_PWNED_2231}`

3. **Step 3: Multi-Layered Cloud Governance Hardening (SCP & Boundaries)**
   - Deploy AWS Organization Service Control Policies (SCPs) with explicit DENY guards.
   - Enforce developer Permission Boundaries and require tag-scoped resource constraints on `iam:PassRole`.
   - Retrieve Step 3 Flag:  
     `FLAG{CLOUD_ORG_SCP_PERMISSION_BOUNDARY_ENFORCED_3342}`

---

## 🚀 Running the Lab

```bash
# Using vhack CLI
vhack lab start 35

# Or with docker compose directly
cd labs/35_cloud_iam_privilege_escalation_lab
docker compose up -d
```

Access the UI at `http://localhost:8035`.
