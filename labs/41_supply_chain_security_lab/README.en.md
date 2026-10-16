# Lab 41: SupplyChainShield — Software Supply Chain Security & SBOM Lab

## 📌 Overview
- **Lab ID**: `41`
- **Directory**: `labs/41_supply_chain_security_lab/`
- **Codename**: `SupplyChainShield`
- **Port**: `8041` (`http://localhost:8041`)
- **Difficulty**: ★★★★★
- **Related Sections**: `35_Supply_Chain_Attacks`, `18_DevSecOps`, `74_Code_Auditing`
- **Core Standards**: SLSA v1.0 / CycloneDX v1.6 / SPDX 3.0 / Sigstore Cosign

---

## 🎯 Learning Objectives
1. **Dependency Confusion & Typosquatting**: Analyze public vs private repository precedence hijacking and enforce scoped package registry or hash pinning.
2. **CI/CD Runner Poisoning & Pwn Request**: Detect and mitigate GitHub Actions `pull_request_target` privilege escalation leaking `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN`.
3. **SBOM Vulnerability Triage**: Parse CycloneDX JSON format Software Bill of Materials, detect xz-utils (CVE-2024-3094) style backdoor tampering, and isolate malicious dependencies.
4. **SLSA Level 3 & Cosign Attestation**: Enforce cryptographic provenance verification with Sigstore Cosign OIDC and Rekor transparency log validation.

---

## 🔬 Stages & Flags
1. **Stage 1 (Dependency Confusion)**: `POST /api/stage1/resolve`
   - Flag: `FLAG{supplychain_dependency_confusion_pypi_hijacked}`
2. **Stage 2 (CI/CD Runner Poisoning)**: `POST /api/stage2/audit-pipeline`
   - Flag: `FLAG{supplychain_pwn_request_actions_secret_leaked}`
3. **Stage 3 (SBOM Vulnerability Triage)**: `POST /api/stage3/triage-sbom`
   - Flag: `FLAG{supplychain_sbom_cyclonedx_backdoor_isolated}`
4. **Stage 4 (SLSA Level 3 & Cosign Attestation)**: `POST /api/stage4/verify-provenance`
   - Flag: `FLAG{supplychain_slsa_cosign_hermetic_verified_100}`
