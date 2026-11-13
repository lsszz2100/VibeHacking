# CVSS v3.1 Scoring Calculation Reference

This guide summarizes the Common Vulnerability Scoring System (CVSS) v3.1 vector calculation used across VibeHacking audit reports and catalog generator.

---

## 1. CVSS v3.1 Base Metrics

### Exploitability Metrics
1. **Attack Vector (AV)**:
   - Network (N): 0.85
   - Adjacent (A): 0.62
   - Local (L): 0.55
   - Physical (P): 0.20
2. **Attack Complexity (AC)**:
   - Low (L): 0.77
   - High (H): 0.44
3. **Privileges Required (PR)**:
   - Unchanged Scope: None (N) = 0.85, Low (L) = 0.62, High (H) = 0.27
   - Changed Scope: None (N) = 0.85, Low (L) = 0.68, High (H) = 0.50
4. **User Interaction (UI)**:
   - None (N): 0.85
   - Required (R): 0.62
5. **Scope (S)**:
   - Unchanged (U)
   - Changed (C)

### Impact Metrics
- **Confidentiality Impact (C)**: None (N: 0.0), Low (L: 0.22), High (H: 0.56)
- **Integrity Impact (I)**: None (N: 0.0), Low (L: 0.22), High (H: 0.56)
- **Availability Impact (A)**: None (N: 0.0), Low (L: 0.22), High (H: 0.56)

---

## 2. Severity Rating Scale
- **Critical**: 9.0 – 10.0 (Immediate mitigation required, remote unauthenticated code execution)
- **High**: 7.0 – 8.9 (Elevated privileges, severe data leakage, remote exploitation)
- **Medium**: 4.0 – 6.9 (Local privilege escalation, user interaction required)
- **Low**: 0.1 – 3.9 (Limited denial of service, minor info disclosure)
- **None**: 0.0
