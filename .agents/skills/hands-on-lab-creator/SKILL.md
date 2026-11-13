---
name: hands-on-lab-creator
description: "Use when creating, scaffolding, or updating hands-on vulnerability labs in the VibeHacking project (labs/XX_name), generating Dockerfile and docker-compose configurations, authoring lab Pytest test suites, or registering new labs into tools/report_generator.py and vhack.py. Also use whenever the user mentions adding a new lab, Docker container lab, or lab scenario."
---

# Hands-on Lab Creator

A specialized skill for authoring, scaffolding, and integrating production-grade cybersecurity hands-on labs into the VibeHacking repository.

## Core Architectural Invariants

Every hands-on lab in `labs/` MUST adhere to the following enterprise invariants:

1. **Localhost Binding (Security Policy)**:
   Per enterprise security memory (`RULE[user_global]`), exposed container ports must ALWAYS be explicitly bound to `127.0.0.1`:
   ```yaml
   ports:
     - "127.0.0.1:80XX:80XX"
   ```
   Never use wildcard `0.0.0.0` or open ports to external networks.

2. **Standard 4-Stage Progressive Workflow**:
   - **Stage 1 (Recon)**: Attack surface reconnaissance & endpoint discovery
   - **Stage 2 (Exploit)**: Vulnerability exploitation & payload injection
   - **Stage 3 (Escalate)**: Trust boundary pivot & privilege escalation
   - **Stage 4 (Mitigate)**: Hardening configuration & defense validation

3. **Status Endpoint Specification**:
   Every lab backend MUST expose `GET /api/status` returning:
   ```json
   {
     "lab_id": "XX",
     "name": "Lab Name",
     "port": 80XX,
     "status": "running",
     "total_stages": 4,
     "solved_count": 0,
     "stages": { "stage1_solved": false, ... }
   }
   ```

4. **Self-Contained Pytest Suite**:
   Every lab must include `labs/XX_name/tests/test_*.py` utilizing `fastapi.testclient.TestClient(app)` to verify all 4 stages without requiring live Docker execution during CI.

---

## Scaffolding a New Lab

Use the bundled generator to scaffold the full directory tree, Dockerfile, Compose, FastAPI app, and Pytest suite:

```bash
python .agents/skills/hands-on-lab-creator/scripts/scaffold_lab.py \
  --id 56 \
  --slug ai_rag_data_poisoning_lab \
  --title-ko "AI RAG 데이터 포이즈닝 및 지식 조작 랩" \
  --title-en "AI RAG Data Poisoning & Knowledge Manipulation Lab"
```

To dry-run and inspect the structure first:
```bash
python .agents/skills/hands-on-lab-creator/scripts/scaffold_lab.py --id 56 --slug test_lab --title-ko "테스트" --title-en "Test" --dry-run
```

---

## Catalog & CVSS Registration

After scaffolding the lab:
1. Validate CVSS 3.1 vector calculation:
   ```bash
   python .agents/skills/hands-on-lab-creator/scripts/register_catalog.py --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   ```
2. Insert the generated `COMPLIANCE_MAP` and `LAB_CATALOG` dictionaries into `tools/report_generator.py`.
3. Add the lab definition to `LABS` in `vhack.py`.

---

## Verification Before Completion (The Iron Law)

Never claim a lab is complete without running fresh tests:

1. Test the specific lab:
   ```bash
   pytest -v labs/<new_lab_dir>/tests/
   ```
2. Run the CLI doctor diagnostic:
   ```bash
   python3 vhack.py doctor
   ```
3. Verify lab catalog coverage:
   ```bash
   pytest -v labs/tests/test_report.py
   ```
