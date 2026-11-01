# Lab 53: ADGraphMaster — Active Directory BloodHound Attack Graph Traversal & ACL Exploitation Lab

## Overview
Learn how to collect Active Directory objects with BloodHound / SharpHound, apply graph theory to discover shortest attack paths to Domain Admins, exploit misconfigured object DACLs/ACEs (`GenericAll`, `WriteDacl`, `ForceChangePassword`), and apply Tiered Administration defensive remediations.

- **Port**: `8053`
- **Category**: `activedirectory` / `redteam` / `hardening`
- **Difficulty**: ★★★★★
- **Related Textbook**: `54_Active_Directory_Attacks/08_bloodhound_graph_theory_and_acl_exploitation_deepdive.md`
- **Wargame Track**: `adgraph` (Track 65)

## Stages
1. **Stage 1 (Domain Data Ingestion & Graph Schema Validation)**:
   - Ingest SharpHound / bloodhound-python JSON/CSV telemetry and validate graph node/edge topologies.
   - Flag: `FLAG{BLOODHOUND_INGESTION_GRAPH_GENERATED_3914}`
2. **Stage 2 (Cypher Graph Traversal & Shortest Path to High Value Target)**:
   - Execute Neo4j Cypher shortest-path queries to identify high-value target exposure.
   - Flag: `FLAG{CYPHER_SHORTEST_PATH_TO_DA_TRAVERSED_8205}`
3. **Stage 3 (Abusable AD ACL Misconfiguration Exploitation)**:
   - Abuse toxic permission chains (`GenericAll`, `WriteDacl`, `ForceChangePassword`) to escalate privileges.
   - Flag: `FLAG{ACL_GENERICALL_WRITEDACL_EXPLOITED_7142}`
4. **Stage 4 (Blue Team ACL Remediation & Tiered Hardening)**:
   - Audit and prune dangerous ACEs, enforce `Protected Users` group membership, and verify path severance.
   - Flag: `FLAG{TIERED_ADMIN_ACL_REMEDIATION_HARDENED_6038}`

## Quick Start
```bash
python3 vhack.py lab start 53
# Web console: http://localhost:8053
```
