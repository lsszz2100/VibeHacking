# Lab 54: AgentSandboxGuard — AI Agent MCP Sandbox Escape & Landlock LSM / eBPF Defense Lab

## Overview
Investigate and remediate advanced attack vectors against Model Context Protocol (MCP) autonomous AI agents: MCP Tool Poisoning, Confused Deputy privilege hijacking, and subprocess shell escape. Implement robust, layered host defenses using unprivileged Linux Landlock LSM file sandboxing and runtime in-kernel eBPF Dual-LLM guardrail enforcement.

- **Port**: `8054`
- **Category**: `ai` / `llm_security` / `kernel_hardening`
- **Difficulty**: ★★★★★
- **Textbook Chapter**: `69_LLM_Security/08_ai_agent_sandbox_escape_and_landlock_defense_deepdive.md`
- **Wargame Track**: `agentsandbox` (Track 66)

## Stages
1. **Stage 1 (MCP Tool Poisoning & Shadowing)**:
   - Exploit untrusted prompt injection into MCP tool schema definitions and override invocation parameters.
   - Flag: `FLAG{MCP_TOOL_POISONING_HIJACK_DEFLECTED_5401}`
2. **Stage 2 (Confused Deputy & Subprocess Escape)**:
   - Abuse agent execution privileges to spawn unauthorized subshells and attempt host credential exfiltration.
   - Flag: `FLAG{CONFUSED_DEPUTY_ESCAPE_VECTOR_CONTAINED_5402}`
3. **Stage 3 (Landlock LSM Unprivileged Sandboxing)**:
   - Configure Linux Landlock LSM rulesets to restrict unprivileged agent processes from traversing sensitive host paths (`/etc`, `/proc`, `/root`).
   - Flag: `FLAG{LANDLOCK_LSM_FILE_SANDBOXING_ENFORCED_5403}`
4. **Stage 4 (eBPF Dual-LLM Guardrail & Runtime Enforcement)**:
   - Enforce in-kernel eBPF LSM syscall filtering paired with secondary LLM semantic verification for inline mitigation.
   - Flag: `FLAG{EBPF_DUAL_LLM_RUNTIME_SHIELD_ACTIVE_5404}`

## Quick Start
```bash
python3 vhack.py lab start 54
# Web Console: http://localhost:8054
```
