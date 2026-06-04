# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

VibeHacking is a bilingual (Korean/English) cybersecurity knowledge base with 64 sections covering everything from Linux basics to quantum cryptography. It is a **content repository**, not a software project — there is no build system, package manager, or test suite. The primary artifact is markdown files and a thin Python CLI (`vhack.py`).

## CLI Commands

```bash
# Run the CLI (no pip install required — stdlib only)
python3 vhack.py list                    # Show all 64 sections
python3 vhack.py study 05               # List files in section 05
python3 vhack.py study 05 1             # Open first file in section 05
python3 vhack.py search "SQL 인젝션"     # Full-text search across all .md files
python3 vhack.py info 57                # Section metadata
python3 vhack.py alias install          # Register shell alias so `vhack` works globally

# Docker lab environments (requires Docker + Docker Compose v2)
python3 vhack.py lab ls                 # List available labs
python3 vhack.py lab start 01           # Start lab (01–05)
python3 vhack.py lab stop 01
python3 vhack.py lab status
python3 vhack.py lab logs 01

# Or use the bash wrapper directly
bash labs/start_lab.sh 01               # Equivalent to lab start 01
bash labs/stop_all.sh

# Translate Korean-only .md files to English (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-... python3 translate_to_english.py
ANTHROPIC_API_KEY=sk-... python3 translate_to_english.py --start 40   # Resume from section 40
ANTHROPIC_API_KEY=sk-... python3 translate_to_english.py --file 57_Quantum_Cryptography/02_quantum_key_distribution.md
```

## Architecture

### Content Structure

Each of the 64 numbered directories (`NN_SectionName/`) contains markdown files numbered `NN_topic_name.md`. Every file follows a **bilingual template**:

```
> 🌐 Language toggle header

<a name="한국어"></a>
# Title (Korean)
... Korean content ...

---

<a name="english"></a>
# Title (English)
... English content ...
```

Files that haven't been translated yet lack the `<a name="english">` anchor. `translate_to_english.py` skips files that already have it.

### `vhack.py` Internals

Single-file CLI using only stdlib. Key functions:
- `section_dir(num)` → resolves `NN_SectionName/` from section number
- `cmd_study` → opens .md files via `$PAGER` or falls back to `less`/`cat`
- `_run_compose(lab_dir, *args)` → delegates to `docker compose` in the lab subdirectory
- `cmd_search` → recursive grep over all `.md` files

### Lab Environments (`labs/`)

Five Docker Compose stacks, each self-contained:

| Lab | Contents |
|-----|----------|
| `01_web_hacking_lab` | DVWA (`:8080`), Juice Shop (`:3001`), WebGoat (`:8081`), nginx reverse proxy |
| `02_pwn_lab` | pwntools client + pwn-server with exploit targets |
| `03_network_lab` | Network attack/defense scenario |
| `04_cloud_container_lab` | Container/Kubernetes misconfig targets |
| `05_full_scenario_lab` | Multi-tier: DMZ web, internal API, DB — full pentest scenario |

All labs run on isolated Docker bridge networks with fixed subnets (e.g., `172.16.0.0/24`).

### Section 57 — Quantum Cryptography (Research-Integrated)

This section is enriched with real research results from ANASIS-II satellite PQC work:
- `02_quantum_key_distribution.md` — §3.3 ANASIS-II case study (QBER 5% rationale, ProVerif 8-property results, P1-c counterexample), §8 design lessons
- `03_post_quantum_algorithms.md` — §8 real liboqs benchmarks (ML-KEM, ML-DSA, SLH-DSA timings), TVLA results (ML-KEM-768 FAIL t=10.91, ML-DSA-44 PASS)
- `04_nist_pqc_standards.md` — §5.5 FIPS 203/204/205 satellite application case
- `05_pqc_migration_strategy.md` — §3.2 military satellite as highest HNDL priority, §5.4 satellite-specific migration risks
- `06_quantum_crypto_ctf_lab.md` — §Challenge 4–5 TVLA timing analysis and P1-c fallback attack labs

## Adding or Editing Content

**New file**: name it `NN_topic_name.md`, write Korean first, add English section with the bilingual header template. Run `translate_to_english.py --file <path>` to auto-generate the English section if needed.

**New section**: create `NN_SectionName/` and add entry to `SECTIONS` dict in `vhack.py` (around line 60).

**File naming**: `NN_영문_소문자_언더스코어.md` — numbers are zero-padded to two digits within a section.

## Constraints

- `vhack.py` must stay stdlib-only (no `pip install`). The only external dependency allowed is in `translate_to_english.py` (`anthropic` package).
- All new educational content must fit within the ethical scope defined in `SECURITY.md` — authorized testing, CTF, bug bounty, or defensive research only.
- Korean is the primary language; English is always added as a second section, never replacing Korean.
