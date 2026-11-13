---
name: wargame-chall-builder
description: "Use when creating, editing, or auditing challenges and tracks in the VibeHacking wargame (wargame/assets/challenges.js), adding new CTF problems, updating topic tables in wargame/README.md, or resolving audit strict violations [A]-[J]. Also use whenever the user mentions adding wargame tracks, verifying flag hashes, or scaling the 2,345-challenge pool."
---

# Wargame Challenge Builder

A specialized skill for authoring, modifying, and strictly auditing challenges in the VibeHacking browser-based wargame engine.

## Core Invariant: The 4-Stage Audit Gate

Every change to `wargame/assets/challenges.js` or `wargame/README.md` MUST pass all 4 audit gates before committing:

1. `verify.js`: Structural invariants, id uniqueness, Tier gates & HUD counts match.
2. `leakscan.js`: Zero cross-challenge answer leaks in prompts and hints.
3. `audit.js --strict`: Format precision (`[G]`, `[H]`), zero topic table answer spoilers (`[F]`), zero stemming/plural ambiguities (`[J]`).
4. `solve-derivable.js`: 100% automated solving of all derivable challenges.

Run the bundled pre-audit script before finishing any task:
```bash
python .agents/skills/wargame-chall-builder/scripts/pre_audit.py
```

---

## Challenge Object Structure

Each challenge in `wargame/assets/challenges.js` must follow this schema:

```json
{
  "id": "t2_example_id",
  "tier": 2,
  "cat": "web",
  "track": "web",
  "points": 100,
  "ci": true,
  "hash": "<sha256 of lowercase trimmed plaintext>",
  "fmt": "한 단어 / one word (8글자 / 8 chars)",
  "title": {
    "ko": "한글 제목",
    "en": "English Title"
  },
  "prompt": {
    "ko": "도전 과제 설명 및 질문",
    "en": "Challenge description and question"
  },
  "hints": {
    "ko": [
      "첫 번째 점진적 힌트",
      "결정적 힌트 (정답 평문 노출 금지)"
    ],
    "en": [
      "First progressive hint",
      "Decisive hint (do not leak plaintext)"
    ]
  }
}
```

---

## Authoring Workflows

### 1. Generating Challenge Snippets with `gen_challenge.py`

Never hand-compute SHA-256 hashes or guess length qualifiers. Use the bundled generator:

```bash
# Calculate hash and length pinning for an answer
python .agents/skills/wargame-chall-builder/scripts/gen_challenge.py --answer "credentials"

# Validate a complete JSON definition
python .agents/skills/wargame-chall-builder/scripts/gen_challenge.py --json-input my_chall.json
```

### 2. Format (`fmt`) Rules to Avoid [H] and [J] Rejections
- Always start with an approved base string (see `references/fmt_standards.md`).
- If an answer has singular/plural ambiguity (e.g. `credential` vs `credentials`, `header` vs `headers`), you **MUST** pin the length explicitly: `(11글자 / 11 chars)`.
- If `"ci": true`, the hash is `sha256(answer.strip().toLowerCase())`. Never include `FLAG{...}` in `fmt` when `ci` is enabled.

### 3. Topic Table Synchronization in `wargame/README.md`
When a new track is added, you must update the Tier 0~4 tables in `wargame/README.md`:
- Every tier must contain an entry for each track (`335` total rows across 67 tracks x 5 tiers).
- **Anti-Leak [F] Rule**: The topic description in `README.md` must NEVER contain a word whose SHA-256 hash equals any challenge's answer in the wargame! Use broad terminology or synonyms (e.g., use `incident assessment` instead of `triage`).

### 4. Verification & Self-Check

Before claiming completion:
```bash
python .agents/skills/wargame-chall-builder/scripts/pre_audit.py
```
If any check fails, refer to `references/audit_codes.md` to identify the rule violation and resolve it immediately.
