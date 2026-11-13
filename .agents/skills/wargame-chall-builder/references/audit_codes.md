# Wargame Audit Codes Reference ([A] ~ [J])

`audit.js --strict` enforces 10 strict heuristics to prevent user frustration, grading bugs, and accidental spoiler leaks in the 2,345-challenge wargame.

| Code | Severity | Description | Fix Requirement |
|---|---|---|---|
| `[A]` | Informational | Artifacts checked (DevTools, comments, DOM) | Ensure artifact challenges have corresponding solvers in `solve-derivable.js`. |
| `[B]` | Informational | Challenge IDs not referenced in `app.js`/`index.html` | Expected for pure decode/knowledge questions. |
| `[C]` | Blocking | Minimally hinted (< 2 hints in `ko` or `en`) | Provide at least 2 progressive hints in both languages. |
| `[D]` | Blocking | `ci: true` but `fmt` contains `FLAG{...}` wrapper | Format must not instruct flag wrappers if grader does case-insensitive lowercasing. |
| `[E]` | Informational | Points distribution bounds | Tier 0: 10-50, Tier 1: 50-80, Tier 2: 80-120, Tier 3: 120-250, Tier 4: 250-500. |
| `[F]` | Blocking | README topic column contains a challenge answer | Never use a challenge answer as a topic keyword in `wargame/README.md`. Use synonyms or generalized descriptions. |
| `[G]` | Blocking | Stated `fmt` promises a length or marker the grader rejects | Ensure the accepted plaintext matches the exact character count stated in `fmt`. |
| `[H]` | Blocking | Unapproved `fmt` base or undisclosed spelling ambiguity | Start `fmt` with an approved base string and qualify length: `(N글자 / N chars)`. |
| `[I]` | Blocking | Textbook chapters spell the answer another way | Pin with exact format hint if common variations exist. |
| `[J]` | Blocking | Stemming or singular/plural ambiguity | When singular and plural forms coexist (e.g., `credential` vs `credentials`), `fmt` must explicitly state `(11글자 / 11 chars)`. |
