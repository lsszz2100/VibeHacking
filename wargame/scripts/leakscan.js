#!/usr/bin/env node
/* Cross-challenge answer-leak scanner.

   verify.js only catches a literal FLAG{...} that hashes to its own
   challenge. It cannot see the other (and more common) failure mode: a
   knowledge answer such as "attach" or "config" sitting in plain sight in
   some *other* challenge's prompt or hints. Answers are stored as SHA-256
   only, so the way to find those is to hash every 1..3-gram of every visible
   string and look the digest up in the answer table.

   Output is deliberately redacted: it names the challenge that leaks and the
   challenge whose answer leaked, never the matched text. That keeps the
   report safe to print in public CI logs. Pass --reveal locally when you
   need the actual token to fix it. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const WG = path.join(ROOT, 'wargame');
const REVEAL = process.argv.includes('--reveal');
const MAX_NGRAM = 3;

/* A token that already appears in this many challenges or more is domain
   vocabulary ("flag", "from", "base64", "secret"), not a targeted spoiler:
   seeing it somewhere tells a player nothing about which challenge it answers.
   Below the threshold the match is specific enough to matter. */
const UBIQUITY_WAIVER = 5;

/* Sub-threshold hits that are still intentional, because the wording cannot
   drop the token without breaking the challenge that contains it. Keyed by
   "<challenge whose text carries it> -> <challenge whose answer it is>";
   anything else under the threshold fails the run. */
const ALLOWLIST = new Map([
  ['t2_md5 -> t0_md5', 'posing a hash-cracking question requires naming the algorithm'],
  ['t2_sha1 -> t0_md5', 'the hint compares digest lengths across algorithms'],
  ['t0_source -> t2_sqlcomment', 'HTML comment syntax happens to be the SQL comment token'],
  ['t3_jwtnone -> t2_jwt', "the JWT's own header decodes to it regardless of the prose"],
  ['t0_base64 -> t0_decimal', 'title word, generic in this domain'],
  ['t0_devtools -> t0_decimal', 'title word, generic in this domain'],
  ['t4_k8ssecret -> t0_decimal', 'Kubernetes object name, cannot be renamed'],
  ['t3_yara -> t2_strings', 'literal YARA rule section name'],
  ['t4_volatility -> t2_strings', 'names the tool used in the scenario'],
  ['t0_base64 -> t2_strings', 'ordinary English plural in the hint'],
]);

function loadChallenges() {
  const src = fs.readFileSync(path.join(WG, 'assets/challenges.js'), 'utf8');
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(src + '\nthis.CHALLENGES=CHALLENGES;', sandbox);
  return sandbox.CHALLENGES;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// The app grades with `ch.ci ? flag.trim().toLowerCase() : flag.trim()`, so a
// candidate has to be hashed both ways and looked up in the matching table.
function buildTables(challenges) {
  const ci = new Map();
  const exact = new Map();
  for (const ch of challenges) (ch.ci ? ci : exact).set(ch.hash, ch.id);
  return { ci, exact };
}

function visibleStrings(ch) {
  const out = [];
  for (const lang of ['ko', 'en']) {
    if (ch.title && ch.title[lang]) out.push(ch.title[lang]);
    if (ch.prompt && ch.prompt[lang]) out.push(ch.prompt[lang]);
    for (const h of (ch.hints && ch.hints[lang]) || []) out.push(h);
  }
  return out;
}

// Answers range from bare words to things like `$ne`, `0.0.0.0/0` and
// `/var/run/docker.sock`, so each n-gram is tested as written and with
// surrounding punctuation shaved off.
const EDGE = /^[^\w$/_.\-{}[\]]+|[^\w$/_.\-{}[\]]+$/g;
function candidates(text) {
  const words = text.split(/\s+/).filter(Boolean);
  const out = [];
  for (let n = 1; n <= MAX_NGRAM; n++) {
    for (let i = 0; i + n <= words.length; i++) {
      const raw = words.slice(i, i + n).join(' ');
      out.push(raw);
      const trimmed = raw.replace(EDGE, '');
      if (trimmed && trimmed !== raw) out.push(trimmed);
    }
  }
  return out;
}

const challenges = loadChallenges();
const { ci, exact } = buildTables(challenges);
const texts = new Map(challenges.map((ch) => [ch.id, visibleStrings(ch).join('\n')]));

function ubiquity(token) {
  const re = new RegExp(`(?:^|[^\\w])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^\\w]|$)`, 'i');
  let n = 0;
  for (const t of texts.values()) if (re.test(t)) n++;
  return n;
}

const hits = [];
for (const ch of challenges) {
  const seen = new Set();
  for (const text of visibleStrings(ch)) {
    for (const cand of candidates(text)) {
      const norm = cand.trim();
      if (!norm) continue;
      const owner = ci.get(sha(norm.toLowerCase())) || exact.get(sha(norm));
      if (!owner) continue;
      const key = `${ch.id} -> ${owner}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // A challenge spelling out its own answer spoils itself no matter how
      // common the word is, so self-hits skip the ubiquity waiver.
      const self = owner === ch.id;
      hits.push({ key, self, token: norm, ubi: self ? 1 : ubiquity(norm) });
    }
  }
}

const generic = hits.filter((h) => h.ubi >= UBIQUITY_WAIVER);
const specific = hits.filter((h) => h.ubi < UBIQUITY_WAIVER);
const waived = specific.filter((h) => ALLOWLIST.has(h.key));
const offenders = specific.filter((h) => !ALLOWLIST.has(h.key));

// An allowlist entry that no longer fires is stale: either the text was
// rewritten and the waiver should go, or it is quietly covering a new leak.
const stale = [...ALLOWLIST.keys()].filter((k) => !specific.some((h) => h.key === k));

for (const h of waived) console.log(`  (allowlisted) ${h.key} — ${ALLOWLIST.get(h.key)}`);
for (const k of stale) console.log(`  (stale allowlist entry, no longer matches) ${k}`);

if (offenders.length) {
  console.error(`\nwargame leakscan: ${offenders.length} answer leak(s) across ${challenges.length} challenges:\n`);
  for (const h of offenders) {
    const kind = h.self ? 'own answer in its own text' : `another challenge answer, seen in ${h.ubi} challenge(s)`;
    console.error(` - ${h.key}  (${kind})${REVEAL ? `  token: ${JSON.stringify(h.token)}` : ''}`);
  }
  if (!REVEAL) console.error('\nRun locally with --reveal to see the offending tokens (never in CI logs).');
  process.exit(1);
}
console.log(`wargame leakscan: OK — ${challenges.length} challenges, no targeted answer leaks in visible text ` +
  `(${waived.length} allowlisted, ${generic.length} generic terms above the ubiquity threshold).`);
