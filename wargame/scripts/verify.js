#!/usr/bin/env node
/* CI regression guard for the wargame. Structural-only: never reads or
   needs plaintext answers, so it stays safe to run in public CI without
   leaking flags. Fails (non-zero exit) on any check below. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const WG = path.join(ROOT, 'wargame');

function loadChallenges() {
  const src = fs.readFileSync(path.join(WG, 'assets/challenges.js'), 'utf8');
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(src + '\nthis.CHALLENGES=CHALLENGES;this.TIERS=TIERS;this.TRACKS=TRACKS;', sandbox);
  return sandbox;
}

const errors = [];
const fail = (msg) => errors.push(msg);

const { CHALLENGES, TIERS, TRACKS } = loadChallenges();
const total = CHALLENGES.length;
const tierIds = new Set(TIERS.map((t) => t.id));
const trackIds = new Set(TRACKS.map((t) => t.id));

// --- per-challenge structural checks ---
const seenIds = new Set();
const HEX64 = /^[0-9a-f]{64}$/;
const FLAG_RE = /FLAG\{[^}]+\}/g;

for (const ch of CHALLENGES) {
  const where = `[${ch.id || '<no id>'}]`;
  if (!ch.id || seenIds.has(ch.id)) fail(`${where} duplicate or missing id`);
  seenIds.add(ch.id);
  if (!tierIds.has(ch.tier)) fail(`${where} tier ${ch.tier} not in TIERS`);
  if (!trackIds.has(ch.track)) fail(`${where} track ${ch.track} not in TRACKS`);
  if (!HEX64.test(ch.hash || '')) fail(`${where} hash is not 64 lowercase hex chars`);
  if (typeof ch.ci !== 'boolean') fail(`${where} ci must be boolean`);
  if (!Number.isInteger(ch.points) || ch.points <= 0) fail(`${where} points must be a positive integer`);
  for (const lang of ['ko', 'en']) {
    if (!ch.title || !ch.title[lang]) fail(`${where} missing title.${lang}`);
    if (!ch.prompt || !ch.prompt[lang]) fail(`${where} missing prompt.${lang}`);
    if (!ch.hints || !Array.isArray(ch.hints[lang]) || ch.hints[lang].length < 1) {
      fail(`${where} missing/empty hints.${lang}`);
    }
  }

  // Leak guard: if a literal FLAG{...} in this challenge's own prompt/hints
  // happens to hash to this challenge's own answer hash, the real flag
  // leaked into visible text (fmt placeholders like "FLAG{...}" never match).
  const haystacks = [
    ch.prompt && ch.prompt.ko, ch.prompt && ch.prompt.en,
    ...((ch.hints && ch.hints.ko) || []), ...((ch.hints && ch.hints.en) || []),
  ].filter(Boolean);
  for (const text of haystacks) {
    const matches = text.match(FLAG_RE) || [];
    for (const m of matches) {
      const norm = ch.ci ? m.trim().toLowerCase() : m.trim();
      const h = require('crypto').createHash('sha256').update(norm).digest('hex');
      if (h === ch.hash) fail(`${where} the correct flag literally appears in prompt/hints text (leak)`);
    }
  }
}

// --- tier gating sanity: need <= number of challenges unlocked by then ---
for (const t of TIERS) {
  const countAtOrBelow = CHALLENGES.filter((c) => c.tier <= t.id).length;
  if (t.need > countAtOrBelow) {
    fail(`tier ${t.id} (${t.en}) needs ${t.need} solves but only ${countAtOrBelow} challenges exist at tier <= ${t.id}`);
  }
}

// --- rank ladder sanity: thresholds must track the pool, not lag behind it ---
// This decayed silently once: thresholds scaled for a 75-challenge pool left
// "Legend" at 70 solves, which is 93% of 75 but only a third of 210. Pull the
// real ladder and its resolver out of app.js instead of restating them here (a
// copy would drift the same way) and resolve them against the actual pool.
const LEGEND_MIN_SHARE = 0.8; // the top rank has to mean "nearly cleared it"
const appJs = fs.readFileSync(path.join(WG, 'assets/app.js'), 'utf8');
const ranksSrc = appJs.match(/const RANKS = \[[\s\S]*?\];/);
const rankMinSrc = appJs.match(/const rankMin = .*;/);

if (!ranksSrc || !rankMinSrc) {
  fail('app.js: could not find the RANKS ladder and/or its rankMin resolver, so the rank checks ran on nothing');
} else {
  const resolveRanks = (pool, tail) => {
    const s = { CHALLENGES: { length: pool } };
    vm.createContext(s);
    vm.runInContext(`${ranksSrc[0]}\n${rankMinSrc[0]}\n${tail}`, s);
    return s.t;
  };
  const steps = resolveRanks(total, 'this.t=RANKS.map(rankMin);');
  const top = steps[steps.length - 1];

  if (steps[0] !== 0) {
    fail(`rank ladder: the lowest rank starts at ${steps[0]} solves, so a player with 0 solves has no rank`);
  }
  for (let i = 1; i < steps.length; i++) {
    if (steps[i] <= steps[i - 1]) {
      fail(`rank ladder: rank ${i} unlocks at ${steps[i]} solves, not above rank ${i - 1} at ${steps[i - 1]} — one of them is unreachable`);
    }
  }
  if (top > total) {
    fail(`rank ladder: the top rank needs ${top} solves but only ${total} challenges exist`);
  } else if (top < Math.ceil(LEGEND_MIN_SHARE * total)) {
    const pct = Math.round((top / total) * 100);
    fail(`rank ladder: the top rank lands at ${top}/${total} (${pct}%), below the ${Math.round(LEGEND_MIN_SHARE * 100)}% the top rank is supposed to mean — thresholds have fallen behind the pool`);
  }

  // It also has to be a *function* of the pool. Re-resolve against a doubled
  // pool: if the top rank does not move, someone hardcoded counts again and the
  // ladder will decay on the next expansion even if it passes the checks today.
  const doubled = resolveRanks(total * 2, 'this.t=rankMin(RANKS[RANKS.length-1]);');
  if (doubled === top) {
    fail(`rank ladder: the top rank stays at ${top} solves when the pool doubles to ${total * 2} — thresholds are hardcoded counts, not shares of the pool`);
  }
}

// --- every track must have at least one challenge in each tier band it claims ---
for (const tr of TRACKS) {
  const count = CHALLENGES.filter((c) => c.track === tr.id).length;
  if (count === 0) fail(`track ${tr.id} has zero challenges`);
}

// --- cross-file count sync: index.html HUD and README badges must match CHALLENGES.length ---
const indexHtml = fs.readFileSync(path.join(WG, 'index.html'), 'utf8');
const hudMatch = indexHtml.match(/id="hudSolved"[^>]*>0\/(\d+)/);
if (!hudMatch) {
  fail('index.html: could not find hudSolved "0/N" HUD marker');
} else if (Number(hudMatch[1]) !== total) {
  fail(`index.html HUD shows 0/${hudMatch[1]} but challenges.js has ${total} challenges`);
}

const readme = fs.readFileSync(path.join(WG, 'README.md'), 'utf8');
const totalKo = readme.match(/총\s*\*\*(\d+)문제\*\*/);
const totalEn = readme.match(/Total\s*\*\*(\d+)\s*challenges\*\*/);
if (!totalKo || Number(totalKo[1]) !== total) {
  fail(`wargame/README.md KO total says ${totalKo ? totalKo[1] : '<missing>'} but challenges.js has ${total}`);
}
if (!totalEn || Number(totalEn[1]) !== total) {
  fail(`wargame/README.md EN total says ${totalEn ? totalEn[1] : '<missing>'} but challenges.js has ${total}`);
}

// --- report ---
if (errors.length) {
  console.error(`wargame verify: ${errors.length} problem(s) found in ${total} challenges:\n`);
  for (const e of errors) console.error(' - ' + e);
  process.exit(1);
}
console.log(`wargame verify: OK — ${total} challenges, ${TIERS.length} tiers, ${TRACKS.length} tracks, no leaks, counts in sync, rank ladder scaled to the pool.`);
