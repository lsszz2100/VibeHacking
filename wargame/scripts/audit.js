#!/usr/bin/env node
/* Deep audit (non-CI): surfaces "미완/약함" candidates that verify.js does NOT
   catch. Never prints plaintext flags. Read-only. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const WG = path.resolve(__dirname, '..');
const src = fs.readFileSync(path.join(WG, 'assets/challenges.js'), 'utf8');
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(src + '\nthis.CHALLENGES=CHALLENGES;this.TIERS=TIERS;this.TRACKS=TRACKS;', sandbox);
const { CHALLENGES, TIERS, TRACKS } = sandbox;

const appJs = fs.readFileSync(path.join(WG, 'assets/app.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(WG, 'index.html'), 'utf8');
const haystack = appJs + '\n' + indexHtml;

const idsInApp = new Set();
// find every challenge id literally referenced in app.js/index.html
for (const ch of CHALLENGES) {
  if (haystack.includes(ch.id)) idsInApp.add(ch.id);
}

// Heuristic: a challenge needs an in-site artifact if its prompt tells the
// player to inspect THIS page / console / terminal rather than decode given text.
const ARTIFACT_RE = /이 페이지|this page|개발자도구|devtools|콘솔|console|window\.|현재 (위치|디렉|셸)|이 (셸|터미널)|this (shell|terminal)|localStorage|쿠키|cookie|숨겨져 있|hidden in|페이지 소스|view source|network 탭|네트워크 탭/i;

const artifactNeeded = [];
const oneHint = [];
const shortAnswerNoFmt = [];

for (const ch of CHALLENGES) {
  const p = (ch.prompt.ko || '') + '\n' + (ch.prompt.en || '');
  if (ARTIFACT_RE.test(p)) {
    artifactNeeded.push(ch);
  }
  if ((ch.hints.ko || []).length < 2 || (ch.hints.en || []).length < 2) oneHint.push(ch);
  // ci (case-insensitive short answer) but fmt still demands FLAG{...} wrapper?
  if (ch.ci && /FLAG\{/.test(ch.fmt)) shortAnswerNoFmt.push(ch);
}

console.log(`\n=== TOTAL: ${CHALLENGES.length} challenges ===\n`);

// Distribution: tier x track
console.log('--- Tier x Track distribution ---');
const trackIds = TRACKS.map(t => t.id);
let header = 'tier'.padEnd(6);
for (const t of trackIds) header += t.padEnd(11);
header += 'SUM  need';
console.log(header);
for (const t of TIERS) {
  let row = String(t.id).padEnd(6);
  let sum = 0;
  for (const tr of trackIds) {
    const n = CHALLENGES.filter(c => c.tier === t.id && c.track === tr).length;
    sum += n;
    row += String(n || '·').padEnd(11);
  }
  row += String(sum).padEnd(5) + String(t.need);
  console.log(row);
}

console.log(`\n--- [A] In-site artifact-dependent challenges (${artifactNeeded.length}) ---`);
console.log('    (flag must be planted in index.html/app.js — verify each is wired)');
for (const ch of artifactNeeded) {
  const wired = idsInApp.has(ch.id);
  console.log(`  ${wired ? 'OK ' : '⚠ MISSING'}  [${ch.id}]  ${ch.title.ko}`);
}

console.log(`\n--- [B] Challenge ids NOT referenced anywhere in app.js/index.html (${CHALLENGES.length - idsInApp.size}) ---`);
console.log('    (fine for pure decode/knowledge tasks; a concern only if artifact-dependent)');

console.log(`\n--- [C] Minimally-hinted (<2 hints in some lang): ${oneHint.length} ---`);
for (const ch of oneHint) console.log(`  [${ch.id}] ko:${ch.hints.ko.length} en:${ch.hints.en.length}`);

console.log(`\n--- [D] ci(case-insensitive) but fmt shows FLAG{...} wrapper: ${shortAnswerNoFmt.length} ---`);
for (const ch of shortAnswerNoFmt) console.log(`  [${ch.id}] fmt=${ch.fmt}`);

// Points sanity
const pts = CHALLENGES.map(c => c.points);
console.log(`\n--- [E] Points: min ${Math.min(...pts)}, max ${Math.max(...pts)}, avg ${(pts.reduce((a,b)=>a+b,0)/pts.length).toFixed(0)} ---`);

// [F] Does README's topics column spell out any answer?
// Answers live only as SHA-256, so hash each topic term under the app's own
// grading rule (ci ? lowercase : as-typed) and look for a hash hit. A hit means
// the table hands a player that challenge's answer. Needs no plaintext, so it
// stays safe to run anywhere.
const crypto = require('crypto');
const sha = (str) => crypto.createHash('sha256').update(str, 'utf8').digest('hex');
const ciHash = new Map(), csHash = new Map();
for (const c of CHALLENGES) (c.ci ? ciHash : csHash).set(c.hash, c);

const readme = fs.readFileSync(path.join(WG, 'README.md'), 'utf8');
const topicRows = readme.split('\n').filter(l => /^\| `(perimeter|webserver|internal|vault|core)`/.test(l));
const terms = new Map();
for (const row of topicRows) {
  const cells = row.split('|');
  if (cells.length < 4) continue;
  for (const chunk of cells[3].split(/[,·/()|]|\s—\s/)) {
    const t = chunk.trim().replace(/^\*+|\*+$/g, '').replace(/`/g, '');
    if (t.length >= 2 && !terms.has(t)) terms.set(t, cells[1].trim());
    for (const w of t.split(/\s+/)) {
      const ww = w.trim();
      if (ww.length >= 2 && !terms.has(ww)) terms.set(ww, cells[1].trim());
    }
  }
}
const spelled = [];
for (const [term, node] of terms) {
  const hit = ciHash.get(sha(term.toLowerCase())) || csHash.get(sha(term));
  if (hit) spelled.push({ term, node, id: hit.id, tier: hit.tier });
}
console.log(`\n--- [F] README topic terms that ARE a challenge answer: ${spelled.length} ---`);
console.log(`    (${terms.size} terms checked across ${topicRows.length} tier rows; describe the topic, don't name the answer)`);
for (const s of spelled.sort((a, b) => a.tier - b.tier)) {
  console.log(`  ⚠ [t${s.tier}] ${s.id} — spelled in ${s.node} as "${s.term}"`);
}
