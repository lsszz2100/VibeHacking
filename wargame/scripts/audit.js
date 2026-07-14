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
