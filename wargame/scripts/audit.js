#!/usr/bin/env node
/* Deep audit (non-CI): surfaces "미완/약함" candidates that verify.js does NOT
   catch. Never prints plaintext flags. Read-only. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// --strict: exit non-zero on [F] leaks and [G] contradictions so CI can gate on
// them. The other sections stay informational ([A] MISSING is a known heuristic
// false positive).
// --reveal: print the offending README term. A term is only a finding because it
// IS an answer, so naming it in a public CI log hands that answer out — keep it
// local-only, the same rule leakscan.js follows.
const STRICT = process.argv.includes('--strict');
const REVEAL = process.argv.includes('--reveal');

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
// A table that stops matching would make this section report a silent 0 forever,
// so treat "could not read the table" as a finding rather than a pass.
const fBlocked = topicRows.length === TIERS.length ? null
  : `README's tier table did not parse — ${topicRows.length}/${TIERS.length} topic rows matched, so [F] checked nothing`;
console.log(`\n--- [F] README topic terms that ARE a challenge answer: ${spelled.length} ---`);
console.log(`    (${terms.size} terms checked across ${topicRows.length} tier rows; describe the topic, don't name the answer)`);
if (fBlocked) console.log(`  ⚠ ${fBlocked}`);
for (const s of spelled.sort((a, b) => a.tier - b.tier)) {
  const where = REVEAL ? `as "${s.term}"` : `(term hidden — rerun locally with --reveal)`;
  console.log(`  ⚠ [t${s.tier}] ${s.id} — spelled in ${s.node} ${where}`);
}

// [G] Does the answer the grader actually accepts match what fmt/prompt promise?
// t4_mft shipped with fmt "(3글자, $___)" and a prompt saying the acronym "starts
// with $", while the stored hash only ever accepted the acronym WITHOUT it — a
// player who followed the stated format was marked wrong, and nothing caught it.
//
// The answer exists only as SHA-256, so recover its *shape* the same way [F]
// works: enumerate a bounded candidate space, hash each under the app's grading
// rule, and keep only the length/charset of whatever hits. The plaintext is
// never stored or printed — only the shape is compared against the declaration.
// Challenges that declare nothing checkable, or whose answer is too long to
// enumerate, are reported as unchecked rather than silently passing.
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGIT = '0123456789';

// A marker is a literal the answer itself carries ("$", "0x", "--"). Prose words
// ("no hyphen") describe how to type the answer and must not be treated as one.
const isMarker = (t) => {
  const v = String(t || '').replace(/`/g, '');
  return v.length > 0 && v.length <= 3 && (/[^\p{L}\p{N}]/u.test(v) || v.length <= 2);
};

function declarationOf(ch) {
  const fmt = ch.fmt || '';
  // a literal skeleton in fmt, e.g. "$___" -> requires a "$" prefix
  let affix = null;
  const tmpl = fmt.match(/([^\s(),/|_]*)_{2,}([^\s(),/|_]*)/);
  if (tmpl && (tmpl[1] || tmpl[2])) affix = { pre: tmpl[1] || '', post: tmpl[2] || '' };
  // "($ 포함)" / "(include the `$`)" also make the marker part of the answer
  const inc = fmt.match(/([^\s(),/|]+)\s*포함/) || fmt.match(/include\s+(?:the\s+)?`?([^\s`)]+)`?/i);
  if (!affix && inc && isMarker(inc[1])) affix = { pre: inc[1].replace(/`/g, ''), post: '' };
  // "( $ 제외 / no $ )" explicitly says the marker is NOT typed
  const exc = fmt.match(/([^\s(),/|]+)\s*제외/) || fmt.match(/\bno\s+`?([^\s`)]+)`?/i);
  const forbid = !affix && exc && isMarker(exc[1]) ? exc[1].replace(/`/g, '') : null;
  // declared length: "3글자", "2자리", "3-letter", "4 digits". fmt only — prompts
  // quote unrelated numbers ("outputs 40 hex chars") that are not the answer.
  const lm = fmt.match(/(\d+)\s*(?:글자|자리)/) || fmt.match(/(\d+)[-\s]?(?:letter|char|digit)/i);
  const len = lm ? +lm[1] : null;
  return { affix, forbid, len, declares: !!(affix || forbid || len) };
}

const decl = new Map();
for (const ch of CHALLENGES) {
  const d = declarationOf(ch);
  // case-sensitive answers are not enumerable over a lowercase space
  if (d.declares && ch.ci && !/FLAG\{/.test(ch.fmt)) decl.set(ch.id, d);
}
// hash -> id, restricted to the challenges we can say something about
const wanted = new Map();
for (const ch of CHALLENGES) if (decl.has(ch.id)) wanted.set(ch.hash, ch.id);

const shape = new Map(); // id -> { len, marker }; marker '' means the bare answer
function sweep(charset, maxLen, pre = '', post = '') {
  const buf = [];
  (function rec(depth) {
    if (depth > 0) {
      const id = wanted.get(sha(pre + buf.join('') + post));
      if (id && !shape.has(id)) shape.set(id, { len: buf.length, marker: pre + post });
    }
    if (depth === maxLen || wanted.size === shape.size) return;
    for (const c of charset) { buf.push(c); rec(depth + 1); buf.pop(); }
  })(0);
}
// staged so the cheap spaces run first; the 36^4 sweep only if still needed
sweep(LOWER, 4);
sweep(DIGIT, 4);
sweep(LOWER + DIGIT, 3);
let stillOpen = [...decl.keys()].filter(id => !shape.has(id));
if (stillOpen.some(id => (decl.get(id).len || 0) >= 4)) sweep(LOWER + DIGIT, 4);
// An answer may legitimately carry its declared marker ("$ne"), and a fmt that
// claims the marker is NOT typed can be wrong the same way. Both only match once
// the marker is applied, so retry every declared marker INCLUDING the forbidden
// ones, otherwise a wrong "제외" slips through as merely unchecked.
stillOpen = [...decl.keys()].filter(id => !shape.has(id));
const markers = new Set();
for (const id of stillOpen) {
  const d = decl.get(id);
  if (d.affix) markers.add(JSON.stringify([d.affix.pre, d.affix.post]));
  if (d.forbid) markers.add(JSON.stringify([d.forbid, '']));
}
for (const m of markers) {
  const [pre, post] = JSON.parse(m);
  sweep(LOWER + DIGIT, 3, pre, post);
}

const bad = [], unchecked = [];
for (const [id, d] of decl) {
  const s = shape.get(id);
  if (!s) { unchecked.push(id); continue; }
  const want = d.affix ? d.affix.pre + d.affix.post : '';
  if (d.affix && s.marker !== want) {
    bad.push(`${id} — fmt/prompt declare a "${want}" marker, but the graded answer has none`);
  } else if (d.forbid && s.marker) {
    bad.push(`${id} — fmt says "${d.forbid} 제외 / no ${d.forbid}", but the graded answer carries it`);
  } else if (d.len && s.len !== d.len) {
    bad.push(`${id} — declares ${d.len} chars, but the graded answer is ${s.len}`);
  }
}
console.log(`\n--- [G] fmt/prompt declarations that the grader contradicts: ${bad.length} ---`);
console.log(`    (${decl.size} challenges declare a length/marker; ${shape.size} answers recovered by bounded sweep, ${unchecked.length} too long to enumerate)`);
for (const b of bad) console.log(`  ⚠ ${b}`);
if (unchecked.length) console.log(`    unchecked: ${unchecked.join(' ')}`);

// [H] Is fmt written in the project's own notation, and does it warn the player
// where the answer's spelling is genuinely ambiguous?
//
// t2_sha1 accepted the algorithm name only unhyphenated while its own hints
// wrote sibling names WITH a hyphen, so a player following the page's spelling
// was marked wrong. [G] could not see it: fmt declared neither a length nor a
// marker, so there was nothing to contradict. The rule that does catch it is
// about the ANSWER, not the declaration — an answer whose rendering a player
// could reasonably separate must pin its length, because inserting a hyphen or
// a space always changes the length and the declaration rules it out. Stating a
// length gives nothing away; it says how to type the answer, not what it is.
//
// The lexicon half keeps fmt worth reading: the same shape was being described
// as 약자/약어/약칭 and as 단어/한 단어/빈칸 한 단어, and qualifiers drifted between
// Korean-only "(3글자)" and bilingual "(3글자 / 3 chars)".
const BASES = new Set([
  'FLAG{...}', '한 단어 / one word', '두 단어 / two words', '약어 / acronym',
  '명령어 / command', '도구 이름 / tool name', '숫자 / number', '확장자 / extension',
  '8진수 / octal', '16진수 / hex', '절대 경로 / absolute path', '파일 이름 / file name',
  '알고리즘 이름 / algorithm name', '기호 / symbol', '연산자 / operator',
  '시스템 콜 / syscall', 'HTTP 메서드 / HTTP method', '헤더 접미사 / header suffix',
  '스킴 이름 / scheme name', '서비스 이름 / service name', 'API 액션 / API action',
  '레지스트리 키 / registry key', 'CIDR 표기 / CIDR notation', '경로 표기 / path notation',
  '리눅스 capability / Linux capability', '사용자:비밀번호 / user:pass', '제목 / title',
  '문구 / phrase', '식 / expression', 'TCP 플래그 / TCP flag', '값 그대로 / literal',
  '장비 이름 / device name', '시그니처 / signature', '포맷 지정자 / format specifier',
  'IP 주소 / IP address',
]);
// every qualifier is bilingual and comes from this list
const QUALIFIERS = [
  /^(\d+)글자 \/ (\d+) chars$/,
  /^하이픈 없이 \/ no hyphen$/,
  /^두 단어 \/ two words$/,
  /^-ing으로 끝남 \/ ends in -ing$/,
  /^(\S+) 포함 \/ include (\S+)$/,
  /^(\S+) 제외 \/ no (\S+)$/,
  /^예: (.+) \/ e\.g\. (.+)$/,
];

const notation = [];
for (const ch of CHALLENGES) {
  const fmt = ch.fmt || '';
  const m = fmt.match(/^(.*?)\s*\(([^()]*)\)$/);
  const base = m ? m[1] : fmt;
  if (!BASES.has(base)) { notation.push(`${ch.id} — "${base}" is not one of the ${BASES.size} approved fmt bases`); continue; }
  if (!m) continue;
  for (const q of m[2].split(', ')) {
    const rule = QUALIFIERS.find(r => r.test(q));
    if (!rule) { notation.push(`${ch.id} — qualifier "${q}" is not written in the approved bilingual form`); continue; }
    const g = q.match(rule);
    // "(3글자 / 4 chars)" would tell the two languages different things
    if (g[1] && g[2] && g[1] !== g[2]) notation.push(`${ch.id} — qualifier "${q}" disagrees between Korean and English`);
  }
}

// Which answers are spelling-ambiguous? Recover shapes for every enumerable
// challenge, not just the ones that opted into a declaration. Separators are in
// the charset precisely so an answer that carries one is visible here.
const SEPS = '-._/: ';
const allWanted = new Map();
for (const ch of CHALLENGES) if (ch.ci && !/FLAG\{/.test(ch.fmt)) allWanted.set(ch.hash, ch.id);
const plain = new Map(); // id -> { len, sep, compound }; plaintext never kept
function scan(charset, maxLen) {
  const buf = [];
  (function rec(depth) {
    if (depth > 0) {
      const id = allWanted.get(sha(buf.join('')));
      if (id && !plain.has(id)) {
        const p = buf.join(''), pattern = p.replace(/[a-z]/g, 'a').replace(/\d/g, '9');
        plain.set(id, { len: p.length, sep: [...SEPS].some(c => p.includes(c)), compound: /^a+9+$|^9+a+$/.test(pattern) });
      }
    }
    if (depth === maxLen) return;
    for (const c of charset) { buf.push(c); rec(depth + 1); buf.pop(); }
  })(0);
}
scan(LOWER, 4);
scan(DIGIT, 4);
scan(LOWER + DIGIT, 4);
scan(LOWER + SEPS, 4);

const undisclosed = [];
for (const ch of CHALLENGES) {
  const p = plain.get(ch.id);
  if (!p || !(p.sep || p.compound)) continue;
  if (declarationOf(ch).len === null) {
    const why = p.sep ? 'carries a separator' : 'is letters run into digits';
    notation.push(`${ch.id} — the graded answer ${why}, so fmt must declare its length; a player who separates it is marked wrong`);
    undisclosed.push(ch.id);
  }
}

// fmt is shown on the challenge card but leakscan.js only reads title/prompt/
// hints, so a fmt that names its own answer would go unnoticed.
const fmtLeaks = [];
for (const ch of CHALLENGES) {
  const tokens = (ch.fmt || '').split(/[\s,()/|]+/).map(t => t.replace(/`/g, '').trim());
  if (tokens.some(t => t.length >= 2 && (ciHash.get(sha(t.toLowerCase())) || csHash.get(sha(t)))?.id === ch.id)) {
    fmtLeaks.push(`${ch.id} — its own fmt spells the answer out`);
  }
}

const hBad = notation.concat(fmtLeaks);
console.log(`\n--- [H] fmt notation and spelling-hazard disclosure: ${hBad.length} ---`);
console.log(`    (${CHALLENGES.length} fmt strings against ${BASES.size} approved bases; ${plain.size} answers recovered, ${[...plain.values()].filter(p => p.sep || p.compound).length} spelling-ambiguous)`);
for (const n of hBad) console.log(`  ⚠ ${n}`);

if (STRICT) {
  const fail = [];
  if (fBlocked) fail.push(`[F] ${fBlocked}`);
  for (const s of spelled.sort((a, b) => a.tier - b.tier)) {
    fail.push(`[F] ${s.id} — the ${s.node} topic row spells out its answer${REVEAL ? ` ("${s.term}")` : ''}`);
  }
  for (const b of bad) fail.push(`[G] ${b}`);
  for (const h of hBad) fail.push(`[H] ${h}`);
  if (fail.length) {
    console.error(`\naudit --strict: FAIL — ${fail.length} issue(s):`);
    for (const f of fail) console.error(`  ✗ ${f}`);
    process.exitCode = 1;
  } else {
    console.log(`\naudit --strict: OK — README's topic rows name no answers ([F]), no fmt/answer contradictions ([G]), fmt on-notation with every spelling hazard disclosed ([H]).`);
  }
}
