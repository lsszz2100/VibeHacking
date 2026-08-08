#!/usr/bin/env node
/* Deep audit (non-CI): surfaces "미완/약함" candidates that verify.js does NOT
   catch. Never prints plaintext flags. Read-only. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// --strict: exit non-zero on the checks that can mark a correct player wrong or
// hand an answer out — [F] [G] [H] [I] [J] — so CI can gate on them. The other
// sections stay informational ([A] MISSING is a known heuristic false positive).
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

// [I] Does the grader insist on a spelling our own chapters contradict?
//
// [H] only sees a hazard when the answer ITSELF carries a separator, and only
// while it stays inside a four-character sweep. The case that slips past is the
// mirror image: an answer written closed up whose ordinary rendering is
// hyphenated. A player types "fine-tuning" the way this repo's own chapters
// write it, is marked wrong, and fmt said nothing. Enumeration cannot reach a
// ten-letter answer, so the candidates come from the only authority the project
// has on how these terms are spelled — the 492 chapters. Every hyphenated token
// and every two/three-word run there is re-rendered closed, hyphenated, spaced
// and underscored, and each rendering is hashed against the stored answers. The
// corpus supplies the word; the hash only reports which rendering the grader
// takes, so nothing is recovered that the chapters did not already say.
//
// A match is not yet a hazard. It becomes one when the chapters write the term
// the OTHER way at least as often (and at least MIN_EVIDENCE times), because
// that is the spelling a player who learned it here would reach for. fmt then
// has to separate the two: a length settles closed-versus-separated, but a
// hyphen and a space are the same length, so those need the word count or the
// marker said out loud.
//
// MIN_EVIDENCE is a false-positive margin, not a detector: one stray "root kit"
// in a chapter should not force a disclosure onto "rootkit". At the current
// content it changes no verdict — dropping it to 1 finds the same hazards — but
// it is what keeps the sweep at tens of thousands of terms instead of 280k.
const MIN_EVIDENCE = 3;
const REPO = path.resolve(WG, '..');
function chapters(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) chapters(p, out);
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}
const freqClosed = new Map(), freqHyphen = new Map(), freqSpace = new Map();
const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);
const chapterFiles = chapters(REPO);
for (const f of chapterFiles) {
  const txt = fs.readFileSync(f, 'utf8').toLowerCase();
  let w1 = null, w2 = null, end = -1;
  for (const m of txt.matchAll(/[a-z]+(?:-[a-z]+)*/g)) {
    const w = m[0];
    if (w.includes('-')) { bump(freqHyphen, w); w1 = w2 = null; end = -1; continue; }
    bump(freqClosed, w);
    // only a single space keeps a run going; punctuation or a newline ends it
    if (w1 !== null && txt.slice(end, m.index) === ' ') {
      bump(freqSpace, `${w1} ${w}`);
      if (w2 !== null) bump(freqSpace, `${w2} ${w1} ${w}`);
      w2 = w1;
    } else w2 = null;
    w1 = w; end = m.index + w.length;
  }
}

const RENDERINGS = ['closed', 'hyphen', 'space', 'under'];
const render = (form, parts) => parts.join(form === 'closed' ? '' : form === 'hyphen' ? '-' : form === 'space' ? ' ' : '_');
// underscores belong to code, not prose, so that rendering has no corpus support
const evidence = (form, parts) =>
  (form === 'closed' ? freqClosed : form === 'hyphen' ? freqHyphen : form === 'space' ? freqSpace : new Map())
    .get(render(form, parts)) || 0;

// A term can only ever produce a hazard through a rendering the chapters use at
// least MIN_EVIDENCE times, so terms that never reach it are dropped before the
// hash sweep rather than matched and then discarded. The closed form counts as a
// rendering here: "railfence" written often enough is a rival to a spaced answer
// that the chapters themselves happen to write only once.
const attested = (parts) => Math.max(evidence('closed', parts), evidence('hyphen', parts), evidence('space', parts)) >= MIN_EVIDENCE;
const termParts = new Set();
for (const h of freqHyphen.keys()) { const p = h.split('-'); if (attested(p)) termParts.add(p.join(' ')); }
for (const s of freqSpace.keys()) { const p = s.split(' '); if (attested(p)) termParts.add(s); }

// id -> the rendering the grader accepts, and the term it came from
const graded = new Map();
for (const t of termParts) {
  const parts = t.split(' ');
  for (const form of RENDERINGS) {
    const id = allWanted.get(sha(render(form, parts)));
    if (!id) continue;
    // an answer can match several terms; keep the best-attested one
    const ev = RENDERINGS.reduce((s, f) => s + evidence(f, parts), 0);
    const prev = graded.get(id);
    if (!prev || ev > prev.ev) graded.set(id, { form, parts, ev });
  }
}

// Does fmt tell the two renderings apart? "한 단어 / one word" deliberately does
// NOT settle a hyphen: a hyphenated compound is still one word, which is exactly
// how a "fine-tuning" answer would keep looking compliant.
function separates(ch, form, rival, parts) {
  const fmt = ch.fmt || '';
  const sameLength = form !== 'closed' && rival !== 'closed';
  if (!sameLength && declarationOf(ch).len !== null) return true;
  if (form === 'closed') return rival === 'space' ? /한 단어 \/ one word/.test(fmt) : /하이픈 없이 \/ no hyphen/.test(fmt);
  if (form === 'space') return parts.length === 2 ? /두 단어 \/ two words/.test(fmt) : /문구 \/ phrase|제목 \/ title/.test(fmt);
  if (form === 'hyphen') return /- 포함 \/ include -/.test(fmt);
  return /_ 포함 \/ include _/.test(fmt);
}
const SPELLING = { closed: 'closed up', hyphen: 'with a hyphen', space: 'as separate words', under: 'with an underscore' };

const iBad = [];
let hazardous = 0;
if (freqHyphen.size < 500) {
  // a trimmed checkout would leave the lexicon empty and every answer "clean"
  iBad.push(`the chapter corpus is missing or unreadable — ${chapterFiles.length} .md files yielded only ${freqHyphen.size} hyphenated terms, so nothing could be checked`);
} else {
  for (const [id, m] of graded) {
    const mine = evidence(m.form, m.parts);
    const rivals = RENDERINGS.filter(f => f !== m.form && evidence(f, m.parts) >= MIN_EVIDENCE && evidence(f, m.parts) >= mine);
    if (!rivals.length) continue;
    hazardous++;
    const ch = CHALLENGES.find(c => c.id === id);
    for (const r of rivals.filter(r => !separates(ch, m.form, r, m.parts))) {
      iBad.push(`${id} — our own chapters spell this answer ${SPELLING[r]} at least as often as the grader's spelling, and fmt does not rule that out`);
    }
  }
}
console.log(`\n--- [I] answers our own chapters spell another way: ${iBad.length} ---`);
console.log(`    (${allWanted.size} graded answers against ${termParts.size} terms the ${chapterFiles.length} chapters use ${MIN_EVIDENCE}+ times; ${graded.size} answers are one of them, ${hazardous} spelled another way at least as often)`);
for (const n of iBad) console.log(`  ⚠ ${n}`);

// [J] Does the grader insist on one word-form where the reader just met another?
//
// [I] settles how a term is BROKEN UP — closed, hyphenated, spaced. What no
// guard has looked at is which FORM of the word the grader takes. t1_lb asked
// for the device (an -er noun) while its own hint glossed the act, and the
// player who paid for that hint was marked wrong by it. Separation cannot see
// that: "balancer" and "balancing" are one word each and the same shape, so the
// word count fmt declares rules out neither.
//
// Two things put a form in a player's head, so both count as evidence: the 492
// chapters they learned the term from, and the challenge text in front of them.
// Neither half is told the answer. The corpus half groups every attested term
// by its stem and hashes the forms that family already has; the self-text half
// mutates each visible token into its own siblings and hashes those. A hit
// reports only which form the grader takes, which the corpus or the challenge
// had already written.
//
// A rival is a hazard when the chapters use it at least as often as the graded
// form, or when it sits in the challenge's own text at all. fmt then has to
// tell the two apart, and only two things do: a declared length, when the forms
// are different lengths, and "-ing으로 끝남 / ends in -ing".
//
// Two limits, stated so this is not mistaken for a clean bill:
//   - challenges solve-derivable.js covers are exempt. Their answer is decoded
//     or read off the page rather than recalled, so no chapter's spelling can
//     mislead; firing there would only buy a meaningless fmt qualifier.
//   - a gloss that PARAPHRASES the wrong form is invisible. t1_lb's own hint
//     ("to distribute weight evenly") shares no stem with the answer, and the
//     chapters never write "load balancing" at all, so neither half sees it.
//     Only a cognate is detectable; the paraphrase case is still a read.
const solverSrc = fs.readFileSync(path.join(WG, 'scripts/solve-derivable.js'), 'utf8');
const solverBlock = solverSrc.slice(solverSrc.indexOf('const SOLVERS = new Map(['));
const DERIVABLE = new Set([...solverBlock.matchAll(/^ {2}\['(\w+)',/gm)].map(m => m[1]));

// One suffix comes off, then the spelling changes English makes to attach it are
// undone, so that "balance", "balancer" and "balancing" land on one stem. Longest
// suffix first, and never down to a stub: "portion" must not become "port".
const SUFFIXES = ['ations', 'ation', 'ities', 'ity', 'ments', 'ment', 'ances', 'ance',
  'ences', 'ence', 'ings', 'ing', 'ers', 'er', 'ors', 'or', 'ies', 'ied', 'ed', 'es', 's'];
const ENDINGS = ['', 'e', 'er', 'ers', 'or', 'ors', 'ing', 'ings', 'ed', 's', 'es',
  'ion', 'ation', 'ity', 'ment', 'ance', 'ence', 'y'];
function stemOf(w) {
  let s = w;
  for (const suf of SUFFIXES) {
    if (s.endsWith(suf) && s.length - suf.length >= 4) { s = s.slice(0, -suf.length); break; }
  }
  if (/([bdfglmnprtz])\1$/.test(s)) s = s.slice(0, -1); // "stopping" -> "stop"
  return s.replace(/e$/, '').replace(/y$/, 'i');
}
// The self-text half never learns the answer, so it cannot stem TOWARDS it —
// it grows every form the token's stem can take and lets the hash pick.
function siblingsOf(w) {
  const st = stemOf(w), out = new Set();
  if (st.length < 3) return out;
  for (const e of ENDINGS) {
    out.add(st + e);
    if (/[bdglmnprt]$/.test(st) && /^(ing|ed|er|ers)/.test(e)) out.add(st + st.slice(-1) + e);
  }
  out.delete(w);
  return out;
}
// "한 단어 / one word" is true of both forms, and so is every word count: only a
// length or the -ing qualifier actually separates two forms of one stem.
function separatesForm(ch, mine, rival) {
  const fmt = ch.fmt || '';
  if (/-ing으로 끝남 \/ ends in -ing/.test(fmt) && mine.endsWith('ing') && !rival.endsWith('ing')) return true;
  return declarationOf(ch).len !== null && mine.length !== rival.length;
}

const jBad = [];
const formPlain = new Map(); // id -> the graded form; plaintext never printed
const formSeen = new Set();  // ids that have a rival form at all, separated or not
const seenPair = new Set();
function noteRival(id, mine, rival, where) {
  formPlain.set(id, mine);
  if (DERIVABLE.has(id)) return;
  formSeen.add(id);
  const ch = CHALLENGES.find(c => c.id === id);
  if (!ch || separatesForm(ch, mine, rival)) return;
  const key = `${id}|${rival}`;
  if (seenPair.has(key)) return;
  seenPair.add(key);
  jBad.push(`${id} — ${where} this answer in another form of the same word, and fmt does not rule that form out`);
}

let families = 0, formsHashed = 0;
if (!DERIVABLE.size) {
  // a renamed SOLVERS would silently exempt nothing and check everything, or a
  // moved one would exempt nothing at all — either way the count must not be 0
  jBad.push('solve-derivable.js no longer declares SOLVERS where this check reads it, so no challenge could be exempted');
} else {
  // grouped per rendering, so this stays the word-form axis and leaves the
  // closed/hyphen/spaced axis entirely to [I]. A missing corpus already fails [I].
  const byStem = new Map();
  for (const [freq, sep] of [[freqClosed, ''], [freqSpace, ' '], [freqHyphen, '-']]) {
    for (const [term, n] of freq) {
      if (n < MIN_EVIDENCE) continue;
      const parts = sep ? term.split(sep) : [term];
      const head = parts[parts.length - 1];
      if (head.length < 4) continue;
      const key = `${sep}|${parts.slice(0, -1).join(sep)}|${stemOf(head)}`;
      if (!byStem.has(key)) byStem.set(key, []);
      byStem.get(key).push([term, n]);
    }
  }
  for (const members of byStem.values()) {
    if (members.length < 2) continue;
    families++;
    for (const [term, n] of members) {
      formsHashed++;
      const id = allWanted.get(sha(term));
      if (!id) continue;
      for (const [rival, m] of members) {
        if (rival !== term && m >= n) noteRival(id, term, rival, 'our own chapters write');
      }
    }
  }
  // A stemmer that stopped grouping would leave every family a singleton and
  // report a clean chapters half forever, so the grouping has to prove it ran.
  if (families < 500) {
    jBad.push(`only ${families} stem families formed from ${freqClosed.size} chapter words — the corpus or the stemmer stopped grouping, so the chapters half checked nothing`);
  }
  for (const ch of CHALLENGES) {
    if (!allWanted.has(ch.hash)) continue;
    const text = [ch.title.ko, ch.title.en, ch.prompt.ko, ch.prompt.en,
      ...(ch.hints.ko || []), ...(ch.hints.en || []), ch.fmt].filter(Boolean).join('\n').toLowerCase();
    for (const t of new Set([...text.matchAll(/[a-z]{4,}/g)].map(m => m[0]))) {
      if (sha(t) === ch.hash) continue; // the answer itself is leakscan's finding, not ours
      for (const sib of siblingsOf(t)) {
        formsHashed++;
        if (sha(sib) === ch.hash) noteRival(ch.id, sib, t, "the challenge's own text writes");
      }
    }
  }
}

// Recovering a form also recovers its length, which reaches past the four-character
// sweep [G] is bounded by — so the lengths [G] had to leave unchecked get checked here.
for (const [id, p] of formPlain) {
  if (shape.has(id)) continue;
  const d = declarationOf(CHALLENGES.find(c => c.id === id));
  if (d.len !== null && d.len !== p.length) {
    jBad.push(`${id} — fmt declares ${d.len} chars but the graded answer is ${p.length} (too long for [G]'s sweep)`);
  }
}

console.log(`\n--- [J] answers graded in one word-form while another is in front of the player: ${jBad.length} ---`);
console.log(`    (${families} stem families in the chapters and ${CHALLENGES.length} challenge texts, ${formsHashed} forms hashed; ${formPlain.size} answers recovered by form, ${formSeen.size} with a rival form, ${DERIVABLE.size} derivable challenges exempt)`);
for (const n of jBad) console.log(`  ⚠ ${n}`);

if (STRICT) {
  const fail = [];
  if (fBlocked) fail.push(`[F] ${fBlocked}`);
  for (const s of spelled.sort((a, b) => a.tier - b.tier)) {
    fail.push(`[F] ${s.id} — the ${s.node} topic row spells out its answer${REVEAL ? ` ("${s.term}")` : ''}`);
  }
  for (const b of bad) fail.push(`[G] ${b}`);
  for (const h of hBad) fail.push(`[H] ${h}`);
  for (const i of iBad) fail.push(`[I] ${i}`);
  for (const j of jBad) fail.push(`[J] ${j}`);
  if (fail.length) {
    console.error(`\naudit --strict: FAIL — ${fail.length} issue(s):`);
    for (const f of fail) console.error(`  ✗ ${f}`);
    process.exitCode = 1;
  } else {
    console.log(`\naudit --strict: OK — README's topic rows name no answers ([F]), no fmt/answer contradictions ([G]), fmt on-notation with every spelling hazard disclosed ([H]), no answer graded against the chapters' own spelling ([I]) or against a word-form the player is looking at ([J]).`);
  }
}
