#!/usr/bin/env node
/* Derivable-answer solver.

   Proves that every challenge which actually gives the player something to
   work from — a ciphertext in its prompt, a flag planted in the page — can be
   solved from exactly that material, and that the grader then accepts the
   result.

   Nothing else in the tree checks this. verify.js checks structure,
   leakscan.js checks that one challenge's answer does not sit in another
   challenge's text, and audit.js [G] only reaches the challenges that declare
   a length or a marker in `fmt`. The failure mode all three miss is the one
   where the prompt promises one thing and the stored hash is another (t4_mft's
   "$" prefix, t2_sha1's hyphen): the player follows the instructions exactly
   and is told they are wrong. That class of bug has only ever been caught by
   playing all of them by hand.

   The rule that keeps this honest: a solver may read its own challenge's
   prompt and hints and the deployed page, and may run transforms over them.
   It may never contain the answer. Recipes ("base64, then rot13") are fine;
   parameters — keys, shifts, targets — are parsed back out of the prompt. A
   solver may return a few candidates when the wording genuinely admits more
   than one reading, but never more than MAX_CANDIDATES, so "derivation" can
   never quietly degrade into searching for the answer.

   Derived plaintext is never printed, which keeps the output safe for public
   CI logs. Pass --reveal locally when a failure needs debugging.

   Knowledge questions ("which HTTP method ...") have nothing to derive from
   and are out of scope. But every exact-match (ci:false) challenge must be
   either covered here or listed in DECLINED with a reason, so a new one
   cannot slip in unchecked. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const WG = path.join(ROOT, 'wargame');
const REVEAL = process.argv.includes('--reveal');

/* A derivation that needs more tries than this is not a derivation any more.
   Small on purpose: the few multi-candidate solvers below exist because the
   prompt is honestly ambiguous (does the blank want the operator or the whole
   expression?), not because the answer is being searched for. */
const MAX_CANDIDATES = 8;

function loadChallenges() {
  const src = fs.readFileSync(path.join(WG, 'assets/challenges.js'), 'utf8');
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(src + '\nthis.CHALLENGES=CHALLENGES;', sandbox);
  return sandbox.CHALLENGES;
}

const INDEX_HTML = fs.readFileSync(path.join(WG, 'index.html'), 'utf8');
const APP_JS = fs.readFileSync(path.join(WG, 'assets/app.js'), 'utf8');

/* ===== reading the challenge's own text ===== */

// Ciphertexts are always inside a `code span`. Longest wins by default, since
// the ciphertext is normally the longest; pass `re` where a prompt carries a
// second, longer span (t2_reverse spells out its transform in code).
function span(ch, re) {
  const found = (ch.prompt.en.match(/`[^`]+`/g) || []).map((s) => s.slice(1, -1));
  const cands = re ? found.filter((s) => re.test(s)) : found;
  if (!cands.length) throw new Error('no matching code span in the prompt');
  return cands.reduce((a, b) => (b.length > a.length ? b : a));
}

// Keys, shifts and targets are stated in the prose — parse them back out
// rather than writing them down here.
function param(ch, re) {
  const hay = [ch.prompt.en, ...ch.hints.en].join('\n');
  const m = hay.match(re);
  if (!m) throw new Error(`prompt does not state the parameter ${re}`);
  return m[1];
}

const B64ISH = /^[A-Za-z0-9+/]+={0,2}$/;

/* ===== primitives ===== */

const b64 = (s) => Buffer.from(s, 'base64').toString('utf8');
const b64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
const unhex = (h) => Buffer.from(h.replace(/\s+/g, ''), 'hex');
const hexText = (h) => unhex(h).toString('utf8');
const reverse = (s) => s.split('').reverse().join('');

const caesar = (s, n) =>
  s.replace(/[a-z]/gi, (c) => {
    const base = c === c.toUpperCase() ? 65 : 97;
    return String.fromCharCode(base + (((c.charCodeAt(0) - base - n) % 26) + 26) % 26);
  });

const rot47 = (s) =>
  s.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));

const atbash = (s) =>
  s.replace(/[a-z]/gi, (c) => {
    const base = c === c.toUpperCase() ? 65 : 97;
    return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base));
  });

const xorText = (hex, key) => {
  const bytes = unhex(hex);
  const k = Buffer.from(key, 'utf8');
  return Buffer.from(bytes.map((b, i) => b ^ k[i % k.length])).toString('utf8');
};

// Whether the key advances on non-letters is a real convention split, so both
// readings are offered as candidates.
function vigenere(ct, key, advanceOnAll) {
  const k = key.toLowerCase();
  let j = 0;
  let out = '';
  for (const c of ct) {
    const letter = /[a-z]/i.test(c);
    if (letter) {
      const base = c === c.toUpperCase() ? 65 : 97;
      const off = k.charCodeAt(j % k.length) - 97;
      out += String.fromCharCode(base + (((c.charCodeAt(0) - base - off) % 26) + 26) % 26);
    } else {
      out += c;
    }
    if (letter || advanceOnAll) j++;
  }
  return out;
}

const B32A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function fromBase32(s) {
  let bits = 0;
  let val = 0;
  const out = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = B32A.indexOf(c);
    if (i < 0) throw new Error('not a Base32 alphabet');
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out).toString('utf8');
}

const B58A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function fromBase58(s) {
  let num = 0n;
  for (const c of s) {
    const i = B58A.indexOf(c);
    if (i < 0) throw new Error('not a Base58 alphabet');
    num = num * 58n + BigInt(i);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let lead = 0;
  while (s[lead] === '1') lead++;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(hex, 'hex')]).toString('utf8');
}

// ASCII85 / Adobe variant, alphabet '!'..'u', no <~ ~> delimiters.
function fromBase85(s) {
  const out = [];
  let group = [];
  const flush = (n) => {
    const g = group.concat(Array(5 - n).fill(84));
    let v = 0;
    for (const d of g) v = v * 85 + d;
    const bytes = [
      Math.floor(v / 16777216) % 256,
      Math.floor(v / 65536) % 256,
      Math.floor(v / 256) % 256,
      v % 256,
    ];
    out.push(...bytes.slice(0, n - 1 || 4));
    group = [];
  };
  for (const c of s.replace(/\s+/g, '')) {
    if (c === 'z' && group.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    const d = c.charCodeAt(0) - 33;
    if (d < 0 || d > 84) throw new Error('not a Base85 alphabet');
    group.push(d);
    if (group.length === 5) flush(5);
  }
  if (group.length) flush(group.length);
  return Buffer.from(out).toString('utf8');
}

const MORSE = {
  '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e', '..-.': 'f',
  '--.': 'g', '....': 'h', '..': 'i', '.---': 'j', '-.-': 'k', '.-..': 'l',
  '--': 'm', '-.': 'n', '---': 'o', '.--.': 'p', '--.-': 'q', '.-.': 'r',
  '...': 's', '-': 't', '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x',
  '-.--': 'y', '--..': 'z',
};

/* ===== the covered set =====
   `via` is a label for the report only. `solve` returns the plaintext a
   player would arrive at, or an array when the wording admits a few readings.
   Nothing in here may name an answer. */

const SOLVERS = new Map([
  /* --- in-page artifacts: also proves the plant is still wired up --- */
  ['t0_source', { kind: 'artifact', via: 'HTML comment', solve: () => {
    const inComments = (INDEX_HTML.match(/<!--[\s\S]*?-->/g) || []).join('\n');
    return (inComments.match(/FLAG\{[^}]*\}/g) || []);
  } }],
  ['t0_meta', { kind: 'artifact', via: '<meta name="ctf-flag">', solve: (ch) => {
    const name = param(ch, /`name` is `([\w-]+)`/);
    const m = INDEX_HTML.match(new RegExp(`<meta name="${name}" content="([^"]*)"`));
    if (!m) throw new Error('the meta tag the prompt names is not in index.html');
    return m[1];
  } }],
  ['t0_title', { kind: 'artifact', via: '<title>', solve: () => {
    const m = INDEX_HTML.match(/<title>([^<]*)<\/title>/);
    if (!m) throw new Error('index.html has no <title>');
    return m[1];
  } }],
  ['t0_devtools', { kind: 'artifact', via: 'window global', solve: (ch) => {
    const global = param(ch, /`window\.(\w+)`/);
    const m = APP_JS.match(new RegExp(`window\\.${global}\\s*=\\s*"([^"]*)"`));
    if (!m) throw new Error('app.js no longer sets the global the prompt names');
    return m[1];
  } }],
  ['t1_cookie', { kind: 'artifact', via: 'document.cookie', solve: (ch) => {
    const name = param(ch, /cookie named `(\w+)`/);
    const m = APP_JS.match(new RegExp(`${name}=([^;"]*)`));
    if (!m) throw new Error('app.js no longer bakes the cookie the hint names');
    return m[1];
  } }],
  ['t1_css', { kind: 'artifact', via: 'hidden DOM node', solve: (ch) => {
    const id = param(ch, /id=`(\w+)`/);
    const m = INDEX_HTML.match(new RegExp(`id="${id}"[^>]*>([^<]*)<`));
    if (!m) throw new Error('index.html no longer carries the hidden element');
    return m[1];
  } }],

  /* --- straight decodes --- */
  ['t0_base64', { kind: 'decode', via: 'base64', solve: (ch) => b64(span(ch)) }],
  ['t0_reverse', { kind: 'decode', via: 'reverse', solve: (ch) => reverse(span(ch)) }],
  ['t0_urlenc', { kind: 'decode', via: 'percent-encoding', solve: (ch) => decodeURIComponent(span(ch)) }],
  ['t0_octal', { kind: 'decode', via: 'octal ASCII', solve: (ch) =>
    span(ch).trim().split(/\s+/).map((n) => String.fromCharCode(parseInt(n, 8))).join('') }],
  ['t0_decimal', { kind: 'decode', via: 'decimal ASCII', solve: (ch) =>
    span(ch).trim().split(/\s+/).map((n) => String.fromCharCode(parseInt(n, 10))).join('') }],
  ['t0_binary', { kind: 'decode', via: 'binary ASCII', solve: (ch) =>
    span(ch).trim().split(/\s+/).map((n) => String.fromCharCode(parseInt(n, 2))).join('') }],
  ['t0_nato', { kind: 'decode', via: 'initials', solve: (ch) =>
    span(ch).trim().split(/\s+/).map((w) => w[0]).join('') }],
  ['t1_hex', { kind: 'decode', via: 'hex', solve: (ch) => hexText(span(ch)) }],
  ['t1_rot13', { kind: 'decode', via: 'letter shift', solve: (ch) =>
    caesar(span(ch), Number(param(ch, /shifted by (\d+)/))) }],
  ['t1_caesar', { kind: 'decode', via: 'letter shift', solve: (ch) =>
    caesar(span(ch), Number(param(ch, /shifted by (\d+)/))) }],
  ['t1_atbash', { kind: 'decode', via: 'atbash', solve: (ch) => atbash(span(ch)) }],
  ['t1_a1z26', { kind: 'decode', via: 'a1z26', solve: (ch) =>
    span(ch).trim().split('-').map((n) => String.fromCharCode(96 + Number(n))).join('') }],
  ['t1_morse', { kind: 'decode', via: 'morse', solve: (ch) =>
    span(ch).trim().split(/\s+/).map((c) => {
      if (!MORSE[c]) throw new Error('unknown morse symbol');
      return MORSE[c];
    }).join('') }],
  ['t1_chmod', { kind: 'decode', via: 'rwx to octal', solve: (ch) =>
    span(ch).match(/.{3}/g).map((t) =>
      (t[0] === 'r' ? 4 : 0) + (t[1] === 'w' ? 2 : 0) + (t[2] === 'x' ? 1 : 0)).join('') }],
  ['t1_creds', { kind: 'decode', via: 'base64', solve: (ch) =>
    b64(param(ch, /Basic ([A-Za-z0-9+/=]+)/)) }],
  ['t2_b32', { kind: 'decode', via: 'base32', solve: (ch) => fromBase32(span(ch)) }],
  ['t2_base58', { kind: 'decode', via: 'base58', solve: (ch) => fromBase58(span(ch)) }],
  ['t2_unicode', { kind: 'decode', via: 'unicode escapes', solve: (ch) =>
    span(ch).replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))) }],
  ['t2_reverse', { kind: 'decode', via: 'base64 then reverse', solve: (ch) =>
    reverse(b64(span(ch, B64ISH))) }],
  ['t2_vigenere', { kind: 'decode', via: 'vigenere', solve: (ch) => {
    const key = param(ch, /key `([A-Za-z]+)`/);
    const ct = span(ch, /[{}]/);
    return [vigenere(ct, key, false), vigenere(ct, key, true)];
  } }],
  ['t3_xor', { kind: 'decode', via: 'single-byte xor', solve: (ch) =>
    xorText(span(ch, /^[0-9a-f\s]+$/i), String.fromCharCode(parseInt(param(ch, /key `0x([0-9a-f]{2})`/i), 16))) }],
  ['t3_xormulti', { kind: 'decode', via: 'repeating-key xor', solve: (ch) =>
    xorText(span(ch, /^[0-9a-f\s]+$/i), param(ch, /repeating key `([^`]+)`/)) }],
  ['t3_rot47', { kind: 'decode', via: 'rot47', solve: (ch) => rot47(span(ch)) }],
  ['t3_base85', { kind: 'decode', via: 'base85', solve: (ch) => fromBase85(span(ch)) }],
  ['t3_jwtdecode', { kind: 'decode', via: 'base64url JWT payload', solve: (ch) =>
    JSON.parse(b64url(span(ch).split('.').pop())).flag }],
  ['t3_jwtnone', { kind: 'decode', via: 'base64url JWT payload', solve: (ch) =>
    JSON.parse(b64url(span(ch).split('.')[1])).flag }],
  ['t3_sig', { kind: 'decode', via: 'magic bytes to ASCII', solve: (ch) =>
    (unhex(span(ch)).toString('latin1').match(/[A-Za-z]{2,}/g) || []).sort((a, b) => b.length - a.length)[0] }],
  ['t4_chain', { kind: 'decode', via: 'base64 then rot13', solve: (ch) => caesar(b64(span(ch)), 13) }],
  ['t4_webchain', { kind: 'decode', via: 'base64 twice', solve: (ch) => b64(b64(span(ch))) }],
  ['t4_doubleb64', { kind: 'decode', via: 'base64 twice', solve: (ch) => b64(b64(span(ch))) }],
  ['t4_megachain', { kind: 'decode', via: 'base64 then hex', solve: (ch) => hexText(b64(span(ch))) }],
  ['t4_triple', { kind: 'decode', via: 'rot13, base64, hex', solve: (ch) => hexText(b64(caesar(span(ch), 13))) }],
  ['t4_capstone', { kind: 'decode', via: 'single-byte xor', solve: (ch) =>
    xorText(span(ch, /^[0-9a-f\s]+$/i), String.fromCharCode(parseInt(param(ch, /key `0x([0-9a-f]{2})`/i), 16))) }],
  ['t4_vigenere', { kind: 'decode', via: 'vigenere', solve: (ch) => {
    const key = param(ch, /key `([A-Za-z]+)`/);
    const ct = span(ch, /[{}]/);
    return [vigenere(ct, key, false), vigenere(ct, key, true)];
  } }],
  ['t4_xorcore', { kind: 'decode', via: 'repeating-key xor', solve: (ch) =>
    xorText(span(ch, /^[0-9a-f\s]+$/i), param(ch, /repeating key `([^`]+)`/)) }],
  ['t4_k8ssecret', { kind: 'decode', via: 'base64', solve: (ch) => b64(span(ch)) }],
  ['t4_volatility', { kind: 'decode', via: 'base64', solve: (ch) => b64(span(ch)) }],

  /* --- exact-match challenges whose answer is computed, not recalled --- */
  ['t2_lfi', { kind: 'computed', via: 'path normalisation', solve: (ch) => {
    // "the N-character sequence that moves up one directory level": build every
    // string of that length over the characters a path can use for it, and keep
    // the ones a real path normaliser resolves upwards.
    const n = Number(param(ch, /what (\w+)-character sequence/).replace('three', '3'));
    const out = [];
    const walk = (s) => {
      if (s.length === n) {
        if (path.posix.normalize('/x/y/' + s).replace(/\/$/, '') === '/x') out.push(s);
        return;
      }
      for (const c of ['.', '/']) walk(s + c);
    };
    walk('');
    return out;
  } }],
  ['t3_ssti', { kind: 'computed', via: 'arithmetic', solve: (ch) => {
    // The prompt gives the number that must render and the hint gives the
    // template shape; find the operator that connects them.
    const target = Number(param(ch, /if (\d+) is rendered/));
    const [, operand] = param(ch, /`\{\{((\d+)__\2)\}\}`/).match(/^(\d+)/);
    const x = Number(operand);
    const ops = { '+': x + x, '-': x - x, '*': x * x, '/': x / x, '%': x % x, '**': x ** x };
    return Object.keys(ops)
      .filter((op) => ops[op] === target)
      .flatMap((op) => [`${operand}${op}${operand}`, op]);
  } }],
  ['t3_imds', { kind: 'computed', via: 'address from stated range', solve: (ch) => {
    // The hints pin both halves: the link-local range it lives in and the
    // octets it ends with. Together they name exactly one address.
    const range = param(ch, /(\d+\.\d+)\.x\.x/);
    const tail = param(ch, /Ends with \.([\d.]+?)\.?$/m);
    return `${range}.${tail}`;
  } }],

  /* --- physical: badge frames and an access log, parsed from the prompt --- */
  ['t2_wiegandfc', { kind: 'computed', via: 'facility code from a 26-bit frame', solve: (ch) => {
    const bits = span(ch, /^[01]{20,}$/);
    return String(parseInt(bits.slice(1, 9), 2));
  } }],
  ['t3_wiegandcn', { kind: 'computed', via: 'card number from a 26-bit frame', solve: (ch) => {
    const bits = span(ch, /^[01]{20,}$/);
    return String(parseInt(bits.slice(9, 25), 2));
  } }],
  ['t4_wiegandflag', { kind: 'computed', via: 'full 26-bit frame parse', solve: (ch) => {
    const bits = span(ch, /^[01]{20,}$/);
    const fc = parseInt(bits.slice(1, 9), 2);
    const cn = parseInt(bits.slice(9, 25), 2);
    return `FLAG{FC${fc}_CN${cn}}`;
  } }],
  ['t2_bcc', { kind: 'computed', via: 'xor check byte over a UID', solve: (ch) => {
    const uid = span(ch, /^[0-9a-fA-F]{8}$/);
    let x = 0;
    for (let i = 0; i < 8; i += 2) x ^= parseInt(uid.slice(i, i + 2), 16);
    return x.toString(16).padStart(2, '0');
  } }],
  ['t4_emdec', { kind: 'computed', via: 'lower 32 bits of a tag id', solve: (ch) => {
    const id = span(ch, /^[0-9a-fA-F]{10}$/);
    return String(parseInt(id.slice(-8), 16));
  } }],
  ['t4_tailgatelog', { kind: 'computed', via: 'smallest follow-through gap', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced access log in the prompt');
    const rows = m[1].trim().split('\n').map((l) => l.split(',').map((s) => s.trim()));
    let best = null;
    for (let i = 1; i < rows.length; i++) {
      const [, badge, door, action, gap] = rows[i];
      const prev = rows[i - 1];
      if (action === 'ACCESS_NO_BADGE' && prev[3] === 'ACCESS_GRANTED' && prev[2] === door) {
        const g = Number(gap);
        if (g > 0 && g <= 3000 && (!best || g < best.g)) best = { id: badge, g };
      }
    }
    if (!best) throw new Error('no tailgate row matched the rule');
    return `FLAG{TAILGATE_${best.id}}`;
  } }],

  /* --- automotive: CAN captures, a checksum and a seed-key computation --- */
  ['t2_canlog', { kind: 'computed', via: 'ascii payload carried on one CAN id', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced capture in the prompt');
    const target = (ch.prompt.en.match(/`0x([0-9A-Fa-f]+)`/) || [])[1];
    if (!target) throw new Error('prompt does not name the target identifier');
    let hex = '';
    for (const line of m[1].trim().split('\n')) {
      const f = line.match(/\)\s+\S+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)/);
      if (f && f[1].toUpperCase() === target.toUpperCase()) hex += f[2];
    }
    const ascii = Buffer.from(hex, 'hex').toString('latin1');
    const g = ascii.match(/FLAG\{[^}]+\}/);
    return g ? g[0] : ascii;
  } }],
  ['t2_cansum', { kind: 'computed', via: 'xor over a stated can payload', solve: (ch) => {
    const span = (ch.prompt.en.match(/`([0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2}){6})`/) || [])[1];
    if (!span) throw new Error('no seven-byte payload span in the prompt');
    let x = 0;
    for (const b of span.split(/\s+/)) x ^= parseInt(b, 16);
    return `FLAG{CKSUM_${x.toString(16).toUpperCase().padStart(2, '0')}}`;
  } }],
  ['t3_seedkey', { kind: 'computed', via: 'xor key from a stated challenge and constant', solve: (ch) => {
    const chal = (ch.prompt.en.match(/challenge `0x([0-9A-Fa-f]{8})`/) || [])[1];
    const konst = (ch.prompt.en.match(/XOR 0x([0-9A-Fa-f]{8})/) || [])[1];
    if (!chal || !konst) throw new Error('challenge value or constant not stated');
    const k = ((parseInt(chal, 16) ^ parseInt(konst, 16)) >>> 0).toString(16).toUpperCase().padStart(8, '0');
    return `FLAG{KEY_${k}}`;
  } }],
  ['t4_cancapstone', { kind: 'computed', via: 'speed and rpm read from OBD reply frames', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced frames in the prompt');
    const frames = [...m[1].matchAll(/#([0-9A-Fa-f]+)/g)].map((x) => x[1].toUpperCase());
    let speed = null, rpm = null;
    for (const f of frames) {
      const a = f.indexOf('410D');
      if (a >= 0) speed = parseInt(f.slice(a + 4, a + 6), 16);
      const b = f.indexOf('410C');
      if (b >= 0) rpm = (parseInt(f.slice(b + 4, b + 6), 16) * 256 + parseInt(f.slice(b + 6, b + 8), 16)) / 4;
    }
    if (speed === null || rpm === null) throw new Error('missing the 0x0D or 0x0C reply');
    return `FLAG{SPEED${speed}_RPM${rpm}}`;
  } }],

  /* --- zero trust: a weighted risk score, a maturity percent, a policy
     evaluation and a device-posture total, each read from a fenced block --- */
  ['t2_ztrisk', { kind: 'computed', via: 'weighted sum of four risk sub-scores', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced risk profile in the prompt');
    const b = m[1];
    const g = (re) => { const x = b.match(re); if (!x) throw new Error(`missing ${re}`); return Number(x[1]); };
    const total = Math.trunc(
      g(/user_score:\s*(\d+)/) * g(/user (0\.\d+)/) +
      g(/device_score:\s*(\d+)/) * g(/device (0\.\d+)/) +
      g(/network_score:\s*(\d+)/) * g(/network (0\.\d+)/) +
      g(/behavioral_score:\s*(\d+)/) * g(/behavioral (0\.\d+)/));
    return `FLAG{RISK_${total}}`;
  } }],
  ['t2_ztmm', { kind: 'computed', via: 'CISA ZTMM overall percent from five pillar levels', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced maturity table in the prompt');
    const lv = [...m[1].matchAll(/(?:Identity|Devices|Networks|Applications|Data):\s*([1-4])/g)].map((x) => Number(x[1]));
    if (lv.length !== 5) throw new Error(`expected five pillar levels, got ${lv.length}`);
    return `FLAG{ZTMM_${Math.round(lv.reduce((a, c) => a + c, 0) / 20 * 100)}}`;
  } }],
  ['t3_ztseg', { kind: 'computed', via: 'count flows permitted by a priority-ordered segmentation policy', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced policy in the prompt');
    const body = m[1];
    const segs = [...body.matchAll(/^\s*([a-z]+)\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\s*$/gm)]
      .map((x) => ({ name: x[1], base: x[2], len: Number(x[3]) }));
    const rules = [...body.matchAll(/^\s*(\d+)\s+([a-z*]+)\s*->\s*([a-z*]+)\s+(\S+)\s+(ALLOW|DENY)\s*$/gm)]
      .map((x) => ({ prio: Number(x[1]), src: x[2], dst: x[3], pp: x[4], act: x[5] }))
      .sort((a, c) => a.prio - c.prio);
    const flows = [...body.matchAll(/^\s*([A-Z])\s+(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)\s+(\w+)\/(\d+)\s*$/gm)]
      .map((x) => ({ s: x[2], d: x[3], proto: x[4], port: Number(x[5]) }));
    const ipn = (ip) => ip.split('.').reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0;
    const segOf = (ip) => {
      const v = ipn(ip);
      const hit = segs.find((s) => { const mask = s.len === 0 ? 0 : (~0 << (32 - s.len)) >>> 0; return (v & mask) === (ipn(s.base) & mask); });
      return hit ? hit.name : null;
    };
    const decide = (f) => {
      const ss = segOf(f.s), ds = segOf(f.d);
      if (!ss || !ds) return 'DENY';
      for (const r of rules) {
        if (r.src !== '*' && r.src !== ss) continue;
        if (r.dst !== '*' && r.dst !== ds) continue;
        if (r.pp !== 'any') {
          const [pr, po] = r.pp.split('/');
          if (pr.toLowerCase() !== f.proto.toLowerCase() || Number(po) !== f.port) continue;
        }
        return r.act;
      }
      return 'DENY';
    };
    return `FLAG{ALLOWED_${flows.filter((f) => decide(f) === 'ALLOW').length}}`;
  } }],
  ['t4_ztcapstone', { kind: 'computed', via: 'device posture score from the stated weighting', solve: (ch) => {
    const m = ch.prompt.en.match(/```([\s\S]+?)```/);
    if (!m) throw new Error('no fenced device profile in the prompt');
    const b = m[1];
    const yes = (re) => /yes/i.test((b.match(re) || [])[1] || '');
    const num = (re) => Number((b.match(re) || [])[1] || 0);
    let s = 0;
    s += (yes(/tpm_2_0:\s*(\w+)/) ? 10 : 0) + (yes(/measured_boot:\s*(\w+)/) ? 8 : 0) + (yes(/disk_encryption:\s*(\w+)/) ? 7 : 0);
    s += (yes(/patched_30d:\s*(\w+)/) ? 15 : 0) + (yes(/firewall:\s*(\w+)/) ? 8 : 0) + (yes(/current_av:\s*(\w+)/) ? 7 : 0);
    s += (yes(/endpoint_agent:\s*(\w+)/) ? 15 : 0) + (yes(/mdm_enrolled:\s*(\w+)/) ? 10 : 0);
    s += -10 * num(/recent_anomalies:\s*(\d+)/) + (yes(/off_hours:\s*(\w+)/) ? -5 : 0);
    return `FLAG{POSTURE_${s}}`;
  } }],
]);

/* Exact-match challenges deliberately left uncovered. Anything ci:false that
   is neither solved above nor listed here fails the run, so a new flag
   challenge cannot arrive without someone deciding which bucket it is in. */
const DECLINED = new Map([]);

/* ===== run ===== */

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const grade = (ch, s) => sha(ch.ci ? String(s).trim().toLowerCase() : String(s).trim());

const challenges = loadChallenges();
const byId = new Map(challenges.map((ch) => [ch.id, ch]));
const errors = [];
const solved = [];

for (const [id, solver] of SOLVERS) {
  const ch = byId.get(id);
  if (!ch) {
    errors.push(`${id}: a solver exists for a challenge that is no longer in challenges.js`);
    continue;
  }
  let cands;
  try {
    const got = solver.solve(ch);
    cands = (Array.isArray(got) ? got : [got]).filter((c) => c !== undefined && c !== null && c !== '');
  } catch (e) {
    errors.push(`${id}: could not derive an answer from the prompt (${e.message})`);
    continue;
  }
  if (!cands.length) {
    errors.push(`${id}: the prompt yielded nothing to submit`);
    continue;
  }
  if (cands.length > MAX_CANDIDATES) {
    errors.push(`${id}: ${cands.length} candidates — that is a search, not a derivation`);
    continue;
  }
  const hit = cands.find((c) => grade(ch, c) === ch.hash);
  if (!hit) {
    errors.push(
      `${id}: derived ${cands.length} candidate(s) from the prompt, the grader rejects all of them` +
        (REVEAL ? ` — got ${JSON.stringify(cands)}` : '')
    );
    continue;
  }
  solved.push({ id, kind: solver.kind, via: solver.via, tries: cands.length });
}

// Every exact-match challenge has material to work from by construction, so
// silence about one means nobody is checking it.
const uncovered = challenges.filter((ch) => !ch.ci && !SOLVERS.has(ch.id) && !DECLINED.has(ch.id));
for (const ch of uncovered) {
  errors.push(`${ch.id}: exact-match challenge with no solver — add one, or add it to DECLINED with a reason`);
}

// A DECLINED entry that no longer applies is either dead or quietly hiding a
// challenge that is now solvable.
for (const [id, why] of DECLINED) {
  const ch = byId.get(id);
  if (!ch) errors.push(`${id}: DECLINED entry for a challenge that no longer exists`);
  else if (ch.ci) errors.push(`${id}: DECLINED entry is stale — the challenge is no longer exact-match`);
  else if (SOLVERS.has(id)) errors.push(`${id}: DECLINED entry is stale — a solver already covers this challenge`);
  else console.log(`  (declined) ${id} — ${why}`);
}

for (const s of solved.sort((a, b) => a.id.localeCompare(b.id))) {
  console.log(`  ok  ${s.id.padEnd(16)} ${s.kind.padEnd(9)} ${s.via}${s.tries > 1 ? `  (${s.tries} readings tried)` : ''}`);
}

if (errors.length) {
  console.error(`\nwargame solve-derivable: ${errors.length} problem(s):\n`);
  for (const e of errors) console.error(' - ' + e);
  if (!REVEAL) console.error('\nRun locally with --reveal to see what was derived (never in CI logs).');
  process.exit(1);
}

const by = (k) => solved.filter((s) => s.kind === k).length;
console.log(
  `\nwargame solve-derivable: OK — ${solved.length}/${challenges.length} challenges solved from their own text ` +
    `(${by('decode')} decode, ${by('artifact')} planted artifact, ${by('computed')} computed), ` +
    `graded by the app's own rule. The remaining ${challenges.length - solved.length} are knowledge questions ` +
    'with nothing to derive.'
);
