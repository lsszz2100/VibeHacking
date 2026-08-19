#!/usr/bin/env node
/* Post-deploy guard: what GitHub Pages is actually serving has to be what
   this commit holds. Structural-only, like the other guards here — it hashes
   bytes and never needs a plaintext answer.

   This exists because a red Deploy run has repeatedly not meant a failed
   deploy, and a green one has not always been checked. The action polls the
   Pages backend and gives up on its own clock; on 2026-07-02 it gave up
   after 600s of `deployment_queued` while the deploy landed anyway, and a
   mis-unit timeout later had it cancelling deployments 5s in — six runs, of
   which at least one (#49) had already finished and served the new bytes
   under a red check, while another (#56) really had been cancelled and left
   the old app.js live. Telling those apart meant reading the raw log for
   whether the cancel succeeded, and then fetching the files by hand. That
   question has one honest answer and a machine can fetch it.

   Fetched plainly, with no cache-buster and no no-cache header: the CDN copy
   a player would get is the thing under test, not the origin behind it.

   Usage: node wargame/scripts/live-check.js https://user.github.io/Repo/ */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const WG = path.resolve(__dirname, '..');
const base = (process.argv[2] || process.env.PAGES_URL || '').trim();

// The deploy uploads ./wargame whole, so every file in it is a served file
// and all of them are checked. Three of them decide whether the game a
// player loads is the game in this commit; if the walk ever stops finding
// those, the walk is broken and this check has stopped meaning anything.
const REQUIRED = ['index.html', 'assets/app.js', 'assets/challenges.js'];

// Budget shaped to what the backend actually does: deploys have reported
// success ~5s after creation for months, so this is slack for CDN
// propagation, not for the deploy itself. Overridable only so the mutation
// tests can plant a difference and see it reported without sitting through
// three minutes of retries; shortening it in CI would just make this check
// flaky, which is the disease it was written to cure.
const ATTEMPT_DELAYS_MS = (process.env.LIVE_CHECK_DELAYS_MS || '0,5000,10000,15000,20000,30000,40000,60000')
  .split(',').map((n) => Number(n.trim()));

function walk(dir, prefix = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...walk(path.join(dir, entry.name), rel));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}

const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  if (!base) {
    console.error('live-check: no Pages URL given (argv[2] or $PAGES_URL) — nothing was checked');
    process.exit(1);
  }
  const root = base.endsWith('/') ? base : base + '/';

  const files = walk(WG);
  const missing = REQUIRED.filter((f) => !files.includes(f));
  if (missing.length) {
    console.error(`live-check: ${missing.join(', ')} not found under ${WG} — the file walk is broken, so a pass here would mean nothing`);
    process.exit(1);
  }

  const local = new Map(files.map((f) => [f, fs.readFileSync(path.join(WG, f))]));
  let pending = [...files];
  const notes = new Map();

  for (let i = 0; i < ATTEMPT_DELAYS_MS.length && pending.length; i++) {
    if (ATTEMPT_DELAYS_MS[i]) {
      console.log(`  ${pending.length} file(s) not in sync yet; waiting ${ATTEMPT_DELAYS_MS[i] / 1000}s (attempt ${i + 1}/${ATTEMPT_DELAYS_MS.length})`);
      await sleep(ATTEMPT_DELAYS_MS[i]);
    }
    const still = [];
    for (const f of pending) {
      const url = root + f.split('/').map(encodeURIComponent).join('/');
      try {
        const res = await fetch(url, { redirect: 'follow' });
        if (!res.ok) {
          notes.set(f, `HTTP ${res.status}`);
          still.push(f);
          continue;
        }
        const body = Buffer.from(await res.arrayBuffer());
        const want = local.get(f);
        if (sha(body) === sha(want)) continue;
        notes.set(f, `served ${body.length}B sha ${sha(body).slice(0, 12)}, commit has ${want.length}B sha ${sha(want).slice(0, 12)}`);
        still.push(f);
      } catch (e) {
        notes.set(f, `fetch failed: ${e.message}`);
        still.push(f);
      }
    }
    pending = still;
  }

  if (pending.length) {
    console.error(`\nlive-check: FAIL — ${pending.length} of ${files.length} file(s) at ${root} are not the bytes in this commit:\n`);
    for (const f of pending) console.error(` - ${f}: ${notes.get(f)}`);
    console.error('\nThe deployment did not land (or landed partially). A re-run of the failed');
    console.error('deploy job will not fix it — that uploads a second artifact and fails on');
    console.error('that instead. Push again, or re-run the whole workflow.');
    process.exit(1);
  }

  console.log(`live-check: OK — all ${files.length} deployed file(s) at ${root} are byte-identical to this commit.`);
}

main().catch((e) => {
  console.error(`live-check: crashed — ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
