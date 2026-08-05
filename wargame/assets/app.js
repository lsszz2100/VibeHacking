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
  // pool was 75 but only a third of 210. These are the 75-era ratios
  // (15/32/52/70 of 75) rounded. Egg/Newbie stay absolute: "have you started
  // at all" is not a share of anything.
  const RANKS = [
    { min:0,   icon:"🥚", ko:"알",     en:"Egg" },
    { min:1,   icon:"🐣", ko:"뉴비",   en:"Newbie" },
    { at:0.20, icon:"🦊", ko:"수습",   en:"Apprentice" },
    { at:0.43, icon:"🐺", ko:"해커",   en:"Hacker" },
    { at:0.69, icon:"🦅", ko:"엘리트", en:"Elite" },
    { at:0.93, icon:"👑", ko:"레전드", en:"Legend" }
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
      hintLabel:"힌트", lockLabel:"잠금장치", format:"형식"
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
      hintLabel:"hint", lockLabel:"lock", format:"format"
    }
  };

  /* ===== state ===== */
  const LS = "vibe_wargame_v1";  // keep key so prior solvers retain progress
  let state = { solved:{}, hints:{}, lang:"ko", sound:true };
  try { const s = JSON.parse(localStorage.getItem(LS)); if (s) state = Object.assign(state, s); } catch (e) {}
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
  // T3 7/12) ... for 50") and never moved through six expansions, so by 245 they
  // gated a layer on roughly an eighth of it. These are those same 50-era ratios,
  // written as the fractions the commit message spelled them with; the count is
  // re-derived from whatever the pool holds now, so expansions carry it along.
  const TIER_NEED_AT = { 0: 4/6, 1: 6/10, 2: 9/15, 3: 7/12, 4: 5/7 };
  const tierNeed = tid => {
    const pool = tierChals(tid).length;
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
      ["ls","현재 위치 목록 (계층 또는 잠금장치) / list here"],
      ["map","침투 경로 지도 / infiltration map"],
      ["connect <노드>","계층에 접속 / connect to a layer  (cd <node>)"],
      ["back","상위로 / go up  (cd ..)"],
      ["cat <번호>","잠금장치(문제) 열기 / open a lock  (open <n>)"],
      ["hint","현재 표적 힌트 공개 / reveal a hint"],
      ["submit <flag>","플래그 제출 / submit a flag  (또는 그냥 입력)"],
      ["status","점수·등급·진행 / score & progress  (whoami)"],
      ["lang","한/영 전환 / toggle language"],
      ["sound","사운드 토글 / toggle sound"],
      ["clear","화면 지우기 / clear screen"],
      ["reset","진행도 초기화 / reset progress"]
    ];
    blank();
    print('<span class="bold">' + (L()==="ko"?"사용 가능한 명령":"AVAILABLE COMMANDS") + '</span>');
    rows.forEach(r => print('<span class="tbl"><span class="cmd-h">' + r[0].padEnd(16," ").replace(/ /g,"&nbsp;") +
      '</span> <span class="dim">' + esc(r[1]) + '</span></span>'));
    blank();
    print('<span class="dim">' + esc(S("welcome")) + '</span>');
  }

  function showNodes(){
    blank();
    print('<span class="bold">' + esc(S("nodesHdr")) + '</span>');
    LAYERS.forEach(lay => {
      const tier = TIERS.find(t => t.id === lay.tier);
      const unlocked = isTierUnlocked(lay.tier);
      const sc = tierSolved(lay.tier), tc = tierChals(lay.tier).length;
      const fullBreach = sc >= tierNeed(lay.tier);
      let statusHtml, cls;
      if (!unlocked){ statusHtml = '🔒 ' + esc(S("locked")); cls = "locked-row"; }
      else if (fullBreach){ statusHtml = '<span class="ok">✓ ' + esc(S("breached")) + '</span>'; cls = "solved-row"; }
      else { statusHtml = '<span class="warn">▸ ' + esc(S("open")) + '</span>'; cls = ""; }
      const name = lay[L()];
      print('<span class="tbl"><span class="row ' + cls + '">' +
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

  function showLocks(nodeId){
    const lay = layerById(nodeId);
    const tier = TIERS.find(t => t.id === lay.tier);
    const chals = locksOf(nodeId);
    blank();
    print('<span class="bold">' + esc(S("connected")) + ' [' + esc(nodeId) + '] ' + esc(lay[L()]) + '</span>');
    print('<span class="dim">' + esc(tier["desc_" + L()]) + '</span>');
    print('<span class="dim">' + esc(S("locksHdr")) + '</span>');
    chals.forEach((c, i) => {
      const solved = !!state.solved[c.id];
      const num = String(i + 1).padStart(2, "0");
      const mark = solved ? '<span class="ok">[✓]</span>' : '<span class="warn">[ ]</span>';
      const cls = solved ? "solved-row" : "";
      print('<span class="tbl"><span class="row ' + cls + '">' +
        mark + ' <span class="id">' + num + '</span>' +
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
    if (!cwd){ printText(S("connFirst"), "warn"); return; }
    const chals = locksOf(cwd);
    let ch = null;
    if (/^\d+$/.test(arg)){ ch = chals[parseInt(arg,10) - 1]; }
    if (!ch) ch = chals.find(c => c.id === arg);
    if (!ch){ printText(S("noLock") + " " + arg, "err"); sDeny(); return; }
    target = ch.id;
    const solved = !!state.solved[ch.id];
    const box = document.createElement("div");
    box.className = "cbox" + (solved ? " solved" : "");
    const idx = chals.indexOf(ch) + 1;
    box.innerHTML =
      '<div class="cbh">' +
        '<span class="tag">' + esc(S("lockLabel")) + ' ' + String(idx).padStart(2,"0") + '</span>' +
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
        if (cwd) showLocks(cwd); else showNodes(); break;
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
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowUp"){ if (hi > 0){ hi--; input.value = history[hi] || ""; } e.preventDefault(); }
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
    ch.addEventListener("click", () => { input.focus(); audio(); run(ch.dataset.cmd); });
  });
  // hud buttons
  document.getElementById("soundBtn").addEventListener("click", () => { audio(); toggleSound(); input.focus(); });
  document.getElementById("langBtn").addEventListener("click", () => { toggleLang(); input.focus(); });

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
