/* Vibe Hacking Wargame engine — client-side only. */
(function () {
  "use strict";

  /* ---------- planted in-page flags (challenges find these) ---------- */
  // cookie challenge (t1_cookie)
  document.cookie = "wg_flag=FLAG{cookie_monster_2026}; path=/; SameSite=Lax";
  // devtools console challenge (t0_devtools)
  window.__hint = "FLAG{devtools_console_hero}";
  try {
    console.log("%c[wargame] 콘솔까지 열어보다니, 될성부른 떡잎! / You opened the console — promising!",
      "color:#00ff41;font-weight:700");
    console.log("%cwindow.__hint = " + window.__hint, "color:#ffd35b");
  } catch (e) {}

  /* ---------- compact SHA-256 (fallback for non-secure contexts) ---------- */
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

  /* ---------- i18n ---------- */
  const I18N = {
    ko: { tagline:"입문부터 전문가까지 · 힌트와 함께 단계별로", reset:"초기화", score:"점수",
      solved:"해결", rank:"등급",
      footer:"교육용 워게임입니다. 모든 도전은 브라우저 안에서 해결됩니다. 외부 시스템을 공격하지 마세요.",
      hint:"힌트 보기", submit:"제출", placeholder:"정답 입력…", correct:"정답입니다! 🎉",
      wrong:"틀렸습니다. 다시 시도하세요.", already:"이미 해결했습니다.",
      lockedMsg:"잠김 — 이전 티어에서 ", lockedMsg2:"문제를 더 풀면 열립니다.",
      need:"통과 조건", solvedOf:"해결", hintPenalty:"힌트 -",
      resetConfirm:"모든 진행도를 초기화할까요?", format:"형식",
      complete:"🏆 모든 티어 클리어!", completeSub:"당신은 진정한 바이브 해커입니다. 최종 플래그를 친구에게도 도전시켜 보세요!",
      langBtn:"🌐 EN" },
    en: { tagline:"From novice to expert · staged, with hints", reset:"Reset", score:"Score",
      solved:"Solved", rank:"Rank",
      footer:"Educational wargame. Every challenge is solved inside your browser. Do not attack external systems.",
      hint:"Reveal hint", submit:"Submit", placeholder:"Enter answer…", correct:"Correct! 🎉",
      wrong:"Incorrect. Try again.", already:"Already solved.",
      lockedMsg:"Locked — solve ", lockedMsg2:" more from the previous tier to unlock.",
      need:"To pass", solvedOf:"solved", hintPenalty:"hint -",
      resetConfirm:"Reset all progress?", format:"Format",
      complete:"🏆 All tiers cleared!", completeSub:"You are a true vibe hacker. Challenge your friends with the final flag!",
      langBtn:"🌐 한국어" }
  };

  const RANKS = [
    { min:0,  icon:"🥚", ko:"알",       en:"Egg" },
    { min:1,  icon:"🐣", ko:"뉴비",     en:"Newbie" },
    { min:6,  icon:"🦊", ko:"수습",     en:"Apprentice" },
    { min:12, icon:"🐺", ko:"해커",     en:"Hacker" },
    { min:18, icon:"🦅", ko:"엘리트",   en:"Elite" },
    { min:24, icon:"👑", ko:"레전드",   en:"Legend" }
  ];

  const HINT_PENALTY = 0.2;   // each hint costs 20% of the challenge points
  const MIN_AWARD = 0.2;      // never award less than 20%

  /* ---------- state ---------- */
  const LS = "vibe_wargame_v1";
  let state = { solved:{}, hints:{}, lang:"ko" };
  try { const s = JSON.parse(localStorage.getItem(LS)); if (s) state = Object.assign(state, s); } catch (e) {}
  function save() { try { localStorage.setItem(LS, JSON.stringify(state)); } catch (e) {} }
  function t(k) { return I18N[state.lang][k]; }

  const totalChals = CHALLENGES.length;

  function tierSolvedCount(tid) {
    return CHALLENGES.filter(c => c.tier === tid && state.solved[c.id]).length;
  }
  function isTierUnlocked(tier) {
    if (tier.id === 0) return true;
    const prev = TIERS.find(x => x.id === tier.id - 1);
    return tierSolvedCount(prev.id) >= prev.need;
  }
  function totalScore() {
    return Object.values(state.solved).reduce((a, b) => a + (b.earned || 0), 0);
  }
  function awardFor(ch) {
    const used = state.hints[ch.id] || 0;
    const factor = Math.max(MIN_AWARD, 1 - used * HINT_PENALTY);
    return Math.round(ch.points * factor);
  }

  /* ---------- rendering ---------- */
  const tiersEl = document.getElementById("tiers");

  function render() {
    document.documentElement.lang = state.lang;
    document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
    document.getElementById("langBtn").textContent = t("langBtn");

    const solvedN = Object.keys(state.solved).length;
    document.getElementById("score").textContent = totalScore();
    document.getElementById("solvedCount").textContent = solvedN + "/" + totalChals;
    const rank = RANKS.slice().reverse().find(r => solvedN >= r.min);
    document.getElementById("rank").textContent = rank.icon;
    document.getElementById("rank").title = rank[state.lang];
    document.getElementById("progressBar").style.width = (solvedN / totalChals * 100) + "%";

    tiersEl.innerHTML = "";

    if (solvedN === totalChals) {
      const b = document.createElement("div");
      b.className = "complete-banner show";
      b.innerHTML = `<h2>${t("complete")}</h2><p>${t("completeSub")}</p>`;
      tiersEl.appendChild(b);
    }

    TIERS.forEach(tier => {
      const unlocked = isTierUnlocked(tier);
      const chals = CHALLENGES.filter(c => c.tier === tier.id);
      const sc = tierSolvedCount(tier.id);

      const sec = document.createElement("section");
      sec.className = "tier t" + tier.id + (unlocked ? "" : " locked") +
        (unlocked ? "" : " collapsed");

      const head = document.createElement("div");
      head.className = "tier-head";
      head.innerHTML =
        `<span class="tier-badge">TIER ${tier.id}</span>
         <h2>${tier[state.lang]}</h2>
         <span class="tier-meta">${sc}/${chals.length} ${t("solvedOf")} · ${t("need")} ${tier.need}</span>
         <span class="tier-lock">${unlocked ? "▾" : "🔒"}</span>`;
      head.addEventListener("click", () => { sec.classList.toggle("collapsed"); });
      sec.appendChild(head);

      const body = document.createElement("div");
      body.className = "tier-body";

      const desc = document.createElement("p");
      desc.className = "tier-desc";
      desc.textContent = tier["desc_" + state.lang];
      body.appendChild(desc);

      if (!unlocked) {
        const prev = TIERS.find(x => x.id === tier.id - 1);
        const remain = Math.max(0, prev.need - tierSolvedCount(prev.id));
        const note = document.createElement("div");
        note.className = "locked-note";
        note.textContent = `🔒 ${t("lockedMsg")}${remain}${t("lockedMsg2")}`;
        body.appendChild(note);
      } else {
        chals.forEach(ch => body.appendChild(renderChal(ch)));
      }
      sec.appendChild(body);
      tiersEl.appendChild(sec);
    });
  }

  function renderChal(ch) {
    const solved = !!state.solved[ch.id];
    const used = state.hints[ch.id] || 0;
    const card = document.createElement("div");
    card.className = "chal" + (solved ? " solved" : "");

    const top = document.createElement("div");
    top.className = "chal-top";
    top.innerHTML =
      `<span class="cat">${ch.cat}</span>
       <h3 class="chal-title">${ch.title[state.lang]}</h3>
       <span class="pts">${ch.points}pt</span>` +
      (solved ? `<span class="solved-tag">✓ +${state.solved[ch.id].earned}</span>` : "");
    card.appendChild(top);

    const prompt = document.createElement("div");
    prompt.className = "prompt";
    prompt.innerHTML = renderPrompt(ch.prompt[state.lang]);
    card.appendChild(prompt);

    if (ch.fmt) {
      const fmt = document.createElement("div");
      fmt.className = "fmt";
      fmt.innerHTML = `${t("format")}: <b>${escapeHtml(ch.fmt)}</b>`;
      card.appendChild(fmt);
    }

    // hints
    const hintsBox = document.createElement("div");
    hintsBox.className = "hints";
    ch.hints[state.lang].forEach((h, idx) => {
      if (idx < used) {
        const ht = document.createElement("div");
        ht.className = "hint-txt";
        ht.textContent = "💡 " + h;
        hintsBox.appendChild(ht);
      } else if (idx === used && !solved) {
        const hb = document.createElement("button");
        hb.className = "hint-btn";
        hb.textContent = `${t("hint")} ${idx + 1}/${ch.hints[state.lang].length} (${t("hintPenalty")}${Math.round(HINT_PENALTY*100)}%)`;
        hb.addEventListener("click", () => {
          state.hints[ch.id] = (state.hints[ch.id] || 0) + 1; save(); render();
        });
        hintsBox.appendChild(hb);
      }
    });
    card.appendChild(hintsBox);

    // answer
    const row = document.createElement("div");
    row.className = "answer-row";
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = t("placeholder");
    input.spellcheck = false;
    input.autocomplete = "off";
    const btn = document.createElement("button");
    btn.className = "submit-btn";
    btn.textContent = t("submit");
    const submit = () => checkAnswer(ch, input.value);
    btn.addEventListener("click", submit);
    input.addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
    row.appendChild(input);
    row.appendChild(btn);
    card.appendChild(row);
    return card;
  }

  function renderPrompt(s) {
    // escape, then turn `code` spans and keep newlines
    let h = escapeHtml(s);
    h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
    return h;
  }
  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;" }[c]));
  }

  async function checkAnswer(ch, raw) {
    if (state.solved[ch.id]) { toast(t("already"), "ok"); return; }
    const norm = ch.ci ? raw.trim().toLowerCase() : raw.trim();
    if (!norm) return;
    const h = await sha256(norm);
    if (h === ch.hash) {
      const earned = awardFor(ch);
      state.solved[ch.id] = { earned: earned, ts: Date.now() };
      save(); render();
      toast(t("correct") + "  +" + earned, "ok");
    } else {
      toast(t("wrong"), "err");
    }
  }

  /* ---------- toast ---------- */
  let toastTimer = null;
  function toast(msg, kind) {
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.className = "toast show " + (kind || "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = "toast"; }, 2200);
  }

  /* ---------- controls ---------- */
  document.getElementById("langBtn").addEventListener("click", () => {
    state.lang = state.lang === "ko" ? "en" : "ko"; save(); render();
  });
  document.getElementById("resetBtn").addEventListener("click", () => {
    if (confirm(t("resetConfirm"))) { state = { solved:{}, hints:{}, lang: state.lang }; save(); render(); }
  });

  render();
})();
