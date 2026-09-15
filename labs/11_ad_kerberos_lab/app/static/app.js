// KeroShield Client Application
document.addEventListener("DOMContentLoaded", () => {
  let sessionTgt = null;
  let sessionGoldenTicket = null;
  let solvedFlags = new Set(JSON.parse(localStorage.getItem("keroshield_solved") || "[]"));

  updateFlagHUD();

  // Tab switching
  const navItems = document.querySelectorAll(".nav-item");
  const tabContents = document.querySelectorAll(".tab-content");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const tabId = item.dataset.tab;
      navItems.forEach(n => n.classList.remove("active"));
      tabContents.forEach(t => t.classList.remove("active"));
      item.classList.add("active");
      const target = document.getElementById("tab-" + tabId);
      if (target) target.classList.add("active");

      if (tabId === "recon") loadReconObjects();
      if (tabId === "audit") loadAuditLogs();
    });
  });

  // Load initial recon
  loadReconObjects();

  // --- 0. Recon Loader ---
  async function loadReconObjects() {
    try {
      const res = await fetch("/api/ad/objects");
      const data = await res.json();
      const tbody = document.getElementById("reconBody");
      tbody.innerHTML = "";

      data.accounts.forEach(acc => {
        const tr = document.createElement("tr");
        const preauthBadge = acc.dont_req_preauth
          ? '<span class="highlight-red">Disabled (Vuln)</span>'
          : '<span style="color:#10b981;">Required</span>';
        const spnBadge = acc.spn
          ? `<span class="highlight-orange">${acc.spn}</span>`
          : '<span style="color:#6b7280;">-</span>';
        const rightsBadge = acc.has_replication_rights
          ? '<span class="highlight-purple">DCSync (Get-Changes-All)</span>'
          : (acc.memberOf.includes("Domain Admins") ? '<span class="highlight-gold">Domain Admin</span>' : '<span style="color:#6b7280;">Standard</span>');

        tr.innerHTML = `
          <td><b>${acc.sAMAccountName}</b></td>
          <td><code>${acc.rid}</code></td>
          <td>${preauthBadge}</td>
          <td>${spnBadge}</td>
          <td>${rightsBadge}</td>
          <td style="color:#94a3b8; font-size:0.8rem;">${acc.description}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      console.error("Failed to load AD objects", err);
    }
  }

  // --- 1. AS-REP Roasting ---
  document.getElementById("btnAsReq").addEventListener("click", async () => {
    const username = document.getElementById("asreqUser").value.trim();
    const resultBox = document.getElementById("asreqResult");
    const output = document.getElementById("asreqHashOutput");

    try {
      const res = await fetch("/api/kerberos/as_req", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
      });
      const data = await res.json();
      if (!res.ok) {
        alert("KDC Error: " + (data.detail || data.message || "Failed to retrieve AS-REP"));
        return;
      }

      sessionTgt = data.tgt_token;
      resultBox.style.display = "block";
      output.textContent = data.asrep_hash;
    } catch (e) {
      alert("Request failed: " + e);
    }
  });

  document.getElementById("btnCrackAsrep").addEventListener("click", () => {
    const out = document.getElementById("asrepCrackedOutput");
    out.style.display = "block";
    out.innerHTML = `
      [+] Cracking hash with rockyou.txt (Hashcat mode 18200)...<br>
      [+] Status: <b>CRACKED</b><br>
      [+] Target: <code>j.smith@CORP.LOCAL</code><br>
      [+] Recovered Password: <b style="color:#fff;">Summer2025!</b><br>
      [+] Flag 1: <b>FLAG{ASREP_R04ST_PREAUTH_BYPASS_8201}</b>
    `;
    markSolved("FLAG{ASREP_R04ST_PREAUTH_BYPASS_8201}");
  });

  // --- 2. Kerberoasting ---
  document.getElementById("btnTgsReq").addEventListener("click", async () => {
    const spn = document.getElementById("tgsSpn").value.trim();
    const resultBox = document.getElementById("tgsResult");
    const output = document.getElementById("tgsHashOutput");

    if (!sessionTgt) {
      alert("You need a valid TGT first! Complete Step 1 or log in as a domain user.");
      return;
    }

    try {
      const res = await fetch("/api/kerberos/tgs_req", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tgt_token: sessionTgt, spn })
      });
      const data = await res.json();
      if (!res.ok) {
        alert("TGS Error: " + (data.detail || "Failed to retrieve TGS"));
        return;
      }

      resultBox.style.display = "block";
      output.textContent = data.tgs_hash;
    } catch (e) {
      alert("Request failed: " + e);
    }
  });

  document.getElementById("btnCrackTgs").addEventListener("click", () => {
    const out = document.getElementById("tgsCrackedOutput");
    out.style.display = "block";
    out.innerHTML = `
      [+] Cracking service ticket with Hashcat mode 13100...<br>
      [+] Service Account: <code>mssql_svc</code><br>
      [+] Recovered Service Password: <b style="color:#fff;">Password123!</b><br>
      [+] Flag 2: <b>FLAG{KERBER04ST_SPN_TGS_EXTRACT_4918}</b>
    `;
    markSolved("FLAG{KERBER04ST_SPN_TGS_EXTRACT_4918}");
  });

  // --- 3. DCSync ---
  document.getElementById("btnDcSync").addEventListener("click", async () => {
    const username = document.getElementById("dcsyncUser").value.trim();
    const password_or_hash = document.getElementById("dcsyncCred").value.trim();
    const target_user = document.getElementById("dcsyncTarget").value.trim();
    const resultBox = document.getElementById("dcsyncResult");
    const output = document.getElementById("dcsyncOutput");
    const flagOut = document.getElementById("dcsyncFlagOutput");

    try {
      const res = await fetch("/api/ad/dcsync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password_or_hash, target_user: "all" })
      });
      const data = await res.json();
      if (!res.ok) {
        alert("DCSync Denied: " + (data.detail || "Replication error"));
        return;
      }

      resultBox.style.display = "block";
      let dump = "";
      for (const [u, info] of Object.entries(data.hashes)) {
        dump += `${u}:${info.rid}:aad3b435b51404eeaad3b435b51404ee:${info.ntlm}:::\n`;
      }
      output.textContent = dump;
      flagOut.innerHTML = `[+] DCSync Completed! Master krbtgt Hash Harvested.<br>[+] Flag 3: <b>${data.flag}</b>`;
      markSolved(data.flag);
    } catch (e) {
      alert("DCSync failed: " + e);
    }
  });

  // --- 4. Golden Ticket ---
  document.getElementById("btnForgeGolden").addEventListener("click", async () => {
    const domain = document.getElementById("gtDomain").value.trim();
    const domain_sid = document.getElementById("gtSid").value.trim();
    const krbtgt_hash = document.getElementById("gtKrbtgt").value.trim();
    const user_to_impersonate = document.getElementById("gtUser").value.trim();
    const resultBox = document.getElementById("gtResult");
    const output = document.getElementById("gtOutput");
    const flagOut = document.getElementById("gtFlagOutput");

    try {
      const res = await fetch("/api/kerberos/golden_ticket", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, domain_sid, krbtgt_hash, user_to_impersonate })
      });
      const data = await res.json();
      if (!res.ok) {
        alert("Golden Ticket Error: " + (data.detail || "Forgery rejected"));
        return;
      }

      sessionGoldenTicket = data.golden_ticket_ccache;
      resultBox.style.display = "block";
      output.textContent = `[+] Master TGT Forged!\nUser: ${user_to_impersonate}\nDomain: ${domain}\nMembership: Domain Admins (512)\nTicket Blob: ${sessionGoldenTicket.substring(0, 80)}...`;
      flagOut.innerHTML = `[+] Golden Ticket Created!<br>[+] Flag 4: <b>${data.flag}</b>`;
      markSolved(data.flag);
    } catch (e) {
      alert("Request failed: " + e);
    }
  });

  document.getElementById("btnAdminExec").addEventListener("click", async () => {
    const command = document.getElementById("adminCmd").value.trim();
    const output = document.getElementById("adminCmdOutput");

    if (!sessionGoldenTicket) {
      alert("Forge a Golden Ticket first!");
      return;
    }

    try {
      const res = await fetch("/api/ad/domain_admin_exec", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + sessionGoldenTicket
        },
        body: JSON.stringify({ command })
      });
      const data = await res.json();
      if (!res.ok) {
        output.textContent = "[-] Access Denied: " + (data.detail || "Execution failed");
        return;
      }
      output.textContent = `[${data.executed_as} @ ${data.domain_controller}]\n${data.output}`;
    } catch (e) {
      output.textContent = "[-] Execution error: " + e;
    }
  });

  // --- Terminal ---
  const termForm = document.getElementById("terminalForm");
  const termInput = document.getElementById("termInput");
  const termScreen = document.getElementById("terminalScreen");

  termForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const cmd = termInput.value.trim();
    if (!cmd) return;

    appendTermLine(`attacker@kali:~$ ${cmd}`, "cmd");
    termInput.value = "";

    if (cmd === "clear") {
      termScreen.innerHTML = "";
      return;
    }

    try {
      const res = await fetch("/api/terminal/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd })
      });
      const data = await res.json();
      appendTermLine(data.output || "", "output");
    } catch (e) {
      appendTermLine("Error: " + e, "err");
    }
  });

  document.querySelectorAll(".chip").forEach(ch => {
    ch.addEventListener("click", () => {
      termInput.value = ch.dataset.cmd;
      termForm.dispatchEvent(new Event("submit"));
    });
  });

  function appendTermLine(text, type) {
    const div = document.createElement("div");
    div.className = "terminal-line " + (type || "");
    div.textContent = text;
    termScreen.appendChild(div);
    termScreen.scrollTop = termScreen.scrollHeight;
  }

  // --- Audit Telemetry Loader ---
  document.getElementById("btnRefreshLogs").addEventListener("click", loadAuditLogs);

  async function loadAuditLogs() {
    try {
      const res = await fetch("/api/terminal/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: "audit" })
      });
      const data = await res.json();
      const raw = data.output || "";
      const lines = raw.split("\n").filter(l => l.trim() && !l.startsWith("-"));
      const tbody = document.getElementById("auditBody");
      tbody.innerHTML = "";

      if (lines.length <= 1) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No security events recorded yet.</td></tr>';
        return;
      }

      // skip header
      lines.slice(1).forEach(line => {
        const parts = line.split(/\s{2,}/);
        if (parts.length >= 4) {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><code>${parts[0]}</code></td>
            <td><b style="color:#00e5ff;">${parts[1]}</b></td>
            <td>${parts[2]}</td>
            <td><b>${parts[3]}</b></td>
            <td>10.10.10.100</td>
            <td style="color:#cbd5e1; font-size:0.8rem;">${parts[4] || ""}</td>
          `;
          tbody.appendChild(tr);
        }
      });
    } catch (e) {
      console.error("Failed to load audit logs", e);
    }
  }

  // --- Flag Submitter ---
  document.getElementById("btnSubmitFlag").addEventListener("click", async () => {
    const input = document.getElementById("flagInput");
    const fb = document.getElementById("flagFeedback");
    const flag = input.value.trim();
    if (!flag) return;

    try {
      const res = await fetch("/api/flags/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flag })
      });
      const data = await res.json();
      if (data.correct) {
        fb.className = "flag-feedback ok";
        fb.textContent = "✓ " + data.message;
        markSolved(flag);
        input.value = "";
      } else {
        fb.className = "flag-feedback err";
        fb.textContent = "✗ " + data.message;
      }
    } catch (e) {
      fb.className = "flag-feedback err";
      fb.textContent = "Error: " + e;
    }
  });

  function markSolved(flag) {
    solvedFlags.add(flag);
    localStorage.setItem("keroshield_solved", JSON.stringify([...solvedFlags]));
    updateFlagHUD();
  }

  function updateFlagHUD() {
    const count = solvedFlags.size;
    const hud = document.getElementById("flagCount");
    if (hud) hud.textContent = `${count}/4`;

    for (let i = 1; i <= 4; i++) {
      const dot = document.getElementById("dot" + i);
      if (dot) {
        if (i <= count) dot.classList.add("done");
        else dot.classList.remove("done");
      }
    }
  }
});
