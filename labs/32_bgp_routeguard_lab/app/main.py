#!/usr/bin/env python3
"""
VibeHacking Lab 32 — BGPRouteGuard: BGP Routing Hijacking & RPKI ROA Security Lab
Autonomous System (AS 65001) BGP Router & Route Validation Engine
"""

import ipaddress
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="BGPRouteGuard — AS 65001 BGP Peering & Route Validation Lab",
    description="Hands-on BGP Prefix Hijacking, Sub-prefix (LPM) Hijacking, Route Leaks, and RPKI ROA Defense Lab",
    version="1.0.0"
)

# -----------------------------------------------------------------------------
# Domain Models & Baseline Topology State
# -----------------------------------------------------------------------------
LOCAL_ASN = 65001
LOCAL_ROUTER_ID = "198.51.100.1"

class ROAEntry(BaseModel):
    prefix: str
    max_length: int
    asn: int
    description: str

class BGPRoute(BaseModel):
    prefix: str
    next_hop: str
    as_path: List[int]
    origin_asn: int
    local_pref: int = 100
    med: int = 0
    community: List[str] = []
    rpki_status: str = "VALID"  # VALID, INVALID, NOT_FOUND
    is_fib_active: bool = True
    peer_asn: int = LOCAL_ASN

class PrefixHijackRequest(BaseModel):
    prefix: str = Field(default="198.51.100.0/24")
    origin_asn: int = Field(default=64599)
    as_path: List[int] = Field(default=[64599])
    local_pref: int = Field(default=200)

class SubprefixHijackRequest(BaseModel):
    subprefix: str = Field(default="198.51.100.0/25")
    origin_asn: int = Field(default=64599)
    as_path: List[int] = Field(default=[64599, 64512])

class ASPathLeakRequest(BaseModel):
    prefix: str = Field(default="198.51.100.0/24")
    spoofed_as_path: List[int] = Field(default=[64599, 65001])
    leak_type: str = Field(default="transit_to_peer")
    origin_asn: int = Field(default=65001)

class HardenConfigRequest(BaseModel):
    rpki_validation: bool = True
    max_prefix_limit: bool = True
    peer_filters: bool = True
    otc_enforcement: bool = True

# Standard RPKI ROA Database (RFC 6480 / RFC 6811)
ROA_DATABASE: List[ROAEntry] = [
    ROAEntry(prefix="198.51.100.0/24", max_length=24, asn=65001, description="VibeCorp Production Core Services"),
    ROAEntry(prefix="203.0.113.0/24", max_length=24, asn=65001, description="VibeCorp Infrastructure DMZ"),
    ROAEntry(prefix="192.0.2.0/24", max_length=24, asn=64512, description="Global Transit Tier-1 Backbone"),
]

def init_default_state() -> Dict[str, Any]:
    return {
        "hardened": False,
        "rpki_validation_enabled": False,
        "max_prefix_limit_enabled": False,
        "peer_filters_enabled": False,
        "otc_enforcement_enabled": False,
        "peers": {
            "64512": {"ip": "192.0.2.1", "name": "Global Transit Provider", "type": "transit", "state": "ESTABLISHED", "prefixes_received": 1},
            "64500": {"ip": "192.0.2.2", "name": "Regional IXP Peer", "type": "peer", "state": "ESTABLISHED", "prefixes_received": 1},
            "64599": {"ip": "192.0.2.99", "name": "Rogue ISP / Attacker", "type": "peer", "state": "ESTABLISHED", "prefixes_received": 0}
        },
        "rib": [
            BGPRoute(
                prefix="198.51.100.0/24",
                next_hop="198.51.100.1",
                as_path=[65001],
                origin_asn=65001,
                local_pref=100,
                rpki_status="VALID",
                is_fib_active=True,
                peer_asn=65001
            ),
            BGPRoute(
                prefix="203.0.113.0/24",
                next_hop="203.0.113.1",
                as_path=[65001],
                origin_asn=65001,
                local_pref=100,
                rpki_status="VALID",
                is_fib_active=True,
                peer_asn=65001
            ),
            BGPRoute(
                prefix="0.0.0.0/0",
                next_hop="192.0.2.1",
                as_path=[64512],
                origin_asn=64512,
                local_pref=100,
                rpki_status="NOT_FOUND",
                is_fib_active=True,
                peer_asn=64512
            )
        ],
        "attack_history": []
    }

STATE = init_default_state()

# -----------------------------------------------------------------------------
# RPKI ROA Validation Helper (RFC 6811)
# -----------------------------------------------------------------------------
def validate_rpki(prefix_str: str, origin_asn: int) -> str:
    """
    Validates a route against ROA entries:
    - VALID: Matching prefix, length <= max_length, origin ASN matches.
    - INVALID: Matching prefix covered by ROA, but origin ASN differs OR prefix length > max_length.
    - NOT_FOUND: No covering ROA exists.
    """
    try:
        route_net = ipaddress.ip_network(prefix_str)
    except ValueError:
        return "INVALID"

    covering_roas = []
    for roa in ROA_DATABASE:
        roa_net = ipaddress.ip_network(roa.prefix)
        if route_net.subnet_of(roa_net):
            covering_roas.append(roa)

    if not covering_roas:
        return "NOT_FOUND"

    for roa in covering_roas:
        if route_net.prefixlen <= roa.max_length and origin_asn == roa.asn:
            return "VALID"

    return "INVALID"

def update_fib():
    """
    Recomputes active routes in Forwarding Information Base (FIB) using Longest Prefix Match (LPM)
    and BGP path selection rules.
    """
    # Group routes by exact prefix
    by_prefix: Dict[str, List[BGPRoute]] = {}
    for r in STATE["rib"]:
        if STATE["rpki_validation_enabled"] and r.rpki_status == "INVALID":
            r.is_fib_active = False
            continue
        by_prefix.setdefault(r.prefix, []).append(r)

    # For each exact prefix, pick the best route (highest local_pref, shortest as_path)
    for pfx, candidates in by_prefix.items():
        # Sort candidates: highest local_pref, shortest as_path
        candidates.sort(key=lambda x: (-x.local_pref, len(x.as_path)))
        for i, c in enumerate(candidates):
            c.is_fib_active = (i == 0)

# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "lab": "Lab 32 — BGPRouteGuard",
        "local_asn": LOCAL_ASN,
        "router_id": LOCAL_ROUTER_ID,
        "hardened": STATE["hardened"],
        "active_routes_count": sum(1 for r in STATE["rib"] if r.is_fib_active)
    }

@app.get("/api/bgp/info")
def get_bgp_info():
    return {
        "local_asn": LOCAL_ASN,
        "router_id": LOCAL_ROUTER_ID,
        "security_controls": {
            "hardened": STATE["hardened"],
            "rpki_validation_enabled": STATE["rpki_validation_enabled"],
            "max_prefix_limit_enabled": STATE["max_prefix_limit_enabled"],
            "peer_filters_enabled": STATE["peer_filters_enabled"],
            "otc_enforcement_enabled": STATE["otc_enforcement_enabled"]
        },
        "peers": STATE["peers"],
        "roa_database": [r.model_dump() for r in ROA_DATABASE],
        "attack_history": STATE["attack_history"]
    }

@app.get("/api/bgp/routes")
def get_routes():
    update_fib()
    return {
        "rib": [r.model_dump() for r in STATE["rib"]],
        "fib": [r.model_dump() for r in STATE["rib"] if r.is_fib_active]
    }

@app.post("/api/bgp/exploit/prefix-hijack")
def exploit_prefix_hijack(req: PrefixHijackRequest):
    """
    Step 1: Exact Prefix Hijack
    Attacker (AS 64599) announces victim prefix 198.51.100.0/24 with competitive AS path/local_pref.
    Without RPKI, the router accepts this route and diverts traffic.
    """
    rpki_status = validate_rpki(req.prefix, req.origin_asn)

    if STATE["rpki_validation_enabled"] and rpki_status == "INVALID":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "BGP Update Dropped by RPKI ROA Validation",
                "reason": f"Announced origin AS {req.origin_asn} does not match authorized ROA ASN 65001 for {req.prefix}",
                "rpki_status": rpki_status,
                "mitigation": "RPKI Route Origin Validation (ROV) successfully rejected unauthorized origin."
            }
        )

    # In vulnerable state: install hijacked route with higher preference
    new_route = BGPRoute(
        prefix=req.prefix,
        next_hop="192.0.2.99",
        as_path=req.as_path,
        origin_asn=req.origin_asn,
        local_pref=req.local_pref,
        rpki_status=rpki_status,
        is_fib_active=True,
        peer_asn=64599
    )

    # Insert into RIB
    STATE["rib"].append(new_route)
    update_fib()
    STATE["attack_history"].append({
        "type": "prefix_hijack",
        "prefix": req.prefix,
        "origin_asn": req.origin_asn,
        "success": True
    })

    return {
        "status": "HIJACK_SUCCESSFUL",
        "attack_type": "Exact Prefix Hijacking",
        "target_prefix": req.prefix,
        "diverted_to_asn": req.origin_asn,
        "rpki_status": rpki_status,
        "fib_status": "Hijacked route selected as best path due to higher Local Preference (200 vs 100)",
        "flag": "FLAG{BGP_EXACT_PREFIX_HIJACK_4401}",
        "explanation": "RFC 4271 BGP lacks native authentication. Without RPKI ROA validation, any peer can announce any prefix and hijack global traffic."
    }

@app.post("/api/bgp/exploit/subprefix-hijack")
def exploit_subprefix_hijack(req: SubprefixHijackRequest):
    """
    Step 2: Sub-prefix Hijacking (Longest Prefix Match)
    Attacker announces more-specific /25 prefix (198.51.100.0/25).
    In IP routing, Longest Prefix Match ALWAYS beats /24 regardless of AS Path length or Local Pref!
    """
    rpki_status = validate_rpki(req.subprefix, req.origin_asn)

    if STATE["rpki_validation_enabled"] and rpki_status == "INVALID":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "BGP Update Dropped by RPKI MaxLength Validation",
                "reason": f"Announced prefix {req.subprefix} (/25) exceeds ROA max_length of 24 for covering prefix 198.51.100.0/24",
                "rpki_status": rpki_status,
                "mitigation": "RPKI ROA MaxLength restriction strictly enforces prefix granularity."
            }
        )

    new_route = BGPRoute(
        prefix=req.subprefix,
        next_hop="192.0.2.99",
        as_path=req.as_path,
        origin_asn=req.origin_asn,
        local_pref=100,
        rpki_status=rpki_status,
        is_fib_active=True,
        peer_asn=64599
    )

    STATE["rib"].append(new_route)
    update_fib()
    STATE["attack_history"].append({
        "type": "subprefix_hijack",
        "subprefix": req.subprefix,
        "origin_asn": req.origin_asn,
        "success": True
    })

    return {
        "status": "SUBPREFIX_HIJACK_SUCCESSFUL",
        "attack_type": "Sub-prefix Longest Prefix Match (LPM) Hijacking",
        "hijacked_subprefix": req.subprefix,
        "covering_prefix": "198.51.100.0/24",
        "lpm_advantage": "Longest Prefix Match (LPM) rule ensures prefix /25 is more specific than /24. All routers will forward packets matching 198.51.100.0~127 to AS 64599 unconditionally.",
        "flag": "FLAG{BGP_SUBPREFIX_LPM_HIJACK_5512}",
        "explanation": "Routers always forward packets according to Longest Prefix Match (LPM). RPKI ROA max-length enforcement prevents sub-prefix fragmentation attacks."
    }

@app.post("/api/bgp/exploit/as-path-leak")
def exploit_as_path_leak(req: ASPathLeakRequest):
    """
    Step 3: AS-Path Forgery & BGP Route Leak (RFC 7908)
    Attacker forges AS-Path [64599, 65001] to bypass naive origin filters while intercepting traffic,
    or leaks routes between non-client peers (transit to peer).
    """
    if STATE["peer_filters_enabled"] or STATE["otc_enforcement_enabled"]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "BGP Route Leak Blocked by Peer Filters & RFC 9234 OTC",
                "reason": "Route leak detected: received route from peer AS 64599 with Only-to-Customer (OTC) violation and unauthorized transit path.",
                "mitigation": "MANRS Inbound Peer Filtering and RFC 9234 BGP Role / OTC enforcement dropped the leaked route."
            }
        )

    new_route = BGPRoute(
        prefix=req.prefix,
        next_hop="192.0.2.99",
        as_path=req.spoofed_as_path,
        origin_asn=req.origin_asn,
        local_pref=150,
        rpki_status="VALID",  # Origin ASN is forged to 65001, so naive origin check passes!
        is_fib_active=True,
        peer_asn=64599
    )

    STATE["rib"].append(new_route)
    update_fib()
    STATE["attack_history"].append({
        "type": "as_path_leak",
        "prefix": req.prefix,
        "spoofed_as_path": req.spoofed_as_path,
        "success": True
    })

    return {
        "status": "ROUTE_LEAK_SUCCESSFUL",
        "attack_type": "AS-Path Forgery & BGP Route Leak (RFC 7908)",
        "spoofed_as_path": req.spoofed_as_path,
        "interception_node": "AS 64599 (Man-in-the-Middle)",
        "flag": "FLAG{BGP_ASPATH_LEAK_INTERCEPTION_6623}",
        "explanation": "RPKI origin validation alone only checks the rightmost (origin) ASN. Attacker forged [64599, 65001] to bypass origin checks and become a traffic interceptor. ASPA and RFC 9234 OTC are required to stop path leaks."
    }

@app.post("/api/bgp/harden")
def harden_bgp(cfg: HardenConfigRequest):
    """
    Enforces enterprise routing defenses:
    1. RPKI Route Origin Validation (discard Invalid routes)
    2. Max-Prefix Limits on peering sessions
    3. Strict Inbound Prefix Filtering (MANRS compliance)
    4. RFC 9234 Only-to-Customer (OTC) route leak prevention
    """
    STATE["hardened"] = True
    STATE["rpki_validation_enabled"] = cfg.rpki_validation
    STATE["max_prefix_limit_enabled"] = cfg.max_prefix_limit
    STATE["peer_filters_enabled"] = cfg.peer_filters
    STATE["otc_enforcement_enabled"] = cfg.otc_enforcement

    # Purge any invalid or leaked routes from RIB
    cleaned_rib = []
    dropped_count = 0
    for r in STATE["rib"]:
        if r.peer_asn == 64599:
            # Drop all unauthorized rogue announcements
            dropped_count += 1
            continue
        cleaned_rib.append(r)

    STATE["rib"] = cleaned_rib
    update_fib()

    return {
        "status": "HARDENED",
        "message": "Enterprise BGP & RPKI routing security controls activated.",
        "dropped_malicious_routes": dropped_count,
        "active_controls": {
            "rpki_rov_mode": "STRICT_DISCARD_INVALID",
            "max_prefix_limit": "ENFORCED (max 50 prefixes per peer)",
            "inbound_filter": "MANRS IRR & ROA Whitelist",
            "leak_prevention": "RFC 9234 OTC Attribute Verification"
        }
    }

@app.post("/api/bgp/reset")
def reset_bgp():
    """Restores baseline unhardened topology."""
    global STATE
    STATE = init_default_state()
    update_fib()
    return {
        "status": "RESET",
        "message": "BGP router topology reset to default baseline.",
        "active_routes": sum(1 for r in STATE["rib"] if r.is_fib_active)
    }

# -----------------------------------------------------------------------------
# Cyberpunk Web UI (Single Page Application)
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>BGPRouteGuard — AS 65001 BGP Peering & RPKI Security Lab</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0a0e17;
      --card: #111927;
      --border: #1e293b;
      --text: #e2e8f0;
      --cyan: #00f2fe;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --purple: #8b5cf6;
      --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 24px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid var(--cyan);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 {
      font-size: 1.6rem;
      color: var(--cyan);
      font-family: var(--font-mono);
      letter-spacing: -0.5px;
    }
    .badge {
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }
    .badge-vuln { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-hardened { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }

    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }

    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }
    .card h2 {
      font-size: 1.1rem;
      color: var(--cyan);
      margin-bottom: 12px;
      font-family: var(--font-mono);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Terminal output */
    pre, code {
      font-family: var(--font-mono);
      font-size: 0.82rem;
    }
    .terminal {
      background: #050811;
      border: 1px solid #1e293b;
      padding: 12px;
      border-radius: 6px;
      max-height: 250px;
      overflow-y: auto;
      color: #38bdf8;
      white-space: pre-wrap;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      margin-top: 8px;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 8px;
      text-align: left;
    }
    th { background: rgba(255,255,255,0.05); color: var(--cyan); }
    tr.fib-active { background: rgba(16, 185, 129, 0.08); }
    tr.fib-inactive { opacity: 0.5; }

    .btn {
      background: #1e293b;
      color: var(--text);
      border: 1px solid var(--cyan);
      padding: 8px 14px;
      border-radius: 4px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      transition: all 0.2s;
    }
    .btn:hover { background: var(--cyan); color: #000; font-weight: bold; }
    .btn-red { border-color: var(--red); color: var(--red); }
    .btn-red:hover { background: var(--red); color: #fff; }
    .btn-green { border-color: var(--green); color: var(--green); }
    .btn-green:hover { background: var(--green); color: #000; }

    .step-box {
      border-left: 3px solid var(--purple);
      padding-left: 12px;
      margin-bottom: 16px;
    }
    .flag-box {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--green);
      color: var(--green);
      padding: 12px;
      border-radius: 6px;
      margin-top: 12px;
      font-family: var(--font-mono);
      font-weight: bold;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>🌐 BGPRouteGuard — AS 65001</h1>
      <small style="color:#64748b;">Autonomous System Border Router & RPKI ROA Defense Lab</small>
    </div>
    <div id="statusBadge">
      <span class="badge badge-vuln">SECURITY: VULNERABLE (RPKI OFF)</span>
    </div>
  </header>

  <div class="grid">
    <!-- Left: Topology & Routing Table -->
    <div class="card">
      <h2>📡 BGP Routing Table (RIB / FIB)</h2>
      <p style="font-size:0.85rem; color:#94a3b8; margin-bottom:8px;">
        Local AS: <b>65001</b> | Router ID: <b>198.51.100.1</b> | Peers: <b>3 Active</b>
      </p>
      <table>
        <thead>
          <tr>
            <th>Prefix</th>
            <th>Next-Hop</th>
            <th>AS-Path</th>
            <th>RPKI</th>
            <th>FIB</th>
          </tr>
        </thead>
        <tbody id="routesBody">
          <tr><td colspan="5" style="text-align:center;">로딩 중...</td></tr>
        </tbody>
      </table>

      <h2 style="margin-top:20px;">📜 RPKI ROA Cache (RFC 6480)</h2>
      <table>
        <thead>
          <tr>
            <th>Authorized Prefix</th>
            <th>Max-Len</th>
            <th>Authorized Origin</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>198.51.100.0/24</td><td>24</td><td>AS 65001</td></tr>
          <tr><td>203.0.113.0/24</td><td>24</td><td>AS 65001</td></tr>
        </tbody>
      </table>

      <div style="margin-top:16px; display:flex; gap:10px;">
        <button class="btn btn-green" onclick="harden()">🛡️ RPKI & MANRS 하드닝</button>
        <button class="btn btn-red" onclick="resetLab()">🔄 토폴로지 리셋</button>
      </div>
    </div>

    <!-- Right: Attack Simulation -->
    <div class="card">
      <h2>⚔️ BGP 취약점 실전 침투 시뮬레이터</h2>

      <div class="step-box">
        <b>Step 1: Exact Prefix Hijacking</b>
        <p style="font-size:0.8rem; color:#94a3b8;">
          공격자 AS 64599가 희생자 대역(198.51.100.0/24)을 고의로 선언하여 트래픽을 가로챕니다.
        </p>
        <button class="btn" onclick="exploitPrefix()">Step 1 실행 (Prefix Hijack)</button>
      </div>

      <div class="step-box">
        <b>Step 2: Sub-prefix Hijacking (Longest Prefix Match)</b>
        <p style="font-size:0.8rem; color:#94a3b8;">
          희생자의 /24보다 더 구체적인 /25 서브프리픽스를 선언하여 LPM 규칙으로 무조건 트래픽을 흡수합니다.
        </p>
        <button class="btn" onclick="exploitSubprefix()">Step 2 실행 (Sub-prefix LPM)</button>
      </div>

      <div class="step-box">
        <b>Step 3: AS-Path Forgery & Route Leak</b>
        <p style="font-size:0.8rem; color:#94a3b8;">
          AS-Path에 정상 ASN을 위조 주입하여 오리진 필터를 우회하고 중간자(MITM) 감청 경로를 형성합니다.
        </p>
        <button class="btn" onclick="exploitLeak()">Step 3 실행 (AS-Path Leak)</button>
      </div>

      <h2 style="margin-top:16px;">💻 BGP BGP-4 Console Log</h2>
      <div id="consoleLog" class="terminal">[SYSTEM] BGPRouteGuard router daemon ready on AS 65001.</div>
      <div id="flagBox" style="display:none;" class="flag-box"></div>
    </div>
  </div>

  <script>
    async function fetchRoutes() {
      try {
        const res = await fetch('/api/bgp/routes');
        const data = await res.json();
        const tbody = document.getElementById('routesBody');
        tbody.innerHTML = '';
        data.rib.forEach(r => {
          const tr = document.createElement('tr');
          tr.className = r.is_fib_active ? 'fib-active' : 'fib-inactive';
          let rpkiColor = r.rpki_status === 'VALID' ? '#10b981' : (r.rpki_status === 'INVALID' ? '#ef4444' : '#f59e0b');
          tr.innerHTML = `
            <td><b>${r.prefix}</b></td>
            <td>${r.next_hop}</td>
            <td>[${r.as_path.join(' ')}]</td>
            <td style="color:${rpkiColor}; font-weight:bold;">${r.rpki_status}</td>
            <td>${r.is_fib_active ? '✅ ACTIVE' : '❌ IGNORED'}</td>
          `;
          tbody.appendChild(tr);
        });
      } catch (e) {
        console.error(e);
      }
    }

    function log(msg) {
      const c = document.getElementById('consoleLog');
      c.innerText += '\\n' + msg;
      c.scrollTop = c.scrollHeight;
    }

    function showFlag(flag) {
      const b = document.getElementById('flagBox');
      b.style.display = 'block';
      b.innerText = '🚩 ' + flag;
    }

    async function exploitPrefix() {
      log('[*] Step 1: Exact Prefix Hijack (198.51.100.0/24 from AS 64599) 전송 중...');
      const res = await fetch('/api/bgp/exploit/prefix-hijack', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prefix: '198.51.100.0/24', origin_asn: 64599, as_path: [64599], local_pref: 200})
      });
      const data = await res.json();
      if (!res.ok) {
        log('[-] 실패: ' + (data.detail.error || JSON.stringify(data.detail)));
        return;
      }
      log('[+] 성공: ' + data.explanation);
      showFlag(data.flag);
      fetchRoutes();
    }

    async function exploitSubprefix() {
      log('[*] Step 2: Sub-prefix Hijack (198.51.100.0/25 from AS 64599) 전송 중...');
      const res = await fetch('/api/bgp/exploit/subprefix-hijack', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({subprefix: '198.51.100.0/25', origin_asn: 64599, as_path: [64599, 64512]})
      });
      const data = await res.json();
      if (!res.ok) {
        log('[-] 실패: ' + (data.detail.error || JSON.stringify(data.detail)));
        return;
      }
      log('[+] 성공: ' + data.lpm_advantage);
      showFlag(data.flag);
      fetchRoutes();
    }

    async function exploitLeak() {
      log('[*] Step 3: AS-Path Forgery & Route Leak ([64599, 65001]) 전송 중...');
      const res = await fetch('/api/bgp/exploit/as-path-leak', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prefix: '198.51.100.0/24', spoofed_as_path: [64599, 65001], leak_type: 'transit_to_peer'})
      });
      const data = await res.json();
      if (!res.ok) {
        log('[-] 실패: ' + (data.detail.error || JSON.stringify(data.detail)));
        return;
      }
      log('[+] 성공: ' + data.explanation);
      showFlag(data.flag);
      fetchRoutes();
    }

    async function harden() {
      log('[*] RPKI ROA 유효성 검증 및 MANRS 라우트 필터링 활성화 중...');
      const res = await fetch('/api/bgp/harden', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rpki_validation: true, max_prefix_limit: true, peer_filters: true, otc_enforcement: true})
      });
      const data = await res.json();
      log('[+] 하드닝 완료: 비인가 라우트 ' + data.dropped_malicious_routes + '개 폐기.');
      document.getElementById('statusBadge').innerHTML = '<span class="badge badge-hardened">SECURITY: HARDENED (RPKI + MANRS ON)</span>';
      fetchRoutes();
    }

    async function resetLab() {
      log('[*] 라우터 상태 초기화 중...');
      await fetch('/api/bgp/reset', {method: 'POST'});
      log('[+] 초기화 완료.');
      document.getElementById('statusBadge').innerHTML = '<span class="badge badge-vuln">SECURITY: VULNERABLE (RPKI OFF)</span>';
      document.getElementById('flagBox').style.display = 'none';
      fetchRoutes();
    }

    fetchRoutes();
  </script>
</body>
</html>
""")
