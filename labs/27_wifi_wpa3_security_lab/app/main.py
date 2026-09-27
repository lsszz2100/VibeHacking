"""Lab 27: WiFiShield - Wireless Penetration & WPA3 Security Lab (FastAPI)."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import hmac
import html
import re

app = FastAPI(title="WiFiShield - Wireless Penetration & WPA3 Security Lab", version="1.0.0")

# ── CTF 플래그 정의 ──────────────────────────────────────────────────────────
FLAGS = {
    "step1": "FLAG{pmkid_rsn_ie_offline_hashcat_cracked_8027}",
    "step2": "FLAG{dragonfly_sae_sidechannel_downgraded_9142}",
    "step3": "FLAG{80211w_pmf_bip_deauth_flood_protected_5583}",
}

# ── 모의 AP 환경 데이터 ───────────────────────────────────────────────────────
TARGET_AP = {
    "ssid": "Enterprise_Corp_Secure",
    "bssid": "00:11:22:33:44:55",
    "client_mac": "aa:bb:cc:dd:ee:ff",
    "valid_psk": "winter2026!corp",
    "security": "WPA2/WPA3-Transition",
    "pmf": "optional",  # optional | required | disabled
    "channel": 6,
    "freq_mhz": 2437,
}

ROGUE_AP = {
    "ssid": "Enterprise_Corp_Secure",
    "bssid": "de:ad:be:ef:13:37",
    "channel": 6,
    "evil_twin_active": True,
    "isolated": False,
}

# ── 요청 모델 ─────────────────────────────────────────────────────────────────
class PMKIDCrackRequest(BaseModel):
    bssid: str
    client_mac: str
    captured_pmkid: str
    dictionary_word: str

class SAEAttackRequest(BaseModel):
    target_ssid: str
    attack_vector: str  # dragonblood_timing_leak | transition_downgrade
    sae_group: int = 19
    injection_frames: int = 100

class MFPDefenseRequest(BaseModel):
    enable_pmf: bool
    pmf_mode: str  # optional | required
    rogue_bssid: str
    isolate_rogue: bool


def calculate_pmkid(psk: str, ssid: str, bssid: str, client_mac: str) -> str:
    """PBKDF2-HMAC-SHA1(PSK, SSID, 4096, 32) -> PMK; HMAC-SHA1(PMK, 'PMK Name' | BSSID | Client_MAC)[:16]"""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)
    bssid_clean = bytes.fromhex(bssid.replace(":", ""))
    sta_clean = bytes.fromhex(client_mac.replace(":", ""))
    pmk_data = b"PMK Name" + bssid_clean + sta_clean
    pmkid = hmac.new(pmk, pmk_data, hashlib.sha1).hexdigest()[:32]
    return pmkid


# 사전 계산된 목표 PMKID
TARGET_PMKID = calculate_pmkid(
    TARGET_AP["valid_psk"],
    TARGET_AP["ssid"],
    TARGET_AP["bssid"],
    TARGET_AP["client_mac"]
)


# ── Health & Web UI ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "lab": "WiFiShield", "port": 8027}


@app.get("/api/wifi/status")
def wifi_status():
    return {
        "target_ap": TARGET_AP,
        "rogue_ap": ROGUE_AP,
        "captured_pmkid": TARGET_PMKID,
    }


@app.get("/", response_class=HTMLResponse)
def index_view():
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Lab 27: WiFiShield - Wireless Penetration & WPA3 Security Lab</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --border: #1f293d;
            --primary: #06b6d4;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --text: #e2e8f0;
            --muted: #94a3b8;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        h1 {{ margin: 0 0 8px 0; color: var(--primary); font-size: 24px; }}
        .badge {{
            display: inline-block;
            background: rgba(6, 182, 212, 0.2);
            color: var(--primary);
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 16px;
            color: #38bdf8;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        .form-group {{
            margin-bottom: 14px;
        }}
        label {{
            display: block;
            font-size: 13px;
            color: var(--muted);
            margin-bottom: 4px;
        }}
        input, select {{
            width: 100%;
            background: #0d1321;
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 6px;
            box-sizing: border-box;
            font-size: 13px;
        }}
        button {{
            background: var(--primary);
            color: #000;
            font-weight: 600;
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            cursor: pointer;
            width: 100%;
            transition: opacity 0.2s;
        }}
        button:hover {{ opacity: 0.9; }}
        .result {{
            margin-top: 14px;
            background: #0d1321;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 200px;
            overflow-y: auto;
        }}
        .flag {{
            color: var(--warning);
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>📡 Lab 27: WiFiShield - Wireless Penetration & WPA3 Security Lab</h1>
                <div style="color: var(--muted); font-size: 14px;">
                    WPA2/WPA3 PMKID 수집 및 오프라인 크래킹 · SAE Dragonblood 부채널 · Evil Twin & 802.11w MFP 방어
                </div>
            </div>
            <div>
                <span class="badge">Port: 8027</span>
                <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: var(--success); margin-left: 8px;">Active</span>
            </div>
        </div>
    </div>

    <div class="grid">
        <!-- Step 1: PMKID Crack -->
        <div class="card">
            <h2>Step 1: PMKID 수집 및 오프라인 사전 공격</h2>
            <p style="font-size: 13px; color: var(--muted);">
                RSN IE EAPOL 1/4 프레임에서 도출된 PMKID를 분석하고 사전 공격을 통해 WPA2/WPA3 혼용 AP의 PSK를 크래킹합니다.
            </p>
            <div class="form-group">
                <label>Target AP BSSID</label>
                <input type="text" id="pmkid_bssid" value="{TARGET_AP['bssid']}">
            </div>
            <div class="form-group">
                <label>Client STA MAC</label>
                <input type="text" id="pmkid_sta" value="{TARGET_AP['client_mac']}">
            </div>
            <div class="form-group">
                <label>Captured PMKID (Hex)</label>
                <input type="text" id="pmkid_hex" value="{TARGET_PMKID}">
            </div>
            <div class="form-group">
                <label>Dictionary Word</label>
                <input type="text" id="pmkid_word" placeholder="테스트할 사전 단어 입력 (예: winter2026!corp)">
            </div>
            <button onclick="crackPMKID()">⚡ Hashcat 오프라인 크래킹 실행</button>
            <div id="pmkid_result" class="result">대기 중...</div>
        </div>

        <!-- Step 2: SAE Dragonblood -->
        <div class="card">
            <h2>Step 2: WPA3 SAE 부채널 & 다운그레이드</h2>
            <p style="font-size: 13px; color: var(--muted);">
                WPA3 SAE Dragonfly PWE 계산의 타이밍 부채널(CVE-2019-9494)을 이용하거나 WPA2 Transition 다운그레이드를 수행합니다.
            </p>
            <div class="form-group">
                <label>Target SSID</label>
                <input type="text" id="sae_ssid" value="{TARGET_AP['ssid']}">
            </div>
            <div class="form-group">
                <label>Attack Vector</label>
                <select id="sae_vector">
                    <option value="transition_downgrade">WPA3 Transition Downgrade Attack</option>
                    <option value="dragonblood_timing_leak">Dragonblood Side-channel Timing Leak (CVE-2019-9494)</option>
                </select>
            </div>
            <div class="form-group">
                <label>SAE Elliptic Curve Group</label>
                <select id="sae_group">
                    <option value="19">Group 19 (NIST P-256)</option>
                    <option value="20">Group 20 (NIST P-384)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Injected Frame Count</label>
                <input type="number" id="sae_frames" value="100">
            </div>
            <button onclick="attackSAE()">🎯 WPA3 SAE 익스플로잇 주입</button>
            <div id="sae_result" class="result">대기 중...</div>
        </div>

        <!-- Step 3: Evil Twin & 802.11w MFP Defense -->
        <div class="card">
            <h2>Step 3: Evil Twin 탐지 & 802.11w MFP 방어</h2>
            <p style="font-size: 13px; color: var(--muted);">
                가짜 AP(Rogue AP)를 통한 Deauth 브로드캐스트 플러딩을 차단하고 802.11w PMF(Protected Management Frames)를 활성화합니다.
            </p>
            <div class="form-group">
                <label>Detected Rogue AP BSSID</label>
                <input type="text" id="defense_rogue_bssid" value="{ROGUE_AP['bssid']}">
            </div>
            <div class="form-group">
                <label>IEEE 802.11w PMF Mode</label>
                <select id="defense_pmf_mode">
                    <option value="optional">Optional (WPA2 호환 모드 - 취약)</option>
                    <option value="required">Required (WPA3 강제 모드 - 안전)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Isolate Rogue AP</label>
                <select id="defense_isolate">
                    <option value="true">격리 정책 활성화 (Isolate)</option>
                    <option value="false">비활성화</option>
                </select>
            </div>
            <button onclick="applyDefense()">🛡️ 802.11w MFP 방어 및 악성 AP 격리</button>
            <div id="defense_result" class="result">대기 중...</div>
        </div>
    </div>

    <script>
        async function crackPMKID() {{
            const bssid = document.getElementById('pmkid_bssid').value;
            const sta = document.getElementById('pmkid_sta').value;
            const pmkid = document.getElementById('pmkid_hex').value;
            const word = document.getElementById('pmkid_word').value;
            const resEl = document.getElementById('pmkid_result');
            resEl.innerText = "⏳ Hashcat 22000 모드 사전 공격 연산 중...";

            try {{
                const res = await fetch('/api/wifi/pmkid/crack', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        bssid: bssid,
                        client_mac: sta,
                        captured_pmkid: pmkid,
                        dictionary_word: word
                    }})
                }});
                const data = await res.json();
                if (data.status === 'cracked') {{
                    resEl.innerHTML = `✅ [CRACKED] 패스워드 복원 성공!\n• 복원된 PSK: <b>${{data.psk}}</b>\n• SSID: ${{data.ssid}}\n• 플래그: <span class="flag">${{data.flag}}</span>`;
                }} else {{
                    resEl.innerText = `❌ [FAILURE] 일치하지 않는 사전 단어입니다.\n• 시도한 단어: ${{word}}\n• 응답: ${{data.message || 'PMK mismatch'}}`;
                }}
            }} catch (e) {{
                resEl.innerText = "오류 발생: " + e.message;
            }}
        }}

        async function attackSAE() {{
            const ssid = document.getElementById('sae_ssid').value;
            const vector = document.getElementById('sae_vector').value;
            const group = parseInt(document.getElementById('sae_group').value);
            const frames = parseInt(document.getElementById('sae_frames').value);
            const resEl = document.getElementById('sae_result');
            resEl.innerText = "⏳ WPA3 SAE 프레임 분석 및 공격 주입 중...";

            try {{
                const res = await fetch('/api/wifi/sae/attack', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        target_ssid: ssid,
                        attack_vector: vector,
                        sae_group: group,
                        injection_frames: frames
                    }})
                }});
                const data = await res.json();
                if (data.status === 'exploited') {{
                    resEl.innerHTML = `✅ [EXPLOITED] WPA3 SAE 익스플로잇 성공!\n• 공격 벡터: ${{data.vector}}\n• 다운그레이드 결과: ${{data.downgrade_target}}\n• 플래그: <span class="flag">${{data.flag}}</span>`;
                }} else {{
                    resEl.innerText = `❌ [FAILURE] 공격 실패: ${{data.detail || data.status}}`;
                }}
            }} catch (e) {{
                resEl.innerText = "오류 발생: " + e.message;
            }}
        }}

        async function applyDefense() {{
            const rogue = document.getElementById('defense_rogue_bssid').value;
            const pmfMode = document.getElementById('defense_pmf_mode').value;
            const isolate = document.getElementById('defense_isolate').value === 'true';
            const resEl = document.getElementById('defense_result');
            resEl.innerText = "⏳ 802.11w MFP 정책 배포 및 Rogue AP 격리 중...";

            try {{
                const res = await fetch('/api/wifi/defense/mfp', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        enable_pmf: true,
                        pmf_mode: pmfMode,
                        rogue_bssid: rogue,
                        isolate_rogue: isolate
                    }})
                }});
                const data = await res.json();
                if (data.status === 'protected') {{
                    resEl.innerHTML = `🛡️ [PROTECTED] 802.11w PMF 방어 완료!\n• PMF 정책: ${{data.pmf_policy}}\n• Deauth 플러딩 방어: BIP(AES-128-CMAC) 활성\n• Rogue AP 격리: ${{data.rogue_isolated ? '성공' : '실패'}}\n• 플래그: <span class="flag">${{data.flag}}</span>`;
                }} else {{
                    resEl.innerText = `⚠️ [WARNING] 방어 미완료: ${{data.detail || data.status}}\n(힌트: PMF 모드를 'required'로 설정하고 Rogue AP를 격리하세요)`;
                }}
            }} catch (e) {{
                resEl.innerText = "오류 발생: " + e.message;
            }}
        }}
    </script>
</body>
</html>"""


# ── Step 1: PMKID 오프라인 사전 공격 ──────────────────────────────────────────
@app.post("/api/wifi/pmkid/crack")
def crack_pmkid(req: PMKIDCrackRequest):
    bssid_norm = req.bssid.strip().lower()
    sta_norm = req.client_mac.strip().lower()
    pmkid_norm = req.captured_pmkid.strip().lower()
    word = req.dictionary_word.strip()

    if not word:
        raise HTTPException(status_code=400, detail="사전 단어를 입력하세요.")

    calculated = calculate_pmkid(word, TARGET_AP["ssid"], bssid_norm, sta_norm)
    if calculated.lower() == pmkid_norm and word == TARGET_AP["valid_psk"]:
        return {
            "status": "cracked",
            "ssid": TARGET_AP["ssid"],
            "bssid": bssid_norm,
            "psk": word,
            "hashcat_mode": "22000 (WPA-PBKDF2-PMKID)",
            "flag": FLAGS["step1"],
        }
    else:
        return {
            "status": "mismatch",
            "message": "사전 단어로 생성된 PMKID가 캡처된 해시와 일치하지 않습니다.",
            "tested_word": word,
            "tested_pmkid": calculated,
        }


# ── Step 2: WPA3 SAE 부채널 & 다운그레이드 공격 ────────────────────────────────
@app.post("/api/wifi/sae/attack")
def attack_sae(req: SAEAttackRequest):
    if req.target_ssid != TARGET_AP["ssid"]:
        raise HTTPException(status_code=404, detail="지정된 SSID를 찾을 수 없습니다.")

    if req.injection_frames < 50:
        return {
            "status": "insufficient_frames",
            "detail": "타이밍 부채널 통계 분석을 위해서는 최소 50개 이상의 프레임 주입이 필요합니다.",
        }

    if req.attack_vector == "transition_downgrade":
        return {
            "status": "exploited",
            "vector": "WPA3 Transition Downgrade (AP Transition Mode Exploited)",
            "downgrade_target": "WPA2-PSK 4-Way Handshake",
            "vulnerability": "RFC 7664 / IEEE 802.11ak Transition Security Fallback",
            "flag": FLAGS["step2"],
        }
    elif req.attack_vector == "dragonblood_timing_leak":
        if req.sae_group not in (19, 20):
            return {"status": "unsupported_group", "detail": "지원되지 않는 타원곡선 그룹입니다."}
        return {
            "status": "exploited",
            "vector": "Dragonblood Timing Side-Channel (CVE-2019-9494)",
            "downgrade_target": "PWE Hunting-and-Pecking Loop Leak",
            "sae_group": f"Group {req.sae_group}",
            "flag": FLAGS["step2"],
        }
    else:
        return {"status": "invalid_vector", "detail": "유효하지 않은 공격 벡터입니다."}


# ── Step 3: Evil Twin Rogue AP 탐지 및 802.11w MFP 방어 ───────────────────────
@app.post("/api/wifi/defense/mfp")
def apply_mfp_defense(req: MFPDefenseRequest):
    if not req.enable_pmf:
        return {
            "status": "pmf_disabled",
            "detail": "802.11w PMF가 비활성화되어 있어 비암호화 Deauth 공격에 취약합니다.",
        }

    if req.pmf_mode != "required":
        return {
            "status": "pmf_not_enforced",
            "detail": "PMF 모드가 'optional'로 설정되어 있어 레거시 공격자의 프레임 위조를 차단할 수 없습니다. 'required'로 설정하십시오.",
        }

    if not req.isolate_rogue or req.rogue_bssid.lower() != ROGUE_AP["bssid"].lower():
        return {
            "status": "rogue_active",
            "detail": "탐지된 Rogue AP가 격리되지 않았습니다.",
        }

    # 방어 성공
    TARGET_AP["pmf"] = "required"
    ROGUE_AP["isolated"] = True
    ROGUE_AP["evil_twin_active"] = False

    return {
        "status": "protected",
        "pmf_policy": "IEEE 802.11w-2009 Required (PMF Mandatory)",
        "cipher_suite": "BIP (Broadcast Integrity Protocol: AES-128-CMAC)",
        "rogue_isolated": True,
        "flag": FLAGS["step3"],
    }
