import os
import binascii
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="DroidShield - Android Security & Frida Lab", version="1.0.0")

# Flags
FLAG_ROOT = os.getenv("LAB_FLAG_ROOT", "FLAG{dr01d_r00t_byp4ss_succ3ss_9281}")
FLAG_PINNING = os.getenv("LAB_FLAG_PINNING", "FLAG{ss1_p1nn1ng_fr1da_unp1nn3d_7143}")
FLAG_JNI = os.getenv("LAB_FLAG_JNI", "FLAG{jn1_n4t1v3_h00k_l1c3ns3_p4ss_3301}")
FLAG_C2 = os.getenv("LAB_FLAG_C2", "FLAG{c2_d30bfusc4t3d_p4ck3t_cl34r_8829}")

# C2 Obfuscation constants (XOR with 0x5A)
XOR_KEY = 0x5A
TARGET_CMD = "STOP_EXFILTRATION_OVERRIDE"
ENCRYPTED_CMD_HEX = "".join(f"{ord(c) ^ XOR_KEY:02x}" for c in TARGET_CMD)


class DeviceCheckRequest(BaseModel):
    build_tags: str = "test-keys"
    su_binary_present: bool = True
    installed_packages: List[str] = ["com.topjohnwu.magisk"]
    frida_hook_applied: bool = False


class SSLPinningRequest(BaseModel):
    server_hostname: str = "api.bankshield.internal"
    cert_sha256: str = "INVALID_PROXY_BURP_CERT_SHA256"
    frida_unpin_hook: bool = False


class NativeLicenseRequest(BaseModel):
    license_key: str = "TEST-USER-KEY"
    hook_native_return: bool = False


class C2CommandRequest(BaseModel):
    command: str


@app.get("/api/status")
def get_status():
    return {
        "lab": "Lab 19: DroidShield (Android & Frida Security)",
        "status": "ready",
        "missions": [
            {"id": 1, "name": "Bypass Root Detection", "endpoint": "/api/mission1/verify_device"},
            {"id": 2, "name": "Bypass SSL Pinning", "endpoint": "/api/mission2/verify_ssl"},
            {"id": 3, "name": "JNI Native Hooking", "endpoint": "/api/mission3/native_license"},
            {"id": 4, "name": "Deobfuscate C2 Packet", "endpoint": "/api/mission4/c2_command"},
        ],
        "c2_hint": {
            "algorithm": "XOR_SINGLE_BYTE",
            "key_hint": "0x5A",
            "obfuscated_hex": ENCRYPTED_CMD_HEX,
        },
    }


@app.post("/api/mission1/verify_device")
def verify_device(req: DeviceCheckRequest):
    """
    루팅 검증 엔드포인트:
    Frida 후킹이 적용되었거나 모든 루팅 아티팩트가 제거/스푸핑된 경우 성공
    """
    if req.frida_hook_applied:
        # Frida 스크립트로 checkRoot()가 false를 반환하도록 변조된 상태
        return {
            "status": "success",
            "message": "[Frida Hook] Device integrity check passed via dynamic hook!",
            "is_rooted": False,
            "flag": FLAG_ROOT,
        }

    # 정적 아티팩트 검사
    if req.su_binary_present or "test-keys" in req.build_tags or any("magisk" in p.lower() for p in req.installed_packages):
        return {
            "status": "blocked",
            "message": "Security Alert: Rooted environment detected! Access denied.",
            "is_rooted": True,
            "detected_triggers": {
                "su_binary": req.su_binary_present,
                "test_keys": "test-keys" in req.build_tags,
                "root_apps": req.installed_packages,
            },
        }

    # 정상 기기로 위장 통과
    return {
        "status": "success",
        "message": "Device integrity check passed.",
        "is_rooted": False,
        "flag": FLAG_ROOT,
    }


@app.post("/api/mission2/verify_ssl")
def verify_ssl(req: SSLPinningRequest):
    """
    SSL Pinning 검증 엔드포인트:
    Frida 언피닝이 적용되었거나 올바른 핀 해시를 제출한 경우 성공
    """
    EXPECTED_PIN = "sha256/a84fd3e78201bc9942a188fca9b109e230718817bc932a9e10842018247192aa"

    if req.frida_unpin_hook or req.cert_sha256 == EXPECTED_PIN:
        return {
            "status": "success",
            "message": "[Frida Hook] TrustManagerImpl / OkHttp3 Pinning bypassed!",
            "connection": "MITM_SECURE_PROXY_ESTABLISHED",
            "flag": FLAG_PINNING,
        }

    return {
        "status": "error",
        "error": "javax.net.ssl.SSLPeerUnverifiedException: Certificate pinning failure!",
        "hint": "Inject Frida universal unpinning script or hook CertificatePinner.check()",
    }


@app.post("/api/mission3/native_license")
def verify_native_license(req: NativeLicenseRequest):
    """
    JNI 네이티브 라이브러리 검증 엔드포인트:
    Frida Interceptor로 반환값을 참(1)으로 치환하거나 올바른 라이선스 키 입력 시 성공
    """
    VALID_KEY = "DROID-SEC-2026-X99"

    if req.hook_native_return:
        return {
            "status": "success",
            "message": "[Frida Hook] Native libnative-crypto.so checkLicenseKey() return replaced with 1!",
            "authorized": True,
            "flag": FLAG_JNI,
        }

    if req.license_key == VALID_KEY:
        return {
            "status": "success",
            "message": "Native license verification succeeded!",
            "authorized": True,
            "flag": FLAG_JNI,
        }

    return {
        "status": "unauthorized",
        "error": "Native checkLicenseKey returned 0 (False). Invalid license key.",
        "hint": "Use Frida Interceptor.attach() on libnative-crypto.so to replace retval with 1",
    }


@app.post("/api/mission4/c2_command")
def execute_c2_command(req: C2CommandRequest):
    """
    악성 C2 패킷 난독화 해제 엔드포인트:
    0x5A 단일 바이트 XOR로 암호화된 명령어를 복호화하여 전송하면 C2 격리 완료
    """
    if req.command.strip() == TARGET_CMD:
        return {
            "status": "success",
            "message": "C2 exfiltration command successfully overridden and terminated!",
            "c2_status": "DISARMED",
            "flag": FLAG_C2,
        }

    return {
        "status": "rejected",
        "error": "Unrecognized or invalid C2 command.",
        "hint": f"Decrypt hex string '{ENCRYPTED_CMD_HEX}' using XOR 0x5A.",
    }


@app.get("/", response_class=HTMLResponse)
def index():
    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>DroidShield — Android & Frida Security Lab</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f172a; color: #f8fafc; padding: 2rem; }}
            .container {{ max-width: 900px; margin: 0 auto; }}
            h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
            .badge {{ background: #0284c7; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; }}
            code {{ background: #0f172a; color: #4ade80; padding: 2px 6px; border-radius: 4px; }}
            button {{ background: #38bdf8; color: #0f172a; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; cursor: pointer; }}
            button:hover {{ background: #7dd3fc; }}
            pre {{ background: #0b0f19; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a5f3fc; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ DroidShield: Android & Frida Security Lab (Lab 19)</h1>
            <p>안드로이드 악성코드 분석, 루팅 탐지 우회, SSL 피닝 무력화, JNI 네이티브 후킹 실습 환경</p>
            
            <div class="card">
                <h3><span class="badge">Mission 1</span> 루팅 탐지 우회 (Root Detection Bypass)</h3>
                <p>기기의 <code>su</code> 바이너리 및 빌드 태그 체크를 Frida 훅을 통해 무력화하세요.</p>
                <pre>POST /api/mission1/verify_device</pre>
            </div>

            <div class="card">
                <h3><span class="badge">Mission 2</span> SSL Pinning 무력화 (Universal SSL Unpinning)</h3>
                <p>인증서 고정 검증을 무력화하여 MITM 패킷 감청을 허용하도록 후킹하세요.</p>
                <pre>POST /api/mission2/verify_ssl</pre>
            </div>

            <div class="card">
                <h3><span class="badge">Mission 3</span> JNI 네이티브 후킹 (Native Interceptor)</h3>
                <p>C/C++ 네이티브 모듈 <code>libnative-crypto.so</code>의 리턴값을 1로 변조하세요.</p>
                <pre>POST /api/mission3/native_license</pre>
            </div>

            <div class="card">
                <h3><span class="badge">Mission 4</span> C2 패킷 난독화 해제 (Deobfuscate C2 Command)</h3>
                <p>암호화된 16진수 문자열 <code>{ENCRYPTED_CMD_HEX}</code>을 단일 바이트 XOR(0x5A)로 복호화하여 명령을 전송하세요.</p>
                <pre>POST /api/mission4/c2_command</pre>
            </div>
        </div>
    </body>
    </html>
    """
