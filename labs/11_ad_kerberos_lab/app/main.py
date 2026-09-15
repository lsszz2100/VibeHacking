#!/usr/bin/env python3
"""Lab 11: Active Directory & Kerberos Security Hands-on Lab (KeroShield).

Provides an interactive simulation of an Active Directory Domain Controller (CORP.LOCAL)
and Kerberos KDC, covering the classic 4-stage AD compromise kill chain:
1. AS-REP Roasting (No Pre-Authentication)
2. Kerberoasting (Service Principal Name TGS Extraction)
3. DCSync (Directory Replication Service Remote Protocol Exploit)
4. Golden Ticket Attack (Forged Master TGT Domain Domination)
"""

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="KeroShield - Active Directory & Kerberos Security Lab")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Domain Configuration
DOMAIN_NAME = "CORP.LOCAL"
DOMAIN_NETBIOS = "CORP"
DOMAIN_SID = "S-1-5-21-382947192-284918239-192837482"
DC_HOSTNAME = "DC01.CORP.LOCAL"
DC_IP = "10.10.10.2"

# Flags
FLAGS = {
    "stage1": "FLAG{ASREP_R04ST_PREAUTH_BYPASS_8201}",
    "stage2": "FLAG{KERBER04ST_SPN_TGS_EXTRACT_4918}",
    "stage3": "FLAG{DCSYNC_DRSR_KRBTGT_SYNC_7193}",
    "stage4": "FLAG{GOLDEN_TICKET_FOREST_OWNED_9934}",
}

# Active Directory Simulated Database
ACCOUNTS_DB: Dict[str, Dict[str, Any]] = {
    "administrator": {
        "sAMAccountName": "Administrator",
        "rid": 500,
        "objectSid": f"{DOMAIN_SID}-500",
        "memberOf": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
        "userAccountControl": 512,  # NORMAL_ACCOUNT
        "preauth_required": True,
        "spn": None,
        "password": "E1t3AdM!nP@ssw0rd#2026",
        "ntlm": "e52cac67419a9a22ecb51412ee8770d1",
        "description": "Built-in account for administering the domain",
    },
    "krbtgt": {
        "sAMAccountName": "krbtgt",
        "rid": 502,
        "objectSid": f"{DOMAIN_SID}-502",
        "memberOf": ["Denied RODC Password Replication Group"],
        "userAccountControl": 514,  # ACCOUNTDISABLE
        "preauth_required": True,
        "spn": f"kadmin/changepw",
        "password": "MasterKdcSecretKey#991471829",
        "ntlm": "b2849e728491a9284f91823901bca928",
        "description": "Key Distribution Center Service Account",
    },
    "guest": {
        "sAMAccountName": "Guest",
        "rid": 501,
        "objectSid": f"{DOMAIN_SID}-501",
        "memberOf": ["Domain Guests"],
        "userAccountControl": 514,
        "preauth_required": True,
        "spn": None,
        "password": "",
        "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0",
        "description": "Built-in account for guest access to the domain",
    },
    "j.smith": {
        "sAMAccountName": "j.smith",
        "displayName": "John Smith",
        "rid": 1104,
        "objectSid": f"{DOMAIN_SID}-1104",
        "memberOf": ["Domain Users", "HelpDesk"],
        "userAccountControl": 4194816,  # NORMAL_ACCOUNT | DONT_REQ_PREAUTH (0x400000)
        "preauth_required": False,  # VULNERABLE TO AS-REP ROASTING
        "spn": None,
        "password": "Summer2025!",
        "ntlm": "cc8d76a7e0e7a46f7f2b1897d1b32e4d",
        "description": "Tier 1 Helpdesk Specialist (Pre-auth disabled for legacy client testing)",
    },
    "mssql_svc": {
        "sAMAccountName": "mssql_svc",
        "displayName": "Database Service Engine",
        "rid": 1105,
        "objectSid": f"{DOMAIN_SID}-1105",
        "memberOf": ["Domain Users"],
        "userAccountControl": 512,
        "preauth_required": True,
        "spn": "MSSQLSvc/db01.corp.local:1433",  # VULNERABLE TO KERBEROASTING
        "password": "Password123!",
        "ntlm": "8846f7eaee8fb117ad06bdd830b7586c",
        "description": "Dedicated service account running MS SQL Production cluster",
    },
    "backup_svc": {
        "sAMAccountName": "backup_svc",
        "displayName": "Enterprise Backup Operator",
        "rid": 1106,
        "objectSid": f"{DOMAIN_SID}-1106",
        "memberOf": ["Domain Users", "Backup Operators"],
        "userAccountControl": 512,
        "preauth_required": True,
        "spn": None,
        "acl_rights": ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"],  # VULNERABLE TO DCSYNC
        "password": "BackupOperator2026!",
        "ntlm": "5d41402abc4b2a76b9719d911017c592",
        "description": "Automated snapshot backup account with replication sync rights",
    },
}

# Audit Log Event Store
AUDIT_LOGS: List[Dict[str, Any]] = []


def record_audit_event(event_id: int, event_type: str, user: str, client_ip: str, details: str) -> None:
    AUDIT_LOGS.insert(
        0,
        {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "eventId": event_id,
            "type": event_type,
            "user": user,
            "clientIp": client_ip,
            "details": details,
        },
    )
    if len(AUDIT_LOGS) > 100:
        AUDIT_LOGS.pop()


# Models
class AsReqPayload(BaseModel):
    username: str
    domain: Optional[str] = DOMAIN_NAME
    enc_type: Optional[str] = "rc4-hmac"  # e-type 23


class TgsReqPayload(BaseModel):
    tgt_token: str
    spn: str


class CrackSubmitPayload(BaseModel):
    stage: str
    cracked_password: str


class DcSyncPayload(BaseModel):
    username: str
    password_or_hash: str
    target_user: Optional[str] = "krbtgt"


class GoldenTicketPayload(BaseModel):
    domain: str
    domain_sid: str
    krbtgt_hash: str
    user_to_impersonate: str
    group_rid: Optional[int] = 512  # Domain Admins


class CommandExecPayload(BaseModel):
    command: str


class FlagSubmitPayload(BaseModel):
    flag: str


# --- Core Kerberos & AD Logic Endpoints ---


@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Renders the main interactive KeroShield console interface."""
    index_html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_html_path):
        with open(index_html_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>KeroShield Lab Loaded. Static files missing.</h1>")


@app.get("/api/health")
async def api_health():
    return {
        "status": "online",
        "service": "Active Directory Domain Services & KDC",
        "domain": DOMAIN_NAME,
        "dc": DC_HOSTNAME,
        "dc_ip": DC_IP,
        "domain_sid": DOMAIN_SID,
        "timestamp": time.time(),
    }


@app.get("/api/ad/objects")
async def get_ad_objects():
    """Enumerates directory objects visible to any domain user (simulating LDAP recon)."""
    public_users = []
    for uname, data in ACCOUNTS_DB.items():
        public_users.append(
            {
                "sAMAccountName": data["sAMAccountName"],
                "displayName": data.get("displayName", data["sAMAccountName"]),
                "rid": data["rid"],
                "objectSid": data["objectSid"],
                "memberOf": data["memberOf"],
                "dont_req_preauth": not data["preauth_required"],
                "spn": data.get("spn"),
                "description": data["description"],
                "has_replication_rights": "acl_rights" in data,
            }
        )
    return {
        "domain": DOMAIN_NAME,
        "domain_sid": DOMAIN_SID,
        "dc": DC_HOSTNAME,
        "forest_level": "Windows Server 2022",
        "accounts": public_users,
    }


@app.post("/api/kerberos/as_req")
async def kerberos_as_req(payload: AsReqPayload, request: Request):
    """Handles Kerberos AS-REQ authentication request (AS-REP Roasting vulnerable endpoint)."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    uname_key = payload.username.strip().lower()

    if uname_key not in ACCOUNTS_DB:
        record_audit_event(4768, "AS-REQ-FAILED", payload.username, client_ip, "Account not found (KDC_ERR_C_PRINCIPAL_UNKNOWN)")
        raise HTTPException(status_code=404, detail=f"User {payload.username} not found in KDC directory.")

    account = ACCOUNTS_DB[uname_key]

    if account["preauth_required"]:
        record_audit_event(4768, "AS-REQ-PREAUTH-REQUIRED", account["sAMAccountName"], client_ip, "Pre-authentication required (KDC_ERR_PREAUTH_REQUIRED)")
        return JSONResponse(
            status_code=401,
            content={
                "error": "KDC_ERR_PREAUTH_REQUIRED",
                "message": f"Pre-authentication required for {account['sAMAccountName']}. PA-ENC-TIMESTAMP must be provided.",
                "vulnerable": False,
            },
        )

    # Vulnerable to AS-REP Roasting! Generate John/Hashcat compatible AS-REP hash
    record_audit_event(4768, "AS-REQ-PREAUTH-BYPASSED", account["sAMAccountName"], client_ip, "AS-REP issued without pre-auth (Event 4768: Audit Success, DONT_REQ_PREAUTH)")

    user_ntlm = account["ntlm"]
    salt = f"{DOMAIN_NAME.upper()}{account['sAMAccountName']}".encode("utf-8")
    pseudo_cipher = hashlib.md5((account["password"] + DOMAIN_NAME).encode("utf-8")).hexdigest()
    asrep_hash = (
        f"$krb5asrep$23${account['sAMAccountName']}@{DOMAIN_NAME}:"
        f"{user_ntlm[:16]}${pseudo_cipher * 4}"
    )

    # Issue a simulated TGT for the user
    tgt_blob = base64.b64encode(
        json.dumps(
            {
                "user": account["sAMAccountName"],
                "domain": DOMAIN_NAME,
                "issued_at": time.time(),
                "expiry": time.time() + 36000,
                "client_ip": client_ip,
                "pac": {"rid": account["rid"], "groups": account["memberOf"]},
            }
        ).encode("utf-8")
    ).decode("utf-8")

    return {
        "status": "success",
        "message": f"Kerberos AS-REP issued successfully for {account['sAMAccountName']}.",
        "username": account["sAMAccountName"],
        "domain": DOMAIN_NAME,
        "enc_type": "rc4-hmac (0x17)",
        "hashcat_mode": 18200,
        "asrep_hash": asrep_hash,
        "tgt_token": tgt_blob,
        "hint": "Crack this hash with Hashcat mode 18200 or John the Ripper to recover the user's plaintext password.",
        "stage": "stage1",
    }


@app.post("/api/kerberos/tgs_req")
async def kerberos_tgs_req(payload: TgsReqPayload, request: Request):
    """Handles Kerberos TGS-REQ ticket granting request (Kerberoasting vulnerable endpoint)."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Validate TGT
    try:
        tgt_data = json.loads(base64.b64decode(payload.tgt_token.encode("utf-8")).decode("utf-8"))
    except Exception:
        record_audit_event(4769, "TGS-REQ-FAILED", "UNKNOWN", client_ip, "Invalid or malformed TGT presented")
        raise HTTPException(status_code=400, detail="Invalid TGT token provided.")

    requester_user = tgt_data.get("user")
    spn_input = payload.spn.strip()

    # Locate account matching SPN
    target_account = None
    for acc in ACCOUNTS_DB.values():
        if acc.get("spn") and acc["spn"].lower() == spn_input.lower():
            target_account = acc
            break

    if not target_account:
        record_audit_event(4769, "TGS-REQ-FAILED", requester_user, client_ip, f"SPN '{spn_input}' not registered in domain")
        raise HTTPException(status_code=404, detail=f"SPN '{spn_input}' does not map to any active domain service account.")

    # Generate Kerberoastable TGS ticket hash
    record_audit_event(
        4769,
        "TGS-REQ-SERVICE-TICKET",
        requester_user,
        client_ip,
        f"Kerberos service ticket requested for SPN '{spn_input}' with rc4-hmac encryption (Event 4769)",
    )

    tgs_checksum = hashlib.sha1((target_account["password"] + spn_input).encode("utf-8")).hexdigest()[:32]
    tgs_cipher = hashlib.sha256((target_account["ntlm"] + spn_input).encode("utf-8")).hexdigest()

    # Hashcat mode 13100 / John format
    tgs_hash = (
        f"$krb5tgs$23$*{target_account['sAMAccountName']}*{DOMAIN_NAME}*"
        f"{spn_input}*${tgs_checksum}${tgs_cipher}"
    )

    return {
        "status": "success",
        "message": f"Kerberos TGS ticket granted for service {spn_input}.",
        "service_account": target_account["sAMAccountName"],
        "spn": spn_input,
        "enc_type": "rc4-hmac (0x17)",
        "hashcat_mode": 13100,
        "tgs_hash": tgs_hash,
        "hint": "Crack this TGS hash to recover the password of the SQL service account.",
        "stage": "stage2",
    }


@app.post("/api/ad/dcsync")
async def ad_dcsync(payload: DcSyncPayload, request: Request):
    """Simulates DCSync attack via MS-DRSR Directory Replication GetNCChanges."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    uname_key = payload.username.strip().lower()

    if uname_key not in ACCOUNTS_DB:
        record_audit_event(4662, "DCSYNC-ACCESS-DENIED", payload.username, client_ip, "Authentication failed: user unknown")
        raise HTTPException(status_code=401, detail="Authentication failed: invalid username.")

    account = ACCOUNTS_DB[uname_key]
    cred = payload.password_or_hash.strip()

    if cred != account["password"] and cred.lower() != account["ntlm"].lower():
        record_audit_event(4662, "DCSYNC-ACCESS-DENIED", account["sAMAccountName"], client_ip, "Authentication failed: bad password or NTLM hash")
        raise HTTPException(status_code=401, detail="Authentication failed: bad credentials.")

    # Check Replication ACL
    acl_rights = account.get("acl_rights", [])
    has_full_sync = "DS-Replication-Get-Changes-All" in acl_rights and "DS-Replication-Get-Changes" in acl_rights
    is_domain_admin = "Domain Admins" in account.get("memberOf", [])

    if not (has_full_sync or is_domain_admin):
        record_audit_event(
            4662,
            "DCSYNC-PERMISSION-DENIED",
            account["sAMAccountName"],
            client_ip,
            "Replication access denied (Access mask 0x100: DS-Replication-Get-Changes-All missing)",
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Account '{account['sAMAccountName']}' lacks DS-Replication-Get-Changes-All permissions on {DOMAIN_NAME}.",
        )

    # DCSync SUCCESS
    record_audit_event(
        4662,
        "DCSYNC-REPLICATION-DETECTED",
        account["sAMAccountName"],
        client_ip,
        f"CRITICAL: Non-DC machine {client_ip} invoked DsGetNCChanges replication sync on {payload.target_user}",
    )

    target_uname = payload.target_user.strip().lower()
    results = {}
    if target_uname in ACCOUNTS_DB:
        target_acc = ACCOUNTS_DB[target_uname]
        results[target_acc["sAMAccountName"]] = {
            "rid": target_acc["rid"],
            "sid": target_acc["objectSid"],
            "ntlm": target_acc["ntlm"],
            "password": target_acc["password"],
        }
    else:
        # Dump all if target_user == "all"
        for acc in ACCOUNTS_DB.values():
            results[acc["sAMAccountName"]] = {
                "rid": acc["rid"],
                "sid": acc["objectSid"],
                "ntlm": acc["ntlm"],
            }

    return {
        "status": "success",
        "message": "DCSync replication synchronization completed successfully.",
        "replicated_by": account["sAMAccountName"],
        "domain_controller": DC_HOSTNAME,
        "domain_sid": DOMAIN_SID,
        "hashes": results,
        "stage": "stage3",
        "flag": FLAGS["stage3"],
    }


@app.post("/api/kerberos/golden_ticket")
async def kerberos_golden_ticket(payload: GoldenTicketPayload, request: Request):
    """Validates parameters for forging a Golden Ticket (krbtgt NTLM hash + domain SID)."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    if payload.domain.upper() != DOMAIN_NAME.upper():
        raise HTTPException(status_code=400, detail=f"Domain mismatch. Expected {DOMAIN_NAME}")

    if payload.domain_sid.strip() != DOMAIN_SID:
        raise HTTPException(status_code=400, detail=f"Domain SID mismatch. Expected {DOMAIN_SID}")

    krbtgt_acc = ACCOUNTS_DB["krbtgt"]
    if payload.krbtgt_hash.strip().lower() != krbtgt_acc["ntlm"].lower():
        record_audit_event(4768, "GOLDEN-TICKET-FAILED", payload.user_to_impersonate, client_ip, "Forged ticket failed: invalid krbtgt key")
        raise HTTPException(status_code=401, detail="Golden Ticket forgery rejected: krbtgt NTLM hash is incorrect.")

    # Successfully forged Golden Ticket
    record_audit_event(
        4672,
        "GOLDEN-TICKET-CREATED",
        payload.user_to_impersonate,
        client_ip,
        f"Forged master TGT presented with Domain Admin RID {payload.group_rid} (Event 4672: Special privileges assigned)",
    )

    forged_ticket = base64.b64encode(
        json.dumps(
            {
                "type": "GOLDEN_TGT",
                "impersonated_user": payload.user_to_impersonate,
                "domain": DOMAIN_NAME,
                "domain_sid": DOMAIN_SID,
                "group_rid": payload.group_rid,
                "roles": ["Domain Admins", "Enterprise Admins"],
                "validity_years": 10,
                "signed_by": "krbtgt",
            }
        ).encode("utf-8")
    ).decode("utf-8")

    return {
        "status": "success",
        "message": f"Golden Ticket for '{payload.user_to_impersonate}' forged and signed with krbtgt key successfully!",
        "golden_ticket_ccache": forged_ticket,
        "stage": "stage4",
        "flag": FLAGS["stage4"],
    }


@app.post("/api/ad/domain_admin_exec")
async def ad_domain_admin_exec(payload: CommandExecPayload, request: Request, authorization: Optional[str] = Header(None)):
    """Executes commands on Domain Controller DC01 as Domain Admin using a valid Golden Ticket."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not authorization or not authorization.startswith("Bearer "):
        record_audit_event(4625, "LOGON-FAILED", "ANONYMOUS", client_ip, "Kerberos authentication token missing")
        raise HTTPException(status_code=401, detail="Missing Kerberos authorization ticket in Bearer header.")

    token = authorization.split(" ", 1)[1].strip()
    try:
        ticket_data = json.loads(base64.b64decode(token.encode("utf-8")).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Corrupted or malformed Kerberos ticket.")

    if ticket_data.get("type") != "GOLDEN_TGT" or "Domain Admins" not in ticket_data.get("roles", []):
        record_audit_event(4625, "LOGON-FAILED", ticket_data.get("impersonated_user", "UNKNOWN"), client_ip, "Ticket lacks Domain Admin rights")
        raise HTTPException(status_code=403, detail="Access Denied: Ticket does not possess Domain Administrator privileges.")

    # Execution simulation
    cmd = payload.command.strip()
    record_audit_event(4688, "PROCESS-CREATION-ADMIN", ticket_data["impersonated_user"], client_ip, f"DC01 WMI/WinRM remote process: {cmd}")

    output = ""
    if "whoami" in cmd:
        output = f"{DOMAIN_NETBIOS}\\Administrator"
    elif "hostname" in cmd:
        output = DC_HOSTNAME
    elif "net group" in cmd:
        output = (
            f"Group name: Domain Admins\n"
            f"Comment: Designated administrators of the domain\n"
            f"Members:\n"
            f"-------------------------------------------------------------------------------\n"
            f"Administrator            backup_svc\n"
            f"The command completed successfully."
        )
    else:
        output = f"[DC01.CORP.LOCAL (SYSTEM)] Command '{cmd}' executed with Enterprise Admin token.\nStatus: 0 (STATUS_SUCCESS)"

    return {
        "status": "success",
        "domain_controller": DC_HOSTNAME,
        "executed_as": f"{DOMAIN_NETBIOS}\\{ticket_data['impersonated_user']}",
        "command": cmd,
        "output": output,
        "flag": FLAGS["stage4"],
    }


@app.post("/api/flags/submit")
async def submit_flag(payload: FlagSubmitPayload):
    """Validates challenge flags."""
    submitted = payload.flag.strip()
    for stage, flg in FLAGS.items():
        if submitted == flg:
            return {
                "correct": True,
                "stage": stage,
                "message": f"Congratulations! Correct flag for {stage.upper()}.",
            }
    return {"correct": False, "message": "Invalid flag. Check your hash cracking or exploitation steps."}


@app.post("/api/terminal/execute")
async def execute_terminal_command(payload: CommandExecPayload, request: Request):
    """Interactive command-line tool emulator for Impacket, John, Hashcat, and BloodHound."""
    cmd_raw = payload.command.strip()
    if not cmd_raw:
        return {"output": ""}

    parts = shlex.split(cmd_raw)
    tool = parts[0].lower() if parts else ""

    if tool in ["help", "?"]:
        return {
            "output": (
                "KeroShield Simulated AD Pentest Toolkit\n"
                "----------------------------------------------------\n"
                "  GetNPUsers.py        Harvest AS-REP hashes from accounts with pre-auth disabled\n"
                "  GetUserSPNs.py       Request Kerberos service tickets (TGS) for Kerberoasting\n"
                "  secretsdump.py       Perform DCSync replication to dump domain hashes\n"
                "  ticketer.py          Forge Kerberos Golden / Silver Tickets\n"
                "  psexec.py            Execute remote commands using Kerberos tickets (-k)\n"
                "  hashcat / john       Crack AS-REP ($krb5asrep$23$) and TGS ($krb5tgs$23$) hashes\n"
                "  bloodhound           View AD domain attack graph paths\n"
                "  users / spns         List active domain accounts and SPN mappings\n"
                "  audit                View Domain Controller security event logs (Events 4768, 4769, 4662)\n"
                "  flags                Check current challenge completion flags\n"
                "  clear                Clear terminal output\n"
            )
        }

    if tool == "users":
        rows = [f"{'Account':<18} {'RID':<6} {'PreAuth':<10} {'SPN':<32} {'Description'}"]
        rows.append("-" * 90)
        for d in ACCOUNTS_DB.values():
            pa = "Disabled" if not d["preauth_required"] else "Enabled"
            spn = d.get("spn") or "None"
            rows.append(f"{d['sAMAccountName']:<18} {d['rid']:<6} {pa:<10} {spn:<32} {d['description']}")
        return {"output": "\n".join(rows)}

    if tool == "spns":
        rows = [f"{'SPN':<35} {'Account':<18} {'Encryption'}"]
        rows.append("-" * 70)
        for d in ACCOUNTS_DB.values():
            if d.get("spn"):
                rows.append(f"{d['spn']:<35} {d['sAMAccountName']:<18} rc4-hmac (0x17)")
        return {"output": "\n".join(rows)}

    if tool == "audit":
        if not AUDIT_LOGS:
            return {"output": "[*] Security Event Log is empty. Perform attacks to generate telemetry."}
        lines = [f"{'Time':<20} {'EventID':<8} {'Type':<26} {'User':<18} {'Details'}"]
        lines.append("-" * 100)
        for ev in AUDIT_LOGS[:15]:
            lines.append(f"{ev['timestamp']:<20} {ev['eventId']:<8} {ev['type']:<26} {ev['user']:<18} {ev['details']}")
        return {"output": "\n".join(lines)}

    if tool == "flags":
        return {
            "output": (
                "KeroShield CTF Flags Status:\n"
                f"  Stage 1 (AS-REP Roasting): {FLAGS['stage1']}\n"
                f"  Stage 2 (Kerberoasting):   {FLAGS['stage2']}\n"
                f"  Stage 3 (DCSync):          {FLAGS['stage3']}\n"
                f"  Stage 4 (Golden Ticket):   {FLAGS['stage4']}\n"
            )
        }

    # Tool: GetNPUsers.py
    if "getnpusers" in tool:
        target_acc = ACCOUNTS_DB["j.smith"]
        hash_val = (
            f"$krb5asrep$23${target_acc['sAMAccountName']}@{DOMAIN_NAME}:"
            f"{target_acc['ntlm'][:16]}$"
            f"{hashlib.md5((target_acc['password'] + DOMAIN_NAME).encode()).hexdigest() * 4}"
        )
        record_audit_event(4768, "AS-REQ-ROAST", "j.smith", "10.10.10.100", "Impacket GetNPUsers.py AS-REP dump")
        return {
            "output": (
                f"[*] Impacket v0.11.0 - GetNPUsers.py\n"
                f"[*] Querying Domain Controller {DC_HOSTNAME} ({DC_IP})...\n"
                f"[*] Found user with DONT_REQ_PREAUTH set: j.smith\n"
                f"\n{hash_val}\n\n"
                f"[+] Extracted 1 AS-REP hash. Crack with: john --wordlist=rockyou.txt or hashcat -m 18200\n"
                f"[+] Stage 1 Completed! Flag: {FLAGS['stage1']}"
            )
        }

    # Tool: GetUserSPNs.py
    if "getuserspns" in tool:
        target_acc = ACCOUNTS_DB["mssql_svc"]
        spn = target_acc["spn"]
        tgs_checksum = hashlib.sha1((target_acc["password"] + spn).encode("utf-8")).hexdigest()[:32]
        tgs_cipher = hashlib.sha256((target_acc["ntlm"] + spn).encode("utf-8")).hexdigest()
        tgs_hash = f"$krb5tgs$23$*{target_acc['sAMAccountName']}*{DOMAIN_NAME}*{spn}*${tgs_checksum}${tgs_cipher}"
        record_audit_event(4769, "KERBEROASTING", "mssql_svc", "10.10.10.100", f"Impacket GetUserSPNs.py ticket requested for {spn}")
        return {
            "output": (
                f"[*] Impacket v0.11.0 - GetUserSPNs.py\n"
                f"[*] Authenticating as domain user j.smith...\n"
                f"[*] Requesting TGS for SPN: {spn}\n"
                f"\n{tgs_hash}\n\n"
                f"[+] Extracted TGS ticket. Crack with: john --wordlist=rockyou.txt or hashcat -m 13100\n"
                f"[+] Stage 2 Completed! Flag: {FLAGS['stage2']}"
            )
        }

    # Tool: secretsdump.py
    if "secretsdump" in tool:
        # Check credentials in command
        cmd_str = " ".join(parts)
        if "backup_svc" in cmd_str and ("backupoperator2026!" in cmd_str.lower() or "5d41402abc4b2a76b9719d911017c592" in cmd_str.lower()):
            record_audit_event(4662, "DCSYNC-SECRETSDUMP", "backup_svc", "10.10.10.100", "secretsdump.py replication dump against DC01")
            return {
                "output": (
                    f"[*] Impacket v0.11.0 - secretsdump.py (DCSync mode)\n"
                    f"[*] Connecting to DCSync endpoint on {DC_HOSTNAME} via MS-DRSR...\n"
                    f"[*] User backup_svc possesses DS-Replication-Get-Changes-All permissions!\n"
                    f"[*] Dumping domain credentials from Active Directory database (NTDS.DIT):\n\n"
                    f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['administrator']['ntlm']}:::\n"
                    f"Guest:501:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['guest']['ntlm']}:::\n"
                    f"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['krbtgt']['ntlm']}:::\n"
                    f"j.smith:1104:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['j.smith']['ntlm']}:::\n"
                    f"mssql_svc:1105:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['mssql_svc']['ntlm']}:::\n"
                    f"backup_svc:1106:aad3b435b51404eeaad3b435b51404ee:{ACCOUNTS_DB['backup_svc']['ntlm']}:::\n\n"
                    f"[+] Successfully extracted krbtgt NTLM hash!\n"
                    f"[+] Stage 3 Completed! Flag: {FLAGS['stage3']}"
                )
            }
        else:
            return {
                "output": (
                    f"[-] secretsdump.py error: Missing or invalid credentials.\n"
                    f"Usage: secretsdump.py -just-dc-ntlm corp.local/backup_svc:BackupOperator2026!@10.10.10.2"
                )
            }

    # Tool: ticketer.py
    if "ticketer" in tool:
        cmd_str = " ".join(parts)
        krbtgt_hash = ACCOUNTS_DB["krbtgt"]["ntlm"]
        if krbtgt_hash in cmd_str.lower() and DOMAIN_SID in cmd_str:
            record_audit_event(4672, "TICKETER-GOLDEN-TICKET", "Administrator", "10.10.10.100", "Forged TGT generated with stolen krbtgt NTLM hash")
            return {
                "output": (
                    f"[*] Impacket v0.11.0 - ticketer.py\n"
                    f"[*] Creating Golden Ticket for user 'Administrator'...\n"
                    f"[*] Domain: {DOMAIN_NAME} | SID: {DOMAIN_SID}\n"
                    f"[*] PAC Membership: RID 512 (Domain Admins), RID 519 (Enterprise Admins)\n"
                    f"[*] Encrypting Ticket with krbtgt key: {krbtgt_hash}\n"
                    f"[+] Saved Ticket in administrator.ccache\n\n"
                    f"[+] You now hold full Forest & Domain Compromise!\n"
                    f"[+] Stage 4 Completed! Flag: {FLAGS['stage4']}"
                )
            }
        else:
            return {
                "output": (
                    f"[-] ticketer.py error: Missing valid -nthash <krbtgt_hash> or -domain-sid <sid>\n"
                    f"Usage: ticketer.py -nthash {krbtgt_hash} -domain-sid {DOMAIN_SID} -domain {DOMAIN_NAME} -user Administrator admin.ccache"
                )
            }

    # Tool: psexec.py / wmiexec.py
    if "psexec" in tool or "wmiexec" in tool:
        record_audit_event(4688, "PSEXEC-EXECUTION", "Administrator", "10.10.10.100", "Remote execution on DC01 as Domain Admin")
        return {
            "output": (
                f"[*] Impacket v0.11.0 - psexec.py\n"
                f"[*] Authenticating with Kerberos ticket to {DC_HOSTNAME}...\n"
                f"[+] Granted SYSTEM privileges on Domain Controller!\n"
                f"C:\\Windows\\system32> whoami\n"
                f"CORP\\Administrator\n"
                f"C:\\Windows\\system32> hostname\n"
                f"{DC_HOSTNAME}\n"
                f"[+] Full Active Directory Forest Takeover Complete!\n"
                f"[+] Master Flag: {FLAGS['stage4']}"
            )
        }

    # Tool: john / hashcat
    if tool in ["john", "hashcat"]:
        cmd_str = " ".join(parts).lower()
        if "asrep" in cmd_str or "18200" in cmd_str:
            return {
                "output": (
                    f"Loaded 1 password hash ($krb5asrep$23$)...\n"
                    f"Cracking with dictionary wordlist (rockyou.txt)...\n"
                    f"Session completed. Status: Cracked!\n"
                    f"\n"
                    f"  j.smith@CORP.LOCAL : Summer2025!\n"
                    f"\n"
                    f"[+] Plaintext password found: Summer2025!\n"
                    f"[+] Flag 1: {FLAGS['stage1']}"
                )
            }
        elif "tgs" in cmd_str or "13100" in cmd_str:
            return {
                "output": (
                    f"Loaded 1 password hash ($krb5tgs$23$)...\n"
                    f"Cracking with dictionary wordlist (rockyou.txt)...\n"
                    f"Session completed. Status: Cracked!\n"
                    f"\n"
                    f"  mssql_svc : Password123!\n"
                    f"\n"
                    f"[+] Plaintext service password found: Password123!\n"
                    f"[+] Flag 2: {FLAGS['stage2']}"
                )
            }
        else:
            return {"output": f"[*] {tool}: specify target hash (asrep.hash or tgs.hash) with wordlist."}

    # BloodHound
    if "bloodhound" in tool:
        return {
            "output": (
                f"[*] BloodHound 4.3 Analysis (CORP.LOCAL Attack Graph):\n"
                f"----------------------------------------------------\n"
                f"1. [Owned] j.smith (Domain User)\n"
                f"   │ (Can Request SPN)\n"
                f"   ▼\n"
                f"2. mssql_svc (SPN: MSSQLSvc/db01.corp.local:1433)\n"
                f"   │ (Shares lateral credentials)\n"
                f"   ▼\n"
                f"3. backup_svc (Has: DS-Replication-Get-Changes-All on CORP.LOCAL)\n"
                f"   │ (DCSync Attack)\n"
                f"   ▼\n"
                f"4. krbtgt NTLM Hash Dumped\n"
                f"   │ (Golden Ticket Forgery: RID 512)\n"
                f"   ▼\n"
                f"5. [HIGH VALUE TARGET] DC01.CORP.LOCAL\\Administrator (DOMINATION)"
            )
        }

    return {"output": f"bash: {tool}: command not found. Type 'help' for available tools."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8011)
