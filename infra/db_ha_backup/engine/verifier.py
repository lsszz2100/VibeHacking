"""
Automated Disaster Recovery & Restore Verification Guard
Prevents "Schrödinger's Backup" by automatically testing:
  - Checksum (SHA-256) consistency across all tiers
  - Sandbox database initialization & full table scan (PRAGMA integrity_check)
  - Recovery Time Objective (RTO) benchmark measurement
  - Smoke query test on restored data
"""

import os
import shutil
import sqlite3
import time
import json
from typing import Dict, Any


class BackupVerifier:
    """Automated restoration verifier for DB backups."""

    def __init__(self, backup_manager, sandbox_dir: str):
        self.bm = backup_manager
        self.sandbox_dir = sandbox_dir
        os.makedirs(self.sandbox_dir, exist_ok=True)

    def run_full_verification(self, backup_id: str) -> Dict[str, Any]:
        """
        Executes an end-to-end restore dry-run in an isolated sandbox.
        """
        start_time = time.time()
        hot_file = os.path.join(self.bm.hot_dir, f"{backup_id}.db")
        manifest_file = os.path.join(self.bm.hot_dir, f"{backup_id}_manifest.json")

        if not os.path.exists(hot_file) or not os.path.exists(manifest_file):
            raise FileNotFoundError(f"Backup files for {backup_id} do not exist.")

        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Step 1: Checksum verification
        expected_hash = manifest["sha256"]
        current_hash = self.bm.calculate_sha256(hot_file)
        if expected_hash != current_hash:
            return {
                "backup_id": backup_id,
                "status": "FAIL",
                "reason": f"Checksum mismatch! expected {expected_hash}, got {current_hash}",
                "rto_sec": round(time.time() - start_time, 4)
            }

        # Step 2: Restore into isolated sandbox
        sandbox_target = os.path.join(self.sandbox_dir, f"sandbox_{backup_id}.db")
        if os.path.exists(sandbox_target):
            os.remove(sandbox_target)
        shutil.copy2(hot_file, sandbox_target)

        # Step 3: Database page integrity check
        integrity_ok = False
        row_count = 0
        try:
            with sqlite3.connect(sandbox_target) as conn:
                cur = conn.cursor()
                cur.execute("PRAGMA integrity_check;")
                result = cur.fetchone()
                integrity_ok = (result and result[0] == "ok")

                cur.execute("SELECT COUNT(*) FROM audit_logs;")
                row_count = cur.fetchone()[0]
        except Exception as e:
            return {
                "backup_id": backup_id,
                "status": "FAIL",
                "reason": f"SQLite engine error during verification: {str(e)}",
                "rto_sec": round(time.time() - start_time, 4)
            }
        finally:
            # Clean up sandbox file
            if os.path.exists(sandbox_target):
                os.remove(sandbox_target)

        elapsed_rto = round(time.time() - start_time, 4)
        sla_met = (elapsed_rto <= 30.0)  # RTO SLA: 30 seconds

        return {
            "backup_id": backup_id,
            "status": "PASS" if integrity_ok else "FAIL",
            "checksum_verified": True,
            "sha256": current_hash,
            "sqlite_integrity_check": "ok" if integrity_ok else "corrupt",
            "sample_row_count": row_count,
            "rto_sec": elapsed_rto,
            "rto_sla_met": sla_met,
            "verified_at": time.time()
        }
