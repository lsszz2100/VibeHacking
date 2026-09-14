"""
End-to-End Automated Test Suite for DB HA & Backup Redundancy
Validates 1, 2, 3 core architecture pillars:
  1. HA Cluster (Quorum, Sync Replication, Split-brain prevention, Failover)
  2. Multi-tier Backup (3-2-1-1-0, WORM lock, Continuous WAL, PITR)
  3. Automated Restoration Verification Guard & Mutation Testing
"""

import os
import sys
import shutil
import tempfile
import time
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.cluster import HACluster
from engine.backup import BackupTierManager
from engine.verifier import BackupVerifier


class TestDBHABackupSuite(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_db_ha_")
        self.cluster_dir = os.path.join(self.test_dir, "cluster")
        self.storage_dir = os.path.join(self.test_dir, "storage")
        self.sandbox_dir = os.path.join(self.test_dir, "sandbox")

        self.cluster = HACluster(self.cluster_dir)
        self.bm = BackupTierManager(self.storage_dir)
        self.verifier = BackupVerifier(self.bm, self.sandbox_dir)

    def tearDown(self):
        # Reset permissions on WORM files before cleanup
        worm_dir = self.bm.worm_cold_dir
        if os.path.exists(worm_dir):
            for f in os.listdir(worm_dir):
                fp = os.path.join(worm_dir, f)
                try:
                    os.chmod(fp, 0o777)
                except Exception:
                    pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. DB 고가용성 (HA) 및 자동 페일오버 검증
    # -------------------------------------------------------------------------
    def test_01_ha_sync_replication_and_failover(self):
        # 1-1. Initial Leader & Write
        self.assertEqual(self.cluster.current_leader, "node1")
        res1 = self.cluster.write_transaction("USER_SIGNUP", "user_id=101")
        self.assertEqual(res1["status"], "COMMITTED")
        self.assertEqual(res1["lsn"], 1)

        # Verify Sync replication to node2
        node2 = self.cluster.nodes["node2"]
        self.assertEqual(node2.current_lsn, 1)

        # 1-2. Read routing to Standby
        read_res = self.cluster.read_query()
        self.assertIn(read_res["node_served"], ["node2", "node3"])
        self.assertGreaterEqual(len(read_res["data"]), 1)

        # 1-3. Simulate Primary failure (Failover)
        failover = self.cluster.simulate_primary_failure()
        self.assertEqual(failover["status"], "FAILOVER_SUCCESS")
        self.assertEqual(failover["old_primary"], "node1")
        self.assertEqual(failover["new_primary"], "node2")
        self.assertEqual(self.cluster.current_leader, "node2")

        # 1-4. Writes must continue on new primary
        res2 = self.cluster.write_transaction("TRANSFER", "from=101 to=102 amt=50")
        self.assertEqual(res2["status"], "COMMITTED")
        self.assertEqual(res2["primary"], "node2")
        self.assertEqual(res2["lsn"], 2)

        # 1-5. Quorum failure & Split-Brain prevention
        # Kill node3 -> now only node2 is alive (1/3 < quorum 2)
        self.cluster.nodes["node3"].is_alive = False
        with self.assertRaises(RuntimeError) as ctx:
            self.cluster.write_transaction("FAIL_TX", "should reject")
        self.assertIn("Quorum lost", str(ctx.exception))

        # 1-6. Node recovery & Catch-up sync
        self.cluster.nodes["node3"].is_alive = True
        self.cluster.recover_node("node1")
        self.assertTrue(self.cluster.nodes["node1"].is_alive)
        self.assertEqual(self.cluster.nodes["node1"].role, "standby")
        self.assertEqual(self.cluster.nodes["node1"].current_lsn, 2)

    # -------------------------------------------------------------------------
    # 2. 다계층 백업 (3-2-1-1-0) 및 PITR 시점 복구 검증
    # -------------------------------------------------------------------------
    def test_02_backup_tiers_and_pitr(self):
        # Generate transactions with timestamps
        t0 = time.time()
        self.cluster.write_transaction("TX_INIT", "payload=0")
        self.bm.archive_wal_segment(1, {"tx_type": "TX_INIT", "payload": "0", "timestamp": t0})

        # Create Full Snapshot
        primary = self.cluster.nodes[self.cluster.current_leader]
        manifest = self.bm.create_full_snapshot(primary.db_path, "backup_test_01")
        self.assertEqual(manifest["backup_id"], "backup_test_01")

        # Verify 3 Tiers existence
        self.assertTrue(os.path.exists(manifest["tiers"]["hot"]))
        self.assertTrue(os.path.exists(manifest["tiers"]["warm"]))
        self.assertTrue(os.path.exists(manifest["tiers"]["worm_cold"]["path"]))

        # Verify WORM Immutability (Tamper-proof)
        self.bm.enforce_worm_deletion_block("backup_test_01")

        # Additional transactions
        time.sleep(0.01)
        t1 = time.time()
        self.cluster.write_transaction("TX_INTERMEDIATE", "payload=1")
        self.bm.archive_wal_segment(2, {"tx_type": "TX_INTERMEDIATE", "payload": "1", "timestamp": t1})

        time.sleep(0.01)
        t2 = time.time()
        self.cluster.write_transaction("CORRUPTED_TX", "unwanted_data")
        self.bm.archive_wal_segment(3, {"tx_type": "CORRUPTED_TX", "payload": "unwanted", "timestamp": t2})

        # PITR Restore to exact timestamp t1 (before corruption)
        pitr_target = os.path.join(self.sandbox_dir, "pitr_recovered.db")
        pitr_res = self.bm.restore_pitr(t1, pitr_target)
        self.assertEqual(pitr_res["status"], "PITR_RESTORE_SUCCESS")
        self.assertEqual(pitr_res["recovered_lsn"], 2)  # Should NOT include LSN 3

    # -------------------------------------------------------------------------
    # 3. 자동 복원 검증 가드 (Schrödinger's Backup Prevention) & Mutation Test
    # -------------------------------------------------------------------------
    def test_03_verification_guard_and_mutation(self):
        primary = self.cluster.nodes[self.cluster.current_leader]
        self.cluster.write_transaction("DATA_A", "record=A")
        manifest = self.bm.create_full_snapshot(primary.db_path, "backup_verify_01")

        # 3-1. Normal verification should PASS
        report = self.verifier.run_full_verification("backup_verify_01")
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["checksum_verified"])
        self.assertTrue(report["rto_sla_met"])
        self.assertLess(report["rto_sec"], 5.0)

        # 3-2. Mutation Test: Tamper with hot backup file -> must trigger FAIL
        hot_file = manifest["tiers"]["hot"]
        with open(hot_file, "ab") as f:
            f.write(b"CORRUPTION_BYTES_1234")

        tamper_report = self.verifier.run_full_verification("backup_verify_01")
        self.assertEqual(tamper_report["status"], "FAIL")
        self.assertIn("Checksum mismatch", tamper_report["reason"])


if __name__ == "__main__":
    unittest.main()
