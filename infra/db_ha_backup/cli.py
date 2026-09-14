#!/usr/bin/env python3
"""
Enterprise Database HA & Multi-Tier Backup Manager CLI
Controls:
  - HA Cluster status, transactions, failover
  - 3-2-1-1-0 Backup snapshots, WORM enforcement, PITR
  - Automated Disaster Recovery Verification Guard
"""

import os
import sys
import argparse
import json
import time

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.cluster import HACluster
from engine.backup import BackupTierManager
from engine.verifier import BackupVerifier


def get_paths():
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    cluster_dir = os.path.join(base_dir, "cluster")
    storage_dir = os.path.join(base_dir, "storage")
    sandbox_dir = os.path.join(base_dir, "sandbox")
    return cluster_dir, storage_dir, sandbox_dir


def cmd_status(args):
    cluster_dir, storage_dir, _ = get_paths()
    cluster = HACluster(cluster_dir)
    health = cluster.get_cluster_health()
    print("\n[📊 HA Cluster Status]")
    print(json.dumps(health, indent=2, ensure_ascii=False))


def cmd_write(args):
    cluster_dir, storage_dir, _ = get_paths()
    cluster = HACluster(cluster_dir)
    bm = BackupTierManager(storage_dir)

    result = cluster.write_transaction(args.type, args.payload)
    print(f"[+] Transaction committed to primary ({result['primary']}): LSN {result['lsn']}")
    
    # Continuous WAL archive
    wal_path = bm.archive_wal_segment(result['lsn'], {
        "tx_type": args.type,
        "payload": args.payload,
        "timestamp": time.time()
    })
    print(f"[+] Archived WAL to: {wal_path}")


def cmd_read(args):
    cluster_dir, _, _ = get_paths()
    cluster = HACluster(cluster_dir)
    res = cluster.read_query()
    print(f"\n[📖 Read from Standby/Node: {res['node_served']} (LSN: {res['lsn']})]")
    for row in res["data"]:
        print(f"  - LSN {row[1]} | {row[2]} | {row[3]} | {row[4]}")


def cmd_failover(args):
    cluster_dir, _, _ = get_paths()
    cluster = HACluster(cluster_dir)
    print(f"[*] Simulating primary node failure on current leader: {cluster.current_leader}...")
    res = cluster.simulate_primary_failure()
    print("\n[⚡ Failover Result]")
    print(json.dumps(res, indent=2, ensure_ascii=False))


def cmd_backup(args):
    cluster_dir, storage_dir, _ = get_paths()
    cluster = HACluster(cluster_dir)
    bm = BackupTierManager(storage_dir)

    leader_node = cluster.nodes[cluster.current_leader]
    print(f"[*] Creating multi-tier snapshot from leader {leader_node.node_id} ({leader_node.db_path})...")
    manifest = bm.create_full_snapshot(leader_node.db_path)
    print("\n[💾 3-2-1-1-0 Backup Created]")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


def cmd_verify(args):
    cluster_dir, storage_dir, sandbox_dir = get_paths()
    bm = BackupTierManager(storage_dir)
    verifier = BackupVerifier(bm, sandbox_dir)

    backup_id = args.backup_id
    if not backup_id:
        manifest_files = sorted([f for f in os.listdir(bm.hot_dir) if f.endswith("_manifest.json")])
        if not manifest_files:
            print("[-] No backups found to verify.")
            return
        backup_id = manifest_files[-1].replace("_manifest.json", "")

    print(f"[*] Running automated sandbox verification for backup: {backup_id}...")
    report = verifier.run_full_verification(backup_id)
    print("\n[🛡️ Automated DR Verification Report]")
    print(json.dumps(report, indent=2, ensure_ascii=False))


def cmd_pitr(args):
    _, storage_dir, sandbox_dir = get_paths()
    bm = BackupTierManager(storage_dir)
    target_time = args.timestamp or time.time()
    dest_path = os.path.join(sandbox_dir, f"pitr_recovered_{int(target_time)}.db")

    print(f"[*] Restoring database to point-in-time: {target_time}...")
    res = bm.restore_pitr(target_time, dest_path)
    print("\n[⏱️ Point-in-Time Recovery Result]")
    print(json.dumps(res, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Enterprise DB HA & Backup Redundancy CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Check cluster health and nodes")

    # write
    p_write = subparsers.add_parser("write", help="Execute a write transaction")
    p_write.add_argument("--type", default="ORDER_PAYMENT", help="Transaction type")
    p_write.add_argument("--payload", default="User: Alice, Amount: $500", help="Transaction payload")

    # read
    subparsers.add_parser("read", help="Execute read query via standby replica")

    # failover
    subparsers.add_parser("failover", help="Simulate primary failure and trigger failover")

    # backup
    subparsers.add_parser("backup", help="Create full snapshot across Hot, Warm, WORM tiers")

    # verify
    p_verify = subparsers.add_parser("verify", help="Run automated sandbox restore verification")
    p_verify.add_argument("--backup-id", default=None, help="Target backup ID")

    # pitr
    p_pitr = subparsers.add_parser("pitr", help="Perform Point-in-Time Recovery")
    p_pitr.add_argument("--timestamp", type=float, default=None, help="Epoch timestamp for recovery target")

    args = parser.parse_args()
    cmds = {
        "status": cmd_status,
        "write": cmd_write,
        "read": cmd_read,
        "failover": cmd_failover,
        "backup": cmd_backup,
        "verify": cmd_verify,
        "pitr": cmd_pitr
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
