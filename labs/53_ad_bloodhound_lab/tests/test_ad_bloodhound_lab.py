#!/usr/bin/env python3
"""Tests for Lab 53: ADGraphMaster — Active Directory BloodHound Attack Graph & ACL Exploitation Lab."""

import sys
import importlib.util
from pathlib import Path
import pytest
from starlette.testclient import TestClient

APP_PATH = Path(__file__).resolve().parent.parent / "app" / "main.py"
spec = importlib.util.spec_from_file_location("lab53_app", str(APP_PATH))
lab53_module = importlib.util.module_from_spec(spec)
sys.modules["lab53_app"] = lab53_module
spec.loader.exec_module(lab53_module)

app = lab53_module.app
state = lab53_module.state
STAGE1_FLAG = lab53_module.STAGE1_FLAG
STAGE2_FLAG = lab53_module.STAGE2_FLAG
STAGE3_FLAG = lab53_module.STAGE3_FLAG
STAGE4_FLAG = lab53_module.STAGE4_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    client.post("/api/reset")
    yield
    client.post("/api/reset")


def test_index_and_status():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ADGraphMaster" in resp.text

    status_resp = client.get("/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["lab"] == "53_ad_bloodhound_lab"
    assert data["port"] == 8053
    assert data["stages"]["stage1_domain_ingestion"] is False


def test_stage1_ingestion():
    # Invalid tool
    bad_tool = client.post("/api/stage1/ingest", json={
        "collector_tool": "malicious_tool",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })
    assert bad_tool.status_code == 400

    # Invalid domain
    bad_domain = client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "fake.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })
    assert bad_domain.status_code == 400

    # Missing essential schemas
    missing_schemas = client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users"]
    })
    assert missing_schemas.status_code == 400

    # Valid ingestion
    valid_resp = client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls", "sessions"]
    })
    assert valid_resp.status_code == 200
    data = valid_resp.json()
    assert data["flag"] == STAGE1_FLAG
    assert data["nodes_loaded"] > 0
    assert data["edges_loaded"] > 0


def test_stage2_shortest_path():
    # Attempt stage 2 before stage 1
    unready = client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p"
    })
    assert unready.status_code == 400

    # Perform stage 1
    client.post("/api/stage1/ingest", json={
        "collector_tool": "bloodhound-python",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })

    # Invalid Cypher syntax (missing shortestPath)
    bad_cypher = client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH (n) RETURN n"
    })
    assert bad_cypher.status_code == 400

    # Valid Cypher query
    valid_cypher = client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH p=shortestPath((u:User {name: 'JAPNEET@CORP.LOCAL'})-[r*1..5]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p"
    })
    assert valid_cypher.status_code == 200
    data = valid_cypher.json()
    assert data["flag"] == STAGE2_FLAG
    assert data["hops"] >= 3
    assert len(data["attack_path"]) >= 3


def test_stage3_acl_exploit():
    # Stage 1 & 2 prep
    client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })
    client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p"
    })

    # Unauthorized right
    unauth = client.post("/api/stage3/exploit_acl", json={
        "principal": "JAPNEET@CORP.LOCAL",
        "target_object": "DC01.CORP.LOCAL",
        "ace_right": "GenericAll",
        "exploit_action": "GrantFullControl"
    })
    assert unauth.status_code == 403

    # Valid ACL exploit: JAPNEET is member of IT SUPPORTS which has GenericAll on GEET
    valid_exploit = client.post("/api/stage3/exploit_acl", json={
        "principal": "JAPNEET@CORP.LOCAL",
        "target_object": "GEET@CORP.LOCAL",
        "ace_right": "GenericAll",
        "exploit_action": "ResetPassword"
    })
    assert valid_exploit.status_code == 200
    data = valid_exploit.json()
    assert data["flag"] == STAGE3_FLAG
    assert "GEET@CORP.LOCAL" in data["compromised_principals"]


def test_stage4_remediation():
    # Stages 1, 2, 3
    client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })
    client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p"
    })
    client.post("/api/stage3/exploit_acl", json={
        "principal": "JAPNEET@CORP.LOCAL",
        "target_object": "GEET@CORP.LOCAL",
        "ace_right": "GenericAll",
        "exploit_action": "ResetPassword"
    })

    # Missing protected users
    bad_rem = client.post("/api/stage4/remediate_acl", json={
        "prune_edges": ["IT SUPPORTS@CORP.LOCAL->GEET@CORP.LOCAL"],
        "enable_protected_users": False,
        "enforce_tiered_admin": True
    })
    assert bad_rem.status_code == 400

    # Successful remediation
    good_rem = client.post("/api/stage4/remediate_acl", json={
        "prune_edges": [
            "IT SUPPORTS@CORP.LOCAL->GEET@CORP.LOCAL",
            "IT SUPPORTS@CORP.LOCAL->SERVER OPERATORS@CORP.LOCAL"
        ],
        "enable_protected_users": True,
        "enforce_tiered_admin": True
    })
    assert good_rem.status_code == 200
    data = good_rem.json()
    assert data["flag"] == STAGE4_FLAG
    assert data["attack_path_exists"] is False

    # Check status
    st = client.get("/status").json()
    assert st["stages"]["stage4_blue_remediation"] is True
    assert st["graph_metrics"]["tiered_admin_enabled"] is True


def test_full_progression_and_reset():
    # 1. Ingest
    r1 = client.post("/api/stage1/ingest", json={
        "collector_tool": "sharphound",
        "collection_method": "All",
        "domain": "corp.local",
        "data_types": ["users", "groups", "computers", "acls"]
    })
    assert r1.status_code == 200

    # 2. Cypher Shortest Path
    r2 = client.post("/api/stage2/shortest_path", json={
        "source_node": "JAPNEET@CORP.LOCAL",
        "target_node": "DOMAIN ADMINS@CORP.LOCAL",
        "cypher_query": "MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p"
    })
    assert r2.status_code == 200

    # 3. Exploit ACL
    r3 = client.post("/api/stage3/exploit_acl", json={
        "principal": "JAPNEET@CORP.LOCAL",
        "target_object": "GEET@CORP.LOCAL",
        "ace_right": "GenericAll",
        "exploit_action": "ResetPassword"
    })
    assert r3.status_code == 200

    # 4. Remediate
    r4 = client.post("/api/stage4/remediate_acl", json={
        "prune_edges": ["IT SUPPORTS@CORP.LOCAL->GEET@CORP.LOCAL"],
        "enable_protected_users": True,
        "enforce_tiered_admin": True
    })
    assert r4.status_code == 200

    # Reset
    reset_resp = client.post("/api/reset")
    assert reset_resp.status_code == 200

    st = client.get("/status").json()
    assert st["stages"]["stage1_domain_ingestion"] is False
    assert st["stages"]["stage4_blue_remediation"] is False
    assert st["graph_metrics"]["node_count"] == 0
