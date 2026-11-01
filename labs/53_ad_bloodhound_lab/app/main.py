#!/usr/bin/env python3
"""
Lab 53: ADGraphMaster — Active Directory BloodHound Attack Graph Traversal & ACL Exploitation Lab
Interactive simulation based on enterprise Active Directory security and attack path management:
1. Domain Data Ingestion: SharpHound / bloodhound-python data collection and graph topology schema validation
2. Cypher Graph Traversal: Shortest path queries to Domain Admins and High Value Targets (HVT)
3. AD ACL Misconfiguration Abuse: GenericAll / WriteDacl privilege escalation chains
4. Blue Team Graph Remediation: Pruning toxic ACEs, Protected Users tiering, and attack path severance
"""

from typing import Dict, Any, List, Optional, Set
import os
import re
from collections import deque
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Lab 53: ADGraphMaster — Active Directory BloodHound Lab",
    description="Graph theory-based attack path analysis, ACL exploitation, and tiered defense.",
    version="1.0.0",
)

# CTF Flags
STAGE1_FLAG = "FLAG{BLOODHOUND_INGESTION_GRAPH_GENERATED_3914}"
STAGE2_FLAG = "FLAG{CYPHER_SHORTEST_PATH_TO_DA_TRAVERSED_8205}"
STAGE3_FLAG = "FLAG{ACL_GENERICALL_WRITEDACL_EXPLOITED_7142}"
STAGE4_FLAG = "FLAG{TIERED_ADMIN_ACL_REMEDIATION_HARDENED_6038}"


class GraphNode:
    def __init__(self, name: str, node_type: str, tier: int = 2) -> None:
        self.name: str = name.upper()
        self.node_type: str = node_type.upper()  # USER, GROUP, COMPUTER, DOMAIN
        self.tier: int = tier  # 0: Domain Admin, 1: Server Operator, 2: Workstation/User


class GraphEdge:
    def __init__(self, source: str, target: str, relationship: str) -> None:
        self.source: str = source.upper()
        self.target: str = target.upper()
        self.relationship: str = relationship.upper()  # MEMBEROF, GENERICALL, WRITEDACL, ADMINTO, HASSESSION


class LabState:
    """State manager for Lab 53."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.stage1_completed: bool = False
        self.stage2_completed: bool = False
        self.stage3_completed: bool = False
        self.stage4_completed: bool = False

        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.compromised_principals: Set[str] = {"JAPNEET@CORP.LOCAL"}
        self.protected_users: Set[str] = set()
        self.tiered_admin_enabled: bool = False


state = LabState()


def init_default_ad_graph() -> None:
    """Initialize realistic enterprise AD graph topology."""
    state.nodes = {
        "JAPNEET@CORP.LOCAL": GraphNode("JAPNEET@CORP.LOCAL", "USER", tier=2),
        "SVC_BACKUP@CORP.LOCAL": GraphNode("SVC_BACKUP@CORP.LOCAL", "USER", tier=1),
        "GEET@CORP.LOCAL": GraphNode("GEET@CORP.LOCAL", "USER", tier=1),
        "ALICE_ADMIN@CORP.LOCAL": GraphNode("ALICE_ADMIN@CORP.LOCAL", "USER", tier=0),
        "KRBTGT@CORP.LOCAL": GraphNode("KRBTGT@CORP.LOCAL", "USER", tier=0),
        "DOMAIN USERS@CORP.LOCAL": GraphNode("DOMAIN USERS@CORP.LOCAL", "GROUP", tier=2),
        "IT SUPPORTS@CORP.LOCAL": GraphNode("IT SUPPORTS@CORP.LOCAL", "GROUP", tier=2),
        "SERVER OPERATORS@CORP.LOCAL": GraphNode("SERVER OPERATORS@CORP.LOCAL", "GROUP", tier=1),
        "DOMAIN ADMINS@CORP.LOCAL": GraphNode("DOMAIN ADMINS@CORP.LOCAL", "GROUP", tier=0),
        "WS01.CORP.LOCAL": GraphNode("WS01.CORP.LOCAL", "COMPUTER", tier=2),
        "FILESRV01.CORP.LOCAL": GraphNode("FILESRV01.CORP.LOCAL", "COMPUTER", tier=1),
        "DC01.CORP.LOCAL": GraphNode("DC01.CORP.LOCAL", "COMPUTER", tier=0),
    }

    state.edges = [
        GraphEdge("JAPNEET@CORP.LOCAL", "DOMAIN USERS@CORP.LOCAL", "MEMBEROF"),
        GraphEdge("JAPNEET@CORP.LOCAL", "IT SUPPORTS@CORP.LOCAL", "MEMBEROF"),
        GraphEdge("IT SUPPORTS@CORP.LOCAL", "GEET@CORP.LOCAL", "GENERICALL"),
        GraphEdge("IT SUPPORTS@CORP.LOCAL", "SERVER OPERATORS@CORP.LOCAL", "WRITEDACL"),
        GraphEdge("GEET@CORP.LOCAL", "FILESRV01.CORP.LOCAL", "ADMINTO"),
        GraphEdge("FILESRV01.CORP.LOCAL", "ALICE_ADMIN@CORP.LOCAL", "HASSESSION"),
        GraphEdge("ALICE_ADMIN@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL", "MEMBEROF"),
        GraphEdge("DOMAIN ADMINS@CORP.LOCAL", "DC01.CORP.LOCAL", "ADMINTO"),
    ]


def find_shortest_attack_path(start: str, target: str) -> Optional[List[Dict[str, str]]]:
    """BFS traversal over AD attack graph with direct edge tuple chaining."""
    start_u = start.strip().upper()
    target_u = target.strip().upper()

    if start_u not in state.nodes or target_u not in state.nodes:
        return None

    if start_u == target_u:
        return []

    # Queue contains tuples of: (current_node_name, path_of_edges)
    queue: deque = deque([(start_u, [])])
    visited: Set[str] = {start_u}

    while queue:
        current, path = queue.popleft()

        if current == target_u:
            return path

        # Find outgoing edges from current node
        for edge in state.edges:
            if edge.source == current and edge.target not in visited:
                visited.add(edge.target)
                edge_dict = {
                    "from": edge.source,
                    "to": edge.target,
                    "relationship": edge.relationship
                }
                queue.append((edge.target, path + [edge_dict]))

    return None


class IngestionRequest(BaseModel):
    collector_tool: str = Field(..., min_length=2, max_length=32, description="sharphound, bloodhound-python, invoke-bloodhound")
    collection_method: str = Field(..., min_length=2, max_length=32, description="All, DCOnly, Session, Group")
    domain: str = Field(..., min_length=3, max_length=64, description="Target domain FQDN (e.g. corp.local)")
    data_types: List[str] = Field(..., min_length=1, max_length=16, description="Uploaded data schemas: users, groups, computers, acls, sessions")


class CypherQueryRequest(BaseModel):
    source_node: str = Field(..., min_length=3, max_length=64, description="Source principal (e.g. JAPNEET@CORP.LOCAL)")
    target_node: str = Field(..., min_length=3, max_length=64, description="Target group/principal (e.g. DOMAIN ADMINS@CORP.LOCAL)")
    cypher_query: str = Field(..., min_length=10, max_length=512, description="Neo4j Cypher query e.g. MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p")


class ACLExploitRequest(BaseModel):
    principal: str = Field(..., min_length=3, max_length=64, description="Compromised principal initiating ACL attack")
    target_object: str = Field(..., min_length=3, max_length=64, description="Target user or group being abused")
    ace_right: str = Field(..., min_length=4, max_length=32, description="GenericAll, WriteDacl, GenericWrite, ForceChangePassword")
    exploit_action: str = Field(..., min_length=4, max_length=64, description="ResetPassword, GrantFullControl, AddPrincipalToGroup")


class RemediationRequest(BaseModel):
    prune_edges: List[str] = Field(..., min_length=1, max_length=32, description="List of source->target edges to remove e.g. ['IT SUPPORTS@CORP.LOCAL->GEET@CORP.LOCAL']")
    enable_protected_users: bool = Field(..., description="Enroll Tier 0 and Tier 1 admins into Protected Users security group")
    enforce_tiered_admin: bool = Field(..., description="Enforce strict PAW/Tier 0 segregation")


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return r"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>Lab 53: ADGraphMaster Console</title>
        <style>
            body { background: #0a0e17; color: #cbd5e1; font-family: 'Fira Code', monospace; padding: 24px; }
            h1 { color: #e11d48; border-bottom: 2px solid #1e293b; padding-bottom: 12px; }
            .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 18px; margin-bottom: 18px; }
            .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 13px; font-weight: bold; }
            .badge-ready { background: #065f46; color: #34d399; }
            .badge-alert { background: #881337; color: #fda4af; }
            pre { background: #030712; padding: 12px; border-radius: 6px; overflow-x: auto; color: #f43f5e; font-size: 13px; }
            ul { margin: 8px 0; padding-left: 20px; }
            li { margin-bottom: 6px; }
        </style>
    </head>
    <body>
        <h1>🩸 Lab 53: ADGraphMaster — Active Directory BloodHound & ACL Exploitation</h1>
        <div class="card">
            <p><strong>상태:</strong> <span class="badge badge-ready">ONLINE</span> | <strong>AD 그래프 관제 포트:</strong> 8053</p>
            <p>SharpHound/BloodHound 도메인 텔레메트리 수집, Neo4j Cypher 최단 공격 경로 탐색, 취약한 DACL/ACE 권한 상승 체인 악용 및 Tiered Administration 방어를 실습합니다.</p>
        </div>
        <div class="card">
            <h3>실습 단계 (Stages)</h3>
            <ul>
                <li><strong>Stage 1:</strong> SharpHound / bloodhound-python 도메인 데이터 인제스천 및 그래프 토폴로지 구축</li>
                <li><strong>Stage 2:</strong> Neo4j Cypher 최단 경로(Shortest Path to Domain Admin) 그래프 순회</li>
                <li><strong>Stage 3:</strong> 오설정된 AD ACL(GenericAll / WriteDacl) 악용 및 권한 상승 체인 완성</li>
                <li><strong>Stage 4:</strong> 불필요한 과도 권한 ACE 제거, Protected Users 적용 및 공격 경로 단절 검증</li>
            </ul>
        </div>
        <div class="card">
            <h3>주요 엔드포인트</h3>
            <pre>
GET  /status                      - 실습 상태 및 그래프 노드/엣지 현황
POST /api/reset                   - 실습 상태 초기화
POST /api/stage1/ingest           - SharpHound 데이터 인제스천
POST /api/stage2/shortest_path    - Cypher 최단 공격 경로 쿼리
POST /api/stage3/exploit_acl      - 취약 DACL 권한 악용
POST /api/stage4/remediate_acl    - 블루팀 ACL 정화 및 계층형 하드닝
            </pre>
        </div>
    </body>
    </html>
    """


@app.get("/status")
async def get_status():
    return {
        "lab": "53_ad_bloodhound_lab",
        "title": "ADGraphMaster — Active Directory BloodHound Attack Graph & ACL Lab",
        "port": 8053,
        "stages": {
            "stage1_domain_ingestion": state.stage1_completed,
            "stage2_shortest_path_cypher": state.stage2_completed,
            "stage3_acl_exploitation": state.stage3_completed,
            "stage4_blue_remediation": state.stage4_completed,
        },
        "graph_metrics": {
            "node_count": len(state.nodes),
            "edge_count": len(state.edges),
            "compromised_principals": sorted(list(state.compromised_principals)),
            "protected_users": sorted(list(state.protected_users)),
            "tiered_admin_enabled": state.tiered_admin_enabled,
        }
    }


@app.post("/api/reset")
async def reset_lab():
    state.reset()
    return {"status": "success", "message": "Lab 53 state has been reset to uninitialized."}


@app.post("/api/stage1/ingest")
async def stage1_ingest(req: IngestionRequest):
    valid_tools = {"sharphound", "bloodhound-python", "invoke-bloodhound"}
    if req.collector_tool.lower() not in valid_tools:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid collector tool: {req.collector_tool}. Valid options: {sorted(valid_tools)}"
        )

    if req.domain.upper() != "CORP.LOCAL":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target domain '{req.domain}' not found. Current target is 'corp.local'."
        )

    req_types = {t.lower() for t in req.data_types}
    required_types = {"users", "groups", "computers", "acls"}
    if not required_types.issubset(req_types):
        missing = required_types - req_types
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing essential BloodHound data schemas: {sorted(missing)}. Required: {sorted(required_types)}"
        )

    init_default_ad_graph()
    state.stage1_completed = True

    return {
        "status": "success",
        "stage": 1,
        "message": "Domain telemetry successfully ingested into Neo4j graph database.",
        "nodes_loaded": len(state.nodes),
        "edges_loaded": len(state.edges),
        "domain": "CORP.LOCAL",
        "flag": STAGE1_FLAG
    }


@app.post("/api/stage2/shortest_path")
async def stage2_shortest_path(req: CypherQueryRequest):
    if not state.stage1_completed or not state.nodes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain graph is empty. Please complete Stage 1 ingestion first."
        )

    query_clean = req.cypher_query.strip().lower()
    if "shortestpath" not in query_clean or "match" not in query_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cypher query must utilize shortestPath() algorithm syntax (e.g. MATCH p=shortestPath((u:User)-[r*1..5]->(g:Group)) RETURN p)."
        )

    path = find_shortest_attack_path(req.source_node, req.target_node)
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No attack path found between '{req.source_node}' and '{req.target_node}'."
        )

    state.stage2_completed = True
    return {
        "status": "success",
        "stage": 2,
        "message": f"Shortest attack path identified with {len(path)} hops.",
        "source": req.source_node.upper(),
        "target": req.target_node.upper(),
        "hops": len(path),
        "attack_path": path,
        "flag": STAGE2_FLAG
    }


@app.post("/api/stage3/exploit_acl")
async def stage3_exploit_acl(req: ACLExploitRequest):
    if not state.stage2_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please identify the attack path in Stage 2 before exploiting ACL misconfigurations."
        )

    principal_u = req.principal.upper()
    target_u = req.target_object.upper()
    ace_u = req.ace_right.upper()

    # Verify if principal has effective ACE on target
    abusable_edge = None
    for edge in state.edges:
        if edge.source == principal_u and edge.target == target_u:
            abusable_edge = edge
            break

    if not abusable_edge:
        # Check if principal belongs to a group that has the right
        for edge in state.edges:
            if edge.target == target_u and edge.relationship in {"GENERICALL", "WRITEDACL", "GENERICWRITE", "FORCECHANGEPASSWORD"}:
                # Check if principal is member of edge.source
                for p_edge in state.edges:
                    if p_edge.source == principal_u and p_edge.target == edge.source and p_edge.relationship == "MEMBEROF":
                        abusable_edge = edge
                        break
                if abusable_edge:
                    break

    if not abusable_edge or abusable_edge.relationship != ace_u:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Principal '{principal_u}' does not possess direct or group-inherited '{ace_u}' right on '{target_u}'."
        )

    # Simulate exploitation action
    if ace_u == "GENERICALL" and req.exploit_action in {"ResetPassword", "GrantFullControl"}:
        state.compromised_principals.add(target_u)
        result_msg = f"Exploited GenericAll on '{target_u}'. Password reset or Full Control achieved."
    elif ace_u == "WRITEDACL" and req.exploit_action == "AddPrincipalToGroup":
        state.edges.append(GraphEdge(principal_u, target_u, "MEMBEROF"))
        state.compromised_principals.add(target_u)
        result_msg = f"Exploited WriteDacl on '{target_u}'. Added '{principal_u}' directly to group."
    else:
        state.compromised_principals.add(target_u)
        result_msg = f"Exploited {ace_u} on '{target_u}' via action {req.exploit_action}."

    state.stage3_completed = True
    return {
        "status": "success",
        "stage": 3,
        "message": result_msg,
        "compromised_principals": sorted(list(state.compromised_principals)),
        "flag": STAGE3_FLAG
    }


@app.post("/api/stage4/remediate_acl")
async def stage4_remediate_acl(req: RemediationRequest):
    if not state.stage3_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please execute Stage 3 exploitation before validating remediation."
        )

    if not req.enable_protected_users or not req.enforce_tiered_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remediation mandates enabling Protected Users security group and enforcing Tiered Administration."
        )

    # Prune toxic ACE edges explicitly specified in remediation plan
    pruned_count = 0
    new_edges = []
    edges_to_prune_parsed = {p.strip().upper() for p in req.prune_edges}

    for edge in state.edges:
        edge_key = f"{edge.source}->{edge.target}"
        if edge_key in edges_to_prune_parsed:
            pruned_count += 1
        else:
            new_edges.append(edge)

    state.edges = new_edges
    state.protected_users.update({"ALICE_ADMIN@CORP.LOCAL", "GEET@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"})
    state.tiered_admin_enabled = True

    # Re-evaluate shortest path from untrusted helpdesk user to Domain Admins
    remaining_path = find_shortest_attack_path("JAPNEET@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL")
    if remaining_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Remediation incomplete! An attack path still exists with {len(remaining_path)} hops."
        )

    state.stage4_completed = True
    return {
        "status": "success",
        "stage": 4,
        "message": f"Remediation successful! Pruned {pruned_count} toxic ACEs. Attack path completely severed.",
        "protected_users": sorted(list(state.protected_users)),
        "attack_path_exists": False,
        "flag": STAGE4_FLAG
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8053)
