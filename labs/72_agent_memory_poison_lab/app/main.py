from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import hashlib
import hmac

app = FastAPI(
    title="Lab 72: AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense Lab",
    version="2.22.0",
    description="Agentic Episodic & Semantic Memory Poisoning, GraphRAG Permission Hijacking, HMAC Session Provenance & Cognitive Firewall Quarantine"
)

MEMORY_SHARED_SECRET = b"vibe-2026-enterprise-agent-memory-defense-secret-8072"

class Stage1Payload(BaseModel):
    sanitization_policy: str
    untrusted_tagging_active: bool
    quarantine_partition_enabled: bool
    blocked_directive_patterns: List[str]

class Stage2Payload(BaseModel):
    memory_node_id: str
    session_id: str
    context_hash: str
    attestation_sig: str
    provenance_hmac: str

class Stage3Payload(BaseModel):
    embedding_model: str
    cosine_drift_threshold: float
    adversarial_cluster_filter_active: bool
    vector_index_isolation_enforced: bool

class Stage4Payload(BaseModel):
    graph_schema_validation: str
    unauthorized_edge_pruning: bool
    admin_relationship_hmac: str
    sleeper_trigger_neutralized: bool

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "lab_id": 72,
        "name": "agent_memory_poison_lab",
        "stages": 4,
        "category": "ai",
        "version": "2.22.0"
    }

@app.get("/")
def read_root():
    return {
        "lab": "Lab 72: AI Agent Long-Term Context Memory & Knowledge Graph Poisoning Defense Lab",
        "status": "ready",
        "port": 8072,
        "stages": 4,
        "category": "ai",
        "version": "2.22.0"
    }

@app.post("/api/stage1/eval")
def evaluate_stage1(payload: Stage1Payload):
    """Stage 1: Episodic Memory Sanitization & Quarantine Partitioning"""
    if payload.sanitization_policy != "strip_prompt_delimiters_and_quarantine":
        raise HTTPException(status_code=400, detail="Sanitization policy must be strip_prompt_delimiters_and_quarantine.")
    
    if not payload.untrusted_tagging_active:
        raise HTTPException(status_code=400, detail="Untrusted memory node tagging must be active.")
    
    if not payload.quarantine_partition_enabled:
        raise HTTPException(status_code=400, detail="Quarantine memory partition must be enabled.")
    
    if len(payload.blocked_directive_patterns) < 2:
        raise HTTPException(status_code=400, detail="At least two blocked directive patterns required.")
    
    return {
        "success": True,
        "stage": 1,
        "flag": "FLAG{v222_s1_episodic_context_sanitized_and_quarantined}",
        "message": "Episodic context memory sanitized and quarantined. Prompt delimiters stripped successfully."
    }

@app.post("/api/stage2/eval")
def evaluate_stage2(payload: Stage2Payload):
    """Stage 2: Cryptographic Session Provenance & HMAC Attestation"""
    if not payload.memory_node_id.startswith("mem_node_"):
        raise HTTPException(status_code=400, detail="Valid memory node identifier required.")
    
    if len(payload.context_hash) != 64:
        raise HTTPException(status_code=400, detail="Context hash must be a 64-character SHA-256 hex string.")
    
    if not payload.attestation_sig.startswith("sig_agent_mem_v222_"):
        raise HTTPException(status_code=400, detail="Valid agent memory attestation signature required.")
    
    expected_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        f"{payload.session_id}:{payload.context_hash}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.provenance_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid cryptographic session provenance HMAC attestation.")
    
    return {
        "success": True,
        "stage": 2,
        "flag": "FLAG{v222_s2_session_provenance_hmac_attested}",
        "message": "Cryptographic session provenance verified. Unattested adversarial context rejected."
    }

@app.post("/api/stage3/eval")
def evaluate_stage3(payload: Stage3Payload):
    """Stage 3: Semantic Embedding Anomaly & Cosine Drift Detection"""
    if not payload.embedding_model.startswith("vibe-semantic-embed-"):
        raise HTTPException(status_code=400, detail="Valid semantic embedding model required.")
    
    if payload.cosine_drift_threshold > 0.35:
        raise HTTPException(status_code=400, detail="Cosine drift threshold must be <= 0.35 to catch adversarial clusters.")
    
    if not payload.adversarial_cluster_filter_active:
        raise HTTPException(status_code=400, detail="Adversarial embedding cluster filtering must be active.")
    
    if not payload.vector_index_isolation_enforced:
        raise HTTPException(status_code=400, detail="Vector index multi-tenant isolation must be enforced.")
    
    return {
        "success": True,
        "stage": 3,
        "flag": "FLAG{v222_s3_cosine_anomaly_adversarial_cluster_filtered}",
        "message": "Semantic cosine anomaly detection active. Adversarial embedding clusters filtered."
    }

@app.post("/api/stage4/eval")
def evaluate_stage4(payload: Stage4Payload):
    """Stage 4: Knowledge Graph (GraphRAG) Permission Invariant & Topological Shield"""
    if payload.graph_schema_validation != "strict_topological_invariant":
        raise HTTPException(status_code=400, detail="Graph schema validation must be strict_topological_invariant.")
    
    if not payload.unauthorized_edge_pruning:
        raise HTTPException(status_code=400, detail="Unauthorized relationship edge pruning must be enabled.")
    
    expected_hmac = hmac.new(
        MEMORY_SHARED_SECRET,
        f"graphrag_schema_v222:invariant_edges_secured".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(payload.admin_relationship_hmac, expected_hmac):
        raise HTTPException(status_code=403, detail="Invalid admin relationship topology HMAC attestation.")
    
    if not payload.sleeper_trigger_neutralized:
        raise HTTPException(status_code=400, detail="Sleeper prompt latent triggers must be neutralized.")
    
    return {
        "success": True,
        "stage": 4,
        "flag": "FLAG{v222_s4_graphrag_topological_permission_shielded}",
        "message": "GraphRAG knowledge graph topological invariant secured. Sleeper prompt triggers neutralized."
    }
