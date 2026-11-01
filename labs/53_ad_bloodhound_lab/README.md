# Lab 53: ADGraphMaster — Active Directory BloodHound 공격 그래프 탐색 및 ACL 익스플로잇 실습

## 실습 개요
Active Directory 환경에서 BloodHound / SharpHound를 활용한 도메인 객체 수집(Ingestion), 그래프 이론(Graph Theory) 기반의 최단 공격 경로(Shortest Path to Domain Admin) 탐색, 오설정된 DACL/ACE(GenericAll, WriteDacl, ForceChangePassword 등) 악용 및 블루팀 계층형 관리(Tiered Administration) 방어 기법을 실습합니다.

- **기본 포트**: `8053`
- **카테고리**: `activedirectory` / `redteam` / `hardening`
- **난이도**: ★★★★★
- **연계 교재**: `54_Active_Directory_Attacks/08_bloodhound_graph_theory_and_acl_exploitation_deepdive.md`
- **워게임 트랙**: `adgraph` (Track 65)

## 실습 단계 (Stages)
1. **Stage 1 (Domain Data Ingestion & Graph Schema Validation)**:
   - SharpHound / bloodhound-python 수집 데이터(JSON/CSV) 파싱 및 도메인 노드(Users, Groups, Computers)와 엣지(Relationships) 무결성 검증
   - 플래그: `FLAG{BLOODHOUND_INGESTION_GRAPH_GENERATED_3914}`
2. **Stage 2 (Cypher Graph Traversal & Shortest Path to High Value Target)**:
   - Neo4j Cypher 쿼리를 활용한 Domain Admin 및 Tier 0 자산까지의 최단 공격 경로 탐색
   - 플래그: `FLAG{CYPHER_SHORTEST_PATH_TO_DA_TRAVERSED_8205}`
3. **Stage 3 (Abusable AD ACL Misconfiguration Exploitation)**:
   - 취약한 DACL 권한(`GenericAll`, `WriteDacl`, `ForceChangePassword`) 체이닝을 통한 권한 상승 공격 실증
   - 플래그: `FLAG{ACL_GENERICALL_WRITEDACL_EXPLOITED_7142}`
4. **Stage 4 (Blue Team ACL Remediation & Tiered Hardening)**:
   - 불필요한 과도 권한 ACE 제거, `Protected Users` 보안 그룹 적용 및 공격 경로 완전 단절 검증
   - 플래그: `FLAG{TIERED_ADMIN_ACL_REMEDIATION_HARDENED_6038}`

## 빠른 실행
```bash
python3 vhack.py lab start 53
# 웹 콘솔: http://localhost:8053
```
