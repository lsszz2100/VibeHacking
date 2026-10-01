# Lab 34: OSINT Surface Recon & Shadow IT Hunter (OsintHunterLab)

**Port**: `8034`  
**Container**: `vhack-lab34-osint`  
**Domain**: OSINT, Shadow IT Discovery, Exposed Database Carving & Git Object Reconstruction

---

## 🎯 Objectives

1. **Step 1: Internet Attack Surface Discovery (Shodan / Censys)**
   - Query global threat intelligence scanner databases for target CIDRs, organizational ASNs, and known shadow service ports (Redis `6379`, Elasticsearch `9200`, HTTP `80`).
   - Identify open unauthenticated nodes and retrieve Step 1 Flag:  
     `FLAG{OSINT_SHODAN_EXPOSED_SERVICES_RECON_7712}`

2. **Step 2: Unauthenticated Database Carving (Redis / Elasticsearch)**
   - Query discovered endpoints (`198.51.100.42:6379`, `198.51.100.43:9200`) to extract company keys, active JWT secrets, and employee records without credentials.
   - Retrieve Step 2 Flag:  
     `FLAG{OSINT_ELASTIC_REDIS_UNAUTH_DUMP_PWNED_8823}`

3. **Step 3: Leaked .git Tree & Detached Secret Reconstruction**
   - Crawl the exposed `/.git` repository on `198.51.100.44:80`.
   - Traverse commit history (`git log -p`), unpack dangling object blobs, and reconstruct discarded high-privilege AWS access keys.
   - Retrieve Step 3 Flag:  
     `FLAG{OSINT_GIT_LEAKED_SECRET_RECONSTRUCTED_9934}`

---

## 🚀 Running the Lab

```bash
# Using vhack CLI
vhack lab start 34

# Or with docker compose directly
cd labs/34_osint_surface_recon_lab
docker compose up -d
```

Access the UI at `http://localhost:8034`.
