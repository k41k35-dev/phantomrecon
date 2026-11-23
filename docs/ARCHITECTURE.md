# 🏛️ Phantom Recon Architecture

## 1. System Components

The Phantom Recon architecture is designed with a decoupled pipeline model:

```
[ Target Input ]
       │
       ▼
┌─────────────────────────┐
│ phantomrecon (CLI)      │ ── Doctor Check & Dispatch
└────────────┬────────────┘
             │
      ┌──────┴──────────────────────┬──────────────────────┐
      │                             │                      │
      ▼                             ▼                      ▼
┌──────────────────┐       ┌─────────────────┐   ┌────────────────────┐
│  nmap_engine.py  │       │   ferodir.sh    │   │  web_inspector.py  │
│  - Host Alive    │       │   - Tech Detect │   │  - Header Auditing │
│  - Port Scan     │       │   - Soft-404    │   │  - CVE Correlation │
│  - Service Intel │       │   - Feroxbuster │   │  - Endpoint Class  │
└────────┬─────────┘       └────────┬────────┘   └─────────▲──────────┘
         │                          │                      │
         └─────── HTTP Service ─────┴──────────────────────┘
```

### 1.1 `nmap_engine.py` (Network Intelligence Layer)
- **Host Validation:** ICMP ping and multi-port TCP connect fallback.
- **Adaptive Rate Tuning:** Adjusts SYN packets-per-second dynamically based on network latency.
- **Service Enrichment Matrix:** Cross-references open ports against a knowledge database of attack vectors, common CVEs, and recommended exploitation tools.
- **Reporting:** Auto-generates clean Markdown summaries (`services.md` and `recon_summary.md`).

### 1.2 `ferodir.sh` (Endpoint Discovery Layer)
- **One-Shot Execution:** Eliminates redundant flags by standardizing on sensible penetration testing defaults.
- **Pre-Scan Heuristics:** Executes concurrent background curl probes to detect HTTP status codes, technology headers (PHP, ASP.NET, Java, Python, Node.js), and dynamically configures file extension fuzz lists.
- **Soft-404 Wildcard Mitigation:** Computes random hash URLs and uses `--filter-similar-to` to prevent false positive floods.
- **Juicy File & Outlier Extraction:** Automatically surfaces sensitive files (.git, .env, backups, admin panels) and response size anomalies.

### 1.3 `web_inspector.py` (Application Threat Layer)
- **Log Ingestion & Stream Processing:** Consumes Feroxbuster JSON streams, raw text URL lists, or direct endpoints.
- **Multi-Threaded Analysis:** Concurrent header probing, security header gap analysis, cookie attribute inspection (`HttpOnly`, `Secure`, `SameSite`), and technology identification.
- **Threat Intel Matrix:** Correlates version banners against known critical CVEs (e.g. Apache Path Traversal, Log4j, OpenSSL bugs).

---

## 2. Directory Layout & Module Interaction

```
/
├── phantomrecon         # Entry point CLI
├── bin/
│   ├── nmap_engine.py   # Executable standalone or invoked via CLI
│   ├── ferodir.sh       # Executable standalone or invoked via CLI/nmap_engine
│   └── web_inspector.py # Executable standalone or invoked via CLI/ferodir
└── docs/                # Architecture and security documentation
```
