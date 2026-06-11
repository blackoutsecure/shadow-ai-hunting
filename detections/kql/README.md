# KQL Detection Queries

Advanced Hunting queries for Microsoft Defender XDR and Microsoft Sentinel.

## Quick Start

1. Open **Microsoft Defender XDR** → Hunting → Advanced hunting
2. Copy-paste any `.kql` file into the query editor
3. Click **Run query**
4. To automate: Click **Create detection rule** to set up recurring alerts

## Detection Index

| # | File | What It Finds | Severity | Tables |
|---|------|---------------|----------|--------|
| 01 | `01-chromadb-discovery.kql` | ChromaDB vector databases on disk | Medium | DeviceFileEvents |
| 02 | `02-faiss-index-discovery.kql` | FAISS vector index files | Medium | DeviceFileEvents |
| 03 | `03-agent-memory-files.kql` | AI agent memory & config files | Low-Medium | DeviceFileEvents |
| 04 | `04-local-llm-processes.kql` | Ollama, vLLM, llama.cpp processes | Medium | DeviceProcessEvents |
| 05 | `05-docker-ai-containers.kql` | Docker containers with AI workloads | Medium-High | DeviceProcessEvents |
| 06 | `06-local-llm-network.kql` | Local LLM API port listeners | Low-Medium | DeviceNetworkEvents |
| 07 | `07-env-api-keys.kql` | .env files with LLM API keys | High | DeviceFileEvents |
| 08 | `08-shadow-ai-network-baseline.kql` | All AI API network traffic (baseline) | Informational | DeviceNetworkEvents |

## Recommended Deployment Order

1. **Start with `08`** — Run the network baseline to understand scope
2. **Deploy `04` + `06`** — Find running LLM runtimes (immediate risk)
3. **Deploy `07`** — Find exposed API keys (high severity)
4. **Deploy `01` + `02`** — Find vector databases (data at rest)
5. **Deploy `03`** — Inventory all agent memory files
6. **Deploy `05`** — Find containerized AI workloads

## Requirements

- Microsoft Defender for Endpoint Plan 2
- Devices onboarded to Defender
- For Sentinel: MDE data connector enabled
- Data retention: queries default to 30 days (`ago(30d)`)

## Promoting to Custom Detection Rules

Any query can become an automated detection rule:
1. Ensure query outputs `Timestamp`, `ReportId`, and `DeviceId` columns
2. Click **Create detection rule** in Advanced Hunting
3. Set frequency (hourly or daily)
4. Configure alert severity and response actions
