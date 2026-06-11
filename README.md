# shadow-ai-hunting

KQL queries, Intune remediation scripts, and documentation for discovering local AI agent infrastructure on managed endpoints.

Detects what Microsoft tools don't — yet: vector databases, agent memory files, Docker containers, local LLM runtimes, and API key storage that AI coding agents leave on developer workstations.

Built for **Microsoft Defender XDR**, **Microsoft Sentinel**, and **Intune**.

---

## Detections

| # | Query | Severity | Table |
|---|-------|----------|-------|
| 01 | [ChromaDB vector databases](detections/kql/01-chromadb-discovery.kql) | Medium | DeviceFileEvents |
| 02 | [FAISS vector index files](detections/kql/02-faiss-index-discovery.kql) | Medium | DeviceFileEvents |
| 03 | [AI agent memory & config files](detections/kql/03-agent-memory-files.kql) | Low-Medium | DeviceFileEvents |
| 04 | [Local LLM processes (Ollama, vLLM, llama.cpp)](detections/kql/04-local-llm-processes.kql) | Medium | DeviceProcessEvents |
| 05 | [Docker containers with AI workloads](detections/kql/05-docker-ai-containers.kql) | Medium-High | DeviceProcessEvents |
| 06 | [Local LLM API port listeners](detections/kql/06-local-llm-network.kql) | Low-Medium | DeviceNetworkEvents |
| 07 | [.env files with LLM API keys](detections/kql/07-env-api-keys.kql) | High | DeviceFileEvents |
| 08 | [Shadow AI network traffic baseline](detections/kql/08-shadow-ai-network-baseline.kql) | Informational | DeviceNetworkEvents |

Plus: [Intune Proactive Remediation script](detections/intune/Detect-ShadowAI.ps1) for fleet-wide scanning.

---

## Quick Start

### Run Your First Detection (30 seconds)

1. Open **Microsoft Defender XDR** → Hunting → Advanced hunting
2. Paste this query and click **Run query**:

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("openai.com","anthropic.com","claude.ai",
    "huggingface.co","api.deepseek.com","cursor.sh")
| summarize Connections = count()
    by DeviceName, InitiatingProcessAccountName, RemoteUrl
| order by Connections desc
```

You'll see every device talking to AI APIs.

### Deploy Fleet-Wide Scanning (5 minutes)

1. Open **Intune Admin Center** → Devices → Scripts and remediations
2. Upload [`Detect-ShadowAI.ps1`](detections/intune/Detect-ShadowAI.ps1)
3. Configure: Run as System · 64-bit PowerShell · Daily schedule
4. Assign to your managed device groups

---

## Coverage Matrix

| Artifact | Defender Native | KQL (this repo) | Intune (this repo) | Agent 365 |
|----------|:-:|:-:|:-:|:-:|
| Claude Code | Preview | `03` | ✓ | Roadmap |
| GitHub Copilot CLI | Preview | `03` | ✓ | Roadmap |
| Cursor / Windsurf | Partial | `03` | ✓ | — |
| Aider | — | `03` | ✓ | — |
| ChromaDB on disk | — | `01` | ✓ | — |
| FAISS indexes | — | `02` | ✓ | — |
| Ollama runtime | — | `04` `06` | ✓ | — |
| vLLM / LM Studio | — | `04` `05` `06` | ✓ | — |
| Docker AI containers | — | `05` | ✓ | — |
| Agent memory files | — | `03` | ✓ | — |
| MCP server configs | Preview | `03` | ✓ | Emerging |
| .env with API keys | — | `07` | ✓ | — |
| HuggingFace cache | — | `04` | ✓ | — |
| AI network traffic | Partial | `08` | — | — |

### Licensing Requirements

| Capability | Minimum |
|-----------|---------|
| Defender Advanced Hunting | Defender for Endpoint Plan 2 |
| Intune Remediations | Microsoft 365 E3 |
| Defender AI Agent Discovery | Defender for Endpoint Plan 2 |
| Agent 365 Shadow AI page | M365 E3 + Frontier preview |
| Purview DSPM for AI | M365 E5 or Agent 365 ($15/user/mo) |
| Sentinel (optional) | Microsoft Sentinel + MDE connector |

---

## Artifact Fingerprints

What local AI tooling leaves on disk — the exact paths and files targeted by the detections above.

### ChromaDB

```
chroma_data/
├── chroma.sqlite3              ← SQLite: metadata, WAL, embeddings
└── {UUID}/
    ├── data_level0.bin         ← HNSW vectors (float32)
    ├── header.bin
    ├── length.bin
    └── link_lists.bin
```

Port 8000 (server mode) · Detection: `chroma.sqlite3` + UUID sibling dirs

### FAISS

```
faiss_store/
├── index.faiss                 ← Binary index (IVF/HNSW/Flat)
├── index.pkl                   ← Docstore ID mapping
└── *.npy (optional)
```

No network component · Detection: `*.faiss` files near vector-related paths

### Ollama

```
~/.ollama/
├── models/manifests/registry.ollama.ai/library/{model}/
└── blobs/sha256-{hash}         ← Model weights (multi-GB GGUF)
```

Port **11434** · Process `ollama` / `ollama.exe` · Docker: `ollama/ollama`

### vLLM

```
~/.cache/huggingface/hub/
└── models--{org}--{model}/
    ├── config.json
    ├── model-*.safetensors
    └── tokenizer.json
```

Port **8000** · Process: `vllm.entrypoints` · Docker: `vllm/vllm-openai`

### Claude Code Memory (4-layer)

```
project/
├── CLAUDE.md                   ← Layer 1: human instructions
├── CLAUDE.local.md             ← Layer 1: local-only (gitignored)
├── MEMORY.md                   ← Layer 2: auto-memory (Claude writes)
└── memories/                   ← Layer 3: Memory Tool

~/.claude/
├── CLAUDE.md                   ← User-level instructions
└── agent-memory/{project}/     ← Layer 4: subagent memory
```

### Cursor

```
project/
├── .cursorrules                ← Legacy single-file rules
└── .cursor/rules/
    ├── backend.mdc
    ├── frontend.mdc
    └── testing.mdc
```

### Aider

```
project/
├── .aider.conf.yml
├── .aider.chat.history.md      ← Full conversation log
├── .aider.input.history
└── .env                        ← API keys in plaintext

~/.aider.conf.yml               ← User-level config
```

### GitHub Copilot

```
.github/
├── copilot-instructions.md
└── agents/
    ├── reviewer.agent.md
    └── security.agent.md
```

### agentmemory (Cross-Agent Service)

Port **3113** · `~/.agentmemory/memories.db` · Shared by Claude Code, Cursor, Codex, Gemini CLI

### HuggingFace Cache

```
~/.cache/huggingface/
├── hub/{model-dirs}            ← Downloaded weights (5 GB – 200 GB+)
└── token                       ← HuggingFace API token (plaintext!)
```

---

## Agent Autonomy Modes

These configuration states progressively remove human approval from the loop. Security teams should monitor the config files and process flags below.

| Tool | Maximum Autonomy Config | Key Risk |
|------|------------------------|----------|
| **Cursor** | Auto-run terminal commands + Allow file deletion | Shell commands execute without prompting |
| **Claude Code** | `--dangerously-skip-permissions` | Disables ALL permission checks |
| **Aider** | `--auto-commits --yes-always --auto-lint --auto-test` | Commits every edit, accepts all prompts |
| **Windsurf** | Cascade Flow Mode (default) | Full autonomy is on by default — no opt-in |
| **VS Code Copilot** | `chat.tools.autoApprove: true` | Repo `.vscode/settings.json` can activate on workspace trust |
| **GitHub Copilot** | `--autopilot` CLI flag | Approval-free issue → code → PR loop |

**Defender detection:** Local AI Agent Discovery (Preview) surfaces auto-approve status per agent.

---

## Microsoft Governance Stack

```
┌──────────────────────────────────────────────────────┐
│  AGENT 365 — Control Plane (GA May 2026)             │
│  Registry · Access Control · Shadow AI · Policy      │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────┼───────────────────┐
│ DEFENDER         │ ENTRA ID          │ INTUNE              │
│ Agent discovery  │ Agent IDs         │ Policy enforcement  │
│ Runtime protect  │ Conditional access│ App blocking        │
│ Threat detection │ Zero Trust        │ Remediation scripts │
└──────────────────┼───────────────────┘
                   │
┌──────────────────┴───────────────────────────────────┐
│  PURVIEW DSPM for AI                                  │
│  DLP · Sensitivity Labels · Audit · Insider Risk      │
└──────────────────────────────────────────────────────┘
                   │
┌──────────┐  ┌────┴──────────────┐  ┌──────────────────┐
│ MXC      │  │ Win 365 for Agents│  │ GitHub Enterprise│
│ Kernel   │  │ Managed Cloud PC  │  │ AI Controls (GA) │
│ sandbox  │  │ Isolated runtime  │  │ Model allowlists │
└──────────┘  └───────────────────┘  └──────────────────┘
```
## Repository Structure

```
shadow-ai-hunting/
├── src/                        # Astro documentation site
│   ├── components/             # Nav, Footer
│   ├── data/detections.ts      # Detection metadata
│   ├── layouts/Layout.astro
│   ├── lib/config.ts
│   ├── pages/index.astro
│   └── styles/
├── public/favicon.svg
├── detections/
│   ├── kql/                    # 8 KQL detection queries
│   └── intune/Detect-ShadowAI.ps1
├── astro.config.mjs
├── package.json
├── tsconfig.json
└── LICENSE
```

---

## Requirements

| Tool | Minimum License |
|------|----------------|
| Defender Advanced Hunting | Defender for Endpoint Plan 2 |
| Intune Remediations | Microsoft 365 E3 |
| Defender AI Agent Discovery | Defender for Endpoint Plan 2 |
| Sentinel (optional) | Microsoft Sentinel + MDE connector |

---

## Contributing

1. Fork the repo
2. Add a new KQL file in `detections/kql/` following the numbered naming convention
3. Use the standard comment header from any existing `.kql` file
4. Test against real Defender Advanced Hunting where possible
5. Update the detection table above and in `src/data/detections.ts`
6. Submit a PR

---

## License

MIT — see [LICENSE](LICENSE).

---

## Related Resources

- [Microsoft Defender Local AI Agent Discovery](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview)
- [Microsoft Agent 365 Resources](https://microsoft.github.io/agent-resources/agent365/)
- [Shadow AI in M365 Admin Center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai)
- [Microsoft Purview for Agent 365](https://learn.microsoft.com/en-us/purview/ai-agent-365)
- [MXC Execution Containers](https://github.com/microsoft/mxc)
- [Shadow AI Detection KQL Pack](https://github.com/ycarmack2647/shadow-ai-detection-kql) — Network-focused companion
