# Intune Proactive Remediation Scripts

PowerShell scripts for fleet-wide shadow AI infrastructure scanning via Microsoft Intune.

## Scripts

| File | Purpose | Exit 0 | Exit 1 |
|------|---------|--------|--------|
| `Detect-ShadowAI.ps1` | Comprehensive shadow AI scanner | No AI found | AI infrastructure detected |

## Deployment

1. Open **Intune Admin Center** → Devices → Scripts and remediations
2. Click **Create script package**
3. Upload `Detect-ShadowAI.ps1` as the **Detection script**
4. Settings:
   - Run this script using the logged-on credentials: **No** (run as System)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell host: **Yes**
5. Assign to device groups (start with pilot, then expand)
6. Schedule: **Daily** for initial discovery, then **Weekly**

## Requirements

- Microsoft 365 E3+ license
- Intune-managed Windows devices (Entra Joined or Hybrid Joined)
- Endpoint Analytics enabled

## What It Scans

| Category | Artifacts | Risk Level |
|----------|-----------|------------|
| Vector Databases | ChromaDB (`chroma.sqlite3`), FAISS (`.faiss`) | Medium |
| Agent Memory | `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `.aider.conf.yml` | Low-Medium |
| Agent Directories | `~/.claude/agent-memory/`, `.cursor/rules/`, `.windsurf/rules/` | Low-Medium |
| LLM Runtimes | Ollama (`~/.ollama/`), HuggingFace cache, LM Studio | Medium-High |
| Docker Containers | Running AI containers (Ollama, vLLM, ChromaDB, Qdrant) | Medium-High |
| Agent Processes | Running Ollama, vLLM, llama-server, agentmemory | Medium |
| Listening Ports | 11434 (Ollama), 8000 (vLLM), 3113 (agentmemory), 6333 (Qdrant) | Medium |
| API Keys | `.env` files in AI project directories | High |

## Output

- Structured CSV findings: `C:\ProgramData\ShadowAIHunting\findings-{date}.csv`
- Transcript log: `C:\ProgramData\ShadowAIHunting\detection-{date}.log`
- Intune reporting: Detection output visible in Endpoint Analytics
