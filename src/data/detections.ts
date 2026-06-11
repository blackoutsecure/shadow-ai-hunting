export interface Detection {
  id: string;
  number: string;
  title: string;
  description: string;
  file: string;
  severity: 'Informational' | 'Low' | 'Low-Medium' | 'Medium' | 'Medium-High' | 'High' | 'Critical';
  tables: string[];
  mitre: string[];
  category: 'Vector Database' | 'Agent Memory' | 'LLM Runtime' | 'Container' | 'Network' | 'Credentials';
  kql: string;
}

export const detections: Detection[] = [
  {
    id: 'chromadb',
    number: '01',
    title: 'ChromaDB Local Vector Database',
    description: 'Discovers ChromaDB persistence files (chroma.sqlite3, HNSW index binaries) on managed endpoints.',
    file: '01-chromadb-discovery.kql',
    severity: 'Medium',
    tables: ['DeviceFileEvents'],
    mitre: ['T1213'],
    category: 'Vector Database',
    kql: `DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("chroma.sqlite3","data_level0.bin","header.bin","length.bin","link_lists.bin")
    or FolderPath has_any ("chroma_db","chroma/","chromadb","vdb_latest","persist_directory","chroma_data")
| summarize FileCount=count(), TotalSizeBytes=sum(FileSize), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FolderPath, FileName
| extend TotalSizeMB = round(TotalSizeBytes / 1048576.0, 2)
| order by LastSeen desc`
  },
  {
    id: 'faiss',
    number: '02',
    title: 'FAISS Vector Index Files',
    description: 'Discovers FAISS binary index files (.faiss) and pickle docstore mappings on managed endpoints.',
    file: '02-faiss-index-discovery.kql',
    severity: 'Medium',
    tables: ['DeviceFileEvents'],
    mitre: ['T1213'],
    category: 'Vector Database',
    kql: `DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".faiss" or FileName == "index.faiss" or FileName == "index.pkl"
    or FolderPath has_any ("faiss_index","faiss_store","vector_store","vector_db","embeddings")
| summarize FileCount=count(), TotalSizeBytes=sum(FileSize), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FolderPath, FileName
| extend TotalSizeMB = round(TotalSizeBytes / 1048576.0, 2)
| order by TotalSizeMB desc`
  },
  {
    id: 'agent-memory',
    number: '03',
    title: 'AI Agent Memory & Config Files',
    description: 'Discovers memory files persisted by Claude Code, Cursor, Copilot, Aider, Windsurf, and Jules.',
    file: '03-agent-memory-files.kql',
    severity: 'Low-Medium',
    tables: ['DeviceFileEvents'],
    mitre: ['T1083', 'T1005'],
    category: 'Agent Memory',
    kql: `let AgentMemoryFiles = dynamic(["CLAUDE.md","CLAUDE.local.md","MEMORY.md",".cursorrules",
    "copilot-instructions.md","AGENTS.md",".aider.conf.yml",".aider.chat.history.md",
    ".aider.input.history","JULES.md","agentmemory.json"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (AgentMemoryFiles)
    or FolderPath has_any (".cursor/rules",".claude/agent-memory",".windsurf/rules",".github/agents","memories/")
| summarize FileCount=count(), Agents=make_set(FileName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FolderPath
| order by LastSeen desc`
  },
  {
    id: 'llm-processes',
    number: '04',
    title: 'Local LLM Inference Processes',
    description: 'Detects Ollama, vLLM, llama.cpp, LM Studio, and other local LLM runtime processes.',
    file: '04-local-llm-processes.kql',
    severity: 'Medium',
    tables: ['DeviceProcessEvents'],
    mitre: ['T1059', 'T1204.002'],
    category: 'LLM Runtime',
    kql: `DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ollama","ollama.exe","vllm","llama-server","llama-cli",
    "llamafile","lmstudio","LM Studio.exe","koboldcpp")
    or ProcessCommandLine has_any ("ollama serve","ollama run","vllm.entrypoints","llama-server --port")
| summarize RunCount=count(), CommandLines=make_set(ProcessCommandLine, 5),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FileName
| order by RunCount desc`
  },
  {
    id: 'docker-ai',
    number: '05',
    title: 'Docker Containers with AI Workloads',
    description: 'Detects Docker/Podman commands running AI inference, vector DB, or agent framework containers.',
    file: '05-docker-ai-containers.kql',
    severity: 'Medium-High',
    tables: ['DeviceProcessEvents'],
    mitre: ['T1610', 'T1059'],
    category: 'Container',
    kql: `DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("docker","docker.exe","podman","podman.exe","docker-compose","nerdctl")
| where ProcessCommandLine has_any ("vllm/vllm-openai","ollama/ollama","chromadb/chroma",
    "qdrant/qdrant","weaviate","milvus","huggingface","text-generation","localai")
| summarize ActionCount=count(), Commands=make_set(ProcessCommandLine, 5),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FileName
| order by ActionCount desc`
  },
  {
    id: 'llm-network',
    number: '06',
    title: 'Local LLM API Port Listeners',
    description: 'Detects network listeners on ports used by Ollama (11434), vLLM (8000), agentmemory (3113), and vector DBs.',
    file: '06-local-llm-network.kql',
    severity: 'Low-Medium',
    tables: ['DeviceNetworkEvents'],
    mitre: ['T1071.001', 'T1571'],
    category: 'Network',
    kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort in (11434, 8000, 8080, 3113, 6333, 19530)
| where ActionType in ("ListeningConnectionCreated","ConnectionSuccess","InboundConnectionAccepted")
    or RemoteIP in ("127.0.0.1","::1","0.0.0.0")
| summarize Connections=count(), Processes=make_set(InitiatingProcessFileName),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, LocalPort
| order by Connections desc`
  },
  {
    id: 'env-api-keys',
    number: '07',
    title: 'API Key Storage in .env Files',
    description: 'Detects .env files in AI project directories that likely contain LLM provider API keys.',
    file: '07-env-api-keys.kql',
    severity: 'High',
    tables: ['DeviceFileEvents'],
    mitre: ['T1552.001', 'T1005'],
    category: 'Credentials',
    kql: `DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName == ".env" or FileName endswith ".env.local" or FileName endswith ".env.development"
| where FolderPath has_any ("aider","claude","langchain","llm","openai","anthropic","agent",
    "rag","vector","embedding","crewai","autogen","llamaindex","chromadb","vllm","ollama","ai-","genai")
| summarize FileCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FolderPath, FileName, ActionType
| order by LastSeen desc`
  },
  {
    id: 'network-baseline',
    number: '08',
    title: 'Shadow AI Network Traffic Baseline',
    description: 'Baseline view of all network traffic to AI provider APIs across the managed fleet.',
    file: '08-shadow-ai-network-baseline.kql',
    severity: 'Informational',
    tables: ['DeviceNetworkEvents'],
    mitre: ['T1567', 'T1071.001'],
    category: 'Network',
    kql: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("openai.com","anthropic.com","claude.ai","gemini.google.com",
    "deepseek.com","huggingface.co","perplexity.ai","cursor.sh","codeium","githubcopilot")
| extend AIProvider = case(
    RemoteUrl has "openai" or RemoteUrl has "chatgpt", "OpenAI",
    RemoteUrl has "anthropic" or RemoteUrl has "claude", "Anthropic",
    RemoteUrl has "gemini", "Google Gemini",
    RemoteUrl has "deepseek", "DeepSeek",
    RemoteUrl has "huggingface", "HuggingFace",
    RemoteUrl has "cursor", "Cursor IDE",
    RemoteUrl has "codeium" or RemoteUrl has "windsurf", "Windsurf/Codeium",
    RemoteUrl has "copilot" or RemoteUrl has "githubcopilot", "GitHub Copilot",
    "Other AI Service")
| summarize Connections=count(), UniqueDevices=dcount(DeviceName),
    UniqueUsers=dcount(InitiatingProcessAccountName)
    by AIProvider
| order by Connections desc`
  }
];

export const severityColors: Record<string, string> = {
  'Informational': '#6b7280',
  'Low': '#3b82f6',
  'Low-Medium': '#60a5fa',
  'Medium': '#f59e0b',
  'Medium-High': '#f97316',
  'High': '#ef4444',
  'Critical': '#dc2626'
};

export const categoryIcons: Record<string, string> = {
  'Vector Database': '🗄️',
  'Agent Memory': '🧠',
  'LLM Runtime': '⚡',
  'Container': '🐳',
  'Network': '🌐',
  'Credentials': '🔑'
};
