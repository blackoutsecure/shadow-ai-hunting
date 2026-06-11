#Requires -Version 5.1
<#
.SYNOPSIS
    Shadow AI Infrastructure Detection Script for Microsoft Intune Remediations.

.DESCRIPTION
    Scans managed Windows endpoints for local AI agent infrastructure including:
    - Vector databases (ChromaDB, FAISS, LanceDB)
    - Agent memory and configuration files (CLAUDE.md, .cursorrules, AGENTS.md, etc.)
    - Local LLM runtimes (Ollama, vLLM, LM Studio, HuggingFace cache)
    - Docker containers running AI workloads
    - Agent services (agentmemory, MCP servers)
    - API key storage in .env files

    Deploy via: Intune Admin Center > Devices > Scripts and remediations
    Exit 0 = Compliant (no shadow AI found)
    Exit 1 = Non-compliant (shadow AI detected)

.NOTES
    Author: shadow-ai-hunting
    Version: 1.0.0
    Date: 2026-06-10
    License: MIT
    Requires: M365 E3+ license, Intune-managed Windows device
    Run as: System (to access all user profiles)
    Run in 64-bit PowerShell: Yes
#>

$ErrorActionPreference = 'Stop'
$LogDir = "$env:ProgramData\ShadowAIHunting"
$LogFile = Join-Path $LogDir "detection-$(Get-Date -Format 'yyyy-MM-dd').log"

try {
    # Ensure log directory exists
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }

    Start-Transcript -Path $LogFile -Append -Force

    $findings = [System.Collections.ArrayList]::new()
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    Write-Output "=== Shadow AI Infrastructure Scan ==="
    Write-Output "Scan time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "Device: $env:COMPUTERNAME"
    Write-Output "Scanning $($userProfiles.Count) user profiles..."
    Write-Output ""

    # ========================================
    # SECTION 1: Vector Databases
    # ========================================
    Write-Output "--- Section 1: Vector Databases ---"

    # ChromaDB
    foreach ($profile in $userProfiles) {
        $chromaFiles = Get-ChildItem -Path $profile.FullName -Recurse -Filter "chroma.sqlite3" -ErrorAction SilentlyContinue
        foreach ($f in $chromaFiles) {
            $sizeMB = [math]::Round($f.Length / 1MB, 2)
            [void]$findings.Add("VECTOR_DB|ChromaDB|$($profile.Name)|$($f.DirectoryName)|${sizeMB}MB")
            Write-Output "  [!] ChromaDB: $($f.FullName) (${sizeMB}MB)"
        }
    }

    # FAISS
    foreach ($profile in $userProfiles) {
        $faissFiles = Get-ChildItem -Path $profile.FullName -Recurse -Filter "*.faiss" -ErrorAction SilentlyContinue
        $faissFiles += Get-ChildItem -Path $profile.FullName -Recurse -Filter "index.faiss" -ErrorAction SilentlyContinue
        foreach ($f in ($faissFiles | Sort-Object FullName -Unique)) {
            $sizeMB = [math]::Round($f.Length / 1MB, 2)
            [void]$findings.Add("VECTOR_DB|FAISS|$($profile.Name)|$($f.DirectoryName)|${sizeMB}MB")
            Write-Output "  [!] FAISS: $($f.FullName) (${sizeMB}MB)"
        }
    }

    # ========================================
    # SECTION 2: Agent Memory Files
    # ========================================
    Write-Output ""
    Write-Output "--- Section 2: Agent Memory Files ---"

    $agentFiles = @{
        "CLAUDE.md" = "Claude Code"
        "CLAUDE.local.md" = "Claude Code (local)"
        "MEMORY.md" = "Claude Code (auto-memory)"
        ".cursorrules" = "Cursor"
        "copilot-instructions.md" = "GitHub Copilot"
        "AGENTS.md" = "Cross-Agent Standard"
        ".aider.conf.yml" = "Aider"
        ".aider.chat.history.md" = "Aider (history)"
        ".aider.input.history" = "Aider (input history)"
        "JULES.md" = "Google Jules"
    }

    foreach ($profile in $userProfiles) {
        foreach ($fileName in $agentFiles.Keys) {
            $found = Get-ChildItem -Path $profile.FullName -Recurse -Filter $fileName -ErrorAction SilentlyContinue
            foreach ($f in $found) {
                [void]$findings.Add("AGENT_MEMORY|$($agentFiles[$fileName])|$($profile.Name)|$($f.FullName)|$($f.Length)B")
                Write-Output "  [!] $($agentFiles[$fileName]): $($f.FullName)"
            }
        }
    }

    # Agent memory directories
    $agentDirs = @{
        ".claude\agent-memory" = "Claude Code Subagent Memory"
        ".cursor\rules" = "Cursor Rules Directory"
        ".windsurf\rules" = "Windsurf Rules Directory"
        ".github\agents" = "GitHub Copilot Custom Agents"
    }

    foreach ($profile in $userProfiles) {
        foreach ($dirPath in $agentDirs.Keys) {
            $fullPath = Join-Path $profile.FullName $dirPath
            if (Test-Path $fullPath) {
                $fileCount = (Get-ChildItem $fullPath -Recurse -File -ErrorAction SilentlyContinue).Count
                [void]$findings.Add("AGENT_DIR|$($agentDirs[$dirPath])|$($profile.Name)|$fullPath|${fileCount} files")
                Write-Output "  [!] $($agentDirs[$dirPath]): $fullPath (${fileCount} files)"
            }
        }
    }

    # ========================================
    # SECTION 3: Local LLM Runtimes
    # ========================================
    Write-Output ""
    Write-Output "--- Section 3: Local LLM Runtimes ---"

    # Ollama
    foreach ($profile in $userProfiles) {
        $ollamaDir = Join-Path $profile.FullName ".ollama"
        if (Test-Path $ollamaDir) {
            $modelsDir = Join-Path $ollamaDir "models"
            $modelCount = 0
            $totalSizeGB = 0
            if (Test-Path $modelsDir) {
                $modelFiles = Get-ChildItem $modelsDir -Recurse -File -ErrorAction SilentlyContinue
                $modelCount = $modelFiles.Count
                $totalSizeGB = [math]::Round(($modelFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
            }
            [void]$findings.Add("LLM_RUNTIME|Ollama|$($profile.Name)|$ollamaDir|${totalSizeGB}GB ${modelCount} files")
            Write-Output "  [!] Ollama: $ollamaDir (${totalSizeGB}GB, ${modelCount} model files)"
        }
    }

    # HuggingFace cache
    foreach ($profile in $userProfiles) {
        $hfCache = Join-Path $profile.FullName ".cache\huggingface"
        if (Test-Path $hfCache) {
            $hfFiles = Get-ChildItem $hfCache -Recurse -File -ErrorAction SilentlyContinue
            $hfSizeGB = [math]::Round(($hfFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
            if ($hfSizeGB -gt 0.5) {
                [void]$findings.Add("LLM_RUNTIME|HuggingFace Cache|$($profile.Name)|$hfCache|${hfSizeGB}GB")
                Write-Output "  [!] HuggingFace cache: $hfCache (${hfSizeGB}GB)"
            }
        }
    }

    # LM Studio
    foreach ($profile in $userProfiles) {
        $lmsDir = Join-Path $profile.FullName ".cache\lm-studio"
        if (Test-Path $lmsDir) {
            $lmsFiles = Get-ChildItem $lmsDir -Recurse -File -ErrorAction SilentlyContinue
            $lmsSizeGB = [math]::Round(($lmsFiles | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
            [void]$findings.Add("LLM_RUNTIME|LM Studio|$($profile.Name)|$lmsDir|${lmsSizeGB}GB")
            Write-Output "  [!] LM Studio: $lmsDir (${lmsSizeGB}GB)"
        }
    }

    # ========================================
    # SECTION 4: Docker AI Containers
    # ========================================
    Write-Output ""
    Write-Output "--- Section 4: Docker AI Containers ---"

    $dockerPath = Get-Command "docker" -ErrorAction SilentlyContinue
    if ($dockerPath) {
        try {
            $containers = docker ps --format "{{.Image}}|||{{.Names}}|||{{.Status}}" 2>$null
            if ($containers) {
                $aiPatterns = @("ollama", "vllm", "llama", "chroma", "qdrant", "weaviate",
                               "milvus", "huggingface", "text-generation", "localai",
                               "embedding", "inference", "langchain", "pgvector")
                foreach ($container in $containers) {
                    $parts = $container -split '\|\|\|'
                    $image = $parts[0]
                    $name = $parts[1]
                    $status = $parts[2]
                    foreach ($pattern in $aiPatterns) {
                        if ($image -match $pattern -or $name -match $pattern) {
                            [void]$findings.Add("DOCKER|$image|container|$name|$status")
                            Write-Output "  [!] AI Container: $image ($name) - $status"
                            break
                        }
                    }
                }
            }
        } catch {
            Write-Output "  [i] Docker present but query failed: $($_.Exception.Message)"
        }
    }

    # ========================================
    # SECTION 5: Running Agent Processes
    # ========================================
    Write-Output ""
    Write-Output "--- Section 5: Running Agent Processes ---"

    $agentProcesses = @("ollama", "vllm", "llama-server", "llama-cli",
                        "llamafile", "lmstudio", "LM Studio",
                        "koboldcpp", "agentmemory", "localai")
    $runningAgents = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $agentProcesses -contains $_.ProcessName -or
                       $_.ProcessName -match "ollama|vllm|llama|agentmemory" }
    foreach ($proc in $runningAgents) {
        [void]$findings.Add("PROCESS|$($proc.ProcessName)|running|PID:$($proc.Id)|$($proc.Path)")
        Write-Output "  [!] Running: $($proc.ProcessName) (PID: $($proc.Id))"
    }

    # ========================================
    # SECTION 6: Listening Ports
    # ========================================
    Write-Output ""
    Write-Output "--- Section 6: AI Service Ports ---"

    $aiPorts = @{
        11434 = "Ollama"
        8000  = "vLLM"
        8080  = "Generic Inference"
        3113  = "agentmemory"
        6333  = "Qdrant"
        19530 = "Milvus"
    }
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($port in $aiPorts.Keys) {
        $match = $listeners | Where-Object { $_.LocalPort -eq $port }
        if ($match) {
            $procId = $match[0].OwningProcess
            $procName = (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName
            [void]$findings.Add("PORT|$($aiPorts[$port])|Port:$port|PID:$procId|Process:$procName")
            Write-Output "  [!] Port $port ($($aiPorts[$port])): PID $procId ($procName)"
        }
    }

    # ========================================
    # SECTION 7: .env Files with AI API Keys
    # ========================================
    Write-Output ""
    Write-Output "--- Section 7: API Key Files ---"

    $aiDirPatterns = @("aider", "claude", "langchain", "openai", "anthropic",
                       "agent", "rag", "vector", "llm", "crewai", "autogen",
                       "llamaindex", "chromadb", "vllm", "ai-", "genai")
    foreach ($profile in $userProfiles) {
        $envFiles = Get-ChildItem -Path $profile.FullName -Recurse -Filter ".env" -ErrorAction SilentlyContinue
        foreach ($f in $envFiles) {
            $isAiDir = $false
            foreach ($pattern in $aiDirPatterns) {
                if ($f.DirectoryName -match [regex]::Escape($pattern)) {
                    $isAiDir = $true
                    break
                }
            }
            if ($isAiDir) {
                [void]$findings.Add("API_KEYS|.env|$($profile.Name)|$($f.FullName)|AI project directory")
                Write-Output "  [!] .env in AI dir: $($f.FullName)"
            }
        }
    }

    # ========================================
    # RESULTS
    # ========================================
    Write-Output ""
    Write-Output "=== Scan Complete ==="
    Write-Output "Total findings: $($findings.Count)"

    if ($findings.Count -gt 0) {
        # Write structured findings for Intune reporting
        $findingsFile = Join-Path $LogDir "findings-$(Get-Date -Format 'yyyy-MM-dd').csv"
        "Category|Tool|User|Path|Detail" | Out-File $findingsFile -Encoding UTF8
        $findings | Out-File $findingsFile -Append -Encoding UTF8

        $summary = ($findings | ForEach-Object { ($_ -split '\|')[0] } |
            Group-Object | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; '
        Write-Output "SHADOW AI DETECTED: $summary"
        Stop-Transcript
        exit 1  # Non-compliant
    } else {
        Write-Output "No shadow AI infrastructure detected."
        Stop-Transcript
        exit 0  # Compliant
    }

} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    try { Stop-Transcript } catch {}
    exit 1  # Treat errors as non-compliant for safety
}
