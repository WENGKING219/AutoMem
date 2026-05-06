"""
Central configuration for the Memory Forensics Agent.

All tuneable knobs and file paths live here so they're easy to find.
"""

import os
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent

# Where things live on disk
MEMORY_DUMPS_DIR = project_root / "memory_dumps"
REPORTS_DIR = project_root / "reports"
LOGS_DIR = project_root / "logs"
TURN_TRACE_FILE = LOGS_DIR / "chat_traces.jsonl"
CHAT_HISTORY_FILE = LOGS_DIR / "chat_history.json"
CHECKPOINT_DB_FILE = LOGS_DIR / "agent_checkpoints.sqlite3"
SKILLS_DIR = project_root / "agent" / "skills"
SUPPORTED_DUMP_EXTENSIONS = (".raw", ".mem", ".dmp", ".vmem", ".lime", ".img")

# Ollama connection
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
# Low temperature for forensic work: reproducibility matters more than
# creative phrasing. Re-running the same triage twice should produce the
# same set of flagged PIDs and IOCs.
OLLAMA_TEMPERATURE = 0.2

# Use a moderate default context window for better stability on normal laptops.
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "32768"))

OLLAMA_KEEP_ALIVE = -1      # keep model in memory forever (avoids reload lag)
# Use a smaller reply budget for normal chat so the UI feels responsive.
OLLAMA_FAST_NUM_PREDICT = int(
    os.getenv("OLLAMA_FAST_NUM_PREDICT", os.getenv("OLLAMA_NUM_PREDICT", "4096"))
)
# Allow deeper turns such as triage and report generation to run a bit longer.
OLLAMA_DEEP_NUM_PREDICT = int(os.getenv("OLLAMA_DEEP_NUM_PREDICT", "6144"))
OLLAMA_NUM_BATCH = int(os.getenv("OLLAMA_NUM_BATCH", "256"))

# GPU offloading — -1 means "put all layers on GPU".
# Lower this (e.g. 20) if you run out of VRAM.
OLLAMA_NUM_GPU = int(os.getenv("OLLAMA_NUM_GPU", "-1"))

# CPU thread count for layers that stay on CPU.
# None lets Ollama pick automatically, which is usually fine.
OLLAMA_NUM_THREAD = None
thread_env = os.getenv("OLLAMA_NUM_THREAD")
if thread_env is not None:
    OLLAMA_NUM_THREAD = int(thread_env)

# Sidebar context presets.
CTX_PRESETS = {
    "Small (16K)": 16384,
    "Standard (32K)": 32768,
    "Large (64K)": 65536,
}

# Volatility MCP server endpoint exposed by docker-compose
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")
# Kept for backwards-compatible diagnostics/messages. The app now connects over HTTP.
MCP_DOCKER_CONTAINER = os.getenv("MCP_DOCKER_CONTAINER", "volatility-mcp")

# Name tag for the LangGraph agent
AGENT_NAME = "memory-forensics-agent"
