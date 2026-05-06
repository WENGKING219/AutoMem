# AutoMem

AutoMem is a local Windows memory-forensics assistant for Final Year Project demonstrations. It combines a Streamlit chat interface, a local Ollama model, and a FastMCP service that exposes Volatility3 tools for evidence-driven memory dump analysis.

The project is designed to keep forensic work local: memory dumps stay on the machine, Volatility runs inside Docker, and the language model runs through Ollama.

## Architecture

```text
Streamlit UI -> DeepAgents / LangChain -> HTTP MCP Server -> Volatility3
                       |
                       +-> Ollama local LLM
```

The Volatility MCP server runs as an HTTP service at `http://localhost:8000/mcp`. The Streamlit app connects to that endpoint directly.

## Features

- Streamlit chat UI for guided memory-forensics workflows.
- Local Ollama model support with configurable context presets.
- FastMCP wrapper around common Volatility3 Windows plugins.
- Dockerized Volatility backend with a persistent cache volume.
- Result caching and row filtering through `query_plugin_rows` for large plugin output.
- Demo-focused quick actions for triage, hidden process checks, network review, credential hash checks, and report generation.
- Markdown report generation with evidence hashing for exact indicators.
- Pytest coverage for MCP contracts, helper behavior, cache handling, prompt safety, and response quality.

## Repository Layout

```text
agent/                  LangChain/DeepAgents setup, routing, memory, and report helpers
agent/skills/           Local forensic instruction files used by the agent
config/                 Central application settings
frontend/               Streamlit UI, upload helpers, chat history utilities, and assets
volatility_mcp_server/  FastMCP Volatility3 service and runner
tests/                  Unit and contract tests
docker-compose.yml      Local Volatility MCP service definition
pyproject.toml          Python project metadata and dependencies
uv.lock                 Locked dependency versions
```

Generated files are intentionally not committed. Keep memory dumps in `memory_dumps/`, reports in `reports/`, and runtime logs in `logs/`.

## Prerequisites

- Python 3.11 or newer.
- `uv` for dependency management.
- Docker Desktop or Docker Engine with Docker Compose.
- Ollama with at least one local chat model pulled.
- A Windows memory dump in one of these formats: `.raw`, `.mem`, `.dmp`, `.vmem`, `.lime`, or `.img`.

Default model: `gemma4:e4b`.

## Setup

Install Python dependencies:

```bash
uv sync --python 3.12
```

Start the Volatility MCP backend:

```bash
docker compose up -d --build
```

Check the service:

```bash
docker compose ps
docker inspect -f "{{.State.Health.Status}}" volatility-mcp
```

Start Ollama and pull the default model:

```bash
ollama serve
ollama pull gemma4:e4b
```

If you prefer another model, set it in the Streamlit sidebar or override `OLLAMA_MODEL`.

Add memory dumps through the Streamlit sidebar uploader, or place files directly in:

```text
memory_dumps/
```

Launch the app:

```bash
uv run streamlit run frontend/app.py
```

Open:

```text
http://localhost:8501
```

## Configuration

Main settings live in `config/settings.py`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama endpoint |
| `OLLAMA_MODEL` | `gemma4:e4b` | Default local model |
| `OLLAMA_NUM_CTX` | `32768` | Default context window |
| `OLLAMA_FAST_NUM_PREDICT` | `4096` | Normal response token budget |
| `OLLAMA_DEEP_NUM_PREDICT` | `6144` | Deeper triage/report token budget |
| `MCP_SERVER_URL` | `http://localhost:8000/mcp` | FastMCP HTTP endpoint |

Docker service settings live in `docker-compose.yml`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DUMPS_DIR` | `/data/memory_dumps` | Mounted dump directory inside the container |
| `CACHE_DIR` | `/data/cache/results` | AutoMem parsed result cache |
| `VOL_FRAMEWORK_CACHE_DIR` | `/data/cache/volatility3-2.27-symbolpack-v1` | Volatility framework cache |
| `VOL_SYMBOL_DIRS` | `/app/symbols` | Windows symbol pack directory |
| `VOL_TIMEOUT` | `300` | Default plugin timeout in seconds |
| `MAX_ROWS_FULL` | `80` | Row count returned before compact summarization |

## Volatility Cache Design

AutoMem uses a Docker named volume called `volatility_cache`.

| Cache | Container Path | Purpose |
| --- | --- | --- |
| Volatility framework cache | `/data/cache/volatility3-2.27-symbolpack-v1` | Volatility symbols and framework cache |
| AutoMem result cache | `/data/cache/results` | Parsed plugin rows for fast drill-downs |

Large plugin output is normalized and cached once. The agent can then call `query_plugin_rows` to retrieve focused evidence by PID, process name, IP, port, path, or state without sending huge tables back through the local LLM.

Example workflow:

```python
run_psxview(memory_dump="sample.raw")
query_plugin_rows(
    plugin="psxview",
    memory_dump="sample.raw",
    filter_field="PID",
    filter_value="740",
)
```

To clear Docker cache data:

```bash
docker compose down -v
docker compose up -d --build
```

## Common MCP Tools

| Tool | Purpose |
| --- | --- |
| `server_diagnostics` | MCP server, dump directory, and cache diagnostics |
| `list_memory_dumps` | Supported dumps available to the backend |
| `get_image_info` | OS/build metadata |
| `run_pslist` | Active process listing |
| `run_psscan` | Pool scan for hidden or terminated processes |
| `run_pstree` | Parent/child process tree |
| `run_psxview` | Cross-view hidden-process validation |
| `run_netscan` | Connections and listening sockets |
| `run_cmdline` | Process command lines |
| `run_malfind` | Suspicious or injected memory regions |
| `run_dlllist` | Loaded DLL/module review for targeted PIDs |
| `run_handles` | File, registry, and mutex handles for targeted PIDs |
| `run_svcscan` | Windows service review |
| `run_hashdump` | LM/NTLM credential hash extraction when explicitly requested |
| `hash_evidence` | MD5/SHA1/SHA256 hashing for exact indicator strings |
| `query_plugin_rows` | Cached row filtering for focused drill-downs |

## Testing

Run the local test suite:

```bash
uv run pytest -q
```

Run a syntax check:

```bash
uv run python -m compileall -q agent config frontend volatility_mcp_server tests
```

Docker may not run inside restricted sandboxes. On a normal development machine, validate the container with:

```bash
docker compose up -d --build
docker compose ps
```

## Troubleshooting

### MCP server is not reachable

Start or rebuild the backend:

```bash
docker compose up -d --build
docker compose ps
```

Check that port `8000` is not already used by another process.

### VMware `.vmem` files

AutoMem passes standalone `.vmem` files directly to Volatility3. If Volatility reports that snapshot metadata is required, place the matching `.vmss` or `.vmsn` file beside the `.vmem` and rerun the plugin.

### Windows symbol errors

The Docker image installs the official Volatility Windows symbol pack into `/app/symbols/windows.zip` and uses the configured symbol directory when running plugins. If you rebuild without internet access and see missing type errors such as `_ETHREAD` or `symbol_table_name`, rebuild once with internet access so the symbol pack can be downloaded.

### Large context settings are unstable

Use the 32K context preset for normal laptop demos. Larger contexts can be slower or unstable depending on the local Ollama model and available VRAM.

## Academic Use

AutoMem was developed as an academic Final Year Project. Use it only on memory images you are authorized to analyze.
