"""
Core agent setup - builds a Deep Agent backed by Ollama and the Volatility MCP server.
"""

from __future__ import annotations

import logging
import hashlib
import re
import socket
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, AsyncIterator

import httpx
from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from deepagents.backends.utils import create_file_data
from langchain_core.tools import tool as langchain_tool
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_ollama import ChatOllama

from agent.chat_routing import build_static_general_reply
from agent.memory_store import get_checkpointer, get_store
from agent.report_utils import build_report_header_comment, ensure_report_date, format_local_timestamp
from config.settings import (
    AGENT_NAME,
    MCP_DOCKER_CONTAINER,
    MCP_SERVER_URL,
    OLLAMA_BASE_URL,
    OLLAMA_DEEP_NUM_PREDICT,
    OLLAMA_FAST_NUM_PREDICT,
    OLLAMA_KEEP_ALIVE,
    OLLAMA_MODEL,
    OLLAMA_NUM_BATCH,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_GPU,
    OLLAMA_NUM_THREAD,
    OLLAMA_TEMPERATURE,
    REPORTS_DIR,
    SKILLS_DIR,
)

logger = logging.getLogger("forensics_agent")


SYSTEM_PROMPT = """\
You are AutoMem, a Windows memory-forensics analyst. Use Volatility3 MCP tools
to investigate dumps and report evidence-based findings.

# Available tools
Volatility plugin runners (one dump per call, no extra filter args):
  get_image_info, run_pslist, run_psscan, run_pstree, run_psxview,
  run_cmdline, run_netscan, run_malfind (pid optional), run_dlllist
  (pid optional), run_handles (pid optional), run_svcscan, run_amcache.
Cached drill-down: query_plugin_rows(plugin, memory_dump, filter_field,
  filter_value, filter_field_2, filter_value_2, filter_field_3,
  filter_value_3, max_rows). Plugin short names accepted: pslist, psscan,
  pstree, psxview, cmdline, netscan, malfind, dlllist, handles, svcscan,
  amcache.
Server / housekeeping: server_diagnostics, list_memory_dumps.
Reporting helpers: hash_evidence (hash IOC strings), save_report (persist
  the final Markdown report).
Do not call any plugin not on this list — it does not exist.

# Core rules
- Use the dump named in `[Selected dump: x]` unless the user names another.
- Never invent PIDs, names, IPs, paths, or command lines. Cite tool output.
- Separate observed evidence from interpretation, and state confidence.
- Pick tools by what the question needs; don't run plugins you don't need.
- For large results, read `statistics` and `sample_data` first, then use
  `query_plugin_rows` to drill into specific PIDs/ports/paths. Don't rerun
  the same plugin to see more rows.
- `run_*` tools take only their documented args. Filtering args go to
  `query_plugin_rows` only.
- Keep tool use focused; most reports finish in 6-10 calls. Use more if the
  evidence genuinely needs it.

# Identifying suspicious processes
Use your judgement on the full picture — name, path, parent, command line,
network activity, injected memory. Common red flags include processes running
from user-writable paths (Temp, Public, AppData, Downloads), system-process
names from non-system paths, unusual parents, names off-by-one from real
binaries, hidden/unlinked processes (in psscan but not pslist), and unexpected
network listeners or C2-style connections. These are signals, not a checklist —
weigh evidence together and report what the data actually shows.

# OS identification
Use `NTBuildLab` from `windows.info.Info` for the Windows version. The
`Major/Minor` row is kernel metadata and is unreliable. Cite the exact
NTBuildLab string as evidence.

# Plugin / OS compatibility
Once you know the OS from NTBuildLab, do NOT call plugins it does not
support. On Windows XP / Server 2003 (`2600.xpsp...`):
- `run_netscan` is unsupported and errors out. Treat absent network data as a
  limitation, not evidence of cleanliness.
- `run_amcache` finds no records (Amcache is Windows 7+, sparse on Win7,
  reliable on Windows 8+). Don't run it on XP.
- `run_svcscan` may report a `null` Binary/ImagePath for kernel-mode services;
  a missing path alone is not suspicious.
On Windows 7+ these plugins are fine. Pick alternatives when blocked rather
than retrying the same tool.

# Using run_amcache
Amcache records every executable that ran on the host (Path, SHA1Hash,
InstallDate, Company, etc.) and routinely returns hundreds to thousands of
rows. Workflow:
1. Call `run_amcache` ONCE per dump. Read `statistics` (top_paths, top_names)
   and `sample_data`; never re-run to "see more rows".
2. Drill in with `query_plugin_rows("amcache", dump, filter_field=..., filter_value=...)`
   on Path (e.g. `AppData`, `Temp`, `Public`, `Downloads`), SHA1Hash, or
   EntryType. Combine filters via filter_field_2 / filter_value_2 for narrow
   matches.
3. Amcache `SHA1Hash` values are real file hashes — list them as file hashes
   in the IOC table and flag them as suitable for VirusTotal lookup.

# Evidence hashing
Call `hash_evidence` on exact suspicious indicator strings (IPs, domains,
paths, command lines) for IOC reporting. These are string hashes, NOT
file-content hashes — only Amcache `SHA1Hash` values qualify as real file
hashes for VirusTotal.

# Answer format
Finding: one or two sentences with PID/IP/path evidence.
Evidence: plugin -> key values.
Confidence: High / Medium / Low — one-line reason.
Limitations: what wasn't checked.
Next step: one best follow-up.

# Formal report format
Start with "# Memory Forensics Analysis Report" and use these sections:
1. Executive Summary  2. System Profile  3. Process Analysis
4. Network Analysis  5. Persistence  6. Injection / Code Analysis
7. IOC Summary Table  8. Evidence Hashes / VirusTotal Lookup Notes
9. Recommendations  10. Limitations
Fill every section with cited evidence or "Evidence not collected in this pass."
No bracket/brace placeholders. Use the harness-supplied local time. Call
`save_report` to finish.

# Failure handling
If a tool fails, don't retry the same call. State the plugin, error, likely
cause, and single best fix. If a requested tool isn't available, proceed with
the closest alternative and state which one in one sentence.
"""


GENERAL_CHAT_SYSTEM_PROMPT = """\
You are AutoMem, a friendly memory-forensics assistant for a university FYP demo.
For general questions, explain concepts clearly without calling tools. If the
user asks for analysis of a dump, remind them to initialize the agent and select
a dump so Volatility evidence can be collected. Do not pretend that analysis was
performed unless a tool result is available.
"""


def build_mcp_connection(server_url: str = MCP_SERVER_URL) -> dict[str, dict]:
    """Return the MCP client config for the Volatility HTTP server."""
    return {
        "volatility": {
            "transport": "http",
            "url": server_url,
        }
    }


def check_mcp_server_status(server_url: str = MCP_SERVER_URL) -> tuple[bool, str]:
    """Return whether the MCP HTTP endpoint is reachable.

    A TCP check is more reliable than a GET request because MCP endpoints may
    reject non-MCP GETs before protocol negotiation.
    """
    parsed = urlparse(server_url)
    host = parsed.hostname or "localhost"
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80

    try:
        with socket.create_connection((host, port), timeout=5):
            return True, ""
    except OSError as err:
        return False, (
            f"Volatility MCP server is not reachable at `{server_url}`. "
            "Run `docker compose up -d --build` from the project root, then "
            "check `docker compose ps`. "
            f"Details: {err}"
        )


def check_mcp_container_status(container_name: str = MCP_DOCKER_CONTAINER) -> tuple[bool, str]:
    """Backward-compatible wrapper used by older tests/messages."""
    return check_mcp_server_status(MCP_SERVER_URL)

def load_skill_files() -> dict[str, Any]:
    """Read all .md skill files and pack them for the agent's virtual filesystem."""
    files: dict[str, Any] = {}
    if SKILLS_DIR.is_dir():
        for skill_path in SKILLS_DIR.glob("*.md"):
            key = f"/skills/{skill_path.name}"
            text = skill_path.read_text(encoding="utf-8")
            files[key] = create_file_data(text)
    return files


def _safe_report_stem(value: str | None) -> str:
    stem = Path(value or "memory_forensics").stem
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._-")
    return stem or "memory_forensics"


def _report_quality_error(content: str) -> str | None:
    """Return a save-blocking report quality error, if one is obvious."""
    lowered = content.lower()
    placeholder_markers = (
        "[details from",
        "(details from",
        "[summary of",
        "(summary of",
        "[current date/time",
        "(current date/time",
        "would be inserted here",
        "insert here",
        "{time_or_",
        "{event}",
        "{plugin}",
        "{action_",
        "{finding_",
    )
    if any(marker in lowered for marker in placeholder_markers):
        return "Report still contains template placeholders. Replace every placeholder with evidence or an explicit limitation before saving."

    planning_markers = (
        "i will now generate",
        "i will now compile",
        "previous steps have gathered sufficient evidence",
    )
    if any(marker in lowered for marker in planning_markers):
        return "Report content looks like planning text rather than the final report."

    # Catch wrong OS identification: model misreads the Major/Minor row instead of NTBuildLab
    bad_os_patterns = (
        "os version: 15.2600",
        "windows 10/server era",
        "windows server 2016 era",
        "consistent with a windows server 2016",
    )
    if any(p in lowered for p in bad_os_patterns):
        return (
            "Report contains an incorrect OS version derived from the windows.info Major/Minor row. "
            "Use NtMajorVersion, NtMinorVersion, CSDVersion, and NTBuildLab to determine the "
            "correct OS profile."
        )

    return None


def _report_os_warning(content: str) -> str | None:
    """Return a soft analyst warning when the OS section looks wrong, or None if OK.

    Unlike _report_quality_error this does NOT block the save — the warning is
    prepended to the report as an HTML comment so analysts can review it.
    """
    lowered = content.lower()
    rs_builds = ("rs4_release", "rs5_release", "rs3_release", "rs2_release", "rs1_release",
                 "th2_release", "th1_release", "vb_release", "co_release", "fe_release")
    win10_buildlabs = any(b in lowered for b in rs_builds)
    false_downgrade = any(w in lowered for w in ("windows 7", "windows xp", "windows vista",
                                                  "windows server 2003", "windows server 2008"))
    if not (win10_buildlabs and false_downgrade):
        return None

    rs_label = next((b for b in rs_builds if b in lowered), "rs4_release")
    rs_map = {
        "rs4_release": "Windows 10 RS4 (Version 1803, April 2018 Update)",
        "rs5_release": "Windows 10 RS5 (Version 1809, October 2018 Update)",
        "rs3_release": "Windows 10 RS3 (Version 1709, Fall Creators Update)",
        "rs2_release": "Windows 10 RS2 (Version 1703, Creators Update)",
        "rs1_release": "Windows 10 RS1 (Version 1607, Anniversary Update)",
        "th2_release": "Windows 10 TH2 (Version 1511)",
        "th1_release": "Windows 10 TH1 (Version 1507)",
        "vb_release":  "Windows 10 VB (Version 2004)",
        "co_release":  "Windows 11 CO (Version 21H2)",
        "fe_release":  "Windows 11 FE (Version 22H2)",
    }
    correct_os = rs_map.get(rs_label, "Windows 10 (Redstone era)")
    return (
        f"<!-- ANALYST NOTE: OS section may be incorrect. "
        f"NTBuildLab '{rs_label}' indicates {correct_os}. "
        f"The 'Major/Minor' row in windows.info is kernel PE metadata, not the Windows version. "
        f"Verify OS identification manually. -->"
    )


def _normalize_hash_inputs(indicators: list[str] | str) -> list[str]:
    """Return a small ordered list of non-empty indicator strings."""
    if isinstance(indicators, str):
        values = [line.strip() for line in indicators.splitlines()]
    else:
        values = [str(value).strip() for value in indicators]
    cleaned: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        cleaned.append(value)
        seen.add(value)
        if len(cleaned) >= 20:
            break
    return cleaned


@langchain_tool
def hash_evidence(indicators: list[str] | str, context: str = "") -> dict[str, Any]:
    """Hash exact suspicious evidence strings for IOC reporting.

    This hashes the string value supplied to the tool. It does not hash file
    contents unless the caller supplies an actual file hash or bytes-derived
    value from another tool.
    """
    values = _normalize_hash_inputs(indicators)
    rows = []
    for value in values:
        raw = value.encode("utf-8", errors="replace")
        rows.append({
            "value": value,
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return {
        "context": context,
        "hash_scope": "exact_indicator_string",
        "warning": (
            "These are hashes of the exact indicator strings, not file-content "
            "hashes unless the input value was already derived from file bytes. "
            "Use VirusTotal file lookup only for real file hashes or known "
            "malware hashes."
        ),
        "count": len(rows),
        "items": rows,
    }


@langchain_tool
def save_report(content: str, memory_dump: str | None = None, filename: str | None = None) -> dict[str, str]:
    """Save a Markdown forensic report under the local reports directory."""
    quality_error = _report_quality_error(content)
    if quality_error:
        return {
            "status": "rejected",
            "error": quality_error,
        }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    now = format_local_timestamp()
    report_body = ensure_report_date(content)

    # Soft OS warning — prepend as an HTML comment but don't block the save
    os_warning = _report_os_warning(content)
    if os_warning:
        logger.warning("OS identification warning in report: %s", os_warning)
        report_body = os_warning + "\n\n" + report_body

    timestamp = now.replace(":", "").replace("-", "").replace(" ", "_")
    if filename:
        # Always append timestamp so re-runs never overwrite a prior report.
        # Strip any pre-existing timestamp suffix (digits/+/-) before appending
        # so a model that re-passes the prior report name doesn't stack timestamps.
        stem = re.sub(r"[_\s]\d{8}[_\s]\d{6}.*$", "", Path(filename).stem)
        stem = stem or Path(filename).stem  # fallback if regex strips everything
        report_name = f"{stem}_{timestamp}.md"
    else:
        report_name = f"{_safe_report_stem(memory_dump)}_report_{timestamp}.md"

    report_path = REPORTS_DIR / report_name
    report_path.write_text(
        build_report_header_comment() + report_body + "\n",
        encoding="utf-8",
    )
    logger.info("Saved report to %s", report_path)
    return {
        "status": "saved",
        "filename": report_path.name,
        "path": str(report_path),
        "analyst_note": os_warning or None,
    }


def build_agent_resources():
    """Create the shared state objects used by both fast and deep agents."""
    checkpointer = get_checkpointer()
    store = get_store()
    backend = CompositeBackend(
        default=StateBackend(),
        routes={
            "/memories/": StoreBackend(
                namespace=lambda ctx: ("forensics",),
            ),
        },
    )
    return checkpointer, store, backend


async def get_mcp_tools() -> list:
    """Connect to the Volatility MCP server and grab the list of available tools."""
    server_ok, server_error = check_mcp_server_status()
    if not server_ok:
        raise RuntimeError(server_error)
    client = MultiServerMCPClient(build_mcp_connection())
    tools = await client.get_tools()
    logger.info("Loaded %d MCP tools from Volatility server", len(tools))
    return tools


async def check_ollama_status(base_url: str = OLLAMA_BASE_URL) -> dict:
    """Quick health check - is Ollama running and what model is loaded?

    Returns {"online": bool, "models_loaded": [...]}.
    """
    info: dict[str, Any] = {"online": False, "models_loaded": []}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/api/ps")
            if resp.status_code == 200:
                info["online"] = True
                for entry in resp.json().get("models", []):
                    info["models_loaded"].append({
                        "name": entry.get("name", "?"),
                        "size_gb": round(entry.get("size", 0) / 1e9, 1),
                        "processor": entry.get("size_vram", 0),
                        "details": entry.get("details", {}),
                    })
    except Exception as err:
        logger.warning("Ollama status check failed (%s): %s", base_url, err)
    return info


async def preload_ollama_model(
    base_url: str = OLLAMA_BASE_URL,
    model: str = OLLAMA_MODEL,
    num_ctx: int = OLLAMA_NUM_CTX,
) -> bool:
    """Warm up the model in Ollama so the first real chat doesn't wait for a cold start."""
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                f"{base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [],
                    "keep_alive": -1,
                    "options": {
                        "num_ctx": num_ctx,
                        "num_gpu": OLLAMA_NUM_GPU,
                    },
                },
            )
            if resp.status_code == 200:
                logger.info("Model %s preloaded (num_ctx=%d)", model, num_ctx)
                return True
            logger.warning("Preload returned status %d", resp.status_code)
    except Exception as err:
        logger.warning("Could not preload model: %s", err)
    return False


async def create_forensics_agent(
    mcp_tools: list | None = None,
    thread_id: str = "default",
    *,
    model_name: str = OLLAMA_MODEL,
    base_url: str = OLLAMA_BASE_URL,
    thinking_mode: bool = False,
    num_ctx: int = OLLAMA_NUM_CTX,
    num_predict: int | None = None,
    checkpointer=None,
    store=None,
    backend=None,
):
    """Build the forensics agent and return (graph, config, skill_files).

    Connects to MCP if tools aren't provided, warms up the model if it's
    not already loaded, and wires up the two specialist sub-agents.
    """
    if mcp_tools is None:
        mcp_tools = await get_mcp_tools()

    status = await check_ollama_status(base_url)
    model_is_loaded = any(
        m["name"] == model_name for m in status.get("models_loaded", [])
    )
    if not model_is_loaded:
        await preload_ollama_model(base_url, model_name, num_ctx)
    else:
        logger.info("Model %s already loaded, skipping preload", model_name)

    if num_predict is None:
        if thinking_mode:
            num_predict = OLLAMA_DEEP_NUM_PREDICT
        else:
            num_predict = OLLAMA_FAST_NUM_PREDICT

    llm = build_chat_model(
        model_name=model_name,
        base_url=base_url,
        thinking_mode=thinking_mode,
        num_ctx=num_ctx,
        num_predict=num_predict,
    )

    if checkpointer is None or store is None or backend is None:
        checkpointer, store, backend = build_agent_resources()

    # Hard guard for both sub-agents: if the parent agent forgets to inline
    # the dump filename in the task description, calling any run_* tool with
    # no `memory_dump` argument crashes the MCP server. We refuse to take a
    # single tool action and bounce back to the parent instead.
    _DUMP_GUARD = (
        "MANDATORY FIRST CHECK before any tool call:\n"
        "Scan the task description for a memory dump filename (must end in "
        ".raw, .mem, .dmp, .vmem, .lime, .bin, or contain '/dumps/'). "
        "If NONE is present, do NOT call any tool. Reply with exactly:\n"
        "  'ERROR: task description has no memory dump filename. "
        "Re-issue with the dump name (e.g. sample.raw).'\n"
        "and stop. Never guess a filename. Never call run_* tools without "
        "a memory_dump argument.\n\n"
    )

    malware_subagent = {
        "name": "malware-analyst",
        "description": (
            "Use for deep malware-focused work on a named memory dump and "
            "specific PIDs or indicators: code injection, malfind follow-up, "
            "DLL path anomalies, handles, hollowed processes, mutex/registry "
            "artifacts. Do not use for broad netscan-only questions."
        ),
        "system_prompt": (
            "You are a malware analyst sub-agent. You only have Volatility MCP tools.\n\n"
            + _DUMP_GUARD +
            "Rules:\n"
            "- Work from explicit PIDs or IOCs passed in the task; if missing, ask "
            "the parent to supply the dump filename and target PIDs.\n"
            "- Prefer `run_malfind`, `run_dlllist`, `run_handles`, and `run_cmdline` "
            "as appropriate. Narrow scope before full-dump scans.\n"
            "- Every claim must cite tool output (plugin + PID or offset). If JSON "
            "is truncated, say so and rate confidence accordingly.\n"
            "- Return a compact briefing: findings table, confidence per row, "
            "gaps, and suggested next tools for the lead analyst."
        ),
        "tools": mcp_tools,
    }

    network_subagent = {
        "name": "network-analyst",
        "description": (
            "Use for network-centric analysis on a named memory dump: "
            "interpreting `run_netscan` output, mapping foreign IPs and listening "
            "ports to PIDs/process names, C2 or exfil hypotheses. Delegate here when "
            "netscan data is large or needs systematic correlation."
        ),
        "system_prompt": (
            "You are a network forensics sub-agent with Volatility MCP tools.\n\n"
            + _DUMP_GUARD +
            "Rules:\n"
            "- Start from `run_netscan` on the given dump. Tie each suspicious "
            "endpoint to a PID and process name (use `run_pslist` / `run_cmdline` "
            "when names are missing).\n"
            "- Call out truncated or partial netscan JSON; do not over-assert.\n"
            "- Flag unusual ports, rare remote ASNs/IPs, listeners without obvious "
            "service names, and processes that should not have network I/O.\n"
            "- Return: summary table (PID, process, remote, port, state, why "
            "suspicious), confidence tags, and open questions for the lead analyst."
        ),
        "tools": mcp_tools,
    }

    all_tools = list(mcp_tools) + [hash_evidence, save_report]
    middleware = []
    try:
        # Compaction layers:
        #   - Auto-trigger: `create_deep_agent` already installs a
        #     SummarizationMiddleware in its default stack (see
        #     deepagents/graph.py — `create_summarization_middleware`).
        #     Adding our own would collide on class name and trip the
        #     "duplicate middleware instances" guard in the langchain
        #     agent factory.
        #   - Manual tool: `SummarizationToolMiddleware` is a different
        #     class, so it doesn't collide. We give it a private
        #     SummarizationMiddleware instance (NOT registered as
        #     middleware) purely so its `compact_conversation` tool uses
        #     the same summary format the auto-trigger would produce.
        from deepagents.middleware.summarization import (
            SummarizationMiddleware,
            SummarizationToolMiddleware,
        )

        summ_engine = SummarizationMiddleware(llm, backend=backend)
        middleware.append(SummarizationToolMiddleware(summ_engine))
        logger.info(
            "Context compression enabled: framework auto-trigger plus "
            "manual compact_conversation tool"
        )
    except Exception as err:
        logger.warning("Could not enable summarization tool middleware: %s", err)

    agent = create_deep_agent(
        model=llm,
        tools=all_tools,
        system_prompt=SYSTEM_PROMPT,
        middleware=middleware,
        subagents=[malware_subagent, network_subagent],
        skills=["/skills/"],
        memory=["/memories/session_notes.md"],
        backend=backend,
        checkpointer=checkpointer,
        store=store,
        name=AGENT_NAME,
        debug=False,
    )

    config = {"configurable": {"thread_id": thread_id}}
    skill_files = load_skill_files()

    return agent, config, skill_files


def build_chat_model(
    *,
    model_name: str = OLLAMA_MODEL,
    base_url: str = OLLAMA_BASE_URL,
    thinking_mode: bool = False,
    num_ctx: int = OLLAMA_NUM_CTX,
    num_predict: int | None = None,
):
    """Create a ChatOllama instance with the project's default runtime settings."""
    if num_predict is None:
        if thinking_mode:
            num_predict = OLLAMA_DEEP_NUM_PREDICT
        else:
            num_predict = OLLAMA_FAST_NUM_PREDICT

    llm_kwargs: dict[str, Any] = {
        "model": model_name,
        "base_url": base_url,
        "temperature": OLLAMA_TEMPERATURE,
        "num_ctx": num_ctx,
        "num_predict": num_predict,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "num_batch": OLLAMA_NUM_BATCH,
        "num_gpu": OLLAMA_NUM_GPU,
        "profile": {"max_input_tokens": num_ctx},
        "disable_streaming": "tool_calling",
    }
    if OLLAMA_NUM_THREAD is not None:
        llm_kwargs["num_thread"] = OLLAMA_NUM_THREAD

    return ChatOllama(**llm_kwargs, reasoning=thinking_mode)


async def answer_general_question(
    user_message: str,
    *,
    model_name: str = OLLAMA_MODEL,
    base_url: str = OLLAMA_BASE_URL,
    thinking_mode: bool = False,
    num_ctx: int = OLLAMA_NUM_CTX,
) -> str:
    """Answer simple general questions without invoking the tool-using agent."""
    static_reply = build_static_general_reply(user_message)
    if static_reply:
        return static_reply

    llm = build_chat_model(
        model_name=model_name,
        base_url=base_url,
        thinking_mode=thinking_mode,
        num_ctx=num_ctx,
    )
    system_prompt = (
        f"{GENERAL_CHAT_SYSTEM_PROMPT}\n\n"
        f"Current local analysis time: {format_local_timestamp()}."
    )
    response = await llm.ainvoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message),
        ]
    )
    content = getattr(response, "content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return "".join(
            item if isinstance(item, str) else str(item)
            for item in content
        ).strip()
    return str(content).strip()


async def stream_agent(
    agent,
    user_message: str,
    config: dict,
    files: dict | None = None,
) -> AsyncIterator[dict]:
    """Stream agent events back to the UI so it can update in real time."""
    input_data: dict[str, Any] = {
        "messages": [{"role": "user", "content": user_message}],
    }
    if files:
        input_data["files"] = files

    async for event in agent.astream(input_data, config=config):
        yield event
