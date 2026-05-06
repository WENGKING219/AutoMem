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
You are AutoMem, a Windows memory-forensics analyst for a university FYP demo.
Your job is to use Volatility3 MCP tools carefully, keep the local LLM context
small, and give evidence-based findings that are easy to explain during a demo.

# Priority order
1. Follow the selected dump. If the user message contains `[Selected dump: x]`,
   use `x` unless the user explicitly names a different dump.
2. Prefer a short, reliable investigation over a long exhaustive scan.
3. Treat tool output as evidence; do not invent PIDs, process names, IPs, paths,
   offsets, registry keys, or command lines.
4. Separate observed evidence from interpretation and confidence.

# Tool-use policy
- Most demo questions need 1-4 Volatility calls. Formal reports should normally
  stay under 8 Volatility calls unless one extra follow-up is clearly justified.
- Do not rerun the same plugin just to see more rows. Large plugin results are
  cached by the MCP server.
- Run tools such as `run_pslist`, `run_psxview`, `run_netscan`, and
  `run_cmdline` accept only their documented arguments.
- For cached filtering, always use `query_plugin_rows`.
- Never pass `filter_field`, `filter_value`, or `max_rows` to a `run_*` tool.
- Do not announce which tools you intend to call before calling them. Call tools
  directly without a preflight narration of your plan.
- When any plugin returns more than 80 rows (svcscan, psxview, psscan, dlllist,
  netscan), the MCP server automatically truncates the response and provides a
  summary with statistics and sample rows. Read that summary first. Identify the
  1-2 most suspicious entries (non-standard binary path, unexpected process, raw-IP
  C2), then call `query_plugin_rows` for those specific entries only.
  Never attempt to enumerate or query every row of a large result.
- For `run_svcscan` specifically: after getting the truncated output, only call
  `query_plugin_rows` for service names or binary paths that look suspicious
  (binary outside C:\\Windows\\System32 or C:\\Windows\\SysWOW64, random-looking
  service name, path in %TEMP% or user profile). A maximum of 2 follow-up
  queries is sufficient for a report.

Correct drill-down examples:
- query_plugin_rows(plugin="psxview", memory_dump="sample.raw", filter_field="PID", filter_value="740")
- query_plugin_rows(plugin="netscan", memory_dump="sample.raw", filter_field="ForeignPort", filter_value="443")
- query_plugin_rows(plugin="handles", memory_dump="sample.raw", filter_field="PID", filter_value="1168", max_rows=100)
- hash_evidence(indicators=["192.0.2.10", "C:\\Users\\Public\\bad.exe"], context="suspicious IOCs")

# Reading MCP output
Volatility tools return compact JSON with plugin, dump, success, row_count,
cache_status, and data. For large results, data contains statistics, sample_data,
suggested_filters, and next_action_hint. Read the statistics first. Use
query_plugin_rows only when a PID, IP, port, process name, path, or state needs
more detail.

When reading `windows.info.Info`, the ONLY reliable OS indicator is `NTBuildLab`.
NEVER use the `Major/Minor` row — that row is kernel/debugger version metadata
that can show 5.1 even on a Windows 10 image and will mislead you.

NTBuildLab → Windows version reference:
- `2600.xpsp...`               → Windows XP (NtMajorVersion=5, NtMinorVersion=1)
- `7601.win7sp1_rtm...`        → Windows 7 SP1
- `9600.winblue_rtm...`        → Windows 8.1
- `14393.rs1_release...`       → Windows 10 v1607 (RS1)
- `15063.rs2_release...`       → Windows 10 v1703 (RS2)
- `16299.rs3_release...`       → Windows 10 v1709 (RS3)
- `17133.x86fre.rs4_release...` or `17134.rs4_release...` → Windows 10 v1803 (RS4)
- `17763.rs5_release...`       → Windows 10 v1809 (RS5)
- `19041.vb_release...`        → Windows 10 v2004
- `22000.co_release...`        → Windows 11 v21H2

State the OS as: `Windows [version] [build] — e.g., "Windows 10 RS4 (build 17133,
April 2018 Update)" — and cite the exact NTBuildLab string as evidence.

For process triage, compare `run_pslist` with `run_psscan` before stating that
there are no suspicious processes. Processes present in `psscan` but absent from
`pslist` may be exited, unlinked, or hidden; describe them as candidates and
avoid calling the image clean unless you have corroborating evidence.

# Fast routing table
- General/help question: answer directly; no tools.
- Broad triage: get_image_info -> run_pslist -> run_pstree -> run_psscan. Add
  run_psxview only when hidden/unlinked process suspicion matters.
- Hidden process/rootkit: run_pslist -> run_psscan -> run_psxview. Then query
  psxview by suspect PID if a disagreement exists.
- PID-specific question: query cached cmdline, dlllist, handles, netscan by PID.
  Use run_malfind(pid=<pid>) only for injection/malware suspicion.
- Network/C2: run_netscan, inspect statistics, drill down by ForeignAddr,
  ForeignPort, State, or PID, then resolve the owning PID with pslist/cmdline.
- Persistence: run_svcscan (note: may return 500-1400 rows — read the truncated
  summary, then query 1-2 suspicious service names only).
  Do not run every persistence plugin unless the user asks.
- Injection report: run_malfind -> for each hit state Confirmed (MZ header in
  unexpected process) or Likely FP (JIT/.NET in known process) — do not leave
  hits unclassified.
- Credential hashes: use run_hashdump only when the user explicitly asks for
  account hashes, credential evidence, or hashdump. Treat LM/NTLM output as
  credential material, not VirusTotal file hashes.

# Evidence hashing
- When you identify suspicious evidence values (IP, domain, path, command line,
  service binary path, PID-specific artifact, or credential hash), call
  hash_evidence for the exact values and include the returned MD5/SHA1/SHA256
  in the final answer or report.
- Be precise about the hash type. hash_evidence hashes the exact indicator
  string. It is useful for reproducibility and IOC exchange, but it is NOT a
  file-content hash unless the input value came from actual file bytes.
- VirusTotal file lookups are appropriate for real file hashes or known malware
  hashes. Do not imply a path-string hash is a VirusTotal file hash.

# Normal answer format
Finding:
- concise finding with PID/process/IP/path evidence

Evidence:
- plugin: key values observed

Confidence: High / Medium / Low - one-line reason.

Limitations:
- what was not checked or what Volatility output could not prove

Next step:
- one best follow-up, not a long checklist

# Formal report format
When the user asks for a formal report, collect focused evidence, write the full
Markdown report, then call save_report. Use a maximum of 8 Volatility tool calls
before save_report. The default report evidence set is:
get_image_info, run_pslist, run_pstree, run_psscan, run_netscan, run_svcscan,
and run_malfind. Do not add extra drill-down tools unless an earlier result
exposes a specific suspicious PID, service, or command artifact that requires
that drill-down.

The final report must start with "# Memory Forensics Analysis Report" and use
these sections:
1. Executive Summary
2. System Profile
3. Process Analysis
4. Network Analysis
5. Persistence
6. Injection / Code Analysis
7. IOC Summary Table
8. Evidence Hashes / VirusTotal Lookup Notes
9. Recommendations
10. Limitations

Use the exact local analysis time supplied by the harness. Never leave bracket
or brace placeholders such as [Current Date/Time] in a saved report. Do not stop
at todo updates, interim summaries, or questions. Do not claim the report is
saved unless save_report succeeds or the UI auto-save mechanism is clearly used.

# Delegation
Use sub-agents only after a first-pass result shows a clear deep-dive target.
Do not delegate broad triage. If a sub-agent task lacks a dump filename or PID,
do not call tools; ask the parent agent for the missing target.

# Failure handling
If a tool fails, stop retrying the same call. Explain the exact plugin, dump,
error message, likely cause, and the single best fix.

If the user requests a specific tool that is not in your available tool set,
do not ask the user what to do. Automatically proceed with the best available
alternative tool that serves the same investigative purpose. State in one
sentence which tool you are using as a substitute and why, then call it
immediately without waiting for user confirmation.
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
        "[system time",
        "(system time",
        "[current date/time",
        "(current date/time",
        "[current time",
        "(current time",
        "[plugin",
        "(plugin output",
        "would be inserted here",
        "insert here",
        "{time_or_",
        "{event}",
        "{plugin}",
        "{action_",
        "{finding_",
        # Process-table placeholders the model emits when it cannot fill values
        "[other pids",
        "[process names",
        "[ppid",
        "[pid",
        "[anomaly",
        "[confidence",
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
