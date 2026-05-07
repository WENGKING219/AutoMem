"""
Streamlit chat UI for the Memory Forensics Agent.

Chat flow (follows the official Streamlit conversational-app pattern):
  1. Render message history from session state
  2. Accept user input via a small form (or a quick-action button)
  3. Stream the assistant response inline - no extra st.rerun()
  4. Append the finished response to session state
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import re
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    CHAT_HISTORY_FILE,
    CTX_PRESETS,
    MEMORY_DUMPS_DIR,
    MCP_SERVER_URL,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_NUM_CTX,
    REPORTS_DIR,
    SUPPORTED_DUMP_EXTENSIONS,
    TURN_TRACE_FILE,
)
from agent.chat_routing import should_bypass_tools
from agent.memory_store import prune_threads
from agent.report_utils import build_report_header_comment, ensure_report_date, format_local_timestamp
from agent.response_quality import (
    build_tool_result_fallback,
    normalize_chat_reply,
    tool_calls_have_hard_errors,
)
from frontend.chat_history import (
    MAX_CHAT_HISTORIES,
    build_history_record,
    find_history,
    format_history_time,
    load_history_file,
    remove_history,
    save_history_file,
    upsert_history,
)
from frontend.upload_utils import save_uploaded_dump, uploaded_file_signature

logger = logging.getLogger("forensics_ui")


@dataclass(frozen=True)
class QuickAction:
    label: str
    icon: str
    prompt: str
    is_report: bool = False


def build_quick_actions(dump_name: str) -> list[QuickAction]:
    """Return small, demo-safe forensic workflows for one selected dump."""
    dump = dump_name.strip() or "selected dump"
    return [
        QuickAction(
            label="Initial Triage",
            icon=":material/radar:",
            prompt=(
                f"Triage {dump}. Start with get_image_info and run_pslist; "
                "add run_pstree or run_psscan if needed. Report any suspicious "
                "processes with evidence and confidence. Use query_plugin_rows "
                "to drill in on specific PIDs."
            ),
        ),
        QuickAction(
            label="Hidden Process",
            icon=":material/visibility_off:",
            prompt=(
                f"Find hidden or unlinked processes in {dump}. Compare run_pslist "
                "and run_psscan; investigate any disagreement with run_psxview and "
                "query_plugin_rows by PID. Report PID, name, and which views agree."
            ),
        ),
        QuickAction(
            label="Network",
            icon=":material/hub:",
            prompt=(
                f"Investigate network and persistence in {dump}. Run run_netscan "
                "and run_svcscan, then use query_plugin_rows on suspicious "
                "ports, PIDs, or service paths. Tie endpoints back to a process."
            ),
        ),
        QuickAction(
            label="Generate Report",
            icon=":material/description:",
            prompt=(
                f"Write the final memory-forensics report for {dump} now.\n"
                "Reuse evidence already collected in this conversation; only call "
                "a tool if a section has no usable data yet, and stop at 4 new "
                "calls. Skip tools that errored earlier (e.g. netscan on XP).\n"
                "Output one Markdown report starting with '# Memory Forensics "
                "Analysis Report' and the 10 sections from the system prompt, "
                "then call save_report once. Every section cites a tool result "
                "or states 'Evidence not collected in this pass.' No placeholders."
            ),
            is_report=True,
        ),
    ]


def tcp_endpoint_reachable(url: str, timeout: float = 0.5) -> bool:
    """Fast UI preflight check for local services."""
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_session_event_loop() -> asyncio.AbstractEventLoop:
    """Return a per-session event loop for async agent work."""
    loop = st.session_state.get("event_loop")
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        st.session_state.event_loop = loop
    return loop


def run_async(coro):
    """Run an async coroutine on the session's persistent event loop."""
    loop = get_session_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        asyncio.set_event_loop(None)


# â”€â”€ Cooperative cancellation â”€â”€
#
# Streamlit serialises script execution per session: while `run_until_complete`
# is blocking the script's main thread, no widget callback (including the Stop
# button) can run. That means relying on `st.session_state.cancel_requested`
# inside the streaming loop is a no-op â€” the value the loop reads is whatever
# was committed when the run started, and never changes mid-run.
#
# To actually be able to halt a turn we keep a process-wide
# `threading.Event` per `thread_id`. The streaming loop checks the event at
# every yield (between agent steps) AND every few seconds against a hard
# wall-clock turn budget. The Stop button still sets the event for the
# documented "next yield" semantics; the wall-clock budget is the real
# safety net against a stuck Ollama call.
_CANCEL_EVENTS: dict[str, threading.Event] = {}
_CANCEL_EVENTS_LOCK = threading.Lock()

# Hard upper bound on a single turn. A normal triage finishes well under
# this; anything longer is almost certainly a hung Ollama call or an
# infinite tool-call loop.
TURN_HARD_TIMEOUT_SEC = 600


def get_cancel_event(thread_id: str) -> threading.Event:
    """Return the shared cancel Event for a thread_id (created on first use)."""
    with _CANCEL_EVENTS_LOCK:
        event = _CANCEL_EVENTS.get(thread_id)
        if event is None:
            event = threading.Event()
            _CANCEL_EVENTS[thread_id] = event
        return event


def request_cancel(thread_id: str) -> None:
    """Signal the streaming loop for `thread_id` to stop after the next step."""
    get_cancel_event(thread_id).set()


def reset_cancel(thread_id: str) -> None:
    """Clear the cancel signal so the next turn starts fresh."""
    get_cancel_event(thread_id).clear()


# Friendly labels shown in the status bar while tools are running
TOOL_LABELS = {
    "server_diagnostics": "Running server diagnostics",
    "list_memory_dumps": "Listing available memory dumps",
    "query_plugin_rows": "Filtering cached plugin results",
    "get_image_info": "Reading OS profile and metadata",
    "run_pslist": "Listing running processes (pslist)",
    "run_psscan": "Scanning for hidden processes (psscan)",
    "run_pstree": "Building process tree (pstree)",
    "run_netscan": "Scanning network connections (netscan)",
    "run_malfind": "Hunting for injected code (malfind)",
    "run_dlllist": "Listing loaded DLLs (dlllist)",
    "run_cmdline": "Extracting command lines (cmdline)",
    "run_handles": "Listing open handles (handles)",
    "run_svcscan": "Checking Windows services (svcscan)",
    "run_psxview": "Cross-checking hidden processes (psxview)",
    "hash_evidence": "Hashing suspicious evidence values",
    "compact_conversation": "Compacting conversation context",
    "save_report": "Saving report to disk",
    "write_todos": "Updating investigation plan",
}


def friendly_tool_name(name: str) -> str:
    return TOOL_LABELS.get(name, f"Running {name}")


def format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m {secs}s"


# â”€â”€ Page config + branding â”€â”€

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
LOGO_PATH = ASSETS_DIR / "automem_logo.svg"
LOGO_ICON_PATH = ASSETS_DIR / "automem_icon.svg"

st.set_page_config(
    page_title="AutoMem - Memory Forensics",
    page_icon=str(LOGO_ICON_PATH) if LOGO_ICON_PATH.is_file() else ":mag:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sticky logo: shown top-left of the main area and at the top of the sidebar.
# When the sidebar collapses, Streamlit swaps to the smaller icon image.
if LOGO_PATH.is_file() and LOGO_ICON_PATH.is_file():
    st.logo(
        str(LOGO_PATH),
        size="large",
        icon_image=str(LOGO_ICON_PATH),
    )

# Light, theme-aware styling for the custom tool/todo blocks.
# Colours come from the active Streamlit theme via CSS variables so they
# stay in sync with `.streamlit/config.toml`.
st.markdown("""
<style>
    .tool-call {
        background-color: var(--secondary-background-color);
        border-left: 3px solid var(--primary-color);
        padding: 10px 15px;
        margin: 5px 0;
        border-radius: 0 8px 8px 0;
        font-family: 'Fira Code', ui-monospace, monospace;
        font-size: 0.85em;
    }
    .tool-result {
        background-color: var(--secondary-background-color);
        border-left: 3px solid #2EBD85;
        padding: 10px 15px;
        margin: 5px 0;
        border-radius: 0 8px 8px 0;
        font-size: 0.85em;
    }
    .todo-item {
        padding: 4px 8px;
        margin: 2px 0;
        border-radius: 4px;
        font-size: 0.9em;
        background-color: var(--secondary-background-color);
    }
    .todo-pending  { border-left: 3px solid #FFA64A; }
    .todo-progress { border-left: 3px solid var(--primary-color); }
    .todo-done     { border-left: 3px solid #2EBD85; }
</style>
""", unsafe_allow_html=True)


# â”€â”€ Session state defaults â”€â”€

def init_session():
    defaults = {
        "messages": [],
        "event_loop": None,
        "agent": None,
        "agent_config": None,
        "agent_files": None,
        "thread_id": str(uuid.uuid4()),
        "active_chat_id": None,
        "chat_histories": [],
        "chat_history_loaded": False,
        "mcp_connected": False,
        "agent_ready": False,
        "todos": [],
        "current_dump": None,
        "ollama_url": OLLAMA_BASE_URL,
        "model_name": OLLAMA_MODEL,
        "available_models": [],
        "models_fetched_url": None,
        "model_name_applied": None,
        "ollama_url_applied": None,
        "num_ctx": OLLAMA_NUM_CTX,
        "num_ctx_applied": None,
        "ollama_status": None,
        "view_report": None,
        "queued_submission": None,
        "pending_submission": None,
        "rejected_prompt": None,
        "last_uploaded_dump": None,
        "last_upload_signature": None,
        "turn_in_progress": False,
        "recent_traces": [],
        "cancel_requested": False,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val
    if not st.session_state.agent_ready:
        if not st.session_state.mcp_connected:
            st.session_state.mcp_connected = tcp_endpoint_reachable(MCP_SERVER_URL)
        if st.session_state.ollama_status is None and tcp_endpoint_reachable(st.session_state.ollama_url):
            st.session_state.ollama_status = {"online": True, "models_loaded": []}
    if st.session_state.active_chat_id is None:
        st.session_state.active_chat_id = st.session_state.thread_id
    if not st.session_state.chat_history_loaded:
        st.session_state.chat_histories = load_history_file(CHAT_HISTORY_FILE)
        st.session_state.chat_history_loaded = True
        # Clear orphan checkpoints left over from previous runs so the DB
        # never grows past the kept-history cap.
        keep = {st.session_state.thread_id}
        keep.update(
            h.get("thread_id") for h in st.session_state.chat_histories if h.get("thread_id")
        )
        try:
            prune_threads(keep)
        except Exception as err:
            logger.warning("Startup checkpoint prune failed: %s", err)


init_session()

# Old sessions or env may still use removed presets (4Kâ€“16K); snap to a valid choice.
allowed_ctx = set(CTX_PRESETS.values())
if st.session_state.num_ctx not in allowed_ctx:
    st.session_state.num_ctx = (
        OLLAMA_NUM_CTX if OLLAMA_NUM_CTX in allowed_ctx else min(allowed_ctx)
    )


# â”€â”€ Helpers â”€â”€

def fetch_ollama_models(base_url: str) -> list[dict]:
    """Ask Ollama which models have been pulled â€” uses plain urllib
    so it works without touching the async event loop on first load."""
    import urllib.request
    models: list[dict] = []
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            for entry in data.get("models", []):
                details = entry.get("details", {})
                models.append({
                    "name": entry.get("name", "?"),
                    "size_gb": round(entry.get("size", 0) / 1e9, 1),
                    "parameter_size": details.get("parameter_size", ""),
                    "family": details.get("family", ""),
                })
    except Exception as exc:
        logger.debug("Could not fetch Ollama models: %s", exc)
    return models


def get_available_dumps() -> list[dict]:
    """Scan the memory_dumps folder and return file info."""
    dumps = []
    if MEMORY_DUMPS_DIR.is_dir():
        for file in sorted(MEMORY_DUMPS_DIR.iterdir()):
            if (
                file.is_file()
                and not file.name.startswith(".")
                and file.suffix.lower() in SUPPORTED_DUMP_EXTENSIONS
            ):
                size_mb = round(file.stat().st_size / (1024 * 1024), 2)
                dumps.append({"name": file.name, "path": str(file), "size_mb": size_mb})
    return dumps


def get_available_reports() -> list[Path]:
    """Return all generated report files, newest first."""
    if not REPORTS_DIR.is_dir():
        return []
    return sorted(
        REPORTS_DIR.glob("*.md"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )


def delete_report_file(report_path: Path) -> bool:
    """Delete a generated report and clear viewer state if it was open."""
    try:
        report_path.unlink()
    except FileNotFoundError:
        pass
    except OSError as err:
        logger.warning("Could not delete report %s: %s", report_path, err)
        return False
    if st.session_state.get("view_report") == str(report_path):
        st.session_state.view_report = None
    st.session_state.pop(f"dl_ready_{report_path.name}", None)
    return True


def reports_dir_signature() -> tuple[int, int]:
    """Count + newest mtime of reports/*.md â€” detects new saves during the same run."""
    paths = get_available_reports()
    if not paths:
        return (0, 0)
    return (len(paths), max(p.stat().st_mtime_ns for p in paths))


def clear_current_turn_state() -> None:
    """Reset queued work that should not carry into another chat."""
    st.session_state.queued_submission = None
    st.session_state.pending_submission = None
    st.session_state.rejected_prompt = None
    st.session_state.view_report = None
    st.session_state.todos = []


def update_agent_thread(thread_id: str) -> None:
    """Point the current agent config at a selected chat thread."""
    st.session_state.thread_id = thread_id
    if st.session_state.agent_config is not None:
        st.session_state.agent_config = {
            "configurable": {"thread_id": thread_id}
        }


def prune_evicted_checkpoints() -> None:
    """Delete checkpoint rows for chats that fell out of the kept-history list.

    Keeps the active thread plus every thread referenced by `chat_histories`
    (capped at MAX_CHAT_HISTORIES). Called whenever the history list changes.
    """
    keep: set[str] = set()
    if st.session_state.thread_id:
        keep.add(st.session_state.thread_id)
    for history in st.session_state.chat_histories:
        thread_id = history.get("thread_id")
        if thread_id:
            keep.add(thread_id)
    try:
        prune_threads(keep)
    except Exception as err:
        logger.warning("Checkpoint prune failed: %s", err)


def save_current_chat_history() -> None:
    """Save the current chat into the capped history list."""
    if not st.session_state.messages:
        return
    chat_id = st.session_state.active_chat_id or st.session_state.thread_id
    record = build_history_record(
        chat_id,
        st.session_state.thread_id,
        st.session_state.messages,
        st.session_state.current_dump,
        st.session_state.todos,
    )
    st.session_state.chat_histories = upsert_history(
        st.session_state.chat_histories,
        record,
    )
    save_history_file(CHAT_HISTORY_FILE, st.session_state.chat_histories)
    prune_evicted_checkpoints()


def start_new_chat() -> None:
    """Save the current chat, then start an empty thread."""
    save_current_chat_history()
    new_thread = str(uuid.uuid4())
    st.session_state.messages = []
    st.session_state.active_chat_id = new_thread
    update_agent_thread(new_thread)
    clear_current_turn_state()


def open_saved_chat(chat_id: str) -> bool:
    """Load one saved chat into the UI."""
    history = find_history(st.session_state.chat_histories, chat_id)
    if history is None:
        return False
    save_current_chat_history()

    st.session_state.active_chat_id = history.get("id", chat_id)
    update_agent_thread(history.get("thread_id", chat_id))
    st.session_state.messages = json.loads(json.dumps(history.get("messages", [])))
    st.session_state.todos = json.loads(json.dumps(history.get("todos", [])))
    st.session_state.current_dump = history.get("current_dump")
    st.session_state.queued_submission = None
    st.session_state.pending_submission = None
    st.session_state.rejected_prompt = None
    st.session_state.view_report = None
    st.session_state.chat_histories = upsert_history(st.session_state.chat_histories, history)
    save_history_file(CHAT_HISTORY_FILE, st.session_state.chat_histories)
    prune_evicted_checkpoints()
    return True


def delete_saved_chat(chat_id: str) -> bool:
    """Delete one saved chat and its checkpoint rows when no longer active."""
    history = find_history(st.session_state.chat_histories, chat_id)
    if history is None:
        return False

    st.session_state.chat_histories = remove_history(
        st.session_state.chat_histories,
        chat_id,
    )
    save_history_file(CHAT_HISTORY_FILE, st.session_state.chat_histories)

    if chat_id == st.session_state.active_chat_id:
        new_thread = str(uuid.uuid4())
        st.session_state.messages = []
        st.session_state.active_chat_id = new_thread
        update_agent_thread(new_thread)
        clear_current_turn_state()

    prune_evicted_checkpoints()
    return True


def clear_saved_chats() -> None:
    """Remove every saved chat and start a clean active thread."""
    st.session_state.chat_histories = []
    save_history_file(CHAT_HISTORY_FILE, [])
    new_thread = str(uuid.uuid4())
    st.session_state.messages = []
    st.session_state.active_chat_id = new_thread
    update_agent_thread(new_thread)
    clear_current_turn_state()
    prune_evicted_checkpoints()


def render_chat_history_sidebar(busy: bool) -> None:
    """Show the latest compact chat histories in the sidebar."""
    st.subheader("Chat History")
    histories = st.session_state.chat_histories[:MAX_CHAT_HISTORIES]
    if not histories:
        st.caption("No saved chats yet. The latest 3 chats will appear here.")
        return

    st.caption(f"Stores up to {MAX_CHAT_HISTORIES} compact chats.")
    if st.button(
        "Clear All",
        key="clear_chat_histories",
        use_container_width=True,
        disabled=busy,
        icon=":material/delete_sweep:",
    ):
        clear_saved_chats()
        st.toast("Chat history cleared", icon=":material/delete_sweep:")
        st.rerun()

    for history in histories:
        chat_id = history.get("id", "")
        is_active = chat_id == st.session_state.active_chat_id
        title = history.get("title", "Untitled chat")
        label = f"Current - {title}" if is_active else title
        time_label = format_history_time(history.get("updated_at"))
        dump_label = history.get("current_dump") or "no dump"
        message_count = history.get("message_count", len(history.get("messages", [])))
        st.caption(f"{message_count} messages | {dump_label} | {time_label}")
        open_col, delete_col = st.columns([5, 1])
        with open_col:
            if st.button(
                label,
                key=f"open_chat_history_{chat_id}",
                use_container_width=True,
                disabled=busy or is_active,
            ):
                if not open_saved_chat(chat_id):
                    st.warning("This chat history could not be opened.")
                st.rerun()
        with delete_col:
            if st.button(
                "",
                key=f"delete_chat_history_{chat_id}",
                icon=":material/delete:",
                help="Delete chat",
                use_container_width=True,
                disabled=busy,
            ):
                if delete_saved_chat(chat_id):
                    st.toast("Chat deleted", icon=":material/delete:")
                else:
                    st.warning("This chat history could not be deleted.")
                st.rerun()


# Snapshot before sidebar + chat (reports written later in the run need a rerun to show up).
reports_signature_at_start = reports_dir_signature()


THINK_TAG_PATTERN = re.compile(r"<think>.*?</think>\s*", re.DOTALL)


def strip_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks that some models emit for chain-of-thought."""
    text = THINK_TAG_PATTERN.sub("", text)
    unclosed = text.find("<think>")
    if unclosed != -1:
        text = text[:unclosed]
    return text.strip()


def trim_replayed_assistant_prefix(text: str, existing_messages: list[dict]) -> str:
    """Drop assistant text replayed from previous turns by the graph.

    Only strips a prior reply if it is meaningfully long (>=120 chars) and
    matches the start of the new reply EXACTLY â€” short prefix matches such
    as a shared "# Memory Forensics Analysis Report" heading must not be
    stripped, or we silently truncate legitimate new content. We also stop
    at the first match (don't iterate-strip) and only consider the most
    recent prior assistant message, since the graph only ever replays
    the immediately preceding turn.
    """
    cleaned = strip_think_tags(text)
    if not cleaned:
        return cleaned

    MIN_PREFIX_CHARS = 120

    prior_assistant_messages = [
        msg.get("content", "")
        for msg in existing_messages
        if msg.get("role") == "assistant" and msg.get("content")
    ]

    if not prior_assistant_messages:
        return cleaned

    last_prior = prior_assistant_messages[-1]
    if (
        last_prior
        and len(last_prior) >= MIN_PREFIX_CHARS
        and cleaned.startswith(last_prior)
    ):
        cleaned = cleaned[len(last_prior):].lstrip()

    return cleaned


# â”€â”€ Agent initialization â”€â”€

def stream_text_chunks(text: str):
    """Yield a response in small line-based chunks for st.write_stream."""
    if not text:
        return
    lines = text.splitlines(keepends=True)
    if not lines:
        yield text
        return
    for line in lines:
        yield line


def count_repeated_tool_calls(call_signatures: list[str]) -> int:
    """Count repeated tool+argument combinations in one turn."""
    seen: set[str] = set()
    repeated = 0
    for signature in call_signatures:
        if signature in seen:
            repeated += 1
        else:
            seen.add(signature)
    return repeated


REPORT_PLACEHOLDER_MARKERS = (
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
    "[source",
    "{time_or_",
    "{event}",
    "{plugin}",
    "{action_",
    "{finding_",
)

REPORT_MARKERS = (
    "executive summary",
    "system profile",
    "process analysis",
    "network analysis",
    "ioc summary",
    "ioc table",
    "indicators of compromise",
    "evidence hashes",
    "virustotal lookup",
    "recommendations",
    "timeline",
    "memory forensics analysis report",
    "forensic analysis report",
    "forensic memory analysis report",
)

REPORT_PLANNING_MARKERS = (
    "i will now generate",
    "i will now compile",
    "previous steps have gathered sufficient evidence",
)

REPORT_INTERIM_MARKERS = (
    "next step:\n",
    "next step: \n",
    "next steps:\n",
    "next steps & recommendations",
    "what would you like to investigate next",
)

GENERIC_REPORT_REPLIES = {
    "analysis complete.",
    "analysis complete",
    "task completed.",
    "task completed",
    "tasks completed.",
    "tasks completed",
}


def extract_successful_save_report_content(tool_calls: list[dict] | None) -> str:
    """Return report Markdown from a successful save_report call, if present."""
    save_content = ""
    save_succeeded = False
    for tool_call in tool_calls or []:
        if tool_call.get("type") == "call" and tool_call.get("name") == "save_report":
            save_content = (tool_call.get("args") or {}).get("content", "") or save_content
        if (
            tool_call.get("type") == "result"
            and tool_call.get("name") == "save_report"
            and "rejected" not in str(tool_call.get("result", "")).lower()
        ):
            save_succeeded = True
    return save_content.strip() if save_succeeded else ""


def report_response_has_blocking_quality_issue(content: str) -> bool:
    """Detect report text that should not be saved as Markdown."""
    text = (content or "").strip()
    if not text:
        return True

    lowered = text.lower()
    if lowered in GENERIC_REPORT_REPLIES:
        return True

    if len(text) < 200:
        return True

    if any(marker in lowered for marker in REPORT_PLACEHOLDER_MARKERS):
        return True

    has_report_shape = any(marker in lowered for marker in REPORT_MARKERS)
    if any(marker in lowered for marker in REPORT_PLANNING_MARKERS):
        return True

    # A partial "Finding: ... Next step:" response is not a report.
    if any(marker in lowered for marker in REPORT_INTERIM_MARKERS) and not has_report_shape:
        return True

    return False


def report_response_has_report_shape(content: str) -> bool:
    """Require enough structure to treat text as a final forensic report."""
    lowered = (content or "").lower()
    required_groups = (
        ("executive summary", "memory forensics analysis report", "forensic analysis report"),
        ("system profile",),
        ("process analysis",),
        ("network analysis",),
        ("recommendations",),
        ("limitations",),
    )
    matched_groups = sum(
        1 for group in required_groups if any(marker in lowered for marker in group)
    )
    return matched_groups >= 5


def report_response_needs_retry(content: str, tool_calls: list[dict] | None) -> bool:
    """Detect incomplete report turns and trigger one basic retry."""
    saved_report = extract_successful_save_report_content(tool_calls)
    if (
        saved_report
        and not report_response_has_blocking_quality_issue(saved_report)
        and report_response_has_report_shape(saved_report)
    ):
        return False

    text = (content or "").strip()
    if report_response_has_blocking_quality_issue(text):
        return True

    rejected_save = any(
        tool_call.get("type") == "result"
        and tool_call.get("name") == "save_report"
        and "rejected" in str(tool_call.get("result", "")).lower()
        for tool_call in (tool_calls or [])
    )
    if rejected_save:
        return True

    return not report_response_has_report_shape(text)


def response_needs_retry(content: str, tool_calls: list[dict] | None) -> bool:
    """Detect short generic replies after tool use and trigger one basic retry."""
    text = (content or "").strip()
    if not text:
        return True

    lowered = text.lower()
    generic_replies = {
        "analysis complete.",
        "analysis complete",
        "task completed.",
        "task completed",
        "tasks completed.",
        "tasks completed",
    }
    if lowered in generic_replies:
        return True

    used_real_tools = any(
        tool_call.get("type") == "call" and tool_call.get("name") not in {"write_todos"}
        for tool_call in (tool_calls or [])
    )
    if used_real_tools and len(text) < 120:
        return True
    return False


def record_trace(trace: dict[str, Any]) -> None:
    """Store a simple trace in session state and on disk for debugging."""
    TURN_TRACE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with TURN_TRACE_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(trace, default=str) + "\n")

    recent = st.session_state.recent_traces
    recent.append(trace)
    st.session_state.recent_traces = recent[-8:]


def render_trace_history():
    """Show the latest turn traces in the sidebar."""
    traces = st.session_state.recent_traces
    if not traces:
        st.caption("No diagnostics yet.")
        return
    for trace in reversed(traces[-5:]):
        label = trace.get("event", "turn")
        elapsed = trace.get("elapsed_sec", 0)
        mode = trace.get("agent_mode", "-")
        tools = trace.get("tool_call_count", 0)
        st.caption(f"{label}: {mode}, {tools} tools, {elapsed:.1f}s")


def agent_config_changed() -> bool:
    """True when sidebar settings no longer match the built agent."""
    if not st.session_state.agent_ready:
        return False
    model_changed = (
        st.session_state.model_name_applied is not None
        and st.session_state.model_name != st.session_state.model_name_applied
    )
    ctx_changed = (
        st.session_state.num_ctx_applied is not None
        and st.session_state.num_ctx != st.session_state.num_ctx_applied
    )
    url_changed = (
        st.session_state.ollama_url_applied is not None
        and st.session_state.ollama_url != st.session_state.ollama_url_applied
    )
    return model_changed or ctx_changed or url_changed


def submission_guard_message(
    agent_ready: bool,
    current_dump: str | None,
    prompt: str | None = None,
    *,
    is_report: bool = False,
) -> str | None:
    """Return a short user-facing guard message when a request should not run."""
    if prompt and should_bypass_tools(prompt, is_report=is_report):
        return None
    if not agent_ready:
        return "Initialize the agent before sending a request."
    if agent_config_changed():
        return "Sidebar configuration changed. Click Initialize Agent again before sending a request."
    if not current_dump:
        return "Select a memory dump before sending a request."
    return None


async def initialize_agent(status_ui=None):
    from agent.agent import (
        build_agent_resources,
        check_mcp_server_status,
        check_ollama_status,
        create_forensics_agent,
        get_mcp_tools,
    )

    def log(msg: str):
        if status_ui:
            status_ui.write(msg)

    start_time = time.time()
    mcp_was_connected = False

    try:
        log("Checking if Ollama is running...")
        ollama_status = await check_ollama_status(st.session_state.ollama_url)
        st.session_state.ollama_status = ollama_status
        if not ollama_status["online"]:
            log("Ollama is not reachable.")
            st.error("Ollama is not running. Start it with `ollama serve`.")
            return False
        loaded = ollama_status.get("models_loaded", [])
        if loaded:
            log(f"Ollama online â€” **{loaded[0]['name']}** ({loaded[0]['size_gb']} GB)")
        else:
            log("Ollama online â€” no model cached yet, will load on first request.")

        if status_ui:
            status_ui.update(label="Connecting to MCP server...")
        log("Connecting to Volatility MCP HTTP server...")
        mcp_tools = await get_mcp_tools()
        st.session_state.mcp_connected = True
        mcp_was_connected = True
        log(f"MCP connected â€” **{len(mcp_tools)} tools** available.")

        checkpointer, store, backend = build_agent_resources()
        ctx_size = st.session_state.num_ctx
        if status_ui:
            status_ui.update(label=f"Building agent (ctx={ctx_size})...")
        log(f"Creating agent â€” context={ctx_size} tokens...")
        agent, config, files = await create_forensics_agent(
            mcp_tools=mcp_tools,
            thread_id=st.session_state.thread_id,
            model_name=st.session_state.model_name,
            base_url=st.session_state.ollama_url,
            num_ctx=ctx_size,
            checkpointer=checkpointer,
            store=store,
            backend=backend,
        )
        st.session_state.agent = agent
        st.session_state.agent_config = config
        st.session_state.agent_files = files
        st.session_state.agent_ready = True
        st.session_state.model_name_applied = st.session_state.model_name
        st.session_state.ollama_url_applied = st.session_state.ollama_url
        st.session_state.num_ctx_applied = ctx_size
        st.session_state.ollama_status = await check_ollama_status(st.session_state.ollama_url)
        log("Agent is ready.")
        record_trace(
            {
                "event": "initialize",
                "model_name": st.session_state.model_name,
                "num_ctx": ctx_size,
                "elapsed_sec": round(time.time() - start_time, 2),
                "mcp_tool_count": len(mcp_tools),
            }
        )
        return True
    except Exception as err:
        logger.error("Failed to initialize agent: %s", err)
        if mcp_was_connected:
            st.session_state.mcp_connected = True
        else:
            st.session_state.mcp_connected = check_mcp_server_status()[0]
        st.session_state.agent_ready = False
        st.session_state.agent = None
        log(f"Error: {err}")
        st.error(f"Failed to initialize: {err}")
        record_trace(
            {
                "event": "initialize_error",
                "model_name": st.session_state.model_name,
                "num_ctx": st.session_state.num_ctx,
                "elapsed_sec": round(time.time() - start_time, 2),
                "error": str(err),
            }
        )
        return False


# â”€â”€ Core chat: stream the agent's reply â”€â”€

async def _consume_agent_stream(
    agent,
    prompt: str,
    config: dict,
    files: dict | None,
    status_container,
    start_time: float,
    starting_step: int = 0,
    cancel_event: threading.Event | None = None,
    hard_timeout_sec: float = TURN_HARD_TIMEOUT_SEC,
    seen_ids: set[str] | None = None,
) -> dict:
    """Stream one request to the agent and collect assistant text, tool calls, and todos.

    `seen_ids` is shared across the original stream and any retry call within
    the same turn so that LangGraph-replayed AIMessages (same `id`) are not
    counted twice in `tool_calls` / `call_signatures`.
    """
    from agent.agent import stream_agent

    text = ""
    reasoning_text = ""
    tool_calls: list[dict] = []
    todos: list = []
    call_signatures: list[str] = []
    step_count = starting_step
    if seen_ids is None:
        seen_ids = set()

    def log_status(msg: str):
        if status_container:
            status_container.write(msg)

    # Mutable holder so the background ticker can read the latest label
    # without us closing over a rebound local.
    current_label = ["Analysing..."]

    def update_label(label: str):
        current_label[0] = label
        if status_container:
            elapsed = time.time() - start_time
            status_container.update(label=f"{label}  ({format_elapsed(elapsed)})")

    async def tick_timer():
        # Refreshes the status label every second so the elapsed counter keeps
        # ticking while the agent is mid-LLM-generation (between tool events).
        try:
            while True:
                await asyncio.sleep(1.0)
                if status_container:
                    elapsed = time.time() - start_time
                    try:
                        status_container.update(
                            label=f"{current_label[0]}  ({format_elapsed(elapsed)})"
                        )
                    except Exception:
                        # Streamlit container went away (rerun, stop) â€” exit quietly.
                        return
        except asyncio.CancelledError:
            return

    ticker_task = asyncio.create_task(tick_timer())

    try:
        async for event in stream_agent(agent, prompt, config, files):
            # Cooperative cancellation: a module-level threading.Event is set
            # by the Stop button (visible across reruns) OR by exceeding the
            # wall-clock budget below. Checked between agent steps â€” finer
            # cancellation requires running the agent in a worker thread,
            # which is out of scope for this build.
            if cancel_event is not None and cancel_event.is_set():
                log_status("Stop requested - finishing current step then halting.")
                break
            if st.session_state.get("cancel_requested"):
                log_status("Stop requested - finishing current step then halting.")
                break
            if (time.time() - start_time) > hard_timeout_sec:
                log_status(
                    f"Turn exceeded hard timeout ({int(hard_timeout_sec)}s) - "
                    "halting to protect the session."
                )
                if cancel_event is not None:
                    cancel_event.set()
                break
            for _node_name, node_output in event.items():
                if not node_output or not isinstance(node_output, dict):
                    continue
                if "messages" not in node_output:
                    continue

                raw_messages = node_output["messages"]
                if hasattr(raw_messages, "value"):
                    raw_messages = raw_messages.value
                if not isinstance(raw_messages, (list, tuple)):
                    raw_messages = [raw_messages] if raw_messages else []

                for msg in raw_messages:
                    msg_id = getattr(msg, "id", None)
                    if msg_id:
                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)

                    kind = type(msg).__name__

                    if kind == "AIMessage":
                        if msg.content and isinstance(msg.content, str):
                            text += msg.content

                        extras = getattr(msg, "additional_kwargs", {})
                        reasoning = extras.get("reasoning_content", "")
                        if reasoning:
                            reasoning_text += reasoning

                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            for call in msg.tool_calls:
                                step_count += 1
                                call_name = call.get("name", "unknown")
                                call_args = call.get("args", {})
                                tool_calls.append({
                                    "type": "call",
                                    "name": call_name,
                                    "args": call_args,
                                    "id": call.get("id", ""),
                                    "step": step_count,
                                })
                                call_signatures.append(
                                    f"{call_name}:{json.dumps(call_args, sort_keys=True, default=str)}"
                                )

                                friendly = friendly_tool_name(call_name)
                                update_label(friendly)

                                brief = ""
                                if "memory_dump" in call_args:
                                    brief = call_args["memory_dump"]
                                if "pid" in call_args:
                                    brief += f" (PID {call_args['pid']})"
                                if brief:
                                    log_status(f"**Step {step_count}** â€” {friendly} `{brief.strip()}`")
                                else:
                                    log_status(f"**Step {step_count}** â€” {friendly}")

                    elif kind == "ToolMessage":
                        content = msg.content if isinstance(msg.content, str) else str(msg.content)
                        preview = content[:2000]
                        tool_name = getattr(msg, "name", "tool_result")
                        tool_calls.append({
                            "type": "result",
                            "name": tool_name,
                            "result": preview,
                            "id": getattr(msg, "tool_call_id", ""),
                        })

                        row_hint = ""
                        try:
                            parsed = json.loads(content)
                            if isinstance(parsed, dict):
                                rows = parsed.get("row_count")
                                if rows is not None:
                                    row_hint = f" â€” {rows} rows"
                        except (json.JSONDecodeError, TypeError):
                            pass
                        log_status(f"  â†³ {tool_name} returned{row_hint}")
                        update_label("Thinking...")

                        if tool_name == "write_todos":
                            try:
                                parsed = json.loads(content)
                                if isinstance(parsed, list):
                                    todos = parsed
                            except (json.JSONDecodeError, TypeError):
                                pass
    finally:
        ticker_task.cancel()
        try:
            await ticker_task
        except (asyncio.CancelledError, Exception):
            pass

    return {
        "text": text,
        "reasoning": reasoning_text,
        "tool_calls": tool_calls,
        "todos": todos,
        "call_signatures": call_signatures,
        "step_count": step_count,
        "seen_message_ids": list(seen_ids),
    }


def _response_still_needs_retry(cleaned: str, tool_calls: list[dict], is_report: bool) -> bool:
    if is_report:
        return report_response_needs_retry(cleaned, tool_calls)
    return response_needs_retry(cleaned, tool_calls)


async def send_message(
    user_input: str,
    status_container=None,
    *,
    is_report: bool = False,
) -> tuple[dict, float, list]:
    """Send user_input to the agent, stream events, return (response_data, elapsed, todos).

    Does NOT touch st.session_state.messages â€” the caller handles that.
    """
    from agent.agent import answer_general_question

    if should_bypass_tools(user_input, is_report=is_report):
        start_time = time.time()
        try:
            reply = await answer_general_question(
                user_input,
                model_name=st.session_state.model_name_applied or st.session_state.model_name,
                base_url=st.session_state.ollama_url,
                num_ctx=st.session_state.num_ctx_applied or st.session_state.num_ctx,
            )
        except Exception as err:
            logger.warning("General question failed: %s", err)
            reply = (
                "I can answer general project questions, but the local Ollama "
                "model is not reachable right now. Start Ollama or initialize "
                "the agent, then try again."
            )
        elapsed = time.time() - start_time
        response_data = {
            "role": "assistant",
            "content": normalize_chat_reply(
                reply,
                is_report=False,
                include_quality_sections=False,
            ),
            "tool_calls": None,
            "elapsed_sec": round(elapsed, 1),
            "agent_mode": "direct",
            "trace": {
                "event": "turn",
                "agent_mode": "direct",
                "elapsed_sec": round(elapsed, 2),
                "tool_call_count": 0,
                "repeated_tool_calls": 0,
                "prompt_chars": len(user_input),
                "response_chars": len(reply or ""),
                "dump": st.session_state.current_dump,
                "report_turn": False,
            },
        }
        return response_data, elapsed, []

    agent = st.session_state.agent
    config = st.session_state.agent_config

    # Attach skill files on the first turn and again for report-writing turns.
    user_count = sum(1 for m in st.session_state.messages if m["role"] == "user")
    is_first_message = user_count <= 1
    files = st.session_state.agent_files if (is_first_message or is_report) else None

    cancel_event = get_cancel_event(st.session_state.thread_id)
    # Shared across the first stream and the retry stream below so that
    # LangGraph-replayed AIMessages (same id) are deduped across both.
    turn_seen_ids: set[str] = {
        str(message_id)
        for message in st.session_state.messages
        for message_id in message.get("message_ids", [])
        if message_id
    }
    start_time = time.time()

    def log_status(msg: str):
        if status_container:
            status_container.write(msg)

    def update_label(label: str):
        if status_container:
            elapsed = time.time() - start_time
            status_container.update(label=f"{label}  ({format_elapsed(elapsed)})")

    update_label("Analysing...")

    text_to_agent = user_input
    if is_report:
        current_report_time = format_local_timestamp()
        text_to_agent = (
            f"{user_input}\n\n"
            "Report requirements:\n"
            "- Write the full final report now in Markdown.\n"
            "- Do not stop at todo updates, planning notes, or 'tasks completed'.\n"
            "- Include the main report sections clearly.\n"
            f"- Use this exact local analysis time in the report date field: {current_report_time}\n"
            "- After writing the report, call save_report with the full report content.\n"
        )

    try:
        result = await _consume_agent_stream(
            agent, text_to_agent, config, files, status_container, start_time,
            cancel_event=cancel_event,
            seen_ids=turn_seen_ids,
        )
    except Exception as err:
        logger.error("Agent error: %s", err)
        result = {
            "text": f"Error during analysis: {err}",
            "reasoning": "",
            "tool_calls": [],
            "todos": [],
            "call_signatures": [],
            "step_count": 0,
        }

    cleaned = trim_replayed_assistant_prefix(result["text"], st.session_state.messages)

    if is_report:
        saved_report_content = extract_successful_save_report_content(result["tool_calls"])
        if (
            saved_report_content
            and not report_response_has_blocking_quality_issue(saved_report_content)
            and report_response_has_report_shape(saved_report_content)
        ):
            cleaned = saved_report_content

    skip_retry_for_tool_error = (
        not cleaned.strip()
        and tool_calls_have_hard_errors(result["tool_calls"])
    )
    if (
        _response_still_needs_retry(cleaned, result["tool_calls"], is_report)
        and not skip_retry_for_tool_error
    ):
        _dump_ctx = (
            f"Memory dump under analysis: {st.session_state.current_dump}.\n"
            if st.session_state.current_dump else ""
        )
        if is_report:
            log_status("Report reply was incomplete. Retrying once with stricter report instructions...")
            update_label("Retrying report...")
            retry_prompt = (
                f"{_dump_ctx}"
                "STOP. Do NOT call any tools. Do NOT invoke any Volatility plugin or MCP tool.\n"
                "\n"
                "The previous response was an incomplete interim summary (Finding:/Evidence:/"
                "Next step: format). That is NOT the report. The investigation evidence has "
                "already been collected from the tool calls earlier in this conversation.\n"
                "\n"
                "Write the complete forensic Markdown report RIGHT NOW using only the "
                "evidence already collected. Start with the report title, then write all "
                "ten sections. Do NOT add any preamble, planning notes, or tool calls.\n"
                "\n"
                "OS IDENTIFICATION â€” trust NTBuildLab only:\n"
                "  rs4_release / 17133  â†’ Windows 10 RS4 (April 2018 Update, v1803)\n"
                "  rs5_release / 17763  â†’ Windows 10 RS5 (October 2018 Update, v1809)\n"
                "  7601.win7sp1         â†’ Windows 7 SP1\n"
                "  2600.xpsp            â†’ Windows XP\n"
                "IGNORE the Major/Minor row â€” it shows kernel PE version, not Windows version.\n"
                "\n"
                "## Required report sections:\n"
                "1. Executive Summary â€” verdict: Compromised / Suspicious / Clean + confidence\n"
                "2. System Profile â€” OS (from NTBuildLab), architecture, capture time\n"
                "3. Process Analysis â€” table: PID | Name | PPID | Anomaly | Confidence\n"
                "4. Network Analysis â€” table: ForeignAddr | Port | State | PID | Process\n"
                "5. Persistence â€” service findings from svcscan with actual binary paths\n"
                "6. Injection / Code â€” malfind hits if run; Confirmed/FP per hit\n"
                "7. IOC Table â€” Type | Value | Confidence | Context\n"
                "8. Evidence Hashes / VirusTotal Lookup Notes â€” include already "
                "collected hash_evidence output if present, otherwise state "
                "'No suspicious evidence hashes were generated in this pass.'\n"
                "9. Recommendations â€” specific next steps\n"
                "10. Limitations â€” what was not checked in this pass\n"
                "\n"
                "Rules:\n"
                "- Use ONLY evidence from tool results already in this conversation.\n"
                "- Every section must cite actual tool output, or state "
                "'Evidence not collected in this pass.' â€” no placeholders.\n"
                "- Do NOT write Finding:/Evidence:/Confidence:/Next step: sections.\n"
                "- After writing all sections, call save_report with the complete report.\n"
            )
            retry_files = st.session_state.agent_files
        else:
            log_status("Model reply was too generic. Retrying once with final-answer instructions...")
            update_label("Retrying answer...")
            retry_prompt = (
                f"{_dump_ctx}"
                "Using the evidence already collected in this thread, answer the user's question directly now.\n"
                "Do not continue planning and do not stop at todos.\n"
                "Give final findings, confidence, and limitations in plain Markdown.\n"
                "Only call another tool if the current evidence is not enough to answer.\n"
            )
            retry_files = None

        try:
            retry = await _consume_agent_stream(
                agent, retry_prompt, config, retry_files, status_container, start_time,
                starting_step=result["step_count"],
                cancel_event=cancel_event,
                seen_ids=turn_seen_ids,
            )
            retry_cleaned = trim_replayed_assistant_prefix(retry["text"], st.session_state.messages)

            # If the model called save_report during the retry but the text response
            # doesn't have report shape (model wrote the report only as the tool arg,
            # not as visible text), extract the report from the tool call args so it
            # is displayed in chat and saved_with_tool is correctly flagged.
            if is_report:
                retry_save_content = extract_successful_save_report_content(retry["tool_calls"])
                if retry_save_content:
                    candidate = retry_save_content
                    if not _response_still_needs_retry(candidate, retry["tool_calls"], is_report):
                        logger.info(
                            "Retry text had no report shape but save_report succeeded "
                            "(content len=%d) â€” using save_report content as display",
                            len(candidate),
                        )
                        retry_cleaned = candidate

            retry_needs_another_retry = _response_still_needs_retry(
                retry_cleaned, retry["tool_calls"], is_report,
            )
            logger.info(
                "Retry result: len=%d, needs_retry=%s, raw_text_len=%d, "
                "tool_calls=%d, text_preview=%r",
                len(retry_cleaned),
                retry_needs_another_retry,
                len(retry["text"]),
                len(retry["tool_calls"]),
                (retry_cleaned or "")[:300],
            )
            if retry_cleaned and not retry_needs_another_retry:
                cleaned = retry_cleaned
                if retry["reasoning"]:
                    result["reasoning"] = retry["reasoning"]
                if retry["tool_calls"]:
                    result["tool_calls"].extend(retry["tool_calls"])
                result["call_signatures"].extend(retry["call_signatures"])
        except Exception as err:
            logger.error("Retry failed: %s", err)

    elapsed = time.time() - start_time
    if not cleaned.strip():
        cleaned = build_tool_result_fallback(result["tool_calls"])
    cleaned = normalize_chat_reply(cleaned, is_report=is_report)

    agent_mode = "standard"

    response_data: dict[str, Any] = {
        "role": "assistant",
        "content": cleaned or "Analysis complete.",
        "tool_calls": result["tool_calls"] or None,
        "elapsed_sec": round(elapsed, 1),
        "agent_mode": agent_mode,
        "trace": {
            "event": "turn",
            "agent_mode": agent_mode,
            "elapsed_sec": round(elapsed, 2),
            "tool_call_count": len(result["call_signatures"]),
            "repeated_tool_calls": count_repeated_tool_calls(result["call_signatures"]),
            "prompt_chars": len(user_input),
            "response_chars": len(cleaned or "Analysis complete."),
            "dump": st.session_state.current_dump,
            "report_turn": is_report,
        },
        "message_ids": list(turn_seen_ids),
    }
    if result["reasoning"]:
        response_data["reasoning"] = result["reasoning"]

    return response_data, elapsed, result["todos"]


def auto_save_report(dump_name: str, content: str) -> str | None:
    """Silently save report Markdown when the model did not call save_report."""
    content = (content or "").strip()
    if (
        report_response_has_blocking_quality_issue(content)
        or not report_response_has_report_shape(content)
    ):
        logger.warning("Skipped report auto-save because content is not safe to persist")
        return None

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stem = Path(dump_name).stem if dump_name else "analysis"
    now = datetime.now().astimezone()
    timestamp = now.strftime("%Y%m%d_%H%M%S%z")
    filename = f"{stem}_report_{timestamp}.md"
    normalized_content = ensure_report_date(content, now=now)
    (REPORTS_DIR / filename).write_text(
        build_report_header_comment(now) + normalized_content,
        encoding="utf-8",
    )
    return filename


# â”€â”€ Rendering helpers â”€â”€

def render_message(msg: dict, message_index: int | str):
    """Display a single chat message (user or assistant) with all its extras."""
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg["role"] == "assistant":
            tools = msg.get("tool_calls")
            if tools:
                render_tool_calls(tools, key=f"message_{message_index}_tools")
            if msg.get("reasoning"):
                render_reasoning(
                    msg["reasoning"],
                    key=f"message_{message_index}_reasoning",
                )
            elapsed = msg.get("elapsed_sec")
            if elapsed is not None:
                st.caption(f"Completed in {format_elapsed(elapsed)}")


def render_detail_toggle(label: str, key: str, *, default_expanded: bool = False) -> bool:
    """Render a stable details toggle that does not collapse on rerender."""
    if key not in st.session_state:
        st.session_state[key] = default_expanded
    return st.toggle(label, key=key)


def render_reasoning(reasoning: str, *, key: str, default_expanded: bool = False):
    """Show captured model reasoning behind a stable toggle."""
    if render_detail_toggle("Model Reasoning", key, default_expanded=default_expanded):
        with st.container(border=True):
            st.markdown(reasoning[:4000])


def render_tool_calls(
    tool_calls: list[dict],
    *,
    key: str = "tools_used",
    default_expanded: bool = False,
):
    """Show an expandable list of tool calls and their results."""
    call_count = sum(1 for tc in tool_calls if tc.get("type") == "call")
    if call_count == 0:
        return
    if not render_detail_toggle(
        f"Tools used ({call_count})",
        key,
        default_expanded=default_expanded,
    ):
        return
    with st.container(border=True):
        for tc in tool_calls:
            if tc.get("type") == "call":
                step = tc.get("step", "")
                prefix = f"Step {step} â€” " if step else ""
                friendly = friendly_tool_name(tc["name"])
                args_str = json.dumps(tc.get("args", {}), default=str)
                if len(args_str) > 120:
                    args_str = args_str[:120] + "..."
                escaped_args = html.escape(args_str)
                st.markdown(
                    f'<div class="tool-call">{prefix}<b>{friendly}</b>'
                    f' <code>{escaped_args}</code></div>',
                    unsafe_allow_html=True,
                )
            elif tc.get("type") == "result":
                result_text = tc.get("result", "")
                snippet = html.escape(result_text[:300]).replace("\n", "<br>")
                if len(result_text) > 300:
                    snippet += "..."
                st.markdown(
                    f'<div class="tool-result">â†³ <b>{tc["name"]}</b>: {snippet}</div>',
                    unsafe_allow_html=True,
                )


def render_todos(todos: list):
    """Display the investigation plan items with status icons."""
    if not todos:
        return
    for item in todos:
        status = item.get("status", "pending")
        content = item.get("content", item.get("task", ""))
        escaped_content = html.escape(content)
        css_class = {
            "pending": "todo-pending",
            "in_progress": "todo-progress",
            "completed": "todo-done",
        }.get(status, "todo-pending")
        icon = {"pending": "â³", "in_progress": "ðŸ”„", "completed": "âœ…"}.get(status, "â³")
        st.markdown(
            f'<div class="todo-item {css_class}">{icon} {escaped_content}</div>',
            unsafe_allow_html=True,
        )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  SIDEBAR
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

with st.sidebar:
    st.title("AutoMem")
    st.caption("AI memory-forensics agent")
    busy = st.session_state.turn_in_progress
    st.divider()

    st.subheader("System Status")
    status_col1, status_col2 = st.columns(2)
    with status_col1:
        if st.session_state.mcp_connected:
            st.badge("MCP", icon=":material/dns:", color="green")
        else:
            st.badge("MCP", icon=":material/dns:", color="red")
    with status_col2:
        if st.session_state.agent_ready:
            st.badge("Agent", icon=":material/smart_toy:", color="green")
        else:
            st.badge("Agent", icon=":material/smart_toy:", color="red")
    st.divider()

    st.subheader("Configuration")
    st.session_state.ollama_url = st.text_input(
        "Ollama URL",
        value=st.session_state.ollama_url,
        disabled=busy,
    )

    # Fetch the model list once per URL. When Ollama is offline, repeated
    # 5-second fetch attempts on every rerun make the UI feel frozen; the
    # Refresh button below explicitly retries.
    url_changed = st.session_state.models_fetched_url != st.session_state.ollama_url
    should_fetch_models = url_changed or st.session_state.models_fetched_url is None
    if should_fetch_models:
        st.session_state.available_models = fetch_ollama_models(st.session_state.ollama_url)
        st.session_state.models_fetched_url = st.session_state.ollama_url

    available_models = st.session_state.available_models
    if available_models:
        model_names = [m["name"] for m in available_models]
        model_labels = [
            f"{m['name']}  ({m['parameter_size']}, {m['size_gb']} GB)"
            if m.get("parameter_size") else m["name"]
            for m in available_models
        ]
        current_model = st.session_state.model_name
        try:
            selected_idx = model_names.index(current_model)
        except ValueError:
            selected_idx = 0
        chosen_label = st.selectbox(
            "Model", model_labels, index=selected_idx,
            help="Select the Ollama model to use. Smaller models are faster.",
            disabled=busy,
        )
        st.session_state.model_name = model_names[model_labels.index(chosen_label)]

        if st.button("Refresh models", use_container_width=True, key="refresh_models", disabled=busy):
            st.session_state.available_models = []
            st.session_state.models_fetched_url = None
            st.rerun()
    else:
        st.session_state.model_name = st.text_input(
            "Model", value=st.session_state.model_name,
            help="No models detected â€” type a model name manually, or check Ollama is running.",
            disabled=busy,
        )
        if st.button("Refresh models", use_container_width=True, key="refresh_models_fallback", disabled=busy):
            st.session_state.available_models = []
            st.session_state.models_fetched_url = None
            st.rerun()

    # Warn the user if they changed any setting after the agent was built.
    if agent_config_changed():
        st.warning("Configuration changed â€” click **Initialize Agent** to apply.")

    preset_names = list(CTX_PRESETS.keys())
    current_ctx = st.session_state.num_ctx
    default_ctx_idx = 0
    for i, (_, val) in enumerate(CTX_PRESETS.items()):
        if val == current_ctx:
            default_ctx_idx = i
            break
    chosen_preset = st.selectbox(
        "Context Window", preset_names, index=default_ctx_idx,
        help="32K is the safest default. Use 64K only if your machine stays stable.",
        disabled=busy,
    )
    st.session_state.num_ctx = CTX_PRESETS[chosen_preset]

    if st.session_state.ollama_status:
        oll_info = st.session_state.ollama_status
        if oll_info["online"]:
            loaded_models = oll_info["models_loaded"]
            if loaded_models:
                current_model = st.session_state.model_name
                active_loaded = next(
                    (model for model in loaded_models if model["name"] == current_model),
                    loaded_models[0],
                )
                st.caption(
                    f"Ollama: **{active_loaded['name']}** ({active_loaded['size_gb']} GB loaded)"
                )
            else:
                st.caption("Ollama: online")
        else:
            st.caption("Ollama: offline")
    st.divider()

    st.subheader("Memory Dumps")
    uploaded_dump = st.file_uploader(
        "Upload memory dump",
        type=[ext.lstrip(".") for ext in SUPPORTED_DUMP_EXTENSIONS],
        disabled=busy,
        help="Choose a dump file from your computer. It will be copied into memory_dumps/.",
    )
    if uploaded_dump is not None:
        upload_size_mb = round(getattr(uploaded_dump, "size", 0) / (1024 * 1024), 2)
        signature = uploaded_file_signature(uploaded_dump)
        if st.session_state.last_upload_signature == signature:
            saved_name = st.session_state.last_uploaded_dump or uploaded_dump.name
            st.caption(f"Uploaded: {saved_name} ({upload_size_mb} MB)")
        elif not busy:
            try:
                with st.spinner("Saving dump to disk..."):
                    saved_path = save_uploaded_dump(uploaded_dump, MEMORY_DUMPS_DIR)
                st.session_state.current_dump = saved_path.name
                st.session_state.last_uploaded_dump = saved_path.name
                st.session_state.last_upload_signature = signature
                st.toast(f"Uploaded {saved_path.name}",
                         icon=":material/check_circle:")
                st.rerun()
            except ValueError as err:
                st.toast(str(err), icon=":material/warning:")
            except Exception as err:
                logger.error("Could not save uploaded dump: %s", err)
                st.toast(f"Upload failed: {err}", icon=":material/error:")
        else:
            st.caption(f"Selected upload: {uploaded_dump.name} ({upload_size_mb} MB)")

    dumps = get_available_dumps()
    if dumps:
        for dump in dumps:
            st.markdown(
                f":material/folder_zip: `{dump['name']}` "
                f"<span style='opacity:0.6'>({dump['size_mb']} MB)</span>",
                unsafe_allow_html=True,
            )
        dump_names = [d["name"] for d in dumps]
        if st.session_state.current_dump in dump_names:
            selected_index = dump_names.index(st.session_state.current_dump)
        else:
            selected_index = 0
        selected_dump = st.selectbox(
            "Select dump for analysis",
            dump_names,
            index=selected_index,
            disabled=busy,
        )
        st.session_state.current_dump = selected_dump
    else:
        st.info("No dumps found. Upload a supported memory dump file to continue.")
        st.session_state.current_dump = None
    st.divider()

    st.subheader("Generated Reports")
    reports = get_available_reports()
    if reports:
        for report in reports:
            name_col, view_col, dl_col, del_col = st.columns([3, 1, 1, 1])
            with name_col:
                st.markdown(f":material/description: {report.name}")
            with view_col:
                if st.button("", icon=":material/visibility:",
                             key=f"view_{report.name}",
                             use_container_width=True, disabled=busy,
                             help="Open in viewer"):
                    st.session_state.view_report = str(report)
                    st.rerun()
            with dl_col:
                if st.button("", icon=":material/download:",
                             key=f"dl_btn_{report.name}",
                             use_container_width=True, disabled=busy,
                             help="Prepare download"):
                    st.session_state[f"dl_ready_{report.name}"] = True
                    st.rerun()
            with del_col:
                if st.button("", icon=":material/delete:",
                             key=f"del_btn_{report.name}",
                             use_container_width=True, disabled=busy,
                             help="Delete report"):
                    if delete_report_file(report):
                        st.toast(f"Deleted {report.name}", icon=":material/delete:")
                    else:
                        st.warning(f"Could not delete {report.name}.")
                    st.rerun()
            if st.session_state.get(f"dl_ready_{report.name}"):
                report_text = report.read_text(encoding="utf-8")
                st.download_button(
                    label=f"Save {report.name}",
                    icon=":material/save:",
                    data=report_text, file_name=report.name,
                    mime="text/markdown", key=f"dl_{report.name}",
                    use_container_width=True, disabled=busy,
                )
    else:
        st.caption("No reports generated yet.")
    st.divider()

    if st.session_state.todos:
        st.subheader("Investigation Plan")
        render_todos(st.session_state.todos)
        st.divider()

    st.subheader("Diagnostics")
    with st.expander("Recent turns", expanded=False):
        render_trace_history()
    st.divider()

    if st.button("Initialize Agent", use_container_width=True, type="primary",
                 disabled=busy, icon=":material/play_arrow:"):
        with st.status("Initializing agent...", expanded=True) as init_status:
            run_async(initialize_agent(status_ui=init_status))
            if st.session_state.agent_ready:
                init_status.update(label="Agent ready", state="complete", expanded=False)
                st.toast("Agent initialized", icon=":material/check_circle:")
            else:
                init_status.update(label="Initialization failed", state="error", expanded=True)
                st.toast("Initialization failed", icon=":material/error:")
        st.rerun()

    if st.button("New Session", use_container_width=True, disabled=busy,
                 icon=":material/add_comment:"):
        start_new_chat()
        st.toast("Started a new chat", icon=":material/add_comment:")
        st.rerun()

    st.divider()
    render_chat_history_sidebar(busy)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  REPORT VIEWER (takes over the main area when active)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if st.session_state.view_report:
    report_path = Path(st.session_state.view_report)
    if report_path.is_file():
        top_left, top_right = st.columns([5, 1], vertical_alignment="center")
        with top_left:
            st.header(f"Report: {report_path.name}", divider="violet")
        with top_right:
            if st.button("Back to Chat", key="back_top",
                         icon=":material/arrow_back:",
                         use_container_width=True):
                st.session_state.view_report = None
                st.rerun()
        st.markdown(report_path.read_text(encoding="utf-8"))
        st.divider()
        if st.button("Back to Chat", key="back_bottom",
                     icon=":material/arrow_back:"):
            st.session_state.view_report = None
            st.rerun()
        st.stop()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  MAIN CHAT AREA
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def render_chat_area():
    header_left, header_right = st.columns([5, 1], vertical_alignment="center")
    with header_left:
        st.header("AutoMem - Memory Forensics Analysis", divider="violet")
        if st.session_state.current_dump:
            st.caption(f"Active dump: `{st.session_state.current_dump}`")
        else:
            st.caption("No dump selected")
    with header_right:
        if st.session_state.agent_ready:
            st.badge("Agent Ready", icon=":material/check_circle:", color="green")
        else:
            st.badge("Not Initialized", icon=":material/warning:", color="orange")

    if not st.session_state.agent_ready and not st.session_state.messages:
        st.markdown("---")
        st.subheader("Getting started")
        col_ollama, col_mcp, col_dumps = st.columns(3)
        with col_ollama:
            ollama_info = st.session_state.ollama_status
            if ollama_info and ollama_info["online"]:
                st.success("Ollama is running")
            else:
                st.error("Ollama not detected")
                st.caption("Run `ollama serve` in a terminal")
        with col_mcp:
            if st.session_state.mcp_connected:
                st.success("MCP server connected")
            else:
                st.warning("MCP server not connected")
                st.caption("Run `docker compose up -d`")
        with col_dumps:
            dump_count = len(get_available_dumps())
            if dump_count > 0:
                st.success(f"{dump_count} memory dump(s) found")
            else:
                st.warning("No memory dumps")
                st.caption("Place .raw/.mem files in memory_dumps/")
        st.info(
            "Click **Initialize Agent** in the sidebar to connect everything and start analysing. "
            "Make sure Ollama is running and the MCP server is up with `docker compose up -d --build`. "
            "You can still ask simple general questions without initializing the agent."
        )
    elif not st.session_state.agent_ready:
        st.info("Click **Initialize Agent** in the sidebar to reconnect.")

    busy = st.session_state.turn_in_progress

    if st.session_state.agent_ready and st.session_state.current_dump:
        dump_name = st.session_state.current_dump
        actions = build_quick_actions(dump_name)

        st.markdown("**Quick actions**")
        action_cols = st.columns(len(actions), gap="small")
        for col, action in zip(action_cols, actions):
            with col:
                if st.button(
                    action.label,
                    icon=action.icon,
                    use_container_width=True,
                    key=f"qa_fragment_{action.label}",
                    disabled=busy,
                ):
                    st.session_state.queued_submission = {
                        "prompt": action.prompt,
                        "is_report": action.is_report,
                    }
                    st.session_state.rejected_prompt = None
                    st.rerun()

    for index, msg in enumerate(st.session_state.messages):
        render_message(msg, index)

    has_pending = (
        st.session_state.pending_submission is not None
        or st.session_state.queued_submission is not None
    )
    last_is_orphan = (
        st.session_state.messages
        and st.session_state.messages[-1]["role"] == "user"
        and not has_pending
    )

    if last_is_orphan and not busy:
        st.warning("The previous request was interrupted before the agent could respond.")
        retry_col, discard_col, spacer = st.columns([1, 1, 4])
        with retry_col:
            if st.button("Retry", key="retry_fragment",
                         icon=":material/refresh:",
                         use_container_width=True):
                orphan = st.session_state.messages.pop()
                st.session_state.queued_submission = {
                    "prompt": orphan["content"],
                    "is_report": orphan.get("is_report", False),
                }
                st.rerun()
        with discard_col:
            if st.button("Discard", key="discard_fragment",
                         icon=":material/delete:",
                         use_container_width=True):
                st.session_state.messages.pop()
                st.rerun()
        st.stop()

    if busy:
        info_col, stop_col = st.columns([4, 1], vertical_alignment="center")
        with info_col:
            if st.session_state.cancel_requested:
                st.warning(
                    "Stop requested. The turn will halt at the next step "
                    "boundary (Stop cannot interrupt an in-flight LLM token "
                    "stream â€” Streamlit blocks widget callbacks while the "
                    f"script is busy). Hard timeout: {TURN_HARD_TIMEOUT_SEC}s.",
                    icon=":material/hourglass_empty:",
                )
            else:
                st.info(
                    "A turn is running. Click Stop to halt at the next step "
                    f"boundary. Hard timeout: {TURN_HARD_TIMEOUT_SEC}s.",
                    icon=":material/autorenew:",
                )
        with stop_col:
            if st.button(
                "Stop",
                key="stop_turn_button",
                type="secondary",
                use_container_width=True,
                disabled=st.session_state.cancel_requested,
                icon=":material/stop_circle:",
            ):
                st.session_state.cancel_requested = True
                request_cancel(st.session_state.thread_id)
                st.toast("Stop requested", icon=":material/stop_circle:")
                st.rerun()

    queued = st.session_state.queued_submission
    if queued and not busy:
        guard_message = submission_guard_message(
            st.session_state.agent_ready,
            st.session_state.current_dump,
            queued.get("prompt"),
            is_report=queued.get("is_report", False),
        )
        if queued.get("is_report"):
            st.caption("Queued request: report generation. Run it now or cancel and edit it first.")
        else:
            st.caption("Queued request: run it now or cancel and edit it first.")
        st.markdown(queued["prompt"])
        if guard_message:
            st.warning(guard_message)
        run_col, cancel_col, spacer_col = st.columns([1, 1, 4])
        with run_col:
            if st.button(
                "Run Request",
                key="run_queued_request",
                type="primary",
                icon=":material/play_arrow:",
                disabled=guard_message is not None,
                use_container_width=True,
            ):
                st.session_state.pending_submission = queued
                st.session_state.queued_submission = None
                st.rerun()
        with cancel_col:
            if st.button(
                "Cancel",
                key="cancel_queued_request",
                icon=":material/close:",
                use_container_width=True,
            ):
                st.session_state.rejected_prompt = queued["prompt"]
                st.session_state.queued_submission = None
                st.toast("Request cancelled", icon=":material/close:")
                st.rerun()

    pending = st.session_state.pending_submission
    if pending and not busy:
        guard_message = submission_guard_message(
            st.session_state.agent_ready,
            st.session_state.current_dump,
            pending.get("prompt"),
            is_report=pending.get("is_report", False),
        )
        if guard_message:
            st.warning(guard_message)
            st.session_state.rejected_prompt = pending["prompt"]
            st.session_state.pending_submission = None
            st.stop()

        prompt = pending["prompt"]
        is_report = pending.get("is_report", False)
        st.session_state.pending_submission = None
        st.session_state.rejected_prompt = None

        text_to_send = prompt
        if (
            st.session_state.current_dump
            and not should_bypass_tools(prompt, is_report=is_report)
            and st.session_state.current_dump not in prompt
        ):
            text_to_send = f"[Selected dump: {st.session_state.current_dump}] {prompt}"

        st.session_state.messages.append({
            "role": "user",
            "content": prompt,
            "is_report": is_report,
        })
        st.session_state.turn_in_progress = True
        # Clear any leftover cancel flag (and the cross-rerun Event) from a
        # previous run before we start the new one.
        st.session_state.cancel_requested = False
        reset_cancel(st.session_state.thread_id)

        with st.chat_message("user"):
            st.markdown(prompt)

        turn_finished_ok = False
        try:
            with st.chat_message("assistant"):
                status_box = st.status("Analysing...", expanded=True)

                response_data, elapsed, todos = run_async(
                    send_message(
                        text_to_send,
                        status_container=status_box,
                        is_report=is_report,
                    )
                )

                status_box.update(
                    label=f"Done ({format_elapsed(elapsed)})",
                    state="complete",
                    expanded=True,
                )

                if response_data.get("content"):
                    streamed_text = st.write_stream(stream_text_chunks(response_data["content"]))
                    if isinstance(streamed_text, str) and streamed_text:
                        response_data["content"] = streamed_text

                tools_used = response_data.get("tool_calls")
                _turn_key = f"turn_{len(st.session_state.get('messages', []))}"
                if tools_used:
                    render_tool_calls(
                        tools_used,
                        key=f"{_turn_key}_tools",
                        default_expanded=False,
                    )
                if response_data.get("reasoning"):
                    render_reasoning(
                        response_data["reasoning"],
                        key=f"{_turn_key}_reasoning",
                        default_expanded=False,
                    )
                if response_data.get("elapsed_sec") is not None:
                    st.caption(f"Completed in {format_elapsed(response_data['elapsed_sec'])}")

                trace = dict(response_data.get("trace", {}))
                if is_report:
                    used_save_report = any(
                        tc.get("type") == "call" and tc.get("name") == "save_report"
                        for tc in (tools_used or [])
                    )
                    trace["saved_with_tool"] = used_save_report
                    if not used_save_report:
                        saved_report = auto_save_report(
                            st.session_state.current_dump or "analysis",
                            response_data["content"],
                        )
                        trace["auto_saved_report"] = bool(saved_report)
                        if saved_report:
                            st.toast("Report auto-saved",
                                     icon=":material/save:")
                        else:
                            st.warning(
                                "Report was not saved: the model's reply did not have a complete report shape "
                                "(missing required sections, placeholders left in, or the model lost context "
                                "after a long session). Click **New Session**, run a couple of focused triage "
                                "actions, then click **Generate Report** again."
                            )
                    else:
                        st.toast("Report saved", icon=":material/save:")

                if trace:
                    record_trace(trace)

                st.session_state.messages.append(response_data)
                if todos:
                    st.session_state.todos = todos
                save_current_chat_history()
                turn_finished_ok = True
        except BaseException:
            if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
                st.session_state.messages.pop()
            raise
        finally:
            st.session_state.turn_in_progress = False
            if st.session_state.cancel_requested:
                # Surface the user's stop request as a system message so the
                # transcript records that the turn was cut short.
                st.toast("Turn stopped by user", icon=":material/stop_circle:")
                st.session_state.cancel_requested = False
            reset_cancel(st.session_state.thread_id)

        if turn_finished_ok and reports_dir_signature() != reports_signature_at_start:
            st.rerun()

    if st.session_state.rejected_prompt:
        st.caption("Last unsent prompt (copy if you want to reuse it):")
        st.code(st.session_state.rejected_prompt, language="markdown")

    composer_disabled = busy or st.session_state.queued_submission is not None
    with st.form("chat_composer", clear_on_submit=True):
        chat_prompt = st.text_input(
            "Message",
            placeholder="Ask about the memory dump (e.g., 'Analyse sample.raw for malware')",
            disabled=composer_disabled,
            label_visibility="collapsed",
        )
        submitted = st.form_submit_button(
            "Send",
            icon=":material/send:",
            disabled=composer_disabled,
        )

    if submitted and chat_prompt and not busy:
        guard_message = submission_guard_message(
            st.session_state.agent_ready,
            st.session_state.current_dump,
            chat_prompt,
        )
        if guard_message:
            st.session_state.rejected_prompt = chat_prompt
            st.warning(guard_message)
            st.stop()
        st.session_state.queued_submission = {
            "prompt": chat_prompt,
            "is_report": False,
        }
        st.session_state.rejected_prompt = None
        st.rerun()


render_chat_area()
st.stop()
