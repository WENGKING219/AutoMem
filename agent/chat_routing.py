"""Basic routing helpers for deciding when to skip forensic tool execution."""

from __future__ import annotations

import re

TOOL_HELP_NAMES = (
    "get_image_info",
    "pslist",
    "psscan",
    "pstree",
    "psxview",
    "netscan",
    "malfind",
    "dlllist",
    "cmdline",
    "handles",
    "svcscan",
    "amcache",
    "scheduled tasks",
)

TOOL_DESCRIPTIONS = {
    "get_image_info": "reads basic operating system and memory image metadata.",
    "pslist": "lists active processes by walking the normal EPROCESS linked list.",
    "psscan": "scans memory for process objects and can find hidden or terminated processes.",
    "pstree": "shows parent-child process relationships so unusual process ancestry is easier to spot.",
    "psxview": "cross-checks multiple process sources to help identify hidden processes.",
    "netscan": "lists network connections and listening sockets found in the memory dump.",
    "malfind": "looks for injected or suspicious executable memory regions inside processes.",
    "dlllist": "lists DLLs loaded by processes, useful for suspicious module or path checks.",
    "cmdline": "extracts command-line arguments for processes.",
    "handles": "lists process handles such as files, registry keys, events, and mutexes.",
    "svcscan": "lists Windows services that may show persistence or suspicious service setup.",
    "amcache": "reads Amcache registry records to list executables that ran on the host with their full paths and SHA1 file hashes (Windows 7+, full coverage on Windows 8+).",
    "scheduled tasks": "can indicate persistence, but this build focuses on service persistence through svcscan.",
}

GENERAL_HELP_PREFIXES = (
    "who are you",
    "what are you",
    "what can you do",
    "help",
    "how do i use",
    "how to use",
    "what does",
    "what is",
    "how does",
    "tell me about",
    "explain",
    "can you explain",
)

FORENSIC_ACTION_HINTS = (
    "analyse",
    "analyze",
    "investigate",
    "scan",
    "triage",
    "check",
    "find",
    "hunt",
    "identify",
    "generate report",
    "report on",
    "suspicious",
    "ioc",
    "network",
    "connection",
    "c2",
    "beacon",
    "exfil",
    "hidden",
    "unlinked",
    "rootkit",
    "malware",
    "injection",
    "persistence",
    "amcache",
    "execution evidence",
    "pid ",
    "process ",
)

DUMP_HINTS = (
    "[selected dump:",
    ".raw",
    ".mem",
    ".dmp",
    ".vmem",
    ".lime",
    ".img",
    "memory dump",
    # Bare references the user makes when a dump is already selected — these
    # route to the tool-using agent even though no filename is in the text.
    "this dump",
    "the dump",
    "current dump",
    "selected dump",
    "this image",
    "the image",
)


def normalize_prompt_text(prompt: str) -> str:
    """Normalize whitespace and casing for lightweight prompt routing."""
    return " ".join((prompt or "").lower().split())


def should_bypass_tools(prompt: str, *, is_report: bool = False) -> bool:
    """Return True when the prompt should be answered without forensic tools.

    Routing rules (first match wins):
      1. Report turns always go to the tool-using agent.
      2. Identity questions ("who are you", "what can you do", ...) always bypass.
      3. If the prompt names a dump file or contains a forensic action verb,
         it goes to the tool-using agent — even if it starts with a help
         prefix like "what is" — because the user is asking about real data.
      4. Otherwise, if the prompt starts with a general-help prefix, it
         bypasses. This catches bare "help", "what is the workflow", and
         "explain pslist" without forcing the user to also mention a
         keyword like "tool" or "volatility".
    """
    if is_report:
        return False

    lower = normalize_prompt_text(prompt)
    if not lower:
        return False

    if any(phrase in lower for phrase in ("who are you", "what are you", "what can you do")):
        return True

    starts_with_help_prefix = any(
        lower.startswith(prefix) for prefix in GENERAL_HELP_PREFIXES
    )

    # Real-data questions always go to the agent. Check this BEFORE the
    # help-prefix bypass so "what is the suspicious PID in sample.raw"
    # routes to tools even though it starts with "what is".
    if any(hint in lower for hint in DUMP_HINTS):
        return False
    if _matches_forensic_action(lower):
        return False

    if starts_with_help_prefix:
        return True

    return False


def _matches_forensic_action(lower: str) -> bool:
    """Whole-word match against FORENSIC_ACTION_HINTS.

    Substring matching breaks on "explain malfind" (the hint "find" matches
    inside "malfind") and similar tool-name questions, so we use a regex
    word-boundary check. Hints that already include a trailing space (e.g.
    "pid ", "process ") are kept as substring checks because the trailing
    space already enforces a boundary.
    """
    for action in FORENSIC_ACTION_HINTS:
        if action.endswith(" "):
            if action in lower:
                return True
        else:
            if re.search(r"\b" + re.escape(action) + r"\b", lower):
                return True
    return False


def build_static_general_reply(prompt: str) -> str | None:
    """Return a deterministic answer for the simplest general prompts."""
    lower = normalize_prompt_text(prompt)

    if "who are you" in lower or "what are you" in lower:
        return (
            "I am a memory forensics assistant for this project. "
            "I help analyse Windows memory dumps with Volatility3 MCP tools, "
            "explain what the tools do, and generate forensic reports."
        )

    if "what can you do" in lower:
        return (
            "I can explain the workflow and tool usage, analyse memory dumps with "
            "Volatility3 through MCP, summarise findings, and generate Markdown reports."
        )

    if "netscan" in lower and any(
        token in lower for token in ("what does", "what is", "how does", "explain", "tell me about")
    ):
        return (
            "`netscan` is a Volatility plugin that enumerates network connections and "
            "listening sockets from a memory dump. It is useful for linking remote IPs, "
            "ports, and connection states back to the owning process."
        )

    for tool_name, description in TOOL_DESCRIPTIONS.items():
        if tool_name in lower and any(
            token in lower for token in ("what does", "what is", "how does", "explain", "tell me about")
        ):
            return f"`{tool_name}` {description}"

    return None
