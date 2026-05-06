"""Helpers that keep final replies readable and consistent across models."""

from __future__ import annotations

import ast
import json
from pathlib import PurePath
from typing import Any


def _has_section(text: str, section_name: str) -> bool:
    lowered = text.lower()
    markers = (
        f"{section_name.lower()}:",
        f"## {section_name.lower()}",
        f"### {section_name.lower()}",
    )
    return any(marker in lowered for marker in markers)


def _coerce_tool_payload(value: Any) -> Any:
    """Decode MCP/adapter tool payloads into their underlying JSON when possible."""
    if not isinstance(value, str):
        return value

    raw = value.strip()
    decoded: Any = None
    for loader in (json.loads, ast.literal_eval):
        try:
            decoded = loader(raw)
            break
        except (json.JSONDecodeError, SyntaxError, ValueError, TypeError):
            decoded = None

    if isinstance(decoded, list):
        text_parts = [
            item.get("text", "")
            for item in decoded
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        if text_parts:
            return _coerce_tool_payload("\n".join(text_parts))
        return decoded

    if isinstance(decoded, dict):
        return decoded

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return raw


def extract_tool_errors(tool_calls: list[dict] | None) -> list[dict[str, str]]:
    """Return structured error summaries from collected tool result entries."""
    errors: list[dict[str, str]] = []
    for item in tool_calls or []:
        if item.get("type") != "result":
            continue
        payload = _coerce_tool_payload(item.get("result", ""))
        if not isinstance(payload, dict):
            continue
        error = payload.get("error")
        if error or payload.get("success") is False:
            errors.append(
                {
                    "tool": str(item.get("name") or payload.get("plugin") or "tool"),
                    "plugin": str(payload.get("plugin") or item.get("name") or "unknown"),
                    "dump": str(payload.get("dump") or ""),
                    "error": str(error or "Tool returned success=false without details."),
                }
            )
    return errors


def tool_calls_have_hard_errors(tool_calls: list[dict] | None) -> bool:
    """True when tool execution failed and another model retry is unlikely to help."""
    return bool(extract_tool_errors(tool_calls))


def build_tool_result_fallback(tool_calls: list[dict] | None) -> str:
    """Build a deterministic final reply when the model produced no text."""
    calls = [item for item in (tool_calls or []) if item.get("type") == "call"]
    errors = extract_tool_errors(tool_calls)
    if not calls and not errors:
        return ""

    lines: list[str] = []
    if errors:
        first = errors[0]
        error_text = first["error"].replace("\r", "\n").strip()
        short_error = next(
            (line.strip() for line in error_text.splitlines() if line.strip()),
            error_text[:300],
        )
        lines.extend(
            [
                "I could not complete the analysis because the forensic tool failed before usable evidence was produced.",
                "",
                f"- Failed tool/plugin: `{first['plugin']}`",
            ]
        )
        if first["dump"]:
            lines.append(f"- Dump: `{first['dump']}`")
        lines.append(f"- Error: {short_error}")

        lowered = error_text.lower()
        if "vmem metadata" in lowered or "vmss" in lowered or "vmsn" in lowered:
            dump_name = PurePath(first["dump"]).name if first["dump"] else "the .vmem file"
            lines.extend(
                [
                    "",
                    f"Most likely cause: `{dump_name}` is a VMware memory file without the matching snapshot metadata. Put the same-base-name `.vmss` or `.vmsn` file beside the `.vmem`, then rerun the analysis. If you only have the `.vmem`, export or convert it to a raw memory image first.",
                ]
            )
    else:
        unique_tools = []
        for call in calls:
            name = str(call.get("name", "unknown"))
            if name not in unique_tools:
                unique_tools.append(name)
        lines.extend(
            [
                "The tools ran, but the model did not produce a final written answer.",
                "",
                "- Tools called: " + ", ".join(f"`{name}`" for name in unique_tools[:8]),
            ]
        )

    lines.extend(
        [
            "",
            "Confidence: Low - no successful forensic plugin output was available for interpretation.",
            "",
            "Limitations:",
            "- No process, network, registry, or malware findings can be trusted until the dump parses successfully.",
        ]
    )
    return "\n".join(lines)


def normalize_chat_reply(
    content: str,
    *,
    is_report: bool = False,
    include_quality_sections: bool = True,
) -> str:
    """Append basic quality sections when a weaker model omits them."""
    text = (content or "").strip()
    if not text:
        if is_report:
            return "# Memory Forensics Analysis Report\n\nNo report content was generated."
        if not include_quality_sections:
            return "No final answer was generated."
        return (
            "No final answer was generated.\n\n"
            "Confidence: Low - the model did not provide a usable response.\n\n"
            "Limitations:\n- The response was empty."
        )

    if is_report or not include_quality_sections:
        return text

    parts = [text]
    if not _has_section(text, "Confidence"):
        parts.append(
            "Confidence: Medium - based on the current evidence collected in this turn."
        )
    if not _has_section(text, "Limitations"):
        parts.append(
            "Limitations:\n"
            "- Results may be partial if plugin output was truncated or the analysis was scoped."
        )
    return "\n\n".join(parts)
