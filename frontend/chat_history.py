"""
Small helpers for saving compact Streamlit chat history.

The app keeps only the latest few chats and trims large tool previews so the
sidebar history does not grow into another context/memory problem.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


MAX_CHAT_HISTORIES = 3
MESSAGE_TEXT_LIMIT = 12000
REASONING_TEXT_LIMIT = 2000
TOOL_RESULT_LIMIT = 600
TOOL_ARGS_LIMIT = 600
TITLE_LIMIT = 56


def shorten_text(value: Any, limit: int) -> str:
    """Return a safe short string for history storage."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n\n[Preview trimmed to save memory.]"


def compact_tool_call(tool_call: dict) -> dict:
    """Keep enough tool data for display without saving huge outputs."""
    compact = {
        "type": tool_call.get("type"),
        "name": tool_call.get("name", ""),
    }
    if tool_call.get("id"):
        compact["id"] = tool_call.get("id")
    if tool_call.get("step"):
        compact["step"] = tool_call.get("step")

    if tool_call.get("type") == "call":
        args = tool_call.get("args", {})
        args_text = json.dumps(args, default=str)
        if len(args_text) > TOOL_ARGS_LIMIT:
            compact["args"] = {"preview": shorten_text(args_text, TOOL_ARGS_LIMIT)}
        else:
            compact["args"] = args
    elif tool_call.get("type") == "result":
        compact["result"] = shorten_text(tool_call.get("result", ""), TOOL_RESULT_LIMIT)

    return compact


def compact_message(message: dict) -> dict:
    """Keep the fields needed by render_message."""
    compact = {
        "role": message.get("role", "assistant"),
        "content": shorten_text(message.get("content", ""), MESSAGE_TEXT_LIMIT),
    }
    if message.get("is_report"):
        compact["is_report"] = True
    if message.get("elapsed_sec") is not None:
        compact["elapsed_sec"] = message.get("elapsed_sec")
    if message.get("agent_mode"):
        compact["agent_mode"] = message.get("agent_mode")
    if message.get("reasoning"):
        compact["reasoning"] = shorten_text(message.get("reasoning", ""), REASONING_TEXT_LIMIT)
    if message.get("tool_calls"):
        compact["tool_calls"] = [
            compact_tool_call(tool_call)
            for tool_call in message.get("tool_calls", [])
            if isinstance(tool_call, dict)
        ]
    return compact


def compact_todos(todos: list) -> list:
    """Store a short copy of the investigation todo list."""
    compact = []
    for item in todos[-10:]:
        if not isinstance(item, dict):
            continue
        compact.append({
            "status": item.get("status", "pending"),
            "content": shorten_text(item.get("content", item.get("task", "")), 300),
        })
    return compact


def make_chat_title(messages: list, current_dump: str | None) -> str:
    """Use the first user prompt as the chat title."""
    title = "New chat"
    for message in messages:
        if message.get("role") == "user" and message.get("content"):
            title = " ".join(str(message["content"]).split())
            break

    if current_dump:
        title = f"{Path(current_dump).stem}: {title}"

    if len(title) > TITLE_LIMIT:
        title = title[: TITLE_LIMIT - 3].rstrip() + "..."
    return title


def build_history_record(
    chat_id: str,
    thread_id: str,
    messages: list,
    current_dump: str | None,
    todos: list,
) -> dict:
    """Create one compact history item."""
    stored_messages = [
        compact_message(message)
        for message in messages
        if isinstance(message, dict) and message.get("role") in {"user", "assistant"}
    ]
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    return {
        "id": chat_id,
        "thread_id": thread_id,
        "title": make_chat_title(stored_messages, current_dump),
        "current_dump": current_dump,
        "message_count": len(stored_messages),
        "updated_at": now,
        "messages": stored_messages,
        "todos": compact_todos(todos),
    }


def upsert_history(histories: list, record: dict) -> list:
    """Insert or replace a history item and keep only the newest few."""
    kept = [item for item in histories if item.get("id") != record.get("id")]
    return [record] + kept[: MAX_CHAT_HISTORIES - 1]


def remove_history(histories: list, chat_id: str) -> list:
    """Return histories without the selected chat id."""
    return [item for item in histories if item.get("id") != chat_id]


def find_history(histories: list, chat_id: str) -> dict | None:
    """Find one saved history by id."""
    for item in histories:
        if item.get("id") == chat_id:
            return item
    return None


def load_history_file(path: Path) -> list:
    """Load saved history records from disk."""
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []
        return data[:MAX_CHAT_HISTORIES]
    except (OSError, json.JSONDecodeError):
        return []


def save_history_file(path: Path, histories: list) -> None:
    """Persist compact history records to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(histories[:MAX_CHAT_HISTORIES], indent=2, ensure_ascii=True),
        encoding="utf-8",
    )


def format_history_time(value: str | None) -> str:
    """Format a saved ISO timestamp for the sidebar."""
    if not value:
        return "unknown time"
    try:
        return datetime.fromisoformat(value).strftime("%d %b %H:%M")
    except ValueError:
        return value
