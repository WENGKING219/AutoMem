"""Test bootstrap for local smoke tests without Docker/Ollama/FastMCP installed."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


if importlib.util.find_spec("fastmcp") is None:
    fastmcp_module = types.ModuleType("fastmcp")
    dependencies_module = types.ModuleType("fastmcp.dependencies")

    class FastMCP:  # minimal decorator-compatible stand-in
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def tool(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

        def run(self, *args, **kwargs):
            return None

    class Progress:
        async def set_message(self, message: str) -> None:
            self.message = message

    fastmcp_module.FastMCP = FastMCP
    dependencies_module.Progress = Progress
    sys.modules["fastmcp"] = fastmcp_module
    sys.modules["fastmcp.dependencies"] = dependencies_module
