"""
FastMCP server that exposes Volatility3 plugins as callable forensic tools.

Large plugin results are summarized before they reach the local model, while
the full parsed rows stay available through the cache for later drill-downs.
"""

import json
import logging
import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.dependencies import Progress

from volatility_mcp_server.tools.runner import (
    CACHE_DIR,
    DUMPS_DIR,
    SUPPORTED_DUMP_EXTENSIONS,
    VOL_CMD,
    compact_result_for_llm,
    lookup_cached_ntbuildlab,
    query_rows_from_cache,
    read_cached_volatility_result,
    resolve_dump_path,
    run_volatility,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("volatility_mcp")

# Small local models with 32K-128K context can handle a moderate amount of
# structured tool output. A lower 12K budget caused useful evidence to be
# hidden behind generic "limitations" replies during demos.
MAX_RESPONSE_CHARS = 60_000

# Map plugin short names (the ones the LLM uses) to the full Volatility3
# plugin path. Used by `query_plugin_rows` so the LLM never has to remember the long names.
AVAILABLE_PLUGIN_NAMES = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "pstree": "windows.pstree.PsTree",
    "psxview": "windows.psxview.PsXView",
    "cmdline": "windows.cmdline.CmdLine",
    "netscan": "windows.netscan.NetScan",
    "malfind": "windows.malfind.Malfind",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "svcscan": "windows.svcscan.SvcScan",
    "amcache": "windows.registry.amcache.Amcache",
}


def parse_optional_pid(value):
    """Convert a PID arg into an int, or None if not provided.

    Accepts the common ways local models and MCP transports encode integers:
      * bare int                          -> 1168
      * str of int                        -> "1168"
      * str of float (Ollama does this)   -> "1168.0"
      * float (some MCP transports)       -> 1168.0
    Rejects booleans (Python treats `True == 1`, which would silently match
    PID 1) and any value that doesn't represent a whole-number PID.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("pid must be an integer process ID, not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"pid must be a whole number, got {value!r}")
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        # Accept "1234" and "1234.0" alike; some Ollama models emit floats.
        try:
            return int(stripped)
        except ValueError:
            try:
                as_float = float(stripped)
            except ValueError:
                raise ValueError(f"pid must be an integer, got {value!r}") from None
            if not as_float.is_integer():
                raise ValueError(f"pid must be a whole number, got {value!r}")
            return int(as_float)
    return int(value)


mcp = FastMCP(
    "VolatilityForensics",
    instructions=(
        "Memory dump forensics tools powered by Volatility3. "
        "Pass a filename from memory_dumps or a full path. "
        "Big outputs are normalized and cached as compact JSON rows. "
        "Use query_plugin_rows for fast PID, port, path, or state drill-downs."
    ),
)


def _json_or_text(value: str) -> Any:
    """Return parsed JSON when possible, otherwise the original text."""
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def error_result(plugin: str, dump: str, error: str) -> dict:
    """Build a consistent tool error payload."""
    return {
        "plugin": plugin,
        "dump": dump,
        "success": False,
        "error": error,
    }


def file_not_found_result(memory_dump: str) -> dict:
    """Return a structured missing-input error."""
    return error_result("input", str(memory_dump), f"File not found: {memory_dump}")


def parse_max_rows(value, *, default: int = 50, hard_cap: int = 200) -> int:
    """Parse and clamp the LLM-provided max_rows argument."""
    if value in (None, ""):
        return default
    try:
        parsed_float = float(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"max_rows must be an integer, got {value!r}") from None
    if not parsed_float.is_integer():
        raise ValueError(f"max_rows must be a whole number, got {value!r}")
    parsed = int(parsed_float)
    return max(1, min(parsed, hard_cap))


async def run_simple_plugin(plugin: str, memory_dump: str) -> dict:
    """Resolve a dump and run a non-progress Volatility plugin."""
    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)
    result = await run_volatility(["-f", str(path), plugin])
    return format_result(plugin, str(path), result)


async def run_progress_plugin(
    plugin: str,
    memory_dump: str,
    progress: Progress | None = None,
) -> dict:
    """Resolve a dump and run a progress-reporting Volatility plugin."""
    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)
    return await run_plugin_with_progress(
        plugin,
        str(path),
        ["-f", str(path), plugin],
        progress,
    )


def _has_filter_args(*values) -> bool:
    return any(value not in (None, "") for value in values)


def _trim_payload_rows_if_needed(payload: dict) -> dict:
    """Keep filtered payloads inside the response budget."""
    if len(json.dumps(payload, default=str)) <= MAX_RESPONSE_CHARS:
        return payload
    payload = dict(payload)
    payload["rows"] = []
    payload["note"] = (
        "Filtered rows exceeded the response budget. Re-run with a more "
        "specific `filter_value` or a smaller `max_rows`."
    )
    return payload


async def run_filterable_progress_plugin(
    plugin_key: str,
    memory_dump: str,
    progress: Progress | None = None,
    *,
    filter_field: str = "",
    filter_value: str = "",
    filter_field_2: str = "",
    filter_value_2: str = "",
    filter_field_3: str = "",
    filter_value_3: str = "",
    max_rows: int | str = 50,
) -> dict:
    """Run a plugin and optionally return filtered cached rows.

    This guards against a common small-LLM mistake: calling `run_psxview` or
    another run tool with `filter_field`/`filter_value` instead of calling
    `query_plugin_rows`. Rather than failing validation, the server now treats
    those arguments as a filtered drill-down request.
    """
    plugin_path = AVAILABLE_PLUGIN_NAMES[plugin_key]
    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)

    args = ["-f", str(path), plugin_path]
    plugin_result = await run_plugin_with_progress(plugin_path, str(path), args, progress)
    if not _has_filter_args(
        filter_field, filter_value,
        filter_field_2, filter_value_2,
        filter_field_3, filter_value_3,
    ):
        return plugin_result
    if not plugin_result.get("success"):
        return plugin_result

    try:
        row_limit = parse_max_rows(max_rows)
    except ValueError as err:
        return error_result(plugin_path, str(path), str(err))

    filtered = await query_rows_from_cache(
        args,
        filter_field=filter_field or None,
        filter_value=filter_value or None,
        filter_field_2=filter_field_2 or None,
        filter_value_2=filter_value_2 or None,
        filter_field_3=filter_field_3 or None,
        filter_value_3=filter_value_3 or None,
        max_rows=row_limit,
        run_if_missing=False,
    )
    payload = {
        "plugin": plugin_path,
        "dump": str(path),
        "filtered": True,
        "original_row_count": plugin_result.get("row_count", 0),
        "hint": (
            "This run tool accepted filter arguments for stability. Prefer "
            "query_plugin_rows(plugin=..., filter_field=..., filter_value=...) "
            "for future drill-downs."
        ),
        **filtered,
    }
    return _trim_payload_rows_if_needed(payload)


async def run_pid_plugin(
    plugin: str,
    memory_dump: str,
    pid=None,
    progress: Progress | None = None,
) -> dict:
    """Resolve a dump and run a plugin with an optional PID filter."""
    try:
        selected_pid = parse_optional_pid(pid)
    except ValueError as err:
        return error_result(plugin, str(memory_dump), str(err))

    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)
    args = ["-f", str(path), plugin]
    if selected_pid is not None:
        args.extend(["--pid", str(selected_pid)])
    return await run_plugin_with_progress(plugin, str(path), args, progress)


def format_result(plugin: str, dump: str, result: dict) -> dict:
    """Turn a normalized Volatility result into a compact MCP payload."""
    if not result.get("success"):
        return error_result(plugin, dump, result.get("error", "Unknown Volatility error"))

    data, response_truncated = compact_result_for_llm(result, MAX_RESPONSE_CHARS)
    raw_char_count = int(result.get("raw_char_count", len(str(result.get("output", "")))) or 0)

    full_structured_result_cached = result.get("rows") is not None or result.get("data") is not None

    return {
        "plugin": plugin,
        "dump": dump,
        "success": True,
        "row_count": result.get("row_count", 0),
        "raw_char_count": raw_char_count,
        "truncated": bool(result.get("truncated")) or response_truncated,
        "response_truncated": response_truncated,
        "raw_output_over_budget": raw_char_count > MAX_RESPONSE_CHARS,
        "full_output_cached": full_structured_result_cached,
        "cache_status": result.get("cache_status", "unknown"),
        "data": data,
        "query_hint": (
            "Use query_plugin_rows with this plugin's short name to inspect "
            "cached rows by PID, PPID, ImageFileName, Path, ForeignAddr, "
            "ForeignPort, LocalPort, or State. Do not rerun the same plugin "
            "just to see more rows."
        ),
    }


# MCP Tools


async def run_plugin_with_progress(
    plugin: str,
    path: str,
    args: list[str],
    progress: Progress | None = None,
) -> dict:
    """Run a plugin with simple progress messages for the client UI."""
    if progress is not None:
        try:
            await progress.set_message(f"Running {plugin}")
        except AssertionError:
            logger.debug("Progress dependency was not bound; continuing without progress updates")
    result = await run_volatility(args)
    if progress is not None:
        try:
            await progress.set_message(f"Formatting {plugin} output")
        except AssertionError:
            logger.debug("Progress dependency was not bound; continuing without progress updates")
    return format_result(plugin, path, result)


@mcp.tool()
async def list_cached_plugins(memory_dump: str) -> dict:
    """Report which Volatility plugins already have cached results for this dump.

    Call this FIRST at the start of any analysis turn - especially when a
    chat session is reloaded - so you don't re-run plugins whose results
    are already on disk. For every plugin listed in `cached_plugins`, use
    `query_plugin_rows(plugin=..., memory_dump=...)` to drill into the
    existing data instead of calling the corresponding `run_<plugin>` tool.
    Only call `run_<plugin>` for entries in `not_cached_plugins`.

    Args:
        memory_dump: Filename or full path to the dump file.

    Returns:
        dict with `dump`, `image_info_cached` (bool), `cached_plugins`
        (list of {plugin, row_count}), and `not_cached_plugins` (list of
        short plugin names).
    """
    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)

    cached: list[dict] = []
    not_cached: list[str] = []
    for short_name, plugin_path in AVAILABLE_PLUGIN_NAMES.items():
        args = ["-f", str(path), plugin_path]
        result = read_cached_volatility_result(args)
        if result is not None and result.get("success"):
            cached.append({
                "plugin": short_name,
                "row_count": int(result.get("row_count", 0) or 0),
            })
        else:
            not_cached.append(short_name)

    info_args = ["-f", str(path), "windows.info.Info"]
    info_cached = read_cached_volatility_result(info_args) is not None

    return {
        "dump": str(path),
        "image_info_cached": info_cached,
        "cached_plugins": cached,
        "not_cached_plugins": not_cached,
        "guidance": (
            "For any entry in cached_plugins, call query_plugin_rows instead "
            "of run_<plugin>. Only run plugins from not_cached_plugins when "
            "fresh evidence is genuinely needed."
        ),
    }


@mcp.tool()
async def list_memory_dumps() -> dict:
    """List all memory dump files in the dumps directory."""
    dumps: list[dict] = []
    if DUMPS_DIR.is_dir():
        for file in sorted(DUMPS_DIR.iterdir()):
            if (
                file.is_file()
                and not file.name.startswith(".")
                and file.suffix.lower() in SUPPORTED_DUMP_EXTENSIONS
            ):
                dumps.append({
                    "name": file.name,
                    "size_mb": round(file.stat().st_size / (1024 * 1024), 2),
                    "path": str(file),
                })
    return {"dumps_directory": str(DUMPS_DIR), "files": dumps}


@mcp.tool()
async def query_plugin_rows(
    plugin: str,
    memory_dump: str,
    filter_field: str = "",
    filter_value: str = "",
    filter_field_2: str = "",
    filter_value_2: str = "",
    filter_field_3: str = "",
    filter_value_3: str = "",
    max_rows: int | str = 50,
    run_if_missing: bool = True,
) -> dict:
    """Drill into a previously-run plugin's full results.

    Prefer this AFTER a plugin returned a truncated preview, instead of running
    the plugin again. Filters normally happen in Python on the cached output.
    If cache is missing, the tool can run the plugin once (`run_if_missing=True`)
    so common LLM call-order mistakes do not crash the analysis.

    Args:
        plugin: Short plugin name. One of: pslist, psscan, pstree, psxview,
            cmdline, netscan, malfind, dlllist, handles, svcscan, amcache.
        memory_dump: Filename or full path to the dump file.
        filter_field: Column to filter on (e.g. PID, ImageFileName,
            ForeignAddr, Path). Leave empty to return the first `max_rows`.
        filter_value: Value to match. Integer match for PID-like fields,
            case-insensitive substring match for everything else.
        max_rows: Maximum number of rows to return (default 50, hard cap 200).
        run_if_missing: If true, run the plugin once when no cache exists.
        filter_field_2: Optional second column filter for narrowing large matches.
        filter_value_2: Value for the optional second filter.
        filter_field_3: Optional third column filter (e.g. combine PID + State + CreateTime).
        filter_value_3: Value for the optional third filter.

    Examples:
        query_plugin_rows("pslist", "sample.raw", "ImageFileName", "powershell")
        query_plugin_rows("netscan", "sample.raw", "ForeignPort", "443")
        query_plugin_rows("handles", "sample.raw", "PID", "1168", max_rows=100)
        query_plugin_rows("amcache", "sample.raw", "Path", "AppData")
        query_plugin_rows("amcache", "sample.raw", "SHA1", "<sha1>")
        query_plugin_rows("amcache", "sample.raw", "EntryType", "Program")
    """
    plugin_key = (plugin or "").strip().lower()
    if plugin_key not in AVAILABLE_PLUGIN_NAMES:
        return error_result(
            "query_plugin_rows",
            str(memory_dump),
            f"Unknown plugin '{plugin}'. Choose one of: {sorted(AVAILABLE_PLUGIN_NAMES.keys())}",
        )

    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)

    try:
        row_limit = parse_max_rows(max_rows)
    except ValueError as err:
        return error_result("query_plugin_rows", str(path), str(err))
    plugin_path = AVAILABLE_PLUGIN_NAMES[plugin_key]
    args = ["-f", str(path), plugin_path]

    result = await query_rows_from_cache(
        args,
        filter_field=filter_field or None,
        filter_value=filter_value or None,
        filter_field_2=filter_field_2 or None,
        filter_value_2=filter_value_2 or None,
        filter_field_3=filter_field_3 or None,
        filter_value_3=filter_value_3 or None,
        max_rows=row_limit,
        run_if_missing=run_if_missing,
    )
    payload = {
        "plugin": plugin_path,
        "dump": str(path),
        **result,
    }
    return _trim_payload_rows_if_needed(payload)


@mcp.tool()
async def server_diagnostics() -> dict:
    """Return basic server-side diagnostics helpful before a live demo."""
    dumps_exist = DUMPS_DIR.is_dir()
    cache_exists = CACHE_DIR.is_dir()
    dump_files = []
    if dumps_exist:
        dump_files = [
            file.name
            for file in sorted(DUMPS_DIR.iterdir())
            if file.is_file()
            and not file.name.startswith(".")
            and file.suffix.lower() in SUPPORTED_DUMP_EXTENSIONS
        ]
    cache_files = []
    cache_size_mb = 0.0
    if cache_exists:
        cache_files = [file for file in CACHE_DIR.glob("*.json") if file.is_file()]
        cache_size_mb = round(sum(file.stat().st_size for file in cache_files) / (1024 * 1024), 2)
    return {
        "volatility_command": VOL_CMD,
        "transport": os.environ.get("MCP_TRANSPORT", "http"),
        "mcp_endpoint": f"http://{os.environ.get('MCP_HOST', '0.0.0.0')}:{os.environ.get('MCP_PORT', '8000')}{os.environ.get('MCP_PATH', '/mcp')}",
        "dumps_directory": str(DUMPS_DIR),
        "dumps_directory_exists": dumps_exist,
        "supported_dump_extensions": list(SUPPORTED_DUMP_EXTENSIONS),
        "dump_count": len(dump_files),
        "dump_files": dump_files,
        "cache_directory": str(CACHE_DIR),
        "cache_directory_exists": cache_exists,
        "cache_entries": len(cache_files),
        "cache_size_mb": cache_size_mb,
        "cache_schema_version": 2,
        "max_response_chars": MAX_RESPONSE_CHARS,
    }


@mcp.tool()
async def get_image_info(memory_dump: str) -> dict:
    """Get OS profile and metadata from a memory dump.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_simple_plugin("windows.info.Info", memory_dump)


@mcp.tool()
async def run_pslist(memory_dump: str) -> dict:
    """List running processes from a memory dump (walks the EPROCESS linked list).

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_simple_plugin("windows.pslist.PsList", memory_dump)


@mcp.tool()
async def run_psscan(memory_dump: str, progress: Progress = Progress()) -> dict:
    """Pool-tag scan for processes -- can find hidden or terminated ones that pslist misses.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_progress_plugin("windows.psscan.PsScan", memory_dump, progress)


@mcp.tool()
async def run_pstree(memory_dump: str) -> dict:
    """Show the process tree (parent-child relationships).

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_simple_plugin("windows.pstree.PsTree", memory_dump)


@mcp.tool()
async def run_netscan(memory_dump: str, progress: Progress = Progress()) -> dict:
    """Scan for network connections and listening sockets.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_progress_plugin("windows.netscan.NetScan", memory_dump, progress)


@mcp.tool()
async def run_malfind(
    memory_dump: str,
    pid=None,
    progress: Progress = Progress(),
) -> dict:
    """Look for injected code and suspicious memory regions (useful for malware hunting).

    Args:
        memory_dump: Filename or full path to the dump file.
        pid: If set, only scan this process ID (faster, narrower scope).
    """
    return await run_pid_plugin("windows.malfind.Malfind", memory_dump, pid, progress)


@mcp.tool()
async def run_dlllist(
    memory_dump: str,
    pid=None,
    progress: Progress = Progress(),
) -> dict:
    """List DLLs loaded by each process, or filter to a specific PID.

    Args:
        memory_dump: Filename or full path to the dump file.
        pid: (Optional) only show DLLs for this process ID.
    """
    return await run_pid_plugin("windows.dlllist.DllList", memory_dump, pid, progress)


@mcp.tool()
async def run_cmdline(memory_dump: str) -> dict:
    """Extract the command-line arguments for each process.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_simple_plugin("windows.cmdline.CmdLine", memory_dump)


@mcp.tool()
async def run_handles(
    memory_dump: str,
    pid=None,
    progress: Progress = Progress(),
) -> dict:
    """List open handles (files, registry keys, mutexes, etc.) for processes.

    Args:
        memory_dump: Filename or full path to the dump file.
        pid: (Optional) only show handles for this process ID.
    """
    return await run_pid_plugin("windows.handles.Handles", memory_dump, pid, progress)


@mcp.tool()
async def run_svcscan(memory_dump: str, progress: Progress = Progress()) -> dict:
    """List Windows services to help spot suspicious or persistent services.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    return await run_progress_plugin("windows.svcscan.SvcScan", memory_dump, progress)


@mcp.tool()
async def run_psxview(
    memory_dump: str,
    filter_field: str = "",
    filter_value: str = "",
    filter_field_2: str = "",
    filter_value_2: str = "",
    filter_field_3: str = "",
    filter_value_3: str = "",
    max_rows: int | str = 50,
    progress: Progress = Progress(),
) -> dict:
    """Cross-check process visibility across multiple sources to spot hidden processes.

    Args:
        memory_dump: Filename or full path to the dump file.
        filter_field: Optional column filter accepted for stability; prefer
            query_plugin_rows(plugin="psxview", ...) for drill-downs.
        filter_value: Optional value for filter_field.
        max_rows: Maximum filtered rows to return when a filter is supplied.
        filter_field_2: Optional second filter column.
        filter_value_2: Optional second filter value.
        filter_field_3: Optional third filter column.
        filter_value_3: Optional third filter value.
    """
    return await run_filterable_progress_plugin(
        "psxview",
        memory_dump,
        progress,
        filter_field=filter_field,
        filter_value=filter_value,
        filter_field_2=filter_field_2,
        filter_value_2=filter_value_2,
        filter_field_3=filter_field_3,
        filter_value_3=filter_value_3,
        max_rows=max_rows,
    )


@mcp.tool()
async def run_amcache(memory_dump: str, progress: Progress = Progress()) -> dict:
    """Pull Amcache execution evidence (program-run records) from the registry.

    Wraps Volatility3's `windows.registry.amcache.Amcache` plugin. It parses
    the Win8/Win10 keys `Root\\InventoryApplicationFile`,
    `Root\\InventoryDriverBinary`, `Root\\Programs`, and `Root\\File`, so:
      - Windows 10/2016+: full coverage (programs, files, drivers).
      - Windows 8/2012:   programs and files (no driver inventory).
      - Windows 7:        usually returns 0 rows (keys not populated).
      - Windows XP/2003:  hive does not exist - blocked at this server.

    Output is a TreeGrid with columns:
      EntryType (Driver/Program/File), Path, Company, LastModifyTime,
      LastModifyTime2, InstallTime, CompileTime, SHA1, Service, ProductName,
      ProductVersion.

    Output can be large (hundreds-thousands of rows on Win10), so the
    response is a statistics + sample preview. Use
    `query_plugin_rows("amcache", ...)` to filter on `Path`, `SHA1`,
    `EntryType`, or `Company`. The returned `SHA1` values are real file
    hashes suitable for VirusTotal lookups.

    Args:
        memory_dump: Filename or full path to the dump file.
    """
    path = resolve_dump_path(memory_dump)
    if not path.is_file():
        return file_not_found_result(memory_dump)
    build_lab = lookup_cached_ntbuildlab(path)
    if build_lab and (
        "xpsp" in build_lab.lower()
        or build_lab.lstrip().startswith("2600.")
    ):
        return error_result(
            "windows.registry.amcache.Amcache",
            str(path),
            (
                f"Amcache hive does not exist on Windows XP / Server 2003 "
                f"(NTBuildLab={build_lab}). Skip this plugin and document it "
                "as 'Evidence not collected (plugin unsupported on this OS)'."
            ),
        )
    return await run_progress_plugin("windows.registry.amcache.Amcache", memory_dump, progress)


# Entrypoint


def run_server() -> None:
    """Start the MCP server in the configured transport mode.

    Default is HTTP because it is simpler for a Streamlit app: Docker Compose
    starts one long-running server, and the agent connects to its /mcp URL.
    Set MCP_TRANSPORT=stdio for inspector/debug sessions that need stdio.
    """
    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    logger.info("Starting Volatility MCP Server")
    logger.info("Dumps directory: %s", DUMPS_DIR)
    logger.info("Result cache directory: %s", CACHE_DIR)

    if transport in {"http", "streamable-http", "streamable_http"}:
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8000"))
        path = os.environ.get("MCP_PATH", "/mcp")
        logger.info("HTTP MCP endpoint: http://%s:%s%s", host, port, path)
        mcp.run(transport="http", host=host, port=port, path=path)
        return

    logger.info("Using stdio MCP transport")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run_server()
