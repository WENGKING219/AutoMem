"""
Small, stable Volatility3 runner used by the MCP server.

Design goals for the FYP demo:
- one Volatility command path: quiet JSON renderer + persistent Volatility cache
- one project result-cache format: parsed JSON rows, not huge escaped raw JSON
- one drill-down path for the LLM: query_plugin_rows filters cached rows quickly
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("volatility_mcp")
VOLATILITY_SUBPROCESS_LOCK = asyncio.Lock()

VOL_CMD = os.environ.get("VOL_CMD", "vol")
DUMPS_DIR = Path(os.environ.get("DUMPS_DIR", "/data/memory_dumps"))
CACHE_DIR = Path(os.environ.get("CACHE_DIR", "/data/cache/results"))
VOL_FRAMEWORK_CACHE_DIR = Path(
    os.environ.get("VOL_FRAMEWORK_CACHE_DIR", "/data/cache/volatility3-2.27-symbolpack-v1")
)
VOL_SYMBOL_DIRS = os.environ.get("VOL_SYMBOL_DIRS", "/app/symbols")
TIMEOUT = int(os.environ.get("VOL_TIMEOUT", "300"))
MAX_OUTPUT = int(os.environ.get("MAX_OUTPUT", "2000000"))
MAX_ROWS_FULL = int(os.environ.get("MAX_ROWS_FULL", "500"))
CACHE_SCHEMA_VERSION = 2
SUPPORTED_DUMP_EXTENSIONS = (".raw", ".mem", ".dmp", ".vmem", ".lime", ".img")

PLUGIN_TIMEOUTS = {
    "windows.malfind.Malfind": 360,
    "windows.handles.Handles": 360,
    "windows.dlllist.DllList": 300,
    "windows.netscan.NetScan": 300,
    "windows.psscan.PsScan": 240,
    "windows.psxview.PsXView": 240,
    "windows.registry.amcache.Amcache": 360,
}

PID_LIKE_FIELDS = {
    "pid",
    "ppid",
    "tid",
    "thread",
    "processid",
    "process_id",
    "process id",
    "ownerpid",
    "owningprocess",
    "owning process",
}

FIELD_ALIASES = {
    "pid": {
        "pid",
        "processid",
        "process_id",
        "process id",
        "owningprocess",
        "owning process",
        "ownerpid",
    },
    "ppid": {"ppid", "parentpid", "parent pid", "inheritedfromuniqueprocessid"},
    "name": {"imagefilename", "imagename", "image", "name", "process", "processname"},
    "path": {"path", "file", "fullpath", "imagepath", "binary", "binarypath", "filename"},
    "commandline": {"commandline", "cmdline", "command", "args"},
    "foreignaddr": {"foreignaddr", "foreignaddress", "remoteaddr", "remoteaddress"},
    "foreignport": {"foreignport", "remoteport", "dstport", "destinationport"},
    "localaddr": {"localaddr", "localaddress", "sourceaddr", "sourceaddress"},
    "localport": {"localport", "sourceport", "srcport"},
    "state": {"state", "status"},
}

SUSPICIOUS_PORTS: set[int] = set()


def detect_plugin_name(cmd_args: list[str]) -> str:
    """Extract the Volatility plugin path from CLI arguments when present."""
    for arg in cmd_args:
        if str(arg).startswith(("windows.", "linux.", "mac.")):
            return str(arg)
    return ""


def get_plugin_timeout(plugin_name: str) -> int:
    """Return the timeout budget for a specific plugin."""
    return PLUGIN_TIMEOUTS.get(plugin_name, TIMEOUT)


def find_dump_argument(args: list[str]) -> Path | None:
    """Return the dump path passed after -f, if one is present."""
    for index, arg in enumerate(args):
        if arg == "-f" and index + 1 < len(args):
            return Path(args[index + 1])
    return None


def make_cache_key(args: list[str], *, use_json: bool = True) -> str:
    """Build a stable cache key for plugin args plus dump identity.

    The project cache key deliberately ignores the Volatility framework cache
    directory. Moving the project between machines should not invalidate result
    cache entries as long as the command, dump size, and dump mtime are the same.
    """
    key_parts = ["json" if use_json else "text", *map(str, args)]
    dump_path = find_dump_argument(args)
    if dump_path and dump_path.is_file():
        stat = dump_path.stat()
        key_parts.extend(
            [
                f"dump_size={stat.st_size}",
                f"dump_mtime_ns={stat.st_mtime_ns}",
            ]
        )
    return hashlib.sha256("\0".join(key_parts).encode("utf-8")).hexdigest()[:24]


def read_cache(key: str) -> str | None:
    """Read one cache file, ignoring missing or unreadable entries."""
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        logger.info("Result cache hit: %s", key)
        return path.read_text(encoding="utf-8")
    except OSError as err:
        logger.warning("Could not read cache entry %s: %s", key, err)
        return None


def write_cache(key: str, data: str) -> None:
    """Atomically write one result cache file."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    target = CACHE_DIR / f"{key}.json"
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{key}.",
        suffix=".tmp",
        dir=str(CACHE_DIR),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
        tmp_path.replace(target)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def resolve_dump_path(name_or_path: str) -> Path:
    """Resolve a bare dump name or safe in-container path to a real file path."""
    path = Path(str(name_or_path or ""))
    if path.is_absolute() and path.is_file():
        dumps_root = DUMPS_DIR.resolve()
        resolved = path.resolve()
        if resolved == dumps_root or dumps_root in resolved.parents:
            return resolved
        # Do not allow the model to make Volatility read arbitrary host paths.
        return DUMPS_DIR / path.name
    if path.is_absolute():
        return path

    candidate = DUMPS_DIR / path.name
    if candidate.is_file():
        return candidate
    for ext in SUPPORTED_DUMP_EXTENSIONS:
        guess = DUMPS_DIR / (path.stem + ext)
        if guess.is_file():
            return guess
    return path


def dump_preflight_error(path: Path) -> str | None:
    """Return an actionable error before invoking Volatility, if any.

    Do not reject standalone VMware ``.vmem`` files here. Volatility3 can often
    recover enough layer information from the memory image itself, and direct
    Kali/Volatility runs should match MCP behavior as closely as possible.
    """
    return None


def _parse_json_safe(raw: str | bytes | None) -> Any:
    """Parse JSON and tolerate harmless text before/after the JSON payload."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    text = str(raw).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # Last-resort salvage for renderers/wrappers that prepend a warning line.
    starts = [idx for idx in (text.find("["), text.find("{")) if idx != -1]
    if not starts:
        return None
    start = min(starts)
    end = max(text.rfind("]"), text.rfind("}"))
    if end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _normalise_column_name(name: str) -> str:
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def _canonical_field_name(name: str | None) -> str:
    normalised = _normalise_column_name(name or "")
    for canonical, aliases in FIELD_ALIASES.items():
        if normalised in {_normalise_column_name(alias) for alias in aliases}:
            return canonical
    return normalised


def _rows_from_columns_shape(data: dict) -> list[dict] | None:
    columns = data.get("columns") or data.get("Columns")
    rows = data.get("rows") or data.get("Rows")
    if not isinstance(columns, list) or not isinstance(rows, list):
        return None
    column_names = [str(col.get("name", col)) if isinstance(col, dict) else str(col) for col in columns]
    converted = []
    for row in rows:
        if isinstance(row, dict):
            converted.append(row)
        elif isinstance(row, (list, tuple)):
            converted.append({column_names[i]: value for i, value in enumerate(row[: len(column_names)])})
    return converted


def _flatten_tree_rows(rows: list) -> list:
    """Flatten Volatility's nested `__children` rows (used by pstree).

    Volatility3's pstree returns one row per root process with descendants
    nested under `__children`. Treating only the roots as rows hides the
    full tree, so we walk the tree depth-first and depth-tag each node.
    """
    if not rows or not isinstance(rows[0], dict) or "__children" not in rows[0]:
        return rows

    flat: list = []

    def visit(row: dict, depth: int) -> None:
        if not isinstance(row, dict):
            flat.append(row)
            return
        children = row.get("__children") or []
        node = {key: value for key, value in row.items() if key != "__children"}
        node.setdefault("Depth", depth)
        flat.append(node)
        for child in children:
            visit(child, depth + 1)

    for root in rows:
        visit(root, 0)
    return flat


def coerce_row_list(data: Any) -> list | None:
    """Return a row list from common Volatility/FastMCP JSON shapes."""
    if isinstance(data, list):
        return _flatten_tree_rows(data)
    if not isinstance(data, dict):
        return None

    table_rows = _rows_from_columns_shape(data)
    if table_rows is not None:
        return _flatten_tree_rows(table_rows)

    for key in ("data", "rows", "results", "items"):
        value = data.get(key)
        if isinstance(value, list):
            if key == "rows":
                table_rows = _rows_from_columns_shape(data)
                if table_rows is not None:
                    return _flatten_tree_rows(table_rows)
            return _flatten_tree_rows(value)
        if isinstance(value, dict):
            nested = coerce_row_list(value)
            if nested is not None:
                return nested
    return None


def resolve_row_field(row: dict, requested: str | None) -> str | None:
    """Resolve a requested column name against a row using aliases."""
    if not requested or not isinstance(row, dict):
        return None
    if requested in row:
        return requested

    requested_lower = str(requested).lower()
    for key in row:
        if str(key).lower() == requested_lower:
            return key

    requested_norm = _normalise_column_name(requested)
    for key in row:
        if _normalise_column_name(key) == requested_norm:
            return key

    requested_canonical = _canonical_field_name(requested)
    for key in row:
        if _canonical_field_name(key) == requested_canonical:
            return key
    return None


def parse_intish(value) -> int | None:
    """Parse integer-like values such as 740, '740', or '740.0'."""
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not parsed.is_integer():
        return None
    return int(parsed)


def _stringify_cell(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    return str(value)


def filter_rows(rows, filter_field=None, filter_value=None):
    """Return rows whose column matches the requested filter.

    PID-like columns use integer equality. Other columns use case-insensitive
    substring matching. Column names are matched by aliases, so PID/ProcessId
    and ForeignAddr/RemoteAddress behave as expected for different renderers.
    """
    if not rows or not filter_field or filter_value in (None, ""):
        return list(rows)

    target_text = str(filter_value).strip().lower()
    canonical = _canonical_field_name(filter_field)
    pid_like = canonical in {_canonical_field_name(field) for field in PID_LIKE_FIELDS}
    target_int = parse_intish(filter_value) if pid_like else None

    def matches(row) -> bool:
        if not isinstance(row, dict):
            return False
        actual_field = resolve_row_field(row, filter_field)
        if actual_field is None:
            return False
        cell = row.get(actual_field)
        if target_int is not None:
            cell_int = parse_intish(cell)
            if cell_int == target_int:
                return True
        return target_text in _stringify_cell(cell).lower()

    return [row for row in rows if matches(row)]


def apply_row_filters(rows, filters: Iterable[tuple[str | None, Any]]):
    """Apply multiple simple filters in sequence."""
    filtered = list(rows)
    applied = []
    for field, value in filters:
        if field and value not in (None, ""):
            before = len(filtered)
            filtered = filter_rows(filtered, field, value)
            applied.append(
                {"field": field, "value": value, "before": before, "after": len(filtered)}
            )
    return filtered, applied


def _volatility_global_args(*, use_json: bool) -> list[str]:
    args: list[str] = []
    if use_json:
        # Volatility's docs recommend json/jsonl in conjunction with -q when the
        # output is intended for another program.
        args.extend(["-q", "-r", "json"])
    symbol_dirs = ";".join(
        str(path)
        for raw_path in VOL_SYMBOL_DIRS.split(";")
        if (path := Path(raw_path.strip())).is_dir()
    )
    if symbol_dirs:
        args.extend(["--symbol-dirs", symbol_dirs])
    if VOL_FRAMEWORK_CACHE_DIR:
        VOL_FRAMEWORK_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        args.extend(["--cache-path", str(VOL_FRAMEWORK_CACHE_DIR)])
    return args


def _normalise_success_result(
    *,
    cmd_args: list[str],
    stdout_text: str,
    stderr_text: str,
    use_json: bool,
    cache_status: str,
) -> dict:
    data = _parse_json_safe(stdout_text) if use_json else None
    rows = coerce_row_list(data) if use_json else None
    if rows is not None:
        row_count = len(rows)
    elif isinstance(data, dict):
        row_count = 1
    else:
        row_count = stdout_text.count("\n") if stdout_text else 0

    result = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "success": True,
        "error": "",
        "plugin": detect_plugin_name(cmd_args),
        "row_count": row_count,
        "raw_char_count": len(stdout_text),
        "stderr_preview": stderr_text[:4000],
        "truncated": len(stdout_text) > MAX_OUTPUT,
        "cache_status": cache_status,
        "data": data,
        "rows": rows,
        # Kept only in the live return value for backwards compatibility with
        # tests and older formatting code. It is stripped before writing cache.
        "output": stdout_text,
    }
    if data is None:
        result["text_preview"] = stdout_text[:MAX_OUTPUT]
    return result


def _cacheable_result(result: dict) -> dict:
    """Return the compact on-disk cache entry.

    The old implementation stored raw Volatility JSON as an escaped string. The
    new cache stores one normalized representation: row plugins keep only rows;
    non-table plugins keep their parsed JSON object or a short text preview.
    """
    cache_entry = {key: value for key, value in result.items() if key != "output"}

    rows = cache_entry.get("rows")
    if rows is not None:
        cache_entry["data"] = None
    else:
        inferred_rows = coerce_row_list(cache_entry.get("data"))
        if inferred_rows is not None:
            cache_entry["rows"] = inferred_rows
            cache_entry["data"] = None

    if cache_entry.get("data") is None and cache_entry.get("rows") is None and "text_preview" not in cache_entry:
        cache_entry["text_preview"] = str(result.get("output", ""))[:MAX_OUTPUT]
    return cache_entry


def _upgrade_cached_result(result: dict) -> dict:
    """Accept both the new normalized cache and the previous raw-output cache."""
    if result.get("schema_version") == CACHE_SCHEMA_VERSION:
        upgraded = dict(result)
        # This function is only used after reading from disk, so report a real
        # cache hit even if the stored entry was originally created by a miss.
        upgraded["cache_status"] = "hit"
        upgraded.setdefault("error", "")
        if upgraded.get("rows") is None:
            upgraded["rows"] = coerce_row_list(upgraded.get("data"))
        if "row_count" not in upgraded:
            upgraded["row_count"] = len(upgraded.get("rows") or [])
        upgraded.setdefault("raw_char_count", len(str(upgraded.get("output", ""))))
        upgraded.setdefault("truncated", upgraded.get("raw_char_count", 0) > MAX_OUTPUT)
        return upgraded

    # Legacy v1 cache shape: {success, output, error, row_count, truncated}
    output = str(result.get("output", ""))
    data = _parse_json_safe(output)
    rows = coerce_row_list(data)
    upgraded = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "success": bool(result.get("success")),
        "error": result.get("error", ""),
        "plugin": "",
        "row_count": len(rows) if rows is not None else int(result.get("row_count", 0) or 0),
        "raw_char_count": len(output),
        "stderr_preview": "",
        "truncated": bool(result.get("truncated", False)) or len(output) > MAX_OUTPUT,
        "cache_status": "hit_legacy",
        "data": data,
        "rows": rows,
    }
    if data is None:
        upgraded["text_preview"] = output[:MAX_OUTPUT]
    return upgraded


async def run_volatility(
    cmd_args: list[str],
    *,
    use_json: bool = True,
    use_cache: bool = True,
    timeout: int | None = None,
) -> dict:
    """Run Volatility3 and return one normalized result dictionary."""
    plugin_args = list(map(str, cmd_args))
    cache_key = make_cache_key(plugin_args, use_json=use_json)

    if use_cache:
        cached = read_cache(cache_key)
        if cached is not None:
            try:
                return _upgrade_cached_result(json.loads(cached))
            except json.JSONDecodeError as err:
                logger.warning("Ignoring corrupt cache entry %s: %s", cache_key, err)

    dump_path = find_dump_argument(plugin_args)
    if dump_path is not None:
        preflight_error = dump_preflight_error(dump_path)
        if preflight_error:
            return {
                "schema_version": CACHE_SCHEMA_VERSION,
                "success": False,
                "output": "",
                "error": preflight_error,
                "row_count": 0,
                "raw_char_count": 0,
                "truncated": False,
                "cache_status": "preflight_error",
                "data": None,
                "rows": None,
            }

    full_cmd_args = _volatility_global_args(use_json=use_json) + plugin_args
    full_cmd = [VOL_CMD] + full_cmd_args
    logger.info("Running: %s", " ".join(full_cmd))

    plugin_name = detect_plugin_name(plugin_args)
    timeout_seconds = timeout if timeout is not None else get_plugin_timeout(plugin_name)

    process = None
    try:
        # Volatility builds and updates framework/symbol caches while plugins
        # run. Concurrent first-run plugins against the same fresh dump can
        # race that cache and surface transient InvalidAddressException errors.
        # The MCP server can still serve multiple users, but it runs one
        # Volatility subprocess at a time for deterministic forensic output.
        async with VOLATILITY_SUBPROCESS_LOCK:
            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
    except asyncio.TimeoutError:
        if process is not None and process.returncode is None:
            try:
                process.kill()
                await process.communicate()
            except ProcessLookupError:
                pass
            except Exception as cleanup_error:
                logger.warning("Could not clean up timed out process: %s", cleanup_error)
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "success": False,
            "output": "",
            "error": f"Command timed out after {timeout_seconds}s",
            "row_count": 0,
            "raw_char_count": 0,
            "truncated": False,
            "cache_status": "timeout",
            "data": None,
            "rows": None,
        }
    except Exception as err:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "success": False,
            "output": "",
            "error": str(err),
            "row_count": 0,
            "raw_char_count": 0,
            "truncated": False,
            "cache_status": "error",
            "data": None,
            "rows": None,
        }

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace").strip()

    if process.returncode != 0:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "success": False,
            "output": stdout_text[:MAX_OUTPUT],
            "error": stderr_text or f"Exit code {process.returncode}",
            "row_count": 0,
            "raw_char_count": len(stdout_text),
            "truncated": len(stdout_text) > MAX_OUTPUT,
            "cache_status": "volatility_error",
            "data": None,
            "rows": None,
        }

    result = _normalise_success_result(
        cmd_args=plugin_args,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        use_json=use_json,
        cache_status="miss_ran_plugin",
    )

    if use_cache:
        write_cache(
            cache_key,
            json.dumps(_cacheable_result(result), ensure_ascii=False, separators=(",", ":"), default=str),
        )
    return result


def read_cached_volatility_result(plugin_args, *, use_json: bool = True) -> dict | None:
    """Read a normalized cached result without running Volatility."""
    cached = read_cache(make_cache_key(list(map(str, plugin_args)), use_json=use_json))
    if cached is None:
        return None
    try:
        return _upgrade_cached_result(json.loads(cached))
    except json.JSONDecodeError as err:
        logger.warning("Ignoring corrupt cached Volatility result: %s", err)
        return None


async def query_rows_from_cache(
    plugin_args,
    filter_field=None,
    filter_value=None,
    filter_field_2=None,
    filter_value_2=None,
    filter_field_3=None,
    filter_value_3=None,
    max_rows=50,
    run_if_missing: bool = False,
):
    """Return filtered rows from cache, optionally running the plugin once."""
    result = read_cached_volatility_result(plugin_args)
    cache_status = "hit"
    if result is None and run_if_missing:
        cache_status = "miss_ran_plugin"
        result = await run_volatility(list(plugin_args))
    elif result is None:
        return {
            "success": False,
            "error": (
                "No successful cached result exists for this plugin and dump. "
                "Run the original plugin once, or call query_plugin_rows with "
                "run_if_missing=true."
            ),
            "total_rows": 0,
            "matched_rows": 0,
            "returned_rows": 0,
            "rows": [],
            "cache_status": "miss",
        }

    if not result.get("success"):
        return {
            "success": False,
            "error": result.get("error", "Unknown plugin error"),
            "total_rows": 0,
            "matched_rows": 0,
            "returned_rows": 0,
            "rows": [],
            "cache_status": result.get("cache_status", cache_status),
        }

    rows = result.get("rows") or coerce_row_list(result.get("data"))
    if rows is None and result.get("output"):
        rows = coerce_row_list(_parse_json_safe(result.get("output")))
    if rows is None:
        return {
            "success": False,
            "error": "Plugin output JSON did not contain filterable rows.",
            "total_rows": 0,
            "matched_rows": 0,
            "returned_rows": 0,
            "rows": [],
            "cache_status": result.get("cache_status", cache_status),
        }

    matched, applied_filters = apply_row_filters(
        rows,
        (
            (filter_field, filter_value),
            (filter_field_2, filter_value_2),
            (filter_field_3, filter_value_3),
        ),
    )
    capped = matched[: max(1, int(max_rows))]
    return {
        "success": True,
        "total_rows": len(rows),
        "matched_rows": len(matched),
        "returned_rows": len(capped),
        "filter_field": filter_field,
        "filter_value": filter_value,
        "applied_filters": applied_filters,
        "cache_status": result.get("cache_status", cache_status),
        "rows": _compact_preview_rows(capped),
    }


def summarise_output(raw: str, max_chars: int = 8000) -> str:
    """Shrink raw Volatility output into valid JSON or compact text."""
    if len(raw) <= max_chars:
        return raw

    data = _parse_json_safe(raw)
    if data is None:
        lines = raw.splitlines()
        head = "\n".join(lines[:25])
        tail = "\n".join(lines[-10:])
        return (
            f"{head}\n\n"
            f"... [{len(lines)} total lines; showing first 25 and last 10] ...\n\n"
            f"{tail}"
        )

    rows = coerce_row_list(data)
    if rows is not None:
        return summarise_json_rows(rows, max_chars)

    rendered = json.dumps(data, indent=2, default=str)
    if len(rendered) <= max_chars:
        return rendered
    return summarise_json_object(data, max_chars)


def compact_result_for_llm(result: dict, max_chars: int) -> tuple[Any, bool]:
    """Return a stable, compact object suitable for a local LLM tool result."""
    rows = result.get("rows") or coerce_row_list(result.get("data"))
    if rows is None and result.get("output"):
        rows = coerce_row_list(_parse_json_safe(result.get("output")))

    if rows is not None:
        compact_rows = _compact_preview_rows(rows)
        rendered_rows = json.dumps(compact_rows, ensure_ascii=False, default=str)
        if len(rows) <= MAX_ROWS_FULL and len(rendered_rows) <= max_chars:
            return compact_rows, False
        preview = summarise_json_rows(rows, max_chars)
        return _parse_json_safe(preview) or preview, True

    data = result.get("data")
    if data is not None:
        rendered = json.dumps(data, ensure_ascii=False, default=str)
        if len(rendered) <= max_chars:
            return data, False
        preview = summarise_json_object(data, max_chars)
        return _parse_json_safe(preview) or preview, True

    text = str(result.get("text_preview") or result.get("output") or "")
    if len(text) <= max_chars:
        return text, False
    return summarise_output(text, max_chars), True


def summarise_json_rows(rows: list[Any], max_chars: int) -> str:
    """Build a JSON preview for a large row set."""
    total = len(rows)
    stats = extract_row_stats(rows)
    sample = _compact_preview_rows(rows[: min(MAX_ROWS_FULL, total)])
    result = {
        "total_rows": total,
        "showing_first": len(sample),
        "statistics": stats,
        "sample_data": sample,
        "next_action_hint": (
            "Statistics include top_names, top_paths, and other distributions you "
            "can use to identify outliers yourself. If you need rows not in "
            "sample_data, call query_plugin_rows with filter_field and filter_value. "
            "Do not re-run the original plugin just to see more rows."
        ),
    }

    rendered = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    while len(rendered) > max_chars and len(sample) > 5:
        sample = sample[: max(5, len(sample) // 2)]
        result["showing_first"] = len(sample)
        result["sample_data"] = sample
        rendered = json.dumps(result, indent=2, ensure_ascii=False, default=str)

    if len(rendered) <= max_chars:
        return rendered

    # Stats can still be big when there are many columns. Trim the least useful
    # pieces before giving up on sample rows.
    slim_stats = dict(stats)
    for key in ("columns", "sample_pids"):
        if isinstance(slim_stats.get(key), list):
            slim_stats[key] = slim_stats[key][:20]
    for key in ("psxview_disagreement_rows",):
        if isinstance(slim_stats.get(key), list):
            slim_stats[key] = slim_stats[key][:8]

    return json.dumps(
        {
            "total_rows": total,
            "statistics": slim_stats,
            "next_action_hint": result["next_action_hint"],
            "note": "Sample rows omitted because they did not fit the response budget.",
        },
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def summarise_json_object(data: Any, max_chars: int) -> str:
    """Build a small, valid JSON preview for large objects."""
    if isinstance(data, dict):
        preview = _compact_preview_rows([data])[0]
        result = {
            "note": "JSON object truncated for preview.",
            "keys": list(data.keys())[:20],
            "preview": preview,
        }
    else:
        result = {
            "note": "JSON value truncated for preview.",
            "preview": str(data)[:200] + "... [truncated]",
        }

    rendered = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if len(rendered) <= max_chars:
        return rendered

    if isinstance(data, dict):
        return json.dumps(
            {"note": "JSON object truncated for preview.", "keys": list(data.keys())[:20]},
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    return json.dumps({"note": "JSON value truncated for preview."}, indent=2)


def _compact_preview_rows(rows: list[Any], max_value_chars: int = 1000) -> list[Any]:
    """Clip long values in sampled JSON rows so previews stay compact."""
    compact_rows: list[Any] = []
    for row in rows:
        if not isinstance(row, dict):
            compact_rows.append(row)
            continue

        compact_row: dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, str) and len(value) > max_value_chars:
                compact_row[key] = value[:max_value_chars] + "... [truncated]"
            elif isinstance(value, (list, dict, tuple)):
                nested = json.dumps(value, ensure_ascii=False, default=str)
                if len(nested) > max_value_chars:
                    compact_row[key] = nested[:max_value_chars] + "... [truncated]"
                else:
                    compact_row[key] = value
            else:
                compact_row[key] = value
        compact_rows.append(compact_row)
    return compact_rows


def _top_counts(values, limit: int = 10) -> dict:
    counts: dict[str, int] = {}
    for value in values:
        if value in (None, ""):
            continue
        key = _stringify_cell(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit])


def _find_column(rows: list[dict], candidates: tuple[str, ...]) -> str | None:
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        for candidate in candidates:
            actual = resolve_row_field(row, candidate)
            if actual:
                return actual
    return None


def _first_existing_column(row: dict, candidates: tuple[str, ...]) -> str | None:
    # Backwards-compatible helper used by older tests/extensions.
    return _find_column([row], candidates)


def _sort_pid_values(values: Iterable[Any]) -> list[Any]:
    def sort_key(value: Any):
        parsed = parse_intish(value)
        if parsed is not None:
            return (0, parsed)
        return (1, str(value))

    return sorted({value for value in values if value not in (None, "")}, key=sort_key)


def build_suggested_filters(stats: dict) -> list[dict]:
    """Kept for backward compatibility. Returns no suggestions.

    The MCP server no longer pre-judges which rows are suspicious. Callers
    should look at top_names, top_paths, command_indicator_rows, and
    psxview_disagreement_rows in `statistics` and form their own conclusions.
    """
    return []


def extract_row_stats(data: list[dict]) -> dict:
    """Extract small, high-signal statistics from Volatility rows."""
    if not data:
        return {"row_count": 0}
    if not isinstance(data[0], dict):
        return {"row_count": len(data)}

    row_dicts = [row for row in data if isinstance(row, dict)]
    stats: dict[str, Any] = {"row_count": len(data)}

    columns: list[str] = []
    for row in row_dicts[:50]:
        for key in row.keys():
            if key not in columns:
                columns.append(key)
    stats["columns"] = columns[:60]

    pid_column = _find_column(row_dicts, ("PID", "Pid", "ProcessId", "Process ID"))
    ppid_column = _find_column(row_dicts, ("PPID", "ParentPid", "Parent PID"))
    name_column = _find_column(
        row_dicts,
        ("ImageFileName", "ImageName", "Name", "Process", "ProcessName", "Image"),
    )
    path_column = _find_column(
        row_dicts,
        ("Path", "File", "FullPath", "ImagePath", "OriginalFileName", "Binary", "BinaryPath"),
    )

    if pid_column:
        pids = [row.get(pid_column) for row in row_dicts]
        unique_pids = _sort_pid_values(pids)
        stats["unique_pids"] = len(unique_pids)
        stats["sample_pids"] = unique_pids[:25]

    if ppid_column:
        stats["top_ppids"] = _top_counts((row.get(ppid_column) for row in row_dicts), 10)

    if name_column:
        stats["top_names"] = _top_counts((row.get(name_column, "") for row in row_dicts), 15)

    if path_column:
        stats["top_paths"] = _top_counts((row.get(path_column, "") for row in row_dicts), 10)

    foreign_addr_column = _find_column(row_dicts, ("ForeignAddr", "RemoteAddress", "ForeignAddress"))
    foreign_port_column = _find_column(row_dicts, ("ForeignPort", "RemotePort"))
    local_port_column = _find_column(row_dicts, ("LocalPort", "SourcePort"))
    state_column = _find_column(row_dicts, ("State", "Status"))

    if foreign_addr_column or local_port_column or foreign_port_column:
        local_ports = {}
        foreign_ports = {}
        foreign_addrs = {}
        states = {}
        for row in row_dicts:
            lp = row.get(local_port_column) if local_port_column else None
            fp = row.get(foreign_port_column) if foreign_port_column else None
            fa = row.get(foreign_addr_column) if foreign_addr_column else None
            st = row.get(state_column) if state_column else None
            if lp not in (None, ""):
                local_ports[lp] = local_ports.get(lp, 0) + 1
            if fp not in (None, ""):
                foreign_ports[fp] = foreign_ports.get(fp, 0) + 1
            if fa not in (None, ""):
                foreign_addrs[fa] = foreign_addrs.get(fa, 0) + 1
            if st not in (None, ""):
                states[st] = states.get(st, 0) + 1
        if local_ports:
            stats["top_local_ports"] = dict(sorted(local_ports.items(), key=lambda x: -x[1])[:10])
        if foreign_ports:
            stats["top_foreign_ports"] = dict(sorted(foreign_ports.items(), key=lambda x: -x[1])[:10])
        if foreign_addrs:
            stats["top_foreign_addrs"] = dict(sorted(foreign_addrs.items(), key=lambda x: -x[1])[:10])
        if states:
            stats["state_counts"] = states


    visibility_columns = [
        col
        for col in columns
        if _normalise_column_name(col)
        in {
            "pslist",
            "psscan",
            "thrdproc",
            "pspcid",
            "csrss",
            "session",
            "deskthrd",
            "exittime",
            "handles",
            "threads",
        }
    ]
    if visibility_columns:
        disagreement_rows = []
        for row in row_dicts:
            false_views = []
            for col in visibility_columns:
                value = row.get(col)
                if value is False or str(value).strip().lower() in {"false", "0", "no"}:
                    false_views.append(col)
            if false_views:
                disagreement_rows.append(
                    {
                        "PID": row.get(pid_column) if pid_column else row.get("PID"),
                        "name": row.get(name_column) if name_column else row.get("ImageFileName"),
                        "missing_or_false_views": false_views,
                    }
                )
        if disagreement_rows:
            stats["psxview_disagreement_count"] = len(disagreement_rows)
            stats["psxview_disagreement_rows"] = disagreement_rows[:15]

    return stats
