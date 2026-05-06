import asyncio

from volatility_mcp_server.tools import runner
from volatility_mcp_server.tools.runner import (
    _cacheable_result,
    _upgrade_cached_result,
    _volatility_global_args,
    compact_result_for_llm,
    query_rows_from_cache,
)


def test_cache_entry_drops_raw_output_and_keeps_single_row_copy():
    rows = [{"PID": 740, "ImageFileName": "evil.exe"}]
    result = {
        "schema_version": runner.CACHE_SCHEMA_VERSION,
        "success": True,
        "error": "",
        "plugin": "windows.pslist.PsList",
        "row_count": 1,
        "raw_char_count": 999,
        "truncated": False,
        "cache_status": "miss_ran_plugin",
        "data": rows,
        "rows": rows,
        "output": "large raw json that should not be cached",
    }

    cache_entry = _cacheable_result(result)

    assert "output" not in cache_entry
    assert cache_entry["rows"] == rows
    assert cache_entry["data"] is None


def test_upgrade_cached_result_restores_rows_from_new_cache_shape():
    cached = {
        "schema_version": runner.CACHE_SCHEMA_VERSION,
        "success": True,
        "data": None,
        "rows": [{"PID": "740"}],
        "row_count": 1,
    }

    upgraded = _upgrade_cached_result(cached)

    assert upgraded["success"] is True
    assert upgraded["cache_status"] == "hit"
    assert upgraded["rows"] == [{"PID": "740"}]


def test_volatility_global_args_use_quiet_json_and_framework_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "VOL_FRAMEWORK_CACHE_DIR", tmp_path)

    args = _volatility_global_args(use_json=True)

    assert args[:3] == ["-q", "-r", "json"]
    assert "--cache-path" in args
    assert str(tmp_path) in args


def test_compact_result_for_llm_summarises_large_row_sets():
    rows = [{"PID": i, "ImageFileName": f"proc{i}.exe"} for i in range(120)]
    data, truncated = compact_result_for_llm(
        {"success": True, "rows": rows, "row_count": len(rows)},
        max_chars=5000,
    )

    assert truncated is True
    assert data["total_rows"] == 120
    assert "statistics" in data
    assert "next_action_hint" in data


def test_query_rows_runs_plugin_once_when_cache_missing(monkeypatch):
    rows = [
        {"PID": 4, "ImageFileName": "System"},
        {"PID": "740.0", "ImageFileName": "evil.exe"},
    ]

    monkeypatch.setattr(runner, "read_cached_volatility_result", lambda args: None)

    async def fake_run_volatility(args):
        return {
            "success": True,
            "rows": rows,
            "data": None,
            "row_count": len(rows),
            "cache_status": "miss_ran_plugin",
        }

    monkeypatch.setattr(runner, "run_volatility", fake_run_volatility)

    result = asyncio.run(
        query_rows_from_cache(
            ["-f", "/tmp/sample.raw", "windows.pslist.PsList"],
            filter_field="PID",
            filter_value="740",
            max_rows=10,
            run_if_missing=True,
        )
    )

    assert result["success"] is True
    assert result["matched_rows"] == 1
    assert result["rows"][0]["ImageFileName"] == "evil.exe"
