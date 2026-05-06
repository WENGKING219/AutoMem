import json

from volatility_mcp_server.tools.runner import (
    coerce_row_list,
    extract_row_stats,
    filter_rows,
    summarise_output,
)


def test_filter_rows_matches_pid_case_insensitively_and_intishly():
    rows = [
        {"Pid": 740, "ImageFileName": "evil.exe"},
        {"Pid": 4, "ImageFileName": "System"},
    ]

    assert filter_rows(rows, "PID", "740.0") == [rows[0]]


def test_coerce_row_list_accepts_common_wrapped_json_shapes():
    rows = [{"PID": 1}, {"PID": 2}]

    assert coerce_row_list(rows) == rows
    assert coerce_row_list({"data": rows}) == rows
    assert coerce_row_list({"rows": rows}) == rows


def test_summarise_output_handles_wrapped_rows_as_rows():
    rows = [{"PID": i, "ImageFileName": f"p{i}.exe"} for i in range(20)]
    summary = summarise_output(json.dumps({"data": rows}), max_chars=800)

    parsed = json.loads(summary)
    assert parsed["total_rows"] == 20
    assert "statistics" in parsed


def test_extract_row_stats_flags_psxview_disagreements():
    stats = extract_row_stats([
        {"PID": 740, "ImageFileName": "hidden.exe", "pslist": False, "psscan": True},
        {"PID": 4, "ImageFileName": "System", "pslist": True, "psscan": True},
    ])

    assert stats["psxview_disagreement_count"] == 1
    assert stats["psxview_disagreement_rows"][0]["PID"] == 740
