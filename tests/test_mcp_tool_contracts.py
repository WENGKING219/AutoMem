import inspect

from volatility_mcp_server import server


def test_run_psxview_accepts_filtered_drilldown_arguments():
    params = inspect.signature(server.run_psxview).parameters

    for name in ("filter_field", "filter_value", "max_rows"):
        assert name in params


def test_mcp_exposes_curated_plugin_set_only():
    assert set(server.AVAILABLE_PLUGIN_NAMES) == {
        "pslist",
        "psscan",
        "pstree",
        "psxview",
        "cmdline",
        "netscan",
        "malfind",
        "dlllist",
        "handles",
        "svcscan",
        "hashdump",
    }
