from pathlib import Path


def test_quick_actions_are_small_and_demo_safe():
    frontend_source = Path("frontend/app.py").read_text(encoding="utf-8")

    for label in [
        "Initial Triage",
        "Hidden Process",
        "Network",
        "Persistence & Execution",
        "Generate Report",
    ]:
        assert f'label="{label}"' in frontend_source or f'label = "{label}"' in frontend_source

    # Hashdump quick action was removed; the prompt should no longer mention it.
    assert "Credential Hashes" not in frontend_source
    assert "run_hashdump" not in frontend_source

    # Amcache replaced hashdump as the registry execution-evidence tool.
    assert "run_amcache" in frontend_source

    combined = frontend_source.lower()
    assert "query_plugin_rows" in combined
    assert "save_report" in combined
    assert "do not skip any" not in combined
    assert "run all" not in combined
    assert "def build_quick_actions" in frontend_source
    assert "is_report=True" in frontend_source


def test_frontend_uses_local_quick_action_builder():
    frontend_source = Path("frontend/app.py").read_text(encoding="utf-8")

    assert "agent.demo_prompts" not in frontend_source
    assert "actions = build_quick_actions(dump_name)" in frontend_source
