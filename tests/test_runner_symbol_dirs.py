from volatility_mcp_server.tools import runner


def test_volatility_global_args_passes_existing_symbol_dirs(monkeypatch, tmp_path):
    symbols_dir = tmp_path / "symbols"
    symbols_dir.mkdir()

    monkeypatch.setattr(runner, "VOL_SYMBOL_DIRS", str(symbols_dir))
    monkeypatch.setattr(runner, "VOL_FRAMEWORK_CACHE_DIR", tmp_path / "cache")

    args = runner._volatility_global_args(use_json=True)

    assert "--symbol-dirs" in args
    assert args[args.index("--symbol-dirs") + 1] == str(symbols_dir)


def test_volatility_global_args_ignores_missing_symbol_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "VOL_SYMBOL_DIRS", str(tmp_path / "missing"))
    monkeypatch.setattr(runner, "VOL_FRAMEWORK_CACHE_DIR", None)

    args = runner._volatility_global_args(use_json=True)

    assert "--symbol-dirs" not in args
