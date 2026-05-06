from volatility_mcp_server import server


def test_run_server_defaults_to_http(monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(server.mcp, "run", fake_run)
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("MCP_HOST", "127.0.0.1")
    monkeypatch.setenv("MCP_PORT", "9000")
    monkeypatch.setenv("MCP_PATH", "/mcp")

    server.run_server()

    assert calls == [((), {"transport": "http", "host": "127.0.0.1", "port": 9000, "path": "/mcp"})]


def test_run_server_can_use_stdio_for_inspector(monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(server.mcp, "run", fake_run)
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")

    server.run_server()

    assert calls == [((), {"transport": "stdio"})]
