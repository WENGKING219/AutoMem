from volatility_mcp_server.tools.runner import dump_preflight_error


def test_vmem_without_snapshot_metadata_is_left_to_volatility(tmp_path):
    dump = tmp_path / "cridex.vmem"
    dump.write_bytes(b"memory")

    assert dump_preflight_error(dump) is None


def test_vmem_with_snapshot_metadata_passes_preflight(tmp_path):
    dump = tmp_path / "cridex.vmem"
    dump.write_bytes(b"memory")
    (tmp_path / "cridex.vmss").write_bytes(b"snapshot")

    assert dump_preflight_error(dump) is None
