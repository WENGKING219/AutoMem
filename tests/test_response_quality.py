from agent.response_quality import (
    build_tool_result_fallback,
    extract_tool_errors,
    tool_calls_have_hard_errors,
)


def test_extract_tool_errors_from_fastmcp_text_block_repr():
    tool_calls = [
        {
            "type": "result",
            "name": "get_image_info",
            "result": (
                "[{'type': 'text', 'text': "
                "'{\"plugin\":\"windows.info.Info\","
                "\"dump\":\"/data/memory_dumps/cridex.vmem\","
                "\"success\":false,"
                "\"error\":\"VMware VMEM metadata is missing.\"}'}]"
            ),
        }
    ]

    errors = extract_tool_errors(tool_calls)

    assert tool_calls_have_hard_errors(tool_calls)
    assert errors == [
        {
            "tool": "get_image_info",
            "plugin": "windows.info.Info",
            "dump": "/data/memory_dumps/cridex.vmem",
            "error": "VMware VMEM metadata is missing.",
        }
    ]


def test_build_tool_result_fallback_is_actionable_for_vmem_metadata():
    tool_calls = [
        {"type": "call", "name": "get_image_info", "args": {"memory_dump": "cridex.vmem"}},
        {
            "type": "result",
            "name": "get_image_info",
            "result": {
                "plugin": "windows.info.Info",
                "dump": "/data/memory_dumps/cridex.vmem",
                "success": False,
                "error": "VMware VMEM metadata is missing.",
            },
        },
    ]

    fallback = build_tool_result_fallback(tool_calls)

    assert "could not complete the analysis" in fallback
    assert "windows.info.Info" in fallback
    assert ".vmss" in fallback
    assert ".vmsn" in fallback
    assert "Confidence: Low" in fallback
