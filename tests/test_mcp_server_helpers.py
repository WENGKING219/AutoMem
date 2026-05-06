import pytest

from volatility_mcp_server.server import parse_max_rows, parse_optional_pid


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 50),
        ("", 50),
        ("25", 25),
        ("25.0", 25),
        ("999", 200),
        ("0", 1),
    ],
)
def test_parse_max_rows_clamps_common_llm_values(value, expected):
    assert parse_max_rows(value) == expected


@pytest.mark.parametrize("value", ["abc", "1.5", True])
def test_optional_pid_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        parse_optional_pid(value)


def test_parse_max_rows_rejects_fractional_values():
    with pytest.raises(ValueError):
        parse_max_rows("10.5")
