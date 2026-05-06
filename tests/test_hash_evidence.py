import hashlib

from agent.agent import hash_evidence


def test_hash_evidence_hashes_exact_indicator_strings():
    result = hash_evidence.invoke({"indicators": ["evil.exe", "evil.exe", "10.0.0.5"]})

    assert result["hash_scope"] == "exact_indicator_string"
    assert result["count"] == 2
    assert result["items"][0]["value"] == "evil.exe"
    assert result["items"][0]["sha256"] == hashlib.sha256(b"evil.exe").hexdigest()
    assert "not file-content hashes" in result["warning"]
