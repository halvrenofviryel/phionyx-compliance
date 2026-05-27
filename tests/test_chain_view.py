"""W1.3 — tests for ChainView (envelope chain wrapper)."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_verify_result_dataclass():
    from phionyx_compliance import VerifyResult

    v = VerifyResult(valid=True)
    assert v.valid is True
    assert v.broken_at is None
    assert v.reason is None


def test_chain_view_from_envelopes_for_tests():
    """from_envelopes builds a ChainView without touching the filesystem."""
    from phionyx_compliance import ChainView

    envelopes = [
        {"subject": {"turn_index": 0, "decision": "pass"}, "integrity": {"current": "h0", "previous": "GENESIS", "key_id": "k1"}},
        {"subject": {"turn_index": 1, "decision": "reject"}, "integrity": {"current": "h1", "previous": "h0", "key_id": "k1"}},
    ]
    chain = ChainView.from_envelopes("trace-fake", envelopes)
    assert chain.trace_id == "trace-fake"
    assert chain.envelope_count == 2
    assert chain.verify_result.valid is True


def test_find_traces_empty_dir():
    from phionyx_compliance import find_traces

    with tempfile.TemporaryDirectory() as td:
        assert find_traces(Path(td)) == []


def test_find_traces_one_trace():
    from phionyx_compliance import find_traces

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        tdir = root / "trace-abc12345"
        tdir.mkdir()
        (tdir / "chain.jsonl").write_text("")
        assert find_traces(root) == ["trace-abc12345"]


def test_chain_view_from_disk_missing_trace():
    """from_disk raises FileNotFoundError when the trace dir is absent."""
    from phionyx_compliance import ChainView

    with tempfile.TemporaryDirectory() as td:
        try:
            ChainView.from_disk("trace-does-not-exist", chain_root=Path(td))
            raise AssertionError("expected FileNotFoundError")
        except FileNotFoundError as exc:
            assert "trace-does-not-exist" in str(exc)
