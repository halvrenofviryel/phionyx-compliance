"""Session-level producer-contract gate.

ACCEPTANCE 4: a wrong dependency version must fail LOUDLY at install/test
— it must not silently produce a wrong answer.

phionyx-compliance verifies nothing itself. Every verification fact in a
report is produced by phionyx-mcp-server. Below 0.2.1 that producer
returns a HASH-ONLY verdict `{valid, checked, broken_at, reason}` with no
per-dimension fields, and its `valid=True` carries no signature
information at all. The failure mode is silent: the suite would run, most
tests would pass, and reports would carry a signature-level posture for a
chain whose signatures were never examined.

So the check runs before collection and aborts the whole session with the
measured versions in the message, rather than letting individual tests
fail with an incidental TypeError/KeyError that reads like a test bug.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def pytest_configure(config: pytest.Config) -> None:
    from phionyx_compliance.chain_view import (
        REQUIRED_MCP_SERVER_VERSION,
        IncompatibleProducerError,
        require_producer,
    )

    try:
        provenance = require_producer()
    except IncompatibleProducerError as exc:
        raise pytest.UsageError(
            "PRODUCER CONTRACT NOT MET — refusing to run the suite.\n\n"
            f"{exc}\n\n"
            "This is not an optional pin. A version below "
            f"{REQUIRED_MCP_SERVER_VERSION} makes this package report "
            "signature-level assurance for chains whose signatures were "
            "never checked. Install the declared floor:\n"
            "    pip install -e '.[dev]'\n"
        ) from exc

    config.stash  # noqa: B018 - touch to keep the object alive across plugins
    config.addinivalue_line(
        "markers", "producer_contract: depends on the phionyx-mcp-server floor"
    )
    print(f"\nproducer under test: {provenance}", file=sys.stderr)
