"""Scaffold-level tests for phionyx-compliance (W1.1).

These prove the package imports, the CLI builds, and the canonical
disclaimer is wired. Real-behaviour tests land at W1.2+.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is on path for tests-in-monorepo style
sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent / "src")
)


def test_package_imports():
    import phionyx_compliance
    assert phionyx_compliance.__version__ == "0.1.0a1.dev0"


def test_cli_builds():
    from phionyx_compliance.cli import build_parser

    parser = build_parser()
    # Help text rendering must not raise
    text = parser.format_help()
    assert "phionyx-compliance" in text
    # The description text is truncated in some argparse output widths,
    # but the description property of the parser carries the full claim.
    assert "NOT certification" in (parser.description or "")


def test_canonical_disclaimer_present():
    from phionyx_compliance.cli import CANONICAL_DISCLAIMER

    # The disclaimer must say what it must say
    assert "evidence-oriented" in CANONICAL_DISCLAIMER
    assert "not legal compliance" in CANONICAL_DISCLAIMER
    assert "lawyer or auditor must review" in CANONICAL_DISCLAIMER
    assert "does not certify" in CANONICAL_DISCLAIMER


def test_subcommand_surface():
    from phionyx_compliance.cli import build_parser

    parser = build_parser()
    # All three documented subcommands parse
    for cmd, extra in [
        ("generate", ["--trace", "T", "--template", "X"]),
        ("list-templates", []),
        ("describe", ["a-template"]),
    ]:
        ns = parser.parse_args([cmd] + extra)
        assert ns.cmd == cmd


def test_generate_chain_not_found_returns_4():
    """W1.3 — generate against a non-existent trace returns 4 (chain not found),
    not EX_NOT_IMPL (which was the W1.1 behaviour). --sample bypass still works.
    """
    from phionyx_compliance.cli import main

    rc = main(["generate", "--trace", "trace-fake-does-not-exist",
               "--template", "eu-ai-act-article-13"])
    assert rc == 4  # FileNotFoundError exit code from ChainView.from_disk


def test_list_templates_succeeds():
    from phionyx_compliance.cli import main

    rc = main(["list-templates"])
    assert rc == 0
