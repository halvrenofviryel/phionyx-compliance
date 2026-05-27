"""phionyx-compliance — CLI entry point.

W1.1 (previous): argparse skeleton.
W1.2 (this commit): list-templates + describe wired to disk; generate
    --sample mode renders a real markdown draft.
W1.3 (next): real chain → inputs mapping for non-sample generate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .templates import list_templates, load_template
from .renderer import render, sample_inputs
from .chain_view import ChainView
from .mapping import resolve_inputs


CANONICAL_DISCLAIMER = (
    "Reports produced by this package are evidence-oriented mappings, "
    "not legal compliance guarantees. A lawyer or auditor must review "
    "before any use that implies legal posture. Phionyx does not "
    "certify AI systems; it produces the evidence chains that "
    "certifications rely on."
)


def _load_operator_inputs(path: Path | None) -> dict:
    """Load operator-supplied inputs from a YAML or JSON file."""
    if not path:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"operator inputs file not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        import yaml
        return yaml.safe_load(text) or {}
    return json.loads(text)


def cmd_generate(args: argparse.Namespace) -> int:
    """Generate a compliance evidence report draft.

    W1.2 supports --sample mode (synthetic inputs).
    W1.3 (this version) supports a real --trace + chain walk.
    """
    try:
        template = load_template(args.template)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.sample:
        inputs = sample_inputs(args.template)
        mode_label = "sample render (synthetic inputs)"
    else:
        # Real chain walk
        try:
            chain = ChainView.from_disk(args.trace, chain_root=args.chain_root)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4
        except ImportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 5
        if args.strict and not chain.verify_result.valid:
            print(
                f"error: chain validation failed ({chain.verify_result.reason!r} "
                f"at envelope {chain.verify_result.broken_at}); refusing to render "
                f"in --strict mode.",
                file=sys.stderr,
            )
            return 6

        operator_inputs = _load_operator_inputs(args.operator_inputs)
        inputs = resolve_inputs(template, chain, operator_inputs)
        mode_label = f"real chain render ({chain.envelope_count} envelopes, valid={chain.verify_result.valid})"

    markdown = render(template, inputs)

    if args.out:
        out_path = Path(args.out)
    elif args.sample:
        out_path = Path(f"sample-{args.template}-report.md")
    else:
        out_path = Path(f"{args.trace}-{args.template}-report.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")

    print(f"phionyx-compliance {__version__} — {mode_label}")
    print(f"  template: {args.template} (version {template.version})")
    if not args.sample:
        print(f"  trace:    {args.trace}")
    print(f"  out:      {out_path}")
    print(f"  bytes:    {out_path.stat().st_size}")
    print()
    print(CANONICAL_DISCLAIMER)
    return 0


def cmd_list_templates(args: argparse.Namespace) -> int:
    names = list_templates()
    if not names:
        print("(no templates available — package may be incomplete)")
        return 1

    print("Available templates:")
    for name in names:
        try:
            t = load_template(name)
            print(f"  {name:30s}  v{t.version}  {t.framework}")
        except Exception as exc:
            print(f"  {name:30s}  (load failed: {exc!r})")
    return 0


def cmd_describe(args: argparse.Namespace) -> int:
    try:
        t = load_template(args.template_name)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    print(f"Template: {t.name}")
    print(f"Version:  {t.version}")
    print(f"Framework: {t.framework}")
    print()
    print("Required input fields (per schema.json):")
    for k in t.required_fields:
        print(f"  - {k}")
    print()
    print(f"Operator-supplied: {len(t.operator_supplied_fields)} field(s)")
    for k in t.operator_supplied_fields:
        print(f"  - {k}")
    print(f"Chain-derived:    {len(t.chain_derived_fields)} field(s)")
    print()
    print("Disclaimer addendum (framework-specific):")
    print(t.disclaimer_addendum.strip() or "  (none)")
    return 0


def cmd_render_sample(args: argparse.Namespace) -> int:
    """Convenience: render the sample for a given template to stdout.
    Useful for piping into pandoc or quick visual inspection.
    """
    try:
        template = load_template(args.template_name)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    inputs = sample_inputs(args.template_name)
    markdown = render(template, inputs)
    if args.format == "json":
        out = {
            "template": template.name,
            "version": template.version,
            "framework": template.framework,
            "inputs": {k: v for k, v in inputs.items() if not isinstance(v, (dict, list))},
            "rendered_markdown": markdown,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print(markdown)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phionyx-compliance",
        description="Evidence-grade compliance report drafts from Phionyx audit chains. NOT certification.",
    )
    parser.add_argument("--version", action="version", version=f"phionyx-compliance {__version__}")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_gen = subparsers.add_parser("generate", help="Generate a draft report")
    p_gen.add_argument("--trace", required=False, default="trace-sample", help="Trace ID to render against (required without --sample)")
    p_gen.add_argument("--template", required=True, help="Template name, e.g. eu-ai-act-article-13")
    p_gen.add_argument("--chain-root", type=Path, default=Path.home() / ".phionyx" / "mcp_audit",
                       help="Envelope chain root (default ~/.phionyx/mcp_audit/)")
    p_gen.add_argument("--out", type=Path, default=None, help="Output markdown path")
    p_gen.add_argument("--format", choices=["markdown", "json"], default="markdown",
                       help="Output format (default markdown)")
    p_gen.add_argument("--strict", action="store_true", help="Refuse to render if chain_valid=False")
    p_gen.add_argument("--sample", action="store_true",
                       help="Render with synthetic inputs (no chain walk needed)")
    p_gen.add_argument("--operator-inputs", type=Path, default=None,
                       help="Path to YAML/JSON file with operator-supplied input overrides")
    p_gen.set_defaults(func=cmd_generate)

    p_list = subparsers.add_parser("list-templates", help="List available templates")
    p_list.set_defaults(func=cmd_list_templates)

    p_desc = subparsers.add_parser("describe", help="Describe a template's inputs")
    p_desc.add_argument("template_name")
    p_desc.set_defaults(func=cmd_describe)

    p_render = subparsers.add_parser(
        "render-sample",
        help="Render the sample of a template to stdout (or JSON via --format)",
    )
    p_render.add_argument("template_name")
    p_render.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_render.set_defaults(func=cmd_render_sample)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
