"""Template loader for phionyx-compliance.

A template is a self-contained directory under
`phionyx_compliance/templates/<name>/` containing:

  - template.md     markdown skeleton with {{placeholders}}
  - schema.json     JSON Schema (Draft 2020-12) for inputs
  - mapping.yaml    RGE envelope field → schema input mapping (W1.3 uses this)
  - disclaimer.md   framework-specific addendum to the canonical disclaimer
  - README.md       human-readable framework notes

Template names use kebab-case at the API surface (e.g. `eu-ai-act-article-13`)
and snake_case on disk (e.g. `eu_ai_act_article_13/`) so they're valid
Python module names if we ever want to import them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml


_TEMPLATES_ROOT = Path(__file__).resolve().parent / "templates"


def _kebab_to_snake(name: str) -> str:
    return name.replace("-", "_")


def _snake_to_kebab(name: str) -> str:
    return name.replace("_", "-")


@dataclass
class Template:
    """One framework template loaded from disk."""

    name: str                  # kebab-case API name, e.g. "eu-ai-act-article-13"
    root: Path                  # filesystem directory
    template_md: str             # raw markdown with {{placeholders}}
    schema: dict                 # parsed schema.json
    mapping: dict                # parsed mapping.yaml
    disclaimer_addendum: str     # contents of disclaimer.md
    readme: str = field(default="")

    @property
    def framework(self) -> str:
        return str(self.mapping.get("framework", "<unspecified>"))

    @property
    def version(self) -> str:
        return str(self.mapping.get("template_version", "0.0.0"))

    @property
    def required_fields(self) -> list[str]:
        req = self.schema.get("required") or []
        return list(req)

    @property
    def operator_supplied_fields(self) -> list[str]:
        return [
            field_name
            for field_name, rule in (self.mapping.get("inputs") or {}).items()
            if rule.get("category") == "operator_supplied"
        ]

    @property
    def chain_derived_fields(self) -> list[str]:
        return [
            field_name
            for field_name, rule in (self.mapping.get("inputs") or {}).items()
            if rule.get("category") == "chain_derived"
        ]


def list_templates(root: Path | None = None) -> list[str]:
    """Return kebab-case names of templates physically present on disk."""
    base = root or _TEMPLATES_ROOT
    if not base.is_dir():
        return []
    names: list[str] = []
    for child in sorted(base.iterdir()):
        if not child.is_dir():
            continue
        if (child / "template.md").is_file():
            names.append(_snake_to_kebab(child.name))
    return names


def load_template(name: str, root: Path | None = None) -> Template:
    """Load a template directory by its kebab-case name."""
    base = root or _TEMPLATES_ROOT
    snake = _kebab_to_snake(name)
    tdir = base / snake
    if not tdir.is_dir():
        available = ", ".join(list_templates(base)) or "(none)"
        raise FileNotFoundError(
            f"Template {name!r} not found under {base}. Available: {available}"
        )

    template_md_path = tdir / "template.md"
    schema_path = tdir / "schema.json"
    mapping_path = tdir / "mapping.yaml"
    disclaimer_path = tdir / "disclaimer.md"
    readme_path = tdir / "README.md"

    missing = [p.name for p in (template_md_path, schema_path, mapping_path) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            f"Template {name!r} is incomplete; missing files: {missing}"
        )

    return Template(
        name=name,
        root=tdir,
        template_md=template_md_path.read_text(encoding="utf-8"),
        schema=json.loads(schema_path.read_text(encoding="utf-8")),
        mapping=yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {},
        disclaimer_addendum=disclaimer_path.read_text(encoding="utf-8") if disclaimer_path.exists() else "",
        readme=readme_path.read_text(encoding="utf-8") if readme_path.exists() else "",
    )
