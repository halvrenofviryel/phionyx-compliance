"""Chain view — wraps phionyx-mcp-server's FilesystemEnvelopeStore.

W1.3 — provides a ChainView dataclass that exposes the envelope chain
+ verification result + aggregations the mapping resolver needs.

The chain on disk is at $PHIONYX_MCP_AUDIT_ROOT (default ~/.phionyx/mcp_audit/)
in the layout documented at FilesystemEnvelopeStore docstring.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class VerifyResult:
    valid: bool
    broken_at: int | None = None
    reason: str | None = None


@dataclass
class ChainView:
    """View over an envelope chain for the renderer's consumption."""

    trace_id: str
    envelopes: list[dict[str, Any]]
    verify_result: VerifyResult
    revoked_keys_referenced: list[str] = field(default_factory=list)

    @property
    def envelope_count(self) -> int:
        return len(self.envelopes)

    @classmethod
    def from_disk(
        cls,
        trace_id: str,
        chain_root: Path | None = None,
    ) -> "ChainView":
        """Load the chain from FilesystemEnvelopeStore.

        Raises:
            ImportError: if phionyx-mcp-server is not installed.
            FileNotFoundError: if the chain directory for the trace does
                               not exist.
        """
        # Find phionyx-mcp-server (sibling package in the monorepo)
        # Locate it via the same defensive sys.path manipulation the
        # pipeline MCP uses (see phionyx_claude_mcp.py:198).
        repo_root = Path(__file__).resolve().parents[4]
        server_src = repo_root / "tools" / "phionyx_mcp_server" / "src"
        if server_src.is_dir() and str(server_src) not in sys.path:
            sys.path.insert(0, str(server_src))

        try:
            from phionyx_mcp_server.audit_chain import (  # type: ignore[import-not-found]
                FilesystemEnvelopeStore,
                verify_chain,
            )
        except ImportError as exc:
            raise ImportError(
                "phionyx-mcp-server is required to load envelope chains. "
                "Install it (pip install phionyx-mcp-server) or run within "
                "the Phionyx monorepo where it is a sibling package."
            ) from exc

        store = FilesystemEnvelopeStore(root=chain_root) if chain_root else FilesystemEnvelopeStore()
        # Validate directory exists before iter_chain returns empty
        trace_dir = store.root / trace_id.replace("/", "_").replace("..", "__")
        if not trace_dir.exists():
            raise FileNotFoundError(
                f"Envelope chain directory not found for trace {trace_id!r} at {trace_dir}. "
                f"If you have not produced any envelopes for this trace yet, the chain is "
                f"empty — re-run with --sample to render against synthetic inputs instead."
            )

        envelopes = list(store.iter_chain(trace_id))
        verdict = verify_chain(envelopes)

        return cls(
            trace_id=trace_id,
            envelopes=envelopes,
            verify_result=VerifyResult(
                valid=bool(verdict.get("valid", False)),
                broken_at=verdict.get("broken_at"),
                reason=verdict.get("reason"),
            ),
            # Revocation list integration is v0.6.0 boundary work
            # (CRYPTOGRAPHIC_POSTURE_ROADMAP.md). For now: empty.
            revoked_keys_referenced=[],
        )

    @classmethod
    def from_envelopes(
        cls,
        trace_id: str,
        envelopes: list[dict[str, Any]],
    ) -> "ChainView":
        """Build a ChainView from already-loaded envelopes (for tests).

        Skips verify_chain (which requires the server import); callers
        provide VerifyResult separately via the returned object's
        attribute set.
        """
        return cls(
            trace_id=trace_id,
            envelopes=envelopes,
            verify_result=VerifyResult(valid=True, broken_at=None, reason=None),
            revoked_keys_referenced=[],
        )


# Convenience helper for tests / debugging
def find_traces(chain_root: Path | None = None) -> list[str]:
    """List trace IDs that have an envelope chain on disk."""
    if chain_root is None:
        chain_root = Path(
            os.environ.get("PHIONYX_MCP_AUDIT_ROOT", "~/.phionyx/mcp_audit")
        ).expanduser()
    if not chain_root.is_dir():
        return []
    traces: list[str] = []
    for child in sorted(chain_root.iterdir()):
        if child.is_dir() and (child / "chain.jsonl").exists():
            traces.append(child.name)
    return traces
