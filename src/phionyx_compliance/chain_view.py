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


# ── Assurance ladder ───────────────────────────────────────────────
# Ordering (weakest → strongest). A consumer may only report the level
# it actually OBTAINED evidence for. Levels above SIGNATURE_VERIFIED
# are declared here so the vocabulary is complete, but this package
# cannot reach them: VERIFIED additionally requires key trust and
# revocation state, TRUSTED additionally requires witness/freshness.
# Neither is implemented here — see `REVOCATION_NOT_IMPLEMENTED`.

INVALID = "INVALID"
NOT_MEASURED = "NOT_MEASURED"
RECORDED = "RECORDED"
HASH_VERIFIED = "HASH_VERIFIED"
SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
VERIFIED = "VERIFIED"
TRUSTED = "TRUSTED"

ASSURANCE_ORDER = [
    INVALID,
    NOT_MEASURED,
    RECORDED,
    HASH_VERIFIED,
    SIGNATURE_VERIFIED,
    VERIFIED,
    TRUSTED,
]
ASSURANCE_RANK = {name: i for i, name in enumerate(ASSURANCE_ORDER)}

#: Revocation checking is NOT implemented in phionyx-compliance. Reports
#: must SAY this rather than omit it or render a bare `0`.
REVOCATION_NOT_IMPLEMENTED = (
    "NOT CHECKED — key revocation is not implemented in phionyx-compliance. "
    "A revoked signing key would not be detected by this report. The operator "
    "must check revocation state out of band before relying on any signature."
)


@dataclass
class VerifyResult:
    """What was actually measured about a chain — and what was not.

    Each dimension is recorded SEPARATELY and is tri-state:
    ``True`` = checked and passed, ``False`` = checked and failed,
    ``None`` = NOT MEASURED. ``None`` is never upgraded to a positive.

    ``valid`` and ``assurance`` are DERIVED from these fields; neither can
    be hand-asserted by a caller. That is the point: a consumer must not
    claim an assurance level it did not obtain.
    """

    received: int = 0
    schema_valid: bool | None = None
    hash_verified: bool | None = None
    signature_verified: bool | None = None
    #: Revocation is not implemented; this stays False and is reported as such.
    revocation_checked: bool = False
    broken_at: int | None = None
    reason: str | None = None
    #: Free-text status from the producer (e.g. upstream's
    #: ``measurement_status``: NOT_MEASURED / PASS / FAIL).
    measurement_status: str | None = None

    @property
    def assurance(self) -> str:
        """Highest level this result has EVIDENCE for."""
        if (
            self.schema_valid is False
            or self.hash_verified is False
            or self.signature_verified is False
        ):
            return INVALID
        if self.signature_verified is True and self.hash_verified is True:
            # Still not VERIFIED: key trust + revocation are unchecked.
            return SIGNATURE_VERIFIED
        if self.hash_verified is True:
            return HASH_VERIFIED
        if self.received > 0:
            return RECORDED
        return NOT_MEASURED

    @property
    def valid(self) -> bool | None:
        """Tri-state overall verdict. ``None`` means NOT MEASURED.

        Only signature verification yields a positive. A hash-chain walk
        proves linkage, not authenticity, so it yields ``None`` — the same
        answer phionyx-mcp-server 0.2.1's ``verify_chain()`` gives when no
        verifier is supplied.
        """
        a = self.assurance
        if a == INVALID:
            return False
        if ASSURANCE_RANK[a] >= ASSURANCE_RANK[SIGNATURE_VERIFIED]:
            return True
        return None


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
            verify_result=verify_result_from_upstream(verdict, received=len(envelopes)),
            # Revocation list integration is NOT implemented (see
            # REVOCATION_NOT_IMPLEMENTED). This stays empty, and the report
            # says "not checked" rather than rendering a bare 0.
            revoked_keys_referenced=[],
        )

    @classmethod
    def from_envelopes(
        cls,
        trace_id: str,
        envelopes: list[dict[str, Any]],
        verify_result: VerifyResult | None = None,
    ) -> "ChainView":
        """Build a ChainView from already-loaded envelopes.

        This does NOT verify anything: it does not walk the hash chain and
        it does not check signatures. The resulting VerifyResult therefore
        records only what is true — envelopes were RECEIVED — and leaves
        every verification dimension at ``None`` (NOT MEASURED), which
        yields assurance ``RECORDED`` and ``valid is None``.

        Callers that HAVE run a verification pass its result in explicitly
        via ``verify_result``. There is no way to assert a positive without
        supplying the evidence for it.
        """
        return cls(
            trace_id=trace_id,
            envelopes=envelopes,
            verify_result=verify_result
            or VerifyResult(
                received=len(envelopes),
                reason=(
                    "envelopes received but not verified — "
                    "ChainView.from_envelopes() performs no hash-chain walk "
                    "and no signature verification"
                ),
                measurement_status=NOT_MEASURED,
            ),
            revoked_keys_referenced=[],
        )


def verify_result_from_upstream(
    verdict: dict[str, Any], received: int
) -> VerifyResult:
    """Map phionyx-mcp-server's ``verify_chain()`` dict onto VerifyResult.

    Preserves the producer's tri-state rather than collapsing it. In
    particular ``valid: None`` + ``measurement_status: NOT_MEASURED``
    (0.2.1's answer when no signature verifier was supplied) must NOT
    become ``False`` — "not measured" is not "failed" — and must NOT
    become ``True``.
    """
    upstream_valid = verdict.get("valid")
    hash_chain_valid = verdict.get("hash_chain_valid")
    signatures_verified = verdict.get("signatures_verified")

    if hash_chain_valid is None:
        # Pre-0.2.1 producers do not report the dimension separately; the
        # walk that returns valid=False IS the hash-chain walk failing.
        hash_chain_valid = None if upstream_valid is None else bool(upstream_valid)

    if upstream_valid is True:
        # Upstream only returns True when a verifier ran and passed.
        signature_verified: bool | None = True
    elif upstream_valid is False and signatures_verified:
        signature_verified = False
    else:
        # No verifier ran, or the failure was hash-level. Either way the
        # signature question went unanswered.
        signature_verified = None

    return VerifyResult(
        received=received,
        hash_verified=hash_chain_valid,
        signature_verified=signature_verified,
        broken_at=verdict.get("broken_at"),
        reason=verdict.get("reason"),
        measurement_status=verdict.get("measurement_status"),
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
