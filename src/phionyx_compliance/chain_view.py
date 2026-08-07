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


# ── Producer requirement ───────────────────────────────────────────
# phionyx-compliance verifies NOTHING itself. Every verification fact in
# a report comes from the producer, phionyx-mcp-server. The consumer
# therefore depends on a specific producer CONTRACT, not merely on the
# module being importable.
#
# Required floor: 0.2.1. Measured 2026-08-07 on this repo's suite:
#
#   phionyx-mcp-server 0.2.1  verify_chain(envelopes, verifier=...) ->
#       {valid, hash_chain_valid, signatures_verified, measurement_status, ...}
#       — reports each dimension SEPARATELY and returns valid=None /
#       measurement_status=NOT_MEASURED when no signature verifier ran.
#
#   phionyx-mcp-server 0.1.0  verify_chain(envelopes) ->
#       {valid, checked, broken_at, reason}
#       — NO dimension fields. It walks the HASH CHAIN ONLY and returns
#       valid=True for a hash-intact chain whose signatures were never
#       looked at. Mapping that valid=True onto a signature fact reports
#       SIGNATURE assurance for a chain carrying literal forged
#       signatures. That is the P0.4 defect re-entering through the
#       dependency floor, and it is SILENT.
#
# So the floor is not a convenience pin: below it the answer is wrong,
# not merely unavailable. `require_producer()` fails closed and loudly.

REQUIRED_MCP_SERVER_VERSION = "0.2.1"

#: Keys a producer verdict MUST carry for its `valid` to be readable as a
#: signature fact. A verdict without them came from a hash-only walker.
REQUIRED_VERDICT_DIMENSION_KEYS = ("hash_chain_valid", "measurement_status")


class IncompatibleProducerError(RuntimeError):
    """The installed phionyx-mcp-server cannot answer what we ask of it."""


class UnprovenancedAssuranceError(ValueError):
    """A positive assurance was asserted without naming who measured it.

    Raised by :class:`VerifyResult` when any dimension is set to ``True``
    without a :class:`MeasurementProvenance`. This is the constructor-level
    gate that makes "hand a boolean, receive an assurance level"
    impossible — there is no call route to a positive that does not carry
    the identity of the component that produced it.
    """


# ── Assurance ladder ───────────────────────────────────────────────
# Ordering (weakest → strongest). A consumer may only report the level
# it actually OBTAINED evidence for. Levels above SIGNATURE_VERIFIED
# are declared here so the vocabulary is complete, but this package
# cannot reach them: VERIFIED additionally requires key trust and
# revocation state, TRUSTED additionally requires witness/freshness.
# Neither is implemented here — see `REVOCATION_NOT_IMPLEMENTED`.
#
# SIGNATURE_VERIFIED_BY_UPSTREAM sits strictly between HASH_VERIFIED and
# SIGNATURE_VERIFIED, and is the CEILING this package can reach today:
#
#   - strictly ABOVE HASH_VERIFIED, because a signature check did run and
#     pass somewhere, which a hash walk alone never establishes;
#   - strictly BELOW SIGNATURE_VERIFIED, because phionyx-compliance made
#     no independent measurement. It re-states a third party's answer.
#     Measured in this ecosystem (2026-08-06): AIREP's own published
#     verifiers returned their TOP class for 7/7 adversarial records,
#     including a forged witness signature and a key the record itself
#     declared revoked. An upstream positive is therefore not evidence
#     that a sound cryptographic check ran — only that some component
#     said so. The report must name that component, and must not read as
#     if this package verified anything.

INVALID = "INVALID"
NOT_MEASURED = "NOT_MEASURED"
RECORDED = "RECORDED"
HASH_VERIFIED = "HASH_VERIFIED"
SIGNATURE_VERIFIED_BY_UPSTREAM = "SIGNATURE_VERIFIED_BY_UPSTREAM"
SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
VERIFIED = "VERIFIED"
TRUSTED = "TRUSTED"

ASSURANCE_ORDER = [
    INVALID,
    NOT_MEASURED,
    RECORDED,
    HASH_VERIFIED,
    SIGNATURE_VERIFIED_BY_UPSTREAM,
    SIGNATURE_VERIFIED,
    VERIFIED,
    TRUSTED,
]
ASSURANCE_RANK = {name: i for i, name in enumerate(ASSURANCE_ORDER)}

#: The strongest level reachable through THIS PACKAGE'S OWN code paths
#: (``ChainView.from_disk`` → ``verify_result_from_upstream``). Nothing
#: here verifies a signature itself, evaluates key trust, checks
#: revocation, or validates a witness, so a producer result can never be
#: promoted past "someone else verified it".
#:
#: This is a property of the mapping, enforced by
#: `test_package_own_paths_never_exceed_the_ceiling`, NOT a clamp applied
#: inside `VerifyResult.assurance`. A clamp there would collapse two
#: distinct levels into one and would misreport a caller that genuinely
#: DID run its own verifier and named it.
MAX_REACHABLE_ASSURANCE = SIGNATURE_VERIFIED_BY_UPSTREAM

#: Revocation checking is NOT implemented in phionyx-compliance. Reports
#: must SAY this rather than omit it or render a bare `0`.
REVOCATION_NOT_IMPLEMENTED = (
    "NOT CHECKED — key revocation is not implemented in phionyx-compliance. "
    "A revoked signing key would not be detected by this report. The operator "
    "must check revocation state out of band before relying on any signature."
)


# ── Provenance ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class MeasurementProvenance:
    """WHO produced a measurement, and at which version.

    A positive assurance without this is not reportable: an auditor cannot
    assess a verification result without knowing which implementation, at
    which version, produced it.
    """

    component: str
    version: str
    #: What the named component actually did. Free text, rendered verbatim.
    method: str = "verify_chain()"

    def __post_init__(self) -> None:
        if not (self.component or "").strip():
            raise ValueError("MeasurementProvenance.component must be non-empty")
        if not (self.version or "").strip():
            raise ValueError("MeasurementProvenance.version must be non-empty")

    def __str__(self) -> str:
        return f"{self.component} {self.version}"

    @property
    def label(self) -> str:
        return f"`{self.component}` version `{self.version}` (`{self.method}`)"


def _installed_version(dist: str) -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version(dist)
    except Exception:  # PackageNotFoundError or anything import-related
        return None


def _version_tuple(v: str) -> tuple:
    parts: list[int] = []
    for chunk in str(v).split("+")[0].split("-")[0].split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def require_producer(
    minimum: str = REQUIRED_MCP_SERVER_VERSION,
) -> MeasurementProvenance:
    """Assert the installed producer meets the contract; return its identity.

    FAILS LOUDLY AND CLOSED. Below the floor the producer returns a
    hash-only verdict that this consumer would otherwise map onto a
    signature fact (see the module header) — a silent wrong answer. There
    is no degraded mode: raise.

    Raises:
        IncompatibleProducerError: not installed, or below the floor.
    """
    installed = _installed_version("phionyx-mcp-server")
    if installed is None:
        raise IncompatibleProducerError(
            "phionyx-mcp-server is not installed. phionyx-compliance performs "
            "no verification of its own and cannot produce any assurance "
            "statement without it. Install "
            f"'phionyx-mcp-server>={minimum}' "
            "(e.g. pip install 'phionyx-compliance[chain]')."
        )
    if _version_tuple(installed) < _version_tuple(minimum):
        raise IncompatibleProducerError(
            f"phionyx-mcp-server {installed} is installed but "
            f">={minimum} is required. Version {installed} reports a "
            "HASH-CHAIN-ONLY verdict with no per-dimension fields; its "
            "valid=True does NOT mean any signature was checked. Mapping it "
            "would report SIGNATURE assurance for an unverified chain. "
            f"Refusing. Upgrade: pip install -U 'phionyx-mcp-server>={minimum}'."
        )
    return MeasurementProvenance(
        component="phionyx-mcp-server",
        version=installed,
        method="audit_chain.verify_chain()",
    )


@dataclass(frozen=True)
class VerifyResult:
    """What was actually measured about a chain — and what was not.

    Each dimension is recorded SEPARATELY and is tri-state:
    ``True`` = checked and passed, ``False`` = checked and failed,
    ``None`` = NOT MEASURED. ``None`` is never upgraded to a positive.

    ``valid`` and ``assurance`` are DERIVED properties, never constructor
    arguments. On top of that, **every positive requires provenance**: any
    dimension set to ``True`` without ``verified_by`` raises
    :class:`UnprovenancedAssuranceError`. So there is no route from a bare
    boolean to a positive assurance level — a caller that wants to report
    one must name the component and version that measured it.

    Negatives (``False``) do NOT require provenance: an unattributed
    negative fails closed, and per the measurement axioms a negative can
    never be converted upward anyway.

    The gate is enforced in THREE independent places, because one of them
    is bypassable on its own:

    1. ``__post_init__`` rejects a positive without provenance at
       construction.
    2. The class is ``frozen``, so the constructor gate cannot be stepped
       around by assigning the field afterwards (``r.hash_verified =
       True`` raises ``FrozenInstanceError``).
    3. ``assurance`` itself refuses to return a positive level when
       ``verified_by`` is absent, so even a hypothetical route that
       produced an inconsistent instance still cannot report one.

    ``signature_verified`` vs ``signature_verified_by_upstream``:
        ``signature_verified`` is reserved for a check THIS package ran.
        Nothing here implements one, so on every code path in this package
        it stays ``None``. Producer results land in
        ``signature_verified_by_upstream`` and are reported as a carried
        third-party assertion, never as this report's own finding.
    """

    received: int = 0
    schema_valid: bool | None = None
    hash_verified: bool | None = None
    #: Signature verification performed BY THIS PACKAGE. Structurally always
    #: None today — phionyx-compliance implements no verifier.
    signature_verified: bool | None = None
    #: Signature verification performed by the producer and CARRIED here.
    #: Requires `verified_by`; reported with attribution, never as our own.
    signature_verified_by_upstream: bool | None = None
    #: Revocation is not implemented; this stays False and is reported as such.
    revocation_checked: bool = False
    broken_at: int | None = None
    reason: str | None = None
    #: Free-text status from the producer (e.g. upstream's
    #: ``measurement_status``: NOT_MEASURED / PASS / FAIL).
    measurement_status: str | None = None
    #: WHO measured. Mandatory for any positive dimension.
    verified_by: MeasurementProvenance | None = None

    #: Dimensions that may not be True without provenance.
    _PROVENANCE_REQUIRED = (
        "schema_valid",
        "hash_verified",
        "signature_verified",
        "signature_verified_by_upstream",
    )

    def __post_init__(self) -> None:
        positives = [
            name
            for name in self._PROVENANCE_REQUIRED
            if getattr(self, name) is True
        ]
        if positives and not isinstance(self.verified_by, MeasurementProvenance):
            raise UnprovenancedAssuranceError(
                "positive assurance asserted without provenance: "
                f"{sorted(positives)} set to True but verified_by is "
                f"{self.verified_by!r}. A positive must name the component "
                "and version that measured it — pass "
                "verified_by=MeasurementProvenance(component=..., version=...). "
                "phionyx-compliance verifies nothing itself; use "
                "verify_result_from_upstream() to carry a producer result."
            )
        if self.revocation_checked is True:
            # Nothing in this package checks revocation. An upstream flag
            # must not flip it — a consumer cannot strengthen upstream
            # assurance, and this dimension has no implementation at all.
            raise UnprovenancedAssuranceError(
                "revocation_checked=True is unreachable: revocation checking "
                "is not implemented in phionyx-compliance. "
                f"{REVOCATION_NOT_IMPLEMENTED}"
            )

    @property
    def assurance(self) -> str:
        """Highest level this result has EVIDENCE for.

        VERIFIED and TRUSTED are structurally unreachable: no field on
        this class can represent key trust, revocation, witness or
        freshness, so no combination of inputs can return them.
        """
        if (
            self.schema_valid is False
            or self.hash_verified is False
            or self.signature_verified is False
            or self.signature_verified_by_upstream is False
        ):
            return INVALID

        level = NOT_MEASURED
        if self.received > 0:
            level = RECORDED

        if self.verified_by is None:
            # Defence in depth. No provenance ⇒ no positive, whatever the
            # dimension flags say. An assurance level nobody can be named
            # for is not reportable, so it is not derivable either.
            return level

        if self.hash_verified is True:
            level = HASH_VERIFIED
            # A signature fact is only readable on top of an intact chain:
            # a signature over a re-linked record proves nothing about the
            # record's position in the chain.
            if self.signature_verified is True:
                level = SIGNATURE_VERIFIED
            elif self.signature_verified_by_upstream is True:
                level = SIGNATURE_VERIFIED_BY_UPSTREAM

        return level

    @property
    def valid(self) -> bool | None:
        """Tri-state overall verdict. ``None`` means NOT MEASURED.

        A positive requires that a signature verification ran, passed, and
        is attributable. A hash-chain walk proves linkage, not
        authenticity, so it yields ``None`` — the same answer
        phionyx-mcp-server 0.2.1's ``verify_chain()`` gives when no
        verifier is supplied.
        """
        a = self.assurance
        if a == INVALID:
            return False
        if ASSURANCE_RANK[a] >= ASSURANCE_RANK[SIGNATURE_VERIFIED_BY_UPSTREAM]:
            return True
        return None

    @property
    def verified_independently(self) -> bool:
        """True only if THIS package ran the signature check. Always False."""
        return self.signature_verified is True

    @property
    def provenance_label(self) -> str:
        """Human-readable "who measured this", for report language."""
        if self.verified_by is None:
            return "no component performed a verification"
        return str(self.verified_by.label)


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
            IncompatibleProducerError: if phionyx-mcp-server is missing or
                below ``REQUIRED_MCP_SERVER_VERSION``. Checked BEFORE any
                chain is read, so a wrong version fails loudly instead of
                silently producing a hash-only verdict read as a
                signature fact.
            ImportError: if phionyx-mcp-server is not importable.
            FileNotFoundError: if the chain directory for the trace does
                               not exist.
        """
        # Fail closed on the producer contract before touching any data.
        provenance = require_producer()

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
            verify_result=verify_result_from_upstream(
                verdict, received=len(envelopes), provenance=provenance
            ),
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
        via ``verify_result``. There is still no way to assert a positive
        without supplying the evidence for it: a ``VerifyResult`` carrying
        any ``True`` dimension cannot be constructed at all without a
        :class:`MeasurementProvenance` (see
        :class:`UnprovenancedAssuranceError`). Handing this method a bare
        envelope list, or a boolean, cannot produce HASH_VERIFIED or any
        signature-level assurance by any route.
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
    verdict: dict[str, Any],
    received: int,
    *,
    provenance: MeasurementProvenance | None = None,
) -> VerifyResult:
    """Map phionyx-mcp-server's ``verify_chain()`` dict onto VerifyResult.

    Three separate disciplines apply here.

    **1. Tri-state is preserved, never collapsed.** ``valid: None`` +
    ``measurement_status: NOT_MEASURED`` (0.2.1's answer when no signature
    verifier was supplied) must NOT become ``False`` — "not measured" is
    not "failed" — and must NOT become ``True``.

    **2. An upstream positive is carried, not adopted.** This package runs
    no verifier. A producer ``valid=True`` therefore lands in
    ``signature_verified_by_upstream``, never in ``signature_verified``,
    and the resulting ceiling is ``SIGNATURE_VERIFIED_BY_UPSTREAM``. The
    report says who measured it. Consumers cannot strengthen upstream
    assurance, and an upstream that returns ``TRUSTED`` gets no further
    than the ceiling.

    **3. A verdict without dimension fields cannot carry a signature
    fact.** phionyx-mcp-server 0.1.0 returns ``{valid, checked, broken_at,
    reason}`` from a HASH-ONLY walk: its ``valid=True`` says nothing about
    signatures. Reading it as one reports SIGNATURE assurance for a chain
    with forged signatures. So a verdict missing
    ``REQUIRED_VERDICT_DIMENSION_KEYS`` is degraded to a hash-level
    reading and its ``reason`` records why. ``require_producer()`` refuses
    such producers up front; this is the second, data-level line.

    Args:
        provenance: identity of the component that produced ``verdict``.
            Required for any positive to survive. Defaults to the
            installed phionyx-mcp-server via ``require_producer()``.
    """
    if provenance is None:
        provenance = require_producer()

    def _tri(value: Any) -> bool | None:
        """Accept ONLY literal booleans. Everything else is NOT MEASURED.

        `bool(value)` would turn any truthy non-boolean into a positive:
        the string "unknown" is truthy, and so are "ERROR" and "NOT_RUN".
        An unrecognised status is an absence of measurement, never a pass.
        """
        return value if isinstance(value, bool) else None

    upstream_valid = _tri(verdict.get("valid"))
    hash_chain_valid = _tri(verdict.get("hash_chain_valid"))
    signatures_verified = _tri(verdict.get("signatures_verified"))

    reports_dimensions = all(
        k in verdict for k in REQUIRED_VERDICT_DIMENSION_KEYS
    )

    degraded_reason: str | None = None
    if not reports_dimensions:
        # Hash-only producer. Its `valid` is a hash-chain answer and may be
        # read ONLY as such.
        degraded_reason = (
            f"producer verdict from {provenance} lacks per-dimension fields "
            f"{list(REQUIRED_VERDICT_DIMENSION_KEYS)}; its `valid` reports a "
            "hash-chain walk only and carries NO signature information. "
            "Signature assurance is NOT MEASURED."
        )
        hash_chain_valid = (
            None if upstream_valid is None else bool(upstream_valid)
        )
        signature_by_upstream: bool | None = None
    else:
        if hash_chain_valid is None:
            hash_chain_valid = (
                None if upstream_valid is None else bool(upstream_valid)
            )
        if upstream_valid is True:
            # Producer reports dimensions AND says a verifier passed.
            signature_by_upstream = True
        elif upstream_valid is False and signatures_verified:
            signature_by_upstream = False
        else:
            # No verifier ran, or the failure was hash-level. Either way the
            # signature question went unanswered.
            signature_by_upstream = None

    reason = verdict.get("reason")
    if degraded_reason:
        reason = f"{reason}. {degraded_reason}" if reason else degraded_reason

    return VerifyResult(
        received=received,
        hash_verified=hash_chain_valid,
        # NEVER set from upstream: this package ran no signature check.
        signature_verified=None,
        signature_verified_by_upstream=signature_by_upstream,
        broken_at=verdict.get("broken_at"),
        reason=reason,
        measurement_status=verdict.get("measurement_status"),
        verified_by=provenance,
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
