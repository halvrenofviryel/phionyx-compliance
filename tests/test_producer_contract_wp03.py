"""WP-03 — producer contract, provenance, and the dependency floor.

These pin the four acceptance criteria that the P0.4 fix did not cover:

  AC-1  No caller can produce HASH_VERIFIED / SIGNATURE_VERIFIED from a
        boolean or a bare envelope list.
  AC-2  None, missing, or unknown never rises to positive assurance.
  AC-3  Reports name the component and version that performed the
        verification.
  AC-4  A wrong dependency version fails loudly at install/test — it must
        not silently produce a wrong answer.

The measured defect AC-4 exists for (reproduced 2026-08-07 against
phionyx-mcp-server 0.1.0, which the previous `>=0.1.0` pin allowed):

    upstream verdict   : {'valid': True, 'checked': 3, 'broken_at': None,
                          'reason': None}
    consumer assurance : SIGNATURE_VERIFIED
    signatures present : ['FORGED-NOT-A-REAL-SIGNATURE', ...]
    report said        : "signature verification ran and passed"

0.1.0's verify_chain() walks the HASH CHAIN ONLY. Its valid=True was read
as a signature fact, so a chain of literal forged signatures rendered a
signature-level posture. Nothing raised, nothing warned.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

ALL_TEMPLATES = [
    "eu-ai-act-article-13",
    "nist-ai-rmf-1",
    "iso-iec-42001",
    "owasp-agentic-ai-v1",
]

#: The exact shape phionyx-mcp-server 0.1.0 returns: no per-dimension
#: fields, no measurement_status. Its `valid` is a hash-chain answer.
HASH_ONLY_PRODUCER_VERDICT = {
    "valid": True,
    "checked": 3,
    "broken_at": None,
    "reason": None,
}


# ── AC-4: the dependency floor ─────────────────────────────────────

def test_declared_floor_matches_the_code_constant():
    """The pin in pyproject.toml and the runtime constant must not drift.

    Two places declare the same fact; if they disagree, one of them is
    lying to somebody (pip, or the operator reading the error message).

    Parsed textually rather than with tomllib: this suite's CI matrix
    includes Python 3.10, where tomllib does not exist, and a skip here
    would leave the drift unmeasured on a third of the matrix.
    """
    import re

    from phionyx_compliance import REQUIRED_MCP_SERVER_VERSION

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    pins = re.findall(r'"(phionyx-mcp-server[^"]*)"', text)
    expected = f"phionyx-mcp-server>={REQUIRED_MCP_SERVER_VERSION}"

    assert pins, "pyproject.toml declares no phionyx-mcp-server dependency"
    assert set(pins) == {expected}, (
        f"pyproject.toml declares {sorted(set(pins))}, "
        f"code requires {expected!r}"
    )
    # Both extras must carry it: `chain` for the feature, `dev` for the suite.
    for extra in ("chain", "dev"):
        block = re.search(rf"^{extra} = \[(.*?)\]", text, re.S | re.M)
        assert block, f"pyproject.toml has no [{extra}] extra"
        assert expected in block.group(1), f"[{extra}] does not pin {expected!r}"


def test_installed_producer_meets_the_declared_floor():
    """AC-4. The environment this suite runs in must satisfy the contract."""
    from phionyx_compliance import REQUIRED_MCP_SERVER_VERSION, require_producer
    from phionyx_compliance.chain_view import _version_tuple

    provenance = require_producer()
    assert provenance.component == "phionyx-mcp-server"
    assert _version_tuple(provenance.version) >= _version_tuple(
        REQUIRED_MCP_SERVER_VERSION
    )


@pytest.mark.parametrize("installed", ["0.1.0", "0.2.0", "0.0.1"])
def test_below_floor_producer_is_refused_loudly(monkeypatch, installed):
    """AC-4. Below the floor: raise. There is no degraded mode."""
    from phionyx_compliance import IncompatibleProducerError, require_producer
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: installed)

    with pytest.raises(IncompatibleProducerError) as exc:
        require_producer()

    message = str(exc.value)
    assert installed in message, "the error must state what IS installed"
    assert "0.2.1" in message, "the error must state what is REQUIRED"
    assert "HASH-CHAIN-ONLY" in message, "the error must state WHY it matters"


@pytest.mark.parametrize(
    "installed", ["0.2.1rc1", "0.2.1a1", "0.2.1b2", "0.2.1.dev0", "0.3.0rc1"]
)
def test_non_final_producer_builds_are_refused(monkeypatch, installed):
    """AC-4. A pre-release of the floor version is not the floor version.

    Truncating PEP 440 suffixes made "0.2.1rc1" compare EQUAL to the floor
    and "0.2.1.dev0" compare GREATER ((0,2,1,0) > (0,2,1)) — both passed
    silently. Dev-suffixed builds of this producer are in circulation.
    """
    from phionyx_compliance import IncompatibleProducerError, require_producer
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: installed)

    with pytest.raises(IncompatibleProducerError) as exc:
        require_producer()
    assert installed in str(exc.value)


def test_ambiguous_producer_identity_is_refused(monkeypatch):
    """AC-3/AC-4. from_disk prepends a monorepo source path to sys.path,
    which can shadow the installed distribution with a same-numbered but
    DIFFERENT build. Provenance must name the code that ran, so when the
    imported module and the installed distribution disagree, refuse rather
    than pick one.
    """
    import types

    from phionyx_compliance import IncompatibleProducerError, require_producer
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: "0.2.1")
    shadow = types.SimpleNamespace(__version__="0.9.9", __file__="/monorepo/x.py")

    with pytest.raises(IncompatibleProducerError) as exc:
        require_producer(module=shadow)
    message = str(exc.value)
    assert "ambiguous producer identity" in message
    assert "0.9.9" in message and "0.2.1" in message
    assert "/monorepo/x.py" in message


def test_provenance_names_the_module_that_actually_ran(monkeypatch):
    """When only the module reports a version, that is the one named."""
    import types

    from phionyx_compliance import require_producer
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: None)
    module = types.SimpleNamespace(__version__="0.2.1", __file__="/monorepo/x.py")

    provenance = require_producer(module=module)
    assert provenance.version == "0.2.1"


def test_absent_producer_is_refused_loudly(monkeypatch):
    from phionyx_compliance import IncompatibleProducerError, require_producer
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: None)

    with pytest.raises(IncompatibleProducerError) as exc:
        require_producer()
    assert "not installed" in str(exc.value)


def test_from_disk_checks_the_producer_before_reading_anything(monkeypatch, tmp_path):
    """AC-4. The gate fires BEFORE the chain is read, so a wrong version can
    never reach the mapping code that would misread it."""
    from phionyx_compliance import ChainView, IncompatibleProducerError
    from phionyx_compliance import chain_view

    monkeypatch.setattr(chain_view, "_installed_version", lambda dist: "0.1.0")

    with pytest.raises(IncompatibleProducerError):
        # tmp_path contains no chain at all; if the producer check did not
        # run first this would raise FileNotFoundError instead.
        ChainView.from_disk("trace-does-not-exist", chain_root=tmp_path)


def test_hash_only_verdict_cannot_produce_a_signature_fact():
    """AC-4, data-level. THE REGRESSION.

    Even if a hash-only verdict somehow reaches the mapper, its valid=True
    must not become a signature positive. This is the exact input that
    produced SIGNATURE_VERIFIED for a forged-signature chain.
    """
    from phionyx_compliance import MeasurementProvenance, verify_result_from_upstream

    # Attribute the synthetic verdict to what it SIMULATES. Defaulting the
    # provenance would stamp it "phionyx-mcp-server 0.2.1" — a wrong
    # provenance fact, and the same class of defect this file exists for.
    r = verify_result_from_upstream(
        dict(HASH_ONLY_PRODUCER_VERDICT),
        received=3,
        provenance=MeasurementProvenance("phionyx-mcp-server", "0.1.0"),
    )

    assert r.signature_verified is None
    assert r.signature_verified_by_upstream is None, (
        "a hash-only walker's valid=True is not a signature measurement"
    )
    assert r.assurance == "HASH_VERIFIED"
    assert r.valid is None, "hash continuity is not overall validity"
    # The report must SAY why the signature dimension is empty.
    assert "carried no per-dimension fields" in (r.reason or "")
    assert "NOT MEASURED" in (r.reason or "")
    assert r.dimensions_reported is False
    assert r.attested == frozenset({"hash_verified"})


def test_dimensionless_failure_does_not_slander_an_in_contract_producer():
    """The degradation notice must fire ONLY on an ambiguous POSITIVE.

    The pinned 0.2.1 returns a bare {valid, checked, broken_at, reason} on
    all four of its HASH-FAILURE paths. Emitting "this producer carried no
    per-dimension fields" there asserts, falsely, that a producer
    require_producer() just certified is a legacy hash-only walker — a
    false claim about the verification pipeline, printed into the evidence
    artefact, on the most common failure path.
    """
    from phionyx_mcp_server.audit_chain import (
        GENESIS_HASH,
        envelope_hash,
        payload_for_hash,
        verify_chain,
    )

    from phionyx_compliance import verify_result_from_upstream

    envelopes: list[dict] = []
    previous = GENESIS_HASH
    for i in range(3):
        payload = {
            "schema": "phionyx.governed_response_envelope.v0.2",
            "subject": {"turn_index": i, "decision": "pass"},
        }
        current = envelope_hash(payload_for_hash(dict(payload)), previous)
        env = dict(payload)
        env["integrity"] = {
            "previous": previous,
            "current": current,
            "key_id": "key-test",
            "signature": f"sig-{i}",
        }
        envelopes.append(env)
        previous = current
    envelopes[2]["integrity"]["previous"] = "TAMPERED-LINK"
    verdict = verify_chain(envelopes)

    # Precondition: the producer reports a hash-level failure. The pinned
    # 0.2.1 omits the dimension keys on this path; 0.2.2 reports them
    # (hash_chain_valid: False, measurement_status: FAIL). The invariant
    # under test holds for both: a hash-level failure is never turned into
    # the "no per-dimension fields" degradation notice.
    assert verdict["valid"] is False
    assert verdict.get("hash_chain_valid") in (None, False)
    assert verdict.get("measurement_status") in (None, "FAIL")

    r = verify_result_from_upstream(verdict, received=3)
    assert r.assurance == "INVALID"
    assert r.valid is False
    assert "carried no per-dimension fields" not in (r.reason or "")
    assert "previous hash mismatch" in (r.reason or "")


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_hash_only_verdict_renders_no_signature_claim(name):
    """AC-4 end-to-end: the degraded verdict must not render as assurance."""
    from phionyx_compliance import (
        ChainView,
        load_template,
        render,
        resolve_inputs,
        verify_result_from_upstream,
    )

    result = verify_result_from_upstream(
        dict(HASH_ONLY_PRODUCER_VERDICT), received=3
    )
    chain = ChainView.from_envelopes("t-hash-only", [{}, {}, {}], verify_result=result)
    t = load_template(name)
    out = render(t, resolve_inputs(t, chain))

    for phrase in (
        "Ed25519 signatures verify",
        "signatures verify against",
        "every decision is signed and replayable",
        "SIGNATURE_VERIFIED",
    ):
        assert phrase not in out, f"{name}: emitted {phrase!r} from a hash-only walk"
    assert "Signatures were **NOT** verified" in out


# ── AC-2: absence never rises ──────────────────────────────────────

@pytest.mark.parametrize(
    "verdict",
    [
        {},
        {"valid": None},
        {"valid": None, "hash_chain_valid": None, "measurement_status": "NOT_MEASURED"},
        {"valid": "unknown", "hash_chain_valid": None, "measurement_status": "UNKNOWN"},
        {"hash_chain_valid": None, "measurement_status": "ERROR"},
        {"valid": None, "hash_chain_valid": None, "measurement_status": "NOT_RUN"},
    ],
)
def test_absence_never_rises_to_positive_assurance(verdict):
    """AC-2. None / missing / unknown / ERROR / NOT_RUN stay non-positive."""
    from phionyx_compliance import ASSURANCE_RANK, verify_result_from_upstream

    r = verify_result_from_upstream(dict(verdict), received=4)

    assert r.valid is not True, verdict
    assert r.signature_verified is not True, verdict
    assert r.signature_verified_by_upstream is not True, verdict
    assert ASSURANCE_RANK[r.assurance] < ASSURANCE_RANK["HASH_VERIFIED"], (
        verdict,
        r.assurance,
    )


def test_unknown_string_is_not_truthy_by_accident():
    """A non-boolean truthy `valid` must not be coerced into a pass."""
    from phionyx_compliance import verify_result_from_upstream

    r = verify_result_from_upstream(
        {"valid": "yes", "hash_chain_valid": None, "measurement_status": "UNKNOWN"},
        received=2,
    )
    assert r.valid is not True
    assert r.assurance == "RECORDED"


def test_not_measured_survives_the_round_trip_to_the_report():
    """AC-2 end-to-end: upstream's honest NOT_MEASURED reaches the reader."""
    from phionyx_compliance import verify_result_from_upstream
    from phionyx_compliance.renderer import render_chain_integrity_summary

    r = verify_result_from_upstream(
        {"valid": None, "hash_chain_valid": True, "measurement_status": "NOT_MEASURED"},
        received=3,
    )
    assert r.assurance == "HASH_VERIFIED"
    assert r.valid is None

    out = render_chain_integrity_summary(result=r)
    assert "Signatures were **NOT** verified" in out
    assert "signature verification ran and passed" not in out


# ── AC-3: reports name the component and version ───────────────────

def _upstream_pass_result(received: int = 3):
    from phionyx_compliance import verify_result_from_upstream

    return verify_result_from_upstream(
        {
            "valid": True,
            "hash_chain_valid": True,
            "signatures_verified": True,
            "measurement_status": "PASS",
            "broken_at": None,
            "reason": None,
        },
        received=received,
    )


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_report_names_the_verifying_component_and_version(name):
    """AC-3. Every positive assurance statement is attributable."""
    from importlib.metadata import version

    from phionyx_compliance import ChainView, load_template, render, resolve_inputs

    result = _upstream_pass_result()
    chain = ChainView.from_envelopes("t-attr", [{}, {}, {}], verify_result=result)
    t = load_template(name)
    out = render(t, resolve_inputs(t, chain))

    assert "phionyx-mcp-server" in out, f"{name}: no component named"
    assert version("phionyx-mcp-server") in out, f"{name}: no version named"


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_report_does_not_present_upstream_result_as_its_own(name):
    """Requirement 4. Carried ≠ verified. The report must say which."""
    from phionyx_compliance import ChainView, load_template, render, resolve_inputs

    result = _upstream_pass_result()
    chain = ChainView.from_envelopes("t-attr", [{}, {}, {}], verify_result=result)
    t = load_template(name)
    out = render(t, resolve_inputs(t, chain))

    assert "SIGNATURE_VERIFIED_BY_UPSTREAM" in out
    assert "did not verify it" in out
    # The bare, unattributed form must never appear on this path.
    assert "Assurance: **SIGNATURE_VERIFIED**" not in out


def test_renderer_helpers_refuse_an_unattributed_positive():
    """AC-3. The public renderer helpers are a call surface too.

    Measured before this fix: handing `render_t8_repudiation_status` an
    assurance string with no `verified_by` rendered "signatures verified
    by an unnamed component" — a signature claim attributable to nobody.
    """
    from phionyx_compliance.renderer import (
        render_t8_repudiation_status,
        render_t9_spoofing_status,
    )

    for assurance, flags in (
        ("SIGNATURE_VERIFIED", {"signature_verified": True}),
        (
            "SIGNATURE_VERIFIED_BY_UPSTREAM",
            {"signature_verified_by_upstream": True},
        ),
    ):
        out = render_t8_repudiation_status(
            assurance=assurance, envelope_count=5, **flags
        )
        assert "unnamed component" not in out, assurance
        assert "signatures verified" not in out, assurance
        assert "reports that signature verification passed" not in out, assurance
        assert "no repudiation defence" in out.lower(), assurance

    for flags in (
        {"signature_verified": True},
        {"signature_verified_by_upstream": True},
    ):
        out = render_t9_spoofing_status(signing_key_id="k", **flags)
        assert "unnamed component" not in out, flags
        assert "ran and passed" not in out, flags
        assert "did **NOT** run" in out, flags

    # A negative still lands without provenance — it fails closed.
    failed = render_t8_repudiation_status(assurance="INVALID", envelope_count=5)
    assert "INTEGRITY FAILURE" in failed
    spoofed = render_t9_spoofing_status(signing_key_id="k", signature_verified=False)
    assert "treat as spoofed" in spoofed


def test_no_report_sentence_takes_none_as_its_subject():
    """A literal `None` must never appear as a sentence subject.

    Measured: render_t9_spoofing_status(signature_verified_by_upstream=False)
    with no provenance emitted "None reports that signature verification
    **FAILED**". The earlier gate only nulled the POSITIVE flags.
    """
    from phionyx_compliance.renderer import (
        render_chain_integrity_summary,
        render_chain_valid_label,
        render_t8_repudiation_status,
        render_t9_spoofing_status,
    )

    outputs = [
        render_t9_spoofing_status(signing_key_id="k", signature_verified_by_upstream=False),
        render_t9_spoofing_status(signing_key_id="k", signature_verified=False),
        render_t9_spoofing_status(signing_key_id="k"),
        render_t8_repudiation_status(envelope_count=5, assurance="INVALID"),
        render_t8_repudiation_status(envelope_count=5),
        render_chain_valid_label(valid=False, broken_at=1),
        render_chain_integrity_summary(envelope_count=5, valid=False, broken_at=1),
    ]
    for out in outputs:
        assert "None " not in out and " None" not in out, out
    # The negative is still reported, just without a fabricated subject.
    unattributed = render_t9_spoofing_status(
        signing_key_id="k", signature_verified_by_upstream=False
    )
    assert "treat as spoofed" in unattributed
    assert "is not recorded" in unattributed


def test_hash_verified_paragraph_does_not_assert_how_producer_was_invoked():
    """"no signature verifier was supplied" is a fact about the producer's
    invocation. On a dimension-less verdict this package never observed it.
    """
    from phionyx_compliance import MeasurementProvenance, verify_result_from_upstream
    from phionyx_compliance.renderer import render_chain_integrity_summary

    dimensionless = verify_result_from_upstream(
        dict(HASH_ONLY_PRODUCER_VERDICT),
        received=3,
        provenance=MeasurementProvenance("phionyx-mcp-server", "0.1.0"),
    )
    out = render_chain_integrity_summary(result=dimensionless)
    assert "no signature verifier was supplied" not in out
    assert "the producer reported no signature result" in out

    # When dimensions WERE reported, the stronger statement is warranted.
    full = verify_result_from_upstream(
        {"valid": None, "hash_chain_valid": True, "measurement_status": "NOT_MEASURED"},
        received=3,
    )
    assert "no signature verifier was supplied" in render_chain_integrity_summary(result=full)


def test_defaulted_provenance_is_labelled_as_inferred():
    """AC-3. A defaulted identity is inferred, not observed.

    `verify_result_from_upstream` cannot know that a caller-supplied dict
    came from the locally installed producer. Stamping it with that
    version reads as an observed fact; the label must say it is inferred.
    """
    from phionyx_compliance import verify_result_from_upstream

    inferred = verify_result_from_upstream(
        {"valid": None, "hash_chain_valid": True, "measurement_status": "NOT_MEASURED"},
        received=3,
    )
    assert "identity inferred from the local installation" in inferred.provenance_label

    # from_disk passes the imported module explicitly, so its label is not
    # hedged. Simulate that call shape.
    from phionyx_compliance import MeasurementProvenance

    observed = verify_result_from_upstream(
        {"valid": None, "hash_chain_valid": True, "measurement_status": "NOT_MEASURED"},
        received=3,
        provenance=MeasurementProvenance(
            "phionyx-mcp-server", "0.2.1", "audit_chain.verify_chain()"
        ),
    )
    assert "inferred" not in observed.provenance_label


def test_provenance_label_is_empty_when_nothing_measured():
    from phionyx_compliance import VerifyResult

    r = VerifyResult(received=3)
    assert r.verified_by is None
    assert "no component performed a verification" in r.provenance_label


def test_positive_cannot_be_injected_by_mutating_after_construction():
    """AC-1. The constructor gate alone is bypassable — close that too.

    Measured before this fix: `r = VerifyResult(received=1)` followed by
    `r.hash_verified = True; r.signature_verified_by_upstream = True`
    yielded assurance=SIGNATURE_VERIFIED_BY_UPSTREAM, valid=True,
    verified_by=None. The __post_init__ check never saw it.
    """
    import dataclasses

    from phionyx_compliance import VerifyResult

    r = VerifyResult(received=1)
    assert r.assurance == "RECORDED"

    for field_name in (
        "hash_verified",
        "signature_verified",
        "signature_verified_by_upstream",
        "schema_valid",
        "revocation_checked",
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(r, field_name, True)

    assert r.assurance == "RECORDED"
    assert r.valid is None


def test_assurance_refuses_a_positive_without_provenance():
    """AC-1/AC-3, third line of defence: the derivation itself checks.

    Built via `dataclasses.replace`-style reconstruction is impossible
    here (the constructor gate fires), so this exercises the derivation
    directly on an object whose provenance was dropped.
    """
    from phionyx_compliance import MeasurementProvenance, VerifyResult

    attested = frozenset({"hash_verified", "signature_verified_by_upstream"})
    good = VerifyResult(
        received=3,
        hash_verified=True,
        signature_verified_by_upstream=True,
        verified_by=MeasurementProvenance("phionyx-mcp-server", "0.2.1"),
        attested=attested,
    )
    assert good.assurance == "SIGNATURE_VERIFIED_BY_UPSTREAM"
    assert good.valid is True

    # Same dimension flags, provenance removed via object.__setattr__
    # (the only way past a frozen dataclass) — must NOT stay positive.
    stripped = VerifyResult(
        received=3,
        hash_verified=True,
        signature_verified_by_upstream=True,
        verified_by=MeasurementProvenance("phionyx-mcp-server", "0.2.1"),
        attested=attested,
    )
    object.__setattr__(stripped, "verified_by", None)
    assert stripped.assurance == "RECORDED"
    assert stripped.valid is None


def test_dataclasses_replace_cannot_escalate_a_legitimate_result():
    """AC-1. `replace()` is the standard way to derive from a frozen
    dataclass, and it re-runs __post_init__ carrying the ORIGINAL
    provenance — so an object-level provenance check passes while a brand
    new dimension is invented.

    Measured before the fix: replace(upstream_result, signature_verified=True)
    gave assurance=SIGNATURE_VERIFIED, valid=True, and rendered "signature
    verification ran and passed ... Verified by phionyx-mcp-server 0.2.1",
    crediting the producer with a check nobody ran.
    """
    import dataclasses

    from phionyx_compliance import UnprovenancedAssuranceError, verify_result_from_upstream

    legit = verify_result_from_upstream(
        {
            "valid": True,
            "hash_chain_valid": True,
            "signatures_verified": True,
            "measurement_status": "PASS",
        },
        received=3,
    )
    assert legit.assurance == "SIGNATURE_VERIFIED_BY_UPSTREAM"

    with pytest.raises(UnprovenancedAssuranceError):
        dataclasses.replace(legit, signature_verified=True)
    with pytest.raises(UnprovenancedAssuranceError):
        dataclasses.replace(legit, schema_valid=True)

    # Escalating a RECORDED result to a hash claim is refused too.
    recorded = verify_result_from_upstream(
        {"valid": None, "hash_chain_valid": None, "measurement_status": "NOT_MEASURED"},
        received=3,
    )
    assert recorded.assurance == "RECORDED"
    with pytest.raises(UnprovenancedAssuranceError):
        dataclasses.replace(recorded, hash_verified=True)


def test_self_verified_dimension_requires_this_package_as_the_verifier():
    """`signature_verified` means WE verified. Nothing here does, so no
    producer's identity may be used to set it."""
    from phionyx_compliance import (
        MeasurementProvenance,
        UnprovenancedAssuranceError,
        VerifyResult,
    )

    with pytest.raises(UnprovenancedAssuranceError) as exc:
        VerifyResult(
            received=3,
            hash_verified=True,
            signature_verified=True,
            verified_by=MeasurementProvenance("phionyx-mcp-server", "0.2.1"),
            attested=frozenset({"hash_verified", "signature_verified"}),
        )
    assert "belongs in" in str(exc.value)


def test_provenance_requires_component_and_version():
    from phionyx_compliance import MeasurementProvenance

    with pytest.raises(ValueError):
        MeasurementProvenance("", "0.2.1")
    with pytest.raises(ValueError):
        MeasurementProvenance("phionyx-mcp-server", "")
